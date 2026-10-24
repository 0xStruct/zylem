//! Generation 1 proving worker for `zylem-build jobs` output, with programs loaded from a
//! registry directory (`programs/<network>/`) instead of compiled in.
//!
//!   prove leaves PROGRAMS JOBS_DIR OUT_DIR --shard I     prove this shard's leaves
//!   prove aggregate PROGRAMS JOBS_DIR OUT_DIR --shard I  append them into one shard proof
//!   prove join PROGRAMS OUT_DIR SHARD_PROOF... [--groth16]  join shard proofs in order into
//!                                                       the history proof, optionally wrap it
//!   prove check                                         print whether this build can use the GPU
//!
//! Each leaf is proved with the newest program the registry allows for its era and
//! heights, and each join with the newest allowed aggregation. Every proof's `.done` file
//! records the key it was made with, which the next join hands to the aggregation. The
//! claim of every proof must equal the one computed natively, or the worker stops.
//!
//! Proofs made by different workers join as long as their programs are registered, so
//! pods no longer need one shared binary, only the same `PROGRAMS` directory.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    time::Instant,
};

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use sp1_sdk::{
    blocking::{EnvProver, EnvProvingKey, ProveRequest, Prover, ProverClient},
    Elf, HashableKey, ProvingKey, SP1Proof, SP1ProofWithPublicValues, SP1Stdin, SP1VerifyingKey,
};
use zylem_hdr::{Claim, Kind, LeafJob, ANY_ERA};
use zylem_hdr_sp1::{arg, flag, key_hex, positional, InRuntime, RegistryFile};

/// Proving keys of the registered programs this run has used, by program key.
struct Programs<'a> {
    client: &'a EnvProver,
    file: RegistryFile,
    loaded: HashMap<[u32; 8], InRuntime<EnvProvingKey>>,
}

impl<'a> Programs<'a> {
    fn key_for(&self, kind: Kind, era: u8, first: u64, last: u64) -> Result<[u32; 8]> {
        Ok(self.file.program_for(kind, era, first, last)?.entry.key)
    }

    /// Sets up the program registered under `key` from its file, and checks the file
    /// really has that key.
    fn pk(&mut self, key: &[u32; 8]) -> Result<&EnvProvingKey> {
        if !self.loaded.contains_key(key) {
            let l = self.file.by_key(key)?;
            let elf = self.file.elf(l)?;
            let pk = InRuntime::new(self.client.setup(Elf::from(elf))?);
            if pk.verifying_key().hash_u32() != *key {
                bail!("{} does not have its registered key", l.artifact.as_deref().unwrap_or("?"));
            }
            println!("loaded {} ({})", l.artifact.as_deref().unwrap_or("?"), pk.verifying_key().bytes32());
            self.loaded.insert(*key, pk);
        }
        Ok(&self.loaded[key])
    }

    fn vk(&mut self, key: &[u32; 8]) -> Result<SP1VerifyingKey> {
        Ok(self.pk(key)?.verifying_key().clone())
    }
}

/// A proof and the key of the program that made it.
struct Made {
    proof: SP1ProofWithPublicValues,
    key: [u32; 8],
}

impl Made {
    fn claim(&self) -> Result<Claim> {
        Claim::decode(self.proof.public_values.as_slice()).context("not a v2 claim")
    }

    fn load(path: &Path) -> Result<Made> {
        let info: Value = serde_json::from_slice(&std::fs::read(path.with_extension("done")).with_context(|| format!("{} not finished", path.display()))?)?;
        let key = key_from_hex(info["key"].as_str().context("key in .done")?)?;
        Ok(Made { proof: SP1ProofWithPublicValues::load(path).with_context(|| path.display().to_string())?, key })
    }

    fn save(&self, path: &Path, mut info: Value) -> Result<()> {
        self.proof.save(path)?;
        info["key"] = json!(key_hex(&self.key));
        info["covers"] = json!(describe(&self.claim()?));
        std::fs::write(path.with_extension("done"), serde_json::to_string_pretty(&info)? + "\n")?;
        Ok(())
    }
}

fn key_from_hex(s: &str) -> Result<[u32; 8]> {
    let b = hex::decode(s)?;
    if b.len() != 32 {
        bail!("a program key is 32 bytes");
    }
    Ok(std::array::from_fn(|i| u32::from_le_bytes(b[i * 4..i * 4 + 4].try_into().unwrap())))
}

fn done(path: &Path) -> bool {
    path.with_extension("done").exists() && path.exists()
}

fn mock() -> bool {
    std::env::var("SP1_PROVER").is_ok_and(|p| p == "mock")
}

fn describe(c: &Claim) -> String {
    format!("{}..={} ({} leaves, Equihash {})", c.first_height, c.last_height, c.leaves, c.equihash_checked)
}

fn shard_jobs(jobs_dir: &Path, shard: u64) -> Result<Vec<Value>> {
    let m: Value = serde_json::from_slice(&std::fs::read(jobs_dir.join("manifest.json")).context("jobs manifest")?)?;
    Ok(m["jobs"].as_array().context("jobs")?.iter().filter(|j| j["shard"].as_u64() == Some(shard)).cloned().collect())
}

/// Joins two proofs with the newest registered aggregation; `groth16` wraps the result.
fn join(p: &mut Programs, left: &Made, right: &Made, groth16: bool) -> Result<Made> {
    let (lc, rc) = (left.claim()?, right.claim()?);
    let registry = p.file.registry();
    let own = p.key_for(Kind::Aggregate, ANY_ERA, lc.first_height, rc.last_height)?;
    // The aggregation would refuse these children; say why before proving.
    let expected = Claim::join((&lc, &left.key), (&rc, &right.key), &registry, &own)
        .map_err(|why| anyhow::anyhow!("cannot join {} and {}: {why:?}", describe(&lc), describe(&rc)))?;
    let mut s = SP1Stdin::new();
    s.write(&own);
    s.write_vec(registry.encode());
    s.write(&left.key);
    s.write_vec(left.proof.public_values.to_vec());
    s.write(&right.key);
    s.write_vec(right.proof.public_values.to_vec());
    // A mock prover only executes, and rejects mock children as deferred proofs.
    if !mock() {
        for m in [left, right] {
            let SP1Proof::Compressed(inner) = &m.proof.proof else { bail!("child proof is not compressed") };
            let vk = p.vk(&m.key)?;
            s.write_proof((**inner).clone(), vk.vk.clone());
        }
    }
    let client = p.client;
    let vk = p.vk(&own)?;
    let pk = p.pk(&own)?;
    let proof = if groth16 { client.prove(pk, s).groth16().run()? } else { client.prove(pk, s).compressed().run()? };
    client.verify(&proof, &vk, None)?;
    if proof.public_values.as_slice() != expected.encode() {
        bail!("the aggregate's claim differs from the natively computed one");
    }
    Ok(Made { proof, key: own })
}

const VALUE_FLAGS: &[&str] = &["--shard"];

fn main() -> Result<()> {
    let mode = std::env::args().nth(1).context("mode: leaves | aggregate | join | check")?;
    if mode == "check" {
        println!("prove ok (cuda feature: {})", cfg!(feature = "cuda"));
        return Ok(());
    }
    let pos = positional(VALUE_FLAGS);
    let client = InRuntime::new(ProverClient::from_env());
    let file = RegistryFile::load(Path::new(pos.first().context("PROGRAMS")?))?;
    println!("{:?} registry {} ({} entries)", file.network, file.root, file.entries.len());
    let mut p = Programs { client: &client, file, loaded: HashMap::new() };

    match mode.as_str() {
        "leaves" | "aggregate" => {
            let jobs_dir = PathBuf::from(pos.get(1).context("JOBS_DIR")?);
            let out = PathBuf::from(pos.get(2).context("OUT_DIR")?);
            let shard: u64 = arg("--shard").context("--shard")?.parse()?;
            std::fs::create_dir_all(&out)?;
            let jobs = shard_jobs(&jobs_dir, shard)?;
            if mode == "leaves" {
                for (i, j) in jobs.iter().enumerate() {
                    let name = j["name"].as_str().context("name")?;
                    let path = out.join(format!("{name}.proof"));
                    if done(&path) {
                        continue;
                    }
                    let job: LeafJob = bincode::deserialize(&std::fs::read(jobs_dir.join(format!("{name}.job")))?)?;
                    let native = zylem_hdr::run(&job.input, &job.headers).map_err(|(h, f)| anyhow::anyhow!("{name}: header {h} rejected natively: {f:?}"))?;
                    let expected = Claim::leaf(&job.input, &native);
                    let key = p.key_for(Kind::HeaderLeaf, expected.era, expected.first_height, expected.last_height)?;
                    let mut stdin = SP1Stdin::new();
                    stdin.write(&job.input);
                    stdin.write_vec(job.headers);
                    let t = Instant::now();
                    let vk = p.vk(&key)?;
                    let client = p.client;
                    let proof = client.prove(p.pk(&key)?, stdin).compressed().run()?;
                    let secs = t.elapsed().as_secs_f64();
                    client.verify(&proof, &vk, None)?;
                    if proof.public_values.as_slice() != expected.encode() {
                        bail!("{name}: the proof's claim differs from the natively computed one");
                    }
                    Made { proof, key }.save(&path, json!({"name": name, "prove_secs": secs, "program": p.file.by_key(&key)?.artifact}))?;
                    println!("[{}/{}] {name}: era {} in {secs:.1} s", i + 1, jobs.len(), expected.era);
                }
                println!("shard {shard}: {} leaves done", jobs.len());
            } else {
                let path = out.join(format!("shard-{shard}.proof"));
                if done(&path) {
                    println!("shard {shard} already aggregated");
                    return Ok(());
                }
                let t = Instant::now();
                let mut acc: Option<Made> = None;
                for j in &jobs {
                    let name = j["name"].as_str().context("name")?;
                    let leaf = Made::load(&out.join(format!("{name}.proof")))?;
                    acc = Some(match acc {
                        None => leaf,
                        Some(left) => join(&mut p, &left, &leaf, false)?,
                    });
                }
                let m = acc.context("empty shard")?;
                let secs = t.elapsed().as_secs_f64();
                m.save(&path, json!({"shard": shard, "aggregate_secs": secs, "registry": p.file.root}))?;
                println!("shard {shard}: {} in {secs:.1} s", describe(&m.claim()?));
            }
        }
        "join" => {
            let out = PathBuf::from(pos.get(1).context("OUT_DIR")?);
            let parts: Vec<PathBuf> = pos[2..].iter().map(PathBuf::from).collect();
            if parts.len() < 2 {
                bail!("join needs at least two parts");
            }
            std::fs::create_dir_all(&out)?;
            let path = out.join("history.proof");
            let left_path = out.join("history-left.proof");
            if !done(&path) {
                let t = Instant::now();
                let mut acc = Made::load(&parts[0])?;
                for (i, part) in parts.iter().enumerate().skip(1) {
                    if i + 1 == parts.len() {
                        // Kept so a Groth16 wrap can redo this last join.
                        acc.save(&left_path, json!({}))?;
                    }
                    acc = join(&mut p, &acc, &Made::load(part)?, false)?;
                }
                acc.save(&path, json!({"join_secs": t.elapsed().as_secs_f64(), "registry": p.file.root}))?;
            }
            let history = Made::load(&path)?;
            println!("history proof: {} under registry {}", describe(&history.claim()?), hex::encode(history.claim()?.registry_root));
            if flag("--groth16") {
                let gpath = out.join("history.groth16");
                if !done(&gpath) {
                    let t = Instant::now();
                    let g = join(&mut p, &Made::load(&left_path)?, &Made::load(parts.last().unwrap())?, true)?;
                    let secs = t.elapsed().as_secs_f64();
                    std::fs::write(out.join("history.groth16.bytes"), g.proof.bytes())?;
                    g.save(&gpath, json!({"wrap_secs": secs, "bytes": g.proof.bytes().len()}))?;
                    println!("Groth16 wrap: {} bytes in {secs:.1} s", g.proof.bytes().len());
                }
            }
        }
        m => bail!("unknown mode {m}"),
    }
    Ok(())
}
