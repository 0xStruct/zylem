//! Proving worker for `zylem-build jobs` output.
//!
//!   prove-jobs leaves JOBS_DIR OUT_DIR --shard I     prove this shard's leaves
//!   prove-jobs aggregate JOBS_DIR OUT_DIR --shard I  append them into one shard proof
//!   prove-jobs join OUT_DIR SHARD_PROOF... [--groth16]  join shard proofs in order into
//!                                                    the history proof, then optionally wrap it
//!   prove-jobs check                                 print whether this build can use the GPU
//!
//! Every step is safe to rerun: a finished proof has a `.done` file next to it and is
//! skipped. Each leaf's published claim must equal the one `zylem-build jobs` computed
//! natively, or the worker stops. `vks.json` records the program keys this binary proves
//! with; proofs from different workers can only be joined if their keys match, so every
//! pod runs the same prebuilt binary.
//!
//! Run with SP1_PROVER=cuda on a GPU machine, built with --features cuda.

use std::{
    path::{Path, PathBuf},
    time::Instant,
};

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use sp1_sdk::{
    blocking::{ProveRequest, Prover, ProverClient},
    include_elf, Elf, HashableKey, ProvingKey, SP1Proof, SP1ProofWithPublicValues, SP1Stdin, SP1VerifyingKey,
};
use zylem_hdr::{LeafJob, RangeClaim};

const LEAF_ELF: Elf = include_elf!("header-chain-leaf");
const AGG_ELF: Elf = include_elf!("header-chain-agg");

/// Keeps the SP1 client and proving keys, which must be dropped inside a tokio runtime
/// (see gpu-bench).
struct InRuntime<T>(Option<T>);

impl<T> InRuntime<T> {
    fn new(value: T) -> Self {
        InRuntime(Some(value))
    }
}

impl<T> std::ops::Deref for InRuntime<T> {
    type Target = T;
    fn deref(&self) -> &T {
        self.0.as_ref().unwrap()
    }
}

impl<T> Drop for InRuntime<T> {
    fn drop(&mut self) {
        match tokio::runtime::Runtime::new() {
            Ok(rt) => {
                let _guard = rt.enter();
                drop(self.0.take());
            }
            Err(_) => std::mem::forget(self.0.take()),
        }
    }
}

fn arg(name: &str) -> Option<String> {
    let args: Vec<String> = std::env::args().collect();
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned()
}

fn flag(name: &str) -> bool {
    std::env::args().any(|a| a == name)
}

fn done(path: &Path) -> bool {
    path.with_extension("done").exists() && path.exists()
}

fn mark_done(path: &Path, info: Value) -> Result<()> {
    std::fs::write(path.with_extension("done"), serde_json::to_string_pretty(&info)? + "\n")?;
    Ok(())
}

fn shard_jobs(jobs_dir: &Path, shard: u64) -> Result<Vec<Value>> {
    let m: Value = serde_json::from_slice(&std::fs::read(jobs_dir.join("manifest.json")).context("jobs manifest")?)?;
    Ok(m["jobs"].as_array().context("jobs")?.iter().filter(|j| j["shard"].as_u64() == Some(shard)).cloned().collect())
}

/// Stdin for one join: the aggregation program's own key, the leaf key, both claims, and
/// both proofs with the key each was made under.
fn join_stdin(
    agg_vk: &SP1VerifyingKey,
    leaf_vk: &SP1VerifyingKey,
    left: &SP1ProofWithPublicValues,
    right: &SP1ProofWithPublicValues,
) -> Result<SP1Stdin> {
    let mut s = SP1Stdin::new();
    s.write(&agg_vk.hash_u32());
    s.write(&leaf_vk.hash_u32());
    s.write_vec(left.public_values.to_vec());
    s.write_vec(right.public_values.to_vec());
    // A mock prover only executes, and rejects mock children as deferred proofs.
    if std::env::var("SP1_PROVER").is_ok_and(|p| p == "mock") {
        return Ok(s);
    }
    for p in [left, right] {
        let claim = RangeClaim::decode(p.public_values.as_slice()).context("child claim")?;
        let vk = if claim.is_leaf() { leaf_vk } else { agg_vk };
        let SP1Proof::Compressed(inner) = &p.proof else { bail!("child proof is not compressed") };
        s.write_proof((**inner).clone(), vk.vk.clone());
    }
    Ok(s)
}

fn describe(p: &SP1ProofWithPublicValues) -> Result<String> {
    let c = RangeClaim::decode(p.public_values.as_slice()).context("claim")?;
    Ok(format!("{}..={} ({} leaves, Equihash {})", c.first_height, c.last_height, c.leaves, c.equihash_checked))
}

fn main() -> Result<()> {
    let mode = std::env::args().nth(1).context("mode: leaves | aggregate | join | check")?;
    if mode == "check" {
        println!("prove-jobs ok (cuda feature: {})", cfg!(feature = "cuda"));
        return Ok(());
    }
    let client = InRuntime::new(ProverClient::from_env());
    let leaf_pk = InRuntime::new(client.setup(LEAF_ELF)?);
    let agg_pk = InRuntime::new(client.setup(AGG_ELF)?);
    let (leaf_vk, agg_vk) = (leaf_pk.verifying_key().clone(), agg_pk.verifying_key().clone());
    let vks = json!({
        "leaf": {"bytes32": leaf_vk.bytes32(), "hash_u32": leaf_vk.hash_u32()},
        "aggregation": {"bytes32": agg_vk.bytes32(), "hash_u32": agg_vk.hash_u32(),
                         "koalabear_bincode_hex": hex::encode(bincode::serialize(&agg_vk.hash_koalabear())?)},
        "sp1_version": sp1_sdk::SP1_CIRCUIT_VERSION,
    });
    println!("leaf program {}\naggregation program {}", leaf_vk.bytes32(), agg_vk.bytes32());

    match mode.as_str() {
        "leaves" | "aggregate" => {
            let jobs_dir = PathBuf::from(std::env::args().nth(2).context("JOBS_DIR")?);
            let out = PathBuf::from(std::env::args().nth(3).context("OUT_DIR")?);
            let shard: u64 = arg("--shard").context("--shard")?.parse()?;
            std::fs::create_dir_all(&out)?;
            std::fs::write(out.join("vks.json"), serde_json::to_string_pretty(&vks)? + "\n")?;
            let jobs = shard_jobs(&jobs_dir, shard)?;
            if mode == "leaves" {
                for (i, j) in jobs.iter().enumerate() {
                    let name = j["name"].as_str().context("name")?;
                    let path = out.join(format!("{name}.proof"));
                    if done(&path) {
                        continue;
                    }
                    let job: LeafJob = bincode::deserialize(&std::fs::read(jobs_dir.join(format!("{name}.job")))?)?;
                    let mut stdin = SP1Stdin::new();
                    stdin.write(&job.input);
                    stdin.write_vec(job.headers);
                    let t = Instant::now();
                    let p = client.prove(&leaf_pk, stdin).compressed().run()?;
                    let secs = t.elapsed().as_secs_f64();
                    client.verify(&p, &leaf_vk, None)?;
                    if hex::encode(p.public_values.as_slice()) != j["claim"].as_str().unwrap_or_default() {
                        bail!("{name}: the proof's claim differs from the natively computed one");
                    }
                    p.save(&path)?;
                    mark_done(&path, json!({"name": name, "prove_secs": secs, "leaf_vk": leaf_vk.bytes32()}))?;
                    println!("[{}/{}] {name}: {secs:.1} s", i + 1, jobs.len());
                }
                println!("shard {shard}: {} leaves done", jobs.len());
            } else {
                let path = out.join(format!("shard-{shard}.proof"));
                if done(&path) {
                    println!("shard {shard} already aggregated");
                    return Ok(());
                }
                let mut acc: Option<SP1ProofWithPublicValues> = None;
                let t = Instant::now();
                for j in &jobs {
                    let name = j["name"].as_str().context("name")?;
                    let leaf = SP1ProofWithPublicValues::load(out.join(format!("{name}.proof")))
                        .with_context(|| format!("{name} not proved yet"))?;
                    acc = Some(match acc {
                        None => leaf,
                        Some(left) => {
                            let p = client.prove(&agg_pk, join_stdin(&agg_vk, &leaf_vk, &left, &leaf)?).compressed().run()?;
                            client.verify(&p, &agg_vk, None)?;
                            p
                        }
                    });
                }
                let p = acc.context("empty shard")?;
                p.save(&path)?;
                let secs = t.elapsed().as_secs_f64();
                mark_done(&path, json!({"shard": shard, "covers": describe(&p)?, "aggregate_secs": secs, "agg_vk": agg_vk.bytes32()}))?;
                println!("shard {shard}: {} in {secs:.1} s", describe(&p)?);
            }
        }
        "join" => {
            let out = PathBuf::from(std::env::args().nth(2).context("OUT_DIR")?);
            let parts: Vec<PathBuf> = std::env::args().skip(3).filter(|a| !a.starts_with("--")).map(PathBuf::from).collect();
            std::fs::write(out.join("vks.json"), serde_json::to_string_pretty(&vks)? + "\n")?;
            let path = out.join("history.proof");
            let history = if done(&path) {
                SP1ProofWithPublicValues::load(&path)?
            } else {
                let t = Instant::now();
                let mut acc: Option<SP1ProofWithPublicValues> = None;
                for (i, part) in parts.iter().enumerate() {
                    let p = SP1ProofWithPublicValues::load(part).with_context(|| part.display().to_string())?;
                    acc = Some(match acc {
                        None => p,
                        Some(left) => {
                            if i + 1 == parts.len() {
                                // Kept so a Groth16 wrap can redo this last join.
                                left.save(out.join("history-left.proof"))?;
                            }
                            let j = client.prove(&agg_pk, join_stdin(&agg_vk, &leaf_vk, &left, &p)?).compressed().run()?;
                            client.verify(&j, &agg_vk, None)?;
                            j
                        }
                    });
                }
                let p = acc.context("nothing to join")?;
                p.save(&path)?;
                mark_done(&path, json!({"covers": describe(&p)?, "join_secs": t.elapsed().as_secs_f64(), "agg_vk": agg_vk.bytes32()}))?;
                p
            };
            println!("history proof: {}", describe(&history)?);
            if flag("--groth16") {
                let gpath = out.join("history.groth16");
                if !done(&gpath) {
                    // Wrapping proves the aggregation once more in Groth16 mode, over the
                    // same last join, so it reuses that join's inputs.
                    let t = Instant::now();
                    let claim = RangeClaim::decode(history.public_values.as_slice()).context("history claim")?;
                    let g = if claim.leaves == 1 {
                        bail!("a single leaf is not a history proof")
                    } else {
                        // Re-run the final join in Groth16 mode.
                        let (left, right) = last_two(&parts, &out)?;
                        client.prove(&agg_pk, join_stdin(&agg_vk, &leaf_vk, &left, &right)?).groth16().run()?
                    };
                    let secs = t.elapsed().as_secs_f64();
                    client.verify(&g, &agg_vk, None)?;
                    g.save(&gpath)?;
                    std::fs::write(out.join("history.groth16.bytes"), g.bytes())?;
                    mark_done(&gpath, json!({"wrap_secs": secs, "bytes": g.bytes().len()}))?;
                    println!("Groth16 wrap: {} bytes in {secs:.1} s", g.bytes().len());
                }
            }
        }
        m => bail!("unknown mode {m}"),
    }
    Ok(())
}

/// The two inputs of the history proof's last join: everything before the last part,
/// joined (saved as `history-left.proof`), and the last part.
fn last_two(parts: &[PathBuf], out: &Path) -> Result<(SP1ProofWithPublicValues, SP1ProofWithPublicValues)> {
    let left = out.join("history-left.proof");
    let right = SP1ProofWithPublicValues::load(parts.last().context("parts")?)?;
    Ok((SP1ProofWithPublicValues::load(&left).context("history-left.proof (kept by the join)")?, right))
}
