//! Which SP1 proof a client should verify: proves one aggregate of two leaves, then
//! measures each form a client could receive.
//!
//! - compressed: the STARK the tree is built from (no trusted setup);
//! - PLONK and Groth16: the aggregate wrapped for small proofs and cheap verification.
//!
//! For each: proving time, size, and verification time with the SDK and with the
//! standalone `sp1-verifier` crate (what a wallet or a WASM build would embed). Proofs and
//! public values are written to `--out` for the WASM test.
//!
//! Usage: wrap [RING_DIR] [--headers N] [--reuse] [--mode compressed|plonk|groth16] [--out DIR]
//! PLONK and Groth16 need gnark: build with `--features native-gnark` (Go) or run Docker.

use std::{path::PathBuf, time::Instant};

use anyhow::{bail, Context, Result};
use sp1_sdk::{
    blocking::{ProveRequest, Prover, ProverClient},
    include_elf, Elf, HashableKey, ProvingKey, SP1Proof, SP1ProofWithPublicValues, SP1Stdin,
};
use sp1_verifier::{Groth16Verifier, PlonkVerifier, GROTH16_VK_BYTES, PLONK_VK_BYTES};
use zylem_hdr::{Input, Net, RangeClaim, MAX_CONTEXT};

const LEAF_ELF: Elf = include_elf!("header-chain-leaf");
const AGG_ELF: Elf = include_elf!("header-chain-agg");

fn segment(all: &[(u64, Vec<u8>)], start: usize, count: usize) -> (Input, Vec<u8>) {
    let context = all[start - MAX_CONTEXT..start]
        .iter()
        .map(|(_, h)| (u32::from_le_bytes(h[104..108].try_into().unwrap()), u32::from_le_bytes(h[100..104].try_into().unwrap())))
        .collect();
    let headers = all[start..start + count].iter().flat_map(|(_, h)| h.clone()).collect();
    let input = Input {
        net: Net::Test,
        first_height: all[start].0,
        anchor_hash: zylem_hdr::sha256d(&all[start - 1].1),
        context,
        count: count as u32,
        check_equihash: false,
    };
    (input, headers)
}

fn arg<T: std::str::FromStr>(name: &str) -> Option<T> {
    let args: Vec<String> = std::env::args().collect();
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).and_then(|v| v.parse().ok())
}

fn flag(name: &str) -> bool {
    std::env::args().any(|a| a == name)
}

/// Mean seconds per call over `n` calls.
fn timed(n: u32, mut f: impl FnMut() -> Result<()>) -> Result<f64> {
    let t = Instant::now();
    for _ in 0..n {
        f()?;
    }
    Ok(t.elapsed().as_secs_f64() / n as f64)
}

fn main() -> Result<()> {
    let dir = std::env::args().nth(1).filter(|a| !a.starts_with("--")).map(PathBuf::from).unwrap_or_else(|| PathBuf::from("../../../data/testnet"));
    let n: usize = arg("--headers").unwrap_or(50);
    let mode: String = arg("--mode").unwrap_or_else(|| "compressed".into());
    let out: PathBuf = arg("--out").unwrap_or_else(|| PathBuf::from("../../../../data/wrap"));
    std::fs::create_dir_all(&out)?;
    let all = zylem_hdr_validate::load_headers(&dir)?;
    let start = MAX_CONTEXT + 1_000;
    let client = ProverClient::from_env();
    let leaf_pk = client.setup(LEAF_ELF)?;
    let agg_pk = client.setup(AGG_ELF)?;
    let (leaf_vk, agg_vk) = (leaf_pk.verifying_key().clone(), agg_pk.verifying_key().clone());
    std::fs::write(out.join("agg-vkey.txt"), agg_vk.bytes32())?;
    std::fs::write(out.join("agg-vkey-koalabear.bin"), bincode::serialize(&agg_vk.hash_koalabear())?)?;

    // Two leaves, reused across modes.
    let mut leaves = vec![];
    for (name, s) in [("A", start), ("B", start + n)] {
        let path = out.join(format!("leaf{name}-{n}.bin"));
        let p = if flag("--reuse") && path.exists() {
            SP1ProofWithPublicValues::load(&path)?
        } else {
            let (input, headers) = segment(&all, s, n);
            let mut stdin = SP1Stdin::new();
            stdin.write(&input);
            stdin.write_vec(headers);
            let t = Instant::now();
            let p = client.prove(&leaf_pk, stdin).compressed().run()?;
            println!("leaf {name} ({n} headers) proved in {:.1} s", t.elapsed().as_secs_f64());
            p.save(&path)?;
            p
        };
        leaves.push(p);
    }
    let agg_stdin = || -> Result<SP1Stdin> {
        let mut s = SP1Stdin::new();
        s.write(&agg_vk.hash_u32());
        s.write(&leaf_vk.hash_u32());
        s.write_vec(leaves[0].public_values.to_vec());
        s.write_vec(leaves[1].public_values.to_vec());
        for p in &leaves {
            let SP1Proof::Compressed(inner) = &p.proof else { bail!("leaf proof is not compressed") };
            s.write_proof((**inner).clone(), leaf_vk.vk.clone());
        }
        Ok(s)
    };

    let t = Instant::now();
    let req = client.prove(&agg_pk, agg_stdin()?);
    let proof = match mode.as_str() {
        "compressed" => req.compressed().run()?,
        "plonk" => req.plonk().run()?,
        "groth16" => req.groth16().run()?,
        m => bail!("unknown mode {m}"),
    };
    let prove_secs = t.elapsed().as_secs_f64();
    let pv = proof.public_values.to_vec();
    let claim = RangeClaim::decode(&pv).context("aggregate claim")?;
    proof.save(out.join(format!("agg-{mode}.bin")))?;
    std::fs::write(out.join("public-values.bin"), &pv)?;
    println!(
        "\n{mode}: proved in {prove_secs:.1} s; claim covers {}..={} ({} leaves), public values {} bytes",
        claim.first_height,
        claim.last_height,
        claim.leaves,
        pv.len()
    );

    let sdk_verify = timed(3, || Ok(client.verify(&proof, &agg_vk, None)?))?;
    println!("  SDK verify: {:.1} ms", sdk_verify * 1e3);

    match mode.as_str() {
        "compressed" => {
            let bytes = bincode::serialize(&proof.proof)?;
            std::fs::write(out.join("compressed.proof"), &bytes)?;
            println!("  proof: {} bytes (bincode)", bytes.len());
            let vk = bincode::serialize(&agg_vk.hash_koalabear())?;
            match sp1_verifier::compressed::SP1CompressedVerifierRaw::verify_with_public_values(&bytes, &pv, &vk) {
                Ok(()) => {
                    let s = timed(3, || {
                        sp1_verifier::compressed::SP1CompressedVerifierRaw::verify_with_public_values(&bytes, &pv, &vk)
                            .map_err(|e| anyhow::anyhow!("{e:?}"))
                    })?;
                    println!("  sp1-verifier: {:.1} ms", s * 1e3);
                }
                Err(e) => println!("  sp1-verifier rejects it: {e:?}"),
            }
            let mut bad = pv.clone();
            bad[208 + 31] ^= 1;
            println!(
                "  altered claim: {}",
                match sp1_verifier::compressed::SP1CompressedVerifierRaw::verify_with_public_values(&bytes, &bad, &vk) {
                    Ok(()) => "ACCEPTED".to_string(),
                    Err(e) => format!("rejected ({e:?})"),
                }
            );
        }
        "plonk" | "groth16" => {
            let bytes = proof.bytes();
            std::fs::write(out.join(format!("{mode}.proof")), &bytes)?;
            println!("  proof: {} bytes", bytes.len());
            let vkey = agg_vk.bytes32();
            let verify = |pv: &[u8], vkey: &str| -> Result<()> {
                if mode == "plonk" {
                    PlonkVerifier::verify(&bytes, pv, vkey, &PLONK_VK_BYTES).map_err(|e| anyhow::anyhow!("{e:?}"))
                } else {
                    Groth16Verifier::verify(&bytes, pv, vkey, &GROTH16_VK_BYTES).map_err(|e| anyhow::anyhow!("{e:?}"))
                }
            };
            let s = timed(20, || verify(&pv, &vkey))?;
            println!("  sp1-verifier: {:.2} ms", s * 1e3);
            let mut bad = pv.clone();
            bad[208 + 31] ^= 1;
            println!("  altered claim: {}", verify(&bad, &vkey).map_or_else(|e| format!("rejected ({e})"), |_| "ACCEPTED".into()));
            println!(
                "  leaf program's key instead: {}",
                verify(&pv, &leaf_vk.bytes32()).map_or_else(|e| format!("rejected ({e})"), |_| "ACCEPTED".into())
            );
        }
        _ => unreachable!(),
    }
    Ok(())
}
