//! Proves two linked header-chain segments in SP1 and measures each link, then checks
//! that broken links are rejected.
//!
//! Usage: chain [RING_DIR] [--headers N] [--skip-proving]

use std::{path::PathBuf, time::Instant};

use anyhow::{bail, Context, Result};
use sp1_sdk::{
    blocking::{ProveRequest, Prover, ProverClient},
    include_elf, Elf, HashableKey, ProvingKey, SP1Proof, SP1ProofWithPublicValues, SP1Stdin,
};
use zylem_hdr::{ChainState, Input, Net, MAX_CONTEXT};

const LINK_ELF: Elf = include_elf!("header-chain-link");

fn segment(all: &[(u64, Vec<u8>)], start: usize, count: usize) -> (Input, Vec<u8>) {
    let context = all[start - MAX_CONTEXT..start]
        .iter()
        .map(|(_, h)| {
            (
                u32::from_le_bytes(h[104..108].try_into().unwrap()),
                u32::from_le_bytes(h[100..104].try_into().unwrap()),
            )
        })
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

/// Stdin for one link; `prev` is the previous link's proof, if any.
fn link_stdin(vk: &sp1_sdk::SP1VerifyingKey, prev: Option<&SP1ProofWithPublicValues>, prev_pv: &[u8], input: &Input, headers: &[u8]) -> Result<SP1Stdin> {
    link_stdin_claiming(vk.hash_u32(), vk, prev, prev_pv, input, headers)
}

/// As `link_stdin`, but telling the guest its key digest is `claimed`.
fn link_stdin_claiming(
    claimed: [u32; 8],
    vk: &sp1_sdk::SP1VerifyingKey,
    prev: Option<&SP1ProofWithPublicValues>,
    prev_pv: &[u8],
    input: &Input,
    headers: &[u8],
) -> Result<SP1Stdin> {
    let mut s = SP1Stdin::new();
    s.write(&claimed);
    s.write_vec(prev_pv.to_vec());
    s.write(input);
    s.write_vec(headers.to_vec());
    if let Some(p) = prev {
        let SP1Proof::Compressed(proof) = &p.proof else { bail!("previous proof is not compressed") };
        s.write_proof((**proof).clone(), vk.vk.clone());
    }
    Ok(s)
}

fn arg(name: &str) -> Option<usize> {
    let args: Vec<String> = std::env::args().collect();
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).and_then(|v| v.parse().ok())
}

fn saved_size(p: &SP1ProofWithPublicValues, name: &str) -> Result<u64> {
    let path = std::env::temp_dir().join(name);
    p.save(&path)?;
    Ok(std::fs::metadata(&path)?.len())
}

fn main() -> Result<()> {
    let dir = std::env::args()
        .nth(1)
        .filter(|a| !a.starts_with("--"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("../../../data/testnet"));
    let n = arg("--headers").unwrap_or(100);
    let all = zylem_hdr_validate::load_headers(&dir)?;
    let start = MAX_CONTEXT + 1_000;
    let client = ProverClient::from_env();
    let pk = client.setup(LINK_ELF)?;
    let vk = pk.verifying_key().clone();
    println!("link program vk digest {}", vk.bytes32());

    let (in1, h1) = segment(&all, start, n);
    let (in2, h2) = segment(&all, start + n, n);
    println!("segment 1: heights {}..={}; segment 2: heights {}..={}", in1.first_height, in1.first_height + n as u64 - 1, in2.first_height, in2.first_height + n as u64 - 1);

    // Execution only: instruction counts with and without a previous proof to verify.
    let (pv1_exec, r1) = client.execute(LINK_ELF, link_stdin(&vk, None, &[], &in1, &h1)?).run()?;
    let state1_exec = ChainState::decode(pv1_exec.as_slice()).context("state 1")?;
    println!("link 1 executes in {} instructions", r1.total_instruction_count());

    if std::env::args().any(|a| a == "--skip-proving") {
        return Ok(());
    }
    if std::env::args().any(|a| a == "--broken-only") {
        let p1 = SP1ProofWithPublicValues::load(std::env::temp_dir().join("zylem-link1.bin"))?;
        return broken_links(&client, &pk, &vk, &all, start, n, &p1);
    }

    // Link 1: no previous proof; its anchor becomes the chain's checkpoint.
    let t = Instant::now();
    let p1 = client.prove(&pk, link_stdin(&vk, None, &[], &in1, &h1)?).compressed().run()?;
    let t1 = t.elapsed().as_secs_f64();
    client.verify(&p1, &vk, None)?;
    let s1 = ChainState::decode(p1.public_values.as_slice()).context("state 1")?;
    assert_eq!(s1, state1_exec);
    println!("link 1 proved and verified in {t1:.1} s, saved proof {} B", saved_size(&p1, "zylem-link1.bin")?);

    // Link 2: verifies link 1 inside the zkVM.
    let pv1 = p1.public_values.to_vec();
    let (_, r2) = client.execute(LINK_ELF, link_stdin(&vk, Some(&p1), &pv1, &in2, &h2)?).run()?;
    println!("link 2 executes in {} instructions", r2.total_instruction_count());
    let t = Instant::now();
    let p2 = client.prove(&pk, link_stdin(&vk, Some(&p1), &pv1, &in2, &h2)?).compressed().run()?;
    let t2 = t.elapsed().as_secs_f64();
    client.verify(&p2, &vk, None)?;
    let s2 = ChainState::decode(p2.public_values.as_slice()).context("state 2")?;
    println!("link 2 proved and verified in {t2:.1} s, saved proof {} B", saved_size(&p2, "zylem-link2.bin")?);

    // What a client checks: its trusted program and checkpoint, and the extended state.
    assert_eq!(s2.vk, vk.hash_u32());
    assert_eq!((s2.checkpoint_height, s2.checkpoint_hash), (in1.first_height - 1, in1.anchor_hash));
    assert_eq!(s2.segments, 2);
    assert_eq!(s2.last_hash, zylem_hdr::sha256d(&all[start + 2 * n - 1].1));
    println!(
        "chain state after 2 links: heights {}..={}, last hash {}, {} segments",
        s2.checkpoint_height + 1,
        s2.last_height,
        hex::encode(s2.last_hash),
        s2.segments
    );
    println!("extra proving time for verifying the previous link: {:.1} s", t2 - t1);

    broken_links(&client, &pk, &vk, &all, start, n, &p1)
}

/// Each way of breaking the chain must stop the link: the guest exits non-zero (and a
/// non-zero exit code can neither verify nor be built on), or proving fails.
fn broken_links<P: Prover>(
    client: &P,
    pk: &P::ProvingKey,
    vk: &sp1_sdk::SP1VerifyingKey,
    all: &[(u64, Vec<u8>)],
    start: usize,
    n: usize,
    p1: &SP1ProofWithPublicValues,
) -> Result<()> {
    let pv1 = p1.public_values.to_vec();
    let (in2, h2) = segment(all, start + n, n);
    println!("\nbroken links:");
    let verdict = |code: u64| if code == 0 { "ACCEPTED".to_string() } else { format!("rejected (guest exit code {code})") };

    // A segment that skips a block after link 1.
    let (in_gap, h_gap) = segment(all, start + n + 1, n);
    let (_, r) = client.execute(LINK_ELF, link_stdin(vk, Some(p1), &pv1, &in_gap, &h_gap)?).run()?;
    println!("  segment skipping a block after link 1: {}", verdict(r.exit_code));

    // Claiming link 1 came from a different program.
    let mut other_vk = vk.hash_u32();
    other_vk[0] ^= 1;
    let (_, r) = client.execute(LINK_ELF, link_stdin_claiming(other_vk, vk, Some(p1), &pv1, &in2, &h2)?).run()?;
    println!("  link 2 claiming a different program key: {}", verdict(r.exit_code));

    // A previous state the proof does not attest to: inflated work.
    let mut forged = pv1.clone();
    forged[144] ^= 0x01;
    let exec = client.execute(LINK_ELF, link_stdin(vk, Some(p1), &forged, &in2, &h2)?).run();
    match exec {
        Err(e) => println!("  previous state altered (work), execution: rejected ({})", e.to_string().lines().next().unwrap_or("")),
        Ok((_, r)) => println!("  previous state altered (work), execution: {}", verdict(r.exit_code)),
    }
    let proved = client.prove(pk, link_stdin(vk, Some(p1), &forged, &in2, &h2)?).compressed().run();
    println!("  previous state altered (work), proving: {}", match proved {
        Err(e) => format!("rejected ({})", e.to_string().lines().next().unwrap_or("")),
        Ok(p) => match client.verify(&p, vk, None) {
            Ok(()) => "ACCEPTED".into(),
            Err(e) => format!("proof produced but fails verification ({e})"),
        },
    });
    Ok(())
}
