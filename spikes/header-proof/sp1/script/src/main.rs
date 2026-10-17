//! Runs the header-chain program in SP1 on the same testnet headers as the RISC Zero host:
//! instruction counts with and without Equihash, output checked against a native run,
//! and optionally a compressed proof of a small batch.
//!
//! Usage: zylem-hdr-sp1 [RING_DIR] [--prove N] [--prove-equihash N]

use std::{path::PathBuf, time::Instant};

use anyhow::{bail, Result};
use sp1_sdk::{
    blocking::{ProveRequest, Prover, ProverClient},
    include_elf, Elf, ProvingKey, SP1Stdin,
};
use zylem_hdr::{Input, Net, Output, MAX_CONTEXT};

const ELF: Elf = include_elf!("header-chain-sp1");

fn batch(all: &[(u64, Vec<u8>)], start: usize, count: usize, check_equihash: bool) -> (Input, Vec<u8>) {
    let context = all[start - MAX_CONTEXT..start]
        .iter()
        .map(|(_, h)| {
            let t = u32::from_le_bytes(h[100..104].try_into().unwrap());
            let b = u32::from_le_bytes(h[104..108].try_into().unwrap());
            (b, t)
        })
        .collect();
    let headers: Vec<u8> = all[start..start + count].iter().flat_map(|(_, h)| h.clone()).collect();
    let input = Input {
        net: Net::Test,
        first_height: all[start].0,
        anchor_hash: zylem_hdr::sha256d(&all[start - 1].1),
        context,
        count: count as u32,
        check_equihash,
    };
    (input, headers)
}

fn stdin(input: &Input, headers: &[u8]) -> SP1Stdin {
    let mut s = SP1Stdin::new();
    s.write(input);
    s.write_vec(headers.to_vec());
    s
}

fn arg(name: &str) -> Option<usize> {
    let args: Vec<String> = std::env::args().collect();
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).and_then(|v| v.parse().ok())
}

fn main() -> Result<()> {
    let dir = std::env::args()
        .nth(1)
        .filter(|a| !a.starts_with("--"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("../../../data/testnet"));
    let all = zylem_hdr_validate::load_headers(&dir)?;
    // Same starting point as the RISC Zero host.
    let start = MAX_CONTEXT + 1_000;
    let client = ProverClient::from_env();
    println!("SP1 6.9.0, first proven height {}", all[start].0);
    println!("{:>9} {:>8} {:>16} {:>16}", "Equihash", "headers", "instructions", "prover gas");

    let mut per_header = vec![];
    for equihash in [false, true] {
        let mut points = vec![];
        for n in [1usize, 10, 100] {
            let (input, headers) = batch(&all, start, n, equihash);
            let (public, report) = client.execute(ELF, stdin(&input, &headers)).calculate_gas(true).run()?;
            let out: Output = bincode_decode(public.as_slice())?;
            let native = zylem_hdr::run(&input, &headers).map_err(|e| anyhow::anyhow!("native: {e:?}"))?;
            if native != out {
                bail!("SP1 output differs from the native run");
            }
            let count = report.total_instruction_count();
            let gas = report.gas().unwrap_or(0);
            println!("{:>9} {:>8} {:>16} {:>16}", if equihash { "on" } else { "off" }, n, count, gas);
            points.push((n as f64, count as f64, gas as f64));
        }
        let (n1, c1, g1) = points[1];
        let (n2, c2, g2) = points[2];
        per_header.push((equihash, (c2 - c1) / (n2 - n1), (g2 - g1) / (n2 - n1)));
    }
    println!();
    for (equihash, c, g) in &per_header {
        let on = if *equihash { "on" } else { "off" };
        println!("per header, Equihash {on}: {c:.0} instructions, {g:.0} prover gas");
        println!("  per 4,096-block Ring: {:.3} billion instructions, {:.3} billion prover gas", c * 4096.0 / 1e9, g * 4096.0 / 1e9);
    }

    for (flag, equihash) in [("--prove", false), ("--prove-equihash", true)] {
        let Some(n) = arg(flag) else { continue };
        let (input, headers) = batch(&all, start, n, equihash);
        println!("\nproving {n} headers (Equihash {}) ...", if equihash { "on" } else { "off" });
        let pk = client.setup(ELF)?;
        let t = Instant::now();
        let proof = client.prove(&pk, stdin(&input, &headers)).compressed().run()?;
        let secs = t.elapsed().as_secs_f64();
        client.verify(&proof, pk.verifying_key(), None)?;
        let path = std::env::temp_dir().join("zylem-hdr-sp1-proof.bin");
        proof.save(&path)?;
        let bytes = std::fs::metadata(&path)?.len();
        println!("  compressed proof generated and verified in {secs:.1} s; saved proof {bytes} bytes (with public values)");
    }
    Ok(())
}

/// SP1 commits public values with bincode.
fn bincode_decode(bytes: &[u8]) -> Result<Output> {
    let mut pv = sp1_sdk::SP1PublicValues::from(bytes);
    Ok(pv.read::<Output>())
}
