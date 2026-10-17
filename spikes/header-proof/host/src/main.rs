//! Runs the header-chain guest on real testnet headers from Zylem Rings: counts cycles per
//! header with and without Equihash, checks the guest's output against a native run, and
//! optionally proves a small batch to measure proving time and receipt size.
//!
//! Usage: zylem-hdr-host [RING_DIR] [--prove N] [--prove-equihash N]

use std::{path::PathBuf, time::Instant};

use anyhow::{bail, Result};
use risc0_zkvm::{default_executor, default_prover, ExecutorEnv, ProverOpts};
use zylem_hdr::{Input, Net, Output, MAX_CONTEXT};
use zylem_hdr_methods::{HEADER_CHAIN_ELF, HEADER_CHAIN_ID};

struct Batch {
    input: Input,
    headers: Vec<u8>,
}

fn batch(all: &[(u64, Vec<u8>)], start: usize, count: usize, check_equihash: bool) -> Batch {
    let context = all[start - MAX_CONTEXT..start]
        .iter()
        .map(|(_, h)| {
            let t = u32::from_le_bytes(h[100..104].try_into().unwrap());
            let b = u32::from_le_bytes(h[104..108].try_into().unwrap());
            (b, t)
        })
        .collect();
    let headers: Vec<u8> = all[start..start + count].iter().flat_map(|(_, h)| h.clone()).collect();
    Batch {
        input: Input {
            net: Net::Test,
            first_height: all[start].0,
            anchor_hash: zylem_hdr::sha256d(&all[start - 1].1),
            context,
            count: count as u32,
            check_equihash,
        },
        headers,
    }
}

fn env(b: &Batch) -> Result<ExecutorEnv<'static>> {
    Ok(ExecutorEnv::builder().write(&b.input)?.write_slice(&b.headers).build()?)
}

/// Executes without proving; returns (total cycles, user cycles, segments).
fn execute(b: &Batch) -> Result<(u64, u64, usize, Output)> {
    let session = default_executor().execute(env(b)?, HEADER_CHAIN_ELF)?;
    let out: Output = session.journal.decode()?;
    let user: u64 = session.segments.iter().map(|s| s.cycles as u64).sum();
    Ok((session.cycles(), user, session.segments.len(), out))
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
        .unwrap_or_else(|| PathBuf::from("../../data/testnet"));
    let all = zylem_hdr_validate::load_headers(&dir)?;
    // Start inside the Rings with a full context window behind it.
    let start = MAX_CONTEXT + 1_000;
    println!("headers from {} (first proven height {})", dir.display(), all[start].0);
    println!("{:>9} {:>8} {:>14} {:>14} {:>8}", "Equihash", "headers", "total cycles", "user cycles", "segments");

    let mut per_header = vec![];
    for equihash in [false, true] {
        let mut points = vec![];
        for n in [1usize, 10, 100] {
            let b = batch(&all, start, n, equihash);
            let (total, user, segments, out) = execute(&b)?;
            // The guest must agree with the same rules run natively.
            let native = zylem_hdr::run(&b.input, &b.headers).map_err(|e| anyhow::anyhow!("native: {e:?}"))?;
            if native != out {
                bail!("guest output differs from the native run");
            }
            println!("{:>9} {:>8} {:>14} {:>14} {:>8}", if equihash { "on" } else { "off" }, n, total, user, segments);
            points.push((n as f64, user as f64));
        }
        let (n1, c1) = points[1];
        let (n2, c2) = points[2];
        per_header.push((equihash, (c2 - c1) / (n2 - n1)));
    }
    println!();
    for (equihash, c) in &per_header {
        println!("marginal user cycles per header, Equihash {}: {:.0}", if *equihash { "on" } else { "off" }, c);
    }
    let (off, on) = (per_header[0].1, per_header[1].1);
    println!("Equihash share of the per-header cost: {:.1}%", 100.0 * (on - off) / on);
    for (label, c) in [("off", off), ("on", on)] {
        println!(
            "per 4,096-block Ring, Equihash {label}: {:.2} billion cycles",
            c * 4096.0 / 1e9
        );
    }

    for (flag, equihash) in [("--prove", false), ("--prove-equihash", true)] {
        let Some(n) = arg(flag) else { continue };
        let b = batch(&all, start, n, equihash);
        println!("\nproving {n} headers (Equihash {}) ...", if equihash { "on" } else { "off" });
        let t = Instant::now();
        let info = default_prover().prove_with_opts(env(&b)?, HEADER_CHAIN_ELF, &ProverOpts::succinct())?;
        let secs = t.elapsed().as_secs_f64();
        info.receipt.verify(HEADER_CHAIN_ID)?;
        let out: Output = info.receipt.journal.decode()?;
        println!(
            "  proved and verified in {secs:.1} s: {} user cycles, {} total, {} segments",
            info.stats.user_cycles, info.stats.total_cycles, info.stats.segments
        );
        println!("  succinct receipt seal: {} bytes; journal {} bytes", info.receipt.seal_size(), info.receipt.journal.bytes.len());
        println!("  proves heights {}..={}, records hash {}", out.first_height, out.last_height, hex::encode(out.records_hash));
    }
    Ok(())
}
