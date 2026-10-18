//! GPU benchmark for the header-chain leaf and aggregation programs.
//!
//! Proves leaves of several sizes with and without Equihash, then one aggregation of two
//! leaves, on real testnet headers. Records proving time, instructions, prover gas, proof
//! size and peak GPU memory, writes one JSON line per test, and projects the cost of
//! backfilling every mainnet header since NU5 at the given hourly price.
//!
//! Usage (SP1_PROVER=cuda on a GPU machine, built with --features cuda):
//!   gpu-bench RING_DIR --price 0.99 [--gpu-name NAME] [--sizes-off 100,1024,4096]
//!             [--sizes-on 100,256,512] [--agg-size 100] [--out results.jsonl]

use std::{
    io::Write,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use anyhow::{bail, Context, Result};
use serde_json::json;
use sp1_sdk::{
    blocking::{ProveRequest, Prover, ProverClient},
    include_elf, Elf, HashableKey, ProvingKey, SP1Proof, SP1ProofWithPublicValues, SP1Stdin,
};
use zylem_hdr::{Input, Net, RangeClaim, MAX_CONTEXT};

const LEAF_ELF: Elf = include_elf!("header-chain-leaf");
const AGG_ELF: Elf = include_elf!("header-chain-agg");

/// Mainnet headers since NU5 activation (1,687,104 to about 3,525,000).
const BACKFILL_HEADERS: f64 = 1_838_000.0;
/// One aggregation per leaf, less one, for about 450 leaves of 4,096 headers.
const BACKFILL_AGGREGATIONS: f64 = 449.0;

struct Args {
    dir: PathBuf,
    price: f64,
    gpu: String,
    sizes_off: Vec<usize>,
    sizes_on: Vec<usize>,
    agg_size: usize,
    out: PathBuf,
    network_price: f64,
}

fn parse() -> Result<Args> {
    let a: Vec<String> = std::env::args().collect();
    let get = |name: &str| a.iter().position(|x| x == name).and_then(|i| a.get(i + 1)).cloned();
    let list = |name: &str, default: &str| -> Result<Vec<usize>> {
        get(name)
            .unwrap_or_else(|| default.into())
            .split(',')
            .filter(|s| !s.is_empty())
            .map(|s| s.parse().context("bad size"))
            .collect()
    };
    Ok(Args {
        dir: a.get(1).filter(|x| !x.starts_with("--")).map(PathBuf::from).unwrap_or_else(|| "../../../data/testnet".into()),
        price: get("--price").map(|p| p.parse()).transpose()?.unwrap_or(0.0),
        gpu: get("--gpu-name").unwrap_or_else(|| "unknown".into()),
        sizes_off: list("--sizes-off", "100,1024,4096")?,
        sizes_on: list("--sizes-on", "100,256,512")?,
        agg_size: get("--agg-size").map(|p| p.parse()).transpose()?.unwrap_or(100),
        out: get("--out").map(PathBuf::from).unwrap_or_else(|| "gpu-bench-results.jsonl".into()),
        // Succinct network, USD per billion prover gas (0.633 PROVE at $0.189, 2026-10-21).
        network_price: get("--network-price").map(|p| p.parse()).transpose()?.unwrap_or(0.12),
    })
}

/// Samples GPU memory in use while a test runs; the peak is read when it stops.
struct VramSampler {
    peak: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

fn gpu_memory_mib() -> Option<u64> {
    let out = std::process::Command::new("nvidia-smi")
        .args(["--query-gpu=memory.used", "--format=csv,noheader,nounits"])
        .output()
        .ok()?;
    String::from_utf8(out.stdout).ok()?.lines().filter_map(|l| l.trim().parse::<u64>().ok()).max()
}

impl VramSampler {
    fn start() -> Self {
        let peak = Arc::new(AtomicU64::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let (p, s) = (peak.clone(), stop.clone());
        let handle = std::thread::spawn(move || {
            while !s.load(Ordering::Relaxed) {
                if let Some(m) = gpu_memory_mib() {
                    p.fetch_max(m, Ordering::Relaxed);
                }
                std::thread::sleep(Duration::from_millis(250));
            }
        });
        VramSampler { peak, stop, handle: Some(handle) }
    }

    fn finish(mut self) -> Option<u64> {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
        let p = self.peak.load(Ordering::Relaxed);
        (p > 0).then_some(p)
    }
}

/// Holds an SP1 client or proving key and drops it inside a tokio runtime. sp1-cuda's
/// destructors release the key and stop its GPU server with `tokio::spawn`, which panics
/// outside a runtime, and the blocking SDK keeps its own runtime private. Without this the
/// process aborts on exit and leaves `sp1-gpu-server` running.
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
            Err(e) => {
                eprintln!("no tokio runtime for cleanup ({e}); leaking the SP1 handle");
                std::mem::forget(self.0.take());
            }
        }
    }
}

fn segment(all: &[(u64, Vec<u8>)], start: usize, count: usize, check_equihash: bool) -> Result<(Input, Vec<u8>)> {
    if start + count > all.len() {
        bail!("not enough headers in the Ring bundle for {count} headers");
    }
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
    Ok((
        Input {
            net: Net::Test,
            first_height: all[start].0,
            anchor_hash: zylem_hdr::sha256d(&all[start - 1].1),
            context,
            count: count as u32,
            check_equihash,
        },
        headers,
    ))
}

fn leaf_stdin(input: &Input, headers: &[u8]) -> SP1Stdin {
    let mut s = SP1Stdin::new();
    s.write(input);
    s.write_vec(headers.to_vec());
    s
}

/// Appends one result as a JSON line and keeps it for the summary.
fn record(rows: &mut Vec<serde_json::Value>, row: serde_json::Value, out: &mut std::fs::File) -> Result<()> {
    writeln!(out, "{row}")?;
    rows.push(row);
    Ok(())
}

fn proof_size(p: &SP1ProofWithPublicValues) -> Result<u64> {
    let path = std::env::temp_dir().join("zylem-gpu-bench-proof.bin");
    p.save(&path)?;
    Ok(std::fs::metadata(&path)?.len())
}

fn main() -> Result<()> {
    // `--check`: the binary loads and runs on this machine (used by setup.sh to decide
    // whether a prebuilt binary can be reused).
    if std::env::args().any(|a| a == "--check") {
        println!("gpu-bench ok (cuda feature: {})", cfg!(feature = "cuda"));
        return Ok(());
    }
    let args = parse()?;
    let all = zylem_hdr_validate::load_headers(&args.dir)?;
    let start = MAX_CONTEXT + 1_000;
    let mut out = std::fs::OpenOptions::new().create(true).append(true).open(&args.out)?;
    let backend = std::env::var("SP1_PROVER").unwrap_or_else(|_| "cpu".into());
    println!("gpu-bench: backend {backend}, GPU {}, price ${}/h, {} headers loaded", args.gpu, args.price, all.len());

    let client = InRuntime::new(ProverClient::from_env());
    let leaf_pk = InRuntime::new(client.setup(LEAF_ELF)?);
    let agg_pk = InRuntime::new(client.setup(AGG_ELF)?);
    let leaf_vk = leaf_pk.verifying_key().clone();
    let agg_vk = agg_pk.verifying_key().clone();

    // Warm-up: first use downloads and starts the GPU server and loads kernels.
    let t = Instant::now();
    let (wi, wh) = segment(&all, start, 10, false)?;
    client.prove(&leaf_pk, leaf_stdin(&wi, &wh)).compressed().run()?;
    println!("warm-up (10 headers, not counted): {:.1} s", t.elapsed().as_secs_f64());

    let mut rows: Vec<serde_json::Value> = vec![];

    let tests: Vec<(usize, bool)> = args
        .sizes_off
        .iter()
        .map(|&n| (n, false))
        .chain(args.sizes_on.iter().map(|&n| (n, true)))
        .collect();
    println!("\n{:>8} {:>8} {:>10} {:>14} {:>14} {:>10} {:>10} {:>12}", "headers", "Equihash", "prove s", "instructions", "prover gas", "MHz", "VRAM MiB", "s/header");
    for (n, equihash) in tests {
        let (input, headers) = segment(&all, start, n, equihash)?;
        let (_, report) = client.execute(LEAF_ELF, leaf_stdin(&input, &headers)).calculate_gas(true).run()?;
        let instructions = report.total_instruction_count();
        let gas = report.gas().unwrap_or(0);
        let sampler = VramSampler::start();
        let t = Instant::now();
        let proof = client.prove(&leaf_pk, leaf_stdin(&input, &headers)).compressed().run()?;
        let secs = t.elapsed().as_secs_f64();
        let vram = sampler.finish();
        client.verify(&proof, &leaf_vk, None)?;
        let bytes = proof_size(&proof)?;
        let mhz = instructions as f64 / secs / 1e6;
        println!(
            "{:>8} {:>8} {:>10.1} {:>14} {:>14} {:>10.2} {:>10} {:>12.4}",
            n,
            if equihash { "on" } else { "off" },
            secs,
            instructions,
            gas,
            mhz,
            vram.map(|v| v.to_string()).unwrap_or_else(|| "-".into()),
            secs / n as f64
        );
        record(
            &mut rows,
            json!({"test": "leaf", "gpu": args.gpu, "backend": backend, "headers": n, "equihash": equihash,
                   "prove_secs": secs, "instructions": instructions, "prover_gas": gas, "mhz": mhz,
                   "peak_vram_mib": vram, "proof_bytes": bytes}),
            &mut out,
        )?;
    }

    // One aggregation of two adjacent leaves (no Equihash: aggregation never re-runs it).
    let (ia, ha) = segment(&all, start, args.agg_size, false)?;
    let (ib, hb) = segment(&all, start + args.agg_size, args.agg_size, false)?;
    let pa = client.prove(&leaf_pk, leaf_stdin(&ia, &ha)).compressed().run()?;
    let pb = client.prove(&leaf_pk, leaf_stdin(&ib, &hb)).compressed().run()?;
    let mut s = SP1Stdin::new();
    s.write(&agg_vk.hash_u32());
    s.write(&leaf_vk.hash_u32());
    s.write_vec(pa.public_values.to_vec());
    s.write_vec(pb.public_values.to_vec());
    for p in [&pa, &pb] {
        let SP1Proof::Compressed(inner) = &p.proof else { bail!("leaf proof is not compressed") };
        s.write_proof((**inner).clone(), leaf_vk.vk.clone());
    }
    let sampler = VramSampler::start();
    let t = Instant::now();
    let agg = client.prove(&agg_pk, s).compressed().run()?;
    let agg_secs = t.elapsed().as_secs_f64();
    let agg_vram = sampler.finish();
    client.verify(&agg, &agg_vk, None)?;
    let claim = RangeClaim::decode(agg.public_values.as_slice()).context("aggregate claim")?;
    println!("\naggregation of two {}-header leaves: {agg_secs:.1} s, {} leaves joined", args.agg_size, claim.leaves);
    record(
        &mut rows,
        json!({"test": "aggregation", "gpu": args.gpu, "backend": backend, "prove_secs": agg_secs,
               "peak_vram_mib": agg_vram, "proof_bytes": proof_size(&agg)?}),
        &mut out,
    )?;

    // Projection from the largest Equihash leaf measured.
    let best = rows
        .iter()
        .filter(|r| r["test"] == "leaf" && r["equihash"] == true)
        .max_by_key(|r| r["headers"].as_u64().unwrap_or(0));
    if let Some(b) = best {
        let per_header = b["prove_secs"].as_f64().unwrap() / b["headers"].as_f64().unwrap();
        let gas_per_header = b["prover_gas"].as_f64().unwrap() / b["headers"].as_f64().unwrap();
        let gpu_hours = (per_header * BACKFILL_HEADERS + agg_secs * BACKFILL_AGGREGATIONS) / 3600.0;
        let network = gas_per_header * BACKFILL_HEADERS / 1e9 * args.network_price;
        println!("\nprojection from the {}-header Equihash leaf:", b["headers"]);
        println!("  {:.4} s and ${:.6} per header at ${}/h", per_header, per_header / 3600.0 * args.price, args.price);
        println!(
            "  backfill since NU5 ({} headers + {} aggregations): {:.0} GPU-hours = ${:.0}",
            BACKFILL_HEADERS, BACKFILL_AGGREGATIONS, gpu_hours, gpu_hours * args.price
        );
        println!("  same work on the Succinct network at ${}/billion prover gas: ${:.0}", args.network_price, network);
        record(
            &mut rows,
            json!({"test": "projection", "gpu": args.gpu, "price_per_hour": args.price,
                   "secs_per_header": per_header, "backfill_gpu_hours": gpu_hours,
                   "backfill_cost": gpu_hours * args.price, "network_cost": network}),
            &mut out,
        )?;
    }
    println!("\nresults appended to {}", args.out.display());
    Ok(())
}
