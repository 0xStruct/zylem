//! Replays a node's header chain through Zylem's header rules: every link, Equihash
//! solution, target, difficulty adjustment and time rule, without storing the headers.
//! Optionally checks block hashes against a checkpoint list (`height hash` per line, as
//! Zakura's `main-checkpoints.txt` / `test-checkpoints.txt`) and writes each header's
//! `(bits, time, hash)` for differential tests.

use std::{collections::BTreeMap, io::Write, path::Path, time::Instant};

use anyhow::{bail, Context, Result};
use futures::{stream, StreamExt};
use zcash_protocol::consensus::{Network, NetworkUpgrade, Parameters};
use zylem_header::{check_contextual, check_equihash_solution, context_needed, expand, sha256d, Net, MAX_CONTEXT};

use crate::node::Node;

/// Headers per fetch; two fetches run ahead of the checks.
const CHUNK: u64 = 2_000;

pub struct Options<'a> {
    pub from: u64,
    pub to: Option<u64>,
    pub equihash: bool,
    pub checkpoints: Option<&'a Path>,
    pub out: Option<&'a Path>,
}

fn net(network: &Network) -> Net {
    match network {
        Network::MainNetwork => Net::Main,
        Network::TestNetwork => Net::Test,
    }
}

fn read_checkpoints(path: &Path) -> Result<BTreeMap<u64, [u8; 32]>> {
    let mut out = BTreeMap::new();
    for line in std::fs::read_to_string(path)?.lines().filter(|l| !l.trim().is_empty()) {
        let (h, hash) = line.split_once(char::is_whitespace).with_context(|| format!("checkpoint line {line:?}"))?;
        let mut hash: [u8; 32] = hex::decode(hash.trim())?.try_into().map_err(|_| anyhow::anyhow!("bad hash"))?;
        hash.reverse();
        out.insert(h.parse()?, hash);
    }
    Ok(out)
}

/// Equihash for a chunk of headers on every core; returns the first failing height.
fn equihash_chunk(first: u64, headers: &[Vec<u8>]) -> Option<u64> {
    let threads = std::thread::available_parallelism().map_or(4, |n| n.get());
    let per = headers.len().div_ceil(threads).max(1);
    std::thread::scope(|s| {
        let jobs: Vec<_> = headers
            .chunks(per)
            .enumerate()
            .map(|(i, c)| {
                s.spawn(move || {
                    c.iter()
                        .position(|h| check_equihash_solution(h).is_err())
                        .map(|j| first + (i * per + j) as u64)
                })
            })
            .collect();
        jobs.into_iter().filter_map(|j| j.join().unwrap()).min()
    })
}

pub async fn run(node: &Node, network: &Network, o: Options<'_>) -> Result<()> {
    let n = net(network);
    let tip = match o.to {
        Some(t) => t,
        None => node.tip().await?,
    };
    // Context for the first checked header comes from the headers just before it.
    let start = o.from.saturating_sub(MAX_CONTEXT as u64).max(1);
    let checkpoints = o.checkpoints.map(read_checkpoints).transpose()?.unwrap_or_default();
    let mut out = o
        .out
        .map(|p| -> Result<_> {
            let mut f = std::io::BufWriter::new(std::fs::File::create(p)?);
            // Header: first height, then 40 bytes a header: bits, time (LE u32), hash.
            f.write_all(&start.to_le_bytes())?;
            Ok(f)
        })
        .transpose()?;
    println!(
        "replaying {} headers {start}..={tip}, rules checked from {} (Equihash {})",
        network_name(network),
        o.from,
        if o.equihash { "on" } else { "off" }
    );
    let upgrades: Vec<(NetworkUpgrade, u64)> = [
        NetworkUpgrade::Blossom,
        NetworkUpgrade::Heartwood,
        NetworkUpgrade::Canopy,
        NetworkUpgrade::Nu5,
        NetworkUpgrade::Nu6,
        NetworkUpgrade::Nu6_1,
        NetworkUpgrade::Nu6_2,
        NetworkUpgrade::Nu6_3,
        NetworkUpgrade::Nu7,
    ]
    .into_iter()
    .filter_map(|u| Some((u, u64::from(network.activation_height(u)?))))
    .filter(|(_, h)| (o.from..=tip).contains(h))
    .collect();

    let started = Instant::now();
    let mut prev_hash: Option<[u8; 32]> = None;
    let mut ctx: Vec<(u32, u32)> = Vec::with_capacity(MAX_CONTEXT + 1);
    let mut newest_first: Vec<(u32, u32)> = Vec::with_capacity(MAX_CONTEXT);
    let (mut checked, mut min_difficulty, mut cps_matched) = (0u64, 0u64, 0usize);
    let min_bits = zylem_header::to_compact(n.limit());
    let starts: Vec<u64> = (start..=tip).step_by(CHUNK as usize).collect();
    let mut fetches = stream::iter(starts)
        .map(|s| {
            let e = (s + CHUNK - 1).min(tip);
            async move { node.headers(s, e).await.map(|h| (s, h)) }
        })
        .buffered(2);
    let mut last_report = Instant::now();
    while let Some(res) = fetches.next().await {
        let (first, headers) = res?;
        if o.equihash {
            if let Some(h) = equihash_chunk(first, &headers) {
                bail!("header {h}: invalid Equihash solution");
            }
        }
        for (i, header) in headers.iter().enumerate() {
            let height = first + i as u64;
            if zylem_header::check_encoding(header).is_err() {
                bail!("header {height}: not a 1,487-byte header with a 1,344-byte solution");
            }
            if let Some(p) = prev_hash {
                if header[4..36] != p {
                    bail!("header {height} does not link to {}", height - 1);
                }
            }
            let time = u32::from_le_bytes(header[100..104].try_into().unwrap());
            let bits = u32::from_le_bytes(header[104..108].try_into().unwrap());
            let hash = sha256d(header);
            let target = expand(bits).with_context(|| format!("header {height}: invalid nBits"))?;
            if target > n.limit() || primitive_types::U256::from_little_endian(&hash) > target {
                bail!("header {height}: hash above target");
            }
            if height >= o.from {
                if ctx.len() < context_needed(n, height) {
                    bail!("header {height}: only {} predecessors known", ctx.len());
                }
                newest_first.clear();
                newest_first.extend(ctx.iter().rev().copied());
                check_contextual(n, height, time, bits, &newest_first)
                    .map_err(|f| anyhow::anyhow!("header {height} rejected: {f:?}"))?;
                checked += 1;
                if bits == min_bits {
                    min_difficulty += 1;
                }
            }
            if let Some(cp) = checkpoints.get(&height) {
                if *cp != hash {
                    bail!("header {height}: hash differs from the checkpoint list");
                }
                cps_matched += 1;
            }
            if let Some(f) = out.as_mut() {
                f.write_all(&bits.to_le_bytes())?;
                f.write_all(&time.to_le_bytes())?;
                f.write_all(&hash)?;
            }
            ctx.push((bits, time));
            if ctx.len() > MAX_CONTEXT {
                ctx.remove(0);
            }
            prev_hash = Some(hash);
        }
        if last_report.elapsed().as_secs() >= 30 {
            let done = first + headers.len() as u64 - start;
            let rate = done as f64 / started.elapsed().as_secs_f64();
            eprintln!(
                "  at {}: {done} headers, {rate:.0}/s, about {:.0} s left",
                first + headers.len() as u64 - 1,
                (tip + 1 - start - done) as f64 / rate
            );
            last_report = Instant::now();
        }
    }
    if let Some(mut f) = out {
        f.flush()?;
    }
    let secs = started.elapsed().as_secs_f64();
    println!(
        "ok: {checked} headers {}..={tip} passed every rule in {secs:.0} s ({:.0}/s); {min_difficulty} at minimum difficulty",
        o.from,
        (tip + 1 - start) as f64 / secs
    );
    if !checkpoints.is_empty() {
        println!("  block hashes matched {cps_matched} checkpoints in range");
    }
    for (u, h) in upgrades {
        println!("  crossed {u:?} at {h}");
    }
    Ok(())
}

fn network_name(network: &Network) -> &'static str {
    match network {
        Network::MainNetwork => "mainnet",
        Network::TestNetwork => "testnet",
    }
}
