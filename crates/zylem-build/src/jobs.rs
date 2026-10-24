//! Proving jobs: the header chain from an upgrade's activation cut into leaves of 512
//! headers, each a self-contained file (input, difficulty context, headers) that a GPU
//! worker can prove without a node. Every leaf is first run natively through the same
//! rules, Equihash included, and its expected claim recorded, so a pod's result can be
//! checked against it. Leaves are split into contiguous shards, one per pod, so each pod
//! can also aggregate its own shard.

use std::path::Path;

use anyhow::{bail, Context, Result};
use serde_json::json;
use sha2::{Digest, Sha256};
use zcash_protocol::consensus::Network;
use zylem_header::{context_hash, record_of, sha256d, Input, LeafJob, Net, RangeClaim, MAX_CONTEXT};

use crate::node::Node;

fn net(network: &Network) -> Net {
    match network {
        Network::MainNetwork => Net::Main,
        Network::TestNetwork => Net::Test,
    }
}

pub struct Options<'a> {
    /// The upgrade activation height leaves are anchored at.
    pub activation: u64,
    /// Last height to cover (default: 100 below the tip); rounded down to whole leaves.
    pub to: Option<u64>,
    /// First leaf to write (default: the first after `activation`), for adding new leaves.
    pub from: Option<u64>,
    pub shards: usize,
    /// Headers per leaf: `LEAF_SIZE`, or fewer for quick proving tests.
    pub leaf_size: u64,
    pub out: &'a Path,
}

pub async fn make(node: &Node, network: &Network, o: Options<'_>) -> Result<()> {
    let n = net(network);
    let end = match o.to {
        Some(t) => t,
        None => node.tip().await? - 100,
    };
    let first = o.from.unwrap_or(o.activation);
    if first < o.activation || (first - o.activation) % o.leaf_size != 0 {
        bail!("leaves start at {} plus a multiple of {}", o.activation, o.leaf_size);
    }
    let leaves = (end + 1).saturating_sub(first) / o.leaf_size;
    if leaves == 0 {
        bail!("no whole leaf between {first} and {end}");
    }
    let last = first + leaves * o.leaf_size - 1;
    let ctx_from = first - MAX_CONTEXT as u64 - 1;
    println!("{leaves} leaves {first}..={last}; fetching headers from {ctx_from}");
    let raw = node.headers(ctx_from, last).await?;
    let at = |h: u64| &raw[(h - ctx_from) as usize];
    std::fs::create_dir_all(o.out)?;

    let mut jobs = vec![];
    let mut records = Vec::with_capacity((leaves * o.leaf_size) as usize * zylem_header::RECORD_SIZE);
    for k in 0..leaves {
        let start = first + k * o.leaf_size;
        let stop = start + o.leaf_size - 1;
        let context: Vec<(u32, u32)> = (start - MAX_CONTEXT as u64..start)
            .map(|h| {
                let x = at(h);
                (u32::from_le_bytes(x[104..108].try_into().unwrap()), u32::from_le_bytes(x[100..104].try_into().unwrap()))
            })
            .collect();
        let input = Input {
            net: n,
            first_height: start,
            anchor_hash: sha256d(at(start - 1)),
            context,
            count: o.leaf_size as u32,
            check_equihash: true,
        };
        let headers: Vec<u8> = (start..=stop).flat_map(|h| at(h).iter().copied()).collect();
        let out = zylem_header::run(&input, &headers).map_err(|(h, f)| anyhow::anyhow!("leaf {start}: header {h} rejected: {f:?}"))?;
        for h in start..=stop {
            records.extend_from_slice(&record_of(at(h), &sha256d(at(h))));
        }
        let claim = RangeClaim::leaf(&input, &out).encode();
        let name = format!("leaf-{start}-{stop}");
        let bytes = bincode::serialize(&LeafJob { input, headers })?;
        std::fs::write(o.out.join(format!("{name}.job")), &bytes)?;
        jobs.push(json!({
            "name": name,
            "first": start,
            "last": stop,
            "shard": (k as usize * o.shards) / leaves as usize,
            "file_sha256": hex::encode(Sha256::digest(&bytes)),
            "claim": hex::encode(&claim),
        }));
        if (k + 1) % 16 == 0 || k + 1 == leaves {
            eprintln!("  {} of {leaves} leaves checked", k + 1);
        }
    }
    std::fs::write(o.out.join("records.bin"), &records)?;
    let anchor = first - 1;
    let manifest = json!({
        "network": match network { Network::MainNetwork => "main", Network::TestNetwork => "test" },
        "activation": o.activation,
        "leaf_size": o.leaf_size,
        "first": first,
        "last": last,
        "anchor": {
            "height": anchor,
            "hash": zylem_core::manifest::display_hash(&sha256d(at(anchor))),
            "context_hash": hex::encode(context_hash(
                &(first - MAX_CONTEXT as u64..first)
                    .map(|h| (u32::from_le_bytes(at(h)[104..108].try_into().unwrap()), u32::from_le_bytes(at(h)[100..104].try_into().unwrap())))
                    .collect::<Vec<_>>()
            )),
        },
        "shards": o.shards,
        "records": "records.bin",
        "jobs": jobs,
    });
    std::fs::write(o.out.join("manifest.json"), serde_json::to_string_pretty(&manifest)? + "\n").context("manifest")?;
    println!("wrote {leaves} jobs and records for {first}..={last} to {}", o.out.display());
    Ok(())
}
