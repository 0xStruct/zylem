//! Phase 0: rebuild every transaction ID in a range of real blocks from compact data
//! plus aux digests, and measure what the Ring format costs.

use anyhow::{bail, Result};
use prost::Message;
use zcash_primitives::block::Block;
use zcash_protocol::consensus::Network;
use zylem_core::{block, header::Header};

use crate::node::Node;

#[derive(Default)]
struct Totals {
    blocks: u64,
    txs: u64,
    by_version: [u64; 7],
    txid_rebuilt: u64,
    library_match: u64,
    merkle_match: u64,
    raw_bytes: u64,
    header_bytes: u64,
    compact_bytes: u64,
    aux_bytes: u64,
    v4_full_bytes: u64,
    ring_block_bytes: u64,
}

pub async fn run(node: &Node, network: Network, from: u64, count: u64) -> Result<()> {
    let mut t = Totals::default();
    for height in from..from + count {
        let raw = node.block(height).await?;
        let rb = block::assemble(height, &raw, &network)?;
        let header = Header::parse_and_check(height, &rb.header)?;

        // Independent reference: librustzcash's own transaction IDs.
        let (_, txs) = Block::read(&raw[..], &network)?.into_parts();
        let library: Vec<[u8; 32]> = txs.iter().map(|tx| *tx.txid().as_ref()).collect();

        let verified = block::verify(&header, &rb, &network)?;
        t.blocks += 1;
        t.txs += txs.len() as u64;
        t.merkle_match += 1;
        t.txid_rebuilt += verified.txids.len() as u64;
        t.library_match += verified
            .txids
            .iter()
            .zip(&library)
            .filter(|(a, b)| a == b)
            .count() as u64;
        if verified.txids != library {
            bail!("height {height}: rebuilt IDs differ from librustzcash");
        }

        let cb = rb.block.as_ref().unwrap();
        for (ctx, aux) in cb.vtx.iter().zip(&rb.aux) {
            t.by_version[aux.version as usize] += 1;
            t.compact_bytes += ctx.encoded_len() as u64;
            if aux.version == 4 {
                t.v4_full_bytes += aux.full_tx.len() as u64;
            } else {
                t.aux_bytes += aux.encoded_len() as u64;
            }
        }
        t.raw_bytes += raw.len() as u64;
        t.header_bytes += rb.header.len() as u64;
        t.ring_block_bytes += rb.encoded_len() as u64;
        if height % 100 == 0 {
            eprintln!("  checked up to {height}");
        }
    }

    let per_tx = |b: u64| b as f64 / t.txs.max(1) as f64;
    let per_block = |b: u64| b as f64 / t.blocks.max(1) as f64;
    println!("Phase 0 spike: heights {from}..{}", from + count - 1);
    println!("  blocks checked              {}", t.blocks);
    println!("  transactions                {} (v4 {}, v5 {}, v6 {})", t.txs, t.by_version[4], t.by_version[5], t.by_version[6]);
    println!("  IDs rebuilt from compact+aux {} / {} match librustzcash", t.library_match, t.txid_rebuilt);
    println!("  Merkle roots matched        {} / {}", t.merkle_match, t.blocks);
    println!("  raw block bytes / block     {:.0}", per_block(t.raw_bytes));
    println!("  header bytes / block        {:.0}", per_block(t.header_bytes));
    println!("  compact bytes / tx          {:.0}", per_tx(t.compact_bytes));
    println!("  aux bytes / v5-v6 tx        {:.0}", t.aux_bytes as f64 / (t.by_version[5] + t.by_version[6]).max(1) as f64);
    println!("  v4 full bytes / v4 tx       {:.0}", t.v4_full_bytes as f64 / t.by_version[4].max(1) as f64);
    println!("  Ring bytes / block (raw)    {:.0}", per_block(t.ring_block_bytes));
    println!(
        "  Ring MB / 4,096-block epoch {:.2} (before zstd)",
        per_block(t.ring_block_bytes) * 4096.0 / 1e6
    );
    println!(
        "  header MB / day             {:.1} at 75 s blocks, {:.1} at 25 s blocks",
        1487.0 * 1152.0 / 1e6,
        1487.0 * 3456.0 / 1e6
    );
    Ok(())
}
