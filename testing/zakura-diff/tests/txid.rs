//! Transaction IDs that Zylem rebuilt from compact data and auxiliary digests (written by
//! `zylem-build verify --txids`) against the IDs Zakura computes from the full blocks the
//! node still holds; also block hashes and auth data roots.

mod common;

use common::{display, rpc_batch, rpc_hex_range, rpc_url};
use zakura_chain::{block::Block, serialization::ZcashDeserializeInto};

const DUMP: &str = "../../data/replay/testnet-txids.txt";

#[test]
fn rebuilt_txids_match_zakura() {
    let Some(url) = rpc_url() else { return };
    let Ok(dump) = std::fs::read_to_string(DUMP) else {
        println!("skipped: run `zylem-build verify data/testnet --txids {DUMP}` first");
        return;
    };
    let info = rpc_batch(&url, "getblockchaininfo", &[serde_json::json!([])]).remove(0);
    let pruned_below = info["pruneheight"].as_u64().unwrap_or(0);
    let lines: Vec<Vec<&str>> =
        dump.lines().map(|l| l.split(' ').collect::<Vec<_>>()).filter(|f| f[0].parse::<u64>().unwrap() > pruned_below).collect();
    assert!(!lines.is_empty(), "no dumped block is above the node's prune height {pruned_below}");
    let (from, to) = (lines[0][0].parse::<u64>().unwrap(), lines.last().unwrap()[0].parse::<u64>().unwrap());
    let (mut blocks, mut txs) = (0, 0);
    let mut versions = std::collections::BTreeMap::new();
    for (chunk_from, chunk) in (from..=to).step_by(1_000).zip(lines.chunks(1_000)) {
        let chunk_to = (chunk_from + 999).min(to);
        let raw = rpc_hex_range(&url, "getblock", chunk_from, chunk_to, serde_json::json!(0));
        for (fields, bytes) in chunk.iter().zip(raw) {
            let height = fields[0];
            let block: Block = bytes.as_slice().zcash_deserialize_into().unwrap_or_else(|e| panic!("{height}: {e}"));
            assert_eq!(display(block.hash().0), fields[1], "block hash at {height}");
            assert_eq!(hex::encode(<[u8; 32]>::from(block.auth_data_root())), fields[2], "auth data root at {height}");
            let theirs: Vec<String> = block.transactions.iter().map(|t| display(t.hash().0)).collect();
            assert_eq!(theirs.join(","), fields[3], "transaction IDs at {height}");
            for t in &block.transactions {
                *versions.entry(t.version()).or_insert(0) += 1;
            }
            blocks += 1;
            txs += theirs.len();
        }
    }
    println!("{blocks} blocks {from}..={to}: {txs} transaction IDs, block hashes and auth data roots match; versions {versions:?}");
}
