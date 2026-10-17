//! Phase 0: do a real light-wallet server's compact blocks, plus Zylem aux digests,
//! rebuild the same transaction IDs?

use anyhow::Result;
use zcash_protocol::consensus::{BlockHeight, BranchId, Network};
use zylem_core::{block, txid};

use crate::{lwd, node::Node};

pub async fn run(node: &Node, lwd_url: &str, network: Network, from: u64, count: u64) -> Result<()> {
    let mut client = lwd::connect(lwd_url).await?;
    let server_tip = lwd::tip(&mut client).await?;
    let to = from + count - 1;
    let served = lwd::blocks(&mut client, from, to).await?;

    let (mut txs, mut served_txs, mut rebuilt, mut differs) = (0u64, 0u64, 0u64, 0u64);
    let (mut with_header, mut with_hash, mut with_tree_sizes) = (0u64, 0u64, 0u64);
    let mut transparent_only_omitted = 0u64;
    for cb in &served {
        let height = cb.height;
        with_header += u64::from(!cb.header.is_empty());
        with_hash += u64::from(!cb.hash.is_empty());
        with_tree_sizes += u64::from(cb.chain_metadata.is_some());
        let rb = block::assemble(height, &node.block(height).await?, &network)?;
        let ours = &rb.block.as_ref().unwrap().vtx;
        txs += ours.len() as u64;
        let branch = BranchId::for_height(&network, BlockHeight::from_u32(height as u32));
        for ctx in &cb.vtx {
            served_txs += 1;
            let i = ctx.index as usize;
            let mut theirs = ctx.clone();
            // Normalize the fields a server may legitimately leave out of compact data.
            theirs.fee = 0;
            let mut mine = ours[i].clone();
            mine.fee = 0;
            if theirs != mine {
                differs += 1;
            }
            let id = txid::rebuild_txid(height, i, &theirs, &rb.aux[i], branch)?;
            if id.as_slice() == ours[i].txid.as_slice() {
                rebuilt += 1;
            }
        }
        transparent_only_omitted += ours
            .iter()
            .filter(|t| t.spends.is_empty() && t.outputs.is_empty() && t.actions.is_empty() && t.ironwood_actions.is_empty())
            .filter(|t| !cb.vtx.iter().any(|s| s.index == t.index))
            .count() as u64;
    }
    println!("Light-wallet server check: {lwd_url} (tip {server_tip}), heights {from}..{to}");
    println!("  blocks served               {}", served.len());
    println!("  blocks with full header     {}", with_header);
    println!("  blocks with hash            {}", with_hash);
    println!("  blocks with tree sizes      {}", with_tree_sizes);
    println!("  transactions in blocks      {txs}");
    println!("  transactions served         {served_txs}");
    println!("  transparent-only omitted    {transparent_only_omitted}");
    println!("  served compact tx differs from Zylem's compact form: {differs}");
    println!("  IDs rebuilt from server compact data + Zylem aux: {rebuilt} / {served_txs}");
    Ok(())
}
