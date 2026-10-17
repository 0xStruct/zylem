//! One block: assembling it from raw bytes (builder side) and checking it against its
//! header (verifier side).

use zcash_primitives::block::Block;
use zcash_protocol::consensus::{BlockHeight, BranchId, Network};
use zylem_proto::{
    ring::RingBlock,
    rpc::{CompactBlock, CompactTx},
};

use crate::{
    header::{Header, HEADER_SIZE},
    merkle::{self, AUTH_DIGEST_PLACEHOLDER},
    txid, Reject,
};

/// Number of transactions with a bundle in each shielded pool, as the history tree
/// counts them.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PoolTxCounts {
    pub sapling: u64,
    pub orchard: u64,
    pub ironwood: u64,
}

impl PoolTxCounts {
    pub fn of(vtx: &[CompactTx]) -> Self {
        let mut c = PoolTxCounts::default();
        for tx in vtx {
            c.sapling += u64::from(!tx.spends.is_empty() || !tx.outputs.is_empty());
            c.orchard += u64::from(!tx.actions.is_empty());
            c.ironwood += u64::from(!tx.ironwood_actions.is_empty());
        }
        c
    }
}

/// Splits a raw block into its Ring form: header, every transaction in compact form,
/// one aux entry per transaction, and the auth data root. Note commitment roots and tree
/// sizes are filled in by the caller, which tracks the trees.
pub fn assemble(height: u64, raw: &[u8], network: &Network) -> Result<RingBlock, Reject> {
    if raw.len() < HEADER_SIZE {
        return Err(Reject::malformed("block", "shorter than a header"));
    }
    let block = Block::read(raw, network).map_err(|e| Reject::malformed("block", e))?;
    let (header, txs) = block.into_parts();
    let mut vtx = Vec::with_capacity(txs.len());
    let mut aux = Vec::with_capacity(txs.len());
    let mut auth = Vec::with_capacity(txs.len());
    for (i, tx) in txs.iter().enumerate() {
        vtx.push(txid::compact_from_tx(i, tx));
        aux.push(txid::aux_from_tx(tx)?);
        auth.push(match aux[i].version {
            5 | 6 => tx.auth_commitment().as_bytes().try_into().unwrap(),
            _ => AUTH_DIGEST_PLACEHOLDER,
        });
    }
    Ok(RingBlock {
        header: raw[..HEADER_SIZE].to_vec(),
        block: Some(CompactBlock {
            height,
            hash: header.hash().0.to_vec(),
            prev_hash: header.prev_block.0.to_vec(),
            time: header.time,
            vtx,
            ..Default::default()
        }),
        aux,
        auth_data_root: merkle::auth_data_root(&auth).to_vec(),
        ..Default::default()
    })
}

/// A block whose every transaction ID was rebuilt and matched the header.
#[derive(Clone, Debug)]
pub struct VerifiedBlock {
    pub header: Header,
    pub txids: Vec<[u8; 32]>,
    pub counts: PoolTxCounts,
}

/// Checks a block against an already-checked header: the compact block's metadata
/// matches the header, every transaction ID is rebuilt from compact data and aux, no ID
/// repeats, and the IDs produce the header's Merkle root.
pub fn verify(header: &Header, rb: &RingBlock, network: &Network) -> Result<VerifiedBlock, Reject> {
    let height = header.height;
    let cb = rb
        .block
        .as_ref()
        .ok_or_else(|| Reject::malformed("ring block", "no compact block"))?;
    let mismatch = |field| Reject::CompactHeaderMismatch { height, field };
    if cb.height != height {
        return Err(mismatch("height"));
    }
    if cb.hash != header.hash {
        return Err(mismatch("hash"));
    }
    if cb.prev_hash != header.prev_hash {
        return Err(mismatch("prevHash"));
    }
    if cb.time != header.time {
        return Err(mismatch("time"));
    }
    if cb.vtx.len() != rb.aux.len() || cb.vtx.is_empty() {
        return Err(Reject::malformed("ring block", "one aux entry per transaction"));
    }
    let branch = BranchId::for_height(network, BlockHeight::from_u32(height as u32));
    let mut txids = Vec::with_capacity(cb.vtx.len());
    for (i, (ctx, aux)) in cb.vtx.iter().zip(&rb.aux).enumerate() {
        if ctx.index != i as u64 {
            return Err(Reject::malformed("compact tx", "out of order"));
        }
        let id = txid::rebuild_txid(height, i, ctx, aux, branch)?;
        if !ctx.txid.is_empty() && ctx.txid != id {
            return Err(Reject::TxIdMismatch { height, index: i });
        }
        txids.push(id);
    }
    if merkle::has_duplicates(&txids) {
        return Err(Reject::DuplicateTxId { height });
    }
    if merkle::merkle_root(&txids) != header.merkle_root {
        return Err(Reject::MerkleMismatch { height });
    }
    Ok(VerifiedBlock {
        header: header.clone(),
        txids,
        counts: PoolTxCounts::of(&cb.vtx),
    })
}
