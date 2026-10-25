//! Rings: one epoch of history in one file, and the checks that make its host
//! irrelevant.

use primitive_types::U256;
use prost::Message;
use zcash_protocol::consensus::Network;
use zylem_proto::ring::{Ring, RingBlock};

use crate::{
    block::{self, VerifiedBlock},
    header::{DifficultyContext, Header},
    history::{HistoryTree, LeafParts},
    merkle,
    tree::{CompletedSubtree, Roots, Trees},
    Reject,
};

pub const FORMAT: u32 = 1;
#[cfg(not(target_arch = "wasm32"))]
const ZSTD_LEVEL: i32 = 9;

/// A Ring file: zstd over the protobuf encoding. Encoding is deterministic, so two
/// builders of the same chain produce byte-identical files.
#[cfg(not(target_arch = "wasm32"))]
pub fn encode_file(ring: &Ring) -> Vec<u8> {
    zstd::encode_all(&ring.encode_to_vec()[..], ZSTD_LEVEL).expect("compressing in memory")
}

/// Rings are bounded so a hostile mirror cannot exhaust a client.
pub const MAX_RING_BYTES: usize = 512 << 20;

pub fn decode_file(bytes: &[u8]) -> Result<Ring, Reject> {
    let mut raw = vec![];
    #[cfg(not(target_arch = "wasm32"))]
    let mut dec = zstd::Decoder::new(bytes).map_err(|e| Reject::malformed("ring", e))?;
    #[cfg(target_arch = "wasm32")]
    let mut dec = ruzstd::decoding::StreamingDecoder::new(bytes).map_err(|e| Reject::malformed("ring", e))?;
    std::io::Read::read_to_end(&mut std::io::Read::take(&mut dec, MAX_RING_BYTES as u64 + 1), &mut raw)
        .map_err(|e| Reject::malformed("ring", e))?;
    if raw.len() > MAX_RING_BYTES {
        return Err(Reject::malformed("ring", "too large"));
    }
    Ring::decode(&raw[..]).map_err(|e| Reject::malformed("ring", e))
}

/// BLAKE2b-256 of a Ring file, as manifests list it.
pub fn file_hash(bytes: &[u8]) -> [u8; 32] {
    blake2b_simd::Params::new()
        .hash_length(32)
        .personal(b"Zylem_Ring_File_")
        .hash(bytes)
        .as_bytes()
        .try_into()
        .unwrap()
}

/// What the verifier knows at the end of the previous Ring.
pub struct Continuation<'a> {
    pub last_header: &'a Header,
    pub trees: &'a Trees,
    /// `(bits, time)` of the headers up to and including `last_header`, oldest first, for
    /// the difficulty and time rules. Shorter than needed only near the trust anchor.
    pub context: &'a DifficultyContext,
}

/// A Ring whose every block passed.
pub struct VerifiedRing {
    pub start_height: u64,
    /// Highest block whose note commitment roots are authenticated by a later header.
    pub authenticated_to: u64,
    pub blocks: Vec<VerifiedBlock>,
    /// Compact blocks with verified chain metadata, in height order.
    pub compact: Vec<zylem_proto::rpc::CompactBlock>,
    /// Frontiers after each block, in height order.
    pub trees_after: Vec<Trees>,
    pub trees_before: Trees,
    pub subtrees: Vec<CompletedSubtree>,
    pub history: HistoryTree,
    pub work: U256,
    /// Context after the Ring's last block, for the next Ring.
    pub context_after: DifficultyContext,
    /// First height whose difficulty and time rules were checked: every later header in
    /// the Ring was. `None` if the context never became long enough.
    pub context_checked_from: Option<u64>,
}

impl VerifiedRing {
    pub fn last_header(&self) -> &Header {
        &self.blocks.last().expect("rings are non-empty").header
    }
    pub fn end_height(&self) -> u64 {
        self.start_height + self.blocks.len() as u64 - 1
    }
}

fn claimed_roots(rb: &RingBlock, height: u64) -> Result<Roots, Reject> {
    let r = |b: &[u8], what| -> Result<[u8; 32], Reject> {
        b.try_into().map_err(|_| Reject::malformed(what, format!("at {height}")))
    };
    Ok(Roots {
        sapling: r(&rb.sapling_root, "Sapling root")?,
        orchard: r(&rb.orchard_root, "Orchard root")?,
        ironwood: r(&rb.ironwood_root, "Ironwood root")?,
    })
}

/// Checks a whole Ring:
///
/// 1. every header has valid Equihash, meets its own target, links to the one before
///    (and to `prev`, the previous Ring's last header, when given), and follows the
///    difficulty adjustment and time rules once enough predecessors are known (from
///    `prev`'s context, else from the Ring itself after its first 28 or, from NU7, 113
///    blocks);
/// 2. every block's transaction IDs are rebuilt from compact data and aux, and match the
///    header's Merkle root;
/// 3. the history tree, restored from the Ring's start peaks and extended with each block's
///    leaf, matches every following header's block commitments, which authenticates every
///    block's claimed tree roots;
/// 4. the Ring's note commitments, appended to its start frontiers, reproduce the
///    authenticated roots, which authenticates the start frontiers and so every tree state
///    inside the Ring.
pub fn verify(network: &Network, ring: &Ring, prev: Option<Continuation>) -> Result<VerifiedRing, Reject> {
    if ring.format != FORMAT {
        return Err(Reject::Unsupported(format!("ring format {}", ring.format)));
    }
    if ring.blocks.is_empty() {
        return Err(Reject::malformed("ring", "no blocks"));
    }
    let start = ring.start.as_ref().ok_or_else(|| Reject::malformed("ring", "no start state"))?;
    let first = ring.start_height;
    if ring.end_height != first + ring.blocks.len() as u64 - 1 {
        return Err(Reject::malformed("ring", "height range"));
    }
    let mut trees = Trees::decode(&start.sapling_frontier, &start.orchard_frontier, &start.ironwood_frontier)?;
    if let Some(p) = &prev {
        // The start frontiers must be the previous Ring's verified end state.
        let (a, b) = (trees.roots(), p.trees.roots());
        let height = first - 1;
        for (pool, x, y) in [
            ("Sapling", a.sapling, b.sapling),
            ("Orchard", a.orchard, b.orchard),
            ("Ironwood", a.ironwood, b.ironwood),
        ] {
            if x != y {
                return Err(Reject::TreeRootMismatch { height, pool });
            }
        }
        if trees.sizes() != p.trees.sizes() {
            return Err(Reject::malformed("ring", "start tree sizes differ from the previous Ring's end"));
        }
    }
    let trees_before = trees.clone();
    let mut history = HistoryTree::from_start(network, first, start)?;

    let mut prev_hash = prev.as_ref().map(|p| p.last_header.hash);
    let mut blocks = Vec::with_capacity(ring.blocks.len());
    let mut compact = Vec::with_capacity(ring.blocks.len());
    let mut trees_after = Vec::with_capacity(ring.blocks.len());
    let mut subtrees = vec![];
    let mut claimed = Vec::with_capacity(ring.blocks.len());
    let mut work = U256::zero();
    let mut context = prev.as_ref().map(|p| p.context.clone()).unwrap_or_default();
    let mut context_checked_from = None;

    for (i, rb) in ring.blocks.iter().enumerate() {
        let height = first + i as u64;
        let header = Header::parse_and_check(height, &rb.header)?;
        if let Some(p) = prev_hash {
            if header.prev_hash != p {
                return Err(Reject::BrokenChain { height });
            }
        }
        // The context needed grows at NU7 (17 to 102 blocks), so a Ring without a prior
        // context can stop being checkable for a while; only an unbroken run counts.
        if context.check_and_push(network, &header)? {
            context_checked_from.get_or_insert(height);
        } else {
            context_checked_from = None;
        }
        // This header commits to the history of every earlier block in the epoch.
        let auth: [u8; 32] = rb.auth_data_root[..]
            .try_into()
            .map_err(|_| Reject::malformed("auth data root", height))?;
        if header.commitments != merkle::block_commitments(&history.root(), &auth) {
            return Err(Reject::HistoryMismatch { height });
        }
        let vb = block::verify(&header, rb, network)?;
        let mut cb = rb.block.clone().expect("checked in block::verify");
        subtrees.extend(trees.append_block(height, &cb.vtx)?);
        let sizes = trees.sizes();
        if let Some(m) = &cb.chain_metadata {
            if *m != sizes {
                return Err(Reject::CompactHeaderMismatch { height, field: "chainMetadata" });
            }
        }
        cb.chain_metadata = Some(sizes);
        let roots = claimed_roots(rb, height)?;
        history.append(&LeafParts { header: &header, roots, counts: vb.counts })?;
        work += header.work;
        prev_hash = Some(header.hash);
        claimed.push(roots);
        trees_after.push(trees.clone());
        compact.push(cb);
        blocks.push(vb);
    }

    // The last block's leaf is authenticated by the next header, when the Ring has one.
    let authenticated_to = if !ring.next_header.is_empty() {
        let height = ring.end_height + 1;
        let next = Header::parse_and_check(height, &ring.next_header)?;
        if Some(next.prev_hash) != prev_hash {
            return Err(Reject::BrokenChain { height });
        }
        context.clone().check_and_push(network, &next)?;
        let auth: [u8; 32] = ring.next_auth_data_root[..]
            .try_into()
            .map_err(|_| Reject::malformed("auth data root", height))?;
        if next.commitments != merkle::block_commitments(&history.root(), &auth) {
            return Err(Reject::HistoryMismatch { height });
        }
        ring.end_height
    } else {
        // An open tail: the newest block's roots wait for its successor.
        ring.end_height - 1
    };

    if authenticated_to >= first {
        let idx = (authenticated_to - first) as usize;
        let computed = trees_after[idx].roots();
        let expected = claimed[idx];
        for (pool, a, b) in [
            ("Sapling", computed.sapling, expected.sapling),
            ("Orchard", computed.orchard, expected.orchard),
            ("Ironwood", computed.ironwood, expected.ironwood),
        ] {
            if a != b {
                return Err(Reject::TreeRootMismatch { height: authenticated_to, pool });
            }
        }
    }

    Ok(VerifiedRing {
        start_height: first,
        authenticated_to,
        blocks,
        compact,
        trees_after,
        trees_before,
        subtrees,
        history,
        work,
        context_after: context,
        context_checked_from,
    })
}
