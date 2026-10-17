//! Note commitment trees, carried as frontiers and advanced with each block's
//! commitments.

use incrementalmerkletree::frontier::{CommitmentTree, Frontier};
use orchard::tree::MerkleHashOrchard;
use zcash_primitives::merkle_tree::{
    read_commitment_tree, read_frontier_v1, write_commitment_tree, write_frontier_v1, HashSer,
};
use zylem_proto::rpc::{ChainMetadata, CompactTx};

use crate::Reject;

pub const DEPTH: u8 = 32;
/// Leaves per shard, as `GetSubtreeRoots` and `shardtree` use them.
pub const SUBTREE_LEVEL: u8 = 16;

/// Roots of the three trees after some block.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Roots {
    pub sapling: [u8; 32],
    pub orchard: [u8; 32],
    pub ironwood: [u8; 32],
}

/// A completed 2^16-leaf subtree, recorded when its last leaf is appended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompletedSubtree {
    pub pool: Pool,
    pub index: u64,
    pub root: [u8; 32],
    pub height: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Pool {
    Sapling,
    Orchard,
    Ironwood,
}

/// The Sapling, Orchard and Ironwood frontiers.
#[derive(Clone, Debug)]
pub struct Trees {
    pub sapling: Frontier<sapling::Node, DEPTH>,
    pub orchard: Frontier<MerkleHashOrchard, DEPTH>,
    pub ironwood: Frontier<MerkleHashOrchard, DEPTH>,
}

fn node_bytes<H: HashSer>(h: &H) -> [u8; 32] {
    let mut out = Vec::with_capacity(32);
    h.write(&mut out).expect("writing to a Vec");
    out.try_into().expect("tree nodes are 32 bytes")
}

fn encode<H: HashSer>(f: &Frontier<H, DEPTH>) -> Vec<u8> {
    let mut out = vec![];
    write_frontier_v1(&mut out, f).expect("writing to a Vec");
    out
}

fn decode<H: HashSer + Clone>(bytes: &[u8], what: &'static str) -> Result<Frontier<H, DEPTH>, Reject> {
    read_frontier_v1(bytes).map_err(|e| Reject::malformed(what, e))
}

fn legacy_hex<H: HashSer + Clone + incrementalmerkletree::Hashable>(f: &Frontier<H, DEPTH>) -> String {
    let tree = CommitmentTree::<H, DEPTH>::from_frontier(f);
    let mut out = vec![];
    write_commitment_tree(&tree, &mut out).expect("writing to a Vec");
    hex::encode(out)
}

fn from_legacy_hex<H: HashSer + Clone + incrementalmerkletree::Hashable>(s: &str, what: &'static str) -> Result<Frontier<H, DEPTH>, Reject> {
    if s.is_empty() {
        return Ok(Frontier::empty());
    }
    let bytes = hex::decode(s).map_err(|e| Reject::malformed(what, e))?;
    let tree: CommitmentTree<H, DEPTH> =
        read_commitment_tree(&bytes[..]).map_err(|e| Reject::malformed(what, e))?;
    Ok(tree.to_frontier())
}

fn sapling_leaf(cmu: &[u8]) -> Result<sapling::Node, Reject> {
    let bytes: [u8; 32] = cmu.try_into().map_err(|_| Reject::malformed("cmu", cmu.len()))?;
    let cmu = Option::from(sapling::note::ExtractedNoteCommitment::from_bytes(&bytes))
        .ok_or_else(|| Reject::malformed("cmu", "not a field element"))?;
    Ok(sapling::Node::from_cmu(&cmu))
}

fn orchard_leaf(cmx: &[u8]) -> Result<MerkleHashOrchard, Reject> {
    let bytes: [u8; 32] = cmx.try_into().map_err(|_| Reject::malformed("cmx", cmx.len()))?;
    let cmx = Option::from(orchard::note::ExtractedNoteCommitment::from_bytes(&bytes))
        .ok_or_else(|| Reject::malformed("cmx", "not a field element"))?;
    Ok(MerkleHashOrchard::from_cmx(&cmx))
}

/// Appends a leaf and, if it completes a 2^16-leaf subtree, returns that subtree's root.
fn append_tracking<H>(f: &mut Frontier<H, DEPTH>, leaf: H) -> Option<(u64, H)>
where
    H: incrementalmerkletree::Hashable + Clone,
{
    f.append(leaf);
    let nf = f.value()?;
    let pos = u64::from(nf.position());
    let mask = (1u64 << SUBTREE_LEVEL) - 1;
    (pos & mask == mask).then(|| {
        (
            pos >> SUBTREE_LEVEL,
            nf.root(Some(incrementalmerkletree::Level::from(SUBTREE_LEVEL))),
        )
    })
}

fn size<H>(f: &Frontier<H, DEPTH>) -> u64 {
    f.value().map(|nf| u64::from(nf.position()) + 1).unwrap_or(0)
}

impl Trees {
    pub fn empty() -> Self {
        Trees {
            sapling: Frontier::empty(),
            orchard: Frontier::empty(),
            ironwood: Frontier::empty(),
        }
    }

    /// Frontiers from their Ring encoding (zcash_primitives frontier v1).
    pub fn decode(sapling: &[u8], orchard: &[u8], ironwood: &[u8]) -> Result<Self, Reject> {
        Ok(Trees {
            sapling: decode(sapling, "Sapling frontier")?,
            orchard: decode(orchard, "Orchard frontier")?,
            ironwood: decode(ironwood, "Ironwood frontier")?,
        })
    }

    pub fn encode(&self) -> [Vec<u8>; 3] {
        [encode(&self.sapling), encode(&self.orchard), encode(&self.ironwood)]
    }

    /// Frontiers from the light-wallet protocol's `TreeState` (legacy tree hex).
    pub fn from_tree_state(sapling: &str, orchard: &str, ironwood: &str) -> Result<Self, Reject> {
        Ok(Trees {
            sapling: from_legacy_hex(sapling, "Sapling tree")?,
            orchard: from_legacy_hex(orchard, "Orchard tree")?,
            ironwood: from_legacy_hex(ironwood, "Ironwood tree")?,
        })
    }

    /// The light-wallet protocol's `TreeState` strings (legacy tree hex).
    pub fn to_tree_state(&self) -> [String; 3] {
        [legacy_hex(&self.sapling), legacy_hex(&self.orchard), legacy_hex(&self.ironwood)]
    }

    /// Appends every note commitment of a block, in block order, and returns any
    /// subtrees the block completed.
    pub fn append_block(&mut self, height: u64, vtx: &[CompactTx]) -> Result<Vec<CompletedSubtree>, Reject> {
        let mut done = vec![];
        for tx in vtx {
            for o in &tx.outputs {
                if let Some((index, root)) = append_tracking(&mut self.sapling, sapling_leaf(&o.cmu)?) {
                    done.push(CompletedSubtree { pool: Pool::Sapling, index, root: node_bytes(&root), height });
                }
            }
            for a in &tx.actions {
                if let Some((index, root)) = append_tracking(&mut self.orchard, orchard_leaf(&a.cmx)?) {
                    done.push(CompletedSubtree { pool: Pool::Orchard, index, root: node_bytes(&root), height });
                }
            }
            for a in &tx.ironwood_actions {
                if let Some((index, root)) = append_tracking(&mut self.ironwood, orchard_leaf(&a.cmx)?) {
                    done.push(CompletedSubtree { pool: Pool::Ironwood, index, root: node_bytes(&root), height });
                }
            }
        }
        Ok(done)
    }

    pub fn roots(&self) -> Roots {
        Roots {
            sapling: node_bytes(&self.sapling.root()),
            orchard: node_bytes(&self.orchard.root()),
            ironwood: node_bytes(&self.ironwood.root()),
        }
    }

    pub fn sizes(&self) -> ChainMetadata {
        ChainMetadata {
            sapling_commitment_tree_size: size(&self.sapling) as u32,
            orchard_commitment_tree_size: size(&self.orchard) as u32,
            ironwood_commitment_tree_size: size(&self.ironwood) as u32,
        }
    }

    /// The roots of all 2^16-leaf subtrees completed before this frontier, given as
    /// claims, are checked against the frontier itself: the frontier's ommers above the
    /// subtree level commit to every completed subtree.
    pub fn check_subtree_roots(&self, pool: Pool, claimed: &[[u8; 32]]) -> Result<(), Reject> {
        match pool {
            Pool::Sapling => check_subtrees(&self.sapling, claimed, |b| {
                Option::from(sapling::Node::from_bytes(*b))
            }),
            Pool::Orchard => check_subtrees(&self.orchard, claimed, |b| Option::from(MerkleHashOrchard::from_bytes(b))),
            Pool::Ironwood => check_subtrees(&self.ironwood, claimed, |b| Option::from(MerkleHashOrchard::from_bytes(b))),
        }
    }
}

fn check_subtrees<H>(
    f: &Frontier<H, DEPTH>,
    claimed: &[[u8; 32]],
    parse: impl Fn(&[u8; 32]) -> Option<H>,
) -> Result<(), Reject>
where
    H: incrementalmerkletree::Hashable + Clone + PartialEq,
{
    use incrementalmerkletree::Level;
    let complete = (size(f) >> SUBTREE_LEVEL) as usize;
    if claimed.len() != complete {
        return Err(Reject::malformed("subtree roots", format!("{} claimed, {complete} complete", claimed.len())));
    }
    let Some(nf) = f.value() else { return Ok(()) };
    let nodes: Vec<H> = claimed
        .iter()
        .map(|b| parse(b).ok_or_else(|| Reject::malformed("subtree root", "not a field element")))
        .collect::<Result<_, _>>()?;
    // The frontier holds one ommer for each set bit of its position, lowest level
    // first. Above the subtree level, ommer k at level L is the root of 2^(L-16)
    // consecutive complete subtrees, which we rebuild from the claimed roots.
    let pos = u64::from(nf.position());
    let mut ommers = nf.ommers().iter();
    let mut start = 0usize;
    let mut expected = vec![];
    for level in 0..DEPTH {
        if pos & (1 << level) == 0 {
            continue;
        }
        let ommer = ommers.next().expect("one ommer per set bit");
        if level >= SUBTREE_LEVEL {
            expected.push((level, ommer.clone()));
        }
    }
    // Higher levels cover earlier subtrees, so walk from the top.
    for (level, ommer) in expected.into_iter().rev() {
        let width = 1usize << (level - SUBTREE_LEVEL);
        let mut layer: Vec<H> = nodes[start..start + width].to_vec();
        let mut l = SUBTREE_LEVEL;
        while layer.len() > 1 {
            layer = layer.chunks(2).map(|p| H::combine(Level::from(l), &p[0], &p[1])).collect();
            l += 1;
        }
        if layer[0] != ommer {
            return Err(Reject::malformed("subtree roots", format!("subtrees {start}..{} do not match the frontier", start + width)));
        }
        start += width;
    }
    // When the newest leaf closed a subtree, that subtree is below the ommers.
    if start < nodes.len() && nodes[start] != nf.root(Some(Level::from(SUBTREE_LEVEL))) {
        return Err(Reject::malformed("subtree roots", format!("subtree {start} does not match the frontier")));
    }
    Ok(())
}
