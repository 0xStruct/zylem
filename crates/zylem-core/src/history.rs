//! The ZIP 221 chain history tree, replayed block by block.
//!
//! Each block's header commits (through `hashBlockCommitments`) to the history tree of
//! every earlier block since the current network upgrade activated. A history-tree leaf
//! holds the block hash, time, target, work, height, the note commitment tree roots after
//! the block and how many transactions touched each pool. Given the tree's peaks before a
//! Ring, a client can append the leaves itself and compare the root with each next
//! header, which authenticates every block's tree roots.

use std::collections::{BTreeMap, HashSet};

use zcash_history::{Entry, NodeData, NodeDataV2, NodeDataV3, Tree, Version, V2, V3};
use zcash_protocol::consensus::{BlockHeight, BranchId, NetworkUpgrade, Network, Parameters};
use zylem_proto::ring::{HistoryPeak, RingStart};

use crate::{block::PoolTxCounts, header::Header, tree::Roots, Reject};

/// The history tree format in force at a height.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    /// NU5 to NU6.2: Sapling and Orchard.
    V2,
    /// NU6.3 on: adds Ironwood.
    V3,
}

/// The network upgrade at `height` and the history format it uses.
pub fn epoch(network: &Network, height: u64) -> Result<(BranchId, Format), Reject> {
    let h = BlockHeight::from_u32(height as u32);
    let branch = BranchId::for_height(network, h);
    let format = match branch {
        BranchId::Nu5 | BranchId::Nu6 | BranchId::Nu6_1 | BranchId::Nu6_2 => Format::V2,
        BranchId::Nu6_3 | BranchId::Nu7 => Format::V3,
        other => return Err(Reject::Unsupported(format!("history tree before NU5 ({other:?})"))),
    };
    Ok((branch, format))
}

/// Height at which the history tree containing `height` started.
pub fn epoch_start(network: &Network, height: u64) -> u64 {
    let h = BlockHeight::from_u32(height as u32);
    let upgrade = [
        NetworkUpgrade::Nu7,
        NetworkUpgrade::Nu6_3,
        NetworkUpgrade::Nu6_2,
        NetworkUpgrade::Nu6_1,
        NetworkUpgrade::Nu6,
        NetworkUpgrade::Nu5,
    ]
    .into_iter()
    .filter_map(|nu| network.activation_height(nu))
    .find(|a| *a <= h);
    upgrade.map(u64::from).unwrap_or(0)
}

/// The data a leaf commits to.
pub struct LeafParts<'a> {
    pub header: &'a Header,
    pub roots: Roots,
    pub counts: PoolTxCounts,
}

fn leaf_v2(branch: u32, p: &LeafParts) -> NodeDataV2 {
    let h = p.header;
    NodeDataV2 {
        v1: NodeData {
            consensus_branch_id: branch,
            subtree_commitment: h.hash,
            start_time: h.time,
            end_time: h.time,
            start_target: h.bits,
            end_target: h.bits,
            start_sapling_root: p.roots.sapling,
            end_sapling_root: p.roots.sapling,
            subtree_total_work: zcash_history_u256(h.work),
            start_height: h.height,
            end_height: h.height,
            sapling_tx: p.counts.sapling,
        },
        start_orchard_root: p.roots.orchard,
        end_orchard_root: p.roots.orchard,
        orchard_tx: p.counts.orchard,
    }
}

fn leaf_v3(branch: u32, p: &LeafParts) -> NodeDataV3 {
    NodeDataV3 {
        v2: leaf_v2(branch, p),
        start_ironwood_root: p.roots.ironwood,
        end_ironwood_root: p.roots.ironwood,
        ironwood_tx: p.counts.ironwood,
    }
}

fn zcash_history_u256(w: primitive_types::U256) -> primitive_types::U256 {
    w
}

/// One format's tree plus the peaks needed to rebuild it.
struct Mmr<V: Version> {
    branch: u32,
    size: u32,
    peaks: BTreeMap<u32, Vec<u8>>,
    tree: Tree<V>,
}

fn peak_positions(size: u32) -> HashSet<u32> {
    // Peaks of an MMR with `size` nodes, as zcashd and Zakura compute them.
    let mut set = HashSet::new();
    if size == 0 {
        return set;
    }
    let mut alt = (32 - (size + 1).leading_zeros() - 1) - 1;
    let mut pos: u32 = (1 << (alt + 1)) - 2;
    loop {
        if pos >= size {
            pos -= 1 << alt;
            alt -= 1;
        }
        if pos < size {
            set.insert(pos);
            pos += (1 << (alt + 1)) - 1;
        }
        if alt == 0 {
            break;
        }
    }
    set
}

impl<V: Version> Mmr<V> {
    fn rebuild(branch: u32, size: u32, peaks: BTreeMap<u32, Vec<u8>>) -> Result<Self, Reject> {
        if peaks.is_empty() {
            return Err(Reject::malformed("history peaks", "none"));
        }
        let entries = peaks
            .iter()
            .map(|(i, b)| {
                Entry::<V>::from_bytes(branch, b)
                    .map(|e| (*i, e))
                    .map_err(|e| Reject::malformed("history peak", e))
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Mmr { branch, size, peaks, tree: Tree::new(size, entries, vec![]) })
    }

    fn first(branch: u32, leaf: V::NodeData) -> Result<Self, Reject> {
        let mut peaks = BTreeMap::new();
        peaks.insert(0, entry_bytes(&Entry::<V>::new_leaf(leaf)));
        Self::rebuild(branch, 1, peaks)
    }

    fn append(&mut self, leaf: V::NodeData) -> Result<(), Reject> {
        let links = self
            .tree
            .append_leaf(leaf)
            .map_err(|e| Reject::malformed("history append", format!("{e:?}")))?;
        for link in links {
            let node = self
                .tree
                .resolve_link(link)
                .map_err(|e| Reject::malformed("history link", format!("{e:?}")))?;
            self.peaks.insert(self.size, entry_bytes(node.node()));
            self.size += 1;
        }
        let keep = peak_positions(self.size);
        self.peaks.retain(|k, _| keep.contains(k));
        *self = Self::rebuild(self.branch, self.size, std::mem::take(&mut self.peaks))?;
        Ok(())
    }

    fn root(&self) -> [u8; 32] {
        V::hash(self.tree.root_node().expect("a non-empty tree has a root").data())
    }
}

fn entry_bytes<V: Version>(e: &Entry<V>) -> Vec<u8> {
    let mut out = vec![];
    e.write(&mut out).expect("writing to a Vec");
    out
}

enum Inner {
    V2(Mmr<V2>),
    V3(Mmr<V3>),
}

/// The chain history tree of one network upgrade epoch.
pub struct HistoryTree {
    inner: Inner,
    /// Height of the last appended block.
    pub tip: u64,
}

impl HistoryTree {
    /// A tree holding only the upgrade's activation block.
    pub fn first(network: &Network, parts: &LeafParts) -> Result<Self, Reject> {
        let (branch, format) = epoch(network, parts.header.height)?;
        let b = u32::from(branch);
        let inner = match format {
            Format::V2 => Inner::V2(Mmr::first(b, leaf_v2(b, parts))?),
            Format::V3 => Inner::V3(Mmr::first(b, leaf_v3(b, parts))?),
        };
        Ok(HistoryTree { inner, tip: parts.header.height })
    }

    /// Restores the tree from a Ring's start state: the peaks after block `first - 1`.
    pub fn from_start(network: &Network, first: u64, start: &RingStart) -> Result<Self, Reject> {
        let (branch, format) = epoch(network, first)?;
        if start.history_branch_id != u32::from(branch) {
            return Err(Reject::malformed("history", "branch ID differs from the Ring's epoch"));
        }
        let peaks: BTreeMap<u32, Vec<u8>> =
            start.history_peaks.iter().map(|p| (p.index, p.entry.clone())).collect();
        let b = start.history_branch_id;
        let inner = match format {
            Format::V2 => Inner::V2(Mmr::rebuild(b, start.history_length, peaks)?),
            Format::V3 => Inner::V3(Mmr::rebuild(b, start.history_length, peaks)?),
        };
        Ok(HistoryTree { inner, tip: first - 1 })
    }

    /// The start-state fields a Ring beginning after `self.tip` carries.
    pub fn export(&self) -> (u32, u32, Vec<HistoryPeak>) {
        let (branch, size, peaks) = match &self.inner {
            Inner::V2(m) => (m.branch, m.size, &m.peaks),
            Inner::V3(m) => (m.branch, m.size, &m.peaks),
        };
        let peaks = peaks
            .iter()
            .map(|(i, e)| HistoryPeak { index: *i, entry: e.clone() })
            .collect();
        (branch, size, peaks)
    }

    pub fn append(&mut self, parts: &LeafParts) -> Result<(), Reject> {
        let height = parts.header.height;
        if height != self.tip + 1 {
            return Err(Reject::malformed("history", format!("appending {height} after {}", self.tip)));
        }
        match &mut self.inner {
            Inner::V2(m) => {
                let b = m.branch;
                m.append(leaf_v2(b, parts))?
            }
            Inner::V3(m) => {
                let b = m.branch;
                m.append(leaf_v3(b, parts))?
            }
        }
        self.tip = height;
        Ok(())
    }

    /// `hashChainHistoryRoot` of the blocks appended so far.
    pub fn root(&self) -> [u8; 32] {
        match &self.inner {
            Inner::V2(m) => m.root(),
            Inner::V3(m) => m.root(),
        }
    }
}
