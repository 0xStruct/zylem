//! The verified chain: every block the proxy will serve, loaded from Rings and checked
//! with zylem-core before it is visible to wallets.

use std::collections::{BTreeMap, HashMap, HashSet};

use anyhow::{bail, Context, Result};
use zcash_protocol::consensus::Network;
use zylem_core::{
    header::Header,
    manifest::{display_hash, Manifest, RingEntry},
    ring::{self, Continuation, VerifiedRing},
    tree::{CompletedSubtree, Pool, Trees},
};
use zylem_proto::rpc::CompactBlock;

pub struct BlockEntry {
    pub header: Header,
    /// Every transaction, all pools, with verified chain metadata.
    pub compact: CompactBlock,
    pub txids: HashSet<[u8; 32]>,
    pub trees_after: Trees,
}

/// A verified checkpoint: the chain must contain this block hash at this height.
#[derive(Clone, Copy, Debug)]
pub struct Checkpoint {
    pub height: u64,
    /// Internal byte order.
    pub hash: [u8; 32],
}

impl std::str::FromStr for Checkpoint {
    type Err = anyhow::Error;
    /// `HEIGHT:HASH`, hash in display hex.
    fn from_str(s: &str) -> Result<Self> {
        let (h, hash) = s.split_once(':').context("expected HEIGHT:HASH")?;
        let mut hash: [u8; 32] = hex::decode(hash)?.try_into().map_err(|_| anyhow::anyhow!("hash must be 32 bytes"))?;
        hash.reverse();
        Ok(Checkpoint { height: h.parse()?, hash })
    }
}

#[derive(Default)]
pub struct Chain {
    pub blocks: BTreeMap<u64, BlockEntry>,
    pub by_hash: HashMap<[u8; 32], u64>,
    /// Subtrees completed inside the verified range, per pool.
    pub subtrees: HashMap<Pool, Vec<CompletedSubtree>>,
    /// Frontiers just before the first verified block, which authenticate every subtree
    /// completed before it.
    pub trees_before: Option<Trees>,
    pub first: u64,
    /// Sealed Rings loaded so far, by start height, with their manifest hash.
    sealed: Vec<RingEntry>,
    /// Last block of the newest sealed Ring.
    sealed_end: u64,
    tail_hash: Option<String>,
}

impl Chain {
    pub fn tip(&self) -> Option<&BlockEntry> {
        self.blocks.values().next_back()
    }

    pub fn get(&self, height: u64) -> Option<&BlockEntry> {
        self.blocks.get(&height)
    }

    pub fn height_of(&self, hash: &[u8; 32]) -> Option<u64> {
        self.by_hash.get(hash).copied()
    }

    fn add(&mut self, v: VerifiedRing) {
        if self.blocks.is_empty() {
            self.first = v.start_height;
            self.trees_before = Some(v.trees_before.clone());
        }
        for st in v.subtrees {
            self.subtrees.entry(st.pool).or_default().push(st);
        }
        for ((b, cb), trees) in v.blocks.into_iter().zip(v.compact).zip(v.trees_after) {
            self.by_hash.insert(b.header.hash, b.header.height);
            self.blocks.insert(
                b.header.height,
                BlockEntry { txids: b.txids.into_iter().collect(), header: b.header, compact: cb, trees_after: trees },
            );
        }
    }

    /// Drops everything above `height` (the old tail, before a new one replaces it).
    fn truncate(&mut self, height: u64) {
        let gone: Vec<u64> = self.blocks.range(height + 1..).map(|(h, _)| *h).collect();
        for h in gone {
            if let Some(b) = self.blocks.remove(&h) {
                self.by_hash.remove(&b.header.hash);
            }
        }
        for list in self.subtrees.values_mut() {
            list.retain(|s| s.height <= height);
        }
    }

    fn continuation(&self) -> Option<(Header, Trees)> {
        self.blocks.get(&self.sealed_end).map(|b| (b.header.clone(), b.trees_after.clone()))
    }
}

/// Fetches Rings from a builder or any mirror. Hosts are untrusted: a file is used only
/// if it matches its manifest hash and then passes verification.
pub struct RingSource {
    pub base: String,
    pub http: reqwest::Client,
}

impl RingSource {
    async fn get(&self, path: &str) -> Result<Vec<u8>> {
        let url = format!("{}/{}", self.base.trim_end_matches('/'), path);
        let resp = self.http.get(&url).send().await.with_context(|| url.clone())?;
        if !resp.status().is_success() {
            bail!("{url}: {}", resp.status());
        }
        Ok(resp.bytes().await?.to_vec())
    }

    pub async fn manifest(&self) -> Result<Manifest> {
        Ok(serde_json::from_slice(&self.get("manifest.json").await?)?)
    }

    async fn ring(&self, entry: &RingEntry) -> Result<zylem_proto::ring::Ring> {
        let bytes = self.get(&entry.file).await?;
        if hex::encode(ring::file_hash(&bytes)) != entry.hash {
            bail!("{}: file hash differs from the manifest", entry.file);
        }
        Ok(ring::decode_file(&bytes)?)
    }
}

/// Brings `chain` up to date with the source's manifest: verifies any new sealed Rings in
/// order, then the open tail. Returns a short report of what changed.
pub async fn refresh(chain: &mut Chain, src: &RingSource, network: &Network, from_height: u64) -> Result<Option<String>> {
    let m = src.manifest().await?;
    let mut report = vec![];
    for entry in &m.rings {
        if entry.end_height < from_height || chain.sealed.iter().any(|e| e.start_height == entry.start_height) {
            continue;
        }
        let ring = src.ring(entry).await?;
        let cont = chain.continuation();
        let v = ring::verify(network, &ring, cont.as_ref().map(|(h, t)| Continuation { last_header: h, trees: t }))
            .with_context(|| format!("Ring {}..={} rejected", entry.start_height, entry.end_height))?;
        chain.truncate(chain.sealed_end.max(v.start_height - 1));
        let end = v.end_height();
        chain.add(v);
        chain.sealed.push(entry.clone());
        chain.sealed_end = end;
        chain.tail_hash = None;
        report.push(format!("Ring {}..={} verified", entry.start_height, entry.end_height));
    }
    if let Some(tail) = &m.tail {
        if chain.tail_hash.as_deref() != Some(&tail.hash) && tail.start_height == chain.sealed_end + 1 {
            let ring = src.ring(tail).await?;
            let cont = chain.continuation();
            let v = ring::verify(network, &ring, cont.as_ref().map(|(h, t)| Continuation { last_header: h, trees: t }))
                .with_context(|| format!("tail {}..={} rejected", tail.start_height, tail.end_height))?;
            chain.truncate(chain.sealed_end);
            chain.add(v);
            chain.tail_hash = Some(tail.hash.clone());
            report.push(format!("tail {}..={} verified", tail.start_height, tail.end_height));
        }
    }
    Ok((!report.is_empty()).then(|| {
        let tip = chain.tip().map(|b| (b.header.height, display_hash(&b.header.hash))).unwrap();
        format!("{}; tip {} {}", report.join(", "), tip.0, tip.1)
    }))
}

/// The chain must contain the checkpoint. Everything verified is hash-linked to it.
pub fn check_checkpoint(chain: &Chain, cp: &Checkpoint) -> Result<()> {
    match chain.get(cp.height) {
        Some(b) if b.header.hash == cp.hash => Ok(()),
        Some(_) => bail!("checkpoint mismatch at {}", cp.height),
        None => bail!("checkpoint {} is outside the verified range", cp.height),
    }
}
