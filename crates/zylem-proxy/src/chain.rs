//! The verified chain: every block the proxy will serve, loaded from Rings and checked
//! with zylem-core before it is visible to wallets.

use std::collections::{BTreeMap, HashMap, HashSet};

use anyhow::{bail, Context, Result};
use primitive_types::U256;
use zcash_protocol::consensus::Network;
use zylem_core::{
    header::{DifficultyContext, Header},
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

/// A trusted checkpoint: the chain must contain this block hash at this height, and the
/// headers after it must carry at least `min_work` (the work the honest chain had from the
/// checkpoint to its release height, from `zylem-build checkpoint`).
#[derive(Clone, Copy, Debug)]
pub struct Checkpoint {
    pub height: u64,
    /// Internal byte order.
    pub hash: [u8; 32],
    pub min_work: Option<U256>,
}

impl std::str::FromStr for Checkpoint {
    type Err = anyhow::Error;
    /// `HEIGHT:HASH[:MINWORK]`, hash in display hex, work in hex.
    fn from_str(s: &str) -> Result<Self> {
        let mut parts = s.split(':');
        let (Some(h), Some(hash)) = (parts.next(), parts.next()) else { bail!("expected HEIGHT:HASH[:MINWORK]") };
        let mut hash: [u8; 32] = hex::decode(hash)?.try_into().map_err(|_| anyhow::anyhow!("hash must be 32 bytes"))?;
        hash.reverse();
        let min_work = parts
            .next()
            .map(|w| U256::from_str_radix(w, 16).map_err(|e| anyhow::anyhow!("minimum work must be hex: {e:?}")))
            .transpose()?;
        if parts.next().is_some() {
            bail!("expected HEIGHT:HASH[:MINWORK]");
        }
        Ok(Checkpoint { height: h.parse()?, hash, min_work })
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
    /// Work of the adopted tail, to compare other sources' tails against.
    tail_work: U256,
    /// First height from which every header's difficulty and time rules were checked.
    pub context_checked_from: Option<u64>,
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
        // An unbroken run of checked headers, from the earliest point it started.
        let continues = self.context_checked_from.is_some() && v.context_checked_from == Some(v.start_height);
        if !continues {
            self.context_checked_from = v.context_checked_from;
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

    fn continuation(&self) -> Option<(Header, Trees, DifficultyContext)> {
        let last = self.blocks.get(&self.sealed_end)?;
        Some((last.header.clone(), last.trees_after.clone(), self.context_at(self.sealed_end)))
    }

    /// The difficulty context up to and including `height`.
    pub fn context_at(&self, height: u64) -> DifficultyContext {
        let from = height.saturating_sub(zylem_header::MAX_CONTEXT as u64 - 1);
        DifficultyContext(self.blocks.range(from..=height).map(|(_, b)| (b.header.bits, b.header.time)).collect())
    }

    /// Total work of the verified headers above `height`.
    pub fn work_above(&self, height: u64) -> U256 {
        self.blocks.range(height + 1..).fold(U256::zero(), |w, (_, b)| w + b.header.work)
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

/// What one Ring host showed in a refresh, for the tip policy.
#[derive(Clone, Debug)]
pub enum RingView {
    /// The host's newest block, after its data verified (or matched data already verified).
    Tip { height: u64, hash: [u8; 32] },
    Unreachable(String),
    /// The host served data that failed verification.
    Rejected(String),
    /// The host lists a sealed Ring that differs from one already verified.
    Conflict(String),
}

fn now_secs() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// Verifies a Ring against the chain's continuation and the clock.
fn verify_next(chain: &Chain, network: &Network, ring: &zylem_proto::ring::Ring) -> Result<VerifiedRing> {
    let cont = chain.continuation();
    let v = ring::verify(network, ring, cont.as_ref().map(|(h, t, c)| Continuation { last_header: h, trees: t, context: c }))?;
    let now = now_secs();
    for b in &v.blocks {
        b.header.check_not_future(now)?;
    }
    Ok(v)
}

fn parse_hash(display: &str) -> Option<[u8; 32]> {
    let mut h: [u8; 32] = hex::decode(display).ok()?.try_into().ok()?;
    h.reverse();
    Some(h)
}

/// Brings `chain` up to date from every Ring host: new sealed Rings are verified in
/// order (they are content-addressed, so honest hosts list the same ones), then every
/// host's open tail is verified and the one with the most work is adopted. Returns a
/// report of what changed and what each host showed.
pub async fn refresh(chain: &mut Chain, srcs: &[RingSource], network: &Network, from_height: u64) -> (Option<String>, Vec<RingView>) {
    let mut report = vec![];
    let mut views: Vec<Option<RingView>> = vec![None; srcs.len()];
    let mut manifests = Vec::with_capacity(srcs.len());
    for (i, src) in srcs.iter().enumerate() {
        match src.manifest().await {
            Ok(m) => manifests.push(Some(m)),
            Err(e) => {
                views[i] = Some(RingView::Unreachable(format!("{e:#}")));
                manifests.push(None);
            }
        }
    }

    // Sealed Rings: any host's, checked against what is already verified.
    for (i, (src, m)) in srcs.iter().zip(&manifests).enumerate() {
        let Some(m) = m else { continue };
        for entry in &m.rings {
            if entry.end_height < from_height {
                continue;
            }
            if let Some(known) = chain.sealed.iter().find(|e| e.start_height == entry.start_height) {
                if known.hash != entry.hash {
                    views[i] = Some(RingView::Conflict(format!("Ring {}: {} differs from verified {}", entry.start_height, entry.hash, known.hash)));
                }
                continue;
            }
            if chain.sealed_end != 0 && entry.start_height != chain.sealed_end + 1 {
                continue;
            }
            let verified = match src.ring(entry).await {
                Ok(ring) => verify_next(chain, network, &ring)
                    .with_context(|| format!("Ring {}..={} rejected", entry.start_height, entry.end_height)),
                Err(e) => Err(e),
            };
            match verified {
                Ok(v) => {
                    chain.truncate(chain.sealed_end.max(v.start_height - 1));
                    let end = v.end_height();
                    chain.add(v);
                    chain.sealed.push(entry.clone());
                    chain.sealed_end = end;
                    chain.tail_hash = None;
                    chain.tail_work = U256::zero();
                    report.push(format!("Ring {}..={} verified", entry.start_height, entry.end_height));
                }
                Err(e) => {
                    tracing::warn!(target: "zylem", "REJECT {}: {e:#}", src.base);
                    views[i] = Some(RingView::Rejected(format!("{e:#}")));
                    break;
                }
            }
        }
    }

    // Open tails: verify every host's, adopt the one with the most work.
    let mut best: Option<(usize, RingEntry, VerifiedRing)> = None;
    let mut best_work = chain.tail_work;
    for (i, (src, m)) in srcs.iter().zip(&manifests).enumerate() {
        let Some(tail) = m.as_ref().and_then(|m| m.tail.clone()) else { continue };
        if views[i].is_some() || tail.start_height != chain.sealed_end + 1 || chain.tail_hash.as_deref() == Some(&tail.hash) {
            continue;
        }
        let verified = match src.ring(&tail).await {
            Ok(ring) => verify_next(chain, network, &ring).with_context(|| format!("tail {}..={} rejected", tail.start_height, tail.end_height)),
            Err(e) => Err(e),
        };
        match verified {
            Ok(v) if v.work > best_work => {
                best_work = v.work;
                best = Some((i, tail, v));
            }
            Ok(_) => {}
            Err(e) => {
                tracing::warn!(target: "zylem", "REJECT {}: {e:#}", src.base);
                views[i] = Some(RingView::Rejected(format!("{e:#}")));
            }
        }
    }
    if let Some((i, tail, v)) = best {
        chain.truncate(chain.sealed_end);
        chain.add(v);
        chain.tail_hash = Some(tail.hash.clone());
        chain.tail_work = best_work;
        report.push(format!("tail {}..={} verified (from {})", tail.start_height, tail.end_height, srcs[i].base));
    }

    // What each host's newest block is, for the tip policy.
    for (i, m) in manifests.iter().enumerate() {
        if views[i].is_some() {
            continue;
        }
        let Some(m) = m else { continue };
        let newest = m.tail.as_ref().or(m.rings.last());
        if let Some(e) = newest {
            if let Some(hash) = parse_hash(&e.last_block_hash) {
                views[i] = Some(RingView::Tip { height: e.end_height, hash });
            }
        }
    }
    let views = views.into_iter().map(|v| v.unwrap_or(RingView::Unreachable("no Rings".into()))).collect();
    let report = (!report.is_empty()).then(|| {
        let tip = chain.tip().map(|b| (b.header.height, display_hash(&b.header.hash))).unwrap();
        format!("{}; tip {} {}", report.join(", "), tip.0, tip.1)
    });
    (report, views)
}

/// The chain must contain the checkpoint. Everything verified is hash-linked to it.
/// Headers up to the checkpoint are authenticated by hash links back from it; every
/// header after it must also have passed the difficulty and time rules, and together
/// carry at least the checkpoint's minimum work.
pub fn check_checkpoint(chain: &Chain, cp: &Checkpoint) -> Result<()> {
    match chain.get(cp.height) {
        Some(b) if b.header.hash == cp.hash => {}
        Some(_) => bail!("checkpoint mismatch at {}", cp.height),
        None => bail!("checkpoint {} is outside the verified range", cp.height),
    }
    match chain.context_checked_from {
        Some(from) if from <= cp.height + 1 => {}
        Some(from) => bail!(
            "difficulty rules are checked only from {from}, after the checkpoint {}; use a later checkpoint",
            cp.height
        ),
        None => bail!("no header was checked against the difficulty rules"),
    }
    if let Some(min) = cp.min_work {
        let have = chain.work_above(cp.height);
        if have < min {
            bail!("verified work after the checkpoint is {have:x}, below the minimum {min:x}: a chain this light is not the real one");
        }
    }
    Ok(())
}
