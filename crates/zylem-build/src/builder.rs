//! Building Rings: bootstrap the chain state at the first Ring, then write one Ring per
//! epoch plus the open tail, verifying each before it is published.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use zcash_protocol::consensus::Network;
use zylem_core::{
    block::{self, PoolTxCounts},
    header::Header,
    history::{self, HistoryTree, LeafParts},
    manifest::{display_hash, Manifest, RingEntry},
    merkle,
    ring::{self, Continuation},
    tree::Trees,
};
use zylem_proto::ring::{Ring, RingStart};

use crate::{lwd, node::Node};

/// Chain state after `height`.
pub struct State {
    pub height: u64,
    pub trees: Trees,
    pub history: HistoryTree,
    pub last_header: Option<Header>,
}

pub struct Builder {
    pub node: Node,
    pub network: Network,
    pub out: PathBuf,
    pub epoch_length: u64,
    pub finality: u64,
}

fn network_name(n: &Network) -> &'static str {
    match n {
        Network::MainNetwork => "main",
        Network::TestNetwork => "test",
    }
}

pub fn read_manifest(dir: &Path) -> Result<Option<Manifest>> {
    let p = dir.join("manifest.json");
    if !p.exists() {
        return Ok(None);
    }
    Ok(Some(serde_json::from_slice(&std::fs::read(p)?)?))
}

impl Builder {
    fn write_manifest(&self, m: &Manifest) -> Result<()> {
        let tmp = self.out.join("manifest.json.tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(m)?)?;
        std::fs::rename(tmp, self.out.join("manifest.json"))?;
        Ok(())
    }

    /// Replays the history tree from the upgrade's activation to `to` (inclusive), using
    /// the node's headers and a light-wallet server's compact blocks for blocks a pruned
    /// node no longer has. Nothing here is trusted: the result is checked against the next
    /// header's block commitments before any Ring is built on it.
    pub async fn bootstrap(&self, lwd_url: &str, to: u64) -> Result<State> {
        let act = history::epoch_start(&self.network, to);
        eprintln!("bootstrap: history tree {act}..={to} ({} blocks)", to - act + 1);
        let mut client = lwd::connect(lwd_url).await?;
        let [s, o, i] = lwd::tree_state(&mut client, act - 1).await?;
        let mut trees = Trees::from_tree_state(&s, &o, &i)?;
        let headers = self.node.headers(act, to).await.context("bootstrap headers")?;
        let mut history: Option<HistoryTree> = None;
        let mut last = None;
        let mut h = act;
        while h <= to {
            let e = (h + 999).min(to);
            let cbs = lwd::blocks(&mut client, h, e).await?;
            if cbs.len() as u64 != e - h + 1 {
                bail!("light-wallet server returned {} blocks for {h}..={e}", cbs.len());
            }
            for cb in cbs {
                let height = cb.height;
                let header = Header::parse_unchecked(height, &headers[(height - act) as usize])?;
                if cb.hash != header.hash {
                    bail!("light-wallet server block {height} differs from the node's header");
                }
                trees.append_block(height, &cb.vtx)?;
                let parts = LeafParts { header: &header, roots: trees.roots(), counts: PoolTxCounts::of(&cb.vtx) };
                match &mut history {
                    None => history = Some(HistoryTree::first(&self.network, &parts)?),
                    Some(t) => t.append(&parts)?,
                }
                last = Some(header);
            }
            h = e + 1;
            eprintln!("  replayed to {e}");
        }
        let history = history.context("empty bootstrap range")?;

        // Self-check against the node: the next header commits to this history tree, and
        // the node's tree state agrees with the replayed frontiers.
        let next = block::assemble(to + 1, &self.node.block(to + 1).await?, &self.network)?;
        let next_header = Header::parse_unchecked(to + 1, &next.header)?;
        let auth: [u8; 32] = next.auth_data_root[..].try_into()?;
        if next_header.commitments != merkle::block_commitments(&history.root(), &auth) {
            bail!("bootstrap history tree does not match header {}", to + 1);
        }
        let [s, o, i] = self.node.tree_state(to).await?;
        if Trees::from_tree_state(&s, &o, &i)?.roots() != trees.roots() {
            bail!("bootstrap trees differ from the node's tree state at {to}");
        }
        eprintln!("bootstrap: history tree and trees match header {} and the node", to + 1);
        Ok(State { height: to, trees, history, last_header: last })
    }

    /// Builds the Ring for `[start, end]` on top of `state`, advancing it. A sealed Ring
    /// carries the next header so its last block is authenticated too.
    pub async fn build(&self, state: &mut State, start: u64, end: u64, sealed: bool) -> Result<Ring> {
        assert_eq!(start, state.height + 1);
        let [sf, of, if_] = state.trees.encode();
        let (branch, len, peaks) = state.history.export();
        let ring_start = RingStart {
            sapling_frontier: sf,
            orchard_frontier: of,
            ironwood_frontier: if_,
            history_length: len,
            history_branch_id: branch,
            history_peaks: peaks,
        };
        let raws = self.node.blocks(start, if sealed { end + 1 } else { end }).await?;
        let mut blocks = Vec::with_capacity((end - start + 1) as usize);
        for (i, raw) in raws.iter().take((end - start + 1) as usize).enumerate() {
            let height = start + i as u64;
            let mut rb = block::assemble(height, raw, &self.network)?;
            let header = Header::parse_unchecked(height, &rb.header)?;
            let cb = rb.block.as_mut().unwrap();
            state.trees.append_block(height, &cb.vtx)?;
            cb.chain_metadata = Some(state.trees.sizes());
            let roots = state.trees.roots();
            rb.sapling_root = roots.sapling.to_vec();
            rb.orchard_root = roots.orchard.to_vec();
            rb.ironwood_root = roots.ironwood.to_vec();
            state
                .history
                .append(&LeafParts { header: &header, roots, counts: PoolTxCounts::of(&cb.vtx) })?;
            state.last_header = Some(header);
            blocks.push(rb);
        }
        state.height = end;
        let (next_header, next_auth_data_root) = if sealed {
            let next = block::assemble(end + 1, raws.last().unwrap(), &self.network)?;
            (next.header, next.auth_data_root)
        } else {
            (vec![], vec![])
        };
        Ok(Ring {
            format: ring::FORMAT,
            network: network_name(&self.network).into(),
            start_height: start,
            end_height: end,
            start: Some(ring_start),
            blocks,
            next_header,
            next_auth_data_root,
        })
    }

    fn write_ring(&self, ring: &Ring, name: &str) -> Result<RingEntry> {
        let bytes = ring::encode_file(ring);
        let hash = ring::file_hash(&bytes);
        std::fs::create_dir_all(self.out.join("rings"))?;
        // Content-addressed names, tail included, so a reader that fetched the manifest
        // just before a rewrite still finds the file it names.
        let file = format!("rings/{name}-{}-{}-{}.zst", ring.start_height, ring.end_height, &hex::encode(hash)[..16]);
        let tmp = self.out.join(format!("{file}.tmp"));
        std::fs::write(&tmp, &bytes)?;
        std::fs::rename(&tmp, self.out.join(&file))?;
        let last = Header::parse_unchecked(ring.end_height, &ring.blocks.last().unwrap().header)?;
        Ok(RingEntry {
            start_height: ring.start_height,
            end_height: ring.end_height,
            last_block_hash: display_hash(&last.hash),
            file,
            hash: hex::encode(hash),
            size: bytes.len() as u64,
        })
    }

    /// Old tail files are kept for a few rewrites so in-flight readers still find them.
    fn retire_tails(&self) {
        let dir = self.out.join("rings");
        let mut tails: Vec<_> = std::fs::read_dir(&dir)
            .into_iter()
            .flatten()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().starts_with("tail-"))
            .filter_map(|e| Some((e.metadata().ok()?.modified().ok()?, e.path())))
            .collect();
        tails.sort();
        let keep = 4;
        for (_, p) in tails.iter().take(tails.len().saturating_sub(keep)) {
            let _ = std::fs::remove_file(p);
        }
    }

    /// Loads the state at the end of the newest sealed Ring by verifying that Ring.
    fn resume(&self, m: &Manifest) -> Result<Option<State>> {
        let Some(entry) = m.rings.last() else { return Ok(None) };
        let ring = ring::decode_file(&std::fs::read(self.out.join(&entry.file))?)?;
        let v = ring::verify(&self.network, &ring, None)?;
        Ok(Some(State {
            height: v.end_height(),
            trees: v.trees_after.last().unwrap().clone(),
            last_header: Some(v.last_header().clone()),
            history: v.history,
        }))
    }

    /// Writes every Ring whose epoch is past the finality depth, then the open tail.
    /// `lwd` is needed only the first time, to bootstrap below a pruned node.
    pub async fn step(&self, lwd_url: Option<&str>, max_rings: Option<usize>) -> Result<Manifest> {
        std::fs::create_dir_all(&self.out)?;
        let tip = self.node.tip().await?;
        let act = history::epoch_start(&self.network, tip);
        let mut m = read_manifest(&self.out)?.unwrap_or(Manifest {
            network: network_name(&self.network).into(),
            format: ring::FORMAT,
            epoch_length: self.epoch_length,
            epoch_start: act,
            finality_depth: self.finality,
            rings: vec![],
            tail: None,
        });
        let mut state = match self.resume(&m)? {
            Some(s) => s,
            None => {
                let prune = self.node.prune_height().await?;
                let k = prune.saturating_sub(act).div_ceil(self.epoch_length).max(1);
                let first = act + k * self.epoch_length;
                let lwd_url = lwd_url.context("first build needs --lwd to bootstrap below the prune height")?;
                self.bootstrap(lwd_url, first - 1).await?
            }
        };
        let mut built = 0;
        loop {
            let start = state.height + 1;
            let end = start + self.epoch_length - 1;
            if end + self.finality > tip || max_rings.is_some_and(|n| built >= n) {
                break;
            }
            let prev_header = state.last_header.clone();
            let prev_trees = state.trees.clone();
            let ring = self.build(&mut state, start, end, true).await?;
            // A builder never publishes a Ring that fails verification.
            let prev = prev_header.as_ref().map(|h| Continuation { last_header: h, trees: &prev_trees });
            ring::verify(&self.network, &ring, prev).context("self-check")?;
            let entry = self.write_ring(&ring, "ring")?;
            eprintln!("ring {start}..={end}: {} bytes, verified", entry.size);
            m.rings.push(entry);
            m.tail = None;
            self.write_manifest(&m)?;
            built += 1;
        }
        // The open tail: everything after the newest sealed Ring.
        let start = state.height + 1;
        if start <= tip && max_rings.is_none() {
            let prev_header = state.last_header.clone();
            let prev_trees = state.trees.clone();
            let ring = self.build(&mut state, start, tip, false).await?;
            let prev = prev_header.as_ref().map(|h| Continuation { last_header: h, trees: &prev_trees });
            ring::verify(&self.network, &ring, prev).context("tail self-check")?;
            let entry = self.write_ring(&ring, "tail")?;
            m.tail = Some(entry);
            self.write_manifest(&m)?;
            self.retire_tails();
            eprintln!("tail {start}..={tip}");
        }
        Ok(m)
    }
}

/// Verifies every Ring in a directory's manifest, in order, as a client would.
pub fn verify_dir(dir: &Path, network: &Network) -> Result<()> {
    let m = read_manifest(dir)?.context("no manifest")?;
    let started = std::time::Instant::now();
    let mut prev: Option<(Header, Trees)> = None;
    let (mut blocks, mut txs) = (0u64, 0u64);
    for entry in m.rings.iter().chain(m.tail.iter()) {
        let bytes = std::fs::read(dir.join(&entry.file))?;
        if hex::encode(ring::file_hash(&bytes)) != entry.hash {
            bail!("{}: file hash differs from the manifest", entry.file);
        }
        let ring = ring::decode_file(&bytes)?;
        let cont = prev.as_ref().map(|(h, t)| Continuation { last_header: h, trees: t });
        let v = ring::verify(network, &ring, cont).with_context(|| entry.file.clone())?;
        blocks += v.blocks.len() as u64;
        txs += v.blocks.iter().map(|b| b.txids.len() as u64).sum::<u64>();
        println!(
            "  {} {}..={}: ok (roots authenticated to {})",
            entry.file, v.start_height, v.end_height(), v.authenticated_to
        );
        prev = Some((v.last_header().clone(), v.trees_after.last().unwrap().clone()));
    }
    println!(
        "verified {blocks} blocks, {txs} transactions in {:.1} s",
        started.elapsed().as_secs_f64()
    );
    Ok(())
}

/// Cuts `[from, to]` out of a verified Ring directory as a self-contained Ring: start
/// state just before `from`, and the next header so every block is authenticated. Used
/// for test fixtures; needs no node.
pub fn slice_dir(dir: &Path, network: &Network, from: u64, to: u64, out: &Path) -> Result<()> {
    let m = read_manifest(dir)?.context("no manifest")?;
    let entry = m
        .rings
        .iter()
        .chain(m.tail.iter())
        .find(|e| e.start_height <= from && to < e.end_height)
        .context("slice must sit inside one Ring, before its last block")?;
    let ring = ring::decode_file(&std::fs::read(dir.join(&entry.file))?)?;
    let skip = (from - ring.start_height) as usize;
    let mut head = ring.clone();
    head.blocks.truncate(skip);
    head.end_height = from - 1;
    head.next_header = ring.blocks[skip].header.clone();
    head.next_auth_data_root = ring.blocks[skip].auth_data_root.clone();
    let v = ring::verify(network, &head, None).context("verifying the part before the slice")?;
    let [sf, of, if_] = v.trees_after.last().unwrap().encode();
    let (branch, len, peaks) = v.history.export();
    let n = (to - from + 1) as usize;
    let slice = Ring {
        format: ring::FORMAT,
        network: ring.network.clone(),
        start_height: from,
        end_height: to,
        start: Some(RingStart {
            sapling_frontier: sf,
            orchard_frontier: of,
            ironwood_frontier: if_,
            history_length: len,
            history_branch_id: branch,
            history_peaks: peaks,
        }),
        blocks: ring.blocks[skip..skip + n].to_vec(),
        next_header: ring.blocks[skip + n].header.clone(),
        next_auth_data_root: ring.blocks[skip + n].auth_data_root.clone(),
    };
    ring::verify(network, &slice, None).context("verifying the slice")?;
    std::fs::write(out, ring::encode_file(&slice))?;
    println!("wrote {} ({} blocks)", out.display(), n);
    Ok(())
}
