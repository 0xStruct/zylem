//! `zylem-build tamper`: a malicious Ring host, for demonstrating rejections. It copies a
//! Ring directory, alters one Ring the way a dishonest server would, and republishes a
//! manifest that matches the altered file, so only verification can catch it.

use std::path::Path;

use anyhow::{bail, Context, Result};
use zylem_core::{
    manifest::Manifest,
    ring,
    tree::Trees,
};
use zylem_proto::ring::Ring;

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub enum Attack {
    /// Add a fake Ironwood action to a transaction (a fake incoming note).
    Inject,
    /// Leave a whole transaction out of a block (a hidden payment).
    Hide,
    /// Replace the Ring's starting Ironwood frontier with a different one of the same
    /// size (wrong tree states, so the wallet builds bad anchors).
    Tree,
}

fn copy_dir(from: &Path, to: &Path) -> Result<()> {
    std::fs::create_dir_all(to.join("rings"))?;
    for entry in std::fs::read_dir(from.join("rings"))? {
        let e = entry?;
        std::fs::copy(e.path(), to.join("rings").join(e.file_name()))?;
    }
    for f in ["manifest.json"] {
        if from.join(f).exists() {
            std::fs::copy(from.join(f), to.join(f))?;
        }
    }
    Ok(())
}

/// Picks the first block at or after `height` with a transaction that has Ironwood
/// actions, or Sapling outputs for `Hide` as a fallback.
fn target(ring: &Ring, height: u64) -> Option<(usize, usize)> {
    for (bi, rb) in ring.blocks.iter().enumerate() {
        let cb = rb.block.as_ref()?;
        if cb.height < height {
            continue;
        }
        if let Some(ti) = cb.vtx.iter().position(|t| !t.ironwood_actions.is_empty()) {
            return Some((bi, ti));
        }
    }
    None
}

pub fn run(from: &Path, out: &Path, attack: Attack, height: u64, tx_index: Option<usize>) -> Result<()> {
    copy_dir(from, out)?;
    let mut m: Manifest = serde_json::from_slice(&std::fs::read(out.join("manifest.json"))?)?;
    let entry = m
        .rings
        .iter_mut()
        .chain(m.tail.iter_mut())
        .find(|e| e.start_height <= height && height <= e.end_height)
        .context("no Ring covers that height")?;
    let path = out.join(&entry.file);
    let mut r = ring::decode_file(&std::fs::read(&path)?)?;

    let what = match attack {
        Attack::Inject | Attack::Hide => {
            let (bi, ti) = match tx_index {
                Some(ti) => ((height - r.start_height) as usize, ti),
                None => target(&r, height).context("no Ironwood transaction at or after that height")?,
            };
            let rb = &mut r.blocks[bi];
            let cb = rb.block.as_mut().unwrap();
            let h = cb.height;
            match attack {
                Attack::Inject => {
                    let mut fake = cb.vtx[ti].ironwood_actions.first().cloned().context("no action to copy")?;
                    fake.nullifier[0] ^= 0x5a;
                    fake.ciphertext[0] ^= 0x5a;
                    cb.vtx[ti].ironwood_actions.push(fake);
                    format!("added a fake Ironwood action to transaction {ti} of block {h}")
                }
                Attack::Hide => {
                    cb.vtx.remove(ti);
                    rb.aux.remove(ti);
                    for (i, t) in cb.vtx.iter_mut().enumerate() {
                        t.index = i as u64;
                    }
                    format!("removed transaction {ti} from block {h}")
                }
                Attack::Tree => unreachable!(),
            }
        }
        Attack::Tree => {
            let start = r.start.as_mut().context("no start state")?;
            let mut t = Trees::decode(&start.sapling_frontier, &start.orchard_frontier, &start.ironwood_frontier)?;
            let Some(nf) = t.ironwood.value() else { bail!("empty Ironwood frontier") };
            // Same position and size, different leaf: the root changes, the sizes don't.
            let leaf = <orchard::tree::MerkleHashOrchard as incrementalmerkletree::Hashable>::empty_leaf();
            t.ironwood = incrementalmerkletree::frontier::Frontier::from_parts(nf.position(), leaf, nf.ommers().to_vec())
                .map_err(|e| anyhow::anyhow!("{e:?}"))?;
            start.ironwood_frontier = t.encode()[2].clone();
            format!("replaced the Ironwood frontier before block {}", r.start_height)
        }
    };
    let bytes = ring::encode_file(&r);
    std::fs::write(&path, &bytes)?;
    entry.hash = hex::encode(ring::file_hash(&bytes));
    entry.size = bytes.len() as u64;
    std::fs::write(out.join("manifest.json"), serde_json::to_vec_pretty(&m)?)?;
    println!("tampered: {what}; manifest updated to match");
    Ok(())
}
