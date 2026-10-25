//! `zylem-build tamper`: a malicious Ring host, for demonstrating rejections. It copies a
//! Ring directory, alters one Ring the way a dishonest server would, and republishes a
//! manifest that matches the altered file, so only verification can catch it.

use std::path::Path;

use anyhow::{Context, Result};
use zylem_core::{manifest::Manifest, ring, tamper};

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
    let attack = match attack {
        Attack::Inject => tamper::Attack::Inject,
        Attack::Hide => tamper::Attack::Hide,
        Attack::Tree => tamper::Attack::Tree,
    };
    let what = tamper::apply(&mut r, attack, height, tx_index).map_err(anyhow::Error::msg)?;
    let bytes = ring::encode_file(&r);
    std::fs::write(&path, &bytes)?;
    entry.hash = hex::encode(ring::file_hash(&bytes));
    entry.size = bytes.len() as u64;
    std::fs::write(out.join("manifest.json"), serde_json::to_vec_pretty(&m)?)?;
    println!("tampered: {what}; manifest updated to match");
    Ok(())
}
