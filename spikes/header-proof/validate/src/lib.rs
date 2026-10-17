//! Loading headers from Zylem Rings, for the native validator and the host.

use std::path::Path;

use anyhow::{Context, Result};
use zylem_core::{manifest::Manifest, ring};

/// Every header in a Ring directory, in height order: (height, raw header).
pub fn load_headers(dir: &Path) -> Result<Vec<(u64, Vec<u8>)>> {
    let m: Manifest = serde_json::from_slice(&std::fs::read(dir.join("manifest.json")).context("manifest")?)?;
    let mut out = vec![];
    for entry in m.rings.iter().chain(m.tail.iter()) {
        let r = ring::decode_file(&std::fs::read(dir.join(&entry.file))?)?;
        for (i, b) in r.blocks.into_iter().enumerate() {
            out.push((r.start_height + i as u64, b.header));
        }
    }
    Ok(out)
}
