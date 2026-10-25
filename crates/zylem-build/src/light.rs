//! Light Rings: for each sealed Ring a published history proof covers, a copy whose
//! covered blocks carry the proof's 104-byte records instead of their headers, and the
//! sibling hashes that bind those records to the proof. Each light Ring is verified
//! against the proof's claim before it is written. Output goes into the publish
//! directory: `rings/light-*.zst` beside the full Rings, `binding/light-*.json` and
//! `light.json`.

use std::path::Path;

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use zcash_protocol::consensus::Network;
use zylem_core::ring::{self, Proven};
use zylem_header::{range_paths, Claim, Peaks, RangeClaim, RECORD_SIZE};

use crate::{builder::read_manifest, publish::named};

/// What a light Ring needs from either claim version.
struct Covered {
    first: u64,
    last: u64,
    anchor_hash: [u8; 32],
    equihash_checked: bool,
    records: Peaks,
}

fn covered(pv: &[u8]) -> Result<Covered> {
    if let Some(c) = Claim::decode(pv) {
        return Ok(Covered { first: c.first_height, last: c.last_height, anchor_hash: c.anchor_hash, equihash_checked: c.equihash_checked, records: c.records });
    }
    let c = RangeClaim::decode(pv).context("history claim")?;
    Ok(Covered { first: c.first_height, last: c.last_height, anchor_hash: c.anchor_hash, equihash_checked: c.equihash_checked, records: c.records })
}

pub fn run(publish: &Path, rings: &Path, network: &Network) -> Result<()> {
    let history: Value = serde_json::from_slice(&std::fs::read(publish.join("history.json")).context("history.json")?)?;
    let file = |key: &str| -> Result<Vec<u8>> {
        let rel = history[key].as_str().with_context(|| format!("history.json has no {key}"))?;
        std::fs::read(publish.join(rel)).with_context(|| rel.to_string())
    };
    let claim = covered(&file("public_values")?)?;
    if !claim.equihash_checked {
        bail!("the proof did not check Equihash, so it cannot stand in for headers");
    }
    let bytes = file("records")?;
    let all: Vec<[u8; RECORD_SIZE]> = bytes.chunks(RECORD_SIZE).map(|c| c.try_into().unwrap()).collect();
    if bytes.len() % RECORD_SIZE != 0 || Peaks::of_records(claim.first, &all) != claim.records {
        bail!("the records do not match the proof's commitment");
    }

    let m = read_manifest(rings)?.context("no Ring manifest")?;
    for d in ["rings", "binding"] {
        std::fs::create_dir_all(publish.join(d))?;
    }
    let mut entries = vec![];
    for e in &m.rings {
        let (a, b) = (e.start_height.max(claim.first), e.end_height.min(claim.last));
        if a > b {
            continue;
        }
        let full = std::fs::read(rings.join(&e.file)).with_context(|| e.file.clone())?;
        // Hosts serve the full Ring beside the light one, for clients without the proof.
        std::fs::write(publish.join(&e.file), &full)?;
        let mut r = ring::decode_file(&full)?;
        let prev_record = (a == e.start_height && a > claim.first).then(|| all[(a - 1 - claim.first) as usize]);
        ring::lighten(&mut r, a, b, prev_record)?;
        let (from, to) = Proven::binding_range(claim.first, a, b);
        let paths = range_paths(claim.first, &all, from, to);
        let proven = Proven {
            first_height: claim.first,
            last_height: claim.last,
            anchor_hash: claim.anchor_hash,
            equihash_checked: claim.equihash_checked,
            records: &claim.records,
            paths: &paths,
        };
        ring::verify_light(network, &r, None, &proven).with_context(|| format!("light Ring {}..={}", e.start_height, e.end_height))?;

        let light = ring::encode_file(&r);
        let hash = hex::encode(ring::file_hash(&light));
        let name = format!("rings/light-{}-{}-{}.zst", e.start_height, e.end_height, &hash[..16]);
        std::fs::write(publish.join(&name), &light)?;
        let hexed: Vec<Vec<String>> = paths.iter().map(|p| p.iter().map(hex::encode).collect()).collect();
        let body = serde_json::to_vec_pretty(&json!({"ring": name, "light": [a, b], "from": from, "to": to, "paths": hexed}))?;
        let binding = named(&publish.join("binding"), &format!("light-{}-{}", e.start_height, e.end_height), "json", &body)?;
        println!(
            "{}..={}: {} of {} blocks light, {} B -> {} B ({:.0}% smaller)",
            e.start_height,
            e.end_height,
            b - a + 1,
            e.end_height - e.start_height + 1,
            full.len(),
            light.len(),
            100.0 * (1.0 - light.len() as f64 / full.len() as f64)
        );
        entries.push(json!({
            "start_height": e.start_height,
            "end_height": e.end_height,
            "light": [a, b],
            "file": name,
            "hash": hash,
            "size": light.len(),
            "full_file": e.file,
            "full_size": full.len(),
            "binding": format!("binding/{binding}"),
        }));
    }
    if entries.is_empty() {
        bail!("no sealed Ring overlaps the proven range {}..={}", claim.first, claim.last);
    }
    let index = json!({"covers": {"first": claim.first, "last": claim.last}, "rings": entries});
    std::fs::write(publish.join("light.json"), serde_json::to_string_pretty(&index)? + "\n")?;
    Ok(())
}
