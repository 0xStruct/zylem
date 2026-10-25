//! Lays out what a host serves: sealed Rings and their manifest, the history proof with
//! its public values, the block records it commits to, and for each Ring inside the
//! proof's range the sibling hashes that bind its records to the proof. Everything except
//! `history.json`, `manifest.json` and `registry.json` is named by its hash and never
//! changes.
//!
//! A generation 0 proof (v1 claim) is published with the two program keys from the
//! prover's `vks.json`; a generation 1 proof (v2 claim) with the registry its aggregation
//! checked against, which clients hash to a root they pin.

use std::path::Path;

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use zylem_header::{range_paths, Claim, Peaks, RangeClaim, RECORD_SIZE};

use crate::builder::read_manifest;

pub struct Options<'a> {
    /// `zylem-build jobs` output: manifest with the anchor, and `records.bin`.
    pub jobs: &'a Path,
    /// `export-proof` output prefix: `PREFIX.proof`, `PREFIX.pv`.
    pub history: &'a Path,
    /// Generation 0: `vks.json` written by the prover.
    pub vks: Option<&'a Path>,
    /// Generation 1: the programs directory holding `registry.json`.
    pub registry: Option<&'a Path>,
    pub rings: &'a Path,
    pub groth16: Option<&'a Path>,
    pub out: &'a Path,
}

pub(crate) fn named(dir: &Path, stem: &str, ext: &str, bytes: &[u8]) -> Result<String> {
    let h = hex::encode(&Sha256::digest(bytes)[..8]);
    let name = format!("{stem}-{h}.{ext}");
    std::fs::write(dir.join(&name), bytes)?;
    Ok(name)
}

fn internal(display: &str) -> Result<String> {
    let mut b = hex::decode(display)?;
    b.reverse();
    Ok(hex::encode(b))
}

pub fn run(o: Options<'_>) -> Result<()> {
    let jm: Value = serde_json::from_slice(&std::fs::read(o.jobs.join("manifest.json")).context("jobs manifest")?)?;
    let records = std::fs::read(o.jobs.join("records.bin")).context("records.bin")?;
    let pv = std::fs::read(o.history.with_extension("pv")).context("history public values")?;
    let proof = std::fs::read(o.history.with_extension("proof")).context("history proof")?;
    let claim = Summary::of(&pv)?;
    let programs = match (&claim.generation, o.vks, o.registry) {
        (0, Some(vks), _) => serde_json::from_slice::<Value>(&std::fs::read(vks).context("vks.json")?)?,
        (1, _, Some(dir)) => {
            let reg: Value = serde_json::from_slice(&std::fs::read(dir.join("registry.json")).context("registry.json")?)?;
            if reg["root"].as_str() != Some(claim.registry_root.as_str()) {
                bail!("the proof was made under registry {}, the registry file is {}", claim.registry_root, reg["root"]);
            }
            reg
        }
        (0, ..) => bail!("a generation 0 proof needs --vks"),
        _ => bail!("a generation 1 proof needs --registry"),
    };
    let first = jm["first"].as_u64().context("first")?;
    if claim.first_height != first {
        bail!("the proof starts at {}, the jobs at {first}", claim.first_height);
    }
    let all: Vec<[u8; RECORD_SIZE]> = records.chunks(RECORD_SIZE).map(|c| c.try_into().unwrap()).collect();
    let covered = (claim.last_height - first + 1) as usize;
    if all.len() < covered {
        bail!("records cover {} blocks, the proof {covered}", all.len());
    }
    let all = &all[..covered];
    if Peaks::of_records(first, all) != claim.records {
        bail!("the records do not match the proof's commitment");
    }

    for d in ["rings", "proofs", "records", "binding"] {
        std::fs::create_dir_all(o.out.join(d))?;
    }
    let last = claim.last_height;
    let proof_name = named(&o.out.join("proofs"), &format!("history-{first}-{last}"), "proof", &proof)?;
    let pv_name = named(&o.out.join("proofs"), &format!("history-{first}-{last}"), "pv", &pv)?;
    let flat: Vec<u8> = all.iter().flatten().copied().collect();
    let rec_name = named(&o.out.join("records"), &format!("records-{first}-{last}"), "bin", &flat)?;
    let groth16 = match o.groth16 {
        Some(p) => Some(named(&o.out.join("proofs"), &format!("history-{first}-{last}"), "groth16", &std::fs::read(p)?)?),
        None => None,
    };

    // Rings, and a binding for each sealed Ring inside the proven range.
    let m = read_manifest(o.rings)?.context("no Ring manifest")?;
    let mut bindings = vec![];
    for e in m.rings.iter().chain(m.tail.iter()) {
        std::fs::copy(o.rings.join(&e.file), o.out.join(&e.file)).with_context(|| e.file.clone())?;
        if e.start_height >= first && e.end_height <= last {
            let paths = range_paths(first, all, e.start_height, e.end_height);
            let hexed: Vec<Vec<String>> = paths.iter().map(|p| p.iter().map(hex::encode).collect()).collect();
            let body = serde_json::to_vec_pretty(&json!({"from": e.start_height, "to": e.end_height, "ring": e.file, "paths": hexed}))?;
            let name = named(&o.out.join("binding"), &format!("ring-{}-{}", e.start_height, e.end_height), "json", &body)?;
            bindings.push(json!({"from": e.start_height, "to": e.end_height, "ring": e.file, "binding": format!("binding/{name}")}));
        }
    }
    std::fs::write(o.out.join("manifest.json"), serde_json::to_string_pretty(&m)? + "\n")?;
    if claim.generation == 1 {
        std::fs::write(o.out.join("registry.json"), serde_json::to_string_pretty(&programs)? + "\n")?;
    }

    let anchor = &jm["anchor"];
    let history = json!({
        "network": jm["network"],
        "covers": {"first": first, "last": last, "leaves": claim.leaves},
        "work": hex::encode(claim.work),
        "equihash_checked": claim.equihash_checked,
        "anchor": {
            "height": anchor["height"],
            "hash": anchor["hash"],
            "hash_internal": internal(anchor["hash"].as_str().unwrap_or_default())?,
            "context_hash": anchor["context_hash"],
        },
        "generation": claim.generation,
        "programs": if claim.generation == 0 { programs } else { json!({"registry": "registry.json", "root": claim.registry_root, "aggregation_key": claim.program}) },
        "proof": format!("proofs/{proof_name}"),
        "public_values": format!("proofs/{pv_name}"),
        "groth16": groth16.map(|g| format!("proofs/{g}")),
        "records": format!("records/{rec_name}"),
        "rings": "manifest.json",
        "bindings": bindings,
    });
    std::fs::write(o.out.join("history.json"), serde_json::to_string_pretty(&history)? + "\n")?;
    println!(
        "published {first}..={last}: proof {} bytes, {} records, {} Ring bindings, to {}",
        proof.len(),
        all.len(),
        history["bindings"].as_array().map_or(0, Vec::len),
        o.out.display()
    );
    Ok(())
}

/// What publishing needs from either claim version.
struct Summary {
    generation: u8,
    first_height: u64,
    last_height: u64,
    work: [u8; 32],
    leaves: u32,
    equihash_checked: bool,
    records: Peaks,
    registry_root: String,
    program: String,
}

impl Summary {
    fn of(pv: &[u8]) -> Result<Self> {
        if let Some(c) = Claim::decode(pv) {
            let key: Vec<u8> = c.program.iter().flat_map(|w| w.to_le_bytes()).collect();
            return Ok(Summary {
                generation: 1,
                first_height: c.first_height,
                last_height: c.last_height,
                work: c.work,
                leaves: c.leaves,
                equihash_checked: c.equihash_checked,
                records: c.records,
                registry_root: hex::encode(c.registry_root),
                program: hex::encode(key),
            });
        }
        let c = RangeClaim::decode(pv).context("history claim")?;
        Ok(Summary {
            generation: 0,
            first_height: c.first_height,
            last_height: c.last_height,
            work: c.work,
            leaves: c.leaves,
            equihash_checked: c.equihash_checked,
            records: c.records,
            registry_root: String::new(),
            program: String::new(),
        })
    }
}
