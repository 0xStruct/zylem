//! Zylem client verification compiled to WebAssembly: the calls a wallet or a web page
//! makes. Every function returns a JSON string, or throws with the reason a check failed.

use serde_json::json;
use wasm_bindgen::prelude::*;
use zylem_header::{range_paths, Claim, Kind, Peaks, RangeClaim, Registry, ANY_ERA, RECORD_SIZE};

fn err(e: impl core::fmt::Debug) -> JsError {
    JsError::new(&format!("{e:?}"))
}

fn u32x8(v: &[u32]) -> Result<[u32; 8], JsError> {
    v.try_into().map_err(|_| JsError::new("a program key digest is 8 words"))
}

fn h32(hex_str: &str) -> Result<[u8; 32], JsError> {
    hex::decode(hex_str).map_err(err)?.try_into().map_err(|_| JsError::new("expected 32 bytes"))
}

fn records(bytes: &[u8]) -> Result<Vec<[u8; RECORD_SIZE]>, JsError> {
    if bytes.len() % RECORD_SIZE != 0 {
        return Err(JsError::new("records are 104 bytes each"));
    }
    Ok(bytes.chunks(RECORD_SIZE).map(|c| c.try_into().unwrap()).collect())
}

fn claim_of(public_values: &[u8]) -> Result<RangeClaim, JsError> {
    RangeClaim::decode(public_values).ok_or_else(|| JsError::new("the public values are not a Zylem claim"))
}

/// The heights and records commitment of a claim of either version.
struct Covered {
    first_height: u64,
    last_height: u64,
    records: Peaks,
}

fn covered(public_values: &[u8]) -> Result<Covered, JsError> {
    if let Some(c) = Claim::decode(public_values) {
        return Ok(Covered { first_height: c.first_height, last_height: c.last_height, records: c.records });
    }
    let c = claim_of(public_values)?;
    Ok(Covered { first_height: c.first_height, last_height: c.last_height, records: c.records })
}

fn registry_of(registry_json: &str) -> Result<Registry, JsError> {
    #[derive(serde::Deserialize)]
    struct File {
        entries: Vec<zylem_header::Entry>,
    }
    Ok(Registry { entries: serde_json::from_str::<File>(registry_json).map_err(err)?.entries })
}

/// The root a `registry.json` hashes to, hex: what a client pins.
#[wasm_bindgen]
pub fn registry_root(registry_json: &str) -> Result<String, JsError> {
    Ok(hex::encode(registry_of(registry_json)?.root()))
}

/// The generation 1 client rule. `registry_json` is the published `registry.json`;
/// `pinned` is JSON `["root hex", ...]`, the registry roots this client trusts; `trusted`
/// is `{"anchor": {"height", "hash", "context_hash"}}` as for `verify_history`.
///
/// The registry must hash to a pinned root. The claim's aggregation key must be allowed
/// in it, the claim must have been made under it or under a prefix of it that no later
/// revocation reaches, and the proof must verify under that key: the key's eight words
/// are the STARK verifier's key, so no separate key file is needed.
#[wasm_bindgen]
pub fn verify_history_v2(proof: &[u8], public_values: &[u8], registry_json: &str, pinned: &str, trusted: &str) -> Result<String, JsError> {
    let registry = registry_of(registry_json)?;
    let root = registry.root();
    let pinned: Vec<String> = serde_json::from_str(pinned).map_err(err)?;
    if !pinned.iter().any(|p| h32(p).ok() == Some(root)) {
        return Err(JsError::new("UnpinnedRegistry: the registry does not hash to a root this client trusts"));
    }
    let c = Claim::decode(public_values).ok_or_else(|| JsError::new("the public values are not a v2 claim"))?;
    if c.kind != Kind::Aggregate {
        return Err(JsError::new("NotAnAggregate: a single leaf is not a history proof"));
    }
    if !c.records.is_canonical(c.first_height, c.last_height) {
        return Err(JsError::new("Malformed: the records commitment does not have the canonical shape"));
    }
    if !registry.allows(Kind::Aggregate, c.net, ANY_ERA, c.first_height, c.last_height, &c.program) {
        return Err(JsError::new("WrongAggregationProgram: the claim's aggregation key is not allowed by the registry"));
    }
    registry.current_for(&c.registry_root, c.last_height).map_err(err)?;
    let vk: Vec<u8> = c.program.iter().flat_map(|w| w.to_le_bytes()).collect();
    sp1_verifier::compressed::SP1CompressedVerifierRaw::verify_with_public_values(proof, public_values, &vk).map_err(err)?;
    let t: serde_json::Value = serde_json::from_str(trusted).map_err(err)?;
    let a = &t["anchor"];
    if c.first_height != a["height"].as_u64().unwrap_or(0) + 1
        || c.anchor_hash != h32(a["hash"].as_str().unwrap_or_default())?
        || c.start_context_hash != h32(a["context_hash"].as_str().unwrap_or_default())?
    {
        return Err(JsError::new("WrongCheckpoint: the proof does not start at the trusted block"));
    }
    if !c.equihash_checked {
        return Err(JsError::new("EquihashNotChecked"));
    }
    Ok(json!({
        "generation": 1,
        "network": format!("{:?}", c.net),
        "registry_root": hex::encode(root),
        "made_under": hex::encode(c.registry_root),
        "aggregation_key": hex::encode(&vk),
        "first_height": c.first_height,
        "last_height": c.last_height,
        "last_hash": hex::encode(c.last_hash),
        "leaves": c.leaves,
        "work": hex::encode(c.work),
        "equihash_checked": c.equihash_checked,
        "commitment_blocks": c.records.0.len(),
    })
    .to_string())
}

/// The client's whole rule for a history proof. `trusted` is JSON:
/// `{"leaf_vk": [8 words], "agg_vk": [8 words], "anchor": {"height", "hash", "context_hash"}}`
/// with hashes in internal byte order, hex. `agg_vk_bincode` is the bincode of the
/// aggregation key's KoalaBear digest, which the STARK verifier takes.
#[wasm_bindgen]
pub fn verify_history(proof: &[u8], public_values: &[u8], agg_vk_bincode: &[u8], trusted: &str) -> Result<String, JsError> {
    sp1_verifier::compressed::SP1CompressedVerifierRaw::verify_with_public_values(proof, public_values, agg_vk_bincode).map_err(err)?;
    let t: serde_json::Value = serde_json::from_str(trusted).map_err(err)?;
    let words = |v: &serde_json::Value| -> Result<[u32; 8], JsError> {
        let w: Vec<u32> = v.as_array().ok_or_else(|| JsError::new("key"))?.iter().map(|x| x.as_u64().unwrap_or(0) as u32).collect();
        u32x8(&w)
    };
    let c = claim_of(public_values)?;
    if !c.records.is_canonical(c.first_height, c.last_height) {
        return Err(JsError::new("Malformed: the records commitment does not have the canonical shape"));
    }
    if c.is_leaf() {
        return Err(JsError::new("NotAnAggregate: a single leaf is not a history proof"));
    }
    if c.agg_vk != words(&t["agg_vk"])? {
        return Err(JsError::new("WrongAggregationProgram"));
    }
    if c.leaf_vk != words(&t["leaf_vk"])? {
        return Err(JsError::new("WrongLeafProgram"));
    }
    let a = &t["anchor"];
    if c.first_height != a["height"].as_u64().unwrap_or(0) + 1
        || c.anchor_hash != h32(a["hash"].as_str().unwrap_or_default())?
        || c.start_context_hash != h32(a["context_hash"].as_str().unwrap_or_default())?
    {
        return Err(JsError::new("WrongCheckpoint: the proof does not start at the trusted block"));
    }
    if !c.equihash_checked {
        return Err(JsError::new("EquihashNotChecked"));
    }
    Ok(json!({
        "first_height": c.first_height,
        "last_height": c.last_height,
        "last_hash": hex::encode(c.last_hash),
        "leaves": c.leaves,
        "work": hex::encode(c.work),
        "equihash_checked": c.equihash_checked,
        "commitment_blocks": c.records.0.len(),
    })
    .to_string())
}

/// Recomputes the records commitment from every record the claim covers and compares it.
#[wasm_bindgen]
pub fn check_all_records(public_values: &[u8], records_bytes: &[u8]) -> Result<String, JsError> {
    let c = covered(public_values)?;
    let r = records(records_bytes)?;
    if r.len() as u64 != c.last_height - c.first_height + 1 {
        return Err(JsError::new("the records file does not cover the claim's range"));
    }
    if Peaks::of_records(c.first_height, &r) != c.records {
        return Err(JsError::new("Mismatch: these records are not the ones the proof commits to"));
    }
    Ok(json!({"records": r.len(), "first_height": c.first_height, "last_height": c.last_height}).to_string())
}

/// Builds the sibling paths for `from..=to` from all the claim's records (what a server
/// sends), then verifies those records against the claim with them (what a client does).
#[wasm_bindgen]
pub fn check_range(public_values: &[u8], records_bytes: &[u8], from: u32, to: u32) -> Result<String, JsError> {
    let (from, to) = (from as u64, to as u64);
    let c = covered(public_values)?;
    let all = records(records_bytes)?;
    if from < c.first_height || to > c.last_height || from > to {
        return Err(JsError::new("OutOfRange"));
    }
    let paths = range_paths(c.first_height, &all, from, to);
    let piece = &all[(from - c.first_height) as usize..=(to - c.first_height) as usize];
    c.records.verify_range(from, piece, &paths).map_err(err)?;
    let r = &piece[0];
    let hex_rev = |b: &[u8]| {
        let mut v = b.to_vec();
        v.reverse();
        hex::encode(v)
    };
    Ok(json!({
        "from": from,
        "to": to,
        "blocks_in_range": piece.len(),
        "sibling_hashes": paths.iter().map(Vec::len).sum::<usize>(),
        "first_record": {
            "hash": hex_rev(&r[..32]),
            "merkle_root": hex_rev(&r[32..64]),
            "block_commitments": hex_rev(&r[64..96]),
            "time": u32::from_le_bytes(r[96..100].try_into().unwrap()),
            "bits": format!("{:08x}", u32::from_le_bytes(r[100..104].try_into().unwrap())),
        },
    })
    .to_string())
}

/// Verifies `records` (for heights `from..`) against the claim with sibling paths given as
/// JSON `[["hex", ...], ...]`, as a client does with a Ring and its published binding.
#[wasm_bindgen]
pub fn verify_binding(public_values: &[u8], from: u32, records_bytes: &[u8], paths_json: &str) -> Result<String, JsError> {
    let from = from as u64;
    let c = covered(public_values)?;
    let r = records(records_bytes)?;
    let paths: Vec<Vec<String>> = serde_json::from_str(paths_json).map_err(err)?;
    let paths: Vec<Vec<[u8; 32]>> = paths.iter().map(|p| p.iter().map(|h| h32(h)).collect::<Result<_, _>>()).collect::<Result<_, _>>()?;
    c.records.verify_range(from, &r, &paths).map_err(err)?;
    Ok(json!({"from": from, "to": from + r.len() as u64 - 1, "sibling_hashes": paths.iter().map(Vec::len).sum::<usize>()}).to_string())
}

#[wasm_bindgen]
pub fn verify_groth16(proof: &[u8], public_values: &[u8], vkey_hash: &str) -> Result<(), JsError> {
    sp1_verifier::Groth16Verifier::verify(proof, public_values, vkey_hash, &sp1_verifier::GROTH16_VK_BYTES).map_err(err)
}

#[wasm_bindgen]
pub fn verify_plonk(proof: &[u8], public_values: &[u8], vkey_hash: &str) -> Result<(), JsError> {
    sp1_verifier::PlonkVerifier::verify(proof, public_values, vkey_hash, &sp1_verifier::PLONK_VK_BYTES).map_err(err)
}

/// `proof` is the bincode of the SDK's `SP1Proof::Compressed`, `vkey` the bincode of the
/// program key's KoalaBear digest.
#[wasm_bindgen]
pub fn verify_compressed(proof: &[u8], public_values: &[u8], vkey: &[u8]) -> Result<(), JsError> {
    sp1_verifier::compressed::SP1CompressedVerifierRaw::verify_with_public_values(proof, public_values, vkey).map_err(err)
}
