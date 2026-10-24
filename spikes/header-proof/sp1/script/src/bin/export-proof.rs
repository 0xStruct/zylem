//! Writes an SDK proof file in the form clients read: the compressed proof as bincode of
//! `SP1Proof`, its public values, and the claim it publishes, as JSON.
//!
//! Usage: export-proof PROOF_FILE OUT_PREFIX

use anyhow::{Context, Result};
use sp1_sdk::SP1ProofWithPublicValues;
use zylem_hdr::{Claim, RangeClaim};

fn main() -> Result<()> {
    let input = std::env::args().nth(1).context("PROOF_FILE")?;
    let prefix = std::env::args().nth(2).context("OUT_PREFIX")?;
    let p = SP1ProofWithPublicValues::load(&input)?;
    let proof = bincode::serialize(&p.proof)?;
    std::fs::write(format!("{prefix}.proof"), &proof)?;
    std::fs::write(format!("{prefix}.pv"), p.public_values.as_slice())?;
    let pv = p.public_values.as_slice();
    // Generation 1 claims are v2; generation 0 claims (no magic) are v1.
    let claim = if let Some(c) = Claim::decode(pv) {
        serde_json::json!({
            "claim_version": 2,
            "kind": format!("{:?}", c.kind),
            "network": format!("{:?}", c.net),
            "first_height": c.first_height,
            "last_height": c.last_height,
            "anchor_hash": hex::encode(c.anchor_hash),
            "last_hash": hex::encode(c.last_hash),
            "leaves": c.leaves,
            "work": hex::encode(c.work),
            "equihash_checked": c.equihash_checked,
            "registry_root": hex::encode(c.registry_root),
            "program": c.program,
            "proof_bytes": proof.len(),
            "sp1_version": p.sp1_version,
        })
    } else {
        let c = RangeClaim::decode(pv).context("claim")?;
        serde_json::json!({
            "claim_version": 1,
            "first_height": c.first_height,
            "last_height": c.last_height,
            "anchor_hash": hex::encode(c.anchor_hash),
            "last_hash": hex::encode(c.last_hash),
            "leaves": c.leaves,
            "work": hex::encode(c.work),
            "equihash_checked": c.equihash_checked,
            "leaf_vk": c.leaf_vk,
            "agg_vk": c.agg_vk,
            "proof_bytes": proof.len(),
            "sp1_version": p.sp1_version,
        })
    };
    std::fs::write(format!("{prefix}.json"), serde_json::to_string_pretty(&claim)? + "\n")?;
    println!("{}", claim);
    Ok(())
}
