//! Aggregation: verifies two child proofs (leaves or earlier aggregations), checks the
//! left range ends exactly where the right one starts, and publishes one claim covering
//! both. No headers or Equihash are re-checked here.
#![no_main]
sp1_zkvm::entrypoint!(main);

use sha2::{Digest, Sha256};
use zylem_hdr::RangeClaim;

/// Verifies a child's proof. Which program must have made it follows from the claim
/// itself, not from the host: leaf claims come from the leaf program, anything else
/// from this aggregation program.
fn child(bytes: &[u8], leaf_vk: &[u32; 8], own_vk: &[u32; 8]) -> RangeClaim {
    let claim = RangeClaim::decode(bytes).expect("child claim is malformed");
    let vk = if claim.is_leaf() { leaf_vk } else { own_vk };
    let digest: [u8; 32] = Sha256::digest(bytes).into();
    sp1_zkvm::lib::verify::verify_sp1_proof(vk, &digest);
    claim
}

pub fn main() {
    let own_vk: [u32; 8] = sp1_zkvm::io::read();
    let leaf_vk: [u32; 8] = sp1_zkvm::io::read();
    let left_bytes = sp1_zkvm::io::read_vec();
    let right_bytes = sp1_zkvm::io::read_vec();
    let left = child(&left_bytes, &leaf_vk, &own_vk);
    let right = child(&right_bytes, &leaf_vk, &own_vk);
    match RangeClaim::join(&left, &right, leaf_vk, own_vk) {
        Ok(claim) => sp1_zkvm::io::commit_slice(&claim.encode()),
        Err(why) => panic!("cannot join the two ranges: {why:?}"),
    }
}
