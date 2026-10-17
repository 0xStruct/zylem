//! One link in a chain of header-chain proofs.
//!
//! Inputs: this program's own verification-key digest, the previous link's public values
//! (empty for the first link), the segment's input and its headers. The previous link's
//! proof itself is supplied to the prover and checked through `verify_sp1_proof`, which
//! binds it to exactly those public values and to this program's key. The link then
//! checks that its headers continue from the previous state, proves them, and publishes
//! the extended state.
#![no_main]
sp1_zkvm::entrypoint!(main);

use sha2::{Digest, Sha256};
use zylem_hdr::{ChainState, Input};

pub fn main() {
    let own_vk: [u32; 8] = sp1_zkvm::io::read();
    let prev_public_values = sp1_zkvm::io::read_vec();
    let input: Input = sp1_zkvm::io::read();
    let headers = sp1_zkvm::io::read_vec();

    let prev = if prev_public_values.is_empty() {
        None
    } else {
        let digest: [u8; 32] = Sha256::digest(&prev_public_values).into();
        // The previous proof must be valid, made by this same program, and publish
        // exactly these bytes.
        sp1_zkvm::lib::verify::verify_sp1_proof(&own_vk, &digest);
        let p = ChainState::decode(&prev_public_values).expect("previous state is malformed");
        assert_eq!(p.vk, own_vk, "previous link was made by a different program");
        if let Err(why) = p.continues(&input) {
            panic!("{why}");
        }
        Some(p)
    };

    let out = match zylem_hdr::run(&input, &headers) {
        Ok(out) => out,
        Err((height, fail)) => panic!("header {height} rejected: {fail:?}"),
    };
    let state = ChainState::extend(prev.as_ref(), own_vk, &input, &out);
    sp1_zkvm::io::commit_slice(&state.encode());
}
