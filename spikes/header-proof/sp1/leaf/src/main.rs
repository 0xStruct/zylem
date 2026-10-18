//! A leaf: proves one segment of headers on its own and publishes a range claim. Leaves
//! do not depend on each other, so they can all be proved at the same time.
#![no_main]
sp1_zkvm::entrypoint!(main);

use zylem_hdr::{Input, RangeClaim};

pub fn main() {
    let input: Input = sp1_zkvm::io::read();
    let headers = sp1_zkvm::io::read_vec();
    let out = match zylem_hdr::run(&input, &headers) {
        Ok(out) => out,
        Err((height, fail)) => panic!("header {height} rejected: {fail:?}"),
    };
    sp1_zkvm::io::commit_slice(&RangeClaim::leaf(&input, &out).encode());
}
