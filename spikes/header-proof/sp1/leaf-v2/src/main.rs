//! Generation 1 header leaf: proves up to `LEAF_SIZE` headers of one era and publishes a
//! v2 claim stating its network and era. One source serves every era; which compiled
//! file may prove which era is the registry's call, not this program's.
#![no_main]
sp1_zkvm::entrypoint!(main);

use zylem_hdr::{Claim, Input};

pub fn main() {
    let input: Input = sp1_zkvm::io::read();
    let headers = sp1_zkvm::io::read_vec();
    let out = match zylem_hdr::run(&input, &headers) {
        Ok(out) => out,
        Err((height, fail)) => panic!("header {height} rejected: {fail:?}"),
    };
    sp1_zkvm::io::commit_slice(&Claim::leaf(&input, &out).encode());
}
