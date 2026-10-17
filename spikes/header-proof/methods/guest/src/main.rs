//! Proves a run of Zcash headers: linkage, target, difficulty rule, median time, work,
//! and optionally Equihash. Publishes the end state and a hash of per-block records.

use risc0_zkvm::guest::env;
use zylem_hdr::{Input, HEADER_SIZE};

fn main() {
    let input: Input = env::read();
    let mut headers = vec![0u8; input.count as usize * HEADER_SIZE];
    env::read_slice(&mut headers);
    match zylem_hdr::run(&input, &headers) {
        Ok(out) => env::commit(&out),
        Err((height, fail)) => panic!("header {height} rejected: {fail:?}"),
    }
}
