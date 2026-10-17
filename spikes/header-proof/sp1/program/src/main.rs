//! The same header-chain checks as the RISC Zero guest, compiled for SP1.
#![no_main]
sp1_zkvm::entrypoint!(main);

use zylem_hdr::Input;

pub fn main() {
    let input: Input = sp1_zkvm::io::read();
    let headers = sp1_zkvm::io::read_vec();
    match zylem_hdr::run(&input, &headers) {
        Ok(out) => sp1_zkvm::io::commit(&out),
        Err((height, fail)) => panic!("header {height} rejected: {fail:?}"),
    }
}
