//! Generation 1 aggregation: verifies two child proofs, each under the key the host names
//! for it, checks both keys against the registry it is given, joins the two ranges and
//! publishes a v2 claim stating the registry root and its own key. It holds no Zcash
//! rules, so new eras and new leaf programs need no new aggregation.
#![no_main]
sp1_zkvm::entrypoint!(main);

use sha2::{Digest, Sha256};
use zylem_hdr::{Claim, Registry};

/// Verifies a child's proof under `key`. Whether that key may make this child is checked
/// by `Claim::join` against the registry.
fn child(bytes: &[u8], key: &[u32; 8]) -> Claim {
    let claim = Claim::decode(bytes).expect("child claim is malformed");
    let digest: [u8; 32] = Sha256::digest(bytes).into();
    sp1_zkvm::lib::verify::verify_sp1_proof(key, &digest);
    claim
}

pub fn main() {
    let own: [u32; 8] = sp1_zkvm::io::read();
    let registry = Registry::decode(&sp1_zkvm::io::read_vec()).expect("registry is malformed");
    let left_key: [u32; 8] = sp1_zkvm::io::read();
    let left_bytes = sp1_zkvm::io::read_vec();
    let right_key: [u32; 8] = sp1_zkvm::io::read();
    let right_bytes = sp1_zkvm::io::read_vec();
    let left = child(&left_bytes, &left_key);
    let right = child(&right_bytes, &right_key);
    match Claim::join((&left, &left_key), (&right, &right_key), &registry, &own) {
        Ok(claim) => sp1_zkvm::io::commit_slice(&claim.encode()),
        Err(why) => panic!("cannot join the two ranges: {why:?}"),
    }
}
