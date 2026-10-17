//! Block Merkle roots (double SHA-256 over transaction IDs) and the ZIP 244 auth data
//! root.

use std::collections::HashSet;

use sha2::{Digest, Sha256};

/// Auth digest that ZIP 244 assigns to transactions before v5.
pub const AUTH_DIGEST_PLACEHOLDER: [u8; 32] = [0xFF; 32];

fn sha256d(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let first = Sha256::new().chain_update(left).chain_update(right).finalize();
    Sha256::digest(first).into()
}

/// Returns true if the list repeats a transaction ID. A repeated ID is how the classic
/// Bitcoin Merkle malleability (CVE-2012-2459) disguises a block with a duplicated last
/// transaction, so such lists are rejected before the root is compared.
pub fn has_duplicates(txids: &[[u8; 32]]) -> bool {
    let mut seen = HashSet::with_capacity(txids.len());
    txids.iter().any(|id| !seen.insert(*id))
}

/// The header's `hashMerkleRoot` for transaction IDs in internal byte order.
pub fn merkle_root(txids: &[[u8; 32]]) -> [u8; 32] {
    assert!(!txids.is_empty(), "a block always has a coinbase");
    let mut level = txids.to_vec();
    while level.len() > 1 {
        level = level
            .chunks(2)
            .map(|pair| match pair {
                [a, b] => sha256d(a, b),
                [a] => sha256d(a, a),
                _ => unreachable!(),
            })
            .collect();
    }
    level[0]
}

/// `hashAuthDataRoot`: a full binary tree of auth digests padded with zero leaves, nodes
/// hashed with BLAKE2b-256 personalized by "ZcashAuthDatHash".
pub fn auth_data_root(auth_digests: &[[u8; 32]]) -> [u8; 32] {
    let mut level = auth_digests.to_vec();
    level.resize(level.len().next_power_of_two(), [0; 32]);
    while level.len() > 1 {
        level = level
            .chunks(2)
            .map(|pair| {
                let h = blake2b_simd::Params::new()
                    .hash_length(32)
                    .personal(b"ZcashAuthDatHash")
                    .to_state()
                    .update(&pair[0])
                    .update(&pair[1])
                    .finalize();
                h.as_bytes().try_into().unwrap()
            })
            .collect();
    }
    level[0]
}

/// `hashBlockCommitments` from NU5 on: BLAKE2b-256("ZcashBlockCommit", history root ||
/// auth data root || 32 zero bytes).
pub fn block_commitments(history_root: &[u8; 32], auth_data_root: &[u8; 32]) -> [u8; 32] {
    let h = blake2b_simd::Params::new()
        .hash_length(32)
        .personal(b"ZcashBlockCommit")
        .to_state()
        .update(history_root)
        .update(auth_data_root)
        .update(&[0; 32])
        .finalize();
    h.as_bytes().try_into().unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicate_last_tx_has_same_root_but_is_caught() {
        let a = [1; 32];
        let b = [2; 32];
        let c = [3; 32];
        assert_eq!(merkle_root(&[a, b, c]), merkle_root(&[a, b, c, c]));
        assert!(!has_duplicates(&[a, b, c]));
        assert!(has_duplicates(&[a, b, c, c]));
    }

    #[test]
    fn single_tx_root_is_its_id() {
        assert_eq!(merkle_root(&[[7; 32]]), [7; 32]);
    }
}
