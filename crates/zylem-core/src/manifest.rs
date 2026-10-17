//! The manifest lists a builder's Rings. It is never trusted: every Ring it points to is
//! verified against headers, and its file hash only lets a client pick the right bytes
//! from any mirror.

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RingEntry {
    pub start_height: u64,
    pub end_height: u64,
    /// Hash of the last block, in display (big-endian hex) order.
    pub last_block_hash: String,
    /// Path relative to the manifest.
    pub file: String,
    /// `ring::file_hash` of the file, hex.
    pub hash: String,
    pub size: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Manifest {
    pub network: String,
    pub format: u32,
    pub epoch_length: u64,
    /// Activation height of the network upgrade whose history tree the Rings extend.
    pub epoch_start: u64,
    pub finality_depth: u64,
    pub rings: Vec<RingEntry>,
    /// The still-open epoch, rewritten as blocks arrive.
    pub tail: Option<RingEntry>,
}

/// Block hashes travel in internal byte order and display reversed.
pub fn display_hash(internal: &[u8; 32]) -> String {
    let mut h = *internal;
    h.reverse();
    hex::encode(h)
}
