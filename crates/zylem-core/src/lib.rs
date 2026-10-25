//! zylem-core takes chain data a light wallet received from an untrusted source and
//! checks it against what consensus committed to in block headers.

mod error;
pub mod block;
pub mod header;
pub mod history;
pub mod manifest;
pub mod merkle;
pub mod ring;
pub mod tamper;
pub mod tree;
pub mod txid;

pub use error::Reject;
