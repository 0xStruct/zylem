//! Block headers: parsing, Equihash, the header's own target, and chain work.

use primitive_types::U256;
use zcash_primitives::block::BlockHeader;

use crate::Reject;

/// Size of a Zcash block header with its Equihash (200, 9) solution.
pub const HEADER_SIZE: usize = 1_487;
/// The part of the header that Equihash commits to (everything before the nonce).
const EQUIHASH_INPUT: usize = 108;

/// A parsed header that has passed its own checks: proof of work and target.
#[derive(Clone, Debug)]
pub struct Header {
    pub height: u64,
    pub hash: [u8; 32],
    pub prev_hash: [u8; 32],
    pub merkle_root: [u8; 32],
    /// `hashBlockCommitments` from NU5 on.
    pub commitments: [u8; 32],
    pub time: u32,
    pub bits: u32,
    pub work: U256,
}

impl Header {
    /// Parses a header without checking proof of work.
    pub fn parse_unchecked(height: u64, bytes: &[u8]) -> Result<Self, Reject> {
        if bytes.len() != HEADER_SIZE {
            return Err(Reject::malformed("header", format!("{} bytes", bytes.len())));
        }
        let h = BlockHeader::read(bytes).map_err(|e| Reject::malformed("header", e))?;
        let target = expand_bits(h.bits).ok_or(Reject::TargetNotMet { height })?;
        Ok(Header {
            height,
            hash: h.hash().0,
            prev_hash: h.prev_block.0,
            merkle_root: h.merkle_root,
            commitments: h.final_sapling_root,
            time: h.time,
            bits: h.bits,
            work: work_from_target(target),
        })
    }

    /// Parses a header and checks its Equihash solution and that its hash meets the
    /// target it declares. It does not check the difficulty adjustment rule.
    pub fn parse_and_check(height: u64, bytes: &[u8]) -> Result<Self, Reject> {
        let header = Self::parse_unchecked(height, bytes)?;
        let nonce = &bytes[EQUIHASH_INPUT..EQUIHASH_INPUT + 32];
        // Solution: 3-byte compact size (1,344) then the solution bytes.
        let solution = &bytes[EQUIHASH_INPUT + 32 + 3..];
        equihash::is_valid_solution(200, 9, &bytes[..EQUIHASH_INPUT], nonce, solution)
            .map_err(|_| Reject::PowInvalid { height })?;
        let target = expand_bits(header.bits).ok_or(Reject::TargetNotMet { height })?;
        // The hash is compared as a little-endian 256-bit number.
        if U256::from_little_endian(&header.hash) > target {
            return Err(Reject::TargetNotMet { height });
        }
        Ok(header)
    }
}

/// Expands compact `nBits` into a 256-bit target, rejecting negative, zero and
/// overflowing encodings the way zcashd does.
pub fn expand_bits(bits: u32) -> Option<U256> {
    if bits & 0x0080_0000 != 0 {
        return None;
    }
    let mantissa = bits & 0x007f_ffff;
    let exponent = (bits >> 24) as i32 - 3;
    let (mantissa, exponent) = match (mantissa, exponent) {
        (_, e) if e >= 32 => return None,
        (m, 31) if m > 0xff => return None,
        (m, 31) => (m << 16, 29),
        (m, 30) if m > 0xffff => return None,
        (m, 30) => (m << 8, 29),
        (m, e) if e < 0 => (m >> ((-e) * 8) as u32, 0),
        (m, e) => (m, e),
    };
    let target = U256::from(mantissa) * U256::from(256).pow(U256::from(exponent));
    (!target.is_zero()).then_some(target)
}

/// Work represented by a target: 2^256 / (target + 1).
pub fn work_from_target(target: U256) -> U256 {
    if target == U256::MAX {
        return U256::one();
    }
    (!target / (target + 1)) + 1
}

/// Work for a compact `nBits`, or zero if the encoding is invalid.
pub fn work_from_bits(bits: u32) -> U256 {
    expand_bits(bits).map(work_from_target).unwrap_or_default()
}
