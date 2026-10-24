//! Block headers: parsing, Equihash, the header's own target, chain work, and the rules
//! that depend on earlier headers (difficulty adjustment, median time past), which come
//! from `zylem-header` so the native verifier and the zkVM programs share one copy.

use primitive_types::U256;
use zcash_primitives::block::BlockHeader;
use zcash_protocol::consensus::Network;
use zylem_header::{Net, MAX_CONTEXT};

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
        zylem_header::check_encoding(bytes).map_err(|_| Reject::malformed("header", "solution length is not fd 40 05"))?;
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
    /// target it declares. The difficulty adjustment rule is `DifficultyContext::check_and_push`.
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

pub use zylem_header::{expand as expand_bits, work as work_from_target};

/// Work for a compact `nBits`, or zero if the encoding is invalid.
pub fn work_from_bits(bits: u32) -> U256 {
    expand_bits(bits).map(work_from_target).unwrap_or_default()
}

/// How far ahead of a verifier's clock a header may be dated, as consensus allows.
pub const MAX_FUTURE_SECS: u64 = 2 * 60 * 60;

impl Header {
    /// Rejects a header dated more than two hours after `now` (Unix seconds). Nodes refuse
    /// such headers, so only a forger serves them.
    pub fn check_not_future(&self, now: u64) -> Result<(), Reject> {
        if self.time as u64 > now + MAX_FUTURE_SECS {
            return Err(Reject::FutureTime { height: self.height });
        }
        Ok(())
    }
}

/// A run of headers checked as a chain from a verified `prev` with its context: every
/// header parses, passes Equihash and its target, links, and follows the difficulty and
/// time rules. Used for header-only sources that witness the tip.
pub struct HeaderRun {
    pub headers: Vec<Header>,
    pub work: U256,
    pub context: DifficultyContext,
}

pub fn verify_run(network: &Network, prev: &Header, context: &DifficultyContext, raw: &[Vec<u8>]) -> Result<HeaderRun, Reject> {
    let mut context = context.clone();
    let mut prev_hash = prev.hash;
    let mut headers = Vec::with_capacity(raw.len());
    let mut work = U256::zero();
    for (i, bytes) in raw.iter().enumerate() {
        let height = prev.height + 1 + i as u64;
        let h = Header::parse_and_check(height, bytes)?;
        if h.prev_hash != prev_hash {
            return Err(Reject::BrokenChain { height });
        }
        if !context.check_and_push(network, &h)? {
            return Err(Reject::ContextInvalid { height, detail: "not enough predecessors to check".into() });
        }
        prev_hash = h.hash;
        work += h.work;
        headers.push(h);
    }
    Ok(HeaderRun { headers, work, context })
}

fn net(network: &Network) -> Net {
    match network {
        Network::MainNetwork => Net::Main,
        Network::TestNetwork => Net::Test,
    }
}

/// The `(bits, time)` of the latest headers, oldest first, that the difficulty and time
/// rules read. Once it holds enough predecessors for a height, every later header is
/// checked against them.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DifficultyContext(pub Vec<(u32, u32)>);

impl DifficultyContext {
    /// Checks `header` against the context if it is long enough, then appends it.
    /// Returns whether the header was checked.
    pub fn check_and_push(&mut self, network: &Network, header: &Header) -> Result<bool, Reject> {
        let n = net(network);
        let checked = self.0.len() >= zylem_header::context_needed(n, header.height);
        if checked {
            let newest_first: Vec<(u32, u32)> = self.0.iter().rev().copied().collect();
            zylem_header::check_contextual(n, header.height, header.time, header.bits, &newest_first)
                .map_err(|f| Reject::ContextInvalid { height: header.height, detail: format!("{f:?}") })?;
        }
        self.0.push((header.bits, header.time));
        if self.0.len() > MAX_CONTEXT {
            self.0.remove(0);
        }
        Ok(checked)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(height: u64, bits: u32, time: u32) -> Header {
        Header {
            height,
            hash: [0; 32],
            prev_hash: [0; 32],
            merkle_root: [0; 32],
            commitments: [0; 32],
            time,
            bits,
            work: U256::zero(),
        }
    }

    #[test]
    fn headers_more_than_two_hours_ahead_are_rejected() {
        let h = header(10, 0, 1_800_007_200);
        assert_eq!(h.check_not_future(1_800_000_000), Ok(()));
        assert_eq!(h.check_not_future(1_799_999_999), Err(Reject::FutureTime { height: 10 }));
    }

    #[test]
    fn difficulty_context_checks_once_long_enough() {
        let net = Network::TestNetwork;
        // 113 predecessors after NU7, 25 s apart, at one difficulty.
        let h0 = 4_500_000u64;
        let mut ctx = DifficultyContext::default();
        for i in 0..MAX_CONTEXT as u64 {
            let checked = ctx.check_and_push(&net, &header(h0 + i, 0x1d01_0000, 1_700_000_000 + 25 * i as u32)).unwrap();
            assert!(!checked, "checked before the context was long enough");
        }
        let h = h0 + MAX_CONTEXT as u64;
        let time = 1_700_000_000 + 25 * MAX_CONTEXT as u32;
        let newest_first: Vec<(u32, u32)> = ctx.0.iter().rev().copied().collect();
        let expected = zylem_header::expected_bits(Net::Test, h, time, &newest_first).unwrap();

        assert!(matches!(
            ctx.clone().check_and_push(&net, &header(h, expected ^ 1, time)),
            Err(Reject::ContextInvalid { .. })
        ));
        let mtp = newest_first[5].1; // the median of the last 11 evenly spaced times
        assert!(matches!(
            ctx.clone().check_and_push(&net, &header(h, expected, mtp)),
            Err(Reject::ContextInvalid { .. })
        ));
        assert!(matches!(
            ctx.clone().check_and_push(&net, &header(h, expected, mtp + 5_401)),
            Err(Reject::ContextInvalid { .. })
        ));
        assert_eq!(ctx.check_and_push(&net, &header(h, expected, time)), Ok(true));
    }
}
