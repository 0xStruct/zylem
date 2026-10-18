//! Zcash header-chain rules, shared by the RISC Zero guest and the native host.
//!
//! For each header: Equihash (optional, it dominates the cost), the link to the previous
//! header, the hash meeting the header's own target, the difficulty adjustment rule
//! (copied from Zakura's `adjusted_difficulty.rs`, including NU7's 102-block window and
//! the testnet minimum-difficulty rule), the median-time-past rules, and accumulated
//! work. Each checked header yields a 104-byte record that Zylem's content checks use in
//! place of the full 1,487-byte header.
#![no_std]
extern crate alloc;

use alloc::vec::Vec;
use primitive_types::{U256, U512};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const HEADER_SIZE: usize = 1_487;
const EQUIHASH_INPUT: usize = 108;
/// hash, Merkle root, block commitments (32 B each), time, bits (4 B each).
pub const RECORD_SIZE: usize = 104;
pub const MEDIAN_SPAN: usize = 11;
const PRE_NU7_WINDOW: usize = 17;
const POST_NU7_WINDOW: usize = 102;
/// The most predecessors any rule reads: the post-NU7 window plus the median span.
pub const MAX_CONTEXT: usize = POST_NU7_WINDOW + MEDIAN_SPAN;
const DAMPING: i64 = 4;
const MAX_ADJUST_UP_PERCENT: i64 = 16;
const MAX_ADJUST_DOWN_PERCENT: i64 = 32;
const MAX_TIME_SINCE_MEDIAN: i64 = 90 * 60;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Net {
    Main,
    Test,
}

impl Net {
    fn blossom(self) -> u64 {
        match self {
            Net::Main => 653_600,
            Net::Test => 584_000,
        }
    }
    fn nu7(self) -> Option<u64> {
        match self {
            Net::Main => None,
            Net::Test => Some(4_465_026),
        }
    }
    fn nu7_active(self, h: u64) -> bool {
        self.nu7().is_some_and(|a| h >= a)
    }
    fn spacing(self, h: u64) -> i64 {
        if self.nu7_active(h) {
            25
        } else if h >= self.blossom() {
            75
        } else {
            150
        }
    }
    fn window(self, h: u64) -> usize {
        if self.nu7_active(h) {
            POST_NU7_WINDOW
        } else {
            PRE_NU7_WINDOW
        }
    }
    /// ZIPs 205 and 208: on testnet a block arriving after this gap may use the minimum
    /// difficulty (six spacings before NU7, 18 from NU7 on).
    fn min_difficulty_gap(self, h: u64) -> Option<i64> {
        match self {
            Net::Main => None,
            Net::Test if h < 299_188 => None,
            Net::Test => Some(self.spacing(h) * if self.nu7_active(h) { 18 } else { 6 }),
        }
    }
    fn max_time_enforced(self, h: u64) -> bool {
        match self {
            Net::Main => true,
            Net::Test => h >= 653_606,
        }
    }
    /// PoWLimit, round-tripped through the compact encoding as zcashd does:
    /// compact(2^243 - 1) on mainnet and compact(2^251 - 1) on testnet.
    pub fn limit(self) -> U256 {
        let bits = match self {
            Net::Main => 0x1f07_ffff,
            Net::Test => 0x2007_ffff,
        };
        expand(bits).expect("limits are valid")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Fail {
    Size,
    BrokenLink,
    Equihash,
    BadBits,
    AboveTarget,
    WrongDifficulty { expected: u32, actual: u32 },
    TimeTooEarly,
    TimeTooLate,
    ShortContext,
}

pub fn sha256d(data: &[u8]) -> [u8; 32] {
    Sha256::digest(Sha256::digest(data)).into()
}

/// Compact `nBits` to a target; rejects negative, zero and overflowing encodings.
pub fn expand(bits: u32) -> Option<U256> {
    if bits & 0x0080_0000 != 0 {
        return None;
    }
    let mantissa = bits & 0x007f_ffff;
    let exponent = (bits >> 24) as i32 - 3;
    let (m, e) = match (mantissa, exponent) {
        (_, e) if e >= 32 => return None,
        (m, 31) if m > 0xff => return None,
        (m, 31) => (m << 16, 29),
        (m, 30) if m > 0xffff => return None,
        (m, 30) => (m << 8, 29),
        (m, e) if e < 0 => (m >> ((-e) * 8) as u32, 0),
        (m, e) => (m, e),
    };
    let t = U256::from(m) << (8 * e as usize);
    (!t.is_zero()).then_some(t)
}

/// A target to compact `nBits`, as zcashd's `GetCompact`.
pub fn to_compact(t: U256) -> u32 {
    let size = t.bits() / 8 + 1;
    let mantissa = if t <= U256::from(0x007f_ffffu32) {
        t << (8 * (3 - size))
    } else {
        t >> (8 * (size - 3))
    };
    mantissa.low_u32() + ((size as u32) << 24)
}

/// 2^256 / (target + 1).
pub fn work(target: U256) -> U256 {
    if target == U256::MAX {
        return U256::one();
    }
    (!target / (target + 1)) + 1
}

fn median(times: &mut [u32]) -> i64 {
    times.sort_unstable();
    times[times.len() / 2] as i64
}

/// The `nBits` a header at `height` with time `time` must carry, given its predecessors'
/// `(bits, time)` newest first.
pub fn expected_bits(net: Net, height: u64, time: u32, prev: &[(u32, u32)]) -> Result<u32, Fail> {
    let window = net.window(height);
    let needed = (window + MEDIAN_SPAN).min(height as usize);
    if prev.len() < needed {
        return Err(Fail::ShortContext);
    }
    let prev = &prev[..needed];
    if let Some(gap) = net.min_difficulty_gap(height) {
        if time as i64 - prev[0].1 as i64 > gap {
            return Ok(to_compact(net.limit()));
        }
    }
    if height as usize <= window {
        return Ok(to_compact(net.limit()));
    }
    let timespan = window as i64 * net.spacing(height);

    // MeanTarget. Zakura sums t / w and t % w separately to stay within 256 bits; the
    // floor of the 512-bit sum divided by w is the same number, with one small division
    // instead of 2w big ones.
    let mut sum = U512::zero();
    for (bits, _) in &prev[..window] {
        sum += U512::from(expand(*bits).ok_or(Fail::BadBits)?);
    }
    let mean = div_small_512(sum, window as u64);

    // ActualTimespanBounded from the medians at both ends of the window.
    let mut newer: Vec<u32> = prev[..MEDIAN_SPAN].iter().map(|p| p.1).collect();
    let newer = median(&mut newer);
    let older = if prev.len() > window {
        let mut o: Vec<u32> = prev[window..].iter().take(MEDIAN_SPAN).map(|p| p.1).collect();
        median(&mut o)
    } else {
        prev[prev.len() - 1].1 as i64
    };
    // Rust's `/` truncates toward zero, as the specification requires.
    let damped = timespan + (newer - older - timespan) / DAMPING;
    let min_span = timespan * (100 - MAX_ADJUST_UP_PERCENT) / 100;
    let max_span = timespan * (100 + MAX_ADJUST_DOWN_PERCENT) / 100;
    let bounded = damped.clamp(min_span, max_span) as u64;

    let limit = net.limit();
    let scaled = div_small(mean, timespan as u64);
    let threshold = if scaled > div_small(limit, bounded) {
        limit
    } else {
        core::cmp::min(limit, scaled * U256::from(bounded))
    };
    Ok(to_compact(threshold))
}

/// `x / d` for a 64-bit divisor, by long division on 64-bit limbs.
fn div_small(x: U256, d: u64) -> U256 {
    let mut out = [0u64; 4];
    let mut rem: u128 = 0;
    for i in (0..4).rev() {
        let cur = (rem << 64) | x.0[i] as u128;
        out[i] = (cur / d as u128) as u64;
        rem = cur % d as u128;
    }
    U256(out)
}

/// `x / d` for a 512-bit dividend whose quotient fits in 256 bits.
fn div_small_512(x: U512, d: u64) -> U256 {
    let mut out = [0u64; 8];
    let mut rem: u128 = 0;
    for i in (0..8).rev() {
        let cur = (rem << 64) | x.0[i] as u128;
        out[i] = (cur / d as u128) as u64;
        rem = cur % d as u128;
    }
    debug_assert!(out[4..].iter().all(|l| *l == 0));
    U256([out[0], out[1], out[2], out[3]])
}

/// What one checked header contributes.
pub struct Checked {
    pub hash: [u8; 32],
    pub bits: u32,
    pub time: u32,
    pub work: U256,
    pub record: [u8; RECORD_SIZE],
}

/// Checks one header against its predecessors (`prev`, newest first) and the previous
/// header's hash.
pub fn check(
    net: Net,
    height: u64,
    header: &[u8],
    prev_hash: &[u8; 32],
    prev: &[(u32, u32)],
    check_equihash: bool,
) -> Result<Checked, Fail> {
    if header.len() != HEADER_SIZE {
        return Err(Fail::Size);
    }
    if &header[4..36] != prev_hash {
        return Err(Fail::BrokenLink);
    }
    let time = u32::from_le_bytes(header[100..104].try_into().unwrap());
    let bits = u32::from_le_bytes(header[104..108].try_into().unwrap());

    if check_equihash {
        let nonce = &header[EQUIHASH_INPUT..EQUIHASH_INPUT + 32];
        let solution = &header[EQUIHASH_INPUT + 35..];
        equihash::is_valid_solution(200, 9, &header[..EQUIHASH_INPUT], nonce, solution)
            .map_err(|_| Fail::Equihash)?;
    }

    let hash = sha256d(header);
    let target = expand(bits).ok_or(Fail::BadBits)?;
    if target > net.limit() || U256::from_little_endian(&hash) > target {
        return Err(Fail::AboveTarget);
    }

    let expected = expected_bits(net, height, time, prev)?;
    if expected != bits {
        return Err(Fail::WrongDifficulty { expected, actual: bits });
    }

    let mut mtp: Vec<u32> = prev.iter().take(MEDIAN_SPAN).map(|p| p.1).collect();
    let mtp = median(&mut mtp);
    if (time as i64) <= mtp {
        return Err(Fail::TimeTooEarly);
    }
    if net.max_time_enforced(height) && time as i64 > mtp + MAX_TIME_SINCE_MEDIAN {
        return Err(Fail::TimeTooLate);
    }

    let mut record = [0u8; RECORD_SIZE];
    record[..32].copy_from_slice(&hash);
    record[32..64].copy_from_slice(&header[36..68]); // hashMerkleRoot
    record[64..96].copy_from_slice(&header[68..100]); // hashBlockCommitments
    record[96..100].copy_from_slice(&header[100..104]);
    record[100..104].copy_from_slice(&header[104..108]);
    Ok(Checked { hash, bits, time, work: work(target), record })
}

/// The guest's input: predecessors for context, then the headers to prove.
#[derive(Serialize, Deserialize)]
pub struct Input {
    pub net: Net,
    /// Height of the first header to prove.
    pub first_height: u64,
    /// Hash of the header just before it.
    pub anchor_hash: [u8; 32],
    /// `(bits, time)` of up to `MAX_CONTEXT` predecessors, oldest first.
    pub context: Vec<(u32, u32)>,
    pub count: u32,
    pub check_equihash: bool,
}

/// What a proof publishes.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct Output {
    pub net: Net,
    pub first_height: u64,
    pub anchor_hash: [u8; 32],
    /// SHA-256 of the context it started from, so proofs chain.
    pub context_hash: [u8; 32],
    pub last_height: u64,
    pub last_hash: [u8; 32],
    /// Work of the proven headers, big-endian.
    pub work: [u8; 32],
    /// SHA-256 over every proven header's record, in order.
    pub records_hash: [u8; 32],
    /// SHA-256 of the context the next proof must start from.
    pub end_context_hash: [u8; 32],
    pub equihash_checked: bool,
}

pub fn context_hash(context: &[(u32, u32)]) -> [u8; 32] {
    let mut h = Sha256::new();
    for (b, t) in context {
        h.update(b.to_le_bytes());
        h.update(t.to_le_bytes());
    }
    h.finalize().into()
}

/// Proves a run of headers: the whole guest, also runnable natively.
pub fn run(input: &Input, headers: &[u8]) -> Result<Output, (u64, Fail)> {
    let mut ctx: Vec<(u32, u32)> = input.context.clone();
    let mut prev_hash = input.anchor_hash;
    let mut total = U256::zero();
    let mut records = Sha256::new();
    let mut height = input.first_height;
    let mut newest_first: Vec<(u32, u32)> = Vec::with_capacity(MAX_CONTEXT);
    for header in headers.chunks(HEADER_SIZE).take(input.count as usize) {
        newest_first.clear();
        newest_first.extend(ctx.iter().rev().take(MAX_CONTEXT).copied());
        let c = check(input.net, height, header, &prev_hash, &newest_first, input.check_equihash)
            .map_err(|f| (height, f))?;
        records.update(c.record);
        total += c.work;
        prev_hash = c.hash;
        ctx.push((c.bits, c.time));
        if ctx.len() > MAX_CONTEXT {
            ctx.remove(0);
        }
        height += 1;
    }
    let mut work = [0u8; 32];
    total.to_big_endian(&mut work);
    Ok(Output {
        net: input.net,
        first_height: input.first_height,
        anchor_hash: input.anchor_hash,
        context_hash: context_hash(&input.context),
        last_height: height - 1,
        last_hash: prev_hash,
        work,
        records_hash: records.finalize().into(),
        end_context_hash: context_hash(&ctx),
        equihash_checked: input.check_equihash,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_match_their_compact_round_trip() {
        assert_eq!(Net::Main.limit(), expand(to_compact((U256::one() << 243) - 1)).unwrap());
        assert_eq!(Net::Test.limit(), expand(to_compact((U256::one() << 251) - 1)).unwrap());
    }

    #[test]
    fn small_division_matches_big_division() {
        let x = U256::from_dec_str("123456789012345678901234567890123456789012345678901234567").unwrap();
        for d in [1u64, 7, 102, 2550, u64::MAX] {
            assert_eq!(div_small(x, d), x / U256::from(d));
        }
        let wide = U512::from(x) * U512::from(97u64);
        assert_eq!(div_small_512(wide, 97), x);
    }
}

/// The running state a chain of segment proofs publishes. Each link verifies the previous
/// link's proof, checks that its own headers continue from this state, and publishes the
/// extended state. A client accepts the chain when `vk` is the program it trusts and the
/// checkpoint fields are a block it trusts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainState {
    /// Digest of the verification key of the program that made every link.
    pub vk: [u32; 8],
    /// The block the chain starts after.
    pub checkpoint_height: u64,
    pub checkpoint_hash: [u8; 32],
    pub checkpoint_context_hash: [u8; 32],
    pub last_height: u64,
    pub last_hash: [u8; 32],
    /// Total work of every proven header, big-endian.
    pub work: [u8; 32],
    pub end_context_hash: [u8; 32],
    /// SHA-256 chain over each segment's records hash.
    pub records_acc: [u8; 32],
    pub segments: u32,
    /// True only if every segment checked Equihash.
    pub equihash_checked: bool,
}

pub const CHAIN_STATE_SIZE: usize = 32 + 8 + 32 + 32 + 8 + 32 + 32 + 32 + 32 + 4 + 1;

impl ChainState {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(CHAIN_STATE_SIZE);
        for w in self.vk {
            out.extend_from_slice(&w.to_le_bytes());
        }
        out.extend_from_slice(&self.checkpoint_height.to_le_bytes());
        out.extend_from_slice(&self.checkpoint_hash);
        out.extend_from_slice(&self.checkpoint_context_hash);
        out.extend_from_slice(&self.last_height.to_le_bytes());
        out.extend_from_slice(&self.last_hash);
        out.extend_from_slice(&self.work);
        out.extend_from_slice(&self.end_context_hash);
        out.extend_from_slice(&self.records_acc);
        out.extend_from_slice(&self.segments.to_le_bytes());
        out.push(self.equihash_checked as u8);
        out
    }

    pub fn decode(b: &[u8]) -> Option<Self> {
        if b.len() != CHAIN_STATE_SIZE {
            return None;
        }
        let a32 = |at: usize| -> [u8; 32] { b[at..at + 32].try_into().unwrap() };
        let u64_at = |at: usize| u64::from_le_bytes(b[at..at + 8].try_into().unwrap());
        let mut vk = [0u32; 8];
        for (i, w) in vk.iter_mut().enumerate() {
            *w = u32::from_le_bytes(b[i * 4..i * 4 + 4].try_into().unwrap());
        }
        Some(ChainState {
            vk,
            checkpoint_height: u64_at(32),
            checkpoint_hash: a32(40),
            checkpoint_context_hash: a32(72),
            last_height: u64_at(104),
            last_hash: a32(112),
            work: a32(144),
            end_context_hash: a32(176),
            records_acc: a32(208),
            segments: u32::from_le_bytes(b[240..244].try_into().unwrap()),
            equihash_checked: b[244] == 1,
        })
    }

    /// The state after one more proven segment. `prev` is `None` for the first segment,
    /// whose anchor becomes the chain's checkpoint.
    pub fn extend(prev: Option<&ChainState>, vk: [u32; 8], input: &Input, out: &Output) -> ChainState {
        let (checkpoint_height, checkpoint_hash, checkpoint_context_hash, work, acc, segments, eq) = match prev {
            Some(p) => (
                p.checkpoint_height,
                p.checkpoint_hash,
                p.checkpoint_context_hash,
                U256::from_big_endian(&p.work),
                p.records_acc,
                p.segments,
                p.equihash_checked,
            ),
            None => (input.first_height - 1, input.anchor_hash, out.context_hash, U256::zero(), [0u8; 32], 0, true),
        };
        let mut total = [0u8; 32];
        (work + U256::from_big_endian(&out.work)).to_big_endian(&mut total);
        let mut h = Sha256::new();
        h.update(acc);
        h.update(out.records_hash);
        ChainState {
            vk,
            checkpoint_height,
            checkpoint_hash,
            checkpoint_context_hash,
            last_height: out.last_height,
            last_hash: out.last_hash,
            work: total,
            end_context_hash: out.end_context_hash,
            records_acc: h.finalize().into(),
            segments: segments + 1,
            equihash_checked: eq && out.equihash_checked,
        }
    }

    /// Why a segment cannot continue this state, if it cannot.
    pub fn continues(&self, input: &Input) -> Result<(), &'static str> {
        if input.anchor_hash != self.last_hash {
            return Err("segment does not start at the previous segment's last block");
        }
        if input.first_height != self.last_height + 1 {
            return Err("segment height does not follow the previous segment");
        }
        if context_hash(&input.context) != self.end_context_hash {
            return Err("segment's difficulty context differs from the previous segment's end");
        }
        Ok(())
    }
}

/// A proven claim about a contiguous range of headers, published by a leaf (one segment
/// of headers) or by an aggregation of two adjacent claims. Aggregations nest, so one
/// claim can cover any number of leaves proved in parallel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RangeClaim {
    /// Key digest of the leaf program every leaf in the range was proved with. Zero in a
    /// leaf's own claim (a program cannot know its own key); the aggregator fills it in.
    pub leaf_vk: [u32; 8],
    /// Key digest of the aggregation program. Zero in a leaf's claim.
    pub agg_vk: [u32; 8],
    pub first_height: u64,
    /// Hash of the block before `first_height`.
    pub anchor_hash: [u8; 32],
    /// Difficulty context the range started from.
    pub start_context_hash: [u8; 32],
    pub last_height: u64,
    pub last_hash: [u8; 32],
    pub end_context_hash: [u8; 32],
    /// Total work, big-endian.
    pub work: [u8; 32],
    /// A leaf's records hash, or SHA-256(0x01 || left root || right root).
    pub records_root: [u8; 32],
    pub leaves: u32,
    pub equihash_checked: bool,
}

pub const RANGE_CLAIM_SIZE: usize = 32 + 32 + 8 + 32 + 32 + 8 + 32 + 32 + 32 + 32 + 4 + 1;

/// Why two claims cannot be combined.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Join {
    NotAdjacent,
    HeightGap,
    ContextMismatch,
    MixedPrograms,
}

fn vk_bytes(vk: &[u32; 8], out: &mut Vec<u8>) {
    for w in vk {
        out.extend_from_slice(&w.to_le_bytes());
    }
}

fn vk_from(b: &[u8]) -> [u32; 8] {
    let mut vk = [0u32; 8];
    for (i, w) in vk.iter_mut().enumerate() {
        *w = u32::from_le_bytes(b[i * 4..i * 4 + 4].try_into().unwrap());
    }
    vk
}

impl RangeClaim {
    /// A leaf's claim about the segment it proved.
    pub fn leaf(input: &Input, out: &Output) -> Self {
        RangeClaim {
            leaf_vk: [0; 8],
            agg_vk: [0; 8],
            first_height: input.first_height,
            anchor_hash: input.anchor_hash,
            start_context_hash: out.context_hash,
            last_height: out.last_height,
            last_hash: out.last_hash,
            end_context_hash: out.end_context_hash,
            work: out.work,
            records_root: out.records_hash,
            leaves: 1,
            equihash_checked: out.equihash_checked,
        }
    }

    pub fn is_leaf(&self) -> bool {
        self.leaves == 1 && self.leaf_vk == [0; 8] && self.agg_vk == [0; 8]
    }

    /// The claim covering `left` followed directly by `right`.
    pub fn join(left: &Self, right: &Self, leaf_vk: [u32; 8], agg_vk: [u32; 8]) -> Result<Self, Join> {
        if right.anchor_hash != left.last_hash {
            return Err(Join::NotAdjacent);
        }
        if right.first_height != left.last_height + 1 {
            return Err(Join::HeightGap);
        }
        if right.start_context_hash != left.end_context_hash {
            return Err(Join::ContextMismatch);
        }
        for c in [left, right] {
            if !c.is_leaf() && (c.leaf_vk != leaf_vk || c.agg_vk != agg_vk) {
                return Err(Join::MixedPrograms);
            }
        }
        let mut work = [0u8; 32];
        (U256::from_big_endian(&left.work) + U256::from_big_endian(&right.work)).to_big_endian(&mut work);
        let mut h = Sha256::new();
        h.update([0x01]);
        h.update(left.records_root);
        h.update(right.records_root);
        Ok(RangeClaim {
            leaf_vk,
            agg_vk,
            first_height: left.first_height,
            anchor_hash: left.anchor_hash,
            start_context_hash: left.start_context_hash,
            last_height: right.last_height,
            last_hash: right.last_hash,
            end_context_hash: right.end_context_hash,
            work,
            records_root: h.finalize().into(),
            leaves: left.leaves + right.leaves,
            equihash_checked: left.equihash_checked && right.equihash_checked,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(RANGE_CLAIM_SIZE);
        vk_bytes(&self.leaf_vk, &mut out);
        vk_bytes(&self.agg_vk, &mut out);
        out.extend_from_slice(&self.first_height.to_le_bytes());
        out.extend_from_slice(&self.anchor_hash);
        out.extend_from_slice(&self.start_context_hash);
        out.extend_from_slice(&self.last_height.to_le_bytes());
        out.extend_from_slice(&self.last_hash);
        out.extend_from_slice(&self.end_context_hash);
        out.extend_from_slice(&self.work);
        out.extend_from_slice(&self.records_root);
        out.extend_from_slice(&self.leaves.to_le_bytes());
        out.push(self.equihash_checked as u8);
        out
    }

    pub fn decode(b: &[u8]) -> Option<Self> {
        if b.len() != RANGE_CLAIM_SIZE {
            return None;
        }
        let a32 = |at: usize| -> [u8; 32] { b[at..at + 32].try_into().unwrap() };
        let u64_at = |at: usize| u64::from_le_bytes(b[at..at + 8].try_into().unwrap());
        Some(RangeClaim {
            leaf_vk: vk_from(&b[0..32]),
            agg_vk: vk_from(&b[32..64]),
            first_height: u64_at(64),
            anchor_hash: a32(72),
            start_context_hash: a32(104),
            last_height: u64_at(136),
            last_hash: a32(144),
            end_context_hash: a32(176),
            work: a32(208),
            records_root: a32(240),
            leaves: u32::from_le_bytes(b[272..276].try_into().unwrap()),
            equihash_checked: b[276] == 1,
        })
    }
}
