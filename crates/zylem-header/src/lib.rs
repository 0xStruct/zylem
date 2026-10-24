//! Zcash header-chain rules, shared by zylem-core and the zkVM programs that prove them.
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
/// The solution's length, 1,344, as a compact size: the only encoding consensus accepts.
const SOLUTION_LENGTH: [u8; 3] = [0xfd, 0x40, 0x05];
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
    /// Target block spacing in seconds at height `h`.
    pub fn spacing(self, h: u64) -> i64 {
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
    /// The 90-minutes-after-median-time rule: from height 2 on mainnet (Zakura's
    /// `validate_contextual_difficulty_and_time`), from 653,606 on testnet.
    fn max_time_enforced(self, h: u64) -> bool {
        match self {
            Net::Main => h >= 2,
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
    /// Not 1,487 bytes, or the solution length is not encoded as `fd 40 05`.
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
    check_encoding(header)?;
    if &header[4..36] != prev_hash {
        return Err(Fail::BrokenLink);
    }
    let time = u32::from_le_bytes(header[100..104].try_into().unwrap());
    let bits = u32::from_le_bytes(header[104..108].try_into().unwrap());

    if check_equihash {
        check_equihash_solution(header)?;
    }

    let hash = sha256d(header);
    let target = expand(bits).ok_or(Fail::BadBits)?;
    if target > net.limit() || U256::from_little_endian(&hash) > target {
        return Err(Fail::AboveTarget);
    }

    check_contextual(net, height, time, bits, prev)?;
    Ok(Checked { hash, bits, time, work: work(target), record: record_of(header, &hash) })
}

/// The rules that depend on a header's predecessors (`prev`, `(bits, time)` newest
/// first): `nBits` is the difficulty adjustment rule's result, and the time is after the
/// median of the previous 11 and, where enforced, at most 90 minutes past it.
pub fn check_contextual(net: Net, height: u64, time: u32, bits: u32, prev: &[(u32, u32)]) -> Result<(), Fail> {
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
    Ok(())
}

/// How many predecessors `check_contextual` needs at `height`.
pub fn context_needed(net: Net, height: u64) -> usize {
    (net.window(height) + MEDIAN_SPAN).min(height as usize)
}

/// A header is 1,487 bytes with the solution length encoded as consensus requires. The
/// length bytes are hashed into the block hash but not into Equihash's input, so without
/// this check a prover could solve Equihash once and then grind them to meet the target.
pub fn check_encoding(header: &[u8]) -> Result<(), Fail> {
    if header.len() != HEADER_SIZE || header[EQUIHASH_INPUT + 32..EQUIHASH_INPUT + 35] != SOLUTION_LENGTH {
        return Err(Fail::Size);
    }
    Ok(())
}

/// Equihash (200, 9) over a 1,487-byte header: the solution after the 3-byte length.
pub fn check_equihash_solution(header: &[u8]) -> Result<(), Fail> {
    check_encoding(header)?;
    let nonce = &header[EQUIHASH_INPUT..EQUIHASH_INPUT + 32];
    let solution = &header[EQUIHASH_INPUT + 35..];
    equihash::is_valid_solution(200, 9, &header[..EQUIHASH_INPUT], nonce, solution).map_err(|_| Fail::Equihash)
}

/// A header's record: what a client keeps of it once the header chain is proven.
pub fn record_of(header: &[u8], hash: &[u8; 32]) -> [u8; RECORD_SIZE] {
    let mut record = [0u8; RECORD_SIZE];
    record[..32].copy_from_slice(hash);
    record[32..64].copy_from_slice(&header[36..68]); // hashMerkleRoot
    record[64..96].copy_from_slice(&header[68..100]); // hashBlockCommitments
    record[96..100].copy_from_slice(&header[100..104]);
    record[100..104].copy_from_slice(&header[104..108]);
    record
}

/// Leaf of the records tree: SHA-256(0x00 ‖ height ‖ record).
pub fn record_leaf(height: u64, record: &[u8; RECORD_SIZE]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x00]);
    h.update(height.to_le_bytes());
    h.update(record);
    h.finalize().into()
}

/// Inner node of the records tree: SHA-256(0x01 ‖ left ‖ right).
pub fn node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x01]);
    h.update(left);
    h.update(right);
    h.finalize().into()
}

/// The root of one aligned block of heights: `2^level` records starting at `start`, a
/// multiple of `2^level`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Peak {
    pub start: u64,
    pub level: u8,
    pub root: [u8; 32],
}

pub const PEAK_SIZE: usize = 8 + 1 + 32;

impl Peak {
    fn end(&self) -> u64 {
        self.start + (1u64 << self.level)
    }
}

/// The canonical commitment to the records of a height range.
///
/// Every height has a fixed place in one binary tree over all heights, so each aligned
/// block of `2^k` heights has one root whatever range it is part of. A range's commitment
/// is the roots of the largest aligned blocks that tile it, lowest height first. It
/// depends only on the heights and records, never on how provers split the range into
/// leaves and aggregations, and a client can check any part of it (a Ring, one block)
/// with sibling hashes up to the peak that contains it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Peaks(pub Vec<Peak>);

/// Why records do not match a commitment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Binding {
    /// The records are not inside the committed range.
    OutOfRange,
    /// A block's path has the wrong length for the peak above it.
    BadPath,
    /// The records, their heights or the path do not hash to the committed peak.
    Mismatch,
}

/// The largest aligned blocks tiling `first..=last`, as `(start, level)`.
pub fn canonical_blocks(first: u64, last: u64) -> Vec<(u64, u8)> {
    let mut out = Vec::new();
    let mut at = first;
    while at <= last {
        let mut level = 0u8;
        while level < 63 && at % (1u64 << (level + 1)) == 0 && at + (1u64 << (level + 1)) - 1 <= last {
            level += 1;
        }
        out.push((at, level));
        match at.checked_add(1u64 << level) {
            Some(next) => at = next,
            None => break,
        }
    }
    out
}

impl Peaks {
    /// Height after the last committed record.
    pub fn end(&self) -> Option<u64> {
        self.0.last().map(Peak::end)
    }

    /// Appends one aligned block that starts where the commitment ends, merging it with
    /// its left sibling for as long as the pair forms a larger aligned block.
    pub fn push(&mut self, peak: Peak) {
        if let Some(end) = self.end() {
            assert_eq!(peak.start, end, "records are not contiguous");
        }
        self.0.push(peak);
        while let [.., l, r] = self.0[..] {
            if l.level != r.level || l.start % (1u64 << (l.level + 1)) != 0 {
                break;
            }
            self.0.truncate(self.0.len() - 2);
            self.0.push(Peak { start: l.start, level: l.level + 1, root: node(&l.root, &r.root) });
        }
    }

    pub fn push_record(&mut self, height: u64, record: &[u8; RECORD_SIZE]) {
        self.push(Peak { start: height, level: 0, root: record_leaf(height, record) });
    }

    /// The commitment to `left`'s range followed directly by `right`'s.
    pub fn join(left: &Peaks, right: &Peaks) -> Peaks {
        let mut out = left.clone();
        for p in &right.0 {
            out.push(*p);
        }
        out
    }

    pub fn of_records(first: u64, records: &[[u8; RECORD_SIZE]]) -> Peaks {
        let mut p = Peaks::default();
        for (i, r) in records.iter().enumerate() {
            p.push_record(first + i as u64, r);
        }
        p
    }

    /// Whether the peaks have exactly the canonical shape for `first..=last`.
    pub fn is_canonical(&self, first: u64, last: u64) -> bool {
        let shape: Vec<(u64, u8)> = self.0.iter().map(|p| (p.start, p.level)).collect();
        shape == canonical_blocks(first, last)
    }

    pub fn encode(&self, out: &mut Vec<u8>) {
        out.push(self.0.len() as u8);
        for p in &self.0 {
            out.extend_from_slice(&p.start.to_le_bytes());
            out.push(p.level);
            out.extend_from_slice(&p.root);
        }
    }

    /// Decodes peaks from the front of `b`; returns them and the bytes used.
    pub fn decode(b: &[u8]) -> Option<(Peaks, usize)> {
        let n = *b.first()? as usize;
        let used = 1 + n * PEAK_SIZE;
        if b.len() < used {
            return None;
        }
        let peaks = b[1..used]
            .chunks(PEAK_SIZE)
            .map(|c| Peak {
                start: u64::from_le_bytes(c[..8].try_into().unwrap()),
                level: c[8],
                root: c[9..41].try_into().unwrap(),
            })
            .collect();
        Some((Peaks(peaks), used))
    }

    pub fn digest(&self) -> [u8; 32] {
        let mut b = Vec::new();
        self.encode(&mut b);
        Sha256::digest(b).into()
    }

    /// Checks that `records` are the committed records at heights `first..`, given one
    /// sibling path per canonical block of that range (as `range_paths` builds them).
    pub fn verify_range(&self, first: u64, records: &[[u8; RECORD_SIZE]], paths: &[Vec<[u8; 32]>]) -> Result<(), Binding> {
        let (Some(start), Some(end)) = (self.0.first().map(|p| p.start), self.end()) else {
            return Err(Binding::OutOfRange);
        };
        if records.is_empty() {
            return Err(Binding::OutOfRange);
        }
        let last = first + records.len() as u64 - 1;
        if first < start || last >= end {
            return Err(Binding::OutOfRange);
        }
        let blocks = canonical_blocks(first, last);
        if paths.len() != blocks.len() {
            return Err(Binding::BadPath);
        }
        for ((bstart, level), path) in blocks.into_iter().zip(paths) {
            let peak = self.0.iter().find(|p| p.start <= bstart && bstart < p.end()).ok_or(Binding::OutOfRange)?;
            if path.len() != (peak.level - level) as usize {
                return Err(Binding::BadPath);
            }
            let from = (bstart - first) as usize;
            let mut root = Peaks::of_records(bstart, &records[from..from + (1usize << level)]).0[0].root;
            for (i, sibling) in path.iter().enumerate() {
                let l = level as u32 + i as u32;
                root = if (bstart >> l) & 1 == 0 { node(&root, sibling) } else { node(sibling, &root) };
            }
            if root != peak.root {
                return Err(Binding::Mismatch);
            }
        }
        Ok(())
    }
}

/// The root of the aligned block `(start, level)` from the leaves of the whole committed
/// range (`leaves[i]` at height `first + i`).
fn block_root(first: u64, leaves: &[[u8; 32]], start: u64, level: u8) -> [u8; 32] {
    let from = (start - first) as usize;
    let mut layer: Vec<[u8; 32]> = leaves[from..from + (1usize << level)].to_vec();
    while layer.len() > 1 {
        layer = layer.chunks(2).map(|c| node(&c[0], &c[1])).collect();
    }
    layer[0]
}

/// What a server holding every record of a committed range sends with a sub-range
/// `sub_first..=sub_last`: for each canonical block of the sub-range, the sibling roots
/// up to the peak containing it.
pub fn range_paths(first: u64, records: &[[u8; RECORD_SIZE]], sub_first: u64, sub_last: u64) -> Vec<Vec<[u8; 32]>> {
    let leaves: Vec<[u8; 32]> = records.iter().enumerate().map(|(i, r)| record_leaf(first + i as u64, r)).collect();
    let peaks = canonical_blocks(first, first + records.len() as u64 - 1);
    canonical_blocks(sub_first, sub_last)
        .into_iter()
        .map(|(start, level)| {
            let (_, top) = *peaks.iter().find(|(s, l)| *s <= start && start < s + (1u64 << l)).expect("inside the range");
            (level..top)
                .map(|l| {
                    let sibling = ((start >> l) ^ 1) << l;
                    block_root(first, &leaves, sibling, l)
                })
                .collect()
        })
        .collect()
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
    /// Canonical commitment to every proven header's record at its height.
    pub records: Peaks,
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
    let mut records = Peaks::default();
    let mut height = input.first_height;
    let mut newest_first: Vec<(u32, u32)> = Vec::with_capacity(MAX_CONTEXT);
    for header in headers.chunks(HEADER_SIZE).take(input.count as usize) {
        newest_first.clear();
        newest_first.extend(ctx.iter().rev().take(MAX_CONTEXT).copied());
        let c = check(input.net, height, header, &prev_hash, &newest_first, input.check_equihash)
            .map_err(|f| (height, f))?;
        records.push_record(height, &c.record);
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
        records,
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

    #[test]
    fn solution_length_must_be_canonical() {
        let mut header = [0u8; HEADER_SIZE];
        header[140..143].copy_from_slice(&SOLUTION_LENGTH);
        assert_eq!(check_encoding(&header), Ok(()));
        // Other encodings of 1,344, or other lengths, change the block hash without
        // changing Equihash's input.
        for bad in [[0xfe, 0x40, 0x05], [0xfd, 0x40, 0x06], [0xfd, 0x41, 0x05]] {
            header[140..143].copy_from_slice(&bad);
            assert_eq!(check_encoding(&header), Err(Fail::Size));
            assert_eq!(check_equihash_solution(&header), Err(Fail::Size));
        }
        assert_eq!(check_encoding(&header[..HEADER_SIZE - 1]), Err(Fail::Size));
    }

    fn records(n: usize, seed: u8) -> Vec<[u8; RECORD_SIZE]> {
        (0..n)
            .map(|i| {
                let mut r = [0u8; RECORD_SIZE];
                for (j, c) in r.chunks_mut(32).enumerate() {
                    let d: [u8; 32] = Sha256::digest([seed, (i >> 8) as u8, i as u8, j as u8]).into();
                    c.copy_from_slice(&d[..c.len()]);
                }
                r
            })
            .collect()
    }

    /// A leaf claim over `records` at `first`, chained by fake hashes so claims join.
    fn claim(first: u64, records: &[[u8; RECORD_SIZE]]) -> RangeClaim {
        let last = first + records.len() as u64 - 1;
        let tag = |h: u64| -> [u8; 32] { Sha256::digest(h.to_le_bytes()).into() };
        RangeClaim {
            leaf_vk: [0; 8],
            agg_vk: [0; 8],
            first_height: first,
            anchor_hash: tag(first - 1),
            start_context_hash: tag(first + 1_000_000),
            last_height: last,
            last_hash: tag(last),
            end_context_hash: tag(last + 1 + 1_000_000),
            work: [0; 32],
            leaves: 1,
            equihash_checked: true,
            records: Peaks::of_records(first, records),
        }
    }

    const FIRST: u64 = 4_494_811;

    #[test]
    fn records_commitment_does_not_depend_on_the_split() {
        let r = records(300, 1);
        let whole = Peaks::of_records(FIRST, &r);
        assert!(whole.is_canonical(FIRST, FIRST + 299));
        for k in [1, 37, 100, 128, 150, 299] {
            let joined = Peaks::join(&Peaks::of_records(FIRST, &r[..k]), &Peaks::of_records(FIRST + k as u64, &r[k..]));
            assert_eq!(joined, whole, "split at {k}");
        }
        // Three leaves, joined left-first and right-first, through the claim rule.
        let (a, b, c) = (claim(FIRST, &r[..90]), claim(FIRST + 90, &r[90..200]), claim(FIRST + 200, &r[200..]));
        let left_first = RangeClaim::join(&RangeClaim::join(&a, &b, [1; 8], [2; 8]).unwrap(), &c, [1; 8], [2; 8]).unwrap();
        let right_first = RangeClaim::join(&a, &RangeClaim::join(&b, &c, [1; 8], [2; 8]).unwrap(), [1; 8], [2; 8]).unwrap();
        assert_eq!(left_first.records, whole);
        assert_eq!(right_first.records, whole);
    }

    #[test]
    fn records_commitment_commits_to_heights_and_order() {
        // 1,024 records at two aligned heights have the same shape: one level-10 peak.
        let r = records(1_024, 2);
        let (at0, at1024) = (Peaks::of_records(4_096, &r), Peaks::of_records(5_120, &r));
        assert_eq!((at0.0.len(), at0.0[0].level, at1024.0[0].level), (1, 10, 10));
        assert_ne!(at0.0[0].root, at1024.0[0].root, "same records at other heights must differ");

        let mut swapped = r.clone();
        swapped.swap(3, 4);
        assert_ne!(Peaks::of_records(4_096, &swapped), at0);
    }

    #[test]
    fn a_ring_binds_to_the_proven_records() {
        let r = records(300, 3);
        let peaks = Peaks::of_records(FIRST, &r);
        // A "Ring" in the middle of the proven range, not aligned to any block.
        let (lo, hi) = (FIRST + 41, FIRST + 233);
        let ring = &r[41..=233];
        let paths = range_paths(FIRST, &r, lo, hi);
        assert_eq!(peaks.verify_range(lo, ring, &paths), Ok(()));
        // A single block.
        assert_eq!(peaks.verify_range(FIRST + 7, &r[7..8], &range_paths(FIRST, &r, FIRST + 7, FIRST + 7)), Ok(()));

        // One altered byte in one record.
        let mut tampered = ring.to_vec();
        tampered[100][40] ^= 1;
        assert_eq!(peaks.verify_range(lo, &tampered, &paths), Err(Binding::Mismatch));
        // Two records swapped.
        let mut swapped = ring.to_vec();
        swapped.swap(10, 11);
        assert_eq!(peaks.verify_range(lo, &swapped, &paths), Err(Binding::Mismatch));
        // The right records presented at the wrong heights, with paths for those heights.
        let shifted = range_paths(FIRST, &r, lo + 1, hi + 1);
        assert_ne!(peaks.verify_range(lo + 1, ring, &shifted), Ok(()));
        // Outside the proven range.
        assert_eq!(peaks.verify_range(FIRST - 1, &r[..2], &paths), Err(Binding::OutOfRange));
        assert_eq!(peaks.verify_range(FIRST + 299, &r[..2], &paths), Err(Binding::OutOfRange));
        // A forged sibling, and a path that stops short of the peak.
        let mut forged = paths.clone();
        forged[0][0][0] ^= 1;
        assert_eq!(peaks.verify_range(lo, ring, &forged), Err(Binding::Mismatch));
        let mut short = paths.clone();
        short[0].pop();
        assert_eq!(peaks.verify_range(lo, ring, &short), Err(Binding::BadPath));
    }

    #[test]
    fn claims_round_trip_and_reject_bad_commitments() {
        let r = records(300, 4);
        let (a, b) = (claim(FIRST, &r[..150]), claim(FIRST + 150, &r[150..]));
        let joined = RangeClaim::join(&a, &b, [1; 8], [2; 8]).unwrap();
        let bytes = joined.encode();
        assert_eq!(RangeClaim::decode(&bytes), Some(joined));
        let mut longer = bytes.clone();
        longer.push(0);
        assert_eq!(RangeClaim::decode(&longer), None);
        assert_eq!(RangeClaim::decode(&bytes[..bytes.len() - 1]), None);

        // A child whose peaks were never merged (two level-0 blocks that form a level-1 one).
        let mut unmerged = claim(FIRST + 150, &r[150..]);
        unmerged.records = Peaks(
            canonical_blocks(FIRST + 150, FIRST + 299)
                .into_iter()
                .flat_map(|(s, l)| (0..1u64 << l).map(move |i| Peak { start: s + i, level: 0, root: [0; 32] }))
                .collect(),
        );
        assert_eq!(RangeClaim::join(&a, &unmerged, [1; 8], [2; 8]), Err(Join::BadRecords));
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
    /// SHA-256 chain over the digest of each segment's records commitment.
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
        h.update(out.records.digest());
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
    pub leaves: u32,
    pub equihash_checked: bool,
    /// Canonical commitment to the range's records; the same whichever leaves and
    /// aggregations produced it.
    pub records: Peaks,
}

/// Size of a claim before its records commitment (one count byte plus 41 bytes a peak).
pub const RANGE_CLAIM_FIXED: usize = 32 + 32 + 8 + 32 + 32 + 8 + 32 + 32 + 32 + 4 + 1;

/// Why two claims cannot be combined.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Join {
    NotAdjacent,
    HeightGap,
    ContextMismatch,
    MixedPrograms,
    /// A child's records commitment does not have the shape of its height range.
    BadRecords,
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
            leaves: 1,
            equihash_checked: out.equihash_checked,
            records: out.records.clone(),
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
        for c in [left, right] {
            if !c.records.is_canonical(c.first_height, c.last_height) {
                return Err(Join::BadRecords);
            }
        }
        let mut work = [0u8; 32];
        (U256::from_big_endian(&left.work) + U256::from_big_endian(&right.work)).to_big_endian(&mut work);
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
            leaves: left.leaves + right.leaves,
            equihash_checked: left.equihash_checked && right.equihash_checked,
            records: Peaks::join(&left.records, &right.records),
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(RANGE_CLAIM_FIXED + 1 + self.records.0.len() * PEAK_SIZE);
        vk_bytes(&self.leaf_vk, &mut out);
        vk_bytes(&self.agg_vk, &mut out);
        out.extend_from_slice(&self.first_height.to_le_bytes());
        out.extend_from_slice(&self.anchor_hash);
        out.extend_from_slice(&self.start_context_hash);
        out.extend_from_slice(&self.last_height.to_le_bytes());
        out.extend_from_slice(&self.last_hash);
        out.extend_from_slice(&self.end_context_hash);
        out.extend_from_slice(&self.work);
        out.extend_from_slice(&self.leaves.to_le_bytes());
        out.push(self.equihash_checked as u8);
        self.records.encode(&mut out);
        out
    }

    pub fn decode(b: &[u8]) -> Option<Self> {
        if b.len() <= RANGE_CLAIM_FIXED {
            return None;
        }
        let (records, used) = Peaks::decode(&b[RANGE_CLAIM_FIXED..])?;
        if RANGE_CLAIM_FIXED + used != b.len() {
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
            leaves: u32::from_le_bytes(b[240..244].try_into().unwrap()),
            equihash_checked: b[244] == 1,
            records,
        })
    }
}
