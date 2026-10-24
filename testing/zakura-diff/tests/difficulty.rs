//! Random and boundary contexts through Zylem's difficulty and time rules and Zakura's:
//! the expected `nBits` and the verdict must agree on every case.

mod common;

use common::{zakura, zakura_net, zylem, Verdict};
use primitive_types::U256;
use rand::{rngs::StdRng, Rng, SeedableRng};
use zylem_header::{Net, MAX_CONTEXT};

const CASES_PER_NETWORK: usize = 200_000;

/// Heights that exercise every rule change, plus uniform ones.
fn height(net: Net, rng: &mut StdRng) -> u64 {
    let near = |h: u64, r: u64, rng: &mut StdRng| rng.gen_range(h.saturating_sub(r).max(1)..=h + r);
    match (net, rng.gen_range(0..10)) {
        (_, 0) => rng.gen_range(1..=150),
        // Blossom: 150 s to 75 s spacing.
        (Net::Main, 1 | 2) => near(653_600, 150, rng),
        (Net::Test, 1) => near(584_000, 150, rng),
        // Testnet: minimum-difficulty rule from 299,188; maximum time from 653,606.
        (Net::Test, 2) => near(299_188, 60, rng),
        (Net::Test, 3) => near(653_606, 60, rng),
        // Testnet NU7: 25 s spacing, 102-block window, 18-spacing minimum-difficulty gap.
        (Net::Test, 4 | 5) => near(4_465_026, 150, rng),
        (Net::Main, _) => rng.gen_range(1..=3_600_000),
        (Net::Test, _) => rng.gen_range(1..=4_600_000),
    }
}

fn spacing(net: Net, h: u64) -> i64 {
    match net {
        Net::Test if h >= 4_465_026 => 25,
        Net::Main if h >= 653_600 => 75,
        Net::Test if h >= 584_000 => 75,
        _ => 150,
    }
}

/// `(bits, time)` of `min(height, 113)` predecessors, newest first.
fn context(net: Net, h: u64, rng: &mut StdRng) -> Vec<(u32, u32)> {
    let n = (h as usize).min(MAX_CONTEXT);
    let limit = net.limit();
    let base = limit >> rng.gen_range(0..48usize);
    let min_share = if net == Net::Test && rng.gen_bool(0.2) { 0.15 } else { 0.0 };
    let mut t: i64 = 1_500_000_000 + rng.gen_range(0..100_000_000);
    let mut oldest_first = Vec::with_capacity(n);
    for i in 0..n {
        let s = spacing(net, h - (n - i) as u64);
        t += match rng.gen_range(0..100) {
            0..=4 => -rng.gen_range(0..=s),
            5..=7 => s * rng.gen_range(5..=30),
            _ => rng.gen_range(1..=3 * s),
        };
        let target = if rng.gen_bool(min_share) {
            limit
        } else {
            let scaled = base / U256::from(1000u32) * U256::from(rng.gen_range(600u32..=1600));
            scaled.min(limit).max(U256::one())
        };
        oldest_first.push((zylem_header::to_compact(target), t.max(1) as u32));
    }
    oldest_first.reverse();
    oldest_first
}

fn median_time(prev: &[(u32, u32)]) -> i64 {
    let mut t: Vec<u32> = prev.iter().take(11).map(|p| p.1).collect();
    t.sort_unstable();
    t[t.len() / 2] as i64
}

fn candidate_time(net: Net, h: u64, prev: &[(u32, u32)], rng: &mut StdRng) -> u32 {
    let s = spacing(net, h);
    let mtp = median_time(prev);
    let t = match rng.gen_range(0..10) {
        // Around the median-time-past and the 90-minute bounds.
        0 => mtp + rng.gen_range(-2..=2),
        1 => mtp + 5_400 + rng.gen_range(-2..=2),
        // Around the testnet minimum-difficulty gap after the previous block.
        2 => prev[0].1 as i64 + 6 * s + rng.gen_range(-2..=2),
        3 => prev[0].1 as i64 + 18 * s + rng.gen_range(-2..=2),
        _ => prev[0].1 as i64 + rng.gen_range(-2 * s..=30 * s),
    };
    t.max(1) as u32
}

fn run(net: Net, seed: u64) {
    let znet = zakura_net(net);
    let mut rng = StdRng::seed_from_u64(seed);
    let (mut agree_ok, mut agree_reject) = (0, 0);
    for case in 0..CASES_PER_NETWORK {
        let h = height(net, &mut rng);
        let prev = context(net, h, &mut rng);
        let t = candidate_time(net, h, &prev, &mut rng);
        // First with whatever both expect, then with a wrong nBits.
        let (z_expected, _) = zakura(&znet, h, t, 0x1f07_ffff, &prev);
        for bits in [z_expected, zylem_header::to_compact(zylem_header::expand(z_expected).unwrap() / 2 + 1)] {
            let (ze, zv) = zakura(&znet, h, t, bits, &prev);
            let (ye, yv) = zylem(net, h, t, bits, &prev);
            assert_eq!(ye, ze, "{net:?} case {case}: height {h}, time {t}: expected nBits differ");
            assert_eq!(yv, zv, "{net:?} case {case}: height {h}, time {t}, bits {bits:08x}: verdicts differ");
            if yv == Verdict::Ok {
                agree_ok += 1;
            } else {
                agree_reject += 1;
            }
        }
    }
    println!("{net:?}: {CASES_PER_NETWORK} contexts, {agree_ok} accepted and {agree_reject} rejected by both");
}

#[test]
fn mainnet_matches_zakura() {
    run(Net::Main, 1);
}

#[test]
fn testnet_matches_zakura() {
    run(Net::Test, 2);
}
