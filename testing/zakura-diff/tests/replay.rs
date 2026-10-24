//! Every real header from a `zylem-build replay-headers --out` file through Zakura's
//! difficulty and time rules and Zylem's: both must accept every header and expect
//! exactly its `nBits`.

mod common;

use common::{zakura, zakura_net, zylem, Verdict};
use zylem_header::{Net, MAX_CONTEXT};

const FILE: &str = "../../data/replay/testnet-from-nu6.bin";

#[test]
fn real_testnet_headers_match_zakura() {
    let Ok(bytes) = std::fs::read(FILE) else {
        println!("skipped: run `zylem-build replay-headers --from 2976000 --out {FILE}` first");
        return;
    };
    let start = u64::from_le_bytes(bytes[..8].try_into().unwrap());
    let entries: Vec<(u32, u32)> = bytes[8..]
        .chunks(40)
        .map(|c| (u32::from_le_bytes(c[..4].try_into().unwrap()), u32::from_le_bytes(c[4..8].try_into().unwrap())))
        .collect();
    let first = start + MAX_CONTEXT as u64;
    let last = start + entries.len() as u64 - 1;
    let threads = std::thread::available_parallelism().map_or(4, |n| n.get());
    let per = ((last - first + 1) as usize).div_ceil(threads);
    let checked: usize = std::thread::scope(|s| {
        let jobs: Vec<_> = (0..threads)
            .map(|t| {
                let entries = &entries;
                s.spawn(move || {
                    let net = zakura_net(Net::Test);
                    let lo = first + (t * per) as u64;
                    let hi = (lo + per as u64 - 1).min(last);
                    let mut n = 0;
                    for h in lo..=hi {
                        let i = (h - start) as usize;
                        let prev: Vec<(u32, u32)> = entries[i - MAX_CONTEXT..i].iter().rev().copied().collect();
                        let (bits, time) = entries[i];
                        let z = zakura(&net, h, time, bits, &prev);
                        let y = zylem(Net::Test, h, time, bits, &prev);
                        assert_eq!(z, (bits, Verdict::Ok), "Zakura at {h}");
                        assert_eq!(y, (bits, Verdict::Ok), "Zylem at {h}");
                        n += 1;
                    }
                    n
                })
            })
            .collect();
        jobs.into_iter().map(|j| j.join().unwrap()).sum()
    });
    println!("{checked} real testnet headers {first}..={last}: both accept each and expect its nBits");
}
