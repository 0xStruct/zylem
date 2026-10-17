//! Checks every header in the Rings with the shared rules, natively. A header passes only
//! if its nBits equals what the ported difficulty rule computes from its predecessors.

use std::{path::PathBuf, time::Instant};

use anyhow::Result;
use zylem_hdr::{check, Fail, Net, MAX_CONTEXT};

fn main() -> Result<()> {
    let dir = PathBuf::from(std::env::args().nth(1).unwrap_or_else(|| "../../data/testnet".into()));
    let equihash = std::env::args().any(|a| a == "--equihash");
    let headers = zylem_hdr_validate::load_headers(&dir)?;
    println!("{} headers, heights {}..={}", headers.len(), headers[0].0, headers.last().unwrap().0);

    let started = Instant::now();
    let (mut ok, mut failed, mut min_difficulty) = (0u64, 0u64, 0u64);
    let limit_bits = zylem_hdr::to_compact(Net::Test.limit());
    // The first MAX_CONTEXT headers only provide context.
    for i in MAX_CONTEXT..headers.len() {
        let (height, ref header) = headers[i];
        let prev: Vec<(u32, u32)> = headers[i - MAX_CONTEXT..i]
            .iter()
            .rev()
            .map(|(_, h)| {
                let t = u32::from_le_bytes(h[100..104].try_into().unwrap());
                let b = u32::from_le_bytes(h[104..108].try_into().unwrap());
                (b, t)
            })
            .collect();
        let prev_hash = zylem_hdr::sha256d(&headers[i - 1].1);
        match check(Net::Test, height, header, &prev_hash, &prev, equihash) {
            Ok(c) => {
                ok += 1;
                min_difficulty += u64::from(c.bits == limit_bits);
            }
            Err(f) => {
                failed += 1;
                if failed <= 10 {
                    println!("  height {height}: {f:?}");
                }
            }
        }
    }
    println!(
        "checked {} headers (Equihash {}): {ok} pass, {failed} fail, {min_difficulty} minimum-difficulty blocks, {:.2} s",
        ok + failed,
        if equihash { "on" } else { "off" },
        started.elapsed().as_secs_f64()
    );

    // Each kind of forgery on a real header must be rejected.
    let i = MAX_CONTEXT + 500;
    let (height, header) = (&headers[i].0, &headers[i].1);
    let prev: Vec<(u32, u32)> = headers[i - MAX_CONTEXT..i]
        .iter()
        .rev()
        .map(|(_, h)| {
            (
                u32::from_le_bytes(h[104..108].try_into().unwrap()),
                u32::from_le_bytes(h[100..104].try_into().unwrap()),
            )
        })
        .collect();
    let prev_hash = zylem_hdr::sha256d(&headers[i - 1].1);
    let forge = |f: &dyn Fn(&mut Vec<u8>), eq: bool| {
        let mut h = header.clone();
        f(&mut h);
        check(Net::Test, *height, &h, &prev_hash, &prev, eq).err()
    };
    let cases: [(&str, Option<Fail>); 4] = [
        // An easier target than the rule allows.
        ("easier nBits", forge(&|h| h[106] = h[106].wrapping_add(1), false)),
        ("wrong parent", forge(&|h| h[4] ^= 1, false)),
        ("time at the median", forge(&|h| {
            let mut t: Vec<u32> = prev.iter().take(11).map(|p| p.1).collect();
            t.sort_unstable();
            h[100..104].copy_from_slice(&t[5].to_le_bytes());
        }, false)),
        ("corrupted solution", forge(&|h| h[200] ^= 1, true)),
    ];
    for (name, res) in cases {
        println!("  forged {name}: {}", res.map(|f| format!("rejected ({f:?})")).unwrap_or_else(|| "ACCEPTED".into()));
    }
    Ok(())
}
