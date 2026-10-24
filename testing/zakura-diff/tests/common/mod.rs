//! Conversions between Zylem's plain values and Zakura's types, and the two
//! implementations of the contextual header rules behind one signature.
#![allow(dead_code)]

use chrono::{DateTime, Utc};
use zakura_chain::{block::Height, parameters::Network, work::difficulty::CompactDifficulty};
use zakura_header_chain::{validate_contextual_difficulty_and_time, AdjustedDifficulty, ContextualValidationError};
use zylem_header::Net;

pub fn zakura_net(net: Net) -> Network {
    match net {
        Net::Main => Network::Mainnet,
        Net::Test => Network::new_default_testnet(),
    }
}

pub fn compact(bits: u32) -> CompactDifficulty {
    CompactDifficulty::from_bytes_in_display_order(&bits.to_be_bytes()).expect("valid nBits")
}

pub fn bits_of(c: CompactDifficulty) -> u32 {
    u32::from_be_bytes(c.bytes_in_display_order())
}

pub fn time(t: u32) -> DateTime<Utc> {
    DateTime::from_timestamp(t as i64, 0).unwrap()
}

/// The outcome of the contextual rules for one header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Ok,
    TimeTooEarly,
    TimeTooLate,
    WrongDifficulty,
}

/// Zakura: expected `nBits`, and the verdict for a header with `bits` at `time_`.
/// `prev` is `(bits, time)` newest first, at most 113 entries and at most `height`.
pub fn zakura(net: &Network, height: u64, time_: u32, bits: u32, prev: &[(u32, u32)]) -> (u32, Verdict) {
    let ctx = prev.iter().map(|(b, t)| (compact(*b), time(*t)));
    let adj = AdjustedDifficulty::new_from_header_time(time(time_), Height(height as u32 - 1), net, ctx)
        .expect("context accepted");
    let expected = bits_of(adj.expected_difficulty_threshold());
    let verdict = match validate_contextual_difficulty_and_time(compact(bits), adj) {
        Ok(()) => Verdict::Ok,
        Err(ContextualValidationError::TimeTooEarly { .. }) => Verdict::TimeTooEarly,
        Err(ContextualValidationError::TimeTooLate { .. }) => Verdict::TimeTooLate,
        Err(ContextualValidationError::InvalidDifficultyThreshold { .. }) => Verdict::WrongDifficulty,
        #[allow(unreachable_patterns)]
        Err(e) => panic!("unexpected Zakura error at {height}: {e}"),
    };
    (expected, verdict)
}

/// Zylem: the same, from `zylem-header`. Zakura checks time before difficulty, so the
/// time verdict is taken first here too.
pub fn zylem(net: Net, height: u64, time_: u32, bits: u32, prev: &[(u32, u32)]) -> (u32, Verdict) {
    let expected = zylem_header::expected_bits(net, height, time_, prev).expect("context long enough");
    let verdict = match zylem_header::check_contextual(net, height, time_, expected, prev) {
        Err(zylem_header::Fail::TimeTooEarly) => Verdict::TimeTooEarly,
        Err(zylem_header::Fail::TimeTooLate) => Verdict::TimeTooLate,
        Err(f) => panic!("unexpected Zylem failure at {height}: {f:?}"),
        Ok(()) if bits != expected => Verdict::WrongDifficulty,
        Ok(()) => match zylem_header::check_contextual(net, height, time_, bits, prev) {
            Ok(()) => Verdict::Ok,
            Err(f) => panic!("Zylem rejected expected bits at {height}: {f:?}"),
        },
    };
    (expected, verdict)
}

/// The node to fetch from, if the test should run: `ZYLEM_RPC=http://127.0.0.1:18292/`.
pub fn rpc_url() -> Option<String> {
    let url = std::env::var("ZYLEM_RPC").ok();
    if url.is_none() {
        println!("skipped: set ZYLEM_RPC to a node's JSON-RPC URL");
    }
    url
}

/// One JSON-RPC batch of `method` over `params`; results in request order.
pub fn rpc_batch(url: &str, method: &str, params: &[serde_json::Value]) -> Vec<serde_json::Value> {
    let body: Vec<serde_json::Value> = params
        .iter()
        .enumerate()
        .map(|(i, p)| serde_json::json!({"jsonrpc": "2.0", "id": i, "method": method, "params": p}))
        .collect();
    let client = reqwest::blocking::Client::builder().timeout(std::time::Duration::from_secs(120)).build().unwrap();
    let resp: Vec<serde_json::Value> =
        client.post(url).basic_auth("zylem", Some("zylem")).json(&body).send().unwrap().json().unwrap();
    let mut out = vec![serde_json::Value::Null; params.len()];
    for r in resp {
        assert!(r["error"].is_null(), "{method}: {}", r["error"]);
        out[r["id"].as_u64().unwrap() as usize] = r["result"].clone();
    }
    out
}

/// Hex-decoded results of `method [height, extra]` for every height in `from..=to`.
pub fn rpc_hex_range(url: &str, method: &str, from: u64, to: u64, extra: serde_json::Value) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for s in (from..=to).step_by(50) {
        let params: Vec<_> = (s..=(s + 49).min(to)).map(|h| serde_json::json!([h.to_string(), extra])).collect();
        out.extend(rpc_batch(url, method, &params).into_iter().map(|v| hex::decode(v.as_str().unwrap()).unwrap()));
    }
    out
}

pub fn display(internal: [u8; 32]) -> String {
    let mut h = internal;
    h.reverse();
    hex::encode(h)
}
