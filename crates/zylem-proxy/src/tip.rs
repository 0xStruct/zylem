//! Tip policy: which chain the proxy may present as current.
//!
//! Valid proof of work is not enough, because Zcash adjusts difficulty every block: a
//! private fork from the checkpoint can lower its difficulty within a few hundred blocks,
//! and an endless fake chain costs about 26 honest blocks of work before NU7 (145 with
//! NU7's 102-block window). So the served tip must also:
//!
//! - carry at least the checkpoint's minimum work after the checkpoint;
//! - be confirmed by at least `min_sources` independent sources (Ring hosts, header-only
//!   node witnesses, the upstream light-wallet server);
//! - not be outworked: no verified source may show a heavier fork, or the same chain more
//!   than `max_behind` blocks further on.
//!
//! A tip whose newest header is older than `stale_after` raises an alarm: blocks arrive
//! every 25 s (75 s before NU7), so a long silence means some source is withholding.
//! Failures make strict mode refuse `GetLatestBlock`; alarms are logged.

use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Value};
use zcash_protocol::consensus::Network;
use zylem_core::{header::verify_run, manifest::display_hash};
use zylem_proto::rpc::{compact_tx_streamer_client::CompactTxStreamerClient, BlockId, ChainSpec};

use crate::chain::{Chain, Checkpoint, RingView};

/// Headers a witness may be ahead by before we stop fetching (it is then "far ahead").
const MAX_WITNESS_HEADERS: u64 = 2_000;
/// How far back to look for a fork point with a witness.
const MAX_FORK_DEPTH: u64 = 200;

/// A Zakura or zcashd JSON-RPC endpoint used only for headers. Credentials, if any, go in
/// the URL (`http://user:pass@host:port/`). Untrusted: every header it serves is checked.
pub struct HeaderSource {
    pub url: String,
    http: reqwest::Client,
}

impl HeaderSource {
    pub fn new(url: &str) -> Self {
        let http = reqwest::Client::builder().timeout(Duration::from_secs(30)).build().expect("client");
        HeaderSource { url: url.to_string(), http }
    }

    pub fn name(&self) -> String {
        // Never log credentials.
        match reqwest::Url::parse(&self.url) {
            Ok(mut u) => {
                let _ = u.set_password(None);
                let _ = u.set_username("");
                u.to_string()
            }
            Err(_) => "header source".into(),
        }
    }

    async fn batch(&self, method: &str, params: Vec<Value>) -> Result<Vec<Value>> {
        let body: Vec<Value> = params
            .into_iter()
            .enumerate()
            .map(|(i, p)| json!({"jsonrpc": "2.0", "id": i, "method": method, "params": p}))
            .collect();
        let n = body.len();
        let resp: Vec<Value> = self.http.post(&self.url).json(&body).send().await?.error_for_status()?.json().await?;
        let mut out = vec![Value::Null; n];
        for r in resp {
            if let Some(e) = r.get("error").filter(|e| !e.is_null()) {
                bail!("{method}: {e}");
            }
            let id = r["id"].as_u64().ok_or_else(|| anyhow!("{method}: response without id"))? as usize;
            *out.get_mut(id).ok_or_else(|| anyhow!("{method}: bad id"))? = r["result"].clone();
        }
        Ok(out)
    }

    async fn tip(&self) -> Result<u64> {
        self.batch("getblockcount", vec![json!([])]).await?[0].as_u64().context("getblockcount")
    }

    async fn hashes(&self, from: u64, to: u64) -> Result<Vec<[u8; 32]>> {
        let params = (from..=to).map(|h| json!([h])).collect();
        self.batch("getblockhash", params)
            .await?
            .into_iter()
            .map(|v| {
                let mut h: [u8; 32] = hex::decode(v.as_str().context("getblockhash")?)?
                    .try_into()
                    .map_err(|_| anyhow!("getblockhash: not 32 bytes"))?;
                h.reverse();
                Ok(h)
            })
            .collect()
    }

    async fn headers(&self, from: u64, to: u64) -> Result<Vec<Vec<u8>>> {
        let mut out = Vec::new();
        for s in (from..=to).step_by(100) {
            let params = (s..=(s + 99).min(to)).map(|h| json!([h.to_string(), false])).collect();
            for v in self.batch("getblockheader", params).await? {
                out.push(hex::decode(v.as_str().context("getblockheader")?)?);
            }
        }
        Ok(out)
    }
}

/// What a source says about the served tip.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Evidence {
    /// Its chain contains the served tip; `ahead` more blocks follow it there, checked
    /// header by header when `verified` (a light-wallet server only reports a height).
    Confirms { ahead: u64, verified: bool },
    /// Its chain is a prefix of ours (it lags).
    Behind { height: u64 },
    /// A fork from `at`, with less verified work than ours.
    LighterFork { at: u64 },
    /// A fork from `at` with more verified work than ours: the served tip is not the best
    /// chain this proxy has seen.
    HeavierFork { at: u64 },
    /// It shares no block with the served chain from `from` up: a fork too deep to weigh
    /// here.
    DeepFork { from: u64 },
    /// The light-wallet server reports a different block at the tip height. It serves no
    /// difficulty, so its fork cannot be weighed.
    Disagrees,
    /// It served headers that failed verification.
    Invalid(String),
    Unreachable(String),
}

/// Weighs a header-only witness against the served chain.
pub async fn witness(src: &HeaderSource, chain: &Chain, network: &Network, floor: u64) -> Evidence {
    match witness_inner(src, chain, network, floor).await {
        Ok(e) => e,
        Err(e) => Evidence::Unreachable(format!("{e:#}")),
    }
}

async fn witness_inner(src: &HeaderSource, chain: &Chain, network: &Network, floor: u64) -> Result<Evidence> {
    let tip = chain.tip().context("nothing verified")?;
    let ours = tip.header.height;
    let theirs = src.tip().await?;
    // Find the highest common block at or below both tips.
    let top = ours.min(theirs);
    let lo = top.saturating_sub(MAX_FORK_DEPTH).max(floor);
    let their_hashes = src.hashes(lo, top).await?;
    let common = (lo..=top)
        .rev()
        .zip(their_hashes.iter().rev())
        .find(|(h, hash)| chain.get(*h).is_some_and(|b| b.header.hash == **hash))
        .map(|(h, _)| h);
    let Some(at) = common else { return Ok(Evidence::DeepFork { from: lo }) };
    if at == ours {
        if theirs == ours {
            return Ok(Evidence::Confirms { ahead: 0, verified: true });
        }
        // Their chain extends ours: check the extension before counting it.
        let to = theirs.min(ours + MAX_WITNESS_HEADERS);
        let raw = src.headers(ours + 1, to).await?;
        return match verify_run(network, &tip.header, &chain.context_at(ours), &raw) {
            Ok(run) => Ok(Evidence::Confirms { ahead: run.headers.len() as u64, verified: true }),
            Err(e) => Ok(Evidence::Invalid(format!("headers after {ours}: {e}"))),
        };
    }
    if at == theirs {
        return Ok(Evidence::Behind { height: theirs });
    }
    // A fork from `at`: compare verified work above it.
    let to = theirs.min(at + MAX_WITNESS_HEADERS);
    let raw = src.headers(at + 1, to).await?;
    let base = &chain.get(at).expect("common block is verified").header;
    let run = match verify_run(network, base, &chain.context_at(at), &raw) {
        Ok(run) => run,
        Err(e) => return Ok(Evidence::Invalid(format!("fork headers after {at}: {e}"))),
    };
    let our_work = chain.work_above(at);
    Ok(if run.work > our_work { Evidence::HeavierFork { at } } else { Evidence::LighterFork { at } })
}

/// The light-wallet server as a witness: block hash agreement only.
pub async fn upstream_witness(
    up: &mut CompactTxStreamerClient<tonic::transport::Channel>,
    chain: &Chain,
) -> Evidence {
    let Some(tip) = chain.tip() else { return Evidence::Unreachable("nothing verified".into()) };
    let (height, hash) = (tip.header.height, tip.header.hash);
    let latest = match up.get_latest_block(ChainSpec {}).await {
        Ok(l) => l.into_inner().height,
        Err(e) => return Evidence::Unreachable(e.message().to_string()),
    };
    if latest < height {
        return match up.get_block(BlockId { height: latest, hash: vec![] }).await {
            Ok(b) if chain.get(latest).is_some_and(|ours| ours.header.hash[..] == b.get_ref().hash[..]) => {
                Evidence::Behind { height: latest }
            }
            Ok(_) => Evidence::Disagrees,
            Err(e) => Evidence::Unreachable(e.message().to_string()),
        };
    }
    match up.get_block(BlockId { height, hash: vec![] }).await {
        Ok(b) if b.get_ref().hash[..] == hash[..] => Evidence::Confirms { ahead: latest - height, verified: false },
        Ok(_) => Evidence::Disagrees,
        Err(e) => Evidence::Unreachable(e.message().to_string()),
    }
}

/// Evidence from a Ring host's newest block.
pub fn ring_evidence(view: &RingView, chain: &Chain) -> Evidence {
    let Some(tip) = chain.tip() else { return Evidence::Unreachable("nothing verified".into()) };
    match view {
        RingView::Tip { height, hash } if *height == tip.header.height && *hash == tip.header.hash => {
            Evidence::Confirms { ahead: 0, verified: true }
        }
        RingView::Tip { height, hash } if chain.get(*height).is_some_and(|b| b.header.hash == *hash) => Evidence::Behind { height: *height },
        // A tail that verified but was not adopted had less work.
        RingView::Tip { height, .. } => Evidence::LighterFork { at: (*height).min(tip.header.height) },
        RingView::Unreachable(e) => Evidence::Unreachable(e.clone()),
        RingView::Rejected(e) => Evidence::Invalid(e.clone()),
        RingView::Conflict(e) => Evidence::Invalid(e.clone()),
    }
}

pub struct Policy {
    pub checkpoint: Checkpoint,
    pub min_sources: usize,
    pub max_behind: u64,
    /// Seconds; `None` derives it from the block spacing at the tip.
    pub stale_after: Option<u64>,
}

#[derive(Clone, Debug, Default)]
pub struct Status {
    /// Why the tip must not be presented; empty when it may.
    pub failures: Vec<String>,
    /// Worth a human's attention, but not a reason to refuse.
    pub alarms: Vec<String>,
    pub confirmations: usize,
}

impl Status {
    pub fn ok(&self) -> bool {
        self.failures.is_empty()
    }
    pub fn summary(&self) -> String {
        if self.ok() {
            format!("tip ok, confirmed by {} sources", self.confirmations)
        } else {
            format!("TIP POLICY FAILED: {}", self.failures.join("; "))
        }
    }
}

/// Seconds without a new block after which a silence is suspicious: the chance of no
/// block in that time is below 1 in 10,000 (e^-9.2), plus two minutes for miners'
/// clocks.
pub fn default_stale_after(network: &Network, height: u64) -> u64 {
    let net = match network {
        Network::MainNetwork => zylem_header::Net::Main,
        Network::TestNetwork => zylem_header::Net::Test,
    };
    (net.spacing(height) as f64 * (10_000f64).ln()) as u64 + 120
}

/// What the policy needs to know about the served chain.
pub struct TipFacts {
    pub height: u64,
    pub hash: [u8; 32],
    pub time: u32,
    /// Verified work above the checkpoint.
    pub work_after_checkpoint: primitive_types::U256,
}

impl TipFacts {
    pub fn of(chain: &Chain, checkpoint: &Checkpoint) -> Option<Self> {
        let tip = chain.tip()?;
        Some(TipFacts {
            height: tip.header.height,
            hash: tip.header.hash,
            time: tip.header.time,
            work_after_checkpoint: chain.work_above(checkpoint.height),
        })
    }
}

pub fn evaluate(tip: Option<&TipFacts>, policy: &Policy, network: &Network, evidence: &[(String, Evidence)], now: u64) -> Status {
    let mut st = Status::default();
    let Some(tip) = tip else {
        st.failures.push("nothing verified".into());
        return st;
    };
    if let Some(min) = policy.checkpoint.min_work {
        if tip.work_after_checkpoint < min {
            st.failures.push(format!("work after the checkpoint {:x} is below the minimum {min:x}", tip.work_after_checkpoint));
        }
    }
    for (name, e) in evidence {
        match e {
            Evidence::Confirms { ahead, verified } => {
                st.confirmations += 1;
                if *ahead > policy.max_behind {
                    // Only verified headers can stop the tip; a bare height claim could be
                    // used to stop every wallet.
                    if *verified {
                        st.failures.push(format!("{name} has {ahead} verified blocks after the served tip"));
                    } else {
                        st.alarms.push(format!("{name} reports {ahead} more blocks after the served tip"));
                    }
                }
            }
            Evidence::Behind { height } => st.alarms.push(format!("{name} lags at {height}")),
            Evidence::LighterFork { at } => st.alarms.push(format!("{name} is on a lighter fork from {at}")),
            Evidence::HeavierFork { at } => st.failures.push(format!("{name} shows a heavier fork from {at}")),
            Evidence::DeepFork { from } => {
                st.failures.push(format!("{name} shares no block with the served chain from {from} on"))
            }
            Evidence::Disagrees => st.alarms.push(format!("{name} has a different block at the tip height")),
            Evidence::Invalid(why) => st.alarms.push(format!("{name} served invalid data: {why}")),
            Evidence::Unreachable(why) => st.alarms.push(format!("{name} unreachable: {why}")),
        }
    }
    if st.confirmations < policy.min_sources {
        st.failures.push(format!("tip confirmed by {} sources, {} required", st.confirmations, policy.min_sources));
    }
    let stale_after = policy.stale_after.unwrap_or_else(|| default_stale_after(network, tip.height));
    let age = now.saturating_sub(tip.time as u64);
    if age > stale_after {
        st.alarms.push(format!(
            "STALE TIP: newest block {} ({}) is {age} s old, alarm after {stale_after} s",
            tip.height,
            display_hash(&tip.hash)
        ));
    }
    st
}

#[cfg(test)]
mod tests {
    use super::*;
    use primitive_types::U256;

    const NOW: u64 = 1_800_000_000;

    fn facts(work: u64, age: u64) -> TipFacts {
        TipFacts { height: 4_526_000, hash: [1; 32], time: (NOW - age) as u32, work_after_checkpoint: U256::from(work) }
    }

    fn policy(min_work: Option<u64>) -> Policy {
        Policy {
            checkpoint: Checkpoint { height: 4_500_000, hash: [0; 32], min_work: min_work.map(U256::from) },
            min_sources: 2,
            max_behind: 12,
            stale_after: None,
        }
    }

    fn run(f: &TipFacts, p: &Policy, ev: &[Evidence]) -> Status {
        let ev: Vec<(String, Evidence)> = ev.iter().enumerate().map(|(i, e)| (format!("s{i}"), e.clone())).collect();
        evaluate(Some(f), p, &Network::TestNetwork, &ev, NOW)
    }

    #[test]
    fn two_confirmations_pass() {
        let st = run(&facts(100, 30), &policy(Some(100)), &[Evidence::Confirms { ahead: 0, verified: true }, Evidence::Confirms { ahead: 3, verified: true }]);
        assert!(st.ok(), "{st:?}");
        assert!(st.alarms.is_empty());
    }

    #[test]
    fn light_chain_fails_minimum_work() {
        let st = run(&facts(99, 30), &policy(Some(100)), &[Evidence::Confirms { ahead: 0, verified: true }, Evidence::Confirms { ahead: 0, verified: true }]);
        assert!(!st.ok() && st.failures[0].contains("below the minimum"), "{st:?}");
    }

    #[test]
    fn one_source_is_not_enough() {
        let st = run(
            &facts(100, 30),
            &policy(None),
            &[Evidence::Confirms { ahead: 0, verified: true }, Evidence::Unreachable("down".into()), Evidence::Disagrees],
        );
        assert!(!st.ok() && st.failures[0].contains("confirmed by 1 sources"), "{st:?}");
        assert_eq!(st.alarms.len(), 2);
    }

    #[test]
    fn heavier_fork_or_withheld_blocks_fail() {
        for e in [Evidence::HeavierFork { at: 4_525_990 }, Evidence::DeepFork { from: 4_525_800 }, Evidence::Confirms { ahead: 13, verified: true }] {
            let st = run(&facts(100, 30), &policy(None), &[Evidence::Confirms { ahead: 0, verified: true }, Evidence::Confirms { ahead: 0, verified: true }, e.clone()]);
            assert!(!st.ok(), "{e:?} should fail: {st:?}");
        }
    }

    #[test]
    fn an_unverified_height_claim_only_alarms() {
        let ok = Evidence::Confirms { ahead: 0, verified: true };
        let st = run(&facts(100, 30), &policy(None), &[ok.clone(), Evidence::Confirms { ahead: 5_000, verified: false }]);
        assert!(st.ok() && st.alarms[0].contains("reports 5000 more"), "{st:?}");
    }

    #[test]
    fn lighter_fork_and_lag_only_alarm() {
        let st = run(
            &facts(100, 30),
            &policy(None),
            &[Evidence::Confirms { ahead: 0, verified: true }, Evidence::Confirms { ahead: 12, verified: true }, Evidence::LighterFork { at: 4_525_999 }, Evidence::Behind { height: 4_525_900 }],
        );
        assert!(st.ok(), "{st:?}");
        assert_eq!(st.alarms.len(), 2);
    }

    #[test]
    fn stale_tip_alarms_after_the_spacing_bound() {
        // NU7 testnet: 25 s blocks, so about 230 s plus 120 s for clocks.
        let after = default_stale_after(&Network::TestNetwork, 4_526_000);
        assert_eq!(after, 350);
        assert_eq!(default_stale_after(&Network::MainNetwork, 3_000_000), 810);
        let ok = [Evidence::Confirms { ahead: 0, verified: true }, Evidence::Confirms { ahead: 0, verified: true }];
        assert!(run(&facts(100, after), &policy(None), &ok).alarms.is_empty());
        let st = run(&facts(100, after + 1), &policy(None), &ok);
        assert!(st.ok() && st.alarms[0].starts_with("STALE TIP"), "{st:?}");
    }
}
