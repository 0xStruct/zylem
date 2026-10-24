//! zylem-proxy: point a wallet's server URL here and every block it receives is
//! verified against block headers first.

mod chain;
mod filter;
mod service;
mod tip;

use std::{net::SocketAddr, sync::Arc, time::Duration};

use anyhow::{Context, Result};
use clap::Parser;
use tokio::sync::RwLock;
use tonic::transport::{ClientTlsConfig, Endpoint, Server};
use zcash_protocol::consensus::Network;
use zylem_proto::rpc::{compact_tx_streamer_client::CompactTxStreamerClient, compact_tx_streamer_server::CompactTxStreamerServer};

use chain::{Chain, Checkpoint, RingSource, RingView};
use service::{Mode, Proxy, Stats};

#[derive(Parser)]
#[command(name = "zylem-proxy", about = "A light-wallet server that serves only verified data")]
struct Args {
    /// Where to listen for wallets.
    #[arg(long, default_value = "127.0.0.1:9067")]
    listen: SocketAddr,
    /// Base URL of a Ring host (a zylem-build serve, a CDN or any mirror). Repeat for
    /// more hosts: every host's tail is verified and the one with the most work is served.
    #[arg(long, required = true)]
    rings: Vec<String>,
    /// JSON-RPC URL of a Zakura or zcashd node used as a header-only witness of the tip
    /// (credentials in the URL). Repeatable. Its headers are verified before they count.
    #[arg(long)]
    headers_rpc: Vec<String>,
    /// Independent sources (Ring hosts, header witnesses, the upstream server) that must
    /// confirm the served tip before strict mode presents it.
    #[arg(long, default_value_t = 2)]
    min_sources: usize,
    /// Verified blocks a source may have beyond the served tip before it counts as
    /// withholding (12 is five minutes at 25-second blocks).
    #[arg(long, default_value_t = 12)]
    max_behind: u64,
    /// Seconds without a new block before a stale-tip alarm (default: from the block
    /// spacing, about 6 minutes at 25-second blocks and 13 at 75).
    #[arg(long)]
    stale_after: Option<u64>,
    /// Upstream light-wallet server, for full transactions, transparent lookups and
    /// broadcast.
    #[arg(long)]
    upstream: String,
    #[arg(long, default_value = "test")]
    network: String,
    /// A block the verified chain must contain, as HEIGHT:HASH[:MINWORK] (display hex;
    /// minimum work after it in hex, from `zylem-build checkpoint`).
    #[arg(long)]
    checkpoint: Checkpoint,
    #[arg(long, value_enum, default_value_t = Mode::Strict)]
    mode: Mode,
    /// Skip Rings that end before this height.
    #[arg(long, default_value_t = 0)]
    from_height: u64,
    /// Seconds between manifest checks.
    #[arg(long, default_value_t = 15)]
    refresh: u64,
}

async fn upstream(url: &str) -> Result<CompactTxStreamerClient<tonic::transport::Channel>> {
    let mut ep = Endpoint::from_shared(url.to_string())?;
    if url.starts_with("https") {
        ep = ep.tls_config(ClientTlsConfig::new().with_webpki_roots())?;
    }
    Ok(CompactTxStreamerClient::new(ep.connect().await.with_context(|| format!("connect {url}"))?)
        .max_decoding_message_size(64 << 20))
}

/// Gathers every source's evidence about the served tip and applies the policy.
async fn assess(
    chain: &RwLock<Chain>,
    views: &[RingView],
    witnesses: &[tip::HeaderSource],
    up: &mut CompactTxStreamerClient<tonic::transport::Channel>,
    srcs: &[RingSource],
    policy: &tip::Policy,
    network: &Network,
) -> tip::Status {
    let c = chain.read().await;
    let mut evidence: Vec<(String, tip::Evidence)> =
        srcs.iter().zip(views).map(|(s, v)| (format!("Ring host {}", s.base), tip::ring_evidence(v, &c))).collect();
    for w in witnesses {
        evidence.push((format!("node {}", w.name()), tip::witness(w, &c, network, c.first).await));
    }
    evidence.push(("upstream".into(), tip::upstream_witness(up, &c).await));
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs());
    tip::evaluate(tip::TipFacts::of(&c, &policy.checkpoint).as_ref(), policy, network, &evidence, now)
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stdout()))
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();
    let args = Args::parse();
    let network = match args.network.as_str() {
        "main" | "mainnet" => Network::MainNetwork,
        _ => Network::TestNetwork,
    };
    let http = reqwest::Client::builder().timeout(Duration::from_secs(60)).build()?;
    let srcs: Vec<RingSource> = args.rings.iter().map(|r| RingSource { base: r.clone(), http: http.clone() }).collect();
    let witnesses: Vec<tip::HeaderSource> = args.headers_rpc.iter().map(|u| tip::HeaderSource::new(u)).collect();
    let mut chain = Chain::default();
    let started = std::time::Instant::now();
    // A host may rewrite its tail mid-fetch; try a few times before giving up.
    let mut views = vec![];
    for attempt in 0..4 {
        let (report, v) = chain::refresh(&mut chain, &srcs, &network, args.from_height).await;
        views = v;
        if let Some(r) = report {
            tracing::info!("{r} ({:.1} s)", started.elapsed().as_secs_f64());
        }
        if chain.tip().is_some() && views.iter().all(|v| matches!(v, RingView::Tip { .. })) || attempt == 3 {
            break;
        }
    }
    if chain.tip().is_none() {
        anyhow::bail!("no Ring host served a verifiable chain: {views:?}");
    }
    chain::check_checkpoint(&chain, &args.checkpoint)?;
    match args.checkpoint.min_work {
        Some(w) => tracing::info!("checkpoint {} matches; work after it {:x} meets the minimum {w:x}", args.checkpoint.height, chain.work_above(args.checkpoint.height)),
        None => tracing::warn!(target: "zylem", "checkpoint {} matches, but it carries no minimum work: a light fork would be accepted", args.checkpoint.height),
    }

    let policy = tip::Policy {
        checkpoint: args.checkpoint,
        min_sources: args.min_sources,
        max_behind: args.max_behind,
        stale_after: args.stale_after,
    };
    let chain = Arc::new(RwLock::new(chain));
    let status = Arc::new(RwLock::new(tip::Status::default()));
    let stats = Arc::new(Stats::default());
    let up = upstream(&args.upstream).await?;
    let mut up_w = up.clone();
    let first = assess(&chain, &views, &witnesses, &mut up_w, &srcs, &policy, &network).await;
    if first.ok() {
        tracing::info!(target: "zylem", "{}", first.summary());
    } else {
        tracing::warn!(target: "zylem", "{}", first.summary());
    }
    for a in &first.alarms {
        tracing::warn!(target: "zylem", "ALARM {a}");
    }
    *status.write().await = first;
    {
        let (chain, status, stats) = (chain.clone(), status.clone(), stats.clone());
        let every = Duration::from_secs(args.refresh);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(every).await;
                let views = {
                    let mut c = chain.write().await;
                    let (report, views) = chain::refresh(&mut c, &srcs, &network, args.from_height).await;
                    if let Some(r) = report {
                        tracing::info!("{r}");
                    }
                    views
                };
                let new = assess(&chain, &views, &witnesses, &mut up_w, &srcs, &policy, &network).await;
                let old = status.read().await.clone();
                if new.summary() != old.summary() {
                    if new.ok() {
                        tracing::info!(target: "zylem", "{}", new.summary());
                    } else {
                        tracing::warn!(target: "zylem", "{}", new.summary());
                    }
                }
                for a in new.alarms.iter().filter(|a| !old.alarms.contains(a)) {
                    tracing::warn!(target: "zylem", "ALARM {a}");
                }
                *status.write().await = new;
                use std::sync::atomic::Ordering::Relaxed;
                tracing::debug!(
                    "served {} blocks, {} rejected, audit {} checked / {} mismatched, {} unverifiable",
                    stats.blocks_served.load(Relaxed),
                    stats.rejected.load(Relaxed),
                    stats.audit_checked.load(Relaxed),
                    stats.audit_mismatches.load(Relaxed),
                    stats.unverifiable.load(Relaxed)
                );
            }
        });
    }
    let proxy = Proxy::new(chain, up, network, args.mode, stats.clone(), status);
    // Bind before announcing, so "serving" means wallets can connect.
    let listener = tokio::net::TcpListener::bind(args.listen).await?;
    tracing::info!("serving {:?} mode on {}", args.mode, args.listen);
    let server = Server::builder()
        .add_service(CompactTxStreamerServer::new(proxy).max_encoding_message_size(64 << 20))
        .serve_with_incoming_shutdown(tokio_stream::wrappers::TcpListenerStream::new(listener), async {
            let _ = tokio::signal::ctrl_c().await;
        });
    server.await?;
    use std::sync::atomic::Ordering::Relaxed;
    eprintln!(
        "zylem-proxy: served {} blocks, {} rejected, audit {} checked / {} mismatched, {} unverifiable calls",
        stats.blocks_served.load(Relaxed),
        stats.rejected.load(Relaxed),
        stats.audit_checked.load(Relaxed),
        stats.audit_mismatches.load(Relaxed),
        stats.unverifiable.load(Relaxed)
    );
    Ok(())
}
