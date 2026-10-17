//! zylem-proxy: point a wallet's server URL here and every block it receives is
//! verified against block headers first.

mod chain;
mod filter;
mod service;

use std::{net::SocketAddr, sync::Arc, time::Duration};

use anyhow::{Context, Result};
use clap::Parser;
use tokio::sync::RwLock;
use tonic::transport::{ClientTlsConfig, Endpoint, Server};
use zcash_protocol::consensus::Network;
use zylem_proto::rpc::{compact_tx_streamer_client::CompactTxStreamerClient, compact_tx_streamer_server::CompactTxStreamerServer};

use chain::{Chain, Checkpoint, RingSource};
use service::{Mode, Proxy, Stats};

#[derive(Parser)]
#[command(name = "zylem-proxy", about = "A light-wallet server that serves only verified data")]
struct Args {
    /// Where to listen for wallets.
    #[arg(long, default_value = "127.0.0.1:9067")]
    listen: SocketAddr,
    /// Base URL of a Ring host (a zylem-build serve, a CDN or any mirror).
    #[arg(long)]
    rings: String,
    /// Upstream light-wallet server, for full transactions, transparent lookups and
    /// broadcast.
    #[arg(long)]
    upstream: String,
    #[arg(long, default_value = "test")]
    network: String,
    /// A block the verified chain must contain, as HEIGHT:HASH (display hex).
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

/// Compares the verified tip with the upstream server's view: a verified tip far behind
/// means Ring hosts are stale or withholding; a different hash at the same height means
/// the two sources disagree about the chain.
async fn tip_check(up: &mut CompactTxStreamerClient<tonic::transport::Channel>, (height, hash): (u64, [u8; 32])) {
    let Ok(latest) = up.get_latest_block(zylem_proto::rpc::ChainSpec {}).await else { return };
    let theirs = latest.into_inner().height;
    // 40 blocks is about 17 minutes at 25-second blocks.
    if theirs > height + 40 {
        tracing::warn!(target: "zylem", "STALE TIP: verified tip {height}, upstream reports {theirs}");
    }
    let id = zylem_proto::rpc::BlockId { height, hash: vec![] };
    if let Ok(b) = up.get_block(id).await {
        if b.get_ref().hash != hash {
            tracing::warn!(target: "zylem", "TIP DISAGREEMENT at {height}: upstream has a different block");
        }
    }
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
    let src = RingSource { base: args.rings.clone(), http: reqwest::Client::new() };
    let mut chain = Chain::default();
    let started = std::time::Instant::now();
    // A host may rewrite its tail mid-fetch; try a few times before giving up.
    let mut attempt = 0;
    loop {
        match chain::refresh(&mut chain, &src, &network, args.from_height).await {
            Ok(Some(r)) => {
                tracing::info!("{r} ({:.1} s)", started.elapsed().as_secs_f64());
                break;
            }
            Ok(None) => anyhow::bail!("no Rings found at {}", args.rings),
            Err(e) if attempt < 3 && chain.tip().is_some() => {
                tracing::warn!("retrying after: {e:#}");
                attempt += 1;
            }
            // A source that fails verification is dropped; whatever verified before the
            // failure is still served, and the wallet sees the verified range end there.
            Err(e) if chain.tip().is_some() => {
                tracing::warn!(target: "zylem", "REJECT {e:#}");
                tracing::warn!("serving only the verified range up to {}", chain.tip().unwrap().header.height);
                break;
            }
            Err(e) => return Err(e),
        }
    }
    chain::check_checkpoint(&chain, &args.checkpoint)?;
    tracing::info!("checkpoint {} matches", args.checkpoint.height);

    let chain = Arc::new(RwLock::new(chain));
    let stats = Arc::new(Stats::default());
    let up = upstream(&args.upstream).await?;
    {
        let (chain, stats, mut up) = (chain.clone(), stats.clone(), up.clone());
        let every = Duration::from_secs(args.refresh);
        tokio::spawn(async move {
            loop {
                let mut c = chain.write().await;
                match chain::refresh(&mut c, &src, &network, args.from_height).await {
                    Ok(Some(r)) => tracing::info!("{r}"),
                    Ok(None) => {}
                    Err(e) => tracing::warn!(target: "zylem", "REJECT refresh: {e:#}"),
                }
                let tip = c.tip().map(|b| (b.header.height, b.header.hash));
                drop(c);
                if let Some(tip) = tip {
                    tip_check(&mut up, tip).await;
                }
                tokio::time::sleep(every).await;
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
    let proxy = Proxy::new(chain, up, network, args.mode, stats.clone());
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
