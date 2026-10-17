//! zylem-build: turns a node's chain into Zylem Rings, verifies them, and serves them.

mod builder;
mod lwd;
mod lwdcheck;
mod node;
mod serve;
mod spike;
mod tamper;

use anyhow::Result;
use clap::{Parser, Subcommand};
use zcash_protocol::consensus::Network;

#[derive(Parser)]
#[command(name = "zylem-build", about = "Build, verify and serve Zylem Rings")]
struct Cli {
    /// Network: test or main.
    #[arg(long, global = true, default_value = "test")]
    network: String,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Phase 0: rebuild every transaction ID in a range from compact data plus aux.
    Spike {
        #[arg(long)]
        rpc: String,
        #[arg(long)]
        from: u64,
        #[arg(long, default_value_t = 1000)]
        count: u64,
    },
    /// Phase 0: rebuild IDs from a light-wallet server's compact blocks plus Zylem aux.
    LwdCheck {
        #[arg(long)]
        rpc: String,
        #[arg(long)]
        lwd: String,
        #[arg(long)]
        from: u64,
        #[arg(long, default_value_t = 100)]
        count: u64,
    },
    /// Write every finished epoch's Ring and the open tail.
    Backfill {
        #[arg(long)]
        rpc: String,
        /// Light-wallet server, used once to bootstrap below a pruned node's prune height.
        #[arg(long)]
        lwd: Option<String>,
        #[arg(long)]
        out: std::path::PathBuf,
        #[arg(long, default_value_t = 4096)]
        epoch_length: u64,
        #[arg(long, default_value_t = 1000)]
        finality: u64,
        #[arg(long)]
        max_rings: Option<usize>,
    },
    /// Host a Ring directory over HTTP; with --rpc, keep building from the node.
    Serve {
        #[arg(long)]
        out: std::path::PathBuf,
        #[arg(long, default_value = "127.0.0.1:8090")]
        listen: std::net::SocketAddr,
        #[arg(long)]
        rpc: Option<String>,
        #[arg(long, default_value_t = 4096)]
        epoch_length: u64,
        #[arg(long, default_value_t = 1000)]
        finality: u64,
        #[arg(long, default_value_t = 30)]
        interval: u64,
    },
    /// Make a malicious copy of a Ring directory, for demonstrating rejections.
    Tamper {
        #[arg(long)]
        from: std::path::PathBuf,
        #[arg(long)]
        out: std::path::PathBuf,
        #[arg(long, value_enum)]
        attack: tamper::Attack,
        /// First block to consider.
        #[arg(long)]
        height: u64,
        /// Transaction index in that block (default: the first with Ironwood actions).
        #[arg(long)]
        tx_index: Option<usize>,
    },
    /// Cut a self-contained Ring out of a verified directory (for test fixtures).
    Slice {
        #[arg(long)]
        dir: std::path::PathBuf,
        #[arg(long)]
        from: u64,
        #[arg(long)]
        to: u64,
        #[arg(long)]
        out: std::path::PathBuf,
    },
    /// Verify every Ring in a directory, as a client would.
    Verify {
        dir: std::path::PathBuf,
    },
}

fn network(name: &str) -> Network {
    match name {
        "main" | "mainnet" => Network::MainNetwork,
        _ => Network::TestNetwork,
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let net = network(&cli.network);
    match cli.cmd {
        Cmd::Spike { rpc, from, count } => spike::run(&node::Node::new(&rpc), net, from, count).await,
        Cmd::Backfill { rpc, lwd, out, epoch_length, finality, max_rings } => {
            let b = builder::Builder { node: node::Node::new(&rpc), network: net, out, epoch_length, finality };
            b.step(lwd.as_deref(), max_rings).await.map(|_| ())
        }
        Cmd::Verify { dir } => builder::verify_dir(&dir, &net),
        Cmd::Slice { dir, from, to, out } => builder::slice_dir(&dir, &net, from, to, &out),
        Cmd::Serve { out, listen, rpc, epoch_length, finality, interval } => {
            let b = rpc.map(|r| builder::Builder { node: node::Node::new(&r), network: net, out: out.clone(), epoch_length, finality });
            serve::run(out, listen, b, std::time::Duration::from_secs(interval)).await
        }
        Cmd::Tamper { from, out, attack, height, tx_index } => tamper::run(&from, &out, attack, height, tx_index),
        Cmd::LwdCheck { rpc, lwd, from, count } => {
            lwdcheck::run(&node::Node::new(&rpc), &lwd, net, from, count).await
        }
    }
}
