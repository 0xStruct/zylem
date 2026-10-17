//! Light-wallet server client (lightwalletd or Zaino).

use anyhow::{Context, Result};
use tonic::transport::{Channel, ClientTlsConfig, Endpoint};
use zylem_proto::rpc::{
    compact_tx_streamer_client::CompactTxStreamerClient, BlockId, BlockRange, ChainSpec, CompactBlock,
    PoolType,
};

pub type Lwd = CompactTxStreamerClient<Channel>;

pub async fn connect(url: &str) -> Result<Lwd> {
    let mut ep = Endpoint::from_shared(url.to_string())?;
    if url.starts_with("https") {
        ep = ep.tls_config(ClientTlsConfig::new().with_webpki_roots())?;
    }
    let ch = ep.connect().await.with_context(|| format!("connect {url}"))?;
    Ok(CompactTxStreamerClient::new(ch).max_decoding_message_size(64 << 20))
}

pub async fn tip(lwd: &mut Lwd) -> Result<u64> {
    Ok(lwd.get_latest_block(ChainSpec {}).await?.into_inner().height)
}

/// Compact blocks for `[from, to]`, asking for every pool including transparent data.
pub async fn blocks(lwd: &mut Lwd, from: u64, to: u64) -> Result<Vec<CompactBlock>> {
    let range = BlockRange {
        start: Some(BlockId { height: from, hash: vec![] }),
        end: Some(BlockId { height: to, hash: vec![] }),
        pool_types: vec![
            PoolType::Transparent as i32,
            PoolType::Sapling as i32,
            PoolType::Orchard as i32,
            PoolType::Ironwood as i32,
        ],
    };
    let mut stream = lwd.get_block_range(range).await?.into_inner();
    let mut out = vec![];
    while let Some(b) = stream.message().await? {
        out.push(b);
    }
    Ok(out)
}

/// The server's tree state after `height` (legacy tree hex per pool).
pub async fn tree_state(lwd: &mut Lwd, height: u64) -> Result<[String; 3]> {
    let ts = lwd
        .get_tree_state(BlockId { height, hash: vec![] })
        .await?
        .into_inner();
    Ok([ts.sapling_tree, ts.orchard_tree, ts.ironwood_tree])
}
