//! Prints the Succinct Prover Network's current market price per prover gas unit (PGU).
//! A read-only query: the client is built with a random throwaway key that is never
//! funded or registered.

use anyhow::Result;
use sp1_sdk::network::{signer::NetworkSigner, NetworkClient, NetworkMode};

#[tokio::main]
async fn main() -> Result<()> {
    let key: [u8; 32] = rand::random();
    let signer = NetworkSigner::local(&hex::encode(key))?;
    let client = NetworkClient::new(signer, "https://rpc.mainnet.succinct.xyz", NetworkMode::Mainnet);
    let price = client.get_market_price_per_pgu().await?;
    // PROVE has 18 decimals; quote per billion PGU.
    let prove_per_bpgu = price.wei as f64 * 1e9 / 1e18;
    println!("market price: {} PROVE-wei per PGU = {prove_per_bpgu:.6} PROVE per billion PGU (as of unix {})", price.wei, price.as_of);
    Ok(())
}
