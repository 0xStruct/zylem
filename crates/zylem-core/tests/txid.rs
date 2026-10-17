//! v4 transactions carry their full bytes; their compact form must match those bytes.

use zcash_primitives::transaction::Transaction;
use zcash_protocol::consensus::BranchId;
use zylem_core::{txid, Reject};

// Testnet block 280003, the librustzcash `tx_read_write` vector (Sapling, v4).
const V4_TX: &str = include_str!("data/v4_testnet_280003.hex");
const V4_TXID_DISPLAY: &str = "64f0bd7fe30ce23753358fe3a2dc835b8fba9c0274c4e2c54a6f73114cb55639";

fn v4() -> Transaction {
    Transaction::read(&hex::decode(V4_TX.trim()).unwrap()[..], BranchId::Sapling).unwrap()
}

#[test]
fn v4_txid_is_rebuilt_from_full_bytes() {
    let tx = v4();
    let ctx = txid::compact_from_tx(1, &tx);
    let aux = txid::aux_from_tx(&tx).unwrap();
    assert_eq!(aux.version, 4);
    assert!(!ctx.spends.is_empty() || !ctx.vout.is_empty());
    let id = txid::rebuild_txid(280_003, 1, &ctx, &aux, BranchId::Sapling).unwrap();
    let mut display = id;
    display.reverse();
    assert_eq!(hex::encode(display), V4_TXID_DISPLAY);
}

#[test]
fn v4_compact_data_cannot_be_swapped() {
    let tx = v4();
    let mut ctx = txid::compact_from_tx(1, &tx);
    let aux = txid::aux_from_tx(&tx).unwrap();
    // A server that keeps the honest full bytes but alters the compact data (to hide a
    // spend or a payment) is caught.
    if let Some(spend) = ctx.spends.first_mut() {
        spend.nf[0] ^= 1;
    } else {
        ctx.vout[0].value += 1;
    }
    assert_eq!(
        txid::rebuild_txid(280_003, 1, &ctx, &aux, BranchId::Sapling),
        Err(Reject::V4CompactMismatch { height: 280_003, index: 1 })
    );
}
