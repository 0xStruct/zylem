# Phase 2 demo: an unmodified wallet, one URL change

`scripts/demo.sh` runs an unmodified `zcash-devtool` (zcash/zcash-devtool at 0b3436b)
against `zylem-proxy` on testnet. Run on 2026-10-21; output below is from that run,
trimmed to the lines that matter.

The victim payment is a real one: the cooperative close of a zdlc contract,
transaction 4 of block 4,521,980 (`0f662f85…a64eb`), which paid two Ironwood outputs.

## 1. Honest Rings: the wallet syncs to the tip

The proxy loads 7 sealed Rings and the open tail (29,513 blocks) and verifies them in
about 9 s, then serves the wallet.

```
Scan complete for range ChainTip(4510000..4520000); progress is 61/611
Scan complete for range ChainTip(4520000..4523265); progress is 87/87
```

Subtree roots for all three pools (6 Sapling, 3 Orchard, 8 Ironwood) come from the
proxy; the ones completed before the first Ring are checked against the verified
starting frontier.

## 2. Malicious Ring hosts: each attack is rejected

Each host publishes a tampered Ring with a manifest that matches it, so only
verification can catch it. The proxy rejects the Ring, keeps serving the verified range
before it, and warns that its tip is behind the network. The wallet syncs to the last
verified block and never sees the altered data.

**Fake incoming note** (an extra Ironwood action in the payment transaction):

```
REJECT Ring 4518274..=4522369 rejected: transaction 4 at height 4521980: rebuilt ID does not match
serving only the verified range up to 4518273
STALE TIP: verified tip 4518273, upstream reports 4523266
Latest block height is 4518273
```

**Hidden payment** (the payment transaction left out of its block):

```
REJECT Ring 4518274..=4522369 rejected: Merkle root mismatch at height 4521980
serving only the verified range up to 4518273
STALE TIP: verified tip 4518273, upstream reports 4523267
```

**Wrong tree state** (the Ring's starting Ironwood frontier replaced, same size):

```
REJECT Ring 4518274..=4522369 rejected: Ironwood note commitment tree root mismatch at height 4518273
serving only the verified range up to 4518273
STALE TIP: verified tip 4518273, upstream reports 4523268
```

## 3. Audit mode: a public server, checked block by block

In audit mode the wallet syncs from `testnet.zec.rocks` through the proxy, which compares
every block it relays with the verified Rings.

```
AUDIT 13270 blocks checked so far, 0 mismatches, 1 outside the verified range
Scan complete for range ChainTip(4520000..4523269); progress is 87/87
```

(The one block outside the range is the server's newest block, ahead of the Ring tail.)

## Offline

`cargo test -p zylem-core` repeats every attack on a committed 7-block Ring around the
same payment, plus a bad Equihash solution, a reordered block, a forged per-block tree
root (caught by the history tree), a duplicated transaction and the v4 path.

## Reproduce

```bash
cargo build --release
# Rings in data/testnet (zylem-build backfill), then:
DEVTOOL=/path/to/zcash-devtool ./scripts/demo.sh
```
