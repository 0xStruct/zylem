# Phase 0: spikes and measurements

Measured on 2026-10-21 against a pruned Zakura 1.6.0 testnet node, the public testnet
light-wallet server `testnet.zec.rocks`, and Blockchair's mainnet index.

## The transaction-ID rebuild works

`zylem-build spike --from 4520000 --count 1000` takes each block, splits every
transaction into its compact form plus aux digests, rebuilds the ID from those alone,
and compares it with librustzcash's ID and with the header's Merkle root.

| Check | Result |
|---|---|
| Blocks | 1,000 (heights 4,520,000 to 4,520,999) |
| Transactions | 2,298 (865 v5, 1,433 v6, 0 v4) |
| IDs rebuilt from compact data + aux that match librustzcash | 2,298 / 2,298 |
| Merkle roots matched | 1,000 / 1,000 |

`zylem-build lwd-check` repeats the rebuild with the compact blocks a real server sends
(`testnet.zec.rocks`, 50 blocks from 4,522,900): its compact transactions are identical
to Zylem's (0 differences), and 64 / 64 IDs rebuild from the server's compact data plus
Zylem aux. Its compact blocks carry no full header, so proof-of-work checks need headers
from a Zylem host or a node.

v4 has no compact split: Rings carry v4 transactions in full, and the verifier checks
that the compact data it was given matches those bytes (`tests/txid.rs`, on the
testnet block 280,003 vector).

## The Ironwood history-tree layout matches

`zylem-build backfill` replays the ZIP 221 history tree from NU7 activation (4,465,026)
with V3 (Ironwood) nodes: 28,672 leaves built from headers, note commitment roots and
per-pool transaction counts. The resulting root matches the block commitments in header
4,493,698, and the replayed frontiers match the node's `z_gettreestate`.

## Sizes

| Measure | Value |
|---|---|
| Header | 1,487 B per block |
| Compact transaction (all pools) | 252 B average |
| Aux digests, v5/v6 | 94 B per transaction |
| Ring, before compression | 2,410 B per block (9.9 MB per 4,096-block epoch) |
| Ring file, zstd level 9 | 7.1 to 8.2 MB per 4,096-block epoch (testnet) |
| Raw blocks, for comparison | 10,581 B per block |
| Header volume | 1.7 MB/day at 75 s blocks, 5.1 MB/day at 25 s |

Headers are the largest single part of a Ring on today's testnet.

## Mainnet v4 volume since NU5

From Blockchair's mainnet index, heights 1,687,104 onward (2026-10-21):

| Version | Transactions | Bytes |
|---|---|---|
| v4 | 4,125,493 | 6.0 GB |
| v5 | 3,517,102 | 232.3 GB |
| v6 | 448,808 | 4.5 GB |

Keeping v4 adds about 6 GB of full transaction bytes to mainnet Rings, about 2.5% of the
raw chain bytes since NU5. Since Ironwood activation (3,428,143): 185,894 v4
transactions, 124 MB. Measured from an indexer, not an archive node.
