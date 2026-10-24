# Phase 3: header rules, checked against Zakura and the real chain

Run on 2026-10-22 against the testnet Zakura 1.6.0 node and the Zakura crates
(`zakura-chain` 9.0.0, `zakura-header-chain` 4.0.0).

## One copy of the header rules

The difficulty adjustment rule, median time past, the 90-minute limit, work, Equihash
and the header encoding now live in `crates/zylem-header`. `zylem-core` uses it for every
Ring header and the zkVM programs in `spikes/header-proof` use the same crate, so the
native verifier and the proofs cannot drift apart.

- `zylem-core` checks the difficulty and time rules for each header once it knows enough
  predecessors (28 before NU7, 113 from NU7), carrying them from one Ring to the next.
- `zylem-proxy` refuses to start unless every header after its checkpoint passed them.
  Headers up to the checkpoint are authenticated by hash links back from it.
- All 29,571 testnet Ring blocks verify with the rules checked from 4,493,811 (113 after
  the first Ring's start).

## Replay of the real testnet chain

`zylem-build replay-headers` streams headers from a node and checks each one: link,
encoding, Equihash, target, difficulty rule, median time past, 90-minute limit.

```bash
zylem-build --network test replay-headers --rpc http://127.0.0.1:18292/ --from 2976000 \
    --checkpoints <zakura-chain>/src/parameters/checkpoint/test-checkpoints.txt \
    --out data/replay/testnet-from-nu6.bin
```

| | |
|---|---|
| Headers checked | 1,550,559 (2,976,000 to the tip at 4,526,558) |
| Upgrades crossed | NU6, NU6.1, NU6.2, NU6.3 (Ironwood), NU7 (17- to 102-block window, 75 s to 25 s) |
| Minimum-difficulty blocks | 10,158 |
| Block hashes against Zakura's checkpoint list | 2,619 of 2,619 in range match |
| Failures | none |
| Time | 1,434 s on an M2 Pro over an SSH tunnel (1,081 headers/s, Equihash on every core), 25 MB of memory |

## Differential tests against Zakura

`testing/zakura-diff` is its own workspace: Zakura's forked Zcash crates
(`zakura-primitives`, `zakura-equihash`, ...) pin pre-releases that cannot share a
lockfile with Zylem's librustzcash pre-releases, so the transaction-ID comparison goes
through a file written by `zylem-build verify --txids`.

```bash
cd testing/zakura-diff
cargo test --test difficulty                                   # no node needed
ZYLEM_RPC=http://127.0.0.1:18292/ cargo test --test equihash --test txid
cargo test --test replay                                       # needs the replay file
```

| Test | Cases | Result |
|---|---|---|
| Difficulty and time rules, random and boundary contexts | 200,000 a network (mainnet, testnet), each with the expected and a wrong `nBits`; heights near Blossom, the testnet minimum-difficulty and 90-minute rule starts, NU7, and low heights | same expected `nBits` and verdict on every case |
| Every replayed testnet header | 1,550,559 | both accept each and expect its `nBits` |
| Equihash and header encoding | 1,200 real headers around NU6, NU6.3, NU7 and recent; 4,800 with one byte changed in the Equihash input, nonce, solution length or solution | same verdict on all |
| Transaction IDs, block hashes, auth data roots | 27,685 blocks (4,495,584 to 4,523,268, everything above the node's prune height), 46,542 transactions (13,069 v5, 33,473 v6) | Zylem's IDs rebuilt from compact data and aux equal Zakura's from full blocks |

## What the differential tests found

1. **Header encoding (a soundness bug in the proofs).** The shared rule checked that a
   header is 1,487 bytes but not the 3 bytes encoding the solution length, which
   consensus fixes as `fd 40 05`. Those bytes enter the block hash but not Equihash's
   input, so a prover could solve Equihash once and grind them (2^24 values) for a hash
   below the target, mining with SHA-256 instead of Equihash. `zylem-core` was not
   affected (it parses the header with `zcash_primitives` first); the zkVM leaf was.
   Fixed: `check_encoding`, applied to every header with or without Equihash.
2. **The 90-minute rule at mainnet height 1.** Zakura enforces it from height 2 on
   mainnet; the port enforced it from height 1, which would reject mainnet block 1.
   Fixed.

## Not covered yet

- Mainnet: no mainnet node yet; the replay needs one (a pruned Zakura keeps headers).
  Zakura 1.6.0 sets no mainnet NU7 height.
- v4 transaction IDs against Zakura: the compared range has none. The fixture test in
  `zylem-core` covers one v4 transaction.
- History tree and subtree roots against Zakura: Zakura rebuilds the history tree from
  the upgrade's activation, which needs every block's roots since then; the Rings start
  later. The real chain already checks both (every header's commitment, every Ring's
  tree roots).
- Tip policy: done after this phase's first part, see [tip-policy.md](tip-policy.md).
