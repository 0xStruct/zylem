# Zylem

Zylem checks everything a Zcash light wallet receives against what consensus committed
to in block headers, so the server it syncs from no longer has to be trusted.

A light-wallet server today can show a payment that never happened, hide one that did,
or hand out wrong note commitment tree states, and the wallet cannot tell. Zylem rebuilds
every transaction ID from the compact data wallets already receive plus a few hundred
bytes of auxiliary digests (ZIP 244 / ZIP 229 split each ID into a compact part and the
rest), matches them to the header's Merkle root, and replays the ZIP 221 history tree to
authenticate every block's note commitment roots.

History travels as **Rings**: one file per 4,096-block epoch that anyone can host,
because every block inside is re-verified. `zylem-proxy` speaks the standard
light-wallet protocol, so an unmodified wallet switches by changing one server URL.

## Status

Phases 0 to 2 of the [phase plan](https://claude.ai/code/artifact/69b2d462-7d97-4b9a-8861-7403b1b3468f)
run end to end on testnet (NU7, Ironwood):

- 29,500 testnet blocks and 49,000 transactions in 8 Rings, verified by a client in
  about 9 seconds.
- An unmodified `zcash-devtool` wallet syncs through `zylem-proxy` from Rings.
- A fake note, a hidden payment and a wrong tree state are each rejected with a typed
  error; the wallet never sees them.
- Two independent builds produce byte-identical Rings.

Numbers: [docs/phase0.md](docs/phase0.md). Demo: [docs/demo.md](docs/demo.md).

## Crates

| Crate | What it does |
|---|---|
| `zylem-core` | Pure verification: headers (Equihash, target, chain work), transaction-ID rebuild for v4/v5/v6, Merkle roots (rejecting duplicate IDs), the history-tree replay, note commitment trees, Ring encoding and checks |
| `zylem-proto` | The light-wallet protocol (with server stubs) and the Ring format, compiled without `protoc` |
| `zylem-build` | Builds Rings from a pruned Zakura node, verifies them, serves them over HTTP; also the Phase 0 spikes and a `tamper` tool for demos |
| `zylem-proxy` | A `CompactTxStreamer` server that serves only verified blocks, tree states and subtree roots, checks what it relays from an upstream server, and has an audit mode |

## Trust model

The client trusts a checkpoint (a block hash it must find in the verified chain) and
the cryptography. Ring hosts, mirrors and upstream servers are untrusted for integrity.

Checked: proof of work and each header's own target; that every transaction ID in a
block is rebuilt from the data served and produces the header's Merkle root; the
history tree against every next header; the Ring's note commitments against the
authenticated roots, which authenticates every tree state; subtree roots older than the
first Ring against the verified frontier; full transactions fetched upstream against
their block.

Not checked yet: the difficulty adjustment rule (an attacker who eclipses every source
needs no hashpower until Phase 3), the mempool, and the completeness of transparent
address lookups. Query privacy (OHTTP, YPIR) is v1 and later.

## Quick start (testnet)

```bash
# 1. Build Rings from a node (a pruned Zakura works; the first run bootstraps the
#    history tree from a light-wallet server for blocks the node pruned).
cargo build --release
./target/release/zylem-build backfill --rpc http://127.0.0.1:18232/ \
    --lwd https://testnet.zec.rocks:443 --out data/testnet --finality 100

# 2. Check them as a client would.
./target/release/zylem-build verify data/testnet

# 3. Host them, and keep the open tail current.
./target/release/zylem-build serve --out data/testnet --rpc http://127.0.0.1:18232/ --finality 100

# 4. Run the proxy and point a wallet at it.
./target/release/zylem-proxy --rings http://127.0.0.1:8090 \
    --upstream https://testnet.zec.rocks:443 \
    --checkpoint 4500000:0000252837996ac6566d67241e6aa7916a6ba5ddcc46458b9682fc0e97860d71
zcash-devtool wallet -w my-wallet sync --server 127.0.0.1:9067
```

`scripts/demo.sh` runs the whole demo (honest sync, three attacks, audit mode).
