# Build Rings, prove them, verify them

Three jobs, each runnable by anyone, none trusted by the clients that use the result:
build **Rings** from a Zcash node, **prove** their headers in SP1, and **verify** both in
a wallet, a browser or a contract. Testnet commands; mainnet takes `--network main`.

## 1. Build Rings

A Ring is one file of 4,096 consecutive blocks (about a day of the chain): every header,
every transaction in the compact form wallets download, short digests that rebuild each
transaction ID, and the state the Ring starts from. Rings are cut from an upgrade's
activation height, sealed once their last block is 100 deep, and named by their hash. Two
builders of the same chain produce byte-identical files.

Needs: Rust (the version in `rust-toolchain.toml`) and a Zakura or zcashd node's JSON-RPC.
A pruned Zakura node works; the first build bootstraps the history tree once from a
light-wallet server for blocks the node has pruned.

```bash
cargo build --release

# Every sealed Ring plus the open tail, into data/testnet (resumes where it left off).
./target/release/zylem-build backfill --rpc http://127.0.0.1:18232/ \
    --lwd https://testnet.zec.rocks:443 --out data/testnet --finality 100

# Check every Ring the way a client does.
./target/release/zylem-build verify data/testnet

# Host them over HTTP, and keep building new Rings as blocks arrive.
./target/release/zylem-build serve --out data/testnet --rpc http://127.0.0.1:18232/ --finality 100
```

Rings are plain files: `data/testnet/manifest.json` and `data/testnet/rings/*.zst` can go
on any static host or CDN.

A checkpoint is the one block a client trusts to start from, shipped with the minimum work
the chain after it must carry (`checkpoints/testnet.json` was made this way):

```bash
./target/release/zylem-build checkpoint --rpc http://127.0.0.1:18232/ --height 4500000 \
    --out checkpoints/testnet.json
```

## 2. Prove the headers in SP1

A history proof states that every header in a range passed Equihash, its target, the link
to the one before and the difficulty rules, and commits to a 104-byte record of every
block (hash, Merkle root, block commitments, time, bits). It is built from leaves of 512
headers, proved independently and joined pairwise, so it stays the same size however many
blocks it covers. Code: `spikes/header-proof/sp1` (programs and provers),
`crates/zylem-header` (the rules, shared with the native client).

Needs: SP1 6.9.0 (`sp1up`), `protoc` in `PROTOC`, and for real proofs an NVIDIA GPU with
about 26 GB of memory (an RTX 5090 proves a 512-header leaf with Equihash in about 5 min).

```bash
# Cut the chain into proving jobs: leaves of 512 headers from NU7's activation, in 4 shards.
./target/release/zylem-build jobs --rpc http://127.0.0.1:18232/ \
    --activation 4465026 --shards 4 --out data/jobs/nu7

# Pack the code and one archive per shard for GPU machines.
spikes/header-proof/pipeline/pack.sh data/jobs/nu7
```

On each GPU machine (Ubuntu with CUDA 12.8 or later), unpack the code and its shard's jobs
into `~/jobs`, then:

```bash
zylem/spikes/header-proof/pipeline/setup.sh        # builds the prover, or reuses prebuilt binaries
zylem/spikes/header-proof/pipeline/run-shard.sh 0  # proves shard 0's leaves and joins them
```

Then join the shards in order into the history proof, and wrap it in Groth16 for contracts:

```bash
# With every shard's shard-N.proof and .done copied into ~/out:
zylem/spikes/header-proof/pipeline/join.sh ~/out ~/out/shard-0.proof ~/out/shard-1.proof ~/out/shard-2.proof ~/out/shard-3.proof --groth16
```

Every step is safe to rerun: finished proofs have a `.done` file and are skipped, and each
leaf's claim must equal the one computed natively, or the prover stops.

**Generation 1 (registry).** Programs frozen in `programs/testnet/` and listed in its
`registry.json` let different machines and builds make joinable proofs, and let a client
pin one registry root instead of program keys. Set `PROGRAMS=programs/testnet` before
`run-shard.sh` and `join.sh`, or run `prove leaves|aggregate|join programs/testnet …`
directly. `programs freeze` and `programs revoke` manage the registry
(`spikes/header-proof/README.md`, "Generation 1").

**Locally, without a GPU:** `SP1_PROVER=mock` runs the same flow and checks every claim
without making proofs; `SP1_PROVER=cpu` makes real proofs of short leaves.

### Publish

```bash
(cd spikes/header-proof/sp1 && cargo build --release --bin export-proof)
spikes/header-proof/sp1/target/release/export-proof ~/out/history.proof data/proofs/history
./target/release/zylem-build publish --jobs data/jobs/nu7 --history data/proofs/history \
    --vks ~/out/vks.json --rings data/testnet --groth16 ~/out/history.groth16.bytes \
    --out data/publish/nu7
```

(`--registry programs/testnet` instead of `--vks` for generation 1.) The output holds
`history.json`, the proof and its public values, every block's record, the Rings, and for
each Ring inside the proven range the few hashes that bind it to the proof.

## 3. Verify

### In a wallet today: `zylem-proxy`

A drop-in light-wallet server. It checks every Ring from the checkpoint and serves only
verified data over the standard light-wallet protocol, so an unmodified wallet switches by
changing its server address.

```bash
./target/release/zylem-proxy --rings http://127.0.0.1:8090 \
    --headers-rpc http://user:pass@127.0.0.1:18232/ \
    --upstream https://testnet.zec.rocks:443 \
    --checkpoint "$(jq -r .checkpoint checkpoints/testnet.json)"
zcash-devtool wallet -w my-wallet sync --server 127.0.0.1:9067
```

### In a browser or a phone: the WebAssembly client

`spikes/header-proof/wasm-verify` compiles `zylem-core` and the proof verifiers to
WebAssembly (1.8 MB). It needs `wasm-pack` and LLVM's clang for one C dependency
(`brew install llvm`; the path is in its `.cargo/config.toml`).

```bash
cd spikes/header-proof/wasm-verify
wasm-pack build --release --target web --out-dir pkg-web       # browsers
wasm-pack build --release --target nodejs --out-dir pkg-node   # Node
```

| Call | Checks |
|---|---|
| `new RingFile(bytes)`, then `.verify()` | the full client check of one Ring: Equihash, transaction IDs against Merkle roots, the history tree, note trees |
| `.records(from, to)`, `.find_tx(id)`, `.block(h)` | a Ring's block records, a transaction by ID, one block in detail |
| `verify_history(proof, publicValues, aggKey, trusted)` | a 1.27 MB history proof (generation 0), pinned to both program keys and a starting block |
| `verify_history_v2(proof, publicValues, registry, pinnedRoots, trusted)` | the same for generation 1, pinned to registry roots |
| `check_all_records(publicValues, records)`, `verify_binding(…)`, `check_range(…)` | that a Ring's blocks are the ones a proof commits to |
| `verify_groth16(proof, publicValues, programKey)` | the 356-byte Groth16 wrap |

`demo/index.html` uses all of these; `demo/stage.py` and `web/build.py` stage it with real
Rings and proofs.

### In a contract: SP1's Groth16 verifier

The 356-byte wrap verifies with SP1's own verifier contract for circuit v6.1.0 (SP1 6.9.0):
`SP1VerifierGroth16.sol` from
[succinctlabs/sp1-contracts](https://github.com/succinctlabs/sp1-contracts),
`contracts/src/v6.1.0/`. Call `verifyProof(programKey, publicValues, proofBytes)` with
Zylem's aggregation program key; the public values are the claim, which
`ZylemClaim.sol` reads.

```bash
cd spikes/header-proof/onchain && forge test -vv
```

Locally with Foundry: 303,762 gas to verify, 334,361 for an example contract that verifies,
reads the claim and stores the proven block hash. Not deployed on any chain yet; a
production contract also needs a freshness rule and links between submitted ranges
(`spikes/header-proof/onchain/README.md`).

### What each path trusts

| Path | Trusts |
|---|---|
| Rings checked directly (proxy, `RingFile.verify`) | the cryptography, a checkpoint, honest-majority hashpower |
| Rings plus a history proof | also SP1 and Zylem's proving programs (pinned keys or a registry root) |
| The 356-byte wrap (phones, contracts) | also SP1's Groth16 trusted setup |

Program keys in use: generation 0 aggregation
`0x007d30f107c4bc577316a24437873fdcd918cbc9319ed6307a19584f876f34cb`, leaf
`0x00b1908cf2c698b3359c2d34dbe0c2d2ba824ba4cc88e478e81fee0485b8daa0`; generation 1 in
`programs/testnet/registry.json`.
