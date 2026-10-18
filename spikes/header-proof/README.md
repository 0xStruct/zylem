# Header-proof spike (RISC Zero)

Can a zkVM prove Zcash's header chain cheaply enough to drop the 1,487-byte header from
every Ring block? This spike proves runs of real testnet headers from Zylem's Rings in
RISC Zero 3.0.6 and measures the cost. Run on 2026-10-21 on an Apple M2 Pro (10 cores,
16 GB), CPU proving only.

## What the guest proves

For each header (`core/src/lib.rs`, shared by the guest and the native validator):

- it links to the previous header (`hashPrevBlock`);
- its double-SHA-256 hash meets its own target, which is no easier than PoWLimit;
- its `nBits` equals the difficulty adjustment rule's result, copied from Zakura's
  `adjusted_difficulty.rs`: NU7's 102-block window and 25-second spacing, damping and
  bounds, and the testnet minimum-difficulty rule (ZIPs 205, 208, 218);
- its time is after the median of the previous 11 and at most 90 minutes past it;
- its work is added to the total;
- optionally, its Equihash (200, 9) solution is valid.

Each header yields a 104-byte record (hash, Merkle root, block commitments, time,
bits). The proof publishes the start anchor and context, the end hash and context, the
total work, and a SHA-256 over the records, so proofs chain and a client can check a
Ring's records against them instead of downloading headers.

## Results

**Correctness.** The same code run natively over every header in the Rings: 29,458 of
29,458 testnet headers pass (heights 4,493,811 to 4,523,268), including one testnet
minimum-difficulty block, so the ported difficulty rule reproduces the chain exactly.
The guest's published output equals the native run's for every measured batch.

**Cycles per header** (marginal, from batches of 10 and 100 headers):

| | Cycles per header | Per 4,096-block Ring |
|---|---|---|
| Without Equihash | 68,790 | 0.28 billion |
| With Equihash | 5,442,293 | 22.3 billion |

Equihash is 98.7% of the per-header cost: RISC Zero accelerates SHA-256 but not
BLAKE2b, so Equihash's 512 BLAKE2b hashes run in software.

The first version cost 2.62M cycles per header without Equihash. The difficulty rule's
mean target did 204 full 256-bit divisions per header (Zakura divides each target
separately to stay within 256 bits). Summing in 512 bits and dividing once by the small
window size gives the same number in 1/38 of the cycles.

**Proving** 100 headers (heights 4,494,811 to 4,494,910), no Equihash, CPU only, to one
succinct receipt:

| Measure | Result |
|---|---|
| User cycles | 6,938,396 (7,864,320 with segment padding, 8 segments) |
| Time | 1,196 s on the M2 Pro's CPU, receipt verified |
| Receipt seal | 222,668 B (succinct; constant size however many headers it covers) |
| Journal | 792 B (risc0 serde stores each byte as a 32-bit word; packable to about 230 B) |

That is about 6,600 cycles a second including compression, too slow for CPU proving to
keep up: one 4,096-block Ring would take about 12 hours here. Metal (not installed:
`xcodebuild -downloadComponent MetalToolchain`) and NVIDIA GPUs are the realistic
targets; neither was measured.

## What it means for Zylem

| Per 4,096-block Ring | Today | With a header proof |
|---|---|---|
| Header data | 6.1 MB of headers | 426 KB of records plus one 217 KB receipt |
| Ring file (measured on the first three testnet Rings, `cargo run --bin slim`) | 7.1 / 8.2 / 7.1 MB | 1.75 / 2.86 / 1.81 MB including the receipt: 2.9 to 4.0 times smaller |

1. **The header chain without Equihash is cheap to prove:** 0.28 billion cycles per
   Ring, 87 billion for a year of NU7 blocks.
2. **Equihash in the proof is 80 times the cost.** Options: keep Equihash outside the
   proof and check a random sample of full headers chosen from the proof's output (as
   FlyClient does), or write a BLAKE2b precompile (RISC Zero supports
   application-defined precompiles).
3. **Proving needs a GPU or a proving service.** CPU proving is 12 hours per Ring.
4. **Receipts stay 217 KB however much they cover,** so a chain of Ring proofs folded
   into one is still 217 KB; a Groth16 wrap (needs an x86 machine with Docker) brings it
   to a few hundred bytes for mobile.

## Next steps

1. Measure proving on a GPU (Metal toolchain, or an NVIDIA machine).
2. Chain proofs: each Ring's guest verifies the previous Ring's receipt.
3. Equihash sampling: derive sample positions from the proof's output and check those
   headers in full natively.
4. Pack the journal into bytes, add mainnet parameters, and test across the NU7
   activation window change.

## Run

```bash
cargo run --release -p zylem-hdr-validate -- ../../data/testnet   # native, all headers
cargo run --release -p zylem-hdr-host -- ../../data/testnet       # cycles
cargo run --release -p zylem-hdr-host -- ../../data/testnet --prove 100
```

## SP1 comparison

`sp1/` runs the same rules crate (`core/`) in SP1 6.9.0, on the same 100 testnet
headers from height 4,494,811, with SP1's patched SHA-256. Its output equals the native
run's for every batch. Measured on the same M2 Pro, CPU only:

| | RISC Zero 3.0.6 | SP1 6.9.0 |
|---|---|---|
| Per header, no Equihash | 68,790 cycles | 29,592 instructions / 41,301 prover gas |
| Per header, with Equihash | 5,442,293 cycles | 3,975,314 instructions / 3,515,391 prover gas |
| Prove 100 headers, no Equihash | 1,196 s | 146 s |
| Peak memory for that proof | about 2.2 GB (r0vm) | 7.1 GB |
| Proof | 222,668 B succinct seal | 1,272,782 B saved compressed proof (includes public values and metadata) |

Cycles, instructions and prover gas are different units, so compare proving time and
price, not the counts. Equihash costs fewer instructions in SP1, plausibly because it
runs 64-bit RISC-V and BLAKE2b is 64-bit arithmetic; RISC Zero runs 32-bit. Neither
zkVM has a BLAKE2b precompile.

**Cost per 4,096-block Ring**, from the measured counts and each network's price:

| | RISC Zero on Boundless ($0.17–0.30 per billion cycles, explorer snapshot, undated) | SP1 on the Succinct network ($0.120 per billion prover gas, live market price 2026-10-21: 0.633 PROVE per billion at $0.189) |
|---|---|---|
| No Equihash | $0.05–0.08 | $0.02 |
| With Equihash | $3.79–6.69 | $1.73 |
| One day of NU7 mainnet with Equihash (3,456 blocks) | $3.20–5.64 | $1.46 |
| All history since NU5 with Equihash (about 1.84M blocks) | about $1,700–3,000 | about $780 |

SP1 figures exclude the network's per-request base fee, which I did not find
published. `cargo run --release -p zylem-hdr-sp1 --bin market` prints the current price.

Run (needs `sp1up`, and `protoc` on the PATH or in `PROTOC`):

```bash
cd sp1
cargo run --release -p zylem-hdr-sp1 -- ../../../data/testnet               # counts
cargo run --release -p zylem-hdr-sp1 -- ../../../data/testnet --prove 100   # proof
cargo run --release -p zylem-hdr-sp1 --bin market                           # price
```

## Proof chaining in SP1

`sp1/link` is one link of a chain: it reads its own verification-key digest, the
previous link's published state (empty for the first link) and a segment of headers. It
verifies the previous link's compressed proof inside the zkVM with `verify_sp1_proof`,
which binds that proof to this program's key and to exactly those state bytes, checks
the new headers continue from that state (last hash, next height, difficulty context),
proves them, and publishes the extended 245-byte state (`ChainState` in `core/`): key
digest, checkpoint, last height and hash, total work, end context, a hash chained over
every segment's records, and the segment count. A client accepts the newest proof if it
verifies, its key digest is the program the client trusts, and its checkpoint is a block
the client trusts.

Two linked segments of 100 headers each (heights 4,494,811 to 4,495,010), M2 Pro CPU:

| | Link 1 (starts at the checkpoint) | Link 2 (verifies link 1) |
|---|---|---|
| Instructions | 2,996,580 | 4,253,330 |
| Proving time, compressed | 134.1 s | 193.9 s |
| Saved proof | 1,272,814 B | 1,272,814 B |

The proof does not grow: two links are the same size as one. Verifying the previous
link added 59.7 s of proving on this CPU; that cost is per link, not per header, so on
4,096-header segments it is small next to the headers themselves.

Broken links (`cargo run --release -p zylem-hdr-sp1 --bin chain -- --broken-only`):

| Attempt | Result |
|---|---|
| Next segment skips a block | guest exits with code 1 |
| Link claims a different program key | guest exits with code 1 |
| Previous state altered (inflated work) | executes, but proving fails: no proof matches the altered state |

A guest that panics ends with a non-zero exit code rather than an error, so a client
must require exit code 0 (SP1's `verify` does by default), and SP1's recursion asserts
that any proof verified inside a link exited with code 0 (`sp1-recursion-circuit`
`machine/deferred.rs`). Execution alone does not check proofs passed into a link; only
proving does.

```bash
cd sp1
cargo run --release -p zylem-hdr-sp1 --bin chain -- ../../../data/testnet               # two links
cargo run --release -p zylem-hdr-sp1 --bin chain -- ../../../data/testnet --broken-only # rejections
```

## Parallel leaves and aggregation in SP1

For the history backfill, segments are proved independently and joined in a tree
instead of one long sequential chain.

- `sp1/leaf` proves one segment of headers and publishes a 277-byte `RangeClaim`
  (`core/`): first height, anchor hash and start difficulty context; last height, last
  hash and end context; total work; a records root; the number of leaves; and whether
  Equihash was checked.
- `sp1/agg` verifies two child proofs, joins their claims and publishes one claim for
  both. It checks that the left range ends exactly where the right one starts (last hash
  and anchor, next height, end and start difficulty context), adds the work, and sets
  the records root to SHA-256(0x01 ‖ left root ‖ right root). Which program must have
  made each child follows from the child's claim (a leaf claim from the leaf program,
  anything else from the aggregation program itself), not from the host. It re-checks
  no headers and no Equihash. Children can be leaves or earlier aggregates, so the same
  program builds a tree of any depth.
- `accept()` in `sp1/script/src/bin/aggregate.rs` is the client's whole rule: the proof
  verifies against the trusted aggregation program (which also requires exit code 0),
  its claim names the trusted leaf and aggregation programs, and its range starts at the
  trusted checkpoint.

Two leaves of 100 headers (heights 4,494,811 to 4,495,010) and one aggregation, M2 Pro
CPU, run one after another:

| | Time | Saved proof |
|---|---|---|
| Leaf A | 133.9 s | 1,272,846 B |
| Leaf B | 146.9 s | 1,272,846 B |
| Aggregation (1,343,319 instructions) | 113.3 s | 1,272,846 B |

The client accepted the aggregate: heights 4,494,811 to 4,495,010, 2 leaves. Peak memory
was 7.5 GB.

Leaves are independent, so with one prover per leaf the backfill takes the time of one
leaf plus one aggregation per tree level: about nine levels for the roughly 450 Rings
since NU5, instead of about 450 links one after another.

Negative tests (`cargo run --release -p zylem-hdr-sp1 --bin aggregate -- --reuse --prove-negatives`):

| Attempt | Rejected by | Result |
|---|---|---|
| Leaves not adjacent (A then C) | aggregation program | exit code 1 |
| Leaves in the wrong order (B then A) | aggregation program | exit code 1 |
| Right leaf starts from another difficulty context | aggregation program | exit code 1 |
| Child aggregate made with other programs | aggregation program | exit code 1 |
| Checkpoint the client does not trust | client | `WrongCheckpoint` |
| Proof checked against a different program key | client | proof invalid (vk hash mismatch) |
| A single leaf presented as the history proof | client | proof invalid (vk hash mismatch) |
| Published claim altered after proving | client | proof invalid (public values) |
| Client trusts a different leaf program | client | `WrongLeafProgram` |
| Leaf A's claim altered, with A's real proof | prover | no proof produced |
| Wrong order, proved anyway | client | SP1 produces a proof with exit code 1; `accept` rejects it ("Unexpected exit code: 1") |

The last row shows why the client must check the exit code: SP1 proves a guest that
panicked, and only the exit code says so. That a child's claim cannot be altered while
keeping its real proof rests on SP1's soundness; the test shows the prover cannot
produce such a proof, not that no adversary could.
