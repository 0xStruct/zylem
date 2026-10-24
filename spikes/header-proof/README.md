# Header-proof spike (RISC Zero)

Can a zkVM prove Zcash's header chain cheaply enough to drop the 1,487-byte header from
every Ring block? This spike proves runs of real testnet headers from Zylem's Rings in
RISC Zero 3.0.6 and measures the cost. Run on 2026-10-21 on an Apple M2 Pro (10 cores,
16 GB), CPU proving only.

## What the guest proves

For each header (`crates/zylem-header`, formerly this spike's `core/`, shared by the
guests, the native validator and `zylem-core`):

- it is 1,487 bytes with the solution length encoded as `fd 40 05` (added after the
  Zakura differential tests, see `docs/phase3.md`);
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
total work, and a commitment to the records at their heights, so proofs chain and a
client can check a Ring's records against them instead of downloading headers (see
"Binding proofs to Rings").

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

`sp1/` runs the same rules crate (`crates/zylem-header`) in SP1 6.9.0, on the same 100 testnet
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
proves them, and publishes the extended 245-byte state (`ChainState` in `zylem-header`): key
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

- `sp1/leaf` proves one segment of headers and publishes a `RangeClaim` (`zylem-header`, 245
  bytes plus 41 per records peak): first height, anchor hash and start difficulty
  context; last height, last hash and end context; total work; the number of leaves;
  whether Equihash was checked; and the records commitment.
- `sp1/agg` verifies two child proofs, joins their claims and publishes one claim for
  both. It checks that the left range ends exactly where the right one starts (last hash
  and anchor, next height, end and start difficulty context) and that each child's
  records commitment has the canonical shape for its range, adds the work, and joins
  the two records commitments. Which program must have
  made each child follows from the child's claim (a leaf claim from the leaf program,
  anything else from the aggregation program itself), not from the host. It re-checks
  no headers and no Equihash. Children can be leaves or earlier aggregates, so the same
  program builds a tree of any depth.
- `accept()` in `sp1/script/src/bin/aggregate.rs` is the client's whole rule: the proof
  verifies against the trusted aggregation program (which also requires exit code 0),
  its records commitment has the canonical shape for its range, its claim names the
  trusted leaf and aggregation programs, its range starts at the trusted checkpoint, and
  every header in it had its Equihash solution checked. Equihash is required, not a
  policy option: without it a forged header only needs a double-SHA-256 below its
  target, which SHA-256 mining hardware makes far cheaper than real Zcash work.

Two leaves of 100 headers (heights 4,494,811 to 4,495,010) and one aggregation, M2 Pro
CPU, run one after another, rerun on 2026-10-22 with the records commitment below:

| | Time | Saved proof |
|---|---|---|
| Leaf A | 172.1 s | 1,273,184 B |
| Leaf B | 162.3 s | 1,273,020 B |
| Aggregation (1,365,932 instructions) | 130.4 s | 1,273,102 B |

(The first run, with the old records hash, took 133.9 s, 146.9 s and 113.3 s; the extra
time is mostly run-to-run variation on a busy laptop, the instruction count rose 1.7%.)
These leaves skip Equihash, because proving it needs about 27 GB of memory on a CPU, so
the client rejects the aggregate with `EquihashNotChecked` after every other check
passes. `SP1_PROVER=mock aggregate --equihash` runs the same flow with Equihash through
execution and the client accepts it; the RTX 5090 run below proves Equihash leaves for
real. Peak resident memory was 6.8 GB.

Leaves are independent, so with one prover per leaf the backfill takes the time of one
leaf plus one aggregation per tree level: about nine levels for the roughly 450 Rings
since NU5, instead of about 450 links one after another.

Negative tests (`cargo run --release -p zylem-hdr-sp1 --bin aggregate -- --reuse --prove-negatives`;
`--equihash` with `SP1_PROVER=mock` adds the mixed-leaf case):

| Attempt | Rejected by | Result |
|---|---|---|
| Leaves not adjacent (A then C) | aggregation program | exit code 1 |
| Leaves in the wrong order (B then A) | aggregation program | exit code 1 |
| Right leaf starts from another difficulty context | aggregation program | exit code 1 |
| Child aggregate made with other programs | aggregation program | exit code 1 |
| Right leaf's records committed one height off | aggregation program | exit code 1 (`BadRecords`) |
| Right leaf's records not merged into the canonical blocks | aggregation program | exit code 1 (`BadRecords`) |
| Checkpoint the client does not trust | client | `WrongCheckpoint` |
| Proof checked against a different program key | client | proof invalid (vk hash mismatch) |
| A single leaf presented as the history proof | client | proof invalid (vk hash mismatch) |
| Published claim altered after proving (work) | client | proof invalid (public values) |
| Published records commitment altered after proving | client | proof invalid (public values) |
| Leaves proved without Equihash | client | `EquihashNotChecked` |
| One Equihash leaf joined with one without (mock prover) | client | `EquihashNotChecked` |
| Client trusts a different leaf program | client | `WrongLeafProgram` |
| Leaf A's claim altered, with A's real proof | prover | no proof produced |
| Wrong order, proved anyway | client | SP1 produces a proof with exit code 1; `accept` rejects it ("Unexpected exit code: 1") |

The last row shows why the client must check the exit code: SP1 proves a guest that
panicked, and only the exit code says so. That a child's claim cannot be altered while
keeping its real proof rests on SP1's soundness; the test shows the prover cannot
produce such a proof, not that no adversary could.

## Binding proofs to Rings

A proof is only useful to a wallet if the records in the Ring it downloaded are the
records the proof covers, at the heights it covers them. The first aggregation hashed
each leaf's records in order and joined leaves as SHA-256(0x01 ‖ left ‖ right), so the
root depended on where provers split the range, and a record carried no height. A
client could not recompute it from a Ring.

The records commitment (`Peaks` in `zylem-header`) is now fixed by the heights alone:

- every height has one place in a binary tree over all heights; a record's leaf is
  SHA-256(0x00 ‖ height ‖ record) and an inner node SHA-256(0x01 ‖ left ‖ right);
- a range's commitment is the roots of the largest aligned blocks of 2^k heights that
  tile it, lowest first: at most about two per bit of the range's length (17 for the
  1.84 million heights since NU5, never more than 42 for a range that size, so a claim
  stays under 2 KB; a testnet Ring is 12 blocks);
- a leaf builds it record by record, merging a block with its left sibling as soon as
  the pair forms an aligned block; an aggregation appends the right child's blocks to
  the left child's the same way. The result is the same however the range was split;
- a Ring, or one block, is checked with the sibling hashes from each of its own aligned
  blocks up to the committed block containing it (`range_paths` and
  `Peaks::verify_range`).

The aggregation program and `accept()` also check that a commitment has exactly the
canonical block layout for its range, so a commitment cannot claim other heights.

Cost: 32,135 instructions per header without Equihash in SP1, up from 29,592 (+8.6%,
the per-record hashing); with Equihash the difference is lost in its 3.96 million.

Checks in `aggregate` against the real headers of the two leaves (heights 4,494,811 to
4,495,010; the commitment has 7 blocks):

| Check | Result |
|---|---|
| Records recomputed from the Ring headers equal the proven commitment | equal |
| The same 200 headers as leaves of 33, 117 and 50, joined right-first (executed) | same commitment |
| Headers 4,494,836 to 4,494,961, across the leaf boundary, with 17 sibling hashes | verified |
| One block (4,494,839) | verified |
| Two neighbouring headers swapped | `Mismatch` |
| Every header one height off | `Mismatch` |
| Headers after the proven range | `OutOfRange` |

Native unit tests (`cargo test -p zylem-header` at the repo root) cover splits at six points and a
three-leaf tree joined both ways, equal records at two heights giving different roots, a
tampered record, swapped records, shifted heights, ranges outside the claim, a forged
sibling, a short path, claim encoding, and a child whose blocks were never merged.

Sibling paths are not yet deduplicated (blocks inside the same committed block repeat
some upper siblings); serving them next to Rings is the next step.

## GPU proving in SP1

`gpu-bench/` run on one RTX 5090 (32 GB, RunPod Secure Cloud on-demand, $1.19/h,
`runpod/pytorch:1.0.2-cu1281-torch280-ubuntu2404`, driver 595.91.07), SP1 6.9.0 with
`SP1_PROVER=cuda`, compressed proofs of real testnet headers from the first two Rings,
2026-10-21:

| Headers | Equihash | Proving time | s/header | Instructions | MHz | Peak GPU memory |
|---|---|---|---|---|---|---|
| 100 | off | 3.1 s | 0.0311 | 2,993,049 | 0.96 | 18,316 MiB |
| 1,024 | off | 10.3 s | 0.0101 | 30,318,283 | 2.93 | 26,126 MiB |
| 4,096 | off | 28.4 s | 0.0069 | 121,209,152 | 4.27 | 26,160 MiB |
| 100 | on | 57.6 s | 0.576 | 397,573,947 | 6.90 | 26,416 MiB |
| 256 | on | 149.6 s | 0.584 | 1,017,723,736 | 6.80 | 26,418 MiB |
| 512 | on | 272.1 s | 0.531 | 2,035,403,253 | 7.48 | 26,418 MiB |
| Aggregation of two 100-header leaves | | 2.2 s | | | | 26,418 MiB |

Every proof is 1,272,846 B saved, as on the CPU. Against the M2 Pro: 100 headers
without Equihash take 3.1 s instead of 146 s, and an aggregation 2.2 s instead of
113.3 s. Throughput grows with leaf size (fixed per-proof overhead), so a full 4,096-
header Ring with Equihash should land at or below the 512-header figure; it was not
measured.

**Backfill since NU5** (1,838,000 headers with Equihash plus 449 aggregations), projected
from the 512-header Equihash leaf: 272 GPU-hours, **$323** at $1.19/h, against **$775**
for the same prover gas on the Succinct network at $0.12 per billion (before its base
fee). One 5090 proves 1.88 headers/s; matching the network's price needs 0.79 at this
hourly rate. Leaves are independent, so the wall time divides by the number of GPUs.
Peak memory stays near 26 GB whatever the size, so a 24 GB card may not fit.

In this run `gpu-bench` panicked after writing its results, while dropping the CUDA
proving keys ("there is no reactor running", `sp1-cuda` `pk.rs:63`: its destructors call
`tokio::spawn`, and the blocking SDK keeps its runtime private). The abort left
`sp1-gpu-server` running and holding the output pipe, so `run.sh` never returned. Since
fixed: `gpu-bench` drops the client and keys inside a tokio runtime, which also stops the
server, and `run.sh` stops a leftover server if `gpu-bench` dies anyway. The fix has
been checked on CPU only; the next GPU run is its first test there.

Results: `gpu-bench/results/NVIDIA-GeForce-RTX-5090-20261021T171749Z.{jsonl,log}`.
