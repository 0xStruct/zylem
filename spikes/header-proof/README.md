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
