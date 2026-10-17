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
