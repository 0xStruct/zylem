# GPU benchmark kit

Measures how fast SP1 proves Zylem's header-chain leaves and aggregations on a rented
GPU, and what backfilling every mainnet header since NU5 would cost there. It runs the
same programs and real testnet headers as the CPU measurements in `../README.md`.

## What it measures

| Test | Default sizes | Why |
|---|---|---|
| Leaf without Equihash | 100, 1,024 and 4,096 headers | Linkage, target, difficulty rule, time and work at increasing scale, up to a full Ring |
| Leaf with Equihash | 100, 256 and 512 headers | Equihash is 99% of the work; this sets the backfill cost |
| Aggregation of two leaves | 100-header leaves | Cost of one join; aggregation never re-runs Equihash, so leaf size barely matters |

For each test: proving time, instructions, prover gas, instructions per second, peak GPU
memory (sampled with `nvidia-smi`) and proof size. The run ends with a projection: cost
per header at your hourly price, and GPU-hours and dollars for the whole backfill
(1,838,000 headers plus 449 aggregations), next to the Succinct network's price for the
same work. A 10-header warm-up runs first and is not counted: the first GPU proof
downloads SP1's GPU server (141 MB) and loads its kernels.

## Steps

1. **Pack** (here): `spikes/header-proof/gpu-bench/pack.sh` writes
   `data/gpu-bench/zylem-gpu-bench.tar.gz` (about 15 MB: the code and the first two
   testnet Rings).
2. **Create a pod**: one RTX 5090 (or RTX 4090, L40S), an Ubuntu image with CUDA 12.8 or
   newer (the RTX 5090 needs it), a container disk of at least 60 GB (the Rust build
   alone takes 10–20 GB), SSH enabled. On-demand is simplest for the first run.
3. **Copy the bundle to the pod**, either way:
   - `runpodctl send data/gpu-bench/zylem-gpu-bench.tar.gz` here, then
     `runpodctl receive <code>` on the pod;
   - or `scp` to the pod's SSH address.
4. **Set up** on the pod:
   ```bash
   tar xzf zylem-gpu-bench.tar.gz
   zylem/spikes/header-proof/gpu-bench/setup.sh
   ```
   - **First run** (no prebuilt binary in the bundle): installs build tools, Rust (the
     version the repo pins), Google's `protoc` and SP1's toolchain (`sp1up`), builds
     `gpu-bench` with CUDA (10–20 minutes, mostly compiling), and saves the result as
     `zylem/spikes/header-proof/gpu-bench/gpu-bench-prebuilt-linux-x86_64.tar.gz`.
   - **Later runs** (the bundle contains that binary): checks the binary starts on this
     machine and skips everything else, about a minute. If it doesn't start (an older
     system library on a different image), it builds from source as on a first run.
     `BUILD-INFO.txt` beside the binary says what it was built on; use the same image or
     a newer one. `FORCE_BUILD=1` always builds.
5. **Run**, passing the pod's hourly price in USD:
   ```bash
   zylem/spikes/header-proof/gpu-bench/run.sh 0.99
   # longer, more precise Equihash figures:
   zylem/spikes/header-proof/gpu-bench/run.sh 0.99 --sizes-on 100,256,512,1024
   ```
   Results go to `zylem/spikes/header-proof/gpu-bench/results/<GPU>-<time>.jsonl` and
   `.log`. SP1 downloads its GPU server (141 MB) from GitHub on the first proof of each
   pod.
6. **Copy back** before deleting the pod:
   - `zylem/spikes/header-proof/gpu-bench/results/` into
     `spikes/header-proof/gpu-bench/results/` here;
   - after a first run, `gpu-bench-prebuilt-linux-x86_64.tar.gz` into `data/gpu-bench/`
     here (about 20 MB). The next `pack.sh` includes it, so the next pod skips the build.
7. **Delete the pod** (not just stop it): a stopped pod still bills for its disk.

## Reading the result

At the Succinct network's price on 2026-10-21 ($0.12 per billion prover gas, before its
base fee), a header with Equihash costs about $0.00042 to prove there. A GPU at $P an
hour matches that when it proves P / (3,600 × 0.00042) headers a second:

| Hourly price | Break-even headers/s | Break-even instructions/s (3.98M per header) |
|---|---|---|
| $0.60 (RTX 5090, marketplace) | 0.40 | 1.6M |
| $0.99 (RTX 5090, RunPod Community) | 0.65 | 2.6M |
| $1.57 (L40S, DigitalOcean) | 1.03 | 4.1M |

Faster than break-even: proving yourself is cheaper than the network. Slower: use the
network (or Boundless) instead.

## Dry run on a CPU

`SP1_PROVER=cpu` runs the same flow without a GPU, for checking the kit:

```bash
cd spikes/header-proof/sp1
cargo build --release -p zylem-hdr-sp1 --bin gpu-bench
SP1_PROVER=cpu ./target/release/gpu-bench ../../../data/testnet --price 0 \
  --sizes-off 10 --sizes-on 5 --agg-size 10
```
