#!/usr/bin/env bash
# Runs the GPU benchmark and saves results under gpu-bench/results/.
# Usage: ./run.sh PRICE_PER_HOUR [extra gpu-bench options]
#   e.g. ./run.sh 0.99
#        ./run.sh 0.99 --sizes-on 100,256,512,1024
set -euo pipefail
cd "$(dirname "$0")/../sp1"
PRICE="${1:?hourly price in USD, e.g. ./run.sh 0.99}"; shift
GPU="$(nvidia-smi --query-gpu=name --format=csv,noheader | head -1)"
mkdir -p ../gpu-bench/results
OUT="../gpu-bench/results/$(echo "$GPU" | tr ' /' '--')-$(date -u +%Y%m%dT%H%M%SZ)"
SP1_PROVER="${SP1_PROVER:-cuda}" ./target/release/gpu-bench ../../../data/testnet \
  --price "$PRICE" --gpu-name "$GPU" --out "$OUT.jsonl" "$@" 2>&1 | tee "$OUT.log"
echo "results: $OUT.jsonl"
