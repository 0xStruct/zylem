#!/usr/bin/env bash
# Prepares a fresh Linux x86-64 GPU machine (e.g. a RunPod pod) and builds gpu-bench with
# CUDA. Run from the unpacked kit: zylem/spikes/header-proof/gpu-bench/setup.sh
set -euo pipefail
cd "$(dirname "$0")"
export DEBIAN_FRONTEND=noninteractive

command -v nvidia-smi >/dev/null || { echo "no NVIDIA GPU visible (nvidia-smi missing)"; exit 1; }
nvidia-smi --query-gpu=name,memory.total,driver_version --format=csv

SUDO=""; [ "$(id -u)" -ne 0 ] && SUDO="sudo"
$SUDO apt-get update -qq
$SUDO apt-get install -y -qq build-essential pkg-config libssl-dev curl git unzip clang >/dev/null

# Rust: the repo's rust-toolchain.toml selects the exact toolchain on first use.
if ! command -v cargo >/dev/null; then
  curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain none
fi
. "$HOME/.cargo/env"

# protoc, which SP1's SDK needs at build time (Google's release binary).
if [ ! -x "$HOME/.local/protoc/bin/protoc" ]; then
  curl -sSL -o /tmp/protoc.zip https://github.com/protocolbuffers/protobuf/releases/download/v36.2/protoc-36.2-linux-x86_64.zip
  mkdir -p "$HOME/.local/protoc" && unzip -oq /tmp/protoc.zip -d "$HOME/.local/protoc"
fi

# SP1 toolchain (sp1up downloads from Succinct's GitHub releases only).
if [ ! -x "$HOME/.sp1/bin/cargo-prove" ]; then
  mkdir -p "$HOME/.sp1/bin"
  curl -sSL https://raw.githubusercontent.com/succinctlabs/sp1/main/sp1up/sp1up -o "$HOME/.sp1/bin/sp1up"
  chmod +x "$HOME/.sp1/bin/sp1up"
  PATH="$HOME/.sp1/bin:$PATH" "$HOME/.sp1/bin/sp1up"
fi

cd ../sp1
PROTOC="$HOME/.local/protoc/bin/protoc" PATH="$HOME/.sp1/bin:$PATH" \
  cargo build --release -p zylem-hdr-sp1 --bin gpu-bench --features cuda
echo "built: $(pwd)/target/release/gpu-bench"
