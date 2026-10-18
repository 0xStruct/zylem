#!/usr/bin/env bash
# Prepares a Linux x86-64 GPU machine (e.g. a RunPod pod) for the benchmark.
#
# Fast path: if the kit contains a prebuilt CUDA binary (prebuilt/gpu-bench) that runs
# here, use it and skip everything else. Otherwise install the toolchains, build from
# source, and save the result as gpu-bench-prebuilt-linux-x86_64.tar.gz next to this
# script so the next run can skip the build. FORCE_BUILD=1 always builds.
#
# Run from the unpacked kit: zylem/spikes/header-proof/gpu-bench/setup.sh
set -euo pipefail
KIT="$(cd "$(dirname "$0")" && pwd)"
cd "$KIT"
export DEBIAN_FRONTEND=noninteractive

command -v nvidia-smi >/dev/null || { echo "no NVIDIA GPU visible (nvidia-smi missing)"; exit 1; }
nvidia-smi --query-gpu=name,memory.total,driver_version --format=csv

PREBUILT="$KIT/prebuilt/gpu-bench"
if [ -x "$PREBUILT" ] && [ "${FORCE_BUILD:-0}" != 1 ]; then
  if "$PREBUILT" --check 2>/dev/null | grep -q "cuda feature: true"; then
    echo "using the prebuilt binary (built on: $(head -1 "$KIT/prebuilt/BUILD-INFO.txt" 2>/dev/null))"
    echo "setup done: nothing to build"
    exit 0
  fi
  echo "the prebuilt binary does not run here; building from source instead"
  ldd "$PREBUILT" 2>&1 | grep -E "not found|GLIBC" || true
fi

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

cd "$KIT/../sp1"
PROTOC="$HOME/.local/protoc/bin/protoc" PATH="$HOME/.sp1/bin:$PATH" \
  cargo build --release -p zylem-hdr-sp1 --bin gpu-bench --features cuda
BIN="$(pwd)/target/release/gpu-bench"
echo "built: $BIN"

# Save the binary for the next run, with what it was built on.
mkdir -p "$KIT/prebuilt"
cp "$BIN" "$KIT/prebuilt/gpu-bench"
{
  echo "$(. /etc/os-release && echo "$PRETTY_NAME"), $(ldd --version | head -1), built $(date -u +%Y-%m-%dT%H:%MZ)"
  echo "GPU: $(nvidia-smi --query-gpu=name,driver_version --format=csv,noheader | head -1)"
  echo "CUDA image: ${CUDA_VERSION:-unknown}"
  echo "rustc: $(rustc --version)"
  echo "shared libraries:"
  ldd "$BIN"
} > "$KIT/prebuilt/BUILD-INFO.txt"
tar -C "$KIT" -czf "$KIT/gpu-bench-prebuilt-linux-x86_64.tar.gz" prebuilt
echo "saved for reuse: $KIT/gpu-bench-prebuilt-linux-x86_64.tar.gz"
