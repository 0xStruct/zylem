#!/usr/bin/env bash
# Prepares a Linux x86-64 GPU pod to run the proving pipeline.
#
# Fast path: if the kit has prebuilt binaries (prebuilt/prove-jobs) that run here, use
# them. Otherwise install the toolchains, build prove-jobs and export-proof with CUDA and
# native gnark (for the Groth16 wrap), and save them as prebuilt.tar.gz next to this
# script, so the other pods run the exact same programs: proofs from different pods can
# only be joined if their program keys match. FORCE_BUILD=1 always builds.
#
# Generation 1 (PROGRAMS=programs/<network> set) proves with the frozen programs in that
# directory, so any build of `prove` makes joinable proofs; prebuilt binaries only save
# the build time.
#
# Run from the unpacked kit: zylem/spikes/header-proof/pipeline/setup.sh
set -euo pipefail
KIT="$(cd "$(dirname "$0")" && pwd)"
cd "$KIT"
export DEBIAN_FRONTEND=noninteractive

command -v nvidia-smi >/dev/null || { echo "no NVIDIA GPU visible (nvidia-smi missing)"; exit 1; }
nvidia-smi --query-gpu=name,memory.total,driver_version --format=csv

NEED=prove-jobs; [ -n "${PROGRAMS:-}" ] && NEED=prove
if [ -x "$KIT/prebuilt/$NEED" ] && [ "${FORCE_BUILD:-0}" != 1 ]; then
  if "$KIT/prebuilt/$NEED" check 2>/dev/null | grep -q "cuda feature: true"; then
    echo "using the prebuilt binaries (built on: $(head -1 "$KIT/prebuilt/BUILD-INFO.txt" 2>/dev/null))"
    exit 0
  fi
  echo "the prebuilt binaries do not run here; building from source"
fi

SUDO=""; [ "$(id -u)" -ne 0 ] && SUDO="sudo"
$SUDO apt-get update -qq
$SUDO apt-get install -y -qq build-essential pkg-config libssl-dev curl git unzip clang golang-go >/dev/null
if ! command -v cargo >/dev/null; then
  curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain none
fi
. "$HOME/.cargo/env"
if [ ! -x "$HOME/.local/protoc/bin/protoc" ]; then
  curl -sSL -o /tmp/protoc.zip https://github.com/protocolbuffers/protobuf/releases/download/v36.2/protoc-36.2-linux-x86_64.zip
  mkdir -p "$HOME/.local/protoc" && unzip -oq /tmp/protoc.zip -d "$HOME/.local/protoc"
fi
if [ ! -x "$HOME/.sp1/bin/cargo-prove" ]; then
  mkdir -p "$HOME/.sp1/bin"
  curl -sSL https://raw.githubusercontent.com/succinctlabs/sp1/main/sp1up/sp1up -o "$HOME/.sp1/bin/sp1up"
  chmod +x "$HOME/.sp1/bin/sp1up"
  PATH="$HOME/.sp1/bin:$PATH" "$HOME/.sp1/bin/sp1up"
fi

cd "$KIT/../sp1"
PROTOC="$HOME/.local/protoc/bin/protoc" PATH="$HOME/.sp1/bin:$PATH" \
  cargo build --release -p zylem-hdr-sp1 --bin prove-jobs --bin prove --bin export-proof --features cuda,native-gnark
mkdir -p "$KIT/prebuilt"
cp target/release/prove-jobs target/release/prove target/release/export-proof "$KIT/prebuilt/"
{
  echo "$(. /etc/os-release && echo "$PRETTY_NAME"), $(ldd --version | head -1), built $(date -u +%Y-%m-%dT%H:%MZ)"
  echo "GPU: $(nvidia-smi --query-gpu=name,driver_version --format=csv,noheader | head -1)"
  echo "rustc: $(rustc --version)"
  "$KIT/prebuilt/prove-jobs" check
  echo "shared libraries:"
  ldd "$KIT/prebuilt/prove-jobs"
} > "$KIT/prebuilt/BUILD-INFO.txt"
tar -C "$KIT" -czf "$KIT/prebuilt.tar.gz" prebuilt
echo "saved for the other pods: $KIT/prebuilt.tar.gz"
