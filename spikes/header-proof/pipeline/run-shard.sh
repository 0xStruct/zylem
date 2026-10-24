#!/usr/bin/env bash
# Proves one shard's leaves, then aggregates them into one shard proof.
# Usage: run-shard.sh SHARD   (jobs in ~/jobs, proofs written to ~/out)
# Set PROGRAMS for generation 1 (see below). Safe to rerun: finished proofs are
# skipped. Ends by writing ~/out/shard-SHARD.status.
set -uo pipefail
KIT="$(cd "$(dirname "$0")" && pwd)"
SHARD="${1:?shard number}"
# Generation 0 proves with the programs compiled into prove-jobs; generation 1
# (PROGRAMS=programs/<network>, relative to the repository) with the frozen programs there.
ROOT="$(cd "$KIT/../../.." && pwd)"
if [ -n "${PROGRAMS:-}" ]; then
  case "$PROGRAMS" in /*) ;; *) PROGRAMS="$ROOT/$PROGRAMS" ;; esac
  BIN="$KIT/prebuilt/prove"
  [ -x "$BIN" ] || BIN="$KIT/../sp1/target/release/prove"
  set -- "$PROGRAMS"
else
  BIN="$KIT/prebuilt/prove-jobs"
  [ -x "$BIN" ] || BIN="$KIT/../sp1/target/release/prove-jobs"
  set --
fi
mkdir -p "$HOME/out"
LOG="$HOME/out/shard-$SHARD.log"
{
  SP1_PROVER=cuda "$BIN" leaves "$@" "$HOME/jobs" "$HOME/out" --shard "$SHARD" \
    && SP1_PROVER=cuda "$BIN" aggregate "$@" "$HOME/jobs" "$HOME/out" --shard "$SHARD" \
    && status=ok || status=failed
  pkill -f sp1-gpu-server && echo "stopped sp1-gpu-server" || true
  echo "$status $(date -u +%FT%TZ)" > "$HOME/out/shard-$SHARD.status"
  echo "shard $SHARD: $status"
} 2>&1 | tee -a "$LOG"
