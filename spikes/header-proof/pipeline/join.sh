#!/usr/bin/env bash
# Joins shard proofs, in order, into the history proof, then wraps it in Groth16.
# Usage: join.sh OUT_DIR SHARD_PROOF... [--groth16]
set -uo pipefail
KIT="$(cd "$(dirname "$0")" && pwd)"
OUT="${1:?output directory}"; shift
PARTS=("$@")
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
mkdir -p "$OUT"
{
  SP1_PROVER=cuda "$BIN" join "$@" "$OUT" "${PARTS[@]}" && status=ok || status=failed
  pkill -f sp1-gpu-server || true
  echo "$status $(date -u +%FT%TZ)" > "$OUT/join.status"
  echo "join: $status"
} 2>&1 | tee -a "$OUT/join.log"
