#!/usr/bin/env bash
# Zylem Phase 2 demo: an unmodified zcash-devtool wallet syncs through zylem-proxy.
#
#   1. honest Rings: the wallet syncs to the tip;
#   2. three malicious Ring hosts (fake note, hidden payment, wrong tree state): the
#      proxy rejects each with its typed error and serves only the verified range;
#   3. audit mode: the wallet syncs from a public lightwalletd while the proxy checks
#      every block it relays against the verified Rings.
#
# Needs: Rings already built in data/testnet (zylem-build backfill), and DEVTOOL pointing
# at a zcash-devtool binary. Ports 8090-8091 and 9067-9069 must be free.
set -euo pipefail
cd "$(dirname "$0")/.."

DEVTOOL=${DEVTOOL:?set DEVTOOL to a zcash-devtool binary}
UPSTREAM=${UPSTREAM:-https://testnet.zec.rocks:443}
CHECKPOINT=${CHECKPOINT:-4500000:0000252837996ac6566d67241e6aa7916a6ba5ddcc46458b9682fc0e97860d71}
BIRTHDAY=${BIRTHDAY:-4510000}
# The coop close of a zdlc contract: a real Ironwood payment, transaction 4 of its block.
VICTIM_HEIGHT=${VICTIM_HEIGHT:-4521980}
VICTIM_TX=${VICTIM_TX:-4}
BIN=./target/release
OUT=data/demo
mkdir -p "$OUT"
rm -rf "$OUT"/wallets
mkdir -p "$OUT"/wallets
PIDS=()
cleanup() {
  for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done
  stop_proxy 9067; stop_proxy 9068; stop_proxy 9069
}
trap cleanup EXIT

strip() { sed -u 's/\x1b\[[0-9;]*m//g'; }

host() { # host DIR PORT
  "$BIN/zylem-build" serve --out "$1" --listen "127.0.0.1:$2" >"$OUT/host-$2.log" 2>&1 &
  PIDS+=($!)
  sleep 1
}

proxy() { # proxy NAME RINGS_PORT LISTEN_PORT MODE
  "$BIN/zylem-proxy" --listen "127.0.0.1:$3" --rings "http://127.0.0.1:$2" --upstream "$UPSTREAM" \
    --checkpoint "$CHECKPOINT" --mode "$4" >"$OUT/proxy-$1.log" 2>&1 &
  PIDS+=($!)
  for _ in $(seq 1 60); do grep -qE "serving (Strict|Audit) mode|^Error" "$OUT/proxy-$1.log" && return; sleep 1; done
}

sync_wallet() { # sync_wallet NAME PORT
  local w="$OUT/wallets/$1"
  "$DEVTOOL" wallet -w "$w" init --name "$1" --identity "$w.age" --birthday "$BIRTHDAY" \
    --network test --server "127.0.0.1:$2" >/dev/null 2>&1
  "$DEVTOOL" wallet -w "$w" sync --server "127.0.0.1:$2" >"$OUT/wallet-$1.raw" 2>&1 || true
  strip <"$OUT/wallet-$1.raw" >"$OUT/wallet-$1.log"
}

stop_proxy() { pkill -f "listen 127.0.0.1:$1" 2>/dev/null || true; }

report() { # report NAME
  echo "--- $1"
  grep -hE "REJECT|STALE|serving only|AUDIT [0-9]|AUDIT mismatch" "$OUT/proxy-$1.log" | cut -c29- | head -4 || true
  grep -hE "Latest block height|Scan complete|Error" "$OUT/wallet-$1.log" | cut -c29- | tail -2 || true
}

echo "== 1. honest Rings"
# Set HONEST_HOST_RUNNING=1 when a zylem-build serve for data/testnet already listens on 8090.
[ -n "${HONEST_HOST_RUNNING:-}" ] || host data/testnet 8090
proxy honest 8090 9067 strict
sync_wallet honest 9067
report honest

echo "== 2. malicious Ring hosts"
for attack in inject hide tree; do
  rm -rf "data/evil-$attack"
  h=$VICTIM_HEIGHT; extra=(--tx-index "$VICTIM_TX")
  [ "$attack" = tree ] && { h=4518274; extra=(); }
  "$BIN/zylem-build" tamper --from data/testnet --out "data/evil-$attack" --attack "$attack" --height "$h" "${extra[@]}"
  host "data/evil-$attack" 8091
  proxy "$attack" 8091 9068 strict
  sync_wallet "$attack" 9068
  report "$attack"
  stop_proxy 9068
  pkill -f "listen 127.0.0.1:8091" 2>/dev/null || true
  sleep 1
done

echo "== 3. audit mode against $UPSTREAM"
proxy audit 8090 9069 audit
sync_wallet audit 9069
report audit
