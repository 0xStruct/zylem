#!/usr/bin/env bash
# Packs the zylem code and a two-Ring testnet bundle for a GPU machine.
# Output: data/gpu-bench/zylem-gpu-bench.tar.gz (in the zylem repo root).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
OUT="$ROOT/data/gpu-bench"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
mkdir -p "$STAGE/zylem" "$OUT"

# Code: tracked and untracked files, without build output or data (both git-ignored).
(cd "$ROOT" && git ls-files -co --exclude-standard) | tar -C "$ROOT" -cf - -T - | tar -C "$STAGE/zylem" -xf -

# Data: the first two sealed Rings, enough for every benchmark size.
python3 - "$ROOT/data/testnet" "$STAGE/zylem/data/testnet" <<'PY'
import json, os, shutil, sys
src, dst = sys.argv[1], sys.argv[2]
m = json.load(open(os.path.join(src, "manifest.json")))
m["rings"] = m["rings"][:2]
m["tail"] = None
os.makedirs(os.path.join(dst, "rings"), exist_ok=True)
for r in m["rings"]:
    shutil.copy(os.path.join(src, r["file"]), os.path.join(dst, r["file"]))
json.dump(m, open(os.path.join(dst, "manifest.json"), "w"), indent=2)
print("bundled Rings", [(r["start_height"], r["end_height"]) for r in m["rings"]])
PY

tar -C "$STAGE" -czf "$OUT/zylem-gpu-bench.tar.gz" zylem
ls -la "$OUT/zylem-gpu-bench.tar.gz"
