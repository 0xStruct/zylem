#!/usr/bin/env bash
# Packs the zylem code for a GPU pod, and each shard's proving jobs separately.
# Usage: pipeline/pack.sh JOBS_DIR
# Output in data/pipeline/: zylem-pipeline.tar.gz (code, plus the prebuilt binary if
# data/pipeline/prebuilt.tar.gz exists) and jobs-shard-N.tar.gz per shard.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
JOBS="$(cd "${1:?jobs directory from zylem-build jobs}" && pwd)"
OUT="$ROOT/data/pipeline"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
mkdir -p "$STAGE/zylem" "$OUT"

# Code: tracked and untracked files, without build output or data (both git-ignored).
(cd "$ROOT" && git ls-files -co --exclude-standard) | tar -C "$ROOT" -cf - -T - | tar -C "$STAGE/zylem" -xf -
if [ -f "$OUT/prebuilt.tar.gz" ]; then
  tar -C "$STAGE/zylem/spikes/header-proof/pipeline" -xzf "$OUT/prebuilt.tar.gz"
  echo "included prebuilt binaries: $(head -1 "$STAGE/zylem/spikes/header-proof/pipeline/prebuilt/BUILD-INFO.txt")"
else
  echo "no prebuilt binaries yet: setup.sh will build from source"
fi
tar -C "$STAGE" -czf "$OUT/zylem-pipeline.tar.gz" zylem
ls -la "$OUT/zylem-pipeline.tar.gz"

# Jobs: one archive per shard, each with the manifest.
python3 - "$JOBS" "$OUT" <<'PY'
import json, os, sys, tarfile
jobs, out = sys.argv[1], sys.argv[2]
m = json.load(open(os.path.join(jobs, "manifest.json")))
for shard in range(m["shards"]):
    path = os.path.join(out, f"jobs-shard-{shard}.tar.gz")
    with tarfile.open(path, "w:gz") as t:
        t.add(os.path.join(jobs, "manifest.json"), "jobs/manifest.json")
        n = 0
        for j in m["jobs"]:
            if j["shard"] == shard:
                t.add(os.path.join(jobs, j["name"] + ".job"), f"jobs/{j['name']}.job")
                n += 1
    print(f"shard {shard}: {n} jobs, {os.path.getsize(path) / 1e6:.1f} MB -> {path}")
PY
