"""Stages a `zylem-build publish` directory for a host that serves only text types:
binary files become base64 `.b64.txt`, and history.json points at them.

Usage: python3 stage.py PUBLISH_DIR PKG_DIR OUT_DIR [PINNED_ROOT...]

For a generation 1 publish the page pins the given registry roots, by default the root
of the published registry.json.
"""
import base64, json, os, shutil, sys

pub, pkg, out = sys.argv[1:4]
pins = sys.argv[4:]
shutil.rmtree(out, ignore_errors=True)
os.makedirs(os.path.join(out, "data"))
os.makedirs(os.path.join(out, "pkg"))
for f in ("zylem_wasm_verify.js", "zylem_wasm_verify_bg.wasm"):
    shutil.copy(os.path.join(pkg, f), os.path.join(out, "pkg", f))
h = json.load(open(os.path.join(pub, "history.json")))

def text(rel):
    src = os.path.join(pub, rel)
    dst_rel = rel + ".b64.txt"
    os.makedirs(os.path.dirname(os.path.join(out, "data", dst_rel)), exist_ok=True)
    with open(src, "rb") as f, open(os.path.join(out, "data", dst_rel), "w") as g:
        g.write(base64.b64encode(f.read()).decode())
    return dst_rel

for key in ("proof", "public_values", "records", "groth16"):
    if h.get(key):
        h[key] = text(h[key])
for b in h["bindings"]:
    os.makedirs(os.path.join(out, "data", "binding"), exist_ok=True)
    shutil.copy(os.path.join(pub, b["binding"]), os.path.join(out, "data", b["binding"]))
if h.get("generation") == 1:
    shutil.copy(os.path.join(pub, h["programs"]["registry"]), os.path.join(out, "data", h["programs"]["registry"]))
    pins = pins or [h["programs"]["root"]]
page = open(os.path.join(os.path.dirname(__file__), "index.html")).read()
page = page.replace("/*PINNED_ROOTS*/", ", ".join(json.dumps(p) for p in pins))
open(os.path.join(out, "index.html"), "w").write(page)
json.dump(h, open(os.path.join(out, "data", "history.json"), "w"), indent=2)
for root, _, files in os.walk(out):
    for f in sorted(files):
        p = os.path.join(root, f)
        print(f"{os.path.getsize(p):>10}  {os.path.relpath(p, out)}")
