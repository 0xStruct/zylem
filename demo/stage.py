"""Stages the "Zcash without a node" demo page: two Rings, the published history proofs,
the light Ring made from the second Ring and the smoke proof, and the WebAssembly client, for a host that serves only text types (binary files become
base64 `.b64.txt`).

Usage: python3 demo/stage.py OUT_DIR [--standalone] [--raw] [--home URL]

`--standalone` wraps the page in its own HTML document (charset, viewport) for a plain
static host; without it the page is the fragment an Artifact publish wraps. `--raw` keeps
Rings and proofs as binary files under their hash-named source names, for hosts that serve
any type (and cache them for good). `--home` links the page's "Zylem" label to a home page.

The page pins the program keys and starting blocks it trusts. They are taken here from
the operator's own publish directories (zylem-build publish output), not from anything
the host serves, and written into the page.
"""
import base64, json, os, shutil, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
out = sys.argv[1]
standalone = "--standalone" in sys.argv[2:]
raw = "--raw" in sys.argv[2:]
home = sys.argv[sys.argv.index("--home") + 1] if "--home" in sys.argv else None
DATA = os.path.join(ROOT, "data")
PKG = os.path.join(ROOT, "spikes/header-proof/wasm-verify/pkg-web")
RINGS = {
    # The Ring with the demo payment: a real Ironwood payment, transaction 4 of 4,521,980.
    "payment": "ring-4518274-4522369-9bd762020e0052b1.zst",
    # The Ring that contains the smoke proof's 1,536 blocks.
    "proven": "ring-4526466-4530561-4a8acfca511db7cc.zst",
}
# A light Ring carries each proven block's 104-byte record in place of its 1,487-byte
# header. These are the sizes with every block proven, measured 2026-10-26 by rewriting
# these Rings that way at the same zstd level (9). No proof covers a whole Ring yet.
LIGHT_BYTES = {"payment": 2034975, "proven": 1632286}
PROOFS = {"smoke": "publish/smoke", "shard0": "publish/nu7-shard0"}
# `zylem-build light` output for the smoke proof: the second Ring with its proven blocks light.
LIGHT = "publish/smoke"

shutil.rmtree(out, ignore_errors=True)
os.makedirs(os.path.join(out, "data"))
os.makedirs(os.path.join(out, "pkg"))
for f in ("zylem_wasm_verify.js", "zylem_wasm_verify_bg.wasm"):
    shutil.copy(os.path.join(PKG, f), os.path.join(out, "pkg", f))


def text(src, name):
    if raw:
        # Source names carry the file's hash, so a host can cache them forever.
        shutil.copy(src, os.path.join(out, "data", os.path.basename(src)))
        return "data/" + os.path.basename(src)
    with open(src, "rb") as f, open(os.path.join(out, "data", name + ".b64.txt"), "w") as g:
        g.write(base64.b64encode(f.read()).decode())
    return "data/" + name + ".b64.txt"


manifest = json.load(open(os.path.join(DATA, "testnet/manifest.json")))
files = {"rings": {}, "proofs": {}, "wasm_bytes": os.path.getsize(os.path.join(PKG, "zylem_wasm_verify_bg.wasm"))}
for key, name in RINGS.items():
    e = next(r for r in manifest["rings"] if r["file"].endswith(name))
    files["rings"][key] = {"file": text(os.path.join(DATA, "testnet", e["file"]), name), "from": e["start_height"],
                           "to": e["end_height"], "bytes": e["size"], "light_bytes": LIGHT_BYTES[key]}

light = json.load(open(os.path.join(DATA, LIGHT, "light.json")))["rings"][0]
binding = json.load(open(os.path.join(DATA, LIGHT, light["binding"])))
files["light"] = {"file": text(os.path.join(DATA, LIGHT, light["file"]), "light-ring"), "bytes": light["size"],
                  "full_bytes": light["full_size"], "from": light["start_height"], "to": light["end_height"],
                  "light": light["light"], "binding": binding, "proof": "smoke"}

trust = {}
for key, rel in PROOFS.items():
    h = json.load(open(os.path.join(DATA, rel, "history.json")))
    d = os.path.join(DATA, rel)
    p = {"from": h["covers"]["first"], "to": h["covers"]["last"], "leaves": h["covers"]["leaves"]}
    for part in ("proof", "public_values", "records", "groth16"):
        if h.get(part):
            p[part] = text(os.path.join(d, h[part]), f"{key}-{part}")
    files["proofs"][key] = p
    trust[key] = {"anchor": {"height": h["anchor"]["height"], "hash": h["anchor"]["hash_internal"],
                             "context_hash": h["anchor"]["context_hash"], "display": h["anchor"]["hash"]}}
    trust["programs"] = {
        "leaf_vk": h["programs"]["leaf"]["hash_u32"],
        "agg_vk": h["programs"]["aggregation"]["hash_u32"],
        "agg_vk_bincode": h["programs"]["aggregation"]["koalabear_bincode_hex"],
        "agg_bytes32": h["programs"]["aggregation"]["bytes32"],
        "leaf_bytes32": h["programs"]["leaf"]["bytes32"],
    }

page = open(os.path.join(ROOT, "demo/index.html")).read()
page = page.replace("/*FILES*/null", json.dumps(files)).replace("/*TRUST*/null", json.dumps(trust))
SITEBAR = '''<header class="sitebar">
    <a class="mark" href="{h}" aria-label="Zylem home">
      <svg viewBox="0 0 26 26" aria-hidden="true"><circle cx="13" cy="13" r="11.5" fill="none" stroke="currentColor" stroke-width="1.5"/><circle cx="13" cy="13" r="7.5" fill="none" stroke="currentColor" stroke-width="1.5"/><circle cx="13" cy="13" r="3.5" fill="currentColor"/></svg>
      Zylem
    </a>
    <nav aria-label="Site">
      <a href="{h}#attacks">Why Zylem</a>
      <a href="{h}how/">How it works</a>
      <a href="{h}#numbers">Performance</a>
      <a href="{h}#try">Developers</a>
      <a class="nav-cta" href="#s1" aria-current="page">Live demo</a>
    </nav>
    <details class="menu">
      <summary aria-label="All pages">Menu</summary>
      <div>
        <a href="{h}">Home</a>
        <a href="{h}#attacks">Why Zylem</a>
        <a href="{h}how/">How it works</a>
        <a href="{h}#numbers">Performance</a>
        <a href="{h}#try">Developers</a>
        <a href="{h}how/#details">Technical details</a>
      </div>
    </details>
  </header>'''
if home:
    # Part of the site: the same top bar as the other pages, with the demo as the current page.
    page = page.replace("<!--SITEBAR-->", SITEBAR.replace("{h}", home))
else:
    page = page.replace("  <!--SITEBAR-->\n", "")
if standalone:
    page = ('<!doctype html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n'
            '<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">\n'
            + (f'<link rel="icon" href="{home}favicon.svg" type="image/svg+xml">\n' if home else '') +
            '<style>body{margin:0}[hidden]{display:none!important}</style>\n</head>\n<body>\n' + page + '\n</body>\n</html>\n')
open(os.path.join(out, "index.html"), "w", encoding="utf-8").write(page)
for root, _, fs in os.walk(out):
    for f in sorted(fs):
        p = os.path.join(root, f)
        print(f"{os.path.getsize(p):>10}  {os.path.relpath(p, out)}")
