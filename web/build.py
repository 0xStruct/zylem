"""Builds the static site: the landing page, the original landing page, How Zylem works,
and the demo with its Rings and proofs, ready for any static host. Live at
https://zylem.cash.

Usage: python3 web/build.py [OUT_DIR]   (default data/site, which git ignores)

The pages in web/ are written as fragments (the form an Artifact publish wraps); this
wraps each in its own HTML document. Netlify and Cloudflare both read the _headers file.
Deploy with:

    npx netlify-cli deploy --dir data/site --prod
"""
import os, shutil, subprocess, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
out = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "data/site"))
PAGES = ["index.html", "v1/index.html", "how/index.html"]

HEAD = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<style>:root{box-sizing:border-box;padding-top:env(safe-area-inset-top,0px);padding-bottom:env(safe-area-inset-bottom,0px)}body{margin:0}img{max-width:100%}[hidden]{display:none!important}</style>
</head>
<body>
"""
TAIL = "\n</body>\n</html>\n"

# The Zylem mark: three growth rings.
FAVICON = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 26 26"><circle cx="13" cy="13" r="11.5" fill="none" stroke="#1d6b47" stroke-width="1.8"/><circle cx="13" cy="13" r="7.5" fill="none" stroke="#1d6b47" stroke-width="1.8"/><circle cx="13" cy="13" r="3.5" fill="#1d6b47"/></svg>
"""

# Ring and proof files are named by their hash, so they never change under a name.
HEADERS = """/demo/data/*
  Cache-Control: public, max-age=31536000, immutable
/demo/pkg/*
  Cache-Control: public, max-age=3600
/*
  X-Content-Type-Options: nosniff
  Referrer-Policy: strict-origin-when-cross-origin
"""

# Empty the folder rather than replace it, so a preview server running in it keeps working.
os.makedirs(out, exist_ok=True)
for entry in os.listdir(out):
    path = os.path.join(out, entry)
    shutil.rmtree(path) if os.path.isdir(path) and not os.path.islink(path) else os.remove(path)
for rel in PAGES:
    dst = os.path.join(out, rel)
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    page = open(os.path.join(ROOT, "web", rel), encoding="utf-8").read()
    open(dst, "w", encoding="utf-8").write(HEAD + page + TAIL)
subprocess.run([sys.executable, os.path.join(ROOT, "demo/stage.py"), os.path.join(out, "demo"),
                "--standalone", "--raw", "--home", "/"], check=True, stdout=subprocess.DEVNULL)
open(os.path.join(out, "favicon.svg"), "w").write(FAVICON)
open(os.path.join(out, "_headers"), "w").write(HEADERS)

total = 0
for root, _, files in os.walk(out):
    for f in sorted(files):
        p = os.path.join(root, f)
        total += os.path.getsize(p)
        print(f"{os.path.getsize(p):>10}  {os.path.relpath(p, out)}")
print(f"{total:>10}  total in {out}")
