// Times each verifier the WASM build exposes on the proofs `wrap` wrote.
// Usage: node bench.mjs <pkg dir> <proof dir>
import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
const [pkg, dir] = process.argv.slice(2);
const m = await import(join(process.cwd(), pkg, "zylem_wasm_verify.js"));
const pv = readFileSync(join(dir, "public-values.bin"));
const vkey = readFileSync(join(dir, "agg-vkey.txt"), "utf8").trim();
const bad = Buffer.from(pv); bad[208 + 31] ^= 1;
function run(name, f, n) {
  f(pv); // warm up
  const t = performance.now();
  for (let i = 0; i < n; i++) f(pv);
  const ms = (performance.now() - t) / n;
  let altered = "ACCEPTED";
  try { f(bad); } catch (e) { altered = "rejected"; }
  console.log(`${name}: ${ms.toFixed(2)} ms per verify (${n} runs); altered claim ${altered}`);
}
for (const [name, file, fn, n] of [["plonk", "plonk.proof", "verify_plonk", 20], ["groth16", "groth16.proof", "verify_groth16", 20]]) {
  if (!existsSync(join(dir, file))) { console.log(`${name}: no proof`); continue; }
  const proof = readFileSync(join(dir, file));
  run(name, (p) => m[fn](proof, p, vkey), n);
}
if (m.verify_compressed && existsSync(join(dir, "compressed.proof"))) {
  const proof = readFileSync(join(dir, "compressed.proof"));
  const vk = readFileSync(join(dir, "agg-vkey-koalabear.bin"));
  try { run("compressed", (p) => m.verify_compressed(proof, p, vk), 3); }
  catch (e) { console.log(`compressed: rejected the honest proof: ${e.message}`); }
}
