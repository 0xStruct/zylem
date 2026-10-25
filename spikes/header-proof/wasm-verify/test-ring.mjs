// Opens Ring files with the WebAssembly client and runs the full check on each.
//   node test-ring.mjs RING_FILE [TAMPERED_RING_FILE...]
import { readFileSync } from "node:fs";
import { RingFile } from "./pkg-node/zylem_wasm_verify.js";

const time = (f) => { const t = performance.now(); const v = f(); return [v, performance.now() - t]; };
const [honest, ...tampered] = process.argv.slice(2);
const [r, open] = time(() => new RingFile(readFileSync(honest)));
const s = JSON.parse(r.summary());
console.log(`opened ${s.start_height}..=${s.end_height} in ${open.toFixed(0)} ms:`, JSON.stringify({ blocks: s.blocks, transactions: s.transactions, bytes: s.bytes, ironwood: s.ironwood_actions, orchard: s.orchard_actions, sapling: s.sapling }));
const [v, ms] = time(() => JSON.parse(r.verify()));
console.log(`verified in ${ms.toFixed(0)} ms:`, JSON.stringify(v));
const busiest = JSON.parse(r.blocks()).sort((a, b) => b[3] - a[3])[0];
const b = JSON.parse(r.block(busiest[0]));
console.log(`block ${b.height}: ${b.transactions.length} txs, first ${b.transactions[0].txid.slice(0, 16)}…`);
console.log("find_tx:", r.find_tx(b.transactions[b.transactions.length - 1].txid));
for (const f of tampered) {
  const [res, t] = time(() => { try { new RingFile(readFileSync(f)).verify(); return "ACCEPTED"; } catch (e) { return "refused: " + (e.message ?? e); } });
  console.log(`${f.split("/").slice(-3, -2)}: ${res} (${t.toFixed(0)} ms)`);
}
