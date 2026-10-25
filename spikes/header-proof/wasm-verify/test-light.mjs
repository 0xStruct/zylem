// A light Ring checked the way a client does: the history proof first, then the Ring
// against it. Then the ways a host could cheat with one.
//   node test-light.mjs PUBLISH_DIR      (a `zylem-build publish` + `light` directory)
import { readFileSync } from "node:fs";
import { RingFile, verify_history } from "./pkg-node/zylem_wasm_verify.js";

const dir = process.argv[2];
const read = (p) => readFileSync(`${dir}/${p}`);
const history = JSON.parse(read("history.json"));
const light = JSON.parse(read("light.json")).rings[0];
const proof = read(history.proof), pv = read(history.public_values);
const binding = read(light.binding).toString();
const time = (f) => { const t = performance.now(); const v = f(); return [v, performance.now() - t]; };
const refused = (f) => { try { f(); return "ACCEPTED"; } catch (e) { return "refused: " + (e.message ?? e); } };
let failed = 0;
const expect = (what, ok) => { console.log(`${ok ? "ok  " : "FAIL"} ${what}`); if (!ok) failed++; };

const p = history.programs;
const trusted = JSON.stringify({ leaf_vk: p.leaf.hash_u32, agg_vk: p.aggregation.hash_u32, anchor: { height: history.anchor.height, hash: history.anchor.hash_internal, context_hash: history.anchor.context_hash } });
const [claim, pt] = time(() => JSON.parse(verify_history(proof, pv, Buffer.from(p.aggregation.koalabear_bincode_hex, "hex"), trusted)));
console.log(`history proof ${claim.first_height}..=${claim.last_height} verified in ${pt.toFixed(0)} ms`);

const ring = new RingFile(read(light.file));
const s = JSON.parse(ring.summary());
console.log(`light Ring ${s.start_height}..=${s.end_height}: ${s.light_blocks} of ${s.blocks} blocks light, ${s.bytes.file} B (full Ring ${light.full_size} B), headers ${s.bytes.headers} B + records ${s.bytes.records} B`);
const [v, vt] = time(() => JSON.parse(ring.verify_light(pv, binding)));
console.log(`verified against the proof in ${vt.toFixed(0)} ms:`, JSON.stringify({ blocks: v.blocks, transactions: v.transactions, light: v.light, authenticated_to: v.authenticated_to }));
expect("light blocks are the proven range", v.light[0] === light.light[0] && v.light[1] === light.light[1]);

const full = new RingFile(read(light.full_file));
const fv = JSON.parse(full.verify());
expect("same transactions, work and last block as the full Ring", fv.transactions === v.transactions && fv.work === v.work && fv.last_hash === v.last_hash);
expect("a light block shows its record", JSON.parse(ring.block(light.light[0])).light === true);
expect("records match the full Ring's", Buffer.compare(Buffer.from(ring.records(light.light[0], light.light[1])), Buffer.from(full.records(light.light[0], light.light[1]))) === 0);

const noProof = refused(() => ring.verify());
console.log("without the proof:", noProof);
expect("a light Ring needs a proof", /no history proof vouches/.test(noProof));
const b = JSON.parse(binding);
b.paths[0][0] = "00".repeat(32);
const badBinding = refused(() => ring.verify_light(pv, JSON.stringify(b)));
console.log("altered binding:", badBinding);
expect("an altered binding is refused", /no history proof vouches/.test(badBinding));
const otherProof = JSON.parse(readFileSync(new URL("../../../data/publish/nu7-shard0/history.json", import.meta.url)));
const otherPv = readFileSync(new URL(`../../../data/publish/nu7-shard0/${otherProof.public_values}`, import.meta.url));
const wrongProof = refused(() => ring.verify_light(otherPv, binding));
console.log("another proof's claim:", wrongProof);
expect("another proof's claim is refused", wrongProof !== "ACCEPTED");
const fake = refused(() => ring.attacked("inject", light.light[0] + 500, undefined).verify_light(pv, binding));
console.log("fake note in a light block:", fake);
expect("a fake note in a light block is refused", /rebuilt ID does not match/.test(fake));
process.exit(failed ? 1 : 0);
