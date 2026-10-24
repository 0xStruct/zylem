// Generation 1 client rule: checks verify_history_v2's registry checks on a published
// directory. With a real proof (PROOF_IS_REAL=1) the pinned case must pass; with a mock
// proof it must get past every registry check and fail only at the STARK verifier.
//
//   node test-registry.mjs PUBLISH_DIR [REVOKED_REGISTRY_JSON]
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { registry_root, verify_history_v2 } from "./pkg-node/zylem_wasm_verify.js";

const dir = process.argv[2];
const revokedPath = process.argv[3];
const real = process.env.PROOF_IS_REAL === "1";
const h = JSON.parse(readFileSync(join(dir, "history.json"), "utf8"));
const proof = readFileSync(join(dir, h.proof));
const pv = readFileSync(join(dir, h.public_values));
const registry = readFileSync(join(dir, h.programs.registry), "utf8");
const root = h.programs.root;
const trusted = JSON.stringify({ anchor: { height: h.anchor.height, hash: h.anchor.hash_internal, context_hash: h.anchor.context_hash } });

let failed = 0;
function expect(name, f, want) {
  let got;
  try {
    got = "ok " + f();
  } catch (e) {
    got = String(e.message ?? e);
  }
  const pass = want === "ok" ? got.startsWith("ok") : got.includes(want);
  if (!pass) failed++;
  console.log(`${pass ? "PASS" : "FAIL"} ${name}: ${got.slice(0, 160)}`);
}

const t0 = performance.now();
expect("pinned registry", () => verify_history_v2(proof, pv, registry, JSON.stringify([root]), trusted), real ? "ok" : "ProofRejected");
console.log(`  (${(performance.now() - t0).toFixed(1)} ms)`);
expect("unpinned registry", () => verify_history_v2(proof, pv, registry, JSON.stringify(["00".repeat(32)]), trusted), "UnpinnedRegistry");
const edited = JSON.parse(registry);
edited.entries[0].last = 4529000;
expect("edited registry", () => verify_history_v2(proof, pv, JSON.stringify(edited), JSON.stringify([root]), trusted), "UnpinnedRegistry");
expect("registry root matches the published one", () => {
  if (registry_root(registry) !== root) throw new Error(`registry_root ${registry_root(registry)} != ${root}`);
  return root.slice(0, 16);
}, "ok");
// A registry that does not allow the claim's aggregation key, pinned by its own root.
const noAgg = JSON.parse(registry);
noAgg.entries = noAgg.entries.filter((e) => e.kind !== "Aggregate");
const noAggJson = JSON.stringify(noAgg);
expect("aggregation key not registered", () => verify_history_v2(proof, pv, noAggJson, JSON.stringify([registry_root(noAggJson)]), trusted), "WrongAggregationProgram");
// A registry that grew by an allow after the proof: the proof's registry is a prefix.
const grown = JSON.parse(registry);
grown.entries.push({ ...grown.entries[0], era: 1, first: 584000, last: 4465025 });
const grownJson = JSON.stringify(grown);
expect("registry grown by an allow", () => verify_history_v2(proof, pv, grownJson, JSON.stringify([registry_root(grownJson)]), trusted), real ? "ok" : "ProofRejected");
// The same entries in another order: a different registry that still allows every key,
// so the proof's registry is not one of its earlier versions.
const foreign = JSON.parse(registry);
foreign.entries.reverse();
const foreignJson = JSON.stringify(foreign);
expect("claim made under a different registry", () => verify_history_v2(proof, pv, foreignJson, JSON.stringify([registry_root(foreignJson)]), trusted), "UnknownRegistry");
// Re-allowing a revoked aggregation key does not restore it.
const reallowed = JSON.parse(registry);
const agg = reallowed.entries.find((e) => e.kind === "Aggregate");
reallowed.entries.push({ ...agg, action: "Revoke", era: 255, first: 0 }, { ...agg });
const reallowedJson = JSON.stringify(reallowed);
expect("aggregation key revoked then allowed again", () => verify_history_v2(proof, pv, reallowedJson, JSON.stringify([registry_root(reallowedJson)]), trusted), "WrongAggregationProgram");
if (revokedPath) {
  const revoked = readFileSync(revokedPath, "utf8");
  const revokedRoot = JSON.parse(revoked).root;
  expect("revocation reaching the range", () => verify_history_v2(proof, pv, revoked, JSON.stringify([revokedRoot]), trusted), "StaleRegistry");
}
const badAnchor = JSON.stringify({ anchor: { height: h.anchor.height + 1, hash: h.anchor.hash_internal, context_hash: h.anchor.context_hash } });
expect("wrong anchor", () => verify_history_v2(proof, pv, registry, JSON.stringify([root]), badAnchor), real ? "WrongCheckpoint" : "ProofRejected");
console.log(failed ? `${failed} failed` : "all passed");
process.exit(failed ? 1 : 0);
