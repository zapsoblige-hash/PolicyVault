"use strict";
/*
 * Codex checkpoint 3 (UX-02) — the exact v0.7 root locking-script
 * reconstruction (core/intent/root-script-v7.js): pure data + pure functions
 * the browser uses to bind a genesis output to the rules the owner reviewed.
 *   • the minimal script-number push encoder (what silverc emits)
 *   • the skeleton pin (sha256 over chunks + holes)
 *   • byte-for-byte reproduction of a REAL silverc-compiled root script from a
 *     REAL testnet-10 genesis (fixture) and of its P2SH scriptPublicKey
 *   • determinism, refusal of a state whose bound org id != template org id
 * The silverc cross-check across a value matrix lives in
 * sdk/test/root-script-v7-reconstruction.test.js (needs the vendored compiler).
 */
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const R = require("../root-script-v7");
const { genesisRootStateV7, normalizeRootTemplateV7 } = require("../../model/vault-state-v7-root");
const { normalizeOwnerSetV7 } = require("../../model/owner-set-v7");

const FIX = JSON.parse(fs.readFileSync(path.join(__dirname, "fixtures", "v7-root-genesis-script-sample.json"), "utf8"));

test("pushScriptNumHex: minimal script-number pushes (OP_0, OP_1..OP_16, OP_DATA_n + LE with sign pad)", () => {
  assert.equal(R.pushScriptNumHex(0), "00");
  assert.equal(R.pushScriptNumHex(1), "51");
  assert.equal(R.pushScriptNumHex(16), "60");
  assert.equal(R.pushScriptNumHex(17), "0111");
  assert.equal(R.pushScriptNumHex(127), "017f");
  assert.equal(R.pushScriptNumHex(128), "028000");
  assert.equal(R.pushScriptNumHex(255), "02ff00");
  assert.equal(R.pushScriptNumHex(256), "020001");
  assert.equal(R.pushScriptNumHex(38880000), "0400435102");
  assert.equal(R.pushScriptNumHex(2147483647), "04ffffff7f");
  assert.equal(R.pushScriptNumHex(2147483648), "050000008000");
  assert.equal(R.pushScriptNumHex(4294967295n), "05ffffffff00");
  assert.throws(() => R.pushScriptNumHex(-1), (e) => e.code === "ROOT_SCRIPT_INVALID");
  assert.equal(R.pushBytes32Hex("ab".repeat(32)), "20" + "ab".repeat(32));
  assert.throws(() => R.pushBytes32Hex("ab"), (e) => e.code === "ROOT_SCRIPT_INVALID");
});

test("skeleton pin: 13 chunks around 12 holes (maxFee ×4, recovery ×1, scriptLen ×4, successorPk ×2, succession ×1); the sha256 is pinned", () => {
  assert.equal(R.ROOT_SCRIPT_CHUNKS_V7.length, 13);
  assert.deepEqual([...R.ROOT_SCRIPT_HOLES_V7], ["rootMaxFeePerTx", "rootMaxFeePerTx", "recoveryDelayDaa", "scriptLen", "scriptLen", "successorPk", "successorPk", "successionDelayDaa", "rootMaxFeePerTx", "rootMaxFeePerTx", "scriptLen", "scriptLen"]);
  const digest = crypto.createHash("sha256").update(R.ROOT_SCRIPT_CHUNKS_V7.join("|") + "#" + R.ROOT_SCRIPT_HOLES_V7.join(",")).digest("hex");
  assert.equal(digest, R.ROOT_SCRIPT_SKELETON_SHA256_V7);
  assert.equal(R.ROOT_SCRIPT_PREFIX_HEX_V7, "6b");
  assert.ok(Object.isFrozen(R) && Object.isFrozen(R.ROOT_SCRIPT_CHUNKS_V7));
});

test("reproduces a REAL silverc-compiled root script and its P2SH scriptPublicKey byte for byte (real testnet-10 genesis fixture)", () => {
  const template = normalizeRootTemplateV7(FIX.template);
  const ownerSet = normalizeOwnerSetV7(FIX.ownerSet);
  const state = genesisRootStateV7({ template, ownerSet });
  const script = R.reconstructRootScriptHexV7({ template, state });
  assert.equal(script.length, FIX.scriptHex.length);
  assert.equal(script, FIX.scriptHex.toLowerCase());
  assert.equal(script.slice(0, 2), "6b");
  assert.equal(1 + 467 + (script.length / 2 - 468), FIX.rootPins.rootPrefixLen + FIX.rootPins.rootStateLen + FIX.rootPins.rootSuffixLen);
  const spk = R.genesisRootSpkHexV7({ template: FIX.template, ownerSet: FIX.ownerSet });
  assert.equal("0000" + spk, FIX.rootOutputSpkHex.toLowerCase(), "the genesis output's P2SH is the hash of the reconstructed script");
  assert.equal(R.p2shSpkHexOf(script), spk);
});

test("determinism + refusals: same rules -> same script; a different M/K/R, owner, waiting period, successor or fee cap -> a different P2SH; org id mismatch refuses", () => {
  const a = R.genesisRootSpkHexV7({ template: FIX.template, ownerSet: FIX.ownerSet });
  assert.equal(R.genesisRootSpkHexV7({ template: FIX.template, ownerSet: FIX.ownerSet }), a);
  const variants = [
    { ownerSet: { ...FIX.ownerSet, ownerM: "1" } },
    { ownerSet: { ...FIX.ownerSet, owners: FIX.ownerSet.owners.map((o, i) => (i === 0 ? "e1".repeat(32) : o)) } },
    { template: { ...FIX.template, recoveryDelayDaa: "1" } },
    { template: { ...FIX.template, successionDelayDaa: "4294967295" } },
    { template: { ...FIX.template, successorPk: "e2".repeat(32) } },
    { template: { ...FIX.template, rootMaxFeePerTx: "0" } }
  ];
  const seen = new Set([a]);
  for (const v of variants) { const spk = R.genesisRootSpkHexV7({ template: v.template || FIX.template, ownerSet: v.ownerSet || FIX.ownerSet }); assert.ok(!seen.has(spk), JSON.stringify(v).slice(0, 80)); seen.add(spk); }
  const template = normalizeRootTemplateV7(FIX.template);
  const state = genesisRootStateV7({ template, ownerSet: normalizeOwnerSetV7(FIX.ownerSet) });
  assert.throws(() => R.reconstructRootScriptHexV7({ template: { ...FIX.template, orgId: "e3".repeat(32) }, state }), (e) => e.code === "ORG_ID_MISMATCH");
});
