"use strict";

/*
 * BRIDGE — OFFLINE mapping (UNIT). Always runs (needs NO compiled
 * toolchain). Exercises the bridge's pure mapping/classification/fail-closed
 * behaviour against BUILDER-OUTPUT-SHAPED objects that mirror EXACTLY what
 * sdk/src/vault-builders-v4.js emits (captured from real builds: agentSpend
 * outputs [payment, successor(, change)], owner ops [successor, change],
 * the §E4 11-field accounting, the callExtra agent leaf + co-path). The
 * real-toolchain proof lives in derive-real-builder.test.js; this file pins
 * the derivation logic, numeric safety, and the G-2 storage-representation
 * regression deterministically and fast.
 *
 * The agent-leaf co-path here is a REAL single-leaf fold (a depth-0 tree:
 * the successor agentRoot IS the updated leaf hash), computed with the real
 * sdk/src/agent-merkle-v4.js — so the bridge's fold cross-check is genuine.
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");

const { deriveManifestFromV4Build, deriveBuildInputs, deriveRequestedIntent, deriveAndVerify, SUPPORTED_BUILD_VERSIONS } = require("../derive");
const { computeManifestHashV1 } = require("../../canonical");
const { VERDICTS } = require("../../verify");

/* Builder-output-shaped fixtures (shared with derive-pg-jsonb.test.js);
 * their agent leaf/root are a REAL depth-0 agent-merkle-v4 fold. */
const { HEX, AGENT, RECIP_ROOT, VAULT_ID, TXID, NETWORK, VERSION, spendBuild, ownerTopUpBuild } = require("../testutil/builds");

const clone = (v) => JSON.parse(JSON.stringify(v));

test("bridge exports the supported v0.4-family versions", () => {
  assert.deepEqual([...SUPPORTED_BUILD_VERSIONS].sort(), ["policyvault-0.4", "policyvault-0.4.1"]);
});

test("faithful derivation of a builder-shaped agentSpend -> VERIFIED_EXACT", () => {
  const { manifest, verification } = deriveAndVerify({ build: spendBuild() });
  assert.equal(verification.verdict, VERDICTS.VERIFIED_EXACT, JSON.stringify(verification.failures));
  assert.deepEqual(manifest.effects.outputs.map((e) => e.kind), ["payment", "successor"]);
  assert.equal(manifest.payment.outputIndex, 0);
  assert.equal(manifest.stateAfter.expectedOutpoint.index, 1);
  assert.equal(manifest.limits.policyAfter.periodSpent, "1500000000");
});

test("faithful derivation of a builder-shaped ownerTopUp -> VERIFIED_EXACT", () => {
  const { manifest, verification } = deriveAndVerify({ build: ownerTopUpBuild() });
  assert.equal(verification.verdict, VERDICTS.VERIFIED_EXACT, JSON.stringify(verification.failures));
  assert.deepEqual(manifest.effects.outputs.map((e) => e.kind), ["successor", "change"]);
  assert.equal(deriveRequestedIntent(ownerTopUpBuild()).params.topUpAmountSompi, "5000000000");
});

test("fold cross-check: a wrong successor agentRoot fails closed (BRIDGE_LEAF_FOLD_MISMATCH)", () => {
  const b = spendBuild();
  b.successorState.agentRoot = HEX("99"); // does not equal fold(policyAfter)
  assert.throws(() => deriveManifestFromV4Build({ build: b }), (e) => e.code === "BRIDGE_LEAF_FOLD_MISMATCH");
});

test("unknown build.kind fails closed", () => {
  assert.throws(() => deriveManifestFromV4Build({ build: { kind: "teleport", contractVersion: VERSION } }), (e) => e.code === "BRIDGE_BUILD_INVALID");
});

test("unknown covenant version fails closed (never routed to a default)", () => {
  const b = spendBuild();
  b.contractVersion = "policyvault-0.3";
  assert.throws(() => deriveManifestFromV4Build({ build: b }), (e) => e.code === "BRIDGE_UNSUPPORTED_VERSION");
});

test("numeric safety: a float/NaN sneaked into a build value is refused before arithmetic", () => {
  const b = spendBuild();
  b.callExtra.payAmount = 1e9; // a JS number, not a canonical digit string
  assert.throws(() => deriveManifestFromV4Build({ build: b }), (e) => e.code === "BRIDGE_VALUE_INVALID");
  const b2 = spendBuild();
  b2.callExtra.periodStartDaa = "0x10"; // non-decimal
  b2.callExtra.periodsElapsed = "1";
  assert.throws(() => deriveManifestFromV4Build({ build: b2 }), (e) => e.code === "BRIDGE_VALUE_INVALID" || e.code === "BRIDGE_LEAF_FOLD_MISMATCH");
});

test("a missing builder field fails closed rather than guessing", () => {
  const b = spendBuild();
  delete b.payment;
  assert.throws(() => deriveManifestFromV4Build({ build: b }), (e) => e.code === "BRIDGE_BUILD_INVALID");
});

/* ---- G-2 storage-representation regression (jsonb key reorder) ---- */
function deepReorderKeys(value) {
  if (Array.isArray(value)) return value.map(deepReorderKeys);
  if (value !== null && typeof value === "object") {
    const out = {};
    for (const k of Object.keys(value).reverse()) out[k] = deepReorderKeys(value[k]);
    return out;
  }
  return value;
}

test("G-2: derived manifest hash is stable under JSON round-trip AND deep key reorder", () => {
  for (const build of [spendBuild(), ownerTopUpBuild()]) {
    const m = deriveManifestFromV4Build({ build });
    const body = { ...m };
    delete body.manifestHash;
    assert.equal(computeManifestHashV1(JSON.parse(JSON.stringify(body))), m.manifestHash, "JSON round-trip drift");
    assert.equal(computeManifestHashV1(deepReorderKeys(body)), m.manifestHash, "jsonb-class key-reorder drift");
    /* the reordered manifest still verifies EXACT (representation-independent) */
    const reordered = deepReorderKeys(clone(m));
    const { verifyIntentManifest } = require("../../verify");
    assert.equal(verifyIntentManifest({ manifest: reordered }).verdict, VERDICTS.VERIFIED_EXACT);
  }
});

test("deriveBuildInputs binds requested intent, transaction, and vault identity from the build", () => {
  const inputs = deriveBuildInputs({ build: spendBuild() });
  assert.equal(inputs.network.networkId, NETWORK);
  assert.equal(inputs.vault.vaultId, VAULT_ID);
  assert.equal(inputs.vault.covenantVersion, VERSION);
  assert.equal(inputs.transaction.txId, TXID);
  assert.equal(inputs.signerXOnly, AGENT);
  assert.equal(inputs.allowlist.agentRecipientRoot, RECIP_ROOT);
});
