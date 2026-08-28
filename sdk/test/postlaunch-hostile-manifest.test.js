"use strict";

/*
 * POSTLAUNCH INTENT-MANIFEST INTEGRITY — HOSTILE FALSIFICATION SUITE
 * (docs/postlaunch/server-enforcement-falsification.md).
 *
 * Adversarial attempts against the browser/server-disagreement and
 * manifest-integrity invariant: a server that RECORDS manifest X must be
 * caught if the bytes it actually built/finalizes are anything else, and a
 * DB tamperer must not be able to slip a mutated or mismatched manifest
 * past the finalize/submit gate. The G-2 read-side rule is: every read of
 * a stored manifest recomputes computeManifestHashV1 over the stored body
 * and compares to the row key AND the embedded hash; canonical hashing is
 * over VALUES, so PostgreSQL jsonb key reordering re-hashes identically —
 * only a real value change (or a wrong binding) trips it.
 *
 * Complements sdk/test/postlaunch-audit-correlation.test.js (positive +
 * the payment-value G-2 tamper): this adds cross-request manifest
 * ownership binding, embedded-hash tamper, a NON-payment nested value
 * mutation, and a precise characterization of the honest backward-compat
 * seam (a stripped manifestHash is bounded by the covenant, never a
 * covenant bypass).
 *
 * Integer sompi / BigInt throughout.
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");
const os = require("os");

const { handle, loadConfig } = require("../../server/src/api");
const { buildAgentTreeV4, normalizeAgentPolicyV4 } = require("../src/agent-merkle-v4");
const { buildRecipientTree } = require("../src/recipient-merkle-v3");
const { normalizeStateV4, computeStateIdV4, stateToJsonV4, CONTRACT_VERSION_V4 } = require("../src/vault-state-v4");
const { compileExactStateV4 } = require("../src/contract-compiler-v4");
const { MANIFEST_SCHEMA_V4, persistManifestV4 } = require("../src/manifest-v4");
const { makeDevSigner } = require("../src/signer-dev");
const { assertRequestManifestVerified } = require("../../server/src/intent-records");

const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "pv-hostile-man-"));
const config = loadConfig({ dataRoot });
const kaspa = require(config.rustyKaspaModule);
const KEY = (v) => new kaspa.PrivateKey(v.toString(16).padStart(2, "0").repeat(32));
const SEC = (v) => v.toString(16).padStart(2, "0").repeat(32);
const XO = (p) => p.toPublicKey().toXOnlyPublicKey().toString().toLowerCase();
const ADDR = (p) => p.toPublicKey().toAddress(config.networkId).toString();
const KAS = 100000000n;

const owner = KEY(1);
const agentA = KEY(0x1e);
const recipient = KEY(0x28);

const REGISTRY = [
  {
    agentPk: XO(agentA), maxPerSpend: (20n * KAS).toString(), periodBudget: (50n * KAS).toString(),
    periodLengthDaa: "864000", periodStartDaa: "541000000", periodSpent: "0",
    approvalThreshold: (50n * KAS).toString(), agentMaxFeePerTx: (1n * KAS).toString(), recipients: [XO(recipient)]
  }
];

let seedCounter = 0;
async function seed(vaultId) {
  seedCounter += 1;
  const outTxId = (0x60 + seedCounter).toString(16).padStart(2, "0").repeat(32).slice(0, 64);
  const template = { owner: XO(owner), vaultId };
  const policies = REGISTRY.map((e) => normalizeAgentPolicyV4({ ...e, agentRecipientRoot: buildRecipientTree(e.recipients).root }));
  const state = normalizeStateV4({ protectedValue: (1000n * KAS).toString(), feeReserve: (5n * KAS).toString(), paused: "0", agentRoot: buildAgentTreeV4(policies).root, approvers: [], approvalM: "0", policyNonce: "0" });
  const compiled = compileExactStateV4({ config, template, state });
  const stateId = computeStateIdV4({ networkId: config.networkId, template, state });
  return await persistManifestV4(config, {
    schema: MANIFEST_SCHEMA_V4, contractVersion: CONTRACT_VERSION_V4, networkId: config.networkId, vaultId,
    label: "hostile-manifest", status: "ACTIVE", template, agentRegistry: REGISTRY,
    live: { state: stateToJsonV4(state), stateId, outpoint: { transactionId: outTxId, index: 0 }, outpointValue: (state.protectedValue + state.feeReserve).toString(), scriptSha256: compiled.scriptSha256, covenantId: "41".repeat(32) },
    creationTxId: "42".repeat(32), latestTransitionTxId: null, lastTransition: null
  });
}

const POST = (segs, body) => handle(config, "POST", segs, {}, body);
const GET = (segs) => handle(config, "GET", segs, {}, null);
async function expectThrow(promise, status, code) {
  try {
    await promise;
    assert.fail("expected an API error");
  } catch (e) {
    if (e.code === "ERR_ASSERTION") throw e;
    if (status !== undefined) assert.equal(e.status, status, `status ${e.status} != ${status}: ${e.message}`);
    if (code !== undefined) assert.equal(e.code, code, `code ${e.code} != ${code}: ${e.message}`);
    return e;
  }
}
function devSignAll(request) {
  const signer = makeDevSigner(config, { secretHex: SEC(0x1e), expectedAddress: ADDR(agentA) });
  return signer.signInputs(request.transaction.unsignedSafeJson, request.transaction.signInputs);
}
const spend = (vaultId, amountKas) => POST(["wallet", "v4", "requests"], {
  vaultId, action: "agentSpend", params: { payAmountSompi: (amountKas * KAS).toString(), agentPk: XO(agentA), recipient: XO(recipient) }, signerAddress: ADDR(agentA)
});
const manifestFile = (hash) => path.join(dataRoot, "manifests", `${hash}.json`);
const requestFile = (id) => path.join(dataRoot, "requests", `${id}.json`);

/* -------------------------------------------------------------------- */
/* 1. CROSS-REQUEST manifest ownership binding                           */
/* -------------------------------------------------------------------- */
test("a request's manifestHash cannot be repointed at ANOTHER request's valid manifest — the finalize gate binds requestId+vaultId (INTENT_MANIFEST_INTEGRITY)", async () => {
  const V = "c1".repeat(32);
  await seed(V);
  const r1 = (await spend(V, 3n)).body.request;
  const r2 = (await spend(V, 4n)).body.request;
  assert.notEqual(r1.manifestHash, r2.manifestHash);
  // DB tamper: point r2 at r1's real, VERIFIED manifest record.
  const stored2 = JSON.parse(fs.readFileSync(requestFile(r2.requestId), "utf8"));
  stored2.manifestHash = r1.manifestHash;
  fs.writeFileSync(requestFile(r2.requestId), JSON.stringify(stored2));
  // The record recomputes/re-hashes fine (it is r1's genuine manifest), but it does
  // not BELONG to r2 -> integrity alarm at the finalize gate.
  const signed = devSignAll(r2);
  await expectThrow(POST(["wallet", "v4", "requests", r2.requestId, "signature"], { signedSafeJson: signed }), 409, "INTENT_MANIFEST_INTEGRITY");
  // …and at the function level, exactly the same refusal (requestId mismatch).
  await assert.rejects(
    () => assertRequestManifestVerified(config, JSON.parse(fs.readFileSync(requestFile(r2.requestId), "utf8"))),
    (e) => e.code === "INTENT_MANIFEST_INTEGRITY" && e.status === 409
  );
});

/* -------------------------------------------------------------------- */
/* 2. EMBEDDED-HASH tamper (row key preserved, embedded hash changed)    */
/* -------------------------------------------------------------------- */
test("a stored manifest whose EMBEDDED manifestHash is edited (body otherwise unchanged) fails closed on read AND at finalize (INTENT_MANIFEST_INTEGRITY)", async () => {
  const V = "c2".repeat(32);
  await seed(V);
  const req = (await spend(V, 3n)).body.request;
  const file = manifestFile(req.manifestHash);
  const record = JSON.parse(fs.readFileSync(file, "utf8"));
  record.manifest.manifestHash = "cd".repeat(32); // embedded hash no longer equals the row key / recompute
  fs.writeFileSync(file, JSON.stringify(record));
  await expectThrow(GET(["manifests", req.manifestHash]), 409, "INTENT_MANIFEST_INTEGRITY");
  const signed = devSignAll(req);
  await expectThrow(POST(["wallet", "v4", "requests", req.requestId, "signature"], { signedSafeJson: signed }), 409, "INTENT_MANIFEST_INTEGRITY");
});

/* -------------------------------------------------------------------- */
/* 3. NON-payment nested value mutation (complements the payment G-2)    */
/* -------------------------------------------------------------------- */
test("a mutation to a NON-payment committed value (the recorded requested action) also fails the read-side re-hash (INTENT_MANIFEST_INTEGRITY)", async () => {
  const V = "c3".repeat(32);
  await seed(V);
  const req = (await spend(V, 3n)).body.request;
  const file = manifestFile(req.manifestHash);
  const record = JSON.parse(fs.readFileSync(file, "utf8"));
  assert.equal(record.manifest.requested.action, "agentSpend");
  record.manifest.requested.action = "ownerRecover"; // a value the manifest commits to
  fs.writeFileSync(file, JSON.stringify(record));
  await expectThrow(GET(["manifests", req.manifestHash]), 409, "INTENT_MANIFEST_INTEGRITY");
  const signed = devSignAll(req);
  await expectThrow(POST(["wallet", "v4", "requests", req.requestId, "signature"], { signedSafeJson: signed }), 409, "INTENT_MANIFEST_INTEGRITY");
});

/* -------------------------------------------------------------------- */
/* 4. jsonb-style key REORDER of the stored manifest re-hashes EQUAL      */
/*    (canonical hashing over values — no false positive on reorder)     */
/* -------------------------------------------------------------------- */
test("a key-reordered stored manifest (the jsonb representation change) re-hashes IDENTICALLY and still verifies — only real value changes trip G-2", async () => {
  const V = "c4".repeat(32);
  await seed(V);
  const req = (await spend(V, 3n)).body.request;
  const file = manifestFile(req.manifestHash);
  const record = JSON.parse(fs.readFileSync(file, "utf8"));
  // Rebuild the manifest object with REVERSED top-level key order (models a jsonb round-trip).
  const reordered = {};
  for (const k of Object.keys(record.manifest).reverse()) reordered[k] = record.manifest[k];
  record.manifest = reordered;
  fs.writeFileSync(file, JSON.stringify(record));
  const read = await GET(["manifests", req.manifestHash]);
  assert.equal(read.status, 200, "the reordered manifest still reads");
  assert.equal(read.body.liveVerification.ok, true, "and re-verifies VERIFIED_EXACT");
  const signed = devSignAll(req);
  const done = await POST(["wallet", "v4", "requests", req.requestId, "signature"], { signedSafeJson: signed });
  assert.equal(done.status, 200);
  assert.equal(done.body.request.state, "PREFLIGHT_VERIFIED");
});

/* -------------------------------------------------------------------- */
/* 5. BACKWARD-COMPAT SEAM — characterized precisely and bounded          */
/* -------------------------------------------------------------------- */
test("the honest predates-recording seam is precise: FAILED marker refuses, dangling hash refuses (MISSING), foreign-owned record refuses (INTEGRITY); only a truly stamp-free request passes as pre-upgrade", async () => {
  const V = "c5".repeat(32);
  await seed(V);
  const req = (await spend(V, 3n)).body.request;

  // (a) intentRecording=FAILED can NEVER be mistaken for a pre-upgrade request.
  await assert.rejects(
    () => assertRequestManifestVerified(config, { requestId: req.requestId, vaultId: V, intentRecording: "FAILED" }),
    (e) => e.code === "INTENT_VERIFICATION_FAILED" && e.status === 409
  );
  // (b) a dangling (valid-format, nonexistent) manifestHash fails closed.
  await assert.rejects(
    () => assertRequestManifestVerified(config, { requestId: req.requestId, vaultId: V, manifestHash: "ab".repeat(32) }),
    (e) => e.code === "INTENT_MANIFEST_MISSING" && e.status === 409
  );
  // (c) a request whose manifestHash points at a record owned by a DIFFERENT request fails closed.
  const r2 = (await spend(V, 4n)).body.request;
  await assert.rejects(
    () => assertRequestManifestVerified(config, { requestId: req.requestId, vaultId: V, manifestHash: r2.manifestHash }),
    (e) => e.code === "INTENT_MANIFEST_INTEGRITY" && e.status === 409
  );
  // (d) ONLY a request with neither marker nor manifestHash passes as honestly pre-upgrade.
  //     This is the documented, BOUNDED seam: such a request still carries its own frozen
  //     transaction bytes, and finalize/submit independently re-verify the wallet signature
  //     and run the covenant VM preflight — the manifest gate is defense in depth ABOVE the
  //     covenant, so a stripped stamp degrades that depth but never bypasses consensus.
  assert.equal(await assertRequestManifestVerified(config, { requestId: req.requestId, vaultId: V }), null);
});
