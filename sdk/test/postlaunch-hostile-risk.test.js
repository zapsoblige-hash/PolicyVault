"use strict";

/*
 * POSTLAUNCH OPERATIONAL RISK PIPELINE — HOSTILE FALSIFICATION SUITE
 * (docs/postlaunch/server-enforcement-falsification.md).
 *
 * Adversarial attempts to convert the RESTRICTIVE-ONLY risk pipeline into
 * a source of authority, or to neutralize/replay a REVIEW hold. Invariant
 * (2), restated: a risk ALLOW authorizes NOTHING — the SDK build (covenant
 * rules) and ultimately Kaspa consensus decide independently — and no
 * adapter error, timeout, malformed verdict, config tamper, or hold replay
 * may yield a silent permission. Every attempt below must fail closed or
 * be refused by the covenant path.
 *
 * Complements sdk/test/postlaunch-risk-server.test.js (the positive
 * suite): this adds risk-ALLOW-cannot-rescue-a-covenant-DENY at the server
 * boundary, cross-vault hold binding, DENIED-eval-not-releasable,
 * DB-tampered permissive-config refusal, the covenant cap bounding even a
 * legitimately released hold, and the read-side hold-integrity regression
 * (RISK_EVALUATION_INTEGRITY — the hardening this pass added).
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
const org = require("../src/organization");
const { saveOrgControls, loadOrgControls } = require("../../server/src/org-controls");
const riskSvc = require("../../server/src/risk");

const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "pv-hostile-risk-"));
const config = loadConfig({ dataRoot });
const kaspa = require(config.rustyKaspaModule);
const KEY = (v) => new kaspa.PrivateKey(v.toString(16).padStart(2, "0").repeat(32));
const XO = (p) => p.toPublicKey().toXOnlyPublicKey().toString().toLowerCase();
const ADDR = (p) => p.toPublicKey().toAddress(config.networkId).toString();
const KAS = 100000000n;

const owner = KEY(1);
const agentA = KEY(0x1e);
const recipient = KEY(0x28);
const other = KEY(0x29); // a valid x-only NOT in agentA's covenant recipient set
const unreg = KEY(0x77); // a key that is NOT a registered agent

function agentEntry(kp, recipients) {
  return {
    agentPk: XO(kp), maxPerSpend: (20n * KAS).toString(), periodBudget: (50n * KAS).toString(),
    periodLengthDaa: "864000", periodStartDaa: "541000000", periodSpent: "0",
    approvalThreshold: (50n * KAS).toString(), agentMaxFeePerTx: (1n * KAS).toString(),
    recipients: recipients.map(XO)
  };
}

let seedCounter = 0;
async function seed(vaultId, registry) {
  seedCounter += 1;
  const outTxId = (0x40 + seedCounter).toString(16).padStart(2, "0").repeat(32).slice(0, 64);
  const template = { owner: XO(owner), vaultId };
  const policies = registry.map((e) => normalizeAgentPolicyV4({ ...e, agentRecipientRoot: buildRecipientTree(e.recipients).root }));
  const state = normalizeStateV4({ protectedValue: (1000n * KAS).toString(), feeReserve: (5n * KAS).toString(), paused: "0", agentRoot: buildAgentTreeV4(policies).root, approvers: [], approvalM: "0", policyNonce: "0" });
  const compiled = compileExactStateV4({ config, template, state });
  const stateId = computeStateIdV4({ networkId: config.networkId, template, state });
  return await persistManifestV4(config, {
    schema: MANIFEST_SCHEMA_V4, contractVersion: CONTRACT_VERSION_V4, networkId: config.networkId, vaultId,
    label: "hostile-risk", status: "ACTIVE", template, agentRegistry: registry,
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
const requestFiles = () => (fs.existsSync(path.join(dataRoot, "requests")) ? fs.readdirSync(path.join(dataRoot, "requests")) : []);
const controlsFile = (orgId) => path.join(dataRoot, "org-controls", `${orgId}.json`);
const evalFile = (id) => path.join(dataRoot, "risk", "evaluations", `${id}.json`);

async function newOrgForVault(vaultId, name) {
  const created = await org.createOrganization(config, { name });
  const assignments = await org.loadAssignments(config);
  await org.assignVault(config, { vaultId, orgId: created.orgId, group: null, expectedVersion: assignments.version, vaultExists: async () => true });
  return created.orgId;
}
async function setControls(orgId, risk) {
  const cur = await loadOrgControls(config, orgId);
  return saveOrgControls(config, orgId, { governance: {}, risk, expectedVersion: cur ? cur.version : 0 });
}
const spendBody = (vaultId, amountKas, over = {}) => ({
  vaultId, action: "agentSpend",
  params: { payAmountSompi: (amountKas * KAS).toString(), agentPk: XO(agentA), recipient: XO(recipient) },
  signerAddress: ADDR(agentA), ...over
});

/* -------------------------------------------------------------------- */
/* 1. A risk ALLOW cannot rescue a covenant DENY (invariant 2, server)   */
/* -------------------------------------------------------------------- */
test("a risk ALLOW never converts a covenant DENY into permission: a recipient the allowlist ALLOWs but the covenant does not authorize still refuses at the build (no durable request)", async () => {
  const V = "b1".repeat(32);
  await seed(V, [agentEntry(agentA, [recipient])]); // covenant recipient set = {recipient} ONLY
  const orgId = await newOrgForVault(V, "risk-allow org");
  // The org risk allowlist explicitly ALLOWs `other` — layered ABOVE the covenant Merkle allowlist.
  await setControls(orgId, { adapters: [{ type: "recipient-allowlist", params: { allowedRecipients: [XO(recipient), XO(other)], unknownRecipient: "DENY" } }] });
  const before = requestFiles().length;
  // spend to `other`: risk ALLOWs it, but `other` is not in the agent's covenant recipient set.
  await expectThrow(POST(["wallet", "v4", "requests"], spendBody(V, 1n, { params: { payAmountSompi: (1n * KAS).toString(), agentPk: XO(agentA), recipient: XO(other) } })), 422, "BUILD_FAILED");
  assert.equal(requestFiles().length, before, "a risk ALLOW manufactured no durable request past the covenant refusal");
});

test("a risk ALLOW cannot manufacture agent authority: an unregistered agent with a permissive amount-threshold still refuses at the build", async () => {
  const V = "b2".repeat(32);
  await seed(V, [agentEntry(agentA, [recipient])]);
  const orgId = await newOrgForVault(V, "risk-allow org 2");
  await setControls(orgId, { adapters: [{ type: "amount-threshold", params: { denyAboveSompi: (1000n * KAS).toString() } }] }); // ALLOWs anything below 1000 KAS
  const before = requestFiles().length;
  await expectThrow(
    POST(["wallet", "v4", "requests"], { vaultId: V, action: "agentSpend", params: { payAmountSompi: (1n * KAS).toString(), agentPk: XO(unreg), recipient: XO(recipient) }, signerAddress: ADDR(unreg) }),
    422, "BUILD_FAILED"
  );
  assert.equal(requestFiles().length, before);
});

/* -------------------------------------------------------------------- */
/* 2. A released REVIEW hold is bound to its exact vault                  */
/* -------------------------------------------------------------------- */
test("a released hold is bound to its vault: consuming a V1 release on a DIFFERENT vault V2 is refused (existence hidden)", async () => {
  const V1 = "b3".repeat(32);
  const V2 = "b4".repeat(32);
  await seed(V1, [agentEntry(agentA, [recipient])]);
  await seed(V2, [agentEntry(agentA, [recipient])]);
  const org1 = await newOrgForVault(V1, "hold org 1");
  const org2 = await newOrgForVault(V2, "hold org 2");
  await setControls(org1, { adapters: [{ type: "static-verdict", params: { verdict: "REVIEW" } }] });
  await setControls(org2, { adapters: [{ type: "static-verdict", params: { verdict: "REVIEW" } }] });
  // a V1 hold, released
  const held = await expectThrow(POST(["wallet", "v4", "requests"], spendBody(V1, 1n)), 409, "RISK_REVIEW_REQUIRED");
  const evId = held.extra.riskEvaluation.evaluationId;
  await POST(["risk", "evaluations", evId, "release"], {});
  // riskEvaluationId at the body TOP LEVEL (as the real client sends it)
  await expectThrow(POST(["wallet", "v4", "requests"], spendBody(V2, 1n, { riskEvaluationId: evId })), 404, "RISK_EVALUATION_NOT_FOUND");
});

/* -------------------------------------------------------------------- */
/* 3. DENY is a pure refusal and a DENIED eval is not a release          */
/* -------------------------------------------------------------------- */
test("a risk DENY mutates nothing (no durable request) and a DENIED evaluation can never be replayed as an authorizing release", async () => {
  const V = "b5".repeat(32);
  await seed(V, [agentEntry(agentA, [recipient])]);
  const orgId = await newOrgForVault(V, "deny org");
  await setControls(orgId, { adapters: [{ type: "amount-threshold", params: { denyAboveSompi: (10n * KAS).toString() } }] });
  const before = requestFiles().length;
  const e = await expectThrow(POST(["wallet", "v4", "requests"], spendBody(V, 11n)), 403, "RISK_DENIED");
  assert.equal(requestFiles().length, before, "a DENY created no durable request");
  const denyEvId = e.extra.riskEvaluation.evaluationId;
  assert.equal((await GET(["risk", "evaluations", denyEvId])).body.evaluation.status, "DENIED");
  // passing the DENIED evaluation as a release is refused (only a RELEASED hold authorizes)
  await expectThrow(POST(["wallet", "v4", "requests"], spendBody(V, 11n, { riskEvaluationId: denyEvId })), 409, "RISK_EVALUATION_NOT_RELEASED");
});

/* -------------------------------------------------------------------- */
/* 4. A DB tamperer cannot inject a PERMISSIVE risk configuration        */
/* -------------------------------------------------------------------- */
test("a stored risk config edited to a permissive/contradictory shape fails closed on load (onAdapterError ALLOW and reviewRequired+onEmpty ALLOW both refuse the operation)", async () => {
  const V = "b6".repeat(32);
  await seed(V, [agentEntry(agentA, [recipient])]);
  const orgId = await newOrgForVault(V, "config tamper org");
  await setControls(orgId, { adapters: [{ type: "static-verdict", params: { verdict: "REVIEW" } }], onAdapterError: "REVIEW" });

  // Tamper A: onAdapterError -> ALLOW (an erroring control resolving permissive).
  let rec = JSON.parse(fs.readFileSync(controlsFile(orgId), "utf8"));
  rec.risk.onAdapterError = "ALLOW";
  fs.writeFileSync(controlsFile(orgId), JSON.stringify(rec));
  await expectThrow(POST(["wallet", "v4", "requests"], spendBody(V, 1n)), 422, "CONTROLS_INVALID");

  // Tamper B: reviewRequired=true with onEmpty=ALLOW and no adapters (silently allow with nothing configured).
  rec = JSON.parse(fs.readFileSync(controlsFile(orgId), "utf8"));
  rec.risk = { adapters: [], reviewRequired: true, onEmpty: "ALLOW" };
  fs.writeFileSync(controlsFile(orgId), JSON.stringify(rec));
  await expectThrow(POST(["wallet", "v4", "requests"], spendBody(V, 1n)), 422, "RISK_CONFIG_CONFLICT");
});

/* -------------------------------------------------------------------- */
/* 5. Even a legitimately-released hold cannot cross the covenant cap     */
/* -------------------------------------------------------------------- */
test("bounded coordination: a legitimately released REVIEW hold for an over-cap spend still refuses at the covenant build (risk sits ABOVE the covenant, never beneath it)", async () => {
  const V = "b7".repeat(32);
  await seed(V, [agentEntry(agentA, [recipient])]); // maxPerSpend = 20 KAS
  const orgId = await newOrgForVault(V, "bound org");
  await setControls(orgId, { adapters: [{ type: "amount-threshold", params: { reviewAboveSompi: (5n * KAS).toString() } }] });
  // 25 KAS > maxPerSpend: risk only knows the review line, so it holds for review…
  const held = await expectThrow(POST(["wallet", "v4", "requests"], spendBody(V, 25n)), 409, "RISK_REVIEW_REQUIRED");
  const evId = held.extra.riskEvaluation.evaluationId;
  await POST(["risk", "evaluations", evId, "release"], {}); // a human releases the EXACT reviewed intent
  const before = requestFiles().length;
  // …and the released, exact-intent build STILL refuses at the covenant cap.
  await expectThrow(POST(["wallet", "v4", "requests"], spendBody(V, 25n, { riskEvaluationId: evId })), 422, "BUILD_FAILED");
  assert.equal(requestFiles().length, before, "no durable request — the covenant cap bounded a released hold");
});

/* -------------------------------------------------------------------- */
/* 6. [FIX PIN] read-side hold self-consistency (G-2 parity)             */
/*    A naive DB edit of only the stored intentHash retargets a released */
/*    hold at a different intent -> now refused RISK_EVALUATION_INTEGRITY */
/* -------------------------------------------------------------------- */
test("REGRESSION: a released hold whose stored intentHash is DB-edited to match a different (bigger) intent fails closed (RISK_EVALUATION_INTEGRITY) — read-side recompute, G-2 parity", async () => {
  const V = "b8".repeat(32);
  await seed(V, [agentEntry(agentA, [recipient])]);
  const orgId = await newOrgForVault(V, "integrity org");
  await setControls(orgId, { adapters: [{ type: "amount-threshold", params: { reviewAboveSompi: (5n * KAS).toString() } }] });
  const held = await expectThrow(POST(["wallet", "v4", "requests"], spendBody(V, 7n)), 409, "RISK_REVIEW_REQUIRED");
  const evId = held.extra.riskEvaluation.evaluationId;
  await POST(["risk", "evaluations", evId, "release"], {});

  // The intentHash a 9-KAS spend would carry (still within the 20-KAS covenant cap,
  // so the attacker's aim is to escape the REVIEW, not the covenant).
  const bigIntent = riskSvc.buildRiskIntent({ config, vaultId: V, action: "agentSpend", params: { payAmountSompi: (9n * KAS).toString(), agentPk: XO(agentA), recipient: XO(recipient) }, signerAddress: ADDR(agentA), signerXOnly: XO(agentA), sdkAction: "agentSpend" });
  const bigHash = riskSvc.intentHashOf(bigIntent);

  const rec = JSON.parse(fs.readFileSync(evalFile(evId), "utf8"));
  const originalHash = rec.intentHash;
  assert.notEqual(bigHash, originalHash);
  rec.intentHash = bigHash; // edit ONLY the scalar hash; rec.intent still describes 7 KAS -> self-inconsistent
  fs.writeFileSync(evalFile(evId), JSON.stringify(rec));

  // Consuming the 9-KAS intent must NOT ride the 7-KAS release: the record is self-inconsistent.
  await expectThrow(POST(["wallet", "v4", "requests"], spendBody(V, 9n, { riskEvaluationId: evId })), 409, "RISK_EVALUATION_INTEGRITY");
  // The release path also refuses a self-inconsistent record.
  await assert.rejects(() => riskSvc.releaseEvaluation(config, evId, { releasedByXOnly: XO(owner) }), (e) => e.code === "RISK_EVALUATION_INTEGRITY");
  // Restoring the record makes the original exact-intent consumption succeed again (the check
  // never false-positives on a self-consistent record).
  rec.intentHash = originalHash;
  fs.writeFileSync(evalFile(evId), JSON.stringify(rec));
  const built = await POST(["wallet", "v4", "requests"], spendBody(V, 7n, { riskEvaluationId: evId }));
  assert.equal(built.status, 201);
});
