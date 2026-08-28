"use strict";

/*
 * RC-UX-1 REGRESSION + ADVERSARIAL SUITE (JSON store) — finding from the
 * fullscale-rc1 controlled-mainnet acceptance
 * (docs/postlaunch/rc-mainnet-acceptance-evidence.md §5.2).
 *
 * THE DEFECT (frozen fullscale-rc1 behavior this suite is RED on): the
 * server consumes a RELEASED review hold ONLY when the request body
 * carries `riskEvaluationId` (server/src/risk.js gateOperationRisk). A
 * plain re-submission of the IDENTICAL intent spawns a NEW evaluation
 * and a NEW hold — observed looping live on mainnet. In self-hosted
 * solo operation the only UI element that sends the id is the hold
 * panel's Re-submit button, which renders only on a RELEASED panel that
 * a solo operator can never reach with action context — so the
 * REVIEW_HELD -> RELEASED -> CONSUMED continuation was structurally
 * unreachable, and the panel's fallback copy ("the server will accept
 * it once it is released and matches the exact reviewed intent") was
 * false: the server did no hash matching.
 *
 * REQUIRED FIXED BEHAVIOR (owner remediation directive, 2026-08-27):
 *   - after an owner/reviewer release, an id-less re-submission of the
 *     EXACT reviewed intent (same vault, same canonical intent hash,
 *     same org-controls version) deterministically CONTINUES the
 *     released hold: it is consumed exactly once and the build proceeds;
 *   - stale (controls version changed since the evaluation was
 *     created), wrong-vault, wrong-intent, already-consumed, non-
 *     RELEASED (HELD/DENIED), and concurrent duplicate attempts all
 *     REFUSE restrictively (fresh evaluation -> fresh hold; never a
 *     silent reuse, never an ALLOW upgrade);
 *   - the explicit riskEvaluationId path is byte-for-byte unchanged
 *     (including its cross-controls-version consumption semantics);
 *   - audit history tells the truth: one RISK_RELEASED_CONSUMED row per
 *     rematch consume, none for explicit-id consumes;
 *   - the canonical risk intent-hash preimage is unchanged (identity
 *     binding preserved).
 *
 * Harness: REAL server api.handle over a temp JSON data root, REAL v0.4
 * build pipeline. Offline; nothing is ever signed or broadcast here.
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
const { readAudit } = require("../src/audit");

const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "pv-rcux1-"));
const config = loadConfig({ dataRoot });
const kaspa = require(config.rustyKaspaModule);
const KEY = (v) => new kaspa.PrivateKey(v.toString(16).padStart(2, "0").repeat(32));
const XO = (p) => p.toPublicKey().toXOnlyPublicKey().toString().toLowerCase();
const ADDR = (p) => p.toPublicKey().toAddress(config.networkId).toString();
const KAS = 100000000n;

const owner = KEY(1);
const agentA = KEY(0x1e);
const recipient = KEY(0x28);

const VAULT_1 = "c1".repeat(32);
const VAULT_2 = "c2".repeat(32);

function agentEntry(kp, recipients) {
  return {
    agentPk: XO(kp), maxPerSpend: (30n * KAS).toString(), periodBudget: (200n * KAS).toString(),
    periodLengthDaa: "864000", periodStartDaa: "541000000", periodSpent: "0",
    approvalThreshold: (100n * KAS).toString(), agentMaxFeePerTx: (1n * KAS).toString(),
    recipients: recipients.map(XO)
  };
}

let seedCounter = 0;
async function seed(vaultId) {
  seedCounter += 1;
  const outTxId = (0x60 + seedCounter).toString(16).padStart(2, "0").repeat(32).slice(0, 64);
  const registry = [agentEntry(agentA, [recipient])];
  const template = { owner: XO(owner), vaultId };
  const policies = registry.map((e) => normalizeAgentPolicyV4({ ...e, agentRecipientRoot: buildRecipientTree(e.recipients).root }));
  const state = normalizeStateV4({ protectedValue: (1000n * KAS).toString(), feeReserve: (5n * KAS).toString(), paused: "0", agentRoot: buildAgentTreeV4(policies).root, approvers: [], approvalM: "0", policyNonce: "0" });
  const compiled = compileExactStateV4({ config, template, state });
  const stateId = computeStateIdV4({ networkId: config.networkId, template, state });
  return await persistManifestV4(config, {
    schema: MANIFEST_SCHEMA_V4, contractVersion: CONTRACT_VERSION_V4, networkId: config.networkId, vaultId,
    label: "rc-ux1", status: "ACTIVE", template, agentRegistry: registry,
    live: { state: stateToJsonV4(state), stateId, outpoint: { transactionId: outTxId, index: 0 }, outpointValue: (state.protectedValue + state.feeReserve).toString(), scriptSha256: compiled.scriptSha256, covenantId: "41".repeat(32) },
    creationTxId: "42".repeat(32), latestTransitionTxId: null, lastTransition: null
  });
}

/* Mutable handle reference so the sabotage test can re-require api.js. */
let H = handle;
const POST = (segs, body) => H(config, "POST", segs, {}, body);
const GET = (segs) => H(config, "GET", segs, {}, null);

async function expectThrow(promise, status, code) {
  try {
    await promise;
    assert.fail(`expected an API error${code ? ` (${code})` : ""}`);
  } catch (e) {
    if (e.code === "ERR_ASSERTION") throw e;
    if (status !== undefined) assert.equal(e.status, status, `status ${e.status} != ${status}: ${e.message}`);
    if (code !== undefined) assert.equal(e.code, code, `code ${e.code} != ${code}: ${e.message}`);
    return e;
  }
}

const spendBody = (vaultId, amountKas, extra = {}) => ({
  vaultId, action: "agentSpend",
  params: { payAmountSompi: (amountKas * KAS).toString(), agentPk: XO(agentA), recipient: XO(recipient) },
  signerAddress: ADDR(agentA), ...extra
});

const orgIds = {};
async function newOrgForVault(vaultId, name) {
  const created = await org.createOrganization(config, { name });
  const assignments = await org.loadAssignments(config);
  await org.assignVault(config, { vaultId, orgId: created.orgId, group: null, expectedVersion: assignments.version, vaultExists: async () => true });
  orgIds[vaultId] = created.orgId;
  return created.orgId;
}
async function setControls(orgId, risk) {
  const cur = await loadOrgControls(config, orgId);
  return saveOrgControls(config, orgId, { governance: {}, risk, expectedVersion: cur ? cur.version : 0 });
}
const REVIEW_ONLY = { adapters: [{ type: "amount-threshold", params: { reviewAboveSompi: (5n * KAS).toString() } }] };

const evaluation = async (id) => (await GET(["risk", "evaluations", id])).body.evaluation;
const rematchAuditRows = async (vaultId) =>
  (await readAudit(config, { vaultId, limit: 500 })).filter((e) => e.kind === "risk" && e.result === "RISK_RELEASED_CONSUMED");

/* Drive one intent to a RELEASED hold; returns the evaluationId. */
async function heldAndReleased(vaultId, amountKas) {
  const held = await expectThrow(POST(["wallet", "v4", "requests"], spendBody(vaultId, amountKas)), 409, "RISK_REVIEW_REQUIRED");
  const evId = held.extra.riskEvaluation.evaluationId;
  const rel = await POST(["risk", "evaluations", evId, "release"], {});
  assert.equal(rel.body.evaluation.status, "RELEASED");
  return evId;
}

test("setup: two org-owned vaults with review-line controls", async () => {
  await seed(VAULT_1);
  await seed(VAULT_2);
  await setControls(await newOrgForVault(VAULT_1, "rc-ux1 org 1"), REVIEW_ONLY);
  await setControls(await newOrgForVault(VAULT_2, "rc-ux1 org 2"), REVIEW_ONLY);
});

/* ================= THE RC-UX-1 REGRESSION (RED on frozen fullscale-rc1) =================
 * The mainnet-observed loop: hold -> owner release -> plain re-attempt of
 * the identical action (the ONLY continuation a solo operator has) MUST
 * continue the released hold instead of spawning hold after hold. */
test("RC-UX-1 core: after release, an id-less re-submission of the EXACT reviewed intent consumes the released hold and builds", async () => {
  const e1 = await heldAndReleased(VAULT_1, 7n);
  let built;
  try {
    built = await POST(["wallet", "v4", "requests"], spendBody(VAULT_1, 7n)); // NO riskEvaluationId — the solo re-attempt
  } catch (e) {
    const fresh = e.extra && e.extra.riskEvaluation ? e.extra.riskEvaluation.evaluationId : "(none)";
    const e1status = (await evaluation(e1)).status;
    assert.fail(
      `RC-UX-1 DEFECT REPRODUCED: the id-less re-submission of the exact released intent did NOT continue the released hold — ` +
        `got ${e.status} ${e.code} with a NEW evaluation ${fresh} while released evaluation ${e1} stayed ${e1status} ` +
        `(the live-observed mainnet loop: every plain re-attempt spawns another hold and the release is unreachable)`
    );
  }
  assert.equal(built.status, 201);
  assert.equal(built.body.request.riskEvaluationId, e1, "the durable request binds the CONSUMED released evaluation");
  const after = await evaluation(e1);
  assert.equal(after.status, "CONSUMED");
  assert.equal(after.consumedByRequestId, built.body.request.requestId);
  assert.equal(after.consumedVia, "RELEASED_INTENT_REMATCH", "evidence names the id-less exact-intent continuation");
  assert.deepEqual(after.policyGate, { final: "REVIEW", source: "risk" }, "same policy-gate evidence as the explicit released-consume path");
  const rows = await rematchAuditRows(VAULT_1);
  assert.equal(rows.length, 1, "exactly one RISK_RELEASED_CONSUMED audit row");
  assert.equal(rows[0].riskEvaluationId, e1);
  assert.equal(rows[0].intentHash, after.intentHash);
});

test("RC-UX-1 exactly-once: a SECOND identical id-less re-attempt after the consume spawns a FRESH hold, never a reuse", async () => {
  const consumedBefore = await evaluation((await rematchAuditRows(VAULT_1))[0].riskEvaluationId);
  const again = await expectThrow(POST(["wallet", "v4", "requests"], spendBody(VAULT_1, 7n)), 409, "RISK_REVIEW_REQUIRED");
  const freshId = again.extra.riskEvaluation.evaluationId;
  assert.notEqual(freshId, consumedBefore.evaluationId, "a fresh evaluation, not the consumed one");
  assert.equal((await evaluation(freshId)).status, "REVIEW_HELD");
  const consumedAfter = await evaluation(consumedBefore.evaluationId);
  assert.equal(consumedAfter.status, "CONSUMED");
  assert.equal(consumedAfter.consumedByRequestId, consumedBefore.consumedByRequestId, "the consumed record is untouched by the refused replay");
});

test("RC-UX-1 wrong-intent: a released hold never matches a DIFFERENT amount; the exact intent still continues afterward", async () => {
  const e2 = await heldAndReleased(VAULT_1, 9n);
  // 8 KAS is above the review line but is NOT the reviewed intent -> fresh hold; e2 untouched.
  const probe = await expectThrow(POST(["wallet", "v4", "requests"], spendBody(VAULT_1, 8n)), 409, "RISK_REVIEW_REQUIRED");
  assert.notEqual(probe.extra.riskEvaluation.evaluationId, e2);
  assert.equal((await evaluation(e2)).status, "RELEASED", "the wrong-intent probe consumed nothing");
  // The exact reviewed 9-KAS intent then continues deterministically.
  const built = await POST(["wallet", "v4", "requests"], spendBody(VAULT_1, 9n));
  assert.equal(built.status, 201);
  assert.equal(built.body.request.riskEvaluationId, e2);
  assert.equal((await evaluation(e2)).status, "CONSUMED");
});

test("RC-UX-1 wrong-vault: a release on vault 2 never matches the identical parameters on vault 1", async () => {
  const e3 = await heldAndReleased(VAULT_2, 13n);
  const probe = await expectThrow(POST(["wallet", "v4", "requests"], spendBody(VAULT_1, 13n)), 409, "RISK_REVIEW_REQUIRED");
  assert.notEqual(probe.extra.riskEvaluation.evaluationId, e3);
  assert.equal((await evaluation(e3)).status, "RELEASED", "the cross-vault probe consumed nothing");
});

test("RC-UX-1 non-RELEASED + stale-controls: HELD and DENIED evaluations are never consumed; a controls change staleness-refuses the id-less path while the explicit-id path is unchanged", async () => {
  // The still-RELEASED 13-KAS hold on vault 2 was created under controls v1.
  const e3 = (await readAudit(config, { vaultId: VAULT_2, limit: 100 })).find((r) => r.result === "RISK_HOLD_RELEASED").riskEvaluationId;
  assert.equal((await evaluation(e3)).status, "RELEASED");
  // DENIED: raise a deny line (controls v2), get a durable DENIED evaluation.
  await setControls(orgIds[VAULT_2], { adapters: [{ type: "amount-threshold", params: { denyAboveSompi: (12n * KAS).toString() } }] });
  const denied = await expectThrow(POST(["wallet", "v4", "requests"], spendBody(VAULT_2, 13n)), 403, "RISK_DENIED");
  const d1 = denied.extra.riskEvaluation.evaluationId;
  assert.equal((await evaluation(d1)).status, "DENIED");
  // Back to review-only (controls v3): the id-less 13-KAS intent gets a FRESH hold —
  // the DENIED record is never consumable, and the RELEASED e3 is STALE (created
  // under controls v1, current v3): a configuration change re-evaluates fresh.
  await setControls(orgIds[VAULT_2], REVIEW_ONLY);
  const fresh = await expectThrow(POST(["wallet", "v4", "requests"], spendBody(VAULT_2, 13n)), 409, "RISK_REVIEW_REQUIRED");
  assert.ok(![e3, d1].includes(fresh.extra.riskEvaluation.evaluationId), "neither the stale release nor the DENIED record was reused");
  assert.equal((await evaluation(e3)).status, "RELEASED");
  assert.equal((await evaluation(d1)).status, "DENIED");
  // The EXPLICIT riskEvaluationId path keeps its existing cross-version
  // semantics byte-for-byte: naming the released hold still consumes it.
  const built = await POST(["wallet", "v4", "requests"], spendBody(VAULT_2, 13n, { riskEvaluationId: e3 }));
  assert.equal(built.status, 201);
  assert.equal((await evaluation(e3)).status, "CONSUMED");
  assert.notEqual((await evaluation(e3)).consumedVia, "RELEASED_INTENT_REMATCH", "an explicit-id consume is not labeled as a rematch");
});

test("RC-UX-1 stale-controls (vault 1, focused): re-saving controls strands NO release for the explicit path but refuses the id-less rematch", async () => {
  const e5 = await heldAndReleased(VAULT_1, 15n); // created under current controls version
  const before = await loadOrgControls(config, orgIds[VAULT_1]);
  await setControls(orgIds[VAULT_1], REVIEW_ONLY); // identical content, version bumped
  const after = await loadOrgControls(config, orgIds[VAULT_1]);
  assert.equal(after.version, before.version + 1);
  const fresh = await expectThrow(POST(["wallet", "v4", "requests"], spendBody(VAULT_1, 15n)), 409, "RISK_REVIEW_REQUIRED");
  assert.notEqual(fresh.extra.riskEvaluation.evaluationId, e5, "stale release not consumed id-lessly after a controls change");
  assert.equal((await evaluation(e5)).status, "RELEASED");
  const built = await POST(["wallet", "v4", "requests"], spendBody(VAULT_1, 15n, { riskEvaluationId: e5 }));
  assert.equal(built.status, 201, "the explicit-id continuation still consumes the release");
  assert.equal((await evaluation(e5)).status, "CONSUMED");
});

test("RC-UX-1 concurrency: two simultaneous identical id-less re-attempts — exactly one continues the release, the loser gets a FRESH hold", async () => {
  const e7 = await heldAndReleased(VAULT_1, 17n);
  const results = await Promise.allSettled([
    POST(["wallet", "v4", "requests"], spendBody(VAULT_1, 17n)),
    POST(["wallet", "v4", "requests"], spendBody(VAULT_1, 17n))
  ]);
  const ok = results.filter((r) => r.status === "fulfilled");
  const failed = results.filter((r) => r.status === "rejected");
  assert.equal(ok.length, 1, `exactly one winner (${JSON.stringify(results.map((r) => (r.status === "rejected" ? r.reason.code : "built")))})`);
  assert.equal(failed.length, 1);
  assert.equal(failed[0].reason.code, "RISK_REVIEW_REQUIRED", "the race loser fell through to a FRESH evaluation, which HOLDS (default-restrictive)");
  assert.notEqual(failed[0].reason.extra.riskEvaluation.evaluationId, e7);
  const rec = await evaluation(e7);
  assert.equal(rec.status, "CONSUMED");
  assert.equal(rec.consumedByRequestId, ok[0].value.body.request.requestId, "consumed exactly once, by the winner");
  assert.equal(ok[0].value.body.request.riskEvaluationId, e7);
});

test("RC-UX-1 identity binding: the canonical risk intent-hash preimage is unchanged and matches stored evaluations", async () => {
  const intent = riskSvc.buildRiskIntent({
    config, vaultId: VAULT_1, action: "agentSpend",
    params: { payAmountSompi: (7n * KAS).toString(), agentPk: XO(agentA), recipient: XO(recipient) },
    signerAddress: ADDR(agentA), signerXOnly: XO(agentA), sdkAction: "agentSpend"
  });
  const hash = riskSvc.intentHashOf(intent);
  const rows = await rematchAuditRows(VAULT_1);
  const core = rows.find((r) => r.intentHash === hash);
  assert.ok(core, "the 7-KAS rematch consume is bound to the SAME canonical intent hash the pipeline always used");
  const rec = await evaluation(core.riskEvaluationId);
  assert.equal(rec.intentHash, hash);
  assert.doesNotThrow(() => riskSvc.assertEvaluationIntegrity(rec), "consumed records stay self-consistent (G-2 parity)");
});

test("RC-UX-1 audit truthfulness: one RISK_RELEASED_CONSUMED row per rematch consume; explicit-id consumes add none", async () => {
  // Vault 1 rematch consumes so far: 7 KAS (core) + 9 KAS (wrong-intent test) + 17 KAS (concurrency winner).
  assert.equal((await rematchAuditRows(VAULT_1)).length, 3);
  // Vault 2 had ONLY an explicit-id consume (13 KAS) — no rematch row.
  assert.equal((await rematchAuditRows(VAULT_2)).length, 0);
});

/* =================== SABOTAGE / MUTATION SENSITIVITY ===================
 * Neutralize the id-less rematch in server/src/risk.js (same in-place
 * technique as the SDK sabotage suites; the SDK suite runs serialized).
 * With the guard gone the RC-UX-1 wedge must come back: an id-less
 * re-attempt of the exact released intent spawns a fresh hold and the
 * release stays unreachable. Restoring the source restores the fix. */
test("RC-UX-1 sabotage: neutralizing the exact-intent rematch resurrects the released-hold wedge; restoring the source restores the continuation", async () => {
  const srcPath = require.resolve("../../server/src/risk.js");
  const original = fs.readFileSync(srcPath, "utf8");
  const TARGET = "const rematched = await consumeReleasedHoldForIntent(";
  assert.ok(original.includes(TARGET), "fix present before sabotage (RED on the frozen tree: the rematch does not exist yet)");
  const sabotaged = original.replace(TARGET, "const rematched = null && await consumeReleasedHoldForIntent(");
  assert.notEqual(sabotaged, original, "sabotage patch applied");
  const rebust = () => {
    for (const k of Object.keys(require.cache)) {
      if (k.endsWith(`${path.sep}risk.js`) || k.endsWith(`${path.sep}api.js`) || k.endsWith(`${path.sep}simulate.js`)) delete require.cache[k];
    }
    H = require("../../server/src/api").handle;
  };
  const e9 = await heldAndReleased(VAULT_1, 19n);
  fs.writeFileSync(srcPath, sabotaged);
  try {
    rebust();
    const wedged = await expectThrow(POST(["wallet", "v4", "requests"], spendBody(VAULT_1, 19n)), 409, "RISK_REVIEW_REQUIRED");
    assert.notEqual(wedged.extra.riskEvaluation.evaluationId, e9, "sabotaged code spawned a fresh hold (the original RC-UX-1 loop)");
    assert.equal((await evaluation(e9)).status, "RELEASED", "the released hold is unreachable again under sabotage");
  } finally {
    fs.writeFileSync(srcPath, original);
    rebust();
  }
  const built = await POST(["wallet", "v4", "requests"], spendBody(VAULT_1, 19n));
  assert.equal(built.status, 201, "restored source restores the deterministic continuation");
  assert.equal((await evaluation(e9)).status, "CONSUMED");
});
