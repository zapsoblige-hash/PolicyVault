"use strict";

/*
 * POSTLAUNCH OPERATIONAL RISK PIPELINE (completion-standard item 5;
 * docs/postlaunch/risk-adapter-spec.md; server/src/risk.js).
 *
 * Real server api.handle + real v0.4 builds over a temp JSON data root.
 * Proves at the server boundary:
 *   - per-organization adapter configuration (org-controls surface:
 *     validation, CAS versioning, unknown types fail closed);
 *   - DENY refuses purely with structured reasons + evidence record;
 *   - deny-wins composition (DENY beats REVIEW across adapters);
 *   - REVIEW holds -> authorized release -> exact-intent consumption;
 *     a changed intent never reuses a release;
 *   - error/timeout/malformed adapters resolve via onAdapterError
 *     (REVIEW/DENY, never silent ALLOW) with evidence recorded;
 *   - ALLOW proceeds to a real build and the evaluation is consumed
 *     with the structural policy-gate record;
 *   - the acting signer never releases their own hold;
 *   - break-glass ownerPause bypasses the risk gate entirely;
 *   - audit evidence rows exist for every evaluation.
 *
 * Restrictive-only: nothing here is covenant authority; the covenant
 * enforces caps/budgets/allowlists on-chain regardless of any adapter.
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
const { saveOrgControls } = require("../../server/src/org-controls");
const riskSvc = require("../../server/src/risk");
const { readAudit } = require("../src/audit");

const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "pv-risk-"));
const config = loadConfig({ dataRoot });
const kaspa = require(config.rustyKaspaModule);
const KEY = (v) => new kaspa.PrivateKey(v.toString(16).padStart(2, "0").repeat(32));
const XO = (p) => p.toPublicKey().toXOnlyPublicKey().toString().toLowerCase();
const ADDR = (p) => p.toPublicKey().toAddress(config.networkId).toString();
const KAS = 100000000n;

const owner = KEY(1);
const agentA = KEY(0x1e);
const recipient = KEY(0x28);
const other = KEY(0x29);

const VAULT_ID = "35".repeat(32);
const template = { owner: XO(owner), vaultId: VAULT_ID };

function agentEntry(kp, recipients) {
  return {
    agentPk: XO(kp), maxPerSpend: (20n * KAS).toString(), periodBudget: (50n * KAS).toString(),
    periodLengthDaa: "864000", periodStartDaa: "541000000", periodSpent: "0",
    approvalThreshold: (50n * KAS).toString(), agentMaxFeePerTx: (1n * KAS).toString(),
    recipients: recipients.map(XO)
  };
}
const REGISTRY = [agentEntry(agentA, [recipient, other])];

let seedCounter = 0;
async function seed() {
  seedCounter += 1;
  const outTxId = (0x40 + seedCounter).toString(16).padStart(2, "0").repeat(32).slice(0, 64);
  const policies = REGISTRY.map((e) => normalizeAgentPolicyV4({ ...e, agentRecipientRoot: buildRecipientTree(e.recipients).root }));
  const agentRoot = buildAgentTreeV4(policies).root;
  const state = normalizeStateV4({ protectedValue: (1000n * KAS).toString(), feeReserve: (5n * KAS).toString(), paused: "0", agentRoot, approvers: [], approvalM: "0", policyNonce: "0" });
  const compiled = compileExactStateV4({ config, template, state });
  const stateId = computeStateIdV4({ networkId: config.networkId, template, state });
  return await persistManifestV4(config, {
    schema: MANIFEST_SCHEMA_V4, contractVersion: CONTRACT_VERSION_V4, networkId: config.networkId, vaultId: VAULT_ID,
    label: "risk test", status: "ACTIVE", template, agentRegistry: REGISTRY,
    live: { state: stateToJsonV4(state), stateId, outpoint: { transactionId: outTxId, index: 0 }, outpointValue: (state.protectedValue + state.feeReserve).toString(), scriptSha256: compiled.scriptSha256, covenantId: "41".repeat(32) },
    creationTxId: "42".repeat(32), latestTransitionTxId: null, lastTransition: null
  });
}

const POST = (segs, body) => handle(config, "POST", segs, {}, body);
const GET = (segs, query) => handle(config, "GET", segs, query ?? {}, null);
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
const spendBody = (amountKas, extra = {}) => ({
  vaultId: VAULT_ID,
  action: "agentSpend",
  params: { payAmountSompi: (amountKas * KAS).toString(), agentPk: XO(agentA), recipient: XO(recipient) },
  signerAddress: ADDR(agentA),
  ...extra
});
const ownerFuel = () => ({ outpoint: { transactionId: "43".repeat(32), index: 1 }, amount: (100n * KAS).toString(), scriptPublicKeyHex: `20${XO(owner)}ac` });
const requestFiles = () => (fs.existsSync(path.join(dataRoot, "requests")) ? fs.readdirSync(path.join(dataRoot, "requests")) : []);

let orgId;
async function setControls(risk) {
  const current = await require("../../server/src/org-controls").loadOrgControls(config, orgId);
  return saveOrgControls(config, orgId, { governance: {}, risk, expectedVersion: current ? current.version : 0 });
}

test("setup: organization owns the vault; controls surface validates and versions", async () => {
  await seed();
  const created = await org.createOrganization(config, { name: "risk org" });
  orgId = created.orgId;
  await org.assignVault(config, { vaultId: VAULT_ID, orgId, group: null, expectedVersion: 0, vaultExists: async () => true });

  // unknown adapter type refuses at SAVE
  await assert.rejects(() => setControls({ adapters: [{ type: "mystery-vendor", params: {} }] }), (e) => e.code === "RISK_ADAPTER_TYPE_UNKNOWN");
  // onAdapterError ALLOW refuses at save (an erroring control can never resolve permissive)
  await assert.rejects(() => setControls({ adapters: [], onAdapterError: "ALLOW" }), (e) => e.code === "CONTROLS_INVALID");
  // review-required + onEmpty ALLOW is contradictory
  await assert.rejects(() => setControls({ reviewRequired: true, onEmpty: "ALLOW" }), (e) => e.code === "RISK_CONFIG_CONFLICT");
  // bad params refuse at save (validated by the factory)
  await assert.rejects(() => setControls({ adapters: [{ type: "amount-threshold", params: { denyAboveSompi: "1.5" } }] }), (e) => e.code === "RISK_ADAPTER_PARAMS_INVALID");
  // a valid save versions with CAS
  const v1 = await setControls({ adapters: [{ type: "amount-threshold", params: { denyAboveSompi: (10n * KAS).toString() } }] });
  assert.equal(v1.version, 1);
  await assert.rejects(
    () => saveOrgControls(config, orgId, { governance: {}, risk: {}, expectedVersion: 0 }),
    (e) => e.code === "VERSION_CONFLICT"
  );
});

test("DENY refuses purely with structured reasons; evidence + audit rows written; below-line spend ALLOWs and consumes", async () => {
  await setControls({
    adapters: [{ type: "amount-threshold", params: { reviewAboveSompi: (5n * KAS).toString(), denyAboveSompi: (10n * KAS).toString() } }]
  });
  const before = requestFiles().length;
  const e = await expectThrow(POST(["wallet", "v4", "requests"], spendBody(11n)), 403, "RISK_DENIED");
  assert.equal(e.extra.riskEvaluation.decision, "DENY");
  assert.ok(e.extra.riskEvaluation.codes.includes("AMOUNT_ABOVE_DENY_LINE"));
  assert.equal(requestFiles().length, before, "a risk DENY creates no durable request");
  // evidence record readable
  const ev = await GET(["risk", "evaluations", e.extra.riskEvaluation.evaluationId]);
  assert.equal(ev.status, 200);
  assert.equal(ev.body.evaluation.status, "DENIED");
  assert.equal(ev.body.evaluation.results.length, 1);
  // audit evidence row exists with the evaluation id
  const events = await readAudit(config, { vaultId: VAULT_ID, limit: 50 });
  assert.ok(events.some((ev2) => ev2.kind === "risk" && ev2.result === "RISK_DENY" && ev2.riskEvaluationId === e.extra.riskEvaluation.evaluationId));

  // an in-policy small spend passes and CONSUMES its ALLOW evaluation
  const built = await POST(["wallet", "v4", "requests"], spendBody(2n));
  assert.equal(built.status, 201);
  assert.match(built.body.request.riskEvaluationId, /^[0-9a-f-]{36}$/);
  const consumed = await GET(["risk", "evaluations", built.body.request.riskEvaluationId]);
  assert.equal(consumed.body.evaluation.status, "CONSUMED");
  assert.equal(consumed.body.evaluation.consumedByRequestId, built.body.request.requestId);
  assert.deepEqual(consumed.body.evaluation.policyGate, { final: "ALLOW", source: "policy+risk" });
});

test("deny-wins composition: a DENY from one adapter beats a REVIEW from another; both reasons in evidence", async () => {
  await setControls({
    adapters: [
      { type: "static-verdict", name: "always-review", params: { verdict: "REVIEW", code: "FORCED_REVIEW" } },
      { type: "recipient-allowlist", name: "vendors", params: { allowedRecipients: [XO(other)], unknownRecipient: "DENY" } }
    ]
  });
  const e = await expectThrow(POST(["wallet", "v4", "requests"], spendBody(1n)), 403, "RISK_DENIED");
  assert.ok(e.extra.riskEvaluation.codes.includes("RECIPIENT_NOT_ALLOWLISTED"));
  assert.ok(e.extra.riskEvaluation.codes.includes("FORCED_REVIEW"), "all adapter reasons are recorded, not just the winner");
});

test("REVIEW -> hold -> release -> exact-intent consumption; a changed intent is a NEW evaluation", async () => {
  await setControls({
    adapters: [{ type: "amount-threshold", params: { reviewAboveSompi: (5n * KAS).toString() } }]
  });
  const held = await expectThrow(POST(["wallet", "v4", "requests"], spendBody(7n)), 409, "RISK_REVIEW_REQUIRED");
  const evaluationId = held.extra.riskEvaluation.evaluationId;
  // consuming an un-released hold refuses
  await expectThrow(POST(["wallet", "v4", "requests"], spendBody(7n, { riskEvaluationId: evaluationId })), 409, "RISK_EVALUATION_NOT_RELEASED");
  // release (self-hosted operator release; hosted reviewer roles are tenancy-tested separately)
  const released = await POST(["risk", "evaluations", evaluationId, "release"], {});
  assert.equal(released.body.evaluation.status, "RELEASED");
  // a DIFFERENT amount cannot ride the release
  await expectThrow(POST(["wallet", "v4", "requests"], spendBody(8n, { riskEvaluationId: evaluationId })), 409, "RISK_INTENT_CHANGED");
  // the EXACT reviewed intent proceeds to a real build and consumes the hold
  const built = await POST(["wallet", "v4", "requests"], spendBody(7n, { riskEvaluationId: evaluationId }));
  assert.equal(built.status, 201);
  const after = await GET(["risk", "evaluations", evaluationId]);
  assert.equal(after.body.evaluation.status, "CONSUMED");
  // a consumed release cannot be replayed
  await expectThrow(POST(["wallet", "v4", "requests"], spendBody(7n, { riskEvaluationId: evaluationId })), 409, "RISK_EVALUATION_NOT_RELEASED");
});

test("the acting signer never releases their own hold (service rule from durable facts)", async () => {
  await setControls({ adapters: [{ type: "static-verdict", params: { verdict: "REVIEW" } }] });
  const held = await expectThrow(POST(["wallet", "v4", "requests"], spendBody(1n)), 409, "RISK_REVIEW_REQUIRED");
  await assert.rejects(
    () => riskSvc.releaseEvaluation(config, held.extra.riskEvaluation.evaluationId, { releasedByXOnly: XO(agentA) }),
    (e) => e.code === "RISK_SELF_RELEASE_FORBIDDEN"
  );
  // a different reviewer identity releases fine
  const rel = await riskSvc.releaseEvaluation(config, held.extra.riskEvaluation.evaluationId, { releasedByXOnly: XO(owner) });
  assert.equal(rel.status, "RELEASED");
});

test("adapter error / timeout / malformed verdict resolve via onAdapterError — never silent ALLOW — with evidence", async () => {
  // throw -> REVIEW (default onAdapterError)
  await setControls({ adapters: [{ type: "static-verdict", params: { behavior: "throw" } }] });
  let e = await expectThrow(POST(["wallet", "v4", "requests"], spendBody(1n)), 409, "RISK_REVIEW_REQUIRED");
  let ev = (await GET(["risk", "evaluations", e.extra.riskEvaluation.evaluationId])).body.evaluation;
  assert.equal(ev.results[0].status, "ERROR");
  assert.equal(ev.results[0].verdict, "REVIEW");

  // hang -> bounded by timeout -> DENY under onAdapterError DENY
  await setControls({ adapters: [{ type: "static-verdict", params: { behavior: "hang" }, timeoutMs: 200 }], onAdapterError: "DENY" });
  e = await expectThrow(POST(["wallet", "v4", "requests"], spendBody(1n)), 403, "RISK_DENIED");
  ev = (await GET(["risk", "evaluations", e.extra.riskEvaluation.evaluationId])).body.evaluation;
  assert.equal(ev.results[0].status, "TIMEOUT");
  assert.equal(ev.results[0].errorCode, "ADAPTER_TIMEOUT");
  assert.equal(ev.results[0].verdict, "DENY");

  // malformed verdict -> mapped restrictive, never ALLOW
  await setControls({ adapters: [{ type: "static-verdict", params: { behavior: "malformed" } }] });
  e = await expectThrow(POST(["wallet", "v4", "requests"], spendBody(1n)), 409, "RISK_REVIEW_REQUIRED");
  ev = (await GET(["risk", "evaluations", e.extra.riskEvaluation.evaluationId])).body.evaluation;
  assert.equal(ev.results[0].status, "ERROR");
  assert.ok(["ADAPTER_VERDICT_UNKNOWN", "ADAPTER_VERDICT_INVALID"].includes(ev.results[0].errorCode));
});

test("reviewRequired with an empty adapter set defaults restrictive (REVIEW), and owner ops are screened too", async () => {
  await setControls({ adapters: [], reviewRequired: true, onEmpty: "REVIEW" });
  await expectThrow(POST(["wallet", "v4", "requests"], spendBody(1n)), 409, "RISK_REVIEW_REQUIRED");
  // an owner policy REDUCTION is also risk-screened (intent-bearing flow)…
  await expectThrow(
    POST(["wallet", "v4", "requests"], { vaultId: VAULT_ID, action: "removeAgent", params: { fuel: ownerFuel(), agentPk: XO(agentA) }, signerAddress: ADDR(owner) }),
    409,
    "RISK_REVIEW_REQUIRED"
  );
  // …but break-glass ownerPause bypasses the risk gate entirely
  const pause = await POST(["wallet", "v4", "requests"], { vaultId: VAULT_ID, action: "ownerPause", params: { fuel: ownerFuel() }, signerAddress: ADDR(owner) });
  assert.equal(pause.status, 201);
});

test("stored controls with a type unknown to this build refuse the OPERATION (control never silently dropped)", async () => {
  await setControls({ adapters: [{ type: "amount-threshold", params: { denyAboveSompi: (10n * KAS).toString() } }] });
  // simulate a NEWER deployment's stored adapter type by editing the record file
  const file = path.join(dataRoot, "org-controls", `${orgId}.json`);
  const record = JSON.parse(fs.readFileSync(file, "utf8"));
  record.risk.adapters[0].type = "future-vendor-adapter";
  fs.writeFileSync(file, JSON.stringify(record));
  await expectThrow(POST(["wallet", "v4", "requests"], spendBody(1n)), 422, "RISK_ADAPTER_TYPE_UNKNOWN");
});
