"use strict";

/* Server/API — v0.4 production-byte HTTP -> VM integration gate
 * (Checkpoint G §G12) + API authorization enforcement (§G13).
 *
 * Drives the REAL server api.handle over a temp data root: HTTP body ->
 * authorization -> durable v0.4 request -> real SDK builder -> frozen package
 * -> dev signer (KasWare signPskt contract) -> FINALIZE -> real encoder ->
 * production covenant VM preflight. The transaction reaching preflight is the
 * one the request review describes and the wallet signed. Offline; no
 * broadcast. */

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

const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "pv4-api-"));
const config = loadConfig({ dataRoot });
const kaspa = require(config.rustyKaspaModule);
const KEY = (v) => new kaspa.PrivateKey(v.toString(16).padStart(2, "0").repeat(32));
const SEC = (v) => v.toString(16).padStart(2, "0").repeat(32);
const XO = (p) => p.toPublicKey().toXOnlyPublicKey().toString().toLowerCase();
const ADDR = (p) => p.toPublicKey().toAddress(config.networkId).toString();
const KAS = 100000000n;

const owner = KEY(1);
const agentA = KEY(0x1e);
const agentB = KEY(0x1f);
const recipient = KEY(0x28);
const other = KEY(0x29);
const approvers = [KEY(20), KEY(21), KEY(22)];
const unrelated = KEY(0x77);

const VAULT_ID = "22".repeat(32);
const template = { owner: XO(owner), vaultId: VAULT_ID };

function agentEntry(kp, recipients, over = {}) {
  return {
    agentPk: XO(kp), maxPerSpend: (20n * KAS).toString(), periodBudget: (50n * KAS).toString(),
    periodLengthDaa: "864000", periodStartDaa: "541000000", periodSpent: "0",
    approvalThreshold: (5n * KAS).toString(), agentMaxFeePerTx: (1n * KAS).toString(),
    recipients: recipients.map(XO), ...over
  };
}
const REGISTRY = [agentEntry(agentA, [recipient, other]), agentEntry(agentB, [other])];

let seedCounter = 0;
async function seed(registry = REGISTRY, over = {}) {
  seedCounter += 1;
  const outTxId = seedCounter.toString(16).padStart(2, "0").repeat(32).slice(0, 64);
  const policies = registry.map((e) => normalizeAgentPolicyV4({ ...e, agentRecipientRoot: buildRecipientTree(e.recipients).root }));
  const agentRoot = buildAgentTreeV4(policies).root;
  const state = normalizeStateV4({ protectedValue: (1000n * KAS).toString(), feeReserve: (5n * KAS).toString(), paused: "0", agentRoot, approvers: over.approvers ?? [], approvalM: over.approvalM ?? "0", policyNonce: "0" });
  const compiled = compileExactStateV4({ config, template: { owner: template.owner, vaultId: VAULT_ID }, state });
  const stateId = computeStateIdV4({ networkId: config.networkId, template, state });
  return await persistManifestV4(config, {
    schema: MANIFEST_SCHEMA_V4, contractVersion: CONTRACT_VERSION_V4, networkId: config.networkId, vaultId: VAULT_ID,
    label: "api test", status: "ACTIVE", template, agentRegistry: registry,
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
    if (status !== undefined) assert.equal(e.status, status, `status ${e.status} != ${status}: ${e.message}`);
    if (code !== undefined) assert.equal(e.code, code, `code ${e.code} != ${code}`);
    return e;
  }
}
function devSignAll(request, kp) {
  const signer = makeDevSigner(config, { secretHex: SEC(secretOf(kp)), expectedAddress: ADDR(kp) });
  return signer.signInputs(request.transaction.unsignedSafeJson, request.transaction.signInputs);
}
function secretOf(kp) {
  const map = { [XO(owner)]: 1, [XO(agentA)]: 0x1e, [XO(agentB)]: 0x1f, [XO(recipient)]: 0x28, [XO(other)]: 0x29, [XO(unrelated)]: 0x77 };
  approvers.forEach((a, i) => (map[XO(a)] = 20 + i));
  return map[XO(kp)];
}
const agentFuel = (kp) => ({ outpoint: { transactionId: "43".repeat(32), index: 1 }, amount: (100n * KAS).toString(), scriptPublicKeyHex: `20${XO(kp)}ac` });

test("G12: HTTP agentSpend -> authz -> BUILD -> sign -> FINALIZE -> production covenant VM preflight PASS", async () => {
  await seed();
  const built = await POST(["wallet", "v4", "requests"], { vaultId: VAULT_ID, action: "agentSpend", params: { payAmountSompi: (4n * KAS).toString(), agentPk: XO(agentA), recipient: XO(recipient) }, signerAddress: ADDR(agentA) });
  assert.equal(built.status, 201);
  const req = built.body.request;
  assert.equal(req.state, "BUILT");
  // the browser NEVER receives the internal build / encoder dirs
  assert.equal(req.build, undefined);
  assert.equal(req.review.recipient, XO(recipient));
  const signed = devSignAll(req, agentA);
  const done = await POST(["wallet", "v4", "requests", req.requestId, "signature"], { signedSafeJson: signed });
  assert.equal(done.status, 200);
  assert.equal(done.body.request.state, "PREFLIGHT_VERIFIED");
  assert.equal(done.body.request.txId, req.txId);
});

test("G12: GET /vaults/:id presents the v0.4 vault (fee reserve + agent registry)", async () => {
  await seed();
  const res = await GET(["vaults", VAULT_ID]);
  assert.equal(res.status, 200);
  assert.equal(res.body.contractVersion, CONTRACT_VERSION_V4);
  assert.equal(res.body.agents.length, 2);
  assert.ok(res.body.live.feeReserveKas);
  assert.ok(res.body.live.protectedValueKas);
  assert.equal(res.body.agents[0].agentAddress?.startsWith("kaspatest:"), true);
});

test("G13 authz: owner cannot agentSpend; unrelated wallet cannot; agent cannot owner-op — all 403, zero durable mutation", async () => {
  await seed();
  const before = fs.existsSync(path.join(dataRoot, "requests")) ? fs.readdirSync(path.join(dataRoot, "requests")).length : 0;
  // owner tries an agent spend
  await expectThrow(POST(["wallet", "v4", "requests"], { vaultId: VAULT_ID, action: "agentSpend", params: { payAmountSompi: (4n * KAS).toString(), agentPk: XO(agentA), recipient: XO(recipient) }, signerAddress: ADDR(owner) }), 403, "NOT_AGENT");
  // unrelated wallet claims to be agent A
  await expectThrow(POST(["wallet", "v4", "requests"], { vaultId: VAULT_ID, action: "agentSpend", params: { payAmountSompi: (4n * KAS).toString(), agentPk: XO(agentA), recipient: XO(recipient) }, signerAddress: ADDR(unrelated) }), 403, "NOT_AGENT");
  // agent tries an owner op
  await expectThrow(POST(["wallet", "v4", "requests"], { vaultId: VAULT_ID, action: "ownerPause", params: { fuel: agentFuel(agentA) }, signerAddress: ADDR(agentA) }), 403, "NOT_OWNER");
  const after = fs.existsSync(path.join(dataRoot, "requests")) ? fs.readdirSync(path.join(dataRoot, "requests")).length : 0;
  assert.equal(after, before, "unauthorized requests create no durable record");
});

test("G13 authz: an agent may spend only their OWN leaf (agent A signing for agent B is rejected)", async () => {
  await seed();
  // signer is agent A but the params name agent B -> NOT_AGENT (signer != acting agent)
  await expectThrow(POST(["wallet", "v4", "requests"], { vaultId: VAULT_ID, action: "agentSpend", params: { payAmountSompi: (4n * KAS).toString(), agentPk: XO(agentB), recipient: XO(other) }, signerAddress: ADDR(agentA) }), 403, "NOT_AGENT");
});

test("G13: unauthorized recipient (not in the agent's set) fails closed at BUILD", async () => {
  await seed();
  await expectThrow(POST(["wallet", "v4", "requests"], { vaultId: VAULT_ID, action: "agentSpend", params: { payAmountSompi: (4n * KAS).toString(), agentPk: XO(agentA), recipient: XO(unrelated) }, signerAddress: ADDR(agentA) }), 422);
});

test("G7 via HTTP: above-threshold spend collects approvals then finalizes to preflight PASS", async () => {
  await seed(REGISTRY, { approvers: approvers.map(XO), approvalM: "2" });
  const built = await POST(["wallet", "v4", "requests"], { vaultId: VAULT_ID, action: "agentSpend", params: { payAmountSompi: (6n * KAS).toString(), agentPk: XO(agentA), recipient: XO(recipient), fuel: agentFuel(agentA) }, signerAddress: ADDR(agentA) });
  const req = built.body.request;
  assert.equal(req.state, "AWAITING_APPROVALS");
  const approverSign = (kp) => makeDevSigner(config, { secretHex: SEC(secretOf(kp)), expectedAddress: ADDR(kp) }).signInputs(req.transaction.unsignedSafeJson, [{ index: 0 }]);
  // finalize before approvals -> 409 INSUFFICIENT_APPROVALS
  const signed = devSignAll(req, agentA);
  await expectThrow(POST(["wallet", "v4", "requests", req.requestId, "signature"], { signedSafeJson: signed }), 409, "INSUFFICIENT_APPROVALS");
  let r = await POST(["wallet", "v4", "requests", req.requestId, "approvals"], { approverAddress: ADDR(approvers[0]), signedSafeJson: approverSign(approvers[0]) });
  assert.equal(r.body.approvals.collected, 1);
  r = await POST(["wallet", "v4", "requests", req.requestId, "approvals"], { approverAddress: ADDR(approvers[1]), signedSafeJson: approverSign(approvers[1]) });
  assert.equal(r.body.approvals.complete, true);
  const done = await POST(["wallet", "v4", "requests", req.requestId, "signature"], { signedSafeJson: signed });
  assert.equal(done.body.request.state, "PREFLIGHT_VERIFIED");
});

test("G1: unknown v0.4 action fails closed; no legacy fallback", async () => {
  await seed();
  await expectThrow(POST(["wallet", "v4", "requests"], { vaultId: VAULT_ID, action: "delegateSpend", params: {}, signerAddress: ADDR(agentA) }), 422, "BUILD_FAILED");
});
