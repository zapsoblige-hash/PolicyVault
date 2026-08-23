"use strict";

/* Server/SDK — Checkpoint G HOSTILE integration review (§G13) + claims /
 * reconciliation / crash safety (§G10). Attacks the v0.4 application layer:
 * identity/authz, agent-tree metadata integrity, request/freeze boundary,
 * approvals, fee/reserve, concurrency (two-tab), and crash/duplicate calls.
 * Every browser-only protection is independently enforced by the backend and
 * proven here (offline; production covenant VM preflight is the endpoint). */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");
const os = require("os");

const { loadConfig } = require("../src/config");
const { buildAgentTreeV4, normalizeAgentPolicyV4 } = require("../src/agent-merkle-v4");
const { buildRecipientTree } = require("../src/recipient-merkle-v3");
const { normalizeStateV4, computeStateIdV4, stateToJsonV4, CONTRACT_VERSION_V4 } = require("../src/vault-state-v4");
const { compileExactStateV4 } = require("../src/contract-compiler-v4");
const { MANIFEST_SCHEMA_V4, persistManifestV4, loadManifestV4 } = require("../src/manifest-v4");
const wr4 = require("../src/wallet-requests-v4");
const { makeDevSigner } = require("../src/signer-dev");

const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "pv4-hostile-"));
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
const attacker = KEY(0x66);

const VAULT_ID = "22".repeat(32);
const template = { owner: XO(owner), vaultId: VAULT_ID };

function agentEntry(kp, recips, over = {}) {
  return {
    agentPk: XO(kp), maxPerSpend: (20n * KAS).toString(), periodBudget: (50n * KAS).toString(),
    periodLengthDaa: "864000", periodStartDaa: "541000000", periodSpent: "0",
    approvalThreshold: (5n * KAS).toString(), agentMaxFeePerTx: (1n * KAS).toString(),
    recipients: recips.map(XO), ...over
  };
}
const REGISTRY = [agentEntry(agentA, [recipient, other]), agentEntry(agentB, [other])];

let seedCounter = 0;
function seed(over = {}, registry = REGISTRY) {
  seedCounter += 1;
  const outTxId = seedCounter.toString(16).padStart(2, "0").repeat(32).slice(0, 64);
  const policies = registry.map((e) => normalizeAgentPolicyV4({ ...e, agentRecipientRoot: buildRecipientTree(e.recipients).root }));
  const agentRoot = buildAgentTreeV4(policies).root;
  const state = normalizeStateV4({ protectedValue: (over.protectedKas ?? 1000n) * KAS + "", feeReserve: (5n * KAS).toString(), paused: "0", agentRoot, approvers: over.approvers ?? [], approvalM: over.approvalM ?? "0", policyNonce: over.policyNonce ?? "0" });
  const compiled = compileExactStateV4({ config, template: { owner: template.owner, vaultId: VAULT_ID }, state });
  const stateId = computeStateIdV4({ networkId: config.networkId, template, state });
  return persistManifestV4(config, {
    schema: MANIFEST_SCHEMA_V4, contractVersion: CONTRACT_VERSION_V4, networkId: config.networkId, vaultId: VAULT_ID,
    label: "hostile", status: "ACTIVE", template, agentRegistry: registry,
    live: { state: stateToJsonV4(state), stateId, outpoint: { transactionId: outTxId, index: 0 }, outpointValue: (state.protectedValue + state.feeReserve).toString(), scriptSha256: compiled.scriptSha256, covenantId: "41".repeat(32) },
    creationTxId: "42".repeat(32), latestTransitionTxId: null, lastTransition: null
  });
}
const fuelFor = (kp) => ({ outpoint: { transactionId: "43".repeat(32), index: 1 }, amount: (100n * KAS).toString(), scriptPublicKeyHex: `20${XO(kp)}ac` });
const signAll = (req, kp) => makeDevSigner(config, { secretHex: SEC(secretOf(kp)), expectedAddress: ADDR(kp) }).signInputs(req.transaction.unsignedSafeJson, req.transaction.signInputs);
function secretOf(kp) {
  const map = { [XO(owner)]: 1, [XO(agentA)]: 0x1e, [XO(agentB)]: 0x1f, [XO(recipient)]: 0x28, [XO(other)]: 0x29, [XO(attacker)]: 0x66 };
  approvers.forEach((a, i) => (map[XO(a)] = 20 + i));
  return map[XO(kp)];
}
function buildSpend(signerKp = agentA, params = {}) {
  return wr4.buildWalletRequestV4({ config, vaultId: VAULT_ID, action: "agentSpend", params: { payAmountSompi: (4n * KAS).toString(), agentPk: XO(signerKp), recipient: XO(recipient), ...params }, signerAddress: ADDR(signerKp) });
}

/* ---------------------------------------------------------- concurrency */

test("G10 two-tab: two requests on one predecessor — only ONE finalizes; the second is CLAIM_CONFLICT", () => {
  seed();
  const a = buildSpend(agentA);
  const b = buildSpend(agentA, { recipient: XO(other) });
  assert.notEqual(a.txId, b.txId);
  const doneA = wr4.finalizeWalletRequestV4({ config, requestId: a.requestId, signedSafeJson: signAll(a, agentA) });
  assert.equal(doneA.state, "PREFLIGHT_VERIFIED");
  // second transition on the SAME predecessor outpoint is refused
  assert.throws(() => wr4.finalizeWalletRequestV4({ config, requestId: b.requestId, signedSafeJson: signAll(b, agentA) }), (e) => e.code === "CLAIM_CONFLICT");
});

test("G10 crash/duplicate: finalizing the SAME request twice is refused by the state machine", () => {
  seed();
  const a = buildSpend(agentA);
  wr4.finalizeWalletRequestV4({ config, requestId: a.requestId, signedSafeJson: signAll(a, agentA) });
  // duplicate FINALIZE call: request is now PREFLIGHT_VERIFIED, not BUILT
  assert.throws(() => wr4.finalizeWalletRequestV4({ config, requestId: a.requestId, signedSafeJson: signAll(a, agentA) }), /not BUILT/);
});

test("G10 stale: a request built against a superseded predecessor is STALE at finalize", () => {
  seed();
  const a = buildSpend(agentA);
  // advance the manifest to a genuinely DIFFERENT live state (different
  // protected value => different stateId => the request's predecessor is
  // superseded).
  seed({ protectedKas: 900n });
  assert.throws(() => wr4.finalizeWalletRequestV4({ config, requestId: a.requestId, signedSafeJson: signAll(a, agentA) }), (e) => e.code === "STALE");
});

/* ------------------------------------------------------- freeze boundary */

test("G13 freeze: a wallet that mutates an OUTPUT (recipient/amount/change) is rejected (immutability)", () => {
  seed();
  const a = buildSpend(agentA);
  const signed = JSON.parse(signAll(a, agentA));
  // move value from the successor into a new attacker output would change outputs;
  // even a single-field change is caught. Bump the payment output value.
  signed.outputs[0].value = (BigInt(signed.outputs[0].value) + 1n).toString();
  assert.throws(() => wr4.finalizeWalletRequestV4({ config, requestId: a.requestId, signedSafeJson: JSON.stringify(signed) }), (e) => e.code === "SIGNATURE_INVALID");
});

test("G13 freeze: a wallet that mutates an INPUT outpoint/sequence is rejected (immutability)", () => {
  seed();
  const a = buildSpend(agentA);
  const signed = JSON.parse(signAll(a, agentA));
  signed.inputs[0].sequence = "5";
  assert.throws(() => wr4.finalizeWalletRequestV4({ config, requestId: a.requestId, signedSafeJson: JSON.stringify(signed) }), (e) => e.code === "SIGNATURE_INVALID");
});

test("G13 identity: signing with the WRONG key passes immutability but FAILS the production covenant preflight", () => {
  seed();
  const a = buildSpend(agentA);
  // the attacker signs input 0 instead of agent A — only the signature script
  // differs (immutability OK), but the covenant checkSig(agentA) fails.
  const wrong = makeDevSigner(config, { secretHex: SEC(secretOf(attacker)), expectedAddress: ADDR(attacker) }).signInputs(a.transaction.unsignedSafeJson, a.transaction.signInputs);
  assert.throws(() => wr4.finalizeWalletRequestV4({ config, requestId: a.requestId, signedSafeJson: wrong }), (e) => e.code === "PREFLIGHT_FAILED");
});

/* ----------------------------------------------------------- approvals */

test("G13 approvals: an approval collected for request A does not verify on request B (cross-tx replay)", () => {
  seed({ approvers: approvers.map(XO), approvalM: "2" });
  const a = wr4.buildWalletRequestV4({ config, vaultId: VAULT_ID, action: "agentSpend", params: { payAmountSompi: (6n * KAS).toString(), agentPk: XO(agentA), recipient: XO(recipient), fuel: fuelFor(agentA) }, signerAddress: ADDR(agentA) });
  const b = wr4.buildWalletRequestV4({ config, vaultId: VAULT_ID, action: "agentSpend", params: { payAmountSompi: (6n * KAS).toString(), agentPk: XO(agentA), recipient: XO(other), fuel: fuelFor(agentA) }, signerAddress: ADDR(agentA) });
  // an approver signs A's transaction, then that signature is offered to B
  const sigForA = makeDevSigner(config, { secretHex: SEC(secretOf(approvers[0])), expectedAddress: ADDR(approvers[0]) }).signInputs(a.transaction.unsignedSafeJson, [{ index: 0 }]);
  assert.throws(() => wr4.collectApprovalV4({ config, requestId: b.requestId, approverAddress: ADDR(approvers[0]), signedSafeJson: sigForA }), (e) => e.code === "SIGNATURE_INVALID");
});

test("G13 approvals: unknown approver and duplicate approval are refused", () => {
  seed({ approvers: approvers.map(XO), approvalM: "2" });
  const a = wr4.buildWalletRequestV4({ config, vaultId: VAULT_ID, action: "agentSpend", params: { payAmountSompi: (6n * KAS).toString(), agentPk: XO(agentA), recipient: XO(recipient), fuel: fuelFor(agentA) }, signerAddress: ADDR(agentA) });
  const approverSign = (kp) => makeDevSigner(config, { secretHex: SEC(secretOf(kp)), expectedAddress: ADDR(kp) }).signInputs(a.transaction.unsignedSafeJson, [{ index: 0 }]);
  // unknown approver (attacker signs, presents own address)
  assert.throws(() => wr4.collectApprovalV4({ config, requestId: a.requestId, approverAddress: ADDR(attacker), signedSafeJson: approverSign(attacker) }), (e) => e.code === "UNKNOWN_APPROVER");
  // valid approval, then duplicate from the same approver
  wr4.collectApprovalV4({ config, requestId: a.requestId, approverAddress: ADDR(approvers[0]), signedSafeJson: approverSign(approvers[0]) });
  assert.throws(() => wr4.collectApprovalV4({ config, requestId: a.requestId, approverAddress: ADDR(approvers[0]), signedSafeJson: approverSign(approvers[0]) }), (e) => e.code === "DUPLICATE_APPROVAL");
});

/* --------------------------------------------------------- fee/reserve */

test("G13 fee/reserve: browser-supplied reserveConsumed > fee (but below the agent cap) is rejected, not trusted", () => {
  seed();
  // agentMaxFeePerTx = 1 KAS; the exact fee is ~0.04 KAS. 0.5 KAS is below the
  // cap yet far above the real fee => RESERVE_OVER_FEE (the browser number is
  // not trusted; the SDK computes the exact fee).
  assert.throws(() => buildSpend(agentA, { fuel: fuelFor(agentA), reserveConsumedSompi: "50000000" }), (e) => e.code === "RESERVE_OVER_FEE");
  // and a value above the cap is rejected by the per-agent fee cap
  assert.throws(() => buildSpend(agentA, { fuel: fuelFor(agentA), reserveConsumedSompi: (90n * KAS).toString() }), (e) => e.code === "OVER_AGENT_FEE_CAP");
});

/* ---------------------------------------------------------- network gate */

test("G11 network gate: v0.4 requests refuse to build on any non-operational network (Gate R posture)", () => {
  seed();
  // A hand-rolled mainnet config WITHOUT the dual-flag unlock is refused
  // (post-Gate-R, mainnet is operational ONLY with the unlock — pinned in
  // mainnet-gate-r.test.js; a hostile caller cannot fake it by spreading).
  const mainnetish = { ...config, networkId: "mainnet" };
  assert.throws(() => wr4.buildWalletRequestV4({ config: mainnetish, vaultId: VAULT_ID, action: "agentSpend", params: { payAmountSompi: (4n * KAS).toString(), agentPk: XO(agentA), recipient: XO(recipient) }, signerAddress: ADDR(agentA) }), /dual-flag unlock/);
  // Unknown networks stay fail-closed.
  const devnetish = { ...config, networkId: "devnet" };
  assert.throws(() => wr4.buildWalletRequestV4({ config: devnetish, vaultId: VAULT_ID, action: "agentSpend", params: { payAmountSompi: (4n * KAS).toString(), agentPk: XO(agentA), recipient: XO(recipient) }, signerAddress: ADDR(agentA) }), /not an operational/);
});

/* ------------------------------------------------- agent-tree integrity */

test("G2/G13: a manifest whose registry cannot reproduce the covenant agentRoot fails closed on load", () => {
  const m = seed();
  // tamper the persisted registry so its root no longer matches live.agentRoot
  const p = path.join(dataRoot, "vaults", VAULT_ID, "manifest.json");
  const doc = JSON.parse(fs.readFileSync(p, "utf8"));
  doc.agentRegistry[0].maxPerSpend = (999n * KAS).toString();
  fs.writeFileSync(p, JSON.stringify(doc));
  assert.throws(() => loadManifestV4(config, VAULT_ID), (e) => e.code === "REGISTRY_ROOT_MISMATCH");
  // and therefore no operation can be built against it
  assert.throws(() => buildSpend(agentA), (e) => e.code === "REGISTRY_ROOT_MISMATCH" || /registry/.test(e.message));
  void m;
});

/* ------------------------------------------------------- browser trust */

test("G13 browser trust: caller-injected successor/agentRoot/policyNonce fields are ignored (server derives)", () => {
  seed();
  const clean = buildSpend(agentA);
  const injected = wr4.buildWalletRequestV4({ config, vaultId: VAULT_ID, action: "agentSpend", params: { payAmountSompi: (4n * KAS).toString(), agentPk: XO(agentA), recipient: XO(recipient), successor: { protectedValue: "1" }, agentRoot: "cd".repeat(32), policyNonce: "99" }, signerAddress: ADDR(agentA) });
  assert.equal(injected.successorStateId, clean.successorStateId, "successor is server-derived, not caller-supplied");
});

test("G13 pause: a paused vault refuses agent spends but allows owner unpause", () => {
  const m = seed();
  // re-persist as paused by mutating state
  const pausedState = normalizeStateV4({ ...stateToJsonV4(m.live.state), paused: "1" });
  const compiled = compileExactStateV4({ config, template: { owner: template.owner, vaultId: VAULT_ID }, state: pausedState });
  persistManifestV4(config, {
    ...m,
    status: "PAUSED",
    agentRegistry: m.agentRegistry.map((e) => ({ agentPk: e.policy.agentPk, maxPerSpend: e.policy.maxPerSpend.toString(), periodBudget: e.policy.periodBudget.toString(), periodLengthDaa: e.policy.periodLengthDaa.toString(), periodStartDaa: e.policy.periodStartDaa.toString(), periodSpent: e.policy.periodSpent.toString(), approvalThreshold: e.policy.approvalThreshold.toString(), agentMaxFeePerTx: e.policy.agentMaxFeePerTx.toString(), recipients: [...e.recipients] })),
    live: { state: stateToJsonV4(pausedState), stateId: computeStateIdV4({ networkId: config.networkId, template, state: pausedState }), outpoint: m.live.outpoint, outpointValue: (pausedState.protectedValue + pausedState.feeReserve).toString(), scriptSha256: compiled.scriptSha256, covenantId: m.live.covenantId }
  });
  assert.throws(() => buildSpend(agentA), /ACTIVE|paused/);
  // owner unpause is allowed while paused
  const un = wr4.buildWalletRequestV4({ config, vaultId: VAULT_ID, action: "ownerUnpause", params: { fuel: fuelFor(owner) }, signerAddress: ADDR(owner) });
  const done = wr4.finalizeWalletRequestV4({ config, requestId: un.requestId, signedSafeJson: signAll(un, owner) });
  assert.equal(done.state, "PREFLIGHT_VERIFIED");
});
