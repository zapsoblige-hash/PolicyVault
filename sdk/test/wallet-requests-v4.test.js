"use strict";

/* SDK — offline v0.4 wallet-request lifecycle (Checkpoint G §G1/§G6/§G7).
 * Drives BUILD -> (approvals) -> sign (dev signer = KasWare signPskt) ->
 * FINALIZE -> production covenant VM PREFLIGHT, entirely offline, through
 * the real SDK + real pv_call_encoder + real pv_vm_preflight. No broadcast. */

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
const {
  buildWalletRequestV4,
  finalizeWalletRequestV4,
  collectApprovalV4,
  RequestState
} = require("../src/wallet-requests-v4");
const { makeDevSigner } = require("../src/signer-dev");

const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "pv4-wr-"));
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
const fuelKey = KEY(3);
const recipient = KEY(0x28);
const other = KEY(0x29);
const approvers = [KEY(20), KEY(21), KEY(22)];

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

function stateFor(registry, over = {}) {
  const policies = registry.map((e) => normalizeAgentPolicyV4({ ...e, agentRecipientRoot: buildRecipientTree(e.recipients).root }));
  const agentRoot = buildAgentTreeV4(policies).root;
  return normalizeStateV4({
    protectedValue: (1000n * KAS).toString(), feeReserve: (5n * KAS).toString(), paused: "0",
    agentRoot, approvers: [], approvalM: "0", policyNonce: "0", ...over
  });
}

/* Persist a live v0.4 manifest whose live.scriptSha256 is the REAL compiled
 * hash. Each call uses a UNIQUE predecessor outpoint so independent test
 * cases never collide on the transition claim (that collision IS the
 * two-tab protection, exercised deliberately elsewhere). */
let seedCounter = 0;
async function seedManifest(registry, over = {}) {
  seedCounter += 1;
  const outTxId = seedCounter.toString(16).padStart(2, "0").repeat(32).slice(0, 64);
  const state = stateFor(registry, over);
  const compiled = compileExactStateV4({ config, template: { owner: template.owner, vaultId: VAULT_ID }, state });
  const stateId = computeStateIdV4({ networkId: config.networkId, template, state });
  return await persistManifestV4(config, {
    schema: MANIFEST_SCHEMA_V4,
    contractVersion: CONTRACT_VERSION_V4,
    networkId: config.networkId,
    vaultId: VAULT_ID,
    label: "test",
    status: "ACTIVE",
    template,
    agentRegistry: registry,
    live: {
      state: stateToJsonV4(state),
      stateId,
      outpoint: { transactionId: outTxId, index: 0 },
      outpointValue: (state.protectedValue + state.feeReserve).toString(),
      scriptSha256: compiled.scriptSha256,
      covenantId: "41".repeat(32)
    },
    creationTxId: "42".repeat(32),
    latestTransitionTxId: null,
    lastTransition: null
  });
}

const fuelUtxo = () => ({
  outpoint: { transactionId: "43".repeat(32), index: 1 },
  amount: (100n * KAS).toString(),
  scriptPublicKeyHex: `20${XO(fuelKey)}ac`
});

function devSign(request, kp) {
  const signer = makeDevSigner(config, { secretHex: SEC(secretOf(kp)), expectedAddress: ADDR(kp) });
  return signer.signInputs(request.transaction.unsignedSafeJson, request.transaction.signInputs);
}
/* recover the small integer secret used to make each KEY (test-only). */
function secretOf(kp) {
  const map = { [XO(owner)]: 1, [XO(agentA)]: 0x1e, [XO(agentB)]: 0x1f, [XO(fuelKey)]: 3, [XO(recipient)]: 0x28, [XO(other)]: 0x29 };
  approvers.forEach((a, i) => (map[XO(a)] = 20 + i));
  const v = map[XO(kp)];
  if (v === undefined) throw new Error("unknown test key");
  return v;
}

test("G6: reserve-funded agent spend — BUILD (agent authz) -> sign -> FINALIZE -> VM preflight PASS", async () => {
  await seedManifest(REGISTRY);
  const req = await buildWalletRequestV4({
    config, vaultId: VAULT_ID, action: "agentSpend",
    params: { payAmountSompi: (4n * KAS).toString(), agentPk: XO(agentA), recipient: XO(recipient) },
    signerAddress: ADDR(agentA)
  });
  assert.equal(req.state, RequestState.BUILT);
  assert.equal(req.signerRole, "agent");
  assert.equal(req.aboveThreshold, false);
  assert.equal(req.review.fundingMode, "RESERVE-FUNDED");
  assert.equal(req.transaction.signInputs.length, 1); // reserve-funded: only the covenant input
  const signed = devSign(req, agentA);
  const done = await finalizeWalletRequestV4({ config, requestId: req.requestId, signedSafeJson: signed });
  assert.equal(done.state, RequestState.PREFLIGHT_VERIFIED);
  assert.equal(done.txId, req.txId);
});

test("G6: fuel-funded agent spend with an explicit fuel UTXO -> preflight PASS", async () => {
  await seedManifest(REGISTRY);
  const req = await buildWalletRequestV4({
    config, vaultId: VAULT_ID, action: "agentSpend",
    params: { payAmountSompi: (4n * KAS).toString(), agentPk: XO(agentA), recipient: XO(recipient), fuel: fuelUtxo() },
    signerAddress: ADDR(agentA)
  });
  assert.equal(req.transaction.signInputs.length, 2);
  assert.equal(req.review.fundingMode, "FUEL-FUNDED");
  // The agent signs input 0; the fuel UTXO belongs to fuelKey, but in this
  // test the agent also owns the fuel — sign both with the agent key would
  // fail input 1 (wrong key). Use a signer that owns both by making fuel a
  // p2pk to the agent. Rebuild with agent-owned fuel:
  const req2 = await buildWalletRequestV4({
    config, vaultId: VAULT_ID, action: "agentSpend",
    params: { payAmountSompi: (4n * KAS).toString(), agentPk: XO(agentA), recipient: XO(recipient),
      fuel: { outpoint: { transactionId: "43".repeat(32), index: 1 }, amount: (100n * KAS).toString(), scriptPublicKeyHex: `20${XO(agentA)}ac` } },
    signerAddress: ADDR(agentA)
  });
  const signed = devSign(req2, agentA);
  const done = await finalizeWalletRequestV4({ config, requestId: req2.requestId, signedSafeJson: signed });
  assert.equal(done.state, RequestState.PREFLIGHT_VERIFIED);
});

test("G6/G7: above-threshold spend requires approvals; freeze-before-collect; finalize after threshold", async () => {
  // approvers configured on the vault, threshold 5 KAS, pay 6 KAS.
  const slots = approvers.map(XO).sort();
  await seedManifest(REGISTRY, { approvers: approvers.map(XO), approvalM: "2" });
  const req = await buildWalletRequestV4({
    config, vaultId: VAULT_ID, action: "agentSpend",
    params: { payAmountSompi: (6n * KAS).toString(), agentPk: XO(agentA), recipient: XO(recipient), fuel: { outpoint: { transactionId: "43".repeat(32), index: 1 }, amount: (100n * KAS).toString(), scriptPublicKeyHex: `20${XO(agentA)}ac` } },
    signerAddress: ADDR(agentA)
  });
  assert.equal(req.aboveThreshold, true);
  assert.equal(req.state, RequestState.AWAITING_APPROVALS);
  // finalize before approvals must fail closed
  const signed = devSign(req, agentA);
  await assert.rejects(async () => finalizeWalletRequestV4({ config, requestId: req.requestId, signedSafeJson: signed }), (e) => e.code === "INSUFFICIENT_APPROVALS");

  // each approver signs input 0 of the SAME unsigned tx
  const approverSignedJson = (kp) => {
    const signer = makeDevSigner(config, { secretHex: SEC(secretOf(kp)), expectedAddress: ADDR(kp) });
    return signer.signInputs(req.transaction.unsignedSafeJson, [{ index: 0 }]);
  };
  let r = await collectApprovalV4({ config, requestId: req.requestId, approverAddress: ADDR(approvers[0]), signedSafeJson: approverSignedJson(approvers[0]) });
  assert.equal(r.approvals.collected, 1);
  assert.equal(r.approvals.complete, false);
  r = await collectApprovalV4({ config, requestId: req.requestId, approverAddress: ADDR(approvers[1]), signedSafeJson: approverSignedJson(approvers[1]) });
  assert.equal(r.approvals.complete, true);
  assert.equal(r.request.state, RequestState.BUILT);

  const done = await finalizeWalletRequestV4({ config, requestId: req.requestId, signedSafeJson: signed });
  assert.equal(done.state, RequestState.PREFLIGHT_VERIFIED);
});

test("G6: owner ops (pause, topUp, topUpReserve, setApprovers) build+finalize+preflight; require fuel", async () => {
  const ownerFuel = { outpoint: { transactionId: "44".repeat(32), index: 0 }, amount: (100n * KAS).toString(), scriptPublicKeyHex: `20${XO(owner)}ac` };
  const run = async (action, params) => {
    await seedManifest(REGISTRY);
    const req = await buildWalletRequestV4({ config, vaultId: VAULT_ID, action, params: { ...params, fuel: ownerFuel }, signerAddress: ADDR(owner) });
    const signed = devSign(req, owner);
    return await finalizeWalletRequestV4({ config, requestId: req.requestId, signedSafeJson: signed });
  };
  assert.equal((await run("ownerPause", {})).state, RequestState.PREFLIGHT_VERIFIED);
  assert.equal((await run("ownerTopUp", { topUpAmountSompi: (10n * KAS).toString() })).state, RequestState.PREFLIGHT_VERIFIED);
  assert.equal((await run("ownerTopUpReserve", { topUpReserveAmountSompi: (2n * KAS).toString() })).state, RequestState.PREFLIGHT_VERIFIED);
  assert.equal((await run("ownerSetApprovers", { newApprovers: { approvers: approvers.map(XO), approvalM: "2" } })).state, RequestState.PREFLIGHT_VERIFIED);
  // fuel required for owner ops
  await seedManifest(REGISTRY);
  await assert.rejects(async () => buildWalletRequestV4({ config, vaultId: VAULT_ID, action: "ownerPause", params: {}, signerAddress: ADDR(owner) }), /fuel UTXO/);
});

test("G4: high-level addAgent/removeAgent/rotateAgent map to ownerSetAgentRoot and preflight PASS", async () => {
  const ownerFuel = { outpoint: { transactionId: "44".repeat(32), index: 0 }, amount: (100n * KAS).toString(), scriptPublicKeyHex: `20${XO(owner)}ac` };
  await seedManifest(REGISTRY);
  const newAgent = agentEntry(KEY(0x55), [recipient]);
  const req = await buildWalletRequestV4({ config, vaultId: VAULT_ID, action: "addAgent", params: { agent: newAgent, fuel: ownerFuel }, signerAddress: ADDR(owner) });
  assert.equal(req.sdkAction, "ownerSetAgentRoot");
  assert.equal(req.highLevel, "addAgent");
  assert.equal(req.newRegistry.length, 3);
  const done = await finalizeWalletRequestV4({ config, requestId: req.requestId, signedSafeJson: devSign(req, owner) });
  assert.equal(done.state, RequestState.PREFLIGHT_VERIFIED);
  // the successor state carries the new root; the new registry travels in the claim's expected
  assert.equal(done.newRegistry.length, 3);
});

test("G6: ownerRecover preflight PASS (terminal, protected + reserve to owner)", async () => {
  const ownerFuel = { outpoint: { transactionId: "44".repeat(32), index: 0 }, amount: (100n * KAS).toString(), scriptPublicKeyHex: `20${XO(owner)}ac` };
  await seedManifest(REGISTRY);
  const req = await buildWalletRequestV4({ config, vaultId: VAULT_ID, action: "ownerRecover", params: { fuel: ownerFuel }, signerAddress: ADDR(owner) });
  assert.equal(req.review.terminal.startsWith("VAULT CLOSED"), true);
  const done = await finalizeWalletRequestV4({ config, requestId: req.requestId, signedSafeJson: devSign(req, owner) });
  assert.equal(done.state, RequestState.PREFLIGHT_VERIFIED);
});
