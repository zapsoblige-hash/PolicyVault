"use strict";

/*
 * GOVERNANCE-TERMINAL-RACE-01 (second item, "build-before-consume"): an
 * AUTHORITY EXPANSION request is admitted (requireApprovedProposal),
 * BUILT and DURABLY SAVED, and only then is the proposal consumed
 * (markProposalConsumed). If the proposal reaches a terminal state
 * between admission and consumption (owner cancel racing the build,
 * or another build consuming it), consumption refuses and the API
 * refuses the build response — but the built request had already been
 * persisted with a verified intent manifest, and the finalize/submit
 * gate re-verifies only the manifest. The request could therefore
 * continue to signing/submission under a proposal that was never
 * consumed by it. The correction: a refused consumption marks the
 * durable request GOVERNANCE_REFUSED and the finalize/submit gate
 * refuses it, exactly like the intent-derivation FAILED marker.
 *
 * Layer: SDK (real api.handle over a temp JSON data root with the real
 * v0.4 build pipeline) + module-level gate assertion.
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");
const os = require("os");
const crypto = require("crypto");

const { handle, loadConfig } = require("../../server/src/api");
const { buildAgentTreeV4, normalizeAgentPolicyV4 } = require("../src/agent-merkle-v4");
const { buildRecipientTree } = require("../src/recipient-merkle-v3");
const { normalizeStateV4, computeStateIdV4, stateToJsonV4, CONTRACT_VERSION_V4 } = require("../src/vault-state-v4");
const { compileExactStateV4 } = require("../src/contract-compiler-v4");
const { MANIFEST_SCHEMA_V4, persistManifestV4 } = require("../src/manifest-v4");
const wr4 = require("../src/wallet-requests-v4");
const governance = require("../../server/src/governance");
const { assertRequestManifestVerified } = require("../../server/src/intent-records");

const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "pv-gov-consume-"));
const config = loadConfig({ dataRoot });
const kaspa = require(config.rustyKaspaModule);
const KEY = (v) => new kaspa.PrivateKey(v.toString(16).padStart(2, "0").repeat(32));
const XO = (p) => p.toPublicKey().toXOnlyPublicKey().toString().toLowerCase();
const ADDR = (p) => p.toPublicKey().toAddress(config.networkId).toString();
const SIGN = (p, message) => kaspa.signMessage({ message, privateKey: p.toString() });
const KAS = 100000000n;
const owner = KEY(1);
const agentA = KEY(0x1e);
const recipient = KEY(0x28);
const VAULT_ID = "39".repeat(32);
const template = { owner: XO(owner), vaultId: VAULT_ID };

function agentEntry(kp, recipients) {
  return {
    agentPk: XO(kp), maxPerSpend: (20n * KAS).toString(), periodBudget: (50n * KAS).toString(),
    periodLengthDaa: "864000", periodStartDaa: "541000000", periodSpent: "0",
    approvalThreshold: (5n * KAS).toString(), agentMaxFeePerTx: (1n * KAS).toString(),
    recipients: recipients.map(XO)
  };
}
const REGISTRY = [agentEntry(agentA, [recipient])];

async function seed() {
  const policies = REGISTRY.map((e) => normalizeAgentPolicyV4({ ...e, agentRecipientRoot: buildRecipientTree(e.recipients).root }));
  const agentRoot = buildAgentTreeV4(policies).root;
  const state = normalizeStateV4({ protectedValue: (1000n * KAS).toString(), feeReserve: (5n * KAS).toString(), paused: "1", agentRoot, approvers: [], approvalM: "0", policyNonce: "0" });
  const compiled = compileExactStateV4({ config, template, state });
  const stateId = computeStateIdV4({ networkId: config.networkId, template, state });
  return persistManifestV4(config, {
    schema: MANIFEST_SCHEMA_V4, contractVersion: CONTRACT_VERSION_V4, networkId: config.networkId, vaultId: VAULT_ID,
    label: "consume-refusal test", status: "PAUSED", template, agentRegistry: REGISTRY,
    live: { state: stateToJsonV4(state), stateId, outpoint: { transactionId: "51".repeat(32), index: 0 }, outpointValue: (state.protectedValue + state.feeReserve).toString(), scriptSha256: compiled.scriptSha256, covenantId: "41".repeat(32) },
    creationTxId: "42".repeat(32), latestTransitionTxId: null, lastTransition: null
  });
}
const POST = (segs, body) => handle(config, "POST", segs, {}, body);
const ownerFuel = () => ({ outpoint: { transactionId: "43".repeat(32), index: 1 }, amount: (100n * KAS).toString(), scriptPublicKeyHex: `20${XO(owner)}ac` });
const requestFiles = () => fs.existsSync(path.join(dataRoot, "requests")) ? fs.readdirSync(path.join(dataRoot, "requests")).filter((f) => f.endsWith(".json")) : [];

async function proposeAndApprove(action, params) {
  const created = await POST(["governance", "proposals"], { vaultId: VAULT_ID, action, params });
  assert.equal(created.status, 201);
  const proposal = created.body.proposal;
  const approved = await POST(["governance", "proposals", proposal.proposalId, "approvals"], { approverAddress: ADDR(owner), signature: SIGN(owner, proposal.approvalMessage) });
  assert.equal(approved.status, 200);
  return approved.body.proposal;
}

test("a proposal cancelled between admission and consumption: the build refuses TERMINAL and the persisted built request is refused by the finalize/submit gate", async () => {
  await seed();
  const proposal = await proposeAndApprove("ownerUnpause", {});
  const before = new Set(requestFiles());
  // Race injection at the exact seam: the owner cancels the proposal right
  // after admission returns and before the build consumes it.
  const originalAdmit = governance.requireApprovedProposal;
  governance.requireApprovedProposal = async (args) => {
    const admitted = await originalAdmit(args);
    await governance.cancelProposal({ config, proposalId: args.proposalId, cancelledByXOnly: XO(owner) });
    return admitted;
  };
  let error = null;
  try {
    await POST(["wallet", "v4", "requests"], { vaultId: VAULT_ID, action: "ownerUnpause", params: { fuel: ownerFuel() }, signerAddress: ADDR(owner), proposalId: proposal.proposalId });
  } catch (e) {
    error = e;
  } finally {
    governance.requireApprovedProposal = originalAdmit;
  }
  assert.ok(error, "the build must refuse when consumption refuses");
  assert.equal(error.code, "GOVERNANCE_PROPOSAL_TERMINAL");
  const record = await governance.loadProposalRecord(config, proposal.proposalId);
  assert.equal(record.status, "CANCELLED", "the cancel won; the proposal was never consumed");
  assert.equal(record.lastConsumedRequestId ?? null, null);

  // The built request was durably saved before consumption was attempted.
  const created = requestFiles().filter((f) => !before.has(f));
  assert.equal(created.length, 1, "exactly one built request was persisted by the refused build");
  const request = await wr4.loadRequest(config, created[0].slice(0, -5));
  assert.ok(request && typeof request.manifestHash === "string", "the persisted request carries a verified intent manifest");

  // THE GAP / THE FIX: the finalize/submit gate must refuse this request.
  await assert.rejects(assertRequestManifestVerified(config, request), (e) => e.code === "GOVERNANCE_PROPOSAL_TERMINAL", "a request whose proposal consumption was refused must never finalize or submit");
  assert.equal(request.governanceConsumption, "REFUSED", "the durable request is marked fail-closed");
});

test("an ordinary consumed build stays finalizable (no false refusal)", async () => {
  await seed();
  const proposal = await proposeAndApprove("ownerUnpause", {});
  const built = await POST(["wallet", "v4", "requests"], { vaultId: VAULT_ID, action: "ownerUnpause", params: { fuel: ownerFuel() }, signerAddress: ADDR(owner), proposalId: proposal.proposalId });
  assert.equal(built.status, 201);
  const request = await wr4.loadRequest(config, built.body.request.requestId);
  assert.equal(request.governanceConsumption, undefined);
  await assertRequestManifestVerified(config, request);
  const record = await governance.loadProposalRecord(config, proposal.proposalId);
  assert.equal(record.status, "CONSUMED");
  assert.equal(record.lastConsumedRequestId, request.requestId);
});

/* GOVERNANCE-TERMINAL-RACE-01 IR-02: a crash between the consumption
 * refusal and the marker write must not leave a finalizable request. The
 * finalize/submit gate re-checks the DURABLE proposal: the manifest record
 * names the proposal, and the proposal must record THIS request as its
 * consumer. Simulated here by stripping the marker from the persisted
 * request after the refused build (exactly the crash-before-marker state). */
test("IR-02: crash before the refusal marker — the finalize/submit gate still refuses on durable proposal truth", async () => {
  await seed();
  const proposal = await proposeAndApprove("ownerUnpause", {});
  const before = new Set(requestFiles());
  const originalAdmit = governance.requireApprovedProposal;
  governance.requireApprovedProposal = async (args) => {
    const admitted = await originalAdmit(args);
    await governance.cancelProposal({ config, proposalId: args.proposalId, cancelledByXOnly: XO(owner) });
    return admitted;
  };
  try {
    await assert.rejects(POST(["wallet", "v4", "requests"], { vaultId: VAULT_ID, action: "ownerUnpause", params: { fuel: ownerFuel() }, signerAddress: ADDR(owner), proposalId: proposal.proposalId }), (e) => e.code === "GOVERNANCE_PROPOSAL_TERMINAL");
  } finally {
    governance.requireApprovedProposal = originalAdmit;
  }
  const created = requestFiles().filter((f) => !before.has(f));
  assert.equal(created.length, 1);
  const requestId = created[0].slice(0, -5);
  const marked = await wr4.loadRequest(config, requestId);
  assert.equal(marked.governanceConsumption, "REFUSED");
  // The crash-before-marker state: the durable request never received the marker.
  const unmarked = { ...marked };
  delete unmarked.governanceConsumption;
  delete unmarked.governanceConsumptionCode;
  await wr4.saveRequest(config, unmarked);
  const reloaded = await wr4.loadRequest(config, requestId);
  assert.equal(reloaded.governanceConsumption, undefined, "marker absent (simulated crash)");
  await assert.rejects(assertRequestManifestVerified(config, reloaded), (e) => e.code === "GOVERNANCE_PROPOSAL_TERMINAL", "durable proposal truth refuses the unmarked request");
});

test("IR-02: a request whose recorded proposal was consumed by a DIFFERENT request is refused; the consuming request stays finalizable", async () => {
  await seed();
  const proposal = await proposeAndApprove("ownerUnpause", {});
  const built = await POST(["wallet", "v4", "requests"], { vaultId: VAULT_ID, action: "ownerUnpause", params: { fuel: ownerFuel() }, signerAddress: ADDR(owner), proposalId: proposal.proposalId });
  assert.equal(built.status, 201);
  const consumer = await wr4.loadRequest(config, built.body.request.requestId);
  await assertRequestManifestVerified(config, consumer);
  // A forged sibling: same durable manifest record (same tx bytes), different request identity.
  const forged = { ...consumer, requestId: crypto.randomUUID() };
  await assert.rejects(assertRequestManifestVerified(config, forged), (e) => e.code === "GOVERNANCE_PROPOSAL_TERMINAL", "a request that is not the proposal's consumer cannot finalize under it");
  await assertRequestManifestVerified(config, consumer);
});
