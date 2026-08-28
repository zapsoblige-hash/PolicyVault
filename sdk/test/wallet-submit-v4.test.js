"use strict";

/* SDK — Checkpoint H live-layer PURE-LOGIC coverage (offline). The live
 * broadcast / chain-proof / reconcile paths were exercised on real testnet-10
 * (genesis chain-proven; reconcile-v4 released a stale claim after proving the
 * predecessor live + effect absent — see docs/testnet-evidence.md). This suite
 * covers the offline-testable, security-relevant helpers that a successful
 * spend would exercise but that the live lifecycle could NOT reach because the
 * v0.4 covenant spend is mempool-non-standard (18 > 15 sig-ops — see
 * docs/v04-h-standardness-finding.md). The atomic manifest+registry advance
 * math must be correct for when the covenant is fixed. */

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
const { buildWalletRequestV4, RequestState } = require("../src/wallet-requests-v4");
const { deriveSuccessorRegistry, manifestToJson } = require("../src/wallet-submit-v4");

const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "pv4-submit-"));
const config = loadConfig({ dataRoot });
const kaspa = require(config.rustyKaspaModule);
const KEY = (v) => new kaspa.PrivateKey(v.toString(16).padStart(2, "0").repeat(32));
const XO = (p) => p.toPublicKey().toXOnlyPublicKey().toString().toLowerCase();
const KAS = 100000000n;

const owner = KEY(1), agentA = KEY(0x1e), agentB = KEY(0x1f), recipient = KEY(0x28), other = KEY(0x29);
const VAULT_ID = "22".repeat(32);
const template = { owner: XO(owner), vaultId: VAULT_ID };

function agentEntry(kp, recips, over = {}) {
  return { agentPk: XO(kp), maxPerSpend: (20n * KAS).toString(), periodBudget: (50n * KAS).toString(), periodLengthDaa: "864000", periodStartDaa: "541000000", periodSpent: "0", approvalThreshold: (5n * KAS).toString(), agentMaxFeePerTx: (1n * KAS).toString(), recipients: recips.map(XO), ...over };
}
const REGISTRY = [agentEntry(agentA, [recipient, other]), agentEntry(agentB, [other])];

async function seed() {
  const policies = REGISTRY.map((e) => normalizeAgentPolicyV4({ ...e, agentRecipientRoot: buildRecipientTree(e.recipients).root }));
  const agentRoot = buildAgentTreeV4(policies).root;
  const state = normalizeStateV4({ protectedValue: (1000n * KAS).toString(), feeReserve: (5n * KAS).toString(), paused: "0", agentRoot, approvers: [], approvalM: "0", policyNonce: "0" });
  const compiled = compileExactStateV4({ config, template: { owner: template.owner, vaultId: VAULT_ID }, state });
  const stateId = computeStateIdV4({ networkId: config.networkId, template, state });
  return await persistManifestV4(config, {
    schema: MANIFEST_SCHEMA_V4, contractVersion: CONTRACT_VERSION_V4, networkId: config.networkId, vaultId: VAULT_ID, label: "t", status: "ACTIVE", template, agentRegistry: REGISTRY,
    live: { state: stateToJsonV4(state), stateId, outpoint: { transactionId: "42".repeat(32), index: 0 }, outpointValue: (state.protectedValue + state.feeReserve).toString(), scriptSha256: compiled.scriptSha256, covenantId: "41".repeat(32) },
    creationTxId: "42".repeat(32), latestTransitionTxId: null, lastTransition: null
  });
}

test("H1: RequestState carries the live submission states", async () => {
  for (const s of ["SUBMITTING", "SUBMITTED", "CHAIN_VERIFIED", "SUBMISSION_REJECTED", "RECONCILIATION_REQUIRED", "TERMINATED_UNKNOWN"]) {
    assert.equal(RequestState[s], s, `RequestState.${s}`);
  }
});

test("H5: registry advance math (agentSpend accumulation) reconstructs the successor root", async () => {
  const manifest = await seed();
  // Simulate a spend request's derived successor: agent A periodSpent += 4 KAS.
  const request = {
    sdkAction: "agentSpend",
    agentPk: XO(agentA),
    build: { payment: { value: (4n * KAS).toString() }, callExtra: { periodsElapsed: "0" }, successorState: null }
  };
  const nextReg = deriveSuccessorRegistry(manifest, request);
  const advanced = nextReg.find((e) => e.agentPk === XO(agentA));
  const unchanged = nextReg.find((e) => e.agentPk === XO(agentB));
  assert.equal(advanced.periodSpent, (4n * KAS).toString(), "spending agent periodSpent advanced");
  assert.equal(unchanged.periodSpent, "0", "unrelated agent unchanged");
  // The advanced registry reproduces the successor agentRoot the covenant would compute.
  const advancedPolicies = nextReg.map((e) => normalizeAgentPolicyV4({ ...e, agentRecipientRoot: buildRecipientTree(e.recipients).root }));
  const successorRoot = buildAgentTreeV4(advancedPolicies).root;
  // Independent single-leaf fold check via the agent-merkle module.
  const { generateAgentProofV4, foldAgentPolicyV4 } = require("../src/agent-merkle-v4");
  const before = REGISTRY.map((e) => normalizeAgentPolicyV4({ ...e, agentRecipientRoot: buildRecipientTree(e.recipients).root }));
  const tree = buildAgentTreeV4(before);
  const proof = generateAgentProofV4(tree, XO(agentA));
  const newLeafPolicy = { ...proof.policy, periodSpent: (4n * KAS).toString() };
  assert.equal(foldAgentPolicyV4(newLeafPolicy, proof.siblingsHex, proof.pathBits), successorRoot, "single-leaf fold == rebuilt successor root");
});

test("H5: value/approver/pause ops leave the registry unchanged; setAgentRoot ops carry the new registry", async () => {
  const manifest = await seed();
  const unchanged = deriveSuccessorRegistry(manifest, { sdkAction: "ownerTopUp", build: {} });
  assert.equal(unchanged.length, 2);
  assert.equal(unchanged.find((e) => e.agentPk === XO(agentA)).periodSpent, "0");
  const newReg = [agentEntry(agentA, [recipient])];
  const carried = deriveSuccessorRegistry(manifest, { sdkAction: "ownerSetAgentRoot", newRegistry: newReg, build: {} });
  assert.deepEqual(carried, newReg);
});

test("H: manifestToJson round-trips through the strict normalizer", async () => {
  const manifest = await seed();
  const round = require("../src/manifest-v4").normalizeManifestV4(manifestToJson(manifest));
  assert.equal(round.agentRegistryRoot, manifest.agentRegistryRoot);
  assert.equal(round.live.stateId, manifest.live.stateId);
});
