"use strict";

/* SDK — durable v0.4 manifest + agent registry (Checkpoint G §G2). The
 * registry must deterministically reproduce the covenant agentRoot; a
 * registry that cannot fails closed (REGISTRY_ROOT_MISMATCH). */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");
const os = require("os");

const { loadConfig } = require("../src/config");
const { buildAgentTreeV4 } = require("../src/agent-merkle-v4");
const { buildRecipientTree } = require("../src/recipient-merkle-v3");
const { normalizeStateV4, computeStateIdV4, CONTRACT_VERSION_V4 } = require("../src/vault-state-v4");
const { MANIFEST_SCHEMA_V4, normalizeManifestV4, loadManifestV4, persistManifestV4 } = require("../src/manifest-v4");
const { loadAnyManifest } = require("../src/manifest-v2");

const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "pv4-manifest-"));
const config = loadConfig({ dataRoot });
const kaspa = require(config.rustyKaspaModule);
const KEY = (v) => new kaspa.PrivateKey(v.toString(16).padStart(2, "0").repeat(32));
const XO = (p) => p.toPublicKey().toXOnlyPublicKey().toString().toLowerCase();

const owner = KEY(1);
const agentA = KEY(0x1e);
const agentB = KEY(0x1f);
const recipient = KEY(0x28);
const other = KEY(0x29);
const KAS = 100000000n;

const rTreeA = buildRecipientTree([XO(recipient), XO(other)]);
const rTreeB = buildRecipientTree([XO(other)]);

/* Registry entries (recipient sets reproduce each agent's recipient root). */
function registry() {
  return [
    {
      agentPk: XO(agentA), maxPerSpend: (20n * KAS).toString(), periodBudget: (50n * KAS).toString(),
      periodLengthDaa: "864000", periodStartDaa: "541000000", periodSpent: "0",
      approvalThreshold: (5n * KAS).toString(), agentMaxFeePerTx: (1n * KAS).toString(),
      recipients: [XO(recipient), XO(other)]
    },
    {
      agentPk: XO(agentB), maxPerSpend: (30n * KAS).toString(), periodBudget: (30n * KAS).toString(),
      periodLengthDaa: "864000", periodStartDaa: "541000000", periodSpent: "0",
      approvalThreshold: (5n * KAS).toString(), agentMaxFeePerTx: (1n * KAS).toString(),
      recipients: [XO(other)]
    }
  ];
}

/* Build the state whose agentRoot matches a registry. */
function stateForRegistry(reg, over = {}) {
  const policies = reg.map((e) => ({ ...e, agentRecipientRoot: buildRecipientTree(e.recipients).root }));
  const agentRoot = buildAgentTreeV4(policies).root;
  return normalizeStateV4({
    protectedValue: (1000n * KAS).toString(),
    feeReserve: (5n * KAS).toString(),
    paused: "0",
    agentRoot,
    approvers: [],
    approvalM: "0",
    policyNonce: "0",
    ...over
  });
}

const template = { owner: XO(owner), vaultId: "22".repeat(32) };

function manifestDoc(reg, state) {
  const stateId = computeStateIdV4({ networkId: config.networkId, template, state });
  return {
    schema: MANIFEST_SCHEMA_V4,
    contractVersion: CONTRACT_VERSION_V4,
    networkId: config.networkId,
    vaultId: template.vaultId,
    label: "test vault",
    status: "ACTIVE",
    template,
    agentRegistry: reg,
    live: {
      state: {
        protectedValue: state.protectedValue.toString(),
        feeReserve: state.feeReserve.toString(),
        paused: state.paused.toString(),
        agentRoot: state.agentRoot,
        approverSlots: [...state.approvers],
        approvalM: state.approvalM.toString(),
        policyNonce: state.policyNonce.toString()
      },
      stateId,
      outpoint: { transactionId: "42".repeat(32), index: 0 },
      outpointValue: (state.protectedValue + state.feeReserve).toString(),
      scriptSha256: "ab".repeat(32),
      covenantId: "41".repeat(32)
    },
    creationTxId: "42".repeat(32),
    latestTransitionTxId: null,
    lastTransition: null
  };
}

test("G2: a registry that reproduces the covenant agentRoot normalizes and round-trips", async () => {
  const reg = registry();
  const state = stateForRegistry(reg);
  const m = normalizeManifestV4(manifestDoc(reg, state));
  assert.equal(m.agentRegistryRoot, state.agentRoot);
  assert.equal(m.live.state.agentRoot, state.agentRoot);
  assert.equal(m.live.outpointValue, state.protectedValue + state.feeReserve);
  // persist + load round-trip
  await persistManifestV4(config, manifestDoc(reg, state));
  const loaded = await loadManifestV4(config, template.vaultId);
  assert.equal(loaded.agentRegistryRoot, state.agentRoot);
  assert.equal(loaded.agentRegistry.length, 2);
  // version-aware loader dispatches to v4
  const any = await loadAnyManifest(config, template.vaultId);
  assert.equal(any.version, "v4");
});

test("G2: a registry that CANNOT reproduce the agentRoot fails closed", async () => {
  const reg = registry();
  const state = stateForRegistry(reg);
  // tamper an agent's cap in the registry so its leaf (and the root) changes,
  // while the covenant state keeps the original agentRoot.
  const tampered = registry();
  tampered[0].maxPerSpend = (999n * KAS).toString();
  assert.throws(
    () => normalizeManifestV4(manifestDoc(tampered, state)),
    (e) => e.code === "REGISTRY_ROOT_MISMATCH"
  );
});

test("G2: an agent whose declared recipient root disagrees with its recipient set fails closed", async () => {
  const reg = registry();
  const state = stateForRegistry(reg);
  const doc = manifestDoc(reg, state);
  doc.agentRegistry[0].agentRecipientRoot = "cd".repeat(32); // lie about the recipient root
  assert.throws(
    () => normalizeManifestV4(doc),
    (e) => e.code === "REGISTRY_RECIPIENT_MISMATCH"
  );
});

test("G2: outpoint value must equal protected + reserve; stateId must match", async () => {
  const reg = registry();
  const state = stateForRegistry(reg);
  const badValue = manifestDoc(reg, state);
  badValue.live.outpointValue = state.protectedValue.toString(); // missing reserve
  assert.throws(() => normalizeManifestV4(badValue), /protectedValue \+ feeReserve/);

  const badStateId = manifestDoc(reg, state);
  badStateId.live.stateId = "00".repeat(32);
  assert.throws(() => normalizeManifestV4(badStateId), /stateId does not match/);
});

test("G2: empty registry is canonical (unspendable-padding root) and must match an all-agents-removed state", async () => {
  const emptyState = stateForRegistry([]);
  const m = normalizeManifestV4(manifestDoc([], emptyState));
  assert.equal(m.agentRegistry.length, 0);
  assert.equal(m.agentRegistryRoot, emptyState.agentRoot);
});

test("G2: unknown schema / contract version fails closed", async () => {
  const reg = registry();
  const state = stateForRegistry(reg);
  const doc = manifestDoc(reg, state);
  assert.throws(() => normalizeManifestV4({ ...doc, schema: "policyvault-vault-manifest/v3" }), /unknown manifest schema/);
  assert.throws(() => normalizeManifestV4({ ...doc, contractVersion: "policyvault-0.3" }), /unknown contract version/);
});
