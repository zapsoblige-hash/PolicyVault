"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");

const { normalizeManifestV5, manifestToJsonV5, MANIFEST_SCHEMA_V5 } = require("../src/manifest-v5");
const { buildTokenAgentTreeV5 } = require("../src/agent-merkle-v5");
const { buildRecipientTree } = require("../src/recipient-merkle-v3");
const { computeStateIdV5 } = require("../src/vault-state-v5");
const assets = require("../../core/assets");

const fixture = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "..", "core", "assets", "test", "fixtures", "kcc20-template-v1.json"), "utf8"));
const b2 = fixture.bounds.find((b) => b.familyBound === 2);
const CONTROLLER_ID = "43".repeat(32);
const TOKEN_FAMILY = "54".repeat(32);
const POWERS = { mint: false, burn: false, freeze: false, blacklist: false, redemptionControl: false, upgradeMigration: false, controllerRotation: false, emergencyControl: false };
const descriptor = {
  schema: "policyvault-asset-descriptor/1",
  assetId: "11".repeat(32),
  displayName: "Fixture Token",
  tokenStandard: "kcc20/1",
  tokenCovenantId: TOKEN_FAMILY,
  acceptedTransferTemplates: [{ templateVmHashBlake2b256: b2.templateVmHashBlake2b256, prefixLen: b2.prefixLen, suffixLen: b2.suffixLen, stateLayout: "kcc20-state/1" }],
  decimalsDisplay: 8,
  issuerPowers: { ...POWERS }
};
const descriptorHash = assets.computeDescriptorHash(descriptor);
const template = { owner: "11".repeat(32), vaultId: "44".repeat(32), descriptorHash, tokenCovenantId: TOKEN_FAMILY, templateVmHash: b2.templateVmHashBlake2b256, templatePrefixLen: 1, templateStateLen: 46, templateSuffixLen: 1521 };
const recipients = ["33".repeat(32)];
const rroot = buildRecipientTree(recipients).root;
const entry = { agentPk: "22".repeat(32), tokenMaxPerSpend: "250", tokenPeriodBudget: "400", periodLengthDaa: "1000", periodStartDaa: "5000", tokenPeriodSpent: "0", agentMaxFeePerTx: "100000000", agentMaxCarryKas: "25000000", recipients };
const { recipients: _r, ...policyOnly } = entry;
const tree = buildTokenAgentTreeV5([{ ...policyOnly, agentRecipientRoot: rroot }]);
const state = { feeReserve: "500000000", paused: "0", agentRoot: tree.root, policyNonce: "0" };
const { normalizeTemplateV5, normalizeStateV5 } = require("../src/vault-state-v5");
const stateId = computeStateIdV5({ networkId: "testnet-10", template: normalizeTemplateV5(template), state: normalizeStateV5(state), contractVersion: "policyvault-0.5" });

function manifest(over = {}) {
  return {
    schema: MANIFEST_SCHEMA_V5,
    contractVersion: "policyvault-0.5",
    networkId: "testnet-10",
    status: "ACTIVE",
    template,
    asset: { descriptor, descriptorHash, templateIndex: 0 },
    agentRegistry: [entry],
    live: {
      state,
      stateId,
      outpoint: { transactionId: "01".repeat(32), index: 0 },
      outpointValue: "500000000",
      scriptSha256: "ab".repeat(32),
      covenantId: CONTROLLER_ID,
      tokenPosition: { outpoint: { transactionId: "02".repeat(32), index: 0 }, value: "200000000", scriptPublicKeyHex: b2.states[0].p2shSpkHex, covenantId: TOKEN_FAMILY, state: { ownerIdentifier: CONTROLLER_ID, identifierType: 2, amount: "300", isMinter: false } }
    },
    ...over
  };
}

test("a coherent v5 manifest normalizes: descriptor pin, registry root, token position (two domains separate)", () => {
  const m = normalizeManifestV5(manifest());
  assert.equal(m.asset.descriptorHash, descriptorHash);
  assert.equal(m.agentRegistryRoot, tree.root);
  assert.equal(m.live.outpointValue, 500000000n); // KAS domain
  assert.equal(m.live.tokenPosition.state.amount, 300n); // TOKEN domain
  const json = manifestToJsonV5(m);
  assert.equal(json.live.tokenPosition.state.amount, "300");
  assert.equal(json.live.outpointValue, "500000000");
  assert.deepEqual(normalizeManifestV5(json).live.tokenPosition.state, m.live.tokenPosition.state);
});

test("fail closed: descriptor substitution/downgrade, wrong family, registry root mismatch, unknown version/schema, token not owned", () => {
  const refuse = (over, re) => assert.throws(() => normalizeManifestV5(manifest(over)), re);
  refuse({ asset: { descriptor: { ...descriptor, issuerPowers: { ...POWERS, mint: true } }, descriptorHash, templateIndex: 0 } }, /DESCRIPTOR_PIN_MISMATCH|pinned descriptorHash/);
  refuse({ asset: { descriptor: { ...descriptor, schema: "policyvault-asset-descriptor/0" }, descriptorHash, templateIndex: 0 } }, /unknown descriptor schema/);
  refuse({ asset: { descriptor, descriptorHash: "00".repeat(32), templateIndex: 0 } }, /does not match the descriptor/);
  refuse({ asset: { descriptor, descriptorHash, templateIndex: 1 } }, /templateIndex/);
  refuse({ contractVersion: "policyvault-0.4.1" }, /unknown contract version/);
  refuse({ schema: "policyvault-vault-manifest/v4" }, /unknown manifest schema/);
  refuse({ agentRegistry: [{ ...entry, tokenMaxPerSpend: "251" }] }, /REGISTRY_ROOT_MISMATCH|does not match the covenant agentRoot/);
  refuse({ agentRegistry: [{ ...entry, agentRecipientRoot: "00".repeat(32) }] }, /REGISTRY_RECIPIENT_MISMATCH|recipient set/);
  const m = manifest();
  refuse({ live: { ...m.live, tokenPosition: { ...m.live.tokenPosition, covenantId: "57".repeat(32) } } }, /WRONG_TOKEN_FAMILY|wrong asset family/);
  refuse({ live: { ...m.live, tokenPosition: { ...m.live.tokenPosition, state: { ...m.live.tokenPosition.state, ownerIdentifier: "99".repeat(32) } } } }, /TOKEN_NOT_OWNED|not owned/);
  refuse({ live: { ...m.live, outpointValue: "500000001" } }, /feeReserve/);
  refuse({ status: "RECOVERED" }, /must carry live: null/);
  const recovered = normalizeManifestV5(manifest({ status: "RECOVERED", live: null }));
  assert.equal(recovered.live, null);
});
