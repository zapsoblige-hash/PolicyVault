"use strict";

/*
 * CAPTURE the v0.7 ORGANIZATIONAL ROOT manifest fixtures used by the
 * PORTABLE explanation tests (core/explain/test/org-root-explain.test.js).
 *
 * The manifests are built by the REAL production SDK — silverc, the real
 * pv_call_encoder / pv_tx_probe binaries, core/model/* and
 * core/intent/org-root-manifest-v7 — over deterministic TEST-ONLY keys, so
 * the fixture is a real production-byte artifact rather than a hand-written
 * approximation. The explanation suite then runs in pure portable core with
 * no compiler or binary dependency, and re-verifies every fixture through
 * verifyOrgRootIntentManifest before rendering it (the explanation layer
 * never trusts a supplied verdict).
 *
 * Regenerate with:
 *   node sdk/tools/capture-v7-manifests.js \
 *     core/explain/test/fixtures/v7-org-root-manifests.json \
 *     core/signer/test/fixtures/v7-org-root-slot.json
 *
 * Determinism: every key, id, outpoint and amount below is a fixed
 * constant, so a re-run must reproduce the file byte-identically. The
 * suite asserts the fixture verifies; a drifted capture therefore fails
 * loudly instead of silently changing what owners are shown.
 *
 * TEST KEYS ONLY: secrets are the byte value repeated 32x. Never
 * production material.
 */

const fs = require("fs");
const path = require("path");

const { loadConfig } = require("../src/config");
const assets = require("../../core/assets");
const { compileKcc20Program } = require("../src/token-program-kcc20");
const { buildTokenAgentTreeV5 } = require("../src/agent-merkle-v5");
const { buildRecipientTree } = require("../src/recipient-merkle-v3");
const { deriveRootPinsV7 } = require("../src/contract-compiler-v7");
const { buildV7RootTransaction, buildV7Transaction } = require("../src/vault-builders-v7");
const { buildOrgRootIntentManifest, verifyOrgRootIntentManifest, buildRootedVaultManifestV7 } = require("../../core/intent/org-root-manifest-v7");
const { INACTIVE_SLOT_KEY, OWNER_SLOTS_V7 } = require("../../core/model/owner-set-v7");

const outPath = process.argv[2];
const signerOutPath = process.argv[3] || null;
if (!outPath) {
  console.error("usage: node capture-v7-manifests.js <explain-fixture-path> [signer-fixture-path]");
  process.exit(1);
}

const config = loadConfig({ dataRoot: fs.mkdtempSync(path.join(require("os").tmpdir(), "pv7-capture-")) });

const KAS = 100000000n;
const H = (b) => b.toString(16).padStart(2, "0").repeat(32);
const ORG_ID = H(0xa7);
const ROOT_ID = H(0x52);
const VAULT_COV_ID = H(0x43);
const TOKEN_FAMILY = H(0x54);
const FUEL = H(0x64);
const RECOVERY_PK = H(0x51);
const ROOT_KAS = 3n * KAS;

function slots(keys) {
  const out = [];
  for (let i = 0; i < OWNER_SLOTS_V7; i += 1) out.push(i < keys.length ? keys[i] : INACTIVE_SLOT_KEY);
  return out;
}

const OWNERS = [H(0x71), H(0x72), H(0x73)];
const NEW_OWNERS = [H(0x81), H(0x82), H(0x83), H(0x84)];
const rootTemplate = { orgId: ORG_ID, recoveryDelayDaa: "1000", successorPk: H(0x7f), successionDelayDaa: "2000", rootMaxFeePerTx: "200000" };
const rootTemplateNoRecovery = { ...rootTemplate, successorPk: "00".repeat(32) };
const ownerSet = { owners: slots(OWNERS), ownerM: 2, emergencyK: 1, recoveryM: 2 };
const rootState = (over = {}) => ({ boundOrgId: ORG_ID, ...ownerSet, frozen: 0, rootNonce: 0, ...over });
const rootChain = () => ({
  predecessorOutpoint: { transactionId: H(0x01), index: 0 },
  covenantId: ROOT_ID,
  predecessorValue: ROOT_KAS.toString(),
  fuel: { outpoint: { transactionId: H(0x03), index: 0 }, amount: (1n * KAS).toString(), scriptPublicKeyHex: `20${FUEL}ac` }
});

/* ---- the rooted vault (one asset family, one delegate) ---- */
const ref = compileKcc20Program({ config, state: assets.kcc20.ZERO_STATE, familyBound: 2 });
const descriptor = {
  schema: "policyvault-asset-descriptor/1",
  assetId: H(0x11),
  displayName: "Org Treasury Token",
  tokenStandard: "kcc20/1",
  tokenCovenantId: TOKEN_FAMILY,
  acceptedTransferTemplates: [
    { templateVmHashBlake2b256: ref.templateVmHashBlake2b256, prefixLen: ref.geometry.prefixLen, suffixLen: ref.geometry.suffixLen, stateLayout: "kcc20-state/1" }
  ],
  decimalsDisplay: 2,
  issuerPowers: { mint: false, burn: false, freeze: false, blacklist: false, redemptionControl: false, upgradeMigration: false, controllerRotation: false, emergencyControl: false }
};
const rootPins = deriveRootPinsV7({ config, template: rootTemplate, ownerSet, covenantId: ROOT_ID });
const vaultTemplate = {
  vaultId: H(0x44),
  descriptorHash: assets.computeDescriptorHash(descriptor),
  tokenCovenantId: TOKEN_FAMILY,
  templateVmHash: ref.templateVmHashBlake2b256,
  templatePrefixLen: ref.geometry.prefixLen,
  templateStateLen: ref.geometry.stateLen,
  templateSuffixLen: ref.geometry.suffixLen,
  ...rootPins,
  recoveryPk: RECOVERY_PK
};
const rTree = buildRecipientTree([H(0x63)]);
const policy = {
  agentPk: H(0x62),
  tokenMaxPerSpend: "250",
  tokenPeriodBudget: "400",
  periodLengthDaa: "1000",
  periodStartDaa: "5000",
  tokenPeriodSpent: "0",
  agentMaxFeePerTx: (1n * KAS).toString(),
  agentMaxCarryKas: (KAS / 4n).toString(),
  agentRecipientRoot: rTree.root
};
const agentTree = buildTokenAgentTreeV5([policy]);
const vaultStateJson = { feeReserve: (5n * KAS).toString(), paused: "0", agentRoot: agentTree.root, policyNonce: "0" };

function tokenPosition(amount = 1000) {
  const state = { ownerIdentifier: VAULT_COV_ID, identifierType: assets.kcc20.OWNER_SCHEMES.COVENANT_ID, amount: String(amount), isMinter: false };
  const program = compileKcc20Program({ config, state, familyBound: 2 });
  return { outpoint: { transactionId: H(0x0b), index: 0 }, value: (2n * KAS).toString(), scriptPublicKeyHex: program.p2shSpkHex, covenantId: TOKEN_FAMILY, state };
}

function vaultChain(over = {}) {
  return {
    predecessorOutpoint: { transactionId: H(0x0a), index: 0 },
    covenantId: VAULT_COV_ID,
    predecessorValue: vaultStateJson.feeReserve,
    fuel: { outpoint: { transactionId: H(0x03), index: 0 }, amount: (1n * KAS).toString(), scriptPublicKeyHex: `20${FUEL}ac` },
    root: { template: rootTemplate, state: rootState(), outpoint: { transactionId: H(0x04), index: 0 }, covenantId: ROOT_ID, value: ROOT_KAS.toString() },
    ...over
  };
}

const captured = [];

function capture(name, manifest, descriptors = {}, redeemScripts = {}) {
  const v = verifyOrgRootIntentManifest({ manifest, descriptors, redeemScripts });
  if (v.verdict !== "VERIFIED") {
    console.error(`capture ${name}: manifest does NOT verify — refusing to write a fixture that would render as refused`);
    console.error(JSON.stringify(v.failures, null, 2));
    process.exit(2);
  }
  captured.push({ name, checks: v.checks.length, manifest, descriptors, redeemScripts });
}

/* ---- root-only actions ---- */
{
  const build = buildV7RootTransaction({ config, templateInput: rootTemplate, stateInput: rootState(), action: "authorize", chain: rootChain(), changeXOnly: FUEL });
  capture("root_authorize_2of3", buildOrgRootIntentManifest({ build, vaultOperations: [], satisfiedApprovals: 2 }));
  /* approvals NOT yet counted: the manifest a signer sees BEFORE any slot is
   * collected. (An UNDER-quorum count is not capturable here: the verifier
   * itself refuses `satisfiedApprovals < requiredApprovals` — check
   * `quorumSatisfied` — so such a manifest can never render as verified.) */
  capture("root_authorize_approvals_not_yet_counted", buildOrgRootIntentManifest({ build, vaultOperations: [], satisfiedApprovals: null }));
}
{
  const build = buildV7RootTransaction({
    config,
    templateInput: rootTemplate,
    stateInput: rootState(),
    action: "rotate",
    params: { newOwnerSet: { owners: slots(NEW_OWNERS), ownerM: 3, emergencyK: 1, recoveryM: 2 } },
    chain: rootChain(),
    changeXOnly: FUEL
  });
  capture("root_rotate_installs_new_set", buildOrgRootIntentManifest({ build, vaultOperations: [], satisfiedApprovals: 2 }));
}
{
  const build = buildV7RootTransaction({ config, templateInput: rootTemplate, stateInput: rootState(), action: "freeze", chain: rootChain(), changeXOnly: FUEL });
  capture("root_freeze_emergency_quorum", buildOrgRootIntentManifest({ build, vaultOperations: [], satisfiedApprovals: 1 }));
}
{
  const build = buildV7RootTransaction({ config, templateInput: rootTemplate, stateInput: rootState({ frozen: 1 }), action: "unfreeze", chain: rootChain(), changeXOnly: FUEL });
  capture("root_unfreeze_full_quorum", buildOrgRootIntentManifest({ build, vaultOperations: [], satisfiedApprovals: 2 }));
}
{
  const build = buildV7RootTransaction({
    config,
    templateInput: rootTemplate,
    stateInput: rootState(),
    action: "ownerRecover",
    params: { newOwnerSet: { owners: slots(NEW_OWNERS.slice(0, 2)), ownerM: 2, emergencyK: 1, recoveryM: 1 } },
    chain: rootChain(),
    changeXOnly: FUEL
  });
  capture("root_owner_recover_lands_frozen", buildOrgRootIntentManifest({ build, vaultOperations: [], satisfiedApprovals: 2 }));
}
{
  const build = buildV7RootTransaction({
    config,
    templateInput: rootTemplate,
    stateInput: rootState(),
    action: "succession",
    params: { newOwnerSet: { owners: slots([H(0x7f)]), ownerM: 1, emergencyK: 1, recoveryM: 0 } },
    chain: rootChain(),
    changeXOnly: FUEL
  });
  capture("root_succession", buildOrgRootIntentManifest({ build, vaultOperations: [], satisfiedApprovals: 1 }));
}
{
  /* recovery DISABLED + succession DISABLED: the "no recovery" warnings */
  const noRecoverySet = { owners: slots(OWNERS), ownerM: 2, emergencyK: 1, recoveryM: 0 };
  const build = buildV7RootTransaction({
    config,
    templateInput: rootTemplateNoRecovery,
    stateInput: { boundOrgId: ORG_ID, ...noRecoverySet, frozen: 0, rootNonce: 0 },
    action: "authorize",
    chain: rootChain(),
    changeXOnly: FUEL
  });
  capture("root_authorize_no_recovery_no_succession", buildOrgRootIntentManifest({ build, vaultOperations: [], satisfiedApprovals: 2 }));
}

/* ---- root + ONE vault operation ---- */
{
  const build = buildV7Transaction({ config, templateInput: vaultTemplate, stateInput: vaultStateJson, action: "ownerPause", chain: vaultChain(), changeXOnly: FUEL, descriptor });
  capture("vault_owner_pause_under_authorize", buildOrgRootIntentManifest({ build, vaultOperations: [{ build, descriptor }], satisfiedApprovals: 2 }), { [VAULT_COV_ID]: descriptor }, { [VAULT_COV_ID]: build.vaultRedeemScriptHex });
}
{
  /* rc26 round-7 review R7-02: an ownerSetAgentRoot carries the FULL new delegate policy set (two policies here: one
   * tightened per-spend cap, one new agent) — the owners approve the RULES; the successor agentRoot is their fold. */
  const newSet = [{ ...policy, tokenMaxPerSpend: "100", recipients: [H(0x63)] }, { ...policy, agentPk: H(0x66), recipients: [H(0x63)] }]; // Codex checkpoint 11 (R7-02): every policy carries its recipients
  const build = buildV7Transaction({ config, templateInput: vaultTemplate, stateInput: vaultStateJson, action: "ownerSetAgentRoot", params: { agents: newSet }, chain: vaultChain(), changeXOnly: FUEL, descriptor });
  capture("vault_set_agent_root_under_authorize", buildOrgRootIntentManifest({ build, vaultOperations: [{ build, descriptor }], satisfiedApprovals: 2 }), { [VAULT_COV_ID]: descriptor }, { [VAULT_COV_ID]: build.vaultRedeemScriptHex });
}
{
  const build = buildV7Transaction({
    config,
    templateInput: vaultTemplate,
    stateInput: vaultStateJson,
    action: "ownerEmergencyPause",
    chain: vaultChain({ root: { template: rootTemplate, state: rootState(), outpoint: { transactionId: H(0x04), index: 0 }, covenantId: ROOT_ID, value: ROOT_KAS.toString() } }),
    changeXOnly: FUEL,
    descriptor
  });
  capture("vault_emergency_pause_under_freeze", buildOrgRootIntentManifest({ build, vaultOperations: [{ build, descriptor }], satisfiedApprovals: 1 }), { [VAULT_COV_ID]: descriptor }, { [VAULT_COV_ID]: build.vaultRedeemScriptHex });
}
{
  const build = buildV7Transaction({
    config,
    templateInput: vaultTemplate,
    stateInput: vaultStateJson,
    action: "ownerRecover",
    chain: vaultChain({ tokenPosition: tokenPosition(300) }),
    changeXOnly: FUEL,
    descriptor
  });
  capture("vault_recover_terminal_with_position", buildOrgRootIntentManifest({ build, vaultOperations: [{ build, descriptor }], satisfiedApprovals: 2 }), { [VAULT_COV_ID]: descriptor }, { [VAULT_COV_ID]: build.vaultRedeemScriptHex });
}

/* ---- a STANDALONE rooted-vault manifest (the VERIFY_WITHIN_PARENT case) ---- */
const standalone = (() => {
  const build = buildV7Transaction({ config, templateInput: vaultTemplate, stateInput: vaultStateJson, action: "ownerPause", chain: vaultChain(), changeXOnly: FUEL, descriptor });
  return buildRootedVaultManifestV7({ build, descriptor });
})();

/* ---- the SIGNER-path fixture: two DIFFERENT frozen transactions of the same
 * organization, plus the predecessor owner set the covenant checks slots
 * against. Two transactions are what makes the txid-drift and cross-request
 * replay rows real rather than synthetic. ---- */
function signerFixture() {
  const primary = captured.find((c) => c.name === "root_authorize_2of3");
  const other = captured.find((c) => c.name === "root_unfreeze_full_quorum");
  return {
    note: "REAL v0.7 org-root builds. `unsignedSafeJson` is the FROZEN canonical transaction JSON the manifest itself carries; the slot path is serialization-agnostic (it requires only that the signer returns the SAME document with exactly one input's signatureScript filled).",
    ownerSet: { owners: slots(OWNERS), ownerM: 2, emergencyK: 1, recoveryM: 2 },
    ownerAddresses: OWNERS.map((_, i) => `kaspatest:orgowner${i + 1}`),
    rootInputIndex: 0,
    primary: { name: primary.name, manifest: primary.manifest, unsignedSafeJson: primary.manifest.transaction.frozenCanonicalJson },
    other: { name: other.name, manifest: other.manifest, unsignedSafeJson: other.manifest.transaction.frozenCanonicalJson },
    succession: { name: "root_succession", manifest: captured.find((c) => c.name === "root_succession").manifest }
  };
}

if (signerOutPath) {
  fs.mkdirSync(path.dirname(path.resolve(signerOutPath)), { recursive: true });
  fs.writeFileSync(path.resolve(signerOutPath), `${JSON.stringify({ capturedBy: "sdk/tools/capture-v7-manifests.js", ...signerFixture() }, null, 1)}\n`);
  console.log(`captured the org-root SLOT fixture -> ${signerOutPath}`);
}

fs.mkdirSync(path.dirname(path.resolve(outPath)), { recursive: true });
fs.writeFileSync(
  path.resolve(outPath),
  `${JSON.stringify(
    {
      capturedBy: "sdk/tools/capture-v7-manifests.js",
      note: "REAL production-byte manifests built by the v0.7 SDK over deterministic TEST-ONLY keys. Regenerate with the command in the tool header.",
      manifests: captured,
      standaloneRootedVaultManifest: standalone
    },
    null,
    1
  )}\n`
);
console.log(`captured ${captured.length} org-root manifests + 1 standalone rooted-vault manifest -> ${outPath}`);
