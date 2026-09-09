"use strict";

/*
 * SDK/INTEGRATION: the v0.7 ORGANIZATIONAL ROOT intent manifest + its
 * deterministic local verification, driven by the REAL builders (silverc,
 * the production pv_call_encoder, pv_tx_probe). Classified
 * REQUIREMENT_NOT_AVAILABLE (skipped, never silently passed) when those
 * binaries are absent.
 *
 * TAMPER MATRIX — each row edits ONE field of an otherwise-VERIFIED manifest
 * and must produce REFUSED with the failing check NAMED. The rows are the
 * things a signing owner is actually trusting the manifest about:
 *   root outpoint, action, threshold, expected slot set, owner-set diff,
 *   root state digests, the successor tail bytes, fee, root value rule,
 *   vault-operation substitution, and a HIDDEN EXTRA vault operation.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const { loadConfig } = require("../src/config");
const assets = require("../../core/assets");
const { compileKcc20Program } = require("../src/token-program-kcc20");
const { buildTokenAgentTreeV5 } = require("../src/agent-merkle-v5");
const { buildRecipientTree } = require("../src/recipient-merkle-v3");
const { deriveRootPinsV7 } = require("../src/contract-compiler-v7");
const { buildV7RootTransaction, buildV7Transaction } = require("../src/vault-builders-v7");
const { buildOrgRootIntentManifest, verifyOrgRootIntentManifest, ORG_ROOT_EXPLANATION, ORG_ROOT_MANIFEST_VERSION_1 } = require("../../core/intent/org-root-manifest-v7");
const { INACTIVE_SLOT_KEY, OWNER_SLOTS_V7 } = require("../../core/model/owner-set-v7");
const { computeManifestHashV1 } = require("../../core/intent/canonical");
const { ENCODER_PATH } = require("../src/vault-builders-v4");

const config = loadConfig({ dataRoot: fs.mkdtempSync(path.join(os.tmpdir(), "pv7-orm-")) });
const available = fs.existsSync(config.silvercPath) && fs.existsSync(ENCODER_PATH) && fs.existsSync(path.join(config.repoRoot, "tests/vm/target/debug/pv_tx_probe"));
const SKIP = !available && "REQUIREMENT_NOT_AVAILABLE: silverc / pv_call_encoder / pv_tx_probe";

const KAS = 100000000n;
const H = (b) => b.toString(16).padStart(2, "0").repeat(32);
const ORG_ID = H(0xa7);
const ROOT_ID = H(0x52);
const VAULT_COV_ID = H(0x43);
const TOKEN_FAMILY = H(0x54);
const FUEL = H(0x64);
const ROOT_KAS = 3n * KAS;

function slots(keys) {
  const out = [];
  for (let i = 0; i < OWNER_SLOTS_V7; i += 1) out.push(i < keys.length ? keys[i] : INACTIVE_SLOT_KEY);
  return out;
}
const OWNERS = [H(0x71), H(0x72), H(0x73)];
const NEW_OWNERS = [H(0x81), H(0x82)];
const rootTemplate = { orgId: ORG_ID, recoveryDelayDaa: "1000", successorPk: H(0x7f), successionDelayDaa: "2000", rootMaxFeePerTx: "200000" };
const ownerSet = { owners: slots(OWNERS), ownerM: 2, emergencyK: 1, recoveryM: 2 };
const rootState = (over = {}) => ({ boundOrgId: ORG_ID, ...ownerSet, frozen: 0, rootNonce: 0, ...over });
const rootChain = { predecessorOutpoint: { transactionId: H(0x01), index: 0 }, covenantId: ROOT_ID, predecessorValue: ROOT_KAS.toString(), fuel: { outpoint: { transactionId: H(0x03), index: 0 }, amount: (1n * KAS).toString(), scriptPublicKeyHex: `20${FUEL}ac` } };

/* deep clone + re-hash so a tamper is HASH-CONSISTENT: the point of each row
 * is the SEMANTIC check, not the hash check (which is asserted separately). */
function tamper(manifest, mutate) {
  const { manifestHash, ...body } = JSON.parse(JSON.stringify(manifest));
  void manifestHash;
  mutate(body);
  return { ...body, manifestHash: computeManifestHashV1(body) };
}

test("org-root manifest: build -> VERIFIED; the fixed explanation and outpoint-kill-switch freshness are carried verbatim", { skip: SKIP }, () => {
  const build = buildV7RootTransaction({ config, templateInput: rootTemplate, stateInput: rootState(), action: "authorize", chain: rootChain, changeXOnly: FUEL });
  const manifest = buildOrgRootIntentManifest({ build, vaultOperations: [], satisfiedApprovals: 2 });
  assert.equal(manifest.manifestVersion, ORG_ROOT_MANIFEST_VERSION_1);
  const v = verifyOrgRootIntentManifest({ manifest });
  assert.equal(v.verdict, "VERIFIED", JSON.stringify(v.failures));
  assert.ok(v.checks.length >= 18, `expected a substantial check list, got ${v.checks.length}`);
  assert.equal(manifest.explanation, ORG_ROOT_EXPLANATION);
  assert.equal(manifest.freshness.kind, "ROOT_OUTPOINT_KILL_SWITCH");
  assert.equal(manifest.freshness.expiry, null, "there is deliberately NO expiry — lockTime is a lower bound only");
  assert.deepEqual(manifest.freshness.rootOutpoint, manifest.root.outpoint);
  assert.equal(manifest.action.requiredApprovals, "2");
  assert.equal(manifest.action.satisfiedApprovals, "2");
  assert.equal(manifest.action.authorityClass, "AUTHORITY-NEUTRAL");
  assert.deepEqual(manifest.action.expectedSignerSlots.map((s) => s.slot), [1, 2, 3]);
  assert.equal(manifest.vaultOperations.length, 0);
});

test("org-root manifest TAMPER MATRIX: every edited field is REFUSED with the failing check named", { skip: SKIP }, () => {
  const build = buildV7RootTransaction({ config, templateInput: rootTemplate, stateInput: rootState(), action: "authorize", chain: rootChain, changeXOnly: FUEL });
  const manifest = buildOrgRootIntentManifest({ build, vaultOperations: [], satisfiedApprovals: 2 });
  assert.equal(verifyOrgRootIntentManifest({ manifest }).verdict, "VERIFIED");

  const rows = [
    ["a bare hash edit (no re-hash)", { ...manifest, manifestHash: H(0xee) }, "manifestHash"],
    ["ROOT OUTPOINT substituted", tamper(manifest, (m) => { m.root.outpoint = { transactionId: H(0x0e), index: 0 }; m.freshness.rootOutpoint = { transactionId: H(0x0e), index: 0 }; }), "rootOutpointBinding"],
    ["ACTION relabelled (authorize -> freeze)", tamper(manifest, (m) => { m.action.name = "freeze"; m.action.code = 2; m.action.authorityClass = "AUTHORITY-REDUCING"; m.action.quorumSource = "emergencyK"; }), "frozenOutcome"],
    ["ACTION class softened", tamper(manifest, (m) => { m.action.authorityClass = "AUTHORITY-REDUCING"; }), "actionTable"],
    ["THRESHOLD understated", tamper(manifest, (m) => { m.action.requiredApprovals = "1"; }), "requiredApprovals"],
    ["QUORUM claimed satisfied below the requirement", tamper(manifest, (m) => { m.action.satisfiedApprovals = "1"; }), "quorumSatisfied"],
    ["SLOT SET truncated (a signer hidden)", tamper(manifest, (m) => { m.action.expectedSignerSlots = m.action.expectedSignerSlots.slice(0, 2); }), "expectedSignerSlots"],
    ["SLOT SET key swapped", tamper(manifest, (m) => { m.action.expectedSignerSlots[0].publicKey = H(0xee); }), "expectedSignerSlots"],
    ["OWNER SET diff hidden (a rotation presented as neutral)", tamper(manifest, (m) => { m.rootState.after.state.owners[0] = H(0x91); }), "stateDigests"],
    ["ROOT STATE DIGEST forged", tamper(manifest, (m) => { m.rootState.after.digest = H(0xdd); }), "stateDigests"],
    ["SUCCESSOR TAIL bytes forged", tamper(manifest, (m) => { m.rootState.after.tailHex = "010008ff00000000000000"; }), "successorTailBytes"],
    ["NONCE not advanced", tamper(manifest, (m) => { m.rootState.after.state.rootNonce = m.rootState.before.state.rootNonce; }), "nonceAdvancesByOne"],
    ["ORG ID rebound", tamper(manifest, (m) => { m.rootState.after.state.boundOrgId = H(0xb7); }), "stateDigests"],
    ["FEE understated", tamper(manifest, (m) => { m.fee.requiredFeeSompi = "1"; }), "feeExact"],
    ["ROOT VALUE loss understated", tamper(manifest, (m) => { m.fee.rootValueLoss = "999"; }), "rootValueRule"],
    ["ROOT VALUE after inflated", tamper(manifest, (m) => { m.root.valueAfter = (ROOT_KAS + 1n).toString(); }), "rootValueAfter"]
  ];
  for (const [label, bad, expectedCheck] of rows) {
    const v = verifyOrgRootIntentManifest({ manifest: bad });
    assert.equal(v.verdict, "REFUSED", `${label}: must be REFUSED`);
    assert.ok(
      v.failures.some((f) => f.name === expectedCheck),
      `${label}: expected the failing check ${expectedCheck}, got [${v.failures.map((f) => f.name).join(", ")}]`
    );
    assert.equal(v.statement, null, `${label}: a refused manifest never carries the verified statement`);
  }
  console.log(`ORGROOT tamper rows refused: ${rows.length}`);
});

test("org-root manifest carries EVERY vault operation, and a hidden extra one is REFUSED", { skip: SKIP }, () => {
  /* a rooted vault pinned to this exact root */
  const ref = compileKcc20Program({ config, state: assets.kcc20.ZERO_STATE, familyBound: 2 });
  const descriptor = {
    schema: "policyvault-asset-descriptor/1",
    assetId: H(0x11),
    displayName: "Org Manifest Token",
    tokenStandard: "kcc20/1",
    tokenCovenantId: TOKEN_FAMILY,
    acceptedTransferTemplates: [{ templateVmHashBlake2b256: ref.templateVmHashBlake2b256, prefixLen: ref.geometry.prefixLen, suffixLen: ref.geometry.suffixLen, stateLayout: "kcc20-state/1" }],
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
    recoveryPk: H(0x51)
  };
  const rTree = buildRecipientTree([H(0x63)]);
  const policy = { agentPk: H(0x62), tokenMaxPerSpend: "250", tokenPeriodBudget: "400", periodLengthDaa: "1000", periodStartDaa: "5000", tokenPeriodSpent: "0", agentMaxFeePerTx: (1n * KAS).toString(), agentMaxCarryKas: (KAS / 4n).toString(), agentRecipientRoot: rTree.root };
  const tree = buildTokenAgentTreeV5([policy]);
  const vaultStateJson = { feeReserve: (5n * KAS).toString(), paused: "0", agentRoot: tree.root, policyNonce: "0" };

  const build = buildV7Transaction({
    config,
    templateInput: vaultTemplate,
    stateInput: vaultStateJson,
    action: "ownerPause",
    chain: {
      predecessorOutpoint: { transactionId: H(0x0a), index: 0 },
      covenantId: VAULT_COV_ID,
      predecessorValue: vaultStateJson.feeReserve,
      fuel: { outpoint: { transactionId: H(0x03), index: 0 }, amount: (1n * KAS).toString(), scriptPublicKeyHex: `20${FUEL}ac` },
      root: { template: rootTemplate, state: rootState(), outpoint: { transactionId: H(0x04), index: 0 }, covenantId: ROOT_ID, value: ROOT_KAS.toString() }
    },
    changeXOnly: FUEL,
    descriptor
  });

  const manifest = buildOrgRootIntentManifest({ build, vaultOperations: [{ build, descriptor }], satisfiedApprovals: 2 });
  const v = verifyOrgRootIntentManifest({ manifest, descriptors: { [VAULT_COV_ID]: descriptor }, redeemScripts: { [VAULT_COV_ID]: build.vaultRedeemScriptHex } });
  assert.equal(v.verdict, "VERIFIED", JSON.stringify(v.failures));
  assert.equal(manifest.vaultOperations.length, 1);
  assert.equal(manifest.vaultOperations[0].opSelector, 2);
  assert.equal(manifest.vaultOperations[0].manifest.action.requiredRootAction, "authorize");
  assert.equal(manifest.vaultOperations[0].manifest.action.expectFrozenAfter, "0");
  assert.equal(manifest.vaultOperations[0].manifest.vault.orgRootCovenantId, ROOT_ID);
  assert.ok(v.checks.some((c) => c.name === "noHiddenCovenantOperations" && c.ok));

  /* HIDDEN EXTRA VAULT OPERATION: the transaction really does spend a second
   * covenant family, but the manifest does not declare it. */
  const hidden = tamper(manifest, (m) => {
    const frozen = JSON.parse(m.transaction.frozenCanonicalJson);
    frozen.inputs.push({ ...frozen.inputs[0], previousOutpoint: { transactionId: H(0x0c), index: 0 }, utxo: { ...frozen.inputs[0].utxo, covenantId: H(0x77) } });
    m.transaction.frozenCanonicalJson = JSON.stringify(frozen);
    m.fee.requiredFeeSompi = (BigInt(m.fee.requiredFeeSompi) + BigInt(frozen.inputs[0].utxo.amount)).toString();
  });
  const hv = verifyOrgRootIntentManifest({ manifest: hidden, descriptors: { [VAULT_COV_ID]: descriptor }, redeemScripts: { [VAULT_COV_ID]: build.vaultRedeemScriptHex } });
  assert.equal(hv.verdict, "REFUSED");
  assert.ok(hv.failures.some((f) => f.name === "noHiddenCovenantOperations"), `expected noHiddenCovenantOperations, got [${hv.failures.map((f) => f.name).join(", ")}]`);

  /* VAULT OPERATION SUBSTITUTED: the declared selector is not the one whose
   * state effect the transaction carries. */
  const swapped = tamper(manifest, (m) => {
    m.vaultOperations[0].opSelector = 4;
    m.vaultOperations[0].manifest.action.opSelector = 4;
    m.vaultOperations[0].manifest.action.sdkAction = "ownerEmergencyPause";
    m.vaultOperations[0].manifest.manifestHash = computeManifestHashV1(Object.fromEntries(Object.entries(m.vaultOperations[0].manifest).filter(([k]) => k !== "manifestHash")));
  });
  const sv = verifyOrgRootIntentManifest({ manifest: swapped, descriptors: { [VAULT_COV_ID]: descriptor }, redeemScripts: { [VAULT_COV_ID]: build.vaultRedeemScriptHex } });
  assert.equal(sv.verdict, "REFUSED");
  assert.ok(sv.failures.some((f) => f.name.endsWith("rootAuthorityPath")), `expected the root-authority-path check to fail, got [${sv.failures.map((f) => f.name).join(", ")}]`);

  /* THE TWO HALVES MUST AGREE WITH EACH OTHER. A relabelling that is
   * INTERNALLY consistent on the vault side — selector 4 really does require
   * a FREEZE root — must still be refused, because THIS manifest's root
   * action is AUTHORIZE. Showing owners a full-quorum action at the top while
   * a vault operation underneath needs only the lighter emergency quorum is
   * exactly the misrepresentation the manifest exists to prevent. */
  const halvesDisagree = tamper(manifest, (m) => {
    m.vaultOperations[0].opSelector = 4;
    m.vaultOperations[0].manifest.action.opSelector = 4;
    m.vaultOperations[0].manifest.action.sdkAction = "ownerEmergencyPause";
    m.vaultOperations[0].manifest.action.mutationClass = "AUTHORITY-REDUCING";
    m.vaultOperations[0].manifest.action.requiredRootAction = "freeze";
    m.vaultOperations[0].manifest.action.expectFrozenAfter = "1";
    m.vaultOperations[0].manifest.manifestHash = computeManifestHashV1(Object.fromEntries(Object.entries(m.vaultOperations[0].manifest).filter(([k]) => k !== "manifestHash")));
  });
  const hd = verifyOrgRootIntentManifest({ manifest: halvesDisagree, descriptors: { [VAULT_COV_ID]: descriptor }, redeemScripts: { [VAULT_COV_ID]: build.vaultRedeemScriptHex } });
  assert.equal(hd.verdict, "REFUSED");
  assert.ok(hd.failures.some((f) => f.name.endsWith("rootPathAgreesWithThisManifest")), `expected the cross-check between the root action and the vault op to fail, got [${hd.failures.map((f) => f.name).join(", ")}]`);
  assert.ok(hd.failures.some((f) => f.name.endsWith("frozenByteAgrees")), "the frozen byte the vault pins must also disagree");

  /* A VAULT PINNED TO A DIFFERENT ROOT cannot ride this manifest. */
  const foreign = tamper(manifest, (m) => {
    m.vaultOperations[0].manifest.vault.orgRootCovenantId = H(0x66);
    m.vaultOperations[0].manifest.manifestHash = computeManifestHashV1(Object.fromEntries(Object.entries(m.vaultOperations[0].manifest).filter(([k]) => k !== "manifestHash")));
  });
  const fv = verifyOrgRootIntentManifest({ manifest: foreign, descriptors: { [VAULT_COV_ID]: descriptor }, redeemScripts: { [VAULT_COV_ID]: build.vaultRedeemScriptHex } });
  assert.equal(fv.verdict, "REFUSED");
  assert.ok(fv.failures.some((f) => f.name.endsWith("rootPin")), `expected the vault root-pin check to fail, got [${fv.failures.map((f) => f.name).join(", ")}]`);
});

test("a set-changing action states the real owner-set diff, and the recovery/succession age gates are stated", { skip: SKIP }, () => {
  const rotate = buildV7RootTransaction({
    config,
    templateInput: rootTemplate,
    stateInput: rootState(),
    action: "rotate",
    params: { newOwnerSet: { owners: slots([OWNERS[0], OWNERS[1], NEW_OWNERS[0]]), ownerM: 3, emergencyK: 2, recoveryM: 2 } },
    chain: rootChain,
    changeXOnly: FUEL
  });
  const m = buildOrgRootIntentManifest({ build: rotate, vaultOperations: [], satisfiedApprovals: 2 });
  assert.equal(verifyOrgRootIntentManifest({ manifest: m }).verdict, "VERIFIED");
  assert.equal(m.action.authorityClass, "AUTHORITY-EXPANDING");
  assert.deepEqual(m.ownerSet.changes.added, [NEW_OWNERS[0]]);
  assert.deepEqual(m.ownerSet.changes.removed, [OWNERS[2]]);
  assert.equal(m.ownerSet.changes.thresholdsChanged, true);

  /* a manifest that hides an added owner is refused by the diff check */
  const hiddenAdd = tamper(m, (x) => {
    x.ownerSet.changes.added = [];
  });
  const hv = verifyOrgRootIntentManifest({ manifest: hiddenAdd });
  assert.equal(hv.verdict, "REFUSED");
  assert.ok(hv.failures.some((f) => f.name === "ownerSetDiff"));

  /* OWNER-RECOVER states the idle delay it is gated behind, and lands frozen */
  const recover = buildV7RootTransaction({
    config,
    templateInput: rootTemplate,
    stateInput: rootState(),
    action: "ownerRecover",
    params: { newOwnerSet: { owners: slots(NEW_OWNERS), ownerM: 2, emergencyK: 1, recoveryM: 1 } },
    chain: rootChain,
    changeXOnly: FUEL
  });
  const rm = buildOrgRootIntentManifest({ build: recover, vaultOperations: [], satisfiedApprovals: 2 });
  assert.equal(verifyOrgRootIntentManifest({ manifest: rm }).verdict, "VERIFIED");
  assert.equal(rm.action.minSequence, "1000");
  assert.equal(rm.rootState.after.state.frozen, "1", "decision D6: a recovery lands FROZEN");
  assert.equal(rm.ownerSet.changes.frozenChanged, true);
  const wrongAge = tamper(rm, (x) => {
    x.action.minSequence = "0";
  });
  const wv = verifyOrgRootIntentManifest({ manifest: wrongAge });
  assert.equal(wv.verdict, "REFUSED");
  assert.ok(wv.failures.some((f) => f.name === "relativeAgeGate" || f.name === "rootInputSequence"));

  /* SUCCESSION is TERMINAL for the outgoing set and expects NO owner slot */
  const succession = buildV7RootTransaction({
    config,
    templateInput: rootTemplate,
    stateInput: rootState(),
    action: "succession",
    params: { newOwnerSet: { owners: slots(NEW_OWNERS), ownerM: 2, emergencyK: 1, recoveryM: 1 } },
    chain: rootChain,
    changeXOnly: FUEL
  });
  const sm = buildOrgRootIntentManifest({ build: succession, vaultOperations: [], satisfiedApprovals: 1 });
  assert.equal(verifyOrgRootIntentManifest({ manifest: sm }).verdict, "VERIFIED");
  assert.equal(sm.action.authorityClassForPreviousSet, "TERMINAL");
  assert.deepEqual(sm.action.expectedSignerSlots, []);
  assert.equal(sm.action.minSequence, "2000");
  assert.equal(sm.rootState.after.state.frozen, "1");
});
