"use strict";

/*
 * SDK/INTEGRATION — v0.7-kas gate I3: THE HOSTILE MATRIX AT THE CORE
 * BOUNDARY, ON THE PRODUCTION BYTES.
 *
 * Sibling of sdk/test/org-root-hostile-matrix-v7.test.js's ARM 2 (the same
 * adversarial-field-class discipline, applied to the ROOTED KAS SAFE-PAYMENT
 * VAULT instead of the rooted payment vault). The covenant is the security
 * boundary; core/intent/org-root-manifest-v7-kas.js is DEFENCE IN DEPTH: a
 * signer reading a manifest must be refused with a NAMED failing check
 * BEFORE they sign, for every field class that could otherwise mislead them.
 *
 * Field classes covered (as scoped by Track C2's I3 assignment):
 *   amounts              — a spend claimed within cap/budget that isn't
 *   recipient            — the manifest's declared recipient != output 0's
 *   approvals            — the vault-level M-of-N approver tier misrepresented
 *   root pins             — the vault's orgRootCovenantId pin substituted
 *   template pins          — the pinned root geometry substituted
 *   lockTime binding       — a period-rollover's CLTV lockTime forged
 *   parent-action cross-check — an owner op's required root path disagrees
 *                               with the org-root-kas manifest wrapping it
 *
 * Classified REQUIREMENT_NOT_AVAILABLE (skipped, never silently passed) when
 * silverc / pv_call_encoder / pv_tx_probe are absent. TEST KEYS ONLY.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const { loadConfig } = require("../src/config");
const { buildAgentTreeV4 } = require("../src/agent-merkle-v4");
const { buildRecipientTree } = require("../src/recipient-merkle-v3");
const { deriveRootPinsV7 } = require("../src/contract-compiler-v7");
const { assertRootPinsMatchV7Kas } = require("../src/contract-compiler-v7-kas");
const { buildV7KasTransaction } = require("../src/vault-builders-v7-kas");
const { ENCODER_PATH } = require("../src/vault-builders-v4");
const { buildOrgRootIntentManifestV7Kas, verifyOrgRootIntentManifestV7Kas, buildRootedKasVaultManifestV7, verifyRootedKasVaultManifestV7 } = require("../../core/intent/org-root-manifest-v7-kas");
const { routeIntentManifestVerifier } = require("../../core/intent/router");
const { computeManifestHashV1 } = require("../../core/intent/canonical");
const { INACTIVE_SLOT_KEY, OWNER_SLOTS_V7 } = require("../../core/model/owner-set-v7");

const config = loadConfig({ dataRoot: fs.mkdtempSync(path.join(os.tmpdir(), "pv7kas-hostile-")) });
const available = fs.existsSync(config.silvercPath) && fs.existsSync(ENCODER_PATH) && fs.existsSync(path.join(config.repoRoot, "tests/vm/target/debug/pv_tx_probe"));
const SKIP = !available && "REQUIREMENT_NOT_AVAILABLE: silverc / pv_call_encoder / pv_tx_probe";

const KAS = 100000000n;
const H = (b) => b.toString(16).padStart(2, "0").repeat(32);
const ORG_ID = H(0xa7);
const ROOT_ID = H(0x52);
const VAULT_COV_ID = H(0x44);
const ALIEN_ID = H(0x7a);
const FUEL = H(0x64);
const RECOVERY_PK = H(0x51);
const AGENT_PK = H(0x62);
const RECIPIENT_PK = H(0x63);
const OTHER_PK = H(0x65);
const ROOT_KAS = 3n * KAS;

function slots(keys) {
  const out = [];
  for (let i = 0; i < OWNER_SLOTS_V7; i += 1) out.push(i < keys.length ? keys[i] : INACTIVE_SLOT_KEY);
  return out;
}

const OWNERS = [H(0x71), H(0x72), H(0x73)];
const rootTemplate = { orgId: ORG_ID, recoveryDelayDaa: "1000", successorPk: H(0x7f), successionDelayDaa: "2000", rootMaxFeePerTx: "200000" };
const ownerSet = { owners: slots(OWNERS), ownerM: 2, emergencyK: 1, recoveryM: 2 };
const rootState = (over = {}) => ({ boundOrgId: ORG_ID, ...ownerSet, frozen: 0, rootNonce: 0, ...over });
const rootChain = () => ({
  predecessorOutpoint: { transactionId: H(0x01), index: 0 },
  covenantId: ROOT_ID,
  predecessorValue: ROOT_KAS.toString(),
  fuel: { outpoint: { transactionId: H(0x03), index: 0 }, amount: (1n * KAS).toString(), scriptPublicKeyHex: `20${FUEL}ac` }
});

let vaultTemplate = null;
let rTree = null;
let agentPolicy = null;
if (available) {
  const rootPins = deriveRootPinsV7({ config, template: rootTemplate, ownerSet, covenantId: ROOT_ID });
  vaultTemplate = { vaultId: H(0x44), ...rootPins, recoveryPk: RECOVERY_PK };
  assertRootPinsMatchV7Kas({ config, vaultTemplate, rootTemplate, rootOwnerSet: ownerSet });
  rTree = buildRecipientTree([RECIPIENT_PK]);
  agentPolicy = { agentPk: AGENT_PK, maxPerSpend: "200000000000", periodBudget: "500000000000", periodLengthDaa: "864000", periodStartDaa: "541000000", periodSpent: "0", approvalThreshold: "100000000000000", agentMaxFeePerTx: "100000000", agentRecipientRoot: rTree.root };
}

const DEFAULT_AGENT_ROOT = "00".repeat(32);
function vaultState(over = {}) {
  return { protectedValue: (10000n * KAS).toString(), feeReserve: (5n * KAS).toString(), paused: "0", agentRoot: over.agentRoot ?? DEFAULT_AGENT_ROOT, approvers: over.approvers ?? [], approvalM: over.approvalM ?? "0", policyNonce: "0", ...over };
}
/* the vault's covenant UTXO carries protectedValue + feeReserve (unlike the
 * payment profile's own hostile-matrix analog, whose covenant value is JUST
 * feeReserve — this profile is plain KAS with a separate protected
 * principal, so the predecessor value must be the SUM). */
function vaultCovenantValue(over) {
  const s = vaultState(over);
  return (BigInt(s.protectedValue) + BigInt(s.feeReserve)).toString();
}
function vaultChain(over = {}) {
  return {
    predecessorOutpoint: { transactionId: H(0x0a), index: 0 },
    covenantId: VAULT_COV_ID,
    predecessorValue: over.predecessorValue ?? vaultCovenantValue(),
    fuel: { outpoint: { transactionId: H(0x03), index: 0 }, amount: (1n * KAS).toString(), scriptPublicKeyHex: `20${FUEL}ac` },
    root: { template: rootTemplate, state: rootState(), outpoint: { transactionId: H(0x04), index: 0 }, covenantId: ROOT_ID, value: ROOT_KAS.toString() },
    ...over
  };
}
const vaultBuild = (action, over = {}) => buildV7KasTransaction({ config, templateInput: vaultTemplate, stateInput: vaultState(over.stateOver), action, params: over.params, chain: vaultChain(over.chain), changeXOnly: FUEL });
const orgManifest = (build, ops = [], satisfied = 2) => buildOrgRootIntentManifestV7Kas({ build, vaultOperations: ops, satisfiedApprovals: satisfied });

function tamper(manifest, mutate) {
  const { manifestHash, ...body } = JSON.parse(JSON.stringify(manifest));
  void manifestHash;
  mutate(body);
  return { ...body, manifestHash: computeManifestHashV1(body) };
}
function rehashVaultOp(m, i = 0) {
  const { manifestHash, ...body } = m.vaultOperations[i].manifest;
  void manifestHash;
  m.vaultOperations[i].manifest = { ...body, manifestHash: computeManifestHashV1(body) };
}
function editFrozen(m, fn) {
  const frozen = JSON.parse(m.transaction.frozenCanonicalJson);
  fn(frozen);
  m.transaction.frozenCanonicalJson = JSON.stringify(frozen);
}
function verdictOf(manifest) {
  /* R7-04: every org-wrapped build in this file spends the SAME predecessor (default vaultState + vaultTemplate), so the
   * pause build's carried predecessor redeem is the redeem of every wrapped operation here. */
  return verifyOrgRootIntentManifestV7Kas({ manifest, redeemScripts: { [VAULT_COV_ID]: shapes().pause.vaultRedeemScriptHex } });
}

let SHAPES = null;
function shapes() {
  if (SHAPES) return SHAPES;
  const pause = vaultBuild("ownerPause");
  const emergency = vaultBuild("ownerEmergencyPause");
  const recover = vaultBuild("ownerRecover");
  const agentTree = buildAgentTreeV4([agentPolicy]);
  const spend = vaultBuild("agentSpend", {
    stateOver: { agentRoot: agentTree.root },
    params: { payAmountSompi: (40n * KAS).toString(), agentPk: AGENT_PK, agents: [agentPolicy], recipient: RECIPIENT_PK, recipients: [...rTree.recipients] },
    chain: { root: undefined }
  });
  /* a PERIOD-ROLLOVER spend: the only shape whose lockTime is non-zero */
  const spentLeaf = { ...agentPolicy, periodSpent: (450n * KAS).toString() };
  const otherLeaf = { ...agentPolicy, agentPk: H(0x66) };
  const rolloverTree = buildAgentTreeV4([spentLeaf, otherLeaf]);
  const rolloverSpend = buildV7KasTransaction({
    config,
    templateInput: vaultTemplate,
    stateInput: vaultState({ agentRoot: rolloverTree.root }),
    action: "agentSpend",
    params: { payAmountSompi: (40n * KAS).toString(), agentPk: AGENT_PK, agents: [spentLeaf, otherLeaf], recipient: RECIPIENT_PK, recipients: [...rTree.recipients], periodsElapsed: "2" },
    chain: { predecessorOutpoint: { transactionId: H(0x0a), index: 0 }, covenantId: VAULT_COV_ID, predecessorValue: vaultCovenantValue(), fuel: { outpoint: { transactionId: H(0x03), index: 0 }, amount: (1n * KAS).toString(), scriptPublicKeyHex: `20${FUEL}ac` } },
    changeXOnly: FUEL
  });
  /* an ABOVE-THRESHOLD spend so the vault-level approver tier is populated */
  const lowThresholdPolicy = { ...agentPolicy, approvalThreshold: (10n * KAS).toString() };
  const lowTree = buildAgentTreeV4([lowThresholdPolicy]);
  const approvedSpend = buildV7KasTransaction({
    config,
    templateInput: vaultTemplate,
    stateInput: vaultState({ agentRoot: lowTree.root, approvers: [H(0x91), H(0x92), H(0x93)], approvalM: "2" }),
    action: "agentSpend",
    params: { payAmountSompi: (40n * KAS).toString(), agentPk: AGENT_PK, agents: [lowThresholdPolicy], recipient: RECIPIENT_PK, recipients: [...rTree.recipients] },
    chain: { predecessorOutpoint: { transactionId: H(0x0a), index: 0 }, covenantId: VAULT_COV_ID, predecessorValue: vaultCovenantValue(), fuel: { outpoint: { transactionId: H(0x03), index: 0 }, amount: (1n * KAS).toString(), scriptPublicKeyHex: `20${FUEL}ac` } },
    changeXOnly: FUEL
  });
  SHAPES = { pause, emergency, recover, spend, rolloverSpend, approvedSpend };
  return SHAPES;
}

test("I3 sanity: every manifest-bearing v0.7-kas ACCEPT shape produces a VERIFIED org-root-kas manifest, and a standalone agentSpend manifest verifies at the vault half alone", { skip: SKIP }, () => {
  const s = shapes();
  for (const [name, build] of [["pause", s.pause], ["emergency", s.emergency], ["recover", s.recover]]) {
    const satisfied = name === "emergency" ? 1 : 2;
    const v = verdictOf(orgManifest(build, [{ build }], satisfied));
    assert.equal(v.verdict, "VERIFIED", `${name}: ${JSON.stringify(v.failures)}`);
  }
  assert.equal(s.spend.hasRootInput, false, "a delegate spend has no root input at all");
  assert.throws(() => buildOrgRootIntentManifestV7Kas({ build: s.spend, vaultOperations: [{ build: s.spend }] }), /SCHEMA_INVALID|without a root input/);
  assert.throws(() => routeIntentManifestVerifier("policyvault-0.7-kas"), /VERIFY_WITHIN_PARENT|verified inside/, "a rooted-kas-vault manifest has no standalone verifier route");
  /* the standalone (non-wrapped) shape a delegate spend manifest actually
   * takes: buildRootedKasVaultManifestV7 directly, never through the router */
  const standalone = buildRootedKasVaultManifestV7({ build: s.spend });
  assert.equal(standalone.manifestVersion, "policyvault-rooted-kas-vault-manifest/1");
  assert.equal(standalone.action.requiresRootInput, false);
});

test("I3 ARM 2: every scoped §4 field class has a mutated sibling REFUSED before signing, with the check named", { skip: SKIP }, () => {
  const s = shapes();
  const pause = orgManifest(s.pause, [{ build: s.pause }]);
  const emergency = orgManifest(s.emergency, [{ build: s.emergency }], 1);
  const recover = orgManifest(s.recover, [{ build: s.recover }]);

  const concreteRows = [
    /* root pins — the vault's orgRootCovenantId pin substituted */
    ["root pins: a vault pinned to a FOREIGN organizational root", tamper(pause, (m) => {
      m.vaultOperations[0].manifest.vault.orgRootCovenantId = ALIEN_ID;
      rehashVaultOp(m);
    }), "vaultOp[44444444]rootPin"],
    /* template pins — the pinned root geometry substituted */
    ["template pins: the vault's pinned ROOT TEMPLATE geometry substituted", tamper(pause, (m) => {
      m.vaultOperations[0].manifest.vault.rootGeometry.stateLen = 466;
      rehashVaultOp(m);
    }), "vault[44444444].templatePins"],
    /* parent-action cross-check — the two halves of the authority model made to disagree */
    ["parent-action cross-check: the EMERGENCY selector's vault op claims it needs a full-quorum AUTHORIZE root", tamper(emergency, (m) => {
      m.vaultOperations[0].manifest.action.requiredRootAction = "authorize";
      m.vaultOperations[0].manifest.action.expectFrozenAfter = "0";
      rehashVaultOp(m);
    }), "vaultOp[44444444]rootPathAgreesWithThisManifest"],
    ["parent-action cross-check: a full-quorum pause claims it needs only the lighter FREEZE root path", tamper(pause, (m) => {
      m.vaultOperations[0].manifest.action.requiredRootAction = "freeze";
      m.vaultOperations[0].manifest.action.expectFrozenAfter = "1";
      rehashVaultOp(m);
    }), "vaultOp[44444444]frozenByteAgrees"],
    /* rc21 review R6-03: the rc21 outer checks ported to this profile */
    ["the outer covenantId declared as a FOREIGN family (inner manifest untouched)", tamper(pause, (m) => { m.vaultOperations[0].covenantId = ALIEN_ID; }), `vaultOp[${ALIEN_ID.slice(0, 8)}]idsBound`],
    ["a genesis-shaped covenant output tagged with the vault family (authorizing input carries no covenant)", tamper(pause, (m) => {
      const f = JSON.parse(m.transaction.frozenCanonicalJson);
      f.outputs.push({ value: "1000", scriptPublicKey: { version: 0, scriptHex: `aa20${H(0x0d)}87` }, covenant: { authorizingInput: f.inputs.length - 1, covenantId: m.vaultOperations[0].covenantId } });
      m.transaction.frozenCanonicalJson = JSON.stringify(f);
    }), "noCovenantGenesisInRootAction"],
    ["the root continuation script substituted (covenant metadata kept)", tamper(pause, (m) => {
      const f = JSON.parse(m.transaction.frozenCanonicalJson);
      const i = f.outputs.findIndex((o) => o.covenant && o.covenant.covenantId === m.root.covenantId);
      f.outputs[i].scriptPublicKey = { version: 0, scriptHex: `aa20${H(0x0d)}87` };
      m.transaction.frozenCanonicalJson = JSON.stringify(f);
    }), "rootScriptsBound"],
    ["a terminal recover that still continues its own vault covenant", tamper(recover, (m) => {
      const f = JSON.parse(m.transaction.frozenCanonicalJson);
      const vi = f.inputs.findIndex((x) => x.utxo.covenantId === m.vaultOperations[0].covenantId);
      f.outputs.push({ value: "1000", scriptPublicKey: { version: 0, scriptHex: `aa20${H(0x0d)}87` }, covenant: { authorizingInput: vi, covenantId: m.vaultOperations[0].covenantId } });
      m.transaction.frozenCanonicalJson = JSON.stringify(f);
    }), "vault[44444444].terminalNoContinuation"],
    /* malicious recovery redirect (bonus, same family as root/template pins) */
    ["recovery destination redirected away from the genesis pin", tamper(recover, (m) => {
      editFrozen(m, (f) => {
        f.outputs[0].scriptPublicKey.scriptHex = `20${OTHER_PK}ac`;
      });
    }), "vault[44444444].payoutToPinnedRecoveryPk"]
  ];

  for (const [label, bad, expectedCheck] of concreteRows) {
    const v = verdictOf(bad);
    assert.equal(v.verdict, "REFUSED", `${label}: must be REFUSED`);
    const hit = v.failures.find((f) => f.name === expectedCheck);
    assert.ok(hit, `${label}: expected the failing check ${expectedCheck}, got [${v.failures.map((f) => f.name).join(", ")}]`);
    assert.equal(v.statement, null, `${label}: a refused manifest never carries the verified statement`);
  }

  /* --- amounts / recipient / lockTime / approvals: standalone agentSpend manifest --- */
  const spendManifest = buildRootedKasVaultManifestV7({ build: s.spend });
  const spendRows = [
    ["amounts: the declared agent policy cap understated below the actual output-0 payment", tamper(spendManifest, (m) => {
      m.policy.agentPolicy.maxPerSpend = "1";
    }), "vault[44444444].spendWithinCap"],
    ["recipient: the manifest claims a different recipient than output 0 actually pays", tamper(spendManifest, (m) => {
      m.policy.recipient = OTHER_PK;
    }), "vault[44444444].outputZeroIsRecipient"]
  ];
  const frozenSpend = JSON.parse(s.spend.frozenCanonicalJson);
  for (const [label, bad, expectedCheck] of spendRows) {
    const checks = [];
    const failures = [];
    const check = (name, ok, detail) => {
      checks.push({ name, ok: !!ok, detail });
      if (!ok) failures.push({ name, detail });
    };
    verifyRootedKasVaultManifestV7({ manifest: bad, frozen: frozenSpend, check });
    const hit = failures.find((f) => f.name === expectedCheck);
    assert.ok(hit, `${label}: expected the failing check ${expectedCheck}, got [${failures.map((f) => f.name).join(", ")}]`);
  }

  /* lockTime binding: only the ROLLOVER spend has a non-zero lockTime */
  const rolloverManifest = buildRootedKasVaultManifestV7({ build: s.rolloverSpend });
  const forgedLockTime = tamper(rolloverManifest, (m) => {
    m.policy.lockTime = String(Number(m.policy.lockTime) + 9000);
  });
  {
    const frozenRollover = JSON.parse(s.rolloverSpend.frozenCanonicalJson);
    const failures = [];
    verifyRootedKasVaultManifestV7({
      manifest: forgedLockTime,
      frozen: frozenRollover,
      check: (name, ok, detail) => {
        if (!ok) failures.push({ name, detail });
      }
    });
    assert.ok(failures.some((f) => f.name === "vault[44444444].lockTimeBound"), `lockTime binding: expected vault[44444444].lockTimeBound, got [${failures.map((f) => f.name).join(", ")}]`);
  }

  /* approvals: the vault-level M-of-N approver tier misrepresented (an
   * above-threshold spend claiming a threshold M below the covenant reality
   * is not itself detectable from the manifest's OWN declared fields without
   * cross-checking the leaf's approvalThreshold — asserted here). */
  const approvedManifest = buildRootedKasVaultManifestV7({ build: s.approvedSpend });
  assert.equal(approvedManifest.approverTier.aboveThreshold, true, "sanity: this spend is above the leaf's approvalThreshold");
  const forgedApprovals = tamper(approvedManifest, (m) => {
    m.approverTier.approvalThreshold = "999999999999999"; // claims a threshold the leaf never declared
  });
  {
    const frozenApproved = JSON.parse(s.approvedSpend.frozenCanonicalJson);
    const failures = [];
    verifyRootedKasVaultManifestV7({
      manifest: forgedApprovals,
      frozen: frozenApproved,
      check: (name, ok, detail) => {
        if (!ok) failures.push({ name, detail });
      }
    });
    assert.ok(failures.some((f) => f.name === "vault[44444444].approverTierThresholdMatchesLeaf"), `approvals: expected vault[44444444].approverTierThresholdMatchesLeaf, got [${failures.map((f) => f.name).join(", ")}]`);
  }

  console.log(`I3 ARM 2: ${concreteRows.length + spendRows.length + 2} §4 field-class rows refused with the failing check named (root pins, template pins, parent-action cross-check x2, recovery redirect, amounts, recipient, lockTime binding, approvals)`);
});

/* rc26 round-7 internal review R7-01 / R7-02 — PARITY on the (unfrozen, never-mainnet) rooted-KAS candidate profile:
 * the kas verifier binds every input's sequence + the lockTime, and the kas setAgentRoot manifest carries the new
 * (v4-layout) policy set bound to stateAfter.agentRoot. Real builds; every tamper re-hashed. RED on cf4e644. */
test("rc26 round-7 R7-01 / R7-02 (kas profile parity, real builds): sequences / lockTime bound; setAgentRoot policy set carried and bound", { skip: SKIP }, () => {
  const s = shapes();
  const tag = `vault[${VAULT_COV_ID.slice(0, 8)}].`;
  const pause = orgManifest(s.pause, [{ build: s.pause }]);
  const setRootBuild = vaultBuild("ownerSetAgentRoot", { params: { agents: [{ ...agentPolicy, agentPk: H(0x71), recipients: [...rTree.recipients] }] } });
  const setRoot = orgManifest(setRootBuild, [{ build: setRootBuild }]);
  assert.equal(verdictOf(setRoot).verdict, "VERIFIED", `control: ${JSON.stringify(verdictOf(setRoot).failures)}`);
  const carried = setRoot.vaultOperations[0].manifest.policy.agentSet;
  assert.ok(Array.isArray(carried) && carried.length === 1 && carried[0].agentPk === H(0x71), "the kas manifest CARRIES the new policy set");
  assert.equal(setRootBuild.successorState.agentRoot, buildAgentTreeV4(carried.map(({ recipients, ...policy }) => { void recipients; return policy; })).root, "the declared successor agentRoot IS the v4 fold of the carried set (policy fields)");
  assert.throws(() => vaultBuild("ownerSetAgentRoot", { params: { newAgentRoot: H(0x99) } }), (e) => e.code === "AGENT_SET_REQUIRED");
  const rows = [
    ["R7-02: the policy set withheld", tamper(setRoot, (m) => { delete m.vaultOperations[0].manifest.policy.agentSet; rehashVaultOp(m); }), `${tag}agentSetPresent`],
    ["R7-02: the policy set substituted (declared root kept)", tamper(setRoot, (m) => { m.vaultOperations[0].manifest.policy.agentSet[0].maxPerSpend = "1000000000"; rehashVaultOp(m); }), `${tag}agentSetBound`],
    ["Codex checkpoint 11 (R7-02, parity): recipients substituted, root kept", tamper(setRoot, (m) => { m.vaultOperations[0].manifest.policy.agentSet[0].recipients = [H(0x0d)]; rehashVaultOp(m); }), `${tag}agentRecipientsBound`],
    ["Codex checkpoint 11 (R7-02, parity): recipients withheld", tamper(setRoot, (m) => { delete m.vaultOperations[0].manifest.policy.agentSet[0].recipients; rehashVaultOp(m); }), `${tag}agentRecipientsBound`],
    ["R7-01: vault input sequence 1,000,000 on a pause", tamper(pause, (m) => editFrozen(m, (f) => { f.inputs[0].sequence = "1000000"; })), `${tag}inputSequencesZero`],
    ["R7-01: fee input sequence 2^32-1 on a pause (outer)", tamper(pause, (m) => editFrozen(m, (f) => { f.inputs[f.inputs.length - 1].sequence = "4294967295"; })), "inputSequencesZero"],
    ["R7-01: root input sequence 1,000,000 on a pause (non-age-gated root)", tamper(pause, (m) => editFrozen(m, (f) => { f.inputs[1].sequence = "1000000"; })), "rootInputSequenceZero"],
    ["R7-01: lockTime 7 on a pause (inner)", tamper(pause, (m) => editFrozen(m, (f) => { f.lockTime = "7"; })), `${tag}lockTimeZero`],
    ["R7-01: lockTime 7 on a pause (outer)", tamper(pause, (m) => editFrozen(m, (f) => { f.lockTime = "7"; })), "lockTimeZero"]
  ];
  for (const [label, manifest, expectedCheck] of rows) {
    const v = verdictOf(manifest);
    assert.notEqual(v.verdict, "VERIFIED", label);
    assert.ok(v.failures.some((f) => f.name === expectedCheck), `${label}: expected ${expectedCheck}, got ${v.failures.map((f) => f.name).join(",")}`);
  }
});

/* R7-04 CLOSURE (v0.7 enablement directive 2026-09-10) — the rooted-KAS pre-sign verifier binds the DECLARED pins and the
 * reviewed predecessor / successor states to the scripts the transaction ACTUALLY spends and creates, through the
 * shared-core skeleton core/intent/vault-script-v7-kas.js (mechanically derived from real silverc output). Real builds;
 * every tamper re-hashed. RED-FIRST on 7cde043: the KAS build carried no predecessor redeem, the successor output was bound
 * by count + value only, and the recovery payout was bound to the DECLARED recoveryPk only — so a successor locking script
 * substituted for garbage (value + covenant metadata kept) and a consistently redirected recoveryPk + payout were both
 * VERIFIED. Every row below names the check that must refuse it. */
const kasScript = require("../../core/intent/vault-script-v7-kas");
test("R7-04 closure (kas profile, real builds): predecessor redeem carried + bound to the spent UTXO and the reviewed state; successor script rebuilt from the redeem AND from the declared pins; recovery payout bound to the pin compiled into the spent script", { skip: SKIP }, () => {
  const s = shapes();
  const tag = `vault[${VAULT_COV_ID.slice(0, 8)}].`;
  const redeemOf = (build) => ({ [VAULT_COV_ID]: build.vaultRedeemScriptHex });
  /* CARRIAGE: every rooted-KAS build carries its predecessor redeem + state region, and P2SH(redeem) IS the spent locking script */
  for (const [name, build] of Object.entries(s)) {
    assert.equal(typeof build.vaultRedeemScriptHex, "string", `${name}: the build carries vaultRedeemScriptHex`);
    assert.equal(typeof build.vaultStateRegionHex, "string", `${name}: the build carries vaultStateRegionHex`);
    const frozen = JSON.parse(build.frozenCanonicalJson);
    const vaultIn = frozen.inputs.find((i) => i.utxo.covenantId === VAULT_COV_ID);
    assert.equal(kasScript.p2shSpkHexOf(build.vaultRedeemScriptHex), vaultIn.utxo.scriptPublicKey.scriptHex, `${name}: P2SH(carried redeem) == the vault input's locking script`);
    assert.equal(kasScript.splitVaultRedeemHexV7Kas(build.vaultRedeemScriptHex).regionHex, build.vaultStateRegionHex, `${name}: the carried region is the redeem's region`);
    assert.deepEqual(kasScript.decodeVaultTemplatePinsV7Kas(build.vaultRedeemScriptHex).pins, { ...vaultTemplate }, `${name}: the pins compiled into the spent script decode back to the vault's template`);
  }
  const pause = orgManifest(s.pause, [{ build: s.pause }]);
  const recover = orgManifest(s.recover, [{ build: s.recover }]);
  /* CONTROLS: VERIFIED with the redeem, the new checks present and passing */
  for (const [name, m, build, expectChecks] of [
    ["pause", pause, s.pause, ["vaultRedeemPresent", "vaultRedeemWellFormed", "vaultRedeemMatchesUtxo", "vaultRedeemStateAgrees", "vaultGenerationAgrees", "templatePinsBound", "successorScriptReconstructed", "successorScriptFromPins"]],
    ["recover", recover, s.recover, ["vaultRedeemPresent", "vaultRedeemMatchesUtxo", "vaultRedeemStateAgrees", "templatePinsBound", "payoutToPinnedRecoveryPk"]]
  ]) {
    const v = verifyOrgRootIntentManifestV7Kas({ manifest: m, redeemScripts: redeemOf(build) });
    assert.equal(v.verdict, "VERIFIED", `${name} control: ${JSON.stringify(v.failures)}`);
    for (const c of expectChecks) assert.ok(v.checks.some((k) => k.name === `${tag}${c}` && k.ok), `${name} control: check ${tag}${c} present and passing (got ${v.checks.map((k) => k.name).join(",")})`);
  }
  /* the redeem withheld / malformed: REFUSED — a manifest is never "verified without the evidence" */
  {
    const v = verifyOrgRootIntentManifestV7Kas({ manifest: pause });
    assert.equal(v.verdict, "REFUSED", "withheld redeem must REFUSE");
    assert.ok(v.failures.some((f) => f.name === `${tag}vaultRedeemPresent`), `withheld: expected ${tag}vaultRedeemPresent, got ${v.failures.map((f) => f.name).join(",")}`);
    const w = verifyOrgRootIntentManifestV7Kas({ manifest: pause, redeemScripts: { [VAULT_COV_ID]: "6b" + "00".repeat(40) } });
    assert.ok(w.failures.some((f) => f.name === `${tag}vaultRedeemWellFormed`), `malformed: expected ${tag}vaultRedeemWellFormed, got ${w.failures.map((f) => f.name).join(",")}`);
  }
  const foreignRedeem = kasScript.reconstructVaultScriptHexV7Kas({ template: { ...vaultTemplate, recoveryPk: OTHER_PK }, state: s.pause.stateJson }); // another vault's (other recovery key) script, pure rebuild
  const rows = [
    ["successor locking script substituted (value + covenant metadata kept)", tamper(pause, (m) => editFrozen(m, (f) => { const i = f.outputs.findIndex((o) => o.covenant && o.covenant.covenantId === VAULT_COV_ID); f.outputs[i].scriptPublicKey.scriptHex = `aa20${H(0x0d)}87`; })), redeemOf(s.pause), [`${tag}successorScriptReconstructed`, `${tag}successorScriptFromPins`]],
    ["recovery destination AND the declared recoveryPk redirected together (self-consistent manifest)", tamper(recover, (m) => { m.vaultOperations[0].manifest.vault.recoveryPk = OTHER_PK; m.vaultOperations[0].manifest.policy.recoveryPk = OTHER_PK; rehashVaultOp(m); editFrozen(m, (f) => { f.outputs[0].scriptPublicKey.scriptHex = `20${OTHER_PK}ac`; }); }), redeemOf(s.recover), [`${tag}templatePinsBound`, `${tag}payoutToPinnedRecoveryPk`]],
    ["declared root suffix geometry +1000 (well-formed pin that is not the compiled one)", tamper(pause, (m) => { m.vaultOperations[0].manifest.vault.rootGeometry.suffixLen += 1000; rehashVaultOp(m); }), redeemOf(s.pause), [`${tag}templatePinsBound`]],
    ["declared rootTemplateVmHash substituted (well-formed)", tamper(pause, (m) => { m.vaultOperations[0].manifest.vault.rootTemplateVmHash = H(0x9b); rehashVaultOp(m); }), redeemOf(s.pause), [`${tag}templatePinsBound`]],
    ["reviewed predecessor state substituted (approvalM) with the true redeem kept", tamper(pause, (m) => { m.vaultOperations[0].manifest.stateBefore.state.approverSlots[0] = H(0x91); m.vaultOperations[0].manifest.stateBefore.state.approvalM = "1"; m.vaultOperations[0].manifest.stateAfter.state.approverSlots[0] = H(0x91); m.vaultOperations[0].manifest.stateAfter.state.approvalM = "1"; rehashVaultOp(m); }), redeemOf(s.pause), [`${tag}vaultRedeemStateAgrees`, `${tag}templatePinsBound`]],
    ["a DIFFERENT vault's redeem (other recovery key) presented for this input", pause, { [VAULT_COV_ID]: foreignRedeem }, [`${tag}vaultRedeemMatchesUtxo`, `${tag}templatePinsBound`]]
  ];
  for (const [label, manifest, redeemScripts, expected] of rows) {
    const v = verifyOrgRootIntentManifestV7Kas({ manifest, redeemScripts });
    assert.equal(v.verdict, "REFUSED", `${label}: must be REFUSED`);
    for (const name of expected) assert.ok(v.failures.some((f) => f.name === name), `${label}: expected ${name}, got [${v.failures.map((f) => f.name).join(", ")}]`);
    assert.equal(v.statement, null, `${label}: a refused manifest never carries the verified statement`);
  }
  /* standalone delegate spend (no root): the same binding, at the vault half alone */
  {
    const spendManifest = buildRootedKasVaultManifestV7({ build: s.spend });
    const frozenSpend = JSON.parse(s.spend.frozenCanonicalJson);
    const run = (manifest, frozen, redeemHex) => { const failures = []; const names = []; verifyRootedKasVaultManifestV7({ manifest, frozen, redeemHex, check: (name, ok, detail) => { names.push(name); if (!ok) failures.push({ name, detail }); } }); return { failures, names }; };
    const control = run(spendManifest, frozenSpend, s.spend.vaultRedeemScriptHex);
    assert.deepEqual(control.failures, [], `spend control: ${JSON.stringify(control.failures)}`);
    for (const c of ["vaultRedeemMatchesUtxo", "vaultRedeemStateAgrees", "templatePinsBound", "successorScriptReconstructed", "successorScriptFromPins"]) assert.ok(control.names.includes(`${tag}${c}`), `spend control: ${tag}${c} exercised`);
    assert.ok(run(spendManifest, frozenSpend, null).failures.some((f) => f.name === `${tag}vaultRedeemPresent`), "spend: withheld redeem refused");
    const badSucc = JSON.parse(s.spend.frozenCanonicalJson);
    const si = badSucc.outputs.findIndex((o) => o.covenant && o.covenant.covenantId === VAULT_COV_ID);
    badSucc.outputs[si].scriptPublicKey.scriptHex = `aa20${H(0x0d)}87`;
    const sub = run(spendManifest, badSucc, s.spend.vaultRedeemScriptHex);
    assert.ok(sub.failures.some((f) => f.name === `${tag}successorScriptReconstructed`), `spend: substituted successor script refused (got ${sub.failures.map((f) => f.name).join(",")})`);
  }
  console.log(`R7-04 closure: ${rows.length} pin/state/script-substitution rows + withheld/malformed redeem + standalone spend refused with the failing check named; ${Object.keys(s).length} real builds carry their bound predecessor redeem`);
});
