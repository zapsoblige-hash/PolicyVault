"use strict";

/*
 * SDK/INTEGRATION — v0.7 gate I3c: THE HOSTILE MATRIX AT THE CORE BOUNDARY,
 * ON THE PRODUCTION BYTES.
 *
 * The covenant is the security boundary; the core is DEFENCE IN DEPTH. This
 * suite asserts that property mechanically, in both directions:
 *
 *   ARM 1 — every SDK-built ACCEPT shape of gate I2 that carries an
 *           organizational-root manifest produces a VERIFIED manifest;
 *   ARM 2 — for every adversarial FIELD CLASS of design §4, a mutated sibling
 *           of a real build is REFUSED by core/intent/org-root-manifest-v7
 *           BEFORE anyone signs, with the failing check NAMED;
 *   ARM 3 — every one of the 20 PRODUCTION-BYTE REJECT VECTORS that gate I2
 *           proved consensus refuses is ALSO refused inside the core, and each
 *           refusal is ATTRIBUTED to the layer that owns it:
 *              MANIFEST      the org-root manifest verifier
 *              VAULT_HALF    the rooted-vault verifier (the half a parent runs)
 *              BUILDER       the SDK refuses to build the shape at all
 *              FINALIZER     the 780-byte blob assembler / signature gate
 *           A vector that is manifest-visible and that the core ACCEPTS is a
 *           FINDING; the suite fails on a non-empty finding list.
 *
 * WHAT IS DELIBERATELY OUT OF THE MANIFEST'S DOMAIN (recorded, not hidden):
 * a manifest is what owners read BEFORE they sign, so it cannot see forged
 * SIGNATURE material — an abstaining slot, a copied slot, an outsider's
 * signature, a forged sighash gate byte, or a succession signed by the wrong
 * key. Those are the FINALIZER's and consensus's domain, and ARM 3 asserts the
 * finalizer refusal for each of them explicitly rather than leaving a hole.
 *
 * Classified REQUIREMENT_NOT_AVAILABLE (skipped, never silently passed) when
 * silverc / pv_call_encoder / pv_tx_probe are absent.
 * TEST KEYS ONLY.
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
const { buildV7RootTransaction, buildV7Transaction, finalizeV7RootTransaction } = require("../src/vault-builders-v7");
const { ENCODER_PATH } = require("../src/vault-builders-v4");
const {
  buildOrgRootIntentManifest,
  verifyOrgRootIntentManifest,
  buildRootedVaultManifestV7,
  verifyRootedVaultManifestV7
} = require("../../core/intent/org-root-manifest-v7");
const { routeIntentManifestVerifier } = require("../../core/intent/router");
const { computeManifestHashV1 } = require("../../core/intent/canonical");
const { INACTIVE_SLOT_KEY, OWNER_SLOTS_V7, PLACEHOLDER_SLOT_HEX_V7, assembleOwnerSigsBlobV7 } = require("../../core/model/owner-set-v7");

const config = loadConfig({ dataRoot: fs.mkdtempSync(path.join(os.tmpdir(), "pv7-hostile-")) });
const available = fs.existsSync(config.silvercPath) && fs.existsSync(ENCODER_PATH) && fs.existsSync(path.join(config.repoRoot, "tests/vm/target/debug/pv_tx_probe"));
const SKIP = !available && "REQUIREMENT_NOT_AVAILABLE: silverc / pv_call_encoder / pv_tx_probe";

const KAS = 100000000n;
const H = (b) => b.toString(16).padStart(2, "0").repeat(32);
const ORG_ID = H(0xa7);
const ROOT_ID = H(0x52);
const VAULT_COV_ID = H(0x43);
const TOKEN_FAMILY = H(0x54);
const ALIEN_ID = H(0x7a);
const FUEL = H(0x64);
const RECOVERY_PK = H(0x51);
const AGENT_PK = H(0x62);
const RECIPIENT_PK = H(0x63);
const ROOT_KAS = 3n * KAS;

function slots(keys) {
  const out = [];
  for (let i = 0; i < OWNER_SLOTS_V7; i += 1) out.push(i < keys.length ? keys[i] : INACTIVE_SLOT_KEY);
  return out;
}

const OWNERS = [H(0x71), H(0x72), H(0x73)];
const NEW_OWNERS = [H(0x81), H(0x82), H(0x83), H(0x84)];
const rootTemplate = { orgId: ORG_ID, recoveryDelayDaa: "1000", successorPk: H(0x7f), successionDelayDaa: "2000", rootMaxFeePerTx: "200000" };
const ownerSet = { owners: slots(OWNERS), ownerM: 2, emergencyK: 1, recoveryM: 2 };
const rootState = (over = {}) => ({ boundOrgId: ORG_ID, ...ownerSet, frozen: 0, rootNonce: 0, ...over });
const rootChain = () => ({
  predecessorOutpoint: { transactionId: H(0x01), index: 0 },
  covenantId: ROOT_ID,
  predecessorValue: ROOT_KAS.toString(),
  fuel: { outpoint: { transactionId: H(0x03), index: 0 }, amount: (1n * KAS).toString(), scriptPublicKeyHex: `20${FUEL}ac` }
});

/* ---- the rooted vault ---- */
let descriptor = null;
let vaultTemplate = null;
let agentTree = null;
let rTree = null;
let agentPolicy = null;
if (available) {
  const ref = compileKcc20Program({ config, state: assets.kcc20.ZERO_STATE, familyBound: 2 });
  descriptor = {
    schema: "policyvault-asset-descriptor/1",
    assetId: H(0x11),
    displayName: "Org Treasury Token",
    tokenStandard: "kcc20/1",
    tokenCovenantId: TOKEN_FAMILY,
    acceptedTransferTemplates: [{ templateVmHashBlake2b256: ref.templateVmHashBlake2b256, prefixLen: ref.geometry.prefixLen, suffixLen: ref.geometry.suffixLen, stateLayout: "kcc20-state/1" }],
    decimalsDisplay: 2,
    issuerPowers: { mint: false, burn: false, freeze: false, blacklist: false, redemptionControl: false, upgradeMigration: false, controllerRotation: false, emergencyControl: false }
  };
  const rootPins = deriveRootPinsV7({ config, template: rootTemplate, ownerSet, covenantId: ROOT_ID });
  vaultTemplate = {
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
  rTree = buildRecipientTree([RECIPIENT_PK]);
  agentPolicy = {
    agentPk: AGENT_PK,
    tokenMaxPerSpend: "250",
    tokenPeriodBudget: "400",
    periodLengthDaa: "1000",
    periodStartDaa: "5000",
    tokenPeriodSpent: "0",
    agentMaxFeePerTx: (1n * KAS).toString(),
    agentMaxCarryKas: (KAS / 4n).toString(),
    agentRecipientRoot: rTree.root
  };
  agentTree = buildTokenAgentTreeV5([agentPolicy]);
}
const vaultState = (over = {}) => ({ feeReserve: (5n * KAS).toString(), paused: "0", agentRoot: agentTree.root, policyNonce: "0", ...over });

function tokenPosition(amount = 300) {
  const state = { ownerIdentifier: VAULT_COV_ID, identifierType: assets.kcc20.OWNER_SCHEMES.COVENANT_ID, amount: String(amount), isMinter: false };
  const program = compileKcc20Program({ config, state, familyBound: 2 });
  return { outpoint: { transactionId: H(0x0b), index: 0 }, value: (2n * KAS).toString(), scriptPublicKeyHex: program.p2shSpkHex, covenantId: TOKEN_FAMILY, state };
}

function vaultChain(over = {}) {
  return {
    predecessorOutpoint: { transactionId: H(0x0a), index: 0 },
    covenantId: VAULT_COV_ID,
    predecessorValue: over.predecessorValue ?? vaultState().feeReserve,
    fuel: { outpoint: { transactionId: H(0x03), index: 0 }, amount: (1n * KAS).toString(), scriptPublicKeyHex: `20${FUEL}ac` },
    root: { template: rootTemplate, state: rootState(), outpoint: { transactionId: H(0x04), index: 0 }, covenantId: ROOT_ID, value: ROOT_KAS.toString() },
    ...over
  };
}

const rootBuild = (action, params = {}, stateOver = {}) =>
  buildV7RootTransaction({ config, templateInput: rootTemplate, stateInput: rootState(stateOver), action, params, chain: rootChain(), changeXOnly: FUEL });

const vaultBuild = (action, over = {}) =>
  buildV7Transaction({ config, templateInput: vaultTemplate, stateInput: vaultState(over.stateOver), action, params: over.params, chain: vaultChain(over.chain), changeXOnly: FUEL, descriptor });

/* Codex checkpoint 6 (UX-02 / UX-13): every verification carries the vault's predecessor redeem script (keyed by the
 * predecessor state id the manifest declares, so re-hashed tamper clones still find it). */
const REDEEM_BY_STATE_ID = new Map();
const orgManifest = (build, ops = [], satisfied = 2) => {
  for (const op of ops) if (op.build && op.build.vaultRedeemScriptHex) REDEEM_BY_STATE_ID.set(op.build.predecessorStateId, op.build.vaultRedeemScriptHex);
  return buildOrgRootIntentManifest({ build, vaultOperations: ops, satisfiedApprovals: satisfied });
};
const REDEEMS = (manifest) => Object.fromEntries((manifest && Array.isArray(manifest.vaultOperations) ? manifest.vaultOperations : []).filter((op) => op && op.manifest && op.manifest.stateBefore && REDEEM_BY_STATE_ID.has(op.manifest.stateBefore.stateId)).map((op) => [op.covenantId, REDEEM_BY_STATE_ID.get(op.manifest.stateBefore.stateId)]));

/* deep clone + re-hash: each row must exercise the SEMANTIC check, not merely
 * the hash check (which is asserted separately). */
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

const DESCRIPTORS = () => ({ [VAULT_COV_ID]: descriptor });

function verdictOf(manifest) {
  return verifyOrgRootIntentManifest({ manifest, descriptors: DESCRIPTORS(), redeemScripts: REDEEMS(manifest) });
}

/* ------------------------------------------------------------------ */
/* ARM 1 — every manifest-bearing ACCEPT shape verifies                 */
/* ------------------------------------------------------------------ */

/* Built ONCE and shared by every arm (each build runs the real compiler and
 * the real encoder). */
let SHAPES = null;
function shapes() {
  if (SHAPES) return SHAPES;
  const setAgentRoot = vaultBuild("ownerSetAgentRoot", { params: { agents: [{ ...agentPolicy, agentPk: H(0x71), recipients: [...rTree.recipients] }] } }); // rc26 round-7 R7-02 (STRICTER): the builder now requires the FULL new policy set; a bare root (newAgentRoot) alone is refused
  const topUp = vaultBuild("ownerTopUpReserve", { params: { topUpReserveAmountSompi: (KAS / 2n).toString() } });
  const pause = vaultBuild("ownerPause");
  const unpause = vaultBuild("ownerUnpause", { stateOver: { paused: "1" } });
  const emergency = vaultBuild("ownerEmergencyPause");
  const recoverWith = vaultBuild("ownerRecover", { chain: { tokenPosition: tokenPosition(300) } });
  const recoverWithout = vaultBuild("ownerRecover");
  const spend = vaultBuild("tokenAgentSpend", {
    params: {
      spendAmount: "200",
      agentPk: AGENT_PK,
      agents: [agentPolicy],
      recipient: RECIPIENT_PK,
      recipients: [...rTree.recipients],
      recipientCarryKasSompi: (KAS / 5n).toString(),
      reserveConsumedSompi: "50000"
    },
    chain: { tokenPosition: tokenPosition(300), root: undefined }
  });
  /* a PERIOD-ROLLOVER spend: the only shape whose lockTime is non-zero, and
   * therefore the only one on which a forged lockTime is meaningful */
  const spentLeaf = { ...agentPolicy, tokenPeriodSpent: "350" };
  const otherLeaf = { ...agentPolicy, agentPk: H(0x65) };
  const rolloverTree = buildTokenAgentTreeV5([spentLeaf, otherLeaf]);
  const rolloverSpend = buildV7Transaction({
    config,
    templateInput: vaultTemplate,
    stateInput: vaultState({ agentRoot: rolloverTree.root }),
    action: "tokenAgentSpend",
    params: {
      spendAmount: "200",
      agentPk: AGENT_PK,
      agents: [spentLeaf, otherLeaf],
      recipient: RECIPIENT_PK,
      recipients: [...rTree.recipients],
      recipientCarryKasSompi: (KAS / 5n).toString(),
      reserveConsumedSompi: "50000",
      periodsElapsed: "2"
    },
    chain: { predecessorOutpoint: { transactionId: H(0x0a), index: 0 }, covenantId: VAULT_COV_ID, predecessorValue: vaultState().feeReserve, fuel: { outpoint: { transactionId: H(0x03), index: 0 }, amount: (1n * KAS).toString(), scriptPublicKeyHex: `20${FUEL}ac` }, tokenPosition: tokenPosition(300) },
    changeXOnly: FUEL,
    descriptor
  });
  SHAPES = {
    root: {
      authorize: rootBuild("authorize"),
      rotate: rootBuild("rotate", { newOwnerSet: { owners: slots(NEW_OWNERS), ownerM: 3, emergencyK: 1, recoveryM: 2 } }),
      freeze: rootBuild("freeze"),
      unfreeze: rootBuild("unfreeze", {}, { frozen: 1 }),
      ownerRecover: rootBuild("ownerRecover", { newOwnerSet: { owners: slots(NEW_OWNERS.slice(0, 2)), ownerM: 2, emergencyK: 1, recoveryM: 1 } }),
      succession: rootBuild("succession", { newOwnerSet: { owners: slots([H(0x7f)]), ownerM: 1, emergencyK: 1, recoveryM: 0 } })
    },
    vault: { setAgentRoot, topUp, pause, unpause, emergency, recoverWith, recoverWithout },
    spend,
    rolloverSpend
  };
  return SHAPES;
}

test("I3c ARM 1: every manifest-bearing SDK ACCEPT shape produces a VERIFIED org-root manifest", { skip: SKIP }, () => {
  const s = shapes();
  const rows = [];
  for (const [name, build] of Object.entries(s.root)) {
    const satisfied = name === "freeze" ? 1 : name === "succession" ? 1 : 2;
    const v = verdictOf(orgManifest(build, [], satisfied));
    assert.equal(v.verdict, "VERIFIED", `root ${name}: ${JSON.stringify(v.failures)}`);
    rows.push(`root.${name}`);
  }
  for (const [name, build] of Object.entries(s.vault)) {
    const satisfied = name === "emergency" ? 1 : 2;
    const v = verdictOf(orgManifest(build, [{ build, descriptor }], satisfied));
    assert.equal(v.verdict, "VERIFIED", `vault ${name}: ${JSON.stringify(v.failures)}`);
    rows.push(`vault.${name}`);
  }
  assert.equal(rows.length, 13, "13 of the 19 I2 accept shapes carry an organizational-root manifest");

  /* The other SIX carry none, by construction — recorded so the gap is a
   * decision, not an oversight:
   *   root genesis / vault genesis  — a creation has no predecessor root to
   *                                   spend, so there is no root authority to
   *                                   describe;
   *   delegate spend x3, token deposit — the agent path and a user's own token
   *                                   deposit never touch the organizational
   *                                   root (the covenant refuses a root rider
   *                                   on the agent path), so an org-root
   *                                   manifest would be a false claim. */
  const s2 = shapes();
  assert.equal(s2.spend.hasRootInput, false, "a delegate spend has no root input at all");
  assert.throws(() => buildOrgRootIntentManifest({ build: s2.spend, vaultOperations: [{ build: s2.spend, descriptor }] }), /SCHEMA_INVALID|rooted-vault build without a root input/);
  assert.throws(() => routeIntentManifestVerifier("policyvault-0.7-payment"), /VERIFY_WITHIN_PARENT|verified inside/, "a rooted-vault manifest has no standalone verifier route (I2-D2)");
  console.log(`I3c ARM 1: ${rows.length} manifest-bearing accept shapes VERIFIED (${rows.join(", ")}); 6 accept shapes carry no org-root manifest by construction`);
});

/* ------------------------------------------------------------------ */
/* ARM 2 — the §4 adversarial FIELD CLASSES                             */
/* ------------------------------------------------------------------ */

test("rc21 review R6-02: a manifest that spends a token position is REFUSED when verified WITHOUT its descriptor (the browser's former mode) — fail closed, never skip", { skip: SKIP }, () => {
  const s = shapes();
  const recoverVault = orgManifest(s.vault.recoverWith, [{ build: s.vault.recoverWith, descriptor }]);
  const v = verifyOrgRootIntentManifest({ manifest: recoverVault, descriptors: {}, redeemScripts: REDEEMS(recoverVault) });
  assert.equal(v.verdict, "REFUSED");
  assert.ok(v.failures.some((f) => f.name === "vault[43434343].tokenDescriptorPresent"), v.failures.map((f) => f.name).join(","));
  assert.equal(verdictOf(recoverVault).verdict, "VERIFIED", "with the descriptor the honest manifest verifies");
});

test("I3c ARM 2: every §4 field class has a mutated sibling REFUSED before signing, with the check named", { skip: SKIP }, () => {
  const s = shapes();
  const authorize = orgManifest(s.root.authorize);
  const rotate = orgManifest(s.root.rotate);
  const recover = orgManifest(s.root.ownerRecover);
  const freeze = orgManifest(s.root.freeze, [], 1);
  const pause = orgManifest(s.vault.pause, [{ build: s.vault.pause, descriptor }]);
  const emergency = orgManifest(s.vault.emergency, [{ build: s.vault.emergency, descriptor }], 1);
  const recoverVault = orgManifest(s.vault.recoverWith, [{ build: s.vault.recoverWith, descriptor }]);

  const rows = [
    /* §4 duplicate owner key */
    ["duplicate owner key installed by a rotation", tamper(rotate, (m) => { m.rootState.after.state.owners[1] = m.rootState.after.state.owners[0]; }), "exception", /DUPLICATE_OWNER_KEY/],
    /* §4 oversized / malformed member set */
    ["an owner-set lockout (ownerM above the active count)", tamper(rotate, (m) => { m.rootState.after.state.ownerM = "9"; }), "exception", /M_ABOVE_ACTIVE/],
    /* §4 insufficient quorum */
    ["a quorum claimed satisfied below the requirement", tamper(authorize, (m) => { m.action.satisfiedApprovals = "1"; }), "quorumSatisfied"],
    /* §4 threshold-lowering attack */
    ["the threshold understated to make fewer signatures look sufficient", tamper(authorize, (m) => { m.action.requiredApprovals = "1"; }), "requiredApprovals"],
    /* §4 wrong owner / stale (removed) owner */
    ["a signer slot key swapped for a key the set does not hold", tamper(authorize, (m) => { m.action.expectedSignerSlots[1].publicKey = H(0xee); }), "expectedSignerSlots"],
    ["a signer slot hidden from the expected set", tamper(authorize, (m) => { m.action.expectedSignerSlots = m.action.expectedSignerSlots.slice(0, 2); }), "expectedSignerSlots"],
    /* §4 replay after nonce change / stale approval */
    ["the root nonce not advanced (a replay of the current state)", tamper(authorize, (m) => { m.rootState.after.state.rootNonce = m.rootState.before.state.rootNonce; }), "nonceAdvancesByOne"],
    ["the root nonce skipped ahead", tamper(authorize, (m) => { m.rootState.after.state.rootNonce = String(Number(m.rootState.before.state.rootNonce) + 2); }), "nonceAdvancesByOne"],
    /* §4 different action */
    ["the action relabelled to a lighter one", tamper(authorize, (m) => { m.action.name = "freeze"; m.action.code = 2; m.action.authorityClass = "AUTHORITY-REDUCING"; m.action.quorumSource = "emergencyK"; }), "frozenOutcome"],
    ["the authority class softened while the action stays", tamper(authorize, (m) => { m.action.authorityClass = "AUTHORITY-REDUCING"; }), "actionTable"],
    /* §4 malicious member rotation hidden inside a neutral action */
    ["a rotation disguised as an AUTHORIZE", tamper(authorize, (m) => { m.rootState.after.state.owners[0] = H(0x91); m.ownerSet.after.slots[0].publicKey = H(0x91); m.ownerSet.changes.added = [H(0x91)]; m.ownerSet.changes.removed = [OWNERS[0]]; }), "stateDigests"],
    ["an owner-set change hidden from the declared diff", tamper(rotate, (m) => { m.ownerSet.changes.added = []; }), "ownerSetDiff"],
    /* §4 different successor */
    ["the pinned successor TAIL bytes forged", tamper(authorize, (m) => { m.rootState.after.tailHex = "010008ff00000000000000"; }), "successorTailBytes"],
    ["a forged root state digest", tamper(authorize, (m) => { m.rootState.after.digest = H(0xdd); }), "stateDigests"],
    /* §4 cross-organization request confusion */
    ["the organization id rebound", tamper(authorize, (m) => { m.rootState.after.state.boundOrgId = H(0xb7); }), "stateDigests"],
    /* §4 fee manipulation */
    ["the network fee understated", tamper(authorize, (m) => { m.fee.requiredFeeSompi = "1"; }), "feeExact"],
    ["the root's value loss understated", tamper(authorize, (m) => { m.fee.rootValueLoss = "999"; }), "rootValueRule"],
    /* §4 value leakage: the root really loses more than its per-transition cap */
    ["the root drained past rootMaxFeePerTx in the frozen transaction", tamper(authorize, (m) => {
      editFrozen(m, (f) => {
        const out = f.outputs.find((o) => o.covenant && o.covenant.covenantId === ROOT_ID);
        out.value = (BigInt(out.value) - 1000000n).toString();
      });
    }), "rootValueAfter"],
    /* §4 input mutation: the root outpoint substituted */
    ["the root outpoint substituted (the freshness kill switch moved)", tamper(authorize, (m) => { m.root.outpoint = { transactionId: H(0x0e), index: 0 }; m.freshness.rootOutpoint = { transactionId: H(0x0e), index: 0 }; }), "rootOutpointBinding"],
    /* §4 relative-age gate (the dead-man's switch) */
    ["the recovery idle delay understated on the input sequence", tamper(recover, (m) => { m.action.minSequence = "1"; }), "relativeAgeGate"],
    /* §4 emergency path abuse — the two halves made to disagree */
    ["a full-quorum vault selector riding the EMERGENCY quorum's root path", tamper(emergency, (m) => {
      m.vaultOperations[0].sdkAction = "ownerPause";
      m.vaultOperations[0].opSelector = 2;
      m.vaultOperations[0].manifest.action.sdkAction = "ownerPause";
      m.vaultOperations[0].manifest.action.opSelector = 2;
      m.vaultOperations[0].manifest.action.requiredRootAction = "authorize";
      m.vaultOperations[0].manifest.action.expectFrozenAfter = "0";
      rehashVaultOp(m);
    }), "vaultOp[43434343]rootPathAgreesWithThisManifest"],
    ["the EMERGENCY selector riding a full-quorum AUTHORIZE root", tamper(pause, (m) => {
      m.vaultOperations[0].sdkAction = "ownerEmergencyPause";
      m.vaultOperations[0].manifest.action.sdkAction = "ownerEmergencyPause";
      m.vaultOperations[0].manifest.action.requiredRootAction = "freeze";
      m.vaultOperations[0].manifest.action.expectFrozenAfter = "1";
      rehashVaultOp(m);
    }), "vaultOp[43434343]rootPathAgreesWithThisManifest"],
    /* rc20 review R5-01: the OUTER vault-op declaration is bound to the INNER manifest; a root action never creates a covenant */
    ["the outer tokenCovenantId declared as a FOREIGN family (inner manifest untouched)", tamper(pause, (m) => { m.vaultOperations[0].tokenCovenantId = ALIEN_ID; }), "vaultOp[43434343]idsBound"],
    ["the outer covenantId declared as a FOREIGN family (inner manifest untouched)", tamper(pause, (m) => { m.vaultOperations[0].covenantId = ALIEN_ID; }), `vaultOp[${ALIEN_ID.slice(0, 8)}]idsBound`],
    ["a genesis-shaped covenant output (its authorizing input carries no covenant) tagged with the vault family", tamper(pause, (m) => {
      const f = JSON.parse(m.transaction.frozenCanonicalJson);
      const fuel = f.inputs.length - 1;
      f.outputs.push({ value: "1000", scriptPublicKey: { version: 0, scriptHex: `aa20${H(0x0d)}87` }, covenant: { authorizingInput: fuel, covenantId: m.vaultOperations[0].covenantId } });
      m.transaction.frozenCanonicalJson = JSON.stringify(f);
    }), "noCovenantGenesisInRootAction"],
    /* rc20 review R5-04: the root continuation SCRIPT is rebuilt from the reviewed template + state */
    ["the root continuation script substituted (covenant metadata kept)", tamper(authorize, (m) => {
      const f = JSON.parse(m.transaction.frozenCanonicalJson);
      const i = f.outputs.findIndex((o) => o.covenant && o.covenant.covenantId === m.root.covenantId);
      f.outputs[i].scriptPublicKey = { version: 0, scriptHex: `aa20${H(0x0d)}87` };
      m.transaction.frozenCanonicalJson = JSON.stringify(f);
    }), "rootScriptsBound"],
    ["the root input script not the reviewed predecessor's", tamper(authorize, (m) => {
      const f = JSON.parse(m.transaction.frozenCanonicalJson);
      const i = f.inputs.findIndex((x) => x.utxo.covenantId === m.root.covenantId);
      f.inputs[i].utxo.scriptPublicKey = { version: 0, scriptHex: `aa20${H(0x0d)}87` };
      m.transaction.frozenCanonicalJson = JSON.stringify(f);
    }), "rootScriptsBound"],
    ["a terminal recover that still continues its own vault covenant", tamper(recoverVault, (m) => {
      const f = JSON.parse(m.transaction.frozenCanonicalJson);
      const vi = f.inputs.findIndex((x) => x.utxo.covenantId === m.vaultOperations[0].covenantId);
      f.outputs.push({ value: "1000", scriptPublicKey: { version: 0, scriptHex: `aa20${H(0x0d)}87` }, covenant: { authorizingInput: vi, covenantId: m.vaultOperations[0].covenantId } });
      m.transaction.frozenCanonicalJson = JSON.stringify(f);
    }), "vault[43434343].terminalNoContinuation"],
    /* rc21 review R6-01 / R6-02 / R6-04 / R6-06 */
    ["the token continuation of a terminal recover carrying the fee payer's change (token KAS +1000, change −1000)", tamper(recoverVault, (m) => {
      const f = JSON.parse(m.transaction.frozenCanonicalJson);
      const ti = f.outputs.findIndex((o) => o.covenant && o.covenant.covenantId === m.vaultOperations[0].tokenCovenantId);
      const ci = f.outputs.length - 1;
      f.outputs[ti].value = (BigInt(f.outputs[ti].value) + 1000n).toString(); f.outputs[ci].value = (BigInt(f.outputs[ci].value) - 1000n).toString();
      m.transaction.frozenCanonicalJson = JSON.stringify(f);
    }), "vault[43434343].tokenCarryPreserved"],
    ["the revealed token redeem script omitted from a manifest that spends a token position", tamper(recoverVault, (m) => { m.vaultOperations[0].manifest.tokenSignatureScriptHex = null; rehashVaultOp(m); }), "vault[43434343].tokenSignaturePresent"],
    ["the succession flag misreported (successor pinned, flag false)", tamper(authorize, (m) => { m.root.template.successionEnabled = false; }), "successionFlag"],
    ["the fee payer's change redirected to the vault's pinned recovery key as a second payout", tamper(recoverVault, (m) => {
      const f = JSON.parse(m.transaction.frozenCanonicalJson);
      f.outputs[f.outputs.length - 1].scriptPublicKey = { version: 0, scriptHex: `20${m.vaultOperations[0].manifest.vault.recoveryPk}ac` };
      m.transaction.frozenCanonicalJson = JSON.stringify(f);
    }), "feePayerChangeBound"],
    ["a bare P2SH output (no covenant metadata) carrying the change", tamper(authorize, (m) => {
      const f = JSON.parse(m.transaction.frozenCanonicalJson);
      f.outputs[f.outputs.length - 1].scriptPublicKey = { version: 0, scriptHex: `aa20${H(0x0d)}87` };
      m.transaction.frozenCanonicalJson = JSON.stringify(f);
    }), "feePayerChangeBound"],
    /* §4 hosted-admin impersonation / delegate pretending to be owner */
    ["a vault owner operation claiming it needs no root authority at all", tamper(pause, (m) => {
      m.vaultOperations[0].manifest.action.requiresRootInput = false;
      rehashVaultOp(m);
    }), "vault[43434343].rootAuthorityPresent"],
    /* §4 cross-organization: a vault of another organization riding this root */
    ["a vault pinned to a FOREIGN organizational root", tamper(pause, (m) => {
      m.vaultOperations[0].manifest.vault.orgRootCovenantId = ALIEN_ID;
      rehashVaultOp(m);
    }), "vaultOp[43434343]rootPin"],
    /* §4 malicious recovery redirect */
    ["the vault recovery destination redirected away from the genesis pin", tamper(recoverVault, (m) => {
      editFrozen(m, (f) => {
        f.outputs[0].scriptPublicKey.scriptHex = `20${H(0x6f)}ac`;
      });
    }), "vault[43434343].payoutToPinnedRecoveryPk"],
    /* §4 terminal-vault mutation */
    ["a terminal vault operation relabelled as non-terminal", tamper(recoverVault, (m) => {
      m.vaultOperations[0].terminal = false;
      m.vaultOperations[0].manifest.action.terminal = false;
      rehashVaultOp(m);
    }), "vault[43434343].action"],
    /* §4 hidden covenant input / hidden output */
    ["a hidden extra covenant family among the inputs", tamper(pause, (m) => {
      editFrozen(m, (f) => {
        f.inputs.push({ ...f.inputs[0], previousOutpoint: { transactionId: H(0x0c), index: 0 }, utxo: { ...f.inputs[0].utxo, covenantId: ALIEN_ID } });
      });
      m.fee.requiredFeeSompi = (BigInt(m.fee.requiredFeeSompi) + BigInt(JSON.parse(m.transaction.frozenCanonicalJson).inputs[0].utxo.amount)).toString();
    }), "noHiddenCovenantOperations"],
    /* §4 covenant/template substitution */
    ["the vault's pinned ROOT TEMPLATE geometry substituted", tamper(pause, (m) => {
      m.vaultOperations[0].manifest.vault.rootGeometry.stateLen = 466;
      rehashVaultOp(m);
    }), "vault[43434343].templatePins"],
    /* §4 migration downgrade / unknown version */
    ["an unknown manifest version", { ...authorize, manifestVersion: "policyvault-org-root-manifest/2" }, "exception"],
    /* a bare hash edit (the hash check itself) */
    ["a bare hash edit with no re-hash", { ...authorize, manifestHash: H(0xee) }, "manifestHash"]
  ];

  for (const [label, bad, expectedCheck, detailRe] of rows) {
    const v = verdictOf(bad);
    assert.equal(v.verdict, "REFUSED", `${label}: must be REFUSED`);
    const hit = v.failures.find((f) => f.name === expectedCheck);
    assert.ok(hit, `${label}: expected the failing check ${expectedCheck}, got [${v.failures.map((f) => f.name).join(", ")}]`);
    if (detailRe) assert.match(String(hit.detail), detailRe, `${label}: the refusal must name the rule it broke`);
    assert.equal(v.statement, null, `${label}: a refused manifest never carries the verified statement`);
  }
  console.log(`I3c ARM 2: ${rows.length} §4 field-class rows refused with the failing check named`);
  assert.ok(rows.length >= 28, "the §4 matrix must stay comprehensive");
});

/* ------------------------------------------------------------------ */
/* ARM 3 — the 20 production-byte REJECT vectors, at the core boundary  */
/* ------------------------------------------------------------------ */

test("I3c ARM 3: every production-byte REJECT vector is ALSO refused inside the core; findings list must be EMPTY", { skip: SKIP }, () => {
  const s = shapes();
  const findings = [];
  const attributed = [];

  /* helper: a manifest-level row */
  function manifestRow(vector, manifest, mutate, expectedCheck) {
    const bad = tamper(manifest, mutate);
    const v = verdictOf(bad);
    if (v.verdict !== "REFUSED") {
      findings.push({ vector, layer: "MANIFEST", detail: "the core ACCEPTED a shape consensus refuses" });
      return;
    }
    if (!v.failures.some((f) => f.name === expectedCheck)) {
      findings.push({ vector, layer: "MANIFEST", detail: `refused, but not by ${expectedCheck}: [${v.failures.map((f) => f.name).join(", ")}]` });
      return;
    }
    attributed.push({ vector, layer: "MANIFEST", check: expectedCheck });
  }

  /* helper: a row the FINALIZER owns (signature material — outside a
   * pre-signature manifest's domain by construction) */
  function finalizerRow(vector, fn, expectedCode) {
    let code = null;
    try {
      fn();
    } catch (e) {
      code = e.code ?? null;
    }
    if (code !== expectedCode) {
      findings.push({ vector, layer: "FINALIZER", detail: `expected ${expectedCode}, got ${code}` });
      return;
    }
    attributed.push({ vector, layer: "FINALIZER", check: expectedCode });
  }

  /* helper: a row the SDK BUILDER refuses outright */
  function builderRow(vector, fn, expectedCode) {
    let code = null;
    try {
      fn();
    } catch (e) {
      code = e.code ?? null;
    }
    if (code !== expectedCode) {
      findings.push({ vector, layer: "BUILDER", detail: `expected ${expectedCode}, got ${code}` });
      return;
    }
    attributed.push({ vector, layer: "BUILDER", check: expectedCode });
  }

  /* helper: a row the ROOTED-VAULT half-verifier owns (the delegate path has
   * no organizational-root manifest; these are the checks a parent runs) */
  function vaultHalfRow(vector, build, mutate, expectedCheck) {
    const m = JSON.parse(JSON.stringify(buildRootedVaultManifestV7({ build, descriptor })));
    const frozen = JSON.parse(build.frozenCanonicalJson);
    mutate(m, frozen);
    const { manifestHash, ...body } = m;
    void manifestHash;
    const rehashed = { ...body, manifestHash: computeManifestHashV1(body) };
    const failures = [];
    const check = (name, ok, detail) => {
      if (!ok) failures.push({ name, detail });
    };
    try {
      verifyRootedVaultManifestV7({ manifest: rehashed, frozen, descriptor, redeemHex: build.vaultRedeemScriptHex, check });
    } catch (e) {
      failures.push({ name: "exception", detail: e.message });
    }
    if (failures.length === 0) {
      findings.push({ vector, layer: "VAULT_HALF", detail: "the core's vault-half verifier ACCEPTED a shape consensus refuses" });
      return;
    }
    if (!failures.some((f) => f.name.endsWith(expectedCheck))) {
      findings.push({ vector, layer: "VAULT_HALF", detail: `refused, but not by ${expectedCheck}: [${failures.map((f) => f.name).join(", ")}]` });
      return;
    }
    attributed.push({ vector, layer: "VAULT_HALF", check: expectedCheck });
  }

  const authorize = orgManifest(s.root.authorize);
  const pause = orgManifest(s.vault.pause, [{ build: s.vault.pause, descriptor }]);
  const emergency = orgManifest(s.vault.emergency, [{ build: s.vault.emergency, descriptor }], 1);
  const recoverVault = orgManifest(s.vault.recoverWith, [{ build: s.vault.recoverWith, descriptor }]);
  const sig = (b) => b.toString(16).padStart(2, "0").repeat(64) + "01";
  const finalize = (approvals) => assembleOwnerSigsBlobV7({ ownerSet, actionName: "authorize", approvals });

  /* ---- 1-4: SIGNATURE MATERIAL — outside a pre-signature manifest ---- */
  finalizerRow("neg_root_under_quorum", () => finalize([{ slot: 1, signatureHex: sig(0x11) }]), "UNDER_QUORUM");
  finalizerRow("neg_root_duplicate_slot", () => finalize([{ slot: 1, signatureHex: sig(0x11) }, { slot: 2, signatureHex: sig(0x11) }]), "SIGNATURE_REUSED");
  finalizerRow("neg_root_outsider_slot", () => finalize([{ slot: 1, signatureHex: sig(0x11) }, { publicKey: H(0x6f), signatureHex: sig(0x22) }]), "OWNER_NOT_IN_SET");
  finalizerRow("neg_root_forged_gate_byte", () => finalize([{ slot: 1, signatureHex: `${sig(0x11).slice(0, -2)}02` }, { slot: 2, signatureHex: sig(0x22) }]), "SIGHASH_NOT_ALL");

  /* ---- 5-8: ROOT STATE / VALUE — manifest-visible ---- */
  manifestRow("neg_root_value_drained", authorize, (m) => {
    editFrozen(m, (f) => {
      const out = f.outputs.find((o) => o.covenant && o.covenant.covenantId === ROOT_ID);
      out.value = (BigInt(out.value) - 1000000n).toString();
    });
  }, "rootValueAfter");
  manifestRow("neg_root_nonce_skipped", authorize, (m) => { m.rootState.after.state.rootNonce = "2"; }, "nonceAdvancesByOne");
  manifestRow("neg_root_nonce_unchanged", authorize, (m) => { m.rootState.after.state.rootNonce = "0"; }, "nonceAdvancesByOne");
  manifestRow("neg_root_authorize_swaps_the_owner_set", authorize, (m) => { m.rootState.after.state.owners[0] = H(0x91); }, "stateDigests");

  /* ---- 9: a succession signed by the wrong key — signature material.
   * The slot path refuses to issue ANY owner-slot request for a succession,
   * and the finalizer refuses owner approvals on that path; the key check
   * itself is the covenant's checkSig. ---- */
  /*
   * ---- 9: a succession signed by the WRONG KEY.
   * The key check is the covenant's own `checkSig` against the genesis-pinned
   * successorPk. A 65-byte signature under the wrong key is indistinguishable
   * from the right one without VERIFYING it, and portable core holds no
   * verifier — so this vector is attributed to CONSENSUS. The attribution is
   * not a hole: the three adjacent core guards that keep the succession path
   * from being fed owner material are asserted here, so nothing else can slip
   * through the same door.
   */
  {
    const guards = [];
    try {
      finalizeV7RootTransaction({ build: s.root.succession, approvals: [{ slot: 1, signatureHex: sig(0x11) }], successorSignatureHex: sig(0x22), fuelSignatureScriptHex: "00".repeat(66) });
    } catch (e) {
      guards.push(e.code);
    }
    try {
      require("../../core/signer/org-root-slot-v7").createRootSlotSigningRequest({
        manifest: orgManifest(s.root.succession, [], 1),
        slot: 1,
        expectedSignerAddress: "kaspatest:orgowner1",
        unsignedSafeJson: s.root.succession.frozenCanonicalJson,
        rootInputIndex: 0,
        expiresAtMs: Date.now() + 60000
      });
      guards.push(null);
    } catch (e) {
      guards.push(e.details ? e.details.reason : null);
    }
    const claimsSlots = tamper(orgManifest(s.root.succession, [], 1), (m) => {
      m.action.expectedSignerSlots = [{ slot: 1, publicKey: OWNERS[0] }];
    });
    guards.push(verdictOf(claimsSlots).failures.some((f) => f.name === "expectedSignerSlots") ? "expectedSignerSlots" : null);

    const expected = ["SUCCESSION_TAKES_NO_APPROVALS", "SUCCESSION_TAKES_NO_SLOTS", "expectedSignerSlots"];
    if (JSON.stringify(guards) !== JSON.stringify(expected)) {
      findings.push({ vector: "neg_root_succession_wrong_key", layer: "CONSENSUS", detail: `adjacent core guards ${JSON.stringify(guards)} != ${JSON.stringify(expected)}` });
    } else {
      attributed.push({ vector: "neg_root_succession_wrong_key", layer: "CONSENSUS", check: "covenant checkSig(successorSig, successorPk); core guards: " + expected.join("+") });
    }
  }

  /* ---- 10-14: ROOTED-VAULT AUTHORITY — manifest-visible ---- */
  manifestRow("neg_vault_selector2_under_freeze_root", emergency, (m) => {
    m.vaultOperations[0].sdkAction = "ownerPause";
    m.vaultOperations[0].opSelector = 2;
    m.vaultOperations[0].manifest.action.sdkAction = "ownerPause";
    m.vaultOperations[0].manifest.action.opSelector = 2;
    m.vaultOperations[0].manifest.action.requiredRootAction = "authorize";
    m.vaultOperations[0].manifest.action.expectFrozenAfter = "0";
    rehashVaultOp(m);
  }, "vaultOp[43434343]rootPathAgreesWithThisManifest");
  manifestRow("neg_vault_selector4_under_authorize_root", pause, (m) => {
    m.vaultOperations[0].sdkAction = "ownerEmergencyPause";
    m.vaultOperations[0].manifest.action.sdkAction = "ownerEmergencyPause";
    m.vaultOperations[0].manifest.action.requiredRootAction = "freeze";
    m.vaultOperations[0].manifest.action.expectFrozenAfter = "1";
    rehashVaultOp(m);
  }, "vaultOp[43434343]rootPathAgreesWithThisManifest");
  manifestRow("neg_vault_root_successor_head_changed", pause, (m) => { m.rootState.after.state.owners[0] = H(0x91); }, "stateDigests");
  manifestRow("neg_vault_alien_covenant_rider", pause, (m) => {
    editFrozen(m, (f) => {
      f.inputs.push({ ...f.inputs[0], previousOutpoint: { transactionId: H(0x0c), index: 0 }, utxo: { ...f.inputs[0].utxo, covenantId: ALIEN_ID } });
    });
    m.fee.requiredFeeSompi = (BigInt(m.fee.requiredFeeSompi) + BigInt(JSON.parse(m.transaction.frozenCanonicalJson).inputs[0].utxo.amount)).toString();
  }, "noHiddenCovenantOperations");
  manifestRow("neg_vault_recover_wrong_destination", recoverVault, (m) => {
    editFrozen(m, (f) => {
      f.outputs[0].scriptPublicKey.scriptHex = `20${H(0x6f)}ac`;
    });
  }, "vault[43434343].payoutToPinnedRecoveryPk");

  /* ---- 15-20: THE DELEGATE PATH. It carries NO organizational-root manifest
   * (its authority is the agent key, and the covenant refuses a root rider),
   * so the core layer that owns these is the ROOTED-VAULT half verifier — the
   * exact checks a parent manifest runs — plus the SDK builder for the shape
   * it refuses to build at all. ---- */
  vaultHalfRow("neg_delegate_spend_wrong_signer", s.spend, (m) => { m.policy.agentPolicy.agentPk = H(0x6f); }, "agentProof");
  vaultHalfRow("neg_delegate_successor_drained", s.spend, (m, f) => {
    const succ = f.outputs.find((o) => o.covenant && o.covenant.covenantId === VAULT_COV_ID);
    succ.value = (BigInt(succ.value) - 1000000n).toString();
  }, "successorOutput");
  vaultHalfRow("neg_delegate_token_family_swapped", s.spend, (m, f) => {
    f.inputs.find((i) => i.utxo.covenantId === TOKEN_FAMILY).utxo.covenantId = ALIEN_ID;
    for (const o of f.outputs) if (o.covenant && o.covenant.covenantId === TOKEN_FAMILY) o.covenant.covenantId = ALIEN_ID;
  }, "familyShape");
  vaultHalfRow("neg_delegate_recipient_carry_over_cap", s.spend, (m, f) => {
    const tokenOuts = f.outputs.filter((o) => o.covenant && o.covenant.covenantId === TOKEN_FAMILY);
    tokenOuts[1].value = (BigInt(agentPolicy.agentMaxCarryKas) + 1n).toString();
  }, "carryWithinAgentCap");
  builderRow(
    "neg_delegate_root_rider",
    () =>
      buildV7Transaction({
        config,
        templateInput: vaultTemplate,
        stateInput: vaultState(),
        action: "tokenAgentSpend",
        params: { spendAmount: "200", agentPk: AGENT_PK, agents: [agentPolicy], recipient: RECIPIENT_PK, recipients: [...rTree.recipients], recipientCarryKasSompi: (KAS / 5n).toString(), reserveConsumedSompi: "50000" },
        chain: vaultChain({ tokenPosition: tokenPosition(300) }),
        changeXOnly: FUEL,
        descriptor
      }),
    "AGENT_PATH_TAKES_NO_ROOT"
  );
  vaultHalfRow("neg_delegate_locktime_forged", s.rolloverSpend, (m, f) => { f.lockTime = "9000"; }, "lockTimeBound");

  /* ---- the verdict ---- */
  for (const f of findings) console.log(`I3c FINDING: ${f.vector} [${f.layer}] ${f.detail}`);
  const byLayer = attributed.reduce((acc, a) => {
    acc[a.layer] = (acc[a.layer] || 0) + 1;
    return acc;
  }, {});
  console.log(`I3c ARM 3: ${attributed.length}/20 reject vectors attributed inside the core — ${JSON.stringify(byLayer)}; findings: ${findings.length}`);
  assert.deepEqual(findings, [], "a vector the core accepts but consensus refuses (or vice versa) is a FINDING and must be recorded, not passed");
  assert.equal(attributed.length, 20, "every one of the 20 production-byte reject vectors must be attributed to a core layer");
});

test("I3c: the abstention placeholder can never be offered as an approval, at any layer", { skip: SKIP }, () => {
  assert.throws(
    () => assembleOwnerSigsBlobV7({ ownerSet, actionName: "authorize", approvals: [{ slot: 1, signatureHex: PLACEHOLDER_SLOT_HEX_V7 }, { slot: 2, signatureHex: "aa".repeat(64) + "01" }] }),
    /PLACEHOLDER_AS_SIGNATURE|placeholder/
  );
});

/* ------------------------------------------------------------------ */
/* Codex checkpoint 6 (UX-02 / UX-13) — DERIVED budgets + rebuilt VAULT   */
/* successor script, on REAL builds (frozen bytes + manifest re-hashed)   */
/* ------------------------------------------------------------------ */
test("Codex checkpoint 6 (UX-02 / UX-13): consistent compute-budget substitutions (root / vault / token / fee input, declared budget moved too) and a substituted or withheld vault successor script / predecessor redeem are REFUSED by the shared verifier with the check named; the honest builds verify", { skip: SKIP }, () => {
  const s = shapes();
  const authorize = orgManifest(s.root.authorize);
  const succession = orgManifest(s.root.succession, [], 1);
  const pause = orgManifest(s.vault.pause, [{ build: s.vault.pause, descriptor }]);
  const emergency = orgManifest(s.vault.emergency, [{ build: s.vault.emergency, descriptor }], 1);
  const recoverVault = orgManifest(s.vault.recoverWith, [{ build: s.vault.recoverWith, descriptor }]);
  for (const [name, m] of [["authorize", authorize], ["succession", succession], ["pause", pause], ["emergency", emergency], ["recoverWith", recoverVault]]) {
    const v = verdictOf(m);
    assert.equal(v.verdict, "VERIFIED", `${name}: honest control — ${JSON.stringify(v.failures)}`);
    assert.ok(v.checks.some((c) => c.name === "rootComputeBudgetBound" && c.ok), `${name}: the root budget is derived and bound`);
    assert.ok(v.checks.some((c) => c.name === "ordinaryInputBudgets" && c.ok), `${name}: the fee input's ordinary budget is bound`);
  }
  for (const name of ["pause", "emergency"]) {
    const v = verdictOf({ pause, emergency }[name]);
    for (const c of ["vaultComputeBudgetBound", "vaultRedeemPresent", "vaultRedeemMatchesUtxo", "vaultRedeemStateAgrees", "successorScriptReconstructed"]) assert.ok(v.checks.some((x) => x.name.endsWith(c) && x.ok), `${name}: ${c} holds on the honest build`);
  }
  {
    const v = verdictOf(recoverVault);
    assert.ok(v.checks.some((x) => x.name.endsWith("tokenInputBudgetBound") && x.ok), "recoverWith: the token input's budget is derived and bound");
    assert.ok(v.checks.some((x) => x.name.endsWith("vaultRedeemMatchesUtxo") && x.ok), "recoverWith: a carried redeem is still bound on a terminal op");
  }
  const rootIdxOf = (m) => JSON.parse(m.transaction.frozenCanonicalJson).inputs.findIndex((i) => i.utxo.covenantId === m.root.covenantId);
  const vaultIdxOf = (m) => JSON.parse(m.transaction.frozenCanonicalJson).inputs.findIndex((i) => i.utxo.covenantId === m.vaultOperations[0].covenantId);
  const tokenIdxOf = (m) => JSON.parse(m.transaction.frozenCanonicalJson).inputs.findIndex((i) => i.utxo.covenantId === m.vaultOperations[0].tokenCovenantId);
  const fuelIdxOf = (m) => JSON.parse(m.transaction.frozenCanonicalJson).inputs.length - 1;
  const rehashOp = (m) => { const { manifestHash, ...b } = m.vaultOperations[0].manifest; void manifestHash; m.vaultOperations[0].manifest = { ...b, manifestHash: computeManifestHashV1(b) }; };
  const rows = [
    ["root input budget 42 -> 0 (declared moved)", tamper(authorize, (m) => { editFrozen(m, (f) => { f.inputs[rootIdxOf(authorize)].computeBudget = 0; }); m.root.computeBudget = 0; }), "rootComputeBudgetBound"],
    ["root input budget 42 -> 41 (one below the derivation)", tamper(authorize, (m) => { editFrozen(m, (f) => { f.inputs[rootIdxOf(authorize)].computeBudget = 41; }); m.root.computeBudget = 41; }), "rootComputeBudgetBound"],
    ["root input budget 42 -> 100 (above; fee/mass would differ)", tamper(authorize, (m) => { editFrozen(m, (f) => { f.inputs[rootIdxOf(authorize)].computeBudget = 100; }); m.root.computeBudget = 100; }), "rootComputeBudgetBound"],
    ["declared root budget disagrees with the frozen input (frozen untouched)", tamper(authorize, (m) => { m.root.computeBudget = 43; }), "rootComputeBudgetBound"],
    ["fee input budget 10 -> 0", tamper(authorize, (m) => { editFrozen(m, (f) => { f.inputs[fuelIdxOf(authorize)].computeBudget = 0; }); }), "ordinaryInputBudgets"],
    ["succession input budget 20 -> 0 (declared moved)", tamper(succession, (m) => { editFrozen(m, (f) => { f.inputs[rootIdxOf(succession)].computeBudget = 0; }); m.root.computeBudget = 0; }), "rootComputeBudgetBound"],
    ["vault input budget 32 -> 0 (declared moved, op re-hashed)", tamper(pause, (m) => { editFrozen(m, (f) => { f.inputs[vaultIdxOf(pause)].computeBudget = 0; }); m.vaultOperations[0].manifest.transaction.computeBudget = 0; rehashOp(m); }), "vaultComputeBudgetBound"],
    ["vault input budget 32 -> 33 (declared moved, op re-hashed)", tamper(emergency, (m) => { editFrozen(m, (f) => { f.inputs[vaultIdxOf(emergency)].computeBudget = 33; }); m.vaultOperations[0].manifest.transaction.computeBudget = 33; rehashOp(m); }), "vaultComputeBudgetBound"],
    ["root input budget 42 -> 0 inside a vault operation", tamper(pause, (m) => { editFrozen(m, (f) => { f.inputs[rootIdxOf(pause)].computeBudget = 0; }); m.root.computeBudget = 0; }), "rootComputeBudgetBound"],
    ["token input budget 6 -> 0", tamper(recoverVault, (m) => { editFrozen(m, (f) => { f.inputs[tokenIdxOf(recoverVault)].computeBudget = 0; }); }), "tokenInputBudgetBound"],
    ["vault SUCCESSOR P2SH replaced (covenant metadata preserved) — the rc20 review R5-04 pre-sign gap", tamper(pause, (m) => { editFrozen(m, (f) => { const i = f.outputs.findIndex((o) => o.covenant && o.covenant.covenantId === pause.vaultOperations[0].covenantId); f.outputs[i].scriptPublicKey = { version: 0, scriptHex: `aa20${H(0x5c)}87` }; }); }), "successorScriptReconstructed"],
    ["vault successor script of the PREDECESSOR state (the pause not applied) under the same template", tamper(emergency, (m) => { editFrozen(m, (f) => { const op = emergency.vaultOperations[0]; const i = f.outputs.findIndex((o) => o.covenant && o.covenant.covenantId === op.covenantId); f.outputs[i].scriptPublicKey = { version: 0, scriptHex: require("../../core/intent/vault-script-v7").reconstructVaultSuccessorSpkHexV7({ redeemHex: REDEEMS(emergency)[op.covenantId], vaultId: op.manifest.vault.vaultId, state: op.manifest.stateBefore.state }) }; }); }), "successorScriptReconstructed"]
  ];
  for (const [label, m, expected] of rows) {
    const v = verdictOf(m);
    assert.equal(v.verdict, "REFUSED", `${label}: must be refused`);
    assert.ok(v.failures.some((f) => f.name.endsWith(expected)), `${label}: expected ${expected} among [${v.failures.map((f) => f.name).join(", ")}]`);
  }
  /* the carried redeem: withheld (non-terminal => fail closed), substituted (P2SH no longer the vault input's), another vault's template */
  const withheld = verifyOrgRootIntentManifest({ manifest: pause, descriptors: DESCRIPTORS(), redeemScripts: {} });
  assert.equal(withheld.verdict, "REFUSED"); assert.ok(withheld.failures.some((f) => f.name.endsWith("vaultRedeemPresent")), "withheld redeem on a continuation => vaultRedeemPresent");
  const real = REDEEMS(pause)[pause.vaultOperations[0].covenantId];
  const flipped = real.slice(0, -2) + (real.slice(-2) === "00" ? "01" : "00");
  const substituted = verifyOrgRootIntentManifest({ manifest: pause, descriptors: DESCRIPTORS(), redeemScripts: { [pause.vaultOperations[0].covenantId]: flipped } });
  assert.equal(substituted.verdict, "REFUSED"); assert.ok(substituted.failures.some((f) => f.name.endsWith("vaultRedeemMatchesUtxo")), "a substituted redeem is not the vault input's script");
  const otherVault = buildV7Transaction({ config, templateInput: { ...vaultTemplate, recoveryPk: H(0x99) }, stateInput: vaultState(), action: "ownerPause", chain: vaultChain(), changeXOnly: FUEL, descriptor });
  const foreignTemplate = verifyOrgRootIntentManifest({ manifest: pause, descriptors: DESCRIPTORS(), redeemScripts: { [pause.vaultOperations[0].covenantId]: otherVault.vaultRedeemScriptHex } });
  assert.equal(foreignTemplate.verdict, "REFUSED"); assert.ok(foreignTemplate.failures.some((f) => f.name.endsWith("vaultRedeemMatchesUtxo")), "another vault's template never binds this vault's input");
  const terminalForeign = verifyOrgRootIntentManifest({ manifest: recoverVault, descriptors: DESCRIPTORS(), redeemScripts: { [recoverVault.vaultOperations[0].covenantId]: otherVault.vaultRedeemScriptHex } });
  assert.equal(terminalForeign.verdict, "REFUSED"); assert.ok(terminalForeign.failures.some((f) => f.name.endsWith("vaultRedeemMatchesUtxo")), "a foreign redeem riding a terminal op is refused too");
});

test("Codex checkpoint 7 (UX-02 / UX-13): the declared template pins and the predecessor state are BOUND to the spent vault — root/token geometry, recovery key, template hashes and the terminal predecessor state substituted CONSISTENTLY (budgets re-derived from the substituted geometry, payouts redirected, manifests re-hashed, predecessor inputs and redeems unchanged) are REFUSED with the check named; a terminal op without its redeem is refused; the root pins must agree with the rebuilt root script; the honest builds verify with every new check ok", { skip: SKIP }, () => {
  const s = shapes();
  const V = require("../../core/intent/vault-script-v7");
  const { selectComputeBudgetV7, selectTokenInputBudgetV7 } = require("../../core/model/compute-budget-v7");
  const pause = orgManifest(s.vault.pause, [{ build: s.vault.pause, descriptor }]);
  const emergency = orgManifest(s.vault.emergency, [{ build: s.vault.emergency, descriptor }], 1);
  const recoverVault = orgManifest(s.vault.recoverWith, [{ build: s.vault.recoverWith, descriptor }]);
  const recoverBare = orgManifest(s.vault.recoverWithout, [{ build: s.vault.recoverWithout, descriptor }]);
  for (const [name, m, expectOk] of [["pause", pause, ["templatePinsBound", "successorScriptFromPins", "rootEvidenceAgrees", "vaultRedeemStateAgrees"]], ["emergency", emergency, ["templatePinsBound", "successorScriptFromPins", "rootEvidenceAgrees"]], ["recoverWith", recoverVault, ["templatePinsBound", "rootEvidenceAgrees", "tokenTemplateBound", "vaultRedeemStateAgrees", "vaultRedeemPresent"]], ["recoverWithout", recoverBare, ["templatePinsBound", "rootEvidenceAgrees", "vaultRedeemStateAgrees"]]]) {
    const v = verdictOf(m);
    assert.equal(v.verdict, "VERIFIED", `${name}: honest control — ${JSON.stringify(v.failures)}`);
    for (const c of expectOk) assert.ok(v.checks.some((x) => x.name.endsWith(c) && x.ok), `${name}: ${c} holds on the honest build`);
    /* the skeleton rebuilds the real predecessor redeem from the manifest's declared pins */
    const op = m.vaultOperations[0];
    assert.equal(V.reconstructVaultScriptHexV7({ template: V.templatePinsFromManifestVault(op.manifest.vault), state: op.manifest.stateBefore.state }), REDEEMS(m)[op.covenantId], `${name}: skeleton(declared pins, stateBefore) == the SDK-captured redeem`);
  }
  const vaultIdxOf = (m) => JSON.parse(m.transaction.frozenCanonicalJson).inputs.findIndex((i) => i.utxo.covenantId === m.vaultOperations[0].covenantId);
  const tokenIdxOf = (m) => JSON.parse(m.transaction.frozenCanonicalJson).inputs.findIndex((i) => i.utxo.covenantId === m.vaultOperations[0].tokenCovenantId);
  const rehashOp = (m) => { const { manifestHash, ...b } = m.vaultOperations[0].manifest; void manifestHash; m.vaultOperations[0].manifest = { ...b, manifestHash: computeManifestHashV1(b) }; };
  const rederiveVaultBudget = (m) => { const op = m.vaultOperations[0].manifest; const b = selectComputeBudgetV7({ operation: op.action.sdkAction, templatePrefixLen: op.vault.templateGeometry.prefixLen, templateSuffixLen: op.vault.templateGeometry.suffixLen, rootPrefixLen: op.vault.rootGeometry.prefixLen, rootSuffixLen: op.vault.rootGeometry.suffixLen }); op.transaction.computeBudget = b; editFrozen(m, (f) => { f.inputs[vaultIdxOf(m)].computeBudget = b; }); return b; };
  const rederiveTokenBudget = (m) => { const op = m.vaultOperations[0].manifest; const b = selectTokenInputBudgetV7({ templatePrefixLen: op.vault.templateGeometry.prefixLen, templateSuffixLen: op.vault.templateGeometry.suffixLen }); editFrozen(m, (f) => { f.inputs[tokenIdxOf(m)].computeBudget = b; }); return b; };
  const NEW_PK = H(0x9b);
  const redirectRecovery = (m) => {
    const op = m.vaultOperations[0].manifest; op.vault.recoveryPk = NEW_PK; op.policy.recoveryPk = NEW_PK;
    const redeemHex = assets.redeemFromSignatureScript(op.tokenSignatureScriptHex);
    const verified = assets.verifyTokenInputRedeem({ descriptor, redeemHex });
    const recoveryState = assets.kcc20.encodeState({ ownerIdentifier: NEW_PK, identifierType: assets.kcc20.OWNER_SCHEMES.P2PK, amount: verified.state.amount, isMinter: false });
    const tokenOut = assets.kcc20.p2shSpkHex(assets.kcc20.reconstructRedeem(verified.prefixHex, recoveryState, verified.suffixHex));
    editFrozen(m, (f) => { f.outputs[0].scriptPublicKey = { version: 0, scriptHex: `20${NEW_PK}ac` }; const t = f.outputs.findIndex((o) => o.covenant && o.covenant.covenantId === op.vault.tokenCovenantId); f.outputs[t].scriptPublicKey = { version: 0, scriptHex: tokenOut }; });
  };
  const rows = [
    ["pause: root suffix length +1000, vault budget re-derived 32 -> 35 (frozen + declared), op re-hashed", tamper(pause, (m) => { m.vaultOperations[0].manifest.vault.rootGeometry.suffixLen += 1000; assert.equal(rederiveVaultBudget(m), 35); rehashOp(m); }), ["templatePinsBound", "rootEvidenceAgrees"]],
    ["pause: root prefix length 1 -> 2, budget re-derived, op re-hashed", tamper(pause, (m) => { m.vaultOperations[0].manifest.vault.rootGeometry.prefixLen = 2; rederiveVaultBudget(m); rehashOp(m); }), ["templatePinsBound", "rootEvidenceAgrees"]],
    ["pause: root template hash substituted, op re-hashed", tamper(pause, (m) => { m.vaultOperations[0].manifest.vault.rootTemplateVmHash = H(0x9c); rehashOp(m); }), ["templatePinsBound", "rootEvidenceAgrees"]],
    ["emergency: token suffix length 1, vault budget re-derived, op re-hashed", tamper(emergency, (m) => { m.vaultOperations[0].manifest.vault.templateGeometry.suffixLen = 1; rederiveVaultBudget(m); rehashOp(m); }), ["templatePinsBound"]],
    ["terminal recovery: token suffix length 1, token budget re-derived 6 -> 4, op re-hashed (descriptor and token redeem unchanged)", tamper(recoverVault, (m) => { m.vaultOperations[0].manifest.vault.templateGeometry.suffixLen = 1; assert.equal(rederiveTokenBudget(m), 4); rederiveVaultBudget(m); rehashOp(m); }), ["templatePinsBound", "tokenTemplateBound"]],
    ["terminal recovery: token template hash substituted, op re-hashed", tamper(recoverVault, (m) => { m.vaultOperations[0].manifest.vault.templateVmHashBlake2b256 = H(0x9d); rehashOp(m); }), ["templatePinsBound", "tokenTemplateBound"]],
    ["terminal recovery: recoveryPk substituted, reserve payout redirected and token payout reconstructed to the replacement key, op re-hashed (predecessor inputs and both redeems unchanged)", tamper(recoverVault, (m) => { redirectRecovery(m); rehashOp(m); }), ["templatePinsBound"]],
    ["terminal recovery (no token position): recoveryPk substituted, payout redirected, op re-hashed", tamper(recoverBare, (m) => { const op = m.vaultOperations[0].manifest; op.vault.recoveryPk = NEW_PK; op.policy.recoveryPk = NEW_PK; editFrozen(m, (f) => { f.outputs[0].scriptPublicKey = { version: 0, scriptHex: `20${NEW_PK}ac` }; }); rehashOp(m); }), ["templatePinsBound"]],
    ["terminal recovery: declared predecessor paused 0 -> 1 while the actual redeem is kept, op re-hashed", tamper(recoverVault, (m) => { m.vaultOperations[0].manifest.stateBefore.state.paused = "1"; rehashOp(m); }), ["vaultRedeemStateAgrees", "templatePinsBound"]],
    ["terminal recovery: declared predecessor policyNonce +1, op re-hashed", tamper(recoverBare, (m) => { const st = m.vaultOperations[0].manifest.stateBefore.state; st.policyNonce = String(BigInt(st.policyNonce) + 1n); rehashOp(m); }), ["vaultRedeemStateAgrees", "templatePinsBound"]],
    ["pause: descriptor hash substituted, op re-hashed", tamper(pause, (m) => { m.vaultOperations[0].manifest.vault.descriptorHash = H(0x9e); rehashOp(m); }), ["templatePinsBound"]],
    ["pause: contract version relabelled to the HD candidate with root suffix +1000 and budget re-derived (a v0.7-payment script may not be presented under another generation)", tamper(pause, (m) => { const op = m.vaultOperations[0].manifest; op.vault.contractVersion = "policyvault-0.7-payment-hd"; op.vault.rootGeometry.suffixLen += 1000; rederiveVaultBudget(m); rehashOp(m); }), ["vaultGenerationAgrees", "rootEvidenceAgrees"]]
  ];
  for (const [label, m, expected] of rows) {
    const v = verdictOf(m);
    assert.equal(v.verdict, "REFUSED", `${label}: must be refused`);
    for (const e of expected) assert.ok(v.failures.some((f) => f.name.endsWith(e)), `${label}: expected ${e} among [${v.failures.map((f) => f.name).join(", ")}]`);
  }
  /* a terminal operation without its redeem is refused (the checkpoint-6 code made it optional) */
  for (const [name, m] of [["recoverWith", recoverVault], ["recoverWithout", recoverBare]]) {
    const withheld = verifyOrgRootIntentManifest({ manifest: m, descriptors: DESCRIPTORS(), redeemScripts: {} });
    assert.equal(withheld.verdict, "REFUSED", `${name}: terminal op without its redeem`); assert.ok(withheld.failures.some((f) => f.name.endsWith("vaultRedeemPresent")), `${name}: vaultRedeemPresent`);
  }
  /* the pins decode back out of the SDK-captured redeem and equal the build's template */
  const decoded = V.decodeVaultTemplatePinsV7(REDEEMS(pause)[pause.vaultOperations[0].covenantId]);
  assert.deepEqual(decoded.pins, require("../../core/model/vault-state-v7").normalizeTemplateV7(vaultTemplate));
});

/* ================================================================== *
 * rc26 round-7 internal review (independent falsification of cf4e644):
 *   R7-01 — the shared verifier binds EVERY input's sequence and the
 *           transaction lockTime (a hidden relative lock / far-future
 *           lockTime authored by a hostile server into an approved owner op
 *           was VERIFIED and signed);
 *   R7-02 — the ownerSetAgentRoot manifest CARRIES the new policy set and the
 *           verifier BINDS stateAfter.agentRoot to its fold (the review used
 *           to show "replace the registry commitment" with no policy at all:
 *           blind M-of-N approval of the rules being installed).
 * Real builds through the real compiler; every tamper re-hashes so the
 * SEMANTIC check refuses. RED on cf4e644.
 * ================================================================== */
test("rc26 round-7 R7-01 / R7-02 (real builds): hidden relative locks / lockTime refused by the verifier; the setAgentRoot policy set is CARRIED and BOUND", { skip: SKIP }, () => {
  const s = shapes();
  const tag = `vault[${VAULT_COV_ID.slice(0, 8)}].`;
  const authorize = orgManifest(s.root.authorize);
  const pause = orgManifest(s.vault.pause, [{ build: s.vault.pause, descriptor }]);
  const setRoot = orgManifest(s.vault.setAgentRoot, [{ build: s.vault.setAgentRoot, descriptor }]);
  /* R7-02 — carriage + binding on the honest build */
  assert.equal(verdictOf(setRoot).verdict, "VERIFIED", `control: ${JSON.stringify(verdictOf(setRoot).failures)}`);
  const carried = setRoot.vaultOperations[0].manifest.policy.agentSet;
  assert.ok(Array.isArray(carried) && carried.length === 1 && carried[0].agentPk === H(0x71), "the manifest CARRIES the new policy set");
  assert.equal(s.vault.setAgentRoot.successorState.agentRoot, buildTokenAgentTreeV5(carried.map(({ recipients, ...policy }) => { void recipients; return policy; })).root, "the declared successor agentRoot IS the fold of the carried set (policy fields; the recipients ride beside each policy)");
  assert.deepEqual(carried.map((p) => p.recipients), [[...rTree.recipients]], "Codex checkpoint 11: every carried policy lists its recipients");
  assert.throws(() => vaultBuild("ownerSetAgentRoot", { params: { newAgentRoot: H(0x99) } }), (e) => e.code === "AGENT_SET_REQUIRED", "a bare root without the policy set is refused by the builder");
  assert.throws(() => vaultBuild("ownerSetAgentRoot", { params: { newAgentRoot: H(0x99), agents: [{ ...agentPolicy, agentPk: H(0x71), recipients: [...rTree.recipients] }] } }), (e) => e.code === "AGENT_ROOT_MISMATCH", "a declared root that is not the set's fold is refused");
  assert.throws(() => vaultBuild("ownerSetAgentRoot", { params: { agents: [{ ...agentPolicy, agentPk: H(0x71) }] } }), (e) => e.code === "AGENT_RECIPIENTS_REQUIRED", "Codex checkpoint 11: a policy without its recipients is refused by the builder");
  assert.throws(() => vaultBuild("ownerSetAgentRoot", { params: { agents: [{ ...agentPolicy, agentPk: H(0x71), recipients: [H(0x0d)] }] } }), (e) => e.code === "AGENT_RECIPIENTS_MISMATCH", "Codex checkpoint 11: recipients that do not fold to the policy's declared agentRecipientRoot are refused");
  const rows = [
    ["R7-02: the policy set WITHHELD from the setAgentRoot manifest", tamper(setRoot, (m) => { delete m.vaultOperations[0].manifest.policy.agentSet; rehashVaultOp(m); }), `${tag}agentSetPresent`],
    ["R7-02: the policy set substituted (per-spend cap 10^9; declared root kept)", tamper(setRoot, (m) => { m.vaultOperations[0].manifest.policy.agentSet[0].tokenMaxPerSpend = "1000000000"; rehashVaultOp(m); }), `${tag}agentSetBound`],
    ["Codex checkpoint 11 (R7-02): recipients substituted, root kept", tamper(setRoot, (m) => { m.vaultOperations[0].manifest.policy.agentSet[0].recipients = [H(0x0d)]; rehashVaultOp(m); }), `${tag}agentRecipientsBound`],
    ["Codex checkpoint 11 (R7-02): recipients withheld", tamper(setRoot, (m) => { delete m.vaultOperations[0].manifest.policy.agentSet[0].recipients; rehashVaultOp(m); }), `${tag}agentRecipientsBound`],
    ["Codex checkpoint 11 (R7-02): recipients substituted CONSISTENTLY (recipient root + agent tree + stateAfter rebuilt; successor NOT rebuilt)", tamper(setRoot, (m) => { const p = m.vaultOperations[0].manifest.policy.agentSet[0]; p.recipients = [H(0x0d)]; p.agentRecipientRoot = buildRecipientTree([H(0x0d)]).root; m.vaultOperations[0].manifest.stateAfter.state.agentRoot = buildTokenAgentTreeV5(m.vaultOperations[0].manifest.policy.agentSet.map(({ recipients, ...q }) => { void recipients; return q; })).root; rehashVaultOp(m); }), `${tag}successorScriptReconstructed`],
    ["R7-02: an extra policy appended to the carried set (declared root kept)", tamper(setRoot, (m) => { const a = m.vaultOperations[0].manifest.policy.agentSet; a.push({ ...a[0], agentPk: H(0x0d) }); rehashVaultOp(m); }), `${tag}agentSetBound`],
    ["R7-02: the policy set emptied (declared root kept)", tamper(setRoot, (m) => { m.vaultOperations[0].manifest.policy.agentSet = []; rehashVaultOp(m); }), `${tag}agentSetBound`],
    ["R7-02: stateAfter.agentRoot substituted (set kept)", tamper(setRoot, (m) => { m.vaultOperations[0].manifest.stateAfter.state.agentRoot = H(0x99); rehashVaultOp(m); }), `${tag}agentSetBound`],
    ["R7-01: root input sequence 1,000,000 on an authorize", tamper(authorize, (m) => editFrozen(m, (f) => { f.inputs[0].sequence = "1000000"; })), "rootInputSequenceZero"],
    ["R7-01: fee input sequence 2^32-1 on an authorize", tamper(authorize, (m) => editFrozen(m, (f) => { f.inputs[f.inputs.length - 1].sequence = "4294967295"; })), "inputSequencesZero"],
    ["R7-01: lockTime 500,000,000,000 on an authorize", tamper(authorize, (m) => editFrozen(m, (f) => { f.lockTime = "500000000000"; })), "lockTimeZero"],
    ["R7-01: vault input sequence 1,000,000 on a pause", tamper(pause, (m) => editFrozen(m, (f) => { f.inputs[0].sequence = "1000000"; })), `${tag}inputSequencesZero`],
    ["R7-01: fee input sequence 1,000,000 on a pause (outer)", tamper(pause, (m) => editFrozen(m, (f) => { f.inputs[f.inputs.length - 1].sequence = "1000000"; })), "inputSequencesZero"],
    ["R7-01: lockTime 7 on a pause (inner)", tamper(pause, (m) => editFrozen(m, (f) => { f.lockTime = "7"; })), `${tag}lockTimeZero`]
  ];
  for (const [label, manifest, expectedCheck] of rows) {
    const v = verdictOf(manifest);
    assert.notEqual(v.verdict, "VERIFIED", label);
    assert.ok(v.failures.some((f) => f.name === expectedCheck), `${label}: expected ${expectedCheck}, got ${v.failures.map((f) => f.name).join(",")}`);
  }
});
