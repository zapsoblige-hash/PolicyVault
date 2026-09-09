"use strict";

/*
 * PolicyVault v0.7 PRODUCTION-BYTE vector generator (organizational root +
 * rooted payment vault).
 *
 * Drives the ACTUAL production SDK code — core/model (owner-set-v7,
 * vault-state-v7-root, vault-state-v7, vault-transitions-v7*,
 * compute-budget-v7), core/assets, token-program-kcc20,
 * contract-compiler-v7 (silverc), agent-merkle-v5, recipient-merkle-v3,
 * frozen-tx-v3, vault-builders-v7, core/intent/org-root-manifest-v7 and the
 * REAL pv_call_encoder + pv_tx_probe binaries — to construct fully-finalized
 * v0.7 transactions with real Schnorr signatures (rusty-kaspa WASM
 * createInputSignature over deterministic TEST-ONLY keys).
 * tests/vm/tests/v7_sdk_integration.rs executes every emitted vector's EXACT
 * bytes on the real TxScriptEngine against the PRODUCTION candidates
 * contracts/PolicyVault.v0.7-root.sil and PolicyVault.v0.7-payment.sil.
 *
 * Negative vectors are otherwise-valid transactions with ONE security field
 * mutated AFTER freeze/finalize (the SDK itself refuses to build them, and
 * the refusal matrix below proves that) and MUST be rejected by consensus.
 * Each carries `rejectInput`: the input index whose script must fail, so a
 * refusal is attributable to the rule it targets rather than to collateral
 * damage on another input.
 *
 * Usage: node gen-v7-vectors.js <output-dir>
 * TEST KEYS ONLY: secrets are the byte value repeated 32x. Never production material.
 */

const fs = require("fs");
const path = require("path");

const { loadConfig } = require("../src/config");
const assets = require("../../core/assets");
const { compileKcc20Program } = require("../src/token-program-kcc20");
const { buildTokenAgentTreeV5 } = require("../src/agent-merkle-v5");
const { buildRecipientTree } = require("../src/recipient-merkle-v3");
const { compileExactStateV7Root, compileExactStateV7, deriveRootPinsV7, assertRootPinsMatchV7 } = require("../src/contract-compiler-v7");
const {
  buildCreateV7Root,
  buildV7RootTransaction,
  finalizeV7RootTransaction,
  buildCreateV7Vault,
  buildV7Transaction,
  finalizeV7Transaction,
  buildTokenDepositV7,
  finalizeTokenDepositV7
} = require("../src/vault-builders-v7");
const { frozenToWasmTransaction } = require("../src/frozen-tx-v3");
const { OWNER_SLOTS_V7, INACTIVE_SLOT_KEY, PLACEHOLDER_SLOT_HEX_V7 } = require("../../core/model/owner-set-v7");
const { normalizeRootStateV7 } = require("../../core/model/vault-state-v7-root");
const { buildOrgRootIntentManifest, verifyOrgRootIntentManifest } = require("../../core/intent/org-root-manifest-v7");
const { routeIntentManifestBuilder, routeIntentManifestVerifier } = require("../../core/intent/router");

const outDir = process.argv[2];
if (!outDir) {
  console.error("usage: node gen-v7-vectors.js <output-dir>");
  process.exit(1);
}
fs.mkdirSync(outDir, { recursive: true });

const config = loadConfig({ dataRoot: path.join(outDir, "data") });
const kaspa = require(config.rustyKaspaModule);

const KAS = 100000000n;
const KEY = (v) => new kaspa.PrivateKey(v.toString(16).padStart(2, "0").repeat(32));
const XO = (p) => p.toPublicKey().toXOnlyPublicKey().toString().toLowerCase();

const ownerKeys = [KEY(0x71), KEY(0x72), KEY(0x73), KEY(0x74)];
const newOwnerKeys = [KEY(0x81), KEY(0x82), KEY(0x83), KEY(0x84)];
const successorKey = KEY(0x7f);
const outsiderKey = KEY(0x6f);
const agentKey = KEY(0x62);
const recipientKey = KEY(0x63);
const fuelKey = KEY(0x64);
const otherKey = KEY(0x65);
const recoveryKey = KEY(0x51);

const ORG_ID = "a7".repeat(32);
const ROOT_ID = "52".repeat(32);
const VAULT_COV_ID = "43".repeat(32);
const TOKEN_FAMILY = "54".repeat(32);
const ALIEN_ID = "57".repeat(32);
const VAULT_ID = "44".repeat(32);
const FAMILY_BOUND = 2;
const RECOVERY_DELAY = 1000n;
const SUCCESSION_DELAY = 2000n;
const ROOT_MAX_FEE = 200000n;
const ROOT_KAS = 3n * KAS;

function slots(keys) {
  const out = [];
  for (let i = 0; i < OWNER_SLOTS_V7; i += 1) out.push(i < keys.length ? XO(keys[i]) : INACTIVE_SLOT_KEY);
  return out;
}

const rootTemplate = { orgId: ORG_ID, recoveryDelayDaa: RECOVERY_DELAY.toString(), successorPk: XO(successorKey), successionDelayDaa: SUCCESSION_DELAY.toString(), rootMaxFeePerTx: ROOT_MAX_FEE.toString() };
const ownerSet3 = { owners: slots(ownerKeys.slice(0, 3)), ownerM: 2, emergencyK: 1, recoveryM: 2 };
const ownerSet4 = { owners: slots(ownerKeys), ownerM: 4, emergencyK: 1, recoveryM: 2 };
const rootState = (over = {}) => normalizeRootStateV7({ boundOrgId: ORG_ID, ...ownerSet3, frozen: 0, rootNonce: 0, ...over });

/* ---- the accepted asset descriptor, from the vendored program's real bytes ---- */
const refProgram = compileKcc20Program({ config, state: assets.kcc20.ZERO_STATE, familyBound: FAMILY_BOUND });
const descriptor = {
  schema: "policyvault-asset-descriptor/1",
  assetId: "11".repeat(32),
  displayName: "Org Vector Token",
  tokenStandard: "kcc20/1",
  tokenCovenantId: TOKEN_FAMILY,
  acceptedTransferTemplates: [{ templateVmHashBlake2b256: refProgram.templateVmHashBlake2b256, prefixLen: refProgram.geometry.prefixLen, suffixLen: refProgram.geometry.suffixLen, stateLayout: "kcc20-state/1" }],
  decimalsDisplay: 8,
  issuerPowers: { mint: false, burn: false, freeze: false, blacklist: false, redemptionControl: false, upgradeMigration: false, controllerRotation: false, emergencyControl: false }
};
const descriptorHash = assets.computeDescriptorHash(descriptor);

/* the root pins a rooted vault carries — DERIVED from a real compiled root */
const rootPins = deriveRootPinsV7({ config, template: rootTemplate, ownerSet: ownerSet3, covenantId: ROOT_ID });
const vaultTemplate = {
  vaultId: VAULT_ID,
  descriptorHash,
  tokenCovenantId: TOKEN_FAMILY,
  templateVmHash: refProgram.templateVmHashBlake2b256,
  templatePrefixLen: refProgram.geometry.prefixLen,
  templateStateLen: refProgram.geometry.stateLen,
  templateSuffixLen: refProgram.geometry.suffixLen,
  ...rootPins,
  recoveryPk: XO(recoveryKey)
};
assertRootPinsMatchV7({ config, vaultTemplate, rootTemplate, rootOwnerSet: ownerSet3 });

/* ---- agent policy / recipient trees (frozen v0.5 shapes) ---- */
const rTree = buildRecipientTree([XO(recipientKey)]);
const agentPolicy = (pk, over = {}) => ({
  agentPk: pk,
  tokenMaxPerSpend: "250",
  tokenPeriodBudget: "400",
  periodLengthDaa: "1000",
  periodStartDaa: "5000",
  tokenPeriodSpent: "0",
  agentMaxFeePerTx: (1n * KAS).toString(),
  agentMaxCarryKas: (KAS / 4n).toString(),
  agentRecipientRoot: rTree.root,
  ...over
});
const agents = [agentPolicy(XO(agentKey)), agentPolicy(XO(otherKey))];
const agentTree = buildTokenAgentTreeV5(agents);
const vaultState = (over = {}) => ({ feeReserve: (5n * KAS).toString(), paused: "0", agentRoot: agentTree.root, policyNonce: "0", ...over });

function tokenPositionFor(amount) {
  const st = { ownerIdentifier: VAULT_COV_ID, identifierType: 2, amount: String(amount), isMinter: false };
  const program = compileKcc20Program({ config, state: st, familyBound: FAMILY_BOUND });
  return { outpoint: { transactionId: "02".repeat(32), index: 0 }, value: (2n * KAS).toString(), scriptPublicKeyHex: program.p2shSpkHex, covenantId: TOKEN_FAMILY, state: st };
}
const fuelUtxo = (id = "03") => ({ outpoint: { transactionId: id.repeat(32), index: 0 }, amount: (1n * KAS).toString(), scriptPublicKeyHex: `20${XO(fuelKey)}ac` });
const rootChain = (over = {}) => ({ predecessorOutpoint: { transactionId: "01".repeat(32), index: 0 }, covenantId: ROOT_ID, predecessorValue: ROOT_KAS.toString(), fuel: fuelUtxo(), ...over });
const rootSide = (state, over = {}) => ({ template: rootTemplate, state, outpoint: { transactionId: "04".repeat(32), index: 0 }, covenantId: ROOT_ID, value: ROOT_KAS.toString(), ...over });
const vaultChain = (over = {}) => ({ predecessorOutpoint: { transactionId: "0a".repeat(32), index: 0 }, covenantId: VAULT_COV_ID, predecessorValue: (5n * KAS).toString(), fuel: fuelUtxo("03"), ...over });

/* ---- signing helpers (TEST KEYS ONLY) ---- */
const wasmOf = (build) => frozenToWasmTransaction(config, build.frozen);
const signInput = (build, index, key) => kaspa.createInputSignature(wasmOf(build), index, key).slice(2);
const signFuelScript = (build, index, key = fuelKey) => kaspa.createInputSignature(wasmOf(build), index, key);
const approvalsFor = (build, index, keyIndexes) => keyIndexes.map((i) => ({ slot: i + 1, signatureHex: signInput(build, index, ownerKeys[i]) }));

/* ---- vector + refusal bookkeeping ---- */
const vectors = [];
const refusals = [];
function emit(name, expect, build, finalTx, extra = {}) {
  vectors.push({ name, expect });
  const dir = path.join(outDir, name);
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(
    path.join(dir, "vector.json"),
    JSON.stringify(
      {
        name,
        expect,
        rejectInput: extra.rejectInput ?? 0,
        action: build?.action ?? "unknown",
        contract: extra.contract ?? build?.contractVersion ?? null,
        committedBudget: build?.computeBudget ?? null,
        requiredFeeSompi: build?.requiredFeeSompi ?? null,
        accounting: build?.accounting ?? null,
        note: extra.note ?? null,
        tx: finalTx
      },
      null,
      1
    )
  );
}
function refuses(name, f, codeRe) {
  try {
    f();
    refusals.push({ name, refused: false });
  } catch (e) {
    refusals.push({ name, refused: true, code: e.code ?? null, message: String(e.message).slice(0, 200), ok: codeRe ? codeRe.test(e.code ?? "") || codeRe.test(e.message) : true });
  }
}
const mutate = (tx, f) => {
  const j = JSON.parse(JSON.stringify(tx));
  f(j);
  return j;
};
const p2sh = (scriptBytes) => String(kaspa.payToScriptHashScript(scriptBytes.toString("hex")).script).toLowerCase();

/* The encoder MUST understand the v0.7 arms; a stale binary would silently
 * produce a different generation's bytes. Fail closed, loudly. */
{
  const probe = buildV7RootTransaction({ config, templateInput: rootTemplate, stateInput: rootState(), action: "authorize", chain: rootChain(), changeXOnly: XO(fuelKey) });
  if (probe.plannedCallHexLength / 2 < 1000) {
    console.error("pv_call_encoder produced an implausibly short v0.7-root call — is the binary stale? rebuild tests/vm --bin pv_call_encoder");
    process.exit(3);
  }
}

/* ================================================================ ROOT: POSITIVE */
const manifests = [];

{
  /* 1. root genesis */
  const build = buildCreateV7Root({
    config,
    template: rootTemplate,
    ownerSet: ownerSet3,
    rootValueSompi: ROOT_KAS.toString(),
    funding: [{ outpoint: { transactionId: "05".repeat(32), index: 0 }, amount: (10n * KAS).toString(), scriptPublicKeyHex: `20${XO(fuelKey)}ac` }],
    changeXOnly: XO(fuelKey)
  });
  const json = JSON.parse(build.frozenCanonicalJson);
  json.inputs[0].signatureScript = kaspa.createInputSignature(wasmOf(build), 0, fuelKey);
  emit("root_genesis", "accept", build, json, { contract: "policyvault-0.7-root", note: "plain funding input; the root output carries the derived covenant binding" });
}

/* 2. AUTHORIZE 2-of-3 (the organization's heartbeat and the ONLY root shape a
 *    rooted vault accepts for a general owner operation) */
let authorizeBuild;
let authorizeTx;
{
  const build = buildV7RootTransaction({ config, templateInput: rootTemplate, stateInput: rootState(), action: "authorize", chain: rootChain(), changeXOnly: XO(fuelKey) });
  /* Schnorr signing draws fresh auxiliary randomness, so every slot signature
   * is produced EXACTLY ONCE and reused: the mutations below must edit the
   * very bytes the finalizer placed in the blob, not a fresh signature. */
  const slot1 = signInput(build, 0, ownerKeys[0]);
  const slot2 = signInput(build, 0, ownerKeys[1]);
  const outsider = signInput(build, 0, outsiderKey);
  const fin = finalizeV7RootTransaction({ build, approvals: [{ slot: 1, signatureHex: slot1 }, { slot: 2, signatureHex: slot2 }], fuelSignatureScriptHex: signFuelScript(build, 1) });
  authorizeBuild = build;
  authorizeTx = fin.finalTransaction;
  emit("root_authorize_2of3", "accept", build, authorizeTx, { contract: "policyvault-0.7-root" });

  const manifest = buildOrgRootIntentManifest({ build, vaultOperations: [], satisfiedApprovals: 2 });
  manifests.push({ name: "root_authorize_2of3", verdict: verifyOrgRootIntentManifest({ manifest }).verdict });

  /* ---- negatives crafted from this accept vector (post-finalize) ---- */
  const swapSlot = (tx, sigHex, replacement) => mutate(tx, (j) => {
    const s = j.inputs[0].signatureScript;
    if (!s.includes(sigHex)) throw new Error("internal: could not locate the owner slot inside the finalized sigscript");
    j.inputs[0].signatureScript = s.replace(sigHex, replacement);
  });

  emit("neg_root_under_quorum", "reject", build, swapSlot(authorizeTx, slot2, PLACEHOLDER_SLOT_HEX_V7), { contract: "policyvault-0.7-root", note: "one of the two required approvals abstains" });
  emit("neg_root_duplicate_slot", "reject", build, swapSlot(authorizeTx, slot2, slot1), { contract: "policyvault-0.7-root", note: "slot 1's signature copied into slot 2 — it verifies under exactly one key, so the count stays 1" });
  emit("neg_root_outsider_slot", "reject", build, swapSlot(authorizeTx, slot2, outsider), { contract: "policyvault-0.7-root", note: "a real signature under a key that is not in the owner set" });
  emit("neg_root_forged_gate_byte", "reject", build, swapSlot(authorizeTx, slot1, slot1.slice(0, -2) + "02"), { contract: "policyvault-0.7-root", note: "the SIGHASH_ALL gate byte forged to 0x02" });
  emit("neg_root_value_drained", "reject", build, mutate(authorizeTx, (j) => {
    const drop = ROOT_MAX_FEE + 1n;
    j.outputs[0].value = (BigInt(j.outputs[0].value) - drop).toString();
    j.outputs[1].value = (BigInt(j.outputs[1].value) + drop).toString();
  }), { contract: "policyvault-0.7-root", note: "the successor loses more than rootMaxFeePerTx" });

  /* successor substitution: the root output commits to a DIFFERENT state */
  const skipped = compileExactStateV7Root({ config, template: rootTemplate, state: rootState({ rootNonce: 2 }) });
  emit("neg_root_nonce_skipped", "reject", build, mutate(authorizeTx, (j) => {
    j.outputs[0].scriptPublicKey.scriptHex = p2sh(skipped.scriptBytes);
  }), { contract: "policyvault-0.7-root", note: "successor nonce +2 instead of +1" });
  const unchanged = compileExactStateV7Root({ config, template: rootTemplate, state: rootState({ rootNonce: 0 }) });
  emit("neg_root_nonce_unchanged", "reject", build, mutate(authorizeTx, (j) => {
    j.outputs[0].scriptPublicKey.scriptHex = p2sh(unchanged.scriptBytes);
  }), { contract: "policyvault-0.7-root", note: "successor nonce unchanged — replay would be possible" });
  const rotated = compileExactStateV7Root({ config, template: rootTemplate, state: rootState({ rootNonce: 1, owners: slots(newOwnerKeys.slice(0, 3)) }) });
  emit("neg_root_authorize_swaps_the_owner_set", "reject", build, mutate(authorizeTx, (j) => {
    j.outputs[0].scriptPublicKey.scriptHex = p2sh(rotated.scriptBytes);
  }), { contract: "policyvault-0.7-root", note: "AUTHORIZE must preserve the set; a disguised rotation is refused" });
}

/* 3. ROTATE (full quorum, new set) */
{
  const build = buildV7RootTransaction({
    config,
    templateInput: rootTemplate,
    stateInput: rootState(),
    action: "rotate",
    params: { newOwnerSet: { owners: slots([...ownerKeys.slice(0, 2), newOwnerKeys[0], newOwnerKeys[1]]), ownerM: 3, emergencyK: 2, recoveryM: 2 } },
    chain: rootChain(),
    changeXOnly: XO(fuelKey)
  });
  const fin = finalizeV7RootTransaction({ build, approvals: approvalsFor(build, 0, [0, 1]), fuelSignatureScriptHex: signFuelScript(build, 1) });
  emit("root_rotate_2of3_installs_4", "accept", build, fin.finalTransaction, { contract: "policyvault-0.7-root" });
  manifests.push({ name: "root_rotate", verdict: verifyOrgRootIntentManifest({ manifest: buildOrgRootIntentManifest({ build, vaultOperations: [], satisfiedApprovals: 2 }) }).verdict });
}

/* 4. FREEZE on the LIGHTER emergency quorum (K = 1) */
let freezeBuild;
{
  const build = buildV7RootTransaction({ config, templateInput: rootTemplate, stateInput: rootState(), action: "freeze", chain: rootChain(), changeXOnly: XO(fuelKey) });
  const fin = finalizeV7RootTransaction({ build, approvals: approvalsFor(build, 0, [0]), fuelSignatureScriptHex: signFuelScript(build, 1) });
  freezeBuild = build;
  emit("root_freeze_emergency_k1", "accept", build, fin.finalTransaction, { contract: "policyvault-0.7-root" });
  manifests.push({ name: "root_freeze", verdict: verifyOrgRootIntentManifest({ manifest: buildOrgRootIntentManifest({ build, vaultOperations: [], satisfiedApprovals: 1 }) }).verdict });
}

/* 5. UNFREEZE (full quorum) */
{
  const build = buildV7RootTransaction({ config, templateInput: rootTemplate, stateInput: rootState({ frozen: 1, rootNonce: 1 }), action: "unfreeze", chain: rootChain(), changeXOnly: XO(fuelKey) });
  const fin = finalizeV7RootTransaction({ build, approvals: approvalsFor(build, 0, [0, 1]), fuelSignatureScriptHex: signFuelScript(build, 1) });
  emit("root_unfreeze_full_quorum", "accept", build, fin.finalTransaction, { contract: "policyvault-0.7-root" });
}

/* 6. OWNER-RECOVER past the idle delay, landing FROZEN (decision D6) */
{
  const prev = normalizeRootStateV7({ boundOrgId: ORG_ID, ...ownerSet4, frozen: 0, rootNonce: 0 });
  const build = buildV7RootTransaction({
    config,
    templateInput: rootTemplate,
    stateInput: prev,
    action: "ownerRecover",
    params: { newOwnerSet: { owners: slots(ownerKeys.slice(0, 2)), ownerM: 2, emergencyK: 1, recoveryM: 2 } },
    chain: rootChain(),
    changeXOnly: XO(fuelKey)
  });
  if (build.minSequence !== RECOVERY_DELAY.toString()) throw new Error("the recovery build must carry the relative-age sequence");
  const fin = finalizeV7RootTransaction({ build, approvals: approvalsFor(build, 0, [0, 1]), fuelSignatureScriptHex: signFuelScript(build, 1) });
  emit("root_owner_recover_after_idle", "accept", build, fin.finalTransaction, { contract: "policyvault-0.7-root", note: "input sequence carries recoveryDelayDaa; the successor lands FROZEN (D6)" });
  manifests.push({ name: "root_owner_recover", verdict: verifyOrgRootIntentManifest({ manifest: buildOrgRootIntentManifest({ build, vaultOperations: [], satisfiedApprovals: 2 }) }).verdict });
}

/* 7. SUCCESSION (the pinned successor key, past the idle delay, D1) */
{
  const build = buildV7RootTransaction({
    config,
    templateInput: rootTemplate,
    stateInput: rootState(),
    action: "succession",
    params: { newOwnerSet: { owners: slots(newOwnerKeys.slice(0, 2)), ownerM: 2, emergencyK: 1, recoveryM: 1 } },
    chain: rootChain(),
    changeXOnly: XO(fuelKey)
  });
  const fin = finalizeV7RootTransaction({ build, successorSignatureHex: signInput(build, 0, successorKey), fuelSignatureScriptHex: signFuelScript(build, 1) });
  emit("root_succession", "accept", build, fin.finalTransaction, { contract: "policyvault-0.7-root" });
  /* a succession signed by anyone but the pinned successor */
  const bad = finalizeV7RootTransaction({ build, successorSignatureHex: signInput(build, 0, outsiderKey), fuelSignatureScriptHex: signFuelScript(build, 1) });
  emit("neg_root_succession_wrong_key", "reject", build, bad.finalTransaction, { contract: "policyvault-0.7-root" });
}

/* ================================================================ ROOTED VAULT */

/* 8. rooted vault genesis */
{
  const build = buildCreateV7Vault({
    config,
    templateInput: vaultTemplate,
    initialStateInput: vaultState(),
    funding: [{ outpoint: { transactionId: "06".repeat(32), index: 0 }, amount: (10n * KAS).toString(), scriptPublicKeyHex: `20${XO(fuelKey)}ac` }],
    changeXOnly: XO(fuelKey),
    descriptor
  });
  const json = JSON.parse(build.frozenCanonicalJson);
  json.inputs[0].signatureScript = kaspa.createInputSignature(wasmOf(build), 0, fuelKey);
  emit("vault_genesis", "accept", build, json, { contract: "policyvault-0.7-payment", note: "the vault output pins orgRootCovenantId + the root template identity" });
}

/* 9-13. owner operations: root input + vault input + fuel */
const ownerOpBuilds = {};
for (const [name, action, params, prevOver] of [
  /* rc26 round-7 R7-02: the builder derives the root from the FULL new delegate policy set (every policy with its complete
   * recipient set); a bare `newAgentRoot` is refused (AGENT_SET_REQUIRED). The vector installs a REDUCED set (the production
   * agent key only, with its recipient set) so the installed root differs from the genesis root (rc29: generator brought in
   * line with the builder contract). */
  ["vault_owner_set_agent_root", "ownerSetAgentRoot", { agents: [{ ...agentPolicy(XO(agentKey)), recipients: [...rTree.recipients] }] }, {}],
  ["vault_owner_top_up_reserve", "ownerTopUpReserve", { topUpReserveAmountSompi: (KAS / 2n).toString() }, {}],
  ["vault_owner_pause", "ownerPause", {}, {}],
  ["vault_owner_unpause", "ownerUnpause", {}, { paused: "1" }],
  ["vault_emergency_pause", "ownerEmergencyPause", {}, {}]
]) {
  const build = buildV7Transaction({
    config,
    templateInput: vaultTemplate,
    stateInput: vaultState(prevOver),
    action,
    params,
    chain: vaultChain({ root: rootSide(rootState()) }),
    changeXOnly: XO(fuelKey),
    descriptor
  });
  const signers = build.rootAuthority.rootActionName === "freeze" ? [0] : [0, 1];
  const fin = finalizeV7Transaction({ build, approvals: approvalsFor(build, 1, signers), fuelSignatureScriptHex: signFuelScript(build, 2) });
  ownerOpBuilds[name] = { build, tx: fin.finalTransaction };
  emit(name, "accept", build, fin.finalTransaction, { contract: "policyvault-0.7-payment" });

  const manifest = buildOrgRootIntentManifest({ build, vaultOperations: [{ build, descriptor }], satisfiedApprovals: signers.length });
  /* Codex checkpoint 7 (UX-02/UX-13): the verifier binds the declared pins to the spent vault through its predecessor redeem script — supplied exactly as the SDK request layer supplies it (rc29: generator brought in line). */
  { const v = verifyOrgRootIntentManifest({ manifest, descriptors: { [build.covenantId]: descriptor }, redeemScripts: { [build.covenantId]: build.vaultRedeemScriptHex } }); manifests.push({ name, verdict: v.verdict, failures: v.failures }); }
}

/* SELECTOR CROSS-OVER: the vault call bytes carry NO signature, so the two
 * shapes below differ ONLY in the opSelector int push. Swapping them proves
 * the vault really does pin WHICH root path ran, not merely that a root is
 * present. Each swap keeps every signature valid — only input 0 must fail. */
{
  const pause = ownerOpBuilds.vault_owner_pause;
  const emergency = ownerOpBuilds.vault_emergency_pause;
  emit("neg_vault_selector2_under_freeze_root", "reject", emergency.build, mutate(emergency.tx, (j) => {
    j.inputs[0].signatureScript = pause.tx.inputs[0].signatureScript;
  }), { contract: "policyvault-0.7-payment", rejectInput: 0, note: "selector 2 (full quorum) riding a FREEZE root successor" });
  emit("neg_vault_selector4_under_authorize_root", "reject", pause.build, mutate(pause.tx, (j) => {
    j.inputs[0].signatureScript = emergency.tx.inputs[0].signatureScript;
  }), { contract: "policyvault-0.7-payment", rejectInput: 0, note: "selector 4 (emergency quorum) riding an AUTHORIZE root successor" });
}

/* the root's continuation output substituted for a ROTATE successor: the vault
 * rebuilds the ONE successor redeem it accepts and no longer matches */
{
  const pause = ownerOpBuilds.vault_owner_pause;
  const rotated = compileExactStateV7Root({ config, template: rootTemplate, state: rootState({ rootNonce: 1, owners: slots(newOwnerKeys.slice(0, 3)) }) });
  emit("neg_vault_root_successor_head_changed", "reject", pause.build, mutate(pause.tx, (j) => {
    j.outputs[1].scriptPublicKey.scriptHex = p2sh(rotated.scriptBytes);
  }), { contract: "policyvault-0.7-payment", rejectInput: 0, note: "a rotation disguised inside a vault owner operation" });
  /* an alien covenant rider — the generalised family closure must refuse it */
  const alienState = { ownerIdentifier: XO(otherKey), identifierType: 0, amount: "5", isMinter: false };
  const alien = compileKcc20Program({ config, state: alienState, familyBound: FAMILY_BOUND });
  emit("neg_vault_alien_covenant_rider", "reject", pause.build, mutate(pause.tx, (j) => {
    j.inputs.splice(2, 0, { previousOutpoint: { transactionId: "0f".repeat(32), index: 0 }, signatureScript: "", sequence: "0", computeBudget: 10, utxo: { amount: KAS.toString(), scriptPublicKey: { version: 0, scriptHex: alien.p2shSpkHex }, covenantId: ALIEN_ID, blockDaaScore: "0" } });
    j.outputs.splice(2, 0, { value: KAS.toString(), scriptPublicKey: { version: 0, scriptHex: alien.p2shSpkHex }, covenant: { authorizingInput: 2, covenantId: ALIEN_ID } });
  }), { contract: "policyvault-0.7-payment", rejectInput: 0, note: "a foreign covenant family riding an owner operation" });
}

/* 14-15. ownerRecover: the reserve and the whole token position -> recoveryPk */
{
  const withPos = buildV7Transaction({
    config,
    templateInput: vaultTemplate,
    stateInput: vaultState(),
    action: "ownerRecover",
    chain: vaultChain({ root: rootSide(rootState()), tokenPosition: tokenPositionFor(300) }),
    changeXOnly: XO(fuelKey),
    descriptor
  });
  const finWith = finalizeV7Transaction({ build: withPos, approvals: approvalsFor(withPos, 1, [0, 1]), fuelSignatureScriptHex: signFuelScript(withPos, 3) });
  emit("vault_recover_with_position", "accept", withPos, finWith.finalTransaction, { contract: "policyvault-0.7-payment" });
  manifests.push({
    name: "vault_recover_with_position",
    verdict: verifyOrgRootIntentManifest({ manifest: buildOrgRootIntentManifest({ build: withPos, vaultOperations: [{ build: withPos, descriptor }], satisfiedApprovals: 2 }), descriptors: { [withPos.covenantId]: descriptor }, redeemScripts: { [withPos.covenantId]: withPos.vaultRedeemScriptHex } }).verdict
  });

  /* the recovery destination is a TEMPLATE CONSTANT, not a session choice */
  emit("neg_vault_recover_wrong_destination", "reject", withPos, mutate(finWith.finalTransaction, (j) => {
    j.outputs[0].scriptPublicKey.scriptHex = `20${XO(otherKey)}ac`;
  }), { contract: "policyvault-0.7-payment", rejectInput: 0 });

  const noPos = buildV7Transaction({
    config,
    templateInput: vaultTemplate,
    stateInput: vaultState(),
    action: "ownerRecover",
    chain: vaultChain({ root: rootSide(rootState()) }),
    changeXOnly: XO(fuelKey),
    descriptor
  });
  const finNo = finalizeV7Transaction({ build: noPos, approvals: approvalsFor(noPos, 1, [0, 1]), fuelSignatureScriptHex: signFuelScript(noPos, 2) });
  emit("vault_recover_without_position", "accept", noPos, finNo.finalTransaction, { contract: "policyvault-0.7-payment" });
}

/* 16-18. DELEGATE SPEND — no root input at all; the frozen v0.5 shape */
const spendParams = (over = {}) => ({ spendAmount: "200", agentPk: XO(agentKey), agents, recipient: XO(recipientKey), recipients: [...rTree.recipients], recipientCarryKasSompi: (KAS / 5n).toString(), reserveConsumedSompi: "50000", ...over });
{
  const build = buildV7Transaction({ config, templateInput: vaultTemplate, stateInput: vaultState(), action: "tokenAgentSpend", params: spendParams(), chain: vaultChain({ tokenPosition: tokenPositionFor(300) }), changeXOnly: XO(fuelKey), descriptor });
  const fin = finalizeV7Transaction({ build, agentSignatureHex: signInput(build, 0, agentKey), fuelSignatureScriptHex: signFuelScript(build, 2) });
  const tx = fin.finalTransaction;
  emit("delegate_spend", "accept", build, tx, { contract: "policyvault-0.7-payment", note: "no root input — the agent path never touches the organization's root" });

  emit("neg_delegate_spend_wrong_signer", "reject", build, finalizeV7Transaction({ build, agentSignatureHex: signInput(build, 0, otherKey), fuelSignatureScriptHex: signFuelScript(build, 2) }).finalTransaction, { contract: "policyvault-0.7-payment" });
  emit("neg_delegate_successor_drained", "reject", build, mutate(tx, (j) => {
    j.outputs[0].value = (BigInt(j.outputs[0].value) - 1000000n).toString();
    j.outputs[3].value = (BigInt(j.outputs[3].value) + 1000000n).toString();
  }), { contract: "policyvault-0.7-payment" });
  emit("neg_delegate_token_family_swapped", "reject", build, mutate(tx, (j) => {
    j.inputs[1].utxo.covenantId = ALIEN_ID;
    j.outputs[1].covenant.covenantId = ALIEN_ID;
    j.outputs[2].covenant.covenantId = ALIEN_ID;
  }), { contract: "policyvault-0.7-payment" });
  emit("neg_delegate_recipient_carry_over_cap", "reject", build, mutate(tx, (j) => {
    j.outputs[2].value = (KAS / 4n + 1n).toString();
    j.outputs[1].value = (2n * KAS - KAS / 4n - 1n).toString();
  }), { contract: "policyvault-0.7-payment" });
  /* a ROOT input riding the agent path: the generalised family closure refuses it */
  const rootCompiled = compileExactStateV7Root({ config, template: rootTemplate, state: rootState() });
  emit("neg_delegate_root_rider", "reject", build, mutate(tx, (j) => {
    j.inputs.splice(2, 0, { previousOutpoint: { transactionId: "04".repeat(32), index: 0 }, signatureScript: "", sequence: "0", computeBudget: 40, utxo: { amount: ROOT_KAS.toString(), scriptPublicKey: { version: 0, scriptHex: p2sh(rootCompiled.scriptBytes) }, covenantId: ROOT_ID, blockDaaScore: "0" } });
    j.outputs.splice(3, 0, { value: ROOT_KAS.toString(), scriptPublicKey: { version: 0, scriptHex: p2sh(rootCompiled.scriptBytes) }, covenant: { authorizingInput: 2, covenantId: ROOT_ID } });
  }), { contract: "policyvault-0.7-payment", note: "the frozen v0.5 requireNoForeignCovenantInputs survived the generator delta" });
}
{
  /* reserve-funded spend (no fuel): reserveConsumed == the exact fee */
  const build = buildV7Transaction({ config, templateInput: vaultTemplate, stateInput: vaultState(), action: "tokenAgentSpend", params: spendParams({ reserveConsumedSompi: undefined }), chain: { predecessorOutpoint: { transactionId: "0a".repeat(32), index: 0 }, covenantId: VAULT_COV_ID, predecessorValue: (5n * KAS).toString(), tokenPosition: tokenPositionFor(300) }, changeXOnly: XO(fuelKey), descriptor });
  const fin = finalizeV7Transaction({ build, agentSignatureHex: signInput(build, 0, agentKey) });
  emit("delegate_spend_reserve_funded", "accept", build, fin.finalTransaction, { contract: "policyvault-0.7-payment" });
}
{
  /* period rollover */
  const spent = agentPolicy(XO(agentKey), { tokenPeriodSpent: "350" });
  const rolloverAgents = [spent, agentPolicy(XO(otherKey))];
  const tree = buildTokenAgentTreeV5(rolloverAgents);
  const build = buildV7Transaction({ config, templateInput: vaultTemplate, stateInput: vaultState({ agentRoot: tree.root }), action: "tokenAgentSpend", params: spendParams({ agents: rolloverAgents, periodsElapsed: "2" }), chain: vaultChain({ tokenPosition: tokenPositionFor(300) }), changeXOnly: XO(fuelKey), descriptor });
  if (build.frozen.lockTime !== 7000n) throw new Error("rollover lockTime must be 7000");
  const fin = finalizeV7Transaction({ build, agentSignatureHex: signInput(build, 0, agentKey), fuelSignatureScriptHex: signFuelScript(build, 2) });
  const tx = fin.finalTransaction;
  emit("delegate_spend_rollover", "accept", build, tx, { contract: "policyvault-0.7-payment" });
  emit("neg_delegate_locktime_forged", "reject", build, mutate(tx, (j) => {
    j.lockTime = "9000";
  }), { contract: "policyvault-0.7-payment" });
}

/* 19. token deposit into a rooted vault (the vault is not an input) */
{
  const user = KEY(0x66);
  const userState = { ownerIdentifier: XO(user), identifierType: 0, amount: "1000", isMinter: false };
  const userProgram = compileKcc20Program({ config, state: userState, familyBound: FAMILY_BOUND });
  const depositChain = { userPosition: { outpoint: { transactionId: "07".repeat(32), index: 0 }, value: (3n * KAS).toString(), scriptPublicKeyHex: userProgram.p2shSpkHex, covenantId: TOKEN_FAMILY, state: userState }, fuel: fuelUtxo("08") };
  const build = buildTokenDepositV7({ config, descriptor, vault: { covenantId: VAULT_COV_ID, template: vaultTemplate }, chain: depositChain, params: { depositAmount: "1000" }, changeXOnly: XO(fuelKey) });
  const fin = finalizeTokenDepositV7({ build, tokenOwnerSignatureHex: signInput(build, 0, user), fuelSignatureScriptHex: signFuelScript(build, 1) });
  emit("token_deposit_full", "accept", build, fin.finalTransaction, { contract: "policyvault-0.7-payment" });
  refuses("deposit_over_position", () => buildTokenDepositV7({ config, descriptor, vault: { covenantId: VAULT_COV_ID, template: vaultTemplate }, chain: depositChain, params: { depositAmount: "1001" }, changeXOnly: XO(fuelKey) }), /INSUFFICIENT_TOKENS/);
  refuses("deposit_descriptor_substitution", () => buildTokenDepositV7({ config, descriptor: { ...descriptor, issuerPowers: { ...descriptor.issuerPowers, freeze: true } }, vault: { covenantId: VAULT_COV_ID, template: vaultTemplate }, chain: depositChain, params: { depositAmount: "1000" }, changeXOnly: XO(fuelKey) }), /DESCRIPTOR_PIN_MISMATCH/);
}

/* ================================================================ SDK REFUSALS */
const rootBuild = (over = {}) => buildV7RootTransaction({ config, templateInput: rootTemplate, stateInput: rootState(), action: "authorize", chain: rootChain(), changeXOnly: XO(fuelKey), ...over });

/* ---- root: state machine + WF(S) ---- */
refuses("root_unknown_action", () => rootBuild({ action: "dissolve" }), /UNKNOWN_ROOT_ACTION/);
refuses("root_unknown_version", () => rootBuild({ contractVersion: "policyvault-0.7" }), /UNKNOWN_VERSION/);
refuses("root_authorize_while_frozen", () => buildV7RootTransaction({ config, templateInput: rootTemplate, stateInput: rootState({ frozen: 1 }), action: "authorize", chain: rootChain(), changeXOnly: XO(fuelKey) }), /ROOT_FROZEN/);
refuses("root_freeze_while_frozen", () => buildV7RootTransaction({ config, templateInput: rootTemplate, stateInput: rootState({ frozen: 1 }), action: "freeze", chain: rootChain(), changeXOnly: XO(fuelKey) }), /ALREADY_FROZEN/);
refuses("root_unfreeze_while_unfrozen", () => buildV7RootTransaction({ config, templateInput: rootTemplate, stateInput: rootState(), action: "unfreeze", chain: rootChain(), changeXOnly: XO(fuelKey) }), /NOT_FROZEN/);
refuses("root_rotate_no_change", () => rootBuild({ action: "rotate", params: { newOwnerSet: ownerSet3 } }), /ROTATE_NO_CHANGE/);
refuses("root_rotate_m_above_active", () => rootBuild({ action: "rotate", params: { newOwnerSet: { owners: slots(ownerKeys.slice(0, 2)), ownerM: 3, emergencyK: 1, recoveryM: 0 } } }), /M_ABOVE_ACTIVE/);
refuses("root_rotate_k_above_m", () => rootBuild({ action: "rotate", params: { newOwnerSet: { owners: slots(newOwnerKeys.slice(0, 3)), ownerM: 2, emergencyK: 3, recoveryM: 0 } } }), /K_ABOVE_M/);
refuses("root_rotate_duplicate_owner_key", () => rootBuild({ action: "rotate", params: { newOwnerSet: { owners: slots([ownerKeys[0], ownerKeys[0], ownerKeys[2]]), ownerM: 2, emergencyK: 1, recoveryM: 0 } } }), /DUPLICATE_OWNER_KEY/);
refuses("root_rotate_noncontiguous_slots", () => {
  const gapped = slots(ownerKeys.slice(0, 3));
  gapped[1] = INACTIVE_SLOT_KEY;
  return rootBuild({ action: "rotate", params: { newOwnerSet: { owners: gapped, ownerM: 1, emergencyK: 1, recoveryM: 0 } } });
}, /NOT_CONTIGUOUS/);
refuses("root_recovery_disabled", () => buildV7RootTransaction({ config, templateInput: rootTemplate, stateInput: rootState({ recoveryM: 0 }), action: "ownerRecover", params: { newOwnerSet: { owners: slots(newOwnerKeys.slice(0, 2)), ownerM: 2, emergencyK: 1, recoveryM: 0 } }, chain: rootChain(), changeXOnly: XO(fuelKey) }), /RECOVERY_DISABLED/);
refuses("root_succession_disabled", () => buildV7RootTransaction({ config, templateInput: { ...rootTemplate, successorPk: INACTIVE_SLOT_KEY }, stateInput: rootState(), action: "succession", params: { newOwnerSet: { owners: slots(newOwnerKeys.slice(0, 2)), ownerM: 2, emergencyK: 1, recoveryM: 1 } }, chain: rootChain(), changeXOnly: XO(fuelKey) }), /SUCCESSION_DISABLED/);
refuses("root_succession_reuses_primary_key(D1)", () => rootBuild({ action: "succession", params: { newOwnerSet: { owners: slots([ownerKeys[0], newOwnerKeys[1]]), ownerM: 2, emergencyK: 1, recoveryM: 1 } } }), /D1_PRIMARY_KEY_UNCHANGED/);
refuses("root_genesis_org_id_mismatch", () => compileExactStateV7Root({ config, template: rootTemplate, state: normalizeRootStateV7({ boundOrgId: "b7".repeat(32), ...ownerSet3, frozen: 0, rootNonce: 0 }) }), /ORG_ID_MISMATCH/);
refuses("root_no_fuel", () => buildV7RootTransaction({ config, templateInput: rootTemplate, stateInput: rootState(), action: "authorize", chain: { ...rootChain(), fuel: undefined }, changeXOnly: XO(fuelKey) }), /FUEL_REQUIRED/);

/* ---- root: the M-of-N finalizer ---- */
{
  const build = authorizeBuild;
  const s1 = signInput(build, 0, ownerKeys[0]);
  const s2 = signInput(build, 0, ownerKeys[1]);
  const fuelScript = signFuelScript(build, 1);
  refuses("finalize_under_quorum", () => finalizeV7RootTransaction({ build, approvals: [{ slot: 1, signatureHex: s1 }], fuelSignatureScriptHex: fuelScript }), /UNDER_QUORUM/);
  refuses("finalize_duplicate_slot", () => finalizeV7RootTransaction({ build, approvals: [{ slot: 1, signatureHex: s1 }, { slot: 1, signatureHex: s2 }], fuelSignatureScriptHex: fuelScript }), /DUPLICATE_SLOT/);
  refuses("finalize_signature_reused_across_slots", () => finalizeV7RootTransaction({ build, approvals: [{ slot: 1, signatureHex: s1 }, { slot: 2, signatureHex: s1 }], fuelSignatureScriptHex: fuelScript }), /SIGNATURE_REUSED/);
  refuses("finalize_key_not_in_set", () => finalizeV7RootTransaction({ build, approvals: [{ slot: 1, signatureHex: s1 }, { publicKey: XO(outsiderKey), signatureHex: s2 }], fuelSignatureScriptHex: fuelScript }), /OWNER_NOT_IN_SET/);
  refuses("finalize_inactive_slot", () => finalizeV7RootTransaction({ build, approvals: [{ slot: 1, signatureHex: s1 }, { slot: 5, signatureHex: s2 }], fuelSignatureScriptHex: fuelScript }), /SLOT_INACTIVE/);
  refuses("finalize_non_all_sighash", () => finalizeV7RootTransaction({ build, approvals: [{ slot: 1, signatureHex: s1.slice(0, -2) + "02" }, { slot: 2, signatureHex: s2 }], fuelSignatureScriptHex: fuelScript }), /SIGHASH_NOT_ALL/);
  refuses("finalize_placeholder_offered_as_signature", () => finalizeV7RootTransaction({ build, approvals: [{ slot: 1, signatureHex: PLACEHOLDER_SLOT_HEX_V7 }, { slot: 2, signatureHex: s2 }], fuelSignatureScriptHex: fuelScript }), /PLACEHOLDER_AS_SIGNATURE/);
  refuses("finalize_slot_key_mismatch", () => finalizeV7RootTransaction({ build, approvals: [{ slot: 1, publicKey: XO(ownerKeys[1]), signatureHex: s1 }, { slot: 2, signatureHex: s2 }], fuelSignatureScriptHex: fuelScript }), /SLOT_KEY_MISMATCH/);
  refuses("finalize_succession_takes_no_approvals", () => finalizeV7RootTransaction({ build, approvals: [{ slot: 1, signatureHex: s1 }], successorSignatureHex: s2, fuelSignatureScriptHex: fuelScript }), /UNEXPECTED_SUCCESSOR_SIGNATURE/);
  refuses("finalize_bad_fuel_sigscript_width", () => finalizeV7RootTransaction({ build, approvals: [{ slot: 1, signatureHex: s1 }, { slot: 2, signatureHex: s2 }], fuelSignatureScriptHex: "ab".repeat(10) }), /fuel signature script/);
}

/* ---- rooted vault ---- */
const vaultBuild = (over = {}) => buildV7Transaction({ config, templateInput: vaultTemplate, stateInput: vaultState(), action: "ownerPause", chain: vaultChain({ root: rootSide(rootState()) }), changeXOnly: XO(fuelKey), descriptor, ...over });
refuses("vault_unknown_action", () => vaultBuild({ action: "ownerRotateDelegate" }), /UNKNOWN_ACTION/);
refuses("vault_unknown_version", () => vaultBuild({ contractVersion: "policyvault-0.5" }), /UNKNOWN_VERSION/);
refuses("vault_owner_op_without_root", () => buildV7Transaction({ config, templateInput: vaultTemplate, stateInput: vaultState(), action: "ownerPause", chain: vaultChain(), changeXOnly: XO(fuelKey), descriptor }), /ROOT_INPUT_REQUIRED/);
refuses("vault_agent_path_with_a_root", () => buildV7Transaction({ config, templateInput: vaultTemplate, stateInput: vaultState(), action: "tokenAgentSpend", params: spendParams(), chain: vaultChain({ root: rootSide(rootState()), tokenPosition: tokenPositionFor(300) }), changeXOnly: XO(fuelKey), descriptor }), /AGENT_PATH_TAKES_NO_ROOT/);
refuses("vault_owner_op_under_a_frozen_root", () => buildV7Transaction({ config, templateInput: vaultTemplate, stateInput: vaultState(), action: "ownerPause", chain: vaultChain({ root: rootSide(rootState({ frozen: 1 })) }), changeXOnly: XO(fuelKey), descriptor }), /ROOT_FROZEN/);
refuses("vault_stale_predecessor_value", () => vaultBuild({ chain: vaultChain({ root: rootSide(rootState()), predecessorValue: (6n * KAS).toString() }) }), /STALE/);
refuses("vault_descriptor_substitution", () => vaultBuild({ descriptor: { ...descriptor, issuerPowers: { ...descriptor.issuerPowers, mint: true } } }), /DESCRIPTOR_PIN_MISMATCH/);
refuses("vault_root_state_len_pin_wrong", () => vaultBuild({ templateInput: { ...vaultTemplate, rootStateLen: 466 } }), /ROOT_GEOMETRY_MISMATCH/);
refuses("vault_root_covenant_id_zero", () => vaultBuild({ templateInput: { ...vaultTemplate, orgRootCovenantId: "00".repeat(32) } }), /ROOT_PIN_MISSING/);
refuses("vault_root_pins_drift", () => assertRootPinsMatchV7({ config, vaultTemplate: { ...vaultTemplate, rootTemplateVmHash: "ee".repeat(32) }, rootTemplate, rootOwnerSet: ownerSet3 }), /ROOT_PIN_DRIFT/);
refuses("vault_root_pins_drift_by_template_constant", () => assertRootPinsMatchV7({ config, vaultTemplate, rootTemplate: { ...rootTemplate, recoveryDelayDaa: "1001" }, rootOwnerSet: ownerSet3 }), /ROOT_PIN_DRIFT/);
refuses("vault_spend_over_cap", () => buildV7Transaction({ config, templateInput: vaultTemplate, stateInput: vaultState(), action: "tokenAgentSpend", params: spendParams({ spendAmount: "251" }), chain: vaultChain({ tokenPosition: tokenPositionFor(300) }), changeXOnly: XO(fuelKey), descriptor }), /OVER_CAP/);
refuses("vault_spend_while_paused", () => buildV7Transaction({ config, templateInput: vaultTemplate, stateInput: vaultState({ paused: "1" }), action: "tokenAgentSpend", params: spendParams(), chain: vaultChain({ tokenPosition: tokenPositionFor(300) }), changeXOnly: XO(fuelKey), descriptor }), /PAUSED/);
refuses("vault_spend_carry_over_cap", () => buildV7Transaction({ config, templateInput: vaultTemplate, stateInput: vaultState(), action: "tokenAgentSpend", params: spendParams({ recipientCarryKasSompi: (KAS / 4n + 1n).toString() }), chain: vaultChain({ tokenPosition: tokenPositionFor(300) }), changeXOnly: XO(fuelKey), descriptor }), /OVER_CARRY_CAP/);
refuses("vault_spend_token_not_owned", () => {
  const st = { ownerIdentifier: XO(otherKey), identifierType: 0, amount: "300", isMinter: false };
  const p = compileKcc20Program({ config, state: st, familyBound: FAMILY_BOUND });
  return buildV7Transaction({ config, templateInput: vaultTemplate, stateInput: vaultState(), action: "tokenAgentSpend", params: spendParams(), chain: vaultChain({ tokenPosition: { ...tokenPositionFor(300), state: st, scriptPublicKeyHex: p.p2shSpkHex } }), changeXOnly: XO(fuelKey), descriptor });
}, /TOKEN_NOT_OWNED/);
refuses("vault_wrong_token_family", () => buildV7Transaction({ config, templateInput: vaultTemplate, stateInput: vaultState(), action: "tokenAgentSpend", params: spendParams(), chain: vaultChain({ tokenPosition: { ...tokenPositionFor(300), covenantId: ALIEN_ID } }), changeXOnly: XO(fuelKey), descriptor }), /WRONG_TOKEN_FAMILY/);

/* ---- the rooted-vault finalizer ---- */
{
  const b = ownerOpBuilds.vault_owner_pause.build;
  const fuelScript = signFuelScript(b, 2);
  refuses("vault_owner_path_takes_no_signature", () => finalizeV7Transaction({ build: b, agentSignatureHex: signInput(b, 0, ownerKeys[0]), approvals: approvalsFor(b, 1, [0, 1]), fuelSignatureScriptHex: fuelScript }), /OWNER_PATH_TAKES_NO_SIGNATURE/);
  refuses("vault_owner_path_under_quorum", () => finalizeV7Transaction({ build: b, approvals: approvalsFor(b, 1, [0]), fuelSignatureScriptHex: fuelScript }), /UNDER_QUORUM/);
  refuses("vault_owner_path_outsider_approval", () => finalizeV7Transaction({ build: b, approvals: [...approvalsFor(b, 1, [0]), { publicKey: XO(outsiderKey), signatureHex: signInput(b, 1, outsiderKey) }], fuelSignatureScriptHex: fuelScript }), /OWNER_NOT_IN_SET/);
}
{
  const b = buildV7Transaction({ config, templateInput: vaultTemplate, stateInput: vaultState(), action: "tokenAgentSpend", params: spendParams(), chain: vaultChain({ tokenPosition: tokenPositionFor(300) }), changeXOnly: XO(fuelKey), descriptor });
  refuses("vault_agent_path_takes_no_approvals", () => finalizeV7Transaction({ build: b, agentSignatureHex: signInput(b, 0, agentKey), approvals: [{ slot: 1, signatureHex: signInput(b, 0, ownerKeys[0]) }], fuelSignatureScriptHex: signFuelScript(b, 2) }), /AGENT_PATH_TAKES_NO_APPROVALS/);
  refuses("vault_agent_non_all_sighash", () => finalizeV7Transaction({ build: b, agentSignatureHex: signInput(b, 0, agentKey).slice(0, -2) + "02", fuelSignatureScriptHex: signFuelScript(b, 2) }), /SIGHASH_NOT_ALL/);
}

/* ---- manifest routing ---- */
refuses("router_unknown_contract_version", () => routeIntentManifestBuilder("policyvault-0.8"), /UNKNOWN_VERSION/);
refuses("router_unknown_verifier_version", () => routeIntentManifestVerifier("policyvault-0.8"), /UNKNOWN_VERSION/);

/* ================================================================ INDEX */
fs.writeFileSync(
  path.join(outDir, "index.json"),
  JSON.stringify({ vectors, refusals, manifests, descriptorHash, rootPins, vaultTemplate, rootTemplate }, null, 1)
);
const unrefused = refusals.filter((r) => !r.refused || r.ok === false);
if (unrefused.length) {
  console.error("SDK did not refuse (or refused with the wrong code):", JSON.stringify(unrefused, null, 1));
  process.exit(2);
}
const badManifests = manifests.filter((m) => m.verdict !== "VERIFIED");
if (badManifests.length) {
  console.error("org-root manifests must verify:", JSON.stringify(badManifests, null, 1));
  process.exit(4);
}
console.log(`emitted ${vectors.length} vectors (${vectors.filter((v) => v.expect === "accept").length} accept / ${vectors.filter((v) => v.expect === "reject").length} reject), ${refusals.length} SDK refusals, ${manifests.length} verified manifests`);
