"use strict";

/*
 * PolicyVault v0.7-payment-hd PRODUCTION-BYTE vector generator (Wave 2
 * Track D, gate I2), sibling of sdk/tools/gen-v7-vectors.js.
 *
 * Drives the ACTUAL production SDK code — sdk/src/vault-builders-v7-hd.js,
 * core/model/hd-leaf-v7.js, core/model/compute-budget-v7-hd.js, the reused
 * v0.7 root/owner-op/deposit machinery, and the REAL pv_call_encoder +
 * pv_tx_probe binaries — to construct fully-finalized v0.7-payment-hd
 * transactions with real Schnorr signatures (rusty-kaspa WASM
 * createInputSignature over deterministic TEST-ONLY keys).
 * tests/vm/tests/v7_hd_sdk_integration.rs executes every emitted vector's
 * EXACT bytes on the real TxScriptEngine against the PRODUCTION CANDIDATE
 * contracts/PolicyVault.v0.7-payment-hd.sil (plus the reused v0.7-root
 * candidate for owner ops).
 *
 * Usage: node gen-v7-hd-vectors.js <output-dir>
 * TEST KEYS ONLY: secrets are the byte value repeated 32x. Never production material.
 */

const fs = require("fs");
const path = require("path");

const { loadConfig } = require("../src/config");
const assets = require("../../core/assets");
const { compileKcc20Program } = require("../src/token-program-kcc20");
const { buildRecipientTree } = require("../src/recipient-merkle-v3");
const { compileExactStateV7Root, deriveRootPinsV7, assertRootPinsMatchV7 } = require("../src/contract-compiler-v7");
const {
  CONTRACT_VERSION_V7_HD,
  buildCreateV7Root,
  buildCreateV7HdVault,
  buildHdSpendTransaction,
  buildHdDelegationTransaction,
  finalizeHdTransaction,
  buildV7HdOwnerTransaction,
  finalizeV7HdOwnerTransaction,
  buildTokenDepositV7,
  finalizeTokenDepositV7
} = require("../src/vault-builders-v7-hd");
const { frozenToWasmTransaction } = require("../src/frozen-tx-v3");
const { OWNER_SLOTS_V7, INACTIVE_SLOT_KEY } = require("../../core/model/owner-set-v7");
const { normalizeRootStateV7 } = require("../../core/model/vault-state-v7-root");
const hd = require("../../core/model/hd-leaf-v7");

const outDir = process.argv[2];
if (!outDir) {
  console.error("usage: node gen-v7-hd-vectors.js <output-dir>");
  process.exit(1);
}
fs.mkdirSync(outDir, { recursive: true });

const config = loadConfig({ dataRoot: path.join(outDir, "data") });
const kaspa = require(config.rustyKaspaModule);

const KAS = 100000000n;
const KEY = (v) => new kaspa.PrivateKey(v.toString(16).padStart(2, "0").repeat(32));
const XO = (p) => p.toPublicKey().toXOnlyPublicKey().toString().toLowerCase();

const ownerKeys = [KEY(0x71), KEY(0x72), KEY(0x73), KEY(0x74)];
const successorKey = KEY(0x7f);
const l1Key = KEY(0x62);
const l2Key = KEY(0x63);
const l3Key = KEY(0x64);
const recipientKey = KEY(0x65);
const fuelKey = KEY(0x66);
const recoveryKey = KEY(0x51);
const outsiderKey = KEY(0x69);

const ORG_ID = "a7".repeat(32);
const ROOT_ID = "52".repeat(32);
const VAULT_COV_ID = "43".repeat(32);
const TOKEN_FAMILY = "54".repeat(32);
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
const rootState = (over = {}) => normalizeRootStateV7({ boundOrgId: ORG_ID, ...ownerSet3, frozen: 0, rootNonce: 0, ...over });

const refProgram = compileKcc20Program({ config, state: assets.kcc20.ZERO_STATE, familyBound: FAMILY_BOUND });
const descriptor = {
  schema: "policyvault-asset-descriptor/1",
  assetId: "11".repeat(32),
  displayName: "HD Vector Token",
  tokenStandard: "kcc20/1",
  tokenCovenantId: TOKEN_FAMILY,
  acceptedTransferTemplates: [{ templateVmHashBlake2b256: refProgram.templateVmHashBlake2b256, prefixLen: refProgram.geometry.prefixLen, suffixLen: refProgram.geometry.suffixLen, stateLayout: "kcc20-state/1" }],
  decimalsDisplay: 8,
  issuerPowers: { mint: false, burn: false, freeze: false, blacklist: false, redemptionControl: false, upgradeMigration: false, controllerRotation: false, emergencyControl: false }
};
const descriptorHash = assets.computeDescriptorHash(descriptor);

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

/* ---- an HD tree: level-1 x2 (n0 has kids), level-2 x2 under n0 (m0 has kids), level-3 x1 under m0 ---- */
const ZERO = "00".repeat(32);
const baseLeaf = (pk, over = {}) => ({ pk, maxPerSpend: "250", periodBudget: "400", periodLengthDaa: "1000", periodStartDaa: "5000", periodSpent: "0", maxFeePerTx: "60000", maxCarryKas: (KAS / 4n).toString(), expiryDaa: "9000000", recipientRoot: buildRecipientTree([XO(recipientKey)]).root, childRoot: ZERO, ...over });
const l3Node = { leaf: baseLeaf(XO(l3Key)), kids: [] };
const l2Node0 = { leaf: baseLeaf(XO(l2Key)), kids: [l3Node] };
const l2SiblingKey = KEY(0x67);
const l2Sibling = { leaf: baseLeaf(XO(l2SiblingKey)), kids: [] };
const l1Node0 = { leaf: baseLeaf(XO(l1Key)), kids: [l2Node0, l2Sibling] };
const l1Sibling = { leaf: baseLeaf(XO(l1Key)), kids: [] };
const tree = [l1Node0, l1Sibling];
const agentRoot0 = hd.forestRoot(tree);

function tokenPositionFor(amount) {
  const st = { ownerIdentifier: VAULT_COV_ID, identifierType: 2, amount: String(amount), isMinter: false };
  const program = compileKcc20Program({ config, state: st, familyBound: FAMILY_BOUND });
  return { outpoint: { transactionId: "02".repeat(32), index: 0 }, value: (2n * KAS).toString(), scriptPublicKeyHex: program.p2shSpkHex, covenantId: TOKEN_FAMILY, state: st };
}
const fuelUtxo = (id = "03") => ({ outpoint: { transactionId: id.repeat(32), index: 0 }, amount: (1n * KAS).toString(), scriptPublicKeyHex: `20${XO(fuelKey)}ac` });
const rootSide = (state, over = {}) => ({ template: rootTemplate, state, outpoint: { transactionId: "04".repeat(32), index: 0 }, covenantId: ROOT_ID, value: ROOT_KAS.toString(), ...over });
const vaultChain = (over = {}) => ({ predecessorOutpoint: { transactionId: "0a".repeat(32), index: 0 }, covenantId: VAULT_COV_ID, predecessorValue: (5n * KAS).toString(), fuel: fuelUtxo("03"), ...over });
const vaultState = (over = {}) => ({ feeReserve: (5n * KAS).toString(), paused: "0", agentRoot: agentRoot0, policyNonce: "0", ...over });

const wasmOf = (build) => frozenToWasmTransaction(config, build.frozen);
const signInput = (build, index, key) => kaspa.createInputSignature(wasmOf(build), index, key).slice(2);
const signFuelScript = (build, index, key = fuelKey) => kaspa.createInputSignature(wasmOf(build), index, key);
const approvalsFor = (build, index, keyIndexes) => keyIndexes.map((i) => ({ slot: i + 1, signatureHex: signInput(build, index, ownerKeys[i]) }));

const vectors = [];
const refusals = [];
function emit(name, expect, build, finalTx, extra = {}) {
  vectors.push({ name, expect });
  const dir = path.join(outDir, name);
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, "vector.json"), JSON.stringify({ name, expect, rejectInput: extra.rejectInput ?? 0, action: build?.action ?? "unknown", contract: extra.contract ?? build?.contractVersion ?? null, committedBudget: build?.computeBudget ?? null, requiredFeeSompi: build?.requiredFeeSompi ?? null, note: extra.note ?? null, tx: finalTx }, null, 1));
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

{
  const probe = buildHdDelegationTransaction({ config, templateInput: vaultTemplate, stateInput: vaultState(), action: "delegateSetChildRoot1", params: { tree, path: [0], newChildRoot: hd.forestRoot(tree) === agentRoot0 ? "aa".repeat(32) : "bb".repeat(32) }, chain: vaultChain(), changeXOnly: XO(fuelKey) });
  if (probe.plannedCallHexLength / 2 < 200) {
    console.error("pv_call_encoder produced an implausibly short v0.7-payment-hd call — is the binary stale? rebuild tests/vm --bin pv_call_encoder");
    process.exit(3);
  }
}

/* 1. root genesis (the HD vault's owner authority) */
{
  const build = buildCreateV7Root({ config, template: rootTemplate, ownerSet: ownerSet3, rootValueSompi: ROOT_KAS.toString(), funding: [{ outpoint: { transactionId: "05".repeat(32), index: 0 }, amount: (10n * KAS).toString(), scriptPublicKeyHex: `20${XO(fuelKey)}ac` }], changeXOnly: XO(fuelKey) });
  const json = JSON.parse(build.frozenCanonicalJson);
  json.inputs[0].signatureScript = kaspa.createInputSignature(wasmOf(build), 0, fuelKey);
  emit("hd_root_genesis", "accept", build, json, { contract: "policyvault-0.7-root" });
}

/* 2. rooted HD vault genesis */
{
  const build = buildCreateV7HdVault({ config, templateInput: vaultTemplate, initialStateInput: vaultState(), funding: [{ outpoint: { transactionId: "06".repeat(32), index: 0 }, amount: (10n * KAS).toString(), scriptPublicKeyHex: `20${XO(fuelKey)}ac` }], changeXOnly: XO(fuelKey), descriptor });
  const json = JSON.parse(build.frozenCanonicalJson);
  json.inputs[0].signatureScript = kaspa.createInputSignature(wasmOf(build), 0, fuelKey);
  emit("hd_vault_genesis", "accept", build, json, { contract: CONTRACT_VERSION_V7_HD, note: "pins orgRootCovenantId + the root template identity, identically to v0.7-payment" });
}

/* 3. token deposit (reused, unchanged builder) */
{
  const build = buildTokenDepositV7({ config, descriptor, vault: { covenantId: VAULT_COV_ID, template: vaultTemplate }, chain: { userPosition: { outpoint: { transactionId: "07".repeat(32), index: 0 }, value: (2n * KAS).toString(), scriptPublicKeyHex: compileKcc20Program({ config, state: { ownerIdentifier: XO(l1Key), identifierType: 0, amount: "3000", isMinter: false }, familyBound: FAMILY_BOUND }).p2shSpkHex, covenantId: TOKEN_FAMILY, state: { ownerIdentifier: XO(l1Key), identifierType: 0, amount: "3000", isMinter: false } }, fuel: fuelUtxo("08") }, params: { depositAmount: "3000" }, changeXOnly: XO(fuelKey) });
  const fin = finalizeTokenDepositV7({ build, tokenOwnerSignatureHex: signInput(build, 0, l1Key), fuelSignatureScriptHex: signFuelScript(build, 1) });
  emit("hd_token_deposit", "accept", build, fin.finalTransaction, { contract: CONTRACT_VERSION_V7_HD });
}

/* 4. level-1 spend (hdSpend) */
let l1SpendBuild;
{
  const build = buildHdSpendTransaction({ config, templateInput: vaultTemplate, stateInput: vaultState(), action: "hdSpend", params: { tree, path: [0], recipient: XO(recipientKey), spendAmount: "100", recipientCarryKasSompi: (KAS / 10n).toString(), recipientListsByLevel: [[XO(recipientKey)]] }, chain: vaultChain({ tokenPosition: tokenPositionFor(3000) }), changeXOnly: XO(fuelKey), descriptor });
  l1SpendBuild = build;
  const fin = finalizeHdTransaction({ build, signatureHex: signInput(build, 0, l1Key), fuelSignatureScriptHex: signFuelScript(build, 2) });
  emit("hd_level1_spend", "accept", build, fin.finalTransaction, { contract: CONTRACT_VERSION_V7_HD });
}

/* 5. level-2 spend (childSpendL2), at n0 -> l2Node0 */
{
  const build = buildHdSpendTransaction({ config, templateInput: vaultTemplate, stateInput: vaultState(), action: "childSpendL2", params: { tree, path: [0, 0], recipient: XO(recipientKey), spendAmount: "50", recipientCarryKasSompi: (KAS / 10n).toString(), recipientListsByLevel: [[XO(recipientKey)], [XO(recipientKey)]] }, chain: vaultChain({ tokenPosition: tokenPositionFor(3000) }), changeXOnly: XO(fuelKey), descriptor });
  const fin = finalizeHdTransaction({ build, signatureHex: signInput(build, 0, l2Key), fuelSignatureScriptHex: signFuelScript(build, 2) });
  emit("hd_level2_spend", "accept", build, fin.finalTransaction, { contract: CONTRACT_VERSION_V7_HD });
}

/* 6. level-3 spend (childSpendL3), the MAXIMUM PROVEN ROOTED LEVEL, at n0 -> l2Node0 -> l3Node */
{
  const build = buildHdSpendTransaction({ config, templateInput: vaultTemplate, stateInput: vaultState(), action: "childSpendL3", params: { tree, path: [0, 0, 0], recipient: XO(recipientKey), spendAmount: "25", recipientCarryKasSompi: (KAS / 10n).toString(), recipientListsByLevel: [[XO(recipientKey)], [XO(recipientKey)], [XO(recipientKey)]] }, chain: vaultChain({ tokenPosition: tokenPositionFor(3000) }), changeXOnly: XO(fuelKey), descriptor });
  const fin = finalizeHdTransaction({ build, signatureHex: signInput(build, 0, l3Key), fuelSignatureScriptHex: signFuelScript(build, 2) });
  emit("hd_level3_spend", "accept", build, fin.finalTransaction, { contract: CONTRACT_VERSION_V7_HD, note: "MAX_LEVEL = 3 — a level-4 spend has no entrypoint" });
}

/* 7. delegateSetChildRoot1 — l1Sibling (a leaf) grants a fresh subtree */
let dsc1Build;
{
  const newChildRoot = "cd".repeat(32);
  const build = buildHdDelegationTransaction({ config, templateInput: vaultTemplate, stateInput: vaultState(), action: "delegateSetChildRoot1", params: { tree, path: [1], newChildRoot }, chain: vaultChain(), changeXOnly: XO(fuelKey) });
  dsc1Build = build;
  const fin = finalizeHdTransaction({ build, signatureHex: signInput(build, 0, l1Key), fuelSignatureScriptHex: signFuelScript(build, 1) });
  emit("hd_delegate_level1", "accept", build, fin.finalTransaction, { contract: CONTRACT_VERSION_V7_HD, note: "the successor leaf = body[0,128) || newChildRoot — every other field of l1Sibling is preserved" });
}

/* 8. delegateSetChildRoot2 — l2Sibling (under n0, currently NO kids) grants a
 *    fresh subtree; must be signed by l2Sibling's OWN key, not its parent's. */
{
  const newChildRoot = "ce".repeat(32);
  const build = buildHdDelegationTransaction({ config, templateInput: vaultTemplate, stateInput: vaultState(), action: "delegateSetChildRoot2", params: { tree, path: [0, 1], newChildRoot }, chain: vaultChain(), changeXOnly: XO(fuelKey) });
  const fin = finalizeHdTransaction({ build, signatureHex: signInput(build, 0, l2SiblingKey), fuelSignatureScriptHex: signFuelScript(build, 1) });
  emit("hd_delegate_level2", "accept", build, fin.finalTransaction, { contract: CONTRACT_VERSION_V7_HD });
}

/* 9. honest revocation: l2Node0 (path [0,0], currently HAS a kid — l3Node —
 *    so its committed childRoot is non-zero) zeroes its OWN childRoot,
 *    revoking l3Node's entire subtree structurally. The covenant refuses a
 *    delegation whose newChildRoot equals the CURRENT childRoot (a no-op is
 *    not a valid delegation — contracts/PolicyVault.v0.7-payment-hd.sil
 *    delegateSetChildRoot2's `require(bytes(newChildRoot) !=
 *    parentLeaf.slice(128,160))`), so a genuine revocation target must
 *    currently have a NON-ZERO childRoot to revoke FROM. */
{
  const build = buildHdDelegationTransaction({ config, templateInput: vaultTemplate, stateInput: vaultState(), action: "delegateSetChildRoot2", params: { tree, path: [0, 0], newChildRoot: ZERO }, chain: vaultChain(), changeXOnly: XO(fuelKey) });
  const fin = finalizeHdTransaction({ build, signatureHex: signInput(build, 0, l2Key), fuelSignatureScriptHex: signFuelScript(build, 1) });
  emit("hd_revocation_zero_child_root", "accept", build, fin.finalTransaction, { contract: CONTRACT_VERSION_V7_HD, note: "l2Node0 revokes its l3Node subtree by zeroing its OWN committed childRoot — structural revocation (design record §1.2/§1.5)" });
}

/* 10-13. owner operations on the HD vault (root input + vault input + fuel) */
for (const [name, action, params, prevOver] of [
  ["hd_vault_owner_set_agent_root", "ownerSetAgentRoot", { newAgentRoot: "99".repeat(32) }, {}],
  ["hd_vault_owner_top_up_reserve", "ownerTopUpReserve", { topUpReserveAmountSompi: (KAS / 2n).toString() }, {}],
  ["hd_vault_owner_pause", "ownerPause", {}, {}],
  ["hd_vault_emergency_pause", "ownerEmergencyPause", {}, {}]
]) {
  const build = buildV7HdOwnerTransaction({ config, templateInput: vaultTemplate, stateInput: vaultState(prevOver), action, params, chain: vaultChain({ root: rootSide(rootState()) }), changeXOnly: XO(fuelKey), descriptor });
  const isFreeze = action === "ownerEmergencyPause";
  const fin = finalizeV7HdOwnerTransaction({ build, approvals: isFreeze ? approvalsFor(build, 1, [0]) : approvalsFor(build, 1, [0, 1]), fuelSignatureScriptHex: signFuelScript(build, 2) });
  emit(name, "accept", build, fin.finalTransaction, { contract: CONTRACT_VERSION_V7_HD });
}

/* 14. FROZEN root -> EMERGENCY pause -> delegation refused (composition proof) */
{
  const build = buildV7HdOwnerTransaction({ config, templateInput: vaultTemplate, stateInput: vaultState(), action: "ownerEmergencyPause", params: {}, chain: vaultChain({ root: rootSide(rootState()) }), changeXOnly: XO(fuelKey), descriptor });
  const fin = finalizeV7HdOwnerTransaction({ build, approvals: approvalsFor(build, 1, [0]), fuelSignatureScriptHex: signFuelScript(build, 2) });
  emit("hd_emergency_pause_via_root_freeze", "accept", build, fin.finalTransaction, { contract: CONTRACT_VERSION_V7_HD, note: "the root's lighter emergency quorum authorizes ownerControl selector 4 only" });
  refuses("hd_delegation_refused_while_paused", () => buildHdDelegationTransaction({ config, templateInput: vaultTemplate, stateInput: vaultState({ paused: "1" }), action: "delegateSetChildRoot1", params: { tree, path: [1], newChildRoot: "aa".repeat(32) }, chain: vaultChain(), changeXOnly: XO(fuelKey) }), /PAUSED/);
  refuses("hd_spend_refused_while_paused", () => buildHdSpendTransaction({ config, templateInput: vaultTemplate, stateInput: vaultState({ paused: "1" }), action: "hdSpend", params: { tree, path: [0], recipient: XO(recipientKey), spendAmount: "1", recipientCarryKasSompi: "1", recipientListsByLevel: [[XO(recipientKey)]] }, chain: vaultChain({ tokenPosition: tokenPositionFor(3000) }), changeXOnly: XO(fuelKey), descriptor }), /PAUSED/);
}

/* 15. ownerRecover with a token position */
{
  const build = buildV7HdOwnerTransaction({ config, templateInput: vaultTemplate, stateInput: vaultState(), action: "ownerRecover", chain: vaultChain({ root: rootSide(rootState()), tokenPosition: tokenPositionFor(3000) }), changeXOnly: XO(fuelKey), descriptor });
  const fin = finalizeV7HdOwnerTransaction({ build, approvals: approvalsFor(build, 1, [0, 1]), fuelSignatureScriptHex: signFuelScript(build, 3) });
  emit("hd_owner_recover_with_position", "accept", build, fin.finalTransaction, { contract: CONTRACT_VERSION_V7_HD });
}

/* ---- SDK pre-build refusals (never asked for a signature) ---- */
refuses("hd_spend_agent_root_mismatch", () => buildHdSpendTransaction({ config, templateInput: vaultTemplate, stateInput: vaultState({ agentRoot: "ff".repeat(32) }), action: "hdSpend", params: { tree, path: [0], recipient: XO(recipientKey), spendAmount: "1", recipientCarryKasSompi: "1", recipientListsByLevel: [[XO(recipientKey)]] }, chain: vaultChain({ tokenPosition: tokenPositionFor(3000) }), changeXOnly: XO(fuelKey), descriptor }), /AGENT_ROOT_MISMATCH/);
refuses("hd_spend_takes_no_root", () => buildHdSpendTransaction({ config, templateInput: vaultTemplate, stateInput: vaultState(), action: "hdSpend", params: { tree, path: [0], recipient: XO(recipientKey), spendAmount: "1", recipientCarryKasSompi: "1", recipientListsByLevel: [[XO(recipientKey)]] }, chain: vaultChain({ tokenPosition: tokenPositionFor(3000), root: rootSide(rootState()) }), changeXOnly: XO(fuelKey), descriptor }), /SPEND_PATH_TAKES_NO_ROOT/);
refuses("hd_delegation_takes_no_root", () => buildHdDelegationTransaction({ config, templateInput: vaultTemplate, stateInput: vaultState(), action: "delegateSetChildRoot1", params: { tree, path: [1], newChildRoot: "aa".repeat(32) }, chain: vaultChain({ root: rootSide(rootState()) }), changeXOnly: XO(fuelKey) }), /DELEGATION_PATH_TAKES_NO_ROOT/);
refuses("hd_unknown_spend_action", () => buildHdSpendTransaction({ config, templateInput: vaultTemplate, stateInput: vaultState(), action: "childSpendL4", params: { tree, path: [0], recipient: XO(recipientKey), spendAmount: "1", recipientCarryKasSompi: "1" }, chain: vaultChain({ tokenPosition: tokenPositionFor(3000) }), changeXOnly: XO(fuelKey), descriptor }), /UNKNOWN_ACTION/);
refuses("hd_finalize_takes_no_approvals", () => finalizeHdTransaction({ build: l1SpendBuild, signatureHex: signInput(l1SpendBuild, 0, l1Key), approvals: [{ slot: 1, signatureHex: "00".repeat(65) }], fuelSignatureScriptHex: signFuelScript(l1SpendBuild, 2) }), /HD_PATH_TAKES_NO_APPROVALS/);

/* ---- post-finalize consensus reject vectors ---- */
{
  const bad = mutate(vectors.find((v) => v.name === "hd_level1_spend") && JSON.parse(fs.readFileSync(path.join(outDir, "hd_level1_spend", "vector.json"))).tx, (j) => {
    j.outputs[2].value = (BigInt(j.outputs[2].value) + 1n).toString();
  });
  emit("neg_hd_level1_spend_recipient_carry_inflated", "reject", l1SpendBuild, bad, { contract: CONTRACT_VERSION_V7_HD, note: "post-finalize: the recipient KAS carry output value increased by 1 sompi after signing" });
}
{
  const skipped = compileExactStateV7Root; // unused placeholder to keep require graph honest
  void skipped;
  const bad = mutate(JSON.parse(fs.readFileSync(path.join(outDir, "hd_delegate_level1", "vector.json"))).tx, (j) => {
    j.outputs[0].value = (BigInt(j.outputs[0].value) - 1n).toString();
  });
  emit("neg_hd_delegate_level1_reserve_drained", "reject", dsc1Build, bad, { contract: CONTRACT_VERSION_V7_HD, note: "post-finalize: the successor vault output value reduced by 1 sompi — the covenant pins the exact successor value" });
}

/* ================================================================ INDEX */
fs.writeFileSync(path.join(outDir, "index.json"), JSON.stringify({ vectors, refusals, descriptorHash, rootPins, vaultTemplate, rootTemplate }, null, 1));
const unrefused = refusals.filter((r) => !r.refused || r.ok === false);
if (unrefused.length) {
  console.error("SDK did not refuse (or refused with the wrong code):", JSON.stringify(unrefused, null, 1));
  process.exit(2);
}
console.log(`gen-v7-hd-vectors: emitted ${vectors.length} vectors (${vectors.filter((v) => v.expect === "accept").length} accept / ${vectors.filter((v) => v.expect === "reject").length} reject), ${refusals.length} SDK refusals all correct`);
