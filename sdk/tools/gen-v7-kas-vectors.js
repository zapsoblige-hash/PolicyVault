"use strict";

/*
 * PolicyVault v0.7-kas PRODUCTION-BYTE vector generator (ROOTED KAS
 * SAFE-PAYMENT VAULT).
 *
 * Sibling of sdk/tools/gen-v7-vectors.js (the rooted PAYMENT profile).
 * Drives the ACTUAL production SDK code — core/model (owner-set-v7,
 * vault-state-v7-root, vault-state-v7-kas, vault-transitions-v7-root,
 * vault-transitions-v7-kas, vault-state-v4, vault-transitions-v4,
 * compute-budget-v7-kas), sdk/src/contract-compiler-v7(-kas) (silverc),
 * agent-merkle-v4, recipient-merkle-v3, frozen-tx-v3, approval-package-v4,
 * vault-builders-v7-kas, core/intent/org-root-manifest-v7-kas and
 * core/intent/router — and the REAL pv_call_encoder + pv_tx_probe binaries
 * — to construct fully-finalized v0.7-kas transactions with real Schnorr
 * signatures (rusty-kaspa WASM createInputSignature over deterministic
 * TEST-ONLY keys). tests/vm/tests/v7_kas_sdk_integration.rs executes every
 * emitted vector's EXACT bytes on the real TxScriptEngine against the
 * PRODUCTION candidates contracts/PolicyVault.v0.7-root.sil and
 * contracts/PolicyVault.v0.7-kas.sil.
 *
 * Negative vectors are otherwise-valid transactions with ONE security field
 * mutated AFTER freeze/finalize (the SDK itself refuses to build them, and
 * the SDK refusal matrix below proves that separately) and MUST be
 * rejected by consensus. Each carries `rejectInput`.
 *
 * Usage: node gen-v7-kas-vectors.js <output-dir>
 * TEST KEYS ONLY: secrets are the byte value repeated 32x. Never production material.
 */

const fs = require("fs");
const path = require("path");

const { loadConfig } = require("../src/config");
const { buildAgentTreeV4, generateAgentProofV4 } = require("../src/agent-merkle-v4");
const { buildRecipientTree } = require("../src/recipient-merkle-v3");
const { compileExactStateV7Root, deriveRootPinsV7 } = require("../src/contract-compiler-v7");
const { compileExactStateV7Kas, assertRootPinsMatchV7Kas } = require("../src/contract-compiler-v7-kas");
const {
  buildCreateV7Root,
  buildV7RootTransaction,
  finalizeV7RootTransaction,
  buildCreateV7KasVault,
  buildV7KasTransaction,
  finalizeV7KasTransaction,
  createApprovalPackageForBuildV7Kas,
  successorCallJsonV7Kas
} = require("../src/vault-builders-v7-kas");
const { runEncoderV4 } = require("../src/vault-builders-v4");
const { frozenToWasmTransaction } = require("../src/frozen-tx-v3");
const { OWNER_SLOTS_V7, INACTIVE_SLOT_KEY, PLACEHOLDER_SLOT_HEX_V7 } = require("../../core/model/owner-set-v7");
const { normalizeRootStateV7 } = require("../../core/model/vault-state-v7-root");
const { submitApprovalV4, approvalsBlobV4, placeholderApprovalsBlob } = require("../src/approval-package-v4");
const { covenantSigscript } = require("../src/spend-vault");
const { buildOrgRootIntentManifestV7Kas, verifyOrgRootIntentManifestV7Kas, buildRootedKasVaultManifestV7 } = require("../../core/intent/org-root-manifest-v7-kas");
const { routeIntentManifestBuilder } = require("../../core/intent/router");

const outDir = process.argv[2];
if (!outDir) {
  console.error("usage: node gen-v7-kas-vectors.js <output-dir>");
  process.exit(1);
}
fs.mkdirSync(outDir, { recursive: true });

const config = loadConfig({ dataRoot: path.join(outDir, "data") });
const kaspa = require(config.rustyKaspaModule);

const KAS = 100000000n;
const KEY = (v) => new kaspa.PrivateKey(v.toString(16).padStart(2, "0").repeat(32));
const XO = (p) => p.toPublicKey().toXOnlyPublicKey().toString().toLowerCase();

const ownerKeys = [KEY(0x71), KEY(0x72), KEY(0x73)];
const successorKey = KEY(0x7f);
const outsiderKey = KEY(0x6f);
const agentKey = KEY(0x30);
const otherAgentKey = KEY(0x31);
const recipientKey = KEY(0x40);
const otherKey = KEY(0x41);
const fuelKey = KEY(0x64);
const recoveryKey = KEY(0x51);
const approvers3 = [KEY(0x91), KEY(0x92), KEY(0x93)];
const approvers10 = Array.from({ length: 10 }, (_, i) => KEY(0xa0 + i));

const ORG_ID = "a7".repeat(32);
const ROOT_ID = "52".repeat(32);
const VAULT_COV_ID = "44".repeat(32);
const ALIEN_ID = "57".repeat(32);
const VAULT_ID = "44".repeat(32);
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
const ownerSet3 = { owners: slots(ownerKeys), ownerM: 2, emergencyK: 1, recoveryM: 2 };
const rootState = (over = {}) => normalizeRootStateV7({ boundOrgId: ORG_ID, ...ownerSet3, frozen: 0, rootNonce: 0, ...over });

const rootPins = deriveRootPinsV7({ config, template: rootTemplate, ownerSet: ownerSet3, covenantId: ROOT_ID });
const vaultTemplate = { vaultId: VAULT_ID, ...rootPins, recoveryPk: XO(recoveryKey) };
assertRootPinsMatchV7Kas({ config, vaultTemplate, rootTemplate, rootOwnerSet: ownerSet3 });

/* ---- agent policy / recipient trees (frozen v0.4.1 shapes) ---- */
function recipTreeAtDepth(depth) {
  if (depth === 0) return buildRecipientTree([XO(recipientKey)]);
  const n = 1 << depth;
  const fillers = [];
  for (let i = 0; fillers.length < n - 1 && i <= 0xffffff; i += 1) {
    const k = i.toString(16).padStart(6, "0").repeat(11).slice(0, 64);
    if (k !== XO(recipientKey) && k !== XO(otherKey)) fillers.push(k);
  }
  if (fillers.length !== n - 1) throw new Error(`could not build ${n - 1} filler recipients for depth ${depth}`);
  return buildRecipientTree([XO(recipientKey), ...fillers]);
}
function agentPolicy(pkHex, recipientRoot, over = {}) {
  return {
    agentPk: pkHex,
    maxPerSpend: (200n * KAS).toString(),
    periodBudget: (1000n * KAS).toString(),
    periodLengthDaa: "864000",
    periodStartDaa: "541000000",
    periodSpent: "0",
    approvalThreshold: (100000n * KAS).toString(),
    agentMaxFeePerTx: (1n * KAS).toString(),
    agentRecipientRoot: recipientRoot,
    ...over
  };
}
const rTree0 = recipTreeAtDepth(0);
const DEFAULT_AGENT_ROOT = "00".repeat(32);
function baseState(over = {}) {
  return { protectedValue: (10000n * KAS).toString(), feeReserve: (5n * KAS).toString(), paused: "0", agentRoot: DEFAULT_AGENT_ROOT, approvers: over.approvers ?? [], approvalM: over.approvalM ?? "0", policyNonce: "0", ...over };
}
const fuelUtxo = (id = "03") => ({ outpoint: { transactionId: id.repeat(32), index: 0 }, amount: (30n * KAS).toString(), scriptPublicKeyHex: `20${XO(fuelKey)}ac` });
const rootChain = (over = {}) => ({ predecessorOutpoint: { transactionId: "01".repeat(32), index: 0 }, covenantId: ROOT_ID, predecessorValue: ROOT_KAS.toString(), fuel: fuelUtxo(), ...over });
const rootSide = (state, over = {}) => ({ template: rootTemplate, state, outpoint: { transactionId: "04".repeat(32), index: 0 }, covenantId: ROOT_ID, value: ROOT_KAS.toString(), ...over });
const vaultChain = (over = {}) => ({ predecessorOutpoint: { transactionId: "0a".repeat(32), index: 0 }, covenantId: VAULT_COV_ID, predecessorValue: (10005n * KAS).toString(), fuel: fuelUtxo("03"), ...over });

/* ---- signing helpers (TEST KEYS ONLY) ---- */
const wasmOf = (build) => frozenToWasmTransaction(config, build.frozen);
const signInput = (build, index, key) => kaspa.createInputSignature(wasmOf(build), index, key).slice(2);
const signFuelScript = (build, index, key = fuelKey) => kaspa.createInputSignature(wasmOf(build), index, key);
const approvalsFor = (build, index, keyIndexes) => keyIndexes.map((i) => ({ slot: i + 1, signatureHex: signInput(build, index, ownerKeys[i]) }));
function collect(build, signers) {
  let pkg = createApprovalPackageForBuildV7Kas(build);
  for (const kp of signers) pkg = submitApprovalV4(pkg, { signatureHex: signInput(build, 0, kp), approverXOnly: XO(kp) });
  return pkg;
}

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

/* The encoder MUST understand the v0.7-kas arm; a stale binary would
 * silently produce a different generation's bytes. Fail closed, loudly. */
{
  const probe = buildV7KasTransaction({ config, templateInput: vaultTemplate, stateInput: baseState(), action: "ownerPause", chain: vaultChain({ root: rootSide(rootState()) }), changeXOnly: XO(fuelKey) });
  if (probe.plannedCallHexLength / 2 < 400) {
    console.error("pv_call_encoder produced an implausibly short v0.7-kas call — is the binary stale? rebuild tests/vm --bin pv_call_encoder");
    process.exit(3);
  }
}

const manifests = [];

/* 1. rooted-kas vault genesis */
{
  const build = buildCreateV7KasVault({ config, templateInput: vaultTemplate, initialStateInput: baseState(), funding: [{ outpoint: { transactionId: "06".repeat(32), index: 0 }, amount: (11000n * KAS).toString(), scriptPublicKeyHex: `20${XO(fuelKey)}ac` }], changeXOnly: XO(fuelKey) });
  const json = JSON.parse(build.frozenCanonicalJson);
  json.inputs[0].signatureScript = kaspa.createInputSignature(wasmOf(build), 0, fuelKey);
  emit("vault_genesis", "accept", build, json, { contract: "policyvault-0.7-kas", note: "the vault output pins orgRootCovenantId + the root template identity" });
}

/* 2-8. owner operations: root input + vault input + fuel, all 7 selectors */
const ownerOpBuilds = {};
for (const [name, action, params, prevOver] of [
  /* rc26 round-7 R7-02: the builder derives the root from the FULL new delegate policy set (every policy with its complete
   * recipient set); a bare `newAgentRoot` is refused (AGENT_SET_REQUIRED). The vector carries one v4-layout policy for the
   * production agent key with its depth-0 recipient set (rc29: generator brought in line with the builder contract). */
  ["vault_owner_set_agent_root", "ownerSetAgentRoot", { agents: [{ ...agentPolicy(XO(agentKey), rTree0.root), recipients: [...rTree0.recipients] }] }, {}],
  ["vault_owner_set_approvers", "ownerSetApprovers", { approvers: approvers10.slice(0, 4).map(XO), approvalM: "3" }, { approvers: approvers3.map(XO), approvalM: "2" }],
  ["vault_owner_top_up", "ownerTopUp", { topUpAmountSompi: (10n * KAS).toString() }, {}],
  ["vault_owner_top_up_reserve", "ownerTopUpReserve", { topUpReserveAmountSompi: (2n * KAS).toString() }, {}],
  ["vault_owner_pause", "ownerPause", {}, {}],
  ["vault_owner_unpause", "ownerUnpause", {}, { paused: "1" }],
  ["vault_emergency_pause", "ownerEmergencyPause", {}, {}]
]) {
  const build = buildV7KasTransaction({ config, templateInput: vaultTemplate, stateInput: baseState(prevOver), action, params, chain: vaultChain({ root: rootSide(rootState()) }), changeXOnly: XO(fuelKey) });
  const signers = build.rootAuthority.rootActionName === "freeze" ? [0] : [0, 1];
  const fin = finalizeV7KasTransaction({ build, approvals: approvalsFor(build, 1, signers), fuelSignatureScriptHex: signFuelScript(build, 2) });
  ownerOpBuilds[name] = { build, tx: fin.finalTransaction };
  emit(name, "accept", build, fin.finalTransaction, { contract: "policyvault-0.7-kas" });

  const manifest = buildOrgRootIntentManifestV7Kas({ build, vaultOperations: [{ build }], satisfiedApprovals: signers.length });
  manifests.push({ name, verdict: verifyOrgRootIntentManifestV7Kas({ manifest }).verdict });
}

/* SELECTOR CROSS-OVER (identical proof shape to the payment profile): the
 * vault call bytes carry NO signature, so the two shapes below differ ONLY
 * in the opSelector int push. */
{
  const pause = ownerOpBuilds.vault_owner_pause;
  const emergency = ownerOpBuilds.vault_emergency_pause;
  emit("neg_vault_selector4_under_freeze_root", "reject", emergency.build, mutate(emergency.tx, (j) => {
    j.inputs[0].signatureScript = pause.tx.inputs[0].signatureScript;
  }), { contract: "policyvault-0.7-kas", rejectInput: 0, note: "selector 4 (full quorum) riding a FREEZE root successor" });
  emit("neg_vault_selector6_under_authorize_root", "reject", pause.build, mutate(pause.tx, (j) => {
    j.inputs[0].signatureScript = emergency.tx.inputs[0].signatureScript;
  }), { contract: "policyvault-0.7-kas", rejectInput: 0, note: "selector 6 (emergency quorum) riding an AUTHORIZE root successor" });
}
{
  const pause = ownerOpBuilds.vault_owner_pause;
  const rotated = compileExactStateV7Root({ config, template: rootTemplate, state: rootState({ rootNonce: 1, owners: slots([outsiderKey, ownerKeys[2]]) }) });
  emit("neg_vault_root_successor_head_changed", "reject", pause.build, mutate(pause.tx, (j) => {
    j.outputs[1].scriptPublicKey.scriptHex = p2sh(rotated.scriptBytes);
  }), { contract: "policyvault-0.7-kas", rejectInput: 0, note: "a rotation disguised inside a vault owner operation" });
  const alienState = { ownerIdentifier: XO(otherKey), identifierType: 0, amount: "5", isMinter: false };
  emit("neg_vault_alien_covenant_rider", "reject", pause.build, mutate(pause.tx, (j) => {
    j.inputs.splice(2, 0, { previousOutpoint: { transactionId: "0f".repeat(32), index: 0 }, signatureScript: "", sequence: "0", computeBudget: 10, utxo: { amount: KAS.toString(), scriptPublicKey: { version: 0, scriptHex: `20${XO(otherKey)}ac` }, covenantId: ALIEN_ID, blockDaaScore: "0" } });
    j.outputs.splice(2, 0, { value: KAS.toString(), scriptPublicKey: { version: 0, scriptHex: `20${XO(otherKey)}ac` }, covenant: { authorizingInput: 2, covenantId: ALIEN_ID } });
  }), { contract: "policyvault-0.7-kas", rejectInput: 0, note: `a foreign covenant family riding an owner operation (alienState placeholder ${JSON.stringify(alienState).length})` });
}

/* 9. ownerRecover: the whole protectedValue+feeReserve -> recoveryPk */
{
  const build = buildV7KasTransaction({ config, templateInput: vaultTemplate, stateInput: baseState(), action: "ownerRecover", chain: vaultChain({ root: rootSide(rootState()) }), changeXOnly: XO(fuelKey) });
  const fin = finalizeV7KasTransaction({ build, approvals: approvalsFor(build, 1, [0, 1]), fuelSignatureScriptHex: signFuelScript(build, 2) });
  emit("vault_recover", "accept", build, fin.finalTransaction, { contract: "policyvault-0.7-kas" });
  const manifest = buildOrgRootIntentManifestV7Kas({ build, vaultOperations: [{ build }], satisfiedApprovals: 2 });
  manifests.push({ name: "vault_recover", verdict: verifyOrgRootIntentManifestV7Kas({ manifest }).verdict });

  emit("neg_vault_recover_wrong_destination", "reject", build, mutate(fin.finalTransaction, (j) => {
    j.outputs[0].scriptPublicKey.scriptHex = `20${XO(otherKey)}ac`;
  }), { contract: "policyvault-0.7-kas", rejectInput: 0 });
}

/* 10-13. DELEGATE SPEND — no root input at all; the frozen v0.4.1 shape */
const spendParams = (over = {}) => ({ payAmountSompi: (40n * KAS).toString(), agentPk: XO(agentKey), agents: [agentPolicy(XO(agentKey), rTree0.root)], recipient: XO(recipientKey), recipients: [...rTree0.recipients], ...over });
{
  const state = baseState({ agentRoot: buildAgentTreeV4(spendParams().agents).root });
  const build = buildV7KasTransaction({ config, templateInput: vaultTemplate, stateInput: state, action: "agentSpend", params: spendParams(), chain: vaultChain(), changeXOnly: XO(fuelKey) });
  const fin = finalizeV7KasTransaction({ build, agentSignatureHex: signInput(build, 0, agentKey), fuelSignatureScriptHex: signFuelScript(build, 1) });
  const tx = fin.finalTransaction;
  emit("delegate_spend", "accept", build, tx, { contract: "policyvault-0.7-kas", note: "no root input — the agent path never touches the organization's root" });

  const m = buildRootedKasVaultManifestV7({ build });
  manifests.push({ name: "delegate_spend_standalone", verdict: "manifest_built (no standalone verifier — see verifyRootedKasVaultManifestV7 doc)" });
  if (m.manifestVersion !== "policyvault-rooted-kas-vault-manifest/1") throw new Error("internal: delegate spend manifest has the wrong version");

  emit("neg_delegate_spend_wrong_signer", "reject", build, finalizeV7KasTransaction({ build, agentSignatureHex: signInput(build, 0, otherKey), fuelSignatureScriptHex: signFuelScript(build, 1) }).finalTransaction, { contract: "policyvault-0.7-kas" });
  emit("neg_delegate_successor_drained", "reject", build, mutate(tx, (j) => {
    j.outputs[0].value = (BigInt(j.outputs[0].value) - 1000000n).toString();
    j.outputs[1].value = (BigInt(j.outputs[1].value) + 1000000n).toString();
  }), { contract: "policyvault-0.7-kas" });
  emit("neg_delegate_recipient_substitution", "reject", build, mutate(tx, (j) => {
    j.outputs[0].scriptPublicKey.scriptHex = `20${XO(otherKey)}ac`;
  }), { contract: "policyvault-0.7-kas" });
  /* candidate hardening E6(a): a non-ALL agent signature and a forged gate
   * byte are now REFUSED — see neg_delegate_forged_gate_byte below (a
   * post-freeze JSON mutation cannot forge a NEW valid signature, so that
   * refusal is built via a proper re-encode with a genuine SIG_HASH_SINGLE
   * signature over the SAME frozen bytes, immediately after this block). */
  /* candidate hardening E6(b): a root-covenant rider is now REFUSED */
  const rootCompiled = compileExactStateV7Root({ config, template: rootTemplate, state: rootState() });
  emit("neg_delegate_root_rider", "reject", build, mutate(tx, (j) => {
    j.inputs.splice(1, 0, { previousOutpoint: { transactionId: "04".repeat(32), index: 0 }, signatureScript: "", sequence: "0", computeBudget: 40, utxo: { amount: ROOT_KAS.toString(), scriptPublicKey: { version: 0, scriptHex: p2sh(rootCompiled.scriptBytes) }, covenantId: ROOT_ID, blockDaaScore: "0" } });
    j.outputs.splice(1, 0, { value: ROOT_KAS.toString(), scriptPublicKey: { version: 0, scriptHex: p2sh(rootCompiled.scriptBytes) }, covenant: { authorizingInput: 1, covenantId: ROOT_ID } });
  }), { contract: "policyvault-0.7-kas", note: "candidate hardening E6(b): requireOnlyPlainInputsOnDelegatePath now refuses this (was accepted, inherited v0.4.1 behavior, before this hardening)" });
}
/* re-encode with a forged gate byte on the agent's own signature (E6(a)) */
{
  const state = baseState({ agentRoot: buildAgentTreeV4(spendParams().agents).root });
  const build = buildV7KasTransaction({ config, templateInput: vaultTemplate, stateInput: state, action: "agentSpend", params: spendParams(), chain: vaultChain(), changeXOnly: XO(fuelKey) });
  const realSig = signInput(build, 0, agentKey);
  if (!realSig.endsWith("01")) throw new Error("internal: sanity — expected a genuine SIG_HASH_ALL trailing byte");
  const forged = realSig.slice(0, -2) + "02";
  const call = { function: "agentSpend", signature: forged, successor: successorCallJsonV7Kas(build.successorState), approvals: placeholderApprovalsBlob(), ...build.callExtra };
  const callHex = runEncoderV4({ sourcePath: path.join(build.encoderBuildDir, "PolicyVault.state.sil"), constructorArgsPath: path.join(build.encoderBuildDir, "constructor-args.json"), call, contractVersion: build.contractVersion });
  const artifact = JSON.parse(fs.readFileSync(path.join(build.encoderBuildDir, "artifact.json")));
  const json = JSON.parse(build.frozenCanonicalJson);
  json.inputs[0].signatureScript = covenantSigscript(callHex, Buffer.from(artifact.script));
  json.inputs[1].signatureScript = signFuelScript(build, 1);
  emit("neg_delegate_forged_gate_byte", "reject", build, json, { contract: "policyvault-0.7-kas", note: "candidate hardening E6(a): requireAgentAuthorization refuses a forged (non-0x01) trailing gate byte" });
}
{
  /* reserve-funded spend (no fuel): reserveConsumed == the exact fee */
  const state = baseState({ agentRoot: buildAgentTreeV4(spendParams().agents).root });
  const build = buildV7KasTransaction({ config, templateInput: vaultTemplate, stateInput: state, action: "agentSpend", params: spendParams(), chain: { predecessorOutpoint: { transactionId: "0a".repeat(32), index: 0 }, covenantId: VAULT_COV_ID, predecessorValue: (10005n * KAS).toString() }, changeXOnly: XO(fuelKey) });
  const fin = finalizeV7KasTransaction({ build, agentSignatureHex: signInput(build, 0, agentKey) });
  emit("delegate_spend_reserve_funded", "accept", build, fin.finalTransaction, { contract: "policyvault-0.7-kas" });
}
{
  /* period rollover */
  const spent = agentPolicy(XO(agentKey), rTree0.root, { periodSpent: (980n * KAS).toString() });
  const agents = [spent];
  const tree = buildAgentTreeV4(agents);
  const state = baseState({ agentRoot: tree.root });
  const build = buildV7KasTransaction({ config, templateInput: vaultTemplate, stateInput: state, action: "agentSpend", params: spendParams({ agents, periodsElapsed: "1" }), chain: vaultChain(), changeXOnly: XO(fuelKey) });
  const fin = finalizeV7KasTransaction({ build, agentSignatureHex: signInput(build, 0, agentKey), fuelSignatureScriptHex: signFuelScript(build, 1) });
  const tx = fin.finalTransaction;
  emit("delegate_spend_rollover", "accept", build, tx, { contract: "policyvault-0.7-kas" });
  emit("neg_delegate_locktime_forged", "reject", build, mutate(tx, (j) => {
    j.lockTime = (BigInt(j.lockTime) + 9000n).toString();
  }), { contract: "policyvault-0.7-kas" });
}

/* 14-16. above-threshold vault-level M-of-N approval tier */
{
  const aPolicy = agentPolicy(XO(agentKey), rTree0.root, { approvalThreshold: (50n * KAS).toString() });
  const agents = [aPolicy];
  const tree = buildAgentTreeV4(agents);
  const approvedBuild = (pay, approverKeys, m) => {
    const state = baseState({ agentRoot: tree.root, approvers: approverKeys.map(XO), approvalM: String(m) });
    return buildV7KasTransaction({ config, templateInput: vaultTemplate, stateInput: state, action: "agentSpend", params: spendParams({ agents, payAmountSompi: pay }), chain: vaultChain(), changeXOnly: XO(fuelKey) });
  };
  const b1 = approvedBuild((70n * KAS).toString(), approvers3, 1);
  emit("approved_1of3", "accept", b1, finalizeV7KasTransaction({ build: b1, agentSignatureHex: signInput(b1, 0, agentKey), approvalPackage: collect(b1, [approvers3[0]]), fuelSignatureScriptHex: signFuelScript(b1, 1) }).finalTransaction, { contract: "policyvault-0.7-kas" });

  const b2 = approvedBuild((80n * KAS).toString(), approvers3, 2);
  const pkg2 = collect(b2, [approvers3[0], approvers3[1]]);
  const fin2 = finalizeV7KasTransaction({ build: b2, agentSignatureHex: signInput(b2, 0, agentKey), approvalPackage: pkg2, fuelSignatureScriptHex: signFuelScript(b2, 1) });
  emit("approved_2of3", "accept", b2, fin2.finalTransaction, { contract: "policyvault-0.7-kas" });
  emit("neg_approved_under_quorum", "reject", b2, mutate(fin2.finalTransaction, (j) => {
    /* replace the second real approver slot with the canonical placeholder */
    const s = j.inputs[0].signatureScript;
    const slot2 = pkg2.approvals[1];
    if (!s.includes(slot2)) throw new Error("internal: could not locate approver slot 2 inside the finalized sigscript");
    j.inputs[0].signatureScript = s.replace(slot2, PLACEHOLDER_SLOT_HEX_V7);
  }), { contract: "policyvault-0.7-kas", note: "one of the two required vault-level approvals abstains" });

  const b10 = approvedBuild((80n * KAS).toString(), approvers10, 10);
  emit("approved_10of10", "accept", b10, finalizeV7KasTransaction({ build: b10, agentSignatureHex: signInput(b10, 0, agentKey), approvalPackage: collect(b10, approvers10), fuelSignatureScriptHex: signFuelScript(b10, 1) }).finalTransaction, { contract: "policyvault-0.7-kas" });
}

/* 17. worst-case shape: agent depth 12, recipient depth 16, 10-of-10 approvals */
{
  function agentSetAtDepth(depth, aPolicy) {
    if (depth === 0) return [aPolicy];
    const n = 1 << depth;
    const agents = [aPolicy];
    for (let i = 1; i < n; i += 1) {
      const pk = i.toString(16).padStart(8, "0").repeat(8);
      const root = ("f" + i.toString(16)).padStart(4, "0").repeat(16).slice(0, 64);
      agents.push(agentPolicy(pk, root, { maxPerSpend: (1n * KAS).toString(), periodBudget: (1n * KAS).toString(), approvalThreshold: "1", agentMaxFeePerTx: "1" }));
    }
    return agents;
  }
  const rTree16 = recipTreeAtDepth(16);
  const aPolicy = agentPolicy(XO(agentKey), rTree16.root, { approvalThreshold: (50n * KAS).toString() });
  const agents = agentSetAtDepth(12, aPolicy);
  const tree = buildAgentTreeV4(agents);
  const state = baseState({ agentRoot: tree.root, approvers: approvers10.map(XO), approvalM: "10" });
  const build = buildV7KasTransaction({ config, templateInput: vaultTemplate, stateInput: state, action: "agentSpend", params: { payAmountSompi: (80n * KAS).toString(), agentPk: XO(agentKey), agents, recipient: XO(recipientKey), recipients: [...rTree16.recipients] }, chain: vaultChain(), changeXOnly: XO(fuelKey) });
  const fin = finalizeV7KasTransaction({ build, agentSignatureHex: signInput(build, 0, agentKey), approvalPackage: collect(build, approvers10), fuelSignatureScriptHex: signFuelScript(build, 1) });
  emit("worst_agent12_recip16_10of10", "accept", build, fin.finalTransaction, { contract: "policyvault-0.7-kas" });
}

/* ================================================================ SDK REFUSALS */
const vaultBuild = (over = {}) => buildV7KasTransaction({ config, templateInput: vaultTemplate, stateInput: baseState(), action: "ownerPause", chain: vaultChain({ root: rootSide(rootState()) }), changeXOnly: XO(fuelKey), ...over });
refuses("vault_unknown_action", () => vaultBuild({ action: "ownerRotateAgent" }), /UNKNOWN_ACTION/);
refuses("vault_unknown_version", () => vaultBuild({ contractVersion: "policyvault-0.5" }), /UNKNOWN_VERSION/);
refuses("vault_owner_op_without_root", () => buildV7KasTransaction({ config, templateInput: vaultTemplate, stateInput: baseState(), action: "ownerPause", chain: vaultChain(), changeXOnly: XO(fuelKey) }), /ROOT_INPUT_REQUIRED/);
refuses("vault_agent_path_with_a_root", () => buildV7KasTransaction({ config, templateInput: vaultTemplate, stateInput: baseState({ agentRoot: buildAgentTreeV4(spendParams().agents).root }), action: "agentSpend", params: spendParams(), chain: vaultChain({ root: rootSide(rootState()) }), changeXOnly: XO(fuelKey) }), /AGENT_PATH_TAKES_NO_ROOT/);
refuses("vault_owner_op_under_a_frozen_root", () => buildV7KasTransaction({ config, templateInput: vaultTemplate, stateInput: baseState(), action: "ownerPause", chain: vaultChain({ root: rootSide(rootState({ frozen: 1 })) }), changeXOnly: XO(fuelKey) }), /ROOT_FROZEN/);
refuses("vault_stale_predecessor_value", () => vaultBuild({ chain: vaultChain({ root: rootSide(rootState()), predecessorValue: (6n * KAS).toString() }) }), /STALE/);
refuses("vault_root_state_len_pin_wrong", () => vaultBuild({ templateInput: { ...vaultTemplate, rootStateLen: 466 } }), /ROOT_GEOMETRY_MISMATCH/);
refuses("vault_root_covenant_id_zero", () => vaultBuild({ templateInput: { ...vaultTemplate, orgRootCovenantId: "00".repeat(32) } }), /ROOT_PIN_MISSING/);
refuses("vault_root_pins_drift", () => assertRootPinsMatchV7Kas({ config, vaultTemplate: { ...vaultTemplate, rootTemplateVmHash: "ee".repeat(32) }, rootTemplate, rootOwnerSet: ownerSet3 }), /ROOT_PIN_DRIFT/);
refuses("vault_spend_over_cap", () => buildV7KasTransaction({ config, templateInput: vaultTemplate, stateInput: baseState({ agentRoot: buildAgentTreeV4(spendParams().agents).root }), action: "agentSpend", params: spendParams({ payAmountSompi: (201n * KAS).toString() }), chain: vaultChain(), changeXOnly: XO(fuelKey) }), /exceeds this agent's maxPerSpend/);
refuses("vault_spend_while_paused", () => buildV7KasTransaction({ config, templateInput: vaultTemplate, stateInput: baseState({ agentRoot: buildAgentTreeV4(spendParams().agents).root, paused: "1" }), action: "agentSpend", params: spendParams(), chain: vaultChain(), changeXOnly: XO(fuelKey) }), /paused/);

/* ---- the rooted-kas-vault finalizer ---- */
{
  const b = ownerOpBuilds.vault_owner_pause.build;
  const fuelScript = signFuelScript(b, 2);
  refuses("vault_owner_path_takes_no_signature", () => finalizeV7KasTransaction({ build: b, agentSignatureHex: signInput(b, 0, ownerKeys[0]), approvals: approvalsFor(b, 1, [0, 1]), fuelSignatureScriptHex: fuelScript }), /OWNER_PATH_TAKES_NO_SIGNATURE/);
  refuses("vault_owner_path_under_quorum", () => finalizeV7KasTransaction({ build: b, approvals: approvalsFor(b, 1, [0]), fuelSignatureScriptHex: fuelScript }), /UNDER_QUORUM/);
}
{
  const state = baseState({ agentRoot: buildAgentTreeV4(spendParams().agents).root });
  const b = buildV7KasTransaction({ config, templateInput: vaultTemplate, stateInput: state, action: "agentSpend", params: spendParams(), chain: vaultChain(), changeXOnly: XO(fuelKey) });
  refuses("vault_agent_path_takes_no_root_approvals", () => finalizeV7KasTransaction({ build: b, agentSignatureHex: signInput(b, 0, agentKey), approvals: [{ slot: 1, signatureHex: signInput(b, 0, ownerKeys[0]) }], fuelSignatureScriptHex: signFuelScript(b, 1) }), /AGENT_PATH_TAKES_NO_ROOT_APPROVALS/);
}

/* ---- manifest routing ---- */
refuses("router_kas_verify_within_parent", () => routeIntentManifestBuilder("policyvault-0.9"), /UNKNOWN_VERSION/);

/* ================================================================ INDEX */
fs.writeFileSync(
  path.join(outDir, "index.json"),
  JSON.stringify({ vectors, refusals, manifests, vaultTemplate, rootTemplate }, null, 1)
);
const unrefused = refusals.filter((r) => !r.refused || r.ok === false);
if (unrefused.length) {
  console.error("SDK did not refuse (or refused with the wrong code):", JSON.stringify(unrefused, null, 1));
  process.exit(2);
}
const badManifests = manifests.filter((m) => m.verdict !== "VERIFIED" && !String(m.verdict).startsWith("manifest_built"));
if (badManifests.length) {
  console.error("org-root-kas manifests must verify:", JSON.stringify(badManifests, null, 1));
  process.exit(4);
}
console.log(`emitted ${vectors.length} vectors (${vectors.filter((v) => v.expect === "accept").length} accept / ${vectors.filter((v) => v.expect === "reject").length} reject), ${refusals.length} SDK refusals, ${manifests.length} manifest checks`);
