"use strict";

/*
 * PolicyVault v0.3 PRODUCTION-BYTE vector generator (Phase 4H §19/§20).
 *
 * Drives the ACTUAL production SDK code — vault-state-v3, the exact-state
 * compiler, recipient-merkle-v3, vault-transitions-v3, compute-budget-v3,
 * frozen-tx-v3, approval-package-v3, vault-builders-v3, and the REAL
 * pv_call_encoder binary — to construct fully-finalized v0.3 transactions
 * with real Schnorr signatures (rusty-kaspa WASM createInputSignature over
 * deterministic TEST-ONLY keys). tests/vm/tests/v3_sdk_integration.rs
 * executes every emitted vector on the real TxScriptEngine against the
 * production covenant.
 *
 * If a JS bug ever produced wrong consensus bytes anywhere in that chain,
 * the VM execution fails — this is the production-byte rule applied to
 * the entire SDK construction path, not just the encoder.
 *
 * Usage: node gen-v3-vectors.js <output-dir>
 * Emits <output-dir>/<case>/vector.json:
 *   { name, expect: "accept"|"reject", action, committedBudget,
 *     requiredFeeSompi, tx: <final transaction JSON incl. sig scripts and
 *     per-input utxo entries> }
 *
 * TEST KEYS ONLY: secrets are the byte value repeated 32x, matching the
 * Rust harness deterministic_keypair(v). Never production material.
 */

const fs = require("fs");
const path = require("path");

const { loadConfig } = require("../src/config");
const { buildRecipientTree, generateRecipientProof, leafHash } = require("../src/recipient-merkle-v3");
const { buildV3Transaction, finalizeV3Transaction, createApprovalPackageForBuild } = require("../src/vault-builders-v3");
const { frozenToWasmTransaction } = require("../src/frozen-tx-v3");
const { submitApprovalV3 } = require("../src/approval-package-v3");

const outDir = process.argv[2];
if (!outDir) {
  console.error("usage: node gen-v3-vectors.js <output-dir>");
  process.exit(1);
}
fs.mkdirSync(outDir, { recursive: true });

const config = loadConfig({ dataRoot: path.join(outDir, "data") });
const kaspa = require(config.rustyKaspaModule);

const KAS = 100000000n;
/* Deterministic TEST keys — same secrets as Rust deterministic_keypair. */
const KEY = (v) => new kaspa.PrivateKey(v.toString(16).padStart(2, "0").repeat(32));
const XO = (p) => p.toPublicKey().toXOnlyPublicKey().toString().toLowerCase();

const owner = KEY(1);
const delegate = KEY(2);
const fuelKey = KEY(3);
const recipient = KEY(0x28); // 40
const approvers3 = [KEY(20), KEY(21), KEY(22)];
const approvers10 = Array.from({ length: 10 }, (_, i) => KEY(60 + i));

const OWNER = XO(owner);
const DELEGATE = XO(delegate);
const RECIPIENT = XO(recipient);
const FUEL_SPK = `20${XO(fuelKey)}ac`;
/* COV_A — the Rust harness covenant id (b"AAAA…" = 0x41 * 32). */
const COVENANT_ID = "41".repeat(32);
const VAULT_ID = "22".repeat(32);

const template = { owner: OWNER, vaultId: VAULT_ID };

function baseState(over = {}) {
  return {
    protectedValue: (1000n * KAS).toString(),
    periodStartDaa: "541000000",
    periodSpent: "0",
    paused: "0",
    delegate: DELEGATE,
    delegateActive: "1",
    maxPerSpend: (200n * KAS).toString(),
    periodBudget: (800n * KAS).toString(),
    periodLengthDaa: "864000",
    recipientRoot: "44".repeat(32),
    approvers: [],
    approvalM: "0",
    approvalThresholdAmount: (200n * KAS).toString(),
    policyNonce: "0",
    ...over
  };
}

function chainCtx(predecessorValue) {
  return {
    predecessorOutpoint: { transactionId: "42".repeat(32), index: 0 },
    predecessorValue,
    covenantId: COVENANT_ID,
    fuel: { outpoint: { transactionId: "43".repeat(32), index: 1 }, amount: (10n * KAS).toString(), scriptPublicKeyHex: FUEL_SPK }
  };
}

/* A depth-d tree containing the real recipient (like the Rust fixtures). */
function treeAtDepth(depth) {
  if (depth === 0) {
    return buildRecipientTree([RECIPIENT]);
  }
  const n = 1 << depth;
  const fillers = [];
  for (let i = 0; fillers.length < n - 1 && i <= 0xffff; i++) {
    const k = i.toString(16).padStart(4, "0").repeat(16);
    if (k !== RECIPIENT) fillers.push(k);
  }
  if (fillers.length !== n - 1) {
    throw new Error(`could not build ${n - 1} filler recipients for depth ${depth}`);
  }
  return buildRecipientTree([RECIPIENT, ...fillers]);
}

function signCovenant(build, keypair) {
  const wtx = frozenToWasmTransaction(config, build.frozen);
  return kaspa.createInputSignature(wtx, 0, keypair).slice(2); // strip 0x41 push
}
function signFuel(build) {
  const wtx = frozenToWasmTransaction(config, build.frozen);
  return kaspa.createInputSignature(wtx, 1, fuelKey);
}
function approverSig(build, keypair) {
  const wtx = frozenToWasmTransaction(config, build.frozen);
  return kaspa.createInputSignature(wtx, 0, keypair).slice(2);
}

const vectors = [];
function emit(name, expect, build, finalized, extra = {}) {
  vectors.push({ name, expect });
  const dir = path.join(outDir, name);
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(
    path.join(dir, "vector.json"),
    JSON.stringify(
      {
        name,
        expect,
        action: build?.action ?? extra.action ?? "unknown",
        committedBudget: build?.computeBudget ?? extra.committedBudget ?? null,
        requiredFeeSompi: build?.requiredFeeSompi ?? extra.requiredFeeSompi ?? null,
        tx: finalized,
        ...extra.meta
      },
      null,
      1
    )
  );
}

function finalizeSimple(build, signer, approvalPackage) {
  return finalizeV3Transaction({
    build,
    covenantSignatureHex: signCovenant(build, signer),
    fuelSignatureScriptHex: signFuel(build),
    approvalPackage
  }).finalTransaction;
}

/* Collect approvals through the PRODUCTION package flow. */
function collectApprovals(build, signers) {
  let pkg = createApprovalPackageForBuild(build);
  for (const kp of signers) {
    pkg = submitApprovalV3(pkg, { signatureHex: approverSig(build, kp), approverXOnly: XO(kp) });
  }
  return pkg;
}

/* ---------------------------------------------------------------- cases */

/* 1) delegateSpend below threshold (depth-2 proof from a 3-recipient set). */
{
  const tree = buildRecipientTree([RECIPIENT, XO(KEY(0x29)), XO(KEY(0x2a))]);
  const state = baseState({ recipientRoot: tree.root });
  const build = buildV3Transaction({
    config,
    templateInput: template,
    stateInput: state,
    action: "delegateSpend",
    params: { payAmountSompi: (40n * KAS).toString(), recipient: RECIPIENT, recipients: [...tree.recipients] },
    chain: chainCtx(state.protectedValue),
    changeXOnly: XO(fuelKey)
  });
  emit("spend_below_threshold", "accept", build, finalizeSimple(build, delegate));
}

/* 2) approved spend 2-of-3 above threshold. */
let approvedBuild = null;
let approvedPkg = null;
{
  const tree = buildRecipientTree([RECIPIENT, XO(KEY(0x29)), XO(KEY(0x2a))]);
  const state = baseState({
    recipientRoot: tree.root,
    approvers: approvers3.map(XO),
    approvalM: "2",
    approvalThresholdAmount: (50n * KAS).toString()
  });
  const build = buildV3Transaction({
    config,
    templateInput: template,
    stateInput: state,
    action: "delegateSpend",
    params: { payAmountSompi: (150n * KAS).toString(), recipient: RECIPIENT, recipients: [...tree.recipients] },
    chain: chainCtx(state.protectedValue),
    changeXOnly: XO(fuelKey)
  });
  const pkg = collectApprovals(build, [approvers3[0], approvers3[1]]);
  approvedBuild = build;
  approvedPkg = pkg;
  emit("approved_spend_2of3", "accept", build, finalizeSimple(build, delegate, pkg));
}

/* 3) rolloverAndSpend below threshold (CLTV lock time). */
{
  const tree = buildRecipientTree([RECIPIENT, XO(KEY(0x29))]);
  const state = baseState({ recipientRoot: tree.root, periodSpent: (700n * KAS).toString() });
  const build = buildV3Transaction({
    config,
    templateInput: template,
    stateInput: state,
    action: "rolloverAndSpend",
    params: { payAmountSompi: (40n * KAS).toString(), recipient: RECIPIENT, recipients: [...tree.recipients], periodsElapsed: "2" },
    chain: chainCtx(state.protectedValue),
    changeXOnly: XO(fuelKey)
  });
  emit("rollover_and_spend", "accept", build, finalizeSimple(build, delegate));
}

/* 4–11) the eight owner state transitions. */
{
  const state = baseState({ periodSpent: (5n * KAS).toString() });
  const chain = chainCtx(state.protectedValue);
  const ownerOp = (name, action, params) => {
    const build = buildV3Transaction({ config, templateInput: template, stateInput: state, action, params, chain, changeXOnly: OWNER });
    emit(name, "accept", build, finalizeSimple(build, owner));
    return build;
  };
  ownerOp("owner_pause", "ownerPause", {});
  ownerOp("revoke_delegate", "revokeDelegate", {});
  ownerOp("rotate_delegate", "rotateDelegate", { newDelegate: XO(KEY(7)) });
  ownerOp("owner_topup", "ownerTopUp", { topUpAmountSompi: (5n * KAS).toString() });
  /* Migrate LOWERS the cap (raising it above the 0-approver threshold is
   * refused by the SDK successor validation — usability fail-closed). */
  ownerOp("migrate_policy", "migratePolicy", { newPolicy: { maxPerSpend: (100n * KAS).toString() } });
  ownerOp("set_recipient_root", "ownerSetRecipientRoot", { newRecipientRoot: "55".repeat(32) });
  ownerOp("set_approvers", "ownerSetApprovers", {
    newApprovers: { approvers: approvers3.map(XO), approvalM: "2", approvalThresholdAmount: (50n * KAS).toString() }
  });
  // unpause needs a paused predecessor
  const paused = baseState({ periodSpent: (5n * KAS).toString(), paused: "1" });
  const b = buildV3Transaction({ config, templateInput: template, stateInput: paused, action: "ownerUnpause", params: {}, chain, changeXOnly: OWNER });
  emit("owner_unpause", "accept", b, finalizeSimple(b, owner));
}

/* 12) ownerRecover (well-formed predecessor). */
{
  const state = baseState();
  const build = buildV3Transaction({
    config,
    templateInput: template,
    stateInput: state,
    action: "ownerRecover",
    params: {},
    chain: chainCtx(state.protectedValue),
    changeXOnly: OWNER
  });
  emit("owner_recover", "accept", build, finalizeSimple(build, owner));
}

/* 13) ownerRecover from a MALFORMED predecessor (duplicate approver keys,
 * M=0, paused, revoked — the break-glass no-trapped-funds path). */
{
  const malformed = baseState({
    paused: "1",
    delegateActive: "0",
    approvers: undefined,
    approverSlots: [XO(KEY(20)), XO(KEY(20)), XO(KEY(22)), ...Array.from({ length: 7 }, () => "00".repeat(32))],
    approvalM: "0",
    approvalThresholdAmount: "1"
  });
  const build = buildV3Transaction({
    config,
    templateInput: template,
    stateInput: malformed,
    action: "ownerRecover",
    params: { allowMalformedState: true },
    chain: chainCtx(malformed.protectedValue),
    changeXOnly: OWNER
  });
  emit("owner_recover_malformed_state", "accept", build, finalizeSimple(build, owner));
}

/* 14) recipient depth matrix 0/1/4/8/12/16. */
for (const depth of [0, 1, 4, 8, 12, 16]) {
  const tree = treeAtDepth(depth);
  const state = baseState({ recipientRoot: tree.root, approvalThresholdAmount: (500n * KAS).toString() });
  const build = buildV3Transaction({
    config,
    templateInput: template,
    stateInput: state,
    action: "delegateSpend",
    params: { payAmountSompi: (40n * KAS).toString(), recipient: RECIPIENT, recipients: [...tree.recipients] },
    chain: chainCtx(state.protectedValue),
    changeXOnly: XO(fuelKey)
  });
  emit(`spend_depth_${depth}`, "accept", build, finalizeSimple(build, delegate));
}

/* 15) WORST CASE: depth 16 + 10-of-10 (committed budget must be 135). */
{
  const tree = treeAtDepth(16);
  const state = baseState({
    recipientRoot: tree.root,
    approvers: approvers10.map(XO),
    approvalM: "10",
    approvalThresholdAmount: (50n * KAS).toString()
  });
  const build = buildV3Transaction({
    config,
    templateInput: template,
    stateInput: state,
    action: "delegateSpend",
    params: { payAmountSompi: (150n * KAS).toString(), recipient: RECIPIENT, recipients: [...tree.recipients] },
    chain: chainCtx(state.protectedValue),
    changeXOnly: XO(fuelKey)
  });
  const pkg = collectApprovals(build, approvers10);
  emit("worst_depth16_10of10", "accept", build, finalizeSimple(build, delegate, pkg));
}

/* 16) threshold boundary: pay == threshold is delegate-only. */
{
  const tree = buildRecipientTree([RECIPIENT, XO(KEY(0x29))]);
  const state = baseState({
    recipientRoot: tree.root,
    approvers: approvers3.map(XO),
    approvalM: "2",
    approvalThresholdAmount: (50n * KAS).toString()
  });
  const build = buildV3Transaction({
    config,
    templateInput: template,
    stateInput: state,
    action: "delegateSpend",
    params: { payAmountSompi: (50n * KAS).toString(), recipient: RECIPIENT, recipients: [...tree.recipients] },
    chain: chainCtx(state.protectedValue),
    changeXOnly: XO(fuelKey)
  });
  emit("spend_equal_threshold_delegate_only", "accept", build, finalizeSimple(build, delegate));
}

/* ---------------- consensus-level NEGATIVE vectors (post-finalize
 * mutations of otherwise-valid transactions — the SDK itself refuses to
 * build these, so they are crafted from the final JSON) ---------------- */

/* 17) threshold+1 with insufficient approvals: splice a placeholder over
 * one collected approval in the final 650-byte blob. The blob sits inside
 * the covenant call; easiest robust splice: rebuild via the package with
 * only ONE approval and force the blob out through internals is refused —
 * so instead reuse the approved build and swap its two collected approval
 * slots (each checkSig then fails; count 0 < 2). */
{
  const json = JSON.parse(JSON.stringify(approvedBuild ? finalizeSimple(approvedBuild, delegate, approvedPkg) : null));
  const sig = json.inputs[0].signatureScript;
  const a = approvedPkg.approvals.map((s, i) => ({ s, i })).filter((e) => e.s !== null);
  const [x, y] = [a[0].s, a[1].s];
  if (!sig.includes(x) || !sig.includes(y)) {
    throw new Error("negative-vector construction failed: approvals not found in sigscript");
  }
  json.inputs[0].signatureScript = sig.replace(x, " TMP ").replace(y, x).replace(" TMP ", y);
  emit("neg_approvals_swapped_slots", "reject", approvedBuild, json, { action: "delegateSpend" });
}

/* 18) approval replayed for a DIFFERENT transaction intent: same
 * predecessor state/keys, different recipient — approvals collected for
 * the first tx spliced into the second. SIG_HASH_ALL must kill it. */
{
  const other = XO(KEY(0x2a));
  const tree = buildRecipientTree([RECIPIENT, XO(KEY(0x29)), other]);
  const state = baseState({
    recipientRoot: tree.root,
    approvers: approvers3.map(XO),
    approvalM: "2",
    approvalThresholdAmount: (50n * KAS).toString()
  });
  const mk = (target) =>
    buildV3Transaction({
      config,
      templateInput: template,
      stateInput: state,
      action: "delegateSpend",
      params: { payAmountSompi: (150n * KAS).toString(), recipient: target, recipients: [...tree.recipients] },
      chain: chainCtx(state.protectedValue),
      changeXOnly: XO(fuelKey)
    });
  const buildA = mk(RECIPIENT);
  const buildB = mk(other);
  const pkgA = collectApprovals(buildA, [approvers3[0], approvers3[1]]);
  const pkgB = collectApprovals(buildB, [approvers3[0], approvers3[1]]);
  const txB = finalizeSimple(buildB, delegate, pkgB);
  // splice A's approvals over B's inside the final sigscript
  let s = txB.inputs[0].signatureScript;
  for (const [i, sigA] of pkgA.approvals.entries()) {
    const sigB = pkgB.approvals[i];
    if (sigA && sigB) {
      if (!s.includes(sigB)) throw new Error("replay-vector construction failed");
      s = s.replace(sigB, sigA);
    }
  }
  txB.inputs[0].signatureScript = s;
  emit("neg_approvals_replayed_other_recipient", "reject", buildB, txB, { action: "delegateSpend" });

  /* 19) freeze violation at consensus: mutate the change output value of a
   * fully-approved valid transaction — every collected signature must die. */
  const txGood = finalizeSimple(buildA, delegate, pkgA);
  const mutated = JSON.parse(JSON.stringify(txGood));
  mutated.outputs[2].value = (BigInt(mutated.outputs[2].value) - 1n).toString();
  emit("neg_output_mutated_after_approval", "reject", buildA, mutated, { action: "delegateSpend" });

  /* 20) A7 gate: flip one collected approval's trailing sighash byte to
   * 0x02 inside the blob (shape gate must reject before checkSig). */
  const txGate = finalizeSimple(buildA, delegate, pkgA);
  const target = pkgA.approvals.find((x) => x !== null);
  if (!txGate.inputs[0].signatureScript.includes(target)) throw new Error("gate-vector construction failed");
  txGate.inputs[0].signatureScript = txGate.inputs[0].signatureScript.replace(target, target.slice(0, -2) + "02");
  emit("neg_approval_trailing_byte_not_all", "reject", buildA, txGate, { action: "delegateSpend" });

  /* 21) duplicate one collected approval into the other collected slot
   * (same signature counted twice must NOT satisfy M=2). */
  const txDup = finalizeSimple(buildA, delegate, pkgA);
  const [sig1, sig2] = pkgA.approvals.filter((x) => x !== null);
  if (!txDup.inputs[0].signatureScript.includes(sig2)) throw new Error("dup-vector construction failed");
  txDup.inputs[0].signatureScript = txDup.inputs[0].signatureScript.replace(sig2, sig1);
  emit("neg_approval_duplicated_across_slots", "reject", buildA, txDup, { action: "delegateSpend" });
}

fs.writeFileSync(path.join(outDir, "index.json"), JSON.stringify(vectors, null, 1));
console.log(`wrote ${vectors.length} vectors to ${outDir}`);
