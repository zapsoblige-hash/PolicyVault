"use strict";

/*
 * PolicyVault v0.4 PRODUCTION-BYTE vector generator (Checkpoint E §E10/§E11).
 *
 * Drives the ACTUAL production SDK code — vault-state-v4, the exact-state
 * compiler (contract-compiler-v4 via silverc), agent-merkle-v4,
 * recipient-merkle-v3, vault-transitions-v4, compute-budget-v4,
 * frozen-tx-v3, approval-package-v4, vault-builders-v4, and the REAL
 * pv_call_encoder + pv_tx_probe binaries — to construct fully-finalized
 * v0.4 transactions with real Schnorr signatures (rusty-kaspa WASM
 * createInputSignature over deterministic TEST-ONLY keys).
 * tests/vm/tests/v4_sdk_integration.rs executes every emitted vector's
 * EXACT bytes on the real TxScriptEngine against the PRODUCTION
 * PolicyVault.v0.4.sil.
 *
 * If a JS bug ever produced wrong consensus bytes anywhere in that chain,
 * the VM execution fails — the production-byte rule applied to the entire
 * SDK construction path, not just the encoder (the v0.2 boundVaultId
 * lesson).
 *
 * Positive vectors (§E10) exercise the full production matrix; negative
 * vectors (§E11) are otherwise-valid transactions with ONE security field
 * mutated after freeze/finalize — the SDK itself refuses to build these,
 * so they are crafted from the final bytes (JSON-level output/outpoint/
 * lock mutations, sigscript approval splices, and re-encoded tampered
 * covenant calls) and MUST be rejected by consensus.
 *
 * Usage: node gen-v4-vectors.js <output-dir>
 * TEST KEYS ONLY: secrets are the byte value repeated 32x, matching the
 * Rust harness deterministic_keypair(v). Never production material.
 */

const fs = require("fs");
const path = require("path");

const { loadConfig } = require("../src/config");
const { buildAgentTreeV4, generateAgentProofV4 } = require("../src/agent-merkle-v4");
const { buildRecipientTree } = require("../src/recipient-merkle-v3");
const {
  buildV4Transaction,
  buildCreateV4,
  finalizeV4Transaction,
  createApprovalPackageForBuildV4,
  runEncoderV4,
  successorCallJsonV4
} = require("../src/vault-builders-v4");
const { frozenToWasmTransaction } = require("../src/frozen-tx-v3");
const { submitApprovalV4, approvalsBlobV4, placeholderApprovalsBlob } = require("../src/approval-package-v4");
const { covenantSigscript } = require("../src/spend-vault");

const outDir = process.argv[2];
if (!outDir) {
  console.error("usage: node gen-v4-vectors.js <output-dir>");
  process.exit(1);
}
fs.mkdirSync(outDir, { recursive: true });

const config = loadConfig({ dataRoot: path.join(outDir, "data") });
const kaspa = require(config.rustyKaspaModule);

const KAS = 100000000n;
const KEY = (v) => new kaspa.PrivateKey(v.toString(16).padStart(2, "0").repeat(32));
const XO = (p) => p.toPublicKey().toXOnlyPublicKey().toString().toLowerCase();

const owner = KEY(1);
const agentA = KEY(0x1e); // 30
const agentB = KEY(0x1f); // 31
const fuelKey = KEY(3);
const recipient = KEY(0x28); // 40
const otherRecipient = KEY(0x29); // 41
const approvers3 = [KEY(20), KEY(21), KEY(22)];
const approvers10 = Array.from({ length: 10 }, (_, i) => KEY(60 + i));

const OWNER = XO(owner);
const COVENANT_ID = "41".repeat(32); // COV_A in the Rust harness (b"AAAA…")
const VAULT_ID = "22".repeat(32);
const template = { owner: OWNER, vaultId: VAULT_ID };

/* A depth-d recipient tree containing the real recipient at index 1. */
function recipTreeAtDepth(depth) {
  if (depth === 0) return buildRecipientTree([XO(recipient)]);
  const n = 1 << depth;
  const fillers = [];
  for (let i = 0; fillers.length < n - 1 && i <= 0xffffff; i++) {
    const k = i.toString(16).padStart(6, "0").repeat(11).slice(0, 64);
    if (k !== XO(recipient) && k !== XO(otherRecipient)) fillers.push(k);
  }
  if (fillers.length !== n - 1) throw new Error(`could not build ${n - 1} filler recipients for depth ${depth}`);
  return buildRecipientTree([XO(recipient), ...fillers]);
}

function agentPolicy(pkHex, recipientRoot, over = {}) {
  return {
    agentPk: pkHex,
    maxPerSpend: (200n * KAS).toString(),
    periodBudget: (1000n * KAS).toString(),
    periodLengthDaa: "864000",
    periodStartDaa: "541000000",
    periodSpent: "0",
    approvalThreshold: (50n * KAS).toString(),
    agentMaxFeePerTx: (1n * KAS).toString(),
    agentRecipientRoot: recipientRoot,
    ...over
  };
}

/* A depth-d agent tree with the real agent (agentA) at some index and
 * distinct fillers (distinct keys + distinct recipient roots). */
function agentSetAtDepth(depth, aPolicy) {
  if (depth === 0) return [aPolicy];
  const n = 1 << depth;
  const agents = [aPolicy];
  for (let i = 1; i < n; i++) {
    const pk = i.toString(16).padStart(8, "0").repeat(8);
    const root = ("f" + i.toString(16)).padStart(4, "0").repeat(16).slice(0, 64);
    agents.push(agentPolicy(pk, root, { maxPerSpend: (1n * KAS).toString(), periodBudget: (1n * KAS).toString(), approvalThreshold: "1", agentMaxFeePerTx: "1" }));
  }
  return agents;
}

function baseState(over = {}) {
  return {
    protectedValue: (10000n * KAS).toString(),
    feeReserve: (5n * KAS).toString(),
    paused: "0",
    agentRoot: over.agentRoot,
    approvers: over.approvers ?? [],
    approvalM: over.approvalM ?? "0",
    policyNonce: over.policyNonce ?? "0",
    ...over
  };
}

function chain({ value, fuel = false, outpoint = "42" }) {
  const ctx = { predecessorOutpoint: { transactionId: outpoint.repeat(32), index: 0 }, predecessorValue: value, covenantId: COVENANT_ID };
  if (fuel) ctx.fuel = { outpoint: { transactionId: "43".repeat(32), index: 1 }, amount: (100n * KAS).toString(), scriptPublicKeyHex: `20${XO(fuelKey)}ac` };
  return ctx;
}

function signCov(build, kp) {
  return kaspa.createInputSignature(frozenToWasmTransaction(config, build.frozen), 0, kp).slice(2);
}
function signFuel(build) {
  return kaspa.createInputSignature(frozenToWasmTransaction(config, build.frozen), 1, fuelKey);
}
function approverSig(build, kp) {
  return kaspa.createInputSignature(frozenToWasmTransaction(config, build.frozen), 0, kp).slice(2);
}
function collect(build, signers) {
  let pkg = createApprovalPackageForBuildV4(build);
  for (const kp of signers) pkg = submitApprovalV4(pkg, { signatureHex: approverSig(build, kp), approverXOnly: XO(kp) });
  return pkg;
}
function finalize(build, covKp, approvalPackage) {
  return finalizeV4Transaction({
    build,
    covenantSignatureHex: signCov(build, covKp),
    fuelSignatureScriptHex: build.hasFuelInput ? signFuel(build) : undefined,
    approvalPackage
  }).finalTransaction;
}

const vectors = [];
function emit(name, expect, build, finalTx) {
  vectors.push({ name, expect });
  const dir = path.join(outDir, name);
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(
    path.join(dir, "vector.json"),
    JSON.stringify({ name, expect, action: build?.action ?? "unknown", committedBudget: build?.computeBudget ?? null, requiredFeeSompi: build?.requiredFeeSompi ?? null, tx: finalTx }, null, 1)
  );
}

/* Re-encode a tampered covenant CALL and reassemble the final tx (the
 * agent/owner sighash excludes the sigscript, so covSig stays valid — the
 * covenant rejects on its internal require). Used for §E11 call-embedded
 * mutations the SDK refuses to emit. */
function reencodeCall(build, covKp, mutateCall, approvalsHex) {
  const covSig = signCov(build, covKp);
  const call = { function: build.action, signature: covSig, ...build.callExtra };
  if (build.action !== "ownerRecover") call.successor = successorCallJsonV4(build.successorState);
  if (build.action === "agentSpend") call.approvals = approvalsHex ?? placeholderApprovalsBlob();
  mutateCall(call);
  const callHex = runEncoderV4({
    sourcePath: path.join(build.encoderBuildDir, "PolicyVault.state.sil"),
    constructorArgsPath: path.join(build.encoderBuildDir, "constructor-args.json"),
    call
  });
  const artifact = JSON.parse(fs.readFileSync(path.join(build.encoderBuildDir, "artifact.json")));
  const sigscript = covenantSigscript(callHex, Buffer.from(artifact.script));
  const json = JSON.parse(build.frozenCanonicalJson);
  json.inputs[0].signatureScript = sigscript;
  if (build.hasFuelInput) json.inputs[1].signatureScript = signFuel(build);
  return json;
}

/* ================================================================ POSITIVE */

/* Agent depth matrix (recip depth 0), reserve-funded, below threshold. */
for (const adepth of [0, 12]) {
  const rTree = recipTreeAtDepth(0);
  const aPolicy = agentPolicy(XO(agentA), rTree.root, { approvalThreshold: (100000n * KAS).toString() });
  const agents = agentSetAtDepth(adepth, aPolicy);
  const aTree = buildAgentTreeV4(agents);
  const state = baseState({ agentRoot: aTree.root });
  const build = buildV4Transaction({
    config, templateInput: template, stateInput: state, action: "agentSpend",
    params: { payAmountSompi: (40n * KAS).toString(), agentPk: XO(agentA), agents, recipient: XO(recipient), recipients: [...rTree.recipients] },
    chain: chain({ value: (10005n * KAS).toString(), fuel: false }), changeXOnly: OWNER
  });
  emit(`agent_depth_${adepth}_reserve`, "accept", build, finalize(build, agentA));
}

/* Recipient depth matrix (agent depth 0), reserve-funded, below threshold. */
for (const rdepth of [0, 16]) {
  const rTree = recipTreeAtDepth(rdepth);
  const aPolicy = agentPolicy(XO(agentA), rTree.root, { approvalThreshold: (100000n * KAS).toString() });
  const agents = [aPolicy];
  const aTree = buildAgentTreeV4(agents);
  const state = baseState({ agentRoot: aTree.root });
  const build = buildV4Transaction({
    config, templateInput: template, stateInput: state, action: "agentSpend",
    params: { payAmountSompi: (40n * KAS).toString(), agentPk: XO(agentA), agents, recipient: XO(recipient), recipients: [...rTree.recipients] },
    chain: chain({ value: (10005n * KAS).toString(), fuel: false }), changeXOnly: OWNER
  });
  emit(`recip_depth_${rdepth}_reserve`, "accept", build, finalize(build, agentA));
}

/* Fuel-funded spend, zero reserve consumption (external ordinary fee). */
{
  const rTree = recipTreeAtDepth(0);
  const aPolicy = agentPolicy(XO(agentA), rTree.root, { approvalThreshold: (100000n * KAS).toString() });
  const agents = [aPolicy];
  const aTree = buildAgentTreeV4(agents);
  const state = baseState({ agentRoot: aTree.root });
  const build = buildV4Transaction({
    config, templateInput: template, stateInput: state, action: "agentSpend",
    params: { payAmountSompi: (40n * KAS).toString(), agentPk: XO(agentA), agents, recipient: XO(recipient), recipients: [...rTree.recipients] },
    chain: chain({ value: (10005n * KAS).toString(), fuel: true }), changeXOnly: XO(fuelKey)
  });
  emit("spend_fuel_zero_reserve", "accept", build, finalize(build, agentA));
}

/* Rollover reserve-funded (near budget, CLTV lock time). */
{
  const rTree = recipTreeAtDepth(0);
  const aPolicy = agentPolicy(XO(agentA), rTree.root, { approvalThreshold: (100000n * KAS).toString(), periodSpent: (980n * KAS).toString() });
  const agents = [aPolicy];
  const aTree = buildAgentTreeV4(agents);
  const state = baseState({ agentRoot: aTree.root });
  const build = buildV4Transaction({
    config, templateInput: template, stateInput: state, action: "agentSpend",
    params: { payAmountSompi: (40n * KAS).toString(), agentPk: XO(agentA), agents, recipient: XO(recipient), recipients: [...rTree.recipients], periodsElapsed: "1" },
    chain: chain({ value: (10005n * KAS).toString(), fuel: false }), changeXOnly: OWNER
  });
  emit("rollover_reserve", "accept", build, finalize(build, agentA));
}

/* Approval tiers: threshold boundary (delegate-only), 1-of-3, 2-of-3, 10-of-10. */
function approvedBuild({ agents, aTree, rTree, pay, approverKeys, m }) {
  const state = baseState({ agentRoot: aTree.root, approvers: approverKeys.map(XO), approvalM: String(m) });
  return buildV4Transaction({
    config, templateInput: template, stateInput: state, action: "agentSpend",
    params: { payAmountSompi: pay, agentPk: XO(agentA), agents, recipient: XO(recipient), recipients: [...rTree.recipients] },
    chain: chain({ value: (10005n * KAS).toString(), fuel: true }), changeXOnly: XO(fuelKey)
  });
}
let approved2of3Build = null;
let approved2of3Pkg = null;
{
  const rTree = recipTreeAtDepth(0);
  const aPolicy = agentPolicy(XO(agentA), rTree.root, { approvalThreshold: (50n * KAS).toString() });
  const agents = [aPolicy];
  const aTree = buildAgentTreeV4(agents);

  // threshold boundary: pay == threshold -> delegate only (below-threshold budget)
  const bBoundary = approvedBuild({ agents, aTree, rTree, pay: (50n * KAS).toString(), approverKeys: approvers3, m: 2 });
  emit("spend_equal_threshold_delegate_only", "accept", bBoundary, finalize(bBoundary, agentA));

  // 1-of-3
  const state1 = baseState({ agentRoot: aTree.root, approvers: approvers3.map(XO), approvalM: "1" });
  const b1 = buildV4Transaction({
    config, templateInput: template, stateInput: state1, action: "agentSpend",
    params: { payAmountSompi: (60n * KAS).toString(), agentPk: XO(agentA), agents, recipient: XO(recipient), recipients: [...rTree.recipients] },
    chain: chain({ value: (10005n * KAS).toString(), fuel: true }), changeXOnly: XO(fuelKey)
  });
  emit("approved_1of3", "accept", b1, finalize(b1, agentA, collect(b1, [approvers3[0]])));

  // 2-of-3 (kept for the negative matrix)
  const b2 = approvedBuild({ agents, aTree, rTree, pay: (60n * KAS).toString(), approverKeys: approvers3, m: 2 });
  const pkg2 = collect(b2, [approvers3[0], approvers3[1]]);
  approved2of3Build = b2;
  approved2of3Pkg = pkg2;
  emit("approved_2of3", "accept", b2, finalize(b2, agentA, pkg2));

  // 10-of-10
  const b10 = approvedBuild({ agents, aTree, rTree, pay: (60n * KAS).toString(), approverKeys: approvers10, m: 10 });
  emit("approved_10of10", "accept", b10, finalize(b10, agentA, collect(b10, approvers10)));
}

/* WORST CASE: agent depth 12 + recipient depth 16 + 10-of-10 + reserve. */
{
  const rTree = recipTreeAtDepth(16);
  const aPolicy = agentPolicy(XO(agentA), rTree.root, { approvalThreshold: (50n * KAS).toString() });
  const agents = agentSetAtDepth(12, aPolicy);
  const aTree = buildAgentTreeV4(agents);
  const state = baseState({ agentRoot: aTree.root, approvers: approvers10.map(XO), approvalM: "10" });
  const build = buildV4Transaction({
    config, templateInput: template, stateInput: state, action: "agentSpend",
    params: { payAmountSompi: (150n * KAS).toString(), agentPk: XO(agentA), agents, recipient: XO(recipient), recipients: [...rTree.recipients], reserveConsumedSompi: (1000000n).toString() },
    chain: chain({ value: (10005n * KAS).toString(), fuel: true }), changeXOnly: XO(fuelKey)
  });
  emit("worst_agent12_recip16_10of10", "accept", build, finalize(build, agentA, collect(build, approvers10)));
}

/* Owner operations. */
{
  const rTree = recipTreeAtDepth(0);
  const aPolicy = agentPolicy(XO(agentA), rTree.root);
  const agents = [aPolicy];
  const aTree = buildAgentTreeV4(agents);
  const state = baseState({ agentRoot: aTree.root, approvers: approvers3.map(XO), approvalM: "2" });
  const c = chain({ value: (10005n * KAS).toString(), fuel: true });
  const ownerOp = (name, action, params) => {
    const build = buildV4Transaction({ config, templateInput: template, stateInput: state, action, params, chain: c, changeXOnly: OWNER });
    emit(name, "accept", build, finalize(build, owner));
    return build;
  };
  ownerOp("owner_set_agent_root", "ownerSetAgentRoot", { newAgentRoot: "cd".repeat(32) });
  ownerOp("owner_set_approvers", "ownerSetApprovers", { newApprovers: { approvers: approvers10.slice(0, 4).map(XO), approvalM: "3" } });
  ownerOp("owner_topup", "ownerTopUp", { topUpAmountSompi: (10n * KAS).toString() });
  ownerOp("owner_topup_reserve", "ownerTopUpReserve", { topUpReserveAmountSompi: (2n * KAS).toString() });
  ownerOp("owner_pause", "ownerPause", {});

  // unpause needs a paused predecessor
  const paused = baseState({ agentRoot: aTree.root, approvers: approvers3.map(XO), approvalM: "2", paused: "1" });
  const b = buildV4Transaction({ config, templateInput: template, stateInput: paused, action: "ownerUnpause", params: {}, chain: c, changeXOnly: OWNER });
  emit("owner_unpause", "accept", b, finalize(b, owner));
}

/* Recover with reserve, and recover with zero reserve (break-glass). */
{
  const rTree = recipTreeAtDepth(0);
  const aPolicy = agentPolicy(XO(agentA), rTree.root);
  const aTree = buildAgentTreeV4([aPolicy]);
  const withReserve = baseState({ agentRoot: aTree.root });
  const b1 = buildV4Transaction({
    config, templateInput: template, stateInput: withReserve, action: "ownerRecover", params: {},
    chain: chain({ value: (10005n * KAS).toString(), fuel: true }), changeXOnly: OWNER
  });
  emit("recover_with_reserve", "accept", b1, finalize(b1, owner));

  const zeroReserve = baseState({ agentRoot: "ef".repeat(32), feeReserve: "0", paused: "1", policyNonce: "9" });
  const b2 = buildV4Transaction({
    config, templateInput: template, stateInput: zeroReserve, action: "ownerRecover", params: { allowMalformedState: true },
    chain: chain({ value: (10000n * KAS).toString(), fuel: true }), changeXOnly: OWNER
  });
  emit("recover_zero_reserve_malformed", "accept", b2, finalize(b2, owner));
}

/* Genesis (executed as an ordinary funding tx — no covenant input to run,
 * but its bytes are emitted for structural parsing; not a VM-accept case,
 * so it is NOT added to the executable index). */
{
  const rTree = recipTreeAtDepth(0);
  const aTree = buildAgentTreeV4([agentPolicy(XO(agentA), rTree.root)]);
  const g = buildCreateV4({
    config, templateInput: template, initialStateInput: baseState({ agentRoot: aTree.root }),
    funding: [{ outpoint: { transactionId: "45".repeat(32), index: 0 }, amount: (20000n * KAS).toString(), scriptPublicKeyHex: `20${OWNER}ac` }],
    changeXOnly: OWNER
  });
  fs.mkdirSync(path.join(outDir, "genesis"), { recursive: true });
  fs.writeFileSync(path.join(outDir, "genesis", "vector.json"), JSON.stringify({ name: "genesis", covenantId: g.covenantId, txId: g.txId, tx: JSON.parse(g.frozenCanonicalJson) }, null, 1));
}

/* ================================================================ NEGATIVE
 * (§E11) — otherwise-valid transactions with ONE security field mutated;
 * consensus MUST reject. */

/* Build one below-threshold fuel-funded spend to mutate. */
const rTree0 = recipTreeAtDepth(0);
const negPolicy = agentPolicy(XO(agentA), rTree0.root, { approvalThreshold: (100000n * KAS).toString() });
const negAgents = [negPolicy, agentPolicy(XO(agentB), "bb".repeat(32), { maxPerSpend: (900n * KAS).toString() })];
const negTree = buildAgentTreeV4(negAgents);
const negState = baseState({ agentRoot: negTree.root });
function negBuild(extraParams = {}) {
  return buildV4Transaction({
    config, templateInput: template, stateInput: negState, action: "agentSpend",
    params: { payAmountSompi: (40n * KAS).toString(), agentPk: XO(agentA), agents: negAgents, recipient: XO(recipient), recipients: [...rTree0.recipients], ...extraParams },
    chain: chain({ value: (10005n * KAS).toString(), fuel: true }), changeXOnly: XO(fuelKey)
  });
}

/* JSON-level mutations (SIG_HASH_ALL binds these; agent checkSig dies or a
 * covenant require fails). */
{
  const build = negBuild();
  const valid = finalize(build, agentA);

  const mutRecipient = JSON.parse(JSON.stringify(valid));
  mutRecipient.outputs[0].scriptPublicKey.scriptHex = `20${XO(otherRecipient)}ac`;
  emit("neg_recipient_substituted", "reject", build, mutRecipient);

  const mutPay = JSON.parse(JSON.stringify(valid));
  mutPay.outputs[0].value = (BigInt(mutPay.outputs[0].value) + 1n).toString();
  emit("neg_payment_amount_raised", "reject", build, mutPay);

  const mutSucc = JSON.parse(JSON.stringify(valid));
  mutSucc.outputs[1].value = (BigInt(mutSucc.outputs[1].value) - 1n).toString();
  emit("neg_successor_value_lowered", "reject", build, mutSucc);

  const mutOutpoint = JSON.parse(JSON.stringify(valid));
  mutOutpoint.inputs[0].previousOutpoint.transactionId = "99".repeat(32);
  mutOutpoint.inputs[0].utxo.outpoint = undefined;
  emit("neg_predecessor_outpoint_changed", "reject", build, mutOutpoint);
}

/* Rollover lock-time / sequence mutations. */
{
  const rTreeR = recipTreeAtDepth(0);
  const aPolicy = agentPolicy(XO(agentA), rTreeR.root, { approvalThreshold: (100000n * KAS).toString(), periodSpent: (980n * KAS).toString() });
  const agents = [aPolicy];
  const aTree = buildAgentTreeV4(agents);
  const state = baseState({ agentRoot: aTree.root });
  const build = buildV4Transaction({
    config, templateInput: template, stateInput: state, action: "agentSpend",
    params: { payAmountSompi: (40n * KAS).toString(), agentPk: XO(agentA), agents, recipient: XO(recipient), recipients: [...rTreeR.recipients], periodsElapsed: "1" },
    chain: chain({ value: (10005n * KAS).toString(), fuel: false }), changeXOnly: OWNER
  });
  const valid = finalize(build, agentA);
  const belowLock = JSON.parse(JSON.stringify(valid));
  belowLock.lockTime = (BigInt(belowLock.lockTime) - 1n).toString();
  emit("neg_rollover_locktime_below_newstart", "reject", build, belowLock);
  const finalizedSeq = JSON.parse(JSON.stringify(valid));
  finalizedSeq.inputs[0].sequence = (2n ** 64n - 1n).toString();
  emit("neg_rollover_finalized_sequence", "reject", build, finalizedSeq);
}

/* Call-embedded mutations (re-encode a tampered covenant call; agent
 * sighash unchanged so the agent sig stays valid — the covenant rejects). */
{
  const build = negBuild();
  emit("neg_call_forged_successor_protected", "reject", build,
    reencodeCall(build, agentA, (c) => { c.successor.protectedValue = (999n * KAS).toString(); }));
  emit("neg_call_forged_successor_reserve", "reject", build,
    reencodeCall(build, agentA, (c) => { c.successor.feeReserve = (999n * KAS).toString(); }));
  emit("neg_call_forged_successor_agentroot", "reject", build,
    reencodeCall(build, agentA, (c) => { c.successor.agentRoot = "ee".repeat(32); }));
  emit("neg_call_successor_nonce_bumped", "reject", build,
    reencodeCall(build, agentA, (c) => { c.successor.policyNonce = 1; }));
  emit("neg_call_successor_paused_flipped", "reject", build,
    reencodeCall(build, agentA, (c) => { c.successor.paused = 1; }));
  emit("neg_call_borrow_bigger_cap", "reject", build,
    reencodeCall(build, agentA, (c) => { c.maxPerSpend = (900n * KAS).toString(); }));
  emit("neg_call_borrow_fee_cap", "reject", build,
    reencodeCall(build, agentA, (c) => { c.agentMaxFeePerTx = (500n * KAS).toString(); }));
  emit("neg_call_agent_key_swapped", "reject", build,
    reencodeCall(build, agentA, (c) => { c.agentPk = XO(agentB); }));
  emit("neg_call_policy_proof_truncated", "reject", build,
    reencodeCall(build, agentA, (c) => { c.policySiblings = c.policySiblings.slice(0, -64); }));
  emit("neg_call_recipient_proof_tampered", "reject", build,
    reencodeCall(build, agentA, (c) => { c.recipientPk = XO(otherRecipient); }));
}

/* Owner-op field-preservation mutations (re-encode a tampered owner call). */
{
  const rTreeO = recipTreeAtDepth(0);
  const aTree = buildAgentTreeV4([agentPolicy(XO(agentA), rTreeO.root)]);
  const state = baseState({ agentRoot: aTree.root, approvers: approvers3.map(XO), approvalM: "2" });
  const c = chain({ value: (10005n * KAS).toString(), fuel: true });
  const setRoot = buildV4Transaction({ config, templateInput: template, stateInput: state, action: "ownerSetAgentRoot", params: { newAgentRoot: "cd".repeat(32) }, chain: c, changeXOnly: OWNER });
  emit("neg_owner_setroot_no_nonce_bump", "reject", setRoot,
    reencodeCall(setRoot, owner, (call) => { call.successor.policyNonce = 0; }));
  emit("neg_owner_setroot_changes_value", "reject", setRoot,
    reencodeCall(setRoot, owner, (call) => { call.successor.protectedValue = (BigInt(call.successor.protectedValue) + KAS).toString(); }));

  const topUp = buildV4Transaction({ config, templateInput: template, stateInput: state, action: "ownerTopUp", params: { topUpAmountSompi: (10n * KAS).toString() }, chain: c, changeXOnly: OWNER });
  emit("neg_owner_topup_touches_reserve", "reject", topUp,
    reencodeCall(topUp, owner, (call) => { call.successor.feeReserve = (BigInt(call.successor.feeReserve) + KAS).toString(); }));
}

/* Approval-blob splices (§E11 approval attacks) against the 2-of-3 build. */
{
  const build = approved2of3Build;
  const pkg = approved2of3Pkg;
  const valid = finalize(build, agentA, pkg);
  const sig = valid.inputs[0].signatureScript;
  const collected = pkg.approvals.filter((s) => s !== null);
  const [x, y] = collected;

  // swap the two collected approvals (each then checkSig-fails its slot)
  const swapped = JSON.parse(JSON.stringify(valid));
  swapped.inputs[0].signatureScript = sig.replace(x, " TMP ").replace(y, x).replace(" TMP ", y);
  emit("neg_approvals_swapped_slots", "reject", build, swapped);

  // duplicate one approval into the other slot (counted once -> < M)
  const dup = JSON.parse(JSON.stringify(valid));
  dup.inputs[0].signatureScript = sig.replace(y, x);
  emit("neg_approval_duplicated_across_slots", "reject", build, dup);

  // flip one approval's trailing sighash byte to 0x02 (A7 gate)
  const gate = JSON.parse(JSON.stringify(valid));
  gate.inputs[0].signatureScript = sig.replace(x, x.slice(0, -2) + "02");
  emit("neg_approval_trailing_byte_not_all", "reject", build, gate);
}

/* Approval replay onto a DIFFERENT transaction intent (same predecessor,
 * different recipient). SIG_HASH_ALL must kill it. */
{
  const rTree = recipTreeAtDepth(0);
  // both recipients live in the agent's tree
  const rTree2 = buildRecipientTree([XO(recipient), XO(otherRecipient)]);
  const aPolicy = agentPolicy(XO(agentA), rTree2.root, { approvalThreshold: (50n * KAS).toString() });
  const agents = [aPolicy];
  const aTree = buildAgentTreeV4(agents);
  const state = baseState({ agentRoot: aTree.root, approvers: approvers3.map(XO), approvalM: "2" });
  const mk = (target) =>
    buildV4Transaction({
      config, templateInput: template, stateInput: state, action: "agentSpend",
      params: { payAmountSompi: (60n * KAS).toString(), agentPk: XO(agentA), agents, recipient: target, recipients: [...rTree2.recipients] },
      chain: chain({ value: (10005n * KAS).toString(), fuel: true }), changeXOnly: XO(fuelKey)
    });
  const buildTarget = mk(XO(recipient));
  const buildOther = mk(XO(otherRecipient));
  const pkgTarget = collect(buildTarget, [approvers3[0], approvers3[1]]);
  const pkgOther = collect(buildOther, [approvers3[0], approvers3[1]]);
  const txOther = finalize(buildOther, agentA, pkgOther);
  let s = txOther.inputs[0].signatureScript;
  for (let i = 0; i < pkgTarget.approvals.length; i++) {
    const a = pkgTarget.approvals[i];
    const b = pkgOther.approvals[i];
    if (a && b) {
      s = s.replace(b, a);
    }
  }
  txOther.inputs[0].signatureScript = s;
  emit("neg_approvals_replayed_other_recipient", "reject", buildOther, txOther);
  void rTree;
}

fs.writeFileSync(path.join(outDir, "index.json"), JSON.stringify(vectors, null, 1));
console.log(`wrote ${vectors.length} executable vectors (+ genesis structural) to ${outDir}`);
