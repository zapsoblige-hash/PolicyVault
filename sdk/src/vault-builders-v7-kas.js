"use strict";

/*
 * PolicyVault v0.7 ROOTED KAS SAFE-PAYMENT VAULT transaction builders.
 *
 * Sibling of sdk/src/vault-builders-v7.js (the rooted PAYMENT profile): the
 * SAME byte-level root-successor pinning and offline-build/finalize
 * discipline, applied to contracts/PolicyVault.v0.7-kas.sil (derived from
 * the FROZEN v0.4.1 plain-KAS covenant) instead of the frozen v0.5 token
 * controller. BUILDERS NEVER BROADCAST. The frozen form is the security
 * object; ANY drift between planned and final bytes fails closed
 * (FEE_DRIFT).
 *
 * SHAPES:
 *
 *   root-only        in: [root(sequence), fuel]        out: [root', change]
 *   rooted owner op  in: [vault, root(seq), fuel]       out: [vault', root', change]
 *   rooted recover    in: [vault, root, fuel]            out: [payout(recoveryPk),
 *                                                             root', change]
 *   delegate spend   in: [vault, fuel?]                 out: [recipient,
 *                                                             vault', change?]
 *                    — NO root input, byte-for-byte the frozen v0.4.1 shape
 *                    (including the vault-level M-of-N approval blob above
 *                    the agent's own approvalThreshold)
 *   vault genesis     in: [funding...]                   out: [vault, change]
 *
 * ROOT-ONLY transactions (genesis, rotate, freeze, unfreeze, succession) are
 * IDENTICAL regardless of which vault profile rides alongside the root, so
 * this module does NOT re-implement them: buildCreateV7Root,
 * buildV7RootTransaction, finalizeV7RootTransaction and resolveRootActionV7
 * are imported from sdk/src/vault-builders-v7.js and re-exported here
 * unchanged. The M-of-N owner-signature blob assembly for a COMBINED
 * (vault + root) transaction reuses the SAME core primitives
 * (assembleOwnerSigsBlobV7, placeholderOwnerSigsBlobV7, OWNER_SLOTS_V7,
 * SIG_BLOB_LEN_V7 from core/model/owner-set-v7.js) that vault-builders-v7.js
 * itself calls — never a second implementation of the blob format.
 *
 * The DELEGATE path (agentSpend) reuses the FROZEN v0.4.1 agent-policy
 * Merkle tree, recipient Merkle tree, and above-threshold M-of-N APPROVAL
 * PACKAGE mechanism VERBATIM (sdk/src/agent-merkle-v4.js,
 * sdk/src/recipient-merkle-v3.js, sdk/src/approval-package-v4.js) — this is
 * a DIFFERENT M-of-N mechanism from the organizational root's (the vault-
 * level approver tier above a per-agent threshold), unchanged by v0.7-kas.
 * NOTE: createApprovalPackageV4 stamps `contractVersion: "policyvault-0.4"`
 * on the package it returns — this is not a bug to work around here; it
 * TRUTHFULLY reflects that the vault-level approval mechanism is v0.4.1's,
 * carried byte-for-byte (see docs/postlaunch/v0.7-kas-profile-readiness.md).
 *
 * The delegate signature (agentSig) is now (candidate hardening E6(a),
 * tools/gen_v7_kas.js) gated to SIG_HASH_ALL in-covenant, exactly like the
 * v0.4/v0.4.1 covenant signature always was — extractSchnorr65 below already
 * enforces the same trailing-0x01 rule the frozen v0.4 builders use, so no
 * new signature-shape handling is needed.
 *
 * FEES. Every owner/recover path takes its network fee from an ordinary
 * FUEL UTXO: an owner operation pins every covenant value, so the fee
 * cannot come from a covenant output. A delegate spend keeps BOTH v0.4.1
 * funding modes (RESERVE: no chain.fuel, the exact fee is derived from the
 * covenant fee reserve by a bounded fixed point; FUEL: chain.fuel present,
 * the caller chooses reserveConsumed within the covenant's bounds).
 *
 * Status: IMPLEMENTED (SDK). Production-byte proof:
 * sdk/tools/gen-v7-kas-vectors.js + tests/vm/tests/v7_kas_sdk_integration.rs
 * execute every SDK-built shape through the real engine.
 */

const fs = require("fs");
const path = require("path");

const { parseSompi, parsePositiveSompi } = require("./amounts");
const { normalizeHex, normalizeXOnlyPubkey } = require("./vault-state");
const {
  CONTRACT_VERSION_V7_KAS,
  resolveV7KasAbi,
  resolveOwnerOpAuthorityV7Kas,
  normalizeTemplateV7Kas,
  templateToJsonV7Kas
} = require("../../core/model/vault-state-v7-kas");
const { normalizeStateV4, normalizeStateV4ForRecovery, stateToJsonV4, MAX_APPROVERS } = require("../../core/model/vault-state-v4");
const {
  CONTRACT_VERSION_V7_ROOT,
  normalizeRootTemplateV7,
  normalizeRootStateV7,
  rootTemplateToJsonV7,
  rootStateToJsonV7
} = require("../../core/model/vault-state-v7-root");
const { rootTransitionV7, assertRootValueRuleV7 } = require("../../core/model/vault-transitions-v7-root");
const {
  agentSpendSuccessorV7Kas,
  ownerOpSuccessorV7Kas,
  recoverPlanV7Kas
} = require("../../core/model/vault-transitions-v7-kas");
const { OWNER_SLOTS_V7, SIG_BLOB_LEN_V7, activeOwnerSlotsV7, assembleOwnerSigsBlobV7, placeholderOwnerSigsBlobV7 } = require("../../core/model/owner-set-v7");
const { selectComputeBudgetV7Kas, V7_KAS_BUDGET, selectRootComputeBudgetV7 } = require("../../core/model/compute-budget-v7-kas");
const { V7_BUDGET } = require("../../core/model/compute-budget-v7");
const { buildAgentTreeV4, generateAgentProofV4, verifyAgentProofV4 } = require("./agent-merkle-v4");
const { buildRecipientTree, generateRecipientProof, verifyRecipientProof } = require("./recipient-merkle-v3");
const { compileExactStateV7Kas, assertRootPinsMatchV7Kas } = require("./contract-compiler-v7-kas");
const { compileExactStateV7Root } = require("./contract-compiler-v7");
const { normalizeFrozenTxV3, describeFrozenTx, feeDescriptorFromFrozen, canonicalFrozenTxJson } = require("./frozen-tx-v3");
const { calculateRequiredFee } = require("./fee-mass");
const { covenantSigscript } = require("./spend-vault");
const { p2pkScriptHex, createApprovalPackageV4, placeholderApprovalsBlob, approvalsBlobV4 } = require("./approval-package-v4");
const { runEncoderV4, PLACEHOLDER_SIG_HEX, MAX_TX_FEE_IO } = require("./vault-builders-v4");
const { assertStorageMassWithinLimit } = require("./storage-mass-preflight");
const {
  buildCreateV7Root,
  buildV7RootTransaction,
  finalizeV7RootTransaction,
  rootSuccessorCallJsonV7,
  ROOT_ACTIONS_V7_NAMES,
  resolveRootActionV7
} = require("./vault-builders-v7");

const ORDINARY_SIGSCRIPT_LEN = 66; // 0x41 push + 65-byte Schnorr signature
const OWNER_CONTROL_ACTIONS_V7_KAS = new Set(["ownerSetAgentRoot", "ownerSetApprovers", "ownerTopUp", "ownerTopUpReserve", "ownerPause", "ownerUnpause", "ownerEmergencyPause"]);
const SPEND_ACTIONS_V7_KAS = new Set(["agentSpend"]);

function fail(message, code) {
  const e = new Error(`vault-builders-v7-kas: ${message}`);
  if (code) e.code = code;
  throw e;
}

function deepFreeze(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const key of Object.keys(value)) deepFreeze(value[key]);
  }
  return value;
}

function normalizeOutpoint(op, label) {
  const transactionId = normalizeHex(op?.transactionId, 32, `${label}.transactionId`);
  const index = Number(op?.index);
  if (!Number.isInteger(index) || index < 0 || index > 0xffffffff) fail(`${label}.index out of range`);
  return { transactionId, index };
}

function normalizeFuel(fuel) {
  if (!fuel || typeof fuel !== "object") fail("chain.fuel { outpoint, amount, scriptPublicKeyHex } is required for this operation (ordinary fee UTXO)", "FUEL_REQUIRED");
  const scriptPublicKeyHex = String(fuel.scriptPublicKeyHex ?? "").toLowerCase();
  if (!/^[0-9a-f]+$/.test(scriptPublicKeyHex) || scriptPublicKeyHex.length % 2 !== 0) fail("chain.fuel.scriptPublicKeyHex must be hex");
  return { outpoint: normalizeOutpoint(fuel.outpoint, "chain.fuel.outpoint"), amount: parsePositiveSompi(fuel.amount, "chain.fuel.amount"), scriptPublicKeyHex };
}

function exactFee(draft, sigScriptLengths) {
  const probe = normalizeFrozenTxV3(draft);
  return calculateRequiredFee(feeDescriptorFromFrozen(probe, sigScriptLengths)).minimumRequiredFee;
}

function p2shOf(config, scriptBytes) {
  const { loadKaspa } = require("./chain");
  const kaspa = loadKaspa(config);
  return String(kaspa.payToScriptHashScript(scriptBytes.toString("hex")).script).toLowerCase();
}

/* The v0.7-kas successor in the encoder's field names — byte-for-byte the
 * frozen v0.4.1 State shape (protectedValue, feeReserve, paused, agentRoot,
 * approver1..10, approvalM, policyNonce), so this is EXACTLY
 * successorCallJsonV4 restated locally to avoid a v4-internal import for one
 * tiny pure function (vault-builders-v4.js does not export it). */
function successorCallJsonV7Kas(stateJson) {
  const successor = {
    protectedValue: stateJson.protectedValue,
    feeReserve: stateJson.feeReserve,
    paused: Number(stateJson.paused),
    agentRoot: stateJson.agentRoot,
    approvalM: stateJson.approvalM,
    policyNonce: stateJson.policyNonce
  };
  stateJson.approverSlots.forEach((key, i) => {
    successor[`approver${i + 1}`] = key;
  });
  return successor;
}

/*
 * Resolve the spending agent's policy + Merkle proof — identical logic to
 * vault-builders-v4.js's resolveAgentProof, restated here (not exported
 * there) against the SAME frozen v0.4.1 agent-merkle module.
 */
function resolveAgentProofV7Kas(state, params) {
  const agentPk = normalizeXOnlyPubkey(params.agentPk, "params.agentPk");
  if (params.agents !== undefined) {
    const tree = buildAgentTreeV4(params.agents);
    if (tree.root !== state.agentRoot) fail("the supplied agent set does not reproduce the live agentRoot — refusing to build", "AGENT_ROOT_MISMATCH");
    const proof = generateAgentProofV4(tree, agentPk);
    return { policy: proof.policy, proof };
  }
  if (params.agentPolicy !== undefined && params.agentProof !== undefined) {
    const proof = {
      agentPk,
      root: normalizeHex(params.agentProof.root ?? state.agentRoot, 32, "agentProof.root"),
      siblingsHex: String(params.agentProof.siblingsHex ?? "").toLowerCase(),
      pathBits: parseSompi(params.agentProof.pathBits ?? 0n, "agentProof.pathBits")
    };
    if (proof.root !== state.agentRoot) fail("agent proof root does not match the live agentRoot", "AGENT_ROOT_MISMATCH");
    if (!verifyAgentProofV4({ root: state.agentRoot, policy: params.agentPolicy, siblingsHex: proof.siblingsHex, pathBits: proof.pathBits })) {
      fail("agent proof does not verify for this policy under the live agentRoot", "AGENT_PROOF_INVALID");
    }
    return { policy: params.agentPolicy, proof };
  }
  return fail("agentSpend requires either params.agents (full set) or params.agentPolicy + params.agentProof");
}

function resolveRecipientProofV7Kas(agentRecipientRoot, params) {
  const recipient = normalizeHex(params.recipient, 32, "params.recipient");
  let proof;
  if (params.recipients !== undefined) {
    const tree = buildRecipientTree(params.recipients);
    if (tree.root !== agentRecipientRoot) fail("the supplied recipient list does not reproduce this agent's agentRecipientRoot — refusing to build", "RECIPIENT_ROOT_MISMATCH");
    proof = generateRecipientProof(tree, recipient);
  } else if (params.recipientProof !== undefined) {
    proof = {
      recipient,
      root: normalizeHex(params.recipientProof.root, 32, "recipientProof.root"),
      siblingsHex: String(params.recipientProof.siblingsHex ?? "").toLowerCase(),
      pathBits: parseSompi(params.recipientProof.pathBits ?? 0n, "recipientProof.pathBits")
    };
  } else {
    fail("agentSpend requires either params.recipients (full list) or params.recipientProof");
  }
  if (proof.root !== agentRecipientRoot) fail("recipient proof root does not match this agent's agentRecipientRoot", "RECIPIENT_ROOT_MISMATCH");
  if (!verifyRecipientProof({ root: proof.root, recipient, siblingsHex: proof.siblingsHex, pathBits: BigInt(proof.pathBits) })) {
    fail("recipient proof does not verify for this recipient", "RECIPIENT_PROOF_INVALID");
  }
  return { recipient, proof };
}

/* Owner-operation successor planning, dispatching by SDK action. */
function planOwnerOpV7Kas(state, action, params) {
  const result = ownerOpSuccessorV7Kas(action, state, params);
  return { successor: result.successor, opSelector: result.opSelector, rootAuthority: result.rootAuthority, externalFunding: result.externalFunding };
}

/*
 * The ROOT SIDE of a rooted-vault owner operation: the exact root path the
 * vault's covenant will pin, planned and compiled from the live root state.
 * Identical in shape to vault-builders-v7.js's resolveRootSide, keyed off
 * the v0.7-kas owner-authority table (which additionally carries the
 * EMERGENCY-pause selector 6 -> FREEZE mapping).
 */
function resolveRootSideV7Kas({ config, action, root }) {
  const authority = resolveOwnerOpAuthorityV7Kas(action);
  if (!root || typeof root !== "object") fail("chain.root { template, state, outpoint, covenantId, value } is required — a rooted vault's owner authority IS the root input", "ROOT_INPUT_REQUIRED");
  const template = normalizeRootTemplateV7(root.template);
  const state = normalizeRootStateV7(root.state);
  const outpoint = normalizeOutpoint(root.outpoint, "chain.root.outpoint");
  const covenantId = normalizeHex(root.covenantId, 32, "chain.root.covenantId");
  const value = parsePositiveSompi(root.value, "chain.root.value");
  const plan = rootTransitionV7(authority.rootActionName, state, { template });
  if (plan.successor.frozen !== authority.expectFrozenAfter) fail("internal: the planned root successor does not carry the frozen byte this vault operation pins");
  const current = compileExactStateV7Root({ config, template, state });
  const next = compileExactStateV7Root({ config, template, state: plan.successor });
  assertRootValueRuleV7({ inputValue: value, successorValue: value, rootMaxFeePerTx: template.rootMaxFeePerTx });
  return {
    authority,
    template,
    state,
    plan,
    outpoint,
    covenantId,
    value,
    current,
    next,
    budget: selectRootComputeBudgetV7({ actionName: authority.rootActionName, activeOwnerSlots: state.activeCount })
  };
}

/* ------------------------------------------------------------------ */
/* ROOTED KAS VAULT: genesis                                            */
/* ------------------------------------------------------------------ */

/*
 * GENESIS of a rooted KAS vault: ordinary funding inputs -> [the vault
 * output holding protectedValue + feeReserve, change]. The template's
 * orgRootCovenantId/rootTemplateVmHash/rootGeometry MUST already pin a REAL
 * compiled root (assertRootPinsMatchV7Kas), so a genesis can never produce a
 * vault whose owner path is permanently unusable.
 */
function buildCreateV7KasVault({ config, templateInput, initialStateInput, funding, changeXOnly, contractVersion, rootTemplate, rootOwnerSet }) {
  const abi = resolveV7KasAbi(contractVersion ?? CONTRACT_VERSION_V7_KAS);
  const template = normalizeTemplateV7Kas(templateInput);
  const state = normalizeStateV4(initialStateInput);
  if (state.policyNonce !== 0n) fail("a v0.7-kas genesis state must carry policyNonce 0");
  if (state.paused !== 0n) fail("a v0.7-kas genesis state must start unpaused");
  if (rootTemplate !== undefined) {
    assertRootPinsMatchV7Kas({ config, vaultTemplate: template, rootTemplate, rootOwnerSet });
  }
  if (!Array.isArray(funding) || funding.length === 0) fail("funding must be a non-empty array of ordinary UTXOs ({ outpoint, amount, scriptPublicKeyHex })");
  const fundingInputs = funding.map((f, i) => {
    const spk = String(f.scriptPublicKeyHex ?? "").toLowerCase();
    if (!/^[0-9a-f]+$/.test(spk) || spk.length % 2 !== 0) fail(`funding[${i}].scriptPublicKeyHex must be hex`);
    return { outpoint: normalizeOutpoint(f.outpoint, `funding[${i}].outpoint`), amount: parsePositiveSompi(f.amount, `funding[${i}].amount`), scriptPublicKeyHex: spk };
  });
  const change = normalizeHex(changeXOnly, 32, "changeXOnly");
  const compiled = compileExactStateV7Kas({ config, template, state, contractVersion: abi.version });
  const { loadKaspa } = require("./chain");
  const kaspa = loadKaspa(config);
  const value = state.protectedValue + state.feeReserve;
  const spkHex = p2shOf(config, compiled.scriptBytes);
  const outputs = [
    { value, scriptPublicKey: { version: 0, scriptHex: spkHex }, covenant: null },
    { value: 1n, scriptPublicKey: { version: 0, scriptHex: p2pkScriptHex(change) }, covenant: null }
  ];
  const unbound = new kaspa.TransactionOutput(value, kaspa.payToScriptHashScript(compiled.scriptBytes.toString("hex")));
  const genesisCovenantId = kaspa
    .covenantId({ transactionId: fundingInputs[0].outpoint.transactionId, index: fundingInputs[0].outpoint.index }, [{ index: 0, output: unbound }])
    .toString()
    .toLowerCase();
  outputs[0] = { ...outputs[0], covenant: { authorizingInput: 0, covenantId: genesisCovenantId } };
  const inputs = fundingInputs.map((f) => ({ previousOutpoint: f.outpoint, sequence: 0n, computeBudget: V7_KAS_BUDGET.ORDINARY_INPUT, utxo: { amount: f.amount, scriptPublicKey: { version: 0, scriptHex: f.scriptPublicKeyHex }, covenantId: null, blockDaaScore: 0n } }));
  const draft = { version: 1, inputs, outputs, lockTime: 0n, subnetworkId: "00".repeat(20), gas: 0n, payload: "" };
  const requiredFee = exactFee(draft, inputs.map(() => ORDINARY_SIGSCRIPT_LEN));
  const totalFunding = fundingInputs.reduce((s, f) => s + f.amount, 0n);
  const changeValue = totalFunding - value - requiredFee;
  if (changeValue <= 0n) fail(`funding ${totalFunding} cannot cover protectedValue+feeReserve ${value} + fee ${requiredFee}`, "INSUFFICIENT_FUEL");
  outputs[1] = { ...outputs[1], value: changeValue };
  const frozen = normalizeFrozenTxV3({ ...draft, outputs });
  assertStorageMassWithinLimit(frozen, "policyvault-0.7-kas builder");
  const described = describeFrozenTx(frozen);
  return deepFreeze({
    kind: "genesis",
    contractVersion: abi.version,
    networkId: config.networkId,
    action: "createRootedKasVault",
    template: templateToJsonV7Kas(template),
    initialState: stateToJsonV4(state),
    stateId: compiled.stateId,
    vaultOutputIndex: 0,
    changeIndex: 1,
    covenantId: genesisCovenantId,
    orgRootCovenantId: template.orgRootCovenantId,
    scriptSha256: compiled.scriptSha256,
    vaultScriptHex: compiled.scriptHex,
    accounting: Object.freeze({ kas: Object.freeze({ protectedValue: state.protectedValue.toString(), feeReserve: state.feeReserve.toString() }) }),
    frozen,
    frozenCanonicalJson: canonicalFrozenTxJson(frozen),
    txId: described.txId,
    requiredFeeSompi: requiredFee.toString(),
    encoderBuildDir: compiled.buildDir
  });
}

/* ------------------------------------------------------------------ */
/* ROOTED KAS VAULT: one transition                                     */
/* ------------------------------------------------------------------ */

function buildV7KasTransaction({ config, contractVersion, templateInput, stateInput, action, params = {}, chain, changeXOnly }) {
  const abi = resolveV7KasAbi(contractVersion ?? CONTRACT_VERSION_V7_KAS);
  if (!OWNER_CONTROL_ACTIONS_V7_KAS.has(action) && !SPEND_ACTIONS_V7_KAS.has(action) && action !== "ownerRecover") {
    fail(`unknown v0.7-kas action ${JSON.stringify(action)} — failing closed`, "UNKNOWN_ACTION");
  }
  const template = normalizeTemplateV7Kas(templateInput);
  const state = action === "ownerRecover" && params.allowMalformedState === true ? normalizeStateV4ForRecovery(stateInput) : normalizeStateV4(stateInput);

  const predecessorOutpoint = normalizeOutpoint(chain?.predecessorOutpoint, "chain.predecessorOutpoint");
  const covenantId = normalizeHex(chain?.covenantId, 32, "chain.covenantId");
  const predecessorValue = parseSompi(chain?.predecessorValue, "chain.predecessorValue");
  if (predecessorValue !== state.protectedValue + state.feeReserve) {
    fail(`chain.predecessorValue ${predecessorValue} != state.protectedValue + state.feeReserve ${state.protectedValue + state.feeReserve} — stale or inconsistent state`, "STALE");
  }
  const change = normalizeHex(changeXOnly, 32, "changeXOnly");
  const isSpend = SPEND_ACTIONS_V7_KAS.has(action);
  const terminal = action === "ownerRecover";
  const hasFuel = chain?.fuel !== undefined && chain?.fuel !== null;
  if (!isSpend && !hasFuel) fail("owner operations pin every covenant value, so the network fee MUST come from an ordinary fuel UTXO — provide chain.fuel", "FUEL_REQUIRED");
  const fuel = hasFuel ? normalizeFuel(chain.fuel) : null;
  if (isSpend && (chain?.root !== undefined && chain?.root !== null)) {
    fail("a delegate spend never touches the organizational root — refusing to build a root input into an agent transaction", "AGENT_PATH_TAKES_NO_ROOT");
  }

  const current = compileExactStateV7Kas({ config, template, state, contractVersion: abi.version });
  const currentSpkHex = p2shOf(config, current.scriptBytes);
  const encoderPaths = { sourcePath: path.join(current.buildDir, "PolicyVault.state.sil"), constructorArgsPath: path.join(current.buildDir, "constructor-args.json") };
  const rootPrefixLen = template.rootPrefixLen;
  const rootSuffixLen = template.rootSuffixLen;

  /* ---------------- DELEGATE SPEND (no root input at all) ---------------- */
  if (isSpend) {
    const { policy, proof } = resolveAgentProofV7Kas(state, params);
    const { recipient, proof: rProof } = resolveRecipientProofV7Kas(
      typeof policy === "object" && policy.agentRecipientRoot ? normalizeHex(policy.agentRecipientRoot, 32, "agentPolicy.agentRecipientRoot") : fail("agent policy is missing agentRecipientRoot"),
      params
    );
    const periods = parseSompi(params.periodsElapsed ?? 0n, "periodsElapsed");
    if (!hasFuel && params.reserveConsumedSompi !== undefined) {
      fail("without chain.fuel the reserve consumption IS the exact network fee and is derived by the builder — do not supply reserveConsumedSompi");
    }
    const requestedConsumed = hasFuel ? parseSompi(params.reserveConsumedSompi ?? 0n, "reserveConsumedSompi") : null;
    const agentTreeDepth = String(proof.siblingsHex ?? "").length / 64;
    const recipientDepth = String(rProof.siblingsHex ?? "").length / 64;

    const shapeFor = (consumed) => {
      const spend = agentSpendSuccessorV7Kas(state, {
        agentPolicy: policy,
        agentProof: { siblingsHex: proof.siblingsHex, pathBits: proof.pathBits },
        payAmount: params.payAmountSompi,
        periodsElapsed: periods,
        reserveConsumed: consumed
      });
      const next = compileExactStateV7Kas({ config, template, state: spend.successor, contractVersion: abi.version });
      const nextSpkHex = p2shOf(config, next.scriptBytes);
      const spendCallExtra = {
        payAmount: spend.payAmount.toString(),
        agentPk: spend.previousPolicy.agentPk,
        maxPerSpend: spend.previousPolicy.maxPerSpend.toString(),
        periodBudget: spend.previousPolicy.periodBudget.toString(),
        periodLengthDaa: spend.previousPolicy.periodLengthDaa.toString(),
        periodStartDaa: spend.previousPolicy.periodStartDaa.toString(),
        periodSpent: spend.previousPolicy.periodSpent.toString(),
        approvalThreshold: spend.previousPolicy.approvalThreshold.toString(),
        agentMaxFeePerTx: spend.previousPolicy.agentMaxFeePerTx.toString(),
        agentRecipientRoot: spend.previousPolicy.agentRecipientRoot,
        policySiblings: proof.siblingsHex,
        policyPathBits: BigInt(proof.pathBits).toString(),
        periodsElapsed: periods.toString(),
        recipientPk: recipient,
        recipientSiblings: rProof.siblingsHex,
        recipientPathBits: BigInt(rProof.pathBits).toString()
      };
      const budget = selectComputeBudgetV7Kas({
        operation: "agentSpend",
        rootPrefixLen,
        rootSuffixLen,
        agentTreeDepth,
        recipientDepth,
        approvalsChecked: spend.aboveThreshold ? MAX_APPROVERS : 0,
        rollover: periods >= 1n
      });
      const placeholderCall = { function: "agentSpend", signature: PLACEHOLDER_SIG_HEX, successor: successorCallJsonV7Kas(stateToJsonV4(spend.successor)), approvals: placeholderApprovalsBlob(), ...spendCallExtra };
      const callHex = runEncoderV4({ ...encoderPaths, call: placeholderCall, contractVersion: abi.version });
      const covenantSigscriptLen = covenantSigscript(callHex, current.scriptBytes).length / 2;
      const inputs = [{ previousOutpoint: predecessorOutpoint, sequence: 0n, computeBudget: budget, utxo: { amount: predecessorValue, scriptPublicKey: { version: 0, scriptHex: currentSpkHex }, covenantId, blockDaaScore: 0n } }];
      const sigLens = [covenantSigscriptLen];
      if (fuel) {
        inputs.push({ previousOutpoint: fuel.outpoint, sequence: 0n, computeBudget: V7_BUDGET.ORDINARY_INPUT, utxo: { amount: fuel.amount, scriptPublicKey: { version: 0, scriptHex: fuel.scriptPublicKeyHex }, covenantId: null, blockDaaScore: 0n } });
        sigLens.push(ORDINARY_SIGSCRIPT_LEN);
      }
      const outputs = [
        { value: spend.payAmount, scriptPublicKey: { version: 0, scriptHex: p2pkScriptHex(recipient) }, covenant: null },
        { value: spend.successor.protectedValue + spend.successor.feeReserve, scriptPublicKey: { version: 0, scriptHex: nextSpkHex }, covenant: { authorizingInput: 0, covenantId } }
      ];
      if (fuel) outputs.push({ value: 1n, scriptPublicKey: { version: 0, scriptHex: p2pkScriptHex(change) }, covenant: null });
      const draft = { version: 1, inputs, outputs, lockTime: spend.lockTime, subnetworkId: "00".repeat(20), gas: 0n, payload: "" };
      const fee = exactFee(draft, sigLens);
      return { spend, next, draft, fee, budget, callHex, covenantSigscriptLen, spendCallExtra, recipient, rProof };
    };

    let shape;
    if (fuel) {
      shape = shapeFor(requestedConsumed);
      if (requestedConsumed > shape.fee) fail(`reserveConsumed ${requestedConsumed} exceeds the exact network fee ${shape.fee} — the covenant requires reserveConsumed <= fee`, "RESERVE_OVER_FEE");
      const changeValue = fuel.amount - (shape.fee - requestedConsumed);
      if (changeValue <= 0n) fail(`fuel ${fuel.amount} cannot cover fee ${shape.fee} minus reserveConsumed ${requestedConsumed}`, "INSUFFICIENT_FUEL");
      shape.draft.outputs[2] = { ...shape.draft.outputs[2], value: changeValue };
    } else {
      let consumed = 0n;
      let iterations = 0;
      for (;;) {
        shape = shapeFor(consumed);
        if (shape.fee === consumed) break;
        consumed = shape.fee;
        iterations += 1;
        if (iterations > 4) fail("reserve-funded fee fixed point did not converge — failing closed", "FEE_FIXPOINT");
      }
      if (shape.spend.reserveConsumed !== shape.fee) fail("internal: reserve-funded spend did not consume exactly the network fee");
    }

    return finishBuildV7Kas({
      config,
      abi,
      action,
      role: "agent",
      encoderFunction: "agentSpend",
      template,
      state,
      covenantId,
      predecessorOutpoint,
      current,
      plan: { successor: shape.spend.successor, next: shape.next, terminal: false, budget: shape.budget, covenantSigscriptLen: shape.covenantSigscriptLen, plannedCallHexLength: shape.callHex.length, externalFunding: 0n },
      draft: shape.draft,
      fee: shape.fee,
      callExtra: shape.spendCallExtra,
      rootSide: null,
      fuel,
      spend: { ...shape.spend, recipient: shape.recipient, recipientProof: shape.rProof }
    });
  }

  /* ---------------- OWNER OPERATIONS (root input required) ---------------- */
  const rootSide = resolveRootSideV7Kas({ config, action, root: chain?.root });
  const rootInput = (idx) => ({ previousOutpoint: rootSide.outpoint, sequence: 0n, computeBudget: rootSide.budget, utxo: { amount: rootSide.value, scriptPublicKey: { version: 0, scriptHex: p2shOf(config, rootSide.current.scriptBytes) }, covenantId: rootSide.covenantId, blockDaaScore: 0n }, __rootIndex: idx });
  const rootOutput = (authorizingInput) => ({ value: rootSide.value, scriptPublicKey: { version: 0, scriptHex: p2shOf(config, rootSide.next.scriptBytes) }, covenant: { authorizingInput, covenantId: rootSide.covenantId } });

  if (!terminal) {
    /* rc26 round-7 review R7-02 (parity): the setAgentRoot root is DERIVED from the full new (v4-layout) policy set. */
    let agentSet = null;
    if (action === "ownerSetAgentRoot") {
      if (!Array.isArray(params.agents)) fail("ownerSetAgentRoot requires params.agents — the FULL new delegate policy set (never a bare root)", "AGENT_SET_REQUIRED");
      /* Codex checkpoint 11 (R7-02, recipients) — parity: recipients travel with every policy; the root is derived. */
      const entries = params.agents.map((a, i) => {
        if (!a || typeof a !== "object") fail(`agents[${i}] must be an object`, "AGENT_SET_INVALID");
        const { recipients, ...policy } = a;
        if (!Array.isArray(recipients) || recipients.length === 0) fail(`agents[${i}].recipients must be a non-empty array of x-only recipient keys — a policy without visible recipients cannot be reviewed`, "AGENT_RECIPIENTS_REQUIRED");
        const recipientKeys = recipients.map((r, j) => normalizeHex(r, 32, `agents[${i}].recipients[${j}]`));
        const recipientRoot = buildRecipientTree(recipientKeys).root;
        if (policy.agentRecipientRoot !== undefined && normalizeHex(policy.agentRecipientRoot, 32, `agents[${i}].agentRecipientRoot`) !== recipientRoot) fail(`agents[${i}].agentRecipientRoot does not match its recipient set`, "AGENT_RECIPIENTS_MISMATCH");
        return { policy: { ...policy, agentRecipientRoot: recipientRoot }, recipients: recipientKeys };
      });
      const tree = buildAgentTreeV4(entries.map((e) => e.policy));
      if (params.newAgentRoot !== undefined && normalizeHex(params.newAgentRoot, 32, "params.newAgentRoot") !== tree.root) fail(`params.newAgentRoot is not the Merkle root of params.agents (${tree.root})`, "AGENT_ROOT_MISMATCH");
      params = { ...params, agents: entries.map((e) => e.policy), newAgentRoot: tree.root };
      const recipientsByAgent = new Map(entries.map((e) => [normalizeHex(e.policy.agentPk, 32, "agentPk"), e.recipients]));
      agentSet = tree.agents.map((a) => ({ ...Object.fromEntries(Object.entries(a).map(([k, v]) => [k, typeof v === "bigint" ? v.toString() : v])), recipients: [...recipientsByAgent.get(a.agentPk)] }));
    }
    const owner = planOwnerOpV7Kas(state, action, params);
    const budget = selectComputeBudgetV7Kas({ operation: action, rootPrefixLen, rootSuffixLen });
    const next = compileExactStateV7Kas({ config, template, state: owner.successor, contractVersion: abi.version });
    const placeholderCall = { function: "ownerControl", opSelector: owner.opSelector, successor: successorCallJsonV7Kas(stateToJsonV4(owner.successor)) };
    const callHex = runEncoderV4({ ...encoderPaths, call: placeholderCall, contractVersion: abi.version });
    const covenantSigscriptLen = covenantSigscript(callHex, current.scriptBytes).length / 2;
    const rootCallHex = runEncoderV4({
      sourcePath: path.join(rootSide.current.buildDir, "PolicyVault.state.sil"),
      constructorArgsPath: path.join(rootSide.current.buildDir, "constructor-args.json"),
      call: { function: "rootAction", successor: rootSuccessorCallJsonV7(rootSide.plan.successor), action: rootSide.plan.action, ownerSigs: placeholderOwnerSigsBlobV7() },
      contractVersion: CONTRACT_VERSION_V7_ROOT
    });
    const rootSigscriptLen = covenantSigscript(rootCallHex, rootSide.current.scriptBytes).length / 2;
    const vaultIn = { previousOutpoint: predecessorOutpoint, sequence: 0n, computeBudget: budget, utxo: { amount: predecessorValue, scriptPublicKey: { version: 0, scriptHex: currentSpkHex }, covenantId, blockDaaScore: 0n } };
    const inputs = [vaultIn, rootInput(1), { previousOutpoint: fuel.outpoint, sequence: 0n, computeBudget: V7_BUDGET.ORDINARY_INPUT, utxo: { amount: fuel.amount, scriptPublicKey: { version: 0, scriptHex: fuel.scriptPublicKeyHex }, covenantId: null, blockDaaScore: 0n } }];
    const outputs = [
      { value: owner.successor.protectedValue + owner.successor.feeReserve, scriptPublicKey: { version: 0, scriptHex: p2shOf(config, next.scriptBytes) }, covenant: { authorizingInput: 0, covenantId } },
      rootOutput(1),
      { value: 1n, scriptPublicKey: { version: 0, scriptHex: p2pkScriptHex(change) }, covenant: null }
    ];
    const draft = { version: 1, inputs, outputs, lockTime: 0n, subnetworkId: "00".repeat(20), gas: 0n, payload: "" };
    const fee = exactFee(draft, [covenantSigscriptLen, rootSigscriptLen, ORDINARY_SIGSCRIPT_LEN]);
    const changeValue = fuel.amount - fee - owner.externalFunding;
    if (changeValue <= 0n) fail(`fuel ${fuel.amount} cannot cover fee ${fee} + external funding ${owner.externalFunding}`, "INSUFFICIENT_FUEL");
    outputs[2] = { ...outputs[2], value: changeValue };
    return finishBuildV7Kas({
      config,
      abi,
      action,
      role: "owners",
      encoderFunction: "ownerControl",
      template,
      state,
      covenantId,
      predecessorOutpoint,
      current,
      plan: { successor: owner.successor, next, terminal: false, budget, covenantSigscriptLen, plannedCallHexLength: callHex.length, externalFunding: owner.externalFunding },
      draft: { ...draft, outputs },
      fee,
      callExtra: { opSelector: owner.opSelector },
      agentSet,
      rootSide: { ...rootSide, plannedCallHexLength: rootCallHex.length, sigscriptLen: rootSigscriptLen, inputIndex: 1 },
      fuel,
      spend: null
    });
  }

  /* ---------------- ownerRecover (TERMINAL) ---------------- */
  const recover = recoverPlanV7Kas(state, template);
  const recoverBudget = selectComputeBudgetV7Kas({ operation: "ownerRecover", rootPrefixLen, rootSuffixLen });
  const placeholderCall = { function: "ownerRecover" };
  const callHex = runEncoderV4({ ...encoderPaths, call: placeholderCall, contractVersion: abi.version });
  const covenantSigscriptLen = covenantSigscript(callHex, current.scriptBytes).length / 2;
  const rootCallHex = runEncoderV4({
    sourcePath: path.join(rootSide.current.buildDir, "PolicyVault.state.sil"),
    constructorArgsPath: path.join(rootSide.current.buildDir, "constructor-args.json"),
    call: { function: "rootAction", successor: rootSuccessorCallJsonV7(rootSide.plan.successor), action: rootSide.plan.action, ownerSigs: placeholderOwnerSigsBlobV7() },
    contractVersion: CONTRACT_VERSION_V7_ROOT
  });
  const rootSigscriptLen = covenantSigscript(rootCallHex, rootSide.current.scriptBytes).length / 2;
  const vaultIn = { previousOutpoint: predecessorOutpoint, sequence: 0n, computeBudget: recoverBudget, utxo: { amount: predecessorValue, scriptPublicKey: { version: 0, scriptHex: currentSpkHex }, covenantId, blockDaaScore: 0n } };
  const inputs = [vaultIn, rootInput(1), { previousOutpoint: fuel.outpoint, sequence: 0n, computeBudget: V7_BUDGET.ORDINARY_INPUT, utxo: { amount: fuel.amount, scriptPublicKey: { version: 0, scriptHex: fuel.scriptPublicKeyHex }, covenantId: null, blockDaaScore: 0n } }];
  const outputs = [{ value: recover.payoutValue, scriptPublicKey: { version: 0, scriptHex: p2pkScriptHex(recover.payoutXOnly) }, covenant: null }, rootOutput(1), { value: 1n, scriptPublicKey: { version: 0, scriptHex: p2pkScriptHex(change) }, covenant: null }];
  const draft = { version: 1, inputs, outputs, lockTime: 0n, subnetworkId: "00".repeat(20), gas: 0n, payload: "" };
  const fee = exactFee(draft, [covenantSigscriptLen, rootSigscriptLen, ORDINARY_SIGSCRIPT_LEN]);
  const changeValue = fuel.amount - fee;
  if (changeValue <= 0n) fail(`fuel ${fuel.amount} cannot cover fee ${fee}`, "INSUFFICIENT_FUEL");
  outputs[2] = { ...outputs[2], value: changeValue };
  return finishBuildV7Kas({
    config,
    abi,
    action,
    role: "owners",
    encoderFunction: "ownerRecover",
    template,
    state,
    covenantId,
    predecessorOutpoint,
    current,
    plan: { successor: null, next: null, terminal: true, budget: recoverBudget, covenantSigscriptLen, plannedCallHexLength: callHex.length, externalFunding: 0n, recover },
    draft: { ...draft, outputs },
    fee,
    callExtra: {},
    rootSide: { ...rootSide, plannedCallHexLength: rootCallHex.length, sigscriptLen: rootSigscriptLen, inputIndex: 1 },
    fuel,
    spend: null
  });
}

/* Shared freeze + describe + invariant checks for every rooted-KAS build. */
function finishBuildV7Kas({ config, abi, action, role, encoderFunction, template, state, covenantId, predecessorOutpoint, current, plan, draft, fee, callExtra, agentSet = null, rootSide, fuel, spend }) {
  if (draft.inputs.length > MAX_TX_FEE_IO || draft.outputs.length > MAX_TX_FEE_IO) fail(`transaction shape exceeds the covenant fee-introspection bound of ${MAX_TX_FEE_IO} inputs/outputs`);
  const cleanInputs = draft.inputs.map((i) => {
    const { __rootIndex, ...rest } = i;
    void __rootIndex;
    return rest;
  });
  const frozen = normalizeFrozenTxV3({ ...draft, inputs: cleanInputs });
  assertStorageMassWithinLimit(frozen, "policyvault-0.7-kas builder");
  const described = describeFrozenTx(frozen);
  const totalIn = frozen.inputs.reduce((s, i) => s + i.utxo.amount, 0n);
  const totalOut = frozen.outputs.reduce((s, o) => s + o.value, 0n);
  if (totalIn - totalOut !== fee) fail("internal: realized fee != required fee");
  if (!plan.terminal) {
    const succ = frozen.outputs.filter((o) => o.covenant !== null && o.covenant.covenantId === covenantId);
    if (succ.length !== 1 || succ[0].value !== plan.successor.protectedValue + plan.successor.feeReserve) fail("internal: successor output does not carry exactly protectedValue + feeReserve");
  }
  if (rootSide) {
    const rootOuts = frozen.outputs.filter((o) => o.covenant !== null && o.covenant.covenantId === rootSide.covenantId);
    if (rootOuts.length !== 1) fail("internal: exactly one root continuation output is required");
    const rootIns = frozen.inputs.filter((i) => i.utxo.covenantId === rootSide.covenantId);
    if (rootIns.length !== 1) fail("internal: exactly one root input is required");
  }

  return deepFreeze({
    /* rc26 round-7 review R7-02 (parity): the full new delegate policy set an ownerSetAgentRoot installs (null otherwise). */
    agentSet: agentSet ? agentSet.map((policy) => ({ ...policy })) : null,
    kind: "transition",
    contractVersion: abi.version,
    encoderFunction,
    networkId: config.networkId,
    action,
    role,
    template: templateToJsonV7Kas(template),
    predecessorOutpoint,
    predecessorStateId: current.stateId,
    covenantId,
    stateJson: stateToJsonV4(state),
    successorState: plan.terminal ? null : stateToJsonV4(plan.successor),
    successorStateId: plan.terminal ? null : compileExactStateV7Kas({ config, template, state: plan.successor, contractVersion: abi.version }).stateId,
    successorScriptSha256: plan.terminal ? null : plan.next.scriptSha256,
    rootAuthority: rootSide
      ? Object.freeze({
          covenantId: rootSide.covenantId,
          outpoint: rootSide.outpoint,
          inputIndex: rootSide.inputIndex,
          rootActionName: rootSide.authority.rootActionName,
          rootAction: rootSide.plan.action,
          authorityClass: rootSide.plan.class,
          quorumSource: rootSide.plan.quorumSource,
          requiredApprovals: rootSide.plan.requiredApprovals.toString(),
          expectedSignerSlots: rootSide.plan.expectedSignerSlots,
          expectFrozenAfter: rootSide.authority.expectFrozenAfter.toString(),
          prevStateDigest: rootSide.plan.prevStateDigest,
          newStateDigest: rootSide.plan.newStateDigest,
          successorTailHex: rootSide.plan.tailHex,
          prevState: rootStateToJsonV7(rootSide.state),
          newState: rootStateToJsonV7(rootSide.plan.successor),
          template: rootTemplateToJsonV7(rootSide.template),
          value: rootSide.value.toString(),
          computeBudget: rootSide.budget,
          plannedCallHexLength: rootSide.plannedCallHexLength,
          buildDir: rootSide.current.buildDir
        })
      : null,
    accounting: Object.freeze({
      kas: Object.freeze({
        predecessorProtected: state.protectedValue.toString(),
        predecessorFeeReserve: state.feeReserve.toString(),
        payAmount: spend ? spend.payAmount.toString() : "0",
        reserveConsumed: spend ? spend.reserveConsumed.toString() : "0",
        externalIn: fuel ? fuel.amount.toString() : "0",
        externalOut: fuel ? draft.outputs[draft.outputs.length - 1].value.toString() : "0",
        externalFunding: plan.externalFunding.toString(),
        fee: fee.toString(),
        successorProtected: plan.terminal ? "0" : plan.successor.protectedValue.toString(),
        successorFeeReserve: plan.terminal ? "0" : plan.successor.feeReserve.toString(),
        successorTotal: plan.terminal ? "0" : (plan.successor.protectedValue + plan.successor.feeReserve).toString(),
        terminalPayout: plan.terminal ? plan.recover.payoutValue.toString() : "0"
      })
    }),
    frozen,
    frozenCanonicalJson: canonicalFrozenTxJson(frozen),
    txId: described.txId,
    covenantSighash: described.sighashAll[0],
    rootSighash: rootSide ? described.sighashAll[rootSide.inputIndex] : null,
    computeBudget: plan.budget,
    requiredFeeSompi: fee.toString(),
    encoderBuildDir: current.buildDir,
    plannedCallHexLength: plan.plannedCallHexLength,
    callExtra,
    hasFuelInput: fuel !== null,
    hasRootInput: rootSide !== null,
    aboveThreshold: spend ? spend.aboveThreshold : false,
    agentProof: spend ? Object.freeze({ root: state.agentRoot, siblingsHex: spend.agentProof.siblingsHex, pathBits: BigInt(spend.agentProof.pathBits).toString() }) : null,
    recipientProof: spend ? Object.freeze({ root: spend.recipientProof.root, siblingsHex: spend.recipientProof.siblingsHex, pathBits: BigInt(spend.recipientProof.pathBits).toString() }) : null,
    payment: spend ? { recipient: spend.recipient, value: spend.payAmount.toString() } : null
  });
}

function extractSchnorr65(signatureHex, label) {
  if (typeof signatureHex !== "string" || !/^[0-9a-f]+$/.test(signatureHex)) fail(`${label} must be lowercase hex`, "SIGNATURE_INVALID");
  let sig = signatureHex;
  if (sig.length === 132 && sig.startsWith("41")) sig = sig.slice(2);
  if (sig.length !== 130) fail(`${label} has unexpected length ${sig.length / 2} bytes (need 65)`, "SIGNATURE_INVALID");
  if (!sig.endsWith("01")) fail(`${label} sighash byte 0x${sig.slice(-2)} != 0x01 — PolicyVault signs SIG_HASH_ALL only`, "SIGHASH_NOT_ALL");
  return sig;
}

/*
 * Create the canonical v0.4.1 approval package for a frozen above-threshold
 * agentSpend build. Reuses createApprovalPackageV4 UNCHANGED — this is the
 * SAME vault-level M-of-N mechanism the frozen v0.4.1 covenant has always
 * had, not re-derived for v0.7-kas.
 */
function createApprovalPackageForBuildV7Kas(build) {
  if (build.kind !== "transition" || build.action !== "agentSpend") fail("approval packages exist only for agentSpend builds");
  if (build.aboveThreshold !== true) fail("this spend is at/below the agent's approvalThreshold — agent authorization is sufficient; do not manufacture approvals");
  return createApprovalPackageV4({
    networkId: build.networkId,
    vaultId: build.template.vaultId,
    predecessorOutpoint: build.predecessorOutpoint,
    predecessorStateId: build.predecessorStateId,
    successorStateId: build.successorStateId,
    policyNonce: build.stateJson.policyNonce,
    predecessorProtectedSompi: build.accounting.kas.predecessorProtected,
    predecessorFeeReserveSompi: build.accounting.kas.predecessorFeeReserve,
    frozenTransaction: build.frozen,
    covenantInputIndex: 0,
    agentPolicy: {
      agentPk: build.callExtra.agentPk,
      maxPerSpend: build.callExtra.maxPerSpend,
      periodBudget: build.callExtra.periodBudget,
      periodLengthDaa: build.callExtra.periodLengthDaa,
      periodStartDaa: build.callExtra.periodStartDaa,
      periodSpent: build.callExtra.periodSpent,
      approvalThreshold: build.callExtra.approvalThreshold,
      agentMaxFeePerTx: build.callExtra.agentMaxFeePerTx,
      agentRecipientRoot: build.callExtra.agentRecipientRoot
    },
    agentProof: build.agentProof,
    successorAgentRoot: build.successorState.agentRoot,
    periodsElapsed: build.callExtra.periodsElapsed,
    recipient: build.payment.recipient,
    payAmountSompi: build.payment.value,
    recipientProof: build.recipientProof,
    reserveConsumedSompi: build.accounting.kas.reserveConsumed,
    approvalM: build.stateJson.approvalM,
    approverSlots: build.stateJson.approverSlots,
    requiredFeeSompi: build.requiredFeeSompi
  });
}

/*
 * FINALIZE a rooted-KAS-vault transition (NO broadcasting).
 *   agentSignatureHex   the delegate's 65-byte SIG_HASH_ALL signature (spend only)
 *   approvalPackage     the vault-level M-of-N approval package (above-threshold spend only)
 *   approvals           the organizational root's M-of-N owner approvals (owner ops only)
 *   fuelSignatureScriptHex  the ordinary fuel input's signature script
 *
 * The vault input itself carries NO signature for owner ops/recover: its
 * authority is the root input. The M-of-N owner-signature blob assembly
 * reuses assembleOwnerSigsBlobV7 from core/model/owner-set-v7.js — the SAME
 * primitive vault-builders-v7.js calls, never re-implemented.
 */
function finalizeV7KasTransaction({ build, agentSignatureHex, approvalPackage, approvals, fuelSignatureScriptHex }) {
  if (build.kind !== "transition" || build.contractVersion !== CONTRACT_VERSION_V7_KAS) fail("finalizeV7KasTransaction takes a v0.7-kas transition build");
  const isSpend = build.action === "agentSpend";
  const call = { function: build.encoderFunction, ...build.callExtra };
  if (isSpend) {
    call.signature = extractSchnorr65(agentSignatureHex, "agent signature");
    call.successor = successorCallJsonV7Kas(build.successorState);
    if (build.aboveThreshold) {
      if (!approvalPackage) fail("above-threshold agent spend requires a complete approval package", "INSUFFICIENT_APPROVALS");
      if (approvalPackage.txId !== build.txId) fail("approval package txId does not match this build — packages are bound to one exact frozen transaction", "PACKAGE_MISMATCH");
      call.approvals = approvalsBlobV4(approvalPackage);
    } else {
      if (approvalPackage) fail("at/below-threshold agent spends carry the canonical placeholder blob, not an approval package");
      call.approvals = placeholderApprovalsBlob();
    }
    if (approvals !== undefined && approvals !== null) fail("a delegate spend carries no organizational-root approvals — the agent path never touches the root", "AGENT_PATH_TAKES_NO_ROOT_APPROVALS");
  } else {
    if (agentSignatureHex !== undefined) fail("a v0.7-kas owner path carries NO signature — the root input is the authority", "OWNER_PATH_TAKES_NO_SIGNATURE");
    if (approvalPackage !== undefined && approvalPackage !== null) fail("a v0.7-kas owner path carries no vault-level approval package — only the organizational root's approvals apply", "UNEXPECTED_APPROVAL_PACKAGE");
    if (build.encoderFunction === "ownerControl") call.successor = successorCallJsonV7Kas(build.successorState);
  }
  const callHex = runEncoderV4({ sourcePath: path.join(build.encoderBuildDir, "PolicyVault.state.sil"), constructorArgsPath: path.join(build.encoderBuildDir, "constructor-args.json"), call, contractVersion: build.contractVersion });
  if (callHex.length !== build.plannedCallHexLength) fail(`final covenant call length ${callHex.length / 2} != planned ${build.plannedCallHexLength / 2} — the exact-fee freeze is violated; refusing`, "FEE_DRIFT");
  const artifact = JSON.parse(fs.readFileSync(path.join(build.encoderBuildDir, "artifact.json")));
  const json = JSON.parse(build.frozenCanonicalJson);
  json.inputs[0].signatureScript = covenantSigscript(callHex, Buffer.from(artifact.script));

  let blob = null;
  if (build.hasRootInput) {
    const ra = build.rootAuthority;
    const slots = ra.expectedSignerSlots.map((s) => s.publicKey);
    while (slots.length < OWNER_SLOTS_V7) slots.push("00".repeat(32));
    blob = assembleOwnerSigsBlobV7({
      ownerSet: { owners: slots, ownerM: ra.prevState.ownerM, emergencyK: ra.prevState.emergencyK, recoveryM: ra.prevState.recoveryM },
      actionName: ra.rootActionName,
      approvals: approvals ?? []
    });
    if (blob.blobHex.length !== SIG_BLOB_LEN_V7 * 2) fail("internal: the assembled owner blob is not 780 bytes");
    const rootCallHex = runEncoderV4({
      sourcePath: path.join(ra.buildDir, "PolicyVault.state.sil"),
      constructorArgsPath: path.join(ra.buildDir, "constructor-args.json"),
      call: { function: "rootAction", successor: rootSuccessorCallJsonV7(ra.newState), action: ra.rootAction, ownerSigs: blob.blobHex },
      contractVersion: CONTRACT_VERSION_V7_ROOT
    });
    if (rootCallHex.length !== ra.plannedCallHexLength) fail(`final root call length ${rootCallHex.length / 2} != planned ${ra.plannedCallHexLength / 2} — the exact-fee freeze is violated; refusing`, "FEE_DRIFT");
    const rootArtifact = JSON.parse(fs.readFileSync(path.join(ra.buildDir, "artifact.json")));
    json.inputs[ra.inputIndex].signatureScript = covenantSigscript(rootCallHex, Buffer.from(rootArtifact.script));
  } else if (approvals !== undefined && approvals !== null) {
    fail("this build has no root input — do not supply organizational-root owner approvals", "NO_ROOT_INPUT");
  }

  if (build.hasFuelInput) {
    if (typeof fuelSignatureScriptHex !== "string" || !/^[0-9a-f]+$/.test(fuelSignatureScriptHex) || fuelSignatureScriptHex.length / 2 !== ORDINARY_SIGSCRIPT_LEN) {
      fail(`fuel signature script must be exactly ${ORDINARY_SIGSCRIPT_LEN} bytes`);
    }
    json.inputs[json.inputs.length - 1].signatureScript = fuelSignatureScriptHex;
  } else if (fuelSignatureScriptHex !== undefined) {
    fail("this build has no fuel input — do not supply a fuel signature");
  }
  return Object.freeze({
    txId: build.txId,
    requiredFeeSompi: build.requiredFeeSompi,
    finalTransaction: json,
    covenantCallHex: callHex,
    ownerSigsBlobHex: blob ? blob.blobHex : null,
    signedSlots: blob ? blob.signedSlots : Object.freeze([]),
    requiredApprovals: blob ? blob.requiredApprovals.toString() : null,
    satisfiedApprovals: blob ? blob.satisfiedApprovals.toString() : null
  });
}

module.exports = {
  buildCreateV7KasVault,
  buildV7KasTransaction,
  finalizeV7KasTransaction,
  createApprovalPackageForBuildV7Kas,
  successorCallJsonV7Kas,
  OWNER_CONTROL_ACTIONS_V7_KAS,
  SPEND_ACTIONS_V7_KAS,
  /* re-exported, never re-implemented: root-only genesis/rotation and the
   * M-of-N root finalizer are IDENTICAL regardless of vault profile */
  buildCreateV7Root,
  buildV7RootTransaction,
  finalizeV7RootTransaction,
  ROOT_ACTIONS_V7_NAMES,
  resolveRootActionV7,
  assertRootPinsMatchV7Kas
};
