"use strict";

/*
 * PolicyVault v0.5 TOKEN CONTROLLER transaction builders (SDK layer).
 * Builds (and FREEZES) every PolicyVault.v0.5.sil transition offline,
 * entirely from consensus-visible bytes + the accepted asset descriptor,
 * then finalizes it with externally-produced signatures. Same discipline
 * as the v0.4 builders: builders never broadcast; the frozen form is the
 * security object; the exact fee is computed from the final byte shape;
 * the production pv_call_encoder produces every covenant-call byte; any
 * drift between planned and final bytes fails closed.
 *
 * Dependency direction (frozen design §II): raw tx/state -> canonical
 * token parser (core/assets) -> descriptor validation -> asset adapter
 * (token-program-kcc20) -> policy evaluation (core/model v5) -> this
 * builder -> manifest/explain -> local verification -> external signer ->
 * covenant enforcement.
 *
 * TWO ACCOUNTING DOMAINS, surfaced separately in `accounting`:
 *   token — spendAmount, position before/after (atomic units);
 *   kas   — fee reserve before/after, reserve consumed, fuel in/out, the
 *           token family's carry KAS, the exact fee.
 *
 * Transaction shapes:
 *   tokenAgentSpend  in: [controller, token position, fuel?]
 *                    out: [successor, token self, token recipient, change?]
 *   ownerControl     in: [controller, fuel]        out: [successor, change]
 *   ownerRecover     in: [controller, token?, fuel] out: [owner payout, token->owner?, change]
 *   create (genesis) in: [funding...]              out: [controller, change]
 *
 * Status: IMPLEMENTED (SDK). Production-byte proof: sdk/tools/gen-v5-vectors.js
 * + tests/vm/tests/v5_sdk_integration.rs execute every built shape on the
 * real engine.
 */

const fs = require("fs");
const path = require("path");

const { parseSompi, parsePositiveSompi } = require("./amounts");
const { normalizeHex, normalizeXOnlyPubkey } = require("./vault-state");
const {
  CONTRACT_VERSION_V5,
  resolveV5Abi,
  OWNER_OP_SELECTOR_V5,
  normalizeTemplateV5,
  normalizeStateV5,
  normalizeStateV5ForRecovery,
  computeStateIdV5,
  stateToJsonV5
} = require("./vault-state-v5");
const {
  tokenAgentSpendSuccessorV5,
  tokenContinuationStatesV5,
  setAgentRootSuccessorV5,
  topUpReserveSuccessorV5,
  pauseSuccessorV5,
  recoverPlanV5
} = require("./vault-transitions-v5");
const { buildTokenAgentTreeV5, generateTokenAgentProofV5, verifyTokenAgentProofV5, tokenAgentPolicyToJsonV5 } = require("./agent-merkle-v5");
const { buildRecipientTree, generateRecipientProof, verifyRecipientProof } = require("./recipient-merkle-v3");
const { compileExactStateV5 } = require("./contract-compiler-v5");
const { selectComputeBudgetV5, selectTokenInputBudgetV5, V5_BUDGET } = require("../../core/model/compute-budget-v5");
const { normalizeFrozenTxV3, describeFrozenTx, feeDescriptorFromFrozen, canonicalFrozenTxJson } = require("./frozen-tx-v3");
const { calculateRequiredFee } = require("./fee-mass");
const { covenantSigscript } = require("./spend-vault");
const { p2pkScriptHex } = require("./approval-package-v4");
const { runEncoderV4, PLACEHOLDER_SIG_HEX, MAX_TX_FEE_IO } = require("./vault-builders-v4");
const assets = require("../../core/assets");
const { verifiedTokenPosition, compileKcc20Program } = require("./token-program-kcc20");

const ORDINARY_SIGSCRIPT_LEN = 66;
const OWNER_CONTROL_ACTIONS = new Set(["ownerSetAgentRoot", "ownerTopUpReserve", "ownerPause", "ownerUnpause"]);
const SPEND_ACTIONS = new Set(["tokenAgentSpend"]);

function fail(message, code) {
  const e = new Error(`vault-builders-v5: ${message}`);
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

/*
 * The controller's token position, PROVEN before use: descriptor validated,
 * template corroborated (family bound resolved through the vendored
 * program), the claimed state's compiled redeem reproduces the live UTXO's
 * P2SH, and the position is owned by THIS controller via covenant-id/v1.
 */
function resolveTokenPosition({ config, descriptor, templateIndex, chain, covenantId, template }) {
  const tp = chain?.tokenPosition;
  if (!tp || typeof tp !== "object") fail("chain.tokenPosition { outpoint, value, scriptPublicKeyHex, covenantId, state } is required", "TOKEN_POSITION_REQUIRED");
  const familyId = normalizeHex(tp.covenantId, 32, "chain.tokenPosition.covenantId");
  if (familyId !== template.tokenCovenantId) fail("chain.tokenPosition.covenantId is not the controller's pinned tokenCovenantId — wrong asset family; failing closed", "WRONG_TOKEN_FAMILY");
  const validated = assets.validateAssetDescriptor(descriptor);
  if (validated.tokenCovenantId !== template.tokenCovenantId) fail("descriptor.tokenCovenantId != the controller's pinned tokenCovenantId — descriptor substitution; failing closed", "DESCRIPTOR_MISMATCH");
  const tpl = validated.acceptedTransferTemplates[templateIndex];
  if (!tpl || tpl.templateVmHashBlake2b256 !== template.templateVmHash || tpl.prefixLen !== template.templatePrefixLen || tpl.suffixLen !== template.templateSuffixLen) {
    fail("the selected descriptor template does not equal the controller's pinned template hash/geometry — failing closed", "TEMPLATE_PIN_MISMATCH");
  }
  const program = verifiedTokenPosition({ config, descriptor: validated, templateIndex, state: tp.state, scriptPublicKeyHex: tp.scriptPublicKeyHex });
  if (program.state.ownerIdentifier !== covenantId || program.state.identifierType !== assets.kcc20.OWNER_SCHEMES.COVENANT_ID) {
    fail("the token position is not owned by this controller's covenant id (covenant-id/v1 scheme) — failing closed", "TOKEN_NOT_OWNED");
  }
  if (program.state.isMinter) fail("the controller's token position must not be a minter position", "TOKEN_MINTER_POSITION");
  return {
    outpoint: normalizeOutpoint(tp.outpoint, "chain.tokenPosition.outpoint"),
    value: parsePositiveSompi(tp.value, "chain.tokenPosition.value"),
    scriptPublicKeyHex: String(tp.scriptPublicKeyHex).toLowerCase(),
    covenantId: familyId,
    program,
    descriptor: validated,
    descriptorHash: assets.computeDescriptorHash(validated),
    templateIndex
  };
}

function resolveAgentProof(state, params) {
  const agentPk = normalizeXOnlyPubkey(params.agentPk, "params.agentPk");
  if (params.agents !== undefined) {
    const tree = buildTokenAgentTreeV5(params.agents);
    if (tree.root !== state.agentRoot) fail("the supplied agent set does not reproduce the live agentRoot — refusing to build", "AGENT_ROOT_MISMATCH");
    const proof = generateTokenAgentProofV5(tree, agentPk);
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
    if (!verifyTokenAgentProofV5({ root: state.agentRoot, policy: params.agentPolicy, siblingsHex: proof.siblingsHex, pathBits: proof.pathBits })) {
      fail("agent proof does not verify for this policy under the live agentRoot", "AGENT_PROOF_INVALID");
    }
    return { policy: params.agentPolicy, proof };
  }
  fail("tokenAgentSpend requires either params.agents (full set) or params.agentPolicy + params.agentProof");
}

function resolveRecipientProof(agentRecipientRoot, params) {
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
    fail("tokenAgentSpend requires either params.recipients (full list) or params.recipientProof");
  }
  if (proof.root !== agentRecipientRoot) fail("recipient proof root does not match this agent's agentRecipientRoot", "RECIPIENT_ROOT_MISMATCH");
  if (!verifyRecipientProof({ root: proof.root, recipient, siblingsHex: proof.siblingsHex, pathBits: BigInt(proof.pathBits) })) {
    fail("recipient proof does not verify for this recipient", "RECIPIENT_PROOF_INVALID");
  }
  return { recipient, proof };
}

function planOwnerOp(state, action, params) {
  switch (action) {
    case "ownerSetAgentRoot": {
      let newRoot;
      if (params.newAgents !== undefined) newRoot = buildTokenAgentTreeV5(params.newAgents).root;
      else if (params.newAgentRoot !== undefined) newRoot = normalizeHex(params.newAgentRoot, 32, "params.newAgentRoot");
      else fail("ownerSetAgentRoot requires params.newAgents (canonical set) or params.newAgentRoot");
      return { ...setAgentRootSuccessorV5(state, newRoot), externalFunding: 0n };
    }
    case "ownerTopUpReserve": {
      const amount = parsePositiveSompi(params.topUpReserveAmountSompi, "topUpReserveAmountSompi");
      return { ...topUpReserveSuccessorV5(state, amount), externalFunding: amount };
    }
    case "ownerPause":
      return { ...pauseSuccessorV5(state, true), externalFunding: 0n };
    case "ownerUnpause":
      return { ...pauseSuccessorV5(state, false), externalFunding: 0n };
    default:
      fail(`unknown v0.5 owner action ${JSON.stringify(action)} — failing closed`);
  }
}

function exactFee(draft, sigScriptLengths) {
  const probe = normalizeFrozenTxV3(draft);
  return calculateRequiredFee(feeDescriptorFromFrozen(probe, sigScriptLengths)).minimumRequiredFee;
}

function successorCallJsonV5(stateJson) {
  return { feeReserve: stateJson.feeReserve, paused: Number(stateJson.paused), agentRoot: stateJson.agentRoot, policyNonce: stateJson.policyNonce };
}

function kcc20StateJson(s) {
  return { ownerIdentifier: s.ownerIdentifier, identifierType: s.identifierType, amount: s.amount.toString(), isMinter: s.isMinter };
}

/* Encode the token family's own leader call (deterministic: covenant-id owner, no signatures). */
function encodeTokenTransfer({ program, newStates, witnessesHex }) {
  return runEncoderV4({
    sourcePath: program.sourcePath,
    constructorArgsPath: program.constructorArgsPath,
    call: { function: "transfer", signature: PLACEHOLDER_SIG_HEX, newStates: newStates.map(kcc20StateJson), sigs: [], witnesses: witnessesHex },
    contractVersion: "kcc20/1"
  });
}

/*
 * Build (and FREEZE) one v0.5 covenant transition.
 *   config, contractVersion ("policyvault-0.5"), templateInput, stateInput,
 *   action, params, chain { predecessorOutpoint, covenantId, predecessorValue,
 *   fuel?, tokenPosition? }, changeXOnly, descriptor (+ templateIndex).
 */
function buildV5Transaction({ config, contractVersion, templateInput, stateInput, action, params = {}, chain, changeXOnly, descriptor, templateIndex = 0 }) {
  const abi = resolveV5Abi(contractVersion ?? CONTRACT_VERSION_V5);
  if (!OWNER_CONTROL_ACTIONS.has(action) && !SPEND_ACTIONS.has(action) && action !== "ownerRecover") fail(`unknown v0.5 action ${JSON.stringify(action)} — failing closed`);
  const template = normalizeTemplateV5(templateInput);

  let state;
  if (action === "ownerRecover" && params.allowMalformedState === true) state = normalizeStateV5ForRecovery(stateInput);
  else state = normalizeStateV5(stateInput);

  const predecessorOutpoint = normalizeOutpoint(chain?.predecessorOutpoint, "chain.predecessorOutpoint");
  const covenantId = normalizeHex(chain?.covenantId, 32, "chain.covenantId");
  const predecessorValue = parseSompi(chain?.predecessorValue, "chain.predecessorValue");
  if (predecessorValue !== state.feeReserve) fail(`chain.predecessorValue ${predecessorValue} != state.feeReserve ${state.feeReserve} — stale or inconsistent state`, "STALE");
  const change = normalizeHex(changeXOnly, 32, "changeXOnly");

  const terminal = action === "ownerRecover";
  const isSpend = SPEND_ACTIONS.has(action);
  const hasFuel = chain?.fuel !== undefined && chain?.fuel !== null;
  if (!isSpend && !hasFuel) fail("owner operations pin every covenant value, so the network fee MUST come from an ordinary fuel UTXO — provide chain.fuel", "FUEL_REQUIRED");
  const fuel = hasFuel ? normalizeFuel(chain.fuel) : null;

  /* descriptor pin: the controller's revealed descriptorHash must equal the hash of the descriptor in hand */
  if (descriptor !== undefined) {
    const dh = assets.computeDescriptorHash(descriptor);
    if (dh !== template.descriptorHash) fail("descriptor hash != the controller's pinned descriptorHash — descriptor substitution/downgrade; failing closed", "DESCRIPTOR_PIN_MISMATCH");
  }

  const current = compileExactStateV5({ config, template, state, contractVersion: abi.version });
  const { loadKaspa } = require("./chain");
  const kaspa = loadKaspa(config);
  const p2sh = (scriptBytes) => String(kaspa.payToScriptHashScript(scriptBytes.toString("hex")).script).toLowerCase();
  const currentSpkHex = p2sh(current.scriptBytes);
  const encoderPaths = { sourcePath: path.join(current.buildDir, "PolicyVault.state.sil"), constructorArgsPath: path.join(current.buildDir, "constructor-args.json") };
  const covIn = (budget) => ({ previousOutpoint: predecessorOutpoint, sequence: 0n, computeBudget: budget, utxo: { amount: predecessorValue, scriptPublicKey: { version: 0, scriptHex: currentSpkHex }, covenantId, blockDaaScore: 0n } });
  const fuelIn = () => ({ previousOutpoint: fuel.outpoint, sequence: 0n, computeBudget: V5_BUDGET.ORDINARY_INPUT, utxo: { amount: fuel.amount, scriptPublicKey: { version: 0, scriptHex: fuel.scriptPublicKeyHex }, covenantId: null, blockDaaScore: 0n } });
  const geometry = { templatePrefixLen: template.templatePrefixLen, templateSuffixLen: template.templateSuffixLen };

  let plan;
  let callExtra = {};
  let tokenSide = null;

  if (isSpend) {
    if (descriptor === undefined) fail("tokenAgentSpend requires the accepted asset descriptor", "DESCRIPTOR_REQUIRED");
    const position = resolveTokenPosition({ config, descriptor, templateIndex, chain, covenantId, template });
    const { policy, proof } = resolveAgentProof(state, params);
    const { recipient, proof: rProof } = resolveRecipientProof(normalizeHex(policy.agentRecipientRoot, 32, "agentPolicy.agentRecipientRoot"), params);
    const periods = parseSompi(params.periodsElapsed ?? 0n, "periodsElapsed");
    const recipientCarry = parseSompi(params.recipientCarryKasSompi, "recipientCarryKasSompi");
    if (recipientCarry >= position.value) fail("recipient carry KAS must leave the token position with KAS", "CARRY_TOO_LARGE");
    const selfCarry = position.value - recipientCarry;
    if (!hasFuel && params.reserveConsumedSompi !== undefined) fail("without chain.fuel the reserve consumption IS the exact network fee and is derived by the builder — do not supply reserveConsumedSompi");
    const requestedConsumed = hasFuel ? parseSompi(params.reserveConsumedSompi ?? 0n, "reserveConsumedSompi") : null;
    const budget = selectComputeBudgetV5({ operation: action, ...geometry });

    const shapeFor = (consumed) => {
      const spend = tokenAgentSpendSuccessorV5(state, {
        agentPolicy: policy,
        agentProof: { siblingsHex: proof.siblingsHex, pathBits: proof.pathBits },
        spendAmount: params.spendAmount,
        tokenPositionAmount: position.program.state.amount,
        periodsElapsed: periods,
        reserveConsumed: consumed,
        tokenInputKas: position.value,
        selfCarryKas: selfCarry,
        recipientCarryKas: recipientCarry
      });
      const states = tokenContinuationStatesV5({ controllerCovenantId: covenantId, recipientPk: recipient, plan: spend });
      const next = compileExactStateV5({ config, template, state: spend.successor, contractVersion: abi.version });
      const selfProgram = compileKcc20Program({ config, state: states.selfNew, familyBound: position.program.familyBound });
      const recipientProgram = compileKcc20Program({ config, state: states.recipientNew, familyBound: position.program.familyBound });
      const spendCallExtra = {
        selfNew: kcc20StateJson(states.selfNew),
        recipientNew: kcc20StateJson(states.recipientNew),
        agentPk: spend.previousPolicy.agentPk,
        tokenMaxPerSpend: spend.previousPolicy.tokenMaxPerSpend.toString(),
        tokenPeriodBudget: spend.previousPolicy.tokenPeriodBudget.toString(),
        periodLengthDaa: spend.previousPolicy.periodLengthDaa.toString(),
        periodStartDaa: spend.previousPolicy.periodStartDaa.toString(),
        tokenPeriodSpent: spend.previousPolicy.tokenPeriodSpent.toString(),
        agentMaxFeePerTx: spend.previousPolicy.agentMaxFeePerTx.toString(),
        agentMaxCarryKas: spend.previousPolicy.agentMaxCarryKas.toString(),
        agentRecipientRoot: spend.previousPolicy.agentRecipientRoot,
        policySiblings: proof.siblingsHex,
        policyPathBits: BigInt(proof.pathBits).toString(),
        periodsElapsed: periods.toString(),
        recipientPk: recipient,
        recipientSiblings: rProof.siblingsHex,
        recipientPathBits: BigInt(rProof.pathBits).toString()
      };
      const placeholderCall = { function: action, signature: PLACEHOLDER_SIG_HEX, successor: successorCallJsonV5(stateToJsonV5(spend.successor)), ...spendCallExtra };
      const callHex = runEncoderV4({ ...encoderPaths, call: placeholderCall, contractVersion: abi.version });
      const covenantSigscriptLen = covenantSigscript(callHex, current.scriptBytes).length / 2;
      const tokenCallHex = encodeTokenTransfer({ program: position.program, newStates: [states.selfNew, states.recipientNew], witnessesHex: "00" });
      const tokenSigscriptHex = covenantSigscript(tokenCallHex, Buffer.from(position.program.scriptHex, "hex"));
      const inputs = [
        covIn(budget),
        { previousOutpoint: position.outpoint, sequence: 0n, computeBudget: V5_BUDGET.OWNER_OP, utxo: { amount: position.value, scriptPublicKey: { version: 0, scriptHex: position.scriptPublicKeyHex }, covenantId: position.covenantId, blockDaaScore: 0n } }
      ];
      const sigLens = [covenantSigscriptLen, tokenSigscriptHex.length / 2];
      if (fuel) {
        inputs.push(fuelIn());
        sigLens.push(ORDINARY_SIGSCRIPT_LEN);
      }
      const outputs = [
        { value: spend.successor.feeReserve, scriptPublicKey: { version: 0, scriptHex: p2sh(next.scriptBytes) }, covenant: { authorizingInput: 0, covenantId } },
        { value: selfCarry, scriptPublicKey: { version: 0, scriptHex: selfProgram.p2shSpkHex }, covenant: { authorizingInput: 1, covenantId: position.covenantId } },
        { value: recipientCarry, scriptPublicKey: { version: 0, scriptHex: recipientProgram.p2shSpkHex }, covenant: { authorizingInput: 1, covenantId: position.covenantId } }
      ];
      if (fuel) outputs.push({ value: 1n, scriptPublicKey: { version: 0, scriptHex: p2pkScriptHex(change) }, covenant: null });
      const draft = { version: 1, inputs, outputs, lockTime: spend.lockTime, subnetworkId: "00".repeat(20), gas: 0n, payload: "" };
      const fee = exactFee(draft, sigLens);
      return { spend, states, next, draft, fee, budget, callHex, covenantSigscriptLen, tokenSigscriptHex, spendCallExtra, recipient, rProof, tokenBudget: V5_BUDGET.OWNER_OP };
    };

    let shape;
    if (fuel) {
      shape = shapeFor(requestedConsumed);
      if (requestedConsumed > shape.fee) fail(`reserveConsumed ${requestedConsumed} exceeds the exact network fee ${shape.fee} — the covenant requires reserveConsumed <= fee`, "RESERVE_OVER_FEE");
      const changeValue = fuel.amount - (shape.fee - requestedConsumed);
      if (changeValue <= 0n) fail(`fuel ${fuel.amount} cannot cover fee ${shape.fee} minus reserveConsumed ${requestedConsumed}`, "INSUFFICIENT_FUEL");
      shape.draft.outputs[3] = { ...shape.draft.outputs[3], value: changeValue };
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
    }
    /* the token input's compute budget: the token leader executes its own family logic (measured 18,709 units at bound 2 -> 1); commit a template-scaled tier */
    const tokenBudget = selectTokenInputBudgetV5({ templatePrefixLen: template.templatePrefixLen, templateSuffixLen: template.templateSuffixLen });
    shape.draft.inputs[1] = { ...shape.draft.inputs[1], computeBudget: tokenBudget };
    /* recompute fee after the token budget change (compute mass) */
    const sigLens2 = [shape.covenantSigscriptLen, shape.tokenSigscriptHex.length / 2].concat(fuel ? [ORDINARY_SIGSCRIPT_LEN] : []);
    const fee2 = exactFee(shape.draft, sigLens2);
    if (fee2 !== shape.fee) {
      if (fuel) {
        const rc = requestedConsumed;
        if (rc > fee2) fail("reserveConsumed exceeds the exact fee after budget sizing", "RESERVE_OVER_FEE");
        shape.draft.outputs[3] = { ...shape.draft.outputs[3], value: fuel.amount - (fee2 - rc) };
        shape.fee = fee2;
      } else {
        fail("reserve-funded fee changed after token budget sizing — failing closed", "FEE_FIXPOINT");
      }
    }
    callExtra = shape.spendCallExtra;
    tokenSide = {
      position,
      states: shape.states,
      tokenSigscriptHex: shape.tokenSigscriptHex,
      recipient: shape.recipient,
      recipientProof: shape.rProof,
      recipientCarry,
      selfCarry
    };
    plan = { kindSpend: true, spend: shape.spend, successor: shape.spend.successor, next: shape.next, draft: shape.draft, fee: shape.fee, budget: shape.budget, covenantSigscriptLen: shape.covenantSigscriptLen, plannedCallHexLength: shape.callHex.length, lockTime: shape.spend.lockTime, externalFunding: 0n };
  } else if (!terminal) {
    const owner = planOwnerOp(state, action, params);
    const next = compileExactStateV5({ config, template, state: owner.successor, contractVersion: abi.version });
    const budget = selectComputeBudgetV5({ operation: action, ...geometry });
    const placeholderCall = { function: "ownerControl", opSelector: owner.opSelector, signature: PLACEHOLDER_SIG_HEX, successor: successorCallJsonV5(stateToJsonV5(owner.successor)) };
    const callHex = runEncoderV4({ ...encoderPaths, call: placeholderCall, contractVersion: abi.version });
    const covenantSigscriptLen = covenantSigscript(callHex, current.scriptBytes).length / 2;
    const inputs = [covIn(budget), fuelIn()];
    const outputs = [
      { value: owner.successor.feeReserve, scriptPublicKey: { version: 0, scriptHex: p2sh(next.scriptBytes) }, covenant: { authorizingInput: 0, covenantId } },
      { value: 1n, scriptPublicKey: { version: 0, scriptHex: p2pkScriptHex(change) }, covenant: null }
    ];
    const draft = { version: 1, inputs, outputs, lockTime: 0n, subnetworkId: "00".repeat(20), gas: 0n, payload: "" };
    const fee = exactFee(draft, [covenantSigscriptLen, ORDINARY_SIGSCRIPT_LEN]);
    const changeValue = fuel.amount - fee - owner.externalFunding;
    if (changeValue <= 0n) fail(`fuel ${fuel.amount} cannot cover fee ${fee} + external funding ${owner.externalFunding}`, "INSUFFICIENT_FUEL");
    outputs[1] = { ...outputs[1], value: changeValue };
    callExtra = { opSelector: owner.opSelector };
    plan = { kindSpend: false, successor: owner.successor, next, draft: { ...draft, outputs }, fee, budget, covenantSigscriptLen, plannedCallHexLength: callHex.length, lockTime: 0n, externalFunding: owner.externalFunding };
  } else {
    /* ownerRecover (terminal): reserve -> owner (output 0); token position -> owner key if present */
    const hasPosition = chain?.tokenPosition !== undefined && chain?.tokenPosition !== null;
    let position = null;
    let recover;
    let recipientProgram = null;
    let tokenSigscriptHex = null;
    if (hasPosition) {
      if (descriptor === undefined) fail("ownerRecover with a token position requires the accepted asset descriptor", "DESCRIPTOR_REQUIRED");
      position = resolveTokenPosition({ config, descriptor, templateIndex, chain, covenantId, template });
      recover = recoverPlanV5(state, template.owner, position.program.state.amount);
      recipientProgram = compileKcc20Program({ config, state: recover.tokenRecipient, familyBound: position.program.familyBound });
      const tokenCallHex = encodeTokenTransfer({ program: position.program, newStates: [recover.tokenRecipient], witnessesHex: "00" });
      tokenSigscriptHex = covenantSigscript(tokenCallHex, Buffer.from(position.program.scriptHex, "hex"));
    } else {
      recover = recoverPlanV5(state, template.owner, null);
    }
    const budget = selectComputeBudgetV5({ operation: action, ...geometry });
    const recipientNewJson = recover.tokenRecipient ? kcc20StateJson(recover.tokenRecipient) : { ownerIdentifier: template.owner, identifierType: 0, amount: "0", isMinter: false };
    const placeholderCall = { function: "ownerRecover", signature: PLACEHOLDER_SIG_HEX, recipientNew: recipientNewJson };
    const callHex = runEncoderV4({ ...encoderPaths, call: placeholderCall, contractVersion: abi.version });
    const covenantSigscriptLen = covenantSigscript(callHex, current.scriptBytes).length / 2;
    const inputs = [covIn(budget)];
    const sigLens = [covenantSigscriptLen];
    if (position) {
      inputs.push({ previousOutpoint: position.outpoint, sequence: 0n, computeBudget: selectTokenInputBudgetV5({ templatePrefixLen: template.templatePrefixLen, templateSuffixLen: template.templateSuffixLen }), utxo: { amount: position.value, scriptPublicKey: { version: 0, scriptHex: position.scriptPublicKeyHex }, covenantId: position.covenantId, blockDaaScore: 0n } });
      sigLens.push(tokenSigscriptHex.length / 2);
    }
    inputs.push(fuelIn());
    sigLens.push(ORDINARY_SIGSCRIPT_LEN);
    const outputs = [{ value: recover.payout, scriptPublicKey: { version: 0, scriptHex: p2pkScriptHex(recover.payoutTo) }, covenant: null }];
    if (position) outputs.push({ value: position.value, scriptPublicKey: { version: 0, scriptHex: recipientProgram.p2shSpkHex }, covenant: { authorizingInput: 1, covenantId: position.covenantId } });
    outputs.push({ value: 1n, scriptPublicKey: { version: 0, scriptHex: p2pkScriptHex(change) }, covenant: null });
    const draft = { version: 1, inputs, outputs, lockTime: 0n, subnetworkId: "00".repeat(20), gas: 0n, payload: "" };
    const fee = exactFee(draft, sigLens);
    const changeValue = fuel.amount - fee;
    if (changeValue <= 0n) fail(`fuel ${fuel.amount} cannot cover fee ${fee}`, "INSUFFICIENT_FUEL");
    outputs[outputs.length - 1] = { ...outputs[outputs.length - 1], value: changeValue };
    callExtra = { recipientNew: recipientNewJson };
    tokenSide = position ? { position, states: { recipientNew: recover.tokenRecipient }, tokenSigscriptHex, recipient: template.owner, recipientProof: null, recipientCarry: position.value, selfCarry: 0n } : null;
    plan = { kindSpend: false, terminal: true, recover, successor: null, next: null, draft: { ...draft, outputs }, fee, budget, covenantSigscriptLen, plannedCallHexLength: callHex.length, lockTime: 0n, externalFunding: 0n };
  }

  if (plan.draft.inputs.length > MAX_TX_FEE_IO || plan.draft.outputs.length > MAX_TX_FEE_IO) fail(`transaction shape exceeds the covenant fee-introspection bound of ${MAX_TX_FEE_IO} inputs/outputs`);

  const frozen = normalizeFrozenTxV3(plan.draft);
  const described = describeFrozenTx(frozen);
  const totalIn = frozen.inputs.reduce((s, i) => s + i.utxo.amount, 0n);
  const totalOut = frozen.outputs.reduce((s, o) => s + o.value, 0n);
  if (totalIn - totalOut !== plan.fee) fail("internal: realized fee != required fee");
  if (!plan.terminal) {
    const succ = frozen.outputs.filter((o) => o.covenant !== null && o.covenant.covenantId === covenantId);
    if (succ.length !== 1 || succ[0].value !== plan.successor.feeReserve) fail("internal: successor output does not carry exactly feeReserve");
  }

  const successorStateId = plan.terminal ? null : computeStateIdV5({ networkId: config.networkId, template, state: plan.successor, contractVersion: abi.version });
  const reserveConsumed = plan.kindSpend ? plan.spend.reserveConsumed : 0n;
  const externalIn = fuel ? fuel.amount : 0n;
  const externalOut = fuel ? frozen.outputs[frozen.outputs.length - 1].value : 0n;

  return deepFreeze({
    kind: "transition",
    contractVersion: abi.version,
    encoderFunction: isSpend ? "tokenAgentSpend" : terminal ? "ownerRecover" : "ownerControl",
    networkId: config.networkId,
    action,
    role: isSpend ? "agent" : "owner",
    template,
    predecessorOutpoint,
    predecessorStateId: current.stateId,
    covenantId,
    stateJson: stateToJsonV5(state),
    successorState: plan.terminal ? null : stateToJsonV5(plan.successor),
    successorStateId,
    successorScriptSha256: plan.terminal ? null : plan.next.scriptSha256,
    asset: tokenSide
      ? Object.freeze({
          descriptorHash: tokenSide.position.descriptorHash,
          assetId: tokenSide.position.descriptor.assetId,
          tokenCovenantId: tokenSide.position.covenantId,
          templateVmHashBlake2b256: tokenSide.position.program.templateVmHashBlake2b256,
          familyBound: tokenSide.position.program.familyBound,
          templateIndex,
          issuerPowers: tokenSide.position.descriptor.issuerPowers,
          displayName: tokenSide.position.descriptor.displayName,
          decimalsDisplay: tokenSide.position.descriptor.decimalsDisplay
        })
      : null,
    accounting: Object.freeze({
      token: Object.freeze({
        positionBefore: tokenSide ? tokenSide.position.program.state.amount.toString() : null,
        spendAmount: plan.kindSpend ? plan.spend.spendAmount.toString() : "0",
        positionAfter: plan.kindSpend ? plan.spend.tokenSelfAfter.toString() : plan.terminal && tokenSide ? "0" : tokenSide ? tokenSide.position.program.state.amount.toString() : null,
        recipient: tokenSide ? tokenSide.recipient : null,
        recoveredToOwner: plan.terminal && tokenSide ? tokenSide.position.program.state.amount.toString() : "0"
      }),
      kas: Object.freeze({
        predecessorFeeReserve: state.feeReserve.toString(),
        reserveConsumed: reserveConsumed.toString(),
        successorFeeReserve: plan.terminal ? "0" : plan.successor.feeReserve.toString(),
        externalIn: externalIn.toString(),
        externalOut: externalOut.toString(),
        externalFunding: plan.externalFunding.toString(),
        tokenInputKas: tokenSide ? tokenSide.position.value.toString() : "0",
        tokenSelfCarryKas: tokenSide ? tokenSide.selfCarry.toString() : "0",
        tokenRecipientCarryKas: tokenSide ? tokenSide.recipientCarry.toString() : "0",
        fee: plan.fee.toString(),
        terminalPayout: plan.terminal ? plan.recover.payout.toString() : "0"
      })
    }),
    frozen,
    frozenCanonicalJson: canonicalFrozenTxJson(frozen),
    txId: described.txId,
    covenantSighash: described.sighashAll[0],
    computeBudget: plan.budget,
    requiredFeeSompi: plan.fee.toString(),
    encoderBuildDir: current.buildDir,
    plannedCallHexLength: plan.plannedCallHexLength,
    callExtra,
    hasFuelInput: fuel !== null,
    hasTokenInput: tokenSide !== null,
    tokenSignatureScriptHex: tokenSide ? tokenSide.tokenSigscriptHex : null,
    agentProof: plan.kindSpend ? Object.freeze({ root: state.agentRoot, siblingsHex: plan.spend.agentProof.siblingsHex, pathBits: BigInt(plan.spend.agentProof.pathBits).toString() }) : null,
    recipientProof: plan.kindSpend ? Object.freeze({ root: tokenSide.recipientProof.root, siblingsHex: tokenSide.recipientProof.siblingsHex, pathBits: BigInt(tokenSide.recipientProof.pathBits).toString() }) : null,
    payment: plan.kindSpend ? { recipient: tokenSide.recipient, tokenAmount: plan.spend.spendAmount.toString(), carryKasSompi: tokenSide.recipientCarry.toString() } : null
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

/* FINALIZE a frozen build (NO broadcasting): real covenant call bytes through pv_call_encoder + the signature scripts. */
function finalizeV5Transaction({ build, covenantSignatureHex, fuelSignatureScriptHex }) {
  if (build.kind !== "transition" || build.contractVersion !== CONTRACT_VERSION_V5) fail("finalizeV5Transaction takes a v0.5 transition build");
  const covenantSig = extractSchnorr65(covenantSignatureHex, "covenant signature");
  const terminal = build.action === "ownerRecover";
  const call = { function: build.encoderFunction, signature: covenantSig, ...build.callExtra };
  if (!terminal) call.successor = successorCallJsonV5(build.successorState);
  const callHex = runEncoderV4({
    sourcePath: path.join(build.encoderBuildDir, "PolicyVault.state.sil"),
    constructorArgsPath: path.join(build.encoderBuildDir, "constructor-args.json"),
    call,
    contractVersion: build.contractVersion
  });
  if (callHex.length !== build.plannedCallHexLength) fail(`final covenant call length ${callHex.length / 2} != planned ${build.plannedCallHexLength / 2} — the exact-fee freeze is violated; refusing`, "FEE_DRIFT");
  const artifact = JSON.parse(fs.readFileSync(path.join(build.encoderBuildDir, "artifact.json")));
  const covenantScript = covenantSigscript(callHex, Buffer.from(artifact.script));
  const json = JSON.parse(build.frozenCanonicalJson);
  json.inputs[0].signatureScript = covenantScript;
  let next = 1;
  if (build.hasTokenInput) {
    json.inputs[next].signatureScript = build.tokenSignatureScriptHex;
    next += 1;
  }
  if (build.hasFuelInput) {
    if (typeof fuelSignatureScriptHex !== "string" || !/^[0-9a-f]+$/.test(fuelSignatureScriptHex) || fuelSignatureScriptHex.length / 2 !== ORDINARY_SIGSCRIPT_LEN) {
      fail(`fuel signature script must be exactly ${ORDINARY_SIGSCRIPT_LEN} bytes`);
    }
    json.inputs[next].signatureScript = fuelSignatureScriptHex;
  } else if (fuelSignatureScriptHex !== undefined) {
    fail("this build has no fuel input — do not supply a fuel signature");
  }
  return Object.freeze({ txId: build.txId, requiredFeeSompi: build.requiredFeeSompi, finalTransaction: json, covenantCallHex: callHex });
}

/* GENESIS: ordinary funding inputs -> [controller output holding the fee reserve, change]. */
function buildCreateV5({ config, templateInput, initialStateInput, funding, changeXOnly, contractVersion, descriptor }) {
  const abi = resolveV5Abi(contractVersion ?? CONTRACT_VERSION_V5);
  const template = normalizeTemplateV5(templateInput);
  const state = normalizeStateV5(initialStateInput);
  if (state.policyNonce !== 0n) fail("a v0.5 genesis state must carry policyNonce 0");
  if (state.paused !== 0n) fail("a v0.5 genesis state must start unpaused");
  if (descriptor !== undefined && assets.computeDescriptorHash(descriptor) !== template.descriptorHash) fail("descriptor hash != template.descriptorHash — failing closed", "DESCRIPTOR_PIN_MISMATCH");
  if (!Array.isArray(funding) || funding.length === 0) fail("funding must be a non-empty array of ordinary UTXOs ({ outpoint, amount, scriptPublicKeyHex })");
  const fundingInputs = funding.map((f, i) => {
    const spk = String(f.scriptPublicKeyHex ?? "").toLowerCase();
    if (!/^[0-9a-f]+$/.test(spk) || spk.length % 2 !== 0) fail(`funding[${i}].scriptPublicKeyHex must be hex`);
    return { outpoint: normalizeOutpoint(f.outpoint, `funding[${i}].outpoint`), amount: parsePositiveSompi(f.amount, `funding[${i}].amount`), scriptPublicKeyHex: spk };
  });
  const change = normalizeHex(changeXOnly, 32, "changeXOnly");
  const compiled = compileExactStateV5({ config, template, state, contractVersion: abi.version });
  const stateId = computeStateIdV5({ networkId: config.networkId, template, state, contractVersion: abi.version });
  const { loadKaspa } = require("./chain");
  const kaspa = loadKaspa(config);
  const spkHex = String(kaspa.payToScriptHashScript(compiled.scriptBytes.toString("hex")).script).toLowerCase();
  const outputs = [{ value: state.feeReserve, scriptPublicKey: { version: 0, scriptHex: spkHex }, covenant: null }, { value: 1n, scriptPublicKey: { version: 0, scriptHex: p2pkScriptHex(change) }, covenant: null }];
  const unbound = new kaspa.TransactionOutput(state.feeReserve, kaspa.payToScriptHashScript(compiled.scriptBytes.toString("hex")));
  const genesisCovenantId = kaspa.covenantId({ transactionId: fundingInputs[0].outpoint.transactionId, index: fundingInputs[0].outpoint.index }, [{ index: 0, output: unbound }]).toString().toLowerCase();
  outputs[0] = { ...outputs[0], covenant: { authorizingInput: 0, covenantId: genesisCovenantId } };
  const inputs = fundingInputs.map((f) => ({ previousOutpoint: f.outpoint, sequence: 0n, computeBudget: V5_BUDGET.ORDINARY_INPUT, utxo: { amount: f.amount, scriptPublicKey: { version: 0, scriptHex: f.scriptPublicKeyHex }, covenantId: null, blockDaaScore: 0n } }));
  const draft = { version: 1, inputs, outputs, lockTime: 0n, subnetworkId: "00".repeat(20), gas: 0n, payload: "" };
  const requiredFee = exactFee(draft, inputs.map(() => ORDINARY_SIGSCRIPT_LEN));
  const totalFunding = fundingInputs.reduce((s, f) => s + f.amount, 0n);
  const changeValue = totalFunding - state.feeReserve - requiredFee;
  if (changeValue <= 0n) fail(`funding ${totalFunding} cannot cover the fee reserve ${state.feeReserve} + fee ${requiredFee}`, "INSUFFICIENT_FUEL");
  outputs[1] = { ...outputs[1], value: changeValue };
  const frozen = normalizeFrozenTxV3({ ...draft, outputs });
  const described = describeFrozenTx(frozen);
  return deepFreeze({
    kind: "genesis",
    contractVersion: abi.version,
    networkId: config.networkId,
    action: "createTokenController",
    template,
    initialState: stateToJsonV5(state),
    stateId,
    controllerOutputIndex: 0,
    changeIndex: 1,
    covenantId: genesisCovenantId,
    scriptSha256: compiled.scriptSha256,
    controllerScriptHex: compiled.scriptHex,
    accounting: Object.freeze({ kas: Object.freeze({ feeReserve: state.feeReserve.toString() }), token: Object.freeze({ positionBefore: "0", positionAfter: "0" }) }),
    frozen,
    frozenCanonicalJson: canonicalFrozenTxJson(frozen),
    txId: described.txId,
    requiredFeeSompi: requiredFee.toString(),
    encoderBuildDir: compiled.buildDir
  });
}


/*
 * TOKEN DEPOSIT ("fund the vault"): a USER-OWNED KCC20 position (p2pk
 * owner scheme) → the controller's covenant id (covenant-id/v1 owner
 * scheme), optionally with a token remainder back to the user. The
 * controller is NOT an input (the token family's own leader authorizes the
 * transfer with the user's signature); PolicyVault only prepares the exact
 * bytes and verifies them. Preserved: exact descriptor binding (the
 * controller's pinned descriptorHash/tokenCovenantId/template must equal
 * the descriptor in hand), template verification (the user's revealed
 * program must reproduce the live UTXO's P2SH under the accepted
 * template), token conservation (deposit + remainder == position), separate
 * KAS accounting (the family's KAS is conserved exactly across the family;
 * the fee comes from the user's fuel), no server signing/custody (the user's
 * wallet signs the token input; PolicyVault never holds a key), fail-closed
 * unsupported programs (UNSUPPORTED_TOKEN_PROGRAM from the adapter).
 *
 *   chain.userPosition { outpoint, value, scriptPublicKeyHex, covenantId, state }
 *   chain.fuel         ordinary user UTXO paying the network fee
 *   controller         { covenantId, template } — the live controller instance
 *   params             { depositAmount (atomic), depositCarryKasSompi }
 */
function buildTokenDepositV5({ config, descriptor, templateIndex = 0, controller, chain, params = {}, changeXOnly }) {
  if (!controller || typeof controller !== "object") fail("controller { covenantId, template } is required", "CONTROLLER_REQUIRED");
  const controllerCovenantId = normalizeHex(controller.covenantId, 32, "controller.covenantId");
  const template = normalizeTemplateV5(controller.template);
  const validated = assets.validateAssetDescriptor(descriptor);
  const descriptorHash = assets.computeDescriptorHash(validated);
  if (descriptorHash !== template.descriptorHash) fail("descriptor hash != the controller's pinned descriptorHash — descriptor substitution/downgrade; failing closed", "DESCRIPTOR_PIN_MISMATCH");
  if (validated.tokenCovenantId !== template.tokenCovenantId) fail("descriptor.tokenCovenantId != the controller's pinned tokenCovenantId — failing closed", "DESCRIPTOR_MISMATCH");
  const tpl = validated.acceptedTransferTemplates[templateIndex];
  if (!tpl || tpl.templateVmHashBlake2b256 !== template.templateVmHash || tpl.prefixLen !== template.templatePrefixLen || tpl.suffixLen !== template.templateSuffixLen) {
    fail("the selected descriptor template does not equal the controller's pinned template hash/geometry — failing closed", "TEMPLATE_PIN_MISMATCH");
  }
  const up = chain?.userPosition;
  if (!up || typeof up !== "object") fail("chain.userPosition { outpoint, value, scriptPublicKeyHex, covenantId, state } is required", "USER_POSITION_REQUIRED");
  const familyId = normalizeHex(up.covenantId, 32, "chain.userPosition.covenantId");
  if (familyId !== template.tokenCovenantId) fail("chain.userPosition.covenantId is not the controller's pinned token family — wrong asset; failing closed", "WRONG_TOKEN_FAMILY");
  const program = verifiedTokenPosition({ config, descriptor: validated, templateIndex, state: up.state, scriptPublicKeyHex: up.scriptPublicKeyHex });
  if (program.state.identifierType !== assets.kcc20.OWNER_SCHEMES.P2PK) fail("deposits are built from a p2pk-owned (user) token position only — failing closed", "USER_POSITION_NOT_P2PK");
  if (program.state.isMinter) fail("a minter position cannot be deposited into a controller", "TOKEN_MINTER_POSITION");
  const userPk = program.state.ownerIdentifier;
  const positionOutpoint = normalizeOutpoint(up.outpoint, "chain.userPosition.outpoint");
  const positionValue = parsePositiveSompi(up.value, "chain.userPosition.value");
  const fuel = normalizeFuel(chain?.fuel);
  const change = normalizeHex(changeXOnly, 32, "changeXOnly");

  /* TOKEN domain: exact conservation */
  const deposit = assets.kcc20.parseAtomicAmount(params.depositAmount, "depositAmount");
  if (deposit <= 0n) fail("depositAmount must be > 0", "ZERO_DEPOSIT");
  if (deposit > program.state.amount) fail("depositAmount exceeds the user's token position — conservation would break", "INSUFFICIENT_TOKENS");
  const remainder = program.state.amount - deposit;
  const depositState = { ownerIdentifier: controllerCovenantId, identifierType: assets.kcc20.OWNER_SCHEMES.COVENANT_ID, amount: deposit, isMinter: false };
  const remainderState = remainder > 0n ? { ownerIdentifier: userPk, identifierType: assets.kcc20.OWNER_SCHEMES.P2PK, amount: remainder, isMinter: false } : null;

  /* KAS domain: the family's KAS is conserved exactly across the family */
  const depositCarry = remainderState ? parsePositiveSompi(params.depositCarryKasSompi, "depositCarryKasSompi") : parseSompi(params.depositCarryKasSompi ?? positionValue, "depositCarryKasSompi");
  if (!remainderState && depositCarry !== positionValue) fail("a full deposit moves the position's entire KAS carry with it (depositCarryKasSompi must equal the position value)", "CARRY_MISMATCH");
  if (remainderState && depositCarry >= positionValue) fail("depositCarryKasSompi must leave KAS for the remainder output", "CARRY_TOO_LARGE");
  const remainderCarry = positionValue - depositCarry;

  const depositProgram = compileKcc20Program({ config, state: depositState, familyBound: program.familyBound });
  const remainderProgram = remainderState ? compileKcc20Program({ config, state: remainderState, familyBound: program.familyBound }) : null;
  const newStates = remainderState ? [depositState, remainderState] : [depositState];
  const tokenBudget = selectTokenInputBudgetV5({ templatePrefixLen: template.templatePrefixLen, templateSuffixLen: template.templateSuffixLen, signerOwned: true });
  /* placeholder signature for the exact byte shape (a real 65-byte Schnorr replaces it at finalize) */
  const placeholderCallHex = runEncoderV4({
    sourcePath: program.sourcePath,
    constructorArgsPath: program.constructorArgsPath,
    call: { function: "transfer", signature: PLACEHOLDER_SIG_HEX, newStates: newStates.map(kcc20StateJson), sigs: [PLACEHOLDER_SIG_HEX], witnesses: "00" },
    contractVersion: "kcc20/1"
  });
  const tokenSigscriptLen = covenantSigscript(placeholderCallHex, Buffer.from(program.scriptHex, "hex")).length / 2;
  const inputs = [
    { previousOutpoint: positionOutpoint, sequence: 0n, computeBudget: tokenBudget, utxo: { amount: positionValue, scriptPublicKey: { version: 0, scriptHex: program.p2shSpkHex }, covenantId: familyId, blockDaaScore: 0n } },
    fuelIn()
  ];
  function fuelIn() {
    return { previousOutpoint: fuel.outpoint, sequence: 0n, computeBudget: V5_BUDGET.ORDINARY_INPUT, utxo: { amount: fuel.amount, scriptPublicKey: { version: 0, scriptHex: fuel.scriptPublicKeyHex }, covenantId: null, blockDaaScore: 0n } };
  }
  const outputs = [{ value: depositCarry, scriptPublicKey: { version: 0, scriptHex: depositProgram.p2shSpkHex }, covenant: { authorizingInput: 0, covenantId: familyId } }];
  if (remainderState) outputs.push({ value: remainderCarry, scriptPublicKey: { version: 0, scriptHex: remainderProgram.p2shSpkHex }, covenant: { authorizingInput: 0, covenantId: familyId } });
  outputs.push({ value: 1n, scriptPublicKey: { version: 0, scriptHex: p2pkScriptHex(change) }, covenant: null });
  const draft = { version: 1, inputs, outputs, lockTime: 0n, subnetworkId: "00".repeat(20), gas: 0n, payload: "" };
  const fee = exactFee(draft, [tokenSigscriptLen, ORDINARY_SIGSCRIPT_LEN]);
  const changeValue = fuel.amount - fee;
  if (changeValue <= 0n) fail(`fuel ${fuel.amount} cannot cover fee ${fee}`, "INSUFFICIENT_FUEL");
  outputs[outputs.length - 1] = { ...outputs[outputs.length - 1], value: changeValue };
  const frozen = normalizeFrozenTxV3({ ...draft, outputs });
  const described = describeFrozenTx(frozen);
  return deepFreeze({
    kind: "tokenDeposit",
    contractVersion: CONTRACT_VERSION_V5,
    networkId: config.networkId,
    action: "tokenDeposit",
    role: "tokenOwner",
    controller: Object.freeze({ covenantId: controllerCovenantId, template }),
    asset: Object.freeze({ descriptorHash, assetId: validated.assetId, tokenCovenantId: familyId, templateVmHashBlake2b256: program.templateVmHashBlake2b256, familyBound: program.familyBound, templateIndex, issuerPowers: validated.issuerPowers, displayName: validated.displayName, decimalsDisplay: validated.decimalsDisplay }),
    userPk,
    accounting: Object.freeze({
      token: Object.freeze({ positionBefore: program.state.amount.toString(), deposit: deposit.toString(), remainderToUser: remainder.toString() }),
      kas: Object.freeze({ positionKas: positionValue.toString(), depositCarryKas: depositCarry.toString(), remainderCarryKas: remainderCarry.toString(), externalIn: fuel.amount.toString(), externalOut: changeValue.toString(), fee: fee.toString() })
    }),
    frozen,
    frozenCanonicalJson: canonicalFrozenTxJson(frozen),
    txId: described.txId,
    tokenInputSighash: described.sighashAll[0],
    requiredFeeSompi: fee.toString(),
    tokenProgram: Object.freeze({ sourcePath: program.sourcePath, constructorArgsPath: program.constructorArgsPath, scriptHex: program.scriptHex }),
    tokenNewStates: Object.freeze(newStates.map(kcc20StateJson)),
    plannedTokenCallHexLength: placeholderCallHex.length
  });
}

/* FINALIZE a deposit: the user's 65-byte SIG_HASH_ALL signature over the token input goes INSIDE the family call (sigs[0]); fuel sigscript as usual. */
function finalizeTokenDepositV5({ build, tokenOwnerSignatureHex, fuelSignatureScriptHex }) {
  if (build.kind !== "tokenDeposit") fail("finalizeTokenDepositV5 takes a tokenDeposit build");
  const sig = extractSchnorr65(tokenOwnerSignatureHex, "token owner signature");
  const callHex = runEncoderV4({
    sourcePath: build.tokenProgram.sourcePath,
    constructorArgsPath: build.tokenProgram.constructorArgsPath,
    call: { function: "transfer", signature: sig, newStates: [...build.tokenNewStates], sigs: [sig], witnesses: "00" },
    contractVersion: "kcc20/1"
  });
  if (callHex.length !== build.plannedTokenCallHexLength) fail("final token call length != planned — exact-fee freeze violated; refusing", "FEE_DRIFT");
  const json = JSON.parse(build.frozenCanonicalJson);
  json.inputs[0].signatureScript = covenantSigscript(callHex, Buffer.from(build.tokenProgram.scriptHex, "hex"));
  if (typeof fuelSignatureScriptHex !== "string" || !/^[0-9a-f]+$/.test(fuelSignatureScriptHex) || fuelSignatureScriptHex.length / 2 !== ORDINARY_SIGSCRIPT_LEN) fail(`fuel signature script must be exactly ${ORDINARY_SIGSCRIPT_LEN} bytes`);
  json.inputs[1].signatureScript = fuelSignatureScriptHex;
  return Object.freeze({ txId: build.txId, requiredFeeSompi: build.requiredFeeSompi, finalTransaction: json, tokenCallHex: callHex });
}

module.exports = {
  buildV5Transaction,
  buildCreateV5,
  finalizeV5Transaction,
  buildTokenDepositV5,
  finalizeTokenDepositV5,
  successorCallJsonV5,
  encodeTokenTransfer,
  OWNER_CONTROL_ACTIONS,
  SPEND_ACTIONS,
  OWNER_OP_SELECTOR_V5
};
