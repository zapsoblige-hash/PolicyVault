"use strict";

/*
 * v0.5 token-controller transition planner — deterministic successor
 * derivation for every PolicyVault.v0.5.sil entrypoint, mirroring the
 * covenant's rules EXACTLY so the core refuses locally what consensus
 * would refuse (local pre-check ONLY; the covenant remains the authority).
 *
 * Two accounting domains, never mixed:
 *   TOKEN — spendAmount / tokenPositionAmount / per-agent caps+budgets are
 *           atomic token units; conservation selfAfter = prev - spend is
 *           verified HERE from the token position's revealed state, never
 *           from an indexer;
 *   KAS   — feeReserve / reserveConsumed / carry values are sompi; the
 *           reserve can only become network fee (bounded by the agent's
 *           agentMaxFeePerTx and by the exact fee, checked by the builder
 *           once the fee is known); the token family's own KAS never leaks
 *           except to the recipient's bounded carry.
 *
 * Status: IMPLEMENTED + UNIT-TESTED (core/model/test/vault-transitions-v5.test.js).
 */

const { parseSompi, parsePositiveSompi } = require("./amounts");
const { normalizeHex, normalizeXOnlyPubkey } = require("./vault-state");
const { normalizeStateV5, OWNER_OP_SELECTOR_V5 } = require("./vault-state-v5");
const { normalizeTokenAgentPolicyV5, verifyTokenAgentProofV5, foldTokenAgentPolicyV5 } = require("./agent-merkle-v5");
const { parseAtomicAmount, OWNER_SCHEMES } = require("./token-amounts");

const MAX_PERIODS_ELAPSED = 1000n;

function fail(message, code) {
  const e = new Error(`vault-transitions-v5: ${message}`);
  if (code) e.code = code;
  throw e;
}

function requireContinuingState(state, label) {
  if (!state || typeof state !== "object") fail(`${label}: state is required`);
  if (state.recoveryParse === true) {
    fail(`${label}: a recovery-mode (shape-only) state may only be used by ownerRecover — refusing to derive a successor from it`, "RECOVERY_STATE_ONLY");
  }
  return normalizeStateV5(state);
}

function withChanges(state, changes) {
  return normalizeStateV5({ ...state, ...changes });
}

/*
 * tokenAgentSpend successor. Inputs:
 *   agentPolicy          the full leaf tuple (from the agent registry)
 *   agentProof           { siblingsHex, pathBits } against state.agentRoot
 *   spendAmount          atomic token units paid to the recipient
 *   tokenPositionAmount  atomic units currently held by the controller's
 *                        token UTXO (decoded from its revealed state)
 *   periodsElapsed       0 (same period) or >= 1 (rollover)
 *   reserveConsumed      sompi taken from the fee reserve (<= min(cap, fee))
 *   tokenInputKas / selfCarryKas / recipientCarryKas  the token family's
 *                        KAS values (input, self continuation, recipient)
 */
function tokenAgentSpendSuccessorV5(state, params) {
  const s = requireContinuingState(state, "tokenAgentSpend");
  if (s.paused !== 0n) fail("tokenAgentSpend: controller is paused", "PAUSED");
  const policy = normalizeTokenAgentPolicyV5(params.agentPolicy);
  const proofIn = params.agentProof;
  if (!proofIn || typeof proofIn !== "object") fail("tokenAgentSpend: agentProof { siblingsHex, pathBits } is required");
  const proof = {
    siblingsHex: String(proofIn.siblingsHex ?? "").toLowerCase(),
    pathBits: typeof proofIn.pathBits === "bigint" ? proofIn.pathBits : BigInt(proofIn.pathBits)
  };
  if (!verifyTokenAgentProofV5({ root: s.agentRoot, policy, siblingsHex: proof.siblingsHex, pathBits: proof.pathBits })) {
    fail("tokenAgentSpend: the agent policy proof does not verify against the live agentRoot — stale tree or forged policy", "AGENT_PROOF_INVALID");
  }

  /* TOKEN domain */
  const spend = parseAtomicAmount(params.spendAmount, "spendAmount");
  if (spend <= 0n) fail("tokenAgentSpend: spendAmount must be > 0", "ZERO_SPEND");
  if (spend > policy.tokenMaxPerSpend) fail("tokenAgentSpend: spendAmount exceeds this agent's tokenMaxPerSpend", "OVER_CAP");
  const position = parseAtomicAmount(params.tokenPositionAmount, "tokenPositionAmount");
  if (spend > position) fail("tokenAgentSpend: spendAmount exceeds the controller's token position — conservation would break", "INSUFFICIENT_TOKENS");
  const tokenSelfAfter = position - spend;

  const periods = parseSompi(params.periodsElapsed ?? 0n, "periodsElapsed");
  if (periods > MAX_PERIODS_ELAPSED) fail(`tokenAgentSpend: periodsElapsed out of range [0, ${MAX_PERIODS_ELAPSED}]`);
  let newStart = policy.periodStartDaa;
  let newSpent = policy.tokenPeriodSpent + spend;
  let lockTime = 0n;
  if (periods >= 1n) {
    newStart = policy.periodStartDaa + periods * policy.periodLengthDaa;
    newSpent = spend;
    lockTime = newStart;
  }
  if (newSpent > policy.tokenPeriodBudget) fail("tokenAgentSpend: spend exceeds this agent's remaining token period budget", "OVER_BUDGET");

  /* KAS domain */
  const consumed = parseSompi(params.reserveConsumed ?? 0n, "reserveConsumed");
  if (consumed > policy.agentMaxFeePerTx) fail("tokenAgentSpend: reserveConsumed exceeds this agent's agentMaxFeePerTx", "OVER_AGENT_FEE_CAP");
  if (consumed > s.feeReserve) fail("tokenAgentSpend: reserveConsumed exceeds the available fee reserve", "INSUFFICIENT_RESERVE");
  const tokenInputKas = parseSompi(params.tokenInputKas, "tokenInputKas");
  const selfCarryKas = parseSompi(params.selfCarryKas, "selfCarryKas");
  const recipientCarryKas = parseSompi(params.recipientCarryKas, "recipientCarryKas");
  if (recipientCarryKas > policy.agentMaxCarryKas) fail("tokenAgentSpend: recipient carry KAS exceeds this agent's agentMaxCarryKas", "OVER_CARRY_CAP");
  if (selfCarryKas + recipientCarryKas < tokenInputKas) {
    fail("tokenAgentSpend: the token family's KAS would leak (self + recipient carry < token input KAS)", "TOKEN_FAMILY_KAS_LEAK");
  }

  const newPolicy = normalizeTokenAgentPolicyV5({ ...policy, periodStartDaa: newStart, tokenPeriodSpent: newSpent });
  const newRoot = foldTokenAgentPolicyV5(newPolicy, proof.siblingsHex, proof.pathBits);
  if (newRoot === null) fail("tokenAgentSpend: internal — successor-root fold left unconsumed path bits");

  const successor = withChanges(s, { feeReserve: s.feeReserve - consumed, agentRoot: newRoot });
  return Object.freeze({
    successor,
    previousPolicy: policy,
    newPolicy,
    newStart,
    newSpent,
    lockTime,
    spendAmount: spend,
    tokenPositionAmount: position,
    tokenSelfAfter,
    reserveConsumed: consumed,
    kas: Object.freeze({ tokenInputKas, selfCarryKas, recipientCarryKas }),
    agentProof: Object.freeze({ siblingsHex: proof.siblingsHex, pathBits: proof.pathBits })
  });
}

/* The two token continuation states the covenant will template-verify. */
function tokenContinuationStatesV5({ controllerCovenantId, recipientPk, plan }) {
  const covid = normalizeHex(controllerCovenantId, 32, "controllerCovenantId");
  const recipient = normalizeXOnlyPubkey(recipientPk, "recipientPk");
  return Object.freeze({
    selfNew: Object.freeze({ ownerIdentifier: covid, identifierType: OWNER_SCHEMES.COVENANT_ID, amount: plan.tokenSelfAfter, isMinter: false }),
    recipientNew: Object.freeze({ ownerIdentifier: recipient, identifierType: OWNER_SCHEMES.P2PK, amount: plan.spendAmount, isMinter: false })
  });
}

function setAgentRootSuccessorV5(state, newAgentRoot) {
  const s = requireContinuingState(state, "setAgentRoot");
  const agentRoot = normalizeHex(newAgentRoot, 32, "newAgentRoot");
  return Object.freeze({ successor: withChanges(s, { agentRoot, policyNonce: s.policyNonce + 1n }), opSelector: OWNER_OP_SELECTOR_V5.ownerSetAgentRoot });
}

function topUpReserveSuccessorV5(state, topUpAmount) {
  const s = requireContinuingState(state, "topUpReserve");
  const amount = parsePositiveSompi(topUpAmount, "topUpAmount");
  return Object.freeze({ successor: withChanges(s, { feeReserve: s.feeReserve + amount }), topUpAmount: amount, opSelector: OWNER_OP_SELECTOR_V5.ownerTopUpReserve });
}

function pauseSuccessorV5(state, pause) {
  const s = requireContinuingState(state, pause ? "pause" : "unpause");
  if (pause && s.paused !== 0n) fail("pause: controller is already paused");
  if (!pause && s.paused !== 1n) fail("unpause: controller is not paused");
  return Object.freeze({
    successor: withChanges(s, { paused: pause ? 1n : 0n }),
    opSelector: pause ? OWNER_OP_SELECTOR_V5.ownerPause : OWNER_OP_SELECTOR_V5.ownerUnpause
  });
}

/*
 * ownerRecover plan (terminal): the reserve pays out to the owner; if a
 * token position exists, its ENTIRE amount moves to the owner's own key.
 */
function recoverPlanV5(state, ownerXOnly, tokenPositionAmount) {
  if (!state || typeof state !== "object") fail("recover: state is required");
  const owner = normalizeXOnlyPubkey(ownerXOnly, "owner");
  const payout = parseSompi(state.feeReserve, "state.feeReserve");
  let tokenRecipient = null;
  if (tokenPositionAmount !== null && tokenPositionAmount !== undefined) {
    const amount = parseAtomicAmount(tokenPositionAmount, "tokenPositionAmount");
    tokenRecipient = Object.freeze({ ownerIdentifier: owner, identifierType: OWNER_SCHEMES.P2PK, amount, isMinter: false });
  }
  return Object.freeze({ terminal: true, payout, payoutTo: owner, tokenRecipient });
}

module.exports = {
  MAX_PERIODS_ELAPSED,
  tokenAgentSpendSuccessorV5,
  tokenContinuationStatesV5,
  setAgentRootSuccessorV5,
  topUpReserveSuccessorV5,
  pauseSuccessorV5,
  recoverPlanV5
};
