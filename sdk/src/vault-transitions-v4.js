"use strict";

/*
 * Canonical v0.4 state-transition derivation (Checkpoint E §E3).
 *
 * One canonical successor builder per non-terminal production entrypoint
 * (FROZEN ABI, docs/covenant-spec-v0.4.md §4). Callers NEVER supply
 * successor state — every builder derives the single covenant-permitted
 * successor from the normalized predecessor, changes ONLY the fields that
 * entrypoint authorizes, preserves everything else, and applies the exact
 * production policyNonce rule:
 *
 *   nonce PRESERVED: agentSpend, ownerTopUp, ownerTopUpReserve,
 *                    ownerPause, ownerUnpause
 *   nonce +1:        ownerSetAgentRoot, ownerSetApprovers
 *
 * The frozen per-entrypoint field-preservation matrix (spec §4) is
 * enforced structurally: each builder spreads the predecessor and touches
 * only its authorized fields, then re-normalizes through the STRICT v0.4
 * normalizer (exact approver-slot layout preserved) so an ill-formed
 * successor can never leave this module.
 *
 * agentSpend mirrors the covenant's exact rules (gen_v4.js / the compiled
 * production covenant is the authority):
 *   paused == 0; payAmount > 0; payAmount <= leaf.maxPerSpend;
 *   0 <= periodsElapsed <= 1000; rollover advances periodStartDaa by
 *   periodsElapsed * periodLengthDaa and resets periodSpent to payAmount
 *   (lockTime must be >= newStart — CLTV); newSpent <= periodBudget;
 *   newProtected = protected - pay > 0; newReserve = reserve -
 *   reserveConsumed >= 0; 0 <= reserveConsumed <= leaf.agentMaxFeePerTx;
 *   successor agentRoot = fold(newLeaf) up the SAME co-path that proved
 *   the old leaf (single-leaf update: every unrelated leaf preserved).
 *
 * Recovery-mode predecessor parses (normalizeStateV4ForRecovery) are
 * rejected by every function here — they exist only for ownerRecover
 * construction (recoverPlanV4 accepts both parse modes).
 *
 * Owner recovery is TERMINAL: recoverPlanV4 returns exact payout facts
 * (protectedValue + feeReserve to the owner) and never fabricates a
 * covenant successor.
 */

const { parseSompi, parsePositiveSompi } = require("./amounts");
const { normalizeXOnlyPubkey, normalizeHex } = require("./vault-state");
const { normalizeStateV4, stateToJsonV4, MAX_APPROVERS } = require("./vault-state-v4");
const { normalizeAgentPolicyV4, verifyAgentProofV4, foldAgentPolicyV4 } = require("./agent-merkle-v4");

const MAX_PERIODS_ELAPSED = 1000n; // covenant: require(periodsElapsed <= 1000)

function fail(message, code) {
  const error = new Error(`vault-transitions-v4: ${message}`);
  if (code) error.code = code;
  throw error;
}

function requireContinuingState(state, label) {
  if (!state || typeof state !== "object") {
    fail(`${label}: normalized predecessor state is required`);
  }
  if (state.recoveryParse === true) {
    fail(`${label}: a recovery-mode state parse can only be used for ownerRecover — refusing ordinary transition`);
  }
  if (typeof state.policyNonce !== "bigint") {
    fail(`${label}: predecessor state is missing policyNonce`);
  }
}

/*
 * Re-normalize a derived successor through the strict normalizer with the
 * EXACT slot layout preserved — asserts the successor is a well-formed
 * continuing state; a canonical builder can never emit a state the strict
 * normalizer rejects.
 */
function normalizeSuccessor(successor) {
  return normalizeStateV4(stateToJsonV4(successor));
}

function withChanges(state, changes) {
  return normalizeSuccessor(Object.freeze({ ...state, ...changes }));
}

/*
 * agentSpend: the one agent path (both approval tiers + rollover).
 * Derives the FULL spend transition:
 *   - authenticates the agent policy against the live agentRoot,
 *   - advances the agent's period accounting exactly as the covenant will,
 *   - derives the successor agentRoot by the single-leaf fold,
 *   - moves protectedValue by exactly payAmount and feeReserve by exactly
 *     reserveConsumed.
 * Returns { successor, previousPolicy, newPolicy, newStart, newSpent,
 *           lockTime, aboveThreshold, payAmount, reserveConsumed }.
 */
function agentSpendSuccessorV4(state, { agentPolicy, agentProof, payAmount, periodsElapsed, reserveConsumed }) {
  requireContinuingState(state, "agentSpend");
  if (state.paused !== 0n) {
    fail("agentSpend: vault is paused");
  }
  const policy = normalizeAgentPolicyV4(agentPolicy);
  if (!agentProof || typeof agentProof !== "object") {
    fail("agentSpend: agentProof { siblingsHex, pathBits } is required");
  }
  const proof = {
    siblingsHex: String(agentProof.siblingsHex ?? "").toLowerCase(),
    pathBits: typeof agentProof.pathBits === "bigint" ? agentProof.pathBits : BigInt(agentProof.pathBits)
  };
  if (!verifyAgentProofV4({ root: state.agentRoot, policy, siblingsHex: proof.siblingsHex, pathBits: proof.pathBits })) {
    fail("agentSpend: the agent policy proof does not verify against the live agentRoot — stale tree or forged policy", "AGENT_PROOF_INVALID");
  }

  const pay = parsePositiveSompi(payAmount, "payAmount");
  if (pay > policy.maxPerSpend) {
    fail("agentSpend: payAmount exceeds this agent's maxPerSpend");
  }
  const periods = parseSompi(periodsElapsed ?? 0n, "periodsElapsed");
  if (periods > MAX_PERIODS_ELAPSED) {
    fail(`agentSpend: periodsElapsed out of range [0, ${MAX_PERIODS_ELAPSED}]`);
  }
  let newStart = policy.periodStartDaa;
  let newSpent = policy.periodSpent + pay;
  let lockTime = 0n;
  if (periods >= 1n) {
    newStart = policy.periodStartDaa + periods * policy.periodLengthDaa;
    newSpent = pay;
    lockTime = newStart; // covenant CLTV: tx lockTime must be >= newStart
  }
  if (newSpent > policy.periodBudget) {
    fail("agentSpend: spend exceeds this agent's remaining period budget");
  }

  if (pay >= state.protectedValue) {
    fail("agentSpend: spend would not leave a positive successor protectedValue (covenant requires newProtected > 0)");
  }
  const consumed = parseSompi(reserveConsumed ?? 0n, "reserveConsumed");
  if (consumed > policy.agentMaxFeePerTx) {
    fail("agentSpend: reserveConsumed exceeds this agent's agentMaxFeePerTx", "OVER_AGENT_FEE_CAP");
  }
  if (consumed > state.feeReserve) {
    fail("agentSpend: reserveConsumed exceeds the available fee reserve", "INSUFFICIENT_RESERVE");
  }

  const newPolicy = normalizeAgentPolicyV4({ ...policy, periodStartDaa: newStart, periodSpent: newSpent });
  const newRoot = foldAgentPolicyV4(newPolicy, proof.siblingsHex, proof.pathBits);
  if (newRoot === null) {
    fail("agentSpend: internal — successor-root fold left unconsumed path bits");
  }

  const successor = withChanges(state, {
    protectedValue: state.protectedValue - pay,
    feeReserve: state.feeReserve - consumed,
    agentRoot: newRoot
  });

  const aboveThreshold = pay > policy.approvalThreshold;
  if (aboveThreshold && state.approvalM < 1n) {
    fail(
      "agentSpend: payAmount exceeds this agent's approvalThreshold but the vault has no approver configuration (approvalM 0) — the covenant rejects this spend; the owner must ownerSetApprovers or re-policy the agent first",
      "NO_APPROVER_TIER"
    );
  }

  return Object.freeze({
    successor,
    previousPolicy: policy,
    newPolicy,
    newStart,
    newSpent,
    lockTime,
    aboveThreshold,
    payAmount: pay,
    reserveConsumed: consumed,
    agentProof: Object.freeze({ siblingsHex: proof.siblingsHex, pathBits: proof.pathBits })
  });
}

/* ownerSetAgentRoot: root replaced wholesale; policyNonce += 1. All agent
 * lifecycle (add/remove/rotate/re-policy/per-agent pause) reduces to an
 * SDK tree edit + this root swap. */
function setAgentRootSuccessorV4(state, newAgentRoot) {
  requireContinuingState(state, "setAgentRoot");
  const agentRoot = normalizeHex(newAgentRoot, 32, "newAgentRoot");
  return withChanges(state, { agentRoot, policyNonce: state.policyNonce + 1n });
}

/*
 * ownerSetApprovers: approver slots + approvalM replaced atomically;
 * policyNonce += 1. The new configuration must be a covenant-valid
 * transition target: >= 1 active approver, distinct active keys,
 * 1 <= M <= activeCount (the zero-approver configuration is GENESIS-ONLY
 * — the covenant requires newApprovalM >= 1 on this path).
 */
function setApproversSuccessorV4(state, { approvers, approverSlots, approvalM }) {
  requireContinuingState(state, "setApprovers");
  if (approvers === undefined && approverSlots === undefined) {
    fail("setApprovers requires the new approver set (approvers or approverSlots)");
  }
  if (approvalM === undefined) {
    fail("setApprovers requires approvalM");
  }
  const json = stateToJsonV4(state);
  delete json.approverSlots;
  const successor = normalizeStateV4({
    ...json,
    ...(approvers !== undefined ? { approvers } : {}),
    ...(approverSlots !== undefined ? { approverSlots } : {}),
    approvalM,
    policyNonce: (state.policyNonce + 1n).toString()
  });
  if (successor.activeApproverCount < 1 || successor.approvalM < 1n) {
    fail(
      "the covenant cannot transition to a zero-approver configuration (ownerSetApprovers requires 1 <= approvalM <= activeCount); the zero-approver tier exists only at genesis"
    );
  }
  return successor;
}

/* ownerTopUp: protectedValue increases by exactly the top-up amount. */
function topUpSuccessorV4(state, topUpAmount) {
  requireContinuingState(state, "topUp");
  const amount = parsePositiveSompi(topUpAmount, "topUpAmount");
  return withChanges(state, { protectedValue: state.protectedValue + amount });
}

/* ownerTopUpReserve: feeReserve increases by exactly the top-up amount. */
function topUpReserveSuccessorV4(state, topUpAmount) {
  requireContinuingState(state, "topUpReserve");
  const amount = parsePositiveSompi(topUpAmount, "topUpReserveAmount");
  return withChanges(state, { feeReserve: state.feeReserve + amount });
}

/* ownerPause / ownerUnpause: only `paused` flips. */
function pauseSuccessorV4(state, pause) {
  requireContinuingState(state, pause ? "pause" : "unpause");
  const target = pause ? 1n : 0n;
  if (state.paused === target) {
    fail(`vault is already ${pause ? "paused" : "active"}`);
  }
  return withChanges(state, { paused: target });
}

/*
 * ownerRecover planning (terminal): no successor exists. Returns the
 * exact covenant-required payout facts: output 0 = P2PK(owner) with value
 * exactly protectedValue + feeReserve. Accepts BOTH strict and
 * recovery-mode predecessor parses — recovery is the break-glass path and
 * must remain possible with an empty fee reserve and malformed policy.
 */
function recoverPlanV4(state, ownerXOnly) {
  if (
    !state ||
    typeof state !== "object" ||
    typeof state.protectedValue !== "bigint" ||
    typeof state.feeReserve !== "bigint"
  ) {
    fail("recover: normalized predecessor state is required");
  }
  const owner = normalizeXOnlyPubkey(ownerXOnly, "owner");
  return Object.freeze({
    terminal: true,
    payoutXOnly: owner,
    payoutValue: state.protectedValue + state.feeReserve
  });
}

module.exports = {
  MAX_PERIODS_ELAPSED,
  agentSpendSuccessorV4,
  setAgentRootSuccessorV4,
  setApproversSuccessorV4,
  topUpSuccessorV4,
  topUpReserveSuccessorV4,
  pauseSuccessorV4,
  recoverPlanV4,
  MAX_APPROVERS
};
