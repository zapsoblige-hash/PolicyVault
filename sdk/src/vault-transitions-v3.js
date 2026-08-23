"use strict";

/*
 * Canonical v0.3 state-transition derivation (Phase 4H §5).
 *
 * One canonical successor builder per non-terminal production entrypoint.
 * Callers NEVER supply successor state — every builder derives the single
 * covenant-permitted successor from the normalized predecessor, changes
 * ONLY the fields that entrypoint authorizes, preserves everything else
 * (including period accounting on every owner/governance operation), and
 * applies the exact production policyNonce rule:
 *
 *   nonce PRESERVED: delegateSpend, rolloverAndSpend, ownerPause,
 *                    ownerUnpause, revokeDelegate, rotateDelegate,
 *                    ownerTopUp
 *   nonce +1:        migratePolicy, ownerSetRecipientRoot,
 *                    ownerSetApprovers
 *
 * Every successor is re-normalized through the STRICT v0.3 normalizer
 * (exact slot layout preserved via approverSlots) so an ill-formed
 * successor can never leave this module. Recovery-mode predecessor parses
 * (normalizeStateV3ForRecovery) are rejected by every function here —
 * they exist only for ownerRecover construction.
 *
 * Production covenant fact (PolicyVault.v0.3.sil ownerSetApprovers):
 * a transition can never REMOVE the last active approver — the covenant
 * requires 1 <= newApprovalM <= newActiveCount, so newActiveCount >= 1.
 * The zero-approver "no approval tier" configuration is GENESIS-ONLY.
 * setApproversSuccessorV3 therefore fails closed on an empty new set.
 */

const { parseSompi, parsePositiveSompi } = require("./amounts");
const { normalizeXOnlyPubkey, normalizeHex } = require("./vault-state");
const { normalizeStateV3, stateToJsonV3, MAX_APPROVERS } = require("./vault-state-v3");

function fail(message) {
  throw new Error(`vault-transitions-v3: ${message}`);
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

function requireActive(state, label) {
  if (state.paused !== 0n) {
    fail(`${label}: vault is paused`);
  }
  if (state.delegateActive !== 1n) {
    fail(`${label}: delegate is revoked`);
  }
}

/*
 * Re-normalize a derived successor through the strict normalizer with the
 * EXACT slot layout preserved. This asserts the successor is a well-formed
 * continuing state (A2 distinctness, M validity, no-approval-tier rule,
 * budget >= cap, nonce domain) — a canonical builder can never emit a
 * state the strict normalizer rejects.
 */
function normalizeSuccessor(successor) {
  const json = stateToJsonV3(successor);
  return normalizeStateV3(json);
}

function withChanges(state, changes) {
  return normalizeSuccessor(Object.freeze({ ...state, ...changes }));
}

/* delegateSpend: principal -pay, periodSpent +pay; everything else exact. */
function spendSuccessorV3(state, payAmount) {
  requireContinuingState(state, "spend");
  requireActive(state, "spend");
  const pay = parsePositiveSompi(payAmount, "payAmount");
  if (pay > state.maxPerSpend) {
    fail("spend exceeds maxPerSpend");
  }
  if (state.periodSpent + pay > state.periodBudget) {
    fail("spend exceeds the remaining period budget");
  }
  if (pay >= state.protectedValue) {
    fail("spend would not leave a positive successor value");
  }
  return withChanges(state, {
    protectedValue: state.protectedValue - pay,
    periodSpent: state.periodSpent + pay
  });
}

/* rolloverAndSpend: periodStartDaa += periods*len, periodSpent = pay. */
function rolloverSuccessorV3(state, payAmount, periodsElapsed) {
  requireContinuingState(state, "rollover");
  requireActive(state, "rollover");
  const pay = parsePositiveSompi(payAmount, "payAmount");
  const periods = parseSompi(periodsElapsed, "periodsElapsed");
  if (periods < 1n || periods > 1000n) {
    fail("periodsElapsed out of range [1, 1000]");
  }
  if (pay > state.maxPerSpend) {
    fail("rollover spend exceeds maxPerSpend");
  }
  if (pay > state.periodBudget) {
    fail("rollover spend exceeds the period budget");
  }
  if (pay >= state.protectedValue) {
    fail("spend would not leave a positive successor value");
  }
  return withChanges(state, {
    protectedValue: state.protectedValue - pay,
    periodStartDaa: state.periodStartDaa + periods * state.periodLengthDaa,
    periodSpent: pay
  });
}

/* ownerPause / ownerUnpause: only `paused` flips; accounting preserved. */
function pauseSuccessorV3(state, pause) {
  requireContinuingState(state, pause ? "pause" : "unpause");
  const target = pause ? 1n : 0n;
  if (state.paused === target) {
    fail(`vault is already ${pause ? "paused" : "active"}`);
  }
  return withChanges(state, { paused: target });
}

/* revokeDelegate: delegateActive 1 -> 0; delegate identity preserved. */
function revokeSuccessorV3(state) {
  requireContinuingState(state, "revoke");
  if (state.delegateActive !== 1n) {
    fail("delegate is already revoked");
  }
  return withChanges(state, { delegateActive: 0n });
}

/* rotateDelegate: delegate = new key, delegateActive = 1. */
function rotateSuccessorV3(state, newDelegate) {
  requireContinuingState(state, "rotate");
  const delegate = normalizeXOnlyPubkey(newDelegate, "newDelegate");
  return withChanges(state, { delegate, delegateActive: 1n });
}

/* ownerTopUp: protectedValue increases by exactly the top-up amount. */
function topUpSuccessorV3(state, topUpAmount) {
  requireContinuingState(state, "topUp");
  const amount = parsePositiveSompi(topUpAmount, "topUpAmount");
  return withChanges(state, { protectedValue: state.protectedValue + amount });
}

/*
 * migratePolicy: may change maxPerSpend / periodBudget / periodLengthDaa
 * (all must stay positive); policyNonce += 1; recipientRoot, approvers,
 * delegate, accounting all preserved (v0.3 recipients move ONLY through
 * ownerSetRecipientRoot, unlike v0.2's migrate).
 */
function migrateSuccessorV3(state, newPolicy) {
  requireContinuingState(state, "migrate");
  if (!newPolicy || typeof newPolicy !== "object") {
    fail("migrate requires a newPolicy object");
  }
  const allowed = new Set(["maxPerSpend", "periodBudget", "periodLengthDaa"]);
  for (const key of Object.keys(newPolicy)) {
    if (!allowed.has(key)) {
      fail(`migratePolicy cannot change ${key} — only maxPerSpend/periodBudget/periodLengthDaa`);
    }
  }
  return withChanges(state, {
    maxPerSpend: newPolicy.maxPerSpend !== undefined ? parsePositiveSompi(newPolicy.maxPerSpend, "newPolicy.maxPerSpend") : state.maxPerSpend,
    periodBudget: newPolicy.periodBudget !== undefined ? parsePositiveSompi(newPolicy.periodBudget, "newPolicy.periodBudget") : state.periodBudget,
    periodLengthDaa:
      newPolicy.periodLengthDaa !== undefined ? parsePositiveSompi(newPolicy.periodLengthDaa, "newPolicy.periodLengthDaa") : state.periodLengthDaa,
    policyNonce: state.policyNonce + 1n
  });
}

/* ownerSetRecipientRoot: root replaced; policyNonce += 1. */
function setRecipientRootSuccessorV3(state, newRecipientRoot) {
  requireContinuingState(state, "setRecipientRoot");
  const recipientRoot = normalizeHex(newRecipientRoot, 32, "newRecipientRoot");
  return withChanges(state, { recipientRoot, policyNonce: state.policyNonce + 1n });
}

/*
 * ownerSetApprovers: approver slots + approvalM + approvalThresholdAmount
 * replaced atomically; policyNonce += 1. The new configuration must be a
 * covenant-valid transition target: >= 1 active approver, distinct active
 * keys, 1 <= M <= activeCount, threshold >= 0.
 */
function setApproversSuccessorV3(state, { approvers, approverSlots, approvalM, approvalThresholdAmount }) {
  requireContinuingState(state, "setApprovers");
  if (approvers === undefined && approverSlots === undefined) {
    fail("setApprovers requires the new approver set (approvers or approverSlots)");
  }
  const json = stateToJsonV3(state);
  const successor = normalizeStateV3({
    ...json,
    approverSlots: undefined,
    approvers,
    ...(approverSlots !== undefined ? { approverSlots } : {}),
    approvalM: approvalM ?? fail("setApprovers requires approvalM"),
    approvalThresholdAmount: approvalThresholdAmount ?? fail("setApprovers requires approvalThresholdAmount"),
    policyNonce: (state.policyNonce + 1n).toString()
  });
  if (successor.activeApproverCount < 1 || successor.approvalM < 1n) {
    fail(
      "the covenant cannot transition to a zero-approver configuration (ownerSetApprovers requires 1 <= approvalM <= activeCount); " +
        "the zero-approver tier exists only at genesis"
    );
  }
  return successor;
}

/*
 * ownerRecover planning (terminal): no successor exists. Returns the exact
 * covenant-required payout facts. Accepts BOTH strict and recovery-mode
 * predecessor parses — recovery is the break-glass path.
 */
function recoverPlanV3(state, ownerXOnly) {
  if (!state || typeof state !== "object" || typeof state.protectedValue !== "bigint") {
    fail("recover: normalized predecessor state is required");
  }
  const owner = normalizeXOnlyPubkey(ownerXOnly, "owner");
  return Object.freeze({
    terminal: true,
    payoutXOnly: owner,
    payoutValue: state.protectedValue
  });
}

module.exports = {
  spendSuccessorV3,
  rolloverSuccessorV3,
  pauseSuccessorV3,
  revokeSuccessorV3,
  rotateSuccessorV3,
  topUpSuccessorV3,
  migrateSuccessorV3,
  setRecipientRootSuccessorV3,
  setApproversSuccessorV3,
  recoverPlanV3,
  MAX_APPROVERS
};
