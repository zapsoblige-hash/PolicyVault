"use strict";

/*
 * Centralized v0.3 covenant compute-budget selection (Phase 4H §14).
 *
 * The committed budget is CONSENSUS-CRITICAL for usability: an
 * under-committed budget makes an otherwise-valid transaction fail script
 * execution on a live node. The values below are PROVEN-SAFE tiers backed
 * by direct measurement of the PRODUCTION covenant under production
 * sig-op pricing (Gram(1000) = 100,000 script units per checkSig;
 * tests/vm/tests/v3_encoder_integration.rs enc3_measure_* and the Phase
 * 4H SDK-shape proofs in v3_sdk_integration.rs):
 *
 *   delegate spend, depth 0,  no approvals:   282,320 units -> budget 29
 *   delegate spend, depth 16, no approvals:   305,505 units -> budget 31
 *   approved spend, 2-of-3 (depth 8):         609,529 units -> budget 61
 *   approved spend, 10-of-10 (depth 8):     1,334,175 units -> budget 134
 *   WORST: depth 16 + 10-of-10:             1,349,839 units -> budget 135
 *   owner op (incl. setApprovers):          ~231k-286k     -> budget 29
 *   ownerRecover (terminal):                  157,203 units -> budget 16
 *
 * Tier policy (documented conservative proven-safe, §14): commit the tier
 * ceiling rather than a per-shape estimate. This is FEE-NEUTRAL for every
 * v0.3 shape because v0.3 fees are transient-mass-dominated (the ~28 KB
 * redeem script sets the fee; compute mass at budget 135 is 13,500 grams,
 * far below the ~60k normalized transient mass — asserted by tests), and
 * it removes all under-commit risk from shape-estimation drift.
 *
 * Callers may NEVER lower the committed budget below the tier value.
 */

const V3_BUDGET = Object.freeze({
  /* Any spend at or below approvalThresholdAmount, any Merkle depth 0..16
   * (proven ceiling: depth 16 = 305,505 units -> 31). */
  SPEND_DELEGATE_ONLY: 31,
  /* Any spend above approvalThresholdAmount, any depth, any approver
   * configuration up to 10-of-10 (proven ceiling: depth16 + 10-of-10 =
   * 1,349,839 units -> 135). */
  SPEND_WITH_APPROVALS: 135,
  /* Every owner state transition (pause/unpause/revoke/rotate/topUp/
   * migrate/setRecipientRoot/setApprovers). */
  OWNER_OP: 29,
  /* Terminal ownerRecover. */
  RECOVER: 16,
  /* Ordinary (non-covenant) fee/fuel inputs. */
  ORDINARY_INPUT: 10
});

function fail(message) {
  throw new Error(`compute-budget-v3: ${message}`);
}

/*
 * Select the committed covenant-input compute budget for a v0.3 operation.
 *   operation: one of the 11 production entrypoint names or "createVault".
 *   aboveThreshold: REQUIRED for spend operations (payAmount >
 *   approvalThresholdAmount on the PREDECESSOR state).
 * Unknown operations fail closed.
 */
function selectComputeBudgetV3({ operation, aboveThreshold }) {
  switch (operation) {
    case "delegateSpend":
    case "rolloverAndSpend":
      if (typeof aboveThreshold !== "boolean") {
        fail(`${operation} budget selection requires aboveThreshold (boolean)`);
      }
      return aboveThreshold ? V3_BUDGET.SPEND_WITH_APPROVALS : V3_BUDGET.SPEND_DELEGATE_ONLY;
    case "ownerPause":
    case "ownerUnpause":
    case "revokeDelegate":
    case "rotateDelegate":
    case "ownerTopUp":
    case "migratePolicy":
    case "ownerSetRecipientRoot":
    case "ownerSetApprovers":
      return V3_BUDGET.OWNER_OP;
    case "ownerRecover":
      return V3_BUDGET.RECOVER;
    default:
      fail(`unknown v0.3 operation ${JSON.stringify(operation)} — failing closed`);
  }
}

/* Reject any attempt to commit less than the proven tier value. */
function assertBudgetSufficient({ operation, aboveThreshold, committed }) {
  const required = selectComputeBudgetV3({ operation, aboveThreshold });
  if (!Number.isInteger(committed) || committed < required) {
    fail(`committed compute budget ${committed} is below the proven-safe minimum ${required} for ${operation}`);
  }
  return committed;
}

module.exports = { V3_BUDGET, selectComputeBudgetV3, assertBudgetSufficient };
