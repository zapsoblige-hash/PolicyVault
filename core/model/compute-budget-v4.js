"use strict";

/*
 * Centralized v0.4 covenant compute-budget selection (Checkpoint E §E5).
 *
 * The committed budget is CONSENSUS-CRITICAL for usability: an
 * under-committed budget makes an otherwise-valid transaction fail script
 * execution on a live node. The values below are PROVEN-SAFE tiers backed
 * by direct measurement of the PRODUCTION v0.4 covenant under production
 * sig-op pricing (Gram(1000) = 100,000 script units per checkSig;
 * tests/vm/tests/v4_production.rs v4p_measure_production_budgets,
 * re-verified at Checkpoint D, and the Checkpoint-E SDK-shape proofs in
 * v4_sdk_integration.rs):
 *
 *   agent spend, agent depth 0,  recip depth 0,  below threshold:
 *                                              222,758 units -> budget 23
 *   agent spend, agent depth 12, recip depth 0, below threshold:
 *                                              251,768 units -> budget 26
 *   agent spend, agent depth 0,  recip depth 16, below threshold:
 *                                              245,943 units -> budget 25
 *   WORST: agent depth 12 + recip depth 16 + 10-of-10 + reserve:
 *                                            1,318,131 units -> budget 132
 *   ownerSetAgentRoot:                         219,115 units -> budget 22
 *   ownerRecover (terminal):                   137,927 units -> budget 14
 *
 * Tier policy (same documented conservative proven-safe scheme as v0.3):
 * commit the tier CEILING rather than a per-shape estimate, with explicit
 * headroom above the measured points for the shape dimensions the
 * measurements did not enumerate (combined agent+recipient depth below
 * threshold; extra external fee inputs/outputs adding txFee() loop
 * iterations; ownerSetApprovers' 45-pair distinctness block, which the
 * owner-op measurement above does not include). This is FEE-NEUTRAL for
 * every v0.4 shape because v0.4 fees are transient-mass-dominated: the
 * ~19-21 KB redeem script sets the fee (normalized transient ~40k grams),
 * while compute mass even at budget 134 is 13,400 grams — asserted by the
 * fee golden vectors. Over-commit costs nothing; under-commit strands a
 * valid transaction. The production-byte integration suite executes every
 * SDK-built accept vector under PRODUCTION pricing with the SDK's OWN
 * committed budget and asserts sufficiency per exact shape.
 *
 * Callers may NEVER lower the committed budget below the tier value.
 */

const V4_BUDGET = Object.freeze({
  /* Any agent spend at or below the leaf's approvalThreshold, any agent
   * depth 0..12, any recipient depth 0..16 (measured single-dimension
   * ceilings 23/26/25; combined-depth additive bound ~28; headroom to 32,
   * VM-asserted at agent depth 12 + recipient depth 16). */
  SPEND_NO_APPROVALS: 32,
  /* Any agent spend above the leaf's approvalThreshold, any depths, any
   * approver configuration up to 10-of-10 (measured worst 1,318,131 units
   * -> 132 for the 1-input/2-output shape; +2 headroom for external
   * fee-input/change txFee() iterations). */
  SPEND_WITH_APPROVALS: 134,
  /* Every owner state transition (setAgentRoot/setApprovers/topUp/
   * topUpReserve/pause/unpause). setAgentRoot measured 22; setApprovers
   * adds the 45-pair distinctness + active-count block (v0.3's analogous
   * op measured ~286k -> 29 on a LARGER script); 30 covers it,
   * VM-asserted per shape. */
  OWNER_OP: 30,
  /* Terminal ownerRecover (measured 137,927 -> 14; +1 headroom). */
  RECOVER: 15,
  /* Ordinary (non-covenant) fee/fuel inputs. */
  ORDINARY_INPUT: 10
});

function fail(message) {
  throw new Error(`compute-budget-v4: ${message}`);
}

/*
 * Select the committed covenant-input compute budget for a v0.4 operation.
 *   operation: one of the 8 production entrypoint names.
 *   aboveThreshold: REQUIRED for agentSpend (payAmount > the spending
 *   agent LEAF's approvalThreshold).
 * Unknown operations fail closed.
 */
function selectComputeBudgetV4({ operation, aboveThreshold }) {
  switch (operation) {
    case "agentSpend":
      if (typeof aboveThreshold !== "boolean") {
        fail("agentSpend budget selection requires aboveThreshold (boolean)");
      }
      return aboveThreshold ? V4_BUDGET.SPEND_WITH_APPROVALS : V4_BUDGET.SPEND_NO_APPROVALS;
    case "ownerSetAgentRoot":
    case "ownerSetApprovers":
    case "ownerTopUp":
    case "ownerTopUpReserve":
    case "ownerPause":
    case "ownerUnpause":
      return V4_BUDGET.OWNER_OP;
    case "ownerRecover":
      return V4_BUDGET.RECOVER;
    default:
      fail(`unknown v0.4 operation ${JSON.stringify(operation)} — failing closed`);
  }
}

/* Reject any attempt to commit less than the proven tier value. */
function assertBudgetSufficientV4({ operation, aboveThreshold, committed }) {
  const required = selectComputeBudgetV4({ operation, aboveThreshold });
  if (!Number.isInteger(committed) || committed < required) {
    fail(`committed compute budget ${committed} is below the proven-safe minimum ${required} for ${operation}`);
  }
  return committed;
}

module.exports = { V4_BUDGET, selectComputeBudgetV4, assertBudgetSufficientV4 };
