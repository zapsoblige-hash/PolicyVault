"use strict";

/*
 * Centralized v0.5 token-controller compute-budget selection.
 *
 * The committed budget is CONSENSUS-CRITICAL for usability: an
 * under-committed budget makes an otherwise-valid transaction fail script
 * execution on a live node. Unlike v0.4, the v0.5 controller's cost SCALES
 * WITH THE ACCEPTED TOKEN TEMPLATE (it hashes the token input's revealed
 * redeem, P2SH-verifies it, and reconstructs two continuation outputs from
 * the template bytes), so the tier is a measured LINEAR MODEL in the
 * template size rather than a flat ceiling.
 *
 * Measured on the PRODUCTION PolicyVault.v0.5.sil under production sig-op
 * pricing (tests/vm/tests/v5_production.rs v5_measurement_units_mass_standardness,
 * 2026-09-01; units INCLUDE the 100,000-unit Schnorr sig-op):
 *
 *   tokenAgentSpend, template suffix 1,521 B, depths 0/0:   199,252 -> 19
 *   tokenAgentSpend, template suffix 1,521 B, depths 12/16: 250,513 -> 25
 *   tokenAgentSpend, template suffix 2,737 B, depths 0/0:   228,436 -> 22
 *   tokenAgentSpend, template suffix 5,169 B, depths 0/0:   286,804 -> 28
 *   ownerControl (pause):                                   156,683 -> 15
 *   ownerRecover (with position, suffix 1,521 B):           142,898 -> 14
 *
 * Slope ~24 units per template byte (bounds 2->8: 87,552 units over
 * 3,648 B). Model = base + 24 x (templateBytes - 1,522) + depth allowance
 * (51,261 measured at 12/16) + 20,000 headroom, in 10,000-unit budget
 * units, ceiling-rounded. Callers may NEVER lower the committed budget
 * below the model value; the production-byte suite executes SDK-built
 * shapes with the SDK's own committed budget and asserts sufficiency.
 */

const UNITS_PER_BUDGET = 10_000;
const SIGOP_UNITS = 100_000;
const SLOPE_PER_TEMPLATE_BYTE = 24;
const REFERENCE_TEMPLATE_BYTES = 1_522; // prefix 1 + suffix 1,521 (bound 2)
const DEPTH_ALLOWANCE = 51_261; // agent depth 12 + recipient depth 16, measured
const HEADROOM = 20_000;
const SPEND_BASE = 199_252; // bound 2, depths 0/0, incl. sig-op
const RECOVER_BASE = 142_898; // bound 2, with position, incl. sig-op

const V5_BUDGET = Object.freeze({
  OWNER_OP: 20, // measured 15 (+5 headroom); ownerControl never reads the template
  ORDINARY_INPUT: 10
});

function fail(message) {
  throw new Error(`compute-budget-v5: ${message}`);
}

function templateBytes({ templatePrefixLen, templateSuffixLen }) {
  if (!Number.isInteger(templatePrefixLen) || !Number.isInteger(templateSuffixLen) || templatePrefixLen < 0 || templateSuffixLen < 0) {
    fail("template geometry (templatePrefixLen/templateSuffixLen) is required to size a template-scaled budget");
  }
  return templatePrefixLen + templateSuffixLen;
}

function ceilBudget(units) {
  return Math.ceil(units / UNITS_PER_BUDGET);
}

function selectComputeBudgetV5({ operation, templatePrefixLen, templateSuffixLen }) {
  switch (operation) {
    case "tokenAgentSpend": {
      const extra = Math.max(0, templateBytes({ templatePrefixLen, templateSuffixLen }) - REFERENCE_TEMPLATE_BYTES) * SLOPE_PER_TEMPLATE_BYTE;
      return ceilBudget(SPEND_BASE + extra + DEPTH_ALLOWANCE + HEADROOM);
    }
    case "ownerSetAgentRoot":
    case "ownerTopUpReserve":
    case "ownerPause":
    case "ownerUnpause":
      return V5_BUDGET.OWNER_OP;
    case "ownerRecover": {
      const extra = Math.max(0, templateBytes({ templatePrefixLen, templateSuffixLen }) - REFERENCE_TEMPLATE_BYTES) * SLOPE_PER_TEMPLATE_BYTE;
      return ceilBudget(RECOVER_BASE + extra + HEADROOM);
    }
    default:
      fail(`unknown v0.5 operation ${JSON.stringify(operation)} — failing closed`);
  }
}

/*
 * Committed budget for a TOKEN-FAMILY input executing the reference KCC20
 * program (measured 18,709 units at bound 2 with a covenant-id owner —
 * no sig-op; a p2pk-owned input adds one Schnorr checkSig = 100,000
 * units). Template-scaled with headroom.
 */
function selectTokenInputBudgetV5({ templatePrefixLen, templateSuffixLen, signerOwned = false }) {
  const base = 20_000 + SLOPE_PER_TEMPLATE_BYTE * templateBytes({ templatePrefixLen, templateSuffixLen });
  return Math.max(4, ceilBudget(base + (signerOwned ? SIGOP_UNITS : 0)));
}

function assertBudgetSufficientV5({ operation, templatePrefixLen, templateSuffixLen, committed }) {
  const required = selectComputeBudgetV5({ operation, templatePrefixLen, templateSuffixLen });
  if (!Number.isInteger(committed) || committed < required) {
    fail(`committed compute budget ${committed} is below the proven-safe minimum ${required} for ${operation}`);
  }
  return committed;
}

module.exports = { V5_BUDGET, UNITS_PER_BUDGET, SIGOP_UNITS, selectComputeBudgetV5, selectTokenInputBudgetV5, assertBudgetSufficientV5 };
