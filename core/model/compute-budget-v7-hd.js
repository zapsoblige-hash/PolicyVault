"use strict";

/*
 * Compute-budget selection for contracts/PolicyVault.v0.7-payment-hd.sil
 * (contract `PolicyVaultRootedTokenHD`).
 *
 * Every constant below is an ENGINE MEASUREMENT from
 * tests/vm/tests/v7_hd_production.rs (`hd_rooted_measurement_redeem_units_
 * mass_sigops_and_stack`, 2026-09-03), run under PRODUCTION sig-op pricing
 * (Gram(1000) = 100,000 priced units per executed checkSig — every HD
 * entrypoint here has exactly ONE, so the reported units are ALREADY fully
 * priced; nothing here re-adds a per-sig-op charge on top):
 *
 *   operation                          shallow units   deep units    budget (shallow/deep)
 *   hdSpend            (level 1)            404,202     (not measured)      41 / --
 *   childSpendL2        (level 2)            412,177     (not measured)      42 / --
 *   childSpendL3        (level 3)            419,602        546,575          42 / 55
 *   delegateSetChildRoot1                    362,987     (not measured)      37 / --
 *   delegateSetChildRoot2                    367,989        410,141          37 / 42
 *
 * "shallow" = agent depth 1, child depth 1, recipient depth 0 per level;
 * "deep" = agent depth 12, child depth 8 per level, recipient depth 16 per
 * level (the covenant's maximum proof depths). The owner's rooted paths
 * (ownerControl / ownerRecover) are BYTE-IDENTICAL to v0.7-payment and use
 * core/model/compute-budget-v7.js UNCHANGED — this module covers ONLY the
 * five new HD entrypoints.
 *
 * ENGINEERING ESTIMATE, NOT AN INDEPENDENT MEASUREMENT (documented
 * limitation): a full per-depth sweep exists only for childSpendL3 and
 * delegateSetChildRoot2 (the deepest spend and the deepest delegation op).
 * hdSpend / childSpendL2 / delegateSetChildRoot1 were measured shallow only.
 * This module conservatively applies the LARGEST measured shallow->deep
 * delta within each family (spend: childSpendL3's +126,973; delegation:
 * delegateSetChildRoot2's +42,152) to every operation in that family
 * regardless of its own level, which is SOUND (a shorter chain has fewer
 * proof components than the one actually measured, so its true delta is
 * <= the applied one) but NOT as tight as a dedicated sweep would be.
 * Tighten with real per-level deep measurements before treating the
 * per-level numbers as anything more than a safe upper bound.
 *
 * Status: IMPLEMENTED + UNIT-TESTED (core/model/test/compute-budget-v7-hd.test.js).
 * Sufficiency for the SHALLOW and DEEP shapes actually measured is PROVEN by
 * `with_covering_budgets` in the VM suite (script units do not depend on the
 * committed budget); the interpolated MID-DEPTH points and the three
 * not-independently-deep-measured operations are the estimate above, not a
 * proof — this file is DESIGNED + UNIT-TESTED, not yet independently
 * VM-VERIFIED across the full depth range.
 */

const { selectComputeBudgetV7 } = require("./compute-budget-v7");

const HEADROOM = 20_000;
const UNITS_PER_BUDGET = 10_000;

const SHALLOW_UNITS = Object.freeze({
  hdSpend: 404_202,
  childSpendL2: 412_177,
  childSpendL3: 419_602,
  delegateSetChildRoot1: 362_987,
  delegateSetChildRoot2: 367_989
});

/* measured shallow -> deep deltas, applied conservatively (see header) */
const SPEND_DEPTH_ALLOWANCE = 546_575 - 419_602; // 126,973 (childSpendL3 shallow -> deep)
const DELEGATION_DEPTH_ALLOWANCE = 410_141 - 367_989; // 42,152 (delegateSetChildRoot2 shallow -> deep)

const SPEND_OPS = Object.freeze(["hdSpend", "childSpendL2", "childSpendL3"]);
const DELEGATION_OPS = Object.freeze(["delegateSetChildRoot1", "delegateSetChildRoot2"]);

function fail(message, code) {
  const e = new Error(`compute-budget-v7-hd: ${message}`);
  if (code) e.code = code;
  throw e;
}

function ceilBudget(units) {
  const n = Math.ceil(units / UNITS_PER_BUDGET);
  if (!Number.isInteger(n) || n < 1 || n > 65_535) fail(`computed compute budget ${n} is outside the u16 domain`);
  return n;
}

/*
 * `atMaxDepth`: true selects the DEEP allowance (agent depth 12 / child
 * depth 8 per level / recipient depth 16 per level — the covenant maximum);
 * false selects the shallow measured base with NO depth allowance, which is
 * ONLY sufficient for genuinely shallow proofs (depth 0/0/0-ish) — callers
 * that do not know their exact proof depth in advance MUST pass true.
 */
function selectHdComputeBudgetV7({ operation, atMaxDepth = true }) {
  if (SHALLOW_UNITS[operation] === undefined) {
    fail(`unknown v0.7-hd operation ${JSON.stringify(operation)} — failing closed`, "UNKNOWN_OPERATION");
  }
  const base = SHALLOW_UNITS[operation];
  const allowance = atMaxDepth ? (SPEND_OPS.includes(operation) ? SPEND_DEPTH_ALLOWANCE : DELEGATION_DEPTH_ALLOWANCE) : 0;
  return ceilBudget(base + allowance + HEADROOM);
}

function assertHdBudgetSufficientV7({ operation, atMaxDepth = true, committed }) {
  const required = selectHdComputeBudgetV7({ operation, atMaxDepth });
  if (!Number.isInteger(committed) || committed < required) {
    fail(`committed compute budget ${committed} is below the proven-safe minimum ${required} for ${operation} (atMaxDepth=${atMaxDepth})`);
  }
  return committed;
}

/*
 * OWNER-CONTROL / OWNER-RECOVER on the rooted HD vault (Wave 2 Track D,
 * gate I2 SDK integration, tests/vm/tests/v7_hd_sdk_integration.rs,
 * 2026-09-03) — a MEASURED CORRECTION, not the readiness record's original
 * assumption.
 *
 * docs/postlaunch/v0.7-hd-readiness.md originally stated that ownerControl/
 * ownerRecover are "BYTE-IDENTICAL to v0.7-payment and use
 * core/model/compute-budget-v7.js UNCHANGED". That is true of the COVENANT
 * BYTES (the owner-op branches genuinely are byte-identical in substance),
 * but it is NOT true of the sufficient COMPUTE BUDGET: compute-budget-v7.js's
 * owner-control/-recover base unit counts were calibrated against the much
 * SMALLER v0.7-payment redeem script (~9,636 B). The v0.7-payment-hd redeem
 * is ~42,830 B (+33,194 B, five extra HD entrypoints), and script
 * interpretation cost scales with total script size even for a branch whose
 * OWN logic is unchanged — so reusing compute-budget-v7.js's owner-op budget
 * for the HD vault silently UNDER-COMMITS. Found the hard way: driving
 * gen-v7-hd-vectors.js's owner-op vectors through the real engine measured
 *   ownerControl (selectors 0-4, HD script): 498,705 - 498,778 units
 *     (compute-budget-v7.js alone selects budget 32 = 320,000 raw — SHORT by
 *     ~179,000 units, i.e. 18 committed budget units short)
 *   ownerRecover (HD script, with a token position):        350,765 units
 *     (compute-budget-v7.js alone selects budget 31 = 310,000 raw — SHORT by
 *     ~41,000 units, i.e. 5 committed budget units short)
 * measured under the SAME template/root geometry
 * sdk/tools/gen-v7-hd-vectors.js uses (token template 1+1521 B, root
 * template 1+11,077 B). This function ADDS a flat, generously-margined
 * budget-unit delta on top of compute-budget-v7.js's own (already
 * template-size-scaled) result, so it remains SOUND if the vault's own
 * token/root template sizes vary, while being tight enough to be a real
 * measurement-derived correction rather than a guess.
 *
 * Status: IMPLEMENTED, MEASURED on one geometry (not yet swept across
 * template-size extremes the way core/model/compute-budget-v7.js's root
 * model was) — sufficiency for THIS geometry is PROVEN by
 * tests/vm/tests/v7_hd_sdk_integration.rs; treat as a safe floor, not a
 * tight bound, until a dedicated sweep exists.
 */
const OWNER_CONTROL_EXTRA_BUDGET_UNITS_HD = 25; // covers the measured ~18-unit shortfall with margin
const OWNER_RECOVER_EXTRA_BUDGET_UNITS_HD = 15; // covers the measured ~5-unit shortfall with margin
const HD_OWNER_CONTROL_OPS = Object.freeze(["ownerSetAgentRoot", "ownerTopUpReserve", "ownerPause", "ownerUnpause", "ownerEmergencyPause"]);

function selectHdOwnerComputeBudgetV7({ operation, templatePrefixLen, templateSuffixLen, rootPrefixLen, rootSuffixLen }) {
  if (!HD_OWNER_CONTROL_OPS.includes(operation) && operation !== "ownerRecover") {
    fail(`unknown v0.7-payment-hd owner operation ${JSON.stringify(operation)} — failing closed`, "UNKNOWN_OPERATION");
  }
  const base = selectComputeBudgetV7({ operation, templatePrefixLen, templateSuffixLen, rootPrefixLen, rootSuffixLen });
  return base + (operation === "ownerRecover" ? OWNER_RECOVER_EXTRA_BUDGET_UNITS_HD : OWNER_CONTROL_EXTRA_BUDGET_UNITS_HD);
}

module.exports = {
  HEADROOM,
  UNITS_PER_BUDGET,
  SHALLOW_UNITS,
  SPEND_DEPTH_ALLOWANCE,
  DELEGATION_DEPTH_ALLOWANCE,
  SPEND_OPS,
  DELEGATION_OPS,
  selectHdComputeBudgetV7,
  assertHdBudgetSufficientV7,
  OWNER_CONTROL_EXTRA_BUDGET_UNITS_HD,
  OWNER_RECOVER_EXTRA_BUDGET_UNITS_HD,
  HD_OWNER_CONTROL_OPS,
  selectHdOwnerComputeBudgetV7
};
