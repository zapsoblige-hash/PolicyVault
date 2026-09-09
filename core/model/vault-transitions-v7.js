"use strict";

/*
 * v0.7 ROOTED PAYMENT VAULT transition planner
 * (contracts/PolicyVault.v0.7-payment.sil, derived from the FROZEN v0.5).
 *
 * The vault's STATE MATH is the frozen v0.5 math, so this module DELEGATES to
 * core/model/vault-transitions-v5.js rather than restating rules that are
 * already VM-proven and byte-frozen. What v0.7 adds is the AUTHORITY:
 *
 *   - there is no owner key and no owner signature; an owner operation is
 *     valid only when the same transaction ALSO spends the pinned
 *     organizational root, and the vault pins that root's EXACT successor
 *     bytes so it can tell WHICH root path ran;
 *   - `ownerControl` and the phase-1 `emergencyPause` are MERGED behind one
 *     entrypoint with selectors 0..4 — selectors 0-3 pin an AUTHORIZE root
 *     successor (full quorum), selector 4 pins a FREEZE one (the lighter
 *     emergency quorum), so the emergency quorum can reach NOTHING but the
 *     AUTHORITY-REDUCING pause;
 *   - `ownerRecover` pays the fee reserve and the whole token position to the
 *     GENESIS-PINNED cold destination `recoveryPk` — never to an address a
 *     quorum-signing session can choose;
 *   - the DELEGATE path (`tokenAgentSpend`) never touches the root at all and
 *     is byte-for-byte the frozen v0.5 logic.
 *
 * Every plan therefore carries `rootAuthority` — the root action the
 * transaction MUST also run, and the frozen byte the vault will pin — so a
 * builder can never assemble a vault operation without the matching root
 * path, and a manifest can state the required organizational authority.
 *
 * Status: IMPLEMENTED + UNIT-TESTED (core/model/test/vault-transitions-v7.test.js).
 */

const { parseSompi, parsePositiveSompi } = require("./amounts");
const { normalizeHex, normalizeXOnlyPubkey } = require("./vault-state");
const { normalizeStateV7, resolveOwnerOpAuthorityV7, OWNER_OP_SELECTOR_V7 } = require("./vault-state-v7");
const {
  tokenAgentSpendSuccessorV5,
  tokenContinuationStatesV5,
  setAgentRootSuccessorV5,
  topUpReserveSuccessorV5,
  pauseSuccessorV5,
  MAX_PERIODS_ELAPSED
} = require("./vault-transitions-v5");
const { parseAtomicAmount, OWNER_SCHEMES } = require("./token-amounts");

function fail(message, code) {
  const e = new Error(`vault-transitions-v7: ${message}`);
  if (code) e.code = code;
  throw e;
}

function authority(action) {
  const info = resolveOwnerOpAuthorityV7(action);
  return Object.freeze({
    action,
    opSelector: info.opSelector,
    rootActionName: info.rootActionName,
    expectFrozenAfter: info.expectFrozenAfter,
    quorum: info.rootActionName === "freeze" ? "emergencyK" : "ownerM"
  });
}

/* DELEGATE spend — the frozen v0.5 rules verbatim; NO root input exists. */
function tokenAgentSpendSuccessorV7(state, params) {
  const plan = tokenAgentSpendSuccessorV5(state, params);
  return Object.freeze({ ...plan, rootAuthority: null, requiresRootInput: false });
}

/* The two token continuation states the covenant template-verifies. */
function tokenContinuationStatesV7(args) {
  return tokenContinuationStatesV5(args);
}

function setAgentRootSuccessorV7(state, newAgentRoot) {
  const base = setAgentRootSuccessorV5(state, newAgentRoot);
  return Object.freeze({ successor: base.successor, opSelector: OWNER_OP_SELECTOR_V7.ownerSetAgentRoot, rootAuthority: authority("ownerSetAgentRoot"), requiresRootInput: true });
}

function topUpReserveSuccessorV7(state, topUpAmount) {
  const base = topUpReserveSuccessorV5(state, topUpAmount);
  return Object.freeze({ successor: base.successor, topUpAmount: base.topUpAmount, opSelector: OWNER_OP_SELECTOR_V7.ownerTopUpReserve, rootAuthority: authority("ownerTopUpReserve"), requiresRootInput: true });
}

function pauseSuccessorV7(state, pause) {
  const base = pauseSuccessorV5(state, pause);
  const action = pause ? "ownerPause" : "ownerUnpause";
  return Object.freeze({ successor: base.successor, opSelector: pause ? OWNER_OP_SELECTOR_V7.ownerPause : OWNER_OP_SELECTOR_V7.ownerUnpause, rootAuthority: authority(action), requiresRootInput: true });
}

/*
 * EMERGENCY pause (selector 4): the identical state effect to selector 2 but
 * a strictly LIGHTER root authority (the root runs FREEZE under emergencyK).
 * AUTHORITY-REDUCING and monotone — paused 0 -> 1, every other field
 * preserved, policyNonce included, no value movement. Unpausing is selector 3
 * and needs the FULL quorum.
 */
function emergencyPauseSuccessorV7(state) {
  const base = pauseSuccessorV5(state, true);
  return Object.freeze({ successor: base.successor, opSelector: OWNER_OP_SELECTOR_V7.ownerEmergencyPause, rootAuthority: authority("ownerEmergencyPause"), requiresRootInput: true });
}

/*
 * ownerRecover (TERMINAL): the reserve pays out to the GENESIS-PINNED
 * recoveryPk and, if a token position exists, its ENTIRE amount moves to
 * recoveryPk under the p2pk owner scheme. The destination is a template
 * constant, so it is NOT a parameter of the signing session.
 */
function recoverPlanV7(state, template, tokenPositionAmount) {
  if (!state || typeof state !== "object") fail("recover: state is required");
  if (!template || typeof template !== "object") fail("recover: the vault template is required (recoveryPk is pinned at genesis)");
  const recoveryPk = normalizeXOnlyPubkey(template.recoveryPk, "template.recoveryPk");
  const payout = parseSompi(state.feeReserve, "state.feeReserve");
  let tokenRecipient = null;
  if (tokenPositionAmount !== null && tokenPositionAmount !== undefined) {
    const amount = parseAtomicAmount(tokenPositionAmount, "tokenPositionAmount");
    tokenRecipient = Object.freeze({ ownerIdentifier: recoveryPk, identifierType: OWNER_SCHEMES.P2PK, amount, isMinter: false });
  }
  return Object.freeze({
    terminal: true,
    payout,
    payoutTo: recoveryPk,
    tokenRecipient,
    opSelector: null,
    rootAuthority: authority("ownerRecover"),
    requiresRootInput: true
  });
}

/* Dispatch by SDK action; unknown actions fail closed. */
function ownerOpSuccessorV7(action, state, params = {}) {
  const s = normalizeStateV7(state);
  switch (action) {
    case "ownerSetAgentRoot": {
      if (params.newAgentRoot === undefined) fail("ownerSetAgentRoot requires params.newAgentRoot");
      return { ...setAgentRootSuccessorV7(s, normalizeHex(params.newAgentRoot, 32, "params.newAgentRoot")), externalFunding: 0n };
    }
    case "ownerTopUpReserve": {
      const amount = parsePositiveSompi(params.topUpReserveAmountSompi, "topUpReserveAmountSompi");
      return { ...topUpReserveSuccessorV7(s, amount), externalFunding: amount };
    }
    case "ownerPause":
      return { ...pauseSuccessorV7(s, true), externalFunding: 0n };
    case "ownerUnpause":
      return { ...pauseSuccessorV7(s, false), externalFunding: 0n };
    case "ownerEmergencyPause":
      return { ...emergencyPauseSuccessorV7(s), externalFunding: 0n };
    default:
      return fail(`unknown v0.7 rooted-vault owner action ${JSON.stringify(action)} — failing closed`, "UNKNOWN_ACTION");
  }
}

module.exports = {
  MAX_PERIODS_ELAPSED,
  tokenAgentSpendSuccessorV7,
  tokenContinuationStatesV7,
  setAgentRootSuccessorV7,
  topUpReserveSuccessorV7,
  pauseSuccessorV7,
  emergencyPauseSuccessorV7,
  recoverPlanV7,
  ownerOpSuccessorV7
};
