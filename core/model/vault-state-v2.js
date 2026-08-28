"use strict";

/*
 * Exact live-state model for a PolicyVault v0.2 vault.
 *
 * v0.2 identity = immutable template constants (owner, vaultId) + mutable
 * state (14 fields, including the delegate and all policy limits) +
 * contract version + network. Owner-guarded fields move only through the
 * owner lifecycle paths; every successor is validated field-by-field by
 * the covenant.
 */

const crypto = require("crypto");
const { parseSompi, parsePositiveSompi } = require("./amounts");
const { normalizeHex, normalizeXOnlyPubkey } = require("./vault-state");

const CONTRACT_VERSION_V2 = "policyvault-0.2";

function fail(message) {
  throw new Error(`vault-state-v2: ${message}`);
}

function normalizeDaa(value, field) {
  const daa = parseSompi(value, field);
  if (daa >= 500_000_000_000n) {
    fail(`${field} must be below the DAA lock-time threshold`);
  }
  return daa;
}

function normalizeSmallInt(value, field, { min, max }) {
  const n = parseSompi(value, field);
  if (n < min || n > max) {
    fail(`${field} out of range [${min}, ${max}]`);
  }
  return n;
}

/* v0.2 immutable template constants. */
function normalizeTemplateV2(input) {
  if (!input || typeof input !== "object") {
    fail("template object is required");
  }
  return Object.freeze({
    owner: normalizeXOnlyPubkey(input.owner, "template.owner"),
    vaultId: normalizeHex(input.vaultId, 32, "template.vaultId")
  });
}

/*
 * v0.2 mutable state (all 14 covenant state fields except boundVaultId,
 * which is pinned by the template's vaultId).
 */
function normalizeStateV2(input) {
  if (!input || typeof input !== "object") {
    fail("state object is required");
  }
  const recipientsIn = input.recipients;
  if (!Array.isArray(recipientsIn) || recipientsIn.length < 1 || recipientsIn.length > 3) {
    fail("state.recipients must contain 1 to 3 recipients");
  }
  const recipients = recipientsIn.map((r, i) => normalizeXOnlyPubkey(r, `state.recipients[${i}]`));
  const padded = [recipients[0], recipients[1] ?? recipients[0], recipients[2] ?? recipients[1] ?? recipients[0]];

  const maxPerSpend = parsePositiveSompi(input.maxPerSpend, "state.maxPerSpend");
  const periodBudget = parsePositiveSompi(input.periodBudget, "state.periodBudget");
  if (periodBudget < maxPerSpend) {
    fail("state.periodBudget must be >= state.maxPerSpend");
  }

  return Object.freeze({
    protectedValue: parsePositiveSompi(input.protectedValue, "state.protectedValue"),
    periodStartDaa: normalizeDaa(input.periodStartDaa, "state.periodStartDaa"),
    periodSpent: parseSompi(input.periodSpent, "state.periodSpent"),
    paused: normalizeSmallInt(input.paused, "state.paused", { min: 0n, max: 1n }),
    delegate: normalizeXOnlyPubkey(input.delegate, "state.delegate"),
    maxPerSpend,
    periodBudget,
    periodLengthDaa: normalizeSmallInt(input.periodLengthDaa, "state.periodLengthDaa", { min: 1n, max: 500_000_000_000n }),
    recipients: Object.freeze(padded),
    delegateActive: normalizeSmallInt(input.delegateActive, "state.delegateActive", { min: 0n, max: 1n }),
    policyNonce: normalizeSmallInt(input.policyNonce, "state.policyNonce", { min: 0n, max: 1_000_000_000n })
  });
}

/* Deterministic v0.2 state ID (application identity, versioned encoding). */
function computeStateIdV2({ networkId, template, state }) {
  if (typeof networkId !== "string" || networkId.length === 0) {
    fail("networkId is required for the state ID");
  }
  const canonical = [
    "policyvault-state/v2",
    `network:${networkId}`,
    `contract:${CONTRACT_VERSION_V2}`,
    `owner:${template.owner}`,
    `vaultId:${template.vaultId}`,
    `protectedValue:${state.protectedValue}`,
    `periodStartDaa:${state.periodStartDaa}`,
    `periodSpent:${state.periodSpent}`,
    `paused:${state.paused}`,
    `delegate:${state.delegate}`,
    `maxPerSpend:${state.maxPerSpend}`,
    `periodBudget:${state.periodBudget}`,
    `periodLengthDaa:${state.periodLengthDaa}`,
    `recipients:${state.recipients.join(",")}`,
    `delegateActive:${state.delegateActive}`,
    `policyNonce:${state.policyNonce}`
  ].join("\n");
  return crypto.createHash("sha256").update(canonical, "utf8").digest("hex");
}

/* ------------------------------------------------- exact successor states */

function requireActive(state, label) {
  if (state.paused !== 0n) {
    fail(`${label}: vault is paused`);
  }
  if (state.delegateActive !== 1n) {
    fail(`${label}: delegate is revoked`);
  }
}

function spendSuccessorV2(state, payAmount) {
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
  return Object.freeze({ ...state, protectedValue: state.protectedValue - pay, periodSpent: state.periodSpent + pay });
}

function rolloverSuccessorV2(state, payAmount, periodsElapsed) {
  requireActive(state, "rollover");
  const pay = parsePositiveSompi(payAmount, "payAmount");
  const periods = normalizeSmallInt(periodsElapsed, "periodsElapsed", { min: 1n, max: 1000n });
  if (pay > state.maxPerSpend || pay > state.periodBudget) {
    fail("rollover spend exceeds the cap or budget");
  }
  if (pay >= state.protectedValue) {
    fail("spend would not leave a positive successor value");
  }
  return Object.freeze({
    ...state,
    protectedValue: state.protectedValue - pay,
    periodStartDaa: state.periodStartDaa + periods * state.periodLengthDaa,
    periodSpent: pay
  });
}

function pauseSuccessorV2(state, pause) {
  const target = pause ? 1n : 0n;
  if (state.paused === target) {
    fail(`vault is already ${pause ? "paused" : "active"}`);
  }
  return Object.freeze({ ...state, paused: target });
}

function revokeSuccessorV2(state) {
  if (state.delegateActive !== 1n) {
    fail("delegate is already revoked");
  }
  return Object.freeze({ ...state, delegateActive: 0n });
}

function rotateSuccessorV2(state, newDelegate) {
  const delegate = normalizeXOnlyPubkey(newDelegate, "newDelegate");
  return Object.freeze({ ...state, delegate, delegateActive: 1n });
}

function topUpSuccessorV2(state, topUpAmount) {
  const amount = parsePositiveSompi(topUpAmount, "topUpAmount");
  return Object.freeze({ ...state, protectedValue: state.protectedValue + amount });
}

/*
 * Policy migration: newPolicy may change maxPerSpend, periodBudget,
 * periodLengthDaa, recipients. Everything else is preserved and the nonce
 * increments by exactly 1 (covenant-enforced).
 */
function migrateSuccessorV2(state, newPolicy) {
  const merged = normalizeStateV2({
    ...stateToJson(state),
    maxPerSpend: newPolicy.maxPerSpend ?? state.maxPerSpend,
    periodBudget: newPolicy.periodBudget ?? state.periodBudget,
    periodLengthDaa: newPolicy.periodLengthDaa ?? state.periodLengthDaa,
    recipients: newPolicy.recipients ?? state.recipients,
    policyNonce: state.policyNonce + 1n
  });
  return merged;
}

/* JSON-safe encoding (BigInt -> digit strings) for manifests/receipts. */
function stateToJson(state) {
  return {
    protectedValue: state.protectedValue.toString(),
    periodStartDaa: state.periodStartDaa.toString(),
    periodSpent: state.periodSpent.toString(),
    paused: state.paused.toString(),
    delegate: state.delegate,
    maxPerSpend: state.maxPerSpend.toString(),
    periodBudget: state.periodBudget.toString(),
    periodLengthDaa: state.periodLengthDaa.toString(),
    recipients: [...state.recipients],
    delegateActive: state.delegateActive.toString(),
    policyNonce: state.policyNonce.toString()
  };
}

module.exports = {
  CONTRACT_VERSION_V2,
  normalizeTemplateV2,
  normalizeStateV2,
  computeStateIdV2,
  spendSuccessorV2,
  rolloverSuccessorV2,
  pauseSuccessorV2,
  revokeSuccessorV2,
  rotateSuccessorV2,
  topUpSuccessorV2,
  migrateSuccessorV2,
  stateToJson
};
