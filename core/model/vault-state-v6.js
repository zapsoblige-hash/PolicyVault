"use strict";
const { ownGet, describeKey } = require("./own-get");

/*
 * Exact live-state model for a PolicyVault v0.6 ATOMIC-COMPOSABILITY TOKEN
 * CONTROLLER instance (docs/postlaunch/v0.6-architecture-freeze.md;
 * contracts/PolicyVault.v0.6.sil — CANDIDATE, not byte-frozen). Low-level
 * normalization + exact serialization only — the deterministic core's
 * single source of truth for what a v0.6 instance IS. Covenant generation
 * v0.6 is unrelated to application release v1.6.0.
 *
 * v0.6 identity = the v0.5 immutable template (owner, vaultId,
 * descriptorHash, tokenCovenantId, templateVmHash, geometry) + 7 mutable
 * state fields (boundVaultId = vaultId, feeReserve, swapPrincipal, paused,
 * agentRoot, swapRoot, policyNonce). The controller UTXO's VALUE is
 * feeReserve + swapPrincipal — TWO KAS domains in one UTXO, never mixed:
 * feeReserve may only become network fee; swapPrincipal is the ONLY BUY
 * consideration source and the type-A SELL proceeds sink. All KAS
 * quantities are BigInt sompi; token quantities never appear here.
 *
 * Status: IMPLEMENTED + UNIT-TESTED (core/model/test/vault-state-v6.test.js).
 */

const crypto = require("crypto");
const { parseSompi } = require("./amounts");
const { normalizeHex, normalizeXOnlyPubkey } = require("./vault-state");
const { KCC20_STATE_LEN } = require("./token-amounts");

const CONTRACT_VERSION_V6 = "policyvault-0.6";

const V6_ABIS = Object.freeze({
  [CONTRACT_VERSION_V6]: Object.freeze({
    version: CONTRACT_VERSION_V6,
    contractName: "PolicyVaultV6",
    contractRelPath: "contracts/PolicyVault.v0.6.sil",
    buildSubdir: "build-v6",
    consolidatedOwner: true,
    /* the covenant's actual freeze status is a separate owner decision; the
     * core never infers it */
    byteFrozen: false
  })
});

/* ownerControl opSelector (mutually exclusive covenant branches). */
const OWNER_OP_SELECTOR_V6 = Object.freeze({
  ownerSetAgentRoot: 0,
  ownerTopUpReserve: 1,
  ownerPause: 2,
  ownerUnpause: 3,
  ownerSetSwapRoot: 4,
  ownerFundSwapPrincipal: 5
});

function fail(message, code) {
  const e = new Error(`vault-state-v6: ${message}`);
  if (code) e.code = code;
  throw e;
}

function resolveV6Abi(contractVersion) {
  const abi = ownGet(V6_ABIS, contractVersion); // own-property only (F-05)
  if (!abi) {
    fail(`unknown contract version ${describeKey(contractVersion)} for the v0.6 lineage — failing closed (no cross-version fallback)`, "UNKNOWN_VERSION");
  }
  return abi;
}

function normalizeSmallInt(value, field, { min, max }) {
  const n = parseSompi(value, field);
  if (n < min || n > max) fail(`${field} out of range [${min}, ${max}]`);
  return n;
}
function normalizeLen(value, field) {
  if (!Number.isInteger(value) || value < 0 || value > 1_000_000) fail(`${field} must be an integer 0..1000000`);
  return value;
}

/* v0.6 immutable template constants (identical layout to v0.5). */
function normalizeTemplateV6(input) {
  if (!input || typeof input !== "object") fail("template object is required");
  const stateLen = normalizeLen(input.templateStateLen, "template.templateStateLen");
  if (stateLen !== KCC20_STATE_LEN) fail(`template.templateStateLen must be ${KCC20_STATE_LEN} for kcc20-state/1 — failing closed`);
  return Object.freeze({
    owner: normalizeXOnlyPubkey(input.owner, "template.owner"),
    vaultId: normalizeHex(input.vaultId, 32, "template.vaultId"),
    descriptorHash: normalizeHex(input.descriptorHash, 32, "template.descriptorHash"),
    tokenCovenantId: normalizeHex(input.tokenCovenantId, 32, "template.tokenCovenantId"),
    templateVmHash: normalizeHex(input.templateVmHash, 32, "template.templateVmHash"),
    templatePrefixLen: normalizeLen(input.templatePrefixLen, "template.templatePrefixLen"),
    templateStateLen: stateLen,
    templateSuffixLen: normalizeLen(input.templateSuffixLen, "template.templateSuffixLen")
  });
}

const STATE_FIELDS_V6 = Object.freeze(["feeReserve", "swapPrincipal", "paused", "agentRoot", "swapRoot", "policyNonce"]);

/* v0.6 mutable state (boundVaultId is always the template vaultId). */
function normalizeStateV6(input) {
  if (!input || typeof input !== "object") fail("state object is required");
  for (const key of Object.keys(input)) {
    if (!STATE_FIELDS_V6.includes(key)) fail(`unknown state field ${JSON.stringify(key)} — closed layout, failing closed`);
  }
  return Object.freeze({
    feeReserve: parseSompi(input.feeReserve, "state.feeReserve"),
    swapPrincipal: parseSompi(input.swapPrincipal, "state.swapPrincipal"),
    paused: normalizeSmallInt(input.paused, "state.paused", { min: 0n, max: 1n }),
    agentRoot: normalizeHex(input.agentRoot, 32, "state.agentRoot"),
    swapRoot: normalizeHex(input.swapRoot, 32, "state.swapRoot"),
    policyNonce: normalizeSmallInt(input.policyNonce, "state.policyNonce", { min: 0n, max: 1_000_000_000n })
  });
}

/* BREAK-GLASS shape-only parse for ownerRecover (quarantined marker). */
function normalizeStateV6ForRecovery(input) {
  if (!input || typeof input !== "object") fail("state object is required");
  return Object.freeze({
    recoveryParse: true,
    feeReserve: parseSompi(input.feeReserve, "state.feeReserve"),
    swapPrincipal: parseSompi(input.swapPrincipal, "state.swapPrincipal"),
    paused: parseSompi(input.paused, "state.paused"),
    agentRoot: normalizeHex(input.agentRoot, 32, "state.agentRoot"),
    swapRoot: normalizeHex(input.swapRoot, 32, "state.swapRoot"),
    policyNonce: parseSompi(input.policyNonce, "state.policyNonce")
  });
}

/* The controller UTXO's exact value (two domains, one UTXO). */
function controllerValueV6(state) {
  if (typeof state.feeReserve !== "bigint" || typeof state.swapPrincipal !== "bigint") fail("state.feeReserve and state.swapPrincipal are required (BigInt)");
  return state.feeReserve + state.swapPrincipal;
}

function requireNonce(state) {
  if (typeof state.policyNonce !== "bigint") fail("state.policyNonce is required (BigInt) — refusing an implicit default for a consensus-visible value");
  return state.policyNonce;
}

/* Deterministic v0.6 state ID (application identity; never a consensus value). */
function computeStateIdV6({ networkId, template, state, contractVersion }) {
  if (typeof networkId !== "string" || networkId.length === 0) fail("networkId is required for the state ID");
  const abi = resolveV6Abi(contractVersion ?? CONTRACT_VERSION_V6);
  const canonical = [
    "policyvault-state/v6",
    `network:${networkId}`,
    `contract:${abi.version}`,
    `owner:${template.owner}`,
    `vaultId:${template.vaultId}`,
    `descriptorHash:${template.descriptorHash}`,
    `tokenCovenantId:${template.tokenCovenantId}`,
    `templateVmHash:${template.templateVmHash}`,
    `templateGeometry:${template.templatePrefixLen}/${template.templateStateLen}/${template.templateSuffixLen}`,
    `feeReserve:${state.feeReserve}`,
    `swapPrincipal:${state.swapPrincipal}`,
    `paused:${state.paused}`,
    `agentRoot:${state.agentRoot}`,
    `swapRoot:${state.swapRoot}`,
    `policyNonce:${requireNonce(state)}`
  ].join("\n");
  return crypto.createHash("sha256").update(canonical, "utf8").digest("hex");
}

function stateToJsonV6(state) {
  return {
    feeReserve: state.feeReserve.toString(),
    swapPrincipal: state.swapPrincipal.toString(),
    paused: state.paused.toString(),
    agentRoot: state.agentRoot,
    swapRoot: state.swapRoot,
    policyNonce: requireNonce(state).toString()
  };
}
function templateToJsonV6(template) {
  return { ...template };
}

module.exports = {
  CONTRACT_VERSION_V6,
  V6_ABIS,
  OWNER_OP_SELECTOR_V6,
  STATE_FIELDS_V6,
  resolveV6Abi,
  normalizeTemplateV6,
  normalizeStateV6,
  normalizeStateV6ForRecovery,
  controllerValueV6,
  computeStateIdV6,
  stateToJsonV6,
  templateToJsonV6
};
