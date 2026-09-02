"use strict";

/*
 * Exact live-state model for a PolicyVault v0.5 TOKEN CONTROLLER instance
 * (docs/postlaunch/v0.5-design-freeze.md; contracts/PolicyVault.v0.5.sil).
 * Low-level normalization + exact serialization only — the deterministic
 * core's single source of truth for what a v0.5 instance IS.
 *
 * v0.5 identity = immutable template (owner, vaultId, descriptorHash,
 * tokenCovenantId, templateVmHash, templatePrefixLen/StateLen/SuffixLen)
 * + 5 mutable state fields (boundVaultId = vaultId, feeReserve, paused,
 * agentRoot, policyNonce). The controller UTXO holds ONLY the KAS fee
 * reserve; token value lives in the token UTXO the instance owns via the
 * covenant-id/v1 scheme (see core/assets). All KAS quantities are BigInt
 * sompi; token quantities never appear in this state.
 *
 * Status: IMPLEMENTED + UNIT-TESTED (core/model/test/vault-state-v5.test.js).
 */

const crypto = require("crypto");
const { parseSompi } = require("./amounts");
const { normalizeHex, normalizeXOnlyPubkey } = require("./vault-state");
const { KCC20_STATE_LEN } = require("./token-amounts");

const CONTRACT_VERSION_V5 = "policyvault-0.5";

const V5_ABIS = Object.freeze({
  [CONTRACT_VERSION_V5]: Object.freeze({
    version: CONTRACT_VERSION_V5,
    contractName: "PolicyVaultToken",
    contractRelPath: "contracts/PolicyVault.v0.5.sil",
    buildSubdir: "build-v5",
    consolidatedOwner: true
  })
});

/* ownerControl opSelector (mutually exclusive covenant branches). */
const OWNER_OP_SELECTOR_V5 = Object.freeze({
  ownerSetAgentRoot: 0,
  ownerTopUpReserve: 1,
  ownerPause: 2,
  ownerUnpause: 3
});

function fail(message, code) {
  const e = new Error(`vault-state-v5: ${message}`);
  if (code) e.code = code;
  throw e;
}

function resolveV5Abi(contractVersion) {
  const abi = V5_ABIS[contractVersion];
  if (!abi) {
    fail(`unknown contract version ${JSON.stringify(contractVersion)} for the v0.5 lineage — failing closed (no cross-version fallback)`, "UNKNOWN_VERSION");
  }
  return abi;
}

function normalizeSmallInt(value, field, { min, max }) {
  const n = parseSompi(value, field);
  if (n < min || n > max) {
    fail(`${field} out of range [${min}, ${max}]`);
  }
  return n;
}

function normalizeLen(value, field) {
  if (!Number.isInteger(value) || value < 0 || value > 1_000_000) {
    fail(`${field} must be an integer 0..1000000`);
  }
  return value;
}

/* v0.5 immutable template constants (the instance's pinned bindings). */
function normalizeTemplateV5(input) {
  if (!input || typeof input !== "object") {
    fail("template object is required");
  }
  const stateLen = normalizeLen(input.templateStateLen, "template.templateStateLen");
  if (stateLen !== KCC20_STATE_LEN) {
    fail(`template.templateStateLen must be ${KCC20_STATE_LEN} for kcc20-state/1 — failing closed`);
  }
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

/* v0.5 mutable state (boundVaultId is always the template vaultId). */
function normalizeStateV5(input) {
  if (!input || typeof input !== "object") {
    fail("state object is required");
  }
  return Object.freeze({
    feeReserve: parseSompi(input.feeReserve, "state.feeReserve"),
    paused: normalizeSmallInt(input.paused, "state.paused", { min: 0n, max: 1n }),
    agentRoot: normalizeHex(input.agentRoot, 32, "state.agentRoot"),
    policyNonce: normalizeSmallInt(input.policyNonce, "state.policyNonce", { min: 0n, max: 1_000_000_000n })
  });
}

/* BREAK-GLASS shape-only parse for ownerRecover (quarantined marker). */
function normalizeStateV5ForRecovery(input) {
  if (!input || typeof input !== "object") {
    fail("state object is required");
  }
  return Object.freeze({
    recoveryParse: true,
    feeReserve: parseSompi(input.feeReserve, "state.feeReserve"),
    paused: parseSompi(input.paused, "state.paused"),
    agentRoot: normalizeHex(input.agentRoot, 32, "state.agentRoot"),
    policyNonce: parseSompi(input.policyNonce, "state.policyNonce")
  });
}

function requireNonce(state) {
  if (typeof state.policyNonce !== "bigint") {
    fail("state.policyNonce is required (BigInt) — refusing an implicit default for a consensus-visible value");
  }
  return state.policyNonce;
}

/* Deterministic v0.5 state ID (application identity; never a consensus value). */
function computeStateIdV5({ networkId, template, state, contractVersion }) {
  if (typeof networkId !== "string" || networkId.length === 0) {
    fail("networkId is required for the state ID");
  }
  const abi = resolveV5Abi(contractVersion ?? CONTRACT_VERSION_V5);
  const canonical = [
    "policyvault-state/v5",
    `network:${networkId}`,
    `contract:${abi.version}`,
    `owner:${template.owner}`,
    `vaultId:${template.vaultId}`,
    `descriptorHash:${template.descriptorHash}`,
    `tokenCovenantId:${template.tokenCovenantId}`,
    `templateVmHash:${template.templateVmHash}`,
    `templateGeometry:${template.templatePrefixLen}/${template.templateStateLen}/${template.templateSuffixLen}`,
    `feeReserve:${state.feeReserve}`,
    `paused:${state.paused}`,
    `agentRoot:${state.agentRoot}`,
    `policyNonce:${requireNonce(state)}`
  ].join("\n");
  return crypto.createHash("sha256").update(canonical, "utf8").digest("hex");
}

function stateToJsonV5(state) {
  return {
    feeReserve: state.feeReserve.toString(),
    paused: state.paused.toString(),
    agentRoot: state.agentRoot,
    policyNonce: requireNonce(state).toString()
  };
}

function templateToJsonV5(template) {
  return { ...template };
}

module.exports = {
  CONTRACT_VERSION_V5,
  V5_ABIS,
  OWNER_OP_SELECTOR_V5,
  resolveV5Abi,
  normalizeTemplateV5,
  normalizeStateV5,
  normalizeStateV5ForRecovery,
  computeStateIdV5,
  stateToJsonV5,
  templateToJsonV5
};
