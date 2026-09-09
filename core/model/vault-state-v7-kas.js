"use strict";
const { ownGet, describeKey } = require("./own-get");

/*
 * Exact live-state model for a PolicyVault v0.7 ROOTED KAS SAFE-PAYMENT
 * VAULT (contracts/PolicyVault.v0.7-kas.sil, contract `PolicyVaultRootedKas`,
 * derived from the FROZEN v0.4.1 KAS covenant by a deterministic delta,
 * tools/gen_v7_kas.js). Same byte-level root-successor pinning as
 * core/model/vault-state-v7.js (the payment profile); this module is its
 * v0.4.1-flavored sibling.
 *
 * The MUTABLE STATE is byte-for-byte the frozen v0.4.1 state — protectedValue,
 * feeReserve, paused, agentRoot, approver1..10, approvalM, policyNonce, with
 * boundVaultId pinned to the template's vaultId — so this module deliberately
 * REUSES the v0.4 normalizers (core/model/vault-state-v4.js) rather than
 * restating them; there is no token position and no descriptor, so this
 * profile carries none of the v0.5-derived asset-descriptor machinery the
 * payment profile's template does. What changes vs plain v0.4.1 is the
 * TEMPLATE:
 *
 *   REMOVED  pubkey owner           — a rooted vault has NO owner key at all
 *   ADDED    orgRootCovenantId      — the organizational root that authorizes
 *            rootTemplateVmHash       every owner operation, pinned by its
 *            rootPrefixLen            covenant id AND its exact template
 *            rootStateLen             identity + geometry, so the vault can
 *            rootSuffixLen            tell WHICH root path ran
 *            recoveryPk             — the COLD recovery destination, fixed at
 *                                     genesis so a hijacked quorum-signing
 *                                     session can never redirect recovery
 *
 * The owner AUTHORITY is therefore an INPUT, not a key: an owner operation is
 * valid only when the same transaction also spends the pinned root, whose own
 * covenant proved M-of-N (or the lighter emergency quorum for FREEZE).
 * ownerControl merges v0.4.1's six selectors (0..5) with a new EMERGENCY
 * pause (selector 6, the ONLY vault effect reachable from the lighter
 * emergency quorum).
 *
 * Status: IMPLEMENTED + UNIT-TESTED (core/model/test/vault-state-v7-kas.test.js).
 */

const crypto = require("crypto");
const { normalizeHex, normalizeXOnlyPubkey } = require("./vault-state");
const { normalizeStateV4, normalizeStateV4ForRecovery, stateToJsonV4, MAX_APPROVERS } = require("./vault-state-v4");
const { ROOT_STATE_LEN_V7, ROOT_TAIL_LEN_V7 } = require("./vault-state-v7-root");

const CONTRACT_VERSION_V7_KAS = "policyvault-0.7-kas";

const V7_KAS_ABIS = Object.freeze({
  [CONTRACT_VERSION_V7_KAS]: Object.freeze({
    version: CONTRACT_VERSION_V7_KAS,
    contractName: "PolicyVaultRootedKas",
    contractRelPath: "contracts/PolicyVault.v0.7-kas.sil",
    buildSubdir: "build-v7-kas",
    rootAuthorized: true
  })
});

/*
 * ownerControl opSelector. Selectors 0..5 are the frozen v0.4.1 owner
 * branches and require the root to run AUTHORIZE (full quorum); selector 6
 * is the new EMERGENCY pause and is the ONLY vault effect reachable from the
 * root's lighter emergency quorum, so it requires the root to run FREEZE.
 */
const OWNER_OP_SELECTOR_V7_KAS = Object.freeze({
  ownerSetAgentRoot: 0,
  ownerSetApprovers: 1,
  ownerTopUp: 2,
  ownerTopUpReserve: 3,
  ownerPause: 4,
  ownerUnpause: 5,
  ownerEmergencyPause: 6
});

const OWNER_OP_ROOT_AUTHORITY_V7_KAS = Object.freeze({
  ownerSetAgentRoot: Object.freeze({ opSelector: 0, rootActionName: "authorize", expectFrozenAfter: 0n }),
  ownerSetApprovers: Object.freeze({ opSelector: 1, rootActionName: "authorize", expectFrozenAfter: 0n }),
  ownerTopUp: Object.freeze({ opSelector: 2, rootActionName: "authorize", expectFrozenAfter: 0n }),
  ownerTopUpReserve: Object.freeze({ opSelector: 3, rootActionName: "authorize", expectFrozenAfter: 0n }),
  ownerPause: Object.freeze({ opSelector: 4, rootActionName: "authorize", expectFrozenAfter: 0n }),
  ownerUnpause: Object.freeze({ opSelector: 5, rootActionName: "authorize", expectFrozenAfter: 0n }),
  ownerEmergencyPause: Object.freeze({ opSelector: 6, rootActionName: "freeze", expectFrozenAfter: 1n }),
  ownerRecover: Object.freeze({ opSelector: null, rootActionName: "authorize", expectFrozenAfter: 0n })
});

function fail(message, code) {
  const e = new Error(`vault-state-v7-kas: ${message}`);
  if (code) e.code = code;
  throw e;
}

function resolveV7KasAbi(contractVersion) {
  const abi = ownGet(V7_KAS_ABIS, contractVersion); // own-property only (F-05)
  if (!abi) {
    fail(`unknown contract version ${describeKey(contractVersion)} for the v0.7-kas rooted-vault lineage — failing closed (no cross-version fallback)`, "UNKNOWN_VERSION");
  }
  return abi;
}

function resolveOwnerOpAuthorityV7Kas(action) {
  const info = ownGet(OWNER_OP_ROOT_AUTHORITY_V7_KAS, action); // own-property only (F-05)
  if (!info) fail(`unknown v0.7-kas rooted-vault owner action ${describeKey(action)} — failing closed`, "UNKNOWN_ACTION");
  return info;
}

function normalizeLen(value, field) {
  if (!Number.isInteger(value) || value < 0 || value > 1_000_000) fail(`${field} must be an integer 0..1000000`);
  return value;
}

/*
 * v0.7-kas immutable template constants: vaultId (unchanged from v0.4.1) plus
 * the organizational-root pins and the cold recovery destination. There is
 * NO descriptor/token/template-vm-hash triple — this profile is plain KAS.
 */
function normalizeTemplateV7Kas(input) {
  if (!input || typeof input !== "object") fail("template object is required");

  const rootStateLen = normalizeLen(input.rootStateLen, "template.rootStateLen");
  if (rootStateLen !== ROOT_STATE_LEN_V7) {
    fail(`template.rootStateLen must be ${ROOT_STATE_LEN_V7} for the v0.7 root state layout — a wrong pin would slice the wrong bytes and self-lock the vault; failing closed`, "ROOT_GEOMETRY_MISMATCH");
  }
  if (rootStateLen <= ROOT_TAIL_LEN_V7) fail("template.rootStateLen must exceed the fixed-width TAIL", "ROOT_GEOMETRY_MISMATCH");
  const rootPrefixLen = normalizeLen(input.rootPrefixLen, "template.rootPrefixLen");
  const rootSuffixLen = normalizeLen(input.rootSuffixLen, "template.rootSuffixLen");
  if (rootPrefixLen < 1 || rootSuffixLen < 1) fail("template.rootPrefixLen/rootSuffixLen must be >= 1", "ROOT_GEOMETRY_MISMATCH");

  const orgRootCovenantId = normalizeHex(input.orgRootCovenantId, 32, "template.orgRootCovenantId");
  if (orgRootCovenantId === "00".repeat(32)) {
    fail("template.orgRootCovenantId must not be the sentinel zero — a rooted vault with no root has no owner authority at all", "ROOT_PIN_MISSING");
  }

  return Object.freeze({
    vaultId: normalizeHex(input.vaultId, 32, "template.vaultId"),
    orgRootCovenantId,
    rootTemplateVmHash: normalizeHex(input.rootTemplateVmHash, 32, "template.rootTemplateVmHash"),
    rootPrefixLen,
    rootStateLen,
    rootSuffixLen,
    recoveryPk: normalizeXOnlyPubkey(input.recoveryPk, "template.recoveryPk")
  });
}

/* The mutable state is the frozen v0.4.1 state, verbatim. */
function normalizeStateV7Kas(input) {
  return normalizeStateV4(input);
}
function normalizeStateV7KasForRecovery(input) {
  return normalizeStateV4ForRecovery(input);
}
function stateToJsonV7Kas(state) {
  return stateToJsonV4(state);
}

function requireNonce(state) {
  if (typeof state.policyNonce !== "bigint") {
    fail("state.policyNonce is required (BigInt) — refusing an implicit default for a consensus-visible value");
  }
  return state.policyNonce;
}

function t2Frozen(t) {
  return Object.isFrozen(t) && typeof t.orgRootCovenantId === "string" && typeof t.recoveryPk === "string" && typeof t.rootStateLen === "number";
}

/* Deterministic v0.7-kas rooted-vault state ID (application identity only). */
function computeStateIdV7Kas({ networkId, template, state, contractVersion }) {
  if (typeof networkId !== "string" || networkId.length === 0) fail("networkId is required for the state ID");
  const abi = resolveV7KasAbi(contractVersion ?? CONTRACT_VERSION_V7_KAS);
  const t = template && t2Frozen(template) ? template : normalizeTemplateV7Kas(template);
  const canonical = [
    "policyvault-state/v7-kas",
    `network:${networkId}`,
    `contract:${abi.version}`,
    `vaultId:${t.vaultId}`,
    `orgRootCovenantId:${t.orgRootCovenantId}`,
    `rootTemplateVmHash:${t.rootTemplateVmHash}`,
    `rootGeometry:${t.rootPrefixLen}/${t.rootStateLen}/${t.rootSuffixLen}`,
    `recoveryPk:${t.recoveryPk}`,
    `protectedValue:${state.protectedValue}`,
    `feeReserve:${state.feeReserve}`,
    `paused:${state.paused}`,
    `agentRoot:${state.agentRoot}`,
    `approvers:${state.approvers.join(",")}`,
    `approvalM:${state.approvalM}`,
    `policyNonce:${requireNonce(state)}`
  ].join("\n");
  return crypto.createHash("sha256").update(canonical, "utf8").digest("hex");
}

function templateToJsonV7Kas(template) {
  return { ...normalizeTemplateV7Kas(template) };
}

module.exports = {
  CONTRACT_VERSION_V7_KAS,
  V7_KAS_ABIS,
  MAX_APPROVERS,
  OWNER_OP_SELECTOR_V7_KAS,
  OWNER_OP_ROOT_AUTHORITY_V7_KAS,
  ROOT_STATE_LEN_V7,
  ROOT_TAIL_LEN_V7,
  resolveV7KasAbi,
  resolveOwnerOpAuthorityV7Kas,
  normalizeTemplateV7Kas,
  normalizeStateV7Kas,
  normalizeStateV7KasForRecovery,
  computeStateIdV7Kas,
  stateToJsonV7Kas,
  templateToJsonV7Kas
};
