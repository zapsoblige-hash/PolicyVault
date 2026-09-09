"use strict";
const { ownGet, describeKey } = require("./own-get");

/*
 * Exact live-state model for a PolicyVault v0.7 ROOTED PAYMENT VAULT
 * (docs/postlaunch/v0.7-organizational-root-design.md §3, §9.2;
 * contracts/PolicyVault.v0.7-payment.sil, contract `PolicyVaultRootedToken`,
 * derived from the FROZEN v0.5 controller by a deterministic delta).
 *
 * The MUTABLE STATE is byte-for-byte the frozen v0.5 state — feeReserve,
 * paused, agentRoot, policyNonce, with boundVaultId pinned to the template's
 * vaultId — so this module deliberately reuses the v0.5 normalizers rather
 * than restating them. What changes is the TEMPLATE:
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
 * The owner AUTHORITY is therefore an INPUT, not a key: an owner operation
 * is valid only when the same transaction also spends the pinned root, whose
 * own covenant proved M-of-N (or the lighter emergency quorum for FREEZE).
 * `rootStateLen` is checked against the measured constant (467 B) and the
 * geometry is checked for self-consistency, because a wrong pin would make
 * the vault slice the wrong bytes and self-lock.
 *
 * Status: IMPLEMENTED + UNIT-TESTED (core/model/test/vault-state-v7.test.js).
 */

const crypto = require("crypto");
const { normalizeHex, normalizeXOnlyPubkey } = require("./vault-state");
const { KCC20_STATE_LEN } = require("./token-amounts");
const { normalizeStateV5, normalizeStateV5ForRecovery, stateToJsonV5 } = require("./vault-state-v5");
const { ROOT_STATE_LEN_V7, ROOT_TAIL_LEN_V7 } = require("./vault-state-v7-root");

const CONTRACT_VERSION_V7 = "policyvault-0.7-payment";

const V7_ABIS = Object.freeze({
  [CONTRACT_VERSION_V7]: Object.freeze({
    version: CONTRACT_VERSION_V7,
    contractName: "PolicyVaultRootedToken",
    contractRelPath: "contracts/PolicyVault.v0.7-payment.sil",
    buildSubdir: "build-v7-payment",
    rootAuthorized: true
  })
});

/*
 * ownerControl opSelector. Selectors 0..3 are the frozen v0.5 owner branches
 * and require the root to run AUTHORIZE (full quorum); selector 4 is the
 * EMERGENCY pause and is the ONLY vault effect reachable from the root's
 * lighter emergency quorum, so it requires the root to run FREEZE.
 * `expectFrozenAfter` is the byte the covenant pins in the root's successor
 * TAIL for that selector.
 */
const OWNER_OP_SELECTOR_V7 = Object.freeze({
  ownerSetAgentRoot: 0,
  ownerTopUpReserve: 1,
  ownerPause: 2,
  ownerUnpause: 3,
  ownerEmergencyPause: 4
});

const OWNER_OP_ROOT_AUTHORITY_V7 = Object.freeze({
  ownerSetAgentRoot: Object.freeze({ opSelector: 0, rootActionName: "authorize", expectFrozenAfter: 0n }),
  ownerTopUpReserve: Object.freeze({ opSelector: 1, rootActionName: "authorize", expectFrozenAfter: 0n }),
  ownerPause: Object.freeze({ opSelector: 2, rootActionName: "authorize", expectFrozenAfter: 0n }),
  ownerUnpause: Object.freeze({ opSelector: 3, rootActionName: "authorize", expectFrozenAfter: 0n }),
  ownerEmergencyPause: Object.freeze({ opSelector: 4, rootActionName: "freeze", expectFrozenAfter: 1n }),
  ownerRecover: Object.freeze({ opSelector: null, rootActionName: "authorize", expectFrozenAfter: 0n })
});

function fail(message, code) {
  const e = new Error(`vault-state-v7: ${message}`);
  if (code) e.code = code;
  throw e;
}

function resolveV7Abi(contractVersion) {
  const abi = ownGet(V7_ABIS, contractVersion); // own-property only (F-05)
  if (!abi) {
    fail(`unknown contract version ${describeKey(contractVersion)} for the v0.7 rooted-vault lineage — failing closed (no cross-version fallback)`, "UNKNOWN_VERSION");
  }
  return abi;
}

function resolveOwnerOpAuthorityV7(action) {
  const info = ownGet(OWNER_OP_ROOT_AUTHORITY_V7, action); // own-property only (F-05)
  if (!info) fail(`unknown v0.7 rooted-vault owner action ${describeKey(action)} — failing closed`, "UNKNOWN_ACTION");
  return info;
}

function normalizeLen(value, field) {
  if (!Number.isInteger(value) || value < 0 || value > 1_000_000) fail(`${field} must be an integer 0..1000000`);
  return value;
}

/*
 * v0.7 immutable template constants — the token pins the frozen v0.5 already
 * had, plus the organizational-root pins and the cold recovery destination.
 */
function normalizeTemplateV7(input) {
  if (!input || typeof input !== "object") fail("template object is required");
  const stateLen = normalizeLen(input.templateStateLen, "template.templateStateLen");
  if (stateLen !== KCC20_STATE_LEN) fail(`template.templateStateLen must be ${KCC20_STATE_LEN} for kcc20-state/1 — failing closed`);

  const rootStateLen = normalizeLen(input.rootStateLen, "template.rootStateLen");
  if (rootStateLen !== ROOT_STATE_LEN_V7) {
    fail(`template.rootStateLen must be ${ROOT_STATE_LEN_V7} for the v0.7 root state layout (measured, §12.3) — a wrong pin would slice the wrong bytes and self-lock the vault; failing closed`, "ROOT_GEOMETRY_MISMATCH");
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
    descriptorHash: normalizeHex(input.descriptorHash, 32, "template.descriptorHash"),
    tokenCovenantId: normalizeHex(input.tokenCovenantId, 32, "template.tokenCovenantId"),
    templateVmHash: normalizeHex(input.templateVmHash, 32, "template.templateVmHash"),
    templatePrefixLen: normalizeLen(input.templatePrefixLen, "template.templatePrefixLen"),
    templateStateLen: stateLen,
    templateSuffixLen: normalizeLen(input.templateSuffixLen, "template.templateSuffixLen"),
    orgRootCovenantId,
    rootTemplateVmHash: normalizeHex(input.rootTemplateVmHash, 32, "template.rootTemplateVmHash"),
    rootPrefixLen,
    rootStateLen,
    rootSuffixLen,
    recoveryPk: normalizeXOnlyPubkey(input.recoveryPk, "template.recoveryPk")
  });
}

/* The mutable state is the frozen v0.5 state, verbatim. */
function normalizeStateV7(input) {
  return normalizeStateV5(input);
}
function normalizeStateV7ForRecovery(input) {
  return normalizeStateV5ForRecovery(input);
}
function stateToJsonV7(state) {
  return stateToJsonV5(state);
}

function requireNonce(state) {
  if (typeof state.policyNonce !== "bigint") {
    fail("state.policyNonce is required (BigInt) — refusing an implicit default for a consensus-visible value");
  }
  return state.policyNonce;
}

/* Deterministic v0.7 rooted-vault state ID (application identity only). */
function computeStateIdV7({ networkId, template, state, contractVersion }) {
  if (typeof networkId !== "string" || networkId.length === 0) fail("networkId is required for the state ID");
  const abi = resolveV7Abi(contractVersion ?? CONTRACT_VERSION_V7);
  const t = template && t2Frozen(template) ? template : normalizeTemplateV7(template);
  const canonical = [
    "policyvault-state/v7",
    `network:${networkId}`,
    `contract:${abi.version}`,
    `vaultId:${t.vaultId}`,
    `descriptorHash:${t.descriptorHash}`,
    `tokenCovenantId:${t.tokenCovenantId}`,
    `templateVmHash:${t.templateVmHash}`,
    `templateGeometry:${t.templatePrefixLen}/${t.templateStateLen}/${t.templateSuffixLen}`,
    `orgRootCovenantId:${t.orgRootCovenantId}`,
    `rootTemplateVmHash:${t.rootTemplateVmHash}`,
    `rootGeometry:${t.rootPrefixLen}/${t.rootStateLen}/${t.rootSuffixLen}`,
    `recoveryPk:${t.recoveryPk}`,
    `feeReserve:${state.feeReserve}`,
    `paused:${state.paused}`,
    `agentRoot:${state.agentRoot}`,
    `policyNonce:${requireNonce(state)}`
  ].join("\n");
  return crypto.createHash("sha256").update(canonical, "utf8").digest("hex");
}

/* A already-normalized template is frozen and carries every v0.7 pin. */
function t2Frozen(t) {
  return Object.isFrozen(t) && typeof t.orgRootCovenantId === "string" && typeof t.recoveryPk === "string" && typeof t.rootStateLen === "number";
}

function templateToJsonV7(template) {
  return { ...normalizeTemplateV7(template) };
}

module.exports = {
  CONTRACT_VERSION_V7,
  V7_ABIS,
  OWNER_OP_SELECTOR_V7,
  OWNER_OP_ROOT_AUTHORITY_V7,
  ROOT_STATE_LEN_V7,
  ROOT_TAIL_LEN_V7,
  resolveV7Abi,
  resolveOwnerOpAuthorityV7,
  normalizeTemplateV7,
  normalizeStateV7,
  normalizeStateV7ForRecovery,
  computeStateIdV7,
  stateToJsonV7,
  templateToJsonV7
};
