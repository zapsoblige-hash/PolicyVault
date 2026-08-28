"use strict";

/*
 * PolicyVault v0.3 approval-package MODEL CORE (Phase 4H §7–§10) — the
 * PURE members of sdk/src/approval-package-v3.js, split out in shared-core
 * extraction step 3. Member bodies are verbatim from the pre-split sdk
 * implementation.
 *
 * Here live the canonical commitment preimage + hasher (the G-2
 * key-order-independent serialization), the fixed-slot bookkeeping
 * (collected / missing / complete), the canonical placeholder material,
 * and the P2PK script projection. Everything that reaches the real
 * consensus code through pv_tx_probe (package creation, the integrity
 * gate's txId/sighash re-derivation, approval submission, blob emission,
 * JSON round-trip — all of which invoke that gate) is IMPURE and stays in
 * sdk/src/approval-package-v3.js, which composes this module.
 *
 * THE COMMITMENT IS NOT A SIGNING DIGEST — approver authority comes only
 * from the Kaspa transaction signature over the real input sighash. The
 * commitment merely identifies "this exact frozen approval package" and
 * closes the fields consensus does not commit (notably the covenant
 * input's compute budget, which the v1 sighash does NOT cover — see
 * frozen-tx-v3.js).
 *
 * Fixed-slot semantics (production covenant): 10 slots x 65 bytes = one
 * 650-byte blob; slot i verifies ONLY approver i's configured key;
 * sentinel (all-zero) slots never count; the canonical absent/placeholder
 * signature is 64 x 0x00 || 0x01.
 */

const crypto = require("crypto");

const { canonicalJsonStringify } = require("./canonical-json");
const { APPROVER_SENTINEL, MAX_APPROVERS } = require("./vault-state-v3");

const APPROVAL_PACKAGE_SCHEMA = "policyvault-approval-package/v1";
const PLACEHOLDER_APPROVAL = "00".repeat(64) + "01";

/* P2PK script for an x-only key: OpData32 push + key + OpCheckSig. */
function p2pkScriptHex(xOnly) {
  return `20${xOnly}ac`;
}

/*
 * The canonical commitment preimage: EVERY security-relevant field in a
 * fixed order. Excludes only `approvals` (the collected material — each
 * approval's validity is independently bound to the sighash), `createdAt`
 * (explicitly NONSECURITY metadata), and the commitment itself.
 */
/* Key-order-independent serialization (Phase G defect G-2 — same class as
 * v0.4): the commitment binds VALUES only, never a storage backend's JSON
 * key ordering (PostgreSQL jsonb re-orders keys; the JSON-file backend
 * does not). Pre-G-2 commitments verify differently: an in-flight
 * awaiting-approvals package from an older build fails closed and its
 * request must be rebuilt — no funds impact. */
function commitmentPreimage(pkg) {
  return canonicalJsonStringify({
    schema: pkg.schema,
    contractVersion: pkg.contractVersion,
    networkId: pkg.networkId,
    vaultId: pkg.vaultId,
    action: pkg.action,
    predecessorOutpoint: { transactionId: pkg.predecessorOutpoint.transactionId, index: pkg.predecessorOutpoint.index },
    predecessorStateId: pkg.predecessorStateId,
    successorStateId: pkg.successorStateId,
    policyNonce: pkg.policyNonce,
    txId: pkg.txId,
    covenantInputIndex: pkg.covenantInputIndex,
    covenantSighash: pkg.covenantSighash,
    frozenTransaction: pkg.frozenTransaction,
    recipient: pkg.recipient,
    payAmountSompi: pkg.payAmountSompi,
    recipientProof: {
      root: pkg.recipientProof.root,
      siblingsHex: pkg.recipientProof.siblingsHex,
      pathBits: pkg.recipientProof.pathBits
    },
    approvalThresholdAmount: pkg.approvalThresholdAmount,
    approvalM: pkg.approvalM,
    approverSlots: pkg.approverSlots,
    computeBudget: pkg.computeBudget,
    requiredFeeSompi: pkg.requiredFeeSompi
  });
}

function packageCommitmentV3(pkg) {
  return crypto.createHash("sha256").update(commitmentPreimage(pkg), "utf8").digest("hex");
}

function collectedCount(pkg) {
  return pkg.approvals.filter((a) => typeof a === "string").length;
}

/* Slots still missing a real approval (active slots only). */
function missingSlots(pkg) {
  const missing = [];
  pkg.approverSlots.forEach((key, i) => {
    if (key !== APPROVER_SENTINEL && pkg.approvals[i] === null) {
      missing.push(i);
    }
  });
  return missing;
}

function isCompleteV3(pkg) {
  return BigInt(collectedCount(pkg)) >= BigInt(pkg.approvalM);
}

/* The all-placeholder blob for at/below-threshold delegate-only spends. */
function placeholderApprovalsBlob() {
  return PLACEHOLDER_APPROVAL.repeat(MAX_APPROVERS);
}

module.exports = {
  APPROVAL_PACKAGE_SCHEMA,
  PLACEHOLDER_APPROVAL,
  p2pkScriptHex,
  commitmentPreimage,
  packageCommitmentV3,
  collectedCount,
  missingSlots,
  isCompleteV3,
  placeholderApprovalsBlob
};
