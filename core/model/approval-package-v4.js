"use strict";

/*
 * PolicyVault v0.4 approval-package MODEL CORE (Checkpoint E §E7/§E8) —
 * the PURE members of sdk/src/approval-package-v4.js, split out in
 * shared-core extraction step 3. Member bodies are verbatim from the
 * pre-split sdk implementation.
 *
 * Here live the v0.4 canonical commitment preimage + hasher and the
 * fixed-slot bookkeeping; the shared placeholder / P2PK members are
 * re-exported from the v0.3 model core exactly as the sdk module has
 * always re-exported them. Everything that reaches the real consensus
 * code through pv_tx_probe (package creation, the integrity gate's
 * txId/sighash re-derivation, approval submission, blob emission, JSON
 * round-trip) is IMPURE and stays in sdk/src/approval-package-v4.js,
 * which composes this module.
 *
 * Serialized with canonicalJsonStringify (key-order-independent): the
 * commitment is a function of the VALUES only, never of a storage
 * backend's JSON representation. Phase G defect G-2: PostgreSQL jsonb
 * re-orders object keys, so the previous JSON.stringify preimage
 * "mutated" across a postgres round trip with every value intact and
 * finalize voided real collected approvals. Commitments computed by
 * pre-G-2 builds verify differently: any in-flight AWAITING_APPROVALS
 * package from an older build fails closed (PACKAGE_MUTATED) and its
 * request must simply be rebuilt — no funds impact.
 *
 * THE COMMITMENT IS NOT A SIGNING DIGEST — approver authority comes only
 * from the Kaspa transaction signature over the real input sighash.
 */

const crypto = require("crypto");

const { canonicalJsonStringify } = require("./canonical-json");
const { APPROVER_SENTINEL } = require("./vault-state-v4");
const { PLACEHOLDER_APPROVAL, placeholderApprovalsBlob, p2pkScriptHex } = require("./approval-package-v3");

const APPROVAL_PACKAGE_SCHEMA_V4 = "policyvault-approval-package/v4";

/*
 * The canonical commitment preimage: EVERY security-relevant field.
 * Excludes only `approvals` (the collected material — each approval's
 * validity is independently bound to the sighash), `createdAt`
 * (explicitly NONSECURITY metadata), and the commitment itself.
 */
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
    agentPolicy: pkg.agentPolicy,
    agentProof: { root: pkg.agentProof.root, siblingsHex: pkg.agentProof.siblingsHex, pathBits: pkg.agentProof.pathBits },
    successorAgentRoot: pkg.successorAgentRoot,
    periodsElapsed: pkg.periodsElapsed,
    recipient: pkg.recipient,
    payAmountSompi: pkg.payAmountSompi,
    recipientProof: { root: pkg.recipientProof.root, siblingsHex: pkg.recipientProof.siblingsHex, pathBits: pkg.recipientProof.pathBits },
    reserveConsumedSompi: pkg.reserveConsumedSompi,
    approvalM: pkg.approvalM,
    approverSlots: pkg.approverSlots,
    computeBudget: pkg.computeBudget,
    requiredFeeSompi: pkg.requiredFeeSompi
  });
}

function packageCommitmentV4(pkg) {
  return crypto.createHash("sha256").update(commitmentPreimage(pkg), "utf8").digest("hex");
}

function collectedCountV4(pkg) {
  return pkg.approvals.filter((a) => typeof a === "string").length;
}

/* Slots still missing a real approval (active slots only). */
function missingSlotsV4(pkg) {
  const missing = [];
  pkg.approverSlots.forEach((key, i) => {
    if (key !== APPROVER_SENTINEL && pkg.approvals[i] === null) {
      missing.push(i);
    }
  });
  return missing;
}

function isCompleteV4(pkg) {
  return BigInt(collectedCountV4(pkg)) >= BigInt(pkg.approvalM);
}

module.exports = {
  APPROVAL_PACKAGE_SCHEMA_V4,
  PLACEHOLDER_APPROVAL,
  placeholderApprovalsBlob,
  p2pkScriptHex,
  commitmentPreimage,
  packageCommitmentV4,
  collectedCountV4,
  missingSlotsV4,
  isCompleteV4
};
