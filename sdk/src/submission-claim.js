"use strict";

/*
 * Durable submission claims (mission §24) and covenant transition claims
 * (mission §25).
 *
 * A claim is created durably BEFORE broadcast via link()-based
 * create-only persistence, so a crash on either side of the RPC call
 * leaves an unambiguous record. A transition claim is keyed by the exact
 * live covenant outpoint so only one local attempt can own a transition.
 */

const path = require("path");
const fs = require("fs");

const { persistJsonDurably, readJsonStrict } = require("./durable-json");

const SUBMISSION_CLAIM_SCHEMA = "policyvault-submission-claim/v1";
const TRANSITION_CLAIM_SCHEMA = "policyvault-transition-claim/v1";

function fail(message) {
  const error = new Error(`submission-claim: ${message}`);
  error.code = "CLAIM_CONFLICT";
  throw error;
}

function submissionClaimPath(config, txId) {
  return path.join(config.dataRoot, "claims", "submission", `${txId}.json`);
}

function transitionClaimPath(config, outpoint) {
  return path.join(
    config.dataRoot,
    "claims",
    "transition",
    `${outpoint.transactionId}-${outpoint.index}.json`
  );
}

/*
 * Claim a transition on the exact current covenant outpoint. Fails with
 * CLAIM_CONFLICT if any attempt (even a crashed one) already owns it —
 * crashed claims are resolved by reconciliation, never by overwrite.
 *
 * `expected` (optional) is the exact chain-provable effect of this
 * transition, so reconciliation can prove success precisely rather than
 * inferring it from a missing predecessor. For a covenant successor:
 *   { kind: "successor", txId, index, valueSompi, covenantId, scriptSha256,
 *     stateId, contractVersion }
 * For terminal recovery:
 *   { kind: "recover", txId, index, valueSompi, ownerAddress,
 *     contractVersion }
 */
function claimTransition(config, { outpoint, action, txId, vaultId, stateId, expected = null }) {
  const filePath = transitionClaimPath(config, outpoint);
  try {
    persistJsonDurably({
      filePath,
      value: {
        schema: TRANSITION_CLAIM_SCHEMA,
        outpoint,
        action,
        txId,
        vaultId,
        stateId,
        expected,
        createdAt: new Date().toISOString()
      },
      createOnly: true
    });
  } catch (error) {
    if (error.code === "EEXIST") {
      const existing = readJsonStrict(filePath, "transition claim");
      fail(
        `outpoint ${outpoint.transactionId}:${outpoint.index} is already claimed by ` +
          `${existing.action} tx ${existing.txId} — reconcile before retrying`
      );
    }
    throw error;
  }
  return filePath;
}

function loadTransitionClaim(config, outpoint) {
  const filePath = transitionClaimPath(config, outpoint);
  return fs.existsSync(filePath) ? readJsonStrict(filePath, "transition claim") : null;
}

/*
 * Claim a broadcast by final txid. Idempotent for the same txid.
 */
function claimSubmission(config, { txId, vaultId, action }) {
  const filePath = submissionClaimPath(config, txId);
  if (fs.existsSync(filePath)) {
    return filePath;
  }
  persistJsonDurably({
    filePath,
    value: {
      schema: SUBMISSION_CLAIM_SCHEMA,
      txId,
      vaultId,
      action,
      createdAt: new Date().toISOString()
    },
    createOnly: true
  });
  return filePath;
}

/*
 * Release a transition claim, guarded and idempotent: only removed when
 * the stored claim's txId matches the caller's (never releases another
 * attempt's claim), and a missing file is a no-op. Callers release ONLY
 * on chain evidence (definitive node rejection with the predecessor
 * proven live and the expected effect absent, or reconcile-v2's aged
 * stale-claim proof) — never on ambiguity.
 */
function releaseTransitionClaim(config, { outpoint, txId }) {
  const filePath = transitionClaimPath(config, outpoint);
  if (!fs.existsSync(filePath)) {
    return false;
  }
  const existing = readJsonStrict(filePath, "transition claim");
  if (existing.txId !== txId) {
    fail(`refusing to release claim for tx ${existing.txId} while releasing ${txId}`);
  }
  try {
    fs.unlinkSync(filePath);
  } catch (error) {
    if (error.code !== "ENOENT") throw error; // concurrent release: idempotent
  }
  return true;
}

/* Release a submission claim by txid; idempotent, missing file is a no-op. */
function releaseSubmissionClaim(config, txId) {
  const filePath = submissionClaimPath(config, txId);
  try {
    fs.unlinkSync(filePath);
    return true;
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
    return false;
  }
}

/* Record the durable receipt after chain proof. */
function persistReceipt(config, { txId, vaultId, action, proof }) {
  persistJsonDurably({
    filePath: path.join(config.dataRoot, "receipts", `${txId}.json`),
    value: {
      schema: "policyvault-receipt/v1",
      txId,
      vaultId,
      action,
      proof,
      verifiedAt: new Date().toISOString()
    }
  });
}

module.exports = {
  claimTransition,
  loadTransitionClaim,
  claimSubmission,
  persistReceipt,
  releaseTransitionClaim,
  releaseSubmissionClaim,
  transitionClaimPath,
  submissionClaimPath
};
