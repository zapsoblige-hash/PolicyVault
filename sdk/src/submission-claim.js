"use strict";

/*
 * Durable submission claims (mission §24) and covenant transition claims
 * (mission §25).
 *
 * A claim is created durably BEFORE broadcast via create-only
 * persistence, so a crash on either side of the RPC call leaves an
 * unambiguous record. A transition claim is keyed by the exact live
 * covenant outpoint so only one local attempt can own a transition.
 *
 * Phase C: persistence goes through the backend store (sdk/src/store.js).
 * The JSON driver keeps the proven link()/EEXIST create-only files; the
 * PostgreSQL driver arbitrates with the (network_id, key) UNIQUE primary
 * key via INSERT ... ON CONFLICT DO NOTHING. Claim-conflict semantics,
 * idempotency, and guarded release are IDENTICAL across backends.
 */

const { getStore, Categories } = require("./store");

const SUBMISSION_CLAIM_SCHEMA = "policyvault-submission-claim/v1";
const TRANSITION_CLAIM_SCHEMA = "policyvault-transition-claim/v1";

function fail(message) {
  const error = new Error(`submission-claim: ${message}`);
  error.code = "CLAIM_CONFLICT";
  throw error;
}

function transitionClaimKey(outpoint) {
  return `${outpoint.transactionId}-${outpoint.index}`;
}

/*
 * Claim a transition on the exact current covenant outpoint. Fails with
 * CLAIM_CONFLICT if any attempt (even a crashed one) already owns it —
 * crashed claims are resolved by reconciliation, never by overwrite.
 *
 * `expected` (optional) is the exact chain-provable effect of this
 * transition, so reconciliation can prove success precisely rather than
 * inferring it from a missing predecessor.
 */
async function claimTransition(config, { outpoint, action, txId, vaultId, stateId, expected = null }) {
  const store = getStore(config);
  const key = transitionClaimKey(outpoint);
  const created = await store.createExclusive(Categories.TRANSITION_CLAIM, key, {
    schema: TRANSITION_CLAIM_SCHEMA,
    outpoint,
    action,
    txId,
    vaultId,
    stateId,
    expected,
    createdAt: new Date().toISOString()
  });
  if (!created) {
    const existing = await store.read(Categories.TRANSITION_CLAIM, key);
    // The conflicting claim may be released concurrently between the
    // refused insert and this read; the conflict verdict stands either way.
    const detail = existing ? `${existing.action} tx ${existing.txId}` : "another attempt";
    fail(`outpoint ${outpoint.transactionId}:${outpoint.index} is already claimed by ${detail} — reconcile before retrying`);
  }
  return key;
}

async function loadTransitionClaim(config, outpoint) {
  return getStore(config).read(Categories.TRANSITION_CLAIM, transitionClaimKey(outpoint));
}

/*
 * Claim a broadcast by final txid. Idempotent for the same txid.
 */
async function claimSubmission(config, { txId, vaultId, action }) {
  await getStore(config).createExclusive(Categories.SUBMISSION_CLAIM, txId, {
    schema: SUBMISSION_CLAIM_SCHEMA,
    txId,
    vaultId,
    action,
    createdAt: new Date().toISOString()
  });
  return txId;
}

/*
 * Release a transition claim, guarded and idempotent: only removed when
 * the stored claim's txId matches the caller's (never releases another
 * attempt's claim), and a missing record is a no-op. Callers release ONLY
 * on chain evidence — never on ambiguity.
 */
async function releaseTransitionClaim(config, { outpoint, txId }) {
  const store = getStore(config);
  const key = transitionClaimKey(outpoint);
  const existing = await store.read(Categories.TRANSITION_CLAIM, key);
  if (existing === null) {
    return false;
  }
  if (existing.txId !== txId) {
    fail(`refusing to release claim for tx ${existing.txId} while releasing ${txId}`);
  }
  await store.remove(Categories.TRANSITION_CLAIM, key); // concurrent release: idempotent
  return true;
}

/* Release a submission claim by txid; idempotent, missing record is a no-op. */
async function releaseSubmissionClaim(config, txId) {
  return getStore(config).remove(Categories.SUBMISSION_CLAIM, txId);
}

/* Record the durable receipt after chain proof. */
async function persistReceipt(config, { txId, vaultId, action, proof }) {
  await getStore(config).write(Categories.RECEIPT, txId, {
    schema: "policyvault-receipt/v1",
    txId,
    vaultId,
    action,
    proof,
    verifiedAt: new Date().toISOString()
  });
}

/* JSON-layout path helpers (json backend only; tests/tools inspect the
 * on-disk layout directly). Meaningless under the postgres backend. */
const path = require("path");
function submissionClaimPath(config, txId) {
  return path.join(config.dataRoot, "claims", "submission", `${txId}.json`);
}
function transitionClaimPath(config, outpoint) {
  return path.join(config.dataRoot, "claims", "transition", `${transitionClaimKey(outpoint)}.json`);
}

module.exports = {
  claimTransition,
  loadTransitionClaim,
  claimSubmission,
  persistReceipt,
  releaseTransitionClaim,
  releaseSubmissionClaim,
  transitionClaimKey,
  transitionClaimPath,
  submissionClaimPath
};
