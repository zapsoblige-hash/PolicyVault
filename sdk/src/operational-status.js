"use strict";

/*
 * Operational status for a v0.2 vault — the single derivation the
 * dashboard consumes. Pure over durable backend truth (manifest +
 * transition claim + request records); performs no chain access and
 * never mutates anything. Fail closed: any state this function cannot
 * positively classify maps to UNKNOWN (zero mutation controls in the UI).
 *
 *   ACTIVE                  live vault, no claim, no in-flight request
 *   WAITING_FOR_SIGNATURE   a BUILT request bound to the current state
 *   TRANSACTION_PENDING     claim held by a SUBMITTING/SUBMITTED request
 *   ACTION_REQUIRED_VERIFY  claim held with no live submission — chain
 *                           verification (reconcile-v2) must resolve it
 *   CLOSED                  terminal recovery proven
 *   UNKNOWN                 fail closed (TERMINATED_UNKNOWN or
 *                           unclassifiable) — no mutation controls
 *
 * There is deliberately NO status and NO input that deletes or overrides
 * a claim: resolution flows only through reconcile-v2's exact proofs.
 */

const OperationalStatus = Object.freeze({
  ACTIVE: "ACTIVE",
  WAITING_FOR_SIGNATURE: "WAITING_FOR_SIGNATURE",
  TRANSACTION_PENDING: "TRANSACTION_PENDING",
  ACTION_REQUIRED_VERIFY: "ACTION_REQUIRED_VERIFY",
  CLOSED: "CLOSED",
  UNKNOWN: "UNKNOWN"
});

/* Advanced-details summary of a request record (never key material). */
function requestSummary(request) {
  if (!request) return null;
  return {
    requestId: request.requestId,
    action: request.action,
    state: request.state,
    txId: request.txId ?? null,
    signerRole: request.signerRole,
    predecessorOutpoint: request.predecessorOutpoint ?? null,
    successorStateId: request.successorStateId ?? null,
    createdAt: request.createdAt ?? null,
    error: request.error ?? null
  };
}

function deriveOperationalStatus({ manifest, claim, requests = [] }) {
  if (!manifest) {
    return { status: OperationalStatus.UNKNOWN, reason: "no manifest" };
  }
  if (manifest.status === "RECOVERED") {
    return { status: OperationalStatus.CLOSED };
  }
  if (manifest.status === "TERMINATED_UNKNOWN" || !manifest.live) {
    return {
      status: OperationalStatus.UNKNOWN,
      reason: "automatic verification could not establish the vault state",
      request: requestSummary(requests.find((r) => r.txId === manifest.latestTransitionTxId) ?? null)
    };
  }

  if (claim) {
    const claimRequest = requests.find((r) => r.txId === claim.txId) ?? null;
    const pending = claimRequest && (claimRequest.state === "SUBMITTING" || claimRequest.state === "SUBMITTED");
    return {
      status: pending ? OperationalStatus.TRANSACTION_PENDING : OperationalStatus.ACTION_REQUIRED_VERIFY,
      claim: {
        action: claim.action,
        txId: claim.txId,
        outpoint: claim.outpoint,
        createdAt: claim.createdAt ?? null,
        expectedSuccessorStateId: claim.expected?.stateId ?? null,
        expectedKind: claim.expected?.kind ?? null
      },
      request: requestSummary(claimRequest)
    };
  }

  const awaiting = requests.find(
    (r) => r.state === "BUILT" && (r.predecessorStateId === manifest.live.stateId || r.kind === "genesis")
  );
  if (awaiting) {
    return { status: OperationalStatus.WAITING_FOR_SIGNATURE, request: requestSummary(awaiting) };
  }

  return { status: OperationalStatus.ACTIVE };
}

module.exports = { OperationalStatus, deriveOperationalStatus, requestSummary };
