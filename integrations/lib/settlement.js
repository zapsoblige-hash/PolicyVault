"use strict";

/*
 * Settlement determination — the adapters' ONLY source of "paid" truth.
 *
 * PolicyVault's success definition is stricter than any payment
 * protocol's: `submitTransaction()` returning is NOT success. Success
 * requires txid verified, old state consumed, expected successor
 * observed, and a durable receipt persisted — all proven SERVER-side by
 * the existing submit/reconcile pipeline. The adapter therefore claims
 * settlement from EXACTLY ONE fact: the durable wallet request's state is
 * CHAIN_VERIFIED. It never reads a node, never interprets a facilitator
 * or merchant claim, and never upgrades SUBMITTED into settled.
 *
 * State classification (sdk/src/wallet-requests-v4.js RequestState):
 *   CHAIN_VERIFIED                      -> SETTLED (evidence extracted)
 *   BUILT                               -> awaiting external signature
 *   AWAITING_APPROVALS                  -> awaiting covenant approvals
 *   SIGNED/FINALIZED/PREFLIGHT_VERIFIED -> ready to submit
 *   SUBMITTING/SUBMITTED                -> broadcast in flight; NOT settled
 *   RECONCILIATION_REQUIRED /
 *   TERMINATED_UNKNOWN                  -> UNKNOWN — fail closed: report
 *                                          reconciliation required, never
 *                                          settled, never "failed"
 *   everything else                     -> FAILED (fail-closed states)
 */

const SETTLED_STATES = Object.freeze(new Set(["CHAIN_VERIFIED"]));
const PENDING_SIGNATURE_STATES = Object.freeze(new Set(["BUILT"]));
const PENDING_APPROVAL_STATES = Object.freeze(new Set(["AWAITING_APPROVALS"]));
const READY_TO_SUBMIT_STATES = Object.freeze(new Set(["PREFLIGHT_VERIFIED", "FINALIZED", "SIGNED"]));
const IN_FLIGHT_STATES = Object.freeze(new Set(["SUBMITTING", "SUBMITTED"]));
const UNKNOWN_STATES = Object.freeze(new Set(["RECONCILIATION_REQUIRED", "TERMINATED_UNKNOWN"]));

function classifyRequestState(state) {
  if (typeof state !== "string") return "UNKNOWN"; // fail closed
  if (SETTLED_STATES.has(state)) return "SETTLED";
  if (PENDING_SIGNATURE_STATES.has(state)) return "PENDING_SIGNATURE";
  if (PENDING_APPROVAL_STATES.has(state)) return "PENDING_APPROVALS";
  if (READY_TO_SUBMIT_STATES.has(state)) return "READY_TO_SUBMIT";
  if (IN_FLIGHT_STATES.has(state)) return "IN_FLIGHT";
  if (UNKNOWN_STATES.has(state)) return "UNKNOWN";
  return "FAILED";
}

/*
 * Settlement evidence from a CHAIN_VERIFIED request record — only fields
 * the Agent API actually serves (never synthesized): the frozen txid (==
 * broadcast txid), the successor state id, the intent-manifest hash, and
 * the exact fee. DAA score is deliberately ABSENT: the receipt schema
 * does not persist one and the adapter must not query a node to invent
 * chain truth (x402 spec OQ-2 / ap2 spec OQ-7 — design option (c)).
 */
function settlementEvidenceFrom(request) {
  if (!request || request.state !== "CHAIN_VERIFIED") {
    throw new Error("settlementEvidenceFrom: request is not CHAIN_VERIFIED — refusing to fabricate settlement evidence");
  }
  return {
    txId: request.txId,
    successorStateId: request.successorStateId ?? null,
    manifestHash: request.manifestHash ?? null,
    feeSompi: request.review && typeof request.review.feeSompi === "string" ? request.review.feeSompi : null,
    requestState: request.state
  };
}

/*
 * Poll the durable request until it leaves the in-flight window or the
 * deadline lapses. Returns { classification, request }. The poller NEVER
 * cancels anything — a broadcast Kaspa transaction is not cancellable,
 * and reconciliation remains the only truth.
 */
async function pollForSettlement(client, requestId, { attempts = 10, delayMs = 500, sleep } = {}) {
  const wait = sleep ?? ((ms) => new Promise((r) => setTimeout(r, ms)));
  let request = null;
  for (let i = 0; i < attempts; i += 1) {
    const answer = await client.getRequest(requestId);
    request = answer && answer.request ? answer.request : null;
    const classification = classifyRequestState(request ? request.state : null);
    if (classification !== "IN_FLIGHT") return { classification, request };
    if (i + 1 < attempts) await wait(delayMs);
  }
  return { classification: "UNKNOWN", request }; // still in flight at deadline: fail closed, reconcile-later
}

module.exports = { classifyRequestState, settlementEvidenceFrom, pollForSettlement };
