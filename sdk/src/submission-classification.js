"use strict";

/*
 * SUBMISSION-OUTCOME CLASSIFICATION — RC35-REC-01 (independent RC35 affected review, 2026-09-11; owner
 * recovery/reservation repair directive of the same day).
 *
 * The ONE classifier of a node's answer to `submitTransaction`, shared by EVERY submitter (headless v0.1 / v0.2,
 * v0.2 requests, v0.4.1, v0.5, v0.6, v0.7 root + rooted genesis, v0.7-payment-hd, v0.7-kas). Three classes, never two:
 *
 *   REJECTED       the node evaluated THIS attempt and rejected it. rusty-kaspa wraps every mempool rule error of a
 *                  submitted transaction as RpcError::RejectedTransaction — "Rejected transaction {id}: {reason}"
 *                  (rpc/core/src/error.rs:54; rpc/service/src/service.rs:671 wraps submit_rpc_transaction's error) — and
 *                  the reason is NOT one of the already-known reasons below. A rejection of THIS attempt is a strong
 *                  negative for this node at this moment; it is NOT by itself proof that no chain effect exists, so the
 *                  caller still verifies the expected effect absent (a genesis: its output; a transition: predecessor
 *                  still live AND successor absent) before it releases any claim — see sdk/src/genesis-recovery.js.
 *   ALREADY_KNOWN  the node reports that it ALREADY holds or accepted this exact transaction (mining/errors/src/
 *                  mempool.rs, retained node source cfafeb4c…): RejectAlreadyAccepted "transaction {id} was already
 *                  accepted by the consensus" (validate_transaction_unacceptance, and again after post-validation for
 *                  a concurrent acceptance — mining/src/mempool/validate_and_insert_transaction.rs), RejectDuplicate
 *                  "transaction {id} is already in the mempool", RejectDuplicateOrphan "orphan transaction {id} is
 *                  already in the orphan pool". These are POSITIVE statements about this attempt's transaction: the
 *                  chain effect exists or is pending. NEVER a negative — claims are kept and the submitter proceeds to
 *                  observation exactly as after an accepted response.
 *   AMBIGUOUS      everything else: transport failures (timeout, dropped connection, "not connected", a crash), a
 *                  RejectedTransaction envelope that names a DIFFERENT transaction id (not this attempt's verdict), or
 *                  a malformed envelope. Uncertainty never releases a claim.
 *
 * The reviewer's finding: the previous single predicate (/\bRejected transaction /) counted RejectAlreadyAccepted as
 * definitive, so a KAS genesis whose submit answer was "was already accepted by the consensus" released its claim and
 * was persisted SUBMISSION_REJECTED although its output existed (exact-image reproduction rejection-recovery-02.json).
 *
 * This module is dependency-free on purpose: sdk/src/vault-identity.js (the identity arbiter) uses it to decide
 * whether a persisted SUBMISSION_REJECTED request is an ESTABLISHED negative (it does not reserve the identity at
 * commit time) or a possible false negative (it does).
 */

const HEX64 = /^[0-9a-f]{64}$/;
/* The envelope appears bare ("Rejected transaction …"), SDK-prefixed ("…: submit failed: Rejected transaction …"),
 * transport-wrapped ("RPC Server (remote error) -> Rejected transaction …") or in the JS/WASM client form
 * ("… message:`Rejected transaction …` …"); the word-boundary marker recognizes all of them. The reason capture keeps
 * any trailing wrapper text ("` }") — every reason match below is a PREFIX match on the exact node strings. */
const ENVELOPE = /\bRejected transaction ([0-9a-fA-F]{64}): (.*)$/;

/* The exact already-known reasons, as formatted by rusty-kaspa (mining/errors/src/mempool.rs), keyed by the enum
 * variant that raises them; `{id}` is the transaction id the reason names (always the submitted transaction's). */
const ALREADY_KNOWN_REASONS = Object.freeze([
  { variant: "RejectAlreadyAccepted", pattern: (id) => new RegExp(`^transaction ${id} was already accepted by the consensus\\b`) },
  { variant: "RejectDuplicate", pattern: (id) => new RegExp(`^transaction ${id} is already in the mempool\\b`) },
  { variant: "RejectDuplicateOrphan", pattern: (id) => new RegExp(`^orphan transaction ${id} is already in the orphan pool\\b`) }
]);

function firstLine(value) {
  const text = value && typeof value === "object" && "message" in value ? value.message : value;
  return String(text ?? "").split("\n")[0];
}

/*
 * classifySubmitOutcome(message, txId?) -> { kind, txId, reason, variant, bound }
 *   kind     "REJECTED" | "ALREADY_KNOWN" | "AMBIGUOUS"
 *   txId     the transaction id the node's envelope names (lowercase), or null without an envelope
 *   reason   the node's reason text after the envelope, or null
 *   variant  the already-known variant name, or null
 *   bound    true when the envelope names the caller's txId (or no txId was given to compare against)
 * An envelope naming ANOTHER transaction than the caller's is AMBIGUOUS: it is not this attempt's verdict.
 */
function classifySubmitOutcome(message, txId = null) {
  const text = firstLine(message);
  const expected = typeof txId === "string" && HEX64.test(txId.toLowerCase()) ? txId.toLowerCase() : null;
  const m = ENVELOPE.exec(text);
  if (!m) return { kind: "AMBIGUOUS", txId: null, reason: null, variant: null, bound: false };
  const named = m[1].toLowerCase();
  const reason = m[2];
  const bound = expected === null || named === expected;
  if (!bound) return { kind: "AMBIGUOUS", txId: named, reason, variant: null, bound: false };
  for (const { variant, pattern } of ALREADY_KNOWN_REASONS) {
    if (pattern(named).test(reason.toLowerCase())) return { kind: "ALREADY_KNOWN", txId: named, reason, variant, bound: true };
  }
  return { kind: "REJECTED", txId: named, reason, variant: null, bound: true };
}

/* DEFINITIVE rejection of THIS attempt (the historical predicate name, kept for every caller; now excludes the
 * already-known answers and, when a txId is given, an envelope naming another transaction). */
function isDefinitiveSubmitRejection(message, txId = null) {
  return classifySubmitOutcome(message, txId).kind === "REJECTED";
}

/* The node reports that it already holds / accepted THIS transaction. */
function isAlreadyKnownSubmitAnswer(message, txId = null) {
  return classifySubmitOutcome(message, txId).kind === "ALREADY_KNOWN";
}

/* A historical error string or current-UTXO absence is not nonacceptance proof.
 * Only the corrected observer's complete, transaction/request-bound funding proof
 * can settle a negative. Old proofs remain recoverable, preserving their bytes. */
const NEGATIVE_PROOF_SCHEMA = "policyvault-negative-proof/v2";
const NON_ACCEPTANCE_PROOF_SCHEMA = "policyvault-nonacceptance-proof/v1";
function negativeEvidenceBinding(record) {
  if (!record || !HEX64.test(record.txId ?? "")) return null;
  const frozen = record.build?.frozen ?? record.transaction?.unsignedSafeJson ?? record.signedSafeJson;
  if (!frozen) return null;
  const immutable = { txId: record.txId, requestId: record.id ?? record.requestId ?? null,
    networkId: record.networkId ?? record.build?.networkId ?? null, submitStartHash: record.submitStartHash ?? null, submissionRejection: record.submissionRejection ?? null,
    vaultId: record.vaultId ?? null, rootCovenantId: record.rootCovenantId ?? null,
    frozen, definition: record.definition ?? null, expected: record.expected ?? null };
  return require("crypto").createHash("sha256").update(require("../../core/intent/canonical").canonicalJsonStringify(JSON.parse(JSON.stringify(immutable, (_k, v) => typeof v === "bigint" ? String(v) : v)))).digest("hex");
}
function recordedNegativeIsEstablished(record) {
  if (!record || record.state !== "SUBMISSION_REJECTED" || !HEX64.test(record.txId ?? "")) return false;
  const outcome = record.submissionOutcome, proof = outcome?.proof;
  const binding = negativeEvidenceBinding(record);
  return !!binding && outcome?.outcome === "SUBMISSION_REJECTED" && outcome.txId === record.txId &&
    proof?.schema === NEGATIVE_PROOF_SCHEMA && proof.txId === record.txId && proof.requestBinding === binding &&
    proof.boundRejection === true && proof.allInputsUnspent === true && proof.repeatedFundingQueries === true &&
    proof.exactMempoolMiss === true && proof.outputsAbsent === true && proof.completeAcceptanceWindow === true &&
    proof.initialAnchorReorg === false && proof.startHash === record.submitStartHash && HEX64.test(proof.startHash ?? "") && HEX64.test(proof.sink ?? "") &&
    classifySubmitOutcome(proof.nodeAnswer, record.txId).kind === "REJECTED";
}

/* An ordinary v4 ambiguous genesis can close only with a retained, bound
 * nonacceptance proof. Historical labels, current index misses and a prior
 * already-known answer never qualify. This is not a node rejection proof. */
function recordedNonAcceptanceIsEstablished(record) {
  if (!record || record.state !== "NOT_BROADCAST" || !HEX64.test(record.txId ?? "") || record.genesisRecovery ||
      record.submissionResponse?.kind === "ALREADY_KNOWN" || record.submissionRejection ||
      classifySubmitOutcome(record.error, record.txId).kind === "ALREADY_KNOWN") return false;
  const outcome = record.submissionOutcome, proof = outcome?.proof, binding = negativeEvidenceBinding(record);
  return !!binding && outcome?.outcome === "NOT_BROADCAST" && outcome.txId === record.txId &&
    proof?.schema === NON_ACCEPTANCE_PROOF_SCHEMA && proof.txId === record.txId && proof.requestBinding === binding &&
    proof.allInputsUnspent === true && proof.repeatedFundingQueries === true && proof.exactMempoolMiss === true &&
    proof.outputsAbsent === true && proof.completeAcceptanceWindow === true && proof.initialAnchorReorg === false &&
    proof.startHash === record.submitStartHash && HEX64.test(proof.startHash ?? "") && HEX64.test(proof.sink ?? "");
}

/* What a persisted negative genesis / transition record proves (null for any other state). */
function classifyRecordedNegative(record) {
  if (!record || typeof record !== "object" || record.state !== "SUBMISSION_REJECTED") return null;
  if (recordedNegativeIsEstablished(record)) return "ESTABLISHED";
  const cls = classifySubmitOutcome(record.error, record.txId);
  if (cls.kind === "ALREADY_KNOWN") return "FALSE_NEGATIVE";
  return "UNKNOWN";
}

module.exports = {
  NEGATIVE_PROOF_SCHEMA,
  NON_ACCEPTANCE_PROOF_SCHEMA,
  recordedNonAcceptanceIsEstablished,
  negativeEvidenceBinding,
  ALREADY_KNOWN_REASONS,
  firstLine,
  classifySubmitOutcome,
  isDefinitiveSubmitRejection,
  isAlreadyKnownSubmitAnswer,
  recordedNegativeIsEstablished,
  classifyRecordedNegative
};
