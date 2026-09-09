"use strict";

/*
 * policyvault-execution-attestation/1 — HUMAN SUMMARY + LANGUAGE RULES.
 *
 * PERMANENT LANGUAGE RULE (binding on every rendered attestation surface:
 * CLI, API, web, mobile, exports). A PolicyVault attestation is an
 * EVIDENCE PRODUCT, never a certification of anything. It must never
 * claim, imply, or borrow the vocabulary of an external approving body.
 * The forbidden vocabulary below is enforced by a test over the rendered
 * output (core/attest/test/language.test.js), not merely by convention.
 *
 * The sanctioned vocabulary is exactly:
 *   - "PolicyVault policy-execution attestation" (what the record is)
 *   - "deterministic authorization evidence"     (what PolicyVault decided)
 *   - "verified chain outcome"                   (what Kaspa showed)
 *
 * MINIMIZED DISCLOSURE, NOT PRIVACY: the record carries the smallest set
 * of facts that makes the outcome independently checkable. Every one of
 * those facts is already public on chain or is a public identifier. An
 * attestation is not an anonymity tool and must never be described as one.
 */

const S = require("./schema");
const { VERDICTS } = require("./verify");

/* Whole-word terms that may never appear in rendered attestation text. */
const FORBIDDEN_TERMS = Object.freeze([
  "compliant",
  "compliance",
  "noncompliant",
  "certified",
  "certifies",
  "certification",
  "certificate",
  "accredited",
  "accreditation",
  "regulator",
  "regulators",
  "regulated",
  "regulatory",
  "audit",
  "audits",
  "audited",
  "auditor",
  "endorsed",
  "endorses",
  "endorsement",
  "notarized",
  "notarised",
  "notary",
  "license",
  "licence",
  "licensed",
  "guarantee",
  "guarantees",
  "guaranteed",
  "warranty",
  "legal",
  "legally",
  "lawful",
  "official",
  "officially",
  "government"
]);

/* Multi-word phrases that may never appear (checked case-insensitively). */
const FORBIDDEN_PHRASES = Object.freeze([
  "approved by a regulator",
  "regulatory approval",
  "legally binding",
  "seal of approval",
  "meets all requirements"
]);

/*
 * Scan arbitrary rendered text for the forbidden vocabulary. Returns the
 * hits (empty array = clean). Pure; no exceptions on clean input.
 */
function forbiddenLanguageHits(text) {
  if (typeof text !== "string") return [{ kind: "input", term: null, detail: "text must be a string" }];
  const hits = [];
  const lower = text.toLowerCase();
  for (const term of FORBIDDEN_TERMS) {
    /* \b boundaries so hyphenated compounds are caught too. */
    const re = new RegExp(`\\b${term}\\b`, "i");
    if (re.test(lower)) hits.push({ kind: "term", term });
  }
  for (const phrase of FORBIDDEN_PHRASES) {
    if (lower.includes(phrase)) hits.push({ kind: "phrase", term: phrase });
  }
  return hits;
}

function assertNoForbiddenLanguage(text) {
  const hits = forbiddenLanguageHits(text);
  if (hits.length > 0) {
    const e = new Error(`attestation text uses forbidden vocabulary: ${hits.map((h) => h.term).join(", ")}`);
    e.code = "ATTESTATION_LANGUAGE_FORBIDDEN";
    e.hits = hits;
    throw e;
  }
  return text;
}

const short = (hex) => (typeof hex === "string" && hex.length === 64 ? `${hex.slice(0, 8)}…` : String(hex));

const LADDER_MEANING = Object.freeze({
  AUTHORIZED: "PolicyVault's own durable request record: policy, limits and intent were checked before anything was signed",
  SIGNED: "an external signer returned a signature; PolicyVault holds bytes, never keys",
  BROADCAST: "a node returned the frozen transaction id — on its own this is NOT success",
  CHAIN_SEEN: "the expected outputs were observed",
  CHAIN_VERIFIED: "the exact expected effect was proven on chain (script, value, covenant identity)",
  VERIFIED_OUTCOME: "the economic result of the execution was proven, not merely the transaction"
});

/*
 * Human-readable rendering. Deterministic: same record + same verification
 * result -> byte-identical text.
 */
function humanReadable(record, verification = null) {
  const L = [];
  const push = (s) => L.push(s);
  const o = record.outcome;
  const a = record.authorization;

  push("PolicyVault policy-execution attestation");
  push(`record ${short(record.attestationHash)} (${record.attestationVersion}), produced ${record.producedAt}`);
  push(`issued by ${record.producer.software} ${record.producer.component} build ${record.producer.buildId}`);
  push("");

  push("WHAT WAS REQUESTED");
  push(`  action ${record.action.type}${record.action.highLevel ? ` (${record.action.highLevel})` : ""} by role ${record.action.role}${record.action.aboveThreshold ? ", above the policy approval threshold" : ""}`);
  push(`  vault ${short(record.subject.vaultId)} on ${record.subject.networkId}, covenant generation ${record.subject.contractVersion}`);
  if (record.subject.organizationId !== null) push(`  organization ${record.subject.organizationId}`);
  push(`  policy nonce ${record.subject.policyNonce}; policy state ${short(record.subject.stateBefore)} -> ${short(record.subject.stateAfter)}`);
  if (record.asset.kind === "KAS") {
    push(`  amount ${record.amounts.amount} sompi of KAS; network fee ${record.amounts.networkFeeSompi} sompi`);
  } else {
    push(`  amount ${record.amounts.amount} atomic units of token family ${short(record.asset.familyId)} (descriptor ${short(record.asset.descriptorHash)}); network fee ${record.amounts.networkFeeSompi} sompi`);
  }
  if (record.amounts.protocolFeeSompi !== null) push(`  venue protocol fee ${record.amounts.protocolFeeSompi} sompi`);
  push(`  destination ${record.destination.kind}${record.destination.identity ? ` ${record.destination.identity}` : ""}`);
  push("");

  push("DETERMINISTIC AUTHORIZATION EVIDENCE");
  push(`  decision ${a.decision}${a.refusalCode ? ` (${a.refusalCode})` : ""}`);
  push(`  intent manifest ${short(a.intentManifestHash)}, verdict ${a.intentManifestVerdict}`);
  push(`  signer-visible digest ${short(a.signerVisibleDigest)}; signing identity ${short(a.signerXOnly)}`);
  push(`  approvals ${record.approvals.collected} of ${record.approvals.required} required, over ${record.approvals.approverSlots.length} covenant approver slots`);
  push("  approval evidence is counts, public keys and per-approval digests only — no signature material is carried");
  push("");

  push("EXECUTION LADDER (never collapsed)");
  if (o.reached.length === 0) {
    push("  no ladder state was reached; the request was refused before anything was signed");
  } else {
    for (const step of o.reached) {
      push(`  ${step.state.padEnd(16)} ${LADDER_MEANING[step.state]} [source: ${step.source}]`);
    }
  }
  push(`  highest state reached: ${o.state}; disposition ${o.disposition}${o.failureCode ? ` (${o.failureCode})` : ""}`);
  push("");

  const hasVerified = o.reached.some((r) => r.state === "CHAIN_VERIFIED");
  push(hasVerified ? "VERIFIED CHAIN OUTCOME" : "CHAIN OUTCOME (NOT YET A VERIFIED CHAIN OUTCOME)");
  if (o.txId === null) {
    push("  no transaction exists for this record");
  } else {
    push(`  transaction ${o.txId} on ${o.networkId}`);
    if (o.chain.acceptingBlockDaaScore !== null) {
      push(`  accepted at DAA ${o.chain.acceptingBlockDaaScore}; observed at DAA ${o.chain.observedVirtualDaaScore ?? "unknown"}; depth ${o.chain.depthDaa ?? "unknown"}${o.chain.minDepthDaa !== null ? ` (declared minimum ${o.chain.minDepthDaa})` : ""}`);
    }
    if (o.chain.predecessorOutpoint !== null) push(`  consumed ${o.chain.predecessorOutpoint.transactionId}:${o.chain.predecessorOutpoint.index}`);
    if (o.chain.successorOutpoint !== null) push(`  successor ${o.chain.successorOutpoint.transactionId}:${o.chain.successorOutpoint.index} state ${short(o.chain.successorStateId)} covenant ${short(o.chain.covenantId)}`);
    push(`  ${o.chain.outputs.length} observed output(s) recorded for independent re-checking`);
  }
  push("");

  if (verification !== null) {
    push("VERIFIER RESULT");
    push(`  ${verification.verifierVersion} verdict ${verification.verdict}`);
    if (verification.failureCodes.length > 0) push(`  failures: ${verification.failureCodes.join(", ")}`);
    for (const w of verification.structural.warnings) push(`  note: ${w.code} — ${w.message}`);
    if (verification.verdict !== VERDICTS.CHAIN_CONFIRMED) {
      push("  the chain facts in this record were NOT confirmed in this run; re-check them against a node before relying on them");
    }
    push("");
  }

  push("WHAT THIS RECORD SHOWS — AND WHAT IT DOES NOT");
  const digestClause = a.signerVisibleDigest === S.NOT_AVAILABLE ? "" : " the exact digest an external signer authorized,";
  push(`  it shows: exactly what was requested, exactly what PolicyVault deterministically decided,${digestClause} and exactly what a Kaspa node reported.`);
  push("  anyone can re-check it without PolicyVault: recompute the record hash and re-read the named outputs from any synced Kaspa node with a UTXO index.");
  push("  it does NOT show: any opinion of any outside body, any status conferred by anyone other than Kaspa consensus, the intentions or solvency of a counterparty, or anything about a venue.");
  push("  PolicyVault is not a wallet, holds no keys, and cannot move funds. Kaspa consensus is the security boundary; this record only describes what consensus already settled.");

  return L.join("\n");
}

/* Machine equivalent of the same rendering (stable keys, no prose). */
function structured(record, verification = null) {
  return {
    summaryVersion: "policyvault-execution-attestation-summary/1",
    attestationHash: record.attestationHash,
    attestationVersion: record.attestationVersion,
    producedAt: record.producedAt,
    vaultId: record.subject.vaultId,
    networkId: record.subject.networkId,
    contractVersion: record.subject.contractVersion,
    action: record.action.type,
    decision: record.authorization.decision,
    refusalCode: record.authorization.refusalCode,
    intentManifestHash: record.authorization.intentManifestHash,
    highestState: record.outcome.state,
    disposition: record.outcome.disposition,
    ladder: record.outcome.reached.map((r) => r.state),
    txId: record.outcome.txId,
    depthDaa: record.outcome.chain.depthDaa,
    observedOutputs: record.outcome.chain.outputs.length,
    verdict: verification === null ? null : verification.verdict,
    chainConfirmed: verification === null ? null : verification.chainConfirmed
  };
}

module.exports = {
  FORBIDDEN_TERMS,
  FORBIDDEN_PHRASES,
  LADDER_MEANING,
  forbiddenLanguageHits,
  assertNoForbiddenLanguage,
  humanReadable,
  structured,
  SANCTIONED_VOCABULARY: Object.freeze([
    "PolicyVault policy-execution attestation",
    "deterministic authorization evidence",
    "verified chain outcome"
  ]),
  LADDER: S.LADDER
};
