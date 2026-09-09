"use strict";

/*
 * policyvault-execution-attestation/1 — VERIFIER CORE.
 *
 * Pure, portable, deterministic. This is the SAME code the standalone CLI
 * (tools/attestation-verify.js), the server, the browser bundle and mobile
 * run: there is exactly one verifier, and it does not depend on the hosted
 * UI, the hosted API, or any indexer.
 *
 * Three independent layers, never collapsed into one boolean:
 *
 *  1. STRUCTURE  — schema (exact version match, closed key sets, numeric
 *     safety) + canonical RE-HASH equality + cross-field consistency
 *     (ladder monotonicity, refusal implies no txid, VERIFIED_OUTCOME
 *     implies CHAIN_VERIFIED, disposition agreement, approval quorum,
 *     network/txid/asset binding). Offline, no node, no network.
 *
 *  2. EXPECTATION BINDING (optional) — "is this the attestation I asked
 *     for?" A caller may pin vaultId / networkId / requestId / txId /
 *     contractVersion. This is how a substituted-but-internally-consistent
 *     record (wrong vault, re-hashed after tampering) is caught without
 *     trusting the issuer.
 *
 *  3. CHAIN FACTS (optional, opt-in) — re-check the record's declared
 *     chain observations against a verified Kaspa node. checkChainFacts()
 *     is PURE: the caller supplies the node observation; core/attest never
 *     opens a socket. A node that is unavailable, on the wrong network, or
 *     that simply does not show the declared outputs yields UNCONFIRMED /
 *     UNAVAILABLE — NEVER a confirmation. Only exact agreement confirms.
 *
 * The overall verdict vocabulary contains exactly one confirming value,
 * CHAIN_CONFIRMED, and it is reachable only through layer 3.
 */

const { attestationBodyOf, computeAttestationHashV1, sha256Hex } = require("./canonical");
const S = require("./schema");

const VERDICTS = Object.freeze({
  INVALID: "ATTESTATION_INVALID",
  STRUCTURE_VERIFIED: "STRUCTURE_VERIFIED",
  CHAIN_CONFIRMED: "CHAIN_CONFIRMED",
  CHAIN_UNCONFIRMED: "CHAIN_UNCONFIRMED",
  CHAIN_UNAVAILABLE: "CHAIN_UNAVAILABLE",
  CHAIN_CONTRADICTED: "CHAIN_CONTRADICTED"
});

const CHAIN_STATUS = Object.freeze({
  NOT_CHECKED: "NOT_CHECKED",
  NOT_APPLICABLE: "NOT_APPLICABLE",
  CONFIRMED: "CONFIRMED",
  UNCONFIRMED: "UNCONFIRMED",
  UNAVAILABLE: "UNAVAILABLE",
  CONTRADICTED: "CONTRADICTED"
});

/* ------------------------------------------------------------------ */
/* layer 1b — cross-field consistency                                  */
/* ------------------------------------------------------------------ */

function reachedStates(record) {
  return record.outcome.reached.map((r) => r.state);
}

function checkConsistency(record, f) {
  const { subject, action, authorization, approvals, asset, outcome } = record;
  const states = reachedStates(record);
  const has = (s) => states.includes(s);

  /* --- the ladder is a contiguous PREFIX, in order, without repeats --- */
  const expectedPrefix = S.LADDER.slice(0, states.length);
  if (states.join(">") !== expectedPrefix.join(">")) {
    f.add(
      "LADDER_ORDER_INVALID",
      "outcome.reached",
      `reached states must be a contiguous prefix of ${S.LADDER.join(" -> ")}; got ${states.join(" -> ") || "(empty)"}`
    );
  }
  /* Explicit, separately-coded restatement of the single most important
   * ladder rule (defence in depth + precise classification in reports). */
  if (has("VERIFIED_OUTCOME") && !has("CHAIN_VERIFIED")) {
    f.add("VERIFIED_OUTCOME_WITHOUT_CHAIN_VERIFIED", "outcome.reached", "VERIFIED_OUTCOME can never be claimed without CHAIN_VERIFIED");
  }
  const last = states.length === 0 ? "REFUSED" : states[states.length - 1];
  if (outcome.state !== last) {
    f.add("LADDER_STATE_MISMATCH", "outcome.state", `outcome.state ${JSON.stringify(outcome.state)} does not equal the highest reached state ${JSON.stringify(last)}`);
  }

  /* --- refusal semantics --- */
  if (authorization.decision === "REFUSED") {
    if (states.length !== 0) f.add("REFUSAL_WITH_LADDER", "outcome.reached", "a REFUSED authorization reaches no ladder state");
    if (outcome.txId !== null) f.add("REFUSAL_WITH_TXID", "outcome.txId", "a REFUSED authorization can never carry a transaction id");
    if (authorization.refusalCode === null) f.add("REFUSAL_WITHOUT_CODE", "authorization.refusalCode", "a REFUSED authorization must name its machine-readable refusal code");
    if (outcome.disposition !== "REFUSED") f.add("DISPOSITION_INCONSISTENT", "outcome.disposition", "a REFUSED authorization has disposition REFUSED");
    /* A REFUSED execution may legitimately carry a VERIFIED_EXACT intent
     * verdict: the transaction bytes can match the described intent
     * exactly while PolicyVault still refuses on authority, quorum,
     * freshness or a claim conflict. What is impossible is refusing FOR
     * a failed intent verification while reporting that it passed. */
    if (authorization.refusalCode === "INTENT_VERIFICATION_FAILED" && authorization.intentManifestVerdict === "VERIFIED_EXACT") {
      f.add("MANIFEST_VERDICT_INCONSISTENT", "authorization.intentManifestVerdict", "the refusal names a failed intent verification, but the recorded verdict says VERIFIED_EXACT");
    }
  } else {
    if (states.length === 0) f.add("AUTHORIZED_WITHOUT_LADDER", "outcome.reached", "an AUTHORIZED decision reaches at least AUTHORIZED");
    if (authorization.refusalCode !== null) f.add("AUTHORIZED_WITH_REFUSAL_CODE", "authorization.refusalCode", "an AUTHORIZED decision carries no refusal code");
    if (outcome.disposition === "REFUSED") f.add("DISPOSITION_INCONSISTENT", "outcome.disposition", "disposition REFUSED requires decision REFUSED");
    if (authorization.intentManifestVerdict === "REFUSED") {
      f.add("MANIFEST_VERDICT_INCONSISTENT", "authorization.intentManifestVerdict", "an AUTHORIZED decision cannot rest on a REFUSED intent-manifest verdict");
    }
    if (authorization.intentManifestHash === S.NOT_AVAILABLE) {
      /* Honest historical seam: requests that predate intent-manifest
       * recording carry no hash. Never backfilled, never fabricated —
       * and never silently presented as if verified. */
      f.warn("INTENT_MANIFEST_NOT_RECORDED", "authorization.intentManifestHash", "this execution predates intent-manifest recording — no manifest evidence exists and none was synthesized");
    }
  }

  /* --- disposition agreement --- */
  if (outcome.disposition === "SETTLED" && !has("CHAIN_VERIFIED")) {
    f.add("DISPOSITION_INCONSISTENT", "outcome.disposition", "SETTLED requires CHAIN_VERIFIED");
  }
  if (outcome.disposition === "FAILED" && has("CHAIN_VERIFIED")) {
    f.add("DISPOSITION_INCONSISTENT", "outcome.disposition", "a CHAIN_VERIFIED execution is not FAILED");
  }
  if ((outcome.disposition === "FAILED" || outcome.disposition === "UNKNOWN") && outcome.failureCode === null) {
    f.add("DISPOSITION_INCONSISTENT", "outcome.failureCode", `disposition ${outcome.disposition} must name a failure/unknown code`);
  }
  if (outcome.disposition === "SETTLED" && outcome.failureCode !== null) {
    f.add("DISPOSITION_INCONSISTENT", "outcome.failureCode", "a SETTLED execution carries no failure code");
  }

  /* --- evidence each ladder rung actually requires --- */
  if (has("SIGNED")) {
    /* A ladder rung may never be claimed without the evidence that
     * DEFINES it. SIGNED is defined by "an external signer returned a
     * signature for this exact transaction": the signing IDENTITY is
     * therefore mandatory. The signer-visible digest is corroborating
     * detail — a covenant transition always has one and the server
     * builder emits it, but a genesis spends ordinary fuel and has none,
     * and an imported historical transcript may never have captured one.
     * A gap there is reported, never a licence to fabricate a digest. */
    if (authorization.signerXOnly === S.NOT_AVAILABLE) {
      f.add("SIGNED_WITHOUT_SIGNER_EVIDENCE", "authorization.signerXOnly", "SIGNED requires the signing identity's x-only public key");
    }
    if (authorization.signerVisibleDigest === S.NOT_AVAILABLE) {
      f.warn("SIGNER_DIGEST_NOT_RECORDED", "authorization.signerVisibleDigest", "the source record does not carry the exact digest the signer was shown; none was synthesized");
    }
  }
  if (has("BROADCAST") && outcome.txId === null) {
    f.add("BROADCAST_WITHOUT_TXID", "outcome.txId", "BROADCAST requires the frozen transaction id");
  }
  if (has("CHAIN_SEEN") && outcome.chain.outputs.length === 0) {
    f.add("CHAIN_SEEN_WITHOUT_OUTPUTS", "outcome.chain.outputs", "CHAIN_SEEN requires at least one observed output");
  }
  if (has("CHAIN_VERIFIED")) {
    /* HARD: without the exact observed outputs there is nothing a reader
     * could re-check, so the claim would be unfalsifiable. */
    if (outcome.chain.outputs.length === 0) {
      f.add("CHAIN_VERIFIED_WITHOUT_EVIDENCE", "outcome.chain.outputs", "CHAIN_VERIFIED requires the exact observed outputs a reader can re-check");
    }
    /* SOFT: the accepting block's DAA score is depth metadata. PolicyVault's
     * v0.4 receipts do not persist it today, and inventing one would be
     * exactly the fabrication this schema exists to prevent — so its
     * absence is reported, not treated as a failed proof. */
    if (outcome.chain.acceptingBlockDaaScore === null) {
      f.warn("ACCEPTING_DAA_NOT_RECORDED", "outcome.chain.acceptingBlockDaaScore", "the source records do not carry the accepting block's DAA score, so this attestation states no confirmation depth");
    }
  }

  /* --- transaction identity binding --- */
  if (outcome.chain.successorOutpoint !== null && outcome.txId !== null && outcome.chain.successorOutpoint.transactionId !== outcome.txId) {
    f.add("TXID_MISMATCH", "outcome.chain.successorOutpoint.transactionId", "the successor outpoint does not belong to this attestation's transaction");
  }
  if (outcome.chain.predecessorOutpoint !== null && outcome.txId !== null && outcome.chain.predecessorOutpoint.transactionId === outcome.txId) {
    f.add("TXID_MISMATCH", "outcome.chain.predecessorOutpoint.transactionId", "the consumed predecessor outpoint cannot belong to this transaction");
  }

  /* --- network binding --- */
  if (outcome.networkId !== subject.networkId) {
    f.add("NETWORK_MISMATCH", "outcome.networkId", `chain observations are on ${outcome.networkId} but the subject is on ${subject.networkId}`);
  }

  /* --- depth arithmetic (integers only) --- */
  const c = outcome.chain;
  if (c.acceptingBlockDaaScore !== null && c.observedVirtualDaaScore !== null && c.depthDaa !== null) {
    const accepted = BigInt(c.acceptingBlockDaaScore);
    const observed = BigInt(c.observedVirtualDaaScore);
    if (observed < accepted) {
      f.add("DEPTH_ARITHMETIC_INVALID", "outcome.chain", "the observed virtual DAA score precedes the accepting block's DAA score");
    } else if (observed - accepted !== BigInt(c.depthDaa)) {
      f.add("DEPTH_ARITHMETIC_INVALID", "outcome.chain.depthDaa", "depthDaa != observedVirtualDaaScore - acceptingBlockDaaScore");
    }
  }
  if (has("CHAIN_VERIFIED") && c.minDepthDaa !== null && c.depthDaa !== null && BigInt(c.depthDaa) < BigInt(c.minDepthDaa)) {
    f.add("DEPTH_BELOW_MINIMUM", "outcome.chain.depthDaa", `observed depth ${c.depthDaa} is below the declared minimum ${c.minDepthDaa} — this is CHAIN_SEEN, not CHAIN_VERIFIED`);
  }

  /* --- approvals / quorum --- */
  const required = BigInt(approvals.required);
  const collected = BigInt(approvals.collected);
  if (collected !== BigInt(approvals.approvalDigests.length)) {
    f.add("APPROVALS_COUNT_MISMATCH", "approvals.collected", `collected ${approvals.collected} != ${approvals.approvalDigests.length} approval digests`);
  }
  for (const [i, d] of approvals.approvalDigests.entries()) {
    if (typeof d?.approverXOnly === "string" && !approvals.approverSlots.includes(d.approverXOnly)) {
      f.add("APPROVER_SLOT_UNKNOWN", `approvals.approvalDigests[${i}].approverXOnly`, "an approval is attributed to a key that is not in the covenant approver set");
    }
  }
  if (action.aboveThreshold && has("SIGNED")) {
    if (required < 1n) f.add("APPROVALS_INSUFFICIENT", "approvals.required", "an above-threshold execution requires at least one approval slot");
    if (collected < required) {
      f.add("APPROVALS_INSUFFICIENT", "approvals.collected", `above-threshold execution signed with ${collected} of ${required} required approvals`);
    }
  }
  if (!action.aboveThreshold && collected > 0n) {
    f.warn("APPROVALS_PRESENT_BELOW_THRESHOLD", "approvals.collected", "approvals recorded for an execution the policy did not require approvals for");
  }

  /* --- asset binding against the observed outputs --- */
  if (asset.kind === "TOKEN" && asset.familyId !== null && outcome.chain.outputs.length > 0) {
    const seen = outcome.chain.outputs.some((o) => o.covenantId === asset.familyId);
    if (!seen) {
      f.add("ASSET_FAMILY_NOT_OBSERVED", "asset.familyId", "no observed output carries the attested token family covenant id");
    }
  }
  if (asset.kind === "KAS" && asset.unit !== "sompi") {
    f.add("ASSET_SHAPE_INVALID", "asset.unit", "KAS is denominated in sompi");
  }

  /* --- detached signature slot: present is never verified --- */
  if (record.signature !== null) {
    f.warn(
      "SIGNATURE_PRESENT_UNVERIFIED",
      "signature",
      "a detached signature is attached but NO attestation-key verifier exists; the record's authority comes from its chain-verifiable facts, not from this slot"
    );
  }
}

/* ------------------------------------------------------------------ */
/* layer 2 — expectation binding                                       */
/* ------------------------------------------------------------------ */

const EXPECTATIONS = Object.freeze({
  vaultId: ["subject", "vaultId", "EXPECTED_VAULT_MISMATCH"],
  networkId: ["subject", "networkId", "EXPECTED_NETWORK_MISMATCH"],
  requestId: ["subject", "requestId", "EXPECTED_REQUEST_MISMATCH"],
  contractVersion: ["subject", "contractVersion", "EXPECTED_CONTRACT_VERSION_MISMATCH"],
  txId: ["outcome", "txId", "EXPECTED_TXID_MISMATCH"]
});

function checkExpectations(record, expect, f) {
  if (expect === null || expect === undefined) return;
  if (!S.isPlainObject(expect)) {
    f.add("SCHEMA_INVALID", "$expect", "expectation binding must be a plain object");
    return;
  }
  for (const key of Object.keys(expect)) {
    const spec = EXPECTATIONS[key];
    if (!spec) {
      f.add("EXPECTATION_UNKNOWN", `$expect.${key}`, `unknown expectation ${JSON.stringify(key)} — failing closed rather than ignoring a pin the caller believed was enforced`);
      continue;
    }
    const [section, field, code] = spec;
    const actual = record[section]?.[field];
    if (actual !== expect[key]) {
      f.add(code, `${section}.${field}`, `expected ${JSON.stringify(expect[key])}, attestation carries ${JSON.stringify(actual)}`);
    }
  }
}

/* ------------------------------------------------------------------ */
/* layer 3 — chain facts (PURE; the caller supplies the observation)   */
/* ------------------------------------------------------------------ */

/*
 * observation = {
 *   available: boolean,
 *   reason: string|null,                      // why unavailable
 *   node: { networkId, isSynced, hasUtxoIndex, virtualDaaScore } | null,
 *   utxos: { "<address>": [ { outpoint:{transactionId,index},
 *                             amountSompi, covenantId, blockDaaScore } ] }
 * }
 *
 * Never confirms on absence. A declared output that is NOT in the UTXO set
 * is UNCONFIRMED (it may legitimately have been spent by a later covenant
 * transition), never falsified and never confirmed. A declared output that
 * IS present but disagrees on value / covenant id / accepting DAA score is
 * a CONTRADICTION — the attestation says something the chain refutes.
 */
function checkChainFacts(record, observation) {
  const checks = [];
  const findings = [];
  const note = (id, ok, detail) => checks.push({ id, ok, detail });

  const outputs = record.outcome?.chain?.outputs ?? [];
  const states = record.outcome?.reached?.map((r) => r.state) ?? [];
  if (!states.includes("CHAIN_SEEN") || outputs.length === 0) {
    return {
      status: CHAIN_STATUS.NOT_APPLICABLE,
      checks: [{ id: "applicable", ok: false, detail: "this attestation declares no observed chain outputs to re-check" }],
      findings: []
    };
  }
  if (!observation || observation.available !== true || !observation.node) {
    const reason = observation?.reason ?? "NODE_UNAVAILABLE";
    note("node.available", false, reason);
    findings.push({ code: "NODE_UNAVAILABLE", detail: reason });
    return { status: CHAIN_STATUS.UNAVAILABLE, checks, findings };
  }
  const node = observation.node;
  note("node.available", true, "verified node observation supplied");
  if (node.networkId !== record.outcome.networkId) {
    note("node.network", false, `node is on ${node.networkId}, attestation is on ${record.outcome.networkId}`);
    findings.push({ code: "NODE_WRONG_NETWORK", detail: `${node.networkId} != ${record.outcome.networkId}` });
    return { status: CHAIN_STATUS.UNAVAILABLE, checks, findings };
  }
  note("node.network", true, node.networkId);
  if (node.isSynced !== true || node.hasUtxoIndex !== true) {
    note("node.usable", false, `isSynced=${node.isSynced} hasUtxoIndex=${node.hasUtxoIndex}`);
    findings.push({ code: "NODE_NOT_USABLE", detail: "an unsynced node or one without a UTXO index can never confirm an outcome" });
    return { status: CHAIN_STATUS.UNAVAILABLE, checks, findings };
  }
  note("node.usable", true, "synced with utxoindex");

  const utxos = observation.utxos ?? {};
  let contradicted = false;
  let unconfirmed = 0;
  for (const out of outputs) {
    const id = `output[${out.index}]`;
    const entries = utxos[out.address];
    if (!Array.isArray(entries)) {
      unconfirmed += 1;
      note(id, false, "no UTXO listing supplied for this address");
      findings.push({ code: "OUTPUT_ADDRESS_NOT_QUERIED", detail: `${out.address} was not queried` });
      continue;
    }
    const match = entries.find(
      (e) => e?.outpoint?.transactionId === record.outcome.txId && Number(e?.outpoint?.index) === Number(out.index)
    );
    if (!match) {
      unconfirmed += 1;
      note(id, false, "not present in the current UTXO set (spent by a later transition, or never existed) — cannot confirm");
      findings.push({ code: "OUTPUT_NOT_IN_UTXO_SET", detail: `${record.outcome.txId}:${out.index} at ${out.address}` });
      continue;
    }
    const disagreements = [];
    if (String(match.amountSompi) !== out.valueSompi) disagreements.push(`value ${match.amountSompi} != ${out.valueSompi}`);
    const observedCovenant = match.covenantId ?? null;
    if (observedCovenant !== out.covenantId) disagreements.push(`covenantId ${observedCovenant} != ${out.covenantId}`);
    if (out.blockDaaScore !== null && match.blockDaaScore !== null && match.blockDaaScore !== undefined && String(match.blockDaaScore) !== out.blockDaaScore) {
      disagreements.push(`blockDaaScore ${match.blockDaaScore} != ${out.blockDaaScore}`);
    }
    if (disagreements.length > 0) {
      contradicted = true;
      note(id, false, disagreements.join("; "));
      findings.push({ code: "OUTPUT_CONTRADICTED", detail: `${record.outcome.txId}:${out.index} — ${disagreements.join("; ")}` });
      continue;
    }
    note(id, true, `exact match at ${out.address}`);
  }

  if (contradicted) return { status: CHAIN_STATUS.CONTRADICTED, checks, findings };
  if (unconfirmed > 0) return { status: CHAIN_STATUS.UNCONFIRMED, checks, findings };
  return { status: CHAIN_STATUS.CONFIRMED, checks, findings };
}

/*
 * The exact set of addresses an independent verifier must query to
 * re-check this attestation. Deterministic, de-duplicated, sorted — a CLI
 * or a browser can drive a read-only node from this alone.
 */
function addressesToQuery(record) {
  const out = new Set();
  for (const o of record?.outcome?.chain?.outputs ?? []) {
    if (typeof o?.address === "string") out.add(o.address);
  }
  return [...out].sort();
}

/* ------------------------------------------------------------------ */
/* the one entry point                                                 */
/* ------------------------------------------------------------------ */

function verifyAttestation(record, { expect = null, chainObservation = null } = {}) {
  const f = new S.Failures();
  S.checkShape(record, f);

  /* Canonical re-hash: the identity of the record is a function of its
   * VALUES, so a PostgreSQL jsonb round trip re-hashes identically and
   * only a real change trips it (the G-2 standing rule). */
  let recomputed = null;
  if (f.ok) {
    try {
      recomputed = computeAttestationHashV1(attestationBodyOf(record));
    } catch (e) {
      f.add("ATTESTATION_NOT_CANONICAL", "$", `the record does not canonicalize (${e.message}) — failing closed`);
    }
    if (recomputed !== null && recomputed !== record.attestationHash) {
      f.add("HASH_MISMATCH", "attestationHash", "the record does not re-hash to its claimed identity — tampering, truncation, or a serialization defect");
    }
  }
  if (f.ok) checkConsistency(record, f);
  checkExpectations(record, expect, f);

  const structural = { ok: f.ok, failures: f.failures, warnings: f.warnings };

  let chain = { status: CHAIN_STATUS.NOT_CHECKED, checks: [], findings: [] };
  if (structural.ok && chainObservation !== null) {
    chain = checkChainFacts(record, chainObservation);
  }

  let verdict;
  if (!structural.ok) verdict = VERDICTS.INVALID;
  else if (chain.status === CHAIN_STATUS.CONFIRMED) verdict = VERDICTS.CHAIN_CONFIRMED;
  else if (chain.status === CHAIN_STATUS.CONTRADICTED) verdict = VERDICTS.CHAIN_CONTRADICTED;
  else if (chain.status === CHAIN_STATUS.UNCONFIRMED) verdict = VERDICTS.CHAIN_UNCONFIRMED;
  else if (chain.status === CHAIN_STATUS.UNAVAILABLE) verdict = VERDICTS.CHAIN_UNAVAILABLE;
  else verdict = VERDICTS.STRUCTURE_VERIFIED;

  return {
    verifierVersion: S.VERIFIER_VERSION_1,
    verdict,
    /* Exactly one boolean may ever mean "the chain agrees". */
    chainConfirmed: verdict === VERDICTS.CHAIN_CONFIRMED,
    attestationHash: record?.attestationHash ?? null,
    recomputedHash: recomputed,
    structural,
    chain,
    signature: {
      present: record?.signature != null,
      verified: false,
      reason: record?.signature != null ? "ATTESTATION_KEY_VERIFICATION_NOT_IMPLEMENTED" : "NO_SIGNATURE_ATTACHED"
    },
    failureCodes: [...new Set(structural.failures.map((x) => x.code))].sort()
  };
}

/* sha256 of a lowercase-hex signature, the only approval material an
 * attestation ever carries (schema.js §approvals explains why). */
function approvalSignatureDigest(signatureHex) {
  if (typeof signatureHex !== "string" || !/^(?:[0-9a-f]{2})+$/.test(signatureHex)) {
    const e = new Error("attest-verify: approval signature must be lowercase even-length hex");
    e.code = "ATTESTATION_INPUT_INVALID";
    throw e;
  }
  return sha256Hex(signatureHex);
}

module.exports = {
  VERDICTS,
  CHAIN_STATUS,
  EXPECTATIONS,
  verifyAttestation,
  checkChainFacts,
  addressesToQuery,
  approvalSignatureDigest
};
