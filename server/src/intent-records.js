"use strict";

/*
 * Intent-manifest RECORDS (audit-correlation-spec §5.2 + completion-
 * standard item 7): at the point the server handles a manifest-bearing
 * flow (the v0.4 build routes — the only flows whose builder output the
 * intent bridge supports today), derive the Transaction Intent Manifest
 * from the REAL builder output (core/intent/bridge — never a rebuilt
 * fixture), run the fail-closed verifier, and persist ONE create-only
 * record keyed by the representation-independent manifestHash.
 *
 * The stored verdict is a RECORD of what the verifier said then; any
 * consumer that needs the truth NOW re-runs verifyIntentManifest on the
 * stored manifest (pure, deterministic) — the finalize/submit gate here
 * does exactly that. Verification claims are NEVER backfilled for
 * requests that predate manifest recording (spec §10): a request with
 * no manifestHash is a plain historical fact, not a failure.
 *
 * G-2 STANDING RULE (read side): whenever a stored manifest is loaded,
 * recompute computeManifestHashV1 over the stored body and compare to
 * the row key AND the embedded manifestHash; a mismatch fails closed as
 * an integrity alarm (tampering or a serialization defect — never
 * acceptable drift). manifestHash is canonical-JSON over VALUES, so
 * PostgreSQL jsonb key reordering cannot trip it — only real change can.
 */

const { getStore, Categories } = require("../../sdk/src/store");
const { appendAudit } = require("./audit"); // server audit = sdk audit + failure-isolated event hook
const { computeManifestHashV1, verifyIntentManifest } = require("../../core/intent");
const { deriveAndVerify } = require("../../core/intent/bridge/derive");

const MANIFEST_RECORD_SCHEMA = "policyvault-intent-manifest-record/v1";

function intentError(status, code, message, extra) {
  const e = new Error(message);
  e.status = status;
  e.code = code;
  if (extra) e.extra = extra;
  return e;
}

/*
 * Derive + verify + persist the manifest for one freshly built v0.4
 * request (transition or genesis). Returns
 *   { manifestHash, verdict, ok, record } on success;
 * on a REFUSED verdict the record IS stored (evidence of the refused
 * attempt, spec §5.2 note) and the caller decides how to refuse.
 * Create-only write: the hash is total over the body, so a lost race
 * is benign idempotence; the record is never updated.
 */
async function recordManifestForRequest(config, request, { proposalId = null } = {}) {
  const { manifest, verification } = deriveAndVerify({ build: request.build });
  const manifestHash = manifest.manifestHash;
  const { manifestHash: embedded, ...body } = manifest;
  void embedded;
  const recomputed = computeManifestHashV1(body);
  if (recomputed !== manifestHash) {
    // The bridge itself embeds the hash it computes; a mismatch here is
    // an internal defect and must never be persisted as evidence.
    throw intentError(500, "INTENT_HASH_INTERNAL_MISMATCH", "derived manifest hash does not recompute — refusing to record");
  }
  const record = {
    schema: MANIFEST_RECORD_SCHEMA,
    manifestHash,
    manifest,
    verification: {
      verdict: verification.verdict,
      ok: verification.ok === true,
      checks: verification.checks.map((c) => ({ id: c.id, ok: c.ok })),
      failureCodes: [...new Set((verification.failures ?? []).map((f) => f.code))].sort(),
      verifiedAt: new Date().toISOString(), // time lives HERE, never in the manifest
      verifierBuild: config.buildId ?? null
    },
    requestId: request.requestId,
    proposalId,
    vaultId: request.vaultId,
    networkId: config.networkId,
    txId: request.txId
  };
  /*
   * RC-LC-1: createExclusive() returning false is NEVER success — the
   * key is already occupied. Records are CONTENT-ADDRESSED by the
   * canonical manifest hash, so an occupied key means this EXACT
   * manifest is already recorded evidence, and any number of
   * byte-identical requests legitimately share it (the conformance
   * C05 multi-path-equivalence contract: the same intent built via
   * every path yields distinct durable requests carrying the same
   * transaction and the same manifest). The incumbent is loaded and
   * G-2-verified HERE, AT BUILD TIME — a record that does not re-hash
   * to its key is tampering and throws INTENT_MANIFEST_INTEGRITY
   * before any wallet signing can happen. Audit history tells the
   * truth: only a real first insert is "recorded"; a share names the
   * creating request; an idempotent same-request replay appends
   * nothing.
   */
  const store = getStore(config);
  let recordMode = "created";
  let sharedFromRequestId = null;
  const classify = (incumbent) => {
    if (incumbent.requestId === request.requestId) {
      recordMode = "reused";
    } else {
      recordMode = "shared";
      sharedFromRequestId = incumbent.requestId;
    }
  };
  const created = await store.createExclusive(Categories.INTENT_MANIFEST, manifestHash, record);
  if (!created) {
    const incumbent = await loadManifestRecord(config, manifestHash); // throws on G-2 divergence
    if (incumbent !== null) {
      classify(incumbent);
    } else {
      // Vanished between the refused insert and the read: re-arbitrate
      // once; losing again means an interleaved writer recreated it —
      // verify and share THAT copy.
      const retried = await store.createExclusive(Categories.INTENT_MANIFEST, manifestHash, record);
      if (!retried) {
        const recheck = await loadManifestRecord(config, manifestHash);
        if (recheck === null) {
          throw intentError(409, "INTENT_MANIFEST_INTEGRITY", "manifest record flapping during recording — failing closed");
        }
        classify(recheck);
      }
    }
  }
  if (recordMode !== "reused") {
    await appendAudit(config, {
      kind: "intent",
      vaultId: request.vaultId,
      action: request.action,
      actor: request.signerRole ?? "owner",
      actorXOnly: request.signerXOnly ?? null,
      contractVersion: request.contractVersion,
      result: verification.ok === true ? "INTENT_MANIFEST_VERIFIED" : "FAIL_CLOSED",
      detail:
        verification.ok !== true
          ? `intent manifest ${manifestHash.slice(0, 16)}… recorded with verdict ${verification.verdict} [${record.verification.failureCodes.join(", ")}]`
          : recordMode === "shared"
            ? `intent manifest ${manifestHash.slice(0, 16)}… content-identical record already exists (created by request ${sharedFromRequestId}) — shared as this request's evidence (VERIFIED_EXACT)`
            : `intent manifest ${manifestHash.slice(0, 16)}… recorded (VERIFIED_EXACT)`,
      requestId: request.requestId,
      manifestHash,
      ...(proposalId ? { proposalId } : {}),
      txId: request.txId
    });
  }
  return { manifestHash, verdict: verification.verdict, ok: verification.ok === true, record };
}

/*
 * Load one stored manifest record with the MANDATORY read-side
 * canonical re-hash check (G-2). Returns null when absent; throws
 * INTENT_MANIFEST_INTEGRITY on any hash divergence.
 */
async function loadManifestRecord(config, manifestHash) {
  if (typeof manifestHash !== "string" || !/^[0-9a-f]{64}$/.test(manifestHash)) return null;
  const record = await getStore(config).read(Categories.INTENT_MANIFEST, manifestHash);
  if (record === null) return null;
  if (record.schema !== MANIFEST_RECORD_SCHEMA) {
    throw intentError(422, "INTENT_RECORD_SCHEMA_UNKNOWN", `stored manifest record has unknown schema ${JSON.stringify(record.schema)} — failing closed`);
  }
  const manifest = record.manifest;
  if (!manifest || typeof manifest !== "object") {
    throw intentError(409, "INTENT_MANIFEST_INTEGRITY", "stored manifest record carries no manifest — integrity alarm");
  }
  const { manifestHash: embedded, ...body } = manifest;
  let recomputed;
  try {
    recomputed = computeManifestHashV1(body);
  } catch (e) {
    throw intentError(409, "INTENT_MANIFEST_INTEGRITY", `stored manifest does not canonicalize (${e.message}) — integrity alarm, failing closed`);
  }
  if (recomputed !== manifestHash || embedded !== manifestHash || record.manifestHash !== manifestHash) {
    throw intentError(
      409,
      "INTENT_MANIFEST_INTEGRITY",
      "stored manifest re-hash does not match its row key — tampering or a serialization defect; failing closed and raising an integrity alarm"
    );
  }
  return record;
}

/*
 * The finalize/submit-time gate: a request stamped with a manifestHash
 * must resolve to a stored record whose manifest, RE-VERIFIED NOW
 * (never merely the recorded verdict), passes VERIFIED_EXACT. Requests
 * without a manifestHash predate manifest recording and pass unchanged
 * (backward compatibility, spec §10 — never backfilled, never blocked).
 */
async function assertRequestManifestVerified(config, request) {
  if (request && request.intentRecording === "FAILED") {
    // Manifest DERIVATION failed at build: never mistakable for a
    // request that predates manifest recording — fail closed.
    throw intentError(409, "INTENT_VERIFICATION_FAILED", "intent-manifest derivation failed for this request at build — refusing to finalize/submit");
  }
  if (!request || typeof request.manifestHash !== "string") return null; // predates recording
  const record = await loadManifestRecord(config, request.manifestHash);
  if (record === null) {
    throw intentError(409, "INTENT_MANIFEST_MISSING", "this request references an intent-manifest record that no longer exists — integrity alarm, failing closed");
  }
  if (record.vaultId !== request.vaultId) {
    throw intentError(409, "INTENT_MANIFEST_INTEGRITY", "the stored manifest record does not belong to this request's vault — failing closed");
  }
  /* CONTENT binding (RC-LC-1 v2): byte-identical requests legitimately
   * SHARE the content-addressed record (conformance C05), so creator
   * identity is provenance, not a gate. What must never pass is a
   * request whose stamped hash resolves to a manifest describing a
   * DIFFERENT transaction (the hostile repoint): the manifest's
   * committed txId is the exact content anchor — the request's own
   * frozen txId must equal it, or this is not its manifest. */
  if (!record.manifest || !record.manifest.transaction || record.manifest.transaction.txId !== request.txId) {
    throw intentError(409, "INTENT_MANIFEST_INTEGRITY", "the stored manifest record does not describe this request's transaction — failing closed");
  }
  const verification = verifyIntentManifest({ manifest: record.manifest });
  if (verification.ok !== true) {
    throw intentError(
      409,
      "INTENT_VERIFICATION_FAILED",
      `the recorded intent manifest no longer verifies (${verification.verdict}) — refusing to finalize/submit`,
      { intent: { manifestHash: record.manifestHash, failureCodes: [...new Set(verification.failures.map((f) => f.code))].sort() } }
    );
  }
  return record;
}

module.exports = {
  MANIFEST_RECORD_SCHEMA,
  recordManifestForRequest,
  loadManifestRecord,
  assertRequestManifestVerified
};
