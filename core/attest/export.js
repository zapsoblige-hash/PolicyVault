"use strict";

/*
 * policyvault-execution-attestation/1 — DETERMINISTIC EXPORT FORMATS.
 *
 * Two formats, both byte-deterministic and both self-describing:
 *
 *  1. CANONICAL JSON (primary, one record). Exactly the bytes the record
 *     hash commits to, plus the envelope: canonicalJsonStringify over the
 *     whole record. Re-exporting a record anywhere in the world yields the
 *     same bytes, so an export can be diffed, hashed, checksummed, or
 *     pinned in a ticket without a normalization argument.
 *
 *  2. LINE-DELIMITED BATCH (NDJSON, one canonical record per line, "\n"
 *     terminated). Every line is a COMPLETE, independently verifiable
 *     attestation carrying its own version string — so a batch can be
 *     streamed, split, grepped, or verified line-by-line, and a truncated
 *     batch degrades into a smaller valid batch instead of an ambiguous
 *     document. There is deliberately NO batch header: a header would be
 *     a second, weaker place for a version to live and a tempting place
 *     to put a summary that nothing verifies.
 *
 * A batch's own identity, when one is wanted, is computeBatchDigest():
 * sha256 over a canonical document naming the batch version and the
 * ordered record hashes. It commits to CONTENT AND ORDER without
 * re-hashing megabytes of JSON.
 *
 * READ SIDE, FAIL CLOSED: parsing checks the exact version string of every
 * record (unknown version => refuse, never routed to a default reader),
 * rejects trailing garbage, rejects duplicate/blank lines, and never
 * silently drops a line it could not understand.
 */

const { canonicalJsonStringify, sha256Hex } = require("./canonical");
const S = require("./schema");

const BATCH_DIGEST_DOMAIN_V1 = "policyvault-execution-attestation-batch-digest/1\n";

class AttestationExportError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "AttestationExportError";
    this.code = code;
  }
}

function requireVersion(record, where) {
  if (!S.isPlainObject(record)) {
    throw new AttestationExportError("ATTESTATION_SCHEMA_INVALID", `${where}: not a JSON object`);
  }
  if (record.attestationVersion !== S.ATTESTATION_VERSION_1) {
    throw new AttestationExportError(
      "ATTESTATION_VERSION_UNSUPPORTED",
      `${where}: this build reads exactly ${S.ATTESTATION_VERSION_1}; got ${JSON.stringify(record.attestationVersion)} — failing closed`
    );
  }
  return record;
}

/* One record -> canonical JSON text (no trailing newline). */
function exportAttestationJson(record) {
  requireVersion(record, "export");
  return canonicalJsonStringify(record);
}

/* Canonical JSON text -> record (version-checked; nothing else assumed). */
function parseAttestationJson(text) {
  if (typeof text !== "string" || text.trim().length === 0) {
    throw new AttestationExportError("ATTESTATION_SCHEMA_INVALID", "attestation JSON text is required");
  }
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch (e) {
    throw new AttestationExportError("ATTESTATION_SCHEMA_INVALID", `not valid JSON: ${e.message}`);
  }
  return requireVersion(parsed, "parse");
}

/* Many records -> NDJSON text (one canonical record per line, newline-terminated). */
function exportAttestationBatchNdjson(records) {
  if (!Array.isArray(records)) {
    throw new AttestationExportError("ATTESTATION_SCHEMA_INVALID", "batch export needs an array of records");
  }
  let out = "";
  for (const [i, record] of records.entries()) {
    requireVersion(record, `export line ${i + 1}`);
    const line = canonicalJsonStringify(record);
    if (line.includes("\n")) {
      /* canonicalJsonStringify escapes control characters, so this is a
       * defence against a future serializer change, not a live case. */
      throw new AttestationExportError("ATTESTATION_SCHEMA_INVALID", `export line ${i + 1} contains a raw newline`);
    }
    out += `${line}\n`;
  }
  return out;
}

/*
 * NDJSON text -> records[]. Every line must be a complete record of the
 * exact supported version. Blank lines, trailing garbage and unparseable
 * lines are REFUSED, never skipped: a verifier that silently drops lines
 * would report "all records valid" over a batch it did not fully read.
 */
function parseAttestationBatchNdjson(text) {
  if (typeof text !== "string") {
    throw new AttestationExportError("ATTESTATION_SCHEMA_INVALID", "batch text is required");
  }
  const body = text.endsWith("\n") ? text.slice(0, -1) : text;
  if (body.length === 0) return [];
  const lines = body.split("\n");
  const records = [];
  for (const [i, line] of lines.entries()) {
    if (line.trim().length === 0) {
      throw new AttestationExportError("ATTESTATION_SCHEMA_INVALID", `batch line ${i + 1} is blank — refusing to skip it`);
    }
    let parsed;
    try {
      parsed = JSON.parse(line);
    } catch (e) {
      throw new AttestationExportError("ATTESTATION_SCHEMA_INVALID", `batch line ${i + 1} is not valid JSON: ${e.message}`);
    }
    records.push(requireVersion(parsed, `batch line ${i + 1}`));
  }
  return records;
}

/*
 * A batch's identity: commits to the ordered record hashes, so reordering
 * or removing a record changes the digest. Not a substitute for verifying
 * each record — it says nothing about whether any record is valid.
 */
function computeBatchDigest(records) {
  if (!Array.isArray(records)) {
    throw new AttestationExportError("ATTESTATION_SCHEMA_INVALID", "batch digest needs an array of records");
  }
  const hashes = records.map((r, i) => {
    requireVersion(r, `batch digest entry ${i + 1}`);
    if (typeof r.attestationHash !== "string" || !/^[0-9a-f]{64}$/.test(r.attestationHash)) {
      throw new AttestationExportError("ATTESTATION_SCHEMA_INVALID", `batch digest entry ${i + 1} carries no record hash`);
    }
    return r.attestationHash;
  });
  return sha256Hex(
    BATCH_DIGEST_DOMAIN_V1 +
      canonicalJsonStringify({ batchVersion: S.BATCH_VERSION_1, count: hashes.length, recordHashes: hashes })
  );
}

module.exports = {
  BATCH_DIGEST_DOMAIN_V1,
  AttestationExportError,
  exportAttestationJson,
  parseAttestationJson,
  exportAttestationBatchNdjson,
  parseAttestationBatchNdjson,
  computeBatchDigest
};
