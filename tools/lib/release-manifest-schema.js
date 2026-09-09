"use strict";

/*
 * Closed schema for `policyvault-release-manifest/1` (TRACK 9 — release
 * signing; docs/postlaunch/release-trust-model.md). Shared by
 * tools/release-manifest.js (builds one) and tools/release-verify.js
 * (validates one) so the two can never silently drift apart.
 *
 * Versioning discipline (CLAUDE.md "Versioning / fail-closed"): an unknown
 * `schema` value FAILS CLOSED — it is never routed to a default parser.
 * A manifest with any top-level key outside this closed list is refused
 * outright ("unknown fields refused"), not merely ignored.
 */

const { canonicalJsonStringify } = require("../../core/model/canonical-json");

const MANIFEST_SCHEMA = "policyvault-release-manifest/1";

/* Exact closed set of top-level manifest fields. */
const MANIFEST_FIELDS = ["schema", "version", "releaseTimestamp", "sourceCommit", "treeHash", "archiveSha256", "imageDigest", "baseImageDigest", "covenants", "dependencies", "generator"];

function schemaError(message) {
  const e = new Error(`release-manifest: ${message}`);
  e.code = "RELEASE_MANIFEST_INVALID";
  return e;
}

/* Bytes that get hashed/signed for a manifest object: the canonical JSON
 * form (storage-order-independent — core/model/canonical-json.js) plus a
 * single trailing newline. This is the ONLY byte form `ssh-keygen -Y sign`
 * ever signs and `-Y verify` ever checks for this tool family. */
function manifestBytes(manifestObject) {
  return Buffer.from(canonicalJsonStringify(manifestObject) + "\n", "utf8");
}

/* Structural validation only (closed fields, exact schema string, basic
 * shape). Does NOT check signatures and does NOT re-hash anything against
 * a tree/artifact — see tools/release-verify.js for that. Throws
 * RELEASE_MANIFEST_INVALID on any violation (fail closed, never partial). */
function assertManifestShape(manifest) {
  if (!manifest || typeof manifest !== "object" || Array.isArray(manifest)) {
    throw schemaError("manifest must be a JSON object");
  }
  const keys = Object.keys(manifest);
  for (const k of keys) {
    if (!MANIFEST_FIELDS.includes(k)) {
      throw schemaError(`unknown manifest field ${JSON.stringify(k)} — refusing (unknown fields are never silently accepted)`);
    }
  }
  if (manifest.schema !== MANIFEST_SCHEMA) {
    const e = schemaError(`unknown manifest schema ${JSON.stringify(manifest.schema)} — this tool only understands ${JSON.stringify(MANIFEST_SCHEMA)}; failing closed rather than guessing`);
    e.code = "RELEASE_MANIFEST_UNKNOWN_VERSION";
    throw e;
  }
  const required = ["version", "releaseTimestamp", "sourceCommit", "treeHash", "covenants", "dependencies", "generator"];
  for (const k of required) {
    if (!(k in manifest)) throw schemaError(`missing required field ${JSON.stringify(k)}`);
  }
  if (typeof manifest.version !== "string" || !manifest.version || manifest.version.length > 200) {
    throw schemaError("version must be a non-empty string (<=200 chars)");
  }
  if (typeof manifest.releaseTimestamp !== "string" || new Date(manifest.releaseTimestamp).toISOString() !== manifest.releaseTimestamp) {
    throw schemaError("releaseTimestamp must be a canonical ISO-8601 UTC string (matches Date#toISOString())");
  }
  if (typeof manifest.treeHash !== "string" || !/^[0-9a-f]{64}$/.test(manifest.treeHash)) {
    throw schemaError("treeHash must be a sha256 hex string");
  }
  if (typeof manifest.sourceCommit !== "string" || !/^[0-9a-f]{40}([0-9a-f]{24})?$/.test(manifest.sourceCommit)) {
    throw schemaError("sourceCommit must be a 40-hex (or 64-hex) git commit id");
  }
  if (manifest.archiveSha256 !== null && manifest.archiveSha256 !== undefined && !/^[0-9a-f]{64}$/.test(manifest.archiveSha256)) {
    throw schemaError("archiveSha256 must be a sha256 hex string or null");
  }
  if (manifest.imageDigest !== null && manifest.imageDigest !== undefined && !/^sha256:[0-9a-f]{64}$/.test(manifest.imageDigest)) {
    throw schemaError("imageDigest must be sha256:<64hex> or null");
  }
  if (manifest.baseImageDigest !== null && manifest.baseImageDigest !== undefined && !/^sha256:[0-9a-f]{64}$/.test(manifest.baseImageDigest)) {
    throw schemaError("baseImageDigest must be sha256:<64hex> or null");
  }
  if (!manifest.covenants || typeof manifest.covenants !== "object" || Array.isArray(manifest.covenants)) {
    throw schemaError("covenants must be an object");
  }
  for (const [ver, entry] of Object.entries(manifest.covenants)) {
    if (!entry || typeof entry !== "object" || typeof entry.path !== "string" || typeof entry.sha256 !== "string" || !/^[0-9a-f]{64}$/.test(entry.sha256) || (entry.label !== "frozen" && entry.label !== "candidate")) {
      throw schemaError(`covenants[${JSON.stringify(ver)}] must be { path, sha256, label: "frozen"|"candidate" }`);
    }
  }
  if (!manifest.dependencies || typeof manifest.dependencies !== "object" || Array.isArray(manifest.dependencies)) {
    throw schemaError("dependencies must be an object");
  }
  const depKeys = Object.keys(manifest.dependencies);
  for (const k of depKeys) {
    if (k !== "lockfiles" && k !== "vendoredKaspaWasmHash") throw schemaError(`unknown dependencies field ${JSON.stringify(k)}`);
  }
  if (!manifest.dependencies.lockfiles || typeof manifest.dependencies.lockfiles !== "object" || Array.isArray(manifest.dependencies.lockfiles)) {
    throw schemaError("dependencies.lockfiles must be an object");
  }
  for (const [p, h] of Object.entries(manifest.dependencies.lockfiles)) {
    if (typeof h !== "string" || !/^[0-9a-f]{64}$/.test(h)) throw schemaError(`dependencies.lockfiles[${JSON.stringify(p)}] must be a sha256 hex string`);
  }
  if (manifest.dependencies.vendoredKaspaWasmHash !== null && manifest.dependencies.vendoredKaspaWasmHash !== undefined && !/^[0-9a-f]{64}$/.test(manifest.dependencies.vendoredKaspaWasmHash)) {
    throw schemaError("dependencies.vendoredKaspaWasmHash must be a sha256 hex string or null");
  }
  if (!manifest.generator || typeof manifest.generator !== "object" || typeof manifest.generator.tool !== "string" || typeof manifest.generator.nodeVersion !== "string") {
    throw schemaError("generator must be { tool, nodeVersion }");
  }
  return manifest;
}

module.exports = {
  MANIFEST_SCHEMA,
  MANIFEST_FIELDS,
  manifestBytes,
  assertManifestShape,
  schemaError
};
