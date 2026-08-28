"use strict";

/*
 * PolicyVault Transaction Intent Manifest — canonical JSON + manifest hash.
 *
 * PORTABLE SHARED CORE (core/intent): pure Node (CommonJS), zero external
 * dependencies, no server/SDK imports. Runnable later in browser / mobile /
 * CLI / server contexts (the only Node builtin used is node:crypto sha256,
 * isolated behind sha256Hex for future substitution by WebCrypto).
 *
 * The canonical serialization here MIRRORS THE SEMANTICS of
 * sdk/src/canonical-json.js (the Phase G defect G-2 remediation) without
 * importing it — the manifest hash MUST be representation-independent:
 * PostgreSQL jsonb canonicalizes object key order (a real production
 * incident: an approval-package commitment preimage that was
 * JSON-key-order-sensitive recomputed differently after a postgres round
 * trip with every value byte-intact, voiding collected approvals).
 *
 * Rules (identical to sdk/src/canonical-json.js):
 *   - arrays keep element order (order is consensus-meaningful: inputs,
 *     outputs, approver slots, Merkle siblings);
 *   - object keys serialize in lexicographic (UTF-16 code unit) order;
 *   - primitives serialize exactly as JSON.stringify does;
 *   - anything not plainly JSON fails CLOSED instead of serializing
 *     surprisingly: undefined values, functions, symbols, BigInt,
 *     non-finite numbers, and non-plain objects (Date, Map, class
 *     instances) all throw. A manifest hash preimage must never silently
 *     omit or coerce a field the way bare JSON.stringify would.
 */

const crypto = require("crypto");

/*
 * Hash-domain separation: this exact prefix keeps intent-manifest hashes
 * from ever colliding with any other sha256(canonical-json) commitment in
 * the PolicyVault codebase (approval-package commitments, frozen-tx
 * commitments, state IDs). Version-bound: a future manifest version defines
 * its own domain string; it never reuses this one.
 */
const MANIFEST_HASH_DOMAIN_V1 = "policyvault-intent-manifest-hash/1\n";

function fail(message) {
  const e = new Error(`intent-canonical: ${message}`);
  e.code = "CANONICAL_JSON_INVALID";
  throw e;
}

function serialize(value, path) {
  if (value === null) return "null";
  const t = typeof value;
  if (t === "string") return JSON.stringify(value);
  if (t === "boolean") return value ? "true" : "false";
  if (t === "number") {
    if (!Number.isFinite(value)) fail(`non-finite number at ${path} — failing closed`);
    return JSON.stringify(value);
  }
  if (t === "bigint") fail(`BigInt at ${path} — consensus integers must be committed as decimal strings`);
  if (t === "undefined") fail(`undefined at ${path} — a manifest field may not be silently omitted`);
  if (t === "function" || t === "symbol") fail(`${t} at ${path} — not JSON`);
  if (Array.isArray(value)) {
    return `[${value.map((v, i) => serialize(v, `${path}[${i}]`)).join(",")}]`;
  }
  if (t === "object") {
    const proto = Object.getPrototypeOf(value);
    if (proto !== Object.prototype && proto !== null) {
      fail(`non-plain object at ${path} — refusing to canonicalize`);
    }
    const keys = Object.keys(value).sort();
    const parts = [];
    for (const key of keys) {
      parts.push(`${JSON.stringify(key)}:${serialize(value[key], `${path}.${key}`)}`);
    }
    return `{${parts.join(",")}}`;
  }
  fail(`unsupported type ${t} at ${path}`);
}

/* Deterministic, storage-representation-independent JSON serialization. */
function canonicalJsonStringify(value) {
  return serialize(value, "$");
}

/* sha256 hex of a UTF-8 string (the one Node-builtin dependency). */
function sha256Hex(text) {
  return crypto.createHash("sha256").update(text, "utf8").digest("hex");
}

/*
 * The v1 manifest hash: sha256 over the domain prefix + the canonical JSON
 * of the manifest BODY. The body is the manifest document with the
 * `manifestHash` key itself removed (a hash cannot cover itself). There is
 * deliberately NO timestamp anywhere in the hashed body: identical
 * transaction facts must always produce the identical manifest hash, on
 * any machine, at any time, through any storage backend.
 */
function computeManifestHashV1(manifestBody) {
  if (manifestBody === null || typeof manifestBody !== "object" || Array.isArray(manifestBody)) {
    fail("manifest body must be a plain object");
  }
  if (Object.prototype.hasOwnProperty.call(manifestBody, "manifestHash")) {
    fail("manifest body must not contain manifestHash — strip it before hashing");
  }
  return sha256Hex(MANIFEST_HASH_DOMAIN_V1 + canonicalJsonStringify(manifestBody));
}

/*
 * Value equality under the canonical serialization: true iff two documents
 * carry the identical VALUES, regardless of key order or storage
 * representation. Throws (fails closed) if either side is not canonically
 * serializable.
 */
function canonicalEqual(a, b) {
  return canonicalJsonStringify(a) === canonicalJsonStringify(b);
}

module.exports = {
  MANIFEST_HASH_DOMAIN_V1,
  canonicalJsonStringify,
  sha256Hex,
  computeManifestHashV1,
  canonicalEqual
};
