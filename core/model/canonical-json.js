"use strict";

/*
 * Canonical JSON serialization for COMMITMENT PREIMAGES (Phase G defect
 * G-2). Identical VALUES must hash identically regardless of how a storage
 * backend represents JSON objects: PostgreSQL jsonb canonicalizes object
 * key order (length-then-bytewise), while the JSON-file backend preserves
 * insertion order. A key-order-SENSITIVE preimage therefore appears
 * "mutated" after a postgres round trip with every value byte-intact.
 *
 * Real incident (Phase G, real-KasWare hosted acceptance): an
 * above-threshold agent spend froze its approval package in memory
 * (insertion-ordered), stored it through the postgres store, and the
 * reloaded package — values intact, keys re-sorted by jsonb — recomputed
 * to a different commitment, so finalize failed PACKAGE_MUTATED and the
 * collected approvals were voided. The consensus-grade defenses (txId +
 * covenant sighash recomputed from the normalized frozen transaction)
 * confirmed no value had actually changed.
 *
 * Rules:
 *   - arrays keep element order (order is consensus-meaningful: inputs,
 *     outputs, approver slots, Merkle siblings);
 *   - object keys serialize in lexicographic (UTF-16 code unit) order;
 *   - primitives serialize exactly as JSON.stringify does;
 *   - anything not plainly JSON fails CLOSED instead of serializing
 *     surprisingly: undefined values, functions, symbols, BigInt,
 *     non-finite numbers, and non-plain objects (Date, Map, class
 *     instances) all throw. A commitment must never silently omit or
 *     coerce a field the way bare JSON.stringify would.
 */

function fail(message) {
  const e = new Error(`canonical-json: ${message}`);
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
  if (t === "bigint") fail(`BigInt at ${path} — consensus integers must be committed as strings`);
  if (t === "undefined") fail(`undefined at ${path} — a commitment field may not be silently omitted`);
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

module.exports = { canonicalJsonStringify };
