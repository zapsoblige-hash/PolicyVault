"use strict";

/*
 * Normalized cross-path outcome shape + shared assertion utilities
 * (docs/postlaunch/conformance-suite-spec.md §5).
 *
 * Every driver reduces its native result to ONE shape so equivalence is a
 * mechanical comparison, never a per-path special case:
 *
 *   {
 *     ok:         boolean          — 2xx (JS/Python/raw) / envelope OK (MCP)
 *     httpStatus: number | null    — null where the surface hides it
 *                                    (the JS client exposes no status on
 *                                    success — by design; errors carry it)
 *     code:       string | null    — the server's error.code, verbatim
 *     body:       any              — the server body, verbatim
 *                                    (MCP: the envelope's `data`)
 *     replayed:   boolean          — idempotency replay marker
 *     errorType:  string | null    — the path's native error class name
 *                                    (never compared cross-path; recorded
 *                                    for the evidence artifact)
 *   }
 *
 * Comparison rule: `ok` and `code` are compared across EVERY path;
 * `httpStatus` is compared only between paths that expose one for that
 * outcome; `body` comparisons always go through prune()/pick() so volatile
 * per-record fields (uuids, timestamps) never masquerade as divergence.
 */

const assert = require("node:assert/strict");

function outcome({ ok, httpStatus = null, code = null, body = null, replayed = false, errorType = null }) {
  return { ok: Boolean(ok), httpStatus, code, body, replayed: Boolean(replayed), errorType };
}

/* ---- deterministic body views ---- */

/* Deep-pick: keep only the named keys (dot paths) from an object. */
function pick(value, paths) {
  const out = {};
  for (const p of paths) {
    const segs = p.split(".");
    let src = value;
    let okPath = true;
    for (const s of segs) {
      if (src === null || typeof src !== "object" || !(s in src)) {
        okPath = false;
        break;
      }
      src = src[s];
    }
    if (okPath) out[p] = src;
  }
  return out;
}

/* Deep-copy with named keys removed wherever they appear (volatile fields). */
function prune(value, dropKeys) {
  const drop = new Set(dropKeys);
  const walk = (v) => {
    if (Array.isArray(v)) return v.map(walk);
    if (v && typeof v === "object") {
      const out = {};
      for (const [k, val] of Object.entries(v)) {
        if (drop.has(k)) continue;
        out[k] = walk(val);
      }
      return out;
    }
    return v;
  };
  return walk(value);
}

/* ---- cross-path equivalence assertions ---- */

/* Same refusal everywhere: every path refused with the SAME server code;
 * status compared wherever the path exposes one. */
function assertSameRefusal(byPath, { code, status }, label) {
  for (const [pathId, o] of Object.entries(byPath)) {
    assert.equal(o.ok, false, `${label}: path ${pathId} did not refuse`);
    assert.equal(o.code, code, `${label}: path ${pathId} refusal code ${o.code} != ${code}`);
    if (status !== undefined && o.httpStatus !== null) {
      assert.equal(o.httpStatus, status, `${label}: path ${pathId} http ${o.httpStatus} != ${status}`);
    }
  }
}

/* Identical value across paths (deep). The first path is the reference. */
function assertAllEqual(byPath, label) {
  const entries = Object.entries(byPath);
  assert.ok(entries.length >= 2, `${label}: needs at least two paths`);
  const [refPath, refValue] = entries[0];
  for (const [pathId, v] of entries.slice(1)) {
    assert.deepEqual(v, refValue, `${label}: path ${pathId} diverges from ${refPath}`);
  }
}

/* ---- integer-sompi / amounts-as-strings hygiene ----
 *
 * CLAUDE.md numeric safety: consensus/accounting values are integer sompi
 * as decimal STRINGS on the wire (JSON numbers would hit the IEEE-754
 * 2^53 cliff). The walker enforces, over ANY response body from ANY path:
 *   - every key matching /sompi$/i or in AMOUNT_KEYS is a canonical
 *     decimal string (no floats, no exponents, no leading zeros);
 *   - keys matching /Kas$/ (display formatting) are strings;
 *   - NO non-integer JSON number appears anywhere, and every integer that
 *     does appear is a safe integer (counters/indices only).
 */
const AMOUNT_KEYS = new Set([
  "protectedValue",
  "feeReserve",
  "outpointValue",
  "maxPerSpend",
  "periodBudget",
  "periodSpent",
  "approvalThreshold",
  "agentMaxFeePerTx",
  "predecessorValue",
  "fee",
  "amount",
  "value",
  "terminalPayout",
  "reserveConsumed",
  "externalIn"
]);
const DECIMAL_RE = /^(0|[1-9][0-9]*)$/;

function assertAmountHygiene(value, label, keyPath = "$") {
  if (Array.isArray(value)) {
    value.forEach((v, i) => assertAmountHygiene(v, label, `${keyPath}[${i}]`));
    return;
  }
  if (value && typeof value === "object") {
    for (const [k, v] of Object.entries(value)) {
      const p = `${keyPath}.${k}`;
      if (/sompi$/i.test(k) || AMOUNT_KEYS.has(k)) {
        // `value` also appears as non-amount metadata in some feeds; only
        // enforce when it is a scalar (objects/arrays recurse below).
        if (v !== null && typeof v !== "object") {
          assert.equal(typeof v, "string", `${label}: amount field ${p} is ${typeof v}, not a string`);
          assert.match(v, DECIMAL_RE, `${label}: amount field ${p} is not a canonical decimal string`);
        }
      }
      if (/Kas$/.test(k) && v !== null && typeof v !== "object") {
        assert.equal(typeof v, "string", `${label}: KAS display field ${p} is ${typeof v}, not a string`);
      }
      assertAmountHygiene(v, label, p);
    }
    return;
  }
  if (typeof value === "number") {
    assert.ok(Number.isSafeInteger(value), `${label}: non-safe-integer JSON number at ${keyPath} (${value})`);
  }
}

module.exports = { outcome, pick, prune, assertSameRefusal, assertAllEqual, assertAmountHygiene, AMOUNT_KEYS };
