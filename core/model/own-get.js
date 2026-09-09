"use strict";

/*
 * OWN-PROPERTY table lookup for every version / action / kind dispatch map
 * in the shared core, the SDK and the server (rc11 internal security review
 * F-01/F-05, 2026-09-04).
 *
 * WHY: a bare `TABLE[key]` lookup on a plain (even frozen) object resolves
 * PROTOTYPE-CHAIN keys — "constructor", "__proto__", "toString",
 * "hasOwnProperty", "valueOf", "isPrototypeOf", "propertyIsEnumerable",
 * "toLocaleString", "__defineGetter__", … — to truthy built-ins. Every
 * `if (!TABLE[key]) fail(...)` guard then passes, and the caller continues
 * with a Function or Object.prototype where it expected a descriptor: the
 * audit found `resolveV4Abi("constructor")` returning `Function`, whose
 * `.version` is `undefined`, which downstream defaulted to policyvault-0.4 —
 * an UNKNOWN version silently routed to a default, which CLAUDE.md's
 * fail-closed rule forbids. `core/intent/router.js` had already adopted this
 * exact guard; this module makes it the single shared implementation so no
 * dispatch map can regress independently.
 *
 * Semantics (byte-for-byte those of the router's former local helper):
 *   ownGet(table, key) -> table[key] iff `key` is a string AND an OWN
 *   property of `table`; otherwise `undefined`. Never throws, never
 *   coerces (arrays / numbers / objects are not keys), never consults the
 *   prototype chain. Callers keep their own closed refusal on `undefined`.
 */
function ownGet(table, key) {
  if (typeof key !== "string" || !Object.prototype.hasOwnProperty.call(table, key)) return undefined;
  return table[key];
}

/* `true` iff `key` is a string naming an OWN property of `table`. */
function ownHas(table, key) {
  return typeof key === "string" && Object.prototype.hasOwnProperty.call(table, key);
}

/* Safe key description for refusal messages: JSON.stringify throws on BigInt
 * and returns undefined for Symbol; a refusal must never turn into a
 * TypeError just because the hostile input was an exotic type. */
function describeKey(key) {
  if (typeof key === "string") return JSON.stringify(key);
  if (key === undefined) return "undefined";
  if (key === null) return "null";
  if (typeof key === "bigint") return `<bigint ${key.toString()}n>`;
  if (typeof key === "symbol") return "<symbol>";
  if (Array.isArray(key)) return "<array>";
  if (typeof key === "object") return "<object>";
  return `<${typeof key} ${String(key)}>`;
}

module.exports = { ownGet, ownHas, describeKey };
