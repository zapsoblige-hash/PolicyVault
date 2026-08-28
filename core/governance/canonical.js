"use strict";

/*
 * PolicyVault post-launch governance — canonical proposal encoding.
 *
 * Deterministic, storage-representation-independent serialization for
 * GOVERNANCE PROPOSAL commitment preimages. Semantics intentionally match
 * `sdk/src/canonical-json.js` (the Phase G-2 standing rule: any integrity
 * commitment over structured data must be representation-independent —
 * PostgreSQL jsonb reorders object keys, the JSON-file backend preserves
 * insertion order, and identical VALUES must hash identically on both).
 * This module is deliberately self-contained (core/ has no runtime
 * dependency on sdk/); any divergence from the sdk serializer's semantics
 * is a defect.
 *
 * Rules:
 *   - arrays keep element order (order can be meaningful: approver slots,
 *     recipient lists, per-agent registries);
 *   - object keys serialize in lexicographic (UTF-16 code unit) order;
 *   - primitives serialize exactly as JSON.stringify does;
 *   - anything not plainly JSON fails CLOSED: undefined, functions,
 *     symbols, BigInt (consensus integers must already be decimal
 *     strings), non-finite numbers, and non-plain objects all throw.
 *
 * The proposal digest is domain-separated and schema-versioned:
 * unknown proposal schemas REFUSE (fail closed) — they are never routed
 * to a default encoding.
 */

const crypto = require("crypto");

const GOVERNANCE_PROPOSAL_SCHEMA = "policyvault-governance-proposal/v1";
const GOVERNANCE_PROPOSAL_DOMAIN = "policyvault-governance-proposal-digest/v1";

class CanonicalEncodingRefusal extends Error {
  constructor(code, message) {
    super(`governance-canonical: ${message}`);
    this.name = "CanonicalEncodingRefusal";
    this.code = code;
  }
}

function fail(code, message) {
  throw new CanonicalEncodingRefusal(code, message);
}

function serialize(value, path) {
  if (value === null) return "null";
  const t = typeof value;
  if (t === "string") return JSON.stringify(value);
  if (t === "boolean") return value ? "true" : "false";
  if (t === "number") {
    if (!Number.isFinite(value)) {
      fail("CANONICAL_JSON_INVALID", `non-finite number at ${path} — failing closed`);
    }
    return JSON.stringify(value);
  }
  if (t === "bigint") {
    fail("CANONICAL_JSON_INVALID", `BigInt at ${path} — consensus integers must be committed as decimal strings`);
  }
  if (t === "undefined") {
    fail("CANONICAL_JSON_INVALID", `undefined at ${path} — a commitment field may not be silently omitted`);
  }
  if (t === "function" || t === "symbol") {
    fail("CANONICAL_JSON_INVALID", `${t} at ${path} — not JSON`);
  }
  if (Array.isArray(value)) {
    return `[${value.map((v, i) => serialize(v, `${path}[${i}]`)).join(",")}]`;
  }
  if (t === "object") {
    const proto = Object.getPrototypeOf(value);
    if (proto !== Object.prototype && proto !== null) {
      fail("CANONICAL_JSON_INVALID", `non-plain object at ${path} — refusing to canonicalize`);
    }
    const keys = Object.keys(value).sort();
    const parts = [];
    for (const key of keys) {
      parts.push(`${JSON.stringify(key)}:${serialize(value[key], `${path}.${key}`)}`);
    }
    return `{${parts.join(",")}}`;
  }
  fail("CANONICAL_JSON_INVALID", `unsupported type ${t} at ${path}`);
}

/* Deterministic, key-order-independent JSON serialization (string out). */
function canonicalJsonStringify(value) {
  return serialize(value, "$");
}

/*
 * Canonical byte encoding of ONE governance proposal. The proposal object
 * must be a plain JSON-safe object carrying exactly the supported schema
 * tag; every signature ever collected for a proposal is a signature over
 * these bytes (wallet personal-message signing — a domain permanently
 * distinct from transaction signing), so a stored proposal that is
 * tampered with in the database no longer verifies against any of its
 * collected signatures.
 */
function encodeGovernanceProposal(proposal) {
  if (proposal === null || typeof proposal !== "object" || Array.isArray(proposal)) {
    fail("PROPOSAL_INVALID", "proposal must be a plain object");
  }
  if (proposal.schema !== GOVERNANCE_PROPOSAL_SCHEMA) {
    fail(
      "GOVERNANCE_SCHEMA_UNKNOWN",
      `unknown proposal schema ${JSON.stringify(proposal.schema)} — only ${GOVERNANCE_PROPOSAL_SCHEMA} is supported; unknown schemas fail closed`
    );
  }
  return Buffer.from(canonicalJsonStringify(proposal), "utf8");
}

/* SHA-256 digest (lowercase hex) over domain || "\n" || canonical bytes. */
function governanceProposalDigest(proposal) {
  const bytes = encodeGovernanceProposal(proposal);
  return crypto
    .createHash("sha256")
    .update(GOVERNANCE_PROPOSAL_DOMAIN, "utf8")
    .update("\n", "utf8")
    .update(bytes)
    .digest("hex");
}

module.exports = {
  GOVERNANCE_PROPOSAL_SCHEMA,
  GOVERNANCE_PROPOSAL_DOMAIN,
  CanonicalEncodingRefusal,
  canonicalJsonStringify,
  encodeGovernanceProposal,
  governanceProposalDigest
};
