"use strict";

/*
 * Canonical serialization + hashing for adapter commitments.
 *
 * canonicalJsonStringify is REQUIRED FROM THE SDK — never reimplemented
 * (standing G-2 rule: every new integrity commitment must be key-order-
 * independent, because PostgreSQL jsonb reorders object keys and a
 * key-order-sensitive preimage "mutates" across a storage round trip with
 * every value byte intact). `sdk/src/canonical-json.js` is the exact
 * module the SDK's public entry (`sdk/src/index.js`, package main)
 * re-exports as `canonicalJsonStringify`; requiring the leaf module keeps
 * the adapter process free of the SDK's financial modules while using the
 * IDENTICAL function object (asserted by test/dependency-direction — the
 * public-entry export and this import are the same reference).
 *
 * Domain-prefixed digests: every sha256(canonical-json) commitment in the
 * adapters carries a domain line so the digests are permanently disjoint
 * from every other commitment in the codebase (manifest hashes,
 * approval-package commitments, governance digests, state IDs) and from
 * each other.
 */

const crypto = require("node:crypto");
const { canonicalJsonStringify } = require("../../sdk/src/canonical-json");

function sha256Hex(text) {
  return crypto.createHash("sha256").update(text, "utf8").digest("hex");
}

function sha256Base64Url(text) {
  return crypto.createHash("sha256").update(text, "utf8").digest("base64url");
}

/* sha256_hex("<domain>\n" + canonicalJsonStringify(value)) — the exact
 * derivation shape both adapter specs' §3.4 define. */
function domainDigestHex(domain, value) {
  if (typeof domain !== "string" || !domain.includes("/")) {
    throw new Error("domainDigestHex: domain must be a versioned domain string like policyvault-x402-requirement-digest/1");
  }
  return sha256Hex(`${domain}\n${canonicalJsonStringify(value)}`);
}

module.exports = { canonicalJsonStringify, sha256Hex, sha256Base64Url, domainDigestHex };
