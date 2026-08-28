"use strict";

/*
 * UNIT tests — canonical governance-proposal encoding.
 * Layer: UNIT (pure functions, no I/O).
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("crypto");

const {
  GOVERNANCE_PROPOSAL_SCHEMA,
  GOVERNANCE_PROPOSAL_DOMAIN,
  CanonicalEncodingRefusal,
  canonicalJsonStringify,
  encodeGovernanceProposal,
  governanceProposalDigest
} = require("../canonical");

function refusalCode(fn) {
  try {
    fn();
  } catch (err) {
    assert.ok(err instanceof CanonicalEncodingRefusal, `expected CanonicalEncodingRefusal, got ${err && err.name}: ${err && err.message}`);
    return err.code;
  }
  assert.fail("expected a refusal");
}

test("object key order does not affect the canonical string", () => {
  const a = { zeta: "1", alpha: { b: "x", a: "y" }, mid: ["1", "2"] };
  const b = { mid: ["1", "2"], alpha: { a: "y", b: "x" }, zeta: "1" };
  assert.equal(canonicalJsonStringify(a), canonicalJsonStringify(b));
  assert.equal(canonicalJsonStringify(a), '{"alpha":{"a":"y","b":"x"},"mid":["1","2"],"zeta":"1"}');
});

test("array element order is preserved (order is meaningful)", () => {
  assert.notEqual(canonicalJsonStringify({ a: ["1", "2"] }), canonicalJsonStringify({ a: ["2", "1"] }));
});

test("primitives serialize exactly as JSON.stringify", () => {
  assert.equal(canonicalJsonStringify("q\"uote"), JSON.stringify("q\"uote"));
  assert.equal(canonicalJsonStringify(true), "true");
  assert.equal(canonicalJsonStringify(null), "null");
  assert.equal(canonicalJsonStringify(3), "3");
});

test("null-prototype objects are accepted as plain", () => {
  const o = Object.create(null);
  o.b = "2";
  o.a = "1";
  assert.equal(canonicalJsonStringify(o), '{"a":"1","b":"2"}');
});

test("BigInt fails closed (consensus integers must be decimal strings)", () => {
  assert.equal(refusalCode(() => canonicalJsonStringify({ amount: 5n })), "CANONICAL_JSON_INVALID");
});

test("undefined, function, symbol, non-finite numbers fail closed", () => {
  assert.equal(refusalCode(() => canonicalJsonStringify({ a: undefined })), "CANONICAL_JSON_INVALID");
  assert.equal(refusalCode(() => canonicalJsonStringify({ a: () => {} })), "CANONICAL_JSON_INVALID");
  assert.equal(refusalCode(() => canonicalJsonStringify({ a: Symbol("s") })), "CANONICAL_JSON_INVALID");
  assert.equal(refusalCode(() => canonicalJsonStringify({ a: NaN })), "CANONICAL_JSON_INVALID");
  assert.equal(refusalCode(() => canonicalJsonStringify({ a: Infinity })), "CANONICAL_JSON_INVALID");
});

test("non-plain objects fail closed (Date, Map, class instances)", () => {
  assert.equal(refusalCode(() => canonicalJsonStringify({ a: new Date(0) })), "CANONICAL_JSON_INVALID");
  assert.equal(refusalCode(() => canonicalJsonStringify({ a: new Map() })), "CANONICAL_JSON_INVALID");
  class C {}
  assert.equal(refusalCode(() => canonicalJsonStringify({ a: new C() })), "CANONICAL_JSON_INVALID");
});

test("proposal encoding requires the exact supported schema tag", () => {
  assert.equal(refusalCode(() => encodeGovernanceProposal({})), "GOVERNANCE_SCHEMA_UNKNOWN");
  assert.equal(refusalCode(() => encodeGovernanceProposal({ schema: "policyvault-governance-proposal/v2" })), "GOVERNANCE_SCHEMA_UNKNOWN");
  assert.equal(refusalCode(() => encodeGovernanceProposal(null)), "PROPOSAL_INVALID");
  assert.equal(refusalCode(() => encodeGovernanceProposal([])), "PROPOSAL_INVALID");
  const bytes = encodeGovernanceProposal({ schema: GOVERNANCE_PROPOSAL_SCHEMA, kind: "policy-change" });
  assert.ok(Buffer.isBuffer(bytes));
});

test("proposal digest is domain-separated, key-order-independent, and stable", () => {
  const p1 = { schema: GOVERNANCE_PROPOSAL_SCHEMA, kind: "policy-change", amounts: { maxPerSpend: "100" } };
  const p2 = { amounts: { maxPerSpend: "100" }, kind: "policy-change", schema: GOVERNANCE_PROPOSAL_SCHEMA };
  const d1 = governanceProposalDigest(p1);
  const d2 = governanceProposalDigest(p2);
  assert.match(d1, /^[0-9a-f]{64}$/);
  assert.equal(d1, d2);

  /* Domain separation: digest != sha256 of the bare canonical bytes. */
  const bare = crypto.createHash("sha256").update(encodeGovernanceProposal(p1)).digest("hex");
  assert.notEqual(d1, bare);

  /* Golden vector: pins the exact preimage layout (domain \n canonical). */
  const expected = crypto
    .createHash("sha256")
    .update(`${GOVERNANCE_PROPOSAL_DOMAIN}\n` + canonicalJsonStringify(p1), "utf8")
    .digest("hex");
  assert.equal(d1, expected);
});

test("ABSOLUTE golden digest (guards against any future canonicalization drift)", () => {
  /* If this test ever fails, the commitment encoding changed — that is a
   * BREAKING schema event, never a test to update casually. */
  const p = { schema: GOVERNANCE_PROPOSAL_SCHEMA, kind: "policy-change" };
  assert.equal(canonicalJsonStringify(p), '{"kind":"policy-change","schema":"policyvault-governance-proposal/v1"}');
  assert.equal(governanceProposalDigest(p), "9cb5537909ea7777a17f1b4f26c0d301655577ef281afc6452d47a64bb7c0736");
});

test("storage-representation round trip (jsonb-style key reorder) keeps the digest", () => {
  /* Simulate PostgreSQL jsonb rendering: parse the canonical JSON (keys
   * arrive re-sorted / re-ordered by the backend) and re-digest. */
  const p = { schema: GOVERNANCE_PROPOSAL_SCHEMA, zeta: "z", alpha: "a", nested: { y: "1", x: "2" } };
  const stored = JSON.parse(JSON.stringify(p)); // representation A
  const reordered = JSON.parse(canonicalJsonStringify(p)); // representation B (sorted keys)
  assert.equal(governanceProposalDigest(stored), governanceProposalDigest(reordered));
});
