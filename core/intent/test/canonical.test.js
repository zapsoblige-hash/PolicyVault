"use strict";

/*
 * UNIT — canonical JSON serialization + representation-independent
 * manifest hashing (core/intent/canonical.js).
 *
 * The determinism suite reproduces the G-2 incident class: identical
 * VALUES must hash identically regardless of object key order or storage
 * representation (PostgreSQL jsonb re-sorts keys); any SEMANTIC change
 * must change the hash.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("crypto");

const {
  MANIFEST_HASH_DOMAIN_V1,
  canonicalJsonStringify,
  sha256Hex,
  computeManifestHashV1,
  canonicalEqual
} = require("../canonical");
const { agentSpendFixture, clone } = require("../testutil/fixtures");

/* Rebuild an object tree with keys inserted in REVERSE-sorted order —
 * models a storage backend that re-orders object keys (jsonb class). */
function reorderKeysDeep(value) {
  if (Array.isArray(value)) return value.map(reorderKeysDeep);
  if (value !== null && typeof value === "object") {
    const out = {};
    for (const key of Object.keys(value).sort().reverse()) {
      out[key] = reorderKeysDeep(value[key]);
    }
    return out;
  }
  return value;
}

test("canonical: object keys serialize sorted, arrays keep order", () => {
  assert.equal(canonicalJsonStringify({ b: 1, a: 2 }), '{"a":2,"b":1}');
  assert.equal(canonicalJsonStringify({ z: { d: 1, c: [3, 1, 2] }, a: null }), '{"a":null,"z":{"c":[3,1,2],"d":1}}');
  assert.equal(canonicalJsonStringify([2, 1, { b: 0, a: 0 }]), '[2,1,{"a":0,"b":0}]');
});

test("canonical: primitives serialize exactly as JSON.stringify", () => {
  assert.equal(canonicalJsonStringify("a\"b\n "), JSON.stringify("a\"b\n "));
  assert.equal(canonicalJsonStringify(true), "true");
  assert.equal(canonicalJsonStringify(false), "false");
  assert.equal(canonicalJsonStringify(null), "null");
  assert.equal(canonicalJsonStringify(0), "0");
  assert.equal(canonicalJsonStringify(12), "12");
});

test("canonical: keys sort by UTF-16 code units", () => {
  // "z" (0x7a) sorts before "é" (0xe9)
  assert.equal(canonicalJsonStringify({ "é": 1, z: 2 }), '{"z":2,"é":1}');
});

test("canonical: null-prototype plain objects are accepted", () => {
  const o = Object.create(null);
  o.b = 1;
  o.a = 2;
  assert.equal(canonicalJsonStringify(o), '{"a":2,"b":1}');
});

test("canonical: every non-JSON value fails closed with CANONICAL_JSON_INVALID", () => {
  class Widget {}
  const cases = [
    ["undefined value", { a: undefined }],
    ["function", { a: () => 1 }],
    ["symbol", { a: Symbol("x") }],
    ["BigInt", { a: 1n }],
    ["NaN", { a: NaN }],
    ["Infinity", { a: Infinity }],
    ["-Infinity", { a: -Infinity }],
    ["Date", { a: new Date(0) }],
    ["Map", { a: new Map() }],
    ["Set", { a: new Set() }],
    ["class instance", { a: new Widget() }],
    ["top-level undefined", undefined],
    ["top-level BigInt", 5n]
  ];
  for (const [label, value] of cases) {
    assert.throws(() => canonicalJsonStringify(value), (e) => e.code === "CANONICAL_JSON_INVALID", `${label} must fail closed`);
  }
});

test("canonical: failure messages name the exact path", () => {
  assert.throws(
    () => canonicalJsonStringify({ outer: { inner: [1, { bad: 7n }] } }),
    (e) => e.code === "CANONICAL_JSON_INVALID" && e.message.includes("$.outer.inner[1].bad")
  );
});

test("hash: computeManifestHashV1 refuses non-objects and self-referential bodies", () => {
  assert.throws(() => computeManifestHashV1(null), (e) => e.code === "CANONICAL_JSON_INVALID");
  assert.throws(() => computeManifestHashV1([1, 2]), (e) => e.code === "CANONICAL_JSON_INVALID");
  assert.throws(() => computeManifestHashV1("x"), (e) => e.code === "CANONICAL_JSON_INVALID");
  assert.throws(() => computeManifestHashV1({ manifestHash: "00" }), (e) => e.code === "CANONICAL_JSON_INVALID");
});

test("hash: domain separation — never a bare sha256 of the canonical JSON", () => {
  const body = { a: "1" };
  assert.equal(computeManifestHashV1(body), sha256Hex(MANIFEST_HASH_DOMAIN_V1 + canonicalJsonStringify(body)));
  assert.notEqual(computeManifestHashV1(body), sha256Hex(canonicalJsonStringify(body)));
  assert.notEqual(computeManifestHashV1(body), crypto.createHash("sha256").update(JSON.stringify(body)).digest("hex"));
});

test("hash determinism: reordered keys (jsonb class) produce the identical hash", () => {
  const { manifest } = agentSpendFixture();
  const body = clone(manifest);
  delete body.manifestHash;
  const reordered = reorderKeysDeep(body);
  assert.notEqual(JSON.stringify(reordered), JSON.stringify(body), "the rebuild must actually change insertion order");
  assert.equal(computeManifestHashV1(reordered), manifest.manifestHash);
  assert.ok(canonicalEqual(reordered, body));
});

test("hash determinism: JSON round-trip produces the identical hash", () => {
  const { manifest } = agentSpendFixture();
  const body = clone(manifest);
  delete body.manifestHash;
  const roundTripped = JSON.parse(JSON.stringify(reorderKeysDeep(body)));
  assert.equal(computeManifestHashV1(roundTripped), manifest.manifestHash);
});

test("hash determinism: two independent builds of the same facts hash identically", () => {
  const a = agentSpendFixture().manifest;
  const b = agentSpendFixture().manifest;
  assert.equal(a.manifestHash, b.manifestHash);
  assert.ok(canonicalEqual(a, b));
});

test("hash inequality: every semantic change changes the hash", () => {
  const { manifest } = agentSpendFixture();
  const base = clone(manifest);
  delete base.manifestHash;
  const baseHash = computeManifestHashV1(base);

  const mutations = [
    ["payment amount", (b) => { b.payment.amountSompi = "1000000001"; }],
    ["recipient key", (b) => { b.payment.recipientXOnly = "99".repeat(32); }],
    ["fee", (b) => { b.accounting.fee = "5001"; }],
    ["successor protectedValue", (b) => { b.stateAfter.state.protectedValue = "49000000001"; }],
    ["approver slot order", (b) => { b.stateBefore.state.approverSlots.reverse(); }],
    ["output order", (b) => { b.transaction.outputs.reverse(); }],
    ["added key", (b) => { b.extra = "1"; }],
    ["removed warning list", (b) => { b.warnings = [{ code: "X_NOTE", detail: "added" }]; }],
    ["network", (b) => { b.network.networkId = "mainnet"; }]
  ];
  for (const [label, mutate] of mutations) {
    const tampered = clone(base);
    mutate(tampered);
    assert.notEqual(computeManifestHashV1(tampered), baseHash, `${label} must change the manifest hash`);
  }
});

test("canonicalEqual: value equality across representations, inequality on change", () => {
  const { manifest } = agentSpendFixture();
  assert.ok(canonicalEqual(manifest, JSON.parse(JSON.stringify(reorderKeysDeep(clone(manifest))))));
  const changed = clone(manifest);
  changed.accounting.payAmount = "999999999";
  assert.ok(!canonicalEqual(manifest, changed));
});
