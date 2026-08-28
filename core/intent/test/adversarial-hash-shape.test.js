"use strict";

/*
 * ADVERSARIAL — hash-collision-SHAPE tricks against the intent-manifest
 * commitment (falsification pass, docs/postlaunch/core-v1-falsification-
 * review.md). The manifest hash is the integrity anchor; these are the
 * concrete "same-looking, different-meaning" and "different-looking,
 * same-meaning" inputs an attacker would try to make two manifests collide
 * or to smuggle a hidden field past the commitment. Every attempt here was
 * run and RECORDED; the claim held — these are the pinned regressions.
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");

const { canonicalJsonStringify, computeManifestHashV1, canonicalEqual } = require("../canonical");
const { validateManifest, parseAmount, requireInt } = require("../manifest");
const { verifyIntentManifest, VERDICTS } = require("../verify");
const { agentSpendFixture } = require("../testutil/fixtures");

const clone = (v) => JSON.parse(JSON.stringify(v));
function rehash(m) {
  const b = { ...m };
  delete b.manifestHash;
  return { ...b, manifestHash: computeManifestHashV1(b) };
}

/* ---- __proto__ / prototype tricks ---- */

test("hash-shape: an own-enumerable __proto__ key is serialized, never silently dropped", () => {
  const withProto = JSON.parse('{"__proto__": 1, "z": 2}'); // JSON.parse makes __proto__ an OWN key
  const s = canonicalJsonStringify(withProto);
  assert.ok(s.includes('"__proto__":1'), `__proto__ own key must be committed, got ${s}`);
  /* it must NOT collide with an object that lacks the key */
  assert.notEqual(canonicalJsonStringify(withProto), canonicalJsonStringify({ z: 2 }));
  assert.notEqual(canonicalJsonStringify(JSON.parse('{"__proto__": 1}')), canonicalJsonStringify({}));
});

test("hash-shape: a prototype-polluted (non-plain) object fails closed", () => {
  const o = { a: 1 };
  Object.setPrototypeOf(o, { evil: true }); // real prototype change -> non-plain
  assert.throws(() => canonicalJsonStringify(o), (e) => e.code === "CANONICAL_JSON_INVALID");
});

/* ---- number-shape tricks ---- */

test("hash-shape: consensus amounts as JS numbers are refused (no float/1e3/-0 smuggling)", () => {
  for (const bad of [1000, 1e3, -0, 0.5, NaN, Infinity, -1]) {
    assert.throws(() => parseAmount(bad, "amt"), (e) => e.code === "VALUE_INVALID", `number ${String(bad)} must be refused`);
  }
  /* non-canonical digit strings are refused too */
  for (const bad of ["1e3", "0x10", "+1", " 1", "1.0", "01", "-1", "٤٢"]) {
    assert.throws(() => parseAmount(bad, "amt"), (e) => e.code === "VALUE_INVALID", `string ${JSON.stringify(bad)} must be refused`);
  }
});

test("hash-shape: negative-zero and 1e3 as a structural index collapse to one encoding (no dual hash)", () => {
  /* structural ints are the only place JS numbers are allowed; -0 and 0 and
   * 1e3 and 1000 are the SAME integer with ONE canonical serialization, so
   * they can never produce two hashes for one value. (=== treats -0 as 0;
   * Object.is is deliberately NOT the comparison anywhere in the engine.) */
  assert.ok(requireInt(-0, "i") === 0, "requireInt(-0) is numerically zero");
  assert.equal(requireInt(1e3, "i", { max: 5000 }), 1000);
  assert.equal(canonicalJsonStringify(-0), "0");
  assert.equal(canonicalJsonStringify(1e3), "1000");
  assert.equal(canonicalJsonStringify(-0), canonicalJsonStringify(0));
});

/* ---- string-shape tricks ---- */

test("hash-shape: unicode NFC vs NFD are DISTINCT (no silent normalization collision)", () => {
  const nfc = "é"; // é composed
  const nfd = "é"; // é decomposed
  assert.notEqual(nfc, nfd);
  assert.notEqual(canonicalJsonStringify({ s: nfc }), canonicalJsonStringify({ s: nfd }));
});

test("hash-shape: duplicate JSON keys collapse to one value deterministically", () => {
  const parsed = JSON.parse('{"a":1,"a":2}'); // JS keeps the last
  assert.equal(canonicalJsonStringify(parsed), '{"a":2}');
});

/* ---- representation independence (the real property) ---- */

test("hash-shape: key order and JSON round-trip never change the manifest hash (jsonb class)", () => {
  const m = agentSpendFixture().manifest;
  const body = { ...m };
  delete body.manifestHash;
  const reversed = {};
  for (const k of Object.keys(body).reverse()) reversed[k] = body[k];
  assert.equal(computeManifestHashV1(reversed), m.manifestHash);
  assert.equal(computeManifestHashV1(JSON.parse(JSON.stringify(body))), m.manifestHash);
  assert.ok(canonicalEqual(body, reversed));
});

/* ---- closed-schema defense in depth: a hidden field cannot ride along ---- */

test("hash-shape: a stray extra key inside a manifest object is refused by the closed schema", () => {
  const m = clone(agentSpendFixture().manifest);
  m.vault.smuggled = "1"; // an unknown key in a closed object
  assert.throws(() => validateManifest(rehash(m)), (e) => e.code === "SCHEMA_INVALID");
});

/* ---- the payment-index confusion (sibling to the output-order fix) ---- */

test("adversarial: payment.outputIndex pointed at the covenant successor -> HIDDEN_RECIPIENT", () => {
  const m = clone(agentSpendFixture().manifest);
  /* real order is [payment@0, successor@1]; redirect the declared payment
   * index at the successor output to try to hide the true recipient. */
  m.payment.outputIndex = 1;
  const r = verifyIntentManifest({ manifest: rehash(m) });
  assert.equal(r.verdict, VERDICTS.REFUSED);
  assert.ok(r.failures.some((f) => f.code === "HIDDEN_RECIPIENT"), JSON.stringify(r.failures));
});
