"use strict";

/* UNIT — canonical-json (Phase G): deterministic, storage-representation-
 * independent serialization for commitment preimages. Strictly fail-closed
 * on anything that JSON.stringify would silently coerce or omit. */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const { canonicalJsonStringify } = require("../src/canonical-json");

test("object key order never changes the output; arrays and values do", () => {
  const a = { beta: "2", alpha: "1", nested: { zz: [1, 2, 3], aa: { y: null, x: "s" } } };
  const b = { nested: { aa: { x: "s", y: null }, zz: [1, 2, 3] }, alpha: "1", beta: "2" };
  assert.equal(canonicalJsonStringify(a), canonicalJsonStringify(b));
  // canonical output is real JSON that parses back to the same values
  assert.deepEqual(JSON.parse(canonicalJsonStringify(a)), a);
  // array ORDER is meaningful — reordering elements changes the bytes
  assert.notEqual(
    canonicalJsonStringify({ k: [1, 2, 3] }),
    canonicalJsonStringify({ k: [3, 2, 1] })
  );
  // any value change changes the bytes
  assert.notEqual(canonicalJsonStringify(a), canonicalJsonStringify({ ...a, alpha: "10" }));
});

test("primitives serialize exactly like JSON.stringify", () => {
  for (const v of ["x", "", 0, 134, -7, 1.5, true, false, null]) {
    assert.equal(canonicalJsonStringify(v), JSON.stringify(v));
  }
  assert.equal(canonicalJsonStringify({ "": "empty-key", "üñî": "ok" }), '{"":"empty-key","üñî":"ok"}');
});

test("fails CLOSED on non-JSON values instead of coercing or omitting", () => {
  const bad = [
    [{ k: undefined }, /undefined/],
    [{ k: 1n }, /BigInt/],
    [{ k: NaN }, /non-finite/],
    [{ k: Infinity }, /non-finite/],
    [{ k: () => 1 }, /function/],
    [{ k: new Date(0) }, /non-plain object/],
    [{ k: new Map() }, /non-plain object/]
  ];
  for (const [value, re] of bad) {
    assert.throws(() => canonicalJsonStringify(value), re, `must reject ${Object.prototype.toString.call(value.k)}`);
  }
  // null-prototype objects are plain data and allowed
  const np = Object.create(null);
  np.a = "1";
  assert.equal(canonicalJsonStringify({ o: np }), '{"o":{"a":"1"}}');
});
