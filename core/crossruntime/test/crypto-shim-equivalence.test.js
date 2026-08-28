"use strict";

/*
 * Cross-runtime equivalence: the browser crypto shim's SHA-256 vs
 * node:crypto over the SAME bytes (PostLaunchUpgradeOG cross-runtime
 * equivalence battery item). This is the single primitive every other
 * equivalence claim in this suite reduces to: core/intent's manifest
 * hash, core/model's state IDs, and every commitment in this codebase
 * ultimately call sha256Hex/createHash("sha256") — if THIS diverged
 * between Node and the browser, every other "byte-identical" claim in
 * this directory would be checking two wrong answers that happen to
 * agree with each other, not agreement with the real algorithm.
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const nodeCrypto = require("node:crypto");

const { loadCommittedBundleInBrowserGlobal } = require("../sandbox.js");
const { SHA256_VECTORS } = require("../vectors.js");

const nodeIntentCanonical = require("../../intent/canonical.js");

const { PolicyVaultCore } = loadCommittedBundleInBrowserGlobal();

function nodeSha256Hex(text) {
  return nodeCrypto.createHash("sha256").update(text, "utf8").digest("hex");
}

for (const vector of SHA256_VECTORS) {
  const label = vector.length > 40 ? `${vector.slice(0, 20)}...(${vector.length} chars)` : JSON.stringify(vector);
  test(`sha256 THREE-WAY equivalence over ${label}`, () => {
    const viaNodeCrypto = nodeSha256Hex(vector);
    const viaNodeIntent = nodeIntentCanonical.sha256Hex(vector);
    const viaBundleShim = PolicyVaultCore.intent.sha256Hex(vector);
    assert.equal(viaNodeIntent, viaNodeCrypto, "core/intent/canonical.js sha256Hex must equal node:crypto (Node runtime, sanity)");
    assert.equal(viaBundleShim, viaNodeCrypto, "the browser crypto shim's pure-JS SHA-256 must equal node:crypto over the identical bytes");
  });
}

test("sha256 shim: the raw crypto module (bundle.require('crypto')) matches node:crypto directly, bypassing core/intent entirely", () => {
  const shimCrypto = PolicyVaultCore.require("crypto");
  for (const vector of SHA256_VECTORS) {
    const shimHex = shimCrypto.createHash("sha256").update(vector, "utf8").digest("hex");
    assert.equal(shimHex, nodeSha256Hex(vector));
  }
});

test("sha256 shim: update() called in multiple chunks matches a single-call node:crypto digest of the concatenation", () => {
  const shimCrypto = PolicyVaultCore.require("crypto");
  const parts = ["policyvault-", "intent-manifest-hash/1\n", "{\"a\":1,\"中\":\"😀\"}"];
  const chunked = shimCrypto.createHash("sha256");
  for (const p of parts) chunked.update(p, "utf8");
  assert.equal(chunked.digest("hex"), nodeSha256Hex(parts.join("")));
});

test("randomBytes: format equivalence (length + hex shape) — VALUE equality is neither possible nor desired for entropy", () => {
  const nodeHex = nodeCrypto.randomBytes(16).toString("hex");
  const shimHex = PolicyVaultCore.require("crypto").randomBytes(16).toString("hex");
  assert.match(nodeHex, /^[0-9a-f]{32}$/);
  assert.match(shimHex, /^[0-9a-f]{32}$/);
  assert.notEqual(nodeHex, shimHex, "two independent draws must not coincide (entropy sanity, astronomically unlikely to collide)");
});

test("FAIL-CLOSED equivalence: the shim's exact-surface refusals mirror node:crypto's own inability to serve the same misuse safely", () => {
  const shimCrypto = PolicyVaultCore.require("crypto");
  /* node:crypto WOULD happily emit a non-hex digest or hash any input —
   * the shim intentionally narrows to exactly what the embedded core
   * modules actually call (createHash("sha256") with
   * update(str,"utf8").digest("hex") for canonical/state-id hashing,
   * update(<Uint8Array>).digest() for the byte-native Merkle modules,
   * randomBytes(n).toString("hex")) and fails closed on anything wider,
   * so a future core change can never silently start depending on a
   * Node-only crypto behavior the browser cannot provide. Byte-mode
   * exactness vs node:crypto is pinned in core-model-portability.test.js
   * and web/test/core-bundle.test.js. */
  assert.throws(() => shimCrypto.createHash("sha512"), /unsupported hash algorithm/);
  assert.throws(() => shimCrypto.createHash("sha256").update(123), /strings and Uint8Array bytes only/);
  assert.throws(() => shimCrypto.createHash("sha256").update({}), /strings and Uint8Array bytes only/);
  assert.throws(() => shimCrypto.createHash("sha256").update(Uint8Array.of(1), "utf8"), /byte updates take no encoding/);
  assert.throws(() => shimCrypto.createHash("sha256").update("x", "latin1"), /unsupported update encoding/);
  assert.throws(() => shimCrypto.createHash("sha256").update("x").digest("base64"), /unsupported digest format/);
  assert.doesNotThrow(() => nodeCrypto.createHash("sha256").update("ab", "latin1").digest("base64"), "sanity: node:crypto itself has no such restriction");
});
