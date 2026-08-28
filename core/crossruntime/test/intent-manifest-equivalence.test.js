"use strict";

/*
 * Cross-runtime equivalence: intent manifest canonical bytes + manifest
 * hash + verifyIntentManifest verdict/detector codes.
 *
 * Runtimes compared: Node direct (require("core/intent")) vs the browser
 * bundle (committed web/core-bundle.js, evaluated in an isolated
 * window-global vm context — see ../sandbox.js). Every manifest fixture
 * comes from core/intent/testutil/fixtures.js (read-only consumption,
 * exactly as core/intent's OWN test suite and web/test/core-bundle.test.js
 * already use it) so the manifests are genuine, real buildIntentManifest
 * output, not hand-rolled approximations.
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");

const { loadCommittedBundleInBrowserGlobal, rehome, rehomeInto } = require("../sandbox.js");
const { reverseKeysDeep, MAX_SOMPI_STRING, OVER_MAX_SOMPI_STRING } = require("../vectors.js");

const nodeCanonical = require("../../intent/canonical.js");
const nodeIntent = require("../../intent");
const fixtures = require("../../intent/testutil/fixtures.js");

const { PolicyVaultCore, global: sandboxGlobal } = loadCommittedBundleInBrowserGlobal();

function sortedCodes(failures) {
  return [...new Set(failures.map((f) => f.code))].sort();
}

const ALL_FIXTURES = Object.freeze([
  ["agentSpend", fixtures.agentSpendFixture()],
  ["ownerTopUp", fixtures.ownerTopUpFixture()],
  ["ownerPause", fixtures.ownerPauseFixture()],
  ["ownerSetApprovers", fixtures.ownerSetApproversFixture()],
  ["ownerSetAgentRoot(direct)", fixtures.ownerSetAgentRootFixture("ownerSetAgentRoot")],
  ["addAgent", fixtures.ownerSetAgentRootFixture("addAgent")],
  ["removeAgent", fixtures.ownerSetAgentRootFixture("removeAgent")],
  ["rotateAgent", fixtures.ownerSetAgentRootFixture("rotateAgent")],
  ["rePolicyAgent", fixtures.ownerSetAgentRootFixture("rePolicyAgent")],
  ["ownerRecover", fixtures.ownerRecoverFixture()],
  ["createVault", fixtures.createVaultFixture()]
]);

for (const [label, fx] of ALL_FIXTURES) {
  test(`EQUIVALENCE[${label}]: buildIntentManifest + verifyIntentManifest agree node vs bundle`, () => {
    const inputsForBundle = rehomeInto(sandboxGlobal, fx.buildInputs);
    const viaNode = nodeIntent.buildIntentManifest(fixtures.clone(fx.buildInputs));
    const viaBundle = PolicyVaultCore.intent.buildIntentManifest(inputsForBundle);

    assert.equal(viaBundle.manifestHash, viaNode.manifestHash, "manifestHash must be byte-identical across runtimes");
    assert.equal(
      nodeCanonical.canonicalJsonStringify(rehome(viaBundle)),
      nodeCanonical.canonicalJsonStringify(rehome(viaNode)),
      "the full manifest document must be value-identical across runtimes"
    );

    const reqForBundle = rehomeInto(sandboxGlobal, fx.requestedIntent);
    const txForBundle = rehomeInto(sandboxGlobal, fx.decodedTransaction);
    const vNode = nodeIntent.verifyIntentManifest({ manifest: viaNode, requestedIntent: fx.requestedIntent, decodedTransaction: fx.decodedTransaction });
    const vBundle = PolicyVaultCore.intent.verifyIntentManifest({ manifest: viaBundle, requestedIntent: reqForBundle, decodedTransaction: txForBundle });

    assert.equal(vNode.ok, true, `fixture ${label} must verify cleanly on Node (sanity)`);
    assert.equal(vBundle.ok, vNode.ok);
    assert.equal(vBundle.verdict, vNode.verdict);
    assert.equal(vBundle.manifestHash, vNode.manifestHash);
    assert.equal(vBundle.txId, vNode.txId);
    assert.deepEqual(sortedCodes(vBundle.failures), sortedCodes(vNode.failures));
    assert.deepEqual(
      rehome(vBundle.checks).map((c) => [c.id, c.ok]),
      rehome(vNode.checks).map((c) => [c.id, c.ok]),
      "every detector's pass/fail outcome must agree, in the same fixed order"
    );
  });
}

test("EQUIVALENCE: sha256Hex agrees node vs bundle over full manifest JSON bodies", () => {
  for (const [, fx] of ALL_FIXTURES) {
    const body = JSON.stringify(fx.manifest);
    assert.equal(PolicyVaultCore.intent.sha256Hex(body), nodeIntent.sha256Hex(body), "sha256Hex must agree over a real manifest's JSON text");
  }
});

test("REPRESENTATION-INDEPENDENCE cross-runtime: reversed key order and a JSON round-trip never change computeManifestHashV1, in either runtime", () => {
  for (const [label, fx] of ALL_FIXTURES) {
    const body = { ...fx.manifest };
    delete body.manifestHash;
    const reversed = reverseKeysDeep(body);
    const roundTripped = JSON.parse(JSON.stringify(body));

    const nodeReversedHash = nodeIntent.computeManifestHashV1(reversed);
    const nodeRoundTripHash = nodeIntent.computeManifestHashV1(roundTripped);
    assert.equal(nodeReversedHash, fx.manifest.manifestHash, `${label}: node must be insensitive to key order`);
    assert.equal(nodeRoundTripHash, fx.manifest.manifestHash, `${label}: node must be insensitive to a JSON round trip`);

    const bundleReversedHash = PolicyVaultCore.intent.computeManifestHashV1(rehomeInto(sandboxGlobal, reversed));
    const bundleRoundTripHash = PolicyVaultCore.intent.computeManifestHashV1(rehomeInto(sandboxGlobal, roundTripped));
    assert.equal(bundleReversedHash, fx.manifest.manifestHash, `${label}: bundle must be insensitive to key order`);
    assert.equal(bundleRoundTripHash, fx.manifest.manifestHash, `${label}: bundle must be insensitive to a JSON round trip`);
  }
});

test("ADVERSARIAL cross-runtime: a policy-invalid adversarial test manifest (recipient substitution) refuses with the identical detector codes in both runtimes", () => {
  const fx = fixtures.agentSpendFixture();
  const tampered = fixtures.rehash({ ...fixtures.clone(fx.manifest), payment: { ...fx.manifest.payment, recipientXOnly: fixtures.ATTACKER } });

  const vNode = nodeIntent.verifyIntentManifest({ manifest: tampered });
  const vBundle = PolicyVaultCore.intent.verifyIntentManifest({ manifest: rehomeInto(sandboxGlobal, tampered) });

  assert.equal(vNode.ok, false);
  assert.equal(vBundle.ok, false);
  assert.ok(sortedCodes(vNode.failures).includes("HIDDEN_RECIPIENT"));
  assert.deepEqual(sortedCodes(vBundle.failures), sortedCodes(vNode.failures));
});

test("ADVERSARIAL cross-runtime: fee inflation beyond the requested cap refuses identically in both runtimes", () => {
  const fx = fixtures.agentSpendFixture();
  const tampered = fixtures.rehash({
    ...fixtures.clone(fx.manifest),
    accounting: { ...fx.manifest.accounting, fee: "999999999999" }
  });

  const vNode = nodeIntent.verifyIntentManifest({ manifest: tampered });
  const vBundle = PolicyVaultCore.intent.verifyIntentManifest({ manifest: rehomeInto(sandboxGlobal, tampered) });

  assert.equal(vNode.ok, false);
  assert.ok(sortedCodes(vNode.failures).length > 0);
  assert.deepEqual(sortedCodes(vBundle.failures), sortedCodes(vNode.failures));
});

test("ADVERSARIAL cross-runtime: a hidden authority expansion (silent unpause) refuses identically in both runtimes", () => {
  const fx = fixtures.ownerTopUpFixture();
  const tampered = fixtures.rehash({
    ...fixtures.clone(fx.manifest),
    stateBefore: { ...fx.manifest.stateBefore, state: { ...fx.manifest.stateBefore.state, paused: "1" } }
  });

  const vNode = nodeIntent.verifyIntentManifest({ manifest: tampered });
  const vBundle = PolicyVaultCore.intent.verifyIntentManifest({ manifest: rehomeInto(sandboxGlobal, tampered) });

  assert.equal(vNode.ok, false);
  assert.ok(sortedCodes(vNode.failures).includes("AUTHORITY_EXPANSION"), JSON.stringify(vNode.failures));
  assert.deepEqual(sortedCodes(vBundle.failures), sortedCodes(vNode.failures));
});

test("UNICODE/CONFUSABLE cross-runtime: a manifest carrying unicode + confusable text in its (schema-legal, free-text) warnings detail hashes and verifies identically", () => {
  /* Manifest identity fields (recipients, keys, roots) are closed-schema
   * 32-byte hex — there is no such thing as a "unicode recipient" at this
   * layer (validateRequestedIntent/requireHex refuse anything else,
   * checked in core/intent/test/manifest.test.js). The one schema-legal
   * free-text surface is warnings[].detail (up to 2000 chars, any
   * string) — exactly where a real hostile-server/-frontend adversary
   * could try to smuggle a lookalike domain or a display-order-flipping
   * bidi control character into what a human reads on the signing
   * screen, so it is the right place to drive unicode/confusable
   * adversarial vectors through this layer. */
  const base = fixtures.ownerPauseFixture();
  const confusableDetail = "recipient looks like аpple.com (Cyrillic а) not apple.com; RTL override: ‮txt.exe‬; astral: \u{1F600}";
  const inputs = { ...fixtures.clone(base.buildInputs), warnings: [{ code: "TEST_LOOKALIKE_TEXT", detail: confusableDetail }] };

  const viaNode = nodeIntent.buildIntentManifest(inputs);
  const viaBundle = PolicyVaultCore.intent.buildIntentManifest(rehomeInto(sandboxGlobal, inputs));
  assert.equal(viaBundle.manifestHash, viaNode.manifestHash);

  const vNode = nodeIntent.verifyIntentManifest({ manifest: viaNode });
  const vBundle = PolicyVaultCore.intent.verifyIntentManifest({ manifest: rehomeInto(sandboxGlobal, viaNode) });
  assert.equal(vNode.ok, true);
  assert.equal(vBundle.ok, true);

  const explainNode = require("../../explain/intent-explain.js").humanReadable({ manifest: viaNode, verification: vNode });
  const explainBundle = PolicyVaultCore.intentExplain.humanReadable({
    manifest: rehomeInto(sandboxGlobal, viaNode),
    verification: rehomeInto(sandboxGlobal, vNode)
  });
  assert.deepEqual([...explainBundle], [...explainNode], "the unicode/confusable warning line must render identically in both runtimes");
  assert.ok(explainNode.some((l) => l.includes("аpple.com")), "the confusable text must survive into the rendered line, not be silently stripped");
});

test("MAX_SOMPI boundary cross-runtime: parseAmount accepts the exact ceiling and refuses one above it, identically in both runtimes", () => {
  assert.equal(nodeIntent.parseAmount(MAX_SOMPI_STRING, "amt").toString(), MAX_SOMPI_STRING);
  assert.equal(PolicyVaultCore.intent.parseAmount(MAX_SOMPI_STRING, "amt").toString(), MAX_SOMPI_STRING);

  let nodeCode = null;
  try {
    nodeIntent.parseAmount(OVER_MAX_SOMPI_STRING, "amt");
  } catch (e) {
    nodeCode = e.code;
  }
  let bundleCode = null;
  try {
    PolicyVaultCore.intent.parseAmount(OVER_MAX_SOMPI_STRING, "amt");
  } catch (e) {
    bundleCode = e.code;
  }
  assert.equal(nodeCode, "VALUE_INVALID");
  assert.equal(bundleCode, nodeCode);
});
