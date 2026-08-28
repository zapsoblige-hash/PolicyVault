"use strict";

/*
 * Cross-runtime equivalence: core/explain structured() + humanReadable()
 * output (Node direct vs the browser bundle). The manifest hash already
 * collapses the whole transaction-fact structure to one hex string
 * (proven identical in intent-manifest-equivalence.test.js); this file
 * proves the human/agent-facing RENDERING built on top of a verified
 * manifest is equally byte-identical — the exact surface a signer
 * actually reads before clicking "sign" (docs/postlaunch/
 * browser-verification.md §1.5).
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");

const { loadCommittedBundleInBrowserGlobal, rehome, rehomeInto } = require("../sandbox.js");

const nodeIntent = require("../../intent");
const nodeExplain = require("../../explain/intent-explain.js");
const fixtures = require("../../intent/testutil/fixtures.js");

const { PolicyVaultCore, global: sandboxGlobal } = loadCommittedBundleInBrowserGlobal();

const ALL_FIXTURES = Object.freeze([
  ["agentSpend", fixtures.agentSpendFixture()],
  ["ownerTopUp", fixtures.ownerTopUpFixture()],
  ["ownerPause", fixtures.ownerPauseFixture()],
  ["ownerSetApprovers", fixtures.ownerSetApproversFixture()],
  ["addAgent", fixtures.ownerSetAgentRootFixture("addAgent")],
  ["ownerRecover", fixtures.ownerRecoverFixture()],
  ["createVault", fixtures.createVaultFixture()]
]);

for (const [label, fx] of ALL_FIXTURES) {
  test(`EQUIVALENCE[${label}]: structured() and humanReadable() agree node vs bundle`, () => {
    const manifest = fx.manifest; // already VM-proven byte-identical to cross into the bundle
    const verification = nodeIntent.verifyIntentManifest({ manifest });
    assert.equal(verification.ok, true, `fixture ${label} must verify cleanly (sanity)`);

    const structuredNode = nodeExplain.structured({ manifest, verification });
    const linesNode = nodeExplain.humanReadable({ manifest, verification });

    const manifestForBundle = rehomeInto(sandboxGlobal, manifest);
    const verificationForBundle = rehomeInto(sandboxGlobal, verification);
    const structuredBundle = PolicyVaultCore.intentExplain.structured({ manifest: manifestForBundle, verification: verificationForBundle });
    const linesBundle = PolicyVaultCore.intentExplain.humanReadable({ manifest: manifestForBundle, verification: verificationForBundle });

    assert.equal(structuredBundle.verdict, "VERIFIED_EXACT");
    assert.deepEqual(rehome(structuredBundle), rehome(structuredNode), `${label}: structured explanation document must be value-identical`);
    assert.deepEqual([...linesBundle], [...linesNode], `${label}: human-readable lines must be byte-identical, in order`);
  });
}

test("EQUIVALENCE: a REFUSED verification renders the identical DO-NOT-SIGN explanation in both runtimes", () => {
  const fx = fixtures.agentSpendFixture();
  const tampered = fixtures.rehash({ ...fixtures.clone(fx.manifest), payment: { ...fx.manifest.payment, recipientXOnly: fixtures.ATTACKER } });
  const verification = nodeIntent.verifyIntentManifest({ manifest: tampered });
  assert.equal(verification.ok, false, "sanity: the tampered manifest must actually refuse");

  const structuredNode = nodeExplain.structured({ manifest: tampered, verification });
  const linesNode = nodeExplain.humanReadable({ manifest: tampered, verification });

  const manifestForBundle = rehomeInto(sandboxGlobal, tampered);
  const verificationForBundle = rehomeInto(sandboxGlobal, verification);
  const structuredBundle = PolicyVaultCore.intentExplain.structured({ manifest: manifestForBundle, verification: verificationForBundle });
  const linesBundle = PolicyVaultCore.intentExplain.humanReadable({ manifest: manifestForBundle, verification: verificationForBundle });

  assert.equal(structuredNode.verdict, "REFUSED");
  assert.deepEqual(rehome(structuredBundle), rehome(structuredNode));
  assert.deepEqual([...linesBundle], [...linesNode]);
  assert.equal(linesNode[0], "!! DO NOT SIGN !!");
  assert.equal(linesBundle[0], linesNode[0]);
});

test("EQUIVALENCE: a fabricated {ok:true} verification object is independently re-verified and refused identically in both runtimes", () => {
  /* structured()/humanReadable() must never trust a caller-supplied
   * verification result at face value — this is the module's own
   * documented self-defense (core/explain/intent-explain.js §"BINDING
   * RULES"). Proving it holds in BOTH runtimes matters because the
   * browser is exactly the environment a hostile page could try this
   * against. */
  const fx = fixtures.agentSpendFixture();
  const tampered = fixtures.rehash({ ...fixtures.clone(fx.manifest), payment: { ...fx.manifest.payment, recipientXOnly: fixtures.ATTACKER } });
  const forged = {
    ok: true,
    verdict: "VERIFIED_EXACT",
    statement: nodeIntent.VERIFIED_STATEMENT,
    manifestHash: tampered.manifestHash,
    txId: tampered.transaction.txId,
    checks: [],
    failures: []
  };

  const structuredNode = nodeExplain.structured({ manifest: tampered, verification: forged });
  const structuredBundle = PolicyVaultCore.intentExplain.structured({
    manifest: rehomeInto(sandboxGlobal, tampered),
    verification: rehomeInto(sandboxGlobal, forged)
  });

  assert.equal(structuredNode.verdict, "REFUSED", "a forged passing verification must not make an unverified manifest render normally");
  assert.deepEqual(rehome(structuredBundle), rehome(structuredNode));
});
