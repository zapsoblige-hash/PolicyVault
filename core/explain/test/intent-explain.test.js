"use strict";

/*
 * UNIT / ADVERSARIAL (display level) — intent-manifest explanations
 * (core/explain/intent-explain.js).
 *
 * Golden explanation outputs for representative VERIFIED manifests of
 * every supported action (built through the REAL core/intent builder via
 * the shared fixtures), refusal rendering for failed-verification cases
 * (each a policy-invalid adversarial test manifest), determinism
 * (same input -> byte-identical output), unknown-version refusals, and
 * adversarial display cases: exact integer KAS rendering and full-value
 * (never truncated) recipient display, including a confusable-key
 * scenario.
 */

const test = require("node:test");
const assert = require("node:assert/strict");

const { verifyIntentManifest, canonicalJsonStringify, buildIntentManifest, VERIFIED_STATEMENT } = require("../../intent");
const { intentExplain, EXPLANATION_VERDICTS, INTENT_EXPLANATION_VERSION_1 } = require("../index");
const {
  agentSpendFixture,
  ownerTopUpFixture,
  ownerPauseFixture,
  ownerSetApproversFixture,
  ownerSetAgentRootFixture,
  ownerRecoverFixture,
  createVaultFixture,
  clone,
  rehash,
  p2pkOutput,
  RECIPIENT,
  VAULT_ID,
  ATTACKER
} = require("../../intent/testutil/fixtures");

/* Verified explanation inputs for a fixture. */
function verified(fixture) {
  const verification = verifyIntentManifest({
    manifest: fixture.manifest,
    requestedIntent: fixture.requestedIntent,
    decodedTransaction: fixture.decodedTransaction
  });
  assert.equal(verification.ok, true, "fixture must verify before it can be explained");
  return { manifest: fixture.manifest, verification };
}

/* Tampered (policy-invalid adversarial test) manifest + its refusing
 * verification result. */
function tampered(fixtureFn, mutate) {
  const m = clone(fixtureFn().manifest);
  mutate(m);
  const manifest = rehash(m);
  const verification = verifyIntentManifest({ manifest });
  assert.equal(verification.ok, false, "the adversarial case must refuse verification");
  return { manifest, verification };
}

function assertNoNormalRendering(doc, label) {
  assert.equal(doc.verdict, EXPLANATION_VERDICTS.REFUSED, `${label}: verdict`);
  assert.equal(doc.statement, null, `${label}: no verified statement`);
  for (const key of ["network", "vault", "action", "actor", "fee", "outputs", "payment", "accounting", "balances", "policyChanges", "policyNonce", "approvals", "limits", "warnings"]) {
    assert.equal(doc[key], null, `${label}: refusal must not carry the ${key} rendering block`);
  }
  assert.ok(doc.refusal !== null && Array.isArray(doc.refusal.codes) && doc.refusal.codes.length > 0, `${label}: refusal codes listed`);
}

function assertRefusalLines(lines, codes, label) {
  assert.equal(lines[0], "!! DO NOT SIGN !!", `${label}: prominent first line`);
  assert.match(lines[1], /VERIFICATION REFUSED/, label);
  const joined = lines.join("\n");
  for (const code of codes) {
    assert.ok(joined.includes(code), `${label}: lines must list detector code ${code}`);
  }
}

/* ------------------------------------------------------------------ */
/* golden verified explanations                                        */
/* ------------------------------------------------------------------ */

test("explain: agentSpend golden human-readable lines (byte-exact)", () => {
  const { manifest, verification } = verified(agentSpendFixture());
  const lines = intentExplain.humanReadable({ manifest, verification });
  assert.deepEqual(
    [...lines],
    [
      `Send exactly 10 KAS to recipient public key ${RECIPIENT} from vault ${VAULT_ID}.`,
      // Builder-authoritative output order: payment first, then successor.
      `Output 0: Payment of exactly 10 KAS to recipient public key ${RECIPIENT}.`,
      "Output 1: Vault covenant successor holding the vault's protected value + fee reserve (490.99995 KAS).",
      "Fee: 0.00005 KAS (within the requested cap of 0.0001 KAS).",
      "Protected value after: 490 KAS (was 500 KAS). Fee reserve after: 0.99995 KAS (was 1 KAS).",
      "Budget after: 15 KAS of the 50 KAS period budget used (35 KAS remaining). Per-spend cap: 20 KAS.",
      "Network fee is paid from the vault fee reserve: 0.00005 KAS (agent per-transaction fee cap 0.001 KAS).",
      `Recipient is authorized by this agent's recipient allowlist (root ${"dd".repeat(32)}); membership proof verified upstream.`,
      "This spend is at or below the approval threshold (15 KAS): no approver signatures are required.",
      "No policy changes — spend and period accounting only.",
      `Vault: ${VAULT_ID} (network testnet-10, covenant policyvault-0.4.1).`,
      `Signer: agent public key ${"22".repeat(32)}.`,
      `Transaction id: ${"0a".repeat(32)}. Manifest hash: ${manifest.manifestHash}.`,
      `Verification: PASSED — ${VERIFIED_STATEMENT}`
    ]
  );
});

test("explain: agentSpend golden structured fields (adversarial display case: 1000000000 sompi -> '10' KAS)", () => {
  const { manifest, verification } = verified(agentSpendFixture());
  const doc = intentExplain.structured({ manifest, verification });
  assert.equal(doc.explanationVersion, INTENT_EXPLANATION_VERSION_1);
  assert.equal(doc.verdict, EXPLANATION_VERDICTS.VERIFIED_EXACT);
  assert.equal(doc.statement, VERIFIED_STATEMENT);
  assert.equal(doc.manifestHash, manifest.manifestHash);
  assert.equal(doc.txId, manifest.transaction.txId);
  // the integer path: "1000000000" sompi renders as exactly "10" KAS
  // (payment is output 0 — the authoritative builder order)
  assert.deepEqual(doc.payment, { recipientXOnly: RECIPIENT, amount: { sompi: "1000000000", kas: "10" }, outputIndex: 0 });
  assert.deepEqual(doc.fee.fee, { sompi: "5000", kas: "0.00005" });
  assert.deepEqual(doc.fee.maxFee, { sompi: "10000", kas: "0.0001" });
  assert.equal(doc.fee.withinRequestedCap, true);
  assert.equal(doc.outputs.length, 2);
  assert.deepEqual(
    doc.outputs.map((o) => o.kind),
    ["payment", "successor"]
  );
  assert.equal(doc.outputs[0].destinationXOnly, RECIPIENT);
  assert.equal(Object.keys(doc.accounting).length, 11);
  assert.deepEqual(doc.accounting.payAmount, { sompi: "1000000000", kas: "10" });
  assert.equal(doc.balances.before.protectedValue.kas, "500");
  assert.equal(doc.balances.after.protectedValue.kas, "490");
  // the covenant-bound successor is output 1 under payment-first ordering
  assert.deepEqual(doc.balances.after.expectedOutpoint, { transactionId: manifest.transaction.txId, index: 1 });
  assert.deepEqual(doc.policyNonce, { before: "7", after: "7", rule: "preserve" });
  assert.equal(doc.approvals.aboveThreshold, false);
  assert.equal(doc.approvals.requiredM, "2");
  assert.equal(doc.limits.remainingAfter.kas, "35");
  assert.equal(doc.limits.rollover, false);
  // spend mutations are funding/accounting — no policy-category entry
  assert.deepEqual(doc.policyChanges.map((e) => [e.field, e.category]), [
    ["protectedValue", "funding"],
    ["feeReserve", "funding"],
    ["agentRoot", "accounting"]
  ]);
  assert.equal(doc.refusal, null);
  assert.equal(doc.verification.ok, true);
  assert.ok(doc.verification.checks.some((c) => c.id === "intent-binding"), "caller verification summary keeps its binding checks");
});

test("explain: every supported action explains under a full verification pass", () => {
  const cases = [
    [agentSpendFixture, /^Send exactly 10 KAS to recipient public key /],
    [ownerTopUpFixture, /^Add exactly 50 KAS to the protected value of vault /],
    [ownerPauseFixture, /^Freeze vault .*emergency pause/],
    [ownerSetApproversFixture, /^Replace the approver configuration of vault .*: 3 of 4 listed approver key/],
    [ownerSetAgentRootFixture, /^Replace the agent registry commitment of vault /],
    [ownerRecoverFixture, /^CLOSE vault .*501 KAS.*This is terminal/],
    [createVaultFixture, /^Create vault .* with 500 KAS protected value and 1 KAS fee reserve/]
  ];
  for (const [fixtureFn, summaryRe] of cases) {
    const { manifest, verification } = verified(fixtureFn());
    const doc = intentExplain.structured({ manifest, verification });
    assert.equal(doc.verdict, EXPLANATION_VERDICTS.VERIFIED_EXACT, fixtureFn.name);
    assert.match(doc.action.summary, summaryRe, fixtureFn.name);
    const lines = intentExplain.humanReadable({ manifest, verification });
    assert.equal(lines[0], doc.action.summary, fixtureFn.name);
    assert.equal(lines[lines.length - 1], `Verification: PASSED — ${VERIFIED_STATEMENT}`, fixtureFn.name);
    // Every explanation document is canonically serializable (JSON-safe:
    // no BigInt, no undefined, plain objects only).
    assert.equal(typeof canonicalJsonStringify(doc), "string", fixtureFn.name);
  }
});

test("explain: high-level lifecycle action renders its own summary (addAgent)", () => {
  const { manifest, verification } = verified(ownerSetAgentRootFixture("addAgent"));
  const doc = intentExplain.structured({ manifest, verification });
  assert.equal(doc.action.highLevelAction, "addAgent");
  assert.match(doc.action.summary, /^Add an agent to vault /);
  assert.match(doc.action.summary, new RegExp(`${"cc".repeat(32)}\\.$`), "the resolved root commitment is pinned in the summary");
});

test("explain: owner policy mutation renders policy changes and the nonce advance", () => {
  const { manifest, verification } = verified(ownerSetApproversFixture());
  const doc = intentExplain.structured({ manifest, verification });
  const fields = doc.policyChanges.map((e) => e.field);
  assert.deepEqual(fields, ["approverSlots", "approvalM", "policyNonce"]);
  assert.deepEqual(doc.policyNonce, { before: "7", after: "8", rule: "increment" });
  const lines = intentExplain.humanReadable({ manifest, verification });
  const joined = lines.join("\n");
  assert.ok(joined.includes("Policy change: Approver key slots replaced"), "approver replacement line");
  assert.ok(joined.includes("Policy change: Approval quorum: 2 -> 3 required approval(s)."), "quorum line");
  assert.ok(joined.includes("Policy nonce advances 7 -> 8."), "nonce line");
});

test("explain: funding-only actions say 'No policy changes — funding only.'", () => {
  const { manifest, verification } = verified(ownerTopUpFixture());
  const lines = intentExplain.humanReadable({ manifest, verification });
  assert.ok(lines.includes("No policy changes — funding only."), lines.join("\n"));
});

test("explain: terminal recovery renders the owner payout and no successor balances", () => {
  const { manifest, verification } = verified(ownerRecoverFixture());
  const doc = intentExplain.structured({ manifest, verification });
  assert.equal(doc.balances.after, null);
  assert.equal(doc.policyNonce, null);
  assert.equal(doc.outputs[0].destinationKind, "owner-payout");
  assert.equal(doc.outputs[0].destinationXOnly, "11".repeat(32));
  const lines = intentExplain.humanReadable({ manifest, verification });
  assert.ok(lines.includes("The vault is CLOSED by this transaction — no successor state remains."), lines.join("\n"));
});

test("explain: genesis renders the initial state and change destination", () => {
  const { manifest, verification } = verified(createVaultFixture());
  const doc = intentExplain.structured({ manifest, verification });
  assert.equal(doc.balances.before, null);
  assert.deepEqual(doc.policyChanges, []);
  assert.equal(doc.outputs[0].destinationKind, "vault-genesis");
  assert.equal(doc.outputs[1].destinationKind, "signer-change");
  assert.equal(doc.outputs[1].destinationXOnly, "11".repeat(32));
});

/* ------------------------------------------------------------------ */
/* determinism                                                         */
/* ------------------------------------------------------------------ */

test("explain: determinism — same input produces byte-identical structured and human output", () => {
  for (const fixtureFn of [agentSpendFixture, ownerTopUpFixture, ownerSetApproversFixture, ownerRecoverFixture, createVaultFixture]) {
    const a = verified(fixtureFn());
    const b = verified(fixtureFn());
    const docA = canonicalJsonStringify(intentExplain.structured(a));
    const docB = canonicalJsonStringify(intentExplain.structured(b));
    assert.equal(docA, docB, `${fixtureFn.name}: structured determinism`);
    const linesA = intentExplain.humanReadable(a).join("\n");
    const linesB = intentExplain.humanReadable(b).join("\n");
    assert.equal(linesA, linesB, `${fixtureFn.name}: human-readable determinism`);
  }
});

test("explain: explanation output is deep-frozen", () => {
  const { manifest, verification } = verified(agentSpendFixture());
  const doc = intentExplain.structured({ manifest, verification });
  assert.ok(Object.isFrozen(doc) && Object.isFrozen(doc.payment) && Object.isFrozen(doc.outputs[0]));
  const lines = intentExplain.humanReadable({ manifest, verification });
  assert.ok(Object.isFrozen(lines));
});

/* ------------------------------------------------------------------ */
/* rollover + above-threshold renderings (rebuilt coherent manifests)  */
/* ------------------------------------------------------------------ */

test("explain: period rollover renders the new period and the CLTV lockTime", () => {
  const { buildInputs } = agentSpendFixture();
  const inputs = clone(buildInputs);
  inputs.requestedIntent.params.periodsElapsed = "1";
  inputs.limits.periodsElapsed = "1";
  inputs.limits.policyAfter = { ...clone(inputs.limits.policyBefore), periodStartDaa: "1086400", periodSpent: "1000000000" };
  inputs.transaction.lockTime = "1086400";
  const manifest = buildIntentManifest(inputs);
  const verification = verifyIntentManifest({ manifest });
  assert.equal(verification.ok, true);
  const doc = intentExplain.structured({ manifest, verification });
  assert.equal(doc.limits.rollover, true);
  assert.equal(doc.limits.lockTime, "1086400");
  const lines = intentExplain.humanReadable({ manifest, verification });
  assert.ok(
    lines.includes("A new budget period starts with this spend (periods elapsed: 1); the transaction is not valid before DAA score 1086400."),
    lines.join("\n")
  );
});

test("explain: an above-threshold spend renders the covenant approval requirement", () => {
  const { buildInputs } = agentSpendFixture();
  const inputs = clone(buildInputs);
  inputs.requestedIntent.params.payAmountSompi = "2000000000";
  inputs.transaction.outputs[0].value = "2000000000"; // payment (output 0)
  inputs.transaction.outputs[1].value = "48099995000"; // successor (output 1)
  inputs.stateAfter.state.protectedValue = "48000000000";
  inputs.accounting.payAmount = "2000000000";
  inputs.accounting.successorProtected = "48000000000";
  inputs.accounting.successorTotal = "48099995000";
  inputs.payment.amountSompi = "2000000000";
  inputs.approvals = { aboveThreshold: true, approvalThreshold: "1500000000", requiredM: "2" };
  inputs.limits.policyAfter = { ...clone(inputs.limits.policyBefore), periodSpent: "2500000000" };
  const manifest = buildIntentManifest(inputs);
  const verification = verifyIntentManifest({ manifest });
  assert.equal(verification.ok, true);
  const lines = intentExplain.humanReadable({ manifest, verification });
  assert.ok(
    lines.includes("This spend is ABOVE the approval threshold (15 KAS): 2 approver signature(s) are required by the covenant."),
    lines.join("\n")
  );
});

test("explain: manifest warnings are carried into structured output and lines", () => {
  const { buildInputs } = ownerTopUpFixture();
  const inputs = clone(buildInputs);
  inputs.warnings = [{ code: "EXAMPLE_WARNING", detail: "informational note" }];
  const manifest = buildIntentManifest(inputs);
  const verification = verifyIntentManifest({ manifest });
  assert.equal(verification.ok, true);
  const doc = intentExplain.structured({ manifest, verification });
  assert.deepEqual(doc.warnings, [{ code: "EXAMPLE_WARNING", detail: "informational note" }]);
  const lines = intentExplain.humanReadable({ manifest, verification });
  assert.ok(lines.includes("Warning EXAMPLE_WARNING: informational note"), lines.join("\n"));
});

/* ------------------------------------------------------------------ */
/* full-value display (anti-substitution)                              */
/* ------------------------------------------------------------------ */

test("explain: confusable recipient keys always render in full — never truncated", () => {
  // A policy-invalid substitution one hex character away from the real
  // recipient would be invisible under prefix truncation. Build a
  // COHERENT spend to the confusable key and require the FULL key
  // everywhere.
  const confusable = `${"33".repeat(31)}34`; // differs from RECIPIENT in the last byte
  const { buildInputs } = agentSpendFixture();
  const inputs = clone(buildInputs);
  inputs.requestedIntent.params.recipient = confusable;
  inputs.payment.recipientXOnly = confusable;
  inputs.transaction.outputs[0] = p2pkOutput("1000000000", confusable); // payment is output 0
  const manifest = buildIntentManifest(inputs);
  const verification = verifyIntentManifest({ manifest });
  assert.equal(verification.ok, true);

  const doc = intentExplain.structured({ manifest, verification });
  assert.equal(doc.payment.recipientXOnly, confusable, "structured carries the full exact key");
  const lines = intentExplain.humanReadable({ manifest, verification });
  const joined = lines.join("\n");
  assert.ok(joined.includes(`recipient public key ${confusable}`), "lines carry the full 64-hex key");
  assert.ok(!joined.includes("…") && !joined.includes("..."), "no ellipsis/truncation anywhere in the rendering");
  // The full-value rule holds for every hex identity in the summary line.
  assert.ok(lines[0].includes(confusable) && lines[0].includes(VAULT_ID), "summary pins full recipient and full vault id");
});

test("explain: no verified rendering ever contains an ellipsis (all fixtures)", () => {
  for (const fixtureFn of [agentSpendFixture, ownerTopUpFixture, ownerPauseFixture, ownerSetApproversFixture, ownerSetAgentRootFixture, ownerRecoverFixture, createVaultFixture]) {
    const { manifest, verification } = verified(fixtureFn());
    const joined = intentExplain.humanReadable({ manifest, verification }).join("\n");
    assert.ok(!joined.includes("…") && !joined.includes("..."), `${fixtureFn.name}: truncation-free rendering`);
  }
});

/* ------------------------------------------------------------------ */
/* refusal rendering (policy-invalid adversarial test manifests)       */
/* ------------------------------------------------------------------ */

test("explain: a hidden-recipient manifest produces a refusal, never a normal rendering", () => {
  const { manifest, verification } = tampered(agentSpendFixture, (m) => {
    m.transaction.outputs[0].scriptPublicKey.scriptHex = `20${ATTACKER}ac`; // outputs[0] = the payment output
  });
  const doc = intentExplain.structured({ manifest, verification });
  assertNoNormalRendering(doc, "hidden recipient");
  assert.ok(doc.refusal.codes.includes("HIDDEN_RECIPIENT"), JSON.stringify(doc.refusal.codes));
  // context is present (the manifest validated) but labeled unverified
  assert.equal(doc.context.sdkAction, "agentSpend");
  const lines = intentExplain.humanReadable({ manifest, verification });
  assertRefusalLines(lines, ["HIDDEN_RECIPIENT"], "hidden recipient");
  assert.ok(lines.some((l) => l.includes("NOT verified")), "context lines are labeled unverified");
});

test("explain: refusal cases for each detector family render their codes", () => {
  const cases = [
    ["excessive fee", agentSpendFixture, (m) => { m.requested.maxFeeSompi = "1"; }, "EXCESSIVE_FEE"],
    ["wrong successor value", agentSpendFixture, (m) => { m.accounting.successorTotal = "49099996000"; }, "ACCOUNTING_MISMATCH"],
    ["hidden policy mutation", ownerTopUpFixture, (m) => {
      m.stateAfter.state.agentRoot = "cc".repeat(32);
      m.policyMutations = [
        { field: "protectedValue", before: "50000000000", after: "55000000000" },
        { field: "agentRoot", before: "bb".repeat(32), after: "cc".repeat(32) }
      ];
    }, "HIDDEN_POLICY_MUTATION"],
    ["nonce violation", ownerPauseFixture, (m) => {
      m.stateAfter.state.policyNonce = "8";
      m.policyMutations = [
        { field: "paused", before: "0", after: "1" },
        { field: "policyNonce", before: "7", after: "8" }
      ];
    }, "NONCE_RULE_VIOLATION"],
    ["unexpected recorded effect", ownerTopUpFixture, (m) => {
      m.unexpectedEffects = [{ code: "UNKNOWN_OUTPUT", detail: "unexplained value flow" }];
    }, "UNEXPECTED_EFFECTS_PRESENT"]
  ];
  for (const [label, fixtureFn, mutate, code] of cases) {
    const { manifest, verification } = tampered(fixtureFn, mutate);
    const doc = intentExplain.structured({ manifest, verification });
    assertNoNormalRendering(doc, label);
    assert.ok(doc.refusal.codes.includes(code), `${label}: expected ${code}, got ${JSON.stringify(doc.refusal.codes)}`);
    assertRefusalLines(intentExplain.humanReadable({ manifest, verification }), [code], label);
  }
});

test("explain: refusal rendering is deterministic too", () => {
  const make = () => tampered(agentSpendFixture, (m) => { m.requested.maxFeeSompi = "1"; });
  const a = make();
  const b = make();
  assert.equal(
    canonicalJsonStringify(intentExplain.structured(a)),
    canonicalJsonStringify(intentExplain.structured(b))
  );
  assert.equal(intentExplain.humanReadable(a).join("\n"), intentExplain.humanReadable(b).join("\n"));
});

/* ------------------------------------------------------------------ */
/* version discipline                                                  */
/* ------------------------------------------------------------------ */

test("explain: unknown manifest version refuses with its own code and no context", () => {
  const m = clone(agentSpendFixture().manifest);
  m.manifestVersion = "policyvault-intent-manifest/999";
  const manifest = rehash(m);
  const verification = verifyIntentManifest({ manifest });
  const doc = intentExplain.structured({ manifest, verification });
  assertNoNormalRendering(doc, "unknown manifest version");
  assert.deepEqual(doc.refusal.codes, ["UNKNOWN_MANIFEST_VERSION"]);
  assert.equal(doc.context, null, "an unvalidated manifest contributes no context at all");
  assert.equal(doc.manifestHash, null);
});

test("explain: unsupported covenant version and unknown action refuse", () => {
  const cases = [
    [(m) => { m.vault.covenantVersion = "policyvault-0.3"; }, "UNSUPPORTED_COVENANT_VERSION"],
    [(m) => { m.action.sdkAction = "ownerDrainVault"; }, "UNKNOWN_ACTION"]
  ];
  for (const [mutate, code] of cases) {
    const m = clone(agentSpendFixture().manifest);
    mutate(m);
    const manifest = rehash(m);
    const doc = intentExplain.structured({ manifest, verification: verifyIntentManifest({ manifest }) });
    assertNoNormalRendering(doc, code);
    assert.ok(doc.refusal.codes.includes(code), `${code}: got ${JSON.stringify(doc.refusal.codes)}`);
  }
});

/* ------------------------------------------------------------------ */
/* verification-binding discipline                                     */
/* ------------------------------------------------------------------ */

test("explain: a manifest without a verification result refuses (MISSING_VERIFICATION)", () => {
  const { manifest } = agentSpendFixture();
  const doc = intentExplain.structured({ manifest });
  assertNoNormalRendering(doc, "missing verification");
  assert.deepEqual(doc.refusal.codes, ["MISSING_VERIFICATION"]);
  assert.equal(doc.context.vaultId, VAULT_ID, "identity context is allowed (labeled unverified)");
});

test("explain: a verification result for a DIFFERENT manifest refuses (VERIFICATION_BINDING_MISMATCH)", () => {
  const spend = verified(agentSpendFixture());
  const topUp = verified(ownerTopUpFixture());
  const doc = intentExplain.structured({ manifest: spend.manifest, verification: topUp.verification });
  assertNoNormalRendering(doc, "binding mismatch");
  assert.deepEqual(doc.refusal.codes, ["VERIFICATION_BINDING_MISMATCH"]);
});

test("explain: a FABRICATED ok:true verification cannot make a policy-invalid manifest render (independent re-verify)", () => {
  const good = verified(agentSpendFixture());
  const bad = tampered(agentSpendFixture, (m) => {
    m.transaction.outputs[0].scriptPublicKey.scriptHex = `20${ATTACKER}ac`; // outputs[0] = the payment output
  });
  // Forge a full-pass verification object bound to the tampered manifest.
  const forged = {
    ...clone({ ...good.verification }),
    manifestHash: bad.manifest.manifestHash,
    txId: bad.manifest.transaction.txId
  };
  const doc = intentExplain.structured({ manifest: bad.manifest, verification: forged });
  assertNoNormalRendering(doc, "forged verification");
  assert.ok(doc.refusal.codes.includes("EXPLAIN_REVERIFY_REFUSED"), JSON.stringify(doc.refusal.codes));
  assert.ok(doc.refusal.codes.includes("HIDDEN_RECIPIENT"), "the independent re-verification's own codes are listed");
});

test("explain: malformed verification objects refuse (VERIFICATION_MALFORMED)", () => {
  const { manifest } = agentSpendFixture();
  const cases = [
    "not an object",
    { ok: true },
    { ok: "yes", verdict: "VERIFIED_EXACT", checks: [], failures: [] },
    { ok: true, verdict: "SOMETHING_ELSE", checks: [], failures: [], statement: VERIFIED_STATEMENT, manifestHash: manifest.manifestHash, txId: manifest.transaction.txId },
    { ok: true, verdict: "VERIFIED_EXACT", checks: [], failures: [{ code: "X" }], statement: VERIFIED_STATEMENT, manifestHash: manifest.manifestHash, txId: manifest.transaction.txId }
  ];
  for (const verification of cases) {
    const doc = intentExplain.structured({ manifest, verification });
    assertNoNormalRendering(doc, "malformed verification");
    assert.deepEqual(doc.refusal.codes, ["VERIFICATION_MALFORMED"]);
  }
});

test("explain: total functions — garbage input never throws, always a refusal document", () => {
  for (const input of [undefined, {}, { manifest: null }, { manifest: 42 }, { manifest: [] }, { manifest: "x", verification: "y" }]) {
    const doc = intentExplain.structured(input);
    assert.equal(doc.verdict, EXPLANATION_VERDICTS.REFUSED);
    const lines = intentExplain.humanReadable(input);
    assert.equal(lines[0], "!! DO NOT SIGN !!");
  }
});
