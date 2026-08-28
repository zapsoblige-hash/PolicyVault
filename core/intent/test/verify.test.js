"use strict";

/*
 * UNIT / ADVERSARIAL (detector level) — fail-closed verification
 * (core/intent/verify.js).
 *
 * Each adversarial case models a policy-invalid adversarial test manifest
 * or transaction description: internally consistent enough to pass the
 * schema (the author controls the manifest hash, so tampered documents
 * are re-hashed canonically), yet describing something OTHER than the
 * requested action. Every case must REFUSE with the specific detector
 * code; the verified statement is emitted only when every detector
 * passes.
 */

const test = require("node:test");
const assert = require("node:assert/strict");

const { verifyIntentManifest, VERIFIED_STATEMENT, VERDICTS } = require("../verify");
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
  ATTACKER
} = require("../testutil/fixtures");

function codes(result) {
  return result.failures.map((f) => f.code);
}

function expectRefused(result, requiredCodes, label) {
  assert.equal(result.ok, false, `${label}: must refuse`);
  assert.equal(result.verdict, VERDICTS.REFUSED, label);
  assert.equal(result.statement, null, `${label}: no statement on refusal`);
  for (const code of requiredCodes) {
    assert.ok(codes(result).includes(code), `${label}: expected code ${code}, got ${JSON.stringify(codes(result))}`);
  }
}

/* Tamper the manifest, rehash canonically, verify self-contained. */
function verifyTampered(fixtureFn, mutate) {
  const m = clone(fixtureFn().manifest);
  mutate(m);
  return verifyIntentManifest({ manifest: rehash(m) });
}

/* Rebuild through the real builder with modified structured inputs and
 * verify against the modified intent/transaction (fully consistent
 * document, wrong facts). */
function verifyRebuilt(fixtureFn, mutateInputs) {
  const { buildInputs } = fixtureFn();
  const inputs = clone(buildInputs);
  mutateInputs(inputs);
  const { buildIntentManifest } = require("../manifest");
  const manifest = buildIntentManifest(inputs);
  return verifyIntentManifest({
    manifest,
    requestedIntent: inputs.requestedIntent,
    decodedTransaction: inputs.transaction
  });
}

test("verdict: every golden fixture is VERIFIED_EXACT with the exact statement", () => {
  const fixtures = [
    agentSpendFixture,
    ownerTopUpFixture,
    ownerPauseFixture,
    ownerSetApproversFixture,
    ownerSetAgentRootFixture,
    ownerRecoverFixture,
    createVaultFixture
  ];
  for (const fn of fixtures) {
    const fx = fn();
    const result = verifyIntentManifest({
      manifest: fx.manifest,
      requestedIntent: fx.requestedIntent,
      decodedTransaction: fx.decodedTransaction
    });
    assert.equal(result.ok, true, `${fn.name}: ${JSON.stringify(result.failures)}`);
    assert.equal(result.verdict, VERDICTS.VERIFIED_EXACT, fn.name);
    assert.equal(result.statement, VERIFIED_STATEMENT, fn.name);
    assert.equal(result.statement, "THIS TRANSACTION DOES EXACTLY WHAT WAS REQUESTED AND NOTHING ELSE.");
    assert.equal(result.manifestHash, fx.manifest.manifestHash);
    assert.equal(result.txId, fx.manifest.transaction.txId);
    assert.ok(result.checks.every((c) => c.ok), fn.name);
  }
});

test("verdict: the high-level lifecycle golden (addAgent) also verifies", () => {
  const fx = ownerSetAgentRootFixture("addAgent");
  const result = verifyIntentManifest({ manifest: fx.manifest, requestedIntent: fx.requestedIntent, decodedTransaction: fx.decodedTransaction });
  assert.equal(result.verdict, VERDICTS.VERIFIED_EXACT);
});

test("adversarial: tampered manifest without a canonical rehash hard-refuses on the hash", () => {
  const m = clone(agentSpendFixture().manifest);
  m.payment.recipientXOnly = ATTACKER; // mutate, keep the stale hash
  const result = verifyIntentManifest({ manifest: m });
  expectRefused(result, ["MANIFEST_HASH_MISMATCH"], "stale-hash tamper");
  assert.equal(result.checks.length, 1, "hard stop after validation failure");
});

test("adversarial: extra hidden output on an owner op", () => {
  const result = verifyTampered(ownerTopUpFixture, (m) => {
    m.transaction.outputs.push(p2pkOutput("5000", ATTACKER));
    m.effects.outputs.push({ index: 2, kind: "change" });
  });
  expectRefused(result, ["UNEXPECTED_OUTPUT"], "third output beyond the action's shape");
});

test("adversarial: extra output smuggled into an agent spend as fuel-less change", () => {
  const result = verifyTampered(agentSpendFixture, (m) => {
    m.transaction.outputs.push(p2pkOutput("5000", ATTACKER));
    m.effects.outputs.push({ index: 2, kind: "change" });
  });
  // change without a fuel input violates the coupled shape; the attacker
  // key fails the change-script rule; the extra value breaks conservation
  expectRefused(result, ["ACTION_TX_SHAPE_MISMATCH", "HIDDEN_RECIPIENT", "VALUE_CONSERVATION_VIOLATION"], "smuggled change output");
});

test("adversarial: recipient substitution in the payment output script", () => {
  const result = verifyTampered(agentSpendFixture, (m) => {
    m.transaction.outputs[0].scriptPublicKey.scriptHex = `20${ATTACKER}ac`; // payment is output 0
  });
  expectRefused(result, ["HIDDEN_RECIPIENT"], "payment script to a different key");
});

test("adversarial: recipient substitution declared consistently still mismatches the request", () => {
  const result = verifyTampered(agentSpendFixture, (m) => {
    m.transaction.outputs[0].scriptPublicKey.scriptHex = `20${ATTACKER}ac`; // payment is output 0
    m.payment.recipientXOnly = ATTACKER;
  });
  expectRefused(result, ["REQUEST_MISMATCH"], "recipient differs from the requested recipient");
});

test("adversarial: change output redirected away from the signer", () => {
  const result = verifyTampered(ownerTopUpFixture, (m) => {
    m.transaction.outputs[1].scriptPublicKey.scriptHex = `20${ATTACKER}ac`;
  });
  expectRefused(result, ["HIDDEN_RECIPIENT"], "change to a non-signer key");
});

test("adversarial: fee inflation against the requested cap (consistent everywhere else)", () => {
  const result = verifyRebuilt(agentSpendFixture, (inputs) => {
    // reserve-funded fee raised to 20000 — every equation consistent,
    // but the request capped the fee at 10000
    inputs.requestedIntent.params.reserveConsumedSompi = "20000";
    inputs.accounting.reserveConsumed = "20000";
    inputs.accounting.fee = "20000";
    inputs.accounting.successorFeeReserve = "99980000";
    inputs.accounting.successorTotal = "49099980000";
    inputs.stateAfter.state.feeReserve = "99980000";
    inputs.transaction.outputs[1].value = "49099980000"; // successor is output 1
  });
  expectRefused(result, ["EXCESSIVE_FEE"], "fee above maxFeeSompi");
});

test("adversarial: fee misdeclaration breaks the sompi ledger", () => {
  const result = verifyTampered(agentSpendFixture, (m) => {
    m.accounting.fee = "4000"; // real inputs−outputs is 5000
  });
  expectRefused(result, ["VALUE_CONSERVATION_VIOLATION"], "declared fee != inputs − outputs");
});

test("adversarial: wrong successor value (skimmed into change)", () => {
  const result = verifyTampered(ownerTopUpFixture, (m) => {
    m.transaction.outputs[0].value = "55099999000"; // −1000
    m.transaction.outputs[1].value = "6000"; // +1000, conservation intact
  });
  expectRefused(result, ["WRONG_SUCCESSOR"], "covenant output no longer carries protected+reserve");
});

test("adversarial: successor bound to a different covenantId", () => {
  const result = verifyTampered(ownerTopUpFixture, (m) => {
    m.transaction.outputs[0].covenant.covenantId = ATTACKER;
  });
  expectRefused(result, ["WRONG_SUCCESSOR"], "foreign covenant binding");
});

test("adversarial: successor outpoint expectation redirected", () => {
  const result = verifyTampered(ownerTopUpFixture, (m) => {
    m.stateAfter.expectedOutpoint.index = 1;
  });
  expectRefused(result, ["WRONG_SUCCESSOR"], "expectedOutpoint does not name the covenant output");
});

test("adversarial: predecessor outpoint mismatch", () => {
  const result = verifyTampered(agentSpendFixture, (m) => {
    m.transaction.inputs[0].previousOutpoint.index = 1;
  });
  expectRefused(result, ["PREDECESSOR_MISMATCH"], "spending a different predecessor outpoint");
});

test("adversarial: predecessor covenantId mismatch", () => {
  const result = verifyTampered(agentSpendFixture, (m) => {
    m.transaction.inputs[0].utxo.covenantId = ATTACKER;
  });
  expectRefused(result, ["PREDECESSOR_MISMATCH"], "covenant input from a different covenant lineage");
});

test("adversarial: hidden policy mutation under an agent spend", () => {
  const result = verifyTampered(agentSpendFixture, (m) => {
    m.stateAfter.state.approvalM = "1"; // approval policy silently weakened
  });
  expectRefused(
    result,
    ["HIDDEN_POLICY_MUTATION", "AUTHORITY_EXPANSION", "POLICY_MUTATION_MISDECLARED"],
    "agentSpend may not touch the approval configuration"
  );
});

test("adversarial: hidden agent-root change under an owner top-up", () => {
  const result = verifyTampered(ownerTopUpFixture, (m) => {
    m.stateAfter.state.agentRoot = ATTACKER;
  });
  expectRefused(result, ["HIDDEN_POLICY_MUTATION", "AUTHORITY_EXPANSION"], "ownerTopUp may not change the agent registry root");
});

test("adversarial: silent unpause smuggled into a top-up", () => {
  const result = verifyRebuilt(ownerTopUpFixture, (inputs) => {
    inputs.stateBefore.state.paused = "1";
    inputs.stateAfter.state.paused = "0";
  });
  expectRefused(result, ["HIDDEN_POLICY_MUTATION", "AUTHORITY_EXPANSION"], "only ownerUnpause may unpause");
});

test("adversarial: requested action != serialized transaction (pause manifest, spend bytes)", () => {
  const spend = agentSpendFixture();
  const result = verifyRebuilt(ownerPauseFixture, (inputs) => {
    inputs.transaction = clone(spend.manifest.transaction);
    // honest classification of the injected spend bytes (payment@0, successor@1)
    inputs.effects = { inputs: ["covenant"], outputs: ["payment", "successor"] };
  });
  expectRefused(result, ["ACTION_TX_SHAPE_MISMATCH", "WRONG_SUCCESSOR"], "the transaction is a spend, not a pause");
});

test("adversarial: authority expansion — approvals weakened relative to the request", () => {
  const result = verifyRebuilt(ownerSetApproversFixture, (inputs) => {
    inputs.stateAfter.state.approvalM = "1"; // requested newApprovalM stays "3"
  });
  expectRefused(result, ["REQUEST_MISMATCH"], "successor approvalM differs from the requested configuration");
});

test("adversarial: nonce rule violations in both directions", () => {
  const advanced = verifyRebuilt(ownerPauseFixture, (inputs) => {
    inputs.stateAfter.state.policyNonce = "8"; // pause must PRESERVE the nonce
  });
  expectRefused(advanced, ["NONCE_RULE_VIOLATION", "AUTHORITY_EXPANSION"], "nonce advanced by a preserving action");

  const frozen = verifyRebuilt(ownerSetApproversFixture, (inputs) => {
    inputs.stateAfter.state.policyNonce = "7"; // setApprovers must INCREMENT
  });
  expectRefused(frozen, ["NONCE_RULE_VIOLATION"], "nonce not incremented by a policy mutation");
});

test("adversarial: rollover spend without the covenant's CLTV lockTime", () => {
  const result = verifyRebuilt(agentSpendFixture, (inputs) => {
    inputs.requestedIntent.params.periodsElapsed = "1";
    inputs.limits.periodsElapsed = "1";
    // lockTime stays "0" and policyAfter still claims the old period
  });
  expectRefused(result, ["LOCKTIME_RULE_VIOLATION", "AGENT_POLICY_MISMATCH"], "rollover requires lockTime = new period start");
});

test("adversarial: spend above the agent's maxPerSpend", () => {
  const result = verifyRebuilt(agentSpendFixture, (inputs) => {
    const pay = "2500000000"; // maxPerSpend is 2000000000
    inputs.requestedIntent.params.payAmountSompi = pay;
    inputs.payment.amountSompi = pay;
    inputs.transaction.outputs[0].value = pay; // payment is output 0
    inputs.transaction.outputs[1].value = "47599995000"; // successor is output 1
    inputs.accounting.payAmount = pay;
    inputs.accounting.successorProtected = "47500000000";
    inputs.accounting.successorTotal = "47599995000";
    inputs.stateAfter.state.protectedValue = "47500000000";
    inputs.limits.policyAfter.periodSpent = "3000000000";
  });
  expectRefused(result, ["LIMIT_VIOLATION"], "payAmount above maxPerSpend");
});

test("adversarial: spend exceeding the remaining period budget", () => {
  const result = verifyRebuilt(agentSpendFixture, (inputs) => {
    inputs.limits.policyBefore.periodSpent = "4500000000"; // + 1e9 pay > 5e9 budget
    inputs.limits.policyAfter.periodSpent = "5500000000";
  });
  expectRefused(result, ["LIMIT_VIOLATION"], "period budget exceeded");
});

test("adversarial: reserve drawdown above the agent's per-tx fee cap", () => {
  const result = verifyRebuilt(agentSpendFixture, (inputs) => {
    inputs.limits.policyBefore.agentMaxFeePerTx = "1000"; // reserveConsumed is 5000
    inputs.limits.policyAfter.agentMaxFeePerTx = "1000";
  });
  expectRefused(result, ["RESERVE_RULE_VIOLATION"], "reserveConsumed above agentMaxFeePerTx");
});

test("adversarial: approval tier misdeclared (above-threshold spend claimed below)", () => {
  const result = verifyRebuilt(agentSpendFixture, (inputs) => {
    inputs.limits.policyBefore.approvalThreshold = "500000000"; // pay 1e9 is ABOVE
    inputs.limits.policyAfter.approvalThreshold = "500000000";
    inputs.approvals.approvalThreshold = "500000000";
    // approvals.aboveThreshold stays false
  });
  expectRefused(result, ["APPROVAL_TIER_MISMATCH"], "aboveThreshold must reflect pay vs threshold");
});

test("adversarial: allowlist not proven / root mismatch", () => {
  const notProven = verifyRebuilt(agentSpendFixture, (inputs) => {
    inputs.allowlist.recipientAllowlisted = false;
  });
  expectRefused(notProven, ["ALLOWLIST_NOT_PROVEN"], "unproven recipient membership");

  const wrongRoot = verifyRebuilt(agentSpendFixture, (inputs) => {
    inputs.allowlist.agentRecipientRoot = ATTACKER;
  });
  expectRefused(wrongRoot, ["ALLOWLIST_MISMATCH"], "allowlist root differs from the agent policy");
});

test("adversarial: terminal payout mismatch on recovery", () => {
  const result = verifyTampered(ownerRecoverFixture, (m) => {
    m.transaction.outputs[0].value = "50099999000"; // −1000
    m.transaction.outputs[1].value = "6000"; // +1000, conservation intact
  });
  expectRefused(result, ["TERMINAL_PAYOUT_MISMATCH"], "recovery must pay out exactly protected+reserve");
});

test("adversarial: genesis state differs from the requested initial state", () => {
  const result = verifyRebuilt(createVaultFixture, (inputs) => {
    inputs.stateAfter.state.approvalM = "1"; // requested initialState says "2"
  });
  expectRefused(result, ["REQUEST_MISMATCH"], "genesis state must equal the requested initialState");
});

test("adversarial: recorded unexpected effects refuse the manifest", () => {
  const result = verifyRebuilt(ownerTopUpFixture, (inputs) => {
    inputs.unexpectedEffects = [{ code: "UNEXPLAINED_VALUE_FLOW", detail: "builder observed an unattributed output" }];
  });
  expectRefused(result, ["UNEXPECTED_EFFECTS_PRESENT"], "unexplained effects are never acceptable");
});

test("binding: a supplied requested intent that differs from the embedded one refuses", () => {
  const fx = agentSpendFixture();
  const differentIntent = clone(fx.requestedIntent);
  differentIntent.params.payAmountSompi = "999999999";
  const result = verifyIntentManifest({ manifest: fx.manifest, requestedIntent: differentIntent });
  expectRefused(result, ["REQUEST_MISMATCH"], "intent binding");
});

test("binding: a supplied decoded transaction that differs from the embedded one refuses", () => {
  const fx = agentSpendFixture();
  const differentTx = clone(fx.decodedTransaction);
  differentTx.outputs[1].value = "1000000001";
  const result = verifyIntentManifest({ manifest: fx.manifest, decodedTransaction: differentTx });
  expectRefused(result, ["TX_MISMATCH"], "transaction binding");
});

test("binding: self-contained verification (no external copies) still runs the full catalogue", () => {
  const fx = agentSpendFixture();
  const result = verifyIntentManifest({ manifest: fx.manifest });
  assert.equal(result.verdict, VERDICTS.VERIFIED_EXACT);
  assert.ok(!result.checks.some((c) => c.id === "intent-binding"));
  assert.ok(!result.checks.some((c) => c.id === "transaction-binding"));
  assert.ok(result.checks.some((c) => c.id === "value-conservation"));
});

test("fail closed: a structurally invalid manifest never reaches the detectors", () => {
  const result = verifyIntentManifest({ manifest: { manifestVersion: "policyvault-intent-manifest/1" } });
  expectRefused(result, ["SCHEMA_INVALID"], "invalid structure");
  assert.equal(result.checks.length, 1);
  assert.equal(result.checks[0].id, "manifest-valid");
});

test("fail closed: unknown versions and actions refuse with their own codes at verify time", () => {
  const base = agentSpendFixture().manifest;
  const version = clone(base);
  version.manifestVersion = "policyvault-intent-manifest/99";
  expectRefused(verifyIntentManifest({ manifest: rehash(version) }), ["UNKNOWN_MANIFEST_VERSION"], "unknown manifest version");

  const covenant = clone(base);
  covenant.vault.covenantVersion = "policyvault-0.3";
  covenant.requested.covenantVersion = "policyvault-0.3";
  expectRefused(verifyIntentManifest({ manifest: rehash(covenant) }), ["UNSUPPORTED_COVENANT_VERSION"], "unsupported covenant version");

  const action = clone(base);
  action.action.sdkAction = "ownerDelegateEverything";
  expectRefused(verifyIntentManifest({ manifest: rehash(action) }), ["UNKNOWN_ACTION"], "unknown action");
});

test("result shape: structured checks, aggregated failures, frozen result", () => {
  const fx = agentSpendFixture();
  const result = verifyIntentManifest({ manifest: fx.manifest, requestedIntent: fx.requestedIntent, decodedTransaction: fx.decodedTransaction });
  assert.ok(Array.isArray(result.checks) && result.checks.length >= 14);
  for (const check of result.checks) {
    assert.ok(typeof check.id === "string" && typeof check.ok === "boolean" && Array.isArray(check.failures));
  }
  assert.ok(Object.isFrozen(result) && Object.isFrozen(result.checks));
  const refused = verifyTampered(agentSpendFixture, (m) => { m.accounting.fee = "4000"; });
  assert.equal(refused.failures.length, refused.checks.reduce((n, c) => n + c.failures.length, 0));
});
