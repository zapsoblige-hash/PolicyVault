"use strict";

/*
 * UNIT tests — deny-wins composition + policy gate (Program D core).
 * Layer: UNIT (pure composition; timers only for timeout paths).
 *
 * The load-bearing invariants under test:
 *   1. DENY wins over REVIEW wins over ALLOW.
 *   2. An erroring / timing-out / malformed adapter NEVER yields ALLOW.
 *   3. The empty adapter set is default-restrictive for review-required
 *      organizations and cannot be configured permissive for them.
 *   4. STRUCTURAL: no risk output — including ALLOW — can upgrade a
 *      policy (covenant-mirroring) DENY.
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");

const { RiskRefusal, VERDICT_ALLOW, VERDICT_REVIEW, VERDICT_DENY } = require("../interface");
const { normalizeCompositionConfig, composeVerdicts, evaluateRisk, applyRiskToPolicyDecision, POLICY_DENY, POLICY_ALLOW, DEFAULT_TIMEOUT_MS } = require("../compose");
const {
  makeAllowAllAdapter,
  makeDenyAllAdapter,
  makeReviewAllAdapter,
  makeAmountThresholdAdapter,
  makeRecipientScreeningAdapter,
  makeThrowingAdapter,
  makeSyncThrowingAdapter,
  makeHangingAdapter,
  makeMalformedVerdictAdapter,
  makeSlowAdapter
} = require("../mock-adapters");

function refusalCode(fn) {
  try {
    fn();
  } catch (err) {
    assert.ok(err instanceof RiskRefusal, `expected RiskRefusal, got ${err && err.name}: ${err && err.message}`);
    return err.code;
  }
  assert.fail("expected a fail-closed refusal");
}

async function refusalCodeAsync(promise) {
  try {
    await promise;
  } catch (err) {
    assert.ok(err instanceof RiskRefusal, `expected RiskRefusal, got ${err && err.name}: ${err && err.message}`);
    return err.code;
  }
  assert.fail("expected a fail-closed refusal");
}

const INTENT = Object.freeze({
  schema: "policyvault-intent/test",
  network: "testnet-10",
  vaultId: "11".repeat(32),
  sdkAction: "agentSpend",
  payAmountSompi: "250000000",
  recipient: "31".repeat(32)
});

/* ------------------------------------------------------------------ */
/* Pure composition                                                    */
/* ------------------------------------------------------------------ */

test("composeVerdicts: DENY wins over REVIEW wins over ALLOW (full matrix)", () => {
  assert.equal(composeVerdicts([VERDICT_ALLOW]), VERDICT_ALLOW);
  assert.equal(composeVerdicts([VERDICT_ALLOW, VERDICT_ALLOW]), VERDICT_ALLOW);
  assert.equal(composeVerdicts([VERDICT_ALLOW, VERDICT_REVIEW]), VERDICT_REVIEW);
  assert.equal(composeVerdicts([VERDICT_REVIEW, VERDICT_ALLOW]), VERDICT_REVIEW);
  assert.equal(composeVerdicts([VERDICT_REVIEW, VERDICT_REVIEW]), VERDICT_REVIEW);
  assert.equal(composeVerdicts([VERDICT_ALLOW, VERDICT_REVIEW, VERDICT_DENY]), VERDICT_DENY);
  assert.equal(composeVerdicts([VERDICT_DENY, VERDICT_ALLOW]), VERDICT_DENY);
  assert.equal(composeVerdicts([VERDICT_DENY, VERDICT_REVIEW]), VERDICT_DENY);
  assert.equal(composeVerdicts([VERDICT_DENY]), VERDICT_DENY);
});

test("composeVerdicts: unknown verdicts and the empty list refuse", () => {
  assert.equal(refusalCode(() => composeVerdicts(["approve"])), "ADAPTER_VERDICT_UNKNOWN");
  assert.equal(refusalCode(() => composeVerdicts([VERDICT_ALLOW, "allow"])), "ADAPTER_VERDICT_UNKNOWN");
  assert.equal(refusalCode(() => composeVerdicts([])), "RISK_COMPOSE_INVALID");
  assert.equal(refusalCode(() => composeVerdicts("DENY")), "RISK_COMPOSE_INVALID");
});

/* ------------------------------------------------------------------ */
/* Configuration (fail-closed)                                         */
/* ------------------------------------------------------------------ */

test("composition config defaults: onAdapterError REVIEW, onEmpty ALLOW, 5s timeout", () => {
  const cfg = normalizeCompositionConfig({}, {});
  assert.equal(cfg.onAdapterError, VERDICT_REVIEW);
  assert.equal(cfg.onEmpty, VERDICT_ALLOW);
  assert.equal(cfg.timeoutMs, DEFAULT_TIMEOUT_MS);
  assert.equal(cfg.reviewRequired, false);
});

test("review-required organizations default to REVIEW on the empty set", () => {
  const cfg = normalizeCompositionConfig({}, { riskPolicy: { reviewRequired: true } });
  assert.equal(cfg.onEmpty, VERDICT_REVIEW);
  assert.equal(cfg.reviewRequired, true);
});

test("a review-required organization may not configure the empty set to ALLOW", () => {
  assert.equal(
    refusalCode(() => normalizeCompositionConfig({ onEmpty: "ALLOW" }, { riskPolicy: { reviewRequired: true } })),
    "RISK_CONFIG_CONFLICT"
  );
  /* DENY-on-empty is fine (more restrictive). */
  const cfg = normalizeCompositionConfig({ onEmpty: "DENY" }, { riskPolicy: { reviewRequired: true } });
  assert.equal(cfg.onEmpty, VERDICT_DENY);
});

test("onAdapterError can never be ALLOW; unknown config values refuse", () => {
  assert.equal(refusalCode(() => normalizeCompositionConfig({ onAdapterError: "ALLOW" })), "RISK_CONFIG_INVALID");
  assert.equal(refusalCode(() => normalizeCompositionConfig({ onAdapterError: "PERMIT" })), "RISK_CONFIG_INVALID");
  assert.equal(refusalCode(() => normalizeCompositionConfig({ onEmpty: "permit" })), "RISK_CONFIG_INVALID");
  assert.equal(refusalCode(() => normalizeCompositionConfig({ unknownKnob: 1 })), "RISK_CONFIG_INVALID");
  assert.equal(refusalCode(() => normalizeCompositionConfig({ timeoutMs: 0 })), "RISK_CONFIG_INVALID");
  assert.equal(refusalCode(() => normalizeCompositionConfig({ timeoutMs: 1.5 })), "RISK_CONFIG_INVALID");
  assert.equal(refusalCode(() => normalizeCompositionConfig({}, { riskPolicy: { reviewRequired: "yes" } })), "RISK_CONTEXT_INVALID");
  assert.equal(refusalCode(() => normalizeCompositionConfig({}, { riskPolicy: "strict" })), "RISK_CONTEXT_INVALID");
});

/* ------------------------------------------------------------------ */
/* evaluateRisk end to end                                             */
/* ------------------------------------------------------------------ */

test("all-ALLOW adapters compose to ALLOW with ordered results", async () => {
  const out = await evaluateRisk({
    adapters: [makeAllowAllAdapter({ name: "a1" }), makeAllowAllAdapter({ name: "a2" })],
    intent: INTENT,
    context: {}
  });
  assert.equal(out.decision, VERDICT_ALLOW);
  assert.deepEqual(out.results.map((r) => r.adapter), ["a1", "a2"]);
  assert.ok(Object.isFrozen(out));
  assert.ok(Object.isFrozen(out.results));
});

test("REVIEW and DENY dominate mixed adapter sets; reasons and evidence propagate", async () => {
  const review = await evaluateRisk({
    adapters: [makeAllowAllAdapter(), makeReviewAllAdapter({ code: "NEEDS_EYES" })],
    intent: INTENT
  });
  assert.equal(review.decision, VERDICT_REVIEW);
  assert.ok(review.codes.includes("NEEDS_EYES"));

  const deny = await evaluateRisk({
    adapters: [makeReviewAllAdapter(), makeDenyAllAdapter({ code: "HARD_STOP" }), makeAllowAllAdapter()],
    intent: INTENT
  });
  assert.equal(deny.decision, VERDICT_DENY);
  assert.ok(deny.codes.includes("HARD_STOP"));
  assert.equal(deny.results.length, 3);
});

test("empty adapter set: default ALLOW for plain contexts, REVIEW for review-required orgs, DENY when configured", async () => {
  const plain = await evaluateRisk({ adapters: [], intent: INTENT, context: {} });
  assert.equal(plain.decision, VERDICT_ALLOW);
  assert.deepEqual([...plain.codes], []);

  const reviewRequired = await evaluateRisk({ adapters: [], intent: INTENT, context: { riskPolicy: { reviewRequired: true } } });
  assert.equal(reviewRequired.decision, VERDICT_REVIEW);
  assert.ok(reviewRequired.codes.includes("RISK_ADAPTER_SET_EMPTY"));

  const denyOnEmpty = await evaluateRisk({ adapters: [], intent: INTENT, context: {}, config: { onEmpty: "DENY" } });
  assert.equal(denyOnEmpty.decision, VERDICT_DENY);
});

test("throwing adapters (sync and async) map to onAdapterError and never ALLOW", async () => {
  const out = await evaluateRisk({
    adapters: [makeAllowAllAdapter(), makeThrowingAdapter(), makeSyncThrowingAdapter()],
    intent: INTENT
  });
  assert.equal(out.decision, VERDICT_REVIEW);
  const errored = out.results.filter((r) => r.status === "ERROR");
  assert.equal(errored.length, 2);
  for (const r of errored) {
    assert.equal(r.errorCode, "ADAPTER_ERROR");
    assert.equal(r.verdict, VERDICT_REVIEW);
  }

  const denyCfg = await evaluateRisk({
    adapters: [makeAllowAllAdapter(), makeThrowingAdapter()],
    intent: INTENT,
    config: { onAdapterError: "DENY" }
  });
  assert.equal(denyCfg.decision, VERDICT_DENY);
});

test("a hanging adapter times out to onAdapterError and never ALLOW", async () => {
  const out = await evaluateRisk({
    adapters: [makeAllowAllAdapter(), makeHangingAdapter({ timeoutMs: 40 })],
    intent: INTENT
  });
  assert.equal(out.decision, VERDICT_REVIEW);
  const timedOut = out.results.find((r) => r.status === "TIMEOUT");
  assert.ok(timedOut);
  assert.equal(timedOut.errorCode, "ADAPTER_TIMEOUT");
  assert.equal(timedOut.verdict, VERDICT_REVIEW);

  const denyCfg = await evaluateRisk({
    adapters: [makeHangingAdapter({ timeoutMs: 40 })],
    intent: INTENT,
    config: { onAdapterError: "DENY" }
  });
  assert.equal(denyCfg.decision, VERDICT_DENY);
});

test("a slow adapter inside its timeout completes normally", async () => {
  const out = await evaluateRisk({
    adapters: [makeSlowAdapter({ delayMs: 20, verdict: VERDICT_REVIEW, timeoutMs: 2000 })],
    intent: INTENT
  });
  assert.equal(out.decision, VERDICT_REVIEW);
  assert.equal(out.results[0].status, "OK");
});

test("malformed and unknown adapter verdicts map through onAdapterError, never ALLOW", async () => {
  const out = await evaluateRisk({
    adapters: [
      makeAllowAllAdapter(),
      makeMalformedVerdictAdapter({ name: "mock-permit", result: { verdict: "PERMIT", reasons: [] } }),
      makeMalformedVerdictAdapter({ name: "mock-shape", result: { verdict: "ALLOW", reasons: "none" } }),
      makeMalformedVerdictAdapter({ name: "mock-null", result: null }),
      makeMalformedVerdictAdapter({ name: "mock-silent-deny", result: { verdict: "DENY", reasons: [] } })
    ],
    intent: INTENT
  });
  assert.equal(out.decision, VERDICT_REVIEW);
  const permit = out.results.find((r) => r.adapter === "mock-permit");
  assert.equal(permit.status, "ERROR");
  assert.equal(permit.errorCode, "ADAPTER_VERDICT_UNKNOWN");
  assert.equal(permit.verdict, VERDICT_REVIEW);
  for (const name of ["mock-shape", "mock-null", "mock-silent-deny"]) {
    const r = out.results.find((x) => x.adapter === name);
    assert.equal(r.status, "ERROR");
    assert.equal(r.verdict, VERDICT_REVIEW);
  }
});

test("reference mocks: amount threshold ALLOW/REVIEW/DENY and unreadable-amount DENY", async () => {
  const adapter = makeAmountThresholdAdapter({ maxSompi: "1000000000", reviewSompi: "500000000" });
  const low = await evaluateRisk({ adapters: [adapter], intent: { ...INTENT, payAmountSompi: "100" } });
  assert.equal(low.decision, VERDICT_ALLOW);
  const mid = await evaluateRisk({ adapters: [adapter], intent: { ...INTENT, payAmountSompi: "600000000" } });
  assert.equal(mid.decision, VERDICT_REVIEW);
  const high = await evaluateRisk({ adapters: [adapter], intent: { ...INTENT, payAmountSompi: "2000000000" } });
  assert.equal(high.decision, VERDICT_DENY);
  assert.ok(high.codes.includes("AMOUNT_ABOVE_LIMIT"));
  const unreadable = await evaluateRisk({ adapters: [adapter], intent: { ...INTENT, payAmountSompi: "1.5" } });
  assert.equal(unreadable.decision, VERDICT_DENY);
  assert.ok(unreadable.codes.includes("INTENT_AMOUNT_UNREADABLE"));
});

test("reference mocks: recipient screening restricts on miss and refuses a permissive miss-verdict", async () => {
  const cleared = makeRecipientScreeningAdapter({ clearedRecipients: [INTENT.recipient] });
  const ok = await evaluateRisk({ adapters: [cleared], intent: INTENT });
  assert.equal(ok.decision, VERDICT_ALLOW);

  const miss = await evaluateRisk({ adapters: [cleared], intent: { ...INTENT, recipient: "77".repeat(32) } });
  assert.equal(miss.decision, VERDICT_DENY);
  assert.ok(miss.codes.includes("RECIPIENT_NOT_SCREENED_CLEAR"));

  const reviewMiss = makeRecipientScreeningAdapter({ name: "screen-review", clearedRecipients: [], verdictOnMiss: "REVIEW" });
  const rm = await evaluateRisk({ adapters: [reviewMiss], intent: INTENT });
  assert.equal(rm.decision, VERDICT_REVIEW);

  assert.throws(
    () => makeRecipientScreeningAdapter({ clearedRecipients: [], verdictOnMiss: "ALLOW" }),
    (err) => err instanceof RiskRefusal
  );
});

test("evaluateRisk input discipline: non-object or JSON-unsafe intents refuse; duplicates refuse", async () => {
  assert.equal(await refusalCodeAsync(evaluateRisk({ adapters: [], intent: "spend" })), "RISK_INTENT_INVALID");
  assert.equal(await refusalCodeAsync(evaluateRisk({ adapters: [], intent: { amount: 5n } })), "JSON_UNSAFE");
  assert.equal(await refusalCodeAsync(evaluateRisk({ adapters: [], intent: { a: undefined } })), "JSON_UNSAFE");
  assert.equal(await refusalCodeAsync(evaluateRisk({ adapters: "none", intent: INTENT })), "RISK_COMPOSE_INVALID");
  assert.equal(
    await refusalCodeAsync(evaluateRisk({ adapters: [makeAllowAllAdapter({ name: "dup" }), makeDenyAllAdapter({ name: "dup" })], intent: INTENT })),
    "ADAPTER_DUPLICATE"
  );
  /* An adapter without a contract version is an UNKNOWN contract (fail closed). */
  assert.equal(
    await refusalCodeAsync(evaluateRisk({ adapters: [{ name: "half-defined" }], intent: INTENT })),
    "ADAPTER_CONTRACT_UNKNOWN"
  );
  /* An adapter that is not even an object is a malformed definition. */
  assert.equal(await refusalCodeAsync(evaluateRisk({ adapters: [null], intent: INTENT })), "ADAPTER_DEFINITION_INVALID");
});

test("adapters receive a frozen clone: mutation attempts cannot leak to the caller or other adapters", async () => {
  const original = { ...INTENT };
  const mutator = {
    name: "mock-mutator",
    adapterVersion: "1.0.0",
    contractVersion: "policyvault-risk-adapter/1",
    capabilities: ["custom-policy"],
    evaluate: async (intent) => {
      try {
        intent.payAmountSompi = "999999999999";
      } catch (_) {
        /* frozen — expected */
      }
      return { verdict: VERDICT_ALLOW, reasons: [] };
    }
  };
  const watcher = {
    name: "mock-watcher",
    adapterVersion: "1.0.0",
    contractVersion: "policyvault-risk-adapter/1",
    capabilities: ["custom-policy"],
    evaluate: async (intent) =>
      intent.payAmountSompi === original.payAmountSompi
        ? { verdict: VERDICT_ALLOW, reasons: [] }
        : { verdict: VERDICT_DENY, reasons: [{ code: "INTENT_MUTATED", message: "intent changed between adapters" }] }
  };
  const out = await evaluateRisk({ adapters: [mutator, watcher], intent: original });
  assert.equal(out.decision, VERDICT_ALLOW);
  assert.equal(original.payAmountSompi, INTENT.payAmountSompi);
});

/* ------------------------------------------------------------------ */
/* The policy gate — structural override impossibility                 */
/* ------------------------------------------------------------------ */

test("policy gate matrix: policy ALLOW passes the risk decision through", () => {
  assert.deepEqual(applyRiskToPolicyDecision({ policyDecision: POLICY_ALLOW, riskDecision: VERDICT_ALLOW }), { final: "ALLOW", source: "policy+risk" });
  assert.deepEqual(applyRiskToPolicyDecision({ policyDecision: POLICY_ALLOW, riskDecision: VERDICT_REVIEW }), { final: "REVIEW", source: "risk" });
  assert.deepEqual(applyRiskToPolicyDecision({ policyDecision: POLICY_ALLOW, riskDecision: VERDICT_DENY }), { final: "DENY", source: "risk" });
});

test("STRUCTURAL: no risk verdict — including ALLOW or garbage — can upgrade a policy DENY", () => {
  for (const risk of [VERDICT_ALLOW, VERDICT_REVIEW, VERDICT_DENY, "PERMIT", "allow", null, undefined, 42, { verdict: "ALLOW" }]) {
    const out = applyRiskToPolicyDecision({ policyDecision: POLICY_DENY, riskDecision: risk });
    assert.equal(out.final, POLICY_DENY);
    assert.equal(out.source, "policy");
  }
});

test("unknown policy decisions refuse (there is no third policy state)", () => {
  for (const bad of ["REVIEW", "allow", "deny", 1, null, undefined, {}]) {
    assert.equal(refusalCode(() => applyRiskToPolicyDecision({ policyDecision: bad, riskDecision: VERDICT_ALLOW })), "POLICY_DECISION_UNKNOWN");
  }
});

test("policy ALLOW + unknown risk decision refuses (fail closed, no default verdict)", () => {
  for (const bad of ["PERMIT", "allow", null, undefined, 42]) {
    assert.equal(refusalCode(() => applyRiskToPolicyDecision({ policyDecision: POLICY_ALLOW, riskDecision: bad })), "ADAPTER_VERDICT_UNKNOWN");
  }
});

test("end to end: a composed risk ALLOW still cannot override a covenant-mirroring DENY", async () => {
  const out = await evaluateRisk({ adapters: [makeAllowAllAdapter(), makeAllowAllAdapter({ name: "a2" })], intent: INTENT });
  assert.equal(out.decision, VERDICT_ALLOW);
  const gated = applyRiskToPolicyDecision({ policyDecision: POLICY_DENY, riskDecision: out.decision });
  assert.equal(gated.final, POLICY_DENY);
  assert.equal(gated.source, "policy");
});
