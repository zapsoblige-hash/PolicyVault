"use strict";

/*
 * UNIT — core/explain/risk-explain.js: deterministic rendering of risk
 * evaluations, strict fail-closed validation, and the stored-label
 * distrust recomputation (decision/codes/status/error-path
 * self-consistency — the governance §7.1 pattern applied to the risk
 * record). Includes the PRODUCER-BOUNDARY case: the exact output of the
 * real core/risk evaluateRisk (real mock adapters, error and timeout
 * paths included) must EXPLAIN, never refuse — the validator is pinned
 * to the real producer, not to a hand-built imitation of it.
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");

const riskExplain = require("../risk-explain.js");
const { structured, humanReadable, RISK_EXPLANATION_VERSION_1, RISK_EXPLANATION_VERDICTS } = riskExplain;
const coreRisk = require("../../risk");
const mocks = require("../../risk/mock-adapters.js");

/* ---- vocabulary mirror pins: the dependency-free mirror inside
 * risk-explain must equal core/risk's authoritative exports ---- */

test("vocabulary mirror: verdict strings and refusal-relevant constants match core/risk exactly", () => {
  assert.deepEqual([...coreRisk.RISK_VERDICTS], ["ALLOW", "REVIEW", "DENY"]);
  assert.equal(coreRisk.VERDICT_ALLOW, "ALLOW");
  assert.equal(coreRisk.VERDICT_REVIEW, "REVIEW");
  assert.equal(coreRisk.VERDICT_DENY, "DENY");
  /* the mirror itself is internal; its correctness is proven by the
   * producer-boundary tests below (real evaluateRisk output EXPLAINS and
   * the recomputed decision equals composeVerdicts) */
  for (const verdicts of [["ALLOW"], ["ALLOW", "REVIEW"], ["REVIEW", "DENY"], ["DENY", "ALLOW"], ["REVIEW", "REVIEW"]]) {
    const results = verdicts.map((v, i) => okResult({ adapter: `a-${i}`, verdict: v, reasons: v === "ALLOW" ? [] : [reason()] }));
    const evaluation = evalDoc({ decision: coreRisk.composeVerdicts(verdicts), results });
    const doc = structured(evaluation);
    assert.equal(doc.verdict, "EXPLAINED", JSON.stringify(doc.refusal));
  }
});

/* ---------------- fixtures ---------------- */

function reason(over = {}) {
  return { code: "THRESHOLD_EXCEEDED", message: "amount above the configured threshold", ...over };
}

function okResult(over = {}) {
  return {
    adapter: "threshold-guard",
    adapterVersion: "1.0.0",
    status: "OK",
    verdict: "REVIEW",
    reasons: [reason()],
    ...over
  };
}

function errorResult(over = {}) {
  return {
    adapter: "flaky",
    adapterVersion: "1.0.0",
    status: "TIMEOUT",
    errorCode: "ADAPTER_TIMEOUT",
    verdict: "REVIEW",
    reasons: [{ code: "ADAPTER_TIMEOUT", message: "adapter flaky exceeded 5000ms and was mapped to REVIEW (never ALLOW)" }],
    ...over
  };
}

function config(over = {}) {
  return { onAdapterError: "REVIEW", onEmpty: "ALLOW", timeoutMs: 5000, reviewRequired: false, ...over };
}

/* codes are recomputed from reasons — keep fixtures self-consistent */
function evalDoc({ decision, results, codes, ...rest }) {
  const expectedCodes =
    codes !== undefined ? codes : [...new Set((results || []).flatMap((r) => r.reasons.map((x) => x.code)))].sort();
  return { decision, results: results || [], codes: expectedCodes, config: config(), ...rest };
}

function serverRecord(over = {}) {
  return {
    schema: "policyvault-risk-evaluation/v1",
    evaluationId: "3c6f2a2e-0000-4000-8000-000000000001",
    networkId: "testnet-10",
    vaultId: "aa".repeat(32),
    orgId: "org-1",
    intentHash: "bd".repeat(32),
    intent: { schema: "policyvault-risk-intent/1", action: "agentSpend" },
    initiatorXOnly: "cc".repeat(32),
    status: "REVIEW_HELD",
    createdAt: "2026-08-26T00:00:00.000Z",
    ...evalDoc({ decision: "REVIEW", results: [okResult()] }),
    ...over
  };
}

/* ---------------- rendering ---------------- */

test("ALLOW / REVIEW / DENY headlines render deterministically with per-adapter lines", () => {
  const allow = humanReadable(evalDoc({ decision: "ALLOW", results: [okResult({ verdict: "ALLOW", reasons: [] })] }));
  assert.match(allow[0], /^RISK ALLOW: no configured risk control added a restriction/);
  assert.ok(allow.some((l) => l === "ALLOW: Adapter threshold-guard (version 1.0.0) declined to add a restriction."));

  const review = humanReadable(evalDoc({ decision: "REVIEW", results: [okResult()] }));
  assert.match(review[0], /^RISK REVIEW: this operation is held for human review/);
  assert.ok(review.some((l) => l.includes("REVIEW: Adapter threshold-guard") && l.includes("THRESHOLD_EXCEEDED: amount above the configured threshold")));

  const deny = humanReadable(evalDoc({ decision: "DENY", results: [okResult({ verdict: "DENY", reasons: [reason({ code: "SANCTIONS_HIT", message: "recipient matched a watchlist" })] })] }));
  assert.match(deny[0], /^RISK DENY: the organization's risk controls refuse/);
  assert.ok(deny.some((l) => l.includes("DENY: Adapter threshold-guard") && l.includes("SANCTIONS_HIT")));
  for (const lines of [allow, review, deny]) {
    assert.ok(lines.some((l) => l.includes("deny-wins")), "composition semantics stated");
    assert.equal(lines[lines.length - 1].includes("restrictive-only hosted coordination"), true, "trust note is the last line");
  }
});

test("determinism: same input renders byte-identical output on repeat calls", () => {
  const doc = serverRecord();
  assert.equal(JSON.stringify(humanReadable(doc)), JSON.stringify(humanReadable(JSON.parse(JSON.stringify(doc)))));
  assert.equal(JSON.stringify(structured(doc)), JSON.stringify(structured(JSON.parse(JSON.stringify(doc)))));
});

test("error/timeout results render the resolved restrictive verdict and never read as an adapter ALLOW", () => {
  const lines = humanReadable(evalDoc({ decision: "REVIEW", results: [errorResult()] }));
  const line = lines.find((l) => l.includes("flaky"));
  assert.ok(line, lines.join("\n"));
  assert.ok(line.includes("TIMED OUT") && line.includes("ADAPTER_TIMEOUT") && line.includes("resolved to REVIEW"));
  assert.ok(line.includes("never resolves to ALLOW"));
  assert.ok(!line.startsWith("ALLOW:"));
});

test("server-record fields render: lifecycle status line, codes, intent hash binding note", () => {
  const lines = humanReadable(serverRecord());
  assert.ok(lines.some((l) => l.startsWith("Evaluation status: REVIEW_HELD")));
  assert.ok(lines.some((l) => l === "Codes: THRESHOLD_EXCEEDED."));
  assert.ok(lines.some((l) => l.includes(`Evaluated intent hash: ${"bd".repeat(32)}`)));
  const doc = structured(serverRecord());
  assert.equal(doc.verdict, "EXPLAINED");
  assert.equal(doc.status, "REVIEW_HELD");
  assert.equal(doc.evaluationId, "3c6f2a2e-0000-4000-8000-000000000001");
  assert.equal(doc.adapterCount, 1);
  assert.equal(doc.errorCount, 0);
  assert.equal(doc.explanationVersion, RISK_EXPLANATION_VERSION_1);
  assert.ok(Object.isFrozen(doc) && Object.isFrozen(doc.perAdapter[0]));
});

test("empty adapter set renders the onEmpty resolution honestly (ALLOW and review-required REVIEW)", () => {
  const allow = humanReadable(evalDoc({ decision: "ALLOW", results: [], codes: [] }));
  assert.ok(allow.some((l) => l.includes("No risk adapters were configured") && l.includes("resolved it to ALLOW")));

  const held = humanReadable({
    decision: "REVIEW",
    results: [],
    codes: ["RISK_ADAPTER_SET_EMPTY"],
    config: config({ onEmpty: "REVIEW", reviewRequired: true })
  });
  assert.ok(held.some((l) => l.includes("resolved it to REVIEW")));
  assert.ok(held.some((l) => l.includes("riskPolicy.reviewRequired")));
  assert.ok(held.some((l) => l === "Codes: RISK_ADAPTER_SET_EMPTY."));
});

test("evidence presence is flagged, never dumped (deterministic across jsonb key reordering)", () => {
  const withEvidence = evalDoc({
    decision: "DENY",
    results: [okResult({ verdict: "DENY", reasons: [reason({ code: "KYT_HIT", message: "cluster exposure", evidence: { b: 1, a: 2 } })] })]
  });
  const reordered = evalDoc({
    decision: "DENY",
    results: [okResult({ verdict: "DENY", reasons: [reason({ code: "KYT_HIT", message: "cluster exposure", evidence: { a: 2, b: 1 } })] })]
  });
  assert.equal(JSON.stringify(humanReadable(withEvidence)), JSON.stringify(humanReadable(reordered)));
  assert.ok(humanReadable(withEvidence).some((l) => l.includes("[structured evidence attached]")));
  assert.equal(structured(withEvidence).perAdapter[0].reasons[0].hasEvidence, true);
  assert.ok(!JSON.stringify(structured(withEvidence).perAdapter).includes('"a":2'), "evidence body is not carried into the explanation");
});

/* ---------------- fail-closed refusals ---------------- */

function assertRefused(evaluation, expectedCode) {
  const doc = structured(evaluation);
  assert.equal(doc.verdict, RISK_EXPLANATION_VERDICTS.REFUSED, `expected refusal ${expectedCode}`);
  assert.ok(doc.refusal.codes.includes(expectedCode), `${expectedCode} not in ${doc.refusal.codes.join(",")}`);
  const lines = humanReadable(evaluation);
  assert.match(lines[0], /^RISK EXPLANATION REFUSED/);
  assert.ok(lines.some((l) => l.includes(expectedCode)));
  return doc;
}

test("TAMPERED stored decision refuses (DECISION_MISMATCH) — a DENY result narrated as ALLOW is an integrity alarm, never a rendering", () => {
  const tampered = evalDoc({ decision: "DENY", results: [okResult({ verdict: "DENY", reasons: [reason({ code: "SANCTIONS_HIT" })] })] });
  tampered.decision = "ALLOW"; // hostile: flat label flipped, per-adapter verdicts untouched
  const lines = humanReadable(tampered);
  assertRefused(tampered, "DECISION_MISMATCH");
  assert.ok(!lines.some((l) => l.startsWith("RISK ALLOW")), "the tampered ALLOW must never be narrated");
});

test("TAMPERED codes refuse (CODES_MISMATCH)", () => {
  const tampered = evalDoc({ decision: "REVIEW", results: [okResult()] });
  tampered.codes = []; // reasons say THRESHOLD_EXCEEDED; codes scrubbed
  assertRefused(tampered, "CODES_MISMATCH");
});

test("TAMPERED lifecycle status refuses (STATUS_MISMATCH) — a DENIED decision cannot wear an ALLOWED status", () => {
  assertRefused(serverRecord({ decision: "DENY", results: [okResult({ verdict: "DENY" })], codes: ["THRESHOLD_EXCEEDED"], status: "ALLOWED" }), "STATUS_MISMATCH");
  assertRefused(serverRecord({ status: "CONSUMED", decision: "DENY", results: [okResult({ verdict: "DENY" })], codes: ["THRESHOLD_EXCEEDED"] }), "STATUS_MISMATCH");
});

test("an ERROR/TIMEOUT result resolved to ALLOW refuses (ERROR_PATH_ALLOW — never-silent-ALLOW is load-bearing)", () => {
  const tampered = evalDoc({ decision: "ALLOW", results: [errorResult({ verdict: "ALLOW", reasons: [] })] });
  assertRefused(tampered, "ERROR_PATH_ALLOW");
});

test("an ERROR result diverging from the stored error policy refuses (ERROR_POLICY_MISMATCH)", () => {
  const doc = evalDoc({ decision: "DENY", results: [errorResult({ status: "ERROR", errorCode: "ADAPTER_ERROR", verdict: "DENY", reasons: [{ code: "ADAPTER_ERROR", message: "adapter threw" }] })] });
  // stored policy says REVIEW; the result claims it resolved to DENY
  assertRefused(doc, "ERROR_POLICY_MISMATCH");
});

test("unknown decision / result status / verdict / lifecycle status / schema all refuse with their own codes", () => {
  assertRefused(evalDoc({ decision: "MAYBE", results: [okResult()] }), "UNKNOWN_DECISION");
  assertRefused(evalDoc({ decision: "REVIEW", results: [okResult({ status: "PENDING" })] }), "UNKNOWN_RESULT_STATUS");
  assertRefused(evalDoc({ decision: "REVIEW", results: [okResult({ verdict: "SOFT_ALLOW" })] }), "UNKNOWN_VERDICT");
  assertRefused(serverRecord({ status: "PAUSED" }), "UNKNOWN_STATUS");
  assertRefused(serverRecord({ schema: "policyvault-risk-evaluation/v99" }), "UNKNOWN_SCHEMA_VERSION");
});

test("malformed shapes refuse: non-object, missing results, restrictive verdict without reasons, empty set without config", () => {
  assertRefused(null, "INVALID_EVALUATION");
  assertRefused("REVIEW", "INVALID_EVALUATION");
  assertRefused({ decision: "REVIEW", codes: [] }, "INVALID_EVALUATION");
  assertRefused(evalDoc({ decision: "REVIEW", results: [okResult({ reasons: [] })], codes: [] }), "INVALID_EVALUATION");
  assertRefused({ decision: "ALLOW", results: [], codes: [] }, "INVALID_EVALUATION"); // no config: onEmpty not cross-checkable
  const doc = structured(undefined);
  assert.equal(doc.verdict, "REFUSED");
});

test("both entry points are TOTAL — hostile inputs never throw", () => {
  const hostile = [null, undefined, 42, "x", [], {}, { decision: "DENY" }, { decision: "DENY", results: [null], codes: null }, { decision: "REVIEW", results: [{ adapter: 7 }], codes: [] }];
  for (const h of hostile) {
    assert.doesNotThrow(() => structured(h));
    assert.doesNotThrow(() => humanReadable(h));
    assert.ok(Array.isArray(humanReadable(h)) && humanReadable(h).length > 0);
  }
});

/* ---------------- PRODUCER BOUNDARY: the real core/risk pipeline ---------------- */

test("PRODUCER: real evaluateRisk output (mock adapters incl. throw + hang + malformed) EXPLAINS — the validator matches the real producer, not an imitation", async () => {
  const intent = { schema: "policyvault-risk-intent/1", action: "agentSpend", payAmountSompi: "2000000000", recipient: "33".repeat(32) };
  const result = await coreRisk.evaluateRisk({
    adapters: [
      mocks.makeAmountThresholdAdapter({ maxSompi: "5000000000", reviewSompi: "1000000000" }),
      mocks.makeAllowAllAdapter(),
      mocks.makeThrowingAdapter(),
      mocks.makeHangingAdapter({ timeoutMs: 25 }),
      mocks.makeMalformedVerdictAdapter({ result: { verdict: "MAYBE", reasons: [] } })
    ],
    intent,
    context: { orgId: "org-1", riskPolicy: { reviewRequired: true } },
    config: { onAdapterError: "REVIEW", timeoutMs: 250 }
  });
  const doc = structured(result);
  assert.equal(doc.verdict, "EXPLAINED", JSON.stringify(doc.refusal));
  assert.equal(doc.decision, result.decision);
  assert.equal(doc.adapterCount, 5);
  assert.equal(doc.errorCount, 3); // throw + hang + malformed
  const lines = humanReadable(result);
  assert.equal(lines[0], structured(result).headline);
  // JSON/jsonb round-trip stability: the wire/stored form explains identically
  assert.equal(JSON.stringify(humanReadable(JSON.parse(JSON.stringify(result)))), JSON.stringify(lines));

  // empty adapter set through the REAL producer, review-required org
  const empty = await coreRisk.evaluateRisk({ adapters: [], intent, context: { orgId: "org-1", riskPolicy: { reviewRequired: true } }, config: {} });
  const emptyDoc = structured(empty);
  assert.equal(emptyDoc.verdict, "EXPLAINED", JSON.stringify(emptyDoc.refusal));
  assert.equal(emptyDoc.decision, "REVIEW");
  assert.ok(humanReadable(empty).some((l) => l.includes("riskPolicy.reviewRequired")));
});

test("PRODUCER: a server-shaped stored record built from real evaluateRisk output EXPLAINS with status + correlation fields", async () => {
  const result = await coreRisk.evaluateRisk({
    adapters: [mocks.makeDenyAllAdapter({ code: "SANCTIONS_HIT", message: "recipient matched a watchlist" })],
    intent: { schema: "policyvault-risk-intent/1", action: "agentSpend" },
    context: { orgId: "org-1" },
    config: {}
  });
  const record = {
    schema: "policyvault-risk-evaluation/v1",
    evaluationId: "11111111-2222-4333-8444-555555555555",
    networkId: "testnet-10",
    vaultId: "aa".repeat(32),
    orgId: "org-1",
    intentHash: "ee".repeat(32),
    intent: { schema: "policyvault-risk-intent/1", action: "agentSpend" },
    initiatorXOnly: "cc".repeat(32),
    decision: result.decision,
    results: result.results,
    codes: result.codes,
    config: result.config,
    status: "DENIED",
    createdAt: "2026-08-26T00:00:00.000Z"
  };
  const doc = structured(JSON.parse(JSON.stringify(record)));
  assert.equal(doc.verdict, "EXPLAINED", JSON.stringify(doc.refusal));
  assert.equal(doc.decision, "DENY");
  assert.equal(doc.status, "DENIED");
});
