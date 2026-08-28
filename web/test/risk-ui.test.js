"use strict";

/*
 * web/risk-ui.js — the risk hold state machine, rendering, and network
 * operations (completion-standard item 2). Covers: never-auto-release
 * (release/resubmit are functions the CALLER invokes explicitly — these
 * tests prove the module itself never calls them), DENY renders final
 * with no release action, self-release pre-check, and evaluationId
 * round-tripping.
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");

const { createModule } = require("../risk-ui.js");
const govRiskExplain = require("../gov-risk-explain.js");

const INITIATOR = "aa".repeat(32);
const REVIEWER = "bb".repeat(32);

function fakeApi() {
  const calls = [];
  const responses = new Map();
  return {
    calls,
    on(key, value) { responses.set(key, value); return this; },
    async getJSON(path) {
      calls.push({ method: "GET", path });
      const r = responses.get(`GET ${path}`);
      if (typeof r === "function") return r();
      if (r === undefined) throw Object.assign(new Error(`no fake response for GET ${path}`), { code: "FAKE_UNMAPPED" });
      return r;
    },
    async postJSON(path, body) {
      calls.push({ method: "POST", path, body });
      const r = responses.get(`POST ${path}`);
      if (typeof r === "function") return r(body);
      if (r === undefined) throw Object.assign(new Error(`no fake response for POST ${path}`), { code: "FAKE_UNMAPPED" });
      return r;
    }
  };
}

function baseEvaluation(overrides) {
  return Object.assign(
    {
      evaluationId: "eval-1",
      networkId: "testnet-10",
      vaultId: "cc".repeat(32),
      orgId: "org-1",
      status: "REVIEW_HELD",
      decision: "REVIEW",
      initiatorXOnly: INITIATOR,
      codes: ["THRESHOLD_EXCEEDED"],
      results: [{ adapter: "threshold-guard", adapterVersion: "1", status: "OK", verdict: "REVIEW", reasons: [{ code: "THRESHOLD_EXCEEDED", message: "amount above the configured threshold" }] }],
      createdAt: "2026-08-26T00:00:00.000Z"
    },
    overrides
  );
}

/* ==================== holdState (pure state machine) ==================== */

test("holdState: no evaluation -> MISSING, nothing actionable", () => {
  const risk = createModule({ api: fakeApi() });
  const s = risk.holdState(null, { xOnly: REVIEWER });
  assert.equal(s.phase, "MISSING");
  assert.equal(s.canRelease, false);
  assert.equal(s.canResubmit, false);
});

test("holdState: REVIEW_HELD by a DIFFERENT wallet than the initiator -> canRelease", () => {
  const risk = createModule({ api: fakeApi() });
  const s = risk.holdState(baseEvaluation(), { xOnly: REVIEWER });
  assert.equal(s.phase, "REVIEW_HELD");
  assert.equal(s.isSelf, false);
  assert.equal(s.canRelease, true);
  assert.equal(s.canResubmit, false);
});

test("holdState: REVIEW_HELD where the connected wallet IS the initiator -> isSelf true, canRelease false (mirrors server RISK_SELF_RELEASE_FORBIDDEN)", () => {
  const risk = createModule({ api: fakeApi() });
  const s = risk.holdState(baseEvaluation(), { xOnly: INITIATOR });
  assert.equal(s.isSelf, true);
  assert.equal(s.canRelease, false);
});

test("holdState: RELEASED -> canResubmit, never canRelease again", () => {
  const risk = createModule({ api: fakeApi() });
  const s = risk.holdState(baseEvaluation({ status: "RELEASED" }), { xOnly: REVIEWER });
  assert.equal(s.phase, "RELEASED");
  assert.equal(s.canResubmit, true);
  assert.equal(s.canRelease, false);
});

test("holdState: DENIED -> final, no release, no resubmit, ever — regardless of who is asking", () => {
  const risk = createModule({ api: fakeApi() });
  for (const xOnly of [REVIEWER, INITIATOR, undefined]) {
    const s = risk.holdState(baseEvaluation({ status: "DENIED", decision: "DENY" }), { xOnly });
    assert.equal(s.phase, "DENIED", String(xOnly));
    assert.equal(s.isFinal, true, String(xOnly));
    assert.equal(s.canRelease, false, String(xOnly));
    assert.equal(s.canResubmit, false, String(xOnly));
  }
});

test("holdState: ALLOWED / CONSUMED are historical evidence only — final, nothing actionable", () => {
  const risk = createModule({ api: fakeApi() });
  for (const status of ["ALLOWED", "CONSUMED"]) {
    const s = risk.holdState(baseEvaluation({ status }), { xOnly: REVIEWER });
    assert.equal(s.isFinal, true, status);
    assert.equal(s.canRelease, false, status);
    assert.equal(s.canResubmit, false, status);
  }
});

/* ==================== rendering: DENY is final, no soft-bypass ==================== */

test("renderEvaluationHtml: DENIED never renders a release affordance, and states finality", () => {
  const risk = createModule({ api: fakeApi(), explain: govRiskExplain });
  const ev = baseEvaluation({ status: "DENIED", decision: "DENY" });
  const html = risk.renderEvaluationHtml(ev, risk.holdState(ev, { xOnly: REVIEWER }));
  assert.ok(!html.includes("data-risk-release"), "no release affordance for a final DENY — no soft-bypass");
  assert.ok(!html.includes("data-risk-resubmit"));
  assert.ok(/DENIED/.test(html) && /final/i.test(html));
});

test("renderEvaluationHtml: REVIEW_HELD by the initiator's own wallet warns instead of offering release", () => {
  const risk = createModule({ api: fakeApi(), explain: govRiskExplain });
  const ev = baseEvaluation();
  const html = risk.renderEvaluationHtml(ev, risk.holdState(ev, { xOnly: INITIATOR }));
  assert.ok(!html.includes("data-risk-release"));
  assert.ok(/cannot release their own review hold/i.test(html));
});

test("renderEvaluationHtml: REVIEW_HELD by a different wallet offers exactly the release action", () => {
  const risk = createModule({ api: fakeApi(), explain: govRiskExplain });
  const ev = baseEvaluation();
  const html = risk.renderEvaluationHtml(ev, risk.holdState(ev, { xOnly: REVIEWER }));
  assert.ok(html.includes(`data-risk-release="${ev.evaluationId}"`));
  assert.ok(!html.includes("data-risk-resubmit"));
});

test("renderEvaluationHtml: RELEASED offers exactly the resubmit action, keyed to the evaluationId", () => {
  const risk = createModule({ api: fakeApi(), explain: govRiskExplain });
  const ev = baseEvaluation({ status: "RELEASED" });
  const html = risk.renderEvaluationHtml(ev, risk.holdState(ev, { xOnly: REVIEWER }));
  assert.ok(html.includes(`data-risk-resubmit="${ev.evaluationId}"`));
  assert.ok(!html.includes("data-risk-release"));
});

test("renderEvaluationHtml: renders each adapter result — never silently drops adapters or shows a bare ALLOW for an error/timeout status", () => {
  const risk = createModule({ api: fakeApi(), explain: govRiskExplain });
  const ev = baseEvaluation({
    results: [
      { adapter: "sanctions-screen", adapterVersion: "1", status: "OK", verdict: "DENY", reasons: [{ code: "SANCTIONS_HIT", message: "recipient matched a watchlist" }] },
      { adapter: "flaky-adapter", adapterVersion: "1", status: "TIMEOUT", errorCode: "ADAPTER_TIMEOUT", verdict: "REVIEW", reasons: [] }
    ]
  });
  const html = risk.renderEvaluationHtml(ev, risk.holdState(ev, { xOnly: REVIEWER }));
  assert.ok(html.includes("sanctions-screen") && html.includes("SANCTIONS_HIT"));
  assert.ok(html.includes("flaky-adapter") && html.includes("TIMEOUT"));
});

test("renderEvaluationHtml: never throws on a missing evaluation", () => {
  const risk = createModule({ api: fakeApi(), explain: govRiskExplain });
  assert.doesNotThrow(() => risk.renderEvaluationHtml(null, risk.holdState(null, {})));
});

/* ==================== network operations ==================== */

test("fetchEvaluation: GETs the exact evaluation route", async () => {
  const api = fakeApi();
  api.on("GET /risk/evaluations/eval-1", { evaluation: baseEvaluation() });
  const risk = createModule({ api });
  const ev = await risk.fetchEvaluation("eval-1");
  assert.equal(ev.evaluationId, "eval-1");
});

test("release: POSTs to the exact release route with an EMPTY body — the evaluationId travels in the URL, never guessed client-side", async () => {
  const api = fakeApi();
  api.on("POST /risk/evaluations/eval-1/release", (body) => {
    assert.deepEqual(body, {});
    return { evaluation: baseEvaluation({ status: "RELEASED" }) };
  });
  const risk = createModule({ api });
  const updated = await risk.release("eval-1");
  assert.equal(updated.status, "RELEASED");
});

test("this module never calls release() or fetchEvaluation() on its own — no auto-release, no polling", () => {
  const api = fakeApi();
  createModule({ api }); // construction alone must never touch the network
  assert.equal(api.calls.length, 0);
});

/* ==================== createModule guards ==================== */

test("createModule: requires api.{getJSON,postJSON}", () => {
  assert.throws(() => createModule({}), /requires api/);
  assert.throws(() => createModule(), /requires api/);
});
