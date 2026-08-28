"use strict";

/*
 * app-v4.js governance/risk WIRING integration (completion-standard
 * items 1/2): proves runFlow's catch block hands a
 * GOVERNANCE_PROPOSAL_REQUIRED / RISK_REVIEW_REQUIRED / RISK_DENIED
 * refusal to the REAL governance-ui.js / risk-ui.js modules — loaded
 * into the SAME sandbox exactly as index.html's <script> order does —
 * rather than silently softening it or proceeding; that retry/re-submit
 * carry proposalId/riskEvaluationId on the SAME POST /wallet/v4/requests
 * call runFlow always uses; and that a page served WITHOUT these modules
 * degrades to the pre-existing plain refusal note() (fails closed to
 * "unavailable" — never crashes, never silently proceeds).
 *
 * Uses the SAME vm-sandbox harness style as app-v4-gate.test.js (the
 * real production source evaluated with a minimal window/document
 * stub), extended with a small querySelector capable of finding the
 * one `[data-x]` button a given modal render offers — enough for this
 * file's scenarios without building a general DOM.
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const APP_V4 = fs.readFileSync(path.join(__dirname, "..", "app-v4.js"), "utf8");
const GOVERNANCE_UI = fs.readFileSync(path.join(__dirname, "..", "governance-ui.js"), "utf8");
const RISK_UI = fs.readFileSync(path.join(__dirname, "..", "risk-ui.js"), "utf8");
const GOV_RISK_EXPLAIN = fs.readFileSync(path.join(__dirname, "..", "gov-risk-explain.js"), "utf8");

const OWNER_ADDR = "kaspatest:owner0000000000000000000000000000000000000000000000000000000000";
const OWNER_X = "bb".repeat(32);
const VAULT_ID = "aa".repeat(32);

/* Minimal DOM: getElementById returns a persistent stub per id (mirrors
 * app-v4-gate.test.js's makeDom); each stub additionally supports
 * querySelector("[data-x]" | '[data-x="y"]') scanning ITS OWN current
 * innerHTML — enough to find and "click" the one button a modal render
 * offers for a given state, matching how app-v4.js's own wireXxx()
 * functions query real DOM in production. */
function makeDom() {
  const elements = new Map();
  const element = (id) => {
    if (!elements.has(id)) {
      // Query cache keyed by "currentInnerHTML::selector" so repeat
      // querySelector(sel) calls against the SAME render return the SAME
      // stub reference (mirrors real DOM identity semantics) — production
      // code sets .onclick on the reference it queried; a test reading it
      // back via its own querySelector(sel) call must see that assignment.
      const queryCache = new Map();
      const el = {
        id,
        innerHTML: "",
        textContent: "",
        className: "",
        style: {},
        onclick: null,
        addEventListener() {},
        classList: { toggle() {}, add() {}, remove() {} },
        querySelectorAll: () => [],
        querySelector(sel) {
          const key = `${el.innerHTML}::${sel}`;
          if (queryCache.has(key)) return queryCache.get(key);
          const m = /^\[([a-zA-Z0-9-]+)(?:="([^"]*)")?\]$/.exec(sel);
          let stub = null;
          if (m) {
            const [, attr, wantVal] = m;
            const re = new RegExp(`${attr}(?:="([^"]*)")?`);
            const found = re.exec(el.innerHTML);
            if (found) {
              const actualVal = found[1];
              if (wantVal === undefined || actualVal === wantVal) {
                stub = { onclick: null, disabled: false, style: {}, getAttribute: (n) => (n === attr ? (actualVal ?? "") : null) };
              }
            }
          }
          queryCache.set(key, stub);
          return stub;
        }
      };
      elements.set(id, el);
    }
    return elements.get(id);
  };
  const document = {
    getElementById: (id) => element(id),
    querySelectorAll: () => []
  };
  return { document, element };
}

function sessionWith(adapter) {
  const snap = { connected: true, ready: true, address: OWNER_ADDR, xonly: OWNER_X, network: "testnet-10", serverNetwork: "testnet-10", provider: "spy", adapter };
  return { active: () => snap, subscribe(cb) { cb(snap); return () => {}; }, connect() {}, disconnect() {} };
}

/* Records every call. `handlers` is keyed "METHOD url" (both GET and POST
 * routes must be registered explicitly — an unregistered route returns a
 * benign empty 200, matching how getJSON/postJSON tolerate an empty body
 * for routes a given scenario does not exercise) so a single fetch mock
 * can drive an entire scenario (build refusal, then a later fetch/
 * release/retry call). */
function makeFetch(handlers) {
  const calls = [];
  const fetchFn = async (url, opts) => {
    const method = (opts && opts.method) || "GET";
    const body = opts && opts.body ? JSON.parse(opts.body) : undefined;
    calls.push({ method, url, body });
    const handler = handlers[`${method} ${url}`];
    if (handler) {
      const result = typeof handler === "function" ? handler(body, calls.length) : handler;
      return { ok: result.status < 400, status: result.status, json: async () => result.body };
    }
    return { ok: true, json: async () => ({}) };
  };
  fetchFn.calls = calls;
  return fetchFn;
}

function govRefusal409() {
  return {
    status: 409,
    body: { error: { code: "GOVERNANCE_PROPOSAL_REQUIRED", message: "addAgent is an AUTHORITY EXPANSION (AGENT_ADDED) — it requires an approved governance proposal", governance: { classification: "EXPANSION", codes: ["AGENT_ADDED"] } } }
  };
}
function riskReview409(evaluationId) {
  return {
    status: 409,
    body: { error: { code: "RISK_REVIEW_REQUIRED", message: "the organization's risk controls require human review before this operation can proceed", riskEvaluation: { evaluationId, decision: "REVIEW", codes: ["THRESHOLD_EXCEEDED"] } } }
  };
}
function riskDenied403(evaluationId) {
  return {
    status: 403,
    body: { error: { code: "RISK_DENIED", message: "the organization's risk controls refused this operation", riskEvaluation: { evaluationId, decision: "DENY", codes: ["SANCTIONS_HIT"] } } }
  };
}

/* ==================== GOVERNANCE_PROPOSAL_REQUIRED: no soft-bypass ==================== */

test("runFlow: a GOVERNANCE_PROPOSAL_REQUIRED refusal opens the ceremony modal, never the signing review modal", async () => {
  const dom = makeDom();
  const fetchFn = makeFetch({ "POST /api/v1/wallet/v4/requests": () => govRefusal409() });
  const loaded = loadAppWithFetch(dom, fetchFn);
  await loaded.api._runFlow(VAULT_ID, "addAgent", { agent: { agentPk: "cc".repeat(32) } }, "Sign add-agent");
  const modalHtml = loaded.element("v4-modal").innerHTML;
  assert.ok(/Governance proposal required/i.test(modalHtml), modalHtml);
  assert.ok(modalHtml.includes("data-gov-createproposal"), "offers the lawful create-proposal path");
  assert.ok(!modalHtml.includes('id="v4-confirm"'), "never the signing review modal — no soft-bypass of the refusal");
});

function loadAppWithFetch(dom, fetchFn) {
  const { document, element } = dom;
  const windowObj = { addEventListener() {}, confirm: () => true, PolicyVaultWalletSession: sessionWith({}) };
  const sandbox = {
    window: windowObj,
    document,
    console,
    crypto: { getRandomValues: (arr) => { for (let i = 0; i < arr.length; i++) arr[i] = i & 0xff; return arr; } },
    fetch: fetchFn,
    setTimeout,
    clearTimeout
  };
  vm.createContext(sandbox);
  vm.runInContext(GOV_RISK_EXPLAIN, sandbox, { filename: "gov-risk-explain.js" });
  vm.runInContext(GOVERNANCE_UI, sandbox, { filename: "governance-ui.js" });
  vm.runInContext(RISK_UI, sandbox, { filename: "risk-ui.js" });
  vm.runInContext(APP_V4, sandbox, { filename: "app-v4.js" });
  return { window: windowObj, element, api: windowObj.PolicyVaultV4 };
}

test("runFlow: GOVERNANCE_PROPOSAL_REQUIRED includes the server's classification/codes verbatim, never a client-invented one", async () => {
  const dom = makeDom();
  const fetchFn = makeFetch({ "POST /api/v1/wallet/v4/requests": () => govRefusal409() });
  const loaded = loadAppWithFetch(dom, fetchFn);
  await loaded.api._runFlow(VAULT_ID, "addAgent", { agent: {} }, "Sign add-agent");
  const html = loaded.element("v4-modal").innerHTML;
  assert.ok(html.includes("EXPANSION") && html.includes("AGENT_ADDED"));
});

test("creating the proposal then retrying carries proposalId on the SAME POST /wallet/v4/requests call — no second signing path, no duplicate build endpoint", async () => {
  const dom = makeDom();
  const createdProposal = {
    proposalId: "prop-xyz",
    status: "OPEN",
    createdAt: "2026-08-26T00:00:00.000Z",
    proposal: { action: "addAgent", vaultId: VAULT_ID, covenantVersion: "policyvault-0.4.1", params: {}, expiresAt: "2026-09-09T00:00:00.000Z" },
    integrity: { digestOk: true, classificationOk: true },
    classification: { classification: "EXPANSION", codes: ["AGENT_ADDED"], perField: [] },
    approvals: { owner: OWNER_X, ownerApproved: true, orgQuorum: null, verified: [{ approverXOnly: OWNER_X }], satisfied: true },
    approvalMessage: "PolicyVault governance approval\n..."
  };
  const fetchFn = makeFetch({
    "POST /api/v1/wallet/v4/requests": (body) => (body && body.proposalId === "prop-xyz" ? { status: 201, body: { request: { requestId: "r1", state: "BUILT", review: {}, transaction: { unsignedSafeJson: "{}", signInputs: [] } } } } : govRefusal409()),
    "POST /api/v1/governance/proposals": () => ({ status: 201, body: { proposal: createdProposal } }),
    // addAgent is fuel-funded; the retry re-selects fuel fresh (the
    // stored proposal never carries the client's original `fuel` — see
    // openGovernanceCeremony's retry handler in app-v4.js).
    [`GET /api/v1/wallet/fuel/${encodeURIComponent(OWNER_ADDR)}`]: { status: 200, body: { utxos: [{ outpoint: { transactionId: "ff".repeat(32), index: 0 }, amount: "500000000", scriptPublicKeyHex: "2000".padEnd(70, "0") }] } }
  });
  const loaded = loadAppWithFetch(dom, fetchFn);
  // DOMContentLoaded never fires in this sandbox (addEventListener is a
  // no-op stub, matching app-v4-gate.test.js's harness), so state.address
  // is never auto-populated from the session — set it directly, exactly
  // as the existing suite's _verifyForSigning tests set api._state.xonly.
  loaded.api._state.address = OWNER_ADDR;
  await loaded.api._runFlow(VAULT_ID, "addAgent", { agent: {} }, "Sign add-agent");
  const createBtn = loaded.element("v4-modal").querySelector("[data-gov-createproposal]");
  assert.ok(createBtn);
  await createBtn.onclick();
  const retryBtn = loaded.element("v4-modal").querySelector("[data-gov-retry]");
  assert.ok(retryBtn, "a satisfied proposal offers retry");
  await retryBtn.onclick();
  const buildCalls = fetchFn.calls.filter((c) => c.url === "/api/v1/wallet/v4/requests");
  assert.equal(buildCalls.length, 2, "original attempt + retry, both through the ONE build endpoint");
  assert.equal(buildCalls[1].body.proposalId, "prop-xyz");
  assert.equal(buildCalls[1].body.vaultId, VAULT_ID);
  assert.equal(buildCalls[1].body.action, "addAgent");
});

test("WITHOUT the governance-ui module loaded, the page fails closed to the plain refusal note — never crashes, never silently proceeds", async () => {
  const dom = makeDom();
  const fetchFn = makeFetch({ "POST /api/v1/wallet/v4/requests": () => govRefusal409() });
  const windowObj = { addEventListener() {}, confirm: () => true, PolicyVaultWalletSession: sessionWith({}) };
  const sandbox = { window: windowObj, document: dom.document, console, crypto: { getRandomValues: (a) => a }, fetch: fetchFn, setTimeout, clearTimeout };
  vm.createContext(sandbox);
  // deliberately NOT loading governance-ui.js / risk-ui.js / gov-risk-explain.js
  vm.runInContext(APP_V4, sandbox, { filename: "app-v4.js" });
  await windowObj.PolicyVaultV4._runFlow(VAULT_ID, "addAgent", { agent: {} }, "Sign add-agent");
  assert.equal(dom.element("v4-modal").style.display, undefined, "no ceremony modal was opened");
  assert.ok(/GOVERNANCE_PROPOSAL_REQUIRED/.test(dom.element("v4-notice").textContent), dom.element("v4-notice").textContent);
});

/* ==================== RISK_REVIEW_REQUIRED / RISK_DENIED: no soft-bypass ==================== */

test("runFlow: a RISK_REVIEW_REQUIRED refusal fetches and renders the held evaluation, never the signing review modal", async () => {
  const dom = makeDom();
  const fetchFn = makeFetch({
    "POST /api/v1/wallet/v4/requests": () => riskReview409("eval-1"),
    "GET /api/v1/risk/evaluations/eval-1": {
      status: 200,
      body: { evaluation: { evaluationId: "eval-1", status: "REVIEW_HELD", decision: "REVIEW", initiatorXOnly: "zz".repeat(32), codes: ["THRESHOLD_EXCEEDED"], results: [{ adapter: "threshold-guard", adapterVersion: "1", status: "OK", verdict: "REVIEW", reasons: [{ code: "THRESHOLD_EXCEEDED", message: "over threshold" }] }], createdAt: "2026-08-26T00:00:00.000Z" } }
    }
  });
  const loaded = loadAppWithFetch(dom, fetchFn);
  await loaded.api._runFlow(VAULT_ID, "agentSpend", { payAmountSompi: "999999999999" }, "Sign spend");
  const html = loaded.element("v4-modal").innerHTML;
  assert.ok(/REVIEW_HELD/.test(html), html);
  assert.ok(html.includes("data-risk-release"), "the connected wallet (not the initiator here) may release");
  assert.ok(!html.includes('id="v4-confirm"'), "never the signing review modal — no soft-bypass of the refusal");
});

test("runFlow: RISK_DENIED renders as FINAL — no release affordance, ever", async () => {
  const dom = makeDom();
  const fetchFn = makeFetch({
    "POST /api/v1/wallet/v4/requests": () => riskDenied403("eval-2"),
    "GET /api/v1/risk/evaluations/eval-2": { status: 200, body: { evaluation: { evaluationId: "eval-2", status: "DENIED", decision: "DENY", initiatorXOnly: OWNER_X, codes: ["SANCTIONS_HIT"], results: [{ adapter: "sanctions", adapterVersion: "1", status: "OK", verdict: "DENY", reasons: [{ code: "SANCTIONS_HIT", message: "recipient matched a watchlist" }] }], createdAt: "2026-08-26T00:00:00.000Z" } } }
  });
  const loaded = loadAppWithFetch(dom, fetchFn);
  await loaded.api._runFlow(VAULT_ID, "agentSpend", { payAmountSompi: "1" }, "Sign spend");
  const html = loaded.element("v4-modal").innerHTML;
  assert.ok(/DENIED/.test(html) && /final/i.test(html));
  assert.ok(!html.includes("data-risk-release"));
  assert.ok(!html.includes('id="v4-confirm"'));
});

test("releasing a hold then re-submitting carries riskEvaluationId on the SAME POST /wallet/v4/requests call", async () => {
  const dom = makeDom();
  const held = { evaluationId: "eval-3", status: "REVIEW_HELD", decision: "REVIEW", initiatorXOnly: "zz".repeat(32), codes: [], results: [], createdAt: "t" };
  const released = { ...held, status: "RELEASED", releasedAt: "t2" };
  const fetchFn = makeFetch({
    "POST /api/v1/wallet/v4/requests": (body) => (body && body.riskEvaluationId === "eval-3" ? { status: 201, body: { request: { requestId: "r1", state: "BUILT", review: {}, transaction: { unsignedSafeJson: "{}", signInputs: [] } } } } : riskReview409("eval-3")),
    "GET /api/v1/risk/evaluations/eval-3": { status: 200, body: { evaluation: held } },
    "POST /api/v1/risk/evaluations/eval-3/release": { status: 200, body: { evaluation: released } }
  });
  const loaded = loadAppWithFetch(dom, fetchFn);
  await loaded.api._runFlow(VAULT_ID, "agentSpend", { payAmountSompi: "1" }, "Sign spend");
  const releaseBtn = loaded.element("v4-modal").querySelector("[data-risk-release]");
  assert.ok(releaseBtn);
  await releaseBtn.onclick();
  const resubmitBtn = loaded.element("v4-modal").querySelector("[data-risk-resubmit]");
  assert.ok(resubmitBtn, "a RELEASED hold offers resubmit");
  await resubmitBtn.onclick();
  const buildCalls = fetchFn.calls.filter((c) => c.url === "/api/v1/wallet/v4/requests");
  assert.equal(buildCalls.length, 2);
  assert.equal(buildCalls[1].body.riskEvaluationId, "eval-3");
  const releaseCalls = fetchFn.calls.filter((c) => c.url === "/api/v1/risk/evaluations/eval-3/release");
  assert.equal(releaseCalls.length, 1, "release happens exactly once — this test never auto-releases or loops");
});

test("WITHOUT the risk-ui module loaded, the page fails closed to the plain refusal note", async () => {
  const dom = makeDom();
  const fetchFn = makeFetch({ "POST /api/v1/wallet/v4/requests": () => riskReview409("eval-9") });
  const windowObj = { addEventListener() {}, confirm: () => true, PolicyVaultWalletSession: sessionWith({}) };
  const sandbox = { window: windowObj, document: dom.document, console, crypto: { getRandomValues: (a) => a }, fetch: fetchFn, setTimeout, clearTimeout };
  vm.createContext(sandbox);
  vm.runInContext(APP_V4, sandbox, { filename: "app-v4.js" });
  await windowObj.PolicyVaultV4._runFlow(VAULT_ID, "agentSpend", { payAmountSompi: "1" }, "Sign spend");
  assert.equal(dom.element("v4-modal").style.display, undefined);
  assert.ok(/RISK_REVIEW_REQUIRED/.test(dom.element("v4-notice").textContent));
});
