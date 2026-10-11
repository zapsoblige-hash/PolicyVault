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
    /* Fixture seam (RC45 R2-07): a delegate-lifecycle build (addAgent / rotateAgent / rePolicyAgent) reads the node's
     * network position (GET /network/status) before it posts. A scenario that registers no such read is answered as a
     * synced node, so the scenarios above keep their expectations; on a build that never reads it, this is unused. */
    if (method === "GET" && url === "/api/v1/network/status") return { ok: true, status: 200, json: async () => ({ networkId: "testnet-10", virtualDaaScore: "545000000" }) };
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
  // The retry handler starts runFlow without awaiting it; a lifecycle build now reads the network position before it
  // posts (RC45 R2-07), so the retry's POST lands a little later. Wait for it (bounded), then assert as before.
  for (let i = 0; i < 2000 && fetchFn.calls.filter((c) => c.url === "/api/v1/wallet/v4/requests").length < 2; i++) await new Promise((r) => setTimeout(r, 5));
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

/* ==================== RC45 R2-07: the browser binds the server's anchored delegate period start ====================
 * PolicyVault starts the budget period of every new or changed v0.4.1 delegate leaf at the network position when the
 * transaction is built (committed start = max(requested start, DAA score at the build)) and reports that position as
 * review.periodStartAnchorDaa. The browser verifier recomputes the successor registry root from THIS browser's own
 * params, so for addAgent / rotateAgent / rePolicyAgent app-v4.js must:
 *   - read the network position (GET /network/status; digits only; one retry after a short pause) BEFORE it posts the
 *     build, and refuse before posting when it still cannot — nothing is built and no proposal is consumed;
 *   - accept the server's anchor iff anchor >= max(this browser's start, D_before - 600), adopting it into a COPY of its
 *     params for verification only — the params SENT to the server stay verbatim (a governed execution compares them);
 *   - put no blocking upper bound on the anchor (more than 6,000 DAA above D_before only adds an advisory line), and
 *     never block the review on a read taken after the build;
 *   - state the anchored start, the amount spendable at once and the next budget's position on the review, and say on
 *     the governance ceremony of a delegate-lifecycle proposal when that delegate's budget period starts.
 * Fixtures: the shared web helpers' v0.4.1 vault and owner-operation transaction (true recomputed fees and state ids),
 * its successor registry root recomputed for the anchored start, and a 3 KAS owner fuel UTXO. Realistic network
 * positions (about 5.45e8). Layer: BROWSER (the real app-v4.js, governance-ui.js and verify-intent.js over the
 * committed core bundle); every HTTP answer is an explicit fixture and no wallet is ever invoked. */
const core = require("../core-bundle.js");
const { createVerifyIntent } = require("../verify-intent.js");
const H = require("./helpers.js");
const R2_VI = createVerifyIntent(core);
const R2_D = 545000000n; // the network position this browser reads before posting (D_before)
const R2_L = BigInt(H.NEW_AGENT_PARAM.periodLengthDaa); // 864,000 DAA (one day)
const R2_FUEL = 300000000n; // a 3 KAS owner fuel UTXO (a governed retry selects fuel above 2 KAS afresh)
const R2_TREE = core.agentMerkle.buildAgentTreeV4([H.AGENT_POLICY_1]);
const R2_RECIPIENT_ROOT = core.recipientMerkle.buildRecipientTree([...H.NEW_AGENT_PARAM.recipients]).root;
const R2_UTXO = Object.freeze({ outpoint: { transactionId: H.FUEL_TXID, index: 5 }, amount: R2_FUEL.toString(), scriptPublicKeyHex: H.p2pk(H.OWNER) });
const R2_READ_FAILED = Object.freeze({ status: 503, body: { error: { code: "NODE_UNAVAILABLE", message: "the node is not synced" } } });
const R2_READ_MALFORMED = Object.freeze({ status: 200, body: { networkId: "testnet-10", virtualDaaScore: "0x207c0000" } });

/* The server's answer to a lifecycle build whose new or changed leaf it anchored at `anchor`: the helpers' owner-op
 * transaction (fuel re-valued to 3 KAS, the fee unchanged) with the successor registry root and state id recomputed
 * for that start. `params` is what THIS browser sends: the same leaf with its own `clientStart`. */
function r2Scenario(action, { clientStart, anchor }) {
  const s = H.addAgentScenario();
  const tx = JSON.parse(s.request.transaction.unsignedSafeJson);
  const fee = BigInt(tx.inputs[1].utxo.amount) - BigInt(tx.outputs[1].value);
  tx.inputs[1].utxo.amount = R2_FUEL.toString();
  tx.outputs[1].value = (R2_FUEL - fee).toString();
  const base = H.NEW_AGENT_PARAM;
  const agentPk = action === "rePolicyAgent" ? H.AGENT : base.agentPk;
  const leaf = { agentPk, maxPerSpend: base.maxPerSpend, periodBudget: base.periodBudget, periodLengthDaa: base.periodLengthDaa, periodStartDaa: String(anchor), periodSpent: "0", approvalThreshold: base.approvalThreshold, agentMaxFeePerTx: base.agentMaxFeePerTx, agentRecipientRoot: R2_RECIPIENT_ROOT };
  const am = core.agentMerkle;
  const root = action === "addAgent" ? am.addAgentV4(R2_TREE, leaf).root : action === "rotateAgent" ? am.rotateAgentV4(R2_TREE, H.AGENT, leaf).root : am.updateAgentPolicyV4(R2_TREE, leaf).root;
  const stateId = H.stateIdOf({ ...H.BASE_STATE, agentRoot: root, policyNonce: "8" });
  const request = {
    ...s.request, action, highLevel: action, successorStateId: stateId,
    review: { ...s.request.review, action, successorAgentRoot: root, successorStateId: stateId, periodStartAnchorDaa: String(anchor) },
    transaction: { ...s.request.transaction, unsignedSafeJson: JSON.stringify(tx) }
  };
  const agent = { ...base, recipients: [...base.recipients], agentPk, periodStartDaa: String(clientStart), periodSpent: "0" };
  return { request, params: action === "addAgent" ? { agent } : { agentPk: H.AGENT, agent } };
}
/* One fetch double per leg: the i-th network-position read answers reads[i] (the last entry repeats; a digit string is
 * a synced node at that position, an object a raw {status, body} answer); the build route answers build(body). */
function r2Fetch({ reads = [R2_D.toString()], build }) {
  let n = 0;
  return makeFetch({
    "GET /api/v1/network/status": () => {
      const a = reads[Math.min(n, reads.length - 1)];
      n += 1;
      return typeof a === "string" ? { status: 200, body: { networkId: "testnet-10", virtualDaaScore: a } } : a;
    },
    "POST /api/v1/wallet/v4/requests": (body) => build(body),
    [`GET /api/v1/wallet/fuel/${encodeURIComponent(H.OWNER_ADDR)}`]: () => ({ status: 200, body: { utxos: [R2_UTXO] } })
  });
}
const r2Built = (scenario) => () => ({ status: 201, body: { request: scenario.request } });
const r2IsRead = (c) => c.method === "GET" && c.url === "/api/v1/network/status";
const r2IsBuild = (c) => c.method === "POST" && c.url === "/api/v1/wallet/v4/requests";
const r2Reads = (f) => f.calls.filter(r2IsRead);
const r2Builds = (f) => f.calls.filter(r2IsBuild);
const r2ReadsBeforeBuild = (f) => { const i = f.calls.findIndex(r2IsBuild); return f.calls.slice(0, i < 0 ? f.calls.length : i).filter(r2IsRead).length; };
const r2ReadsAfterBuild = (f) => { const i = f.calls.findIndex(r2IsBuild); return i < 0 ? 0 : f.calls.slice(i + 1).filter(r2IsRead).length; };
/* The owner (helpers' OWNER) on testnet-10 with the helpers' vault known to this browser and the verify layer loaded. */
function loadR2App(fetchFn) {
  const dom = makeDom();
  const snap = { connected: true, ready: true, address: H.OWNER_ADDR, xonly: H.OWNER, network: "testnet-10", serverNetwork: "testnet-10", provider: "spy", adapter: { signInputs: async () => { throw new Error("this suite never invokes a wallet"); } } };
  const windowObj = {
    addEventListener() {}, confirm: () => true, PolicyVaultCore: core, PolicyVaultVerifyIntent: R2_VI,
    PolicyVaultWalletSession: { active: () => snap, subscribe(cb) { cb(snap); return () => {}; }, connect() {}, disconnect() {} }
  };
  const sandbox = { window: windowObj, document: dom.document, console, crypto: { getRandomValues: (arr) => { for (let i = 0; i < arr.length; i++) arr[i] = i & 0xff; return arr; } }, fetch: fetchFn, setTimeout, clearTimeout };
  vm.createContext(sandbox);
  vm.runInContext(GOV_RISK_EXPLAIN, sandbox, { filename: "gov-risk-explain.js" });
  vm.runInContext(GOVERNANCE_UI, sandbox, { filename: "governance-ui.js" });
  vm.runInContext(RISK_UI, sandbox, { filename: "risk-ui.js" });
  vm.runInContext(APP_V4, sandbox, { filename: "app-v4.js" });
  const api = windowObj.PolicyVaultV4;
  api._state.address = H.OWNER_ADDR;
  api._state.xonly = H.OWNER;
  api._state.vaultsById = { [H.VAULT_ID]: H.baseVault() };
  return { api, modal: () => dom.element("v4-modal"), notice: () => dom.element("v4-notice") };
}
/* Visible text of a rendered region (tags dropped, the five escaped characters restored, white space collapsed). */
const r2Text = (html) => String(html ?? "").replace(/<[^>]*>/g, " ").replace(/&#39;/g, "'").replace(/&quot;/g, '"').replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&amp;/g, "&").replace(/\s+/g, " ").trim();
/* A network position or amount as it may be displayed: its digits, optionally grouped in thousands. */
const r2NumSrc = (n) => `(?<![0-9])${String(n).replace(/\B(?=(\d{3})+(?!\d))/g, "[,\\u00a0\\u202f\\u2009 ]?")}(?![0-9])`;
const r2Num = (n) => new RegExp(r2NumSrc(n));
const r2Verified = (h) => /data-verify="pass"/.test(h.modal().innerHTML) && h.modal().innerHTML.includes('id="v4-confirm"');
async function r2Until(pred, ms = 15000) { const t0 = Date.now(); while (!pred() && Date.now() - t0 < ms) await new Promise((r) => setTimeout(r, 5)); }
function r2Proposal(action, params) {
  return {
    proposalId: `prop-r2-07-${action}`, status: "OPEN", createdAt: "2026-01-01T00:00:00.000Z",
    proposal: { action, vaultId: H.VAULT_ID, covenantVersion: "policyvault-0.4.1", params, expiresAt: "2026-01-15T00:00:00.000Z" },
    integrity: { digestOk: true, classificationOk: true },
    classification: { classification: "EXPANSION", codes: ["AGENT_ADDED"], perField: [] },
    approvals: { owner: H.OWNER, ownerApproved: true, orgQuorum: null, verified: [{ approverXOnly: H.OWNER }], satisfied: true },
    approvalMessage: "PolicyVault governance approval\n..."
  };
}
const R2_NOTE = Object.freeze([
  "Budget period start: for an agent this change adds, replaces or re-policies, PolicyVault starts the budget period at the network position when the approved change is built for signing",
  "never earlier than the start shown above",
  "a limitation of the installed covenant that this release does not change"
]);

for (const action of ["addAgent", "rotateAgent", "rePolicyAgent"]) {
  test(`RC45 R2-07: ${action} — the server's anchored start (above this browser's own start, at or above D_before - 600) is adopted for verification: the review opens VERIFIED with the signing action, and the build request still carries this browser's own start verbatim [RED on b89f0f7]`, async () => {
    const sc = r2Scenario(action, { clientStart: R2_D, anchor: R2_D + 40n });
    const f = r2Fetch({ build: r2Built(sc) });
    const h = loadR2App(f);
    await h.api._runFlow(H.VAULT_ID, action, { ...sc.params, fuel: R2_UTXO }, "Approve in wallet");
    assert.equal(r2Builds(f).length, 1, "one build request");
    assert.equal(r2Builds(f)[0].body.params.agent.periodStartDaa, R2_D.toString(), "the params SENT keep this browser's own start (never the adopted anchor)");
    assert.ok(r2Verified(h), `the review opens VERIFIED with the signing action; it shows: ${r2Text(h.modal().innerHTML).slice(0, 600)}`);
  });
}

test("RC45 R2-07: a governed retry whose stored proposal carries a stale delegate start (three periods old) adopts the server's anchored start for verification — the review opens VERIFIED — while the retried build sends the stored params verbatim with the proposal id [RED on b89f0f7]", async () => {
  const stale = R2_D - 3n * R2_L;
  const sc = r2Scenario("addAgent", { clientStart: stale, anchor: R2_D + 40n });
  const f = r2Fetch({ build: (body) => (body && body.proposalId === "prop-r2-07-addAgent" ? { status: 201, body: { request: sc.request } } : govRefusal409()) });
  const h = loadR2App(f);
  await h.api._openGovernanceCeremony({ proposal: r2Proposal("addAgent", sc.params) });
  const retry = h.modal().querySelector("[data-gov-retry]");
  assert.ok(retry, "a satisfied proposal offers Retry the original action");
  await retry.onclick();
  await r2Until(() => /data-verify="/.test(h.modal().innerHTML));
  const builds = r2Builds(f);
  assert.equal(builds.length, 1, "one build request");
  assert.equal(builds[0].body.proposalId, "prop-r2-07-addAgent");
  assert.equal(builds[0].body.params.agent.periodStartDaa, stale.toString(), "the stored start is sent verbatim (the governed execution compares the params with the approved proposal)");
  assert.ok(builds[0].body.params.fuel, "fresh fuel is attached to the retry");
  assert.ok(r2Verified(h), `the governed review opens VERIFIED with the signing action; it shows: ${r2Text(h.modal().innerHTML).slice(0, 600)}`);
});

test("RC45 R2-07: an anchor exactly 600 DAA below D_before (this browser's start lower still) is accepted: the review opens VERIFIED [RED on b89f0f7]", async () => {
  const sc = r2Scenario("addAgent", { clientStart: R2_D - 10000n, anchor: R2_D - 600n });
  const f = r2Fetch({ build: r2Built(sc) });
  const h = loadR2App(f);
  await h.api._runFlow(H.VAULT_ID, "addAgent", { ...sc.params, fuel: R2_UTXO }, "Approve in wallet");
  assert.ok(r2Verified(h), `the review opens VERIFIED; it shows: ${r2Text(h.modal().innerHTML).slice(0, 600)}`);
});

test("RC45 R2-07: an anchor 601 DAA below D_before (above this browser's start) is refused: DO NOT SIGN, no signing action, and the review names the anchored position and this browser's read [RED on b89f0f7]", async () => {
  const A = R2_D - 601n;
  const sc = r2Scenario("addAgent", { clientStart: R2_D - 10000n, anchor: A });
  const f = r2Fetch({ build: r2Built(sc) });
  const h = loadR2App(f);
  await h.api._runFlow(H.VAULT_ID, "addAgent", { ...sc.params, fuel: R2_UTXO }, "Approve in wallet");
  const html = h.modal().innerHTML, t = r2Text(html);
  assert.ok(!html.includes('id="v4-confirm"'), "no signing action");
  assert.match(t, /DO NOT SIGN/);
  assert.ok(t.includes("the server anchored this delegate's budget period at network position"), `the refusal names the anchored start; it shows: ${t.slice(0, 600)}`);
  assert.ok(t.includes("earlier than this browser's read"), "the refusal says the anchor is earlier than this browser's read allows");
  assert.match(t, r2Num(A), "the anchored position is shown");
  assert.match(t, r2Num(R2_D), "this browser's read is shown");
});

test("RC45 R2-07: an anchor below this browser's own (later) start is refused even though it is above D_before: DO NOT SIGN, no signing action, the lower-bound refusal names the anchored position [RED on b89f0f7]", async () => {
  const A = R2_D + 1000n;
  const sc = r2Scenario("addAgent", { clientStart: R2_D + 5000n, anchor: A });
  const f = r2Fetch({ build: r2Built(sc) });
  const h = loadR2App(f);
  await h.api._runFlow(H.VAULT_ID, "addAgent", { ...sc.params, fuel: R2_UTXO }, "Approve in wallet");
  const html = h.modal().innerHTML, t = r2Text(html);
  assert.ok(!html.includes('id="v4-confirm"'), "no signing action");
  assert.match(t, /DO NOT SIGN/);
  assert.ok(t.includes("the server anchored this delegate's budget period at network position"), `the lower-bound refusal is shown; it shows: ${t.slice(0, 600)}`);
  assert.match(t, r2Num(A), "the anchored position is shown");
});

test("RC45 R2-07: an anchor 10,000 DAA above D_before has no blocking upper bound — the review opens VERIFIED and carries the advisory that the node is ahead of this browser's read [RED on b89f0f7]", async () => {
  const sc = r2Scenario("addAgent", { clientStart: R2_D, anchor: R2_D + 10000n });
  const f = r2Fetch({ build: r2Built(sc) });
  const h = loadR2App(f);
  await h.api._runFlow(H.VAULT_ID, "addAgent", { ...sc.params, fuel: R2_UTXO }, "Approve in wallet");
  const t = r2Text(h.modal().innerHTML);
  assert.ok(r2Verified(h), `a later anchor is never blocked; it shows: ${t.slice(0, 600)}`);
  assert.ok(t.includes("PolicyVault's node is ahead of this browser's last read"), "the advisory line is shown");
  assert.ok(t.includes("a later start only delays this agent's next budget"), "the advisory explains the effect");
});

test("RC45 R2-07: when the network position cannot be read twice (a failed read, then a malformed one), the lifecycle build is refused BEFORE posting — no build request is sent; exactly one retry [RED on b89f0f7]", async () => {
  const sc = r2Scenario("addAgent", { clientStart: R2_D, anchor: R2_D + 40n });
  const f = r2Fetch({ reads: [R2_READ_FAILED, R2_READ_MALFORMED], build: r2Built(sc) });
  const h = loadR2App(f);
  await h.api._runFlow(H.VAULT_ID, "addAgent", { ...sc.params, fuel: R2_UTXO }, "Approve in wallet");
  assert.equal(r2Builds(f).length, 0, "nothing is built: no build request is sent");
  assert.equal(r2Reads(f).length, 2, "one read and exactly one retry");
  assert.ok(!h.modal().innerHTML.includes('id="v4-confirm"'), "no signing review");
});

test("RC45 R2-07: a governed retry whose network-position reads fail twice never sends its proposal id — the proposal is not consumed [RED on b89f0f7]", async () => {
  const sc = r2Scenario("addAgent", { clientStart: R2_D - 3n * R2_L, anchor: R2_D + 40n });
  const f = r2Fetch({ reads: [R2_READ_FAILED], build: (body) => (body && body.proposalId ? { status: 201, body: { request: sc.request } } : govRefusal409()) });
  const h = loadR2App(f);
  await h.api._openGovernanceCeremony({ proposal: r2Proposal("addAgent", sc.params) });
  const retry = h.modal().querySelector("[data-gov-retry]");
  assert.ok(retry, "a satisfied proposal offers Retry the original action");
  await retry.onclick();
  await r2Until(() => r2Reads(f).length >= 2 || r2Builds(f).length > 0);
  await new Promise((r) => setTimeout(r, 300));
  assert.equal(r2Builds(f).filter((c) => c.body && c.body.proposalId).length, 0, "the proposal id is never sent");
  assert.equal(r2Builds(f).length, 0, "no build request at all");
});

test("RC45 R2-07: a single failed network-position read is retried once after a short pause and the build then proceeds — two reads precede the one build request [RED on b89f0f7]", async () => {
  const sc = r2Scenario("addAgent", { clientStart: R2_D, anchor: R2_D + 40n });
  const f = r2Fetch({ reads: [R2_READ_FAILED, R2_D.toString()], build: r2Built(sc) });
  const h = loadR2App(f);
  await h.api._runFlow(H.VAULT_ID, "addAgent", { ...sc.params, fuel: R2_UTXO }, "Approve in wallet");
  assert.equal(r2Builds(f).length, 1, "the build is posted after the retry");
  assert.equal(r2ReadsBeforeBuild(f), 2, "the failed read and its one retry precede the build");
  assert.ok(r2Verified(h), "the review opens VERIFIED");
});

test("RC45 R2-07: a build response followed by failing network-position reads still opens the review unblocked — no read after the build decides anything [RED on b89f0f7]", async () => {
  const sc = r2Scenario("addAgent", { clientStart: R2_D, anchor: R2_D + 40n });
  let built = false;
  const f = makeFetch({
    "GET /api/v1/network/status": () => (built ? R2_READ_FAILED : { status: 200, body: { networkId: "testnet-10", virtualDaaScore: R2_D.toString() } }),
    "POST /api/v1/wallet/v4/requests": () => { built = true; return { status: 201, body: { request: sc.request } }; },
    [`GET /api/v1/wallet/fuel/${encodeURIComponent(H.OWNER_ADDR)}`]: () => ({ status: 200, body: { utxos: [R2_UTXO] } })
  });
  const h = loadR2App(f);
  await h.api._runFlow(H.VAULT_ID, "addAgent", { ...sc.params, fuel: R2_UTXO }, "Approve in wallet");
  assert.ok(r2Verified(h), `the review opens VERIFIED although every later read fails; it shows: ${r2Text(h.modal().innerHTML).slice(0, 600)}`);
  assert.equal(r2ReadsAfterBuild(f), 0, "no read after the build");
});

test("RC45 R2-07: the signing review states the anchored budget period start, the amount spendable at once if confirmed now and the next budget's network position (A + L) [RED on b89f0f7]", async () => {
  const A = R2_D + 40n;
  const sc = r2Scenario("addAgent", { clientStart: R2_D, anchor: A });
  const f = r2Fetch({ build: r2Built(sc) });
  const h = loadR2App(f);
  await h.api._runFlow(H.VAULT_ID, "addAgent", { ...sc.params, fuel: R2_UTXO }, "Approve in wallet");
  const t = r2Text(h.modal().innerHTML);
  assert.match(t, new RegExp(`Budget period starts at network position ${r2NumSrc(A)}`), `the anchored start is stated; it shows: ${t.slice(0, 800)}`);
  assert.ok(t.includes("anchored when this transaction was built"));
  assert.match(t, /If confirmed now, this agent can spend up to 30 KAS at once/, "a new delegate's whole budget (30 KAS), nothing banked");
  assert.match(t, new RegExp(`its next budget of 30 KAS becomes available at network position ${r2NumSrc(A + R2_L)}`), "the next budget's position is A + L");
  assert.match(t, /then 30 KAS per period/);
});

for (const action of ["addAgent", "rotateAgent", "rePolicyAgent", "ownerSetAgentRoot"]) {
  test(`RC45 R2-07: the governance ceremony of a ${action} proposal says when the budget period of a delegate it adds, replaces or re-policies starts (at the build for signing, never earlier than the start shown) and that untouched or idle delegates keep the installed covenant's limitation [RED on b89f0f7]`, async () => {
    const f = r2Fetch({ build: () => govRefusal409() });
    const h = loadR2App(f);
    await h.api._openGovernanceCeremony({ proposal: r2Proposal(action, {}) });
    const t = r2Text(h.modal().innerHTML);
    assert.ok(/Governance proposal/.test(t), "the ceremony is open");
    for (const needle of R2_NOTE) assert.ok(t.includes(needle), `the ceremony note says "${needle}"; it shows: ${t.slice(0, 800)}`);
  });
}

test("RC45 R2-07: the ceremony of a proposal that sets no delegate leaf (a spend, a removal, a pause, an approver change) carries no budget-period-start note", async () => {
  for (const action of ["agentSpend", "removeAgent", "ownerPause", "ownerSetApprovers"]) {
    const f = r2Fetch({ build: () => govRefusal409() });
    const h = loadR2App(f);
    await h.api._openGovernanceCeremony({ proposal: r2Proposal(action, {}) });
    const t = r2Text(h.modal().innerHTML);
    assert.ok(/Governance proposal/.test(t), `${action}: the ceremony is open`);
    assert.ok(!t.includes(R2_NOTE[0]), `${action}: no budget-period-start note`);
  }
});
