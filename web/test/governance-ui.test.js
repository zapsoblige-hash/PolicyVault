"use strict";

/*
 * web/governance-ui.js — the governance ceremony state machine, rendering,
 * and network operations (completion-standard item 1). Network calls are
 * driven against a FAKE api ({getJSON,postJSON}) recording every call, so
 * these tests prove the module's own logic without fetch or a DOM.
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");

const { createModule } = require("../governance-ui.js");
const govRiskExplain = require("../gov-risk-explain.js");

const OWNER = "bb".repeat(32);
const APPROVER = "cc".repeat(32);
const VAULT_ID = "aa".repeat(32);

function fakeApi() {
  const calls = [];
  const responses = new Map(); // "METHOD path" -> value | fn
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

function baseProposal(overrides) {
  return Object.assign(
    {
      proposalId: "prop-1",
      status: "OPEN",
      createdAt: "2026-08-26T00:00:00.000Z",
      proposal: { action: "addAgent", vaultId: VAULT_ID, covenantVersion: "policyvault-0.4.1", params: { agent: { agentPk: "dd".repeat(32) } }, expiresAt: "2026-09-09T00:00:00.000Z" },
      proposalDigest: "de".repeat(32),
      integrity: { digestOk: true, classificationOk: true },
      classification: { classification: "EXPANSION", codes: ["AGENT_ADDED"], perField: [{ field: "agents[dd..].added", direction: "EXPANSION", code: "AGENT_ADDED" }] },
      approvals: { owner: OWNER, ownerApproved: false, orgQuorum: null, verified: [], satisfied: false },
      approvalMessage: "PolicyVault governance approval\nnetwork: testnet-10\nproposal: prop-1\ndigest: de...\nThis signature approves a policy-change workflow step. It cannot move funds."
    },
    overrides
  );
}

/* ==================== ceremonyState (pure state machine) ==================== */

test("ceremonyState: no proposal -> MISSING, nothing actionable", () => {
  const gov = createModule({ api: fakeApi() });
  const s = gov.ceremonyState(null, { xOnly: OWNER });
  assert.equal(s.phase, "MISSING");
  assert.equal(s.canApprove, false);
  assert.equal(s.canRetry, false);
});

test("ceremonyState: CLOSED (non-OPEN status) never offers approve/retry regardless of approvals content", () => {
  const gov = createModule({ api: fakeApi() });
  for (const status of ["EXPIRED", "CANCELLED", "CONSUMED"]) {
    const s = gov.ceremonyState(baseProposal({ status, approvals: { owner: OWNER, ownerApproved: true, orgQuorum: null, verified: [{ approverXOnly: OWNER }], satisfied: true } }), { xOnly: OWNER });
    assert.equal(s.phase, "CLOSED", status);
    assert.equal(s.canApprove, false, status);
    assert.equal(s.canRetry, false, status);
  }
});

test("ceremonyState: OPEN + unsatisfied + this wallet is the owner and has not approved -> canApprove", () => {
  const gov = createModule({ api: fakeApi() });
  const s = gov.ceremonyState(baseProposal(), { xOnly: OWNER });
  assert.equal(s.phase, "COLLECTING_APPROVALS");
  assert.equal(s.isOwner, true);
  assert.equal(s.alreadyApproved, false);
  assert.equal(s.canApprove, true);
  assert.equal(s.canRetry, false);
});

test("ceremonyState: this wallet already appears in verified[] -> alreadyApproved, cannot approve again", () => {
  const gov = createModule({ api: fakeApi() });
  const p = baseProposal({ approvals: { owner: OWNER, ownerApproved: true, orgQuorum: { required: 2, of: 3, collected: 1 }, verified: [{ approverXOnly: OWNER, collectedAt: "x" }], satisfied: false } });
  const s = gov.ceremonyState(p, { xOnly: OWNER });
  assert.equal(s.alreadyApproved, true);
  assert.equal(s.canApprove, false);
  assert.equal(s.canRetry, false, "org quorum still short");
});

test("ceremonyState: satisfied === true -> READY_TO_RETRY, canRetry, never canApprove again", () => {
  const gov = createModule({ api: fakeApi() });
  const p = baseProposal({ approvals: { owner: OWNER, ownerApproved: true, orgQuorum: null, verified: [{ approverXOnly: OWNER }], satisfied: true } });
  const s = gov.ceremonyState(p, { xOnly: OWNER });
  assert.equal(s.phase, "READY_TO_RETRY");
  assert.equal(s.satisfied, true);
  assert.equal(s.canRetry, true);
  assert.equal(s.canApprove, false);
});

test("ceremonyState: an unrelated wallet (not owner, not in verified[]) can still attempt to approve — the server decides whether it counts", () => {
  const gov = createModule({ api: fakeApi() });
  const s = gov.ceremonyState(baseProposal(), { xOnly: APPROVER });
  assert.equal(s.isOwner, false);
  assert.equal(s.alreadyApproved, false);
  assert.equal(s.canApprove, true, "the UI offers the button; server-side counting is the real gate");
});

test("ceremonyState: no xOnly supplied (disconnected) never crashes and never claims ownership", () => {
  const gov = createModule({ api: fakeApi() });
  const s = gov.ceremonyState(baseProposal(), {});
  assert.equal(s.isOwner, false);
  assert.equal(s.alreadyApproved, false);
});

/* ==================== rendering: refusal / no-soft-bypass ==================== */

test("renderProposalHtml: unsatisfied proposal never renders a retry button", () => {
  const gov = createModule({ api: fakeApi() });
  const p = baseProposal();
  const html = gov.renderProposalHtml(p, gov.ceremonyState(p, { xOnly: OWNER }));
  assert.ok(!html.includes("data-gov-retry"), "no retry affordance while approvals are outstanding — no soft-bypass");
  assert.ok(html.includes("data-gov-approve"));
});

test("renderProposalHtml: satisfied proposal offers retry and no longer offers approve", () => {
  const gov = createModule({ api: fakeApi() });
  const p = baseProposal({ approvals: { owner: OWNER, ownerApproved: true, orgQuorum: null, verified: [{ approverXOnly: OWNER }], satisfied: true } });
  const html = gov.renderProposalHtml(p, gov.ceremonyState(p, { xOnly: OWNER }));
  assert.ok(html.includes("data-gov-retry"));
  assert.ok(!html.includes("data-gov-approve"));
});

test("renderProposalHtml: a CLOSED (e.g. EXPIRED) proposal never offers approve or retry — server truth rendered as-is", () => {
  const gov = createModule({ api: fakeApi() });
  const p = baseProposal({ status: "EXPIRED" });
  const html = gov.renderProposalHtml(p, gov.ceremonyState(p, { xOnly: OWNER }));
  assert.ok(!html.includes("data-gov-approve"));
  assert.ok(!html.includes("data-gov-retry"));
  assert.ok(html.includes("EXPIRED"));
});

test("renderProposalHtml: an integrity alarm (digest/classification mismatch) is surfaced prominently", () => {
  const gov = createModule({ api: fakeApi() });
  const p = baseProposal({ integrity: { digestOk: false, classificationOk: true } });
  const html = gov.renderProposalHtml(p, gov.ceremonyState(p, { xOnly: OWNER }));
  assert.ok(/INTEGRITY ALARM/.test(html));
});

test("renderProposalHtml: with the real explanation renderer wired in (as production does via window.PolicyVaultGovRiskExplain), renders classification codes/explanation content", () => {
  const gov = createModule({ api: fakeApi(), explain: govRiskExplain });
  const p = baseProposal();
  const html = gov.renderProposalHtml(p, gov.ceremonyState(p, { xOnly: OWNER }));
  assert.ok(html.includes("AGENT_ADDED") || /expansion/i.test(html));
});

test("renderProposalHtml: WITHOUT an explanation renderer wired in, degrades honestly instead of fabricating content", () => {
  const gov = createModule({ api: fakeApi() }); // no `explain` — mirrors a page missing gov-risk-explain.js
  const p = baseProposal();
  const html = gov.renderProposalHtml(p, gov.ceremonyState(p, { xOnly: OWNER }));
  assert.ok(html.includes("(explanation renderer not loaded)"));
  // Server truth (action, vault, proposal id, approval status) is still
  // rendered directly by this module either way — only the code->English
  // narration depends on the explainer.
  assert.ok(html.includes("addAgent") && html.includes("data-gov-approve"));
});

test("renderCompactCard: always offers a View & act affordance keyed to the exact proposalId", () => {
  const gov = createModule({ api: fakeApi() });
  const html = gov.renderCompactCard(baseProposal());
  assert.ok(html.includes('data-govopen="prop-1"'));
});

/* ==================== network operations ==================== */

test("createProposalFor: posts exactly vaultId/action/params to /governance/proposals", async () => {
  const api = fakeApi();
  api.on("POST /governance/proposals", (body) => {
    assert.deepEqual(body, { vaultId: VAULT_ID, action: "addAgent", params: { agent: { agentPk: "ee".repeat(32) } } });
    return { proposal: baseProposal() };
  });
  const gov = createModule({ api });
  const p = await gov.createProposalFor({ vaultId: VAULT_ID, action: "addAgent", params: { agent: { agentPk: "ee".repeat(32) } } });
  assert.equal(p.proposalId, "prop-1");
});

test("fetchProposal / fetchOpenProposals: correct routes, and fetchOpenProposals filters to status OPEN only", async () => {
  const api = fakeApi();
  api.on(`GET /governance/proposals/prop-1`, { proposal: baseProposal() });
  api.on(`GET /governance/proposals`, { proposals: [baseProposal({ proposalId: "a", status: "OPEN" }), baseProposal({ proposalId: "b", status: "EXPIRED" }), baseProposal({ proposalId: "c", status: "CONSUMED" })] });
  const gov = createModule({ api });
  const single = await gov.fetchProposal("prop-1");
  assert.equal(single.proposalId, "prop-1");
  const open = await gov.fetchOpenProposals();
  assert.deepEqual(open.map((p) => p.proposalId), ["a"]);
});

test("fetchOpenProposals: vaultId filter is passed as a query string", async () => {
  const api = fakeApi();
  api.on(`GET /governance/proposals?vaultId=${VAULT_ID}`, { proposals: [] });
  const gov = createModule({ api });
  const out = await gov.fetchOpenProposals({ vaultId: VAULT_ID });
  assert.deepEqual(out, []);
});

test("cancelProposal: posts to the exact cancel route", async () => {
  const api = fakeApi();
  api.on("POST /governance/proposals/prop-1/cancel", { proposal: baseProposal({ status: "CANCELLED" }) });
  const gov = createModule({ api });
  const p = await gov.cancelProposal("prop-1");
  assert.equal(p.status, "CANCELLED");
});

/* ==================== approve(): signs THROUGH the existing adapter,
 * never a second signing path; posts the SERVER's own approvalMessage ==================== */

test("approve: signs the server's approvalMessage via adapter.signAuthMessage (the SAME method hosted sign-in uses) and posts approverAddress+signature", async () => {
  const signCalls = [];
  const adapter = {
    async signAuthMessage(message, expectations) {
      signCalls.push({ message, expectations });
      return "ab".repeat(64);
    }
  };
  const api = fakeApi();
  const p = baseProposal();
  api.on("POST /governance/proposals/prop-1/approvals", (body) => {
    assert.equal(body.approverAddress, "kaspatest:owner");
    assert.equal(body.signature, "ab".repeat(64));
    return { proposal: baseProposal({ approvals: { owner: OWNER, ownerApproved: true, orgQuorum: null, verified: [{ approverXOnly: OWNER }], satisfied: true } }) };
  });
  const gov = createModule({ api });
  const updated = await gov.approve({ proposal: p, adapter, address: "kaspatest:owner", network: "testnet-10" });
  assert.equal(signCalls.length, 1, "signs exactly once — no double-prompt");
  assert.equal(signCalls[0].message, p.approvalMessage, "signs the SERVER's reconstructed message, never a client-composed string");
  assert.deepEqual(signCalls[0].expectations, { expectedSignerAddress: "kaspatest:owner", network: "testnet-10" });
  assert.equal(updated.approvals.satisfied, true);
});

test("approve: refuses BEFORE any signing call when the proposal carries no approvalMessage (integrity failure)", async () => {
  const signCalls = [];
  const adapter = { async signAuthMessage() { signCalls.push(1); return "x"; } };
  const gov = createModule({ api: fakeApi() });
  const p = baseProposal({ approvalMessage: null });
  await assert.rejects(() => gov.approve({ proposal: p, adapter, address: "kaspatest:owner" }), (e) => e.code === "GOVERNANCE_APPROVAL_MESSAGE_MISSING");
  assert.equal(signCalls.length, 0, "no signing prompt for a proposal with broken integrity");
});

test("approve: refuses when no adapter is connected, before touching the network", async () => {
  const api = fakeApi();
  const gov = createModule({ api });
  await assert.rejects(() => gov.approve({ proposal: baseProposal(), adapter: null, address: "kaspatest:owner" }), (e) => e.code === "WALLET_NOT_READY");
  assert.equal(api.calls.length, 0);
});

/* ==================== createModule guards ==================== */

test("createModule: requires api.{getJSON,postJSON}", () => {
  assert.throws(() => createModule({}), /requires api/);
  assert.throws(() => createModule(), /requires api/);
});
