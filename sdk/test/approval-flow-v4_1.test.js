"use strict";

/*
 * H2 INCIDENT REGRESSION — above-threshold approval orchestration (v0.4.1).
 *
 * Live incident (2026-08-22, requests 98190595/a206048d): the browser offered
 * "Sign spend" on an AWAITING_APPROVALS build (2-of-2 required), the real
 * agent KasWare signed, and the browser POSTed /signature — the server
 * correctly refused (INSUFFICIENT_APPROVALS) and persisted nothing, but the
 * UI had routed the agent into finalize with 0 approvals collected.
 *
 * These tests drive the REAL server over HTTP (createServer, temp data root)
 * and the REAL production web/app-v4.js in jsdom. Only the wallet boundary is
 * mocked, with REAL Schnorr signatures from the dev signer (the same seam the
 * proven automated acceptance used). Layers: API + BROWSER. No broadcast: the
 * flow is proven through FINALIZE/PREFLIGHT_VERIFIED; the browser submit call
 * is stubbed at the test fetch layer (live submission is proven elsewhere).
 */

const { test, before, after } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { JSDOM } = require("jsdom");

const { loadConfig } = require("../src/config");
const { createServer } = require("../../server/src/server");
const { makeDevSigner } = require("../src/signer-dev");
const { buildAgentTreeV4, normalizeAgentPolicyV4 } = require("../src/agent-merkle-v4");
const { buildRecipientTree } = require("../src/recipient-merkle-v3");
const { normalizeStateV4, computeStateIdV4, stateToJsonV4, CONTRACT_VERSION_V4_1 } = require("../src/vault-state-v4");
const { compileExactStateV4 } = require("../src/contract-compiler-v4");
const { MANIFEST_SCHEMA_V4, persistManifestV4 } = require("../src/manifest-v4");

const PORT = 3096;
const ORIGIN = `http://127.0.0.1:${PORT}`;
const BASE = `${ORIGIN}/api/v1`;

const config = loadConfig({ dataRoot: fs.mkdtempSync(path.join(os.tmpdir(), "pv-approval-flow-")) });
const kaspa = require(config.rustyKaspaModule);
const KEYHEX = (v) => v.toString(16).padStart(2, "0").repeat(32);
const KEY = (v) => new kaspa.PrivateKey(KEYHEX(v));
const XO = (v) => KEY(v).toPublicKey().toXOnlyPublicKey().toString().toLowerCase();
const ADDR = (v) => KEY(v).toPublicKey().toAddress(config.networkId).toString();
const KAS = 100000000n;

const OWNER = 1, AGENT = 0x1e, APPR_A = 0x51, APPR_B = 0x52, RECIP = 0x28, UNRELATED = 0x66;
const VAULT_A = "77".repeat(32); // approval-flow vault (2-of-2)
const VAULT_B = "78".repeat(32); // below-threshold control vault (2-of-2 too)

function seedVault(vaultId, outpointTx) {
  const registry = [{ agentPk: XO(AGENT), maxPerSpend: (20n * KAS).toString(), periodBudget: (50n * KAS).toString(), periodLengthDaa: "864000", periodStartDaa: "541000000", periodSpent: "0", approvalThreshold: (5n * KAS).toString(), agentMaxFeePerTx: (1n * KAS).toString(), recipients: [XO(RECIP)] }];
  const template = { owner: XO(OWNER), vaultId };
  const policies = registry.map((e) => normalizeAgentPolicyV4({ ...e, agentRecipientRoot: buildRecipientTree(e.recipients).root }));
  const state = normalizeStateV4({ protectedValue: (1000n * KAS).toString(), feeReserve: (5n * KAS).toString(), paused: "0", agentRoot: buildAgentTreeV4(policies).root, approvers: [XO(APPR_A), XO(APPR_B)], approvalM: "2", policyNonce: "0" });
  const compiled = compileExactStateV4({ config, template, state, contractVersion: CONTRACT_VERSION_V4_1 });
  const stateId = computeStateIdV4({ networkId: config.networkId, template, state, contractVersion: CONTRACT_VERSION_V4_1 });
  persistManifestV4(config, {
    schema: MANIFEST_SCHEMA_V4, contractVersion: CONTRACT_VERSION_V4_1, networkId: config.networkId, vaultId,
    label: `approval-flow-${vaultId.slice(0, 2)}`, status: "ACTIVE", template, agentRegistry: registry,
    live: { state: stateToJsonV4(state), stateId, outpoint: { transactionId: outpointTx, index: 0 }, outpointValue: (state.protectedValue + state.feeReserve).toString(), scriptSha256: compiled.scriptSha256, covenantId: "41".repeat(32) },
    creationTxId: "42".repeat(32), latestTransitionTxId: null, lastTransition: null
  });
}

const signerFor = (v) => makeDevSigner(config, { secretHex: KEYHEX(v), expectedAddress: ADDR(v) });
const post = async (url, body) => { const r = await fetch(BASE + url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body ?? {}) }); return { status: r.status, j: await r.json() }; };
const get = async (url) => { const r = await fetch(BASE + url); return { status: r.status, j: await r.json() }; };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function waitFor(fn, ms = 120000) {
  const t0 = Date.now();
  for (;;) {
    const v = await fn();
    if (v) return v;
    if (Date.now() - t0 > ms) throw new Error("waitFor timed out");
    await sleep(25);
  }
}
const claimFiles = (kind) => {
  const dir = path.join(config.dataRoot, "claims", kind);
  return fs.existsSync(dir) ? fs.readdirSync(dir) : [];
};

let server;
before(async () => {
  seedVault(VAULT_A, "45".repeat(32));
  seedVault(VAULT_B, "46".repeat(32));
  server = createServer(config);
  await new Promise((r) => server.listen(PORT, "127.0.0.1", r));
});
after(() => server && server.close());

/* jsdom over the REAL production browser code. The wallet session is the ONE
 * mocked seam; `setAccount` re-emits a snapshot exactly like a real KasWare
 * account switch (a security event for the app). POST */
function openApp(role, { prompts = [] } = {}) {
  const html = fs.readFileSync(path.join(__dirname, "..", "..", "web", "index.html"), "utf8").replace(/<script src="[^"]*"><\/script>/g, "");
  const appV4 = fs.readFileSync(path.join(__dirname, "..", "..", "web", "app-v4.js"), "utf8");
  const dom = new JSDOM(html, { url: `${ORIGIN}/`, runScripts: "outside-only", pretendToBeVisual: true });
  const { window } = dom;
  window.fetch = (u, o) => {
    const url = new URL(u, ORIGIN);
    if (o && o.method === "POST" && /\/submit$/.test(url.pathname)) {
      // Tests never broadcast: the pipeline is proven through PREFLIGHT_VERIFIED.
      return Promise.resolve({ ok: false, status: 409, json: async () => ({ error: { code: "TEST_NO_BROADCAST", message: "tests stop before broadcast" } }) });
    }
    return fetch(url, o);
  };
  window.prompt = () => prompts.shift();
  window.confirm = () => true;
  let current = role;
  const listeners = [];
  const snap = () => ({
    connected: true, ready: true, address: ADDR(current), xonly: XO(current),
    network: "testnet-10", provider: "test",
    adapter: { signInputs: async (u, s) => signerFor(current).signInputs(u, s) }
  });
  window.PolicyVaultWalletSession = {
    active: snap,
    subscribe(cb) { listeners.push(cb); cb(snap()); return () => {}; },
    connect() {}, disconnect() {}
  };
  window.eval(appV4);
  window.dispatchEvent(new window.Event("DOMContentLoaded"));
  const doc = window.document;
  return {
    window, doc,
    setAccount(v) { current = v; for (const cb of listeners) cb(snap()); },
    click: (el) => el.dispatchEvent(new window.MouseEvent("click", { bubbles: true, cancelable: true })),
    tabAll: async function () { // the All filter shows every phase of the flow
      const pill = await waitFor(() => doc.querySelector('[data-status="All"]'));
      this.click(pill);
      await sleep(50);
    },
    banner: (reqId) => doc.querySelector(`[data-reqcard="${reqId}"]`),
    notice: () => doc.getElementById("v4-notice").textContent
  };
}

// Shared flow state (tests in this file run sequentially by design).
let REQ = null; // the 2-of-2 request under test
let FROZEN_TX_ID = null;
let FROZEN_UNSIGNED = null;

test("above-threshold build enters AWAITING_APPROVALS with authoritative 0-of-2 progress", async () => {
  const r = await post("/wallet/v4/requests", { vaultId: VAULT_A, action: "agentSpend", params: { agentPk: XO(AGENT), recipient: XO(RECIP), payAmountSompi: (6n * KAS).toString() }, signerAddress: ADDR(AGENT) });
  assert.equal(r.status, 201, JSON.stringify(r.j).slice(0, 200));
  REQ = r.j.request;
  assert.equal(REQ.state, "AWAITING_APPROVALS");
  assert.equal(REQ.aboveThreshold, true);
  assert.deepEqual({ collected: REQ.approvalProgress.collected, required: REQ.approvalProgress.required, complete: REQ.approvalProgress.complete }, { collected: 0, required: 2, complete: false });
  FROZEN_TX_ID = REQ.txId;
  FROZEN_UNSIGNED = REQ.transaction.unsignedSafeJson;
  assert.ok(FROZEN_TX_ID && FROZEN_UNSIGNED);
  // The open-request listing (reload-restore backing store) reports it.
  const list = await get(`/wallet/v4/requests?open=1&vaultId=${VAULT_A}`);
  assert.ok(list.j.requests.some((q) => q.requestId === REQ.requestId));
});

test("INCIDENT REGRESSION: the agent cannot finalize at 0/2 — refused, nothing persisted, no claims", async () => {
  const signed = signerFor(AGENT).signInputs(FROZEN_UNSIGNED, REQ.transaction.signInputs);
  const r = await post(`/wallet/v4/requests/${REQ.requestId}/signature`, { signedSafeJson: signed });
  assert.equal(r.status, 409);
  assert.equal(r.j.error.code, "INSUFFICIENT_APPROVALS");
  const back = (await get(`/wallet/v4/requests/${REQ.requestId}`)).j.request;
  assert.equal(back.state, "AWAITING_APPROVALS", "request state unchanged by the refused finalize");
  assert.equal(back.approvalProgress.collected, 0);
  assert.equal(back.txId, FROZEN_TX_ID);
  const raw = JSON.parse(fs.readFileSync(path.join(config.dataRoot, "requests", `${REQ.requestId}.json`), "utf8"));
  assert.equal(raw.approvalPackage, null, "agent signature was NOT persisted into the request");
  assert.deepEqual(claimFiles("transition"), [], "no transition claim before approvals complete");
  assert.deepEqual(claimFiles("submission"), [], "no submission claim before approvals complete");
});

test("BROWSER: the agent is never offered premature signing; duplicate builds are cancellable", async () => {
  const app = openApp(AGENT, { prompts: [ADDR(RECIP), "6"] });
  await app.tabAll();
  // The durable pending request renders from SERVER state with no sign action.
  const banner = await waitFor(() => app.banner(REQ.requestId));
  assert.match(banner.textContent, /Awaiting approvals/);
  assert.match(banner.textContent, /0 of 2 approved/);
  assert.match(banner.textContent, /Approvers sign first/);
  assert.ok(!banner.querySelector("[data-agentsign]"), "no agent-sign action while approvals are outstanding");
  assert.ok(!banner.querySelector("[data-approvereq]"), "the agent is not an approver");
  // Building the same spend again (the live-incident retry) shows the
  // INFORMATIONAL review — no Sign confirm button — and can be cancelled.
  const spendBtn = await waitFor(() => app.doc.querySelector("[data-spend]"));
  app.click(spendBtn);
  await waitFor(() => app.doc.getElementById("v4-modal").style.display === "flex");
  assert.equal(app.doc.getElementById("v4-confirm"), null, "AWAITING_APPROVALS review offers NO sign action");
  assert.match(app.doc.getElementById("v4-modal").textContent, /Awaiting approvals — 0 of 2/);
  app.click(app.doc.getElementById("v4-cancel"));
  const dup = (await get(`/wallet/v4/requests?open=1&vaultId=${VAULT_A}`)).j.requests.find((q) => q.requestId !== REQ.requestId);
  assert.ok(dup, "duplicate request exists (mirrors the live incident)");
  assert.equal(dup.txId, FROZEN_TX_ID, "identical transition freezes the identical transaction");
  await app.tabAll();
  const dupBanner = await waitFor(() => app.banner(dup.requestId));
  app.click(dupBanner.querySelector("[data-cancelreq]"));
  await waitFor(async () => (await get(`/wallet/v4/requests/${dup.requestId}`)).j.request.state === "WALLET_REJECTED");
  const open = (await get(`/wallet/v4/requests?open=1&vaultId=${VAULT_A}`)).j.requests;
  assert.deepEqual(open.map((q) => q.requestId), [REQ.requestId], "cancel is explicit and leaves the original request pending");
});

test("BROWSER: approver A approves (fresh session = reload restore at 0/2) -> 1 of 2; account switch discards an open modal", async () => {
  const app = openApp(APPR_A);
  await app.tabAll();
  const banner = await waitFor(() => app.banner(REQ.requestId));
  const btn = banner.querySelector("[data-approvereq]");
  assert.ok(btn, "approver A sees an actionable approval request");
  // Account switching mid-review is a security event: the modal is discarded.
  app.click(btn);
  await waitFor(() => app.doc.getElementById("v4-modal").style.display === "flex");
  app.setAccount(UNRELATED);
  await waitFor(() => app.doc.getElementById("v4-modal").style.display === "none");
  app.setAccount(APPR_A);
  // Approve for real.
  await app.tabAll();
  const banner2 = await waitFor(() => { const b = app.banner(REQ.requestId); return b && b.querySelector("[data-approvereq]") ? b : null; });
  app.click(banner2.querySelector("[data-approvereq]"));
  const confirm = await waitFor(() => app.doc.getElementById("v4-confirm"));
  assert.equal(confirm.textContent, "Approve");
  app.click(confirm);
  await waitFor(async () => (await get(`/wallet/v4/requests/${REQ.requestId}`)).j.request.approvalProgress.collected === 1);
  const now = (await get(`/wallet/v4/requests/${REQ.requestId}`)).j.request;
  assert.equal(now.state, "AWAITING_APPROVALS");
  // Fixed 10-slot package layout with CANONICAL approver ordering: approver A
  // fills EXACTLY its own slot — every other slot stays empty.
  const slotA = now.approvalProgress.approverSlots.indexOf(XO(APPR_A));
  assert.ok(slotA >= 0);
  assert.deepEqual(now.approvalProgress.approvedSlots, now.approvalProgress.approverSlots.map((_, i) => i === slotA), "approver A filled exactly approver A's slot");
  assert.equal(now.txId, FROZEN_TX_ID, "frozen transaction unchanged by the approval");
  // The approver's own view flips to non-actionable progress.
  await app.tabAll();
  const after = await waitFor(() => { const b = app.banner(REQ.requestId); return b && /You approved/.test(b.textContent) ? b : null; });
  assert.match(after.textContent, /1 of 2 approved/);
});

test("API: the same approver cannot count twice; an unrelated wallet has no approval authority", async () => {
  const dupSig = signerFor(APPR_A).signInputs(FROZEN_UNSIGNED, [{ index: 0 }]);
  const dup = await post(`/wallet/v4/requests/${REQ.requestId}/approvals`, { approverAddress: ADDR(APPR_A), signedSafeJson: dupSig });
  assert.ok(dup.status >= 400, "duplicate approval refused");
  const unrelSig = signerFor(UNRELATED).signInputs(FROZEN_UNSIGNED, [{ index: 0 }]);
  const unrel = await post(`/wallet/v4/requests/${REQ.requestId}/approvals`, { approverAddress: ADDR(UNRELATED), signedSafeJson: unrelSig });
  assert.ok(unrel.status >= 400, "unrelated wallet refused");
  const still = (await get(`/wallet/v4/requests/${REQ.requestId}`)).j.request;
  assert.equal(still.approvalProgress.collected, 1, "collected count unchanged");
  assert.equal(still.txId, FROZEN_TX_ID);
});

test("BROWSER: approver B approves (fresh session = reload restore at 1/2) -> 2 of 2; commitment unchanged; state BUILT", async () => {
  const app = openApp(APPR_B);
  await app.tabAll();
  const banner = await waitFor(() => { const b = app.banner(REQ.requestId); return b && b.querySelector("[data-approvereq]") ? b : null; });
  assert.match(banner.textContent, /1 of 2 approved/, "reload restored backend truth at 1/2");
  app.click(banner.querySelector("[data-approvereq]"));
  const confirm = await waitFor(() => app.doc.getElementById("v4-confirm"));
  app.click(confirm);
  await waitFor(async () => (await get(`/wallet/v4/requests/${REQ.requestId}`)).j.request.approvalProgress.complete === true);
  const done = (await get(`/wallet/v4/requests/${REQ.requestId}`)).j.request;
  assert.equal(done.state, "BUILT", "threshold met -> ready for the ACTING AGENT to sign");
  // Approver B filled EXACTLY slot 1 (fixed 10-slot layout; no reinterpretation).
  assert.deepEqual(done.approvalProgress.approvedSlots, [true, true, ...Array(8).fill(false)]);
  assert.equal(done.txId, FROZEN_TX_ID, "exact transaction commitment unchanged through BOTH approvals");
  assert.equal(done.transaction.unsignedSafeJson, FROZEN_UNSIGNED, "frozen bytes byte-identical through approval collection");
});

test("BROWSER: only the acting agent gets Sign spend after 2/2; an unrelated wallet sees read-only progress; finalize succeeds", async () => {
  // Unrelated wallet: progress only, no actions.
  const stranger = openApp(UNRELATED);
  await stranger.tabAll();
  const roBanner = await waitFor(() => stranger.banner(REQ.requestId));
  assert.match(roBanner.textContent, /Approved — awaiting agent signature/);
  assert.ok(!roBanner.querySelector("[data-agentsign]") && !roBanner.querySelector("[data-approvereq]") && !roBanner.querySelector("[data-cancelreq]"), "unrelated wallet has no authority");

  // Acting agent: Review & sign spend -> FINALIZE (server re-verifies approvals).
  const app = openApp(AGENT);
  await app.tabAll();
  const banner = await waitFor(() => { const b = app.banner(REQ.requestId); return b && b.querySelector("[data-agentsign]") ? b : null; });
  assert.match(banner.textContent, /2 of 2 approved/);
  app.click(banner.querySelector("[data-agentsign]"));
  const confirm = await waitFor(() => app.doc.getElementById("v4-confirm"));
  assert.equal(confirm.textContent, "Sign spend");
  app.click(confirm);
  await waitFor(async () => {
    const st = (await get(`/wallet/v4/requests/${REQ.requestId}`)).j.request.state;
    return st === "PREFLIGHT_VERIFIED";
  });
  assert.ok(claimFiles("transition").length === 1 && claimFiles("submission").length === 1, "durable claims exist only after the approved finalize");
});

test("API: the below-threshold agent-only flow is unchanged (control vault)", async () => {
  const r = await post("/wallet/v4/requests", { vaultId: VAULT_B, action: "agentSpend", params: { agentPk: XO(AGENT), recipient: XO(RECIP), payAmountSompi: (4n * KAS).toString() }, signerAddress: ADDR(AGENT) });
  assert.equal(r.status, 201);
  const req = r.j.request;
  assert.equal(req.state, "BUILT", "below threshold: immediately signable, no approvals");
  assert.equal(req.aboveThreshold, false);
  assert.equal(req.approvalProgress, undefined, "no approval progress on a below-threshold spend");
  const signed = signerFor(AGENT).signInputs(req.transaction.unsignedSafeJson, req.transaction.signInputs);
  const fin = await post(`/wallet/v4/requests/${req.requestId}/signature`, { signedSafeJson: signed });
  assert.equal(fin.status, 200, JSON.stringify(fin.j).slice(0, 200));
  assert.equal(fin.j.request.state, "PREFLIGHT_VERIFIED");
});

test("API: rejecting a pending approval request is explicit and leaves the vault untouched", async () => {
  const manifestPath = path.join(config.dataRoot, "vaults", VAULT_A, "manifest.json");
  const before = fs.readFileSync(manifestPath);
  const r = await post("/wallet/v4/requests", { vaultId: VAULT_A, action: "agentSpend", params: { agentPk: XO(AGENT), recipient: XO(RECIP), payAmountSompi: (7n * KAS).toString() }, signerAddress: ADDR(AGENT) });
  assert.equal(r.status, 201);
  assert.equal(r.j.request.state, "AWAITING_APPROVALS");
  const rej = await post(`/wallet/v4/requests/${r.j.request.requestId}/reject`, {});
  assert.equal(rej.status, 200);
  assert.equal(rej.j.request.state, "WALLET_REJECTED");
  const open = (await get(`/wallet/v4/requests?open=1&vaultId=${VAULT_A}`)).j.requests.map((q) => q.requestId);
  assert.ok(!open.includes(r.j.request.requestId), "rejected request leaves the open list");
  assert.deepEqual(fs.readFileSync(manifestPath), before, "vault manifest byte-identical — nothing stranded");
});
