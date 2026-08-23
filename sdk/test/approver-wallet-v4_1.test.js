"use strict";

/*
 * H2 REAL-KASWARE APPROVER BLOCKER regression (v0.4.1).
 *
 * Live failure (request 98190595, 2026-08-22): the browser approver path
 * reconstructed signing metadata as [{ index: 0 }] — dropping the frozen
 * sighashType — and real KasWare's signPskt panicked with the WASM error
 * "unreachable" AFTER the human clicked Sign. KasWare's own source maps a
 * provided options.signInputs entry to sighashTypes:[input.sighashType] with
 * NO default (wallet.ts signPskt), the keyring sees the truthy [undefined]
 * array and skips its fallback (simple-keyring.ts), and
 * new Uint8Array([undefined]) coerces to the INVALID sighash type 0, which
 * panics kaspa-wasm. The dev signer ignores sighashType entirely, which is
 * why every automated run passed while the real wallet failed.
 *
 * These tests drive the REAL server over HTTP + the REAL production
 * web/app-v4.js in jsdom, with an adapter SPY at the wallet seam that records
 * the exact metadata handed to the provider and returns REAL kaspa-wasm
 * signed Safe JSON (the same serializeToSafeJSON() string shape real KasWare
 * returns per its source). Layers: API + BROWSER. No broadcast.
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

let ORIGIN = null; // ephemeral port, assigned in before()
let BASE = null;

const config = loadConfig({ dataRoot: fs.mkdtempSync(path.join(os.tmpdir(), "pv-approver-wallet-")) });
const kaspa = require(config.rustyKaspaModule);
const KEYHEX = (v) => v.toString(16).padStart(2, "0").repeat(32);
const KEY = (v) => new kaspa.PrivateKey(KEYHEX(v));
const XO = (v) => KEY(v).toPublicKey().toXOnlyPublicKey().toString().toLowerCase();
const ADDR = (v) => KEY(v).toPublicKey().toAddress(config.networkId).toString();
const KAS = 100000000n;
const OWNER = 1, AGENT = 0x1e, APPR_A = 0x51, APPR_B = 0x52, RECIP = 0x28;
const VAULT = "79".repeat(32);

function seed() {
  const registry = [{ agentPk: XO(AGENT), maxPerSpend: (20n * KAS).toString(), periodBudget: (50n * KAS).toString(), periodLengthDaa: "864000", periodStartDaa: "541000000", periodSpent: "0", approvalThreshold: (5n * KAS).toString(), agentMaxFeePerTx: (1n * KAS).toString(), recipients: [XO(RECIP)] }];
  const template = { owner: XO(OWNER), vaultId: VAULT };
  const policies = registry.map((e) => normalizeAgentPolicyV4({ ...e, agentRecipientRoot: buildRecipientTree(e.recipients).root }));
  const state = normalizeStateV4({ protectedValue: (1000n * KAS).toString(), feeReserve: (5n * KAS).toString(), paused: "0", agentRoot: buildAgentTreeV4(policies).root, approvers: [XO(APPR_A), XO(APPR_B)], approvalM: "2", policyNonce: "0" });
  const compiled = compileExactStateV4({ config, template, state, contractVersion: CONTRACT_VERSION_V4_1 });
  const stateId = computeStateIdV4({ networkId: config.networkId, template, state, contractVersion: CONTRACT_VERSION_V4_1 });
  persistManifestV4(config, {
    schema: MANIFEST_SCHEMA_V4, contractVersion: CONTRACT_VERSION_V4_1, networkId: config.networkId, vaultId: VAULT,
    label: "approver-wallet", status: "ACTIVE", template, agentRegistry: registry,
    live: { state: stateToJsonV4(state), stateId, outpoint: { transactionId: "47".repeat(32), index: 0 }, outpointValue: (state.protectedValue + state.feeReserve).toString(), scriptSha256: compiled.scriptSha256, covenantId: "41".repeat(32) },
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
  seed();
  server = createServer(config);
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  ORIGIN = `http://127.0.0.1:${server.address().port}`;
  BASE = `${ORIGIN}/api/v1`;
});
after(() => server && server.close());

/* jsdom over the REAL production browser code; the wallet seam is an adapter
 * SPY: it records exactly what the app hands the provider, then either signs
 * with the REAL dev signer or throws the injected provider error. */
function openApp(role, { providerError = null } = {}) {
  const html = fs.readFileSync(path.join(__dirname, "..", "..", "web", "index.html"), "utf8").replace(/<script src="[^"]*"><\/script>/g, "");
  const appV4 = fs.readFileSync(path.join(__dirname, "..", "..", "web", "app-v4.js"), "utf8");
  const dom = new JSDOM(html, { url: `${ORIGIN}/`, runScripts: "outside-only", pretendToBeVisual: true });
  const { window } = dom;
  window.fetch = (u, o) => {
    const url = new URL(u, ORIGIN);
    if (o && o.method === "POST" && /\/submit$/.test(url.pathname)) {
      return Promise.resolve({ ok: false, status: 409, json: async () => ({ error: { code: "TEST_NO_BROADCAST", message: "tests stop before broadcast" } }) });
    }
    return fetch(url, o);
  };
  window.prompt = () => null;
  window.confirm = () => true;
  const providerCalls = [];
  const listeners = [];
  const snap = () => ({
    connected: true, ready: true, address: ADDR(role), xonly: XO(role),
    network: "testnet-10", provider: "spy",
    adapter: {
      signInputs: async (unsignedSafeJson, signInputs) => {
        providerCalls.push({ unsignedSafeJson, signInputs: JSON.parse(JSON.stringify(signInputs)) });
        if (providerError) throw providerError;
        return signerFor(role).signInputs(unsignedSafeJson, signInputs);
      }
    }
  });
  window.PolicyVaultWalletSession = { active: snap, subscribe(cb) { listeners.push(cb); cb(snap()); return () => {}; }, connect() {}, disconnect() {} };
  window.eval(appV4);
  window.dispatchEvent(new window.Event("DOMContentLoaded"));
  const doc = window.document;
  return {
    window, doc, providerCalls,
    click: (el) => el.dispatchEvent(new window.MouseEvent("click", { bubbles: true, cancelable: true })),
    tabAll: async function () {
      const pill = await waitFor(() => doc.querySelector('[data-status="All"]'));
      this.click(pill);
      await sleep(50);
    },
    banner: (id) => doc.querySelector(`[data-reqcard="${id}"]`),
    notice: () => doc.getElementById("v4-notice").textContent
  };
}

let REQ = null;

test("setup: above-threshold 2-of-2 request freezes explicit SIG_HASH_ALL signing metadata", async () => {
  const r = await post("/wallet/v4/requests", { vaultId: VAULT, action: "agentSpend", params: { agentPk: XO(AGENT), recipient: XO(RECIP), payAmountSompi: (6n * KAS).toString() }, signerAddress: ADDR(AGENT) });
  assert.equal(r.status, 201, JSON.stringify(r.j).slice(0, 200));
  REQ = r.j.request;
  assert.equal(REQ.state, "AWAITING_APPROVALS");
  // Every frozen signing entry carries an EXPLICIT sighashType 1 — the field
  // real KasWare requires per entry (its per-entry mapping has no default).
  assert.ok(REQ.transaction.signInputs.length > 0);
  for (const si of REQ.transaction.signInputs) {
    assert.ok(Number.isInteger(si.index) && si.index >= 0);
    assert.equal(si.sighashType, 1, "explicit SIG_HASH_ALL committed in the frozen request");
  }
  assert.equal(REQ.transaction.covenantInputIndex, 0);
});

test("BROWSER: the approver hands the provider the CANONICAL FROZEN signInputs — never a reconstructed [{index:0}]", async () => {
  const app = openApp(APPR_A);
  await app.tabAll();
  const banner = await waitFor(() => { const b = app.banner(REQ.requestId); return b && b.querySelector("[data-approvereq]") ? b : null; });
  app.click(banner.querySelector("[data-approvereq]"));
  const confirm = await waitFor(() => app.doc.getElementById("v4-confirm"));
  app.click(confirm);
  await waitFor(async () => (await get(`/wallet/v4/requests/${REQ.requestId}`)).j.request.approvalProgress.collected === 1);
  // The EXACT provider invocation: the frozen covenant-input entry, verbatim.
  assert.equal(app.providerCalls.length, 1);
  const call = app.providerCalls[0];
  assert.deepEqual(call.signInputs, [{ index: 0, sighashType: 1 }], "canonical frozen metadata reaches the wallet");
  assert.equal(call.unsignedSafeJson, REQ.transaction.unsignedSafeJson, "the approver signs the exact frozen bytes");
  // Real returned-wallet shape: kaspa-wasm serializeToSafeJSON string (the
  // same shape real KasWare returns per its source) with a hex
  // signatureScript on the signed input — accepted by the server as 1/2.
  const signedShape = JSON.parse(signerFor(APPR_A).signInputs(REQ.transaction.unsignedSafeJson, [{ index: 0, sighashType: 1 }]));
  assert.match(signedShape.inputs[0].signatureScript, /^[0-9a-f]+$/);
});

test("BROWSER: a provider WASM 'unreachable' error surfaces the stage + original exception and persists NOTHING", async () => {
  const boom = Object.assign(new Error("unreachable"), { name: "RuntimeError" });
  const app = openApp(APPR_B, { providerError: boom });
  const manifestPath = path.join(config.dataRoot, "vaults", VAULT, "manifest.json");
  const manifestBefore = fs.readFileSync(manifestPath);
  const reqBefore = JSON.parse(fs.readFileSync(path.join(config.dataRoot, "requests", `${REQ.requestId}.json`), "utf8"));
  await app.tabAll();
  const banner = await waitFor(() => { const b = app.banner(REQ.requestId); return b && b.querySelector("[data-approvereq]") ? b : null; });
  app.click(banner.querySelector("[data-approvereq]"));
  const confirm = await waitFor(() => app.doc.getElementById("v4-confirm"));
  app.click(confirm);
  await waitFor(() => /Approval rejected/.test(app.notice()));
  // The opaque "unreachable" is gone: the notice carries the exact stage and
  // the ORIGINAL exception name + message.
  assert.match(app.notice(), /stage E:provider-signPskt-invoked/, app.notice());
  assert.match(app.notice(), /RuntimeError: unreachable/, app.notice());
  // Fail-closed: nothing persisted anywhere.
  const now = (await get(`/wallet/v4/requests/${REQ.requestId}`)).j.request;
  assert.equal(now.state, reqBefore.state);
  assert.equal(now.approvalProgress.collected, 1, "approval count unchanged by the wallet failure");
  assert.equal(now.txId, REQ.txId, "frozen txId unchanged");
  assert.equal(now.transaction.unsignedSafeJson, REQ.transaction.unsignedSafeJson, "frozen bytes unchanged");
  assert.deepEqual(claimFiles("transition"), [], "no transition claim");
  assert.deepEqual(claimFiles("submission"), [], "no submission claim");
  assert.deepEqual(fs.readFileSync(manifestPath), manifestBefore, "vault manifest byte-identical");
});

test("BROWSER: the canonical-signInputs guard refuses malformed metadata BEFORE any provider call", async () => {
  const app = openApp(APPR_B);
  await app.tabAll();
  const ws = app.window.PolicyVaultV4._walletSign;
  // The exact shape that panicked real KasWare: missing sighashType.
  await assert.rejects(() => ws(REQ.transaction.unsignedSafeJson, [{ index: 0 }], ADDR(APPR_B)), (e) => e.code === "SIGN_INPUTS_INVALID" && e.walletStage === "D:signInputs-validated");
  // Any non-SIG_HASH_ALL type is refused (the app only ever emits 1).
  await assert.rejects(() => ws(REQ.transaction.unsignedSafeJson, [{ index: 0, sighashType: 3 }], ADDR(APPR_B)), (e) => e.code === "SIGN_INPUTS_INVALID");
  // Empty metadata is refused.
  await assert.rejects(() => ws(REQ.transaction.unsignedSafeJson, [], ADDR(APPR_B)), (e) => e.code === "SIGN_INPUTS_INVALID");
  assert.equal(app.providerCalls.length, 0, "the wallet is NEVER invoked with malformed signing metadata");
});

test("API: approver A's signature cannot fill approver B's slot (identity-bound verification)", async () => {
  const sigFromA = signerFor(APPR_A).signInputs(REQ.transaction.unsignedSafeJson, [{ index: 0, sighashType: 1 }]);
  const r = await post(`/wallet/v4/requests/${REQ.requestId}/approvals`, { approverAddress: ADDR(APPR_B), signedSafeJson: sigFromA });
  assert.ok(r.status >= 400, "A's signature presented as B is refused");
  const still = (await get(`/wallet/v4/requests/${REQ.requestId}`)).j.request;
  assert.equal(still.approvalProgress.collected, 1, "collected count unchanged");
  const slotB = still.approvalProgress.approverSlots.indexOf(XO(APPR_B));
  assert.equal(still.approvalProgress.approvedSlots[slotB], false, "B's slot remains empty");
});

test("BROWSER: approver B completes 2-of-2 through the canonical path; frozen commitment intact end-to-end", async () => {
  const app = openApp(APPR_B);
  await app.tabAll();
  const banner = await waitFor(() => { const b = app.banner(REQ.requestId); return b && b.querySelector("[data-approvereq]") ? b : null; });
  app.click(banner.querySelector("[data-approvereq]"));
  const confirm = await waitFor(() => app.doc.getElementById("v4-confirm"));
  app.click(confirm);
  await waitFor(async () => (await get(`/wallet/v4/requests/${REQ.requestId}`)).j.request.approvalProgress.complete === true);
  assert.deepEqual(app.providerCalls[0].signInputs, [{ index: 0, sighashType: 1 }]);
  const done = (await get(`/wallet/v4/requests/${REQ.requestId}`)).j.request;
  assert.equal(done.state, "BUILT");
  assert.equal(done.txId, REQ.txId);
  assert.equal(done.transaction.unsignedSafeJson, REQ.transaction.unsignedSafeJson, "frozen bytes identical through the whole collection");
});
