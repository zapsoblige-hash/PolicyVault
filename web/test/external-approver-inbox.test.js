"use strict";

/*
 * EXTERNAL APPROVER INBOX — BROWSER INTEGRATION (mainnet incident
 * 2026-08-27; server-side twin: sdk/test/external-approver-discovery*.js).
 *
 * The REAL production browser sources (app-v4.js + risk-ui.js +
 * gov-risk-explain.js) run in the vm sandbox against a REAL HTTP server
 * in HOSTED mode (authMode enabled), authenticated as the EXTERNAL
 * covenant approver via a REAL Schnorr sign-in; the sandbox fetch
 * carries the real session cookie. The wallet adapter is a SPY that
 * fails the suite if anything attempts to sign.
 *
 * PROVES (§9 test 20 of the incident directive): after the tenancy fix,
 * the approver's own reload path — render() over GET /vaults +
 * GET /wallet/v4/requests?open=1 — renders the vault card with the
 * "Review & approve" action for THEIR canonical slot, with NO owner
 * controls, NO cancel, NO agent-sign affordance, and ZERO wallet
 * invocations until an explicit approval action. On the frozen
 * fullscale-rc2 source this render is an EMPTY vault list (the incident
 * symptom): the card assertions below are RED.
 */

const { test, before, after } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const vm = require("node:vm");
const http = require("node:http");

const { loadConfig } = require("../../sdk/src/config");
const { createServer } = require("../../server/src/server");
const { normalizeStateV4, computeStateIdV4, normalizeTemplateV4 } = require("../../core/model/vault-state-v4.js");
const { persistManifestV4 } = require("../../sdk/src/manifest-v4");
const { getStore, Categories } = require("../../sdk/src/store");

const core = require("../core-bundle.js");
const { createVerifyIntent } = require("../verify-intent.js");

const APP_V4 = fs.readFileSync(path.join(__dirname, "..", "app-v4.js"), "utf8");
const RISK_UI = fs.readFileSync(path.join(__dirname, "..", "risk-ui.js"), "utf8");
const GOV_RISK_EXPLAIN = fs.readFileSync(path.join(__dirname, "..", "gov-risk-explain.js"), "utf8");

const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "pv-extappr-web-"));
const config = loadConfig({ dataRoot, authMode: "enabled", authCookieInsecure: true });
const kaspa = require(config.rustyKaspaModule);

function walletOf(hexPair) {
  const priv = new kaspa.PrivateKey(hexPair.repeat(32));
  return {
    priv,
    compressed: priv.toPublicKey().toString().toLowerCase(),
    xonly: priv.toPublicKey().toXOnlyPublicKey().toString().toLowerCase(),
    address: priv.toPublicKey().toAddress(config.networkId).toString()
  };
}
const OWNER = walletOf("a7");
const AGENT = walletOf("b8");
const APPROVER = walletOf("c9"); // external covenant approver — the browser identity under test

const VAULT = "aa".repeat(32);
const REQ = "a1000000-0000-4000-8000-000000000001";

let server, BASE, cookie;

async function seed() {
  const template = normalizeTemplateV4({ owner: OWNER.xonly, vaultId: VAULT });
  const state = normalizeStateV4({
    protectedValue: "1000000000", feeReserve: "100000000", paused: "0", policyNonce: "0",
    approvers: [APPROVER.xonly], approvalM: "1",
    agentRoot: "5c646a4a6876b59e313254411585f771fee77dba8d9e947d5bd4a777b2a1d7f8"
  });
  await persistManifestV4(config, {
    schema: "policyvault-vault-manifest/v4", contractVersion: "policyvault-0.4.1", networkId: config.networkId,
    vaultId: VAULT, label: "approver inbox vault", status: "ACTIVE", template, agentRegistry: [],
    live: {
      state: {
        protectedValue: state.protectedValue.toString(), feeReserve: state.feeReserve.toString(),
        paused: state.paused.toString(), agentRoot: state.agentRoot, approverSlots: [...state.approvers],
        approvalM: state.approvalM.toString(), policyNonce: state.policyNonce.toString()
      },
      stateId: computeStateIdV4({ networkId: config.networkId, template, state, contractVersion: "policyvault-0.4.1" }),
      outpoint: { transactionId: "ee".repeat(32), index: 0 }, outpointValue: "1100000000",
      scriptSha256: "ab".repeat(32), covenantId: "cd".repeat(32)
    },
    creationTxId: "12".repeat(32), latestTransitionTxId: null, lastTransition: null
  });
  await getStore(config).write(Categories.REQUEST, REQ, {
    schema: "policyvault-wallet-request/v4", requestId: REQ, vaultId: VAULT,
    action: "agentSpend", state: "AWAITING_APPROVALS", signerAddress: AGENT.address,
    aboveThreshold: true, review: { approvalsRequired: 1 },
    createdAt: new Date().toISOString()
  });
}

function rawReq(method, pathName, { body, cookie: ck } = {}) {
  return new Promise((resolve, reject) => {
    const data = body === undefined ? undefined : JSON.stringify(body);
    const headers = { "Content-Type": "application/json", Origin: BASE, Host: BASE.replace("http://", "") };
    if (ck) headers.Cookie = ck;
    const r = http.request(`${BASE}${pathName}`, { method, headers }, (res) => {
      let buf = "";
      res.on("data", (d) => (buf += d));
      res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, json: buf ? JSON.parse(buf) : null }));
    });
    r.on("error", reject);
    if (data !== undefined) r.write(data);
    r.end();
  });
}

async function signIn(w) {
  const ch = await rawReq("POST", "/api/v1/auth/challenge", { body: { walletAddress: w.address } });
  assert.equal(ch.status, 200, "challenge issued");
  const signature = kaspa.signMessage({ message: ch.json.challenge.message, privateKey: w.priv.toString() });
  const v = await rawReq("POST", "/api/v1/auth/verify", { body: { nonce: ch.json.challenge.nonce, signature, publicKey: w.compressed } });
  assert.equal(v.status, 200, "verified");
  return v.headers["set-cookie"][0].split(";")[0];
}

/* ---- minimal DOM (rc-ux1-browser-continuation makeDom, verbatim) ---- */
function makeDom() {
  const elements = new Map();
  const element = (id) => {
    if (!elements.has(id)) {
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
  const document = { getElementById: (id) => element(id), querySelectorAll: () => [] };
  return { document, element };
}

/* Wallet SPY adapter: any invocation is a test failure. */
const walletSpy = { calls: 0, signInputs() { walletSpy.calls += 1; throw new Error("approver inbox render must NEVER invoke the wallet"); } };

function loadApp(dom) {
  const snap = { connected: true, ready: true, address: APPROVER.address, xonly: APPROVER.xonly, network: config.networkId, serverNetwork: config.networkId, provider: "spy", adapter: walletSpy };
  const session = { active: () => snap, subscribe(cb) { cb(snap); return () => {}; }, connect() {}, disconnect() {} };
  const calls = [];
  const fetchFn = async (url, opts) => {
    const method = (opts && opts.method) || "GET";
    calls.push({ method, url });
    const headers = { ...((opts && opts.headers) || {}), Cookie: cookie, Origin: BASE };
    return fetch(`${BASE}${url}`, { ...(opts || {}), headers });
  };
  const windowObj = {
    addEventListener() {},
    confirm: () => true,
    scrollTo() {},
    PolicyVaultWalletSession: session,
    PolicyVaultVerifyIntent: createVerifyIntent(core)
  };
  const sandbox = {
    window: windowObj,
    document: dom.document,
    console,
    crypto: { getRandomValues: (arr) => { for (let i = 0; i < arr.length; i++) arr[i] = i & 0xff; return arr; } },
    fetch: fetchFn,
    setTimeout,
    clearTimeout
  };
  vm.createContext(sandbox);
  vm.runInContext(GOV_RISK_EXPLAIN, sandbox, { filename: "gov-risk-explain.js" });
  vm.runInContext(RISK_UI, sandbox, { filename: "risk-ui.js" });
  vm.runInContext(APP_V4, sandbox, { filename: "app-v4.js" });
  return { window: windowObj, element: dom.element, api: windowObj.PolicyVaultV4, calls };
}

let loaded;

before(async () => {
  await seed();
  server = createServer(config);
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  BASE = `http://127.0.0.1:${server.address().port}`;
  cookie = await signIn(APPROVER);
  const dom = makeDom();
  loaded = loadApp(dom);
  loaded.api._state.address = APPROVER.address;
  loaded.api._state.xonly = APPROVER.xonly;
  loaded.api._state.network = config.networkId;
  loaded.api._state.serverNetwork = config.networkId;
  loaded.api._state.ready = true; // the session gate render() checks first
});
after(() => server && server.close());

test("external approver browser: render() shows the vault card with Review & approve for THEIR slot — no owner/agent/cancel controls, wallet never invoked", async () => {
  await loaded.api.render();
  const html = loaded.element("v4-root").innerHTML;
  assert.ok(html.includes(`data-vault="${VAULT}"`), `the approver's vault card renders (got: ${html.slice(0, 300)})`);
  assert.ok(html.includes(`data-approvereq="${REQ}"`), "Review & approve is offered for the approver's unfilled canonical slot");
  assert.ok(html.includes("Awaiting approvals"), "the pending request banner renders from SERVER state (reload-restore)");
  assert.ok(!html.includes("data-addagent"), "no owner management controls for the approver");
  assert.ok(!html.includes("data-setapprovers"), "no Set approvers control for the approver");
  assert.ok(!html.includes("data-recover"), "no Close & recover control for the approver");
  assert.ok(!html.includes("data-cancelreq"), "no Cancel affordance — the approver is neither acting agent nor owner");
  assert.ok(!html.includes("data-agentsign"), "no agent-sign affordance for the approver");
  assert.equal(walletSpy.calls, 0, "the wallet is NEVER invoked by discovery/render");
});

test("external approver browser: the approval inbox is server-derived — the exact open request id came over ?open=1 with the session cookie", async () => {
  const listed = loaded.calls.filter((c) => c.url.includes("/wallet/v4/requests?open=1"));
  assert.ok(listed.length >= 1, "render() consulted the durable open-request listing");
  const viaApi = await rawReq("GET", `/api/v1/wallet/v4/requests/${REQ}`, { cookie });
  assert.equal(viaApi.status, 200, "the approver can fetch the exact frozen request by id for review");
  assert.equal(viaApi.json.request.requestId, REQ);
  assert.equal(walletSpy.calls, 0, "still zero wallet invocations");
});
