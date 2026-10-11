"use strict";

/*
 * RC32 delayed KAS creation responses: exercise the actual Organizations
 * screen, wizard, Cancel and navigation in a DOM. Only the wallet session and
 * HTTP responses are doubles. No external resources are loaded; every request
 * is intercepted, and every wallet-signing method fails if invoked.
 *
 * Availability is presentation, never mainnet authorization. These fixtures
 * do not modify SDK configuration, create durable requests or build/sign/send
 * a transaction. Existing roots and hosted organization metadata must remain
 * accessible when NEW root creation is unavailable.
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { JSDOM, VirtualConsole } = require("../../sdk/node_modules/jsdom");

const WEB_DIR = path.join(__dirname, "..");
const HTML = fs.readFileSync(path.join(WEB_DIR, "index.html"), "utf8");
const SCRIPTS = ["core-bundle.js", "setup-ui.js", "org-root-ui.js", "kas-vault-ui.js", "refusal-explain.js", "app-v4.js"]
  .map((name) => ({ name, source: fs.readFileSync(path.join(WEB_DIR, name), "utf8") }));
const F = require('../../core/explain/test/fixtures/v7-kas-manifests.json');
const R = F.manifests[0].manifest;
const ROOT_ID = R.root.covenantId;
const OWNER_KEY = F.genesis.funderXOnly; // public synthetic fixture identity, no private key
const ROOT_VERSIONS = ["policyvault-0.7-root", "policyvault-0.7-kas"];


function capabilities(networkId, versions) {
  return { networkId, contract: { creatableCovenantVersions: versions } };
}

function rootFixture(networkId, address) {
  return {
    rootCovenantId: ROOT_ID,
    orgId: "7b".repeat(32),
    label: "Existing root history",
    networkId,
    ownerSlotsActive: 1,
    ownerM: "1",
    frozen: false,
    slots: [{ slot: 1, publicKey: OWNER_KEY, address, label: "Existing owner" }],
    state: { ownerM: "1", emergencyK: "1", recoveryM: "0", frozen: "0", rootNonce: "3" },
    template: { recoveryDelayDaa: "1000", successionDelayDaa: "2000", successorPk: "00".repeat(32), rootMaxFeePerTx: "100000" },
    live: { outpoint: { transactionId: "7c".repeat(32), index: 0 }, blockDaaScore: "1000" },
    pendingRequestId: null,
    vaults: []
  };
}

async function waitFor(predicate, message) {
  for (let i = 0; i < 100; i++) {
    if (predicate()) return;
    await new Promise((resolve) => setImmediate(resolve));
  }
  assert.ok(predicate(), message);
}

async function loadBrowser(t, { networkId = "mainnet", discovery, discoveryStatus = 200, initialGenesisState = null, holdReject = false, holdStatus = false } = {}) {
  const errors = [];
  const vc = new VirtualConsole();
  vc.on("jsdomError", (e) => errors.push(e.message));
  const dom = new JSDOM(HTML, {
    url: "https://policyvault-fixture.invalid/",
    runScripts: "outside-only",
    pretendToBeVisual: true,
    virtualConsole: vc
  });
  t.after(async () => {
    // Cancel/tab handlers launch asynchronous render refreshes. Let their
    // already-stubbed promise chains settle before destroying the document.
    await new Promise((resolve) => setImmediate(resolve));
    dom.window.close();
  });
  const { window } = dom;
  const document = window.document;
  const address = `${networkId === "mainnet" ? "kaspa" : "kaspatest"}:qfixtureowner`;
  const calls = [];
  let signingCalls = 0;
  const unexpected = [];
  const root = {...rootFixture(networkId, address),orgId:R.root.orgId,template:R.root.template,state:R.rootState.before.state};
  let cap = discovery === undefined
    ? capabilities(networkId, ["policyvault-0.4.1", ...ROOT_VERSIONS])
    : discovery;
  const reply = (body, status = 200) => ({ ok: status < 400, status, json: async () => body });
  const fixtureRequest = (state) => ({ requestId: "late-kas", kind: "kasGenesis", state, contractVersion: "policyvault-0.7-kas", vaultId: F.genesis.summary.vaultId, signerXOnly: OWNER_KEY, signerAddress: address, summary: F.genesis.summary,
    transaction: {unsignedSafeJson:F.genesis.unsignedSafeJson,signInputs:F.genesis.signInputs,frozenCanonicalJson:F.genesis.frozenCanonicalJson} });
  let durable = initialGenesisState ? fixtureRequest(initialGenesisState) : null;
  let releaseKasBuild, releaseReject, releaseStatus;
  window.fetch = async (url, options = {}) => {
    const target = new URL(url, window.location);
    assert.equal(target.origin, window.location.origin, "fixture never reaches an external origin");
    const method = options.method || "GET";
    const route = target.pathname.replace(/^\/api\/v1/, "");
    const body = options.body ? JSON.parse(options.body) : undefined;
    calls.push({ method, route, body });
    if (method === "GET" && route === "/health") return reply({ networkId });
    if (method === "GET" && route === "/capabilities") return reply(cap, discoveryStatus);
    if (method === "GET" && route === "/organizations") return reply({ organizations: [], assignments: {} });
    if (method === "GET" && route === "/org-roots") return reply({ orgRoots: [root] });
    if (method === "GET" && route === `/org-roots/${ROOT_ID}`) return reply({ orgRoot: root });
    if (method === "GET" && route === "/network/status") return reply({ networkId, virtualDaaScore: "2000" });
    if (method === "GET" && route === "/wallet/v7/vaults") return reply({vaults:[]});
    if (method === "GET" && route === "/wallet/v7/requests") {assert.equal(target.search, "", "genesis listing is unfiltered");return reply({requests:durable?[durable]:[]});}
    if (method === "GET" && route === "/wallet/v7/requests/late-kas") return holdStatus ? new Promise(resolve=>{releaseStatus=()=>resolve(reply({request:durable}));}) : reply({request:durable});
    if (method === "POST" && route === "/wallet/v7/requests/late-kas/submit") {durable.state="CHAIN_VERIFIED";return reply({request:durable});}
    if (method === "POST" && route === `/org-roots/${ROOT_ID}/vaults`) return new Promise(resolve => {releaseKasBuild = (fail) => resolve(fail ? reply({error:{code:"BUILD_FAILED",message:"delayed fixture refusal"}},422) : reply({request:(durable=fixtureRequest("BUILT"))}));});
    if (method === "POST" && route === "/wallet/v7/requests/late-kas/reject") {
      const finish=()=>{durable.state="WALLET_REJECTED";return reply({request:durable});};
      return holdReject ? new Promise(resolve=>{releaseReject=()=>resolve(finish());}) : finish();
    }
    if (method === "GET" && route === "/vaults") return reply({ vaults: [] });
    if (method === "GET" && route === "/wallet/v4/requests") return reply({ requests: [] });
    if (method === "GET" && route === "/audit") return reply({ events: [{ kind: "chain", action: "rootGenesis", vaultId: ROOT_ID, txId: "7c".repeat(32), detail: "Existing root creation history", at: "2026-09-01T00:00:00.000Z" }] });
    if (method === "POST" && route === "/identity/resolve-address") return reply({ identity: { xOnlyPubkey: OWNER_KEY } });
    if (method === "POST" && route === "/organizations") return reply({ organization: { orgId: "fixture-hosted", name: body.name } }, 201);
    if (method === "POST" && route === "/wallet/v4/requests") return reply({ error: { code: "RECONCILIATION_REQUIRED", message: "Original payment request is pending with submission outcome uncertain — do not sign again." } }, 409);
    unexpected.push({ method, route });
    throw new Error(`Unmapped fixture HTTP call: ${method} ${route}`);
  };
  const refuseSigning = async () => {
    signingCalls++;
    throw new Error("This presentation test must never invoke wallet signing");
  };
  const snapshot = {
    connected: true, ready: true, address, xonly: OWNER_KEY,
    network: networkId, serverNetwork: networkId, auth: "AUTHENTICATED", provider: "fixture",
    adapter: { signInputs: refuseSigning, signPskt: refuseSigning, signAuthMessage: refuseSigning }
  };
  window.PolicyVaultHealthPromise = Promise.resolve({ networkId });
  let subscriber;
  window.PolicyVaultWalletSession = { active: () => snapshot, subscribe(fn) { subscriber=fn; fn(snapshot); return () => {}; } };
  for (const { name, source } of SCRIPTS) window.eval(`${source}\n//# sourceURL=${name}`);
  await waitFor(() => typeof document.querySelector('.v4-tab[data-view="orgs"]').onclick === "function", "app navigation initialized");
  const api = window.PolicyVaultV4;
  const modal = () => document.getElementById("v4-modal");
  const notice = () => document.getElementById("v4-notice");
  const clickTab = async (view, selector) => {
    document.querySelector(`.v4-tab[data-view="${view}"]`).click();
    await waitFor(() => api._state.view === view && (!selector || document.querySelector(selector)), `${view} view rendered`);
  };
  await clickTab("orgs", "#v4-orgroot-create-btn");
  t.after(() => {
    assert.deepEqual(unexpected, [], "every HTTP operation was explicitly stubbed");
    assert.deepEqual(errors, [], "no uncaught DOM errors");
    assert.equal(signingCalls, 0, "no wallet signing invoked");
    assert.equal(calls.filter((c) => /\/(signature|genesis-submit|finalize)$/.test(c.route)).length, 0, "no signature upload operation");
    if(!initialGenesisState) assert.equal(calls.filter(c=>c.route.endsWith("/submit")).length,0,"no submission operation");
  });
  return {
    window, document, api, calls, modal, notice, clickTab,
    releaseReject(){assert.ok(releaseReject);releaseReject();},
    releaseStatus(){assert.ok(releaseStatus);releaseStatus();},
    changeWallet(patch) { Object.assign(snapshot,patch); subscriber(snapshot); },
    releaseKasBuild(fail=false) {assert.ok(releaseKasBuild,"KAS build pending");releaseKasBuild(fail);},
    setDiscovery(value) { cap = value; },
  };
}

async function startKasBuild(h, honest = false) {
 h.document.querySelector(`[data-viewroot="${ROOT_ID}"]`).click();
 await waitFor(()=>h.modal().querySelector('[data-kascreate]'),'KAS create button');
 h.modal().querySelector('[data-kascreate]').click();
 await waitFor(()=>h.modal().querySelector('[data-kas-wizard]'),'KAS wizard opens');
 const f=h.modal().querySelector('[data-kas-wizard]');
 f.querySelector('[name="depositKas"]').value='10';
 f.querySelector('[name="recoveryAddress"]').value='kaspa:qfixturerecovery';
 if(honest) {
  const values={depositKas:'100',feeReserveKas:'5',recoveryAddress:F.genesis.summary.recoveryPk,
   'agent-0-agentKey':'62'.repeat(32),'agent-0-maxPerSpendKas':'5','agent-0-periodBudgetKas':'20','agent-0-period':'custom','agent-0-periodValue':'1000','agent-0-periodUnit':'daa','agent-0-periodStartDaa':'5000','agent-0-approvalThresholdKas':'2','agent-0-agentMaxFeePerTxKas':'0.1','agent-0-recipient':'63'.repeat(32)};
  for(const [name,value] of Object.entries(values)){const input=f.querySelector(`[name="${name}"]`);assert.ok(input,name);input.value=value;}
  f.querySelector('[data-rows="approver"]').innerHTML=['91','92'].map(k=>`<div class="addr-row"><input name="approverKey" value="${k.repeat(32)}"></div>`).join('');
  const count=f.querySelector('[name="approvalM"]');count.innerHTML='<option value="1">1</option>';count.value='1';
 } else f.querySelectorAll('[data-agent-row]').forEach(r=>r.remove());
 f.dispatchEvent(new h.window.Event('submit',{bubbles:true,cancelable:true}));
 await waitFor(()=>h.calls.some(c=>c.method==='POST' && c.route===`/org-roots/${ROOT_ID}/vaults`),'KAS build pending');
}
for (const interruption of ['cancel','navigate','account','network','auth']) {
 test(`KAS genesis: ${interruption} invalidates a delayed build without reopening review`,async t=>{
  const h=await loadBrowser(t);await startKasBuild(h);
  if(interruption==='cancel') h.modal().querySelector('section:not([hidden]) [data-setup-cancel]').click();
  else if(interruption==='navigate') await h.clickTab('create');
  else h.changeWallet(interruption==='account'?{address:'kaspa:qnewfixture'}:interruption==='network'?{network:'testnet-10',ready:false}:{auth:'EXPIRED'});
  await new Promise(resolve=>setImmediate(resolve));
  h.releaseKasBuild();
  await new Promise(resolve=>setImmediate(resolve));await new Promise(resolve=>setImmediate(resolve));
  assert.equal(h.modal().querySelector('#v4-kas-review-title'),null,'late review never renders');
  assert.equal(h.calls.filter(c=>c.route==='/wallet/v7/requests/late-kas/reject').length,1,'unsigned late request withdrawn once');
 });
}
test('KAS delayed build refusal cannot replace the warning after a wallet change',async t=>{
 const h=await loadBrowser(t);await startKasBuild(h);h.changeWallet({address:'kaspa:qnewfixture'});
 await new Promise(resolve=>setImmediate(resolve));const before=h.notice().textContent;h.releaseKasBuild(true);
 await new Promise(resolve=>setImmediate(resolve));await new Promise(resolve=>setImmediate(resolve));
 assert.equal(h.notice().textContent,before);assert.equal(h.modal().style.display,'none');
});

test('KAS delayed build opens the review while its original setup remains active',async t=>{
 const h=await loadBrowser(t);await startKasBuild(h);h.releaseKasBuild();
 await waitFor(()=>h.modal().querySelector('#v4-kas-review-title'),'original review is reachable');
 assert.equal(h.calls.filter(c=>c.route==='/wallet/v7/requests/late-kas/reject').length,0);
});
test('an old KAS build cannot replace a newly opened treasury setup',async t=>{
 const h=await loadBrowser(t);await startKasBuild(h);
 h.modal().querySelector('section:not([hidden]) [data-setup-cancel]').click();
 await waitFor(()=>h.modal().querySelector('[data-kascreate]'),'returned to root');
 h.modal().querySelector('[data-kascreate]').click();
 await waitFor(()=>h.modal().querySelector('[data-kas-wizard]'),'new setup');
 const form=h.modal().querySelector('[data-kas-wizard]');h.releaseKasBuild();
 await waitFor(()=>h.calls.some(c=>c.route==='/wallet/v7/requests/late-kas/reject'),'late unsigned build withdrawn');
 assert.equal(h.modal().querySelector('[data-kas-wizard]'),form);
 assert.equal(h.modal().querySelector('#v4-kas-review-title'),null);
});

test('Back invalidates Approve before the unsigned withdrawal returns',async t=>{
 const h=await loadBrowser(t,{networkId:'testnet-10',holdReject:true});await startKasBuild(h,true);h.releaseKasBuild();
 await waitFor(()=>h.modal().querySelector('#v4-kas-confirm'),'honest review offers wallet approval');
 const approve=h.modal().querySelector('#v4-kas-confirm');h.modal().querySelector('#v4-kas-review-back').click();
 await waitFor(()=>h.calls.some(c=>c.route==='/wallet/v7/requests/late-kas/reject'),'withdrawal pending');
 approve.click();h.releaseReject();
 await waitFor(()=>h.modal().querySelector('[data-kas-wizard]'),'returns to editing');
});
for(const state of ['SIGNED','SUBMITTED','RECONCILIATION_REQUIRED']) {
 test(`unlinked ${state} KAS genesis remains discoverable and acts on the same request`,async t=>{
  const h=await loadBrowser(t,{initialGenesisState:state});
  h.document.querySelector(`[data-viewroot="${ROOT_ID}"]`).click();
  await waitFor(()=>h.modal().querySelector('[data-kasgenesis-request="late-kas"]'),'unlinked pending creation is visible');
  assert.equal(h.modal().querySelector('[data-kascreate]').disabled,true,'resolve original before another creation');
  h.modal().querySelector('[data-kasgenesis-request="late-kas"]').click();
  await waitFor(()=>h.modal().querySelector('#v4-kasreq-submit'),'same-request action');
  assert.doesNotMatch(h.modal().textContent,/nothing has moved/);
  assert.match(h.modal().querySelector('#v4-kasreq-submit').textContent,state==='SIGNED'?/Submit signed transaction/:/Verify this creation/);
  assert.equal(h.calls.filter(c=>c.route.endsWith('/submit')).length,0,'opening is read-only');
  h.modal().querySelector('#v4-kasreq-submit').click();
  await waitFor(()=>h.modal().textContent.includes('CHAIN_VERIFIED'),'original request completed');
  assert.deepEqual(h.calls.filter(c=>c.route.endsWith('/submit')).map(c=>c.route),['/wallet/v7/requests/late-kas/submit']);
  assert.equal(h.calls.filter(c=>c.method==='POST'&&c.route===`/org-roots/${ROOT_ID}/vaults`).length,0,'no replacement built');
 });
}

test('a delayed genesis status response cannot reopen the request after an account change',async t=>{
 const h=await loadBrowser(t,{initialGenesisState:'SIGNED',holdStatus:true});
 h.document.querySelector(`[data-viewroot="${ROOT_ID}"]`).click();
 await waitFor(()=>h.modal().querySelector('[data-kasgenesis-request]'),'pending creation');
 h.modal().querySelector('[data-kasgenesis-request]').click();
 await waitFor(()=>h.calls.some(c=>c.route==='/wallet/v7/requests/late-kas'),'status read pending');
 h.changeWallet({address:'kaspa:qnewfixture'});h.releaseStatus();
 await new Promise(resolve=>setImmediate(resolve));await new Promise(resolve=>setImmediate(resolve));
 assert.equal(h.modal().style.display,'none');assert.equal(h.modal().querySelector('#v4-kasreq-submit'),null);
 assert.equal(h.calls.filter(c=>c.route.endsWith('/submit')).length,0);
});

for(const reason of ['navigation','auth-expiry']) test(`pending creation modal closes on ${reason}`,async t=>{
 const h=await loadBrowser(t,{initialGenesisState:'SIGNED'});
 h.document.querySelector(`[data-viewroot="${ROOT_ID}"]`).click();
 await waitFor(()=>h.modal().querySelector('[data-kasgenesis-request]'),'pending creation');
 h.modal().querySelector('[data-kasgenesis-request]').click();
 await waitFor(()=>h.modal().querySelector('#v4-kasreq-submit'),'request view');
 if(reason==='navigation') await h.clickTab('create');else h.changeWallet({auth:'EXPIRED'});
 await new Promise(resolve=>setImmediate(resolve));assert.equal(h.modal().style.display,'none');
 assert.equal(h.calls.filter(c=>c.route.endsWith('/submit')).length,0);
});

/* ==================== RC45 R2-07 / R2-08: delegate period starts in the browser (shared harness) ====================
 * A second browser harness for the delegate-period-start legs: the same index.html and served scripts in jsdom, every
 * HTTP answer an explicit fixture (an unmapped route is recorded and fails the leg), node network-position reads
 * (GET /network/status) answered in sequence, and a wallet double that refuses unless the leg supplies a signer.
 * Network positions are realistic (about 5.45e8) except where a leg uses the production-byte KAS fixtures, whose own
 * delegate starts are 5000 with 1,000-DAA periods (core/explain/test/fixtures/v7-kas-manifests.json). */
const H = require("./helpers.js");
const core = require("../core-bundle.js");
const R2_KAS = "policyvault-0.7-kas";
const R2_V4_SCRIPTS = ["core-bundle.js", "verify-intent.js", "setup-ui.js", "refusal-explain.js", "app-v4.js"].map((name) => ({ name, source: fs.readFileSync(path.join(WEB_DIR, name), "utf8") }));
const R2_READ_FAILED = Object.freeze({ status: 503, body: { error: { code: "NODE_UNAVAILABLE", message: "the node is not synced" } } });
const R2_READ_MALFORMED = Object.freeze({ status: 200, body: { networkId: "testnet-10", virtualDaaScore: "0x207c0000" } });
async function r2Until(pred, ms = 15000) { const t0 = Date.now(); while (!pred() && Date.now() - t0 < ms) await new Promise((r) => setTimeout(r, 5)); }
const r2Pause = (ms) => new Promise((r) => setTimeout(r, ms));
/* Visible text of an element: its text nodes joined with spaces (jsdom's textContent runs adjacent blocks together). */
function r2Visible(el) {
  if (!el) return "";
  const out = [];
  const walk = (n) => { if (n.nodeType === 3) out.push(n.nodeValue); else if (n.nodeType === 1 && !["SCRIPT", "STYLE"].includes(n.tagName)) n.childNodes.forEach(walk); };
  walk(el);
  return out.join(" ").replace(/\s+/g, " ").trim();
}
/* A network position or amount as it may be displayed: its digits, optionally grouped in thousands. */
const r2NumSrc = (n) => `(?<![0-9])${String(n).replace(/\B(?=(\d{3})+(?!\d))/g, "[,\\u00a0\\u202f\\u2009 ]?")}(?![0-9])`;
const r2Num = (n) => new RegExp(r2NumSrc(n));

async function loadR2Browser(t, { networkId = "testnet-10", address, xonly, scripts = SCRIPTS, routes = {}, reads = ["545000000"], roots = [], resolve = {}, signer = null, startView = "orgs" } = {}) {
  const errors = [];
  const vc = new VirtualConsole();
  vc.on("jsdomError", (e) => errors.push(e.message));
  const dom = new JSDOM(HTML, { url: "https://policyvault-fixture.invalid/", runScripts: "outside-only", pretendToBeVisual: true, virtualConsole: vc });
  t.after(async () => { await r2Pause(20); dom.window.close(); });
  const { window } = dom;
  const document = window.document;
  const calls = [], unexpected = [];
  let nRead = 0, signingCalls = 0;
  // A response body is parsed in the page's own realm, as a browser's fetch does (the shared core's plain-object checks are realm-bound).
  const reply = (body, status = 200) => ({ ok: status < 400, status, statusText: String(status), json: async () => window.JSON.parse(JSON.stringify(body)) });
  const confirms = [];
  window.confirm = (message) => { confirms.push(String(message)); return true; };
  window.fetch = async (url, options = {}) => {
    const target = new URL(url, window.location);
    assert.equal(target.origin, window.location.origin, "fixture never reaches an external origin");
    const method = options.method || "GET";
    const route = target.pathname.replace(/^\/api\/v1/, "");
    const body = options.body ? JSON.parse(options.body) : undefined;
    calls.push({ method, route, search: target.search, body });
    const key = `${method} ${route}`;
    if (routes[key]) { const r = await routes[key](body, target); return reply(r.body, r.status ?? 200); }
    if (method === "GET" && route === "/network/status") {
      const a = reads[Math.min(nRead, reads.length - 1)];
      nRead += 1;
      return typeof a === "string" ? reply({ networkId, virtualDaaScore: a }) : reply(a.body, a.status);
    }
    if (method === "GET" && route === "/health") return reply({ networkId });
    if (method === "GET" && route === "/capabilities") return reply(capabilities(networkId, ["policyvault-0.4.1", ...ROOT_VERSIONS]));
    if (method === "GET" && route === "/organizations") return reply({ organizations: [], assignments: {} });
    if (method === "GET" && route === "/org-roots") return reply({ orgRoots: roots });
    const one = /^\/org-roots\/([0-9a-f]{64})$/.exec(route);
    if (method === "GET" && one && roots.some((r) => r.rootCovenantId === one[1])) return reply({ orgRoot: roots.find((r) => r.rootCovenantId === one[1]) });
    if (method === "GET" && route === "/vaults") return reply({ vaults: [] });
    if (method === "GET" && route === "/wallet/v4/requests") return reply({ requests: [] });
    if (method === "GET" && route === "/wallet/v7/vaults") return reply({ vaults: [] });
    if (method === "GET" && route === "/wallet/v7/requests") return reply({ requests: [] });
    if (method === "GET" && route === "/audit") return reply({ events: [] });
    if (method === "POST" && route === "/identity/resolve-address") {
      if (body && Object.prototype.hasOwnProperty.call(resolve, body.address)) return reply({ identity: { xOnlyPubkey: resolve[body.address] } });
      return reply({ error: { code: "ADDRESS_INVALID", message: `unknown fixture address ${body && body.address}` } }, 422);
    }
    unexpected.push(key);
    return reply({ error: { code: "FIXTURE_UNMAPPED", message: `unmapped fixture route ${key}` } }, 404);
  };
  const refuse = async () => { signingCalls += 1; throw new Error("this leg never invokes wallet signing"); };
  const adapter = { signInputs: async (...args) => { if (!signer) return refuse(); signingCalls += 1; return signer(...args); }, signPskt: refuse, signAuthMessage: refuse };
  const snapshot = { connected: true, ready: true, address, xonly, network: networkId, serverNetwork: networkId, auth: "AUTHENTICATED", provider: "fixture", adapter };
  window.PolicyVaultHealthPromise = Promise.resolve({ networkId });
  window.PolicyVaultWalletSession = { active: () => snapshot, subscribe(fn) { fn(snapshot); return () => {}; } };
  for (const { name, source } of scripts) window.eval(`${source}\n//# sourceURL=${name}`);
  const wired = () => { const tab = document.querySelector('.v4-tab[data-view="orgs"]'); return !!(tab && typeof tab.onclick === "function"); };
  await r2Until(wired, 3000);
  if (!wired()) window.dispatchEvent(new window.Event("DOMContentLoaded"));
  await r2Until(wired, 3000);
  assert.ok(wired(), "app navigation initialized");
  const api = window.PolicyVaultV4;
  const modal = () => document.getElementById("v4-modal");
  const notice = () => document.getElementById("v4-notice");
  const clickTab = async (view, selector) => {
    document.querySelector(`.v4-tab[data-view="${view}"]`).click();
    await r2Until(() => api._state.view === view && (!selector || document.querySelector(selector)));
    assert.ok(api._state.view === view && (!selector || document.querySelector(selector)), `${view} view rendered`);
  };
  if (startView) await clickTab(startView, startView === "orgs" ? "#v4-orgroot-create-btn" : null);
  t.after(() => {
    assert.deepEqual(unexpected, [], "every HTTP operation was explicitly stubbed");
    assert.deepEqual(errors, [], "no uncaught DOM errors");
  });
  const isRead = (c) => c.method === "GET" && c.route === "/network/status";
  return {
    window, document, api, calls, modal, notice, clickTab, confirms,
    signingCalls: () => signingCalls,
    reads: () => calls.filter(isRead).length,
    posts: (route) => calls.filter((c) => c.method === "POST" && c.route === route),
    readsSince: (i) => calls.slice(i).filter(isRead).length
  };
}

/* ---------- R2-07: the friendly v0.4.1 create binds the server's single-agent start ---------- */
const R2_CREATE_D = 545000000n;
const R2_CREATE_RESOLVE = Object.freeze({ [H.OWNER_ADDR]: H.OWNER, [H.AGENT_ADDR]: H.AGENT, "kaspatest:r2recipient": H.RECIPIENT, "kaspatest:r2appr1": H.K1, "kaspatest:r2appr2": H.K2, "kaspatest:r2appr3": H.K3 });
/* The server's genesis for the browser's own vault id with the single agent's period started at `anchor`: the shared web
 * helpers' create scenario (true recomputed fee) with the registry tuple, its root and review.technical for that start. */
function r2CreateResponse(body, anchor) {
  const s = H.createScenario();
  const reg = { ...H.AGENT_POLICY_1, periodLengthDaa: "864000", periodStartDaa: String(anchor), recipients: [H.RECIPIENT] };
  const { recipients, ...policy } = reg;
  void recipients;
  const root = core.agentMerkle.buildAgentTreeV4([policy]).root;
  const request = { ...s.request, vaultId: body.vaultId, template: { owner: H.OWNER, vaultId: body.vaultId }, initialState: { ...s.request.initialState, agentRoot: root }, initialRegistry: [reg], review: { ...s.request.review, technical: { periodLengthDaa: "864000", periodStartDaa: String(anchor), approvalM: "2" } } };
  return { status: 201, body: { request } };
}
async function r2CreateBuild(t, { reads, anchor }) {
  const h = await loadR2Browser(t, { address: H.OWNER_ADDR, xonly: H.OWNER, scripts: R2_V4_SCRIPTS, reads, resolve: R2_CREATE_RESOLVE, startView: null, routes: {
    "POST /wallet/v4/create": (body) => r2CreateResponse(body, anchor)
  } });
  Object.assign(h.api._vaultSetup().draft, {
    label: "R2 create", agent: H.AGENT_ADDR, recipients: [{ address: "kaspatest:r2recipient" }], maxPerSpend: "20", budget: "50", period: { preset: "1d", customValue: "", customUnit: "day" },
    approvalThreshold: "15", approvers: [{ address: "kaspatest:r2appr1" }, { address: "kaspatest:r2appr2" }, { address: "kaspatest:r2appr3" }], approvalM: "2", deposit: "500", reserve: "1", maxFee: "0.1", creationMaxFee: "1"
  });
  await h.clickTab("create", "#v4-create-form");
  const before = h.calls.length;
  h.document.getElementById("v4-create-form").dispatchEvent(new h.window.Event("submit", { bubbles: true, cancelable: true }));
  await r2Until(() => /data-verify="/.test(h.modal().innerHTML) || (h.readsSince(before) >= 2 && h.posts("/wallet/v4/create").length === 0 && !h.api._vaultSetup().busy));
  await r2Pause(30);
  return { h, before };
}
const r2CreateReview = (h) => ({ html: h.modal().innerHTML, text: r2Visible(h.modal()), signable: !!h.modal().querySelector("#v4-confirm") && /data-verify="pass"/.test(h.modal().innerHTML) });

test("RC45 R2-07: friendly create — when the network position cannot be read twice, the create build is refused BEFORE posting: no POST /wallet/v4/create; one retry only [RED on b89f0f7]", async (t) => {
  const { h, before } = await r2CreateBuild(t, { reads: [R2_READ_FAILED, R2_READ_MALFORMED], anchor: R2_CREATE_D });
  assert.equal(h.posts("/wallet/v4/create").length, 0, "nothing is built: the create request is never posted");
  assert.equal(h.readsSince(before), 2, "one read and exactly one retry");
});

test("RC45 R2-07: friendly create — a single failed network-position read is retried once and the create build then proceeds [RED on b89f0f7]", async (t) => {
  const { h, before } = await r2CreateBuild(t, { reads: [R2_READ_FAILED, R2_CREATE_D.toString()], anchor: R2_CREATE_D + 40n });
  assert.equal(h.posts("/wallet/v4/create").length, 1, "the create build is posted after the retry");
  const firstPost = h.calls.findIndex((c, i) => i >= before && c.method === "POST" && c.route === "/wallet/v4/create");
  assert.equal(h.calls.slice(before, firstPost).filter((c) => c.method === "GET" && c.route === "/network/status").length, 2, "the failed read and its retry precede the create build");
});

test("RC45 R2-07: friendly create — the server's single-agent start 601 DAA below this browser's pre-build read blocks the review: DO NOT SIGN, no signing action [RED on b89f0f7]", async (t) => {
  const { h } = await r2CreateBuild(t, { reads: [R2_CREATE_D.toString()], anchor: R2_CREATE_D - 601n });
  assert.equal(h.posts("/wallet/v4/create").length, 1, "the create build was posted");
  const r = r2CreateReview(h);
  assert.equal(r.signable, false, `a start below D_before - 600 is never offered for signing; the review shows: ${r.text.slice(0, 600)}`);
  assert.match(r.text, /DO NOT SIGN/);
});

test("RC45 R2-07: friendly create — a single-agent start exactly 600 DAA below this browser's pre-build read is accepted: the review opens VERIFIED with the signing action", async (t) => {
  const { h } = await r2CreateBuild(t, { reads: [R2_CREATE_D.toString()], anchor: R2_CREATE_D - 600n });
  const r = r2CreateReview(h);
  assert.equal(r.signable, true, `the review opens VERIFIED; it shows: ${r.text.slice(0, 600)}`);
});

test("RC45 R2-07: friendly create — a single-agent start 10,000 DAA above this browser's pre-build read has no blocking upper bound: the review opens VERIFIED and carries the advisory that the node is ahead of this browser's read [RED on b89f0f7]", async (t) => {
  const { h } = await r2CreateBuild(t, { reads: [R2_CREATE_D.toString()], anchor: R2_CREATE_D + 10000n });
  const r = r2CreateReview(h);
  assert.equal(r.signable, true, `a later start is never blocked; it shows: ${r.text.slice(0, 600)}`);
  assert.ok(r.text.includes("PolicyVault's node is ahead of this browser's last read"), `the advisory line is shown; it shows: ${r.text.slice(0, 900)}`);
});

test("RC45 R2-07: the add-agent form refuses before building when the network-position read carries no digit-string DAA — no build request is posted (never a start of \"undefined\") [RED on b89f0f7]", async (t) => {
  const NEW_AGENT_ADDR = "kaspatest:r2newagent";
  const h = await loadR2Browser(t, { address: H.OWNER_ADDR, xonly: H.OWNER, scripts: R2_V4_SCRIPTS, startView: null,
    reads: [{ status: 200, body: { networkId: "testnet-10" } }],
    resolve: { [NEW_AGENT_ADDR]: "88".repeat(32), "kaspatest:r2recipient": H.RECIPIENT },
    routes: {
      [`GET /wallet/fuel/${encodeURIComponent(H.OWNER_ADDR)}`]: () => ({ body: { utxos: [{ outpoint: { transactionId: H.FUEL_TXID, index: 5 }, amount: "300000000", scriptPublicKeyHex: H.p2pk(H.OWNER) }] } }),
      "POST /wallet/v4/requests": () => ({ status: 409, body: { error: { code: "RECONCILIATION_REQUIRED", message: "fixture: no build is answered in this leg" } } })
    } });
  h.api._openAgentPolicyForm({ vault: H.baseVault(), mode: "add" });
  await r2Until(() => h.document.getElementById("v4-agent-form"));
  const f = h.document.getElementById("v4-agent-form");
  const set = (name, value) => { const el = f.querySelector(`[name="${name}"]`); assert.ok(el, name); el.value = value; };
  set("agent", NEW_AGENT_ADDR); set("recipient", "kaspatest:r2recipient"); set("maxPerSpend", "10"); set("budget", "30"); set("approvalThreshold", "5"); set("maxFee", "0.1");
  f.dispatchEvent(new h.window.Event("submit", { bubbles: true, cancelable: true }));
  await r2Until(() => h.reads() >= 1);
  await r2Pause(600); // a refusal writes nothing; a build (today) is posted well within this pause
  const builds = h.posts("/wallet/v4/requests");
  assert.equal(builds.filter((c) => c.body && c.body.params && c.body.params.agent && c.body.params.agent.periodStartDaa === "undefined").length, 0, "no build carries a period start of \"undefined\"");
  assert.equal(builds.length, 0, "nothing is built when the network position is not a digit string");
});

/* ---------- R2-08: KAS treasury creation, Change delegate rules and delegate-rule change requests ----------
 * The root of the production-byte KAS fixtures (owners 0x71 / 0x72 / 0x73, 2 of 3) with one KAS treasury (the fixtures'
 * treasury id) whose installed delegates are the shared vectors' realistic rows (one lagging five periods, one fresh).
 * A delegate-rule change request is the fixtures' production-byte ownerSetAgentRoot (manifest, frozen transaction,
 * redeem script) with the shared vectors' stored registry: the browser's gating reads only that registry, the installed
 * rows and the network position; the manifest drives the review and the fee-input signing binding. */
const R2_SET = F.manifests.find((m) => m.name === "vault_owner_set_agent_root");
const R2_VAULT_ID = R2_SET.manifest.vaultOperations[0].vaultId;
const R2_OWNERS = ["71", "72", "73"].map((b) => b.repeat(32));
const R2_FEE_PAYER = "64".repeat(32); // the fixture transaction's fee input key
const R2_REQUEST_ID = "q-r2-08";
const R2_PK_A = "cb144659ef300200912762786a173663150592d78f4408390c47e9956d9a6c31";
const R2_PK_B = "5ab4689e400a4a160cf01cd44730845a54768df8547dcdf073d964f109f18c30";
const R2_PK_N1 = "eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619";
const R2_RECIPIENT = "1195a8046dcbb8e17034bca630065e7a0982e4e36f6f7e5a8d4554e4846fcd99";
const R2_RECIPIENT_ROOT = "125252f3e043c314d06f8989ed81d9d716552e2d1ebf73b35c826c5ee3cc89d4";
const r2Leaf = (agentPk, periodStartDaa, over = {}) => ({ agentPk, maxPerSpend: "500000000", periodBudget: "2000000000", periodLengthDaa: "864000", periodStartDaa: String(periodStartDaa), periodSpent: "0", approvalThreshold: "200000000", agentMaxFeePerTx: "10000000", agentRecipientRoot: R2_RECIPIENT_ROOT, recipients: [R2_RECIPIENT], ...over });
const R2_V_A = r2Leaf(R2_PK_A, 540680000, { periodSpent: "300000000" });
const R2_V_B = r2Leaf(R2_PK_B, 544999000);
const R2_FRESH = Object.freeze({ newRegistry: [R2_V_A, R2_V_B, r2Leaf(R2_PK_N1, 545000000)], D: "545001000" }); // CARRIED lagging A; the new delegate is fresh
const R2_STALE = Object.freeze({ newRegistry: [R2_V_A, R2_V_B, r2Leaf(R2_PK_N1, 545000000)], D: "545858001" }); // the new daily delegate at W + 1
const R2_FAILED_FETCH = Object.freeze({ status: 503, body: { error: { code: "STORE_UNAVAILABLE", message: "the treasury summaries could not be read" } } });
const R2_NO_BUILD = Object.freeze({ status: 422, body: { error: { code: "BUILD_FAILED", message: "fixture: nothing is built in this leg" } } });
const R2_READ_REFUSAL = "could not read the current network position, so it will not build delegate rules";
function r2KasRoot({ vaults = [], pendingRequestId = null } = {}) {
  return { rootCovenantId: ROOT_ID, orgId: R.root.orgId, label: "R2 root", networkId: "testnet-10", ownerSlotsActive: 3, ownerM: "2", frozen: false,
    slots: R2_OWNERS.map((k, i) => ({ slot: i + 1, publicKey: k, address: `kaspatest:r2owner${i + 1}`, label: `Owner ${i + 1}` })),
    template: R.root.template, state: R.rootState.before.state, live: { outpoint: { transactionId: "7c".repeat(32), index: 0 }, blockDaaScore: "1000" }, pendingRequestId, vaults };
}
const r2KasVault = (agents) => ({ vaultId: R2_VAULT_ID, label: "R2 treasury", status: "ACTIVE", orgRootCovenantId: ROOT_ID, contractVersion: R2_KAS, candidateStatus: "CANDIDATE", profile: "kas", generation: 3, recoveryPk: "51".repeat(32), agents, approvers: ["91".repeat(32), "92".repeat(32)], approvalM: "1",
  live: { covenantId: R2_VAULT_ID, outpoint: { transactionId: "0a".repeat(32), index: 0 }, protectedValueKas: "100", feeReserveKas: "5", totalKas: "105", paused: false, policyNonce: "0" } });
function r2RootRequest(newRegistry, over = {}) {
  return { schemaVersion: "policyvault-org-root-request/1", id: R2_REQUEST_ID, rootCovenantId: ROOT_ID, orgId: R.root.orgId, contractVersion: "policyvault-0.7-root", kind: "rootAction", action: "authorize", actionClass: R2_SET.manifest.action.authorityClass,
    vaultOperations: [{ vaultId: R2_VAULT_ID, profile: R2_KAS, action: "ownerSetAgentRoot", params: { agents: newRegistry } }], newRegistry,
    manifest: R2_SET.manifest, redeemScripts: R2_SET.redeemScripts, manifestHash: R2_SET.manifest.manifestHash, signerVisibleDigest: R2_SET.manifest.manifestHash,
    requiredApprovals: R2_SET.manifest.action.requiredApprovals, signaturesPresent: 2,
    slots: R2_OWNERS.map((k, i) => ({ slot: i + 1, publicKey: k, address: `kaspatest:r2owner${i + 1}`, label: `Owner ${i + 1}`, status: i < 2 ? "SIGNED" : "PENDING", signedAt: null, responseEnvelopeHash: null })),
    state: "AUTHORIZED", rootInputIndex: R2_SET.rootInputIndex, txId: R2_SET.txId,
    transaction: { unsignedSafeJson: R2_SET.unsignedSafeJson, frozenCanonicalJson: R2_SET.frozenCanonicalJson, signInputs: R2_SET.signInputs }, ...over };
}
async function r2OpenRootDetail(h) {
  h.document.querySelector(`[data-viewroot="${ROOT_ID}"]`).click();
  await r2Until(() => h.document.getElementById("v4-orgroot-detail-close"));
  assert.ok(h.document.getElementById("v4-orgroot-detail-close"), "the root detail opened");
}
async function r2OpenWizard(h) {
  await r2OpenRootDetail(h);
  const create = h.modal().querySelector("[data-kascreate]");
  assert.ok(create && !create.disabled, "Create KAS treasury is offered");
  create.click();
  await r2Until(() => h.modal().querySelector("[data-kas-wizard]"));
  assert.ok(h.modal().querySelector("[data-kas-wizard]"), "the treasury wizard opened");
}
/* The production-byte genesis rules (deposit 100, reserve 5, approvers 0x91/0x92 one of two, the fixture recovery key, delegate
 * 0x62 with 5 KAS per payment, 20 KAS per period, approvals above 2, fee cap 0.1, recipient 0x63); the period as given. The
 * delegate row's hidden start is left as the wizard drafted it. */
function r2FillWizard(h, { period = { preset: "1d" } } = {}) {
  const f = h.modal().querySelector("[data-kas-wizard]");
  const set = (name, value) => { const el = f.querySelector(`[name="${name}"]`); assert.ok(el, name); el.value = value; };
  set("depositKas", "100"); set("feeReserveKas", "5"); set("recoveryAddress", F.genesis.summary.recoveryPk);
  set("agent-0-agentKey", "62".repeat(32)); set("agent-0-maxPerSpendKas", "5"); set("agent-0-periodBudgetKas", "20"); set("agent-0-period", period.preset);
  if (period.preset === "custom") { set("agent-0-periodValue", period.value); set("agent-0-periodUnit", period.unit); }
  set("agent-0-approvalThresholdKas", "2"); set("agent-0-agentMaxFeePerTxKas", "0.1"); set("agent-0-recipient", "63".repeat(32));
  f.querySelector('[data-rows="approver"]').innerHTML = ["91", "92"].map((k) => `<div class="addr-row"><input name="approverKey" value="${k.repeat(32)}"></div>`).join("");
  const count = f.querySelector('[name="approvalM"]'); count.innerHTML = '<option value="1">1</option>'; count.value = "1";
  return f;
}
const r2Submit = (h, f) => f.dispatchEvent(new h.window.Event("submit", { bubbles: true, cancelable: true }));
const R2_VAULTS_ROUTE = `POST /org-roots/${ROOT_ID}/vaults`;
const R2_REQUESTS_ROUTE = `POST /org-roots/${ROOT_ID}/requests`;
/* The server's genesis summary for the rules above with the delegate's start (and period) as given; its agent root is the
 * root of that delegate tuple; every other field is the production-byte summary. */
function r2GenesisSummary(start, periodLengthDaa) {
  const agent = { ...F.genesis.summary.agents[0], periodStartDaa: String(start), periodLengthDaa: String(periodLengthDaa) };
  const { recipients, ...policy } = agent;
  void recipients;
  return { ...F.genesis.summary, agents: [agent], initialState: { ...F.genesis.summary.initialState, agentRoot: core.agentMerkle.buildAgentTreeV4([policy]).root } };
}
const r2GenesisRequest = (summary, state = "BUILT", requestId = "r2-genesis") => ({ requestId, kind: "kasGenesis", state, contractVersion: R2_KAS, vaultId: summary.vaultId, signerXOnly: R2_OWNERS[0], signerAddress: "kaspatest:r2owner1", summary,
  transaction: { unsignedSafeJson: F.genesis.unsignedSafeJson, signInputs: F.genesis.signInputs, frozenCanonicalJson: F.genesis.frozenCanonicalJson } });
const r2Owner1 = { address: "kaspatest:r2owner1", xonly: R2_OWNERS[0] };

test("RC45 R2-08: treasury wizard Build re-reads the network position — a stale modal-open snapshot is overwritten: the new delegate's start sent is the Build read [RED on b89f0f7]", async (t) => {
  const h = await loadR2Browser(t, { ...r2Owner1, roots: [r2KasRoot()], reads: ["545000000", "545000500"], routes: { [R2_VAULTS_ROUTE]: () => R2_NO_BUILD } });
  await r2OpenWizard(h);
  r2Submit(h, r2FillWizard(h));
  await r2Until(() => h.posts(`/org-roots/${ROOT_ID}/vaults`).length > 0);
  const posts = h.posts(`/org-roots/${ROOT_ID}/vaults`);
  assert.equal(posts.length, 1, "one treasury build");
  assert.equal(posts[0].body.agents[0].periodStartDaa, "545000500", "the new delegate's start is the Build read, not the modal-open snapshot (545000000)");
});

test("RC45 R2-08: treasury wizard Build refuses before posting when the network position cannot be read twice: no treasury build, the refusal says why [RED on b89f0f7]", async (t) => {
  const h = await loadR2Browser(t, { ...r2Owner1, roots: [r2KasRoot()], reads: ["545000000", R2_READ_FAILED, R2_READ_MALFORMED], routes: { [R2_VAULTS_ROUTE]: () => R2_NO_BUILD } });
  await r2OpenWizard(h);
  const before = h.calls.length;
  r2Submit(h, r2FillWizard(h));
  await r2Until(() => h.readsSince(before) >= 2 || h.posts(`/org-roots/${ROOT_ID}/vaults`).length > 0);
  await r2Pause(300);
  assert.equal(h.posts(`/org-roots/${ROOT_ID}/vaults`).length, 0, "nothing is built: the treasury build is never posted");
  assert.equal(h.readsSince(before), 2, "one Build read and exactly one retry");
  assert.ok(r2Visible(h.notice()).includes(R2_READ_REFUSAL), `the refusal names the unread network position; the notice says: ${r2Visible(h.notice())}`);
});

test("RC45 R2-08: a missing modal-open network position (null snapshot) leaves treasury creation and Change delegate rules enabled — Build's read is the only network-position gate", async (t) => {
  const h = await loadR2Browser(t, { ...r2Owner1, roots: [r2KasRoot({ vaults: [R2_VAULT_ID] })], reads: [R2_READ_FAILED], routes: { [`GET /org-roots/${ROOT_ID}/vaults`]: () => ({ body: { vaults: [r2KasVault([R2_V_A, R2_V_B])] } }) } });
  await r2OpenRootDetail(h);
  const create = h.modal().querySelector("[data-kascreate]");
  assert.ok(create && !create.disabled, "Create KAS treasury stays enabled");
  const change = h.modal().querySelector(`[data-rootvaultop="ownerSetAgentRoot"][data-vault="${R2_VAULT_ID}"]`);
  assert.ok(change && !change.disabled, "Change delegate rules stays enabled");
});

test("RC45 R2-08: the treasury wizard opened with a null snapshot walks through the delegates step (Next passes with a filled new delegate, no reload error) and Build sets the delegate's start from its own read before posting [RED on b89f0f7]", async (t) => {
  const h = await loadR2Browser(t, { ...r2Owner1, roots: [r2KasRoot()], reads: [R2_READ_FAILED, "545000500"], routes: { [R2_VAULTS_ROUTE]: () => R2_NO_BUILD } });
  await r2OpenWizard(h);
  const next = async (to) => {
    h.modal().querySelector("section:not([hidden]) [data-setup-next]").click();
    await r2Until(() => h.api._state.kasSetup && h.api._state.kasSetup.step === to);
    assert.equal(h.api._state.kasSetup.step, to, `reached step ${to + 1}; errors: ${r2Visible(h.modal().querySelector("section:not([hidden])"))}`);
  };
  r2FillWizard(h);
  await next(1);
  r2FillWizard(h);
  assert.doesNotMatch(r2Visible(h.modal()), /reload/i, "no reload error for a new delegate drafted without a snapshot");
  await next(2);
  r2FillWizard(h);
  await next(3);
  const f = r2FillWizard(h);
  await next(4);
  r2Submit(h, h.modal().querySelector("[data-kas-wizard]") || f);
  await r2Until(() => h.posts(`/org-roots/${ROOT_ID}/vaults`).length > 0);
  const posts = h.posts(`/org-roots/${ROOT_ID}/vaults`);
  assert.equal(posts.length, 1, "the treasury build is posted");
  assert.equal(posts[0].body.agents[0].periodStartDaa, "545000500", "Build set the new delegate's start from its own read (never \"0\")");
});

/* Change delegate rules: the installed rows are the shared vectors' A (lagging) and B; a new delegate (0x41 key) is added. */
async function r2OpenChangeRules(h) {
  await r2OpenRootDetail(h);
  const change = h.modal().querySelector(`[data-rootvaultop="ownerSetAgentRoot"][data-vault="${R2_VAULT_ID}"]`);
  assert.ok(change && !change.disabled, "Change delegate rules is offered");
  change.click();
  await r2Until(() => h.modal().querySelector("[data-vaultop-form]"));
  h.modal().querySelector("#v4-add-agent").click();
  await r2Until(() => h.modal().querySelector('[name="agent-2-agentKey"]'));
  const f = h.modal().querySelector("[data-vaultop-form]");
  const set = (name, value) => { const el = f.querySelector(`[name="${name}"]`); assert.ok(el, name); el.value = value; };
  set("agent-2-agentKey", R2_PK_N1); set("agent-2-maxPerSpendKas", "5"); set("agent-2-periodBudgetKas", "20"); set("agent-2-approvalThresholdKas", "2"); set("agent-2-agentMaxFeePerTxKas", "0.1"); set("agent-2-recipient", R2_RECIPIENT);
  return f;
}
const r2ChangeRoutes = () => ({ [`GET /org-roots/${ROOT_ID}/vaults`]: () => ({ body: { vaults: [r2KasVault([R2_V_A, R2_V_B])] } }), [R2_REQUESTS_ROUTE]: () => R2_NO_BUILD });

test("RC45 R2-08: Change delegate rules Build re-reads the network position — the new delegate's start sent is the Build read; the installed delegates are sent exactly as installed [RED on b89f0f7]", async (t) => {
  const h = await loadR2Browser(t, { ...r2Owner1, roots: [r2KasRoot({ vaults: [R2_VAULT_ID] })], reads: ["545000000", "545000500"], routes: r2ChangeRoutes() });
  r2Submit(h, await r2OpenChangeRules(h));
  await r2Until(() => h.posts(`/org-roots/${ROOT_ID}/requests`).length > 0);
  const posts = h.posts(`/org-roots/${ROOT_ID}/requests`);
  assert.equal(posts.length, 1, "one root request build");
  const agents = posts[0].body.vaultOperations[0].params.agents;
  assert.deepEqual(agents.slice(0, 2).map((a) => [a.agentPk, a.periodStartDaa, a.periodSpent]), [[R2_PK_A, R2_V_A.periodStartDaa, R2_V_A.periodSpent], [R2_PK_B, R2_V_B.periodStartDaa, R2_V_B.periodSpent]], "installed delegates carried exactly");
  assert.equal(agents[2].periodStartDaa, "545000500", "the new delegate's start is the Build read, not the modal-open snapshot (545000000)");
});

test("RC45 R2-08: Change delegate rules opened with a null snapshot adds a delegate without a start and Build sets it from its own read (never \"0\") [RED on b89f0f7]", async (t) => {
  const h = await loadR2Browser(t, { ...r2Owner1, roots: [r2KasRoot({ vaults: [R2_VAULT_ID] })], reads: [R2_READ_FAILED, "545000500"], routes: r2ChangeRoutes() });
  r2Submit(h, await r2OpenChangeRules(h));
  await r2Until(() => h.posts(`/org-roots/${ROOT_ID}/requests`).length > 0);
  const posts = h.posts(`/org-roots/${ROOT_ID}/requests`);
  assert.equal(posts.length, 1, "the root request build is posted");
  assert.equal(posts[0].body.vaultOperations[0].params.agents[2].periodStartDaa, "545000500");
});

test("RC45 R2-08: Change delegate rules refuses before posting when the Build read fails twice — no root request is built, the refusal says why [RED on b89f0f7]", async (t) => {
  const h = await loadR2Browser(t, { ...r2Owner1, roots: [r2KasRoot({ vaults: [R2_VAULT_ID] })], reads: ["545000000", R2_READ_FAILED], routes: r2ChangeRoutes() });
  const f = await r2OpenChangeRules(h);
  const before = h.calls.length;
  r2Submit(h, f);
  await r2Until(() => h.readsSince(before) >= 2 || h.posts(`/org-roots/${ROOT_ID}/requests`).length > 0);
  await r2Pause(300);
  assert.equal(h.posts(`/org-roots/${ROOT_ID}/requests`).length, 0, "nothing is built");
  assert.equal(h.readsSince(before), 2, "one Build read and exactly one retry");
  assert.ok(r2Visible(h.notice()).includes(R2_READ_REFUSAL), `the refusal names the unread network position; the notice says: ${r2Visible(h.notice())}`);
});

test("RC45 R2-08: treasury genesis cross-check adopts a server delegate start above the Build read: the review opens with Approve in wallet, and the delegates row states what the delegate could pay at once and when its next budget arrives [RED on b89f0f7]", async (t) => {
  const S = 545000040n, L = 864000n;
  const h = await loadR2Browser(t, { ...r2Owner1, roots: [r2KasRoot()], reads: ["545000000"], routes: { [R2_VAULTS_ROUTE]: () => ({ status: 201, body: { request: r2GenesisRequest(r2GenesisSummary(S, L)) } }) } });
  await r2OpenWizard(h);
  r2Submit(h, r2FillWizard(h));
  await r2Until(() => h.modal().querySelector("#v4-kas-review-title"));
  const text = r2Visible(h.modal());
  assert.ok(h.modal().querySelector("#v4-kas-confirm"), `the adopted start matches: Approve in wallet is offered; the review says: ${text.slice(0, 700)}`);
  assert.match(text, new RegExp(`If confirmed now \\(network position ${r2NumSrc(545000000)}\\): can pay out up to 20 KAS at once`), "the immediate amount (one budget: the start is ahead of the network position)");
  assert.match(text, new RegExp(`its next budget of 20 KAS becomes available at network position ${r2NumSrc(S + L)}`), "the next budget arrives at S + L");
});

test("RC45 R2-08: treasury genesis cross-check has no upper bound — a server start 10,000 DAA above the Build read is accepted with the advisory that the node is ahead of this browser's read [RED on b89f0f7]", async (t) => {
  const h = await loadR2Browser(t, { ...r2Owner1, roots: [r2KasRoot()], reads: ["545000000"], routes: { [R2_VAULTS_ROUTE]: () => ({ status: 201, body: { request: r2GenesisRequest(r2GenesisSummary(545010000n, 864000n)) } }) } });
  await r2OpenWizard(h);
  r2Submit(h, r2FillWizard(h));
  await r2Until(() => h.modal().querySelector("#v4-kas-review-title"));
  const text = r2Visible(h.modal());
  assert.ok(h.modal().querySelector("#v4-kas-confirm"), `accepted: Approve in wallet is offered; the review says: ${text.slice(0, 700)}`);
  assert.ok(text.includes("ahead of this browser"), "the advisory line is shown");
});

test("RC45 R2-08: treasury genesis cross-check refuses a server delegate start below the Build read (DO NOT SIGN, no Approve)", async (t) => {
  const h = await loadR2Browser(t, { ...r2Owner1, roots: [r2KasRoot()], reads: ["545000000"], routes: { [R2_VAULTS_ROUTE]: () => ({ status: 201, body: { request: r2GenesisRequest(r2GenesisSummary(544999000n, 864000n)) } }) } });
  await r2OpenWizard(h);
  r2Submit(h, r2FillWizard(h));
  await r2Until(() => h.modal().querySelector("#v4-kas-review-title"));
  assert.equal(h.modal().querySelector("#v4-kas-confirm"), null, "no Approve in wallet");
  assert.match(r2Visible(h.modal()), /DO NOT SIGN/);
});

/* The delegate-rule change request modal (opened from the root detail's pending request). */
async function r2OpenRequest(t, { viewer, newRegistry, D, vaults = "ok", finalize = null, signer = null, reject = null }) {
  let request = r2RootRequest(newRegistry);
  const h = await loadR2Browser(t, { address: viewer.address, xonly: viewer.xonly, roots: [r2KasRoot({ vaults: [R2_VAULT_ID], pendingRequestId: R2_REQUEST_ID })], reads: [D], signer, routes: {
    [`GET /org-roots/${ROOT_ID}/vaults`]: () => (vaults === "ok" ? { body: { vaults: [r2KasVault([R2_V_A, R2_V_B])] } } : Array.isArray(vaults) ? { body: { vaults } } : R2_FAILED_FETCH),
    [`GET /org-roots/${ROOT_ID}/requests/${R2_REQUEST_ID}`]: () => ({ body: { request } }),
    ...(finalize ? { [`POST /org-roots/${ROOT_ID}/requests/${R2_REQUEST_ID}/finalize`]: (body) => finalize(body) } : {}),
    ...(reject ? { [`POST /org-roots/${ROOT_ID}/requests/${R2_REQUEST_ID}/reject`]: (body) => { request = { ...request, state: "REFUSED" }; return reject(body, request); } } : {})
  } });
  await r2OpenRootDetail(h);
  const open = h.modal().querySelector(`[data-vieworequest="${R2_REQUEST_ID}"]`);
  assert.ok(open, "the pending request can be opened");
  open.click();
  await r2Until(() => h.modal().querySelector(`[data-org-root-request="${R2_REQUEST_ID}"]`) && h.modal().querySelector("#v4-orgroot-request-close"));
  await r2Pause(30);
  return h;
}
const r2Slot3 = { address: "kaspatest:r2owner3", xonly: R2_OWNERS[2] };

test("RC45 R2-08: delegate-rule change modal with the treasury summaries failing to load — a fresh request on a treasury with a CARRIED lagging delegate keeps Approve in wallet and Finalize and offers no withdrawal (the web never judges without the installed rows)", async (t) => {
  const h = await openR2(t, "fail");
  assert.ok(h.modal().querySelector("#v4-orgroot-signmyslot"), "Approve in wallet stays");
  assert.ok(h.modal().querySelector(`[data-rootfinalize="${R2_REQUEST_ID}"]`), "Finalize stays");
  assert.equal(h.modal().querySelector("[data-rootreject]"), null, "no withdrawal on the web's own judgement");
});
async function openR2(t, vaults) { return r2OpenRequest(t, { viewer: r2Slot3, newRegistry: R2_FRESH.newRegistry, D: R2_FRESH.D, vaults }); }

test("RC45 R2-08: delegate-rule change modal with the treasury summaries failing to load shows the finalize deadline as unknown — never computed over all leaves [RED on b89f0f7]", async (t) => {
  const h = await openR2(t, "fail");
  const text = r2Visible(h.modal());
  assert.ok(text.includes("The finalize deadline is unknown: this treasury's installed delegate rules could not be loaded."), `the unknown deadline is stated; the modal says: ${text.slice(0, 900)}`);
  assert.doesNotMatch(text, new RegExp(r2NumSrc(540680000 + 858000)), "never the CARRIED lagging delegate's deadline");
});

/* Fail-closed loading of the installed rows: the treasury summaries answer, but not as exactly one v0.7-kas summary for
 * the request's treasury whose rows all carry the nine committed fields canonically. Every misleading row below is the
 * lagging delegate A with one committed field different from the stored registry's A (or with no key at all), so a
 * browser that used such an answer as the installed rows would judge A changed or new and its lagging start stale —
 * hiding Approve in wallet and Finalize on its own judgement. When the answer does not establish the installed key set
 * (several summaries, a foreign profile, rows that are not a list or a row without a key) the deadline is unknown. The
 * request is the fresh vector (the new delegate's window is open at D = 545,001,000). */
const R2_A_SPENT_DIFFERS = { ...R2_V_A, periodSpent: "0" };
const R2_A_START_DIFFERS = { ...R2_V_A, periodStartDaa: "540680001" };
const R2_UNKNOWN_DEADLINE = "The finalize deadline is unknown: this treasury's installed delegate rules could not be loaded.";
const R2_NOT_LOADED_ANSWERS = [
  ["two summaries for the request's treasury (ambiguous)", () => [r2KasVault([R2_A_SPENT_DIFFERS, R2_V_B]), r2KasVault([R2_A_START_DIFFERS, R2_V_B])]],
  ["one summary for the request's treasury whose profile is policyvault-0.7-payment (a foreign profile)", () => [{ ...r2KasVault([R2_A_SPENT_DIFFERS, R2_V_B]), contractVersion: "policyvault-0.7-payment", profile: "payment" }]],
  ["one summary for the request's treasury whose delegate rows are not a list (malformed; the installed key set is unknown)", () => [{ ...r2KasVault([]), agents: { [R2_PK_A]: R2_A_SPENT_DIFFERS, [R2_PK_B]: R2_V_B } }]],
  ["one summary for the request's treasury with a delegate row that carries no key (malformed; the installed key set is unknown)", () => [r2KasVault([(() => { const { agentPk, ...rest } = R2_A_SPENT_DIFFERS; void agentPk; return rest; })(), R2_V_B])]]
];
function r2AssertCollecting(h, label) {
  assert.ok(h.modal().querySelector("#v4-orgroot-signmyslot"), `${label}: Approve in wallet stays`);
  assert.ok(h.modal().querySelector(`[data-rootfinalize="${R2_REQUEST_ID}"]`), `${label}: Finalize stays`);
  assert.equal(h.modal().querySelector("[data-rootreject]"), null, `${label}: no withdrawal on the web's own judgement`);
}
for (const [label, answer] of R2_NOT_LOADED_ANSWERS) {
  test(`RC45 R2-08: delegate-rule change modal whose treasury summaries answer ${label} treats the installed rows as not loaded — Approve in wallet and Finalize stay, no withdrawal is offered on the web's own judgement, and the finalize deadline is unknown (never computed over all leaves) [RED on b89f0f7]`, async (t) => {
    const h = await openR2(t, answer());
    r2AssertCollecting(h, label);
    const text = r2Visible(h.modal());
    assert.ok(text.includes(R2_UNKNOWN_DEADLINE), `${label}: the unknown deadline is stated; the modal says: ${text.slice(0, 900)}`);
    assert.doesNotMatch(text, new RegExp(r2NumSrc(540680000 + 858000)), `${label}: never the lagging delegate's deadline`);
  });
}
/* One v0.7-kas summary for the request's treasury whose rows carry canonical keys but fail the nine-field check: the
 * installed KEY SET is known, the rows are not loaded. The deadline may then be shown only over the leaves whose keys are
 * absent from the installed set (the new delegate: 545,000,000 + 858,000), labelled "for the new delegates" — never for
 * the installed keys (A: 541,538,000; B: 545,857,000). */
const R2_ROWS_FAILING_CHECK = [
  ["a hex spent amount (0x11e1a300, numerically the installed 300000000)", { ...R2_V_A, periodSpent: "0x11e1a300" }],
  ["no recipient root", (() => { const { agentRecipientRoot, ...rest } = R2_V_A; void agentRecipientRoot; return rest; })()],
  ["a period start given as a JSON number", { ...R2_V_A, periodStartDaa: 540680000 }]
];
for (const [label, rowA] of R2_ROWS_FAILING_CHECK) {
  test(`RC45 R2-08: delegate-rule change modal whose single treasury summary has an installed row with ${label} (keys known, nine-field check failed) treats the rows as not loaded — Approve in wallet and Finalize stay, no withdrawal on the web's own judgement — and shows the finalize deadline only for the new delegates, never over the installed keys [RED on b89f0f7]`, async (t) => {
    const h = await openR2(t, [r2KasVault([rowA, R2_V_B])]);
    r2AssertCollecting(h, label);
    const text = r2Visible(h.modal());
    assert.match(text, new RegExp(`finalized before network position ${r2NumSrc(545000000 + 858000)}`, "i"), `${label}: the new delegate's deadline is shown; the modal says: ${text.slice(0, 900)}`);
    assert.ok(text.includes("for the new delegates"), `${label}: the deadline is labelled as covering only the new delegates`);
    assert.doesNotMatch(text, new RegExp(r2NumSrc(540680000 + 858000)), `${label}: never the installed lagging delegate's deadline`);
    assert.doesNotMatch(text, new RegExp(r2NumSrc(544999000 + 858000)), `${label}: never the other installed delegate's deadline`);
  });
}

test("RC45 R2-08: delegate-rule change modal with the installed rows loaded hides Approve in wallet and Finalize and offers the stale withdrawal exactly when the stored registry is stale (the new delegate at W + 1) [RED on b89f0f7]", async (t) => {
  const h = await r2OpenRequest(t, { viewer: r2Slot3, newRegistry: R2_STALE.newRegistry, D: R2_STALE.D });
  assert.equal(h.modal().querySelector("#v4-orgroot-signmyslot"), null, "no Approve in wallet for a request the server will not finalize");
  assert.equal(h.modal().querySelector(`[data-rootfinalize="${R2_REQUEST_ID}"]`), null, "no Finalize");
  assert.ok(h.modal().querySelector(`[data-rootreject="${R2_REQUEST_ID}"]`), "the stale withdrawal is offered");
});

test("RC45 R2-08: the stale withdrawal's confirmation says the delegate budget period start aged out and that withdrawing does not revoke the owner signatures or prevent a broadcast outside PolicyVault, and releases the root's reservation; confirming posts the withdrawal [RED on 8877dee]", async (t) => {
  const h = await r2OpenRequest(t, { viewer: r2Slot3, newRegistry: R2_STALE.newRegistry, D: R2_STALE.D, reject: (body, request) => ({ body: { request } }) });
  const withdraw = h.modal().querySelector(`[data-rootreject="${R2_REQUEST_ID}"]`);
  assert.ok(withdraw, "the stale withdrawal is offered");
  withdraw.click();
  await r2Until(() => h.posts(`/org-roots/${ROOT_ID}/requests/${R2_REQUEST_ID}/reject`).length > 0);
  const said = h.confirms.join(" ");
  assert.ok(said.includes("Its delegate budget period start has aged out, so PolicyVault will not finalize it."), `the confirmation says why; it says: ${said}`);
  assert.ok(said.includes("Withdrawing marks this request withdrawn in PolicyVault and releases the root's reservation. It does not revoke the owner signatures already given: anyone holding them and the fee-input signature can still broadcast this exact transaction outside PolicyVault while the outputs it spends are unspent. Withdrawing broadcasts nothing."), `the confirmation states that withdrawing does not revoke the owner signatures or prevent a broadcast outside PolicyVault; it says: ${said}`);
  assert.equal(h.posts(`/org-roots/${ROOT_ID}/requests/${R2_REQUEST_ID}/reject`).length, 1, "the withdrawal is posted (the server re-decides)");
});

test("RC45 R2-08: delegate-rule change modal with the installed rows loaded and a fresh stored registry keeps Approve in wallet and Finalize and offers no withdrawal", async (t) => {
  const h = await openR2(t, "ok");
  assert.ok(h.modal().querySelector("#v4-orgroot-signmyslot"), "Approve in wallet");
  assert.ok(h.modal().querySelector(`[data-rootfinalize="${R2_REQUEST_ID}"]`), "Finalize");
  assert.equal(h.modal().querySelector("[data-rootreject]"), null, "no withdrawal");
});

test("RC45 R2-08: delegate-rule change modal with the installed rows loaded shows the finalize deadline on the detail and next to Approve in wallet [RED on b89f0f7]", async (t) => {
  const h = await openR2(t, "ok");
  const deadline = new RegExp(`Must be finalized before network position ${r2NumSrc(545000000 + 858000)}`);
  assert.match(r2Visible(h.modal().querySelector(`[data-org-root-request="${R2_REQUEST_ID}"]`)), deadline, "the deadline on the request detail");
  const approve = h.modal().querySelector("#v4-orgroot-signmyslot");
  assert.ok(approve, "Approve in wallet");
  const near = [approve.parentElement, approve.parentElement.previousElementSibling, approve.parentElement.nextElementSibling].map(r2Visible).join(" | ");
  assert.match(near, deadline, `the deadline next to Approve in wallet (its container or the element beside it): ${near.slice(0, 400)}`);
});

test("RC45 R2-08: after the server's finalize answers 409 PERIOD_START_STALE the delegate-rule change modal offers the stale withdrawal and no longer offers Finalize [RED on b89f0f7]", async (t) => {
  const signer = async (u, list) => { const s = JSON.parse(u); for (const e of list) s.inputs[e.index].signatureScript = `41${"cc".repeat(64)}01`; return JSON.stringify(s); };
  const finalize = () => ({ status: 409, body: { error: { code: "PERIOD_START_STALE", message: "manifest-v4: kas-root-finalize: delegate period start 545000000 is older than its window — refusing" } } });
  const h = await r2OpenRequest(t, { viewer: { address: "kaspatest:r2feepayer", xonly: R2_FEE_PAYER }, newRegistry: R2_FRESH.newRegistry, D: R2_FRESH.D, finalize, signer });
  const fin = h.modal().querySelector(`[data-rootfinalize="${R2_REQUEST_ID}"]`);
  assert.ok(fin && !fin.disabled, "the fee payer can finalize (the web judges this request fresh)");
  fin.click();
  await r2Until(() => h.posts(`/org-roots/${ROOT_ID}/requests/${R2_REQUEST_ID}/finalize`).length > 0);
  assert.equal(h.posts(`/org-roots/${ROOT_ID}/requests/${R2_REQUEST_ID}/finalize`).length, 1, `finalize was posted once; the notice says: ${r2Visible(h.notice())}`);
  await r2Until(() => h.modal().querySelector(`[data-rootreject="${R2_REQUEST_ID}"]`), 3000);
  await r2Pause(50);
  assert.ok(h.modal().querySelector(`[data-rootreject="${R2_REQUEST_ID}"]`), "the server's 409 PERIOD_START_STALE makes the withdrawal available");
  assert.equal(h.modal().querySelector(`[data-rootfinalize="${R2_REQUEST_ID}"]`), null, "Finalize is no longer offered");
});

/* A treasury creation signed earlier and resumed through "Open this creation": its delegate (start 542,400,000, daily,
 * 20 KAS, nothing spent) at network position 545,000,000 could pay four periods' budgets (80 KAS) at once; the next
 * budget arrives at 545,856,000. */
async function r2OpenSignedCreation(t, reads) {
  const summary = r2GenesisSummary(542400000n, 864000n);
  const request = r2GenesisRequest(summary, "SIGNED", "r2-signed");
  const h = await loadR2Browser(t, { ...r2Owner1, roots: [r2KasRoot()], reads, routes: {
    "GET /wallet/v7/requests": () => ({ body: { requests: [request] } }),
    "GET /wallet/v7/requests/r2-signed": () => ({ body: { request } })
  } });
  await r2OpenRootDetail(h);
  const open = h.modal().querySelector('[data-kasgenesis-request="r2-signed"]');
  assert.ok(open, "the signed creation is listed");
  open.click();
  await r2Until(() => h.modal().querySelector("#v4-kasreq-submit"));
  await r2Pause(30);
  return h;
}

test("RC45 R2-08: a resumed SIGNED treasury creation shows, per delegate and in warning style, what it could pay at once if submitted now, and that its starts were fixed when it was signed [RED on b89f0f7]", async (t) => {
  const h = await r2OpenSignedCreation(t, ["545000000"]);
  const text = r2Visible(h.modal());
  assert.match(text, new RegExp(`If confirmed now \\(network position ${r2NumSrc(545000000)}\\): can pay out up to 80 KAS at once`), `the immediate amount; the modal says: ${text.slice(0, 900)}`);
  assert.match(text, new RegExp(`its next budget of 20 KAS becomes available at network position ${r2NumSrc(545856000)}`));
  assert.ok(text.includes("includes 3 earlier, unused periods — the covenant lets them be spent at once"));
  assert.ok(text.includes("This creation was signed earlier; its delegate period starts were fixed then. Submitting it now gives each delegate the amount above at once."));
  const warned = [...h.modal().querySelectorAll(".warn, .bad")].some((el) => /can pay out up to 80 KAS at once/.test(r2Visible(el)));
  assert.ok(warned, "the amount is shown in warning style");
  assert.ok(h.modal().querySelector("#v4-kasreq-submit"), "Submit stays the owner's choice");
});

test("RC45 R2-08: a resumed SIGNED treasury creation whose network-position read fails says the immediately spendable amount is unknown; Submit stays available [RED on b89f0f7]", async (t) => {
  const h = await r2OpenSignedCreation(t, [R2_READ_FAILED]);
  const text = r2Visible(h.modal());
  assert.ok(text.includes("the current network position could not be read — the immediately spendable amount is unknown"), `the unknown amount is stated; the modal says: ${text.slice(0, 900)}`);
  assert.ok(h.modal().querySelector("#v4-kasreq-submit"), "Submit stays available");
});
