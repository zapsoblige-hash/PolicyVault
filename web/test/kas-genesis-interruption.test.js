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
   'agent-0-agentKey':'62'.repeat(32),'agent-0-maxPerSpendKas':'5','agent-0-periodBudgetKas':'20','agent-0-periodLengthDaa':'1000','agent-0-periodStartDaa':'5000','agent-0-approvalThresholdKas':'2','agent-0-agentMaxFeePerTxKas':'0.1','agent-0-recipients':'63'.repeat(32)};
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
