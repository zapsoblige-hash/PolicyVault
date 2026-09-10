"use strict";

/*
 * RC30 owner-observed root-creation refusal: exercise the actual Organizations
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
const SCRIPTS = ["core-bundle.js", "setup-ui.js", "org-root-ui.js", "refusal-explain.js", "app-v4.js"]
  .map((name) => ({ name, source: fs.readFileSync(path.join(WEB_DIR, name), "utf8") }));
const ROOT_ID = "7a".repeat(32);
const LATE_ROOT_ID = "7e".repeat(32); // a root whose genesis build completes AFTER the owner cancelled its setup
const LATE_REQUEST_ID = "late-genesis-request";
const OWNER_KEY = "71".repeat(32); // public synthetic fixture identity, no private key
const ROOT_VERSIONS = ["policyvault-0.7-root", "policyvault-0.7-payment"];
const GENERATION_REFUSAL = "wallet-requests-v7: mainnet: covenant generation \"policyvault-0.7-payment\" is NOT owner-authorized for mainnet creation/mutation — refusing (fail closed). Only the v0.4.1 production generation is mainnet-authorized.";

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

async function loadBrowser(t, { networkId = "mainnet", discovery, discoveryStatus = 200, holdRootBuild = false } = {}) {
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
  const root = rootFixture(networkId, address);
  let cap = discovery === undefined
    ? capabilities(networkId, networkId === "mainnet" ? ["policyvault-0.4.1"] : ["policyvault-0.4.1", ...ROOT_VERSIONS])
    : discovery;
  const reply = (body, status = 200) => ({ ok: status < 400, status, json: async () => body });
  let releaseRootBuild;
  const rootRefusal = () => reply({ error: { code: "BUILD_FAILED", message: GENERATION_REFUSAL } }, 422);
  // A synthetic genesis summary shaped like the server's (kind, slots, initial
  // state, template, fee). Cross-check agreement is irrelevant to the late-
  // success assertions: a review must never open for a cancelled setup at all.
  const rootSuccess = (body) => reply({ request: { id: LATE_REQUEST_ID, rootCovenantId: LATE_ROOT_ID, state: "BUILT", manifest: {
    kind: "genesis-summary", contractVersion: "policyvault-0.7-root", networkId, covenantId: LATE_ROOT_ID,
    slots: (body.owners || []).map((o) => ({ slot: o.slot, publicKey: OWNER_KEY, address: o.address || address, label: o.label || "" })),
    initialState: { ownerM: String(body.ownerM), emergencyK: String(body.emergencyK), recoveryM: String(body.recoveryM), frozen: "0", rootNonce: "0" },
    template: { recoveryDelayDaa: String(body.recoveryDelayDaa), successorPk: "00".repeat(32), successionEnabled: false, successionDelayDaa: String(body.successionDelayDaa), rootMaxFeePerTx: "0" },
    rootValueKas: String(body.rootValueKas), txId: "7f".repeat(32), requiredFeeSompi: "208300"
  } } }, 201);
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
    if (method === "GET" && route === "/vaults") return reply({ vaults: [] });
    if (method === "GET" && route === "/wallet/v4/requests") return reply({ requests: [] });
    if (method === "GET" && route === "/audit") return reply({ events: [{ kind: "chain", action: "rootGenesis", vaultId: ROOT_ID, txId: "7c".repeat(32), detail: "Existing root creation history", at: "2026-09-01T00:00:00.000Z" }] });
    if (method === "POST" && route === "/identity/resolve-address") return reply({ identity: { xOnlyPubkey: OWNER_KEY } });
    if (method === "POST" && route === "/organizations") return reply({ organization: { orgId: "fixture-hosted", name: body.name } }, 201);
    if (method === "POST" && route === "/org-roots") {
      if (holdRootBuild) return new Promise((resolve) => { releaseRootBuild = () => resolve(holdRootBuild === "success" ? rootSuccess(body) : rootRefusal()); });
      return rootRefusal();
    }
    if (method === "POST" && route === `/org-roots/${LATE_ROOT_ID}/requests/${LATE_REQUEST_ID}/reject`) return reply({ request: { id: LATE_REQUEST_ID, state: "WALLET_REJECTED" } });
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
  window.PolicyVaultWalletSession = { active: () => snapshot, subscribe(fn) { fn(snapshot); return () => {}; } };
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
    assert.equal(calls.filter((c) => /\/(submit|signature|genesis-submit|finalize)$/.test(c.route)).length, 0, "no financial submission operation");
  });
  return {
    window, document, api, calls, modal, notice, clickTab,
    setDiscovery(value) { cap = value; },
    releaseRootBuild() { assert.ok(releaseRootBuild, "a root build response is pending"); releaseRootBuild(); }
  };
}

async function openWizard(h) {
  const button = h.document.getElementById("v4-orgroot-create-btn");
  assert.equal(button.disabled, false, "advertised root creation is available");
  button.click();
  await waitFor(() => h.modal().querySelector("[data-orgroot-wizard]"), "root setup opens");
}

async function reachRootReview(h) {
  await openWizard(h);
  for (let step = 0; step < 4; step++) {
    const next = h.modal().querySelector("section:not([hidden]) [data-setup-next]");
    assert.ok(next, `Continue available at root step ${step + 1}`);
    next.click();
    await waitFor(() => h.api._state.rootSetup.step === step + 1, `root step ${step + 2} reached`);
  }
  assert.match(h.modal().querySelector("section:not([hidden])").textContent, /Review governance/);
}

async function refuseRootBuild(h) {
  await reachRootReview(h);
  h.modal().querySelector("section:not([hidden]) [data-setup-build]").click();
  await waitFor(() => h.calls.some((c) => c.method === "POST" && c.route === "/org-roots") && !h.api._state.rootSetup.busy, "server root refusal handled");
}

test("mainnet root creation is unavailable before setup; existing roots, hosted organizations and v4 creation remain usable", async (t) => {
  const h = await loadBrowser(t);
  const create = h.document.getElementById("v4-orgroot-create-btn");
  assert.equal(create.disabled, true, "unauthorized mainnet root setup is disabled upfront");
  assert.match(create.closest('[data-org-root-section="on-chain"]').textContent, /mainnet/i);
  assert.match(create.closest('[data-org-root-section="on-chain"]').textContent, /unavailable|not available|not authorized|not enabled/i);
  create.click();
  assert.notEqual(h.modal().style.display, "flex", "disabled root control cannot open setup");

  h.document.querySelector(`[data-viewroot="${ROOT_ID}"]`).click();
  await waitFor(() => h.modal().querySelector(`[data-org-root-detail="${ROOT_ID}"]`), "existing root is still readable");
  assert.match(h.modal().textContent, /Existing root history/);
  assert.ok(h.modal().textContent.includes(ROOT_ID), "existing root identity retained in details");
  h.document.getElementById("v4-orgroot-detail-close").click();
  await waitFor(() => h.modal().style.display === "none", "root detail closes");

  h.document.getElementById("v4-org-new-name").value = "Acceptance grouping";
  h.document.getElementById("v4-org-create-btn").click();
  await waitFor(() => h.calls.some((c) => c.method === "POST" && c.route === "/organizations"), "hosted organization remains creatable");
  assert.equal(h.calls.find((c) => c.method === "POST" && c.route === "/organizations").body.name, "Acceptance grouping");

  await h.clickTab("activity", ".evt");
  assert.match(h.document.getElementById("v4-root").textContent, /Existing root creation history/);
  await h.clickTab("create", "#v4-create-form");
  assert.match(h.document.getElementById("v4-create-form").textContent, /Basics and ownership/);
  assert.equal(h.calls.filter((c) => c.method === "POST" && c.route === "/org-roots").length, 0);
});

for (const [name, overrides] of [
  ["failed capability discovery", { discovery: { error: { code: "UNAVAILABLE", message: "Fixture discovery unavailable" } }, discoveryStatus: 503 }],
  ["missing creatable versions", { discovery: { networkId: "mainnet" } }],
  ["mismatched capability network", { discovery: capabilities("testnet-10", ROOT_VERSIONS) }],
  ["only the root version advertised", { discovery: capabilities("mainnet", ["policyvault-0.7-root"]) }],
  ["unknown operational network", { networkId: "fixture-other-network", discovery: capabilities("fixture-other-network", ROOT_VERSIONS) }]
]) {
  test(`${name} keeps new root creation unavailable without hiding existing roots or hosted metadata`, async (t) => {
    const h = await loadBrowser(t, overrides);
    assert.equal(h.document.getElementById("v4-orgroot-create-btn").disabled, true);
    assert.ok(h.document.querySelector(`[data-viewroot="${ROOT_ID}"]`));
    assert.equal(h.document.getElementById("v4-org-create-btn").disabled, false);
    assert.equal(h.calls.filter((c) => c.method === "POST").length, 0);
  });
}

test("supported testnet discovery keeps all five root wizard steps and Cancel usable", async (t) => {
  const h = await loadBrowser(t, { networkId: "testnet-10" });
  await reachRootReview(h);
  h.modal().querySelector("section:not([hidden]) [data-setup-cancel]").click();
  await waitFor(() => h.modal().style.display === "none", "Cancel closes testnet setup");
  assert.equal(h.api._state.rootSetup, null);
  assert.equal(h.calls.filter((c) => c.method === "POST" && c.route === "/org-roots").length, 0, "form review did not create a request");
});

test("a server refusal after stale discovery is visible inside setup, can be cancelled, and does not follow the owner into Create Vault", async (t) => {
  const h = await loadBrowser(t, { discovery: capabilities("mainnet", ROOT_VERSIONS) });
  await refuseRootBuild(h);
  const inline = h.modal().querySelector('[role="alert"]');
  assert.ok(inline, "root refusal is announced inside the visible modal");
  assert.match(inline.textContent, /policyvault-0\.7-payment/);
  assert.match(inline.textContent, /NOT owner-authorized/);
  assert.equal(h.modal().style.display, "flex");
  const cancel = h.modal().querySelector("section:not([hidden]) [data-setup-cancel]");
  assert.equal(cancel.disabled, false);
  cancel.click();
  await waitFor(() => h.modal().style.display === "none", "refused setup can be dismissed");
  await h.clickTab("create", "#v4-create-form");
  assert.ok(h.notice().style.display === "none" || !/policyvault-0\.7-payment/.test(h.notice().textContent), "root refusal is scoped to Organizations");
  assert.equal(h.calls.filter((c) => c.method === "POST" && c.route === "/org-roots").length, 1, "no automatic root retry");
});

test("clearing a root refusal must preserve a newer unrelated pending or uncertain transaction warning", async (t) => {
  const h = await loadBrowser(t, { discovery: capabilities("mainnet", ROOT_VERSIONS) });
  await refuseRootBuild(h);
  h.modal().querySelector("section:not([hidden]) [data-setup-cancel]").click();
  await waitFor(() => h.modal().style.display === "none", "refused setup closed");
  // Exercise the real notice writer with a separate request's durable-state
  // refusal. The fixture refuses BUILD; no wallet or transaction is involved.
  await h.api._runFlow("fixture-v4-vault", "agentSpend", {}, "Sign spend");
  const warning = h.notice().textContent;
  assert.match(warning, /submission outcome uncertain/);
  assert.match(warning, /do not sign again/);
  await h.clickTab("create", "#v4-create-form");
  assert.notEqual(h.notice().style.display, "none");
  assert.equal(h.notice().textContent, warning, "navigation preserves the newer unresolved-payment warning");
});

test("a capability refresh while setup is open refuses before build and explains the change inside the modal", async (t) => {
  const h = await loadBrowser(t, { networkId: "testnet-10" });
  await reachRootReview(h);
  h.setDiscovery(capabilities("testnet-10", ["policyvault-0.4.1"]));
  await h.api.render();
  await waitFor(() => h.document.getElementById("v4-orgroot-create-btn").disabled, "refreshed discovery disables new root creation");
  h.modal().querySelector("section:not([hidden]) [data-setup-build]").click();
  await waitFor(() => h.modal().querySelector('[role="alert"]'), "changed availability is explained inside setup");
  assert.match(h.modal().querySelector('[role="alert"]').textContent, /not available|unavailable|not enabled/i);
  assert.equal(h.calls.filter((c) => c.method === "POST" && c.route === "/org-roots").length, 0);
  h.modal().querySelector("section:not([hidden]) [data-setup-cancel]").click();
  await waitFor(() => h.modal().style.display === "none", "Cancel still dismisses setup after availability changed");
});

for (const newerWarning of [false, true]) {
  test(`a delayed root refusal after Cancel and Create Vault ${newerWarning ? "preserves a newer uncertain-payment warning" : "cannot contaminate the new view"}`, async (t) => {
    const h = await loadBrowser(t, { discovery: capabilities("mainnet", ROOT_VERSIONS), holdRootBuild: true });
    await reachRootReview(h);
    h.modal().querySelector("section:not([hidden]) [data-setup-build]").click();
    await waitFor(() => h.calls.some((c) => c.method === "POST" && c.route === "/org-roots"), "root build awaits its server response");
    h.modal().querySelector("section:not([hidden]) [data-setup-cancel]").click();
    await waitFor(() => h.modal().style.display === "none", "Cancel dismisses an in-flight build form");
    assert.equal(h.notice().style.display, "none", "Cancel clears the wizard's own 'Building…' progress notice");
    await h.clickTab("create", "#v4-create-form");
    if (newerWarning) await h.api._runFlow("fixture-v4-vault", "agentSpend", {}, "Sign spend");
    const before = h.notice().textContent;
    h.releaseRootBuild();
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(h.api._state.view, "create");
    assert.equal(h.api._state.rootSetup, null);
    assert.equal(h.modal().style.display, "none");
    assert.ok(h.document.getElementById("v4-create-form"));
    assert.doesNotMatch(h.notice().textContent, /policyvault-0\.7-payment/);
    if (newerWarning) {
      assert.match(h.notice().textContent, /submission outcome uncertain/);
      assert.equal(h.notice().textContent, before, "late failure cannot overwrite a newer warning");
    } else {
      assert.equal(h.notice().style.display, "none", "a dropped late refusal leaves no wizard notice behind in Create Vault");
    }
  });
}

test("a delayed root build SUCCESS after Cancel is withdrawn and never opens a review over the new view", async (t) => {
  const h = await loadBrowser(t, { networkId: "testnet-10", holdRootBuild: "success" });
  await reachRootReview(h);
  h.modal().querySelector("section:not([hidden]) [data-setup-build]").click();
  await waitFor(() => h.calls.some((c) => c.method === "POST" && c.route === "/org-roots"), "root build awaits its server response");
  h.modal().querySelector("section:not([hidden]) [data-setup-cancel]").click();
  await waitFor(() => h.modal().style.display === "none", "Cancel dismisses an in-flight build form");
  assert.equal(h.notice().style.display, "none", "Cancel clears the wizard's own 'Building…' progress notice");
  await h.clickTab("create", "#v4-create-form");
  h.releaseRootBuild();
  const withdrawn = () => h.calls.find((c) => c.method === "POST" && c.route === `/org-roots/${LATE_ROOT_ID}/requests/${LATE_REQUEST_ID}/reject`);
  await waitFor(() => !!withdrawn() || h.modal().style.display === "flex", "late build outcome processed");
  assert.equal(h.modal().style.display, "none", "no governance review opens over Create Vault for a setup the owner cancelled");
  assert.equal(h.modal().querySelector("#v4-orgroot-review-title"), null, "no governance review is rendered (the hidden modal keeps only the cancelled wizard markup)");
  assert.equal(h.api._state.view, "create");
  assert.equal(h.api._state.rootSetup, null, "no setup is resurrected for an abandoned build");
  assert.ok(withdrawn(), "the late-built request is withdrawn best-effort, exactly as Cancel withdraws a built request");
  assert.equal(withdrawn().body.reason, "withdrawn before signing");
  assert.equal(h.notice().style.display, "none");
  assert.ok(h.document.getElementById("v4-create-form"));
});
