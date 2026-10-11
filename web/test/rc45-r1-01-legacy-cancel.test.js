"use strict";
/*
 * RC45 R1-01 (web half) — THE LEGACY CONSOLE OFFERS "Cancel request" ONLY FOR
 * v0.2 VAULTS (remediation plan rc45-r1-plan-01 PLAN-R1 revision 2 §2 R1-01
 * "web/app.js legacy console: render Cancel only when v.contractVersion ===
 * 'policyvault-0.2'" and §4 R1-01 "Web"; condition C7; review finding S-01's
 * web entry point). Internal RED-first regression material for the RC45
 * successor candidate; not an audit.
 *
 * The production page loads web/app.js (the legacy console) next to
 * web/app-v4.js. app.js lists EVERY vault of GET /vaults and, for a vault whose
 * operational status is WAITING_FOR_SIGNATURE with a pending request, renders
 * "Cancel request", which posts to the LEGACY route
 * POST /wallet/requests/:id/reject — the route that (S-01) let an agent or an
 * approver-only principal cancel the owner's v0.4 Pause. The server half of
 * R1-01 (sdk/test/rc45-r1-01-legacy-request-routes.test.js) makes the legacy
 * route refuse every non-v0.2 record; this file pins that the console never
 * offers the control for any vault that is not exactly contractVersion
 * "policyvault-0.2" (every other generation, an unknown version, a case or
 * whitespace variant, an empty and a missing version), and still offers it,
 * posting to the legacy route, for a v0.2 vault.
 *
 * RED on dc7552e: operationalHtml renders "Cancel request" for every
 * WAITING_FOR_SIGNATURE vault whatever its version.
 * HOLDS on dc7552e (and must keep holding): the v0.2 vault's Cancel request is
 * offered and posts to /api/v1/wallet/requests/:id/reject.
 *
 * BROWSER layer: the REAL web/app.js evaluated in a vm sandbox with a recording
 * fetch (the harness of web/test/network-banner.test.js and of the review
 * probe review-surface-legacy-app); no server, no network. Synthetic
 * presentation documents only (repeated-byte hex identities).
 */
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const APP_JS = fs.readFileSync(path.join(__dirname, "..", "app.js"), "utf8");
const HEX = (b) => b.repeat(32);
const jsonResponse = (body, ok = true) => ({ ok, status: ok ? 200 : 403, json: async () => body });
const settle = async () => { for (let i = 0; i < 60; i++) await new Promise((r) => setImmediate(r)); };
const REQUEST_ID = (n) => `0f0f0f0f-1111-4222-8333-${String(n).padStart(12, "0")}`;

function makeEnv(vaults) {
  const elements = new Map(), calls = [];
  const element = (id) => {
    if (!elements.has(id)) elements.set(id, { id, innerHTML: "", textContent: "", className: "", value: "", disabled: false, style: {}, dataset: {}, options: [], onclick: null, addEventListener() {}, querySelectorAll: () => [], querySelector: () => null, classList: { toggle() {}, add() {}, remove() {} } });
    return elements.get(id);
  };
  const route = (p) => {
    if (p.endsWith("/health")) return jsonResponse({ ok: true, networkId: "testnet-10", authMode: "disabled" });
    if (p.endsWith("/network/status")) return jsonResponse({ networkId: "testnet-10", isSynced: true, virtualDaaScore: "1" });
    if (p.endsWith("/organizations")) return jsonResponse({ organizations: [], roleLabels: [], assignments: {}, assignmentsVersion: 0 });
    if (p.endsWith("/vaults")) return jsonResponse({ vaults });
    if (p.endsWith("/reject")) return jsonResponse({ request: { state: "WALLET_REJECTED" } });
    if (p.endsWith("/wallet/dev-accounts")) return jsonResponse({}, false);
    return Promise.reject(new Error(`unrouted: ${p}`));
  };
  const sandbox = {
    console,
    document: { getElementById: element, querySelectorAll: () => [], addEventListener() {} },
    localStorage: { getItem: () => null, setItem() {}, removeItem() {} },
    setTimeout: () => 0, clearTimeout() {},
    fetch: (url, init) => { calls.push({ url: String(url), method: (init && init.method) || "GET", body: init && init.body }); return Promise.resolve().then(() => route(String(url), init)); },
    PolicyVaultWallet: require("../wallet.js"),
    PolicyVaultIdentity: {}
  };
  sandbox.window = sandbox; sandbox.globalThis = sandbox;
  vm.createContext(sandbox);
  vm.runInContext(APP_JS, sandbox, { filename: "web/app.js" });
  return { sandbox, element, calls };
}

/* A vault presentation of `contractVersion` waiting for the owner's signature on BUILT request `requestId`. */
function waitingVault(tag, contractVersion, requestId, action = "ownerPause") {
  const v = {
    vaultId: HEX(tag), label: `R1-01 ${tag}`, status: "ACTIVE", owner: HEX("11"), delegate: HEX("21"),
    policy: { maxPerSpendKas: "10", periodBudgetKas: "100", periodLengthDaa: "600" },
    live: { outpoint: { transactionId: HEX("b1"), index: 0 }, covenantId: HEX("c1"), protectedValueKas: "195", periodSpentKas: "5", remainingBudgetKas: "95", delegateActive: true, policyNonce: "0" },
    operational: { status: "WAITING_FOR_SIGNATURE", request: { requestId, action, state: "BUILT", signerRole: "owner" } }
  };
  if (contractVersion !== undefined) v.contractVersion = contractVersion;
  return v;
}
/* The rendered card of one vault (app.js renders <div class="vault" id="vault-<vaultId>"> per vault). */
function cardOf(html, vaultId) {
  const start = html.indexOf(`id="vault-${vaultId}"`);
  assert.ok(start >= 0, `the legacy console rendered the vault ${vaultId.slice(0, 8)}`);
  const next = html.indexOf('<div class="vault" id="vault-', start + 1);
  return html.slice(start, next < 0 ? html.length : next);
}
const offersCancel = (card, requestId) => card.includes(`pvActions.cancelRequest('${requestId}')`) || /Cancel request/.test(card);

/* Every version that is NOT exactly "policyvault-0.2" (key "<missing>": the field is absent). */
const NOT_V02 = ["policyvault-0.4.1", "policyvault-0.4", "policyvault-0.1-beta", "policyvault-0.3", "policyvault-0.5", "policyvault-0.6", "policyvault-0.7-kas", "policyvault-0.7-payment",
  "policyvault-0.7-payment-hd", "policyvault-0.2.1", "POLICYVAULT-0.2", " policyvault-0.2", "policyvault-0.2 ", "", null, undefined];

test("RC45 R1-01 web: the owner's BUILT v0.4.1 Pause (WAITING_FOR_SIGNATURE) renders no 'Cancel request' in the legacy console, so the console never posts it to the legacy reject route [RED on dc7552e]", async () => {
  const id = REQUEST_ID(1), env = makeEnv([waitingVault("e1", "policyvault-0.4.1", id)]);
  await settle();
  const card = cardOf(env.element("vaults").innerHTML, HEX("e1"));
  assert.equal(offersCancel(card, id), false, "app.js offers Cancel request only when contractVersion === 'policyvault-0.2' (plan R1-01, C7)");
  assert.equal(env.calls.filter((c) => c.method === "POST" && c.url.includes("/reject")).length, 0, "nothing was posted to any reject route");
});

test("RC45 R1-01 web: no vault whose contractVersion is not exactly 'policyvault-0.2' (every other generation, an unknown, a case or whitespace variant, an empty, a null and a missing version) is offered 'Cancel request' [RED on dc7552e]", async () => {
  const vaults = NOT_V02.map((ver, i) => waitingVault((0x40 + i).toString(16), ver, REQUEST_ID(100 + i)));
  const env = makeEnv(vaults);
  await settle();
  const html = env.element("vaults").innerHTML, offered = [];
  vaults.forEach((v, i) => { if (offersCancel(cardOf(html, v.vaultId), REQUEST_ID(100 + i))) offered.push(v.contractVersion === undefined ? "<missing>" : JSON.stringify(v.contractVersion)); });
  assert.deepEqual(offered, [], "Cancel request is rendered only for contractVersion === 'policyvault-0.2' (plan R1-01, C7)");
});

test("RC45 R1-01 web: in a mixed list the v0.2 vault keeps its 'Cancel request' and the v0.4.1 vault next to it has none [RED on dc7552e]", async () => {
  const v2 = waitingVault("a2", "policyvault-0.2", REQUEST_ID(2)), v4 = waitingVault("a4", "policyvault-0.4.1", REQUEST_ID(4), "ownerRecover");
  const env = makeEnv([v2, v4]);
  await settle();
  const html = env.element("vaults").innerHTML;
  assert.equal(offersCancel(cardOf(html, v4.vaultId), REQUEST_ID(4)), false, "no Cancel request on the v0.4.1 vault's Close & recover");
  assert.equal(offersCancel(cardOf(html, v2.vaultId), REQUEST_ID(2)), true, "the v0.2 vault keeps its Cancel request");
});

test("RC45 R1-01 web: a v0.2 vault waiting for a signature is still offered 'Cancel request', and it posts to the legacy route /api/v1/wallet/requests/:id/reject", async () => {
  const id = REQUEST_ID(3), env = makeEnv([waitingVault("a3", "policyvault-0.2", id)]);
  await settle();
  const card = cardOf(env.element("vaults").innerHTML, HEX("a3"));
  assert.ok(card.includes(`pvActions.cancelRequest('${id}')`), "the v0.2 vault's Cancel request is rendered");
  await env.sandbox.window.pvActions.cancelRequest(id);
  const post = env.calls.find((c) => c.method === "POST" && c.url.includes("/reject"));
  assert.ok(post, "Cancel request posted");
  assert.equal(post.url, `/api/v1/wallet/requests/${id}/reject`);
});
