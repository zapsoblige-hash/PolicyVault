"use strict";

/*
 * RC45 T8 — WEB-1 / WEB-2 / WEB-3 AND THE v0.4-ONLY OUTCOME LINES (fix item F8
 * RC45-L5-API-WEB; plan rc45-simplified-plan-r2 §3 concepts 4-6, §5 WEB-1
 * (a closed Verify status map kept in refusal-explain.js; unknown -> "bad"
 * with its token; the quoted outcome and refusal lines), WEB-2 (the Verify
 * control on an owner's TERMINATED_UNKNOWN card), WEB-3 (the recover-evidence
 * paste), CR2-M5 (the v0.4 lines are appended only for v0.4 transitions),
 * §8 T8 "every status mapped; one control on TERMINATED_UNKNOWN cards; WEB-3
 * post; a v0.7-kas SIGNED and SUBMITTED outcome, a v4 genesis
 * PREFLIGHT_VERIFIED outcome and a genesis CLAIM_CONFLICT refusal render
 * without the v0.4 lines"). Internal RED-first regression material for the
 * RC45 candidate; not an audit.
 *
 * RED on C1 e62b1973: the Verify handler renders every status as
 * `Verify state: <STATUS>` in the "good" class (app-v4.js :3720) — a
 * CLAIM_PENDING, REQUEST_RECOVERY_REQUIRED, UNKNOWN or CHAIN_CONTRADICTION
 * answer looks like success, ADVANCED names nothing, settled[] is never
 * listed; a TERMINATED_UNKNOWN card has no Verify control; nothing offers the
 * owner's recover paste; v0.4 transition outcomes carry no closure / armed-
 * request / "Pause and Close & recover stay available" line. GREEN after F8.
 * HOLDS on C1 (and must keep holding): CONSISTENT and TERMINAL render good;
 * a RECOVERED card and a non-owner's TERMINATED_UNKNOWN card offer no Verify;
 * the shared OUTCOMES / REFUSALS entries stay unchanged and every non-v0.4
 * rendering (v0.7-kas SIGNED / SUBMITTED, v4 genesis PREFLIGHT_VERIFIED,
 * genesis CLAIM_CONFLICT) carries none of the v0.4 lines.
 *
 * Readings chosen where the plan leaves a detail open (fail closed):
 *   - the level ("good" / "warn" / "bad") is the class of the status region
 *     #v4-notice (note(summary, cls), the established convention);
 *   - quoted plan sentences are pinned verbatim, case-insensitively and with
 *     whitespace normalised; the "N s" of CLAIM_PENDING is not pinned;
 *   - a listed settled[] / pending[] entry is identified by its requestId or
 *     txId (the first 8 characters: app-v4.js short() keeps them); ADVANCED
 *     also shows the settled entry's state token;
 *   - WEB-3's control is the one textarea that appears with the UNKNOWN answer,
 *     posted by the form that contains it or else by its nearest container's
 *     non-cancel button; the post is POST /vaults/:id/reconcile with exactly
 *     { outOfAppTransaction: <pasted text> };
 *   - CR2-M5 positive lines are driven through the v4 transition caller
 *     (completeRequestFlow via the exposed _runFlow); negatives through the
 *     shared module entries and the genesis create-view reconcile path.
 *
 * Layer: BROWSER (jsdom; the real web/refusal-explain.js and web/app-v4.js
 * with web/core-bundle.js and web/setup-ui.js; only the wallet session and the
 * HTTP responses are doubles — server-document-shaped fixtures from
 * web/test/helpers.js). Every request is intercepted and recorded; no external
 * resource loads; signing is a fixture that returns a fixed string (no key).
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { JSDOM, VirtualConsole } = require("../../sdk/node_modules/jsdom");
const { baseVault, VAULT_ID, OWNER, AGENT, OWNER_ADDR } = require("./helpers.js");

const WEB_DIR = path.join(__dirname, "..");
const HTML = fs.readFileSync(path.join(WEB_DIR, "index.html"), "utf8");
const SCRIPTS = ["core-bundle.js", "setup-ui.js", "refusal-explain.js", "app-v4.js"].map((name) => ({ name, source: fs.readFileSync(path.join(WEB_DIR, name), "utf8") }));
const RX = require("../refusal-explain.js");
const AGENT_ADDR_FIXTURE = "kaspatest:agent0000000000000000000000000000000000000000000000000000000000";
const HEX = (s) => s.repeat(32);
const TX_W = HEX("a1"), TX_L = HEX("a2"), TX_C = HEX("a3");
const REQ_W = "0f8a0001-0000-4000-8000-000000000001", REQ_L = "0f8a0002-0000-4000-8000-000000000002", REQ_P = "0f8a0003-0000-4000-8000-000000000003", REQ_R = "0f8a0004-0000-4000-8000-000000000004";
const PASTE = '{"version":0,"inputs":[{"transactionId":"' + HEX("b1") + '","index":0}],"outputs":[],"fixture":"RC45 F8 owner recover paste"}';

/* The v0.4-family lines of plan r2 §5 WEB-1 (CR-H2, CR-M7, CR2-L13, CR2-M5). */
const V04_LINES = Object.freeze({
  closure: "If this was Close & recover, do not move the recovered funds until Verify state shows RECOVERED.",
  armed: "This signed request can still be broadcast and blocks other actions on this vault until it completes.",
  armedExit: "Pause and Close & recover stay available; after a Pause, Verify at depth marks it superseded, then Unpause through a governance proposal (three owner signatures, plus any delay or quorum).",
  available: "Pause and Close & recover stay available"
});
const norm = (s) => String(s ?? "").replace(/\s+/g, " ").trim().toLowerCase();
const has = (text, phrase) => norm(text).includes(norm(phrase));

async function ticks(n = 30) { for (let i = 0; i < n; i++) await new Promise((resolve) => setImmediate(resolve)); }
async function waitFor(predicate, message, limit = 400) {
  for (let i = 0; i < limit; i++) { if (predicate()) return; await new Promise((resolve) => setImmediate(resolve)); }
  assert.ok(predicate(), message);
}

/*
 * One browser: `vaults` is the GET /vaults document; `reconcile(vaultId, body, n)` answers POST /vaults/:id/reconcile
 * ({status, body}); `routes` maps "METHOD /path" (pathname without /api/v1, no query) to a handler(body, target).
 */
async function loadBrowser(t, { vaults, reconcile, routes = {}, xonly = OWNER, address = OWNER_ADDR, unresolved = [] } = {}) {
  const errors = [];
  const vc = new VirtualConsole();
  vc.on("jsdomError", (e) => errors.push(e.message));
  const dom = new JSDOM(HTML, { url: "https://policyvault-fixture.invalid/", runScripts: "outside-only", pretendToBeVisual: true, virtualConsole: vc });
  t.after(async () => { await ticks(5); dom.window.close(); });
  const { window } = dom;
  const document = window.document;
  const calls = [], unexpected = [];
  let reconcileCount = 0;
  const reply = (body, status = 200) => ({ ok: status < 400, status, statusText: String(status), json: async () => body });
  const suspension = (vaultId) => ({ schema: "policyvault-agent-suspensions/v1", vaultId, version: 1, allAgents: false, agents: [], updatedAt: "2026-09-29T00:00:00.000Z", updatedBy: { type: "wallet", identityId: null }, notice: "hosted coordination control; not a covenant control" });
  window.confirm = () => true;
  window.prompt = () => null;
  window.fetch = async (url, options = {}) => {
    const target = new URL(url, window.location);
    assert.equal(target.origin, window.location.origin, "the fixture never reaches an external origin");
    const method = options.method || "GET";
    const route = target.pathname.replace(/^\/api\/v1/, "");
    const body = options.body ? JSON.parse(options.body) : undefined;
    calls.push({ method, route, search: target.search, body });
    const key = `${method} ${route}`;
    if (routes[key]) { const r = await routes[key](body, target); return reply(r.body, r.status ?? 200); }
    const m = /^\/vaults\/([0-9a-f]{64})\/reconcile$/.exec(route);
    if (method === "POST" && m && reconcile) { reconcileCount += 1; const r = await reconcile(m[1], body, reconcileCount); return reply(r.body, r.status ?? 200); }
    if (method === "GET" && route === "/health") return reply({ networkId: "testnet-10" });
    if (method === "GET" && route === "/network/status") return reply({ networkId: "testnet-10", virtualDaaScore: "90000000" });
    if (method === "GET" && route === "/capabilities") return reply({ networkId: "testnet-10", contract: { creatableCovenantVersions: ["policyvault-0.4.1"] } });
    if (method === "GET" && route === "/vaults") return reply({ vaults: vaults ?? [] });
    if (method === "GET" && route === "/organizations") return reply({ organizations: [], assignments: {}, assignmentsVersion: null });
    if (method === "GET" && route === "/wallet/v4/requests") return reply({ requests: target.searchParams.get("unresolved") ? unresolved : [] });
    const s = /^\/vaults\/([0-9a-f]{64})\/agent-suspensions$/.exec(route);
    if (method === "GET" && s) return reply({ suspensions: suspension(s[1]) });
    if (method === "GET" && route === "/org-roots") return reply({ orgRoots: [] });
    if (method === "GET" && route === "/wallet/v7/vaults") return reply({ vaults: [] });
    if (method === "GET" && route === "/wallet/v7/requests") return reply({ requests: [] });
    unexpected.push(key);
    return reply({ error: { code: "FIXTURE_UNMAPPED", message: `unmapped fixture route ${key}` } }, 404);
  };
  let signingCalls = 0;
  const snapshot = {
    connected: true, ready: true, address, xonly, network: "testnet-10", serverNetwork: "testnet-10", auth: "AUTHENTICATED", provider: "fixture",
    adapter: { signInputs: async () => { signingCalls += 1; return '{"fixture":"TEST signed Safe JSON (no key material)"}'; } }
  };
  window.PolicyVaultHealthPromise = Promise.resolve({ networkId: "testnet-10" });
  window.PolicyVaultWalletSession = { active: () => snapshot, subscribe(fn) { fn(snapshot); return () => {}; } };
  for (const { name, source } of SCRIPTS) window.eval(`${source}\n//# sourceURL=${name}`);
  const tabsWired = () => { const tab = document.querySelector('.v4-tab[data-view="vaults"]') || document.querySelector(".v4-tab"); return tab && typeof tab.onclick === "function"; };
  for (let i = 0; i < 20 && !tabsWired(); i++) await ticks(1);
  if (!tabsWired()) window.dispatchEvent(new window.Event("DOMContentLoaded"));
  await waitFor(tabsWired, "app navigation initialized");
  const api = window.PolicyVaultV4;
  const notice = () => document.getElementById("v4-notice");
  const h = {
    window, document, api, calls, unexpected, notice, errors,
    signingCalls: () => signingCalls,
    posts: (routeRe) => calls.filter((c) => c.method === "POST" && routeRe.test(c.route)),
    async showAll() {
      await waitFor(() => document.querySelector('[data-status="All"]'), "the vaults view rendered its filter bar");
      document.querySelector('[data-status="All"]').click();
      await ticks();
    },
    card: (vaultId) => document.querySelector(`[data-vault="${vaultId}"]`),
    async clickVerify(vaultId) {
      await waitFor(() => document.querySelector(`[data-verify="${vaultId}"]`), `the vault card offers Verify state for ${vaultId}`);
      const before = calls.length;
      document.querySelector(`[data-verify="${vaultId}"]`).click();
      await waitFor(() => calls.slice(before).some((c) => c.method === "POST" && c.route === `/vaults/${vaultId}/reconcile`), "Verify posted the reconcile request");
      await ticks(60);
    }
  };
  await waitFor(() => h.card(VAULT_ID) || document.querySelector('[data-status="All"]'), "the vaults view rendered");
  return h;
}
/* The level of the status region: exactly one of good / warn / bad. */
function levelOf(el) {
  const levels = ["good", "warn", "bad"].filter((c) => el.classList.contains(c));
  assert.equal(levels.length, 1, `the status region carries exactly one level class (className "${el.className}")`);
  return levels[0];
}
/* Verify on the owner's live card answering `reconcileBody`; returns the status region. */
async function verifyAnswer(t, reconcileBody) {
  const h = await loadBrowser(t, { vaults: [baseVault()], reconcile: () => ({ status: 200, body: { reconcile: reconcileBody, vault: baseVault() } }) });
  await h.clickVerify(VAULT_ID);
  return { h, el: h.notice(), text: h.notice().textContent };
}
function assertPhrases(text, phrases, label) {
  for (const p of phrases) assert.ok(has(text, p), `${label}: the status region must say "${p}" (plan r2 §5 WEB-1); it says: ${text}`);
}
const idShown = (text, entry) => [entry.requestId, entry.txId].filter(Boolean).some((id) => text.includes(id.slice(0, 8)));

/* ======================= WEB-1: every Verify status mapped ======================= */

test("RC45 WEB-1 holds: CONSISTENT and TERMINAL render in the good class with their token [holds on C1]", async (t) => {
  for (const body of [{ status: "CONSISTENT", vaultId: VAULT_ID }, { status: "TERMINAL", vaultStatus: "RECOVERED" }]) {
    const { el, text } = await verifyAnswer(t, body);
    assert.equal(levelOf(el), "good", `${body.status} is good`);
    assert.ok(text.includes(body.status), `${body.status}: the token stays visible`);
  }
});

test("RC45 WEB-1: ADVANCED renders good, names its `to` and lists settled[] (the superseded entry with its state) [RED on C1]", async (t) => {
  const settled = { requestId: REQ_L, action: "agentSpend", state: "STALE", txId: TX_L };
  const { el, text } = await verifyAnswer(t, { status: "ADVANCED", to: "ownerPause", txId: TX_W, requestId: REQ_W, settled: [settled] });
  assert.equal(levelOf(el), "good");
  assert.ok(text.includes("ownerPause"), `ADVANCED names its to (ownerPause); it says: ${text}`);
  assert.ok(idShown(text, settled), `ADVANCED lists the settled entry (${REQ_L} / ${TX_L}); it says: ${text}`);
  assert.ok(text.includes("STALE"), `the settled entry shows its state; it says: ${text}`);
});

test("RC45 WEB-1: an adopted ADVANCED is marked \"(change made outside PolicyVault)\" [RED on C1]", async (t) => {
  const { el, text } = await verifyAnswer(t, { status: "ADVANCED", to: "ownerPause", adopted: true, txId: TX_W, settled: [] });
  assert.equal(levelOf(el), "good");
  assertPhrases(text, ["(change made outside PolicyVault)"], "adopted ADVANCED");
});

test("RC45 WEB-1: CONSISTENT lists a released leftover (settled[]) and stays good [RED on C1]", async (t) => {
  const leftover = { requestId: REQ_R, action: "ownerRecover", state: "SUBMISSION_REJECTED", txId: TX_C };
  const { el, text } = await verifyAnswer(t, { status: "CONSISTENT", vaultId: VAULT_ID, settled: [leftover] });
  assert.equal(levelOf(el), "good");
  assert.ok(idShown(text, leftover), `CONSISTENT lists the released leftover (${REQ_R} / ${TX_C}); it says: ${text}`);
});

test("RC45 WEB-1: CLAIM_PENDING with {depth, required} renders warn: \"confirming (d of 1000); press Verify again in about N s\" plus the closure advice [RED on C1]", async (t) => {
  const { el, text } = await verifyAnswer(t, { status: "CLAIM_PENDING", vaultId: VAULT_ID, txId: TX_W, depth: "250", required: "1000" });
  assert.equal(levelOf(el), "warn", `CLAIM_PENDING is never success; it says: ${text}`);
  assertPhrases(text, ["confirming (250 of 1000)", "press Verify again in about", "If this is a closure, do not move the recovered funds until Verify shows RECOVERED."], "CLAIM_PENDING at depth");
});

test("RC45 WEB-1: CLAIM_PENDING naming a claim renders warn: \"A claim by <claimTxId> may still execute. Pause and Close & recover stay available; Verify again later.\" [RED on C1]", async (t) => {
  const { el, text } = await verifyAnswer(t, { status: "CLAIM_PENDING", vaultId: VAULT_ID, claimTxId: TX_C, reason: "a claim on the recorded outpoint" });
  assert.equal(levelOf(el), "warn", `CLAIM_PENDING is never success; it says: ${text}`);
  assert.ok(text.includes(TX_C.slice(0, 8)), `the claim's txid is named; it says: ${text}`);
  assertPhrases(text, ["A claim by", "may still execute", "Pause and Close & recover stay available", "Verify again later"], "CLAIM_PENDING with a claim");
});

test("RC45 WEB-1: REQUEST_RECOVERY_REQUIRED renders warn and lists pending[]: signed work may still execute and blocks other actions; Pause and Close & recover stay available [RED on C1]", async (t) => {
  const pending = { requestId: REQ_P, action: "agentSpend", state: "PREFLIGHT_VERIFIED", signerRole: "agent", txId: TX_L };
  const { el, text } = await verifyAnswer(t, { status: "REQUEST_RECOVERY_REQUIRED", vaultId: VAULT_ID, requestId: REQ_P, pending: [pending], vaultStatus: "ACTIVE", recordedVaultClosed: false, reason: "signed work on the recorded outpoint" });
  assert.equal(levelOf(el), "warn", `REQUEST_RECOVERY_REQUIRED is never success; it says: ${text}`);
  assertPhrases(text, ["signed work may still execute and blocks other actions", "Pause and Close & recover stay available", "if yours confirms first, the pending one can never execute"], "REQUEST_RECOVERY_REQUIRED");
  assert.ok(idShown(text, pending), `the pending record is listed; it says: ${text}`);
});

test("RC45 WEB-1: REQUEST_RECOVERY_REQUIRED on a recorded-closed vault renders warn: \"closed vault, history only\" [RED on C1]", async (t) => {
  const { el, text } = await verifyAnswer(t, { status: "REQUEST_RECOVERY_REQUIRED", vaultId: VAULT_ID, requestId: REQ_P, vaultStatus: "RECOVERED", recordedVaultClosed: true, reason: "historical request evidence remains unresolved" });
  assert.equal(levelOf(el), "warn");
  assertPhrases(text, ["closed vault, history only"], "recorded-closed REQUEST_RECOVERY_REQUIRED");
});

test("RC45 WEB-1: UNKNOWN renders bad with the likely cause and the on-chain remedy (CR-M1, OD-1 condition 2) [RED on C1]", async (t) => {
  const { el, text } = await verifyAnswer(t, { status: "UNKNOWN", reason: "the recorded outpoint is spent and no known spender was seen", unchecked: 0 });
  assert.equal(levelOf(el), "bad", `UNKNOWN is never success; it says: ${text}`);
  assertPhrases(text, [
    "Nothing changed.",
    "The vault may have moved outside PolicyVault with a vault key.",
    "Do not sign new actions for this vault.",
    "If a delegate key may be misused, pause or close the vault on chain with the owner key.",
    "Hosted Pause and Close & recover cannot act on this vault.",
    "After you act on chain, PolicyVault keeps showing this vault's last recorded state; only a recover that spends the recorded outpoint can be pasted below."
  ], "UNKNOWN");
});

test("RC45 WEB-1: CHAIN_CONTRADICTION renders bad: the chain currently contradicts the record; nothing changed; Verify again later [RED on C1]", async (t) => {
  const { el, text } = await verifyAnswer(t, { status: "CHAIN_CONTRADICTION", reason: "the recorded predecessor is live again" });
  assert.equal(levelOf(el), "bad", `CHAIN_CONTRADICTION is never success; it says: ${text}`);
  assertPhrases(text, ["the chain currently contradicts the record (for example a reorganization); nothing changed; Verify again later"], "CHAIN_CONTRADICTION");
});

test("RC45 WEB-1: an unknown Verify status fails closed — bad, with its token shown [RED on C1]", async (t) => {
  const { el, text } = await verifyAnswer(t, { status: "SOMETHING_NEW_42" });
  assert.equal(levelOf(el), "bad", `an unmapped status is never success; it says: ${text}`);
  assert.ok(text.includes("SOMETHING_NEW_42"), "the unknown token stays visible");
});

test("RC45 WEB-1 (CR2-L14): the closed Verify status map lives in web/refusal-explain.js — it names every Verify status [RED on C1]", () => {
  const src = fs.readFileSync(path.join(WEB_DIR, "refusal-explain.js"), "utf8");
  for (const status of ["CONSISTENT", "ADVANCED", "TERMINAL", "CLAIM_PENDING", "REQUEST_RECOVERY_REQUIRED", "UNKNOWN", "CHAIN_CONTRADICTION"]) {
    assert.ok(src.includes(`${status}`) && new RegExp(`\\b${status}\\b`).test(src), `web/refusal-explain.js maps the Verify status ${status}`);
  }
});

/* ======================= WEB-2: Verify on an owner's TERMINATED_UNKNOWN card ======================= */

function terminatedUnknownVault() {
  const v = baseVault();
  return { ...v, status: "TERMINATED_UNKNOWN", live: null, approverSlots: undefined, approvalM: undefined, operational: { status: "UNKNOWN", reason: "automatic verification could not establish the vault state" }, latestTransitionTxId: TX_W };
}
function recoveredVault() {
  const v = baseVault();
  return { ...v, status: "RECOVERED", live: null, approverSlots: undefined, approvalM: undefined, operational: { status: "CLOSED" }, latestTransitionTxId: TX_W };
}

test("RC45 WEB-2: an owner's TERMINATED_UNKNOWN card renders exactly one Verify control (the existing data-verify button), and it posts Verify for that vault [RED on C1]", async (t) => {
  const h = await loadBrowser(t, { vaults: [terminatedUnknownVault()], reconcile: () => ({ status: 200, body: { reconcile: { status: "CONSISTENT", vaultId: VAULT_ID }, vault: baseVault() } }) });
  await h.showAll();
  await waitFor(() => h.card(VAULT_ID), "the TERMINATED_UNKNOWN card renders under All");
  const controls = h.card(VAULT_ID).querySelectorAll("[data-verify]");
  assert.equal(controls.length, 1, "exactly one Verify control on the owner's TERMINATED_UNKNOWN card (WEB-2)");
  assert.equal(controls[0].getAttribute("data-verify"), VAULT_ID);
  await h.clickVerify(VAULT_ID);
  assert.equal(h.posts(new RegExp(`^/vaults/${VAULT_ID}/reconcile$`)).length, 1, "one Verify post");
});

test("RC45 WEB-2 holds: a RECOVERED card offers no Verify control, and a non-owner's TERMINATED_UNKNOWN card offers none [holds on C1]", async (t) => {
  const owner = await loadBrowser(t, { vaults: [recoveredVault()] });
  await owner.showAll();
  await waitFor(() => owner.card(VAULT_ID), "the RECOVERED card renders under All");
  assert.equal(owner.card(VAULT_ID).querySelectorAll("[data-verify]").length, 0, "a closed (RECOVERED) card stays read-only history");
  const agent = await loadBrowser(t, { vaults: [terminatedUnknownVault()], xonly: AGENT, address: AGENT_ADDR_FIXTURE });
  await agent.showAll();
  await waitFor(() => agent.card(VAULT_ID), "the TERMINATED_UNKNOWN card renders for the agent");
  assert.equal(agent.card(VAULT_ID).querySelectorAll("[data-verify]").length, 0, "Verify is an owner control (H-52)");
});

/* ======================= WEB-3: the owner's recover-evidence paste ======================= */

test("RC45 WEB-3: on an owner's UNKNOWN the page offers the recover paste (\"Closed this vault outside PolicyVault? Paste the signed transaction (Safe JSON). Keep one output of it unspent until Verify shows RECOVERED.\"), a textarea whose submission POSTs exactly {outOfAppTransaction} to Verify, and renders the answer through WEB-1 [RED on C1]", async (t) => {
  const h = await loadBrowser(t, {
    vaults: [baseVault()],
    reconcile: (_vaultId, body, n) => n === 1
      ? { status: 200, body: { reconcile: { status: "UNKNOWN", reason: "the recorded outpoint is spent and no known spender was seen", unchecked: 0 }, vault: baseVault() } }
      : { status: 200, body: { reconcile: { status: "ADVANCED", to: "RECOVERED", txId: TX_W, settled: [] }, vault: recoveredVault() } }
  });
  const textareasBefore = h.document.querySelectorAll("textarea").length;
  await h.clickVerify(VAULT_ID);
  const pageText = h.document.body.textContent;
  assertPhrases(pageText, ["Closed this vault outside PolicyVault? Paste the signed transaction (Safe JSON). Keep one output of it unspent until Verify shows RECOVERED."], "WEB-3");
  const textareas = [...h.document.querySelectorAll("textarea")];
  assert.equal(textareas.length, textareasBefore + 1, "the UNKNOWN answer opens exactly one paste textarea (WEB-3)");
  const ta = textareas[textareas.length - 1];
  ta.value = PASTE;
  ta.dispatchEvent(new h.window.Event("input", { bubbles: true }));
  const posted = h.posts(/\/reconcile$/).length;
  const form = ta.form || ta.closest("form");
  if (form) {
    form.dispatchEvent(new h.window.Event("submit", { bubbles: true, cancelable: true }));
  } else {
    let box = ta.parentElement;
    while (box && !box.querySelector("button")) box = box.parentElement;
    assert.ok(box, "the paste textarea sits in a container with a submit control");
    const buttons = [...box.querySelectorAll("button")].filter((b) => !/cancel|close/i.test(b.textContent) && !b.hasAttribute("data-verify"));
    assert.ok(buttons.length >= 1, "the paste has a submit control");
    buttons[0].click();
  }
  await waitFor(() => h.posts(/\/reconcile$/).length === posted + 1, "the paste is posted to Verify");
  await ticks(60);
  const post = h.posts(/\/reconcile$/).at(-1);
  assert.equal(post.route, `/vaults/${VAULT_ID}/reconcile`);
  assert.deepEqual(post.body, { outOfAppTransaction: PASTE }, "the paste posts exactly {outOfAppTransaction}");
  assert.equal(levelOf(h.notice()), "good", "the answer renders through WEB-1");
  assert.ok(h.notice().textContent.includes("RECOVERED"), `the ADVANCED answer names RECOVERED; it says: ${h.notice().textContent}`);
});

/* ======================= CR2-M5: the v0.4-only outcome and refusal lines ======================= */

function flowRoutes({ action, signatureState = "PREFLIGHT_VERIFIED", submit }) {
  const doc = (state, extra = {}) => ({ schema: "policyvault-wallet-request/v4", requestId: "0f8a0100-0000-4000-8000-000000000100", kind: "transition", state, action, sdkAction: action, contractVersion: "policyvault-0.4.1", networkId: "testnet-10", vaultId: VAULT_ID,
    signerRole: "owner", signerAddress: OWNER_ADDR, signerXOnly: OWNER, txId: TX_W, review: { action, network: "testnet-10" },
    transaction: { unsignedSafeJson: '{"fixture":"unsigned"}', signInputs: [{ index: 1, sighashType: 1 }] }, ...extra });
  return {
    "POST /wallet/v4/requests": () => ({ status: 201, body: { request: doc("BUILT") } }),
    "POST /wallet/v4/requests/0f8a0100-0000-4000-8000-000000000100/signature": () => ({ status: 200, body: { request: doc(signatureState) } }),
    "POST /wallet/v4/requests/0f8a0100-0000-4000-8000-000000000100/submit": () => submit(doc)
  };
}
/* Drive the v4 transition caller: _runFlow -> review modal -> confirm -> completeRequestFlow. */
async function runV4Flow(t, { action, signatureState, submit }) {
  const h = await loadBrowser(t, { vaults: [baseVault()], routes: flowRoutes({ action, signatureState, submit: submit || (() => ({ status: 409, body: { error: { code: "FIXTURE", message: "unused" } } })) }) });
  const fuel = { outpoint: { transactionId: HEX("f2"), index: 1 }, amount: "10000000000", scriptPublicKeyHex: `20${OWNER}ac` };
  h.api._runFlow(VAULT_ID, action, action === "ownerTopUp" ? { topUpAmountSompi: "100000000", fuel } : { fuel }, "Approve in wallet");
  await waitFor(() => h.document.getElementById("v4-confirm"), "the review modal offers the wallet approval");
  h.document.getElementById("v4-confirm").click();
  await waitFor(() => h.posts(/\/signature$/).length === 1, "the signature is attached");
  await ticks(80);
  assert.equal(h.signingCalls(), 1, "the fixture wallet was asked exactly once");
  return h;
}

test("RC45 CR2-M5: a v0.4 Close & recover whose submit returns SUBMITTED carries the closure warning \"If this was Close & recover, do not move the recovered funds until Verify state shows RECOVERED.\" (CR-H2) [RED on C1]", async (t) => {
  const h = await runV4Flow(t, { action: "ownerRecover", submit: (doc) => ({ status: 200, body: { request: doc("SUBMITTED"), txId: TX_W } }) });
  const text = h.notice().textContent;
  assert.ok(text.includes("SUBMITTED"), `the outcome keeps its state; it says: ${text}`);
  assertPhrases(text, [V04_LINES.closure], "v0.4 SUBMITTED outcome");
  assert.notEqual(levelOf(h.notice()), "good", "SUBMITTED is never success");
});

test("RC45 CR2-M5: a v0.4 ordinary request left FINALIZED (an armed request, L-5) carries the armed-request line and its exit (CR-M7, CR2-L13) [RED on C1]", async (t) => {
  const h = await runV4Flow(t, { action: "ownerTopUp", signatureState: "FINALIZED" });
  const text = h.notice().textContent;
  assert.ok(text.includes("FINALIZED"), `the outcome keeps its state; it says: ${text}`);
  assertPhrases(text, [V04_LINES.armed, V04_LINES.armedExit], "v0.4 FINALIZED outcome");
});

test("RC45 CR2-M5: a v0.4 transition submit refused 409 CLAIM_CONFLICT adds \"Pause and Close & recover stay available\" to the CLAIM_CONFLICT explanation [RED on C1]", async (t) => {
  const h = await runV4Flow(t, { action: "ownerTopUp", submit: () => ({ status: 409, body: { error: { code: "CLAIM_CONFLICT", message: "another transaction holds the claim on this outpoint" } } }) });
  const text = h.notice().textContent;
  assert.ok(text.includes("CLAIM_CONFLICT"), `the refusal keeps its code; it says: ${text}`);
  assertPhrases(text, [V04_LINES.available], "v0.4 CLAIM_CONFLICT refusal");
});

test("RC45 CR2-M5 holds: the shared OUTCOMES and REFUSALS entries stay unchanged, and v0.7-kas SIGNED / SUBMITTED outcomes, a v4 genesis PREFLIGHT_VERIFIED outcome and a genesis CLAIM_CONFLICT refusal render without any v0.4 line [holds on C1]", () => {
  // The shared entries, byte-for-byte as at C1 (plan r2 §5: "stay unchanged"; the SIGNED edit is dropped).
  assert.deepEqual({ ...RX.outcome("SUBMITTED"), next: [...RX.outcome("SUBMITTED").next] }, { level: "pending", title: "Broadcast — NOT yet confirmed", meaning: "The transaction was accepted by the node for relay. That is not proof it is in the DAG, and it is not proof the vault changed. It may still be confirmed, or it may not.", next: ["Use Verify state on the vault to check the chain.", "Do not treat this as a completed payment yet."] });
  assert.deepEqual({ ...RX.outcome("SIGNED"), next: [...RX.outcome("SIGNED").next] }, { level: "pending", title: "Signed — NOT yet broadcast", meaning: "The wallet returned a signature. No transaction has reached the network and nothing has moved.", next: ["If this does not progress, use Verify state on the vault and rebuild the action."] });
  assert.deepEqual({ ...RX.outcome("PREFLIGHT_VERIFIED"), next: [...RX.outcome("PREFLIGHT_VERIFIED").next] }, { level: "pending", title: "Checked, not yet broadcast", meaning: "The signed transaction passed PolicyVault's final pre-broadcast checks. Nothing has been sent to the network.", next: ["Broadcasting follows automatically; if it does not complete, rebuild the action."] });
  assert.deepEqual({ ...RX.outcome("FINALIZED"), next: [...RX.outcome("FINALIZED").next] }, { level: "pending", title: "Assembled, not yet broadcast", meaning: "The signature was accepted and the transaction assembled. Nothing has been sent to the network.", next: ["If this does not progress, use Verify state on the vault and rebuild the action."] });
  const cc = RX.explain("CLAIM_CONFLICT");
  assert.deepEqual({ title: cc.title, meaning: cc.meaning, next: [...cc.next] }, { title: "Another transaction for this vault is still unresolved", meaning: "PolicyVault records a durable claim before broadcasting so a crash can never leave the outcome ambiguous. One is still open for this vault, so a second transaction is refused rather than risking a conflicting spend.", next: ["Use Verify state on the vault to reconcile the open claim against the chain, then retry."] });
  const renders = [
    RX.renderOutcomeHtml({ summary: "Delegate payment: SIGNED", state: "SIGNED", txId: TX_W, contractVersion: "policyvault-0.7-kas" }),
    RX.renderOutcomeHtml({ summary: "Delegate payment: SUBMITTED", state: "SUBMITTED", txId: TX_W, contractVersion: "policyvault-0.7-kas" }),
    RX.renderOutcomeHtml({ summary: "KAS treasury creation: SUBMITTED", state: "SUBMITTED", txId: TX_W, contractVersion: "policyvault-0.7-kas", kind: "kasGenesis" }),
    // v4 genesis renders: the genesis callers (app-v4.js signAndSubmitVaultGenesis / reconcileCreation) pass no
    // contractVersion, exactly as here.
    RX.renderOutcomeHtml({ summary: "Create vault: PREFLIGHT_VERIFIED", state: "PREFLIGHT_VERIFIED", txId: TX_W }),
    RX.renderOutcomeHtml({ summary: "Create vault (durable state): FINALIZED", state: "FINALIZED", txId: TX_W }),
    RX.renderRefusalHtml({ summary: "Reconciliation did not complete: CLAIM_CONFLICT", code: "CLAIM_CONFLICT", message: "claim held" }),
    RX.renderRefusalHtml({ summary: "Create refused: CLAIM_CONFLICT", code: "CLAIM_CONFLICT", message: "claim held" })
  ];
  for (const html of renders) for (const [name, line] of Object.entries(V04_LINES)) assert.ok(!has(html, line), `a non-v0.4-transition rendering carries the v0.4 ${name} line: ${html}`);
});

test("RC45 CR2-M5 holds: the genesis create-view reconcile refused 409 CLAIM_CONFLICT renders the refusal without the v0.4 \"Pause and Close & recover stay available\" line [holds on C1]", async (t) => {
  const genesis = { schema: "policyvault-wallet-request/v4", requestId: "0f8a0200-0000-4000-8000-000000000200", kind: "genesis", action: "createVault", state: "SUBMITTED", contractVersion: "policyvault-0.4.1", networkId: "testnet-10", signerAddress: OWNER_ADDR, txId: TX_W, label: "fixture creation" };
  const h = await loadBrowser(t, {
    vaults: [baseVault()], unresolved: [genesis],
    routes: { [`POST /wallet/v4/requests/${genesis.requestId}/reconcile`]: () => ({ status: 409, body: { error: { code: "CLAIM_CONFLICT", message: "a claim is held on the genesis funding outpoint" } } }) }
  });
  h.document.querySelector('.v4-tab[data-view="create"]').click();
  await waitFor(() => h.document.querySelector(`[data-reconcile-create="${genesis.requestId}"]`), "the create view lists the unresolved creation");
  h.document.querySelector(`[data-reconcile-create="${genesis.requestId}"]`).click();
  await waitFor(() => h.posts(/\/reconcile$/).length === 1, "the creation reconcile is posted");
  await ticks(60);
  const text = h.notice().textContent;
  assert.ok(text.includes("CLAIM_CONFLICT"), `the genesis refusal keeps its code; it says: ${text}`);
  for (const [name, line] of Object.entries(V04_LINES)) assert.ok(!has(text, line), `the genesis CLAIM_CONFLICT refusal must not carry the v0.4 ${name} line`);
});
