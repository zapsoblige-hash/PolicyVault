"use strict";

/*
 * RC45 R1-07 — VERIFY ANSWERS THAT WROTE ARE TOLD AS WRITES (finding F-02 of
 * the independent candidate review rc45-patch-independent-01; remediation plan
 * rc45-r1-plan-01 PLAN-R1 revision 2, §2 R1-07 with condition C8, §4 R1-07
 * "web legs for CONSISTENT with CHAIN_VERIFIED / STALE / leftover entries and
 * for a restore"). Internal RED-first regression material for the RC45
 * successor candidate; not an audit.
 *
 * The rules (plan R1-07):
 *   - the Verify map in web/refusal-explain.js omits "Nothing was changed."
 *     whenever settled[] is non-empty or a restore occurred;
 *   - each settled[] entry is labelled by its resulting state: completed
 *     (CHAIN_VERIFIED), superseded (STALE), released leftover
 *     (SUBMISSION_REJECTED);
 *   - C8: the restore notice is derived in the web from the card's prior
 *     status (TERMINATED_UNKNOWN before the Verify, live after); there is NO
 *     new response field (every fixture answer here carries only the fields
 *     sdk/src/reconcile-v4.js already returns, and the route's existing
 *     `vault` document).
 *
 * RED on dc7552e: a CONSISTENT answer always says "Nothing was changed." and
 * labels every settled[] entry "Released by this Verify (an established
 * rejection's leftover claim)", so a completion (CHAIN_VERIFIED) and a
 * supersession (STALE) are told as leftover releases and the writes are
 * denied; a TERMINATED_UNKNOWN vault that Verify restored is told "Nothing was
 * changed." with no restore notice; CLAIM_PENDING and REQUEST_RECOVERY_REQUIRED
 * answers never list their settled[]; ADVANCED and TERMINAL list it under a
 * neutral label with no resulting-state label.
 * HOLDS on dc7552e (and must keep holding): a CONSISTENT answer on a live card
 * that settled nothing still says "Nothing was changed." with no restore
 * notice; a TERMINATED_UNKNOWN card that is not live after the Verify
 * (CLAIM_PENDING below depth, UNKNOWN) shows no restore notice.
 *
 * Readings chosen where the plan leaves a detail open (fail closed; recorded
 * in the R1-07 RED record):
 *   - "label each settled[] entry by its resulting state" (the second clause
 *     of §2 R1-07) is read for EVERY Verify answer that carries a non-empty
 *     settled[] (CONSISTENT, ADVANCED, TERMINAL, CLAIM_PENDING,
 *     REQUEST_RECOVERY_REQUIRED: the answers sdk/src/reconcile-v4.js can
 *     return with settled entries), so no answer that wrote leaves a write
 *     undisclosed or mislabelled;
 *   - the label words are matched case-insensitively and layout-free over the
 *     whole Verify text of a one-entry settled[]: completed /\bcomplet/,
 *     superseded /\bsupersed/, released leftover /\breleas/ and /leftover/;
 *     a completion or a supersession is never told as a leftover or a
 *     rejection, a leftover never as a completion or a supersession; an entry
 *     whose state the map does not know is never labelled completed and keeps
 *     its raw state token;
 *   - the restore notice is web text in the status region #v4-notice that
 *     matches /\brestor/i once the server's own `reason` string is removed
 *     (a below-depth CLAIM_PENDING reason itself says "restored at depth");
 *     it is required after a restore for each answer settleLive can give
 *     after restore() (CONSISTENT, CLAIM_PENDING with a claim,
 *     REQUEST_RECOVERY_REQUIRED; review PR1-08) and is absent when the card
 *     was not TERMINATED_UNKNOWN before or is not live after.
 *
 * Layers: MAP (the real web/refusal-explain.js verifyStatus /
 * renderVerifyHtml) and BROWSER (jsdom; the real web/refusal-explain.js and
 * web/app-v4.js with web/core-bundle.js and web/setup-ui.js, the harness of
 * web/test/rc45-t8-verify-web.test.js; only the wallet session and the HTTP
 * responses are doubles — server-document-shaped fixtures from
 * web/test/helpers.js). Every request is intercepted and recorded; no
 * external resource loads; nothing signs. The candidate-written answers of
 * the real Verify pass are in web/test/rc45-r1-07-consistent-web-real.test.js.
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { JSDOM, VirtualConsole } = require("../../sdk/node_modules/jsdom");
const { baseVault, VAULT_ID, OWNER, OWNER_ADDR } = require("./helpers.js");

const WEB_DIR = path.join(__dirname, "..");
const HTML = fs.readFileSync(path.join(WEB_DIR, "index.html"), "utf8");
const SCRIPTS = ["core-bundle.js", "setup-ui.js", "refusal-explain.js", "app-v4.js"].map((name) => ({ name, source: fs.readFileSync(path.join(WEB_DIR, name), "utf8") }));
const RX = require("../refusal-explain.js");
const HEX = (s) => s.repeat(32);
const TX_W = HEX("a1"), TX_S = HEX("a2"), TX_R = HEX("a3"), TX_C = HEX("a4"), TX_X = HEX("a5");
const REQ_W = "0f8a0701-0000-4000-8000-000000000701", REQ_S = "0f8a0702-0000-4000-8000-000000000702", REQ_R = "0f8a0703-0000-4000-8000-000000000703";
const REQ_X = "0f8a0704-0000-4000-8000-000000000704", REQ_P = "0f8a0705-0000-4000-8000-000000000705";

/* One settled[] entry of each resulting state, exactly entryOf()'s shape (sdk/src/reconcile-v4.js :99). */
const COMPLETED = Object.freeze({ requestId: REQ_W, action: "ownerPause", state: "CHAIN_VERIFIED", txId: TX_W });
const SUPERSEDED = Object.freeze({ requestId: REQ_S, action: "agentSpend", state: "STALE", txId: TX_S });
const LEFTOVER = Object.freeze({ requestId: REQ_R, action: "agentSpend", state: "SUBMISSION_REJECTED", txId: TX_R });
const UNMAPPED = Object.freeze({ requestId: REQ_X, action: "agentSpend", state: "SOME_FUTURE_STATE_42", txId: TX_X });
const NOTHING = "Nothing was changed.";
const RRR_EXIT = "Verify at depth marks it superseded";
const LABEL = Object.freeze({
  completed: /\bcomplet/i,
  superseded: /\bsupersed/i,
  released: /\breleas/i,
  leftover: /leftover/i,
  rejection: /\breject/i
});
const norm = (s) => String(s ?? "").replace(/\s+/g, " ").trim();
/* The visible text of a rendered region, its text nodes joined by spaces (jsdom's textContent runs adjacent blocks together). */
function textOf(el) {
  const doc = el.ownerDocument, walker = doc.createTreeWalker(el, doc.defaultView.NodeFilter.SHOW_TEXT), parts = [];
  for (let n = walker.nextNode(); n; n = walker.nextNode()) parts.push(n.data);
  return norm(parts.join(" "));
}
const short8 = (id) => id.slice(0, 8);
const listed = (text, entry) => [entry.requestId, entry.txId].filter(Boolean).some((id) => text.includes(short8(id)));

/* The whole Verify text of an answer, through the closed map (lines) and its HTML rendering. */
function mapText(result) {
  const v = RX.verifyStatus(result);
  return { v, lines: v.lines, text: norm(v.lines.join(" ")) };
}
function assertLabel(text, entry, kind, where) {
  assert.ok(listed(text, entry), `${where}: the settled entry ${entry.requestId} is listed; it says: ${text}`);
  assert.ok(text.includes(entry.state), `${where}: the entry keeps its resulting state token ${entry.state}; it says: ${text}`);
  if (kind === "completed") {
    assert.match(text, LABEL.completed, `${where}: a CHAIN_VERIFIED entry is labelled completed (plan R1-07); it says: ${text}`);
    assert.doesNotMatch(text, LABEL.leftover, `${where}: a completion is never told as an established rejection's leftover; it says: ${text}`);
    assert.doesNotMatch(text, LABEL.rejection, `${where}: a completion is never told as a rejection; it says: ${text}`);
  } else if (kind === "superseded") {
    assert.match(text, LABEL.superseded, `${where}: a STALE entry is labelled superseded (plan R1-07); it says: ${text}`);
    assert.doesNotMatch(text, LABEL.leftover, `${where}: a supersession is never told as an established rejection's leftover; it says: ${text}`);
    assert.doesNotMatch(text, LABEL.rejection, `${where}: a supersession is never told as a rejection; it says: ${text}`);
    assert.doesNotMatch(text, LABEL.completed, `${where}: a supersession is never told as a completion; it says: ${text}`);
  } else if (kind === "leftover") {
    assert.match(text, LABEL.released, `${where}: a SUBMISSION_REJECTED entry is labelled released (plan R1-07); it says: ${text}`);
    assert.match(text, LABEL.leftover, `${where}: a SUBMISSION_REJECTED entry is labelled a leftover (plan R1-07); it says: ${text}`);
    assert.doesNotMatch(text, LABEL.completed, `${where}: a released leftover is never told as a completion; it says: ${text}`);
    assert.doesNotMatch(text, LABEL.superseded, `${where}: a released leftover is never told as a supersession; it says: ${text}`);
  } else throw new Error(`unknown kind ${kind}`);
}

/* ======================= MAP: CONSISTENT answers that wrote ======================= */

test("RC45 R1-07 map: a CONSISTENT answer whose settled[] holds a completion (CHAIN_VERIFIED) omits \"Nothing was changed.\" and labels the entry completed, never an established rejection's leftover [RED on dc7552e]", () => {
  const { v, lines, text } = mapText({ status: "CONSISTENT", vaultId: VAULT_ID, settled: [COMPLETED] });
  assert.equal(v.level, "good"); assert.equal(v.known, true);
  assert.ok(!lines.includes(NOTHING), `settled[] is non-empty: "${NOTHING}" is omitted (plan R1-07); lines: ${JSON.stringify(lines)}`);
  assertLabel(text, COMPLETED, "completed", "CONSISTENT + CHAIN_VERIFIED");
});

test("RC45 R1-07 map: a CONSISTENT answer whose settled[] holds a supersession (STALE) omits \"Nothing was changed.\" and labels the entry superseded [RED on dc7552e]", () => {
  const { lines, text } = mapText({ status: "CONSISTENT", vaultId: VAULT_ID, settled: [SUPERSEDED] });
  assert.ok(!lines.includes(NOTHING), `settled[] is non-empty: "${NOTHING}" is omitted (plan R1-07); lines: ${JSON.stringify(lines)}`);
  assertLabel(text, SUPERSEDED, "superseded", "CONSISTENT + STALE");
});

test("RC45 R1-07 map: a CONSISTENT answer whose settled[] holds an established rejection's leftover (SUBMISSION_REJECTED) omits \"Nothing was changed.\" (claims and the reservation were released) and labels the entry a released leftover [RED on dc7552e]", () => {
  const { lines, text } = mapText({ status: "CONSISTENT", vaultId: VAULT_ID, settled: [LEFTOVER] });
  assert.ok(!lines.includes(NOTHING), `settled[] is non-empty: "${NOTHING}" is omitted (plan R1-07); lines: ${JSON.stringify(lines)}`);
  assertLabel(text, LEFTOVER, "leftover", "CONSISTENT + SUBMISSION_REJECTED");
});

test("RC45 R1-07 map: a CONSISTENT answer settling a completion, a supersession and a leftover omits \"Nothing was changed.\", lists every entry with its state token and carries all three labels (completed, superseded, released leftover) [RED on dc7552e]", () => {
  const { lines, text } = mapText({ status: "CONSISTENT", vaultId: VAULT_ID, settled: [COMPLETED, SUPERSEDED, LEFTOVER] });
  assert.ok(!lines.includes(NOTHING), `settled[] is non-empty: "${NOTHING}" is omitted (plan R1-07); lines: ${JSON.stringify(lines)}`);
  for (const e of [COMPLETED, SUPERSEDED, LEFTOVER]) {
    assert.ok(listed(text, e), `the entry ${e.requestId} is listed; it says: ${text}`);
    assert.ok(text.includes(e.state), `the entry keeps its state token ${e.state}; it says: ${text}`);
  }
  assert.match(text, LABEL.completed, `the completion is labelled completed; it says: ${text}`);
  assert.match(text, LABEL.superseded, `the supersession is labelled superseded; it says: ${text}`);
  assert.match(text, LABEL.leftover, `the leftover is labelled a released leftover; it says: ${text}`);
});

test("RC45 R1-07 map: a CONSISTENT answer whose settled[] entry carries a state the map does not know omits \"Nothing was changed.\", keeps the raw state token and never labels it completed (fail closed) [RED on dc7552e]", () => {
  const { lines, text } = mapText({ status: "CONSISTENT", vaultId: VAULT_ID, settled: [UNMAPPED] });
  assert.ok(!lines.includes(NOTHING), `settled[] is non-empty: "${NOTHING}" is omitted (plan R1-07); lines: ${JSON.stringify(lines)}`);
  assert.ok(listed(text, UNMAPPED), `the entry is listed; it says: ${text}`);
  assert.ok(text.includes(UNMAPPED.state), `the raw state token stays visible; it says: ${text}`);
  assert.doesNotMatch(text, LABEL.completed, `an unrecognised resulting state is never told as a completion; it says: ${text}`);
});

test("RC45 R1-07 map: renderVerifyHtml of a CONSISTENT answer that settled a completion carries no \"Nothing was changed.\" and no leftover label [RED on dc7552e]", () => {
  const html = RX.renderVerifyHtml({ status: "CONSISTENT", vaultId: VAULT_ID, settled: [COMPLETED] });
  assert.ok(!html.includes(NOTHING), `the rendering omits "${NOTHING}"; it is: ${html}`);
  assert.doesNotMatch(html, LABEL.leftover, `the rendering does not call the completion a leftover; it is: ${html}`);
  assert.ok(html.includes('data-verify-answer="CONSISTENT"') && html.includes('data-verify-level="good"'), "the token and the good level stay");
});

/* ======================= MAP: every other answer that carries settled[] (fail-closed reading) ======================= */

test("RC45 R1-07 map: an ADVANCED answer labels its superseded loser (STALE) superseded and its completed twin (CHAIN_VERIFIED) completed, one entry at a time [RED on dc7552e]", () => {
  const base = { status: "ADVANCED", vaultId: VAULT_ID, to: "ownerPause", txId: TX_C, requestId: REQ_P };
  const stale = mapText({ ...base, settled: [SUPERSEDED] });
  assert.equal(stale.v.level, "good");
  assertLabel(stale.text, SUPERSEDED, "superseded", "ADVANCED + STALE");
  const twin = mapText({ ...base, settled: [COMPLETED] });
  assertLabel(twin.text, COMPLETED, "completed", "ADVANCED + CHAIN_VERIFIED twin");
});

test("RC45 R1-07 map: a TERMINAL answer whose settled[] holds the recorded closure's completion (finishRecordedV4) labels it completed [RED on dc7552e]", () => {
  const { v, text } = mapText({ status: "TERMINAL", vaultStatus: "RECOVERED", settled: [{ ...COMPLETED, action: "ownerRecover" }] });
  assert.equal(v.level, "good");
  assertLabel(text, { ...COMPLETED, action: "ownerRecover" }, "completed", "TERMINAL + CHAIN_VERIFIED");
});

test("RC45 R1-07 map: a CLAIM_PENDING answer (a claim on the live outpoint) that carries settled[] lists every settled entry labelled by its resulting state [RED on dc7552e]", () => {
  for (const [entry, kind] of [[COMPLETED, "completed"], [SUPERSEDED, "superseded"], [LEFTOVER, "leftover"]]) {
    const { v, text } = mapText({ status: "CLAIM_PENDING", vaultId: VAULT_ID, claimTxId: TX_C, reason: "the recorded outpoint is live and claimed; absence does not establish rejection; the claim is kept", settled: [entry] });
    assert.equal(v.level, "warn", "CLAIM_PENDING stays warn");
    assertLabel(text, entry, kind, `CLAIM_PENDING + ${entry.state}`);
  }
});

test("RC45 R1-07 map: a REQUEST_RECOVERY_REQUIRED answer (signed work on the live outpoint) that carries settled[] lists every settled entry labelled by its resulting state, next to its pending[] [RED on dc7552e]", () => {
  const pending = { requestId: REQ_P, action: "agentSpend", state: "PREFLIGHT_VERIFIED", txId: TX_C, signerRole: "agent" };
  for (const [entry, kind] of [[COMPLETED, "completed"], [SUPERSEDED, "superseded"], [LEFTOVER, "leftover"]]) {
    const { v, text } = mapText({ status: "REQUEST_RECOVERY_REQUIRED", vaultId: VAULT_ID, requestId: REQ_P, pending: [pending], vaultStatus: "ACTIVE", recordedVaultClosed: false,
      reason: "signed work on the recorded outpoint may still execute and blocks other actions", settled: [entry] });
    assert.equal(v.level, "warn", "REQUEST_RECOVERY_REQUIRED stays warn");
    assert.ok(listed(text, pending), `the pending record stays listed; it says: ${text}`);
    // The answer's own exit advice (pinned by T8: "Pause, then Verify at depth marks it superseded, ...") is not a label.
    assertLabel(text.split(RRR_EXIT).join(" "), entry, kind, `REQUEST_RECOVERY_REQUIRED + ${entry.state}`);
  }
});

/* ======================= BROWSER (app-v4.js) ======================= */

async function ticks(n = 30) { for (let i = 0; i < n; i++) await new Promise((resolve) => setImmediate(resolve)); }
async function waitFor(predicate, message, limit = 400) {
  for (let i = 0; i < limit; i++) { if (predicate()) return; await new Promise((resolve) => setImmediate(resolve)); }
  assert.ok(predicate(), message);
}

/*
 * One browser. `vaults(n)` is the GET /vaults document after n Verify posts (the card's prior status at n = 0, the
 * vault after the Verify from n = 1); `reconcile(vaultId, body, n)` answers POST /vaults/:id/reconcile ({status, body}).
 */
async function loadBrowser(t, { vaults, reconcile, xonly = OWNER, address = OWNER_ADDR }) {
  const errors = [];
  const vc = new VirtualConsole();
  vc.on("jsdomError", (e) => errors.push(e.message));
  const dom = new JSDOM(HTML, { url: "https://policyvault-fixture.invalid/", runScripts: "outside-only", pretendToBeVisual: true, virtualConsole: vc });
  t.after(async () => { await ticks(5); dom.window.close(); });
  const { window } = dom;
  const document = window.document;
  const calls = [];
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
    const m = /^\/vaults\/([0-9a-f]{64})\/reconcile$/.exec(route);
    if (method === "POST" && m) { reconcileCount += 1; const r = await reconcile(m[1], body, reconcileCount); return reply(r.body, r.status ?? 200); }
    if (method === "GET" && route === "/health") return reply({ networkId: "testnet-10" });
    if (method === "GET" && route === "/network/status") return reply({ networkId: "testnet-10", virtualDaaScore: "90000000" });
    if (method === "GET" && route === "/capabilities") return reply({ networkId: "testnet-10", contract: { creatableCovenantVersions: ["policyvault-0.4.1"] } });
    if (method === "GET" && route === "/vaults") return reply({ vaults: vaults(reconcileCount) });
    if (method === "GET" && route === "/organizations") return reply({ organizations: [], assignments: {}, assignmentsVersion: null });
    if (method === "GET" && route === "/wallet/v4/requests") return reply({ requests: [] });
    const s = /^\/vaults\/([0-9a-f]{64})\/agent-suspensions$/.exec(route);
    if (method === "GET" && s) return reply({ suspensions: suspension(s[1]) });
    if (method === "GET" && route === "/org-roots") return reply({ orgRoots: [] });
    if (method === "GET" && route === "/wallet/v7/vaults") return reply({ vaults: [] });
    if (method === "GET" && route === "/wallet/v7/requests") return reply({ requests: [] });
    return reply({ error: { code: "FIXTURE_UNMAPPED", message: `unmapped fixture route ${method} ${route}` } }, 404);
  };
  const snapshot = {
    connected: true, ready: true, address, xonly, network: "testnet-10", serverNetwork: "testnet-10", auth: "AUTHENTICATED", provider: "fixture",
    adapter: { signInputs: async () => { throw new Error("R1-07 fixture: nothing signs"); } }
  };
  window.PolicyVaultHealthPromise = Promise.resolve({ networkId: "testnet-10" });
  window.PolicyVaultWalletSession = { active: () => snapshot, subscribe(fn) { fn(snapshot); return () => {}; } };
  for (const { name, source } of SCRIPTS) window.eval(`${source}\n//# sourceURL=${name}`);
  const tabsWired = () => { const tab = document.querySelector('.v4-tab[data-view="vaults"]') || document.querySelector(".v4-tab"); return tab && typeof tab.onclick === "function"; };
  for (let i = 0; i < 20 && !tabsWired(); i++) await ticks(1);
  if (!tabsWired()) window.dispatchEvent(new window.Event("DOMContentLoaded"));
  await waitFor(tabsWired, "app navigation initialized");
  const h = {
    window, document, calls, errors,
    notice: () => document.getElementById("v4-notice"),
    posts: (routeRe) => calls.filter((c) => c.method === "POST" && routeRe.test(c.route)),
    card: (vaultId) => document.querySelector(`[data-vault="${vaultId}"]`),
    async showAll() {
      await waitFor(() => document.querySelector('[data-status="All"]'), "the vaults view rendered its filter bar");
      document.querySelector('[data-status="All"]').click();
      await ticks();
    },
    async clickVerify(vaultId) {
      await waitFor(() => document.querySelector(`[data-verify="${vaultId}"]`), `the vault card offers Verify state for ${vaultId}`);
      const before = calls.length;
      document.querySelector(`[data-verify="${vaultId}"]`).click();
      await waitFor(() => calls.slice(before).some((c) => c.method === "POST" && c.route === `/vaults/${vaultId}/reconcile`), "Verify posted the reconcile request");
      await ticks(80);
    }
  };
  await waitFor(() => h.card(VAULT_ID) || document.querySelector('[data-status="All"]'), "the vaults view rendered");
  return h;
}
function levelOf(el) {
  const levels = ["good", "warn", "bad"].filter((c) => el.classList.contains(c));
  assert.equal(levels.length, 1, `the status region carries exactly one level class (className "${el.className}")`);
  return levels[0];
}
/* A TERMINATED_UNKNOWN card (RC44 case E; the shape of web/test/rc45-t8-verify-web.test.js). */
function terminatedUnknownVault() {
  const v = baseVault();
  return { ...v, status: "TERMINATED_UNKNOWN", live: null, approverSlots: undefined, approvalM: undefined, operational: { status: "UNKNOWN", reason: "automatic verification could not establish the vault state" }, latestTransitionTxId: TX_W };
}
/* The vault restored by Verify: live again (restore writes live = the recorded base, status by paused). */
function restoredVault({ paused = false } = {}) {
  const v = baseVault();
  return { ...v, status: paused ? "PAUSED" : "ACTIVE", live: { ...v.live, paused }, latestTransitionTxId: TX_W };
}
/* Verify once on the owner's card; `before` is the card at n = 0, `after` the vault document from the Verify on. */
async function verifyOnCard(t, { before, after, answer }) {
  const h = await loadBrowser(t, { vaults: (n) => [n === 0 ? before : after], reconcile: () => ({ status: 200, body: { reconcile: answer, vault: after } }) });
  if (before.status === "TERMINATED_UNKNOWN") {
    await h.showAll();
    await waitFor(() => h.card(VAULT_ID), "the TERMINATED_UNKNOWN card renders under All");
  }
  await h.clickVerify(VAULT_ID);
  assert.equal(h.posts(new RegExp(`^/vaults/${VAULT_ID}/reconcile$`)).length, 1, "one Verify post");
  const el = h.notice();
  return { h, el, text: textOf(el) };
}
/* The status region's own text with the server's `reason` string removed (the restore notice is web text, C8). */
const withoutReason = (text, reason) => (reason ? text.split(norm(reason)).join(" ") : text);
const RESTORE = /\brestor/i;

test("RC45 R1-07 browser: Verify on a live card answering CONSISTENT with a completion (CHAIN_VERIFIED) in settled[] renders good without \"Nothing was changed.\" and labels the entry completed [RED on dc7552e]", async (t) => {
  const { el, text } = await verifyOnCard(t, { before: baseVault(), after: baseVault(), answer: { status: "CONSISTENT", vaultId: VAULT_ID, settled: [COMPLETED] } });
  assert.equal(levelOf(el), "good");
  assert.ok(text.includes("CONSISTENT"), "the token stays visible");
  assert.ok(!text.includes(NOTHING), `a CONSISTENT answer that wrote is not told "${NOTHING}" (plan R1-07); it says: ${text}`);
  assertLabel(text, COMPLETED, "completed", "browser CONSISTENT + CHAIN_VERIFIED");
});

test("RC45 R1-07 browser: Verify on a live card answering CONSISTENT with a supersession (STALE) in settled[] renders good without \"Nothing was changed.\" and labels the entry superseded [RED on dc7552e]", async (t) => {
  const { el, text } = await verifyOnCard(t, { before: baseVault(), after: baseVault(), answer: { status: "CONSISTENT", vaultId: VAULT_ID, settled: [SUPERSEDED] } });
  assert.equal(levelOf(el), "good");
  assert.ok(!text.includes(NOTHING), `a CONSISTENT answer that wrote is not told "${NOTHING}" (plan R1-07); it says: ${text}`);
  assertLabel(text, SUPERSEDED, "superseded", "browser CONSISTENT + STALE");
});

test("RC45 R1-07 browser: Verify on a live card answering CONSISTENT with an established rejection's leftover (SUBMISSION_REJECTED) in settled[] renders good without \"Nothing was changed.\" and labels the entry a released leftover [RED on dc7552e]", async (t) => {
  const { el, text } = await verifyOnCard(t, { before: baseVault(), after: baseVault(), answer: { status: "CONSISTENT", vaultId: VAULT_ID, settled: [LEFTOVER] } });
  assert.equal(levelOf(el), "good");
  assert.ok(!text.includes(NOTHING), `a CONSISTENT answer that released leftover claims is not told "${NOTHING}" (plan R1-07); it says: ${text}`);
  assertLabel(text, LEFTOVER, "leftover", "browser CONSISTENT + SUBMISSION_REJECTED");
});

test("RC45 R1-07 browser (C8): Verify on the owner's TERMINATED_UNKNOWN card whose vault is live after the Verify, answering CONSISTENT with settled [] (restore()), shows a restore notice and not \"Nothing was changed.\" — derived from the card's prior status, with no new response field [RED on dc7552e]", async (t) => {
  const answer = { status: "CONSISTENT", vaultId: VAULT_ID, settled: [] };
  assert.deepEqual(Object.keys(answer).sort(), ["settled", "status", "vaultId"], "exactly the fields settleLive returns for CONSISTENT (no `restored` field)");
  const { el, text } = await verifyOnCard(t, { before: terminatedUnknownVault(), after: restoredVault(), answer });
  assert.equal(levelOf(el), "good");
  assert.match(text, RESTORE, `a restore is disclosed by a restore notice (plan R1-07, C8); it says: ${text}`);
  assert.ok(!text.includes(NOTHING), `a Verify that restored the vault is not told "${NOTHING}" (plan R1-07); it says: ${text}`);
});

test("RC45 R1-07 browser (C8): the restore notice also follows a restore answered CLAIM_PENDING (a claim on the restored live outpoint) — the card was TERMINATED_UNKNOWN before and is live (PAUSED) after [RED on dc7552e]", async (t) => {
  const reason = "the recorded outpoint is live and claimed; absence does not establish rejection; the claim is kept";
  const { el, text } = await verifyOnCard(t, { before: terminatedUnknownVault(), after: restoredVault({ paused: true }), answer: { status: "CLAIM_PENDING", vaultId: VAULT_ID, claimTxId: TX_C, reason } });
  assert.equal(levelOf(el), "warn", "CLAIM_PENDING stays warn");
  assert.match(withoutReason(text, reason), RESTORE, `a restore is disclosed by the web's restore notice (plan R1-07, C8; PR1-08 statuses); it says: ${text}`);
});

test("RC45 R1-07 browser (C8): the restore notice also follows a restore answered REQUEST_RECOVERY_REQUIRED (signed work on the restored live outpoint) [RED on dc7552e]", async (t) => {
  const reason = "signed work on the recorded outpoint may still execute and blocks other actions";
  const pending = { requestId: REQ_P, action: "agentSpend", state: "PREFLIGHT_VERIFIED", signerRole: "agent", txId: TX_C };
  const { el, text } = await verifyOnCard(t, { before: terminatedUnknownVault(), after: restoredVault(), answer: { status: "REQUEST_RECOVERY_REQUIRED", vaultId: VAULT_ID, requestId: REQ_P, pending: [pending], vaultStatus: "ACTIVE", recordedVaultClosed: false, reason } });
  assert.equal(levelOf(el), "warn", "REQUEST_RECOVERY_REQUIRED stays warn");
  assert.match(withoutReason(text, reason), RESTORE, `a restore is disclosed by the web's restore notice (plan R1-07, C8; PR1-08 statuses); it says: ${text}`);
});

test("RC45 R1-07 browser holds: Verify on a live card answering CONSISTENT with settled [] still says \"Nothing was changed.\" and shows no restore notice (the card was not TERMINATED_UNKNOWN)", async (t) => {
  const { el, text } = await verifyOnCard(t, { before: baseVault(), after: baseVault(), answer: { status: "CONSISTENT", vaultId: VAULT_ID, settled: [] } });
  assert.equal(levelOf(el), "good");
  assert.ok(text.includes(NOTHING), `nothing was written and nothing was restored: "${NOTHING}" stays; it says: ${text}`);
  assert.doesNotMatch(text, RESTORE, `no restore occurred, so no restore notice; it says: ${text}`);
});

test("RC45 R1-07 browser holds: Verify on the owner's TERMINATED_UNKNOWN card that is still not live after the Verify (CLAIM_PENDING below depth, whose own reason says \"restored at depth\"; UNKNOWN) shows no restore notice of the web's own", async (t) => {
  const belowReason = "the recorded live outpoint is observed below the settlement depth; the vault is restored at depth; nothing was written";
  const below = await verifyOnCard(t, { before: terminatedUnknownVault(), after: terminatedUnknownVault(), answer: { status: "CLAIM_PENDING", vaultId: VAULT_ID, reason: belowReason, depth: "250", required: "1000" } });
  assert.equal(levelOf(below.el), "warn");
  assert.doesNotMatch(withoutReason(below.text, belowReason), RESTORE, `below depth nothing was restored; the web adds no restore notice; it says: ${below.text}`);
  const unknownReason = "the recorded outpoint is spent and no known spender was seen";
  const unknown = await verifyOnCard(t, { before: terminatedUnknownVault(), after: terminatedUnknownVault(), answer: { status: "UNKNOWN", vaultId: VAULT_ID, reason: unknownReason, unchecked: 0 } });
  assert.equal(levelOf(unknown.el), "bad");
  assert.doesNotMatch(withoutReason(unknown.text, unknownReason), RESTORE, `UNKNOWN restores nothing; it says: ${unknown.text}`);
});
