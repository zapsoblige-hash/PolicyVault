"use strict";
/*
 * RC45 R1-10 — THE LEGACY CONSOLE AND v0.4-FAMILY VAULTS (finding S-04 of the
 * independent candidate review rc45-patch-independent-01; remediation plan
 * rc45-r1-plan-01 PLAN-R1 revision 2, §2 R1-10 and §4 R1-10 "legacy-console
 * legs: no automatic Verify for v0.4-family vaults, and statuses rendered
 * through the closed map"). Adapted from the review-only probe
 * review-surface-legacy-app (its A6 part; its Cancel part is R1-01's, pinned
 * in web/test/rc45-r1-01-legacy-cancel.test.js). Internal RED-first
 * regression material for the RC45 successor candidate; not an audit.
 *
 * The production page loads web/refusal-explain.js, then web/app.js (the
 * legacy console, "Legacy vault compatibility") and web/app-v4.js
 * (index.html :559, :580-581). app.js lists EVERY vault of GET /vaults,
 * v0.4-family ones included, and auto-verifies once per page load every vault
 * whose operational status is ACTION_REQUIRED_VERIFY (RC45 A6 badges a v0.4
 * vault so whenever a PENDING record sits on its live outpoint), rendering the
 * answer through its own v0.2 message table. The rules (plan R1-10):
 *   - app.js excludes v0.4-family vaults (contractVersion "policyvault-0.4" /
 *     "policyvault-0.4.1") from its automatic Verify;
 *   - it renders any Verify answer for a v0.4-family vault through
 *     refusal-explain.verifyStatus, the closed map (app-v4.js already owns
 *     these vaults).
 *
 * RED on dc7552e: a v0.4 / v0.4.1 vault badged ACTION_REQUIRED_VERIFY is
 * POSTed to /vaults/:id/reconcile on page load; a Verify answer for a v0.4
 * vault is rendered through the legacy table — CONSISTENT as "Vault verified.
 * No transaction occurred." in a neutral class, CHAIN_CONTRADICTION and
 * REQUEST_RECOVERY_REQUIRED as "Verification result: <STATUS>" in a neutral
 * class, UNKNOWN with the v0.2 text in "warn".
 * HOLDS on dc7552e (and must keep holding): a v0.2 vault badged
 * ACTION_REQUIRED_VERIFY is still auto-verified exactly once per page load,
 * and a v0.2 answer (reconcile-v2's CONSISTENT / CLAIM_RELEASED) keeps the
 * legacy console's own text.
 *
 * Readings chosen where the plan leaves a detail open (fail closed; recorded
 * in the R1-10 RED record):
 *   - "rendered through the closed map" means the status notice (#notice)
 *     carries the map's level (good / warn / bad) as its single level class —
 *     app.js note(message, cls) — or, when no level class is set, as the
 *     data-verify-level of renderVerifyHtml in its HTML, and shows the map's
 *     title for that answer; an unrecognised status also keeps its raw token;
 *   - the legacy table's sentence for that status is absent unless the closed
 *     map itself says it;
 *   - a manual Verify is driven exactly as the card's "Verify vault state"
 *     button does (pvActions.verify(vaultId)) on a TRANSACTION_PENDING card,
 *     which app.js never auto-verifies, so the rendering legs are independent
 *     of the auto-Verify legs.
 *
 * BROWSER layer: the REAL web/refusal-explain.js and web/app.js evaluated, in
 * index.html's order, in one vm sandbox with a recording fetch (the harness of
 * web/test/network-banner.test.js, web/test/rc45-r1-01-legacy-cancel.test.js
 * and the review probe); no server, no network. Synthetic presentation
 * documents and server-shaped Verify answers only (repeated-byte hex
 * identities).
 */
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const WEB_DIR = path.join(__dirname, "..");
const APP_JS = fs.readFileSync(path.join(WEB_DIR, "app.js"), "utf8");
const RX_JS = fs.readFileSync(path.join(WEB_DIR, "refusal-explain.js"), "utf8");
const RX = require("../refusal-explain.js");
const HEX = (b) => b.repeat(32);
const jsonResponse = (body, ok = true) => ({ ok, status: ok ? 200 : 403, json: async () => body });
const settle = async () => { for (let i = 0; i < 80; i++) await new Promise((r) => setImmediate(r)); };
const V04_FAMILY = Object.freeze(["policyvault-0.4.1", "policyvault-0.4"]);

/* `answers` maps vaultId -> the Verify answer (the route's `reconcile` field) or a function (n) -> answer. */
function makeEnv(vaults, answers = {}) {
  const elements = new Map(), calls = [];
  const element = (id) => {
    if (!elements.has(id)) elements.set(id, { id, innerHTML: "", textContent: "", className: "", value: "", disabled: false, style: {}, dataset: {}, options: [], onclick: null, addEventListener() {}, querySelectorAll: () => [], querySelector: () => null, classList: { toggle() {}, add() {}, remove() {} } });
    return elements.get(id);
  };
  const posted = {};
  const route = (p) => {
    const m = /\/vaults\/([0-9a-f]{64})\/reconcile$/.exec(p);
    if (m) {
      posted[m[1]] = (posted[m[1]] || 0) + 1;
      const a = answers[m[1]];
      const reconcile = typeof a === "function" ? a(posted[m[1]]) : a;
      if (!reconcile) return Promise.reject(new Error(`R1-10 fixture: no Verify answer for ${m[1]}`));
      return jsonResponse({ reconcile, vault: vaults.find((v) => v.vaultId === m[1]) || null });
    }
    if (p.endsWith("/health")) return jsonResponse({ ok: true, networkId: "testnet-10", authMode: "disabled" });
    if (p.endsWith("/network/status")) return jsonResponse({ networkId: "testnet-10", isSynced: true, virtualDaaScore: "1" });
    if (p.endsWith("/organizations")) return jsonResponse({ organizations: [], roleLabels: [], assignments: {}, assignmentsVersion: 0 });
    if (p.endsWith("/vaults")) return jsonResponse({ vaults });
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
  vm.runInContext(RX_JS, sandbox, { filename: "web/refusal-explain.js" });
  assert.equal(typeof sandbox.PolicyVaultRefusalExplain?.verifyStatus, "function", "the page's refusal-explain module is loaded before app.js (index.html :559)");
  vm.runInContext(APP_JS, sandbox, { filename: "web/app.js" });
  const reconcilePosts = (vaultId) => calls.filter((c) => c.method === "POST" && c.url.endsWith(`/vaults/${vaultId}/reconcile`));
  return { sandbox, element, calls, reconcilePosts };
}

/* A v0.4-family presentation (the review probe's shape) with operational status `operational`. */
function v4Vault(tag, contractVersion, operational) {
  return {
    vaultId: HEX(tag), label: `R1-10 ${tag}`, status: "ACTIVE", contractVersion, owner: HEX("11"),
    live: { outpoint: { transactionId: HEX("b1"), index: 0 }, covenantId: HEX("c1"), protectedValueKas: "500", feeReserveKas: "1", paused: false },
    operational
  };
}
/* A v0.2 presentation (web/test/rc45-r1-01-legacy-cancel.test.js's shape). */
function v2Vault(tag, operational) {
  return {
    vaultId: HEX(tag), label: `R1-10 ${tag}`, status: "ACTIVE", contractVersion: "policyvault-0.2", owner: HEX("11"), delegate: HEX("21"),
    policy: { maxPerSpendKas: "10", periodBudgetKas: "100", periodLengthDaa: "600" },
    live: { outpoint: { transactionId: HEX("b2"), index: 0 }, covenantId: HEX("c2"), protectedValueKas: "195", periodSpentKas: "5", remainingBudgetKas: "95", delegateActive: true, policyNonce: "0" },
    operational
  };
}
const ARV = (txTag) => ({ status: "ACTION_REQUIRED_VERIFY", claim: { txId: HEX(txTag), action: "agentSpend" }, reason: "a PENDING record sits on the live outpoint" });
const PENDING_TX = (txTag) => ({ status: "TRANSACTION_PENDING", request: { requestId: "0f0f0f0f-1111-4222-8333-000000001010", action: "agentSpend", state: "SUBMITTED", txId: HEX(txTag) } });

/* The legacy console's own v0.2 message table (web/app.js pvActions.verify), as at dc7552e. */
const LEGACY = Object.freeze({
  CONSISTENT: "Vault verified. No transaction occurred.",
  CLAIM_RELEASED: "Vault verified. No transaction occurred — the vault is available again.",
  ADVANCED: "Transaction confirmed on-chain — the vault advanced to the verified successor state.",
  TERMINAL: "This vault is closed.",
  CLAIM_PENDING: "Still verifying — the outcome cannot be proven yet. Try again in a couple of minutes.",
  UNKNOWN: "Automatic verification could not establish the vault state. Controls remain disabled."
});
const decode = (s) => String(s).replace(/<[^>]*>/g, " ").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&#39;|&#x27;/g, "'").replace(/&amp;/g, "&");
const norm = (s) => String(s ?? "").replace(/\s+/g, " ").trim();
/* What the notice shows: its text and the text of any HTML it carries. */
const shown = (el) => norm(`${el.textContent} ${decode(el.innerHTML)}`);
/* The level the notice carries: its single good/warn/bad class, else the data-verify-level of its HTML. */
function levelShown(el) {
  const classes = String(el.className).split(/\s+/).filter((c) => ["good", "warn", "bad"].includes(c));
  assert.ok(classes.length <= 1, `the notice carries at most one level class (className "${el.className}")`);
  if (classes.length === 1) return classes[0];
  const m = /data-verify-level="(good|warn|bad)"/.exec(String(el.innerHTML));
  return m ? m[1] : null;
}
/* Assert the notice renders `answer` through the closed map (plan R1-10). */
function assertClosedMap(el, answer, where) {
  const view = RX.verifyStatus(answer);
  const text = shown(el);
  assert.equal(levelShown(el), view.level, `${where}: the notice carries the closed map's level "${view.level}" for ${answer.status} (plan R1-10); className "${el.className}", it says: ${text}`);
  assert.ok(text.includes(view.title), `${where}: the notice shows the closed map's title "${view.title}" (plan R1-10); it says: ${text}`);
  const legacy = LEGACY[answer.status] ?? `Verification result: ${answer.status}`;
  const mapSays = norm(`${view.title} ${view.lines.join(" ")}`);
  if (!mapSays.includes(legacy)) assert.ok(!text.includes(legacy), `${where}: the legacy v0.2 table's "${legacy}" is not shown for a v0.4-family vault; it says: ${text}`);
  if (!view.known) assert.ok(text.includes(answer.status), `${where}: an unrecognised answer keeps its raw token; it says: ${text}`);
}

/* ======================= no automatic Verify for v0.4-family vaults ======================= */

for (const version of V04_FAMILY) {
  test(`RC45 R1-10 legacy console: a ${version} vault badged ACTION_REQUIRED_VERIFY (RC45 A6) is not auto-verified on page load — no POST /vaults/:id/reconcile [RED on dc7552e]`, async () => {
    const v = v4Vault(version === "policyvault-0.4" ? "e4" : "e1", version, ARV("d1"));
    const env = makeEnv([v], { [v.vaultId]: { status: "CHAIN_CONTRADICTION", vaultId: v.vaultId, reason: "the recorded predecessor is live again; nothing was written" } });
    await settle();
    assert.ok(env.element("vaults").innerHTML.includes(v.vaultId), "the legacy console lists the vault");
    assert.equal(env.reconcilePosts(v.vaultId).length, 0, `app.js excludes ${version} vaults from its automatic Verify (plan R1-10; app-v4.js owns them)`);
  });
}

test("RC45 R1-10 legacy console: in a mixed list of ACTION_REQUIRED_VERIFY vaults only the v0.2 vault is auto-verified (exactly once); the v0.4.1 and v0.4 vaults are not [RED on dc7552e]", async () => {
  const v2 = v2Vault("a2", ARV("d2")), v41 = v4Vault("e2", "policyvault-0.4.1", ARV("d3")), v40 = v4Vault("e3", "policyvault-0.4", ARV("d4"));
  const answer = (v) => ({ status: "CONSISTENT", vaultId: v.vaultId, settled: [] });
  const env = makeEnv([v2, v41, v40], { [v2.vaultId]: answer(v2), [v41.vaultId]: answer(v41), [v40.vaultId]: answer(v40) });
  await settle();
  const posts = env.calls.filter((c) => c.method === "POST" && /\/reconcile$/.test(c.url)).map((c) => c.url);
  assert.deepEqual(posts, [`/api/v1/vaults/${v2.vaultId}/reconcile`], "only the v0.2 vault is auto-verified, once (plan R1-10)");
});

test("RC45 R1-10 legacy console holds: a v0.2 vault badged ACTION_REQUIRED_VERIFY is still auto-verified exactly once per page load, and its CONSISTENT answer keeps the console's own text", async () => {
  const v = v2Vault("a3", ARV("d5"));
  const env = makeEnv([v], { [v.vaultId]: { status: "CONSISTENT", vaultId: v.vaultId } });
  await settle();
  assert.equal(env.reconcilePosts(v.vaultId).length, 1, "one automatic Verify per page load (reconcile-v2's exact proof rules)");
  assert.equal(env.element("notice").textContent, LEGACY.CONSISTENT, "the v0.2 answer keeps the legacy console's text");
});

/* ======================= Verify answers for v0.4-family vaults rendered through the closed map ======================= */

const ANSWERS = Object.freeze([
  ["CONSISTENT", (id) => ({ status: "CONSISTENT", vaultId: id, settled: [] })],
  ["ADVANCED", (id) => ({ status: "ADVANCED", vaultId: id, to: "ownerPause", txId: HEX("a1"), requestId: "0f8a0a01-0000-4000-8000-000000000a01", stateId: HEX("5a"), settled: [] })],
  ["TERMINAL", () => ({ status: "TERMINAL", vaultStatus: "RECOVERED" })],
  ["CLAIM_PENDING", (id) => ({ status: "CLAIM_PENDING", vaultId: id, txId: HEX("a2"), depth: "250", required: "1000", reason: "a recorded transaction spending the recorded outpoint is observed below the settlement depth; nothing was written" })],
  ["REQUEST_RECOVERY_REQUIRED", (id) => ({ status: "REQUEST_RECOVERY_REQUIRED", vaultId: id, requestId: "0f8a0a02-0000-4000-8000-000000000a02", pending: [{ requestId: "0f8a0a02-0000-4000-8000-000000000a02", action: "agentSpend", state: "PREFLIGHT_VERIFIED", txId: HEX("a3"), signerRole: "agent" }], vaultStatus: "ACTIVE", recordedVaultClosed: false, reason: "signed work on the recorded outpoint may still execute and blocks other actions" })],
  ["UNKNOWN", (id) => ({ status: "UNKNOWN", vaultId: id, reason: "the recorded outpoint is spent and no known spender was seen", unchecked: 0 })],
  ["CHAIN_CONTRADICTION", (id) => ({ status: "CHAIN_CONTRADICTION", vaultId: id, reason: "the recorded predecessor is live again; nothing was written" })],
  ["SOMETHING_NEW_42", (id) => ({ status: "SOMETHING_NEW_42", vaultId: id })]
]);

for (const [status, make] of ANSWERS) {
  test(`RC45 R1-10 legacy console: a Verify of a policyvault-0.4.1 vault (its card's "Verify vault state") answering ${status} is rendered through refusal-explain.verifyStatus — the closed map's level and title, not the legacy v0.2 table [RED on dc7552e]`, async () => {
    const v = v4Vault("f1", "policyvault-0.4.1", PENDING_TX("c3"));
    const answer = make(v.vaultId);
    const env = makeEnv([v], { [v.vaultId]: answer });
    await settle();
    assert.equal(env.reconcilePosts(v.vaultId).length, 0, "a TRANSACTION_PENDING card is never auto-verified");
    assert.ok(env.element("vaults").innerHTML.includes(`pvActions.verify('${v.vaultId}')`), "the card offers Verify vault state");
    await env.sandbox.window.pvActions.verify(v.vaultId);
    await settle();
    assert.equal(env.reconcilePosts(v.vaultId).length, 1, "one Verify post");
    assertClosedMap(env.element("notice"), answer, `v0.4.1 ${status}`);
  });
}

test("RC45 R1-10 legacy console (review probe A6): a policyvault-0.4 vault's CHAIN_CONTRADICTION is rendered through the closed map in the bad class, never neutrally [RED on dc7552e]", async () => {
  const v = v4Vault("f4", "policyvault-0.4", PENDING_TX("c4"));
  const answer = { status: "CHAIN_CONTRADICTION", vaultId: v.vaultId, reason: "the chain currently contradicts the record" };
  const env = makeEnv([v], { [v.vaultId]: answer });
  await settle();
  await env.sandbox.window.pvActions.verify(v.vaultId);
  await settle();
  assert.equal(levelShown(env.element("notice")), "bad", `the contradiction is bad (closed map), className "${env.element("notice").className}"`);
  assertClosedMap(env.element("notice"), answer, "v0.4 CHAIN_CONTRADICTION");
});

test("RC45 R1-10 legacy console holds: a v0.2 vault's Verify answers keep the console's own reconcile-v2 texts (CLAIM_RELEASED, CONSISTENT) — the closed v0.4 map is not applied to v0.2", async () => {
  const v = v2Vault("a4", { status: "TRANSACTION_PENDING", request: { requestId: "0f0f0f0f-1111-4222-8333-000000002020", action: "delegateSpend", state: "SUBMITTED", txId: HEX("c5") } });
  const answers = [{ status: "CLAIM_RELEASED", vaultId: v.vaultId }, { status: "CONSISTENT", vaultId: v.vaultId }];
  const env = makeEnv([v], { [v.vaultId]: (n) => answers[n - 1] });
  await settle();
  await env.sandbox.window.pvActions.verify(v.vaultId);
  await settle();
  assert.equal(env.element("notice").textContent, LEGACY.CLAIM_RELEASED, "reconcile-v2's CLAIM_RELEASED keeps the console's text");
  await env.sandbox.window.pvActions.verify(v.vaultId);
  await settle();
  assert.equal(env.element("notice").textContent, LEGACY.CONSISTENT, "reconcile-v2's CONSISTENT keeps the console's text");
});
