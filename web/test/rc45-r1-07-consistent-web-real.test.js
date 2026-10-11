"use strict";

/*
 * RC45 R1-07 — CANDIDATE-WRITTEN VERIFY ANSWERS THAT WROTE, RENDERED BY THE
 * REAL WEB (finding F-02 of the independent candidate review
 * rc45-patch-independent-01; remediation plan rc45-r1-plan-01 PLAN-R1
 * revision 2, §2 R1-07 with condition C8, §4 R1-07). Adapted from the
 * review-only probe review-lead-consistent-web (lead): P2a (a twin completed
 * by settleOneHop) and P2b (a SYNTHETIC RC44 case-E TERMINATED_UNKNOWN
 * restored by Verify), extended with a supersession (STALE) and an
 * established rejection's leftover (SUBMISSION_REJECTED). Internal RED-first
 * regression material for the RC45 successor candidate; not an audit.
 *
 * Every answer here is the candidate's own: the real hosted Verify route
 * (server/src/api.js handle, POST /vaults/:id/reconcile, self-hosted) over the
 * real reconcileVaultV4, whose module-cache export is wrapped only to pass the
 * explicit chain model's rpc (plan r2 §8 rules CR-M14, CR2-L12); the card
 * documents are the real GET /vaults presentations before and after the
 * Verify. Those exact bodies are then served to the REAL web/app-v4.js and
 * web/refusal-explain.js in jsdom (the harness of
 * web/test/rc45-t8-verify-web.test.js), and the closed map is also asked
 * directly. The fixture-driven legs are in
 * web/test/rc45-r1-07-verify-writes-web.test.js (its readings apply here).
 *
 * RED on dc7552e: each of these CONSISTENT answers wrote (a completion, a
 * supersession, a leftover release, a restore) and the web says "Nothing was
 * changed.", labels every settled[] entry "an established rejection's
 * leftover claim", and gives no restore notice.
 * HOLDS on dc7552e (and must keep holding): the answers are exactly
 * {status, vaultId, settled} (no new response field, C8); a further Verify
 * writes nothing and is still told "Nothing was changed." with no restore
 * notice.
 *
 * Populations (candidate-written; TEST keys 0x11 owner / 0x21 agent): F5 kit
 * vaults; tw: two owner Pauses with the same fuel (twins, one txid), both
 * finalized; sp: the delegate's spend D and the owner's Pause Q finalized
 * apart (D holds the only claim on L0); lo: the delegate's spend finalized.
 * Real v0.4.1 compiler, pv_call_encoder, TEST-key signatures and the pinned
 * pv_vm_preflight for every consensus byte. SYNTHETIC (labelled where used):
 * the in-process store fault that stops Verify before its loser settlement
 * (sp) and before the leftover claim release of a rejected submit (lo, the
 * T3 leftover leg's interruption), and the TERMINATED_UNKNOWN rewrite (P2b,
 * as the review probe made it). Node observations come only from the explicit
 * chain model of sdk/testutil/rc45-f5-kit.js; every config names
 * ws://127.0.0.1:1, so nothing can dial a node. Both stores: JSON always;
 * PostgreSQL with POLICYVAULT_TEST_PG_{PORT,USER,DATABASE} (the rc45 runner's
 * pg mode; a skipped PostgreSQL leg there is a FAIL).
 */

const path = require("node:path");
const fs = require("node:fs");
const assert = require("node:assert/strict");
const { test, before, after } = require("node:test");
const { JSDOM, VirtualConsole } = require("../../sdk/node_modules/jsdom");
const K = require("../../sdk/testutil/rc45-f5-kit");
const F3 = require("../../sdk/testutil/rc45-f3-kit");
const { LOOPBACK, SETTLE_DEPTH_DAA, frozenOf } = K;

const SDK_SRC = path.join(__dirname, "..", "..", "sdk", "src");
const cand = K.modulesOf(SDK_SRC);
const { Categories } = cand.store;
const { recordedNegativeIsEstablished } = require(path.join(SDK_SRC, "submission-classification.js"));
const TOOLCHAIN = require("../../sdk/testutil/org-root-durable-fixture").toolchainAvailable();
const RX = require("../refusal-explain.js");
const WEB_DIR = path.join(__dirname, "..");
const HTML = fs.readFileSync(path.join(WEB_DIR, "index.html"), "utf8");
const SCRIPTS = ["core-bundle.js", "setup-ui.js", "refusal-explain.js", "app-v4.js"].map((name) => ({ name, source: fs.readFileSync(path.join(WEB_DIR, name), "utf8") }));
const PG = K.pgFromEnv();
const PG_AVAILABLE = Boolean(PG.port && PG.user && PG.database);
const V = Object.freeze({ tw: K.vault("r107-tw"), sp: K.vault("r107-sp"), lo: K.vault("r107-lo") });
const NOTHING = "Nothing was changed.";
const RESTORE = /\brestor/i;
const LABEL = Object.freeze({ completed: /\bcomplet/i, superseded: /\bsupersed/i, released: /\breleas/i, leftover: /leftover/i, rejection: /\breject/i });
const roots = [], stores = [], databases = [];
let admin = null, serial = 0, history = null, B = null, w = null, templateRoot = null;
const mk = (prefix) => { const dir = K.ownedTempRoot(prefix); roots.push(dir); return dir; };
const track = (root) => roots.push(root);
const settle = (promise) => promise.then((value) => ({ value, error: null }), (error) => ({ value: null, error }));
const norm = (s) => String(s ?? "").replace(/\s+/g, " ").trim();
/* The visible text of a rendered region, its text nodes joined by spaces (jsdom's textContent runs adjacent blocks together). */
function textOf(el) {
  const doc = el.ownerDocument, walker = doc.createTreeWalker(el, doc.defaultView.NodeFilter.SHOW_TEXT), parts = [];
  for (let n = walker.nextNode(); n; n = walker.nextNode()) parts.push(n.data);
  return norm(parts.join(" "));
}
const listed = (text, entry) => [entry.requestId, entry.txId].filter(Boolean).some((id) => text.includes(id.slice(0, 8)));

before(async () => {
  assert.ok(TOOLCHAIN, "real compiler, encoder and VM are required (a missing VM toolchain is a FAIL, never a SKIP)");
  const template = cand.config.loadConfig({ dataRoot: mk("pv-rc45-r107-template-"), rpcUrl: LOOPBACK });
  assert.equal(template.tenancyEnforced, false, "self-hosted template");
  w = K.walletsFor(template);
  const k = K.kitFor(cand, template, w), id = (r) => r.requestId;
  B = {};
  { // tw (review P2a): two owner Pauses with the same fuel on L0 (one transaction, twins), both finalized.
    const v = V.tw; await K.seedVault(cand, template, v, w);
    const q1 = await k.ownerOp(v, "ownerPause"); await K.sleep(3);
    const q2 = await k.ownerOp(v, "ownerPause");
    assert.equal(q1.txId, q2.txId, "same fuel: one transaction (twins)");
    const f1 = await k.finalize(q1, w.owner), f2 = await k.finalize(q2, w.owner);
    assert.equal(f1.state, "PREFLIGHT_VERIFIED"); assert.equal(f2.state, "PREFLIGHT_VERIFIED");
    B.tw = { q1: id(q1), q2: id(q2) };
  }
  { // sp: the delegate's spend D and the owner's Pause Q on L0, finalized apart (D holds the only claim; contested).
    const v = V.sp; await K.seedVault(cand, template, v, w);
    const d = await k.agentSpend(v, 4); await K.sleep(3);
    const q = await k.ownerOp(v, "ownerPause");
    await K.finalizeApart(cand, template, [{ requestId: d.requestId, signer: w.agent }, { requestId: q.requestId, signer: w.owner }], { claimHolder: d.requestId, track });
    B.sp = { d: id(d), q: id(q) };
  }
  { // lo: the delegate's spend finalized (holds its claim on L0).
    const v = V.lo; await K.seedVault(cand, template, v, w);
    B.lo = { d: id(await k.finalize(await k.agentSpend(v, 4), w.agent)) };
  }
  history = await K.snapshot(cand, template);
  templateRoot = template.dataRoot;
  if (PG_AVAILABLE) admin = new (require("pg").Pool)(PG);
});
after(async () => {
  for (const s of stores) { try { await s.close(); } catch { /* closed */ } }
  if (admin) { for (const db of databases) await admin.query(`DROP DATABASE IF EXISTS ${db} WITH (FORCE)`); await admin.end(); }
  for (const root of roots) K.removeOwnedRoot(root);
});

/* A fresh self-hosted case over the template history. */
async function fresh(backend) {
  const dataRoot = mk("pv-rc45-r107-case-");
  K.warmCompileCache(templateRoot, dataRoot);
  let config, pgDatabase = null;
  if (backend === "PostgreSQL") {
    pgDatabase = `pv_rc45_r107_${process.pid}_${++serial}`;
    await admin.query(`CREATE DATABASE ${pgDatabase}`); databases.push(pgDatabase);
    config = cand.config.loadConfig({ persistenceBackend: "postgres", pgHost: PG.host, pgPort: PG.port, pgUser: PG.user, pgDatabase, pgNoTls: true, hostedDevOpen: true, dataRoot, rpcUrl: LOOPBACK });
    stores.push(await cand.store.openPgStore(config, { migrate: true }));
    assert.equal(cand.store.getStore(config).kind, "postgres");
  } else config = cand.config.loadConfig({ dataRoot, rpcUrl: LOOPBACK });
  assert.equal(config.tenancyEnforced, false, "self-hosted case");
  await K.install(cand, config, history);
  const store = cand.store.getStore(config), model = K.chainModel(config), api = F3.apiFor(config);
  const x = {
    config, store, model, pgDatabase, api,
    req: (requestId) => cand.wr4.loadRequest(config, requestId),
    rawRequest: (requestId) => store.read(Categories.REQUEST, requestId),
    rawManifest: (v) => store.read(Categories.VAULT, v.vaultId),
    snap: () => K.snapshot(cand, config),
    submit: (requestId) => cand.submit4.submitWalletRequestV4({ config, requestId, rpc: model.rpc, pollAttempts: 1, pollDelayMs: 0 }),
    verify: (v) => cand.reconcile4.reconcileVaultV4(config, v.vaultId, { rpc: model.rpc }),
    /* GET /vaults through the real route: the card document of `v`. */
    async card(v) {
      const r = await api.call("GET", ["vaults"]);
      assert.equal(r.status, 200, `GET /vaults answers (${r.code ?? ""} ${r.message ?? ""})`);
      const doc = r.body.vaults.find((d) => d && d.vaultId === v.vaultId);
      assert.ok(doc, `GET /vaults presents ${v.tag}`);
      return K.jsonSafe(doc);
    },
    /* POST /vaults/:id/reconcile through the REAL reconcileVaultV4 wrapped with the explicit chain model's rpc. */
    async verifyRoute(v) {
      const m4 = require(path.join(SDK_SRC, "reconcile-v4.js")), real4 = m4.reconcileVaultV4;
      m4.reconcileVaultV4 = (c, vid, options = {}) => real4(c, vid, { ...options, rpc: model.rpc });
      let r;
      try { r = await api.call("POST", ["vaults", v.vaultId, "reconcile"], {}); } finally { m4.reconcileVaultV4 = real4; }
      assert.equal(r.status, 200, `the Verify route answers (${r.code ?? ""} ${r.message ?? ""})`);
      return K.jsonSafe(r.body);
    }
  };
  return x;
}
async function release(x) {
  if (!x.pgDatabase) return;
  const i = stores.indexOf(x.store);
  if (i >= 0) { stores.splice(i, 1); await x.store.close(); }
}
/* One in-process store fault (the next matching durable step throws instead of being performed). SYNTHETIC. */
function storeFault(store, when) {
  const names = ["write", "createExclusive", "remove", "appendAudit"], own = {};
  let fired = false;
  for (const name of names) {
    own[name] = Object.prototype.hasOwnProperty.call(store, name) ? store[name] : undefined;
    const original = store[name].bind(store);
    store[name] = async (...args) => {
      if (!fired && when(name, args)) { fired = true; throw new Error(`TEST store fault at ${name}`); }
      return original(...args);
    };
  }
  return { get fired() { return fired; }, restore() { for (const name of names) { if (own[name] === undefined) delete store[name]; else store[name] = own[name]; } } };
}

/* ---------------- the browser (real app-v4.js) fed the real route bodies ---------------- */
async function ticks(n = 30) { for (let i = 0; i < n; i++) await new Promise((resolve) => setImmediate(resolve)); }
async function waitFor(predicate, message, limit = 400) {
  for (let i = 0; i < limit; i++) { if (predicate()) return; await new Promise((resolve) => setImmediate(resolve)); }
  assert.ok(predicate(), message);
}
/* Serve `before` as the card until the Verify, the real Verify body, then `after`; click Verify; return the status region text. */
async function renderInBrowser(t, { vaultId, before: beforeDoc, body, after: afterDoc }) {
  const vc = new VirtualConsole();
  const dom = new JSDOM(HTML, { url: "https://policyvault-fixture.invalid/", runScripts: "outside-only", pretendToBeVisual: true, virtualConsole: vc });
  t.after(async () => { await ticks(5); dom.window.close(); });
  const { window } = dom;
  const document = window.document;
  const calls = [];
  let posted = 0;
  const reply = (b, status = 200) => ({ ok: status < 400, status, statusText: String(status), json: async () => b });
  window.confirm = () => true;
  window.prompt = () => null;
  window.fetch = async (url, options = {}) => {
    const target = new URL(url, window.location);
    assert.equal(target.origin, window.location.origin, "the fixture never reaches an external origin");
    const method = options.method || "GET";
    const route = target.pathname.replace(/^\/api\/v1/, "");
    calls.push({ method, route });
    if (method === "POST" && route === `/vaults/${vaultId}/reconcile`) { posted += 1; return reply(body); }
    if (method === "GET" && route === "/health") return reply({ networkId: "testnet-10" });
    if (method === "GET" && route === "/network/status") return reply({ networkId: "testnet-10", virtualDaaScore: "90000000" });
    if (method === "GET" && route === "/capabilities") return reply({ networkId: "testnet-10", contract: { creatableCovenantVersions: ["policyvault-0.4.1"] } });
    if (method === "GET" && route === "/vaults") return reply({ vaults: [posted === 0 ? beforeDoc : afterDoc] });
    if (method === "GET" && route === "/organizations") return reply({ organizations: [], assignments: {}, assignmentsVersion: null });
    if (method === "GET" && route === "/wallet/v4/requests") return reply({ requests: [] });
    const s = /^\/vaults\/([0-9a-f]{64})\/agent-suspensions$/.exec(route);
    if (method === "GET" && s) return reply({ suspensions: { schema: "policyvault-agent-suspensions/v1", vaultId: s[1], version: 1, allAgents: false, agents: [], updatedAt: "2026-09-29T00:00:00.000Z", updatedBy: { type: "wallet", identityId: null }, notice: "hosted coordination control; not a covenant control" } });
    if (method === "GET" && route === "/org-roots") return reply({ orgRoots: [] });
    if (method === "GET" && route === "/wallet/v7/vaults") return reply({ vaults: [] });
    if (method === "GET" && route === "/wallet/v7/requests") return reply({ requests: [] });
    return reply({ error: { code: "FIXTURE_UNMAPPED", message: `unmapped fixture route ${method} ${route}` } }, 404);
  };
  const snapshot = {
    connected: true, ready: true, address: w.owner.address, xonly: w.owner.xonly, network: "testnet-10", serverNetwork: "testnet-10", auth: "AUTHENTICATED", provider: "fixture",
    adapter: { signInputs: async () => { throw new Error("R1-07 fixture: nothing signs"); } }
  };
  window.PolicyVaultHealthPromise = Promise.resolve({ networkId: "testnet-10" });
  window.PolicyVaultWalletSession = { active: () => snapshot, subscribe(fn) { fn(snapshot); return () => {}; } };
  for (const { name, source } of SCRIPTS) window.eval(`${source}\n//# sourceURL=${name}`);
  const tabsWired = () => { const tab = document.querySelector('.v4-tab[data-view="vaults"]') || document.querySelector(".v4-tab"); return tab && typeof tab.onclick === "function"; };
  for (let i = 0; i < 20 && !tabsWired(); i++) await ticks(1);
  if (!tabsWired()) window.dispatchEvent(new window.Event("DOMContentLoaded"));
  await waitFor(tabsWired, "app navigation initialized");
  await waitFor(() => document.querySelector('[data-status="All"]'), "the vaults view rendered its filter bar");
  document.querySelector('[data-status="All"]').click();
  await ticks();
  await waitFor(() => document.querySelector(`[data-verify="${vaultId}"]`), "the owner's card offers Verify state");
  document.querySelector(`[data-verify="${vaultId}"]`).click();
  await waitFor(() => posted === 1, "Verify posted the reconcile request");
  await ticks(80);
  const el = document.getElementById("v4-notice");
  return { el, text: textOf(el) };
}
function assertLabel(text, entry, kind, where) {
  assert.ok(listed(text, entry), `${where}: the settled entry ${entry.requestId} is listed; it says: ${text}`);
  if (kind === "completed") {
    assert.match(text, LABEL.completed, `${where}: a CHAIN_VERIFIED entry is labelled completed (plan R1-07); it says: ${text}`);
    assert.doesNotMatch(text, LABEL.leftover, `${where}: a completion is never told as an established rejection's leftover; it says: ${text}`);
    assert.doesNotMatch(text, LABEL.rejection, `${where}: a completion is never told as a rejection; it says: ${text}`);
  } else if (kind === "superseded") {
    assert.match(text, LABEL.superseded, `${where}: a STALE entry is labelled superseded (plan R1-07); it says: ${text}`);
    assert.doesNotMatch(text, LABEL.leftover, `${where}: a supersession is never told as an established rejection's leftover; it says: ${text}`);
    assert.doesNotMatch(text, LABEL.rejection, `${where}: a supersession is never told as a rejection; it says: ${text}`);
  } else {
    assert.match(text, LABEL.released, `${where}: a SUBMISSION_REJECTED entry is labelled released (plan R1-07); it says: ${text}`);
    assert.match(text, LABEL.leftover, `${where}: a SUBMISSION_REJECTED entry is labelled a leftover (plan R1-07); it says: ${text}`);
    assert.doesNotMatch(text, LABEL.completed, `${where}: a released leftover is never told as a completion; it says: ${text}`);
    assert.doesNotMatch(text, LABEL.superseded, `${where}: a released leftover is never told as a supersession; it says: ${text}`);
  }
}
const CONSISTENT_KEYS = Object.freeze(["settled", "status", "vaultId"]);

/* ---------------- populations driven to a CONSISTENT answer that writes ---------------- */
/* P2a: q1 completes uncontested at zero depth (L-2), leaving its twin q2 PREFLIGHT_VERIFIED on the ancestor; then depth D. */
async function twinsAtDepth(x) {
  const q1 = await x.req(B.tw.q1);
  x.model.know(q1); x.model.seedInputs(frozenOf(q1), q1.covenantId); x.model.confirmOnSubmit = true;
  let sub;
  try { sub = await x.submit(q1.requestId); } finally { x.model.confirmOnSubmit = false; }
  assert.equal(sub.request.state, "CHAIN_VERIFIED", "the uncontested non-terminal break-glass completes at zero depth (L-2)");
  assert.equal((await x.rawRequest(B.tw.q2)).state, "PREFLIGHT_VERIFIED", "the twin is left on the ancestor");
  x.model.advance(SETTLE_DEPTH_DAA);
}
/* sp: Q lands and reaches D; Verify completes Q and is stopped (SYNTHETIC fault) before its loser settlement. */
async function winnerWithoutLoserSettlement(x) {
  const q = await x.req(B.sp.q);
  x.model.seedInputs(frozenOf(q), q.covenantId); x.model.confirm(frozenOf(q), q.txId); x.model.advance(SETTLE_DEPTH_DAA);
  const f = storeFault(x.store, (name, args) => name === "appendAudit" && args[0] && args[0].action === "transition_superseded");
  let first;
  try { first = await settle(x.verify(V.sp)); } finally { f.restore(); }
  assert.equal(f.fired, true, "the fault fired at the loser's transition_superseded row");
  assert.ok(first.error && /TEST store fault/.test(String(first.error.message)), "the faulted Verify stopped at the fault");
  assert.equal((await x.rawManifest(V.sp)).latestTransitionTxId, q.txId, "the manifest is advanced by Q");
  assert.equal((await x.rawRequest(B.sp.q)).state, "CHAIN_VERIFIED", "Q is completed");
  assert.equal((await x.rawRequest(B.sp.d)).state, "PREFLIGHT_VERIFIED", "the delegate's D is not yet settled");
}
/* lo: D's submit is rejected (established negative) and stopped (SYNTHETIC fault) before its leftover claim release (T3 leg). */
async function establishedLeftover(x) {
  const d = await x.req(B.lo.d), L = d.predecessorOutpoint, key = cand.claims.transitionClaimKey(L);
  x.model.know(d); x.model.seedInputs(frozenOf(d), d.covenantId);
  x.model.mempoolAdd(K.hex("rc45-r1-07-lo-out-of-app-spend"), [L]); // an out-of-app spend of L waits in the mempool
  const f = storeFault(x.store, (name, args) => name === "remove" && args[0] === Categories.TRANSITION_CLAIM && args[1] === key);
  let run;
  try { run = await settle(x.submit(d.requestId)); } finally { f.restore(); }
  assert.equal(f.fired, true, `the rejected submit reached its claim release (${run.error && run.error.message})`);
  const rejected = await x.rawRequest(d.requestId);
  assert.equal(rejected.state, "SUBMISSION_REJECTED"); assert.equal(recordedNegativeIsEstablished(rejected), true, "the rejection is an established negative");
  assert.ok(await x.store.read(Categories.TRANSITION_CLAIM, key), "its leftover transition claim on L");
}
/* The route Verify of `v` with its real card documents, its durable effect and the browser rendering. */
async function verifyAndRender(t, x, v) {
  const beforeDoc = await x.card(v), beforeSnap = await x.snap();
  const body = await x.verifyRoute(v);
  const afterSnap = await x.snap(), afterDoc = await x.card(v);
  const wrote = K.canonicalState(beforeSnap) !== K.canonicalState(afterSnap);
  const web = await renderInBrowser(t, { vaultId: v.vaultId, before: beforeDoc, body, after: afterDoc });
  return { answer: body.reconcile, body, beforeDoc, afterDoc, wrote, web, map: RX.verifyStatus(body.reconcile) };
}

const PG_SKIP = PG_AVAILABLE ? undefined : "REQUIREMENT_NOT_AVAILABLE in this process: isolated PostgreSQL (the rc45 runner's pg mode runs these legs; a skipped PostgreSQL leg there is a FAIL)";
for (const [backend, skip] of [["JSON", undefined], ["PostgreSQL", PG_SKIP]]) {
  const r107 = (name, fn) => test(`RC45 R1-07 ${backend}: ${name}`, { skip }, async (t) => { const x = await fresh(backend); try { await fn(t, x); } finally { await release(x); } });

  r107("review P2a: the route Verify at depth D completes the twin left on the ancestor (settleOneHop) and answers CONSISTENT {status, vaultId, settled: [the twin, CHAIN_VERIFIED]}; the map and the real web omit \"Nothing was changed.\" and label the twin completed, never a leftover [RED on dc7552e]", async (t, x) => {
    await twinsAtDepth(x);
    const r = await verifyAndRender(t, x, V.tw);
    assert.equal(r.answer.status, "CONSISTENT"); assert.deepEqual(Object.keys(r.answer).sort(), CONSISTENT_KEYS, "no new response field (C8)");
    const twin = r.answer.settled.find((e) => e.requestId === B.tw.q2);
    assert.ok(twin && twin.state === "CHAIN_VERIFIED", `settled[] reports the completed twin (${JSON.stringify(r.answer.settled)})`);
    assert.equal(r.wrote, true, "this CONSISTENT answer wrote durable state");
    assert.equal((await x.rawRequest(B.tw.q2)).state, "CHAIN_VERIFIED");
    assert.ok(!r.map.lines.includes(NOTHING), `the closed map omits "${NOTHING}" for an answer that wrote (plan R1-07); lines: ${JSON.stringify(r.map.lines)}`);
    assert.ok(!r.web.text.includes(NOTHING), `the real web omits "${NOTHING}" (plan R1-07); it says: ${r.web.text}`);
    assertLabel(r.web.text, twin, "completed", "real web, P2a");
  });

  r107("a supersession: Verify completed the owner's Q and stopped (SYNTHETIC fault) before settling the delegate's D; the next route Verify supersedes D (settleOneHop) and answers CONSISTENT {settled: [D, STALE]}; the map and the real web omit \"Nothing was changed.\" and label D superseded [RED on dc7552e]", async (t, x) => {
    await winnerWithoutLoserSettlement(x);
    const r = await verifyAndRender(t, x, V.sp);
    assert.equal(r.answer.status, "CONSISTENT"); assert.deepEqual(Object.keys(r.answer).sort(), CONSISTENT_KEYS, "no new response field (C8)");
    const loser = r.answer.settled.find((e) => e.requestId === B.sp.d);
    assert.ok(loser && loser.state === "STALE", `settled[] reports the superseded D (${JSON.stringify(r.answer.settled)})`);
    assert.equal(r.wrote, true, "this CONSISTENT answer wrote durable state");
    assert.ok(!r.map.lines.includes(NOTHING), `the closed map omits "${NOTHING}" for an answer that wrote (plan R1-07); lines: ${JSON.stringify(r.map.lines)}`);
    assert.ok(!r.web.text.includes(NOTHING), `the real web omits "${NOTHING}" (plan R1-07); it says: ${r.web.text}`);
    assertLabel(r.web.text, loser, "superseded", "real web, supersession");
  });

  r107("an established rejection's leftover: D's rejected submit stopped (SYNTHETIC fault) before releasing its claim; the route Verify with L live releases the claims and the reservation (releaseEstablishedLeftover) and answers CONSISTENT {settled: [D, SUBMISSION_REJECTED]}; the map and the real web omit \"Nothing was changed.\" and label D a released leftover [RED on dc7552e]", async (t, x) => {
    await establishedLeftover(x);
    const r = await verifyAndRender(t, x, V.lo);
    assert.equal(r.answer.status, "CONSISTENT"); assert.deepEqual(Object.keys(r.answer).sort(), CONSISTENT_KEYS, "no new response field (C8)");
    const left = r.answer.settled.find((e) => e.requestId === B.lo.d);
    assert.ok(left && left.state === "SUBMISSION_REJECTED", `settled[] reports the released leftover (${JSON.stringify(r.answer.settled)})`);
    assert.equal(r.wrote, true, "this CONSISTENT answer wrote durable state (claims and reservation released)");
    assert.ok(!r.map.lines.includes(NOTHING), `the closed map omits "${NOTHING}" for an answer that wrote (plan R1-07); lines: ${JSON.stringify(r.map.lines)}`);
    assert.ok(!r.web.text.includes(NOTHING), `the real web omits "${NOTHING}" (plan R1-07); it says: ${r.web.text}`);
    assertLabel(r.web.text, left, "leftover", "real web, leftover");
  });

  r107("review P2b (C8): the same vault rewritten to TERMINATED_UNKNOWN with live = null (SYNTHETIC RC44 case E) is restored by the route Verify at D (TERMINATED_UNKNOWN -> PAUSED) with the answer CONSISTENT {status, vaultId, settled: []} and no new field; the real web, from the card's prior TERMINATED_UNKNOWN status and the live vault after, shows a restore notice and not \"Nothing was changed.\" [RED on dc7552e]", async (t, x) => {
    await twinsAtDepth(x);
    assert.equal((await x.verify(V.tw)).status, "CONSISTENT", "P2a settled first (SDK Verify)");
    const m = await x.rawManifest(V.tw);
    await x.store.write(Categories.VAULT, V.tw.vaultId, { ...m, status: "TERMINATED_UNKNOWN", live: null });
    const r = await verifyAndRender(t, x, V.tw);
    assert.equal(r.beforeDoc.status, "TERMINATED_UNKNOWN"); assert.equal(r.beforeDoc.live, undefined, "the card had no live state before the Verify");
    assert.equal(r.answer.status, "CONSISTENT"); assert.deepEqual(r.answer.settled, []);
    assert.deepEqual(Object.keys(r.answer).sort(), CONSISTENT_KEYS, "no new response field: the restore is not announced by the answer (C8)");
    assert.equal(r.afterDoc.status, "PAUSED", "Verify restored the manifest"); assert.ok(r.afterDoc.live, "the vault is live after the Verify");
    assert.equal(r.wrote, true, "the restore wrote the manifest");
    assert.match(r.web.text, RESTORE, `the web derives a restore notice from the card's prior TERMINATED_UNKNOWN status (plan R1-07, C8); it says: ${r.web.text}`);
    assert.ok(!r.web.text.includes(NOTHING), `a Verify that restored the vault is not told "${NOTHING}" (plan R1-07); it says: ${r.web.text}`);
  });

  r107("holds: after P2a's settlement a further route Verify writes nothing and answers CONSISTENT {settled: []}; the real web still says \"Nothing was changed.\" with no restore notice", async (t, x) => {
    await twinsAtDepth(x);
    await x.verify(V.tw);
    const r = await verifyAndRender(t, x, V.tw);
    assert.equal(r.answer.status, "CONSISTENT"); assert.deepEqual(r.answer.settled, []);
    assert.equal(r.wrote, false, "a further Verify writes nothing");
    assert.ok(r.web.text.includes(NOTHING), `nothing was written: the web keeps "${NOTHING}"; it says: ${r.web.text}`);
    assert.doesNotMatch(r.web.text, RESTORE, `no restore occurred; it says: ${r.web.text}`);
  });
}
