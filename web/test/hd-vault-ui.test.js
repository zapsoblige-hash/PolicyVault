"use strict";

/*
 * web/hd-vault-ui.js — the v0.7-payment-hd HIERARCHICAL DELEGATION web
 * surface (Wave 2, Track H-web; contract
 * docs/postlaunch/v0.7-app-surface-contract.md §6). The server lane
 * (Track E) for the HD actions on /wallet/v7/requests had not landed when
 * this suite was written, so every network call runs against FIXTURE
 * responses — never a live server. Manifest verification/rendering runs
 * through the REAL web/core-bundle.js against REAL, self-verifying
 * policyvault-rooted-hd-vault-manifest/1 manifests
 * (web/test/fixtures/hd-manifest-fixtures.js) — every hash/root/fold is
 * produced by the SAME pinned core/model/hd-leaf-v7.js functions the
 * verifier itself recomputes with.
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const WEB_DIR = path.join(__dirname, "..");
const core = require("../core-bundle.js");
const hdUiMod = require("../hd-vault-ui.js");
const HD_UI_SRC = fs.readFileSync(path.join(WEB_DIR, "hd-vault-ui.js"), "utf8");
const fx = require("./fixtures/hd-manifest-fixtures.js");

function fakeApi(overrides = {}) {
  const calls = [];
  const responses = new Map(Object.entries(overrides));
  return {
    calls,
    on(key, value) { responses.set(key, value); return this; },
    async getJSON(p) {
      calls.push({ method: "GET", path: p });
      const r = responses.get(`GET ${p}`);
      if (typeof r === "function") return r();
      if (r === undefined) throw Object.assign(new Error(`no fake response for GET ${p}`), { code: "FAKE_UNMAPPED" });
      return r;
    },
    async postJSON(p, body) {
      calls.push({ method: "POST", path: p, body });
      const r = responses.get(`POST ${p}`);
      if (typeof r === "function") return r(body);
      if (r === undefined) throw Object.assign(new Error(`no fake response for POST ${p}`), { code: "FAKE_UNMAPPED" });
      return r;
    },
    async resolveXOnly(address) {
      calls.push({ method: "resolveXOnly", address });
      const map = overrides.__resolve || {};
      if (Object.prototype.hasOwnProperty.call(map, address)) return map[address];
      throw Object.assign(new Error(`address rejected: ${address}`), { code: "ADDRESS_INVALID" });
    }
  };
}

const KEYS = { "kaspa:qdelegate": "aa".repeat(32) };

function mod(apiOverrides) {
  const api = fakeApi({ __resolve: KEYS, ...apiOverrides });
  return { api, m: hdUiMod.createModule({ api, core }) };
}

/* ==================================================================
 * createModule guards
 * ================================================================== */

test("createModule: requires api.{getJSON,postJSON,resolveXOnly}", () => {
  assert.throws(() => hdUiMod.createModule({ api: { getJSON: async () => {} }, core }), /requires api/);
});

test("createModule: requires the v0.7-payment-hd core bundle closure", () => {
  const { api } = mod();
  assert.throws(() => hdUiMod.createModule({ api, core: {} }), /requires the v0\.7-payment-hd core bundle/);
});

/* ==================================================================
 * constants — read from the core, never retyped
 * ================================================================== */

test("EXPIRY_STATEMENT is read verbatim from core.hdLeafV7.EXPIRY_IS_NOT_CONSENSUS_ENFORCED", () => {
  const { m } = mod();
  assert.equal(m.EXPIRY_STATEMENT, core.hdLeafV7.EXPIRY_IS_NOT_CONSENSUS_ENFORCED);
  assert.match(m.EXPIRY_STATEMENT, /not by Kaspa consensus/i);
});

test("MAX_LEVEL is read from core.hdLeafV7.MAX_LEVEL (3, measured — never a config flag)", () => {
  const { m } = mod();
  assert.equal(m.MAX_LEVEL, 3);
});

test("HD_ACTIONS is the exact closed action table core/intent/org-root-manifest-v7-hd.js exports", () => {
  const { m } = mod();
  assert.deepEqual(Object.keys(m.HD_ACTIONS).sort(), ["childSpendL2", "childSpendL3", "delegateSetChildRoot1", "delegateSetChildRoot2", "hdSpend"].sort());
  assert.equal(m.HD_ACTIONS.hdSpend.level, 1);
  assert.equal(m.HD_ACTIONS.childSpendL3.level, 3);
});

/* ==================================================================
 * action classification — level derived from action name ONLY
 * ==================================================================================================================== */

test("isSpendAction / isDelegationAction classify exactly the closed action set", () => {
  const { m } = mod();
  for (const a of ["hdSpend", "childSpendL2", "childSpendL3"]) { assert.equal(m.isSpendAction(a), true, a); assert.equal(m.isDelegationAction(a), false, a); }
  for (const a of ["delegateSetChildRoot1", "delegateSetChildRoot2"]) { assert.equal(m.isDelegationAction(a), true, a); assert.equal(m.isSpendAction(a), false, a); }
  assert.equal(m.isSpendAction("tokenDeposit"), false);
});

test("actionInfo: tokenDeposit is recognised as a deposit (no level); an unrecognised action fails closed HD_LEVEL_UNPROVEN", () => {
  const { m } = mod();
  assert.equal(m.actionInfo("tokenDeposit").kind, "deposit");
  assert.throws(() => m.actionInfo("childSpendL4"), (e) => { assert.equal(e.code, "HD_LEVEL_UNPROVEN"); return true; });
  assert.throws(() => m.actionInfo("hdOwnerRecover"), (e) => { assert.equal(e.code, "HD_LEVEL_UNPROVEN"); return true; });
});

/* ==================================================================
 * LOCAL LEAF pre-check
 * ================================================================== */

function leafForm(overrides = {}) {
  return {
    pk: "kaspa:qdelegate",
    maxPerSpend: "1000", periodBudget: "5000", periodLengthDaa: "1000", periodStartDaa: "0", periodSpent: "0",
    maxFeePerTxKas: "0.001", maxCarryKas: "0.01", expiryDaa: "9000000",
    recipientRoot: "cd".repeat(32), childRoot: fx.ZERO,
    ...overrides
  };
}

test("normalizeHdLeafForm: a well-formed leaf normalizes through the real core.hdLeafV7.normalizeHdLeaf", async () => {
  const { m } = mod();
  const raw = await m.normalizeHdLeafForm(leafForm());
  assert.equal(raw.pk, KEYS["kaspa:qdelegate"]);
  core.hdLeafV7.normalizeHdLeaf(raw); // re-derivable without throwing
});

test("normalizeHdLeafForm: a missing recipientRoot is refused locally, before any network call", async () => {
  const { api, m } = mod();
  await assert.rejects(() => m.normalizeHdLeafForm(leafForm({ recipientRoot: "" })), (e) => { assert.equal(e.code, "HD_AUTHORITY_EXCEEDS_ANCESTOR"); return true; });
  assert.equal(api.calls.filter((c) => c.method === "POST").length, 0);
});

test("normalizeHdLeafForm: zero periodLengthDaa is refused (the covenant's own invariant, re-derived locally)", async () => {
  const { m } = mod();
  await assert.rejects(() => m.normalizeHdLeafForm(leafForm({ periodLengthDaa: "0" })));
});

/* ==================================================================
 * AUTHORITY MAY NEVER INCREASE DESCENDING
 * ================================================================== */

test("verifyChildNeverExceedsParent: an equal-or-narrower child passes", () => {
  const { m } = mod();
  const parent = fx.leaf(1);
  const child = fx.leaf(2, { maxPerSpend: "100" }); // parent's default maxPerSpend is 250000
  const r = m.verifyChildNeverExceedsParent(parent, child);
  assert.equal(r.ok, true);
});

test("verifyChildNeverExceedsParent: a WIDENED child is refused HD_AUTHORITY_EXCEEDS_ANCESTOR, naming every violated field", () => {
  const { m } = mod();
  const parent = fx.leaf(1);
  const widened = fx.leaf(2, { maxPerSpend: "999999999", expiryDaa: "999999999999" });
  assert.throws(
    () => m.verifyChildNeverExceedsParent(parent, widened),
    (e) => { assert.equal(e.code, "HD_AUTHORITY_EXCEEDS_ANCESTOR"); assert.ok(e.violations.includes("maxPerSpend")); assert.ok(e.violations.includes("expiryDaa")); return true; }
  );
});

/* ==================================================================
 * resolveHdChain — real local chain-proof computation
 * ================================================================== */

test("resolveHdChain: level-2 spend, chain reproduces the fixture's own ancestorChain and effectiveAuthority exactly", () => {
  const { manifest, tree, path: p } = fx.buildSpendFixture({ level: 2 });
  const { m } = mod();
  const liveAgentRoot = manifest.stateBefore.state.agentRoot;
  const { chain, effectiveAuthority } = m.resolveHdChain({ tree, path: p, liveAgentRoot, action: "childSpendL2" });
  assert.equal(chain.length, 2);
  assert.deepEqual(chain.map((c) => c.leaf.pk), manifest.ancestorChain.map((c) => c.leaf.pk));
  assert.equal(effectiveAuthority.maxPerSpend.toString(), manifest.effectiveAuthority.maxPerSpend);
});

test("resolveHdChain: a STALE local tree copy (does not reproduce the live agentRoot) refuses HD_CHAIN_STALE, locally", () => {
  const { tree, path: p } = fx.buildSpendFixture({ level: 1 });
  const { m } = mod();
  assert.throws(() => m.resolveHdChain({ tree, path: p, liveAgentRoot: "00".repeat(32), action: "hdSpend" }), (e) => { assert.equal(e.code, "HD_CHAIN_STALE"); return true; });
});

test("resolveHdChain: a path shorter than the action's required level is refused HD_LEVEL_UNPROVEN", () => {
  const { manifest, tree } = fx.buildSpendFixture({ level: 2 });
  const { m } = mod();
  assert.throws(() => m.resolveHdChain({ tree, path: [0], liveAgentRoot: manifest.stateBefore.state.agentRoot, action: "childSpendL2" }), (e) => { assert.equal(e.code, "HD_LEVEL_UNPROVEN"); return true; });
});

test("resolveHdChain: tokenDeposit carries no chain", () => {
  const { tree, path: p } = fx.buildSpendFixture({ level: 1 });
  const { m } = mod();
  assert.throws(() => m.resolveHdChain({ tree, path: p, liveAgentRoot: "00".repeat(32), action: "tokenDeposit" }), (e) => { assert.equal(e.code, "HD_LEVEL_UNPROVEN"); return true; });
});

/* ==================================================================
 * REQUEST building (contract §6.1: POST /wallet/v7/requests extended)
 * ================================================================== */

test("buildHdRequest: POSTs the exact body to /wallet/v7/requests; level is never a caller field on the wire", async () => {
  const { api, m } = mod({ "POST /wallet/v7/requests": (b) => ({ request: { requestId: "r1", ...b } }) });
  await m.buildHdRequest({ vaultId: "v1", action: "childSpendL2", params: { spendAmount: "10" }, signerAddress: "kaspa:qdelegate" });
  const call = api.calls.find((c) => c.path === "/wallet/v7/requests");
  assert.deepEqual(call.body, { vaultId: "v1", action: "childSpendL2", params: { spendAmount: "10" }, signerAddress: "kaspa:qdelegate" });
  assert.ok(!("level" in call.body));
});

test("buildHdRequest: an unrecognised action refuses locally, before any network call", async () => {
  const { api, m } = mod();
  await assert.rejects(() => m.buildHdRequest({ vaultId: "v1", action: "childSpendL4", params: {}, signerAddress: "x" }), (e) => { assert.equal(e.code, "HD_LEVEL_UNPROVEN"); return true; });
  assert.equal(api.calls.length, 0);
});

test("buildHdRequest: a delegation while the vault is paused refuses DELEGATION_WHILE_PAUSED locally", async () => {
  const { api, m } = mod();
  await assert.rejects(
    () => m.buildHdRequest({ vaultId: "v1", action: "delegateSetChildRoot1", params: {}, signerAddress: "x", vaultPaused: true }),
    (e) => { assert.equal(e.code, "DELEGATION_WHILE_PAUSED"); return true; }
  );
  assert.equal(api.calls.length, 0);
});

test("buildHdRequest: a delegation while the organizational root is frozen refuses DELEGATION_WHILE_ROOT_FROZEN locally", async () => {
  const { api, m } = mod();
  await assert.rejects(
    () => m.buildHdRequest({ vaultId: "v1", action: "delegateSetChildRoot2", params: {}, signerAddress: "x", rootFrozen: true }),
    (e) => { assert.equal(e.code, "DELEGATION_WHILE_ROOT_FROZEN"); return true; }
  );
  assert.equal(api.calls.length, 0);
});

test("buildHdRequest: a SPEND action is never gated by vaultPaused/rootFrozen locally (the server/covenant decides)", async () => {
  const { api, m } = mod({ "POST /wallet/v7/requests": (b) => ({ request: { requestId: "r1", ...b } }) });
  await m.buildHdRequest({ vaultId: "v1", action: "hdSpend", params: {}, signerAddress: "x", vaultPaused: true, rootFrozen: true });
  assert.equal(api.calls.length, 1);
});

test("buildDepositRequest: forces action tokenDeposit", async () => {
  const { api, m } = mod({ "POST /wallet/v7/requests": (b) => ({ request: { requestId: "r1", ...b } }) });
  await m.buildDepositRequest({ vaultId: "v1", params: {}, signerAddress: "kaspa:qdelegate" });
  assert.equal(api.calls[0].body.action, "tokenDeposit");
});

test("buildRevokeDelegationRequest: forces the zero root and the correct level's action name", async () => {
  const { api, m } = mod({ "POST /wallet/v7/requests": (b) => ({ request: { requestId: "r1", ...b } }) });
  await m.buildRevokeDelegationRequest({ vaultId: "v1", level: 1, chain: [{ leaf: {}, siblingsHex: "", pathBits: "0", level: 1 }], signerAddress: "kaspa:qdelegate" });
  const call = api.calls[0];
  assert.equal(call.body.action, "delegateSetChildRoot1");
  assert.equal(call.body.params.newChildRoot, core.hdLeafV7.ZERO_ROOT_HEX);
});

test("buildRevokeDelegationRequest: level 3 is refused — revocation narrows a DELEGATING level's childRoot, and level 3 never delegates", () => {
  const { m } = mod();
  assert.rejects(() => m.buildRevokeDelegationRequest({ vaultId: "v1", level: 3, chain: [], signerAddress: "x" }), (e) => { assert.equal(e.code, "HD_LEVEL_UNPROVEN"); return true; });
});

test("fetchHdRequests / fetchHdRequest: GET the exact /wallet/v7/requests routes", async () => {
  const { api, m } = mod({ "GET /wallet/v7/requests?vaultId=v1": () => ({ requests: [] }), "GET /wallet/v7/requests/r1": () => ({ request: { requestId: "r1" } }) });
  await m.fetchHdRequests("v1");
  await m.fetchHdRequest("r1");
  assert.deepEqual(api.calls.map((c) => c.path), ["/wallet/v7/requests?vaultId=v1", "/wallet/v7/requests/r1"]);
});

test("submitHdRequest / rejectHdRequest: POST to the exact routes", async () => {
  const { api, m } = mod({
    "POST /wallet/v7/requests/r1/submit": () => ({ request: { requestId: "r1", state: "SUBMITTED" }, txId: "tx1" }),
    "POST /wallet/v7/requests/r1/reject": () => ({ request: { requestId: "r1", state: "REFUSED" } })
  });
  const sub = await m.submitHdRequest("r1");
  assert.equal(sub.txId, "tx1");
  const rej = await m.rejectHdRequest("r1", "changed my mind");
  assert.deepEqual(api.calls.find((c) => c.path === "/wallet/v7/requests/r1/reject").body, { reason: "changed my mind" });
  void rej;
});

/* ==================================================================
 * ROOTED HD VAULT CREATION — profile forced
 * ================================================================== */

test("createRootedHdVault: profile is ALWAYS policyvault-0.7-payment-hd, even if the caller tries to override it", async () => {
  const { api, m } = mod({ "POST /org-roots/r1/vaults": (b) => ({ request: { requestId: "req1", ...b } }) });
  await m.createRootedHdVault("r1", { label: "HD vault", profile: "policyvault-0.7-payment" });
  const call = api.calls.find((c) => c.path === "/org-roots/r1/vaults");
  assert.equal(call.body.profile, "policyvault-0.7-payment-hd");
});

/* ==================================================================
 * SIGN — local manifest re-verification BEFORE the wallet, real fixture
 * ================================================================== */

for (const level of [1, 2, 3]) {
  test(`signHdRequest: a REAL, VERIFIED level-${level} spend manifest -> the wallet is invoked and the signature is POSTed`, async () => {
    const { manifest } = fx.buildSpendFixture({ level });
    const { m } = mod({ "POST /wallet/v7/requests/r1/signature": (b) => ({ request: { requestId: "r1", state: "PREFLIGHT_VERIFIED", ...b } }) });
    let adapterCalledWith = null;
    const adapter = { signInputs: async (u, list, opts) => { adapterCalledWith = { u, list, opts }; return JSON.stringify({ signed: true }); } };
    const request = { requestId: "r1", manifest, transaction: { unsignedSafeJson: "{}", signInputs: [{ index: 0, sighashType: 1 }] } };
    const result = await m.signHdRequest({ request, adapter, network: "testnet-10", expectedSignerAddress: "kaspa:qdelegate" });
    assert.ok(adapterCalledWith, "the wallet was invoked exactly once");
    assert.equal(result.request.state, "PREFLIGHT_VERIFIED");
  });
}

test("signHdRequest: a REAL, VERIFIED delegation manifest also verifies and signs", async () => {
  const { manifest } = fx.buildDelegationFixture({ level: 1 });
  const { m } = mod({ "POST /wallet/v7/requests/r1/signature": (b) => ({ request: { requestId: "r1", state: "PREFLIGHT_VERIFIED", ...b } }) });
  const adapter = { signInputs: async () => JSON.stringify({ signed: true }) };
  const request = { requestId: "r1", manifest, transaction: { unsignedSafeJson: "{}", signInputs: [] } };
  const result = await m.signHdRequest({ request, adapter, network: "testnet-10", expectedSignerAddress: "kaspa:qdelegate" });
  assert.equal(result.request.state, "PREFLIGHT_VERIFIED");
});

test("signHdRequest: a TAMPERED manifest fails local re-verification and the wallet is NEVER invoked", async () => {
  const { manifest } = fx.buildSpendFixture({ level: 1 });
  const tampered = { ...manifest, manifestHash: "0".repeat(64) };
  const { m } = mod();
  let adapterInvoked = false;
  const adapter = { signInputs: async () => { adapterInvoked = true; return "{}"; } };
  const request = { requestId: "r1", manifest: tampered, transaction: { unsignedSafeJson: "{}", signInputs: [] } };
  await assert.rejects(
    () => m.signHdRequest({ request, adapter, network: "testnet-10", expectedSignerAddress: "kaspa:qdelegate" }),
    (e) => { assert.equal(e.code, "HD_CHAIN_STALE"); return true; }
  );
  assert.equal(adapterInvoked, false, "the wallet must never be invoked for a manifest that fails local verification");
});

test("signHdRequest: no build on the request refuses before touching the wallet", async () => {
  const { m } = mod();
  let adapterInvoked = false;
  const adapter = { signInputs: async () => { adapterInvoked = true; return "{}"; } };
  await assert.rejects(() => m.signHdRequest({ request: { requestId: "r1" }, adapter }));
  assert.equal(adapterInvoked, false);
});

/* ==================================================================
 * REVIEW rendering — DO NOT SIGN gate, real fixtures
 * ================================================================== */

test("renderHdRequestReviewHtml: a REAL VERIFIED spend manifest renders the core's own hdVaultExplain lines verbatim", () => {
  const { manifest } = fx.buildSpendFixture({ level: 2 });
  const { m } = mod();
  const html = m.renderHdRequestReviewHtml({ manifest });
  assert.match(html, /VERIFIED — EXACT DELEGATION CHAIN BEFORE SIGNING/);
  const lines = core.hdVaultExplain.humanReadable({ manifest });
  for (const line of lines) assert.ok(html.includes(escapeForHtmlCheck(line)), `line present: ${String(line).slice(0, 60)}`);
  assert.ok(html.includes(escapeForHtmlCheck(core.hdLeafV7.EXPIRY_IS_NOT_CONSENSUS_ENFORCED)));
});

function escapeForHtmlCheck(s) {
  return String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
}

test("renderHdRequestReviewHtml: a REAL VERIFIED delegation manifest states what changes and that every other field is preserved", () => {
  const { manifest } = fx.buildDelegationFixture({ level: 1 });
  const { m } = mod();
  const html = m.renderHdRequestReviewHtml({ manifest });
  assert.match(html, /VERIFIED/);
  assert.match(html, /Delegation:/i);
  assert.match(html, /UNCHANGED/i);
});

test("renderHdRequestReviewHtml: no manifest -> DO NOT SIGN, never a normal review", () => {
  const { m } = mod();
  const html = m.renderHdRequestReviewHtml({});
  assert.match(html, /Do not sign|DO NOT SIGN/i);
});

test("renderHdRequestReviewHtml: a TAMPERED manifest renders DO NOT SIGN naming the failing checks", () => {
  const { manifest } = fx.buildSpendFixture({ level: 1 });
  const tampered = { ...manifest, manifestHash: "0".repeat(64) };
  const { m } = mod();
  const html = m.renderHdRequestReviewHtml({ manifest: tampered });
  assert.match(html, /DO NOT SIGN/);
  assert.match(html, /manifestHash/);
});

/* ==================================================================
 * DELEGATION TREE rendering (contract §6.3)
 * ================================================================== */

test("renderAncestorChainHtml: shows every level's caps/budgets/counters and the effective intersection, from a REAL structured() doc", () => {
  const { manifest } = fx.buildSpendFixture({ level: 3 });
  const doc = core.hdVaultExplain.structured({ manifest });
  const { m } = mod();
  const html = m.renderAncestorChainHtml(doc);
  assert.match(html, /<table class="mtable">/);
  assert.equal((html.match(/<tr>/g) || []).length, 3 + 1 /* header */);
  assert.match(html, /Effective \(intersected\) authority/);
  assert.ok(html.includes(escapeForHtmlCheck(core.hdLeafV7.EXPIRY_IS_NOT_CONSENSUS_ENFORCED)));
  for (const level of doc.ancestorChain) assert.ok(html.includes(level.pk), "each level's full signer key appears untruncated");
});

test("renderAncestorChainHtml: a non-verified doc renders a warning, never a fabricated chain", () => {
  const { m } = mod();
  const html = m.renderAncestorChainHtml({ verdict: "REFUSED" });
  assert.match(html, /No verified ancestor chain/);
});

/* ==================================================================
 * CARD rendering (contract §6.3)
 * ================================================================== */

test("renderHdVaultCardHtml: authorityModel ON_CHAIN_ORGANIZATIONAL_ROOT, status CANDIDATE, the never-touches-root statement, and the verbatim expiry sentence", () => {
  const { m } = mod();
  const vault = { vaultId: "v1", label: "HD vault", status: "ACTIVE", contractVersion: "policyvault-0.7-payment-hd", orgRootCovenantId: "3c".repeat(32) };
  const html = m.renderHdVaultCardHtml(vault);
  assert.match(html, /ON_CHAIN_ORGANIZATIONAL_ROOT/);
  assert.match(html, /status: CANDIDATE/);
  assert.ok(html.includes(m.NEVER_TOUCHES_ROOT_STATEMENT));
  assert.ok(html.includes(escapeForHtmlCheck(core.hdLeafV7.EXPIRY_IS_NOT_CONSENSUS_ENFORCED)));
  assert.ok(html.includes("3c".repeat(32)));
  assert.ok(!/single[- ]owner (vault|owner authority)/i.test(html), "never claims this HD vault has legacy single-owner authority");
});

test("renderHdVaultCardHtml: owner operations are described as ROOT REQUESTS, never a single-owner signature", () => {
  const { m } = mod();
  const html = m.renderHdVaultCardHtml({ vaultId: "v1", contractVersion: "policyvault-0.7-payment-hd" });
  assert.match(html, /ROOT REQUESTS, never a single-owner signature/);
});

/* ==================================================================
 * ARIA live regions
 * ================================================================== */

test("ARIA: every status-bearing render function carries role=status/aria-live=polite/aria-atomic=true", () => {
  const { manifest } = fx.buildSpendFixture({ level: 1 });
  const { m } = mod();
  const reviewHtml = m.renderHdRequestReviewHtml({ manifest });
  const cardHtml = m.renderHdVaultCardHtml({ vaultId: "v1", contractVersion: "policyvault-0.7-payment-hd" });
  for (const [name, html] of [["review", reviewHtml], ["card", cardHtml]]) {
    assert.match(html, /role="status"/, name);
    assert.match(html, /aria-live="polite"/, name);
    assert.match(html, /aria-atomic="true"/, name);
  }
});

/* ==================================================================
 * 375px layout / no hardcoded pixel widths, and .mtable scroll container
 * ================================================================== */

test("375px: no fixed pixel width over 375 is hardcoded in this module's own markup", () => {
  assert.ok(!/width:\s*\d{3,}px/.test(HD_UI_SRC));
});

test("375px: the ancestor-chain table uses the app's existing .mtable scroll container, never a bare <table>", () => {
  const { manifest } = fx.buildSpendFixture({ level: 1 });
  const doc = core.hdVaultExplain.structured({ manifest });
  const { m } = mod();
  const html = m.renderAncestorChainHtml(doc);
  const tables = [...html.matchAll(/<table[^>]*>/g)];
  assert.ok(tables.length > 0);
  for (const t of tables) assert.match(t[0], /class="mtable"/);
});

/* ==================================================================
 * keyboard focus / reduced motion
 * ================================================================== */

test("keyboard focus: renderHdVaultCardHtml renders only native <button> controls, no tabindex trap, no click-only div", () => {
  const { m } = mod();
  const html = m.renderHdVaultCardHtml({ vaultId: "v1", contractVersion: "policyvault-0.7-payment-hd" });
  assert.ok(!/tabindex="-1"/.test(html));
  assert.ok(!/<div[^>]*onclick=/.test(html));
  assert.match(html, /<button/);
});

test("reduced motion: web/hd-vault-ui.js defines no <style>, @keyframes, or inline CSS animation/transition of its own", () => {
  assert.ok(!/<style/i.test(HD_UI_SRC));
  assert.ok(!/@keyframes/.test(HD_UI_SRC));
  assert.ok(!/style="[^"]*\b(animation|transition)\s*:/.test(HD_UI_SRC));
});

/* ==================================================================
 * truthfulness
 * ================================================================== */

const FORBIDDEN_CLAIMS = [
  /\baudited\b/i, /\bcertified\b/i, /\bcompliant\b/i, /\bindependently reviewed\b/i,
  /\bindustry standard\b/i, /\binstitutional[- ]grade\b/i, /\bfully decentrali[sz]ed\b/i,
  /\btrustless stablecoin\b/i, /\bproduction verified\b/i, /\bno alternative\b/i
];

test("truthfulness: web/hd-vault-ui.js never claims audited/certified/compliant/institutional-grade/etc.", () => {
  for (const re of FORBIDDEN_CLAIMS) assert.ok(!re.test(HD_UI_SRC), `must not match ${re}`);
});

test("truthfulness: this module never presents an HD vault as covenant-byte-frozen or as a single-owner vault", () => {
  const { m } = mod();
  const html = m.renderHdVaultCardHtml({ vaultId: "v1", contractVersion: "policyvault-0.7-payment-hd" });
  assert.match(html, /status: CANDIDATE/);
  assert.ok(!/\bFROZEN\b/.test(html));
  assert.ok(!/single[- ]owner (vault|owner authority)/i.test(html), "never claims this HD vault has legacy single-owner authority");
});

/* ---------------- refusal-explain.js closed table for HD codes -------- */

test("refusal-explain.js: every contract-closed HD code has a title/meaning/next with no override offered", () => {
  const RX = require("../refusal-explain.js");
  const { m } = mod();
  for (const code of m.HD_REFUSAL_CODES) {
    const e = RX.explain(code);
    assert.ok(e, `refusal-explain.js explains ${code}`);
    assert.ok(e.title && e.meaning && e.next.length, code);
  }
});

test("displayCodeFor: passes through recognised HD codes; unrecognised codes fall back to UNKNOWN", () => {
  const { m } = mod();
  assert.equal(m.displayCodeFor({ code: "HD_CHAIN_STALE" }), "HD_CHAIN_STALE");
  assert.equal(m.displayCodeFor({}), "UNKNOWN");
  assert.equal(m.displayCodeFor(null), "UNKNOWN");
});
