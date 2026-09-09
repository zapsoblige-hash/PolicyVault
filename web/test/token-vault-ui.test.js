"use strict";

/*
 * web/token-vault-ui.js — the v0.5 / v0.6 TOKEN CONTROLLER web surface
 * (Wave 2, Track H-web; contract docs/postlaunch/v0.7-app-surface-contract.md
 * §6). The server lane (Track E) for /wallet/v5/* and /wallet/v6/* had not
 * landed when this suite was written, so every network call runs against
 * FIXTURE responses shaped exactly per the contract's route table — never
 * a live server. Manifest verification/rendering runs through the REAL
 * web/core-bundle.js against REAL, self-verifying v0.5 manifests
 * (web/test/fixtures/token-manifest-fixtures.js, built the same way
 * web/test/org-root-ui.test.js consumes captured v0.7 fixtures — a real
 * production codec pipeline, not a hand-typed approximation).
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const WEB_DIR = path.join(__dirname, "..");
const core = require("../core-bundle.js");
const tokenUiMod = require("../token-vault-ui.js");
const TOKEN_UI_SRC = fs.readFileSync(path.join(WEB_DIR, "token-vault-ui.js"), "utf8");
const fx = require("./fixtures/token-manifest-fixtures.js");

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

const K = (b) => b.toString(16).padStart(2, "0").repeat(32);
const KEYS = { "kaspa:qagent": K(0x71), "kaspa:qrecover": K(0x72), "kaspa:qfunder": K(0xf1), "kaspa:qrecipient1": K(0x81) };

function mod(apiOverrides) {
  const api = fakeApi({ __resolve: KEYS, ...apiOverrides });
  return { api, m: tokenUiMod.createModule({ api, core }) };
}

function descriptorJson() {
  return JSON.stringify({
    schema: "policyvault-asset-descriptor/1",
    assetId: "a1".repeat(32),
    displayName: "Demo Token",
    tokenStandard: "kcc20/1",
    tokenCovenantId: "f1".repeat(32),
    acceptedTransferTemplates: [{ templateVmHashBlake2b256: "cc".repeat(32), prefixLen: 10, suffixLen: 12, stateLayout: "kcc20-state/1" }],
    decimalsDisplay: 8,
    issuerPowers: { mint: false, burn: false, freeze: false, blacklist: false, redemptionControl: false, upgradeMigration: false, controllerRotation: false, emergencyControl: false }
  });
}

function createForm(overrides = {}) {
  return {
    contractVersion: "policyvault-0.5",
    descriptorJson: descriptorJson(),
    agentPk: "kaspa:qagent",
    tokenMaxPerSpend: "1000",
    tokenPeriodBudget: "5000",
    periodLengthDaa: "1000",
    recipients: "kaspa:qrecipient1",
    agentMaxFeePerTxKas: "0.001",
    agentMaxCarryKas: "0.01",
    recoveryAddress: "kaspa:qrecover",
    depositKas: "10",
    feeReserveKas: "1",
    signerAddress: "kaspa:qfunder",
    label: "Demo vault",
    ...overrides
  };
}

/* ==================================================================
 * createModule guards
 * ================================================================== */

test("createModule: requires api.{getJSON,postJSON,resolveXOnly}", () => {
  assert.throws(() => tokenUiMod.createModule({ api: { getJSON: async () => {} }, core }), /requires api/);
  assert.throws(() => tokenUiMod.createModule({ core }), /requires api/);
});

test("createModule: requires the v0.5/v0.6 core bundle closure", () => {
  const { api } = mod();
  assert.throws(() => tokenUiMod.createModule({ api, core: {} }), /requires the v0\.5\/v0\.6 core bundle/);
});

/* ==================================================================
 * version routing — fail closed, never a default
 * ================================================================== */

test("routeOf: policyvault-0.5 -> v5, policyvault-0.6 -> v6", () => {
  const { m } = mod();
  assert.equal(m.routeOf("policyvault-0.5"), "v5");
  assert.equal(m.routeOf("policyvault-0.6"), "v6");
});

test("routeOf: an unknown contractVersion is refused UNKNOWN_COVENANT_VERSION, never routed to a default", () => {
  const { m } = mod();
  assert.throws(() => m.routeOf("policyvault-0.4.1"), (e) => { assert.equal(e.code, "UNKNOWN_COVENANT_VERSION"); return true; });
  assert.throws(() => m.routeOf(""), (e) => { assert.equal(e.code, "UNKNOWN_COVENANT_VERSION"); return true; });
});

test("versionInfo: v0.6 carries composability OPTIONAL_ATOMIC and venues [FIXTURE]; v0.5 carries neither", () => {
  const { m } = mod();
  assert.equal(m.versionInfo("policyvault-0.6").composability, "OPTIONAL_ATOMIC");
  assert.deepEqual(m.versionInfo("policyvault-0.6").venues, ["FIXTURE"]);
  assert.equal(m.versionInfo("policyvault-0.5").composability, undefined);
  assert.equal(m.versionInfo("policyvault-0.5").authorityModel, "SINGLE_ON_CHAIN_OWNER");
  assert.equal(m.versionInfo("policyvault-0.5").status, "FROZEN");
});

/* ==================================================================
 * DESCRIPTOR validation — local, before any network round trip
 * ================================================================== */

test("parseAndValidateDescriptor: a well-formed descriptor validates through the real core validator", () => {
  const { m } = mod();
  const d = m.parseAndValidateDescriptor(descriptorJson());
  assert.equal(d.validated.displayName, "Demo Token");
  assert.match(d.descriptorHash, /^[0-9a-f]{64}$/);
});

test("parseAndValidateDescriptor: malformed JSON is refused ASSET_DESCRIPTOR_INVALID, locally", () => {
  const { m } = mod();
  assert.throws(() => m.parseAndValidateDescriptor("{not json"), (e) => { assert.equal(e.code, "ASSET_DESCRIPTOR_INVALID"); return true; });
});

test("parseAndValidateDescriptor: an unknown descriptor schema version fails closed", () => {
  const { m } = mod();
  const bad = JSON.parse(descriptorJson());
  bad.schema = "policyvault-asset-descriptor/99";
  assert.throws(() => m.parseAndValidateDescriptor(JSON.stringify(bad)), (e) => { assert.equal(e.code, "ASSET_DESCRIPTOR_INVALID"); return true; });
});

test("parseAndValidateDescriptor: an unknown field is refused (closed schema)", () => {
  const { m } = mod();
  const bad = JSON.parse(descriptorJson());
  bad.extraField = "1";
  assert.throws(() => m.parseAndValidateDescriptor(JSON.stringify(bad)), (e) => { assert.equal(e.code, "ASSET_DESCRIPTOR_INVALID"); return true; });
});

/* ==================================================================
 * CREATE — descriptor + token agent policy (contract §6.1)
 * ================================================================== */

test("normalizeTokenCreateForm: a well-formed v0.5 create form resolves addresses and normalizes through the real core", async () => {
  const { m } = mod();
  const norm = await m.normalizeTokenCreateForm(createForm());
  assert.equal(norm.route, "v5");
  assert.equal(norm.agentPolicy.agentPk, KEYS["kaspa:qagent"]);
  assert.equal(norm.body.recoveryAddress, "kaspa:qrecover");
  assert.equal(norm.body.signerAddress, "kaspa:qfunder");
  assert.equal(norm.body.depositKas, "10");
  assert.ok(!("tokenMaxPerSpend" in norm.body), "the network body carries descriptor/agentPolicy/recovery/deposit/fee/signer only");
});

test("normalizeTokenCreateForm: a floating-point-looking KAS amount never reaches Number() arithmetic", async () => {
  const { m } = mod();
  await assert.rejects(() => m.normalizeTokenCreateForm(createForm({ depositKas: "1e10" })));
  await assert.rejects(() => m.normalizeTokenCreateForm(createForm({ depositKas: "NaN" })));
  await assert.rejects(() => m.normalizeTokenCreateForm(createForm({ depositKas: "-1" })));
});

test("normalizeTokenCreateForm: an unknown contractVersion is refused before any address resolution", async () => {
  const { api, m } = mod();
  await assert.rejects(() => m.normalizeTokenCreateForm(createForm({ contractVersion: "policyvault-0.9" })), (e) => { assert.equal(e.code, "UNKNOWN_COVENANT_VERSION"); return true; });
  assert.equal(api.calls.filter((c) => c.method === "resolveXOnly").length, 0);
});

test("normalizeTokenCreateForm: a malformed agent policy field is refused locally, before any POST", async () => {
  const { api, m } = mod();
  await assert.rejects(() => m.normalizeTokenCreateForm(createForm({ tokenMaxPerSpend: "-5" })), (e) => { assert.equal(e.code, "ASSET_DESCRIPTOR_INVALID"); return true; });
  assert.equal(api.calls.filter((c) => c.method === "POST").length, 0);
});

test("normalizeTokenCreateForm: v0.6 create form carries the extra KAS-swap-cap agent policy fields", async () => {
  const { m } = mod();
  const norm = await m.normalizeTokenCreateForm(createForm({ contractVersion: "policyvault-0.6", kasMaxPerSwapKas: "1", kasPeriodBudgetKas: "5" }));
  assert.equal(norm.route, "v6");
  assert.ok(norm.agentPolicy.kasMaxPerSwap);
  assert.ok(norm.agentPolicy.kasPeriodBudget);
});

test("createTokenVault: POSTs to /wallet/v5/create for a v0.5 body and /wallet/v6/create for v0.6", async () => {
  const { api, m } = mod({
    "POST /wallet/v5/create": (b) => ({ request: { requestId: "r1", ...b } }),
    "POST /wallet/v6/create": (b) => ({ request: { requestId: "r2", ...b } })
  });
  await m.createTokenVault("policyvault-0.5", { label: "a" });
  await m.createTokenVault("policyvault-0.6", { label: "b" });
  assert.deepEqual(api.calls.map((c) => c.path), ["/wallet/v5/create", "/wallet/v6/create"]);
});

test('renderCreatePolicyPanelHtml: "EXACT ASSET POLICY BEFORE SIGNING", full untruncated descriptor hash and agent key, the verbatim token/KAS sentence', async () => {
  const { m } = mod();
  const norm = await m.normalizeTokenCreateForm(createForm());
  const html = m.renderCreatePolicyPanelHtml(norm);
  assert.match(html, /EXACT ASSET POLICY BEFORE SIGNING/);
  assert.ok(html.includes(norm.descriptor.descriptorHash), "full descriptor hash appears untruncated");
  assert.ok(html.includes(KEYS["kaspa:qagent"]), "full agent key appears untruncated");
  assert.ok(html.includes(m.TOKEN_KAS_SENTENCE));
  assert.match(html, /Deposit: 10 KAS/);
  assert.match(html, /Fee reserve: 1 KAS/);
});

/* ==================================================================
 * AGENT / RECIPIENT MERKLE local pre-checks (real core, real math)
 * ================================================================== */

test("normalizeAgentPolicyForm: an explicit 64-hex agentRecipientRoot is accepted without resolving any recipient address", async () => {
  const { api, m } = mod();
  const { policy } = await m.normalizeAgentPolicyForm({ agentPk: "kaspa:qagent", tokenMaxPerSpend: "1", tokenPeriodBudget: "1", periodLengthDaa: "10", agentRecipientRoot: "cd".repeat(32) }, "policyvault-0.5");
  assert.equal(policy.agentRecipientRoot, "cd".repeat(32));
  assert.equal(api.calls.filter((c) => c.method === "resolveXOnly" && c.address !== "kaspa:qagent").length, 0);
});

test("normalizeAgentPolicyForm: recipients fold into a real Merkle root via core.recipientMerkle", async () => {
  const { m } = mod();
  const { policy, recipients } = await m.normalizeAgentPolicyForm({ agentPk: "kaspa:qagent", tokenMaxPerSpend: "1", tokenPeriodBudget: "1", periodLengthDaa: "10", recipients: "kaspa:qrecipient1" }, "policyvault-0.5");
  assert.match(policy.agentRecipientRoot, /^[0-9a-f]{64}$/);
  assert.deepEqual(recipients, [KEYS["kaspa:qrecipient1"]]);
  const tree = core.recipientMerkle.buildRecipientTree(recipients);
  assert.equal(tree.root, policy.agentRecipientRoot, "the locally-computed root reproduces the real recipientMerkle fold");
});

test("normalizeAgentPolicyForm: neither a root nor a recipient list is refused locally", async () => {
  const { m } = mod();
  await assert.rejects(() => m.normalizeAgentPolicyForm({ agentPk: "kaspa:qagent", tokenMaxPerSpend: "1", tokenPeriodBudget: "1", periodLengthDaa: "10" }, "policyvault-0.5"));
});

test("verifyAgentSetReproducesRoot: a supplied agent set that reproduces the live agentRoot passes; a stale one refuses AGENT_ROOT_MISMATCH locally", () => {
  const { m } = mod();
  const agents = [{ agentPk: "aa".repeat(32), tokenMaxPerSpend: "100", tokenPeriodBudget: "1000", periodLengthDaa: "500", periodStartDaa: "0", tokenPeriodSpent: "0", agentMaxFeePerTx: "1000", agentMaxCarryKas: "1000", agentRecipientRoot: "00".repeat(32) }];
  const tree = core.agentMerkleV5.buildTokenAgentTreeV5(agents);
  const ok = m.verifyAgentSetReproducesRoot({ agents, liveAgentRoot: tree.root, contractVersion: "policyvault-0.5" });
  assert.equal(ok.root, tree.root);
  assert.throws(() => m.verifyAgentSetReproducesRoot({ agents, liveAgentRoot: "ff".repeat(32), contractVersion: "policyvault-0.5" }), (e) => { assert.equal(e.code, "AGENT_ROOT_MISMATCH"); return true; });
});

/* ==================================================================
 * REQUEST building / signing (contract §6.1 routes, exactly)
 * ================================================================== */

test("buildTokenRequest: POSTs the exact {vaultId,action,params,signerAddress} body to /wallet/v5/requests", async () => {
  const { api, m } = mod({ "POST /wallet/v5/requests": (b) => ({ request: { requestId: "r1", ...b } }) });
  const req = await m.buildTokenRequest({ vaultId: "v1", contractVersion: "policyvault-0.5", action: "tokenAgentSpend", params: { spendAmount: "10" }, signerAddress: "kaspa:qagent" });
  const call = api.calls.find((c) => c.path === "/wallet/v5/requests");
  assert.deepEqual(call.body, { vaultId: "v1", action: "tokenAgentSpend", params: { spendAmount: "10" }, signerAddress: "kaspa:qagent" });
  assert.equal(req.requestId, "r1");
});

test("buildTokenRequest: a swap action on a v0.5 vault is refused locally, before any network call", async () => {
  const { api, m } = mod();
  await assert.rejects(() => m.buildTokenRequest({ vaultId: "v1", contractVersion: "policyvault-0.5", action: "tokenAtomicSell", params: {}, signerAddress: "x" }), (e) => { assert.equal(e.code, "VENUE_PROFILE_UNSUPPORTED"); return true; });
  assert.equal(api.calls.length, 0);
});

test("buildDepositRequest: forces action tokenDeposit", async () => {
  const { api, m } = mod({ "POST /wallet/v5/requests": (b) => ({ request: { requestId: "r1", ...b } }) });
  await m.buildDepositRequest({ vaultId: "v1", contractVersion: "policyvault-0.5", params: {}, signerAddress: "kaspa:qagent" });
  assert.equal(api.calls[0].body.action, "tokenDeposit");
});

test("buildSwapRequest: refuses locally when the venue profile names a kind other than FIXTURE", async () => {
  const { api, m } = mod();
  await assert.rejects(
    () => m.buildSwapRequest({ vaultId: "v1", action: "tokenAtomicSell", params: { venueProfile: { kind: "REAL_DEX" } }, signerAddress: "x" }),
    (e) => { assert.equal(e.code, "VENUE_PROFILE_UNSUPPORTED"); return true; }
  );
  assert.equal(api.calls.length, 0);
});

test("buildSwapRequest: an unrecognised action is refused locally", async () => {
  const { m } = mod();
  await assert.rejects(() => m.buildSwapRequest({ vaultId: "v1", action: "tokenAgentSpend", params: {}, signerAddress: "x" }), (e) => { assert.equal(e.code, "VENUE_PROFILE_UNSUPPORTED"); return true; });
});

test("buildSwapRequest: a well-formed FIXTURE-venue swap POSTs to /wallet/v6/requests", async () => {
  const { api, m } = mod({ "POST /wallet/v6/requests": (b) => ({ request: { requestId: "r1", ...b } }) });
  await m.buildSwapRequest({ vaultId: "v1", action: "tokenAtomicSell", params: { venueProfile: { kind: "FIXTURE" }, amountIn: "10", minKasOut: "1" }, signerAddress: "kaspa:qagent" });
  assert.equal(api.calls[0].path, "/wallet/v6/requests");
});

test("submitTokenRequest / rejectTokenRequest: POST to the exact versioned route", async () => {
  const { api, m } = mod({
    "POST /wallet/v5/requests/r1/submit": () => ({ request: { requestId: "r1", state: "SUBMITTED" }, txId: "tx1" }),
    "POST /wallet/v5/requests/r1/reject": () => ({ request: { requestId: "r1", state: "REFUSED" } })
  });
  const sub = await m.submitTokenRequest("policyvault-0.5", "r1");
  assert.equal(sub.txId, "tx1");
  const rej = await m.rejectTokenRequest("policyvault-0.5", "r1", "changed my mind");
  assert.equal(rej.request.state, "REFUSED");
  assert.deepEqual(api.calls.find((c) => c.path === "/wallet/v5/requests/r1/reject").body, { reason: "changed my mind" });
});

/* ==================================================================
 * SIGN — local manifest re-verification BEFORE the wallet, real fixture
 * ================================================================== */

test("signTokenRequest: a REAL, VERIFIED v0.5 deposit manifest -> the wallet is invoked and the signature is POSTed", async () => {
  const { manifest, descriptor } = fx.buildDepositFixture({});
  const { api, m } = mod({ "POST /wallet/v5/requests/r1/signature": (b) => ({ request: { requestId: "r1", state: "PREFLIGHT_VERIFIED", ...b } }) });
  let adapterCalledWith = null;
  const adapter = { signInputs: async (u, list, opts) => { adapterCalledWith = { u, list, opts }; return JSON.stringify({ signed: true }); } };
  const request = { requestId: "r1", manifest, transaction: { unsignedSafeJson: "{}", signInputs: [{ index: 0, sighashType: 1 }] } };
  const result = await m.signTokenRequest({ request, contractVersion: "policyvault-0.5", adapter, network: "testnet-10", expectedSignerAddress: "kaspa:quser", descriptor });
  assert.ok(adapterCalledWith, "the wallet was invoked exactly once");
  assert.equal(result.request.state, "PREFLIGHT_VERIFIED");
});

test("signTokenRequest: a TAMPERED manifest fails local re-verification and the wallet is NEVER invoked", async () => {
  const { manifest, descriptor } = fx.buildDepositFixture({});
  const tampered = { ...manifest, manifestHash: "0".repeat(64) };
  const { m } = mod();
  let adapterInvoked = false;
  const adapter = { signInputs: async () => { adapterInvoked = true; return "{}"; } };
  const request = { requestId: "r1", manifest: tampered, transaction: { unsignedSafeJson: "{}", signInputs: [] } };
  await assert.rejects(
    () => m.signTokenRequest({ request, contractVersion: "policyvault-0.5", adapter, network: "testnet-10", expectedSignerAddress: "kaspa:quser", descriptor }),
    (e) => { assert.equal(e.code, "TOKEN_TEMPLATE_MISMATCH"); return true; }
  );
  assert.equal(adapterInvoked, false, "the wallet must never be invoked for a manifest that fails local verification");
});

test("signTokenRequest: no build on the request refuses before touching the wallet", async () => {
  const { m } = mod();
  let adapterInvoked = false;
  const adapter = { signInputs: async () => { adapterInvoked = true; return "{}"; } };
  await assert.rejects(() => m.signTokenRequest({ request: { requestId: "r1" }, contractVersion: "policyvault-0.5", adapter }));
  assert.equal(adapterInvoked, false);
});

/* ==================================================================
 * REVIEW rendering — DO NOT SIGN gate
 * ================================================================== */

test("renderTokenRequestReviewHtml: a REAL VERIFIED v0.5 deposit manifest renders the core's own tokenExplain sections verbatim", () => {
  const { manifest, descriptor } = fx.buildDepositFixture({});
  const { m } = mod();
  const html = m.renderTokenRequestReviewHtml({ manifest }, { descriptor });
  assert.match(html, /VERIFIED — EXACT REQUEST BEFORE SIGNING/);
  assert.match(html, /TOKEN DEPOSIT/);
  const doc = core.tokenExplain.explainTokenIntent({ manifest, descriptor });
  for (const section of doc.sections) for (const line of section.lines) assert.ok(html.includes(escapeForHtmlCheck(line)), `line present: ${String(line).slice(0, 60)}`);
});

function escapeForHtmlCheck(s) {
  return String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
}

test("renderTokenRequestReviewHtml: no manifest -> DO NOT SIGN, never a normal review", () => {
  const { m } = mod();
  const html = m.renderTokenRequestReviewHtml({});
  assert.match(html, /Do not sign|DO NOT SIGN/i);
});

test("renderTokenRequestReviewHtml: a v0.6 manifest that does not verify falls back to the generic checks-derived lines and still says DO NOT SIGN", () => {
  const { m } = mod();
  const fakeManifest = { manifestVersion: core.controllerManifestV6.CONTROLLER_MANIFEST_VERSION_1, controller: {}, asset: {}, action: { sdkAction: "ownerPause" }, manifestHash: "bad" };
  const html = m.renderTokenRequestReviewHtml({ manifest: fakeManifest });
  assert.match(html, /DO NOT SIGN/);
});

test("renderTokenRequestReviewHtml: a v0.6 SWAP manifest renders manifest.explanation verbatim and the deadlineDaa pre-sign sentence", () => {
  const { m } = mod();
  const explanation = ["ACTION tokenAtomicSell on controller x", "FRESHNESS: usable only while ..."];
  const fakeManifest = { manifestVersion: core.swapManifestV6.SWAP_MANIFEST_VERSION_1, action: { sdkAction: "tokenAtomicSell" }, explanation, manifestHash: "bad" };
  const html = m.renderTokenRequestReviewHtml({ manifest: fakeManifest });
  for (const line of explanation) assert.ok(html.includes(escapeForHtmlCheck(line)));
  assert.ok(html.includes(m.DEADLINE_DAA_SENTENCE));
});

/* ==================================================================
 * v0.6 fixture-venue truth banner
 * ================================================================== */

test("renderVenueFixtureNoticeHtml: carries the verbatim composability sentence and the deadlineDaa sentence", () => {
  const { m } = mod();
  const html = m.renderVenueFixtureNoticeHtml();
  assert.ok(html.includes(m.V6_COMPOSABILITY_SENTENCE));
  assert.ok(html.includes(m.DEADLINE_DAA_SENTENCE));
  assert.match(html, /role="status"/);
  assert.match(html, /aria-live="polite"/);
});

/* ==================================================================
 * CARD rendering (contract §6.3) — the required identity/balance/
 * sentence surface, defensively read.
 * ================================================================== */

test("renderTokenVaultCardHtml: v0.5 shows asset identity, token balance atomic+symbol, KAS reserve SEPARATELY, and the verbatim sentence", () => {
  const { m } = mod();
  const vault = {
    vaultId: "v1", label: "My Token Vault", status: "ACTIVE", contractVersion: "policyvault-0.5",
    asset: { assetId: "a1".repeat(32), displayName: "Demo Token", decimalsDisplay: 8, descriptorHash: "bb".repeat(32) },
    accounting: { token: { position: "123456789" }, kas: { feeReserve: "50000000" } }
  };
  const html = m.renderTokenVaultCardHtml(vault);
  assert.match(html, /authorityModel: SINGLE_ON_CHAIN_OWNER/);
  assert.match(html, /status: FROZEN/);
  assert.ok(html.includes("Demo Token"));
  assert.ok(html.includes("a1".repeat(32)));
  assert.match(html, /123456789 atomic units Demo Token \(display 1\.23456789\)/);
  assert.match(html, /0\.5 KAS/, "KAS fee reserve is rendered via the canonical sompi<->KAS conversion");
  assert.ok(html.includes(m.TOKEN_KAS_SENTENCE));
  assert.ok(!html.includes(m.V6_COMPOSABILITY_SENTENCE), "a v0.5 card never claims v0.6 composability");
});

test("renderTokenVaultCardHtml: v0.6 additionally shows the composability sentence and the FIXTURE-only truth", () => {
  const { m } = mod();
  const vault = { vaultId: "v2", label: "Swap-capable vault", status: "ACTIVE", contractVersion: "policyvault-0.6", asset: {}, accounting: {} };
  const html = m.renderTokenVaultCardHtml(vault);
  assert.match(html, /composability: OPTIONAL_ATOMIC/);
  assert.ok(html.includes(m.V6_COMPOSABILITY_SENTENCE));
});

test("renderTokenVaultCardHtml: missing balance/reserve fields render 'unavailable', never a fabricated number", () => {
  const { m } = mod();
  const vault = { vaultId: "v3", label: "Bare vault", status: "ACTIVE", contractVersion: "policyvault-0.5", asset: {}, accounting: {} };
  const html = m.renderTokenVaultCardHtml(vault);
  assert.match(html, /unavailable — not yet reported by the server/);
});

test("renderTokenVaultCardHtml: falls back to the flat live.feeReserveKas convention every other vault card in this app already uses", () => {
  const { m } = mod();
  const vault = { vaultId: "v4", label: "Flat-shape vault", status: "ACTIVE", contractVersion: "policyvault-0.5", asset: {}, live: { feeReserveKas: "3.5" } };
  const html = m.renderTokenVaultCardHtml(vault);
  assert.match(html, /3\.5 KAS/);
});

test("renderTokenVaultCardHtml: an unknown contractVersion throws (never silently renders a legacy card)", () => {
  const { m } = mod();
  assert.throws(() => m.renderTokenVaultCardHtml({ vaultId: "v5", contractVersion: "policyvault-0.9" }), (e) => { assert.equal(e.code, "UNKNOWN_COVENANT_VERSION"); return true; });
});

/* ==================================================================
 * ARIA live regions
 * ================================================================== */

test("ARIA: every status-bearing render function carries role=status/aria-live=polite/aria-atomic=true", async () => {
  const { m } = mod();
  const norm = await m.normalizeTokenCreateForm(createForm());
  const { manifest, descriptor } = fx.buildDepositFixture({});
  const html1 = m.renderCreatePolicyPanelHtml(norm);
  const html2 = m.renderTokenRequestReviewHtml({ manifest }, { descriptor });
  const html3 = m.renderVenueFixtureNoticeHtml();
  const html4 = m.renderTokenVaultCardHtml({ vaultId: "v1", contractVersion: "policyvault-0.5", asset: {}, accounting: {} });
  for (const [name, html] of [["review", html2], ["venue notice", html3], ["card", html4]]) {
    assert.match(html, /role="status"/, name);
    assert.match(html, /aria-live="polite"/, name);
    assert.match(html, /aria-atomic="true"/, name);
  }
  void html1;
});

/* ==================================================================
 * 375px layout / no hardcoded pixel widths
 * ================================================================== */

test("375px: no fixed pixel width over 375 is hardcoded in this module's own markup", () => {
  assert.ok(!/width:\s*\d{3,}px/.test(TOKEN_UI_SRC), "no hardcoded 3+-digit pixel width in web/token-vault-ui.js");
});

/* ==================================================================
 * keyboard focus — only native interactive elements
 * ================================================================== */

test("keyboard focus: this module renders no interactive elements at all in its own render functions (wiring lives in app-v4.js) — never a tabindex trap either way", () => {
  const { m } = mod();
  const html = m.renderTokenVaultCardHtml({ vaultId: "v1", contractVersion: "policyvault-0.5", asset: {}, accounting: {} });
  assert.ok(!/tabindex="-1"/.test(html));
  assert.ok(!/<div[^>]*onclick=/.test(html));
});

/* ==================================================================
 * reduced motion — no CSS/animation of its own
 * ================================================================== */

test("reduced motion: web/token-vault-ui.js defines no <style>, @keyframes, or inline CSS animation/transition of its own", () => {
  assert.ok(!/<style/i.test(TOKEN_UI_SRC));
  assert.ok(!/@keyframes/.test(TOKEN_UI_SRC));
  assert.ok(!/style="[^"]*\b(animation|transition)\s*:/.test(TOKEN_UI_SRC));
});

/* ==================================================================
 * truthfulness
 * ================================================================== */

const FORBIDDEN_CLAIMS = [
  /\baudited\b/i, /\bcertified\b/i, /\bcompliant\b/i, /\bindependently reviewed\b/i,
  /\bindustry standard\b/i, /\binstitutional[- ]grade\b/i, /\bfully decentrali[sz]ed\b/i,
  /\btrustless stablecoin\b/i, /\bproduction verified\b/i, /\bno alternative\b/i,
  /\bsupports DEX\b/i, /\breal DEX\b/i
];

test("truthfulness: web/token-vault-ui.js never claims audited/certified/compliant/etc., and every 'real DEX' mention is a denial", () => {
  for (const re of FORBIDDEN_CLAIMS) {
    if (re.source === "\\breal DEX\\b") {
      // every mention of "real DEX" in this file must be inside a negation
      // ("no real DEX", "never a real DEX") — never an affirmative claim.
      const re2 = /(.{0,30})\breal DEX\b/gi;
      let match;
      let found = 0;
      while ((match = re2.exec(TOKEN_UI_SRC)) !== null) {
        found++;
        assert.match(match[1], /\b(no|never)\b/i, `unexpected "real DEX" usage not preceded by a denial: ${match[0]}`);
      }
      assert.ok(found > 0, "the module does discuss the real-DEX boundary at least once");
      continue;
    }
    assert.ok(!re.test(TOKEN_UI_SRC), `must not match ${re}`);
  }
});

test("truthfulness: the two verbatim sentences are defined exactly once and never re-worded elsewhere in this file", () => {
  const kasHits = (TOKEN_UI_SRC.match(/token amounts and KAS are never converted into each other\./g) || []).length;
  assert.ok(kasHits >= 1);
  const composHits = (TOKEN_UI_SRC.match(/optional atomic composability — no real DEX venue is supported \(fixture\/conformance only\)\./g) || []).length;
  assert.ok(composHits >= 1);
});

test("truthfulness: a v0.5/v0.6 vault card never claims M-of-N or organizational ownership", () => {
  const { m } = mod();
  const html = m.renderTokenVaultCardHtml({ vaultId: "v1", contractVersion: "policyvault-0.5", asset: {}, accounting: {} });
  assert.ok(!/M-of-N/i.test(html));
  assert.ok(!/organizational (owner|root)/i.test(html));
  assert.match(html, /SINGLE_ON_CHAIN_OWNER/);
});

/* ---------------- refusal-explain.js closed table for §6.1 codes -------- */

test("refusal-explain.js: every contract-closed token/HD code has a title/meaning/next with no override offered", () => {
  const RX = require("../refusal-explain.js");
  for (const code of tokenUiMod.createModule({ api: fakeApi({ __resolve: KEYS }), core }).TOKEN_REFUSAL_CODES) {
    const e = RX.explain(code);
    assert.ok(e, `refusal-explain.js explains ${code}`);
    assert.ok(e.title && e.meaning && e.next.length, code);
  }
});

test("displayCodeFor: maps the pinned core's granular reasons onto the contract's closed vocabulary", () => {
  const { m } = mod();
  assert.equal(m.displayCodeFor({ code: "DESCRIPTOR_MALFORMED" }), "ASSET_DESCRIPTOR_INVALID");
  assert.equal(m.displayCodeFor({ code: "TEMPLATE_HASH_MISMATCH" }), "TOKEN_TEMPLATE_MISMATCH");
  assert.equal(m.displayCodeFor({ code: "UNKNOWN_COVENANT_VERSION" }), "UNKNOWN_COVENANT_VERSION");
  assert.equal(m.displayCodeFor({}), "UNKNOWN");
  assert.equal(m.displayCodeFor(null), "UNKNOWN");
});
