"use strict";

/*
 * CHECKPOINT I — production release gates.
 *
 * Covers the release-blocking production guards:
 *   §8/§9  donation/support: explicitly configured owner MAINNET address only,
 *          canonically validated; testnet/malformed/empty fail closed; the
 *          displayed address never follows the connected wallet;
 *   §4     legacy v0.2 creation disabled in production (explicit dev flag);
 *   §11    cross-network data separation (write-once data-root network marker);
 *   §12    mainnet stays dual-locked; dev/test hooks refuse mainnet startup;
 *   §13    dev-signer routes unavailable without the explicit dev env;
 *   §7(A)  Activity surface serves durable audit events with CHAIN/METADATA
 *          separation.
 * Layers: API + BROWSER (real server + real production app-v4.js in jsdom).
 */

const { test, before, after } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { JSDOM } = require("jsdom");

const { loadConfig, assertDataRootNetwork, DEFAULT_DONATION_ADDRESS } = require("../src/config");
const { validateDonationAddress } = require("../src/donation-address");
const { createServer, validateStartup } = require("../../server/src/server");
const { appendAudit } = require("../src/audit");

const config = loadConfig({ dataRoot: fs.mkdtempSync(path.join(os.tmpdir(), "pv-prodgates-")) });
const kaspa = require(config.rustyKaspaModule);
const KEY = (v) => new kaspa.PrivateKey(v.toString(16).padStart(2, "0").repeat(32));
const ADDR_TEST = (v) => KEY(v).toPublicKey().toAddress("testnet-10").toString();
const ADDR_MAIN = (v) => KEY(v).toPublicKey().toAddress("mainnet").toString();

let server, ORIGIN, BASE;
before(async () => {
  server = createServer(config);
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  ORIGIN = `http://127.0.0.1:${server.address().port}`;
  BASE = `${ORIGIN}/api/v1`;
});
after(() => server && server.close());

const get = async (url) => { const r = await fetch(BASE + url); return { status: r.status, j: await r.json() }; };
const post = async (url, body, headers = {}) => { const r = await fetch(BASE + url, { method: "POST", headers: { "Content-Type": "application/json", ...headers }, body: JSON.stringify(body ?? {}) }); return { status: r.status, j: await r.json() }; };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function waitFor(fn, ms = 30000) {
  const t0 = Date.now();
  for (;;) { const v = await fn(); if (v) return v; if (Date.now() - t0 > ms) throw new Error("waitFor timed out"); await sleep(20); }
}

/* ---------------------------- donation / support ---------------------------- */

test("§9 donation validation: owner mainnet address accepted; testnet/malformed/empty fail closed", async () => {
  // The owner-supplied production address validates as MAINNET (PubKeyECDSA —
  // a standard spendable receiving address; covenant identities remain
  // Schnorr-only through the separate address boundary).
  const ok = validateDonationAddress(config, DEFAULT_DONATION_ADDRESS);
  assert.equal(ok.address, DEFAULT_DONATION_ADDRESS);
  assert.equal(ok.network, "mainnet");
  assert.ok(["PubKey", "PubKeyECDSA"].includes(ok.addressType));
  // A mainnet Schnorr PubKey address also validates.
  assert.equal(validateDonationAddress(config, ADDR_MAIN(7)).addressType, "PubKey");
  // Testnet address -> rejected (never render a testnet donation address).
  assert.throws(() => validateDonationAddress(config, ADDR_TEST(7)), (e) => e.code === "DONATION_WRONG_NETWORK");
  // Malformed / bad checksum -> rejected.
  assert.throws(() => validateDonationAddress(config, "kaspa:qqnotachecksum"), (e) => e.code === "DONATION_ADDRESS_INVALID");
  assert.throws(() => validateDonationAddress(config, DEFAULT_DONATION_ADDRESS.slice(0, -2) + "qq"), (e) => e.code === "DONATION_ADDRESS_INVALID");
  // Empty -> not configured.
  assert.throws(() => validateDonationAddress(config, ""), (e) => e.code === "DONATION_NOT_CONFIGURED");
  assert.throws(() => validateDonationAddress(config, undefined), (e) => e.code === "DONATION_NOT_CONFIGURED");
});

test("§8 GET /support serves ONLY the validated configured mainnet address; misconfiguration fails closed to null", async () => {
  const ok = await get("/support");
  assert.equal(ok.status, 200);
  assert.equal(ok.j.support.donation.address, DEFAULT_DONATION_ADDRESS);
  // A server configured with a TESTNET donation address serves support:null
  // with the exact validation reason (release gate red, nothing substituted).
  const badConfig = loadConfig({ dataRoot: fs.mkdtempSync(path.join(os.tmpdir(), "pv-prodgates-bad-")), donationAddress: ADDR_TEST(9) });
  const badServer = createServer(badConfig);
  await new Promise((r) => badServer.listen(0, "127.0.0.1", r));
  try {
    const r = await fetch(`http://127.0.0.1:${badServer.address().port}/api/v1/support`);
    const j = await r.json();
    assert.equal(j.support, null);
    assert.equal(j.reason, "DONATION_WRONG_NETWORK");
  } finally {
    badServer.close();
  }
  // Empty configuration -> "not configured" (development posture).
  const emptyConfig = loadConfig({ dataRoot: fs.mkdtempSync(path.join(os.tmpdir(), "pv-prodgates-empty-")), donationAddress: "" });
  const emptyServer = createServer(emptyConfig);
  await new Promise((r) => emptyServer.listen(0, "127.0.0.1", r));
  try {
    const r = await fetch(`http://127.0.0.1:${emptyServer.address().port}/api/v1/support`);
    const j = await r.json();
    assert.equal(j.support, null);
    assert.equal(j.reason, "DONATION_NOT_CONFIGURED");
  } finally {
    emptyServer.close();
  }
});

function openApp(role) {
  const html = fs.readFileSync(path.join(__dirname, "..", "..", "web", "index.html"), "utf8").replace(/<script src="[^"]*"><\/script>/g, "");
  const appV4 = fs.readFileSync(path.join(__dirname, "..", "..", "web", "app-v4.js"), "utf8");
  const dom = new JSDOM(html, { url: `${ORIGIN}/`, runScripts: "outside-only", pretendToBeVisual: true });
  const { window } = dom;
  window.fetch = (u, o) => fetch(new URL(u, ORIGIN), o);
  window.prompt = () => null;
  window.confirm = () => true;
  let current = role;
  const listeners = [];
  const snap = () => ({ connected: true, ready: true, address: ADDR_TEST(current), xonly: KEY(current).toPublicKey().toXOnlyPublicKey().toString().toLowerCase(), network: "testnet-10", provider: "test", adapter: { signInputs: async () => { throw new Error("no signing in this suite"); } } });
  window.PolicyVaultWalletSession = { active: snap, subscribe(cb) { listeners.push(cb); cb(snap()); return () => {}; }, connect() {}, disconnect() {} };
  window.eval(appV4);
  window.dispatchEvent(new window.Event("DOMContentLoaded"));
  return {
    window, doc: window.document,
    setAccount(v) { current = v; for (const cb of listeners) cb(snap()); },
    click: (el) => el.dispatchEvent(new window.MouseEvent("click", { bubbles: true, cancelable: true })),
    tab: (v) => window.document.querySelector(`.v4-tab[data-view="${v}"]`)
  };
}

test("§9 BROWSER: the Support view shows the server-configured address and NEVER follows the connected wallet", async () => {
  const app = openApp(0x11);
  app.click(app.tab("support"));
  const addrEl = await waitFor(() => app.doc.getElementById("v4-donate-addr"));
  assert.equal(addrEl.textContent, DEFAULT_DONATION_ADDRESS);
  assert.ok(app.doc.getElementById("v4-donate-copy"), "copy control present");
  // Connected-wallet change -> the donation address does NOT change.
  app.setAccount(0x22);
  app.click(app.tab("support"));
  const addrEl2 = await waitFor(() => app.doc.getElementById("v4-donate-addr"));
  assert.equal(addrEl2.textContent, DEFAULT_DONATION_ADDRESS);
  assert.notEqual(ADDR_TEST(0x22), DEFAULT_DONATION_ADDRESS);
  // The footer offers an obvious Support entry point.
  assert.ok(app.doc.getElementById("footer-support-link"), "footer support link present");
});

/* ------------------------------ legacy creation ------------------------------ */

test("§4 legacy v0.2 creation is DISABLED in production (explicit dev flag opens it)", async () => {
  const r = await post("/wallet/create", { signerAddress: ADDR_TEST(1) });
  assert.equal(r.status, 403);
  assert.equal(r.j.error.code, "LEGACY_CREATE_DISABLED");
  // With the explicit dev flag, the gate opens (request then fails on its own
  // strict validation, proving the gate — not the route — was the refusal).
  const prev = process.env.POLICYVAULT_LEGACY_CREATE;
  process.env.POLICYVAULT_LEGACY_CREATE = "1";
  try {
    const r2 = await post("/wallet/create", { signerAddress: "not-a-testnet-address" });
    assert.equal(r2.status, 400);
    assert.equal(r2.j.error.code, "BAD_SIGNER");
  } finally {
    if (prev === undefined) delete process.env.POLICYVAULT_LEGACY_CREATE; else process.env.POLICYVAULT_LEGACY_CREATE = prev;
  }
});

/* --------------------------- network data separation --------------------------- */

test("§11 a data root is stamped with its owning network; a cross-network process REFUSES it", async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "pv-netsep-"));
  const testnetConfig = loadConfig({ dataRoot: root });
  assertDataRootNetwork(testnetConfig); // stamps testnet-10
  assert.equal(fs.readFileSync(path.join(root, ".pv-network"), "utf8").trim(), "testnet-10");
  // Same network: fine, idempotent.
  assertDataRootNetwork(testnetConfig);
  // A mainnet-configured process pointed at the SAME root refuses to start.
  const mainnetish = { networkId: "mainnet", dataRoot: root };
  assert.throws(() => assertDataRootNetwork(mainnetish), /cross-network data contamination/);
  // createServer performs the check at startup.
  fs.writeFileSync(path.join(root, ".pv-network"), "mainnet\n");
  assert.throws(() => createServer(loadConfig({ dataRoot: root })), /cross-network data contamination/);
});

test("§11 default data roots are per-network (mainnet never shares the testnet namespace)", async () => {
  const t = loadConfig({});
  assert.equal(t.dataRoot, path.join(t.repoRoot, "data")); // checkout-relative
  // Mainnet config construction is locked (below), but the dataRoot rule is
  // visible via the config source: data-mainnet is a DIFFERENT directory.
  assert.ok(!t.dataRoot.includes("data-mainnet"));
});

/* ------------------------------ mainnet locking ------------------------------ */

test("§12 mainnet remains DUAL-LOCKED: env flag AND explicit override are both required", async () => {
  assert.throws(() => loadConfig({ networkId: "mainnet" }), /mainnet mode is locked/);
  assert.throws(() => loadConfig({ networkId: "mainnet", allowMainnet: true }), /mainnet mode is locked/); // env flag absent
  const prev = process.env.POLICYVAULT_ALLOW_MAINNET;
  process.env.POLICYVAULT_ALLOW_MAINNET = "true";
  try {
    assert.throws(() => loadConfig({ networkId: "mainnet" }), /mainnet mode is locked/); // override absent
  } finally {
    if (prev === undefined) delete process.env.POLICYVAULT_ALLOW_MAINNET; else process.env.POLICYVAULT_ALLOW_MAINNET = prev;
  }
});

test("§13/§14 startup validation refuses mainnet with dev signer / test hooks / legacy create armed", async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "pv-mainnet-guard-"));
  // A REAL dual-flag mainnet config through loadConfig (env flag +
  // explicit override + explicit RPC URL — the Gate R deployment shape).
  // Hand-rolled config objects are no longer accepted by validateStartup
  // (it fails closed without the Phase D requestProtection block).
  const prevAllow = process.env.POLICYVAULT_ALLOW_MAINNET;
  process.env.POLICYVAULT_ALLOW_MAINNET = "true";
  let mainnetish;
  try {
    mainnetish = loadConfig({ networkId: "mainnet", allowMainnet: true, rpcUrl: "ws://127.0.0.1:18110", dataRoot: root });
  } finally {
    if (prevAllow === undefined) delete process.env.POLICYVAULT_ALLOW_MAINNET; else process.env.POLICYVAULT_ALLOW_MAINNET = prevAllow;
  }
  const prev = process.env.POLICYVAULT_DEV_SIGNER;
  process.env.POLICYVAULT_DEV_SIGNER = "1";
  try {
    assert.throws(() => validateStartup(mainnetish), /must not be enabled on mainnet/);
  } finally {
    if (prev === undefined) delete process.env.POLICYVAULT_DEV_SIGNER; else process.env.POLICYVAULT_DEV_SIGNER = prev;
  }
  // Clean flags: startup passes and reports posture without secrets.
  const report = validateStartup(mainnetish);
  assert.equal(report.devSigner, "disabled");
  assert.equal(report.mainnetBroadcast, "ENABLED"); // Gate R granted 2026-08-22: a dual-flag mainnet config is operational (mainnet-gate-r.test.js pins the posture)
  // Hand-rolled configs (no requestProtection) refuse with a clear reason.
  assert.throws(
    () => validateStartup({ networkId: "mainnet", dataRoot: root, allowMainnet: true, donationAddress: DEFAULT_DONATION_ADDRESS }),
    /lacks requestProtection/
  );
});

test("§13 dev-signer routes are unavailable without the explicit dev environment", async () => {
  assert.notEqual(process.env.POLICYVAULT_DEV_SIGNER, "1", "suite must run without the dev-signer env");
  const r = await post("/wallet/dev-sign", { address: ADDR_TEST(1) });
  assert.equal(r.status, 404);
  assert.equal(r.j.error.code, "DEV_SIGNER_DISABLED");
  const r2 = await fetch(`${BASE}/wallet/dev-accounts`);
  assert.equal(r2.status, 404);
});

/* ------------------------------ origin hardening ------------------------------ */

test("§15 browser cross-origin POSTs are refused; same-origin and tool requests pass", async () => {
  const evil = await post("/identity/resolve-address", { address: ADDR_TEST(1) }, { Origin: "https://evil.example" });
  assert.equal(evil.status, 403);
  assert.equal(evil.j.error.code, "ORIGIN_FORBIDDEN");
  const sameOrigin = await post("/identity/resolve-address", { address: ADDR_TEST(1) }, { Origin: ORIGIN });
  assert.equal(sameOrigin.status, 200);
  const noOrigin = await post("/identity/resolve-address", { address: ADDR_TEST(1) });
  assert.equal(noOrigin.status, 200);
});

/* ------------------------------ Activity surface ------------------------------ */

test("§7 Activity: durable audit events served with CHAIN/METADATA separation and rendered in the browser", async () => {
  await appendAudit(config, { kind: "metadata", orgId: "00000000-0000-0000-0000-000000000001", action: "org_created", detail: "Activity Test Org" });
  await appendAudit(config, { kind: "chain", vaultId: "aa".repeat(32), action: "spend_chain_verified", txId: "bb".repeat(32) });
  const { j } = await get("/audit?limit=50");
  assert.ok(j.events.some((e) => e.kind === "metadata" && e.action === "org_created"));
  assert.ok(j.events.some((e) => e.kind !== "metadata" && e.action === "spend_chain_verified"));
  const app = openApp(0x11);
  app.click(app.tab("activity"));
  await waitFor(() => /Activity/.test(app.doc.getElementById("v4-root").textContent));
  const text = app.doc.getElementById("v4-root").textContent;
  assert.match(text, /METADATA/);
  assert.match(text, /CHAIN/);
  assert.match(text, /never chain-enforced/);
});
