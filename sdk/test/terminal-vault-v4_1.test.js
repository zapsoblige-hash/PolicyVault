"use strict";

/*
 * TERMINAL-VAULT correction (H2 closeout Phase A / Checkpoint I §27).
 *
 * A closed vault (RECOVERED / TERMINATED_UNKNOWN, live === null) is
 * permanently READ-ONLY history:
 *   - the SERVER independently rejects EVERY write action with VAULT_TERMINAL
 *     and ZERO durable mutation (no request, no claim, manifest byte-identical);
 *   - the BROWSER renders zero transaction-producing controls — for the
 *     owner, the agent, and any other wallet — and never the misleading
 *     "0-of-0" approvals display (historical numbers are not fabricated);
 *   - a hard refresh (fresh session) keeps it terminal.
 *
 * Layers: API + BROWSER (real server handler + real production app-v4.js in
 * jsdom; the wallet session is the only mocked seam and nothing ever signs).
 */

const { test, before, after } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { JSDOM } = require("jsdom");

const { loadConfig } = require("../src/config");
const { createServer } = require("../../server/src/server");
const wr4 = require("../src/wallet-requests-v4");
const { MANIFEST_SCHEMA_V4, persistManifestV4 } = require("../src/manifest-v4");

const config = loadConfig({ dataRoot: fs.mkdtempSync(path.join(os.tmpdir(), "pv-terminal-")) });
const kaspa = require(config.rustyKaspaModule);
const KEY = (v) => new kaspa.PrivateKey(v.toString(16).padStart(2, "0").repeat(32));
const XO = (v) => KEY(v).toPublicKey().toXOnlyPublicKey().toString().toLowerCase();
const ADDR = (v) => KEY(v).toPublicKey().toAddress(config.networkId).toString();
const KAS = 100000000n;
const OWNER = 1, AGENT = 0x1e, RECIP = 0x28;
const VAULT = "7a".repeat(32);

function seedTerminalVault() {
  // Mirrors the REAL post-ownerRecover manifest shape (status RECOVERED,
  // live null, historical registry retained) — the schema the live H2 vault
  // 0c3e785f… persisted after its chain-verified terminal recovery.
  const registry = [{ agentPk: XO(AGENT), maxPerSpend: (20n * KAS).toString(), periodBudget: (50n * KAS).toString(), periodLengthDaa: "864000", periodStartDaa: "541000000", periodSpent: "0", approvalThreshold: (5n * KAS).toString(), agentMaxFeePerTx: (1n * KAS).toString(), recipients: [XO(RECIP)] }];
  persistManifestV4(config, {
    schema: MANIFEST_SCHEMA_V4, contractVersion: "policyvault-0.4.1", networkId: config.networkId, vaultId: VAULT,
    label: "terminal-history", status: "RECOVERED", template: { owner: XO(OWNER), vaultId: VAULT }, agentRegistry: registry,
    live: null, creationTxId: "42".repeat(32), latestTransitionTxId: "43".repeat(32), lastTransition: null
  });
}

const dirFiles = (rel) => {
  const p = path.join(config.dataRoot, rel);
  return fs.existsSync(p) ? fs.readdirSync(p).sort() : [];
};
const manifestBytes = () => fs.readFileSync(path.join(config.dataRoot, "vaults", VAULT, "manifest.json"));

let server;
let ORIGIN = null, BASE = null;
before(async () => {
  seedTerminalVault();
  server = createServer(config);
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  ORIGIN = `http://127.0.0.1:${server.address().port}`;
  BASE = `${ORIGIN}/api/v1`;
});
after(() => server && server.close());

const post = async (url, body) => { const r = await fetch(BASE + url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body ?? {}) }); return { status: r.status, j: await r.json() }; };
const get = async (url) => { const r = await fetch(BASE + url); return { status: r.status, j: await r.json() }; };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function waitFor(fn, ms = 30000) {
  const t0 = Date.now();
  for (;;) {
    const v = await fn();
    if (v) return v;
    if (Date.now() - t0 > ms) throw new Error("waitFor timed out");
    await sleep(20);
  }
}

test("SERVER: every write action against a terminal vault is refused with VAULT_TERMINAL and ZERO durable mutation", async () => {
  const before1 = manifestBytes();
  const fuel = { outpoint: { transactionId: "44".repeat(32), index: 1 }, amount: (100n * KAS).toString(), scriptPublicKeyHex: `20${XO(OWNER)}ac` };
  const paramsByAction = {
    agentSpend: { agentPk: XO(AGENT), recipient: XO(RECIP), payAmountSompi: (1n * KAS).toString() },
    ownerSetAgentRoot: { fuel, newAgentRoot: "55".repeat(32) },
    ownerSetApprovers: { fuel, newApprovers: { approvers: [XO(RECIP)], approvalM: "1" } },
    ownerTopUp: { fuel, topUpAmountSompi: (1n * KAS).toString() },
    ownerTopUpReserve: { fuel, topUpReserveAmountSompi: (1n * KAS).toString() },
    ownerPause: { fuel },
    ownerUnpause: { fuel },
    ownerRecover: { fuel },
    addAgent: { fuel, agent: { agentPk: XO(0x33), maxPerSpend: "1", periodBudget: "1", periodLengthDaa: "864000", periodStartDaa: "1", periodSpent: "0", approvalThreshold: "0", agentMaxFeePerTx: "1", recipients: [XO(RECIP)] } },
    removeAgent: { fuel, agentPk: XO(AGENT) },
    rotateAgent: { fuel, agentPk: XO(AGENT), agent: {} },
    rePolicyAgent: { fuel, agentPk: XO(AGENT), agent: {} }
  };
  const actions = Object.keys(wr4.ROLE_BY_ACTION);
  assert.ok(actions.length >= 12, "the full v0.4 action map is covered");
  for (const action of actions) {
    const signer = wr4.ROLE_BY_ACTION[action] === "owner" ? ADDR(OWNER) : ADDR(AGENT);
    const r = await post("/wallet/v4/requests", { vaultId: VAULT, action, params: paramsByAction[action] ?? { fuel }, signerAddress: signer });
    assert.equal(r.status, 422, `${action}: ${JSON.stringify(r.j).slice(0, 120)}`);
    assert.equal(r.j.error.code, "VAULT_TERMINAL", `${action} refused as VAULT_TERMINAL`);
  }
  assert.deepEqual(dirFiles("requests"), [], "no durable request was created by any refused write");
  assert.deepEqual(dirFiles("claims/transition"), [], "no transition claim");
  assert.deepEqual(dirFiles("claims/submission"), [], "no submission claim");
  assert.deepEqual(manifestBytes(), before1, "terminal manifest byte-identical after every refused write");
  // The closed vault remains fully readable history.
  const v = (await get(`/vaults/${VAULT}`)).j;
  assert.equal(v.status, "RECOVERED");
  assert.equal(v.operational.status, "CLOSED");
});

function openApp(role) {
  const html = fs.readFileSync(path.join(__dirname, "..", "..", "web", "index.html"), "utf8").replace(/<script src="[^"]*"><\/script>/g, "");
  const appV4 = fs.readFileSync(path.join(__dirname, "..", "..", "web", "app-v4.js"), "utf8");
  const dom = new JSDOM(html, { url: `${ORIGIN}/`, runScripts: "outside-only", pretendToBeVisual: true });
  const { window } = dom;
  window.fetch = (u, o) => fetch(new URL(u, ORIGIN), o);
  window.prompt = () => null;
  window.confirm = () => true;
  const snap = () => ({
    connected: true, ready: true, address: ADDR(role), xonly: XO(role),
    network: "testnet-10", provider: "test",
    adapter: { signInputs: async () => { throw new Error("terminal vaults must never reach signing"); } }
  });
  window.PolicyVaultWalletSession = { active: snap, subscribe(cb) { cb(snap()); return () => {}; }, connect() {}, disconnect() {} };
  window.eval(appV4);
  window.dispatchEvent(new window.Event("DOMContentLoaded"));
  const doc = window.document;
  return {
    doc,
    click: (el) => el.dispatchEvent(new window.MouseEvent("click", { bubbles: true, cancelable: true })),
    tab: (v) => doc.querySelector(`.v4-tab[data-view="${v}"]`)
  };
}

const FORBIDDEN = ["[data-spend]", "[data-repolicy]", "[data-rotate]", "[data-remove]", "[data-addagent]", "[data-setapprovers]", "[data-pause]", "[data-unpause]", "[data-topup]", "[data-topupreserve]", "[data-recover]"];

async function assertTerminalCard(role, label) {
  const app = openApp(role);
  const allPill = await waitFor(() => app.doc.querySelector('[data-status="All"]'));
  app.click(allPill);
  const card = await waitFor(() => app.doc.querySelector(`[data-vault="${VAULT}"]`));
  for (const sel of FORBIDDEN) {
    assert.equal(card.querySelector(sel), null, `${label}: forbidden control ${sel} must not render on a terminal vault`);
  }
  assert.ok(!/0-of-0/.test(card.textContent), `${label}: no misleading 0-of-0 approvals display`);
  assert.match(card.textContent, /read-only history/, `${label}: terminal copy shown`);
  assert.match(card.textContent, /CLOSED/, `${label}: CLOSED status shown`);
  return app;
}

test("BROWSER: a terminal vault renders ZERO transaction-producing controls for the OWNER", async () => {
  await assertTerminalCard(OWNER, "owner");
});

test("BROWSER: a terminal vault renders ZERO transaction-producing controls for the AGENT", async () => {
  await assertTerminalCard(AGENT, "agent");
});

test("BROWSER: hard refresh (fresh session) keeps the vault terminal and read-only; Closed filter lists it", async () => {
  const app = await assertTerminalCard(OWNER, "reload");
  // The Closed pill shows the historical vault too.
  app.click(app.doc.querySelector('[data-status="Closed"]'));
  const card = await waitFor(() => app.doc.querySelector(`[data-vault="${VAULT}"]`));
  for (const sel of FORBIDDEN) assert.equal(card.querySelector(sel), null);
});
