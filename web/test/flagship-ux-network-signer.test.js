"use strict";

/*
 * BROWSER — wrong-network diagnosis and signer-identity messages
 * (TRACK 11 flagship UX pass).
 *
 * N1 (MED-HIGH, wrong-network path). Signing fails closed whenever the
 * wallet's network and the NODE-reported network are not the same known
 * value — and that INCLUDES the case where PolicyVault could not read its
 * node's network at all (the same fail-closed condition the top banner
 * shows as "NETWORK STATUS UNKNOWN"). Both cases rendered the identical
 * sentence, "switch KasWare to the configured network", sending users to
 * fiddle with their wallet over a backend problem their wallet cannot fix.
 * They are now distinguished. NO GATE CHANGED — only the explanation.
 *
 * S1 (MED, signer mismatch). The refusal a user compares against their
 * wallet used to truncate BOTH addresses (short() = 8 chars + 6 chars), so
 * two accounts could be indistinguishable in the very message telling them
 * they picked the wrong one. Both are now shown in full, and SIGNER_CHANGED
 * names the expected and the current account.
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const WEB_DIR = path.join(__dirname, "..");
const APP_V4 = fs.readFileSync(path.join(WEB_DIR, "app-v4.js"), "utf8");

/* ---------------- harness (same shape as ux-responsiveness.test.js) ------- */

function makeEnv(sessionSnap) {
  const elements = new Map();
  const element = (id) => {
    if (!elements.has(id)) {
      elements.set(id, {
        id, innerHTML: "", textContent: "", className: "", value: "", disabled: false,
        style: {}, dataset: {}, options: [], onclick: null, addEventListener() {},
        insertAdjacentHTML() {}, querySelectorAll: () => [], querySelector: () => null,
        classList: { toggle() {}, add() {}, remove() {} }, closest: () => null
      });
    }
    return elements.get(id);
  };
  let subscriber = null;
  const sandbox = {
    console,
    document: { getElementById: element, querySelectorAll: () => [], addEventListener() {} },
    localStorage: { getItem: () => null, setItem() {}, removeItem() {} },
    setTimeout: (fn) => { return 0; }, clearTimeout() {},
    fetch: () => Promise.resolve({ ok: true, status: 200, json: async () => ({ vaults: [], organizations: [], assignments: {}, requests: [] }) }),
    crypto: { getRandomValues: (a) => a.fill(7) },
    PolicyVaultWalletSession: {
      active: () => sessionSnap,
      subscribe: (cb) => { subscriber = cb; return () => {}; }
    }
  };
  sandbox.listeners = {};
  sandbox.addEventListener = (n, f) => { (sandbox.listeners[n] = sandbox.listeners[n] || []).push(f); };
  sandbox.window = sandbox;
  sandbox.globalThis = sandbox;
  vm.createContext(sandbox);
  vm.runInContext(APP_V4, sandbox, { filename: "app-v4.js" });
  // Fire the module's own DOMContentLoaded wiring so it subscribes to the
  // canonical wallet session exactly as it does in a real page.
  const boot = () => (sandbox.listeners.DOMContentLoaded || []).forEach((f) => f());
  return {
    element, sandbox, boot,
    V4: sandbox.window.PolicyVaultV4,
    notify: (snap) => { if (!subscriber) boot(); return subscriber && subscriber(snap); }
  };
}

const settle = async () => { for (let i = 0; i < 8; i++) await Promise.resolve(); };

const BASE = {
  connected: true, ready: false, address: "kaspa:qowner", xonly: "aa".repeat(32),
  provider: "kasware", adapter: {}, auth: "AUTHENTICATED"
};

/* ---------------- N1: the two not-ready causes are distinguished ---------- */

test("node network UNKNOWN: the app says signing is disabled and that the WALLET is not the problem", async () => {
  const { element, V4 } = makeEnv({ ...BASE, network: "mainnet", serverNetwork: null });
  Object.assign(V4._state, { view: "vaults", address: "kaspa:qowner", network: "mainnet", nodeNetwork: null, serverNetwork: null, ready: false });
  await V4.render();
  const root = element("v4-root");
  assert.match(root.innerHTML, /Network status unknown — signing is disabled/);
  assert.match(root.innerHTML, /has not confirmed which Kaspa network its node is on/);
  assert.match(root.innerHTML, /not a problem with your wallet/);
  assert.ok(!/Switch KasWare to/.test(root.innerHTML), "it must NOT tell the user to change networks");
});

test("wallet on the WRONG network (node network known): the app still says switch the wallet", async () => {
  const { element, V4 } = makeEnv({ ...BASE, network: "testnet-10", serverNetwork: "mainnet" });
  Object.assign(V4._state, { address: "kaspa:qowner", network: "testnet-10", nodeNetwork: "mainnet", serverNetwork: "mainnet", ready: false });
  await V4.render();
  const root = element("v4-root");
  assert.match(root.innerHTML, /Wallet is not on mainnet/);
  assert.match(root.innerHTML, /switch KasWare to mainnet/i);
  assert.ok(!/Network status unknown/.test(root.innerHTML));
});

test("no wallet at all still says connect — never a network diagnosis", async () => {
  const { element, V4 } = makeEnv({ connected: false, ready: false, address: null, network: null, serverNetwork: null, auth: "AUTHENTICATED" });
  Object.assign(V4._state, { address: null, ready: false, nodeNetwork: null });
  await V4.render();
  assert.match(element("v4-root").innerHTML, /Connect KasWare in the Wallet panel above to begin/);
});

test("the node-unknown explanation derives from the session's node-reported network only (no second probe, no gate)", () => {
  assert.match(APP_V4, /state\.nodeNetwork = snap\.serverNetwork \?\? null;/, "read from the canonical session snapshot");
  // It must never be used to decide readiness or to permit anything.
  assert.ok(!/state\.ready = [^\n]*nodeNetwork/.test(APP_V4), "nodeNetwork never sets readiness");
  assert.ok(!/nodeNetwork[^\n]*(walletSign|signInputs|verifyForSigning)/.test(APP_V4), "nodeNetwork never gates signing");
  // The explanation is pure text: it reads no endpoint of its own (the
  // banner's derivation lives in app.js and is untouched).
  const helper = /const notReadyNodeUnknownHtml = \(\) =>[\s\S]*?;\n/.exec(APP_V4)[0];
  assert.ok(!/fetch|getJSON|network\/status/.test(helper), "the explanation issues no read of its own");
});

test("a change in the node-reported network re-renders the explanation", async () => {
  const { element, V4, notify } = makeEnv({ ...BASE, network: "mainnet", serverNetwork: null });
  Object.assign(V4._state, { address: "kaspa:qowner", network: "mainnet", nodeNetwork: null, ready: false });
  await V4.render();
  assert.match(element("v4-root").innerHTML, /Network status unknown/);
  // The node comes back, reporting a network the wallet is NOT on: the
  // explanation must switch from "we cannot tell" to "switch your wallet".
  await notify({ ...BASE, network: "testnet-10", serverNetwork: "mainnet" });
  await settle();
  assert.equal(V4._state.nodeNetwork, "mainnet", "the snapshot's node network was adopted");
  assert.match(element("v4-root").innerHTML, /Wallet is not on mainnet/);
  assert.ok(!/Network status unknown/.test(element("v4-root").innerHTML), "the stale diagnosis is gone");
});

/* ---------------- S1: identity refusals show full addresses -------------- */

test("SIGNER_MISMATCH names BOTH accounts in full — never truncated", async () => {
  const connected = "kaspa:qyp" + "a".repeat(58);
  const expected = "kaspa:qyp" + "b".repeat(58);
  const { V4 } = makeEnv({ ...BASE, ready: true, address: connected, network: "mainnet", serverNetwork: "mainnet", adapter: { signInputs: async () => "signed" } });
  let err = null;
  try {
    await V4._walletSign("UNSIGNED", [{ index: 0, sighashType: 1 }], expected, { ok: true, unsignedSafeJson: "UNSIGNED" });
  } catch (e) { err = e; }
  assert.ok(err, "it refuses");
  assert.equal(err.code, "SIGNER_MISMATCH");
  assert.ok(err.message.includes(connected), "the connected address is shown in full");
  assert.ok(err.message.includes(expected), "the expected address is shown in full");
  assert.ok(!err.message.includes("…"), "no ellipsis in an identity refusal");
});

test("app-v4.js never wraps a signer-identity refusal address in short()", () => {
  const sign = /async function walletSign\([\s\S]*?\n  \}/.exec(APP_V4)[0];
  assert.ok(!/short\(s\.address\)/.test(sign), "the connected address is not truncated");
  assert.ok(!/short\(expectedSigner\)/.test(sign), "the expected signer is not truncated");
  assert.match(sign, /expected \$\{expectedSigner \|\| "the connected account"\}, now \$\{after\.address[\s\S]*?SIGNER_CHANGED/, "SIGNER_CHANGED names the expected and the current account");
});

test("networkLabel() prefers the NODE-reported identity (the value the signing gate uses), then /health, then a neutral phrase", async () => {
  const m = /const networkLabel = \(\) => ([^;]+);/.exec(APP_V4);
  assert.ok(m, "helper found");
  assert.equal(m[1].trim(), 'state.nodeNetwork || state.serverNetwork || "the configured network"');
  assert.ok(!/testnet-10|mainnet/.test(m[1]), "still names no specific network as a fallback");

  const { element, V4 } = makeEnv({ ...BASE, network: "testnet-10", serverNetwork: "mainnet" });
  // /health has not resolved; the node probe has. The user must still be
  // told WHICH network to switch to.
  Object.assign(V4._state, { address: "kaspa:qowner", network: "testnet-10", nodeNetwork: "mainnet", serverNetwork: null, ready: false });
  await V4.render();
  assert.match(element("v4-root").innerHTML, /Wallet is not on mainnet/);
});
