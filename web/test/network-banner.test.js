"use strict";

/*
 * BROWSER regression — network identity banner (2026-08-29 production
 * presentation defect): the live MAINNET deployment displayed the stale
 * hardcoded "TESTNET-10 — no real value · mainnet broadcasting is
 * disabled" banner because (a) web/index.html shipped that string as the
 * default markup and (b) app.js only corrected it after a SUCCESSFUL
 * GET /network/status — any failed/hung probe (e.g. the backend node
 * unreachable or unsynced) left the page asserting a false network
 * identity. Fail-open on network identity is never acceptable.
 *
 * These tests evaluate the REAL production web/app.js in a vm sandbox
 * (same harness style as app-v4-gate.test.js) and prove the fail-closed
 * contract:
 *
 *   1. initial markup is neutral (VERIFYING) — never names a network;
 *   2. resolved mainnet   -> restrained "MAINNET — real KAS" indicator;
 *   3. resolved testnet   -> explicit TESTNET warning banner;
 *   4. pending probe      -> JS writes NOTHING (neutral markup stands);
 *   5. failed probe       -> NETWORK STATUS UNKNOWN, never a network name;
 *   6. malformed response -> NETWORK STATUS UNKNOWN (no networkId = unknown);
 *   7. retry/reconnect    -> a later successful probe replaces UNKNOWN;
 *   8. stale-response ordering -> a LATE response (any outcome) can never
 *      overwrite a newer resolution in either direction (no stale testnet
 *      after mainnet, no stale mainnet after testnet, no late failure
 *      clobbering a success);
 *   9. staging ownership  -> the NON-PRODUCTION staging label is never
 *      overwritten by network resolution;
 *  10. the signing-path network gate (verifyNetwork's fail-closed
 *      comparison) is byte-identical — the banner rework changed ONLY
 *      presentation, and ui.serverNetwork stays null (= signing gate
 *      fails closed) in every unresolved/failed/malformed case.
 *
 * The banner derives from GET /network/status — the node-verified network
 * identity (sdk/src/chain.js connectVerified) that verifyNetwork() gates
 * signing on — NEVER from the hostname, a build-time constant, or cached
 * markup.
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const WEB_DIR = path.join(__dirname, "..");
const APP_JS = fs.readFileSync(path.join(WEB_DIR, "app.js"), "utf8");
const INDEX_HTML = fs.readFileSync(path.join(WEB_DIR, "index.html"), "utf8");

const UNKNOWN_TEXT = "NETWORK STATUS UNKNOWN — verify connection before transacting";
const MAINNET_TEXT = "MAINNET — real KAS";
const TESTNET_TEXT = "TESTNET-10 — no real value · mainnet broadcasting is disabled";

/* ---------------- vm harness ---------------- */

function jsonResponse(body, ok = true) {
  return { ok, status: ok ? 200 : 503, json: async () => body };
}

/*
 * Evaluate the REAL app.js with a minimal DOM stub. `route(path)` returns
 * a Promise of a fetch-response stub (or rejects). setTimeout is captured,
 * never auto-fired: tests fire retry timers explicitly.
 */
function makeEnv(route) {
  const elements = new Map();
  const element = (id) => {
    if (!elements.has(id)) {
      elements.set(id, {
        id,
        innerHTML: "",
        textContent: "",
        className: "",
        value: "",
        disabled: false,
        style: {},
        dataset: {},
        options: [],
        onclick: null,
        addEventListener() {},
        querySelectorAll: () => [],
        querySelector: () => null,
        classList: { toggle() {}, add() {}, remove() {} }
      });
    }
    return elements.get(id);
  };
  const timers = [];
  const sandbox = {
    console,
    document: { getElementById: element, querySelectorAll: () => [], addEventListener() {} },
    localStorage: { getItem: () => null, setItem() {}, removeItem() {} },
    setTimeout: (fn, ms) => (timers.push({ fn, ms }), timers.length),
    clearTimeout() {},
    fetch: (url) => Promise.resolve().then(() => route(String(url))),
    PolicyVaultWallet: require("../wallet.js"),
    PolicyVaultIdentity: {}
  };
  sandbox.window = sandbox;
  sandbox.globalThis = sandbox;
  vm.createContext(sandbox);
  vm.runInContext(APP_JS, sandbox, { filename: "web/app.js" });
  return { sandbox, element, timers, banner: element("testnet-banner"), net: element("net") };
}

/* Default routes for the endpoints boot() touches besides network/status. */
function defaultRoute(p) {
  if (p.endsWith("/health")) return jsonResponse({ ok: true, networkId: "mainnet", authMode: "disabled" });
  if (p.endsWith("/organizations")) return jsonResponse({ organizations: [], roleLabels: [], assignments: {}, assignmentsVersion: 0 });
  if (p.endsWith("/vaults")) return jsonResponse({ vaults: [] });
  if (p.endsWith("/wallet/dev-accounts")) return jsonResponse({}, false);
  return Promise.reject(new Error(`unrouted: ${p}`));
}

const settle = async () => {
  for (let i = 0; i < 40; i++) await new Promise((r) => setImmediate(r));
};

const withStatus = (impl) => (p) => (p.endsWith("/network/status") ? impl() : defaultRoute(p));

/* ---------------- static markup ---------------- */

test("index.html ships a NEUTRAL verifying banner — the initial markup never names a network", () => {
  assert.ok(
    INDEX_HTML.includes('<div id="testnet-banner">VERIFYING NETWORK…</div>'),
    "the banner's initial markup must be the neutral VERIFYING state"
  );
  assert.ok(!INDEX_HTML.includes("TESTNET-10"), "no hardcoded TESTNET-10 anywhere in index.html");
  assert.ok(!INDEX_HTML.includes(MAINNET_TEXT), "the MAINNET indicator must come from a resolved probe, not markup");
  assert.ok(INDEX_HTML.includes("Connect a wallet to begin."), "the pre-JS v4-root placeholder is network-neutral");
});

test("index.html styles all four banner states (neutral base, testnet/unknown/staging warn, restrained mainnet)", () => {
  assert.ok(/#testnet-banner\[data-net="testnet"\], #testnet-banner\[data-net="unknown"\], #testnet-banner\[data-staging\]/.test(INDEX_HTML));
  assert.ok(/#testnet-banner\[data-net="mainnet"\]/.test(INDEX_HTML));
});

/* ---------------- resolution outcomes ---------------- */

test("mainnet status -> restrained MAINNET indicator (visible, data-net=mainnet), serverNetwork=mainnet", async () => {
  const env = makeEnv(withStatus(() => jsonResponse({ networkId: "mainnet", isSynced: true, virtualDaaScore: "123" })));
  await settle();
  assert.equal(env.banner.textContent, MAINNET_TEXT);
  assert.equal(env.banner.dataset.net, "mainnet");
  assert.equal(env.banner.style.display, "", "the indicator informs — it is shown, not hidden");
  assert.equal(env.sandbox.window.PolicyVaultNetworkBanner._serverNetwork(), "mainnet");
  assert.match(env.net.innerHTML, /mainnet · synced · DAA 123/);
});

test("testnet-10 status -> explicit TESTNET-10 warning banner (exact established string)", async () => {
  const env = makeEnv(withStatus(() => jsonResponse({ networkId: "testnet-10", isSynced: true, virtualDaaScore: "9" })));
  await settle();
  assert.equal(env.banner.textContent, TESTNET_TEXT);
  assert.equal(env.banner.dataset.net, "testnet");
  assert.equal(env.sandbox.window.PolicyVaultNetworkBanner._serverNetwork(), "testnet-10");
});

test("pending probe -> JS writes NOTHING to the banner (neutral markup stands; no premature network claim)", async () => {
  const env = makeEnv(withStatus(() => new Promise(() => {}))); // never resolves
  await settle();
  assert.equal(env.banner.textContent, "", "no premature banner write while the probe is pending");
  assert.equal(env.banner.dataset.net, undefined);
  assert.equal(env.sandbox.window.PolicyVaultNetworkBanner._serverNetwork(), null, "signing gate input stays unresolved (fails closed)");
});

test("failed probe -> NETWORK STATUS UNKNOWN (fail closed), serverNetwork stays null, retry scheduled", async () => {
  const env = makeEnv(withStatus(() => Promise.reject(new Error("origin 502"))));
  await settle();
  assert.equal(env.banner.textContent, UNKNOWN_TEXT);
  assert.equal(env.banner.dataset.net, "unknown");
  assert.equal(env.sandbox.window.PolicyVaultNetworkBanner._serverNetwork(), null);
  assert.ok(env.timers.some((t) => t.ms >= 15000), "a bounded retry is scheduled after a failure");
});

for (const [label, body] of [
  ["missing networkId", { isSynced: true, virtualDaaScore: "1" }],
  ["empty networkId", { networkId: "", isSynced: true, virtualDaaScore: "1" }],
  ["non-string networkId", { networkId: 42, isSynced: true, virtualDaaScore: "1" }]
]) {
  test(`malformed status (${label}) -> NETWORK STATUS UNKNOWN, never a guessed network`, async () => {
    const env = makeEnv(withStatus(() => jsonResponse(body)));
    await settle();
    assert.equal(env.banner.textContent, UNKNOWN_TEXT);
    assert.equal(env.banner.dataset.net, "unknown");
    assert.equal(env.sandbox.window.PolicyVaultNetworkBanner._serverNetwork(), null, "a malformed response must not satisfy the signing-path network gate");
  });
}

/* ---------------- retry / reconnect ---------------- */

test("recovery: failed probe shows UNKNOWN, the scheduled retry then resolves mainnet -> banner heals, no stale UNKNOWN", async () => {
  let calls = 0;
  const env = makeEnv(withStatus(() => (++calls === 1 ? Promise.reject(new Error("down")) : jsonResponse({ networkId: "mainnet", isSynced: true, virtualDaaScore: "77" }))));
  await settle();
  assert.equal(env.banner.textContent, UNKNOWN_TEXT);
  const retry = env.timers.shift();
  assert.ok(retry, "retry timer exists");
  retry.fn();
  await settle();
  assert.equal(env.banner.textContent, MAINNET_TEXT);
  assert.equal(env.sandbox.window.PolicyVaultNetworkBanner._serverNetwork(), "mainnet");
});

test("retries stop at the first successful resolution (no timer scheduled after success)", async () => {
  const env = makeEnv(withStatus(() => jsonResponse({ networkId: "mainnet", isSynced: true, virtualDaaScore: "5" })));
  await settle();
  assert.equal(env.timers.filter((t) => t.ms >= 15000).length, 0, "no network retry timers after a clean resolution");
});

test("retry backoff is bounded (15s -> 30s -> 60s cap)", async () => {
  const env = makeEnv(withStatus(() => Promise.reject(new Error("down"))));
  await settle();
  const delays = [];
  for (let i = 0; i < 5; i++) {
    const t = env.timers.shift();
    assert.ok(t, `retry ${i + 1} scheduled`);
    delays.push(t.ms);
    t.fn();
    await settle();
  }
  assert.deepEqual(delays, [15000, 30000, 60000, 60000, 60000]);
});

/* ---------------- stale/late response ordering ---------------- */

function deferredStatus() {
  const pending = [];
  const route = withStatus(() => new Promise((resolve, reject) => pending.push({ resolve, reject })));
  return { route, pending };
}

test("no stale TESTNET after mainnet resolution: a LATE testnet-10 response never overwrites a newer mainnet one", async () => {
  const d = deferredStatus();
  const env = makeEnv(d.route);
  await settle(); // boot probe #1 pending
  env.sandbox.window.PolicyVaultNetworkBanner.refresh(); // probe #2
  await settle();
  d.pending[1].resolve(jsonResponse({ networkId: "mainnet", isSynced: true, virtualDaaScore: "2" }));
  await settle();
  assert.equal(env.banner.textContent, MAINNET_TEXT);
  d.pending[0].resolve(jsonResponse({ networkId: "testnet-10", isSynced: true, virtualDaaScore: "1" })); // stale
  await settle();
  assert.equal(env.banner.textContent, MAINNET_TEXT, "stale testnet response must be discarded");
  assert.equal(env.sandbox.window.PolicyVaultNetworkBanner._serverNetwork(), "mainnet");
});

test("no stale MAINNET after testnet resolution: a LATE mainnet response never overwrites a newer testnet one", async () => {
  const d = deferredStatus();
  const env = makeEnv(d.route);
  await settle();
  env.sandbox.window.PolicyVaultNetworkBanner.refresh();
  await settle();
  d.pending[1].resolve(jsonResponse({ networkId: "testnet-10", isSynced: true, virtualDaaScore: "2" }));
  await settle();
  assert.equal(env.banner.textContent, TESTNET_TEXT);
  d.pending[0].resolve(jsonResponse({ networkId: "mainnet", isSynced: true, virtualDaaScore: "1" })); // stale
  await settle();
  assert.equal(env.banner.textContent, TESTNET_TEXT, "stale mainnet response must be discarded");
  assert.equal(env.sandbox.window.PolicyVaultNetworkBanner._serverNetwork(), "testnet-10");
});

test("a LATE FAILURE never clobbers a newer successful resolution (no UNKNOWN regression, no bogus retry loop)", async () => {
  const d = deferredStatus();
  const env = makeEnv(d.route);
  await settle();
  env.sandbox.window.PolicyVaultNetworkBanner.refresh();
  await settle();
  d.pending[1].resolve(jsonResponse({ networkId: "mainnet", isSynced: true, virtualDaaScore: "2" }));
  await settle();
  d.pending[0].reject(new Error("late failure of the superseded probe"));
  await settle();
  assert.equal(env.banner.textContent, MAINNET_TEXT, "a late failed request must not restore a non-mainnet banner");
  assert.equal(env.sandbox.window.PolicyVaultNetworkBanner._serverNetwork(), "mainnet");
  assert.equal(env.timers.filter((t) => t.ms >= 15000).length, 0, "the discarded stale failure schedules no retry");
});

/* ---------------- staging ownership ---------------- */

test("staging label owns the banner: network resolution (even mainnet) never overwrites NON-PRODUCTION", async () => {
  const route = (p) => {
    if (p.endsWith("/health")) return jsonResponse({ ok: true, staging: true, networkId: "testnet-10", authMode: "disabled" });
    if (p.endsWith("/network/status")) return jsonResponse({ networkId: "mainnet", isSynced: true, virtualDaaScore: "3" });
    return defaultRoute(p);
  };
  const env = makeEnv(route);
  await settle();
  assert.match(env.banner.textContent, /TESTNET-10 STAGING — NON-PRODUCTION/);
  assert.equal(env.banner.dataset.staging, "1");
  // and an explicit later refresh still cannot take the banner over
  env.sandbox.window.PolicyVaultNetworkBanner.refresh();
  await settle();
  assert.match(env.banner.textContent, /STAGING — NON-PRODUCTION/, "staging banner survives every network resolution");
});

/* ---------------- protected signing gate unchanged ---------------- */

test("the signing-path network gate is byte-identical (banner rework is presentation-only)", () => {
  assert.ok(
    APP_JS.includes('if (ui.network !== ui.serverNetwork || (ui.serverNetwork !== "testnet-10" && ui.serverNetwork !== "mainnet")) {'),
    "verifyNetwork()'s fail-closed comparison must remain untouched"
  );
  assert.ok(
    APP_JS.includes('setWalletState(WalletState.WRONG_NETWORK, `wallet on ${ui.network ?? "unknown"}, required ${ui.serverNetwork}`);'),
    "verifyNetwork()'s fail-closed outcome must remain untouched"
  );
});

test("the banner derives ONLY from /network/status — never hostname, location, or a build constant", () => {
  const bannerSection = APP_JS.slice(APP_JS.indexOf("function applyNetworkBanner"), APP_JS.indexOf("async function boot"));
  assert.ok(!/location|hostname|BUILD/i.test(bannerSection), "no non-authoritative network identity source in the banner path");
  assert.ok(/getJSON\("\/network\/status"\)/.test(bannerSection), "the banner path reads the authoritative network-status surface");
});
