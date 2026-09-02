"use strict";

/*
 * BROWSER regressions — UX responsiveness / signed-out UX successor
 * (owner directive 2026-08-29). Drives the REAL production web/app.js and
 * web/app-v4.js in the vm harness (same style as app-v4-gate.test.js /
 * network-banner.test.js) and proves the directive's regression matrix:
 *
 * SIGNED-OUT UX
 *  - fresh signed-out hosted load: NO Organizations auth toast, NO
 *    privileged reads at all (organizations/vaults are simply not
 *    requested while signed out on a hosted server);
 *  - explicit signed-out navigation: quiet inline sign-in states
 *    ("Sign in to use Organizations." / vaults / activity);
 *  - self-hosted (authMode disabled): unchanged open behavior;
 *  - AUTHENTICATED failures still surface; unrelated errors (e.g. the
 *    network banner's fail-closed UNKNOWN) are never suppressed.
 *
 * IDENTITY / NAVIGATION
 *  - retained view data renders IMMEDIATELY on tab return, marked
 *    "Refreshing…", while an authoritative background refresh runs;
 *  - wallet switch / network switch / auth transition each discard
 *    retained state (old identity's data never paints for the new one);
 *  - a response that started under an older identity is DISCARDED when
 *    it resolves after a switch (stale-response protection);
 *  - concurrent identical GETs share ONE request (dedupe), and the
 *    banner's network probe is explicitly EXEMPT from that sharing.
 *
 * SIGNING
 *  - hanging unrelated reads (organizations / audit / suspensions) can
 *    NOT delay the wallet invocation once the transaction is ready;
 *  - wallet rejection produces no success state;
 *  - the pre-sign gate order itself is separately pinned by
 *    app-v4-gate.test.js (unchanged by this pass).
 *
 * POST-SIGN — PENDING IS NOT SUCCESS
 *  - "Waiting for KasWare…" / "signed — submitting…" intermediate states
 *    appear immediately and truthfully;
 *  - a non-CHAIN_VERIFIED outcome NEVER renders as success; only the
 *    server's authoritative CHAIN_VERIFIED does.
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const WEB_DIR = path.join(__dirname, "..");
const APP_JS = fs.readFileSync(path.join(WEB_DIR, "app.js"), "utf8");
const APP_V4 = fs.readFileSync(path.join(WEB_DIR, "app-v4.js"), "utf8");

/* ---------------- shared harness ---------------- */

function jsonResponse(body, ok = true, status) {
  return { ok, status: status || (ok ? 200 : 401), json: async () => body };
}
const AUTH_REFUSAL = jsonResponse({ error: { code: "SESSION_INVALID", message: "sign in to use this route" } }, false, 401);

function makeSandbox(route, extraGlobals = {}) {
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
  const calls = [];
  const sandbox = {
    console,
    document: { getElementById: element, querySelectorAll: () => [], addEventListener() {} },
    localStorage: { getItem: () => null, setItem() {}, removeItem() {} },
    setTimeout: () => 0,
    clearTimeout() {},
    fetch: (u) => {
      const p = String(u).replace("/api/v1", "");
      calls.push(p);
      return Promise.resolve().then(() => route(p));
    },
    crypto: { getRandomValues: (a) => a.fill(7) },
    PolicyVaultWallet: require("../wallet.js"),
    PolicyVaultIdentity: {},
    ...extraGlobals
  };
  sandbox.listeners = {};
  sandbox.addEventListener = (n, f) => { (sandbox.listeners[n] = sandbox.listeners[n] || []).push(f); };
  sandbox.window = sandbox;
  sandbox.globalThis = sandbox;
  vm.createContext(sandbox);
  return { sandbox, element, calls };
}

const settle = async (n = 30) => { for (let i = 0; i < n; i++) await new Promise((r) => setImmediate(r)); };

/* routes for a HOSTED server (authMode enabled) with no session */
function hostedSignedOutRoute(p) {
  if (p.endsWith("/health")) return jsonResponse({ ok: true, networkId: "mainnet", authMode: "enabled" });
  if (p.endsWith("/network/status")) return jsonResponse({ networkId: "mainnet", isSynced: true, virtualDaaScore: "5" });
  if (p.endsWith("/auth/session")) return jsonResponse({ authenticated: false, reason: "SESSION_INVALID" });
  if (p.endsWith("/wallet/dev-accounts")) return jsonResponse({}, false, 404);
  if (p.endsWith("/organizations") || p.endsWith("/vaults") || p.includes("/audit") || p.includes("/wallet/")) return AUTH_REFUSAL;
  return jsonResponse({ error: { code: "NOT_FOUND", message: `nf ${p}` } }, false, 404);
}

/* ---------------- SIGNED-OUT UX (app.js) ---------------- */

test("fresh signed-out hosted load: NO Organizations toast, NO privileged reads, quiet vaults hint", async () => {
  const env = makeSandbox(hostedSignedOutRoute);
  vm.runInContext(APP_JS, env.sandbox, { filename: "app.js" });
  await settle();
  assert.ok(!/Organizations unavailable/.test(env.element("notice").textContent), "no auth toast on a normal signed-out visit");
  assert.ok(!env.calls.includes("/organizations"), "organizations is not requested while signed out");
  assert.ok(!env.calls.includes("/vaults"), "vaults is not requested while signed out");
  assert.match(env.element("vaults").innerHTML, /Sign in to view your vaults\./);
});

test("self-hosted (authMode disabled): open reads unchanged — organizations and vaults ARE fetched", async () => {
  const route = (p) => {
    if (p.endsWith("/health")) return jsonResponse({ ok: true, networkId: "mainnet", authMode: "disabled" });
    if (p.endsWith("/network/status")) return jsonResponse({ networkId: "mainnet", isSynced: true, virtualDaaScore: "5" });
    if (p.endsWith("/organizations")) return jsonResponse({ organizations: [], roleLabels: [], assignments: {}, assignmentsVersion: 0 });
    if (p.endsWith("/vaults")) return jsonResponse({ vaults: [] });
    if (p.endsWith("/wallet/dev-accounts")) return jsonResponse({}, false, 404);
    return jsonResponse({ error: { code: "NOT_FOUND", message: "nf" } }, false, 404);
  };
  const env = makeSandbox(route);
  vm.runInContext(APP_JS, env.sandbox, { filename: "app.js" });
  await settle();
  assert.ok(env.calls.includes("/organizations"), "self-hosted orgs read unchanged");
  assert.ok(env.calls.includes("/vaults"), "self-hosted vaults read unchanged");
  assert.ok(!/Organizations unavailable/.test(env.element("notice").textContent));
});

test("prefetch after authentication: session restore fetches organizations + vaults exactly once each (dedupe collapses duplicates)", async () => {
  const route = (p) => {
    if (p.endsWith("/health")) return jsonResponse({ ok: true, networkId: "mainnet", authMode: "enabled" });
    if (p.endsWith("/network/status")) return jsonResponse({ networkId: "mainnet", isSynced: true, virtualDaaScore: "5" });
    if (p.endsWith("/auth/session")) return jsonResponse({ authenticated: true, walletAddress: "kaspa:qbound", networkId: "mainnet" });
    if (p.endsWith("/organizations")) return jsonResponse({ organizations: [], roleLabels: [], assignments: {}, assignmentsVersion: 0 });
    if (p.endsWith("/vaults")) return jsonResponse({ vaults: [] });
    if (p.endsWith("/wallet/dev-accounts")) return jsonResponse({}, false, 404);
    return jsonResponse({ error: { code: "NOT_FOUND", message: "nf" } }, false, 404);
  };
  const env = makeSandbox(route);
  vm.runInContext(APP_JS, env.sandbox, { filename: "app.js" });
  await settle();
  assert.equal(env.calls.filter((p) => p === "/organizations").length, 1, "exactly one organizations read");
  assert.equal(env.calls.filter((p) => p === "/vaults").length, 1, "exactly one vaults read");
  assert.equal(env.calls.filter((p) => p === "/health").length, 1, "exactly one health read at startup (was three)");
  assert.ok(!/Organizations unavailable/.test(env.element("notice").textContent));
});

test("AUTHENTICATED organizations failure still surfaces as a visible toast", async () => {
  const route = (p) => {
    if (p.endsWith("/health")) return jsonResponse({ ok: true, networkId: "mainnet", authMode: "enabled" });
    if (p.endsWith("/network/status")) return jsonResponse({ networkId: "mainnet", isSynced: true, virtualDaaScore: "5" });
    if (p.endsWith("/auth/session")) return jsonResponse({ authenticated: true, walletAddress: "kaspa:qbound", networkId: "mainnet" });
    if (p.endsWith("/organizations")) return jsonResponse({ error: { code: "STORE_ERROR", message: "metadata store unavailable" } }, false, 500);
    if (p.endsWith("/vaults")) return jsonResponse({ vaults: [] });
    if (p.endsWith("/wallet/dev-accounts")) return jsonResponse({}, false, 404);
    return jsonResponse({ error: { code: "NOT_FOUND", message: "nf" } }, false, 404);
  };
  const env = makeSandbox(route);
  vm.runInContext(APP_JS, env.sandbox, { filename: "app.js" });
  await settle();
  assert.match(env.element("notice").textContent, /Organizations unavailable: metadata store unavailable/, "authenticated failures are never suppressed");
});

test("unrelated failures are never suppressed: network probe failure still renders the fail-closed UNKNOWN banner while signed out", async () => {
  const route = (p) => {
    if (p.endsWith("/network/status")) return Promise.reject(new Error("origin down"));
    return hostedSignedOutRoute(p);
  };
  const env = makeSandbox(route);
  vm.runInContext(APP_JS, env.sandbox, { filename: "app.js" });
  await settle();
  assert.match(env.element("testnet-banner").textContent, /NETWORK STATUS UNKNOWN/, "fail-closed banner unaffected by signed-out quieting");
});

/* ---------------- v0.4.1 retained-state navigation ---------------- */

const VAULT = {
  vaultId: "ab".repeat(32), contractVersion: "policyvault-0.4.1", status: "ACTIVE",
  owner: "cd".repeat(32), agents: [], approverSlots: [], label: "Ops Treasury",
  live: { protectedValueKas: "10", feeReserveKas: "1", outpoint: { transactionId: "ee".repeat(32), index: 0 } }
};
function signedInRoute(overrides = {}) {
  return (p) => {
    if (overrides[p]) return overrides[p]();
    if (p.endsWith("/health")) return jsonResponse({ ok: true, networkId: "mainnet", authMode: "enabled" });
    if (p.endsWith("/vaults")) return jsonResponse({ vaults: [VAULT] });
    if (p.endsWith("/organizations")) return jsonResponse({ organizations: [], roleLabels: [], assignments: {}, assignmentsVersion: 0 });
    if (p.includes("/wallet/v4/requests?open=1")) return jsonResponse({ requests: [] });
    if (p.includes("/agent-suspensions")) return jsonResponse({ suspensions: { schema: "s1", allAgents: false, agents: [], version: 3 } });
    if (p.includes("/audit")) return jsonResponse({ events: [] });
    return jsonResponse({ error: { code: "NOT_FOUND", message: `nf ${p}` } }, false, 404);
  };
}
const READY_SNAP = Object.freeze({ connected: true, ready: true, address: "kaspa:quser", xonly: "cd".repeat(32), network: "mainnet", serverNetwork: "mainnet", provider: "kasware", adapter: null, auth: "AUTHENTICATED" });
function makeV4(route) {
  // The REAL canonical-session contract: app-v4 subscribes at
  // DOMContentLoaded; identity events reach it exactly as in production —
  // through the subscriber callback (updateWallet), never by poking state.
  const holder = { snap: { connected: false, ready: false, address: null, xonly: null, network: null, serverNetwork: null, provider: null, adapter: null, auth: "AUTHENTICATED" }, subscriber: null };
  const env = makeSandbox(route, {
    PolicyVaultWalletSession: {
      active: () => holder.snap,
      subscribe: (cb) => { holder.subscriber = cb; cb(holder.snap); return () => {}; }
    }
  });
  vm.runInContext(APP_V4, env.sandbox, { filename: "app-v4.js" });
  (env.sandbox.listeners["DOMContentLoaded"] || []).forEach((f) => f());
  const V4 = env.sandbox.window.PolicyVaultV4;
  const setSnap = (snap) => { holder.snap = snap; return holder.subscriber(snap); };
  return { env, V4, root: env.element("v4-root"), setSnap };
}

test("cold vaults view shows Loading immediately; tab return paints RETAINED data instantly with a Refreshing marker", async () => {
  let release;
  const gate = new Promise((r) => { release = r; });
  const route = (p) => (p.endsWith("/vaults") ? gate.then(() => jsonResponse({ vaults: [VAULT] })) : signedInRoute()(p));
  const { V4, root, setSnap } = makeV4(route);
  const p0 = setSnap(READY_SNAP); // real session event → render
  await settle(3);
  assert.match(root.innerHTML, /Loading vaults…/, "immediate feedback on a cold view — never a silently idle old view");
  release();
  await p0; await settle();
  assert.match(root.innerHTML, /Ops Treasury/, "fresh content painted");
  assert.ok(!/Refreshing…/.test(root.innerHTML), "no refresh marker after a fresh paint");
  // tab away and back: retained data paints synchronously
  V4._state.view = "activity"; await V4.render(); await settle();
  V4._state.view = "vaults";
  const p2 = V4.render();
  assert.match(root.innerHTML, /Ops Treasury/, "retained vaults painted IMMEDIATELY on tab return");
  assert.match(root.innerHTML, /Refreshing…/, "retained paint is truthfully marked as refreshing");
  await p2; await settle();
  assert.match(root.innerHTML, /Ops Treasury/);
  assert.ok(!/Refreshing…/.test(root.innerHTML), "marker cleared once the authoritative refresh landed");
});

test("independent vaults-view reads are PARALLEL (fired in the same turn), suspensions follow", async () => {
  const { env, V4, setSnap } = makeV4(signedInRoute());
  await setSnap(READY_SNAP); await settle();
  const first = env.calls.indexOf("/vaults");
  const batch = env.calls.slice(first, first + 3);
  assert.deepEqual(new Set(batch), new Set(["/vaults", "/organizations", "/wallet/v4/requests?open=1"]), "primary reads fired together, not serially");
  assert.ok(env.calls.some((c) => c.includes("/agent-suspensions")), "suspension stage still runs (fail-closed rendering preserved)");
});

test("wallet switch discards retained state: the old wallet's data never paints for the new identity", async () => {
  const { V4, root, setSnap } = makeV4(signedInRoute());
  await setSnap(READY_SNAP); await settle();
  assert.match(root.innerHTML, /Ops Treasury/);
  // the canonical session reports a NEW wallet (real subscriber path)
  await setSnap({ ...READY_SNAP, address: "kaspa:qother", xonly: "ef".repeat(32) });
  const p = V4.render();
  assert.match(root.innerHTML, /Loading vaults…/, "no retained paint across a wallet switch");
  await p; await settle();
});

test("network switch discards retained state", async () => {
  const { V4, root, setSnap } = makeV4(signedInRoute());
  await setSnap(READY_SNAP); await settle();
  assert.match(root.innerHTML, /Ops Treasury/);
  await setSnap({ ...READY_SNAP, network: "testnet-10", ready: false });
  await setSnap(READY_SNAP); // back on the right network — cache must be gone
  const p = V4.render();
  assert.match(root.innerHTML, /Loading vaults…/, "cache was invalidated by the network change");
  await p; await settle();
});

test("auth transition (sign-out) discards retained privileged state and renders the quiet sign-in state", async () => {
  let signedOut = false;
  const route = (p) => {
    if (signedOut && (p.endsWith("/vaults") || p.endsWith("/organizations") || p.includes("/wallet/") || p.includes("/audit"))) return AUTH_REFUSAL;
    return signedInRoute()(p);
  };
  const { root, setSnap } = makeV4(route);
  await setSnap(READY_SNAP); await settle();
  assert.match(root.innerHTML, /Ops Treasury/);
  signedOut = true;
  await setSnap({ ...READY_SNAP, auth: "SIGNED_OUT" });
  await settle();
  assert.ok(!/Ops Treasury/.test(root.innerHTML), "privileged retained data removed on sign-out");
  assert.match(root.innerHTML, /Sign in to view your vaults\./, "quiet signed-out state, not an error dump");
});

test("stale-response protection: a fetch started under the OLD identity is discarded after a wallet switch", async () => {
  let release;
  const gate = new Promise((r) => { release = r; });
  let gated = true;
  const route = (p) => {
    if (p.endsWith("/vaults") && gated) return gate.then(() => jsonResponse({ vaults: [VAULT] }));
    if (p.endsWith("/vaults")) return jsonResponse({ vaults: [] });
    return signedInRoute()(p);
  };
  const { V4, root, setSnap } = makeV4(route);
  const p1 = setSnap(READY_SNAP); // old identity's fetch now pending
  await settle(3);
  gated = false; // the NEW identity's own refresh resolves immediately
  const p2 = setSnap({ ...READY_SNAP, address: "kaspa:qother", xonly: "ef".repeat(32) });
  await settle(3);
  release(); // OLD identity's response lands only now
  await p1; await p2; await settle();
  assert.ok(!/Ops Treasury/.test(root.innerHTML), "old identity's data never painted for the new identity");
  for (const k of Object.keys(V4._state.cache)) {
    assert.ok(!/Ops Treasury/.test(JSON.stringify(V4._state.cache[k] || {})), "old identity's response never cached under the new epoch");
  }
});

test("concurrent identical GETs share ONE request (in-flight dedupe)", async () => {
  const { env, V4, setSnap } = makeV4(signedInRoute());
  await setSnap(READY_SNAP); await settle(); // first render fully settled
  env.calls.length = 0;
  V4._state.cache = {}; // force both renders to fetch
  const a = V4.render();
  const b = V4.render();
  await a; await b; await settle();
  assert.equal(env.calls.filter((c) => c === "/vaults").length, 1, "two overlapping renders share one /vaults read");
});

test("signed-out Organizations tab: quiet 'Sign in to use Organizations.' — never an error toastline", async () => {
  const route = (p) => {
    if (p.endsWith("/organizations") || p.endsWith("/vaults")) return AUTH_REFUSAL;
    return signedInRoute()(p);
  };
  const { V4, root, setSnap } = makeV4(route);
  await setSnap({ ...READY_SNAP, auth: "SIGNED_OUT" });
  V4._state.view = "orgs";
  await V4.render(); await settle();
  assert.match(root.innerHTML, /Sign in to use Organizations\./);
});

test("AUTHENTICATED v4 vaults failure still renders the real error (never silently quieted)", async () => {
  const route = (p) => {
    if (p.endsWith("/vaults")) return jsonResponse({ error: { code: "STORE_ERROR", message: "database unreachable" } }, false, 503);
    return signedInRoute()(p);
  };
  const { root, setSnap } = makeV4(route);
  await setSnap(READY_SNAP); await settle();
  assert.match(root.innerHTML, /Could not load vaults: database unreachable/);
});

/* ---------------- signing independence + truthful progress ---------------- */

function makeSigningEnv({ hangUnrelated = false, rejectWallet = false, submitState = "CHAIN_VERIFIED" } = {}) {
  const never = new Promise(() => {});
  const notes = [];
  const route = (p) => {
    if (hangUnrelated && (p.endsWith("/organizations") || p.includes("/audit") || p.includes("/agent-suspensions"))) return never;
    if (p.endsWith("/vaults")) return jsonResponse({ vaults: [VAULT] });
    if (p.includes("/wallet/v4/requests?open=1")) return jsonResponse({ requests: [] });
    return jsonResponse({ error: { code: "NOT_FOUND", message: `nf ${p}` } }, false, 404);
  };
  const signCalls = [];
  const adapter = {
    signInputs: async (unsigned, list) => {
      signCalls.push({ unsigned, list });
      if (rejectWallet) throw Object.assign(new Error("user rejected"), { walletCategory: "USER_REJECTED", code: "USER_REJECTED" });
      return "signed-safe-json";
    }
  };
  const env = makeSandbox((p) => {
    if (p === "/wallet/v4/requests" ) return null; // POSTs go through postJSON → fetch; handled below
    return route(p);
  }, {
    PolicyVaultWalletSession: {
      active: () => ({ connected: true, ready: true, address: "kaspa:quser", xonly: "cd".repeat(32), network: "mainnet", serverNetwork: "mainnet", provider: "kasware", adapter, auth: "AUTHENTICATED" }),
      subscribe: () => () => {}
    }
  });
  // full fetch override including POST bodies:
  env.sandbox.fetch = (u, opts) => {
    const p = String(u).replace("/api/v1", "");
    env.calls.push(p);
    if (hangUnrelated && (p.endsWith("/organizations") || p.includes("/audit") || p.includes("/agent-suspensions"))) return never;
    if (p === "/wallet/v4/requests" && opts && opts.method === "POST") {
      return Promise.resolve(jsonResponse({ request: {
        requestId: "req-1", state: "BUILT", vaultId: VAULT.vaultId, signerAddress: "kaspa:quser",
        review: { paymentKas: "1" },
        transaction: { unsignedSafeJson: "UNSIGNED", signInputs: [{ index: 0, sighashType: 1 }], covenantInputIndex: 0 }
      } }));
    }
    if (p.includes("/signature")) return Promise.resolve(jsonResponse({ request: { state: "PREFLIGHT_VERIFIED" } }));
    if (p.includes("/submit")) return Promise.resolve(jsonResponse({ request: { state: submitState }, txId: "ff".repeat(32) }));
    return Promise.resolve(route(p));
  };
  // Record EVERY note() write so intermediate progress states are
  // observable even when the whole flow settles within microtasks.
  const notice = env.element("v4-notice");
  const noteWrites = [];
  Object.defineProperty(notice, "textContent", {
    get() { return this._t || ""; },
    set(v) { this._t = String(v); noteWrites.push(String(v)); }
  });
  vm.runInContext(APP_V4, env.sandbox, { filename: "app-v4.js" });
  const V4 = env.sandbox.window.PolicyVaultV4;
  Object.assign(V4._state, { address: "kaspa:quser", xonly: "cd".repeat(32), network: "mainnet", ready: true, auth: "AUTHENTICATED" });
  V4._state.vaultsById = { [VAULT.vaultId]: VAULT };
  return { env, V4, signCalls, notice, noteWrites };
}

test("KasWare cannot be delayed by unrelated reads: signing completes while organizations/audit/suspensions HANG forever", async () => {
  const { env, V4, signCalls, notice } = makeSigningEnv({ hangUnrelated: true });
  await V4._runFlow(VAULT.vaultId, "agentSpend", { agentPk: "aa".repeat(32), recipient: "bb".repeat(32), payAmountSompi: "100" }, "Sign spend");
  await settle();
  // the review modal is open; confirm it (the modal's confirm handler)
  const confirm = env.element("v4-confirm");
  assert.equal(typeof confirm.onclick, "function", "review modal offered the signing action");
  await confirm.onclick();
  await settle();
  assert.equal(signCalls.length, 1, "the wallet was invoked exactly once, with unrelated endpoints still hanging");
  assert.equal(signCalls[0].unsigned, "UNSIGNED", "the exact frozen payload reached the wallet");
  assert.match(notice.textContent, /CHAIN_VERIFIED/, "flow completed to the authoritative outcome");
});

test("truthful progress: Waiting-for-KasWare and signed-submitting states appear; CHAIN_VERIFIED renders as good", async () => {
  const { env, V4, notice, noteWrites } = makeSigningEnv({});
  await V4._runFlow(VAULT.vaultId, "agentSpend", { agentPk: "aa".repeat(32), recipient: "bb".repeat(32), payAmountSompi: "100" }, "Sign spend");
  await settle();
  await env.element("v4-confirm").onclick();
  await settle();
  assert.ok(noteWrites.some((s) => /Preparing transaction…/.test(s)), `immediate feedback on action start (saw: ${JSON.stringify(noteWrites)})`);
  assert.ok(noteWrites.some((s) => /Waiting for KasWare/.test(s)), "pre-popup state shown");
  assert.ok(noteWrites.some((s) => /signed — submitting/.test(s)), "post-signature intermediate state shown");
  assert.match(notice.textContent, /CHAIN_VERIFIED/);
  assert.equal(notice.className.includes("good"), true, "authoritative success only");
});

test("PENDING IS NOT SUCCESS: a non-CHAIN_VERIFIED submit outcome never renders as success", async () => {
  const { env, V4, notice } = makeSigningEnv({ submitState: "SUBMITTED" });
  await V4._runFlow(VAULT.vaultId, "agentSpend", { agentPk: "aa".repeat(32), recipient: "bb".repeat(32), payAmountSompi: "100" }, "Sign spend");
  await settle();
  await env.element("v4-confirm").onclick();
  await settle();
  assert.match(notice.textContent, /SUBMITTED/, "the truthful intermediate state is shown");
  assert.ok(!notice.className.includes("good"), "never rendered as success without chain proof");
});

test("wallet rejection: no success state, no signed submission", async () => {
  const { env, V4, notice, signCalls } = makeSigningEnv({ rejectWallet: true });
  await V4._runFlow(VAULT.vaultId, "agentSpend", { agentPk: "aa".repeat(32), recipient: "bb".repeat(32), payAmountSompi: "100" }, "Sign spend");
  await settle();
  await env.element("v4-confirm").onclick();
  await settle();
  assert.equal(signCalls.length, 1, "wallet was asked once");
  assert.ok(!env.calls.some((c) => c.includes("/signature")), "no signature was submitted after rejection");
  assert.ok(!notice.className.includes("good"), "no success state after rejection");
  assert.match(notice.textContent, /failed|rejected|USER_REJECTED/i);
});

/* ---------------- PRODUCTION CONSOLE CORRECTIVES (owner-live findings, 2026-09-02) ---------------- */

test("dev signer: the console NEVER probes /wallet/dev-accounts; the mock connect button appears ONLY when /health advertises devSigner:true", async () => {
  // production-shaped server (mainnet, no dev signer advertised)
  const prod = makeSandbox(hostedSignedOutRoute);
  vm.runInContext(APP_JS, prod.sandbox, { filename: "app.js" });
  await settle();
  assert.ok(!prod.calls.some((c) => c.includes("/wallet/dev-accounts")), "zero /wallet/dev-accounts requests against a production server");
  assert.equal(prod.element("btn-connect-mock").style.display, undefined, "mock connect never shown");
  assert.ok(!APP_JS.includes('"/wallet/dev-accounts"'), "the console carries no dev-accounts probe at all");
  // an explicitly configured development server (testnet + POLICYVAULT_DEV_SIGNER=1) advertises it on /health
  const dev = makeSandbox((p) => (p.endsWith("/health") ? jsonResponse({ ok: true, networkId: "testnet-10", authMode: "disabled", devSigner: true }) : hostedSignedOutRoute(p)));
  vm.runInContext(APP_JS, dev.sandbox, { filename: "app.js" });
  await settle();
  assert.equal(dev.element("btn-connect-mock").style.display, "", "mock connect offered when — and only when — the server advertises its dev signer");
  assert.ok(!dev.calls.some((c) => c.includes("/wallet/dev-accounts")), "still no probe: the advertisement is the only trigger");
});

test("WALLET CONNECTED ≠ SESSION AUTHENTICATED: a connected, ready wallet with a SIGNED_OUT hosted session issues ZERO privileged reads and paints the quiet sign-in state — on every view and on repeated wallet events", async () => {
  const { env, V4, root, setSnap } = makeV4(hostedSignedOutRoute);
  const privileged = () => env.calls.filter((c) => c.endsWith("/vaults") || c.endsWith("/organizations") || c.includes("/wallet/v4/requests") || c.includes("/governance/proposals") || c.includes("/audit"));
  await setSnap({ ...READY_SNAP, auth: "SIGNED_OUT" });
  await settle();
  assert.match(root.innerHTML, /Sign in to view your vaults\./, "quiet sign-in state, not a 401 dump");
  assert.deepEqual(privileged(), [], "no privileged read while signed out");
  for (const [view, hint] of [["orgs", /Sign in to use Organizations\./], ["activity", /Sign in to view activity\./], ["vaults", /Sign in to view your vaults\./]]) {
    V4._state.view = view;
    await V4.render();
    await settle();
    assert.match(root.innerHTML, hint, `quiet state on the ${view} view`);
  }
  // repeated wallet events while signed out (reconnects, account/network echoes): still nothing
  for (let i = 0; i < 5; i++) { await setSnap({ ...READY_SNAP, auth: "SIGNED_OUT", xonly: null }); await setSnap({ ...READY_SNAP, auth: "SIGNED_OUT" }); }
  await settle();
  assert.deepEqual(privileged(), [], "wallet churn while signed out never turns into a 401 loop");
});

test("session lifecycle: sign-in triggers the reads once; SESSION_INVALID clears retained state and stops all privileged reads; a 401 on a read IS still honoured as a refusal", async () => {
  let signedOut = true;
  const route = (p) => {
    if (signedOut && (p.endsWith("/vaults") || p.endsWith("/organizations") || p.includes("/wallet/") || p.includes("/audit"))) return AUTH_REFUSAL;
    return signedInRoute()(p);
  };
  const { env, V4, root, setSnap } = makeV4(route);
  const privileged = () => env.calls.filter((c) => c.endsWith("/vaults") || c.endsWith("/organizations") || c.includes("/wallet/v4/requests") || c.includes("/audit"));
  V4._state.view = "vaults";
  await setSnap({ ...READY_SNAP, auth: "SIGNED_OUT" }); await settle();
  assert.deepEqual(privileged(), []);
  // login
  signedOut = false;
  await setSnap(READY_SNAP); await settle();
  assert.match(root.innerHTML, /Ops Treasury/, "authenticated data loads after sign-in");
  const afterLogin = privileged().length;
  assert.ok(afterLogin >= 3, "the required loads occurred exactly once per view render");
  // server invalidates the session out of band: the next read is refused, honoured as a refusal (no retry loop)
  signedOut = true;
  await V4.render(); await settle();
  assert.equal(privileged().length, afterLogin + 3, "exactly one batch of attempts, no retry");
  assert.match(root.innerHTML, /Sign in to view your vaults\./, "a 401 remains a genuine refusal, rendered quietly");
  assert.ok(!/Ops Treasury/.test(root.innerHTML), "stale privileged data never stands after a refusal");
  // the canonical session reports SIGNED_OUT: no further attempts on any later event
  await setSnap({ ...READY_SNAP, auth: "SIGNED_OUT" }); await settle();
  const settled = privileged().length;
  for (let i = 0; i < 4; i++) { await V4.render(); await setSnap({ ...READY_SNAP, auth: "SIGNED_OUT", xonly: i % 2 ? null : READY_SNAP.xonly }); }
  await settle();
  assert.equal(privileged().length, settled, "signed out: zero authenticated polling");
});

test("self-hosted (auth DISABLED) app-v4 reads are unchanged by the signed-out gate", async () => {
  const { env, root, setSnap } = makeV4(signedInRoute());
  await setSnap({ ...READY_SNAP, auth: "DISABLED" }); await settle();
  assert.match(root.innerHTML, /Ops Treasury/);
  assert.ok(env.calls.includes("/vaults"));
});
