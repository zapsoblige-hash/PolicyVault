"use strict";

/*
 * PolicyVault mobile — NATIVE HTTP TRANSPORT ADAPTER unit + adversarial
 * tests (NATIVE MOBILE TRANSPORT directive Phase B/G). Drives the real
 * adapter (mobile/www/js/platform/native-http.js) against a fake
 * CapacitorHttp plugin, proving the fetch-shaped contract and the bearer/
 * transport security invariants WITHOUT a device. Device-level proof
 * (real CapacitorHttp against a real server) is the emulator Phase F/K
 * work; this file locks the deterministic behavior.
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");

const NH = require("../www/js/platform/native-http.js");

/* A fake CapacitorHttp that records the exact options it was called with
 * and returns a scripted response (or rejects to model a transport
 * failure). */
function fakePlugin(script) {
  const calls = [];
  return {
    calls,
    request(opts) {
      calls.push(opts);
      if (typeof script === "function") return script(opts);
      if (script && script.reject) return Promise.reject(script.reject);
      return Promise.resolve(script);
    }
  };
}

const okJson = { status: 200, url: "https://app.example.org/api/v1/health", headers: { "Content-Type": "application/json" }, data: { ok: true, networkId: "mainnet" } };

test("createNativeFetch requires a real plugin", () => {
  assert.throws(() => NH.createNativeFetch({}), /requires a CapacitorHttp plugin/);
});

test("nativeHttp() returns null off-native (no Capacitor)", () => {
  assert.equal(NH.nativeHttp({}), null);
  assert.equal(NH.nativeHttp({ Capacitor: { getPlatform: () => "web", Plugins: { CapacitorHttp: { request() {} } } } }), null);
});

test("nativeHttp() returns the plugin on android when present", () => {
  const plugin = { request() {} };
  const got = NH.nativeHttp({ Capacitor: { getPlatform: () => "android", Plugins: { CapacitorHttp: plugin } } });
  assert.equal(got, plugin);
});

test("GET: maps status/ok and re-serializes a parsed JSON body to text()", async () => {
  const plugin = fakePlugin(okJson);
  const f = NH.createNativeFetch({ capacitorHttp: plugin });
  const res = await f("https://app.example.org/api/v1/health", { method: "GET" });
  assert.equal(res.ok, true);
  assert.equal(res.status, 200);
  const text = await res.text();
  assert.equal(text, JSON.stringify({ ok: true, networkId: "mainnet" }));
  assert.deepEqual(JSON.parse(text), { ok: true, networkId: "mainnet" });
});

test("every request disables redirects and sets timeouts", async () => {
  const plugin = fakePlugin(okJson);
  const f = NH.createNativeFetch({ capacitorHttp: plugin });
  await f("https://app.example.org/api/v1/health", { method: "GET" });
  const call = plugin.calls[0];
  assert.equal(call.disableRedirects, true);
  assert.ok(call.connectTimeout > 0 && call.readTimeout > 0);
});

test("HTTPS ONLY: a non-https URL is refused before any request is made", async () => {
  const plugin = fakePlugin(okJson);
  const f = NH.createNativeFetch({ capacitorHttp: plugin });
  await assert.rejects(() => f("http://app.example.org/api/v1/health", { method: "GET" }), /non-HTTPS/);
  assert.equal(plugin.calls.length, 0, "no request may be issued for a cleartext URL");
});

test("bearer travels ONLY in the Authorization header, never the URL", async () => {
  const plugin = fakePlugin(okJson);
  const f = NH.createNativeFetch({ capacitorHttp: plugin });
  await f("https://app.example.org/api/v1/vaults", { method: "GET", headers: { Authorization: "Bearer " + "a".repeat(64) } });
  const call = plugin.calls[0];
  assert.equal(call.headers.Authorization, "Bearer " + "a".repeat(64));
  assert.ok(!/[?&]/.test(call.url), "URL must carry no query string");
  assert.ok(!call.url.includes("a".repeat(64)), "the token must never appear in the URL");
});

test("the body is passed through VERBATIM as data (no double-encoding)", async () => {
  const plugin = fakePlugin({ status: 201, url: "https://app.example.org/api/v1/x", headers: {}, data: { created: true } });
  const f = NH.createNativeFetch({ capacitorHttp: plugin });
  const payload = JSON.stringify({ vaultId: "7a".repeat(32), amountSompi: "100000000" });
  await f("https://app.example.org/api/v1/x", { method: "POST", headers: { "Content-Type": "application/json" }, body: payload });
  assert.equal(plugin.calls[0].data, payload, "the exact serialized bytes must reach the wire unchanged");
});

test("a redirected-host response is refused (never expose a body from another host)", async () => {
  const plugin = fakePlugin({ status: 200, url: "https://evil.example/stolen", headers: {}, data: { x: 1 } });
  const f = NH.createNativeFetch({ capacitorHttp: plugin });
  await assert.rejects(() => f("https://app.example.org/api/v1/health", { method: "GET" }), /response host .* != requested host/);
});

test("a 4xx/5xx RESOLVES with the status (an HTTP error is not a transport failure)", async () => {
  for (const status of [401, 403, 409, 429, 500, 503]) {
    const plugin = fakePlugin({ status, url: "https://app.example.org/api/v1/x", headers: { "Retry-After": "5" }, data: { error: { code: "X" } } });
    const f = NH.createNativeFetch({ capacitorHttp: plugin });
    const res = await f("https://app.example.org/api/v1/x", { method: "POST", body: "{}" });
    assert.equal(res.ok, false);
    assert.equal(res.status, status);
    const text = await res.text();
    assert.equal(JSON.parse(text).error.code, "X");
  }
});

test("Retry-After is readable via case-insensitive headers.get()", async () => {
  const plugin = fakePlugin({ status: 429, url: "https://app.example.org/api/v1/x", headers: { "retry-after": "7" }, data: {} });
  const f = NH.createNativeFetch({ capacitorHttp: plugin });
  const res = await f("https://app.example.org/api/v1/x", { method: "GET" });
  assert.equal(res.headers.get("Retry-After"), "7");
  assert.equal(res.headers.get("RETRY-AFTER"), "7");
});

test("a genuine transport rejection propagates (becomes a PolicyVaultNetworkError upstream)", async () => {
  const plugin = fakePlugin({ reject: Object.assign(new Error("Unable to resolve host"), { code: "ENOTFOUND" }) });
  const f = NH.createNativeFetch({ capacitorHttp: plugin });
  await assert.rejects(() => f("https://nope.example/x", { method: "GET" }), /Unable to resolve host/);
});

test("a string (non-JSON) body is returned as-is by text()", async () => {
  const plugin = fakePlugin({ status: 404, url: "https://app.example.org/x", headers: { "Content-Type": "text/plain" }, data: "not found" });
  const f = NH.createNativeFetch({ capacitorHttp: plugin });
  const res = await f("https://app.example.org/x", { method: "GET" });
  assert.equal(await res.text(), "not found");
  assert.equal(res.ok, false);
});

test("an empty body yields empty text, never a thrown parse", async () => {
  const plugin = fakePlugin({ status: 204, url: "https://app.example.org/x", headers: {}, data: null });
  const f = NH.createNativeFetch({ capacitorHttp: plugin });
  const res = await f("https://app.example.org/x", { method: "DELETE" });
  assert.equal(await res.text(), "");
});

test("Origin is set to the request's own origin (the hosted programmatic-client contract), enabling pre-auth POSTs", async () => {
  const plugin = fakePlugin({ status: 200, url: "https://app.policy-vault.org/api/v1/auth/challenge", headers: {}, data: { challenge: {} } });
  const f = NH.createNativeFetch({ capacitorHttp: plugin });
  await f("https://app.policy-vault.org/api/v1/auth/challenge", { method: "POST", body: "{}" });
  assert.equal(plugin.calls[0].headers.Origin, "https://app.policy-vault.org");
});

test("Origin can only ever equal the host actually dialed (never a forged foreign origin)", async () => {
  const plugin = fakePlugin({ status: 200, url: "https://app.policy-vault.org/x", headers: {}, data: {} });
  const f = NH.createNativeFetch({ capacitorHttp: plugin });
  await f("https://app.policy-vault.org/x", { method: "POST", body: "{}" });
  const origin = plugin.calls[0].headers.Origin;
  assert.equal(new URL(origin).host, new URL(plugin.calls[0].url).host);
});

test("a caller-provided Origin is never overridden", async () => {
  const plugin = fakePlugin({ status: 200, url: "https://app.policy-vault.org/x", headers: {}, data: {} });
  const f = NH.createNativeFetch({ capacitorHttp: plugin });
  await f("https://app.policy-vault.org/x", { method: "POST", headers: { Origin: "https://app.policy-vault.org" }, body: "{}" });
  assert.equal(plugin.calls[0].headers.Origin, "https://app.policy-vault.org");
});

test("an already-aborted signal rejects without issuing a request", async () => {
  const plugin = fakePlugin(okJson);
  const f = NH.createNativeFetch({ capacitorHttp: plugin });
  const ctrl = new AbortController();
  ctrl.abort();
  await assert.rejects(() => f("https://app.example.org/x", { method: "GET", signal: ctrl.signal }), /aborted/);
});
