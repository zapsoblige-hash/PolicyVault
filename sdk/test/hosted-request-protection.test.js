"use strict";

/*
 * HOSTED REQUEST PROTECTION (Phase D) — Origin/Host verification and the
 * security header set, over the REAL HTTP server.
 *
 * Hosted mode (authMode enabled) must enforce the configured application
 * origin on state-changing requests (CSRF wall #2 — SameSite=Strict
 * cookies are #1) and validate Host against the allowlist (DNS-rebinding
 * guard). The self-hosted loopback product keeps its RELEASED origin
 * semantics (no-Origin tools pass; loopback browser origins pass;
 * foreign origins refuse) plus the new rebinding Host guard, which no
 * real loopback client can trip.
 */

const { test, after } = require("node:test");
const assert = require("node:assert/strict");
const http = require("node:http");
const net = require("node:net");
const os = require("node:os");
const fs = require("node:fs");
const path = require("node:path");

const { loadConfig } = require("../src/config");
const { createServer } = require("../../server/src/server");
const { verifyOrigin, verifyHost, parseHost, isLoopbackHostname } = require("../../server/src/limits");

const DATA = () => fs.mkdtempSync(path.join(os.tmpdir(), "pv-prot-"));
const APP_HOST = "app.pv-test.example";
const APP_ORIGIN = `http://${APP_HOST}`;

const servers = [];
async function startServer(config) {
  const server = createServer(config);
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  servers.push(server);
  return { server, port: server.address().port };
}
after(async () => {
  for (const s of servers) await new Promise((r) => s.close(r));
});

/* Raw-control request helper: only the headers WE list are sent (plus
 * node's automatic Host unless overridden). */
function req(port, method, pathName, { body, headers = {} } = {}) {
  return new Promise((resolve, reject) => {
    const data = body === undefined ? undefined : JSON.stringify(body);
    const r = http.request(
      { host: "127.0.0.1", port, method, path: pathName, headers: { "Content-Type": "application/json", ...headers } },
      (res) => {
        let buf = "";
        res.on("data", (d) => (buf += d));
        res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, json: buf && res.headers["content-type"]?.includes("json") ? JSON.parse(buf) : null, text: buf }));
      }
    );
    r.on("error", reject);
    if (data) r.write(data);
    r.end();
  });
}

/* An HTTP/1.0 request with NO Host header at all (raw socket). */
function rawNoHost(port, line) {
  return new Promise((resolve, reject) => {
    const sock = net.connect(port, "127.0.0.1", () => {
      sock.write(`${line} HTTP/1.0\r\n\r\n`);
    });
    let buf = "";
    sock.on("data", (d) => (buf += d));
    sock.on("end", () => resolve(buf));
    sock.on("error", reject);
  });
}

/* "Passed protection" marker: the request reached the route layer (its
 * outcome is a route-level answer, not an origin/host/limit refusal). */
const PROTECTION_CODES = new Set(["ORIGIN_FORBIDDEN", "ORIGIN_REQUIRED", "HOST_FORBIDDEN", "HOST_REQUIRED", "RATE_LIMITED", "SERVER_BUSY"]);
function passedProtection(resp) {
  return !(resp.json && resp.json.error && PROTECTION_CODES.has(resp.json.error.code));
}

let hostedPort;
test("§D1 hosted setup: server with a production-shaped application origin", async () => {
  const config = loadConfig({ authMode: "enabled", authCookieInsecure: true, appOrigin: APP_ORIGIN, dataRoot: DATA() });
  assert.deepEqual([...config.requestProtection.hostAllowlist], [APP_HOST]);
  assert.equal(config.requestProtection.originEnforced, true);
  assert.equal(config.requestProtection.rateLimitsEnabled, true, "hosted mode always rate-limits");
  hostedPort = (await startServer(config)).port;
});

test("§D2 hosted: matching Origin + allowlisted Host passes to the route layer", async () => {
  const r = await req(hostedPort, "POST", "/api/v1/auth/challenge", { body: { walletAddress: "garbage" }, headers: { Host: APP_HOST, Origin: APP_ORIGIN } });
  assert.ok(passedProtection(r), JSON.stringify(r.json));
  assert.equal(r.status, 422, "route-level AUTH_BAD_INPUT proves the request went through");
});

test("§D3 hosted: cross-origin POST refused (403 ORIGIN_FORBIDDEN)", async () => {
  for (const origin of ["https://evil.example", "http://evil.example", `http://${APP_HOST}.evil.example`, `https://${APP_HOST}`]) {
    const r = await req(hostedPort, "POST", "/api/v1/auth/challenge", { body: {}, headers: { Host: APP_HOST, Origin: origin } });
    assert.equal(r.status, 403, origin);
    assert.equal(r.json.error.code, "ORIGIN_FORBIDDEN", origin);
  }
});

test("§D4 hosted: opaque (null) and malformed Origins refused", async () => {
  for (const origin of ["null", "not a url", "app.pv-test.example"]) {
    const r = await req(hostedPort, "POST", "/api/v1/auth/challenge", { body: {}, headers: { Host: APP_HOST, Origin: origin } });
    assert.equal(r.status, 403, origin);
  }
});

test("§D5 hosted: POST without Origin requires Sec-Fetch-Site: same-origin", async () => {
  const bare = await req(hostedPort, "POST", "/api/v1/auth/challenge", { body: {}, headers: { Host: APP_HOST } });
  assert.equal(bare.status, 403);
  assert.equal(bare.json.error.code, "ORIGIN_REQUIRED");

  const sameOrigin = await req(hostedPort, "POST", "/api/v1/auth/challenge", { body: { walletAddress: "garbage" }, headers: { Host: APP_HOST, "Sec-Fetch-Site": "same-origin" } });
  assert.ok(passedProtection(sameOrigin));
  assert.equal(sameOrigin.status, 422);

  for (const site of ["cross-site", "same-site", "none"]) {
    const r = await req(hostedPort, "POST", "/api/v1/auth/challenge", { body: {}, headers: { Host: APP_HOST, "Sec-Fetch-Site": site } });
    assert.equal(r.status, 403, site);
  }
});

test("§D6 hosted: a mismatched Origin is never rescued by Sec-Fetch-Site", async () => {
  const r = await req(hostedPort, "POST", "/api/v1/auth/challenge", {
    body: {},
    headers: { Host: APP_HOST, Origin: "https://evil.example", "Sec-Fetch-Site": "same-origin" }
  });
  assert.equal(r.status, 403);
  assert.equal(r.json.error.code, "ORIGIN_FORBIDDEN");
});

test("§D7 hosted: GET reads pass without Origin; Host still enforced", async () => {
  const ok = await req(hostedPort, "GET", "/api/v1/health", { headers: { Host: APP_HOST } });
  assert.equal(ok.status, 200);
  const evil = await req(hostedPort, "GET", "/api/v1/health", { headers: { Host: "evil.example" } });
  assert.equal(evil.status, 421);
  assert.equal(evil.json.error.code, "HOST_FORBIDDEN");
});

test("§D8 hosted: foreign Host refused on every surface (API, static), good Origin or not", async () => {
  const api = await req(hostedPort, "POST", "/api/v1/auth/challenge", { body: {}, headers: { Host: "evil.example", Origin: APP_ORIGIN } });
  assert.equal(api.status, 421);
  const page = await req(hostedPort, "GET", "/", { headers: { Host: "evil.example" } });
  assert.equal(page.status, 421);
});

test("§D9 hosted: a Host header is required (HTTP/1.0 no-Host refused)", async () => {
  const raw = await rawNoHost(hostedPort, "GET /api/v1/health");
  assert.match(raw, /HOST_REQUIRED/);
});

test("§D10 hosted: loopback allowance — machine-local hosted simulation works (Origin and Host agree on loopback)", async () => {
  const r = await req(hostedPort, "POST", "/api/v1/auth/challenge", {
    body: { walletAddress: "garbage" },
    headers: { Host: `127.0.0.1:${hostedPort}`, Origin: `http://127.0.0.1:${hostedPort}` }
  });
  assert.ok(passedProtection(r));
  assert.equal(r.status, 422);
});

test("§D11 hosted: loopback Origin with a non-matching Host refused", async () => {
  const r = await req(hostedPort, "POST", "/api/v1/auth/challenge", {
    body: {},
    headers: { Host: APP_HOST, Origin: `http://127.0.0.1:${hostedPort}` }
  });
  assert.equal(r.status, 403);
});

test("§D12 hosted headers: strict set + no HSTS on an http application origin", async () => {
  const api = await req(hostedPort, "GET", "/api/v1/health", { headers: { Host: APP_HOST } });
  assert.equal(api.headers["x-content-type-options"], "nosniff");
  assert.equal(api.headers["cache-control"], "no-store");
  assert.equal(api.headers["cross-origin-resource-policy"], "same-origin");
  assert.match(api.headers["permissions-policy"], /camera=\(\)/);
  assert.equal(api.headers["strict-transport-security"], undefined, "no HSTS for an http origin");
  const page = await req(hostedPort, "GET", "/", { headers: { Host: APP_HOST } });
  assert.equal(page.status, 200);
  assert.match(page.headers["content-security-policy"], /script-src 'self'/);
  assert.equal(page.headers["cross-origin-opener-policy"], "same-origin");
  assert.equal(page.headers["cache-control"], "no-cache");
});

test("§D13 hosted headers: HSTS emitted when the application origin is https", async () => {
  const config = loadConfig({ authMode: "enabled", appOrigin: `https://${APP_HOST}`, dataRoot: DATA() });
  const { port } = await startServer(config);
  const api = await req(port, "GET", "/api/v1/health", { headers: { Host: APP_HOST } });
  assert.equal(api.headers["strict-transport-security"], "max-age=31536000; includeSubDomains");
  const page = await req(port, "GET", "/", { headers: { Host: APP_HOST } });
  assert.equal(page.headers["strict-transport-security"], "max-age=31536000; includeSubDomains");
});

test("§D14 hosted: extra allowlisted hosts are honored (explicit operator act)", async () => {
  const config = loadConfig({ authMode: "enabled", authCookieInsecure: true, appOrigin: APP_ORIGIN, extraHosts: "probe.internal:8080", dataRoot: DATA() });
  const { port } = await startServer(config);
  const ok = await req(port, "GET", "/api/v1/health", { headers: { Host: "probe.internal:8080" } });
  assert.equal(ok.status, 200);
  const wrongPort = await req(port, "GET", "/api/v1/health", { headers: { Host: "probe.internal:9090" } });
  assert.equal(wrongPort.status, 421);
});

let selfPort;
test("§D15 self-hosted: released origin semantics preserved exactly", async () => {
  const config = loadConfig({ dataRoot: DATA() });
  assert.equal(config.requestProtection.originEnforced, false);
  assert.equal(config.requestProtection.rateLimitsEnabled, false, "self-hosted default: no rate limits");
  selfPort = (await startServer(config)).port;

  // Tools without an Origin header pass (curl, local scripts).
  const tool = await req(selfPort, "POST", "/api/v1/identity/resolve-address", { body: { address: "garbage" }, headers: { Host: `127.0.0.1:${selfPort}` } });
  assert.ok(passedProtection(tool));
  assert.equal(tool.status, 422);

  // Loopback browser origin matching Host passes.
  const browser = await req(selfPort, "POST", "/api/v1/identity/resolve-address", {
    body: { address: "garbage" },
    headers: { Host: `127.0.0.1:${selfPort}`, Origin: `http://127.0.0.1:${selfPort}` }
  });
  assert.equal(browser.status, 422);

  // Foreign origins refuse (the permanent loopback-CORS lesson).
  const evil = await req(selfPort, "POST", "/api/v1/identity/resolve-address", {
    body: { address: "garbage" },
    headers: { Host: `127.0.0.1:${selfPort}`, Origin: "https://evil.example" }
  });
  assert.equal(evil.status, 403);
  assert.equal(evil.json.error.code, "ORIGIN_FORBIDDEN");
});

test("§D16 self-hosted: DNS-rebinding Host guard — foreign Host refused, loopback Hosts pass, missing Host tolerated", async () => {
  // The rebinding signature: a browser resolves evil.example to 127.0.0.1
  // and sends Host: evil.example. Refused on every surface.
  const api = await req(selfPort, "GET", "/api/v1/health", { headers: { Host: "evil.example" } });
  assert.equal(api.status, 421);
  const page = await req(selfPort, "GET", "/", { headers: { Host: "evil.example:3080" } });
  assert.equal(page.status, 421);

  // Real loopback clients are untouched (any port; localhost family).
  for (const host of [`127.0.0.1:${selfPort}`, `localhost:${selfPort}`, "127.0.0.1", "localhost:9999"]) {
    const ok = await req(selfPort, "GET", "/api/v1/health", { headers: { Host: host } });
    assert.equal(ok.status, 200, host);
  }

  // HTTP/1.0 tooling without a Host header still works against the
  // loopback-bound listener (self-hosted tolerance).
  const raw = await rawNoHost(selfPort, "GET /api/v1/health");
  assert.match(raw, /"ok": true/);
});

test("§D17 OPTIONS stays a bare 204 (no CORS grants on any mode)", async () => {
  const r = await req(hostedPort, "OPTIONS", "/api/v1/health", { headers: { Host: APP_HOST } });
  assert.equal(r.status, 204);
  assert.equal(r.headers["access-control-allow-origin"], undefined);
  const s = await req(selfPort, "OPTIONS", "/api/v1/health", { headers: { Host: `127.0.0.1:${selfPort}` } });
  assert.equal(s.status, 204);
  assert.equal(s.headers["access-control-allow-origin"], undefined);
});

test("§D18 UNIT: parseHost/isLoopbackHostname/verifyOrigin edge shapes", () => {
  assert.equal(parseHost("App.PV-Test.Example").host, "app.pv-test.example");
  assert.equal(parseHost("[::1]:8080").hostname, "[::1]");
  assert.equal(parseHost("a@b"), null, "credentials shape refused");
  assert.equal(parseHost("evil.example/path"), null);
  assert.equal(parseHost(""), null);
  assert.equal(parseHost("x".repeat(300)), null);
  assert.ok(isLoopbackHostname("[::1]"));
  assert.ok(!isLoopbackHostname("127.0.0.2"));

  const hosted = loadConfig({ authMode: "enabled", authCookieInsecure: true, appOrigin: APP_ORIGIN, dataRoot: DATA() });
  // GET/HEAD/OPTIONS are never origin-gated.
  for (const method of ["GET", "HEAD", "OPTIONS"]) {
    verifyOrigin(hosted, { method, origin: "https://evil.example", secFetchSite: undefined, host: APP_HOST });
  }
  // An Origin with a path still matches by URL origin.
  verifyOrigin(hosted, { method: "POST", origin: `${APP_ORIGIN}`, secFetchSite: undefined, host: APP_HOST });
  assert.throws(() => verifyOrigin(hosted, { method: "POST", origin: `${APP_ORIGIN}:8443`, secFetchSite: undefined, host: APP_HOST }), /cross-origin/);
  // Host verification is case-insensitive and port-exact.
  verifyHost(hosted, "APP.PV-TEST.EXAMPLE");
  assert.throws(() => verifyHost(hosted, `${APP_HOST}:8080`), /does not serve/);
});
