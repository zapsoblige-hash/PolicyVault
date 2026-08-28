"use strict";

/*
 * HOSTED RATE LIMITS (Phase D) — per-class request budgets over the REAL
 * HTTP server, keyed by client IP (trusted-proxy aware) and hosted
 * session. Refusals are PURE: a 429 happens before any durable mutation.
 * Self-hosted default keeps limits OFF (released behavior); hosted mode
 * cannot switch them off.
 */

const { test, after } = require("node:test");
const assert = require("node:assert/strict");
const http = require("node:http");
const os = require("node:os");
const fs = require("node:fs");
const path = require("node:path");

const { loadConfig } = require("../src/config");
const { createServer } = require("../../server/src/server");
const { RateLimiter } = require("../../server/src/limits");
const { getStore, Categories } = require("../src/store");

const DATA = () => fs.mkdtempSync(path.join(os.tmpdir(), "pv-rate-"));

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

function req(port, method, pathName, { body, headers = {} } = {}) {
  return new Promise((resolve, reject) => {
    const data = body === undefined ? undefined : JSON.stringify(body);
    const r = http.request(
      {
        host: "127.0.0.1",
        port,
        method,
        path: pathName,
        headers: { "Content-Type": "application/json", Host: `127.0.0.1:${port}`, Origin: `http://127.0.0.1:${port}`, ...headers }
      },
      (res) => {
        let buf = "";
        res.on("data", (d) => (buf += d));
        res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, json: buf ? JSON.parse(buf) : null }));
      }
    );
    r.on("error", reject);
    if (data) r.write(data);
    r.end();
  });
}

test("§R1 hosted: the auth class enforces its budget with Retry-After; other classes are independent", async () => {
  const config = loadConfig({
    authMode: "enabled",
    authCookieInsecure: true,
    dataRoot: DATA(),
    rateLimits: { auth: { limit: 3, windowMs: 60_000 } }
  });
  const { port } = await startServer(config);
  for (let i = 0; i < 3; i++) {
    const r = await req(port, "POST", "/api/v1/auth/challenge", { body: { walletAddress: "garbage" } });
    assert.equal(r.status, 422, `request ${i + 1} passes the limiter (route-level refusal)`);
  }
  const fourth = await req(port, "POST", "/api/v1/auth/challenge", { body: { walletAddress: "garbage" } });
  assert.equal(fourth.status, 429);
  assert.equal(fourth.json.error.code, "RATE_LIMITED");
  assert.ok(Number(fourth.headers["retry-after"]) >= 1, "Retry-After header present");
  // The read class still flows — budgets are per endpoint class.
  const health = await req(port, "GET", "/api/v1/health");
  assert.equal(health.status, 200);
});

test("§R2 hosted: the window expires and the budget refills", async () => {
  const config = loadConfig({
    authMode: "enabled",
    authCookieInsecure: true,
    dataRoot: DATA(),
    rateLimits: { read: { limit: 2, windowMs: 500 } }
  });
  const { port } = await startServer(config);
  assert.equal((await req(port, "GET", "/api/v1/health")).status, 200);
  assert.equal((await req(port, "GET", "/api/v1/health")).status, 200);
  assert.equal((await req(port, "GET", "/api/v1/health")).status, 429);
  await new Promise((r) => setTimeout(r, 600));
  assert.equal((await req(port, "GET", "/api/v1/health")).status, 200, "budget refilled after the window");
});

test("§R3 hosted: a rate-limited build is PURE — no durable request is created", async () => {
  const dataRoot = DATA();
  const config = loadConfig({
    authMode: "enabled",
    authCookieInsecure: true,
    dataRoot,
    rateLimits: { build: { limit: 1, windowMs: 60_000 } }
  });
  const { port } = await startServer(config);
  const first = await req(port, "POST", "/api/v1/wallet/v4/requests", { body: { vaultId: "zz" } });
  assert.equal(first.status, 400, "reaches the route layer (BAD_VAULT_ID)");
  const second = await req(port, "POST", "/api/v1/wallet/v4/requests", { body: { vaultId: "zz" } });
  assert.equal(second.status, 429, "limiter refuses BEFORE the route layer");
  assert.equal((await getStore(config).listValues(Categories.REQUEST)).length, 0, "no durable request exists");
});

test("§R4 hosted: trusted-proxy client IPs get separate buckets; malformed header falls back to the socket", async () => {
  const config = loadConfig({
    authMode: "enabled",
    authCookieInsecure: true,
    dataRoot: DATA(),
    trustedProxyHeader: "x-real-ip",
    rateLimits: { read: { limit: 2, windowMs: 60_000 } }
  });
  const { port } = await startServer(config);
  const asIp = (ip) => req(port, "GET", "/api/v1/health", { headers: { "X-Real-Ip": ip } });
  assert.equal((await asIp("203.0.113.7")).status, 200);
  assert.equal((await asIp("203.0.113.7")).status, 200);
  assert.equal((await asIp("203.0.113.7")).status, 429, "client A exhausted");
  assert.equal((await asIp("203.0.113.8")).status, 200, "client B has its own bucket");
  // Malformed proxy values collapse to the socket address bucket.
  assert.equal((await asIp("not an ip!!")).status, 200);
  assert.equal((await asIp("<script>")).status, 200);
  assert.equal((await asIp("also bad")).status, 429, "socket-address bucket exhausted");
});

test("§R5 hosted: session-keyed budgets bound one session across client IPs", async () => {
  const kaspa = require(loadConfig({}).rustyKaspaModule);
  const priv = new kaspa.PrivateKey("d1".repeat(32));
  const wallet = {
    priv,
    compressed: priv.toPublicKey().toString().toLowerCase(),
    address: priv.toPublicKey().toAddress("testnet-10").toString()
  };
  const config = loadConfig({
    authMode: "enabled",
    authCookieInsecure: true,
    dataRoot: DATA(),
    trustedProxyHeader: "x-real-ip",
    rateLimits: { mutate: { limit: 2, windowMs: 60_000 } }
  });
  const { port } = await startServer(config);
  const ch = await req(port, "POST", "/api/v1/auth/challenge", { body: { walletAddress: wallet.address } });
  assert.equal(ch.status, 200);
  const signature = kaspa.signMessage({ message: ch.json.challenge.message, privateKey: wallet.priv.toString() });
  const v = await req(port, "POST", "/api/v1/auth/verify", { body: { nonce: ch.json.challenge.nonce, signature, publicKey: wallet.compressed } });
  assert.equal(v.status, 200);
  const cookie = v.headers["set-cookie"][0].split(";")[0];
  // The same session from three different client IPs shares ONE budget.
  const mutate = (ip) =>
    req(port, "POST", "/api/v1/identity/resolve-address", { body: { address: "garbage" }, headers: { Cookie: cookie, "X-Real-Ip": ip } });
  assert.equal((await mutate("203.0.113.1")).status, 422);
  assert.equal((await mutate("203.0.113.2")).status, 422);
  const third = await mutate("203.0.113.3");
  assert.equal(third.status, 429, "session bucket exhausted across IPs");
});

test("§R6 self-hosted: limits stay OFF by default (released behavior)", async () => {
  const config = loadConfig({ dataRoot: DATA() });
  const { port } = await startServer(config);
  for (let i = 0; i < 30; i++) {
    const r = await req(port, "GET", "/api/v1/health");
    assert.equal(r.status, 200);
  }
});

test("§R7 self-hosted: limits can be explicitly enabled without hosted auth", async () => {
  const config = loadConfig({ dataRoot: DATA(), rateLimitsEnabled: true, rateLimits: { read: { limit: 2, windowMs: 60_000 } } });
  const { port } = await startServer(config);
  assert.equal((await req(port, "GET", "/api/v1/health")).status, 200);
  assert.equal((await req(port, "GET", "/api/v1/health")).status, 200);
  assert.equal((await req(port, "GET", "/api/v1/health")).status, 429);
});

test("§R8 config: hosted mode refuses the rate-limit off switch; unknown classes and bad values fail closed", () => {
  const prev = process.env.POLICYVAULT_RATE_LIMITS;
  process.env.POLICYVAULT_RATE_LIMITS = "0";
  try {
    assert.throws(() => loadConfig({ authMode: "enabled", authCookieInsecure: true, dataRoot: DATA() }), /cannot be disabled in hosted mode/);
  } finally {
    if (prev === undefined) delete process.env.POLICYVAULT_RATE_LIMITS;
    else process.env.POLICYVAULT_RATE_LIMITS = prev;
  }
  assert.throws(() => loadConfig({ dataRoot: DATA(), rateLimits: { nonsense: { limit: 5 } } }), /unknown rate-limit class/);
  assert.throws(() => loadConfig({ dataRoot: DATA(), rateLimits: { read: { limit: 0 } } }), /must be an integer/);
  assert.throws(() => loadConfig({ dataRoot: DATA(), rateLimits: { read: { limit: "many" } } }), /must be an integer/);
  assert.throws(() => loadConfig({ dataRoot: DATA(), trustedProxyHeader: "x-forwarded-for" }), /not a supported single-value/);
});

test("§R9 UNIT RateLimiter: bounded memory under key spraying; unknown class fails closed", () => {
  let t = 0;
  const limiter = new RateLimiter({ read: { limit: 10, windowMs: 1000 } }, { maxKeys: 10, now: () => t });
  for (let i = 0; i < 50; i++) limiter.check("read", `ip:203.0.113.${i}`);
  assert.ok(limiter.size() <= 10, `bucket map bounded (${limiter.size()})`);
  assert.throws(() => limiter.check("mystery", "ip:x"), /unknown rate-limit class/);
  // Expired buckets are swept before eviction of live ones.
  t += 2000;
  limiter.check("read", "ip:fresh");
  assert.ok(limiter.size() <= 10);
});
