"use strict";

/*
 * OPERATIONAL OBSERVABILITY (fullscale surface 25; server/src/metrics.js;
 * server.js instrumentation; GET /api/v1/metrics; structured request log;
 * /health/ready sourcing).
 *
 * Proves, over the REAL HTTP server (createServer + listen — the metrics
 * are recorded in the HTTP layer, so handle()-only tests would miss the
 * wiring):
 *   1. request counters/histograms are ACCURATE under driven traffic
 *      (exact counts per route class/method/status; histogram count sums);
 *   2. refusal codes are counted; the Prometheus exposition renders the
 *      same data and parses; unknown format refuses;
 *   3. structured request logging emits one JSON line per request with
 *      routeClass/status/duration/principal TYPE only — and can be
 *      disabled by POLICYVAULT_REQUEST_LOG=off;
 *   4. NO-SECRET SWEEP: neither the metrics JSON, nor the Prometheus
 *      text, nor any log line contains the scenario's vault id, wallet
 *      addresses, x-only keys, machine tokens, or raw request paths;
 *   5. /health/ready's events aggregate comes from the SAME source as
 *      /metrics (values agree);
 *   6. hosted mode: unauthenticated scrape 401; machine credential
 *      without read:metrics 403 SCOPE_FORBIDDEN; with the scope 200.
 *
 * Layers: API + HTTP (real server, real sockets; JSON backend; no node).
 */

const { test, before, after } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");
const os = require("os");

const { loadConfig } = require("../../server/src/api");
const { createServer } = require("../../server/src/server");
const metrics = require("../../server/src/metrics");

const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "pv-observability-"));
const config = loadConfig({ dataRoot });
const kaspa = require(config.rustyKaspaModule);
const KEY = (v) => new kaspa.PrivateKey(v.toString(16).padStart(2, "0").repeat(32));
const XO = (p) => p.toPublicKey().toXOnlyPublicKey().toString().toLowerCase();
const ADDR = (p) => p.toPublicKey().toAddress(config.networkId).toString();
const OWNER = KEY(0xc1);
const VAULT_ID = "5d".repeat(32);

let server;
let BASE;

/* capture the structured request-log lines this process's server writes */
const logLines = [];
const realWrite = process.stdout.write.bind(process.stdout);
function startLogCapture() {
  process.stdout.write = (chunk, ...rest) => {
    const s = typeof chunk === "string" ? chunk : chunk.toString("utf8");
    if (s.startsWith('{"t":')) {
      for (const line of s.split("\n").filter(Boolean)) logLines.push(line);
      return true; // swallow: keep test output clean
    }
    return realWrite(chunk, ...rest);
  };
}
function stopLogCapture() {
  process.stdout.write = realWrite;
}

const GET = async (url, headers) => {
  const r = await fetch(BASE + url, { headers: headers ?? {} });
  const text = await r.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch {
    /* prometheus text */
  }
  return { status: r.status, text, json };
};

before(async () => {
  metrics._resetForTests();
  startLogCapture();
  server = createServer(config);
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  BASE = `http://127.0.0.1:${server.address().port}`;
});
after(() => {
  stopLogCapture();
  if (server) server.close();
});

test("metrics accuracy under driven traffic: exact per-route counters, histogram totals, refusal codes", async () => {
  // driven traffic: 3x capabilities (200), 2x health (200),
  // 1x missing vault (404 VAULT_NOT_FOUND), 1x bad route (403/404 class)
  for (let i = 0; i < 3; i++) assert.equal((await GET("/api/v1/capabilities")).status, 200);
  for (let i = 0; i < 2; i++) assert.equal((await GET("/api/v1/health")).status, 200);
  const missing = await GET(`/api/v1/vaults/${"9d".repeat(32)}`);
  assert.equal(missing.status, 404);

  const m = await GET("/api/v1/metrics");
  assert.equal(m.status, 200);
  const doc = m.json;
  assert.equal(doc.schemaVersion, "policyvault-metrics/v1");

  const series = (routeClass, method, status) => doc.requests.series.find((s) => s.routeClass === routeClass && s.method === method && s.status === status);
  assert.equal(series("capabilities", "GET", 200).count, 3, JSON.stringify(doc.requests.series));
  assert.equal(series("health", "GET", 200).count, 2);
  assert.equal(series("vaults.get", "GET", 404).count, 1);

  const capDur = doc.durationsMs.find((d) => d.routeClass === "capabilities");
  assert.equal(capDur.count, 3, "histogram count matches driven traffic");
  assert.equal(
    capDur.buckets.reduce((a, b) => a + b.count, 0),
    3,
    "bucket counts sum to the observation count"
  );

  const refusal = doc.refusals.byCode.find((r) => r.code === "VAULT_NOT_FOUND");
  assert.equal(refusal.count, 1, JSON.stringify(doc.refusals));

  // sections present (JSON backend): events aggregate + closed aggregates
  assert.ok(doc.events && typeof doc.events.totalEvents === "number");
  assert.ok(doc.governance && typeof doc.governance.total === "number");
  assert.ok(doc.risk && typeof doc.risk.holdsOpen === "number");
  assert.ok(doc.agentSuspensions && typeof doc.agentSuspensions.vaultsWithSuspensions === "number");
  assert.equal(doc.nodeGate.lastOkAt, null, "no node interaction happened — passive observation stays null");
});

test("prometheus exposition renders the same data; unknown format refuses", async () => {
  const p = await GET("/api/v1/metrics?format=prometheus");
  assert.equal(p.status, 200);
  assert.equal(p.json, null, "prometheus format is text, not JSON");
  assert.match(p.text, /# TYPE policyvault_requests_total counter/);
  assert.match(p.text, /policyvault_requests_total\{route="capabilities",method="GET",status="200"\} 3/);
  assert.match(p.text, /policyvault_refusals_total\{code="VAULT_NOT_FOUND"\} 1/);
  assert.match(p.text, /# TYPE policyvault_request_duration_ms histogram/);
  assert.match(p.text, /policyvault_request_duration_ms_bucket\{route="capabilities",le="\+Inf"\} \d+/);
  assert.match(p.text, /policyvault_webhook_deliveries_total\{outcome="delivered"\} 0/);

  const bad = await GET("/api/v1/metrics?format=xml");
  assert.equal(bad.status, 400);
  assert.equal(bad.json.error.code, "BAD_FORMAT");
});

test("structured request log: one JSON line per request; routeClass/status/duration/principal TYPE only; disable flag honored", async () => {
  logLines.length = 0;
  await GET("/api/v1/capabilities");
  await GET(`/api/v1/vaults/${"9e".repeat(32)}`); // 404 with code
  // give the finish handlers a tick
  await new Promise((r) => setTimeout(r, 50));

  assert.ok(logLines.length >= 2, `captured ${logLines.length} log lines`);
  const parsed = logLines.map((l) => JSON.parse(l));
  const cap = parsed.find((l) => l.route === "capabilities");
  assert.ok(cap, JSON.stringify(parsed));
  assert.equal(cap.kind, "http");
  assert.equal(cap.method, "GET");
  assert.equal(cap.status, 200);
  assert.equal(cap.principal, "none");
  assert.ok(Number.isInteger(cap.ms));
  const nf = parsed.find((l) => l.route === "vaults.get" && l.status === 404);
  assert.ok(nf, "404 line present");
  assert.equal(nf.code, "VAULT_NOT_FOUND");
  // closed line shape: nothing beyond the documented fields
  for (const l of parsed) {
    for (const k of Object.keys(l)) {
      assert.ok(["t", "kind", "route", "method", "status", "ms", "principal", "code"].includes(k), `unexpected log field ${k}`);
    }
  }

  // disable flag
  process.env.POLICYVAULT_REQUEST_LOG = "off";
  try {
    logLines.length = 0;
    await GET("/api/v1/health");
    await new Promise((r) => setTimeout(r, 50));
    assert.equal(logLines.length, 0, "POLICYVAULT_REQUEST_LOG=off silences the request log");
  } finally {
    delete process.env.POLICYVAULT_REQUEST_LOG;
  }
});

test("NO-SECRET SWEEP: metrics JSON, prometheus text, and log lines carry no vault ids, addresses, keys, tokens, or raw paths", async () => {
  logLines.length = 0;
  const probeVault = "9f".repeat(32);
  await GET(`/api/v1/vaults/${probeVault}`); // the raw path embeds a vault id — it must never surface
  await new Promise((r) => setTimeout(r, 50));

  const mJson = (await GET("/api/v1/metrics")).text;
  const mProm = (await GET("/api/v1/metrics?format=prometheus")).text;
  const logs = logLines.join("\n");
  const forbidden = [probeVault, VAULT_ID, ADDR(OWNER), XO(OWNER), "pvmk_", "kaspatest:"];
  for (const surface of [mJson, mProm, logs]) {
    for (const secret of forbidden) {
      assert.ok(!surface.includes(secret), `observability output must never contain ${secret.slice(0, 24)}…`);
    }
  }
  // and no 64-hex identifier of any kind leaks into the log lines
  assert.ok(!/[0-9a-f]{64}/.test(logs), "log lines carry no 64-hex identifiers");
});

test("/health/ready sources its events aggregate from the SAME registry as /metrics (values agree)", async () => {
  const ready = await GET("/api/v1/health/ready");
  assert.equal(ready.status, 200);
  assert.ok(ready.json.events, "ready carries the events aggregate");
  const m = (await GET("/api/v1/metrics")).json;
  assert.equal(ready.json.events.activeEndpoints, m.events.endpoints.active);
  assert.equal(ready.json.events.deadLettered, m.events.deadLettered);
  assert.equal(ready.json.events.droppedEmissions, m.events.droppedEmissions);
});

/* ---------------- hosted mode: principal + scope gating ---------------- */

test("hosted: unauthenticated scrape 401; machine credential without read:metrics 403; with the scope 200", async () => {
  const hostedConfig = loadConfig({
    dataRoot: fs.mkdtempSync(path.join(os.tmpdir(), "pv-observability-hosted-")),
    authMode: "enabled",
    authCookieInsecure: true
  });
  const { handle } = require("../../server/src/api");
  const mi = require("../../server/src/machine-identity");

  await assert.rejects(
    handle(hostedConfig, "GET", ["metrics"], {}, null, { headers: {} }),
    (e) => e.status === 401,
    "unauthenticated scrape refuses in hosted mode"
  );

  const noScope = await mi.createIdentity(hostedConfig, { creatorXOnly: XO(OWNER), label: "no-metrics", scopes: ["read:vaults"] });
  await assert.rejects(
    handle(hostedConfig, "GET", ["metrics"], {}, null, { headers: { authorization: `Bearer ${noScope.credential.token}` } }),
    (e) => e.status === 403 && e.code === "SCOPE_FORBIDDEN",
    "machine credential without read:metrics refuses (deny-by-default)"
  );

  const scoped = await mi.createIdentity(hostedConfig, { creatorXOnly: XO(OWNER), label: "metrics-bot", scopes: ["read:metrics"] });
  const ok = await handle(hostedConfig, "GET", ["metrics"], {}, null, { headers: { authorization: `Bearer ${scoped.credential.token}` } });
  assert.equal(ok.status, 200);
  assert.equal(ok.body.schemaVersion, "policyvault-metrics/v1");
  // the scoped scrape must not leak the token or creator identity back out
  const text = JSON.stringify(ok.body);
  assert.ok(!text.includes(scoped.credential.token));
  assert.ok(!text.includes(XO(OWNER)));
});
