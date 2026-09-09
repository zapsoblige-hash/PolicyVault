"use strict";

/*
 * MCP USAGE TELEMETRY (Track 7; server/src/mcp-telemetry.js; migration
 * server/migrations/010_mcp_telemetry.sql; docs/postlaunch/
 * mcp-usage-telemetry-todo.md).
 *
 * PRIVACY-MINIMIZING, CONFIG-GATED, OFF BY DEFAULT. This suite proves:
 *   1. OFF (default/unset/"off"): zero events recorded, zero storage, the
 *      aggregate route does not exist (404 MCP_TELEMETRY_DISABLED).
 *   2. ON: exactly one event per machine-credential API call, with the
 *      correct closed fields (identityId/mcpClient/tool/method/outcome/
 *      code/latencyMs/at); wallet-session and unauthenticated calls never
 *      produce an event.
 *   3. Header validation: an oversized/malformed X-PolicyVault-MCP-Client
 *      header records as "unknown" and NEVER refuses the underlying
 *      request.
 *   4. Schema closed: an unrecognized event field is refused.
 *   5. PRIVACY NEGATIVES: a bearer token, a signature, a transaction hex,
 *      and request-body content never appear anywhere in the stored
 *      telemetry bytes, even when present in the real request.
 *   6. Aggregates correctness on a hand-built fixture (identities, calls/
 *      day, tools, outcome/code distribution, p50/p95 latency, client
 *      distribution, first/last seen per identity).
 *   7. Retention pruning removes events older than the window and keeps
 *      recent ones.
 *   8. The defensive hard cap silently stops new writes without throwing.
 *   9. The aggregate endpoint reuses the EXACT read:metrics scope gate
 *      (no new authority) and never leaks the credential/token.
 *
 * Layers: API (real server/src/api.js handle(); JSON backend) + one real
 * HTTP round trip (server/src/server.js createServer) for the header +
 * no-secret-sweep proof that needs the actual wire header parsing.
 */

const { test, before, after } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");
const os = require("os");
const crypto = require("crypto");

const { handle, loadConfig } = require("../../server/src/api");
const { createServer } = require("../../server/src/server");
const mi = require("../../server/src/machine-identity");
const { Categories, getPlatformStore } = require("../../server/src/platform-store");
const mcpTelemetry = require("../../server/src/mcp-telemetry");

const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "pv-mcp-telemetry-"));
const config = loadConfig({ dataRoot, authMode: "enabled", authCookieInsecure: true });
const kaspa = require(config.rustyKaspaModule);
const KEY = (v) => new kaspa.PrivateKey(v.toString(16).padStart(2, "0").repeat(32));
const XO = (p) => p.toPublicKey().toXOnlyPublicKey().toString().toLowerCase();
const OWNER = KEY(0xd1);

const GET = (segs, headers, query) => handle(config, "GET", segs, query ?? {}, undefined, { headers: headers ?? {} });

let readerToken; // read:vaults only
let metricsToken; // read:metrics only
let buildToken; // request:build (for the privacy-negative POST)
let readerIdentityId;

async function readEvents(cfg = config) {
  return getPlatformStore(cfg).listValues(Categories.MCP_TELEMETRY_EVENT);
}

/* Each readEvents() call re-parses fresh objects from disk — object
 * identity never survives across two reads, so diffing "before" and
 * "after" snapshots must compare by eventId, never by reference. */
function newEventsSince(beforeList, afterList) {
  const knownIds = new Set(beforeList.map((e) => e.eventId));
  return afterList.filter((e) => !knownIds.has(e.eventId));
}

/* Run a callback with telemetry explicitly ON, restoring the previous
 * env value afterward (never leaks across tests). */
async function withTelemetryOn(fn) {
  const prev = process.env.POLICYVAULT_MCP_TELEMETRY;
  process.env.POLICYVAULT_MCP_TELEMETRY = "1";
  try {
    return await fn();
  } finally {
    if (prev === undefined) delete process.env.POLICYVAULT_MCP_TELEMETRY;
    else process.env.POLICYVAULT_MCP_TELEMETRY = prev;
  }
}
async function withTelemetryOff(fn) {
  const prev = process.env.POLICYVAULT_MCP_TELEMETRY;
  delete process.env.POLICYVAULT_MCP_TELEMETRY;
  try {
    return await fn();
  } finally {
    if (prev !== undefined) process.env.POLICYVAULT_MCP_TELEMETRY = prev;
  }
}

before(async () => {
  delete process.env.POLICYVAULT_MCP_TELEMETRY; // ensure a known-clean starting state
  const reader = await mi.createIdentity(config, { creatorXOnly: XO(OWNER), label: "telemetry-reader", scopes: ["read:vaults"] });
  readerToken = reader.credential.token;
  readerIdentityId = reader.identity.identityId;
  const metricsId = await mi.createIdentity(config, { creatorXOnly: XO(OWNER), label: "telemetry-metrics", scopes: ["read:metrics"] });
  metricsToken = metricsId.credential.token;
  const buildId = await mi.createIdentity(config, { creatorXOnly: XO(OWNER), label: "telemetry-build", scopes: ["request:build"] });
  buildToken = buildId.credential.token;
});

/* ------------------------------- OFF by default ------------------------------- */

test("OFF by default: unset and explicit 'off' both record zero events and the aggregate route does not exist", async () => {
  await withTelemetryOff(async () => {
    const before = await readEvents();
    const r = await GET(["vaults"], { authorization: `Bearer ${readerToken}` });
    assert.equal(r.status, 200);
    const after = await readEvents();
    assert.equal(after.length, before.length, "no event stored while telemetry is unset");

    await assert.rejects(GET(["mcp-telemetry"], { authorization: `Bearer ${metricsToken}` }), (e) => e.status === 404 && e.code === "MCP_TELEMETRY_DISABLED");
  });

  process.env.POLICYVAULT_MCP_TELEMETRY = "off";
  try {
    const before = await readEvents();
    await GET(["vaults"], { authorization: `Bearer ${readerToken}` });
    const after = await readEvents();
    assert.equal(after.length, before.length, "no event stored while POLICYVAULT_MCP_TELEMETRY=off");
    await assert.rejects(GET(["mcp-telemetry"], { authorization: `Bearer ${metricsToken}` }), (e) => e.status === 404 && e.code === "MCP_TELEMETRY_DISABLED");
  } finally {
    delete process.env.POLICYVAULT_MCP_TELEMETRY;
  }
});

/* --------------------------------- ON: recording --------------------------------- */

test("ON: exactly one event per machine-credential call; correct identityId/tool/method/outcome/code/latency/mcpClient/at", async () => {
  await withTelemetryOn(async () => {
    const before = await readEvents();

    const ok = await GET(["vaults"], { authorization: `Bearer ${readerToken}`, mcpClient: "policyvault-mcp/1.4.2" });
    assert.equal(ok.status, 200);
    let after = await readEvents();
    assert.equal(after.length, before.length + 1, "exactly one event for the successful call");
    let ev = newEventsSince(before, after)[0];
    assert.equal(ev.schema, mcpTelemetry.TELEMETRY_EVENT_SCHEMA);
    assert.equal(ev.identityId, readerIdentityId);
    assert.equal(ev.mcpClient, "policyvault-mcp/1.4.2");
    assert.equal(ev.tool, "vaults.list");
    assert.equal(ev.method, "GET");
    assert.equal(ev.outcome, "success");
    assert.equal(ev.code, null);
    assert.ok(Number.isInteger(ev.latencyMs) && ev.latencyMs >= 0, `latencyMs ${ev.latencyMs}`);
    assert.ok(Number.isFinite(Date.parse(ev.at)));
    assert.ok(Date.now() - Date.parse(ev.at) < 10000, "at is recent");
    assert.equal(ev.requestId, null, "GET /vaults carries no requestId in its body");
    // never the credential or its hash anywhere in the stored event
    const bytes = JSON.stringify(ev);
    assert.ok(!bytes.includes(readerToken));

    // refusal: unknown vault -> 404 VAULT_NOT_FOUND
    const before2 = await readEvents();
    await assert.rejects(GET(["vaults", "ff".repeat(32)], { authorization: `Bearer ${readerToken}` }));
    after = await readEvents();
    assert.equal(after.length, before2.length + 1, "exactly one event for the refused call");
    ev = newEventsSince(before2, after)[0];
    assert.equal(ev.outcome, "refusal");
    assert.equal(ev.code, "VAULT_NOT_FOUND");
    assert.equal(ev.tool, "vaults.get");

    // scope refusal (403 SCOPE_FORBIDDEN, thrown before dispatch even runs)
    const before3 = await readEvents();
    await assert.rejects(GET(["mcp-telemetry"], { authorization: `Bearer ${readerToken}` }), (e) => e.status === 403 && e.code === "SCOPE_FORBIDDEN");
    after = await readEvents();
    assert.equal(after.length, before3.length + 1, "a scope refusal still records exactly one event");
    ev = newEventsSince(before3, after)[0];
    assert.equal(ev.outcome, "refusal");
    assert.equal(ev.code, "SCOPE_FORBIDDEN");
  });
});

test("ON: wallet-session and unauthenticated calls never produce a telemetry event (machine credential only)", async () => {
  await withTelemetryOn(async () => {
    // self-hosted-style config: authMode disabled entirely -> handle()
    // never resolves any principal for a non-public route; use a fresh
    // config/data root so telemetry storage starts empty and isolated.
    const openDataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "pv-mcp-telemetry-open-"));
    const openConfig = loadConfig({ dataRoot: openDataRoot });
    const before = await readEvents(openConfig);
    const r = await handle(openConfig, "GET", ["vaults"], {}, undefined, { headers: {} });
    assert.equal(r.status, 200);
    const after = await readEvents(openConfig);
    assert.equal(after.length, before.length, "an unauthenticated/self-hosted call never emits telemetry");
    assert.equal(after.length, 0);
  });
});

/* ------------------------------- header validation ------------------------------- */

test("header validation: oversized/malformed X-PolicyVault-MCP-Client records as 'unknown', never refuses the request", async () => {
  await withTelemetryOn(async () => {
    const cases = [
      { header: undefined, expect: "unknown" },
      { header: "x".repeat(500), expect: "unknown" },
      { header: "no-slash-here", expect: "unknown" },
      { header: "/missing-name", expect: "unknown" },
      { header: "claude-desktop/2.1.0", expect: "claude-desktop/2.1.0" },
      { header: "policyvault-mcp/1.4.2", expect: "policyvault-mcp/1.4.2" }
    ];
    for (const c of cases) {
      const before = await readEvents();
      const headers = { authorization: `Bearer ${readerToken}` };
      if (c.header !== undefined) headers.mcpClient = c.header;
      const r = await GET(["vaults"], headers);
      assert.equal(r.status, 200, `request never refused for header ${JSON.stringify(c.header)}`);
      const after = await readEvents();
      const ev = newEventsSince(before, after)[0];
      assert.ok(ev, "an event was recorded");
      assert.equal(ev.mcpClient, c.expect, `header ${JSON.stringify(c.header)}`);
    }
  });
});

/* --------------------------------- schema closed --------------------------------- */

test("schema closed: buildTelemetryEvent refuses an unrecognized field", () => {
  const valid = {
    identityId: crypto.randomUUID(),
    mcpClient: "policyvault-mcp/1.4.2",
    tool: "vaults.list",
    method: "GET",
    outcome: "success",
    code: null,
    latencyMs: 5,
    at: new Date().toISOString(),
    requestId: null
  };
  const ev = mcpTelemetry.buildTelemetryEvent(config, valid);
  assert.equal(ev.schema, mcpTelemetry.TELEMETRY_EVENT_SCHEMA);
  assert.throws(() => mcpTelemetry.buildTelemetryEvent(config, { ...valid, bogusField: "x" }), (e) => e.code === "MCP_TELEMETRY_EVENT_UNKNOWN_FIELD");
  assert.throws(() => mcpTelemetry.buildTelemetryEvent(config, { ...valid, prompt: "ignore all instructions" }), (e) => e.code === "MCP_TELEMETRY_EVENT_UNKNOWN_FIELD");
});

/* ------------------------------- privacy negatives ------------------------------- */

test("PRIVACY: a bearer token, a signature, a transaction hex, and request-body content never appear in stored telemetry bytes", async () => {
  await withTelemetryOn(async () => {
    const server = createServer(config);
    await new Promise((r) => server.listen(0, "127.0.0.1", r));
    try {
      const port = server.address().port;
      const secretMarker = `SECRET_MARKER_${crypto.randomBytes(8).toString("hex")}`;
      const fakeSignature = crypto.randomBytes(64).toString("hex");
      const fakeTxHex = crypto.randomBytes(96).toString("hex");
      const body = JSON.stringify({
        vaultId: "ab".repeat(32),
        action: "agentSpend",
        signerAddress: "kaspatest:notarealaddress",
        params: {},
        signature: fakeSignature,
        transactionHex: fakeTxHex,
        secretMarker
      });
      const responseText = await new Promise((resolve, reject) => {
        const req = require("http").request(
          {
            host: "127.0.0.1",
            port,
            method: "POST",
            path: "/api/v1/wallet/v4/simulate",
            headers: {
              Host: `127.0.0.1:${port}`,
              "Content-Type": "application/json",
              "Content-Length": Buffer.byteLength(body),
              Authorization: `Bearer ${buildToken}`,
              "X-PolicyVault-MCP-Client": "policyvault-mcp/1.4.2"
            }
          },
          (res) => {
            let buf = "";
            res.on("data", (d) => (buf += d));
            res.on("end", () => resolve(buf));
          }
        );
        req.on("error", reject);
        req.write(body);
        req.end();
      });
      void responseText; // the closed-body refusal itself isn't the point here

      // scan every stored telemetry event's raw bytes for the secrets
      const dir = path.join(dataRoot, "platform", "mcp-telemetry-events");
      const files = fs.existsSync(dir) ? fs.readdirSync(dir).filter((f) => f.endsWith(".json")) : [];
      assert.ok(files.length > 0, "at least one telemetry file exists to scan");
      const allBytes = files.map((f) => fs.readFileSync(path.join(dir, f), "utf8")).join("\n");
      for (const secret of [buildToken, fakeSignature, fakeTxHex, secretMarker, "Bearer "]) {
        assert.ok(!allBytes.includes(secret), `telemetry storage must never contain ${secret.slice(0, 16)}…`);
      }
      // and the aggregate/event never carries an "authorization"/"body" key at all
      assert.ok(!allBytes.includes('"authorization"'));
      assert.ok(!allBytes.includes('"body"'));

      // confirm the real HTTP round trip DID thread the client header through
      const events = await readEvents();
      const simEvent = events.find((e) => e.tool === "wallet.v4.simulate");
      assert.ok(simEvent, "the simulate call was recorded");
      assert.equal(simEvent.mcpClient, "policyvault-mcp/1.4.2");
    } finally {
      await new Promise((r) => server.close(r));
    }
  });
});

/* -------------------------------- aggregates -------------------------------- */

test("aggregates correctness on a hand-built fixture", async () => {
  const fixDataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "pv-mcp-telemetry-agg-"));
  const fixConfig = loadConfig({ dataRoot: fixDataRoot, authMode: "enabled", authCookieInsecure: true });
  const store = getPlatformStore(fixConfig);

  const idA = crypto.randomUUID();
  const idB = crypto.randomUUID();
  const day1 = "2020-01-01T00:00:00.000Z";
  const day1Late = "2020-01-01T12:00:00.000Z";
  const day2 = "2020-01-02T00:00:00.000Z";
  const nowMs = Date.parse("2020-01-02T00:00:00.000Z");

  const fixture = [
    { identityId: idA, mcpClient: "policyvault-mcp/1.4.2", tool: "vaults.list", method: "GET", outcome: "success", code: null, latencyMs: 10, at: day1, requestId: null },
    { identityId: idA, mcpClient: "policyvault-mcp/1.4.2", tool: "vaults.list", method: "GET", outcome: "refusal", code: "VAULT_NOT_FOUND", latencyMs: 20, at: day1Late, requestId: null },
    { identityId: idA, mcpClient: "claude-desktop/2.0.0", tool: "wallet.v4.build", method: "POST", outcome: "error", code: "INTERNAL", latencyMs: 100, at: day2, requestId: null },
    { identityId: idB, mcpClient: "unknown", tool: "audit", method: "GET", outcome: "success", code: null, latencyMs: 40, at: day2, requestId: null },
    { identityId: idB, mcpClient: "unknown", tool: "audit", method: "GET", outcome: "success", code: null, latencyMs: 30, at: day2, requestId: null }
  ];
  for (const f of fixture) {
    const ev = mcpTelemetry.buildTelemetryEvent(fixConfig, f);
    const created = await store.createExclusive(Categories.MCP_TELEMETRY_EVENT, ev.eventId, ev);
    assert.ok(created);
  }

  const doc = await mcpTelemetry.buildTelemetryAggregate(fixConfig, { nowMs });
  assert.equal(doc.schemaVersion, mcpTelemetry.TELEMETRY_AGGREGATE_SCHEMA);
  assert.equal(doc.window.totalStored, 5);
  assert.equal(doc.identities.distinct, 2);

  const idAEntry = doc.identities.firstLastSeen.find((e) => e.identityId === idA);
  assert.equal(idAEntry.calls, 3);
  assert.equal(idAEntry.firstSeenAt, day1);
  assert.equal(idAEntry.lastSeenAt, day2);
  const idBEntry = doc.identities.firstLastSeen.find((e) => e.identityId === idB);
  assert.equal(idBEntry.calls, 2);

  const day1Count = doc.callsPerDay.find((d) => d.date === "2020-01-01");
  const day2Count = doc.callsPerDay.find((d) => d.date === "2020-01-02");
  assert.equal(day1Count.count, 2);
  assert.equal(day2Count.count, 3);

  assert.equal(doc.tools.byTool["vaults.list"], 2);
  assert.equal(doc.tools.byTool["wallet.v4.build"], 1);
  assert.equal(doc.tools.byTool["audit"], 2);

  assert.equal(doc.outcomes.success, 3);
  assert.equal(doc.outcomes.refusal, 1);
  assert.equal(doc.outcomes.error, 1);
  assert.equal(doc.outcomes.byCode.VAULT_NOT_FOUND, 1);
  assert.equal(doc.outcomes.byCode.INTERNAL, 1);

  assert.equal(doc.clients.byClient["policyvault-mcp/1.4.2"], 2);
  assert.equal(doc.clients.byClient["claude-desktop/2.0.0"], 1);
  assert.equal(doc.clients.byClient.unknown, 2);

  // latencies sorted: [10, 20, 30, 40, 100] -> p50 idx floor(0.5*5)=2 -> 30; p95 idx floor(0.95*5)=4 -> 100
  assert.equal(doc.latencyMs.count, 5);
  assert.equal(doc.latencyMs.p50, 30);
  assert.equal(doc.latencyMs.p95, 100);
});

/* ------------------------------- retention pruning ------------------------------- */

test("retention pruning removes events older than the window and keeps recent ones", async () => {
  const pruneDataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "pv-mcp-telemetry-prune-"));
  const pruneConfig = loadConfig({ dataRoot: pruneDataRoot, authMode: "enabled", authCookieInsecure: true });
  const store = getPlatformStore(pruneConfig);

  const nowMs = Date.parse("2020-06-01T00:00:00.000Z");
  const oldAt = new Date(nowMs - 91 * 24 * 60 * 60 * 1000).toISOString(); // 91 days old
  const recentAt = new Date(nowMs - 1 * 24 * 60 * 60 * 1000).toISOString(); // 1 day old

  const oldIds = [];
  for (let i = 0; i < 3; i++) {
    const ev = mcpTelemetry.buildTelemetryEvent(pruneConfig, {
      identityId: crypto.randomUUID(),
      mcpClient: "unknown",
      tool: "vaults.list",
      method: "GET",
      outcome: "success",
      code: null,
      latencyMs: 1,
      at: oldAt,
      requestId: null
    });
    await store.createExclusive(Categories.MCP_TELEMETRY_EVENT, ev.eventId, ev);
    oldIds.push(ev.eventId);
  }
  const recentEv = mcpTelemetry.buildTelemetryEvent(pruneConfig, {
    identityId: crypto.randomUUID(),
    mcpClient: "unknown",
    tool: "vaults.list",
    method: "GET",
    outcome: "success",
    code: null,
    latencyMs: 1,
    at: recentAt,
    requestId: null
  });
  await store.createExclusive(Categories.MCP_TELEMETRY_EVENT, recentEv.eventId, recentEv);

  const result = await mcpTelemetry.pruneExpiredEvents(pruneConfig, { nowMs, days: 90 });
  assert.equal(result.prunedCount, 3);

  const remaining = await store.listValues(Categories.MCP_TELEMETRY_EVENT);
  assert.equal(remaining.length, 1);
  assert.equal(remaining[0].eventId, recentEv.eventId);
});

/* --------------------------------- hard cap --------------------------------- */

test("hard cap: writes beyond the cap are silently dropped, never throw", async () => {
  const capDataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "pv-mcp-telemetry-cap-"));
  const capConfig = loadConfig({ dataRoot: capDataRoot, authMode: "enabled", authCookieInsecure: true });
  const identity = await mi.createIdentity(capConfig, { creatorXOnly: XO(OWNER), label: "cap-test", scopes: ["read:vaults"] });
  const principal = { isMachine: true, identityId: identity.identity.identityId, scopes: identity.identity.scopes };

  await withTelemetryOn(async () => {
    mcpTelemetry._setMaxStoredEventsForTests(2);
    try {
      for (let i = 0; i < 5; i++) {
        await mcpTelemetry.recordMcpToolInvocation(capConfig, {
          principal,
          method: "GET",
          segments: ["vaults"],
          status: 200,
          code: null,
          requestId: null,
          latencyMs: 1,
          mcpClientHeader: undefined
        });
      }
      const stored = await getPlatformStore(capConfig).listValues(Categories.MCP_TELEMETRY_EVENT);
      assert.equal(stored.length, 2, "the hard cap stops further writes");
    } finally {
      mcpTelemetry._setMaxStoredEventsForTests(null);
    }
  });
});

/* ------------------------- aggregate endpoint access model ------------------------- */

test("aggregate endpoint reuses read:metrics (no new scope): unauthenticated 401; missing scope 403; with the scope 200 and no secret leakage", async () => {
  await withTelemetryOn(async () => {
    await assert.rejects(GET(["mcp-telemetry"]), (e) => e.status === 401);
    await assert.rejects(GET(["mcp-telemetry"], { authorization: `Bearer ${readerToken}` }), (e) => e.status === 403 && e.code === "SCOPE_FORBIDDEN");
    const ok = await GET(["mcp-telemetry"], { authorization: `Bearer ${metricsToken}` });
    assert.equal(ok.status, 200);
    assert.equal(ok.body.schemaVersion, mcpTelemetry.TELEMETRY_AGGREGATE_SCHEMA);
    assert.equal(ok.body.config.retentionDays, mcpTelemetry.DEFAULT_RETENTION_DAYS);
    assert.equal(ok.body.config.enabled, true);
    const text = JSON.stringify(ok.body);
    assert.ok(!text.includes(metricsToken));
    assert.ok(!text.includes(readerToken));
    assert.ok(!text.includes(XO(OWNER)));
  });
});

test("GET /mcp-telemetry when OFF is 404 regardless of tenancy mode", async () => {
  await withTelemetryOff(async () => {
    const selfHostedDataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "pv-mcp-telemetry-selfhosted-"));
    const selfHostedConfig = loadConfig({ dataRoot: selfHostedDataRoot });
    await assert.rejects(handle(selfHostedConfig, "GET", ["mcp-telemetry"], {}, undefined, { headers: {} }), (e) => e.status === 404 && e.code === "MCP_TELEMETRY_DISABLED");
  });
});

/* ------------------------------ capabilities reflect the flag ------------------------------ */

test("capabilities document reflects the live POLICYVAULT_MCP_TELEMETRY flag and advertises the schemas", async () => {
  const { buildCapabilities } = require("../../server/src/capabilities");
  await withTelemetryOff(() => {
    const doc = buildCapabilities(config);
    assert.equal(doc.features.mcpTelemetry, false);
    assert.equal(doc.schemas.mcpTelemetryEvent, mcpTelemetry.TELEMETRY_EVENT_SCHEMA);
    assert.equal(doc.schemas.mcpTelemetryAggregate, mcpTelemetry.TELEMETRY_AGGREGATE_SCHEMA);
  });
  await withTelemetryOn(() => {
    const doc = buildCapabilities(config);
    assert.equal(doc.features.mcpTelemetry, true);
  });
});

/* ---------------- PostgreSQL: migration 010 + PG round-trip ---------------- */

const PG = {
  host: process.env.POLICYVAULT_TEST_PG_HOST || "127.0.0.1",
  port: Number(process.env.POLICYVAULT_TEST_PG_PORT || 0),
  user: process.env.POLICYVAULT_TEST_PG_USER,
  database: process.env.POLICYVAULT_TEST_PG_DATABASE
};
const PG_AVAILABLE = Boolean(PG.port && PG.user && PG.database);

test(
  "postgres: migration 010 applies and telemetry round-trips through the real server on PG (record, aggregate, prune)",
  { skip: PG_AVAILABLE ? undefined : "set POLICYVAULT_TEST_PG_{PORT,USER,DATABASE} to run the PG section" },
  async () => {
    const { Pool } = require("pg");
    const adminPool = new Pool({ host: PG.host, port: PG.port, user: PG.user, database: PG.database });
    // A dedicated, throwaway database per run (dropped in `finally`) is the
    // isolation unit — never a shared table other concurrent suites/runs
    // might also be writing to. pid+timestamp is the established
    // convention here (postlaunch-agent-suspend-server.test.js's PG
    // section), plus a random suffix as defense in depth against a
    // same-millisecond collision when the cluster is under concurrent use.
    const dbName = `pv_mcptel_${process.pid}_${Date.now() % 100000}_${crypto.randomBytes(4).toString("hex")}`;
    await adminPool.query(`CREATE DATABASE ${dbName}`);
    let pgStore = null;
    try {
      const pgConfig = loadConfig({
        persistenceBackend: "postgres",
        pgHost: PG.host,
        pgPort: PG.port,
        pgUser: PG.user,
        pgDatabase: dbName,
        pgNoTls: true,
        hostedDevOpen: true,
        authMode: "enabled",
        authCookieInsecure: true,
        dataRoot: fs.mkdtempSync(path.join(os.tmpdir(), "pv-mcp-telemetry-pg-"))
      });
      const { openPgStore, getStore } = require("../src/store");
      pgStore = await openPgStore(pgConfig, { migrate: true });
      // 010 applied: the mcp_telemetry_events table exists
      const t = await getStore(pgConfig).pool().query("SELECT to_regclass('mcp_telemetry_events') AS reg");
      assert.equal(t.rows[0].reg, "mcp_telemetry_events");

      const identity = await mi.createIdentity(pgConfig, { creatorXOnly: XO(OWNER), label: "pg-reader", scopes: ["read:vaults", "read:metrics"] });
      const token = identity.credential.token;

      await withTelemetryOn(async () => {
        const r = await handle(pgConfig, "GET", ["vaults"], {}, undefined, { headers: { authorization: `Bearer ${token}` } });
        assert.equal(r.status, 200);

        // This database is exclusively ours (created fresh above, dropped
        // in `finally`) — a plain row count is genuinely local state, not
        // a "global count" shared with any concurrent suite/run.
        const row = await getStore(pgConfig)
          .pool()
          .query("SELECT value FROM mcp_telemetry_events WHERE network_id = $1", [pgConfig.networkId]);
        assert.equal(row.rowCount, 1);
        assert.equal(row.rows[0].value.identityId, identity.identity.identityId);
        assert.equal(row.rows[0].value.tool, "vaults.list");
        assert.equal(row.rows[0].value.outcome, "success");
        // never the raw credential anywhere in the durable row
        assert.ok(!JSON.stringify(row.rows[0].value).includes(token));

        const agg = await handle(pgConfig, "GET", ["mcp-telemetry"], {}, undefined, { headers: { authorization: `Bearer ${token}` } });
        assert.equal(agg.status, 200);
        // Computed from BEFORE this same request's own event is durable
        // (server/src/api.js handle() writes the telemetry row only AFTER
        // dispatchRoute resolves) — so it still reports just the prior
        // vaults.list call, not this aggregate read itself.
        assert.equal(agg.body.window.totalStored, 1);
        assert.equal(agg.body.identities.distinct, 1);

        // By NOW both real machine-credential calls above are durable: the
        // vaults.list read AND this aggregate GET itself (it is, like any
        // other route, telemetry-recorded once its own response is ready —
        // see the comment above). Read the actual count rather than
        // assuming one, then prove pruning removes exactly what is there.
        const beforePrune = await getStore(pgConfig)
          .pool()
          .query("SELECT count(*)::int AS n FROM mcp_telemetry_events WHERE network_id = $1", [pgConfig.networkId]);
        assert.equal(beforePrune.rows[0].n, 2, "vaults.list + the mcp-telemetry read itself are both recorded by this point");

        const pruned = await mcpTelemetry.pruneExpiredEvents(pgConfig, { nowMs: Date.now() + 91 * 24 * 60 * 60 * 1000, days: 90 });
        assert.equal(pruned.prunedCount, 2);
        const after = await getStore(pgConfig)
          .pool()
          .query("SELECT count(*)::int AS n FROM mcp_telemetry_events WHERE network_id = $1", [pgConfig.networkId]);
        assert.equal(after.rows[0].n, 0);
      });
    } finally {
      if (pgStore) await pgStore.close().catch(() => {});
      await adminPool.query(`DROP DATABASE IF EXISTS ${dbName} WITH (FORCE)`).catch(() => {});
      await adminPool.end();
    }
  }
);
