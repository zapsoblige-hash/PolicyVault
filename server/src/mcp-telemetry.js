"use strict";

/*
 * MCP USAGE TELEMETRY (Track 7; docs/postlaunch/mcp-usage-telemetry-todo.md;
 * server/migrations/010_mcp_telemetry.sql).
 *
 * PRIVACY-MINIMIZING, CONFIG-GATED, OFF BY DEFAULT. Records ONE closed
 * event per API call that resolved to a machine (AI/agent) credential
 * principal — the broader "any programmatic caller authenticated with a
 * machine bearer token" surface, of which the MCP adapter (mcp/) is one
 * caller among several (JS/Python clients, x402/AP2 adapters). The MCP
 * adapter identifies itself via an explicit request header it already
 * controls (X-PolicyVault-MCP-Client: <name>/<version>, added in
 * mcp/src/http.js) — treated here as UNTRUSTED DISPLAY DATA (length-capped,
 * charset-validated); every other caller simply shows up as mcpClient
 * "unknown".
 *
 * WIRING: server/src/api.js handle() — the SAME single per-request
 * principal-resolution funnel that already does deny-by-default scope
 * gating — calls recordMcpToolInvocation() once per request, in a
 * try/finally around dispatch, keyed by the resolved principal
 * (machine:<identityId>). No new authentication path, no new middleware.
 *
 * PRIVACY CONTRACT (binding; enforced by construction in
 * buildTelemetryEvent below — never a spread of caller-controlled input):
 * an event NEVER carries prompts/model context; bearer tokens or any
 * credential material (raw or hashed); private keys; wallet secrets; raw
 * signing material (signatures, PSKTs, transaction bytes); or request
 * bodies. The closed field set is EXACTLY: identityId (the machine
 * identity — never the credential/hash), mcpClient (display string),
 * tool (a closed route-class label — reuses server/src/metrics.js's
 * existing enumeration, never a raw path), method, outcome
 * (success|refusal|error) + a closed code, latencyMs, at (ISO-8601), and
 * an optional requestId carried ONLY when it was already public in that
 * same response body (never a new disclosure).
 *
 * CONFIG GATE: POLICYVAULT_MCP_TELEMETRY unset/"off" (default) means NO
 * events are ever built, stored, or served, and the aggregate read route
 * (GET /api/v1/mcp-telemetry, server/src/api.js) does not exist (404
 * MCP_TELEMETRY_DISABLED). This module shipping does NOT enable
 * production telemetry — enabling it is a separate, explicit deployment
 * decision (env var) the owner makes later.
 *
 * STORAGE: a new CREATE-ONLY platform-store category
 * (server/src/platform-store.js Categories.MCP_TELEMETRY_EVENT; JSON +
 * PostgreSQL, migration 010) — same shape discipline as every other
 * category table. Retention (default 90 days) and a hard per-process
 * storage cap are enforced here, honestly, as best-effort, aggregate-on-
 * read observability data (the SAME "scrape-time aggregate" posture
 * server/src/metrics.js already documents) — never consensus/financial
 * state.
 *
 * ACCESS: the aggregate read endpoint reuses the EXACT same access model
 * as GET /metrics (server/src/scopes.js `read:metrics`) — no new scope,
 * no new authority. See docs/postlaunch/operational-observability.md.
 */

const crypto = require("crypto");
const { Categories, getPlatformStore } = require("./platform-store");
const { metricsRouteClass } = require("./metrics");

const TELEMETRY_EVENT_SCHEMA = "policyvault-mcp-telemetry-event/v1";
const TELEMETRY_AGGREGATE_SCHEMA = "policyvault-mcp-telemetry-aggregate/v1";

const DEFAULT_RETENTION_DAYS = 90;
const MIN_RETENTION_DAYS = 1;
const MAX_RETENTION_DAYS = 3650;

/* Defensive per-process hard cap (mirrors server/src/metrics.js's own
 * defensive series/refusal caps): never let unbounded telemetry writes
 * grow the durable store without bound. Best-effort (see currentCount
 * below) — a strict consensus-grade limit is not the goal here. */
const MAX_STORED_EVENTS = 100000;

const MCP_CLIENT_HEADER_MAX = 160;
/* "<name>/<version>", each half a boring package-identifier-shaped
 * string. Anything else (oversized, wrong shape, absent) normalizes to
 * the literal display value "unknown" — the header is NEVER trusted
 * enough to reject a request over, per the binding spec. */
const MCP_CLIENT_RE = /^([A-Za-z0-9][A-Za-z0-9._-]{0,63})\/([A-Za-z0-9][A-Za-z0-9._+-]{0,63})$/;

const EVENT_FIELDS = Object.freeze(["identityId", "mcpClient", "tool", "method", "outcome", "code", "latencyMs", "at", "requestId"]);
const OUTCOMES = Object.freeze(["success", "refusal", "error"]);
const METHODS = Object.freeze(["GET", "POST"]);
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const CODE_RE = /^[A-Z][A-Z0-9_]{1,63}$/;
const MAX_TOOL_LEN = 64;

class McpTelemetryError extends Error {
  constructor(code, message) {
    super(message);
    this.code = code;
  }
}

/* ------------------------------- config -------------------------------- */

function telemetryEnabled() {
  const v = process.env.POLICYVAULT_MCP_TELEMETRY;
  return v === "1" || v === "on" || v === "true";
}

function retentionDays() {
  const raw = process.env.POLICYVAULT_MCP_TELEMETRY_RETENTION_DAYS;
  if (raw === undefined || raw === "") return DEFAULT_RETENTION_DAYS;
  const n = Number(raw);
  if (!Number.isInteger(n) || n < MIN_RETENTION_DAYS || n > MAX_RETENTION_DAYS) return DEFAULT_RETENTION_DAYS;
  return n;
}

let maxStoredEventsOverride = null;
function maxStoredEvents() {
  return maxStoredEventsOverride ?? MAX_STORED_EVENTS;
}
/* test-only: exercise the hard cap without writing 100k real records. */
function _setMaxStoredEventsForTests(n) {
  maxStoredEventsOverride = Number.isInteger(n) && n >= 0 ? n : null;
}

/* --------------------------- header handling ---------------------------- */

/*
 * Normalize the caller-controlled X-PolicyVault-MCP-Client header into a
 * closed display string. NEVER throws; NEVER influences whether the
 * request itself succeeds — an oversized or malformed header simply
 * records as "unknown".
 */
function parseMcpClientHeader(raw) {
  if (typeof raw !== "string") return "unknown";
  const trimmed = raw.trim();
  if (trimmed.length === 0 || trimmed.length > MCP_CLIENT_HEADER_MAX) return "unknown";
  if (!MCP_CLIENT_RE.test(trimmed)) return "unknown";
  return trimmed;
}

/* ------------------------------ event build ------------------------------ */

/*
 * Build ONE closed telemetry event. Fields are picked explicitly (never a
 * spread of caller input), so nothing outside EVENT_FIELDS can ever reach
 * storage; an unrecognized key throws (deny-by-default — the same
 * discipline server/src/api.js assertClosedBody and server/src/events.js
 * buildEvent already use elsewhere in this codebase).
 */
function buildTelemetryEvent(config, fields) {
  if (!fields || typeof fields !== "object" || Array.isArray(fields)) {
    throw new McpTelemetryError("MCP_TELEMETRY_EVENT_INVALID", "telemetry event fields must be an object");
  }
  for (const key of Object.keys(fields)) {
    if (!EVENT_FIELDS.includes(key)) {
      throw new McpTelemetryError("MCP_TELEMETRY_EVENT_UNKNOWN_FIELD", `unknown telemetry field ${JSON.stringify(key)} — refusing (closed schema)`);
    }
  }
  const { identityId, mcpClient, tool, method, outcome, code, latencyMs, at, requestId } = fields;

  if (typeof identityId !== "string" || !UUID_RE.test(identityId)) {
    throw new McpTelemetryError("MCP_TELEMETRY_IDENTITY_INVALID", "identityId must be a machine identity uuid");
  }
  if (typeof mcpClient !== "string" || mcpClient.length === 0 || mcpClient.length > MCP_CLIENT_HEADER_MAX) {
    throw new McpTelemetryError("MCP_TELEMETRY_CLIENT_INVALID", "mcpClient must be a normalized display string");
  }
  if (typeof tool !== "string" || tool.length === 0 || tool.length > MAX_TOOL_LEN) {
    throw new McpTelemetryError("MCP_TELEMETRY_TOOL_INVALID", "tool must be a short route-class string");
  }
  if (!METHODS.includes(method)) {
    throw new McpTelemetryError("MCP_TELEMETRY_METHOD_INVALID", "method must be GET or POST");
  }
  if (!OUTCOMES.includes(outcome)) {
    throw new McpTelemetryError("MCP_TELEMETRY_OUTCOME_INVALID", "outcome must be success|refusal|error");
  }
  if (!Number.isFinite(latencyMs) || latencyMs < 0) {
    throw new McpTelemetryError("MCP_TELEMETRY_LATENCY_INVALID", "latencyMs must be a non-negative finite number");
  }
  if (typeof at !== "string" || !Number.isFinite(Date.parse(at))) {
    throw new McpTelemetryError("MCP_TELEMETRY_AT_INVALID", "at must be an ISO-8601 timestamp");
  }

  const normalizedCode = outcome === "success" ? null : typeof code === "string" && CODE_RE.test(code) ? code : "UNKNOWN";
  const normalizedRequestId = typeof requestId === "string" && UUID_RE.test(requestId) ? requestId : null;

  return Object.freeze({
    schema: TELEMETRY_EVENT_SCHEMA,
    eventId: crypto.randomUUID(),
    networkId: config.networkId,
    identityId,
    mcpClient,
    tool,
    method,
    outcome,
    code: normalizedCode,
    latencyMs: Math.round(latencyMs),
    at,
    requestId: normalizedRequestId
  });
}

/* status -> outcome. Anything that is not a clean 2xx/4xx is treated as
 * "error" (fail toward reporting a problem, never silently "success"). */
function outcomeFor(status) {
  const s = Number(status);
  if (Number.isInteger(s) && s >= 200 && s < 300) return "success";
  if (Number.isInteger(s) && s >= 400 && s < 500) return "refusal";
  return "error";
}

/* ------------------------ per-process write bookkeeping ------------------------ */

/* Best-effort per-process event count, used only to enforce the defensive
 * hard cap cheaply (avoids a full store scan on every write). Lazily
 * initialized from a real count; incremented/decremented on writes/prunes.
 * Mirrors server/src/metrics.js's own per-process, restart-resets registry
 * posture — this is a defensive bound, not a strict consensus-grade limit. */
const countByConfig = new WeakMap();

async function currentCount(config) {
  let n = countByConfig.get(config);
  if (n === undefined) {
    n = (await getPlatformStore(config).listValues(Categories.MCP_TELEMETRY_EVENT)).length;
    countByConfig.set(config, n);
  }
  return n;
}
function bumpCount(config, delta) {
  const n = countByConfig.get(config);
  if (n !== undefined) countByConfig.set(config, Math.max(0, n + delta));
}

let writesSinceProbe = 0;
const PRUNE_EVERY_N_WRITES = 200;

/* Opportunistic, rate-limited retention sweep (never on every write — a
 * full store scan per request would be wasteful). pruneExpiredEvents
 * itself is separately exported/callable directly (operator tooling,
 * tests) for a deterministic, immediate sweep. */
async function maybePrune(config) {
  writesSinceProbe += 1;
  if (writesSinceProbe < PRUNE_EVERY_N_WRITES) return;
  writesSinceProbe = 0;
  try {
    await pruneExpiredEvents(config);
  } catch {
    /* never block a write on a failed prune */
  }
}

/* --------------------------------- record --------------------------------- */

/*
 * THE recording hook, called once per finished request from
 * server/src/api.js handle(). NEVER throws (telemetry must never fail or
 * delay the response it observes beyond a best-effort durable write).
 * Records ONLY when telemetry is enabled AND the resolved principal is a
 * machine credential (the "reaching the platform API through a machine
 * credential" scope of the spec) — wallet-session and unauthenticated
 * requests never produce a telemetry event.
 */
async function recordMcpToolInvocation(config, { principal, method, segments, status, code, requestId, latencyMs, mcpClientHeader }) {
  try {
    if (!telemetryEnabled()) return;
    if (!principal || principal.isMachine !== true || typeof principal.identityId !== "string") return;

    await maybePrune(config);
    const n = await currentCount(config);
    if (n >= maxStoredEvents()) return; // hard cap reached: drop silently (best-effort, per-process)

    const outcome = outcomeFor(status);
    const event = buildTelemetryEvent(config, {
      identityId: principal.identityId,
      mcpClient: parseMcpClientHeader(mcpClientHeader),
      tool: metricsRouteClass(method === "POST" ? "POST" : "GET", Array.isArray(segments) ? segments : []),
      method: method === "POST" ? "POST" : "GET",
      outcome,
      code: outcome === "success" ? null : typeof code === "string" ? code : null,
      latencyMs: Number.isFinite(latencyMs) && latencyMs >= 0 ? latencyMs : 0,
      at: new Date().toISOString(),
      requestId: typeof requestId === "string" ? requestId : null
    });

    const created = await getPlatformStore(config).createExclusive(Categories.MCP_TELEMETRY_EVENT, event.eventId, event);
    if (created) bumpCount(config, 1);
  } catch {
    /* telemetry must never fail a request */
  }
}

/* -------------------------------- retention -------------------------------- */

/*
 * Prune events older than the retention window. O(n) over the stored
 * category (the same "aggregate on read" posture the rest of this
 * codebase's platform-store consumers already accept — see
 * server/src/metrics.js's own honesty notes). Exported for direct,
 * deterministic use by operators/tests; also called opportunistically
 * (rate-limited) from recordMcpToolInvocation.
 */
async function pruneExpiredEvents(config, { nowMs = Date.now(), days } = {}) {
  const window = Number.isInteger(days) && days > 0 ? days : retentionDays();
  const cutoffMs = nowMs - window * 24 * 60 * 60 * 1000;
  const store = getPlatformStore(config);
  const all = await store.listValues(Categories.MCP_TELEMETRY_EVENT);
  let prunedCount = 0;
  for (const event of all) {
    if (!event || typeof event !== "object" || typeof event.eventId !== "string") continue;
    const t = Date.parse(event.at);
    if (!Number.isFinite(t) || t < cutoffMs) {
      const removed = await store.remove(Categories.MCP_TELEMETRY_EVENT, event.eventId);
      if (removed) prunedCount += 1;
    }
  }
  if (prunedCount > 0) bumpCount(config, -prunedCount);
  return { prunedCount, cutoffAt: new Date(cutoffMs).toISOString() };
}

/* -------------------------------- aggregates -------------------------------- */

function percentileOf(sortedAsc, p) {
  if (sortedAsc.length === 0) return null;
  const idx = Math.min(sortedAsc.length - 1, Math.floor((p / 100) * sortedAsc.length));
  return sortedAsc[idx];
}

/*
 * Build the aggregate document GET /api/v1/mcp-telemetry serves.
 * COMPUTED ON READ from the durable per-invocation event store — no
 * separate rollup state to keep consistent. Events older than the
 * retention window are excluded even if a prune sweep has not yet run
 * (defense in depth: the window is enforced both at read time and by
 * durable deletion). Numbers only, plus the non-secret identityId/tool/
 * mcpClient labels the events already carry — never a credential.
 */
async function buildTelemetryAggregate(config, { nowMs = Date.now() } = {}) {
  const days = retentionDays();
  const cutoffMs = nowMs - days * 24 * 60 * 60 * 1000;
  const day24hCutoff = nowMs - 24 * 60 * 60 * 1000;
  const day7dCutoff = nowMs - 7 * 24 * 60 * 60 * 1000;

  const store = getPlatformStore(config);
  const all = await store.listValues(Categories.MCP_TELEMETRY_EVENT);
  const events = [];
  for (const e of all) {
    if (!e || typeof e !== "object") continue;
    const t = Date.parse(e.at);
    if (Number.isFinite(t) && t >= cutoffMs) events.push({ ...e, __t: t });
  }

  const byIdentity = new Map(); // identityId -> { calls, firstSeenAt, firstT, lastSeenAt, lastT }
  const byTool = new Map();
  const byOutcome = { success: 0, refusal: 0, error: 0 };
  const byCode = new Map();
  const byClient = new Map();
  const byDay = new Map();
  const latencies = [];
  const active24h = new Set();
  const active7d = new Set();

  for (const e of events) {
    const identityId = typeof e.identityId === "string" ? e.identityId : "unknown";
    let idEntry = byIdentity.get(identityId);
    if (!idEntry) {
      idEntry = { calls: 0, firstSeenAt: e.at, firstT: e.__t, lastSeenAt: e.at, lastT: e.__t };
      byIdentity.set(identityId, idEntry);
    }
    idEntry.calls += 1;
    if (e.__t < idEntry.firstT) {
      idEntry.firstT = e.__t;
      idEntry.firstSeenAt = e.at;
    }
    if (e.__t > idEntry.lastT) {
      idEntry.lastT = e.__t;
      idEntry.lastSeenAt = e.at;
    }
    if (e.__t >= day24hCutoff) active24h.add(identityId);
    if (e.__t >= day7dCutoff) active7d.add(identityId);

    const tool = typeof e.tool === "string" ? e.tool : "other";
    byTool.set(tool, (byTool.get(tool) || 0) + 1);

    const outcome = OUTCOMES.includes(e.outcome) ? e.outcome : "error";
    byOutcome[outcome] += 1;
    if (outcome !== "success" && typeof e.code === "string") {
      byCode.set(e.code, (byCode.get(e.code) || 0) + 1);
    }

    const client = typeof e.mcpClient === "string" ? e.mcpClient : "unknown";
    byClient.set(client, (byClient.get(client) || 0) + 1);

    const day = typeof e.at === "string" && e.at.length >= 10 ? e.at.slice(0, 10) : "unknown";
    byDay.set(day, (byDay.get(day) || 0) + 1);

    if (Number.isFinite(e.latencyMs)) latencies.push(e.latencyMs);
  }
  latencies.sort((a, b) => a - b);

  return {
    schemaVersion: TELEMETRY_AGGREGATE_SCHEMA,
    generatedAt: new Date(nowMs).toISOString(),
    networkId: config.networkId,
    config: { enabled: telemetryEnabled(), retentionDays: days, maxStoredEvents: maxStoredEvents() },
    window: { retentionCutoffAt: new Date(cutoffMs).toISOString(), eventsInWindow: events.length, totalStored: all.length },
    identities: {
      distinct: byIdentity.size,
      activeLast24h: active24h.size,
      activeLast7d: active7d.size,
      firstLastSeen: [...byIdentity.entries()]
        .map(([identityId, v]) => ({ identityId, calls: v.calls, firstSeenAt: v.firstSeenAt, lastSeenAt: v.lastSeenAt }))
        .sort((a, b) => a.identityId.localeCompare(b.identityId))
    },
    callsPerDay: [...byDay.entries()].map(([date, count]) => ({ date, count })).sort((a, b) => a.date.localeCompare(b.date)),
    tools: { byTool: Object.fromEntries([...byTool.entries()].sort((a, b) => a[0].localeCompare(b[0]))) },
    outcomes: { ...byOutcome, byCode: Object.fromEntries([...byCode.entries()].sort((a, b) => a[0].localeCompare(b[0]))) },
    latencyMs: { count: latencies.length, p50: percentileOf(latencies, 50), p95: percentileOf(latencies, 95) },
    clients: { byClient: Object.fromEntries([...byClient.entries()].sort((a, b) => a[0].localeCompare(b[0]))) }
  };
}

/* test-only: reset per-process bookkeeping (cap override + write counters). */
function _resetForTests() {
  maxStoredEventsOverride = null;
  writesSinceProbe = 0;
}

module.exports = {
  TELEMETRY_EVENT_SCHEMA,
  TELEMETRY_AGGREGATE_SCHEMA,
  DEFAULT_RETENTION_DAYS,
  MAX_STORED_EVENTS,
  McpTelemetryError,
  telemetryEnabled,
  retentionDays,
  maxStoredEvents,
  parseMcpClientHeader,
  buildTelemetryEvent,
  outcomeFor,
  recordMcpToolInvocation,
  pruneExpiredEvents,
  buildTelemetryAggregate,
  _setMaxStoredEventsForTests,
  _resetForTests
};
