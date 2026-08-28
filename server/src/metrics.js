"use strict";

/*
 * OPERATIONAL OBSERVABILITY (fullscale surface 25; completion of the
 * /health/ready "surface 25 seam").
 *
 * A REAL metrics surface: in-process counters/histograms recorded by the
 * HTTP layer (server.js) plus scrape-time aggregates read from the durable
 * stores, exposed as
 *   GET /api/v1/metrics                    -> closed-schema JSON document
 *   GET /api/v1/metrics?format=prometheus  -> text exposition (hand-rolled,
 *                                             no dependencies)
 * and consumed by /health/ready for its events aggregate (ONE source).
 *
 * PRIVACY CONTRACT (enforced by the closed schema + the no-secret sweep in
 * sdk/test/postlaunch-observability-server.test.js): AGGREGATE NON-SECRET
 * NUMBERS ONLY. No tokens, no addresses, no x-only keys, no vault/org/
 * request/proposal/evaluation ids, no URLs, no per-tenant breakdowns.
 * Route labels come from a CLOSED route-class enumeration (never raw
 * paths, which can embed vault ids); refusal-code labels are the server's
 * own bounded error-code vocabulary, capped defensively.
 *
 * SCOPE: per-process (the launch pins a SINGLE app replica — the rate
 * limiter/semaphores/quotas are process-local for the same reason; a
 * second replica is gated behind the documented scaling gate, which now
 * includes aggregating this registry). Counters reset on restart —
 * standard Prometheus counter semantics (consumers use rate()/increase()).
 *
 * The node-gate section is PASSIVE observation: it records the outcome of
 * work the server already did against the trusted kaspad tier
 * (/network/status reads, submits, reconciles). A metrics scrape NEVER
 * dials the node (the same doctrine that keeps kaspad out of /health/ready
 * — an observability poll must not add node load or hang on an outage).
 */

const METRICS_SCHEMA = "policyvault-metrics/v1";

/* Closed route-class enumeration (label safety: never raw paths). */
const ROUTE_CLASSES = Object.freeze([
  "static",
  "capabilities",
  "health",
  "health.ready",
  "metrics",
  "auth",
  "identity.resolve",
  "identities",
  "vaults.list",
  "vaults.get",
  "vaults.status",
  "vaults.reconcile",
  "vaults.agent-suspensions",
  "manifests",
  "network.status",
  "audit",
  "support",
  "wallet.fuel",
  "wallet.v4.create",
  "wallet.v4.build",
  "wallet.v4.simulate",
  "wallet.v4.approvals",
  "wallet.v4.signature",
  "wallet.v4.submit",
  "wallet.v4.genesis-submit",
  "wallet.v4.reject",
  "wallet.v4.read",
  "wallet.legacy",
  "governance",
  "risk",
  "organizations",
  "events",
  "webhooks",
  "dev",
  "other"
]);
const ROUTE_CLASS_SET = new Set(ROUTE_CLASSES);

/* Duration histogram bucket bounds (ms), cumulative `le` semantics. */
const DURATION_BUCKETS_MS = Object.freeze([5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000, 30000]);

const MAX_REFUSAL_CODES = 256; // defensive label cap; overflow -> "_OTHER"
const MAX_REQUEST_SERIES = 2048; // routeClass x method x status combinations

/*
 * Classify an API request (segments AFTER /api/v1) into the closed route
 * class set. Deliberately parallel to limits.js classifyRoute (which
 * decides rate class + semaphore) but finer-grained for observability;
 * both are CLOSED maps and an unmapped route lands in "other", never a
 * raw path.
 */
function metricsRouteClass(method, segments) {
  const s0 = segments[0];
  if (s0 === "capabilities") return "capabilities";
  if (s0 === "health") return segments[1] === "ready" ? "health.ready" : "health";
  if (s0 === "metrics") return "metrics";
  if (s0 === "auth") return "auth";
  if (s0 === "identity") return "identity.resolve";
  if (s0 === "identities") return "identities";
  if (s0 === "support") return "support";
  if (s0 === "manifests") return "manifests";
  if (s0 === "network") return "network.status";
  if (s0 === "audit") return "audit";
  if (s0 === "events") return "events";
  if (s0 === "webhooks") return "webhooks";
  if (s0 === "governance") return "governance";
  if (s0 === "risk") return "risk";
  if (s0 === "organizations") return "organizations";
  if (s0 === "vaults") {
    if (segments.length === 1) return "vaults.list";
    if (segments[2] === "reconcile") return "vaults.reconcile";
    if (segments[2] === "status") return "vaults.status";
    if (segments[2] === "agent-suspensions") return "vaults.agent-suspensions";
    return "vaults.get";
  }
  if (s0 === "wallet") {
    const s1 = segments[1];
    if (s1 === "fuel") return "wallet.fuel";
    if (s1 === "dev-accounts" || s1 === "dev-sign") return "dev";
    if (s1 === "v4") {
      if (method === "GET") return "wallet.v4.read";
      if (segments[2] === "create") return "wallet.v4.create";
      if (segments[2] === "simulate") return "wallet.v4.simulate";
      if (segments[2] === "requests" && segments.length === 3) return "wallet.v4.build";
      const tail = segments[4];
      if (tail === "approvals") return "wallet.v4.approvals";
      if (tail === "signature") return "wallet.v4.signature";
      if (tail === "submit") return "wallet.v4.submit";
      if (tail === "genesis-submit") return "wallet.v4.genesis-submit";
      if (tail === "reject") return "wallet.v4.reject";
      return "other";
    }
    return "wallet.legacy";
  }
  return "other";
}

/* ------------------------- in-process registry ------------------------- */

function freshState() {
  return {
    startedAtMs: Date.now(),
    /* "routeClass|method|status" -> count */
    requestSeries: new Map(),
    requestOverflow: 0,
    /* routeClass -> { count, sumMs, buckets: number[] (le), inf } */
    durations: new Map(),
    /* refusal code -> count */
    refusals: new Map(),
    refusalOverflow: 0,
    nodeGate: { lastOkAtMs: null, lastFailAtMs: null, lastFailCode: null }
  };
}

let state = freshState();

function boundedMethod(method) {
  return method === "GET" || method === "POST" ? method : "OTHER";
}

/*
 * Record one finished API/static request. NEVER throws (observability
 * must never fail a request); every input is defensively normalized.
 * `code` is the machine-readable error code for status >= 400 (bounded
 * vocabulary — the server's own apiError codes).
 */
function recordApiRequest({ routeClass, method, status, durationMs, code }) {
  try {
    const rc = ROUTE_CLASS_SET.has(routeClass) ? routeClass : "other";
    const st = Number.isInteger(status) && status >= 100 && status <= 599 ? status : 0;
    const key = `${rc}|${boundedMethod(method)}|${st}`;
    if (state.requestSeries.has(key)) {
      state.requestSeries.set(key, state.requestSeries.get(key) + 1);
    } else if (state.requestSeries.size < MAX_REQUEST_SERIES) {
      state.requestSeries.set(key, 1);
    } else {
      state.requestOverflow += 1;
    }
    const ms = Number.isFinite(durationMs) && durationMs >= 0 ? durationMs : 0;
    let d = state.durations.get(rc);
    if (!d) {
      d = { count: 0, sumMs: 0, buckets: DURATION_BUCKETS_MS.map(() => 0), inf: 0 };
      state.durations.set(rc, d);
    }
    d.count += 1;
    d.sumMs += ms;
    let bucketed = false;
    for (let i = 0; i < DURATION_BUCKETS_MS.length; i++) {
      if (ms <= DURATION_BUCKETS_MS[i]) {
        d.buckets[i] += 1;
        bucketed = true;
        break;
      }
    }
    if (!bucketed) d.inf += 1;
    if (st >= 400 && typeof code === "string" && code.length > 0 && code.length <= 64) {
      if (state.refusals.has(code)) {
        state.refusals.set(code, state.refusals.get(code) + 1);
      } else if (state.refusals.size < MAX_REFUSAL_CODES) {
        state.refusals.set(code, 1);
      } else {
        state.refusalOverflow += 1;
      }
    }
  } catch {
    /* never throw */
  }
}

/* Passive node-gate observation (see the header). */
function noteNodeGate(ok, code) {
  try {
    if (ok) {
      state.nodeGate.lastOkAtMs = Date.now();
    } else {
      state.nodeGate.lastFailAtMs = Date.now();
      state.nodeGate.lastFailCode = typeof code === "string" && code.length <= 64 ? code : "UNKNOWN";
    }
  } catch {
    /* never throw */
  }
}

/* --------------------- scrape-time durable aggregates --------------------- */

/* Count records by a status-like string field — AGGREGATE numbers only. */
function countBy(rows, field) {
  const out = {};
  for (const r of rows) {
    if (!r || typeof r !== "object") continue;
    const v = typeof r[field] === "string" && r[field].length <= 32 ? r[field] : "UNKNOWN";
    out[v] = (out[v] || 0) + 1;
  }
  return out;
}

/*
 * The /health/ready events aggregate — the SAME numbers the metrics
 * document carries, from the SAME source (server/src/events.js eventStats,
 * which folds in the events-delivery.js per-endpoint delivery counters).
 * Extracted here so readiness and metrics can never drift apart.
 */
async function eventsAggregate(config) {
  const s = await require("./events").eventStats(config);
  return {
    activeEndpoints: s.endpoints.active,
    deadLettered: s.deadLettered,
    droppedEmissions: s.droppedEmissions,
    oldestUnprocessedMs: s.oldestUnprocessedMs
  };
}

/*
 * Build the full metrics document. Store reads are best-effort per
 * section: a failing durable read yields `null` for that section (the
 * scrape itself must never 500 because one aggregate is unavailable) —
 * honest partial data over a dead endpoint.
 */
async function buildMetricsDocument(config) {
  const doc = {
    schemaVersion: METRICS_SCHEMA,
    generatedAt: new Date().toISOString(),
    networkId: config.networkId,
    ...(config.buildId ? { buildId: config.buildId } : {}),
    process: {
      startedAt: new Date(state.startedAtMs).toISOString(),
      uptimeMs: Date.now() - state.startedAtMs,
      note: "per-process registry (single-replica launch pin); counters reset on restart"
    },
    requests: {
      series: [...state.requestSeries.entries()]
        .map(([key, count]) => {
          const [routeClass, method, status] = key.split("|");
          return { routeClass, method, status: Number(status), count };
        })
        .sort((a, b) => (a.routeClass + a.method + a.status).localeCompare(b.routeClass + b.method + b.status)),
      overflow: state.requestOverflow
    },
    durationsMs: [...state.durations.entries()]
      .map(([routeClass, d]) => ({
        routeClass,
        count: d.count,
        sumMs: Math.round(d.sumMs),
        buckets: DURATION_BUCKETS_MS.map((le, i) => ({ leMs: le, count: d.buckets[i] })).concat([{ leMs: null, count: d.inf }])
      }))
      .sort((a, b) => a.routeClass.localeCompare(b.routeClass)),
    refusals: {
      byCode: [...state.refusals.entries()].map(([code, count]) => ({ code, count })).sort((a, b) => a.code.localeCompare(b.code)),
      overflow: state.refusalOverflow
    },
    nodeGate: {
      lastOkAt: state.nodeGate.lastOkAtMs ? new Date(state.nodeGate.lastOkAtMs).toISOString() : null,
      lastFailAt: state.nodeGate.lastFailAtMs ? new Date(state.nodeGate.lastFailAtMs).toISOString() : null,
      lastFailCode: state.nodeGate.lastFailCode,
      note: "passive observation of real node work (network reads, submits, reconciles); a metrics scrape never dials the node"
    }
  };

  try {
    const s = await require("./events").eventStats(config);
    doc.events = {
      totalEvents: s.totalEvents,
      droppedEmissions: s.droppedEmissions,
      endpoints: s.endpoints,
      delivered: s.delivered,
      failed: s.failed,
      deadLettered: s.deadLettered,
      oldestUnprocessedMs: s.oldestUnprocessedMs
    };
  } catch {
    doc.events = null;
  }
  try {
    const { getStore, Categories } = require("../../sdk/src/store");
    const proposals = await getStore(config).listValues(Categories.GOVERNANCE_PROPOSAL);
    doc.governance = { proposalsByStatus: countBy(proposals, "status"), total: proposals.length };
  } catch {
    doc.governance = null;
  }
  try {
    const { getStore, Categories } = require("../../sdk/src/store");
    const evals = await getStore(config).listValues(Categories.RISK_EVALUATION);
    const byStatus = countBy(evals, "status");
    doc.risk = { evaluationsByStatus: byStatus, holdsOpen: byStatus.REVIEW_HELD || 0, total: evals.length };
  } catch {
    doc.risk = null;
  }
  try {
    const { Categories: PlatCategories, getPlatformStore } = require("./platform-store");
    const suspensions = await getPlatformStore(config).listValues(PlatCategories.AGENT_SUSPENSION);
    let vaultsWithSuspensions = 0;
    let allAgentsVaults = 0;
    let suspendedAgentEntries = 0;
    for (const r of suspensions) {
      if (!r || typeof r !== "object") continue;
      const hasAny = r.allAgents === true || (Array.isArray(r.agents) && r.agents.length > 0);
      if (hasAny) vaultsWithSuspensions += 1;
      if (r.allAgents === true) allAgentsVaults += 1;
      if (Array.isArray(r.agents)) suspendedAgentEntries += r.agents.length;
    }
    doc.agentSuspensions = { vaultsWithSuspensions, allAgentsVaults, suspendedAgentEntries };
  } catch {
    doc.agentSuspensions = null;
  }
  return doc;
}

/* ---------------------- Prometheus text exposition ---------------------- */

function promEscape(v) {
  return String(v).replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/\n/g, "\\n");
}

/* Hand-rolled exposition (text format 0.0.4) over the SAME document. */
function renderPrometheus(doc) {
  const lines = [];
  const push = (l) => lines.push(l);
  push("# HELP policyvault_requests_total Finished HTTP requests by closed route class, method, and status.");
  push("# TYPE policyvault_requests_total counter");
  for (const s of doc.requests.series) {
    push(`policyvault_requests_total{route="${promEscape(s.routeClass)}",method="${promEscape(s.method)}",status="${s.status}"} ${s.count}`);
  }
  push("# HELP policyvault_request_duration_ms Request duration histogram (ms) by closed route class.");
  push("# TYPE policyvault_request_duration_ms histogram");
  for (const d of doc.durationsMs) {
    let cumulative = 0;
    for (const b of d.buckets) {
      cumulative += b.count;
      const le = b.leMs === null ? "+Inf" : String(b.leMs);
      push(`policyvault_request_duration_ms_bucket{route="${promEscape(d.routeClass)}",le="${le}"} ${cumulative}`);
    }
    push(`policyvault_request_duration_ms_sum{route="${promEscape(d.routeClass)}"} ${d.sumMs}`);
    push(`policyvault_request_duration_ms_count{route="${promEscape(d.routeClass)}"} ${d.count}`);
  }
  push("# HELP policyvault_refusals_total Refused requests by machine-readable error code.");
  push("# TYPE policyvault_refusals_total counter");
  for (const r of doc.refusals.byCode) {
    push(`policyvault_refusals_total{code="${promEscape(r.code)}"} ${r.count}`);
  }
  if (doc.events) {
    push("# HELP policyvault_events_total Durable platform events appended to the outbox.");
    push("# TYPE policyvault_events_total counter");
    push(`policyvault_events_total ${doc.events.totalEvents}`);
    push("# HELP policyvault_event_emissions_dropped_total Event emissions dropped (emission failure isolation).");
    push("# TYPE policyvault_event_emissions_dropped_total counter");
    push(`policyvault_event_emissions_dropped_total ${doc.events.droppedEmissions}`);
    push("# HELP policyvault_webhook_deliveries_total Webhook delivery outcomes.");
    push("# TYPE policyvault_webhook_deliveries_total counter");
    push(`policyvault_webhook_deliveries_total{outcome="delivered"} ${doc.events.delivered}`);
    push(`policyvault_webhook_deliveries_total{outcome="failed"} ${doc.events.failed}`);
    push(`policyvault_webhook_deliveries_total{outcome="dead_lettered"} ${doc.events.deadLettered}`);
    push("# HELP policyvault_webhook_endpoints Webhook endpoints by state.");
    push("# TYPE policyvault_webhook_endpoints gauge");
    push(`policyvault_webhook_endpoints{state="active"} ${doc.events.endpoints.active}`);
    push(`policyvault_webhook_endpoints{state="total"} ${doc.events.endpoints.total}`);
    push("# HELP policyvault_event_outbox_oldest_unprocessed_ms Age of the oldest event not yet processed by every active endpoint.");
    push("# TYPE policyvault_event_outbox_oldest_unprocessed_ms gauge");
    push(`policyvault_event_outbox_oldest_unprocessed_ms ${doc.events.oldestUnprocessedMs === null ? 0 : doc.events.oldestUnprocessedMs}`);
  }
  if (doc.governance) {
    push("# HELP policyvault_governance_proposals Governance proposals by status.");
    push("# TYPE policyvault_governance_proposals gauge");
    for (const [status, count] of Object.entries(doc.governance.proposalsByStatus)) {
      push(`policyvault_governance_proposals{status="${promEscape(status)}"} ${count}`);
    }
  }
  if (doc.risk) {
    push("# HELP policyvault_risk_evaluations Risk evaluations by status.");
    push("# TYPE policyvault_risk_evaluations gauge");
    for (const [status, count] of Object.entries(doc.risk.evaluationsByStatus)) {
      push(`policyvault_risk_evaluations{status="${promEscape(status)}"} ${count}`);
    }
    push("# HELP policyvault_risk_holds_open Risk evaluations currently held for review.");
    push("# TYPE policyvault_risk_holds_open gauge");
    push(`policyvault_risk_holds_open ${doc.risk.holdsOpen}`);
  }
  if (doc.agentSuspensions) {
    push("# HELP policyvault_agent_suspensions Hosted-layer agent suspensions (coordination control, never covenant).");
    push("# TYPE policyvault_agent_suspensions gauge");
    push(`policyvault_agent_suspensions{kind="vaults_with_suspensions"} ${doc.agentSuspensions.vaultsWithSuspensions}`);
    push(`policyvault_agent_suspensions{kind="all_agents_vaults"} ${doc.agentSuspensions.allAgentsVaults}`);
    push(`policyvault_agent_suspensions{kind="suspended_agent_entries"} ${doc.agentSuspensions.suspendedAgentEntries}`);
  }
  push("# HELP policyvault_node_gate_last_ok_timestamp_seconds Last successful real node interaction (passive observation).");
  push("# TYPE policyvault_node_gate_last_ok_timestamp_seconds gauge");
  push(`policyvault_node_gate_last_ok_timestamp_seconds ${doc.nodeGate.lastOkAt ? Math.floor(Date.parse(doc.nodeGate.lastOkAt) / 1000) : 0}`);
  push("# HELP policyvault_node_gate_last_fail_timestamp_seconds Last failed real node interaction (passive observation).");
  push("# TYPE policyvault_node_gate_last_fail_timestamp_seconds gauge");
  push(`policyvault_node_gate_last_fail_timestamp_seconds ${doc.nodeGate.lastFailAt ? Math.floor(Date.parse(doc.nodeGate.lastFailAt) / 1000) : 0}`);
  push("# HELP policyvault_process_uptime_ms Process uptime.");
  push("# TYPE policyvault_process_uptime_ms gauge");
  push(`policyvault_process_uptime_ms ${doc.process.uptimeMs}`);
  return lines.join("\n") + "\n";
}

/* ------------------------ structured request log ------------------------ */

/*
 * One JSON line per finished request on stdout. DEFAULT ON; disable with
 * POLICYVAULT_REQUEST_LOG=0|off|false. Env-read per call (cheap, and lets
 * tests flip it without process restarts).
 *
 * PRIVACY: routeClass (closed set) — never the raw path (paths can embed
 * vault ids); principalType is the PRESENTED credential kind derived from
 * header PRESENCE only ("machine" for an Authorization header, "wallet"
 * for a cookie, "none") — never the credential, never a resolved
 * identity; code is the machine-readable refusal code. Nothing else.
 */
function requestLogEnabled() {
  const v = process.env.POLICYVAULT_REQUEST_LOG;
  return !(v === "0" || v === "off" || v === "false");
}

function logRequestLine({ routeClass, method, status, durationMs, principalType, code }) {
  try {
    if (!requestLogEnabled()) return;
    const line = {
      t: new Date().toISOString(),
      kind: "http",
      route: ROUTE_CLASS_SET.has(routeClass) ? routeClass : "other",
      method: boundedMethod(method),
      status: Number.isInteger(status) ? status : 0,
      ms: Number.isFinite(durationMs) ? Math.round(durationMs) : 0,
      principal: principalType === "machine" || principalType === "wallet" ? principalType : "none",
      ...(typeof code === "string" && code && status >= 400 ? { code } : {})
    };
    process.stdout.write(JSON.stringify(line) + "\n");
  } catch {
    /* logging must never fail a request */
  }
}

/* test-only: reset the in-process registry */
function _resetForTests() {
  state = freshState();
}

module.exports = {
  METRICS_SCHEMA,
  ROUTE_CLASSES,
  DURATION_BUCKETS_MS,
  metricsRouteClass,
  recordApiRequest,
  noteNodeGate,
  eventsAggregate,
  buildMetricsDocument,
  renderPrometheus,
  logRequestLine,
  requestLogEnabled,
  _resetForTests
};
