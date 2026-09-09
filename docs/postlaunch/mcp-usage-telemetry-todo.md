# MCP usage attribution / telemetry (Track 7)

**Status: IMPLEMENTED + UNIT-TESTED.** Module: `server/src/mcp-telemetry.js`
(schema, config gate, event builder, recorder, retention, aggregates);
storage: `server/src/platform-store.js` category `MCP_TELEMETRY_EVENT`
(migration `server/migrations/010_mcp_telemetry.sql`); wiring:
`server/src/api.js` `handle` (recording hook) and `GET /api/v1/mcp-telemetry`
(aggregate read route); client header: `mcp/src/http.js`. Tests:
`sdk/test/postlaunch-mcp-telemetry-server.test.js` (13 cases: OFF-by-default,
recording accuracy, header validation, schema-closed, privacy-negative byte
scan, aggregate fixture correctness, retention pruning, hard-cap, scope
reuse, capabilities reflection, plus a PostgreSQL section that skips
cleanly without `POLICYVAULT_TEST_PG_*`) and conformance scenario C21
(`conformance/agent-conformance.test.js`, real `mcp/server.js` subprocess
over real stdio JSON-RPC against the real server).

**NOT ENABLED IN PRODUCTION BY THIS WORK.** Recording defaults OFF
(`POLICYVAULT_MCP_TELEMETRY` unset/"off"). Turning it on for a live
deployment is a separate, explicit owner deployment decision — this
change ships the capability, not the activation.

**MINIMIZED DISCLOSURE, NOT PRIVACY.** This system deliberately records
*less* than it could (no prompts, no credentials, no signing material, no
bodies) — that is data minimization, a good practice. It is NOT an
anonymity or confidentiality guarantee: a stored event still names a real
machine identity, the tool it called, when, and how the call went. Anyone
who can read the aggregate (an owner-console-equivalent credential) can
see per-identity usage patterns. Treat this the same way the codebase
already treats the anonymous `/metrics` document and the audit trail:
useful operational visibility, not a security boundary, and never
confused with anonymized analytics.

## 1. What is recorded

One closed event per API call that resolves to a **machine (AI/agent)
credential principal** — the general "any programmatic caller
authenticated with a machine bearer token" surface (of which the MCP
adapter in `mcp/` is one caller among several: the JS/Python clients and
the x402/AP2 protocol adapters authenticate the same way). Recording
happens once, from the SAME single per-request principal-resolution
funnel `server/src/api.js` `handle` already uses for deny-by-default
scope gating — no new authentication path.

### Exact stored schema (`policyvault-mcp-telemetry-event/v1`)

```
{
  schema:      "policyvault-mcp-telemetry-event/v1",
  eventId:     "<uuid>",                 // store key
  networkId:   "<mainnet|testnet-10|...>",
  identityId:  "<uuid>",                 // the MACHINE IDENTITY — never the credential or its hash
  mcpClient:   "<name>/<version>" | "unknown",  // untrusted display string, see §2
  tool:        "<closed route-class label>",    // e.g. "vaults.list" — reuses server/src/metrics.js's enumeration
  method:      "GET" | "POST",
  outcome:     "success" | "refusal" | "error",
  code:        "<CLOSED_CODE>" | null,   // present only for refusal/error
  latencyMs:   <integer >= 0>,
  at:          "<ISO-8601>",             // server clock
  requestId:   "<uuid>" | null           // ONLY when already public in that same response body
}
```

The field list is CLOSED: `server/src/mcp-telemetry.js`'s `buildTelemetryEvent`
picks each field explicitly (never a spread of caller-controlled input)
and throws `MCP_TELEMETRY_EVENT_UNKNOWN_FIELD` on anything outside this
set — there is no code path that can widen it silently.

`outcome` is derived purely from the HTTP status the request actually
produced: 2xx → `success`, 4xx → `refusal`, anything else (5xx, or an
unclassifiable internal throw) → `error`. This mirrors the closed
refusal-code vocabulary `server/src/metrics.js` already uses.

## 2. `mcpClient` — the MCP adapter's own header

`mcp/src/http.js` adds one line: every outbound call from the MCP
adapter carries

```
X-PolicyVault-MCP-Client: <name>/<version>
```

taken directly from `mcp/package.json` (currently `policyvault-mcp/1.4.2`
— exactly the example in the original TODO). The server treats this
value as **untrusted display data only**:

- length-capped (160 bytes) and charset-validated
  (`^[name]/[version]$`, boring identifier characters only);
- an oversized, malformed, or absent header **never rejects the
  request** — it just records `mcpClient: "unknown"` (proven by a
  dedicated header-validation test);
- it is never used for authorization, routing, or any decision — only
  for the stored/aggregated display label.

Any other machine-credential caller (JS/Python client, x402/AP2 adapter,
a raw curl script) that never sends this header simply shows up as
`"unknown"` in the client/version distribution.

## 3. Privacy contract (binding, enforced by construction)

Never recorded, in any stored event, under any circumstance: prompts or
model context; bearer tokens or any credential material (raw or hashed);
private keys; wallet secrets; raw signing material (signatures, PSKTs,
transaction bytes); full request bodies; unnecessary wallet addresses;
private policy contents.

This is enforced structurally, not by a denylist scan: `buildTelemetryEvent`
only ever receives the nine fields above, explicitly extracted at the call
site (`server/src/api.js` `recordMcpTelemetrySafe`) — the request body,
the `Authorization` header value, and any other request material are
simply never passed in, so there is no code path by which they could
reach storage. The `requestId` field is the one exception carrying
caller-adjacent data, and only when it was **already public** in that
same response body (e.g. a wallet-request id the route already returned)
— never a new disclosure.

The unit suite includes a dedicated privacy-negative test: a real HTTP
request carrying a real bearer token, a fake signature, a fake
transaction hex, and a marker string in the body is sent through the
real server with telemetry ON, and the test then scans the raw bytes of
every stored telemetry file/row for all four secrets — asserting none
appear.

## 4. Config gate

`POLICYVAULT_MCP_TELEMETRY` — unset or `"off"` (default): **no events
are built, no storage is touched, and `GET /api/v1/mcp-telemetry` does
not exist** (404 `MCP_TELEMETRY_DISABLED`). Set to `"1"`, `"on"`, or
`"true"` to enable. Read fresh from `process.env` on every call (cheap;
lets an operator flip it without a process restart in a supervised
environment that re-execs, and lets tests toggle it without reloading
config).

`POLICYVAULT_MCP_TELEMETRY_RETENTION_DAYS` — optional integer override,
default **90 days**, clamped to `[1, 3650]`; an out-of-range or malformed
value falls back to the default rather than failing closed (retention is
a housekeeping knob, not a security gate).

## 5. Storage

New CREATE-ONLY platform-store category (`server/src/platform-store.js`
`Categories.MCP_TELEMETRY_EVENT`; JSON backend: one file per event under
`platform/mcp-telemetry-events/`; PostgreSQL backend: table
`mcp_telemetry_events`, migration `010_mcp_telemetry.sql`) — the SAME
`(network_id, key)` jsonb shape discipline every other category table in
this codebase uses, keyed by `eventId`. Retention and a defensive
per-process hard cap (100,000 events; test-overridable) are enforced in
`mcp-telemetry.js`, not by the schema — this is honestly documented as
best-effort observability data (the same "aggregate on read, per-process
registry" posture `server/src/metrics.js` already uses), never
consensus/financial state.

`pruneExpiredEvents(config, opts)` deletes events older than the
retention window; it runs opportunistically (rate-limited, every ~200th
write) from the recording hook and is separately exported for direct,
deterministic operator/test use.

## 6. Aggregate read endpoint

`GET /api/v1/mcp-telemetry` — computed on read from the durable
per-invocation event store (no separate rollup to keep in sync).
Schema `policyvault-mcp-telemetry-aggregate/v1`:

```
{
  schemaVersion, generatedAt, networkId,
  config:      { enabled, retentionDays, maxStoredEvents },
  window:      { retentionCutoffAt, eventsInWindow, totalStored },
  identities:  { distinct, activeLast24h, activeLast7d,
                 firstLastSeen: [{ identityId, calls, firstSeenAt, lastSeenAt }] },
  callsPerDay: [{ date, count }],
  tools:       { byTool: { "<tool>": count } },
  outcomes:    { success, refusal, error, byCode: { "<CODE>": count } },
  latencyMs:   { count, p50, p95 },
  clients:     { byClient: { "<name>/<version>|unknown": count } }
}
```

**Access model — no new authority, no new scope.** The route reuses the
EXACT same gate `GET /api/v1/metrics` already uses: self-hosted mode is
open to the single local operator; hosted mode requires an authenticated
principal, and a machine credential additionally needs the existing
`read:metrics` scope (`server/src/scopes.js`). This is a deliberate
choice, not an oversight: MCP usage telemetry is operationally the same
kind of "how is my deployment being used" question `/metrics` already
answers for anonymous traffic, so it is gated the same way the owner
console already gates that class of read.

When `POLICYVAULT_MCP_TELEMETRY` is off, the route does not exist at
all (404 `MCP_TELEMETRY_DISABLED`) — this check runs before any scope
check for a wallet-session caller, and (for a machine credential) after
the existing scope gate, matching how every other feature-flagged route
in this codebase (e.g. the dev-signer routes) already layers its own
enabled-check under the standard auth/scope gates.

## 7. What this is NOT

- **Not authority.** Exactly like the events/webhooks/audit-chain
  surfaces, telemetry is observation. It cannot grant, verify, or modify
  anything; a total telemetry outage must never (and, by construction,
  cannot) affect request processing — every write is wrapped in
  failure-isolated try/catch at two layers (the module itself, and the
  `api.js` call site) and never throws.
- **Not the audit trail.** The existing hash-chained audit store already
  carries request-level financial facts; telemetry does not duplicate
  them — it attributes USAGE (who called what, how often, how it went),
  never transaction content.
- **Not anonymized analytics.** See "MINIMIZED DISCLOSURE, NOT PRIVACY"
  above.
- **Not a workflow-sequence tracker (yet).** The "intended aggregates"
  list in the original TODO included workflow counts (e.g. capabilities
  → list vaults → build → sign-ready sequences); this v1 intentionally
  ships the flat per-call aggregates only. Sequence mining is a natural,
  purely additive follow-up over the same event stream and is not
  blocked by anything built here.

## 8. Original design intent (preserved for history)

```
MCP client/version → machine identity → tool/action → success/refusal/error → latency → timestamp
```

This is the exact shape implemented above; nothing in the original
minimum-event-schema or privacy-constraints sections (owner directive
2026-09-03 §J) was weakened to ship it.
