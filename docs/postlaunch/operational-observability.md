# Operational observability (fullscale surface 25)

**Status: IMPLEMENTED + UNIT-TESTED** (HTTP + API layers; release-
candidate lane — NOT part of the frozen production artifact
`phaseg-rc2`). Branch `fs-residuals`. Module: `server/src/metrics.js`;
instrumentation: `server/src/server.js`; route + readiness sourcing:
`server/src/api.js`. Tests:
`sdk/test/postlaunch-observability-server.test.js` (6/6 — real HTTP
server, driven-traffic accuracy, no-secret sweep, scope gating).

## 1. Surfaces

1. **`GET /api/v1/metrics`** — closed-schema JSON document
   (`policyvault-metrics/v1`):
   - `requests.series` — counters by CLOSED route class × method ×
     status (route classes are a fixed enumeration in metrics.js —
     never raw paths, which can embed vault ids; unmapped → `other`;
     defensive series cap with an overflow counter);
   - `durationsMs` — per-route-class histograms (fixed bucket bounds
     5ms…30s + Inf, count + sum);
   - `refusals.byCode` — refused requests by machine-readable error
     code (bounded vocabulary, capped, overflow bucket);
   - `events` — durable outbox + webhook delivery stats
     (`server/src/events.js eventStats`, which folds in the
     events-delivery.js per-endpoint counters): totalEvents,
     droppedEmissions, endpoints active/total, delivered / failed /
     deadLettered, oldestUnprocessedMs;
   - `governance.proposalsByStatus`, `risk.evaluationsByStatus` +
     `holdsOpen`, `agentSuspensions` — scrape-time AGGREGATE counts
     from the durable stores (numbers only; a failing store read yields
     `null` for that section, never a 500 scrape);
   - `nodeGate` — PASSIVE observation of real node work
     (/network/status reads; chain-proven submits): lastOkAt /
     lastFailAt / lastFailCode. **A metrics scrape never dials the
     node** (same doctrine that keeps kaspad out of /health/ready).
2. **`GET /api/v1/metrics?format=prometheus`** — hand-rolled text
   exposition (format 0.0.4; no dependencies) over the SAME document
   (`policyvault_requests_total`, `policyvault_request_duration_ms`
   histogram, `policyvault_refusals_total`,
   `policyvault_webhook_deliveries_total`, gauges). Unknown format
   values refuse (`BAD_FORMAT`).
3. **Structured request log** — ONE JSON line per finished request on
   stdout, DEFAULT ON; `POLICYVAULT_REQUEST_LOG=0|off|false` disables.
   Closed line shape: `{t, kind:"http", route, method, status, ms,
   principal, code?}` — `route` is the closed route class (never the
   raw path), `principal` is the PRESENTED credential TYPE derived from
   header presence only (`machine` | `wallet` | `none` — never the
   credential, never a resolved identity, never an address).
4. **`/health/ready`** now sources its events aggregate from
   `metrics.eventsAggregate` — the SAME function the metrics document
   uses, so readiness and metrics can never drift (tested for value
   agreement). Readiness semantics unchanged (stats failure never
   degrades readiness; kaspad still deliberately excluded).

## 2. Access model (honest)

- Self-hosted (tenancy off): open to the single local operator, like
  every route there.
- Hosted: an authenticated principal is REQUIRED (401 otherwise);
  machine credentials additionally need the deny-by-default
  `read:metrics` scope (403 `SCOPE_FORBIDDEN` without it). HONESTY
  NOTE (stated in the route comment): scopes narrow ONE credential's
  authority — any authenticated wallet could mint itself
  `read:metrics`, so the endpoint's privacy rests on the CLOSED
  AGGREGATE-ONLY schema (the same class of numbers the public
  /health/ready already exposes), not on the scope as a tenant
  boundary.

## 3. Privacy contract (tested no-secret sweep)

Neither the JSON document, nor the Prometheus text, nor any log line
may contain: vault ids (including ids embedded in request PATHS —
proven by driving `/vaults/<id>` and sweeping), wallet addresses,
x-only keys, machine tokens (`pvmk_`), or any 64-hex identifier (log
lines). Route labels and refusal codes are the only strings, both from
closed vocabularies.

## 4. Scope + limits (honest)

- Per-process registry: the launch pins a SINGLE app replica (the rate
  limiter/semaphores/quotas are process-local for the same reason).
  The documented scaling gate before any second replica now includes
  aggregating/functionally sharding this registry. Counters reset on
  restart — standard Prometheus counter semantics.
- `nodeGate` is passive: if no node-touching work happens, it stays
  null rather than fabricating a probe.
- Alerting/dashboards are operator tooling OUTSIDE the tree (the
  Prometheus exposition is the integration point); no alert rules ship
  here.
- Recording is failure-isolated: metrics/log recording never throws
  and can never fail a request.
