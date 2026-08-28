# PolicyVault Signed Webhooks + Asynchronous Events — Specification

Status: IMPLEMENTED (surface 18 of `FULLSCALE_COMPLETION_ADDENDUM.md`,
feeding surface 25 monitoring). Source of truth: `server/src/events.js`,
`events-store.js`, `webhooks.js`, `events-signing.js`,
`events-delivery.js`, migration `server/migrations/006_events_webhooks.sql`.
Test evidence: `sdk/test/postlaunch-webhooks-events.test.js` (13),
`postlaunch-webhooks-delivery.test.js` (9), `postlaunch-webhooks-pg.test.js`
(3, PG-gated).

## 1. Trust model — events are OBSERVATION, never authority

Every event is a **notification that durable PolicyVault state changed**.
It is NEVER a source of truth and confers NO authority:

- The truth about hosted state lives at the PolicyVault API (re-read it).
- The truth about anything consensus-visible lives at the Kaspa covenant.
- No PolicyVault component consumes webhook data as input to any
  decision. Deliveries are fire-and-forget; consumer **responses are
  size-capped, drained, and discarded — never parsed** as data or
  instructions (`events-delivery.js`).
- Every signed payload embeds this notice verbatim (`notice` field), so a
  consumer cannot honestly mistake a webhook body for authority:

  > "This event is a notification of durable PolicyVault state. It is not
  > authority: verify current state via the PolicyVault API; Kaspa
  > covenant consensus remains the only financial authority."

**Degradation guarantee (binding addendum rule):** the entire
events/webhooks subsystem is failure-isolated from core request
processing. Emission never throws into a request path (a broken event
store loses the notification, never the mutation — tested); the delivery
worker is a decoupled timer loop whose absence, crash, or shutdown leaves
every API surface intact (tested by killing it).

## 2. Storage: the durable outbox

Events append to `platform_events` (PostgreSQL, bigserial `id` = append
order = cursor; `UNIQUE (network_id, event_id)`) or to the NDJSON stream
`<dataRoot>/platform/events/stream.log` (JSON backend parity — the audit
JSONL idiom, process-local monotonic `seq`). Cursors are **opaque decimal
strings**; clients only echo values the API returned. JSON-backend seq
assignment assumes one server process per data root — exactly the
released self-hosted shape; hosted deployments run PostgreSQL, where the
database arbitrates. Emission is a single atomic append per event; it
happens at the same call sites as (and immediately after) the audit
write, sharing the audit stream's documented crash-window semantics: a
crash between mutation and notification loses the notification, never
the mutation.

## 3. Event envelope — `policyvault-event/v1`

```json
{
  "schemaVersion": "policyvault-event/v1",
  "eventId": "9be4…-uuid",
  "type": "request.built",
  "occurredAt": "2026-08-26T12:00:00.000Z",
  "networkId": "testnet-10",
  "vaultId": "64-hex | null",
  "orgId": "uuid | null",
  "correlation": { "requestId": "…", "manifestHash": "…", "proposalId": "…",
                    "riskEvaluationId": "…", "txId": "…", "identityId": "…" },
  "data": { "…closed per-type fields only…" }
}
```

- `eventId` is the **consumer-side dedup key** (at-least-once delivery).
- `correlation` carries only the ids present for that event — the same
  ids the audit-correlation spec uses, so a consumer can join events to
  audit rows, manifests, proposals, risk evidence, and txids.
- `data` is a **closed per-type field list** (`events.js` EVENT_TYPES).
  Undeclared fields are dropped at emission; unknown types refuse.
  **No secrets, no tokens, no signatures, no preimages, no key material**
  beyond public identities the same tenant can already read via the API.

## 4. Event catalog (closed; unknown types fail closed)

### 4.1 Wallet-request lifecycle (v0.4 family)

| type | data | emitted when |
|---|---|---|
| `request.built` | action, contractVersion, state, aboveThreshold, signerRole | a durable, intent-verified request exists (create + transition builds) |
| `request.approval.collected` | action, collected, required, complete | an approver signature was accepted |
| `request.finalized` | action, state | owner/agent signature attached; VM preflight passed |
| `request.confirmed` | action, state, terminal | submit succeeded — **which in this pipeline means chain proof**: txid verified, predecessor consumed, exact successor observed |
| `request.failed` | action, stage (`intent`\|`finalize`\|`submit`\|`genesis-submit`), code | a durable request's finalize/submit/intent gate refused |
| `request.rejected` | action, state | the signer declined in the wallet / cancelled |

**There is deliberately NO "submitted but unproven" success event.**
`submitTransaction()` returning is not success in PolicyVault; the event
stream refuses to claim an unproven broadcast. A crash-after-broadcast
surfaces later through reconciliation (`vault.reconciled`). Legacy v0.2
routes emit no events (documented limitation; poll `/audit` for those).

### 4.2 Vault lifecycle

| type | data |
|---|---|
| `vault.created` | contractVersion, label — genesis chain-proven |
| `vault.reconciled` | outcome (reconciler status: CONSISTENT / CLAIM_PENDING / CLAIM_RELEASED / ADVANCED / TERMINAL / UNKNOWN…), to |

### 4.3 Governance and risk (hosted coordination plane)

`governance.proposal.created` / `.approved` / `.cancelled` / `.consumed`,
`governance.reduction.recorded`; `risk.evaluation.allowed`,
`risk.hold.created`, `risk.evaluation.denied`, `risk.hold.released`,
`risk.evaluation.consumed` (data: action, decision where applicable).
Derived from the server audit hook (§5) and the risk consumption point.

### 4.4 Machine identities and organization controls

`identity.created` (label, scopes, creatorXOnly), `identity.revoked`,
`identity.credential.minted` / `.revoked` (credentialId, creatorXOnly) —
**never token or hash material** — and `org.controls.updated` (summary).

### 4.5 Hosted-layer agent suspensions (surface 21 residual)

`vault.agent.suspended` / `vault.agent.unsuspended` (agentPk?, allAgents,
byType — the mutating principal's TYPE only). Emitted directly by the
`/vaults/:id/agent-suspensions` route (like the identity events). These
notify a COORDINATION control — never a covenant state change: the
standing NOTIFICATION_NOTICE applies with full force, and the suspension
itself is documented in `docs/postlaunch/hosted-agent-suspend.md` as NOT
a covenant control.

## 5. Emission hook points

All server-side audit writes flow through `server/src/audit.js`
(= sdk audit + `events.js noteAuditRecord`, a CLOSED audit→event mapping:
unmapped audit kinds/results publish nothing). Transitions the sdk
records internally (submit chain proof, reconciliation) are emitted at
their API routes — the server's observation point. Emission is
failure-isolated everywhere (`safeEmitPlatformEvent` never throws).

## 6. Subscriptions (webhook endpoints)

Routes (scope-gated for machine identities per `scopes.js`; wallet
sessions use normal tenancy; self-hosted single operator needs neither):

- `POST /api/v1/webhooks` `{ url, eventTypes?, label? }` → 201 with the
  endpoint and **the signing secret, shown exactly once** (`pvwh_` +
  64 hex). `eventTypes` is `["*"]` (default) or a subset of the catalog.
- `GET /api/v1/webhooks` — own endpoints (never secrets).
- `GET /api/v1/webhooks/:id` — endpoint + delivery monitoring: durable
  cursor, counters (delivered/failed/deadLettered), bounded
  recent-attempt log, dead letters.
- `POST /api/v1/webhooks/:id/rotate-secret` — new secret (shown once);
  the previous secret co-signs deliveries for a 24 h grace window.
- `POST /api/v1/webhooks/:id/revoke` — terminal disable.

Scopes: `webhooks:manage` (all endpoint routes), `read:events`
(polling). Tenancy: an endpoint belongs to its creating wallet
(`creatorXOnly`) and receives ONLY events that wallet could read via the
API (§10); foreign endpoints 404. Quota: 20 active endpoints per wallet.
Machine credentials inherit exactly their creating wallet's tenancy;
granting `webhooks:manage` deliberately lets that credential point
deliveries of that same data at a URL — an operator decision,
deny-by-default like every scope.

URL rules: `https://` only; no userinfo; ≤2000 chars. The explicit
development override `POLICYVAULT_WEBHOOK_ALLOW_INSECURE_LOCAL=1`
additionally permits `http://` to loopback hosts only and is never
honored on mainnet.

`POST /webhooks` and `rotate-secret` are **excluded from Idempotency-Key
response persistence** (the recorded response would contain the one-time
secret). Consequence: replaying such a POST with the same key creates a
second endpoint rather than replaying the first response — the
deliberate, safer tradeoff.

## 7. Secret storage — the honest tradeoff

HMAC signing requires the raw secret server-side at every delivery, so
the hash-at-rest discipline used for sessions and machine credentials is
**structurally impossible** here. PolicyVault stores each secret as a
versioned envelope in the single restricted `webhook_endpoints` category:

- **`aes256gcm/v1`** when the operator sets
  `POLICYVAULT_WEBHOOK_SECRET_KEY` (64-hex, 32 bytes): AES-256-GCM with a
  random 96-bit IV. Threat honestly covered: database dumps/backups and
  DB-only compromise (the hosted managed-PG backup surface). Threat NOT
  covered: full application-host compromise — the key lives beside the
  process; no at-rest scheme can protect a secret the process must use.
- **`plain/v1`** otherwise (self-hosted default): plaintext inside that
  one category, documented as such; filesystem permissions (0700/0600)
  are the boundary, as for the rest of the data root.

Unknown envelope versions, a missing key, or failed authenticated
decryption **fail closed** (`WEBHOOK_SECRET_UNAVAILABLE`): deliveries for
that endpoint fail with a recorded attempt error; there is never a
plaintext fallback or guessed key. Rotation support: `rotate-secret`
(§6) with dual-signature grace (§8).

## 8. Signing scheme `pv1` + consumer verification recipe

Request headers on every delivery:

```
X-PolicyVault-Signature:  v=pv1,t=<unixSeconds>,s=<hexHmac>[,s=<hexHmac>]
X-PolicyVault-Event-Id:   <eventId>          (dedup key)
X-PolicyVault-Delivery-Id:<deliveryId>       (stable per endpoint×event)
User-Agent:               PolicyVault-Webhooks/1
Content-Type:             application/json
```

`s = HMAC-SHA256(secret, "<t>.<rawBody>")` over the **exact raw request
body bytes**. Two `s=` entries appear during secret rotation (current
secret first, previous during its grace window) — verify against the one
secret you hold. Reference implementation (tested):
`server/src/events-signing.js verifyWebhookSignature`.

**Consumer recipe (all three steps are mandatory):**

1. **Authenticate:** recompute `HMAC-SHA256(yourSecret, t + "." + rawBody)`
   and compare constant-time against every `s=` entry; reject unless one
   matches (`SIGNATURE_MISMATCH`). Reject any `v=` other than `pv1`
   (`UNSUPPORTED_SCHEME` — never ignore an unknown scheme). Use the raw
   received bytes; never re-serialize JSON before verifying.
2. **Bound replay in time:** reject unless `|now − t| ≤ 300` seconds
   (`TIMESTAMP_OUT_OF_TOLERANCE`). A captured delivery cannot be
   replayed outside the window even with a valid signature.
3. **Dedup:** track processed `X-PolicyVault-Event-Id` values (at least
   across the tolerance window) and skip repeats — at-least-once
   delivery makes legitimate redeliveries of the same eventId normal.

```js
const crypto = require("crypto");
function verifyPolicyVaultWebhook({ header, rawBody, secret,
    nowSeconds = Math.floor(Date.now() / 1000), toleranceSeconds = 300 }) {
  let version = null, timestamp = null; const signatures = [];
  for (const part of String(header ?? "").split(",")) {
    const eq = part.indexOf("="); if (eq < 1) return { ok: false, reason: "MALFORMED_HEADER" };
    const k = part.slice(0, eq).trim(), v = part.slice(eq + 1).trim();
    if (k === "v") version = v; else if (k === "t") timestamp = v; else if (k === "s") signatures.push(v);
  }
  if (version !== "pv1") return { ok: false, reason: "UNSUPPORTED_SCHEME" };
  if (!/^\d{1,12}$/.test(timestamp ?? "") || !signatures.length) return { ok: false, reason: "MALFORMED_HEADER" };
  const expected = crypto.createHmac("sha256", secret).update(`${timestamp}.${rawBody}`, "utf8").digest();
  const matched = signatures.some((s) => /^[0-9a-f]{64}$/.test(s) &&
    crypto.timingSafeEqual(Buffer.from(s, "hex"), expected));
  if (!matched) return { ok: false, reason: "SIGNATURE_MISMATCH" };
  if (Math.abs(nowSeconds - Number(timestamp)) > toleranceSeconds)
    return { ok: false, reason: "TIMESTAMP_OUT_OF_TOLERANCE" };
  return { ok: true }; // then: dedup on X-PolicyVault-Event-Id, and treat the body as a notification only
}
```

Delivered body — `policyvault-webhook/v1`:

```json
{ "schemaVersion": "policyvault-webhook/v1", "deliveryId": "…",
  "endpointId": "…", "attempt": 1, "sentAt": "…", "notice": "…(§1)…",
  "event": { …policyvault-event/v1… } }
```

## 9. Delivery semantics (documented honestly)

- **At-least-once.** The durable per-endpoint cursor advances only after
  a 2xx response; a crash between response and cursor write redelivers
  the same `eventId`. Success is 200–299 only.
- **Ordered per endpoint.** One in-flight event per endpoint; the cursor
  is strictly monotonic. Consequence: a failing head event blocks that
  endpoint's stream until it dead-letters — bounded by
  maxAttempts (8) × the backoff schedule (1 s, 5 s, 25 s, 2 m, 10 m,
  30 m, 1 h; ≈ 1 h 43 m worst case), never other endpoints or the API.
- **Dead-letter.** After 8 failed attempts the event is recorded in
  `webhook_dead_letters` (with the full envelope, last status/error) and
  the cursor advances past it. Dead letters are never auto-retried;
  recover via `GET /webhooks/:id` (inspect) + polling (§11) to re-read
  the events. Retention: newest 200 per endpoint.
- **Filters are evaluated at delivery time, once.** Events excluded by
  the type filter or the tenant-visibility rule are skipped permanently
  for that endpoint (later visibility changes do not resurrect skipped
  events — poll for history).
- **New endpoints start at the stream head** (no historical flood);
  history is served by polling.
- Outbound hardening: DNS resolved once per attempt and the answer
  validated against loopback/private/link-local/CGNAT/reserved/mapped
  ranges then pinned for the connection (SSRF + rebinding); redirects
  are never followed (3xx = failure); strict 10 s per-attempt timeout;
  response bodies capped at 8 KiB, drained, discarded.
- The worker runs inside the existing server process (no new infra),
  starts after the listener, and can be disabled with
  `POLICYVAULT_WEBHOOK_DELIVERY=0` (interval:
  `POLICYVAULT_WEBHOOK_INTERVAL_MS`, default 2000).

## 10. Tenancy

Event visibility uses exactly the hosted global audit feed's derivation
(`events.js eventVisibleTo`): vault events require covenant participation
in that vault (read), org events require org membership, identity events
require the creating wallet; anything else is invisible (**default
deny**). Self-hosted mode (tenancy disabled) exposes the whole stream to
the single local operator. Both the polling route and the delivery
scanner apply the same rule; hostile cross-tenant reads are tested.

## 11. Polling fallback

`GET /api/v1/events?cursor=&limit=&types=a,b` — the same stream,
tenant-scoped, for integrators without webhook receivers (and for the
conformance suite). Response `policyvault-events-page/v1`:
`{ notice, events: [{ cursor, event }], nextCursor, latestCursor }`.
Resume by echoing `nextCursor`; unknown types 422; malformed cursors 400
(fail closed); limit ≤ 500.

## 12. Monitoring (surface 25 seam)

`events.js eventStats(config)` returns aggregate numbers: totalEvents,
droppedEmissions (process-local count of isolated emission failures),
endpoint counts, delivered/failed/deadLettered, oldestUnprocessedMs (age
of the oldest event not yet processed for some active endpoint —
pre-filter, so it is an upper bound). `/health/ready` surfaces
`events: { activeEndpoints, deadLettered, droppedEmissions,
oldestUnprocessedMs }` — non-secret numbers only, computed best-effort,
**never load-bearing for readiness**. A full metrics endpoint is a later
surface; `eventStats` is its clean seam.

## 13. Adversarial coverage (addendum "malicious webhook data" target)

Tested: forged/tampered payload rejection via the consumer recipe;
scheme-downgrade rejection; replay-window rejection; eventId dedup path;
cross-tenant event leakage (polling + delivery filter); secret exposure
(never in listings/reads/logs/idempotency records; encrypted-at-rest
option; wrong-key fail-closed); malicious consumer responses (huge
bodies capped/discarded, never parsed; timeouts; redirects never
followed); SSRF/rebinding target guard; delivery-loop kill/crash
isolation from the API; emission-crash consistency; hostile cursors;
unknown event types/versions failing closed everywhere.
