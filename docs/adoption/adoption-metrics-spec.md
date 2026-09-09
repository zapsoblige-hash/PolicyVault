# Adoption metrics: what PolicyVault can measure, and what it never collects

**Status: IMPLEMENTED · UNIT-TESTED. OFF by default. NOT enabled in
production.** This describes the real, closed-schema MCP usage telemetry
in `server/src/mcp-telemetry.js` (migration `010_mcp_telemetry.sql`) —
the only adoption-measurement mechanism that exists in PolicyVault today.
Enabling it anywhere is a separate, explicit deployment decision the
owner makes later; this document does not authorize that.

**Principle: MINIMIZED DISCLOSURE, NOT PRIVACY.** This is observability
data about API usage patterns, not a privacy guarantee — treat every
field below as what it is: a closed, deliberately small set of
operational facts, off by default.

## Scope: which requests can ever produce an event

Only requests that resolve to a **machine (AI/agent) credential
principal** — the same "programmatic caller authenticated with a bearer
token" surface the MCP adapter is one caller among several of (JS/Python
SDK clients, x402/AP2 adapters also qualify if they authenticate the same
way). A wallet-session (human, browser) request **never** produces a
telemetry event, enabled or not.

## The closed field set (exact, `policyvault-mcp-telemetry-event/v1`)

| field | what it is | what it is NOT |
|---|---|---|
| `identityId` | the machine identity's UUID | never the raw credential, never a hash of it |
| `mcpClient` | a normalized `<name>/<version>` display string from the caller-controlled `X-PolicyVault-MCP-Client` header, or the literal `"unknown"` if absent/malformed | never trusted for authorization; oversized or off-shape values are discarded to `"unknown"`, never rejected |
| `tool` | a closed route-class label (reused from the existing metrics enumeration) | never a raw URL path, never a query string |
| `method` | `GET` or `POST` | — |
| `outcome` | `success` \| `refusal` \| `error` (derived from the HTTP status class) | — |
| `code` | a closed refusal/error code, or `null` on success | never a free-text error message |
| `latencyMs` | request duration, rounded to the millisecond | — |
| `at` | an ISO-8601 timestamp | — |
| `requestId` | carried ONLY if it was already public in that same response body | never a new disclosure |

That is the entire schema (`EVENT_FIELDS` in `server/src/mcp-telemetry.js`
is enforced as closed — an unrecognized field throws, deny-by-default,
the same discipline the rest of the codebase's closed schemas use).

## What is NEVER collected — by construction, not by policy choice

An event is built by picking these exact fields one at a time from
validated inputs (`buildTelemetryEvent`) — never by spreading
caller-controlled input into storage. It is therefore structurally
impossible, not merely disallowed, for an event to carry:

- prompts or any AI model context;
- bearer tokens or any credential material, raw or hashed;
- private keys or wallet secrets;
- raw signing material — signatures, PSKTs, transaction bytes;
- request bodies, request parameters, or free-text error messages;
- IP addresses or any other network-identifying data;
- which specific vault, agent, recipient, or amount a call concerned.

## Configuration (closed, fail-closed)

| variable | default | effect |
|---|---|---|
| `POLICYVAULT_MCP_TELEMETRY` | unset (off) | must be `1`/`on`/`true` to record anything at all |
| `POLICYVAULT_MCP_TELEMETRY_RETENTION_DAYS` | 90 | 1–3650; out-of-range values fall back to the default, never fail open to "keep forever" |

When telemetry is off, **no events are ever built, stored, or served**,
and the aggregate read route (`GET /api/v1/mcp-telemetry`) does not
exist — it answers 404 `MCP_TELEMETRY_DISABLED`. Shipping this module
does not enable production telemetry.

## Storage and limits

- A dedicated, create-only platform-store category
  (`Categories.MCP_TELEMETRY_EVENT`) — JSON in self-hosted mode,
  PostgreSQL migration 010 in hosted mode, the same shape discipline as
  every other stored category.
- A hard per-process cap (`MAX_STORED_EVENTS`, default 100,000): once
  reached, new writes are silently dropped rather than growing storage
  unbounded — an opportunistic, non-guaranteed defensive bound, not a
  consensus-grade limit.
- Retention: events older than the configured window are pruned, both
  opportunistically on writes and on demand
  (`pruneExpiredEvents`), and excluded from the aggregate at read time
  even if a sweep hasn't run yet.
- Telemetry recording **never fails or delays** the request it observes
  — a failure inside the telemetry path is swallowed, never surfaced to
  the caller.

## The aggregate (`GET /api/v1/mcp-telemetry`, `read:metrics` scope —
same access model as `GET /metrics`, no new authority)

Computed on read from the durable event store; carries only counts,
labels already present on events, and latency percentiles:

- distinct identities, active-in-last-24h, active-in-last-7d;
- per-identity `calls` / `firstSeenAt` / `lastSeenAt`;
- calls per day;
- calls by tool (route class);
- outcomes (`success`/`refusal`/`error`) and, for non-success, counts by
  code;
- latency `p50`/`p95`;
- calls by `mcpClient` display string.

Nothing above identifies a vault, a spend, an amount, or a recipient —
the aggregate answers "how much is PolicyVault being used, by roughly
what kind of client, how healthily" and nothing about what any specific
call did.

## Why this maps to adoption evidence

Row U of `docs/postlaunch/flagship-readiness-matrix.md` (outside-user /
adoption evidence) is honestly `ABSENT` — no outside-user feedback has
been recorded yet. This telemetry mechanism exists so that, once real
outside usage occurs (registry listing, an MCP agent connecting, an x402
pilot), PolicyVault can measure adoption without adding any new
disclosure risk — the field set above was frozen before any real usage
data could exist.
