# Hosted Request Protection (Phase D)

**Status: IMPLEMENTED + ADVERSARIALLY TESTED (Hosted Web Architecture +
Security checkpoint, Phase D, 2026-08-24). Nothing here is deployed;
hosted deployment remains a separate owner gate.** Companion documents:
`docs/hosted-architecture.md` (§4 same-origin model, §10 headers, §11
rate limiting), `docs/hosted-threat-model.md` (gap 4 → closed by this
phase), `docs/hosted-persistence.md` (Phase C).

Scope rule: **none of this is the funds-security boundary** — Kaspa
consensus is. This layer bounds abuse of the hosted HTTP surface (CSRF,
DNS rebinding, floods, slow clients, resource exhaustion) and its
refusals are PURE: every refusal happens before any durable mutation,
so a throttled or refused request never touches manifests, requests,
claims, or covenant state. A throttled submission keeps its claims
exactly as an ambiguous submission does; reconcile remains the recovery
path.

Implementation: `server/src/limits.js` (verification, limiter,
semaphores, classification, depth cap), wired in `server/src/server.js`;
quotas and listing clamps in `server/src/api.js`; configuration in
`sdk/src/config.js` (`config.requestProtection`, all validated,
fail-closed).

## 1. Modes

| Posture | Self-hosted (authMode disabled — the released product) | Hosted (authMode enabled) |
|---|---|---|
| Origin gate | RELEASED semantics preserved exactly: no-Origin tools pass; loopback browser Origin matching Host passes; foreign Origin 403 | Application-origin enforcement (below); no off-switch |
| Host validation | NEW rebinding guard: loopback-family Hosts (any port) pass; missing Host tolerated (HTTP/1.0 tooling on the loopback-bound listener); any other Host 421 | Host REQUIRED; must be loopback-family or on the allowlist (the appOrigin host + explicit `POLICYVAULT_EXTRA_HOSTS`) |
| Rate limits | OFF by default (released behavior); explicitly enableable (`POLICYVAULT_RATE_LIMITS=1` / override) | ALWAYS ON — `POLICYVAULT_RATE_LIMITS=0` refuses to start (fail closed) |
| Semaphores | ACTIVE (generous defaults — a wedged RPC pile-up is a real self-hosted failure mode too) | ACTIVE |
| Slow-client deadlines | ACTIVE | ACTIVE |
| Open-request quota | ACTIVE (generous defaults) | ACTIVE |

The self-hosted DNS-rebinding Host guard is the one deliberate
self-hosted behavior addition: the released deployment model is
loopback/single-operator and the listener binds 127.0.0.1 only, so no
legitimate client presents a non-loopback Host — but a DNS-rebinding
page (attacker's domain re-pointed at 127.0.0.1) does, and could
otherwise READ API responses cross-origin (rebinding bypasses SOP;
CORS absence does not help because the browser considers the origin to
be the attacker's own). A reverse-proxy operator who fronts the
self-hosted server with a real hostname sets `POLICYVAULT_EXTRA_HOSTS`.

## 2. Origin verification (CSRF wall #2)

Wall #1 is the `SameSite=Strict` HttpOnly session cookie (Phase B).
Wall #2, enforced on every state-changing request (non-GET/HEAD/OPTIONS)
in hosted mode:

- `Origin` present → must equal the configured application origin
  (`config.appOrigin`) exactly by URL origin. `Origin: null` (opaque)
  and malformed values refuse. A mismatched Origin is NEVER rescued by
  Sec-Fetch-Site.
- `Origin` absent → the request must carry
  `Sec-Fetch-Site: same-origin`; otherwise 403 `ORIGIN_REQUIRED`.
  Browsers send these headers automatically; PROGRAMMATIC hosted
  clients must set `Origin: <appOrigin>` explicitly (the error message
  says so). This is deliberately strict/fail-closed: the header is
  trivial for a legitimate tool and free for the browser.
- Loopback allowance: an Origin whose hostname is loopback and whose
  host:port equals the request's Host header passes (exactly the
  released self-hosted rule). This keeps machine-local hosted
  simulation and the test harness working; in production topology
  (Cloudflare Tunnel, no public inbound port) a request presenting
  loopback Origin+Host can only come from inside the box.

GET/HEAD/OPTIONS are never Origin-gated: reads are side-effect-free by
API discipline, and the response is unreadable cross-origin because the
API sends NO CORS headers (the permanent loopback-CORS lesson).

## 3. Host validation (DNS-rebinding guard)

All surfaces (API and static), both modes: a present Host must be
loopback-family (`127.0.0.1` / `localhost` / `[::1]`, any port) or on
the allowlist; otherwise **421 HOST_FORBIDDEN**. Hosted mode requires
the header (400 `HOST_REQUIRED` without it). The allowlist is built at
config time: the application origin's host plus validated
`POLICYVAULT_EXTRA_HOSTS` entries (an explicit operator act, e.g. an
in-VPC probe hostname). Malformed Host values (credentials, paths,
overlong strings) refuse.

## 4. Client IP and the trusted proxy header (boundary B2)

Rate-limit keys use the socket address by default. Behind Cloudflare
Tunnel every socket is local, so the operator may set
`POLICYVAULT_TRUSTED_PROXY_HEADER` to exactly one of
`cf-connecting-ip` / `x-real-ip` (single-value headers only —
`x-forwarded-for` chains are refused at config time). The header is
believed ONLY when configured; a missing/malformed value falls back to
the socket address (a direct VPC-internal probe still works). Setting
it is only sensible when the origin is reachable exclusively through
the trusted proxy — the production Tunnel topology guarantees that.

## 5. Rate limiting

Application-layer, per endpoint class, keyed by client IP AND (when a
hosted session cookie is present) by session — both buckets must pass,
so one session cannot spray from many IPs and one IP cannot spray
across sessions. Fixed-window counting (boundary bursts of at most 2×
are accepted and documented; the semaphores independently bound
instantaneous concurrency). Memory is bounded (≤ 50k buckets; expired swept, oldest
evicted). Refusals: **429 RATE_LIMITED + Retry-After**, before any
route work.

| Class | Routes | Default budget |
|---|---|---|
| auth | POST /auth/* | 60 / 10 min |
| build | wallet create/request builds (v2+v4) | 60 / min |
| mutate | signatures, approvals, rejects, org writes, identity resolve | 120 / min |
| submit | submit, genesis-submit, reconcile | 30 / min |
| rpcRead | network/status, fuel, vault status | 120 / min |
| read | all other GETs (health, vaults, audit, session) | 600 / min |
| static | non-API static files | 1200 / min |

Limits are per-class env-tunable (`POLICYVAULT_RATE_AUTH`, `_BUILD`,
`_MUTATE`, `_SUBMIT`, `_RPC_READ`, `_READ`, `_STATIC` — the limit count
only; windows are fixed). The auth budget is a DoS/load bound, not a
guessing bound: nonces are 256-bit single-use secrets and signatures
are Schnorr — cryptography is the security boundary there. Cloudflare
edge rules (volumetric/bot/body-size) layer IN FRONT of these in
production (Phase E+); the application limits are the layer that still
works with the edge gone.

## 6. Concurrency semaphores

Two always-on semaphores bound expensive work (`queue + reject-with-429
when saturated, never unbounded` — architecture §11):

- **rpc** (default 4 concurrent + 16 queued): every route that dials
  kaspad — network/status, fuel, vault status, submit, genesis-submit,
  reconcile.
- **compute** (default 2 + 8): build/finalize/approval routes (encoder
  + VM-preflight work).

Env: `POLICYVAULT_RPC_CONCURRENCY/_QUEUE`,
`POLICYVAULT_COMPUTE_CONCURRENCY/_QUEUE`. Saturation refuses with
**429 SERVER_BUSY + Retry-After**; the release path is exception-safe
(`finally`), proven by test. Handler PROCESSING time is not bounded by
these (a submission awaiting chain proof is never cut off mid-flight).

## 7. Slow-client deadlines

Configured windows (`POLICYVAULT_HTTP_HEADERS_TIMEOUT_MS` default 15 s,
`POLICYVAULT_HTTP_REQUEST_TIMEOUT_MS` default 30 s, headers ≤ request
enforced at config time): request headers must complete within the
headers window (re-armed per keep-alive request), and the entire
request body must arrive within the request window. **Enforcement is
explicit per-socket deadline logic in server.js** — during Phase D,
Node v20.20.x's own `headersTimeout`/`requestTimeout` connection
checker was probed and observed never to fire (neither a header-stalled
nor a body-stalled socket was destroyed even with explicit
`connectionsCheckingInterval`), so the deadlines are enforced
deterministically by our code and the Node properties are set only as
defense-in-depth. A cut-off client's half-read body settles fail-closed
(`BODY_ABORTED`) instead of hanging the handler.

## 8. Input-shape and listing caps

- JSON body: 1 MB size cap (shipped previously) + **depth cap 64**
  (400 `BODY_TOO_DEEP`), enforced iteratively after parse.
- Audit listings clamp client `limit` values to ≤ 1000 (junk values
  fall back to defaults) — both `/audit` and the organization audit.
- v4 request listings stay capped at 100 (shipped previously).

## 9. Open-request quota (abandoned-request cap)

Enforced at the four build routes (v2 create/build, v4 create/build)
BEFORE any build work: open requests — the cancellable states, v2
`BUILT`, v4 `BUILT`/`AWAITING_APPROVALS`, counted across both families
(they share the durable category) — are capped **per vault (default
32)** and **per signer wallet (default 64)**
(`POLICYVAULT_MAX_OPEN_REQUESTS_PER_VAULT` / `_PER_WALLET`). Refusal:
**429 QUOTA_EXCEEDED** naming the count, the limit, and the remedy
(cancel stale requests via the reject route, or complete them). A
refusal creates nothing durable.

## 10. Security headers (final set)

API responses: CSP `default-src 'none'; frame-ancestors 'none'`,
`X-Frame-Options: DENY`, nosniff, `Referrer-Policy: no-referrer`,
restrictive `Permissions-Policy`, `Cross-Origin-Resource-Policy:
same-origin`, `Cache-Control: no-store`, and NO CORS headers ever.
Static app: CSP `default-src 'self'; script-src 'self'` (no
inline/eval), `Cross-Origin-Opener-Policy: same-origin`, nosniff,
no-referrer, Permissions-Policy, CORP, `Cache-Control: no-cache` (the
stale-build lesson). **HSTS** (`max-age=31536000; includeSubDomains`)
is emitted on every response exactly when hosted auth is enabled AND
the application origin is https — the production topology (TLS at the
edge, plain-HTTP origin behind the Tunnel) therefore declares it, the
insecure local test posture never does.

## 11. Error codes added in Phase D

`ORIGIN_FORBIDDEN` (403), `ORIGIN_REQUIRED` (403), `HOST_FORBIDDEN`
(421), `HOST_REQUIRED` (400), `RATE_LIMITED` (429 + Retry-After),
`SERVER_BUSY` (429 + Retry-After), `QUOTA_EXCEEDED` (429),
`BODY_TOO_DEEP` (400), `BODY_ABORTED` (400). All refusals are pure.

## 12. Test evidence (all green, 2026-08-24)

| Suite | Coverage | Count |
|---|---|---|
| `sdk/test/hosted-request-protection.test.js` | hostile Origin/Host matrix over real HTTP (hosted + self-hosted), Sec-Fetch handling, rebinding guard, HTTP/1.0 no-Host, loopback allowance, header set incl. HSTS on/off, OPTIONS/no-CORS, parser unit shapes | 18 |
| `sdk/test/hosted-rate-limit.test.js` | per-class budgets + Retry-After, window refill, refusal purity (no durable record), trusted-proxy bucket separation + malformed fallback, session-keyed budget across IPs (real Schnorr sign-in), self-hosted off-default, hosted off-switch refused, limiter memory bound | 9 |
| `sdk/test/hosted-dos-guards.test.js` | Semaphore unit semantics (FIFO/saturation/idempotent release), route classification table, HTTP compute saturation + exception-safe release (real v4 builds), slow-client header/body stall cutoffs, JSON depth cap, audit clamp | 6 |
| `sdk/test/hosted-quota.test.js` | per-vault + per-wallet quotas over real builds, cancellation frees quota, v2-route guard position, state-based family-agnostic counting, purity, defaults/validation | 6 |
| `sdk/test/hosted-protection-sabotage.test.js` | in-source neutralization (byte-identical restore) of the origin exact-match, the Host allowlist, the budget refusal, and the semaphore queue bound — each shown load-bearing | 6 (5+integrity) |

Deferred to later phases: Cloudflare edge rules + container/staging
enforcement (Phase E), the full hostile multi-user matrix re-run on the
hosted build (Phase F), real-KasWare hosted acceptance (Phase G).
