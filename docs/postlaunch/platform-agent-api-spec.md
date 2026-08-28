# Platform Agent API — machine identities, idempotency, dry-run,
# discovery, versioned schemas, origin policy

Status: IMPLEMENTED + UNIT/INTEGRATION-TESTED (real `server/src/api.js`
`handle()`, real HTTP server for the origin-policy properties, real
PostgreSQL for backend parity). Not yet TESTNET-VERIFIED or subjected to
a dedicated hostile-AI-agent/prompt-injection review (completion-standard
surface 26, out of this worker's scope). Covers `FULLSCALE_COMPLETION_
ADDENDUM.md` surfaces 6 (machine identities + scoped capabilities), 14
(idempotent machine operations), 16 (dry-run/simulation), 22 (capability/
version discovery), 23 (versioned platform schemas), and the
"programmatic-client origin policy" item under the REST/Agent API surface
(8).

**Anti-bloat compliance.** Nothing here implements financial authority,
policy semantics, successor derivation, transaction verification, or
reconciliation truth. Every consequential decision (signer authorization,
governance classification, risk composition, fee/mass, intent-manifest
derivation and verification) is a call into the EXISTING core/SDK
pipeline — `sdk/src/wallet-requests-v4.js` `planV4`/
`assertSignerAuthorizedV4`, `sdk/src/vault-builders-v4.js`
`buildV4Transaction`, `server/src/governance.js` `classifyActionV4`,
`core/risk` `evaluateRisk`, `core/intent/bridge/derive.js`
`deriveAndVerify`. This module is orchestration and reporting around
those functions, never a second implementation of what they decide.
**AI MAY REQUEST. POLICYVAULT DETERMINISTICALLY DECIDES.**

## 1. Machine (AI/agent) identities + scoped capabilities (surface 6)

### 1.1 Model

A machine identity (`server/src/machine-identity.js`) is created by an
authenticated hosted WALLET SESSION (never by another machine identity —
see §1.5) and is bound to that creating wallet's own x-only public key
(`creatorXOnly`). A resolved machine principal presents `xOnlyPubkey =
creatorXOnly`, so **every existing tenancy/covenant check applies
completely unmodified** (`server/src/tenancy.js` `vaultAccessAllowed`
etc. never had to change): a machine identity sees and can attempt
exactly what its creating wallet could, never more. Scopes are a
*separate, additional, narrowing* gate on top — they restrict which API
OPERATIONS a specific credential may attempt; they can never widen access
tenancy would otherwise deny.

Machine identities are a HOSTED-ONLY feature (`config.authMode ===
"enabled"`) — self-hosted mode (a single trusted local operator on
loopback) has no concept of them, exactly as it has no hosted sessions.

### 1.2 Credentials

`POST /api/v1/identities { label?, scopes: [...], orgId? }` creates an
identity AND mints its first bearer credential in one call (the raw
token is a 256-bit random value, prefixed `pvmk_`, shown to the caller
EXACTLY ONCE in the response). Only the credential's SHA-256 is ever
persisted — as the store's own record KEY, mirroring
`server/src/auth.js` sessions (`auth_sessions.token_hash`) exactly.
`POST /api/v1/identities/:id/credentials` mints an ADDITIONAL credential
for zero-downtime rotation (mint the new one, deploy it, then revoke the
old one). `POST .../credentials/:credentialId/revoke` revokes one
credential; `POST /api/v1/identities/:id/revoke` revokes the identity
itself, which immediately invalidates every credential it ever minted
(checked at resolution time — no fan-out write is needed for
correctness). All identity-management routes are tenancy-scoped to the
creating wallet (a foreign identity is 404, existence hidden, matching
`tenancy.js`'s discipline).

### 1.3 Scope enum (`server/src/scopes.js`)

Deny-by-default; derived from the real route map in `api.js`:

| Scope | Gates |
|---|---|
| `read:vaults` | `GET /vaults*` |
| `read:requests` | `GET /wallet/requests*`, `GET /wallet/v4/requests*` |
| `read:governance` | `GET /governance/proposals*` |
| `read:risk` | `GET /risk/evaluations/:id` |
| `read:organizations` | `GET /organizations*` |
| `read:manifests` | `GET /manifests/:hash` |
| `read:network` | `GET /network/status`, `GET /wallet/fuel/:address` |
| `read:audit` | `GET /audit` |
| `request:build` | `POST /wallet*create`, `POST /wallet*requests` (build), `POST /wallet/v4/simulate` |
| `request:sign` | `POST .../signature`, `POST .../approvals` |
| `request:submit` | `POST .../submit`, `POST .../genesis-submit` |
| `request:reject` | `POST .../reject` |
| `request:break-glass` | ADDITIONALLY required, on top of `request:build`, for `ownerPause`/`ownerRecover` |
| `governance:propose` / `:approve` / `:cancel` | the matching governance routes |
| `risk:release` | `POST /risk/evaluations/:id/release` |
| `vaults:reconcile` | `POST /vaults/:id/reconcile` |
| `vaults:suspend-agents` | `POST /vaults/:id/agent-suspensions` — instant HOSTED-layer agent suspend/unsuspend (coordination control, NEVER a covenant control — docs/postlaunch/hosted-agent-suspend.md; vault-owner tenancy still required) |
| `organizations:manage` | every mutating `/organizations*` route |
| `read:metrics` | `GET /metrics` — aggregate non-secret operational metrics (docs/postlaunch/operational-observability.md) |

An unmapped route is deny-by-default (403 `SCOPE_FORBIDDEN`) for a
machine principal — a new route added later without an explicit entry
here is unreachable by any machine identity until a human classifies it.

**Break-glass carve-out.** `ownerPause` (freeze) and `ownerRecover`
(terminal recovery) bypass governance/risk entirely at the covenant
workflow level (`governance-spec.md` §6.1). Holding `request:build`
alone is deliberately NOT enough to attempt them through the API — the
operator must additionally grant `request:break-glass`. This is an
API-surface conservatism, not a covenant rule: the covenant's own
owner-signature requirement is unaffected either way; this only bounds
what an automated caller may ATTEMPT to ask PolicyVault to build.

**Structural, non-grantable exclusions.** `/identities*` (machine-identity
management) and `/wallet/dev-accounts` + `/wallet/dev-sign` (the
TEST-ONLY dev signer) are never reachable by ANY machine credential,
regardless of scope — a wallet-session check, not a scope. A token can
never mint, widen, or revoke its own or a sibling's authority.

### 1.4 Enforcement point

`server/src/api.js` `handle()` resolves the principal once
(`requestAuthPrincipal`, extended — see §6) and, ONLY when it is a
machine principal, checks the wallet-session-only exclusion and the
required scope list BEFORE calling `dispatchRoute` (the renamed, byte-
identical original handler). A refusal here is PURE — it never touches
governance, risk, the SDK builder, or the durable store.

### 1.5 Deliberate v1 simplifications (documented, not implemented)

- `orgId` at creation is a descriptive/audit tag only; it does not
  currently grant org-wide identity management (only the creating wallet
  can see/rotate/revoke an identity). Org-shared machine-identity
  management is a natural future extension, intentionally deferred to
  avoid scope creep.
- Identity/credential quotas (`MAX_IDENTITIES_PER_WALLET = 50`,
  `MAX_CREDENTIALS_PER_IDENTITY = 10`, `server/src/machine-identity.js`)
  are fixed constants, not per-org configurable.

## 2. Idempotent machine operations (surface 14)

`server/src/idempotency.js`. Header-driven: a mutating POST that carries
`Idempotency-Key` is wrapped; a POST without it is byte-identical to
before (the shipped web client never sends it — verified in the
end-to-end tests). Semantics mirror `server/src/auth.js`'s challenge CAS
claim exactly:

1. **Claim** the composite key (`<principalScope>:<Idempotency-Key>`) via
   `platform-store.js` `createExclusive`. Win → execute the real handler
   exactly once.
2. **Lose** (key already claimed):
   - stored request fingerprint (a hash of method+path+query+body,
     `core/intent` `canonicalJsonStringify`) differs → deterministic 409
     `IDEMPOTENCY_KEY_CONFLICT`, the handler is never called;
   - fingerprint matches, still `IN_PROGRESS`, not stale → 409
     `IDEMPOTENCY_IN_PROGRESS` (a genuine concurrent duplicate never
     reaches the handler a second time — proven under real concurrency in
     the funds-safety test);
   - fingerprint matches, `IN_PROGRESS` but older than
     `IN_PROGRESS_STALE_MS` (5 minutes — a crashed handler that never
     completed) → one reclaim attempt;
   - `COMPLETE` → replay the ORIGINAL response verbatim, with
     `idempotency: { replayed: true, key }` added to the body (or to the
     thrown error's `extra`).
3. On a REAL execution's outcome: a **durable** result (2xx, or any
   business refusal with `status` in `[400,500)`) is recorded and will be
   replayed identically on retry. A **transient** result (no status, or
   `status >= 500` — an infrastructure failure: RPC down, an unexpected
   internal throw) RELEASES the claim instead of poisoning the key
   forever; the caller still sees the original error once, but a retry
   gets a genuinely fresh attempt.

Keys are scoped per authenticated identity (`machine:<identityId>`,
`wallet:<xOnlyPubkey>`, or `anonymous` for self-hosted/unauthenticated) —
two different callers can never collide or replay each other's keys
(proven directly).

**Funds-safety proof** (the property this surface exists for):
`sdk/test/postlaunch-idempotency-server.test.js` fires two CONCURRENT
identical `POST /wallet/v4/requests` calls sharing one Idempotency-Key
through the real server and asserts exactly one durable wallet-request
row exists afterward — never two.

## 3. Dry-run / simulation (surface 16)

`POST /api/v1/wallet/v4/simulate` (`server/src/simulate.js`), same body
shape as `POST /wallet/v4/requests`. Runs the exact same pipeline —
`classifyActionV4`, `evaluateRisk` (via the same adapters/composition
core `risk.js`'s real gate uses, called directly instead of through
`gateOperationRisk` specifically to skip its `saveEvaluation`/
`appendAudit` persistence), `planV4`, `assertSignerAuthorizedV4`,
`buildV4Transaction` (the identical SDK builder — real silverc + real
call-encoder subprocess, no RPC/store I/O), `deriveAndVerify` (the real
intent-manifest bridge + fail-closed verifier) — but **persists nothing
and consumes no gate**: no `saveRequest`, no proposal
consumption/creation, no risk-evaluation record, no audit row. Never
broadcasts (nothing here is even a finalized transaction).

A well-formed request (valid vaultId/action/signerAddress shape) always
answers `200` with `simulation.ok: true|false`:

- `ok: true` — the full decision: `governance` (governed/breakGlass/
  classification/quorum), `risk` (skipped/decision/codes), `review` (fee,
  mass/compute budget, before/after protected+reserve, payment), `intent`
  (manifestHash/verdict/failureCodes from the REAL, unpersisted
  verification), and `wouldRequire` (approvals/proposal/riskRelease).
- `ok: false` — `refusalReason: { status, code, message }` for whatever
  would have refused the real route (unauthorized signer, over-budget,
  a real RISK_REVIEW_REQUIRED-equivalent decision, an unknown action,
  etc.).

Malformed INPUT (bad vaultId/action/signerAddress shape) is a real HTTP
4xx, never folded into `ok:false` — that split exists because a dry run
answers "would this succeed", not "is this even a well-formed request".

**VM preflight is intentionally skipped** and stated as such
(`vmPreflight: { skipped: true, reason: "..." }`): real preflight
validates a Schnorr signature over the frozen transaction, and a dry run
never asks the caller to produce one. Fee/mass/successor correctness are
still exact (the real compiler/encoder ran); only the signature-
verification stage is not exercised. Stated honestly per the progress-
reporting discipline (CLAUDE.md) rather than oversold.

**No-state-change proof:** `sdk/test/postlaunch-simulate-capabilities-
server.test.js` snapshots every SDK store category, every new platform
category, and the audit log's line count before and after a battery of
simulate calls — including governed, risk-REVIEW, and break-glass paths
— and asserts byte-identical snapshots. The identical operation, run for
real immediately after, is shown to still genuinely require the reported
gate (`RISK_REVIEW_REQUIRED`).

Genesis/create simulation (`POST /wallet/v4/create`) is out of scope for
v1 — governance and risk never apply to genesis (no before-state; a
documented existing rule), so its "simulation" value is materially
smaller; deferred rather than half-built.

## 4. Capability / version discovery (surface 22)

`GET /api/v1/capabilities` (`server/src/capabilities.js`) — PUBLIC, no
auth/scope required, exactly like `/health`. Generated from code truth
wherever a real exported constant already exists rather than retyped as
prose: `apiVersion` (`api-version.js`), `contract.supportedCovenantVersions`
(`core/intent` `SUPPORTED_COVENANT_VERSIONS`), `actions.v4` (`sdk/src/
wallet-requests-v4.js` `ROLE_BY_ACTION`, literally enumerated), `scopes`
(`scopes.js` `SCOPES`, the SAME array `handle()` enforces against),
`schemas` (every schemaVersion string this build understands), `limits`
(the live `config.requestProtection` rate limits/quotas/semaphores), and
`features` (booleans computed from the live config — e.g.
`machineIdentities` is honestly `false` in self-hosted mode, proven in
the tests). The per-scope one-line English description is the one
hand-maintained exception (an English sentence describing what a route
classifier function gates cannot itself be mechanically derived) — the
scope NAMES themselves are still single-sourced from `scopes.js`.

## 5. Versioned platform schemas (surface 23)

`server/src/api-version.js` defines
`V4_WALLET_REQUEST_SCHEMA_VERSION = "policyvault-wallet-v4-request/v1"`.
Every v0.4 wallet-request route (`create`, `requests` build, `simulate`,
`approvals`, `signature`, `submit`, `genesis-submit`, `reject`, and the
GET listing/detail routes) additively stamps its response with a
top-level sibling `schemaVersion` field — the existing `request`/
`requests` field is untouched, so the shipped web client (which reads
`body.request`/`body.requests` and ignores unknown siblings) sees zero
behavior change. On the request side, `schemaVersion` in the body is
OPTIONAL: omitted (every existing caller) is unchanged behavior exactly;
if present, it MUST equal the current value or the route fails closed
with `422 SCHEMA_VERSION_UNSUPPORTED` — never routed to a default or
best-guess handler. New machine-facing surfaces (`simulation`,
`machineIdentity`, `machineCredential`, `idempotencyRecord`,
`capabilities`) each carry their own `schemaVersion`/`schema` field from
day one.

Legacy v0.2 wallet routes are explicitly out of scope for this
versioning pass (production-disabled for new creation already; the
mission named "v4 wallet routes" specifically).

**Compatibility policy going forward:** a NEW backward-INcompatible wire
shape for any of these bodies must mint a NEW schemaVersion string and
add it to the accepted set (or, if truly incompatible, replace the
accepted set and bump — never silently reinterpret an old string under
new semantics). A machine client that pins a schemaVersion it understands
is guaranteed either that exact behavior or a clean 422, never silent
drift.

## 6. Programmatic-client origin policy

`server/src/limits.js` `verifyOrigin` (server.js's CSRF wall #2 — the
existing `SameSite=Strict` cookie is wall #1, unaffected). Today's rule,
UNCHANGED: cookie-session requests must prove browser same-origin intent
in hosted mode.

**The addition:** a request carrying NO `Cookie` header at all, presenting
a syntactically plausible machine Bearer credential
(`/^Bearer\s+\S{20,300}$/i` — a cheap shape pre-filter; the actual token
is resolved cryptographically downstream in `requestAuthPrincipal`,
which throws `401 MACHINE_TOKEN_INVALID` on anything that doesn't
resolve), is exempted from the Origin/`Sec-Fetch-Site` checks.

**Reasoning (why this is safe).** CSRF is fundamentally an AMBIENT-
credential attack: a cross-origin attacker page cannot read the victim's
response, but the victim's browser still automatically attaches cookies
to the forged request, so the mutation happens anyway — that is the
entire threat the Origin wall defends against. An `Authorization: Bearer
<token>` header is never ambient: no browser mechanism attaches it
automatically to a cross-origin request. A cross-origin attacker page
therefore cannot forge a request carrying a valid bearer credential it
does not already know — and if it already knows one, it is an
authenticated party by definition, not a CSRF forgery (whether that
specific credential is honored is exactly what `requestAuthPrincipal` +
the scope gate decide, independently, on every such request). This
server additionally sends NO CORS headers at all (`server.js`
`apiHeaders`), so even the network-level preflight/response-visibility
story for a genuine cross-origin script is already closed off; this
exemption does not depend on that fact but it is consistent with it.

**What is never weakened.** The exemption applies ONLY when no Cookie
header is present. A request carrying a cookie (alone, or together with
a bearer header) gets the full, unchanged origin wall — a hostile test
(`sdk/test/postlaunch-origin-policy-server.test.js`) proves a cookie
session is refused cross-origin exactly as before, INCLUDING when a
garbage Authorization header is deliberately attached alongside it. The
same file also proves the exemption is not a blanket bypass: an invalid/
unresolvable bearer credential still fails the request, just at
authentication (`401`) rather than at the origin wall.

## 7. `agent-sdk/` deletion

`agent-sdk/index.js` (the v0.1/v0.2-era headless-agent helper, built on
the legacy `spendFromVault`/`spendFromVaultV2` pipeline, zero references
anywhere in tests/tools) has been deleted — it predated and would have
masqueraded as this surface. This spec + `server/src/machine-identity.js`
+ `server/src/simulate.js` are the current, real, v0.4-integrated
machine-facing surfaces.

## 8. Evidence (files, commits, test counts)

| Surface | Files | Tests |
|---|---|---|
| 6 — machine identities + scopes | `server/src/machine-identity.js`, `server/src/scopes.js`, `server/migrations/005_platform_agent_api.sql`, `server/src/platform-store.js` | `sdk/test/postlaunch-machine-identity-server.test.js` 11/11 |
| 14 — idempotency | `server/src/idempotency.js` | `sdk/test/postlaunch-idempotency-server.test.js` 13/13 |
| 16 — dry-run/simulation | `server/src/simulate.js` | `sdk/test/postlaunch-simulate-capabilities-server.test.js` 8/8 (shared file) |
| 22 — capability discovery | `server/src/capabilities.js`, `server/src/api-version.js` | (shared file above) |
| 23 — versioned schemas | `server/src/api-version.js`, `server/src/api.js` | (shared file above) |
| origin policy | `server/src/limits.js`, `server/src/server.js` | `sdk/test/postlaunch-origin-policy-server.test.js` 8/8 |
| PG backend parity | `server/migrations/005_platform_agent_api.sql`, `server/src/platform-store.js` | `sdk/test/postlaunch-platform-store-pg.test.js` 4/4 (ephemeral DB) |

Full existing regression (every pre-existing `hosted-*`/`postlaunch-*`
test file, 217 tests) re-run green after this work, including one
one-line fix to `postlaunch-migrations-pg.test.js`'s hardcoded migration
count (`[1,2,3,4]` → `[1,2,3,4,5]`), the mechanical and unavoidable
consequence of adding a real new migration.

## 9. Claim labels

DESIGNED + IMPLEMENTED + UNIT-TESTED + INTEGRATION-PROVEN (real
`handle()`, real HTTP server, real PostgreSQL where applicable). NOT
TESTNET-VERIFIED. NOT independently reviewed for hostile-AI-agent/
prompt-injection concerns (completion-standard surface 26 — out of this
worker's scope; note for whichever surface owns it: this surface's
routes accept only closed-schema JSON, never free-form natural-language
tool output, so the main injection surface here is "an AI client
misconstrues an ALLOW/REVIEW/DENY decision", not "malicious content
crosses into trusted bytes" — but that judgment deserves its own
dedicated adversarial pass, not a self-assessment here).
