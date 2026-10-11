# Platform Agent API — machine identities, idempotency, dry-run,
# discovery, versioned schemas, origin policy

Status: IMPLEMENTED + UNIT/INTEGRATION-TESTED (real `server/src/api.js`
`handle`, real HTTP server for the origin-policy properties, real
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

`orgId` is optional and confers no authority anywhere; it routes the
identity's events to that organization's readers
(`webhooks-events-spec.md` §10). Naming an organization therefore requires
organization ownership (RC45 R1-11): when `orgId` is present (not absent and
not null), the route applies the existing organization-owner rule
(`requireOrgAccess(..., "owner")`) before anything is written. An `orgId` that
is not a lowercase UUID string answers `422 ORG_ID_INVALID`, a missing or
foreign organization the non-oracle `404 ORG_NOT_FOUND`, and a member who is
not the owner `403 ORG_FORBIDDEN`; none of them writes an identity, a
credential or an event. A request without `orgId` is unchanged.
`identity.revoked` carries the stored `orgId` only when the revoking wallet
still owns that organization; otherwise the event has no `orgId`.

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

`server/src/api.js` `handle` resolves the principal once
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

`server/src/idempotency.js`. A mutating POST carrying `Idempotency-Key`
uses a durable claim scoped to the authenticated identity. Header-absent
behavior is unchanged; the secret-bearing route exclusions now also cover the
authentication routes (below). All anonymous
requests share the existing anonymous scope; the scope itself is not authority.
Secret-bearing routes are excluded from response replay: `/webhooks`,
`/identities`, `/notifications` and the authentication routes `/auth/*`
(`POST /auth/verify` returns a live session token, and sign-in is bound to a
one-time challenge nonce). A request to them with an Idempotency-Key executes
normally and nothing is persisted for replay.

1. Create the claim once. A successful create acknowledgement grants this
   invocation permission to call the handler. A missing acknowledgement leaves
   the outcome uncertain and does not dispatch the handler.
2. An existing key with a different method/path/query/body fingerprint returns
   `409 IDEMPOTENCY_KEY_CONFLICT`. An unfinished matching claim returns
   `409 IDEMPOTENCY_IN_PROGRESS`, or `IDEMPOTENCY_OUTCOME_UNKNOWN` when an
   uncertain handler result was recorded. Neither age nor an infrastructure
   error permits replacement or replay of the handler.
3. Successful definitive responses and deterministic 4xx refusals are first
   saved as an exact completion receipt embedded in the claim. Conditional
   updates require the original claim owner and complete expected record.
   The claim is then marked complete and replays the retained response, with
   `idempotency: { replayed, key }`. Original creation time is preserved.
4. Exceptions with no status or a 5xx status, returned 5xx responses, and
   unavailable persistence acknowledgements remain uncertain. A successful
   exact readback may establish a saved transition; an error alone cannot.
5. A later matching request may finalize an already-retained completion
   receipt and return it. This repairs response persistence without calling
   the handler. Without such a receipt, the original operation remains
   protected until its domain outcome can be established independently.

[Inspection and recovery](idempotency-recovery.md) documents supported trusted
local helpers, legacy compatibility, failure cases and the single-writer JSON
boundary. Schema 005 and historical migration bytes remain unchanged. Legacy
complete records still replay; legacy unfinished records do not expire.

Verification includes the existing real API `POST /wallet/v4/requests`
concurrency and identity tests, plus JSON/PostgreSQL delayed-handler,
unknown-effect, conditional-update, lost-acknowledgement and fresh-process
recovery regressions. These tests exercise synthetic operations and establish
no on-chain payment outcome or release qualification.

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
(`scopes.js` `SCOPES`, the SAME array `handle` enforces against),
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

### 5.1 v0.4-family Verify and transition refusals (RC45)

**Verify — `POST /vaults/:id/reconcile`** (scope `vaults:reconcile`; the
vault owner only). The body may carry one optional field,
`outOfAppTransaction`: optional owner-supplied recover evidence, verified
against the chain, grants no authority — the owner's signed recover
transaction as a Safe JSON string. It is read only after the principal and
the owner-access check (a foreign vault answers the same 404 before any
parse or node call); a non-string, a string over 64 KiB or a transaction
with more than 64 outputs is `400 BAD_FORMAT` (a document that does not
parse as a transaction is not refused: it settles nothing), and a vault
outside the v0.4 family with the field is `422 UNSUPPORTED_VERSION`;
neither reconciles. Verify reads the address of the pasted transaction's
`outputs[0]` and at most 4 further distinct output addresses; the
addresses it does not read are counted in `UNKNOWN`'s `unchecked`
(RC45 R1-09). No other input is read (no
force, override, age or claim-release option). The answer is
`{reconcile, vault}`; `reconcile.status` for a v0.4-family vault is one of:

| status | meaning | fields |
|---|---|---|
| `CONSISTENT` | the recorded live state is on chain | `settled[]` (what this Verify settled, below; empty when it settled nothing) |
| `ADVANCED` | Verify settled a transition observed at depth (1,000 DAA) | `to`, `txId`, `requestId` (hosted request; none for an unsigned request the governance gate refuses, which keeps its label), `adopted: true` (an out-of-app pause / unpause), `settled[]` |
| `TERMINAL` | the vault is closed | `vaultStatus`, `settled[]` |
| `CLAIM_PENDING` | not settled yet | `depth`, `required` (below depth; with `txId`, `requestId` for a recorded transaction) or `claimTxId` (a live claim) |
| `REQUEST_RECOVERY_REQUIRED` | signed work may still execute | `requestId`, `pending[]`, `recordedVaultClosed` |
| `UNKNOWN` | the recorded outpoint is spent and no known spender was seen | `reason`, `unchecked` |
| `CHAIN_CONTRADICTION` | the chain contradicts the record | `reason` |

Verify writes only on positive chain evidence at depth; `UNKNOWN` and
`CHAIN_CONTRADICTION` write nothing; a node that cannot be read, or
an environment failure that R1-04 classifies (a missing binary, a spawn error, a signal or temp-file I/O of the `pv_tx_probe` harness, or any compiler or VM-preflight failure), is `422 RECONCILE_FAILED`, nothing written, except a restore
earlier in the same pass, which the message names (R1-14); a dynamic-loader
failure of `pv_tx_probe` is not one (lead5 L-17). A `CONSISTENT` answer can still
have written (RC45 R1-07):

- Each `settled[]` entry `{requestId, action, state, txId}` carries its
  resulting `state`: `CHAIN_VERIFIED` (completed by this Verify), `STALE`
  (superseded) or `SUBMISSION_REJECTED` (an established rejection's leftover
  claims and reservation released).
- `CONSISTENT` and `ADVANCED` always carry `settled[]`. `TERMINAL`,
  `CLAIM_PENDING` and `REQUEST_RECOVERY_REQUIRED` carry it only when it is
  non-empty. On a closed vault, `REQUEST_RECOVERY_REQUIRED` carries it when
  Verify first finished requests of the vault's recorded advancement,
  requests their own completion receipts name, or their signed same-txid
  twins (each `CHAIN_VERIFIED`) while another request is still pending
  (RC45 R1-13).
- A restore of a TERMINATED_UNKNOWN vault is not in `settled[]` and adds no
  field. The returned `vault` is live again, and the web derives its restore
  notice from the card's TERMINATED_UNKNOWN status before the Verify.

`CLAIM_RELEASED` is no longer produced for the v0.4 family. Every Close &
recover submit, and an owner Pause contested by pending delegate work,
returns at `SUBMITTED`; Verify completes it at depth. Webhook consequences:
`docs/postlaunch/webhooks-events-spec.md` §4.

**Transition refusals** (`POST /wallet/v4/requests`, `.../signature`,
`.../submit`): `422 REQUEST_RECOVERY_REQUIRED` when an unresolved (PENDING)
transition record of another transaction sits on the vault's live outpoint
(on a closed vault, anywhere), and `409 CLAIM_CONFLICT` when an ordinary
build meets a transaction claim on the live outpoint (pre-sign) or a
finalize / submit meets another transaction's claim. A refusal of this
live-outpoint guard names the blocking record and the claim in the error
envelope: `{ code, message, requestId, action, state, signerRole, claimTxId }`
(RC45 A3); the signature and submit routes also carry `request`, the
caller's own request. The owner's break-glass (`ownerPause`,
`ownerRecover`) is never refused by pending work on a live vault and does
not count toward the open-request quota. A closed manifest answers
`422 VAULT_TERMINAL` (recovered) or `422 RECONCILIATION_REQUIRED`, as does a
manifest already advanced by the request's own transaction or (at submit) a
live outpoint the node does not show; none of them writes. A completion
receipt of the request's own transaction that names the request answers
`422 RECONCILIATION_REQUIRED` at `.../signature` and `.../submit` before the
live-outpoint guard, and writes nothing: a request whose own completion
receipt names it is never `409 STALE` (RC45 R1-06). A signed same-txid twin of
an executed request is not covered and can still answer `409 STALE` (residual,
lead5 record L-2). Rejecting a
request (`.../reject`) is limited to the request's signer or the vault
owner (`403 REQUEST_FORBIDDEN` otherwise; owner-minted machine credentials
act as the owner).

### 5.2 Delegate budget period start (RC45)

Applies to the delegate leaves of `policyvault-0.4.1` vaults (and the
testnet-only `policyvault-0.4`, which shares their builders) and of
`policyvault-0.7-kas` treasuries. Status: IMPLEMENTED and UNIT-TESTED (SDK,
API and browser suites on JSON and PostgreSQL; built requests go through the
real compiler, encoder and VM preflight with TEST-key signatures). Not
TESTNET-VERIFIED.

**New or changed leaves.** A leaf is new or changed unless its key is
installed and all nine committed fields (`agentPk`, `maxPerSpend`,
`periodBudget`, `periodLengthDaa`, `periodStartDaa`, `periodSpent`,
`approvalThreshold`, `agentMaxFeePerTx`, `agentRecipientRoot`) equal the
installed leaf. Any change to a delegate, including a recipient-only change,
restarts that delegate's budget period at the build; `periodSpent` is
committed as requested. A leaf the request leaves exactly as installed is
carried unchanged and is not checked. A request with no new or changed leaf
reads no DAA score (remove a delegate, Pause, Close & recover, Unpause,
approver changes, top-ups, delegate payments).

**Anchor at build.** The `periodStartDaa` a client sends for a new or
changed leaf is a lower bound. The build reads the configured node's virtual
DAA score (network, sync and UTXO index verified; a value that is not a
canonical integer is refused) and commits `max(sent, anchor)`; every other
field is committed as sent, and the agent root is computed from the committed
leaves. A v0.4-family request reports the anchor as
`review.periodStartAnchorDaa` (a decimal string; absent when no leaf was
anchored), so a caller's committed start is `max(sent, anchor)`. A
`policyvault-0.7-kas` creation carries the committed starts in `summary`; a
root request in `newRegistry` and `vaultOperations[0].params.agents`. A
governance proposal records the requested start; its execution build anchors
at execution, so a proposal with any start stays executable after any delay
window (the stated exception in `governance-spec.md` §6.2 step 4: later than
approved, never earlier, `periodSpent` unchanged; classification stays on the
requested change). `POST /wallet/v4/simulate` anchors the same way.

**Later start.** API, SDK and MCP callers may request a later start for a
new or changed leaf. It is kept as requested and never raises what the
delegate can spend at any time (the spend bound of lead5 §6 does not increase
when the start moves later). The window below is measured from it, so a slow
M-of-N quorum has more time. The web always starts the period at its Build.
A proposal created through the API, SDK or Python client that requests a
start later than the network position at the build cannot be executed from
the web: the build commits the requested start but reports the node's score
as `review.periodStartAnchorDaa`, and the web review refuses to sign it.
Execute such a proposal through the API or SDK, or reject the built request
and create a new proposal (a web attempt has already consumed the proposal at
its build). The refusal never gives a delegate more.

**Window.** For a period of `L` DAA, `W(L) = max(L − 6,000, 600)` DAA: the
period minus ten minutes, never less than one minute (1 hour: 30,000 DAA,
50 min; 1 day: 858,000 DAA, 23 h 50 min). A request is refused when, for any
new or changed leaf, `current DAA − periodStartDaa > W(L)`.

**Refusals.**

| code | where | effect |
|---|---|---|
| `422 PERIOD_START_REQUIRED` | any build of a new or changed leaf (`POST /wallet/v4/create`, `POST /wallet/v4/requests`, `POST /org-roots/:rootId/vaults`, `POST /org-roots/:rootId/requests`; simulate reports it as `refusalReason`) and every check point below, when the node's DAA score cannot be read | no request, reservation, claim or proposal consumption is written. At a v0.4-family build the gates before the read have already run: a released risk review that matched this action is used up (release it again), and audit-log rows may exist |
| `409 PERIOD_START_STALE` | v0.4-family `.../genesis-submit` (before the submission claim), `.../signature` (finalize) and `.../submit`; a `policyvault-0.7-kas` creation's `POST /wallet/v7/requests/:id/signature`; `POST /org-roots/:rootId/requests/:id/finalize` | nothing written. A v0.4-family request stays `BUILT` (cancel it and build again) or, at submit, `PREFLIGHT_VERIFIED` (it keeps blocking ordinary builds; Pause, Verify about two minutes later and Unpause, or Close & recover). A creation stays `BUILT` and can be withdrawn. A root request stays `AUTHORIZED` with its owner approvals; it can then be withdrawn (`POST /org-roots/:rootId/requests/:id/reject`) although it carries slot signatures. A governed build already consumed its proposal, so a request that ages out before its signature needs a new proposal |
| `422 REGISTRY_ROOT_MISMATCH` | every build and check point above | the request's stored registry does not fold to the agent root it commits (store damage only); nothing written. At root finalize a missing treasury record is `404 VAULT_NOT_FOUND` |

**Periods shorter than 6,600 DAA.** These are below the 1-hour product
minimum and reachable only through the API. They are accepted, with a
600-DAA window. A leaf that passes the last check and is accepted within ten
minutes of it can confirm with up to `⌊6,599 / L⌋` budgets beyond
`periodBudget − periodSpent` (L = 6,000: 1; 1,200: 5; 600: 10; 60: 109;
1: 6,599). Each later ten minutes of acceptance add one budget per `L` DAA,
as for any period. Each payment stays bounded by `maxPerSpend`, the fee cap,
the recipients and the approval tier, and the total by the protected value.
Periods of 6,600 DAA or more confirm with no extra budget when accepted
within ten minutes of the check.

**What this does not do.** The banking of lead5 §6 is a property of the
installed covenants and is unchanged:

- leaves already on chain are not repaired; they keep their starts until an
  owner action changes, rotates or removes them;
- an idle or carried leaf still banks one budget per elapsed period at
  consensus, and an unpause still releases the paused backlog;
- a delegate holding its own key can still submit directly to a Kaspa node,
  where no hosted check applies;
- a signed `policyvault-0.7-kas` creation and a finalized root request are
  not re-checked for their period start at submit, and neither can be
  withdrawn on that ground. A request built by this release then holds no
  more than a leaf whose period started at its build and stayed idle; one
  signed before this release keeps the start it was signed with, which may be
  `0`. Separately, a finalized root request's Submit first reads every input
  the request spends (`v0.7-app-surface-contract.md` §2.2.5): when a non-root
  input is proven spent by another transaction it refuses `409
  RECORDED_OUTPUT_SPENT` with nothing written and nothing broadcast, and the
  request can then be withdrawn (`POST /org-roots/:rootId/requests/:id/reject`)
  in two steps, at least 1,000 DAA apart, once that spend and the input's
  existence are final; another unresolved input read refuses `409
  SUBMIT_INPUT_UNRESOLVED`, and an unreadable chain position `422
  OBSERVATION_ERROR`, also with nothing written;
- the check is hosted: the browser compares the server's start only with the
  same server's `/network/status`, and the covenant sees only the agent root,
  so a dishonest server can still commit a stale start.

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
`handle`, real HTTP server, real PostgreSQL where applicable). NOT
TESTNET-VERIFIED. NOT independently reviewed for hostile-AI-agent/
prompt-injection concerns (completion-standard surface 26 — out of this
worker's scope; note for whichever surface owns it: this surface's
routes accept only closed-schema JSON, never free-form natural-language
tool output, so the main injection surface here is "an AI client
misconstrues an ALLOW/REVIEW/DENY decision", not "malicious content
crosses into trusted bytes" — but that judgment deserves its own
dedicated adversarial pass, not a self-assessment here).
