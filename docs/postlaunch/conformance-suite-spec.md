# Agent-Integration Conformance Suite — Specification

**Surface 24 of `FULLSCALE_COMPLETION_ADDENDUM.md`** (binding: "The agent
conformance suite MUST exercise the REAL reference MCP, JS/TS, Python, and
protocol-adapter paths (not mocks)."). This document is the authoritative
description of what the suite proves, its equivalence rules, its
documented-limitation assertions, how a new path registers, and the
evidence format an RC record cites.

Code layout (all NEW; no driven surface was modified to build this):

```
conformance/
  agent-conformance.test.js   the scenario matrix (node --test)
  paths.js                    path registry + declared capability subsets
  lib/server-harness.js       ONE real server boot + seeding + minting
  lib/normalize.js            normalized outcome + equivalence assertions
  lib/report.js               machine-readable evidence artifact
  drivers/js-driver.js        JS path  (surface 9, in-process)
  drivers/py-driver.js        Python path wrapper (spawns the subprocess)
  drivers/pv_conformance_driver.py   Python path (surface 10, subprocess)
  drivers/mcp-driver.js       MCP path (surface 7, stdio subprocess)
  drivers/x402-driver.js      x402 adapter path (surface 27; REAL
                              integrations/x402/service.js over HTTP)
  drivers/ap2-driver.js       AP2 adapter path (surface 28; REAL
                              integrations/ap2/service.js over HTTP,
                              real ES256 SD-JWT mandates)
  results/                    per-run artifacts (gitignored)
```

Run: `node --test conformance/` (from the repo root). One run boots one
server, drives every path, writes
`conformance/results/conformance-summary.json`, and prints a human
summary. Reference run on this tree: **20/20 scenarios green — 79 matrix
cells: 71 PASS + 8 LIMITATION_ASSERTED, 0 FAIL** (~90 s; W4-refinements:
the x402/AP2 protocol-adapter paths are REGISTERED and DRIVEN — 5 paths).

## 1. What is real (zero mocks)

- **Server**: `server/src/server.js createServer(config)` — the exact
  production entry point — JSON persistence backend, ephemeral loopback
  port, `authMode: "enabled"` (hosted sessions + machine identities +
  origin wall + rate limits + scopes all live). Webhook DELIVERY worker is
  disabled (`POLICYVAULT_WEBHOOK_DELIVERY=0`) for determinism; endpoint
  RECORDS and the event stream itself are fully live.
- **Build pipeline**: the real SDK builder — real silverc covenant
  compilation and the real Rust `pv_call_encoder`/`pv_tx_probe`
  subprocesses — runs inside every simulate/build the suite performs.
- **JS path**: `sdk/src/http-client.js PolicyVaultClient` in-process over
  real HTTP.
- **Python path**: the stdlib-only `policyvault_client` package running in
  a REAL `python3 -m pv_conformance_driver` subprocess speaking a
  one-JSON-per-line op protocol; credentials arrive via environment only.
- **MCP path**: a REAL `node mcp/server.js` subprocess per session,
  spoken to over actual stdio newline-delimited JSON-RPC 2.0
  (initialize → initialized → tools/list → tools/call), stdout purity
  asserted on every line.
- **x402 adapter path** (W4-refinements): the REAL
  `integrations/x402/service.js createX402Service()` on its own loopback
  port with the six-scope credential, driven over real HTTP with
  protocol-correct base64 PAYMENT-REQUIRED headers; the adapter itself
  speaks real HTTP to the one conformance server through
  `integrations/lib/pv-client.js`.
- **AP2 adapter path** (W4-refinements): the REAL
  `integrations/ap2/service.js createAp2Service()` (PolicyVault as
  Credential Provider), driven with REAL compact SD-JWT payment mandates
  (ES256 over `node:crypto`, minted by the driver's own issuer/holder
  trust-anchor keys — the operator role, played by the harness the same
  way it plays the wallet owner). Instrument → conformance vault A;
  payee directory → operator-configured addresses (plus a deliberate
  foreign-vault instrument for the tenancy-refusal proof).
- **Raw-HTTP probe**: `node:http` requests used where a scenario needs
  the verbatim wire view (cross-client key replay, hostile bodies). It is
  a probe, not a registered path.
- **Human/wallet roles** the paths cannot play are played by the harness
  in-process, exactly as the Python client suite already does:
  wallet sign-in (kaspa-wasm Schnorr over `PersonalMessageSigningHash`),
  machine-identity minting (wallet-session-only by design), and the
  external approver signature (`sdk/src/signer-dev.js`, TEST-ONLY keys).

Out of matrix scope, deliberately: routes that dial a live Kaspa node
(`/network/status`, `/vaults/:id/status`, submit/reconcile execution) —
this suite runs without a node; live-testnet coverage is a separate layer.
Genesis creation (`/wallet/v4/create`) and governance/risk MUTATIONS are
likewise outside this suite's v1 matrix (reads and gate refusals are in).

## 2. Principals (minted per scenario role, deny-by-default)

| name | scopes | role |
|---|---|---|
| `six` | `read:network read:vaults read:requests read:manifests request:build request:submit` | the documented autonomous-agent profile — exactly the six-scope credential the x402/AP2 adapter specs mandate |
| `readonly` | `read:vaults` | scope-refusal probe |
| `reader` | `read:audit read:events read:governance read:risk` | observer feeds |
| `signer` | `read:requests request:sign` | approval submission |
| `janitor` | `read:requests request:reject` | request cancellation |
| `hooks` | `webhooks:manage` | injection round-trip field |
| `tenant2` | (second wallet) `read:vaults read:requests read:events` | isolation probe |
| `bogus` | syntactically valid, unknown credential | auth refusal |
| over-scoped | mint attempt with an unknown scope | **refused at mint** (`422 MACHINE_IDENTITY_SCOPE_UNKNOWN`) — an over-scoped identity can never exist |

Vaults seeded: **A** (v0.4, no approvers, 500 KAS threshold) and **B**
(v0.4.1, 2-of-2 approvers, 5 KAS threshold), both owned by wallet 1.

## 3. Scenario matrix (path × scenario)

| id | proves | js | python | mcp |
|---|---|---|---|---|
| C01 | discovery document identical; every path pins `schemas.walletV4Request`; MCP action enum derived from live discovery | ✓ | ✓ | ✓ |
| C02 | vault list/detail/audit data identical (tenancy-scoped) | ✓ | ✓ | ✓ |
| C03 | dry-run simulation **byte-identical** across paths — ok body, over-cap refusal (`SIMULATION_FAILED` + builder message), unknown vault (`BUILD_FAILED`); `vmPreflight.skipped` stated honestly | ✓ | ✓ | ✓ |
| C04 | simulate persists NOTHING: sha256 snapshot of the whole data root identical around simulates (sole exclusion: `platform/credentials/` — auth `lastUsedAt` touches, documented) | ✓ | ✓ | ✓ |
| C07 | `403 SCOPE_FORBIDDEN` identical for scoped-out routes (simulate/build/audit/events), break-glass (`ownerPause` without `request:break-glass`), approvals without `request:sign`; `MACHINE_IDENTITY_ROUTE_FORBIDDEN` for `/identities` at any scope; unknown scope refused at mint | ✓ | ✓ | ✓ |
| C08 | unknown `schemaVersion` → `422 SCHEMA_VERSION_UNSUPPORTED`, identical envelope on every body-carrying path (js/python/raw) | ✓ | ✓ | LIMITATION |
| C09 | refusal-envelope identity: `VAULT_NOT_FOUND`, `GOVERNANCE_PROPOSAL_UNKNOWN`, `RISK_EVALUATION_NOT_FOUND`, `MACHINE_TOKEN_INVALID` (401), anonymous mutation → `ORIGIN_REQUIRED`; governance listings identical | ✓ | ✓ | ✓ |
| C05 | build → status: the SAME intent built via each path yields the SAME exact transaction (equal `txId`, review, manifestHash); every path reads every path's request identically; open listings identical | ✓ | ✓ | ✓ |
| C06 | idempotency: a JS-created key replayed via raw HTTP and via Python returns the ORIGINAL response (`idempotency.replayed: true`); same key + different body → `409 IDEMPOTENCY_KEY_CONFLICT` everywhere; exactly ONE durable request per key | ✓ | ✓ | LIMITATION |
| C14 | adversarial concurrency: two callers racing one key → exactly one execution (loser replays or `IDEMPOTENCY_IN_PROGRESS`), one durable request; sequential retries replay; **reservation honesty** (below) | ✓ | ✓ | — |
| C18 | reject: MCP's mutating reject tool cancels an open request (`WALLET_REJECTED`), visible identically everywhere; repeat-reject benign; `six` cannot reject (scope split live) | ✓ | ✓ | ✓ |
| C15 | approval replay: a collected approver signature replayed → `422 DUPLICATE_APPROVAL`, identical envelope via JS+Python; state/txId/collected unchanged | ✓ | ✓ | LIMITATION |
| C10 | events polling (`GET /events`, `read:events`): identical pages, cursor semantics, `400 BAD_CURSOR`, `422 EVENT_TYPE_UNKNOWN`; events correlate to this run's requestIds | ✓ | ✓ | LIMITATION |
| C13 | cross-tenant isolation: tenant2 sees no tenant-1 vault (404), request (404), listing entry, or event — after all this run's activity | ✓ | ✓ | ✓ |
| C12 | injection: hostile MCP tool args → `SCHEMA_REFUSED` with the literal NEVER echoed on stdout/stderr; hostile tool name sanitized; a hostile free-text API field (webhook label) round-trips byte-identically as DATA via every path; listings never carry the signing-secret value | ✓ | ✓ | ✓ |
| C16 | surface locks (see §7) | ✓ | LIMITATION | LIMITATION |
| C17 | amounts-as-strings walker over the collected corpus (capabilities, vault detail, simulation, request record, events page): every amount key is a canonical decimal string; no non-safe-integer JSON number anywhere | all paths' bodies | | |
| C11 | token hygiene: every minted credential grepped against ALL subprocess stdout+stderr, JS client `JSON.stringify`/`util.inspect`, every error message, the results rows, the hygiene corpus, AND (W4) every adapter response body + every durable byte of both adapter attempt stores — zero occurrences | ✓ | ✓ | ✓ |

**Protocol-adapter scenarios (W4-refinements; paths `x402`, `ap2`):**

| id | proves |
|---|---|
| C19 | x402: a real PAYMENT-REQUIRED header drives normalize → mandatory dry run → REAL durable platform build → `PENDING requires [signature]` (pay-first stops at the external signer; nothing settles without chain proof). **Same-intent equivalence**: the identical logical intent built via the reference JS path commits the SAME exact transaction (equal `txId` + `manifestHash` — the C14 no-reservation structure), and the adapter-built request reads identically via JS and Python. Derived idempotency (attemptId + requirement digest): replays converge on ONE durable request; a mutated price under the same attemptId is `409 IDEMPOTENCY_KEY_CONFLICT`. Platform refusals surface VERBATIM (`VAULT_NOT_FOUND`, dry-run `SIMULATION_FAILED`) and are PURE. LIMITATION_ASSERTED: closed caller schema (a caller-supplied idempotency key refuses `X402_CALLER_INPUT_INVALID`); the route surface is attempts-only. |
| C20 | AP2: a REAL ES256 SD-JWT payment mandate drives verify → normalize → dry run → REAL durable build; the destination is the payee-DIRECTORY-resolved, covenant-allowlisted key — never mandate content (`normalized.recipientXOnly` asserted). Same-intent `txId`/`manifestHash` equivalence with the JS reference build; cross-path request reads identical. Derived idempotency on `transaction_id` (replay converges; same id + different amount conflicts). A foreign-vault instrument surfaces the platform's existence-hiding `VAULT_NOT_FOUND` verbatim. LIMITATION_ASSERTED: restrictive-only destination double binding (`AP2_PAYEE_UNKNOWN`, `AP2_PAYEE_NOT_ALLOWLISTED` — pure, free refusals; a valid signature proves authorship, never authorization); mandate-only route surface. Amount-boundary honesty: the PolicyVault-side amount is the canonical sompi STRING (`normalized.payAmountSompi`, asserted); the mandate's own `payment_amount.amount` is AP2's minor-unit INTEGER echoed verbatim as verification evidence (external-protocol field, asserted explicitly in the scenario rather than silently exempted from C17). |

**Reservation honesty (C14, FLIPPED — gap closed):** per
`docs/postlaunch/fullscale-gap-analysis.md` surface 15 and
`docs/postlaunch/budget-reservations.md`, every v4 agent-spend build now
takes a **durable pre-build period-budget reservation** scoped to the
predecessor-outpoint context (`sdk/src/budget-reservation.js`). The cell
proves it end-to-end on a tight-budget vault: an in-budget build creates
a durable ACTIVE reservation; a different-key build that no longer fits
the window's remaining headroom refuses at build time with
`422 BUDGET_RESERVED_EXCEEDED` (deterministic message naming the holding
requestId; nothing durable created; identical refusal via Python);
rejecting the holder releases the reservation and the rebuild succeeds.
The mitigation structure is still asserted on VAULT_A: two
different-key builds of the same in-budget intent are both durable,
commit to the **same exact transaction**, and now EACH holds its own
ACTIVE reservation — the covenant admits at most one on chain, the
finalize-time claims still serialize before broadcast, and the covenant
remains the only financial authority (a delegate submitting directly to
a node is refused by consensus, not by this coordination layer). If
reservation semantics change again, the cell fails and the matrix must
be deliberately re-classified.

## 4. Normalized outcome + equivalence rules

Every driver reduces its native result to
`{ ok, httpStatus, code, body, replayed, errorType }`
(`conformance/lib/normalize.js`). Rules:

1. **`ok` and the server's `error.code` are compared across every path.**
   A refusal must be the same refusal everywhere.
2. **`httpStatus` is compared wherever a path exposes one** for that
   outcome (the JS client hides status on success by design; Python typed
   methods likewise; raw/MCP always carry it; all error paths carry it).
3. **Bodies are compared as data.** Same-record reads and deterministic
   pipelines (discovery, simulation, refusal envelopes, event pages) are
   compared **deep-equal, byte-for-byte**. Where records embed volatile
   per-record values (uuids, timestamps), comparisons go through
   `pick()` (stable fields) or `prune()` (volatile keys removed) — never
   ad-hoc per-path exceptions.
4. **Client convenience shapes are documented, not penalized**: the
   Python client returns bare lists where the wire wraps
   (`vaults`/`events`/`requests`/`proposals`); the JS client auto-stamps
   an `Idempotency-Key` on POSTs unless told otherwise (suppressed where
   a wire-identity comparison needs the unkeyed envelope). Equivalence is
   about the DATA and the DECISION, which must be identical.
5. **`errorType` is never compared cross-path** — it is each path's
   native error taxonomy, recorded for evidence only.

## 5. Amount hygiene (CLAUDE.md numeric safety, mechanical)

`assertAmountHygiene` walks any response: keys matching `/sompi$/i` or in
the named amount set (`protectedValue`, `feeReserve`, `maxPerSpend`,
`periodBudget`, `periodSpent`, `approvalThreshold`, `agentMaxFeePerTx`,
`outpointValue`, `fee`, `amount`, `value`, …) must be canonical decimal
STRINGS; `/Kas$/` display fields must be strings; and any JSON number
anywhere must be a safe integer (counters/indices only). Applied to
bodies from all registered paths (C17 walks the whole collected corpus,
adapter outcomes and the x402 attempt record included; the AP2 record's
external-protocol minor-unit integer is asserted explicitly in C20 — see
the scenario table).

## 6. Idempotency semantics proven

- caller-keyed (JS/Python/raw): claim-CAS admits ONE execution per
  `(principal, key)`; durable outcomes (2xx and <500 refusals) replay
  verbatim with `idempotency: { replayed: true, key }`; different body
  under the same key is `409 IDEMPOTENCY_KEY_CONFLICT`; concurrent
  duplicates see `409 IDEMPOTENCY_IN_PROGRESS` or the replay.
- MCP (derived): `mcp1-` + sha256 of canonical `{v, tool, id, args}` —
  the suite proves a NEW session of the same credential replaying the
  same JSON-RPC id + identical args receives the ORIGINAL durable
  outcome (`replayedIdempotency: true`), the funds-conservative failure
  mode.

## 7. Documented-limitation assertions (must FAIL on silent drift)

Declared in `conformance/paths.js` and mechanically asserted in C08, C06,
C15, C10, C16:

- **Python has NO local verification** (`python-client-spec.md`
  asymmetry): the package module list is pinned EXACTLY
  (`__init__ amounts client errors schemas transport py.typed`) and no
  client/package attribute may match
  `/verif|successor|sighash|fee_mass|feemass|preflight|compile/i`.
  A "fake verifier" appearing in the Python tree fails the suite until
  the divergence is deliberately re-classified. (Route-call methods like
  `reconcile_vault` — where the SERVER does the work — are transport and
  stay allowed.)
- **MCP v1 catalog is EXACTLY 14 tools**, mutating subset EXACTLY
  `{policyvault_create_request, policyvault_reject_request}`; no
  approval/sign/submit/events/webhook/identity tool; every input schema
  closed (`additionalProperties: false`); `destructiveHint`/
  `openWorldHint` false everywhere. An undocumented mutating tool fails
  the suite.
- **MCP cannot supply an Idempotency-Key** (`SCHEMA_REFUSED` on the
  attempt) and **cannot express a schemaVersion override** (structural
  pin: the field is refused locally, `httpStatus: null` proving nothing
  was transmitted).
- **JS hosts the core**: `sdk.intent.verifyIntentManifest` must exist —
  the verifier the other paths' documentation defers to.

`LIMITATION_ASSERTED` in the artifact is a GREEN outcome: the documented
absence was verified present. It is never a skipped cell.

## 8. Adding a path (future clients; the x402 / AP2 adapters are DONE)

The x402 and AP2 protocol-adapter paths were registered through exactly
this procedure (W4-refinements): declarations in `conformance/paths.js`
(narrow capability subsets — `build` + `derivedIdempotencyKey` true,
everything else asserted absent; internal discovery/vault-read/simulate
pipeline stages are NOT caller-drivable ops and are declared absent),
drivers `drivers/x402-driver.js` / `drivers/ap2-driver.js` booting the
REAL adapter services, and scenarios C19/C20 wiring their cells plus the
C11/C17 hygiene corpora. For the next path:

1. **Register** in `conformance/paths.js` (`registerPath({ id, surface,
   kind, capabilities, limitations, notes })`) — the capability
   vocabulary is closed; extend it deliberately. External modules can
   register via `POLICYVAULT_CONFORMANCE_EXTRA_PATHS=/abs/mod.js`
   (module exports `register({ registerPath })`).
2. **Provide a driver** exposing the ops for each declared capability,
   returning the normalized outcome shape of §4. The op names to match
   are those on `JsDriver`/`PyDriver` (`capabilities`, `listVaults`,
   `getVault`, `vaultAudit`, `auditFeed`, `simulate`, `buildRequest`,
   `getRequest`, `listRequests`, `rejectRequest`, `submitApproval`,
   `pollEvents`, `getProposal`, `listProposals`, `getRiskEvaluation`,
   `raw`). A protocol adapter that only translates external payment
   requests into intents declares the narrow subset it truly has (per
   its spec §"scopes": typically `discovery, vaultReads, requestReads,
   simulate, build` + its own limitation strings).
3. **Wire it into the matrix**: add its cells to the scenarios its
   capabilities cover, plus limitation assertions for what it must NOT
   be able to do (the adapter specs' forbidden-scope tables are the
   source of those assertions).
4. A subprocess path MUST route credentials via environment (never argv)
   and its stdout/stderr MUST be captured into the C11 hygiene scan.

## 9. Environment notes (honest classification)

- The build pipeline shells out to gitignored Cargo artifacts
  `tests/vm/target/debug/{pv_call_encoder, pv_tx_probe, pv_vm_preflight}`.
  A git WORKTREE cannot `cargo build` them (Cargo cannot resolve the
  sibling `../silverscript` path), so they are **copied from the main
  checkout** — the same documented procedure the Python client suite
  uses. Their absence fails the suite `before()` hook with an explicit
  ENVIRONMENT message; it is never a driven-surface defect.
- Requires `python3` on PATH, the kaspa-wasm module at the configured
  `rustyKaspaModule` path, and silverc at the configured `silvercPath`.
- No live Kaspa node is used or required.

## 10. Evidence format (what an RC record cites)

`conformance/results/conformance-summary.json`, schema
`policyvault-conformance-results/v1`:

```json
{
  "schema": "policyvault-conformance-results/v1",
  "suite": "agent-integration-conformance",
  "startedAt": "…", "finishedAt": "…",
  "server": { "networkId": "testnet-10", "apiVersion": "v1", "buildId": "…?" },
  "paths": [ { "id": "js", "surface": 9, "kind": "…",
               "capabilities": { … }, "limitations": [ … ] }, … ],
  "totals": { "PASS": 61, "LIMITATION_ASSERTED": 6 },
  "results": [ { "scenario": "C05-build-and-status", "path": "mcp",
                 "outcome": "PASS", "note": "…" }, … ]
}
```

Outcome vocabulary: `PASS`, `LIMITATION_ASSERTED` (green — documented
absence verified), `FAIL` (the run's tests also fail), `SKIPPED_ENV`
(environment gap), `N/A`. The artifact is written even when a scenario
fails (the `after()` hook), so a red run still leaves citable evidence.
The `results/` directory is gitignored; an RC record checks in the
specific run's copy it cites. The credential-hygiene scenario scans the
rows before they are written, so the artifact itself is secret-free.

## 11. Claim labels (honest)

- Suite: **IMPLEMENTED + INTEGRATION-TESTED against the real platform**
  (real server, real subprocess clients, real adapter services, real
  covenant compiler + call-encoder in every build) — two consecutive
  fully-green runs on this tree, including the W4 protocol-adapter paths
  (5 paths, 20/20, 79 cells).
- NOT claimed: live-testnet/live-node behavior (out of scope here),
  external review.
