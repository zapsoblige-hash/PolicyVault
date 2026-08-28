# Pre-build period-budget reservations (full-scale surface 15)

Status: **IMPLEMENTED + UNIT/ADVERSARIAL/CRASH/PG-TESTED + conformance-
asserted** (W4-reservations). Not TESTNET-VERIFIED as a distinct layer —
it changes no consensus-visible bytes (asserted by test), so covenant
claims are unaffected.

Module: `sdk/src/budget-reservation.js`. Wiring:
`sdk/src/wallet-requests-v4.js` (build/finalize/reject),
`sdk/src/wallet-submit-v4.js` (stale/definitive-rejection/chain-verified),
`sdk/src/reconcile-v4.js` (stale-claim release).

## 1. The gap this closes

Before this layer, concurrent v0.4 agent-spend BUILDS all validated
against the same durable manifest state: each proved
`periodSpent + pay <= periodBudget` independently, so N open requests
could together promise more headroom than the period budget holds. The
first exclusivity arbitration happened only at FINALIZE (the transition
claim on the predecessor outpoint), and financially on chain (the
covenant). The conformance suite asserted this honestly (the C14
"reservation honesty" cell); that cell now asserts the closed behavior.

## 2. Truth discipline (unchanged, permanent)

- **The Kaspa covenant is the ONLY financial authority.** A reservation
  is an availability/coordination layer that keeps the build pipeline
  honest about headroom already promised to open requests. It prevents
  wasted builds/signatures/approvals and optimistic over-commitment.
- **It is NOT a security boundary.** An actor holding the legitimate
  delegate key who constructs transactions independently of the
  application and submits them directly to a node bypasses this layer
  entirely — and the covenant refuses over-budget spends on chain
  regardless. Authorized testnet negative-validation transactions
  constructed independently of the PolicyVault application continue to
  verify exactly that.
- **No consensus-visible byte changes.** Reservations run strictly
  outside the builder/encoder/finalizer. The frozen transaction for a
  given build is byte-identical with the layer in place
  (`budget-reservation.test.js` byte-identity case compares the pipeline
  output against the raw `buildV4Transaction` output: same txId, same
  `frozenCanonicalJson`).
- The finalize-time transition claim (`submission-claim.js`) REMAINS the
  pre-broadcast exclusivity arbiter. The reservation never replaces or
  weakens it.

## 3. Storage (no migration; JSON + PG parity by construction)

Records live in the existing `TRANSITION_CLAIM` store category (PG table
`transition_claims`, JSON dir `claims/transition/`) under key prefixes
that can never collide with a transition-claim key
(`<64-hex-txid>-<index>`):

- `resv-<vaultId>-<agentPk>-<requestId>` — one reservation per request,
  created with `createExclusive` (link()/EEXIST — INSERT ... ON CONFLICT
  DO NOTHING). Schema `policyvault-budget-reservation/v1`.
- `resvlock-<vaultId>` — the short-lived per-vault admission lock.
  Schema `policyvault-reservation-lock/v1`.

Transition claims are read only by exact outpoint key, so no existing
reader interprets these records; both backends keep identical
list/read/create/remove semantics with **no schema migration**.

## 4. Admission (where the new refusal comes from — and only it)

Admission runs in `buildWalletRequestV4`'s persist path, for
`agentSpend` only, AFTER the real SDK builder succeeded and BEFORE the
durable request is written. The window math re-uses the builder's own
canonical outputs (`callExtra` + `accounting`) with the exact
`deriveSuccessorRegistry`/covenant rule:

```
windowStartDaa = periodsElapsed >= 1
    ? periodStartDaa + periodsElapsed * periodLengthDaa : periodStartDaa
newSpent       = periodsElapsed >= 1 ? pay : periodSpent + pay
```

The builder has already enforced `pay <= maxPerSpend` and
`newSpent <= periodBudget` for the single spend (per-spend cap + single-
spend budget), so admission adds ONLY the cross-request cumulative rule,
under the per-vault lock:

```
newSpent + SUM(open reservations, same window, same predecessor outpoint)
    <= periodBudget
```

- Violation → `BUDGET_RESERVED_EXCEEDED` (HTTP 422 through the existing
  v4 error mapping) with a deterministic message naming the reserved
  amount and the holding requestId(s). PURE: nothing durable created.
- Every pre-existing refusal surface (caps, pause, proofs, recipients,
  budgets for a single spend, …) still comes from the real builder with
  its unchanged codes — no behavior change for non-concurrent callers.
- Rollover windows (`periodsElapsed >= 1`) are independent budgets;
  mixed-window builds against one outpoint coexist (at most one lands on
  chain; the others sweep on advance).
- Owner operations, genesis builds, v2 flows, and dry-run simulation
  (`server/src/simulate.js` calls the pure builder directly and persists
  nothing — dataroot-snapshot-proven) take NO reservation.

Concurrency: the admission lock (`createExclusive` + deterministic
stale-reclaim at 30 s, mirroring server idempotency's IN_PROGRESS
pattern) serializes list+sum+create per vault. A live holder makes a
contender retry briefly, then fail closed `RESERVATION_BUSY` (pure,
retryable).

## 5. Lifecycle

- **ACTIVE** — taken immediately before `saveRequest`. A crash between
  the two leaves an orphan, reclaimed deterministically (below).
- **CONSUMED** — at finalize, after `claimTransition` +
  `claimSubmission` succeed; ties the finalized txId. Consumed
  reservations KEEP counting against their window until the manifest
  advances (the spend is in flight on this state).
- **Released** (removed) when the owning request dies:
  `markWalletRejected` (the reject routes), every finalize fail-closed
  transition (STALE / AUTHORIZATION_FAILED / SIGNATURE_INVALID /
  WALLET_REJECTED / INSUFFICIENT_APPROVALS / PREFLIGHT_FAILED /
  CLAIM_CONFLICT), submit-time STALE, definitive node rejection
  (mirrors the claim release), CHAIN_VERIFIED (accounting now lives in
  the registry's `periodSpent`), and reconciliation's stale-claim
  release (the one path the sweep cannot infer: the predecessor is still
  live there). `releaseReservationForRequest` is guarded by the embedded
  requestId, idempotent, and never throws into a caller's failure path.
- **Swept** (deterministic, self-healing, under the admission lock):
  - context-stale: `predecessorStateId` OR `predecessorOutpoint` no
    longer match the live manifest state. The OUTPOINT is the primary
    context key — the same stateId can legitimately recur at a different
    outpoint (spend then top-up back), and headroom promised against a
    consumed outpoint must never bind the new one;
  - request-released: the durable request reached a released state but
    the release hook was missed (crash between the two writes);
  - orphans: ACTIVE, older than 5 minutes, with no durable request
    (crash between reservation and `saveRequest`).

An abandoned open request holds its reservation deliberately — an open
request IS a promise of headroom. The existing open-request quota caps
accumulation; reject frees it.

## 6. Fail-closed rules

- Unknown reservation schema versions in scope → `RESERVATION_UNRECOGNIZED`
  (admission refuses; unknown versions are never ignored or defaulted).
- Unreadable/corrupt reservation record → `RESERVATION_RECORD_CORRUPT`
  (admission refuses, naming the key — silently skipping would
  under-count and re-open the over-commit gap).
- A doctored record whose embedded requestId mismatches its owner →
  `RESERVATION_FORGERY` on consume. Keys embed the owner requestId, so a
  request can only ever consume/release its own reservation;
  `createExclusive` forbids overwriting an existing one.
- Idempotency interplay: same-key concurrent builds already admit
  exactly one execution (one reservation); a durable
  `BUDGET_RESERVED_EXCEEDED` refusal is recorded per idempotency key
  like every 4xx — after headroom frees, rebuild with a NEW key (the
  documented pattern).

## 7. Evidence

- `sdk/test/budget-reservation.test.js` — 17/17 (JSON backend): unit
  (reservation shape, owner no-op, AWAITING_APPROVALS holds, byte
  identity), adversarial (concurrent one-winner + named holder,
  reject→rebuild, finalize-consume + exact-boundary admission, rollover
  independence, forgery, unknown-schema, corrupt-record, lock
  stale/live), crash-recovery (orphan reclaim + fresh-orphan kept,
  missed-release sweep, outpoint-context sweep), simulate
  zero-persistence snapshot.
- `sdk/test/budget-reservation-pg.test.js` — 3/3 on real PostgreSQL
  (fresh ephemeral DB; clean skip without env): rows live in
  `transition_claims`, claims untouched, real concurrent race, full
  lifecycle parity.
- `conformance/agent-conformance.test.js` C14 platform cell — FLIPPED to
  assert enforcement end-to-end (18/18 tests, 67 cells green).
- Targeted regression on the changed pipeline: wallet-requests-v4 6/6,
  wallet-submit-v4 4/4, api-v4 7/7, idempotency+claims 16/16,
  wallet-v4-hostile 13/13, mainnet-gate-r 11/11.
