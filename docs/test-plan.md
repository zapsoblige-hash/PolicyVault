# PolicyVault Test Plan

Layered test architecture (mission §35), current suites, and the standing
rules that keep the layers honest.

**Release-gate binding (2026-08-16):** the mandatory testing gates for
production release live in `docs/production-completion-checklist.md` —
complete VM negative-validation matrix (gate E, extended to v0.3),
complete SDK/API/browser tests (gate F), property/fuzz testing (gate G,
Phase 5), and crash/concurrency/reconciliation hardening (gate H). The
property/fuzz layer is MANDATORY and currently OPEN: targets include
canonical amount parsing, state serialization, state IDs, the encoder,
recipient proof parsing (v0.3), signature/approval sets (v0.3), policy
migrations, nonce progression, the request state machine, claims,
reconcile, crash/restart, concurrent mutations, malformed/truncated
persisted JSON, duplicate/stale requests, and signer account/network
changes. Crashing inputs become regression fixtures, and no "fuzzing
passed" claim is valid without target, seed/corpus strategy, run
count/time, discovered defects, and regression status. v0.2 regression
coverage is never removed by v0.3 work.

## Layers and where they live

| Layer | Suite | Count (2026-08-13) |
|---|---|---|
| UNIT | `sdk/test/{amounts,vault-state,contract-compiler,vault-state-v2,fee-mass}.test.js` | part of SDK 60 |
| SDK / INTEGRATION | `sdk/test/{claims,manifest,organization,encoder-boundvaultid,v2-reconcile,v2-claims-adversarial}.test.js` | part of SDK 60 |
| VM (valid paths) | `tests/vm/tests/{happy_path,v2_happy_path}.rs` | 9 + 14 |
| ADVERSARIAL VM | `tests/vm/tests/{adversarial,v2_adversarial}.rs` | 35 + 32 |
| VM lineage/architecture gates | `tests/vm/tests/{v2_lineage_experiment,v2_compute_budget,v2_live_shape}.rs` | 11 + 1 + 2 |
| **Production-byte integration** | `tests/vm/tests/v2_encoder_integration.rs` (+ `pv_replay_probe`, `pv_compile_probe` bins) | 9 |
| Fee/mass golden vectors | `pv_mass_probe` (rusty-kaspa MassCalculator) ↔ `sdk/test/fee-mass.test.js` | 9/9 shapes |
| LIVE TESTNET lifecycle | `tools/testnet-v2-lifecycle.js` (v0.2), `tools/testnet-{create,spend,lifecycle,recover}.js` (v0.1) | evidence in docs/testnet-evidence.md |
| CRASH-RECOVERY / CONCURRENCY (live) | `tools/testnet-v2-crash.js` (5 cases) + `tools/testnet-crash-recovery.js` (v0.1) | evidence in docs/testnet-evidence.md |
| v0.3 UNIT/SDK (Phase 4H) | `sdk/test/{vault-state-v3,recipient-merkle-v3,vault-transitions-v3,compute-budget-v3,frozen-tx-v3,approval-package-v3,vault-builders-v3,covenant-generator-v3}.test.js` | part of SDK 194 |
| **v0.3 SDK production-byte gate** | `tests/vm/tests/v3_sdk_integration.rs` — the REAL SDK (node) builds 26 finalized vectors (genesis + 11 entrypoints, depth/threshold/worst-case matrix, malformed-state recover, 5 consensus-negative mutations); every vector executes on the real TxScriptEngine against the production covenant under production sig-op pricing with the SDK's own committed budgets | 3 tests / 26 vectors |
| v0.3 consensus probes | `pv_tx_probe` (frozen-tx txId/sighash/approval verification via real consensus code) + `pv_call_encoder` v0.3 dispatch + `pv_mass_probe` v0.3 shapes | bins driven by SDK + tests |
| v0.4 DESIGN experiments (isolated) | `tests/vm/tests/v4_experiment_fee_reserve.rs` (11) + `tests/vm/tests/v4_experiment_multi_agent.rs` (11) against `contracts/experiments/V4{Fee,Agent}Probe.sil` — real VM, real Schnorr; falsification pass for the fee-reserve isolation and multi-agent authority separation. DESIGN ONLY; not a production path | 22 |
| HOSTED AUTH (Phase B) — hostile matrix | `sdk/test/hosted-auth.test.js` — UNIT (auth service over the pinned kaspa-wasm `signMessage`/`verifyMessage`, real Schnorr) + API (real server over HTTP: challenge/verify/session/logout, cookie attributes, disabled-mode 404). Challenge canonicalization, single-use nonce + release-on-failure, atomic consumption, session entropy/hash-at-rest, expiry/inactivity/rotation, identity binding, custody-boundary assertions | 29 |
| HOSTED AUTH sabotage | `sdk/test/hosted-auth-sabotage.test.js` — real in-source neutralization (byte-identical restore) of single-use, pubkey↔address equality, server message reconstruction, absolute-expiry, logout revocation; each guard's test shown to go red | 6 (+1 integrity) |
| HOSTED AUTH property/fuzz | `sdk/test/hosted-auth-fuzz.test.js` — bounded fuzz of challenge/verify/cookie/session parsers: never crash, never false-accept, always a structured fail-closed error | 4 |
| HOSTED PERSISTENCE (Phase C) — PG integration + JSON↔PG equivalence | `sdk/test/hosted-pg-integration.test.js` — REAL local PostgreSQL (self-skips without `POLICYVAULT_TEST_PG_*`): migrations (fresh/re-run/future-version-fail-closed), per-category CRUD, the UNIQUE claim arbiter, network-composite isolation, transaction rollback (all-or-nothing), restart durability, and JSON↔PG behavioral equivalence | 10 (PG) |
| HOSTED PG AUTH (Phase C) | `sdk/test/hosted-pg-auth.test.js` — Phase B auth on PostgreSQL: cross-process single-use challenge (two service instances / one DB → one success), concurrent-verify CAS, session/revocation/expiry survive restart, hash-only token storage, UNIQUE nonce | 8 (PG) |
| HOSTED TENANCY (Phase C) — multi-user hostile matrix | `sdk/test/hosted-tenancy.test.js` — REAL HTTP + hosted auth + PG, wallets A/B/C, REAL foreign ids: org + vault read/mutate isolation (404 hides existence), body-cannot-rebind-identity, unauthenticated refusal, vault→org assignment isolation, org-role ≠ covenant authority, session non-transfer, positive controls | 11 (PG) |
| HOSTED CONFIG MATRIX (Phase C) | `sdk/test/hosted-config-matrix.test.js` — fail-closed config interlocks: backend selection, dangerous hosted combos (multi-user PG without auth refused), TLS/cookie/mainnet guards, pool bounds, no-lazy-dial/no-JSON-fallback | 9 |
| HOSTED REQUEST PROTECTION (Phase D) — origin/Host hostile matrix | `sdk/test/hosted-request-protection.test.js` — real HTTP: hosted application-origin enforcement (cross-origin/null/malformed refused; Sec-Fetch-Site fallback; mismatch never rescued), Host allowlist + DNS-rebinding guard on API and static, HTTP/1.0 no-Host, loopback allowance, extra-hosts config, self-hosted released semantics preserved, header set (HSTS on https origins only, Permissions-Policy, CORP/COOP), OPTIONS/no-CORS, parser unit shapes | 18 |
| HOSTED RATE LIMITS (Phase D) | `sdk/test/hosted-rate-limit.test.js` — per-class budgets with Retry-After, window refill, PURITY (429 creates nothing durable), trusted-proxy bucket separation + malformed-value fallback, session-keyed budget across IPs (real Schnorr sign-in), self-hosted off-default, hosted off-switch refused at config, limiter memory bound under key spraying | 9 |
| HOSTED DoS GUARDS (Phase D) | `sdk/test/hosted-dos-guards.test.js` — Semaphore unit semantics (FIFO queue, saturation refusal, idempotent release), route-classification table, HTTP compute saturation + exception-safe release over real v4 builds, slow-client header/body stall cutoffs (explicit per-socket deadlines — Node's own checker proven inert on this runtime), JSON depth cap, audit listing clamp | 6 |
| HOSTED OPEN-REQUEST QUOTA (Phase D) | `sdk/test/hosted-quota.test.js` — per-vault + per-wallet abandoned-request caps enforced before build work, cancellation frees quota, v2-route guard position, family-agnostic state counting, refusal purity, default/validation checks | 6 |
| HOSTED PROTECTION sabotage | `sdk/test/hosted-protection-sabotage.test.js` — real in-source neutralization (byte-identical restore) of the origin exact-match, Host allowlist, rate-limit refusal, and semaphore queue bound; each guard shown load-bearing | 5 (+1 integrity) |
| HOSTED DEPLOYMENT (Phase E) | `sdk/test/hosted-deployment.test.js` — deployment-posture config validation (bindAddress/buildId/stagingBanner/dataRoot env, all fail-closed), /health build identity, /health/ready readiness semantics (json + postgres; NEVER ready with the DB gone), pg-pool idle-error survivability regression (a PostgreSQL restart must not kill the process), the standalone migrator as a REAL child process (fresh/idempotent/TWO CONCURRENT migrators serialize), and server startup order as a real child process (unreachable DB refuses to listen; unmigrated schema refuses; migrate-then-serve ready; mainnet-without-dual-unlock refuses), plus the Phase E-R compose regression (the migrate service must OVERRIDE the image ENTRYPOINT — `command:` is appended to it and silently runs the server) | 14 (10 PG) |
| HOSTED DEPLOYMENT sabotage | `sdk/test/hosted-deployment-sabotage.test.js` — real in-source neutralization (byte-identical restore) of the startup DB-open gate (server listens with a dead database), the postgres readiness branch (/health/ready lies), and the database network-stamp comparison (foreign-network DB opens); each shown load-bearing | 4 (3 PG +1 integrity) |
| IMAGE SCAN CLASSIFY (Phase E-R) | `sdk/test/image-scan-classify.test.js` — drives `tools/image-privacy-scan.sh --classify-paths` (the EXACT layer-walk path logic, no docker): every private-material path class still fails; the four benign classes classified against the REAL image (public CA store `.pem`, `usr/lib/ssl/cert.pem` bundle symlink, empty `var/backups/` entry, node_modules `keys/` module dirs) are filtered; the filter is proven no wider than its classification | 4 |
| PHASE F HOSTILE MULTI-USER | `sdk/test/hosted-phase-f-hostile.test.js` — real server + PG + three distinct wallets (A/B/outsider C) + real Schnorr sign-in. The wallet-request pipeline tenancy boundary (Findings F-1/F-2/F-3): the v4 open-request LIST is tenant-scoped (no cross-tenant leak, no vaultId oracle); request DETAIL by id (v4 + v2) 404s a foreign id (existence hidden); outsider C sees nothing; unauthenticated is 401; A cannot REJECT/cancel B's request (durable state unchanged); a body/proxy-header claiming to be B cannot rebind the session principal; positive control (B reads/rejects its own); global `GET /audit` is tenant-scoped; and (no-PG) a hosted auth signature is message-bound and domain-separated from transaction signing (§32) | 11 (10 PG) |
| PHASE F SABOTAGE | `sdk/test/hosted-phase-f-sabotage.test.js` — neutralizes the new `server/src/tenancy.js` `requestAccessAllowed` guard in-source (default-deny removed; hosted enforcement bypassed), proves it is load-bearing (a foreign/unauthenticated principal is wrongly allowed → RED), then restores `tenancy.js` BYTE-IDENTICALLY | 4 |
| BROWSER v4 ERROR RENDER (Phase G, defect G-1) | `sdk/test/browser-v4-error-render.test.js` — jsdom + real served markup + real production `web/app-v4.js`; the hosted `{error:{code,message}}` envelope must surface its MESSAGE (never "[object Object]") in the vaults view, and postJSON failures must expose BOTH envelope code and message to notices (found by the real-KasWare Phase G human run: a session-expiry 401 rendered unreadably) | 2 |
| CANONICAL JSON (Phase G, defect G-2) | `sdk/test/canonical-json.test.js` — key-order-independent commitment serialization: object-key order never changes output, array order and values always do, JSON.stringify primitive equivalence, strict fail-closed rejection of undefined/BigInt/NaN/non-plain objects | 3 |
| APPROVAL PACKAGE STORAGE ROUNDTRIP (Phase G, defect G-2) | `sdk/test/approval-package-storage-roundtrip.test.js` — faithful PostgreSQL-jsonb key-reorder transform over fully-shaped v0.3 AND v0.4 approval packages: the commitment must be IDENTICAL across the reorder (the pre-fix preimage was key-order-sensitive and voided real collected approvals in the Phase G human run) while every tested value mutation must still change it (guard not weakened) | 3 |
| HOSTED PG APPROVAL LIFECYCLE (Phase G, defect G-2) | `sdk/test/hosted-pg-approval.test.js` — the FULL above-threshold agent-spend lifecycle (build → approval #1 → approval #2 → agent finalize → VM preflight) with the durable request/approval package persisted in a REAL PostgreSQL database; pre-fix this reproduced the exact production PACKAGE_MUTATED failure at approval #2 | 1 (PG) |

Totals as of 2026-08-16 (commit abb0aed): **SDK 118 PASS, VM 113 PASS,
fee/mass 9/9.** (The SDK suite has since grown: wallet-adapter/identity
contract + pubkey-normalization tests, address-identity UNIT vectors,
BROWSER identity-flow tests, wallet authorization/classification
regressions, and operational-status UNIT tests.)

## Standing rules

1. **Production-byte rule.** Any component that can change consensus-visible
   bytes (call encoder, exact-state compiler, state/transaction serializer,
   signed-package finalizer) must have an integration test that drives its
   exact output through the downstream validator — the real TxScriptEngine
   or the live node. A harness that rebuilds equivalent bytes in-process
   does not count: that blind spot shipped the v0.2 `boundVaultId` encoder
   defect (100% VM pass, every live transaction rejected). Component
   inventory and coverage map: `docs/v02-production-boundary-audit.md`.
2. **Baselines never shrink.** v0.1's 44 VM tests are frozen; new work adds
   suites rather than rewriting old ones to reach a count.
3. **Failure classification before fixes.** CONTRACT BUG / PRODUCTION CODE
   BUG / TEST BUG / ENVIRONMENT / STALE ASSUMPTION / DEPENDENCY CHANGE /
   UNKNOWN — and funds-safety code is never weakened to satisfy a broken
   harness.
4. **Exact-fee regression gate.** Every live transaction asserts
   `requiredFeeSompi == actualFeeSompi` in its receipt; `pv_mass_probe`
   golden vectors must stay green; new transaction shapes get a golden
   vector only when technically necessary.
5. **Crash/concurrency proofs are durable-state proofs.** Unit level: every
   durable state a crash can leave (claim present/absent × predecessor
   live/consumed × effect proven/unproven) has a reconcile test with the
   exact proof-of-effect standard. Live level: post-broadcast crashes,
   claim conflicts, and stale signed packages are re-proven on testnet-10
   (`tools/testnet-v2-crash.js`).
6. **Mutation-check new integration tests.** A test that guards a
   production boundary must be shown to FAIL when the historical defect is
   reintroduced (done for the encoder index defect).
7. **SDK test files run serially** (`node --test --test-concurrency=1`,
   the `npm test` script). The sabotage-sensitivity suites neutralize
   guards by REAL in-source mutation with byte-identical restore; under
   concurrent per-file child processes another file can `require()` a
   module inside that mutation window and fail spuriously (observed
   2026-08-23: `live-layer-sabotage-v4_1` §G4's `isDefinitiveSubmitRejection
   → return true` window made `submit-classification-v4_1` §24 classify ""
   as definitive — TEST BUG, harness concurrency, production code correct).
   Serial execution structurally removes the entire cross-file
   mutation-window class; do not remove the flag while any suite mutates
   shared source on disk. (Suites that mutate source in place as of
   Phase F: `hosted-auth-sabotage` → server/src/auth.js,
   `hosted-protection-sabotage` → server/src/limits.js,
   `live-layer-sabotage-v4_1` → sdk sources,
   `hosted-deployment-sabotage` → server/src/server.js,
   server/src/api.js, sdk/src/store.js,
   `hosted-phase-f-sabotage` → server/src/tenancy.js.)

**Checkpoint B (2026-08-18) additions:** `tests/vm/tests/v4_experiment_combined.rs`
(12) drives the frozen-design combined probe `V4CombinedProbe.sil` through
the full hostile matrix (fee-reserve abuse, cross-agent theft, the
funds-critical agent-tree-update proof, approvals, period accounting,
pause, recovery, owner-op field preservation, depth bound);
`tests/vm/tests/v4_experiment_migration.rs` (2) proves the real production
v0.3 covenant rejects a v0.4-template successor. DESIGN experiments only;
not a production path. v0.4 ABI is FROZEN (`docs/covenant-spec-v0.4.md`).

**Checkpoint C (2026-08-18):** v0.4 is now the production covenant
`contracts/PolicyVault.v0.4.sil` (generator `tools/gen_v4.js`, byte-identical
regen). `tests/vm/tests/v4_production.rs` (production covenant, valid +
mutation matrix + stack/budget measurement) and
`tests/vm/tests/v4_encoder_integration.rs` (real `pv_call_encoder` binary,
all 8 entrypoints + mutation matrix — the production-byte gate) prove the byte
path; `sdk/test/vault-state-v4.test.js` proves the SDK compiler is byte-exact
(state 441 B); `sdk/test/fee-mass.test.js` carries the v0.4 golden vectors.
v0.1/v0.2/v0.3 covenants + fee-mass core byte-identical; the pv_call_encoder
v0.4 arm is additive. v0.4 is PRODUCTION-BYTE-PROVEN, NOT live-testnet-verified.

**Checkpoint D (2026-08-18) — MAX-REVIEWED:** `v4_production.rs` gained 4
independent hostile tests (VM 237→241): `d_byte_facts_and_state_layout`
(reproduce redeem 18,839 B + 441 B state region field-by-field from the
compiled script), `d_num8_large_value_injectivity` (num8 injective at
2^32/2^53/large), `d_rollover_cltv_finalization_and_boundary` (finalized-input
CLTV bypass + lock_time boundary rejected), `d_agent_delete_insert_move_rejected`
(structural tree edits rejected). A deliberate-sabotage matrix confirmed 8/8
funds/authority rules are enforced (each break turns its guard test red, 0 blind
spots). Production covenant bytes UNCHANGED (SHA256 8f87dea…). MAX-REVIEWED is
an internal hostile review, not an external audit.

**Checkpoint E (2026-08-18) — high-level SDK construction layer (OFFLINE):**
the v0.4 transaction-construction SDK now exists and is production-byte proven.
New SDK unit/adversarial suites: `sdk/test/agent-merkle-v4.test.js` (13; leaf
bytes, canonical order, unspendable padding, single-leaf update preserving
unrelated leaves, full proof-forgery matrix), `sdk/test/vault-transitions-v4.test.js`
(10; 8-entrypoint successor derivation, field-preservation matrix, nonce rules,
fail-closed matrix), `sdk/test/compute-budget-v4.test.js` (3),
`sdk/test/recipient-v4-compat.test.js` (4; the reused v0.3 recipient tree
reproduces the v0.4 covenant walk byte-for-byte), `sdk/test/vault-builders-v4.test.js`
(12; reserve/fuel funding, freeze-before-approval, approval collection,
finalization mutation detection, staleness, owner ops, recover, genesis).
New production-byte gate: `sdk/tools/gen-v4-vectors.js` drives the REAL SDK to
build 42 finalized transactions executed on the real `TxScriptEngine` against
the production covenant by `tests/vm/tests/v4_sdk_integration.rs` (3) — 19
accept (each sufficient under its committed budget at production pricing) + 23
negative (§E11 mutation matrix, all consensus-rejected). SDK 201→243; VM
241→244. Production covenant bytes UNCHANGED. OFFLINE; NOT live-testnet-verified.

**Checkpoint F (2026-08-18) — MAX hostile review of the v0.4 SDK layer:**
new adversarial suites `sdk/test/v4-hostile-review-f.test.js` (11; interleaved
accounting, recipient-reuse boundary, caller-injection, independent
conservation, cross-package approval migration, deep-freeze aliasing,
malformed/recovery) and `sdk/test/v4-property-f.test.js` (10; > 820 deterministic
seeds — order-independent roots, membership iff member, single-path change,
padding-never-a-member, duplicate-key rejection, idempotent state round-trip,
leaf injectivity, input-surface). New production-covenant VM tests in
`tests/vm/tests/v4_production.rs`: `f_duplicate_last_padding_enables_agent_double_spend`
(independently REPRODUCES the E padding vulnerability — agent double-spends its
period budget through a duplicated leaf) and `f_unspendable_padding_blocks_the_double_spend`
(the SDK's `SHA256(0x50563400)` padding closes it). A 10-guard SDK sabotage
sensitivity harness confirmed 10/10 guards turn their test red (0 blind spots).
SDK 243→264; VM 244→246. Production covenant bytes UNCHANGED. OFFLINE.

**Checkpoint G (2026-08-19) — v0.4 server/API + browser-wallet integration
(OFFLINE):** new suites `sdk/test/manifest-v4.test.js` (6; durable registry
root-equality, fail-closed), `sdk/test/wallet-requests-v4.test.js` (6; offline
BUILD→sign→FINALIZE→VM-preflight for reserve/fuel spends, approvals, all owner
ops, high-level agent lifecycle, recover), `sdk/test/api-v4.test.js` (7;
production-byte HTTP→VM gate via real api.handle + authorization negatives),
`sdk/test/wallet-v4-hostile.test.js` (13; identity/authz, agent-tree integrity,
freeze boundary, approvals, fee/reserve, two-tab concurrency, crash/duplicate,
stale, network gate, pause). New Rust binary
`tests/vm/src/bin/pv_vm_preflight.rs` executes finalized transactions against
the production covenant with no broadcast. A 9-guard app-layer sabotage harness
showed 9/9 sensitive, 0 blind spots. SDK 264→296; VM 246 unchanged (additive
binary). Production covenant bytes UNCHANGED. OFFLINE, VM-PREFLIGHT-PROVEN —
NOT live-testnet-verified.
