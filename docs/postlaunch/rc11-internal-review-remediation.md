# rc11 internal security review — successor remediation record (lane `rc11-security-remediation`)

INTERNAL review and INTERNAL remediation. nothing here may be
described as an "audit".
Review subject: `df5d7fa` / image `sha256:2994a085…` — BLOCKED, immutable,
never repaired in place, never deployed. Evidence (private `main`,
`docs/postlaunch/audit-evidence/rc11-internal-review/`) preserved.

## 1. Findings → remediation (this lane, from `df5d7fa`)

| id | sev | finding (short) | remediation | commit | permanent regression |
|---|---|---|---|---|---|
| F-01 | MEDIUM | `contractVersion` prototype keys silently resolve v0.4 | own-property lookups (`core/model/own-get.js`) at every version/action table; API refuses non-string/unknown versions (422 `UNKNOWN_VERSION`) | `0a08305` | `sdk/test/unknown-version-prototype-matrix.test.js` |
| F-02 | MEDIUM (policy) | v0.4 (18 sig-ops, non-standard relay) mainnet-creatable | per-generation allowlist `MAINNET_CREATABLE_GENERATIONS = {policyvault-0.4.1}`; capabilities expose `mainnetCreatable` / `creatableCovenantVersions` | `d55e9f2` | `sdk/test/mainnet-generation-authorization.test.js` |
| F-03 | HIGH (pre-existing rc8) | unauthenticated hosted builds; ~2 MB artifact per genesis on a 256 MB tmpfs; quota/inbox pollution | hosted BUILD AUTHORITY (principal required; genesis signer = principal; participant signer; agent self-only; owner may build for its agents); bounded LRU build cache with minimal artifacts + recompile-on-miss; lifecycle-safe (a cache is a cache) | `feefc47` | `sdk/test/hosted-build-authority.test.js`, `sdk/test/build-cache-bound.test.js` |
| F-04a | HIGH | unverified signature material persisted as SIGNED (org-root genesis) | real-VM preflight of EVERY input before SIGNED/finalize across v4/v5/v6/v7/HD (`sdk/src/vm-preflight.js`) — standing invariant §F | `c97f656` | `sdk/test/cryptographic-transition-invariant.test.js` |
| F-04b | HIGH | `/org-roots/*`, `/wallet/v7/*` discarded the principal; `/wallet/v5|v6/*` had no auth; cross-tenant read/mutate; live-root lock griefing (proven on a real testnet root) | principal never discarded; authority from durable covenant facts only (active owner slots + pinned successor; vault agents; request creator/signer); signer bound to principal; slot envelopes bound to the slot key; non-oracle 404 / 403; tenant-scoped listings; v5/v6 surface receives ctx | `c5d9b09` | `sdk/test/hosted-foreign-tenant-matrix.test.js` |
| F-04c | LOW (follow-up found by GATE 1) | a caller-supplied vault id of another generation reached the v1/v2/v4 loader, which throws → HTTP 500 before the principal check (existence/schema oracle) | `loadVaultOrNull` on every caller-supplied id; principal FIRST on `GET /vaults/:id*` and reconcile; `MANIFEST_SCHEMA_UNKNOWN` closed code | this lane | same file (test "v4-FAMILY routes given a v5 controller id") |
| F-05 | MEDIUM | six `resolve*Abi` resolvers return built-ins for prototype keys | folded into F-01 | `0a08305` | as F-01 |
| F-06 | LOW | dead `/wallet/v7` scope block (no machine credential could reach the family; GET mis-scoped) | route precedence fixed inside the wallet branch | `52acaa9` | `sdk/test/scopes-route-precedence.test.js` |
| F-07 | LOW | candidate packet lacked vendored `pv_*` pins | `tools/verify-image-vendor-pins.sh` (fail-closed against `deploy/vendor/SHA256SUMS.txt`); successor packet records every pin | this lane | run at image build; recorded in the successor packet |

INFO items from the review: gate codes at HTTP (BUILD_FAILED/NETWORK_MISMATCH)
now accompanied by the closed `GENERATION_NOT_MAINNET_AUTHORIZED`;
capabilities on mainnet list every generation but mark exactly one
`mainnetCreatable`; served `web/test` tree, compose hardening
(no-new-privileges/cap_drop), KAS parser leading-zero tolerance and the
reconcile successor-covenantId re-check remain OPEN follow-ups (not
security-blocking; recorded for the next lane).

## 1.1 Second review round — rc12 (`a8a4eb8` / `sha256:01aa7fa6…`) BLOCKED → remediated as the next successor

The independent in-house review of rc12 (detached worktree, hostile probes
only, zero broadcasts; evidence `docs/postlaunch/audit-evidence/rc12-internal-review/`)
returned **POLICYVAULT-RC12-INTERNAL-SECURITY-REVIEW-BLOCKED** with one HIGH.
rc12 (`a8a4eb8`) is immutable and must not be accepted; the fixes below
form the next successor identity (see the successor packet).

| id | sev | finding (reviewer) | remediation | permanent regression |
|---|---|---|---|---|
| R-01 | HIGH | `GET /vaults` 500 `MANIFEST_SCHEMA_UNKNOWN` for every caller (unauthenticated included, before the principal check) once any v0.5/v0.6/v0.7/HD vault exists — the part of the F-04c class the lane missed | principal FIRST; `loadVaultOrNull` per id; other generations are not part of this family's listing | `hosted-foreign-tenant-matrix.test.js` "rc12 review R-01" (+ `/vaults/:id/status`, `/audit`) |
| R-02 | MEDIUM | own-property remediation never reached the per-generation INTENT manifest builders/verifiers (5 tables; `verifyRootedVaultManifestV7`'s action check PASSED for prototype keys; shipped in the browser bundle) | `ownGet` at every action lookup in `core/intent/{manifest,token-manifest-v5,token-manifest-v6,swap-manifest-v6,org-root-manifest-v7,org-root-manifest-v7-hd,org-root-manifest-v7-kas}.js`; bundles regenerated | `core/intent/test/prototype-key-actions.test.js` (sabotage-checked: red with a raw lookup) |
| R-03 | MEDIUM | a cache saturated with in-grace entries refused the finalize-time recompile (`BUILD_CACHE_FULL`) | `ensureBuildDir({config})`: on `BUILD_CACHE_FULL` force LRU eviction (grace ignored for a finalize of an already-built request) and retry once; fresh builds keep the grace rule | `build-cache-bound.test.js` "R-03" |
| R-04 | MEDIUM | GATE 2 complete only at route-FAMILY granularity | row granularity: every dispatcher path literal must be inventoried at its own segment position + the exact route list is digest-pinned (re-pin only in a reviewed commit); this immediately exposed two missing rows (`GET /vaults/:id/status`, `GET /vaults/:id/audit`) now inventoried with hostile evidence | `authorization-boundary-inventory.test.js` "row granularity (a)/(b)" |
| R-05 | MEDIUM | `POST /org-roots/:id/requests/:rid/signature` had no hostile evidence | foreign `signature` probes on a pending genesis and on a pending root action | matrix test (404, state unchanged) |
| R-06 | LOW | vendored-pin verifier anchored to a gitignored local inventory | TRACKED `deploy/vendor-pins.sha256` is the verifier default; local `deploy/vendor/SHA256SUMS.txt` must agree | `vendor-pins-tracked.test.js` |
| R-07 | LOW | byte cap enforced pre-compile only (transient overshoot by one artifact) | `minimizeArtifactFile(path, config)` re-enforces the cap once the real size is known | `build-cache-bound.test.js` "R-07" |
| R-08 | LOW | malformed `signedSafeJson` surfaced a raw TypeError message | closed 400 `BAD_SIGNATURE` shape check on the v5/v6, v7 and org-root signature routes | matrix test "rc12 review R-08" |
| R-09 | INFO | unchanged rc11 INFO items (compose hardening, served `web/test`, KAS parser leading zeros, reconcile successor covenantId) | OPEN follow-ups, unchanged | — |
| R-10 | INFO (packet correction) | rc8 refuses a schema-011 DB: rollback needs a database restore, not an image swap | packet §7 + runbook §2.13 corrected (verified: "schema version 11 is newer than this build (9)") | — |

Reviewer NOT-TESTED classes carried into the next review round: hosted
MAINNET (https + PG TLS), VM↔pre-sign parity (its v0.5 spot-check was
inconclusive), dynamic reconciliation divergence, the full numeric matrix,
browser DOM/CSP.

## 1.2 Third round — rc13 (`38e7bce` / `sha256:efc2cb78…`) NOT-FALSIFIED with two pre-existing MEDIUMs → fixed as the next successor

Round-2 verdict: **POLICYVAULT-RC13-INTERNAL-SECURITY-REVIEW-NOT-FALSIFIED**
(all eight round-1 findings verified fixed; no CRITICAL/HIGH). The reviewer
still reproduced two pre-existing MEDIUM defects in the shipped rc13 image
and one LOW side effect of R-03; a candidate presented for human acceptance
must not carry a known owner-facing 500, so they were fixed as the next
successor (rc13 stays immutable).

| id | sev | finding (reviewer) | remediation | permanent regression |
|---|---|---|---|---|
| N-01 | MEDIUM (pre-existing since rc11) | `GET /vaults/:id/status` 500 for the OWNER of any ACTIVE v0.4.1 vault — the branch compiled the v1 `policy` path for a v4 manifest | dispatch on the manifest's own generation (`compileExactStateV4` for v0.4.x) | `hosted-build-authority.test.js` "N-01" (owner/agent 200, foreign 404, unauthenticated 401) |
| N-02 | MEDIUM (pre-existing) | a registered agent could terminally burn an owner request (`SIGNATURE_INVALID`) with one malformed byte on `/wallet/v4/requests/:id/signature`; R-08's shape guard had not reached the v4 family | signature-bearing routes (v4 `signature`, `genesis-submit`, legacy v0.2 `signature`) are reachable ONLY by the request's signer (`requireRequestSigner`, 403 `NOT_THE_SIGNER`; foreign stays 404) + closed 400 `BAD_SIGNATURE` shape check before the SDK | `hosted-build-authority.test.js` "N-02" (agent on the owner's live-vault request 403 + state BUILT; signer malformed 400 + BUILT) |
| N-03 | LOW (introduced by R-03) | forced eviction could delete a concurrent IN-PROGRESS build entry of another process | force mode never evicts an artifact-less entry inside the grace window (abandoned ones past the window are reclaimed) | `build-cache-bound.test.js` "N-03" |
| N-04 | LOW | GATE 2 residual: a new route using only already-inventoried literals at their positions passes without a row | DOCUMENTED residual (the digest pin + literal-position checks catch deletions/renames/new literals; a fully mechanical route extraction from nested dispatch conditions is a follow-up) | — |
| N-05 | INFO | v4 reconcile terminalises (`TERMINATED_UNKNOWN`, `live: null`) on a divergent/empty UTXO answer and cannot be reopened via the API; mitigated by `connectVerified` on the server RPC path | OPEN follow-up (documented fail-closed behaviour; changing it is a state-machine decision) | — |
| N-06 | INFO | compose hardening (`no-new-privileges`, `cap_drop`) still absent; rollback below schema 011 refuses (consistent with R-10) | OPEN follow-up (deployment config; not an image change) | — |

Held in round 2 (fresh): R-01…R-08 closed; F-04 matrix 106/106; F-02 gate
52/53 (known probe-expectation row); cryptographic invariant 18/18; VM↔pre-sign
parity on v0.4.1 (round-1 gap closed); reconciliation divergence UNKNOWN never
ADVANCED (round-1 gap closed); MCP custody; bundle parity; image posture;
migrations. Round-2 evidence: `docs/postlaunch/audit-evidence/rc13-internal-review/`.

## 1.3 Round 3 — rc14 (`98c3159` / `sha256:2fa206da…`) NOT-FALSIFIED

**POLICYVAULT-RC14-INTERNAL-SECURITY-REVIEW-NOT-FALSIFIED.** N-01 (owner/agent
200, foreign 404, unauthenticated 401, `chainConfirmed` computed from the node,
zero 500s across 36 `/vaults*` route/caller combinations with mixed-generation
records), N-02 (agent / agent machine credential / suspended agent → 403
NOT_THE_SIGNER, foreign 404, unauthenticated 401, request stays BUILT in every
family; the signer's malformed payload is 400 BAD_SIGNATURE and no longer burns
the request; a well-formed bogus signature is still refused before SIGNED; the
legitimate signer still reaches PREFLIGHT_VERIFIED) and N-03 (6/6) verified
closed; R-03 still holds on the real pipeline; F-04 matrix 106/106; F-02 gate
52/53 (known probe row); cryptographic invariant 18/18; R-02 still closed; MCP
custody; image posture; migrations. Sabotage sensitivity: SN1–SN4 caught.

| id | sev | finding | disposition |
|---|---|---|---|
| T-01 | MEDIUM (test quality) | the N-03 regression test passed with the guard removed (its in-progress entry was never the LRU victim) | FIXED test-only (the in-progress entry is now the LRU candidate; red with the guard removed, green restored) — `sdk/test` is not in the image, identity unchanged |
| T-02 | LOW | a registered agent can still `reject` an owner request (explicit, attributable WALLET_REJECTED; owner rebuilds) — the documented participant mutation rule, declared unchanged | OPEN follow-up (product decision: whether `reject` becomes signer/owner-only) |
| T-03 | INFO | when every cache neighbour is an in-grace in-progress entry, the finalize recompile fails closed (`BUILD_CACHE_FULL`) rather than corrupting a concurrent build | by design (correctness over availability); recorded |
| T-04 | INFO | compose hardening still absent; rollback below schema 011 refuses | OPEN follow-ups (as N-06) |

Round-3 evidence: `docs/postlaunch/audit-evidence/rc14-internal-review/`.

## 2. Contract changes a client can observe (hosted mode only)

- Every hosted build/create/simulate on `/wallet/*`, `/org-roots/*` requires
  a principal (wallet session or `pvmk_` credential). Unauthenticated → 401.
- The initiating signer of a build is the principal (genesis / root genesis /
  rooted-vault genesis / root action / controller create). An active vault
  owner (v4/v5/v6) or active root owner (v7/HD) may build for the vault's
  REGISTERED agents (the documented owner-minted machine-credential flow);
  an agent builds only for its own key. A stranger named as signer → 403
  `SIGNER_NOT_PARTICIPANT`; a participant naming another → 403
  `SIGNER_NOT_PRINCIPAL`.
- Signature-bearing routes (v4 `signature` / `genesis-submit`, legacy v0.2
  `signature`, v5/v6/v7 `signature`, org-root `signature`) are reachable only
  by the request's SIGNER wallet (other participants: 403 `NOT_THE_SIGNER`;
  foreign: 404) and refuse malformed payloads with a closed 400 `BAD_SIGNATURE`.
- `POST /wallet/v4/simulate` requires the principal to hold build authority
  on the vault (it persists nothing; the signer is what is simulated).
- v5/v6/v7 `tokenDeposit` in hosted mode is built by a vault participant
  (owner or registered agent) for its own key. A third-party depositor is
  not a hosted flow on these NOT-production generations (fail closed).
- Foreign objects answer 404 (never an existence oracle); an id of another
  generation on a family that does not serve it answers the same 404.
- `GET /org-roots`, `/org-roots/:id/requests`, `/wallet/v5|v6|v7/requests`
  are tenant-scoped listings.
- Slot signing requests / slot signatures are served only to the wallet
  holding that owner slot; the pinned successor may read a root and its
  requests and may mutate only a succession request.
- Owner rooted-vault genesis and reconcile require an ACTIVE owner slot
  (successor: 403 `NOT_AN_ACTIVE_SLOT`).
- mainnet: only `policyvault-0.4.1` is creatable (422
  `GENERATION_NOT_MAINNET_AUTHORIZED` for every other generation, including
  `policyvault-0.4`); testnet unchanged.

## 3. Properties that HELD under hostile probing — pinned (owner addendum §H)

| property (held in the review) | canonical gate that now pins it |
|---|---|
| mainnet generation gate (14 paired call sites; every non-0.4.1 generation refused on a mainnet identity; testnet unaffected) | `sdk/test/mainnet-generation-authorization.test.js` (WIRING + F-02 SDK tests), `sdk/test/mainnet-gate-r.test.js` |
| v0.4 hosted tenancy (foreign 404 / participant 403 on every v4 route; approver-only cannot mutate) | `sdk/test/hosted-tenancy.test.js`, `sdk/test/postlaunch-server-tenancy.test.js`, `sdk/test/hosted-build-authority.test.js` (review L5 rows added) |
| MCP custody boundary (no signing/key primitive; deny-by-default scopes; HTTP only) | `mcp/test/custody-boundary.test.js` (new), `mcp/test/mcp-schema-hostile.test.js` |
| VM ↔ pre-sign parity (over-cap / non-allowlisted refused pre-sign for every generation) | `sdk/test/vm-presign-parity.test.js`, `core/model/test/hd-leaf-ancestor-budget.test.js` |
| reconciliation never advances on divergence (CONSISTENT / UNKNOWN never mutate; only a proven successor advances) | `sdk/test/hosted-pg-org-roots.test.js`, `sdk/test/v2-reconcile.test.js`, generation reconcile suites |
| the authorization boundary itself | GATE 2 `sdk/test/authorization-boundary-inventory.test.js` + GATE 1 `sdk/test/hosted-foreign-tenant-matrix.test.js` |

## 4. Accurate conclusion (wording that may be reused)

The rc11 internal security review found SERIOUS hosted-layer tenancy and
availability defects (cross-tenant read and mutation on the v0.7 / v0.5 /
v0.6 route families, a live organizational-root lock griefing, unverified
signature material persisted as SIGNED, and a storage-mass path on the live
rc8 build cache). It did NOT demonstrate any crossing of the covenant
funds boundary or of cryptographic authority: no probe moved funds, forged
a counted owner signature, bypassed a covenant rule, or made the covenant
accept an unauthorized spend; the mainnet generation gate, the v0.4 hosted
tenancy, the MCP custody boundary, VM↔pre-sign parity and reconciliation
discipline held. This is an INTERNAL review; it does not make PolicyVault "safe" — it makes the listed
properties tested.
