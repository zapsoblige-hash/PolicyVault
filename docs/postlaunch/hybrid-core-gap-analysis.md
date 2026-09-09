# HYBRID LOCAL-FIRST / SHARED DETERMINISTIC CORE — gap analysis and incremental migration

Status: **DESIGNED + IMPLEMENTED + UNIT-TESTED + INTEGRATION-VERIFIED**
for the three migrations executed here; the inventory and the remaining
gap list are ANALYSIS (source-derived, cited file:function). Lane: `t4-shared-core`
(base `59e57dc`).

The binding target (owner):

```
raw transaction/state -> canonical parser -> asset descriptor -> policy
  -> manifest -> explanation -> local pre-sign verification
  -> external signer -> covenant enforcement -> reconciliation
```

with cloud responsibility confined to authentication, organizations,
coordination, approval collection, notifications, shared metadata,
synchronization, webhooks and MCP coordination — and the rule that
**cloud must not be the only location where financial truth exists**.
ONE authoritative deterministic core (`core/`); every integration
(server, web, mobile, MCP, x402, AP2, python, examples, CLI) is a thin
consumer. Unknown asset / version / template FAILS CLOSED.

---

## 0. Headline

The architecture is **substantially already in place**. 60 modules under
`core/` (non-test) hold the deterministic semantics; 33 of the 68
`sdk/src` files import `core/` (21 of them are 3–5 line pure re-export
shims). The server re-implements **no** financial semantics: every
consequential decision on its request path is a call into the SDK
builders or `core/` (`server/src/simulate.js` says so in its own header
and it survives inspection). The gaps that remain are **coverage** gaps
(operations, versions and runtimes that the local-first layer does not
reach yet), plus a small number of genuine duplications — one of which
was a live floating-point defect on a funds path.

Counted mechanically (`core/**` excluding `test/`, `testutil/`, `tools/`,
mock adapters; exported values of `typeof === "function"`):

| class | count | meaning |
|---|---:|---|
| SHARED-CORE, funds-relevant | **273 exported functions across 40 modules** — `core/model` 189/27, `core/assets` 30/4, `core/intent` 54/9 | the single authoritative implementation; every consumer calls it. §1 tables cite the ~90 that are individually funds-decisive |
| SHARED-CORE, supporting | 89 functions across 15 modules — `core/signer` 39/3, `core/risk` 20/3, `core/governance` 16/3, `core/explain` 14/6 | signer negotiation, risk composition, authority classification, explanation rendering |
| SDK-ONLY (impure, justified) | **35 of 68** `sdk/src` modules | do not import `core/` at all: builders, compilers, chain/wasm, stores, manifests, reconcilers, wallet-request pipelines — welded to `child_process` (silverc / `pv_call_encoder` / `pv_tx_probe`), kaspa-wasm, `fs` or config, so they cannot be portable. Their deterministic members were already extracted by core-extraction steps 1–3 |
| DUPLICATED | 6 sites | 3 documented twins (now all gated), 2 closed by this wave, 1 unguarded cross-language port (G5) |
| SERVER-ONLY financial fact | **0** | no financial fact is computed only server-side |
| SERVER-ONLY coordination | **29** `server/src` modules | authentication, orgs, approvals, events, webhooks, idempotency, audit — correctly cloud-only |
| CLIENT-ONLY | 2 sites | browser amount entry (migrated here) and the browser verifier's own twin parser (now gated) |
| SDK → core delegation | **33 of 68** `sdk/src` modules import `core/` | of these, **21** are 3–5 line pure re-export shims (`amounts`, `fee-mass`, both Merkle families, every `vault-state-*` / `vault-transitions-*` / `compute-budget-*`, `swap-policy-v6`, `canonical-json`) and **12** are composition modules keeping only their impure members locally |

---

## 1. INVENTORY — every funds-relevant deterministic function, and where it executes

Legend for **executes-in**: `S` server · `B` browser · `M` Android/mobile
(WebView over byte-identical vendored artifacts) · `C` CLI/tools · `H`
self-host · `K` SDK (Node) · `P` MCP adapter · `X` x402/AP2 · `V`
covenant (Silverscript/VM).
Bundled = present in `web/core-bundle.js` (hence also in
`mobile/www/vendor/core-bundle.js`, byte-identical via
`mobile/tools/sync-portable.js`).

### 1.1 Amounts and canonical serialization

| function | layer | executes in | status |
|---|---|---|---|
| `core/model/amounts.js` `parseSompi` / `parsePositiveSompi` / `kasToSompi` / `sompiToKas` / `MAX_SOMPI` | numeric safety | K S B M C H (bundled; exposed on the api surface by this wave) | SHARED-CORE |
| `core/model/canonical-json.js` `canonicalJsonStringify` | commitment preimage | K S B M P | SHARED-CORE (twin of the next row, pinned in lockstep) |
| `core/intent/canonical.js` `canonicalJsonStringify` / `sha256Hex` / `computeManifestHashV1` / `canonicalEqual` | manifest hashing | K S B M | DUPLICATED — deliberate independently-maintained twin, byte-equality pinned by `core/crossruntime/test/core-model-portability.test.js` |
| `core/explain/kas.js` `parseCanonicalSompi` / `sompiToKasString` | display | K S B M | DUPLICATED — deliberate twin of `sompiToKas`, pinned by the same suite |
| `core/model/token-amounts.js` `parseAtomicAmount`, `MAX_I64`, `OWNER_SCHEMES` | token units | K B M | SHARED-CORE |
| `integrations/lib/amounts-gate.js` `requireCanonicalSompiString` / `requireSafeMinorUnitsInteger` | protocol boundary | X | SHARED-CORE consumer — imports `MAX_SOMPI` from the SDK re-export; deliberately STRICTER (one value, one encoding), never looser |
| `python/policyvault_client/amounts.py` | client boundary hygiene | python | DUPLICATED — documented port, strictly stricter; **no mechanical parity gate** (gap G5) |
| `web/app.js` `kasToSompiCanonical` / `promptSompi` / `promptCheck`; `web/app-v4.js` `kasToSompiClient` | amount entry | B M | ~~CLIENT-ONLY duplicate~~ → **SHARED-CORE since this wave** (§3.1) |
| `web/verify-intent.js` `kasToSompi` | pre-sign verifier | B M | DUPLICATED — reviewed byte-vendored twin; **now gated** by `web/test/client-amounts-parity.test.js` (§3.1) |

### 1.2 Covenant state, transitions and state IDs

| function | layer | executes in | status |
|---|---|---|---|
| `core/model/vault-state.js` `normalizePolicy` / `normalizeState` / `computeStateId` / `normalizeHex` / `normalizeXOnlyPubkey` | v1 state | K S B M | SHARED-CORE |
| `core/model/vault-state-v2/v3/v4.js` `normalizeTemplate*` / `normalizeState*` / `computeStateId*` / `stateToJson*` / `resolveV4Abi` | v0.2–v0.4 state | K S B M | SHARED-CORE (v4 bundled) |
| `core/model/vault-state-v5.js`, `vault-state-v6.js` (+ `OWNER_OP_SELECTOR_V5/V6`, `controllerValueV6`) | v0.5/v0.6 state | K B (v5 bundled) M; **v6 not bundled** | SHARED-CORE, browser coverage incomplete (gap G3) |
| `core/model/vault-transitions-v3/v4/v5/v6.js` — every successor derivation (`agentSpendSuccessorV4`, `tokenAgentSpendSuccessorV5/V6`, `tokenAtomicSell/BuySuccessorV6`, owner ops, `recoverPlanV*`) | policy evaluation | K B M (v3/v4/v5 bundled; v6 not) | SHARED-CORE, browser coverage incomplete (G3) |
| `core/model/vault-transitions-v6.js` `poolSellQuote` / `poolBuyQuote` | exact venue quote | K, **V** (the covenant re-derives it) | SHARED-CORE |
| `sdk/src/vault-builders-v3/v4/v5/v6.js` `buildV*Transaction` / `buildCreate*` / `finalize*` | transaction construction | K (S and C call it) | SDK-ONLY (impure, justified) — welded to `runEncoderV4` (`pv_call_encoder` spawn), the exact-fee finalizer loop (`pv_tx_probe`), `compileExactState*` (silverc) and kaspa-wasm |
| `sdk/src/contract-compiler*.js` `compileExactState*` | covenant compilation | K | SDK-ONLY (spawn + fs) |

### 1.3 Fee, mass and compute budgets

| function | layer | executes in | status |
|---|---|---|---|
| `core/model/fee-mass.js` `estimatedSerializedSize` / `computeMass` / `feeMass` / `calculateRequiredFee` / `validateComputeBudget` / `finalizeWithExactFee` | consensus fee/mass | K S B M | SHARED-CORE (bundled) |
| `core/model/storage-mass.js` `calcStorageMass` / `minimumOutputValueForLimit` / `STORAGE_MASS_LIMIT` | KIP-9 storage mass | K; browser only via the probe | SHARED-CORE, not bundled (G3) |
| `core/model/compute-budget-v3/v4/v5/v6.js` `selectComputeBudget*` / `selectTokenInputBudget*` / `selectPoolInputBudgetV6` / `assertBudgetSufficient*` | committed budgets | K S B M (v3/v4/v5 bundled) | SHARED-CORE |
| `core/model/frozen-tx-v3.js` `normalizeFrozenTxV3` / `canonicalFrozenTxJson` / `frozenTxCommitment` / `feeDescriptorFromFrozen` | frozen-tx normalization | K S B M | SHARED-CORE (bundled) |
| `sdk/src/frozen-tx-v3.js` `describeFrozenTx` / `verifyApprovalSignature` / `frozenToWasmTransaction` | consensus txId / sighash / signature check | K | SDK-ONLY (impure, justified — `pv_tx_probe`, wasm) |

### 1.4 Merkle roots, approval packages and authority

| function | layer | executes in | status |
|---|---|---|---|
| `core/model/recipient-merkle-v3.js` `leafHash` / `buildRecipientTree` / `generateRecipientProof` / `verifyRecipientProof` | recipient allowlist | K S B M | SHARED-CORE (bundled, byte-native) |
| `core/model/agent-merkle-v4.js` (`normalizeAgentPolicyV4` … `applyAgentSpendV4`) | v0.4 agent registry | K S B M | SHARED-CORE (bundled) |
| `core/model/agent-merkle-v5.js` / `agent-merkle-v6.js` (leaf preimage/hash, tree, proof, fold, add/remove/rotate) | v0.5/v0.6 agent registry | K B (v5 bundled) M; v6 not bundled | SHARED-CORE (G3) |
| `core/model/swap-policy-v6.js` `normalizeSwapVenueProfile` / `computeSwapVenueProfileHash` / `normalizeSwapPolicyV6` / `swapPolicyLeafHashV6` / `buildSwapPolicyTreeV6` / `verifySwapPolicyProofV6` | venue authority | K; not bundled | SHARED-CORE (G3) |
| `core/model/approval-package-v3.js` / `approval-package-v4.js` `commitmentPreimage` / `packageCommitmentV3/V4` / `collectedCount*` / `missingSlots*` / `isComplete*` / `p2pkScriptHex` / `placeholderApprovalsBlob` | M-of-N approvals | K S; not bundled | SHARED-CORE (G4) |
| `sdk/src/approval-package-v3/v4.js` `createApprovalPackage*` / `assertPackageIntegrity*` / `submitApproval*` / `approvalsBlob*` | approval lifecycle | K S | SDK-ONLY (impure, justified — probe re-derivation + `new Date`) |
| `core/governance/authority-delta.js` `classifyPolicyDelta` / `classifyMigrationDelta`; `core/governance/canonical.js` `encodeGovernanceProposal` / `governanceProposalDigest` | governance | K S B(explain only) | SHARED-CORE — the digest FAILS CLOSED in the browser (ambient `Buffer`), pinned by `bundle-anti-drift.test.js`; the explain path never calls it |

### 1.5 Assets and token semantics

| function | layer | executes in | status |
|---|---|---|---|
| `core/assets/descriptor.js` `validateAssetDescriptor`; `core/assets/index.js` `computeDescriptorHash` / `corroborateTemplate` / `verifyTokenInputRedeem` / `redeemFromSignatureScript` | asset descriptor | K S(x402f) B M X | SHARED-CORE (bundled) |
| `core/assets/kcc20.js` `encodeState` / `decodeState` / `splitRedeem` / `reconstructRedeem` / `templateVmHashHex` / `p2shSpkHex` / `countStaticSigOps` / `templateStandardness` | canonical token parser | K B M X | SHARED-CORE (bundled) |
| `core/assets/blake2b.js` `blake2b` / `blake2bHex` | in-VM template identity | K B M X | SHARED-CORE (bundled, portable pure JS) |
| `integrations/x402-facilitator/verify-token.js` token conservation Σin = Σout | independent verification | X | SHARED-CORE consumer — sums come from `core/assets` codecs; it can only REFUSE |

### 1.6 Intent manifests, verification and explanation

| function | layer | executes in | status |
|---|---|---|---|
| `core/intent/manifest.js` `buildIntentManifest` / `validateManifest` / `validateRequestedIntent` / `validateTransactionShape` / `diffStates` (+ `HIGH_LEVEL_TO_SDK`) | v0.4 manifest | K S B M | SHARED-CORE (bundled) |
| `core/intent/verify.js` `verifyIntentManifest` (16 detectors) | v0.4 local pre-sign verification | K S B M | SHARED-CORE (bundled) |
| `core/intent/bridge/derive.js` `deriveManifestFromV4Build` / `deriveAndVerify` | SDK→manifest bridge | K S | SDK-adjacent by design (the single core↔sdk seam; imports `sdk/src`) |
| `core/intent/token-manifest-v5.js` `buildTokenIntentManifest` / `verifyTokenIntentManifest` | v0.5 manifest + verification | K B M (bundled) | SHARED-CORE — **bundled but not wired to any browser flow** (G2) |
| `core/intent/swap-manifest-v6.js` `buildSwapIntentManifest` / `verifySwapIntentManifest` (51 checks) | v0.6 swap manifest | K | SHARED-CORE, Node-only reach (G3) |
| `core/intent/token-manifest-v6.js` `buildControllerIntentManifestV6` / `verifyControllerIntentManifestV6` | v0.6 non-swap manifest | K | **NEW this wave** (§3.2) — SHARED-CORE |
| `core/intent/router.js` `routeBuild` / `routeManifest` / `buildManifestForBuild` / `verifyManifest` | version-aware dispatch | K | **NEW this wave** (§3.2) — SHARED-CORE, portable |
| `core/explain/intent-explain.js` / `governance-explain.js` / `risk-explain.js` / `token-explain.js` `structured` / `humanReadable` | explanation | K S B M | SHARED-CORE (bundled) |
| `web/verify-intent.js` `verifyBeforeSigning` (+ detector catalogue) | browser pre-sign gate | B M | CLIENT-ONLY orchestration over SHARED-CORE — decides nothing itself; **covers `policyvault-0.4` / `0.4.1` only** (`MERKLE_RECOMPUTABLE_VERSIONS`, line 279) — G2/G3 |
| `core/signer/interface.js` (+ `errors.js`, `adapters/cli`) `createTransactionSigningRequest` / `assertCanonicalSignInputs` / `normalizePublicKeyToXOnly` / `negotiateCapabilities` | universal signer | K B M C | SHARED-CORE (bundled) |
| `core/risk/compose.js` `composeVerdicts` / `evaluateRisk` / `applyRiskToPolicyDecision` | risk orchestration | K S | SHARED-CORE |

### 1.7 Cloud-only (correctly)

`server/src/`: `auth.js`, `tenancy.js`, `scopes.js`, `machine-identity.js`,
`organization`-facing routes, `org-controls.js`, `agent-suspensions.js`,
`events*.js`, `webhooks.js`, `notifications.js`, `notify-delivery.js`,
`idempotency.js`, `limits.js`, `metrics.js`, `migrate.js`,
`platform-store.js`, `audit.js`, `audit-chain.js`, `intent-records.js`,
`capabilities.js`, `api-version.js`, `risk-adapters.js` — **31 modules,
none computing a financial fact.** `server/src/governance.js` classifies
authority deltas through `core/governance`; `server/src/risk.js` composes
through `core/risk`; `server/src/simulate.js` runs the REAL planner,
builder, classifier and manifest bridge and persists nothing.

`mcp/`: a thin HTTP client (`mcp/src/{tools,http,envelope,schema}.js`)
with **one** byte-synced core copy (`mcp/core/model/canonical-json.js`,
sha256 pinned in `mcp/core/MANIFEST.json`, drift fails `prepack` and
`mcp/test/core-sync.test.js`). No financial arithmetic — verified by
grep: zero `BigInt(` sites.

---

## 2. GAPS, ranked by funds-relevance

(G-numbers are assignment order, not rank; the list below is in rank
order, so G9 appears before G8.)

**G1 — Floating-point KAS→sompi in the live browser (CLOSED by this wave).**
`web/app.js` `promptSompi`/`promptCheck` computed
`BigInt(Math.round(Number(v) * 1e8))` and sent the result to
`POST /wallet/requests` as `payAmountSompi`/`topUpAmountSompi`. Captured
evidence (`web/test/fixtures/golden-client-amounts.json`, taken from the
original code): `"0x10"` → 16 KAS, `"1e3"` → 1000 KAS, `"1."`/`".5"`/`"+1"`
accepted, a 9th decimal silently rounded, `"0.000000001"` → **0**, and
double precision loss on large amounts (KAS `"9007199254740993"` came out
**1000 KAS below** the exact value; `"90071992547.40993"` came out 24
sompi high). Direct violation of the numeric-safety rule ("never floating
point… use the canonical KAS↔sompi parsers only").
Classification: **PRODUCTION CODE BUG**. → §3.1.

**G2 — v0.5 has a shipped browser verifier that nothing calls.**
`core/intent/token-manifest-v5.js` and `core/explain/token-explain.js`
are embedded in `web/core-bundle.js` and exposed as
`window.PolicyVaultCore.tokenManifestV5` / `.tokenExplain`, but no `web/`
source references them, and `web/verify-intent.js` refuses any covenant
version outside `["policyvault-0.4", "policyvault-0.4.1"]`
(`MERKLE_RECOMPUTABLE_VERSIONS`, line 279). Mobile agrees:
`mobile/www/js/portable/verification.js` `REQUIRED_CORE_KEYS` (line 40)
lists only the v0.4 surface. There is also no v0.5 server route. So a
v0.5 token operation today has local pre-sign verification in **Node
only** — every browser/mobile path fails closed on it. Fail-closed is
correct, but the capability is already shipped in the bundle bytes and
unused. Owner of the fix: a web/mobile wiring wave (not a core wave).

**G3 — v0.6 reaches no client runtime at all (partially closed).**
Before this wave: non-swap v0.6 operations had **no manifest at all**
(`docs/postlaunch/v0.6-byte-freeze-readiness.md` limitation 8), and
`buildTokenDepositV6` emitted a build that no manifest module accepted —
which is why `tools/testnet-v6-atomic-proof.js:261` had to build its
deposit with `buildTokenDepositV5`. Closed in §3.2. **Still open:** none
of the v0.6 modules (`vault-state-v6`, `agent-merkle-v6`,
`swap-policy-v6`, `vault-transitions-v6`, `compute-budget-v6`,
`storage-mass`, both v6 manifests, the router) is in the bundle's
`MODULES` list, so the browser and mobile cannot verify a v0.6
transaction. §3.3 proves all 32 of those files ALREADY run
byte-identically in the browser-shaped runtime, so bundling is now a
reviewed `MODULES` change rather than a research question.

**G4 — approval-package commitments are not browser-reachable.**
`core/model/approval-package-v3/v4.js` `commitmentPreimage` /
`packageCommitmentV3/V4` are pure and (per §3.3) portable, but are not
bundled, so an approver in a browser cannot independently recompute the
package commitment they are approving. Noted as an available core surface
by `docs/postlaunch/core-extraction-step3.md` §7; still unbundled.

**G5 — the Python client's amount parser has no mechanical parity gate.**
`python/policyvault_client/amounts.py` is an honest, documented,
strictly-stricter port of `core/model/amounts.js`, but its test vectors
are **hand-copied** (`python/tests/test_amounts.py` lines 3–4: "copied
from `sdk/test/amounts.test.js`"). A change to the canonical parser would
not fail any Python test. Needs a generated shared vector file (JSON
emitted from `core/model/amounts.js`, consumed by both suites).

**G6 — `server/src/simulate.js` re-states a presenter that the SDK does
not export.** `reviewFromBuild` (line 62) reproduces
`sdk/src/wallet-requests-v4.js` `reviewForBuild` (line 256) field for
field because the latter is not exported. Presentation only (KAS
formatting over `build.accounting`), no arithmetic — but the dry run and
the real request can drift in what they show a human. Fix: export
`reviewForBuild` and call it.

**G7 — `web/verify-intent.js` carries its own `kasToSompi`
(now gated, not removed).** It is a reviewed, byte-vendored signing
artifact (mobile ships identical bytes), used on 20 funds-path
cross-checks. Rewriting it in place is a higher-risk change than the
value it returns, so §3.1 pins it in lockstep with the canonical parser
instead — the treatment `docs/postlaunch/cross-runtime-equivalence.md` §3
already gives the canonical-json and `sompiToKas` twins. Its only
divergence (no `MAX_SOMPI` ceiling) is asserted to be the only one.

**G9 — v0.6 non-swap operations have verification but no rendered
explanation.** `core/explain/token-explain.js` renders the v0.5 manifest;
`core/intent/swap-manifest-v6.js` builds its own `explanation` array
inline. `core/intent/token-manifest-v6.js` (new here) deliberately does
neither — it ships the verification first, and the renderer is a separate
reviewed addition. Until then a v0.6 spend/owner/recover is verified but
not narrated.

**G8 — `sdk/src/ux-normalize-v4.js` and the builders' deterministic
sections remain unextracted.** Recorded already by
`docs/postlaunch/core-extraction-step3.md` §7; unchanged by this wave. Low value until a
core consumer exists (`ux-normalize-v4` needs `address-identity` → wasm
at module top level; the builders are welded to the encoder/probe).

**Not a gap (checked and cleared):** the server computes **no** financial
fact a client cannot recompute. `server/src/{events,events-store,
risk-adapters}.js`'s 14 `BigInt(` sites are cursors, sequence numbers and
a risk threshold; `server/src/simulate.js`'s are KAS display formatting
over `build.accounting`. `sdk/src/budget-reservation.js` and
`sdk/src/reconcile-v4.js` are coordination/availability layers whose own
headers state they are not security boundaries and do not change
consensus-visible bytes.

---

## 3. MIGRATIONS EXECUTED (with parity evidence)

Method, in all three cases: capture golden outputs from the ORIGINAL code
path FIRST (the `core/model/test/golden-f1-merkle.test.js` method), then
migrate, then prove old vs new vector by vector.

### 3.1 Browser amounts → the canonical shared-core parser (closes G1, gates G7)

Commits `b5a0bc3` (capture, no production change) and `ed90e51`.

- `web/tools/build-core-bundle.js` exposes `amounts` on the api surface.
  `MODULES` is unchanged — `core/model/amounts.js` was already embedded
  as the byte-native Merkle modules' dependency closure. Bundle
  regenerated deterministically (`--check` clean); mobile re-synced
  (`npm run check:portable` OK, 3 artifacts).
- `web/app.js` `promptSompi`/`promptCheck` and `web/app-v4.js`
  `kasToSompiClient` now call `window.PolicyVaultCore.amounts.kasToSompi`
  and fail closed (null; nothing requested) on refusal or an unavailable
  core.
- **Parity evidence** — `web/test/client-amounts-parity.test.js`, 6 tests
  over the 41-vector golden fixture:
  1. every input the canonical parser accepts keeps its **byte-identical**
     original digit string (≥ 12 vectors; `app-v4`'s original agreed
     outright, `app.js`'s agreed on every accepted positive amount);
  2. all **15** recorded defect inputs are now REFUSED, each asserted
     against the exact wrong value the float path produced;
  3. no `web/` source performs a float KAS→sompi conversion or carries a
     second amount grammar, and the two original float function bodies'
     sha256 can never recur;
  4. the `verify-intent.js` twin agrees with the canonical parser on
     every vector it accepts, its only divergence being the missing
     supply ceiling (G7 gated).
  The canonical parser is reached through the COMMITTED bundle in a
  browser-shaped `vm` context, so a bundle that stopped exposing it fails
  here.
- Two follow-on test-fidelity fixes, both classified, neither weakening
  an assertion:
  - `web/test/network-strings.test.js` line pins 1314→1345 and
    1956→1966. **TEST BUG / STALE ASSUMPTION** — the exempt occurrences
    are byte-identical comments that only moved.
  - `sdk/test/browser-create-form-v4_1.test.js` and
    `sdk/test/approval-flow-v4_1.test.js` (commit `0bbbb35`) now evaluate
    the committed `web/core-bundle.js` BEFORE `web/app-v4.js`, exactly the
    order `web/index.html` uses. Both jsdom harnesses stripped every
    `<script src>` and evaluated only `app-v4.js`, so
    `window.PolicyVaultCore` was undefined — they were modelling a page
    that never exists. Invisible until `kasToSompiClient` started reading
    the canonical parser off the bundle, at which point both suites timed
    out waiting for a form submission that had correctly failed closed.
    **TEST BUG (harness fidelity)**, surfaced by a production change that
    is itself correct; the fix makes the harness drive the real artifact.

### 3.2 v0.6 controller intent manifest + fail-closed version router (closes G3's manifest half)

Commits `b6881ac` and `0c8c081` (the break-glass follow-up).

- NEW `core/intent/token-manifest-v6.js` —
  `policyvault-controller-intent-manifest/1`, additive; v0.5 and the v0.6
  swap manifest are byte-untouched. Covers `tokenAgentSpend`, all six
  owner control operations, `ownerRecover`, and a v0.6-labelled
  `tokenDeposit`. `verifyControllerIntentManifestV6` recomputes from the
  frozen bytes + descriptor + core codecs: exact fee, KIP-9 storage mass,
  descriptor/family/template pins with issuer powers verbatim, the
  controller input as `feeReserve + swapPrincipal`, the successor output,
  both v0.6 KAS domains stated apart, per-action state equations (a spend
  cannot move protected principal, re-approve a venue, or advance the
  nonce; each owner op may change only its own field and its external
  funding must land in the domain it names; recover returns both domains
  and the token position to the owner key), the token domain
  reconstructed from the revealed redeem + descriptor template, and the
  agent's authority re-proven under the LIVE `agentRoot` with caps,
  budget, rollover lockTime, recipient allowlist and the successor-root
  fold.
- NEW `core/intent/router.js` — one dispatch point keyed on the exact
  `(contractVersion, kind, action)` tuple. Unknown version/kind/action and
  swap↔non-swap mismatches refuse with specific codes; the v0.4 family
  refuses as `HANDLER_NOT_PORTABLE` naming
  `core/intent/bridge/derive.js`. Requires only sibling `core/intent`
  modules, so it stays portable.
- **Parity/coverage evidence** — this is a NEW capability, so the
  equivalent of a parity test is (a) proof over REAL builds and (b) proof
  that the previously-unroutable build is now routable:
  - `sdk/test/token-manifest-v6.test.js` (7 tests) drives every non-swap
    v0.6 shape through the REAL builder (silverc + the production
    `pv_call_encoder` + `pv_tx_probe`): fuel-funded and reserve-funded
    `tokenAgentSpend`, all six owner ops (each asserting its own field
    moved and an owner-op relabel REFUSES), `ownerRecover` with and
    without a token position, and a v0.6 `tokenDeposit` — which the test
    first asserts the v0.5 manifest still REFUSES, pinning the exact gap
    that was closed. 12 spend tamper classes, a diverted top-up, a
    redirected recover payout and a redirected deposit all REFUSE, and
    a break-glass recovery from a malformed state VERIFIES while the same
    malformed state on a continuing action REFUSES.
  - `core/intent/test/router.test.js` (9 tests, offline) pins the closed
    dispatch table, every refusal code, and — by reading the SDK's own
    `OWNER_CONTROL_ACTIONS` / `SPEND_ACTIONS` / `SWAP_ACTIONS` — that no
    builder action is orphaned.
- **Two PRODUCTION CODE BUGS found in the new verifier and fixed**, both
  false-refusals of legitimate transactions — the failure mode that
  matters most here, because a manifest that refuses a real operation
  pushes its owner to sign with no local verification at all:
  1. (caught by the real-build test, before the first commit) the reserve
     check treated the fee reserve as monotonically decreasing and
     wrongly REFUSED a legitimate `ownerTopUpReserve`. The direction is
     now role-dependent — an agent op consumes (`0 <= consumed <= fee`),
     an owner op consumes nothing and its increase is proven against the
     declared external funding.
  2. (caught by self-review, commit `0c8c081`) the predecessor state was
     parsed strictly for every action, so a BREAK-GLASS `ownerRecover`
     from a malformed state — which `sdk/src/vault-builders-v6.js` accepts
     under `params.allowMalformedState`, quarantined to ownerRecover —
     was REFUSED. `ownerRecover` now falls back to the same quarantined
     `normalizeStateV6ForRecovery` shape-only parse; every CONTINUING
     action keeps the strict parse; the fallback is never silent (a
     `stateParse` check is always reported and says BREAK-GLASS when it
     fires); and the payout is still proven from the frozen output bytes,
     not from the declared state. Both halves are pinned by the 7th case
     in `sdk/test/token-manifest-v6.test.js`.
- **No production-byte surface touched**: `git diff` vs the base is empty
  for `sdk/src`, `contracts/`, `tools/`, `server/`, `integrations/`,
  `python/`, `mcp/`, `conformance/` and `tests/`. No builder, serializer,
  encoder or compiler path changed, so no vector regeneration was
  required (rule applied, not skipped).

### 3.3 Cross-runtime battery for the whole v0.5/v0.6 stack (makes G3's bundling decision mechanical)

Commit `a3132fc`.

- NEW `core/crossruntime/test/v5-v6-portability.test.js` — 44 cases over
  the exact 32-file dependency closure. Beyond load smoke: state ids agree
  including the `MAX_SOMPI`/max-nonce boundary and `swapPrincipal` /
  `swapRoot` are proven committed; Merkle leaf preimages, hashes, roots,
  proofs and successor folds agree byte-for-byte for v5 and v6; the swap
  policy leaf/tree and profile hash agree; pool quotes agree to the sompi
  **or refuse with the same code**; storage mass agrees on the relaxed
  path, the general path and an over-limit shape; every v5/v6 budget
  operation resolves to the same tier at two template geometries; the
  router's dispatch and all eight refusal codes agree; the v0.6 verifier's
  failing-check names agree; and the KCC20 encode/decode, redeem
  reconstruction and P2SH script agree.
- `core/crossruntime/vectors.js` gains the v5/v6 batteries.
- `core/crossruntime/sandbox.js` `resolveId` gains the **directory-index
  fallback the real bundle loader already has**
  (`factories[id + "/index"]`). Without it the probe could not load any
  module that requires a package directory (`require("../assets")`) — the
  probe was strictly narrower than the runtime it models. Still
  fail-closed.
- Findings while building it, all classified, none a production
  divergence: `templateStateLen` vectors were 41 vs the real
  `KCC20_STATE_LEN` 46 (**TEST BUG**, fixed); a pool vector whose amount
  is entirely consumed by the pool fee refuses in both runtimes (loop now
  asserts equal outcomes OR equal codes); and the manifest layer is
  subject to the realm-identity caveat already recorded in
  `cross-runtime-equivalence.md` §5.2, so manifest inputs are re-homed
  INTO the sandbox realm with `rehomeInto` — a host-realm object looks
  like a divergence and is not one.

---

## 4. MIGRATION PLAN for the remaining gaps, with parity-test requirements

Ordered by funds-relevance. Every item keeps the same discipline: capture
golden outputs from the CURRENT code path first; migrate; prove
byte-identity or an explicitly enumerated, strictly-safer divergence.

| # | gap | change | parity-test requirement | risk |
|---|---|---|---|---|
| 1 | G3 (rest) | Add the v0.6 closure to `web/tools/build-core-bundle.js` `MODULES` (a reviewed change) and expose `vaultStateV6`, `agentMerkleV6`, `swapPolicyV6`, `vaultTransitionsV6`, `computeBudgetV6`, `storageMass`, `controllerManifestV6`, `swapManifestV6`, `intentRouter` | `bundle-anti-drift.test.js` api-key set updated; §3.3's 44 cases re-run against the SHIPPED bundle (not just the probe); `mobile sync:portable` + `check:portable`; `web/test/core-bundle.test.js` byte-identity | LOW — portability already proven; bundle grows |
| 2 | G2 | Extend `web/verify-intent.js` to route by covenant version through `core/intent/router.js` instead of the hardcoded `MERKLE_RECOMPUTABLE_VERSIONS` list | Golden capture of the CURRENT v0.4 verifier outcome for every fixture in `web/test/helpers.js` FIRST; the refactor must reproduce every `refusalCodes` set and `lines[]` byte-identically for v0.4, and only ADD v0.5/v0.6 arms; mobile vendored bytes re-synced | MEDIUM — the reviewed signing artifact; must be a pure addition |
| 3 | G4 | Add `core/model/approval-package-v3/v4.js` to `MODULES`; expose `packageCommitmentV3/V4` + `commitmentPreimage` | Extend §3.3 to assert the browser-computed commitment equals the fixture commitments in `core/model/test/fixtures/golden-v3.json` (captured from the ORIGINAL sdk modules) | LOW |
| 4 | G5 | Emit `core/model/test/fixtures/amount-vectors.json` from `core/model/amounts.js` in CI; have BOTH `sdk/test/amounts.test.js` and `python/tests/test_amounts.py` read it | The generated file is the single source; the Python suite must assert its documented divergences EXPLICITLY (unicode digits, exotic whitespace, `bool`) rather than by omission | LOW |
| 5 | G6 | Export `reviewForBuild` from `sdk/src/wallet-requests-v4.js`; `server/src/simulate.js` calls it | Capture both presenters' output over the existing simulate fixtures FIRST; assert byte-identity after | LOW |
| 6 | G7 | (Optional) Replace `web/verify-intent.js`'s twin with the bundled canonical parser | Must preserve the verifier's exact refusal codes/messages; §3.1's lockstep test already fails on any divergence, so this is optional hardening, not a correctness fix | MEDIUM |
| 7 | G9 (new, recorded here) | A v0.6 EXPLANATION renderer beside `core/explain/token-explain.js`. The v0.6 swap manifest carries its own `explanation` array inline; the new controller manifest carries none, so a v0.6 non-swap operation has verification but no rendered human explanation | Golden-fixture the rendered lines from real builds; assert every number in the explanation is re-derivable from the manifest and that a REFUSED manifest never renders as approved (the `{ok:true}` fabrication case `core/explain` already tests) | LOW |
| 8 | G8 | Interface-split `sdk/src/ux-normalize-v4.js` and the builders' deterministic sections | The `core-extraction-step3.md` §4 member-golden method, verbatim: pre-split fixture, member-by-member identity, production-byte vector generators windowed-compared, full SDK suite | HIGH — touches the production-byte surface; requires the vector generators |

---

## 5. TEST COUNTS

| suite | before | after |
|---|---:|---:|
| `node --test core/*/test/` | 602 / 0 fail / 0 skip | **655 / 0 / 0** |
| of which `core/crossruntime/test/` | 134 | **178** |
| `node --test web/test/` | 337 / 0 / 0 | **343 / 0 / 0** |
| `cd mobile && npm test` | 81 / 0 / 0 | **81 / 0 / 0** |
| `cd mcp && npm test` | 53 / 0 / 0 | **53 / 0 / 0** |
| `node --test integrations/test/` | 188 = 182 pass / 6 skip | **188 = 182 / 6** |
| `node --test conformance/` | 20 / 0 / 0 | **20 / 0 / 0** |
| `cd sdk && npm test` | 897 = 802 pass / 0 fail / 95 skip | **904 = 809 / 0 / 95** |

There is no separate `server/test` directory — the server's coverage
lives in the SDK suite's `hosted-*` / API suites, which the `sdk` row
includes. `tests/vm` (Rust) was not run, and the SDK production-byte vector
generators were not re-run: `git diff` vs the base is EMPTY for
`sdk/src`, `contracts/`, `tools/`, `tests/`, `server/`, `integrations/`,
`python/`, `mcp/`, `conformance/`, `data/`, `security/`, `examples/` and
`deploy/`. Only `core/`, `web/`, `mobile/www/vendor` (regenerated) and
`sdk/test` changed, so no builder, serializer, encoder, compiler or
covenant byte path was touched. Classification: NOT APPLICABLE (the
production-byte rule was applied and found to have no trigger), stated
rather than skipped silently.

Skips are the pre-existing `REQUIREMENT_NOT_AVAILABLE` /
`POLICYVAULT_TEST_PG_*` gates; no test was weakened, deleted, skipped or
reclassified. Two SDK BROWSER harnesses were made MORE faithful (they now
evaluate the committed `web/core-bundle.js` before `web/app-v4.js`,
exactly as `web/index.html` does) — see §3.1's note; no assertion in
either was changed.

---

## 6. Claim labels

- `core/intent/token-manifest-v6.js`, `core/intent/router.js`:
  **IMPLEMENTED + UNIT-TESTED + INTEGRATION-VERIFIED** (real builder,
  real `silverc`, real `pv_call_encoder`, real `pv_tx_probe`).
  NOT VM-VERIFIED as a new consensus surface — it adds none; NOT
  TESTNET-VERIFIED;.
- Browser canonical amounts: **IMPLEMENTED + UNIT-TESTED** with
  byte-identity parity evidence against the pre-migration code.
- v5/v6 cross-runtime battery: **UNIT-TESTED** (deterministic, offline).
- The inventory and gap list: **ANALYSIS**, source-derived.

---

## 7. Wave 2 Track F addendum (2026-09-03) — v0.6/v0.7 bundling, router
wiring, mechanical parity gates, and a re-run SERVER-ONLY FINANCIAL FACTS
inventory

Lane `w2-f-shared-core` (base `6f9eb73` on `flagship-wave2`). Executes the
§4 migration plan items 1-3 and 5 for v0.6, extends the same treatment to
v0.7 (not yet in scope when §4 was written), and closes G4/G5/G6/G9 by the
method already established in §3 (capture/migrate/prove, never delete a
check).

### 7.1 SERVER-ONLY FINANCIAL FACTS re-run — **result: 0** (unchanged)

Method: the same one §1's headline table used — grep every `BigInt(` site
across `server/src/*.js` (excluding `*.test.js`) and classify each as
cursor/sequence/coordination vs. an independently-computed financial fact;
cross-checked against a `no-float-financial-parsing` scan (§7.4 below) for
the float-arithmetic equivalent of the same question. Re-run over the
CURRENT tree, which now also includes this wave's own v0.6/v0.7 additions
to `core/` (server/src imports none of them) and `sdk/src/wallet-
requests-v4.js` `reviewForBuild` becoming exported (§7.3).

`server/src` is unchanged in file count (31 modules) since the headline
table was written. `server/src/org-roots.js` (named in this track's
exclusion list as a precaution) **does not exist in this tree** — the v0.7
app-surface contract landed as a design document only
(`docs/postlaunch/v0.7-app-surface-contract.md`, commit `6f9eb73`), so
there is no v0.7 server route surface to inventory yet.

Exactly 5 `BigInt(` sites, unchanged in kind from the headline table's
description:

| site | value | classification |
|---|---|---|
| `server/src/risk-adapters.js:46` `parseSompiParam` | a risk-adapter PARAM the caller supplies (a configured threshold), bounds-checked against the i64 domain | coordination — a policy THRESHOLD, not a chain fact |
| `server/src/risk-adapters.js:59` `readSpendAmount` | reads `intent.payAmountSompi` — a value the SDK/core ALREADY computed and put in the intent | coordination — relays an existing fact, computes nothing new |
| `server/src/events-store.js:106` | `BigInt(cursor)` | pagination cursor |
| `server/src/events-store.js:175` | `BigInt(row.seq) <= after` | sequence-number comparison |
| `server/src/events.js:320` | webhook delivery cursor | pagination cursor |

**Conclusion: still 0 SERVER-ONLY financial facts.** No new site was
found; none needed migration into the shared core. (Contrast with a
*positive* finding this wave's `no-float-financial-parsing` scan DID
surface, in `sdk/src` and `web/` — see §7.4; scanning `server/src` with
the same tool independently found zero unjustified hits there too.)

### 7.2 G2/G3 — closed (browser + mobile can now verify v0.5/v0.6/v0.7 locally)

- `web/tools/build-core-bundle.js` `MODULES` gained the full v0.6 closure
  (`vault-state-v6`, `agent-merkle-v6`, `swap-policy-v6`, `vault-
  transitions-v6`, `compute-budget-v6`, `storage-mass`, both v0.6 manifest
  modules), the v0.7 closure (`owner-set-v7`, `vault-state-v7[-root]`,
  `vault-transitions-v7[-root]`, `compute-budget-v7`, `org-root-manifest-
  v7`, `org-root-explain`, `org-root-slot-v7`), and `core/intent/router.js`
  — 32 new modules total, all loading and running byte-identically in the
  Buffer-free browser-shaped sandbox (`core/crossruntime/test/v6-v7-
  shipped-bundle.test.js`, 63 cases through the SHIPPED bundle, not just
  the forward-looking probe §3.3 used).
- `web/verify-intent.js` gains `verifyManifestBeforeSigning(args)` — an
  ADDITIVE new entry point beside the untouched `verifyBeforeSigning`
  (v0.4/v0.4.1; same 437 pre-existing `web/test` assertions pass unchanged
  after the addition — the practical byte-identical-behavior proof, since
  no line of that function's code changed). It routes a manifest through
  the bundle's `core/intent/router.js` to policyvault-0.5 / -0.6 controller
  / -0.6 swap / -0.7-root, and refuses policyvault-0.7-payment
  `VERIFY_WITHIN_PARENT` (no standalone verifier by design) and anything
  else `UNKNOWN_MANIFEST_VERSION` — never a default route
  (`web/test/verify-manifest-router.test.js`, 12 cases).
- **A real PRODUCTION CODE BUG was found and fixed while building the
  fail-closed test matrix for this**: every table `core/intent/router.js`
  indexes by a caller-supplied string was a plain object literal, so a
  `manifestVersion`/`contractVersion`/action of `"constructor"`,
  `"__proto__"`, `"toString"`, `"hasOwnProperty"`, etc. resolved through
  `Object.prototype` to a truthy built-in instead of `undefined` on a bare
  `TABLE[key]` lookup —
  `resolveIntentRoute("constructor")` silently returned the `Object`
  function rather than throwing `UNKNOWN_VERSION`. No ordinary input ever
  triggers this (it needs a specific string, not a general malformed
  value), and every net-visible caller in this tree still ended up
  refusing (the garbage route object's missing `.build`/`.verify` throws
  an uncoded TypeError one level down) — but an uncoded exception is not
  the same as a deliberate, coded, fail-closed refusal, and a future
  caller that trusted `resolveIntentRoute`'s return value directly would
  not have been protected. Fixed with an `ownGet` own-property-only
  guard applied to every such lookup (`MANIFEST_FAMILIES`, `ROUTES`,
  `NON_PORTABLE_VERSIONS`, `UNSUPPORTED`, the imported `ACTIONS` tables);
  pinned by 12 prototype-shaped keys × 7 router entry points
  (`core/intent/test/router.test.js`) and re-proven through the shipped
  bundle (`core/crossruntime/test/v6-v7-shipped-bundle.test.js`,
  `unknown-version-fail-closed-matrix.test.js`).
- G3's remaining §4-row-1 checklist items are done: bundle anti-drift
  api-key set updated, `mobile/tools/sync-portable.js` re-run
  (`check:portable` OK, 3 artifacts), `web/test/core-bundle.test.js`'s
  reviewed-module-list pin updated.

### 7.3 G4 closed, G6 closed, G9 closed (via a generic renderer), G8 unchanged (residual, recorded honestly)

- **G4 closed**: `core/model/vault-state-v3.js` (dependency only),
  `approval-package-v3.js`, `approval-package-v4.js` are now bundled and
  exposed (`approvalPackageV3`, `approvalPackageV4`, `vaultStateV3` on the
  api surface) — a browser approver can independently recompute the exact
  M-of-N package commitment they are approving.
- **G6 closed**: `sdk/src/wallet-requests-v4.js` `reviewForBuild` is now
  exported; `server/src/simulate.js` `reviewFromBuild(config, manifest,
  build)` calls it directly instead of re-stating the same
  `build.accounting` → KAS-string presenter field-for-field. The
  simulation's `review` object now carries the FULL field set the real
  request path shows (action/network/vaultId/predecessorOutpoint/
  policyNonce.../recipient/recipientAddress/approvalsRequired in addition
  to the fee/protected/reserve fields both presenters always computed
  identically) — the dry run and the real request can no longer drift in
  what they show a human, which was G6's actual concern. Verified against
  the existing `sdk/test/postlaunch-simulate-capabilities-server.test.js`
  (25/0/0, real silverc builds) and `sdk/test/budget-reservation.test.js`.
- **G9 closed, by a generic (not bespoke) renderer**: rather than building
  a new `core/explain/controller-explain-v6.js` (a new architecture
  surface this wave deliberately avoided per its own scope), `web/verify-
  intent.js`'s `verifyManifestBeforeSigning` renders v0.6 controller/swap
  manifests (which have no dedicated explain module) from the real
  recomputed `checks`/`failures` array directly — every line is either the
  verdict or one recomputed check name/detail, never invented prose, and a
  REFUSED verification can never render as approved. v0.5 and v0.7-root
  still use their dedicated renderers (`tokenExplain`,
  `orgRootExplain`) where available, with the SAME generic fallback if a
  dedicated renderer throws on a malformed manifest (a real robustness
  fix found during testing — see `web/test/verify-manifest-router.test.js`
  "an explain-renderer failure ... falls back to the generic ...
  renderer"). A v0.6 operation is now verified AND narrated, honestly
  labeled as a mechanically-derived narration rather than a purpose-built
  one; a bespoke v0.6 renderer (matching `token-explain.js`'s hand-written
  per-field prose) remains a residual if a future track wants it.
- **G8 unchanged (residual)**: `sdk/src/ux-normalize-v4.js` and the
  builders' deterministic sections remain unextracted. Still correctly
  HIGH risk per §4's own table (touches the production-byte surface,
  needs the `core-extraction-step3.md` §4 member-golden method and the
  vector generators) and out of this track's rules (`tools/gen_*.js` is
  forbidden to touch). Not attempted this wave.

### 7.4 No-float-financial-parsing mechanical scan (new; not a numbered gap)

`sdk/test/no-float-financial-parsing.test.js` scans `web/`, `mobile/www/
js/`, `server/src/`, `sdk/src/`, `mcp/src/`, `core/`, `python/` for
`parseFloat(`, `Number(`/unary-`+` on a financial-shaped identifier,
`Math.round(...)` combined with a `1e8`/`100000000` literal (the exact G1
defect shape), `.toFixed(` on a financial identifier, and Python `float(`
on a financial identifier. 16 raw hits, individually classified in
`sdk/test/no-float-financial-parsing.allowlist.json`:

- 14 are small-integer/bounds-checked conversions (compute-budget sig-op
  counts, swap-policy `smallInt` fields, the `contract-compiler*.js` /
  `token-program-kcc20.js` `intArg`/`byteArg` helpers) — every one
  converts a BigInt to `Number` ONLY after an explicit
  `value > BigInt(Number.MAX_SAFE_INTEGER)`-shaped bounds check fails
  closed immediately above, so the conversion is exact/lossless by
  construction: the opposite of G1's unbounded float-parsing shape.
- **2 real, low-severity, DISPLAY-ONLY hits remain, RECORDED AS A
  RESIDUAL rather than fixed**: `web/app-v4.js:244` (a warning-message KAS
  threshold, `Number(minSompi) / 1e8`, `minSompi` a small hardcoded
  default, not user/attacker-controlled) and `web/app.js:864` (an
  org-overview "Total protected" aggregate, `Number(v.live?.
  protectedValueKas)` summed across an organization's vaults). Neither is
  on a funds-moving decision path. `web/app*.js` is outside this track's
  edit scope (excluded by the lane's own rules; owned by Track B-web) —
  the fix recommendation (migrate to `core/model/amounts.js`
  `sompiToKas` / integer sompi summation, now bundled and already used
  elsewhere in both files for the G1 fix) is recorded for that track
  rather than applied here.

### 7.5 Updated test counts (this addendum's commits only; cumulative over §5's table)

| suite | before this addendum | after |
|---|---:|---:|
| `node --test core` (recursive) | 1110 (§5's `core/*/test/` figure is not directly comparable — recursive count) | **1179 / 0 / 0** |
| `node --test web/test/` | 343 | **449 / 0 / 0** |
| `cd mobile && npm test` | 81 | **97 / 0 / 0** |
| `cd mobile && npm run check:portable` | — | OK (3 artifacts) |
| `python3 -m unittest discover -s tests` | 88 | **92 / 0** |
| `sdk/test/postlaunch-simulate-capabilities-server.test.js` (G6 regression) | — | **25 / 0 / 0** |

No test was weakened, deleted, skipped, or reclassified. The full `cd sdk
&& npm test` (with the dev PG suites) and `cargo test` (`tests/vm`) runs
are reported separately in this track's final report, not duplicated here.

### 7.6 Claim labels (this addendum)

- Bundled v0.6/v0.7 modules, `core/intent/router.js` browser wiring:
  **IMPLEMENTED + UNIT-TESTED** with byte-identity parity evidence against
  Node, through the SHIPPED bundle (not just a portability probe). NOT
  VM-VERIFIED as a new consensus surface (adds none); NOT TESTNET-VERIFIED;
.
- `core/intent/router.js` prototype-shaped-key fix:
  **IMPLEMENTED + UNIT-TESTED** (Node + shipped bundle), a genuine
  defect found and closed by this wave's own adversarial test-writing, not
  a hypothetical.
- Amounts Python parity gate: **IMPLEMENTED + UNIT-TESTED** (mechanical,
  generated fixture, both languages).
- No-float-financial-parsing scan: **IMPLEMENTED + UNIT-TESTED**
  (mechanical, allowlist-gated, 2 residuals recorded honestly, not fixed).
- SERVER-ONLY FINANCIAL FACTS re-run: **ANALYSIS**, source-derived,
  result 0, cited sites listed in §7.1 for independent re-verification.
