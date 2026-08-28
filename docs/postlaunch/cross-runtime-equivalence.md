# Cross-Runtime Core Equivalence (PostLaunchUpgradeOG)

**Status: DESIGNED + IMPLEMENTED + UNIT-TESTED.** Deterministic,
offline, vector-comparison mission (no PostgreSQL, no docker, no
network, no live nodes; branch merges into `postlaunch-rc`). This is
the completion-standard's "cross-runtime equivalence" pipeline item
(`docs/postlaunch/COMPLETION_STANDARD.md`), covering the "portable
local shared core" layer's one binding property: **the local-first
verification a signer relies on must not silently compute something
different depending on where it runs.**

Implementation: `core/crossruntime/sandbox.js` (harness),
`core/crossruntime/vectors.js` (shared vector battery), seven suites in
`core/crossruntime/test/` (127 cases). Nothing here modifies
core/intent, core/explain, core/model, core/signer, or web/ — every
file under test is consumed read-only, exactly as committed.

---

## 1. Runtimes compared

| # | Runtime | How it's instantiated | What it covers |
|---|---|---|---|
| 1 | **Node direct** | `require("core/...")` in this process's own V8 realm | The reference implementation |
| 2 | **Browser bundle** | The COMMITTED `web/core-bundle.js`, evaluated via `vm.Script(...).runInContext(...)` inside a fresh `vm.Context` shaped like a browser global (`window === globalThis === self`; `crypto.getRandomValues` backed by Node's WebCrypto; **no** `require`/`module`/`process`/`Buffer`) | The exact `window.PolicyVaultCore` branch a real page executes — not the `module.exports` CommonJS escape hatch a plain `require()` would take |
| 3 | **CLI signer core path** | The REAL `core/signer/adapters/cli/adapter.js`, constructed with a synthetic (never-read) keyfile path, exercised up to (not through) its lazy kaspa-wasm boundary | The descriptor/negotiation surface this materially-different signer shares with core/signer/interface.js, the same module the bundle embeds |
| 3′ | **Core-model probe** (forward-looking, not "the bundle") | An analogous `vm.Context`, generalized to load an EXPLICIT list of `core/model/*.js` files not (yet) in the bundle's reviewed module set | Whether those files would already run unmodified in a browser today |

Runtime 2 is reached exclusively through `core/crossruntime/sandbox.js`
`loadCommittedBundleInBrowserGlobal()`; runtime 3′ through the same
file's `loadCoreFilesInSandbox(relPaths)`, a generalization of
`web/tools/build-core-bundle.js`'s own loader technique to an arbitrary
explicit file list (it is not a second bundle generator; nothing it
produces is shipped). Full method/rationale is documented inline in
`sandbox.js`.

A real second JS engine (e.g. an actual browser's SpiderMonkey/
JavaScriptCore) was **not** used — see §7 residual gaps.

---

## 2. The vector battery

`core/crossruntime/vectors.js` holds the hand-built battery; the real
manifest fixtures come from `core/intent/testutil/fixtures.js`
(read-only reuse — the same fixtures core/intent's own test suite and
`web/test/core-bundle.test.js` already trust).

| Battery | Entries | Composition |
|---|---:|---|
| `SHA256_VECTORS` | 22 | empty/short/1-char strings; SHA-256 block-boundary lengths (54,55,56,63,64,65,119,120,1000,10000 chars); multi-byte UTF-8 incl. an astral-plane code point and surrogate-pair runs; control chars; a UTF-8 BOM; NFC-vs-NFD "á"; Cyrillic-confusable text (`аpple.com` vs `apple.com`) |
| `CANONICAL_JSON_VECTORS` | 14 | key-order/sorting, nesting, unicode keys+values (incl. emoji keys), numeric edge cases (`-0`, `1e21`), empty containers, JSON escapes, NFC/NFD distinctness, Cyrillic-vs-ASCII key distinctness, top-level primitives, repeated array elements |
| `MESSAGE_SIGNING_VECTORS` | 4 | plain / unicode / `MAX_MESSAGE_CHARS`-boundary (16384) / with-expected-address |
| `TRANSACTION_SIGNING_VECTORS` | 2 | testnet-10 single-input; mainnet multi-input incl. index 41 |
| `PUBLIC_KEY_NORMALIZATION_VECTORS` | 8 | 64-hex x-only, 66-hex compressed (02/03, mixed case), uncompressed 04 (refused), garbage, empty, one-digit-short |
| `CAPABILITY_NEGOTIATION_REQUIREMENTS` | 6 | scheme/feature/network requirement combinations, incl. two designed to fail negotiation |
| `STATE_ID_V4_VECTORS` | 4 | representative testnet v0.4, mainnet v0.4.1, zero-approver vault, MAX_SOMPI + max-policyNonce + full-10-approver boundary |
| `STATE_ID_V1_VECTORS` | 2 | representative v1, three-recipient mainnet |
| `FEE_MASS_TX_VECTORS` | 3 | small single-input, covenant-shaped multi-I/O, many-small-outputs |
| `BUDGET_V4_OPERATIONS` / `BUDGET_V3_OPERATIONS` | 9 / 13 | every v0.4 and v0.3 production entrypoint, both approval tiers where applicable |
| `REPRESENTATIVE_SOMPI` | 7 | 0, 1, and representative amounts up to `MAX_SOMPI` |
| Manifest fixtures (reused, not reinvented) | 11 actions | agentSpend, ownerTopUp, ownerPause, ownerSetApprovers, ownerSetAgentRoot (direct + addAgent/removeAgent/rotateAgent/rePolicyAgent aliases), ownerRecover, createVault |

**94** hand-built raw vectors + **11** real manifest-fixture actions,
each driven through multiple detectors/assertions per runtime =
**127** test cases across 7 suites (below).

Manifest identity fields (recipients, keys, roots) are closed-schema
32-byte hex by `core/intent/manifest.js` design — there is no such
thing as a "unicode recipient" at that layer (verified: `requireHex`
refuses anything else). The unicode/confusable requirement is exercised
at the two layers where it is actually schema-legal and actually
adversarially meaningful: the SHA-256/canonical-JSON primitive layer
(any byte sequence), and manifest `warnings[].detail` (free text up to
2000 chars — exactly where a hostile server/frontend would try to
smuggle lookalike-domain or bidi-override text into what a human reads
before signing). Both are covered.

---

## 3. Results — per surface

All byte-identical unless noted.

| Surface | Node direct vs Browser bundle | Detail |
|---|---|---|
| Intent manifest canonical bytes + `computeManifestHashV1` | **BYTE-IDENTICAL** | 11/11 fixture actions; representation-independence (reversed key order + JSON round-trip) proven cross-runtime too, not just within one runtime |
| `verifyIntentManifest` verdict + detector codes | **BYTE-IDENTICAL** | 11/11 clean passes; 3 policy-invalid adversarial test manifests (recipient substitution, fee inflation, hidden authority expansion) refuse with identical sorted code sets and identical per-detector pass/fail vectors, in fixed detector order |
| `core/explain` structured() + humanReadable() | **BYTE-IDENTICAL** | 7 representative fixtures, a REFUSED rendering, and a fabricated-`{ok:true}` re-verification-refusal case |
| SHA-256 (shim vs `node:crypto`) | **BYTE-IDENTICAL** | 22/22 vectors, three-way (node:crypto, core/intent Node, bundle shim); chunked `update()` matches single-call; fail-closed refusal surface (non-string update, non-hex digest, sha512) confirmed to genuinely narrow vs. `node:crypto`'s wider real surface |
| `randomBytes` | **FORMAT-IDENTICAL** (32-hex), values differ by design | Entropy; value equality is neither possible nor desired |
| Signer interface (`core/signer/interface.js` + `errors.js`) | **BYTE-IDENTICAL** | error-code vocabulary, `SignerError` shape, `normalizeAdapterFailure` classification, `createMessageSigningRequest`/`createTransactionSigningRequest` (requestId/createdAtMs normalized out, format-checked separately), `assertCanonicalSignInputs`, `normalizePublicKeyToXOnly` (8/8 vectors), `validateCapabilityDescriptor` + `negotiateCapabilities` (6/6 requirement sets) |
| CLI signer adapter's real descriptor | **BYTE-IDENTICAL** | The REAL `createCliSignerAdapter(...).describe()` output (testnet-10 AND a dual-unlocked mainnet construction) normalizes and negotiates identically through Node's and the bundle's copies of `core/signer/interface.js` |
| State IDs — `computeStateIdV4` | **BYTE-IDENTICAL** (probe, not the bundle — see §4) | 4/4 vectors incl. MAX_SOMPI + max-policyNonce + full-approver-set boundary; empty-networkId reject-path also identical |
| State IDs — `computeStateId` (v1) | **BYTE-IDENTICAL** (probe) | 2/2 vectors |
| Fee/mass (`fee-mass.js`) | **BYTE-IDENTICAL** (probe) | 3/3 tx shapes incl. reject-path (mass-cap exceeded) |
| Compute budgets (v3 + v4) | **BYTE-IDENTICAL** (probe) | 9/9 and 13/13 operations, plus unknown-operation refusal message |
| `canonical-json.js` (core/model) vs `canonical.js` (core/intent) | **BYTE-IDENTICAL**, three-way | 14/14 accept vectors + 5/5 reject vectors — these are independently-maintained TWINS (both restate the Phase-G G-2 remediation semantics without importing each other) and were proven to stay in lockstep |
| `sompiToKas` (core/model) vs `sompiToKasString` (core/explain) | **BYTE-IDENTICAL**, cross-implementation | 8/8 amounts incl. `MAX_SOMPI`, another independently-maintained pair |

"(probe)" = proven for core/model's own unmodified source running in a
browser-like sandbox; **not** a claim about the shipped
`web/core-bundle.js`, which does not embed core/model (§4).

---

## 4. Bundle-vs-source anti-drift result

**PASS.** `web/core-bundle.js` (committed) is byte-identical to a fresh
`generateBundle()` regeneration from the current `core/intent`,
`core/explain`, `core/signer` sources — confirmed independently by this
suite's own harness (`bundle-anti-drift.test.js`), in addition to the
pre-existing `web/test/core-bundle.test.js` assertion. No drift.

---

## 5. Findings

### 5.1 DRIFT (real, reproduced, root-caused): three `core/model` files are not yet browser-portable

> **CLOSED by the F1 browser-portability wave (branch `f1-portability`,
> 2026-08-26; evidence: `docs/postlaunch/f1-merkle-portability.md`).**
> `recipient-merkle-v3.js` and `agent-merkle-v4.js` are now byte-native
> (Uint8Array; no ambient Buffer), the bundle crypto shim supports
> exactly `update(<Uint8Array>)`/`digest()` alongside its original
> string surface, the two Merkle modules (+ `amounts.js`,
> `contract-version.js`, `vault-state.js`) are embedded in
> `web/core-bundle.js`, and `vault-transitions-v4.js` loads transitively.
> Byte identity with the pre-refactor implementation is pinned by
> `core/model/test/golden-f1-merkle.test.js` (fixture captured from the
> ORIGINAL code) plus the production-byte vector generators. The TIER2
> documented-gap tests below were flipped into full cross-runtime byte
> equivalence tests (`core-model-portability.test.js`): all 14
> core/model files now load and run byte-identically in the browser-like
> sandbox. The remainder of this section is kept as the historical
> finding record.

**What:** `core/model/agent-merkle-v4.js` and
`core/model/recipient-merkle-v3.js` — and, transitively,
`core/model/vault-transitions-v4.js` (`require("./agent-merkle-v4")`)
— throw `ReferenceError: Buffer is not defined` when their unmodified
source is loaded in a browser-like sandbox (no other core/model file
does; 11/14 files load and run cleanly with zero changes — §6).

**Reproduction:** `core-model-portability.test.js` TIER2 cases load a
sandbox with **all 14** core/model files available and call
`.require()` on each of the three; each throws the exact
`ReferenceError` above, in both load orders tried (agent-merkle-v4
first, and vault-transitions-v4 first — see the cache-eviction note in
§6).

**Root cause, precisely, in two independent layers:**
1. Both files reference the ambient Node global `Buffer` directly
   (`Buffer.from(...)`, `Buffer.alloc(8)`, `Buffer.concat([...])`,
   `Buffer.isBuffer(...)`) — never through `require("buffer")`, so
   `core/model/test/purity.test.js`'s static `require(...)`-call scan
   cannot see this dependency; it is real only at runtime.
2. **Even with a Buffer polyfill**, their `sha256()` helper calls
   `crypto.createHash("sha256").update(<Buffer>).digest()` — raw bytes
   in, raw bytes out, no encoding/format arguments. This is OUTSIDE the
   existing browser crypto shim's exact supported surface
   (`update(<string>, "utf8")` / `digest("hex")` only — anything else
   fails closed by design). Reproduced directly against the committed
   `CRYPTO_SHIM` source in `core-model-portability.test.js`'s final
   case: `update(Buffer.from("ab"))` throws "...strings only...", and
   `update("ab","utf8").digest()` (no format) throws "...unsupported
   digest format...".

**Impact today: none (latent).** core/model is not in
`web/tools/build-core-bundle.js`'s `MODULES` list at all, so this
never executes in the real, shipped browser page. This finding matters
only for a *future* wave that wants browser-side Merkle verification —
`core/explain/intent-explain.js`'s own residual-trust table already
documents (independently, in `docs/postlaunch/browser-verification.md`
§5 item 4) that "the browser core has no Merkle module in v1"; this
finding is the precise, reproduced reason why extending it is not a
drop-in.

**Recommended action (coordinator decision — two options, not
mutually exclusive):**
- **(a) Extend the bundle generator's crypto shim** with a byte-native
  variant alongside the existing string/hex surface — e.g.
  `sha256Bytes(Uint8Array) -> Uint8Array`, which the shim's existing
  pure-JS block-processing code can serve almost for free (its
  `sha256HexOfUtf8` already reduces to byte-array processing after
  `utf8Bytes()`; a byte-native entry point only needs to skip that one
  step) — plus a minimal `Buffer`-like polyfill (`from`/`concat`/
  `alloc`/`isBuffer`/`subarray`/`toString("hex")`/`writeBigUInt64LE`)
  covering exactly the calls these two files make (enumerated in full
  in the code that reproduces this, `core-model-portability.test.js`).
  This is backward-compatible: it adds surface, changes nothing the
  eight already-embedded modules use.
- **(b) Refactor `agent-merkle-v4.js`/`recipient-merkle-v3.js`** to
  operate on hex strings + a byte-array-returning hash helper instead
  of `Buffer`, matching the Buffer-free style every OTHER core/model
  file already uses (`amounts.js`, `vault-state*.js`,
  `vault-transitions-v3.js`, `fee-mass.js`, `compute-budget-*.js`) —
  removing the dependency at the source rather than shimming around it.

No fix was attempted here: both options touch `web/tools/
build-core-bundle.js` and/or `core/model`, outside this mission's
writable scope (`core/crossruntime/**` + this document only).

### 5.2 Methodology finding: realm identity affects `instanceof`/prototype checks, not values

Building the sandbox harness surfaced (and required correcting for) a
general fact about `vm.Context`-based cross-realm testing, with two
concrete manifestations found directly in this codebase's own
production logic:

- `core/intent/canonical.js`'s (and `core/model/canonical-json.js`'s)
  `canonicalJsonStringify` detects "is this a plain object" via
  `Object.getPrototypeOf(v) !== Object.prototype` — checked against the
  **calling code's own realm**. A structurally plain object built in a
  *different* realm fails that check and is refused as "non-plain",
  even though every value inside it is identical. Reproduced directly
  in `core-model-portability.test.js`'s dedicated
  "REALM-SENSITIVITY finding" case: a real object returned by the
  sandboxed `normalizeTemplateV4` is refused by the host's
  `canonicalJsonStringify`, and accepted once re-homed.
- `e instanceof ReferenceError` (or any built-in constructor) is
  **false** for an error thrown by code executing inside a different
  realm, even for a completely genuine `ReferenceError` — its
  prototype chain points at that realm's own `ReferenceError.prototype`.
  `e.name`/`e.message`/`e.code` (plain string/primitive properties) are
  unaffected and are what this suite's own assertions use instead
  (`core-model-portability.test.js` TIER2 cases; `sandbox.js`
  `rehome`/`rehomeInto`).

**Assessment: not a bug, and not currently live in production.**
PolicyVault's actual browser page runs entirely in ONE realm — there is
no iframe, worker, or vm sandboxing in the real `web/` deployment — so
`canonicalJsonStringify` never sees a foreign-realm object in
production, and refusing one it did see is the correct fail-closed
choice for a commitment preimage (silently canonicalizing an object of
ambiguous provenance would be the unsafe behavior). This is recorded
here as a **portability caveat**, precisely reproduced, for exactly one
future scenario: if a Web Worker or sandboxed iframe is ever
introduced for browser-side verification (e.g. to isolate the verifier
process from the page that could be compromised — see
`browser-verification.md` §5 item 1's own residual-trust discussion of
that exact idea), any value crossing that boundary via
`postMessage`/structured-clone would need an explicit re-home
(`JSON.parse(JSON.stringify(...))`, exactly as this suite's own
`sandbox.js` does) before being handed to `canonicalJsonStringify`.
Full technical detail lives in `core/crossruntime/sandbox.js`'s
`rehome`/`rehomeInto` doc comments, which this suite's own tests
depend on being correct (verified by construction: every cross-runtime
comparison in this suite that touches a structured value uses them).

---

## 6. Notes for the coordinator (not findings, but worth recording)

- **A real harness bug was caught and fixed during this work**, worth
  noting because it could recur in any future hand-rolled sandbox
  loader: this suite's `loadCoreFilesInSandbox` originally cached a
  module's (empty) `exports` object **before** invoking its factory
  and did not evict that cache entry when the factory threw. A module
  that transitively `require()`s a failed module would then silently
  destructure `undefined` members from the stale empty stub instead of
  re-observing the failure — concretely, `vault-transitions-v4.js`
  appeared to "load successfully" (with its `agent-merkle-v4` imports
  silently `undefined`) in one specific test ordering, until this was
  caught and fixed by evicting the cache entry on throw (mirroring
  Node's own `require()` behavior). The fix and the reasoning are
  recorded in `sandbox.js`'s `load()` function; the TIER2 tests now
  pass identically regardless of load order (both orders are exercised
  explicitly).
- `core/model/test/purity.test.js` (pre-existing, unmodified) proves
  the STATIC half of core/model's portability claim (only
  `require("node builtin")` / sibling `./file` calls, no
  `process.env`, no sdk/server/web imports). This suite proves the
  DYNAMIC half (actual execution in an environment with zero Node
  globals beyond a browser-realistic `crypto`) — and that is exactly
  why the Buffer-global dependency in §5.1 was invisible to the static
  scan but visible here: the static scan only ever looks at
  `require(...)` call sites.
- `core/model/testutil/golden.js`/`golden2.js` (pre-existing,
  unmodified, consumed read-only) already carry a comprehensive,
  well-designed determinism battery for core/model's full surface,
  including `agentMerkle`/`recipientMerkle`. They were **not** invoked
  wholesale against the sandbox in this wave, precisely because
  constructing their required `mods.agentMerkle`/`mods.recipientMerkle`
  requires successfully loading exactly the two files this section's
  finding is about. If/when §5.1 is remediated, re-running
  `computeGolden`/`computeGolden2` with a sandboxed `mods` object
  (Node-direct vs. sandboxed, compared via `rehome()`) would be a very
  low-effort way to extend this suite's coverage to the full 14/14
  files with almost no new vector-authoring work.

---

## 7. Residual gaps (honestly out of scope for this wave)

- **One JS engine, not an independent second implementation.** "Browser
  bundle" and "core-model probe" both still execute inside THIS Node
  process's V8 — a separate `vm.Context` gives separate intrinsics
  (real value: it caught the two realm-sensitivity findings in §5.2)
  but is not proof against an independently-implemented engine (e.g.
  SpiderMonkey/JavaScriptCore, or a real browser). `docs/postlaunch/
  browser-verification.md` already records that the real-KasWare human
  acceptance pass (a real browser) is a later phase; that phase would
  be the first genuine cross-*engine* (not just cross-realm) evidence.
- **`core/signer/adapters/cli`'s actual signing calls** (`signMessage`/
  `signTransaction`, both requiring a real vendored kaspa-wasm module,
  loaded lazily) are out of scope for this deterministic, offline,
  no-vendored-dependency mission by design; they are covered by
  `core/signer/adapters/cli/test/*.test.js` instead. This suite proves
  only the portable core-overlap (descriptor/negotiation) surface —
  see `cli-signer-core-path.test.js`'s own header comment.
- **Merkle modules** (`agent-merkle-v4.js`, `recipient-merkle-v3.js`)
  are not part of the "byte-identical" claim at all — see §5.1; they
  are proven to currently REFUSE (not silently misbehave), which is
  the honest, correct status to record.
- **Governance/risk (`core/governance`, `core/risk`)** were out of this
  mission's named battery ("intent manifest ... state IDs ...
  fee/mass ... budget ... crypto shim") and were not touched.
- core/model's other three Tier-1-adjacent files not individually
  vector-tested here (`vault-state-v2.js`, `vault-state-v3.js` beyond
  the smoke/export-surface check) are proven to LOAD and export the
  same surface cross-runtime (`TIER1 smoke` cases, 11/11) but were not
  driven through their own dedicated business-logic vectors in this
  wave, since they are structurally identical in shape to
  `vault-state-v4.js`/`vault-state.js` (which are fully vector-tested)
  and share the exact same `crypto`/`amounts`/no-Buffer profile. Low
  residual risk; flagged for completeness rather than as a concern.

---

## 8. Open questions for the coordinator

1. Which remediation for §5.1 is preferred — extend the crypto shim
   (5.1a) or refactor the two Merkle files off `Buffer` (5.1b) — or
   defer until browser-side Merkle verification is actually scheduled?
2. Should `core/model` be added to `web/tools/build-core-bundle.js`'s
   `MODULES` list at all in a near-term wave (state IDs / fee-mass /
   budgets becoming independently browser-verifiable, not just
   intent-manifest-derived), given 11/14 files are proven ready today
   with zero changes?
3. Is a real-browser (not just real-KasWare-in-a-real-browser, but a
   literal second-engine) run worth scheduling as its own acceptance
   phase, given §7's one-engine caveat, or does the real-KasWare human
   acceptance phase already planned in `browser-verification.md`
   sufficiently retire that risk?

---

## 9. Test evidence (this wave)

- `core/crossruntime/` — **127/127** (`node --test core/crossruntime/`):
  `bundle-anti-drift.test.js` 3, `intent-manifest-equivalence.test.js`
  18, `explain-equivalence.test.js` 9, `crypto-shim-equivalence.test.js`
  26, `signer-interface-equivalence.test.js` 21,
  `cli-signer-core-path.test.js` 4, `core-model-portability.test.js` 46.
- `core/` (whole tree, incl. the above) — **576/576**
  (`node --test core/`; 449 pre-existing + 127 new, 0 skipped, 0
  failed) — confirms no interference with core/intent, core/explain,
  core/model, core/signer, core/governance, or core/risk's own suites.
- No PostgreSQL, no docker, no network, no live nodes, no new npm
  dependencies (node builtins only: `vm`, `fs`, `path`, `crypto`,
  `node:test`, `node:assert/strict`) were used anywhere in this wave.

## 10. Claim labels

| Component | Claim |
|---|---|
| Cross-runtime equivalence architecture + this report | DESIGNED |
| `core/crossruntime/sandbox.js`, `vectors.js`, and the 7 test suites | IMPLEMENTED |
| All of the above (127 cases) + `core/` regression (576 cases) | UNIT-TESTED |

Nothing in this wave is VM-VERIFIED, TESTNET-VERIFIED, or
PRODUCTION-HARDENED, and none of that is claimed. The two findings in
§5 are precisely reproduced and root-caused, not speculative; neither
was fixed here (outside this mission's writable scope), and neither is
currently live in production (§5.1 impact: latent, core/model is not
bundled; §5.2 impact: latent, the real page runs single-realm).
