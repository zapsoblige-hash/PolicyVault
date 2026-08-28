# PolicyVault Mobile Client — v1 Scaffold

**Overall claim: SCAFFOLDED. The mobile surface is NOT
production-capable.** No `.ipa` and no `.aab` has been built, no iOS or
Android device or simulator has executed this payload, no App Store or
Play submission has been prepared, and no signing transport is functional
end to end. Per-piece claim labels are in §1 and the honest
verified/unverified split is in §5. Nothing here is TESTNET-VERIFIED,
PRODUCTION-HARDENED, EXTERNALLY REVIEWED, or AUDITED.

This implements wave M0–M1 (partial) of
`docs/postlaunch/mobile-architecture-decision.md`, which remains the
authoritative design. Where this document and the decision disagree about
intent, the decision wins; where they disagree about what EXISTS, this
document and the code win.

---

## 1. What exists

Everything lives under `mobile/`. Nothing outside `mobile/` and this file
was modified.

| Piece | Path | Claim |
|---|---|---|
| Capacitor project (config, own `package.json`, committed lockfile) | `mobile/package.json`, `mobile/capacitor.config.json`, `mobile/package-lock.json` | **IMPLEMENTED** — `npx cap` runs; both platforms add successfully (§5) |
| Portable-artifact sync + hash pinning + build gate | `mobile/tools/sync-portable.js` | **IMPLEMENTED**, UNIT-TESTED |
| Vendored byte-identical portable layer | `mobile/www/vendor/` + `mobile/www/vendor-pins.json` | **IMPLEMENTED**, byte-identity UNIT-TESTED |
| On-device verification wiring | `mobile/www/js/portable/verification.js` | **IMPLEMENTED**, UNIT-TESTED (PASS + DO-NOT-SIGN through the app's own wiring) |
| QR frame codec (chunk, reassemble, integrity) | `mobile/www/js/portable/qr-frames.js` | **IMPLEMENTED**, UNIT-TESTED |
| Air-gap signing documents + independent second refusal | `mobile/www/js/portable/airgap.js` | **IMPLEMENTED**, UNIT-TESTED |
| Signer roster + capability-limitation data | `mobile/www/js/portable/signer-capabilities.js` | **IMPLEMENTED**, UNIT-TESTED |
| Hosted-API access (wraps the vendored SDK client) | `mobile/www/js/portable/api.js` | **IMPLEMENTED**, UNIT-TESTED |
| On-device build integrity | `mobile/www/js/portable/build-integrity.js` | **IMPLEMENTED**, UNIT-TESTED |
| Host environment report (platform layer) | `mobile/www/js/platform/env.js` | **SCAFFOLDED** — reports honestly; camera/file/push/biometrics all report UNAVAILABLE |
| DOM rendering + PASS/DO-NOT-SIGN ceremony | `mobile/www/js/platform/ui.js` | **SCAFFOLDED** — parses; never executed in a browser here |
| App shell + screens | `mobile/www/index.html`, `mobile/www/js/app.js`, `mobile/www/css/app.css` | **SCAFFOLDED** — parses; never rendered in a browser here |
| Test suites | `mobile/test/*.test.js` (+ `mobile/test/sandbox.js`) | **52 tests, 52 passing** |

**Screens present:** Vaults, Agents, Approvals, Activity, Alerts, Verify,
Sign (QR/air-gap), Signers (incl. capability limitations), Settings
(server config + Build integrity).

---

## 2. The sync + hash-pinning mechanism

This is the mechanism the whole architecture rests on: the mobile client
must run the **reviewed bytes**, never a rebuild, a re-translation, or a
bundler's output.

### 2.1 Closed artifact set

`mobile/tools/sync-portable.js` carries a CLOSED list of three artifacts.
Adding a row is a security-relevant change: it widens what the app
executes.

| Repository source | Packaged as | Mode | Installs |
|---|---|---|---|
| `web/core-bundle.js` | `mobile/www/vendor/core-bundle.js` | `verbatim` | `window.PolicyVaultCore` |
| `web/verify-intent.js` | `mobile/www/vendor/verify-intent.js` | `verbatim` | `window.PolicyVaultVerifyIntent` |
| `sdk/src/http-client.js` | `mobile/www/vendor/http-client.js` | `cjs-host` | `window.PolicyVaultHttpClient` |

**`verbatim`** means `sha256(dest) === sha256(src)` — the file is copied
with zero transformation. Both security-relevant artifacts use this mode.
Current digests (committed in `mobile/www/vendor-pins.json`):

```
web/core-bundle.js      sha256:8523d9e69228ef942ab5cf9d2c07fda594e6504b9a3229afbe29385ffa85d923
web/verify-intent.js    sha256:e89ae1c6b8c0e1b531118d8368df679eda1ea3f16581ce95c7d649b15936f347
sdk/src/http-client.js  sha256:6291be0a406b646fecd4a90f8a3c3b7e3e20ad68c615f1f4396edf708e8780a2
                        (emitted wrapper sha256:388de602ddedc8e72ad96d4f175559e048e8e0000d540f583ab21de3ad6e89c4)
```

**`cjs-host`** exists for one reason: `sdk/src/http-client.js` is a Node
CommonJS module (`require("crypto")` at the top, `module.exports` at the
bottom) and cannot be loaded by a `<script>` tag. Its bytes are embedded
**verbatim and recoverably** inside a fixed deterministic wrapper that
supplies `module`/`exports` and a **closed** `require` resolving only
`"crypto"`/`"node:crypto"` — and resolving it to the crypto shim
**already inside the reviewed core bundle**
(`PolicyVaultCore.require("crypto")`). No second crypto implementation is
introduced anywhere in the app. This is the same embedding technique
`web/tools/build-core-bundle.js` already uses for core sources. A test
extracts the embedded region and asserts equality with the repository
file.

### 2.2 How it stays in sync

Two gates, both wired into npm lifecycle scripts so they cannot be
skipped by forgetting:

```
node mobile/tools/sync-portable.js            # regenerate vendor/ + pins
node mobile/tools/sync-portable.js --check    # SOURCE gate,   exit 1 on drift
node mobile/tools/sync-portable.js --check-packaged
                                              # PACKAGED gate, exit 1 on drift
```

- **Source gate** (`--check`): what is committed under
  `mobile/www/vendor/` must be exactly what the generator would produce
  from the current repository sources; the pin file must match; and the
  vendor directory must contain **nothing unlisted** (an unlisted file in
  the payload is code the review never covered). Runs as `pretest`,
  `presync`, `precopy`, `preadd:ios`, `preadd:android`.
- **Packaged gate** (`--check-packaged`): `npx cap copy` is the **last**
  step that could substitute the verifier, running after every source-side
  check has passed. This gate re-reads what actually landed in
  `android/app/src/main/assets/public/` and `ios/App/App/public/` and
  judges it against the repository sources. Runs as `postsync`,
  `postcopy`, `postadd:*`. A platform directory that does not exist is
  skipped, never silently passed.

**When `web/core-bundle.js` or `web/verify-intent.js` changes**, the
source gate goes red on the very next `npm test` in `mobile/`. The fix is
always `npm run sync:portable` followed by reviewing the diff — never a
hand-edit of `mobile/www/vendor/`, which the gate would reject anyway.
Because `web/core-bundle.js` is itself generated and anti-drift-tested
against `core/**` (`web/tools/build-core-bundle.js --check`,
`core/crossruntime/test/bundle-anti-drift.test.js`), the chain from
`core/**` to the bytes on a phone is pinned end to end.

Both gates are proven to work **in both directions** by the test suite: a
single injected byte, an unlisted file, a stale pin file, and a
substituted verifier in a copied payload each make the gate go red
(verified against scratch copies, never by mutating the committed
payload).

### 2.3 On-device integrity

`mobile/www/vendor-pins.json` ships **inside** the payload, so the
Settings → Build integrity screen re-reads each packaged artifact off the
app's own origin, re-hashes it with the packaged core's own sha256, and
compares against the pin. An unreadable artifact is a FAILURE, not an
"unknown" rendered as neutral. Stated plainly on the screen and here: this
proves the packaged files match their pins **as read by this running
code**; it is not an attestation, and a compromised build can lie about
any screen including that one. Play Integrity / App Attest are not
implemented and must never be described as reproducibility.

---

## 3. The portable/platform seam

`docs/postlaunch/mobile-architecture-decision.md` §3.6 makes the Capacitor
decision reversible by requiring a hard two-layer seam. Risk R10 names the
failure mode: the rule decays unless something breaks when it is broken.

`mobile/test/seam.test.js` is that something. Over `mobile/www/js/portable/**`
it statically forbids `document.*`, `navigator`, `localStorage`,
`sessionStorage`, `indexedDB`, ambient `fetch(`, `XMLHttpRequest`,
`Capacitor`, `alert(`, `require(`, and any reference to a platform module —
after stripping comments and string literals, so prose that merely NAMES
the DOM does not trip it. `window` is permitted on exactly one line per
file: the self-install guard. It additionally asserts that the platform
layer never restates what the verifier says (no
`THIS TRANSACTION DOES EXACTLY WHAT WAS REQUESTED`, no
`buildIntentManifest`, no `agentRecipientRoot`, …), that `ui.js` renders
`outcome.lines` rather than composing a verdict, that the verdict layer
creates exactly ONE control and it is the explicit Cancel, and that the
stylesheet contains no `text-overflow`, `line-clamp`, or `nowrap` (§6.3
rule 8 — eliding an address is how a small screen silently weakens the
ceremony).

If React Native is ever adopted (the documented escape hatch), the
portable layer moves unmodified and only `js/platform/**` + `js/app.js`
are rewritten.

---

## 4. Verification, signing, and honest UX behaviour

### 4.1 Verify screen

Runs the **real** packaged verifier over a pasted or fetched request
document and renders exactly what the browser renders, because the lines
come from the same `core/explain` code. A refusal owns the screen; the
signing affordance is **absent, not disabled**; refusal codes are shown
verbatim in a copyable, content-free diagnostics block.

### 4.2 QR / air-gap signing

The v1 signer is the existing offline `core/signer/adapters/cli` reference
signer over an optical or file gap — a new **transport**, not new
cryptography and not a new document format. The app builds the CLI
signer's own `policyvault-cli-signing-request/1` document with exactly its
closed six-key schema (`format`, `kind`, `network`,
`expectedSignerAddress`, `unsignedSafeJson`, `signInputs`) and validates
its own `policyvault-cli-signer-signed-transaction/1` response.

Enforced, and tested:

1. **A signing request cannot be built without a PASS bound to the exact
   payload bytes.** `VERIFICATION_REQUIRED` / `VERIFICATION_REFUSED` /
   `VERIFICATION_TX_BINDING_MISMATCH` — the independent second refusal, so
   a UI defect alone cannot produce a signature.
2. **`signInputs` are taken from the durable request and re-asserted**,
   never invented or trimmed; every entry must be exactly
   `{ index: integer ≥ 0, sighashType: 1 }`.
3. **A scanned response is bound back** to the verified transaction:
   format, kind, network, signer address, and the transaction id embedded
   in the signed payload must all match.
4. **Frame integrity**: frames carry the document sha256; reassembly
   refuses on an incomplete scan, a conflicting duplicate, mixed
   documents, an unknown frame version, or a digest mismatch.

**Honest limit, stated rather than papered over:** the app does NOT verify
the Schnorr signature bytes, does not re-derive the sighash, and does not
confirm that the signed payload differs from the unsigned one only in
signature scripts. It confirms provenance and transaction identity. The
authoritative checks remain where they already are — the server's
finalizer re-derives the frozen txid and runs a VM preflight before
broadcast — and the covenant remains the only security boundary.

### 4.3 No key custody, anywhere, ever

There is no key material in this app, no device-key signer, no Keychain/
Keystore signing path, and no code that could hold one.
`mobile-architecture-decision.md` §4.4 gives the architectural reason and
it is repeated here so it is re-argued rather than quietly reversed: the
entire value of on-device verification comes from the verifier and the key
being independently compromisable. If the same app both renders the
verdict and holds the authorizing key, one compromised build fabricates a
PASS and signs it.

### 4.4 Capability limitations

Kaspium, Tangem, Ledger, WalletConnect, and the KasWare browser extension
are **listed, not hidden**, each with a concrete reason and each ending at
the supported alternative. Tangem names the technical cause (ECDSA vs the
BIP-340 Schnorr the covenant path requires) because the USI's scheme
negotiation refuses it automatically — the UX describes an enforced
refusal, not a preference. **Nothing is claimed about KasWare mobile**:
the injected-provider path is a runtime probe with fail-closed
negotiation, present in the code and unclaimed in the product.

Tested: with no camera and no file transport, **no signing transport is
offered at all**, each with a stated reason. A future edit that flips a
capability to `true` without building it fails the suite.

### 4.5 Session bootstrap is UNDECIDED, and says so

Hosted sessions are wallet-bound, so even read-only use needs one
signature per session (§5.1). This scaffold does **not** pick between QR
login and a desktop→mobile hand-off — the latter is a credential transfer
needing its own hostile review. The app reports `UNDECIDED` with both
candidates and their costs, rather than rendering a sign-in flow that does
not exist. Unauthenticated control-plane reads therefore surface the
server's own refusal verbatim, which is the honest outcome. A machine
credential can be pasted in Settings for read-only testing.

---

## 5. Verified vs unverified — exactly

### 5.1 VERIFIED here (real commands, real output)

- **52 / 52 tests pass** (`cd mobile && npm test`), stable across repeated
  runs, Node v20.20.2.
- **Byte identity**: `mobile/www/vendor/core-bundle.js` and
  `verify-intent.js` are byte-for-byte the repository files; the wrapped
  API client embeds `sdk/src/http-client.js` verbatim and recoverably.
- **The app's own wiring produces the reviewed verdicts.** Loading the
  app's own scripts, in the app's own order, into a browser-like context
  with `require`/`module`/`process`/`Buffer` absent (so the BROWSER branch
  is the only one available), every fixture flow — `agentSpend`,
  above-threshold spend, `ownerTopUp`, `pause`, `setApprovers`,
  `addAgent`, `recover`, `createVault` — yields the **same manifest hash,
  same txId, and line-for-line identical explanation text** as the direct
  Node path over the repository originals.
- **DO-NOT-SIGN** on authorized negative-validation cases (policy-invalid
  adversarial test transactions modelling a hostile server): recipient
  substitution → `HIDDEN_RECIPIENT`; amount inflation →
  `VALUE_CONSERVATION_VIOLATION`; wrong network → `NETWORK_MISMATCH`;
  malformed input → refusal. Each leads with `!! DO NOT SIGN !!`, carries
  `unsignedSafeJson: null`, and matches the repository verifier code for
  code and line for line.
- **Fail-closed packaging**: a payload shipped without the core bundle
  refuses every verification with `CORE_UNAVAILABLE`; a core bundle
  missing required modules is treated as no core at all.
- **Both gates go red when they should** (drift, unlisted file, stale
  pins, substituted verifier in a copied payload).
- **Capacitor CLI runs**: `npx cap --version` → `7.6.8`.
- **`npx cap add android` and `npx cap add ios` both succeed** and copy the
  payload. The copied bytes were then verified: `--check-packaged` reports
  OK for both platforms, and a deliberately tampered Android asset makes
  it exit 1.
- **`npm audit`: 0 vulnerabilities** (with and without dev dependencies).

### 5.2 NOT verified — no claim is made

- **No iOS build. No Android build.** No `.ipa`, no `.aab`, no archive, no
  signing. CocoaPods and `xcodebuild` are absent from this environment
  (`cap add ios` said so explicitly and skipped `pod install`); no Android
  SDK/Gradle build was attempted.
- **No WebView has ever executed this payload.** No iOS Simulator, no
  Android emulator, no physical device, no desktop browser. The DOM code
  (`js/app.js`, `js/platform/*.js`) is proven only to PARSE. Screens have
  never been rendered; every rendering claim in §4.1 is a design claim
  about code that has not been run.
- **No cross-ENGINE evidence.** The test sandbox is one V8 process with
  fresh `vm.Context` intrinsics — its own intrinsics, not a second
  JavaScript engine. The §6.2(b) on-device equivalence harness
  (JavaScriptCore on iOS Simulator + V8 on Android emulator, across an
  Android WebView version matrix, byte-comparing the existing
  `core/crossruntime/vectors.js` battery against the Node reference) is
  **NOT BUILT**. The "shipping mobile retires the one-engine caveat"
  argument in the decision document remains a plan.
- **No camera / QR decoder.** Optical capture does not exist; the Sign
  screen shows frame TEXT with an explicit UNAVAILABLE label. No QR
  *encoder* ships either, so no scannable image is produced.
- **No share sheet / Files integration**, no push (APNs/FCM), no
  biometric or Keychain session gate, no deep links, no `FLAG_SECURE`.
- **No end-to-end exchange with a real CLI signer process.** The documents
  are built and validated against the CLI's schema constants read from
  `core/signer/adapters/cli/cli.js`, but no `cli.js sign-tx` invocation
  consumed a document this app produced.
- **No hosted-API integration run.** No screen has been pointed at a live
  PolicyVault server; route shapes are consumed through the vendored SDK
  client but no response has been rendered.
- **Emergency controls, governance, risk, organizations, reconcile** — the
  feature map's remaining screens are not built. Agents renders an
  explicit unavailable card rather than a stub.
- **No store work.** No Apple Developer organization enrollment, no
  privacy nutrition labels, no Play declarations, no review notes. §7.2 of
  the decision document is untouched.
- **`mobile-architecture-decision.md` §6.3 rules 6, 9, and 10** (navigation
  cannot become consent; screenshot hardening; no deep link lands on a
  signing action) need native integrations that do not exist and are
  therefore unenforced.

### 5.3 One correction to the decision document

§6.1 of `mobile-architecture-decision.md` records as a residual that
`core/model/fee-mass.js` is "not in the bundle's `MODULES` list today".
That is now **stale**: the F2 fee/state-recomputation wave added
`fee-mass`, `frozen-tx-v3`, `compute-budget-v3/v4`, `vault-state-v4`, and
`vault-transitions-v4` to the bundle. The mobile client inherits the
upgraded verifier automatically, because it packages the bundle rather
than reimplementing it — which is exactly the property the architecture
was chosen for. Open question 5 in that document is answered: it was done
in the shared bundle, upgrading both clients at once.

---

## 6. Dependencies and supply-chain note

**These are the project's first new npm runtime dependencies. Flagging
them explicitly for the security consolidation.**

Until now `sdk/`, `server/`, `web/`, and `core/` have been
zero-runtime-dependency or near it. `mobile/` introduces a dependency
tree, and that is a genuine change in the project's supply-chain posture
even though the security-relevant layer remains dependency-free.

### 6.1 Declared dependencies (all EXACT pins, no ranges)

| Package | Version | Kind | Why |
|---|---|---|---|
| `@capacitor/core` | `7.6.8` | dependency | The Capacitor runtime the native bridge resolves during `cap sync`. Required for the native shell to exist at all. |
| `@capacitor/cli` | `7.6.8` | devDependency | Provides `cap add` / `cap copy` / `cap sync`. Tooling only — never shipped. |
| `@capacitor/ios` | `7.6.8` | devDependency | The iOS native project template. Tooling only. |
| `@capacitor/android` | `7.6.8` | devDependency | The Android native project template. Tooling only. |

Every version is a bare exact string (`"7.6.8"`, not `"^7.6.8"`), so
`npm install` cannot silently pull a different build.
`mobile/package-lock.json` is **committed** and is the authoritative
supply-chain record.

### 6.2 What actually ships

The lockfile has **93 entries**, of which **exactly 2 are production**:

```
@capacitor/core  7.6.8
tslib            2.8.1     (transitive, from @capacitor/core)
```

The other **91 are dev-only tooling** (the CLI and its transitive tree)
and never enter an app binary.

**The security-relevant payload has zero npm dependencies.** Every file
under `mobile/www/vendor/` and `mobile/www/js/` is repository code —
either byte-identical vendored artifacts or hand-written modules — and
`mobile/www/index.html` loads no package. The web payload contains no
Capacitor API calls at all; `js/platform/env.js` only *detects* the
`window.Capacitor` object the native bridge injects at runtime. A
consequence worth stating: the payload runs identically in a plain
browser, which is exactly how the test suite exercises it.

### 6.3 Why Capacitor 7 and not 8

`@capacitor/cli@8.x` requires Node ≥ 22. This project runs Node v20.20.2.
Pinning 8.x would have produced a scaffold whose toolchain cannot run on
the project's own Node — the CLI was installed and refused with
`EBADENGINE`. `7.6.8` requires Node ≥ 20, runs here, and let both
`cap add` commands and the packaged-payload gate be genuinely exercised
rather than assumed. Moving to 8.x is a deliberate later step gated on a
Node upgrade.

### 6.4 Standing supply-chain rules for this directory

- **Exact pins only.** No `^`, no `~`, no `*`, no `latest`.
- **The lockfile is committed and reviewed like source.**
- **Nothing enters `mobile/www/`** except through
  `mobile/tools/sync-portable.js`. No bundler, no minifier, no
  transpiler, no CDN, no npm package in the payload. The `--check` gate
  rejects any unlisted file in `mobile/www/vendor/`.
- **No over-the-air updates of the security payload. Ever.** Capacitor
  ecosystems support live/OTA web-payload updates; that is a silent
  channel to replace the verifier and is forbidden for
  `core-bundle.js`, `verify-intent.js`, and the explanation layer — in
  practice, no OTA at all, since separating "security payload" from
  "other payload" inside one WebView bundle is a distinction too easy to
  erode. No OTA package is installed and none may be added.
- **Any new dependency is a security-review item**, especially a native
  plugin: camera, filesystem, share, biometrics, and push plugins all sit
  adjacent to the signing path and must be reviewed before adoption, not
  after.
- Generated native projects (`mobile/android/`, `mobile/ios/`) are
  **gitignored**: regenerable on demand, never built or reviewed here, and
  committing an unbuilt native tree would imply verification that does not
  exist.

---

## 7. How to run what exists

```bash
cd mobile
npm install                 # exact-pinned; 0 vulnerabilities
npm test                    # 52 tests; runs the source gate first (pretest)

npm run check:portable      # source gate:   vendor/ == repository sources
npm run sync:portable       # regenerate vendor/ + pins after a web/ or sdk/ change

npm run add:android         # gate -> cap add android -> packaged gate
npm run add:ios             # gate -> cap add ios     -> packaged gate
npm run copy                # gate -> cap copy        -> packaged gate
npm run check:packaged      # packaged gate alone, on whatever platforms exist
```

The payload is `mobile/www/` and needs no build step. Serving that
directory over any static server loads the app in a desktop browser —
**untried here**, and the first thing a follow-up wave should do.

---

## 8. Path to production-capable

In the decision document's phase language, this scaffold covers part of M0
and part of M1. What each remaining step needs:

| Step | What it requires | Blocker kind |
|---|---|---|
| **Render the app at all** | Serve `mobile/www/` and exercise every screen in a desktop browser; then in a WebView | none — do this first |
| **Finish M1 (read/coordinate)** | Decide the session bootstrap (open question 3 — QR login vs a reviewed hand-off); wire vault selection so Agents, Governance, Risk, Organizations, Reconcile and Emergency screens can render; point the client at a live server | needs an owner/coordinator decision on §5.1 |
| **On-device cross-ENGINE harness (§6.2b)** | Serialize the existing `core/crossruntime/vectors.js` battery to a fixture at build time (**invent no new vectors** — divergence between batteries would itself be drift), ship a debug-only harness screen, byte-compare against the Node reference document on iOS Simulator (JSC) and Android emulator (V8) across a WebView version matrix | needs Xcode + Android SDK |
| **M2 (signing)** | A QR encoder for frame display and a QR decoder for capture, behind the existing platform seam; then the full §9.1 adversarial suite | needs plugin selection + security review of each plugin |
| **M3 (native integrations)** | Camera, share sheet, biometric/Keychain session gate, deep links, APNs/FCM registration, `FLAG_SECURE`, emergency controls under degradation. **Required before any Apple submission** — Apple 4.2/4.2.2 rejects WebView wrappers without genuine native integration (risk R3) | needs plugins + devices |
| **M4 (opportunistic interop)** | A real KasWare Android in-app-browser device probe. Claim nothing until it produces evidence (open question 1) | needs a device and a KasWare build |
| **M5 (release)** | **Apple Developer Program ORGANIZATION enrollment with a D-U-N-S number** — guideline 3.1.5(b) blocks any wallet app from an individual account, and enrollment has real lead time. This is an **owner action on the critical path** and cannot be done by this program (risk R4). Plus privacy nutrition labels, Play blockchain declarations, target API 35+, TestFlight/internal track, human acceptance on real devices | **HUMAN GATE** |

### 8.1 Store constraints carried forward from the decision document

- **Apple 3.1.5(b)** — organization enrollment required. Owner action,
  long lead time, on the critical path. Raise early.
- **Apple 4.2 / 4.2.2** — a naive WebView wrapper is a rejection risk. The
  M3 native integrations must exist and be called out in review notes
  before first submission. **Do not submit the read-only phase alone.**
- **Google Play** — the Cryptocurrency Exchanges and Software Wallets
  policy requires licensing for **custodial** apps; non-custodial is out
  of scope. PolicyVault is non-custodial by construction, and the §4.3
  no-key-custody exclusion is what keeps that demonstrable.
- **Reproducibility, stated honestly:** the *payload* is reproducible and
  digest-published (§2). The `.ipa`/`.aab` are **not** — Xcode and Gradle
  are not bit-reproducible in general and both stores require code
  signing (Apple's certificate; Google Play re-signs). The only honest
  claim is *"a reproducible, digest-published verification payload inside
  an attested — not reproducible — native shell."* Never write
  "reproducible mobile build."
- **Neither store is a security boundary.** Review outcomes change nothing
  about what the covenant enforces.

---

## 9. Claim summary

| Claim | Status |
|---|---|
| Runnable Capacitor project exists, CLI works, both platforms add | **IMPLEMENTED / VERIFIED** |
| Byte-identical portable layer + hash-pinned build gates (source + packaged) | **IMPLEMENTED / UNIT-TESTED**, both directions |
| On-device verification through the app's own wiring, PASS and DO-NOT-SIGN | **UNIT-TESTED** in a browser-like sandbox; **never run in a real WebView** |
| QR framing + air-gap documents + independent second refusal | **IMPLEMENTED / UNIT-TESTED**; no optical capture, no real signer exchange |
| Read/coordinate screens, capability-limitation UX, build-integrity screen | **SCAFFOLDED**; parses, never rendered |
| Cross-engine (JSC/V8) equivalence evidence | **NOT BUILT** |
| iOS / Android application build | **NOT DONE** |
| Store readiness | **NOT STARTED** (Apple org enrollment is a human gate) |
| **The mobile surface overall** | **NOT PRODUCTION-CAPABLE** |
