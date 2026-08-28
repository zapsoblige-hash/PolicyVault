# PolicyVault Mobile Client — Architecture Decision (DRAFT)

**Claim label: DESIGNED.** Nothing in this document is IMPLEMENTED,
UNIT-TESTED, VM-VERIFIED, TESTNET-VERIFIED, or PRODUCTION-HARDENED. No
code was written and no repository file was modified in producing it.
It covers full-scale completion surfaces **3 (mobile-local transaction-
intent verification)** and **20 (production-capable iOS/Android mobile
functionality)** of `docs/postlaunch/FULLSCALE_COMPLETION_ADDENDUM.md`,
both currently **ABSENT** per `docs/postlaunch/fullscale-gap-analysis.md`
(wave W3, "after mobile arch decision" — this is that decision).

Binding constraints this document is written against
(FULLSCALE_COMPLETION_ADDENDUM.md §"Mobile", §"Architectural anti-bloat
rule", §"Security model"):

1. Mobile is a **separate first-class client, not another financial
   engine**. ONE authoritative deterministic core.
2. **Reuse the portable shared core directly wherever technically
   possible.**
3. Full human control plane: vaults, agents, policies, approvals,
   governance, risk, activity, alerts, pause/revoke/recovery, plus
   signing through supported Universal Signer Interface adapters.
4. **Never invent unsupported wallet capabilities.** Where a mobile
   wallet/provider cannot perform an operation, expose a clear
   capability limitation — never weaken verification or custody.
5. Mobile-LOCAL intent verification runs **on device**, the same
   deterministic verification the browser does in `web/verify-intent.js`.
6. Infrastructure never touches seeds or keys.

---

## 0. Executive recommendation (the six lines)

1. **Build the mobile client as a Capacitor-hosted native app** (iOS
   WKWebView / Android System WebView) that packages the *byte-identical*
   committed `web/core-bundle.js` + `web/verify-intent.js` + `core/explain`
   rendering — zero reimplementation of any financial, policy,
   verification, or explanation logic.
2. Rationale that decides it: the deterministic core is **JavaScript**
   and the pre-sign verifier `createVerifyIntent(core)` is already a
   **pure, DOM-free factory** — Capacitor is the only option where the
   *exact same reviewed bytes*, not a port, run on device.
3. Free side-benefit that no other option gives: WKWebView runs
   **JavaScriptCore** and Android WebView runs **V8**, so shipping mobile
   *retires* the honestly-recorded one-engine residual gap in
   `docs/postlaunch/cross-runtime-equivalence.md` §7 by producing real
   cross-*engine* equivalence evidence.
4. **The v1 signer is QR/airgap to the existing `core/signer/adapters/cli`
   reference signer.** No Kaspa mobile wallet today exposes a documented,
   verifiable external signing interface (§2) — inventing one would break
   constraint 4.
5. **No key custody in the app, ever, in v1** — including no device-key
   signer: the app that builds and displays the intent must never also
   hold the key that authorizes it, or local verification stops meaning
   anything.
6. Everything else (external-wallet adapters, push, biometrics) is
   capability-probed at runtime and rendered as an explicit **capability
   limitation** when absent — never claimed in advance, never a
   verification bypass.

---

## 1. Ground truth used (code-truth, read-only)

Verified directly in the `postlaunch-rc` worktree, not taken from docs:

| Fact | Evidence |
|---|---|
| The core is plain JavaScript across `core/model` (14 files), `core/intent`, `core/explain`, `core/signer`, `core/governance`, `core/risk` | file inventory of `core/` |
| After F1 the core is Buffer-free / browser-portable; the only Node builtin used by core sources is `require("crypto")` | `docs/postlaunch/f1-merkle-portability.md` §1; `grep` of `require(` across `core/` non-test sources |
| `web/verify-intent.js` is a **pure factory** — `createVerifyIntent(core)` at line 86, with **zero** `document.` / `navigator.` / `localStorage` / `fetch(` references (the three grep hits are the English word "document" inside comments) | `web/verify-intent.js:86`, `:1328-1337` |
| The core bundle is deterministic, self-contained, per-source sha256-pinned, `--check`-verifiable, with an anti-drift test | `web/tools/build-core-bundle.js`; `core/crossruntime/test/bundle-anti-drift.test.js`; `docs/postlaunch/browser-verification.md` §2 |
| The cross-runtime equivalence suite (127 cases) runs **all** runtimes inside one V8 process and says so | `docs/postlaunch/cross-runtime-equivalence.md` §7 first bullet |
| The core contains **no floating point, no `Intl`, no `toLocaleString`, no `localeCompare`, no `String.normalize`, no unicode property-escape regexes** in any value-bearing path; KAS rendering is BigInt-only and refuses JS numbers | `grep` across `core/` non-test sources; `core/explain/kas.js:1-60` |
| The only `Math.*` uses are `Math.floor(idx/2)` on small integers (Merkle path walk) and `Math.max` over array lengths — exact in every conforming engine | `core/model/agent-merkle-v4.js:288`, `core/model/recipient-merkle-v3.js:191`, `core/intent/verify.js:140` |
| `Date.now()` appears only in signing-request metadata / lifecycle transitions, never in a hashed or value-bearing field | `core/signer/interface.js:494,551,640` |
| The USI already models exactly the capabilities mobile needs: `airGapped`, `asynchronousApproval`, `hardwareDisplay`, `messageSigning`, `transactionSigning`, `specificInputSigning`, plus fail-closed negotiation and unknown-capability refusal | `core/signer/interface.js:85-95, 179-250, 336-395` |
| A materially different, offline, no-network, file-in/file-out reference signer already exists | `core/signer/adapters/cli/{adapter.js,cli.js}`; `docs/postlaunch/signer-cli-reference.md` |
| The hosted API is segment-routed and already exposes the whole control plane the mobile client needs | `server/src/api.js` — `auth`, `identities`, `identity/resolve-address`, `wallet/create`, `wallet/requests`, `wallet/v4/*`, `governance`, `risk/evaluations`, `organizations`, `vaults`, `vaults/:id/reconcile`, `audit`, `manifests`, `network/status`, `capabilities`, `health` |

**This is the decisive fact pattern:** the entire security-relevant client
layer PolicyVault must run on mobile — deterministic core, manifest
derivation, the full fail-closed detector catalogue, Merkle root
recomputation, and human-readable explanation — is already portable
JavaScript with a host-agnostic entry point. The architecture decision is
therefore not "which framework do we like" but "which runtime lets us
execute the *already-reviewed bytes* rather than a translation of them."

---

## 2. The Kaspa mobile wallet / signing landscape (researched 2026-08-26)

**Honest headline: it is very thin.** There is no Kaspa equivalent of
EIP-1193 + WalletConnect on mobile. Nothing below should be read as a
commitment that PolicyVault will interoperate with any of these wallets.

| Wallet | Platforms | Signing interface exposed to third-party apps | Verifiable today? |
|---|---|---|---|
| **KasWare (extension)** | Chrome/desktop | Full documented `window.kasware.*`: `requestAccounts`, `getAccounts`, `getPublicKey`, `getNetwork`, `switchNetwork`, `signMessage(text, params)`, `verifyMessage`, `signPskt({txJsonString, options})`, `pushTx`, `sendKaspa`, KRC20/marketplace helpers, `on`/`removeListener` | YES — documented, and already the production signing path via `web/signer-kasware-adapter.js` |
| **KasWare (Android app)** | Android only — **no iOS build listed** | Releases mention an *"in-app browser feature in Mainnet for developers"* (v0.2.7.1-beta / v0.2.8-beta, Apr 2026); latest v0.5.3 (Aug 2026). The API docs note `switchNetwork` "is disable in the mobile app", which implies an injected provider exists on mobile **with a reduced surface** — but there is **no mobile documentation page at all** in the KasWare docs sitemap | **PARTIALLY / UNVERIFIED.** Provider presence, method coverage, sighash handling, and network semantics on mobile are all unverified. Treat as runtime-probed, never assumed |
| **Kaspium** | iOS + Android, Flutter/Dart, non-custodial, fork of Natrium | **None found.** No deep-link/URI signing scheme, no WalletConnect, no PSKT, no `signMessage`, no external signing API in the repository README or the public docs | **NO** |
| **Tangem** | NFC card + iOS/Android app | Native Kaspa support for store/send/receive. No third-party arbitrary-transaction or arbitrary-message signing API for external apps. Separately, PolicyVault's own prior research already established that Tangem keyrings sign **ECDSA**, not Schnorr, through KasWare's `signMessage` — which is why Tangem is already refused for hosted auth v1 | **NO** (and would fail USI scheme negotiation even if an API appeared) |
| **Ledger** | hardware + Ledger Live mobile | Kaspa supported for custody/transfer. No documented third-party PSKT/message-signing API surfaced to arbitrary mobile apps | **NO** |
| **WalletConnect / Reown** | protocol | Requires a **CAIP-2 namespace** for the chain. No Kaspa namespace was found in the CASA `ChainAgnostic/namespaces` registry, and no Kaspa entry surfaced in the WalletConnect chain onboarding docs | **NO** |
| **PSKT (the format itself)** | — | Real and specified: `kaspa-wallet-pskt` (Rust crate, BIP-370-shaped, `PSKT`/`PSKTBuilder`/`Bundle`). KasWare's extension `signPskt` consumes it. But **format support ≠ wallet interop**: no *mobile* wallet documents accepting a PSKT from an external app | Format YES, mobile interop **NO** |

### 2.1 What this forces

- **We cannot build the mobile signing story on external mobile wallets.**
  Doing so would either (a) require inventing a deep-link/URI protocol and
  then claiming wallets support it, which violates constraint 4 outright,
  or (b) block surface 20 indefinitely on third parties.
- **We can build it on something we already own and have already proven:**
  the offline `core/signer/adapters/cli` reference signer, reached over a
  QR/file transport. The USI already declares `airGapped` and
  `asynchronousApproval` as first-class capabilities — this is the shape
  the interface was designed for, not a workaround.
- **KasWare-mobile is an opportunistic upside, not a plan.** Its in-app
  browser is a documented-in-release-notes, undocumented-in-API-docs beta
  feature on Android only. We will ship a detection path and a capability
  card, and we will claim nothing until a real device probe produces
  evidence (§7 open question 1).

---

## 3. Framework analysis

Scored strictly against the six binding constraints, with constraint 2
("reuse the portable shared core **directly**") weighted as the
tie-breaker because the addendum makes it binding rather than
preferential.

### 3.1 Capacitor (web payload in a native shell) — **RECOMMENDED**

| Constraint | Assessment |
|---|---|
| 1 — not another engine | **Best possible.** The mobile app packages the *same file bytes* as the web client: `web/core-bundle.js` (sha256-pinned per embedded source), `web/verify-intent.js`, `core/explain` rendering. There is no second implementation to drift. |
| 2 — direct core reuse | **Literal.** Not "reuse the same language" — reuse the same artifact. `createVerifyIntent(core)` needs only a `PolicyVaultCore` object; the bundle's browser branch (`window.PolicyVaultCore = api`) is exactly what a WebView provides. |
| 5 — on-device verification | Runs unchanged, including F1 Merkle root recomputation (the bundle's `CRYPTO_SHIM` needs only `crypto.getRandomValues`, present in both WebViews; SHA-256 is pure JS in the shim, so there is no native crypto dependency at all). |
| 3 — control plane | The existing hosted API + existing UI logic port with responsive layout work rather than a rewrite. |
| 6 — no seeds/keys | Trivially satisfied; the shell never gains a key-handling surface. |
| 4 — no invented capabilities | Neutral. |

**The engine dividend.** iOS WKWebView is JavaScriptCore; Android
System WebView is V8/Chromium. Today, `cross-runtime-equivalence.md` §7
records honestly that "Browser bundle" and "core-model probe" both still
execute inside one Node V8 process, and that a real second engine is
future work. Shipping Capacitor makes cross-engine equivalence a
*byproduct of the product*, on the two engines that actually matter for
users. This is a security argument, not a convenience argument: the
binding property of the whole local-first design is that "the local-first
verification a signer relies on must not silently compute something
different depending on where it runs."

**Determinism risk assessment (why this is safe here specifically).**
The core's exposure to engine divergence is unusually small, and this is
verifiable rather than assumed:

- No floating point anywhere in a value-bearing path (project numeric-
  safety rule; confirmed by grep). All sompi are BigInt. BigInt is mature
  and spec-exact in both JSC and V8.
- No `Intl`, `toLocaleString`, `localeCompare`, or `String.normalize` —
  the historically largest source of engine/locale divergence. The
  canonical-JSON battery already contains NFC-vs-NFD vectors precisely
  because the core treats them as *distinct* (no normalization), which is
  engine-independent by construction.
- `JSON.stringify` number formatting (`-0`, `1e21`) is spec-pinned and is
  already in `CANONICAL_JSON_VECTORS` — but it *is* an engine-observable
  surface, which is exactly why it must be re-run on device (§6.2).
- Key sorting is codepoint/UTF-16-code-unit ordering with ES2019-stable
  `sort()` — identical in JSC and V8.
- Residual, named honestly: **Android System WebView ships as an
  independently-updatable APK**, so the Android engine version is *not*
  pinned at build time and varies across the device fleet. This is not a
  reason to reject Capacitor (an RN app pins Hermes but then owns a third
  engine's divergence instead) — it is a reason for the on-device
  equivalence harness in §6.2 to run at app start in debug builds and in
  CI across a device matrix.
- Also honest: iOS restricts JIT in some WebView contexts. That is a
  *performance* property, not a semantic one — interpreter and JIT tiers
  of JSC must produce identical results or JSC is broken. Flagged, not
  feared.

**Store-policy cost — the real one.** Apple guideline 4.2 / 4.2.2
("minimum functionality" / "web clippings") rejects apps that are "not
sufficiently different from a mobile web browsing experience." A naive
WebView wrapper is a rejection risk. PolicyVault's mobile app is not
naive — it needs camera QR capture for the airgap signer, platform push
for approvals, biometric/secure-enclave session gating, deep-link
handling, and a share sheet for signing-request files. Those are genuine
native integrations that must be built *deliberately and early*, and
declared in the review notes. Mitigatable, but it is a real constraint on
scope: **the M1 read-only phase must not be submitted to Apple alone.**

**When this decision would be wrong.** If the mobile product later needs
deep offline-first local persistence, heavy native gesture UX, or
background execution beyond push, RN would have been the better host.
Mitigation is structural, see §3.6.

### 3.2 React Native (+ Expo) — strong second, rejected on drift surface

Genuine merits, stated fairly: the core is JS, so RN also satisfies
constraint 2 *in principle* — `core/**` are plain CommonJS modules that
Metro can bundle directly. Native UI quality, push, biometrics, deep
links, and background behavior are all better. Apple 4.2 risk is
essentially zero. RN 0.84 (2026) makes Hermes v1 the default on both
platforms and adds WebAssembly support to Hermes, removing the historic
"no WASM in RN" blocker that would have mattered if the client ever needs
kaspa-wasm locally.

Why it still loses:

1. **It reuses the core's *source*, not the reviewed *artifact*.** The
   browser path's security argument rests on a specific bundle whose
   header pins the sha256 of every embedded source and whose regeneration
   is byte-compared by `build-core-bundle.js --check` and an anti-drift
   test. An RN app consumes `core/**` through Metro, producing a
   *different* build product with a different toolchain, different module
   resolution, and its own minifier. That is a second thing to pin,
   review, and keep from drifting.
2. **It adds a third engine instead of covering the two that ship.**
   Hermes is a genuinely separate implementation with its own history of
   spec-coverage gaps (BigInt only landed in 0.70; Intl/ICU coverage has
   long been partial). Choosing RN means the equivalence suite must now
   cover Node-V8 *and* Hermes — and users still never run the JSC/V8
   WebView paths we would then have no product reason to test.
3. **It forces a second implementation of the DO-NOT-SIGN ceremony.**
   `web/verify-intent.js` is portable, but `web/app-v4.js`,
   `governance-ui.js`, `risk-ui.js`, `gov-risk-explain.js`,
   `org-controls-ui.js`, and the signing-modal DOM would all be rewritten
   in RN components. The anti-bloat rule names the *financial engine*, so
   this is not a rule violation — but the pre-sign human-readable
   rendering is the surface a human actually reads before authorizing
   money to move, and having two independent implementations of it is a
   real, security-relevant drift risk with no compensating benefit.
4. `require("crypto")` is absent in RN; it needs `expo-crypto` /
   `react-native-get-random-values` / `react-native-quick-crypto`. Each is
   a **native** dependency in the trusted path — strictly worse than the
   current pure-JS SHA-256 shim whose equivalence to `node:crypto` is
   already proven over 22 adversarial vectors.
5. Hermes WASM support is brand new (shipped 2026) and unproven for a
   module the size and shape of kaspa-wasm.

**Verdict: REJECT for v1, KEEP as the documented escape hatch (§3.6).**

### 3.3 Flutter — reject

Dart. Reusing the JS core would require either a full Dart
reimplementation of the deterministic core (a direct violation of the
anti-bloat rule and of constraint 2) or embedding a JS engine through a
third-party bridge — which yields Capacitor's tradeoffs *plus* an
unreviewed FFI boundary in the trusted path and *minus* the platform
WebView's guarantees. There is a mild irony worth recording: **Kaspium is
itself Flutter**, which is part of why Kaspium is not a natural host for
anyone else's verification logic.

### 3.4 Native Swift + Kotlin pair — reject for the core, required for the shell

Two additional reimplementations of the deterministic core, in two
languages, kept bit-identical to the JS reference forever. Rejected
outright. Note the distinction, though: **native shell code is required
regardless of framework** — camera/QR, keychain/Keystore, biometrics,
APNs/FCM, deep links, share sheet. Under Capacitor that is a small,
bounded, non-financial Swift/Kotlin surface reached through plugins, which
is the correct amount of native code.

### 3.5 PWA — reject as the completion answer, keep as immediate coverage

A responsive, installable PWA is cheap and would give phone users
*something* quickly, and PolicyVault's web client is already
architecturally close to it. But:

- **It cannot satisfy surface 20.** A PWA cannot be listed in the Apple
  App Store — Apple requires a native binary; iOS installation is
  Safari → Add to Home Screen only. Google Play accepts PWAs via Trusted
  Web Activity; Apple has no equivalent.
- No camera/QR-grade capture guarantees, no keychain/secure-enclave
  session binding, no reliable background push on iOS, no share-sheet
  file exchange for the airgap signer.
- Nothing about a PWA is *wasted* under the Capacitor recommendation:
  responsive layout work, offline shell, and manifest work all become the
  Capacitor payload.

**Verdict: build the responsive/PWA-quality web payload as a deliberate
step *toward* Capacitor, not as an alternative to it.**

### 3.6 The seam that makes the decision reversible

Because the decision is contested rather than obvious, the architecture
must keep it cheap to revisit. Enforce a hard two-layer seam:

```
  PORTABLE LAYER  (identical in every client, never forked)
    web/core-bundle.js        — the sha256-pinned deterministic core
    web/verify-intent.js      — createVerifyIntent(core), pure factory
    core/explain rendering    — structured() + humanReadable()
    core/signer/interface.js  — USI descriptors, negotiation, lifecycle

  PLATFORM LAYER  (swappable: DOM today, RN components if ever needed)
    presentation, navigation, transport, camera, push, biometrics,
    keychain, deep links
```

The portable layer must never import from the platform layer, must never
touch the DOM, and must never take a host object other than the core API.
`web/verify-intent.js` already satisfies this today (verified: pure
factory, zero DOM references) — the rule is to *keep* it true, enforced by
a lint/test gate. If RN is ever adopted, the portable layer moves
unmodified and only the platform layer is rewritten, which is exactly the
cost profile we want a reversible decision to have.

---

## 4. Mobile Universal Signer Interface adapter strategy

Governing principle, from the addendum's security model: **AI MAY
REQUEST. POLICYVAULT DETERMINISTICALLY DECIDES. THE COVENANT ENFORCES
FINANCIAL AUTHORITY. SIGNERS RETAIN CUSTODY.** Mobile changes the
transport and the display; it changes nothing about who holds keys.

### 4.1 Adapter roster for v1

| Adapter | Kind / features | Status | Notes |
|---|---|---|---|
| **`qr-airgap`** — QR/file transport to the existing `core/signer/adapters/cli` reference signer | `airGapped: true`, `asynchronousApproval: true`, `messageSigning: true`, `transactionSigning: true`, `specificInputSigning: true`, `multiAccount: false`, `accountEvents: false`, `networkSwitching: false`, `hardwareDisplay: false` | **v1 PRIMARY** | New *transport*, not new cryptography. The phone renders the USI signing request (or an animated multi-frame QR for large `unsignedSafeJson`); the operator's offline CLI signer consumes it; the phone's camera scans the signed response. `asynchronousApproval: true` binds `cancelSigning` and requires an explicit `timeoutMs` — already enforced by `executeSigning`. |
| **`qr-airgap-file`** — same adapter, share-sheet/Files transport instead of camera | same descriptor | **v1 PRIMARY (fallback)** | For devices where camera capture is unavailable or the payload is too large for practical QR framing. Same request/response documents, so no second security review. |
| **`kasware-mobile`** — injected provider inside KasWare's Android in-app browser | probed at runtime; declared from what `describe()`/`detect()` actually finds | **v1 OPPORTUNISTIC, unclaimed** | Only reachable in the *PolicyVault-served-in-KasWare's-browser* deployment mode (§4.3), not inside our own Capacitor app. Ship detection + negotiation; if `signPskt`/`signMessage`/`specificInputSigning` are absent or the network is wrong, **negotiation refuses fail-closed** and the capability-limitation card renders. Never advertised in store copy or docs until device-probed. |
| **`mock`** (`core/signer/mock-adapter.js`) | — | dev/test only | Must be structurally absent from production builds, enforced by a build-time assertion, mirroring the existing mainnet-startup refusal of dev signers. |
| **`kaspium` / `tangem` / `ledger` / `walletconnect`** | — | **NOT BUILT** | No verifiable interface exists (§2). These appear in the product **only** as capability-limitation entries. |

### 4.2 Capability-limitation UX (constraint 4, made concrete)

Where a wallet cannot do something, the app states it plainly instead of
degrading. Rules:

- Unsupported wallets are **listed, not hidden** — a user holding KAS in
  Kaspium must be told *why* it cannot sign here, or they will assume the
  app is broken and look for a workaround.
- The wording is factual and non-derogatory, e.g.
  *"Kaspium holds KAS safely, but it does not currently offer an
  interface for approving transactions built by another application.
  PolicyVault cannot use it as a signer. Nothing about your vault is less
  safe — it just means approvals must come from a signer that supports
  this."*
- For Tangem, additionally name the concrete technical reason
  (**ECDSA vs the BIP-340 Schnorr scheme PolicyVault's covenant path
  requires**) — the USI's `schemes` negotiation refuses this
  automatically, so the UX is describing an enforced refusal rather than a
  policy preference.
- Every limitation card ends with the *supported* alternative (the
  QR/airgap signer), so the flow is never a dead end.
- **A capability limitation NEVER downgrades verification.** There is no
  "reduced verification mode," no "sign without local check," and no
  "the wallet says it is fine" path. If negotiation refuses, the outcome
  is a refusal, rendered like any other fail-closed refusal.

### 4.3 Two deployment modes, kept explicitly distinct

Conflating these is the most likely architectural mistake, so name them:

- **Mode A — the PolicyVault mobile app (Capacitor).** Our binary, our
  WebView, our packaged verifier. Signer adapters available:
  `qr-airgap`, `qr-airgap-file`. **No injected wallet provider exists in
  this mode** — a WebView we control does not receive `window.kasware`.
- **Mode B — the PolicyVault web client loaded in a wallet's in-app
  browser** (today: KasWare Android, unverified). Their browser, their
  injected provider, our served payload. Signer adapter available:
  `kasware-mobile`, subject to runtime probing. The verification pipeline
  is identical because it is the same served payload — but the *bundle
  integrity story is weaker* (the user is trusting the served bytes and
  their WebView, not a store-reviewed binary), and that difference should
  be stated in the residual-trust table rather than papered over.

Both modes route through the same core, the same manifest derivation, the
same detector catalogue, and the same USI lifecycle. Neither gets a
privileged signing path.

### 4.4 Device-key custody — **EXPLICITLY OUT OF SCOPE FOR v1**

A signer whose key lives in the PolicyVault app (Keychain / Android
Keystore / Secure Enclave) is technically buildable and will be requested.
It is out of scope for v1, and the reason is architectural rather than
cautious:

**The entire value of on-device verification comes from the verifier and
the key being independently compromisable.** Local verification protects
against a hostile server or a hostile frontend. If the same app both
renders the verdict and holds the authorizing key, a single compromised
build both fabricates a PASS and signs it — the user gains a reassuring
screen and loses the property that made the screen meaningful. The
addendum's own framing separates the roles: *hosted = coordination,
portable core = independent deterministic verification, external signer =
key custody*. Merging the last two deletes a boundary.

Additional consequences worth recording:

- It would move PolicyVault from "never touches keys" to "sometimes holds
  keys," which changes the App Store 3.1.5(b) posture, the Google Play
  custody posture, the threat model, the backup/recovery story, and the
  support burden — none of which are v1 problems worth buying.
- **If it is ever revisited**, the acceptable shape is a *separate
  application or process* with its own display and its own consent
  surface — i.e. a real second party, structurally equivalent to the CLI
  signer running on a different machine — never a mode inside this app.
  A hardware-backed signer that declares `hardwareDisplay: true` (the USI
  already models this) is the more honest long-term direction.

---

## 5. Feature map — the full human control plane on mobile

`R` = read/coordinate only (no signature). `S` = signature-required
(routes through on-device verification + USI). `S*` = requires a
signature today only because the hosted session is wallet-auth-bound
(see the M1 note below).

| Screen | Contents | Class | Backing API (existing) | Notes |
|---|---|---|---|---|
| **Sign in** | connect signer, sign auth challenge | `S*` | `auth/*` | Sessions are opaque SHA-256-at-rest and wallet-bound; the challenge is a `sign-message` USI request. On mobile v1 this means **even read-only use needs the QR signer once per session** — see §5.1. |
| **Vaults** | list, balances, protected value, fee reserve, live outpoint, covenant version | `R` | `vaults`, `vaults/:id` | Version-gated display; unknown covenant version renders as unknown, never as a default. |
| **Vault detail** | policy state, approver slots, agent registry, recipient registry, budgets | `R` | `vaults/:id` | Full leaf data must be present for §6 root recomputation — a vault view that cannot be recomputed shows a verification-unavailable state, not a silent pass. |
| **Agents** | list, per-agent policy, caps, period budgets, allowlists | `R` | `vaults/:id`, `identities` | |
| **Agent lifecycle** | add / remove / rotate / re-policy | `S` | `wallet/v4/*` | Successor agent root recomputed on-device from the client's own typed params. |
| **Policies** | per-spend cap, period budget, approval threshold, approver set | `S` | `wallet/v4/*` | Authority-changing → governance classification applies. |
| **Approvals** | pending queue, request detail, approve / reject | `S` | `wallet/requests`, `wallet/requests/:id/{signature,reject}` | **The single highest-value mobile flow.** The approver never saw the original form, so intent provenance is the durable server request — the browser has the same property and the same detectors. |
| **Governance** | authority-delta review, quorum/delay state, ceremony | `S` | `governance/*` | `core/explain/governance-explain.js` renders the delta; note it is currently unconsumed by the web client (gap-analysis surface 13) — mobile must consume the same module, not a mobile-specific renderer. |
| **Risk** | evaluations, ALLOW/REVIEW/DENY, hold release | `R` + `S` on release | `risk/evaluations` | Review-triggered approvals become normal approval flows. |
| **Organizations** | members, quorum/delay config, org audit | `R` + `S` on authority change | `organizations/*` | |
| **Activity / Audit** | correlated intent ↔ manifest ↔ policy ↔ approvals ↔ signer ↔ txid ↔ chain state | `R` | `audit`, `manifests` | Read-only; the mobile view is a lens on the same correlation, never a second source of truth. |
| **Alerts / Notifications** | approval requested, approval granted, risk hold, reconciliation anomaly, pause/revoke executed | `R` | surface 19 (ABSENT) | See §5.2. |
| **Emergency controls** | pause, unpause, revoke agent, break-glass, recovery | `S` | `wallet/v4/*` | Distinct destructive-confirm ceremony; must remain reachable when the rest of the app is degraded (§5.3). |
| **Reconcile** | trigger reconciliation, view chain-verified state | `R` (trigger is unsigned) | `vaults/:id/reconcile` | `submitTransaction()` returning is not success — the mobile UI must show the reconciliation state machine, never an optimistic "sent." |
| **Signers** | connected signers, capability descriptors, **capability limitations** (§4.2) | `R` | local | Renders the USI descriptor honestly, including declared-false features. |
| **Settings → Build integrity** | packaged core-bundle digest, app version, build id, network | `R` | local | §6.4. |

### 5.1 The read-only-still-needs-a-signature problem (real, must be decided)

Because hosted sessions are wallet-bound (a Schnorr signature over
`PersonalMessageSigningHash`), a "read-only" mobile app still needs one
`sign-message` per session. Two candidate resolutions, neither free:

- **(a) QR login (recommended for v1).** The phone renders the auth
  challenge as a QR; the CLI signer signs it; the phone scans the
  response. Uses the exact same adapter and lifecycle as transaction
  signing, adds no new credential type, and keeps the "one signer, two
  request kinds" story clean. Cost: friction on every session start —
  mitigated by a longer session TTL bound to a biometric/Keychain-held
  session, **not** by a longer-lived key.
- **(b) Desktop→mobile session hand-off.** Scan a QR from an
  authenticated desktop session containing a short-lived, single-use,
  device-bound token that the phone exchanges for its own session. Much
  better UX. But it is a **credential transfer**, and it needs its own
  threat model (QR shoulder-surfing/photography, replay, token binding,
  revocation, what a stolen phone inherits) and its own hostile review.
  **Do not ship it in v1 as a shortcut.**

This is a genuine open decision, not a detail — it sets the floor on
mobile usability. Recorded as open question 3 (§8).

### 5.2 Notification integration points (coordinate, do not design here)

Surface 19 is ABSENT and is a separate design. Mobile only declares the
seams it needs:

- **Transport:** APNs (iOS) / FCM (Android), device token registered
  against the authenticated session, revoked on sign-out and on session
  invalidation.
- **Payload rule (binding):** a push payload is **untrusted, non-
  authoritative, and value-free**. It may carry a request identifier and
  a category; it must **never** carry amounts, addresses, approval
  outcomes, or anything a human might act on without opening the app.
  Everything displayed is re-fetched and re-verified in-app.
- **Deep links:** a notification may deep-link to a *request detail*
  screen; it may **never** deep-link to a signing action, a confirmation,
  or a pre-approved state. Every path to a signature passes through
  verification.
- **Delivery is best-effort.** Push is not an alerting guarantee.
  Time-critical states (risk holds, approval deadlines) must also be
  visible on open, and the anti-bloat rule applies: if the notification
  provider is unavailable, core financial safety and existing wallet
  functionality remain correct.
- **Privacy:** lock-screen previews must be content-free by default;
  balances and counterparties never appear on a locked device.

### 5.3 Emergency controls availability

Pause / revoke / break-glass must reach a signer even when the app is
partly degraded. Concretely: the emergency screen must be reachable
without the notification service, without risk evaluation, and with a
stale vault view (it operates on authority, not on a computed spend), and
it must render the QR signing request even if the camera is unavailable
(file/share-sheet fallback). It must **not** be reachable without
verification — degraded availability never buys a verification bypass.

---

## 6. On-device verification (surface 3)

### 6.1 Exactly which steps run locally

Identical to the browser, because it is literally the same code path
(`createVerifyIntent(core)` over the packaged `core-bundle.js`), executed
before any signing affordance is rendered and again immediately before
the adapter is invoked (stage `D2` binding):

1. **Strict decode of the exact payload.** The verifier takes the exact
   `unsignedSafeJson` *string* that will be handed to the signer and
   decodes it under closed schemas — any unknown key, pre-filled
   signature, non-zero gas/mass/payload, or malformed value refuses.
2. **Requested intent from the device's own context.** Amounts the user
   typed, recipients the user entered (resolved through the server's
   single address-identity boundary), client-generated vaultId at
   genesis, connected signer identity — **never from a server
   description**. For approver review, provenance is the durable server
   request, because the approver never saw the original form.
3. **Vault knowledge from the presented covenant state:** live outpoint,
   covenantId, protected value, fee reserve, approver slots, agent
   policies, recipient registry.
4. **Manifest derivation on device** — `buildIntentManifest` through the
   portable core, then `verifyIntentManifest` with the complete
   fail-closed detector catalogue, binding the independent intent to the
   independent transaction decode.
5. **Merkle root recomputation on device (F1).** A core bundle lacking
   the Merkle modules is treated as no core at all (`CORE_UNAVAILABLE`
   for every verification):
   - predecessor **agent-registry root** — the full displayed agent
     policy set must hash to exactly `live.agentRoot`
     (`AGENT_REGISTRY_ROOT_MISMATCH` / `VAULT_KNOWLEDGE_MISSING`);
   - acting agent's **allowlist root** — the displayed recipient list is
     rebuilt and must equal the covenant-committed `agentRecipientRoot`
     (`ALLOWLIST_ROOT_MISMATCH`), with membership then proven under it;
     empty/unbuildable refuses (`MERKLE_RECOMPUTE_FAILED`);
   - **successor roots are never adopted** — spend successors via
     `applyAgentSpendV4`; lifecycle ops recomputed from the device's own
     full typed agent params; raw `ownerSetAgentRoot` requires the
     device's own `newAgentRoot`; `review.successorAgentRoot` must EQUAL
     the recomputation (`REVIEW_MISMATCH`);
   - **version-gated** to `policyvault-0.4` / `policyvault-0.4.1`;
     anything else refuses `UNSUPPORTED_COVENANT_VERSION` — unknown
     versions never route to a default tree rule.
6. **Fee ceiling.** The client applies `CLIENT_MAX_FEE_SOMPI` (1 KAS) as
   `requested.maxFeeSompi` wherever the user set no explicit cap — a
   blocking ceiling so a hostile builder cannot reroute value into the
   network fee.
7. **Successor / state-transition checks** through the same detectors
   (protected value, fee reserve, budget consumption, approvals tier,
   authority delta).
8. **Explanation rendering on a full pass** — `core/explain` structured +
   human-readable lines: requested action, every output with its full
   destination key and exact KAS value, fee with the client's cap,
   protected value / fee reserve before and after, per-spend cap and
   period budget consumption, approvals tier, policy impact, warnings,
   and the exact statement *THIS TRANSACTION DOES EXACTLY WHAT WAS
   REQUESTED AND NOTHING ELSE.* Full values only — **no truncation-only
   display**, which is a specific mobile hazard (§6.3).

**Honest residuals, identical to the browser — mobile inherits, it does
not fix and must not claim otherwise:**

- **Fee/mass is not independently recomputed on device.** `core/model/
  fee-mass.js` exports `computeMass` / `calculateRequiredFee` but is
  **not** in the bundle's `MODULES` list today (which carries `amounts`,
  `contract-version`, `vault-state`, `recipient-merkle-v3`,
  `agent-merkle-v4`). The exact fee remains a cross-checked claim under a
  blocking ceiling. Adding `fee-mass.js` (+ `vault-state-v4.js`,
  `compute-budget-v4.js`) to the bundle would upgrade **both** clients at
  once — which is exactly how it must be done. **Do not build a
  mobile-only fee path.**
- **txId** is a consensus hash computed server-side by rusty-kaspa and
  re-derived by the SDK finalizer before broadcast; the client enforces
  only that the request's `txId` equals the id embedded in the payload
  being signed. Residual-trust table entry, unchanged.
- **Genesis `initialState.agentRoot`** remains a cross-checked claim
  (F1 §3): the create flow does not disclose the initial registry's full
  leaf tuples in a recomputable form. Same on mobile.

### 6.2 Extending the anti-drift and cross-runtime harnesses to mobile

Two additions, both reusing existing assets rather than creating new ones:

**(a) Build-time bundle identity gate.** The mobile build must fail if it
packages anything other than the repo's bundle:
`node web/tools/build-core-bundle.js --check` runs in the mobile CI job,
and a packaging step asserts the sha256 of the embedded
`web/core-bundle.js` equals the committed artifact's, with the header's
per-source digests re-verified. A mobile release whose verifier bytes are
not the reviewed bytes must be structurally impossible, not merely
unlikely.

**(b) On-device cross-ENGINE equivalence harness** — the piece that turns
`cross-runtime-equivalence.md` §7's honest caveat into evidence. Shape:

- Serialize the **existing** `core/crossruntime/vectors.js` battery (94
  hand-built vectors + 11 real manifest-fixture actions: SHA-256 block
  boundaries and astral-plane UTF-8, canonical-JSON `-0`/`1e21`/NFC-NFD/
  Cyrillic-confusable keys, message- and transaction-signing requests,
  public-key normalization, capability negotiation, state-ID v1/v4,
  fee/mass, v3/v4 budget operations, representative sompi) to a JSON
  fixture at build time. **No new vectors are invented** — divergence
  between the mobile battery and the Node battery would itself be drift.
- Ship a debug-only harness screen that loads the packaged bundle,
  executes every vector, and emits a canonical result document.
- Compare that document **byte-for-byte** against the Node reference
  document. Run it: in CI on iOS Simulator (JSC) + Android emulator (V8),
  across an Android WebView version matrix; and at app start in debug
  builds. Any mismatch is a release blocker.
- The same harness runs unchanged in desktop Safari/Chrome, so it also
  retires the "one JS engine" caveat for the *web* client — a second
  place where mobile pays for itself.

**Reference-document rule:** the Node battery stays the reference. If a
device engine disagrees, the finding is investigated as a potential core
defect first (classification per the project's failure taxonomy:
CONTRACT BUG / PRODUCTION CODE BUG / TEST BUG / ENVIRONMENT / STALE
ASSUMPTION / DEPENDENCY CHANGE / UNKNOWN) — never resolved by relaxing
the comparison.

### 6.3 How DO-NOT-SIGN renders on mobile

Design rules, several of which are mobile-specific hazards the browser
does not have:

1. **The refusal owns the screen.** A full-screen, opaque interstitial —
   not a toast, not a banner, not a collapsible section, not a bottom
   sheet that can be dismissed by dragging into a signing state.
2. **The signing affordance is absent, not disabled.** No greyed button,
   no long-press override, no developer flag, no "I understand the risks."
   There is no proceed-anyway path in the product.
3. **Independent second refusal.** The adapter invocation re-checks
   independently and refuses `VERIFICATION_REQUIRED` /
   `VERIFICATION_REFUSED` / `VERIFICATION_TX_BINDING_MISMATCH` when the
   outcome is missing, refused, or bound to different bytes. A UI defect
   therefore cannot produce a signature.
4. **Codes verbatim + plain language.** Every refusal code (e.g.
   `ALLOWLIST_ROOT_MISMATCH`, `REVIEW_MISMATCH`,
   `UNSUPPORTED_COVENANT_VERSION`, `CORE_UNAVAILABLE`) shown exactly as
   emitted, each with a one-sentence human explanation, in a copyable
   diagnostics block for support.
5. **A verification error is a refusal.** No partial verdicts, no
   "couldn't check" state that renders as neutral.
6. **Navigation cannot become consent.** OS back button, swipe-back
   gesture, notification dismissal, app backgrounding, and phone-call
   interruption all resolve to **cancel**. Returning from background
   re-runs verification against freshly fetched state rather than
   restoring a stale PASS.
7. **Not colour alone.** Icon + heading text + colour + haptic. Meets
   accessibility requirements and survives display/theme oddities.
8. **No truncation of value-bearing text, ever.** The most likely way a
   small screen silently weakens this ceremony is by eliding an address
   or an amount. Full destination keys and full KAS values must be
   displayed in full — wrapped, monospaced, chunked, horizontally
   scrollable if necessary — never `kaspa:qypp…z7ehd`. This applies to
   the PASS rendering as much as the refusal.
9. **Screenshot/recording**: on Android, `FLAG_SECURE` should be
   considered for signing screens; note honestly that iOS has no
   equivalent guarantee, so this is a hardening measure, not a control.
10. **No push, deep link, or OS intent may land directly on a signing
    action** (§5.2).

### 6.4 Build-integrity surface

A Settings → Build integrity screen shows: app version, build id, the
sha256 of the packaged `core-bundle.js`, and the active network — so a
user (or the owner during acceptance) can compare the shipped verifier
digest against the repository. Under Mode B (§4.3) this screen states
plainly that the payload was served, not store-reviewed.

---

## 7. Delivery and operations

### 7.1 Build pipeline

```
  repo (postlaunch-rc)
    └─ node web/tools/build-core-bundle.js --check      # HARD GATE: bundle is the reviewed bundle
    └─ node --test core/ web/test/ core/crossruntime/   # existing gates, unchanged
    └─ build responsive web payload (same sources as the web client)
    └─ npx cap sync ios | android                        # copy payload into native projects
    └─ assert sha256(packaged core-bundle.js) == repo artifact   # HARD GATE
    └─ on-device equivalence harness: iOS Simulator (JSC) + Android emulator (V8)  # HARD GATE
    └─ xcodebuild → .ipa   |   gradle → .aab
    └─ TestFlight / Play internal track → store review → release
```

### 7.2 Store distribution constraints (current rules, cited)

**Apple.**
- **3.1.5(b)** — apps facilitating virtual-currency storage are permitted
  **only from developers enrolled as an organization**, not individuals.
  Practically: PolicyVault needs an Apple Developer Program *organization*
  enrollment with a D-U-N-S number. That has real lead time and is an
  **owner action**, not something this program can do autonomously — flag
  it early (§9, M0).
- **4.2 / 4.2.2** — "minimum functionality" / "web clippings." The
  Capacitor payload must be accompanied by genuine native integrations
  (camera/QR, push, biometric session gate, deep links, share sheet) and
  those should be called out in review notes. This is the single largest
  Apple-specific rejection risk for the recommended architecture.
- Privacy nutrition labels must be declared accurately; ATT applies only
  if tracking (PolicyVault does not track — declare accordingly).
- No in-app purchase, no paid tiers, no subscriptions — consistent with
  the permanent free-forever policy, and it simplifies review.

**Google.**
- The **Cryptocurrency Exchanges and Software Wallets** policy (effective
  2025-10-29) requires licensing/registration (US MSB/money transmitter;
  EU MiCA CASP) for **custodial** apps. **Non-custodial wallets are out of
  scope** of that requirement. PolicyVault is non-custodial by
  construction — but the app must be able to *demonstrate* it (no key
  custody, no funds held, no exchange functionality), and the §4.4
  device-key exclusion is what keeps this true.
- Blockchain-content declarations still apply, plus the standard target-
  API-level requirement (API 35+ as of 2026).
- Google Play re-signs uploads with Play App Signing — relevant to §7.4.

**Neither store is a security boundary.** Review outcomes do not change
what the covenant enforces; store policy is a distribution constraint and
is treated as such.

### 7.3 Update strategy

- **No over-the-air updates of the security payload. Ever.** Capacitor
  ecosystems support live/OTA web-payload updates; that mechanism is a
  silent channel to replace the verifier — the exact artifact the user is
  trusting — and it is therefore **forbidden** for `core-bundle.js`,
  `verify-intent.js`, and the explanation layer. In practice: no OTA at
  all in v1, since separating "security payload" from "other payload"
  inside one WebView bundle is a distinction too easy to erode.
- Releases are store-reviewed builds only.
- **Minimum-version enforcement**: the hosted API's capability/version
  discovery (surface 22) should let the server refuse a client below a
  minimum verifier version, fail-closed, with an update prompt — so a
  known-defective verifier can be retired without an OTA channel.
- Covenant-version handling is unchanged: unknown versions fail closed on
  the client regardless of app version.

### 7.4 Reproducibility of mobile artifacts (stated honestly)

- **Reproducible:** the web payload — which is the part that matters.
  `core-bundle.js` is deterministic by construction (no timestamps, no
  environment data, per-source sha256 pins, `--check` byte-comparison).
  Its digest can be published per release and displayed in-app (§6.4).
- **Not reproducible:** the `.ipa` / `.aab` binaries. Xcode and Gradle
  toolchains are not bit-reproducible in general, and **both stores
  require code signing** — Apple signs with the developer certificate,
  and Google Play re-signs with the Play App Signing key. A third party
  cannot rebuild a byte-identical store binary.
- **Therefore the honest claim is:** *"reproducible, digest-published
  verification payload inside an attested — not reproducible — native
  shell."* Do not write "reproducible mobile build."
- Play Integrity / App Attest are anti-tamper attestations, not
  reproducibility, and must not be described as such.
- Mitigation that is actually available: publish per-release payload
  digests, keep the native shell minimal and reviewable, and make the
  in-app digest display trivially comparable against the repository.

### 7.5 Operations

- Crash/error reporting must be **content-free**: no amounts, addresses,
  public keys, manifest contents, or session identifiers. Refusal codes
  and shape-only diagnostics only — mirroring the CLI signer's existing
  no-secret-in-output discipline.
- Mobile client metrics feed surface 25 (observability) with the same
  privacy constraint.
- Support flow: the copyable diagnostics block from §6.3 is the
  supported channel; users are never asked for screenshots of vault
  contents.

---

## 8. Risks and unknowns

| # | Risk / unknown | Severity | Current state | Mitigation / resolution path |
|---|---|---|---|---|
| R1 | No Kaspa mobile wallet exposes a verifiable external signing interface | **HIGH** (product) | Established (§2) | QR/airgap adapter as v1 primary; capability-limitation UX; opportunistic adapters only on evidence |
| R2 | KasWare mobile in-app browser provider surface is undocumented/unverified (Android only) | MEDIUM | Release notes only; no docs page | Device probe in M0; ship detection + fail-closed negotiation; claim nothing until probed |
| R3 | Apple 4.2/4.2.2 rejection of a WebView-hosted app | MEDIUM | Known rule | Real native integrations built in M2/M3 **before** first submission; explicit review notes; never submit the read-only phase alone |
| R4 | Apple organization enrollment (3.1.5(b)) has lead time and is an owner action | MEDIUM | Not started | Raise at M0 as a human-gate item; it is on the critical path for any iOS release date |
| R5 | Android System WebView version varies across the fleet (independently updatable) | MEDIUM | Inherent | On-device equivalence harness across a WebView version matrix; minimum-WebView-version check with a fail-closed refusal if below the tested floor |
| R6 | Engine divergence (JSC vs V8) in canonical JSON / BigInt / sorting | LOW-MEDIUM | Exposure is small and verified small (§3.1) | The §6.2 harness is the control; treat any divergence as a core defect until proven otherwise |
| R7 | Fee/mass and genesis-agentRoot residuals inherited from the browser | MEDIUM | Known, documented | Fix in the **shared** bundle (both clients at once); never a mobile-only path |
| R8 | QR capacity for large `unsignedSafeJson` (up to `MAX_SAFE_JSON_CHARS` = 1,048,576) | MEDIUM | Unmeasured | Measure real payload sizes in M0; animated multi-frame QR with a deterministic, integrity-checked framing scheme; file/share-sheet fallback as a first-class path, not a degraded one |
| R9 | Session bootstrap requires a signature even for read-only use | MEDIUM (UX) | Real (§5.1) | Decide (a) QR login vs (b) reviewed session hand-off — open question 3 |
| R10 | A second DO-NOT-SIGN rendering drifting from the web one | MEDIUM | Avoided by the recommendation; would be real under RN | Enforce the §3.6 seam with a test/lint gate that fails on DOM/platform imports in the portable layer |
| R11 | Store review latency on a security fix | MEDIUM | Inherent to no-OTA | Server-side minimum-version refusal (§7.3) retires bad clients without an OTA channel |
| R12 | Device compromise (malware, jailbreak/root, screen capture, hostile keyboard) | MEDIUM | Inherent to mobile | State it in the residual-trust table; root/jailbreak detection is a signal, not a control; the covenant remains the only security boundary |
| R13 | Pressure to add a device-key signer for UX reasons | MEDIUM (architectural) | Excluded (§4.4) | Keep the exclusion and its reasoning in the shipped docs so it is re-argued, not quietly reversed |
| R14 | Mobile scope pulling core changes that destabilize the frozen production lane | MEDIUM | Governed | Mobile is `postlaunch-rc`-lane only; `phaseg-rc2` untouched; any shared-bundle change re-runs the full consolidated gate |
| R15 | Push (surface 19) is ABSENT — mobile alerts depend on an undesigned surface | LOW-MEDIUM | Known | Mobile declares seams only (§5.2); app must be fully correct with notifications unavailable, per the anti-bloat rule |

---

## 9. Phased implementation plan

Sizing is deliberately conservative and in *engineering-wave* terms
rather than calendar dates. Anything touching the shared bundle is
serial with other bundle work (shared mutable state).

| Phase | Scope | Deliverable / exit criterion | Size |
|---|---|---|---|
| **M0 — spike + evidence** | Capacitor shell loading the committed bundle + `verify-intent.js`; build the §6.2 on-device equivalence harness; probe KasWare Android in-app browser on a real device; measure real `unsignedSafeJson` sizes for QR framing; raise Apple org-enrollment as a human gate | Byte-identical vector results on JSC (iOS Sim) and V8 (Android emu) vs the Node reference; a written, evidence-backed answer on KasWare mobile; a QR feasibility number | 1 wave |
| **M1 — read/coordinate client** | Vaults, agents, policies, approvals queue (read), governance view, risk view, activity/audit, organizations, signers + capability limitations, build-integrity screen; QR login (§5.1a); responsive payload that also upgrades the web client | Full control plane readable on device; **no signing**; not submitted to Apple alone (R3) | 1–2 waves |
| **M2 — signing** | `qr-airgap` + `qr-airgap-file` USI adapters; on-device verification enforced on every signing path; DO-NOT-SIGN ceremony per §6.3; approvals, agent lifecycle, policy changes, spends | A signature is impossible without a local PASS bound to the exact payload; adversarial suite (§9.1) green | 2 waves |
| **M3 — native integrations + emergency** | Camera/QR capture, share sheet, biometric/Keychain session gate, deep links, APNs/FCM registration (transport only, coordinated with surface 19), emergency controls with hardened confirmation | Apple 4.2 posture defensible; emergency controls reachable under degradation | 1–2 waves |
| **M4 — opportunistic interop** | `kasware-mobile` adapter behind runtime probing, **only if** M0 produced evidence; Mode B (§4.3) documented with its weaker integrity story | Adapter present and fail-closed, or formally deferred with the evidence recorded | 0–1 wave |
| **M5 — release** | Apple org enrollment complete, privacy labels, Play declarations, TestFlight/internal track, human acceptance on real devices, store submission | Store-reviewed builds; published payload digests | 1–2 waves + external review latency |

**Explicitly deferred beyond v1:** device-key custody in any form (§4.4);
WalletConnect (no Kaspa namespace); Kaspium/Tangem/Ledger adapters (no
interface); desktop→mobile session hand-off (§5.1b — needs its own
hostile review); offline-first local vault caching; tablet/large-screen
layouts; watch/complication surfaces.

### 9.1 Adversarial testing this client must pass (per the addendum's
"required adversarial testing for every new interface")

Prove the mobile client cannot: bypass policy or approval; escalate an
agent capability; exceed budget via concurrency (two devices, one
approver); duplicate spends through retries or app relaunch; substitute
destinations; mutate verified amounts; change fees outside policy; change
signer; replay approvals or auth challenges; exploit stale state after
backgrounding; cross organizations/tenants; downgrade covenant/schema
versions; treat a push payload or deep link as authority; treat a
capability limitation as a verification bypass; or produce a signature
from a refused or unbound verification outcome. Plus mobile-specific
cases: refusal-screen dismissal-as-consent; background/foreground state
restoration of a stale PASS; truncation-induced address substitution; a
malicious QR response (wrong signature, wrong request id, wrong network,
replayed frame); a tampered packaged bundle (must fail the §7.1 gate);
and a served payload in Mode B differing from the reviewed bytes.

---

## 10. Open questions

Listed in priority order; 1–5 are the ones that most change the design.

1. **Does KasWare's Android in-app browser actually inject a usable
   provider, and what is its exact method surface?** Release notes
   describe a developer in-app browser; the API docs have **no mobile
   page** and only hint at mobile via "`switchNetwork` … is disable in the
   mobile app." Unverified: whether `signPskt` and `signMessage` exist on
   mobile, whether specific-input signing with `SIG_HASH_ALL` is honored,
   what network semantics apply, and whether an iOS build is planned.
   **Requires a real device probe (M0) — nothing should be claimed until
   then.**
2. **Are there Kaspa mobile signing interfaces this research missed?**
   The search was thorough but the ecosystem is small and fast-moving, and
   negative results ("no documented interface") are weaker evidence than
   positive ones. Worth a direct inquiry to the Kaspium and KasWare
   maintainers, and worth re-checking the CASA namespaces registry for a
   Kaspa CAIP-2 entry before M4.
3. **Session bootstrap: QR login (5.1a) or reviewed desktop→mobile
   hand-off (5.1b)?** This sets the usability floor for the entire mobile
   product and (b) introduces a new credential-transfer threat model.
   Owner/coordinator decision.
4. **Apple Developer Program organization enrollment** — is it already in
   place, and under what legal entity? 3.1.5(b) blocks any wallet app from
   an individual account, and enrollment lead time sits on the critical
   path for M5. **Human gate.**
5. **Should `core/model/fee-mass.js` (+ `vault-state-v4.js`,
   `compute-budget-v4.js`) be added to the bundle's `MODULES` list now,
   as part of the mobile wave?** It would upgrade fee/mass from a
   cross-checked claim to an independent recomputation for **both**
   clients — but it is shared-bundle work and therefore serial with other
   bundle changes, and it re-opens the consolidated gate.

Additional open items (lower priority, recorded so they are not lost):

6. Is the QR/airgap flow acceptable to the owner as the *primary* v1
   signing path, given that it requires a second device? If not, the only
   honest alternatives are (a) wait on third-party wallets, or (b)
   re-open §4.4 — and (b) is explicitly not recommended.
7. Does mobile launch on mainnet-only, testnet-only, or both? The USI
   negotiates network fail-closed either way, but it changes store copy,
   review framing, and the acceptance plan.
8. Which Android WebView version is the tested floor, and does the app
   refuse below it (fail-closed) or warn?
9. Does the genesis-`agentRoot` residual (F1 §3) get closed before or
   after mobile ships? It is a server-side disclosure change and affects
   both clients identically.
10. Should Mode B (PolicyVault served inside a wallet's in-app browser) be
    supported at all, given its weaker bundle-integrity story — or should
    the served client detect that context and steer users to the store
    app?

---

## 11. Claim labels

| Component | Claim |
|---|---|
| This architecture decision | **DESIGNED** |
| Kaspa mobile wallet landscape survey (§2) | **DESIGNED** (research findings, cited; the KasWare-mobile row is explicitly UNVERIFIED pending a device probe) |
| Framework analysis and recommendation (§3) | **DESIGNED** |
| Mobile USI adapter strategy (§4) | **DESIGNED** — no adapter implemented |
| Feature map (§5) | **DESIGNED** |
| On-device verification design (§6) | **DESIGNED** — the *browser* equivalents it mirrors are IMPLEMENTED + UNIT-TESTED per `browser-verification.md` and `f1-merkle-portability.md`; **no mobile code exists** |
| Delivery/ops (§7) | **DESIGNED** |

Nothing here is IMPLEMENTED, UNIT-TESTED, VM-VERIFIED, TESTNET-VERIFIED,
PRODUCTION-HARDENED, EXTERNALLY REVIEWED, or AUDITED, and none of that is
claimed.

---

## 12. Sources

- [FULLSCALE_COMPLETION_ADDENDUM.md — binding owner directive, 2026-08-26] (repo: `docs/postlaunch/`)
- [Kaspium wallet — GitHub (azbuky/kaspium_wallet)](https://github.com/azbuky/kaspium_wallet)
- [Kaspium v1.0.1 Release — Kaspa](https://kaspa.org/kaspium-v1-0-1-release/)
- [KasWare Wallet developer documentation (full text)](https://docs.kasware.xyz/wallet/llms-full.txt)
- [KasWare Wallet docs — sitemap](https://docs.kasware.xyz/wallet/sitemap.md)
- [KasWare mobile app repository](https://github.com/kasware-wallet/kasware-app) and [releases](https://github.com/kasware-wallet/kasware-app/releases)
- [Kaspa integration — KasWare Wallet docs](https://docs.kasware.xyz/wallet/dev-base/kaspa)
- [Kaspa Integrated on Tangem — kaspa.org](https://kaspa.org/kaspa-integrated-on-tangem/)
- [Tangem — Kaspa cold wallet](https://tangem.com/en/wallet-for/kaspa/)
- [Partially Signed Kaspa Transactions (PSKT & PSKTB) — Kaspa Notes](https://kaspanotes.com/technical/pskt-pskb)
- [kaspa-wallet-pskt — docs.rs](https://docs.rs/kaspa-wallet-pskt)
- [WalletConnect Specs — Namespaces](https://specs.walletconnect.com/2.0/specs/clients/sign/namespaces)
- [Chain Onboarding — Reown Docs](https://docs.reown.com/cloud/chains/overview)
- [ChainAgnostic/namespaces registry](https://github.com/ChainAgnostic/namespaces-2)
- [App Review Guidelines — Apple Developer](https://developer.apple.com/app-store/review/guidelines/)
- [App Store Guideline 3.1.5 Explained: Cryptocurrencies — AcceptMyApp](https://acceptmy.app/guidelines/3-1-5-cryptocurrencies)
- [App Store Review Guidelines: Will Your Webview App Be Rejected? — MobiLoud](https://www.mobiloud.com/blog/app-store-review-guidelines-webview-wrapper)
- [Can You Publish a PWA to the App Store and Google Play? (2026) — MobiLoud](https://www.mobiloud.com/blog/publishing-pwa-app-store)
- [Understanding Google Play's Cryptocurrency Exchanges and Software Wallets Policy — Play Console Help](https://support.google.com/googleplay/android-developer/answer/16329703?hl=en)
- [Google Play Developer Program Policy — Play Console Help](https://support.google.com/googleplay/android-developer/answer/16810878?hl=en)
- [Google Play's new policy not to impact non-custodial crypto wallets — The Paypers](https://thepaypers.com/crypto-web3-and-cbdc/news/google-plays-new-policy-not-to-impact-non-custodial-crypto-wallets)
- [Capacitor Complete Guide — Port Your Web App to iOS & Android (2026) — Oflight](https://www.oflight.co.jp/en/columns/capacitor-web-to-ios-android-porting-guide-2026)
- [11 Steps to Get Your Web App on the App Store (2026) — Capawesome](https://capawesome.io/blog/11-steps-to-get-your-web-app-on-the-app-store/)
- [React Native 0.84: Hermes v1, WebAssembly, and Ecosystem Shifts — Callstack](https://www.callstack.com/events/react-native-0-84-and-other-news)
- [Hermes V1 by Default in React Native 0.84 — TO THE NEW](https://www.tothenew.com/blog/hermes-v1-by-default-in-react-native-0-84-the-biggest-performance-win-of-2026/)
- [Using Hermes — React Native docs](https://reactnative.dev/docs/hermes)
- [WASM support within Hermes? — facebook/hermes issue #429](https://github.com/facebook/hermes/issues/429)
- [WebView: Usage Scenarios and Challenges — W3C WebView CG](https://webview-cg.github.io/usage-and-challenges/)
- [react-native-quick-crypto](https://github.com/margelo/react-native-quick-crypto) / [Expo Crypto](https://docs.expo.dev/versions/latest/sdk/crypto/)
