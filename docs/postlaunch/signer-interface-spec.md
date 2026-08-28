# PolicyVault Universal Signer Interface — v1 specification

Status: **DESIGNED + IMPLEMENTED + UNIT-TESTED** (post-launch upgrade
program C; core implementation `core/signer/`, suites
`core/signer/test/` — `node --test`, 88/88). Nothing in this document is
TESTNET-VERIFIED or PRODUCTION-HARDENED, and no production component has
been migrated onto it; the existing `web/wallet.js` adapter surface and
hosted auth remain the shipped production path unchanged.

Companion document: `docs/postlaunch/signer-kasware-mapping.md` maps the
EXISTING production KasWare + hosted-auth flow onto this interface,
citing the real source files.

---

## 1. Purpose

PolicyVault today integrates exactly one production browser signer
(KasWare) through the generic `WalletAdapter` surface in `web/wallet.js`.
That surface already proved the app has no KasWare-specific branch in
funds-critical logic, but it is browser-shaped, informally specified, and
lives inside the web layer. The Universal Signer Interface (USI) v1 is
the stable, host-independent version of that boundary:

- ONE adapter contract every signer class can implement — browser
  extensions, mobile wallets, hardware devices, air-gapped signers, CLI
  signers, HSMs, MPC quorums, institutional custody platforms, and
  automated agent signers;
- ALL policy/security logic stays in the shared core and its consumers
  (capability gating, identity binding, network binding, request
  freezing, response validation, fail-closed error classification);
  signer-specific code lives ONLY in adapters;
- the architectural dependence on KasWare is removed without changing a
  byte of the existing production flow.

## 2. Goals

1. Express the EXISTING production KasWare flow exactly (connection,
   account/network discovery, challenge signing, frozen-transaction
   signing, error handling) — see the mapping document.
2. Make custody structurally impossible at the interface level (§3).
3. Fail closed on every unknown: versions, capabilities, schemes,
   networks, error codes, request kinds, requirement keys.
4. Support signers whose approval settles out-of-band (asynchronous
   approval lifecycle with explicit deadlines and cancellation).
5. Zero-dependency portability: `core/signer/` is pure Node CommonJS,
   no external packages, no imports from `server/` or `sdk/`, no
   cryptography (see non-goals).

## 3. Non-goals and the NON-CUSTODIAL INVARIANT (hard)

**PolicyVault is not a wallet and never becomes one.** Private keys,
seed phrases, and wallet backups exist ONLY inside external signers. The
interface enforces this structurally, not aspirationally:

- There is **no capability, no request field, and no response field**
  through which secret material could be requested, declared, or
  returned. The capability vocabulary is closed; a hypothetical
  `keyExport`/custody capability cannot even be *declared* — a
  descriptor carrying an unknown key or feature is REFUSED at
  registration (UNIT-TESTED: `conformance.test.js`).
- Signing requests carry only public inputs: a challenge message, or the
  frozen transaction serialization plus canonical per-input signing
  metadata. Responses are validated to their exact expected shape (a
  128-hex signature string; a signed-serialization string); anything
  else is refused.
- The signing act — display, holder consent, key use — happens entirely
  inside the external signer. PolicyVault passes frozen bytes/messages
  in and receives signatures out. It never observes, stores, or proxies
  key material, and this interface gives it no vocabulary to start.

Further non-goals of `core/signer/` itself:

- **No cryptography.** Signature verification (BIP-340 Schnorr over
  Kaspa's `PersonalMessageSigningHash` / `TransactionSigningHash`
  domains) stays in the consumers that hold the authoritative verifier
  (kaspa-wasm in `sdk/`/`server/` — e.g.
  `server/src/auth.js` `kaspa.verifyMessage`). The core validates
  shapes and transports claims; it can therefore never become a
  homemade-crypto risk and never a verification oracle.
- **No transaction construction, fee logic, or broadcast.** Builders,
  finalizers, and submitters remain in the SDK under the existing
  pipeline discipline (intent → build → sign → finalize → submit →
  reconcile).
- **No session management.** Hosted sessions remain a server concern
  (`server/src/auth.js`).
- Kaspa consensus remains the ONLY security boundary. An adapter is
  authorization *material* transport; it is never the funds-security
  boundary — the covenant is.

## 4. Interface identity and versioning rules

- Interface version string: **`policyvault-signer/1`**
  (`SIGNER_INTERFACE_VERSION`).
- Version strings are compared by **exact equality**. Any other value —
  older, newer, malformed, absent — fails closed with
  `INTERFACE_VERSION_UNSUPPORTED`. There is no range matching, no
  downgrade negotiation, no "compatible enough".
- Every capability descriptor and every signing request carries the
  version; the core cross-checks both against itself.
- All v1 vocabularies are **closed**: signature schemes, networks,
  adapter kinds, capability features, request kinds, lifecycle states,
  error codes, negotiation requirement keys, executeSigning options.
  Extending ANY vocabulary is a new interface version, built additively;
  a frozen version's vocabulary is never mutated (same rule as covenant
  versions).
- Unknown values inside any vocabulary position are refused with a
  structured error — never ignored, never defaulted, never routed to a
  "closest match".

## 5. Capability descriptor

Every adapter exposes `describe()` returning:

```
{
  interfaceVersion: "policyvault-signer/1",
  provider: <machine id, /^[a-z][a-z0-9-]{1,31}$/>,   e.g. "kasware"
  label:    <human label, <= 64 chars>,               e.g. "KasWare"
  kind:     <adapter kind>,                           e.g. "browser-extension"
  schemes:  <non-empty unique subset of ["schnorr", "ecdsa"]>,
  networks: <non-empty unique subset of ["mainnet", "testnet-10"]>,
  features: {   // EVERY key declared explicitly, strictly boolean
    messageSigning:        can sign personal messages (auth challenges)
    transactionSigning:    can sign transactions
    specificInputSigning:  can sign exactly the named inputs
    multiAccount:          exposes/switches multiple accounts
    networkSwitching:      can switch networks (declarative in v1)
    accountEvents:         emits accountChanged/networkChanged events
    asynchronousApproval:  approval settles out-of-band
    airGapped:             requests/responses cross an offline boundary
    hardwareDisplay:       payload shown on trusted hardware display
  }
}
```

Validation (`validateCapabilityDescriptor`) refuses, fail closed:
unknown top-level keys, missing keys, unknown kind, unknown/duplicate
scheme or network values, unknown feature keys, missing feature keys
(explicit declaration — no defaults), non-boolean feature values. The
validated descriptor is deep-frozen.

**Schemes.** `schnorr` is BIP-340 (64-byte signatures) — the scheme of
Kaspa PubKey accounts and the ONLY scheme with a defined v1 response
contract. `ecdsa` exists in the vocabulary so Tangem-class signers can
declare themselves truthfully and consumers can refuse them fail-closed
(exactly as hosted auth v1 refuses ECDSA/Tangem accounts); v1 defines
NO verified ECDSA response contract (§9), and a contract will only be
added from source-backed evidence of the exact byte format, never
guessed. A descriptor describes what the ADAPTER offers upward, not
everything its underlying provider could theoretically do.

**Networks.** The v1 set mirrors the Gate R operational set of
`sdk/src/address-identity.js` (`mainnet`, `testnet-10`). New networks
require a new interface version.

**Feature ↔ method binding.** Declaring a feature that binds a method
without implementing the method refuses registration:
`messageSigning → signMessage`, `transactionSigning → signTransaction`,
`asynchronousApproval → cancelSigning`, `accountEvents → on`. The other
features are declarative negotiation/UX facts in v1 (e.g.
`networkSwitching` binds no method yet — §13 gap 6). Extra methods
beyond the declared features are permitted but consumers MUST gate on
declared capabilities, never probe for methods.

## 6. Adapter interface (methods)

Required unconditionally: `describe`, `detect`, `connect`, `disconnect`,
`getActiveAccount`, `getNetwork`, `getPublicKey`. Conditional methods
per §5. All methods except `describe`/`detect` may be async.

- `detect() -> boolean` — is the provider present/reachable (e.g.
  `window.kasware` injection). Never throws for absence.
- `connect() -> { address, network }` — establish the provider session
  (may open a provider consent prompt). Holder refusal is
  `USER_REJECTED`.
- `disconnect() -> void` — best-effort provider-session teardown.
- `getActiveAccount() -> { address } | null` — the currently active
  account CLAIM, or null when disconnected.
- `getNetwork() -> <network id> | null` — the live network CLAIM,
  normalized to the canonical vocabulary (`mainnet` / `testnet-10`);
  null/unknown when unavailable. Consumers must treat any non-matching
  value as `WRONG_NETWORK`, never assume.
- `getPublicKey() -> <provider-native public key hex>` — the active
  account's public key CLAIM in the provider's native encoding. The core
  supplies the ONE shared normalization `normalizePublicKeyToXOnly`
  (exact `web/wallet.js` rules): 64-hex x-only accepted; 66-hex
  compressed (02/03) reduced to X; uncompressed 04-keys and every other
  shape refused with `INVALID_PUBLIC_KEY`, with shape-only diagnostics
  (the malformed value itself is never echoed).
- `on(event, callback)` — `accountChanged(address)`,
  `networkChanged(network)`. Account/network switches are SECURITY
  EVENTS for consumers (invalidate in-progress flows and hosted
  sessions, as the production web app already does).
- `signMessage(request) -> signature` and
  `signTransaction(request) -> signedSerialization` — §8/§9.
- `cancelSigning(requestId) -> void` — required with
  `asynchronousApproval`; best-effort revocation of a pending approval.

### Claimed vs proven identity (standing wallet-identity boundary)

**Everything an adapter reports — address, public key, network — is an
unproven CLAIM.** A provider-claimed identity is NEVER trusted for
authentication, tenancy, or authorization. Identity is established only
by cryptographic proof:

1. the verifier (server/core consumer) issues a challenge it
   constructed itself (CSPRNG nonce, its own configured origin/network,
   an expiry);
2. the signer signs the challenge message through `signMessage`;
3. the verifier reconstructs the challenge text server-side (a
   client-submitted message string is never verified), derives the
   x-only key from the CLAIMED address via the authoritative parser,
   requires the submitted public key to equal it exactly, and verifies
   the Schnorr signature against it;
4. network mismatches fail closed at every step (challenge network vs
   verifier network vs live signer network).

Reference implementation of the verifier side:
`server/src/auth.js` `HostedAuthService.verify` (with
`sdk/src/address-identity.js` as the one address→pubkey boundary).
`core/signer` transports the claims and enforces the *binding gates* it
can see (live-network equality, active-account equality around signing);
the cryptographic proof itself is the consumer's obligation because the
core deliberately contains no cryptography (§3).

## 7. Registration, registry, negotiation

- `validateAdapter(adapter)` → frozen `{ adapter, descriptor }`;
  refuses (PROTOCOL_VIOLATION) an adapter missing required methods or
  presenting an invalid/unknown-capability descriptor. Partial
  acceptance does not exist.
- `SignerRegistry.register(adapter)` — validates and stores by provider
  id; duplicate ids refused; `get(id)` of an unregistered provider fails
  closed with `SIGNER_NOT_FOUND`.
- `negotiateCapabilities(descriptor, requirements)` — consumer-side
  check against `{ schemes, features, network }` requirements. Returns
  frozen `{ ok: true, provider }` or a structured refusal
  `{ ok: false, provider, code, missing }` with
  `UNSUPPORTED_SCHEME` / `UNSUPPORTED_CAPABILITY` / `WRONG_NETWORK`.
  Malformed or UNKNOWN requirement keys/values throw `REQUEST_INVALID`
  — a consumer constraint the vocabulary cannot express must never
  silently match. `requireCapabilities` is the throwing variant.
  Canonical case (UNIT-TESTED): a consumer requiring `schnorr` refuses
  an ecdsa-only (Tangem-class) adapter.

## 8. signMessage semantics (authentication challenges)

Request (`createMessageSigningRequest`): frozen
`{ interfaceVersion, requestId (32-hex CSPRNG), kind: "sign-message",
message, scheme, network?, expectedSignerAddress?, createdAtMs }`.

- The message is signed **verbatim**; the signer displays exactly this
  text to its holder (the production challenge ends with "This
  signature only signs you in. It cannot move funds.").
- `scheme` is **always explicit** — never defaulted, never "auto"
  (auto could silently change the cryptographic scheme on Tangem-class
  accounts; `web/wallet.js` forces `{ type: "schnorr" }` for the same
  reason). Unknown schemes are refused at creation.
- Domain separation is structural (Kaspa semantics): personal messages
  are hashed in the `PersonalMessageSigningHash` keyed-blake2b domain,
  transactions in `TransactionSigningHash` — an authentication
  signature can never validate as covenant/funds authority and vice
  versa.
- Response contract: `schnorr` → exactly 128 lowercase hex chars
  (64-byte BIP-340) after trim+lowercase — the same gate as
  `web/wallet.js signAuthMessage` and `server/src/auth.js`
  `SCHNORR_SIG_HEX`. `ecdsa` → **no v1 contract; refused**
  (`UNSUPPORTED_SCHEME`) — and `executeSigning` refuses a non-schnorr
  message request BEFORE invoking the signer, so no prompt is ever
  opened whose result cannot be accepted.

## 9. signTransaction semantics (frozen bytes in, signature out)

Request (`createTransactionSigningRequest`): frozen
`{ interfaceVersion, requestId, kind: "sign-transaction",
unsignedSafeJson, signInputs, network, expectedSignerAddress, scheme?,
createdAtMs }`.

- `unsignedSafeJson` is the EXACT frozen serialized transaction
  produced by the SDK builders. The core never parses, rebuilds, edits,
  trims, or re-encodes it — pass-through only, in both directions.
- `signInputs` is the canonical frozen signing metadata, ported exactly
  from `web/app-v4.js assertCanonicalSignInputs`: every entry is
  `{ index: integer >= 0, sighashType: 1 }` (SIG_HASH_ALL — the only
  sighash type this application ever emits) and carries NO other keys.
  The core never invents or trims signing semantics. (Motivating
  real-KasWare incident: a reconstructed entry that dropped
  `sighashType` panicked kaspa-wasm AFTER the human clicked Sign; the
  guard refuses before any signer prompt opens.)
- `network` and `expectedSignerAddress` are **required**: a funds-path
  signature request is always bound to one network and one expected
  identity, fail closed.
- The signer displays/holds; it adds signatures for exactly the named
  inputs and returns the signed serialization (non-empty string,
  returned VERBATIM). **PolicyVault never reconstructs different bytes
  after signature:** the downstream SDK finalizer independently
  re-derives the txid from the frozen serialization and refuses any
  drift (`sdk/src/wallet-submit-v4.js` — `TXID_MISMATCH`, "any other
  txid is ambiguous"). The interface transports; consensus and the
  frozen-txid check remain the authority.
- v1 transaction requests REQUIRE the adapter to declare
  `specificInputSigning`: approvers sign ONLY the covenant input of the
  exact frozen transaction — a whole-transaction-only signer cannot
  honor the contract and is refused (`UNSUPPORTED_CAPABILITY`).

## 10. Signing execution and the approval lifecycle

`executeSigning(adapterOrRegistration, request, { timeoutMs?,
onTransition? })` drives one request through every fail-closed gate of
the existing production flow (`web/app-v4.js walletSign`, generalized):

States (closed vocabulary; CREATED is implicit at request creation;
exactly ONE terminal state is emitted per execution):

```
            +----------- gates fail ----------> REFUSED   (terminal)
 CREATED -> | capability / scheme / v1-contract
            | async-deadline / network(live) / identity(pre)
            +-> SUBMITTED  (the external signer now holds the request)
                  |-> APPROVED   (terminal: response validated,
                  |               identity re-verified post-approval)
                  |-> REJECTED   (terminal: holder declined -> USER_REJECTED)
                  |-> TIMED_OUT  (terminal: deadline elapsed; cancelSigning
                  |               best-effort; late settlements DISCARDED)
                  +-> FAILED     (terminal: provider/protocol/validation)
```

Gates, in order, all before the signer is contacted:

1. **Capability** — request kind vs declared features (incl. the
   `specificInputSigning` rule of §9).
2. **Scheme** — request scheme must be declared by the adapter; and a
   `sign-message` request must use a scheme with a v1 response contract
   (schnorr) — refused pre-invocation otherwise.
3. **Async deadline** — adapters declaring `asynchronousApproval`
   REQUIRE an explicit `timeoutMs` (an unbounded out-of-band wait is
   refused).
4. **Network** — the request network must be declared by the adapter
   AND equal the adapter's LIVE `getNetwork()` answer; null/unknown live
   networks fail closed. Declared networks are never trusted alone.
5. **Identity (pre)** — when `expectedSignerAddress` is bound, the live
   active account must equal it (`SIGNER_DISCONNECTED` when none;
   `ACCOUNT_CHANGED` when different).

After the signer settles: response shape is validated (§8/§9), then the
active account is re-verified against `expectedSignerAddress`
(**post-approval identity re-check** — a mid-prompt account switch
discards the signature with `ACCOUNT_CHANGED`, mirroring walletSign
stages F/G→I).

Timeout semantics (asynchronous signers — mobile push, hardware button,
MPC quorum, institutional policy engine): when the deadline elapses the
core (a) invokes `cancelSigning(requestId)` best-effort (a cancellation
failure never masks the timeout), (b) emits `TIMED_OUT`, (c) throws
`SIGNER_TIMEOUT`, and (d) **discards any later provider settlement** —
a late approval is never delivered, and no second terminal transition is
ever emitted (UNIT-TESTED, including a sabotaged-cancellation variant).

Observer callbacks (`onTransition`) receive frozen
`{ requestId, state, atMs, code? }` records and can never alter signing
outcomes (observer exceptions are isolated).

On approval, `executeSigning` returns frozen
`{ requestId, status: "approved", result }` with
`result = { signature }` or `{ signedSafeJson }`; every other outcome
throws a `SignerError`.

## 11. Structured error taxonomy (closed, fail-closed unknowns)

`SignerErrorCodes` (v1, closed):

| Code | Meaning |
| --- | --- |
| `SIGNER_NOT_FOUND` | provider not installed / not registered |
| `SIGNER_DISCONNECTED` | no connected/active account |
| `SIGNER_LOCKED` | provider present but locked; holder action needed |
| `USER_REJECTED` | the signer's holder declined |
| `WRONG_NETWORK` | declared or live network mismatch — fail closed |
| `ACCOUNT_CHANGED` | active identity changed before/during/after signing |
| `UNSUPPORTED_CAPABILITY` | required feature not offered |
| `UNSUPPORTED_SCHEME` | required scheme not offered / no v1 contract |
| `INVALID_PUBLIC_KEY` | public-key claim malformed / unsupported encoding |
| `INVALID_SIGNATURE_RESPONSE` | signing result malformed for scheme/kind |
| `SIGNER_TIMEOUT` | approval deadline elapsed; cancelled fail-closed |
| `PROVIDER_ERROR` | unclassified provider/transport fault (cause kept) |
| `PROTOCOL_VIOLATION` | interface contract breached (incl. unknown codes) |
| `INTERFACE_VERSION_UNSUPPORTED` | version mismatch — no downgrade |
| `REQUEST_INVALID` | malformed request/options refused pre-invocation |

Fail-closed unknown mapping (`normalizeAdapterFailure`):

- a `SignerError` passes through unchanged;
- an adapter failure carrying a KNOWN `signerCode` is the sanctioned
  adapter-side classification (the USI descendant of `web/wallet.js`
  `walletCategory`) — wrapped preserving code/message/cause;
- a failure claiming an **unknown** code is a contract breach →
  `PROTOCOL_VIOLATION` (claimed code recorded in details) — never
  passed through, never guessed into a "similar" meaning;
- anything else (plain exception, garbage) → `PROVIDER_ERROR` with the
  original preserved as `cause`.
- even *constructing* a SignerError with an unknown code is refused —
  PolicyVault components cannot mint codes outside the vocabulary.

Diagnostics discipline: messages and `details` carry NON-SECRET data
only — never key material, never seed phrases, never raw malformed
values (public-key errors report only the value's shape).

## 12. Target adapter catalogue (v1 kinds)

| Kind | Examples | Expected declaration profile |
| --- | --- | --- |
| `browser-extension` | KasWare (reference — see mapping doc); other injected Kaspa wallets | schnorr; messageSigning + transactionSigning + specificInputSigning + accountEvents; sync approval |
| `mobile` | phone wallet via deep-link/relay | asynchronousApproval (push-approve on the phone); explicit timeouts |
| `hardware` | device-held keys with trusted display | hardwareDisplay; often asynchronousApproval (physical button) |
| `air-gapped` | offline QR/file shuttle signer | airGapped + asynchronousApproval; long explicit deadlines |
| `cli` | operator command-line signer | schnorr; sync or async; scriptable operations |
| `hsm` | organization-controlled hardware security module | transactionSigning; possibly no messageSigning; policy-gated |
| `mpc` | threshold/multi-party quorum | asynchronousApproval (quorum collection); timeouts mandatory |
| `institutional` | custody-platform policy engine | asynchronousApproval; approval may take hours/days — explicit long deadlines |
| `agent` | automated agent runtime holding ITS OWN delegate key | no human present; the COVENANT remains the control plane — the interface grants no policy relief |
| `mock` | in-memory conformance/test adapter (`mock-adapter.js`) | everything, deterministic placeholders, async mode |

In every row the key stays inside the external signer; for `agent`
signers specifically, the agent's runtime is the external signer — the
covenant-enforced spending limits are exactly the protection that makes
a non-human key holder safe to authorize, and nothing in this interface
weakens or substitutes for them.

## 13. Honest gaps / open questions (v1)

1. **ECDSA response contract undefined** — expressible in negotiation,
   refused at signing (mirrors hosted auth v1's Tangem refusal). Adding
   it requires source-backed evidence of the exact signature byte
   format (kaspa-wasm / KasWare Tangem path), never a guess.
2. **No cryptographic verification in the core** — identity PROOF
   (challenge signature verification) is a consumer obligation
   (server/SDK with kaspa-wasm). The interface documents the rule and
   enforces the observable bindings but cannot itself verify.
3. **Frozen-txid equality is enforced downstream** — the core cannot
   parse Safe JSON without kaspa-wasm; byte-drift refusal remains in
   `sdk/src/wallet-submit-v4.js` (by design; documented, not hidden).
4. **Whole-transaction-only signers unsupported** — v1 requires
   `specificInputSigning` for transaction requests (§9).
5. **Multi-account enumeration API not specified** — v1 models the
   ACTIVE account (all production flows need only it); `multiAccount`
   is declarative. An enumeration/selection method is a candidate for
   v2.
6. **`networkSwitching` binds no method** — declarative only; the
   production app never switches programmatically (the server's network
   is authoritative and the human switches in the wallet).
7. **Event unsubscription** — `on()` has no `off()`/return-unsubscriber
   contract yet (the existing `web/wallet.js` adapters have none
   either); listener lifecycle management is a v2 candidate.
8. **Air-gapped transport format unspecified** — the async lifecycle
   (explicit deadline + cancel + discard-late) is the v1 hook; the
   QR/file chunking transport belongs to the adapter until a shared
   format earns standardization.
9. **Rich response shapes** — v1 responses are strings (signature /
   signed serialization), matching the KasWare contract. Multi-part /
   partially-signed exchange formats would be a versioned addition.
10. **Session/connection lifecycle beyond connect/disconnect** (e.g.
    KasWare's origin-scoped disconnect) stays adapter-internal.

## 14. Migration posture

The interface is additive. `web/wallet.js`, `web/app.js`,
`web/app-v4.js`, and `server/src/auth.js` are UNCHANGED and remain the
shipped production path. The mapping document demonstrates expressibility
of the existing flow; actually porting the web layer onto `core/signer`
(and adding a real second adapter) is future work with its own gates —
including BROWSER-layer tests, since `core/signer` is deliberately
DOM-free and the suites here are UNIT only.
