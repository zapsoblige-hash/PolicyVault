# PolicyVault Universal Signer Interface — v2 specification

Status: **DESIGNED + IMPLEMENTED + UNIT-TESTED**, with the CLI reference
adapter additionally exercised against **REAL kaspa-wasm cryptography**.
Nothing here is TESTNET-VERIFIED, PRODUCTION-HARDENED, or EXTERNALLY
REVIEWED, and **no live third-party wallet was exercised in this track** —
the KasWare adapter is unit-tested against the *documented* provider API
with a recorded mock, never against a running extension. No production
flow has been migrated onto v2: the shipped signing path
(`createKasWareSessionAdapter` → interface v1) is unchanged.

**§12 (Wave 2, Track G) adds the first real DOMAIN consumer of v2**: the
v0.7 organizational-root slot-signing flow. It is
**IMPLEMENTED + UNIT-TESTED + ADVERSARIAL-TESTED**, with the CLI keyfile
path additionally **REAL-CRYPTO-TESTED**. It is still NOT
TESTNET-VERIFIED, NOT PRODUCTION-HARDENED, and
makes **no live-wallet compatibility claim** — see §12 for the exact
scope.

Implementation `core/signer/v2/`. Suites:

| Suite | Layer | Count |
| --- | --- | --- |
| `core/signer/test/v2-conformance.test.js` | UNIT | 25 |
| `core/signer/test/v2-lifecycle.test.js` | UNIT | 29 |
| `core/signer/test/v2-adapters.test.js` | UNIT | 30 |
| `core/signer/test/hostile-v2.test.js` | ADVERSARIAL | 48 |
| `core/signer/adapters/cli/test/v2-conformance.test.js` | UNIT + REAL CRYPTO | 7 |
| `web/test/signer-kasware-v2.test.js` | BROWSER-LAYER UNIT | 14 |
| `mobile/test/signer-v2-airgap-compat.test.js` | MOBILE UNIT | 9 |
| `core/signer/test/org-root-slot-v2-hostile.test.js` (§12) | ADVERSARIAL | 15 (a 24-row table + further hostile assertions across the other 14) |
| `sdk/test/org-root-slot-signer-v2.test.js` (§12) | SDK/INTEGRATION + REAL CRYPTO | 3 |

v1 remains frozen and fully supported:
`docs/postlaunch/signer-interface-spec.md`, `core/signer/`.

---

## 1. Why a new interface version

Interface v1's vocabularies are **closed and frozen** — the same
discipline the covenant versions follow: *a frozen version's vocabulary is
never mutated; extensions are a new version, built additively.* Every
capability v1 could not express is therefore added in v2, leaving
`policyvault-signer/1` byte-for-byte untouched.

Version strings are matched by **exact equality in both directions**: v1
refuses a v2 descriptor and v2 refuses a v1 descriptor, both with
`INTERFACE_VERSION_UNSUPPORTED`. There is no range matching, no downgrade,
no "compatible enough". Both cores run side by side in one process
(pinned by `v2-conformance.test.js`).

The **non-custodial invariant is unchanged and structural**: there is no
capability, no request field, and no response field through which a seed
phrase, private key, or wallet backup could be requested, declared, or
returned. Every vocabulary below is closed, so a custody capability cannot
even be spelled — a descriptor or envelope carrying one is refused
(`hostile-v2.test.js` H13). Kaspa consensus remains the only security
boundary; this interface transports authorization material.

---

## 2. GAP ANALYSIS — v1 against the flagship signer contract

`COVERED` = v1 already does it. `PARTIAL` = v1 does part of it, with the
gap named. `MISSING` = v1 has no vocabulary for it.

| # | Flagship requirement | v1 status | Detail / where v2 closes it |
| --- | --- | --- | --- |
| 1 | **Network identity** | COVERED | `describe.networks` (closed set `mainnet` / `testnet-10`) + a LIVE `getNetwork` gate inside `executeSigning`; a null/unknown live answer fails closed. v2 keeps this and adds the response-side check (§6). |
| 2 | **Signer address** | COVERED | `getActiveAccount` → `{ address } \| null`, bound per request via `expectedSignerAddress`, re-checked after approval. Everything reported is a CLAIM; proof is the consumer's signature verification. |
| 3 | **Public key** | COVERED | `getPublicKey` plus the one shared `normalizePublicKeyToXOnly` (64-hex x-only, 66-hex compressed → X; uncompressed `04` and everything else refused with shape-only diagnostics). Re-exported unchanged by v2. |
| 4 | **Sign message** | COVERED | Verbatim message, always-explicit scheme, 128-hex Schnorr response contract; ECDSA refused *before* the prompt opens (no verified response contract). |
| 5 | **Sign transaction** | COVERED | Frozen `unsignedSafeJson` in, signed serialization out, pass-through in both directions; canonical `{ index, sighashType: 1 }` entries; `specificInputSigning` required. |
| 6 | **PSKT capability** | MISSING | v1 has no word for it. **v2 adds `pskt: { supported, roles }`, DECLARATION ONLY** — see §4 for why no response contract exists. |
| 7 | **Transaction format / version** | MISSING | v1 assumes Kaspa Safe JSON implicitly and never states or checks it. **v2 adds `transactionFormats` + a per-request pin** (`kaspa-safe-json/1`), enforced both ways. |
| 8 | **Sighash behaviour declaration** | PARTIAL | v1 *emits* SIGHASH_ALL and refuses anything else in `assertCanonicalSignInputs`, but the signer never DECLARES what it supports, so a signer that cannot honour SIGHASH_ALL is discovered after the prompt. **v2 adds a declared, negotiated `sighash` matrix** and refuses before invocation. |
| 9 | **User-presence requirement** | MISSING | v1 cannot distinguish "a human clicks Sign" from "a process signs unattended" — an `agent` and a `hardware` adapter look alike. **v2 adds `userPresence` + a consumer gate.** |
| 10 | **Mobile deep-link / transport capability** | MISSING | v1 has `kind` (what the signer IS) but not how request and response TRAVEL, which is the security-relevant fact. **v2 adds `transport` (`in-page` / `deep-link` / `qr-airgap` / `file` / `cli`) + a consumer allow-list.** |
| 11 | **Cancellation / refusal** | PARTIAL | Holder refusal (`USER_REJECTED`) is covered; CONSUMER-initiated cancellation is not — v1 can only wait for a timeout, and `cancelSigning` is bound to `asynchronousApproval` rather than declared. **v2 adds a `cancellation` declaration, a cancellation token, `REQUEST_CANCELLED`, and a `CANCELLED` state**, plus the structural rule that an asynchronous signer MUST support cancellation. |
| 12 | **Timeout** | PARTIAL | v1 has `timeoutMs` and requires it for async signers, but nothing bounds it against what the signer can honour, and the REQUEST itself never expires — a v1 request is a bearer authorization with no staleness. **v2 adds `maxTimeoutMs`, a mandatory request `expiresAtMs`, an `EXPIRED` state, and the rule that the effective deadline is the EARLIER of the two.** |
| 13 | **Wrong-network handling** | PARTIAL | Declared + live checks exist; the RESPONSE could not be checked (bare strings). **v2 binds the network into the response envelope.** |
| 14 | **Capability truthfulness** | MISSING | v1 trusts `describe` completely. A signer (or an adapter written from a wallet's release notes) can declare what its provider cannot do; the discovery happens after a human clicks Sign. **v2 adds a REQUIRED `probeCapabilities` and refuses over-declaration with `CAPABILITY_MISMATCH`.** |
| 15 | **Request/response binding** | MISSING | v1 responses are BARE STRINGS. Mis-binding, replay, duplicate settlement, and "the signer answered a different request" are structurally undetectable. **v2 adds nonce + expiry + payload digest on the request and a bound response ENVELOPE.** |
| 16 | **Signed-bytes identity** | DEFERRED-BY-DESIGN in v1 | The core holds no transaction code, so v1 leaves frozen-txid enforcement to `sdk/src/wallet-submit-v4.js` (`TXID_MISMATCH`). **v2 keeps the core crypto-free but accepts an INJECTED `deriveTransactionId`**, so the check can run at the interface too — and reports `txIdVerified: false` when it did not, never as passed. |

### Intentionally deferred in v2 as well (with reasons, from source)

- **ECDSA response contract** — still undefined. `ecdsa` stays declarable
  so Tangem-class signers describe themselves truthfully and consumers
  refuse them at negotiation, but no byte format is guessed. Adding one
  requires source-backed evidence (kaspa-wasm / KasWare's Tangem path);
  hosted auth refuses ECDSA account types before any prompt
  (`server/src/auth.js`, `sdk/src/address-identity.js`).
- **A PSKT wire contract** — see §4.
- **Multi-account enumeration, `off` unsubscription, programmatic
  network switching** — unchanged v1 gaps; no production flow needs them
  and inventing an API without a consumer is how a closed vocabulary
  rots. `multiAccount` / `networkSwitching` / `accountEvents` remain
  declarative negotiation facts.
- **Cryptography in the core** — permanently out of scope. The core
  validates shapes, binds requests, and transports claims; it never
  verifies a signature, derives a sighash, or parses a transaction. That
  is what keeps it from becoming either a homemade-crypto risk or a
  verification oracle.
- **A nonce that crosses an air gap** — requires a new offline-signer
  document version; see §8 L1.

---

## 3. Interface identity

- Version string: **`policyvault-signer/2`** (`SIGNER_INTERFACE_VERSION_V2`).
- Shared, UNFORKED vocabularies (re-exported from v1, not copied):
  `SIGNATURE_SCHEMES`, `SIGNER_NETWORKS`, `ADAPTER_KINDS`,
  `CAPABILITY_FEATURES`, `REQUEST_KINDS`, `SIGHASH_ALL`.
- New closed vocabularies:

```
SIGHASH_FLAGS       ["all", "none", "single", "anyoneCanPay"]
TRANSACTION_FORMATS ["kaspa-safe-json/1"]
PSKT_ROLES          ["creator","constructor","updater","signer",
                     "combiner","finalizer","extractor"]     (§4)
TRANSPORT_KINDS     ["in-page","deep-link","qr-airgap","file","cli"]
USER_PRESENCE_MODES ["required","not-required"]
CANCELLATION_MODES  ["supported","unsupported"]
SIGNING_STATES_V2   ["REFUSED","SUBMITTED","APPROVED","REJECTED",
                     "TIMED_OUT","EXPIRED","CANCELLED","FAILED"]
```

`USER_PRESENCE_MODES` has deliberately **no "unknown" value**: an
unknown-presence signer is one a consumer could accidentally accept, so an
adapter that cannot honestly claim a human declares `not-required` and a
presence-requiring consumer refuses it.

---

## 4. PSKT — declared only, and why

rusty-kaspa ships a real PSKT implementation: the `wallet/pskt` crate,
whose roles are enumerated in `wallet/pskt/src/role.rs` (Creator,
Constructor, Updater, Signer, Combiner, Finalizer, Extractor) and exposed
through the WASM `PSKT` class (`wasm/nodejs/kaspa/kaspa.d.ts` —
`creator`, `toConstructor`, `toUpdater`, `toSigner`,
`toCombiner`, `toFinalizer`, `toExtractor`). `PSKT_ROLES` mirrors
that enum exactly, in upstream order.

**PolicyVault does not use it, and neither does its production signer.**
The KasWare provider method is *named* `signPskt`, but its payload is
`{ txJsonString, options: { signInputs } }` and its result is a Kaspa
**Safe JSON transaction serialization** — the exact string the SDK hands
to `Transaction.deserializeFromSafeJSON`. The evidence is in this
codebase, not in a wallet's release notes:

- `web/wallet.js` / `web/signer-kasware-adapter.js` — the call site and
  its return handling;
- `sdk/src/signer-dev.js` — "Mirrors KasWare's `signPskt(...)` return
  shape: a transaction whose signed inputs carry a signature-script push",
  implemented as `deserializeFromSafeJSON` → `createInputSignature` →
  `serializeToSafeJSON`;
- `sdk/src/wallet-requests-v4.js` — the builder that produces the unsigned
  Safe JSON "to bridge the frozen build to the KasWare signPskt contract".

Nothing in that path constructs, combines, finalizes, or extracts a PSKT.
So v2 lets an adapter DECLARE `pskt: { supported, roles }` — enough for a
consumer to route or refuse a future multi-party flow — and defines **no
PSKT response contract**. The KasWare and CLI adapters both declare
`pskt.supported: false`; declaring otherwise because of a method's *name*
is exactly the unverified capability claim v2 exists to abolish. A wire
contract will be added from source-backed evidence, never a guess.

---

## 5. Capability descriptor

`describe` returns the v1 fields (`interfaceVersion`, `provider`,
`label`, `kind`, `schemes`, `networks`, `features`) **plus**:

```
sighash:            { all, none, single, anyoneCanPay }   every flag, strict boolean
pskt:               { supported: boolean, roles: [<PSKT_ROLES>] }
transactionFormats: [<TRANSACTION_FORMATS>]
userPresence:       "required" | "not-required"
transport:          <TRANSPORT_KINDS>
cancellation:       "supported" | "unsupported"
maxTimeoutMs:       positive integer, <= 30 days
```

Every key is REQUIRED and every value is checked against a closed
vocabulary. Unknown keys, missing keys, unknown values, and non-boolean
flags are refused (`PROTOCOL_VIOLATION`). The validated descriptor is
deep-frozen.

**Internal consistency is enforced** — a descriptor that contradicts
itself is a contract breach, not a preference:

- `asynchronousApproval: true` REQUIRES `cancellation: "supported"` (an
  out-of-band authorization that can never be revoked is not acceptable);
- `transactionSigning: true` requires ≥1 transaction format and ≥1
  sighash behaviour; `transactionSigning: false` forbids naming formats;
- `pskt.roles` is non-empty exactly when `pskt.supported` is true;
- `airGapped: true` cannot pair with `transport: "in-page"`;
- `cancellation: "supported"` requires a `cancelSigning` method.

**Required methods**: v1's seven (`describe`, `detect`, `connect`,
`disconnect`, `getActiveAccount`, `getNetwork`, `getPublicKey`) **plus
`probeCapabilities`**. Feature→method binding is inherited from v1.

### Capability probe

`probeCapabilities` returns what the LIVE provider actually exposes:

```
{ interfaceVersion, probed: true,
  methods?: [<interface method names>], sighash?, pskt?,
  transactionFormats?, network? }
{ interfaceVersion, probed: false, reason: "<short, non-empty>" }
```

`verifyDeclaredCapabilities(descriptor, report)` cross-checks them. The
asymmetry is the point: **an adapter may offer upward LESS than its
provider can do** (the v1 rule — KasWare's adapter declares `schnorr`
only although the extension can emit ECDSA for Tangem cards) **but never
more**. Every declaration the probe contradicts is a `CAPABILITY_MISMATCH`
and the adapter is refused *before* any prompt opens.

`probed: false` is an HONEST answer (an offline signer cannot be
interrogated before the shuttle) and must carry a reason; a consumer
passing `requireProbedCapabilities: true` then refuses, and the returned
outcome always records `capabilitiesProbed` truthfully.

---

## 6. Requests, envelopes, and binding

**Request** (frozen, core-created; `ttlMs` is REQUIRED):

```
{ interfaceVersion, requestId (32-hex CSPRNG), nonce (64-hex CSPRNG),
  kind, <message | unsignedSafeJson>, payloadSha256,
  signInputs, transactionFormat, sighash,        (transactions)
  scheme, network, expectedSignerAddress,
  createdAtMs, expiresAtMs }
```

`payloadSha256` is the sha256 of the EXACT bytes to be signed. It is
RECOMPUTED inside `executeSigningV2`: a request whose digest does not
match its own payload was altered after creation and is refused with
`PAYLOAD_MUTATED` **before the signer is invoked**.

Every request expires (1 s … 30 days). An authorization that never goes
stale is a replayable bearer token; the 30-day ceiling accommodates
institutional/MPC approvals that legitimately take days.

**Response envelope** — v2 responses are bound envelopes, never bare
values:

```
{ interfaceVersion, requestId, nonce, kind, network, signerAddress,
  scheme, payloadSha256, sighashType, transactionFormat, signedTxId?,
  result: { signature } | { signedSafeJson } }
```

`validateResponseEnvelope` checks, in order: version → closed key set →
requestId → nonce → kind → network → signer identity → scheme →
sighash/format → payload digest → result shape. Each mismatch has its own
code, so a consumer can tell "the holder declined" from "the transport
handed me somebody else's signature". The signed serialization is returned
**verbatim** — never trimmed or re-encoded, because a downstream validator
will check these exact bytes.

**Replay guard** (`createReplayGuard`): a session-scoped single-use
ledger. `open` claims a requestId+nonce pair; `consume` spends it
exactly once. A second consume is `DUPLICATE_SETTLEMENT`; a nonce reused
by a different request is `REPLAY_DETECTED`; a settlement for a request
this session never issued is `RESPONSE_BINDING_MISMATCH`.

**What binding does and does not prove.** For a signer that natively
speaks v2, the envelope is the signer's own statement and the binding is
end-to-end. For a **lifted v1 adapter** (§7) the envelope is assembled by
the lift from the request plus a live `getActiveAccount` read, so the
digest echo is tautological and proves transport integrity only up to the
lift boundary. In BOTH cases the load-bearing detection of "the signer
signed a different transaction" is the transaction-identity
re-derivation, which reads the RETURNED bytes:

> `deriveTransactionId` is injected by the consumer (the core holds no
> transaction code). Kaspa txids EXCLUDE signature scripts, so a correctly
> signed transaction keeps the unsigned transaction's id; a different id
> means different consensus-visible bytes were signed → `PAYLOAD_MUTATED`,
> signature discarded. Without a deriver the outcome reports
> `txIdVerified: false` — never a verification that did not happen — and
> the SDK finalizer's `TXID_MISMATCH` refusal remains the authority.

---

## 7. Signing execution — gates, in order

`executeSigningV2(adapterOrRegistration, request, options)`.

Nothing reaches the signer until every pre-gate passes:

1. request re-validation (including payload-digest recomputation)
2. replay guard: claim requestId + nonce
3. **expiry** — a stale request never reaches a signer (`REQUEST_EXPIRED`)
4. **capability probe** — declaration vs observed reality (`CAPABILITY_MISMATCH`)
5. capability + scheme gates (`UNSUPPORTED_CAPABILITY` / `UNSUPPORTED_SCHEME`)
6. **sighash gate** — the signer must declare SIGHASH_ALL (`UNSUPPORTED_SIGHASH`)
7. **transaction-format gate** — exact pin (`UNSUPPORTED_TRANSACTION_FORMAT`)
8. **transport gate** — `allowedTransports` (`TRANSPORT_UNSUPPORTED`)
9. **user-presence gate** — `requireUserPresence` (`USER_PRESENCE_REQUIRED`)
10. **deadline gate** — async signers require an explicit `timeoutMs`; a
    `timeoutMs` above the signer's `maxTimeoutMs` is refused rather than
    waited out
11. network gate — declared AND live; null/unknown fails closed
12. identity gate — live active account === `expectedSignerAddress`

Then `SUBMITTED`, and a settlement race against **the earlier of** the
consumer's `timeoutMs` and the request's own `expiresAtMs`, plus an
optional cancellation token. Terminal handling:

| Outcome | State | Code | Behaviour |
| --- | --- | --- | --- |
| consumer cancelled | `CANCELLED` | `REQUEST_CANCELLED` | best-effort `cancelSigning`; late settlement discarded |
| request expired | `EXPIRED` | `REQUEST_EXPIRED` | same |
| deadline elapsed | `TIMED_OUT` | `SIGNER_TIMEOUT` | same |
| holder declined | `REJECTED` | `USER_REJECTED` | — |
| provider/validation fault | `FAILED` | (classified) | — |
| approved | `APPROVED` | — | envelope validated → guard consumed → txid re-derived → identity re-checked |

A cancellation failure never masks the terminal condition. **Exactly one
terminal transition is emitted per execution**, and no late provider
settlement can deliver a signature. Observer exceptions are isolated and
can never alter an outcome.

The approved result is frozen:

```
{ interfaceVersion, requestId, status: "approved", provider, transport,
  capabilitiesProbed, txIdVerified, transactionId, result }
```

`POLICYVAULT_TRANSACTION_REQUIREMENTS` is the canonical funds-path
negotiation set, exported as a frozen constant so no consumer has to
remember it and none can quietly relax it: `schnorr`,
`transactionSigning` + `specificInputSigning`, `sighash: ["all"]`,
`transactionFormat: "kaspa-safe-json/1"`.

---

## 8. Adapters and their capability matrices

All four pass the same gates: `validateAdapterV2`, registry registration,
negotiation, and the full `executeSigningV2` lifecycle.

| | KasWare (browser) | CLI keyfile (offline) | Air-gap shuttle (QR/file) | Mock (test) |
| --- | --- | --- | --- | --- |
| `kind` | `browser-extension` | `cli` | `air-gapped` | `mock` |
| `transport` | `in-page` | `cli` | `qr-airgap` / `file` | `in-page` |
| `schemes` | `schnorr` | `schnorr` | `schnorr` | configurable |
| `networks` | `mainnet`, `testnet-10` | the ONE configured network | the ONE configured network | configurable |
| `sighash` | `all` only | `all` only | `all` only | configurable |
| `transactionFormats` | `kaspa-safe-json/1` | `kaspa-safe-json/1` | `kaspa-safe-json/1` | configurable |
| `pskt` | **false** (§4) | **false** | **false** | configurable |
| `userPresence` | `required` (popup per signature) | **`not-required`** (running the process IS the approval) | `required` (a human shuttles the document) | configurable |
| `cancellation` | **`unsupported`** (no provider API) | `unsupported` (synchronous) | `supported` (abandon the shuttle) | derived |
| `asynchronousApproval` | false | false | **true** (explicit deadline mandatory) | configurable |
| `accountEvents` | true | false | false | true |
| `multiAccount` | false | false | false | configurable |
| Probe | live `window.kasware` method observation | kaspa-wasm module surface | **`probed: false` with a reason** | configurable |
| Cryptography | the extension's | **REAL kaspa-wasm BIP-340** | the offline CLI signer's | deterministic placeholders |
| Evidence label | **UNIT-TESTED against the documented API; NOT live-wallet-verified** | **UNIT-TESTED with REAL kaspa-wasm signing + verification** | **UNIT-TESTED (documents + gates); no camera, no share sheet, no real offline-signer process** | test fixture only |

### KasWare — `web/signer-kasware-adapter.js` + `core/signer/v2/adapters/kasware.js`

The existing v1 KasWare adapter is reused **object-for-object**; v2 is
reached through the lift (below). **No provider call changes**, and
`web/test/signer-kasware-v2.test.js` proves it by recording every
invocation on both paths and asserting byte-level equality of the
arguments — `signMessage(message, { type: "schnorr" })` and
`signPskt({ txJsonString, options: { signInputs: [{ index, sighashType }] } })`
are identical under v1 and v2.

The capability profile is DOM-free (it judges, it does not look — the same
split `mobile/www/js/portable/signer-capabilities.js` already uses); the
browser layer performs the one observation (which method names exist on
the injected object) and hands the list to the profile. A provider missing
`signPskt` therefore refuses a transaction request with
`CAPABILITY_MISMATCH` **before a popup opens** rather than failing after a
human clicked Sign.

### CLI keyfile signer — `core/signer/v2/adapters/cli.js`

The v1 adapter (`core/signer/adapters/cli/adapter.js`) is unchanged: real
BIP-340 Schnorr through the vendored rusty-kaspa kaspa-wasm module,
mode-600 keyfile custody, identity re-derivation, mainnet dual unlock.
`core/signer/adapters/cli/test/v2-conformance.test.js` drives REAL
signatures through the v2 pipeline, verifies the personal-message
signature with `kaspa.verifyMessage`, confirms the signed transaction
keeps its consensus id, and proves a cheating signer that returns bytes
for a *different* transaction is caught by id re-derivation.

Its `userPresence: "not-required"` is the honest declaration and a genuinely
useful one: a consumer that needs a human at the signer now refuses this
adapter structurally instead of assuming.

### Air-gap shuttle — `core/signer/v2/adapters/airgap.js`

A new TRANSPORT, not new cryptography and not a new document format
(`docs/postlaunch/mobile-architecture-decision.md` §4.1). The signer on
the other side is the existing offline CLI signer, driven through its OWN
frozen closed schemas — `policyvault-cli-signing-request/1`,
`policyvault-cli-signer-signed-transaction/1`,
`policyvault-cli-signer-signature/1` — and, for messages, the CLI's
`--message-file` input, which is the message's exact bytes. All I/O is
injected (`exchange`); this module never opens a camera, a file, or a
socket.

Its **capability limitations are exported and carried on the adapter**
(`adapter.limitations`, `AIRGAP_LIMITATIONS`) so a UI renders them
verbatim instead of a developer discovering them later:

- **L1 — no nonce crosses the gap.** The frozen CLI request schema carries
  no request id and no nonce, and a frozen schema is never mutated in
  place. The v2 nonce is a LOCAL single-use token; the `requestId` the CLI
  prints in its response is the OFFLINE SIGNER'S OWN id, unrelated to the
  request, so this adapter deliberately does not treat it as a binding.
  Fix: a new additive document version
  (`policyvault-cli-signing-request/3`) carrying the request id and nonce.
- **L2 — binding is by payload identity, not request identity.** Messages
  bind on `messageSha256` (which the CLI already emits) equalling the
  request's payload digest; transactions bind on the re-derived
  transaction id. Consequence: a genuine response to an earlier,
  byte-identical request is indistinguishable at this boundary. Every
  PolicyVault transaction spends specific UTXOs, so a replayed signature
  is for a transaction that is already accepted or already dead — but the
  adapter does not claim to detect it.
- **L3 — no pre-flight probe.** `probed: false` with a reason; a consumer
  requiring a probe refuses this adapter, which is the correct outcome.
- **L4 — no local signature verification.** Authority remains the server
  finalizer's frozen-txid re-derivation, its VM preflight, and consensus.

`mobile/test/signer-v2-airgap-compat.test.js` pins this adapter against
the shipped mobile portable layer: identical format ids, identical closed
key sets in identical order, a field-for-field identical request document,
and responses both modules accept or both refuse.

#### Defect found and fixed by that anti-drift suite

`mobile/www/js/portable/airgap.js` serialized its outgoing document with a
`JSON.stringify(doc, keys, 2)` **replacer ARRAY** of the closed key list. A
replacer array filters property names at EVERY nesting level, so the text
that actually crossed the gap carried `signInputs: [{}]` — and, in the `/2`
VERIFYING form, `manifest: {}` — while the in-memory document object looked
correct. The offline signer refuses such a document (fail closed, not fail
open), but the flow was broken and the `/2` form's independent offline
verification was inert on the wire.

Classification: **PRODUCTION CODE BUG**, same defect class as the
motivating KasWare incident recorded in `core/signer/interface.js` (a
reconstructed signing entry that dropped `sighashType`), and the same
lesson as the production-byte rule: the EMITTED BYTES must be driven
through the downstream validator, never only through a second in-process
rebuild. Fixed by serializing the document directly and ASSERTING its
closed key set and order instead of imposing them with a serializer trick;
regression-tested by reading the TEXT and feeding it to the offline
signer's own canonical signing-entry assertion.

### The v1→v2 lift — `core/signer/v2/adapters/lift.js`

`liftV1Adapter(v1Adapter, declarations)` keeps a reviewed v1 adapter
EXACTLY as it is (its provider calls are byte-exact reproductions of the
shipped flow; rewriting them would put those bytes back on the table) and
adds only what v2 introduces. The v1 half of the descriptor is carried
over verbatim after re-validation through v1; **every v2-only capability
must be declared explicitly** — a lift that guessed "probably SIGHASH_ALL"
would be the silent capability assumption v2 exists to abolish. Its honest
limitation is stated in §6 and in the module header.

---

## 9. Error taxonomy

v2's vocabulary is a strict superset of v1's, with **v1 meanings
preserved exactly** (pinned by `v2-conformance.test.js`). Additions:

| Code | Meaning | Why v1 could not express it |
| --- | --- | --- |
| `UNSUPPORTED_SIGHASH` | requested/declared/returned sighash is not one PolicyVault accepts | collapsed into `UNSUPPORTED_CAPABILITY`, losing the reason |
| `UNSUPPORTED_TRANSACTION_FORMAT` | the signer does not speak the pinned serialization | no format vocabulary existed |
| `TRANSPORT_UNSUPPORTED` | the adapter's transport is not one this consumer accepts | no transport vocabulary existed |
| `USER_PRESENCE_REQUIRED` | a human is required at the signer and this one is unattended | no presence vocabulary existed |
| `REQUEST_EXPIRED` | the REQUEST's own expiry elapsed (distinct from the consumer's deadline) | v1 requests never expired |
| `REQUEST_CANCELLED` | the CONSUMER revoked (distinct from `USER_REJECTED`, the holder declining) | only a timeout could end a wait |
| `RESPONSE_BINDING_MISMATCH` | the envelope is not bound to this request | responses were bare strings |
| `REPLAY_DETECTED` | a response/nonce was already consumed | undetectable without binding |
| `DUPLICATE_SETTLEMENT` | a second settlement for a terminal request | undetectable without binding |
| `PAYLOAD_MUTATED` | the signed bytes are not the verified bytes | undetectable without a digest/id check |
| `CAPABILITY_MISMATCH` | a probe contradicts a declaration | `describe` was trusted absolutely |

Fail-closed normalization is unchanged in spirit: a v2 error passes
through; a v1 `SignerError` is re-expressed with the same code; an
adapter-claimed KNOWN code is the sanctioned classification channel; an
UNKNOWN claimed code is a contract breach → `PROTOCOL_VIOLATION`;
anything else → `PROVIDER_ERROR` with the original preserved as `cause`.
Diagnostics carry NON-SECRET data only — shapes and digests, never key
material and never raw malformed payloads.

---

## 10. Hostile coverage

`core/signer/test/hostile-v2.test.js` (48 ADVERSARIAL cases) drives a
misbehaving signer, transport, or consumer and asserts a specific code:

| Block | Scenario | Codes |
| --- | --- | --- |
| H1 | wrong network — live, undeclared, null/unknown, and in the response | `WRONG_NETWORK` |
| H2 | wrong account — pre-gate, disconnected, and in the response | `ACCOUNT_CHANGED`, `SIGNER_DISCONNECTED` |
| H3 | account switched WHILE the signer held the request | `ACCOUNT_CHANGED` |
| H4 | transaction/message mutated after local verification | `PAYLOAD_MUTATED` |
| H5 | unsupported sighash — requested, declared, returned; wrong format | `UNSUPPORTED_SIGHASH`, `UNSUPPORTED_TRANSACTION_FORMAT` |
| H6 | malformed responses — bare string, bad signature, empty/oversized serialization, extra result keys, unknown envelope key, unparseable bytes | `RESPONSE_BINDING_MISMATCH`, `INVALID_SIGNATURE_RESPONSE`, `PROTOCOL_VIOLATION`, `PAYLOAD_MUTATED` |
| H7 | the signer signed a DIFFERENT transaction (txid drift; false txid claim; and the no-deriver case reporting `txIdVerified: false`) | `PAYLOAD_MUTATED`, `RESPONSE_BINDING_MISMATCH` |
| H8 | stale request — before invocation, during approval, late settlement discarded, expiry beating a longer timeout | `REQUEST_EXPIRED` |
| H9 | cancellation — holder declined, consumer cancelled, pre-cancelled, sabotaged `cancelSigning` | `USER_REJECTED`, `REQUEST_CANCELLED` |
| H10 | duplicate settlement — same request twice, double consume, settlement for an unissued request | `DUPLICATE_SETTLEMENT`, `RESPONSE_BINDING_MISMATCH` |
| H11 | transport replay — an old valid envelope at a new request, nonce reuse, wrong nonce, wrong kind | `RESPONSE_BINDING_MISMATCH`, `REPLAY_DETECTED` |
| H12 | a signer claiming capabilities it lacks — missing method, denied sighash, false PSKT support, false PSKT role, unprobeable under a probe requirement, unknown probe value, wrong-version probe, reasonless unprobed report | `CAPABILITY_MISMATCH`, `PROTOCOL_VIOLATION`, `INTERFACE_VERSION_UNSUPPORTED` |
| H13 | structural non-custody — a custody capability/field cannot even be declared | `PROTOCOL_VIOLATION` |

In every pre-invocation case the suite additionally asserts
`control.invocations === 0`: **no prompt may open for a request that
cannot be accepted.**

A production-code defect in v2 itself was found by this suite during
development and fixed: the deadline timer was `unref`'d, so a runtime
could exit while an out-of-band approval was outstanding. It is now
explicitly never `unref`'d (and always cleared).

---

## 11. Migration posture

v2 is **additive and currently inert for production**. `web/wallet.js`,
`web/app.js`, `web/app-v4.js`, `server/src/auth.js`, and the shipped
`createKasWareSessionAdapter` path are unchanged and remain on v1. The
browser bundle now carries BOTH cores (`web/tools/build-core-bundle.js`
module list, pinned by `web/test/core-bundle.test.js` and
`core/crossruntime/test/bundle-anti-drift.test.js`, mirrored to mobile by
`mobile/tools/sync-portable.js`), and v2 loads correctly inside the
Buffer-free browser context.

Migrating a production flow onto v2 is future work with its own gates —
it changes what a real wallet is asked for and when, so it needs
BROWSER-layer evidence and, for any live-wallet claim, an actual
extension. **This track produced none, and none is claimed.**

### Residuals

1. Wire a production consumer onto v2 (KasWare session adapter, hosted
   auth, the approver flow) — not attempted here.
2. Live-wallet verification of the KasWare v2 path (requires a real
   extension).
3. `policyvault-cli-signing-request/3` carrying the request id + nonce, to
   close air-gap limitations L1/L2.
4. Wire the v2 air-gap adapter into the mobile platform layer (camera /
   share-sheet transports remain platform stubs; the mobile roster and its
   honest UNAVAILABLE states are unchanged).
5. An ECDSA response contract, if and only if source-backed evidence of
   the exact byte format appears.
6. A PSKT wire contract, on the same condition.

---

## 12. `policyvault-org-root-slot-request/2` — the v0.7 organizational-root slot-signing flow over v2 (Wave 2, Track G)

Status: **IMPLEMENTED + UNIT-TESTED + ADVERSARIAL-TESTED**, with the CLI
keyfile path additionally **REAL-CRYPTO-TESTED** (real BIP-340 Schnorr
through the vendored kaspa-wasm module). NOT TESTNET-VERIFIED, NOT
PRODUCTION-HARDENED. This is a **domain**
consumer of v2 — it does not change anything in §1–§11 above, and it does
not touch the v1 `policyvault-org-root-slot-request/1` path described in
`core/signer/org-root-slot-v7.js`'s own header, which stays
byte-identical and frozen (pinned by
`core/signer/test/org-root-slot-v7.test.js`, still 10/10 unchanged).

**Residual #1 above is now PARTIALLY closed**: a v2 consumer exists — the
v0.7 organizational root's out-of-band M-of-N owner-slot signature
collection round. It is still not a *production* consumer (nothing in
`server/` or `web/` calls it yet; the org-roots server lane that will is a
parallel Wave 2 track), and it is a **NEW additive path**
(`policyvault-org-root-slot-request/2` / `.../response/2`), not a
migration of the existing v1 path — the v1 collection round remains
exactly as implemented and exactly as tested.

### 12.1 What v2 adds to the org-root slot flow, over v1

`core/signer/org-root-slot-v7.js` gains, additively:
`createRootSlotSigningRequestV2`, `assertRootSlotSigningRequestV2`,
`extractSlotSignatureFromSignedTransactionV2`,
`buildRootSlotSignatureResponseV2`, `verifyRootSlotSignatureResponseV2`,
`collectRootSlotApprovalsV2`, `createOrgRootSlotReplayGuardV2`,
`requestRootSlotSignatureV2`.

- **Capability PROBING before a request is issued.** Every call to
  `requestRootSlotSignatureV2` drives the request through
  `executeSigningV2`, whose gate 3 cross-checks the adapter's declared
  descriptor against what `probeCapabilities` actually observes —
  SIGHASH_ALL and the transaction format included — and refuses
  `CAPABILITY_MISMATCH` before any prompt opens. By default an
  unprobeable signer (`probed: false`) is ALSO refused
  (`requireProbedCapabilities: true` by default); the override exists,
  and is exercised, for adapters whose whole point is that they cannot be
  interrogated before a shuttle (the air-gap adapter, §8's L3).
- **User presence required by SAFE DEFAULT for every counted owner
  signature** (`requireUserPresence: true` by default in
  `requestRootSlotSignatureV2`). The override is real, tested, and used
  deliberately — never silently defaulted away — for adapters that are
  legitimately unattended by explicit operator choice: the CLI keyfile
  adapter declares `userPresence: "not-required"` because running the
  process IS the approval (§8), so the org-root-slot-v2 tests that drive
  it pass `requireUserPresence: false` explicitly, with the reason stated
  at the call site.
- **A wide `payloadSha256`.** The v2 request carries a digest over the
  EXACT unsigned transaction bytes AND the manifest hash AND the slot AND
  the root outpoint AND the request's own nonce
  (`computeSlotRequestDigestV2`), recomputed on every structural
  re-validation — a strictly wider, single-step binding than v1's
  per-field checks.
- **Bound response envelopes with a nonce echo.** The v2 response is a
  closed envelope (`SLOT_RESPONSE_V2_KEYS`) that must echo the request's
  `requestVersion`, `requestId`, and `nonce`. A v1 envelope presented on
  the v2 path (or a v2 envelope presented on the v1 path) is refused with
  `INTERFACE_VERSION_UNSUPPORTED` before any other field is read — proven
  by dedicated cross-presentation tests, not merely asserted.
- **A domain-level replay guard**, `createOrgRootSlotReplayGuardV2`,
  keyed on `(root covenant id, root STATE nonce, request id, slot)` —
  separate from and coarser than v2's own per-call requestId/nonce guard
  (which `executeSigningV2` already runs internally on every invocation).
  It catches a caller issuing two overlapping requests for the SAME slot
  of the SAME root generation, a case the per-call guard cannot see
  because each request legitimately mints its own fresh requestId/nonce.
- **Provenance carried on the response**: `capabilitiesProbed`,
  `txIdVerified`, `provider`, `transport` — copied verbatim from the
  `executeSigningV2` outcome that produced the response, never
  re-derived. `slotKeyClaimChecked` (the same local-provenance flag v1
  carries) is returned alongside the response but is NOT part of the
  closed response envelope — a caller that re-verifies a shuttled
  response destructures it out first (`const { slotKeyClaimChecked,
  ...response } = ...`), matching the SAME "local provenance, never
  proof" trust boundary the v1 header documents for that flag.

**What did NOT change.** The 65-byte/0x01 SIGHASH_ALL gate is checked by
the SAME `normalizeSlotSignatureHex` the v1 path calls; the frozen-byte
structural proof (TXID drift / foreign-input attribution) is the SAME
logic as `extractSlotSignatureFromSignedTransaction`, duplicated into
`extractSlotSignatureFromSignedTransactionV2` ONLY because the v1
function hard-validates its input through the v1 assert and the v1 path
must stay untouched; `collectRootSlotApprovalsV2` folds into the SAME
pinned `assembleOwnerSigsBlobV7` the v1 path uses, so a v2-collected blob
is **byte-identical** to a v1-collected one for the same approvals —
proven directly in `sdk/test/org-root-slot-signer-v2.test.js` by folding
the SAME two real signatures through both paths and comparing
`blobHex`.

### 12.2 Exercised through

| Signer | Evidence |
| --- | --- |
| Mock v2 adapter | `core/signer/test/org-root-slot-v2-hostile.test.js` (15 tests: a 24-row hostile table plus further hostile assertions in the other 14 — foreign slot key, duplicate slot, replay across request/root/nonce/network, expiry, cancellation, mutated payload, capability-probe mismatches, malformed signature lengths and sighash bytes, closed-envelope key-set violations, oversized fields, the user-presence override, v1↔v2 envelope cross-presentation) |
| CLI keyfile adapter | `sdk/test/org-root-slot-signer-v2.test.js` — **REAL kaspa-wasm BIP-340 Schnorr**, two independent offline signers, the PRODUCTION finalizer, and the v1/v2 byte-identical-blob proof |
| Air-gap shuttle | The same SDK suite: a REAL signature produced through the CLI v2 adapter is re-expressed as the offline CLI script's own closed response document and driven through `createAirGapSignerAdapter`'s TEXT-only `exchange` seam — the serialization round trip is proven over REAL bytes, not a mock's placeholder |
| KasWare / any browser wallet | **NOT exercised by this track.** Same limitation as §1/§8: no live extension was driven. Do not infer compatibility. |

### 12.3 Compatibility claim (stated precisely)

This track proves: (1) the org-root-slot-v2 envelope binding is correct
against a conformant mock adapter under hostile conditions; (2) a real
offline signer (the CLI keyfile adapter) can produce a genuine slot
signature through the v2 gates that the production finalizer accepts;
(3) that signature survives an air-gap-shaped text transport unchanged.
It does **not** prove, and does not claim: TESTNET-VERIFIED status (no
live testnet-10 round used this path — the org-root-slot **v1** path has
its own separate SDK real-signature test, also not yet run live), a
production wiring (no server or web caller exists yet), or compatibility
with any specific third-party wallet.
