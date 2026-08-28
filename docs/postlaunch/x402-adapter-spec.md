# PolicyVault x402 Interoperability Adapter — Design Specification (DRAFT)

**Claim label: DESIGNED.** Nothing in this document is IMPLEMENTED,
UNIT-TESTED, VM-VERIFIED, TESTNET-VERIFIED, or PRODUCTION-HARDENED. No
production file, migration, covenant byte, or configuration is changed by
this document. It covers `FULLSCALE_COMPLETION_ADDENDUM.md` surface **27
(x402 interoperability adapter)**.

Binding parents: `docs/postlaunch/FULLSCALE_COMPLETION_ADDENDUM.md`
(anti-bloat rule, security model, payment-interop conceptual flow,
adversarial matrix), `docs/postlaunch/COMPLETION_STANDARD.md`,
`CLAUDE.md` (numeric safety, network safety, pipeline discipline,
fail-closed versioning, progress-reporting labels, free-forever product
policy).

Sibling: `docs/postlaunch/ap2-adapter-spec.md` (surface 28). The two
adapters share §3's normalized-intent schema and §5's deployment
boundary; they are otherwise independent.

---

## 0. One-paragraph summary

x402 is an HTTP-native payment protocol: a resource server answers `402
Payment Required` with a machine-readable statement of what it will
accept, and the client retries the identical request carrying a signed
payment payload. The PolicyVault x402 adapter is a **thin, unprivileged,
separately-deployed translator** that turns an inbound
`PaymentRequirements` object into an ordinary closed PolicyVault
transaction intent, pushes it through the *exact same* authoritative
pipeline every other client uses (via the public Agent API with a scoped
machine credential), and — only after real chain proof — renders the
resulting Kaspa txid back as an x402 settlement payload. It holds no
keys, signs nothing, has no privileged path, and its complete absence
costs PolicyVault nothing but x402 translation.

---

## 1. Protocol summary (cited; exact shapes an adapter must handle)

### 1.1 Provenance and governance

x402 originated at Coinbase (`github.com/coinbase/x402`) and is now
maintained under the **x402 Foundation** organization
(`github.com/x402-foundation/x402`); both repository paths currently
resolve to the same protocol content
([coinbase/x402](https://github.com/coinbase/x402),
[x402-foundation/x402](https://github.com/x402-foundation/x402)).
Documentation is at [docs.x402.org](https://docs.x402.org/faq).

### 1.2 Versions (the adapter's fail-closed version gate)

Two wire generations exist and they are **not field-compatible**:

| | v1 | v2 |
|---|---|---|
| `x402Version` value | `1` | `2` |
| Amount field | `maxAmountRequired` | `amount` |
| Network id | chain slug, e.g. `"base-sepolia"` | CAIP-2, e.g. `"eip155:8453"` |
| Resource fields | flat `resource`, `description`, `mimeType`, `outputSchema` on each requirement | separated `ResourceInfo` object |
| Extensions | — | `extensions` object |
| Client→server header | `X-PAYMENT` | `PAYMENT-SIGNATURE` |
| Server→client (requirements) | 402 body | `PAYMENT-REQUIRED` header (+ body) |
| Server→client (settlement) | `X-PAYMENT-RESPONSE` | `PAYMENT-RESPONSE` |

Sources: v2 spec
([specs/x402-specification-v2.md](https://github.com/coinbase/x402/blob/main/specs/x402-specification-v2.md)),
v2 HTTP transport
([specs/transports-v2/http.md](https://github.com/coinbase/x402/blob/main/specs/transports-v2/http.md),
[docs.x402.org/core-concepts/http-402](https://docs.x402.org/core-concepts/http-402)),
v1 spec
([specs/x402-specification.md](https://github.com/coinbase/x402/blob/main/specs/x402-specification.md)).
The v2 changelog states the delta as *"Protocol v2: CAIP-2 networks,
restructured PaymentPayload/Required, ResourceInfo separation, extensions
support."*

**Adapter rule:** `x402Version` is matched against an explicit supported
set. v2 is the design target. An unknown or absent `x402Version` refuses
with `X402_VERSION_UNSUPPORTED` **before any structural assumption is
applied** — never routed to a default (CLAUDE.md fail-closed versioning).
Whether v1 is supported at all is a deployment decision (§10 OQ-1); if
supported it MUST be a separate, explicitly-coded normalizer, never a
"best effort" reinterpretation of v2 field names.

### 1.3 `PaymentRequired` (server → client, on HTTP 402)

Per the v2 spec, base64-encoded JSON carried in the `PAYMENT-REQUIRED`
header (all three x402 v2 headers carry base64-encoded JSON):

```
PaymentRequired {
  x402Version : number   (required)
  error       : string   (optional)  // human-readable explanation
  resource    : ResourceInfo (required)
  accepts     : PaymentRequirements[] (required)
  extensions  : object   (optional)
}

ResourceInfo {
  url         : string (required)
  description : string (optional)
  mimeType    : string (optional)
}

PaymentRequirements {
  scheme            : string (required)   // e.g. "exact"
  network           : string (required)   // CAIP-2 "{namespace}:{reference}"
  amount            : string (required)   // atomic token units, as a STRING
  asset             : string (required)   // token contract address or ISO 4217 code
  payTo             : string (required)   // recipient address or role constant
  maxTimeoutSeconds : number (required)
  extra             : object (optional)   // scheme-specific
}
```

### 1.4 `PaymentPayload` (client → server, in `PAYMENT-SIGNATURE`)

```
PaymentPayload {
  x402Version : number (required)
  resource    : ResourceInfo (optional)
  accepted    : PaymentRequirements (required)  // the selected requirement, echoed
  payload     : object (required)               // SCHEME-SPECIFIC payment data
  extensions  : object (optional)
}
```

For the EVM `exact` scheme, `payload` is `{ signature, authorization {
from, to, value, validAfter, validBefore, nonce } }` — an **EIP-3009
"transfer with authorization"** delegated pull. This shape is
chain-specific; it is *not* what a Kaspa scheme would carry (§6).

### 1.5 `SettlementResponse` (server → client, in `PAYMENT-RESPONSE`)

```
SettlementResponse {
  success     : boolean (required)
  errorReason : string  (optional; present only when unsuccessful)
  payer       : string  (optional)
  transaction : string  (required)   // blockchain transaction hash
  network     : string  (required)   // CAIP-2
  amount      : string  (optional)   // actual settled amount
  extensions  : object  (optional)
}
```

### 1.6 Facilitator role and endpoints

A **facilitator** is an optional third party that performs verification
and/or settlement on the resource server's behalf. The resource server
may verify locally or `POST` `{ x402Version, paymentPayload,
paymentRequirements }` to the facilitator's `/verify`, and settle via the
identically-shaped `/settle`.

```
POST /verify  → VerifyResponse { isValid: boolean, invalidReason?: string, payer?: string }
POST /settle  → SettlementResponse (§1.5)
GET  /supported → { kinds: [{ x402Version, scheme, network, extra? }],
                    extensions: [ids], signers: { <CAIP-2 pattern>: <address> } }
```

### 1.7 HTTP flow (v2 transport)

1. Client requests the resource.
2. Server answers `402` with the `PAYMENT-REQUIRED` header.
3. Client **resubmits the original request intact**, adding
   `PAYMENT-SIGNATURE`.
4. Server answers `200` + `PAYMENT-RESPONSE` (success) or `402` +
   `PAYMENT-RESPONSE` carrying `errorReason` (failure). The transport
   spec states *"all x402 protocol information is communicated through
   headers"* rather than response bodies.

### 1.8 `exact` scheme, and the two payment flows

The generic `exact` scheme transfers a predetermined amount known to the
server in advance
([specs/schemes/exact/scheme_exact.md](https://github.com/x402-foundation/x402/blob/main/specs/schemes/exact/scheme_exact.md)).
It defines two flows:

- **Authorization flow (default):** `verify → resource → settle`. The
  client hands the server a *pre-signed authorization the server later
  settles*.
- **Upfront flow (optional):** `settle → resource → respond`, "used when
  on-chain finality is required before execution". When used,
  `accepts[].extra.paymentFlow` MUST be `"upfront"`.

Normative requirements the scheme states: *"The transferred amount MUST
equal `maxAmountRequired`"*, *"`amount` MUST equal `requirements.amount`
exactly"*, and *"the receiver MUST match the `payTo` derived destination
for the specified `asset`."*

### 1.9 Extensions

Servers advertise supported extensions in `PaymentRequired`; clients echo
them in `PaymentPayload`. The spec constrains the client: *"The client
must include at least the info received; it may append additional info
but cannot delete or overwrite existing info."* Each extension entry is
`{ info, schema }`.

### 1.10 What x402 does NOT specify (do not invent it)

- **No protocol-level payment identifier / idempotency key.** Replay
  protection is delegated to the chain-specific scheme (EVM: the EIP-3009
  32-byte nonce, enforced by the token contract; plus `validAfter` /
  `validBefore`). The v2 spec gives **no idempotency guidance for
  `/settle` retries**. → §3.4 derives PolicyVault's own key.
- **No specified behaviour if settlement fails after the resource was
  served.** (Not addressed in the sources reviewed.)
- **No centralized scheme/network registry.** Extension happens by PR
  (§6.2).

---

## 2. Roles: which x402 role PolicyVault plays (and which it never does)

| x402 role | PolicyVault | Rationale |
|---|---|---|
| **Client / payer** | **IN SCOPE — the only role** | An AI agent with a PolicyVault-delegated agent key pays for a resource, under covenant-enforced caps, budgets, recipient allowlists and approval tiers. This is exactly the product. |
| Resource server / seller | **OUT OF SCOPE, permanently** | PolicyVault is **free forever, including commercial use**; it never charges for its protocol, covenant, SDK, API, security features, or ordinary usage (CLAUDE.md product policy). PolicyVault must never emit a `402` for its own API. |
| Facilitator | **OUT OF SCOPE** | A facilitator verifies and settles *on someone else's behalf* — an intermediary/custodial posture PolicyVault does not take ("No master keys, no admin bypass, no custodial recovery"). |

**Note on receiving:** a PolicyVault user who runs a paid service and
wants x402 payments *into* a vault needs no adapter — receiving KAS is an
address, not a covenant spend. Nothing in this spec is required for that.

---

## 3. Trust classification and closed-schema normalization

### 3.1 The classification rule

> Every byte that arrives over x402 is **UNTRUSTED**, without exception.
> A field is either (a) a **PROPOSAL** that is normalized into the closed
> PolicyVault intent schema and then subjected in full to policy,
> governance, risk, local deterministic verification, and finally the
> covenant; or (b) **AUDIT-ONLY METADATA** that is length-capped,
> recorded verbatim for correlation, and read by *nothing* in the
> decision path.

There is no third category. A field that is neither explicitly a
proposal nor explicitly audit-only causes the adapter to **refuse** —
unknown keys are not tolerated (`X402_SCHEMA_UNKNOWN_FIELD`), because a
hidden field is a hidden effect (intent-manifest-spec §3).

Restating the addendum's security model at this boundary: **the resource
server MAY REQUEST. POLICYVAULT DETERMINISTICALLY DECIDES. THE COVENANT
ENFORCES FINANCIAL AUTHORITY. THE SIGNER RETAINS CUSTODY.** A valid,
well-formed, correctly-served `PaymentRequirements` is a *request for
money*, and carries precisely zero authority to move any.

### 3.2 Field-by-field table

| Field | Class | Normalization / rule | Refusal code |
|---|---|---|---|
| `x402Version` | **PROPOSAL (gate)** | exact member of the supported set; checked first | `X402_VERSION_UNSUPPORTED` |
| `accepts[i].scheme` | **PROPOSAL (gate)** | exact member of the supported scheme set for this deployment (§6). Unknown ⇒ refuse; never a default | `X402_SCHEME_UNSUPPORTED` |
| `accepts[i].network` | **PROPOSAL (gate)** | must equal the *configured* Kaspa network's identifier AND the Agent API's reported `networkId` (`GET /network/status`). Cross-network ⇒ refuse. **Never silently switch network** (CLAUDE.md) | `X402_NETWORK_MISMATCH` |
| `accepts[i].asset` | **PROPOSAL (gate)** | must be the Kaspa-scheme native-KAS asset identifier. PolicyVault v0.4 covenants move native KAS only; any token/contract/ISO-4217 value ⇒ refuse | `X402_ASSET_UNSUPPORTED` |
| `accepts[i].amount` (v2) / `maxAmountRequired` (v1) | **PROPOSAL → `payAmountSompi`** | §3.3 | `X402_AMOUNT_INVALID` |
| `accepts[i].payTo` | **PROPOSAL → `recipient`** | §3.3. Must resolve to a valid Kaspa address for the configured network AND be an *already-allowlisted* recipient of the acting agent. Never a "role constant" | `X402_DESTINATION_INVALID` / `X402_DESTINATION_NOT_ALLOWLISTED` |
| `accepts[i].maxTimeoutSeconds` | **PROPOSAL → adapter deadline only** | §3.3. Bounds the adapter's own wall-clock deadline. **NEVER** enters `lockTime`, CLTV, fee, period arithmetic, or any covenant field | `X402_TIMEOUT_INVALID` |
| `accepts[i].extra.paymentFlow` | **PROPOSAL (gate)** | MUST be `"upfront"` for the Kaspa scheme (§6.3). Absent / `"authorization"` ⇒ refuse | `X402_FLOW_UNSUPPORTED` |
| `accepts[i].extra.*` (other) | **AUDIT-ONLY** unless explicitly named by the Kaspa scheme spec | opaque; size-capped; recorded verbatim | `X402_EXTRA_TOO_LARGE` |
| `resource.url` | **AUDIT-ONLY** | absolute `https:` URI, ≤ 2048 bytes, recorded verbatim. Also used to construct the retry request — but a URL is a *routing* fact, never a financial one | `X402_RESOURCE_INVALID` |
| `resource.description`, `resource.mimeType`, `error` | **AUDIT-ONLY** | length-capped (≤ 1024 / ≤ 255 / ≤ 1024 bytes), stored as opaque strings. **Never** rendered as an authorization statement, never shown to a human as if PolicyVault vouched for it, never parsed for amounts | `X402_METADATA_TOO_LARGE` |
| `extensions` | **AUDIT-ONLY (echo-required)** | recorded verbatim; echoed back in `PaymentPayload` to satisfy §1.9. The intent normalizer never reads it. Unknown extension ids are recorded and **not acted on** | `X402_EXTENSIONS_TOO_LARGE` |
| Any other key, at any depth | — | **refuse** | `X402_SCHEMA_UNKNOWN_FIELD` |

**Multiple `accepts[]` entries.** The adapter selects at most ONE. Selection
is deterministic and PolicyVault-side: filter to entries passing every
gate above, then pick the lexicographically-first surviving entry by
`(amount ascending as BigInt, scheme, network, payTo)`. If zero survive,
refuse — never "pick the closest". The selected entry is echoed verbatim
in `accepted` and hashed into the requirement digest (§3.4).

### 3.3 Closed normalization rules (types, ranges, integer discipline)

The output of normalization is a `policyvault-requested-intent/1`
document (intent-manifest-spec §6.2) with `action: "agentSpend"` — the
*same* closed schema the web client and CLI produce. There is no x402
variant of it.

**Amount.**
- Input MUST be a JSON **string**. A JSON *number* is refused outright —
  `X402_AMOUNT_NOT_STRING`. (No float ever touches a consensus value;
  CLAUDE.md numeric safety.)
- MUST match `^(0|[1-9][0-9]*)$` — ASCII digits, no sign, no decimal
  point, no exponent, no whitespace, no leading zeros. This is the
  intent-manifest canonical encoding, which is deliberately *stricter*
  than `core/model/amounts.js parseSompi` (which tolerates leading
  zeros): one value must have exactly one encoding, because the manifest
  hash is a function of encodings.
- Parsed with `BigInt`. MUST be `> 0` (an `agentSpend` requires
  `payAmountSompi > 0`) and `≤ MAX_SOMPI` (`29_000_000_000n *
  100_000_000n`, `core/model/amounts.js`).
- **Atomic-unit binding:** for the Kaspa scheme, one atomic unit is one
  **sompi**, so the mapping is the identity — `payAmountSompi =
  amount`. This MUST be stated normatively in the Kaspa scheme spec
  (§6). The adapter performs **no unit conversion, no decimal parsing,
  no rounding, and no currency conversion**, ever. If a future scheme
  variant expressed KAS rather than sompi, that is a *different scheme
  identifier* with its own normalizer — never a runtime multiply.
- Rejected explicitly: `NaN`, `Infinity`, `-0`, negatives, `1e8`,
  `"1.0"`, `"0x64"`, `" 100"`, `"100 "`, `"０"` (non-ASCII digits),
  values exceeding `MAX_SOMPI`, and unsafe-integer JS numbers.

**Destination.**
- `payTo` MUST be a syntactically valid Kaspa bech32 address whose
  **network prefix matches the configured network exactly**
  (`kaspa:` for mainnet, `kaspatest:` for testnet-10). A prefix mismatch
  is a hard refusal, not a normalization.
- It MUST decode to a P2PK x-only public key (32 bytes); the canonical
  internal identity is the **x-only key, never the address string**
  (intent-manifest-spec §6.3 `actor`/`payment`). P2SH / other script
  types refuse — v0.4 `agentSpend` pays a P2PK output
  (`20 <32-byte key> ac`).
- **The adapter never accepts a raw pubkey, a "role constant", a
  resolvable name, or a redirect.** x402 permits `payTo` to be a "role
  constant"; PolicyVault refuses every non-literal-address form
  (`X402_DESTINATION_NOT_LITERAL`) — indirection is a destination-
  substitution vector.
- The resulting x-only key MUST already be a member of the acting
  agent's recipient allowlist and provable against the leaf's
  `agentRecipientRoot`. **The adapter never adds a recipient.** Adding
  a recipient is a governance-classified `AGENT_RECIPIENT_ADDED`
  EXPANSION (governance-spec §5.1) requiring the owner's wallet
  signature — structurally unreachable from an adapter credential (§4.2).

**Deadline.**
- `maxTimeoutSeconds` MUST be a JS safe integer in `1..3600`. The adapter
  computes `deadline = adapterReceiveTime + min(maxTimeoutSeconds,
  configuredCeiling)`. Purpose: decide when to abandon the attempt and
  when a `PaymentRequirements` is stale. It has **no covenant effect**.
- If the deadline elapses before chain proof, the adapter reports
  `X402_DEADLINE_ELAPSED` to its caller **without cancelling anything** —
  a broadcast Kaspa transaction is not cancellable, and reconciliation
  remains the only truth (§7.3).

**Everything else.** Total decoded `PAYMENT-REQUIRED` header size is
capped (recommended 16 KiB) before JSON parsing; JSON nesting depth is
capped (recommended 8); duplicate object keys refuse. Byte caps are
applied to the *encoded* header first so an oversized payload is rejected
without ever being parsed.

### 3.4 Idempotency-key derivation (a protocol retry must never duplicate a spend)

x402 provides **no payment identifier** (§1.10), so the adapter derives
one and requires its caller to supply the disambiguator.

```
requirementDigest = sha256_hex(
    "policyvault-x402-requirement-digest/1\n" +
    canonicalJsonStringify({ x402Version, resource, accepted }) )

idempotencyKey   = "pvx402-" + sha256_hex(
    "policyvault-x402-idempotency/1\n" +
    canonicalJsonStringify({ attemptId, requirementDigest, vaultId, agentPk }) )
```

- `canonicalJsonStringify` is `core/intent/canonical.js` — key-sorted,
  representation-independent. **Mandatory**, per the standing G-2 rule:
  any new integrity commitment must be key-order-independent, because
  PostgreSQL `jsonb` reorders keys and a key-order-sensitive preimage
  "mutates" across a storage round-trip with every value byte intact.
- The domain prefixes keep these digests permanently disjoint from every
  other `sha256(canonical-json)` commitment in the codebase (manifest
  hashes, approval-package commitments, governance digests, state IDs).
- `attemptId` is a **caller-supplied UUID** identifying one logical
  purchase. It is **mandatory**: the adapter refuses
  (`X402_ATTEMPT_ID_REQUIRED`) rather than minting one, because a
  self-minted id would make every network-level retry a *fresh spend*.
- Consequence, and it is the correct one: replaying the same `attemptId`
  against the **same** requirement digest replays the original response
  verbatim (platform idempotency §2 `COMPLETE` branch); replaying it
  against a **different** requirement digest is a deterministic `409
  IDEMPOTENCY_KEY_CONFLICT` and the build handler is never called. A
  resource server that mutates its price on the retry therefore cannot
  extract a second, larger payment.
- The key is sent as the `Idempotency-Key` header on the Agent API build
  call. Platform keys are already scoped per authenticated identity
  (`machine:<identityId>`), so two adapters/tenants can never collide or
  replay each other's keys.

**Kaspa's structural double-spend answer.** Beyond the key: each v0.4
vault transition consumes the single covenant UTXO named by the frozen
transaction's input 0. A duplicate broadcast is either the *same txid*
(idempotent at the node) or a transaction whose predecessor outpoint is
already consumed (rejected by consensus). This is a stronger guarantee
than x402's EIP-3009 nonce and should be stated as such in the Kaspa
scheme spec — but the adapter still derives the key, because
double-*building* wastes the agent's budget window and produces
misleading audit history.

---

## 4. Mapped flow onto the PolicyVault pipeline

### 4.1 The flow

Per the addendum's payment-interop conceptual flow, mapped onto real
surfaces:

```
 402 + PAYMENT-REQUIRED
        │
 [A] decode + closed-schema normalize (§3)                    ← adapter, pure
        │
 [B] POST /api/v1/wallet/v4/simulate            (dry run)     ← Agent API
        │   governance · risk · planV4 · assertSignerAuthorizedV4
        │   · buildV4Transaction · deriveAndVerify — persists NOTHING
        ├─ simulation.ok:false ⇒ REFUSE now, nothing built, no gate consumed
        │
 [C] POST /api/v1/wallet/v4/requests + Idempotency-Key         ← Agent API
        │   the real durable build; intent manifest derived + verified
        │   fail-closed; governance/risk gates really consumed
        ├─ RISK_REVIEW_REQUIRED / approvals required ⇒ PENDING (§4.5)
        │
 [D] external signer over frozen bytes           ← Universal Signer Interface
        │   NOT the adapter. Browser-local / CLI reference signer
        │   independently re-verifies the manifest before signing.
        │
 [E] POST .../signature   then   POST .../submit               ← Agent API
        │   builders never broadcast; finalizers never mark chain state
        │
 [F] chain proof: proveExpectedEffectV4 → receipt → reconcile  ← existing
        │   txid verified · predecessor consumed · successor observed
        │   · durable receipt persisted
        │
 [G] SettlementResponse + PaymentPayload → retry original request
            with PAYMENT-SIGNATURE                             ← adapter
```

Stages **A** and **G** are the entire adapter. **B–F are untouched
existing surfaces**, reached over the same public HTTP API a Python
client or an MCP server would use. This is the anti-bloat rule made
structural: the adapter has no in-process handle to `buildV4Transaction`,
`sdk/src/store.js`, the signer, or the node.

### 4.2 Machine identity and scopes

The adapter authenticates as a **machine identity**
(`server/src/machine-identity.js`), created by the vault-owning wallet
session, bearing a `pvmk_`-prefixed credential whose SHA-256 alone is
persisted. Because a resolved machine principal presents `xOnlyPubkey =
creatorXOnly`, every existing tenancy check applies unmodified: the
adapter can see and attempt exactly what its creating wallet could, and
scopes narrow that further.

**Required scopes (the complete set — grant no more):**

| Scope | Why |
|---|---|
| `read:network` | verify `networkId` + sync before anything (CLAUDE.md network safety) |
| `read:vaults` | resolve vault state, agent leaf, allowlist membership |
| `read:requests` | poll a pending request's state |
| `read:manifests` | fetch the manifest for audit correlation |
| `request:build` | `POST /wallet/v4/simulate` and `POST /wallet/v4/requests` |
| `request:submit` | broadcast a fully-signed request (§4.4 note) |

**Scopes the adapter credential MUST NEVER carry** — this is the
structural, testable form of "cannot bypass":

| Forbidden scope | What it would let the adapter do |
|---|---|
| `risk:release` | release its **own** risk REVIEW hold — self-approval |
| `governance:propose` / `:approve` / `:cancel` | manufacture or approve an authority-expanding policy change |
| `request:break-glass` | attempt `ownerPause` / `ownerRecover`, which bypass governance and risk by design |
| `organizations:manage` | rewrite the org metadata plane the risk config lives in |
| `vaults:reconcile` | trigger reconciliation — the sole writer of chain truth |
| `request:reject` | cancel a human's pending decision |
| `read:audit`, `read:governance`, `read:risk`, `read:organizations` | not needed; deny by default |

Additionally, `/identities*` and `/wallet/dev-accounts` + `/wallet/dev-sign`
are **structurally unreachable by any machine credential regardless of
scope** (a wallet-session check, not a scope) — a token can never mint,
widen, or revoke its own or a sibling's authority.

A conformance test MUST assert the adapter's minted credential carries
*exactly* the six scopes above and that each forbidden route answers
`403 SCOPE_FORBIDDEN`.

### 4.3 Dry-run use (mandatory, not optional)

The adapter **always** calls `POST /api/v1/wallet/v4/simulate` before
`POST /wallet/v4/requests`. Simulation runs the identical pipeline —
`classifyActionV4`, `evaluateRisk`, `planV4`,
`assertSignerAuthorizedV4`, the real `buildV4Transaction` (real silverc,
real call-encoder subprocess), and the real `deriveAndVerify` — while
persisting nothing and consuming no gate.

Why mandatory here specifically:

1. It converts most refusals into a *free* refusal that never consumes an
   idempotency key, never creates a durable request, never consumes a
   governance proposal, and never writes a risk evaluation.
2. It returns `wouldRequire { approvals, proposal, riskRelease }`, which
   is exactly what the adapter needs to decide whether an x402 payment
   can possibly complete inside `maxTimeoutSeconds`, before spending the
   resource server's patience.
3. It returns the exact `fee` and `review` block, which the adapter
   compares against `maxAmountRequired`/`amount` semantics — the x402
   `exact` rule is that the transferred amount MUST equal the required
   amount; PolicyVault's fee is paid from the vault's covenant fee
   reserve, not deducted from the payment output, so the payment output
   equals `amount` exactly. This equality MUST be asserted from the
   simulated `review.payment`, not assumed.

Honest limitation to carry through to the adapter's own docs:
simulation deliberately **skips VM preflight** (`vmPreflight: { skipped:
true }`), because real preflight validates a Schnorr signature over the
frozen transaction and a dry run has none. Fee/mass/successor correctness
are exact; signature verification is not exercised. The adapter must
never report a successful simulation as "payment verified".

### 4.4 Signing — the adapter's hardest boundary

`request:sign` gates `POST .../signature`, which *submits a signature
produced elsewhere*. Two deployment shapes exist:

- **RECOMMENDED — separate signer credential.** The USI reference signer
  (offline/CLI) holds the agent key, polls or is handed the request id,
  independently re-verifies the intent manifest, signs the frozen bytes,
  and posts its **own** signature under its **own** machine credential
  holding `request:sign` only. The adapter never sees a signature and
  never holds `request:sign`. Two credentials, two blast radii.
- **PERMITTED — adapter as courier.** The adapter additionally holds
  `request:sign` and relays a signature it received from the signer over
  a separate channel. This is weaker (a compromised adapter can withhold
  or reorder signatures — it still cannot forge one) and MUST be a
  documented deployment choice, never the default.

In **both** shapes the adapter **never holds a private key, never
computes a signature, and never runs a signer**. Where the acting agent
is fully autonomous, the key custody question is the *signer's* problem
and is governed by `signer-interface-spec.md`, not by this document.

### 4.5 How refusals surface as protocol-correct responses

Because PolicyVault occupies the **client/payer** role (§2), an
"x402-correct response" means: *what the adapter does about the
outstanding 402, and what it reports to its own caller*. The adapter's
caller is the AI agent that asked it to pay; the resource server sees
only the presence or absence of a `PAYMENT-SIGNATURE` retry.

| PolicyVault outcome | Adapter behaviour toward the resource server | Report to the caller |
|---|---|---|
| Normalization refusal (§3) | **No retry.** The 402 stands unpaid | `refused`, `stage: "normalize"`, machine code, deterministic explanation |
| Simulation `ok:false` — unauthorized signer, over-budget, unknown action | **No retry** | `refused`, `stage: "simulate"`, `refusalReason { status, code, message }` verbatim from the API |
| Policy/covenant DENY | **No retry** | `refused`, `stage: "policy"` — final; the risk verdict is not even consulted on a policy DENY (`applyRiskToPolicyDecision`) |
| Risk `DENY` | **No retry** | `refused`, `stage: "risk"`, with the composed `codes[]` |
| Risk `REVIEW` hold | **No retry yet.** Requirement is likely to expire | `pending`, `requires: ["riskRelease"]`, `requestId`, `manifestHash`, `evaluationId`. A human releases; the caller re-drives the **same `attemptId`** |
| Covenant M-of-N approval required (`aboveThreshold`) | **No retry yet** | `pending`, `requires: ["approvals"]`, `requiredM`, `requestId`. Not a defect — the amount exceeded the agent's `approvalThreshold`, and that tier is a covenant rule an adapter cannot lower |
| Governance proposal required | **No retry yet** | `pending`, `requires: ["proposal"]` — in practice unreachable for `agentSpend`; reported honestly if it ever occurs |
| Adapter deadline elapsed | **No retry** | `expired`, `X402_DEADLINE_ELAPSED`; caller must obtain a **fresh** 402 (§7.3) |
| Node rejection / submit failure | **No retry** | `failed`, with the node's refusal; the transition claim lifecycle handles recovery |
| **CHAIN_VERIFIED** | **Retry the original request with `PAYMENT-SIGNATURE`** (§4.6) | `settled` + settlement evidence (§4.7) |

Two rules that hold in every row:

1. **The adapter never emits a `PAYMENT-SIGNATURE` for a payment that is
   not chain-proven.** There is no optimistic path.
2. **The adapter never retries a 402 more than once per `attemptId` per
   requirement digest.** A resource server cannot induce a payment loop
   by answering `402` again after settlement — that outcome is reported
   as `X402_SERVER_REFUSED_AFTER_SETTLEMENT` and escalated to a human,
   because it means PolicyVault paid and did not receive (§7.4, OQ-4).

Every refusal carries a deterministic machine code plus the
`core/explain` human-readable explanation — the G-1 lesson (a refusal
nobody can read is an availability bug).

### 4.6 The settlement payload (what goes into `PAYMENT-SIGNATURE`)

```
PaymentPayload {
  x402Version : 2,
  resource    : <ResourceInfo echoed verbatim>,
  accepted    : <the selected PaymentRequirements, echoed BYTE-VERBATIM>,
  payload     : {                       // Kaspa-scheme shape, §6.3
                  transactionId : <64-hex Kaspa txid>,
                  payer         : <vault covenant address>,   // OQ-3
                  amount        : <sompi, canonical digit string>,
                  daaScore      : <accepting DAA score, digits>  // OQ-2
                },
  extensions  : <echoed verbatim per §1.9>
}
```

`accepted` is echoed byte-verbatim from the requirement the adapter
digested — not re-serialized from parsed values — so the resource
server's own comparison cannot be defeated by a re-encoding difference,
and the requirement digest stays reproducible.

### 4.7 Settlement evidence → protocol receipt

PolicyVault's success definition is unchanged and stricter than x402's:
`submitTransaction()` returning is **not** success. Success requires txid
verified, old state consumed, expected successor observed, and a durable
receipt persisted (CLAUDE.md). Only then:

| Evidence | Source (real) |
|---|---|
| `txId` | `receipts[txId]` key; frozen v1 txid = broadcast txid |
| `successorOutpoint`, `value` | `receipts.value.proof.successorOutpoint`, `.value` |
| `feeSompi` | `receipts.value.proof.actualFeeSompi` |
| `successorStateId` | `wallet_requests.value.successorStateId`; `vaults.live.stateId` after reconcile |
| `manifestHash` + verdict | `intent_manifests[manifestHash].verification` |
| `acceptingDaaScore` | **not currently persisted — OQ-2** |

**OQ-2 (DAA score), stated precisely.** `policyvault-receipt/v1`
(`proof {requestId, successorOutpoint, value, requiredFeeSompi,
actualFeeSompi, covenantId?}`) and the v4 manifest's `live
{outpoint, stateId, state, outpointValue, scriptSha256, covenantId}`
carry **no DAA score**. `blockDaaScore` *is* available on UTXO entries at
proof time (`sdk/src/wallet-submit-v4.js:134` reads
`input.utxo.blockDaaScore`). Emitting a DAA score in an x402 settlement
payload therefore requires one of: (a) an **additive** field on the
receipt schema written at `proveExpectedEffectV4` time; (b) an additive
`live.blockDaaScore` on the vault manifest, written by reconciliation;
or (c) the adapter omits `daaScore` entirely. **The adapter MUST NOT
query the node itself to synthesize one** — that would make the adapter a
second source of chain truth, which the anti-bloat rule forbids. Until
(a) or (b) lands as a separately reviewed change, the design is (c).

### 4.8 Audit-correlation record shape

The adapter contributes ONE additive record per attempt. Following
`audit-correlation-spec.md` §5: a new create-only table, correlation
fields lifted to indexed columns, raw protocol metadata preserved
verbatim, no secrets.

```
{
  schema:        "policyvault-x402-attempt/v1",
  attemptId:     <uuid>,                    -- row key (per network)
  idempotencyKey:<"pvx402-" + 64-hex>,
  requirementDigest: <64-hex>,

  -- correlation spine (audit-correlation-spec §3)
  requestId:     <uuid> | null,
  manifestHash:  <64-hex> | null,
  txId:          <64-hex> | null,
  vaultId:       <64-hex>,
  networkId:     <string>,
  agentPk:       <64-hex>,
  actorXOnly:    <64-hex>,                  -- the machine identity's creatorXOnly

  -- the normalized proposal (what PolicyVault actually decided on)
  normalized: {
    payAmountSompi: <canonical digits>,
    recipientXOnly: <64-hex>,
    deadlineEpochSeconds: <integer>
  },

  -- RAW PROTOCOL METADATA, preserved verbatim, read by nothing
  protocol: {
    protocol:     "x402",
    x402Version:  <number>,
    selectedIndex:<integer>,                -- index into accepts[]
    paymentRequiredRaw: <the decoded PaymentRequired JSON, size-capped>,
    settlementResponseRaw: <decoded PAYMENT-RESPONSE JSON> | null
  },

  outcome: {
    status: "REFUSED"|"PENDING"|"EXPIRED"|"FAILED"|"SETTLED",
    stage:  "normalize"|"simulate"|"build"|"sign"|"submit"|"prove"|"deliver",
    codes:  [ <UPPER_SNAKE machine codes> ],
    at:     <ISO timestamp>                 -- time lives HERE, never in a manifest
  }
}
```

Rules carried over verbatim from the parent specs:

- **Append-only / create-only** (`createExclusive`), keyed by
  `attemptId`. Never updated in place except by appending a new
  outcome-transition audit event.
- **`protocol.*` is quarantined by construction.** Nothing in the
  decision path reads it. A conformance test asserts that mutating any
  byte under `protocol.*` changes no PolicyVault decision and no
  `manifestHash` — because the manifest hash is a function of the
  *normalized* intent only.
- The correlation walk becomes:
  `x402 attemptId → requestId → manifestHash → txId → successor
  outpoint/stateId → chain`, i.e. the existing spine with one extra
  hop on the front.
- **No secrets.** The machine credential, its SHA-256, the
  `Idempotency-Key` header value, any facilitator credential, and any
  `Authorization` header seen in flight are NEVER stored. (The
  idempotency *key* derived in §3.4 is stored — it is a public digest of
  public inputs, not a credential.)
- **Never backfilled.** No tool may synthesize an x402 attempt record for
  a payment that predates the adapter.

---

## 5. What the adapter must NEVER do

Normative prohibitions. Each is stated with the mechanism that makes it
structural rather than merely policy.

1. **NEVER hold, derive, import, generate, cache, or log a private key,
   seed phrase, or signature.** Mechanism: the adapter process has no
   signer dependency and no wallet library; the hosted layer holds no key
   material at all (`docs/hosted-threat-model.md` §3).
2. **NEVER sign.** Mechanism: §4.4 — signing is the USI signer's job,
   over frozen bytes, after independent local re-verification.
3. **NEVER use a privileged path.** No import of `sdk/src/**`,
   `server/src/**`, or `core/**` financial modules; no direct database
   handle; no node RPC client; no filesystem access to the store.
   Mechanism: separate process + a dependency-direction test (§5.1 of
   the degradation section) that fails the build on any such import.
4. **NEVER bypass, weaken, pre-empt, or "pre-approve" policy, governance,
   risk, or approvals.** Mechanism: the scope set of §4.2 makes
   `risk:release`, `governance:*`, and `request:break-glass`
   unreachable; and `applyRiskToPolicyDecision` has no code path that
   reads a risk verdict once the policy decision is DENY.
5. **NEVER treat protocol metadata as authority.** A signed, valid,
   facilitator-verified `PaymentRequirements` authorizes nothing. Only
   the covenant + the signer's signature authorize a spend.
6. **NEVER add, widen, or edit a recipient allowlist, budget, cap,
   approval threshold, approver set, or agent registry entry.** Every one
   of those is a governance-classified mutation requiring the owner's
   wallet signature (governance-spec §4, §5.1).
7. **NEVER take custody.** No pooled balance, no adapter-controlled
   address, no escrow, no "settlement account", no netting. Funds move
   vault → allowlisted recipient, once, on chain.
8. **NEVER act as facilitator or resource server** (§2). No `/verify`,
   no `/settle`, no `402` emitted by PolicyVault.
9. **NEVER report settled before chain proof** (§4.7), and never treat a
   facilitator's `VerifyResponse.isValid: true` as evidence about
   PolicyVault's own transaction.
10. **NEVER convert currencies, units, or prices.** No oracle, no quote,
    no rounding. Atomic unit == sompi, identity mapping, or refuse.
11. **NEVER mint its own `attemptId`, retry silently, or fabricate an
    idempotency key** (§3.4).
12. **NEVER follow a redirect, resolve a name, or dereference a URL to
    determine a destination.** Destinations come from literal validated
    addresses that are already allowlisted.
13. **NEVER let an LLM, a tool result, or free text reach a consensus
    value.** The adapter's input is closed-schema JSON. If a deployment
    ever lets a model *choose* which `accepts[]` entry to pay, the model's
    output is a **selection index**, re-validated against the same gates
    — never an amount, an address, or a network.
14. **NEVER widen the network.** Cross-network material never broadcasts;
    the config==request==manifest==node network equality chain is
    enforced already and the adapter adds a fourth checkpoint, not an
    exception.

---

## 6. Kaspa-specific gaps (honest)

### 6.1 The gap

**Neither the x402 core specification nor any published scheme lists
Kaspa.** The x402 Foundation repository's README enumerates support for
EVM chains, Solana (SVM), Avalanche, Aptos, Stellar, TVM, Hedera and
Keeta; Kaspa is absent. There is therefore **no `scheme` string, no
CAIP-2 network identifier, and no payload shape for Kaspa that any
resource server or facilitator recognizes today.**

### 6.2 The extension point (real, documented)

x402 is explicitly extensible and the process is public
([CONTRIBUTING.md](https://github.com/x402-foundation/x402/blob/main/CONTRIBUTING.md)):

- New schemes: *"Propose a scheme by opening a PR with a spec in
  `specs/schemes/`"*, after discussing "architecture and purpose".
- New chains: a **three-PR workflow** — (1) *"Add
  `specs/schemes/<scheme>/scheme_<scheme>_<chain>.md`"* documenting
  payload structure, verification logic and settlement logic; (2) a
  reference implementation of `SchemeNetworkClient`,
  `SchemeNetworkServer`, and `SchemeNetworkFacilitator`, with unit,
  integration and e2e coverage plus package READMEs and examples; (3)
  optional additional SDKs.
- CAIP-2 namespace registration is **not** listed as an acceptance
  criterion by CONTRIBUTING.md — but a CAIP-2-shaped `network` string is
  what v2 requires on the wire, so one is needed regardless (**OQ-5**).

### 6.3 Proposed Kaspa scheme (design only — NOT proposed upstream)

| Item | Proposal | Status |
|---|---|---|
| Scheme id | `exact` (reuse; the semantics fit precisely — a predetermined amount known in advance) | proposed |
| Chain spec file | `specs/schemes/exact/scheme_exact_kaspa.md` | not written |
| Network id | `kaspa:mainnet` / `kaspa:testnet-10` — CAIP-2-shaped; a real CAIP-2 namespace registration for Kaspa is **OQ-5** | **UNVERIFIED** |
| `asset` | a fixed sentinel for native KAS (Kaspa has no token contract address). Exact literal is **OQ-6** | **OPEN** |
| Atomic unit | **1 sompi** — normative, and the reason the adapter never converts | proposed |
| `payTo` | a literal Kaspa bech32 address with the network's prefix | proposed |
| Payment flow | **`extra.paymentFlow: "upfront"` is MANDATORY** — see §6.4 | proposed |
| `payload` shape | `{ transactionId, payer, amount, daaScore? }` (§4.6) | proposed |
| Verification | resource server (or facilitator) queries a Kaspa node for the txid, asserts an output paying exactly `amount` to `payTo`, and asserts sufficient confirmation depth | proposed |

### 6.4 Why Kaspa MUST use the upfront flow (a real protocol-fit finding)

x402's **default authorization flow** presupposes a *delegated pull*: the
client signs an authorization (EVM: EIP-3009 `transferWithAuthorization`)
that the **resource server later executes** to move the client's funds.

**Kaspa has no such primitive, and PolicyVault must never emulate one.**
Handing a counterparty an artifact they can later use to move funds is
exactly the delegated-spending authority the covenant exists to bound —
and it would place a spend decision outside PolicyVault's pipeline, which
the anti-bloat rule forbids. Therefore:

- The Kaspa scheme MUST be **upfront** (`settle → resource → respond`),
  which the generic `exact` scheme already provides for cases where
  "on-chain finality is required before execution".
- If a resource server advertises a Kaspa scheme **without**
  `extra.paymentFlow: "upfront"`, the adapter **refuses**
  (`X402_FLOW_UNSUPPORTED`). It never downgrades to the authorization
  flow, and never "approximates" it.

Consequence to state plainly: PolicyVault pays *before* receiving the
resource, so a dishonest resource server can take payment and withhold
delivery. This is a **counterparty risk, not a custody or consensus
risk**, and it is bounded by exactly the mechanisms PolicyVault already
enforces: per-spend cap, period budget, recipient allowlist (a server
that is not allowlisted cannot be paid at all), and approval tier. The
adapter surfaces `X402_SERVER_REFUSED_AFTER_SETTLEMENT` for human
follow-up; it must never "retry to make up for it" (§4.5 rule 2).

### 6.5 Ecosystem-acceptance risks — all OPEN

- **OPEN:** No resource server, client SDK, or facilitator supports
  Kaspa today. Until an accepted upstream scheme spec exists, the adapter
  interoperates only with servers explicitly configured to accept the
  proposed Kaspa scheme. **The adapter must not be described as "x402
  compatible" without this qualification** — that would collapse the
  claim ladder.
- **OPEN:** Whether the x402 Foundation would accept an upfront-only
  scheme as a first-class citizen, given the ecosystem's strong default
  toward the authorization flow.
- **OPEN:** Facilitator support. Most deployed servers verify via a
  facilitator; a facilitator that cannot see a Kaspa node will answer
  `isValid: false` regardless of a valid payment. Local verification by
  the resource server is the only path until a facilitator adds Kaspa.
- **OPEN:** Settlement latency. x402 assumes a payment resolves inside an
  HTTP round trip. PolicyVault requires chain proof before claiming
  settlement, and an M-of-N approval tier or a risk REVIEW hold can take
  minutes to hours. `maxTimeoutSeconds` will frequently be exceeded for
  exactly the payments that matter most. This is a **product-fit** issue
  that no adapter can engineer away, and the honest answer is the
  `pending` outcome (§4.5), not an optimistic settlement claim.

---

## 7. Degradation and deployment boundary

### 7.1 The addendum requirement

> "No optional integration may make the core depend on it. If x402, AP2,
> MCP, mobile, notification providers, or any other peripheral component
> is unavailable, PolicyVault's core financial safety and existing wallet
> functionality MUST remain correct and fail safely."

### 7.2 Recommendation: separate module, separate process, API client

**Normative: `integrations/x402/` — its own module, deployed as its own
process, communicating with PolicyVault exclusively over the public Agent
API (HTTPS, or loopback HTTP when co-located) using a scoped machine
bearer credential.**

Rationale:

1. **Structural unprivilege.** A separate process *cannot* reach a
   privileged path, because it has no in-process handle to
   `buildV4Transaction`, `sdk/src/store.js`, the migration runner, the
   RPC client, or the signer. §5's prohibitions stop being promises and
   become facts about the process boundary. The strongest available proof
   that "the adapter can only do what a scoped machine credential can do"
   is that the adapter *is* a scoped machine credential holder and
   nothing else.
2. **Failure isolation.** An unhandled exception, an OOM, a hung outbound
   HTTP call to a hostile resource server, or a slow-loris facilitator
   cannot consume the server's request semaphores, rate-limiter budget,
   or event loop. `server/src/limits.js`'s process-local protections
   already assume one app replica; adding an integration's untrusted-peer
   I/O into that process directly contradicts the launch pin.
3. **Blast radius on compromise.** A compromised adapter is a compromised
   *client* — bounded by tenancy (its creating wallet), by its six
   scopes, by the covenant's caps/allowlist/approval tier, and by the
   fact that it holds no key. It cannot become a compromised server.
4. **Independent lifecycle.** The adapter tracks a fast-moving external
   protocol (v1→v2 already broke field names and header names). It must
   be updatable, restartable, and *removable* without redeploying the
   financial core or touching the frozen production image identity.
5. **Honest capability advertisement.** `GET /api/v1/capabilities` is
   generated from live config; `features.x402` is honestly `false` when
   the adapter is not deployed, exactly as `machineIdentities` is
   honestly `false` in self-hosted mode.

**Rejected: in-server route namespace (`/api/v1/integrations/x402/*`).**
It buys deployment convenience and loses every property above.
Permitted only as a documented, flag-gated (`default: off`)
self-hosted convenience, and **only under all four constraints**:
(a) the module lives in `integrations/x402/` and imports nothing from
`sdk/src/**` or `server/src/**` except pure schema constants;
(b) it reaches PolicyVault over **loopback HTTP with a machine
credential** like any other client — never by direct function call;
(c) every route is wrapped so no adapter exception can propagate into the
core request path; (d) outbound calls to resource servers/facilitators
carry hard timeouts and a dedicated concurrency budget that cannot borrow
from the core semaphores. Even then, hosted production uses the separate
process.

### 7.3 Degradation semantics (what "adapter down" actually means)

| Failure | Effect on PolicyVault core |
|---|---|
| Adapter process not deployed | `features.x402: false`; every other surface byte-identical |
| Adapter crashes at any point | **Zero.** No core route, migration, reconciliation, signing, or web flow depends on it |
| Adapter crashes **after** `POST .../submit` | The durable request, transition claim, submission claim, and reconciliation recover the truth exactly as for any other client. **The adapter is not on the recovery path.** The payment completes or fails on chain regardless; the *x402 receipt* is what is lost, and a human can reconstruct it from `receipts[txId]` |
| Adapter credential revoked mid-flight | Revocation is checked at resolution time and invalidates every credential the identity minted, immediately. In-flight PolicyVault work already accepted continues under normal pipeline rules; no new adapter call is authorized |
| Hostile/slow resource server or facilitator | Bounded by the adapter's own timeouts and its separate process budget. Cannot reach core semaphores |
| Adapter compromised | Bounded by tenancy + six scopes + covenant. Worst case: it can *propose* spends within the agent's existing caps to *already-allowlisted* recipients, and can refuse to pay. It cannot exceed a budget, add a recipient, release a risk hold, approve a proposal, change a signer, or move funds anywhere new |

**Mechanical enforcement (required, not aspirational):** a
dependency-direction test that fails the build if any file under
`core/**`, `sdk/src/**`, or `server/src/**` imports anything under
`integrations/**`, and if any file under `integrations/x402/**` imports
anything under `sdk/src/**` or `server/src/**`. Per the efficiency
doctrine, this is a deterministic test, not a review convention.

### 7.4 Human escalation

`X402_SERVER_REFUSED_AFTER_SETTLEMENT` (paid but not delivered) and any
integrity alarm (a stored manifest whose recomputed hash ≠ its row key)
are **human-notification events**, never auto-retried and never
auto-remediated by the adapter.

---

## 8. Adversarial test plan

The addendum's matrix, applied concretely. Every case is a **policy-invalid
adversarial test transaction / authorized negative-validation case** run
against PolicyVault's own adapter and, where covenant-relevant, against a
real node — never framed as an attack.

Per the addendum: *"The agent conformance suite MUST exercise the REAL
reference MCP, JS/TS, Python, and protocol-adapter paths (not mocks)."*
These run against the real adapter process, the real Agent API, real
PostgreSQL, and (for X-13/X-14) a live testnet-10 node.

| # | Class | Case | Required outcome |
|---|---|---|---|
| X-1 | Destination substitution | `payTo` = a valid, well-formed Kaspa address that is **not** in the agent's allowlist | Refuse pre-build; and if forced past the adapter, the covenant rejects (Merkle membership) |
| X-2 | Destination substitution | `payTo` mutated **between** simulate and build (adapter re-fetches requirements) | Idempotency fingerprint conflict `409`; handler never called |
| X-3 | Destination substitution | `payTo` = a non-literal form: role constant, name, `https://` URL, IDN homograph of an allowlisted address, mixed-case bech32, wrong network prefix | Refuse each (`X402_DESTINATION_NOT_LITERAL` / `_INVALID`) |
| X-4 | Destination substitution | Settlement succeeds; adapter is asked to report a **different** `payTo` in `PaymentPayload.accepted` than the one paid | Impossible by construction (byte-verbatim echo); test asserts the digest binds |
| X-5 | Amount mutation | `amount` as JSON number `100`; as `"1e8"`, `"1.0"`, `"0x64"`, `"+100"`, `"-1"`, `" 100"`, `"0100"`, `"０"`, `MAX_SOMPI+1`, `"0"` | Refuse each with its distinct code; **no float ever constructed** |
| X-6 | Amount mutation | `amount` raised on the retry after the first 402 | `409 IDEMPOTENCY_KEY_CONFLICT`; no second spend |
| X-7 | Amount mutation | `amount` ≤ cap but pushing cumulative period spend over `periodBudget` | Refuse at simulate; covenant refuses independently |
| X-8 | Amount mutation | `amount` > agent `approvalThreshold` | `pending` + `requires: ["approvals"]`; **never** auto-settled |
| X-9 | Replay | Same `attemptId` + same digest, replayed 10× serially | Exactly one durable request, one txid; 9 verbatim replays |
| X-10 | Replay | Same `attemptId` + same digest, fired **concurrently** ×2 | Exactly one `wallet_requests` row (mirrors the proven `postlaunch-idempotency-server.test.js` property) |
| X-11 | Replay | A previously-settled `PaymentPayload` re-presented to a second resource server | PolicyVault-side: a **new** attempt requires a new `attemptId` and a new spend. Cross-server payload reuse is the *resource server's* verification duty (its own txid/`payTo`/depth check) — the adapter never re-uses a settlement payload for a different requirement digest |
| X-12 | Replay | Broadcast the identical frozen transaction twice | Same txid ⇒ node-idempotent; or predecessor already consumed ⇒ consensus rejection. Asserted on a real node |
| X-13 | Chain truth vs metadata | Node accepts a transaction whose payment output differs from the `PaymentRequirements` (deliberately hand-built) | The **manifest verifier** refuses at `outputs-explained` / `request-equations` before signing; the adapter never reaches settlement |
| X-14 | Metadata-overrides-chain-truth | `resource.description` / `error` / `extra` / `extensions` carry text asserting a different amount, a different recipient, "already approved", "risk cleared", "policy waived", or prompt-injection targeting a downstream LLM | Byte-identical PolicyVault decision and byte-identical `manifestHash` vs the same case with empty metadata. **This is the headline test for surface 27** |
| X-15 | Metadata-overrides-chain-truth | `SettlementResponse` from the server claims `success: false` for a chain-proven payment (and vice-versa) | PolicyVault's own record is authoritative; the server's claim is stored under `protocol.*` and never alters `outcome.status` |
| X-16 | Malformed / oversized | 64 MiB `PAYMENT-REQUIRED` header; invalid base64; base64 of non-JSON; 10 000-deep nesting; duplicate keys; NUL bytes; invalid UTF-8; `__proto__` / `constructor` / `prototype` keys (prototype pollution) | Refuse **before** JSON parsing where the size cap applies; no memory blowup; no prototype pollution; adapter stays responsive |
| X-17 | Malformed | `accepts: []`; `accepts` with 10 000 entries; every entry failing a different gate | Deterministic refusal; selection never falls back to "closest match" |
| X-18 | Downgrade | `x402Version: 1` presented to a v2-only adapter; `x402Version: 0`, `3`, `"2"`, `null`, absent, `2.0` | Refuse each with `X402_VERSION_UNSUPPORTED`; never coerced |
| X-19 | Downgrade | v2 envelope carrying v1 field names (`maxAmountRequired`) | `X402_SCHEMA_UNKNOWN_FIELD`; never "understood anyway" |
| X-20 | Downgrade | `extra.paymentFlow` absent / `"authorization"` for the Kaspa scheme | `X402_FLOW_UNSUPPORTED` — the delegated-pull refusal (§6.4) |
| X-21 | Downgrade | Unknown `scheme`; a scheme string differing only by case or Unicode confusable | Refuse; exact-match only |
| X-22 | Wrong network | `network` = mainnet CAIP-2 while the deployment is testnet-10, and the reverse | Refuse at the adapter; the config==request==manifest==node equality chain refuses independently |
| X-23 | Concurrency budget race | N concurrent **distinct** `attemptId`s that individually fit the cap but jointly exceed `periodBudget` | Aggregate spend never exceeds `periodBudget`. Covenant-enforced; asserted against a real node, not only the API |
| X-24 | Concurrency | N concurrent attempts racing for the single covenant UTXO | At most one succeeds per state; the rest refuse cleanly with a stale-predecessor error, no stranded claims |
| X-25 | Capability escalation | Adapter credential attempts `risk:release`, `governance:approve`, `request:break-glass`, `organizations:manage`, `vaults:reconcile`, `POST /identities`, `POST /wallet/dev-sign` | `403 SCOPE_FORBIDDEN` for each; the last two forbidden **regardless of scope** |
| X-26 | Capability escalation | Adapter attempts to mint itself a second credential or widen its own scopes | Structurally unreachable (`/identities*` is wallet-session-only) |
| X-27 | Tenancy | Adapter references a `vaultId` belonging to another wallet | `404` (existence hidden), matching `tenancy.js` discipline |
| X-28 | Signer substitution | Adapter attempts to name a different `signerAddress`/`agentPk` than the vault's registered agent | `assertSignerAuthorizedV4` refuses at build **and again** at finalize |
| X-29 | Approval replay | A covenant approval signature collected for attempt A re-presented for attempt B | Refused — approvals are over the frozen covenant input of a specific transaction |
| X-30 | Stale state | Requirement paid against a vault state that advanced between simulate and build | Frozen bytes bind the exact predecessor outpoint; a stale predecessor cannot confirm |
| X-31 | Fee manipulation | Server-supplied `extra` attempts to set fee, `lockTime`, `computeBudget`, or `periodsElapsed` | Refused as unknown fields; none of these are ever adapter-controllable |
| X-32 | Degradation | Kill the adapter process mid-flow at each of the 7 stages; kill it after broadcast | Core financial safety unaffected at every stage; post-broadcast truth recovered by reconciliation with **no** adapter involvement |
| X-33 | Degradation | Hostile resource server: 1-byte-per-minute response, infinite redirect, 10 GB body, TLS renegotiation loop | Bounded by adapter timeouts; core semaphores/rate limits untouched (measured, not asserted) |
| X-34 | Dependency direction | Static check: any `core/**`, `sdk/src/**`, `server/src/**` import of `integrations/**`, or `integrations/x402/**` import of `sdk/src/**` | Build fails |
| X-35 | Audit integrity | Mutate any byte under `protocol.*` in a stored attempt record | No decision changes; `manifestHash` unchanged; the read-side manifest re-hash still matches its row key |
| X-36 | Storage round-trip (G-2 class) | Write an attempt record + requirement digest to **live PostgreSQL**, read back, recompute both digests | Byte-equal digests after `jsonb` key reordering. **Must run against live PG** — a JSON-backend suite cannot catch a jsonb representation defect |

---

## 9. Implementation status

| Component | Claim |
|---|---|
| This specification | **DESIGNED** |
| Kaspa `exact` scheme spec (upstream `specs/schemes/exact/scheme_exact_kaspa.md`) | NOT WRITTEN, NOT PROPOSED |
| `integrations/x402/` adapter | NOT IMPLEMENTED |
| Additive DAA-score evidence field (§4.7 OQ-2) | NOT IMPLEMENTED — separate reviewed change |
| `policyvault-x402-attempt/v1` store + migration | NOT IMPLEMENTED |
| Adversarial suite §8 | NOT WRITTEN |

Nothing here is IMPLEMENTED, UNIT-TESTED, VM-VERIFIED, TESTNET-VERIFIED,
PRODUCTION-HARDENED, EXTERNALLY REVIEWED, or AUDITED.

---

## 10. Open questions

- **OQ-1 — v1 support.** Support x402 v1 (`X-PAYMENT`,
  `maxAmountRequired`, chain-slug networks) at all, or v2-only? Leaning
  **v2-only**: v1 is superseded, and a second normalizer doubles the
  fail-closed surface for no Kaspa-ecosystem benefit (no v1 Kaspa servers
  exist either).
- **OQ-2 — DAA score in settlement evidence.** Add an additive
  `blockDaaScore` to `policyvault-receipt/v1` at `proveExpectedEffectV4`
  time, add `live.blockDaaScore` to the vault manifest at reconcile time,
  or omit `daaScore` from the x402 payload? Design currently omits it.
  Owner/coordinator decision.
- **OQ-3 — `payer` identity.** Should `SettlementResponse.payer` /
  `payload.payer` be the vault's covenant address, the agent's x-only
  key, or omitted? Privacy tradeoff: the covenant address is already
  public on chain, but naming the agent key links an agent identity to a
  merchant.
- **OQ-4 — paid-but-not-delivered.** Beyond human notification, is any
  automated posture wanted (auto-suspend the agent, auto-remove the
  recipient from the allowlist after N failures)? Auto-removal is a
  governance REDUCTION and therefore *safe by classification*, but it is
  still an authority change and should not happen without an explicit
  decision.
- **OQ-5 — CAIP-2 for Kaspa.** Is there (or will there be) a registered
  CAIP-2 namespace for Kaspa? `kaspa:mainnet` is a **guess** in this
  document and is marked UNVERIFIED. It must be settled before any
  upstream scheme PR.
- **OQ-6 — `asset` literal for native KAS.** x402 `asset` is "token
  contract address or ISO 4217 code"; Kaspa native KAS is neither. Needs
  a scheme-defined sentinel, agreed upstream.
- **OQ-7 — upstream engagement.** Should PolicyVault propose the Kaspa
  scheme upstream at all (a public, named, ecosystem-facing act), and if
  so, when relative to the still-CLOSED hosted/PostLaunch source
  publication gate? **This is an owner decision, not an engineering one.**
  Note the publication gate explicitly: no public repo, push, or upload
  is authorized for this lane.
- **OQ-8 — latency posture.** Should the adapter refuse up front when
  simulation reports `wouldRequire.approvals` and `maxTimeoutSeconds` is
  small (fail fast, honest), or always attempt and report `pending`?
  Leaning **refuse fast with a distinct code**, so the caller can seek a
  human before the requirement expires.
- **OQ-9 — facilitator interoperability.** Is there value in publishing a
  read-only Kaspa *verification* helper (given a txid + requirements,
  answer `isValid`) that others could run inside their own facilitator?
  It would take no custody and settle nothing. Free-forever policy
  permits it; ecosystem value is unproven.

---

## Sources

- [coinbase/x402](https://github.com/coinbase/x402)
- [x402-foundation/x402](https://github.com/x402-foundation/x402)
- [x402 specification v2](https://github.com/coinbase/x402/blob/main/specs/x402-specification-v2.md)
- [x402 v1 specification](https://github.com/coinbase/x402/blob/main/specs/x402-specification.md)
- [x402 v2 HTTP transport](https://github.com/coinbase/x402/blob/main/specs/transports-v2/http.md)
- [x402 generic `exact` scheme](https://github.com/x402-foundation/x402/blob/main/specs/schemes/exact/scheme_exact.md)
- [x402 CONTRIBUTING.md](https://github.com/x402-foundation/x402/blob/main/CONTRIBUTING.md)
- [docs.x402.org — HTTP 402 core concept](https://docs.x402.org/core-concepts/http-402)
- [docs.x402.org — FAQ](https://docs.x402.org/faq)
- [Cloudflare Agents — x402 (v1/v2 header coexistence)](https://developers.cloudflare.com/agents/tools/payments/x402/)
