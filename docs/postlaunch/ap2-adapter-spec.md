# PolicyVault AP2 Interoperability Adapter — Design Specification (DRAFT)

**Claim label: DESIGNED.** Nothing in this document is IMPLEMENTED,
UNIT-TESTED, VM-VERIFIED, TESTNET-VERIFIED, or PRODUCTION-HARDENED. No
production file, migration, covenant byte, or configuration is changed by
this document. It covers `FULLSCALE_COMPLETION_ADDENDUM.md` surface **28
(AP2 interoperability adapter)**.

Binding parents: `docs/postlaunch/FULLSCALE_COMPLETION_ADDENDUM.md`
(anti-bloat rule, security model, payment-interop conceptual flow,
adversarial matrix), `docs/postlaunch/COMPLETION_STANDARD.md`,
`CLAUDE.md` (numeric safety, network safety, pipeline discipline,
fail-closed versioning, progress-reporting labels, free-forever product
policy).

Sibling: `docs/postlaunch/x402-adapter-spec.md` (surface 27). The two
adapters share the normalized-intent schema (§3.3), the machine-identity
scope set (§4.2), and the deployment boundary (§7); they are otherwise
independent. Where a finding is identical in both (the delegated-pull
impossibility, the dependency-direction test), this document restates it
rather than cross-referencing, because the two adapters must be
independently reviewable.

---

## 0. One-paragraph summary

AP2 (Agent Payments Protocol) is a mandate-based agentic-commerce
protocol: a user's authorization is captured in cryptographically signed,
selectively-disclosable verifiable credentials ("mandates") that travel
between a shopping agent, a credential provider, a merchant, and a
merchant payment processor. PolicyVault occupies exactly one AP2 role —
**Credential Provider** (optionally also **Trusted Surface**) — and the
AP2 adapter is a **thin, unprivileged, separately-deployed translator**
that verifies inbound mandates, treats every mandate field as untrusted,
normalizes only the amount/destination/deadline into an ordinary closed
PolicyVault transaction intent, pushes that intent through the *exact
same* authoritative pipeline every other client uses (via the public
Agent API with a scoped machine credential), maps the user's own mandate
constraints into the risk layer as **restrictive-only** inputs, and — only
after real chain proof — returns settlement evidence. It holds no keys,
signs no Kaspa transaction, has no privileged path, and its complete
absence costs PolicyVault nothing but AP2 translation.

---

## 1. Protocol summary (cited; exact shapes an adapter must handle)

### 1.1 Provenance, versions, and a version divergence the adapter must handle

AP2 was announced by Google on **2025-09-16** and is documented at
[ap2-protocol.org](https://ap2-protocol.org/); the reference
implementation is
[google-agentic-commerce/AP2](https://github.com/google-agentic-commerce/AP2)
(Apache-2.0). **AP2 v0.2 shipped in April 2026** alongside the protocol's
donation to the **FIDO Alliance**, adding human-not-present payments and
"Verifiable Intent".

**There are two materially different mandate models in circulation. An
adapter that conflates them is broken.**

| | **v0.1** (2025-09 → early 2026) | **v0.2** (current spec) |
|---|---|---|
| Mandates | `IntentMandate`, `CartMandate`, `PaymentMandate` — three, chained | **Checkout Mandate**, **Payment Mandate** — two, each with an **open** and a **closed** form |
| Credential format | W3C Verifiable Credentials | **SD-JWT VC** (selective disclosure), `vct` type claim |
| Versioning | document/model version | `vct` string with a numeric suffix; *"Implementations MUST match the exact `vct` string, including the version suffix"* |
| A2A linkage | A2A **AgentCard extension**, URI `https://github.com/google-agentic-commerce/ap2/tree/v0.1` | **Agent Card extension dropped.** "Agent-to-Agent Delegation" is stated to be *"outside the scope of the current specification"* |
| Human-not-present | limited | first-class (open mandates + agent-signed closed mandates) |

**Adapter rule.** The design target is **v0.2 only**. The `vct` claim is
matched against an explicit supported set **before any structural
assumption is applied**; an unknown, absent, or near-miss `vct` refuses
with `AP2_VCT_UNSUPPORTED` and is never routed to a default. v0.1
artifacts (W3C VC `IntentMandate`/`CartMandate`/`PaymentMandate`) are
**refused, not translated** (§10 OQ-1) — a "best-effort" reinterpretation
across a model change this large is precisely the guessing CLAUDE.md
forbids.

**OPEN:** whether the AP2 maintainers formally deprecate v0.1 or run both
models concurrently. Sources reviewed do not contain a migration
statement, and third-party write-ups published after v0.2 still describe
the three-mandate model. Treat v0.1's status as **UNVERIFIED**.

### 1.2 Roles

The v0.2 specification defines **five** roles, noting *"While AP2 defines
five roles, it is possible for a single entity to play multiple (or even
all) of the roles."*

| Role | Definition (per spec) |
|---|---|
| **Shopping Agent (SA)** | performs product discovery, builds checkout, executes purchase |
| **Credential Provider (CP)** | source of payment credentials; verifies agent authorization |
| **Merchant (M)** | provides and completes checkout; verifies purchase approval |
| **Merchant Payment Processor (MPP)** | processes payments; verifies credential authorization |
| **Trusted Surface (TS)** | trusted UI surface that obtains user consent for mandates |

### 1.3 Checkout Mandate

Source: [ap2-protocol.org/ap2/checkout_mandate](https://ap2-protocol.org/ap2/checkout_mandate/).
SD-JWT format with disclosures.

```
Closed Checkout Mandate      vct = "mandate.checkout.1"
{
  vct           : string  (required)
  checkout_jwt  : string  (required, SELECTIVELY DISCLOSABLE)
                            -- base64url-encoded MERCHANT-SIGNED JWT
  checkout_hash : string  (required)
                            -- base64url hash of the checkout_jwt value,
                               using the algorithm named by `_sd_alg`
                               (SHA-256 if absent)
  iat           : integer (optional)   -- Unix epoch, created
  exp           : integer (optional)   -- Unix epoch, expires
}

Open Checkout Mandate        vct = "mandate.checkout.open.1"
  -- carries `delegate_payload` references and CONSTRAINTS:
     { type: "checkout.allowed_merchants", allowed: Merchant[] }   (selectively disclosable)
     { type: "checkout.line_items",        items:   LineItemRequirements[] }

Item     { id, title }
Product  { id, title, price, currency }      -- as carried inside a checkout
Merchant { id, name, website? }
```

Key binding: open mandates carry `cnf` with a `jwk`; closed mandates use
holder binding via `nonce` and `sd_hash`.

The spec states it *"is agnostic to the contents of the merchant-signed
Checkout JWT. It is created to be compatible with logically represented
Checkout Objects."*

### 1.4 Payment Mandate

Source: [ap2-protocol.org/ap2/payment_mandate](https://ap2-protocol.org/ap2/payment_mandate/).

```
Closed Payment Mandate       vct = "mandate.payment.1"
{
  vct                : string  (required)
  transaction_id     : string  (required)
                         -- base64url-encoded hash of the associated checkout_jwt
  payee              : { id, name, website? }        (required)
  payment_amount     : { amount   : integer,          -- MINOR UNITS
                         currency : string }          -- ISO 4217 code
  payment_instrument : { id, type, description? }     (required)
  pisp               : ...      (optional)
  execution_date     : ...      (optional)
  risk_data          : ...      (optional)
  iat, exp           : integer  (optional)
}

Open Payment Mandate         vct = "mandate.payment.open.1"
  -- "MAY optionally include any property from the closed Payment Mandate";
     carries CONSTRAINTS rather than specific transaction details.
```

**The seven constraint types** (open Payment Mandate):

| `type` | Meaning |
|---|---|
| `payment.agent_recurrence` | frequency and occurrence limits |
| `payment.allowed_payees` | restricted merchant set |
| `payment.allowed_payment_instruments` | restricted instrument set |
| `payment.allowed_pisps` | restricted PISP set |
| `payment.amount_range` | min/max amount boundaries |
| `payment.budget` | cumulative spending limit |
| `payment.reference` | links to a checkout mandate via `conditional_transaction_id` |
| `payment.execution_date` | valid window (`not_before` / `not_after`) |

Authorship and verification: *"The Payment Mandate Content is created by
the Shopping Agent, rendered to the User by the Trusted Surface and
verified by the Credential Provider, Network, and Merchant Payment
Processor."*

### 1.5 Payment-instrument extensibility (the Kaspa extension point)

The specification states, verbatim: *"AP2 is agnostic to the particular
payment instrument used. New Payment Instruments are supported by
defining a unique `type` in the Payment Instrument JSON object."*

This single sentence is the entire honest basis for a Kaspa integration
(§6). No published payment rails are enumerated as normatively supported.

### 1.6 The two operating modes

- **Direct (Human Present):** *"The User directly sees the closed
  Checkout and approves it and its payment explicitly."* The SA
  constructs mandates and passes them to the TS for user signing; the SA
  forwards the Payment Mandate to the CP for verification; on success the
  SA gives both mandates to the Merchant; the Merchant initiates payment
  with the MPP; a Checkout Receipt returns to the SA and a Payment
  Receipt returns to the SA, CP, and Network.
- **Autonomous (Human Not Present):** *"The User sees and approves a set
  of constraints over what closed Checkout and Payment would meet their
  intent."* The agent creates **open** mandates with constraints, the TS
  authorizes them, and the agent later signs the **closed** mandates with
  **its own key**, presenting both the user-signed open mandate and the
  agent-signed closed mandate to verifiers.

### 1.7 What AP2 does NOT specify (do not invent it)

- **No blockchain destination field anywhere.** `payee` is `{id, name,
  website?}` — an identity, never an address. (§3.2 turns this into a
  security property.)
- **No crypto-native amount representation.** `payment_amount` is
  `{amount: integer minor units, currency: ISO 4217}`. **KAS has no ISO
  4217 code.** This is the central Kaspa gap (§6.3).
- **No receipt schema** was recoverable from the sources reviewed beyond
  the existence of "Checkout Receipt" and "Payment Receipt" — their exact
  field names are **OPEN** (§10 OQ-6).
- **No A2A transport binding in v0.2** — the AgentCard extension was
  dropped and agent-to-agent delegation is explicitly out of scope. How a
  Payment Mandate reaches a CP over the wire is therefore
  implementation-chosen (**OQ-2**).
- **No idempotency guidance.** `transaction_id` exists and is a hash, but
  no retry semantics are specified. → §3.4 derives PolicyVault's own key.

---

## 2. Roles: which AP2 role PolicyVault plays (and which it never does)

| AP2 role | PolicyVault | Rationale |
|---|---|---|
| **Credential Provider (CP)** | **IN SCOPE — the primary role** | The CP is *"the source of payment credentials"* that *"verifies agent authorization"*. That is precisely PolicyVault: it holds the delegated-spending relationship (vault + agent registry + covenant policy) and deterministically decides whether an agent is authorized. |
| **Trusted Surface (TS)** | **IN SCOPE, optional** | PolicyVault already ships a wallet-authenticated UI with **browser-local intent verification** (`web/verify-intent.js` + the core bundle enforced pre-sign) — a client that independently detects server/frontend manipulation before signing. That is a stronger Trusted Surface than most AP2 deployments will have. Whether to *claim* the TS role is a deployment decision (§10 OQ-3). |
| Shopping Agent | **OUT OF SCOPE** | PolicyVault never does product discovery, never builds a checkout, and never decides *what* to buy. The SA is the customer's AI agent; PolicyVault is what bounds it. |
| Merchant / Merchant Payment Processor | **OUT OF SCOPE, permanently** | PolicyVault is **free forever, including commercial use** and never charges for its protocol, covenant, SDK, API, security features, or ordinary usage (CLAUDE.md). It sells nothing and processes no one else's payments. |
| Network | **OUT OF SCOPE** | Kaspa consensus is the network. PolicyVault is not an intermediary over it. |

---

## 3. Trust classification and closed-schema normalization

### 3.1 The classification rule

> Every byte that arrives inside an AP2 mandate is **UNTRUSTED**, without
> exception — **including cryptographically valid, correctly
> key-bound, unexpired, merchant-signed and user-signed content.** A
> field is either (a) a **PROPOSAL** normalized into the closed
> PolicyVault intent schema and then subjected in full to policy,
> governance, risk, local deterministic verification, and finally the
> covenant; (b) a **RESTRICTIVE-ONLY CONSTRAINT** that may make
> PolicyVault *more* restrictive and can never make it less; or (c)
> **AUDIT-ONLY METADATA**, length-capped, recorded verbatim for
> correlation, and read by *nothing* in the decision path.

Anything that is none of the three causes a refusal
(`AP2_SCHEMA_UNKNOWN_FIELD`).

**The mandate-signature fallacy, stated explicitly and once:** a
successfully verified mandate proves *who said what*. It does not prove
*that PolicyVault agreed*. A valid user signature over an open Payment
Mandate authorizing "up to 500 KAS to anyone" grants the agent **exactly
zero** additional PolicyVault authority: the covenant's `maxPerSpend`,
`periodBudget`, `agentRecipientRoot`, `approvalThreshold` and `paused`
flag are enforced by Kaspa consensus against a malicious actor holding
the legitimate delegate key, and no off-chain credential can raise any of
them. Restating the addendum's model at this boundary: **the mandate MAY
REQUEST. POLICYVAULT DETERMINISTICALLY DECIDES. THE COVENANT ENFORCES
FINANCIAL AUTHORITY. THE SIGNER RETAINS CUSTODY.**

### 3.2 Field-by-field table (v0.2)

| Field | Class | Normalization / rule | Refusal code |
|---|---|---|---|
| `vct` (every mandate) | **PROPOSAL (gate)** | exact member of `{mandate.payment.1, mandate.payment.open.1, mandate.checkout.1, mandate.checkout.open.1}`; checked first | `AP2_VCT_UNSUPPORTED` |
| JWS header `alg` | **PROPOSAL (gate)** | exact member of a pinned allow-list (e.g. `ES256`). `none`, symmetric algorithms, and unknown values refuse. Never algorithm-negotiated from the token | `AP2_ALG_UNSUPPORTED` |
| `_sd_alg` | **PROPOSAL (gate)** | exact member of a pinned allow-list (SHA-256 and stronger). A weak or unknown digest refuses. **Never** "SHA-256 if absent" for *inbound* mandates — absence refuses (§8 A-19) | `AP2_SD_ALG_UNSUPPORTED` |
| `cnf.jwk` / `nonce` + `sd_hash` | **PROPOSAL (gate)** | key binding MUST verify against the presenting party. Failure refuses; a partial or absent binding refuses | `AP2_KEY_BINDING_INVALID` |
| Disclosure set completeness | **PROPOSAL (gate)** | §3.3 "no-silent-absence" rule — every constraint slot the deployment requires MUST be disclosed. An undisclosed slot is **never** read as "unconstrained" | `AP2_DISCLOSURE_INCOMPLETE` |
| `exp` / `iat` | **PROPOSAL (gate)** | integers; `exp` in the future, `iat` not in the future beyond a small skew. Expired refuses. Used only to bound the adapter's own deadline — **never** enters `lockTime`, CLTV, fee, or period arithmetic | `AP2_MANDATE_EXPIRED` |
| `transaction_id` | **PROPOSAL (correlation anchor)** | base64url, fixed expected length for the pinned `_sd_alg`; MUST be present on a closed Payment Mandate. Feeds the idempotency key (§3.4). **Carries no authority** | `AP2_TRANSACTION_ID_INVALID` |
| `checkout_hash` | **PROPOSAL (integrity)** | MUST recompute to equal the digest of `checkout_jwt` under the pinned `_sd_alg` when `checkout_jwt` is disclosed. Mismatch refuses. Correlation only thereafter | `AP2_CHECKOUT_HASH_MISMATCH` |
| `payment_amount.amount` | **PROPOSAL → `payAmountSompi`** | §3.3. Integer **minor units**. **Only** normalizable when the pinned Kaspa instrument declares minor unit == sompi (§6.3); otherwise refuse | `AP2_AMOUNT_INVALID` |
| `payment_amount.currency` | **PROPOSAL (gate)** | MUST equal the Kaspa instrument's declared currency token (§6.3). **Any ISO 4217 fiat code refuses** — the adapter performs no currency conversion, ever | `AP2_CURRENCY_UNSUPPORTED` |
| `payment_instrument.type` | **PROPOSAL (gate)** | exact member of the supported instrument-type set (§6.3). Unknown ⇒ refuse | `AP2_INSTRUMENT_TYPE_UNSUPPORTED` |
| `payment_instrument.id` | **PROPOSAL → vault/agent selection** | an **opaque PolicyVault-minted handle**, resolved *PolicyVault-side* to `(vaultId, agentPk)`. Never a vault id, never an address, never a key. Unresolvable ⇒ refuse | `AP2_INSTRUMENT_UNKNOWN` |
| `payee.id` | **PROPOSAL → `recipient`** | §3.3. Resolved through an **operator-configured, PolicyVault-side payee directory** to an x-only key that MUST already be in the acting agent's allowlist | `AP2_PAYEE_UNKNOWN` / `AP2_PAYEE_NOT_ALLOWLISTED` |
| `payee.name`, `payee.website` | **AUDIT-ONLY** | length-capped (≤ 255 / ≤ 2048 bytes), recorded verbatim, **never** used for destination resolution, matching, or display-as-authority | `AP2_METADATA_TOO_LARGE` |
| `payment.amount_range`, `payment.budget`, `payment.allowed_payees`, `payment.allowed_payment_instruments`, `payment.allowed_pisps`, `payment.agent_recurrence`, `payment.execution_date`, `payment.reference` | **RESTRICTIVE-ONLY CONSTRAINT** | §3.5 — evaluated by a `policyvault-risk-adapter/1` adapter whose maximum power is `DENY`/`REVIEW` | (risk codes) |
| `checkout.allowed_merchants`, `checkout.line_items` | **RESTRICTIVE-ONLY CONSTRAINT** | §3.5 | (risk codes) |
| `checkout_jwt` (contents) | **AUDIT-ONLY** | AP2 itself is *"agnostic to the contents"*; PolicyVault treats it as an **opaque blob**: size-capped, digest-verified against `checkout_hash`, stored verbatim, **never parsed for amounts, addresses, or authorizations** | `AP2_CHECKOUT_JWT_TOO_LARGE` |
| `Item`/`Product` `{id, title, price, currency}` | **AUDIT-ONLY** | line-item detail is *what was bought*, not *what may be paid*. **`price`/`currency` here NEVER become `payAmountSompi`** — only the Payment Mandate's `payment_amount` is a proposal | `AP2_METADATA_TOO_LARGE` |
| `pisp` | **AUDIT-ONLY** | PolicyVault is never a PISP and never routes through one | — |
| `risk_data` | **AUDIT-ONLY (may be forwarded as evidence)** | may be passed to risk adapters as `reasons[].evidence`; is **never itself a verdict** and can never produce an ALLOW | `AP2_METADATA_TOO_LARGE` |
| `execution_date`, `delegate_payload`, any other spec-defined field | **AUDIT-ONLY** unless promoted by an explicit later revision of this document | recorded verbatim | — |
| Any other claim, at any depth | — | **refuse** | `AP2_SCHEMA_UNKNOWN_FIELD` |

### 3.3 Closed normalization rules (types, ranges, integer discipline)

The output is a `policyvault-requested-intent/1` document
(`intent-manifest-spec.md` §6.2) with `action: "agentSpend"` — the *same*
closed schema the web client and CLI produce. There is no AP2 variant of
it.

**Amount.**
- `payment_amount.amount` is specified as a JSON **integer**. It MUST be
  a JS safe integer ≥ 1 (AP2's own type), and it is immediately
  re-encoded as the canonical base-10 digit string
  `^(0|[1-9][0-9]*)$` before entering the intent — the intent-manifest
  encoding, deliberately stricter than `core/model/amounts.js
  parseSompi`, because the manifest hash is a function of encodings.
- Parsed with `BigInt`. MUST be `> 0` and `≤ MAX_SOMPI`
  (`29_000_000_000n * 100_000_000n`).
- **Minor unit == sompi, by declaration of the Kaspa payment instrument
  (§6.3). The mapping is the identity.** The adapter performs **no unit
  conversion, no decimal parsing, no rounding, and no currency
  conversion** — ever. A fiat-denominated mandate is a refusal, not a
  quote lookup (§6.3, OQ-4).
- Rejected explicitly: any JSON *number* that is not a safe integer,
  `NaN`, `Infinity`, `-0`, negatives, `0`, `1e8`, `1.0`, strings,
  bignum-as-string forms not permitted by the declared instrument, and
  anything exceeding `MAX_SOMPI`. **No float ever touches a consensus
  value** (CLAUDE.md numeric safety).

**Destination — the strongest property in this spec.**

AP2 has **no destination field**. `payee` is `{id, name, website?}`. This
is not a gap to work around; it is a structural advantage, and the
adapter must preserve it:

- The destination is resolved **entirely PolicyVault-side**:
  `payee.id` → an **operator-configured payee directory** → an x-only
  public key. The directory is deployment configuration under the vault
  owner's control, not mandate content.
- The resolved x-only key MUST already be a member of the acting agent's
  recipient allowlist and provable against the leaf's
  `agentRecipientRoot`. **The adapter never adds a recipient** — that is
  a governance-classified `AGENT_RECIPIENT_ADDED` **EXPANSION**
  (governance-spec §5.1) requiring the owner's wallet signature, which is
  structurally unreachable from an adapter credential (§4.2).
- Therefore: **no combination of mandate bytes, however signed, can name
  a destination PolicyVault has not already authorized.** A merchant that
  is not both in the directory *and* in the allowlist cannot be paid, and
  a mandate cannot put itself in either.
- `payee.name` and `payee.website` are **never** used for resolution or
  fuzzy matching — that would reintroduce the substitution vector the
  directory removes (§8 A-3).
- The address must additionally be a valid Kaspa bech32 address for the
  configured network, decoding to a P2PK x-only key (v0.4 `agentSpend`
  pays `20 <32-byte key> ac`).

**Instrument → vault/agent selection.** `payment_instrument.id` is an
**opaque handle minted by PolicyVault**, resolvable only PolicyVault-side
to `(vaultId, agentPk)`. It MUST NOT be a vault id, an address, an x-only
key, or anything from which one is derivable — the instrument id is
visible to the merchant and the MPP, and leaking a vault identity to
every counterparty is an avoidable privacy regression (§10 OQ-5 covers
per-merchant handle rotation).

**Deadline.** From `exp` (and `payment.execution_date.not_after` when
present), clamped to a configured ceiling. It bounds the adapter's own
wall clock only. It has **no covenant effect**: the transaction's
`lockTime` comes solely from the v0.4 period-rollover CLTV rule
(`newStart = start + periods × length`), never from protocol metadata.

**Envelope hygiene.** Total mandate size capped before parsing
(recommended 64 KiB per mandate, 256 KiB per submission); JSON nesting
depth capped (recommended 8); duplicate keys refuse; disclosure count
capped; `checkout_jwt` capped independently. Caps are applied to the
**encoded** bytes first, so an oversized submission is rejected without
ever being parsed or verified.

**The no-silent-absence rule (SD-JWT specific, and important).** SD-JWT
lets a holder present a *subset* of disclosures. A withheld disclosure
must therefore **never** be read as "no constraint was set". The adapter
requires the deployment's configured constraint slots to be *present and
disclosed*; an undisclosed required slot refuses with
`AP2_DISCLOSURE_INCOMPLETE`. Reading absence as permission would let a
shopping agent silently strip its own spending limits — the single most
obvious way to abuse selective disclosure (§8 A-18).

### 3.4 Idempotency-key derivation (a protocol retry must never duplicate a spend)

AP2 specifies no retry semantics, but unlike x402 it *does* provide a
transaction anchor: the closed Payment Mandate's `transaction_id`
(base64url hash of the associated `checkout_jwt`).

```
paymentMandateDigest = sha256_hex(
    "policyvault-ap2-mandate-digest/1\n" +
    canonicalJsonStringify({ vct, transaction_id, payee, payment_amount,
                             payment_instrument, exp }) )

idempotencyKey       = "pvap2-" + sha256_hex(
    "policyvault-ap2-idempotency/1\n" +
    canonicalJsonStringify({ transaction_id, paymentMandateDigest,
                             vaultId, agentPk }) )
```

- `canonicalJsonStringify` is `core/intent/canonical.js` — key-sorted,
  representation-independent. **Mandatory**, per the standing G-2 rule:
  a key-order-sensitive preimage "mutates" across a PostgreSQL `jsonb`
  round trip with every value byte intact. That defect was a real
  production HIGH-severity fail-closed availability bug; it must not be
  reintroduced by a new commitment.
- Domain prefixes keep these digests permanently disjoint from every
  other `sha256(canonical-json)` commitment in the codebase.
- `transaction_id` is **required**. A closed Payment Mandate without one
  refuses (`AP2_TRANSACTION_ID_INVALID`): a payment with no transaction
  anchor cannot be made idempotency-safe, and the adapter must not invent
  an anchor.
- Recurring payments under one open mandate produce **distinct**
  `transaction_id`s (one per checkout), so recurrence works naturally
  without weakening the key.
- Same `transaction_id` + same digest ⇒ verbatim replay of the original
  response. Same `transaction_id` + **different** digest ⇒ deterministic
  `409 IDEMPOTENCY_KEY_CONFLICT`, handler never called. A merchant that
  re-presents a mutated mandate under the same transaction id therefore
  cannot extract a second or larger payment.
- Sent as the `Idempotency-Key` header on the Agent API build call.
  Platform keys are already scoped per identity (`machine:<identityId>`),
  so tenants can never collide or replay each other's keys.

**Kaspa's structural double-spend answer.** Each v0.4 vault transition
consumes the single covenant UTXO named by the frozen transaction's input
0. A duplicate broadcast is either the *same txid* (node-idempotent) or a
transaction whose predecessor is already consumed (consensus rejection).
The idempotency key exists to stop double-*building* (which wastes the
agent's budget window and produces misleading audit history), not because
the chain needs help.

### 3.5 Mandate constraints → the risk layer (restrictive-only, by construction)

The user's own AP2 constraints are exactly the kind of input
`risk-adapter-spec.md` was built for, so they are mapped there rather
than into a new evaluation engine (anti-bloat rule):

```
{
  name:            "ap2-mandate-constraints",
  adapterVersion:  "<impl version>",
  contractVersion: "policyvault-risk-adapter/1",
  capabilities:    [ "x-ap2-mandate-constraints" ],   // the x- extension namespace
  evaluate(transactionIntent, organizationContext) → { verdict, reasons[] },
  timeoutMs:       <bounded>
}
```

Why this is the right home, and not a new gate:

1. **The maximum power of any adapter, correct or hostile, is `DENY` or
   `REVIEW`.** Registering an adapter grants it no authority. A mandate
   constraint therefore *cannot* become permission, no matter how it is
   authored or signed.
2. **Composition is deny-wins** and `applyRiskToPolicyDecision` has **no
   code path** that reads a risk verdict once the policy decision is
   `DENY` (property-tested across arbitrary inputs). AP2 constraints
   compose *under* covenant policy, never over it.
3. **Errors and timeouts can never resolve permissive:**
   `onAdapterError: "ALLOW"` is refused at configuration time; a hanging
   evaluation is a bounded `REVIEW`/`DENY`.
4. Every synthesized reason carries a machine code, so a mandate-driven
   refusal stays legible (the G-1 lesson).

Constraint mapping:

| AP2 constraint | Risk verdict semantics | Reason code |
|---|---|---|
| `payment.amount_range` (min/max) | `DENY` outside the range | `AP2_AMOUNT_OUT_OF_RANGE` |
| `payment.budget` (cumulative) | `DENY` when this payment would exceed the mandate's cumulative limit, tracked PolicyVault-side against settled attempts | `AP2_MANDATE_BUDGET_EXCEEDED` |
| `payment.allowed_payees` | `DENY` when the resolved payee is not in the mandate's allowed set | `AP2_PAYEE_NOT_IN_MANDATE` |
| `payment.allowed_payment_instruments` | `DENY` on mismatch | `AP2_INSTRUMENT_NOT_IN_MANDATE` |
| `payment.allowed_pisps` | `DENY` if a PISP is required (PolicyVault is never one) | `AP2_PISP_UNSUPPORTED` |
| `payment.agent_recurrence` | `DENY` beyond the frequency/occurrence limit | `AP2_RECURRENCE_EXCEEDED` |
| `payment.execution_date` (`not_before`/`not_after`) | `DENY` outside the window | `AP2_EXECUTION_WINDOW` |
| `payment.reference` (`conditional_transaction_id`) | `DENY` on a mismatched linkage | `AP2_REFERENCE_MISMATCH` |
| `checkout.allowed_merchants` | `DENY` on a payee outside the merchant set | `AP2_MERCHANT_NOT_ALLOWED` |
| `checkout.line_items` | `REVIEW` (line items are descriptive; a mismatch is a human question, not a mechanical one) | `AP2_LINE_ITEMS_MISMATCH` |
| Any unrecognized constraint `type` | **`DENY`** — an unreadable control never allows | `AP2_CONSTRAINT_UNKNOWN` |
| Any unparseable constraint value | **`DENY`** | `AP2_CONSTRAINT_UNREADABLE` |

**The floor never moves.** If an AP2 constraint is *looser* than the
covenant's agent policy — say `payment.amount_range.max` = 500 KAS while
the agent's `maxPerSpend` is 10 KAS — the covenant wins, silently and
absolutely. The mandate is a ceiling the user may lower, never a floor
they may raise. This is stated in the user-facing explanation text so the
behaviour is never surprising.

**Human-present vs human-not-present, mapped honestly.** AP2's
human-not-present mode is a *pre-authorization*, and PolicyVault already
has a stronger, chain-enforced one: the agent policy leaf (`maxPerSpend`,
`periodBudget`, `periodLengthDaa`, `agentRecipientRoot`,
`approvalThreshold`, `agentMaxFeePerTx`). An open Payment Mandate maps
onto that as an **additional** restriction. It **cannot** lower
`approvalThreshold`: a payment above the threshold requires M-of-N
covenant approvals whether or not the user pre-authorized it in AP2,
because that tier is enforced by consensus. The adapter reports this as
`requires: ["approvals"]`, not as a failure of AP2 (§4.5).

---

## 4. Mapped flow onto the PolicyVault pipeline

### 4.1 The flow

```
 Shopping Agent presents { closed Payment Mandate, closed Checkout Mandate,
                           open mandates when human-not-present }
        │
 [A] verify SD-JWT: alg/_sd_alg pinned · signatures · key binding ·
     disclosure completeness · exp/iat · checkout_hash recompute   ← adapter, pure
        │   (a verification PASS proves authorship, NOT authorization)
 [B] closed-schema normalize (§3.2/§3.3) + constraint extraction (§3.5)
        │
 [C] POST /api/v1/wallet/v4/simulate            (dry run)          ← Agent API
        │   governance · risk (incl. the AP2 constraint adapter) · planV4
        │   · assertSignerAuthorizedV4 · buildV4Transaction · deriveAndVerify
        │   — persists NOTHING, consumes NO gate
        ├─ simulation.ok:false ⇒ MANDATE REJECTION now; nothing built
        │
 [D] POST /api/v1/wallet/v4/requests + Idempotency-Key              ← Agent API
        │   the real durable build; intent manifest derived + verified
        │   fail-closed; governance/risk gates really consumed
        ├─ RISK_REVIEW_REQUIRED / approvals required ⇒ PENDING (§4.5)
        │
 [E] external signer over frozen bytes            ← Universal Signer Interface
        │   NOT the adapter. Browser-local / CLI reference signer
        │   independently re-verifies the manifest before signing.
        │
 [F] POST .../signature   then   POST .../submit                    ← Agent API
        │   builders never broadcast; finalizers never mark chain state
        │
 [G] chain proof: proveExpectedEffectV4 → receipt → reconcile        ← existing
        │   txid verified · predecessor consumed · successor observed
        │   · durable receipt persisted
        │
 [H] Payment Receipt / settlement evidence → Shopping Agent          ← adapter
```

Stages **A**, **B** and **H** are the entire adapter. **C–G are untouched
existing surfaces**, reached over the same public HTTP API a Python
client or an MCP server would use. The adapter has no in-process handle
to `buildV4Transaction`, `sdk/src/store.js`, the signer, or the node.

### 4.2 Machine identity and scopes

The adapter authenticates as a **machine identity**
(`server/src/machine-identity.js`), created by the vault-owning wallet
session, bearing a `pvmk_`-prefixed credential whose SHA-256 alone is
persisted. A resolved machine principal presents `xOnlyPubkey =
creatorXOnly`, so every existing tenancy check applies unmodified; scopes
narrow further.

**Required scopes (the complete set — grant no more):**
`read:network`, `read:vaults`, `read:requests`, `read:manifests`,
`request:build`, `request:submit`.

**Scopes the adapter credential MUST NEVER carry** — the structural,
testable form of "cannot bypass":

| Forbidden scope | What it would let the adapter do |
|---|---|
| `risk:release` | release its **own** risk `REVIEW` hold — including a hold raised by the AP2 constraint adapter itself. **Catastrophic if granted:** the mandate constraints become self-waivable |
| `governance:propose` / `:approve` / `:cancel` | manufacture or approve an authority-expanding policy change |
| `request:break-glass` | attempt `ownerPause` / `ownerRecover`, which bypass governance and risk by design |
| `organizations:manage` | rewrite the org metadata plane the risk configuration lives in |
| `vaults:reconcile` | trigger reconciliation — the sole writer of chain truth |
| `request:reject` | cancel a human's pending decision |
| `read:audit`, `read:governance`, `read:risk`, `read:organizations` | not needed; deny by default |

`/identities*` and `/wallet/dev-accounts` + `/wallet/dev-sign` are
**structurally unreachable by any machine credential regardless of
scope** (a wallet-session check, not a scope): a token can never mint,
widen, or revoke its own or a sibling's authority.

A conformance test MUST assert the credential carries *exactly* those six
scopes and that each forbidden route answers `403 SCOPE_FORBIDDEN`.

### 4.3 Dry-run use (mandatory)

The adapter **always** calls `POST /api/v1/wallet/v4/simulate` before the
real build. Simulation runs the identical pipeline —
`classifyActionV4`, `evaluateRisk` (including the AP2 constraint
adapter), `planV4`, `assertSignerAuthorizedV4`, the real
`buildV4Transaction`, and the real `deriveAndVerify` — while persisting
nothing and consuming no gate.

Why mandatory here specifically:

1. Most mandate rejections become *free* rejections: no idempotency key
   consumed, no durable request, no risk-evaluation record, no audit row.
   AP2 rejection is a first-class protocol outcome, so it must be cheap.
2. `wouldRequire { approvals, proposal, riskRelease }` is exactly what
   the CP must tell the Shopping Agent: *"this needs the human-present
   flow"* is a far better answer than a bare failure, and it is derived,
   not guessed.
3. `review.payment` gives the exact payment output and fee, so the
   adapter can assert the paid amount equals `payment_amount.amount`
   exactly (the fee is drawn from the vault's covenant fee reserve, not
   deducted from the payee's output) rather than assuming it.

Honest limitation, carried into the adapter's own docs: simulation
deliberately **skips VM preflight** (`vmPreflight: { skipped: true }`) —
real preflight validates a Schnorr signature over the frozen transaction
and a dry run has none. Fee/mass/successor correctness are exact;
signature verification is not exercised. A successful simulation must
never be reported to a merchant as "payment verified".

### 4.4 Signing — the adapter's hardest boundary

Two distinct signing concepts must never be conflated:

- **AP2 mandate signing** (ES256/JWS over mandate content) is done by the
  **user** (via the Trusted Surface) or by the **Shopping Agent** with
  its own key. PolicyVault-as-CP *verifies* mandates; it does not author
  them. If PolicyVault ever also acts as Trusted Surface (§2, OQ-3),
  mandate signing happens in the **user's own wallet/authenticator**,
  through the same non-custodial path as everything else — never in the
  adapter, never server-side.
- **Kaspa transaction signing** is done by the **Universal Signer
  Interface** signer over frozen bytes, after independent local
  re-verification of the intent manifest.

The recommended deployment gives the USI signer its **own** machine
credential with `request:sign` only, so the adapter never sees a
signature and never holds `request:sign`. The adapter-as-courier variant
(adapter additionally holds `request:sign` and relays a signature
produced elsewhere) is permitted but weaker and must be a documented
deployment choice, never the default.

In every shape the adapter **never holds a private key, never computes a
signature, and never runs a signer.**

### 4.5 How refusals surface as protocol-correct AP2 responses

As Credential Provider, PolicyVault's protocol-correct output is a
**mandate verification / authorization result** returned to the Shopping
Agent. The CP declines to authorize; it never emits a partial or
provisional authorization.

| PolicyVault outcome | AP2-facing result | Detail returned |
|---|---|---|
| SD-JWT verification failure (signature, key binding, `alg`, `_sd_alg`, expiry, `checkout_hash`) | **mandate rejected — invalid** | machine code; the mandate is *cryptographically* unacceptable |
| Disclosure incomplete (§3.3) | **mandate rejected — incomplete** | `AP2_DISCLOSURE_INCOMPLETE`; names the missing slot, never guesses |
| Normalization refusal (§3.2/§3.3) | **mandate rejected — unsupported** | e.g. `AP2_CURRENCY_UNSUPPORTED`, `AP2_INSTRUMENT_TYPE_UNSUPPORTED` |
| `payee.id` unresolvable / not allowlisted | **mandate rejected — payee not authorized** | `AP2_PAYEE_UNKNOWN` / `AP2_PAYEE_NOT_ALLOWLISTED`. **The CP never offers to add the payee** |
| Simulation `ok:false` | **mandate rejected — not authorized** | `refusalReason { status, code, message }` verbatim from the API |
| Policy/covenant `DENY` | **mandate rejected — not authorized** | final; the risk verdict is not consulted on a policy DENY |
| Risk `DENY` (incl. AP2 constraint `DENY`) | **mandate rejected — constraint violated** | composed `codes[]`, including the mandate's own constraint codes — *"your own mandate forbids this"* is the clearest possible rejection |
| Risk `REVIEW` hold | **authorization pending** | `requestId`, `manifestHash`, `evaluationId`; a human releases; the SA re-drives the **same `transaction_id`** |
| Covenant M-of-N approval required | **authorization pending — human presence required** | `requiredM`. Honest framing: the amount exceeded the agent's `approvalThreshold`; an open mandate cannot lower a covenant tier (§3.5) |
| Mandate expired mid-flow | **mandate rejected — expired** | `AP2_MANDATE_EXPIRED`; the SA must obtain a fresh mandate. Nothing is cancelled server-side |
| Node rejection / submit failure | **payment failed** | node refusal; transition-claim lifecycle handles recovery |
| **CHAIN_VERIFIED** | **payment authorized and settled** | settlement evidence (§4.6) |

Two rules that hold in every row:

1. **The adapter never returns an authorization for a payment that is not
   chain-proven.** There is no optimistic path and no provisional token.
2. **The adapter never re-attempts a rejected mandate.** A re-attempt
   requires a new mandate with a new `transaction_id`, presented by the
   Shopping Agent — which regenerates the idempotency key honestly.

Every rejection carries a deterministic machine code plus the
`core/explain` human-readable explanation (the G-1 lesson).

### 4.6 Settlement evidence → AP2 Payment Receipt

PolicyVault's success definition is unchanged and stricter than any
payment protocol's: `submitTransaction()` returning is **not** success.
Success requires txid verified, old state consumed, expected successor
observed, and a durable receipt persisted (CLAUDE.md). Only then:

| Evidence | Source (real) |
|---|---|
| `txId` | `receipts[txId]` key; frozen v1 txid = broadcast txid |
| `successorOutpoint`, `value` | `receipts.value.proof.successorOutpoint`, `.value` |
| `feeSompi` | `receipts.value.proof.actualFeeSompi` |
| `successorStateId` | `wallet_requests.value.successorStateId`; `vaults.live.stateId` after reconcile |
| `manifestHash` + verdict | `intent_manifests[manifestHash].verification` |
| `transaction_id` (AP2 anchor) | echoed verbatim from the mandate |
| `acceptingDaaScore` | **not currently persisted — OQ-7** |

**OQ-7 (DAA score), stated precisely.** `policyvault-receipt/v1` (`proof
{requestId, successorOutpoint, value, requiredFeeSompi, actualFeeSompi,
covenantId?}`) and the v4 manifest's `live {outpoint, stateId, state,
outpointValue, scriptSha256, covenantId}` carry **no DAA score**.
`blockDaaScore` *is* available on UTXO entries at proof time
(`sdk/src/wallet-submit-v4.js:134`). Emitting a DAA score therefore
requires an **additive** receipt field, an additive `live.blockDaaScore`,
or omission. **The adapter MUST NOT query the node itself** — that would
make it a second source of chain truth, which the anti-bloat rule
forbids. Until (a) or (b) lands as a separately reviewed change, the
design omits it.

**OPEN (OQ-6): the AP2 Payment Receipt schema.** The sources reviewed
confirm that a "Payment Receipt" returns to the SA, CP and Network, but
do not give its field names. The exact mapping of the evidence above onto
AP2 receipt fields cannot be specified without that schema, and this
document does **not** invent one.

### 4.7 Audit-correlation record shape

One additive create-only record per attempt, following
`audit-correlation-spec.md` §5: correlation fields lifted to indexed
columns, raw protocol metadata preserved verbatim, no secrets.

```
{
  schema:        "policyvault-ap2-attempt/v1",
  transactionId: <base64url, from the mandate>,   -- row key (per network)
  idempotencyKey:<"pvap2-" + 64-hex>,
  mandateDigest: <64-hex>,

  -- correlation spine (audit-correlation-spec §3)
  requestId:     <uuid> | null,
  manifestHash:  <64-hex> | null,
  txId:          <64-hex> | null,
  vaultId:       <64-hex>,
  networkId:     <string>,
  agentPk:       <64-hex>,
  actorXOnly:    <64-hex>,          -- the machine identity's creatorXOnly

  -- the normalized proposal (what PolicyVault actually decided on)
  normalized: {
    payAmountSompi: <canonical digits>,
    recipientXOnly: <64-hex>,
    deadlineEpochSeconds: <integer>
  },

  -- what the CRYPTO proved (authorship), kept separate from what was DECIDED
  verification: {
    mandates: [ { vct, alg, sdAlg, signatureValid, keyBindingValid,
                  disclosuresPresented: [<slot ids>], expiresAt } ],
    checkoutHashVerified: boolean
  },

  -- constraint evaluation (restrictive-only), from the risk pipeline
  constraints: {
    evaluated: [ { type, verdict, code } ],
    riskDecision: "ALLOW"|"REVIEW"|"DENY",
    riskCodes: [ ... ]
  },

  -- RAW PROTOCOL METADATA, preserved verbatim, read by nothing
  protocol: {
    protocol:  "ap2",
    specVersion: "0.2",
    paymentMandateRaw:  <compact SD-JWT string, size-capped>,
    checkoutMandateRaw: <compact SD-JWT string, size-capped>,
    openMandatesRaw:    [ <compact SD-JWT strings> ] | null,
    payeeRaw:           { id, name, website },
    riskDataRaw:        <verbatim> | null
  },

  outcome: {
    status: "REJECTED"|"PENDING"|"EXPIRED"|"FAILED"|"SETTLED",
    stage:  "verify"|"normalize"|"simulate"|"build"|"sign"|"submit"|"prove"|"receipt",
    codes:  [ <UPPER_SNAKE machine codes> ],
    at:     <ISO timestamp>       -- time lives HERE, never in a manifest
  }
}
```

Rules carried over verbatim from the parent specs:

- **Append-only / create-only** (`createExclusive`), keyed by
  `transactionId`. Never updated in place except by appending a new
  outcome-transition audit event.
- **`protocol.*` is quarantined by construction.** Nothing in the
  decision path reads it. A conformance test asserts that mutating any
  byte under `protocol.*` changes no PolicyVault decision and no
  `manifestHash` — the manifest hash is a function of the *normalized*
  intent only.
- **`verification.*` is evidence, never authority.** It records that a
  signature checked out; it must never be read anywhere as permission.
  A stored verdict is *what the verifier said then* — any consumer
  needing truth *now* re-runs the pure verification.
- Correlation walk: `ap2 transaction_id → requestId → manifestHash →
  txId → successor outpoint/stateId → chain`.
- **No secrets.** No machine credential, no credential hash, no
  `Idempotency-Key` header value, no session material. Mandates are
  signed *public* artifacts (a JWS signature is a public artifact), but
  they may carry personal shopping data — retention is therefore an
  explicit owner decision (§10 OQ-8), and the design defaults to storing
  the compact SD-JWT **as presented** (i.e. only the disclosures the
  holder chose to reveal), never re-expanded.
- **Never backfilled.** No tool may synthesize an AP2 attempt record for
  a payment that predates the adapter.

---

## 5. What the adapter must NEVER do

Normative prohibitions, each with the mechanism that makes it structural.

1. **NEVER hold, derive, import, generate, cache, or log a private key,
   seed phrase, or signature.** Mechanism: no signer dependency, no
   wallet library; the hosted layer holds no key material at all
   (`docs/hosted-threat-model.md` §3).
2. **NEVER sign a Kaspa transaction, and never sign an AP2 mandate on a
   user's behalf** (§4.4).
3. **NEVER use a privileged path.** No import of `sdk/src/**`,
   `server/src/**`, or `core/**` financial modules; no direct database
   handle; no node RPC client. Mechanism: separate process + the
   dependency-direction test (§7.3).
4. **NEVER treat a valid mandate signature as authorization** (§3.1).
   Verification proves authorship. Authority comes from the covenant and
   the signer, and from nowhere else.
5. **NEVER let a mandate constraint be permissive.** Constraints enter
   only through the risk layer, whose maximum power is `DENY`/`REVIEW`
   and whose composition is deny-wins (§3.5).
6. **NEVER read an undisclosed SD-JWT slot as "unconstrained"** (§3.3
   no-silent-absence rule).
7. **NEVER resolve a destination from mandate content.** Destinations
   come from the PolicyVault-side payee directory and must already be
   allowlisted (§3.3). No name matching, no `website` parsing, no URL
   dereference, no redirect following.
8. **NEVER add, widen, or edit a recipient allowlist, budget, cap,
   approval threshold, approver set, agent registry entry, or the payee
   directory.** Every one is a governance-classified mutation requiring
   the owner's wallet signature (governance-spec §4, §5.1).
9. **NEVER bypass, weaken, pre-empt, or self-release policy, governance,
   risk, or approvals.** Mechanism: §4.2's scope set makes `risk:release`,
   `governance:*`, and `request:break-glass` unreachable; and
   `applyRiskToPolicyDecision` has no code path reading a risk verdict
   once policy is `DENY`.
10. **NEVER convert currency or units.** No oracle, no quote, no FX, no
    rounding, no "approximate KAS equivalent". Minor unit == sompi under
    the declared instrument, or refuse (§6.3).
11. **NEVER take custody.** No pooled balance, no adapter-controlled
    address, no escrow, no settlement account, no netting.
12. **NEVER act as Merchant, Merchant Payment Processor, Network, or
    Shopping Agent** (§2). PolicyVault charges nothing and processes no
    one else's payments.
13. **NEVER issue a delegated-pull credential.** See §6.4 — there is no
    Kaspa primitive that lets a counterparty later move vault funds, and
    emulating one would move a spend decision outside PolicyVault's
    pipeline.
14. **NEVER report settled before chain proof** (§4.6).
15. **NEVER parse the `checkout_jwt`, line items, or `risk_data` for
    amounts, addresses, or authorizations.** They are opaque
    audit-only blobs; AP2 itself is agnostic to `checkout_jwt` contents.
16. **NEVER let an LLM, a tool result, or free text reach a consensus
    value.** The adapter's input is closed-schema, cryptographically
    verified JSON. Merchant-authored strings (`payee.name`, product
    `title`, `description`) are prime prompt-injection carriers and are
    stored, never interpreted.
17. **NEVER widen the network.** Cross-network material never broadcasts;
    the config==request==manifest==node equality chain is enforced
    already and the adapter adds a checkpoint, not an exception.
18. **NEVER re-attempt a rejected mandate** or mint its own
    `transaction_id` (§3.4, §4.5).

---

## 6. Kaspa-specific gaps (honest)

### 6.1 The gap

**AP2 lists no blockchain destination field, no crypto-native amount
representation, and no Kaspa payment instrument.** Its money model is
`{amount: integer minor units, currency: ISO 4217}` — a card/bank-rails
shape. Third-party commentary describes AP2 as supporting "stablecoins
and real-time bank transfers", but the specification pages reviewed
enumerate **no** normatively supported rails; the only extensibility
statement is the payment-instrument `type` sentence (§1.5).

### 6.2 The extension point (real, documented, and narrow)

> *"AP2 is agnostic to the particular payment instrument used. New
> Payment Instruments are supported by defining a unique `type` in the
> Payment Instrument JSON object."*

That is the whole documented mechanism. There is **no published registry,
no acceptance criteria, no conformance process, and no contribution
workflow** for a new instrument type comparable to x402's three-PR chain
process. Whether an instrument type must be registered anywhere, and with
whom (Google? the FIDO Alliance, post-donation?), is **OPEN** (OQ-9).

### 6.3 Proposed Kaspa payment instrument (design only — NOT proposed upstream)

| Item | Proposal | Status |
|---|---|---|
| `payment_instrument.type` | a unique reverse-DNS-style literal, e.g. `org.policy-vault.kaspa.covenant-vault.v1` | **proposed; exact literal is OQ-9** |
| `payment_instrument.id` | an **opaque PolicyVault-minted handle** → `(vaultId, agentPk)`, resolvable only PolicyVault-side. Never a vault id, address, or key | proposed |
| `payment_instrument.description` | human label only; audit-only | proposed |
| Minor unit | **1 sompi**, declared normatively by the instrument type — the reason the adapter never converts | proposed |
| `payment_amount.currency` | a non-ISO-4217 token pinned by the instrument type (e.g. `"KAS"`). **This deviates from the spec's ISO 4217 statement** and is the single largest interop risk | **UNVERIFIED / OPEN (OQ-4)** |
| Destination | **not carried in AP2 at all** — resolved PolicyVault-side (§3.3). A property, not a gap |
| Settlement evidence | Kaspa txid + successor outpoint + fee (+ DAA, OQ-7), returned in the Payment Receipt (schema OQ-6) | proposed |

**The currency problem, stated without hand-waving.** `payment_amount`
requires an ISO 4217 `currency`. KAS has no ISO 4217 code. Three
candidate resolutions, and the design's position on each:

1. **Non-ISO currency token (`"KAS"`) pinned by the instrument type.**
   Simplest, honest, keeps the amount exact and integral. **Deviates
   from the spec text.** Merchants/MPPs that validate `currency` against
   an ISO 4217 table will reject it. **This is the design's choice**,
   with the deviation stated openly rather than hidden.
2. **Fiat-denominated mandate + a KAS quote.** Would require the adapter
   to convert an ISO 4217 amount into sompi at some rate. **REJECTED
   OUTRIGHT.** It introduces an oracle into the financial path, makes the
   paid amount a function of a price feed the user never signed,
   contradicts "no floats / integer sompi only", and would let a
   quote source (or a compromised one) change how much leaves the vault.
   No amount of care makes this safe inside an adapter.
3. **A mandate extension carrying an exact sompi amount alongside a fiat
   display amount.** Plausible and strictly better than (2) *if* the
   sompi amount is inside the user-signed content, so the user signed the
   exact number of sompi. Still needs an extension mechanism AP2 does not
   currently document for this. **OPEN (OQ-4).**

**Hard rule regardless of resolution:** the adapter **never** converts.
If it cannot read an exact, user-signed, integral sompi amount, it
refuses.

### 6.4 Why AP2-over-Kaspa must be pay-first (the same finding as x402)

AP2's card-shaped flow ends with the MPP *processing* a payment against a
credential the CP supplied — a **pull**. There is no Kaspa primitive that
lets a counterparty later move vault funds, and PolicyVault must never
emulate one: handing out an artifact someone else can redeem is exactly
the delegated-spending authority the covenant exists to bound, and it
would place a spend decision outside PolicyVault's pipeline (anti-bloat
rule).

Therefore PolicyVault-as-CP does not issue a redeemable credential. It
**settles on chain first** and returns **settlement evidence** (a proven
txid) in place of a pull token. Consequences, stated plainly:

- The merchant is paid before delivering. That is **counterparty risk,
  not custody or consensus risk**, and it is bounded by exactly the
  mechanisms PolicyVault already enforces: per-spend cap, period budget,
  recipient allowlist (a merchant not in the payee directory *and* the
  allowlist cannot be paid at all), and approval tier.
- Chargeback/reversal semantics that card rails assume **do not exist**.
  A Kaspa transaction is final. Any AP2 dispute flow that presumes
  reversal is unsupported, and must be documented as such rather than
  approximated.
- **OPEN (OQ-10):** whether an AP2 MPP will accept "here is a settled
  txid" in place of a processable credential at all. This may be the
  deepest structural mismatch between AP2's model and a UTXO chain.

### 6.5 Ecosystem-acceptance risks — all OPEN

- **OPEN:** No AP2 merchant, MPP, or credential-provider implementation
  supports Kaspa today. The adapter interoperates only with counterparties
  explicitly configured to accept the proposed instrument type. **The
  adapter must not be described as "AP2 compatible" without this
  qualification** — that would collapse the claim ladder.
- **OPEN:** The non-ISO `currency` deviation (§6.3) will be rejected by
  strict validators.
- **OPEN:** Whether v0.1 artifacts remain in circulation and whether
  refusing them is a practical interop problem (§1.1).
- **OPEN:** Transport. With the A2A AgentCard extension dropped in v0.2
  and agent-to-agent delegation out of scope, *how* a Payment Mandate
  reaches a CP is unspecified. Any transport the adapter exposes is a
  PolicyVault invention until AP2 specifies one (OQ-2).
- **OPEN:** Post-FIDO-donation governance. The protocol changed models
  once already, between v0.1 and v0.2, in ~7 months. A v0.3 could change
  them again. This argues strongly for the separate-process deployment
  boundary (§7).

---

## 7. Degradation and deployment boundary

### 7.1 The addendum requirement

> "No optional integration may make the core depend on it. If x402, AP2,
> MCP, mobile, notification providers, or any other peripheral component
> is unavailable, PolicyVault's core financial safety and existing wallet
> functionality MUST remain correct and fail safely."

### 7.2 Recommendation: separate module, separate process, API client

**Normative: `integrations/ap2/` — its own module, deployed as its own
process, communicating with PolicyVault exclusively over the public Agent
API (HTTPS, or loopback HTTP when co-located) using a scoped machine
bearer credential.**

Rationale:

1. **Structural unprivilege.** A separate process cannot reach a
   privileged path — it has no in-process handle to `buildV4Transaction`,
   `sdk/src/store.js`, the migration runner, the RPC client, or the
   signer. §5's prohibitions become facts about the process boundary
   rather than promises about code review.
2. **Cryptographic-library isolation — sharper for AP2 than for x402.**
   The AP2 adapter must run SD-JWT/JWS verification: signature
   verification, selective-disclosure processing, JWK handling, and
   base64url parsing over **attacker-supplied** input. That is a
   historically rich vulnerability class (algorithm confusion, `alg:
   none`, key-injection via embedded JWK, disclosure-digest collisions,
   parser differentials). It must not run in the process that serves
   wallet requests. This is the single strongest argument in either
   adapter spec for process separation.
3. **Failure isolation.** An unhandled exception, an OOM from a
   pathological disclosure set, or a hung outbound call cannot consume
   the server's request semaphores, rate-limiter budget, or event loop.
   `server/src/limits.js`'s protections are process-local and the launch
   pin is one app replica; adding untrusted-peer crypto work into that
   process contradicts it.
4. **Blast radius on compromise.** A compromised adapter is a compromised
   *client* — bounded by tenancy, by six scopes, by the covenant's
   caps/allowlist/approval tier, and by holding no key. It cannot become
   a compromised server.
5. **Independent lifecycle.** AP2 changed its entire mandate model
   between v0.1 and v0.2 and moved to a new standards body. It must be
   updatable, restartable, and *removable* without redeploying the
   financial core or touching the frozen production image identity.
6. **Honest capability advertisement.** `GET /api/v1/capabilities` is
   generated from live config; `features.ap2` is honestly `false` when
   the adapter is not deployed.

**Rejected: in-server route namespace (`/api/v1/integrations/ap2/*`).**
Permitted only as a documented, flag-gated (`default: off`) self-hosted
convenience, and **only under all four constraints**: (a) the module
lives in `integrations/ap2/` and imports nothing from `sdk/src/**` or
`server/src/**` except pure schema constants; (b) it reaches PolicyVault
over **loopback HTTP with a machine credential** — never by direct
function call; (c) every route is wrapped so no adapter exception can
propagate into the core request path; (d) outbound calls and SD-JWT
verification carry hard timeouts, memory caps, and a dedicated
concurrency budget that cannot borrow from the core semaphores. Even
then, hosted production uses the separate process — and given §7.2(2),
the in-process variant is discouraged more strongly for AP2 than for
x402.

### 7.3 Degradation semantics (what "adapter down" actually means)

| Failure | Effect on PolicyVault core |
|---|---|
| Adapter not deployed | `features.ap2: false`; every other surface byte-identical |
| Adapter crashes at any point | **Zero.** No core route, migration, reconciliation, signing, or web flow depends on it |
| Adapter crashes **after** `POST .../submit` | The durable request, transition claim, submission claim, and reconciliation recover the truth exactly as for any other client. **The adapter is not on the recovery path.** The payment completes or fails on chain regardless; the *AP2 receipt* is what is lost, and a human can reconstruct it from `receipts[txId]` |
| Adapter credential revoked mid-flight | Revocation is checked at resolution time and invalidates every credential the identity minted, immediately. In-flight PolicyVault work already accepted continues under normal pipeline rules; no new adapter call is authorized |
| AP2 constraint risk adapter unavailable/hanging | **Fails restrictive by construction:** `onAdapterError` may be `REVIEW` or `DENY` and can never be configured to `ALLOW`; a hang is a bounded `REVIEW`/`DENY` |
| Hostile Shopping Agent / merchant | Bounded by the adapter's own timeouts, size caps, and separate process budget. Cannot reach core semaphores |
| Adapter compromised | Bounded by tenancy + six scopes + covenant. Worst case: it can *propose* spends within the agent's existing caps to *already-allowlisted, already-directory-listed* payees, and can refuse to pay. It cannot exceed a budget, add a payee, release a risk hold, approve a proposal, change a signer, or move funds anywhere new |

**Mechanical enforcement (required, not aspirational):** a
dependency-direction test that fails the build if any file under
`core/**`, `sdk/src/**`, or `server/src/**` imports anything under
`integrations/**`, and if any file under `integrations/ap2/**` imports
anything under `sdk/src/**` or `server/src/**`. Per the efficiency
doctrine, this is a deterministic test, not a review convention.

### 7.4 Human escalation

Paid-but-not-delivered, and any integrity alarm (a stored manifest whose
recomputed hash ≠ its row key), are **human-notification events** — never
auto-retried and never auto-remediated by the adapter.

---

## 8. Adversarial test plan

The addendum's matrix, applied concretely. Every case is a
**policy-invalid adversarial test transaction / authorized
negative-validation case** run against PolicyVault's own adapter and,
where covenant-relevant, against a real node — never framed as an attack.

Per the addendum: *"The agent conformance suite MUST exercise the REAL
reference MCP, JS/TS, Python, and protocol-adapter paths (not mocks)."*
These run against the real adapter process, the real Agent API, real
PostgreSQL, and (for A-13/A-14) a live testnet-10 node.

| # | Class | Case | Required outcome |
|---|---|---|---|
| A-1 | Destination substitution | Mandate names a `payee.id` absent from the payee directory | Reject; **the adapter never offers to add it** |
| A-2 | Destination substitution | `payee.id` present in the directory but resolving to a key **not** in the agent's allowlist | Reject pre-build; and if forced past the adapter, the covenant rejects (Merkle membership) |
| A-3 | Destination substitution | `payee.name`/`payee.website` impersonate an allowlisted merchant while `payee.id` is different; and the reverse | Resolution uses `payee.id` **only**; name/website never influence it |
| A-4 | Destination substitution | Two mandates share a `payee.id` but disagree on name/website | Identical destination; the difference is audit metadata only |
| A-5 | Destination substitution | Payee directory entry mutated **between** simulate and build | Idempotency fingerprint conflict `409`; handler never called |
| A-6 | Amount mutation | `payment_amount.amount` as `1.5`, `1e8`, `"100"`, `-1`, `0`, `2**53`, `MAX_SOMPI+1`, `null`, absent | Reject each with a distinct code; **no float ever constructed** |
| A-7 | Amount mutation | `payment_amount.currency` = `"USD"`, `"EUR"`, `"usd"`, `"KAS "`, `"KA S"`, absent | Reject each (`AP2_CURRENCY_UNSUPPORTED`); **no conversion attempted, ever** |
| A-8 | Amount mutation | Amount raised on a re-presentation under the same `transaction_id` | `409 IDEMPOTENCY_KEY_CONFLICT`; no second spend |
| A-9 | Amount mutation | Amount inside cap but pushing cumulative spend over `periodBudget`; and over the mandate's own `payment.budget` | Covenant refuses the first independently; the constraint adapter `DENY`s the second |
| A-10 | Amount mutation | Amount > agent `approvalThreshold` while the open mandate "pre-authorizes" it | `pending` + `requires: ["approvals"]`. **An open mandate cannot lower a covenant tier** — the headline assertion for §3.5 |
| A-11 | Amount mutation | Line-item `Product.price`/`currency` disagree with `payment_amount` | `payment_amount` alone is the proposal; the mismatch produces `REVIEW` via `checkout.line_items`, never a different paid amount |
| A-12 | Replay | Same `transaction_id` + same digest, replayed 10× serially | Exactly one durable request, one txid; 9 verbatim replays |
| A-13 | Replay | Same `transaction_id` + same digest, fired **concurrently** ×2 | Exactly one `wallet_requests` row (mirrors the proven `postlaunch-idempotency-server.test.js` property) |
| A-14 | Replay | Broadcast the identical frozen transaction twice | Same txid ⇒ node-idempotent; or predecessor already consumed ⇒ consensus rejection. Asserted on a real node |
| A-15 | Replay | A settled mandate re-presented to a *second* PolicyVault deployment / different vault | Distinct `(vaultId, agentPk)` produce a distinct idempotency key, so this is a genuinely new spend — but it must still pass every gate independently, and the constraint adapter's `payment.budget` accounting must be **per-mandate**, not per-vault (asserted) |
| A-16 | Replay | Replay a *user-signed open mandate* long after its `exp` | Reject (`AP2_MANDATE_EXPIRED`); no skew tolerance beyond the configured bound |
| A-17 | Replay | Replay a *closed* mandate whose linked open mandate has been superseded | `payment.reference` linkage mismatch ⇒ `DENY` |
| A-18 | **Downgrade (SD-JWT)** | Present the mandate with constraint disclosures **withheld** — `payment.amount_range`, `payment.budget`, `payment.allowed_payees` omitted from the disclosure set | `AP2_DISCLOSURE_INCOMPLETE`. **Absence is NEVER read as "unconstrained".** The single most important test in this table |
| A-19 | Downgrade (SD-JWT) | `_sd_alg` absent; `_sd_alg` = a weak/unknown digest; `_sd_alg` differing between mandates | Reject each; **no "SHA-256 if absent" default for inbound** |
| A-20 | Downgrade (JWS) | `alg: "none"`; symmetric `alg` with the public key as the MAC secret (algorithm confusion); embedded `jwk`/`jku`/`x5u` header key injection; unknown `alg` | Reject each; algorithm pinned, never taken from the token; embedded key material never trusted |
| A-21 | Downgrade (protocol) | v0.1 `IntentMandate`/`CartMandate`/`PaymentMandate` W3C VCs presented to a v0.2 adapter | `AP2_VCT_UNSUPPORTED`; **never translated** |
| A-22 | Downgrade (protocol) | `vct` = `"mandate.payment.2"`, `"mandate.payment"`, `"Mandate.Payment.1"`, a Unicode confusable, or absent | Reject each; exact-match only, per the spec's own MUST |
| A-23 | Downgrade | Closed mandate signed by the **agent's** key presented as if human-present; open mandate missing entirely in an autonomous flow | Reject — the human-present/human-not-present distinction must be established from what was actually presented, never assumed |
| A-24 | Malformed / oversized | 64 MiB mandate; 100 000 disclosures; 10 000-deep nesting; invalid base64url; base64url of non-JSON; duplicate claims; NUL bytes; invalid UTF-8; `__proto__`/`constructor`/`prototype` claims | Reject **before** verification where the size cap applies; no memory blowup; no prototype pollution; adapter stays responsive; measured, not asserted |
| A-25 | Malformed | Disclosure-digest collision attempt; a disclosure not referenced by any `_sd` digest; a duplicate disclosure | Reject each |
| A-26 | Malformed | `checkout_jwt` disclosed but `checkout_hash` mismatched; `checkout_hash` present with `checkout_jwt` withheld | Mismatch rejects; withheld-with-hash is accepted **only** as an opaque correlation anchor and is never parsed |
| A-27 | Metadata-overrides-chain-truth | `payee.name`, product `title`, `description`, `risk_data`, `checkout_jwt` contents carry text asserting a different amount, a different recipient, "already approved", "risk cleared", "policy waived", or prompt injection targeting a downstream LLM | Byte-identical PolicyVault decision and byte-identical `manifestHash` vs the same case with empty metadata. **The headline test for surface 28** |
| A-28 | Metadata-overrides-chain-truth | Merchant returns a receipt claiming a different amount/txid than PolicyVault proved | PolicyVault's own record is authoritative; the merchant's claim is stored under `protocol.*` and never alters `outcome.status` |
| A-29 | Chain truth | Node accepts a transaction whose payment output differs from the mandate (deliberately hand-built) | The **manifest verifier** refuses at `outputs-explained` / `request-equations` before signing; the adapter never reaches settlement |
| A-30 | Constraint bypass | A constraint with an unknown `type`; a constraint whose value is unparseable; a constraint adapter that throws, hangs, or returns a malformed verdict | **`DENY`/`REVIEW` in every case — never `ALLOW`.** `onAdapterError: "ALLOW"` refused at configuration time |
| A-31 | Constraint bypass | Adapter attempts `POST /risk/evaluations/:id/release` on its own hold | `403 SCOPE_FORBIDDEN` (no `risk:release`) |
| A-32 | Capability escalation | Adapter attempts `governance:approve`, `request:break-glass`, `organizations:manage`, `vaults:reconcile`, `POST /identities`, `POST /wallet/dev-sign` | `403` for each; the last two forbidden **regardless of scope** |
| A-33 | Tenancy | Mandate references an instrument handle resolving to another wallet's vault | `404` (existence hidden), matching `tenancy.js` discipline |
| A-34 | Signer substitution | Adapter attempts to name a different `signerAddress`/`agentPk` than the vault's registered agent | `assertSignerAuthorizedV4` refuses at build **and again** at finalize |
| A-35 | Approval replay | A covenant approval signature collected for mandate A re-presented for mandate B | Refused — approvals are over the frozen covenant input of a specific transaction |
| A-36 | Stale state | Mandate honored against a vault state that advanced between simulate and build | Frozen bytes bind the exact predecessor outpoint; a stale predecessor cannot confirm |
| A-37 | Concurrency budget race | N concurrent **distinct** mandates that individually fit the cap but jointly exceed `periodBudget`, and separately jointly exceed the mandate's `payment.budget` | Neither aggregate is exceeded. The covenant enforces the first (asserted against a real node); the constraint adapter's accounting must be race-safe for the second |
| A-38 | Concurrency | N concurrent mandates racing for the single covenant UTXO | At most one succeeds per state; the rest refuse cleanly with a stale-predecessor error, no stranded claims |
| A-39 | Fee manipulation | Mandate content attempts to influence fee, `lockTime`, `computeBudget`, or `periodsElapsed` | Rejected as unknown claims; none are ever adapter-controllable |
| A-40 | Degradation | Kill the adapter process mid-flow at each of the 8 stages; kill it after broadcast | Core financial safety unaffected at every stage; post-broadcast truth recovered by reconciliation with **no** adapter involvement |
| A-41 | Degradation | Hostile Shopping Agent: 1-byte-per-minute submission, 10 GB body, pathological disclosure fan-out | Bounded by adapter timeouts/caps; core semaphores and rate limits untouched (measured) |
| A-42 | Dependency direction | Static check: any `core/**`, `sdk/src/**`, `server/src/**` import of `integrations/**`, or `integrations/ap2/**` import of `sdk/src/**` | Build fails |
| A-43 | Audit integrity | Mutate any byte under `protocol.*` or `verification.*` in a stored attempt record | No decision changes; `manifestHash` unchanged; the read-side manifest re-hash still matches its row key |
| A-44 | Storage round-trip (G-2 class) | Write an attempt record + mandate digest to **live PostgreSQL**, read back, recompute both digests | Byte-equal digests after `jsonb` key reordering. **Must run against live PG** — a JSON-backend suite cannot catch a jsonb representation defect |

---

## 9. Implementation status

| Component | Claim |
|---|---|
| This specification | **DESIGNED** |
| Kaspa payment-instrument type (upstream) | NOT DEFINED, NOT PROPOSED |
| `integrations/ap2/` adapter | NOT IMPLEMENTED |
| `ap2-mandate-constraints` risk adapter | NOT IMPLEMENTED |
| Payee directory (config surface + governance treatment) | NOT DESIGNED IN DETAIL — see OQ-11 |
| Additive DAA-score evidence field (§4.6 OQ-7) | NOT IMPLEMENTED — separate reviewed change |
| `policyvault-ap2-attempt/v1` store + migration | NOT IMPLEMENTED |
| Adversarial suite §8 | NOT WRITTEN |

Nothing here is IMPLEMENTED, UNIT-TESTED, VM-VERIFIED, TESTNET-VERIFIED,
PRODUCTION-HARDENED, EXTERNALLY REVIEWED, or AUDITED.

---

## 10. Open questions

- **OQ-1 — v0.1 support.** Refuse v0.1 W3C-VC mandates outright
  (current design), or add a separate, explicitly-coded v0.1 normalizer?
  Leaning **refuse**: the model changed too much to reinterpret safely,
  and no Kaspa-capable v0.1 counterparties exist either. Depends on
  whether v0.1 is formally deprecated (**UNVERIFIED**, §1.1).
- **OQ-2 — transport.** With the A2A AgentCard extension dropped in v0.2
  and agent-to-agent delegation out of scope, what transport does a
  Shopping Agent use to reach PolicyVault-as-CP? Any answer the adapter
  ships is a PolicyVault invention until AP2 specifies one. Candidate:
  reuse the Agent API surface with an AP2-specific route namespace,
  clearly labelled non-normative.
- **OQ-3 — claim the Trusted Surface role?** PolicyVault's
  browser-local intent verification is arguably a *stronger* TS than most
  AP2 deployments will field. Claiming the role means PolicyVault renders
  mandates to users and obtains consent — a real product surface with
  real UX and review obligations. Owner/product decision.
- **OQ-4 — the currency representation.** Non-ISO `"KAS"` token (current
  design, deviates from spec), or a mandate extension carrying an exact
  user-signed sompi amount? **Fiat + quote is rejected outright** (§6.3).
  Blocks any real merchant integration.
- **OQ-5 — instrument-handle privacy.** Should the opaque
  `payment_instrument.id` be **per-merchant** (unlinkable across
  merchants) or stable per vault (simpler, correlatable)? Leaning
  per-merchant.
- **OQ-6 — AP2 receipt schema.** The exact Payment Receipt / Checkout
  Receipt field names were not recoverable from the sources reviewed.
  Needed before §4.6's mapping can be finalized. **Do not invent it.**
- **OQ-7 — DAA score in settlement evidence.** Additive
  `blockDaaScore` on `policyvault-receipt/v1` at `proveExpectedEffectV4`
  time, additive `live.blockDaaScore` at reconcile time, or omit?
  Design currently omits. Coordinator/owner decision. *(Identical to the
  x402 spec's OQ-2 — resolve once, for both.)*
- **OQ-8 — mandate retention.** Mandates may carry personal shopping
  data (line items, merchant identities). Store the full compact SD-JWT
  as presented (current design), store digests only, or make retention
  org-configurable? Interacts with `risk-adapter-spec.md` OQ-3 (evidence
  retention).
- **OQ-9 — instrument-type registration.** AP2 documents no registry or
  acceptance process for a new `payment_instrument.type`. Is registration
  required, and with whom — Google, or the FIDO Alliance post-donation?
  The exact reverse-DNS literal is a guess in this document.
- **OQ-10 — pay-first vs pull.** Will an AP2 MPP accept a settled Kaspa
  txid in place of a processable credential (§6.4)? This may be the
  deepest structural mismatch between AP2's model and a UTXO chain, and
  it is not something the adapter can resolve unilaterally.
- **OQ-11 — payee directory governance.** The `payee.id → x-only key`
  directory is deployment configuration that determines *who can be
  paid*. It is **strictly weaker** than the covenant allowlist (a
  directory entry means nothing unless the key is also allowlisted), so
  it is not a financial authority — but should adding a directory entry
  nevertheless be a governed, audited action rather than plain config?
  Leaning **audited config with an explicit UI review step**, not a
  governance proposal, precisely because the covenant allowlist is the
  real gate and adding a second governance ceremony would imply the
  directory is one.
- **OQ-12 — upstream engagement.** Should PolicyVault propose the Kaspa
  instrument type upstream (a public, named, ecosystem-facing act), and
  if so, when relative to the still-CLOSED hosted/PostLaunch source
  publication gate? **Owner decision, not engineering.** The publication
  gate is explicit: no public repo, push, or upload is authorized for
  this lane. *(Identical to the x402 spec's OQ-7 — resolve once.)*

---

## Sources

- [ap2-protocol.org — home](https://ap2-protocol.org/)
- [ap2-protocol.org — AP2 specification (v0.2)](https://ap2-protocol.org/ap2/specification/)
- [ap2-protocol.org — Checkout Mandate](https://ap2-protocol.org/ap2/checkout_mandate/)
- [ap2-protocol.org — Payment Mandate](https://ap2-protocol.org/ap2/payment_mandate/)
- [ap2-protocol.org — A2A extension for AP2 (v0.1 lineage)](https://ap2-protocol.org/a2a-extension/)
- [google-agentic-commerce/AP2 (reference implementation, Apache-2.0)](https://github.com/google-agentic-commerce/AP2)
- [Google Cloud — Announcing Agent Payments Protocol (AP2)](https://cloud.google.com/blog/products/ai-machine-learning/announcing-agents-to-payments-ap2-protocol)
- [Cloud Security Alliance — Secure Use of the Agent Payments Protocol (AP2)](https://cloudsecurityalliance.org/blog/2025/10/06/secure-use-of-the-agent-payments-protocol-ap2-a-framework-for-trustworthy-ai-driven-transactions)
- [An Illustrated Guide to AP2 (v0.1 three-mandate model)](https://arthurchiao.art/blog/ap2-illustrated-guide/)
- [Zero-Trust Runtime Verification for Agentic Payment Protocols: Mitigating Replay and Context-Binding Failures in AP2 (arXiv)](https://arxiv.org/pdf/2602.06345)
