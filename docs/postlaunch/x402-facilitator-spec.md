# PolicyVault x402 FACILITATOR — Design Specification (REVISION 3 — DESIGN FROZEN)

**Claim label: DESIGNED. Freeze status: FROZEN — "X402 FACILITATOR DESIGN
FREEZE — OWNER AUTHORIZED + COMPLETE" (2026-09-02; record:
`x402-facilitator-design-freeze.md`, which pins this revision's sha256
and the frozen constants).** This document specifies the DESIGN of the
`pv-x402-kaspa-exact-upfront/1` facilitator; the implementation status of
D3–D6 (IMPLEMENTED / UNIT-TESTED / TESTNET-VERIFIED / …) is tracked ONLY
in `x402-facilitator-program.md`, never here. No production file,
migration, covenant byte, configuration, or published artifact is changed
by this document. **No covenant change is required; the frozen v0.5 bytes
(`c693aeff…4197dd9`) remain untouched.** Any change to the frozen
semantics of `/1` is a NEW scheme / policy / profile version or an
explicit freeze-reopen decision by the owner — never an in-place edit.

Incorporated by reference (not weakened): `x402-adapter-spec.md` §1
(x402 v2 objects), §3 (normalized intent), §4.8 (attempt records), §6.3
(proposed Kaspa scheme), §6.4 (upfront flow — a delegated pull is never
emulated). Program record: `x402-facilitator-program.md`.

Revision 2 (2026-09-02, adversarial review pass): explicit output index,
requirement/resource binding digest, destination-reuse refusal, DAA
validity window, versioned settlement policy, state ladder AUTHORIZED /
VERIFIED / CHAIN_SEEN / CHAIN_VERIFIED, token path with mandatory
transaction bytes and independent conservation, durable-claim atomicity,
race semantics, full hostile matrix with dispositions.

Revision 3 (2026-09-02, design freeze): every freeze-time question is
resolved by owner decision — OQ-F1 `MIN_DEPTH_DAA` default 100 / hard
floor 20 (A); OQ-F2 `MAX_WINDOW_DAA` 36,000 (B); OQ-F3 the PROVISIONAL
Kaspa network identifiers `kaspa:mainnet` / `kaspa:testnet-10` (§2.1);
OQ-F4 asset literals `KAS` | `pvad1:<descriptor-hash>` (G); OQ-F5 single
instance, PostgreSQL unique-constraint claims before any scaling, hosted
operation a separate owner gate (E/F); OQ-F6 payload binding NOT part of
`/1` (C); OQ-F7 facilitator-issued API key over HTTPS with a dedicated
resource-server principal model, mTLS optional future hardening (§14.1).
Implementation-level pins that the wire contract left open are fixed in
§17 (requirement-digest domain, `transactionHex` carriage encoding, token
observation address, credential format, HTTP status mapping).

---

## 0. Summary

The proposed Kaspa x402 scheme is **`exact` + `extra.paymentFlow:
"upfront"`**: the payer settles FIRST with an ordinary on-chain Kaspa
transaction and then presents `{ transactionId, outputIndex, … }`. There
is no delegated pull and nothing for anyone to execute later. The
PolicyVault x402 FACILITATOR is therefore the **smallest possible
facilitator: a separately deployed, unprivileged, READ-ONLY chain
verification / settlement-attestation service.** It holds no keys, signs
nothing, broadcasts nothing, escrows nothing, nets nothing, converts
nothing, never calls a PolicyVault API, and never emits a `402`. Its
only inputs are (a) the resource server's own `PaymentRequirements`,
(b) the payer's `PaymentPayload` (public bytes whose hashes are verified
against consensus data), and (c) a synced, UTXO-indexed Kaspa node.

## 1. Role and boundary

| x402 facilitator duty (EVM default) | Kaspa exact/upfront | PolicyVault facilitator |
|---|---|---|
| `POST /verify`: validate a pull authorization off-chain | validate an on-chain payment | deterministic chain check (§6/§7), NO state change |
| `POST /settle`: EXECUTE the pull (custodial) | nothing to execute — the payer already settled | the same check + a durable SINGLE-USE CLAIM + a settlement-evidence record; NO transaction is created, signed, or broadcast (§8) |
| `GET /supported` | advertise kinds | advertises the Kaspa kinds it verifies; `signers` is EMPTY |

Non-custodial invariants (each has hostile-matrix rows in §11 and an
authority proof in §12): no keys / no signing / no broadcast; no
PolicyVault privilege (no machine credential, no tenant store, no app
route); deterministic core only (`core/`, `integrations/lib/`); evidence
only from an observed UTXO-index entry on a synced UTXO-indexed node whose
network equals the bound network; unknown = fail closed; free forever;
separate from MCP.

## 2. Wire contract (x402 v2 shapes)

### 2.1 `GET /supported`
```
{ "kinds": [ { "x402Version": 2, "scheme": "exact", "network": "<CAIP-2>",
              "extra": { "paymentFlow": "upfront",
                         "kaspaScheme": "pv-x402-kaspa-exact-upfront/1",
                         "assets": [ "KAS", "pvad1:<descriptorHash>", … ],
                         "settlementPolicies": [ "pv-x402-settlement/1" ] } } ],
  "extensions": [], "signers": {} }
```
Exactly ONE network per deployment. **FROZEN network identifiers for
`pv-x402-kaspa-exact-upfront/1` (OQ-F3 RESOLVED, owner decision
2026-09-02):**

| Kaspa network | identifier (exact string) | node identity that MUST be observed |
|---|---|---|
| mainnet | `kaspa:mainnet` | kaspad `networkId == "mainnet"` |
| testnet-10 | `kaspa:testnet-10` | kaspad `networkId == "testnet-10"` (the netsuffix is verified explicitly — `testnet`, `testnet-11`, or any other suffix is NOT equivalent) |

Classification: these are PolicyVault's **PROVISIONAL Kaspa network
identifiers in CAIP-2 syntax / profile form**. The Kaspa namespace is NOT
claimed to be an upstream-registered Chain Agnostic (CAIP-2) namespace;
that claim may only be made if and when such a registration actually
exists. The `/1` implementation MUST: emit exactly these identifiers;
accept exactly these identifiers (byte-exact; no case folding, trimming,
aliasing, or prefix matching); advertise them through `/supported`; bind
them into `requirementDigest`; reject every unknown Kaspa reference
(`NETWORK_MISMATCH`); independently verify the connected node's actual
network identity on every observation; and fail closed whenever the
requested identifier and the node network disagree. **The string alone is
never authoritative chain evidence** — only the node identity gate (§7.1
step 1) and the observed UTXO entry are. If a future official Kaspa
CAIP-2 namespace / profile standardizes DIFFERENT identifiers, the
meaning of `/1` does NOT change: the new identifiers arrive through an
explicit successor profile / version or a separately reviewed
compatibility mapping, and there is never a transparent alias that could
make one signed requirement change network meaning.

`signers` is empty by construction: the facilitator signs nothing.

### 2.2 `PaymentRequirements` — Kaspa profile (closed schema)
```
PaymentRequirements {
  scheme            : "exact"                       (REQUIRED, literal)
  network           : "<CAIP-2>"                    (REQUIRED, == bound network)
  amount            : "<decimal integer string>"    (REQUIRED; atomic units: sompi for KAS, token units for tokens; canonical: no sign, no leading zeros, ≤ 2^63−1; NEVER a float)
  asset             : "KAS" | "pvad1:<64-hex>"      (REQUIRED; native KAS, or a v0.5 `policyvault-asset-descriptor/1` hash from the facilitator's CONFIGURED allowlist)
  payTo             : "<bech32 address, network prefix>" (REQUIRED; MUST be unique per requirement — §5)
  maxTimeoutSeconds : <positive integer>            (REQUIRED; bounds ONLY the facilitator's node-call budget)
  extra: {
    paymentFlow        : "upfront"                   (REQUIRED, literal — else FLOW_UNSUPPORTED)
    kaspaScheme        : "pv-x402-kaspa-exact-upfront/1" (REQUIRED; unknown → SCHEME_UNSUPPORTED)
    settlementPolicy   : "pv-x402-settlement/1"      (REQUIRED; unknown → POLICY_UNSUPPORTED)
    requirementId      : "<uuid or 32-hex>"          (REQUIRED; unique per resource request)
    resourceUrl        : "<absolute URL>"            (REQUIRED; the resource being paid for)
    validFromDaaScore  : "<decimal integer string>"  (REQUIRED; DAA score at issuance)
    validUntilDaaScore : "<decimal integer string>"  (REQUIRED; > validFrom; ≤ validFrom + MAX_WINDOW_DAA)
  }
}
```
Unknown fields anywhere → `SCHEMA_INVALID` (closed schema, json-guard).

**Requirement binding digest:** `requirementDigest = sha256(canonicalJson(PaymentRequirements))`
over the WHOLE object above (scheme, network, amount, asset, payTo,
maxTimeoutSeconds, extra). It binds resource, requirement id, amount,
asset, destination, network, and validity window into one identity that
the claim store keys on (§9).

### 2.3 `PaymentPayload` — Kaspa profile
```
PaymentPayload {
  x402Version : 2
  resource    : ResourceInfo (optional; if present, resource.url MUST equal extra.resourceUrl)
  accepted    : PaymentRequirements            (REQUIRED; MUST canonical-equal the paymentRequirements passed alongside → else REQUIREMENTS_MISMATCH)
  payload: {
    transactionId  : "<64 lowercase hex>"        (REQUIRED)
    outputIndex    : <non-negative integer>      (REQUIRED — removes alternate-output ambiguity)
    payer          : "<bech32 address>"          (optional, informational only)
    transactionHex : "<serialized signed tx>"    (OPTIONAL for KAS; REQUIRED for token assets — §7)
    outputRedeems  : { "<index>": "<redeem hex>" } (token assets only: redeem scripts of EVERY family output of the transaction — §7)
  }
}
```
`payload.daaScore` from the adapter-spec draft is REMOVED: a payer-asserted
DAA score is never trusted; inclusion DAA comes from the node.

### 2.4 `POST /verify` → `VerifyResponse`
`{ isValid: boolean, invalidReason?: <reason code>, payer?: string,
extensions: { policyvault: <state record §4> } }`. `isValid: true` ⇔
state `CHAIN_VERIFIED`. `/verify` NEVER writes state.

### 2.5 `POST /settle` → `SettlementResponse`
`{ success: boolean, errorReason?: <reason code>, payer?: string,
transaction: "<txid>", network: "<CAIP-2>", amount: "<string>",
extensions: { policyvault: <evidence record §10> } }`. `success: true` ⇔
state `CHAIN_VERIFIED` AND the single-use claim was recorded (or already
exists for this exact requirementDigest + outpoint — idempotent replay
returns the SAME stored evidence).

## 3. Pinned identities

| item | pin |
|---|---|
| network identity | one of the FROZEN identifiers of §2.1 (`kaspa:mainnet` / `kaspa:testnet-10`), bound at deployment; every request's `network` must byte-equal it; the node's reported `networkId` must equal the bound network's kaspad identity on EVERY observation |
| scheme / version | `exact` + `pv-x402-kaspa-exact-upfront/1`; `x402Version` 2 |
| asset identity | `KAS` (atomic unit 1 sompi) or `pvad1:<descriptorHash>` where the descriptor is loaded from the facilitator's configured allowlist and `computeDescriptorHash(descriptor) === hash` (payer-supplied descriptors are never accepted) |
| amount representation | canonical decimal integer string (core amount parser); `exact` ⇒ equality |
| pay-to destination | bech32 with the bound network's prefix (core address module) → canonical script-public-key bytes; must be unique per requirement (§5) |
| resource / payment binding | `requirementDigest` (§2.2) |
| transaction identity | `transactionId` (64 hex) + `outputIndex`; when `transactionHex` is present, `txid(transactionHex)` MUST equal `transactionId` (`TXID_MISMATCH` otherwise) |
| expiry / deadline | inclusion DAA score `blockDaaScore ∈ [validFromDaaScore, validUntilDaaScore]`; window length ≤ `MAX_WINDOW_DAA` (policy) |
| replay / single-use | durable claims keyed by BOTH `(network, transactionId, outputIndex)` and `requirementDigest` (§9) |
| settlement depth | `pv-x402-settlement/1` (§6): `MIN_DEPTH_DAA` default **100**, hard floor **20**, `MAX_WINDOW_DAA` **36,000** (frozen) |
| resource-server identity | a facilitator-local PRINCIPAL authenticated by a facilitator-issued API credential (§14.1); grants facilitator access ONLY — never any PolicyVault authority |
| reason codes | closed set (§13) |

## 4. State ladder (never collapsed)

| state | meaning | who establishes it |
|---|---|---|
| **AUTHORIZED** | PolicyVault (payer side) decided the spend is within policy and the covenant accepted the transaction | the payer's own PolicyVault pipeline — OUTSIDE the facilitator; the facilitator never sees or needs it |
| **VERIFIED** | schema, scheme, network, asset, amount, destination, binding digest and payload identity are deterministically valid (no chain access yet) | facilitator, pure |
| **CHAIN_SEEN** | the exact outpoint is observed in the node's UTXO index with the required SPK / amount / covenant id, inclusion DAA inside the validity window, but depth < policy minimum | facilitator, node read |
| **CHAIN_VERIFIED** (= SETTLED) | CHAIN_SEEN AND depth ≥ policy minimum on a synced, UTXO-indexed node of the bound network; for `/settle` additionally: durable single-use claim recorded | facilitator, node read (+ claim on `/settle`) |

Transaction visibility (mempool) is NOT a state: the facilitator never
consults the mempool.

## 5. Payment binding and replay

A valid chain transaction alone never proves payment for an arbitrary
request. Binding = (requirementDigest ↔ exactly one outpoint) enforced by:

1. **Per-requirement unique destination (NORMATIVE for resource servers):**
   `payTo` MUST be freshly derived per requirement. The facilitator
   enforces the observable consequence: if a presented requirement's
   `(network, payTo, amount)` equals that of a DIFFERENT stored
   requirementDigest whose DAA window overlaps, it refuses
   `REQUIREMENT_DESTINATION_REUSED` (fail closed on reuse rather than
   guessing which request a payment belongs to).
2. **Validity window:** the paid output's inclusion `blockDaaScore` must
   lie inside `[validFromDaaScore, validUntilDaaScore]`; an old payment to
   the same address cannot satisfy a newer requirement
   (`PAYMENT_OUTSIDE_WINDOW`); windows are bounded (`MAX_WINDOW_DAA`).
3. **Explicit outpoint:** `outputIndex` is required; the claim binds
   `(network, transactionId, outputIndex)`; a transaction paying the same
   destination twice yields two distinct outpoints and can satisfy at most
   two distinct requirements, never one requirement twice.
4. **Exact match at the outpoint:** SPK == canonical SPK(payTo), amount ==
   `amount`, covenant id as required by the asset (§6/§7) — amount,
   recipient, asset, network substitution all fail at this step.
5. **Single-use claims (`/settle`):** create-only records keyed by outpoint
   AND by requirementDigest; second claim of the same outpoint →
   `PAYMENT_ALREADY_CLAIMED`; second outpoint for the same requirement →
   `REQUIREMENT_ALREADY_SETTLED`; the identical pair → idempotent replay of
   the stored evidence (no new state).
6. **txid-only spoofing:** a presenter who did not pay cannot obtain a
   requirement with the payer's unique `payTo` (resource servers issue
   requirements; the facilitator only accepts requirements presented by
   the resource server itself, authenticated at the deployment boundary
   §14); rule 1 makes destination collisions refuse.
7. **Optional stronger binding (scheme v2, NOT in this freeze):**
   `extra.binding: "payload"` requiring the paying transaction's `payload`
   to commit `requirementDigest`. Non-coinbase payloads are permitted by
   the 2.0.1 consensus rules (no validator restriction), but the PolicyVault
   builders do not emit payloads today; deferred (OQ-F6).

## 6. Settlement / finality policy — `pv-x402-settlement/1`

- Observation source: `getUtxosByAddresses([payTo])` (UTXO index) +
  `getBlockDagInfo.virtualDaaScore` + `getServerInfo` (network,
  isSynced, hasUtxoIndex) in the same request batch. Never mempool, never
  an indexer, never a payer assertion.
- `depth = virtualDaaScore − entry.blockDaaScore`.
- CHAIN_SEEN when the exact outpoint matches at depth ≥ 0; CHAIN_VERIFIED
  when `depth ≥ MIN_DEPTH_DAA`. **FROZEN (owner decision A, OQ-F1
  RESOLVED): default `MIN_DEPTH_DAA = 100` (≈ 10 s at 10 blocks/s);
  deployment-configurable upward, HARD FLOOR `20` — a configuration below
  20 is refused at boot, and 20 is the floor, never the target or the
  recommended value.** Reviewed under the DAGKNIGHT foresight (roadmap
  §3.2): a finality/DAA semantics change ships as `pv-x402-settlement/2`.
- **FROZEN (owner decision B, OQ-F2 RESOLVED): `MAX_WINDOW_DAA = 36,000`
  (≈ 1 h)** bounds every requirement window; a window longer than this, a
  window that is not strictly increasing, or an inclusion outside the
  window fails closed (`REQUIREMENT_WINDOW_INVALID` /
  `PAYMENT_OUTSIDE_WINDOW`).
- Versioned capability boundary: the policy id is pinned in the requirement
  and echoed in the evidence; a future consensus change (DAGKNIGHT
  finality, changed DAA semantics) introduces `pv-x402-settlement/2` with
  its own rules; unknown ids fail closed; PolicyVault AUTHORIZATION
  semantics are untouched by any policy version.
- Reorg residual: an entry observed at depth ≥ MIN can in principle be
  reorganized away; the evidence carries the observed depth so a resource
  server may apply a stricter threshold. This is stated, not hidden.
- Spent-before-verification residual: the UTXO index only holds UNSPENT
  outputs and kaspad has no transaction index; an output the payee already
  spent is `PAYMENT_NOT_OBSERVED`. Resource servers therefore MUST call
  `/settle` (claim) BEFORE spending or serving (§8).

## 7. Verification algorithms

### 7.1 Native KAS (`asset: "KAS"`)
1. Node identity gate: network == bound, `isSynced`, `hasUtxoIndex`;
   otherwise `NODE_UNAVAILABLE` / `NODE_UNSYNCED` /
   `UTXO_INDEX_UNAVAILABLE` (RETRY class; never a validity judgement).
2. Closed-schema parse of requirements + payload (§2); `accepted` canonical-
   equals requirements; `requirementDigest` computed; window sanity.
3. If `transactionHex` present: deserialize (rusty-kaspa wasm via a
   sanctioned SDK helper), recompute txid; `≠ transactionId` →
   `TXID_MISMATCH`.
4. Read UTXOs of `payTo`; select the entry at exactly
   `(transactionId, outputIndex)`; absent → `PAYMENT_NOT_OBSERVED`
   (PENDING until `virtualDaaScore > validUntil + MIN_DEPTH`, then REFUSE).
5. Entry checks: `scriptPublicKey == canonicalSpk(payTo)`; `amount ==
   required` (exact); `covenantId == null` (a covenant-carrying output is
   not a plain KAS payment → `OUTPUT_MISMATCH`); `isCoinbase == false`.
6. Window: `validFrom ≤ blockDaaScore ≤ validUntil` else
   `PAYMENT_OUTSIDE_WINDOW`.
7. Depth per §6 → CHAIN_SEEN (`PAYMENT_PENDING_DEPTH`) or CHAIN_VERIFIED.
8. `/settle` only: durable claim (§9) → evidence (§10).

### 7.2 Token payments (`asset: "pvad1:<hash>"`, frozen v0.5 semantics)
Both bindings are REQUIRED; covenant ownership alone is never sufficient.
1–3 as above, with `transactionHex` and `outputRedeems` REQUIRED
(`TOKEN_REDEEM_REQUIRED`).
4. Descriptor: loaded from the facilitator's configured allowlist by hash;
   `validateAssetDescriptor` + `computeDescriptorHash` must reproduce the
   `asset` hash; the descriptor names `tokenCovenantId` (family) and the
   accepted transfer templates (VM hash, KCC-0001 hash, prefix/suffix
   lengths, state layout).
5. **Binding 1 — covenant authorization (WHO):** the UTXO entry at
   `(transactionId, outputIndex)` must carry `covenantId ==
   descriptor.tokenCovenantId` (consensus-tracked KIP-20 lineage: only a
   spend authorized by the family covenant can create it).
6. **Binding 2 — hash-verified template (WHICH):** `outputRedeems[outputIndex]`
   must hash to the entry's P2SH `scriptPublicKey`; split by the descriptor
   geometry (`splitRedeem`), `corroborateTemplate` (prefix/suffix VM hash +
   KCC-0001 hash + geometry + standardness sig-op envelope), decode the
   `kcc20-state/1` state (`decodeState`): owner scheme + owner bytes must
   equal `payTo`'s canonical owner encoding (0x00 p2pk x-only, 0x01 p2sh,
   0x02 covenant-id — anything else `TOKEN_OWNER_MISMATCH`); decoded
   token amount == `amount` (token units, exact).
7. **Independent conservation:** from `transactionHex`, every input whose
   signature script's redeem (`redeemFromSignatureScript` →
   `verifyTokenInputRedeem`) belongs to the family, and every output whose
   SPK matches a supplied `outputRedeems[i]` of the family (every family
   output MUST have a supplied redeem — an undecodable family output →
   `TOKEN_CONSERVATION_FAILED`); Σ input token amounts == Σ output token
   amounts (i64-safe integers). KAS carried by token outputs is a SEPARATE
   domain and is never summed with token units.
8. Issuer/controller powers from the descriptor (`issuerPowers`) are
   surfaced VERBATIM in the evidence as trust properties (DECLARED-ONLY
   where uncorroborated), never as guarantees. Unsupported family /
   template / version / owner scheme → `UNSUPPORTED_TOKEN_PROGRAM` /
   `TOKEN_TEMPLATE_MISMATCH`.
9. Window, depth, claim as in 7.1 steps 6–8.

No x402-specific token parser exists: every token operation above is a
call into `core/assets` / `core/model/token-amounts` (the same code the
v0.5 SDK and browser bundle use).

## 8. `/verify` vs `/settle` — decision (option A, documented)

For the Kaspa exact/upfront scheme the facilitator neither broadcasts nor
signs, so "settlement" cannot mean execution. `/settle` is PRESERVED for
upstream x402 compatibility and implemented as: **verification + durable
single-use claim + evidence record** (option A). `/verify` is the same
verification WITHOUT any state change (option B is rejected: an alias
would lose the single-use guarantee). Recommended resource-server order:
`/verify` (optional fast pre-check) → **`/settle` (claim) → serve the
resource → (later) spend the funds**. Serving before `/settle` risks a
race with a second request; spending before `/settle` makes the payment
unverifiable (§6). No custodial or broadcasting role is invented to
resemble another chain's facilitator.

## 9. Durable state and race semantics

- Store: create-only claim records `{ claimKey, requirementDigest,
  network, transactionId, outputIndex, evidence, createdAt }` with TWO
  uniqueness invariants: `(network, transactionId, outputIndex)` and
  `requirementDigest`. Also a requirement-observation record per
  requirementDigest `{ payTo, amount, window }` for the destination-reuse
  rule (§5.1).
- Atomicity: the claim write is a single atomic create (POSIX `O_EXCL`
  file create for the single-instance JSON store; a unique-constraint
  insert for PostgreSQL). The evidence is written IN the same record —
  never a two-phase "claim then evidence".
- Crash between verification and claim: nothing is stored → the resource
  server retries `/settle` (idempotent by requirementDigest + outpoint).
  Crash after the claim: the record exists → the retry returns it.
- **Two instances racing:** the durable store is the single authority —
  whoever's atomic create succeeds owns the claim; the loser receives
  `PAYMENT_ALREADY_CLAIMED` / `REQUIREMENT_ALREADY_SETTLED`. This REQUIRES
  a shared store with real uniqueness (PostgreSQL unique constraints);
  the single-instance JSON store gives no cross-instance guarantee.
  **Therefore: ONE instance until PostgreSQL claim storage is implemented
  and its concurrency proven (matches the production app's one-replica
  rule).**
- The store holds NO PolicyVault tenant data, NO secrets, and is never
  backfilled or mutated in place.

## 10. Evidence record (`extensions.policyvault`; stored in the claim)
```
{ schema: "policyvault-x402-facilitator-evidence/1",
  status: "CHAIN_VERIFIED",
  settlementPolicy: "pv-x402-settlement/1", minDepthDaa: "100",
  network, requirementDigest, requirementId, resourceUrl,
  transactionId, outputIndex, payTo, asset, amount: "<string>",
  covenantId: "<hex>|null", descriptorHash?: "<hex>", tokenOwnerScheme?: "0x00",
  issuerPowers?: [ … verbatim … ],
  blockDaaScore: "<string>", virtualDaaScore: "<string>", depth: "<string>",
  node: { serverVersion, isSynced: true, hasUtxoIndex: true, networkId },
  observedAt: "<ISO-8601>", claimedAt?: "<ISO-8601>",
  evidenceDigest: "<sha256 of the canonical JSON of the fields above>" }
```
Every chain number is a decimal string. No field originates from the
payer or a resource server except the requirement echoes; all chain
fields come from the node RPC entry observed in this request.

## 11. Failure + hostile matrix (disposition and reason)

| case | disposition | reason / why |
|---|---|---|
| malformed payload / unknown field / wrong types | REFUSE | `SCHEMA_INVALID` — closed schema |
| unknown scheme / x402Version / kaspaScheme | REFUSE | `SCHEME_UNSUPPORTED` / `VERSION_UNSUPPORTED` |
| unknown settlement policy id | REFUSE | `POLICY_UNSUPPORTED` — never a default |
| wrong network (or look-alike string) | REFUSE | `NETWORK_MISMATCH` — exact equality with the bound network |
| wrong / unknown asset | REFUSE | `ASSET_UNSUPPORTED` — allowlist only |
| wrong recipient (SPK ≠ payTo) | REFUSE | `OUTPUT_MISMATCH` |
| amount below / above / altered (±1) | REFUSE | `OUTPUT_MISMATCH` (exact scheme) |
| float / exponent / hex / leading-zero amount | REFUSE | `AMOUNT_INVALID` |
| `accepted` ≠ requirements by one field | REFUSE | `REQUIREMENTS_MISMATCH` |
| missing tx / not yet accepted / never existed | PENDING → REFUSE | `PAYMENT_NOT_OBSERVED` until `virtualDaa > validUntil + MIN_DEPTH`, then final refusal |
| wrong output index (exists but mismatches) | REFUSE | `OUTPUT_MISMATCH` — the payer names the index; no search |
| already spent before settle | REFUSE | `PAYMENT_NOT_OBSERVED` — documented limitation (§6); resource servers settle before spending |
| reorganized away after CHAIN_SEEN | PENDING → REFUSE | same as missing; a claim is only ever written at CHAIN_VERIFIED |
| insufficient settlement depth | PENDING | `PAYMENT_PENDING_DEPTH` — retry after the depth is reached |
| expired requirement, no inclusion | REFUSE | `REQUIREMENT_EXPIRED` |
| inclusion outside the window | REFUSE | `PAYMENT_OUTSIDE_WINDOW` |
| replayed requirement (same digest, new outpoint) | REFUSE | `REQUIREMENT_ALREADY_SETTLED` |
| same tx/outpoint claimed twice (different requirements) | REFUSE (second) | `PAYMENT_ALREADY_CLAIMED` |
| same tx paying multiple resources | VERIFIED per distinct outpoint; REFUSE any second use of one outpoint | claims are per outpoint |
| payTo reused across overlapping requirements | REFUSE | `REQUIREMENT_DESTINATION_REUSED` |
| token descriptor mismatch (family ≠ entry covenantId) | REFUSE | `UNSUPPORTED_TOKEN_PROGRAM` |
| token template mismatch (VM/KCC-0001 hash, geometry) | REFUSE | `TOKEN_TEMPLATE_MISMATCH` |
| token owner mismatch / unknown owner scheme | REFUSE | `TOKEN_OWNER_MISMATCH` |
| token conservation failure / undecodable family output | REFUSE | `TOKEN_CONSERVATION_FAILED` |
| unsupported issuer / template variant | REFUSE | `UNSUPPORTED_TOKEN_PROGRAM` |
| indexer disagreement | n/a | indexers are never consulted; only the node |
| node unavailable | RETRY | `NODE_UNAVAILABLE` — not a judgement |
| node unsynced | RETRY | `NODE_UNSYNCED` |
| UTXO index unavailable | RETRY | `UTXO_INDEX_UNAVAILABLE` |
| malformed RPC response | RETRY (after refusing to interpret) | `RPC_MALFORMED` — never partially trusted |
| concurrent settlement claim | exactly one SETTLED, the other REFUSE | atomic create-only claim (§9) |
| facilitator restart between verification and durable claim | retry → SETTLED or REFUSE | no claim without evidence in the same atomic write; idempotent retry |
| unknown protocol / capability version | REFUSE | `VERSION_UNSUPPORTED` |
| oversized body / rate exceeded | REFUSE | `BODY_TOO_LARGE` / `RATE_LIMITED` |
| `signers` probing / any signing or broadcast path | impossible by construction | no signer module importable (dependency test) |
| missing / invalid / revoked / expired resource-server credential | REFUSE (401) before body parse | `CREDENTIAL_REQUIRED` / `CREDENTIAL_INVALID` — zero node access, zero store mutation, zero replay-slot consumption, zero evidence, zero anonymous downgrade |
| valid credential without `settle` authority calling `/settle` | REFUSE (403) | `SCOPE_FORBIDDEN` — nothing observed, nothing claimed |
| resource server A's credential presenting a requirement whose `payTo` belongs to B | REFUSE (403) | `PRINCIPAL_FORBIDDEN` — B's ownership is never disclosed; the outpoint stays claimable by B |
| PolicyVault `pvmk_` machine credential / browser session / wallet signature presented as a facilitator credential | REFUSE (401) | `CREDENTIAL_INVALID` — a dedicated credential model, nothing else is accepted |

## 12. Authority + security review (trust boundaries)

| the facilitator cannot… | because |
|---|---|
| expand vault authority | it has no PolicyVault credential, no store access, no app route, and never calls a PolicyVault API |
| bypass PolicyVault policy | it creates no payments; payments exist only if the payer's own pipeline (and, for agents, the covenant) accepted them; it merely observes chain results |
| sign on behalf of a payer | no keys, no signer modules, `signers: {}`; dependency-direction test forbids importing signer/builder/store modules |
| alter a signed payment | it only reads; when tx bytes are supplied it recomputes the txid and requires equality with the observed outpoint |
| redirect proceeds | `payTo` comes from the resource server's requirement; the facilitator matches, never chooses, destinations |
| downgrade token verification | descriptors come only from configuration; BOTH bindings are mandatory; unknown = refuse |
| turn indexer metadata into truth | no indexer is consulted; all chain fields come from the node's UTXO index + DAG info |
| transform a refused PolicyVault action into an accepted x402 payment | a refused action produces no chain output → `PAYMENT_NOT_OBSERVED` |
| mint settlement evidence without chain evidence | the evidence record is composed exclusively from the RPC entry observed in the request; the claim write happens only at CHAIN_VERIFIED |

Trust boundaries: (1) resource server ↔ facilitator: authenticated
deployment boundary — **v1 = facilitator-issued API key over HTTPS bound
to a dedicated resource-server principal (§14.1; OQ-F7 RESOLVED); mTLS is
an OPTIONAL FUTURE deployment-hardening mode, NOT part of the frozen `/1`
interoperability requirement** — READ-oriented, grants nothing in
PolicyVault; (2)
facilitator ↔ node: read-only RPC on loopback / private network, node
identity re-verified per request; (3) payer ↔ facilitator: untrusted
bytes, accepted only after hash equality with consensus data.

## 13. Reason codes (closed set)

RETRY class: `NODE_UNAVAILABLE`, `NODE_UNSYNCED`, `UTXO_INDEX_UNAVAILABLE`,
`RPC_MALFORMED`, `RATE_LIMITED`. PENDING class: `PAYMENT_NOT_OBSERVED`
(until window + depth elapse), `PAYMENT_PENDING_DEPTH`. REFUSE class:
`SCHEMA_INVALID`, `VERSION_UNSUPPORTED`, `SCHEME_UNSUPPORTED`,
`FLOW_UNSUPPORTED`, `POLICY_UNSUPPORTED`, `NETWORK_MISMATCH`,
`ASSET_UNSUPPORTED`, `AMOUNT_INVALID`, `ADDRESS_INVALID`,
`REQUIREMENTS_MISMATCH`, `REQUIREMENT_WINDOW_INVALID`,
`REQUIREMENT_EXPIRED`, `REQUIREMENT_DESTINATION_REUSED`,
`PAYMENT_OUTSIDE_WINDOW`, `OUTPUT_MISMATCH`, `TXID_MISMATCH`,
`PAYMENT_ALREADY_CLAIMED`, `REQUIREMENT_ALREADY_SETTLED`,
`TOKEN_REDEEM_REQUIRED`, `TOKEN_TEMPLATE_MISMATCH`, `TOKEN_OWNER_MISMATCH`,
`TOKEN_CONSERVATION_FAILED`, `UNSUPPORTED_TOKEN_PROGRAM`, `BODY_TOO_LARGE`.
AUTH class (revision 3, OQ-F7; HTTP 401/403 — never a validity
judgement, never a chain observation): `CREDENTIAL_REQUIRED` (401, no
credential presented), `CREDENTIAL_INVALID` (401, unknown / malformed /
revoked / expired credential — one code for all four so nothing about
other principals' credentials is revealed), `SCOPE_FORBIDDEN` (403, a
valid credential whose principal lacks the operation, e.g. `/settle`
without settle authority), `PRINCIPAL_FORBIDDEN` (403, a valid credential
whose principal's configured constraints — network, payTo destinations,
resource origin — do not cover the presented requirement; the response
never states whether ANOTHER principal owns the requirement).
Unknown situations map to `SCHEMA_INVALID` or a RETRY code, never to
validity.

## 14. Deployment architecture

- **Distinct process** `integrations/x402-facilitator/` (not a route
  group in the app): isolation, least privilege, independent failure. Its
  only outbound dependency is read-only kaspad RPC (loopback / VPC); it
  holds no PolicyVault credential, no PostgreSQL tenant access, no signing
  or custody credential of any kind.
- Inbound: resource servers only, authenticated per §14.1 (facilitator-
  issued API key over HTTPS); body caps; per-principal rate limits
  (availability protection ONLY — never a substitute for authentication,
  deterministic verification, replay protection, or settlement depth);
  closed schemas. Endpoint policy: `GET /supported` = PUBLIC (no
  resource-server credential); `POST /verify` and `POST /settle` =
  AUTHENTICATED RESOURCE SERVER REQUIRED; anonymous `/verify` or `/settle`
  is never allowed in hosted production.
- Storage: claim store (§9) — single-instance JSON `O_EXCL` records
  initially; PostgreSQL unique-constraint store before any second
  instance. **No horizontal scaling until claim concurrency is proven.**
- Configuration (closed set): bound network, node URL (public node URLs
  refused), settlement policy id + `MIN_DEPTH_DAA` (≥ floor),
  `MAX_WINDOW_DAA`, descriptor allowlist (paths + hashes), store class.
- Dependency direction: `core/**`, `sdk/src/**`, `server/src/**` never
  import the facilitator; the facilitator imports only `core/`,
  `integrations/lib/`, and TWO additionally sanctioned read-only SDK
  leaves: `sdk/src/chain.js` (connectVerified, getVirtualDaaScore,
  getAddressUtxos, proveOutpointStatus) and a txid-recomputation helper
  (wasm `Transaction` deserialize → id) — the allowlist test is extended
  explicitly; builders / signers / store / rpc-mutation modules stay
  forbidden.

### 14.1 Resource-server principals and credentials (OQ-F7 RESOLVED — owner decision 2026-09-02, frozen for v1)

- **Mechanism:** FACILITATOR-ISSUED API KEY OVER HTTPS, presented as
  `Authorization: Bearer <credential>`. **mTLS = OPTIONAL FUTURE HARDENING,
  NOT A v1 REQUIREMENT**; v1 implements exactly ONE authentication surface
  (no dual API-key-or-mTLS path). If mTLS is introduced later, the
  certificate identity binds to the SAME principal model below — never a
  second authority system.
- **Dedicated credential model.** A facilitator credential is NOT a
  PolicyVault browser session, NOT a PolicyVault bearer machine credential
  (`pvmk_`), NOT a wallet signature, NOT a payer credential, NOT a signer
  credential, and none of those are accepted in its place. It grants
  access ONLY to the facilitator service and confers ZERO PolicyVault
  financial authority (§12).
- **Generation:** cryptographically secure randomness, ≥ 256 bits of
  entropy (32 random bytes). The raw credential is shown / returned ONLY
  at creation; it is never persisted in plaintext, never logged, never
  placed in a URL or query string, and never returned by any list / read
  API. Only a strong verifier (SHA-256 of the raw credential) plus
  metadata is persisted; comparison is constant-time.
- **Principal record (persisted / configured, at minimum):** `principalId`,
  credential verifier(s), `status` (`active` | `revoked`), `createdAt`,
  optional `expiresAt`, allowed facilitator operations (`verify`,
  `settle`), allowed networks (subset of §2.1), allowed `payTo`
  destinations (an explicit list, or an explicit "any" — never an implicit
  default), optional allowed resource origins / `resourceUrl` constraints.
  Each credential identifies exactly one principal; multiple ACTIVE
  credentials per principal exist only when explicitly configured
  (rotation overlap).
- **Authority is facilitator-local only.** A credential without `settle`
  authority MUST NOT call `/settle` (`SCOPE_FORBIDDEN`).
- **Binding supplements, never replaces, deterministic verification.** For
  every authenticated request the facilitator STILL verifies
  `requirementDigest`, `resourceUrl`, `network`, `scheme`, `asset`,
  `amount`, `payTo`, the validity window, the settlement policy, the
  transaction / outpoint evidence, and the replay state. Where a principal
  has configured allowed `payTo` destinations, the presented requirement's
  `payTo` MUST belong to that principal: a valid API key of resource
  server A never verifies or settles a requirement owned by resource
  server B (`PRINCIPAL_FORBIDDEN`, without disclosing B's existence) —
  the cross-principal negative test is mandatory (§11).
- **Failure semantics.** Missing / invalid / revoked / expired credential →
  HTTP 401 (`CREDENTIAL_REQUIRED` / `CREDENTIAL_INVALID`) and, by
  construction: ZERO node-dependent financial acceptance, ZERO claim-store
  mutation, ZERO replay-slot consumption, ZERO settlement evidence, ZERO
  downgrade to anonymous behavior (authentication runs before the body is
  parsed and before any node or store access). Valid credential lacking
  operation authority → 403 `SCOPE_FORBIDDEN`.
- **Rotation + revocation.** Creation, revocation, replacement / rotation
  with overlap (a second active credential for the same principal, then
  revocation of the old one) are supported; rotation never changes the
  principal identity, requirement semantics, payment authority, or any
  covenant state. Revocation takes effect immediately for new facilitator
  requests (the principal store is re-read on every authentication).
- **Rate limiting** is applied per principal to `/verify` and `/settle` as
  availability protection only (`RATE_LIMITED`, 429).

## 15. Non-goals (permanent)

Resource-server role; delegated-pull emulation; signing, broadcasting,
escrow, netting, refunds; currency/unit conversion or quotes; DEX / swap
verification (next program); MCP exposure; any PolicyVault-privileged
path; any change to v0.4 / v0.4.1 / v0.5 covenant bytes.

## 16. Freeze-time decisions — ALL RESOLVED (owner, 2026-09-02)

| item | resolution | where |
|---|---|---|
| OQ-F1 `MIN_DEPTH_DAA` | default 100; HARD FLOOR 20 (20 is never the target); `pv-x402-settlement/1` versioned; DAGKNIGHT/finality changes = new policy version | §6 (decision A) |
| OQ-F2 `MAX_WINDOW_DAA` | 36,000; outside the window fails closed | §6 (decision B) |
| OQ-F3 network identifiers | `kaspa:mainnet` / `kaspa:testnet-10`, PROVISIONAL CAIP-2-syntax identifiers, exact strings, node identity verified independently, no transparent aliasing, successor profile for any future official identifiers | §2.1 |
| OQ-F4 asset literal | `KAS` (sompi) or `pvad1:<descriptor-hash>` (configured descriptors only, no blessed list, unknown fails closed) | §2.2 / §3 (decision G) |
| OQ-F5 store class / hosted operation | ONE instance; PostgreSQL unique-constraint claim storage before any scaling; durable claim storage wherever `/settle` is served; hosted production deployment = separate owner gate | §9 / §14 (decisions E, F) |
| OQ-F6 payload binding | NOT part of `/1`; the mandatory unique destination + window + explicit outpoint IS the binding of `/1`; payload binding is a future scheme version | §5.7 (decision C) |
| OQ-F7 inbound authentication | facilitator-issued API key over HTTPS with a dedicated principal model; `/supported` public, `/verify` + `/settle` authenticated; mTLS optional future hardening | §14.1 |

## 17. Implementation-level pins (frozen with the design; revision 3)

These fix the details the wire contract of §2 left to the implementation.
They are part of `pv-x402-kaspa-exact-upfront/1` and change only with a
new version.

1. **`requirementDigest` derivation:** `sha256_hex("policyvault-x402-facilitator-requirement/1\n" + canonicalJsonStringify(PaymentRequirements))`
   over the WHOLE closed requirement object (§2.2), using the SDK's
   canonical JSON (key-order independent). The domain line keeps the
   digest disjoint from every other PolicyVault commitment, including the
   client adapter's `policyvault-x402-requirement-digest/1`.
2. **`transactionHex` carriage:** lowercase hex of the UTF-8 bytes of the
   rusty-kaspa wasm SDK `Transaction.serializeToSafeJSON` document (the
   reference SDK's only signed-transaction serialization; there is no
   exposed consensus binary encoding). The facilitator decodes hex →
   UTF-8 → strict closed JSON (json-guard, byte caps) →
   `Transaction.deserializeFromSafeJSON` and REQUIRES the recomputed
   consensus id to equal `transactionId` (`TXID_MISMATCH`). The embedded
   `id` field and every embedded `utxo` are payer-supplied and are NEVER
   trusted. Evidentiary weight (stated, not hidden): the Kaspa
   transaction id commits to version, inputs' outpoints, outputs
   (value + script), lockTime, subnetwork, gas and payload, but NOT to
   signature scripts; supplied signature scripts are therefore payer
   consistency data — the token conservation check (§7.2 step 7) can only
   REFUSE an inconsistent submission, and acceptance never rests on it.
   Acceptance rests on Binding 1 (consensus covenant lineage on the
   observed entry) and Binding 2 (template hash + decoded state ==
   observed P2SH script).
3. **Token observation address:** for `pvad1:` assets the UTXO-index
   lookup address is the P2SH address of `outputRedeems[outputIndex]`
   (`p2shSpkHex(redeem)` → `addressFromScriptPublicKey`), because a KCC20
   output is a P2SH token program whose OWNER (not its script) is
   `payTo`; `payTo` is bound through the decoded `kcc20-state/1` owner
   (scheme `0x00` ⇔ a `PubKey` address's x-only key; scheme `0x01` ⇔ a
   `ScriptHash` address's 32-byte hash; scheme `0x02` — a covenant id —
   can never equal an address and fails `TOKEN_OWNER_MISMATCH`). For
   `KAS` the lookup address is `payTo` itself.
4. **`outputRedeems` keys** are decimal output indices as strings; every
   family output of the transaction (every output whose P2SH script equals
   the hash of a supplied redeem that matches an accepted template) MUST
   be supplied, and an output at `outputIndex` without a redeem is
   `TOKEN_REDEEM_REQUIRED`.
5. **Evidence digest:** `evidenceDigest = sha256_hex("policyvault-x402-facilitator-evidence/1\n" + canonicalJsonStringify(evidence-without-evidenceDigest))`.
6. **Credential format:** `pvx402f_` + 64 lowercase hex (32 random bytes);
   verifier = `sha256_hex(rawCredential)`; principals are re-read per
   authentication so revocation is immediate.
7. **HTTP status mapping:** 200 for every verification answer (`isValid`
   / `success` carry the judgement), 401 / 403 for the AUTH class, 413
   `BODY_TOO_LARGE`, 429 `RATE_LIMITED`, 400 `SCHEMA_INVALID` when the
   body is not even parseable, 503 for the RETRY class when the node gate
   fails before any judgement, 404 unknown routes, 405 wrong methods.
   Query strings on `/verify` and `/settle` are refused (`SCHEMA_INVALID`)
   so no credential can travel in a URL.
8. **Public-node refusal:** the node URL must be loopback, an RFC 1918 /
   ULA / link-local private address, or a single-label host name; any
   other host is refused at boot. Mainnet additionally requires the dual
   unlock (`POLICYVAULT_ALLOW_MAINNET=true` + an explicit mainnet node
   URL); the identifier `kaspa:mainnet` is never a default.
