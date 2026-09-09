# x402 FACILITATOR — D1/D2 DESIGN-FREEZE READINESS RECORD (2026-09-02)

> **Status (2026-09-02, later the same day): the owner resolved OQ-F1…F7
> and authorized the freeze — see `x402-facilitator-design-freeze.md`
> ("X402 FACILITATOR DESIGN FREEZE — OWNER AUTHORIZED + COMPLETE"). This
> record is the historical readiness input; the frozen spec is revision 3.**

Owner directive: "PUBLIC v1.5.0 RELEASE + x402 DESIGN-FREEZE CHECKPOINT"
§3–§14. This record summarizes the adversarially reviewed design in
`x402-facilitator-spec.md` (revision 2) so the owner can make the
design-freeze decision. **Claim label: DESIGNED. Nothing is implemented;
D3–D6 have not started; no DEX work has started.**

| item | resolution |
|---|---|
| **Exact proposed Kaspa x402 scheme** | x402 v2 `exact` + `extra.paymentFlow: "upfront"` + `extra.kaspaScheme: "pv-x402-kaspa-exact-upfront/1"`; network `kaspa:mainnet` / `kaspa:testnet-10` (CAIP-2-shaped, unregistered); assets `KAS` (sompi) or `pvad1:<v0.5 descriptor hash>` (token units); amounts are canonical decimal integer strings; the payer settles first with an ordinary Kaspa transaction and presents `{ transactionId, outputIndex, transactionHex?, outputRedeems? }` |
| **Facilitator role** | the smallest role: READ-ONLY CHAIN VERIFICATION / SETTLEMENT ATTESTATION. No keys, no signing, no broadcast, no escrow, no netting, no conversion, no PolicyVault credential, no `402` of its own. A broader role was NOT found necessary by the current protocol requirements |
| **`/supported`** | one bound network; kinds = exact/upfront with the configured asset allowlist and settlement-policy ids; `signers` EMPTY by construction |
| **`/verify`** | deterministic validity + current chain state; `isValid: true` ⇔ CHAIN_VERIFIED; NEVER writes state |
| **`/settle`** | option A (documented): the same verification + durable single-use claim + evidence record; preserved for upstream compatibility; non-custodial; idempotent replay returns the stored evidence; resource servers settle BEFORE serving/spending |
| **Payment requirement schema** | closed Kaspa profile: scheme, network, amount, asset, payTo (unique per requirement), maxTimeoutSeconds, extra { paymentFlow, kaspaScheme, settlementPolicy, requirementId, resourceUrl, validFromDaaScore, validUntilDaaScore }; binding digest = sha256(canonical JSON of the whole object) |
| **Payment evidence schema** | `policyvault-x402-facilitator-evidence/1`: status, policy + min depth, requirement echoes, outpoint, payTo, asset, amount, covenantId, descriptor hash / owner scheme / issuer powers (tokens), blockDaaScore, virtualDaaScore, depth, node identity, timestamps, evidenceDigest; every chain number a decimal string; every chain field from the node entry observed in the request |
| **KAS verification algorithm** | node identity gate → closed-schema parse + binding digest → optional txid recomputation from tx bytes → exact outpoint in the UTXO index of payTo → SPK == payTo, amount == required, covenantId null, not coinbase → inclusion DAA inside the window → depth ≥ policy → (settle) atomic claim |
| **KCC20 / token verification algorithm** | descriptor from the CONFIGURED allowlist (hash-reproduced) → Binding 1: UTXO entry `covenantId == descriptor.tokenCovenantId` (consensus lineage, WHO) → Binding 2: payer-supplied output redeem hashes to the entry's P2SH SPK, template corroborated (VM hash + KCC-0001 hash + geometry + sig-op envelope), decoded owner == payTo's owner encoding, decoded amount == required (WHICH) → independent conservation over the supplied transaction (family inputs from signature-script redeems, family outputs from supplied redeems; Σ in == Σ out; token units never summed with KAS) → issuer powers surfaced verbatim as trust properties → window/depth/claim as KAS. All via `core/assets` / `core/model/token-amounts` — no x402-specific token parsing |
| **Replay / single-use design** | durable create-only claims keyed by `(network, txid, outputIndex)` AND `requirementDigest`; explicit `outputIndex`; unique payTo per requirement (normative) with facilitator-enforced `REQUIREMENT_DESTINATION_REUSED`; DAA validity window; exact-match at the outpoint; second use of an outpoint or a second outpoint for a requirement refuses; idempotent replay of the identical pair |
| **Finality / depth policy** | `pv-x402-settlement/1`: CHAIN_SEEN at observation, CHAIN_VERIFIED at `virtualDaaScore − blockDaaScore ≥ MIN_DEPTH_DAA` (proposed default 100 ≈ 10 s, floor 20) on a synced UTXO-indexed node of the bound network; versioned policy id in requirement + evidence; unknown ids fail closed; DAGKNIGHT/finality changes arrive as a new policy version without touching PolicyVault authority semantics |
| **State ladder** | AUTHORIZED (payer's PolicyVault pipeline, outside the facilitator) / VERIFIED (deterministic, no chain) / CHAIN_SEEN (observed, depth < min) / CHAIN_VERIFIED = SETTLED (depth ≥ min; claim on settle) — never collapsed; mempool visibility is not a state |
| **Durable-state requirements** | claim store with two uniqueness invariants, atomic single-write records (POSIX `O_EXCL` file create for a single instance; PostgreSQL unique constraints for shared storage); requirement-observation records for the destination-reuse rule; no PolicyVault tenant data, no secrets, never mutated or backfilled; crash semantics: no claim without evidence in the same write, idempotent retry |
| **Race authority** | the durable store's atomic uniqueness is the single authority between instances; cross-instance safety REQUIRES the PostgreSQL store → ONE instance until that store exists and its concurrency is proven |
| **Reason-code set** | closed (spec §13): 5 RETRY, 2 PENDING, 24 REFUSE codes; unknown situations map to `SCHEMA_INVALID` or RETRY, never to validity |
| **Hostile matrix disposition** | spec §11: 32 rows, each REFUSE / RETRY / PENDING / VERIFIED / SETTLED with the reason; every row of the owner's minimum list is covered (malformed, unknown scheme/version, wrong network/asset/recipient/amount, missing/wrong output, spent/reorg, depth, expiry, replay, double claim, multi-resource tx, token descriptor/template/conservation/issuer variants, indexer disagreement, node unavailable/unsynced/no index, malformed RPC, concurrent claim, restart between verify and claim) |
| **Authority / security review** | spec §12: nine "cannot" proofs (authority expansion, policy bypass, signing, altering a signed payment, redirecting proceeds, downgrading token verification, indexer-as-truth, refused-action laundering, evidence without chain evidence) with the structural reason for each; three trust boundaries mapped (resource server ↔ facilitator, facilitator ↔ node, payer ↔ facilitator) |
| **Deployment boundary** | distinct process `integrations/x402-facilitator/`; read-only kaspad RPC on loopback/VPC; authenticated inbound (resource servers only); body caps + rate limits; claim store as above; no horizontal scaling before the PostgreSQL store; dependency-direction test extended to sanction ONLY `sdk/src/chain.js` (read helpers) and a txid-recomputation helper for the facilitator; builders/signers/store/mutation modules stay forbidden |
| **Upstream / spec dependencies** | x402 v2 object shapes (PaymentRequirements / PaymentPayload / VerifyResponse / SettlementResponse); CAIP-2 identifier for Kaspa (unregistered, OQ-F3); no upstream Kaspa scheme exists (adapter spec §6.5 stays OPEN — the facilitator interoperates only with servers configured for the proposed scheme and must not be called "x402-compatible" without that qualification); Kaspa consensus: KIP-20 covenant ids on UTXO entries (verified in rusty-kaspa 2.0.1 `RpcUtxoEntry.covenant_id`), `block_daa_score` on entries, non-coinbase payloads permitted (validator restricts coinbase payloads only); kaspad RPC `getServerInfo`, `getBlockDagInfo`, `getUtxosByAddresses` (already wrapped by `sdk/src/chain.js`); rusty-kaspa wasm `Transaction` for txid recomputation; vendored KCC20 reference program + `core/assets` (frozen v0.5) |
| **Residual risks** | reorg after CHAIN_VERIFIED (bounded by the depth policy; depth carried in evidence); outputs spent before `/settle` are unverifiable (no txindex in kaspad — resource servers settle before spending); payTo reuse by a resource server is refused rather than resolved; payer-supplied bytes are trusted only after hash equality; CAIP-2 non-registration; ecosystem non-acceptance of the scheme; counterparty risk of the upfront flow (payer's, adapter spec §6.4) |
| **Unresolved questions (freeze-time decisions)** | OQ-F1 `MIN_DEPTH_DAA` default (100 proposed, floor 20) · OQ-F2 `MAX_WINDOW_DAA` (36,000 proposed) · OQ-F3 CAIP-2 strings · OQ-F4 KAS asset literal (`"KAS"` proposed) · OQ-F5 hosted store class / whether a hosted facilitator is ever operated · OQ-F6 payload binding as scheme v2 (needs builder payload support) · OQ-F7 resource-server auth (mTLS vs API key). None changes the algorithms; all are parameters or deployment choices |
| **Covenant change required?** | **NO.** The facilitator observes consensus outputs; it needs nothing from any covenant beyond what v0.4.1 / v0.5 already enforce |
| **v0.5 frozen bytes untouched?** | **YES** — `contracts/PolicyVault.v0.5.sil` sha256 `c693aeffb59286d21d44452bde0943d78840b66cf480b629624b7747b4197dd9` (re-verified at this checkpoint) |
| **Implementation plan D3–D6 (NOT started)** | **D3** `integrations/x402-facilitator/` (service.js routes `/supported`, `/verify`, `/settle`; `verify-kas.js`, `verify-token.js`, `claims.js` store with `O_EXCL` + PostgreSQL adapters, `policy.js` versioned settlement policies, `codes.js`), dependency-direction test extension, config gate (public node URL refused; mainnet dual unlock), no signer/builder import possible. **D4** hostile suites: the §11 matrix as UNIT + INTEGRATION tests against a spawned facilitator with a scripted node stub AND against the real local testnet-10 node (spent/reorg/depth rows); concurrency test (two settles racing on one outpoint); restart test. **D5** live testnet-10 proof (test keys only): a KAS payment from the v0.4.1 agent path and a KCC20 token payment from the frozen v0.5 path, each verified and settled through the facilitator with CHAIN_VERIFIED evidence, plus the consensus-rejected negatives re-expressed as facilitator refusals. **D6** conformance-suite extension, public docs (README/SECURITY claim block with exact labels), the honest ecosystem statement, x402 adapter spec cross-references. Each step stops at its gate; production deployment of a hosted facilitator is a separate owner decision |

## Adversarial review findings folded into revision 2

1. The draft's `payload.daaScore` was a payer assertion → removed; inclusion
   DAA comes only from the node entry.
2. The draft searched outputs by amount → replaced by a REQUIRED explicit
   `outputIndex` (alternate-output ambiguity eliminated).
3. The draft had no requirement/resource binding → `requirementDigest` over
   the closed requirement object incl. `resourceUrl`, `requirementId`, and
   the DAA validity window; unique `payTo` per requirement made normative
   and enforced (`REQUIREMENT_DESTINATION_REUSED`).
4. The draft's `/verify` reported `isValid` at CHAIN_SEEN → now only at
   CHAIN_VERIFIED; the four-state ladder is explicit.
5. Token verification could not verify conservation without inputs → the
   payer now supplies `transactionHex` + `outputRedeems`; txid is
   recomputed and family outputs must all be decodable.
6. Race semantics were unspecified → durable-store atomicity is the single
   authority; one instance until a PostgreSQL store exists.
7. The draft implied a single generic reason set → 31 closed codes in
   three classes with explicit dispositions.

## Verdict

All protocol semantics, schemas, algorithms, binding/replay rules, the
finality policy boundary, durable-state requirements, reason codes, the
hostile matrix, the authority review, and the deployment boundary are
specified deterministically and fail closed; the remaining open items are
freeze-time parameter and deployment choices that do not alter any
algorithm. No covenant change is required and the frozen v0.5 bytes are
untouched.

**X402-DESIGN-FREEZE-READY**

The owner makes the design-freeze decision from this record. Until then:
no facilitator implementation, no DEX work.
