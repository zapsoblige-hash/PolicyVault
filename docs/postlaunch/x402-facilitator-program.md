# x402 FACILITATOR program — IMPLEMENTATION / LIVE-PROOF PROGRAM COMPLETE (owner accepted 2026-09-03; verdict X402-FACILITATOR-PRODUCTION-READY; production deployment NOT authorized — pilot packet track separate)

**Claim labels (per deliverable, never collapsed):** D1/D2 = DESIGNED +
**DESIGN FROZEN** ("X402 FACILITATOR DESIGN FREEZE — OWNER AUTHORIZED +
COMPLETE", 2026-09-02; spec revision 3 sha256 `f027a054…`; record
`x402-facilitator-design-freeze.md`). D3–D6 status is recorded in §3
below as each gate is passed. No production file, migration, covenant
byte, production configuration, or published artifact is changed by this
document; no hosted facilitator deployment is authorized.

Owner authorization (2026-09-02, "v0.5 BYTE FREEZE + rc8 DEPLOYMENT + MCP
1.4.2 CLOSURE" §5): once the v0.5 BYTE FREEZE is recorded, x402 is no longer
blocked by v0.5; after the rc8 / MCP 1.4.2 corrective release train reaches a
clean checkpoint, BEGIN the x402 FACILITATOR program as the next adoption
roadmap item. Checkpoint reached 2026-09-02 ~19:00Z: the v0.5 freeze is recorded (lane `4be7dc0`); fullscale-rc8 is live + accepted (buildId `1c02162`); `policyvault-mcp@1.4.2` is published on npm (shasum `e33bcc65…`, remote clean-room proof PASSED) and listed on the official Registry (1.4.2 active, latest); the v1.5.0 public successor is prepared and staged (push owner-gated). The program is therefore BEGUN at the design gate.

Binding roadmap position (`docs/postlaunch/roadmap-dex-adapter-and-protocol-evolution.md`
§1): v0.5 TOKENS (frozen) → **x402 FACILITATOR (this program)** → DEX / SWAP
ADAPTER FRAMEWORK (AFTER x402; not started) → …

## 0. MILESTONE CLOSURE (owner acceptance, 2026-09-03)

**X402 FACILITATOR IMPLEMENTATION / LIVE-PROOF PROGRAM — COMPLETE.** The
owner accepted the D3–D6 stop report and the verdict
X402-FACILITATOR-PRODUCTION-READY (`x402-facilitator-production-readiness.md`).
This acceptance closes the implementation + live-testnet-proof milestone
and does NOT authorize production deployment. Preserved identities (do not
redo D1–D6):

| item | identity |
|---|---|
| frozen spec revision 3 | `docs/postlaunch/x402-facilitator-spec.md` sha256 `f027a0547042b36f686beb6186ae1e910a4b55f5bde142174b873234ab47fb3b` |
| freeze record | `docs/postlaunch/x402-facilitator-design-freeze.md` sha256 `c8571a1ab0cbaefa31c6a4b108bf71f6cb6688e680da93d738e476c69eeefc45` |
| lane tip | `x402-facilitator` @ `2e4fd99` (0934707 → 3ab89e1 freeze → be5c05e D3+D4 → 3eb1401 → 99c33ba D5 → 2e4fd99 stop) |
| testnet evidence | `docs/testnet-x402-facilitator-evidence.json` sha256 `e7e052c04f475784…` (testnet-10, 2026-09-03T00:10–00:11Z, 2 claims) |
| real KAS payment | `679219319aa80554…` — PENDING_DEPTH@3 → CHAIN_VERIFIED@101 (10 s) → settled → replayed |
| real frozen-v0.5 token payment | tokenAgentSpend `300974f9e5a0ae42…` (2000 units; descriptor `f8bd6f7e…`, family `320d9731…`) — CHAIN_VERIFIED@101 (8 s), both bindings + conservation → settled → replayed |
| replay / concurrency | live: PAYMENT_ALREADY_CLAIMED, REQUIREMENT_ALREADY_SETTLED, REQUIREMENT_DESTINATION_REUSED, spent-before-settle; suites: JSON 8-way race, PostgreSQL 16-way races from two store instances |
| txid / covenant-binding finding | the Kaspa txid commits to output covenant bindings; wasm `.id` cached at construction; regression `sdk/test/tx-identity.test.js` (Rust `pv_tx_probe`) |
| full regression | VM 328/0 · SDK 891 (796/0/95) + tx-identity 3/3 · core 578 · web 337 · security 54 · mcp 53 · mobile 81 · integrations 146 + PG 6 + x402-server 18 + ap2-server 15 · conformance 20 · python 75 · anti-drift/freeze 23 |
| v0.5 covenant | `contracts/PolicyVault.v0.5.sil` sha256 `c693aeff…4197dd9` UNCHANGED |

## 1. Binding boundaries (verbatim intent of the owner directive)

1. PolicyVault is not a wallet.
2. PolicyVault never signs.
3. Signers retain custody.
4. x402 never bypasses deterministic policy / covenant verification.
5. MCP and x402 remain separate programs (MCP stays a thin distribution
   surface; the facilitator is not an MCP tool and gains no authority from
   MCP).
6. Settlement evidence is CHAIN_VERIFIED only (an observed UTXO / accepted
   transaction on a synced, UTXO-indexed node; never "pending", never a
   third party's assertion).
7. No DEX implementation (no pools, AMMs, order books, own liquidity,
   market making, LP economics, exchange custody); the DEX / Swap Adapter
   Framework remains AFTER x402.
8. Token / stablecoin payment support uses the FROZEN v0.5 token semantics
   (`policyvault-asset-descriptor/1`, dual binding covenant-ID + hash-verified
   template, KCC20 state codec, two-domain accounting) — never a parallel
   token model.
9. Free forever: PolicyVault never emits a `402` for its own API and never
   charges for facilitation.

## 2. What "facilitator" means here — reconciliation with the existing spec

`docs/postlaunch/x402-adapter-spec.md` (surface 27, the CLIENT / PAYER
adapter that is IMPLEMENTED + INTEGRATION-TESTED in `integrations/x402/`)
listed the facilitator role as OUT OF SCOPE because, in x402's default EVM
flow, a facilitator *settles on someone else's behalf* by executing a
delegated pull authorization — a custodial posture PolicyVault does not
take. That reasoning stands unchanged. The owner's program is therefore
scoped to the ONLY facilitator shape that is non-custodial by construction:

- The proposed Kaspa scheme is **`exact` + `extra.paymentFlow: "upfront"`**
  (spec §6.3–6.4): the payer settles FIRST with an ordinary on-chain
  transaction and presents `payload = { transactionId, payer, amount,
  daaScore? }`. There is no delegated pull, no authorization artifact, no
  later execution by anyone.
- A Kaspa **verification facilitator** therefore holds NO keys, signs
  NOTHING, broadcasts NOTHING, escrows NOTHING, nets NOTHING. `POST /verify`
  is a deterministic CHAIN check; `POST /settle` for an upfront payment is
  the same check re-expressed as a `SettlementResponse` (the payer already
  settled); `GET /supported` advertises the Kaspa kinds. Every response is
  derived from a synced UTXO-indexed node plus the shared deterministic core.
- The facilitator is a SEPARATELY DEPLOYED, UNPRIVILEGED service for
  resource servers that choose to accept the Kaspa scheme. It has no
  privileged path into PolicyVault, no tenant data, no machine credential
  with mutation scopes; its complete absence costs PolicyVault nothing.
- The adapter-spec rules that stay binding are re-affirmed, not weakened:
  the CLIENT adapter never treats a facilitator's `isValid: true` as evidence
  about its own transaction (rule 9), never converts units (rule 10), never
  emulates a pull (§6.4). The facilitator adds a verification SERVICE for the
  other side of the wire; it does not move the spend decision out of the
  PolicyVault pipeline.

## 3. Program deliverables (design gate → implementation, in order)

| # | deliverable | label at start | gate to leave |
|---|---|---|---|
| D1 | **FROZEN (revision 3)** — facilitator design spec `docs/postlaunch/x402-facilitator-spec.md`: role, endpoints (`/verify`, `/settle`, `/supported`), exact Kaspa `exact`/upfront verification algorithm (txid lookup through the UTXO index / accepted-transaction proof, output paying EXACTLY `amount` sompi to `payTo`, network binding, confirmation depth / DAA-score policy, replay and double-presentation rules, fail-closed unknown scheme/network/version), CHAIN_VERIFIED evidence schema, hostile matrix, deployment boundary (separate process, read-only node access, no credentials with mutation scopes), free-forever posture | DESIGNED → DESIGN FROZEN 2026-09-02 | owner design freeze — GRANTED |
| D2 | **FROZEN (spec §7.2, §17)** — token payments (KCC20 via frozen v0.5): verification of a token-family output paying `amount` token units to `payTo` — family covenant-ID + hash-verified template + KCC20 state decode from `core/assets`; asset identifier = the frozen `policyvault-asset-descriptor/1` hash; unsupported programs fail closed | DESIGNED → DESIGN FROZEN 2026-09-02 | same design freeze — GRANTED |
| D3 | Implementation in `integrations/x402-facilitator/` (constants · codes · network · policy · schema · assets · carriage · verify-kas · verify-token · claims [JSON + PostgreSQL] · principals · node · facilitator · service · bin) reusing `integrations/lib/`, `core/assets`, `core/model/token-amounts` and the two sanctioned read-only SDK leaves (`sdk/src/chain.js`, new `sdk/src/tx-identity.js`); dependency-direction rules 5 / 5b | **IMPLEMENTED + UNIT-TESTED + INTEGRATION-TESTED** (2026-09-02; freeze pin 6 · unit 14 · service 12 · PG 6 — all green) | unit + integration — PASSED |
| D4 | Hostile matrix: every spec §11 row (schema / version / scheme / flow / policy / network look-alikes / assets / amounts / addresses / requirements mismatch / windows / not-observed → expired / wrong index / recipient / ±1 sompi / covenant + coinbase outputs / outside window / depth ladder / reorg / spent-before-settle / replay classes / two resources / destination reuse / concurrent claims / restart / carriage tampering / RETRY class / token family substitution, template downgrade, owner, amount, minter, conservation, txid, ECDSA, i64) + the AUTH rows incl. the cross-principal negative | **ADVERSARIAL-TESTED** (2026-09-02; hostile 34 + service/auth 12 — all green) | ADVERSARIAL suite green — PASSED |
| D5 | Live testnet-10 proof: real upfront KAS payment + real KCC20 token payment (frozen v0.5 path) verified through the facilitator against the local synced node (test keys only); negatives re-expressed as facilitator refusals; consensus-rejected negative-validation transaction unobservable | **TESTNET-VERIFIED** (2026-09-03; §3.1) | TESTNET-VERIFIED — PASSED |
| D6 | Conformance + docs: `docs/postlaunch/conformance-suite-spec.md` §12, README status + layout, SECURITY claim block, facilitator README, adapter-spec cross-reference, honest ecosystem statement (no upstream Kaspa scheme exists — spec §6.5 stays OPEN) | **DONE** (inputs prepared; publication owner-gated) | publication gates — prepared, not exercised |

Explicitly NOT in this program: resource-server role (PolicyVault never
charges), delegated-pull emulation, any signing/broadcast on behalf of a
payer, custody/escrow/netting, currency conversion or quotes, DEX/swap
verification (next program), MCP tool exposure of the facilitator.

### 3.1 D5 / D6 status and implementation findings

- **Finding (D3, probe-verified 2026-09-02):** the Kaspa transaction id
  COMMITS to each output's covenant binding (authorizing input + covenant
  id) and does NOT commit to signature scripts, `sigOpCount`,
  `computeBudget`, or UTXO entries (verified against the Rust consensus
  hasher through `tests/vm` `pv_tx_probe`). The rusty-kaspa 2.0.1 wasm
  `Transaction` caches its `id` at construction — bindings assigned
  afterwards leave a stale `.id` and a stale embedded `id` in
  `serializeToSafeJSON`, and `deserializeFromSafeJSON` echoes the
  embedded id verbatim. `sdk/src/tx-identity.js` therefore rebuilds every
  carried transaction through the engine constructor WITH its covenant
  bindings and ignores the embedded id; the first live token run exposed
  this (`TXID_MISMATCH` on a real v0.5 spend) and the second confirmed the
  fix. Consequence for the token conservation rule: a family output
  without a supplied redeem is detected from consensus-committed data.
- **D5 — TESTNET-VERIFIED (2026-09-03T00:10–00:11Z, testnet-10, kaspad
  2.0.1 synced + utxoindex, DAA 560,354,963; test keys only; evidence
  `docs/testnet-x402-facilitator-evidence.json`, 2 claims recorded).**
  KAS leg: real upfront payment `679219319aa80554defa59c570be74c217d1188cd3672de1f2557b2579a37690`
  observed at depth 3 (`PAYMENT_PENDING_DEPTH`) → CHAIN_VERIFIED at depth
  101 after 10 s (inclusion DAA 560354978) → `/settle`
  success (evidence digest `c9a4928d663e0c7f…`) →
  idempotent replay (same evidence). Refusals live: ±1 sompi
  `OUTPUT_MISMATCH`; wrong destination / wrong index
  `PAYMENT_NOT_OBSERVED`; `kaspa:mainnet` string `NETWORK_MISMATCH`;
  output-tampered carriage `TXID_MISMATCH` (embedded-id tamper correctly
  ignored); new requirement on the claimed outpoint
  `PAYMENT_ALREADY_CLAIMED`; second payment `2cbe745f9d0476e3…` for
  the settled requirement `REQUIREMENT_ALREADY_SETTLED`; overlapping
  requirement with the same destination tuple
  `REQUIREMENT_DESTINATION_REUSED`; a third payment
  `078a7dc7016d3b9c…` verified (depth 103) then spent by the
  merchant (`7aedaca4f65fff23…`) before settling →
  `PAYMENT_NOT_OBSERVED` (documented limitation shown live); 401
  `CREDENTIAL_REQUIRED` / `CREDENTIAL_INVALID`, 403 `SCOPE_FORBIDDEN`,
  403 `PRINCIPAL_FORBIDDEN` (cross-principal) before any chain access.
  TOKEN leg (frozen v0.5 path, descriptor hash
  `f8bd6f7ee8ddea7a…`, family
  `320d9731e8c08839…`): issuance
  `b67203c7c452e6b2…` → controller genesis
  `88ee12fcd67691ae…` → deposit
  `3e308936751880a0…` → authorized tokenAgentSpend
  `300974f9e5a0ae42b4525e9dd170c534874b2a28146bcc6f963464ba2a2c8d89` paying 2000 units to the
  merchant (output 2) → CHAIN_VERIFIED at depth 101 after 8 s with BOTH
  bindings + conservation, evidence carrying descriptor hash, owner
  scheme 0x00, issuer powers verbatim → `/settle` success → replay.
  Refusals live: `TOKEN_REDEEM_REQUIRED`, `ASSET_UNSUPPORTED` (unknown
  descriptor hash), `TOKEN_OWNER_MISMATCH`, `OUTPUT_MISMATCH` (1999),
  `TOKEN_CONSERVATION_FAILED` (family output without redeem),
  `TOKEN_TEMPLATE_MISMATCH`, `PAYMENT_ALREADY_CLAIMED`. Authorized
  testnet negative-validation transaction constructed independently of
  the PolicyVault application (over-cap agent spend 3000 > cap 2500,
  re-encoded through the real encoder, delegate-signed,
  `f8e6d878fd942429…`): REJECTED by consensus and
  therefore `PAYMENT_NOT_OBSERVED` at the facilitator.
- **D6 — DONE (publication-gate inputs prepared on the lane; NOT
  published):** conformance spec §12, README status + layout, SECURITY
  claim block, facilitator README, adapter spec §1.6 cross-reference,
  this record. Stop record:
  `docs/postlaunch/x402-facilitator-production-readiness.md`.

## 4. Open design questions (carried from the adapter spec; resolved or parameterized in spec §16 — OQ-F1…F7 are freeze-time decisions)

- OQ-5 CAIP-2 network identifier for Kaspa → RESOLVED 2026-09-02 (OQ-F3):
  `kaspa:mainnet` / `kaspa:testnet-10` are PolicyVault's PROVISIONAL
  identifiers in CAIP-2 syntax; no upstream registration is claimed.
- OQ-6 `asset` literal for native KAS; for tokens the proposal is the frozen
  descriptor hash (D2).
- Confirmation-depth policy: DAA-score distance vs. "accepted + UTXO-index
  observed" — must be explicit, conservative, and reviewed against the
  DAGKNIGHT foresight (roadmap §3.2) before any freeze.
- Replay: one txid must satisfy at most ONE resource request; the store is
  the facilitator's own (durable, idempotent), never PolicyVault's tenant
  data.

## 5. Starting state (exact)

- x402 CLIENT adapter (surface 27): IMPLEMENTED + UNIT-TESTED +
  INTEGRATION-TESTED (`integrations/x402/`, `integrations/test/x402-*`),
  113/113 in the integrations suite at the current lane tip; not
  testnet-verified through the adapter; not "x402 compatible" in the
  ecosystem sense.
- x402 FACILITATOR: DESIGN FROZEN (2026-09-02); D3–D6 implementation on
  lane `x402-facilitator` (status in §3).
- v0.5 token semantics: COVENANT-BYTE-FROZEN (`c693aeff…`), available for D2.
- Local testnet-10 node: synced, running (kept for D5).
