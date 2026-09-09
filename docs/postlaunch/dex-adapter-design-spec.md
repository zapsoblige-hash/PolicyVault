# PolicyVault DEX / SWAP ADAPTER FRAMEWORK — Design Specification (DESIGN CANDIDATE, revision 1)

**Claim label: DESIGNED (candidate). Nothing here is IMPLEMENTED,
UNIT-TESTED, VM-VERIFIED, TESTNET-VERIFIED, or PRODUCTION-HARDENED. No
production adapter exists. No covenant byte changes (v0.4.1 / v0.5
frozen identities untouched). The owner's design-freeze decision gates
every implementation step.** Program record and stop verdict:
`dex-adapter-program.md`. Roadmap boundary: `roadmap-dex-adapter-and-protocol-evolution.md` §2.

## 0. Summary

PolicyVault MUST NOT become a DEX. External venues execute swaps and hold
liquidity; PolicyVault deterministically **AUTHORIZES** an intended swap
(policy + covenant), **VERIFIES** the exact transaction bytes the external
signer is about to sign against a closed swap-intent manifest, and
**RECONCILES** the actual chain outcome from a node it trusts. The signer
stays external and retains custody. Indexers, quote servers, venue APIs,
MCP responses, and UIs are never financial truth.

The framework is a **venue/protocol adapter interface** over the shared
deterministic core: each adapter is a pure, versioned, fail-closed
function from `(raw transaction bytes, on-chain state facts, pinned
protocol template facts)` to a **swap verification verdict** plus the
`SwapIntentManifest/1` fields it can prove. Unknown venue / protocol /
version / template → `UNSUPPORTED_SWAP_PROTOCOL` (the `UNSUPPORTED_TOKEN_PROGRAM`
rule of v0.5).

Two execution shapes exist on Kaspa L1 today, and the framework names
both explicitly rather than pretending one is the other:

| shape | what the vault signs | atomicity | frozen-covenant compatibility |
|---|---|---|---|
| **S1 — AUTHORIZED SEND + VERIFIED RECEIPT** (two legs) | leg 1: an ordinary PolicyVault spend (v0.4.1 `agentSpend` for KAS, v0.5 `tokenAgentSpend` for tokens) whose recipient is the venue's **allowlisted deposit identity**; leg 2 is the venue's own transaction paying proceeds to the vault | NOT atomic — bounded counterparty risk (exactly the x402 upfront posture) | **COMPATIBLE with frozen v0.4.1 / v0.5 — no covenant change** |
| **S2 — ATOMIC CO-SIGNED SWAP** (one transaction) | one transaction spending the vault's covenant input AND the venue's pool/counterparty input, producing both successors and both proceeds outputs (PSKT: venue constructs, vault-side signer signs its input) | atomic | **INCOMPATIBLE with frozen v0.5** (`tokenAgentSpend` requires exactly one family input, two family outputs, and refuses foreign covenant inputs — probe-verified in `tools/gen_v5.js` lines 330–333) and with v0.4.1's exact-successor accounting; requires a NEW covenant version (§13) — **STOP + justify, never touch frozen bytes** |

The framework is designed so that S1 ships first under the frozen
covenants and S2 becomes possible later through an additive covenant
version and a new adapter capability, without redesigning the interface.

## 1. Boundaries (binding)

1. PolicyVault never runs liquidity pools, holds swap inventory,
   market-makes, custodies swap funds, operates an order book, creates
   proprietary liquidity, or signs for the user.
2. The adapter verifies from **deterministic evidence only**: transaction
   bytes (consensus-committed fields — recall the Kaspa txid commits to
   outpoints, outputs incl. covenant bindings, lockTime, subnetwork, gas,
   payload, NOT signature scripts), UTXO-index entries from a verified
   node, and PINNED protocol templates (script bytes whose hashes are
   configured, never fetched). A quote is an INPUT to intent, never
   evidence.
3. Asset identity = the frozen v0.5 `policyvault-asset-descriptor/1`
   (dual binding: covenant id WHO + hash-verified template WHICH) reused
   verbatim from `core/assets`; the DEX layer never parses KCC20 itself.
4. Stablecoin PAYMENTS are NOT swaps: they stay on the v0.5 token
   transfer / x402 paths; the swap framework only handles exchanges of one
   asset for another.
5. Approval of an intent is NEVER proof of swap success: the ladder
   AUTHORIZED → SIGNED → BROADCAST → CHAIN_SEEN → CHAIN_VERIFIED /
   VERIFIED_OUTCOME is never collapsed (§9).
6. Prefer no covenant change; every covenant-dependent capability is
   named as such and gated separately.

## 2. Adapter interface (`core/swap/`, shared deterministic core)

```
SwapAdapter/1 {
  id            : "<venue>/<protocol>/<version>"      e.g. "kaspa-l1-send-receive/1"
  capabilities  : { shape: "S1" | "S2", assets: ["KAS", "kcc20/1"], preSign: true, postChain: true,
                    atomic: boolean, quoteSource: "external" }
  pins          : { templates: [{ templateVmHashBlake2b256, prefixLen, suffixLen, role }], venueIdentities: [...] }
  deriveIntent(quote, policyContext)        -> SwapIntentManifest/1 (pure; refuses unknown fields)
  verifyPreSign(txBytes, chainFacts, manifest)  -> { verdict: "VERIFIED_EXACT" | refusal code, proofs }
  expectedOutcome(manifest)                  -> { outpoints/outputs that must appear, deadline }
  reconcile(nodeFacts, manifest)             -> { state: CHAIN_SEEN | CHAIN_VERIFIED | VERIFIED_OUTCOME | FAILED | UNKNOWN, evidence }
}
```

- Adapters are REGISTERED by exact id; lookup is by exact string; an
  unregistered id fails closed. Adapters are pure CommonJS in `core/swap/`
  (browser / mobile / server / CLI / MCP reuse; the dependency-direction
  rule: `core/swap` imports only `core/assets`, `core/model`,
  `core/intent`).
- Every numeric quantity is a canonical decimal integer string
  (atomic units; token units and sompi are separate domains that are
  never summed).
- `verifyPreSign` MUST be a total function of its inputs: same bytes +
  same facts + same manifest ⇒ same verdict (no clock, no network).

## 3. Swap-intent manifest (`SwapIntentManifest/1`, closed schema)

An extension of the frozen transaction-intent manifest
(`core/intent/manifest.js`, `policyvault-intent-manifest/1`): the base
manifest still describes the PolicyVault transition (state before/after,
value accounting, limits, approvals, allowlist evaluation, policy
mutation diff); the swap extension adds the swap semantics that the
adapter proves:

```
swap: {
  schema           : "policyvault-swap-intent/1"
  adapter          : "<adapter id>"
  shape            : "S1" | "S2"
  venue            : { id, identityKind: "allowlisted-recipient" | "covenant-id" | "template-hash", identity }
  pool             : { id | null, identityKind, identity }          (S2 / pool-based venues; null for RFQ/S1)
  assetIn          : { asset: "KAS" | "pvad1:<hash>", amountMax: "<int>" }
  assetOut         : { asset: "KAS" | "pvad1:<hash>", amountMin: "<int>" }
  pair             : { in, out, policyPairId }                        (policy-approved pair)
  slippageBps      : <int ≤ policy max>
  quote            : { source: "external", amountOutQuoted, quotedAt, ttl }   INFORMATIONAL — never evidence
  deadline         : { kind: "daa", validUntilDaaScore }              (fail closed when unbounded)
  fees             : { protocolFeeMax: "<int>", kasFeeMax: "<int sompi>", feeReserveDelta: "<int sompi>" }
  proceeds         : { destination: "vault-successor" | "approved-recipient", identity }
  outputs          : [ { index, role: "vault-successor"|"asset-in-to-venue"|"asset-out-to-vault"|"change"|"venue-successor"|"fee", asset, amount, spkHex, covenantId|null } ]   ALL outputs, each accounted
  successorState   : { stateId, ... }                                  (the exact expected PolicyVault successor)
  conservation     : { tokenIn, tokenOut, kasIn, kasOut, feeReserveBefore, feeReserveAfter }
  reconciliation   : { expect: [ { outpoint|address, asset, amount, byDaaScore } ] }   what leg 2 / the atomic tx must produce
}
```

Manifest hash = the existing representation-independent canonical hash;
the signer surface shows the swap block verbatim (signer-visible intent);
`verifyIntentManifest` refuses any swap block whose `outputs` do not
account for EVERY transaction output.

## 4. Pre-sign verification model (deterministic boundary)

`verifyPreSign` runs BEFORE the external signer is asked for anything:

1. Decode the exact proposed bytes with the existing frozen-tx decoder
   (`core/model/frozen-tx-v3`) — never the builder's intent object.
2. Prove the PolicyVault leg exactly as today (predecessor outpoint,
   successor state/script, value accounting, fee) with `core/intent/verify.js`.
3. Venue identity: S1 — the recipient output's identity must equal the
   venue deposit identity AND that identity must be in the agent's
   recipient allowlist (Merkle proof, as the covenant enforces); S2 — the
   foreign covenant input's covenant id / redeem template must hash to a
   PINNED venue template.
4. Assets: input asset descriptor (dual binding via `core/assets`) for
   token legs; `KAS` for native; unknown → refuse.
5. Amounts: `amountIn ≤ amountMax`; expected `amountOut ≥ amountMin`
   (S2: proven from the co-signed outputs; S1: NOT provable pre-sign —
   recorded as `amountMin` to be enforced at reconciliation and by the
   counterparty bound in policy).
6. Slippage: `amountMin ≥ amountOutQuoted × (1 − slippageBps/10000)`
   (integer arithmetic; the quote is informational — the bound is what
   is enforced).
7. Deadline: `validUntilDaaScore` present and ≤ policy window; the
   transaction's own lock time / the requirement's DAA window consistent.
8. Fees: KAS fee = Σ inputs − Σ outputs ≤ `kasFeeMax` and ≤ the agent's
   fee cap; fee-reserve delta ≤ permitted; any venue/protocol fee output
   must be an accounted `fee` role output ≤ `protocolFeeMax`.
9. Hidden outputs: every output index appears exactly once in
   `swap.outputs` with a role; any output not in the manifest, or any
   manifest output not in the transaction → refuse.
10. Proceeds destination: S2 asset-out output owner == vault successor
    (controller covenant-id owner scheme 0x02 for tokens; vault successor
    script for KAS); S1 the expected leg-2 destination is recorded for
    reconciliation.
11. Token conservation across the whole transaction (family inputs vs
    family outputs) using `core/assets` exactly as the x402 facilitator
    does; KAS fee-reserve separation (two domains never summed).
12. Successor state equals the manifest's `successorState`.
Any failure → a closed refusal code (§8); the signer is never asked.

## 5. Post-chain reconciliation model

Only a verified node (network / synced / utxoindex, per observation) is
consulted — the same `sdk/src/chain.js` reads the x402 facilitator uses:

| state | evidence |
|---|---|
| AUTHORIZED | PolicyVault's own durable request record (dry-run + policy + manifest hash) |
| SIGNED | the external signer returned a signature; PolicyVault holds bytes, not keys |
| BROADCAST | `submitTransaction` returned a txid equal to the frozen txid — NOT success |
| CHAIN_SEEN | the expected outputs are observed in the UTXO index at depth < policy minimum |
| CHAIN_VERIFIED | the PolicyVault successor outpoint is observed with the exact script/value/covenant id (existing reconcile) AND (S2) the asset-out output is observed at the vault at depth ≥ `MIN_DEPTH_DAA` |
| VERIFIED_OUTCOME | S1 only: leg 2 observed — an output of `assetOut` ≥ `amountMin` paying the vault (token: family covenant id + decoded owner == controller id; KAS: vault successor / approved recipient) inside the deadline window; recorded with the leg-2 txid |
| FAILED / UNKNOWN | leg 2 absent after `deadline + MIN_DEPTH` → `SWAP_PROCEEDS_NOT_RECEIVED` (a counterparty default, escalated to a human — never auto-retried); node unavailable → UNKNOWN (fail closed, reconcile later) |

The reconciliation result is a claim record (create-only, like the x402
claim store), never a mutation of the manifest.

## 6. Protocol capability / version model

- `SwapAdapter/1.capabilities` is a closed vocabulary; the server's
  `/capabilities` names the registered adapter ids and their shapes;
  clients (browser, MCP, x402) NEVER infer support — unknown ids refuse.
- Every pinned template carries `templateVmHashBlake2b256` + geometry
  (the v0.5 convention); a venue upgrade = a NEW adapter version with new
  pins; old pins keep verifying old positions (no forced migration).
- Kaspa Protocol Evolution Compatibility applies: a change to any relied
  property (covenant ids, DAA semantics, txid commitment scope, sighash
  types, PSKT format) REOPENS the design freeze.

## 7. Trust boundaries

| boundary | trust | what crosses |
|---|---|---|
| agent / MCP / UI → PolicyVault | untrusted request | "swap X for at least Y at venue V before DAA D" — a REQUEST, zero authority |
| quote server / venue API → adapter | untrusted data | a quote → `amountOutQuoted` (informational), a venue-constructed PSKT/tx bytes (S2) — verified byte-by-byte, never trusted |
| PolicyVault → external signer | signer-visible manifest + exact bytes | the signer sees the swap block; PolicyVault never holds keys |
| PolicyVault → node | read-only RPC, identity verified per observation | UTXO entries, DAA, server info |
| venue → chain | the venue's own leg / co-signature | observed only through the node |

## 8. Hostile matrix (design dispositions; every row becomes a test before any freeze)

| case | disposition |
|---|---|
| wrong venue (recipient not the allowlisted venue identity / covenant template hash mismatch) | REFUSE `SWAP_VENUE_MISMATCH` |
| wrong pool (S2 pool identity ≠ manifest) | REFUSE `SWAP_POOL_MISMATCH` |
| wrong asset / asset substitution (descriptor hash, family covenant id, or template differs) | REFUSE `SWAP_ASSET_MISMATCH` (via `core/assets` dual binding) |
| output substitution (proceeds output owner/script ≠ vault) | REFUSE `SWAP_PROCEEDS_MISMATCH` |
| excessive amount-in | REFUSE `SWAP_AMOUNT_IN_EXCEEDED` |
| insufficient amount-out (S2 pre-sign; S1 at reconciliation) | REFUSE `SWAP_AMOUNT_OUT_INSUFFICIENT` / outcome `SWAP_PROCEEDS_SHORT` |
| slippage above policy | REFUSE `SWAP_SLIPPAGE_EXCEEDED` |
| expired / unbounded quote or deadline | REFUSE `SWAP_DEADLINE_INVALID` |
| hidden output (any output without a manifest role) | REFUSE `SWAP_HIDDEN_OUTPUT` |
| redirected proceeds | REFUSE `SWAP_PROCEEDS_MISMATCH` |
| unexpected protocol fee (unaccounted or > max) | REFUSE `SWAP_FEE_EXCEEDED` |
| unexpected KAS fee / fee-reserve breach | REFUSE `SWAP_KAS_FEE_EXCEEDED` (and the covenant refuses independently) |
| token conservation failure | REFUSE `SWAP_CONSERVATION_FAILED` |
| descriptor / template mismatch | REFUSE `SWAP_ASSET_MISMATCH` |
| malicious quote server (quote lies) | the quote is never evidence: min-out + slippage bounds are enforced; a lying quote yields a refused or unfilled swap, never a loss beyond the bounds |
| indexer disagreement | indexers are never consulted |
| stale pool state (S2) | the co-signed transaction is verified against the CURRENT node view at pre-sign and the covenant enforces at consensus; a stale state simply fails to confirm → reconciliation UNKNOWN/FAILED, never a false success |
| transaction differs from the reviewed intent (bytes ≠ manifest) | REFUSE `SWAP_INTENT_MISMATCH` (manifest hash over the exact bytes) |
| successor-vault mismatch | REFUSE `SWAP_SUCCESSOR_MISMATCH` |
| unsupported protocol version | REFUSE `UNSUPPORTED_SWAP_PROTOCOL` |
| venue takes leg 1 and never pays leg 2 (S1) | outcome `SWAP_PROCEEDS_NOT_RECEIVED` — human escalation; bounded by per-spend cap / period budget / allowlist (the same bound as x402 upfront) |
| replayed leg 2 (one proceeds output claimed for two swaps) | reconciliation claims are keyed by outpoint (single use) |

## 9. State ladder (never collapsed)

AUTHORIZED (PolicyVault) → SIGNED (external signer) → BROADCAST (txid
returned) → CHAIN_SEEN (observed, shallow) → CHAIN_VERIFIED (PolicyVault
leg proven) → VERIFIED_OUTCOME (proceeds proven; S2 coincides with
CHAIN_VERIFIED; S1 is a separate later event). "The swap was approved"
and "the swap succeeded" are different sentences and different records.

## 10. Required shared-core changes (no covenant change)

- `core/swap/` (new): adapter registry + interface + the S1 adapter
  `kaspa-l1-send-receive/1`; pure, fixture-tested, browser-bundled.
- `core/intent/manifest.js`: additive `swap` block (`policyvault-swap-intent/1`),
  closed; `verify.js`: swap detectors (§4 items 3–12) behind the block's
  presence (manifests without a swap block are byte-identical in behaviour).
- `core/assets`: none (reused as is).
- SDK: a reconciliation reader for leg-2 proceeds (reusing
  `chain.getAddressUtxos` + `core/assets` decoding; the x402 facilitator's
  token verification is the reference implementation), a create-only
  outcome claim store, and the `/capabilities` adapter listing.
- Server / MCP / x402: expose swap REQUESTS through the existing
  request pipeline with the manifest; no new authority.

## 11. Whether a covenant change is required

- **S1: NO.** Leg 1 is exactly a frozen v0.4.1 `agentSpend` / v0.5
  `tokenAgentSpend` to an allowlisted recipient (the venue's deposit
  identity); leg 2 is an ordinary inbound transfer (token owner =
  controller id; KAS to the vault's successor by the existing top-up
  path). The swap semantics live in the manifest, the adapter, and the
  reconciliation — outside consensus, exactly like x402 settlement.
- **S2: YES — a new additive covenant version (v0.6 candidate) would be
  required**, because the frozen v0.5 controller refuses foreign covenant
  inputs and pins exactly one family input / two family outputs, and
  v0.4.1 pins exact successor accounting. Per the owner's rule this is a
  STOP + JUSTIFY item, not a design assumption: the justification is
  atomicity (no counterparty default window). It is NOT proposed for the
  first adapter; it is recorded as owner decision OQ-D1 (§16).

## 12. Testnet / live-proof plan (after the freeze)

1. Fixture-level: real compiler bytes for the venue templates pinned;
   `core/swap` unit + hostile matrix on the real `core/assets` codec.
2. VM: the S1 legs are existing frozen-covenant transitions — reuse the
   v0.4.1 / v0.5 VM suites; no new covenant tests.
3. Live testnet-10 (test keys only): a scripted "venue" made of ordinary
   test-key transactions plays leg 2 (pays proceeds back); prove
   AUTHORIZED → … → VERIFIED_OUTCOME and every hostile row that is
   observable on chain (proceeds short, late, redirected, replayed,
   asset substituted), plus authorized testnet negative-validation
   transactions constructed independently of the PolicyVault application
   for the leg-1 policy bounds (consensus rejects).
4. A REAL external venue only after the upstream review names one whose
   transaction semantics are deterministically verifiable (§14).

## 13. Implementation phases (after the owner's design freeze; none started)

| phase | content | gate |
|---|---|---|
| P1 | `core/swap` interface + registry + `SwapIntentManifest/1` + verify detectors + S1 adapter + hostile suite | UNIT + ADVERSARIAL |
| P2 | SDK reconciliation (leg-2 proceeds, outcome claims) + `/capabilities` listing + explain/signer surfaces | INTEGRATION |
| P3 | live testnet-10 proof with a scripted venue | TESTNET-VERIFIED |
| P4 | first REAL venue adapter (per §14 recommendation) with pinned templates + its own live proof | TESTNET-VERIFIED (venue) |
| P5 | docs / conformance / public docs (honest ecosystem statement) | publication gates |
| P6 (conditional) | S2 atomic shape — only after an owner decision on a new covenant version (OQ-D1) | design gate of its own |

## 14. Venue comparison and recommended first adapter

Source: the current-upstream survey of 2026-09-03 (research worker;
primary sources fetched; every claim labelled VERIFIED / REPORTED /
UNVERIFIED — the full report with URLs and access dates is preserved
privately with the program record). Two of its consensus-level claims
were re-verified locally against `~/rusty-kaspa` v2.0.1:
`hash_output` commits `covenant.is_some`, `authorizing_input` and
`covenant_id` for version-1 outputs (`consensus/core/src/hashing/sighash.rs`
lines 228–235), and `SIGHASH_SINGLE` with `input_index >= outputs.len`
hashes to `ZERO_HASH` (lines 204–205) while `ANYONECANPAY` zeroes the
previous-outputs / sequences / sig-op commitments (lines 142–199).

Kaspa L1 context (VERIFIED): Toccata active on mainnet since DAA
474,165,565 (rusty-kaspa 2.0.1); KIP-17/20 active; first mainnet
covenants 2026-07-02; Silverscript v1-rc1 2026-08-30 (v1 promised about a
week later — not final at this writing); Argent pre-release; vProgs
research-stage; no covenant-id-keyed UTXO RPC (address-keyed lookup
returns `covenant_id`). **Three incompatible on-chain layouts are all
called "KCC20"**: the Silverscript reference 4-field / 46-byte layout
(`kcc20-46` — the one PolicyVault v0.5 decodes as `kcc20-state/1`), the
KCC-0020 draft 6-field / BLAKE3 layout with an OPEN supply-partition
defect (kccs issue #14), and KaspaCom's 3-field KCC20V2.

| rank | venue | status | settlement | asset layout | model | what the vault would sign | templates published? | pre-sign deterministic verification | node reconciliation | version risk | verdict against the bar |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | **KRON** (kron.technology) | MAINNET LIVE (kascov: 80+ markets, 7 constant-product pools, thousands of trades, latest 2026-09-02) | ONE Kaspa L1 v1 transaction, atomic; pool + token-note covenant inputs authorized by covenant logic | KCC20 4-field (REPORTED = template `469ea253…`; UNVERIFIED) | bonding curve → constant-product pool + LP KCC20 | the taker's own inputs only (sighash UNVERIFIED) — i.e. the **S2 shape** | **NO** (only program hashes on chain; kascov source-verify `ok:false`; no repo; audit UNVERIFIED) | outcome-envelope only (the vault's spent inputs, every output's value/script/binding, a KCC20 note to the vault decodable by P2SH reconstruction); NOT the pool template or fee routing | YES | HIGH (curve v1–v4, pool v1–v3 in ~2 months) | closest live venue; FAILS the published-template requirement |
| 2 | **KaspaKaha KCC20 reference AMM** (MIT) | TESTNET-10 only (explicitly not mainnet) | ONE L1 transaction | KCC20 4-field / 46-byte, template hash `469ea253…` (Silverscript 0.1.0, maxIns 4 / maxOuts 6) | constant-product pool + LP token, protocol fee to a pinned P2PK | the user's funding input, `sighashType: 1` (ALL); "dumb relay" broadcasts — **S2 shape** | **YES** (source, SDK, golden vectors) | YES — bytes can be rebuilt and compared | YES | HIGH (v0→v3 redeploys; pre-v1 compiler) | meets the bar TECHNICALLY; no mainnet venue |
| 3 | Zealous CoAMM | TN10 (REPORTED) | one L1 tx, two covenant families, 2-hop routes | own 4-field token layout (not the reference) | constant-product | own inputs (flag UNVERIFIED) | NO (BUSL-1.1, unpublished) | NO | YES | HIGH (rebuilt on Argent master) | fails today |
| 4 | KaspaCom "Cook" / KCC20 marketplace | TN10 order book; mainnet marketplace "next" | L1 covenant listings + indexer quoting | KCC20V2 3-field (non-standard) | fixed listings / bids | UNVERIFIED | NO | NO | YES | MEDIUM | fails today |
| 5 | EVM L2 DEXes (Zealous Swap on Kasplex/Igra, Kaspa Finance V3, Kaspa.com LFG) | MAINNET (L2) | L2 execution state, bridges (multisig; Igra Governor without timelock, UUPS proxies) | ERC-20 / wrapped KAS | Uniswap v2/v3 | EVM calldata | partly (Solidity) | not from Kaspa L1 | not from Kaspa L1 | EVM upgradeability + bridge admin | out of scope (not consensus-validated bytes) |
| 6 | KRC20 PSKT marketplaces (Kaspa.com, KasWare, KSPR, Kaspiano) | MAINNET (several sites unreachable) | L1 tx, but token truth = Kasplex indexer | KRC20 inscriptions | seller-first PSKT (SINGLE\|ANYONECANPAY implied) | buyer completes | n/a | NO (indexer) | KAS only | migration expected | fails by construction |
| 7 | wKAS / Chainge / XODEX | custodial / other chains | — | wrapped | — | — | — | NO | NO | custodian solvency (depeg, trapped funds 2025) | excluded |

Template identity note: PolicyVault's vendored KCC20 reference
(`contracts/vendor/kcc20-reference.sil`, `2b7d59b0…`) compiles with the
project's silverc to the fixture in-VM hashes per family bound
(blake2b(prefix‖suffix), e.g. bound 2 = `9ed5a66c…`); the KaspaKaha /
KRON hash `469ea253…` is quoted for a different compiler version and
bound (maxIns 4 / maxOuts 6) and a different hash convention (KCC-1
BLAKE3 framing) — **byte identity with our fixture is UNVERIFIED and not
assumed**; pinning is always by explicit configured hash, never by name.

**Recommended first adapter target (conditional):** the **"Kaspa L1
KCC20 constant-product pool, taker side"** family — the only class that
settles in one Kaspa-consensus-validated transaction with a decodable
token state and node-only reconciliation — with (i) a configured
template-hash allowlist for BOTH the token template and the pool
template, (ii) SIGHASH_ALL-only vault signatures, (iii) full-output
enumeration and KCC20 state decode by P2SH reconstruction, (iv) pool
state read from the node (`getUtxosByAddresses(pool P2SH address)`, entry
`covenant_id` == pinned pool id) immediately before build, (v)
claim-based reconciliation, using **KaspaKaha's TN10 MIT reference as the
byte-exact conformance fixture** and admitting **KRON mainnet pools only
after their pool/curve source and compiler version are published and the
owner allowlists the exact hashes** (an "outcome-envelope-only" mode
against opaque pool hashes is possible but would be an explicitly
labelled DEGRADED mode, not the bar). NOT targeted: Cook (unpublished
listing template, non-standard layout), CoAMM (BUSL-1.1, unpublished),
EVM L2 DEXes (not L1-verifiable), KRC20 PSKT markets (indexer truth),
custodial wrappers.

**Consequence for the covenant question:** this target class is the
atomic taker-side shape (S2): the vault's covenant input must co-exist
with the pool's covenant inputs/outputs in ONE transaction, which the
frozen v0.5 controller refuses (`requireNoForeignCovenantInputs`, exact
family input/output counts) and the frozen v0.4.1 KAS covenant cannot
account for (exact successor value) — see §11 and OQ-D1. The S1 shape
(authorized send + verified receipt) remains available under the frozen
bytes for RFQ / OTC / venue-deposit counterparties, none of which exists
as a verifiable Kaspa venue today.

## 15. Kaspa primitives relevant to swaps (source-verified, rusty-kaspa 2.0.1)

- PSKT (`wallet/pskt`): BIP-370-style roles Creator → Constructor →
  Updater → Signer → Combiner → Finalizer → Extractor; hex transport;
  per-input `sighash_type`, `redeem_script`, `partial_sigs`, `utxo_entry`;
  a venue can construct a multi-party transaction and hand the vault side
  its input to sign — the ONLY thing PolicyVault would verify is the
  extracted final bytes against the manifest (the PSKT is carriage, not
  evidence).
- Sighash types (`consensus/core/src/hashing/sighash_type.rs`): ALL,
  NONE, SINGLE, each with ANYONECANPAY. An atomic swap in which the vault
  signs SINGLE|ANYONECANPAY would let a counterparty add inputs/outputs —
  PolicyVault's covenant signatures are ALL (the covenant call binds the
  whole transaction) and the framework NEVER authorizes a non-ALL sighash
  for a vault input (`SWAP_SIGHASH_UNSUPPORTED`).
- Introspection opcodes (`crypto/txscript/src/opcodes`): OpTxInputCount /
  OpTxOutputCount / OpTxInputAmount / OpTxInputSpk / OpTxOutputAmount /
  OpTxOutputSpk (+ Len/Substr variants) and the KIP-20 covenant opcodes
  (OpCovInputCount / OpCovOutputCount) — a future S2 covenant could bind
  the counterparty's outputs by template exactly as v0.5 binds token
  outputs; this is the technical basis of OQ-D1, not a commitment.
- Payloads: non-coinbase transaction payloads are permitted by consensus
  (validator restricts coinbase only) — a possible carrier for a swap
  intent commitment in a future scheme (as x402 deferred payload binding).

## 16. Unresolved owner decisions

- **OQ-D1** — whether to open a NEW additive covenant version (v0.6
  candidate) enabling the atomic S2 shape (foreign covenant input from a
  pinned venue template; venue-output template binding). Recommendation:
  NOT for the first adapter; decide after S1 is proven live.
- **OQ-D2** — the first real venue (from §14) and the exact deposit
  identity model (allowlisted recipient per venue vs per pool).
- **OQ-D3** — counterparty-default policy for S1: per-swap cap and
  period budget for "in-flight" value (proceeds not yet received), and
  the human-escalation channel.
- **OQ-D4** — whether swap requests are exposed through MCP / x402
  surfaces at P2 or only through the console/API.
- **OQ-D5** — `MIN_DEPTH_DAA` for VERIFIED_OUTCOME (reuse
  `pv-x402-settlement/1`'s 100 / floor 20, or a separate policy id).

## 17. Non-goals (permanent)

Pools, AMMs, order books, own liquidity, market making, LP economics,
exchange custody, signing for the user, currency conversion or price
oracles as truth, cross-chain bridging custody, any change to frozen
covenant bytes.
