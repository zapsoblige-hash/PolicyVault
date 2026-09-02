# Roadmap addendum (owner decisions, 2026-09-02): DEX / Swap Adapter Framework + Kaspa Protocol Evolution Compatibility

Status: BINDING program record (owner directive "OWNER DECISIONS + ROADMAP
ADDENDUM + PARALLEL UX TRACK", accepted at the v0.5 prerequisites
checkpoint). Nothing in this document is implemented; it records scope,
boundaries, and ordering for future work. Claim labels: everything here is
DESIGN TARGET / ROADMAP unless a later document proves otherwise.

## 1. Updated post-v0.5 sequence (binding)

```
v0.5 TOKENS
→ x402 FACILITATOR
→ DEX / SWAP ADAPTER FRAMEWORK          (added 2026-09-02)
→ UNIVERSAL SIGNER INTERFACE
→ EXPORTABLE COMPLIANCE ATTESTATIONS
→ HIERARCHICAL DELEGATION
→ VERIFIED OUTCOMES
```

Gating that still applies at this checkpoint:

- v0.5 remains **NOT COVENANT-BYTE-FROZEN**; COVENANT-FREEZE-READY may not be
  declared until the live testnet-10 proof (prerequisite B) has run.
- The v0.5 live proof is **date/node-gated**: the owner selected WAITING for
  the Option-A mainnet rollback node retirement gate (after 2026-09-05) and
  then using the local testnet-10 data/node. A second, memory-capped
  testnet-10 kaspad must NOT be started on the laptop while the Option-A
  node must stay warm. A genuinely separate trusted testnet-10 node may be
  PROPOSED as an alternative, but no new trust assumption may be introduced
  at the financial verification boundary without explicit classification.
- x402 does **not** begin until the v0.5 covenant-byte-freeze gate resolves.
- Preserve covenant `contracts/PolicyVault.v0.5.sil` sha256
  `c693aeffb59286d21d44452bde0943d78840b66cf480b629624b7747b4197dd9` and
  the completed prerequisite A/C/D evidence.
- DEX, vProgs, DAGKNIGHT-specific, and x402 implementation are all
  **not started**; they are roadmap / compatibility requirements only.

## 2. DEX / Swap Adapter Framework — product boundary

**POLICYVAULT MUST NOT BECOME A DEX.** PolicyVault will not operate:

- liquidity pools, AMMs, order books;
- proprietary swap liquidity, market making, LP-token economics;
- exchange custody.

External DEX / swap protocols provide execution and liquidity. PolicyVault
provides **AUTHORIZATION + DETERMINISTIC INTENT VERIFICATION + COVENANT /
POLICY ENFORCEMENT**. The signer remains external and retains custody.
PolicyVault MUST NOT sign the swap transaction.

A future agent should be able to REQUEST "Swap 500 USDx to KAS"; PolicyVault
must independently determine whether the exact proposed transaction is
authorized. The verification is a deterministic function of the raw
transaction and the vault's exact live state — never of a DEX API, indexer,
UI metadata, MCP response, or hosted service (none of those are authoritative
for financial semantics).

### 2.1 Minimum verification surface of a canonical DEX adapter

A future canonical DEX adapter verifies, at minimum:

| # | property | fails closed when |
|---|---|---|
| 1 | exact DEX / protocol covenant identity | unknown / unpinned protocol |
| 2 | exact pool or market identity (where applicable) | not the authorized pool/market |
| 3 | exact input asset descriptor / template | descriptor mismatch, unverified template |
| 4 | exact output asset descriptor / template | descriptor mismatch, unverified template |
| 5 | permitted trading pair | pair not in policy |
| 6 | maximum amount in | exceeds the authorized input |
| 7 | minimum amount out | proceeds below the authorized floor |
| 8 | maximum slippage | implied slippage above policy |
| 9 | permitted venue | venue not authorized |
| 10 | deadline / expiry | expired or unbounded |
| 11 | protocol fees | exceed policy or are hidden |
| 12 | network fees | exceed the fee policy / reserve rules |
| 13 | output / proceeds destination | not the authorized destination (vault successor or approved recipient) |
| 14 | resulting PolicyVault successor state | successor state not the exact expected transition |
| 15 | token conservation | any unexplained token delta |
| 16 | KAS fee-reserve preservation | reserve reduced beyond the permitted fee |
| 17 | absence of hidden / unapproved asset outputs | any output not accounted for by policy |
| 18 | exact transaction intent before external signing | intent manifest does not reproduce the bytes |

Unsupported DEX / protocol / template variants MUST FAIL CLOSED (the same
rule as `UNSUPPORTED_TOKEN_PROGRAM` in v0.5). Canonical swap verification
belongs in / derives from the shared deterministic core (`core/`), reused by
browser, mobile, server, CLI, MCP, and x402 surfaces — no surface may carry
independent swap semantics.

### 2.2 Relationship to earlier programs

- Depends on v0.5 asset descriptors (`policyvault-asset-descriptor/1`), the
  dual binding (covenant-ID WHO + hash-verified template WHICH), the
  two-domain accounting (token protected value vs KAS fee reserve), and the
  intent-manifest / explain / local-verification pipeline.
- Depends on the x402 facilitator only for ordering; the adapter framework
  is its own design gate with its own hostile matrix and production-byte
  proof before any freeze.

## 3. Kaspa Protocol Evolution Compatibility — permanent cross-cutting program

Not a sequential feature: every PolicyVault program must maintain explicit
foresight for relevant Kaspa protocol evolution, including DAGKNIGHT, vProgs,
future based-app execution models, inline / other ZK capabilities, covenant
opcode changes, transaction-version changes, covenant-ID changes, sighash
changes, transaction-introspection changes, fee / mass changes, mempool /
standardness changes, block-fit / resource-limit changes, SilverScript /
compiler changes, KCC / token-convention evolution, RPC / node API changes,
and wallet / signing standards.

- **CURRENT-PROTOCOL RULE:** do not postpone useful functionality that is
  provable on current Kaspa merely because a future protocol upgrade might
  improve it.
- **FUTURE-PROTOCOL RULE:** do not couple production PolicyVault financial
  semantics to unstable or experimental future APIs. Use explicit, versioned
  capability / adaptation boundaries.

### 3.1 vProgs foresight

vProgs is a possible FUTURE execution / composition backend — an optional
capability, not a current dependency. Do NOT rewrite current PolicyVault
around vProgs now. Potential future opportunities: larger or richer policy
state, shared-state applications, higher-concurrency coordination, complex
DEX routing, richer multi-party financial workflows, verified outcomes,
ZK-backed computation, and application logic that is inefficient in
individual covenant UTXOs.

POLICYVAULT AUTHORITY SEMANTICS REMAIN CANONICAL. Future vProgs support MUST
NOT: give PolicyVault custody; give PolicyVault servers signing keys; make
cloud execution authoritative without verifiable settlement; force existing
covenant vaults to migrate; silently widen owner / delegate authority.
Existing covenant vaults remain valid where consensus permits. Any migration
to a new execution architecture is explicit and owner-authorized.

### 3.2 DAGKNIGHT foresight

Separate **POLICY AUTHORIZATION** from **CHAIN ACCEPTANCE / FINALITY /
SETTLEMENT POLICY**. Today's confirmation / finality / timing behaviour is not
permanent. When DAGKNIGHT or another consensus upgrade approaches activation,
separately review: the CHAIN_VERIFIED definition; confirmation / finality
policy; reconciliation timing; DAA / time assumptions; periodic-budget
timing assumptions; transaction timeout policy; node / RPC behaviour; event /
notification timing; x402 settlement timing; DEX settlement timing;
verified-outcome settlement timing. Faster consensus must NEVER weaken
PolicyVault authorization. Avoid covenant migration if the upgrade does not
actually invalidate the existing covenant semantics.

### 3.3 Consensus-upgrade freeze rule

Any upstream Kaspa change affecting a property PolicyVault relies on
**reopens the AFFECTED freeze** — examples: script execution, serialization,
sighash, covenant IDs, introspection, compute budgets, fee / mass,
standardness, token-template validation, state-transition semantics. Before
adopting the changed capability in production:

```
UPSTREAM/SOURCE REVIEW
→ COMPATIBILITY IMPLEMENTATION
→ HOSTILE REGRESSION
→ PRODUCTION-BYTE PROOF (where applicable)
→ TESTNET/LIVE PROOF
→ OWNER RELEASE/FREEZE DECISION
```

Old code merely compiling is NOT compatibility evidence.

### 3.4 Migration / compatibility invariant

Protocol improvements should be ADDITIVE where possible. Preferred model:
the existing mode remains supported + the new capability becomes available +
the owner explicitly elects migration. Do not force migration of valid old
vaults unless consensus itself makes their continued use impossible. Unknown
or unverified protocol capability combinations FAIL CLOSED.

## 4. Parallel adoption UX — visual upgrade (PRESENTATION track)

The read-only inspection of commit `07b790b`
(`docs/postlaunch/onboarding-ux-inspection.md`, FUNCTIONALLY COMPLETE BUT
VISUALLY WEAK) was accepted, and a presentation-only upgrade was authorized
in a separable UX lane (`adoption-ux-visual`): preserve every behaviour and
message (6 steps, Skip on every step, Don't-show-again, Help replay,
persistent home entry, authority statement, wallet-vs-PolicyVault
distinction, accepted / refused / needs-approval examples, no private-key
request, never gates functionality, benign persistence only), and improve
presentation with local HTML / CSS / SVG, lightweight animation, no remote
or analytics dependency, no autoplay video / mandatory GIF, responsive
mobile layout, dark + light compatibility, prefers-reduced-motion support,
keyboard accessibility, and focused presentation / accessibility
regressions. The lane must not touch covenant, transaction construction,
signer, authentication, or deterministic financial semantics.
