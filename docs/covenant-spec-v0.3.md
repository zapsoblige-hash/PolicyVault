# PolicyVault Covenant Spec v0.3 (DESIGN — not frozen, not implemented)

Candidate design, source-proven at the primitive level
(`docs/v03-experiment-results.md`). Freeze only after Phase 4 real-VM
implementation + full negative-validation matrix. v0.2 remains the
production covenant and is unchanged.

## Scope

v0.3 adds, over v0.2:
- **Scalable recipient authorization** via a Merkle `recipientRoot`
  (replaces `recipient1..3`) — `docs/v03-recipient-auth-design.md`.
- **Covenant-enforced M-of-N approval thresholds** on large delegate
  spends — `docs/v03-approval-design.md`.

Everything else (per-spend cap, periodic budget, CLTV period progression,
value conservation, pause, revoke, rotate, top-up, policy migration,
terminal recovery, exact successor, singleton lineage) carries over from
v0.2 unchanged in intent.

## Candidate state layout

IMMUTABLE TEMPLATE (root of authority + identity; never change):
| field | type | why immutable |
|-------|------|---------------|
| owner | pubkey | root of authority (break-glass) |
| vaultId | byte[32] | vault identity anchor |

MUTABLE STATE (owner-guarded except accounting):
| field | type | notes |
|-------|------|-------|
| boundVaultId | byte[32] | echo of vaultId, exact-validated |
| protectedValue | int | exact principal in the covenant UTXO |
| periodStartDaa | int | budget period start (DAA) |
| periodSpent | int | delegate spend in current period |
| paused | int | 0/1 |
| delegate | pubkey | rotate/revoke |
| delegateActive | int | 0/1 |
| maxPerSpend | int | per-spend cap |
| periodBudget | int | cumulative period cap |
| periodLengthDaa | int | period length |
| recipientRoot | byte[32] | Merkle allowlist commitment (NEW) |
| approver1..N | pubkey | fixed approver slots, empty = zero pubkey (NEW) |
| approvalM | int | required approvals above threshold (NEW) |
| approvalThresholdAmount | int | delegate-only at/below this (NEW) |
| policyNonce | int | +1 on every owner policy change |

DERIVED / NOT STORED: successor script (rebuilt by the singleton
machinery from this template); the recipient tree (only its root is on
chain); per-transaction sighash (consensus-computed).

Field classification rationale: only `owner` and `vaultId` are immutable
(as in v0.2 — the minimal identity/authority anchor). All policy —
including the new recipient root and approver configuration — is mutable
owner-guarded state so it can evolve without a template change (the v0.2
lesson that avoided the impossible in-lineage migration). Accounting
fields stay mutable and are never reset by owner operations.

## Entry points (candidate)

Delegate:
- `delegateSpendWithProof(prevState, newState, payAmount, recipientPk,
  siblings, pathBits, delegateSig, approval1..N)` — one path covering
  both tiers: recipient membership proof always required; approvals
  required only when `payAmount > approvalThresholdAmount`. **Each
  `approvalK` is a `byte[]`, NOT a `sig`:** the covenant requires
  `length == 65` and trailing byte `== 0x01` (SIG_HASH_ALL gate, Phase 3.5
  finding) before `checkSig(sig(approvalK), approverK)`. Without the gate,
  a SIG_HASH_NONE approval authorizes an unseen payment (VM-proven).
- `rolloverAndSpendWithProof(...)` — as above, fused with a CLTV period
  advance (carried over from v0.2 rollover).

Owner (single owner signature — MODEL 2 governance):
- `ownerPause`, `ownerUnpause`, `revokeDelegate`, `rotateDelegate`,
  `ownerTopUp`, `migratePolicy` (caps/budget/period),
  `ownerSetRecipientRoot`, `ownerSetApprovers` (slots + M + threshold),
  `ownerRecover` (terminal). `ownerSetApprovers` MUST reject any set with
  a duplicate x-only key (Phase 3.5 finding — a duplicate key lets one
  signer satisfy two slots) and enforce `1 <= approvalM <=
  activeApproverCount` atomically.

## Preserved v0.2 invariants (unchanged)

- Exact principal conservation; exact successor `protectedValue`.
- No owner operation resets `periodSpent` / `periodStartDaa`.
- No delegate rotation or approver rotation resets accounting or budget.
- No policy migration grants a fresh budget.
- `policyNonce` strictly +1 per owner policy change.
- Paused semantics; terminal close stays terminal.
- Every delegate payment binds the exact output (now via the Merkle proof
  + P2PK output check rather than fixed slots).

## New v0.3 invariants

See `docs/security-invariants.md` (R1–R4 recipients, A1–A6 approvals,
G1–G2 governance, MG1–MG3 migration). Summary: every delegate payment
recipient must prove membership in the CURRENT `recipientRoot` and bind
the exact paid output; every spend above the threshold must carry ≥ M
distinct valid approvals from the CURRENT approver slots; approvals bind
the exact transaction/state; owner remains break-glass and recovery is
always available with the single owner key.

## Implementation status (Phase 4, consensus-critical band)

IMPLEMENTED + VM-VERIFIED (commit at Phase 4 consensus checkpoint):
- `contracts/PolicyVault.v0.3.sil` — 11 entrypoints; script 20,101 bytes;
  state region 528 bytes; N = 10 fixed approver slots (sentinel = all-zero
  pubkey); A7 sighash gate + A2 distinctness enforced.
- `pv_call_encoder` v0.3 dispatch (additive; v0.1/v0.2 byte-identical).
- Production-byte integration (`v3_encoder_integration.rs`): all 11
  entrypoints via the REAL encoder binary + an 11-case mutation matrix,
  all executed on the real VM.
- Valid + negative VM matrix (`v3_production.rs`, `v3_encoder_integration.rs`):
  recipient depths 0/1/4/8/12/16, approval configs incl. 10-of-10, the
  full non-ALL sighash rejection matrix, duplicate-key rejection,
  accounting-reset rejections, successor/nonce forgeries.
- SDK state compiler `sdk/src/vault-state-v3.js` (strict normalization,
  distinctness, M validity).
- Exact mass/fee: `pv_mass_probe` v0.3 shapes + `fee-mass.js` golden
  vectors (`docs/v03-mass-estimates.md` MEASURED section). Compute budgets
  measured under production sig-op pricing: depth0=24, depth16=26,
  2-of-3=56, 10-of-10=127, owner op=24, recover=15.

IMPLEMENTED + PRODUCTION-BYTE-PROVEN (Phase 4H, 2026-08-17): SDK builders
for genesis + all 11 entrypoints (`sdk/src/vault-builders-v3.js` and
supporting modules), canonical recipient Merkle SDK, freeze-before-collect
approval packages with fixed 65-byte SIG_HASH_ALL slots and authoritative
`pv_tx_probe` verification, proven-safe compute-budget tiers
(31/135/29/16), exact fees; the whole SDK construction path is executed on
the real TxScriptEngine against this production covenant
(`tests/vm/tests/v3_sdk_integration.rs`).

REMAINING before the freeze (Phase 4I+): API, wallet/dashboard UX,
organization approval UX, close-and-recreate upgrade UX, authorized live
testnet negative-validation + full testnet lifecycle, real-KasWare manual
verification. v0.3 remains NOT LIVE-TESTNET-VERIFIED.
