# PolicyVault Covenant Specification — v0.2

Status: **TESTNET-VERIFIED** (2026-08-13; see docs/testnet-evidence.md
"Vault 4"). Source: `contracts/PolicyVault.v0.2.sil`
(4708-byte script, state region start=1 len=246, 9 entrypoints).
Design rationale and lineage proofs: `docs/v02-lineage-findings.md`.
v0.1 (`contracts/PolicyVault.v0.1.beta.sil`) remains immutable and separately
deployed; v0.2 is an explicit new contract version.

## Field placement

Immutable template constants (never change for the lineage's lifetime):

| constant | role |
|---|---|
| `owner` | root of authority; signs every lifecycle operation |
| `vaultId` | vault identity anchor (echoed in state as `boundVaultId`) |

Mutable exact live state (all validated field-by-field on every transition):

| field | changed by | preserved by |
|---|---|---|
| `protectedValue` | delegateSpend/rollover (−pay), ownerTopUp (+) | everything else |
| `periodStartDaa` | rolloverAndSpend (CLTV-proven) | everything else incl. ALL owner ops |
| `periodSpent` | delegateSpend (+pay), rollover (=pay) | everything else incl. ALL owner ops |
| `paused` | ownerPause/ownerUnpause | everything else |
| `delegate` | rotateDelegate | everything else |
| `maxPerSpend`, `periodBudget`, `periodLengthDaa` | migratePolicy | everything else |
| `recipient1..3` | migratePolicy | everything else |
| `delegateActive` | revokeDelegate (→0), rotateDelegate (→1) | everything else |
| `policyNonce` | migratePolicy (exactly +1) | everything else |

## Paths

Delegate paths (require `checkSig(delegateSig, prevState.delegate)`,
`prevState.delegateActive == 1`, `prevState.paused == 0`, and preserve every
owner-policy field exactly):

- `delegateSpend(newState, payAmount, recipientIndex, sig)` — as v0.1, with
  limits/allowlist read from **previous state**.
- `rolloverAndSpend(newState, payAmount, recipientIndex, periodsElapsed, sig)`
  — CLTV time proof `tx.time >= periodStartDaa + periodsElapsed*periodLengthDaa`
  (period length from previous state).

Owner paths (require `checkSig(ownerSig, owner)`; ALL preserve
`protectedValue`* , `periodStartDaa`, `periodSpent` — no lifecycle operation
can move value or reset budget accounting; *top-up increases value):

- `ownerPause` / `ownerUnpause` — flip `paused`, all else exact-copy.
- `revokeDelegate` — `delegateActive 1→0`, all else exact-copy. The vault
  stays owner-usable; delegate key retained in state for audit.
- `rotateDelegate(newState, newDelegate, sig)` — `delegate := newDelegate`
  (pinned by the explicit arg — successor with any other key is rejected),
  `delegateActive := 1` (doubles as re-enable-after-revoke), all else
  exact-copy. **Rotation never resets periodSpent/periodStartDaa** — a new
  key inherits the current period's accounting.
- `ownerTopUp` — `protectedValue` strictly increases; successor output value
  equals the new principal exactly; every other field exact-copy. Funding
  comes from ordinary owner inputs; fee never touches principal.
- `migratePolicy` — may change `maxPerSpend`, `periodBudget`,
  `periodLengthDaa`, `recipient1..3` (all must be > 0 where numeric);
  `policyNonce := prev + 1` exactly; principal, accounting, delegate
  identity/status, pause status exact-copy. If the new budget is below
  `periodSpent`, delegate spending stays blocked until a valid rollover;
  the preserved `periodStartDaa` + the NEW `periodLengthDaa` define the
  next rollover boundary deterministically.
- `ownerRecover(nextStates=[], sig)` — terminal; full principal to owner
  P2PK at output 0; works regardless of pause/revocation.

## Identity / lineage (all VM-proven)

| ACTION | vaultId | covenantId | template | contractVersion | policyNonce | stateId | outpoint |
|---|---|---|---|---|---|---|---|
| spend/rollover | same | same | same | same | same | new | new |
| pause/unpause | same | same | same | same | same | new | new |
| revoke | same | same | same | same | same | new | new |
| rotate | same | same | same | same | same | new | new |
| topUp | same | same | same | same | same | new | new |
| migrate | same | same | same | same | +1 | new | new |
| recover | — | ends | — | — | — | terminal | consumed |

v0.1 → v0.2 upgrade: `ownerRecover` on the v0.1 vault, then create a v0.2
vault (new genesis/lineage). In-lineage migration from v0.1 is impossible
(proven; see lineage findings §3).

## Test coverage (VM layer, real TxScriptEngine + real Schnorr)

- `tests/vm/tests/v2_happy_path.rs` — 14 V2-VVM tests: spends (plain, exact
  cap, exact budget, sequential), rollover, pause/unpause, revoke→rotate→
  spend-by-new-delegate, rotation accounting preservation, top-up→spend,
  migration→spend-under-new-policy, allowlist migration→pay-new-recipient,
  budget-below-spent migration→rollover, recover (plain and while
  revoked+paused), layout sanity.
- `tests/vm/tests/v2_adversarial.rs` — 32 V2-AVM negative-validation tests
  covering the required matrix: delegate-signed lifecycle attempts, wrong
  signatures, successor forgeries (retained authority, unintended rotation
  key, allowlist/cap/nonce smuggling in spends/top-ups/rotations/
  migrations), accounting resets hidden in every owner op, top-up value
  mismatches (under/over/no-increase/decrease), migration nonce/identity/
  zero-value violations, paused/revoked spends and rollovers, cross-template
  successor substitution (owner-signed), delegate recovery attempt, multiple
  bound successors, unauthorized termination.

Whole-suite total: 101 VM tests PASS (44 v0.1 + 11 Phase A experiment +
14 + 32 v0.2). The 44-test v0.1 baseline is untouched.

## Known limitations

- Compute cost: the v0.2 script is ~2.8× the v0.1 script; the live covenant
  input compute budget (100 in v0.1 transactions) must be re-measured on
  testnet and the fee-mass golden vectors extended for v0.2 shapes.
- Approval thresholds/multisig remain v0.3.
- Stale-transaction replay across states is prevented by consensus (outpoint
  consumption + SIG_HASH_ALL binding to the spent outpoint), not by the
  script; covered at the SDK layer by transition claims.
