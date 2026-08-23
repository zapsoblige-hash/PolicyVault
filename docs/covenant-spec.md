# PolicyVault Covenant Specification — v0.1-beta (DRAFT)

Status: **DESIGNED** (not frozen). The state layout must not be frozen until
the Phase 3 open questions in `source-review-findings.md` §5 are proven by
compile/VM experiments. Everything here is grounded in the Phase 1 findings.

## 1. Purpose

One PolicyVault covenant instance ("vault") holds protected KAS and enforces,
under Kaspa consensus:

- only the designated delegate can spend within policy;
- each spend ≤ `maxPerSpend`;
- cumulative spends within a period ≤ `periodBudget`;
- period progression is consensus-verified (DAA-score based, CLTV);
- payments go only to allowlisted recipients;
- every spend produces exactly one successor vault with exact state and
  exact value conservation;
- the owner can always recover remaining funds;
- the owner can pause the delegate (v0.1 includes pause/unpause;
  revoke/rotate/policy-migration follow in v0.2 after the nucleus is
  testnet-proven).

## 2. Constructor parameters (immutable identity)

```text
pubkey owner                  // owner authority (32-byte x-only schnorr key)
pubkey delegate               // delegate authority
byte[32] vaultId              // unique vault identity, chosen at creation
int maxPerSpend               // sompi, > 0
int periodBudget              // sompi, >= maxPerSpend
int periodLengthDaa           // DAA units, > 0
pubkey recipient1..recipientN // allowlist (N fixed per compiled contract, 1–3 in v0.1)
int initValue                 // initial protected principal, sompi
int initPeriodStartDaa        // DAA score at/before creation
```

Rationale: immutable policy lives in constructor params (part of the
template), mutable accounting lives in state fields. Changing policy is
therefore a *template change* = policy migration (v0.2), which preserves the
earlier-production lesson that state region vs template region are distinct
(`state_layout`).

Note: allowlist size N is fixed per compiled artifact. v0.1 ships N = 3
(unused slots repeat recipient1). This keeps the template stable across
vaults with 1–3 recipients.

## 3. State fields (mutable, exact live state)

```text
int protectedValue     // exact sompi held by the covenant UTXO
int periodStartDaa     // start of current budget period (DAA score)
int periodSpent        // sompi spent in current period
int paused             // 0 = active, 1 = paused
```

The full exact live-state tuple = constructor params + state fields +
contract version. State ID = blake2b-256 over the canonical encoding of that
tuple (defined in the SDK, tested with fixed vectors).

## 4. Spend paths

### 4.1 `delegateSpend` — #[covenant.singleton]

Signature (verification mode):

```text
delegateSpend(State prevState, State newState,
              int payAmount, int recipientIndex, sig delegateSig)
```

Requires:

1. `checkSig(delegateSig, delegate)`.
2. `prevState.paused == 0`.
3. `payAmount > 0` and `payAmount <= maxPerSpend`.
4. `prevState.periodSpent + payAmount <= periodBudget`.
5. Recipient: `tx.outputs[0].scriptPubKey == new ScriptPubKeyP2PK(recipientK)`
   where `recipientK` is selected by `recipientIndex` from the fixed
   allowlist (explicit if/else chain over N; invalid index fails).
6. `tx.outputs[0].value == payAmount` (exact, not >=; prevents paying the
   recipient more than accounted).
7. Successor state exactness:
   - `newState.protectedValue == prevState.protectedValue - payAmount`
   - `newState.periodStartDaa == prevState.periodStartDaa`
   - `newState.periodSpent == prevState.periodSpent + payAmount`
   - `newState.paused == 0`
8. Successor value exactness: the authorized output
   (`OpAuthOutputIdx(this.activeInputIndex, 0)`) has
   `value == newState.protectedValue`.
9. `newState.protectedValue > 0` (a spend may not zero the vault in v0.1;
   closing is owner recovery. Keeps the "exactly one successor" invariant
   simple).

Value conservation equation (covenant principal):

```text
prevState.protectedValue == payAmount + newState.protectedValue
```

Fees are paid by ordinary delegate UTXOs (inputs 1..N) with ordinary change
outputs — never from protected principal. The covenant does not need to
inspect fee inputs; it pins output 0 (payment) and the authorized successor
output exactly, so extra inputs/outputs cannot touch protected value.

### 4.2 `rolloverAndSpend` — #[covenant.singleton]

Same as `delegateSpend` but starts a new period first:

```text
rolloverAndSpend(State prevState, State newState,
                 int payAmount, int recipientIndex, int periodsElapsed,
                 sig delegateSig)
```

1. `checkSig(delegateSig, delegate)`; `prevState.paused == 0`.
2. `periodsElapsed >= 1` (bounded above by a small constant, e.g. <= 1000,
   to cap arithmetic).
3. New period start:
   `newStart = prevState.periodStartDaa + periodsElapsed * periodLengthDaa`.
4. **Time proof:** `require(tx.time >= newStart)` — CLTV proves the network
   DAA score exceeded `newStart` at acceptance. The delegate cannot fake
   this (consensus rejects lock_time above current DAA score); they can only
   under-claim `periodsElapsed`, which is budget-conservative.
5. `payAmount > 0`, `payAmount <= maxPerSpend`,
   `payAmount <= periodBudget` (fresh period).
6. Recipient/exact-payment checks as in 4.1.
7. Successor:
   - `newState.protectedValue == prevState.protectedValue - payAmount`
   - `newState.periodStartDaa == newStart`
   - `newState.periodSpent == payAmount`
   - `newState.paused == 0`
8. Successor value exact; `newState.protectedValue > 0`.

Design note: rollover is fused with a spend (rather than a separate no-spend
rollover transition) so the delegate never needs to pay fees just to tick a
period. A standalone `rollover` path is unnecessary: budgets reset lazily at
next spend.

### 4.3 `ownerPause` / `ownerUnpause` — #[covenant.singleton]

```text
ownerPause(State prevState, State newState, sig ownerSig)
```

1. `checkSig(ownerSig, owner)`.
2. All fields copied exactly except `paused`: pause requires
   `prevState.paused == 0`, `newState.paused == 1`; unpause the reverse.
3. Successor value exact: authorized output value ==
   `newState.protectedValue` (unchanged).
4. No payment output required; output 0 is the successor itself.

### 4.4 `ownerRecover` — #[covenant.singleton(mode = transition, termination = allowed)]

```text
ownerRecover(State prevState, State[] nextStates, sig ownerSig) : (State[])
```

1. `checkSig(ownerSig, owner)`.
2. `nextStates.length == 0` (terminal; lineage ends).
3. `tx.outputs[0].scriptPubKey == new ScriptPubKeyP2PK(owner)`.
4. `tx.outputs[0].value == prevState.protectedValue` (exact full recovery).
5. Works regardless of `paused` — owner recovery is unconditional.

## 5. What is NOT in v0.1 (explicitly deferred)

- revoke/rotate delegate, top-up, limit changes, policy migration → v0.2
  (template-change transitions; need the nucleus proven first).
- approval thresholds / co-signing → v0.3, only if actual covenant support
  is proven.
- allowlist > 3 entries, allowlistRoot/Merkle proofs → later.
- partial owner recovery → later (full recovery is sufficient for safety).

## 6. Fee / transaction architecture

```text
INPUT 0   PolicyVault covenant UTXO (value == prevState.protectedValue)
INPUT 1+  ordinary delegate/owner UTXOs (fees)
OUTPUT 0  payment (spend paths) or owner recovery (recover path)
          — successor itself for pause/unpause (no payment output)
OUTPUT k  successor covenant (authorized, exact newState.protectedValue)
OUTPUT k+1 ordinary change (optional)
```

To be verified in Phase 4 (VM) and Phase 13+ (testnet): the exact position
of the authorized successor output is discovered by `OpAuthOutputIdx`, so
the covenant does not assume its index — but builders will place it
deterministically (payment at 0, successor at 1, change at 2).

## 7. Adversarial obligations

Every requirement above maps to at least one adversarial VM test in
`docs/threat-model.md`. The covenant is VM-VERIFIED only when the full
matrix passes against real TxScriptEngine execution with real Schnorr
signatures, and TESTNET-VERIFIED only after live direct-to-node rejection
tests.
