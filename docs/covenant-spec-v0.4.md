# PolicyVault Covenant Spec v0.4 — frozen prior version (superseded by v0.4.1)

Status: ABI frozen, implemented, VM-proven and production-byte-proven;
superseded by v0.4.1 (identical semantics, standard-mempool sig-op count)
as the deployed protocol — see `docs/covenant-spec-v0.4.1.md`. `contracts/PolicyVault.v0.4.sil`
exists (deterministic generator `tools/gen_v4.js`, byte-identical
regeneration test), the `pv_call_encoder` has an additive `policyvault-0.4`
dispatch, and the SDK low-level state compiler exists
(`sdk/src/{vault-state-v4,contract-compiler-v4}.js`). The full byte path is
proven on the real VM (see the implementation record at the end for measured
facts). NOT yet live-testnet-verified. High-level SDK transaction builders,
API, and UI are deliberately NOT implemented yet. v0.1/v0.2/v0.3 remain
unchanged and byte-identical.

Evidence: isolated VM experiments during the design gate, then
production-byte tests
(`tests/vm/tests/v4_production.rs`, `v4_encoder_integration.rs`,
`sdk/test/vault-state-v4.test.js`, `sdk/test/fee-mass.test.js`).

## Scope

v0.4 adds the two FINAL major consensus features:
- **Covenant-controlled fee reserve** (FR-1).
- **Multiple independent delegates / AI agents** (MD-3) with per-agent
  authenticated policy and per-agent approval thresholds.

The single v0.3 delegate and its per-delegate policy fields MOVE INTO the
per-agent leaf, so fixed vault state shrinks even as capability grows.

---

## 1. FROZEN state ABI

IMMUTABLE TEMPLATE (constructor constants; never change post-genesis):

| # | field | type | width | signed | ctor pos |
|---|-------|------|------:|--------|---------:|
| — | owner | pubkey | 32 | n/a | 0 |
| — | vaultId | byte[32] | 32 | n/a | 1 |

MUTABLE STATE (state region, in declaration/serialization order):

| # | field | type | width | signed | init | mutated by |
|---|-------|------|------:|--------|------|-----------|
| 0 | boundVaultId | byte[32] | 32 | n/a | vaultId | (never; identity echo) |
| 1 | protectedValue | int | 8 (num8) | unsigned* | genesis deposit | agentSpend(−pay), ownerTopUp(+), ownerRecover(T) |
| 2 | feeReserve | int | 8 (num8) | unsigned* | genesis reserve | agentSpend(−consumed), ownerTopUpReserve(+), ownerRecover(T) |
| 3 | paused | int | 8 (num8) | 0/1 | 0 | ownerPause(→1), ownerUnpause(→0) |
| 4 | agentRoot | byte[32] | 32 | n/a | genesis agent tree | agentSpend(accounting update), ownerSetAgentRoot(replace) |
| 5 | approver1 | pubkey | 32 | n/a | sentinel/approver | ownerSetApprovers |
| … | approver2..10 | pubkey | 32 each | n/a | sentinel/approver | ownerSetApprovers |
| 15 | approvalM | int | 8 (num8) | unsigned | 0 or M | ownerSetApprovers |
| 16 | policyNonce | int | 8 (num8) | unsigned | 0 | +1 on ownerSetAgentRoot / ownerSetApprovers |

*"unsigned" = the value domain is non-negative; the on-chain encoding is
`num8 = OpNum2Bin(v,8)` (canonical little-endian, injective over i64). A
negative state field is structurally unconstructible (the SilverScript
front-end refuses to compile a negative state template).

State region size (10 approver slots), computed from the compiler's exact
layout — each state field carries a 1-byte push opcode + its payload
(byte[32]/pubkey = 33 B, int = 9 B; source-verified: v0.3's 528 B =
13×33 + 11×9, and the 2-slot combined probe's 177 B = 4×33 + 5×9):
byte[32]/pubkey fields = boundVaultId + agentRoot + approver1..10 = 12×33
= 396; int fields = protectedValue + feeReserve + paused + approvalM +
policyNonce = 5×9 = 45; **state region = 441 bytes** (payload 432; vs
v0.3's 528). The covenant UTXO holds `protectedValue + feeReserve` sompi.
(int fields use the same 8-byte canonical encoding as the leaf's num8.)

REMOVED vs v0.3 (now per-agent, in the leaf): `delegate`, `delegateActive`,
`maxPerSpend`, `periodBudget`, `periodLengthDaa`, `periodStartDaa`,
`periodSpent`, `recipientRoot`, `approvalThresholdAmount`. There is NO
global `maxFeePerTx` (fee authority is per-agent, in the leaf).

## 2. FROZEN agent-policy leaf ABI

Ordered preimage (124 bytes), hashed with SHA-256:

| offset | field | width | encoding |
|-------:|-------|------:|----------|
| 0 | domain separator `0x50 0x56 0x34 0x01` | 4 | fixed ("PV" v4 recordType=agent-policy) |
| 4 | agentPk | 32 | x-only pubkey (the KEY binding) |
| 36 | maxPerSpend | 8 | num8 |
| 44 | periodBudget | 8 | num8 |
| 52 | periodLengthDaa | 8 | num8 |
| 60 | periodStartDaa | 8 | num8 (advanced in-covenant) |
| 68 | periodSpent | 8 | num8 (advanced in-covenant) |
| 76 | approvalThreshold | 8 | num8 |
| 84 | agentMaxFeePerTx | 8 | num8 (per-agent fee authority) |
| 92 | agentRecipientRoot | 32 | per-agent SHA-256 recipient Merkle root |
| — | **total preimage** | **124** | |

- `num8(v) = OpNum2Bin(v, 8)` — consensus-canonical fixed-width
  little-endian (`serialize_i64`), injective over i64; unique for every
  sompi/DAA value (0 ≤ v < 2^63).
- `agentLeaf = SHA256(preimage)` (32-byte leaf).
- The covenant ALWAYS reconstructs the leaf from typed call arguments;
  it never accepts a preformed leaf.

## 3. FROZEN Merkle parameters

| tree | leaf | internal node | max depth | proof |
|------|------|---------------|----------:|-------|
| agent-policy | `SHA256(0x50563401 ‖ …)` (124 B preimage) | `SHA256(left ‖ right)` (64 B) | **12** (4,096 agents) | siblings ≤ 384 B (mult. of 32), `pathBits` in [0, 4096) |
| recipient (per agent) | `SHA256(0x50563301 ‖ xonly)` (36 B preimage) | `SHA256(left ‖ right)` (64 B) | **16** (65,536) | siblings ≤ 512 B, `pathBits` in [0, 65536) |

- Domain separation: 124-byte agent-leaf preimage vs 36-byte recipient-leaf
  preimage vs 64-byte node — three distinct lengths, no cross-interpretation.
- `pathBits` bit *i* (LSB-first) = 1 ⇒ the running node is the RIGHT child
  at level *i* (sibling hashed on the LEFT). Fully consumed after the walk
  (`bits == 0`).
- Padding: SDK pads the leaf level to the next power of two by duplicating
  the last leaf (documented benign path-bit insignificance at padded
  levels — same recipient/agent, same root).
- **Agent-tree max depth 12 rationale:** 4,096 independent agents per vault
  is far beyond any realistic single-treasury agent count; smaller than the
  recipient depth (16) to bound worst-case proof/compute/stack; treasury
  segmentation into multiple vaults (MD-4, org metadata, no new consensus)
  handles any larger need. Explicit + consensus-verifiable
  (`siblings.length ≤ 384`, ≤ 12 levels).

## 4. FROZEN entrypoints

Delegate/agent tier:
- **agentSpend**(prevState, newState, payAmount, agentPk, maxPerSpend,
  periodBudget, periodLengthDaa, periodStartDaa, periodSpent,
  approvalThreshold, agentMaxFeePerTx, agentRecipientRoot, policySiblings,
  policyPathBits, periodsElapsed, recipientPk, recipientSiblings,
  recipientPathBits, agentSig, approvals[650]) — one path covering both
  spend tiers and rollover.

Owner (single owner signature — MODEL 2 governance):
- **ownerSetAgentRoot** — replace `agentRoot`; nonce +1. (add/remove/rotate/
  re-policy/fee-cap/per-agent-pause = SDK tree edit + this root swap)
- **ownerSetApprovers** — replace approver slots + `approvalM`; nonce +1.
- **ownerTopUp** — increase `protectedValue`; nonce preserved.
- **ownerTopUpReserve** — increase `feeReserve`; nonce preserved.
- **ownerPause** / **ownerUnpause** — flip `paused`; nonce preserved.
- **ownerRecover** — terminal; pays `protectedValue + feeReserve` to owner.

Dropped vs the initial draft: `ownerSetMaxFeePerTx` (fee cap is now
per-agent in the leaf, changed via `ownerSetAgentRoot`).

### Per-entrypoint state-change permissions (frozen)

Legend: `=` MUST preserve · `Δ` MUST change per rule · `~` may change ·
`T` terminal.

| field | agentSpend | setAgentRoot | setApprovers | topUp | topUpReserve | pause | unpause | recover |
|-------|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|
| boundVaultId | = | = | = | = | = | = | = | T |
| protectedValue | Δ−pay | = | = | Δ+ | = | = | = | T |
| feeReserve | Δ−consumed | = | = | = | Δ+ | = | = | T |
| paused | =(must be 0) | = | = | = | = | Δ→1 | Δ→0 | T |
| agentRoot | Δ(accounting) | Δ(replace) | = | = | = | = | = | T |
| approver1..10 | = | = | Δ(replace) | = | = | = | = | T |
| approvalM | = | = | Δ | = | = | = | = | T |
| policyNonce | = | Δ+1 | Δ+1 | = | = | = | = | T |

agentSpend additionally: `agentSig` verifies against the leaf `agentPk`;
`payAmount ≤ leaf.maxPerSpend`; per-agent period accounting advanced in the
leaf (`periodSpent += pay`, or rollover with CLTV `tx.time ≥ newStart`);
recipient membership + exact output-0 binding against `leaf.agentRecipientRoot`;
above `leaf.approvalThreshold` requires ≥ `approvalM` vault-global approvals
(A7 SIG_HASH_ALL gate); `0 ≤ reserveConsumed ≤ leaf.agentMaxFeePerTx`;
`reserveConsumed ≤ fee`; successor value == `newProtected + newFeeReserve`.

## 5. FROZEN nonce rule

`policyNonce` is RETAINED. It increments by exactly 1 on `ownerSetAgentRoot`
and `ownerSetApprovers` (the policy-defining ops) and is preserved by every
other entrypoint. **Consensus replay-safety does NOT depend on the nonce** —
SIG_HASH_ALL binds the specific input outpoint, so any package is bound to
one consumed outpoint and cannot replay against a later same-tuple state.
The nonce is retained for (a) a clean monotonic governance/audit counter and
(b) trivial SDK stale-package detection; it is defense in depth, not the
replay defense. (VM-experiment-proven: `v4c_owner_ops` requires the +1.)

## 6. FROZEN value conservation

Summary:
`fee = reserveConsumed + (externalIn − externalOut)`, and the covenant
requires `reserveConsumed ≤ fee`, so `externalOut ≤ externalIn`: no covenant
value (principal or reserve) can escape to a non-pinned output; principal
moves only by the exact payment; reserve becomes only network fee, bounded
by the spending agent's own `agentMaxFeePerTx`.

## 7. Migration / versioning

v0.3 → v0.4 in-lineage migration is **VM-EXPERIMENT-PROVEN IMPOSSIBLE**
(proven during the design gate: the real production v0.3 covenant rejects a
v0.4-template successor). Upgrade = v0.3 `ownerRecover` → v0.4 create (new
covenantId/lineage). v0.4 gets contractVersion `policyvault-0.4`, its own
encoder dispatch arm, compiler, normalizer, SDK builders, manifest support,
fee/mass vectors; unknown versions fail closed; v0.1/v0.2/v0.3 remain
independently interpretable.

## 8. Implementation status

ARCHITECTURE FROZEN + EXPERIMENT-PROVEN via isolated probes before
production implementation (recorded below).

---

## Implementation record — production covenant + byte path (MEASURED)

Status upgraded: the frozen ABI is now IMPLEMENTED as the production
covenant `contracts/PolicyVault.v0.4.sil` (deterministic generator
`tools/gen_v4.js`, byte-identical regeneration test) and PROVEN through the
real byte path. NOT yet live-testnet-verified.

**Measured production facts (supersede the design projections):**
- redeem script: **18,839 bytes** (smaller than v0.3's 28,483 — the single
  delegate + fixed policy fields moved into the per-agent leaf).
- state region: **441 bytes** (exactly as frozen), 17 mutable fields.
- agent-leaf preimage: 124 bytes (7 num8 fields + domain + agentPk + root).
- compute budgets under production sig-op pricing (Gram(1000)=100,000/checkSig):
  | shape | used script units | required budget |
  |-------|------------------:|----------------:|
  | agent spend, agent depth 0, recip depth 0, below threshold | 222,758 | 23 |
  | agent spend, agent depth 12, recip depth 0, below threshold | 251,768 | 26 |
  | agent spend, agent depth 0, recip depth 16, below threshold | 245,943 | 25 |
  | **WORST: agent depth 12 + recip depth 16 + 10-of-10 + reserve** | **1,318,131** | **132** |
  | ownerSetAgentRoot | 219,115 | 22 |
  | ownerRecover (terminal) | 137,927 | 14 |
- exact fees (rusty-kaspa MassCalculator ↔ `sdk/src/fee-mass.js`, both green):
  | shape | feeMass | min fee (KAS) |
  |-------|--------:|--------------:|
  | create (2in/3out) | 3,604 | 0.003604 |
  | agent spend min, reserve-funded (1in/2out) | 40,808 | 0.040808 |
  | agent spend min + fuel (2in/3out) | 41,152 | 0.041152 |
  | agent spend worst + fuel | 42,950 | 0.042950 |
  | owner op | 39,454 | 0.039454 |
  | recover | 38,596 | 0.038596 |
  Fees are transient-mass-dominated (~0.036–0.043 KAS), LOWER than v0.3's
  ~0.06 KAS because the redeem script is smaller.
- **stack:** the true worst case (agent depth 12 + recipient depth 16 +
  10-of-10 + reserve) EXECUTES on the real VM, proving peak stack ≤
  `MAX_STACK_SIZE 244`. Achieving this required the v0.3 stack discipline
  plus one v0.4-specific reduction: the 45-pair predecessor
  approver-distinctness checks are INLINED in `requireApproverSetWellFormed`
  (not routed through a per-pair helper) to remove one call-nesting level —
  the extra frame tipped the combined worst case one slot over 244. Same
  semantics; no frozen-ABI change (leaf/state/entrypoints/rules unchanged).

**Byte-path proof:** `tests/vm/tests/v4_encoder_integration.rs` drives the
REAL `pv_call_encoder` binary (SDK-shaped source + constructor-args +
call.json) through the production covenant on the real TxScriptEngine for
all 8 entrypoints + a mutation matrix; `tests/vm/tests/v4_production.rs`
executes the full valid + negative matrix (incl. the funds-critical
single-leaf agent-tree update, cross-agent theft, malformed-genesis
approval defense, fee-reserve isolation, per-agent fee cap, pause, owner
ops, recovery) on the production covenant; the SDK compiler is byte-exact
(`sdk/test/vault-state-v4.test.js`). v0.1/v0.2/v0.3 covenants + encoder +
fee-mass core byte-identical; v2_encoder_integration 9/9.

Status: **PRODUCTION-VM-PROVEN + PRODUCTION-BYTE-PROVEN, NOT
LIVE-TESTNET-VERIFIED.**

---

## Implementation record — high-level SDK construction layer (OFFLINE)

The v0.4 high-level SDK transaction-construction layer is now IMPLEMENTED and
PRODUCTION-BYTE-PROVEN offline, on top of the frozen covenant.
Production covenant bytes are UNCHANGED (SHA256 unchanged; `tools/gen_v4.js`
regenerates byte-identically). New modules: `agent-merkle-v4`,
`vault-transitions-v4`, `compute-budget-v4`, `approval-package-v4`,
`vault-builders-v4` (+ `normalizeStateV4ForRecovery` added to
`vault-state-v4`). The reused v0.3 recipient tree reproduces the frozen v0.4
covenant walk byte-for-byte (no fork). A funds-critical agent-tree padding finding was found and closed during
the hostile review (unspendable padding leaf `SHA256(0x50563400)`; duplicate-last padding would
have created extra spendable budget lanes) and the full 42-vector
production-byte matrix. Status: v0.4 is VM-proven and production-byte-proven; live deployment
uses v0.4.1.
