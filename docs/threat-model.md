# PolicyVault Threat Model

Attacker model: a malicious party holding the **legitimate delegate private
key**, full knowledge of the covenant, and direct node access (bypassing all
PolicyVault software). Secondary attackers: a compromised PolicyVault
backend/frontend, a crashed/racing local process, and a hostile network
peer. The owner key is assumed uncompromised (an attacker with the owner key
owns the vault by definition).

Format per threat: **Invariant** (docs/security-invariants.md), **Layer**,
**Test** (planned id), **Expected**. `Actual` columns are filled in as test
layers execute; until then status is DESIGNED.

Test id prefixes: `AVM` = adversarial VM test (Phase 5), `VVM` = valid-path
VM test (Phase 4), `SDK`/`API`/`CR` (crash-recovery)/`TN` (live testnet).

| # | Threat | Invariant | Layer | Test | Expected |
|---|--------|-----------|-------|------|----------|
| 1 | Wrong delegate key signs a spend | I1 | CONSENSUS | AVM-01 | script fails (bad checkSig) |
| 2 | Payment to non-allowlisted recipient | I7 | CONSENSUS | AVM-02 | script fails |
| 3 | Single spend over `maxPerSpend` | I3 | CONSENSUS | AVM-03 | script fails |
| 4 | Cumulative spends exceed `periodBudget` | I4 | CONSENSUS | AVM-04 | script fails |
| 5 | Early period reset (rollover before period end) | I5 | CONSENSUS | AVM-05 | CLTV/consensus rejects |
| 6 | Forged period start (successor periodStartDaa not prev + k*len) | I5, I6 | CONSENSUS | AVM-06 | script fails |
| 7 | Successor with reduced `periodSpent` (no rollover proof) | I6 | CONSENSUS | AVM-07 | script fails |
| 8 | Successor with unchanged `periodSpent` after spend | I6 | CONSENSUS | AVM-08 | script fails |
| 9 | Successor with wrong increment (`periodSpent != prev + pay`) | I6 | CONSENSUS | AVM-09 | script fails |
| 10 | Successor with modified owner | I11 | CONSENSUS | AVM-10 | template mismatch fails |
| 11 | Successor with modified delegate | I11 | CONSENSUS | AVM-11 | template mismatch fails |
| 12 | Successor with modified `maxPerSpend` | I11 | CONSENSUS | AVM-12 | template mismatch fails |
| 13 | Successor with modified `periodBudget` | I11 | CONSENSUS | AVM-13 | template mismatch fails |
| 14 | Successor with modified allowlist | I11 | CONSENSUS | AVM-14 | template mismatch fails |
| 15 | Successor with modified policy constants (periodLengthDaa) | I11 | CONSENSUS | AVM-15 | template mismatch fails |
| 16 | Successor bound to wrong vault identity (other vaultId) | I11 | CONSENSUS | AVM-16 | template mismatch fails |
| 17 | Successor output value != `newState.protectedValue` | I9, I10 | CONSENSUS | AVM-17 | script fails |
| 18 | Siphon protected principal into ordinary change output | I9 | CONSENSUS | AVM-18 | script fails (value equation) |
| 19 | Extra unauthorized output claiming covenant binding | I10 | CONSENSUS | AVM-19 | covenant context rejects |
| 20 | Spend with missing successor (delegate burns vault) | I10, I14 | CONSENSUS | AVM-20 | script fails (auth output count) |
| 21 | Spend with multiple successors | I10 | CONSENSUS | AVM-21 | script fails |
| 22 | Delegate executes terminal path (unauthorized termination) | I14, I2 | CONSENSUS | AVM-22 | script fails (owner checkSig) |
| 23 | Delegate attempts `ownerRecover` with delegate sig | I12, I2 | CONSENSUS | AVM-23 | script fails |
| 24 | Spend against stale (already-spent) covenant state | A2 | CONSENSUS (double-spend) + APP | SDK-24, TN-24 | node rejects; app fails closed |
| 25 | Two conflicting prepared spends on one outpoint | A4 | APP | SDK-25 | transition claim blocks second |
| 26 | Request replay (same request re-submitted) | A4, A5 | APP | SDK-26 | claim/guard rejects |
| 27 | Signed-package tampering (any tx field) | A5 | APP | SDK-27 | validation rejects |
| 28 | Version confusion (v0.1 artifact routed to other builder) | A1 | APP | SDK-28 | fail closed |
| 29 | Unknown-version fallback attempt | A1 | APP | SDK-29 | fail closed, no default route |
| 30 | Corrupted manifest (truncated/garbled JSON) | A2 | APP | SDK-30 | fail closed as UNKNOWN |
| 31 | Crash before broadcast (claim exists, no tx) | A3, A4 | APP | CR-31 | deterministic recovery |
| 32 | Crash after broadcast (tx on chain, no receipt) | A3, A4 | APP | CR-32 | reconcile proves effect, advances |
| 33 | Node accepted tx but successor not yet observed | A3 | APP | SDK-33 | no success report; claim preserved |
| 34 | Floating-point / rounding amounts (e.g. 0.1 KAS float) | A6 | APP | SDK-34 | parser rejects |
| 35 | Fee-drain: covenant principal consumed as fees | I9 | CONSENSUS | AVM-35 | value equation fails |
| 36 | Malformed signature bytes (wrong length/sighash byte) | I1 | CONSENSUS | AVM-36 | script fails |
| 37 | Wrong network (mainnet address / mismatched networkId) | A7 | APP | SDK-37 | build/sign/submit refused |
| 38 | Valid delegate key + illegal policy transition (paused vault spend; pause-flag flip by delegate) | I13, I2 | CONSENSUS | AVM-38 | script fails |

Additional threats discovered during design (extend as found):

| # | Threat | Invariant | Layer | Test | Expected |
|---|--------|-----------|-------|------|----------|
| 39 | Rollover with `periodsElapsed = 0` (skip time proof) | I5 | CONSENSUS | AVM-39 | script fails (require >= 1) |
| 40 | Rollover overflow: huge `periodsElapsed` wraps arithmetic | I5, A6 | CONSENSUS | AVM-40 | bounded; script fails |
| 41 | Payment output value above `payAmount` (drain via recipient) | I8, I9 | CONSENSUS | AVM-41 | exact-value check fails |
| 42 | Invalid `recipientIndex` (out of allowlist range) | I7 | CONSENSUS | AVM-42 | script fails |
| 43 | Max-sequence input to bypass CLTV | I5 | CONSENSUS | AVM-43 | CLTV rejects finalized input |
| 44 | Lock-time type confusion (timestamp vs DAA threshold) | I5 | CONSENSUS | AVM-44 | CLTV type check fails |
| 45 | Spend that zeroes the vault (bypass recovery discipline) | I14 | CONSENSUS | AVM-45 | `newState.protectedValue > 0` fails |
| 46 | Unpause forged by delegate in successor state | I13, I2 | CONSENSUS | AVM-46 | owner checkSig fails |

## Live testnet obligations (Phase 15)

The flagship direct-to-node demo re-runs at minimum threats 2, 3, 4, and a
forged-successor variant (17/18) as **real transactions signed by the real
delegate key submitted directly via RPC**, proving node-level rejection.

## Status

Updated 2026-08-11 after the Phase 4–5 VM runs (`tests/vm`, 44 tests, all
passing on the real TxScriptEngine with covenants enabled and real Schnorr
signatures):

- **VM-VERIFIED (Actual == Expected: rejected by the VM):** threats 1–23,
  35–36, 38–46 — every consensus-layer row. Test names in
  `tests/vm/tests/adversarial.rs` carry the AVM ids.
- **VM-VERIFIED (valid paths accepted):** the VVM suite in
  `tests/vm/tests/happy_path.rs` (valid payment, exact cap, exact remaining
  budget, sequential payments, single/multi-period rollover,
  pause/unpause, recovery incl. while paused).
- **DESIGNED (pending later phases):** threats 24–34, 37 (application
  layer: SDK/CR/TN tests), and the live direct-to-node reruns of 2/3/4/17.

One TEST BUG found and fixed during Phase 5: a truncated 64-byte signature
cannot be *encoded* through the covenant declaration API (the encoder
enforces the declared `sig` width), so AVM-36 instead corrupts bytes inside
a well-formed 65-byte signature. No contract change was needed.

Any divergence between Expected and Actual is a release blocker until
classified (CONTRACT BUG / TEST BUG / STALE ASSUMPTION / ...) and resolved.

---

# v0.3 THREAT MODEL EXTENSION (Phase 3 design; NOT implemented)

Status labels: **EXP-PROVEN** = rejected/accepted as expected by a real-VM
Phase 3 experiment (`tests/vm/tests/v3_experiment_*.rs`); **DESIGNED** =
to be covered by the Phase 4 negative-validation matrix (real VM + live
testnet). Each maps to an invariant in `docs/security-invariants.md` and
an expected result (all attacks: consensus REJECT).

## Scalable recipients (Merkle allowlist)

| id | threat | invariant | layer | expected | status |
|----|--------|-----------|-------|----------|--------|
| V3-R1 | forged membership proof | R1 | consensus | reject | EXP-PROVEN |
| V3-R2 | proof for wrong recipient | R1/R2 | consensus | reject | EXP-PROVEN |
| V3-R3 | proof from wrong/other root | R1 | consensus | reject | EXP-PROVEN |
| V3-R4 | alternate/injected leaf encoding | R2 | consensus | reject | EXP-PROVEN (leaf always recomputed; 36 vs 64-byte preimage separation) |
| V3-R5 | leaf/output substitution (pay a different output) | R2 | consensus | reject | EXP-PROVEN |
| V3-R6 | modified sibling | R1 | consensus | reject | EXP-PROVEN |
| V3-R7 | wrong path direction | R1 | consensus | reject | EXP-PROVEN |
| V3-R8 | root substitution in successor state | R3 | consensus | reject | DESIGNED (owner-gov path) |
| V3-R9 | stale root: old proof after root update | R3 | consensus+app | reject | DESIGNED (singleton state binding) |
| V3-R10 | truncated proof | R1 | consensus | reject | EXP-PROVEN |
| V3-R11 | extended proof | R1 | consensus | reject | EXP-PROVEN |
| V3-R12 | excessive proof depth (> max) | R1 | consensus | reject | EXP-PROVEN (length ≤ 512) |
| V3-R13 | ragged sibling width (not ×32) | R1 | consensus | reject | EXP-PROVEN |
| V3-R14 | cross-vault / cross-policy proof replay | R1 | consensus | reject unless genuinely a member of the live root | EXP-PROVEN (root is the domain) + DESIGNED |

## Approvals / multisig

| id | threat | invariant | layer | expected | status |
|----|--------|-----------|-------|----------|--------|
| V3-A1 | insufficient signatures (< M) | A1 | consensus | reject | EXP-PROVEN |
| V3-A2 | duplicate signer counted twice | A2 | consensus | reject | EXP-PROVEN (structural fixed slots) |
| V3-A3 | same key in multiple slots | A2 | consensus | reject | EXP-PROVEN |
| V3-A4 | unknown / non-approver signer | A1 | consensus | reject | EXP-PROVEN |
| V3-A5 | removed approver signs | A1/A6 | consensus | reject | DESIGNED |
| V3-A6 | stale signature after state change | A3/A4 | consensus | reject | EXP-PROVEN (sighash binding) |
| V3-A7 | signature for different amount/recipient | A3 | consensus | reject | EXP-PROVEN |
| V3-A8 | signature for different vault/action/successor | A3 | consensus | reject | EXP-PROVEN (sighash) + DESIGNED |
| V3-A9 | threshold downgrade (lower M in successor) | A5 | consensus | reject | DESIGNED |
| V3-A10 | approver-set substitution in successor | A5/A6 | consensus | reject | DESIGNED |
| V3-A11 | malicious delegate + minority approvers | A1 | consensus | reject (< M) | EXP-PROVEN |
| V3-A12 | approval bypass above threshold | A1 | consensus | reject | EXP-PROVEN |
| V3-A13 | approval package replaced pre-submission | A3 | app+consensus | stale/reject | DESIGNED |
| V3-A14 | partial approvals replayed into another tx | A3 | consensus | reject | EXP-PROVEN (sighash) |
| V3-A15 | malicious owner changes governance then spends | — | — | ACCEPTED BY DESIGN (owner is break-glass; documented, not protected) | DESIGNED |
| V3-A16 | lost approver keys trap funds | — | — | ownerRecover always available (single owner key) | DESIGNED |

## Migration (v0.2 → v0.3)

| id | threat | invariant | layer | expected | status |
|----|--------|-----------|-------|----------|--------|
| V3-M1 | v0.2 authorizes a v0.3 template successor in-lineage | MG1 | consensus | reject | EXP-PROVEN |
| V3-M2 | forged migration successor | MG1 | consensus | reject | EXP-PROVEN (singleton template bind) |
| V3-M3 | lineage confusion (fake continuity) | MG2 | app | UI shows close+recreate | DESIGNED |
| V3-M4 | old v0.2 delegate spends after upgrade | MG3 | consensus | reject (outpoint consumed) | DESIGNED |
| V3-M5 | stale v0.2 signed tx after upgrade | MG3 | consensus | reject | DESIGNED |
| V3-M6 | accounting/principal reset smuggled during "migration" | MG2 | app | new genesis is a NEW vault by design | DESIGNED |

## v0.3 Phase 3.5 review additions (VM-PROVEN findings)

| id | threat | invariant | layer | expected | status |
|----|--------|-----------|-------|----------|--------|
| V3-A17 | approval signed SIG_HASH_NONE authorizes an unseen payment (redirect within allowlist / change amount) | A7 | consensus | reject via sighash-ALL gate | EXP-PROVEN gap + EXP-PROVEN fix (V3SighashGateProbe) |
| V3-A18 | approval signed SIG_HASH_ANYONE_CAN_PAY not bound to the input | A7 | consensus | reject via sighash-ALL gate | DESIGNED (same gate; ALL required) |
| V3-A19 | duplicate x-only key in the approver SET lets one signer satisfy two slots | A2 | consensus+app | reject at ownerSetApprovers (set-time) | EXP-PROVEN gap; fix = set-time validation |
| V3-A20 | empty-slot sentinel counted as an approver | A2 | consensus | never counts (placeholder fails verification) | EXP-PROVEN |

## Phase 4H SDK construction / approval-collection additions

Statuses: SDK-PROVEN = `sdk/test/*-v3.test.js`; VM-PROVEN =
`tests/vm/tests/v3_sdk_integration.rs` (SDK-built bytes executed on the
production covenant). Consensus remains the security boundary; the SDK
layer is defense in depth.

| id | threat | invariant | layer | expected | status |
|----|--------|-----------|-------|----------|--------|
| V3-S1 | approval package field mutated after approvals collected (recipient/amount/outpoint/state/nonce/fee/budget/proof/network/version/frozen tx) | AP1 | app+consensus | package void; collected sigs consensus-dead | SDK-PROVEN (full mutation matrix) + VM-PROVEN (output mutation) |
| V3-S2 | approval replayed into a different transaction intent | A3/AP1 | consensus | reject (SIG_HASH_ALL) | VM-PROVEN (replay onto other-recipient tx rejected on the production covenant) |
| V3-S3 | one collected approval duplicated into a second slot | A2 | consensus | reject (slot key mismatch → count short) | VM-PROVEN |
| V3-S4 | approval slots swapped in the final blob | A2 | consensus | reject | VM-PROVEN |
| V3-S5 | non-ALL sighash byte on a real approval (NONE/SINGLE/ACP variants + arbitrary trailer) | A7/AP2 | app+consensus | reject at SDK gate AND covenant gate | SDK-PROVEN (real WASM non-ALL sigs) + VM-PROVEN (trailer flip) |
| V3-S6 | 64-byte / 66-byte / truncated / placeholder-as-approval | A7/AP2 | app+consensus | reject | SDK-PROVEN |
| V3-S7 | unknown signer / signer claiming another's slot / sentinel as signer | AP2 | app | reject before acceptance | SDK-PROVEN |
| V3-S8 | caller-forced illegal successor via builder inputs | AP4 | app+consensus | builders take intent only; illegal successors also consensus-rejected | SDK-PROVEN + VM-PROVEN (enc3 matrix) |
| V3-S9 | committed compute budget below the proven shape requirement (unusable valid spend) | AP5 | app | central tiers; caller cannot lower; sufficiency proven per shape per run | SDK-PROVEN + VM-PROVEN |
| V3-S10 | compute-budget malleation after freeze (v1 sighash/txId do NOT commit it — source-checked) | AP1 | app | package commitment closes it; consensus impact limited to non-viability (fee shortfall / execution abort), never value flows | SDK-PROVEN (commitment) + SOURCE-CHECKED |
| V3-S11 | recovery-mode (malformed-state) parse used for an ordinary transition | AP6 | app | quarantined to ownerRecover; ordinary builders reject | SDK-PROVEN |
| V3-S12 | malformed genesis blocks owner recovery operationally | AP6/G2 | app+consensus | SDK builds recovery from the exact malformed state; executes on the covenant | VM-PROVEN |
| V3-S13 | recipient list/proof not matching the live root at build time | R1/AP4 | app+consensus | fail closed before construction; covenant would reject regardless | SDK-PROVEN |
| V3-S14 | duplicate-padding path-bit ambiguity abused | R1/R2 | consensus | benign: both encodings prove the SAME recipient under the SAME root; output binding unchanged | SOURCE-CHECKED + documented |
| V3-S15 | v0.3 intent routed through v0.2 implementation (version confusion) | A1(app) | app+consensus | fail closed; no fallback; wrong dispatch also consensus-rejected | SDK-PROVEN + VM-PROVEN (enc3) |

## v0.4 design-gate additions (fee reserve + multi-agent)

DESIGN ONLY. Status: VM-EXP-PROVEN = rejected/accepted as stated on a real
VM probe (`tests/vm/tests/v4_experiment_{fee_reserve,multi_agent}.rs`);
SOURCE-PROVEN; DESIGNED = to be tested at Checkpoint C. Consensus remains
the security boundary.

Fee reserve:

| id | threat | invariant | expected | status |
|----|--------|-----------|----------|--------|
| V4-FR1 | delegate burns reserve as fee | v4-FR3 | allowed up to maxFeePerTx; bounded | VM-EXP-PROVEN |
| V4-FR2 | delegate burns PRINCIPAL as fee | v4-FR1 | reject (exact successor value) | VM-EXP-PROVEN |
| V4-FR3 | reserve redirected to a recipient/extra output | v4-FR2 | reject (reserveConsumed <= fee) | VM-EXP-PROVEN |
| V4-FR4 | fee inflated beyond the per-tx cap | v4-FR3 | reject (maxFeePerTx) | VM-EXP-PROVEN |
| V4-FR5 | external input added to mask reserve theft | v4-FR2 | reject (isolation holds) | VM-EXP-PROVEN |
| V4-FR6 | extra/reordered output manipulation | VP2/VP3 | reject (value-pinned outputs; SIG_HASH_ALL) | VM-EXP-PROVEN + SOURCE |
| V4-FR7 | change-output manipulation | v4-FR2 | reject | VM-EXP-PROVEN |
| V4-FR8 | reserve/accounting reset during a spend | FR8/PA3 | reject (require-preserved) | DESIGNED |
| V4-FR9 | reserve exhaustion (DoS) | v4-FR3 | agent stalls; principal + recovery safe | VM-EXP-PROVEN |
| V4-FR10 | malformed reserve state | v4-FR4 | reject/unconstructible; recovery still works | VM-EXP-PROVEN |
| V4-FR11 | reserve recovery failure | v4-FR5 | reject not possible; recover pays principal+reserve | VM-EXP-PROVEN |

Multi-delegate / agents:

| id | threat | invariant | expected | status |
|----|--------|-----------|----------|--------|
| V4-MD1 | delegate substitution | v4-MD1 | reject (leaf binds key) | VM-EXP-PROVEN |
| V4-MD2 | delegate-policy substitution (borrow another's limits) | v4-MD2 | reject (leaf not in tree) | VM-EXP-PROVEN |
| V4-MD3 | stale delegate proof / stale root | v4-MD4 | reject (live-root mismatch) | VM-EXP-PROVEN |
| V4-MD4 | stale nonce | v4-MD4 | reject (singleton state binding) | VM-EXP-PROVEN |
| V4-MD5 | cross-agent budget theft | v4-MD2 | reject | VM-EXP-PROVEN |
| V4-MD6 | cross-agent recipient-policy theft | v4-MD2 | reject | VM-EXP-PROVEN |
| V4-MD7 | cross-agent approval-policy theft (threshold) | v4-MD2 | reject | VM-EXP-PROVEN |
| V4-MD8 | cross-agent fee-allowance theft | v4-MD2 | reject (leaf field, if adopted) | DESIGNED |
| V4-MD9 | concurrent agent race | v4-MD6 | one confirms; other is a double-spend reject | SOURCE-PROVEN |
| V4-MD10 | delegate removal / re-add replay | v4-MD4 | reject (nonce+root change) | DESIGNED |
| V4-MD11 | rotate replay | v4-MD4 | reject | DESIGNED |
| V4-MD12 | duplicate agent identity in the tree | v4-MD1 | harmless (membership only checks presence); SDK de-dups | DESIGNED |
| V4-MD13 | malformed agent-policy leaf | v4-MD1 | reject (reconstructed leaf not in tree) | VM-EXP-PROVEN |
| V4-MD14 | forged successor root (dodge accounting) | v4-MD3 | reject (recomputed-root equality) | VM-EXP-PROVEN |
| V4-MD15 | key A + leaf B | v4-MD1 | reject (checkSig against leaf key) | VM-EXP-PROVEN |

Approvals / recovery / migration:

| id | threat | invariant | expected | status |
|----|--------|-----------|----------|--------|
| V4-AP1 | approval reused between agents | v4-AP2 | reject (sighash binds this agent's tx) | VM-EXP-PROVEN |
| V4-AP2 | approval reused between policy roots / after update | v4-AP2 | reject (state change → sighash change) | VM-EXP-PROVEN + DESIGNED |
| V4-AP3 | non-ALL approval sighash | v4-AP2 | reject (A7 gate) | VM-EXP-PROVEN |
| V4-AP4 | approver-set ambiguity across agents | v4-AP1 | none (one global set) | DESIGNED |
| V4-REC1 | malformed state traps funds | REC1/REC2 | reject not possible; owner recovers | VM-EXP-PROVEN |
| V4-REC2 | empty reserve / missing approvers / missing agents trap funds | REC2 | recovery ignores them | VM-EXP-PROVEN |
| V4-MG1 | fake v0.3→v0.4 continuity | v4-MG1 | UI shows close+recreate; two chain events | DESIGNED |
| V4-MG2 | stale v0.3 package against v0.4 | MG3 | inert (outpoint consumed; different covenant) | DESIGNED |
| V4-MG3 | wrong template/version dispatch | TX2 | fail closed; no fallback | DESIGNED |

## v0.4 Checkpoint-B freeze — additional hostile rows (VM-EXP-PROVEN)

Driven through `contracts/experiments/V4CombinedProbe.sil` (frozen design
as one system) + `v4_experiment_migration.rs`. All REJECTED as required.

| id | threat | invariant | status |
|----|--------|-----------|--------|
| V4B-1 | agent spend alters an UNRELATED agent's leaf (tampered successor root) | v4-MD-UPD | VM-EXP-PROVEN |
| V4B-2 | forged sibling co-path in the policy proof | v4-MD-UPD | VM-EXP-PROVEN |
| V4B-3 | A borrows B's per-agent fee cap (agentMaxFeePerTx) | v4-FR-CAP/MD2 | VM-EXP-PROVEN |
| V4B-4 | reserve consumed beyond the per-agent fee cap | v4-FR-CAP | VM-EXP-PROVEN |
| V4B-5 | principal→reserve swap (payment routed into reserve) | v4-VP-CONS | VM-EXP-PROVEN |
| V4B-6 | principal forged down / reserve forged up in the successor | v4-VP-CONS | VM-EXP-PROVEN |
| V4B-7 | reserve redirected to a change output (with/without external input) | v4-VP-CONS | VM-EXP-PROVEN |
| V4B-8 | external output exceeds external input | v4-VP-CONS | VM-EXP-PROVEN |
| V4B-9 | agent spend while globally paused | pause | VM-EXP-PROVEN |
| V4B-10 | owner op reset of value/nonce/approvers (field-preservation matrix) | GOV2/PA3 | VM-EXP-PROVEN |
| V4B-11 | ownerTopUp touches reserve / ownerTopUpReserve touches principal | v4-FR/VP | VM-EXP-PROVEN |
| V4B-12 | policy-tree depth beyond the frozen max | RP/MD | VM-EXP-PROVEN (probe-scaled) |
| V4B-13 | v0.3 covenant produces a v0.4-template successor (in-lineage migration) | v4-MG1 | VM-EXP-PROVEN |
| V4B-14 | recover from paused + malformed agentRoot + empty reserve | REC1/REC2 | VM-EXP-PROVEN |

## v0.4 Checkpoint-C — production-byte re-proof (2026-08-18)

Every V4-* / V4B-* row above is now RE-PROVEN on the PRODUCTION covenant
`PolicyVault.v0.4.sil` via the real `pv_call_encoder` binary + real VM
(`v4_production.rs`, `v4_encoder_integration.rs`), not only the probes. New
production-byte mutation rows all REJECTED: wrong recipient, forged
successor protectedValue/feeReserve, borrowed cap, borrowed fee cap,
SIG_HASH_NONE approval, insufficient approvals, reserve redirect, over
per-agent fee cap, forged successor root, wrong version dispatch
(policyvault-0.3 arm on a v0.4 call), truncated policy proof, terminal-shape
mismatch, agent/recipient depth overflow. Status: PRODUCTION-BYTE-PROVEN.

**Checkpoint D (2026-08-18) — MAX-REVIEWED.** Direct production-covenant VM
evidence added for the time/arithmetic rows: AVM-43 (max-sequence input to
bypass CLTV) and AVM-44 (lock-time boundary) are now VM-proven —
`require(tx.time >= newStart)` compiles to OpCheckLockTimeVerify, which rejects
a finalized input (sequence = u64::MAX) and requires lock_time ≥ newStart
(`d_rollover_cltv_finalization_and_boundary`); AVM-40 (rollover overflow) is
source-proven fail-closed (checked_add/sub/mul → NumberTooBig). num8 is VM-proven
injective at 2^32/2^53/large; the singleton successor is unique
(OpAuthOutputCount == 1). An 8-way deliberate-sabotage matrix confirmed the
suite catches each broken funds/authority rule (0 blind spots). Production bytes
UNCHANGED (SHA256 8f87dea…); MAX-REVIEWED is internal, not an external audit.

## v0.4 application-integration threats (Checkpoint G, 2026-08-19)

The v0.4 server/API integration adds an application trust boundary above the
consensus boundary. The browser is untrusted; every browser-only protection has
an independent backend enforcement test (`sdk/test/wallet-v4-hostile.test.js`,
`sdk/test/api-v4.test.js`). Enforced application invariants (each proven by a
sabotage-sensitive test): signer authorization at BUILD and FINALIZE (owner vs
acting agent; agent must be an active registry member); durable agent-registry
root-equality with the covenant state (a metadata tree that cannot reproduce the
on-chain root fails closed); frozen-request immutability (a wallet may change
only signature scripts); stale-predecessor rejection; one transition per
covenant outpoint (two-tab / duplicate-FINALIZE protection); testnet-10 network
gate; server-derived successor fields (caller injection ignored); approvals
bound to the exact frozen transaction (no cross-tx/recipient/nonce replay);
per-agent fee cap and reserveConsumed≤fee enforced by the SDK (browser fee
numbers not trusted). The integration is OFFLINE (production-covenant VM
preflight, no broadcast); live-node submission/reconciliation threats are
Checkpoint H.
