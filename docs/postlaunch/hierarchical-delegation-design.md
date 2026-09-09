# PolicyVault HIERARCHICAL DELEGATION — design record (lane `hd-design`)

**Claim label: DESIGNED (this record). No covenant, probe, SDK or UI code exists for hierarchical delegation yet.** Per the owner directive (2026-09-03 §12) this lane begins only as DESIGN + PROBE PLAN while the v0.7 organizational root finishes its implementation gates; real-engine probes start after the v0.7 production VM suites are green, and no production covenant successor is built until the model is mechanically convincing. Nothing here touches any v0.5 / v0.6 / v0.7 file.

Core invariant (owner, verbatim): **AUTHORITY MAY NEVER INCREASE DESCENDING.** A child or grandchild must never gain a higher per-spend cap, a higher periodic budget, a broader destination set, a broader asset set, a longer expiry, a broader action set, stronger owner/root powers, swap permissions absent in the parent, or an ability to escape revocation.

Authority statement unchanged: AI MAY REQUEST · POLICYVAULT DETERMINISTICALLY DECIDES · THE COVENANT ENFORCES · SIGNERS RETAIN CUSTODY.

---

## 0. Consensus facts the design rests on (verified in source)

| fact | source | consequence |
|---|---|---|
| Kaspa `lockTime` is a LOWER bound: `OpCheckLockTimeVerify` requires `tx.lockTime >= arg`; consensus `check_tx_is_finalized` requires the lock time to have been REACHED. Nothing makes a transaction invalid once a DAA score is exceeded. | `~/rusty-kaspa/crypto/txscript/src/opcodes/mod.rs:1014`; `consensus/src/processes/transaction_validator/tx_validation_in_header_context.rs` | a delegation EXPIRY (upper bound) is NOT consensus-enforceable as a time check. Expiry must be delivered by REVOCATION (state change) or by the periodic-budget clock. "Expiry monotonicity" is therefore enforced as a consistency rule on the committed leaves and as a shared-core/manifest refusal, and stated honestly as such. |
| Relative input-age locks ARE enforceable (v0.7 §0) | same as v0.7 | not needed here; noted so nobody reaches for it as a fake expiry |
| Merkle membership under an owner-committed root is the proven policy mechanism (v0.4 agent leaves depth ≤ 12; v0.3 recipient leaves depth ≤ 16; two folds already coexist in one spend) | `contracts/PolicyVault.v0.4.1.sil`, `v0.5.sil`, `v0.6.sil`; VM suites | a delegate's leaf can itself commit a `childRoot`; a child spend proves a CHAIN of memberships and updates a CHAIN of leaves in one transaction |
| One agent transaction currently carries exactly one signature check (the leaf key) and 1–3 static sig-ops; static sig-op standardness budget 15 | v0.7 §0 | a child spend still needs exactly ONE signature (the child's); ancestors are proven by membership, never by signature |
| Script arithmetic is checked (no wrap); stack limit 244 items | v0.6 adversarial review; v0.7 probes | nested proofs must be measured for stack headroom at maximum depth |

---

## 1. Model

### 1.1 Tree

```
owner / org root (v0.7)
 └─ agentRoot ─ agent leaf A            (level 1; today's delegate)
                 └─ childRoot(A) ─ leaf B   (level 2; sub-delegate created by A)
                                   └─ childRoot(B) ─ leaf C   (level 3; created by B)
```

- Bounded depth: `MAX_LEVEL = 3` (owner-committed agents = level 1; two delegated levels below). Deeper is a future version if measurements allow; the covenant refuses any deeper claim by construction (no entrypoint accepts a longer chain).
- Every leaf at every level has the SAME shape as today's agent leaf (key, tokenMaxPerSpend, tokenPeriodBudget, periodLengthDaa, periodStartDaa, periodSpent, agentMaxFeePerTx, agentMaxCarryKas [, kas caps for composability profiles], recipientRoot) PLUS `childRoot` (32 B; zero = no children allowed) and `level` (int). Leaf domain tag distinct from every existing tag (new 4-byte prefix) so an HD leaf can never be presented as a v0.4/v0.5/v0.6 leaf or vice versa.
- Asset set / action set are inherited by the PROFILE (a v0.5-payment child can only do payment spends; a v0.6-composability child gets swap authority ONLY if its parent leaf carries the swap caps and the child's are ≤ — per-spend intersection, §1.3). No child ever reaches an owner/root entrypoint: those require the owner signature (v0.5/v0.6) or the org-root input (v0.7); a leaf key is never an owner.

### 1.2 Who may change what (mutation classes)

| operation | signer | class | rule |
|---|---|---|---|
| owner/root sets `agentRoot` (today's op) | owner / org root quorum | AUTHORITY-EXPANDING (full authority) | unchanged |
| parent P sets `childRoot(P)` — add / remove / re-policy a child | P's key (one signature) | AUTHORITY-REDUCING for P (P can only grant a subset of itself; removal is pure reduction), never expanding for the tree | the covenant checks: P's leaf is a member of the current agentRoot (or of ITS parent's childRoot, recursively); P's new leaf differs ONLY in `childRoot`; the successor agentRoot is the refold. The covenant does NOT verify the contents of the new child set at delegation time (the leaves are hashes) — subset-ness is enforced at EVERY SPEND by intersection (§1.3), so a malformed child set can never authorize more than P could |
| child spend | the child's key | ordinary spend, bounded by the whole ancestor chain | §1.3 |
| revocation | any ancestor (or the owner/root) | AUTHORITY-REDUCING | removing a node removes its entire subtree by construction (its `childRoot` is unreachable) |
| parent key rotation | owner/root (level 1) or the grandparent (level ≥ 2) | neutral for descendants if `childRoot` is carried into the new leaf; the rotating authority may also zero it | explicit |

### 1.3 Per-spend intersection (the enforcement point)

A spend by leaf L at level k presents the FULL ancestor chain `[A1, …, A(k−1), L]` with a membership proof at each level (A1 under agentRoot; A2 under childRoot(A1); …; L under childRoot(A(k−1))) and ONE signature by L's key. The covenant requires, for the spend amount `s` and recipient `r`:

1. `s ≤ cap(Ai)` for EVERY i (monotone cap intersection — no need to trust that a child cap was set ≤ the parent's);
2. period accounting on EVERY ancestor AND the leaf: each level's `periodSpent' = periodSpent + s` within its own budget after its own rollover (each level has its own clock; a child cannot outrun the parent's budget because the parent's counter also advances);
3. `r` is a member of `recipientRoot(Ai)` for EVERY i (allowlist intersection by k membership proofs);
4. network fee from the fee reserve `≤ min(agentMaxFeePerTx(Ai))`; carry `≤ min(agentMaxCarryKas(Ai))`; for composability profiles the KAS caps likewise, and a swap is allowed only if EVERY ancestor's `directionMask`-equivalent permits it;
5. `level(L) = k`, `level(Ai) = i`, `k ≤ MAX_LEVEL`;
6. the successor `agentRoot` is the refold of the whole chain with every level's advanced counters (nested folds: new leaf L → new childRoot(A(k−1)) → new leaf A(k−1) → … → new agentRoot).

Because every bound is checked against every ancestor at spend time, a hostile or buggy parent who commits a child leaf with LARGER caps gains nothing: the child is still bounded by the parent (and grandparent) at every spend. This is what makes the "lighter" delegation rule (a single parent signature, no owner ceremony) safe: **delegation can never create authority; it can only name a key that is then bounded by the intersection.**

### 1.4 Expiry (honest)

- Each leaf may carry `expiryDaa`; the covenant enforces `expiryDaa(child) ≤ expiryDaa(parent)` as a consistency rule at spend time AND the shared core refuses to build or sign after expiry — but consensus cannot refuse a transaction merely because a DAA score has passed (§0). The consensus-enforced substitutes are: revocation (§1.2) and the periodic budget (a stale delegate's authority decays to its per-period budget). The manifest and UI must state: "expiry is enforced by PolicyVault's core and by revocation, not by consensus".

### 1.5 Stale-delegation replay resistance

A spend proves membership under the CURRENT `agentRoot` (and current `childRoot`s, which are inside the current parent leaves, which are under the current root). Any earlier leaf (revoked child, re-policied parent, stale counters) fails membership. Outpoint binding of the vault UTXO adds the usual single-use guarantee. No signature is ever portable: SIGHASH_ALL over the whole transaction.

### 1.6 Recovery, freeze, pause, root interaction

Unchanged: owner/root recover pays out regardless of the tree; `paused` (vault) and `frozen` (org root) refuse every spend at every level; a v0.7 organization revokes a whole subtree by one root-authorized `setAgentRoot`.

---

## 2. Alternative considered: signature-chain certificates (rejected for v1)

A parent could sign an off-chain "child certificate" (child key + caps) that the covenant verifies with `checkSigFromStack` at spend time instead of committing the child in state. It avoids a parent-signed on-chain delegation transaction, but (a) the child then has no on-chain `periodSpent` of its own (only the parent's budget applies), (b) revocation needs an on-chain state change anyway (a revocation list or a parent counter), (c) it adds one sig-op per level, and (d) the certificate is exactly the "stale delegation" object the replay class warns about. In-state child leaves (§1) give per-child budgets, structural revocation and no extra sig-ops. A hybrid ("stateless children with caps only") may return as a later, measured option.

---

## 3. Adversarial classes → refusal mechanism

| class | refused by |
|---|---|
| child cap/budget/allowlist/fee/carry/swap broader than the parent | per-spend intersection against EVERY ancestor (§1.3) — never trusted at delegation time |
| escaping revocation (spend with a removed child/parent) | membership under the current roots fails |
| cycles / self-parenting / a leaf claiming a shorter level | `level` pinned per level; chain length pinned to k; a leaf's `childRoot` never points "up" — a claimed chain is a straight path, verified level by level |
| parent budget bypass (child spends without advancing the parent) | the parent's counters are part of the refold; an unadvanced parent leaf changes the successor root → mismatch |
| double-counting across siblings | each sibling advances the SAME parent counter; the parent's budget bounds the subtree total |
| stale parent leaf (old counters) | membership fails |
| grandparent removed but parent chain reused | membership of the parent under the (new) grandparent childRoot fails |
| a level-2 key presented as level-1 (or as an owner) | distinct leaf tag + `level` field + no owner entrypoint accepts a leaf key |
| delegation op forging any field other than `childRoot` | the parent-signed op pins every other field equal |
| unbounded depth | no entrypoint accepts > MAX_LEVEL proofs; deeper leaves are unreachable |
| expiry inversion | consistency rule at spend + core refusal; documented non-consensus |
| sighash misuse / post-sign mutation | in-covenant 65-byte 0x01 gate (as v0.6/v0.7) |
| fee/value leakage | unchanged exact successor value + fee-reserve domain rules |

---

## 4. Measure before believing (probe plan; after v0.7 I1 is green)

Experimental namespace only (`contracts/experiments/HDProbe.sil`, `tests/vm/tests/hd_experiment.rs`):

1. Redeem growth of a v0.5-shaped controller with `childSpend` at levels 2 and 3 (nested folds + k recipient proofs) — target: measured, with stack headroom at level 3 / agent depth 12 / recipient depth 16 / child depth 8.
2. `delegateSetChildRoot` cost; delegate spend at level 1 must remain byte-identical in semantics to today's spend (only the leaf tag/format changes).
3. Every §3 row as a real-engine refusal; every honest path at every level accepted.
4. Compute/mass/fee per level; standardness.
5. Decide MAX_LEVEL (2 or 3) and child-tree depth from measurements, not preference.

Stop target for this wave: **HIERARCHICAL-DELEGATION-DESIGN-FREEZE-READY** (design + probe evidence), never a production covenant in this wave unless the model is mechanically convincing and time remains — and never at the expense of the organizational-root review.

---

## 5. Open questions (do not block probes)

- OQ-HD-1: should a parent be allowed to delegate WITHOUT a per-child period budget (stateless children bounded only by caps + the parent's budget) as a cheaper tier?
- OQ-HD-2: MAX_LEVEL 2 vs 3 (measurement).
- OQ-HD-3: whether the org root (v0.7) needs a rule that a FROZEN root also blocks delegation ops (proposal: yes — delegation ops are spends of the vault's owner-controlled state and should respect `paused`; the root is not involved).

---

## 6. Probe results

**Claim label: VM-VERIFIED (experimental probe).** Not IMPLEMENTED as a
production covenant, not TESTNET-VERIFIED. Every
number below was produced by the real Kaspa `TxScriptEngine`
(rusty-kaspa v2.0.1, covenants enabled) executing real Schnorr-signed
transactions with the real upstream KCC20 token contract on the other
inputs. Artefacts: `contracts/experiments/HDProbe.sil`,
`tests/vm/tests/hd_experiment.rs` (lane `hd-design`).

`contracts/PolicyVault.v0.5.sil` was read as the baseline and never
modified — sha256 `c693aeffb59286d21d44452bde0943d78840b66cf480b629624b7747b4197dd9`
verified before and after the probe wave. No v0.6 / v0.7 file was touched.

### 6.1 What was built

The probe controller is the frozen v0.5 token controller with the §1 model
added. Three source variants are compiled from the one probe source by
removing whole marked entrypoint regions, so MAX_LEVEL is a measured
variable rather than an assumption:

| variant | entrypoints | MAX_LEVEL |
|---|---|---|
| `L1` | `hdSpend`, `ownerControl`, `ownerRecover` | 1 (the v0.5 shape with the HD leaf format) |
| `L2` | + `childSpendL2`, `delegateSetChildRoot1` | 2 |
| `L3` | + `childSpendL3`, `delegateSetChildRoot2` | 3 |

HD leaf: NEW domain tag `0x50564801` over a **173-byte** preimage
(`0x50564801 || body(160) || num8(level) || 0x00`), disjoint from v0.5's
`0x50563501` / 125-byte token-agent leaf, from the v0.3 recipient leaf and
from every other PolicyVault leaf length.

### 6.2 Leaf carriage — a measured design change to §1.1

**MAX_STACK_SIZE (244 combined stack items) is the binding constraint on
MAX_LEVEL, and it is decided by how the leaf is CARRIED, not by the
policy.** Two layouts were built and measured on the real engine:

| leaf carriage | level-1 spend | level-2 spend | level-3 spend | verdict |
|---|---|---|---|---|
| 11 separate leaf arguments per ancestor (the literal §1.1 reading) | 140 | 206 | **272** | level 3 **EXCEEDS 244** by 28 |
| ONE 160-byte canonical body per ancestor (adopted) | 119 | 162 | **208** | level 3 fits, 36 items of headroom |

Measured slope for the field-argument layout: removing one leaf field saved
9 items at level 3 (~3 combined stack items per leaf field per ancestor).
`level` was additionally removed from the caller's arguments entirely — each
entrypoint substitutes the level CONSTANT of the position it is checking, so
a leaf committed at level k still fails membership anywhere else and the
security property is unchanged. Body layout (little-endian `num8` ints):
`pk[0,32) maxPerSpend[32,40) periodBudget[40,48) periodLengthDaa[48,56)
periodStartDaa[56,64) periodSpent[64,72) maxFeePerTx[72,80)
maxCarryKas[80,88) expiryDaa[88,96) recipientRoot[96,128) childRoot[128,160)`.

A pleasant consequence: `delegateSetChildRoot` no longer has to re-assert
"every other field equal" field by field — the successor leaf is literally
`body[0,128) || newChildRoot`, so no other field CAN move.

### 6.3 Redeem geometry (identical template pins and state)

| covenant | redeem B | vs frozen v0.5 | state region B |
|---|---:|---:|---:|
| FROZEN `PolicyVault.v0.5.sil` | 9,273 | — | 93 |
| HDProbe `L1` (MAX_LEVEL 1) | 9,353 | **+80** | 93 |
| HDProbe `L2` (MAX_LEVEL 2) | 22,671 | +13,398 | 93 |
| HDProbe `L3` (MAX_LEVEL 3) | 42,472 | +33,199 | 93 |

The level-1 spend costs **+80 B of redeem** over frozen v0.5 (the HD leaf
format plus the explicit in-covenant SIGHASH gate). MAX_LEVEL 2 costs
+13,318 B over `L1`; MAX_LEVEL 3 costs a further +19,801 B. The state
region is unchanged at 93 B in every variant — the tree lives entirely
inside `agentRoot`.

### 6.4 Per-operation cost (real engine, covering compute budgets)

Shallow proofs (agent depth 1, child depth 1, recipient depth 0). "units"
is the harness price (sig-ops free), "priced units" prices sig-ops as a live
node does (Gram(1000) per checkSig); the committed compute budget is the
smallest covering budget, re-verified to not change the consumed units.
Masses use `MassCalculator::new(1, 10, STORAGE_MASS_PARAMETER)`; "fee mass"
is `max(compute, normalized_transient)` against the post-Toccata block
reference of 500,000.

| operation | sigscript B | units | priced units | budget | tx B | compute mass | transient mass | fee mass | static sig-ops |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `L1` level-1 spend | 9,805 | 103,337 | 203,337 | 20 | 12,103 | 16,673 | 48,412 | 24,206 | 3 |
| `L2` level-1 spend | 23,123 | 183,245 | 283,245 | 28 | 25,421 | 30,791 | 101,684 | 50,842 | 5 |
| `L2` level-2 spend | 23,322 | 191,220 | 291,220 | 29 | 25,620 | 31,090 | 102,480 | 51,240 | 5 |
| `L2` `delegateSetChildRoot1` | 23,043 | 142,030 | 242,030 | 24 | 23,450 | 27,580 | 93,800 | 46,900 | 5 |
| `L3` level-1 spend | 42,924 | 302,054 | 402,054 | 40 | 45,222 | 51,792 | 180,888 | 90,444 | 7 |
| `L3` level-2 spend | 43,123 | 310,029 | 410,029 | 41 | 45,421 | 52,091 | 181,684 | 90,842 | 7 |
| `L3` level-3 spend | 43,290 | 317,454 | 417,454 | 41 | 45,588 | 52,258 | 182,352 | 91,176 | 7 |
| `L3` `delegateSetChildRoot1` | 42,844 | 260,839 | 360,839 | 36 | 43,251 | 48,581 | 173,004 | 86,502 | 7 |
| `L3` `delegateSetChildRoot2` | 43,040 | 265,841 | 365,841 | 36 | 43,447 | 48,777 | 173,788 | 86,894 | 7 |
| `L3` `ownerRecover` | 42,586 | 109,300 | 209,300 | 20 | 44,720 | 48,910 | 178,880 | 89,440 | 7 |

Maximum-depth shapes (agent depth 12, child depth 8 at every level,
recipient depth 16 at every level):

| operation | sigscript B | units | priced units | budget | tx B | compute mass | transient mass | fee mass | static sig-ops |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `L1` level-1 spend (deep) | 10,673 | 154,470 | 254,470 | 25 | 12,971 | 18,041 | 51,884 | 25,942 | 3 |
| `L3` level-2 spend (deep) | 44,731 | 398,551 | 498,551 | 49 | 47,029 | 54,499 | 188,116 | 94,058 | 7 |
| `L3` level-3 spend (deep) | 45,670 | 444,427 | 544,427 | 54 | 47,968 | 55,938 | 191,872 | 95,936 | 7 |
| `L3` `delegateSetChildRoot2` (deep) | 43,620 | 307,993 | 407,993 | 40 | 44,027 | 49,757 | 176,108 | 88,054 | 7 |

Reading: the DOMINANT cost of a delegated spend is the redeem push itself
(the whole controller script is revealed in the signature script), not the
proofs — going from the shallowest to the maximum-depth level-3 shape adds
only 2,380 sigscript bytes and 4,760 fee mass. A maximum-depth level-3
spend is 95,936 normalized mass against the 500,000 post-Toccata block
compute reference (~19% of a block), and its 47,968 transaction bytes are
far inside the 1,000,000-byte post-Toccata script/element limits.

**Standardness.** Static sig-ops stay well inside
`MAX_STANDARD_P2SH_SIG_OPS = 15` in every variant: **3** at MAX_LEVEL 1
(exactly the frozen v0.5 count), **5** at MAX_LEVEL 2, **7** at MAX_LEVEL 3
— one per entrypoint that carries a `checkSig`. This DEVIATES from the §4
expectation of "3-4": the probe deliberately keeps `childSpendL2`,
`childSpendL3`, `delegateSetChildRoot1` and `delegateSetChildRoot2` as
separate entrypoints so each pins its own chain length and level constants
(fail-closed by construction, and independently strippable for measurement).
Merging the two delegation entrypoints behind a selector would cost one
sig-op less; it was not done because it would put a runtime selector where a
compile-time constant is currently doing the pinning.

### 6.5 MAX_STACK_SIZE accounting — this is what decides MAX_LEVEL

Method: front-pad the covenant's signature script with N one-byte data
pushes and binary-search the smallest N whose failure is
`StackSizeExceeded`; peak combined stack = 245 - N (the v0.7 phase-2
method). Measured peaks are IDENTICAL at shallow and maximum proof depth
(208 both for the level-3 spend), i.e. proof depth costs bytes, not stack
items.

| shape | peak combined stack | headroom to 244 |
|---|---:|---:|
| level-1 spend (`hdSpend`) | 119 | 125 |
| level-2 spend (`childSpendL2`) | 162 | 82 |
| **level-3 spend (`childSpendL3`)** | **208** | **36** |
| `delegateSetChildRoot1` | 51 | 193 |
| `delegateSetChildRoot2` | 75 | 169 |

Decomposition, measured by executing the same chains against a
MEASUREMENT-ONLY source with the v0.5 token dual-binding block removed
(never treated as an acceptance):

| component | stack items |
|---|---:|
| chain logic alone, level-1 / level-2 / level-3 | 73 / 117 / 163 |
| v0.5 token dual-binding block (constant) | 45 |
| marginal cost of one delegation level | 43 (L1→L2), 46 (L2→L3) |
| **extrapolated level-4 spend** | **254 — OVER 244** |

### 6.6 Honest paths accepted (8 tests, real engine)

1. level-1 spend under all three variants (the level-1 path is unchanged by
   the presence of deeper entrypoints);
2. **level-2 spend at the intersection boundary** — amount == the minimum
   cap over the chain, budget EXACTLY exhausted at the tightest level, the
   recipient a member of every level's allowlist; one sompi more of budget
   at the tightest level is refused;
3. **level-3 spend at the intersection boundary** — same, three levels; one
   sompi more of budget at the tightest level is refused;
4. **rollover at one level only** — the three levels carry different period
   lengths and starts (1000/700/500 DAA from 5000/5200/5400); the child's
   own period rolls over while both ancestors simply accumulate. Premature
   rollover at the child, and rollover claimed at the parent before its own
   boundary, are both refused;
5. `delegateSetChildRoot1` and `delegateSetChildRoot2` — each asserted to
   refold to EXACTLY the agentRoot of the same tree with the new child set
   attached, not merely to "some" successor root;
6. **revocation** — the parent zeroes its `childRoot`; the successor root
   is asserted equal to the agentRoot of the childless tree, and the child's
   spend against the revoked state is then REFUSED;
7. **shared parent budget across siblings** — with 200 of the parent's 300
   already spent by child B, sibling B2 may spend exactly the remaining 100
   and no more;
8. owner `pause` and `ownerRecover` still accept unchanged.

### 6.7 Hostile matrix — 66 rows, 0 accepted

42 spend rows + 24 delegation rows, every one REFUSED by the real engine.
Every §3 class is covered:

*Authority may never increase descending* — child cap > parent cap (spend
inside the child's own cap); child budget > parent budget (the parent's
counter binds); recipient allowed by the child but not by the parent;
recipient allowed by the child but not by the grandparent; child fee cap >
parent fee cap; child carry cap > parent carry cap.

*Refold / counter forgery* — spend without advancing the level-1 counter;
spend without advancing the level-2 counter; successor agentRoot misreport;
sibling double-count beyond the shared parent budget; parent
period-accounting misreport (claimed spent 0).

*Membership / structural revocation* — stale parent leaf (committed counters
already advanced); removed grandparent with a reused parent chain; revoked
subtree (parent childRoot zeroed); ancestor presented with a zero childRoot.

*Level / chain shape* — level-2 key presented as level-1; chain shorter than
the leaf level; leaf committed at a different level than its chain position;
`> MAX_LEVEL` chain (a level-4 leaf through `childSpendL3`); self-parenting
(parent key reused as the child key); grandparent key reused as the spending
leaf key; level-2 parent presented to `delegateSetChildRoot1`; level-3 leaf
attempting `delegateSetChildRoot2`.

*Leaf-domain separation, both directions* — a tree committed with v0.5 leaf
hashes presented to `hdSpend`; and the FROZEN `PolicyVault.v0.5.sil` driven
with an HD-committed `agentRoot` (with a positive control proving the same
transaction shape IS accepted when the tree is committed in v0.5 format).

*Delegation integrity* — `delegateSetChildRoot1` signed by a sibling level-1
leaf, by the child, by a grandchild, by the vault owner, by an outsider;
`delegateSetChildRoot2` signed by the grandparent; the op also changing
`feeReserve` / `paused` / `policyNonce` / `boundVaultId` / the successor
output value; the op raising the parent's own cap in the refold; successor
root misreport; a no-op (childRoot unchanged); tokens riding a delegation
op; a stale parent leaf; a removed grandparent.

*Expiry consistency* — child `expiryDaa` > parent's; parent's >
grandparent's.

*Signature and sighash* — wrong signer (outsider, the PARENT's key on the
child's spend, the owner key); `SIGHASH_NONE` / `SIGHASH_SINGLE` /
`SIGHASH_ANYONECANPAY` on both a level-3 spend and a delegation op;
post-sign mutation of an output value on both.

*Fee / value leakage and pause* — fee reserve consumed above the exact
network fee; successor value below the declared reserve; declared successor
reserve inflated; token-family KAS leaked to change; token conservation
(+1); paused vault; a spend flipping the vault to paused; a spend bumping
the owner policy nonce; a spend rebinding the vault id; recipient owned by
the covenant-id scheme instead of p2pk; recipient outside every allowlist;
**delegation while the vault is PAUSED** (resolving OQ-HD-3, below).

**Refusal strings.** Every one of the 66 rows fails as
`TxScriptError::VerifyError`. That is the expected and only granularity
here: each rule is a SilverScript `require`, which compiles to
`OP_VERIFY`-class failure, so the engine reports the same terminal error for
every policy violation. Two structural classes surface a different error and
were seen during the wave: `StackSizeExceeded(245, 244)` for the rejected
field-argument layout at level 3, and `CleanStack`-class failures for
under-threshold stack padding. Because a uniform refusal string proves only
that *something* failed, the wave adds an explicit sabotage test.

### 6.8 Sabotage sensitivity — 7 guards proven load-bearing

For each guard: with the covenant INTACT the attack is refused, and with
exactly that guard removed from the source the SAME attack is ACCEPTED by
the real engine.

| guard | attack that passes once it is removed |
|---|---|
| per-level cap intersection | child cap 400 vs level-1 cap 250, spend 300 |
| per-level recipient allowlist intersection | recipient allowed by the child, not by the grandparent |
| nested refold pins the successor agentRoot | spend without advancing the parent's counter |
| fee cap = minimum over the chain | child fee cap 100,000 vs level-1 cap 20,000 |
| carry cap = minimum over the chain | child carry cap 1 KAS vs level-1 cap 0.05 KAS |
| expiry consistency | child `expiryDaa` beyond its parent's |
| delegation may change ONLY the parent's childRoot | delegation also bumping `policyNonce` |

The chain-position **level pin is structural, not a removable `require`** —
the level is a covenant constant inside the leaf preimage — so it is proven
by the four hostile rows that present a leaf at the wrong position rather
than by guard removal.

### 6.9 Answers to the open questions

- **OQ-HD-2 (MAX_LEVEL 2 vs 3) — ANSWERED BY MEASUREMENT: MAX_LEVEL = 3.**
  A level-3 spend executes on the real engine at 208/244 combined stack
  items (36 of headroom, depth-independent), 7 static sig-ops of 15,
  91,176 normalized mass of the 500,000 block reference, and a 42,472-byte
  redeem. A level-4 spend extrapolates to 254 items and is therefore
  refused by construction — no entrypoint accepts a longer chain, which is
  now a MEASURED bound rather than a stylistic one. Child-tree depth 8
  (256 children per node) and agent depth 12 (4,096 level-1 leaves) are
  proven at full depth with no stack cost. If a future version wants
  MAX_LEVEL 4 it must first buy ~10 more stack items per level; the
  measured levers are the token dual-binding block (45 items, constant) and
  the per-level 43-46.
- **OQ-HD-3 (should a paused vault block delegation) — YES, implemented and
  probed.** `delegateSetChildRoot1/2` both require `prevState.paused == 0`,
  and "delegation while the vault is PAUSED" is a refused hostile row. The
  v0.7 organizational root is not involved in this probe; the same rule
  should apply to a FROZEN root when the two are composed.
- **OQ-HD-1 (a cheaper stateless-child tier) — NOT ANSWERED, and now
  cheaper to leave open.** The per-child period counter costs no stack
  (the counters live inside the body that is already carried) and the
  marginal cost of a level is dominated by the membership proof and refold,
  not by the counter. A stateless tier would save little and would give up
  per-child budgets, so there is no measured reason to add it.

### 6.10 Deviations from the §4 plan, with source-level reasons

1. **Leaf carriage changed from separate fields to one 160-byte body**
   (§6.2). Reason: `MAX_STACK_SIZE = 244`
   (`~/rusty-kaspa/crypto/txscript/src/lib.rs:76`); the field layout puts a
   level-3 spend at 272 items. The committed leaf CONTENT is unchanged.
2. **`level` is never a caller argument.** Each entrypoint substitutes the
   level constant of the position it checks. Same binding, ~3 fewer stack
   items per ancestor, and one fewer runtime check.
3. **Four entrypoints instead of two parameterised ones** (`childSpendL2` /
   `childSpendL3`, `delegateSetChildRoot1` / `delegateSetChildRoot2`).
   Reason: each pins its own chain length and level constants at compile
   time, and the regions are independently strippable so MAX_LEVEL could be
   measured. Cost: static sig-ops 7 instead of the §4 estimate of 3-4
   (still less than half of the standardness budget of 15).
4. **§4 item 2 asked for a level-1 spend "byte-identical in semantics" to
   today's** — the semantics are preserved (identical caps, budget,
   recipient allowlist, fee-reserve and carry rules, and the identical v0.5
   token dual binding) but the bytes are NOT identical: +80 B of redeem from
   the new leaf format and the explicit in-covenant SIGHASH gate. A
   production successor would be a NEW additive covenant version, never a
   mutation of the frozen v0.5 file.
5. **`sig` parameters replaced by `byte[]` + an explicit 65-byte / `0x01`
   SIGHASH gate** (the v0.6 `requireAgentAuthorization` pattern), so
   `SIGHASH_NONE` / `SINGLE` / `ANYONECANPAY` are refused inside the
   covenant. Probed on both a level-3 spend and a delegation op.
6. **`expiryDaa` IS carried and IS checked for monotonicity down the chain**
   — as a CONSISTENCY rule only. §0 stands unchanged: Kaspa `lockTime` is a
   lower bound, so an expiry is not consensus-enforceable as a time check.
   What consensus enforces here is that a chain whose committed expiries
   invert cannot spend; what actually retires a delegate is REVOCATION or
   the periodic budget.
7. **A measurement-only source variant** (the token dual-binding block
   removed) is used for stack accounting and is never treated as an
   acceptance; it exists only to attribute stack items between the
   hierarchical logic and the inherited v0.5 block.

### 6.11 What remains UNPROVEN

- **No production covenant, no generator, no byte freeze.** There is no
  `PolicyVault.v0.x.sil` for hierarchical delegation and no `tools/gen_*.js`
  deterministic generator. The probe source is experimental and may change.
- **No live testnet.** Nothing has been broadcast; there is no lifecycle
  evidence, no real DAA-score rollover, no real mempool acceptance. In
  particular the rollover paths were exercised with `tx.lockTime` in the VM,
  not against a live node's `check_tx_is_finalized`.
- **No production-byte integration.** The CLAUDE.md production-byte rule is
  unmet: the covenant calls were encoded in-process, not through
  `pv_call_encoder`. A production successor MUST drive the real encoder's
  exact bytes through the engine before any freeze (the motivating incident
  is the v0.2 `boundVaultId` defect).
- **No SDK, API, manifest, state-format or request versioning**, no UI, no
  shared-core refusal for expired delegations (§1.4 assigns that to the core
  and it does not exist yet).
- **No composition with v0.7.** The organizational root was deliberately
  kept out of this probe. The interaction of a FROZEN root with delegation
  ops, and the combined stack cost of a rooted level-3 spend, are unmeasured
  — and the 36 items of level-3 headroom are the budget any such composition
  has to fit into.
- **No fee-economics or adversarial-mempool analysis.** A ~46 KB
  transaction whose cost is dominated by revealing a 42 KB redeem has real
  fee consequences that were not modelled.

### 6.12 Verdict

**HIERARCHICAL-DELEGATION-DESIGN-FREEZE-READY.**

The §1 model is mechanically convincing on the real engine: authority never
increases descending (proven by 6 hostile rows and 6 sabotage rows, not by
argument), delegation costs exactly one parent signature and can only name a
key, a spend at any level costs exactly one signature, every ancestor's cap,
budget, allowlist, fee and carry bind at every spend, revocation is
structural, and MAX_LEVEL 3 is a MEASURED bound with 36 stack items of
headroom rather than a preference. The design record above is amended by
§6.2 (leaf carriage) and §6.10 (deviations); OQ-HD-2 and OQ-HD-3 are
resolved.

This freezes the DESIGN only. It is not authorization to build a production
covenant version, and nothing here is TESTNET-VERIFIED or PRODUCTION-BYTE-
PROVEN.
