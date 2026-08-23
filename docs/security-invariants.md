# PolicyVault Security Invariants

Each invariant states its enforcement layer. CONSENSUS means enforced by
Kaspa L1 (covenant script + consensus rules) — unbreakable even by a
malicious actor holding the legitimate delegate key. APP means enforced by
PolicyVault software (defense in depth, not the security boundary).

## Consensus-enforced (the product's core claims)

- **I1 Delegate identity.** Only a valid Schnorr signature by `delegate`
  can execute a spend path. Layer: CONSENSUS (checkSig).
- **I2 Owner identity.** Only a valid signature by `owner` can execute
  pause/unpause/recover. Layer: CONSENSUS.
- **I3 Per-spend cap.** `payAmount <= maxPerSpend` on every spend path.
  Layer: CONSENSUS.
- **I4 Period budget.** `periodSpent + payAmount <= periodBudget` within a
  period. Layer: CONSENSUS.
- **I5 No early period reset.** A rollover requires CLTV proof that
  `tx.lock_time >= periodStartDaa + k*periodLengthDaa`, and consensus only
  accepts the tx when the DAA score exceeds `lock_time`. Client clocks are
  never trusted. Layer: CONSENSUS.
- **I6 Monotonic accounting.** Successor `periodSpent` is exactly
  `prev + payAmount` (same period) or exactly `payAmount` (rollover with
  proof); successor `periodStartDaa` advances only by whole periods with
  proof. Layer: CONSENSUS.
- **I7 Recipient allowlist.** Payment output scriptPubKey must equal an
  allowlisted P2PK exactly (canonical script bytes, not string compare).
  Layer: CONSENSUS.
- **I8 Exact payment.** Payment output value == payAmount exactly.
  Layer: CONSENSUS.
- **I9 Value conservation.** `prev.protectedValue == payAmount +
  new.protectedValue`; the successor covenant output carries exactly
  `new.protectedValue`. Protected principal can never leak into ordinary
  change or fees. Layer: CONSENSUS.
- **I10 Exact successor state.** Every non-terminal transition produces
  exactly one authorized successor whose full state tuple is pinned
  field-by-field. Layer: CONSENSUS (validateOutputState via covenant decl).
- **I11 Vault identity continuity.** `vaultId`, `owner`, `delegate`, and
  all policy constants are template constants — a successor with different
  policy is a different script and fails covenant validation.
  Layer: CONSENSUS.
- **I12 Owner recovery.** The owner can always move the full remaining
  protected value to the owner key; the delegate cannot execute this path;
  no third party (including PolicyVault operators) has any key that can.
  Layer: CONSENSUS.
- **I13 Pause.** While paused, no delegate spend path can execute.
  Layer: CONSENSUS.
- **I14 Termination discipline.** Only `ownerRecover` may terminate the
  lineage; spend paths cannot burn or orphan the vault. Layer: CONSENSUS.

## Application-enforced (defense in depth — NOT the security boundary)

- **A1 Fail-closed versioning.** Unknown contract/request/package versions
  are rejected, never defaulted.
- **A2 Exact live-state discipline.** The SDK acts only on a proven exact
  current state (state ID + outpoint); missing/ambiguous state fails
  closed as UNKNOWN.
- **A3 Builders never broadcast; only chain-proof reconciliation advances
  the manifest.**
- **A4 Durable claims.** Submission claims and covenant-transition claims
  serialize competing local attempts on the same outpoint.
- **A5 Signed-package immutability.** Any post-signing mutation of tx
  fields, outpoints, outputs, values, or metadata is rejected.
- **A6 Numeric safety.** BigInt sompi everywhere; canonical parsers reject
  NaN/Infinity/negatives/overflow/malformed decimals.
- **A7 Network safety.** Explicit networkId on every artifact and request;
  mainnet locked behind explicit authorization; no silent node switching.
- **A8 Secrets.** No seed phrases or owner private keys ever requested,
  stored, or logged.

## Claim-label discipline

Every invariant carries a status label that never collapses:
DESIGNED → IMPLEMENTED → UNIT-TESTED → VM-VERIFIED → TESTNET-VERIFIED →
PRODUCTION-HARDENED → EXTERNALLY REVIEWED → AUDITED.

Current status: all invariants **DESIGNED** (2026-08-11).

---

## v0.3 invariants (Phase 3 design; status EXP-PROVEN or DESIGNED)

Consensus-enforced unless noted. "EXP-PROVEN" = demonstrated on the real
VM by a Phase 3 experiment; "DESIGNED" = to be enforced + tested in
Phase 4. These extend, and do not replace, the v0.1/v0.2 invariants above.

Recipient authorization:
- **R1 Membership.** Every delegate payment recipient must prove
  membership in the CURRENT `recipientRoot` via a valid Merkle proof
  (bounded depth ≤ 16). Forged/modified/truncated/extended/foreign proofs
  are rejected. (EXP-PROVEN)
- **R2 Exact output binding.** The proven leaf commits to the exact
  x-only recipient, and the covenant independently requires
  `tx.outputs[0] == P2PK(recipientPk), value == payAmount`; the leaf is
  always recomputed (never accepted preformed), and leaf (36-byte) vs node
  (64-byte) preimages cannot collide. (EXP-PROVEN)
- **R3 Root governance.** `recipientRoot` changes only through an
  owner-authorized transition that bumps `policyNonce`; stale proofs
  against a superseded root cannot spend the new outpoint. (DESIGNED)
- **R4 Domain.** Authorization is "membership in the exact current root";
  the root itself is the domain, and output binding prevents redirection,
  so leaves need no per-vault salt for safety. (EXP-PROVEN + DESIGNED)

Approvals / multisig:
- **A1 Threshold.** A spend with `payAmount > approvalThresholdAmount`
  must carry ≥ `approvalM` distinct valid approvals from the CURRENT
  approver slots. (EXP-PROVEN)
- **A2 Distinctness.** An approver counts at most once; slot *i* verifies
  only approver *i*'s key (structural), so duplicates never double-count —
  PROVIDED the active approver keys are distinct. Enforced on BOTH:
  `ownerSetApprovers` (transitions) AND the delegate spend paths
  (`requireApproverSetWellFormed`, above threshold), because consensus does
  NOT validate v0.3 GENESIS state — a manually-baked malformed genesis UTXO
  with duplicate keys or `approvalM < 1` would otherwise bypass the tier.
  The empty-slot sentinel (all-zero, not a valid secp256k1 X coordinate)
  never counts and cannot collide with a real key. (Phase 4.5:
  malformed-genesis bypass reproduced on the production VM and fixed;
  regression `v3_REVIEW_malformed_genesis_*`.) VM-PROVEN.
- **A7 Sighash-type gate.** Every approval MUST be SIG_HASH_ALL. The
  covenant passes approvals as `byte[]`, requires 65-byte length + trailing
  byte 0x01, then verifies via a sig cast. Without this, a SIG_HASH_NONE
  approval authorizes an unseen payment (Phase 3.5 VM-PROVEN gap;
  V3SighashGateProbe VM-PROVEN fix). The delegate signature is gated the
  same way for uniformity. (EXP-PROVEN)
- **A3 Transaction binding.** Approvals are Schnorr signatures over THIS
  input's SIG_HASH_ALL sighash, binding the exact predecessor, amount,
  recipient, successor state/value, and action. (EXP-PROVEN)
- **A4 Freshness.** Any state or policy change alters the successor SPK /
  sighash and invalidates in-flight approvals. (EXP-PROVEN)
- **A5 No downgrade.** A successor may not lower `approvalM` / weaken the
  approver set except through an owner-authorized governance transition
  with `policyNonce + 1`. (DESIGNED)
- **A6 Rotation.** Approver rotation is atomic, preserves accounting,
  keeps `approvalM <= activeApproverCount`, and removed approvers cannot
  authorize afterward. (DESIGNED)

Governance / break-glass (MODEL 2, documented scope):
- **G1 Owner break-glass.** The owner retains single-signature lifecycle
  and recovery authority; v0.3 multisig protects the delegate tier, NOT
  against owner-key compromise (stated exactly in the product). (DESIGNED)
- **G2 Funds never trapped.** `ownerRecover` is always available with the
  single owner key, so lost approver keys cannot trap funds. (DESIGNED)

Migration:
- **MG1 No in-lineage upgrade.** A v0.2 covenant cannot authorize a v0.3
  template successor; upgrade is `ownerRecover` → create v0.3. (EXP-PROVEN)
- **MG2 Honest continuity.** The upgrade is presented as close + recreate
  (new covenantId/lineage); application continuity is metadata only, never
  a claimed on-chain lineage, and accounting is a fresh genesis, not a
  preserved migration. (DESIGNED; SDK primitives UNIT-TESTED in 4H)
- **MG3 Post-upgrade safety.** After upgrade the old v0.2 outpoint is
  consumed, so stale v0.2 transactions and the old delegate have no
  authority. (DESIGNED)

## Phase 4H application-layer invariants (defense in depth — NOT the
## security boundary; consensus remains the authority)

- **AP1 Freeze-before-collect.** The exact transaction (all
  sighash-visible fields) is frozen before any approval is collected;
  txId + covenant sighash come from real consensus code (`pv_tx_probe`).
  Consensus enforces the binding via SIG_HASH_ALL; the SDK additionally
  voids the package on ANY protected-field mutation via the sha256
  package commitment (which also closes the fields v1 consensus does not
  commit: the compute budget). UNIT/SDK/VM-PROVEN (4H).
- **AP2 Slot-bound verified approvals.** An approval is accepted only
  into the slot whose configured key it matches, only once, only as
  exactly 65 bytes ending 0x01, and only after authoritative Schnorr
  verification against the frozen transaction. UNIT/SDK-PROVEN; the
  covenant re-enforces all of it on chain (VM-PROVEN).
- **AP3 Package commitment is not authority.** The package commitment is
  a local integrity identifier; approver authority is exclusively the
  Kaspa Schnorr signature over the real transaction sighash. (By
  construction; asserted in code + tests.)
- **AP4 Canonical builders.** Callers supply intent, never successor
  state; every successor is derived and strictly re-normalized; version
  dispatch fails closed with no v0.3→v0.2 fallback. UNIT/SDK-PROVEN;
  illegal successors additionally consensus-rejected (VM-PROVEN).
- **AP5 Proven-safe budgets.** Committed compute budgets come from one
  central tier table (31/135/29/16) proven sufficient per shape on every
  VM run; callers can never commit less. VM-PROVEN (4H).
- **AP6 Break-glass parse quarantine.** The recovery-mode state parse
  (malformed approver sets etc.) constructs ONLY `ownerRecover`; every
  ordinary builder rejects it. Funds are never operationally trapped
  where consensus allows recovery (SDK-built recovery from a malformed
  state executes on the production covenant — VM-PROVEN).

---

## v0.4 invariants (architecture frozen — experiment-proven / source-proven)

v0.4 adds a covenant-controlled fee reserve and multiple independent
delegates/AI agents. Architecture frozen, implemented as
the production covenant `PolicyVault.v0.4.sil`, VM-proven,
production-byte-proven, and hostile-reviewed (production bytes unchanged,
SHA256 8f87dea…; no funds/authority/consensus defect); deployment uses the
semantically identical v0.4.1. These extend, and do not replace, the
v0.1/v0.2/v0.3 invariants. Classes:
VM-EXPERIMENT-PROVEN (real VM probe) / SOURCE-PROVEN / DESIGNED /
UNRESOLVED-LOW. No funds-critical invariant is UNRESOLVED.

Fee reserve:
- **v4-FR1** protected principal cannot pay fees. (VM-EXPERIMENT-PROVEN)
- **v4-FR2** the reserve cannot be redirected to a recipient; consumed
  reserve provably becomes network fee (`reserveConsumed <= fee`, with fee
  computed in-covenant from full value introspection). (VM-EXPERIMENT-PROVEN)
- **v4-FR3** per-transaction reserve-burn cap `maxFeePerTx`. (VM-EXPERIMENT-PROVEN)
- **v4-FR4** reserve floor ≥ 0 (negative state also structurally
  unconstructible). (VM-EXPERIMENT-PROVEN)
- **v4-FR5** owner tops up and recovers the reserve; an empty reserve
  never blocks recovery. (VM-EXPERIMENT-PROVEN)

Multi-delegate / agents:
- **v4-MD1** each agent's full policy is one authenticated Merkle leaf
  binding its key; a signature authorizes ONLY that leaf's exact policy.
  (VM-EXPERIMENT-PROVEN)
- **v4-MD2** no agent can borrow another's cap/budget/recipients/threshold
  (any field change alters the leaf → membership fails; another agent's
  leaf carries another's key → signature fails). (VM-EXPERIMENT-PROVEN)
- **v4-MD3** per-agent accounting is advanced in-covenant via a recomputed
  `agentRoot`; a forged successor root is rejected. (VM-EXPERIMENT-PROVEN)
- **v4-MD4** policy updates (`ownerSetAgentRoot`, nonce +1) invalidate
  stale agent proofs. (VM-EXPERIMENT-PROVEN)
- **v4-MD5** lost agent/approver keys never trap owner funds; owner
  recovers from any state incl. a malformed `agentRoot`. (VM-EXPERIMENT-PROVEN)
- **v4-MD6** concurrent agents on one MD-3 vault serialize on the single
  UTXO (normal double-spend resolution); parallel throughput uses MD-4
  child vaults. (SOURCE-PROVEN; honest limitation)

Approvals under agents (model D):
- **v4-AP1** one vault-global 10-slot approver set + per-agent threshold;
  a spend above the agent's threshold needs ≥ `approvalM` approvals.
  (VM-EXPERIMENT-PROVEN)
- **v4-AP2** the v0.3 A7 SIG_HASH_ALL gate and A2 distinctness hold for
  agent approvals; approvals bind the exact tx incl. the successor
  `agentRoot`, so no cross-agent/after-update reuse. (VM-EXPERIMENT-PROVEN)

Governance / migration:
- **v4-GOV1** owner remains single-sig break-glass; approvals protect the
  delegate tier only, stated honestly. (CONFIRMED)
- **v4-MG1** in-lineage v0.3→v0.4 migration impossible; upgrade =
  `ownerRecover` → create v0.4. (structural; confirmed, not funds-critical)

### Freeze additions

- **v4-FR-CAP** the per-transaction fee cap is per-agent
  (`agentMaxFeePerTx`, authenticated in the leaf); no global `maxFeePerTx`
  state field; no cumulative fee budget in v0.4.0 (bounded availability
  residual documented). (VM-EXPERIMENT-PROVEN)
- **v4-MD-UPD** an agent spend advances ONLY the spending agent's leaf
  accounting; the single-leaf Merkle update preserves every unrelated leaf;
  forged siblings/roots are rejected. FUNDS-CRITICAL. (VM-EXPERIMENT-PROVEN)
- **v4-VP-CONS** frozen conservation: `fee = reserveConsumed + (extIn −
  extOut)` with `reserveConsumed ≤ fee` ⇒ `extOut ≤ extIn`; principal moves
  only by the exact payment; reserve becomes only network fee bounded by
  `agentMaxFeePerTx`; no covenant value escapes a non-pinned output.
  (VM-EXPERIMENT-PROVEN + SOURCE-PROVEN)
- **v4-MG1** in-lineage v0.3→v0.4 migration impossible (real v0.3 covenant
  rejects a v0.4-template successor); upgrade = ownerRecover → create.
  (VM-EXPERIMENT-PROVEN)
- **v4-NONCE** `policyNonce` retained as a governance/audit counter;
  consensus replay-safety comes from SIG_HASH_ALL outpoint binding, not the
  nonce. (SOURCE-PROVEN + VM)

All v0.4 funds-critical invariants are SOURCE-PROVEN or
VM-EXPERIMENT-PROVEN; none remain DESIGNED/UNRESOLVED/BLOCKED. Frozen ABI:
`docs/covenant-spec-v0.4.md`.
