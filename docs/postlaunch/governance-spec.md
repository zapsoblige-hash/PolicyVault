# PolicyVault Policy-Change Governance — Program B v1

Status: **DESIGNED** (this framework) / classifier core **IMPLEMENTED +
UNIT-TESTED** (`core/governance/`, 57/57 `node --test`). Nothing in this
document is deployed, wired into the hosted server, or externally
reviewed. This is a post-launch upgrade design layered on the released
v0.4.1 product; it changes **no covenant bytes, no SDK transaction
pipeline, no existing hosted behavior**.

Related: `docs/postlaunch/risk-adapter-spec.md` (Program D),
`docs/hosted-threat-model.md` (compromised-server/DB verdicts this design
must remain consistent with), `docs/covenant-spec-v0.4.1.md` /
`docs/covenant-spec-v0.4.md` / `docs/covenant-spec-v0.3.md` /
`docs/covenant-spec.md` (frozen ABIs and per-entrypoint permissions).

---

## 1. Scope and non-goals

Program B governs **changes to vault policy** — who may spend, how much,
how often, to whom, under whose approval — across the frozen covenant
versions `policyvault-0.2`, `policyvault-0.3`, `policyvault-0.4`, and
`policyvault-0.4.1`. It adds a coordination protocol (proposals,
classification, approvals, delays, cancellation) **around** the covenant's
existing owner-signed policy operations.

Non-goals, permanently:

- Governance NEVER replaces, weakens, or shortcuts a covenant signature
  requirement. Every policy transition still requires the vault owner's
  BIP-340 signature over the exact frozen transaction bytes, verified by
  Kaspa consensus. Governance can only ADD ceremony, never remove the
  covenant's.
- No new consensus features. Program B is SDK/API/UI-plane work (the
  owner's v0.4 final-core direction: after v0.4, prefer SDK/API/UI
  features over covenant growth).
- No monetization of any kind. Governance is part of the free product for
  everyone, like every security feature (docs/product-policy.md).

### 1.1 Core invariants (binding on every implementation phase)

1. **No hosted authority expansion.** A compromised hosted administrator
   or database must NEVER be able to expand covenant financial authority
   by changing database state. Authority expansion requires cryptographic
   owner (and, where configured, approver-quorum) authority verified
   against the covenant boundary — never hosted records. §9 states how
   the design achieves this.
2. **Restrictive-only off-chain controls.** Off-chain governance and risk
   controls may make PolicyVault MORE restrictive; they may never
   override a covenant denial or substitute for covenant verification
   (Program D, `docs/postlaunch/risk-adapter-spec.md`).
3. **Unknown fails closed.** Unknown covenant versions, unknown mutation
   classes/fields, and unknown verdicts refuse or classify as EXPANSION;
   nothing unknown is ever routed to a default or to the lighter lane.
4. **Numeric safety.** All consensus/accounting quantities are integer
   sompi/DAA: BigInt in JS, base-10 decimal strings in JSON. Floats, NaN,
   negatives, unsafe integers, and out-of-i64-domain values refuse.

---

## 2. Two administration planes

PolicyVault's hosted layer already distinguishes these planes (proven in
Phases B–F of the hosted program); Program B makes the split an explicit
design rule with named catalogues.

### 2.1 Ordinary hosted administration (metadata plane)

Database-writable, session-authorized, **zero covenant authority**:

- organization records, member lists, role labels (`sdk/src/organization.js`
  `ROLE_LABELS`: `owner`, `administrator`, `treasurer`, `approver`,
  `delegate`, `auditor`, `viewer` — "Application role LABELS (metadata
  only — never on-chain authority)");
- vault labels, org assignment/grouping, display names, activity feeds;
- proposal records, collected approval records, governance configuration
  (quorum sizes, delay windows) — **stored, never authority-granting**
  (§9);
- sessions, rate-limit state, audit metadata.

Tampering with this plane can mislead displays, deny service, and leak
metadata — the residuals already accepted and bounded in
`docs/hosted-threat-model.md` §3/§5 — but cannot move funds or change any
covenant rule.

### 2.2 Financial-authority administration (covenant plane)

Every mutation in the governed catalogue (§4). Executable ONLY as a
covenant transition, signed inside the owner's wallet over frozen bytes,
accepted ONLY if Kaspa consensus verifies it against the current on-chain
state. The hosted layer builds and displays these transitions; it cannot
authorize them. There are no master keys, no admin bypass, and no
custodial recovery anywhere in the stack.

---

## 3. The real policy surface per covenant version

Field names below are the authoritative covenant/SDK names (from
`contracts/PolicyVault.v0.{2,3,4,4.1}.sil` and
`sdk/src/{vault-state-v2,vault-state-v3,vault-state-v4,agent-merkle-v4}.js`).

**Immutable template (all versions):** `owner` (pubkey), `vaultId`
(byte[32]). Never changeable in-lineage; changing either is a covenant
migration (§8). The covenant's `ownerRecover` pays
`protectedValue` (+ `feeReserve` in v0.4+) to the **owner key's P2PK
output** — recovery authority IS the owner key, so a "recovery-authority
change" is by construction an owner change, i.e. a migration.

**v0.2 mutable policy** (state fields; SDK form in parentheses):
`paused`, `delegate`, `delegateActive`, `maxPerSpend`, `periodBudget`,
`periodLengthDaa`, `recipient1..3` (SDK `recipients`, 1..3 keys).
Executing entrypoints: `ownerPause`/`ownerUnpause`, `rotateDelegate`,
`revokeDelegate`, `migratePolicy` (caps/budget/period **and** the
recipient slots — v0.2's `migratePolicy` does not pin `recipient1..3`),
`ownerTopUp`, `ownerRecover`. Accounting `protectedValue`,
`periodStartDaa`, `periodSpent` and identity `boundVaultId` are preserved
by every owner policy op (`requireOwnerLifecycleCore`).

**v0.3 adds:** `recipientRoot` (Merkle allowlist commitment),
`approver1..10` (SDK `approvers`/`approverSlots`, sentinel = 64 zero
hex), `approvalM`, `approvalThresholdAmount`. Executing entrypoints add
`ownerSetRecipientRoot`, `ownerSetApprovers` (slots + M + threshold
atomically, A2 distinctness), while `migratePolicy` narrows to
caps/budget/period only (it preserves delegate, recipients, approvers).

**v0.4 / v0.4.1 restructure:** the single delegate and its per-delegate
policy move INTO an authenticated per-agent Merkle leaf. Vault-global
state: `boundVaultId`, `protectedValue`, `feeReserve`, `paused`,
`agentRoot`, `approver1..10`, `approvalM`, `policyNonce`. Per-agent leaf
(124-byte frozen preimage, `sdk/src/agent-merkle-v4.js`): `agentPk`,
`maxPerSpend`, `periodBudget`, `periodLengthDaa`, `periodStartDaa`,
`periodSpent`, `approvalThreshold`, `agentMaxFeePerTx`,
`agentRecipientRoot` (SDK registry keeps the per-agent `recipients` list
and recomputes the root). Executing entrypoints: v0.4 has discrete owner
ops; v0.4.1 consolidates them into `ownerControl(opSelector)` with
`OWNER_OP_SELECTOR_V4_1` = `ownerSetAgentRoot:0`, `ownerSetApprovers:1`,
`ownerTopUp:2`, `ownerTopUpReserve:3`, `ownerPause:4`, `ownerUnpause:5`;
plus `agentSpend` and terminal `ownerRecover`. ALL agent-policy edits
(add/remove/rotate/re-policy/fee-cap change) execute as one
`ownerSetAgentRoot` root swap built from the edited registry.

`policyNonce` increments by exactly 1 on policy-defining ops
(`ownerSetAgentRoot`/`ownerSetApprovers` in v0.4+; every owner policy
change in v0.2/v0.3) — governance uses it as the monotonic audit counter
it was retained to be, and never sets it directly.

---

## 4. Governed mutation catalogue

Every row names the REAL fields and the covenant entrypoint that executes
it. "Direction" is the classification the §5 rule produces for the pure
form of the mutation.

| # | Mutation class | Fields (version) | Executing entrypoint | Direction |
|---|---|---|---|---|
| M1 | Per-spend cap change | `maxPerSpend` (v0.2/v0.3 state; v0.4 leaf) | `migratePolicy` / `ownerSetAgentRoot` | decrease REDUCTION · increase EXPANSION |
| M2 | Periodic budget change | `periodBudget` (v0.2/v0.3 state; v0.4 leaf) | `migratePolicy` / `ownerSetAgentRoot` | decrease REDUCTION · increase EXPANSION |
| M3 | Budget period change | `periodLengthDaa` (v0.2/v0.3 state; v0.4 leaf) | `migratePolicy` / `ownerSetAgentRoot` | lengthen REDUCTION · shorten EXPANSION (long-run rate = `periodBudget`/`periodLengthDaa`) |
| M4 | Delegate revocation / re-enable | `delegateActive` (v0.2/v0.3) | `revokeDelegate` / `rotateDelegate` | 1→0 REDUCTION · 0→1 EXPANSION |
| M5 | Delegate key rotation | `delegate` (v0.2/v0.3) | `rotateDelegate` | any change EXPANSION (a new key gains authority) |
| M6 | Agent added / removed | agent leaf keyed by `agentPk` (v0.4 family) | `ownerSetAgentRoot` | remove REDUCTION · add EXPANSION |
| M7 | Agent policy edit | leaf `maxPerSpend`, `periodBudget`, `periodLengthDaa`, `approvalThreshold`, `agentMaxFeePerTx` | `ownerSetAgentRoot` | per §5 table |
| M8 | Agent accounting rewrite | leaf `periodSpent`, `periodStartDaa` | `ownerSetAgentRoot` (root swap CAN rewrite leaf accounting — unlike v0.2/v0.3, where covenant rules preserve accounting) | spent increase REDUCTION · spent decrease (refund/reset) EXPANSION · any `periodStartDaa` change EXPANSION |
| M9 | Recipient allowlist edit | `recipient1..3`/`recipients` (v0.2), `recipientRoot` (v0.3), leaf `agentRecipientRoot` + registry `recipients` (v0.4) | `migratePolicy` (v0.2) / `ownerSetRecipientRoot` (v0.3) / `ownerSetAgentRoot` (v0.4) | removal REDUCTION · addition EXPANSION · bare root swap EXPANSION (opaque) |
| M10 | Approval quorum change | `approvalM` (v0.3/v0.4) | `ownerSetApprovers` | increase REDUCTION · decrease EXPANSION |
| M11 | Approver set change | `approver1..10` (v0.3/v0.4) | `ownerSetApprovers` | removal REDUCTION · addition EXPANSION · replacement EXPANSION |
| M12 | Approval threshold change | `approvalThresholdAmount` (v0.3) / leaf `approvalThreshold` (v0.4) | `ownerSetApprovers` / `ownerSetAgentRoot` | decrease REDUCTION · increase EXPANSION (more spends escape the approval tier) |
| M13 | Emergency freeze / resume | `paused` | `ownerPause` / `ownerUnpause` (v4.1 selectors 4/5) | 0→1 REDUCTION (always-available freeze) · 1→0 EXPANSION |
| M14 | Owner change | template `owner` | impossible in-lineage → migration (§8) | ALWAYS EXPANSION |
| M15 | Recovery-authority change | `ownerRecover` destination = owner P2PK | = owner change → migration (§8) | ALWAYS EXPANSION |
| M16 | Covenant migration / policy-version upgrade | `contractVersion` (`policyvault-0.2/0.3/0.4/0.4.1`) | `ownerRecover` → new-version create (in-lineage cross-version migration is VM-experiment-proven impossible, covenant-spec-v0.4 §7) | ALWAYS EXPANSION |
| M17 | Policy migration (v0.2/v0.3 composite) | `migratePolicy` bundles M1+M2+M3 (+M9 in v0.2) | `migratePolicy` | per-field; any expansion side ⇒ EXPANSION |

**Not governed policy (proposals refuse changes to them):**
`protectedValue` and `feeReserve` (funding — `ownerTopUp`/
`ownerTopUpReserve`/spends move them; classifier code
`NOT_A_POLICY_FIELD`); v0.2/v0.3 top-level `periodStartDaa`/`periodSpent`
(covenant-preserved accounting; `ACCOUNTING_IMMUTABLE`); `boundVaultId`
(`IDENTITY_IMMUTABLE`); `policyNonce` (`EXECUTION_MANAGED`).

---

## 5. Classification rule — AUTHORITY REDUCTION vs AUTHORITY EXPANSION

Implemented as the pure function
`classifyPolicyDelta({ covenantVersion, before, after })` in
`core/governance/authority-delta.js`, returning
`{ classification: REDUCTION|EXPANSION, perField, codes }`. The rule:

1. Parse both tuples strictly against the version's exact key schema
   (`TUPLE_KEYS`). Unknown version / unknown field / missing field /
   malformed value / structurally invalid tuple ⇒ **refuse** (throw
   `GovernanceRefusal` with a machine code; `failClosed: true`).
2. Evaluate each governed field's direction independently (table below),
   ceteris paribus.
3. Aggregate: **any EXPANSION field ⇒ EXPANSION** (this is what makes
   per-field evaluation compose safely — e.g. `periodBudget` up +
   `periodLengthDaa` up may lower the long-run rate, but the within-period
   burst capacity still rose, so the proposal is EXPANSION with
   `MIXED_CHANGE`); otherwise ≥1 REDUCTION ⇒ REDUCTION; all-NEUTRAL ⇒
   refuse `NO_CHANGE`.
4. Anything ambiguous, opaque, or mixed lands on the EXPANSION side.
   There is no third classification and no unknown-to-lighter-lane path.

### 5.1 Per-field direction table (normative; mirrored by the code and tests)

| Field (real name) | Versions | REDUCTION when | EXPANSION when | Codes |
|---|---|---|---|---|
| `paused` | all | 0→1 (freeze) | 1→0 (resume) | `EMERGENCY_FREEZE` / `RESUME_SPENDING` |
| `delegate` | v0.2, v0.3 | never | any key change | `DELEGATE_KEY_CHANGED` |
| `delegateActive` | v0.2, v0.3 | 1→0 (revoke) | 0→1 (enable) | `DELEGATE_REVOKED` / `DELEGATE_ENABLED` |
| `maxPerSpend` | v0.2, v0.3 state | decrease | increase | `PER_SPEND_CAP_LOWERED` / `PER_SPEND_CAP_RAISED` |
| `periodBudget` | v0.2, v0.3 state | decrease | increase | `PERIOD_BUDGET_LOWERED` / `PERIOD_BUDGET_RAISED` |
| `periodLengthDaa` | v0.2, v0.3 state | increase (lower spend rate; no window ever gains budget) | decrease (budget refreshes faster) | `PERIOD_LENGTHENED` / `PERIOD_SHORTENED` |
| `recipients` (v0.2 `recipient1..3`) | v0.2 | member removed | member added | `RECIPIENT_REMOVED` / `RECIPIENT_ADDED`; reorder/duplicate padding is set-NEUTRAL |
| `recipients` list (both sides) | v0.3 | member removed | member added | `RECIPIENT_REMOVED` / `RECIPIENT_ADDED` |
| `recipientRoot` (bare root, or list-vs-root mismatch) | v0.3 | never (subset unprovable) | any change / mismatch | `OPAQUE_COMMITMENT_CHANGED` |
| `approvers` (`approver1..10`) | v0.3, v0.4 family | member removed | member added; replacement = add+remove ⇒ EXPANSION | `APPROVER_REMOVED` / `APPROVER_ADDED` (set semantics; slot position is authority-neutral) |
| `approvalM` | v0.3, v0.4 family | increase (more approvals required) | decrease (quorum weakening) | `APPROVAL_QUORUM_RAISED` / `APPROVAL_QUORUM_WEAKENED` |
| `approvalThresholdAmount` | v0.3 | decrease (more spends need approvals) | increase | `APPROVAL_THRESHOLD_LOWERED` / `APPROVAL_THRESHOLD_RAISED` |
| agents set (leaf keyed by `agentPk`) | v0.4 family | agent removed | agent added | `AGENT_REMOVED` / `AGENT_ADDED` |
| leaf `maxPerSpend` | v0.4 family | decrease | increase | `AGENT_PER_SPEND_CAP_LOWERED` / `_RAISED` |
| leaf `periodBudget` | v0.4 family | decrease | increase | `AGENT_PERIOD_BUDGET_LOWERED` / `_RAISED` |
| leaf `periodLengthDaa` | v0.4 family | increase | decrease | `AGENT_PERIOD_LENGTHENED` / `AGENT_PERIOD_SHORTENED` |
| leaf `periodStartDaa` | v0.4 family | never (temporal effect ambiguous — can open a fresh period early) | any change | `AGENT_PERIOD_PHASE_CHANGED` |
| leaf `periodSpent` | v0.4 family | increase (records consumption) | decrease (refunds budget — a fresh lane; the "no policy migration grants a fresh budget" invariant made classifiable) | `AGENT_BUDGET_CONSUMPTION_RECORDED` / `AGENT_BUDGET_REFUNDED` |
| leaf `approvalThreshold` | v0.4 family | decrease | increase | `AGENT_APPROVAL_THRESHOLD_LOWERED` / `_RAISED` |
| leaf `agentMaxFeePerTx` | v0.4 family | decrease | increase | `AGENT_FEE_CAP_LOWERED` / `AGENT_FEE_CAP_RAISED` |
| per-agent `recipients` (lists both sides) | v0.4 family | member removed | member added | `AGENT_RECIPIENT_REMOVED` / `AGENT_RECIPIENT_ADDED` |
| leaf `agentRecipientRoot` (bare/mismatch) | v0.4 family | never | any change | `OPAQUE_COMMITMENT_CHANGED` |
| `agentRoot` (bare vault root, or list-vs-root mismatch) | v0.4 family | never | any change / mismatch | `AGENT_SET_OPAQUE` |
| `boundVaultId` | all | — refuse on change — | | `IDENTITY_IMMUTABLE` |
| `protectedValue`, `feeReserve` | all present | — refuse on change — | | `NOT_A_POLICY_FIELD` |
| top-level `periodStartDaa`, `periodSpent` | v0.2, v0.3 | — refuse on change — | | `ACCOUNTING_IMMUTABLE` |
| `policyNonce` | all | — refuse on change — | | `EXECUTION_MANAGED` |
| Owner / recovery authority / covenant version | template | never | ALWAYS (migration, §8) | `COVENANT_MIGRATION` |

Opaque-commitment rule, stated fully: proving a recipient/agent-set
REDUCTION requires explicit before/after key lists (sourced from the
root-verified durable registry) on **both** sides; the classifier compares
sets. A side carrying both a list and a root refuses `AMBIGUOUS_FORM`
(two authorities for one fact). The classifier never recomputes Merkle
roots — the EXECUTION layer (the existing SDK builders) is what binds a
list to the on-chain root, because it already rebuilds
`recipientRoot`/`agentRoot` from registry lists and root-verifies against
chain state. A list the execution layer cannot bind to the committed root
simply fails to build.

Structural validity is enforced per side before any classification
(mirroring `normalizeStateV3`/`normalizeStateV4` and covenant rule A2):
active-approver distinctness, `1 ≤ approvalM ≤ activeApproverCount` (or
`approvalM = 0` with zero approvers, plus v0.3's
`approvalThresholdAmount ≥ maxPerSpend` so approvals stay unreachable),
`periodBudget ≥ maxPerSpend` (v0.2/v0.3), duplicate `agentPk` refusal. A
malformed BEFORE tuple (hand-baked genesis class) refuses
`BEFORE_TUPLE_INVALID`: malformed live states are handled by break-glass
`ownerRecover`, never by governed policy editing.

---

## 6. Governance lanes (ceremony strength — free for everyone, never a paid tier)

The classification selects a **lane**. Both lanes end at the same hard
gate: the owner signs the covenant transition in their wallet, over
frozen bytes, reviewed from those bytes.

### 6.1 REDUCTION lane (safely-restrictive changes)

- Available immediately to the vault owner; no quorum, no delay.
- The app shows the per-field delta (all-REDUCTION by construction) and
  builds the wallet request directly.
- Organizations MAY configure advisory review even here (config can add
  ceremony; it can never subtract the owner signature).
- **Emergency freeze is privileged inside this lane:** a `paused 0→1`
  proposal (`EMERGENCY_FREEZE`) and terminal `ownerRecover` are
  break-glass owner actions. NO governance configuration may delay,
  gate, quorum, or block them — governance must never make a vault less
  protectable than the bare covenant does. (On-chain they are
  owner-signature-only operations regardless; this rule forbids the
  hosted UX from adding friction.) Cancellation of any pending proposal
  is likewise always available to the owner.

### 6.2 EXPANSION lane (authority expansions — strongest ceremony)

Applies to every EXPANSION classification, every `MIXED_CHANGE`, every
opaque/ambiguous change, and every migration (§8).

1. **Proposal** (§7) with the full recomputed per-field delta rendered
   from proposal content — never from a stored label.
2. **Approval collection**: the organization's configured governance
   quorum signs the canonical proposal digest (§7.2). For personal
   vaults the quorum defaults to the owner alone. Governance quorum
   settings are metadata; they gate the hosted WORKFLOW, not the chain.
3. **Delay window**: dangerous-change execution is delayed
   (org-configurable; recommended default 24h for organizations, 0
   permitted for personal vaults). During the delay the proposal is
   visible to all vault participants and cancellable by the owner (and
   by any configured governance approver withdrawing support below
   quorum). Delay is enforced by the hosted workflow AND advisorily
   surfaced in the signing review; it is coordination hygiene, not a
   consensus rule (§9 states this honestly).
4. **Execution**: after the delay, the app builds the covenant
   transition whose after-state is DERIVED FROM THE SIGNED PROPOSAL
   CONTENT, re-verifies live chain state still equals the proposal's
   `before` tuple (else refuse `STALE_PROPOSAL` — the existing frozen-tx
   pipeline enforces this anyway: frozen bytes bind the exact predecessor
   outpoint, so a stale predecessor cannot confirm), re-runs
   `classifyPolicyDelta`, and only then requests the owner's wallet
   signature. The wallet renders the real bytes (the Phase G-grounded
   trust anchor).
5. **Reconciliation**: the proposal is COMPLETED only by proven chain
   reconciliation (txid verified, predecessor consumed, successor
   observed) — the existing pipeline discipline, unchanged.

Availability note (honest): the REDUCTION lane's lightness is a UX
statement, not a security one — a reduction still requires the owner
signature, so a lost owner key blocks reductions too; that is the
existing, documented covenant model.

---

## 7. Proposals, canonical encoding, approval collection

### 7.1 Proposal object (schema `policyvault-governance-proposal/v1`)

JSON-safe (integers as decimal strings), stored in the hosted DB or the
self-hosted JSON store identically:

```
{
  schema: "policyvault-governance-proposal/v1",
  kind: "policy-change" | "covenant-migration",
  network: <networkId>,                 // config==request==manifest==node equality chain
  vaultId: <64-hex>,
  covenantVersion: "policyvault-0.2|0.3|0.4|0.4.1",
  before: <policy tuple, §5 schema>,    // from the reconciled live manifest
  after:  <policy tuple, §5 schema>,
  // covenant-migration additionally: fromVersion, toVersion, newTemplate
  proposedBy: <wallet identity>,
  createdAt: <ISO timestamp>,
  expiresAt: <ISO timestamp>            // proposals expire; stale tuples fail anyway
}
```

The stored record MAY cache `classification`, but every consumer —
listing UI, review modal, approval prompt, execution builder — recomputes
`classifyPolicyDelta(proposal)` and refuses on divergence
(`CLASSIFICATION_MISMATCH`, an integrity alarm). Unknown `schema` or
`kind` refuses (`GOVERNANCE_SCHEMA_UNKNOWN`).

### 7.2 Canonical bytes and signatures

`core/governance/canonical.js`:

- `encodeGovernanceProposal(proposal)` — strict key-sorted,
  representation-independent serialization (semantic parity with
  `sdk/src/canonical-json.js`; arrays ordered, BigInt/undefined/non-plain
  refuse). This is mandatory because PostgreSQL jsonb reorders object
  keys — the Phase G-2 incident class; the standing rule requires every
  integrity commitment to be canonical AND to carry a PG-round-trip
  regression when wired to a store.
- `governanceProposalDigest(proposal)` = SHA-256 over
  `"policyvault-governance-proposal-digest/v1" || "\n" || canonical bytes`.

Governance approvals are wallet signatures over this digest via the
existing personal-message signing mechanism (kaspa-wasm Schnorr over
`PersonalMessageSigningHash`) — the domain rusty-kaspa keeps permanently
disjoint from `TransactionSigningHash`, so a governance approval can
never be replayed as a transaction signature or vice versa (verified in
the hosted program; `docs/hosted-threat-model.md` §3). The DB stores
`{proposalDigest, approverWallet, signature}` rows; anyone can re-verify
every row from the proposal content. Governance approvals authorize the
hosted WORKFLOW to proceed; they are not covenant approvals — the
covenant's own `approver1..10` M-of-N signatures over the frozen
transaction remain a separate, consensus-verified mechanism.

---

## 8. Migration governance

Covenant migration (v0.2→v0.3, v0.3→v0.4.1, policy-version upgrade, or a
same-version recreate to change the `owner`/recovery authority) is a
two-step lineage replacement — `ownerRecover` (terminal) then a
new-version `create` — because in-lineage cross-version migration is
VM-experiment-proven impossible. Governance treats it as ONE proposal of
`kind: "covenant-migration"`:

- `classifyMigrationDelta({fromVersion, toVersion})` is ALWAYS
  `EXPANSION` (`COVENANT_MIGRATION`) — the lineage, and possibly the
  authority anchor itself, is replaced. Unknown versions refuse.
- The proposal binds BOTH steps' parameters (recovery vault/outpoint and
  the complete new template + genesis policy). The UI additionally
  renders the old-vs-new policy delta for information, but the lane is
  EXPANSION regardless of how restrictive the new policy looks.
- Execution is two owner wallet signatures (recover, create), each over
  frozen bytes; the workflow completes only when reconciliation proves
  both (the funds sit in the owner's own P2PK between steps — the
  documented, honest custody model of every migration).
- Version discipline: `fromVersion`/`toVersion` must be in the governed
  registry; the new vault's `contractVersion` routes through the
  existing fail-closed version dispatch (`resolveV4Abi` etc.).

---

## 9. Invariant (1): why a compromised hosted admin/DB cannot expand authority

Statement (binding): **a compromised hosted administrator or database
must never be able to expand covenant financial authority by changing
database state; authority expansion requires cryptographic owner/quorum
authority verified against the covenant boundary, not hosted records.**

How the design achieves it, mechanism by mechanism:

1. **No key material server-side.** Proven hosted posture: no signing
   key exists in any server process, table, or deployment artifact
   (`docs/hosted-threat-model.md` §3 "none unilaterally"; Phase F
   re-verification). Governance adds no signer, no custody, and no
   donation-wallet signing logic.
2. **Consensus never reads the DB.** The covenant validates owner/agent/
   approver BIP-340 signatures over the exact transaction bytes against
   the on-chain predecessor state. DB rows are not an input to any
   consensus check. Rewriting `proposals`, `approvals`, governance
   config, or cached classifications changes displays and workflows —
   never what the chain accepts.
3. **Proposal integrity is signature-bound.** Every collected governance
   approval signs the canonical digest (§7.2). Tampering any committed
   proposal byte in storage invalidates every signature against the
   recomputed digest; jsonb key reordering does NOT (canonical encoding),
   so integrity failures are real tampering, not representation noise.
4. **Classification is recomputed, stored labels distrusted.** A DB
   writer who flips a stored `classification` to "REDUCTION" achieves
   nothing: every consumer recomputes from `before`/`after`; divergence
   refuses. A DB writer who edits `after` to smuggle an expansion breaks
   the collected signatures (3), and the classifier — run at render and
   again at execution — reports EXPANSION anyway.
5. **The last mile is the wallet, over frozen bytes.** Even a fully
   hostile hosted stack that fabricates an entire proposal chain still
   ends at the owner's wallet rendering the REAL transaction from the
   actual PSKT bytes (the Phase G-grounded trust anchor and the
   `docs/hosted-threat-model.md` §4 residual, stated honestly: a human
   who approves an unread wallet prompt can be defrauded by a fully
   compromised frontend — governance narrows the paths to that prompt
   and enriches what is displayed, and the canonical server review
   renders from frozen bytes, but the wallet-review anchor remains).
6. **Governance config sabotage is bounded.** The worst a DB
   administrator can do to governance itself is REDUCE off-chain
   ceremony (shrink a quorum, zero a delay) or DENY service (drop
   proposals). Reduced ceremony still leaves the full covenant gate: the
   owner's personal wallet signature over displayed frozen bytes, plus
   the covenant's own M-of-N approver signatures where the spend tier
   requires them. Denial-of-service cannot block `ownerPause` /
   `ownerRecover`, which any owner can execute against the chain with no
   hosted cooperation (self-hosted product, unchanged). This is the
   honest statement of what governance IS: coordination hygiene ABOVE
   the boundary, never the boundary.
7. **Fail-closed everywhere** (invariants 3–4): unknown versions/fields/
   schemas refuse; ambiguity classifies EXPANSION (strongest lane);
   numeric parsing refuses floats/negatives/overflow; `GovernanceRefusal`
   carries machine codes so refusals stay legible (the G-1 lesson).

Residuals (accepted, documented, consistent with the hosted threat
model): metadata privacy loss on DB compromise; service denial; the
wallet-review anchor for owner-signed operations.

---

## 10. Implementation status and evidence

| Component | Claim | Evidence |
|---|---|---|
| Program B framework (this document) | DESIGNED | — |
| `core/governance/authority-delta.js` (classifier, direction table, migration rule) | IMPLEMENTED + UNIT-TESTED | `core/governance/test/authority-delta.test.js` — per-field reduction AND expansion cases for every governed field class across v0.2/v0.3/v0.4/v0.4.1, mixed⇒EXPANSION, unknown version/field⇒refusal, neutral-field refusals, BigInt boundary cases (I64_MAX ±1, float/number/exponent/sign refusals), frozen JSON-safe results |
| `core/governance/canonical.js` (canonical proposal encoding + digest) | IMPLEMENTED + UNIT-TESTED | `core/governance/test/canonical.test.js` — key-order independence, jsonb-style round trip, BigInt/undefined/non-plain refusals, domain-separated golden digest |
| Proposal store/API/UI, approval collection, delay scheduler, execution wiring | DESIGNED only — NOT implemented | future phase; wiring into `server/` is out of this program's write scope |

Test totals for this program's core: **57/57** (`node --test
core/governance/test/`). No existing file was modified; covenant bytes,
SDK, server, and web are untouched.

## 11. Open questions (for the owner / next phase)

1. Should organization governance-quorum membership be bound to wallet
   identities only (current design) or also allow the covenant approver
   set to be reused as the default governance quorum? (Reuse is
   convenient; separation is cleaner — covenant approvals and workflow
   approvals are different authorities.)
2. Delay-window defaults per preset (Personal 0h / Business 24h?) and
   whether an owner may waive the delay per-proposal with an extra
   explicit confirmation.
3. Whether the v1 UI should refuse bare-root (`OPAQUE_COMMITMENT_CHANGED`
   / `AGENT_SET_OPAQUE`) proposals outright and always require
   list-form tuples from the registry (strictly better UX; the classifier
   already supports both).
4. Proposal expiry defaults and whether expiry should be
   `policyNonce`-based in addition to time-based.
