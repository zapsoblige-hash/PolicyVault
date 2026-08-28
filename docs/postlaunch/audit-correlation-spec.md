# PolicyVault Audit Correlation — Design (completion-standard item 7)

Status: **DESIGNED** (design only — this document changes NO schema, NO
migration, NO production file). Implementation belongs to the
`postlaunch-rc` lane (COMPLETION_STANDARD.md lane separation): every
writer named in §7 lives in `sdk/` or `server/`, and refactors of those
files happen on `postlaunch-rc` with their own build identity and test
evidence — never on the frozen production lane.

Requirement (owner-enumerated, `docs/postlaunch/COMPLETION_STANDARD.md`
item 7): *requested intent, verified manifest, policy state, approvals,
signer authorization, transaction identity, and resulting chain state
must be correlatable in audit/history.*

Related: `docs/postlaunch/intent-manifest-spec.md` (the manifest and its
hash), `docs/postlaunch/governance-spec.md` (proposals, digests,
governance approvals), `docs/hosted-threat-model.md` (what hosted
records can and cannot mean), `sdk/src/canonical-json.js` + the Phase
G-2 incident (why every stored commitment is canonical-JSON).

---

## 1. Ground rules

1. **Audit rows describe; the chain decides.** Nothing in this design
   grants or verifies authority. A database writer who edits any record
   here changes what the application DISPLAYS, never what Kaspa
   consensus accepted (hosted threat model §3). Correlation is history
   plumbing, not a security boundary.
2. **Append-only evidence, mutable workflow.** Durable *evidence*
   objects (audit events, receipts, stored manifests) are append-only /
   write-once. Durable *workflow* objects (wallet requests, claims,
   vault manifests) mutate by design; correlation therefore pins
   evidence by immutable keys (hashes, txids, state IDs), never by "the
   current content of a workflow row".
3. **Fail closed on unknowns.** Every stored record carries a `schema`
   version string; readers refuse unknown schemas. Missing correlation
   fields on old rows mean "predates correlation" (§10), never a
   default claim.
4. **No secrets exist to store** (§11). No key material, no seed
   phrases, no bearer tokens, and no token hashes ever enter audit or
   correlation records.

## 2. The real persistence layer today (evidence)

Schema: `server/migrations/001_initial_hosted_schema.sql` (PostgreSQL),
mirrored 1:1 by the self-hosted JSON layout through
`sdk/src/store.js` (`Categories` -> `CATEGORY_TABLE`). All value
columns are `jsonb` documents keyed by `(network_id, key)`.

| Table | Key | Value (as written today) | Writer (actual code) |
|---|---|---|---|
| `vaults` | vaultId | v4 manifest: `schema`, `contractVersion`, `networkId`, `vaultId`, `template.owner`, `status`, `agentRegistry[]`, `agentRegistryRoot`, `live {outpoint, stateId, state, outpointValue, scriptSha256, covenantId}`, `latestTransitionTxId`, `lastTransition {action, txId, oldStateId, newStateId, oldOutpoint, newOutpoint}` | `persistManifestV4` via `advanceManifestAndRegistryV4` (`sdk/src/wallet-submit-v4.js`) — advanced ONLY after exact chain proof |
| `wallet_requests` | requestId (uuid) | request envelope `policyvault-wallet-request/v4`: `state`, `contractVersion`, `networkId`, `vaultId`, `action`, `sdkAction`, `highLevel`, `signerRole`, `signerAddress`, `signerXOnly`, `agentPk`, `aboveThreshold`, `predecessorOutpoint`, `predecessorStateId`, `covenantId`, `successorStateId`, `newRegistry`, `build` (frozen tx + 11-field accounting + successorState + txId), `approvalPackage` (covenant approver slot signatures), `review`, `transaction` (unsigned Safe JSON), `finalTransaction`, `txId`, `createdAt`, `error` | `saveRequest` in `sdk/src/wallet-requests-v4.js` (`buildWalletRequestV4`, `collectApprovalV4`, `finalizeWalletRequestV4`) and `sdk/src/wallet-submit-v4.js` state advances |
| `transition_claims` | `<predecessor txid>-<index>` | `policyvault-transition-claim/v1`: `outpoint`, `action`, `txId`, `vaultId`, `stateId` (predecessor), `expected` (exact chain-provable effect incl. successor `stateId`/`state`/`covenantId`), `createdAt` | `claimTransition` (`sdk/src/submission-claim.js`), created at finalize (G) BEFORE broadcast |
| `submission_claims` | txId | `policyvault-submission-claim/v1`: `txId`, `vaultId`, `action`, `createdAt` | `claimSubmission`, created before the node call |
| `receipts` | txId | `policyvault-receipt/v1`: `txId`, `vaultId`, `action`, `proof {requestId, successorOutpoint \| outpoint, value, requiredFeeSompi, actualFeeSompi, covenantId?}`, `verifiedAt` | `persistReceipt`, written ONLY after `proveExpectedEffectV4` chain proof |
| `audit_events` | bigserial `id` (+ `network_id`, `vault_id` columns lifted from the record) | free-form event: `at`, `vaultId`, `action`, `actor` (**a ROLE string** — `"owner"`/`"agent"`/`"system"` — or org metadata), `contractVersion`, `txId`, `result` (`PREFLIGHT_VERIFIED`/`CHAIN_VERIFIED`/`REJECTED_BY_NODE`/`FAIL_CLOSED`/…), `feeSompi`, `oldStateId`, `newStateId`, `via`, `detail`, `kind`, `orgId`, `memberId` | `appendAudit` (`sdk/src/audit.js`) from `wallet-requests-v4.js` (finalize), `wallet-submit-v4.js` (submit outcomes), `reconcile-v4.js`, `organization.js`; append-only, written AFTER its mutation (non-atomic by ported contract) |
| `auth_sessions` | token_hash = sha256(token) | `wallet_address`, `xonly`, timestamps, `revoked` — **hash-at-rest; the raw bearer token is never stored** | `server/src/auth.js` |
| `organizations` / `org_assignments` | orgId / `assignments` | metadata plane only (zero covenant authority) | `sdk/src/organization.js` |

Claim lifecycle fact (relevant to queries): transition/submission
claims are **operational race arbiters, not audit history** — they are
released on a definitive node rejection (`wallet-submit-v4.js`) and by
reconciliation outcomes (`reconcile-v4.js`), and may linger after a
clean success until a reconcile touches the vault. Their absence proves
nothing; the durable evidence objects are receipts, audit events, and
the stored manifest record introduced below.

### 2.1 What already correlates today

`txId` already appears in receipts (key), submission claims (key),
transition claims (value), request envelopes, audit event values, and
`vaults.lastTransition`. `requestId` appears in `receipts.proof` and is
the wallet-request key. State IDs (`predecessorStateId` /
`successorStateId` / audit `oldStateId`/`newStateId` /
`live.stateId`) tie rows to exact policy states. Vault and network
scoping exist everywhere.

### 2.2 What item 7 still needs (the gaps)

1. **Requested intent** is not stored as a versioned structured object
   — the request row stores the build result and a human `review`, not
   the `policyvault-requested-intent/1` document.
2. **Verified manifest + verdict** are stored nowhere (the manifest
   layer is new).
3. **Governance proposals/approvals** have no store (Program B is
   classifier-only so far).
4. **Actor identity in audit events** is a role string; the wallet
   identity (x-only key) is not on the event, so "everything this
   wallet did" cannot be answered from the audit stream alone.
5. **No indexed walk** from an audit row to its manifest/request/
   proposal (`value->>'txId'` scans aside).

## 3. Correlation keys (the spine)

| Key | Form | Minted by | Meaning |
|---|---|---|---|
| `proposalId` | uuid | governance proposal store (Program B wiring) | one governance proposal (policy change / covenant migration) |
| `proposalDigest` | 32-byte hex | `governanceProposalDigest` (`core/governance/canonical.js`) | canonical content digest the governance approvals sign |
| `requestId` | uuid | `buildWalletRequestV4` / genesis builder | one durable wallet request (build→sign→submit lifecycle) |
| `manifestHash` | 32-byte hex | `computeManifestHashV1` (`core/intent/canonical.js`) | ONE exact intent manifest: requested intent + decoded transaction + states + accounting, representation-independent |
| `predecessorOutpoint` | `<txid>-<index>` | chain | the exact consumed covenant state (transition-claim key) |
| `stateId` (before/after) | 32-byte hex | `computeStateIdV4` | exact policy state identity |
| `txId` | 32-byte hex | rusty-kaspa (frozen v1 txid = broadcast txid) | the transaction identity, on-chain and everywhere at rest |
| `actorXOnly` (+ `actorAddress`) | 32-byte hex (+ bech32) | wallet | the ACTING wallet identity (§3.1) |
| `vaultId`, `networkId`, `contractVersion` | — | existing | scoping on every record |

The intended chain of custody for one covenant operation:

```
[proposalId?] -> requestId -> manifestHash -> txId -> successor outpoint/stateId -> chain
     |               |             |            |               |
governance      signer auth    requested     claims,        vault manifest
approvals       + covenant     intent +      receipt,       live/lastTransition
(digest-        approvals      verification  audit rows     (chain-proven)
 signed)        (request row)  verdict
```

### 3.1 Actor identity rule (sessions are hash-at-rest)

Hosted sessions are stored ONLY as `sha256(token)` (`auth_sessions`),
so a session row is deliberately unusable as a public audit reference.
The identity reference stored in audit/correlation records is the
**wallet's canonical x-only public key** (plus its canonical address
form for display): the same identity the covenant binds, hosted
authentication proves (Schnorr challenge over
`PersonalMessageSigningHash`), and tenancy scopes by. Rules:

- NEVER store the bearer token (already the rule) and NEVER copy
  `token_hash` into audit/correlation records — it is derived from a
  live credential, rotates/revokes, and would let an audit reader link
  rows to a credential hash for no correlation benefit.
- The audit event gains `actorXOnly` (and optionally `actorAddress`);
  the existing `actor` ROLE string stays (role and identity are
  different facts; `"system"` events carry `actorXOnly: null`).
- If per-session granularity is ever genuinely needed, first add a
  random surrogate `session_id` column to `auth_sessions` and reference
  THAT — a design decision explicitly deferred (§12).

## 4. Element-by-element mapping (required item-7 elements)

| Element | Where it lives today | postlaunch-rc addition |
|---|---|---|
| Requested intent | implicit in `wallet_requests.value.action/params` + `review` (not versioned) | embedded verbatim inside the stored manifest (`intent_manifests.value.manifest.requested` — the manifest schema REQUIRES the full `policyvault-requested-intent/1` document) |
| Verified manifest | nowhere | NEW `intent_manifests` table (§5), keyed by `manifestHash`, storing the canonical manifest JSON + the verification verdict recorded when it was produced |
| Policy state (before/after) | `predecessorStateId`/`successorStateId` (request), `stateId` + `expected.stateId` (transition claim), `oldStateId`/`newStateId` (audit), `vaults.live.state` + `lastTransition` | manifest carries the FULL state tuples (`stateBefore`/`stateAfter`), bound into `manifestHash` |
| Approvals — covenant (M-of-N spend approvals) | `wallet_requests.value.approvalPackage` (per-slot 65-byte Schnorr signatures over the frozen covenant input; slot keys = approver set) | audit event on approval collection gains `requestId` + `manifestHash` + `actorXOnly` of the approver |
| Approvals — governance (proposal quorum) | nowhere | NEW `governance_proposals` + `governance_approvals` (§5.3); every approval row is `{proposalDigest, approverWallet, signature}` re-verifiable from proposal content |
| Signer authorization | `signerRole`/`signerAddress`/`signerXOnly`/`agentPk` on the request; `assertSignerAuthorizedV4` runs at build AND at finalize (re-authorization), but leaves no explicit trace | the finalize-time audit event gains `actorXOnly`; the manifest's `actor` block (verified: owner-op signer = template owner; spend signer = agentPk) is the durable authorization statement, bound into `manifestHash` |
| Transaction identity | `txId` on request/claims/receipt/audit/lastTransition | `tx_id` lifted to an indexed audit column; `intent_manifests.value.txId` |
| Resulting chain state | `receipts.proof.successorOutpoint`+`value`; `vaults.live` (outpoint/stateId/covenantId, advanced only after exact chain proof); audit `newStateId` | no change needed — correlation reaches it through `txId`/`stateId`; Kaspa itself remains the final authority beyond the database |

## 5. New durable objects (minimal additive migration)

Two migration files, both purely additive (new tables, new NULLABLE
columns, new indexes — no rewrite of any existing row):

### 5.1 `002_postlaunch_audit_correlation.sql` (lands with intent enforcement)

```sql
-- One row per DISTINCT verified intent manifest, keyed by its
-- representation-independent hash. Write-once (create-only).
CREATE TABLE intent_manifests (
  network_id text  NOT NULL,
  key        text  NOT NULL,            -- manifestHash (64-hex)
  value      jsonb NOT NULL,            -- record, §5.2
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (network_id, key)
);
CREATE INDEX intent_manifests_request_idx
  ON intent_manifests (network_id, (value->>'requestId'));
CREATE INDEX intent_manifests_txid_idx
  ON intent_manifests (network_id, (value->>'txId'));
CREATE INDEX intent_manifests_vault_idx
  ON intent_manifests (network_id, (value->>'vaultId'));

-- Correlation columns on the audit stream (nullable: old rows predate
-- them, system events have no wallet actor, metadata events have no tx).
ALTER TABLE audit_events
  ADD COLUMN request_id    text,
  ADD COLUMN manifest_hash text,
  ADD COLUMN proposal_id   text,
  ADD COLUMN tx_id         text,
  ADD COLUMN actor_xonly   text;
CREATE INDEX audit_events_txid_idx
  ON audit_events (network_id, tx_id)         WHERE tx_id IS NOT NULL;
CREATE INDEX audit_events_request_idx
  ON audit_events (network_id, request_id)    WHERE request_id IS NOT NULL;
CREATE INDEX audit_events_manifest_idx
  ON audit_events (network_id, manifest_hash) WHERE manifest_hash IS NOT NULL;
CREATE INDEX audit_events_actor_idx
  ON audit_events (network_id, actor_xonly)   WHERE actor_xonly IS NOT NULL;

-- Vault-scoped walks over evidence keyed by txid.
CREATE INDEX receipts_vault_idx
  ON receipts (network_id, (value->>'vaultId'));
-- Request rows already have wallet_requests_vault_idx; the manifest
-- hash inside the envelope gets an expression index (jsonb field is
-- additive — no ALTER needed for the envelope itself):
CREATE INDEX wallet_requests_manifest_idx
  ON wallet_requests (network_id, (value->>'manifestHash'));
```

Size: 1 new table, 5 nullable columns on `audit_events`, 8 indexes.
Nothing existing is rewritten; `001`'s checksum discipline
(`server/src/migrate.js`) is untouched — `002` is a new numbered file.

### 5.2 `intent_manifests` record shape

```
{
  schema: "policyvault-intent-manifest-record/v1",
  manifestHash: <64-hex>,                  -- equals the row key
  manifest: <the FULL policyvault-intent-manifest/1 document>,
  verification: {                          -- verdict recorded at build/finalize
    verdict: "VERIFIED_EXACT" | "REFUSED",
    ok: boolean,
    checks: [{ id, ok }],
    failureCodes: [ ... ],
    verifiedAt: ISO timestamp,             -- time lives HERE, never in the manifest
    verifierBuild: <buildId string>        -- which release computed the verdict
  },
  requestId: uuid,
  proposalId: uuid | null,
  vaultId: <64-hex>, networkId: string, txId: <64-hex>
}
```

Notes:

- The manifest embeds the requested intent by schema, so storing the
  manifest stores the requested intent — no second copy to drift.
- A REFUSED manifest MAY be stored (it is evidence of a refused
  attempt, e.g. a policy-invalid adversarial test transaction exercised
  against staging, or a real defect); the verdict field says exactly
  what it is. A stored verdict is a **record of what the verifier said
  then** — any consumer that needs the truth NOW re-runs
  `verifyIntentManifest` on the stored manifest (pure, deterministic).
- Write discipline: `createExclusive` (INSERT … ON CONFLICT DO
  NOTHING), the same arbiter the claims use. Same hash ⇒ same manifest
  body (the hash is total over the body), so a lost race is benign
  idempotence. The record is never updated; a re-verification that
  disagrees is an integrity alarm to report, not a row to edit.

### 5.3 `003_governance_store.sql` (lands with Program B server wiring)

```sql
CREATE TABLE governance_proposals (
  network_id text  NOT NULL,
  key        text  NOT NULL,            -- proposalId (uuid)
  value      jsonb NOT NULL,            -- policyvault-governance-proposal/v1
                                        -- (+ proposalDigest cached; every
                                        --  consumer recomputes digest AND
                                        --  classification from content)
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (network_id, key)
);
CREATE INDEX governance_proposals_vault_idx
  ON governance_proposals (network_id, (value->>'vaultId'));
CREATE INDEX governance_proposals_digest_idx
  ON governance_proposals (network_id, (value->>'proposalDigest'));

-- One row per collected governance approval; create-only, append-only.
CREATE TABLE governance_approvals (
  network_id text  NOT NULL,
  key        text  NOT NULL,            -- "<proposalDigest>-<approverXOnly>"
  value      jsonb NOT NULL,            -- { schema, proposalId, proposalDigest,
                                        --   approverXOnly, approverAddress,
                                        --   signature, collectedAt }
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (network_id, key)         -- one approval per wallet per digest
);
```

Approval rows are re-verifiable by anyone from proposal content
(Schnorr over the domain-separated digest,
`policyvault-governance-proposal-digest/v1` — permanently disjoint from
`TransactionSigningHash`, so an approval can never be replayed as a
transaction signature). Tampering any proposal byte invalidates every
collected signature against the recomputed digest.

## 6. Retention, immutability, and the canonical-JSON commitment rule

- **Append-only:** `audit_events`, `intent_manifests`,
  `governance_approvals`. No application UPDATE/DELETE path exists or
  is added. (Optional deploy hardening, not required by this design:
  REVOKE UPDATE/DELETE on these tables from the app role.)
- **Write-once by key:** `receipts` (per txid; `persistReceipt` may
  idempotently rewrite the same content after a crash — content is a
  pure function of the proven effect), `intent_manifests` (create-only
  by hash), `governance_approvals` (create-only per wallet+digest).
- **Mutable workflow:** `wallet_requests` (state machine — but its
  correlation fields `requestId`, `txId`, `manifestHash`,
  `signerXOnly`, `predecessorStateId`, `successorStateId` are set-once
  facts within it), `vaults` (advanced only by proven chain
  reconciliation), claims (released per their proven lifecycle).
- **Retention:** indefinite by default — audit history is the product
  feature. Nothing here creates a purge path; any future retention
  policy is an owner decision and must never orphan a receipt from its
  request/manifest on the same network.
- **Canonical-JSON commitment (G-2 standing rule):** `manifestHash` is
  `sha256(domain || canonicalJsonStringify(body))` — a function of
  VALUES only, immune to PostgreSQL jsonb key reordering. The
  **mandatory read-side check**: whenever a stored manifest is loaded
  for display/re-verification, recompute `computeManifestHashV1` over
  the stored body and compare to the row key; mismatch ⇒ fail closed
  and raise an integrity alarm (it is tampering or a serialization
  defect, never acceptable drift). The implementation MUST land with a
  **live-PG round-trip regression test** (write manifest → read → hash
  equality → verdict re-derivation), because JSON-backend suites cannot
  catch jsonb representation defects — the exact lesson of Phase G-2.
  The same rule already governs `governanceProposalDigest`.

## 7. Writer integration points (postlaunch-rc; named, minimal)

| Point | File (postlaunch-rc) | Change |
|---|---|---|
| Build | `sdk/src/wallet-requests-v4.js buildWalletRequestV4` (+ genesis builder) | derive the requested-intent document + manifest from the REAL `buildV4Transaction` output, run `verifyIntentManifest`, refuse the request on a non-pass, store `intent_manifests` row (create-only), stamp `request.manifestHash` |
| Approval collection | `collectApprovalV4` | audit event `{action: "approval_collected", requestId, manifestHash, txId, actorXOnly: approverXOnly}` |
| Finalize/preflight | `finalizeWalletRequestV4` | existing PREFLIGHT_VERIFIED audit event gains `requestId`, `manifestHash`, `actorXOnly` (signer) |
| Submit/chain proof | `sdk/src/wallet-submit-v4.js` | CHAIN_VERIFIED / REJECTED audit events gain the same fields; receipt `proof` gains `manifestHash` |
| Reconcile | `sdk/src/reconcile-v4.js` | events gain `requestId`/`txId` where the claim carries them (`actorXOnly: null` — system actor) |
| Governance (future) | proposal/approval endpoints (Program B) | proposal lifecycle audit events carry `proposalId` (+ `proposalDigest` in the value); an executed proposal's wallet request stores `proposalId`, flowing into `intent_manifests.value.proposalId` |
| Store driver | `sdk/src/store.js PgStore.appendAudit` | lift `requestId`/`manifestHash`/`proposalId`/`txId`/`actorXOnly` from the record into the new nullable columns (exactly how `vaultId` is lifted today); JSON backend keeps the same fields inline in the JSONL record (backend parity — the correlation VALUES live in the record either way; columns are indexes, not truth) |

## 8. Query patterns

**"Show me everything about txid X"** (one network; the walk):

```
receipts[X]                    -> action, vaultId, proof.requestId, verifiedAt
wallet_requests[requestId]     -> signer identity + role, action/params source,
                                  predecessor/successor stateIds, accounting,
                                  approvalPackage (covenant approvals),
                                  manifestHash, request state history endpoint
intent_manifests[manifestHash] -> the requested intent (embedded), the FULL
                                  verified manifest, verification verdict
governance_proposals[proposalId?] + governance_approvals by digest
transition_claims / submission_claims (if still held: in-flight/unresolved)
audit_events WHERE tx_id = X ORDER BY id   -> the timeline
vaults[vaultId]                -> live state / lastTransition (chain-proven)
```

SQL sketches (all scoped `network_id = $1`):

```sql
SELECT value FROM receipts           WHERE network_id=$1 AND key=$2;
SELECT value FROM wallet_requests    WHERE network_id=$1 AND value->>'txId'=$2;
SELECT value FROM intent_manifests   WHERE network_id=$1 AND value->>'txId'=$2;
SELECT value FROM audit_events       WHERE network_id=$1 AND tx_id=$2 ORDER BY id;
```

Other first-class walks, each answered by one indexed predicate:

- by vault: `audit_events (network_id, vault_id)` (exists),
  `wallet_requests_vault_idx` (exists), `receipts_vault_idx`,
  `intent_manifests_vault_idx`, `governance_proposals_vault_idx`;
- by request: `audit_events_request_idx`, `intent_manifests_request_idx`;
- by manifest: `audit_events_manifest_idx`, `wallet_requests_manifest_idx`;
- by actor wallet: `audit_events_actor_idx` (plus
  `wallet_requests.value->>'signerXOnly'` for build-time attribution);
- by exact policy state: state IDs appear in requests
  (`predecessorStateId`/`successorStateId`), audit values
  (`oldStateId`/`newStateId`), claims, and manifests — a stateId query
  is a value scan today and stays one (acceptable: it is a forensic
  query, not a UI path; an index is a future option, §12).

API surface (postlaunch-rc): one read endpoint per walk (e.g.
`GET /audit/tx/:txId`), assembled server-side by the joins above,
tenancy-scoped exactly like the existing `/audit` route (covenant
participants only), self-hosted unrestricted as today.

## 9. Consistency semantics (honest)

- The audit write happens AFTER its mutation and is not atomic with it
  (ported contract, `sdk/src/audit.js`). A crash can lose the audit row
  while the mutation and its receipt survive. Correlation therefore
  treats `audit_events` as the *narrative* and
  receipts/manifests/requests as the *evidence*; a missing narrative
  row is a gap to display, never grounds to infer an event did not
  happen.
- `intent_manifests` is written BEFORE broadcast (at build), so a
  manifest row with no receipt means "built, never chain-proven" —
  exactly what it says. The receipt, written only after
  `proveExpectedEffectV4`, is the chain-proof marker; `vaults.live`
  advancing is the state-of-record marker. No correlation field ever
  implies more than its writer proved.

## 10. Backward compatibility (explicit)

- **Existing rows predate manifests.** Every correlation field is
  NULLABLE (columns) or absent (jsonb). Readers MUST render
  `manifest_hash IS NULL` as "recorded before intent-manifest
  correlation" — a plain historical fact.
- **Verification claims are NEVER backfilled.** No migration, tool, or
  reconciliation may synthesize an `intent_manifests` row, a
  `manifestHash`, or any "verified" rendering for a transaction that
  predates intent enforcement, even where the bytes could be
  reconstructed — a verification verdict is a record of a check that
  actually ran at the time, and claiming otherwise would collapse the
  claim ladder (a v1 manifest built after the fact from stored rows
  would also be a NEW document, not evidence about the past decision).
- Old audit events keep their role-string `actor`; new events carry
  role AND identity. Mixed streams are expected and the API says which
  vintage each row is (presence of the fields is the vintage marker;
  the record `schema` field versions any future shape change).
- The JSON (self-hosted) backend gains the same record fields with no
  layout change (JSONL values are schemaless); correlation QUERIES
  differ only in that the JSON driver filters in process, as `readAudit`
  does today.
- Unknown record schemas refuse on read (existing store discipline);
  a database whose `schema_migrations` is ahead of the build already
  fails closed (`assertSchemaCurrent`).

## 11. Privacy notes

- **There are no secrets to store.** No private keys, no seeds, no
  bearer tokens, no token hashes, no approval-signature *private*
  material (a Schnorr signature is a public artifact). This design adds
  none and forbids session-credential derivatives in audit records
  (§3.1).
- Explanations (core/explain) contain only what the manifest contains;
  the manifest contains only what the transaction reveals on-chain
  anyway (amounts, keys, states) plus the requested parameters that the
  transaction realizes. Storing manifests therefore widens no privacy
  surface beyond the existing request rows, which already carry the
  full build.
- Wallet x-only keys and addresses are public identifiers by design;
  correlating them across a tenant's own history is the product
  feature. Cross-tenant exposure is governed by the existing tenancy
  layer (participant-scoped 404-on-foreign) — the new endpoints reuse
  it unchanged.
- Residual (unchanged from `docs/hosted-threat-model.md`): a database
  compromise leaks metadata/history; it still cannot move funds,
  forge a verification verdict that survives the read-side re-hash +
  re-verify, or fabricate governance approvals that verify.

## 12. Open questions (owner / next phase)

1. Should `intent_manifests` also store REFUSED manifests from
   production flows (evidence of refused build attempts), or only
   verified ones, with refusals living solely in audit events? (Design
   allows both; default proposed: store both, verdict labeled.)
2. Is a `state_id` expression index warranted for forensic state walks,
   or is the value-scan acceptable long-term (§8)?
3. Per-session audit granularity: is the wallet identity enough
   (proposed), or add the surrogate `session_id` (§3.1)?
4. DB-role hardening (REVOKE UPDATE/DELETE on append-only tables) at
   deploy time — include in the postlaunch-rc runbook?
5. Should the hosted API expose `verifierBuild` in audit reads, or is
   that operator-only detail?

## 13. Claim labels

| Component | Claim |
|---|---|
| This correlation design (keys, mapping, migration sketch, rules) | DESIGNED |
| `002`/`003` migrations, writer changes, read endpoints, PG round-trip regressions | NOT IMPLEMENTED (postlaunch-rc lane; separate reviewed change) |

Nothing here is IMPLEMENTED, UNIT-TESTED, or beyond; no schema or
production file changed with this document.
