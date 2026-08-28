# Audit Hash Chain (fullscale surface 17 residual)

Status: IMPLEMENTED + UNIT/API-TESTED (JSON + live-PG suites:
`sdk/test/postlaunch-audit-chain.test.js`,
`sdk/test/postlaunch-audit-chain-pg.test.js`). Closes the
`fullscale-gap-analysis.md` surface-17 gap "audit log not hash-chained".
Code: `server/src/audit-chain.js` (+ `server/src/audit.js` wiring),
migration `server/migrations/008_audit_chain.sql`, routes in
`server/src/api.js`.

## 1. What it is — and is not

Every audit record written through the SERVER audit module
(`server/src/audit.js`) now carries an embedded, tamper-evident chain
envelope. The chain makes silent **modification, insertion, reordering,
or interior deletion** of those records detectable by anyone allowed to
call the verification endpoint.

The chain is an integrity control over the HOSTED AUDIT COPY. It is
**not** authority of any kind: audit rows describe; the Kaspa covenant
decides (`audit-correlation-spec.md` §1). A broken chain is an alarm
about the hosted database/file, never a statement about chain state.

## 2. Record format

Each chained record gains one additive field:

```json
"chain": {
  "v": "policyvault-audit-chain/v1",
  "seq": 42,
  "nonce": "<16 random bytes, hex>",
  "prevHash": "<64-hex>",
  "recordHash": "<64-hex>"
}
```

- `recordHash = SHA-256( canonicalJsonStringify({ content, nonce,
  prevHash, seq }) )` where `content` is the record **without** its
  `chain` envelope, in **storage-normal form** (BigInt→string, undefined
  dropped — exactly the value both persistence backends put at rest).
- `canonicalJsonStringify` is the SDK's G-2 serializer
  (`sdk/src/canonical-json`, re-exported by the SDK public entry). It is
  key-order-independent, so a PostgreSQL **jsonb round trip — which
  reorders object keys — re-verifies exactly** (the Phase G-2 defect
  class; proven by a live-PG regression that writes, reloads, and
  re-verifies).
- `prevHash` of seq 1 is the deterministic genesis anchor:
  `SHA-256(canonicalJson({ genesis: "policyvault-audit-chain/v1",
  networkId }))`.
- `nonce` (per-record random) exists so record **hashes can be exposed
  to other tenants without leaking content**: without it, a hash of a
  semi-predictable record could confirm a guessed foreign record's exact
  content. With it, hashes are non-confirmable; record content remains
  behind the existing tenant-scoped audit reads.

## 3. Durable head anchor

`audit_chain_state` (migration 008; platform-store category
`AUDIT_CHAIN`, key `head`) stores the append head `{ seq, recordHash }`.
The **records are the verification truth**; the anchor serves two
purposes: O(1) appends after process init, and a **tail-truncation
tripwire** — if the anchor claims seq N but the newest stored chained
record is M < N, verification reports `TAIL_TRUNCATED` (a plain hash
chain cannot otherwise see its tail cut off). The anchor write is not
atomic with the record append; a crash between them leaves the anchor
one behind, and init recovers it from the records (the larger seq wins).
For stronger truncation evidence operators can externally archive the
`head` from `GET /audit/chain` on any schedule; nothing in-tree can
protect the audit copy from an adversary who controls the entire store
AND every external copy — stated honestly.

## 4. Stream partitioning (deliberate)

**One chain per (networkId, data root)** — the same shape the audit
stream itself has always had. Per-tenant chains were rejected because a
record's tenant visibility is DERIVED state (covenant participation,
org membership) that changes over time, while chain membership must be
immutable. Cross-tenant safety is provided at the verification surface
instead: responses carry **structure only** (seqs, hashes, counts,
reasons — never record content), and the per-record nonce (§2) makes
hashes non-confirmable, so any authenticated tenant may verify the
shared stream's integrity without learning anyone else's records.

## 5. Coverage — chained vs unchained (honest compat)

Chained: every record appended through `server/src/audit.js` — api.js
routes, governance.js, risk.js, intent-records.js, org-controls,
agent-suspension and notification-rule metadata.

**Unchained (reported, never claimed chained):**
1. Records written **before this deployment** (pre-chain history).
2. Records written by **sdk-internal audit paths** that do not flow
   through the server module: wallet-submit/reconcile chain proofs,
   sdk organization metadata, create/spend/lifecycle/recover flows, CLI
   tools. `sdk/src/**` is owned by another lane this wave; closing this
   is a one-line adoption of `appendChainedAudit` inside
   `sdk/src/audit.js` (the chain module is layer-neutral by design).
   Until then these remain authentic-but-unchained and are counted in
   every verification response (`records.unchained`).

The verification response's `notice` states this verbatim. `VALID`
always means "the CHAINED subsequence is intact", never more.

## 6. Append semantics

- **Fail-safe:** chain bookkeeping failure (anchor unavailable,
  canonicalization refusal, `chain` field collision) falls back to the
  exact pre-chain UNCHAINED append — the chain never costs a mutation
  its audit line. Only a failure of the audit store itself still
  propagates (pre-existing behavior). Fallbacks are counted in-process
  (`chainSkipCount`) and logged.
- **Serialization:** chained appends serialize on an in-process mutex
  per (data root, network). The released deployment shape is ONE server
  process per data root (single-replica launch pin; the events-store
  JSON seq counter and process-local rate limiter already assume it). A
  misconfigured second writer produces duplicate/out-of-order seqs that
  verification reports as `SEQ_DUPLICATE` — detected, never silent.
- Head recovery at init: records win when ahead of the anchor (crash
  window); the anchor wins when ahead of the records, preserving the
  seq gap as permanent evidence of loss.

## 7. Verification API

- `GET /api/v1/audit/chain` — status: anchor, genesis anchor, record
  counts (total / chained / unchained). No walk.
- `GET /api/v1/audit/chain/verify?fromSeq=&toSeq=&limit=` — walks the
  chained subsequence in append order and reports
  `VALID | BROKEN | EMPTY` with `checked {fromSeq, toSeq, count}`,
  `broken {atSeq, reason}` and reasons:
  `RECORD_TAMPERED` (any persisted content field changed),
  `LINK_BROKEN` (prevHash mismatch), `SEQ_GAP` (record deleted),
  `SEQ_DUPLICATE` (second writer / re-insertion), `CHAIN_MALFORMED`
  (envelope shape destroyed; atSeq = walk position), `TAIL_TRUNCATED`
  (anchor ahead of newest record), `PREV_RECORD_MISSING` (window
  predecessor absent). Walks are bounded (default 5000, max 20000
  records per call); `complete:false` + `nextFromSeq` continue. The
  authoritative check is the full walk from seq 1; ranged walks are
  windows into it.
- Gating: hosted mode requires an authenticated principal; machine
  credentials need the deny-by-default `read:audit` scope (scopes.js).
  Self-hosted single-operator mode is open like every other route.

## 8. Tests

`postlaunch-audit-chain.test.js` (JSON backend): chain builds across
real api.handle governance/org-controls/suspension/notification flows;
genesis determinism; single-byte tamper of a persisted content field →
`RECORD_TAMPERED` at the right seq; interior deletion → `SEQ_GAP`;
prevHash flip → `LINK_BROKEN`; unchained sdk-direct records counted and
never claimed; endpoint gating (401 unauthenticated hosted, 403 missing
scope, foreign tenant may verify but sees structure only); SDK-public-
entry identity of `canonicalJsonStringify`.
`postlaunch-audit-chain-pg.test.js` (live PG): migration 008 shapes;
appends against real PG; **jsonb round-trip re-verification**; SQL
tamper via `jsonb_set` → `RECORD_TAMPERED` at the right seq; DELETE →
`SEQ_GAP`; JSON/PG parity of hashes for identical content.
