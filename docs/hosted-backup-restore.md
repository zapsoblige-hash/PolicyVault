# Hosted Backup & Disaster Recovery (Phase E)

**Status: REAL exercise PERFORMED on TESTNET-10 (Hosted Web Architecture
+ Security checkpoint, Phase E, 2026-08-24). PASS.** A real PostgreSQL
backup was created, restored into new isolated databases, an application
booted against the restored state, logical state was verified against the
backup point, and — the crown-jewel DR rule — chain truth was proven to
remain authoritative after restore (no duplicate submission, no ambiguous
claim released). Driver: `tools/staging-backup-restore.js`. Evidence
values below are from that live run.

## 1. The one rule that dominates hosted DR

```
A DATABASE RESTORE DOES NOT ROLL BACK THE KASPA BLOCKDAG.
```

PostgreSQL is the durable APPLICATION source of truth (requests, claims,
receipts, manifests, metadata). It is NOT the funds-security boundary —
Kaspa consensus is. Restoring an older database therefore produces a
view that may be STALE relative to the chain, and the recovery path is
never "the DB says old state, so broadcast again". It is always: verify
chain → reconcile the exact frozen tx/outpoint → advance safely, or fail
closed. Phase E proves this holds against real chain truth.

## 2. Backup method

- **Tool:** `pg_dump -Fc` (PostgreSQL custom format), `--no-owner
  --no-privileges`. Custom format restores selectively into a
  differently-named isolated database via `pg_restore`.
- **Production:** DigitalOcean Managed PostgreSQL provides automated
  daily backups + point-in-time recovery as the PROVIDER capability; the
  APPLICATION restore procedure proven here is what turns a provider
  backup into a verified running system. The two are distinct and both
  matter (directive §38/§50).
- **What is recorded per backup (no secrets):** method, timestamp, source
  database identity, schema version, network stamp, byte size, SHA-256.
- **Backup security:** backups carry application metadata (wallet
  addresses, org/member/request/activity data) but ZERO key material —
  no signing key exists in any table by construction, so a stolen backup
  cannot spend vault funds (it exposes metadata/activity privacy only,
  documented honestly). Backups are never committed, never placed in an
  image, never in a public archive; local exercise backups are deleted
  after evidence and `backups/` is gitignored.

## 3. The live exercise (real testnet-10 chain truth)

Driver: a chain-proven v0.4.1 vault is created in a live PostgreSQL
database, then two real backups are taken around a real covenant spend,
and the spend is confirmed on chain so the first backup becomes provably
stale. Representative run (2026-08-24):

| Backup | Point | Bytes | SHA-256 (prefix) | Manifest | Claims |
|---|---|---|---|---|---|
| B1 | S0, no pending transition | 22,289 | `473d1671e88ee379…` | genesis outpoint | 0 |
| B2 | S0 + broadcast tx + ambiguous claim | 27,594 | `a7635e7a9c165b17…` | still S0 | 1 |

The spend `31c9238208e5395e446cdb30dadcebb0927823e2fed44db43405e0577d86bd98`
was broadcast then confirmed; the LIVE database reconciled to S1
(successor `…d86bd98:1`). Both backups predate that advance, so restoring
either yields a database whose recorded manifest is at S0 while the chain
is at S1.

## 4. Restore = new isolated database + app boot + logical verify (§32–§34)

Each backup is restored with `pg_restore` into a NEW, EMPTY, DISTINCTLY
NAMED database (never in place, never row-copies, never a mock). An
application config is pointed at the restored database and opened through
the exact production `openPgStore` path — which independently gates the
restore: schema exactly current (`assertSchemaCurrent`) + write-once
network stamp match. A deterministic LOGICAL SNAPSHOT (vault/request/
claim/submission-claim/receipt/organization/member/assignment identities
+ audit and session counts + schema version + network stamp) is compared
against the backup point.

- **B2 restored → logical state EXACTLY matches the B2 snapshot.**
- **B1 restored → logical state EXACTLY matches the B1 snapshot.**

Physical PostgreSQL details need not be byte-identical; the LOGICAL state
matched the backup point in both cases.

## 5. Chain truth after restore (§35–§37) — the funds-safety core

**B2 (ambiguous claim) restored, then reconciled against chain:** the
restored database is at S0 with a durable ambiguous transition/submission
claim for a tx that the app (at backup time) did not yet know had
confirmed. Reconcile-v4 against real chain truth **PROVED the exact
successor and ADVANCED to the SAME broadcast tx**
(`31c9238208…`) — it did NOT broadcast a new transaction
(`duplicateBroadcast: false`, §36), and the ambiguous claim was resolved
by chain proof, never force-released while unresolved (§37). Reconcile
has no broadcast path at all; advancement requires the exact expected
outpoint+value+txid proven on chain.

**B1 (stale, no claim) restored, then reconciled:** the restored database
is at S0 with no pending claim, but the chain has consumed S0 (the spend
mined). Reconcile-v4 **failed closed → `UNKNOWN`**: it did not resubmit
(there is no request to resubmit), and did not fabricate a successor —
it recorded `TERMINATED_UNKNOWN` and stopped (§35). Chain truth remained
authoritative; the older restored database was never treated as
permission to act.

## 6. Restore failure cases (§40) — all fail closed

- **Wrong-network restored database:** a database whose `pv_meta`
  network stamp is `mainnet` opened by a testnet process is REFUSED
  (`STORE_NETWORK_MISMATCH` / "belongs to network …") — the operator
  "restored the wrong backup" mistake cannot serve foreign-network
  tenant state.
- **Corrupt / truncated backup:** a half-truncated archive is REFUSED —
  `pg_restore` errors on the damaged archive and the incomplete schema
  fails `assertSchemaCurrent`; the app never serves partial tenant data.
- **Future schema / missing migration:** covered by
  `sdk/test/hosted-deployment.test.js` (a database newer than the build,
  or not yet migrated, refuses to serve).

## 7. RPO / RTO / retention (achievable with the ~$100/mo launch topology)

These are honest, defensible LOW-ADOPTION targets — not aspirational
enterprise numbers the launch budget cannot deliver (§38/§65). Funds
safety is covenant-based and independent of these service-availability
targets.

| Target | Value | Basis |
|---|---|---|
| **RPO** | ≤ 24 h (worst case), typically minutes | Managed-PG automated daily backup as the floor; PITR narrows to minutes where the plan provides WAL retention. A lost window costs at most recent METADATA — chain truth + durable receipts reconstruct funds state via reconcile. |
| **RTO** | ≤ 4 h, operator-driven | provision/restore a managed-PG backup + boot a fresh app instance + readiness-gated cutover. Single-operator, no HA automation at launch. |
| **Retention** | ≥ 7 daily + a pre-upgrade snapshot before each schema migration | enough to recover from a bad deploy or late-detected corruption without unbounded storage cost. |
| **Restore procedure** | §4–§5 above, encoded in `tools/staging-backup-restore.js` and the hosted runbook | the APPLICATION restore is what is tested; the provider backup is the capability it consumes. |

Explicitly NOT claimed: sub-minute RTO, zero-data-loss RPO, or
multi-region automatic failover — the launch topology does not provide
them, so they are not promised (§65).

## 8. What backup/restore can and cannot expose (compromise recheck)

- **Stolen backup:** exposes metadata/organization/activity/request data
  and (depending on the backup point) session/challenge rows — a real,
  documented PRIVACY consequence. It exposes ZERO signing keys and cannot
  authorize a covenant transition. DB + backups contain no wallet private
  keys because the application never holds them.
- **Restore cannot escalate authority:** a restored database is still
  just application state; covenant operations continue to require the
  right wallet signature over frozen bytes, and reconcile re-proves
  against chain. No deployment or DR component gained any signing
  authority (directive §52 verified).

## Production procedure pointer (Phase H, 2026-08-25)

The PRODUCTION backup/DR procedure (DigitalOcean Managed PostgreSQL
daily backups + PITR, pre-migration logical snapshots, the
restore-to-isolation-first + reconcile-first sequence, RPO/RTO targets,
and the clean-initialization rule that production mainnet state never
imports staging/testnet data) is specified in
`docs/hosted-production-runbook.md` §7.1/§14. The semantics exercised in
this document carry forward unchanged — CHAIN TRUTH IS AUTHORITATIVE;
a restored database is a hypothesis to reconcile, never a license to
rebroadcast or release claims.
