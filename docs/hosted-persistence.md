# PolicyVault Hosted Persistence & Multi-Tenancy (Phase C)

**Status: IMPLEMENTED (Phase C of the Hosted Web Architecture + Security
checkpoint, 2026-08-23).** Not deployed; no cloud resource provisioned.
Companion docs: `docs/hosted-architecture.md`, `docs/hosted-threat-model.md`.
Frozen covenants unchanged (v0.4 `8f87deab…`, v0.4.1 `421bfed8…`).

## The three independent layers

```
1. AUTHENTICATION      which wallet is this session?          (auth.js)
2. TENANCY AUTHZ       may this wallet see/edit this object?  (tenancy.js)
3. COVENANT AUTHORITY  did the right wallet SIGN the exact tx? (consensus)
```

Each is proven on its own. A session never implies (2)+ ; an
organization role never implies (3); a database row never implies (3).
`LOW-COST INITIAL SIZING != LOWER SECURITY SEMANTICS` (directive §2): the
owner's ~$100/month initial hosted budget is a deployment-sizing
constraint only and removes none of these boundaries.

## Backend abstraction (`sdk/src/store.js`)

Durable application state has one shape: one logical JSON object per key
within a closed set of categories (vault manifests, wallet requests,
transition claims, submission claims, receipts, organizations, org
assignments), plus an append-only audit stream. Two drivers implement
the SAME primitive interface (`read`, `write`, `createExclusive`,
`remove`, `listKeys`, `listValues`, `appendAudit`, `readAudit`):

- **json** — the released self-hosted backend: files under
  `config.dataRoot` with the proven `durable-json` fsync-rename
  discipline and `link()`/`EEXIST` create-only claims. It IS the
  pre-Phase-C code, relocated — behavior-identical by construction.
- **postgres** — the hosted backend: one table per category,
  `(network_id, key)` composite primary key, single-statement atomic
  operations. `INSERT … ON CONFLICT DO NOTHING` is the create-only claim
  arbiter — the exact `link()`/`EEXIST` equivalent.

Backend selection is validated configuration (`config.persistenceBackend`,
default `json`). Unknown values fail closed. **The postgres driver never
falls back to json and vice versa**: a hosted process that cannot open
its database refuses to operate (`openPgStore` is called at startup; a
lazy `getStore` on an unopened postgres config throws).

### Semantic port, not a redesign (directive §6)

Ported UNCHANGED and proven by the JSON↔PG equivalence suite
(`hosted-pg-integration.test.js`): claim-conflict classes, idempotent
submission claims, guarded release (only the matching `txId`, never
another attempt's claim), overwrite-vs-create-only, list shapes and
corrupt-record skipping, and the existing NON-atomic audit-after-mutation
ordering (a crash between a mutation and its audit line loses the audit
line, never the mutation — both backends). Chain truth stays
authoritative above both drivers: PostgreSQL is the durable application
source of truth, never a substitute for Kaspa chain proof. A
`SUBMITTED` row with no chain proof is never reported `CHAIN_VERIFIED`;
DB/chain disagreement fails closed to reconciliation.

## Schema & migrations

`server/migrations/NNN_*.sql` applied by `server/src/migrate.js`
(`runMigrations`): numbered, applied once each, inside a transaction
under an advisory lock (concurrent migrators serialize), with a
per-file checksum (a changed historical migration is a hard error). A
database whose recorded version is newer than the build fails closed
(`assertSchemaCurrent`, run at startup). Migrations are runnable
standalone (`node server/src/migrate.js`) separately from serving.

Tables: `vaults`, `wallet_requests`, `transition_claims`,
`submission_claims`, `receipts`, `organizations`, `org_assignments`
(all `(network_id, key)` PK + `jsonb value`), `audit_events`
(bigserial-ordered append log), `auth_challenges` / `auth_sessions`
(Phase B semantics on PG), `pv_meta` (write-once network stamp),
`schema_migrations`. UNIQUE primary keys are the race arbiters
(directive §20). No wallet key material exists in any table.

### Network is part of tenant identity (directive §11)

Two guards: the write-once `pv_meta.network` stamp makes a database
belong to ONE network (a mainnet process refuses a testnet-stamped DB,
the `.pv-network` analog), AND every row's `(network_id, key)` composite
key keeps same-id objects on different networks distinct. A testnet
session can never read mainnet tenant state and vice versa — proven at
the row level and the process level.

## Tenancy model (`server/src/tenancy.js`)

**Tenant root = an authenticated wallet identity (its x-only pubkey).**
IDs are authoritative; a human-readable name never grants access.
Default deny.

- **Vault access derives from the covenant itself.** A vault's
  participants are the wallets the covenant already binds — owner /
  agents / approvers (v0.4.1), owner / delegate (v0.2). Read access =
  any participant; owner-role (metadata write, reconcile trigger) = the
  template owner only. Hosted vault visibility therefore EXACTLY tracks
  on-chain participation and cannot be widened by hosted metadata.
- **Organization access uses an explicit stored owner** (`tenantOwner`,
  the creating wallet's x-only). The owner has full control; a member
  with a wallet identity gets READ. Pre-Phase-C / self-hosted org
  records have no `tenantOwner` — treated as unclaimed/legacy: fully
  usable in self-hosted mode, inaccessible in hosted mode (fail closed).
- **Denials return 404, not 403**, for foreign objects — the API never
  confirms another tenant's object exists (directive §14, no existence
  oracle). A known participant lacking the higher owner role gets 403.

Enforcement is server-side on the Phase B principal
(`requestAuthPrincipal` — the ONLY hosted identity source; request
bodies, query params, and headers are never trusted as identity). With
`config.tenancyEnforced` false (self-hosted, auth off) every gate
allows — the released single-operator product is unchanged.

### Organization role ≠ covenant authority (directive §13)

An application member labeled `owner` / `approver` / `manager` / `CFO`
gains only the documented HOSTED APPLICATION read/permission. It never
becomes Kaspa covenant authority: covenant operations keep the exact
existing owner/agent/approver signature checks over frozen bytes. Proven
in the tenant matrix (an org-`owner`-labeled member cannot even mutate
the org, let alone sign).

## What a compromise yields (directive §24/§36)

- **Stolen session store / bearer token:** at most the authenticated
  wallet's hosted tenancy authority (see/edit its own metadata). ZERO
  wallet private keys, ZERO ability to forge a covenant signature. A
  session is not funds authority (distinct signing domains; §Phase B).
- **Fully compromised PostgreSQL:** serious — the attacker can corrupt
  hosted metadata, forge application roles, change displayed data, deny
  service, damage audit integrity. But **DB compromise ≠ private-key
  compromise**: no signing key exists in the database, so the attacker
  cannot produce a valid covenant transaction. The later layers that
  still stop funds-authority escalation are the wallet review + signature,
  signed-package binding, server validation, covenant consensus, and
  chain reconciliation. Tampered "successor" metadata fails reconcile
  against chain truth.

## Connection & operations

`pg` (node-postgres), a bounded pool (`pgPoolMax`, default 10,
validated 1..100; pool exhaustion fails safely, never corrupts state).
TLS is the hosted default (`pg.ssl`); the explicit no-TLS override is
local-testing only and refused on mainnet. Credentials come from
validated config/env and are never logged. Least-privilege intent: the
runtime role needs only DML on the app tables (no superuser / CREATE
DATABASE / role admin); migrations may use a separately privileged
context. `POLICYVAULT_HOSTED_DEV_OPEN` permits an explicit single-user
open PG instance for local development (never on mainnet); a hosted
multi-user PG deployment with authentication disabled is refused
outright (directive §44). No existing JSON data is destructively
migrated — an import utility, if built, reads copies into an isolated
database (directive §26).

## Test layers (all real PostgreSQL where marked; self-skip without it)

- `hosted-pg-integration.test.js` — migrations, per-category CRUD, the
  UNIQUE claim arbiter, network-composite isolation, transaction
  rollback (all-or-nothing), restart durability, and JSON↔PG behavioral
  equivalence.
- `hosted-pg-auth.test.js` — Phase B auth on PG: cross-process
  single-use challenge (two service instances / one DB → one success),
  concurrent-verify CAS, session/revocation/expiry survive restart,
  hash-only token storage, UNIQUE nonce.
- `hosted-tenancy.test.js` — the multi-user hostile matrix over REAL
  HTTP + hosted auth + PG with real foreign ids (A/B/C wallets): org and
  vault read/mutate isolation, body-cannot-rebind-identity,
  unauthenticated refusal, vault→org assignment isolation, org-role ≠
  covenant authority, session non-transfer, plus positive controls.
- `hosted-config-matrix.test.js` — fail-closed config interlocks
  (backend selection, dangerous hosted combos, TLS/cookie/mainnet
  guards, pool bounds, no-lazy-dial).

Self-hosted JSON mode remains fully supported and unchanged — the
served-app acceptance runs green with auth disabled and the JSON backend.
