# PolicyVault Organization Model

**Organization roles are application metadata. They do not grant or
modify Kaspa covenant authority.**

On-chain authority is determined solely by the vault/covenant: the
template owner, the live state delegate (and `delegateActive`), the
paused flag, the recipient policy, spend cap, period budget, lifecycle
authorization, and — once v0.3 exists — covenant approvers. The
wallet-request pipeline authorizes signers against those consensus
identities only and never consults organization metadata. A member
labeled "Administrator" or "Treasurer" gains nothing on-chain; a real
owner or delegate loses nothing by having no member record.

## Data model (schema `policyvault-organization/v2`)

One durable JSON file per organization at `data/orgs/<orgId>.json`,
written with the same atomic `durable-json` primitives as funds-critical
state (temp file → fsync → rename → dir fsync):

- `orgId` — server-generated UUID; the stable identifier. The
  human-readable `name` is display metadata and never a security or
  lookup identifier; duplicate names are allowed.
- `name`, `createdAt`, `updatedAt` — validated text (non-empty, ≤120
  chars, control characters rejected).
- `version` — integer for optimistic concurrency. Every mutation
  (rename, member add/update/remove) requires the caller's
  `expectedVersion` to match and fails with `VERSION_CONFLICT` (HTTP
  409) otherwise. Competing writes are rejected loudly; there is no
  silent last-write-wins.
- `members[]` — `{ memberId (UUID), displayName, address|null,
  xOnlyPubkey|null, roles[], status ACTIVE|INACTIVE, note, createdAt,
  updatedAt }`. Wallet addresses go through the ONE shared
  address-identity boundary (`resolveAddressIdentity`), which stores
  both the canonical address and the derived x-only key used to match
  members against actual on-chain identities. Malformed, wrong-network,
  script-hash, or ECDSA addresses fail closed. Members without
  addresses are contact metadata and have no signing identity at all.
- `roles[]` — labels from a fixed allowlist (`owner`, `administrator`,
  `treasurer`, `approver`, `delegate`, `auditor`, `viewer`). Labels
  only. "Approver" is informational until v0.3 consensus approvals
  exist, and the UI says so.

## Vault assignments (schema `policyvault-org-assignments/v1`)

A single atomic file `data/orgs/assignments.json` mapping
`vaultId → { orgId, group, assignedAt }` with its own `version`. The map
key structurally enforces ONE canonical organization per vault; moving a
vault between organizations is a single atomic write. Assignment is
local PolicyVault metadata: it never touches vault ids, covenant ids,
owners, delegates, wallet authorization, or chain state. Unknown vault
ids are rejected; CLOSED vaults may stay assigned for history/audit.
`group` is an optional user-defined label (Payroll, Vendors, …) — it
does not enforce spend policy.

## Fail-closed corruption semantics

Unknown or legacy schemas are rejected, never silently upgraded or
repaired. A corrupt organization file surfaces in listings as
`{ orgId, error: "CORRUPT_METADATA" }`; a corrupt assignments file is
reported (`assignmentsError`) and vaults degrade to Unassigned. In every
case vault presentation and vault operations continue from the
independent vault truth (manifests/claims/requests): **organization
metadata failure never makes funds unreachable.**

## Audit

Metadata events (`org_created`, `org_renamed`, `member_added`,
`member_updated`, `member_removed`, `vault_assigned`,
`vault_assignment_updated`, `vault_moved`, `vault_unassigned`) are
appended to the same durable audit log as chain events, tagged
`kind: "metadata"`. The organization audit API returns this
organization's metadata events plus chain events for its assigned
vaults, each explicitly typed `APPLICATION METADATA EVENT` or
`CHAIN EVENT` — metadata events are never presented as blockchain
transactions.

## API

```
GET  /api/v1/organizations                       list (+corrupt markers, assignments, role labels)
POST /api/v1/organizations                       { name }
GET  /api/v1/organizations/:id                   organization + assigned vault ids
POST /api/v1/organizations/:id/rename            { name, expectedVersion }
GET  /api/v1/organizations/:id/members
POST /api/v1/organizations/:id/members           { displayName, address?, roles, note?, expectedVersion }
POST /api/v1/organizations/:id/members/:mid      partial update + expectedVersion
POST /api/v1/organizations/:id/members/:mid/remove   { expectedVersion }
GET  /api/v1/organizations/:id/vaults            presented vaults assigned to this org
POST /api/v1/organizations/:id/vaults            { vaultId, group?, expectedVersion }
POST /api/v1/organizations/:id/vaults/:vaultId/unassign  { expectedVersion }
GET  /api/v1/organizations/:id/audit             typed event stream
```

Every input is validated server-side; organization scoping is enforced
in the handler (org A's routes can never read or mutate org B's scoped
metadata — isolation is not a frontend filter). Funds-changing vault
operations continue exclusively through the existing wallet request
pipeline; the organization API offers no alternate mutation path.

## Dashboard

The organization selector (All vaults / individual organizations /
Unassigned) affects grouping and filtering only. The organization panel
shows Overview (counts and an informational KAS total across separate
on-chain vaults — never presented as a single account), Members (with
"Organization role" and "On-chain authority" as SEPARATE columns),
Delegates (visibility + navigation to the vault card's standard owner
actions), and Audit. Vault cards annotate the on-chain owner/delegate
with matching member names next to — never instead of — the actual
authority tags, and carry the assignment control with the disclaimer:
"Organization assignment is local PolicyVault metadata and does not
change on-chain ownership or permissions."

## Hosted multi-tenancy (Phase C, 2026-08-23)

In a hosted multi-user deployment (hosted authentication enabled),
organizations become tenant-scoped: each record carries a `tenantOwner`
(the creating wallet's x-only public key). The owner has full control;
a member with a wallet identity gets read access. Foreign or unclaimed
(pre-Phase-C / self-hosted) records are inaccessible in hosted mode
(fail closed), and denials return 404 to avoid confirming another
tenant's object exists. This is HOSTED APPLICATION authorization only —
the permanent rule stands unchanged: an organization role NEVER grants
Kaspa covenant authority (`docs/hosted-persistence.md`,
`server/src/tenancy.js`). In the self-hosted single-operator product
(hosted auth off) organizations behave exactly as before; tenancy is not
enforced.
