# Authorization-boundary inventory (hosted API) — GATE 2

GENERATED from `server/src/authorization-boundary-inventory.json` by
`tools/render-authorization-inventory.js`; do not edit by hand. Verified
mechanically by `sdk/test/authorization-boundary-inventory.test.js`.

## Why this exists

The rc11 internal security review (2026-09-04, finding F-04) found three
hosted route families that resolved — or never received — the request
principal and then discarded it. Every green floor that "covered tenancy"
measured only the v0.4 family. **Green floors measure what was tested.**
This inventory makes the authorization boundary a checked artifact: a new
route family, a scope drift, a missing principal, a bypassed tenancy
resolver, a tenant-owned mutation without a gate, a family without a
foreign-tenant hostile probe, or a `void principal` discard now FAILS the
floor instead of passing silently.

## Column meanings

| column | meaning |
|---|---|
| resource class | **public** — no authority; **global** — authenticated aggregate or chain fact; not a tenant-owned object; **identity** — machine identities of the creating wallet; **dev-hook** — development signer hooks (production-disabled); **vault** — vault manifest / per-vault records; **request** — wallet request records; **org-root** — on-chain organizational root records and their requests; **organization** — off-chain organization metadata (never covenant authority); **creator-owned** — records owned by the creating principal (webhooks, notification rules, events) |
| principal type | **none** — public route; no principal; **optional** — principal resolved when presented; route serves no tenant-owned object; **session-or-machine** — wallet session cookie / bearer session or a pvmk_ machine credential (deny-by-default scopes); **session-only** — wallet session only; never machine-reachable |
| auth gate | the symbol (in the named file) that resolves/requires the principal |
| tenancy resolver | the durable-fact resolver that scopes the object to the principal (`server/src/tenancy.js` export or a file-local gate) |
| mutation gate | the additional rule for state-changing routes |
| machine scope | `requiredScopesFor` result: `pvmk_` credentials need every listed scope; `null` = never machine-reachable |
| hostile evidence | the test that exercises this path with a FOREIGN principal (GATE 1) |

## Standing rules for contributors

1. Every new hosted route gets a row here BEFORE it ships; the test fails otherwise.
2. A route that receives `principal`/`ctx` must USE it; `void principal` is a lint failure unless listed under `documentedExceptions` with a reason.
3. Authority derives only from durable covenant facts (vault manifest participants, org-root active owner slots + pinned successor, request creator/signer) — never from hosted organization roles, request bodies, or headers.
4. Foreign objects answer the non-oracle 404; a known participant without the required authority gets 403; a foreign caller persists or locks NOTHING.
5. Every tenant-owned family carries a foreign-tenant hostile probe (foreign LIST/GET/CREATE/MUTATE refused, same-tenant accepted).

## Documented exceptions

None.

## Routes

### /health

| method | path | resource class | principal | auth gate (file) | tenancy resolver | mutation gate | machine scope | hostile evidence | note |
|---|---|---|---|---|---|---|---|---|---|
| GET | `/health` | public | none | `isPublicRoute` (server/src/scopes.js) | n/a | n/a | (none — public) | — |  |
| GET | `/health/ready` | public | none | `isPublicRoute` (server/src/scopes.js) | n/a | n/a | (none — public) | — |  |

### /support

| method | path | resource class | principal | auth gate (file) | tenancy resolver | mutation gate | machine scope | hostile evidence | note |
|---|---|---|---|---|---|---|---|---|---|
| GET | `/support` | public | none | `isPublicRoute` (server/src/scopes.js) | n/a | n/a | (none — public) | — |  |

### /capabilities

| method | path | resource class | principal | auth gate (file) | tenancy resolver | mutation gate | machine scope | hostile evidence | note |
|---|---|---|---|---|---|---|---|---|---|
| GET | `/capabilities` | public | optional | `isPublicRoute` (server/src/scopes.js) | n/a | n/a | (none — public) | — | capabilities narrows to the presented principal's scopes when one is presented |

### /auth

| method | path | resource class | principal | auth gate (file) | tenancy resolver | mutation gate | machine scope | hostile evidence | note |
|---|---|---|---|---|---|---|---|---|---|
| POST | `/auth/challenge` | public | none | `isPublicRoute` (server/src/scopes.js) | n/a | n/a | (none — public) | — |  |
| POST | `/auth/verify` | public | none | `isPublicRoute` (server/src/scopes.js) | n/a | n/a | (none — public) | — |  |
| GET | `/auth/session` | public | none | `isPublicRoute` (server/src/scopes.js) | n/a | n/a | (none — public) | — |  |
| POST | `/auth/logout` | public | none | `isPublicRoute` (server/src/scopes.js) | n/a | n/a | (none — public) | — |  |

### /identity

| method | path | resource class | principal | auth gate (file) | tenancy resolver | mutation gate | machine scope | hostile evidence | note |
|---|---|---|---|---|---|---|---|---|---|
| POST | `/identity/resolve-address` | public | none | `isPublicRoute` (server/src/scopes.js) | n/a | n/a | (none — public) | — |  |

### /metrics

| method | path | resource class | principal | auth gate (file) | tenancy resolver | mutation gate | machine scope | hostile evidence | note |
|---|---|---|---|---|---|---|---|---|---|
| GET | `/metrics` | global | session-or-machine | `requestAuthPrincipal` (server/src/api.js) | n/a | n/a | `read:metrics` | `sdk/test/hosted-foreign-tenant-matrix.test.js` |  |

### /mcp-telemetry

| method | path | resource class | principal | auth gate (file) | tenancy resolver | mutation gate | machine scope | hostile evidence | note |
|---|---|---|---|---|---|---|---|---|---|
| GET | `/mcp-telemetry` | global | session-or-machine | `requestAuthPrincipal` (server/src/api.js) | n/a | n/a | `read:metrics` | `sdk/test/hosted-foreign-tenant-matrix.test.js` | feature-gated (POLICYVAULT_MCP_TELEMETRY); disabled -> 404 MCP_TELEMETRY_DISABLED for every caller; enabled -> principal required |

### /network

| method | path | resource class | principal | auth gate (file) | tenancy resolver | mutation gate | machine scope | hostile evidence | note |
|---|---|---|---|---|---|---|---|---|---|
| GET | `/network/status` | global | optional | `connectVerified` (server/src/api.js) | n/a | n/a | `read:network` | — | node-verified network identity; no tenant data; machine credentials need read:network |

### /wallet/fuel

| method | path | resource class | principal | auth gate (file) | tenancy resolver | mutation gate | machine scope | hostile evidence | note |
|---|---|---|---|---|---|---|---|---|---|
| GET | `/wallet/fuel/:address` | global | optional | `connectVerified` (server/src/api.js) | n/a | n/a | `read:network` | — | chain UTXO lookup for a caller-supplied address (public chain data) |

### /audit

| method | path | resource class | principal | auth gate (file) | tenancy resolver | mutation gate | machine scope | hostile evidence | note |
|---|---|---|---|---|---|---|---|---|---|
| GET | `/audit/chain` | global | session-or-machine | `requestAuthPrincipal` (server/src/api.js) | n/a | n/a | `read:audit` | `sdk/test/postlaunch-audit-chain.test.js` | tamper-evident chain head; no per-tenant record body |
| GET | `/audit/chain/verify` | global | session-or-machine | `requestAuthPrincipal` (server/src/api.js) | n/a | n/a | `read:audit` | `sdk/test/postlaunch-audit-chain.test.js` |  |
| GET | `/audit` | vault | session-or-machine | `requestAuthPrincipal` (server/src/api.js) | vaultAccessAllowed(read) filter | n/a | `read:audit` | `sdk/test/hosted-phase-f-hostile.test.js` |  |

### /identities

| method | path | resource class | principal | auth gate (file) | tenancy resolver | mutation gate | machine scope | hostile evidence | note |
|---|---|---|---|---|---|---|---|---|---|
| POST | `/identities` | identity | session-only | `requestAuthPrincipal` (server/src/api.js) | listIdentitiesForCreator / getIdentityScoped (creatorXOnly) + requireOrgAccess(owner) when orgId is present | requireOrgAccess(owner) when orgId is present, before createIdentity and any event (a malformed orgId is 422 ORG_ID_INVALID, a missing or foreign organization the non-oracle 404 ORG_NOT_FOUND, a member who is not the owner 403 ORG_FORBIDDEN; nothing written) + createIdentity (creatorXOnly is the session wallet's xOnlyPubkey) | — | `sdk/test/postlaunch-machine-identity-server.test.js` | RC45 R1-02 (S-02): row corrected to the code; the mutation gate is the one machine-identity function this route calls (createIdentity), not all three \| RC45 R1-11 (OBS-R1-02-A; PA-R1-01 r1): an orgId routes the identity's events to that organization's readers, so naming one requires the organization owner; absent or null orgId is unchanged; the tag confers no authority; hostile evidence for the gate: sdk/test/rc45-r1-11-identity-org-scope.test.js |
| GET | `/identities` | identity | session-only | `requestAuthPrincipal` (server/src/api.js) | listIdentitiesForCreator / getIdentityScoped (creatorXOnly) | n/a | — | `sdk/test/postlaunch-machine-identity-server.test.js` |  |
| GET | `/identities/:id` | identity | session-only | `requestAuthPrincipal` (server/src/api.js) | listIdentitiesForCreator / getIdentityScoped (creatorXOnly) | n/a | — | `sdk/test/postlaunch-machine-identity-server.test.js` |  |
| POST | `/identities/:id/credentials` | identity | session-only | `requestAuthPrincipal` (server/src/api.js) | listIdentitiesForCreator / getIdentityScoped (creatorXOnly) | mintCredential (creatorXOnly; a foreign identity is the non-oracle 404 MACHINE_IDENTITY_NOT_FOUND) | — | `sdk/test/postlaunch-machine-identity-server.test.js` | RC45 R1-02 (S-02): row corrected to the code; the mutation gate is the one machine-identity function this route calls (mintCredential), not all three |
| POST | `/identities/:id/credentials/:cid/revoke` | identity | session-only | `requestAuthPrincipal` (server/src/api.js) | listIdentitiesForCreator / getIdentityScoped (creatorXOnly) | revokeCredential (creatorXOnly; a foreign identity is the non-oracle 404 MACHINE_IDENTITY_NOT_FOUND) | — | `sdk/test/postlaunch-machine-identity-server.test.js` | RC45 R1-02 (S-02): row corrected to the code; the mutation gate is the one machine-identity function this route calls (revokeCredential), not all three |
| POST | `/identities/:id/revoke` | identity | session-only | `requestAuthPrincipal` (server/src/api.js) | listIdentitiesForCreator / getIdentityScoped (creatorXOnly) | revokeIdentity (creatorXOnly; a foreign identity is the non-oracle 404 MACHINE_IDENTITY_NOT_FOUND); after it persisted, identity.revoked carries the stored orgId only when orgAccessAllowed(owner) holds for the revoker on that live organization (otherwise omitted: creator-only visibility; the check never throws) | — | `sdk/test/postlaunch-machine-identity-server.test.js` | RC45 R1-02 (S-02): row corrected to the code; the mutation gate is the one machine-identity function this route calls (revokeIdentity), not all three \| RC45 R1-11 (OBS-R1-02-A; PA-R1-01 r1 C1): the event rule only; the revocation stays creator-scoped; hostile evidence for the event rule: sdk/test/rc45-r1-11-identity-org-scope.test.js |

### /wallet/dev-accounts

| method | path | resource class | principal | auth gate (file) | tenancy resolver | mutation gate | machine scope | hostile evidence | note |
|---|---|---|---|---|---|---|---|---|---|
| GET | `/wallet/dev-accounts` | dev-hook | session-only | `devSignerEnabled` (server/src/api.js) | devSignerEnabled (production-disabled; session-only) | n/a | — | `sdk/test/hosted-foreign-tenant-matrix.test.js` | never machine-reachable; production-disabled |

### /wallet/dev-sign

| method | path | resource class | principal | auth gate (file) | tenancy resolver | mutation gate | machine scope | hostile evidence | note |
|---|---|---|---|---|---|---|---|---|---|
| POST | `/wallet/dev-sign` | dev-hook | session-only | `devSignerEnabled` (server/src/api.js) | devSignerEnabled (production-disabled; session-only) | devSignerEnabled | — | `sdk/test/hosted-foreign-tenant-matrix.test.js` | never machine-reachable; production-disabled |

### /vaults

| method | path | resource class | principal | auth gate (file) | tenancy resolver | mutation gate | machine scope | hostile evidence | note |
|---|---|---|---|---|---|---|---|---|---|
| GET | `/vaults` | vault | session-or-machine | `requestAuthPrincipal` (server/src/api.js) | vaultAccessAllowed(read) filter | n/a | `read:vaults` | `sdk/test/hosted-foreign-tenant-matrix.test.js` | principal FIRST; caller-visible records of another generation are not part of this family's listing: loadVaultOrNull (never 500) — rc12 review R-01 |
| GET | `/vaults/:id` | vault | session-or-machine | `requestAuthPrincipal` (server/src/api.js) | requireVaultAccess(read) | n/a | `read:vaults` | `sdk/test/hosted-tenancy.test.js` | caller-supplied vault id: loadVaultOrNull (an id of another generation answers the same 404, never 500) |
| GET | `/vaults/:id/status` | vault | session-or-machine | `requestAuthPrincipal` (server/src/api.js) | requireVaultAccess(read) | n/a | `read:vaults` | `sdk/test/hosted-build-authority.test.js` | live chain status of a vault; principal FIRST then loadVaultOrNull (rc12 review R-04 found this row missing) \| rc13 review N-01: v0.4.x manifests compile through compileExactStateV4 (owner/agent 200, never the v1 policy path) |
| GET | `/vaults/:id/audit` | vault | session-or-machine | `requestAuthPrincipal` (server/src/api.js) | requireVaultAccess(read) | n/a | `read:vaults` | `sdk/test/hosted-foreign-tenant-matrix.test.js` | per-vault audit view; principal FIRST then loadVaultOrNull (rc12 review R-04) |
| POST | `/vaults/:id/reconcile` | vault | session-or-machine | `requestAuthPrincipal` (server/src/api.js) | requireVaultAccess(owner) | requireVaultAccess(owner) | `vaults:reconcile` | `sdk/test/hosted-build-authority.test.js` | caller-supplied vault id: loadVaultOrNull (an id of another generation answers the same 404, never 500). RC45 F6/F8 A5 (H-51): the body may carry outOfAppTransaction, optional owner-supplied recover evidence, verified against the chain, grants no authority; it is read only after the principal and requireVaultAccess(owner) (foreign evidence answers the same 404 before any parse or node call), a non-string, a string over 64 KiB or a transaction with more than 64 outputs (RC45 R1-09) is 400 BAD_FORMAT and a vault outside the v0.4 family with the field is 422 UNSUPPORTED_VERSION, neither reconciles; hostile evidence for the field: sdk/test/rc45-t8-recover-evidence-route.test.js |
| GET | `/vaults/:id/agent-suspensions` | vault | session-or-machine | `requestAuthPrincipal` (server/src/api.js) | requireVaultAccess(read) | n/a | `read:vaults` | `sdk/test/hosted-build-authority.test.js` | caller-supplied vault id: loadVaultOrNull (an id of another generation answers the same 404, never 500) |
| POST | `/vaults/:id/agent-suspensions` | vault | session-or-machine | `requestAuthPrincipal` (server/src/api.js) | requireVaultAccess(owner) | requireVaultAccess(owner) | `vaults:suspend-agents` | `sdk/test/hosted-build-authority.test.js` | caller-supplied vault id: loadVaultOrNull (an id of another generation answers the same 404, never 500) |

### /manifests

| method | path | resource class | principal | auth gate (file) | tenancy resolver | mutation gate | machine scope | hostile evidence | note |
|---|---|---|---|---|---|---|---|---|---|
| GET | `/manifests/:vaultId` | vault | session-or-machine | `requestAuthPrincipal` (server/src/api.js) | requireVaultAccess(read) | n/a | `read:manifests` | `sdk/test/postlaunch-server-tenancy.test.js` |  |

### /attestations

| method | path | resource class | principal | auth gate (file) | tenancy resolver | mutation gate | machine scope | hostile evidence | note |
|---|---|---|---|---|---|---|---|---|---|
| GET | `/attestations/export` | vault | session-or-machine | `requestAuthPrincipal` (server/src/api.js) | requireVaultAccess(read) \| requireOrgAccess(read) | n/a | `read:attestations` | `sdk/test/hosted-foreign-tenant-matrix.test.js` |  |

### /wallet/create

| method | path | resource class | principal | auth gate (file) | tenancy resolver | mutation gate | machine scope | hostile evidence | note |
|---|---|---|---|---|---|---|---|---|---|
| POST | `/wallet/create` | vault | session-or-machine | `requireLegacyBuildAuthority` (server/src/api.js) | requireLegacyBuildAuthority (genesis: signer == principal) | requireLegacyBuildAuthority | `request:build` | `sdk/test/hosted-foreign-tenant-matrix.test.js` | production-disabled (POLICYVAULT_LEGACY_CREATE); when enabled the hosted build-authority rule applies |

### /wallet/requests

| method | path | resource class | principal | auth gate (file) | tenancy resolver | mutation gate | machine scope | hostile evidence | note |
|---|---|---|---|---|---|---|---|---|---|
| POST | `/wallet/requests` | request | session-or-machine | `requireLegacyBuildAuthority` (server/src/api.js) | requireVaultAccess(read) + participant signer | requireLegacyBuildAuthority | `request:build` | `sdk/test/hosted-foreign-tenant-matrix.test.js` | caller-supplied vault id: loadVaultOrNull (an id of another generation answers the same 404, never 500) |
| POST | `/wallet/requests/:id/signature` | request | session-or-machine | `requireRequestSigner` (server/src/api.js) | loadLegacyV2Request (v0.2 records only) + requestAccessAllowed | loadLegacyV2Request (hosted: authentication, 401; then a missing record or one whose schema is not exactly policyvault-wallet-request/v2 is the non-oracle 404 REQUEST_NOT_FOUND with nothing written and no node call) + requireRequestSigner (the request's signer only) + requireSignedSafeJsonShape | `request:sign` | `sdk/test/rc45-r1-01-legacy-request-routes.test.js` | RC45 R1-01 (S-01, C6; row corrected to the code by R1-02): in this order, a missing signedSafeJson is the closed 400 BAD_SIGNATURE; then authentication (hosted: 401 for an unauthenticated caller); then a missing or non-v0.2 record answers 404 REQUEST_NOT_FOUND before the signer gate, so no non-v0.2 record (a v0.4 or v0.7-kas genesis or transition among them) reaches the v0.2 signing and broadcast pipeline; then the signer gate. sdk/src/wallet-requests-v2.js attachWalletSignatureV2 also refuses a non-v0.2 record (defence in depth). rc13 review N-02: a participant that is not the request's signer (an agent on the owner's request, the owner on its agent's) gets 403 NOT_THE_SIGNER before any state can change; malformed payloads are a closed 400 BAD_SIGNATURE |
| POST | `/wallet/requests/:id/reject` | request | session-or-machine | `requireRequestRejecter` (server/src/api.js) | loadLegacyV2Request (v0.2 records only) + requestAccessAllowed | loadLegacyV2Request (hosted: authentication, 401; then a missing record or one whose schema is not exactly policyvault-wallet-request/v2 is the non-oracle 404 REQUEST_NOT_FOUND with nothing written and no node call) + requireRequestRejecter (requestMutationAllowed, then the request's signer or the vault owner only) | `request:reject` | `sdk/test/rc45-r1-01-legacy-request-routes.test.js` | RC45 R1-01 (S-01, C7; row corrected to the code by R1-02): in this order, authentication (hosted: 401 for an unauthenticated caller on v0.2, v0.4 and missing ids alike); then a missing or non-v0.2 record answers 404 REQUEST_NOT_FOUND with nothing written, so the owner's v0.4 Pause, Close & recover or removeAgent and an agent spend can no longer be cancelled through this route; then requireRequestRejecter: the request's signer or the vault owner only, any other participant (the v0.2 delegate on the owner's request, AZ-03) 403 REQUEST_FORBIDDEN, a foreign principal the non-oracle 404; then markWalletRejected, which itself returns null for a non-v0.2 record (defence in depth). Hostile evidence: the legacy reject legs of the named suite (owner, agent, approver-only, FOREIGN and UNAUTHENTICATED principals against v0.2, v0.4 and missing ids) |
| GET | `/wallet/requests/:id` | request | session-or-machine | `requireRequestAccess` (server/src/api.js) | requestAccessAllowed | n/a | `read:requests` | `sdk/test/hosted-phase-f-hostile.test.js` |  |

### /wallet/v4

| method | path | resource class | principal | auth gate (file) | tenancy resolver | mutation gate | machine scope | hostile evidence | note |
|---|---|---|---|---|---|---|---|---|---|
| POST | `/wallet/v4/create` | vault | session-or-machine | `requireBuildAuthority` (server/src/api.js) | requireBuildAuthority (genesis: signer == principal) | requireBuildAuthority | `request:build` | `sdk/test/hosted-build-authority.test.js` |  |
| POST | `/wallet/v4/requests` | request | session-or-machine | `requireBuildAuthority` (server/src/api.js) | requireVaultAccess(read) + build authority + participant signer | requireBuildAuthority | `request:build` | `sdk/test/hosted-build-authority.test.js` | caller-supplied vault id: loadVaultOrNull (an id of another generation answers the same 404, never 500) |
| POST | `/wallet/v4/requests` | request | session-or-machine | `requireBuildAuthority` (server/src/api.js) | requireVaultAccess(read) + build authority + participant signer | requireBuildAuthority | `request:build` + `request:break-glass` | `sdk/test/hosted-build-authority.test.js` | break-glass actions need the additional scope \| caller-supplied vault id: loadVaultOrNull (an id of another generation answers the same 404, never 500) |
| POST | `/wallet/v4/simulate` | vault | session-or-machine | `requireBuildAuthority` (server/src/api.js) | requireVaultAccess(read) + principal build authority | requireBuildAuthority(simulate) — persists nothing | `request:build` | `sdk/test/hosted-build-authority.test.js` | persists nothing; the signer is what is being simulated \| caller-supplied vault id: loadVaultOrNull (an id of another generation answers the same 404, never 500) |
| GET | `/wallet/v4/requests` | request | session-or-machine | `requestAuthPrincipal` (server/src/api.js) | requestAccessAllowed filter (scoped listing) | n/a | `read:requests` | `sdk/test/postlaunch-server-tenancy.test.js` | caller-supplied vault id: loadVaultOrNull (an id of another generation answers the same 404, never 500) |
| GET | `/wallet/v4/requests/:id` | request | session-or-machine | `requireRequestAccess` (server/src/api.js) | requestAccessAllowed | n/a | `read:requests` | `sdk/test/hosted-phase-f-hostile.test.js` |  |
| POST | `/wallet/v4/requests/:id/signature` | request | session-or-machine | `requireRequestSigner` (server/src/api.js) | requestAccessAllowed | requireRequestSigner (the request's signer only) + requireSignedSafeJsonShape | `request:sign` | `sdk/test/hosted-build-authority.test.js` | rc13 review N-02: a participant that is not the request's signer (an agent on the owner's request, the owner on its agent's) gets 403 NOT_THE_SIGNER before any state can change; malformed payloads are a closed 400 BAD_SIGNATURE |
| POST | `/wallet/v4/requests/:id/approvals` | request | session-or-machine | `requireRequestAccess` (server/src/api.js) | requestAccessAllowed | collectApprovalV4: the approver signature is verified against the approval package (a 65-byte SIG_HASH_ALL signature over the frozen covenant input, in the approver's fixed slot); for an invalid one nothing is written to the approvals or the request state (the build-derived, empty approval package may be materialized first) | `request:sign` | `sdk/test/external-approver-discovery.test.js` | RC45 R1-02 (S-02): row corrected to the code. The route calls requireRequestAccess (read access: a covenant participant of the vault or the request's signer; a foreign principal gets the non-oracle 404), not requireRequestMutation, because approver-only principals must reach it. The approver's authority is its approval signature alone: approverAddress names the slot and only a valid signature by that configured approver over the frozen covenant input is accepted. The route's code is unchanged |
| POST | `/wallet/v4/requests/:id/submit` | request | session-or-machine | `requireRequestMutation` (server/src/api.js) | requestAccessAllowed | requestMutationAllowed | `request:submit` | `sdk/test/hosted-build-authority.test.js` |  |
| POST | `/wallet/v4/requests/:id/genesis-submit` | request | session-or-machine | `requireRequestSigner` (server/src/api.js) | requestAccessAllowed | requireRequestSigner (the request's signer only) + requireSignedSafeJsonShape | `request:submit` | `sdk/test/hosted-build-authority.test.js` | rc13 review N-02: a participant that is not the request's signer (an agent on the owner's request, the owner on its agent's) gets 403 NOT_THE_SIGNER before any state can change; malformed payloads are a closed 400 BAD_SIGNATURE |
| POST | `/wallet/v4/requests/:id/reject` | request | session-or-machine | `requireRequestRejecter` (server/src/api.js) | requestAccessAllowed | requestMutationAllowed + requireRequestRejecter (the request's signer or the vault owner only) | `request:reject` | `sdk/test/rc45-r1-01-legacy-request-routes.test.js` | RC45 F3 A2 (H-11): hosted rejection is narrowed to the request's signer or the vault owner (template.owner); any other participant (an agent on the owner's request or on another agent's) gets 403 REQUEST_FORBIDDEN with nothing changed; a foreign principal keeps the non-oracle 404 and an approver-only principal the 403 of requestMutationAllowed; owner-minted machine credentials act as the owner (CR-I4). Hostile evidence: the v0.4 reject legs of the named suite (RC45 R1-01: a FOREIGN principal 404, an UNAUTHENTICATED caller 401, an agent on the owner's requests and an approver-only principal 403 REQUEST_FORBIDDEN, the signer or the owner 200, nothing written on any refusal), the A2 legs of sdk/test/rc45-t8-api-routes.test.js (another agent 403 REQUEST_FORBIDDEN, a foreign principal 404; its request paths are spelled in sdk/testutil/rc45-f3-kit.js) and sdk/test/rc45-t3-owner-breakglass.test.js (an agent on the owner's request 403) |
| POST | `/wallet/v4/requests/:id/reconcile` | request | session-or-machine | `requireRequestSigner` (server/src/api.js) | requestAccessAllowed | requireRequestSigner (the request's signer only); genesis requests only (409 NOT_A_GENESIS otherwise) | `request:submit` | `sdk/test/hosted-build-authority.test.js` | Codex checkpoint 2 UX-05: resolves an UNRESOLVED genesis (SUBMITTING / SUBMITTED / RECONCILIATION_REQUIRED) by chain proof only — CHAIN_VERIFIED / NOT_BROADCAST / PENDING; never by a status read. POST /wallet/v4/create refuses 409 CREATION_UNRESOLVED for the same signer while one exists; GET /wallet/v4/requests?unresolved=1 lists them under the listing's own scoping |

### /wallet/v5

| method | path | resource class | principal | auth gate (file) | tenancy resolver | mutation gate | machine scope | hostile evidence | note |
|---|---|---|---|---|---|---|---|---|---|
| POST | `/wallet/v5/create` | vault | session-or-machine | `requestAuthPrincipal` (server/src/wallet-token-surface.js) | xOnly(signerAddress) == principal.xOnlyPubkey (SIGNER_NOT_PRINCIPAL) | xOnly(signerAddress) == principal.xOnlyPubkey | `request:build` | `sdk/test/hosted-foreign-tenant-matrix.test.js` |  |
| POST | `/wallet/v5/requests` | request | session-or-machine | `requestAuthPrincipal` (server/src/wallet-token-surface.js) | requireTokenBuildAuthority | requireTokenBuildAuthority | `request:build` | `sdk/test/hosted-foreign-tenant-matrix.test.js` |  |
| GET | `/wallet/v5/requests` | request | session-or-machine | `requestAuthPrincipal` (server/src/wallet-token-surface.js) | requestVisible filter | n/a | `read:requests` | `sdk/test/hosted-foreign-tenant-matrix.test.js` |  |
| GET | `/wallet/v5/requests/:id` | request | session-or-machine | `requestAuthPrincipal` (server/src/wallet-token-surface.js) | requireRequestAccess | n/a | `read:requests` | `sdk/test/hosted-foreign-tenant-matrix.test.js` |  |
| POST | `/wallet/v5/requests/:id/signature` | request | session-or-machine | `requestAuthPrincipal` (server/src/wallet-token-surface.js) | requireRequestAccess | requireRequestAccess(mutation) + signer-only (NOT_THE_SIGNER; rc13 review N-02) | `request:sign` | `sdk/test/hosted-foreign-tenant-matrix.test.js` |  |
| POST | `/wallet/v5/requests/:id/submit` | request | session-or-machine | `requestAuthPrincipal` (server/src/wallet-token-surface.js) | requireRequestAccess | requireRequestAccess(mutation) | `request:submit` | `sdk/test/hosted-foreign-tenant-matrix.test.js` |  |
| POST | `/wallet/v5/requests/:id/reject` | request | session-or-machine | `requestAuthPrincipal` (server/src/wallet-token-surface.js) | requireRequestAccess | requireRequestAccess(mutation) + requireTokenRequestRejecter (the request's signer or the vault owner only; any other participant 403 REQUEST_FORBIDDEN) | `request:reject` | `sdk/test/rc45-r2-az-reject-scope.test.js` |  |

### /wallet/v6

| method | path | resource class | principal | auth gate (file) | tenancy resolver | mutation gate | machine scope | hostile evidence | note |
|---|---|---|---|---|---|---|---|---|---|
| POST | `/wallet/v6/create` | vault | session-or-machine | `requestAuthPrincipal` (server/src/wallet-token-surface.js) | xOnly(signerAddress) == principal.xOnlyPubkey (SIGNER_NOT_PRINCIPAL) | xOnly(signerAddress) == principal.xOnlyPubkey | `request:build` | `sdk/test/hosted-foreign-tenant-matrix.test.js` |  |
| POST | `/wallet/v6/requests` | request | session-or-machine | `requestAuthPrincipal` (server/src/wallet-token-surface.js) | requireTokenBuildAuthority | requireTokenBuildAuthority | `request:build` | `sdk/test/hosted-foreign-tenant-matrix.test.js` |  |
| GET | `/wallet/v6/requests` | request | session-or-machine | `requestAuthPrincipal` (server/src/wallet-token-surface.js) | requestVisible filter | n/a | `read:requests` | `sdk/test/hosted-foreign-tenant-matrix.test.js` |  |
| GET | `/wallet/v6/requests/:id` | request | session-or-machine | `requestAuthPrincipal` (server/src/wallet-token-surface.js) | requireRequestAccess | n/a | `read:requests` | `sdk/test/rc45-r1-02-gate1-evidence.test.js` |  |
| POST | `/wallet/v6/requests/:id/signature` | request | session-or-machine | `requestAuthPrincipal` (server/src/wallet-token-surface.js) | requireRequestAccess | requireRequestAccess(mutation) + signer-only (NOT_THE_SIGNER; rc13 review N-02) | `request:sign` | `sdk/test/rc45-r1-02-gate1-evidence.test.js` |  |
| POST | `/wallet/v6/requests/:id/submit` | request | session-or-machine | `requestAuthPrincipal` (server/src/wallet-token-surface.js) | requireRequestAccess | requireRequestAccess(mutation) | `request:submit` | `sdk/test/rc45-r1-02-gate1-evidence.test.js` |  |
| POST | `/wallet/v6/requests/:id/reject` | request | session-or-machine | `requestAuthPrincipal` (server/src/wallet-token-surface.js) | requireRequestAccess | requireRequestAccess(mutation) + requireTokenRequestRejecter (the request's signer or the vault owner only; any other participant 403 REQUEST_FORBIDDEN) | `request:reject` | `sdk/test/rc45-r2-az-reject-scope.test.js` |  |

### /wallet/v7

| method | path | resource class | principal | auth gate (file) | tenancy resolver | mutation gate | machine scope | hostile evidence | note |
|---|---|---|---|---|---|---|---|---|---|
| POST | `/wallet/v7/requests` | request | session-or-machine | `requestAuthPrincipal` (server/src/org-roots.js) | requireRootedBuildAuthority | requireRootedBuildAuthority | `write:org-roots` | `sdk/test/hosted-foreign-tenant-matrix.test.js` |  |
| GET | `/wallet/v7/vaults` | vault | session-or-machine | `requestAuthPrincipal` (server/src/org-roots.js) | anyVaultAccessAllowed filter | n/a | `read:org-roots` | `sdk/test/hosted-foreign-tenant-matrix.test.js` |  |
| GET | `/wallet/v7/requests` | request | session-or-machine | `requestAuthPrincipal` (server/src/org-roots.js) | walletRequestVisible filter | n/a | `read:org-roots` | `sdk/test/hosted-foreign-tenant-matrix.test.js` |  |
| GET | `/wallet/v7/requests/:id` | request | session-or-machine | `requestAuthPrincipal` (server/src/org-roots.js) | requireWalletRequest | n/a | `read:org-roots` | `sdk/test/hosted-foreign-tenant-matrix.test.js` |  |
| POST | `/wallet/v7/requests/:id/signature` | request | session-or-machine | `requestAuthPrincipal` (server/src/org-roots.js) | requireWalletRequest | requireWalletRequest(mutation) + signer-only (NOT_THE_SIGNER; rc13 review N-02) | `write:org-roots` | `sdk/test/hosted-foreign-tenant-matrix.test.js` |  |
| POST | `/wallet/v7/requests/:id/submit` | request | session-or-machine | `requestAuthPrincipal` (server/src/org-roots.js) | requireWalletRequest | requireWalletRequest(mutation) | `write:org-roots` | `sdk/test/hosted-foreign-tenant-matrix.test.js` |  |
| POST | `/wallet/v7/requests/:id/reject` | request | session-or-machine | `requestAuthPrincipal` (server/src/org-roots.js) | requireWalletRequest | requireWalletRequest(mutation) + requireWalletRequestRejecter (the request's signer or an active owner slot of the vault's organizational root only; any other participant, another agent included, 403 REQUEST_FORBIDDEN) | `write:org-roots` | `sdk/test/rc45-r2-az-reject-scope.test.js` |  |
| POST | `/wallet/v7/requests/:id/approvals` | request | session-or-machine | `requestAuthPrincipal` (server/src/org-roots.js) | requireWalletRequest | approver-only (hosted: approverAddress must be the signed-in wallet, 403 SIGNER_NOT_PRINCIPAL, and one of the vault's approver slots via tenancy.rootedVaultRoles, 403 NOT_AN_APPROVER) + collectApprovalKas (the approver's 65-byte SIG_HASH_ALL signature over the frozen covenant input, in its fixed slot; v0.7-kas vault-level approval tier) | `write:org-roots` | `sdk/test/hosted-foreign-tenant-matrix.test.js` | RC45 R1-02 (S-02, K7): row corrected to the code. requireWalletRequest is this route's visibility resolver (the non-oracle 404 for strangers) and is called without { mutation: true } by design, so approvers reach the route; its mutation gate is the approver-only check and collectApprovalKas |

### /org-roots

| method | path | resource class | principal | auth gate (file) | tenancy resolver | mutation gate | machine scope | hostile evidence | note |
|---|---|---|---|---|---|---|---|---|---|
| GET | `/org-roots` | org-root | session-or-machine | `requestAuthPrincipal` (server/src/org-roots.js) | orgRootAccessAllowed(read) filter | n/a | `read:org-roots` | `sdk/test/hosted-foreign-tenant-matrix.test.js` |  |
| POST | `/org-roots` | org-root | session-or-machine | `requestAuthPrincipal` (server/src/org-roots.js) | bindSignerToPrincipal (genesis funder) | bindSignerToPrincipal | `write:org-roots` | `sdk/test/hosted-foreign-tenant-matrix.test.js` |  |
| GET | `/org-roots/:id` | org-root | session-or-machine | `requestAuthPrincipal` (server/src/org-roots.js) | loadRootScoped(read) | n/a | `read:org-roots` | `sdk/test/hosted-foreign-tenant-matrix.test.js` |  |
| GET | `/org-roots/:id/vaults` | org-root | session-or-machine | `requestAuthPrincipal` (server/src/org-roots.js) | loadRootScoped(read) | n/a | `read:org-roots` | `sdk/test/hosted-foreign-tenant-matrix.test.js` |  |
| POST | `/org-roots/:id/vaults` | org-root | session-or-machine | `requestAuthPrincipal` (server/src/org-roots.js) | loadRootScoped(owner) + bindSignerToPrincipal | loadRootScoped(owner) | `write:org-roots` | `sdk/test/hosted-foreign-tenant-matrix.test.js` |  |
| POST | `/org-roots/:id/reconcile` | org-root | session-or-machine | `requestAuthPrincipal` (server/src/org-roots.js) | loadRootScoped(owner) | loadRootScoped(owner) | `write:org-roots` | `sdk/test/hosted-foreign-tenant-matrix.test.js` |  |
| POST | `/org-roots/:id/requests` | org-root | session-or-machine | `requestAuthPrincipal` (server/src/org-roots.js) | loadRootScoped(read) + bindSignerToPrincipal | bindSignerToPrincipal | `write:org-roots` | `sdk/test/hosted-foreign-tenant-matrix.test.js` | the SDK's assertInitiatingOwner then requires the bound signer to be an ACTIVE owner slot (successor only for succession) before any lock |
| GET | `/org-roots/:id/requests` | org-root | session-or-machine | `requestAuthPrincipal` (server/src/org-roots.js) | requireOrgRootAccess(read) + orgRootRequestAccessAllowed filter | n/a | `read:org-roots` | `sdk/test/hosted-foreign-tenant-matrix.test.js` |  |
| GET | `/org-roots/:id/requests/:rid` | org-root | session-or-machine | `requestAuthPrincipal` (server/src/org-roots.js) | loadRequestScoped | n/a | `read:org-roots` | `sdk/test/hosted-foreign-tenant-matrix.test.js` |  |
| GET | `/org-roots/:id/requests/:rid/slot-request/:slot` | org-root | session-or-machine | `requestAuthPrincipal` (server/src/org-roots.js) | loadRequestScoped + requireSlotOwner | n/a | `read:org-roots` | `sdk/test/hosted-foreign-tenant-matrix.test.js` |  |
| POST | `/org-roots/:id/requests/:rid/slot-signatures` | org-root | session-or-machine | `requestAuthPrincipal` (server/src/org-roots.js) | loadRequestScoped + requireSlotOwner | requireSlotOwner | `write:org-roots` | `sdk/test/hosted-foreign-tenant-matrix.test.js` |  |
| POST | `/org-roots/:id/requests/:rid/signature` | org-root | session-or-machine | `requestAuthPrincipal` (server/src/org-roots.js) | loadRequestScoped | loadRequestScoped(mutation) + signer-only (NOT_THE_SIGNER; rc13 review N-02) | `write:org-roots` | `sdk/test/hosted-foreign-tenant-matrix.test.js` |  |
| POST | `/org-roots/:id/requests/:rid/finalize` | org-root | session-or-machine | `requestAuthPrincipal` (server/src/org-roots.js) | loadRequestScoped | loadRequestScoped(mutation) | `write:org-roots` | `sdk/test/hosted-foreign-tenant-matrix.test.js` |  |
| POST | `/org-roots/:id/requests/:rid/submit` | org-root | session-or-machine | `requestAuthPrincipal` (server/src/org-roots.js) | loadRequestScoped | loadRequestScoped(mutation) | `write:org-roots` | `sdk/test/hosted-foreign-tenant-matrix.test.js` |  |
| POST | `/org-roots/:id/requests/:rid/reject` | org-root | session-or-machine | `requestAuthPrincipal` (server/src/org-roots.js) | loadRequestScoped | loadRequestScoped(mutation) | `write:org-roots` | `sdk/test/hosted-foreign-tenant-matrix.test.js` |  |

### /governance

| method | path | resource class | principal | auth gate (file) | tenancy resolver | mutation gate | machine scope | hostile evidence | note |
|---|---|---|---|---|---|---|---|---|---|
| POST | `/governance/proposals` | vault | session-or-machine | `requestAuthPrincipal` (server/src/api.js) | requireVaultAccess(owner) | requireVaultAccess(owner) | `governance:propose` | `sdk/test/postlaunch-server-tenancy.test.js` | caller-supplied vault id: loadVaultOrNull (an id of another generation answers the same 404, never 500) |
| GET | `/governance/proposals` | vault | session-or-machine | `requestAuthPrincipal` (server/src/api.js) | vaultAccessAllowed(read) \| quorum approver filter | n/a | `read:governance` | `sdk/test/postlaunch-server-tenancy.test.js` | caller-supplied vault id: loadVaultOrNull (an id of another generation answers the same 404, never 500) |
| GET | `/governance/proposals/:id` | vault | session-or-machine | `requestAuthPrincipal` (server/src/api.js) | vaultAccessAllowed(read) \| quorum approver | n/a | `read:governance` | `sdk/test/postlaunch-server-tenancy.test.js` |  |
| POST | `/governance/proposals/:id/approvals` | vault | session-or-machine | `requestAuthPrincipal` (server/src/api.js) | loadScopedProposal (vaultAccessAllowed(read) \| quorum approver) | collectProposalApproval (approver Schnorr signature verified against the quorum key; SDK) | `governance:approve` | `sdk/test/postlaunch-governance-server.test.js` |  |
| POST | `/governance/proposals/:id/cancel` | vault | session-or-machine | `requestAuthPrincipal` (server/src/api.js) | requireVaultAccess(owner) | requireVaultAccess(owner) | `governance:cancel` | `sdk/test/postlaunch-server-tenancy.test.js` |  |

### /risk

| method | path | resource class | principal | auth gate (file) | tenancy resolver | mutation gate | machine scope | hostile evidence | note |
|---|---|---|---|---|---|---|---|---|---|
| GET | `/risk/evaluations/:id` | vault | session-or-machine | `requestAuthPrincipal` (server/src/api.js) | vaultAccessAllowed(read) \| orgAccessAllowed(read) | n/a | `read:risk` | `sdk/test/postlaunch-server-tenancy.test.js` |  |
| POST | `/risk/evaluations/:id/release` | vault | session-or-machine | `requestAuthPrincipal` (server/src/api.js) | orgAccessAllowed(owner) \| vaultAccessAllowed(owner) | orgAccessAllowed(owner) \| vaultAccessAllowed(owner) | `risk:release` | `sdk/test/postlaunch-server-tenancy.test.js` |  |

### /organizations

| method | path | resource class | principal | auth gate (file) | tenancy resolver | mutation gate | machine scope | hostile evidence | note |
|---|---|---|---|---|---|---|---|---|---|
| GET | `/organizations` | organization | session-or-machine | `requestAuthPrincipal` (server/src/api.js) | orgAccessAllowed(read) filter | n/a | `read:organizations` | `sdk/test/hosted-tenancy.test.js` |  |
| POST | `/organizations` | organization | session-or-machine | `requestAuthPrincipal` (server/src/api.js) | tenantOwner = principal | tenantOwner = principal | `organizations:manage` | `sdk/test/hosted-tenancy.test.js` |  |
| GET | `/organizations/:id` | organization | session-or-machine | `requestAuthPrincipal` (server/src/api.js) | requireOrgAccess(read) | n/a | `read:organizations` | `sdk/test/hosted-tenancy.test.js` |  |
| POST | `/organizations/:id/rename` | organization | session-or-machine | `requestAuthPrincipal` (server/src/api.js) | requireOrgAccess(owner\|admin) (+ requireVaultAccess(owner) for vault assignment) | requireOrgAccess(owner\|admin) | `organizations:manage` | `sdk/test/hosted-tenancy.test.js` |  |
| POST | `/organizations/:id/archive` | organization | session-or-machine | `requestAuthPrincipal` (server/src/api.js) | requireOrgAccess(owner\|admin) (+ requireVaultAccess(owner) for vault assignment) | requireOrgAccess(owner\|admin) | `organizations:manage` | `sdk/test/hosted-tenancy.test.js` |  |
| POST | `/organizations/:id/restore` | organization | session-or-machine | `requestAuthPrincipal` (server/src/api.js) | requireOrgAccess(owner\|admin) (+ requireVaultAccess(owner) for vault assignment) | requireOrgAccess(owner\|admin) | `organizations:manage` | `sdk/test/hosted-tenancy.test.js` |  |
| POST | `/organizations/:id/delete` | organization | session-or-machine | `requestAuthPrincipal` (server/src/api.js) | requireOrgAccess(owner\|admin) (+ requireVaultAccess(owner) for vault assignment) | requireOrgAccess(owner\|admin) | `organizations:manage` | `sdk/test/hosted-tenancy.test.js` |  |
| POST | `/organizations/:id/members` | organization | session-or-machine | `requestAuthPrincipal` (server/src/api.js) | requireOrgAccess(owner\|admin) (+ requireVaultAccess(owner) for vault assignment) | requireOrgAccess(owner\|admin) | `organizations:manage` | `sdk/test/hosted-tenancy.test.js` |  |
| POST | `/organizations/:id/members/:m/remove` | organization | session-or-machine | `requestAuthPrincipal` (server/src/api.js) | requireOrgAccess(owner\|admin) (+ requireVaultAccess(owner) for vault assignment) | requireOrgAccess(owner\|admin) | `organizations:manage` | `sdk/test/rc45-r1-02-gate1-evidence.test.js` |  |
| POST | `/organizations/:id/members/:m` | organization | session-or-machine | `requestAuthPrincipal` (server/src/api.js) | requireOrgAccess(owner\|admin) (+ requireVaultAccess(owner) for vault assignment) | requireOrgAccess(owner\|admin) | `organizations:manage` | `sdk/test/rc45-r1-02-gate1-evidence.test.js` |  |
| POST | `/organizations/:id/vaults` | organization | session-or-machine | `requestAuthPrincipal` (server/src/api.js) | requireOrgAccess(owner\|admin) (+ requireVaultAccess(owner) for vault assignment) | requireOrgAccess(owner\|admin) | `organizations:manage` | `sdk/test/hosted-tenancy.test.js` |  |
| POST | `/organizations/:id/vaults/:v/unassign` | organization | session-or-machine | `requestAuthPrincipal` (server/src/api.js) | requireOrgAccess(owner\|admin) (+ requireVaultAccess(owner) for vault assignment) | requireOrgAccess(owner\|admin) | `organizations:manage` | `sdk/test/hosted-foreign-tenant-matrix.test.js` |  |
| POST | `/organizations/:id/controls` | organization | session-or-machine | `requestAuthPrincipal` (server/src/api.js) | requireOrgAccess(owner\|admin) (+ requireVaultAccess(owner) for vault assignment) | requireOrgAccess(owner\|admin) | `organizations:manage` | `sdk/test/postlaunch-server-tenancy.test.js` |  |
| GET | `/organizations/:id/members` | organization | session-or-machine | `requestAuthPrincipal` (server/src/api.js) | requireOrgAccess(read) | n/a | `read:organizations` | `sdk/test/hosted-tenancy.test.js` |  |
| GET | `/organizations/:id/vaults` | organization | session-or-machine | `requestAuthPrincipal` (server/src/api.js) | requireOrgAccess(read) | n/a | `read:organizations` | `sdk/test/hosted-tenancy.test.js` |  |
| GET | `/organizations/:id/controls` | organization | session-or-machine | `requestAuthPrincipal` (server/src/api.js) | requireOrgAccess(read) | n/a | `read:organizations` | `sdk/test/postlaunch-server-tenancy.test.js` |  |
| GET | `/organizations/:id/audit` | organization | session-or-machine | `requestAuthPrincipal` (server/src/api.js) | requireOrgAccess(read) | n/a | `read:organizations` | `sdk/test/hosted-foreign-tenant-matrix.test.js` |  |

### /events

| method | path | resource class | principal | auth gate (file) | tenancy resolver | mutation gate | machine scope | hostile evidence | note |
|---|---|---|---|---|---|---|---|---|---|
| GET | `/events` | creator-owned | session-or-machine | `requestAuthPrincipal` (server/src/api.js) | eventVisibleTo filter | n/a | `read:events` | `sdk/test/postlaunch-webhooks-events.test.js` |  |

### /webhooks

| method | path | resource class | principal | auth gate (file) | tenancy resolver | mutation gate | machine scope | hostile evidence | note |
|---|---|---|---|---|---|---|---|---|---|
| POST | `/webhooks` | creator-owned | session-or-machine | `requestAuthPrincipal` (server/src/api.js) | creatorXOnly scoping | creatorXOnly scoping | `webhooks:manage` | `sdk/test/postlaunch-webhooks-events.test.js` |  |
| GET | `/webhooks` | creator-owned | session-or-machine | `requestAuthPrincipal` (server/src/api.js) | creatorXOnly scoping | n/a | `webhooks:manage` | `sdk/test/postlaunch-webhooks-events.test.js` |  |
| GET | `/webhooks/:id` | creator-owned | session-or-machine | `requestAuthPrincipal` (server/src/api.js) | creatorXOnly scoping | n/a | `webhooks:manage` | `sdk/test/postlaunch-webhooks-events.test.js` |  |
| POST | `/webhooks/:id/rotate-secret` | creator-owned | session-or-machine | `requestAuthPrincipal` (server/src/api.js) | creatorXOnly scoping | creatorXOnly scoping | `webhooks:manage` | `sdk/test/hosted-foreign-tenant-matrix.test.js` |  |
| POST | `/webhooks/:id/revoke` | creator-owned | session-or-machine | `requestAuthPrincipal` (server/src/api.js) | creatorXOnly scoping | creatorXOnly scoping | `webhooks:manage` | `sdk/test/postlaunch-webhooks-events.test.js` |  |

### /notifications

| method | path | resource class | principal | auth gate (file) | tenancy resolver | mutation gate | machine scope | hostile evidence | note |
|---|---|---|---|---|---|---|---|---|---|
| GET | `/notifications/channels` | creator-owned | session-or-machine | `requestAuthPrincipal` (server/src/api.js) | creatorXOnly scoping | n/a | `read:notifications` | `sdk/test/postlaunch-notifications.test.js` |  |
| POST | `/notifications/rules` | creator-owned | session-or-machine | `requestAuthPrincipal` (server/src/api.js) | creatorXOnly scoping | creatorXOnly scoping | `notifications:manage` | `sdk/test/postlaunch-notifications.test.js` |  |
| GET | `/notifications/rules` | creator-owned | session-or-machine | `requestAuthPrincipal` (server/src/api.js) | creatorXOnly scoping | n/a | `read:notifications` | `sdk/test/postlaunch-notifications.test.js` |  |
| GET | `/notifications/rules/:id` | creator-owned | session-or-machine | `requestAuthPrincipal` (server/src/api.js) | creatorXOnly scoping | n/a | `read:notifications` | `sdk/test/postlaunch-notifications.test.js` |  |
| POST | `/notifications/rules/:id/disable` | creator-owned | session-or-machine | `requestAuthPrincipal` (server/src/api.js) | creatorXOnly scoping | creatorXOnly scoping | `notifications:manage` | `sdk/test/postlaunch-notifications.test.js` |  |
| POST | `/notifications/rules/:id/enable` | creator-owned | session-or-machine | `requestAuthPrincipal` (server/src/api.js) | creatorXOnly scoping | creatorXOnly scoping | `notifications:manage` | `sdk/test/postlaunch-notifications.test.js` |  |
| POST | `/notifications/rules/:id/delete` | creator-owned | session-or-machine | `requestAuthPrincipal` (server/src/api.js) | creatorXOnly scoping | creatorXOnly scoping | `notifications:manage` | `sdk/test/postlaunch-notifications.test.js` |  |

Routes: 124. Families: 29.
