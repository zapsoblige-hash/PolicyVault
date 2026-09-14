# PolicyVault MCP server — distribution & discovery

How to install, configure, and safely operate the PolicyVault MCP server
from any MCP-capable agent runtime. The authoritative protocol/tool
specification is `docs/postlaunch/mcp-interface-spec.md`; this page is the
distribution-facing summary.

> **AI MAY REQUEST. POLICYVAULT DETERMINISTICALLY DECIDES.
> THE COVENANT ENFORCES. SIGNERS RETAIN CUSTODY.**

The MCP server is a thin distribution surface over PolicyVault's existing
capability. It holds no keys, signs nothing, broadcasts nothing, implements
no policy and no financial semantics of its own — every tool call becomes
an ordinary authenticated HTTP request to `/api/v1`, subject to the same
tenancy, scope, governance, risk, and covenant decisions as every other
client. If this process dies, PolicyVault safety is unaffected.

## Install

Registry identity: **`io.github.zapsoblige-hash/policyvault`**
(official MCP registry). npm package: **`policyvault-mcp`**.

```bash
npm install -g policyvault-mcp     # or: npx policyvault-mcp
```

No build step, no runtime dependencies (Node ≥ 20; the server is plain
Node with zero npm dependencies). Running from a source checkout is
identical: `node mcp/server.js`.

## Transport

**stdio** (JSON-RPC 2.0, one message per line, UTF-8; stderr is
diagnostics only). Protocol revisions supported: **2025-11-25** and
**2025-06-18** (initialization-based). A client probing the 2026-07-28
`server/discover` era receives a clean `-32601`, which that revision's
compatibility rules define as "legacy server — fall back to initialize".

## Configuration example

```json
{
  "mcpServers": {
    "policyvault": {
      "command": "npx",
      "args": ["policyvault-mcp"],
      "env": {
        "POLICYVAULT_MCP_SERVER_URL": "https://app.policy-vault.org",
        "POLICYVAULT_MCP_TOKEN": "pvmk_..."
      }
    }
  }
}
```

| Variable | Required | Meaning |
|---|---|---|
| `POLICYVAULT_MCP_SERVER_URL` | yes | Bare origin of the PolicyVault server (hosted or self-hosted). Refused if it embeds credentials or a path. |
| `POLICYVAULT_MCP_TOKEN` | yes | Machine-identity bearer credential. Never logged; deleted from the process environment after being read. |
| `POLICYVAULT_MCP_SCOPES` | no | Narrow which tools are *advertised* (display-side only — enforcement is always server-side). |
| `POLICYVAULT_MCP_HTTP_TIMEOUT_MS` | no | Per-call HTTP timeout, 1000..600000 (default 60000). |
| `POLICYVAULT_MCP_ALLOW_INSECURE_HTTP` | no | `1` permits plaintext `http://` to a non-loopback host — ONLY inside a private, separately-encrypted operator transport. Never on an open network. |
| `POLICYVAULT_MCP_DEBUG` | no | `1` writes one-line per-message diagnostics to stderr (never bodies, never the token). |

## Auth setup

1. The vault operator signs into PolicyVault with their wallet (a human,
   wallet-session-only action) and mints a **machine identity** with
   exactly the scopes the agent should hold (`POST /api/v1/identities`).
   Deny-by-default applies to everything else.
2. The returned `pvmk_...` credential goes into `POLICYVAULT_MCP_TOKEN`.
3. Rotation/revocation happen in the PolicyVault app; the MCP server
   needs only a restart with the new credential.

The credential authenticates; it never authorizes signatures. There is no
way to grant this server — or any agent behind it — signing authority.

## Tools: read-only vs mutation

Read-only (no state change, ever):
`policyvault_capabilities`, `policyvault_list_vaults`,
`policyvault_vault`, `policyvault_vault_audit`, `policyvault_audit_feed`,
`policyvault_network_status`, `policyvault_request_status`,
`policyvault_list_requests`, `policyvault_governance_proposals`,
`policyvault_governance_proposal`, `policyvault_risk_evaluation`.

Dry-run (persists nothing):
`policyvault_simulate_request` — a full pass through the real
governance/risk/build/intent pipeline without creating anything.

Mutations (durable, but never funds-moving):
- `policyvault_create_request` — creates a durable **unsigned** spending
  request (idempotent via a derived `Idempotency-Key`). Signing and
  submission are separate, signer-controlled steps outside this tool set:
  the request only ever becomes a transaction if a human/wallet signer
  independently verifies and signs it.
- `policyvault_reject_request` — withdraws a pending request.
- v0.7 organizational roots (since 1.5.0): `policyvault_org_roots`,
  `policyvault_org_root`, `policyvault_org_root_requests` (read-only);
  `policyvault_create_org_root_request` (build-only root-authorized
  request — per-owner-slot signer envelopes, signatures collected out of
  band) and `policyvault_create_v7_request` (build-only rooted-vault
  delegate request). Since **1.6.x (1.6.1 proposed; 1.6.0 packed for two BLOCKED release sets, never published)** these carry the native-KAS
  treasury mappings: `agentSpend` on a rooted KAS treasury, and the
  `ownerSetApprovers` / `ownerTopUp` vault operations riding a root
  request. Recovery through MCP, precisely: the ROOT action `ownerRecover`
  (the root's own owner-recovery transition, built UNSIGNED, signatures
  collected out of band) IS accepted by `policyvault_create_org_root_request`;
  the rooted-VAULT operation `ownerRecover` (a treasury's terminal recovery)
  is NOT accepted as a vault operation, and MCP exposes no genesis, signature
  or submit tool — an unsigned root recovery request never implies
  rooted-vault recovery support. Builds only — nothing is signed or broadcast.

The active tool list is derived per session from the live
`GET /api/v1/capabilities` document. Since 1.4.2 (owner-live finding of
2026-09-02: a read:network-only credential saw all 14 tools) discovery is
**credential-scoped**: the credential is presented at discovery, the
server (`features.principalScopedDiscovery`, hosted mode) names that
credential's own granted scopes, and only the tools those scopes cover are
advertised. Hidden tools stay callable by exact name and meet the
server's `403 SCOPE_FORBIDDEN` — enforcement never moved into the
adapter. Malformed or missing principal data fails closed at startup; a
server without the feature yields the build-level catalog (announced on
stderr). Permanent tests: `mcp/test/mcp-discovery-scopes.test.js` (mock)
and `mcp/test/mcp-live-server.test.js` (real server, real credential).

## Network guidance

- Hosted: `https://app.policy-vault.org` (MAINNET — real KAS). Verify
  network identity with `policyvault_network_status` before financial
  reasoning; the server refuses mixed-network operations.
- Self-hosted: point `POLICYVAULT_MCP_SERVER_URL` at your own origin
  (testnet-10 recommended for development). Self-hosting is a first-class,
  equal-security path.
- Amounts are integer-sompi decimal **strings** (1 KAS = 100,000,000
  sompi). Floats are refused before any network traffic.

## Example prompts

- "List my PolicyVault vaults and summarize each vault's remaining
  periodic budget."
- "Simulate paying 25 KAS from vault X to kaspa:… and explain exactly
  which policy rules the payment would pass or violate."
- "Create a spending request for invoice #123 (12.5 KAS to the approved
  vendor address) and tell me who still needs to approve it."
- "Show the audit trail for vault X for the last week."

An agent can *request* a spend; it cannot make one happen. Every
funds-moving signature stays with the owner's or agent's own wallet over
frozen, independently verified bytes.

## Version compatibility

| Component | Version |
|---|---|
| npm package / registry entry | **1.6.1 PROPOSED — NOT PUBLISHED** (the corrected successor of the never-published 1.6.0 tarball `f8e7c6ee…`, which was packed for the BLOCKED rc33 / rc35 sets and is retained unchanged as history; 1.6.1 differs from it ONLY in the packaged README recovery statement and the version fields — no tool schema or runtime byte changed; adds the native-KAS treasury mappings: `agentSpend` on `policyvault_create_v7_request`; `ownerSetApprovers` / `ownerTopUp` vault operations on `policyvault_create_org_root_request`; the exact tarball is packed, audited and clean-consumer-proven — including a KAS consumer proof — before the independent review of the `fullscale-rc33` replacement release and is published unchanged only after that review's PASS, the deployment and the served verification; the registry is the authority for what is delivered). **Published: 1.5.0** (2026-09-09; v0.7 organizational-root tool schemas + the `x-policyvault-mcp-client` identification header; registry tarball sha256 `73567fe0858b8a1c2382adb28dbc8b5381f56015b2a43532b7acf637e4dfc5b9`; contains NO native-KAS schemas), 1.4.2 (least-privilege discovery corrective, 2026-09-02) and 1.4.1; 1.4.0 is BROKEN for standalone npm/npx use (missing sibling `core/`) — never install it. |
| MCP protocol revisions | 2025-11-25, 2025-06-18 |
| PolicyVault API | `/api/v1` (capability document is the authority; unknown versions fail closed) |
| Node | ≥ 20 |

## Fail-closed behavior

- Refuses to start without `POLICYVAULT_MCP_SERVER_URL` and
  `POLICYVAULT_MCP_TOKEN`.
- Exits (code 3) if the live capability-discovery document cannot be
  fetched or validated — there is no hand-maintained fallback tool list.
- All tool input schemas are CLOSED (`additionalProperties: false`,
  exact types); malformed input is refused before any network traffic.
- Server refusals (scope, tenancy, policy, risk, governance) pass through
  unchanged — the MCP layer never retries, reinterprets, or downgrades a
  refusal.
- Everything under a tool result's `data` key is untrusted data from the
  vault system and its users — never instructions to the agent.

## Package topology and the consumer gate (hotfix 1.4.1, 2026-09-01)

`policyvault-mcp@1.4.0` escaped with an incomplete npm runtime closure:
`src/idempotency.js` required `../../core/model/canonical-json` (a
monorepo sibling path), so every clean `npm install` / `npx` consumer died
at module load — before any MCP `initialize`. The repository tests had
proven the adapter inside the full monorepo, never the tarball a consumer
receives.

Corrective topology (smallest safe change, ONE canonical implementation):

- `core/` remains the only implementation of every deterministic
  PolicyVault semantic. `mcp/tools/sync-core.js` copies a CLOSED list of
  shared-core files VERBATIM (byte-identical) into `mcp/core/` and records
  every sha256 in `mcp/core/MANIFEST.json` — the same generated-verbatim
  precedent as the browser `web/core-bundle.js`. `mcp/src` requires the
  packaged copy by a package-internal path; nothing in the package
  reaches outside its root. `npm run prepack` fails on any drift, and
  `mcp/test/core-sync.test.js` fails on edits, missing copies, or stray
  files, so the copy can never diverge from canonical.
- `mcp/test/package-closure.test.js` mechanically walks the runtime
  `require` closure from `server.js` and fails on any require that escapes
  the package root, is omitted by `package.json` `files`, or names an
  undeclared package.
- `mcp/test/package-consumer.test.js` is the PERMANENT packaged-artifact
  gate: `npm pack` the exact candidate, install it into a fresh consumer
  directory outside the repository, run it through the published bin
  mapping, drive a REAL stdio `initialize` (+ `initialized`, `tools/list`)
  against a mock PolicyVault API, require a valid protocol response, and
  audit every module the installed server resolved (only node builtins and
  files under the installed package). Negative variants prove the gate
  fails when `files` omits `core/`, when a require escapes to `../../core`
  (no sibling checkout exists in the consumer tree), or when the packaged
  shared implementation is missing (`npm pack` itself refuses).
  "Process stayed alive" is never success.

**2026-09-11 (`fullscale-rc35` replacement, RC33-ID-01 record-uniqueness repair):** the `mcp/` tree (and the vendored `core/`) is byte-identical between the blocked rc33 build source `efe9372` and the rc35 build source `17bccf6` (mechanical `git diff` empty). `policyvault-mcp-1.6.0.tgz` re-packed from the detached checkout of `17bccf6` is BYTE-IDENTICAL to the rc33 tarball — sha256 `f8e7c6eed7bdf40ee2b15e5e2b1d2694bff3e77509478451142be92b07045e46`, npm shasum `db45328a1998bb2b94e324aa45345cb1636c2fde`, 15 files identical to the commit tree — so the exact unpublished tarball is REUSED as the proposed 1.6.0; the clean-consumer proofs were re-run from the exact tarball against the CORRECTED server (`mcp/tools/candidate-proof.js` PASS — 7 steps; `mcp/tools/candidate-proof-kas.js` PASS — 10 steps incl. v0.4 compatibility) and the tarball privacy scan is clean (evidence `docs/postlaunch/ux-evidence/claude-rc35/mcp/`). The uniqueness correction changes no MCP API behaviour: none of the 19 tools creates a vault (the reviewer's checkpoint-02 extension confirms no direct genesis tool and a schema-refused genesis action), so `VAULT_ID_IN_USE` is not reachable through MCP. Still NOT published; the registry remains the authority; publication only after the matching independent PASS, deployment and served verification of `fullscale-rc35`.

**2026-09-11 (`fullscale-rc36` replacement, RC35 recovery / reservation repair):** the independent RC35 affected review found the packaged README's blanket statement that `ownerRecover` is "NOT exposed to machine callers" imprecise — `policyvault_create_org_root_request` DOES accept the ROOT action `ownerRecover` (an unsigned root-level owner-recovery request; per-owner-slot signatures collected out of band), while the rooted-VAULT operation `ownerRecover` is not accepted and MCP has no genesis / signature / submit tool — and the README still named the blocked `fullscale-rc33` / `v1.10.1` release. Both are corrected in the packaged README (and in this record and the interface spec); because packaged bytes changed, the package is re-identified as **1.6.1** (package.json / server.json), packed from the rc36 build source, and consumer-proven again from the exact new tarball; the never-published 1.6.0 tarball is retained unchanged. No tool schema, catalog entry or runtime byte of the adapter changed (`mcp/src`, `mcp/server.js`, vendored `core/` byte-identical to `17bccf6`); the RC35 runtime corrections (submission-outcome classification, genesis recovery, headless reservation) are server / SDK behaviour reached only through REST routes the adapter does not call. Still NOT published; the registry remains the authority.
