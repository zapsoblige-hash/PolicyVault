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
| npm package / registry entry | 1.4.2 CANDIDATE (least-privilege discovery corrective; NOT published — owner gate). Published: 1.4.1 (distribution hotfix: self-contained topology); 1.4.0 is BROKEN for standalone npm/npx consumers and is deprecated in favour of >=1.4.1 |
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
