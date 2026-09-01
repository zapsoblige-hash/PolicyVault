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
`GET /api/v1/capabilities` document; a scope the credential does not hold
simply hides/refuses the tool server-side.

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
| npm package / registry entry | 1.4.0 (matches the PolicyVault v1.4.0 release it ships with) |
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
