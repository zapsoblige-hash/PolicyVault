# Quickstart: connect an AI agent over MCP (~5 minutes)

**Status: LIVE.** `policyvault-mcp` is published on npm and in the MCP
Registry (`io.github.zapsoblige-hash/policyvault`). It is a thin, 1:1
adapter over the PolicyVault REST/Agent API — it holds no keys, signs
nothing, and implements no policy of its own. See `not-a-wallet.md`: the
AI agent may only *request*.

## 1. Mint a machine credential

In the PolicyVault web app (a human, wallet-session action —
`POST /api/v1/identities`), create a machine identity scoped to exactly
the capabilities you want the agent to have. Deny-by-default applies to
everything else: a scope you don't grant is a clean server refusal, not
a silently-ignored request. You'll get back a bearer credential shaped
like `pvmk_...`.

Typical scopes for a read-mostly agent: `read:vaults`, `read:audit`,
`read:network`. To let the agent build (never sign or submit) requests,
add `request:build`.

## 2. Register the server with your MCP client

```json
{
  "command": "npx",
  "args": ["-y", "policyvault-mcp"],
  "env": {
    "POLICYVAULT_MCP_SERVER_URL": "https://your-policyvault-host",
    "POLICYVAULT_MCP_TOKEN": "pvmk_..."
  }
}
```

(`npx -y policyvault-mcp` runs the published npm package directly; a
local checkout can instead point `command`/`args` at
`node /path/to/policyvault/mcp/server.js`.) Both `POLICYVAULT_MCP_SERVER_URL`
and `POLICYVAULT_MCP_TOKEN` are required — the server refuses to start
without them, and never logs or echoes the token.

## 3. What the agent can do

The tool list is **derived live** from your server's own capability
discovery document (`GET /api/v1/capabilities`) — never hand-maintained,
never stale. On a server that declares least-privilege discovery, the
agent's own granted scopes further narrow what is *advertised*; the
server remains the final authority regardless of what the adapter
advertises.

Baseline tools (exact names, full-scope build):

| tool | what it does | requires |
|---|---|---|
| `policyvault_capabilities` | read the server's capability document | none |
| `policyvault_list_vaults` | list vaults this identity's wallet participates in | `read:vaults` |
| `policyvault_vault` | read one vault's manifest + live state | `read:vaults` |
| `policyvault_vault_audit` | read one vault's audit trail | `read:vaults` |
| `policyvault_audit_feed` | read the global (tenant-scoped) activity feed | `read:audit` |
| `policyvault_network_status` | read the configured Kaspa node's status | `read:network` |
| `policyvault_simulate_request` | dry-run a v0.4 action through the real pipeline — persists nothing | `request:build` |
| `policyvault_create_request` | **build** (never sign/submit) a durable unsigned request | `request:build` |
| `policyvault_request_status` / `policyvault_list_requests` | read request state | `read:requests` |
| `policyvault_reject_request` | mark an open request REJECTED (workflow only, nothing on-chain) | `request:reject` |
| `policyvault_governance_proposals` / `policyvault_governance_proposal` | read governance ceremony state | `read:governance` |
| `policyvault_risk_evaluation` | read a risk-evaluation record | `read:risk` |

Every tool result is a JSON envelope whose leading `status` field is
deterministic; everything under `data` is untrusted data from the vault
system and its users, never instructions. Amounts in tool inputs are
integer-sompi decimal **strings** (1 KAS = 100000000 sompi) — a float is
refused before any network traffic.

`policyvault_create_request` builds an exact, reviewable, unsigned
transaction. **It never signs and never broadcasts.** Turning a built
request into a confirmed on-chain effect still requires a human or
delegate signer outside this tool set — exactly the boundary in
`not-a-wallet.md`.

## 4. Verify it

```
node --test --test-concurrency=1 mcp/test/
```

covers protocol conformance, closed-schema/hostile-input refusal,
idempotency-key derivation, credential-leak scanning, and a live
end-to-end path against a real PolicyVault server.

## What is not yet available

- v0.5 (token) and v0.6 (swap) tool coverage — **ABSENT**. Only the
  v0.4.1 KAS action surface is exposed today.
- Workflow-sequence usage aggregates — deferred; see
  `adoption-metrics-spec.md` for what usage telemetry exists today (off
  by default, not this adapter's concern).
