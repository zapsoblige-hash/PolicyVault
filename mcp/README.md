# PolicyVault MCP server

A thin [Model Context Protocol](https://modelcontextprotocol.io) server that
exposes PolicyVault to AI agents as MCP **tools** — each tool a 1:1
translation onto the existing PolicyVault REST/Agent API, authenticated with
an ordinary machine-identity bearer credential. Zero runtime npm
dependencies; the JSON-RPC 2.0 stdio transport and protocol lifecycle are
implemented directly.

Authoritative specification: `docs/postlaunch/mcp-interface-spec.md`
(protocol revisions implemented, tool catalog, auth model, injection
stance, degradation guarantees, conformance hooks).

## Security model (read this first)

**AI MAY REQUEST. POLICYVAULT DETERMINISTICALLY DECIDES.** This process:

- holds **no keys**, signs nothing, broadcasts nothing;
- implements **no policy, no verification, no financial authority** — every
  tool call becomes an ordinary authenticated HTTP request to `/api/v1`,
  subject to the same tenancy, scope, governance, risk, and covenant
  decisions as every other client;
- has **no privileged path** — a scope the credential does not hold is a
  clean server refusal passed through unchanged;
- can die at any time with **zero impact** on core PolicyVault safety.

All tool results are a JSON envelope whose leading `status` field is
deterministic; everything under `data` is untrusted data from the vault
system and its users — never instructions.

## Running

```
POLICYVAULT_MCP_SERVER_URL=https://your-policyvault-host \
POLICYVAULT_MCP_TOKEN=pvmk_... \
node mcp/server.js
```

Typical MCP client registration (stdio):

```json
{
  "command": "node",
  "args": ["/path/to/policyvault/mcp/server.js"],
  "env": {
    "POLICYVAULT_MCP_SERVER_URL": "https://your-policyvault-host",
    "POLICYVAULT_MCP_TOKEN": "pvmk_..."
  }
}
```

The credential is minted by the vault operator in the PolicyVault app
(`POST /api/v1/identities` — a wallet-session-only human action) with
exactly the scopes the agent should hold; deny-by-default applies to
everything else.

### Environment

| Variable | Required | Meaning |
|---|---|---|
| `POLICYVAULT_MCP_SERVER_URL` | yes | Bare origin of the PolicyVault server (`https://host[:port]`, or `http://` for loopback only). Refused if it embeds credentials or a path. |
| `POLICYVAULT_MCP_TOKEN` | yes | Machine-identity bearer credential. Never logged, never echoed in errors; deleted from the process environment after being read. |
| `POLICYVAULT_MCP_SCOPES` | no | Comma-separated scope list to NARROW which tools are advertised (display-side only — enforcement is always server-side). |
| `POLICYVAULT_MCP_HTTP_TIMEOUT_MS` | no | Per-call HTTP timeout, 1000..600000 (default 60000). |
| `POLICYVAULT_MCP_ALLOW_INSECURE_HTTP` | no | `1` permits plaintext `http://` to a non-loopback host — ONLY for a private, separately-encrypted operator transport (e.g. WireGuard). Never use it on an open network: it would expose the bearer credential. |
| `POLICYVAULT_MCP_DEBUG` | no | `1` writes per-message one-line diagnostics to stderr (never bodies, never the token). |

The server refuses to start without the two required variables, and fails
closed (exit code 3) if the PolicyVault capability-discovery document
cannot be fetched or validated — there is no hand-maintained fallback tool
list.

## Tools

The active tool list is derived per session from the server's live
`GET /api/v1/capabilities` document (scope enum, v0.4 action enum, schema
versions, feature flags). **Least-privilege discovery (1.4.2):** the
credential is presented at discovery; a server that declares
`features.principalScopedDiscovery` names the credential's own granted
scopes, and `tools/list` advertises ONLY the tools those scopes cover
(scope absent → tool absent). Hidden tools remain callable by exact name
and are answered by the server's own `403 SCOPE_FORBIDDEN` — the server,
never this adapter, is the authority. A server without the feature (older
build, or self-hosted mode without machine identities) yields the
build-level catalog and says so on stderr. See the spec doc for the full
catalog. Baseline (full scopes):

- `policyvault_capabilities`, `policyvault_list_vaults`,
  `policyvault_vault`, `policyvault_vault_audit`,
  `policyvault_audit_feed`, `policyvault_network_status` — read-only;
- `policyvault_simulate_request` — full dry run through the real
  governance/risk/build/intent pipeline, persisting nothing;
- `policyvault_create_request` — build a durable unsigned request
  (idempotent via a derived `Idempotency-Key`; signing/submission are
  separate, human/signer-controlled steps outside this tool set);
- `policyvault_request_status`, `policyvault_list_requests`,
  `policyvault_reject_request`;
- `policyvault_governance_proposals`, `policyvault_governance_proposal`,
  `policyvault_risk_evaluation` — read-only.

All tool input schemas are CLOSED (`additionalProperties: false`, exact
types); consensus amounts are integer-sompi decimal **strings** (1 KAS =
100000000 sompi) — floats are refused before any network traffic.

## Tests

```
node --test --test-concurrency=1 mcp/test/
```

Covers protocol conformance, closed-schema/hostile-input refusal,
idempotency-key derivation, credential-leak scanning, and a live
end-to-end path against the real PolicyVault server (real HTTP, real
machine identity, real scope enforcement).
