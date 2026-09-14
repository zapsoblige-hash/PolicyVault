# PolicyVault MCP server

> **Package version 1.6.2 — native-KAS treasury mappings (proposed successor of the published 1.5.0; 1.6.0 and 1.6.1 were packed for application candidates that were blocked by independent review and were never published).** This package version carries the v0.7 organizational-root tool set (since 1.5.0) **and** the rooted native-KAS treasury extensions: `policyvault_create_v7_request` accepts `agentSpend` (a delegate payment from a rooted KAS treasury, vault-level approvals above the delegate's threshold collected through the server's approvals route) and `policyvault_create_org_root_request` accepts the vault operations `ownerSetApprovers` and `ownerTopUp` on a rooted KAS treasury. The published `policyvault-mcp@1.5.0` does NOT contain these schemas. The npm registry is the authority for what is delivered: until `npm view policyvault-mcp version` reports `1.6.2` (or later), native-KAS MCP support exists only in a source checkout, and no record may claim it delivered. Publication of 1.6.2 is conditional on the independent review, deployment and served verification of the application release that carries the same tool bytes (the exact matching application and public-source identities recorded in its release manifest); the tarball is packed, audited and consumer-tested before that review and published unchanged afterwards. Whether a KAS treasury may be created or operated on a network is decided by the server's capability discovery and generation gates (the KAS profile is a CANDIDATE covenant until its byte freeze is attested), never by this adapter.

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
- `policyvault_org_roots`, `policyvault_org_root`,
  `policyvault_org_root_requests` — read-only v0.7 organizational-root
  reads (since 1.5.0); `policyvault_create_org_root_request` and
  `policyvault_create_v7_request` — build-only root-authorized and
  rooted-vault requests (since 1.5.0), extended in 1.6.x with the native-KAS
  treasury mappings (`agentSpend`; `ownerSetApprovers` / `ownerTopUp` as
  root-carried vault operations). Every request is unsigned and signing
  stays with external signer custody.

**Recovery through MCP, stated precisely.** MCP exposes NO genesis, NO
signature and NO submit / broadcast tool of any kind (root genesis, rooted-
vault genesis, wallet genesis, signature attach, submit, reconcile and the
observation-only genesis recovery routes are REST / browser operations that
this adapter never reaches). `policyvault_create_org_root_request` accepts
the ROOT action `ownerRecover` — the organizational root's own owner-recovery
transition, built UNSIGNED (per-owner-slot signer envelopes; signatures are
collected out of band; the covenant enforces the consensus-level recovery
delay). The rooted-VAULT operation `ownerRecover` (the terminal recovery of a
rooted treasury's funds riding a root transition) is NOT accepted as a vault
operation by this adapter, so an unsigned root recovery request does NOT
imply rooted-vault recovery support — rooted-vault recovery stays a human
owner decision in the browser. Nothing here rebuilds, re-signs or rebroadcasts
a transaction.

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
