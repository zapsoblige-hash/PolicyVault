# MCP production interface — protocol, tool catalog, auth, injection stance

Status: IMPLEMENTED + UNIT-TESTED (protocol conformance + adversarial
suites against a mock API) + INTEGRATION-PROVEN (real `server/src/server.js`
over real HTTP with a real machine identity, real scope enforcement, a real
silverc-built v0.4 request, and a real subprocess over actual stdio). NOT
TESTNET-VERIFIED (no tool here broadcasts, so live-testnet applicability is
limited to what the underlying API routes already prove). NOT yet covered
by the dedicated hostile-AI-agent/prompt-injection review (completion-
standard surface 26 — this spec §8 documents the stance that review must
attack). Covers `FULLSCALE_COMPLETION_ADDENDUM.md` surface 7 (MCP
production interface).

Implementation: `mcp/` (`server.js` + `src/config.js`, `src/schema.js`,
`src/tools.js`, `src/http.js`, `src/envelope.js`, `src/idempotency.js`).
Zero new runtime npm dependencies — the MCP protocol and transport are
implemented directly on `node:` builtins.

## 1. Security model (binding)

**AI MAY REQUEST. POLICYVAULT DETERMINISTICALLY DECIDES.** The MCP layer is
a THIN adapter: every tool call is translated into an ordinary
authenticated HTTP request to the same `/api/v1` surface every client
uses (`docs/postlaunch/platform-agent-api-spec.md` is the underlying
contract). It implements NO financial authority, NO policy semantics, NO
successor derivation, NO verification, NO signing, NO broadcasting, and
holds NO keys. There is no privileged path: a scope the machine credential
does not hold is the server's own `403 SCOPE_FORBIDDEN`, passed through
unchanged; tenancy, governance, risk, and covenant enforcement are exactly
the hosted platform's, untouched. If the MCP process is absent or
compromised-then-killed, core PolicyVault safety and function are
unaffected (degradation guarantees: §9).

## 2. Protocol revisions implemented

The adapter implements the Model Context Protocol **initialization-based
("legacy"-era) revisions `2025-11-25` and `2025-06-18`** (researched from
modelcontextprotocol.io on 2026-08-26): JSON-RPC 2.0 messages over
**stdio**, one message per line, newline-delimited, UTF-8, no embedded
newlines; stdout carries ONLY protocol messages (tested on every emitted
line); stderr carries optional one-line diagnostics. JSON-RPC **batch
arrays are refused** with `-32600` (batching was removed in 2025-06-18 and
stayed removed). Streamable HTTP/SSE transports are intentionally out of
scope for v1 — stdio is the production target (the platform API itself is
the multi-client network surface).

At the time of writing the CURRENT MCP revision is `2026-07-28`
("modern" era: per-request `_meta` protocol-version declaration and a
mandatory `server/discover` RPC; no initialize handshake). v1 of this
adapter deliberately implements the legacy era, because deployed MCP
clients speak it and the mission pins `initialize`/capability negotiation.
The 2026-07-28 backward-compatibility rules define exactly how a dual-era
client detects a legacy server on stdio: probe `server/discover` and fall
back on any error that is not a recognized modern error. This server
answers `server/discover` with a plain `-32601` method-not-found — the
precise "legacy server, fall back to initialize" signal (tested).

### 2.1 Lifecycle

- `initialize` (must be first; refused with `-32600` if repeated):
  validates `params.protocolVersion` (string, else `-32602`); if the
  requested version is supported it is echoed, otherwise the response
  carries the newest supported version (`2025-11-25`) per the spec's
  negotiation rule, and a client that cannot accept it disconnects.
  The response declares `capabilities: { tools: {} }` (no `listChanged`:
  the catalog is fixed per session), `serverInfo`
  (`name: "policyvault-mcp"`, version from `mcp/package.json`, plus the
  2025-11-25 optional `description`), and defensive `instructions`
  (§8.4).
- `notifications/initialized` marks the session operational. Requests
  other than `ping`/`initialize` before `initialize` are refused with
  the de-facto standard `-32002` "Server not initialized"
  (implementation-defined: the published spec pages prescribe no code for
  this; `-32002` is the ecosystem SDK convention).
- `ping` answers `{}` at any time.
- `tools/list` returns the whole catalog in one page (`nextCursor` never
  issued; a supplied `cursor` is `-32602`).
- `tools/call` per §5/§6.
- `notifications/cancelled` aborts the named in-flight call (the upstream
  HTTP request is aborted) and its response is SUPPRESSED entirely, per
  the cancellation utility. Unknown notifications are ignored silently;
  uncorrelated response messages are ignored (this server never issues
  its own requests, so client-capability features — sampling,
  elicitation, roots — are unused).
- Shutdown: closing stdin exits the process cleanly (tested in a real
  subprocess).

### 2.2 Error codes

| Code | Used for |
|---|---|
| `-32700` | unparseable line; a line exceeding the 4 MiB line cap (single deterministic refusal, session keeps serving) |
| `-32600` | non-object message, wrong `jsonrpc`, batch array, `id: null` request, repeated `initialize`, duplicate in-flight id |
| `-32601` | unknown method (including `server/discover` — see era stance) |
| `-32602` | malformed `initialize`/`tools/list`/`tools/call` params; **unknown tool name** |
| `-32603` | internal adapter defect (generic text only — nothing propagated) |
| `-32002` | request before initialization (implementation-defined) |

Invalid tool ARGUMENTS are deliberately NOT `-32602`: per the 2025-11-25
clarification (SEP-1303), input-validation failures return as **tool
execution errors** (`isError: true`, envelope status `SCHEMA_REFUSED`)
so the calling model can self-correct.

## 3. Configuration & credential handling

Environment only (see `mcp/README.md` for the operator table):
`POLICYVAULT_MCP_SERVER_URL` (bare origin; refused if it embeds userinfo
or a path; plaintext `http://` only for loopback unless
`POLICYVAULT_MCP_ALLOW_INSECURE_HTTP=1`, documented for private
separately-encrypted operator transports only) and `POLICYVAULT_MCP_TOKEN`
(machine credential; shape-checked against the server's own
`\S{20,300}` pre-filter). The adapter refuses to start without them.

Secret rules (all tested, including a grep of every byte of stdout+stderr
across success/refusal/transport-failure/config-failure paths, in-process
AND subprocess): the token is read once, deleted from `process.env`, held
behind a closure (`JSON.stringify(config)` cannot leak it), never logged,
never echoed in any error (config errors name the RULE, never the value),
and sent ONLY as the `Authorization` header of API calls — except the
public `GET /api/v1/capabilities` fetch, which is sent anonymously
(least exposure).

Origin-policy interaction: the adapter sends no cookies and no Origin
header; it authenticates purely by bearer credential, which is exactly the
non-ambient programmatic-client case `platform-agent-api-spec.md` §6
carves out of the browser CSRF wall.

## 4. Tool catalog

### 4.1 Dynamic derivation (no hand-maintained drift)

At startup the adapter fetches `GET /api/v1/capabilities` and FAILS CLOSED
(exit 3) if the fetch fails, the document's `schemaVersion` is not
`policyvault-capabilities/v1`, or any consumed value is off-shape — there
is no static fallback catalog. From the validated document:

- a tool is ACTIVATED only if every scope it requires appears in the
  document's scope enum (a build that drops a scope silently drops the
  tool — tested) and its feature flag (e.g. `dryRunSimulation`) is true;
- the v0.4 `action` enum inside tool schemas is copied from
  `capabilities.actions.v4` (the server's literal `ROLE_BY_ACTION`
  export; asserted equal to the SDK export end-to-end);
- request bodies pin `schemaVersion` to `schemas.walletV4Request`, so
  wire-schema drift surfaces as the server's clean
  `422 SCHEMA_VERSION_UNSUPPORTED`, never silent reinterpretation;
- `POLICYVAULT_MCP_SCOPES` (env) can only NARROW what is advertised —
  advertisement is cosmetic; enforcement is always server-side per call.

The server cannot report a credential's granted scopes to the credential
itself (identity management is wallet-session-only by structural rule), so
the advertised catalog is the BUILD's capability surface; a call outside
the credential's grants surfaces as the pass-through `403` (§6).

### 4.2 Catalog (v1)

| Tool | Route | Scopes | Mutating |
|---|---|---|---|
| `policyvault_capabilities` | `GET /capabilities` | — (public) | no |
| `policyvault_list_vaults` | `GET /vaults` | `read:vaults` | no |
| `policyvault_vault` | `GET /vaults/:vaultId` | `read:vaults` | no |
| `policyvault_vault_audit` | `GET /vaults/:vaultId/audit` | `read:vaults` | no |
| `policyvault_audit_feed` | `GET /audit?limit` | `read:audit` | no |
| `policyvault_network_status` | `GET /network/status` | `read:network` | no |
| `policyvault_simulate_request` | `POST /wallet/v4/simulate` | `request:build` (¹) | no (persists nothing) |
| `policyvault_create_request` | `POST /wallet/v4/requests` | `request:build` (¹) | yes (durable request; idempotent) |
| `policyvault_request_status` | `GET /wallet/v4/requests/:id` | `read:requests` | no |
| `policyvault_list_requests` | `GET /wallet/v4/requests?vaultId&open` | `read:requests` | no |
| `policyvault_reject_request` | `POST /wallet/v4/requests/:id/reject` | `request:reject` | yes (workflow record only; idempotent) |
| `policyvault_governance_proposals` | `GET /governance/proposals?vaultId&limit` | `read:governance` | no |
| `policyvault_governance_proposal` | `GET /governance/proposals/:id` | `read:governance` | no |
| `policyvault_risk_evaluation` | `GET /risk/evaluations/:id` | `read:risk` | no |

(¹) `ownerPause`/`ownerRecover` additionally require `request:break-glass`
SERVER-side (`server/src/scopes.js`); the discovery document does not
enumerate the break-glass action set, so this is stated in the static tool
description and enforced — as everything is — by the server.

**Deliberate v1 exclusions** (documented, not oversights): signature
attach/approvals (externally produced signature material belongs to signer
tooling, not an LLM channel), submit/genesis-submit (broadcast is a
separately-scoped, deliberately non-MCP step in v1 — an agent that should
broadcast can use the REST API directly under `request:submit`),
governance propose/approve/cancel and risk release (human ceremonies:
approvals are owner-signature acts, and risk release must not be
performable by the initiating agent), organization management, machine-
identity management (wallet-session-only by structural rule — a token can
never mint or widen authority, so an MCP tool for it is impossible by
construction), v0.2 legacy routes, and genesis creation (`/wallet/v4/create`
carries UTXO funding selection; v1 keeps MCP to existing-vault
operations).

### 4.3 Input schemas (closed)

Every `inputSchema` is CLOSED: `additionalProperties: false`, exact types,
bounded strings/arrays, validated by `mcp/src/schema.js` BEFORE any HTTP.
Conventions:

- consensus amounts are integer-sompi decimal STRINGS
  (`^(0|[1-9][0-9]{0,19})$`) — floats are structurally impossible, and
  numeric-looking hostility (`"1.5"`, `"1e3"`, `"-5"`, `"05"`, unicode
  digits) fails the anchored ASCII pattern;
- ids: vault/pubkey/txid `^[0-9a-f]{64}$` (lowercase only);
  request/proposal/evaluation ids are UUIDs; addresses
  `^(kaspa|kaspatest):[a-z0-9]{20,120}$` (ASCII-only, so unicode
  confusables are refused at the boundary — full canonical validation
  remains the SDK's);
- `params` is a closed union of the v0.4 SDK parameter fields (typed
  fuel/agent-entry/approver sub-schemas). Which params a given action
  REQUIRES is deliberately not re-encoded: `planV4` is the single
  authority (anti-bloat), and its refusals pass through;
- caps: arguments serialized > 128 KiB refused pre-validation; arrays
  bounded (recipients ≤ 128, approvers ≤ 16); validator depth/node
  budgets bound pathological nesting.

`outputSchema` on every tool advertises the envelope (§6) frame.
Annotations are honest: `readOnlyHint` true except
create/reject, `destructiveHint` false, `idempotentHint` true for the two
mutating tools (derived keys), `openWorldHint` false.

## 5. Request mapping

Path parameters are pattern-validated then URI-encoded (no traversal);
query strings are built only from schema-validated values; bodies are
constructed field-by-field from validated arguments (never spread from
client input), with the discovery-pinned `schemaVersion` added. One HTTP
attempt per tool call — the adapter NEVER retries (a 409/429/5xx is
returned to the caller as data; retry policy belongs to the agent and the
server's idempotency layer makes retries safe). Per-call timeout
(`POLICYVAULT_MCP_HTTP_TIMEOUT_MS`, default 60 s) via abortable requests;
MCP cancellation aborts the underlying HTTP request.

## 6. Result envelope

Every tool result: `structuredContent` =

```
{ "status": "OK" | "REFUSED" | "SCHEMA_REFUSED" | "TRANSPORT_ERROR",
  "schema": "policyvault-mcp-result/v1",
  "tool": "<tool name>",
  "httpStatus": <int|null>,
  "replayedIdempotency": true,            // only when the server marked a replay
  "notice": "<fixed untrusted-data notice>",
  "data": <server body | {schemaErrors} | {reason,target,detail}> }
```

with `content: [{ type: "text", text: JSON.stringify(structuredContent) }]`
EXACTLY (spec: structured results also serialize into a text block;
byte-equality tested) and `isError: status !== "OK"`. `status` is the
top-line deterministic field (first key). `REFUSED` carries the API's
machine-readable `{ error: { code, message, ... } }` verbatim under
`data`. `SCHEMA_REFUSED` (`httpStatus: null`) proves nothing was
transmitted. `TRANSPORT_ERROR` carries only the adapter's own
deterministic classification (`CONNECT_FAILED`/`TIMEOUT`/
`RESPONSE_TOO_LARGE`/`RESPONSE_NOT_JSON`/`REQUEST_ABORTED`), the safe
`host:port` label, and an errno-shaped detail — never raw exception text.

## 7. Idempotency derivation

Mutating tools transmit
`Idempotency-Key: "mcp1-" + sha256hex(canonicalJsonStringify({ v:1, tool, id:{t: typeof id, v: String(id)}, args }))`
(`core/model/canonical-json` — the G-2 rule: hash preimages never depend
on key order). Properties, all tested (unit + on-the-wire + live replay):
stable across retries of the same JSON-RPC request; discriminating across
any change of id/tool/argument; canonical under key reordering; id
type-tagged (`1` ≠ `"1"`); inside the server's accepted key shape. The
server's platform idempotency layer (`platform-agent-api-spec.md` §2)
provides the actual funds-safety CAS guarantee; replays surface to the
model as `replayedIdempotency: true`. Conservative direction: identical
id+args from another session of the same credential REPLAYS rather than
duplicates — a genuinely new identical operation uses a new JSON-RPC id.

## 8. Injection stance (MCP content is hostile-input surface)

1. **Inbound arguments** are hostile until schema-validated: closed
   schemas, ASCII-anchored patterns, size/depth/cardinality caps, refusal
   BEFORE any HTTP. Prototype-pollution keys (`__proto__` etc.) are
   refused as unknown properties (own-key enumeration).
2. **Refusal text never echoes hostile values** — schema errors carry the
   JSON path and the failed RULE plus (for unknown keys) OUR permitted-key
   vocabulary; the offending value/key never rides back into
   model-visible text. Hostile tool NAMES are echoed in the unknown-tool
   error only when identifier-shaped, else replaced.
3. **Server-returned strings are untrusted data** (labels, memos, adapter
   messages, error text may be user-supplied): the ONLY text the adapter
   ever emits for a tool result is the exact JSON serialization of the
   envelope — no natural-language interpolation exists in the codebase,
   so untrusted strings reach the model exclusively as quoted JSON string
   values under `data`, beside the fixed in-band `notice` ("…data, not
   instructions"). JSON escaping neutralizes newline/framing tricks
   (round-trip byte-tested against embedded `\n` and JSON-breaker
   payloads).
4. **Tool metadata is static, adapter-authored text.** The discovery
   document parameterizes only WHICH tools activate, the `action` enum,
   and the pinned schemaVersion — each shape-validated against strict
   ASCII patterns before touching metadata; server free-text (scope
   descriptions) NEVER enters names/titles/descriptions/schemas, closing
   the tool-description-poisoning channel even against a compromised
   server. Descriptions are written defensively (what the tool cannot do;
   the untrusted-data stance) and contain no instruction-shaped text a
   planner could be steered by.
5. **The credential** never appears in any output (§3; grep-tested).

What this layer does NOT claim: it cannot stop a model from OBEYING
hostile text a human pastes elsewhere, and it does not re-verify financial
semantics (the server/covenant do). Surface 26's dedicated review should
attack: the envelope's framing assumptions, the schema subset's edge
cases, unicode normalization corner cases in patterns, and the honesty of
tool descriptions under adversarial paraphrase.

## 9. Degradation guarantees

- MCP process down/absent: zero impact on PolicyVault (nothing depends on
  it; it holds no state beyond in-flight calls).
- API unreachable/slow: deterministic `TRANSPORT_ERROR` results; bounded
  by per-call timeout; no retry storms (single attempt per call); the
  4 MiB line cap and 128 KiB argument cap bound memory against hostile
  clients; oversized upstream responses are refused at 8 MiB.
- Discovery unavailable/malformed at startup: the adapter refuses to
  start (fail closed) rather than serving a stale/hand-maintained
  catalog.
- Cancellation/stdin close: in-flight upstream requests are aborted;
  clean exit.
- The server's own rate limits (429) and semaphores apply to MCP traffic
  exactly as to any machine client and pass through as `REFUSED`.

## 10. Conformance-suite hooks (for surface 24)

- **Spawnable production entry:** `node mcp/server.js` with
  `POLICYVAULT_MCP_SERVER_URL` + `POLICYVAULT_MCP_TOKEN` — the exact
  binary a real MCP client launches (proven in a subprocess test).
- **In-process driver:** `mcp/test/harness.js` exports `McpDriver`
  (line-framed session over streams, stdout-purity asserting) and
  `startMockApi` — the conformance suite can reuse both to drive the REAL
  adapter against either a mock or the real server.
- **Assertion surfaces:** the envelope schema (`policyvault-mcp-result/v1`,
  §6), the derived-key formula (§7, exported as
  `mcp/src/idempotency.js`), `SUPPORTED_PROTOCOL_VERSIONS` and caps
  exported from `mcp/server.js`, and the catalog table (§4.2).
- **Reference end-to-end:** `mcp/test/mcp-live-server.test.js` is the
  canonical real-HTTP/real-scope/real-build path the conformance suite
  must keep exercising (addendum rule: real reference MCP path, not
  mocks).

## 11. Evidence

| Item | Files | Tests |
|---|---|---|
| Protocol conformance (lifecycle, negotiation, framing, errors, cancellation, concurrency, dynamic derivation) | `mcp/server.js`, `mcp/src/tools.js` | `mcp/test/mcp-protocol.test.js` 15/15 |
| Hostile input / closed schemas / secret handling / server-string injection / scope passthrough / idempotency | `mcp/src/schema.js`, `mcp/src/envelope.js`, `mcp/src/idempotency.js`, `mcp/src/config.js`, `mcp/src/http.js` | `mcp/test/mcp-schema-hostile.test.js` 9/9 |
| Live end-to-end (real server, real machine identity, real scope refusals, real build + cross-session idempotent replay, real subprocess stdio) | all of `mcp/` | `mcp/test/mcp-live-server.test.js` 8/8 |

Run: `node --test --test-concurrency=1 mcp/test/`.

## 12. Claim labels

DESIGNED + IMPLEMENTED + UNIT-TESTED + INTEGRATION-PROVEN (real HTTP
server, real machine identity + scopes, real silverc build, real
subprocess stdio). NOT TESTNET-VERIFIED. NOT EXTERNALLY REVIEWED. The
dedicated hostile-AI-agent/prompt-injection security review (surface 26)
remains a separate, unstarted gate and must treat §8 as the attack map,
not as a completed defense audit.
