-- PolicyVault MCP USAGE TELEMETRY (Track 7; privacy-minimizing,
-- config-gated, OFF by default; docs/postlaunch/mcp-usage-telemetry-todo.md).
--
-- ONE row per recorded MCP-tool-shaped invocation reaching the platform
-- API through a resolved machine credential (server/src/mcp-telemetry.js,
-- wired from the EXISTING per-request principal-resolution hook in
-- server/src/api.js handle() — no new authentication/authorization path).
-- CREATE-ONLY, standard (network_id, key) jsonb category shape (key =
-- eventId uuid), accessed exclusively by server/src/mcp-telemetry.js via
-- server/src/platform-store.js — the SAME pattern as migrations 005/007/008.
--
-- PRIVACY (binding — enforced at construction in mcp-telemetry.js, never
-- at this layer): value NEVER carries prompts/model context; bearer
-- tokens or any credential material (raw or hashed); private keys; wallet
-- secrets; raw signing material (signatures, PSKTs, transaction bytes);
-- or request bodies. The closed field set is exactly: identityId (the
-- resolved MACHINE IDENTITY, never the credential or its hash),
-- mcpClient (an untrusted display string derived from the caller's
-- X-PolicyVault-MCP-Client request header, length-capped and
-- charset-validated before storage), tool (a closed route-class label —
-- the SAME enumeration server/src/metrics.js already uses, never a raw
-- path), method, outcome (success|refusal|error) + a closed refusal/
-- error code, latencyMs, at (ISO-8601, server clock), and an optional
-- requestId carried ONLY when it was already public in that same
-- response body.
--
-- Recording is entirely config-gated OFF by default
-- (POLICYVAULT_MCP_TELEMETRY unset/"off"): this table exists in every
-- schema from this migration forward, but stays EMPTY unless an operator
-- explicitly enables telemetry. Retention (default 90 days) and a hard
-- per-process storage cap are enforced in server/src/mcp-telemetry.js,
-- not by this schema.

CREATE TABLE mcp_telemetry_events (
  network_id text  NOT NULL,
  key        text  NOT NULL,            -- eventId (uuid)
  value      jsonb NOT NULL,            -- policyvault-mcp-telemetry-event/v1
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (network_id, key)
);
CREATE INDEX mcp_telemetry_events_identity_idx
  ON mcp_telemetry_events (network_id, (value->>'identityId'));
CREATE INDEX mcp_telemetry_events_at_idx
  ON mcp_telemetry_events (network_id, (value->>'at'));
