-- PolicyVault hosted-layer AGENT SUSPENSIONS (fullscale surface 21 residual:
-- instant hosted-layer suspend; docs/postlaunch/hosted-agent-suspend.md).
--
-- COORDINATION CONTROL ONLY — NEVER A COVENANT CONTROL. A suspension makes
-- THIS server refuse to build/finalize/submit NEW agent-driven requests for
-- the suspended agent (instant, zero fees, no chain interaction). It does
-- NOT and CANNOT bind the covenant: a malicious actor holding the
-- legitimate delegate key can still construct and submit transactions
-- directly to a Kaspa node, and only the covenant's own consensus rules
-- constrain what such transactions can do. The covenant-enforced controls
-- (ownerPause freeze, ownerSetAgentRoot/removeAgent, ownerRecover) remain
-- the security boundary; a suspension is the owner's INSTANT hosted
-- stopgap while (or instead of) executing one of those on-chain actions.
--
-- Owned and accessed exclusively by server/src/agent-suspensions.js via
-- server/src/platform-store.js (same shape discipline as migration 005:
-- (network_id, key) PRIMARY KEY + jsonb value).
--
-- agent_suspensions — ONE record per vault.
--   key = vaultId (64-hex). value = policyvault-agent-suspensions/v1
--   { vaultId, networkId, version, allAgents: bool, agents: [xonly...]
--     (sorted, unique), updatedAt, updatedBy: { type: wallet|machine|
--     operator, identityId|null } }.
--   version supports expectedVersion CAS (org-controls discipline).

CREATE TABLE agent_suspensions (
  network_id text  NOT NULL,
  key        text  NOT NULL,            -- vaultId (64-hex)
  value      jsonb NOT NULL,            -- policyvault-agent-suspensions/v1
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (network_id, key)
);
