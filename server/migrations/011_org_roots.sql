-- v0.7 ON-CHAIN ORGANIZATIONAL ROOT durable records
-- (docs/postlaunch/v0.7-app-surface-contract.md §1).
--
-- ORG_ROOT and ORG_ROOT_REQUEST are ordinary (network_id, key) -> jsonb
-- records, exactly the shape every other category in sdk/src/store.js uses
-- (governance_proposals, org_controls, ...). Rooted vaults reuse the
-- EXISTING `vaults` table (sdk/src/manifest-v7.js writes Categories.VAULT) —
-- no new table for them.
--
-- These rows are COORDINATION state, never authority: only
-- sdk/src/reconcile-v7.js (proven chain readback) may advance an org_roots
-- row's state/live/generation, and every slot-signature envelope is
-- verified against the request's manifest hash, the slot's committed public
-- key, and the unsigned transaction before being stored. Covenant financial
-- authority moves ONLY through owner-slot Schnorr signatures over frozen
-- transaction bytes, verified by Kaspa consensus.

CREATE TABLE org_roots (
  network_id text  NOT NULL,
  key         text  NOT NULL,           -- rootCovenantId (64-hex)
  value       jsonb NOT NULL,           -- policyvault-org-root-record/1
  updated_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (network_id, key)
);
CREATE INDEX org_roots_org_idx ON org_roots (network_id, (value->>'orgId'));

CREATE TABLE org_root_requests (
  network_id text  NOT NULL,
  key         text  NOT NULL,           -- requestId (uuid)
  value       jsonb NOT NULL,           -- policyvault-org-root-request/1
  updated_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (network_id, key)
);
CREATE INDEX org_root_requests_root_idx
  ON org_root_requests (network_id, (value->>'rootCovenantId'));
CREATE INDEX org_root_requests_state_idx
  ON org_root_requests (network_id, (value->>'state'));
