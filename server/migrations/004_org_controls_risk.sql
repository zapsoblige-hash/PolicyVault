-- PolicyVault per-organization controls + risk-evaluation evidence
-- (Program D server wiring; docs/postlaunch/risk-adapter-spec.md §7
-- "Server wiring" + docs/postlaunch/server-integration.md).
--
-- NOT part of the audit-correlation spec's 002/003 sketch: this is the
-- persisted "new config surface" the operational risk pipeline requires
-- (per-organization adapter configuration + governance ceremony
-- configuration) plus the durable risk-evaluation workflow/evidence
-- object (ALLOW/REVIEW/DENY outcomes, REVIEW holds and their releases).
--
-- Same shape discipline as every category table: (network_id, key)
-- PRIMARY KEY + jsonb value. Purely additive. These rows are METADATA-
-- PLANE records (docs/postlaunch/governance-spec.md §2.1): rewriting
-- them can change hosted WORKFLOW ceremony and displays, never covenant
-- authority — adapters and governance config can only make PolicyVault
-- MORE restrictive, and the covenant boundary is independent of both.

-- One controls record per organization (key = orgId): governance quorum
-- and delay configuration + risk adapter configuration.
CREATE TABLE org_controls (
  network_id text  NOT NULL,
  key        text  NOT NULL,            -- orgId (uuid)
  value      jsonb NOT NULL,            -- policyvault-org-controls/v1
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (network_id, key)
);

-- One row per risk evaluation (key = evaluationId, uuid): the full
-- composed adapter result (evidence) plus the REVIEW-hold workflow
-- state (HELD -> RELEASED -> CONSUMED). Evidence fields are write-once
-- in application discipline; only the workflow status/stamps mutate.
CREATE TABLE risk_evaluations (
  network_id text  NOT NULL,
  key        text  NOT NULL,            -- evaluationId (uuid)
  value      jsonb NOT NULL,            -- policyvault-risk-evaluation/v1
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (network_id, key)
);
CREATE INDEX risk_evaluations_vault_idx
  ON risk_evaluations (network_id, (value->>'vaultId'));
CREATE INDEX risk_evaluations_intent_idx
  ON risk_evaluations (network_id, (value->>'intentHash'));
