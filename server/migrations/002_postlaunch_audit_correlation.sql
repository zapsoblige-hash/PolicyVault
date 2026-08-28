-- PolicyVault post-launch audit correlation (completion-standard item 7).
-- Implements docs/postlaunch/audit-correlation-spec.md §5.1 EXACTLY.
--
-- Purely additive: one new table, five NULLABLE columns on audit_events,
-- new indexes. No existing row is rewritten, no existing column changes,
-- and NO verification claim is ever backfilled (spec §10): a NULL
-- correlation column means "recorded before intent-manifest correlation"
-- — a plain historical fact, never a default claim.
--
-- Audit rows describe; the chain decides (spec §1). Nothing in this
-- schema grants or verifies covenant authority.

-- One row per DISTINCT verified intent manifest, keyed by its
-- representation-independent hash. Write-once (create-only).
CREATE TABLE intent_manifests (
  network_id text  NOT NULL,
  key        text  NOT NULL,            -- manifestHash (64-hex)
  value      jsonb NOT NULL,            -- policyvault-intent-manifest-record/v1
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (network_id, key)
);
CREATE INDEX intent_manifests_request_idx
  ON intent_manifests (network_id, (value->>'requestId'));
CREATE INDEX intent_manifests_txid_idx
  ON intent_manifests (network_id, (value->>'txId'));
CREATE INDEX intent_manifests_vault_idx
  ON intent_manifests (network_id, (value->>'vaultId'));

-- Correlation columns on the audit stream (nullable: old rows predate
-- them, system events have no wallet actor, metadata events have no tx).
ALTER TABLE audit_events
  ADD COLUMN request_id    text,
  ADD COLUMN manifest_hash text,
  ADD COLUMN proposal_id   text,
  ADD COLUMN tx_id         text,
  ADD COLUMN actor_xonly   text;
CREATE INDEX audit_events_txid_idx
  ON audit_events (network_id, tx_id)         WHERE tx_id IS NOT NULL;
CREATE INDEX audit_events_request_idx
  ON audit_events (network_id, request_id)    WHERE request_id IS NOT NULL;
CREATE INDEX audit_events_manifest_idx
  ON audit_events (network_id, manifest_hash) WHERE manifest_hash IS NOT NULL;
CREATE INDEX audit_events_actor_idx
  ON audit_events (network_id, actor_xonly)   WHERE actor_xonly IS NOT NULL;

-- Vault-scoped walks over evidence keyed by txid.
CREATE INDEX receipts_vault_idx
  ON receipts (network_id, (value->>'vaultId'));
-- Request rows already have wallet_requests_vault_idx; the manifest
-- hash inside the envelope gets an expression index (jsonb field is
-- additive — no ALTER needed for the envelope itself):
CREATE INDEX wallet_requests_manifest_idx
  ON wallet_requests (network_id, (value->>'manifestHash'));
