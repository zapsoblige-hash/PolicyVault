-- PolicyVault Platform Agent API — machine identities, machine credentials,
-- and idempotency records (docs/postlaunch/platform-agent-api-spec.md).
--
-- NOT part of server/src/store.js's Categories/PgStore (that abstraction is
-- an EXISTING sdk/src file this worker does not own/edit). These tables are
-- owned and accessed exclusively by server/src/platform-store.js, which
-- mirrors the SAME shape discipline as every other category table:
-- (network_id, key) PRIMARY KEY + jsonb value, create-only via
-- INSERT ... ON CONFLICT DO NOTHING (the link()/EEXIST equivalent for the
-- JSON backend, implemented in platform-store.js with the SAME fsync-rename
-- primitives sdk/src/durable-json.js uses elsewhere).
--
-- machine_identities   — first-class AI/machine principals (surface 6).
--   key = identityId (uuid). value = policyvault-machine-identity/v1
--   { identityId, networkId, creatorXOnly, orgId|null, label, scopes:[...],
--     status: ACTIVE|REVOKED, createdAt, updatedAt, revokedAt|null }.
--   Tenancy: creatorXOnly is the authenticated wallet that created the
--   identity (never a separate ownership fact — mirrors tenancy.js's rule
--   that hosted access always derives from a real signing identity).
--
-- machine_credentials  — bearer API-key credentials for an identity.
--   key = SHA-256(raw token) hex (64-hex) — the SAME "hash the bearer
--   secret, key the store by the hash" pattern server/src/auth.js uses for
--   sessions (auth_sessions.token_hash). The raw token is NEVER stored;
--   it is shown to the caller exactly once at mint time.
--   value = policyvault-machine-credential/v1
--   { credentialId, identityId, networkId, status: ACTIVE|REVOKED, label,
--     createdAt, lastUsedAt, revokedAt|null }.
--   Multiple credentials per identity support zero-downtime rotation:
--   mint a new one, deploy it, then revoke the old one.
--
-- idempotency_records  — durable key -> response mapping for
-- Idempotency-Key-bearing mutating POST requests (surface 14).
--   key = "<principalScope>:<caller-supplied Idempotency-Key>" — scoped per
--   authenticated identity (machine identity, hosted wallet session, or a
--   fixed self-hosted scope) so two different callers can never collide or
--   replay each other's keys.
--   value = policyvault-idempotency-record/v1
--   { status: IN_PROGRESS|COMPLETE, requestHash, response:{status,body}|null,
--     createdAtMs, completedAtMs|null }.
--   A CLAIMED (IN_PROGRESS) record that never completes (a crashed
--   in-flight handler) is reclaimable after a bounded staleness window —
--   see server/src/idempotency.js IN_PROGRESS_STALE_MS — never open-ended.

CREATE TABLE machine_identities (
  network_id text  NOT NULL,
  key        text  NOT NULL,            -- identityId (uuid)
  value      jsonb NOT NULL,            -- policyvault-machine-identity/v1
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (network_id, key)
);
CREATE INDEX machine_identities_creator_idx
  ON machine_identities (network_id, (value->>'creatorXOnly'));
CREATE INDEX machine_identities_org_idx
  ON machine_identities (network_id, (value->>'orgId'));

CREATE TABLE machine_credentials (
  network_id text  NOT NULL,
  key        text  NOT NULL,            -- SHA-256(raw token) hex — never the raw token
  value      jsonb NOT NULL,            -- policyvault-machine-credential/v1
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (network_id, key)
);
CREATE INDEX machine_credentials_identity_idx
  ON machine_credentials (network_id, (value->>'identityId'));

CREATE TABLE idempotency_records (
  network_id text  NOT NULL,
  key        text  NOT NULL,            -- "<principalScope>:<idempotencyKey>"
  value      jsonb NOT NULL,            -- policyvault-idempotency-record/v1
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (network_id, key)
);
CREATE INDEX idempotency_records_created_idx
  ON idempotency_records (network_id, ((value->>'createdAtMs')::bigint));
