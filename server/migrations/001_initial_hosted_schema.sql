-- PolicyVault hosted persistence — initial schema (Phase C).
--
-- Design rules (docs/hosted-persistence.md):
--  * one table per durable object category, mirroring the proven
--    file-per-object JSON model: (network_id, key) PRIMARY KEY + jsonb
--    value. The composite key makes cross-network collision impossible
--    (directive §11) on top of the write-once database network stamp.
--  * UNIQUE primary keys are the race arbiters (directive §20):
--    transition_claims (exact predecessor outpoint) and
--    submission_claims (txid) turn INSERT ... ON CONFLICT DO NOTHING
--    into the link()/EEXIST claim acquisition of the JSON backend.
--  * audit_events is the append-only stream (bigserial preserves order).
--  * auth_challenges / auth_sessions carry the Phase B semantics with
--    database CAS single-use (state predicate) and hash-only tokens.
--  * NO wallet key material exists anywhere in this schema.
--  * Foreign keys: only where the JSON model guarantees parent-first
--    (org assignments -> organizations, RESTRICT: deleting a non-empty
--    org stays refused). Requests deliberately have NO FK to vaults:
--    genesis requests exist BEFORE the vault manifest (manifests are
--    created only after chain proof) — porting, not redesigning.

CREATE TABLE pv_meta (
  key   text PRIMARY KEY,
  value text NOT NULL
);

CREATE TABLE vaults (
  network_id text  NOT NULL,
  key        text  NOT NULL,            -- vaultId (64-hex)
  value      jsonb NOT NULL,            -- the manifest, verbatim
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (network_id, key)
);

CREATE TABLE wallet_requests (
  network_id text  NOT NULL,
  key        text  NOT NULL,            -- requestId (uuid)
  value      jsonb NOT NULL,            -- the durable request envelope
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (network_id, key)
);
CREATE INDEX wallet_requests_vault_idx
  ON wallet_requests (network_id, (value->>'vaultId'));

CREATE TABLE transition_claims (
  network_id text  NOT NULL,
  key        text  NOT NULL,            -- "<predecessor txid>-<index>"
  value      jsonb NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (network_id, key)         -- THE single-writer arbiter
);

CREATE TABLE submission_claims (
  network_id text  NOT NULL,
  key        text  NOT NULL,            -- txid
  value      jsonb NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (network_id, key)
);

CREATE TABLE receipts (
  network_id text  NOT NULL,
  key        text  NOT NULL,            -- txid
  value      jsonb NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (network_id, key)
);

CREATE TABLE organizations (
  network_id text  NOT NULL,
  key        text  NOT NULL,            -- orgId (uuid)
  value      jsonb NOT NULL,            -- org record incl. members, version
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (network_id, key)
);

-- The single assignments record per network (vaultId -> orgId map),
-- ported as-is from orgs/assignments.json. The org FK is enforced by
-- the application layer exactly as today (the record is one document);
-- org emptiness on delete keeps its existing application check.
CREATE TABLE org_assignments (
  network_id text  NOT NULL,
  key        text  NOT NULL,            -- always 'assignments'
  value      jsonb NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (network_id, key)
);

CREATE TABLE audit_events (
  id         bigserial PRIMARY KEY,     -- append order
  network_id text  NOT NULL,
  vault_id   text,
  value      jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX audit_events_scope_idx ON audit_events (network_id, vault_id, id DESC);

-- Phase B auth objects, hosted-persistent (directive §23).
CREATE TABLE auth_challenges (
  network_id     text   NOT NULL,
  nonce          text   NOT NULL,       -- 64-hex; returned only to its requester
  wallet_address text   NOT NULL,
  xonly          text   NOT NULL,
  issued_at_ms   bigint NOT NULL,
  expires_at_ms  bigint NOT NULL,
  state          text   NOT NULL CHECK (state IN ('issued', 'verifying')),
  PRIMARY KEY (network_id, nonce)       -- duplicate nonce impossible
);
CREATE INDEX auth_challenges_wallet_idx ON auth_challenges (network_id, wallet_address, issued_at_ms);

CREATE TABLE auth_sessions (
  network_id     text    NOT NULL,
  token_hash     text    NOT NULL,      -- sha256(token); the raw bearer token is NEVER stored
  wallet_address text    NOT NULL,
  xonly          text    NOT NULL,
  created_at_ms  bigint  NOT NULL,
  last_seen_ms   bigint  NOT NULL,
  revoked        boolean NOT NULL DEFAULT false,
  PRIMARY KEY (network_id, token_hash)
);
