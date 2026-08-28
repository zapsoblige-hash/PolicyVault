-- PolicyVault signed/replay-safe webhooks + asynchronous events
-- (completion-standard surface 18, feeding surface 25 monitoring;
-- docs/postlaunch/webhooks-events-spec.md).
--
-- EVENTS ARE OBSERVATION, NEVER AUTHORITY: every row here is a
-- NOTIFICATION about durable state whose truth lives at the API and, for
-- anything consensus-visible, at the Kaspa covenant. Nothing in this
-- schema grants, verifies, or modifies covenant authority, and a total
-- outage of every table below must leave core request processing intact
-- (server/src/events.js emission is failure-isolated by contract).
--
-- platform_events — the durable append-only OUTBOX stream.
--   Mirrors audit_events' shape deliberately (bigserial id = append order
--   = the polling/delivery cursor). value = policyvault-event/v1 (closed
--   per-type schemas; NO secrets, NO tokens, NO signatures/preimages —
--   enforced at emission in server/src/events.js). (network_id, event_id)
--   is UNIQUE so one logical event can never be recorded twice.
--
-- webhook_endpoints — per-tenant webhook subscriptions.
--   Standard (network_id, key) jsonb category shape (key = endpointId
--   uuid), accessed exclusively by server/src/events-store.js (same
--   server-local pattern as platform-store.js; sdk/src/store.js's frozen
--   Categories are untouched). value = policyvault-webhook-endpoint/v1.
--   SECRET STORAGE (documented tradeoff — spec §7): the per-endpoint HMAC
--   secret CANNOT be stored as a hash (the server must re-derive HMAC
--   signatures with the raw secret on every delivery). It is stored as a
--   versioned envelope: AES-256-GCM-encrypted when the operator sets
--   POLICYVAULT_WEBHOOK_SECRET_KEY, otherwise plaintext inside this
--   single restricted category. Unknown envelope versions fail closed.
--
-- webhook_delivery_state — one row per endpoint (key = endpointId):
--   durable cursor, in-flight retry state, counters, and a bounded
--   recent-attempt log (delivery monitoring, surface 25 seam).
--
-- webhook_dead_letters — events that exhausted delivery attempts for an
--   endpoint (key = "<endpointId>:<eventId>"); the stream cursor advances
--   past them so one unreachable consumer can never stall the stream.

CREATE TABLE platform_events (
  id         bigserial PRIMARY KEY,     -- append order; the cursor
  network_id text  NOT NULL,
  event_id   text  NOT NULL,            -- uuid; consumer-side dedup key
  type       text  NOT NULL,            -- closed catalog (events.js EVENT_TYPES)
  vault_id   text,                      -- lifted index columns; truth is value
  org_id     text,
  value      jsonb NOT NULL,            -- policyvault-event/v1
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (network_id, event_id)
);
CREATE INDEX platform_events_scan_idx  ON platform_events (network_id, id);
CREATE INDEX platform_events_vault_idx ON platform_events (network_id, vault_id, id) WHERE vault_id IS NOT NULL;
CREATE INDEX platform_events_type_idx  ON platform_events (network_id, type, id);

CREATE TABLE webhook_endpoints (
  network_id text  NOT NULL,
  key        text  NOT NULL,            -- endpointId (uuid)
  value      jsonb NOT NULL,            -- policyvault-webhook-endpoint/v1
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (network_id, key)
);
CREATE INDEX webhook_endpoints_creator_idx
  ON webhook_endpoints (network_id, (value->>'creatorXOnly'));

CREATE TABLE webhook_delivery_state (
  network_id text  NOT NULL,
  key        text  NOT NULL,            -- endpointId (uuid)
  value      jsonb NOT NULL,            -- policyvault-webhook-delivery-state/v1
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (network_id, key)
);

CREATE TABLE webhook_dead_letters (
  network_id text  NOT NULL,
  key        text  NOT NULL,            -- "<endpointId>:<eventId>"
  value      jsonb NOT NULL,            -- policyvault-webhook-dead-letter/v1
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (network_id, key)
);
CREATE INDEX webhook_dead_letters_endpoint_idx
  ON webhook_dead_letters (network_id, (value->>'endpointId'));
