-- PolicyVault HUMAN NOTIFICATIONS coordination layer (fullscale surface
-- 19; docs/postlaunch/notifications-spec.md).
--
-- NOTIFICATIONS ARE A PERIPHERAL COORDINATION SURFACE, NEVER AUTHORITY
-- (FULLSCALE_COMPLETION_ADDENDUM module boundaries: "platform ...
-- notification coordination"; "If ... notification providers ... are
-- unavailable, PolicyVault's core financial safety and existing wallet
-- functionality MUST remain correct and fail safely"). A total outage of
-- every table below must leave request processing, events, and webhooks
-- intact — the notification worker is a decoupled second consumer of the
-- SAME durable platform_events outbox (its own per-rule cursors; no
-- second emission path exists).
--
-- notification_rules — per-tenant notification subscriptions.
--   Standard (network_id, key) jsonb category shape (key = ruleId uuid),
--   accessed exclusively by server/src/events-store.js (same server-local
--   pattern as webhook_endpoints). value =
--   policyvault-notification-rule/v1: creatorXOnly tenancy (identical to
--   webhook endpoints — a rule can only ever be notified of events its
--   creating wallet could already read), closed event-type filter over
--   the EXISTING catalog (notification.* self-referential types are
--   unsubscribable — the structural no-feedback-loop rule), and a channel
--   config { type: console | webhook | smtp, ... }. A webhook channel's
--   optional HMAC secret is stored as the SAME versioned envelope
--   webhook endpoints use (plain/v1 or aes256gcm/v1 under
--   POLICYVAULT_WEBHOOK_SECRET_KEY) — see migration 006 notes.
--
-- notification_delivery_state — one row per rule (key = ruleId): durable
--   outbox cursor, bounded retry state, counters (delivered / failed /
--   skipped / rateLimited), consecutive-failure tracking for the bounded
--   failing/auto-disable transitions, and a bounded recent-attempt log.

CREATE TABLE notification_rules (
  network_id text  NOT NULL,
  key        text  NOT NULL,            -- ruleId (uuid)
  value      jsonb NOT NULL,            -- policyvault-notification-rule/v1
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (network_id, key)
);
CREATE INDEX notification_rules_creator_idx
  ON notification_rules (network_id, (value->>'creatorXOnly'));

CREATE TABLE notification_delivery_state (
  network_id text  NOT NULL,
  key        text  NOT NULL,            -- ruleId (uuid)
  value      jsonb NOT NULL,            -- policyvault-notification-delivery-state/v1
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (network_id, key)
);
