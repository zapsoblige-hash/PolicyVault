# Human Notifications (fullscale surface 19)

Status: IMPLEMENTED + UNIT/API-TESTED (JSON + live-PG suites:
`sdk/test/postlaunch-notifications.test.js`,
`sdk/test/postlaunch-notifications-pg.test.js`). Code:
`server/src/notifications.js` (rules), `server/src/notify-delivery.js`
(worker + providers), migration
`server/migrations/009_notifications.sql`, routes in `server/src/api.js`.

## 1. Position in the architecture

Notifications are the addendum's **platform notification-coordination**
surface: PolicyVault COORDINATES (which events, to whom, through which
channel); providers are optional peripherals. The binding
peripheral-failure rule applies in full: a total notification outage —
dead provider, unstarted worker, dropped tables — must leave core
financial safety, request processing, the event stream, and webhook
delivery untouched (proven by test). **A notification is observation,
never authority**; every structured payload carries the events.js
`NOTIFICATION_NOTICE` verbatim.

## 2. One outbox, a second consumer group

The delivery worker consumes the SAME durable `platform_events` outbox
that webhook delivery reads (`server/src/events-store.js`), with its own
per-RULE durable cursors (`notification_delivery_state`). There is
deliberately **no second emission path**: anything not in the closed
event catalog cannot be notified, and emission remains failure-isolated
exactly as before. Event-type filters reuse the EXISTING catalog
(`events.js EVENT_TYPES`) — this surface invents no new event semantics
for existing types.

## 3. Rules (per tenant)

`policyvault-notification-rule/v1`: `{ ruleId, networkId, creatorXOnly,
label, eventTypes, vaultId?, orgId?, channel, status, disabledReason,
initialCursor, createdAt, updatedAt }`.

- **Tenancy** inherits from `creatorXOnly` (webhook-endpoint idiom):
  the worker delivers only events `eventVisibleTo` grants the creating
  wallet; filters (`eventTypes`, `vaultId`, `orgId`) narrow, never
  widen. Foreign rules 404 (existence hidden).
- **eventTypes**: `["*"]` or a non-empty subset of the closed catalog.
  Unknown types refuse (`NOTIFY_EVENT_TYPE_UNKNOWN`). `notification.*`
  types are **unsubscribable** (`NOTIFY_EVENT_TYPE_SELF_REFERENTIAL`)
  and excluded from `*` expansion — the structural no-feedback-loop
  rule (§6).
- **Quota**: 20 rules per wallet. New rules start at the CURRENT stream
  head (subscribing never floods a human with history; history stays at
  `GET /events`).
- **Unsubscribe/disable per rule**: `POST /notifications/rules/:id/
  disable` (status DISABLED, reason OPERATOR), `/enable` (re-activates
  FROM THE CURRENT HEAD, failure counters reset), `/delete` (removes
  rule + delivery state).
- **Audit**: every rule mutation writes a chained audit record (kind
  `notification`, actions `notification_rule_created/disabled/enabled/
  deleted`) through the server audit module (audit-chain-spec.md).

## 4. Channels (closed set) + recipient validation

- `console` — always available. One structured operator log line per
  notification (closed fields; injectable sink in tests).
- `webhook` — the **generic provider bridge** (Slack/Mattermost/ntfy/
  any inbound webhook). REUSES surface 18's machinery — nothing
  duplicated: `webhooks.validateEndpointUrl` (https-only; the same
  explicit localhost dev override, never on mainnet),
  `webhooks.sealSecret/openSecret` for the optional caller-supplied
  HMAC secret (same versioned at-rest envelope), `events-signing`
  pv1 signatures when a secret is set, and `events-delivery
  httpPostJson` (SSRF/rebinding pin, strict timeout, redirects refused,
  response drained + discarded — nothing a provider returns is ever
  parsed). `template: "json"` posts the full structured payload;
  `"text"` posts `{ text }` for text-first providers.
- `smtp` — **specified pluggable seam, not shipped** (honest > fake): a
  robust dependency-free SMTP client (STARTTLS, auth, multiline replies,
  dot-stuffing, deliverability) was judged out of bounded scope, and a
  half-robust mailer that silently mangles alerts is worse than an
  honest refusal. Config shape is validated (`to`/`from` addresses,
  `subjectPrefix`), but rule creation REFUSES
  (`NOTIFY_CHANNEL_UNAVAILABLE`) unless a deployment explicitly
  registers a provider: `notifications.registerChannelProvider("smtp")`
  plus a worker `options.providers.smtp` implementation of the provider
  interface `{ type, async deliver({config, rule, event, text,
  deliveryId, attempt}) -> { ok, httpStatus?, errorCode?,
  durationMs? } }` (never throws; result treated as untrusted). The
  seam itself is proven by test with an injected provider.
  `GET /notifications/channels` reports what THIS deployment can
  actually deliver.

## 5. Delivery semantics (documented honestly)

- **Best-effort at-least-once with bounded retry**: 3 attempts,
  backoff 5s/30s; then the event is SKIPPED (cursor advances,
  `counters.skipped`) — notifications are human alerts, not a
  durability substrate; one dead channel never dams its rule.
- **Ordered per rule**; one in-flight event per rule.
- **Rate-limited per tenant**: at most N delivery attempts per creating
  wallet per rolling hour (default 120;
  `POLICYVAULT_NOTIFY_RATE_PER_HOUR`). NEW notifications beyond the
  window are DROPPED (`counters.rateLimited`) — flood control is the
  point; pending retries wait instead of being dropped. Process-local
  window (single-replica launch pin, like the API rate limiter).
- Worker startup: `startNotificationWorker` in server.js after listen;
  `POLICYVAULT_NOTIFY_DELIVERY=0` disables;
  `POLICYVAULT_NOTIFY_INTERVAL_MS` tunes the loop.

## 6. Failure signals — bounded, loop-free

Two catalog additions (closed payloads, creator-visibility like
identity events): `notification.rule.failing` (emitted ONCE when a rule
crosses 5 consecutive failed attempts) and `notification.rule.disabled`
(emitted once when sustained failure — 20 consecutive failed attempts —
auto-disables the rule, reason `AUTO_FAILURE`, with a chained audit
line). Emitted on state TRANSITIONS only, never per attempt.
**No feedback loop is possible**: rules cannot subscribe to
`notification.*` (refused at creation; excluded from `*`; the worker
additionally skips them structurally), and webhook-endpoint delivery of
these events cannot loop either (webhook delivery failures emit no
events — they dead-letter). A successful delivery resets the failure
counters; `/enable` resets an auto-disabled rule deliberately.

## 7. No secrets in payloads

Payloads carry `{ schemaVersion, ruleId, deliveryId, attempt, sentAt,
notice, text, event }` (or `{ text }`): the event is already the closed
no-secret catalog envelope; `text` is a deterministic human line built
ONLY from catalog-bounded event fields (`humanText`). Channel secrets
live solely in the sealed envelope inside the rule record, are never
echoed by any route (`presentRule` strips to `hasSecret`), and the
`/notifications` family is excluded from Idempotency-Key response
persistence (api.js `secretBearingRoute`). The suites sweep every
persisted platform byte and every captured payload for the secret.

## 8. API + scopes

`POST /notifications/rules`, `GET /notifications/rules[/:id]`,
`POST /notifications/rules/:id/{disable,enable,delete}`,
`GET /notifications/channels`. Hosted mode requires an authenticated
principal; machine credentials need the deny-by-default
`read:notifications` / `notifications:manage` scopes (scopes.js;
capability document lists both). Self-hosted single-operator mode is
open like every other route.
