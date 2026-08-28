"use strict";

/*
 * HUMAN NOTIFICATION delivery worker + reference providers (fullscale
 * surface 19; docs/postlaunch/notifications-spec.md §6–§8).
 *
 * A SECOND CONSUMER GROUP over the SAME durable platform_events outbox
 * the webhook deliverer reads (server/src/events-store.js) — its own
 * per-RULE durable cursors, never a second emission path and never a
 * shared cursor with webhook endpoints. FULLY DECOUPLED FROM REQUEST
 * PROCESSING (the addendum's peripheral-failure rule): a timer loop in
 * the existing process sharing no in-flight state with any API route;
 * killing it, crashing it, or never starting it leaves every API surface,
 * the event stream, and webhook delivery untouched (proven by test).
 *
 * DELIVERY SEMANTICS (documented honestly):
 *   - BEST-EFFORT AT-LEAST-ONCE with a SMALL bounded retry (default 3
 *     attempts, short backoff): notifications are human alerts, not a
 *     durability substrate — after the attempts are exhausted the event
 *     is SKIPPED (cursor advances; counters.skipped) so one dead channel
 *     never dams its rule. Durable history remains at GET /events.
 *   - ORDERED PER RULE: one in-flight event per rule, cursor monotonic.
 *   - RATE-LIMITED PER TENANT: at most N delivery attempts per creating
 *     wallet per rolling hour (default 120; POLICYVAULT_NOTIFY_RATE_PER_
 *     HOUR). NEW notifications beyond the window are dropped
 *     (counters.rateLimited) — flood control is the point; pending
 *     retries wait instead of being dropped. The window is process-local
 *     (single-replica launch pin, same as the API rate limiter).
 *   - BOUNDED FAILURE SIGNALS, STRUCTURALLY LOOP-FREE: after
 *     FAILING_THRESHOLD consecutive failed attempts a rule emits
 *     notification.rule.failing ONCE (per degradation episode); at
 *     AUTO_DISABLE_THRESHOLD the rule is auto-disabled (audited) and
 *     notification.rule.disabled is emitted once. notification.* events
 *     are UNSUBSCRIBABLE by rules and skipped by this worker, so failure
 *     signals can never fan back into notifications.
 *
 * PROVIDERS (dependency-free, closed registry; the smtp seam is spec'd in
 * notifications.js and injected via options.providers when a deployment
 * registers one):
 *   console — always-available structured operator log line (no secrets).
 *   webhook — generic provider bridge REUSING surface 18's machinery:
 *     events-delivery httpPostJson (SSRF/rebinding pin, https-only with
 *     the same explicit localhost dev override, strict timeout, response
 *     drained+discarded, redirects refused) and events-signing pv1 HMAC
 *     when the rule configured a secret. Payloads carry the event
 *     verbatim plus a deterministic human-readable `text` line — NEVER
 *     secrets, tokens, or channel credentials.
 */

const crypto = require("crypto");

const { Categories, getEventsStore } = require("./events-store");
const { eventVisibleTo, visibilityCaches, safeEmitPlatformEvent, NOTIFICATION_NOTICE } = require("./events");
const { listActiveRules, autoDisableRule } = require("./notifications");
const { httpPostJson } = require("./events-delivery");
const { signWebhookPayload, SIGNATURE_HEADER, EVENT_ID_HEADER, DELIVERY_ID_HEADER } = require("./events-signing");
const { openSecret, insecureLocalAllowed } = require("./webhooks");

const NOTIFY_PAYLOAD_SCHEMA = "policyvault-notification/v1";
const NOTIFY_STATE_SCHEMA = "policyvault-notification-delivery-state/v1";

const DEFAULT_MAX_ATTEMPTS = 3;
/* Waits after failure 1..2 (failure 3 skips the event). */
const DEFAULT_BACKOFF_MS = Object.freeze([5_000, 30_000]);
const DEFAULT_TIMEOUT_MS = 10_000;
const DEFAULT_INTERVAL_MS = 2_000;
const DEFAULT_RATE_PER_HOUR = 120;
const RATE_WINDOW_MS = 60 * 60 * 1000;
const FAILING_THRESHOLD = 5;
const AUTO_DISABLE_THRESHOLD = 20;
const RECENT_ATTEMPTS_CAP = 50;

/* ------------------------------------------------------------------ */
/* Deterministic human-readable line (closed formatting; catalog-bounded
 * fields only — no free text can enter from outside the closed event)   */
/* ------------------------------------------------------------------ */

function shortId(v) {
  return typeof v === "string" && v.length > 12 ? `${v.slice(0, 12)}…` : v;
}

function humanText(event) {
  const bits = [`PolicyVault ${event.networkId}: ${event.type}`];
  const d = event.data || {};
  for (const field of ["action", "state", "decision", "classification", "outcome", "stage", "code", "reason", "label", "summary"]) {
    if (typeof d[field] === "string" && d[field]) bits.push(`${field}=${d[field]}`);
  }
  if (typeof event.vaultId === "string" && event.vaultId) bits.push(`vault ${shortId(event.vaultId)}`);
  if (typeof event.orgId === "string" && event.orgId) bits.push(`org ${shortId(event.orgId)}`);
  const corr = event.correlation || {};
  if (typeof corr.requestId === "string") bits.push(`request ${shortId(corr.requestId)}`);
  if (typeof corr.txId === "string") bits.push(`tx ${shortId(corr.txId)}`);
  const line = bits.join(" — ");
  return line.length > 300 ? `${line.slice(0, 299)}…` : line;
}

/* ------------------------------------------------------------------ */
/* Reference providers                                                 */
/* ------------------------------------------------------------------ */

/* Console provider: one structured line to the operator log. Closed
 * fields; never channel config, never secrets. */
function makeConsoleProvider({ sink } = {}) {
  const write = sink ?? ((line) => console.log(line));
  return {
    type: "console",
    async deliver({ event, rule, text, deliveryId, attempt }) {
      const line = `policyvault-notify: ${JSON.stringify({
        schemaVersion: NOTIFY_PAYLOAD_SCHEMA,
        ruleId: rule.ruleId,
        deliveryId,
        attempt,
        eventId: event.eventId,
        type: event.type,
        occurredAt: event.occurredAt,
        vaultId: event.vaultId,
        orgId: event.orgId,
        text
      })}`;
      write(line);
      return { ok: true, httpStatus: null, errorCode: null, durationMs: 0 };
    }
  };
}

/* Webhook bridge provider: signed (when a secret is configured) POST of
 * the notification payload to the rule's provider URL through the SAME
 * hardened transport webhook endpoints use. */
function makeWebhookBridgeProvider({ transport, timeoutMs, now } = {}) {
  const post = transport ?? httpPostJson;
  const clock = now ?? (() => Date.now());
  return {
    type: "webhook",
    async deliver({ config, event, rule, text, deliveryId, attempt }) {
      const payload =
        rule.channel.template === "text"
          ? { text }
          : {
              schemaVersion: NOTIFY_PAYLOAD_SCHEMA,
              ruleId: rule.ruleId,
              deliveryId,
              attempt,
              sentAt: new Date(clock()).toISOString(),
              notice: NOTIFICATION_NOTICE,
              text,
              event
            };
      const rawBody = JSON.stringify(payload);
      const headers = { [EVENT_ID_HEADER]: event.eventId, [DELIVERY_ID_HEADER]: deliveryId };
      if (rule.channel.secret) {
        let secret;
        try {
          secret = openSecret(rule.channel.secret); // fail closed: unknown envelope/missing key never falls back to unsigned
        } catch (error) {
          return { ok: false, httpStatus: null, errorCode: error.code || "NOTIFY_SECRET_UNAVAILABLE", durationMs: 0 };
        }
        try {
          headers[SIGNATURE_HEADER] = signWebhookPayload({ secrets: [secret], timestampSeconds: Math.floor(clock() / 1000), rawBody });
        } catch (error) {
          return { ok: false, httpStatus: null, errorCode: error.code || "NOTIFY_SIGNING_FAILED", durationMs: 0 };
        }
      }
      try {
        return await post({
          url: rule.channel.url,
          rawBody,
          headers,
          timeoutMs: timeoutMs ?? DEFAULT_TIMEOUT_MS,
          allowLoopback: insecureLocalAllowed(config)
        });
      } catch (error) {
        return { ok: false, httpStatus: null, errorCode: error.code || "NOTIFY_TRANSPORT_FAILED", durationMs: 0 };
      }
    }
  };
}

/* ------------------------------------------------------------------ */
/* The worker                                                          */
/* ------------------------------------------------------------------ */

function freshState(rule) {
  return {
    schema: NOTIFY_STATE_SCHEMA,
    ruleId: rule.ruleId,
    networkId: rule.networkId,
    cursor: typeof rule.initialCursor === "string" ? rule.initialCursor : "0",
    pending: null,
    counters: { delivered: 0, failed: 0, skipped: 0, rateLimited: 0 },
    consecutiveFailures: 0,
    failingNotified: false,
    recentAttempts: []
  };
}

class NotificationWorker {
  constructor(config, options = {}) {
    this._config = config;
    this._intervalMs = options.intervalMs ?? DEFAULT_INTERVAL_MS;
    this._maxAttempts = options.maxAttempts ?? DEFAULT_MAX_ATTEMPTS;
    this._backoffMs = options.backoffScheduleMs ?? DEFAULT_BACKOFF_MS;
    this._maxPerRulePerTick = options.maxDeliveriesPerRulePerTick ?? 20;
    this._scanBatch = options.scanBatch ?? 100;
    this._now = options.now ?? (() => Date.now());
    this._ratePerHour = options.rateLimitPerHour ?? envRatePerHour();
    this._attemptTimesByCreator = new Map(); // process-local rolling window
    this._providers = new Map();
    const consoleProvider = makeConsoleProvider({ sink: options.consoleSink });
    const webhookProvider = makeWebhookBridgeProvider({ transport: options.transport, timeoutMs: options.requestTimeoutMs, now: this._now });
    this._providers.set("console", consoleProvider);
    this._providers.set("webhook", webhookProvider);
    for (const [type, provider] of Object.entries(options.providers ?? {})) {
      this._providers.set(type, provider); // the pluggable seam (smtp etc.)
    }
    this._timer = null;
    this._running = false;
    this._ticking = null;
  }

  start() {
    if (this._running) return;
    this._running = true;
    const loop = async () => {
      if (!this._running) return;
      try {
        this._ticking = this.tick();
        await this._ticking;
      } catch (error) {
        // Worker failures are ISOLATED: log and keep looping.
        try {
          console.error(`policyvault-notify: delivery tick failed (${error.code || error.message})`);
        } catch {
          /* never throw */
        }
      } finally {
        this._ticking = null;
        if (this._running) {
          this._timer = setTimeout(loop, this._intervalMs);
          this._timer.unref();
        }
      }
    };
    this._timer = setTimeout(loop, this._intervalMs);
    this._timer.unref();
  }

  async stop() {
    this._running = false;
    if (this._timer) {
      clearTimeout(this._timer);
      this._timer = null;
    }
    if (this._ticking) {
      try {
        await this._ticking;
      } catch {
        /* already isolated */
      }
    }
  }

  /* One pass over every ACTIVE rule. Rule failures are isolated from each
   * other. Exposed for deterministic tests. */
  async tick() {
    const rules = await listActiveRules(this._config);
    for (const rule of rules) {
      try {
        await this._processRule(rule);
      } catch (error) {
        try {
          console.error(`policyvault-notify: rule ${rule.ruleId} tick failed (${error.code || error.message})`);
        } catch {
          /* never throw */
        }
      }
    }
  }

  _backoffFor(failureCount) {
    const idx = Math.min(failureCount - 1, this._backoffMs.length - 1);
    return this._backoffMs[idx];
  }

  _matchesRule(rule, event) {
    if (typeof event.type !== "string" || event.type.startsWith("notification.")) return false; // structural no-loop rule
    const types = rule.eventTypes;
    if (!Array.isArray(types) || types.length === 0) return false;
    if (!(types.includes("*") || types.includes(event.type))) return false;
    if (rule.vaultId && event.vaultId !== rule.vaultId) return false;
    if (rule.orgId && event.orgId !== rule.orgId) return false;
    return true;
  }

  /* Rolling per-creator attempt window. Returns true when one more
   * attempt is admitted (and records it). */
  _admitAttempt(creatorXOnly, now) {
    const key = creatorXOnly ?? "__local__";
    const cutoff = now - RATE_WINDOW_MS;
    let times = this._attemptTimesByCreator.get(key);
    if (!times) {
      times = [];
      this._attemptTimesByCreator.set(key, times);
    }
    while (times.length && times[0] <= cutoff) times.shift();
    if (times.length >= this._ratePerHour) return false;
    times.push(now);
    return true;
  }

  _rateWindowFull(creatorXOnly, now) {
    const key = creatorXOnly ?? "__local__";
    const cutoff = now - RATE_WINDOW_MS;
    const times = this._attemptTimesByCreator.get(key) ?? [];
    while (times.length && times[0] <= cutoff) times.shift();
    return times.length >= this._ratePerHour;
  }

  async _processRule(rule) {
    const store = getEventsStore(this._config);
    let state = (await store.read(Categories.NOTIFY_STATE, rule.ruleId)) ?? freshState(rule);
    const caches = visibilityCaches();
    const principalLike = { xOnlyPubkey: rule.creatorXOnly, networkId: rule.networkId };

    for (let i = 0; i < this._maxPerRulePerTick; i++) {
      const now = this._now();
      let candidate = null;
      let attempts = 0;
      let deliveryId = null;

      if (state.pending) {
        if (now < state.pending.nextAttemptAtMs) return; // backoff window still open
        // A pending RETRY is never dropped by the limiter — it waits.
        if (!this._admitAttempt(rule.creatorXOnly, now)) return;
        candidate = { seq: state.pending.seq, cursor: state.pending.cursor, event: state.pending.event };
        attempts = state.pending.attempts;
        deliveryId = state.pending.deliveryId;
      } else {
        const batch = await store.listEventsAfter({ cursor: state.cursor, limit: this._scanBatch });
        if (!batch.length) return;
        for (const row of batch) {
          if (this._matchesRule(rule, row.event) && (await eventVisibleTo(this._config, row.event, principalLike, caches))) {
            // Flood control: NEW notifications beyond the tenant's rolling
            // window are dropped (history stays at GET /events).
            if (this._rateWindowFull(rule.creatorXOnly, now)) {
              state.counters.rateLimited += 1;
              state.cursor = row.cursor;
              continue;
            }
            candidate = row;
            break;
          }
          state.cursor = row.cursor; // permanently skipped for this rule (filtered / not visible)
        }
        if (!candidate) {
          await store.write(Categories.NOTIFY_STATE, rule.ruleId, state);
          continue; // scan further batches on later iterations
        }
        this._admitAttempt(rule.creatorXOnly, now); // count the first attempt
        deliveryId = crypto.randomUUID();
      }

      const attemptNumber = attempts + 1;
      const outcome = await this._attempt(rule, candidate.event, { deliveryId, attempt: attemptNumber });

      state.recentAttempts = [
        {
          at: new Date(this._now()).toISOString(),
          eventId: candidate.event.eventId,
          seq: candidate.seq,
          deliveryId,
          attempt: attemptNumber,
          outcome: outcome.ok ? "DELIVERED" : attemptNumber >= this._maxAttempts ? "SKIPPED" : "FAILED",
          httpStatus: outcome.httpStatus ?? null,
          errorCode: outcome.errorCode ?? null,
          durationMs: outcome.durationMs ?? null
        },
        ...(state.recentAttempts || [])
      ].slice(0, RECENT_ATTEMPTS_CAP);

      if (outcome.ok) {
        state.counters.delivered += 1;
        state.consecutiveFailures = 0;
        state.failingNotified = false;
        state.cursor = candidate.cursor;
        state.pending = null;
        await store.write(Categories.NOTIFY_STATE, rule.ruleId, state);
        continue; // drain further events this tick
      }

      state.counters.failed += 1;
      state.consecutiveFailures += 1;
      if (attemptNumber >= this._maxAttempts) {
        // Notifications are best-effort: the event is skipped, the rule's
        // stream continues (durable history stays at GET /events).
        state.counters.skipped += 1;
        state.cursor = candidate.cursor;
        state.pending = null;
      } else {
        state.pending = {
          seq: candidate.seq,
          cursor: candidate.cursor,
          eventId: candidate.event.eventId,
          event: candidate.event,
          deliveryId,
          attempts: attemptNumber,
          nextAttemptAtMs: now + this._backoffFor(attemptNumber)
        };
      }
      await this._noteFailureTransitions(rule, state, outcome);
      await store.write(Categories.NOTIFY_STATE, rule.ruleId, state);
      return; // after a failure, stop this rule until its backoff elapses
    }
  }

  /* Bounded degradation signals: emitted on state TRANSITIONS only, never
   * per attempt. All failure-isolated (safeEmit* never throws; audit
   * failures are caught — a broken store must not crash the worker). */
  async _noteFailureTransitions(rule, state, outcome) {
    if (!state.failingNotified && state.consecutiveFailures >= FAILING_THRESHOLD) {
      state.failingNotified = true;
      await safeEmitPlatformEvent(this._config, {
        type: "notification.rule.failing",
        data: { ruleId: rule.ruleId, channelType: rule.channel.type, consecutiveFailures: state.consecutiveFailures, creatorXOnly: rule.creatorXOnly ?? undefined }
      });
    }
    if (state.consecutiveFailures >= AUTO_DISABLE_THRESHOLD) {
      try {
        await autoDisableRule(this._config, rule); // audited (chained) inside
      } catch (error) {
        try {
          console.error(`policyvault-notify: auto-disable of rule ${rule.ruleId} failed (${error.code || error.message})`);
        } catch {
          /* never throw */
        }
        return; // rule stays ACTIVE; the threshold fires again next failure
      }
      await safeEmitPlatformEvent(this._config, {
        type: "notification.rule.disabled",
        data: { ruleId: rule.ruleId, channelType: rule.channel.type, reason: "AUTO_FAILURE", creatorXOnly: rule.creatorXOnly ?? undefined }
      });
      try {
        console.error(`policyvault-notify: rule ${rule.ruleId} auto-disabled after ${state.consecutiveFailures} consecutive failures (${outcome.errorCode || outcome.httpStatus || "failure"})`);
      } catch {
        /* never throw */
      }
    }
  }

  /* One provider dispatch. Never throws; a missing or hostile provider is
   * a failed attempt with an error code, never a crash. */
  async _attempt(rule, event, { deliveryId, attempt }) {
    const provider = this._providers.get(rule.channel ? rule.channel.type : undefined);
    if (!provider) {
      return { ok: false, httpStatus: null, errorCode: "NOTIFY_PROVIDER_UNAVAILABLE", durationMs: 0 };
    }
    try {
      const outcome = await provider.deliver({ config: this._config, rule, event, text: humanText(event), deliveryId, attempt });
      if (!outcome || typeof outcome.ok !== "boolean") {
        return { ok: false, httpStatus: null, errorCode: "NOTIFY_PROVIDER_MALFORMED_RESULT", durationMs: 0 };
      }
      return outcome;
    } catch (error) {
      return { ok: false, httpStatus: null, errorCode: error.code || "NOTIFY_PROVIDER_FAILED", durationMs: 0 };
    }
  }
}

function envRatePerHour() {
  const raw = Number(process.env.POLICYVAULT_NOTIFY_RATE_PER_HOUR || DEFAULT_RATE_PER_HOUR);
  return Number.isSafeInteger(raw) && raw >= 1 ? raw : DEFAULT_RATE_PER_HOUR;
}

/* server.js main-block helper: start the worker unless explicitly
 * disabled. Never throws (a notification worker must not stop the
 * server). */
function startNotificationWorker(config, options = {}) {
  if (process.env.POLICYVAULT_NOTIFY_DELIVERY === "0") return null;
  const intervalMs = Number(process.env.POLICYVAULT_NOTIFY_INTERVAL_MS || DEFAULT_INTERVAL_MS);
  const worker = new NotificationWorker(config, { intervalMs: Number.isSafeInteger(intervalMs) && intervalMs >= 100 ? intervalMs : DEFAULT_INTERVAL_MS, ...options });
  worker.start();
  return worker;
}

module.exports = {
  NotificationWorker,
  startNotificationWorker,
  makeConsoleProvider,
  makeWebhookBridgeProvider,
  humanText,
  NOTIFY_PAYLOAD_SCHEMA,
  NOTIFY_STATE_SCHEMA,
  DEFAULT_MAX_ATTEMPTS,
  DEFAULT_BACKOFF_MS,
  DEFAULT_RATE_PER_HOUR,
  FAILING_THRESHOLD,
  AUTO_DISABLE_THRESHOLD
};
