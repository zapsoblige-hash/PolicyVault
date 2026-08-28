"use strict";

/*
 * Background webhook delivery worker (completion-standard surface 18;
 * docs/postlaunch/webhooks-events-spec.md §9).
 *
 * FULLY DECOUPLED FROM REQUEST PROCESSING (binding addendum rule): the
 * worker is a timer loop inside the existing server process that reads the
 * durable outbox and per-endpoint delivery state. It shares NO in-flight
 * state with any API route; killing it, crashing it, or never starting it
 * leaves every API surface — and all core safety — untouched (proven by
 * test). Nothing a webhook receiver returns is ever parsed as data or
 * instructions: response bodies are size-capped, drained, and discarded.
 *
 * DELIVERY SEMANTICS (documented honestly, spec §9):
 *   - AT-LEAST-ONCE: the cursor advances durably only AFTER a 2xx
 *     response; a crash between response and cursor write redelivers the
 *     same event with the same eventId/deliveryId — consumers dedup on
 *     eventId (spec §8 recipe).
 *   - ORDERED PER ENDPOINT: one in-flight event per endpoint, cursor
 *     strictly monotonic. Consequence: a failing event head-of-line
 *     blocks that endpoint's stream until it dead-letters (bounded by
 *     maxAttempts × backoff) — never other endpoints, never the API.
 *   - DEAD-LETTER: after maxAttempts failures the event is recorded in
 *     webhook_dead_letters for the endpoint and the cursor advances past
 *     it (one unreachable consumer can never permanently stall).
 *   - Events an endpoint's tenant may not see, or that its type filter
 *     excludes, are skipped permanently at scan time (visibility is
 *     evaluated at delivery time, once).
 *
 * OUTBOUND HARDENING: https only (the explicit localhost dev override in
 * webhooks.js aside); DNS resolved once per attempt with the resolved
 * address validated against private/reserved ranges (SSRF + rebinding
 * pin); redirects are NEVER followed (any 3xx is a failure); strict
 * per-attempt timeout; response bodies capped and discarded.
 */

const http = require("http");
const https = require("https");
const dns = require("dns");
const net = require("net");
const crypto = require("crypto");

const { Categories, getEventsStore } = require("./events-store");
const { eventVisibleTo, visibilityCaches, NOTIFICATION_NOTICE } = require("./events");
const { listActiveEndpoints, signingSecretsFor, insecureLocalAllowed } = require("./webhooks");
const { signWebhookPayload, SIGNATURE_HEADER, EVENT_ID_HEADER, DELIVERY_ID_HEADER } = require("./events-signing");

const WEBHOOK_PAYLOAD_SCHEMA = "policyvault-webhook/v1";
const DELIVERY_STATE_SCHEMA = "policyvault-webhook-delivery-state/v1";
const DEAD_LETTER_SCHEMA = "policyvault-webhook-dead-letter/v1";

const DEFAULT_MAX_ATTEMPTS = 8;
/* Waits after failure 1..7 (failure 8 dead-letters). */
const DEFAULT_BACKOFF_MS = Object.freeze([1_000, 5_000, 25_000, 120_000, 600_000, 1_800_000, 3_600_000]);
const DEFAULT_TIMEOUT_MS = 10_000;
const DEFAULT_INTERVAL_MS = 2_000;
const RESPONSE_DRAIN_CAP = 8 * 1024; // never read more than 8 KiB of a response we discard anyway
const RECENT_ATTEMPTS_CAP = 50;
const DEAD_LETTERS_PER_ENDPOINT_CAP = 200;

/* ------------------------------------------------------------------ */
/* Outbound target guard (SSRF / rebinding)                            */
/* ------------------------------------------------------------------ */

/*
 * True when an IP must NOT be a webhook target: loopback (unless the
 * explicit localhost dev override), private, link-local, CGNAT,
 * unspecified, multicast, reserved, documentation ranges, v6 ULA,
 * v4-mapped/NAT64 embeddings. Unparseable input is forbidden (fail
 * closed).
 */
function isForbiddenTargetIp(ip, { allowLoopback = false } = {}) {
  if (typeof ip !== "string") return true;
  if (net.isIPv4(ip)) {
    const o = ip.split(".").map(Number);
    if (o.length !== 4 || o.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return true;
    if (o[0] === 127) return !allowLoopback;
    if (o[0] === 0 || o[0] === 10) return true;
    if (o[0] === 100 && o[1] >= 64 && o[1] <= 127) return true; // CGNAT 100.64/10
    if (o[0] === 169 && o[1] === 254) return true; // link-local (cloud metadata)
    if (o[0] === 172 && o[1] >= 16 && o[1] <= 31) return true;
    if (o[0] === 192 && o[1] === 0 && (o[2] === 0 || o[2] === 2)) return true; // 192.0.0/24 + 192.0.2/24
    if (o[0] === 192 && o[1] === 168) return true;
    if (o[0] === 198 && (o[1] === 18 || o[1] === 19)) return true; // benchmarking
    if (o[0] === 198 && o[1] === 51 && o[2] === 100) return true; // doc
    if (o[0] === 203 && o[1] === 0 && o[2] === 113) return true; // doc
    if (o[0] >= 224) return true; // multicast + reserved + broadcast
    return false;
  }
  if (net.isIPv6(ip)) {
    const v6 = ip.toLowerCase();
    if (v6 === "::1") return !allowLoopback;
    if (v6 === "::") return true;
    // v4-mapped / v4-compatible / NAT64: judge the embedded v4.
    const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(v6);
    if (mapped) return isForbiddenTargetIp(mapped[1], { allowLoopback });
    if (v6.startsWith("64:ff9b:")) return true; // NAT64 translation prefix — conservative deny
    if (v6.startsWith("fe8") || v6.startsWith("fe9") || v6.startsWith("fea") || v6.startsWith("feb")) return true; // link-local fe80::/10
    if (v6.startsWith("fc") || v6.startsWith("fd")) return true; // ULA fc00::/7
    if (v6.startsWith("ff")) return true; // multicast
    if (v6.startsWith("2001:db8")) return true; // documentation
    return false;
  }
  return true; // not an IP at all: fail closed
}

/* A dns.lookup wrapper that validates the RESOLVED address and pins the
 * connection to it (the socket dials exactly what we validated — no
 * second resolution for a rebinding race to win). */
function guardedLookup(allowLoopback) {
  return (hostname, options, callback) => {
    const cb = typeof options === "function" ? options : callback;
    dns.lookup(hostname, { verbatim: true }, (err, address, family) => {
      if (err) return cb(err);
      if (isForbiddenTargetIp(address, { allowLoopback })) {
        return cb(Object.assign(new Error(`webhook target resolves to a forbidden address`), { code: "WEBHOOK_TARGET_FORBIDDEN" }));
      }
      cb(null, address, family);
    });
  };
}

/*
 * The default transport: POST rawBody to url. Resolves
 * { ok, httpStatus, errorCode, durationMs }; NEVER rejects, never returns
 * response content. ok === true only for 2xx (3xx is a failure — a
 * redirect is never followed).
 */
function httpPostJson({ url, rawBody, headers, timeoutMs, allowLoopback }) {
  return new Promise((resolve) => {
    const startedAt = Date.now();
    let settled = false;
    const finish = (out) => {
      if (settled) return;
      settled = true;
      resolve({ durationMs: Date.now() - startedAt, ...out });
    };
    let target;
    try {
      target = new URL(url);
    } catch {
      return finish({ ok: false, httpStatus: null, errorCode: "WEBHOOK_URL_INVALID" });
    }
    const isHttps = target.protocol === "https:";
    if (!isHttps && target.protocol !== "http:") {
      return finish({ ok: false, httpStatus: null, errorCode: "WEBHOOK_URL_INVALID" });
    }
    // Literal-IP hosts bypass dns.lookup inside net.connect — validate here.
    const literalHost = target.hostname.replace(/^\[|\]$/g, "");
    if (net.isIP(literalHost) && isForbiddenTargetIp(literalHost, { allowLoopback })) {
      return finish({ ok: false, httpStatus: null, errorCode: "WEBHOOK_TARGET_FORBIDDEN" });
    }
    const mod = isHttps ? https : http;
    const req = mod.request(
      {
        method: "POST",
        hostname: literalHost,
        port: target.port || (isHttps ? 443 : 80),
        path: `${target.pathname}${target.search}`,
        servername: net.isIP(literalHost) ? undefined : target.hostname, // SNI stays the hostname
        lookup: guardedLookup(allowLoopback),
        agent: false, // one socket per attempt; no pooled keep-alive to a consumer
        headers: {
          ...headers,
          "content-type": "application/json",
          "content-length": Buffer.byteLength(rawBody),
          "user-agent": "PolicyVault-Webhooks/1"
        }
      },
      (res) => {
        const status = res.statusCode || 0;
        // The response body is NEVER data to us: cap + drain + discard.
        let drained = 0;
        res.on("data", (chunk) => {
          drained += chunk.length;
          if (drained > RESPONSE_DRAIN_CAP) res.destroy();
        });
        res.on("error", () => {});
        finish({ ok: status >= 200 && status < 300, httpStatus: status, errorCode: status >= 200 && status < 300 ? null : "WEBHOOK_HTTP_STATUS" });
      }
    );
    const deadline = setTimeout(() => {
      req.destroy(Object.assign(new Error("webhook delivery timed out"), { code: "WEBHOOK_TIMEOUT" }));
    }, timeoutMs);
    deadline.unref();
    req.on("error", (error) => {
      clearTimeout(deadline);
      finish({ ok: false, httpStatus: null, errorCode: error.code === "WEBHOOK_TARGET_FORBIDDEN" ? "WEBHOOK_TARGET_FORBIDDEN" : error.code === "WEBHOOK_TIMEOUT" ? "WEBHOOK_TIMEOUT" : "WEBHOOK_CONNECT_FAILED" });
    });
    req.on("response", () => clearTimeout(deadline));
    req.end(rawBody);
  });
}

/* ------------------------------------------------------------------ */
/* The worker                                                          */
/* ------------------------------------------------------------------ */

function freshState(endpoint) {
  return {
    schema: DELIVERY_STATE_SCHEMA,
    endpointId: endpoint.endpointId,
    networkId: endpoint.networkId,
    cursor: typeof endpoint.initialCursor === "string" ? endpoint.initialCursor : "0",
    pending: null,
    counters: { delivered: 0, failed: 0, deadLettered: 0 },
    recentAttempts: []
  };
}

class DeliveryWorker {
  constructor(config, options = {}) {
    this._config = config;
    this._intervalMs = options.intervalMs ?? DEFAULT_INTERVAL_MS;
    this._maxAttempts = options.maxAttempts ?? DEFAULT_MAX_ATTEMPTS;
    this._backoffMs = options.backoffScheduleMs ?? DEFAULT_BACKOFF_MS;
    this._timeoutMs = options.requestTimeoutMs ?? DEFAULT_TIMEOUT_MS;
    this._maxPerEndpointPerTick = options.maxDeliveriesPerEndpointPerTick ?? 20;
    this._scanBatch = options.scanBatch ?? 100;
    this._transport = options.transport ?? httpPostJson;
    this._now = options.now ?? (() => Date.now());
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
        // Worker failures are ISOLATED: log and keep looping; the API
        // never observes this.
        try {
          console.error(`policyvault-webhooks: delivery tick failed (${error.code || error.message})`);
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

  /* One pass over every ACTIVE endpoint. Endpoint failures are isolated
   * from each other. Exposed for deterministic tests. */
  async tick() {
    const endpoints = await listActiveEndpoints(this._config);
    for (const endpoint of endpoints) {
      try {
        await this._processEndpoint(endpoint);
      } catch (error) {
        try {
          console.error(`policyvault-webhooks: endpoint ${endpoint.endpointId} tick failed (${error.code || error.message})`);
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

  _matchesTypes(endpoint, event) {
    const types = endpoint.eventTypes;
    if (!Array.isArray(types) || types.length === 0) return false;
    return types.includes("*") || types.includes(event.type);
  }

  async _processEndpoint(endpoint) {
    const store = getEventsStore(this._config);
    let state = (await store.read(Categories.WEBHOOK_DELIVERY_STATE, endpoint.endpointId)) ?? freshState(endpoint);
    const caches = visibilityCaches();
    const principalLike = { xOnlyPubkey: endpoint.creatorXOnly, networkId: endpoint.networkId };

    for (let i = 0; i < this._maxPerEndpointPerTick; i++) {
      const now = this._now();
      let candidate = null;
      let attempts = 0;
      let deliveryId = null;
      let firstAttemptAt = null;

      if (state.pending) {
        if (now < state.pending.nextAttemptAtMs) return; // backoff window still open
        candidate = { seq: state.pending.seq, cursor: state.pending.cursor, event: state.pending.event };
        attempts = state.pending.attempts;
        deliveryId = state.pending.deliveryId;
        firstAttemptAt = state.pending.firstAttemptAt;
      } else {
        const batch = await store.listEventsAfter({ cursor: state.cursor, limit: this._scanBatch });
        if (!batch.length) return;
        for (const row of batch) {
          if (this._matchesTypes(endpoint, row.event) && (await eventVisibleTo(this._config, row.event, principalLike, caches))) {
            candidate = row;
            break;
          }
          state.cursor = row.cursor; // permanently skipped for this endpoint (filtered / not visible)
        }
        if (!candidate) {
          await store.write(Categories.WEBHOOK_DELIVERY_STATE, endpoint.endpointId, state);
          continue; // scan further batches on the next iterations
        }
        deliveryId = crypto.randomUUID();
        firstAttemptAt = new Date(now).toISOString();
      }

      const attemptNumber = attempts + 1;
      const outcome = await this._attempt(endpoint, candidate.event, { deliveryId, attemptNumber });

      state.recentAttempts = [
        {
          at: new Date(this._now()).toISOString(),
          eventId: candidate.event.eventId,
          seq: candidate.seq,
          deliveryId,
          attempt: attemptNumber,
          outcome: outcome.ok ? "DELIVERED" : attemptNumber >= this._maxAttempts ? "DEAD_LETTERED" : "FAILED",
          httpStatus: outcome.httpStatus ?? null,
          errorCode: outcome.errorCode ?? null,
          durationMs: outcome.durationMs ?? null
        },
        ...(state.recentAttempts || [])
      ].slice(0, RECENT_ATTEMPTS_CAP);

      if (outcome.ok) {
        state.counters.delivered += 1;
        state.cursor = candidate.cursor;
        state.pending = null;
        await store.write(Categories.WEBHOOK_DELIVERY_STATE, endpoint.endpointId, state);
        continue; // drain further events this tick
      }

      state.counters.failed += 1;
      if (attemptNumber >= this._maxAttempts) {
        state.counters.deadLettered += 1;
        state.cursor = candidate.cursor; // stream progress is preserved past the dead letter
        state.pending = null;
        await this._writeDeadLetter(endpoint, candidate, { deliveryId, attempts: attemptNumber, firstAttemptAt, outcome });
      } else {
        state.pending = {
          seq: candidate.seq,
          cursor: candidate.cursor,
          eventId: candidate.event.eventId,
          event: candidate.event,
          deliveryId,
          attempts: attemptNumber,
          nextAttemptAtMs: now + this._backoffFor(attemptNumber),
          firstAttemptAt
        };
      }
      await store.write(Categories.WEBHOOK_DELIVERY_STATE, endpoint.endpointId, state);
      return; // after a failure, stop this endpoint until its backoff elapses
    }
  }

  /* One signed POST. Never throws; refusals (secret unavailable, url
   * invalid under current config) are failed attempts with error codes. */
  async _attempt(endpoint, event, { deliveryId, attemptNumber }) {
    let secrets;
    try {
      secrets = signingSecretsFor(endpoint, this._now());
    } catch (error) {
      return { ok: false, httpStatus: null, errorCode: error.code || "WEBHOOK_SECRET_UNAVAILABLE", durationMs: 0 };
    }
    const payload = {
      schemaVersion: WEBHOOK_PAYLOAD_SCHEMA,
      deliveryId,
      endpointId: endpoint.endpointId,
      attempt: attemptNumber,
      sentAt: new Date(this._now()).toISOString(),
      notice: NOTIFICATION_NOTICE,
      event
    };
    const rawBody = JSON.stringify(payload);
    let signatureHeader;
    try {
      signatureHeader = signWebhookPayload({ secrets, timestampSeconds: Math.floor(this._now() / 1000), rawBody });
    } catch (error) {
      return { ok: false, httpStatus: null, errorCode: error.code || "WEBHOOK_SIGNING_FAILED", durationMs: 0 };
    }
    const allowLoopback = insecureLocalAllowed(this._config);
    try {
      return await this._transport({
        url: endpoint.url,
        rawBody,
        headers: {
          [SIGNATURE_HEADER]: signatureHeader,
          [EVENT_ID_HEADER]: event.eventId,
          [DELIVERY_ID_HEADER]: deliveryId
        },
        timeoutMs: this._timeoutMs,
        allowLoopback
      });
    } catch (error) {
      // A transport is contractually resolve-only; a hostile/broken
      // injected transport still cannot crash the worker.
      return { ok: false, httpStatus: null, errorCode: error.code || "WEBHOOK_TRANSPORT_FAILED", durationMs: 0 };
    }
  }

  async _writeDeadLetter(endpoint, candidate, { deliveryId, attempts, firstAttemptAt, outcome }) {
    const store = getEventsStore(this._config);
    const record = {
      schema: DEAD_LETTER_SCHEMA,
      endpointId: endpoint.endpointId,
      networkId: endpoint.networkId,
      eventId: candidate.event.eventId,
      seq: candidate.seq,
      cursor: candidate.cursor,
      deliveryId,
      attempts,
      lastHttpStatus: outcome.httpStatus ?? null,
      lastErrorCode: outcome.errorCode ?? null,
      firstAttemptAt,
      deadLetteredAt: new Date(this._now()).toISOString(),
      event: candidate.event
    };
    await store.write(Categories.WEBHOOK_DEAD_LETTER, `${endpoint.endpointId}:${candidate.event.eventId}`, record);
    // Bounded retention per endpoint: prune oldest beyond the cap.
    try {
      const all = (await store.listValues(Categories.WEBHOOK_DEAD_LETTER)).filter((r) => r && r.endpointId === endpoint.endpointId);
      if (all.length > DEAD_LETTERS_PER_ENDPOINT_CAP) {
        all.sort((a, b) => String(a.deadLetteredAt).localeCompare(String(b.deadLetteredAt)));
        for (const stale of all.slice(0, all.length - DEAD_LETTERS_PER_ENDPOINT_CAP)) {
          await store.remove(Categories.WEBHOOK_DEAD_LETTER, `${stale.endpointId}:${stale.eventId}`);
        }
      }
    } catch {
      /* retention pruning is best-effort */
    }
  }
}

/* server.js main-block helper: start the worker unless explicitly
 * disabled. Never throws (a webhook worker must not stop the server). */
function startDeliveryWorker(config, options = {}) {
  if (process.env.POLICYVAULT_WEBHOOK_DELIVERY === "0") return null;
  const intervalMs = Number(process.env.POLICYVAULT_WEBHOOK_INTERVAL_MS || DEFAULT_INTERVAL_MS);
  const worker = new DeliveryWorker(config, { intervalMs: Number.isSafeInteger(intervalMs) && intervalMs >= 100 ? intervalMs : DEFAULT_INTERVAL_MS, ...options });
  worker.start();
  return worker;
}

module.exports = {
  DeliveryWorker,
  startDeliveryWorker,
  httpPostJson,
  isForbiddenTargetIp,
  WEBHOOK_PAYLOAD_SCHEMA,
  DELIVERY_STATE_SCHEMA,
  DEAD_LETTER_SCHEMA,
  DEFAULT_MAX_ATTEMPTS,
  DEFAULT_BACKOFF_MS
};
