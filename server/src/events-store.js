"use strict";

/*
 * Durable persistence for the events/webhooks surface (completion-standard
 * surface 18; docs/postlaunch/webhooks-events-spec.md; migration
 * server/migrations/006_events_webhooks.sql).
 *
 * SAME server-local pattern as server/src/platform-store.js: this module
 * owns its own small category set in ITS OWN tables/directories, reuses
 * sdk/src/durable-json.js's fsync-rename primitives (read-only import) and
 * the SAME already-open PgStore pool (getStore(config).pool()) — it dials
 * no connections of its own and never extends sdk/src/store.js's frozen
 * Categories enum.
 *
 * Two shapes live here:
 *   1. The APPEND-ONLY EVENT STREAM (the outbox). PG: platform_events with
 *      a bigserial id as the append order/cursor. JSON: an NDJSON file
 *      (platform/events/stream.log — the exact idiom of the audit JSONL)
 *      with a process-local monotonic seq initialized from the file.
 *      JSON-backend concurrency note (documented honestly): seq assignment
 *      assumes ONE server process per data root — exactly the released
 *      self-hosted deployment shape (hosted mode runs PostgreSQL, where
 *      bigserial arbitrates). Cursors are OPAQUE STRINGS to callers.
 *   2. Keyed jsonb categories for endpoints / delivery state / dead
 *      letters (the standard (network_id, key) + jsonb shape).
 *
 * NOTHING here is authority: a total failure of this module must never
 * fail a request — emission callers (server/src/events.js) isolate it.
 */

const fs = require("fs");
const path = require("path");

const { persistJsonDurably, readJsonStrict } = require("../../sdk/src/durable-json");
const { getStore } = require("../../sdk/src/store");

const Categories = Object.freeze({
  WEBHOOK_ENDPOINT: "webhook-endpoint", // key = endpointId (uuid)
  WEBHOOK_DELIVERY_STATE: "webhook-delivery-state", // key = endpointId
  WEBHOOK_DEAD_LETTER: "webhook-dead-letter", // key = `${endpointId}:${eventId}`
  /* Human-notification coordination (fullscale surface 19; migration 009;
   * server/src/notifications.js + notify-delivery.js). The notification
   * worker is a SECOND consumer of the SAME platform_events outbox above
   * (its own per-rule cursors — never a second emission path). */
  NOTIFY_RULE: "notify-rule", // key = ruleId (uuid)
  NOTIFY_STATE: "notify-delivery-state" // key = ruleId
});

const CATEGORY_DIR = Object.freeze({
  [Categories.WEBHOOK_ENDPOINT]: "webhook-endpoints",
  [Categories.WEBHOOK_DELIVERY_STATE]: "webhook-delivery-state",
  [Categories.WEBHOOK_DEAD_LETTER]: "webhook-dead-letters",
  [Categories.NOTIFY_RULE]: "notify-rules",
  [Categories.NOTIFY_STATE]: "notify-delivery-state"
});

const CATEGORY_TABLE = Object.freeze({
  [Categories.WEBHOOK_ENDPOINT]: "webhook_endpoints",
  [Categories.WEBHOOK_DELIVERY_STATE]: "webhook_delivery_state",
  [Categories.WEBHOOK_DEAD_LETTER]: "webhook_dead_letters",
  [Categories.NOTIFY_RULE]: "notification_rules",
  [Categories.NOTIFY_STATE]: "notification_delivery_state"
});

class EventsStoreError extends Error {
  constructor(code, message) {
    super(message);
    this.code = code;
  }
}

function tableFor(category) {
  const table = CATEGORY_TABLE[category];
  if (!table) throw new EventsStoreError("EVENTS_STORE_CATEGORY_UNKNOWN", `unknown events-store category ${JSON.stringify(category)} — failing closed`);
  return table;
}

/* Keys are server-generated (uuids / "<uuid>:<uuid>"), never raw caller
 * text, so the on-disk filename is the key itself after a strict shape
 * check (fail closed on anything else — no traversal surface). */
const FILE_KEY_RE = /^[0-9a-fA-F-]{1,80}(:[0-9a-fA-F-]{1,80})?$/;
function jsonPathFor(config, category, key) {
  const dir = CATEGORY_DIR[category];
  if (!dir) throw new EventsStoreError("EVENTS_STORE_CATEGORY_UNKNOWN", `unknown events-store category ${JSON.stringify(category)} — failing closed`);
  if (typeof key !== "string" || !FILE_KEY_RE.test(key)) {
    throw new EventsStoreError("EVENTS_STORE_KEY_INVALID", "events-store keys are server-generated ids — refusing a malformed key (fail closed)");
  }
  return path.join(config.dataRoot, "platform", dir, `${key.replace(/:/g, "_")}.json`);
}

/* BigInt-safe jsonb round trip, identical discipline to sdk/src/store.js. */
function toJsonb(value) {
  return JSON.stringify(value, (_, item) => (typeof item === "bigint" ? item.toString() : item));
}

/* ------------------------------------------------------------------ */
/* Cursor discipline: opaque strings over a monotonic integer.         */
/* ------------------------------------------------------------------ */

const CURSOR_RE = /^\d{1,18}$/;
function parseCursor(cursor, { fallback = 0n } = {}) {
  if (cursor === undefined || cursor === null || cursor === "") return fallback;
  if (typeof cursor !== "string" || !CURSOR_RE.test(cursor)) {
    throw new EventsStoreError("EVENTS_CURSOR_INVALID", "cursor must be a decimal string previously returned by this API — failing closed");
  }
  return BigInt(cursor);
}
function cursorOf(seq) {
  return String(seq);
}

/* ------------------------------------------------------------------ */
/* JSON backend                                                        */
/* ------------------------------------------------------------------ */

/* Process-local seq counters keyed by the RESOLVED stream file path (not
 * the config object — two config objects over the same data root must
 * share one counter). Single-process-per-data-root assumption documented
 * in the module header. */
const jsonSeqByFile = new Map();

class JsonEventsStore {
  constructor(config) {
    this.kind = "json";
    this._config = config;
  }

  _streamFile() {
    return path.join(this._config.dataRoot, "platform", "events", "stream.log");
  }

  _readStream() {
    const file = this._streamFile();
    if (!fs.existsSync(file)) return [];
    const out = [];
    for (const line of fs.readFileSync(file, "utf8").split("\n")) {
      if (!line.trim()) continue;
      try {
        const row = JSON.parse(line);
        if (row && Number.isSafeInteger(row.seq) && row.event && typeof row.event === "object") out.push(row);
      } catch {
        /* a torn/corrupt trailing line is skipped, exactly like the audit
         * JSONL reader — it can only be the tail of a crashed append */
      }
    }
    return out;
  }

  _nextSeq() {
    const file = path.resolve(this._streamFile());
    let counter = jsonSeqByFile.get(file);
    if (!counter) {
      const rows = this._readStream();
      counter = { next: rows.length ? rows[rows.length - 1].seq + 1 : 1 };
      jsonSeqByFile.set(file, counter);
    }
    return counter.next++;
  }

  async appendEvent(event) {
    const dir = path.dirname(this._streamFile());
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    // seq assignment + append run synchronously on the event loop — atomic
    // within the single self-hosted server process by construction.
    const seq = this._nextSeq();
    fs.appendFileSync(this._streamFile(), toJsonb({ seq, event }) + "\n", { mode: 0o600 });
    return { seq, cursor: cursorOf(seq) };
  }

  async listEventsAfter({ cursor, limit = 100, types = null } = {}) {
    const after = parseCursor(cursor);
    const wanted = types && types.length && !types.includes("*") ? new Set(types) : null;
    const out = [];
    for (const row of this._readStream()) {
      if (BigInt(row.seq) <= after) continue;
      if (wanted && !wanted.has(row.event.type)) continue;
      out.push({ seq: row.seq, cursor: cursorOf(row.seq), event: row.event });
      if (out.length >= limit) break;
    }
    return out;
  }

  async latestCursor() {
    const rows = this._readStream();
    return rows.length ? cursorOf(rows[rows.length - 1].seq) : "0";
  }

  async countEvents() {
    return this._readStream().length;
  }

  async read(category, key) {
    const p = jsonPathFor(this._config, category, key);
    if (!fs.existsSync(p)) return null;
    const record = readJsonStrict(p, category);
    if (record && record.__key !== undefined && record.__key !== key) {
      throw new EventsStoreError("EVENTS_STORE_KEY_MISMATCH", "stored record key does not match the requested key — failing closed");
    }
    return record ? record.value : null;
  }

  async write(category, key, value) {
    persistJsonDurably({ filePath: jsonPathFor(this._config, category, key), value: { __key: key, value } });
  }

  async createExclusive(category, key, value) {
    try {
      persistJsonDurably({ filePath: jsonPathFor(this._config, category, key), value: { __key: key, value }, createOnly: true });
      return true;
    } catch (error) {
      if (error.code === "EEXIST") return false;
      throw error;
    }
  }

  async remove(category, key) {
    try {
      fs.unlinkSync(jsonPathFor(this._config, category, key));
      return true;
    } catch (error) {
      if (error.code === "ENOENT") return false;
      throw error;
    }
  }

  async listValues(category) {
    const dir = path.join(this._config.dataRoot, "platform", CATEGORY_DIR[category] || "unknown");
    if (!fs.existsSync(dir)) return [];
    const out = [];
    for (const f of fs.readdirSync(dir).filter((f) => f.endsWith(".json"))) {
      try {
        const record = readJsonStrict(path.join(dir, f), category);
        if (record && record.value !== undefined) out.push(record.value);
      } catch {
        /* corrupt record: skipped in listings, exactly like sdk/src/store.js */
      }
    }
    return out;
  }
}

/* ------------------------------------------------------------------ */
/* PostgreSQL backend                                                  */
/* ------------------------------------------------------------------ */

class PgEventsStore {
  constructor(config, pool) {
    this.kind = "postgres";
    this._config = config;
    this._pool = pool;
    this._network = config.networkId;
  }

  async appendEvent(event) {
    const r = await this._pool.query(
      `INSERT INTO platform_events (network_id, event_id, type, vault_id, org_id, value)
       VALUES ($1, $2, $3, $4, $5, $6::jsonb)
       ON CONFLICT (network_id, event_id) DO NOTHING
       RETURNING id`,
      [
        this._network,
        event.eventId,
        event.type,
        typeof event.vaultId === "string" ? event.vaultId : null,
        typeof event.orgId === "string" ? event.orgId : null,
        toJsonb(event)
      ]
    );
    if (!r.rowCount) {
      // The same eventId was already recorded (uuid collision or a caller
      // retry) — the stream stays exactly-once per eventId by construction.
      throw new EventsStoreError("EVENTS_DUPLICATE_EVENT_ID", `event ${event.eventId} already recorded — refusing a duplicate append`);
    }
    const seq = String(r.rows[0].id);
    return { seq: Number(seq), cursor: seq };
  }

  async listEventsAfter({ cursor, limit = 100, types = null } = {}) {
    const after = parseCursor(cursor);
    const params = [this._network, after.toString()];
    let where = `network_id = $1 AND id > $2::bigint`;
    if (types && types.length && !types.includes("*")) {
      params.push(types);
      where += ` AND type = ANY($${params.length})`;
    }
    params.push(Math.max(1, Math.min(Number(limit) || 100, 500)));
    const r = await this._pool.query(`SELECT id, value FROM platform_events WHERE ${where} ORDER BY id ASC LIMIT $${params.length}`, params);
    return r.rows.map((row) => ({ seq: Number(row.id), cursor: String(row.id), event: row.value }));
  }

  async latestCursor() {
    const r = await this._pool.query(`SELECT COALESCE(MAX(id), 0) AS m FROM platform_events WHERE network_id = $1`, [this._network]);
    return String(r.rows[0].m);
  }

  async countEvents() {
    const r = await this._pool.query(`SELECT count(*)::int AS n FROM platform_events WHERE network_id = $1`, [this._network]);
    return r.rows[0].n;
  }

  async read(category, key) {
    const r = await this._pool.query(`SELECT value FROM ${tableFor(category)} WHERE network_id = $1 AND key = $2`, [this._network, key]);
    return r.rowCount ? r.rows[0].value : null;
  }

  async write(category, key, value) {
    await this._pool.query(
      `INSERT INTO ${tableFor(category)} (network_id, key, value, updated_at) VALUES ($1, $2, $3::jsonb, now())
       ON CONFLICT (network_id, key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()`,
      [this._network, key, toJsonb(value)]
    );
  }

  async createExclusive(category, key, value) {
    const r = await this._pool.query(
      `INSERT INTO ${tableFor(category)} (network_id, key, value, updated_at) VALUES ($1, $2, $3::jsonb, now())
       ON CONFLICT (network_id, key) DO NOTHING`,
      [this._network, key, toJsonb(value)]
    );
    return r.rowCount === 1;
  }

  async remove(category, key) {
    const r = await this._pool.query(`DELETE FROM ${tableFor(category)} WHERE network_id = $1 AND key = $2`, [this._network, key]);
    return r.rowCount > 0;
  }

  async listValues(category) {
    const r = await this._pool.query(`SELECT value FROM ${tableFor(category)} WHERE network_id = $1`, [this._network]);
    return r.rows.map((row) => row.value);
  }
}

const eventsStoreByConfig = new WeakMap();

/* The events store for a config. Mirrors platform-store.js exactly: json
 * is eager; postgres reuses the ALREADY-OPENED sdk store's pool and throws
 * if it is not open (never a silent JSON fallback). */
function getEventsStore(config) {
  const existing = eventsStoreByConfig.get(config);
  if (existing) return existing;
  if (config.persistenceBackend === "json") {
    const store = new JsonEventsStore(config);
    eventsStoreByConfig.set(config, store);
    return store;
  }
  if (config.persistenceBackend === "postgres") {
    const pool = getStore(config).pool(); // throws if the sdk store is not open
    const store = new PgEventsStore(config, pool);
    eventsStoreByConfig.set(config, store);
    return store;
  }
  throw new EventsStoreError("EVENTS_STORE_BACKEND_UNKNOWN", `unknown persistenceBackend ${JSON.stringify(config.persistenceBackend)} — failing closed`);
}

module.exports = { Categories, getEventsStore, EventsStoreError, parseCursor };
