"use strict";

/*
 * Durable persistence for the NEW platform-agent-api surfaces (machine
 * identities/credentials, idempotency records — docs/postlaunch/
 * platform-agent-api-spec.md). SAME PATTERN as sdk/src/store.js (create-
 * only claims via link()/EEXIST for the JSON backend and
 * INSERT ... ON CONFLICT DO NOTHING for PostgreSQL) applied to a small,
 * independent category set that lives in ITS OWN tables/directory rather
 * than extending sdk/src/store.js's frozen Categories enum — this worker
 * owns server/** only, not existing sdk/src files, and the store.js
 * category→table/path switch is closed source there. The reused pieces are
 * genuinely shared: sdk/src/durable-json.js's fsync-rename/link() JSON
 * primitives (read-only import), and the SAME open PgStore pool
 * (getStore(config).pool()) so this module dials no connections of its own.
 *
 * Categories (server/migrations/005_platform_agent_api.sql):
 *   MACHINE_IDENTITY   — key = identityId (uuid)
 *   MACHINE_CREDENTIAL — key = SHA-256(raw bearer token) hex
 *   IDEMPOTENCY        — key = "<principalScope>:<Idempotency-Key>"
 *
 * JSON backend layout: config.dataRoot/platform/<category>/<fileKey>.json,
 * where fileKey = SHA-256(key) hex — decouples on-disk filenames from
 * caller-controlled key content (an Idempotency-Key header is arbitrary
 * caller text; hashing it closes any path-traversal/length surface without
 * a bespoke sanitizer). The PG backend uses the raw key as a parameterized
 * query value (no such concern — no string concatenation into SQL).
 */

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const { persistJsonDurably, readJsonStrict } = require("../../sdk/src/durable-json");
const { getStore } = require("../../sdk/src/store");

const Categories = Object.freeze({
  MACHINE_IDENTITY: "platform-machine-identity",
  MACHINE_CREDENTIAL: "platform-machine-credential",
  IDEMPOTENCY: "platform-idempotency",
  /* Hosted-layer agent suspensions (surface 21 residual; migration 007;
   * server/src/agent-suspensions.js). Coordination control only — never a
   * covenant control. key = vaultId. */
  AGENT_SUSPENSION: "platform-agent-suspension",
  /* Audit hash-chain head anchor (surface 17 residual; migration 008;
   * server/src/audit-chain.js). key = "head" — one record per network/
   * data root. An append-time anchor + truncation tripwire; the chained
   * audit records themselves are the verification truth. */
  AUDIT_CHAIN: "platform-audit-chain"
});

const CATEGORY_DIR = Object.freeze({
  [Categories.MACHINE_IDENTITY]: "identities",
  [Categories.MACHINE_CREDENTIAL]: "credentials",
  [Categories.IDEMPOTENCY]: "idempotency",
  [Categories.AGENT_SUSPENSION]: "agent-suspensions",
  [Categories.AUDIT_CHAIN]: "audit-chain"
});

const CATEGORY_TABLE = Object.freeze({
  [Categories.MACHINE_IDENTITY]: "machine_identities",
  [Categories.MACHINE_CREDENTIAL]: "machine_credentials",
  [Categories.IDEMPOTENCY]: "idempotency_records",
  [Categories.AGENT_SUSPENSION]: "agent_suspensions",
  [Categories.AUDIT_CHAIN]: "audit_chain_state"
});

class PlatformStoreError extends Error {
  constructor(code, message) {
    super(message);
    this.code = code;
  }
}

function tableFor(category) {
  const table = CATEGORY_TABLE[category];
  if (!table) throw new PlatformStoreError("PLATFORM_STORE_CATEGORY_UNKNOWN", `unknown platform-store category ${JSON.stringify(category)} — failing closed`);
  return table;
}

function fileKeyOf(key) {
  return crypto.createHash("sha256").update(String(key), "utf8").digest("hex");
}

function jsonPathFor(config, category, key) {
  const dir = CATEGORY_DIR[category];
  if (!dir) throw new PlatformStoreError("PLATFORM_STORE_CATEGORY_UNKNOWN", `unknown platform-store category ${JSON.stringify(category)} — failing closed`);
  return path.join(config.dataRoot, "platform", dir, `${fileKeyOf(key)}.json`);
}

/* BigInt-safe jsonb round trip, identical discipline to sdk/src/store.js. */
function toJsonb(value) {
  return JSON.stringify(value, (_, item) => (typeof item === "bigint" ? item.toString() : item));
}

class JsonPlatformStore {
  constructor(config) {
    this.kind = "json";
    this._config = config;
  }

  async read(category, key) {
    const p = jsonPathFor(this._config, category, key);
    if (!fs.existsSync(p)) return null;
    const record = readJsonStrict(p, category);
    // The stored envelope carries the real key (fileKeyOf collisions are
    // astronomically unlikely at 256 bits, but this is a cheap, honest
    // belt-and-suspenders check — a divergence fails closed rather than
    // silently returning someone else's record).
    if (record && record.__key !== undefined && record.__key !== key) {
      throw new PlatformStoreError("PLATFORM_STORE_KEY_MISMATCH", "stored platform record key does not match the requested key — failing closed");
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

class PgPlatformStore {
  constructor(config, pool) {
    this.kind = "postgres";
    this._config = config;
    this._pool = pool;
    this._network = config.networkId;
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

const platformStoreByConfig = new WeakMap();

/*
 * The platform store for a config. json is eager (no separate open step —
 * it needs no connection, exactly like sdk/src/store.js's JsonStore).
 * postgres reuses the ALREADY-OPENED sdk store's pool (server startup
 * discipline proves that pool open before serving); if the sdk store is not
 * open this throws (never a silent JSON fallback), matching sdk/src/
 * store.js getStore's own contract.
 */
function getPlatformStore(config) {
  const existing = platformStoreByConfig.get(config);
  if (existing) return existing;
  if (config.persistenceBackend === "json") {
    const store = new JsonPlatformStore(config);
    platformStoreByConfig.set(config, store);
    return store;
  }
  if (config.persistenceBackend === "postgres") {
    const pool = getStore(config).pool(); // throws PLATFORM read: STORE_NOT_OPEN-shaped error if not open
    const store = new PgPlatformStore(config, pool);
    platformStoreByConfig.set(config, store);
    return store;
  }
  throw new PlatformStoreError("PLATFORM_STORE_BACKEND_UNKNOWN", `unknown persistenceBackend ${JSON.stringify(config.persistenceBackend)} — failing closed`);
}

module.exports = { Categories, getPlatformStore, PlatformStoreError };
