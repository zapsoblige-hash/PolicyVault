"use strict";

/*
 * Durable persistence backend abstraction (Hosted Web checkpoint,
 * Phase C).
 *
 * PolicyVault's durable application state has exactly one write shape:
 * one logical JSON object per key within a small set of categories, plus
 * an append-only audit stream. This module abstracts THAT — the exact
 * primitives the proven JSON implementation uses — behind two drivers:
 *
 *   json      — the released self-hosted backend: files under
 *               config.dataRoot with the durable-json fsync-rename
 *               discipline and link()-based create-only claims.
 *               Behavior-identical to the pre-Phase-C code by
 *               construction (it IS that code, relocated).
 *   postgres  — the hosted backend: one table per category, single-
 *               statement atomic operations; INSERT ... ON CONFLICT
 *               DO NOTHING is the create-only claim arbiter (the
 *               link()/EEXIST equivalent). Real network binding: the
 *               database is stamped with ONE owning network (write-once
 *               meta row, the .pv-network analog) AND every row carries
 *               network_id in its primary key.
 *
 * SEMANTIC PORT, NOT A REDESIGN (Phase C directive §6): claim conflict
 * classes, idempotency, overwrite vs create-only, list shapes, and the
 * EXISTING non-atomic audit-after-mutation ordering are preserved
 * exactly. Chain truth remains authoritative above both drivers.
 *
 * Backend selection is validated configuration (config.persistenceBackend);
 * unknown values fail closed, and the postgres driver NEVER falls back to
 * json (or vice versa) — a hosted process that cannot reach its database
 * refuses to operate.
 */

const fs = require("fs");
const path = require("path");

const { persistJsonDurably, readJsonStrict } = require("./durable-json");

/* Categories — the closed set of durable object families. */
const Categories = Object.freeze({
  VAULT: "vault", // key: vaultId              (manifest.json per vault)
  REQUEST: "request", // key: requestId
  TRANSITION_CLAIM: "transition-claim", // key: "<txid>-<index>" (exact predecessor outpoint)
  SUBMISSION_CLAIM: "submission-claim", // key: txId
  RECEIPT: "receipt", // key: txId
  ORG: "org", // key: orgId
  ORG_ASSIGNMENTS: "org-assignments", // key: "assignments" (single record)
  // Post-launch correlation + governance + risk families (postlaunch-rc;
  // migrations 002/003/004). Same one-object-per-key shape as the rest.
  INTENT_MANIFEST: "intent-manifest", // key: manifestHash (64-hex); create-only
  GOVERNANCE_PROPOSAL: "governance-proposal", // key: proposalId (uuid)
  GOVERNANCE_APPROVAL: "governance-approval", // key: "<proposalDigest>-<approverXOnly>"; create-only
  ORG_CONTROLS: "org-controls", // key: orgId (governance quorum/delay + risk adapter config)
  RISK_EVALUATION: "risk-evaluation" // key: evaluationId (uuid)
});

class StoreError extends Error {
  constructor(code, message) {
    super(message);
    this.code = code;
  }
}

/* ------------------------------------------------------------------ */
/* JSON driver — the released self-hosted layout, byte-for-byte.       */
/* ------------------------------------------------------------------ */

function jsonPathFor(config, category, key) {
  switch (category) {
    case Categories.VAULT:
      return path.join(config.dataRoot, "vaults", key, "manifest.json");
    case Categories.REQUEST:
      return path.join(config.dataRoot, "requests", `${key}.json`);
    case Categories.TRANSITION_CLAIM:
      return path.join(config.dataRoot, "claims", "transition", `${key}.json`);
    case Categories.SUBMISSION_CLAIM:
      return path.join(config.dataRoot, "claims", "submission", `${key}.json`);
    case Categories.RECEIPT:
      return path.join(config.dataRoot, "receipts", `${key}.json`);
    case Categories.ORG:
      return path.join(config.dataRoot, "orgs", `${key}.json`);
    case Categories.ORG_ASSIGNMENTS:
      return path.join(config.dataRoot, "orgs", "assignments.json");
    case Categories.INTENT_MANIFEST:
      return path.join(config.dataRoot, "manifests", `${key}.json`);
    case Categories.GOVERNANCE_PROPOSAL:
      return path.join(config.dataRoot, "governance", "proposals", `${key}.json`);
    case Categories.GOVERNANCE_APPROVAL:
      return path.join(config.dataRoot, "governance", "approvals", `${key}.json`);
    case Categories.ORG_CONTROLS:
      return path.join(config.dataRoot, "org-controls", `${key}.json`);
    case Categories.RISK_EVALUATION:
      return path.join(config.dataRoot, "risk", "evaluations", `${key}.json`);
    default:
      throw new StoreError("STORE_CATEGORY_UNKNOWN", `unknown store category ${JSON.stringify(category)} — failing closed`);
  }
}

class JsonStore {
  constructor(config) {
    this.kind = "json";
    this._config = config;
  }

  async read(category, key) {
    const p = jsonPathFor(this._config, category, key);
    return fs.existsSync(p) ? readJsonStrict(p, category) : null;
  }

  /* Overwrite-or-create durable write (fsync-rename). */
  async write(category, key, value) {
    persistJsonDurably({ filePath: jsonPathFor(this._config, category, key), value });
  }

  /*
   * Create-only claim write. Returns true when THIS call created the
   * record; false when the key already existed (the caller maps false to
   * its claim-conflict semantics). link()/EEXIST is the arbiter.
   */
  async createExclusive(category, key, value) {
    try {
      persistJsonDurably({ filePath: jsonPathFor(this._config, category, key), value, createOnly: true });
      return true;
    } catch (error) {
      if (error.code === "EEXIST") return false;
      throw error;
    }
  }

  /* Idempotent delete. Returns true when a record was removed. */
  async remove(category, key) {
    try {
      fs.unlinkSync(jsonPathFor(this._config, category, key));
      return true;
    } catch (error) {
      if (error.code === "ENOENT") return false;
      throw error;
    }
  }

  /* Keys in a category. Vaults are directories; the rest are *.json. */
  async listKeys(category) {
    if (category === Categories.VAULT) {
      const dir = path.join(this._config.dataRoot, "vaults");
      if (!fs.existsSync(dir)) return [];
      return fs
        .readdirSync(dir, { withFileTypes: true })
        .filter((e) => e.isDirectory())
        .map((e) => e.name)
        .filter((name) => fs.existsSync(path.join(dir, name, "manifest.json")));
    }
    const dir = path.dirname(jsonPathFor(this._config, category, "x"));
    if (!fs.existsSync(dir)) return [];
    return fs
      .readdirSync(dir)
      .filter((f) => f.endsWith(".json"))
      .map((f) => f.slice(0, -5))
      .filter((k) => category !== Categories.ORG || k !== "assignments");
  }

  /* All values in a category (corrupt records skipped exactly as the
   * existing request/org listers do — a corrupt record fails in its own
   * flow, never someone else's listing). */
  async listValues(category) {
    const out = [];
    for (const key of await this.listKeys(category)) {
      try {
        const v = await this.read(category, key);
        if (v !== null) out.push(v);
      } catch {
        /* corrupt record: skipped in listings */
      }
    }
    return out;
  }

  /* Append-only audit stream (JSONL), verbatim existing behavior. */
  async appendAudit(record) {
    const dir = path.join(this._config.dataRoot, "audit");
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    fs.appendFileSync(path.join(dir, "events.log"), JSON.stringify(record) + "\n", { mode: 0o600 });
  }

  async readAudit({ vaultId, limit = 200 } = {}) {
    const file = path.join(this._config.dataRoot, "audit", "events.log");
    if (!fs.existsSync(file)) return [];
    const events = fs
      .readFileSync(file, "utf8")
      .trim()
      .split("\n")
      .filter(Boolean)
      .map((line) => {
        try {
          return JSON.parse(line);
        } catch {
          return null;
        }
      })
      .filter(Boolean);
    const filtered = vaultId ? events.filter((e) => e.vaultId === vaultId) : events;
    return filtered.slice(-limit).reverse();
  }

  async close() {
    /* nothing to release */
  }
}

/* ------------------------------------------------------------------ */
/* PostgreSQL driver — hosted mode.                                    */
/* ------------------------------------------------------------------ */

const CATEGORY_TABLE = Object.freeze({
  [Categories.VAULT]: "vaults",
  [Categories.REQUEST]: "wallet_requests",
  [Categories.TRANSITION_CLAIM]: "transition_claims",
  [Categories.SUBMISSION_CLAIM]: "submission_claims",
  [Categories.RECEIPT]: "receipts",
  [Categories.ORG]: "organizations",
  [Categories.ORG_ASSIGNMENTS]: "org_assignments",
  [Categories.INTENT_MANIFEST]: "intent_manifests",
  [Categories.GOVERNANCE_PROPOSAL]: "governance_proposals",
  [Categories.GOVERNANCE_APPROVAL]: "governance_approvals",
  [Categories.ORG_CONTROLS]: "org_controls",
  [Categories.RISK_EVALUATION]: "risk_evaluations"
});

/* BigInt-safe JSON round-trip identical to durable-json's stringify. */
function toJsonb(value) {
  return JSON.stringify(value, (_, item) => (typeof item === "bigint" ? item.toString() : item));
}

class PgStore {
  constructor(config, pool) {
    this.kind = "postgres";
    this._config = config;
    this._pool = pool;
    this._network = config.networkId;
  }

  _table(category) {
    const table = CATEGORY_TABLE[category];
    if (!table) throw new StoreError("STORE_CATEGORY_UNKNOWN", `unknown store category ${JSON.stringify(category)} — failing closed`);
    return table;
  }

  async read(category, key) {
    const r = await this._pool.query(`SELECT value FROM ${this._table(category)} WHERE network_id = $1 AND key = $2`, [this._network, key]);
    return r.rowCount ? r.rows[0].value : null;
  }

  async write(category, key, value) {
    await this._pool.query(
      `INSERT INTO ${this._table(category)} (network_id, key, value, updated_at) VALUES ($1, $2, $3::jsonb, now())
       ON CONFLICT (network_id, key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()`,
      [this._network, key, toJsonb(value)]
    );
  }

  /* The claim arbiter: INSERT ... ON CONFLICT DO NOTHING. rowCount 0 =
   * someone else owns the key (the link()/EEXIST equivalent). The UNIQUE
   * primary key (network_id, key) is the final race arbiter — never
   * SELECT-then-INSERT. */
  async createExclusive(category, key, value) {
    const r = await this._pool.query(
      `INSERT INTO ${this._table(category)} (network_id, key, value, updated_at) VALUES ($1, $2, $3::jsonb, now())
       ON CONFLICT (network_id, key) DO NOTHING`,
      [this._network, key, toJsonb(value)]
    );
    return r.rowCount === 1;
  }

  async remove(category, key) {
    const r = await this._pool.query(`DELETE FROM ${this._table(category)} WHERE network_id = $1 AND key = $2`, [this._network, key]);
    return r.rowCount > 0;
  }

  async listKeys(category) {
    const r = await this._pool.query(`SELECT key FROM ${this._table(category)} WHERE network_id = $1 ORDER BY key`, [this._network]);
    return r.rows.map((row) => row.key);
  }

  async listValues(category) {
    const r = await this._pool.query(`SELECT value FROM ${this._table(category)} WHERE network_id = $1`, [this._network]);
    return r.rows.map((row) => row.value);
  }

  async appendAudit(record) {
    /*
     * Correlation columns (migration 002, audit-correlation-spec §7):
     * requestId/manifestHash/proposalId/txId/actorXOnly are LIFTED from
     * the record into indexed nullable columns, exactly how vault_id is
     * lifted — columns are indexes, never truth; the correlation VALUES
     * live in the jsonb record either way (JSON-backend parity: the
     * JSONL record carries the same fields inline). Records without a
     * field write NULL — "predates correlation" / "no such fact", never
     * a default claim.
     */
    const lift = (field) => (typeof record[field] === "string" && record[field] ? record[field] : null);
    await this._pool.query(
      `INSERT INTO audit_events (network_id, vault_id, value, request_id, manifest_hash, proposal_id, tx_id, actor_xonly)
       VALUES ($1, $2, $3::jsonb, $4, $5, $6, $7, $8)`,
      [
        this._network,
        typeof record.vaultId === "string" ? record.vaultId : null,
        toJsonb(record),
        lift("requestId"),
        lift("manifestHash"),
        lift("proposalId"),
        lift("txId"),
        lift("actorXOnly")
      ]
    );
  }

  async readAudit({ vaultId, limit = 200 } = {}) {
    const params = [this._network];
    let where = "network_id = $1";
    if (vaultId) {
      params.push(vaultId);
      where += ` AND vault_id = $2`;
    }
    params.push(limit);
    const r = await this._pool.query(
      `SELECT value FROM audit_events WHERE ${where} ORDER BY id DESC LIMIT $${params.length}`,
      params
    );
    return r.rows.map((row) => row.value);
  }

  /* The shared connection pool (hosted auth store and Phase C+ layers
   * reuse it; single pool per process, bounded by config). */
  pool() {
    return this._pool;
  }

  async close() {
    await this._pool.end();
  }
}

/* ------------------------------------------------------------------ */
/* Selection + lifecycle                                               */
/* ------------------------------------------------------------------ */

const storeByConfig = new WeakMap();

/*
 * The store for a config. json is constructed eagerly; postgres must be
 * OPENED first (openPgStore) so startup can fail closed before serving —
 * getStore never lazily dials a database.
 */
function getStore(config) {
  const existing = storeByConfig.get(config);
  if (existing) return existing;
  if (config.persistenceBackend === "json") {
    const store = new JsonStore(config);
    storeByConfig.set(config, store);
    return store;
  }
  if (config.persistenceBackend === "postgres") {
    throw new StoreError(
      "STORE_NOT_OPEN",
      "postgres persistence is configured but the store was not opened at startup (openPgStore) — refusing; no silent JSON fallback"
    );
  }
  throw new StoreError("STORE_BACKEND_UNKNOWN", `unknown persistenceBackend ${JSON.stringify(config.persistenceBackend)} — failing closed`);
}

/*
 * Construct the bounded connection pool for a postgres config. The ONE
 * place pg pool options are derived from validated configuration — the
 * store, the standalone migrator, and deployment tooling all share it
 * (and `pg` itself resolves HERE, inside the sdk package, so callers
 * outside sdk/ need no node_modules of their own).
 */
function createPgPool(config) {
  if (config.persistenceBackend !== "postgres" || !config.pg) {
    throw new StoreError("STORE_BACKEND_MISMATCH", "createPgPool requires persistenceBackend=postgres");
  }
  const { Pool } = require("pg");
  const pool = new Pool({
    host: config.pg.host,
    port: config.pg.port,
    user: config.pg.user,
    password: config.pg.password,
    database: config.pg.database,
    ssl: config.pg.ssl ? { rejectUnauthorized: true } : undefined,
    max: config.pg.poolMax,
    connectionTimeoutMillis: config.pg.connectTimeoutMs,
    idleTimeoutMillis: 30_000
  });
  /*
   * A database restart/failover kills the pool's IDLE clients, and pg
   * surfaces that as an 'error' EVENT on the pool — with no listener,
   * Node terminates the whole process (found in the Phase E restart
   * matrix: stopping PostgreSQL crashed the hosted app instead of
   * degrading). In-flight queries reject on their own paths (each route
   * fails closed); the idle-client event is logged coarsely (never
   * credentials) and the process stays up, refusing work until the
   * database returns (readiness reports 503 meanwhile).
   */
  pool.on("error", (error) => {
    console.error(`postgres pool: idle client error (${error.code || error.message}) — refusing work until the database returns`);
  });
  return pool;
}

/*
 * Open (and stamp-verify) the postgres store. Fails closed on: missing
 * driver config, unreachable database, schema not migrated, or a
 * database owned by a DIFFERENT network (the write-once meta stamp — the
 * .pv-network analog). Never falls back to JSON.
 */
async function openPgStore(config, { migrate = false } = {}) {
  if (config.persistenceBackend !== "postgres") {
    throw new StoreError("STORE_BACKEND_MISMATCH", "openPgStore requires persistenceBackend=postgres");
  }
  const pool = createPgPool(config);
  try {
    if (migrate) {
      const { runMigrations } = require("../../server/src/migrate");
      await runMigrations(pool);
    }
    // Schema must be current (fail closed on unknown/older/newer).
    const { assertSchemaCurrent } = require("../../server/src/migrate");
    await assertSchemaCurrent(pool);
    // Write-once network stamp (the .pv-network marker analog).
    await pool.query(`INSERT INTO pv_meta (key, value) VALUES ('network', $1) ON CONFLICT (key) DO NOTHING`, [config.networkId]);
    const stamp = await pool.query(`SELECT value FROM pv_meta WHERE key = 'network'`);
    const owner = stamp.rows[0] ? stamp.rows[0].value : null;
    if (owner !== config.networkId) {
      throw new StoreError(
        "STORE_NETWORK_MISMATCH",
        `database belongs to network ${JSON.stringify(owner)} but this process is configured for ${JSON.stringify(config.networkId)} — refusing (cross-network data contamination)`
      );
    }
    const store = new PgStore(config, pool);
    storeByConfig.set(config, store);
    return store;
  } catch (error) {
    await pool.end().catch(() => {});
    throw error;
  }
}

module.exports = { Categories, getStore, openPgStore, createPgPool, StoreError, JsonStore, PgStore };
