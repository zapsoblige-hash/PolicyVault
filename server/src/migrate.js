"use strict";

/*
 * Versioned PostgreSQL schema migrations (Phase C, directive §9).
 *
 * Deterministic numbered .sql files in server/migrations/, applied in
 * order, each exactly once, inside a transaction with an advisory lock
 * (two concurrent migrators serialize; a failed migration rolls back and
 * is NOT recorded — partial application cannot masquerade as complete).
 * A database whose recorded version is NEWER than this build's migration
 * set fails closed (unknown future schema). Checksums pin each applied
 * migration's exact bytes: a changed historical file is a hard error,
 * never silently re-run.
 *
 * Runnable standalone (node server/src/migrate.js) with the same
 * validated configuration the server uses; separate from normal
 * startup so operators can migrate deliberately.
 */

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const MIGRATIONS_DIR = path.join(__dirname, "..", "migrations");
const ADVISORY_LOCK_KEY = 0x70765f6d; // 'pv_m'

function listMigrationFiles() {
  const files = fs
    .readdirSync(MIGRATIONS_DIR)
    .filter((f) => /^\d{3}_[a-z0-9_]+\.sql$/.test(f))
    .sort();
  return files.map((file) => {
    const version = Number(file.slice(0, 3));
    const sql = fs.readFileSync(path.join(MIGRATIONS_DIR, file), "utf8");
    return { version, file, sql, checksum: crypto.createHash("sha256").update(sql).digest("hex") };
  });
}

async function ensureMigrationsTable(client) {
  await client.query(
    `CREATE TABLE IF NOT EXISTS schema_migrations (
       version    integer PRIMARY KEY,
       name       text NOT NULL,
       checksum   text NOT NULL,
       applied_at timestamptz NOT NULL DEFAULT now()
     )`
  );
}

async function appliedMigrations(client) {
  await ensureMigrationsTable(client);
  const r = await client.query(`SELECT version, name, checksum FROM schema_migrations ORDER BY version`);
  return r.rows;
}

/* Apply all pending migrations. Idempotent: an already-current database
 * is a no-op. Throws on checksum drift, gaps, or a future version. */
async function runMigrations(pool) {
  const client = await pool.connect();
  try {
    await client.query(`SELECT pg_advisory_lock($1)`, [ADVISORY_LOCK_KEY]);
    const available = listMigrationFiles();
    const applied = await appliedMigrations(client);

    const maxAvailable = available.length ? available[available.length - 1].version : 0;
    for (const row of applied) {
      const match = available.find((m) => m.version === row.version);
      if (!match) {
        throw new Error(
          `migrate: database has schema version ${row.version} (${row.name}) unknown to this build ` +
            `(max known ${maxAvailable}) — failing closed; upgrade the application, never the guess`
        );
      }
      if (match.checksum !== row.checksum) {
        throw new Error(`migrate: migration ${row.version} checksum mismatch (file changed after being applied) — failing closed`);
      }
    }

    const appliedVersions = new Set(applied.map((r) => r.version));
    for (const migration of available) {
      if (appliedVersions.has(migration.version)) continue;
      await client.query("BEGIN");
      try {
        await client.query(migration.sql);
        await client.query(`INSERT INTO schema_migrations (version, name, checksum) VALUES ($1, $2, $3)`, [
          migration.version,
          migration.file,
          migration.checksum
        ]);
        await client.query("COMMIT");
      } catch (error) {
        await client.query("ROLLBACK");
        throw new Error(`migrate: migration ${migration.file} failed and was rolled back: ${error.message}`);
      }
    }
    return { applied: available.length };
  } finally {
    await client.query(`SELECT pg_advisory_unlock($1)`, [ADVISORY_LOCK_KEY]).catch(() => {});
    client.release();
  }
}

/* Startup gate: the schema must be exactly this build's migration set. */
async function assertSchemaCurrent(pool) {
  const client = await pool.connect();
  try {
    const available = listMigrationFiles();
    const applied = await appliedMigrations(client);
    const appliedVersions = applied.map((r) => r.version);
    const availableVersions = available.map((m) => m.version);
    const maxApplied = appliedVersions.length ? Math.max(...appliedVersions) : 0;
    const maxAvailable = availableVersions.length ? Math.max(...availableVersions) : 0;
    if (maxApplied > maxAvailable) {
      throw new Error(`migrate: database schema version ${maxApplied} is newer than this build (${maxAvailable}) — failing closed`);
    }
    for (const m of available) {
      const row = applied.find((r) => r.version === m.version);
      if (!row) {
        throw new Error(`migrate: database schema is not current (missing migration ${m.file}) — run migrations first; refusing to serve`);
      }
      if (row.checksum !== m.checksum) {
        throw new Error(`migrate: migration ${m.version} checksum mismatch — failing closed`);
      }
    }
  } finally {
    client.release();
  }
}

if (require.main === module) {
  (async () => {
    const { loadConfig } = require("../../sdk/src/config");
    const config = loadConfig({ allowMainnet: process.env.POLICYVAULT_ALLOW_MAINNET === "true" });
    if (config.persistenceBackend !== "postgres") {
      console.error("migrate: persistenceBackend is not postgres — nothing to do");
      process.exit(2);
    }
    // The pool comes from the sdk helper so `pg` resolves inside the sdk
    // package (this file has no node_modules of its own — requiring "pg"
    // directly here fails standalone; found+fixed in Phase E).
    const { createPgPool } = require("../../sdk/src/store");
    const pool = createPgPool(config);
    try {
      const r = await runMigrations(pool);
      console.log(`migrate: schema current (${r.applied} migrations known)`);
    } finally {
      await pool.end();
    }
  })().catch((e) => {
    console.error(e.message);
    process.exit(1);
  });
}

module.exports = { runMigrations, assertSchemaCurrent, listMigrationFiles };
