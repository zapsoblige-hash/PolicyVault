"use strict";

/*
 * HOSTED DEPLOYMENT posture (Phase E — containers/staging).
 *
 * UNIT + INTEGRATION over the deployment-facing surfaces added in Phase E:
 *   - config validation: bindAddress / buildId / stagingBanner (fail closed)
 *   - GET /health liveness additions (buildId, staging)
 *   - GET /health/ready readiness semantics (json + postgres; NEVER ready
 *     with the database gone — no silent JSON fallback)
 *   - standalone migrator: `node server/src/migrate.js` as a real child
 *     process (regression for the Phase E MODULE_NOT_FOUND finding), its
 *     idempotence, and TWO CONCURRENT migrators serializing safely
 *   - server startup order as a real child process: a hosted postgres
 *     server must refuse to listen when the database is unreachable or
 *     the schema is not current, and must never auto-migrate
 *   - deployment-level mainnet refusals (staging cannot boot mainnet)
 *
 * PostgreSQL-backed tests self-skip without POLICYVAULT_TEST_PG_*.
 */

const { test, before, after } = require("node:test");
const assert = require("node:assert/strict");
const os = require("node:os");
const fs = require("node:fs");
const net = require("node:net");
const path = require("node:path");
const http = require("node:http");
const { spawn } = require("node:child_process");

const { loadConfig, assertDataRootNetwork } = require("../src/config");
const { openPgStore } = require("../src/store");
const { handle } = require("../../server/src/api");

const REPO_ROOT = path.join(__dirname, "..", "..");
const SERVER_JS = path.join(REPO_ROOT, "server", "src", "server.js");
const MIGRATE_JS = path.join(REPO_ROOT, "server", "src", "migrate.js");

const PG = {
  host: process.env.POLICYVAULT_TEST_PG_HOST || "127.0.0.1",
  port: Number(process.env.POLICYVAULT_TEST_PG_PORT || 0),
  user: process.env.POLICYVAULT_TEST_PG_USER,
  database: process.env.POLICYVAULT_TEST_PG_DATABASE
};
const PG_AVAILABLE = Boolean(PG.port && PG.user && PG.database);
const pgSkip = PG_AVAILABLE ? undefined : "set POLICYVAULT_TEST_PG_{PORT,USER,DATABASE} to run PostgreSQL deployment tests";

let adminPool;
let dbCounter = 0;
const createdDbs = [];
const openStores = [];
const children = [];

const tmpRoot = () => fs.mkdtempSync(path.join(os.tmpdir(), "pv-deploy-"));

async function freshDatabase() {
  const dbName = `pv_dep_${process.pid}_${++dbCounter}`;
  await adminPool.query(`CREATE DATABASE ${dbName}`);
  createdDbs.push(dbName);
  return dbName;
}

function pgEnv(dbName) {
  return {
    POLICYVAULT_PERSISTENCE: "postgres",
    POLICYVAULT_PG_HOST: PG.host,
    POLICYVAULT_PG_PORT: String(PG.port),
    POLICYVAULT_PG_USER: PG.user,
    POLICYVAULT_PG_DATABASE: dbName,
    POLICYVAULT_PG_NO_TLS: "1"
  };
}

/* The migration step runs with the SAME hosted environment as the app
 * (one env file in the deployment) — postgres config requires the hosted
 * auth posture (§44 hosted-safe-by-default), migration included. */
function migrateEnv(dbName) {
  return {
    ...pgEnv(dbName),
    POLICYVAULT_HOSTED_AUTH: "1",
    POLICYVAULT_AUTH_COOKIE_INSECURE: "1"
  };
}

function freePort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.listen(0, "127.0.0.1", () => {
      const port = srv.address().port;
      srv.close(() => resolve(port));
    });
    srv.on("error", reject);
  });
}

/* Spawn a real server/migrate child with a clean, explicit environment.
 * Returns { child, exited } where exited resolves to the exit code. */
function spawnNode(script, env, { collect = true } = {}) {
  const child = spawn(process.execPath, [script], {
    cwd: REPO_ROOT,
    env: { HOME: process.env.HOME, PATH: process.env.PATH, ...env },
    stdio: ["ignore", "pipe", "pipe"]
  });
  children.push(child);
  let out = "";
  if (collect) {
    child.stdout.on("data", (d) => (out += d));
    child.stderr.on("data", (d) => (out += d));
  }
  const exited = new Promise((resolve) => child.on("exit", (code) => resolve(code)));
  return { child, exited, output: () => out };
}

function getJson(port, pathname) {
  return new Promise((resolve, reject) => {
    const req = http.get({ host: "127.0.0.1", port, path: pathname }, (res) => {
      let body = "";
      res.on("data", (d) => (body += d));
      res.on("end", () => {
        try {
          resolve({ status: res.statusCode, body: JSON.parse(body) });
        } catch (e) {
          reject(e);
        }
      });
    });
    req.on("error", reject);
    req.setTimeout(5000, () => req.destroy(new Error("timeout")));
  });
}

async function waitFor(fn, { timeoutMs = 30_000, intervalMs = 200, label = "condition" } = {}) {
  const start = Date.now();
  for (;;) {
    try {
      const v = await fn();
      if (v) return v;
    } catch {
      /* keep waiting */
    }
    if (Date.now() - start > timeoutMs) throw new Error(`timed out waiting for ${label}`);
    await new Promise((r) => setTimeout(r, intervalMs));
  }
}

before(async () => {
  if (!PG_AVAILABLE) return;
  const { Pool } = require("pg");
  adminPool = new Pool({ host: PG.host, port: PG.port, user: PG.user, database: PG.database });
});

after(async () => {
  for (const c of children) {
    try {
      c.kill("SIGKILL");
    } catch {
      /* already gone */
    }
  }
  if (!PG_AVAILABLE) return;
  for (const store of openStores) {
    try {
      await store.close();
    } catch {
      /* already closed */
    }
  }
  for (const db of createdDbs) {
    try {
      await adminPool.query(`DROP DATABASE IF EXISTS ${db} WITH (FORCE)`);
    } catch {
      /* best effort */
    }
  }
  await adminPool.end();
});

/* ------------------------------------------------------------------ */
/* Config validation                                                   */
/* ------------------------------------------------------------------ */

test("§E config: bindAddress defaults to loopback; IP literals accepted; junk fails closed", () => {
  assert.equal(loadConfig({ dataRoot: tmpRoot() }).bindAddress, "127.0.0.1");
  assert.equal(loadConfig({ dataRoot: tmpRoot(), bindAddress: "0.0.0.0" }).bindAddress, "0.0.0.0");
  assert.equal(loadConfig({ dataRoot: tmpRoot(), bindAddress: "::1" }).bindAddress, "::1");
  assert.equal(loadConfig({ dataRoot: tmpRoot(), bindAddress: " 10.8.0.5 " }).bindAddress, "10.8.0.5");
  for (const bad of ["app.example.com", "localhost", "http://127.0.0.1", "127.0.0.1:3080", "", "0.0.0.0 --evil"]) {
    assert.throws(() => loadConfig({ dataRoot: tmpRoot(), bindAddress: bad }), /IP literal/, `bindAddress ${JSON.stringify(bad)} must fail closed`);
  }
});

test("§E config: POLICYVAULT_DATA_ROOT must be absolute (fail closed), and is honored", () => {
  const prev = process.env.POLICYVAULT_DATA_ROOT;
  try {
    process.env.POLICYVAULT_DATA_ROOT = "relative/path";
    assert.throws(() => loadConfig({}), /POLICYVAULT_DATA_ROOT/);
    const abs = tmpRoot();
    process.env.POLICYVAULT_DATA_ROOT = abs;
    assert.equal(loadConfig({}).dataRoot, abs);
    // An explicit override still wins over the env.
    const other = tmpRoot();
    assert.equal(loadConfig({ dataRoot: other }).dataRoot, other);
  } finally {
    if (prev === undefined) delete process.env.POLICYVAULT_DATA_ROOT;
    else process.env.POLICYVAULT_DATA_ROOT = prev;
  }
});

test("§E config: buildId optional, shape-validated, surfaced by /health only when set", async () => {
  const none = loadConfig({ dataRoot: tmpRoot() });
  assert.equal(none.buildId, null);
  const withId = loadConfig({ dataRoot: tmpRoot(), buildId: "058019f-phaseE.1" });
  assert.equal(withId.buildId, "058019f-phaseE.1");
  for (const bad of ["has space", "a".repeat(65), "semi;colon", "sla/sh", "$secret"]) {
    assert.throws(() => loadConfig({ dataRoot: tmpRoot(), buildId: bad }), /POLICYVAULT_BUILD_ID/, `buildId ${JSON.stringify(bad)} must fail closed`);
  }
  const h1 = await handle(withId, "GET", ["health"], {}, undefined);
  assert.equal(h1.status, 200);
  assert.equal(h1.body.buildId, "058019f-phaseE.1");
  const h0 = await handle(none, "GET", ["health"], {}, undefined);
  assert.equal("buildId" in h0.body, false, "no buildId claim when none configured");
});

test("§E config: stagingBanner reports via /health and is IMPOSSIBLE on mainnet", async () => {
  const staging = loadConfig({ dataRoot: tmpRoot(), stagingBanner: true });
  assert.equal(staging.stagingBanner, true);
  const h = await handle(staging, "GET", ["health"], {}, undefined);
  assert.equal(h.body.staging, true);
  const plain = loadConfig({ dataRoot: tmpRoot() });
  assert.equal("staging" in (await handle(plain, "GET", ["health"], {}, undefined)).body, false);
  // Staging identity on mainnet fails closed at config time (§26: the
  // staging deployment configuration cannot accidentally boot mainnet
  // wearing a staging label, and vice versa).
  const prevEnv = process.env.POLICYVAULT_ALLOW_MAINNET;
  process.env.POLICYVAULT_ALLOW_MAINNET = "true";
  try {
    assert.throws(
      () =>
        loadConfig({
          networkId: "mainnet",
          allowMainnet: true,
          rpcUrl: "ws://127.0.0.1:18110",
          dataRoot: tmpRoot(),
          stagingBanner: true
        }),
      /STAGING_BANNER|staging/i
    );
  } finally {
    if (prevEnv === undefined) delete process.env.POLICYVAULT_ALLOW_MAINNET;
    else process.env.POLICYVAULT_ALLOW_MAINNET = prevEnv;
  }
});

/* ------------------------------------------------------------------ */
/* Readiness (json mode)                                               */
/* ------------------------------------------------------------------ */

test("§E readiness (json): stamped data root is ready; unstamped or foreign-network root is NOT", async () => {
  const config = loadConfig({ dataRoot: tmpRoot() });
  // Before the startup stamp: not ready.
  const before1 = await handle(config, "GET", ["health", "ready"], {}, undefined);
  assert.equal(before1.status, 503);
  assert.equal(before1.body.ready, false);
  assert.equal(before1.body.reason, "DATA_ROOT_NOT_STAMPED");
  // After the normal startup stamp: ready.
  assertDataRootNetwork(config);
  const ok = await handle(config, "GET", ["health", "ready"], {}, undefined);
  assert.equal(ok.status, 200);
  assert.equal(ok.body.ready, true);
  assert.equal(ok.body.persistence, "json");
  // A root stamped for a DIFFERENT network is never ready.
  const foreign = loadConfig({ dataRoot: tmpRoot() });
  fs.writeFileSync(path.join(foreign.dataRoot, ".pv-network"), "mainnet\n");
  const bad = await handle(foreign, "GET", ["health", "ready"], {}, undefined);
  assert.equal(bad.status, 503);
  assert.equal(bad.body.reason, "DATA_ROOT_NOT_STAMPED");
});

/* ------------------------------------------------------------------ */
/* Readiness (postgres mode)                                           */
/* ------------------------------------------------------------------ */

test("§E readiness (postgres): ready with a live migrated DB; NOT ready when the store is unopened or the DB dies", { skip: pgSkip }, async () => {
  const dbName = await freshDatabase();
  const overrides = {
    persistenceBackend: "postgres",
    pgHost: PG.host,
    pgPort: PG.port,
    pgUser: PG.user,
    pgDatabase: dbName,
    pgNoTls: true,
    hostedDevOpen: true,
    dataRoot: tmpRoot()
  };
  // Unopened store (startup order violated): 503, store-not-open.
  const unopened = loadConfig(overrides);
  const r0 = await handle(unopened, "GET", ["health", "ready"], {}, undefined);
  assert.equal(r0.status, 503);
  assert.equal(r0.body.reason, "STORE_NOT_OPEN");
  // Properly opened (migrated) store: ready.
  const config = loadConfig(overrides);
  const store = await openPgStore(config, { migrate: true });
  openStores.push(store);
  const r1 = await handle(config, "GET", ["health", "ready"], {}, undefined);
  assert.equal(r1.status, 200);
  assert.equal(r1.body.ready, true);
  assert.equal(r1.body.persistence, "postgres");
  // Database gone: NEVER ready, NEVER a silent JSON fallback.
  await store.pool().end();
  const r2 = await handle(config, "GET", ["health", "ready"], {}, undefined);
  assert.equal(r2.status, 503);
  assert.equal(r2.body.ready, false);
  assert.equal(r2.body.reason, "DATABASE_UNREACHABLE");
});

test("§E pool survivability: the pg pool carries an idle-client error handler (DB restart must not kill the process)", { skip: pgSkip }, async () => {
  // REGRESSION (found in the Phase E restart matrix): with no pool
  // 'error' listener, a PostgreSQL stop/failover killed the whole app
  // via an unhandled 'error' event from an idle client. The shared
  // createPgPool must always attach one.
  const { createPgPool } = require("../src/store");
  const config = loadConfig({
    persistenceBackend: "postgres",
    pgHost: PG.host,
    pgPort: PG.port,
    pgUser: PG.user,
    pgDatabase: PG.database,
    pgNoTls: true,
    hostedDevOpen: true,
    dataRoot: tmpRoot()
  });
  const pool = createPgPool(config);
  try {
    assert.ok(pool.listenerCount("error") >= 1, "pool must handle idle-client errors");
    // And the handler actually absorbs an emitted error (no throw).
    pool.emit("error", Object.assign(new Error("simulated idle-client termination"), { code: "57P01" }));
  } finally {
    await pool.end();
  }
});

/* ------------------------------------------------------------------ */
/* Standalone migrator (child process)                                 */
/* ------------------------------------------------------------------ */

test("§E migrate: `node server/src/migrate.js` runs standalone (regression: pg resolution), idempotently", { skip: pgSkip }, async () => {
  const dbName = await freshDatabase();
  const env = migrateEnv(dbName);
  const first = spawnNode(MIGRATE_JS, env);
  assert.equal(await first.exited, 0, `first migrate run must exit 0 — output:\n${first.output()}`);
  assert.match(first.output(), /schema current/);
  // Applied exactly the known migration set.
  const { Pool } = require("pg");
  const probe = new Pool({ host: PG.host, port: PG.port, user: PG.user, database: dbName });
  try {
    const { listMigrationFiles } = require("../../server/src/migrate");
    const rows = await probe.query(`SELECT version FROM schema_migrations ORDER BY version`);
    assert.deepEqual(
      rows.rows.map((r) => r.version),
      listMigrationFiles().map((m) => m.version)
    );
  } finally {
    await probe.end();
  }
  // Second run: no-op, still exit 0.
  const second = spawnNode(MIGRATE_JS, env);
  assert.equal(await second.exited, 0, `re-run must be a no-op success — output:\n${second.output()}`);
});

test("§E migrate: TWO CONCURRENT migrators serialize under the advisory lock (no corruption)", { skip: pgSkip }, async () => {
  const dbName = await freshDatabase();
  const env = migrateEnv(dbName);
  const a = spawnNode(MIGRATE_JS, env);
  const b = spawnNode(MIGRATE_JS, env);
  const [codeA, codeB] = await Promise.all([a.exited, b.exited]);
  assert.equal(codeA, 0, `migrator A must succeed — output:\n${a.output()}`);
  assert.equal(codeB, 0, `migrator B must succeed — output:\n${b.output()}`);
  const { Pool } = require("pg");
  const probe = new Pool({ host: PG.host, port: PG.port, user: PG.user, database: dbName });
  try {
    const { listMigrationFiles } = require("../../server/src/migrate");
    const rows = await probe.query(`SELECT version, count(*) AS n FROM schema_migrations GROUP BY version`);
    assert.equal(rows.rowCount, listMigrationFiles().length, "each migration recorded exactly once");
    for (const r of rows.rows) assert.equal(Number(r.n), 1);
  } finally {
    await probe.end();
  }
});

/* ------------------------------------------------------------------ */
/* Server startup order (child process)                                */
/* ------------------------------------------------------------------ */

function hostedServerEnv(dbName, port) {
  return {
    ...pgEnv(dbName),
    POLICYVAULT_API_PORT: String(port),
    POLICYVAULT_HOSTED_AUTH: "1",
    POLICYVAULT_AUTH_COOKIE_INSECURE: "1",
    POLICYVAULT_APP_ORIGIN: `http://127.0.0.1:${port}`,
    POLICYVAULT_DATA_ROOT: tmpRoot(),
    POLICYVAULT_BUILD_ID: "phaseE-test"
  };
}

test("§E startup: a hosted postgres server REFUSES to listen when the database is unreachable", { skip: pgSkip }, async () => {
  const port = await freePort();
  const deadDbPort = await freePort(); // nothing listens here
  const env = {
    ...hostedServerEnv("pv_nonexistent", port),
    POLICYVAULT_PG_PORT: String(deadDbPort)
  };
  const proc = spawnNode(SERVER_JS, env);
  const code = await proc.exited;
  assert.notEqual(code, 0, `startup must fail closed — output:\n${proc.output()}`);
  assert.match(proc.output(), /startup failed \(fail closed\)/);
  // And it never listened.
  await assert.rejects(getJson(port, "/api/v1/health"), /ECONNREFUSED|timeout/);
});

test("§E startup: an UNMIGRATED database refuses to serve (no auto-migration, no HTTP before schema)", { skip: pgSkip }, async () => {
  const dbName = await freshDatabase(); // fresh: no schema
  const port = await freePort();
  const proc = spawnNode(SERVER_JS, hostedServerEnv(dbName, port));
  const code = await proc.exited;
  assert.notEqual(code, 0, `unmigrated schema must refuse startup — output:\n${proc.output()}`);
  assert.match(proc.output(), /not current|missing migration|schema/i);
  await assert.rejects(getJson(port, "/api/v1/health"), /ECONNREFUSED|timeout/);
});

test("§E startup: migrate-then-serve succeeds; /health/ready is TRUE and reports buildId", { skip: pgSkip }, async () => {
  const dbName = await freshDatabase();
  const migrate = spawnNode(MIGRATE_JS, migrateEnv(dbName));
  assert.equal(await migrate.exited, 0, `migration step must succeed — output:\n${migrate.output()}`);
  const port = await freePort();
  const proc = spawnNode(SERVER_JS, hostedServerEnv(dbName, port));
  try {
    const ready = await waitFor(
      async () => {
        const r = await getJson(port, "/api/v1/health/ready");
        return r.status === 200 ? r : null;
      },
      { label: "server readiness" }
    );
    assert.equal(ready.body.ready, true);
    assert.equal(ready.body.persistence, "postgres");
    assert.equal(ready.body.buildId, "phaseE-test");
    const health = await getJson(port, "/api/v1/health");
    assert.equal(health.body.ok, true);
    assert.equal(health.body.buildId, "phaseE-test");
  } finally {
    proc.child.kill("SIGKILL");
    await proc.exited;
  }
});

test("§E startup: staging deployment env CANNOT boot mainnet (missing dual unlock refuses)", async () => {
  const port = await freePort();
  const proc = spawnNode(SERVER_JS, {
    KASPA_NETWORK_ID: "mainnet",
    POLICYVAULT_API_PORT: String(port)
    // deliberately NO POLICYVAULT_ALLOW_MAINNET, NO explicit RPC URL
  });
  const code = await proc.exited;
  assert.notEqual(code, 0, `mainnet without the dual unlock must refuse — output:\n${proc.output()}`);
  assert.match(proc.output(), /mainnet mode is locked/i);
  await assert.rejects(getJson(port, "/api/v1/health"), /ECONNREFUSED|timeout/);
});

test("§E-R compose: migrate service overrides the image ENTRYPOINT (server.js) with migrate.js", () => {
  // Found by the first REAL `docker compose run migrate` (Phase E-R): the
  // image pins ENTRYPOINT to server.js, and compose `command:` is
  // APPENDED to the entrypoint — a migrate service using `command:`
  // silently runs the SERVER (which fails closed on a missing schema)
  // instead of the migrator. The migrate service must use `entrypoint:`.
  const dockerfile = fs.readFileSync(path.join(REPO_ROOT, "deploy", "Dockerfile"), "utf8");
  assert.match(
    dockerfile,
    /^ENTRYPOINT \["node", "\/app\/server\/src\/server\.js"\]\s*$/m,
    "Dockerfile ENTRYPOINT contract this regression is anchored to"
  );
  const compose = fs.readFileSync(path.join(REPO_ROOT, "deploy", "docker-compose.staging.yml"), "utf8");
  const migrateBlock = compose.split(/\n  migrate:\n/)[1]?.split(/\n  app:\n/)[0];
  assert.ok(migrateBlock, "migrate service block present");
  assert.match(
    migrateBlock,
    /entrypoint: \["node", "\/app\/server\/src\/migrate\.js"\]/,
    "migrate service must OVERRIDE the entrypoint to run the migrator"
  );
  assert.doesNotMatch(
    migrateBlock,
    /command: \[[^\]]*migrate\.js/,
    "migrate.js must never ride on `command:` (appended to the server entrypoint)"
  );
});
