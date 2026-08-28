"use strict";

/*
 * DEPLOYMENT-GUARD sabotage sensitivity (Phase E). Each load-bearing
 * deployment guard is neutralized by a REAL in-source edit, the guarded
 * behavior is shown to go RED (the bad outcome actually happens), then
 * the file is restored BYTE-IDENTICALLY. Nothing sabotaged is committed.
 *
 * Guards proven load-bearing here:
 *   S1  server startup DB gate — without the openPgStore-before-listen
 *       step, a hosted postgres server LISTENS with its database dead
 *       (the §10 startup-order violation the guard exists to prevent).
 *   S2  readiness truthfulness — without the postgres readiness branch,
 *       /health/ready reports ready:true while the database is gone.
 *   S3  database network stamp — without the stamp comparison, a
 *       database owned by a DIFFERENT network opens successfully
 *       (cross-network contamination the guard exists to prevent).
 *
 * Requires live PostgreSQL (self-skips without POLICYVAULT_TEST_PG_*).
 * Runs serially with the rest of the SDK suite (docs/test-plan.md rule
 * 7) — in-place source mutation is safe only because test files never
 * run concurrently.
 */

const { test, before, after } = require("node:test");
const assert = require("node:assert/strict");
const os = require("node:os");
const fs = require("node:fs");
const net = require("node:net");
const path = require("node:path");
const http = require("node:http");
const crypto = require("node:crypto");
const { spawn } = require("node:child_process");

const { loadConfig } = require("../src/config");

const REPO_ROOT = path.join(__dirname, "..", "..");
const SERVER_SRC = path.join(REPO_ROOT, "server", "src", "server.js");
const API_SRC = path.join(REPO_ROOT, "server", "src", "api.js");
const STORE_SRC = path.join(REPO_ROOT, "sdk", "src", "store.js");

const ORIGINALS = new Map(
  [SERVER_SRC, API_SRC, STORE_SRC].map((p) => [p, fs.readFileSync(p)])
);
const shaOf = (buf) => crypto.createHash("sha256").update(buf).digest("hex");
const ORIGINAL_SHAS = new Map([...ORIGINALS].map(([p, buf]) => [p, shaOf(buf)]));

const PG = {
  host: process.env.POLICYVAULT_TEST_PG_HOST || "127.0.0.1",
  port: Number(process.env.POLICYVAULT_TEST_PG_PORT || 0),
  user: process.env.POLICYVAULT_TEST_PG_USER,
  database: process.env.POLICYVAULT_TEST_PG_DATABASE
};
const PG_AVAILABLE = Boolean(PG.port && PG.user && PG.database);
const skip = PG_AVAILABLE ? undefined : "set POLICYVAULT_TEST_PG_{PORT,USER,DATABASE} to run deployment sabotage";

let adminPool;
let dbCounter = 0;
const createdDbs = [];
const children = [];
const tmpRoot = () => fs.mkdtempSync(path.join(os.tmpdir(), "pv-depsab-"));

async function freshDatabase() {
  const dbName = `pv_dsab_${process.pid}_${++dbCounter}`;
  await adminPool.query(`CREATE DATABASE ${dbName}`);
  createdDbs.push(dbName);
  return dbName;
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

function spawnServer(env) {
  const child = spawn(process.execPath, [SERVER_SRC], {
    cwd: REPO_ROOT,
    env: { HOME: process.env.HOME, PATH: process.env.PATH, ...env },
    stdio: ["ignore", "pipe", "pipe"]
  });
  children.push(child);
  let out = "";
  child.stdout.on("data", (d) => (out += d));
  child.stderr.on("data", (d) => (out += d));
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

async function waitFor(fn, { timeoutMs = 20_000, intervalMs = 200, label = "condition" } = {}) {
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

/* Mutate one source file on disk, run fn, restore byte-identically. */
async function withSabotage(file, find, replace, fn) {
  const original = ORIGINALS.get(file);
  const mutated = original.toString().replace(find, replace);
  assert.notEqual(mutated, original.toString(), "sabotage pattern must actually change the source");
  fs.writeFileSync(file, mutated);
  try {
    return await fn();
  } finally {
    fs.writeFileSync(file, original);
    assert.equal(shaOf(fs.readFileSync(file)), ORIGINAL_SHAS.get(file), `${path.basename(file)} restored byte-identically`);
  }
}

function hostedEnv(dbName, port) {
  return {
    POLICYVAULT_PERSISTENCE: "postgres",
    POLICYVAULT_PG_HOST: PG.host,
    POLICYVAULT_PG_PORT: String(PG.port),
    POLICYVAULT_PG_USER: PG.user,
    POLICYVAULT_PG_DATABASE: dbName,
    POLICYVAULT_PG_NO_TLS: "1",
    POLICYVAULT_HOSTED_AUTH: "1",
    POLICYVAULT_AUTH_COOKIE_INSECURE: "1",
    POLICYVAULT_APP_ORIGIN: `http://127.0.0.1:${port}`,
    POLICYVAULT_API_PORT: String(port),
    POLICYVAULT_DATA_ROOT: tmpRoot()
  };
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
      /* gone */
    }
  }
  if (!PG_AVAILABLE) return;
  for (const db of createdDbs) {
    try {
      await adminPool.query(`DROP DATABASE IF EXISTS ${db} WITH (FORCE)`);
    } catch {
      /* best effort */
    }
  }
  await adminPool.end();
});

test("S1 startup DB gate is load-bearing: neutralized, the server LISTENS with a dead database", { skip }, async () => {
  const port = await freePort();
  const deadDbPort = await freePort(); // nothing listens here
  const env = { ...hostedEnv("pv_none", port), POLICYVAULT_PG_PORT: String(deadDbPort) };

  // Control: with the real guard, startup refuses (exit != 0, no listener).
  const control = spawnServer(env);
  assert.notEqual(await control.exited, 0, "control: real guard must refuse startup");

  // Sabotage: drop the await'd open — the server then listens happily.
  await withSabotage(
    SERVER_SRC,
    "      const { openPgStore } = require(\"../../sdk/src/store\");\n      await openPgStore(config);",
    "      void 0; /* SABOTAGE: DB open removed */",
    async () => {
      const sabotaged = spawnServer(env);
      try {
        const health = await waitFor(async () => {
          const r = await getJson(port, "/api/v1/health");
          return r.status === 200 ? r : null;
        }, { label: "sabotaged server listening without its database" });
        // RED: liveness answers while the durable backend never opened.
        assert.equal(health.body.ok, true, "sabotaged server serves /health with a dead database — guard is load-bearing");
      } finally {
        sabotaged.child.kill("SIGKILL");
        await sabotaged.exited;
      }
    }
  );
});

test("S2 readiness truthfulness is load-bearing: neutralized, /health/ready lies while the DB is gone", { skip }, async () => {
  const dbName = await freshDatabase();
  // Migrate, then serve, then KILL the database connection path by
  // dropping the database out from under the server... simpler and just
  // as honest: point readiness at a store whose pool we close via the
  // in-process handler (the unit surface the child server also uses).
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
  const { openPgStore } = require("../src/store");
  const config = loadConfig(overrides);
  const store = await openPgStore(config, { migrate: true });
  // Stamp the json fallback surface too (what the sabotaged branch reads).
  require("../src/config").assertDataRootNetwork(config);
  await store.pool().end(); // database now unreachable for this store

  // Control: the real readiness handler reports NOT ready.
  {
    const { handle } = require("../../server/src/api");
    const r = await handle(config, "GET", ["health", "ready"], {}, undefined);
    assert.equal(r.status, 503, "control: real readiness must refuse with the DB gone");
  }

  // Sabotage: skip the postgres readiness branch entirely.
  await withSabotage(
    API_SRC,
    "      if (config.persistenceBackend === \"postgres\") {",
    "      if (false) { /* SABOTAGE: postgres readiness skipped */",
    async () => {
      const tmp = path.join(path.dirname(API_SRC), `.api.sabotage.${process.pid}.js`);
      fs.copyFileSync(API_SRC, tmp);
      try {
        const mod = require(tmp);
        const r = await mod.handle(config, "GET", ["health", "ready"], {}, undefined);
        // RED: ready:true while the database is unreachable.
        assert.equal(r.status, 200, "sabotaged readiness lies — guard is load-bearing");
        assert.equal(r.body.ready, true);
      } finally {
        delete require.cache[require.resolve(tmp)];
        fs.unlinkSync(tmp);
      }
    }
  );
});

test("S3 database network stamp is load-bearing: neutralized, a foreign-network database OPENS", { skip }, async () => {
  const dbName = await freshDatabase();
  // Create + stamp the database as testnet-10.
  const { openPgStore } = require("../src/store");
  const t10 = loadConfig({
    persistenceBackend: "postgres",
    pgHost: PG.host,
    pgPort: PG.port,
    pgUser: PG.user,
    pgDatabase: dbName,
    pgNoTls: true,
    hostedDevOpen: true,
    dataRoot: tmpRoot()
  });
  const s1 = await openPgStore(t10, { migrate: true });
  await s1.close();

  // Foreign-network scenario without mainnet TLS constraints (mainnet
  // configs refuse the local no-TLS test cluster at config time, which
  // is itself correct): stamp the database as MAINNET by direct meta
  // write, then open it with a TESTNET process — the exact "restored the
  // wrong backup" operator mistake.
  const { Pool } = require("pg");
  const stampPool = new Pool({ host: PG.host, port: PG.port, user: PG.user, database: dbName });
  await stampPool.query(`UPDATE pv_meta SET value = 'mainnet' WHERE key = 'network'`);
  await stampPool.end();

  // Control: the real guard refuses the foreign-network database.
  await assert.rejects(
    openPgStore(
      loadConfig({
        persistenceBackend: "postgres",
        pgHost: PG.host,
        pgPort: PG.port,
        pgUser: PG.user,
        pgDatabase: dbName,
        pgNoTls: true,
        hostedDevOpen: true,
        dataRoot: tmpRoot()
      })
    ),
    /belongs to network/,
    "control: real stamp guard must refuse"
  );

  // Sabotage: neutralize the stamp comparison.
  await withSabotage(
    STORE_SRC,
    "    if (owner !== config.networkId) {",
    "    if (false) { /* SABOTAGE: network stamp ignored */",
    async () => {
      const tmp = path.join(path.dirname(STORE_SRC), `.store.sabotage.${process.pid}.js`);
      fs.copyFileSync(STORE_SRC, tmp);
      try {
        const mod = require(tmp);
        const cfg = loadConfig({
          persistenceBackend: "postgres",
          pgHost: PG.host,
          pgPort: PG.port,
          pgUser: PG.user,
          pgDatabase: dbName,
          pgNoTls: true,
          hostedDevOpen: true,
          dataRoot: tmpRoot()
        });
        // RED: the foreign-network database opens.
        const s = await mod.openPgStore(cfg);
        assert.equal(s.kind, "postgres", "sabotaged store opened a foreign-network DB — guard is load-bearing");
        await s.close();
      } finally {
        delete require.cache[require.resolve(tmp)];
        fs.unlinkSync(tmp);
      }
    }
  );
});

test("SABOTAGE integrity: every mutated file is byte-identical to its original", () => {
  for (const [p, sha] of ORIGINAL_SHAS) {
    assert.equal(shaOf(fs.readFileSync(p)), sha, `${path.basename(p)} must be restored`);
  }
});
