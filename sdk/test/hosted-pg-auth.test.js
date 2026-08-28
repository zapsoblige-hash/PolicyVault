"use strict";

/*
 * HOSTED AUTH ON POSTGRESQL — persistence, cross-process single-use,
 * restart durability, concurrency (Phase C, directive §23/§28/§29).
 * Real local PostgreSQL (SKIPPED without POLICYVAULT_TEST_PG_*).
 *
 * Proves the PG auth store keeps every Phase B invariant AND adds:
 * challenge single-use holds across SEPARATE service instances (two app
 * processes), revocation/expiry survive restart, raw bearer token never
 * persisted.
 */

const { test, before, after } = require("node:test");
const assert = require("node:assert/strict");
const os = require("node:os");
const fs = require("node:fs");
const path = require("node:path");

const { loadConfig } = require("../src/config");
const { openPgStore } = require("../src/store");
const { HostedAuthService, PgAuthStore, AuthErrorCodes } = require("../../server/src/auth");
const kaspa = require(loadConfig({}).rustyKaspaModule);

const PG = {
  host: process.env.POLICYVAULT_TEST_PG_HOST || "127.0.0.1",
  port: Number(process.env.POLICYVAULT_TEST_PG_PORT || 0),
  user: process.env.POLICYVAULT_TEST_PG_USER,
  database: process.env.POLICYVAULT_TEST_PG_DATABASE
};
const PG_AVAILABLE = Boolean(PG.port && PG.user && PG.database);
const skip = PG_AVAILABLE ? undefined : "set POLICYVAULT_TEST_PG_{PORT,USER,DATABASE} to run hosted PG auth tests";

const priv = new kaspa.PrivateKey("51".repeat(32));
const W = { priv, compressed: priv.toPublicKey().toString().toLowerCase(), address: priv.toPublicKey().toAddress("testnet-10").toString() };
const sign = (m) => kaspa.signMessage({ message: m, privateKey: priv.toString() });

let adminPool, dbName, config, store;

before(async () => {
  if (!PG_AVAILABLE) return;
  const { Pool } = require("pg");
  adminPool = new Pool({ host: PG.host, port: PG.port, user: PG.user, database: PG.database });
  dbName = `pv_pgauth_${process.pid}`;
  await adminPool.query(`DROP DATABASE IF EXISTS ${dbName} WITH (FORCE)`);
  await adminPool.query(`CREATE DATABASE ${dbName}`);
  config = loadConfig({
    persistenceBackend: "postgres", pgHost: PG.host, pgPort: PG.port, pgUser: PG.user, pgDatabase: dbName, pgNoTls: true,
    authMode: "enabled", authCookieInsecure: true, dataRoot: fs.mkdtempSync(path.join(os.tmpdir(), "pv-pgauth-"))
  });
  store = await openPgStore(config, { migrate: true });
});

after(async () => {
  if (!PG_AVAILABLE) return;
  if (store) await store.close();
  if (adminPool) { await adminPool.query(`DROP DATABASE IF EXISTS ${dbName} WITH (FORCE)`).catch(() => {}); await adminPool.end(); }
});

/* A service instance backed by the SAME database (models one app process). */
function svc(providers = {}) {
  return new HostedAuthService(config, { store: new PgAuthStore(store.pool(), config.networkId), ...providers });
}

test("§C pg-auth: full challenge->verify->session->resolve->logout on PostgreSQL", { skip }, async () => {
  const auth = svc();
  const ch = await auth.createChallenge(W.address);
  const { token, session } = await auth.verify({ nonce: ch.nonce, signature: sign(ch.message), publicKey: W.compressed });
  assert.equal(session.authenticated, true);
  const p = await auth.resolveSession(token);
  assert.equal(p.walletAddress, W.address);
  assert.equal(await auth.revokeByToken(token), true);
  assert.equal((await (async () => { try { await auth.resolveSession(token); } catch (e) { return e; } })()).code, AuthErrorCodes.SESSION_INVALID);
});

test("§C pg-auth: only the token HASH is persisted (raw bearer token never in the DB)", { skip }, async () => {
  const auth = svc();
  const ch = await auth.createChallenge(W.address);
  const { token } = await auth.verify({ nonce: ch.nonce, signature: sign(ch.message), publicKey: W.compressed });
  const rows = await store.pool().query("SELECT token_hash FROM auth_sessions");
  const hashes = rows.rows.map((r) => r.token_hash);
  assert.ok(!hashes.includes(token), "raw token is not stored");
  assert.ok(hashes.includes(require("node:crypto").createHash("sha256").update(token).digest("hex")), "the hash IS stored");
});

test("§C pg-auth: TWO app processes cannot consume ONE challenge twice (cross-process single-use)", { skip }, async () => {
  const proc1 = svc();
  const proc2 = svc(); // separate service instance, SAME database
  const ch = await proc1.createChallenge(W.address);
  const sig = sign(ch.message);
  const first = await proc1.verify({ nonce: ch.nonce, signature: sig, publicKey: W.compressed });
  const second = await (async () => { try { return await proc2.verify({ nonce: ch.nonce, signature: sig, publicKey: W.compressed }); } catch (e) { return e; } })();
  assert.equal(first.session.authenticated, true);
  assert.ok([AuthErrorCodes.AUTH_CHALLENGE_UNKNOWN, AuthErrorCodes.AUTH_CHALLENGE_USED].includes(second.code), `second process must be denied (got ${second.code})`);
});

test("§C pg-auth: concurrent verify of ONE challenge -> exactly one success (DB CAS arbiter)", { skip }, async () => {
  const auth = svc();
  const ch = await auth.createChallenge(W.address);
  const sig = sign(ch.message);
  // Fire N verifies concurrently against the same nonce.
  const results = await Promise.allSettled(
    Array.from({ length: 6 }, () => auth.verify({ nonce: ch.nonce, signature: sig, publicKey: W.compressed }))
  );
  const wins = results.filter((r) => r.status === "fulfilled").length;
  assert.equal(wins, 1, "exactly one concurrent verify may succeed");
});

test("§C pg-auth: a session survives a process 'restart' (new service instance, same DB)", { skip }, async () => {
  const auth1 = svc();
  const ch = await auth1.createChallenge(W.address);
  const { token } = await auth1.verify({ nonce: ch.nonce, signature: sign(ch.message), publicKey: W.compressed });
  // New instance (restart) resolves the SAME token from the database.
  const auth2 = svc();
  assert.equal((await auth2.resolveSession(token)).walletAddress, W.address);
});

test("§C pg-auth: a REVOKED session stays revoked after 'restart'", { skip }, async () => {
  const auth1 = svc();
  const ch = await auth1.createChallenge(W.address);
  const { token } = await auth1.verify({ nonce: ch.nonce, signature: sign(ch.message), publicKey: W.compressed });
  await auth1.revokeByToken(token);
  const auth2 = svc();
  assert.equal((await (async () => { try { await auth2.resolveSession(token); } catch (e) { return e; } })()).code, AuthErrorCodes.SESSION_INVALID);
});

test("§C pg-auth: an EXPIRED session stays expired after 'restart' (injected clock)", { skip }, async () => {
  let t = 2_000_000;
  const auth1 = svc({ now: () => t });
  const ch = await auth1.createChallenge(W.address);
  const { token } = await auth1.verify({ nonce: ch.nonce, signature: sign(ch.message), publicKey: W.compressed });
  t += 25 * 60 * 60 * 1000; // past the 24h absolute cap
  // A restarted instance sharing the clock still rejects it.
  const auth2 = svc({ now: () => t });
  assert.equal((await (async () => { try { await auth2.resolveSession(token); } catch (e) { return e; } })()).code, AuthErrorCodes.SESSION_EXPIRED);
});

test("§C pg-auth: a duplicate challenge nonce cannot exist (UNIQUE PK)", { skip }, async () => {
  // Insert a nonce, then a manual duplicate insert must be rejected by PG.
  const auth = svc();
  const ch = await auth.createChallenge(W.address);
  await assert.rejects(
    () => store.pool().query(`INSERT INTO auth_challenges (network_id, nonce, wallet_address, xonly, issued_at_ms, expires_at_ms, state) VALUES ('testnet-10', $1, 'a', 'b', 1, 2, 'issued')`, [ch.nonce]),
    /duplicate key|unique/i
  );
});
