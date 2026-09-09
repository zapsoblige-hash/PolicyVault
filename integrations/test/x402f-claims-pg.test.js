"use strict";

/*
 * INTEGRATION (PostgreSQL) — the shared claim store (spec §9 / decision E):
 * one INSERT with two UNIQUE constraints is the single race authority
 * between instances. Requires POLICYVAULT_TEST_PG_{PORT,USER,DATABASE}
 * (the same env contract as the SDK's PG suites); otherwise
 * REQUIREMENT_NOT_AVAILABLE (skipped, never silently green).
 */

const { test, before, after } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const { PgClaimStore } = require("../x402-facilitator/claims");

const PG = { host: process.env.POLICYVAULT_TEST_PG_HOST || "127.0.0.1", port: Number(process.env.POLICYVAULT_TEST_PG_PORT || 0), user: process.env.POLICYVAULT_TEST_PG_USER, database: process.env.POLICYVAULT_TEST_PG_DATABASE, password: process.env.POLICYVAULT_TEST_PG_PASSWORD };
const PG_AVAILABLE = Boolean(PG.port && PG.user && PG.database);
const skip = PG_AVAILABLE ? undefined : "REQUIREMENT_NOT_AVAILABLE: set POLICYVAULT_TEST_PG_{PORT,USER,DATABASE}";

let pool;
let store;
let stores;
const D = (n) => n.toString(16).padStart(2, "0").repeat(32);
const claimInput = (over = {}) => ({ requirementDigest: D(1), network: "kaspa:testnet-10", transactionId: D(0xaa), outputIndex: 0, payTo: "kaspatest:qpuk94zm8r5te7p04rh6sse2q8eqexjnufx860c3muvhew88pynd56n845dz8", amount: "100000000", asset: "KAS", validFromDaaScore: "1000", validUntilDaaScore: "2000", evidence: { schema: "policyvault-x402-facilitator-evidence/1", status: "CHAIN_VERIFIED" }, ...over });

before(async () => {
  if (!PG_AVAILABLE) return;
  const { Pool } = require(require.resolve("pg", { paths: [path.join(__dirname, "..", "..", "sdk")] }));
  pool = new Pool({ host: PG.host, port: PG.port, user: PG.user, password: PG.password, database: PG.database, max: 8 });
  await pool.query("DROP TABLE IF EXISTS x402f_claims");
  store = new PgClaimStore({ query: (sql, params) => pool.query(sql, params) });
  await store.ensureSchema();
  // "two instances": two independent store objects over separate connections
  stores = [store, new PgClaimStore({ query: (sql, params) => pool.query(sql, params) })];
});
after(async () => {
  if (pool) await pool.end();
});

test("PG: create, read by digest / outpoint, idempotent replay returns the stored evidence", { skip }, async () => {
  const first = await store.createClaim(claimInput());
  assert.equal(first.created, true);
  assert.equal((await store.readByDigest(D(1))).evidence.status, "CHAIN_VERIFIED");
  assert.equal((await store.readByOutpoint("kaspa:testnet-10", D(0xaa), 0)).claim.requirementDigest, D(1));
  const replay = await store.createClaim(claimInput({ evidence: { changed: true } }));
  assert.equal(replay.reason, "REPLAY");
  assert.equal(replay.claim.evidence.status, "CHAIN_VERIFIED");
});

test("PG: both uniqueness invariants — outpoint reuse → PAYMENT_ALREADY_CLAIMED; requirement reuse → REQUIREMENT_ALREADY_SETTLED", { skip }, async () => {
  assert.equal((await store.createClaim(claimInput({ requirementDigest: D(2) }))).reason, "PAYMENT_ALREADY_CLAIMED");
  assert.equal((await store.createClaim(claimInput({ transactionId: D(0xbb) }))).reason, "REQUIREMENT_ALREADY_SETTLED");
});

test("PG: 16 concurrent settles from two store instances racing on one fresh outpoint → exactly one wins, the database is the authority", { skip }, async () => {
  const results = await Promise.all(Array.from({ length: 16 }, (_, i) => stores[i % 2].createClaim(claimInput({ requirementDigest: D(0x10 + i), transactionId: D(0xcc) }))));
  assert.equal(results.filter((r) => r.created).length, 1);
  assert.equal(results.filter((r) => r.reason === "PAYMENT_ALREADY_CLAIMED").length, 15);
  const rows = await pool.query("SELECT count(*)::int AS n FROM x402f_claims WHERE transaction_id = $1", [D(0xcc)]);
  assert.equal(rows.rows[0].n, 1);
});

test("PG: 16 concurrent settles of one requirement with distinct outpoints → exactly one settles", { skip }, async () => {
  const results = await Promise.all(Array.from({ length: 16 }, (_, i) => stores[i % 2].createClaim(claimInput({ requirementDigest: D(0x50), transactionId: D(0x60 + i) }))));
  assert.equal(results.filter((r) => r.created).length, 1);
  assert.equal(results.filter((r) => r.reason === "REQUIREMENT_ALREADY_SETTLED").length, 15);
});

test("PG: destination-reuse query — overlapping window for the same (network, payTo, amount) is found; same digest / disjoint window / other amount are not", { skip }, async () => {
  const q = (over) => store.findDestinationConflicts({ network: "kaspa:testnet-10", payTo: claimInput().payTo, amount: "100000000", validFromDaaScore: "1500", validUntilDaaScore: "2500", excludeDigest: D(0x99), ...over });
  assert.ok((await q({})).length >= 1);
  assert.equal((await q({ validFromDaaScore: "2001", validUntilDaaScore: "3000" })).length, 0);
  assert.equal((await q({ amount: "100000001" })).length, 0);
  assert.equal((await q({ excludeDigest: D(1), validFromDaaScore: "1000", validUntilDaaScore: "1000" })).filter((c) => c.requirementDigest === D(1)).length, 0);
});

test("PG: the record column carries the complete claim (evidence IN the same row — never a two-phase write)", { skip }, async () => {
  const row = await pool.query("SELECT record FROM x402f_claims WHERE requirement_digest = $1", [D(1)]);
  assert.equal(row.rows[0].record.evidence.status, "CHAIN_VERIFIED");
  assert.equal(row.rows[0].record.schema, "policyvault-x402-facilitator-claim/1");
});
