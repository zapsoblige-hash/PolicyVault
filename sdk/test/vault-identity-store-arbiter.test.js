"use strict";
/*
 * SDK / CONCURRENCY — RC33-ID-01: the STORE-LEVEL arbiter behind global vault-record uniqueness (sdk/src/vault-identity.js).
 *
 * The directive's bar: "do not substitute mocked success for an atomic storage guarantee". These tests drive the REAL
 * create-only primitives of both persistence backends with genuinely concurrent writers on the SAME key —
 *   json      link()/EEXIST under the durable fsync-rename discipline (sdk/src/durable-json.js),
 *   postgres  INSERT … ON CONFLICT (network_id, key) DO NOTHING on the real vaults table (skipped cleanly, never
 *             silently passed, without POLICYVAULT_TEST_PG_{PORT,USER,DATABASE}),
 * and pin the semantics the genesis writers rely on: exactly ONE writer wins, the loser sees the winner's record,
 * `createVaultRecordOrMatch` accepts only the byte-identical genesis outcome (volatile fields aside) and refuses every
 * other record of any generation without touching it, `findVaultIdentityReservation` recognises a record of any
 * generation, an unreadable record, and a request of any family naming the identity, and the per-identity lock
 * serializes a check-then-write.
 */
const { test, before, after } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");

const { loadConfig } = require("../src/config");
const { getStore, openPgStore, Categories } = require("../src/store");
const VI = require("../src/vault-identity");
const { fundingRequest, provenNegative } = require("./helpers/negative-proof-fixtures");

const PG = {
  host: process.env.POLICYVAULT_TEST_PG_HOST || "127.0.0.1",
  port: Number(process.env.POLICYVAULT_TEST_PG_PORT || 0),
  user: process.env.POLICYVAULT_TEST_PG_USER,
  database: process.env.POLICYVAULT_TEST_PG_DATABASE
};
const PG_AVAILABLE = Boolean(PG.port && PG.user && PG.database);
const PG_SKIP = !PG_AVAILABLE && "set POLICYVAULT_TEST_PG_{PORT,USER,DATABASE} to run the PostgreSQL arbiter";

const KAS_SCHEMA = "policyvault-rooted-kas-vault-manifest-record/1";
const hex32 = () => crypto.randomBytes(32).toString("hex");
const record = (vaultId, extra = {}) => ({ schema: KAS_SCHEMA, vaultId, creationTxId: "11".repeat(32), live: { outpoint: { transactionId: "11".repeat(32), index: 0 }, covenantId: "22".repeat(32) }, updatedAt: "2026-09-11T00:00:00.000Z", label: "a", ...extra });

function jsonConfig() {
  return loadConfig({ dataRoot: fs.mkdtempSync(path.join(os.tmpdir(), "pv-vid-arbiter-")) });
}

/* ------------------------------------------------------------------ */
/* backend-agnostic contract, run against BOTH drivers                 */
/* ------------------------------------------------------------------ */

async function arbiterContract(t, config, label) {
  const store = getStore(config);

  /* 1. N genuinely concurrent create-only writers on ONE key: exactly one wins; the record is the winner's */
  const id = hex32();
  const N = 12;
  const results = await Promise.all(Array.from({ length: N }, (_, n) => store.createExclusive(Categories.VAULT, id, record(id, { writer: n }))));
  assert.equal(results.filter(Boolean).length, 1, `${label}: exactly one of ${N} concurrent create-only writers wins`);
  const winner = results.indexOf(true);
  assert.equal((await store.read(Categories.VAULT, id)).writer, winner, `${label}: the stored record is the winner's`);
  /* a later create-only attempt on the occupied key loses too */
  assert.equal(await store.createExclusive(Categories.VAULT, id, record(id, { writer: "late" })), false);
  assert.equal((await store.read(Categories.VAULT, id)).writer, winner);

  /* 2. createVaultRecordOrMatch: CREATED, then ALREADY_PRESENT only for the same genesis outcome (volatile fields aside) */
  const id2 = hex32();
  const doc = record(id2);
  assert.equal((await VI.createVaultRecordOrMatch(config, id2, doc)).outcome, "CREATED");
  const same = { ...doc, updatedAt: "2099-01-01T00:00:00.000Z", label: "renamed", createdAt: "2000-01-01T00:00:00.000Z" };
  const again = await VI.createVaultRecordOrMatch(config, id2, same);
  assert.equal(again.outcome, "ALREADY_PRESENT", `${label}: the same outcome (only updatedAt / createdAt / label differ) is accepted`);
  assert.deepEqual(await store.read(Categories.VAULT, id2), doc, `${label}: ALREADY_PRESENT rewrites nothing`);
  /* a different creation (another txid) under the same identity is a conflict; nothing is replaced */
  await assert.rejects(() => VI.createVaultRecordOrMatch(config, id2, record(id2, { creationTxId: "33".repeat(32) })), (e) => e.code === "RECONCILIATION_REQUIRED");
  /* a record of ANOTHER generation under the same identity is a conflict; nothing is replaced */
  await assert.rejects(() => VI.createVaultRecordOrMatch(config, id2, { schema: "policyvault-vault-manifest/v4", vaultId: id2, creationTxId: doc.creationTxId }), (e) => e.code === "RECONCILIATION_REQUIRED");
  assert.deepEqual(await store.read(Categories.VAULT, id2), doc, `${label}: the existing record survives every conflicting attempt`);
  /* the manifestVersion-tagged family (v0.7 rooted vaults) is compared by ITS tag */
  const id3 = hex32();
  const v7 = { manifestVersion: "policyvault-rooted-vault-manifest-record/1", vaultId: id3, creationTxId: "44".repeat(32), updatedAt: "x" };
  assert.equal((await VI.createVaultRecordOrMatch(config, id3, v7)).outcome, "CREATED");
  assert.equal((await VI.createVaultRecordOrMatch(config, id3, { ...v7, updatedAt: "y" })).outcome, "ALREADY_PRESENT");
  await assert.rejects(() => VI.createVaultRecordOrMatch(config, id3, { ...v7, manifestVersion: "policyvault-rooted-hd-vault-manifest-record/1" }), (e) => e.code === "RECONCILIATION_REQUIRED");

  /* 3. reservations: a vault record of any generation; a wallet request / org-root request naming the identity (any
   *    field a durable request uses); the caller's own request excluded; free otherwise */
  assert.equal(await VI.findVaultIdentityReservation(config, hex32()), null, `${label}: an unused identity is free`);
  assert.deepEqual(await VI.findVaultIdentityReservation(config, id2), { kind: "VAULT_RECORD", readable: true });
  const idR = hex32(), reqId = crypto.randomUUID();
  await store.write(Categories.REQUEST, reqId, { schema: "policyvault-wallet-request/v7-kas", requestId: reqId, kind: "kasGenesis", state: "WALLET_REJECTED", vaultId: idR });
  assert.deepEqual(await VI.findVaultIdentityReservation(config, idR), { kind: "REQUEST" }, `${label}: a request in ANY state reserves its identity`);
  assert.equal(await VI.findVaultIdentityReservation(config, idR, { exceptRequestId: reqId }), null, `${label}: the caller's own request is not a conflict`);
  await assert.rejects(() => VI.assertVaultIdentityFree(config, idR), (e) => e.code === "VAULT_ID_IN_USE" && !/WALLET_REJECTED|kasGenesis|schema/.test(e.message));
  /* phase "commit" (a request's OWN signature / submission): an UNCOMMITTED other request (never signed / definitively
   * negative / pre-signature) does not block; one that may carry a signed transaction or a broadcast does; an unknown
   * state counts as committed (fail closed); a vault record always blocks */
  assert.equal(await VI.findVaultIdentityReservation(config, idR, { phase: "commit" }), null, `${label}: a WALLET_REJECTED request does not block another request's commit`);
  /* RC35-REC-01 (2026-09-11, STALE ASSUMPTION corrected — property preserved and widened): a SUBMISSION_REJECTED request is
   * uncommitted ONLY with the RC36 corrected, original-anchor/request-bound acceptance and exact-funding proof;
   * historical bare errors and output-absence-only proofs are insufficient; a record the pre-correction
   * runtime wrote for an "already accepted" node answer — or without any bound answer — may carry a chain effect and
   * blocks like a committed request. NOT_BROADCAST / SUPERSEDED come only from the outcome observer with proof. */
  const validNegative = await provenNegative(config, fundingRequest(config, { requestId: reqId, vaultId: idR }));
  const txR = validNegative.txId;
  const negatives = {
    SUBMISSION_REJECTED: validNegative,
    NOT_BROADCAST: {}, SUPERSEDED: {}
  };
  for (const state of ["BUILT", "AUTHORIZED", "SUBMISSION_REJECTED", "NOT_BROADCAST", "SUPERSEDED"]) {
    await store.write(Categories.REQUEST, reqId, { schema: "policyvault-wallet-request/v7-kas", requestId: reqId, kind: "kasGenesis", state, vaultId: idR, ...(negatives[state] ?? {}) });
    assert.equal(await VI.findVaultIdentityReservation(config, idR, { phase: "commit" }), null, `${label}: ${state} is uncommitted`);
    assert.deepEqual(await VI.findVaultIdentityReservation(config, idR, { phase: "build" }), { kind: "REQUEST" }, `${label}: ${state} still reserves the identity for a NEW creation`);
  }
  /* RC36: no historical bare error proves nonacceptance, including an apparently genuine bound rejection. */
  const legacy = (error) => ({ schema: "policyvault-wallet-request/v7-kas", requestId: reqId, kind: "kasGenesis", state: "SUBMISSION_REJECTED", vaultId: idR, txId: txR, error });
  await store.write(Categories.REQUEST, reqId, legacy(`Rejected transaction ${txR}: transaction ${txR} is not standard: too many sig ops`));
  assert.deepEqual(await VI.findVaultIdentityReservation(config, idR, { phase: "commit" }), { kind: "REQUEST" }, `${label}: a legacy bound rejection without historical acceptance/funding proof remains protected`);
  for (const proof of [{ outputsAbsent: true }, { txId: txR, boundRejection: true, outputsAbsent: true }]) {
    await store.write(Categories.REQUEST, reqId, { ...legacy(`Rejected transaction ${txR}: TEST rejected`), submissionOutcome: { outcome: "SUBMISSION_REJECTED", txId: txR, proof } });
    assert.deepEqual(await VI.findVaultIdentityReservation(config, idR, { phase: "commit" }), { kind: "REQUEST" }, `${label}: historical partial proof stays reserved`);
  }
  for (const answer of [`Rejected transaction ${txR}: transaction ${txR} was already accepted by the consensus`, `Rejected transaction ${txR}: transaction ${txR} is already in the mempool`, "connection closed before response", undefined, `Rejected transaction ${hex32()}: transaction is not standard`]) {
    await store.write(Categories.REQUEST, reqId, legacy(answer));
    assert.deepEqual(await VI.findVaultIdentityReservation(config, idR, { phase: "commit" }), { kind: "REQUEST" }, `${label}: SUBMISSION_REJECTED without an established negative blocks at commit (${String(answer).slice(0, 40)})`);
  }
  /* RC35-RES-01: a durable SUBMISSION claim naming an identity reserves it in BOTH phases (a headless creation's only pre-record
   * trace; a legacy retained claim carries exactly the vaultId <-> txId binding); only the caller's own transaction is excluded */
  await store.remove(Categories.REQUEST, reqId);
  const idC = hex32(), txC = hex32();
  await store.createExclusive(Categories.SUBMISSION_CLAIM, txC, { schema: "policyvault-submission-claim/v1", txId: txC, vaultId: idC, action: "createVault", createdAt: new Date().toISOString() });
  assert.deepEqual(await VI.findVaultIdentityReservation(config, idC), { kind: "SUBMISSION_CLAIM", txId: txC, action: "createVault" }, `${label}: a submission claim reserves at build`);
  assert.deepEqual(await VI.findVaultIdentityReservation(config, idC, { phase: "commit" }), { kind: "SUBMISSION_CLAIM", txId: txC, action: "createVault" }, `${label}: … and at commit`);
  assert.equal(await VI.findVaultIdentityReservation(config, idC, { phase: "commit", exceptTxId: txC }), null, `${label}: the caller's own transaction is not a conflict`);
  await assert.rejects(() => VI.assertVaultIdentityFree(config, idC), (e) => e.code === "VAULT_ID_IN_USE" && !e.message.includes(txC) && !/createVault/.test(e.message), `${label}: the refusal discloses nothing about the claim (no txid, no action)`);
  await store.remove(Categories.SUBMISSION_CLAIM, txC);
  assert.equal(await VI.findVaultIdentityReservation(config, idC), null);
  await store.write(Categories.REQUEST, reqId, { schema: "policyvault-wallet-request/v7-kas", requestId: reqId, kind: "kasGenesis", state: "SUPERSEDED", vaultId: idR });
  for (const state of ["SIGNED", "SUBMITTING", "SUBMITTED", "RECONCILIATION_REQUIRED", "CHAIN_VERIFIED", "FINALIZED", "BROADCAST", "SOME_FUTURE_STATE", undefined]) {
    await store.write(Categories.REQUEST, reqId, { schema: "policyvault-wallet-request/v7-kas", requestId: reqId, kind: "kasGenesis", ...(state === undefined ? {} : { state }), vaultId: idR });
    assert.deepEqual(await VI.findVaultIdentityReservation(config, idR, { phase: "commit" }), { kind: "REQUEST" }, `${label}: ${state} blocks (committed or unknown)`);
  }
  await store.write(Categories.REQUEST, reqId, { schema: "policyvault-wallet-request/v7-kas", requestId: reqId, kind: "kasGenesis", state: "WALLET_REJECTED", vaultId: idR });
  await assert.rejects(() => VI.findVaultIdentityReservation(config, idR, { phase: "later" }), (e) => e.code === "BAD_PHASE");
  assert.deepEqual(await VI.findVaultIdentityReservation(config, id2, { phase: "commit" }), { kind: "VAULT_RECORD", readable: true }, `${label}: a vault record blocks in every phase`);
  const idT = hex32(), reqT = crypto.randomUUID();
  await store.write(Categories.REQUEST, reqT, { schema: "policyvault-wallet-request/v4", requestId: reqT, kind: "genesis", state: "BUILT", template: { owner: "00".repeat(32), vaultId: idT } });
  assert.deepEqual(await VI.findVaultIdentityReservation(config, idT), { kind: "REQUEST" }, `${label}: template.vaultId names the identity`);
  const idO = hex32(), orgReqId = crypto.randomUUID();
  await store.write(Categories.ORG_ROOT_REQUEST, orgReqId, { schemaVersion: "policyvault-org-root-request/1", id: orgReqId, kind: "rootedVaultGenesis", state: "AUTHORIZED", build: { template: { vaultId: idO } }, manifest: { vaultId: idO } });
  assert.deepEqual(await VI.findVaultIdentityReservation(config, idO), { kind: "ORG_ROOT_REQUEST" }, `${label}: a rooted-vault genesis (org-root request) names the identity`);
  assert.equal(await VI.findVaultIdentityReservation(config, idO, { exceptRequestId: orgReqId }), null);
  /* identities are compared case-insensitively and validated */
  assert.deepEqual(await VI.findVaultIdentityReservation(config, idO.toUpperCase()), { kind: "ORG_ROOT_REQUEST" });
  await assert.rejects(() => VI.assertVaultIdentityFree(config, "not-hex"), (e) => e.code === "BAD_VAULT_ID");

  /* 4. the per-identity lock serializes a check-then-write */
  const idL = hex32();
  const order = [];
  const first = VI.withVaultIdentityLock(idL, async () => { order.push("a-in"); await new Promise((r) => setTimeout(r, 30)); await store.write(Categories.VAULT, idL, record(idL)); order.push("a-out"); });
  const second = VI.withVaultIdentityLock(idL, async () => { order.push("b-in"); assert.ok(await store.read(Categories.VAULT, idL), "the second worker sees the first worker's write"); order.push("b-out"); });
  await Promise.all([first, second]);
  assert.deepEqual(order, ["a-in", "a-out", "b-in", "b-out"], `${label}: strictly serialized per identity`);
  /* a failing worker releases the lock */
  await assert.rejects(() => VI.withVaultIdentityLock(idL, async () => { throw new Error("boom"); }), /boom/);
  assert.equal(await VI.withVaultIdentityLock(idL, async () => "after"), "after");
}

/* ------------------------------------------------------------------ */
/* JSON driver                                                          */
/* ------------------------------------------------------------------ */

test("JSON driver: the real link()/EEXIST arbiter — exactly one concurrent writer wins; create-or-match accepts only the same genesis outcome; reservations of every kind; per-identity lock", async (t) => {
  const config = jsonConfig();
  t.after(() => fs.rmSync(config.dataRoot, { recursive: true, force: true }));
  await arbiterContract(t, config, "json");
  /* an UNREADABLE record occupies the identity (fail closed) */
  const id = hex32();
  const file = path.join(config.dataRoot, "vaults", id, "manifest.json");
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, "{ not json");
  assert.deepEqual(await VI.findVaultIdentityReservation(config, id), { kind: "VAULT_RECORD", readable: false });
  await assert.rejects(() => VI.assertVaultIdentityFree(config, id), (e) => e.code === "VAULT_ID_IN_USE");
  await assert.rejects(() => VI.createVaultRecordOrMatch(config, id, record(id)), (e) => e.code === "RECONCILIATION_REQUIRED");
  assert.equal(fs.readFileSync(file, "utf8"), "{ not json");
  /* a record whose own identity differs from its key (a mis-bound / aliased record) occupies the identity too */
  const id2 = hex32();
  const file2 = path.join(config.dataRoot, "vaults", id2, "manifest.json");
  fs.mkdirSync(path.dirname(file2), { recursive: true });
  fs.writeFileSync(file2, JSON.stringify(record(hex32())));
  assert.deepEqual(await VI.findVaultIdentityReservation(config, id2), { kind: "VAULT_RECORD", readable: false });
  /* the contrast the finding was about: a plain write() overwrites — which is why genesis completion never uses it */
  const id3 = hex32();
  await getStore(config).write(Categories.VAULT, id3, { schema: "test-other-generation", vaultId: id3 });
  await getStore(config).write(Categories.VAULT, id3, record(id3));
  assert.equal((await getStore(config).read(Categories.VAULT, id3)).schema, KAS_SCHEMA, "write() replaces (documented contrast; not used for genesis completion)");
});

/* ------------------------------------------------------------------ */
/* PostgreSQL driver (real database)                                    */
/* ------------------------------------------------------------------ */

let adminPool, pgStore, pgDb;
before(async () => {
  if (!PG_AVAILABLE) return;
  const { Pool } = require("pg");
  adminPool = new Pool({ host: PG.host, port: PG.port, user: PG.user, database: PG.database });
  pgDb = `pv_vid_arbiter_${process.pid}`;
  await adminPool.query(`DROP DATABASE IF EXISTS ${pgDb} WITH (FORCE)`);
  await adminPool.query(`CREATE DATABASE ${pgDb}`);
});
after(async () => {
  if (!PG_AVAILABLE) return;
  if (pgStore) await pgStore.close().catch(() => {});
  if (adminPool) { await adminPool.query(`DROP DATABASE IF EXISTS ${pgDb} WITH (FORCE)`).catch(() => {}); await adminPool.end(); }
});

test("PostgreSQL driver: the real INSERT … ON CONFLICT DO NOTHING arbiter on the vaults table — exactly one concurrent writer wins; create-or-match accepts only the same genesis outcome; reservations of every kind; per-identity lock", { skip: PG_SKIP }, async (t) => {
  const config = loadConfig({
    persistenceBackend: "postgres", pgHost: PG.host, pgPort: PG.port, pgUser: PG.user, pgDatabase: pgDb, pgNoTls: true,
    authMode: "enabled", authCookieInsecure: true, // hosted persistence requires hosted auth (fail closed) — same as every hosted-pg-* sibling
    dataRoot: fs.mkdtempSync(path.join(os.tmpdir(), "pv-vid-arbiter-pg-"))
  });
  pgStore = await openPgStore(config, { migrate: true });
  assert.equal(getStore(config).kind, "postgres");
  await arbiterContract(t, config, "postgres");
  /* the unique primary key (network_id, key) is the arbiter: a second row for the same key cannot exist */
  const id = hex32();
  await getStore(config).createExclusive(Categories.VAULT, id, record(id));
  const rows = await pgStore.pool().query(`SELECT count(*)::int AS n FROM vaults WHERE key = $1`, [id]);
  assert.equal(rows.rows[0].n, 1);
  /* a record whose own identity differs from its key is refused by the read (mis-bound) and therefore OCCUPIES the identity */
  const id2 = hex32();
  await pgStore.pool().query(`INSERT INTO vaults (network_id, key, value, updated_at) VALUES ($1, $2, $3::jsonb, now())`, [config.networkId, id2, JSON.stringify(record(hex32()))]);
  assert.deepEqual(await VI.findVaultIdentityReservation(config, id2), { kind: "VAULT_RECORD", readable: false });
  await assert.rejects(() => VI.createVaultRecordOrMatch(config, id2, record(id2)), (e) => e.code === "RECONCILIATION_REQUIRED");
});
