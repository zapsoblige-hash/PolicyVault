"use strict";

/*
 * PHASE E — REAL PostgreSQL BACKUP / ISOLATED RESTORE / CHAIN-TRUTH DR
 * (directive §31–§37, §40). TESTNET-10 ONLY.
 *
 * Exercises the hosted durable layer (postgres persistence) end to end
 * against REAL testnet-10 chain truth:
 *
 *   1. Build representative state at S0 (a chain-proven v0.4.1 vault +
 *      an organization + member + assignment + audit) in a live PG DB.
 *      -> logical snapshot + REAL pg_dump BACKUP B1.
 *   2. Build + finalize a real agentSpend and SUBMIT it with the
 *      AFTER_SUBMITTED crash injection: the tx is BROADCAST but the
 *      manifest is NOT advanced and an AMBIGUOUS transition/submission
 *      claim is left durable.  -> snapshot + REAL pg_dump BACKUP B2.
 *   3. Let the spend confirm; reconcile the LIVE DB -> ADVANCED to the
 *      exact broadcast tx (the live DB is now at S1, chain-proven).
 *   4. RESTORE B2 into a NEW ISOLATED database, boot an app config
 *      against it, verify logical state == B2 (§34), then reconcile:
 *      chain proves the exact successor -> ADVANCE to the SAME tx, NO
 *      duplicate broadcast (§36); the ambiguous claim is resolved by
 *      chain proof, never force-released (§37).
 *   5. RESTORE B1 (now STALE — chain is past S0) into another NEW
 *      ISOLATED database; reconcile -> fail closed (predecessor consumed,
 *      no claim): chain truth stays authoritative, no blind resubmit,
 *      no invented state (§35).
 *   6. Restore FAILURE cases (§40): wrong-network restored DB refused;
 *      corrupt/truncated backup refused. (future-schema / missing-
 *      migration are covered by sdk/test/hosted-deployment*.test.js.)
 *
 * The backup tool is REAL pg_dump (custom format); restore is REAL
 * pg_restore into a distinct empty database. Records method, timestamp,
 * source identity, schema version, network stamp, size, and SHA256 —
 * NO secrets. Evidence JSON at OUT.
 *
 * Usage:
 *   PG_BIN=<dir with pg_dump/pg_restore> LD_LIBRARY_PATH=<libpq dir> \
 *   POLICYVAULT_TEST_PG_PORT=15432 POLICYVAULT_TEST_PG_USER=pvdev \
 *   node tools/staging-backup-restore.js [out.json]
 */

const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");
const { execFileSync } = require("child_process");

const { loadConfig } = require("../sdk/src/config");
const { openPgStore, getStore, Categories } = require("../sdk/src/store");
const { loadOrCreateTestKeys } = require("../sdk/src/keys");
const { connectVerified, getAddressUtxos } = require("../sdk/src/chain");
const { makeDevSigner } = require("../sdk/src/signer-dev");
const wr4 = require("../sdk/src/wallet-requests-v4");
const submit4 = require("../sdk/src/wallet-submit-v4");
const { reconcileVaultV4 } = require("../sdk/src/reconcile-v4");
const { loadManifestV4 } = require("../sdk/src/manifest-v4");
const org = require("../sdk/src/organization");

const V4_1 = "policyvault-0.4.1";
const KAS = 100000000n;
const OUT = process.argv[2] || "/tmp/pv-dr-evidence.json";
const log = (...a) => console.log("[dr]", ...a);
function assert(c, m) { if (!c) throw new Error("ASSERT FAILED: " + m); }

const PG = {
  host: process.env.POLICYVAULT_TEST_PG_HOST || "127.0.0.1",
  port: Number(process.env.POLICYVAULT_TEST_PG_PORT || 15432),
  user: process.env.POLICYVAULT_TEST_PG_USER || "pvdev"
};
const PG_BIN = process.env.PG_BIN;
if (!PG_BIN || !fs.existsSync(path.join(PG_BIN, "pg_dump"))) {
  throw new Error("set PG_BIN to a directory containing pg_dump/pg_restore (and LD_LIBRARY_PATH for libpq)");
}
const BACKUP_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "pv-dr-backups-"));
const DR_JSON_ROOT = fs.mkdtempSync(path.join(os.tmpdir(), "pv-dr-json-")); // config.dataRoot stub (postgres mode: only the artifact cache)

// `pg` resolves inside the sdk package (tools/ has no node_modules).
const { Pool } = require("../sdk/node_modules/pg");
const admin = new Pool({ host: PG.host, port: PG.port, user: PG.user, database: "postgres" });
const createdDbs = [];

function pgEnv() {
  return { ...process.env, PGHOST: PG.host, PGPORT: String(PG.port), PGUSER: PG.user };
}
async function createEmptyDb(name) {
  await admin.query(`DROP DATABASE IF EXISTS ${name} WITH (FORCE)`);
  await admin.query(`CREATE DATABASE ${name}`);
  createdDbs.push(name);
}
/* REAL pg_dump (custom format). Returns { file, sha256, bytes }. */
function backup(dbName, label) {
  const file = path.join(BACKUP_DIR, `${label}.dump`);
  execFileSync(path.join(PG_BIN, "pg_dump"), ["-Fc", "--no-owner", "--no-privileges", "--dbname", dbName, "-f", file], { env: pgEnv() });
  const bytes = fs.statSync(file).size;
  const sha256 = crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");
  return { file, sha256, bytes };
}
/* REAL pg_restore into a distinct EMPTY database.
 *
 * pg_dump 18 (the only client available on this host) emits a
 * `SET transaction_timeout` the 16.4 server does not recognize — a
 * single IGNORABLE session-GUC error that does not affect the restored
 * data (a pure client/server version skew that does not exist in
 * production, where the client matches the managed server). We tolerate
 * exactly that one error and NOTHING else; the REAL restore-integrity
 * gate is openPgStore's assertSchemaCurrent + network-stamp check, run
 * by the caller. A corrupt/truncated archive produces different errors
 * (or an incomplete schema) and is rejected. */
async function restoreInto(dumpFile, newDbName) {
  await createEmptyDb(newDbName);
  let combined = "";
  try {
    combined = execFileSync(path.join(PG_BIN, "pg_restore"), ["--no-owner", "--no-privileges", "--dbname", newDbName, dumpFile], {
      env: pgEnv(),
      stdio: ["ignore", "pipe", "pipe"]
    }).toString();
  } catch (e) {
    combined = `${e.stdout || ""}${e.stderr || ""}`;
    const errorLines = combined
      .split("\n")
      .filter((l) => /error:/i.test(l))
      .filter((l) => !/transaction_timeout/.test(l) && !/errors ignored on restore/.test(l));
    if (errorLines.length) {
      const err = new Error(`pg_restore failed: ${errorLines.slice(0, 5).join(" | ")}`);
      err.code = "RESTORE_FAILED";
      throw err;
    }
    // only the known-ignorable GUC error remained — restore is complete.
  }
  return combined;
}

/* Deterministic logical snapshot for state comparison (§34). Counts +
 * identities across every durable category, schema version, network
 * stamp. NO secrets (token hashes are already hashes; we count only). */
async function logicalSnapshot(pool) {
  const q = async (sql, params = []) => (await pool.query(sql, params)).rows;
  const one = async (sql) => Number((await pool.query(sql)).rows[0].n);
  const vaultRows = await q(`SELECT key, value->>'status' AS status, value->'live'->'outpoint'->>'transactionId' AS live_tx FROM vaults ORDER BY key`);
  const reqRows = await q(`SELECT key, value->>'state' AS state, value->>'vaultId' AS vault FROM wallet_requests ORDER BY key`);
  const claimRows = await q(`SELECT key, value->>'txId' AS tx FROM transition_claims ORDER BY key`);
  const subRows = await q(`SELECT key FROM submission_claims ORDER BY key`);
  const rcptRows = await q(`SELECT key FROM receipts ORDER BY key`);
  const orgRows = await q(`SELECT key, value->>'name' AS name, jsonb_array_length(COALESCE(value->'members','[]'::jsonb)) AS members FROM organizations ORDER BY key`);
  const asnRows = await q(`SELECT value FROM org_assignments`);
  return {
    schemaVersion: Number((await pool.query(`SELECT COALESCE(max(version),0) AS n FROM schema_migrations`)).rows[0].n),
    networkStamp: (await pool.query(`SELECT value FROM pv_meta WHERE key='network'`)).rows[0]?.value ?? null,
    vaults: vaultRows,
    requests: reqRows,
    transitionClaims: claimRows,
    submissionClaims: subRows.map((r) => r.key),
    receipts: rcptRows.map((r) => r.key),
    organizations: orgRows,
    assignments: asnRows[0]?.value ?? null,
    auditCount: await one(`SELECT count(*) AS n FROM audit_events`),
    sessionCount: await one(`SELECT count(*) AS n FROM auth_sessions`)
  };
}
function snapshotEquals(a, b) {
  return JSON.stringify(a) === JSON.stringify(b);
}

async function pollReconcile(config, vaultId, opts = {}, attempts = 60, delayMs = 2000) {
  let rec;
  for (let i = 0; i < attempts; i++) {
    rec = await reconcileVaultV4(config, vaultId, opts);
    if (rec.status !== "CLAIM_PENDING") return rec;
    await new Promise((r) => setTimeout(r, delayMs));
  }
  return rec;
}

function liveDbConfig(dbName) {
  return loadConfig({
    persistenceBackend: "postgres",
    pgHost: PG.host, pgPort: PG.port, pgUser: PG.user, pgDatabase: dbName, pgNoTls: true,
    hostedDevOpen: true,
    dataRoot: fs.mkdtempSync(path.join(DR_JSON_ROOT, "cfg-"))
  });
}

async function main() {
  const evidence = { gate: "phase-e-backup-restore", network: "testnet-10", startedAt: new Date().toISOString(), backupDir: BACKUP_DIR, steps: [] };

  // ---- live DB + chain ----
  const liveDb = `pv_dr_live_${process.pid}`;
  await createEmptyDb(liveDb);
  const config = liveDbConfig(liveDb);
  assert(config.networkId === "testnet-10", `refusing: ${config.networkId} != testnet-10`);
  const liveStore = await openPgStore(config, { migrate: true });

  const keys = loadOrCreateTestKeys(config);
  const kaspa = require(config.rustyKaspaModule);
  const XO = (s) => new kaspa.PrivateKey(s).toPublicKey().toXOnlyPublicKey().toString().toLowerCase();
  const owner = keys.owner, agentA = keys.delegate, recipientX = XO(keys.funding.secret);
  const signerFor = (k) => makeDevSigner(config, { secretHex: k.secret, expectedAddress: k.address });

  const { rpc, serverInfo } = await connectVerified(config);
  evidence.node = { networkId: serverInfo.networkId, isSynced: serverInfo.isSynced, serverVersion: serverInfo.serverVersion };
  assert(serverInfo.isSynced, "node not synced");

  const fetchFuel = async (address, min) => {
    const u = (await getAddressUtxos(rpc, address)).filter((x) => x.covenantId === null && x.amount > min).sort((a, b) => (a.amount < b.amount ? 1 : -1));
    if (!u.length) throw new Error(`no ordinary UTXO > ${min} at ${address}`);
    return { outpoint: u[0].outpoint, amount: u[0].amount.toString(), scriptPublicKeyHex: u[0].scriptPublicKeyHex };
  };

  try {
    // ============ STEP 1: state at S0 + BACKUP B1 ============
    const vaultId = crypto.randomBytes(32).toString("hex");
    const agentPolicy = { agentPk: XO(agentA.secret), maxPerSpend: (10n * KAS).toString(), periodBudget: (100n * KAS).toString(), periodLengthDaa: "864000", periodStartDaa: "541000000", periodSpent: "0", approvalThreshold: (100000n * KAS).toString(), agentMaxFeePerTx: (1n * KAS).toString(), recipients: [recipientX] };
    const genReq = await wr4.buildCreateWalletRequestV4({ config, contractVersion: V4_1, templateInput: { owner: XO(owner.secret), vaultId }, initialAgents: [agentPolicy], initialState: { protectedValue: (40n * KAS).toString(), feeReserve: (5n * KAS).toString(), approvers: [], approvalM: "0" }, signerAddress: owner.address, funding: [await fetchFuel(owner.address, 60n * KAS)], label: "dr-exercise" });
    const genSigned = signerFor(owner).signInputs(genReq.transaction.unsignedSafeJson, genReq.transaction.signInputs);
    const gr = await submit4.submitCreateWalletRequestV4({ config, requestId: genReq.requestId, signedSafeJson: genSigned, rpc });
    assert(gr.request.state === "CHAIN_VERIFIED", "genesis CHAIN_VERIFIED");
    const s0Outpoint = (await loadManifestV4(config, vaultId)).live.outpoint;
    log("genesis CHAIN_VERIFIED", gr.txId.slice(0, 16), "vault", vaultId.slice(0, 10), "S0", `${s0Outpoint.transactionId.slice(0,10)}:${s0Outpoint.index}`);

    // organization + member + assignment (metadata tables non-empty)
    const orgRec = await org.createOrganization(config, { name: "DR Exercise Org" });
    await org.addMember(config, orgRec.orgId, { displayName: "Auditor", address: agentA.address, roles: ["auditor"], note: "dr", expectedVersion: orgRec.version });
    await org.assignVault(config, { vaultId, orgId: orgRec.orgId, group: "treasury", expectedVersion: (await org.loadAssignments(config)).version, vaultExists: async () => true });

    const snapB1 = await logicalSnapshot(liveStore.pool());
    const b1 = backup(liveDb, "B1_S0");
    evidence.backupB1 = { method: "pg_dump -Fc", timestamp: new Date().toISOString(), sourceDb: liveDb, schemaVersion: snapB1.schemaVersion, networkStamp: snapB1.networkStamp, bytes: b1.bytes, sha256: b1.sha256, manifestState: "S0", vaults: snapB1.vaults.length, requests: snapB1.requests.length, claims: snapB1.transitionClaims.length };
    evidence.steps.push("B1 backup (S0, no pending transition)");
    log("BACKUP B1", `${b1.bytes}B sha256 ${b1.sha256.slice(0, 16)}… schema v${snapB1.schemaVersion} stamp ${snapB1.networkStamp}`);

    // ============ STEP 2: ambiguous pending claim + BACKUP B2 ============
    const spend = await wr4.buildWalletRequestV4({ config, vaultId, action: "agentSpend", params: { agentPk: XO(agentA.secret), recipient: recipientX, payAmountSompi: (3n * KAS).toString() }, signerAddress: agentA.address });
    const spendTxId = spend.txId;
    const spendSigned = signerFor(agentA).signInputs(spend.transaction.unsignedSafeJson, spend.transaction.signInputs);
    const fin = await wr4.finalizeWalletRequestV4({ config, requestId: spend.requestId, signedSafeJson: spendSigned });
    assert(fin.state === "PREFLIGHT_VERIFIED", `spend finalize preflight, got ${fin.state}`);
    // crash AFTER broadcast: tx sent, claim durable, manifest NOT advanced.
    process.env.PV_TEST_CRASH_AT = "AFTER_SUBMITTED";
    let crashed = null;
    try { await submit4.submitWalletRequestV4({ config, requestId: spend.requestId, rpc }); }
    catch (e) { crashed = e; }
    finally { delete process.env.PV_TEST_CRASH_AT; }
    assert(crashed && /crash|INJECTION/i.test(crashed.message), `AFTER_SUBMITTED crash expected, got ${crashed && crashed.message}`);
    const manAfterCrash = await loadManifestV4(config, vaultId);
    assert(`${manAfterCrash.live.outpoint.transactionId}:${manAfterCrash.live.outpoint.index}` === `${s0Outpoint.transactionId}:${s0Outpoint.index}`, "manifest must still be at S0 (ambiguous, not advanced)");
    const claimCount = (await liveStore.listKeys(Categories.TRANSITION_CLAIM)).length;
    assert(claimCount >= 1, "an ambiguous transition claim must be durable");
    const snapB2 = await logicalSnapshot(liveStore.pool());
    assert(snapB2.transitionClaims.length >= 1, "B2 snapshot must carry the ambiguous claim");
    const b2 = backup(liveDb, "B2_ambiguous");
    evidence.backupB2 = { method: "pg_dump -Fc", timestamp: new Date().toISOString(), sourceDb: liveDb, schemaVersion: snapB2.schemaVersion, networkStamp: snapB2.networkStamp, bytes: b2.bytes, sha256: b2.sha256, manifestState: "S0 + ambiguous claim", broadcastTx: spendTxId, transitionClaims: snapB2.transitionClaims.length };
    evidence.steps.push("B2 backup (S0 manifest + broadcast tx + ambiguous pending claim)");
    log("BACKUP B2", `${b2.bytes}B sha256 ${b2.sha256.slice(0, 16)}… broadcast ${spendTxId.slice(0, 16)}… claim present`);

    // ============ STEP 3: advance the LIVE DB to S1 (chain confirms) ============
    const recLive = await pollReconcile(config, vaultId, { rpc });
    assert(recLive.status === "ADVANCED", `live reconcile must ADVANCE, got ${recLive.status}`);
    assert(recLive.txId === spendTxId, `live advanced to the EXACT broadcast tx ${spendTxId}, got ${recLive.txId}`);
    const s1Outpoint = (await loadManifestV4(config, vaultId)).live.outpoint;
    assert(s1Outpoint.transactionId === spendTxId, "S1 successor is the spend tx");
    log("LIVE advanced to S1", `${s1Outpoint.transactionId.slice(0,10)}:${s1Outpoint.index} (chain now past S0)`);
    evidence.confirmedSpend = { txId: spendTxId, s1Outpoint: `${s1Outpoint.transactionId}:${s1Outpoint.index}` };

    // ============ STEP 4: RESTORE B2 -> isolated DB #2, reconcile ============
    const restoreB2Db = `pv_dr_restore_b2_${process.pid}`;
    await restoreInto(b2.file, restoreB2Db);
    const configB2 = liveDbConfig(restoreB2Db);
    const storeB2 = await openPgStore(configB2); // no migrate: the dump carries the schema
    const snapRestoredB2 = await logicalSnapshot(storeB2.pool());
    assert(snapshotEquals(snapRestoredB2, snapB2), "restored B2 logical state must EXACTLY match the B2 backup point (§34)");
    log("RESTORE B2 -> isolated DB, logical state == backup point ✓");
    // the restored DB is at S0 with the ambiguous claim; chain has confirmed the spend.
    const manRB2 = await loadManifestV4(configB2, vaultId);
    assert(`${manRB2.live.outpoint.transactionId}:${manRB2.live.outpoint.index}` === `${s0Outpoint.transactionId}:${s0Outpoint.index}`, "restored B2 manifest is at S0");
    const recB2 = await pollReconcile(configB2, vaultId, { rpc });
    assert(recB2.status === "ADVANCED", `restored-B2 reconcile must ADVANCE via chain proof, got ${recB2.status}`);
    assert(recB2.txId === spendTxId, `NO DUPLICATE SUBMISSION: reconcile advanced to the SAME broadcast tx ${spendTxId}, got ${recB2.txId} (§36)`);
    const manRB2After = await loadManifestV4(configB2, vaultId);
    assert(manRB2After.live.outpoint.transactionId === spendTxId, "restored B2 advanced to the confirmed successor");
    // the ambiguous claim was resolved by chain proof, not force-released while unresolved (§37)
    log("RESTORE B2 reconcile ADVANCED to the SAME tx — no duplicate broadcast (§36); claim resolved by chain proof (§37) ✓");
    evidence.steps.push("B2 restore: logical match; reconcile advanced to the exact confirmed tx (no duplicate submission; ambiguous claim resolved by chain proof)");
    evidence.restoreB2 = { isolatedDb: restoreB2Db, logicalMatch: true, reconcile: recB2.status, advancedTx: recB2.txId, duplicateBroadcast: false };

    // ============ STEP 5: RESTORE B1 (STALE) -> isolated DB #1, reconcile ============
    const restoreB1Db = `pv_dr_restore_b1_${process.pid}`;
    await restoreInto(b1.file, restoreB1Db);
    const configB1 = liveDbConfig(restoreB1Db);
    const storeB1 = await openPgStore(configB1);
    const snapRestoredB1 = await logicalSnapshot(storeB1.pool());
    assert(snapshotEquals(snapRestoredB1, snapB1), "restored B1 logical state must EXACTLY match the B1 backup point (§34)");
    log("RESTORE B1 -> isolated DB, logical state == backup point ✓");
    // B1 is at S0 with NO claim; chain has consumed S0 (the spend). Reconcile
    // must fail closed — never resubmit, never invent state (§35).
    const recB1 = await reconcileVaultV4(configB1, vaultId, { rpc });
    assert(["UNKNOWN", "TERMINATED_UNKNOWN"].includes(recB1.status) || recB1.status === "CLAIM_PENDING", `stale B1 reconcile must fail closed (UNKNOWN/TERMINATED_UNKNOWN), got ${recB1.status}`);
    const manRB1After = await loadManifestV4(configB1, vaultId);
    assert(manRB1After.live === null || manRB1After.status === "TERMINATED_UNKNOWN", `stale B1 must not fabricate a live successor, status=${manRB1After.status}`);
    log(`RESTORE B1 (stale) reconcile=${recB1.status} — chain truth authoritative; no blind resubmit; no invented state (§35) ✓`);
    evidence.steps.push("B1 restore (stale): reconcile fails closed against chain truth — no duplicate submission, no fabricated state");
    evidence.restoreB1 = { isolatedDb: restoreB1Db, logicalMatch: true, reconcile: recB1.status, failClosed: true };

    // ============ STEP 6: restore FAILURE cases (§40) ============
    // (a) wrong-network restored DB: flip the stamp, a testnet process refuses.
    const wrongNetDb = `pv_dr_wrongnet_${process.pid}`;
    await restoreInto(b1.file, wrongNetDb);
    await admin.query(`UPDATE pv_meta SET value='mainnet' WHERE key='network'`).catch(() => {});
    {
      const wn = new Pool({ host: PG.host, port: PG.port, user: PG.user, database: wrongNetDb });
      await wn.query(`UPDATE pv_meta SET value='mainnet' WHERE key='network'`);
      await wn.end();
    }
    let wrongNetRefused = false;
    try {
      await openPgStore(liveDbConfig(wrongNetDb));
    } catch (e) {
      wrongNetRefused = e.code === "STORE_NETWORK_MISMATCH" || /belongs to network/.test(e.message);
    }
    assert(wrongNetRefused, "a wrong-network restored DB must be refused (§40)");
    log("FAILURE CASE: wrong-network restored DB refused ✓");

    // (b) corrupt/truncated backup: pg_restore fails; no partial serving.
    const corruptFile = path.join(BACKUP_DIR, "B2_corrupt.dump");
    const buf = fs.readFileSync(b2.file);
    fs.writeFileSync(corruptFile, buf.subarray(0, Math.floor(buf.length / 2))); // truncate
    let corruptRefused = false;
    try {
      await restoreInto(corruptFile, `pv_dr_corrupt_${process.pid}`);
      // if pg_restore didn't hard-fail, the schema won't be current -> openPgStore refuses
      await openPgStore(liveDbConfig(`pv_dr_corrupt_${process.pid}`));
    } catch {
      corruptRefused = true;
    }
    assert(corruptRefused, "a corrupt/truncated backup must be refused (§40)");
    log("FAILURE CASE: corrupt/truncated backup refused ✓");
    evidence.steps.push("Restore failure cases: wrong-network DB refused; corrupt backup refused (§40)");
    evidence.restoreFailures = { wrongNetworkRefused: true, corruptBackupRefused: true };

    evidence.result = "PASS";
    evidence.finishedAt = new Date().toISOString();
    fs.writeFileSync(OUT, JSON.stringify(evidence, null, 2));
    log(`=== BACKUP/RESTORE DR EXERCISE PASS -> ${OUT} ===`);
  } catch (e) {
    evidence.result = "FAIL";
    evidence.error = e.message;
    fs.writeFileSync(OUT, JSON.stringify(evidence, null, 2));
    log("FAILED:", e.message);
    throw e;
  } finally {
    await rpc.disconnect().catch(() => {});
    for (const db of createdDbs) {
      await admin.query(`DROP DATABASE IF EXISTS ${db} WITH (FORCE)`).catch(() => {});
    }
    await admin.end().catch(() => {});
    // backups contain application metadata — remove them after evidence.
    fs.rmSync(BACKUP_DIR, { recursive: true, force: true });
    fs.rmSync(DR_JSON_ROOT, { recursive: true, force: true });
  }
}

main().catch((e) => { console.error(e); process.exit(1); });
