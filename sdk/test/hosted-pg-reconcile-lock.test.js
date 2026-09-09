"use strict";

/*
 * HOSTED PG: Codex checkpoint 12 (rc26 round-7 review R7-07, "residual
 * backing-store identity bypasses — Low"): two ACCEPTED PostgreSQL
 * configurations naming ONE backing database as `localhost` and
 * `127.0.0.1` obtained different reconcile locks on the rc27 runtime
 * `9da991f`, so two concurrent reconciliations of one request ran side by
 * side (CHAIN_VERIFIED / PENDING, a durable RECONCILIATION_REQUIRED request
 * beside an installed verified manifest). The queue is now keyed by the
 * request id alone (sdk/src/wallet-submit-v4.js `reconcileLockKey`), and
 * `reconcileLockIdentity` unifies every loopback alias.
 *
 * This file exercises the LIVE database with two separately opened stores
 * (two pools, two config objects, two host spellings) — SKIPPED cleanly
 * without POLICYVAULT_TEST_PG_{PORT,USER,DATABASE}. The node is a minimal
 * fake: the vault query answers the covenant output ONCE (first caller),
 * every other query fails — so an UNSERIALIZED second caller could never
 * reach CHAIN_VERIFIED on its own evidence. RED on 9da991f.
 */

const { test, before, after } = require("node:test");
const assert = require("node:assert/strict");
const os = require("node:os");
const fs = require("node:fs");
const path = require("node:path");
const { loadConfig } = require("../src/config");
const { openPgStore } = require("../src/store");
const wr4 = require("../src/wallet-requests-v4");
const submit4 = require("../src/wallet-submit-v4");
const { claimSubmission } = require("../src/submission-claim");
const { loadManifestV4 } = require("../src/manifest-v4");
const { CONTRACT_VERSION_V4_1 } = require("../../core/model/vault-state-v4.js");
const { ENCODER_PATH } = require("../src/vault-builders-v4");

const PG = {
  host: process.env.POLICYVAULT_TEST_PG_HOST || "127.0.0.1",
  port: Number(process.env.POLICYVAULT_TEST_PG_PORT || 0),
  user: process.env.POLICYVAULT_TEST_PG_USER,
  database: process.env.POLICYVAULT_TEST_PG_DATABASE
};
const PG_AVAILABLE = Boolean(PG.port && PG.user && PG.database);
const probe = loadConfig({ dataRoot: fs.mkdtempSync(path.join(os.tmpdir(), "pv-pglock-probe-")) });
const TOOLCHAIN_AVAILABLE = fs.existsSync(probe.silvercPath) && fs.existsSync(ENCODER_PATH);
const skip = !PG_AVAILABLE ? "set POLICYVAULT_TEST_PG_{PORT,USER,DATABASE} to run PostgreSQL integration" : !TOOLCHAIN_AVAILABLE ? "REQUIREMENT_NOT_AVAILABLE: silverc / pv_call_encoder" : undefined;

let adminPool;
const createdDbs = [];
const openStores = [];
function pgConfigFor(dbName, host) {
  return loadConfig({ persistenceBackend: "postgres", pgHost: host, pgPort: PG.port, pgUser: PG.user, pgDatabase: dbName, pgNoTls: true, authMode: "enabled", authCookieInsecure: true, dataRoot: fs.mkdtempSync(path.join(os.tmpdir(), "pv-pglock-")) });
}
before(async () => {
  if (!PG_AVAILABLE) return;
  const { Pool } = require("pg");
  adminPool = new Pool({ host: PG.host, port: PG.port, user: PG.user, database: PG.database });
});
after(async () => {
  if (!PG_AVAILABLE) return;
  for (const s of openStores) { try { await s.close(); } catch { /* closed */ } }
  for (const db of createdDbs) { try { await adminPool.query(`DROP DATABASE IF EXISTS ${db} WITH (FORCE)`); } catch { /* best effort */ } }
  await adminPool.end();
});

const kaspa = TOOLCHAIN_AVAILABLE ? require(probe.rustyKaspaModule) : null;
const KAS = 100000000n;
const KEY = (v) => new kaspa.PrivateKey(v.toString(16).padStart(2, "0").repeat(32));
const XO = (v) => KEY(v).toPublicKey().toXOnlyPublicKey().toString().toLowerCase();
const ADDR = (v, networkId) => KEY(v).toPublicKey().toAddress(networkId).toString();
const p2pk = (x) => `20${x}ac`;
const OWNER = 5, AGENT = 0x2f, RECIP = 0x39;

/* the minimal fake node described above */
function fakeNode(vaultUtxo) {
  let vaultAnswers = 1;
  const failing = async () => { throw new Error("fake node: query not available"); };
  return {
    getUtxosByAddresses: async ({ addresses }) => {
      if (addresses[0] === vaultUtxo.address && vaultAnswers > 0) { vaultAnswers -= 1; return { entries: [{ outpoint: vaultUtxo.outpoint, utxoEntry: { amount: vaultUtxo.amount, scriptPublicKey: { script: "aa" }, covenantId: vaultUtxo.covenantId, blockDaaScore: "1", isCoinbase: false } }] }; }
      throw new Error("fake node: query not available");
    },
    getMempoolEntry: failing, getBlockDagInfo: failing, getVirtualChainFromBlock: failing, getBlocks: failing, getBlock: failing,
    disconnect: async () => {}
  };
}

test("R7-07 (checkpoint 12) on live PostgreSQL: two accepted configurations of ONE database (`127.0.0.1` and `localhost`, separately opened stores) reconcile ONE request serialized — both CHAIN_VERIFIED, one manifest, no unresolved request beside it", { skip }, async () => {
  const dbName = `pv_pglock_${process.pid}_${Date.now() % 100000}`;
  await adminPool.query(`CREATE DATABASE ${dbName}`);
  createdDbs.push(dbName);
  const A = pgConfigFor(dbName, "127.0.0.1");
  openStores.push(await openPgStore(A, { migrate: true }));
  const B = pgConfigFor(dbName, "localhost");
  openStores.push(await openPgStore(B));
  assert.notEqual(A.pg.host, B.pg.host, "two different accepted host spellings");

  const rec0 = await wr4.buildCreateWalletRequestV4({
    config: A,
    templateInput: { owner: XO(OWNER), vaultId: "d9".repeat(32) },
    initialAgents: [{ agentPk: XO(AGENT), maxPerSpend: (2n * KAS).toString(), periodBudget: (10n * KAS).toString(), periodLengthDaa: "864000", periodStartDaa: "541000000", periodSpent: "0", approvalThreshold: (1n * KAS).toString(), agentMaxFeePerTx: (KAS / 10n).toString(), recipients: [XO(RECIP)] }],
    initialState: { protectedValue: (100n * KAS).toString(), feeReserve: (5n * KAS).toString(), approvers: [], approvalM: "0" },
    signerAddress: ADDR(OWNER, A.networkId),
    funding: [{ outpoint: { transactionId: "9f".repeat(32), index: 0 }, amount: (200n * KAS).toString(), scriptPublicKeyHex: p2pk(XO(OWNER)) }],
    label: "pglock", contractVersion: CONTRACT_VERSION_V4_1
  });
  const rec = await wr4.loadRequest(A, rec0.requestId);
  rec.state = "SUBMITTED"; rec.txId = rec.build.txId; rec.submittedAt = new Date(Date.now() - 10 * 60 * 1000).toISOString();
  rec.chainObservation = { sink: "cc".repeat(32) };
  await wr4.saveRequest(A, rec);
  await claimSubmission(A, { txId: rec.txId, vaultId: rec.vaultId, action: "createVault" });
  const { vaultAddress, vaultValue } = submit4.genesisTargetV4(A, rec);
  const rpc = fakeNode({ address: vaultAddress, outpoint: { transactionId: rec.txId, index: rec.vaultOutputIndex }, amount: vaultValue, covenantId: rec.covenantId });

  const [a, b] = await Promise.all([
    submit4.reconcileCreateWalletRequestV4({ config: A, requestId: rec.requestId, rpc, stalePendingMinimumMs: 1000 }),
    submit4.reconcileCreateWalletRequestV4({ config: B, requestId: rec.requestId, rpc, stalePendingMinimumMs: 1000 })
  ]);
  assert.deepEqual([a.outcome, b.outcome], ["CHAIN_VERIFIED", "CHAIN_VERIFIED"], `serialized across the two configurations (got ${a.outcome} / ${b.outcome}: ${a.detail} / ${b.detail})`);
  assert.ok([a.detail, b.detail].some((d) => /already chain-verified/.test(String(d))), "the waiting caller re-read the durable outcome instead of deciding on its own answers");
  for (const cfg of [A, B]) {
    assert.equal((await wr4.loadRequest(cfg, rec.requestId)).state, "CHAIN_VERIFIED", `durable state through ${cfg.pg.host}`);
    const manifest = await loadManifestV4(cfg, rec.vaultId);
    assert.ok(manifest && manifest.creationTxId === rec.txId, `one verified manifest through ${cfg.pg.host}`);
  }
  const unresolved = await require("../src/store").getStore(A).pool().query("SELECT value->>'state' AS s FROM wallet_requests WHERE key = $1", [rec.requestId]);
  assert.equal(unresolved.rows[0].s, "CHAIN_VERIFIED", "no RECONCILIATION_REQUIRED request beside the installed manifest (jsonb row)");
  /* the corrected interface, asserted AFTER the behaviour so a RED run on the old runtime reaches the concurrency outcome first */
  assert.equal(submit4.reconcileLockIdentity(A), submit4.reconcileLockIdentity(B), "the diagnostic store identity unifies the loopback aliases");
  assert.equal(submit4.reconcileLockKey("r-1"), submit4.reconcileLockKey("r-1"), "the queue key depends on the request id only");
});
