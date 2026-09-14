"use strict";
// Synthetic wallets and real v041 builds/signatures/VM. Only node observations
// are simulated. No production IDs, records, credentials or endpoints.
const { test, before, after } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs"), path = require("node:path"), crypto = require("node:crypto");
// Corrupt storage identity must be tested without asking validated reads to
// snapshot the deliberately malformed record before the operation under test.
// Compare durable records only; recorded-script verification may populate its
// separate disposable compiler cache, which is not a store mutation.
function rawTreeSnapshot(root) {
  const result = {};
  function visit(dir) { for (const entry of fs.readdirSync(dir, { withFileTypes: true }).sort((a,b) => a.name.localeCompare(b.name))) {
    const file = path.join(dir, entry.name);
    if (entry.isDirectory()) visit(file);
    else if (entry.isFile()) result[path.relative(root, file)] = crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");
    else throw Error("TEST unexpected file type");
  } }
  for (const name of ["audit", "claims", "receipts", "requests", "vaults"]) {
    const dir = path.join(root,name); if (fs.existsSync(dir)) visit(dir);
  }
  return result;
}
const fx = require("../testutil/v4-transition-recovery-fixture");
const { makeDevSigner } = require("../src/signer-dev");
const { reconcileTransitionWalletRequestV4, canonicalRecordFingerprint } = require("../src/wallet-recovery-v4");
const { recordedNegativeIsEstablished } = require("../src/submission-classification");
const { deriveOperationalStatus } = require("../src/operational-status");
const { openPgStore } = require("../src/store");
const { Categories, getStore, clone, wr4, submit4, transitionClaimKey } = fx;
const toolchain = require("../testutil/org-root-durable-fixture").toolchainAvailable();
const skip = toolchain ? undefined : "REQUIREMENT_NOT_AVAILABLE: real compiler and VM";
const pg = { host: "127.0.0.1", port: Number(process.env.POLICYVAULT_TEST_PG_PORT || 0), user: process.env.POLICYVAULT_TEST_PG_USER, database: process.env.POLICYVAULT_TEST_PG_DATABASE };
const pgSkip = skip || (!pg.port || !pg.user || !pg.database ? "REQUIREMENT_NOT_AVAILABLE: isolated PostgreSQL" : undefined);
const roots = [], stores = [], databases = [];
let base, winning, history, admin, serial = 0;
before(async () => {
  if (!toolchain) return;
  base = await fx.baseFixture("ownerRecover");
  const config = fx.freshConfig(); roots.push(config.dataRoot);
  await getStore(config).write(Categories.VAULT, base.request.vaultId, clone(base.before));
  const request = await wr4.buildWalletRequestV4({ ...base.pendingBuild, config, action: "ownerRecover",
    params: { fuel: { ...base.pendingBuild.params.fuel, outpoint: { transactionId: "54".repeat(32), index: 1 } } } });
  const signed = makeDevSigner(config, { secretHex: base.owner.secretHex, expectedAddress: base.owner.address }).signInputs(request.transaction.unsignedSafeJson, request.transaction.signInputs);
  winning = await wr4.finalizeWalletRequestV4({ config, requestId: request.requestId, signedSafeJson: signed });
  assert.notEqual(winning.txId, base.request.txId);
  const node = fx.caseFor({ ...base, request: winning }, config);
  node.rpc.submitTransaction = async () => { node.settle(); return { transactionId: winning.txId }; };
  const result = await submit4.submitWalletRequestV4({ config, requestId: winning.requestId, rpc: node.rpc, pollAttempts: 1, pollDelayMs: 0 });
  assert.equal(result.request.state, "CHAIN_VERIFIED");
  winning = result.request;
  assert.equal((await node.manifest()).status, "RECOVERED");
  // Historical writer left a successful same-predecessor claim in place.
  assert.equal((await node.store().read(Categories.TRANSITION_CLAIM, transitionClaimKey(winning.predecessorOutpoint))).txId, winning.txId);
  await wr4.saveRequest(config, clone(base.request));
  history = await fx.snapshot(config);
  if (!pgSkip) admin = new (require("pg").Pool)(pg);
});
after(async () => {
  for (const store of stores) await store.close();
  if (admin) { for (const name of databases) await admin.query(`DROP DATABASE ${name} WITH (FORCE)`); await admin.end(); }
  if (base) base.cleanup();
  for (const root of roots) fs.rmSync(root, { recursive: true, force: true });
});
async function makeCase(backend = "JSON") {
  let config, pgOptions;
  if (backend === "PostgreSQL") {
    const name = `pv_rc40_foreign_${process.pid}_${++serial}`; await admin.query(`CREATE DATABASE ${name}`); databases.push(name);
    pgOptions = { persistenceBackend: "postgres", pgHost: pg.host, pgPort: pg.port, pgUser: pg.user, pgDatabase: name, pgNoTls: true, authMode: "enabled", authCookieInsecure: true };
    config = fx.freshConfig(pgOptions);
    stores.push(await openPgStore(config, { migrate: true }));
  } else config = fx.freshConfig();
  roots.push(config.dataRoot); await fx.install(config, history);
  const x = fx.caseFor(base, config);
  x.reopen = async () => {
    if (backend === "PostgreSQL") {
      const previous = x.store(); await previous.close(); stores.splice(stores.indexOf(previous), 1);
      config = fx.loadConfig({ ...pgOptions, dataRoot: config.dataRoot });
      stores.push(await openPgStore(config));
    } else config = fx.loadConfig({ dataRoot: config.dataRoot });
    x.config = config;
  };
  return x;
}
for (const [backend, omitted] of [["JSON", skip], ["PostgreSQL", pgSkip]]) {
  test(`RC40 ${backend}: foreign completed owner recovery is protected unchanged across retries and reload`, { skip: omitted }, async () => {
    const x = await makeCase(backend), before = await fx.snapshot(x.config), q = await x.request();
    const fp = canonicalRecordFingerprint(q);
    for (let i = 0; i < 2; i++) {
      const result = await x.recover({ expectedFingerprint: fp });
      assert.equal(result.outcome, "PROTECTED_UNRESOLVED");
      assert.match(result.detail, /another.*recovery.*claim/i);
      assert.equal(result.request.state, "SUBMISSION_REJECTED");
      assert.equal(result.request.transitionRecovery, undefined);
      assert.equal(recordedNegativeIsEstablished(result.request), false);
      assert.deepEqual(await fx.snapshot(x.config), before);
      await x.reopen();
    }
    assert.equal(x.submits(), 0); assert.equal(x.reads(), 0);
  });
  test(`RC40 ${backend}: closed vault history stays readable and protected admission authorizes no second recovery`, { skip: omitted }, async () => {
    const x = await makeCase(backend), before = await fx.snapshot(x.config);
    const status = await x.generic();
    assert.equal(status.status, "REQUEST_RECOVERY_REQUIRED");
    assert.equal(status.vaultStatus, "RECOVERED");
    assert.equal(status.recordedVaultClosed, true);
    assert.equal(status.requestId, base.request.requestId);
    assert.match(status.reason, /historical.*unresolved/i);
    assert.equal(deriveOperationalStatus({ manifest: await x.manifest() }).status, "CLOSED");
    assert.equal((await wr4.loadRequest(x.config, winning.requestId)).state, "CHAIN_VERIFIED");
    assert.equal((await x.store().read(Categories.RECEIPT, winning.txId)).proof.requestId, winning.requestId);
    await assert.rejects(wr4.buildWalletRequestV4({ ...base.pendingBuild, config: x.config, action: "ownerRecover" }), { code: "REQUEST_RECOVERY_REQUIRED" });
    await assert.rejects(submit4.submitWalletRequestV4({ config: x.config, requestId: base.request.requestId, rpc: x.rpc }), { code: "SUBMISSION_REJECTED" });
    assert.deepEqual(await fx.snapshot(x.config), before);
    assert.equal(x.submits(), 0); assert.equal(x.reads(), 0);
  });
}
for (const fault of ["foreign-vault", "foreign-predecessor", "same-transaction", "malformed-claim", "wrong-winner", "winner-no-receipt", "winner-not-verified", "winner-wrong-receipt", "winner-wrong-manifest", "winner-no-signature", "own-submission", "own-receipt", "shared-transaction", "protected-journal", "no-retained-signature"]) {
  test(`RC40 narrow disposition refuses ${fault} without writes`, { skip }, async () => {
    const x = await makeCase(), s = x.store(), q = await x.request(), key = transitionClaimKey(q.predecessorOutpoint);
    const claim = await s.read(Categories.TRANSITION_CLAIM, key);
    if (fault === "foreign-vault") claim.vaultId = "fb".repeat(32);
    if (fault === "foreign-predecessor") claim.outpoint = { transactionId: "fc".repeat(32), index: 0 };
    if (fault === "same-transaction") claim.txId = q.txId;
    if (fault === "malformed-claim") claim.expected = null;
    if (fault === "wrong-winner") claim.requestId = "unrelated-request";
    if (["foreign-vault", "foreign-predecessor", "same-transaction", "malformed-claim", "wrong-winner"].includes(fault)) await s.write(Categories.TRANSITION_CLAIM, key, claim);
    if (fault === "winner-no-receipt") await s.remove(Categories.RECEIPT, winning.txId);
    if (fault === "winner-not-verified" || fault === "winner-no-signature") {
      const r = await wr4.loadRequest(x.config, winning.requestId);
      if (fault === "winner-not-verified") r.state = "SUBMITTED"; else delete r.finalTransaction;
      await wr4.saveRequest(x.config, r);
    }
    if (fault === "winner-wrong-receipt") {
      const r = await s.read(Categories.RECEIPT, winning.txId); r.proof.requestId = "unrelated-request"; await s.write(Categories.RECEIPT, winning.txId, r);
    }
    if (fault === "winner-wrong-manifest") { const m = await x.manifest(); m.latestTransitionTxId = "fd".repeat(32); await s.write(Categories.VAULT, q.vaultId, m); }
    if (fault === "own-submission") await s.write(Categories.SUBMISSION_CLAIM, q.txId, { schema: "policyvault-submission-claim/v1", txId: q.txId, vaultId: q.vaultId, action: q.action, requestId: "unrelated-request" });
    if (fault === "own-receipt") await s.write(Categories.RECEIPT, q.txId, { schema: "policyvault-receipt/v1", txId: q.txId, vaultId: q.vaultId, action: q.action, proof: { requestId: "unrelated-request" } });
    if (fault === "shared-transaction") await wr4.saveRequest(x.config, { ...clone(q), requestId: "shared-tx-request", state: "RECONCILIATION_REQUIRED" });
    if (fault === "protected-journal") { q.transitionRecovery = { schema: "policyvault-transition-recovery/v1", phase: "PROTECTED" }; await wr4.saveRequest(x.config, q); }
    if (fault === "no-retained-signature") { delete q.finalTransaction; await wr4.saveRequest(x.config, q); }
    const snapshot = fault === "foreign-predecessor" ? async () => rawTreeSnapshot(x.config.dataRoot) : async () => fx.snapshot(x.config);
    const before = await snapshot();
    await assert.rejects(x.recover(), fault === "foreign-predecessor" ? { code: "STORE_IDENTITY_MISMATCH" } : undefined);
    assert.deepEqual(await snapshot(), before);
    assert.equal(x.submits(), 0); assert.equal(x.reads(), 0);
  });
}
test("RC40: selected fingerprint drift still refuses before narrow disposition", { skip }, async () => {
  const x = await makeCase(), before = await fx.snapshot(x.config);
  await assert.rejects(x.recover({ expectedFingerprint: "00".repeat(32) }), { code: "REQUEST_FINGERPRINT_MISMATCH" });
  assert.deepEqual(await fx.snapshot(x.config), before);
});
test("RC40: ordinary owner recovery without the foreign-claim disposition still completes", { skip }, async () => {
  const x = await fx.jsonCase(base); roots.push(x.config.dataRoot); x.settle();
  assert.equal((await x.recover()).outcome, "CHAIN_VERIFIED");
  await fx.assertComplete(x, base);
});
async function inspectionSnapshot(x) {
  const all = await fx.snapshot(x.config), read = (cat,key) => all.records[cat].find(([k]) => k === key)?.[1] ?? null;
  const request = await x.request(), transitionClaim = read(Categories.TRANSITION_CLAIM, transitionClaimKey(request.predecessorOutpoint));
  return { request, manifest: await x.manifest(), requests: all.records[Categories.REQUEST].map(([,r]) => r).filter(r => r.vaultId === request.vaultId),
    transitionClaim, submissionClaim: read(Categories.SUBMISSION_CLAIM, request.txId), receipt: read(Categories.RECEIPT, request.txId),
    winnerSubmissionClaim: read(Categories.SUBMISSION_CLAIM, transitionClaim.txId), winnerReceipt: read(Categories.RECEIPT, transitionClaim.txId) };
}
function freezeSnapshot(x) { if (x && typeof x === "object") { for (const v of Object.values(x)) freezeSnapshot(v); Object.freeze(x); } return x; }
test("RC40: snapshot inspector verifies retained evidence without using any record-store method", { skip }, async () => {
  const x = await makeCase(), snapshot = freezeSnapshot(await inspectionSnapshot(x)), before = await fx.snapshot(x.config), s = x.store();
  const original = new Map();
  for (const key of ["read","write","createExclusive","remove","listKeys","readAudit","appendAudit"]) {
    original.set(key,s[key]); s[key] = () => { throw Error("TEST snapshot inspection called record store"); };
  }
  try {
    assert.deepEqual(require("../src/wallet-recovery-v4").inspectForeignCompletedRecoveryV4(x.config,snapshot), {
      schema: "policyvault-foreign-owner-recovery-inspection/v1", eligible: true, disposition: "PROTECTED_UNRESOLVED",
      requestOutcomeEstablished: false, newAdmissionAuthorized: false, writesAuthorized: false });
  } finally { for (const [key,fn] of original) s[key] = fn; }
  assert.deepEqual(await fx.snapshot(x.config),before); assert.equal(x.submits(),0); assert.equal(x.reads(),0);
});
for (const fault of ["missing-key","missing-request","duplicate-request","different-vault","no-winner-receipt","wrong-winner-receipt","own-claim-conflict","missing-winner-signature","invalid-loser-signature"]) {
  test(`RC40 snapshot inspector refuses ${fault} and preserves the supplied records`, { skip }, async () => {
    const x = await makeCase(), snapshot = await inspectionSnapshot(x);
    if (fault === "missing-key") delete snapshot.receipt;
    if (fault === "missing-request") snapshot.requests = snapshot.requests.filter(r => r.requestId !== snapshot.request.requestId);
    if (fault === "duplicate-request") snapshot.requests.push(clone(snapshot.request));
    if (fault === "different-vault") snapshot.requests.push({ ...clone(snapshot.request), requestId: "other-vault", vaultId: "fa".repeat(32) });
    if (fault === "no-winner-receipt") snapshot.winnerReceipt = null;
    if (fault === "wrong-winner-receipt") snapshot.winnerReceipt.proof.requestId = "other-request";
    if (fault === "own-claim-conflict") snapshot.submissionClaim = { schema:"policyvault-submission-claim/v1",txId:snapshot.request.txId,requestId:"other-request" };
    if (fault === "missing-winner-signature") delete snapshot.requests.find(r => r.txId === snapshot.transitionClaim.txId).finalTransaction;
    if (fault === "invalid-loser-signature") { snapshot.request.finalTransaction.inputs[0].signatureScript = "00"; snapshot.requests = snapshot.requests.map(r => r.requestId === snapshot.request.requestId ? clone(snapshot.request) : r); }
    const before = JSON.stringify(snapshot), durable = await fx.snapshot(x.config); freezeSnapshot(snapshot);
    let result;
    try { result = require("../src/wallet-recovery-v4").inspectForeignCompletedRecoveryV4(x.config,snapshot); }
    catch (e) { assert.ok(e.code, "typed refusal required"); }
    if (result) { assert.equal(result.eligible,false); assert.equal(result.disposition,null); assert.equal(result.writesAuthorized,false); }
    assert.equal(JSON.stringify(snapshot),before); assert.deepEqual(await fx.snapshot(x.config),durable);
    assert.equal(x.submits(),0); assert.equal(x.reads(),0);
  });
}
