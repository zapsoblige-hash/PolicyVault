"use strict";
// Real isolated PostgreSQL databases/fresh pools + real SDK/VM; RPC is stubbed.
const { test, before, after } = require("node:test"), assert = require("node:assert/strict");
const fs = require("node:fs"), path = require("node:path");
const f = require("../testutil/rc27f-fixtures"), { dep, fx, d, wr } = f;
const { outcomeRpc } = require("../testutil/rc27f-outcome-fixture");
const { loadConfig } = require("../src/config"), { openPgStore } = require("../src/store");
const rec = dep("sdk/src/reconcile-v7"), claims = dep("sdk/src/submission-claim"), hd = dep("sdk/src/wallet-requests-v7-hd"), C = fx.Categories;
const PG = { host: process.env.POLICYVAULT_TEST_PG_HOST || "127.0.0.1", port: Number(process.env.POLICYVAULT_TEST_PG_PORT || 0), user: process.env.POLICYVAULT_TEST_PG_USER, database: process.env.POLICYVAULT_TEST_PG_DATABASE };
const skip = !(PG.port && PG.user && PG.database) ? "set POLICYVAULT_TEST_PG_{PORT,USER,DATABASE}" : !fx.toolchainAvailable() ? "REQUIREMENT_NOT_AVAILABLE: real v7 compiler/VM" : undefined;
let admin, spendBase, depositBase, hdBase, serial = 0;
const databases = [], stores = [];
test("RC27F live PG F-8: reservations retain composite identities and refuse substitutions", { skip }, async () => {
  const x = await fresh();
  await require("../testutil/rc27f-store-controls")(fx.getStore(x.config), C);
});
before(async () => {
  if (skip) return;
  admin = new (require("pg").Pool)(PG); spendBase = await d.baseFixture(); depositBase = await f.depositBase();
  const config = fx.cloneJsonConfig(spendBase.config, "pv-rc27f-pg-hd-base-"), o = spendBase.o;
  const q = await hd.buildHdVaultGenesisRequest({ config, rootCovenantId: o.rootCovenantId, descriptor: o.descriptor, initialAgents: [{ pk: fx.XO(config, o.agentKey), maxPerSpend: "500", periodBudget: "2000", periodLengthDaa: "1000", periodStartDaa: "0", periodSpent: "0", maxFeePerTx: fx.KAS.toString(), maxCarryKas: fx.KAS.toString(), expiryDaa: "999999999", recipients: [fx.XO(config, o.recipientKey)] }], recoveryAddress: fx.ADDR(config, o.owner1), feeReserveKas: "5", signerAddress: fx.ADDR(config, o.funder), funding: [fx.fuelUtxoFor(config, o.funder)] });
  const ready = await hd.finalizeHdWalletRequest({ config, requestId: q.requestId, signedSafeJson: fx.signAll(config, q.transaction.unsignedSafeJson, q.transaction.signInputs.map((i) => [i.index, o.funder])) });
  hdBase = { ...spendBase, config, q: ready };
});
after(async () => {
  for (const store of stores) if (!store.pool().ending) await store.close();
  for (const db of databases) await admin.query(`DROP DATABASE ${db} WITH (FORCE)`);
  if (admin) await admin.end();
});
async function open(db, dataRoot, migrate = false) {
  const config = loadConfig({ dataRoot, persistenceBackend: "postgres", pgHost: PG.host, pgPort: PG.port, pgUser: PG.user, pgDatabase: db, pgNoTls: true, authMode: "enabled", authCookieInsecure: true });
  stores.push(await openPgStore(config, { migrate })); return config;
}
async function fresh(base = spendBase) {
  const db = `pv_rc27f_${process.pid}_${++serial}`, files = fx.cloneJsonConfig(base.config, "pv-rc27f-pg-files-");
  await admin.query(`CREATE DATABASE ${db}`); databases.push(db);
  const config = await open(db, files.dataRoot, true), target = fx.getStore(config), source = fx.getStore(base.config);
  for (const c of [C.ORG_ROOT, C.ORG_ROOT_REQUEST, C.VAULT, C.REQUEST, C.RECEIPT, C.SUBMISSION_CLAIM, C.TRANSITION_CLAIM]) for (const key of await source.listKeys(c)) await target.write(c, key, await source.read(c, key));
  for (const e of await source.readAudit({ limit: 1000 })) await target.appendAudit(e);
  const x = base === depositBase ? f.depositCase(base, config) : d.caseFor(base, config);
  x.db = db;
  x.reopen = async () => { await fx.getStore(x.config).close(); x.config = await open(db, files.dataRoot); };
  x.other = () => open(db, files.dataRoot);
  x.org = () => rec.reconcileOrgRootV7(x.config, x.o.rootCovenantId, { rpc: x.rpc, stalePendingMinimumMs: 0 });
  return x;
}
for (const stage of ["vault", "receipt", "finalRequest"]) test(`RC27F live PG F-4: org-only ${stage} recovery preserves the preceding root request across fresh pools`, { skip }, async () => {
  const x = await fresh(), previous = await wr.loadOrgRootRequest(x.config, x.first.id);
  const [method, predicate] = d.boundaries[stage], fault = fx.inject(x.config, method, (...args) => predicate(x, ...args));
  x.settle(); await assert.rejects(x.submit()); assert.equal(fault.count(), 1); fault.restore();
  await x.reopen(); await x.org(); await x.org(); await d.assertComplete(x);
  assert.deepEqual(await wr.loadOrgRootRequest(x.config, x.first.id), previous);
  await d.signedSpend(x.config, x.o);
});
for (const stage of ["vault", "receipt", "audit", "submissionRelease", "finalRequest"]) test(`RC27F live PG F-3: deposit ${stage} failure resumes through public organization reconciliation`, { skip }, async () => {
  const x = await fresh(depositBase), [method, predicate] = d.boundaries[stage], fault = fx.inject(x.config, method, (...args) => predicate(x, ...args));
  x.settle(); await assert.rejects(x.submit()); assert.equal(fault.count(), 1); fault.restore();
  await x.reopen(); await x.org(); await x.submit(); await f.assertDepositComplete(x);
  await d.signedSpend(x.config, x.o);
});
for (const kind of ["delegate", "deposit"]) test(`RC27F live PG F-5: compound ${kind} inspection failures cannot rewind completion`, { skip }, async () => {
  const x = await fresh(kind === "deposit" ? depositBase : spendBase); x.settle(); await x.submit(); await x.reopen();
  const q = await x.request(), vault = await x.vault(); let armed = false;
  const a = fx.inject(x.config, "readAudit", (args) => { if (args.txId === x.q.txId) { armed = true; return true; } return false; }, { times: Infinity });
  const b = fx.inject(x.config, "read", (c, k) => armed && c === C.REQUEST && k === x.q.requestId, { times: Infinity });
  await assert.rejects(x.submit()); assert.ok(a.count() && b.count()); a.restore(); b.restore(); await x.reopen();
  assert.deepEqual(await x.request(), q); assert.deepEqual(await x.vault(), vault); await x.submit(); assert.equal(x.rpc.submits(), 1);
});
for (const mode of ["rejection", "uncertain", "claim-write", "release-write", "conflict"]) test(`RC27F live PG F-1: ${mode} retains/replays exactly its own outcome across sessions`, { skip }, async () => {
  const x = await fresh(); outcomeRpc(x, { rejection: mode === "rejection", conflict: mode === "conflict" });
  const claim = mode === "claim-write" && fx.inject(x.config, "createExclusive", (c) => c === C.SUBMISSION_CLAIM);
  await assert.rejects(x.submit()); if (claim) claim.restore();
  if (mode === "uncertain") x.rpc.getMempoolEntry = async () => { throw Error("unknown RPC response"); };
  await x.reopen();
  if (mode === "release-write") {
    const fault = fx.inject(x.config, "remove", (c) => c === C.SUBMISSION_CLAIM);
    assert.equal((await x.reconcile()).status, "UNKNOWN"); assert.equal(fault.count(), 1); fault.restore(); await x.reopen();
  }
  const r = await x.reconcile();
  if (mode === "uncertain") {
    assert.equal(r.status, "UNKNOWN"); assert.ok(await fx.loadSubmissionClaim(x.config, x.q.txId));
    await assert.rejects(d.signedSpend(x.config, x.o), { code: "VAULT_PENDING_REQUEST" });
    x.settle(); await x.org(); await d.assertComplete(x);
  } else {
    assert.equal((await x.request()).state, mode === "rejection" ? "SUBMISSION_REJECTED" : mode === "conflict" ? "SUPERSEDED" : "NOT_BROADCAST");
    assert.equal(await fx.loadSubmissionClaim(x.config, x.q.txId), null); assert.equal(await claims.loadTransitionClaim(x.config, x.q.predecessorOutpoint), null);
    await d.signedSpend(x.config, x.o);
  }
  assert.equal(x.rpc.submits(), mode === "claim-write" ? 0 : 1);
});
for (const scenario of ["latest-delegate", "interleaved-agents", "replaced-agent-and-recipients", "terminal-with-retained-token", "deposit-terminal-with-retained-token"]) test(`RC27F live PG F-2: actual df68 ${scenario} history remains usable after fresh-pool reload`, { skip }, async () => {
  const saved = JSON.parse(fs.readFileSync(path.resolve(__dirname, "../../docs/postlaunch/ux-evidence/codex-rc27f/fixtures", scenario + ".json")), (_k, v) => v?.$big ? BigInt(v.$big) : v);
  assert.equal(saved.producedBy, "df68a1fd64775948e799935759d08b549181100c");
  const config = fx.freshJsonConfig("pv-rc27f-legacy-pg-base-"), source = fx.getStore(config);
  for (const [c, rows] of Object.entries(saved.records)) for (const [k, row] of Object.entries(rows)) await source.write(c, k, row);
  for (const e of saved.audit) await source.appendAudit(e);
  const o = { ...saved.ids, fuelKey: fx.KEY(config, 0x64), agentKey: fx.KEY(config, 0x62), owner1: fx.KEY(config, 0x71), owner2: fx.KEY(config, 0x72), recipientKey: fx.KEY(config, 0x63), rTree: dep("sdk/src/recipient-merkle-v3").buildRecipientTree([fx.XO(config, fx.KEY(config, 0x63))]) };
  const base = { config, o, root: await wr.loadOrgRoot(config, o.rootCovenantId), q: await wr.loadV7WalletRequest(config, o.spend ?? o.deposit) }, x = await fresh(base);
  for (const [a, entries] of Object.entries(saved.rpc)) { x.rpc.clear(a); for (const e of entries) x.rpc.seed(a, e); }
  const root = await wr.loadOrgRoot(x.config, o.rootCovenantId), vault = await x.vault();
  if (scenario === "latest-delegate") await d.signedSpend(x.config, o);
  await x.submit(); await x.reopen(); await x.org(); await x.org();
  assert.deepEqual(await wr.loadOrgRoot(x.config, o.rootCovenantId), root); assert.deepEqual(await x.vault(), vault);
  assert.equal((await x.request()).state, "CHAIN_VERIFIED"); assert.equal(x.rpc.submits(), 0);
  if (scenario === "replaced-agent-and-recipients") { o.agentKey = fx.KEY(x.config, 0x66); o.recipientKey = fx.KEY(x.config, 0x67); o.rTree = dep("sdk/src/recipient-merkle-v3").buildRecipientTree([fx.XO(x.config, o.recipientKey)]); }
  if (scenario.includes("terminal")) {
    assert.equal(vault.status, "RECOVERED"); assert.equal(vault.live, null);
    assert.equal((await wr.loadOrgRootRequest(x.config, o.terminal)).build.hasTokenInput, false);
    for (const requestId of [o.deposit, o.secondSpend].filter(Boolean)) assert.equal((await wr.submitV7WalletRequest({ config: x.config, requestId, rpc: x.rpc })).state, "CHAIN_VERIFIED");
    await x.reopen(); await x.org(); await fx.signedRootOnly(x.config, o);
    assert.deepEqual(await x.vault(), vault); assert.equal(x.rpc.submits(), 0);
  } else await d.signedSpend(x.config, o);
});
test("RC27F live PG F-6/F-7: independent owner signatures, cancellation and finalization share the root queue", { skip }, async () => {
  const x = await fresh(), other = await x.other(), third = await x.other();
  const q = await wr.buildRootActionRequest({ config: x.config, rootCovenantId: x.o.rootCovenantId, action: "authorize", params: { fuel: fx.fuelUtxoFor(x.config, x.o.fuelKey) }, signerAddress: fx.ADDR(x.config, x.o.owner1) });
  async function response(config, slot, key) {
    const r = await wr.getOrCreateSlotSigningRequest({ config, requestId: q.id, slot });
    return { responseVersion: "policyvault-org-root-slot-response/1", requestVersion: r.requestVersion, requestId: r.requestId, network: r.network, manifestHash: r.manifestHash, txId: r.txId, root: r.root, slot: r.slot, signerAddress: fx.ADDR(config, key), signatureHex: fx.sign65(config, q.transaction.unsignedSafeJson, q.rootInputIndex, key), sighashType: 1, signedAtMs: Date.now() };
  }
  const [one, two] = await Promise.all([response(x.config, 1, x.o.owner1), response(other, 2, x.o.owner2)]);
  const results = await Promise.allSettled([wr.submitSlotSignature({ config: x.config, requestId: q.id, slot: 1, response: one }), wr.submitSlotSignature({ config: other, requestId: q.id, slot: 2, response: two }), wr.rejectOrgRootRequest({ config: third, requestId: q.id })]);
  assert.equal(results[0].status, "fulfilled"); assert.equal(results[1].status, "fulfilled"); assert.equal(results[2].reason.code, "CANNOT_REJECT");
  await assert.rejects(wr.submitSlotSignature({ config: other, requestId: q.id, slot: 1, response: one }), { code: "DUPLICATE_SLOT_SIGNATURE" });
  const fuelSignatureScriptHex = fx.kaspaOf(x.config).createInputSignature(fx.kaspaOf(x.config).Transaction.deserializeFromSafeJSON(q.transaction.unsignedSafeJson), q.build.frozen.inputs.length - 1, x.o.fuelKey);
  await wr.finalizeOrgRootRequest({ config: x.config, requestId: q.id, fuelSignatureScriptHex });
  await fx.spendPredecessors(x.config, x.rpc, x.o); fx.settle(x.config, x.rpc, q);
  const done = await Promise.allSettled([wr.submitOrgRootRequest({ config: other, requestId: q.id, rpc: x.rpc }), wr.finalizeOrgRootRequest({ config: third, requestId: q.id, fuelSignatureScriptHex })]);
  assert.equal(done[0].value?.state, "CHAIN_VERIFIED"); assert.equal(done[1].status, "rejected");
  await x.reopen(); assert.equal((await wr.loadOrgRootRequest(x.config, q.id)).state, "CHAIN_VERIFIED"); assert.equal(x.rpc.submits(), 1);
});
test("RC27F live PG F-8: keyed/listed identities and canonical keys fail closed without folding legitimate spellings", { skip }, async () => {
  const x = await fresh(), store = fx.getStore(x.config);
  for (const key of ["Mixed", "MIXED"]) await store.write(C.REQUEST, key, { schema: "policyvault-wallet-request/v7", requestId: key });
  assert.equal((await store.read(C.REQUEST, "Mixed")).requestId, "Mixed"); assert.equal((await store.read(C.REQUEST, "MIXED")).requestId, "MIXED");
  await store.write(C.ORG_ROOT_REQUEST, "missing-id", { schemaVersion: wr.ORG_ROOT_REQUEST_SCHEMA, id: null });
  await assert.rejects(wr.listOrgRootRequests(x.config), { code: "REQUEST_ID_MISMATCH" }); await store.remove(C.ORG_ROOT_REQUEST, "missing-id");
  await store.pool().query("INSERT INTO org_root_requests(network_id,key,value) VALUES($1,$2,$3::jsonb)", [x.config.networkId, "./aliased", JSON.stringify({ generic: true })]);
  await assert.rejects(store.listValues(C.ORG_ROOT_REQUEST, { strict: true }), { code: "STORE_KEY_INVALID" });
});
for (const stage of ["root", "receipt", "audit", "submissionRelease", "finalRequest"]) test(`RC27F live PG F-9: HD genesis ${stage} recovers its root membership and records across fresh pools`, { skip }, async () => {
  const x = await fresh(hdBase), out = x.q.build.frozen.outputs[x.q.build.vaultOutputIndex], a = fx.spkAddress(x.config, out.scriptPublicKey);
  x.rpc.seed(a, fx.utxo(a, x.q.txId, x.q.build.vaultOutputIndex, out.value, x.q.build.covenantId));
  x.submit = () => hd.submitHdWalletRequest({ config: x.config, requestId: x.q.requestId, rpc: x.rpc });
  const cases = { root: ["write", (c, k, v) => c === C.ORG_ROOT && v.vaults.includes(x.q.vaultId)], receipt: ["write", (c, k) => c === C.RECEIPT && k === x.q.txId], audit: ["appendAudit", (e) => e.txId === x.q.txId], submissionRelease: ["remove", (c, k) => c === C.SUBMISSION_CLAIM && k === x.q.txId], finalRequest: ["write", (c, k, v) => c === C.REQUEST && k === x.q.requestId && v.state === "CHAIN_VERIFIED"] };
  const [method, predicate] = cases[stage], fault = fx.inject(x.config, method, predicate);
  await assert.rejects(x.submit()); assert.equal(fault.count(), 1); fault.restore(); await x.reopen();
  await x.submit(); await x.submit();
  assert.equal((await hd.loadHdWalletRequest(x.config, x.q.requestId)).state, "CHAIN_VERIFIED");
  assert.equal((await wr.loadOrgRoot(x.config, x.o.rootCovenantId)).vaults.filter((id) => id === x.q.vaultId).length, 1);
  assert.equal(await fx.loadSubmissionClaim(x.config, x.q.txId), null); assert.equal((await fx.auditLinesFor(x.config, x.q.txId)).length, 1); assert.equal(x.rpc.submits(), 1);
});
