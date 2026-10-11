"use strict";
/*
 * RC45 T3 (spam) — CANDIDATE GROUPING, DEDUPE AND THE 64-ADDRESS CAP OF THE
 * VERIFY SETTLEMENT PASS (fix item F5 RC45-L5-VERIFY-SETTLEMENT; plan
 * rc45-simplified-plan-r2 §2.2 step 7 a-d (CR-M6), L-14, §8 T3 "Spam (CR-M11
 * m): winning delegate request built first, then >= 64 addresses of newer
 * optional groups, then the oldest finalized; delegate wins", §8.2 sabotage
 * m). Internal RED-first regression material for the RC45 candidate; not an
 * audit. A separate file from rc45-t3-verify-settlement.test.js only so that
 * the 72 real builds of its base get their own process and watchdog budget.
 *
 * RED on C1 e62b1973 (Verify refuses on the vault-wide PENDING record before
 * reading the chain). GREEN after F5:
 *   - groups = requests on L (any state) by txid; addresses = frozenScriptAddress
 *     of the frozen outputs, deduplicated, no compile;
 *   - MANDATORY groups (a PENDING member, the claim holder, owner break-glass)
 *     are never dropped: the oldest group W, finalized, lands among more than
 *     64 distinct addresses of newer optional groups and completes at D;
 *   - OPTIONAL groups are taken newest first while the distinct addresses stay
 *     <= 64; a landing of a skipped (oldest) optional group is never read and
 *     answers UNKNOWN{reason, unchecked > 0} with no write (L-14); every
 *     address read at most once.
 *
 * Base (candidate-written, real builds): a vault whose agent policy names 73
 * TEST recipients; O (optional, oldest, pays recipient3, unique amount) and W
 * (pays recipient2, unique amount) are built first, then 70 newer optional
 * spends of one amount to 70 distinct TEST recipients (one shared successor
 * address + 70 distinct recipient addresses = 71 > 64), then W is finalized
 * (PREFLIGHT_VERIFIED, the claim holder). O's and W's addresses are disjoint
 * from every optional group's.
 *
 * Layers: SDK. Real v0.4.1 compiler, pv_call_encoder, TEST-key signatures and
 * pv_vm_preflight for every consensus byte; node observations only from the
 * explicit chain model of sdk/testutil/rc45-f5-kit.js (ws://127.0.0.1:1, never
 * dialled). Both stores: JSON always; PostgreSQL with
 * POLICYVAULT_TEST_PG_{PORT,USER,DATABASE} (the rc45 runner's pg mode; a
 * skipped PostgreSQL leg there is a FAIL). TEST keys only.
 */
const path = require("node:path");
const assert = require("node:assert/strict");
const { test, before, after } = require("node:test");
const K = require("../testutil/rc45-f5-kit");
const { KAS, LOOPBACK, SETTLE_DEPTH_DAA, frozenOf } = K;

const cand = K.modulesOf(path.join(__dirname, "..", "src"));
const { Categories } = cand.store;
const TOOLCHAIN = require("../testutil/org-root-durable-fixture").toolchainAvailable();
const PG = K.pgFromEnv();
const PG_AVAILABLE = Boolean(PG.port && PG.user && PG.database);
const V = Object.freeze({ sp: K.vault("t3-sp") });
const OPTIONAL_SPAM = 70; // newer optional groups: one shared successor address + 70 distinct recipient addresses > 64
const roots = [], stores = [], databases = [];
let admin = null, serial = 0, history = null, B = null, templateRoot = null;
const mk = (prefix) => { const dir = K.ownedTempRoot(prefix); roots.push(dir); return dir; };
const successorAddress = (x, r) => x.model.addressOf(frozenOf(r).outputs.find((o) => o.covenant !== null).scriptPublicKey);
const addressesOf = (x, r) => frozenOf(r).outputs.map((o) => x.model.addressOf(o.scriptPublicKey));

async function resolved(fn, message) {
  let value;
  await assert.doesNotReject(async () => { value = await fn(); }, message);
  return value;
}

before(async () => {
  assert.ok(TOOLCHAIN, "real compiler, encoder and VM are required (a missing VM toolchain is a FAIL, never a SKIP)");
  const template = cand.config.loadConfig({ dataRoot: mk("pv-rc45-f5-t3cap-template-"), rpcUrl: LOOPBACK });
  const w = K.walletsFor(template), k = K.kitFor(cand, template, w), id = (r) => r.requestId;
  const spam = K.spamRecipients(template, OPTIONAL_SPAM);
  const v = V.sp; await K.seedVault(cand, template, v, w, { recipients: [w.recipient, w.recipient2, w.recipient3, ...spam], periodBudgetKas: 1000n, protectedKas: 5000n });
  const o = await k.agentSpendSompi(v, KAS + 1n, w.recipient3); await K.sleep(3);
  const wr = await k.agentSpendSompi(v, KAS + 2n, w.recipient2); await K.sleep(3);
  const optional = [];
  for (let i = 0; i < OPTIONAL_SPAM; i++) { optional.push(id(await k.agentSpendSompi(v, 2n * KAS, spam[i]))); await K.sleep(2); }
  const wf = await k.finalize(wr, w.agent); assert.equal(wf.state, "PREFLIGHT_VERIFIED");
  B = { o: id(o), w: id(wr), optional };
  history = await K.snapshot(cand, template);
  templateRoot = template.dataRoot;
  if (PG_AVAILABLE) admin = new (require("pg").Pool)(PG);
});
after(async () => {
  for (const s of stores) { try { await s.close(); } catch { /* closed */ } }
  if (admin) { for (const db of databases) await admin.query(`DROP DATABASE IF EXISTS ${db} WITH (FORCE)`); await admin.end(); }
  for (const root of roots) K.removeOwnedRoot(root);
});

async function fresh(backend) {
  const dataRoot = mk("pv-rc45-f5-t3cap-case-");
  K.warmCompileCache(templateRoot, dataRoot);
  let config, pgDatabase = null;
  if (backend === "PostgreSQL") {
    pgDatabase = `pv_rc45_f5_t3cap_${process.pid}_${++serial}`;
    await admin.query(`CREATE DATABASE ${pgDatabase}`); databases.push(pgDatabase);
    config = cand.config.loadConfig({ persistenceBackend: "postgres", pgHost: PG.host, pgPort: PG.port, pgUser: PG.user, pgDatabase, pgNoTls: true, hostedDevOpen: true, dataRoot, rpcUrl: LOOPBACK });
    stores.push(await cand.store.openPgStore(config, { migrate: true }));
    assert.equal(cand.store.getStore(config).kind, "postgres");
  } else config = cand.config.loadConfig({ dataRoot, rpcUrl: LOOPBACK });
  await K.install(cand, config, history);
  const store = cand.store.getStore(config), model = K.chainModel(config);
  return {
    config, store, model, pgDatabase,
    req: (requestId) => cand.wr4.loadRequest(config, requestId),
    rawRequest: (requestId) => store.read(Categories.REQUEST, requestId),
    snap: () => K.snapshot(cand, config),
    verify: (v) => cand.reconcile4.reconcileVaultV4(config, v.vaultId, { rpc: model.rpc })
  };
}
async function release(x) {
  if (!x.pgDatabase) return;
  const i = stores.indexOf(x.store);
  if (i >= 0) { stores.splice(i, 1); await x.store.close(); }
}

const PG_SKIP = PG_AVAILABLE ? undefined : "REQUIREMENT_NOT_AVAILABLE in this process: isolated PostgreSQL (the rc45 runner's pg mode runs these legs; a skipped PostgreSQL leg there is a FAIL)";
for (const [backend, skip] of [["JSON", undefined], ["PostgreSQL", PG_SKIP]]) {
  const t3 = (name, fn) => test(`RC45 T3 ${backend}: ${name}`, { skip }, async () => { const x = await fresh(backend); try { await fn(x); } finally { await release(x); } });

  t3(`cap never drops a MANDATORY group (sabotage m): the oldest finalized W, older than ${OPTIONAL_SPAM} optional groups spanning more than 64 distinct addresses, lands and completes at D [RED on C1]`, async (x) => {
    const wr = await x.req(B.w), optional = await Promise.all(B.optional.map((r) => x.req(r)));
    assert.equal(wr.state, "PREFLIGHT_VERIFIED");
    const optionalAddresses = new Set(optional.flatMap((r) => addressesOf(x, r)));
    assert.ok(optionalAddresses.size > 64, `the optional groups span more than 64 distinct addresses (${optionalAddresses.size})`);
    assert.equal(addressesOf(x, wr).some((a) => optionalAddresses.has(a)), false, "W's addresses are disjoint from the optional groups'");
    x.model.confirm(frozenOf(wr), wr.txId); x.model.advance(SETTLE_DEPTH_DAA);
    const from = x.model.reads.length;
    const done = await resolved(() => x.verify(V.sp), "Verify at depth D");
    assert.equal(done.status, "ADVANCED"); assert.equal(done.txId, wr.txId); assert.equal(done.requestId, wr.requestId);
    assert.equal((await x.rawRequest(wr.requestId)).state, "CHAIN_VERIFIED");
    assert.ok(x.model.readAddresses(from).includes(successorAddress(x, wr)), "the mandatory group's successor address was read");
    for (const r of optional) assert.equal((await x.rawRequest(r.requestId)).state, "BUILT", "optional BUILT groups are not losers");
  });
  t3("cap skips the oldest OPTIONAL group: its landing beyond 64 distinct addresses is never read -> UNKNOWN{unchecked > 0} with no write (L-14); at most 64 distinct optional addresses are read, each once [RED on C1]", async (x) => {
    const o = await x.req(B.o), optional = await Promise.all(B.optional.map((r) => x.req(r)));
    const optionalAddresses = new Set(optional.flatMap((r) => addressesOf(x, r)));
    assert.equal(addressesOf(x, o).some((a) => optionalAddresses.has(a)), false, "O's addresses are disjoint from the optional groups'");
    x.model.confirm(frozenOf(o), o.txId); x.model.advance(SETTLE_DEPTH_DAA);
    const before = await x.snap(), from = x.model.reads.length;
    const out = await resolved(() => x.verify(V.sp), "Verify at depth D");
    assert.equal(out.status, "UNKNOWN");
    const unchecked = Array.isArray(out.unchecked) ? out.unchecked.length : Number(out.unchecked);
    assert.ok(unchecked > 0, `UNKNOWN reports the skipped optional groups as unchecked (got ${JSON.stringify(out.unchecked)})`);
    assert.deepEqual(await x.snap(), before, "a skipped landing writes nothing");
    const read = x.model.readAddresses(from);
    for (const address of addressesOf(x, o)) assert.equal(read.includes(address), false, "the skipped oldest optional group is never read");
    const readOptional = read.filter((a) => optionalAddresses.has(a));
    assert.ok(readOptional.length > 0 && new Set(readOptional).size <= 64, `at most 64 distinct optional addresses are read (read ${new Set(readOptional).size})`);
    assert.equal(readOptional.length, new Set(readOptional).size, "addresses are deduplicated (each read once)");
  });
}
