"use strict";
/*
 * RC45 R1-08 — VERIFY STEP 10 EXCLUDES THE RECORDED TRANSITION'S OWN TXID
 * (remediation plan R1 revision 2 §2 R1-08, §4 R1-08; finding F-03 of the
 * independent review rc45-patch-independent-01; plan rc45-simplified-plan-r2
 * §2.2 step 10 (CR2-L6), §2.0 -05 conformance, WEB-3; PA-01 r1). A permanent
 * T5/T7 leg adapted from the review probe review-lead-step10 (lead P3).
 * Internal regression material for the RC45 successor candidate; not an
 * audit.
 *
 * HOLDS ONLY (must pass on dc7552e and after the R1 implementation; nothing
 * here is claimed RED). Step 10 reads the requests ON the recorded old
 * outpoint L0 = lastTransition.oldOutpoint with step 7's grouping, EXCLUDING
 * the recorded transition W1's own txid (reconcile-v4.js ancestorContradiction,
 * candidateGroups(..., { exceptTxId: t.txId })). W1's other outputs (the owner's
 * fuel change of a Pause, the recipient payment of a delegate spend) normally
 * stay unspent after W1 completed L0 -> L1; without the exclusion they would be
 * "another recorded transaction SEEN spending L0" and an ordinary out-of-app
 * spend of L1 would answer CHAIN_CONTRADICTION instead of UNKNOWN, hiding
 * WEB-3 (offered on UNKNOWN only). Legs:
 *   - review probe P3: W1 = the owner's hosted Pause completed by submit
 *     (uncontested, zero depth); its fuel-change output stays unspent; L1 is
 *     spent by an unknown transaction -> UNKNOWN{unchecked: 0}, nothing
 *     written;
 *   - W1 = a delegate spend completed by submit; its recipient output (the
 *     recipient class, read last) stays unspent -> UNKNOWN, nothing written;
 *   - W1 = the owner's Pause completed by Verify itself at depth D (step 7
 *     completePositive writes the lastTransition) -> after an out-of-app
 *     spend of L1 the next Verify answers UNKNOWN, nothing written;
 *   - sensitivity control: another recorded request N on L0 (BUILT, another
 *     txid; the owner's Pause W1 on L0 is therefore contested and completed by
 *     Verify at D) observed on chain is still a contradiction ->
 *     CHAIN_CONTRADICTION, nothing written (the exclusion removes W1's own
 *     txid only).
 * Sabotage row (plan R1-08): reconcile-v4.js step 10 `exceptTxId` set to null
 * must fail the first three legs (CHAIN_CONTRADICTION); the control stays
 * green.
 *
 * Layers: SDK. Real v0.4.1 compiler, pv_call_encoder, TEST-key signatures
 * (deterministic dev signer) and pv_vm_preflight for every consensus byte (the
 * candidate builders and finalize of sdk/testutil/rc45-f5-kit.js). Node
 * observations come ONLY from the explicit chain model of that kit passed as
 * `rpc`; every config names ws://127.0.0.1:1; nothing dials a node.
 *
 * Both stores: JSON always; PostgreSQL with POLICYVAULT_TEST_PG_{PORT,USER,
 * DATABASE} (the rc45 runner's pg mode; a skipped PostgreSQL leg there is a
 * FAIL). TEST keys only; no production data, credentials or endpoints.
 */
const path = require("node:path");
const assert = require("node:assert/strict");
const { test, before, after } = require("node:test");
const K = require("../testutil/rc45-f5-kit");
const { LOOPBACK, SETTLE_DEPTH_DAA, frozenOf } = K;

const cand = K.modulesOf(path.join(__dirname, "..", "src"));
const { Categories } = cand.store;
const TOOLCHAIN = require("../testutil/org-root-durable-fixture").toolchainAvailable();
const PG = K.pgFromEnv();
const PG_AVAILABLE = Boolean(PG.port && PG.user && PG.database);
const V = Object.freeze({ ps: K.vault("r108-ps"), as: K.vault("r108-as"), vc: K.vault("r108-vc"), cn: K.vault("r108-cn") });
const roots = [], stores = [], databases = [];
let admin = null, serial = 0, history = null, B = null, w = null, templateRoot = null;
const mk = (prefix) => { const dir = K.ownedTempRoot(prefix); roots.push(dir); return dir; };

async function resolved(fn, message) {
  let value;
  await assert.doesNotReject(async () => { value = await fn(); }, message);
  return value;
}
/* W1's covenant successor output L1 and its other (non-covenant) output indexes. */
function outputsOf(r) {
  const frozen = frozenOf(r), index = frozen.outputs.findIndex((o) => o.covenant !== null);
  return { L1: { transactionId: r.txId, index }, others: frozen.outputs.map((_o, i) => i).filter((i) => i !== index), L0: frozen.inputs[0].previousOutpoint };
}
/* W1 submitted through the candidate submit with the explicit chain model (confirmOnSubmit). An uncontested W1
 * completes at submit (zero depth); a contested one (another request ON L0) answers SUBMITTED and is completed by the
 * candidate Verify at depth D (step 7 completePositive). Returns the model's serialized state. */
async function submitted(config, r, { contested = false } = {}) {
  const model = K.chainModel(config);
  model.know(r); model.seedInputs(frozenOf(r), r.covenantId); model.confirmOnSubmit = true;
  const done = await cand.submit4.submitWalletRequestV4({ config, requestId: r.requestId, rpc: model.rpc, pollAttempts: 1, pollDelayMs: 0 });
  if (!contested) {
    assert.equal(done.request.state, "CHAIN_VERIFIED", `${r.sdkAction} completes at submit (uncontested, zero depth)`);
    return model.serialize();
  }
  assert.equal(done.request.state, "SUBMITTED", `the contested ${r.sdkAction} returns at SUBMITTED`);
  model.confirmOnSubmit = false; model.advance(SETTLE_DEPTH_DAA);
  const out = await cand.reconcile4.reconcileVaultV4(config, r.vaultId, { rpc: model.rpc });
  assert.equal(out.status, "ADVANCED", `Verify completes the contested ${r.sdkAction} at D (got ${JSON.stringify(out)})`); assert.equal(out.txId, r.txId);
  assert.equal((await cand.wr4.loadRequest(config, r.requestId)).state, "CHAIN_VERIFIED");
  return model.serialize();
}

before(async () => {
  assert.ok(TOOLCHAIN, "real compiler, encoder and VM are required (a missing VM toolchain is a FAIL, never a SKIP)");
  const template = cand.config.loadConfig({ dataRoot: mk("pv-rc45-r108-template-"), rpcUrl: LOOPBACK });
  w = K.walletsFor(template);
  const k = K.kitFor(cand, template, w);
  B = {};
  { // ps (review probe P3): the owner's hosted Pause W1 completed L0 -> L1 by submit; its fuel change stays unspent.
    const v = V.ps; await K.seedVault(cand, template, v, w);
    const q = await k.finalize(await k.ownerOp(v, "ownerPause"), w.owner); assert.equal(q.state, "PREFLIGHT_VERIFIED");
    B.ps = { w1: q.requestId, txId: q.txId, ...outputsOf(q), model: await submitted(template, q) };
  }
  { // as: a delegate spend W1 completed L0 -> L1 by submit; its recipient payment stays unspent.
    const v = V.as; await K.seedVault(cand, template, v, w);
    const a = await k.finalize(await k.agentSpend(v, 4), w.agent); assert.equal(a.state, "PREFLIGHT_VERIFIED");
    B.as = { w1: a.requestId, txId: a.txId, ...outputsOf(a), model: await submitted(template, a) };
  }
  { // vc: the owner's hosted Pause W1 finalized (PENDING, holding the claim on L0); each case lands it on the model and
    // lets Verify complete it at depth D (step 7 completePositive writes the manifest's lastTransition).
    const v = V.vc; await K.seedVault(cand, template, v, w);
    const q = await k.finalize(await k.ownerOp(v, "ownerPause"), w.owner); assert.equal(q.state, "PREFLIGHT_VERIFIED");
    B.vc = { w1: q.requestId, txId: q.txId, frozen: frozenOf(q), ...outputsOf(q) };
  }
  { // cn: a delegate spend N built on L0 (BUILT, never signed here); the owner's hosted Pause W1 on L0 is then contested:
    // submitted (SUBMITTED) and completed by the candidate Verify at depth D.
    const v = V.cn; await K.seedVault(cand, template, v, w);
    const n = await k.agentSpend(v, 1); assert.equal(n.state, "BUILT"); await K.sleep(3);
    const q = await k.finalize(await k.ownerOp(v, "ownerPause"), w.owner); assert.equal(q.state, "PREFLIGHT_VERIFIED");
    const model = await submitted(template, q, { contested: true });
    const nr = await cand.wr4.loadRequest(template, n.requestId);
    assert.notEqual(nr.txId, q.txId); assert.deepEqual(nr.predecessorOutpoint, q.predecessorOutpoint, "N is ON the recorded old outpoint L0");
    B.cn = { w1: q.requestId, txId: q.txId, ...outputsOf(q), model, n: n.requestId, nTxId: nr.txId, nFrozen: frozenOf(nr) };
  }
  // Warm the template's compile cache with the states step 8 compiles (address(S1), address(pauseSuccessorV4(S1))):
  // one Verify per vault on a throwaway model with L1 spent, asserted to write nothing.
  for (const [v, b] of [[V.ps, B.ps], [V.as, B.as], [V.cn, B.cn]]) {
    const before = await K.snapshot(cand, template), model = K.chainModel(template, b.model);
    model.remove(b.L1);
    await cand.reconcile4.reconcileVaultV4(template, v.vaultId, { rpc: model.rpc });
    assert.deepEqual(await K.snapshot(cand, template), before, "the warm-up Verify writes nothing");
  }
  history = await K.snapshot(cand, template);
  templateRoot = template.dataRoot;
  if (PG_AVAILABLE) admin = new (require("pg").Pool)(PG);
});
after(async () => {
  for (const s of stores) { try { await s.close(); } catch { /* closed */ } }
  if (admin) { for (const db of databases) await admin.query(`DROP DATABASE IF EXISTS ${db} WITH (FORCE)`); await admin.end(); }
  for (const root of roots) K.removeOwnedRoot(root);
});

async function fresh(backend, init = null) {
  const dataRoot = mk("pv-rc45-r108-case-");
  K.warmCompileCache(templateRoot, dataRoot);
  let config, pgDatabase = null;
  if (backend === "PostgreSQL") {
    pgDatabase = `pv_rc45_r108_${process.pid}_${++serial}`;
    await admin.query(`CREATE DATABASE ${pgDatabase}`); databases.push(pgDatabase);
    config = cand.config.loadConfig({ persistenceBackend: "postgres", pgHost: PG.host, pgPort: PG.port, pgUser: PG.user, pgDatabase, pgNoTls: true, hostedDevOpen: true, dataRoot, rpcUrl: LOOPBACK });
    stores.push(await cand.store.openPgStore(config, { migrate: true }));
    assert.equal(cand.store.getStore(config).kind, "postgres");
  } else config = cand.config.loadConfig({ dataRoot, rpcUrl: LOOPBACK });
  await K.install(cand, config, history);
  const store = cand.store.getStore(config), model = K.chainModel(config, init);
  return {
    config, store, model, pgDatabase,
    rawRequest: (requestId) => store.read(Categories.REQUEST, requestId),
    rawManifest: (v) => store.read(Categories.VAULT, v.vaultId),
    snap: () => K.snapshot(cand, config),
    verify: (v) => cand.reconcile4.reconcileVaultV4(config, v.vaultId, { rpc: model.rpc })
  };
}
async function release(x) {
  if (!x.pgDatabase) return;
  const i = stores.indexOf(x.store);
  if (i >= 0) { stores.splice(i, 1); await x.store.close(); }
}
/* The recorded advancement W1 (L0 -> L1) as the manifest holds it. */
async function assertRecordedAdvancement(x, v, b) {
  const m = await x.rawManifest(v);
  assert.notEqual(m.live, null, "the vault is live");
  assert.deepEqual(m.live.outpoint, b.L1, "the recorded live outpoint is W1's covenant output L1");
  assert.equal(m.lastTransition.txId, b.txId, "lastTransition names W1");
  assert.deepEqual(m.lastTransition.oldOutpoint, b.L0, "lastTransition.oldOutpoint is L0");
  assert.equal((await x.rawRequest(b.w1)).state, "CHAIN_VERIFIED", "W1 is CHAIN_VERIFIED");
}
/* Step 10 with W1's other outputs unspent and L1 spent outside PolicyVault: UNKNOWN, nothing written. */
async function assertOwnTxidExcluded(x, v, b, label) {
  assert.ok(b.others.length >= 1, `${label}: W1 has a non-covenant output`);
  for (const i of b.others) assert.ok(x.model.has({ transactionId: b.txId, index: i }), `${label}: W1's output ${i} stays unspent (observed on the model)`);
  assert.ok(x.model.has(b.L1), `${label}: L1 is observed before the out-of-app spend`);
  x.model.remove(b.L1); // L1 spent by an unknown, out-of-app transaction (its successor is nowhere PolicyVault reads)
  const before = await x.snap();
  const out = await resolved(() => x.verify(v), `${label}: Verify`);
  assert.equal(out.status, "UNKNOWN", `${label}: W1's own still-unspent outputs are not another recorded spender of L0; the answer is UNKNOWN (WEB-3 stays available), never CHAIN_CONTRADICTION (got ${JSON.stringify(out)})`);
  assert.equal(out.unchecked, 0, `${label}: W1's own group is excluded, not skipped (unchecked 0)`);
  assert.deepEqual(await x.snap(), before, `${label}: nothing is written (no TERMINATED_UNKNOWN, no relabel, no audit)`);
}

const PG_SKIP = PG_AVAILABLE ? undefined : "REQUIREMENT_NOT_AVAILABLE in this process: isolated PostgreSQL (the rc45 runner's pg mode runs these legs; a skipped PostgreSQL leg there is a FAIL)";
for (const [backend, skip] of [["JSON", undefined], ["PostgreSQL", PG_SKIP]]) {
  const r108 = (name, init, fn) => test(`RC45 R1-08 ${backend}: ${name}`, { skip }, async () => { const x = await fresh(backend, init()); try { await fn(x); } finally { await release(x); } });

  r108("review probe P3 (T5 step 10): after the owner's hosted Pause W1 completed L0 -> L1 at submit with its fuel-change output still unspent, an out-of-app spend of L1 answers UNKNOWN{unchecked: 0} (step 10 excludes W1's own txid), nothing written [holds on dc7552e]", () => B.ps.model, async (x) => {
    x.model.advance(SETTLE_DEPTH_DAA + 10n);
    await assertRecordedAdvancement(x, V.ps, B.ps);
    await assertOwnTxidExcluded(x, V.ps, B.ps, "Pause W1, fuel change unspent");
  });
  r108("step 10 own-txid exclusion, recipient class: after a delegate spend W1 completed L0 -> L1 at submit with its recipient payment still unspent, an out-of-app spend of L1 answers UNKNOWN{unchecked: 0}, nothing written [holds on dc7552e]", () => B.as.model, async (x) => {
    x.model.advance(SETTLE_DEPTH_DAA + 10n);
    await assertRecordedAdvancement(x, V.as, B.as);
    await assertOwnTxidExcluded(x, V.as, B.as, "delegate spend W1, recipient output unspent");
  });
  r108("step 10 own-txid exclusion after a Verify completion (T7 path): the owner's Pause W1 lands and Verify completes it at depth D (step 7 completePositive writes lastTransition L0 -> L1); after an out-of-app spend of L1 the next Verify answers UNKNOWN{unchecked: 0} with W1's fuel change unspent, nothing written [holds on dc7552e]", () => null, async (x) => {
    x.model.confirm(B.vc.frozen, B.vc.txId); x.model.advance(SETTLE_DEPTH_DAA);
    const done = await resolved(() => x.verify(V.vc), "Verify completes W1 at D");
    assert.equal(done.status, "ADVANCED", `W1 is completed by Verify (got ${JSON.stringify(done)})`); assert.equal(done.txId, B.vc.txId);
    await assertRecordedAdvancement(x, V.vc, B.vc);
    x.model.advance(10n);
    await assertOwnTxidExcluded(x, V.vc, B.vc, "Verify-completed Pause W1, fuel change unspent");
  });
  r108("sensitivity control: with W1's own outputs unspent and L1 spent out of app, ANOTHER recorded request N on L0 (BUILT, another txid) observed on chain is still a contradiction -> CHAIN_CONTRADICTION, nothing written (the exclusion removes W1's own txid only) [holds on dc7552e]", () => B.cn.model, async (x) => {
    x.model.advance(SETTLE_DEPTH_DAA + 10n);
    await assertRecordedAdvancement(x, V.cn, B.cn);
    assert.equal((await x.rawRequest(B.cn.n)).state, "BUILT", "N stays BUILT");
    for (const i of B.cn.others) assert.ok(x.model.has({ transactionId: B.cn.txId, index: i }), `W1's output ${i} stays unspent`);
    x.model.remove(B.cn.L1);
    x.model.confirm(B.cn.nFrozen, B.cn.nTxId, x.model.virtualDaaScore - SETTLE_DEPTH_DAA); // N's outputs observed (a conflicting spend of L0)
    const before = await x.snap();
    const out = await resolved(() => x.verify(V.cn), "Verify");
    assert.equal(out.status, "CHAIN_CONTRADICTION", `another recorded transaction observed spending L0 is a contradiction (got ${JSON.stringify(out)})`);
    assert.deepEqual(await x.snap(), before, "nothing is written");
  });
}
