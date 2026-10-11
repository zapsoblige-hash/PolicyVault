"use strict";
/*
 * RC45 T5 — DIRECT OWNER ACTIONS: ADOPTION AND HISTORICAL TERMINATED_UNKNOWN
 * (fix item F5 RC45-L5-VERIFY-SETTLEMENT; plan rc45-simplified-plan-r2 §1 O3,
 * §2.2 steps 4, 6, 8, 10, 11 with lastRecordedLive and restore, §2.5(1) and
 * (4), §8 T5 (the adoption and restore legs; the pasted-recover legs are F6's),
 * §8.2 sabotage f/g/p/r) and, for step 8's candidate rule, plan amendment
 * PA-01 revision 1 (fix item F5a; rules 1-5, its Tests section, sabotage f').
 * Internal RED-first regression material for the RC45 candidate; not an audit.
 *
 * RED on C1 e62b1973 (Verify writes TERMINATED_UNKNOWN whenever the recorded
 * outpoint is gone without a proven claimed effect, answers TERMINAL for a
 * TERMINATED_UNKNOWN vault without reading the chain, and refuses on any
 * vault-wide PENDING record first). GREEN after F5:
 *   - adoption (step 8): S = the recorded state; a single candidate Y at
 *     address(S) or address(pauseSuccessorV4(S)) with the vault's covenant id,
 *     value pv+fr, Y != L and Y != lastTransition.oldOutpoint, observed at
 *     depth >= D (CLAIM_PENDING below), is adopted: live = Y, status by
 *     paused, lastTransition {ownerPause|ownerUnpause, Y.txid, oldStateId,
 *     newStateId, oldOutpoint: L, newOutpoint: Y}, audit reconciled_advanced
 *     {via: "adopted"}; it settles NO losers (a PENDING delegate record on L
 *     stays byte-identical); pause, unpause and pause->unpause are adopted;
 *   - C-bound decoys answer CHAIN_CONTRADICTION with no write (PA-01 rule 4):
 *     the vault's covenant id with a wrong value, Y = the recorded old
 *     outpoint, Y's txid the creation txid or a recorded request txid, more
 *     than one C-bound candidate across both addresses;
 * RED on F5 fd78f9f (step 8 counts every output at the two addresses as a
 * candidate: a lone output without the vault's covenant id answers
 * CHAIN_CONTRADICTION, one beside a valid Y makes two candidates, and a null
 * base covenant id matches a covenant-less output). GREEN after F5a (PA-01 r1):
 *   - a candidate is only an unspent output at the two addresses whose
 *     covenant id equals base.covenantId, which must be a canonical 32-byte
 *     lowercase hex string (otherwise there are no candidates; rule 1);
 *     outputs with no covenant id or a foreign one are IGNORED (rule 2): alone
 *     they leave the answer to steps 9-11 (UNKNOWN, nothing written; a pasted
 *     valid recover of L still settles RECOVERED once step 9, F6, exists;
 *     rule 5), beside a valid C-bound Y (at Y's address or the other one) Y
 *     is adopted and they change nothing;
 *   - L itself observed with a mismatching covenant id is no ignored output
 *     (rule 3): CHAIN_CONTRADICTION, nothing written (holds on F5);
 *   - historical TERMINATED_UNKNOWN (RC44 case E): base = lastRecordedLive
 *     (from the lastTransition's request W1); the recorded outpoint observed at
 *     depth >= D restores the vault (one manifest write + reconciled_advanced
 *     {via: "restored"}), CLAIM_PENDING{depth, required} below; the recorded
 *     old outpoint live again -> CHAIN_CONTRADICTION; a failed read -> 422;
 *     nothing observed -> UNKNOWN; no lastTransition and no genesis record ->
 *     UNKNOWN{reason: "no recorded live state"} before any node call; never a
 *     TERMINATED_UNKNOWN write.
 *
 * Layers: SDK. Real v0.4.1 compiler, pv_call_encoder, TEST-key signatures
 * (deterministic dev signer) and pv_vm_preflight for every consensus byte: the
 * out-of-app owner Pause / Unpause transactions are real TEST-key signed
 * transactions built in a side root of the same vault (their request records
 * never reach the tested root, so their txids are unknown to it). Node
 * observations come ONLY from the explicit chain model of
 * sdk/testutil/rc45-f5-kit.js; every config names ws://127.0.0.1:1.
 * Outputs WITHOUT the vault's covenant id at the vault's two addresses are
 * REALISTIC, never synthetic: anyone can pay a covenant-less output to either
 * address, and a covenant the payer controls can bind an output there to its
 * own (foreign) covenant id (PA-01). SYNTHETIC decoys: C-bound UTXOs a real
 * chain cannot hold (C is unforgeable and single-lineage: the vault's
 * covenant id with a wrong value, at a known txid or at the recorded old
 * outpoint, a second C-bound candidate) and L itself carrying another
 * covenant id, modelled as an inconsistent indexer view. The pasted recover
 * (the ignored-output-plus-paste legs) is a real TEST-key signed Close &
 * recover of L, hosted-built and finalized in a side root (its record never
 * reaches the tested root), pasted as Safe JSON (sdk/testutil/rc45-f6-kit.js
 * safeJsonOf). SYNTHETIC base (the rule 1 leg): the loader canonicalizes
 * live.covenantId, so a base without a valid covenant id is presented to the
 * real pass through a load-time loadManifestV4 seam in a fresh Verify child
 * (sdk/testutil/rc45-f5a-kit.js).
 *
 * RC44-written shapes (CR-M13): the TERMINATED_UNKNOWN vaults (tuW with a
 * lastTransition, tuG without) come from the pinned df5b8de writers in
 * POLICYVAULT_TEST_RC44_TREE (sdk/testutil/rc45-f5-rc44-history.js; a missing
 * or mismatched tree FAILS, never skips).
 *
 * Both stores: JSON always; PostgreSQL with POLICYVAULT_TEST_PG_{PORT,USER,
 * DATABASE} (the rc45 runner's pg mode; a skipped PostgreSQL leg there is a
 * FAIL). TEST keys only; no production data, credentials or endpoints.
 */
const path = require("node:path");
const assert = require("node:assert/strict");
const { test, before, after } = require("node:test");
const K = require("../testutil/rc45-f5-kit");
const H5 = require("../testutil/rc45-f5-rc44-history");
const F6 = require("../testutil/rc45-f6-kit");
const F5A = require("../testutil/rc45-f5a-kit");
const { LOOPBACK, SETTLE_DEPTH_DAA, frozenOf } = K;

const cand = K.modulesOf(path.join(__dirname, "..", "src"));
const { Categories } = cand.store;
const TOOLCHAIN = require("../testutil/org-root-durable-fixture").toolchainAvailable();
const PG = K.pgFromEnv();
const PG_AVAILABLE = Boolean(PG.port && PG.user && PG.database);
const V = Object.freeze({ ad: K.vault("t5-ad"), adP: K.vault("t5-adP"), adD: K.vault("t5-adD"), adH: K.vault("t5-adH"), rc: K.vault("t5-rc"), tuW: H5.F5_RC44_VAULTS.tuW, tuG: H5.F5_RC44_VAULTS.tuG });
const roots = [], stores = [], databases = [];
let admin = null, serial = 0, history = null, H = null, B = null, w = null, templateRoot = null;
const mk = (prefix) => { const dir = K.ownedTempRoot(prefix); roots.push(dir); return dir; };
const track = (root) => roots.push(root);

async function rejection(promise, message) {
  let caught = null;
  await assert.rejects(promise, (e) => { caught = e; return true; }, message);
  return caught;
}
async function resolved(fn, message) {
  let value;
  await assert.doesNotReject(async () => { value = await fn(); }, message);
  return value;
}
/* A signed transaction the owner makes OUTSIDE PolicyVault: built, TEST-key signed and VM-preflighted in a side root. */
const outOfApp = (r) => ({ txId: r.txId, frozen: frozenOf(r), successorStateId: r.successorStateId, predecessorStateId: r.predecessorStateId, scriptSha256: r.build.successorScriptSha256, action: r.sdkAction });

before(async () => {
  assert.ok(TOOLCHAIN, "real compiler, encoder and VM are required (a missing VM toolchain is a FAIL, never a SKIP)");
  const rc44 = H5.runF5Rc44Scenario("t5", { track });
  H = rc44.result.hist;
  const template = cand.config.loadConfig({ dataRoot: mk("pv-rc45-f5-t5-template-"), rpcUrl: LOOPBACK });
  await K.install(cand, template, await K.snapshot(cand, cand.config.loadConfig({ dataRoot: rc44.dataRoot, rpcUrl: LOOPBACK })));
  w = K.walletsFor(template);
  const k = K.kitFor(cand, template, w), sides = [];
  const side = async (v, seedOptions = {}) => {
    const config = cand.config.loadConfig({ dataRoot: mk("pv-rc45-f5-t5-side-"), rpcUrl: LOOPBACK });
    await K.seedVault(cand, config, v, w, seedOptions);
    sides.push(config.dataRoot);
    return { config, k: K.kitFor(cand, config, w) };
  };
  B = {};
  { // ad: ACTIVE S at L0. Side root: the owner's Pause P (fuel2) lands; then the owner's Unpause U (fuel3) from P's output.
    const v = V.ad; await K.seedVault(cand, template, v, w);
    const s = await side(v);
    const p = await s.k.finalize(await s.k.ownerOp(v, "ownerPause", "fuel2"), w.owner);
    const model = K.chainModel(s.config); model.know(p); model.seedInputs(frozenOf(p), p.covenantId); model.confirmOnSubmit = true;
    const done = await cand.submit4.submitWalletRequestV4({ config: s.config, requestId: p.requestId, rpc: model.rpc, pollAttempts: 1, pollDelayMs: 0 });
    assert.equal(done.request.state, "CHAIN_VERIFIED", "the side root advanced to the paused state");
    const u = await s.k.finalize(await s.k.ownerOp(v, "ownerUnpause", "fuel3"), w.owner);
    assert.deepEqual(frozenOf(u).inputs[0].previousOutpoint, { transactionId: p.txId, index: 0 }, "the Unpause spends the Pause's covenant output");
    B.ad = { p: outOfApp(p), u: outOfApp(u), stateId: (await cand.manifest4.loadManifestV4(template, v.vaultId)).live.stateId };
  }
  { // adP: PAUSED S at L0. Side root: the owner's Unpause (fuel2).
    const v = V.adP; await K.seedVault(cand, template, v, w, { paused: true });
    const s = await side(v, { paused: true });
    B.adP = { u: outOfApp(await s.k.finalize(await s.k.ownerOp(v, "ownerUnpause", "fuel2"), w.owner)) };
  }
  { // adD: ACTIVE S at L0 with a delegate spend D finalized (PENDING, holding the claim). Side root (without D): the owner's Pause.
    const v = V.adD; await K.seedVault(cand, template, v, w);
    const d = await k.finalize(await k.agentSpend(v, 4), w.agent); assert.equal(d.state, "PREFLIGHT_VERIFIED");
    const s = await side(v);
    B.adD = { d: d.requestId, p: outOfApp(await s.k.finalize(await s.k.ownerOp(v, "ownerPause", "fuel2"), w.owner)) };
  }
  { // adH: a hosted Pause P1 completed L0 -> P1:0 (uncontested non-terminal, zero depth); lastTransition.oldOutpoint = L0.
    const v = V.adH; await K.seedVault(cand, template, v, w);
    const p1 = await k.finalize(await k.ownerOp(v, "ownerPause"), w.owner);
    const model = K.chainModel(template); model.know(p1); model.seedInputs(frozenOf(p1), p1.covenantId); model.confirmOnSubmit = true;
    const done = await cand.submit4.submitWalletRequestV4({ config: template, requestId: p1.requestId, rpc: model.rpc, pollAttempts: 1, pollDelayMs: 0 });
    assert.equal(done.request.state, "CHAIN_VERIFIED");
    B.adH = { p1: p1.requestId, L0spk: frozenOf(p1).inputs[0].utxo.scriptPublicKey, L0: frozenOf(p1).inputs[0].previousOutpoint, value: frozenOf(p1).inputs[0].utxo.amount };
  }
  { // rc (PA-01 rule 5): ACTIVE S at L0. Side root: the owner's Pause, built only (its covenant output script is
    // address(pauseSuccessorV4(S))), and the owner's hosted-built Close & recover of L0 (fuel2), finalized there and
    // broadcast outside PolicyVault; the owner pastes its Safe JSON.
    const v = V.rc; await K.seedVault(cand, template, v, w);
    const s = await side(v);
    const pb = await cand.wr4.loadRequest(s.config, (await s.k.ownerOp(v, "ownerPause", "fuel3")).requestId);
    const x = await s.k.finalize(await s.k.ownerOp(v, "ownerRecover", "fuel2"), w.owner); assert.equal(x.state, "PREFLIGHT_VERIFIED");
    assert.deepEqual(x.predecessorOutpoint, { transactionId: v.out, index: 0 }, "the recover spends the recorded outpoint L0");
    const xf = frozenOf(x);
    B.rc = { here: xf.inputs[0].utxo.scriptPublicKey, flip: frozenOf(pb).outputs[0].scriptPublicKey, value: xf.inputs[0].utxo.amount,
      x: { txId: x.txId, frozen: xf, safe: F6.safeJsonOf(s.config, x.finalTransaction), L: x.predecessorOutpoint, oldStateId: x.predecessorStateId } };
    assert.notEqual(B.rc.here.scriptHex, B.rc.flip.scriptHex, "address(S) and address(pauseSuccessorV4(S)) differ");
  }
  // The side roots' and the RC44-written states, compiled by the candidate compiler, join the template's cache.
  for (const root of sides) K.warmCompileCache(root, template.dataRoot);
  const b = await cand.wr4.loadRequest(template, H.tuW.b.requestId);
  for (const s of [b.build.stateJson, b.build.successorState]) cand.submit4.successorAddressAndScript(template, b.build.template, s, b.contractVersion);
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
  const dataRoot = mk("pv-rc45-f5-t5-case-");
  K.warmCompileCache(templateRoot, dataRoot);
  let config, pgDatabase = null;
  if (backend === "PostgreSQL") {
    pgDatabase = `pv_rc45_f5_t5_${process.pid}_${++serial}`;
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
    rawManifest: (v) => store.read(Categories.VAULT, v.vaultId),
    claimOn: (outpoint) => store.read(Categories.TRANSITION_CLAIM, cand.claims.transitionClaimKey(outpoint)),
    reservationOf: (r) => store.read(Categories.TRANSITION_CLAIM, cand.budget.reservationKey(r)),
    audit: () => store.readAudit({ limit: 5000 }),
    snap: () => K.snapshot(cand, config),
    verify: (v) => cand.reconcile4.reconcileVaultV4(config, v.vaultId, { rpc: model.rpc }),
    paste: (v, outOfAppTransaction) => cand.reconcile4.reconcileVaultV4(config, v.vaultId, { rpc: model.rpc, outOfAppTransaction }),
    receipt: (txId) => store.read(Categories.RECEIPT, txId)
  };
}
async function release(x) {
  if (!x.pgDatabase) return;
  const i = stores.indexOf(x.store);
  if (i >= 0) { stores.splice(i, 1); await x.store.close(); }
}
/* Plan r2 §2.5(1) names the row only as reconciled_advanced {via: "adopted"}; a txId it carries must name Y. */
const adoptedAudit = async (x, txId) => (await x.audit()).filter((e) => e.action === "reconciled_advanced" && e.via === "adopted" && (e.txId === undefined || e.txId === txId));
/* Assert the manifest adopted the out-of-app transaction `y` (its covenant output 0) from L. */
async function assertAdopted(x, v, y, L, { status, action, oldStateId }) {
  const m = await x.rawManifest(v), value = y.frozen.outputs[0].value;
  assert.equal(m.status, status, `status by paused: ${status}`);
  assert.deepEqual(m.live.outpoint, { transactionId: y.txId, index: 0 }, "live = Y");
  assert.equal(m.live.stateId, y.successorStateId); assert.equal(String(m.live.outpointValue), String(value)); assert.equal(m.live.scriptSha256, y.scriptSha256);
  assert.equal(m.live.covenantId, v.cov, "the covenant id is unchanged");
  assert.equal(m.lastTransition.action, action); assert.equal(m.lastTransition.txId, y.txId);
  assert.equal(m.lastTransition.oldStateId, oldStateId); assert.equal(m.lastTransition.newStateId, y.successorStateId);
  assert.deepEqual(m.lastTransition.oldOutpoint, L); assert.deepEqual(m.lastTransition.newOutpoint, { transactionId: y.txId, index: 0 });
  assert.equal((await adoptedAudit(x, y.txId)).length, 1, "one reconciled_advanced {via: \"adopted\"} row");
}

const PG_SKIP = PG_AVAILABLE ? undefined : "REQUIREMENT_NOT_AVAILABLE in this process: isolated PostgreSQL (the rc45 runner's pg mode runs these legs; a skipped PostgreSQL leg there is a FAIL)";
for (const [backend, skip] of [["JSON", undefined], ["PostgreSQL", PG_SKIP]]) {
  const t5 = (name, fn) => test(`RC45 T5 ${backend}: ${name}`, { skip }, async () => { const x = await fresh(backend); try { await fn(x); } finally { await release(x); } });
  const L0 = (v) => ({ transactionId: v.out, index: 0 });

  /* ---------------- adoption (step 8; sabotage p, r) ---------------- */
  t5("adoption of an out-of-app TEST-key Pause: CLAIM_PENDING{depth, required} with zero writes below D; at D the vault is PAUSED at Y with lastTransition ownerPause and one reconciled_advanced {via: adopted}; no request is created; a second Verify writes nothing [RED on C1]", async (x) => {
    const y = B.ad.p;
    x.model.seedInputs(y.frozen, V.ad.cov); x.model.confirm(y.frozen, y.txId); x.model.advance(SETTLE_DEPTH_DAA - 1n);
    const below = await x.snap();
    const pending = await resolved(() => x.verify(V.ad), "Verify below D");
    assert.equal(pending.status, "CLAIM_PENDING", "adoption waits for depth D"); assert.equal(String(pending.required), "1000");
    assert.deepEqual(await x.snap(), below);
    x.model.advance(1n);
    const out = await resolved(() => x.verify(V.ad), "Verify at depth D");
    assert.equal(out.status, "ADVANCED"); assert.equal(out.txId, y.txId);
    await assertAdopted(x, V.ad, y, L0(V.ad), { status: "PAUSED", action: "ownerPause", oldStateId: B.ad.stateId });
    assert.deepEqual((await x.snap()).records[Categories.REQUEST], below.records[Categories.REQUEST], "adoption creates or changes no request record");
    const settled = await x.snap();
    const again = await resolved(() => x.verify(V.ad), "a second Verify");
    assert.equal(again.status, "CONSISTENT"); assert.deepEqual(await x.snap(), settled);
  });
  t5("adoption of an out-of-app Unpause of a PAUSED vault: at D the vault is ACTIVE at Y with lastTransition ownerUnpause [RED on C1]", async (x) => {
    const y = B.adP.u, stateId = (await cand.manifest4.loadManifestV4(x.config, V.adP.vaultId)).live.stateId;
    x.model.seedInputs(y.frozen, V.adP.cov); x.model.confirm(y.frozen, y.txId); x.model.advance(SETTLE_DEPTH_DAA);
    const out = await resolved(() => x.verify(V.adP), "Verify at depth D");
    assert.equal(out.status, "ADVANCED"); assert.equal(out.txId, y.txId);
    await assertAdopted(x, V.adP, y, L0(V.adP), { status: "ACTIVE", action: "ownerUnpause", oldStateId: stateId });
  });
  t5("adoption of an out-of-app Pause -> Unpause (the recorded state S recurs at a new outpoint, read at address(S); sabotage p): CLAIM_PENDING below D; at D the vault is ACTIVE at Y2 [RED on C1]", async (x) => {
    const p = B.ad.p, u = B.ad.u;
    x.model.seedInputs(p.frozen, V.ad.cov); x.model.confirm(p.frozen, p.txId, x.model.virtualDaaScore - 3000n);
    x.model.seedInputs(u.frozen, V.ad.cov); x.model.confirm(u.frozen, u.txId); x.model.advance(SETTLE_DEPTH_DAA - 1n);
    const below = await x.snap();
    const pending = await resolved(() => x.verify(V.ad), "Verify below D");
    assert.equal(pending.status, "CLAIM_PENDING"); assert.deepEqual(await x.snap(), below);
    x.model.advance(1n);
    const out = await resolved(() => x.verify(V.ad), "Verify at depth D");
    assert.equal(out.status, "ADVANCED"); assert.equal(out.txId, u.txId);
    assert.equal(u.successorStateId, B.ad.stateId, "the unpaused state is the recorded S (H-35 recurrence)");
    await assertAdopted(x, V.ad, u, L0(V.ad), { status: "ACTIVE", action: "ownerUnpause", oldStateId: B.ad.stateId });
  });
  t5("adoption settles no losers (CR-M11 r): a PENDING delegate record on L, its claim and its reservation stay byte-identical when the out-of-app Pause is adopted [RED on C1]", async (x) => {
    const d = await x.req(B.adD.d), y = B.adD.p;
    const dBefore = await x.rawRequest(d.requestId), claimBefore = await x.claimOn(d.predecessorOutpoint), reservationBefore = await x.reservationOf(d);
    assert.equal(claimBefore.txId, d.txId);
    x.model.seedInputs(y.frozen, V.adD.cov); x.model.confirm(y.frozen, y.txId); x.model.advance(SETTLE_DEPTH_DAA);
    const out = await resolved(() => x.verify(V.adD), "Verify at depth D");
    assert.equal(out.status, "ADVANCED"); assert.equal(out.txId, y.txId);
    assert.equal((await x.rawManifest(V.adD)).status, "PAUSED");
    assert.deepEqual(await x.rawRequest(d.requestId), dBefore, "the delegate record is untouched (not STALE)");
    assert.deepEqual(await x.claimOn(d.predecessorOutpoint), claimBefore); assert.deepEqual(await x.reservationOf(d), reservationBefore);
    assert.equal((await x.audit()).filter((e) => e.action === "transition_superseded").length, 0);
  });

  /* ---------------- C-bound decoys -> CHAIN_CONTRADICTION, no write (CR-L8; PA-01 rule 4) ---------------- */
  const decoys = [
    ["the vault's covenant id with a wrong value", (x) => { const o = B.ad.p.frozen.outputs[0]; x.model.add({ transactionId: K.hex("t5-decoy-value"), index: 0 }, (BigInt(o.value) - 1n).toString(), o.scriptPublicKey, V.ad.cov, x.model.virtualDaaScore - 2000n); }],
    ["Y's txid is the vault's creation txid", (x) => { const o = B.ad.p.frozen.outputs[0]; x.model.add({ transactionId: V.ad.out, index: 1 }, o.value, o.scriptPublicKey, V.ad.cov, x.model.virtualDaaScore - 2000n); }],
    ["two candidates across both addresses", (x) => {
      const o = B.ad.p.frozen.outputs[0], i0 = B.ad.p.frozen.inputs[0];
      x.model.add({ transactionId: K.hex("t5-decoy-two-a"), index: 0 }, o.value, o.scriptPublicKey, V.ad.cov, x.model.virtualDaaScore - 2000n);
      x.model.add({ transactionId: K.hex("t5-decoy-two-b"), index: 0 }, i0.utxo.amount, i0.utxo.scriptPublicKey, V.ad.cov, x.model.virtualDaaScore - 2000n);
    }]
  ];
  for (const [label, plant] of decoys) {
    t5(`decoy: ${label} -> CHAIN_CONTRADICTION, nothing written [RED on C1]`, async (x) => {
      plant(x); // L is gone; only the decoy sits at the vault's two addresses, deep
      const before = await x.snap();
      const out = await resolved(() => x.verify(V.ad), "Verify answers");
      assert.equal(out.status, "CHAIN_CONTRADICTION");
      assert.deepEqual(await x.snap(), before, "a decoy is never adopted and nothing is written");
    });
  }
  for (const [label, outpointOf] of [["Y is the recorded lastTransition.oldOutpoint", () => B.adH.L0], ["Y's txid is a recorded request txid", async (x) => ({ transactionId: (await x.req(B.adH.p1)).txId, index: 5 })]]) {
    t5(`decoy on a vault with a recorded transition: ${label} -> CHAIN_CONTRADICTION, nothing written [RED on C1]`, async (x) => {
      const m = await x.rawManifest(V.adH);
      assert.equal(m.status, "PAUSED"); assert.deepEqual(m.lastTransition.oldOutpoint, B.adH.L0);
      x.model.add(await outpointOf(x), B.adH.value, B.adH.L0spk, V.adH.cov, x.model.virtualDaaScore - 2000n); // at address(S0) = address(pauseSuccessorV4-flip of the recorded S1)
      const before = await x.snap();
      const out = await resolved(() => x.verify(V.adH), "Verify answers");
      assert.equal(out.status, "CHAIN_CONTRADICTION");
      assert.deepEqual(await x.snap(), before);
    });
  }

  /* ---------------- lone ignored outputs -> UNKNOWN, no write (PA-01 rules 2 and 5; sabotage f) ---------------- */
  // Each keeps the full value pv+fr, depth >= D and an unknown txid, so adoption without the covenant-id check
  // (sabotage f) would adopt it (ADVANCED where UNKNOWN is expected).
  const ignored = [
    ["a foreign covenant id at address(pauseSuccessorV4(S))", (x) => { const o = B.ad.p.frozen.outputs[0]; x.model.add({ transactionId: K.hex("t5-decoy-foreign"), index: 0 }, o.value, o.scriptPublicKey, K.hex("t5-foreign-covenant"), x.model.virtualDaaScore - 2000n); }],
    ["a covenant-less output at address(S)", (x) => { const i0 = B.ad.p.frozen.inputs[0]; x.model.add({ transactionId: K.hex("t5-decoy-plain"), index: 0 }, i0.utxo.amount, i0.utxo.scriptPublicKey, null, x.model.virtualDaaScore - 2000n); }]
  ];
  for (const [label, plant] of ignored) {
    t5(`lone ignored output: ${label} is no candidate and no contradiction -> UNKNOWN, nothing written (PA-01 rules 2 and 5; sabotage f) [RED on F5]`, async (x) => {
      plant(x); // L is gone; only the ignored output sits at the vault's two addresses, deep
      const before = await x.snap();
      const out = await resolved(() => x.verify(V.ad), "Verify answers");
      assert.equal(out.status, "UNKNOWN", "an output without the vault's covenant id is ignored: steps 10-11 answer UNKNOWN");
      assert.deepEqual(await x.snap(), before, "an ignored output is never adopted and nothing is written");
    });
  }

  /* ---------------- ignored outputs beside a valid C-bound Y -> Y adopted (PA-01 rule 2; sabotage f') ---------------- */
  const IGNORED_KINDS = [["covenant-less", null], ["foreign-covenant", K.hex("t5-foreign-covenant")]];
  const Y_LANDINGS = [
    ["the out-of-app Pause Y at address(pauseSuccessorV4(S))", (x) => {
      const p = B.ad.p;
      x.model.seedInputs(p.frozen, V.ad.cov); x.model.confirm(p.frozen, p.txId);
      return { y: p, status: "PAUSED", action: "ownerPause" };
    }],
    ["the out-of-app Pause -> Unpause Y2 at address(S)", (x) => {
      const p = B.ad.p, u = B.ad.u;
      x.model.seedInputs(p.frozen, V.ad.cov); x.model.confirm(p.frozen, p.txId, x.model.virtualDaaScore - 3000n);
      x.model.seedInputs(u.frozen, V.ad.cov); x.model.confirm(u.frozen, u.txId);
      return { y: u, status: "ACTIVE", action: "ownerUnpause" };
    }]
  ];
  for (const [kind, covenantId] of IGNORED_KINDS) {
    for (const [landing, land] of Y_LANDINGS) {
      t5(`${kind} outputs beside a valid C-bound Y are ignored (PA-01 rule 2; sabotage f'): ${landing} with a ${kind} output at Y's address and one at the other address (full value, deeper than Y, unknown txids) -> ADVANCED, Y adopted, nothing else written; a second Verify writes nothing [RED on F5]`, async (x) => {
        const { y, status, action } = land(x); x.model.advance(SETTLE_DEPTH_DAA);
        const o = y.frozen.outputs[0], deep = x.model.virtualDaaScore - 2000n;
        x.model.add({ transactionId: K.hex(`t5a-beside-${kind}-${action}-same`), index: 0 }, o.value, o.scriptPublicKey, covenantId, deep); // at Y's address
        x.model.add({ transactionId: K.hex(`t5a-beside-${kind}-${action}-other`), index: 0 }, o.value, y.frozen.inputs[0].utxo.scriptPublicKey, covenantId, deep); // at the other address
        const before = await x.snap();
        const out = await resolved(() => x.verify(V.ad), "Verify at depth D");
        assert.equal(out.status, "ADVANCED", `the ${kind} outputs are no candidates and no contradiction (got ${JSON.stringify(out)})`); assert.equal(out.txId, y.txId);
        await assertAdopted(x, V.ad, y, L0(V.ad), { status, action, oldStateId: B.ad.stateId });
        assert.deepEqual((await x.snap()).records[Categories.REQUEST], before.records[Categories.REQUEST], "adoption creates or changes no request record");
        const settled = await x.snap();
        const again = await resolved(() => x.verify(V.ad), "a second Verify");
        assert.equal(again.status, "CONSISTENT"); assert.deepEqual(await x.snap(), settled);
      });
    }
  }

  /* ---------------- ignored outputs beside a pasted valid recover of L -> RECOVERED (PA-01 rule 5; WEB-3; step 9 is F6's) ---------------- */
  for (const [label, covenantId, where] of [["a covenant-less output at address(S)", null, "here"], ["a foreign-covenant output at address(pauseSuccessorV4(S))", K.hex("t5-foreign-covenant"), "flip"]]) {
    t5(`an ignored output beside a pasted valid recover of L (PA-01 rule 5; sabotage f'): ${label} (full value, depth >= D, unknown txid) forces nothing; at D the paste settles the vault RECOVERED [RED on F5; owners F5a and F6]`, async (x) => {
      const p = B.rc.x;
      x.model.confirm(p.frozen, p.txId); x.model.advance(SETTLE_DEPTH_DAA); // X accepted; its outputs at depth D
      x.model.add({ transactionId: K.hex(`t5a-paste-${where}`), index: 0 }, B.rc.value, B.rc[where], covenantId, x.model.virtualDaaScore - 2000n);
      const out = await resolved(() => x.paste(V.rc, p.safe), "Verify with the paste at D");
      assert.equal(out.status, "ADVANCED", `the ignored output is no contradiction and the paste settles the vault (got ${JSON.stringify(out)})`);
      assert.equal(out.to, "RECOVERED"); assert.equal(out.txId, p.txId);
      const m = await x.rawManifest(V.rc);
      assert.equal(m.status, "RECOVERED"); assert.equal(m.live, null); assert.equal(m.latestTransitionTxId, p.txId);
      assert.equal(m.lastTransition.action, "ownerRecover"); assert.equal(m.lastTransition.txId, p.txId);
      assert.equal(m.lastTransition.oldStateId, p.oldStateId); assert.deepEqual(m.lastTransition.oldOutpoint, p.L);
      assert.ok(await x.receipt(p.txId), "a case-B receipt is created for X");
      const audit = await x.audit();
      assert.equal(audit.filter((e) => e.action === "reconciled_recovered" && e.via === "owner-evidence").length, 1, "one reconciled_recovered {via: owner-evidence} row");
      assert.equal(audit.filter((e) => e.via === "adopted").length, 0, "the ignored output is never adopted");
    });
  }

  /* ---------------- a base without a valid covenant id has no candidates (PA-01 rule 1, review R1) ---------------- */
  t5("a base without a valid covenant id (SYNTHETIC: live.covenantId presented as null to the real pass through a load-time loader seam in a fresh Verify child) beside a covenant-less output at address(S) (full value, depth >= D, unknown txid): step 8 has no candidates (a null expected id never matches) -> UNKNOWN, nothing adopted, nothing written (PA-01 rule 1) [RED on F5]", async (x) => {
    const i0 = B.ad.p.frozen.inputs[0];
    x.model.add({ transactionId: K.hex("t5a-r1-plain"), index: 0 }, i0.utxo.amount, i0.utxo.scriptPublicKey, null, x.model.virtualDaaScore - 2000n);
    const before = await x.snap();
    const run = F5A.verifyWithLiveCovenantIdInChild(x, V.ad, null, { pg: PG });
    assert.equal(run.signal, null); assert.equal(run.status, 0, run.stderr); assert.ok(run.result, "the child reported");
    assert.ok(run.result.seam > 0, "the loader seam reached the pass");
    assert.deepEqual(await x.snap(), before, "nothing is written");
    assert.equal(run.result.ok, true, `Verify answers; no adoption is attempted (got ${JSON.stringify(run.result)})`);
    assert.equal(run.result.value.status, "UNKNOWN", "no candidate: steps 10-11 answer UNKNOWN");
  });

  /* ---------------- L itself with a mismatching covenant id is no ignored output (PA-01 rule 3, review I1) ---------------- */
  for (const [label, covenantId] of [["a foreign covenant id", K.hex("t5-foreign-covenant")], ["no covenant id", null]]) {
    t5(`the recorded outpoint L observed at address(S) with ${label} (SYNTHETIC indexer view) is a positive contradiction, never an ignored output -> CHAIN_CONTRADICTION, nothing written (PA-01 rule 3) [HOLDS on F5]`, async (x) => {
      const i0 = B.ad.p.frozen.inputs[0];
      assert.deepEqual(i0.previousOutpoint, L0(V.ad), "the Pause's vault input is the recorded outpoint L");
      x.model.add(L0(V.ad), i0.utxo.amount, i0.utxo.scriptPublicKey, covenantId, x.model.virtualDaaScore - 2000n);
      const before = await x.snap();
      const out = await resolved(() => x.verify(V.ad), "Verify answers");
      assert.equal(out.status, "CHAIN_CONTRADICTION", "an observation of L itself is never ignored");
      assert.deepEqual(await x.snap(), before);
    });
  }

  /* ---------------- historical TERMINATED_UNKNOWN (RC44 case E; sabotage g) ---------------- */
  const tuWBase = async (x) => {
    const b = await x.req(H.tuW.b.requestId), m = await x.rawManifest(V.tuW);
    assert.equal(m.status, "TERMINATED_UNKNOWN"); assert.equal(m.live, null); assert.equal(m.lastTransition.txId, b.txId);
    const index = frozenOf(b).outputs.findIndex((o) => o.covenant !== null), out = frozenOf(b).outputs[index];
    return { b, m, index, out, L1: { transactionId: b.txId, index } };
  };
  t5("RC44-written TERMINATED_UNKNOWN is restored from lastRecordedLive: CLAIM_PENDING{depth, required} with zero writes below D; at D one manifest write (ACTIVE, live = the recorded successor) and reconciled_advanced {via: restored}; a second Verify writes nothing [RED on C1]", async (x) => {
    const { b, m, out, L1 } = await tuWBase(x);
    x.model.add(L1, out.value, out.scriptPublicKey, b.covenantId); x.model.advance(SETTLE_DEPTH_DAA - 1n);
    const below = await x.snap();
    const pending = await resolved(() => x.verify(V.tuW), "Verify below D");
    assert.equal(pending.status, "CLAIM_PENDING"); assert.equal(String(pending.depth), "999"); assert.equal(String(pending.required), "1000");
    assert.deepEqual(await x.snap(), below);
    x.model.advance(1n);
    const done = await resolved(() => x.verify(V.tuW), "Verify at depth D");
    assert.ok(["CONSISTENT", "ADVANCED"].includes(done.status), `the restored vault is consistent (got ${done.status})`);
    const r = await x.rawManifest(V.tuW);
    assert.equal(r.status, "ACTIVE"); assert.deepEqual(r.live.outpoint, L1); assert.equal(r.live.stateId, b.successorStateId);
    assert.equal(r.live.scriptSha256, b.build.successorScriptSha256); assert.equal(r.live.covenantId, b.covenantId); assert.equal(String(r.live.outpointValue), String(out.value));
    assert.deepEqual(r.lastTransition, m.lastTransition, "lastTransition is kept"); assert.equal(r.latestTransitionTxId, m.latestTransitionTxId);
    assert.equal((await x.audit()).filter((e) => e.action === "reconciled_advanced" && e.via === "restored").length, 1);
    assert.deepEqual((await x.snap()).records[Categories.REQUEST], below.records[Categories.REQUEST], "restore writes no request");
    const restored = await x.snap();
    const again = await resolved(() => x.verify(V.tuW), "a second Verify");
    assert.equal(again.status, "CONSISTENT"); assert.deepEqual(await x.snap(), restored);
  });
  t5("RC44-written TERMINATED_UNKNOWN whose recorded old outpoint P is live again -> CHAIN_CONTRADICTION, nothing written [RED on C1]", async (x) => {
    const { b } = await tuWBase(x), i0 = frozenOf(b).inputs[0];
    x.model.add(i0.previousOutpoint, i0.utxo.amount, i0.utxo.scriptPublicKey, b.covenantId, x.model.virtualDaaScore - 5000n);
    const before = await x.snap();
    const out = await resolved(() => x.verify(V.tuW), "Verify answers");
    assert.equal(out.status, "CHAIN_CONTRADICTION"); assert.deepEqual(await x.snap(), before);
  });
  t5("RC44-written TERMINATED_UNKNOWN with a failing node read -> 422 (the SDK call rejects), nothing written [RED on C1]", async (x) => {
    await tuWBase(x);
    x.model.failRead = () => true;
    const before = await x.snap();
    await rejection(x.verify(V.tuW), "the chain must be read before a TERMINATED_UNKNOWN vault is answered");
    assert.deepEqual(await x.snap(), before);
  });
  t5("RC44-written TERMINATED_UNKNOWN with nothing observed -> UNKNOWN, nothing written (it stays TERMINATED_UNKNOWN; no new write) [RED on C1]", async (x) => {
    await tuWBase(x);
    const before = await x.snap();
    const out = await resolved(() => x.verify(V.tuW), "Verify answers");
    assert.equal(out.status, "UNKNOWN"); assert.deepEqual(await x.snap(), before);
  });
  t5("RC44-written TERMINATED_UNKNOWN without lastTransition or a genesis record -> UNKNOWN{reason: no recorded live state} before any node call, nothing written (CR-L9, CR2-L4) [RED on C1]", async (x) => {
    const m = await x.rawManifest(V.tuG);
    assert.equal(m.status, "TERMINATED_UNKNOWN"); assert.equal(m.lastTransition, null);
    const before = await x.snap(), calls = x.model.calls.length;
    const out = await resolved(() => x.verify(V.tuG), "Verify answers");
    assert.equal(out.status, "UNKNOWN"); assert.match(String(out.reason), /no recorded live state/);
    assert.deepEqual(await x.snap(), before); assert.equal(x.model.calls.length, calls, "no node call is needed");
  });
}
