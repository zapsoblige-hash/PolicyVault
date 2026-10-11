"use strict";
/*
 * RC45 T5 — OWNER-PASTED RECOVER EVIDENCE (fix item F6
 * RC45-L5-RECOVER-EVIDENCE; plan rc45-simplified-plan-r2 §1 O3 (3), §2.0
 * validateIdentity error rule, §2.2 step 9, §2.5(3), §4 "Recover evidence"
 * row, §7 L-12, §8 T5 (the pasted-recover legs; the adoption and restore legs
 * are F5's, sdk/test/rc45-t5-adoption.test.js), §8.2 sabotage n; CR-M2,
 * CR-L4, CR-I3, CR-I4, CR2-L3). Internal RED-first regression material for
 * the RC45 candidate; not an audit.
 *
 * RED on C1 e62b1973: reconcileVaultV4 ignores `outOfAppTransaction`; with
 * the recorded outpoint L spent and no claimed effect it writes
 * TERMINATED_UNKNOWN (case E), it refuses on any vault-wide PENDING record
 * first (REQUEST_RECOVERY_REQUIRED), and it answers TERMINAL for a
 * TERMINATED_UNKNOWN vault without reading the chain. GREEN after F6 (on F5):
 *   - step 9: the pasted Safe JSON (<= 64 KiB) is parsed by
 *     parseSignedTransactionSafeJson, which recomputes X (the embedded `id`
 *     is never trusted); SOME input spends L (index 0 or 1); outputs[0] pays
 *     20||template.owner||ac exactly pv+fr; NO output carries the covenant
 *     id C; one X:i is observed exactly at depth >= D = 1,000 DAA. Then the
 *     journal-free identity-valid PENDING records exactly on L with another
 *     txid become STALE first (settleLoser against the input equal to L),
 *     the manifest becomes RECOVERED through advanceManifestAndRegistryV4
 *     with case B's synthetic request built from `base` (lastRecordedLive
 *     for a TERMINATED_UNKNOWN vault), a create-only case-B receipt is
 *     written and one audit row reconciled_recovered {via: "owner-evidence"};
 *     any one output of X kept unspent suffices (L-12);
 *   - a mismatch answers UNKNOWN with no write (tampered embedded id, no
 *     input spending L, a V-1 payout, a C-bound output, the consensus-valid
 *     dangerous ownerControl shape, no output observed exactly); below D
 *     nothing is written; the dangerous shape as a Pause never makes the
 *     vault RECOVERED;
 *   - txid-X records are never STALE (CR-M2): an identity-valid one
 *     (PREFLIGHT_VERIFIED, or BUILT) completes or stays unchanged, an
 *     identity-invalid one (a record-shape throw, which excludes only its
 *     record and is no 422, CR2-L3) stays byte-identical;
 *   - an environment error in validateIdentity (VM harness spawn) is a 422
 *     (the SDK call rejects) with no write.
 *
 * Layers: SDK. Real v0.4.1 compiler, pv_call_encoder, TEST-key signatures
 * and pv_vm_preflight for every consensus byte. The pasted transactions are
 * real TEST-key signed transactions made OUTSIDE the tested store: the
 * index-0 recovers are hosted-built and finalized in side roots (their
 * records never reach the tested root); the index-1 recover and the two
 * dangerous ownerControl shapes are built from candidate SDK builds,
 * re-arranged, signed and VM-preflighted on every input by
 * sdk/testutil/rc45-f6-kit.js construct (VM-verified; fee policy not
 * evaluated). SYNTHETIC (labelled below): the V-1 payout and the C-bound
 * output variants (signature scripts kept, so not consensus-valid; the
 * chain model shows them as accepted, an inconsistent indexer view), the
 * foreign UTXO named by the tampered id, the X:0 observed with another value,
 * and the record-shape defect of the identity-invalid same-txid record. The
 * BUILT same-txid record and its out-of-app twin are the same candidate
 * build (same state, fuel and change) in the tested root and a side root. Node observations come ONLY from the
 * explicit chain model of sdk/testutil/rc45-f5-kit.js passed as `rpc`; every
 * config names ws://127.0.0.1:1. The harness-failure legs run the candidate
 * Verify with the paste in a fresh child with POLICYVAULT_PV_VM_PREFLIGHT_PATH
 * on a failing TEST harness.
 *
 * RC44-written shapes (CR-M13): the TERMINATED_UNKNOWN vault tuW comes from
 * the pinned df5b8de writers in POLICYVAULT_TEST_RC44_TREE
 * (sdk/testutil/rc45-f5-rc44-history.js, scenario t5; a missing or
 * mismatched tree FAILS, never skips).
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
const { LOOPBACK, SETTLE_DEPTH_DAA, frozenOf } = K;

const cand = K.modulesOf(path.join(__dirname, "..", "src"));
const { Categories } = cand.store;
const B4 = require("../src/vault-builders-v4");
const TOOLCHAIN = require("../testutil/org-root-durable-fixture").toolchainAvailable();
const PG = K.pgFromEnv();
const PG_AVAILABLE = Boolean(PG.port && PG.user && PG.database);
const PASTE_LIMIT = 64 * 1024;
const V = Object.freeze({
  p0: K.vault("t5r-p0"), p1: K.vault("t5r-p1"), ng: K.vault("t5r-ng"), dz: K.vault("t5r-dz"), st: K.vault("t5r-st"), si: K.vault("t5r-si"),
  sb: K.vault("t5r-sb"), tuW: H5.F5_RC44_VAULTS.tuW
});
const roots = [], stores = [], databases = [];
let admin = null, serial = 0, history = null, H = null, B = null, w = null, templateRoot = null;
const mk = (prefix) => { const dir = K.ownedTempRoot(prefix); roots.push(dir); return dir; };
const track = (root) => roots.push(root);
const sansState = (r) => { const { state, ...rest } = r; void state; return rest; };

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
/* What the owner pastes for a signed recover record made outside the tested store. */
const pasted = (config, r) => ({ txId: r.txId, frozen: frozenOf(r), safe: F6.safeJsonOf(config, r.finalTransaction), payout: String(frozenOf(r).outputs[0].value), L: r.predecessorOutpoint, oldStateId: r.predecessorStateId });

before(async () => {
  assert.ok(TOOLCHAIN, "real compiler, encoder and VM are required (a missing VM toolchain is a FAIL, never a SKIP)");
  const rc44 = H5.runF5Rc44Scenario("t5", { track });
  H = rc44.result.hist;
  const template = cand.config.loadConfig({ dataRoot: mk("pv-rc45-f6-t5-template-"), rpcUrl: LOOPBACK });
  await K.install(cand, template, await K.snapshot(cand, cand.config.loadConfig({ dataRoot: rc44.dataRoot, rpcUrl: LOOPBACK })));
  const store = cand.store.getStore(template);
  w = K.walletsFor(template);
  const k = K.kitFor(cand, template, w), sides = [];
  const sideRoot = () => { const config = cand.config.loadConfig({ dataRoot: mk("pv-rc45-f6-t5-side-"), rpcUrl: LOOPBACK }); K.warmCompileCache(template.dataRoot, config.dataRoot); sides.push(config.dataRoot); return config; };
  const side = async (v, seedOptions = {}) => { const config = sideRoot(); await K.seedVault(cand, config, v, w, seedOptions); return { config, k: K.kitFor(cand, config, w) }; };
  B = {};
  { // p0: a delegate spend D finalized on L (PENDING, holding the claim) and an earlier BUILT spend N. Side root: the owner's
    // hosted-built Close & recover (fuel2), finalized there and broadcast outside PolicyVault (vault input at index 0).
    const v = V.p0; await K.seedVault(cand, template, v, w);
    const n = await k.agentSpend(v, 1); await K.sleep(3);
    const d = await k.finalize(await k.agentSpend(v, 4), w.agent); assert.equal(d.state, "PREFLIGHT_VERIFIED");
    const s = await side(v);
    const x = await s.k.finalize(await s.k.ownerOp(v, "ownerRecover", "fuel2"), w.owner); assert.equal(x.state, "PREFLIGHT_VERIFIED");
    assert.deepEqual(x.predecessorOutpoint, d.predecessorOutpoint, "the recover spends the recorded outpoint L");
    B.p0 = { n: n.requestId, d: d.requestId, x: pasted(s.config, x) };
  }
  { // p1: D finalized on L. Side root: the owner's out-of-app recover with the vault input at INDEX 1 (fuel at index 0),
    // from the candidate build, re-arranged, TEST-key signed and VM-preflighted on both inputs.
    const v = V.p1; await K.seedVault(cand, template, v, w);
    const d = await k.finalize(await k.agentSpend(v, 4), w.agent); assert.equal(d.state, "PREFLIGHT_VERIFIED");
    const s = await side(v);
    const r = await cand.wr4.loadRequest(s.config, (await s.k.ownerOp(v, "ownerRecover", "fuel2")).requestId);
    const d0 = JSON.parse(r.build.frozenCanonicalJson);
    const x = F6.construct(s.config, r.build, { ...d0, inputs: [d0.inputs[1], d0.inputs[0]] }, { covenantInput: 1, fuelInput: 0, secretHex: w.owner.secretHex });
    assert.deepEqual(x.verdict, { valid: true, inputs: 2 }, "the index-1 recover executes valid on the real VM (both inputs)");
    assert.deepEqual(x.frozen.inputs[1].previousOutpoint, d.predecessorOutpoint, "the vault input (index 1) spends L");
    assert.equal(x.frozen.inputs[0].utxo.covenantId, null, "input 0 is the owner's fuel");
    B.p1 = { d: d.requestId, x: { txId: x.txId, frozen: x.frozen, safe: x.safe, payout: String(x.frozen.outputs[0].value), L: r.predecessorOutpoint, oldStateId: r.predecessorStateId } };
  }
  { // ng: a clean vault. X = the owner's hosted-built recover of L (side root, fuel2). R2 = a real recover of the SAME
    // vault state at another outpoint L' (side root, fuel3): input != L. SYNTHETIC variants of X: V-1 payout, C-bound change.
    const v = V.ng; await K.seedVault(cand, template, v, w);
    const s = await side(v);
    const x = await s.k.finalize(await s.k.ownerOp(v, "ownerRecover", "fuel2"), w.owner);
    const other = { ...v, out: K.hex("rc45-f6-t5r-ng-other-outpoint") };
    const s2 = await side(other);
    const r2 = await s2.k.finalize(await s2.k.ownerOp(other, "ownerRecover", "fuel3"), w.owner);
    assert.notDeepEqual(r2.predecessorOutpoint, x.predecessorOutpoint); assert.equal(frozenOf(r2).outputs[0].value, frozenOf(x).outputs[0].value);
    const vMinus = F6.synthetic(s.config, x.finalTransaction, (j) => { j.outputs[0].value = String(BigInt(j.outputs[0].value) - 1n); j.outputs[1].value = String(BigInt(j.outputs[1].value) + 1n); });
    const cBound = F6.synthetic(s.config, x.finalTransaction, (j) => { j.outputs[1].covenant = { authorizingInput: 0, covenantId: v.cov }; });
    const doc = JSON.parse(pasted(s.config, x).safe); doc.id = K.hex("rc45-f6-t5r-ng-tampered-id"); const tampered = JSON.stringify(doc);
    assert.equal(F6.consensusIdOf(s.config, tampered), x.txId, "the engine recomputes X from a document whose embedded id was replaced");
    B.ng = { x: pasted(s.config, x), r2: pasted(s2.config, r2), vMinus, cBound, tampered, tamperedId: doc.id };
  }
  { // dz: a small clean vault (pv+fr = 55 KAS < the 100 KAS fuel). The DANGEROUS ownerControl shape (CR-I3): outputs[0] =
    // P2PK(owner) worth pv+fr paid from fuel, the C successor at index 1, change at index 2; real, VM-verified (both inputs).
    const v = V.dz; await K.seedVault(cand, template, v, w, { protectedKas: 50n });
    const s = await side(v, { protectedKas: 50n });
    const m = await cand.manifest4.loadManifestV4(s.config, v.vaultId);
    B.dz = {};
    for (const [tag, action, params] of [["root", "ownerSetAgentRoot", { newAgentRoot: K.hex("rc45-f6-t5r-dz-new-agent-root") }], ["pause", "ownerPause", {}]]) {
      const build = B4.buildV4Transaction({ config: s.config, contractVersion: m.contractVersion, templateInput: { owner: m.template.owner, vaultId: m.vaultId }, stateInput: cand.vs4.stateToJsonV4(m.live.state), action, params,
        chain: { predecessorOutpoint: m.live.outpoint, covenantId: m.live.covenantId, predecessorValue: m.live.outpointValue, fuel: s.k.fuelOf(v, tag === "root" ? "fuel2" : "fuel3") }, changeXOnly: w.owner.xonly });
      const dj = JSON.parse(build.frozenCanonicalJson), pvfr = BigInt(m.live.outpointValue), fee = 3n * BigInt(build.requiredFeeSompi), fuel = BigInt(dj.inputs[1].utxo.amount);
      const draft = { ...dj, outputs: [{ value: pvfr.toString(), scriptPublicKey: { version: 0, scriptHex: `20${w.owner.xonly}ac` }, covenant: null }, dj.outputs[0], { ...dj.outputs[1], value: (fuel - pvfr - fee).toString() }] };
      const x = F6.construct(s.config, build, draft, { covenantInput: 0, fuelInput: 1, secretHex: w.owner.secretHex });
      assert.deepEqual(x.verdict, { valid: true, inputs: 2 }, `the dangerous ${action} shape executes valid on the real VM (both inputs)`);
      assert.equal(x.frozen.outputs[1].covenant.covenantId, v.cov, "the C successor sits at index 1");
      B.dz[tag] = { txId: x.txId, frozen: x.frozen, safe: x.safe, L: m.live.outpoint };
    }
  }
  for (const tag of ["st", "si"]) { // a delegate spend D and the owner's hosted Close & recover Q on L, finalized apart: D holds the only claim.
    const v = V[tag]; await K.seedVault(cand, template, v, w);
    const d = await k.agentSpend(v, 4); await K.sleep(3);
    const q = await k.ownerOp(v, "ownerRecover");
    await K.finalizeApart(cand, template, [{ requestId: d.requestId, signer: w.agent }, { requestId: q.requestId, signer: w.owner }], { claimHolder: d.requestId, track });
    const qf = await cand.wr4.loadRequest(template, q.requestId);
    assert.equal(qf.state, "PREFLIGHT_VERIFIED");
    B[tag] = { d: d.requestId, q: q.requestId, x: pasted(template, qf) };
  }
  { // sb: the owner's hosted Close & recover Q left BUILT here (never finalized in PolicyVault). Side root: the SAME recover
    // (same state, same fuel, same change) finalized there = the transaction the owner signed and broadcast outside.
    const v = V.sb; await K.seedVault(cand, template, v, w);
    const qb = await k.ownerOp(v, "ownerRecover"); assert.equal(qb.state, "BUILT");
    const s = await side(v);
    const x = await s.k.finalize(await s.k.ownerOp(v, "ownerRecover"), w.owner);
    assert.equal(x.txId, qb.txId, "the same Close & recover with the same fuel is the same transaction (same txid)");
    B.sb = { q: qb.requestId, x: pasted(s.config, x) };
  }
  { // si: SYNTHETIC record-shape defect on the owner's same-txid record (its accounting no longer matches its frozen payout),
    // so validateIdentity throws a record-shape error for it (not an environment error): it excludes only this record.
    const raw = await store.read(Categories.REQUEST, B.si.q);
    raw.build.accounting.terminalPayout = String(BigInt(raw.build.accounting.terminalPayout) - 1n);
    await store.write(Categories.REQUEST, B.si.q, raw);
  }
  { // tuW (RC44-written TERMINATED_UNKNOWN; lastTransition L0 -> L1 by B). Side root live at L1 = lastRecordedLive: the
    // owner's out-of-app recover of L1 (fuel2), hosted-built and finalized there.
    const b = await cand.wr4.loadRequest(template, H.tuW.b.requestId), raw = await store.read(Categories.VAULT, V.tuW.vaultId);
    assert.equal(raw.status, "TERMINATED_UNKNOWN"); assert.equal(raw.lastTransition.txId, b.txId);
    const index = frozenOf(b).outputs.findIndex((o) => o.covenant !== null), out = frozenOf(b).outputs[index], L1 = { transactionId: b.txId, index };
    const config = sideRoot();
    await cand.manifest4.persistManifestV4(config, { ...raw, status: "ACTIVE", live: { state: b.build.successorState, stateId: b.successorStateId, outpoint: L1, outpointValue: String(out.value), scriptSha256: b.build.successorScriptSha256, covenantId: b.covenantId } });
    const sk = K.kitFor(cand, config, w);
    const x = await sk.finalize(await sk.ownerOp(V.tuW, "ownerRecover", "fuel2"), w.owner);
    assert.deepEqual(x.predecessorOutpoint, L1, "the recover spends the recorded successor L1");
    B.tuW = { b: b.requestId, L1, x: pasted(config, x) };
    for (const s of [b.build.stateJson, b.build.successorState]) cand.submit4.successorAddressAndScript(template, b.build.template, s, b.contractVersion);
  }
  for (const root of sides) K.warmCompileCache(root, template.dataRoot);
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
  const dataRoot = mk("pv-rc45-f6-t5-case-");
  K.warmCompileCache(templateRoot, dataRoot);
  let config, pgDatabase = null;
  if (backend === "PostgreSQL") {
    pgDatabase = `pv_rc45_f6_t5_${process.pid}_${++serial}`;
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
    submissionClaim: (txId) => store.read(Categories.SUBMISSION_CLAIM, txId),
    reservationOf: (r) => store.read(Categories.TRANSITION_CLAIM, cand.budget.reservationKey(r)),
    receipt: (txId) => store.read(Categories.RECEIPT, txId),
    audit: () => store.readAudit({ limit: 5000 }),
    snap: () => K.snapshot(cand, config),
    paste: (v, outOfAppTransaction) => cand.reconcile4.reconcileVaultV4(config, v.vaultId, { rpc: model.rpc, outOfAppTransaction }),
    child: (v, outOfAppTransaction, env) => F6.verifyPasteInChild({ config, model, pgDatabase }, v, outOfAppTransaction, { env, pg: PG })
  };
}
async function release(x) {
  if (!x.pgDatabase) return;
  const i = stores.indexOf(x.store);
  if (i >= 0) { stores.splice(i, 1); await x.store.close(); }
}
const auditOf = async (x, action) => (await x.audit()).filter((e) => e.action === action);
/* The recover-evidence settlement of plan r2 §2.5(3): RECOVERED via case B's synthetic request built from `base`. */
async function assertRecovered(x, v, p, out) {
  assert.equal(out.status, "ADVANCED", `the pasted recover settles the vault (got ${JSON.stringify(out)})`); assert.equal(out.to, "RECOVERED"); assert.equal(out.txId, p.txId);
  const m = await x.rawManifest(v);
  assert.equal(m.status, "RECOVERED"); assert.equal(m.live, null); assert.equal(m.latestTransitionTxId, p.txId);
  const t = m.lastTransition;
  assert.equal(t.action, "ownerRecover"); assert.equal(t.txId, p.txId); assert.equal(t.oldStateId, p.oldStateId); assert.equal(t.newStateId, null);
  assert.deepEqual(t.oldOutpoint, p.L, "lastTransition.oldOutpoint is the recorded outpoint L (base)"); assert.equal(t.newOutpoint, null);
  const receipt = await x.receipt(p.txId);
  assert.ok(receipt, "a case-B receipt is created for X");
  assert.equal(receipt.schema, "policyvault-receipt/v1"); assert.equal(receipt.txId, p.txId); assert.equal(receipt.vaultId, v.vaultId); assert.equal(receipt.action, "ownerRecover");
  assert.equal(receipt.proof.consumedOutpoint, `${p.L.transactionId}:${p.L.index}`); assert.equal(String(receipt.proof.recoveredValue), p.payout); assert.equal(receipt.proof.reconciled, true);
  const rows = (await auditOf(x, "reconciled_recovered")).filter((e) => e.via === "owner-evidence");
  assert.equal(rows.length, 1, "one reconciled_recovered {via: owner-evidence} row");
  assert.equal(rows[0].vaultId, v.vaultId); assert.ok(rows[0].txId === undefined || rows[0].txId === p.txId, "a txId the row carries names X");
}
/* settleLoser (plan r2 §2.2): STALE (state only, H-44), claims and reservation released, one transition_superseded row. */
async function assertLoser(x, d, dBefore, winnerTxId) {
  const da = await x.rawRequest(d.requestId);
  assert.equal(da.state, "STALE", "the PENDING delegate record on L is superseded by the pasted recover");
  assert.deepEqual(sansState(da), sansState(dBefore), "the loser's relabel changes only its state (H-44)");
  assert.equal(await x.claimOn(d.predecessorOutpoint), null, "the loser's claim on L is released");
  assert.equal(await x.submissionClaim(d.txId), null); assert.equal(await x.reservationOf(d), null, "the loser's reservation is released");
  const superseded = await auditOf(x, "transition_superseded");
  assert.equal(superseded.length, 1, "one transition_superseded row");
  assert.equal(superseded[0].requestId, d.requestId); assert.equal(superseded[0].txId, d.txId); assert.equal(superseded[0].winnerTxId, winnerTxId);
  if (superseded[0].depth !== undefined) assert.ok(BigInt(superseded[0].depth) >= SETTLE_DEPTH_DAA, "a depth the row carries is >= D");
}
/* A mismatched paste: UNKNOWN (plan r2 §2.5(3) "Mismatch -> UNKNOWN, no write"), nothing written, never RECOVERED. */
async function assertRefused(x, v, safe, label) {
  const before = await x.snap();
  const out = await resolved(() => x.paste(v, safe), `Verify with ${label}`);
  assert.deepEqual(await x.snap(), before, `${label}: nothing is written (no TERMINATED_UNKNOWN, no RECOVERED, no receipt, no audit)`);
  assert.equal(out.status, "UNKNOWN", `${label}: the mismatch answers UNKNOWN`);
}

/* CR-I4: a real v0.4.1 recover Safe JSON measured against the 64 KiB paste limit (store-independent). */
test("RC45 T5: real v0.4.1 recover Safe JSON documents (broadcast form, full covenant signature script) fit the 64 KiB paste limit (CR-I4) [holds on C1]", async (t) => {
  for (const [label, safe] of [["hosted-built recover, vault input 0", B.p0.x.safe], ["out-of-app recover, vault input 1", B.p1.x.safe], ["dangerous ownerSetAgentRoot shape", B.dz.root.safe]]) {
    const bytes = Buffer.byteLength(safe, "utf8");
    t.diagnostic(`${label}: ${bytes} bytes (limit ${PASTE_LIMIT})`);
    assert.ok(bytes <= PASTE_LIMIT, `${label} is ${bytes} bytes, within ${PASTE_LIMIT}`);
  }
});

const PG_SKIP = PG_AVAILABLE ? undefined : "REQUIREMENT_NOT_AVAILABLE in this process: isolated PostgreSQL (the rc45 runner's pg mode runs these legs; a skipped PostgreSQL leg there is a FAIL)";
for (const [backend, skip] of [["JSON", undefined], ["PostgreSQL", PG_SKIP]]) {
  const t5 = (name, fn) => test(`RC45 T5 ${backend}: ${name}`, { skip }, async () => { const x = await fresh(backend); try { await fn(x); } finally { await release(x); } });

  /* ---------------- pasted recover -> RECOVERED at depth, losers STALE (CR-L4; sabotage n) ---------------- */
  t5("pasted recover, vault input at index 0 (hosted-built, broadcast outside PolicyVault): below D nothing is written; at D the vault is RECOVERED (case-B receipt, one reconciled_recovered {via: owner-evidence}), the PENDING delegate record on L is STALE with its claims and reservation released and one transition_superseded naming X, BUILT noise untouched; the same paste again answers TERMINAL with no write and no node call [RED on C1]", async (x) => {
    const p = B.p0.x, d = await x.req(B.p0.d), dBefore = await x.rawRequest(d.requestId), nBefore = await x.rawRequest(B.p0.n);
    assert.equal(d.state, "PREFLIGHT_VERIFIED"); assert.equal((await x.claimOn(p.L)).txId, d.txId, "the delegate holds the claim on L");
    x.model.confirm(p.frozen, p.txId); x.model.advance(SETTLE_DEPTH_DAA - 1n); // X accepted; its outputs at depth 999
    const below = await x.snap();
    const early = await resolved(() => x.paste(V.p0, p.safe), "Verify with the paste below D");
    assert.ok(["CLAIM_PENDING", "UNKNOWN"].includes(early.status), `below D the paste settles nothing (got ${JSON.stringify(early)})`);
    assert.deepEqual(await x.snap(), below, "below D nothing is written");
    x.model.advance(1n);
    const done = await resolved(() => x.paste(V.p0, p.safe), "Verify with the paste at D");
    await assertRecovered(x, V.p0, p, done);
    await assertLoser(x, d, dBefore, p.txId);
    assert.deepEqual(await x.rawRequest(B.p0.n), nBefore, "a BUILT record on L is neither a loser nor a twin");
    const closed = await x.snap(), calls = x.model.calls.length;
    const again = await resolved(() => x.paste(V.p0, p.safe), "the same paste on the closed vault");
    assert.equal(again.status, "TERMINAL"); assert.deepEqual(await x.snap(), closed); assert.equal(x.model.calls.length, calls, "a closed vault answers without a node call");
  });
  t5("pasted recover, vault input at INDEX 1 (out-of-app, VM-verified): at D the vault is RECOVERED from L and the PENDING delegate record on L is STALE (settleLoser compares the input equal to L, not input 0; CR-L4) [RED on C1]", async (x) => {
    const p = B.p1.x, d = await x.req(B.p1.d), dBefore = await x.rawRequest(d.requestId);
    x.model.confirm(p.frozen, p.txId); x.model.advance(SETTLE_DEPTH_DAA);
    const done = await resolved(() => x.paste(V.p1, p.safe), "Verify with the paste at D");
    await assertRecovered(x, V.p1, p, done);
    await assertLoser(x, d, dBefore, p.txId);
  });
  t5("pasted recover of a RC44-written TERMINATED_UNKNOWN vault: base = lastRecordedLive L1; below D nothing is written; at D the vault is RECOVERED from L1 (case B's synthetic request built from base, never the null manifest.live; CR-L4) [RED on C1]", async (x) => {
    const p = B.tuW.x, m0 = await x.rawManifest(V.tuW);
    assert.equal(m0.status, "TERMINATED_UNKNOWN"); assert.equal(m0.live, null); assert.deepEqual(p.L, B.tuW.L1);
    x.model.confirm(p.frozen, p.txId); x.model.advance(SETTLE_DEPTH_DAA - 1n);
    const below = await x.snap();
    const early = await resolved(() => x.paste(V.tuW, p.safe), "Verify with the paste below D");
    assert.ok(["CLAIM_PENDING", "UNKNOWN"].includes(early.status), `below D the paste settles nothing (got ${JSON.stringify(early)})`);
    assert.deepEqual(await x.snap(), below, "below D nothing is written");
    x.model.advance(1n);
    const done = await resolved(() => x.paste(V.tuW, p.safe), "Verify with the paste at D");
    await assertRecovered(x, V.tuW, p, done);
    assert.equal(p.oldStateId, (await x.req(B.tuW.b)).successorStateId, "the recorded live state is B's successor");
  });

  /* ---------------- zero-write negatives: mismatch -> UNKNOWN (sabotage n) ---------------- */
  t5("one output of X kept unspent suffices (L-12, WEB-3): the owner already moved the payout X:0, only the change X:1 remains at depth D -> RECOVERED [RED on C1]", async (x) => {
    const p = B.ng.x;
    x.model.confirm(p.frozen, p.txId); x.model.remove({ transactionId: p.txId, index: 0 }); x.model.advance(SETTLE_DEPTH_DAA);
    const done = await resolved(() => x.paste(V.ng, p.safe), "Verify with the paste at D");
    await assertRecovered(x, V.ng, p, done);
  });
  t5("zero-write negative: unobserved output (the owner spent every output of X before Verify, L-12) -> UNKNOWN, nothing written; an X:0 observed with a value other than the document's (SYNTHETIC indexer view) is not 'exactly' observed -> UNKNOWN, nothing written [RED on C1]", async (x) => {
    await assertRefused(x, V.ng, B.ng.x.safe, "a paste of X with no X output observed");
    const o = B.ng.x.frozen.outputs[0];
    x.model.add({ transactionId: B.ng.x.txId, index: 0 }, (BigInt(o.value) - 1n).toString(), o.scriptPublicKey, null, x.model.virtualDaaScore - SETTLE_DEPTH_DAA);
    await assertRefused(x, V.ng, B.ng.x.safe, "a paste of X whose only observed output differs from the document");
  });
  t5("zero-write negative: tampered embedded id (the document names T; T:0 pays the owner pv+fr at depth; X itself never landed) -> the id is recomputed, UNKNOWN, nothing written (sabotage n) [RED on C1]", async (x) => {
    // SYNTHETIC: T:0 is a plain owner UTXO worth pv+fr at depth D; nothing spends L that the store or the paste can attribute.
    const o = B.ng.x.frozen.outputs[0];
    x.model.add({ transactionId: B.ng.tamperedId, index: 0 }, o.value, o.scriptPublicKey, null, x.model.virtualDaaScore - SETTLE_DEPTH_DAA);
    await assertRefused(x, V.ng, B.ng.tampered, "a document whose embedded id was replaced");
  });
  t5("zero-write negative: input != L (a real recover of the same vault state at another outpoint, observed at depth) -> UNKNOWN, nothing written (sabotage n) [RED on C1]", async (x) => {
    const r2 = B.ng.r2;
    x.model.confirm(r2.frozen, r2.txId); x.model.advance(SETTLE_DEPTH_DAA);
    await assertRefused(x, V.ng, r2.safe, "a recover that spends no input equal to L");
  });
  t5("zero-write negative: V-1 payout (SYNTHETIC: outputs[0] pays the owner pv+fr-1, shown accepted at depth) -> UNKNOWN, nothing written [RED on C1]", async (x) => {
    const s = B.ng.vMinus;
    x.model.confirm(s.frozen, s.txId); x.model.advance(SETTLE_DEPTH_DAA);
    await assertRefused(x, V.ng, s.safe, "a V-1 payout");
  });
  t5("zero-write negative: C-bound output (SYNTHETIC: the recover's change output bound to the vault's covenant id, shown accepted at depth) -> UNKNOWN, nothing written [RED on C1]", async (x) => {
    const s = B.ng.cBound;
    x.model.confirm(s.frozen, s.txId); x.model.advance(SETTLE_DEPTH_DAA);
    await assertRefused(x, V.ng, s.safe, "a recover-shaped transaction with a C-bound output");
  });
  t5("zero-write negative: the dangerous ownerControl shape (CR-I3; real, VM-verified ownerSetAgentRoot: outputs[0] = P2PK(owner) worth pv+fr from fuel, the C successor at index 1, all at depth) -> UNKNOWN, nothing written; the vault is never RECOVERED while its covenant continues [RED on C1]", async (x) => {
    const z = B.dz.root;
    x.model.confirm(z.frozen, z.txId); x.model.advance(SETTLE_DEPTH_DAA);
    await assertRefused(x, V.dz, z.safe, "the dangerous ownerControl shape");
  });
  t5("the dangerous ownerControl shape as a Pause (real, VM-verified; the C successor at index 1 sits at address(pauseSuccessorV4(S))): the paste never makes the vault RECOVERED; the manifest stays live (unchanged, or adopted at X:1 by step 8) [RED on C1]", async (x) => {
    const z = B.dz.pause, m0 = await x.rawManifest(V.dz);
    x.model.confirm(z.frozen, z.txId); x.model.advance(SETTLE_DEPTH_DAA);
    await resolved(() => x.paste(V.dz, z.safe), "Verify with the dangerous Pause pasted");
    const m = await x.rawManifest(V.dz);
    assert.notEqual(m.status, "RECOVERED", "never RECOVERED"); assert.notEqual(m.live, null, "the manifest keeps a live outpoint (the covenant continues)");
    const adopted = m.live.outpoint.transactionId === z.txId;
    if (adopted) { assert.equal(m.status, "PAUSED"); assert.deepEqual(m.live.outpoint, { transactionId: z.txId, index: 1 }); assert.equal(m.live.covenantId, V.dz.cov); }
    else assert.deepEqual(m, m0, "not adopted: the manifest is unchanged");
    assert.equal(await x.receipt(z.txId), null, "no receipt is written for the pasted transaction");
    assert.equal((await auditOf(x, "reconciled_recovered")).length, 0);
  });

  /* ---------------- environment errors -> 422; same-txid never STALE (CR-M2, CR2-L3) ---------------- */
  t5("harness failure in validateIdentity: with a failing VM harness the pasted recover at D with a byte-carrying loser on L is a 422 (the SDK call rejects) with no write; with a working harness the same paste completes (RECOVERED, loser STALE) [RED on C1]", async (x) => {
    const p = B.p0.x, d = await x.req(B.p0.d), dBefore = await x.rawRequest(d.requestId);
    x.model.confirm(p.frozen, p.txId); x.model.advance(SETTLE_DEPTH_DAA);
    const before = await x.snap();
    const run = x.child(V.p0, p.safe, F6.failingHarness(mk("pv-rc45-f6-t5-harness-")));
    assert.equal(run.signal, null); assert.equal(run.status, 0, run.stderr); assert.ok(run.result, "the child reported");
    assert.equal(run.result.ok, false, `the harness failure aborts the settlement (${JSON.stringify(run.result.value)})`);
    assert.match(run.result.message, /harness/i, "the refusal is the harness spawn failure");
    assert.deepEqual(await x.snap(), before, "an environment error writes nothing (validate before the first write)");
    const done = await resolved(() => x.paste(V.p0, p.safe), "Verify with a working harness");
    await assertRecovered(x, V.p0, p, done);
    await assertLoser(x, d, dBefore, p.txId);
  });
  t5("a same-txid paste is never STALE (CR-M2): the owner's contested hosted recover Q landed at D and its Safe JSON is pasted; with a failing harness Verify is a 422 with no write (Q not STALE); with a working harness the vault is RECOVERED, Q CHAIN_VERIFIED and the delegate D STALE (the only transition_superseded row, winner Q) [RED on C1]", async (x) => {
    const p = B.st.x, q = await x.req(B.st.q), d = await x.req(B.st.d);
    assert.equal(q.state, "PREFLIGHT_VERIFIED"); assert.equal(q.txId, p.txId); assert.equal((await x.claimOn(q.predecessorOutpoint)).txId, d.txId, "the delegate holds the only claim");
    x.model.confirm(p.frozen, p.txId); x.model.advance(SETTLE_DEPTH_DAA);
    const before = await x.snap();
    const run = x.child(V.st, p.safe, F6.failingHarness(mk("pv-rc45-f6-t5-harness-")));
    assert.equal(run.signal, null); assert.equal(run.status, 0, run.stderr); assert.ok(run.result, "the child reported");
    assert.equal(run.result.ok, false, `an environment error is a 422, never UNKNOWN followed by a STALE X-record (${JSON.stringify(run.result.value)})`);
    assert.match(run.result.message, /harness/i);
    assert.deepEqual(await x.snap(), before, "nothing is written");
    const done = await resolved(() => x.paste(V.st, p.safe), "Verify with a working harness");
    assert.equal(done.status, "ADVANCED"); assert.equal(done.txId, p.txId);
    const m = await x.rawManifest(V.st);
    assert.equal(m.status, "RECOVERED"); assert.equal(m.live, null); assert.equal(m.latestTransitionTxId, p.txId);
    assert.equal((await x.rawRequest(q.requestId)).state, "CHAIN_VERIFIED", "the same-txid owner record completes; it is never STALE");
    assert.equal((await x.rawRequest(d.requestId)).state, "STALE");
    const superseded = await auditOf(x, "transition_superseded");
    assert.equal(superseded.length, 1); assert.equal(superseded[0].requestId, d.requestId); assert.equal(superseded[0].winnerTxId, p.txId);
    assert.equal(superseded.filter((e) => e.requestId === q.requestId).length, 0, "no transition_superseded row names the same-txid record");
  });
  t5("a same-txid paste is never STALE (CR-M2), BUILT variant: the owner's hosted Close & recover Q stayed BUILT here while the owner signed and broadcast the same transaction outside PolicyVault; its paste at D settles the vault RECOVERED and Q is never STALE (completed by its txid, or left BUILT byte-identical) [RED on C1]", async (x) => {
    const p = B.sb.x, qBefore = await x.rawRequest(B.sb.q);
    assert.equal(qBefore.state, "BUILT"); assert.equal(qBefore.txId, p.txId);
    x.model.confirm(p.frozen, p.txId); x.model.advance(SETTLE_DEPTH_DAA);
    const done = await resolved(() => x.paste(V.sb, p.safe), "Verify with the paste at D");
    assert.equal(done.status, "ADVANCED", `the paste settles the vault (got ${JSON.stringify(done)})`); assert.equal(done.txId, p.txId);
    const m = await x.rawManifest(V.sb);
    assert.equal(m.status, "RECOVERED"); assert.equal(m.live, null); assert.equal(m.latestTransitionTxId, p.txId);
    const q = await x.rawRequest(B.sb.q);
    assert.ok(["BUILT", "CHAIN_VERIFIED"].includes(q.state), `the same-txid record is never STALE (got ${q.state})`);
    if (q.state === "BUILT") assert.deepEqual(q, qBefore, "left BUILT: byte-identical");
    assert.equal((await auditOf(x, "transition_superseded")).length, 0, "nothing is superseded");
  });
  t5("a same-txid paste never touches an identity-invalid X-record (SYNTHETIC record-shape defect): its record-shape throw excludes only that record (no 422, CR2-L3); the paste settles the vault RECOVERED, the delegate D STALE, and the X-record stays byte-identical (never STALE) [RED on C1]", async (x) => {
    const p = B.si.x, d = await x.req(B.si.d), dBefore = await x.rawRequest(d.requestId), qBefore = await x.rawRequest(B.si.q);
    assert.equal(qBefore.state, "PREFLIGHT_VERIFIED"); assert.equal(qBefore.txId, p.txId);
    x.model.confirm(p.frozen, p.txId); x.model.advance(SETTLE_DEPTH_DAA);
    const done = await resolved(() => x.paste(V.si, p.safe), "Verify with the paste at D (a record-shape throw is no 422)");
    await assertRecovered(x, V.si, p, done);
    await assertLoser(x, d, dBefore, p.txId);
    assert.deepEqual(await x.rawRequest(B.si.q), qBefore, "the identity-invalid same-txid record is untouched (never STALE)");
  });
}
