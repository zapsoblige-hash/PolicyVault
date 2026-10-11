"use strict";
/*
 * RC45 T6 — REQUEST-SCOPED RECOVERY DECIDES BEFORE IT WRITES (fix item F7
 * RC45-RV-SRR-01; plan rc45-simplified-plan-r2 §1 O4, §2.6 steps 1-5 with the
 * "why finishing needs no fresh read" rule, §2.2 finishRecorded / the pass,
 * §8 T6, §8.2 sabotage e; finding RV-SRR-01 of rc44-patch-independent-01,
 * shapes SR-A..SR-D). Internal RED-first regression material for the RC45
 * candidate; not an audit.
 *
 * RED on C1 e62b1973 (reconcileTransitionWalletRequestV4 validates, then
 * writes a PROTECTED journal, relabels the record RECONCILIATION_REQUIRED and
 * re-creates claims BEFORE it decides whether the record is already settled;
 * it completes at any depth; it needs a fresh read unless a receipt exists;
 * it refuses every closed label). GREEN after F7:
 *   - a journal-free record that is not PENDING answers {request, outcome:
 *     its own label} with an EMPTY write log (records, claims, receipts,
 *     manifest and audit) and ZERO node calls: SR-A (established rejection,
 *     vault not advanced), SR-B (established rejection after the vault
 *     advanced; the Pause's claim on the old key untouched), SR-C (an older
 *     CHAIN_VERIFIED), SR-D (the latest CHAIN_VERIFIED) and every closed
 *     label; the vault is not blocked afterwards;
 *   - a journal-free PENDING record: RC44's read-only checks run unchanged
 *     (a contested break-glass record fails closed CLAIM_CONFLICT at the
 *     retained claim check, zero writes); a recorded advancement of exactly
 *     this txid is finished with no node call (finishRecorded); otherwise the
 *     Verify settlement pass runs under the same lock: CHAIN_VERIFIED (at
 *     depth D = 1,000 only) or STALE when it settles the record, else
 *     PROTECTED_UNRESOLVED with zero writes, the record still submittable;
 *     a read failure in the pass (its 422) is PROTECTED_UNRESOLVED with no
 *     write; a store error propagates;
 *   - no journal is ever written, no claim is ever re-created, and a claim
 *     the submit re-created for a claimless PREFLIGHT_VERIFIED is accepted as
 *     the record's own (CR2-L7).
 * The RC40 foreign-completed-recovery disposition and its fault matrix are
 * the retained read-only checks; they are pinned unchanged by
 * sdk/test/v4-foreign-recovery-rc40.test.js (holds on C1 and after F7).
 *
 * Layers: SDK. Real v0.4.1 compiler, pv_call_encoder, TEST-key signatures
 * (deterministic dev signer) and pv_vm_preflight for every consensus byte.
 * Node observations come ONLY from the explicit chain model of
 * sdk/testutil/rc45-f5-kit.js passed as `rpc` (UTXOs with blockDaaScore, a
 * virtualDaaScore, a selected chain, a mempool with rusty-kaspa v2.0.1 wire
 * texts); every config names ws://127.0.0.1:1, so nothing can dial a node.
 *
 * RC44-written shapes (CR-M13): SR-A..SR-D, the closed labels WALLET_REJECTED,
 * SIGNATURE_INVALID, CLAIM_CONFLICT, STALE and the wrong-key finalize close,
 * and the age-released PREFLIGHT_VERIFIED come from the pinned df5b8de
 * writers in POLICYVAULT_TEST_RC44_TREE (sdk/testutil/rc45-f7-rc44-history.js;
 * a missing or mismatched tree FAILS, never skips). CANDIDATE-WRITTEN: the
 * finalized spend (cmp), the contested pair finalized apart (stl; the
 * delegate holds the only claim) and the uncontested submit that crashed
 * right after its manifest advance (fin). SYNTHETIC (labelled below): the
 * closed labels no inspected writer path here produces (a state-only relabel
 * of an RC44-written BUILT request under a new request id), and RC44's orphan
 * claim used to produce CLAIM_CONFLICT.
 *
 * Both stores: JSON always; PostgreSQL with POLICYVAULT_TEST_PG_{PORT,USER,
 * DATABASE} (the rc45 runner's pg mode; a skipped PostgreSQL leg there is a
 * FAIL). TEST keys only; no production data, credentials or endpoints.
 */
const path = require("node:path");
const assert = require("node:assert/strict");
const { test, before, after } = require("node:test");
const K = require("../testutil/rc45-f5-kit");
const H7 = require("../testutil/rc45-f7-rc44-history");
const { KAS, LOOPBACK, SETTLE_DEPTH_DAA, frozenOf, clone } = K;

const cand = K.modulesOf(path.join(__dirname, "..", "src"));
const recovery = require("../src/wallet-recovery-v4");
const { Categories } = cand.store;
const TOOLCHAIN = require("../testutil/org-root-durable-fixture").toolchainAvailable();
const PG = K.pgFromEnv();
const PG_AVAILABLE = Boolean(PG.port && PG.user && PG.database);
const V = Object.freeze({ cmp: K.vault("t6-cmp"), stl: K.vault("t6-stl"), fin: K.vault("t6-fin"), ...H7.F7_RC44_VAULTS });
/* Closed labels: RC44-written where a df5b8de writer path produces them here, else a SYNTHETIC state-only relabel. */
const CLOSED_LABELS = Object.freeze(["WALLET_REJECTED", "SIGNATURE_INVALID", "PREFLIGHT_FAILED", "CLAIM_CONFLICT", "STALE", "AUTHORIZATION_FAILED", "INSUFFICIENT_APPROVALS", "BUILD_FAILED", "TERMINATED_UNKNOWN"]);
const roots = [], stores = [], databases = [];
let admin = null, serial = 0, history = null, H = null, B = null, w = null, templateRoot = null, LABELS = null, LABEL_SOURCE = null;
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
const settle = (promise) => promise.then((value) => ({ value, error: null }), (error) => ({ value: null, error }));
/* Every durable store mutation (records, claims, receipts, manifests AND audit rows) made while the log is open. */
function writeLog(store) {
  const entries = [], originals = {};
  for (const name of ["write", "createExclusive", "remove", "appendAudit"]) {
    originals[name] = store[name];
    const bound = store[name].bind(store);
    store[name] = async (...args) => { entries.push(name === "appendAudit" ? [name, args[0]?.action ?? null] : [name, args[0], args[1]]); return bound(...args); };
  }
  return { entries, restore: () => { for (const [name, fn] of Object.entries(originals)) store[name] = fn; } };
}

before(async () => {
  assert.ok(TOOLCHAIN, "real compiler, encoder and VM are required (a missing VM toolchain is a FAIL, never a SKIP)");
  // (1) RC44-written history (SR-A..SR-D, closed labels, the age-released spend), by the pinned df5b8de writers only.
  const rc44 = H7.runF7Rc44Scenario("t6", { track });
  H = rc44.result.hist;
  // (2) One template root: the RC44 records plus the candidate-written bases.
  const template = cand.config.loadConfig({ dataRoot: mk("pv-rc45-f7-t6-template-"), rpcUrl: LOOPBACK });
  await K.install(cand, template, await K.snapshot(cand, cand.config.loadConfig({ dataRoot: rc44.dataRoot, rpcUrl: LOOPBACK })));
  w = K.walletsFor(template);
  const k = K.kitFor(cand, template, w), id = (r) => r.requestId;
  B = {};
  { const v = V.cmp; await K.seedVault(cand, template, v, w); B.cmp = { d: id(await k.finalize(await k.agentSpend(v, 4), w.agent)) }; }
  { // stl: a delegate spend D and the owner's Pause Q on L0, finalized apart: D holds the only claim (the contested shape).
    const v = V.stl; await K.seedVault(cand, template, v, w);
    const d = await k.agentSpend(v, 4); await K.sleep(3);
    const q = await k.ownerOp(v, "ownerPause");
    await K.finalizeApart(cand, template, [{ requestId: d.requestId, signer: w.agent }, { requestId: q.requestId, signer: w.owner }], { claimHolder: d.requestId, track });
    B.stl = { d: id(d), q: id(q) };
  }
  { // fin: an uncontested agent spend submitted, accepted and observed at depth 0; the process dies right after the
    // manifest advance (the durable state of a kill there: SUBMITTED, manifest recorded, no receipt, claims kept).
    const v = V.fin; await K.seedVault(cand, template, v, w);
    const f = await k.finalize(await k.agentSpend(v, 4), w.agent);
    assert.equal(f.state, "PREFLIGHT_VERIFIED");
    const model = K.chainModel(template); model.know(f); model.seedInputs(frozenOf(f), f.covenantId); model.confirmOnSubmit = true;
    const s = cand.store.getStore(template), write = s.write.bind(s); let crashed = false;
    s.write = async (c, key, value) => {
      const out = await write(c, key, value);
      if (!crashed && c === Categories.VAULT && key === v.vaultId) { crashed = true; throw new Error("TEST crash right after the manifest advance"); }
      return out;
    };
    try {
      await assert.rejects(cand.submit4.submitWalletRequestV4({ config: template, requestId: f.requestId, rpc: model.rpc, pollAttempts: 1, pollDelayMs: 0 }), /TEST crash right after the manifest advance/);
    } finally { s.write = write; }
    assert.equal(crashed, true, "the submit reached its manifest advance");
    const r = await cand.wr4.loadRequest(template, f.requestId);
    assert.equal(r.state, "SUBMITTED"); assert.equal((await s.read(Categories.VAULT, v.vaultId)).latestTransitionTxId, f.txId);
    B.fin = { f: id(f), model: model.serialize() };
  }
  { // Closed labels: RC44-written, or SYNTHETIC — a state-only relabel of the RC44-written BUILT request under a new id.
    const built = await cand.wr4.loadRequest(template, H.scl.built.requestId);
    assert.equal(built.state, "BUILT");
    LABELS = { WALLET_REJECTED: H.scl.rejected.requestId, SIGNATURE_INVALID: H.scl.invalid.requestId, CLAIM_CONFLICT: H.scl.conflict.requestId, STALE: H.srb.stale.requestId };
    if (H.scl.wrongKey.state === "PREFLIGHT_FAILED") LABELS.PREFLIGHT_FAILED = H.scl.wrongKey.requestId;
    LABEL_SOURCE = Object.fromEntries(Object.keys(LABELS).map((label) => [label, "RC44-written (df5b8de writers)"]));
    for (const label of CLOSED_LABELS) {
      if (LABELS[label]) continue;
      LABEL_SOURCE[label] = `SYNTHETIC state-only relabel of the RC44-written BUILT request (RC44 closed the wrong-key spend ${H.scl.wrongKey.state})`;
      const requestId = `rc45-f7-synthetic-${label.toLowerCase().replace(/_/g, "-")}`;
      await cand.wr4.saveRequest(template, { ...clone(built), requestId, state: label });
      LABELS[label] = requestId;
    }
  }
  // Compile the states the candidate recovery will read once, so fresh cases reuse the template's cache.
  for (const requestId of [H.sag.a.requestId, B.cmp.d, B.stl.d, B.stl.q, B.fin.f]) {
    const q = await cand.wr4.loadRequest(template, requestId);
    for (const s of [q.build.stateJson, q.build.successorState]) if (s) cand.submit4.successorAddressAndScript(template, q.build.template, s, q.contractVersion);
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

async function fresh(backend) {
  const dataRoot = mk("pv-rc45-f7-t6-case-");
  K.warmCompileCache(templateRoot, dataRoot);
  let config, pgDatabase = null;
  if (backend === "PostgreSQL") {
    pgDatabase = `pv_rc45_f7_t6_${process.pid}_${++serial}`;
    await admin.query(`CREATE DATABASE ${pgDatabase}`); databases.push(pgDatabase);
    config = cand.config.loadConfig({ persistenceBackend: "postgres", pgHost: PG.host, pgPort: PG.port, pgUser: PG.user, pgDatabase, pgNoTls: true, hostedDevOpen: true, dataRoot, rpcUrl: LOOPBACK });
    stores.push(await cand.store.openPgStore(config, { migrate: true }));
    assert.equal(cand.store.getStore(config).kind, "postgres");
  } else config = cand.config.loadConfig({ dataRoot, rpcUrl: LOOPBACK });
  await K.install(cand, config, history);
  const store = cand.store.getStore(config), model = K.chainModel(config);
  return {
    config, store, model, pgDatabase, k: K.kitFor(cand, config, w),
    req: (requestId) => cand.wr4.loadRequest(config, requestId),
    rawRequest: (requestId) => store.read(Categories.REQUEST, requestId),
    rawManifest: (v) => store.read(Categories.VAULT, v.vaultId),
    claimOn: (outpoint) => store.read(Categories.TRANSITION_CLAIM, cand.claims.transitionClaimKey(outpoint)),
    submissionClaim: (txId) => store.read(Categories.SUBMISSION_CLAIM, txId),
    reservationOf: (r) => store.read(Categories.TRANSITION_CLAIM, cand.budget.reservationKey(r)),
    receipt: (txId) => store.read(Categories.RECEIPT, txId),
    audit: () => store.readAudit({ limit: 5000 }),
    snap: () => K.snapshot(cand, config),
    submit: (requestId) => cand.submit4.submitWalletRequestV4({ config, requestId, rpc: model.rpc, pollAttempts: 1, pollDelayMs: 0 }),
    recover: (requestId, rpc = model.rpc) => recovery.reconcileTransitionWalletRequestV4({ config, requestId, rpc })
  };
}
async function release(x) {
  if (!x.pgDatabase) return;
  const i = stores.indexOf(x.store);
  if (i >= 0) { stores.splice(i, 1); await x.store.close(); }
}
const auditOf = async (x, action) => (await x.audit()).filter((e) => e.action === action);
/* The SR-A..SR-D / closed-label contract: outcome = the label, empty write log (audit included), zero node calls. */
async function settledDisposition(x, requestId, label) {
  const stored = await x.rawRequest(requestId);
  assert.equal(stored.state, label, `the base record is ${label}`); assert.equal(stored.transitionRecovery, undefined, "the base record carries no journal");
  const before = await x.snap(), calls = x.model.calls.length, log = writeLog(x.store);
  let out;
  try { out = await resolved(() => x.recover(requestId), `request-scoped recovery answers the settled ${label} record`); } finally { log.restore(); }
  assert.equal(out.outcome, label, "outcome = the record's own label (plan §2.6 step 2)");
  assert.deepEqual(log.entries, [], "empty write log: no request, claim, receipt, manifest or audit write (sabotage e)");
  assert.equal(x.model.calls.length, calls, "zero node calls");
  assert.deepEqual(await x.snap(), before, "every durable record and the audit log are byte-identical");
  assert.deepEqual(out.request, stored, "the answer carries the stored record unchanged");
  return out;
}

const PG_SKIP = PG_AVAILABLE ? undefined : "REQUIREMENT_NOT_AVAILABLE in this process: isolated PostgreSQL (the rc45 runner's pg mode runs these legs; a skipped PostgreSQL leg there is a FAIL)";
for (const [backend, skip] of [["JSON", undefined], ["PostgreSQL", PG_SKIP]]) {
  const t6 = (name, fn) => test(`RC45 T6 ${backend}: ${name}`, { skip }, async (t) => { const x = await fresh(backend); try { await fn(x, t); } finally { await release(x); } });

  /* ---------------- SR-A..SR-D (RV-SRR-01), RC44-written ---------------- */
  t6("SR-A: an ESTABLISHED SUBMISSION_REJECTED on a vault that did not advance answers SUBMISSION_REJECTED with an empty write log and zero node calls; the vault is not blocked afterwards [RED on C1]", async (x) => {
    const a = await x.req(H.sra.a.requestId);
    assert.equal(a.state, "SUBMISSION_REJECTED"); assert.equal(await x.claimOn(a.predecessorOutpoint), null, "RC44 released its claims");
    assert.deepEqual((await x.rawManifest(V.sra)).live.outpoint, a.predecessorOutpoint, "the predecessor is still the recorded live outpoint");
    await settledDisposition(x, a.requestId, "SUBMISSION_REJECTED");
    const built = await resolved(() => x.k.agentSpend(V.sra, 1), "an ordinary build is not blocked by the settled record");
    assert.equal(built.state, "BUILT");
  });
  t6("SR-B: an ESTABLISHED SUBMISSION_REJECTED after the vault advanced (the Pause's claim occupies the old predecessor key) answers SUBMISSION_REJECTED with an empty write log and zero node calls; that claim stays byte-identical [RED on C1]", async (x) => {
    const a = await x.req(H.srb.a.requestId), claim = await x.claimOn(a.predecessorOutpoint);
    assert.equal(claim.txId, H.srb.p.txId, "the RC44 Pause holds the old predecessor key");
    assert.equal((await x.rawManifest(V.srb)).status, "PAUSED");
    await settledDisposition(x, a.requestId, "SUBMISSION_REJECTED");
    assert.deepEqual(await x.claimOn(a.predecessorOutpoint), claim);
  });
  t6("SR-C: an older CHAIN_VERIFIED transition (the vault advanced since) answers CHAIN_VERIFIED with an empty write log and zero node calls [RED on C1]", async (x) => {
    const c1 = await x.req(H.src.c1.requestId);
    assert.notEqual((await x.rawManifest(V.src)).latestTransitionTxId, c1.txId, "the vault advanced after this transition");
    assert.ok(await x.receipt(c1.txId), "RC44 persisted its receipt");
    await settledDisposition(x, c1.requestId, "CHAIN_VERIFIED");
  });
  t6("SR-D: the latest CHAIN_VERIFIED transition answers CHAIN_VERIFIED with an empty write log and zero node calls (no journal, no claim cleanup) [RED on C1]", async (x) => {
    const c2 = await x.req(H.src.c2.requestId);
    assert.equal((await x.rawManifest(V.src)).latestTransitionTxId, c2.txId);
    await settledDisposition(x, c2.requestId, "CHAIN_VERIFIED");
  });

  /* ---------------- every closed label ---------------- */
  for (const label of CLOSED_LABELS) {
    t6(`closed label ${label}: outcome = ${label}, empty write log, zero node calls [RED on C1]`, async (x, t) => {
      t.diagnostic(`${label} record provenance: ${LABEL_SOURCE[label]}`);
      await settledDisposition(x, LABELS[label], label);
    });
  }
  t6("a BUILT request (never signed, not PENDING): request-scoped recovery writes nothing and calls no node, whatever it answers [holds on C1]", async (x) => {
    const requestId = H.scl.built.requestId, before = await x.snap(), calls = x.model.calls.length, log = writeLog(x.store);
    try { await settle(x.recover(requestId)); } finally { log.restore(); }
    assert.deepEqual(log.entries, []); assert.equal(x.model.calls.length, calls); assert.deepEqual(await x.snap(), before);
  });

  /* ---------------- journal-free PENDING records ---------------- */
  t6("unlanded PREFLIGHT_VERIFIED: PROTECTED_UNRESOLVED with zero writes (record, claims and reservation byte-identical; no journal, no re-created claim, no audit), and the record is still submitted normally afterwards [RED on C1]", async (x) => {
    const d = await x.req(B.cmp.d);
    assert.equal(d.state, "PREFLIGHT_VERIFIED"); assert.equal((await x.claimOn(d.predecessorOutpoint)).txId, d.txId);
    x.model.seedInputs(frozenOf(d), d.covenantId); // L live and deep; nothing landed
    const before = await x.snap(), log = writeLog(x.store);
    let out;
    try { out = await resolved(() => x.recover(d.requestId), "request-scoped recovery answers"); } finally { log.restore(); }
    assert.equal(out.outcome, "PROTECTED_UNRESOLVED");
    assert.deepEqual(log.entries, [], "zero writes: no journal, no relabel, no claim re-creation, no audit (H-45)");
    assert.deepEqual(await x.snap(), before);
    assert.equal(x.model.broadcasts.length, 0, "recovery never broadcasts");
    x.model.know(d); x.model.confirmOnSubmit = true;
    const sub = await settle(x.submit(d.requestId));
    assert.equal(sub.error, null, `the PREFLIGHT_VERIFIED record is still submittable (${sub.error && sub.error.code} ${sub.error && sub.error.message})`);
    assert.deepEqual(x.model.broadcasts, [d.txId], "its signed bytes reach the node");
    assert.equal((await x.rawRequest(d.requestId)).state, "CHAIN_VERIFIED", "an uncontested non-terminal submit completes (L-2)");
  });
  t6("completion via the pass: a landed own spend below D answers PROTECTED_UNRESOLVED with zero writes; at D it completes (manifest, receipt, one reconciled_advanced {via: reconcile} with the txId, claims and reservation released, CHAIN_VERIFIED last, no journal, no transition_recovery_completed); a repeat call writes nothing and calls no node [RED on C1]", async (x) => {
    const d = await x.req(B.cmp.d), dBefore = await x.rawRequest(d.requestId);
    x.model.seedInputs(frozenOf(d), d.covenantId); x.model.confirm(frozenOf(d), d.txId); x.model.advance(SETTLE_DEPTH_DAA - 1n);
    const below = await x.snap(); let log = writeLog(x.store), out;
    try { out = await resolved(() => x.recover(d.requestId), "request-scoped recovery below D"); } finally { log.restore(); }
    assert.equal(out.outcome, "PROTECTED_UNRESOLVED", "depth 999 < D: the SEEN spend is not CONFIRMED, so request-scoped recovery does not complete it (J1-D1-05)");
    assert.deepEqual(log.entries, [], "below D nothing is written"); assert.deepEqual(await x.snap(), below);
    x.model.advance(1n);
    out = await resolved(() => x.recover(d.requestId), "request-scoped recovery at D");
    assert.equal(out.outcome, "CHAIN_VERIFIED");
    const r = await x.rawRequest(d.requestId);
    assert.equal(r.state, "CHAIN_VERIFIED"); assert.equal(r.transitionRecovery, undefined, "no journal (H-45)");
    assert.deepEqual(sansState(r), sansState(dBefore), "the relabel changes only the state (H-44)");
    const m = await x.rawManifest(V.cmp), index = frozenOf(d).outputs.findIndex((o) => o.covenant !== null);
    assert.equal(m.status, "ACTIVE"); assert.equal(m.latestTransitionTxId, d.txId); assert.deepEqual(m.live.outpoint, { transactionId: d.txId, index });
    assert.equal(m.agentRegistry[0].periodSpent, (4n * KAS).toString());
    const receipt = await x.receipt(d.txId);
    assert.equal(receipt.proof.requestId, d.requestId); assert.equal(receipt.proof.successorOutpoint, `${d.txId}:${index}`); assert.equal(receipt.proof.reconciled, true);
    const advanced = (await auditOf(x, "reconciled_advanced")).filter((e) => e.txId === d.txId);
    assert.equal(advanced.length, 1, "one reconciled_advanced row names the txid");
    assert.equal(advanced[0].requestId, d.requestId); assert.equal(advanced[0].via, "reconcile"); assert.equal(advanced[0].result, "CHAIN_VERIFIED");
    assert.equal((await auditOf(x, "transition_recovery_completed")).length, 0, "the journal-era completion row is never written");
    assert.equal(await x.claimOn(d.predecessorOutpoint), null); assert.equal(await x.submissionClaim(d.txId), null); assert.equal(await x.reservationOf(d), null);
    const done = await x.snap(), calls = x.model.calls.length; log = writeLog(x.store);
    let again;
    try { again = await resolved(() => x.recover(d.requestId), "a repeat call"); } finally { log.restore(); }
    assert.equal(again.outcome, "CHAIN_VERIFIED"); assert.deepEqual(log.entries, []); assert.equal(x.model.calls.length, calls); assert.deepEqual(await x.snap(), done);
  });
  t6("the pass settles a PENDING delegate record superseded by a CONFIRMED owner Pause: request-scoped recovery answers STALE (one transition_superseded row, its claims and reservation released, no journal) and the Pause completes [RED on C1]", async (x) => {
    const d = await x.req(B.stl.d), q = await x.req(B.stl.q), dBefore = await x.rawRequest(d.requestId);
    assert.equal(d.state, "PREFLIGHT_VERIFIED"); assert.equal(q.state, "PREFLIGHT_VERIFIED");
    assert.equal((await x.claimOn(d.predecessorOutpoint)).txId, d.txId, "the delegate holds the only claim on L");
    x.model.seedInputs(frozenOf(q), q.covenantId); x.model.confirm(frozenOf(q), q.txId); x.model.advance(SETTLE_DEPTH_DAA);
    const out = await resolved(() => x.recover(d.requestId), "request-scoped recovery of the delegate record");
    assert.equal(out.outcome, "STALE", "settled by the pass: superseded by the CONFIRMED Pause");
    const da = await x.rawRequest(d.requestId);
    assert.equal(da.state, "STALE"); assert.equal(da.transitionRecovery, undefined); assert.deepEqual(sansState(da), sansState(dBefore));
    assert.equal(await x.claimOn(d.predecessorOutpoint), null); assert.equal(await x.submissionClaim(d.txId), null); assert.equal(await x.reservationOf(d), null);
    const superseded = await auditOf(x, "transition_superseded");
    assert.equal(superseded.length, 1); assert.equal(superseded[0].requestId, d.requestId); assert.equal(superseded[0].winnerTxId, q.txId);
    assert.equal((await x.rawRequest(q.requestId)).state, "CHAIN_VERIFIED"); assert.equal((await x.rawManifest(V.stl)).status, "PAUSED");
  });
  t6("contested break-glass (the P claim is the delegate's): request-scoped recovery of the owner's Pause fails closed CLAIM_CONFLICT at the retained claim check with zero writes and zero node calls, before and after the Pause lands at D (Verify completes it) [holds on C1]", async (x) => {
    const d = await x.req(B.stl.d), q = await x.req(B.stl.q);
    assert.equal((await x.claimOn(q.predecessorOutpoint)).txId, d.txId);
    for (const landed of [false, true]) {
      if (landed) { x.model.seedInputs(frozenOf(q), q.covenantId); x.model.confirm(frozenOf(q), q.txId); x.model.advance(SETTLE_DEPTH_DAA); }
      const before = await x.snap(), calls = x.model.calls.length, log = writeLog(x.store);
      let e;
      try { e = await rejection(x.recover(q.requestId), `the contested owner record refuses (${landed ? "landed at D" : "not landed"})`); } finally { log.restore(); }
      assert.equal(e.code, "CLAIM_CONFLICT"); assert.match(e.message, /a claim belongs to another attempt/, "the retained claim check refuses");
      assert.deepEqual(log.entries, []); assert.equal(x.model.calls.length, calls); assert.deepEqual(await x.snap(), before);
    }
  });
  t6("finishRecorded: an uncontested submit that died right after its manifest advance (SUBMITTED, manifest recorded, no receipt) is finished with ZERO node calls — receipt, one reconciled_advanced, own claims and reservation released, CHAIN_VERIFIED, no journal, manifest unchanged [RED on C1]", async (x) => {
    const model = K.chainModel(x.config, B.fin.model); // the landed spend is indexed, so any read would observe it
    const f = await x.req(B.fin.f), fBefore = await x.rawRequest(f.requestId), m0 = await x.rawManifest(V.fin);
    assert.equal(f.state, "SUBMITTED"); assert.equal(m0.latestTransitionTxId, f.txId); assert.equal(await x.receipt(f.txId), null);
    assert.equal((await x.claimOn(f.predecessorOutpoint)).txId, f.txId, "its own claim is still held");
    const out = await resolved(() => x.recover(f.requestId, model.rpc), "request-scoped recovery finishes the recorded advancement");
    assert.equal(out.outcome, "CHAIN_VERIFIED");
    assert.equal(model.calls.length, 0, "finishRecorded makes no node call: the manifest records exactly this advancement (§2.6 'why finishing needs no fresh read')");
    const r = await x.rawRequest(f.requestId);
    assert.equal(r.state, "CHAIN_VERIFIED"); assert.equal(r.transitionRecovery, undefined); assert.deepEqual(sansState(r), sansState(fBefore));
    assert.deepEqual(await x.rawManifest(V.fin), m0, "the recorded manifest is not rewritten");
    assert.equal((await x.receipt(f.txId)).proof.requestId, f.requestId);
    assert.equal((await auditOf(x, "reconciled_advanced")).filter((e) => e.txId === f.txId).length, 1);
    assert.equal((await auditOf(x, "transition_recovery_completed")).length, 0);
    assert.equal(await x.claimOn(f.predecessorOutpoint), null); assert.equal(await x.submissionClaim(f.txId), null); assert.equal(await x.reservationOf(f), null);
  });
  t6("a read failure inside the pass (its 422) answers PROTECTED_UNRESOLVED with zero writes [RED on C1]", async (x) => {
    const d = await x.req(B.cmp.d);
    x.model.failRead = () => true;
    const before = await x.snap(), log = writeLog(x.store);
    let out;
    try { out = await resolved(() => x.recover(d.requestId), "the node cannot answer"); } finally { log.restore(); }
    assert.equal(out.outcome, "PROTECTED_UNRESOLVED");
    assert.deepEqual(log.entries, [], "no write"); assert.deepEqual(await x.snap(), before);
  });
  t6("a store error inside the pass propagates (never converted to PROTECTED_UNRESOLVED) and nothing durable is written [RED on C1]", async (x) => {
    const d = await x.req(B.cmp.d), dBefore = await x.rawRequest(d.requestId);
    x.model.seedInputs(frozenOf(d), d.covenantId); x.model.confirm(frozenOf(d), d.txId); x.model.advance(SETTLE_DEPTH_DAA);
    const before = await x.snap(), s = x.store, write = s.write.bind(s); let hit = false;
    s.write = async (c, key, value) => {
      if (!hit && c === Categories.VAULT) { hit = true; throw new Error("TEST store unavailable: the manifest write is refused"); }
      return write(c, key, value);
    };
    let e;
    try { e = await rejection(x.recover(d.requestId), "the store error propagates"); } finally { s.write = write; }
    assert.equal(hit, true, "the pass reached its manifest write");
    assert.match(e.message, /TEST store unavailable/, "the store's own error is rethrown");
    assert.deepEqual(await x.rawRequest(d.requestId), dBefore, "the record is byte-identical (no journal, no relabel)");
    // RC45 R1-06 (plan R1 r2 section 2 R1-06, C3/K4; declared changed-by-design, was "nothing durable is written"): the
    // winner's create-only receipt is the first durable write of a completion, so a store error at the manifest write
    // leaves exactly that receipt and nothing else (finalize/submit then answer 422 by the receipt guard; the next pass
    // re-enters step 7 and advances).
    const after = await x.snap();
    assert.deepEqual(after.audit, before.audit, "no audit row is written");
    const changed = Object.keys({ ...before.records, ...after.records }).filter((c) => JSON.stringify(after.records[c]) !== JSON.stringify(before.records[c]));
    assert.deepEqual(changed, [Categories.RECEIPT], "only the receipt category changes");
    const added = after.records[Categories.RECEIPT].filter(([k]) => !(before.records[Categories.RECEIPT] || []).some(([b]) => b === k));
    assert.equal(added.length, 1, "exactly one receipt is added");
    assert.equal(added[0][1].proof.requestId, d.requestId, "the only new durable record is the winner's own receipt");
    assert.equal((before.records[Categories.RECEIPT] || []).length + 1, after.records[Categories.RECEIPT].length, "no receipt is replaced");
  });
  t6("O4 accepts a submit-re-created claim (CR2-L7): the RC44 age-released PREFLIGHT_VERIFIED is submitted, the submit re-creates its own claim and broadcasts; once the spend lands at D, request-scoped recovery accepts that claim as its own and completes (no CLAIM_CONFLICT, no journal) [RED on C1]", async (x) => {
    const a = await x.req(H.sag.a.requestId);
    assert.equal(a.state, "PREFLIGHT_VERIFIED"); assert.equal(await x.claimOn(a.predecessorOutpoint), null, "RC44 released its claim by age");
    x.model.know(a); x.model.seedInputs(frozenOf(a), a.covenantId);
    const sub = await settle(x.submit(a.requestId));
    assert.notEqual(sub.error && sub.error.code, "CLAIM_CONFLICT", "submit re-creates a missing own claim (plan §2.3, §2.4 historical shapes)");
    assert.deepEqual(x.model.broadcasts, [a.txId], "the signed bytes reach the node");
    const claim = await x.claimOn(a.predecessorOutpoint);
    assert.equal(claim && claim.txId, a.txId, "the re-created claim names this request's txid");
    assert.ok(["SUBMITTED", "RECONCILIATION_REQUIRED"].includes((await x.rawRequest(a.requestId)).state), "not yet observed: the record stays pending");
    x.model.confirm(frozenOf(a), a.txId); x.model.advance(SETTLE_DEPTH_DAA);
    const out = await resolved(() => x.recover(a.requestId), "request-scoped recovery accepts the submit-re-created claim");
    assert.equal(out.outcome, "CHAIN_VERIFIED");
    const r = await x.rawRequest(a.requestId);
    assert.equal(r.state, "CHAIN_VERIFIED"); assert.equal(r.transitionRecovery, undefined);
    assert.equal(await x.claimOn(a.predecessorOutpoint), null); assert.equal(await x.submissionClaim(a.txId), null);
    assert.equal((await x.receipt(a.txId)).proof.requestId, a.requestId);
    assert.equal((await x.rawManifest(V.sag)).latestTransitionTxId, a.txId);
  });
}
