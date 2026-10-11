"use strict";
/*
 * RC45 T7 — VERIFY SETTLEMENT CRASH CONVERGENCE (fix item F5
 * RC45-L5-VERIFY-SETTLEMENT; plan rc45-simplified-plan-r2 §2.2 completePositive
 * / settleLoser / settleOneHop / finishRecorded, §4 durable write orders and
 * crash points ("completePositive, non-terminal: manifest -> receipt -> audit
 * -> claims -> reservation -> CHAIN_VERIFIED -> twins -> losers";
 * "completePositive, terminal: losers -> manifest RECOVERED -> receipt ->
 * audit -> claims -> reservation -> CHAIN_VERIFIED -> twins"; "settleLoser:
 * audit (idempotent) -> STALE -> claims -> reservation"), rule R, CR-M3, L-15, §8 T7,
 * §8.2 sabotage l/x/y). Internal RED-first regression material for the RC45
 * candidate; not an audit.
 *
 * RC45 R1-06 (finding ST-03 of the independent candidate review
 * rc45-patch-independent-01; remediation plan R1 revision 2, R1-06 with
 * conditions C2, C3, K4 and K5) re-pins the crash points, declared
 * changed-by-design: the create-only receipt of the winner is the FIRST
 * durable write of a completion, before the manifest advance; the order of
 * the remaining writes is unchanged (non-terminal: receipt -> manifest ->
 * audit -> claims -> reservation -> CHAIN_VERIFIED -> twins -> losers;
 * terminal: losers settled before the terminal manifest, the receipt before
 * the RECOVERED manifest). Crash convergence holds for winners in
 * SIGNED_OR_REJECTED because the receipt precedes every other durable write of
 * a completion (K5). Re-pinned legs: the contested Pause and contested Close &
 * recover sweeps and the CR-M3 leg (their original assertions are unchanged;
 * the receipt-first assertions are appended, so they are RED on dc7552e, whose
 * completion writes the manifest first). New R1-06 legs at the end of the
 * backend loop: probe C (review-settlement-c-strand /
 * review-lead-closeout-strand) and the receipt-first crash window (K4).
 *
 * The plan marks T7 GREEN-only (it is meaningful only once the settlement
 * exists). On C1 e62b1973 every leg fails with an AssertionError because the
 * settlement does not exist there (Verify refuses on the vault-wide PENDING
 * record with zero durable steps, so no crash window opens and no end state
 * converges); these failures are recorded, not treated as the item's RED
 * evidence of a design property.
 *
 * GREEN after F5: for a contested Pause and a contested Close & recover that
 * landed at depth D, SIGKILL before every durable step of the Verify
 * settlement (inside and between completePositive and settleLoser) leaves a
 * state from which the NEXT Verify converges to exactly the uninterrupted end
 * state (canonical: sorted keys, volatile timestamps dropped, audit rows as a
 * multiset — so every idempotent step is proven idempotent); the ordering
 * invariants hold at every kill point (a CHAIN_VERIFIED winner implies the
 * advanced manifest and its receipt; a non-terminal loser is STALE only after
 * the winner is CHAIN_VERIFIED; a terminal manifest implies every loser is
 * already STALE); a SIGKILL right after the terminal manifest write leaves
 * the loser STALE and the next Verify finishes the owner's record with no node
 * call (finishRecorded); the converged end states are identical on JSON and
 * PostgreSQL.
 *
 * Layers: SDK + CRASH-RECOVERY. Real v0.4.1 compiler, pv_call_encoder,
 * TEST-key signatures and pv_vm_preflight for every consensus byte. The
 * killed Verify runs in a FRESH child process (sdk/testutil/rc45-f5-kit.js
 * verify child) against the same JSON root or PostgreSQL database with the
 * serialized chain model; nothing dials a node (ws://127.0.0.1:1).
 * Candidate-written bases: a delegate spend D and the owner's break-glass Q
 * finalized apart and merged (D holds the only claim; plan §2.3).
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
const V = Object.freeze({ cp: K.vault("t7-cp"), cr: K.vault("t7-cr"), uw: K.vault("t7-r106-uw") });
const roots = [], stores = [], databases = [];
let admin = null, serial = 0, history = null, B = null, w = null, templateRoot = null;
const mk = (prefix) => { const dir = K.ownedTempRoot(prefix); roots.push(dir); return dir; };

async function resolved(fn, message) {
  let value;
  await assert.doesNotReject(async () => { value = await fn(); }, message);
  return value;
}

before(async () => {
  assert.ok(TOOLCHAIN, "real compiler, encoder and VM are required (a missing VM toolchain is a FAIL, never a SKIP)");
  const template = cand.config.loadConfig({ dataRoot: mk("pv-rc45-f5-t7-template-"), rpcUrl: LOOPBACK });
  w = K.walletsFor(template);
  const k = K.kitFor(cand, template, w);
  B = {};
  for (const [tag, action] of [["cp", "ownerPause"], ["cr", "ownerRecover"]]) {
    const v = V[tag]; await K.seedVault(cand, template, v, w);
    const d = await k.agentSpend(v, 4); await K.sleep(3);
    const q = await k.ownerOp(v, action);
    await K.finalizeApart(cand, template, [{ requestId: d.requestId, signer: w.agent }, { requestId: q.requestId, signer: w.owner }], { claimHolder: d.requestId, track: (r) => roots.push(r) });
    B[tag] = { d: d.requestId, q: q.requestId };
  }
  // RC45 R1-06: an unsigned winner — an ordinary agent spend BUILT alone on L0 (its transaction is signed outside
  // PolicyVault and lands; Verify completes the BUILT record by its txid, the T4 :678-695 population).
  { const v = V.uw; await K.seedVault(cand, template, v, w);
    const u = await k.agentSpend(v, 3); assert.equal(u.state, "BUILT");
    B.uw = { u: u.requestId }; }
  history = await K.snapshot(cand, template);
  templateRoot = template.dataRoot;
  if (PG_AVAILABLE) admin = new (require("pg").Pool)(PG);
});
after(async () => {
  for (const s of stores) { try { await s.close(); } catch { /* closed */ } }
  if (admin) { for (const db of databases) await admin.query(`DROP DATABASE IF EXISTS ${db} WITH (FORCE)`); await admin.end(); }
  for (const root of roots) K.removeOwnedRoot(root);
});

/* A fresh case whose chain shows the owner's Q landed and confirmed at depth D (L and the owner's fuel spent). */
async function fresh(backend, tag) {
  const x = await openCase(backend);
  const q = await cand.wr4.loadRequest(x.config, B[tag].q);
  x.model.seedInputs(frozenOf(q), q.covenantId); x.model.confirm(frozenOf(q), q.txId); x.model.advance(SETTLE_DEPTH_DAA);
  return x;
}
/* A fresh case with the base history installed and an empty chain model (nothing observed yet). */
async function openCase(backend) {
  const dataRoot = mk("pv-rc45-f5-t7-case-");
  K.warmCompileCache(templateRoot, dataRoot);
  let config, pgDatabase = null;
  if (backend === "PostgreSQL") {
    pgDatabase = `pv_rc45_f5_t7_${process.pid}_${++serial}`;
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
    receipt: (txId) => store.read(Categories.RECEIPT, txId),
    snap: () => K.snapshot(cand, config),
    verify: (v) => cand.reconcile4.reconcileVaultV4(config, v.vaultId, { rpc: model.rpc }),
    submit: (requestId) => cand.submit4.submitWalletRequestV4({ config, requestId, rpc: model.rpc, pollAttempts: 1, pollDelayMs: 0 })
  };
}
async function release(x) {
  if (!x.pgDatabase) return;
  const i = stores.indexOf(x.store);
  if (i >= 0) { stores.splice(i, 1); await x.store.close(); }
}
const stateIn = (snap, requestId) => (snap.records[Categories.REQUEST].find(([k]) => k === requestId) ?? [null, null])[1]?.state ?? null;
const manifestIn = (snap, v) => (snap.records[Categories.VAULT].find(([k]) => k === v.vaultId) ?? [null, null])[1];
const receiptIn = (snap, txId) => (snap.records[Categories.RECEIPT].find(([k]) => k === txId) ?? [null, null])[1];
const recordIn = (snap, category, key) => (snap.records[category].find(([k]) => k === key) ?? [null, null])[1];
/* The delegate's claim on L as the base holds it (the delegate is the only claim holder). */
const baseClaim = (tag) => { const d = recordIn(history, Categories.REQUEST, B[tag].d), key = cand.claims.transitionClaimKey(d.predecessorOutpoint); return { key, claim: recordIn(history, Categories.TRANSITION_CLAIM, key) }; };
/* Plan r2 §4 settleLoser row ("audit (idempotent) -> STALE -> claims -> reservation | claims on a spent outpoint; sweep
 * drops stale reservations"): a kill after the loser's STALE write may leave exactly the loser's transition claim on the
 * spent L, its submission claim and its budget reservation. Nothing else may differ from the uninterrupted end state. */
function loserLeftovers(tag) {
  const d = recordIn(history, Categories.REQUEST, B[tag].d);
  return [[Categories.TRANSITION_CLAIM, cand.claims.transitionClaimKey(d.predecessorOutpoint)], [Categories.SUBMISSION_CLAIM, d.txId], [Categories.TRANSITION_CLAIM, cand.budget.reservationKey(d)]];
}
function canonicalWithout(snap, drops) {
  const records = {};
  for (const [c, entries] of Object.entries(snap.records)) records[c] = entries.filter(([k]) => !drops.some(([dc, dk]) => dc === c && dk === k));
  return K.canonicalState({ records, audit: snap.audit });
}
/* Every window converges to the reference; only a kill inside settleLoser after its STALE write may leave the loser's leftovers. */
function assertConverged(o, tag, reference) {
  const drops = loserLeftovers(tag);
  assert.equal(canonicalWithout(o.convergedSnap, drops), canonicalWithout(reference, drops), `window ${o.k}: the next Verify converges to the uninterrupted end state`);
  const left = drops.filter(([c, k]) => recordIn(o.convergedSnap, c, k) !== null);
  if (left.length) assert.equal(stateIn(o.atKill, B[tag].d), "STALE", `window ${o.k}: loser leftovers (${left.map(([, k]) => k).join(", ")}) arise only from a kill after the loser's STALE write (plan §4)`);
  else assert.equal(K.canonicalState(o.convergedSnap), K.canonicalState(reference), `window ${o.k}: full convergence`);
}

/* ---------------- RC45 R1-06 helpers ---------------- */
const settle = (promise) => promise.then((value) => ({ value, error: null }), (error) => ({ value: null, error }));
const said = (outcome) => (outcome.error ? `${outcome.error.code ?? "no code"}: ${String(outcome.error.message).slice(0, 240)}` : `success (${JSON.stringify(outcome.value && outcome.value.request ? { state: outcome.value.request.state } : outcome.value && outcome.value.state ? { state: outcome.value.state } : null)})`);
/*
 * One in-process store fault (the next matching durable step throws instead of being performed; equivalent to a
 * crash at that step for this pass, as the review probes inject it). Every store mutation the kit counts as a durable
 * step (write, createExclusive, remove, appendAudit) is wrapped; `when(name, args, performed)` sees the steps already
 * performed. Restored by the caller.
 */
function storeFault(store, when) {
  const names = ["write", "createExclusive", "remove", "appendAudit"], own = {}, performed = [];
  let fired = false;
  for (const name of names) {
    own[name] = Object.prototype.hasOwnProperty.call(store, name) ? store[name] : undefined;
    const original = store[name].bind(store);
    store[name] = async (...args) => {
      if (!fired && when(name, args, performed)) {
        fired = true;
        throw Object.assign(new Error(`TEST store fault at ${name} ${String(args[0])}/${String(args[1])}`), { code: "ECONNRESET" });
      }
      const out = await original(...args);
      performed.push([name, args[0], args[1]]);
      return out;
    };
  }
  return { get fired() { return fired; }, restore() { for (const name of names) { if (own[name] === undefined) delete store[name]; else store[name] = own[name]; } } };
}
/* The review's fault: the winner's CHAIN_VERIFIED relabel (the last durable step of its completion). */
const atRelabel = (r) => (name, args) => name === "write" && args[0] === Categories.REQUEST && args[1] === r.requestId && args[2] && args[2].state === "CHAIN_VERIFIED";
/* AT the manifest advance (the manifest write throws; it is not performed). */
const atManifest = (v) => (name, args) => name === "write" && args[0] === Categories.VAULT && args[1] === v.vaultId;
/* Right AFTER the manifest advance: the first durable step after the manifest write throws. */
const afterManifest = (v) => (_name, _args, performed) => performed.some(([n, c, k]) => n === "write" && c === Categories.VAULT && k === v.vaultId);
/* Run one Verify of `v` under `when`; the pass must have been interrupted by the fault. */
async function faultedVerify(x, v, when, label) {
  const f = storeFault(x.store, when);
  let outcome;
  try { outcome = await settle(x.verify(v)); } finally { f.restore(); }
  assert.equal(f.fired, true, `${label}: the injected fault fired`);
  assert.ok(outcome.error && /TEST store fault/.test(String(outcome.error.message)), `${label}: the faulted Verify stopped at the fault (${said(outcome)})`);
}
/* The receipt exactly as the completion writes it (sdk/src/reconcile-v4.js completeRecord: create-only, keyed by txid). */
async function completionReceipt(x, r) {
  const e = require(path.join(__dirname, "..", "src", "wallet-recovery-v4.js")).validateIdentity(x.config, r).expected;
  return { schema: "policyvault-receipt/v1", txId: r.txId, vaultId: r.vaultId, action: r.action,
    proof: { requestId: r.requestId, successorOutpoint: e.kind === "recover" ? null : `${r.txId}:${e.index}`, value: e.valueSompi, reconciled: true }, verifiedAt: new Date().toISOString() };
}
/*
 * Probe C's strand (review-settlement-c-strand, review-lead-closeout-strand): the delegate's spend W (= D) lands and is
 * CONFIRMED at depth D over the owner's contested Pause Q; Verify's completion of W stops at `when`; then, before the
 * owner's next Verify, the delegate's ordinary spend P2 on L1 is finalized and submitted and completes uncontested at
 * zero depth (L-2), so the manifest moves past W's successor.
 */
async function probeC(backend, opened, when, label) {
  const x = await openCase(backend); opened.push(x);
  const d = await x.req(B.cp.d), q = await x.req(B.cp.q);
  x.model.seedInputs(frozenOf(q), q.covenantId);
  x.model.confirm(frozenOf(d), d.txId); x.model.advance(SETTLE_DEPTH_DAA);
  await faultedVerify(x, V.cp, when(d), label);
  assert.equal((await x.rawManifest(V.cp)).latestTransitionTxId, d.txId, `${label}: the manifest is advanced by the executed winner W`);
  assert.equal((await x.rawRequest(d.requestId)).state, "PREFLIGHT_VERIFIED", `${label}: W is not relabelled`);
  const p2 = await x.k.finalize(await x.k.agentSpend(V.cp, 2), w.agent);
  assert.equal(p2.state, "PREFLIGHT_VERIFIED", "the delegate's ordinary spend P2 on L1 finalizes (W on the ancestor L0 blocks nothing)");
  x.model.know(p2); x.model.confirmOnSubmit = true;
  let run;
  try { run = await settle(x.submit(p2.requestId)); } finally { x.model.confirmOnSubmit = false; }
  assert.equal(run.error, null, `P2's ordinary submit completes (${said(run)})`);
  assert.equal(run.value.request.state, "CHAIN_VERIFIED");
  assert.equal((await x.rawManifest(V.cp)).latestTransitionTxId, p2.txId, "the manifest moved past W's successor (P2 at zero depth, L-2)");
  return { x, d, q, p2 };
}

/* The uninterrupted reference, then one SIGKILL window per durable step until the child completes. */
async function sweep(backend, tag, opened) {
  const v = V[tag], ref = await fresh(backend, tag); opened.push(ref);
  const done = await resolved(() => ref.verify(v), "the uninterrupted Verify at depth D answers");
  assert.equal(done.status, "ADVANCED", "the uninterrupted Verify settles the landed break-glass at depth D");
  const q = await ref.rawRequest(B[tag].q);
  assert.equal(q.state, "CHAIN_VERIFIED");
  const reference = await ref.snap();
  const windows = [];
  for (let k = 0; ; k++) {
    assert.ok(k <= 40, "the settlement completes within 40 durable steps");
    const x = await fresh(backend, tag); opened.push(x);
    const run = K.verifyInChild(x, v, { killBefore: k, pg: PG });
    const killed = run.signal === "SIGKILL";
    if (!killed) {
      assert.equal(run.signal, null, `window ${k}: the child ended by ${run.signal}: ${run.stderr}`);
      assert.equal(run.status, 0, `window ${k}: the child failed: ${run.stderr}`);
      assert.ok(run.result && run.result.ok, `window ${k}: the uninterrupted child Verify answers (${JSON.stringify(run.result)})`);
    }
    const atKill = await x.snap();
    const next = await resolved(() => x.verify(v), `window ${k}: the next Verify answers`);
    const converged = await x.snap();
    const again = await resolved(() => x.verify(v), `window ${k}: a further Verify answers`);
    windows.push({ k, killed, atKill, next, convergedSnap: converged, stable: K.canonicalState(await x.snap()) === K.canonicalState(converged), again });
    if (!killed) break;
  }
  return { reference, windows };
}

const PG_SKIP = PG_AVAILABLE ? undefined : "REQUIREMENT_NOT_AVAILABLE in this process: isolated PostgreSQL (the rc45 runner's pg mode runs these legs; a skipped PostgreSQL leg there is a FAIL)";
for (const [backend, skip] of [["JSON", undefined], ["PostgreSQL", PG_SKIP]]) {
  const t7 = (name, fn) => test(`RC45 T7 ${backend}: ${name}`, { skip }, async () => { const opened = []; try { await fn(opened); } finally { for (const x of opened) await release(x); } });

  t7("contested Pause (non-terminal): SIGKILL before every durable step inside and between completePositive and settleLoser; the next Verify converges to the uninterrupted end state (a kill after the loser's STALE write may leave only its claims and reservation, plan §4); ordering invariants hold at every kill point; R1-06 C3 re-pin: the winner's receipt is the first durable write of its completion (after exactly one durable step only the receipt exists; an advanced manifest implies the receipt) [GREEN-only; fails on C1] [RED on dc7552e]", async (opened) => {
    const { reference, windows } = await sweep(backend, "cp", opened);
    assert.ok(windows.filter((o) => o.killed).length >= 6, "the settlement spans several durable steps (winner and loser)");
    const q = B.cp.q, d = B.cp.d, held = baseClaim("cp");
    assert.ok(held.claim, "the delegate holds the claim on L in the base");
    for (const o of windows) {
      if (stateIn(o.atKill, d) === "PREFLIGHT_VERIFIED") assert.deepEqual(recordIn(o.atKill, Categories.TRANSITION_CLAIM, held.key), held.claim, `window ${o.k}: a loser not yet superseded keeps its claim byte-identical (R: never release another txid's claim, sabotage l)`);
      const qs = stateIn(o.atKill, q), ds = stateIn(o.atKill, d), m = manifestIn(o.atKill, V.cp), txId = (o.atKill.records[Categories.REQUEST].find(([k]) => k === q) ?? [])[1]?.txId;
      if (qs === "CHAIN_VERIFIED") {
        assert.equal(m.latestTransitionTxId, txId, `window ${o.k}: a CHAIN_VERIFIED winner implies the advanced manifest (CHAIN_VERIFIED last)`);
        assert.ok(receiptIn(o.atKill, txId), `window ${o.k}: and its receipt`);
      }
      if (ds === "STALE") assert.equal(qs, "CHAIN_VERIFIED", `window ${o.k}: a non-terminal loser is superseded only after the winner completed`);
      assertConverged(o, "cp", reference);
      assert.ok(o.stable, `window ${o.k}: a further Verify writes nothing`);
    }
    // RC45 R1-06 C3 (PLAN-R1 r2 §2 R1-06 "Receipt before manifest"; declared changed-by-design re-pin of the crash
    // points): the create-only receipt of the winner is the first durable write of its completion.
    const qTx = recordIn(history, Categories.REQUEST, q).txId, first = windows.find((o) => o.k === 1);
    assert.ok(first && first.killed, "a crash window after exactly one durable step exists");
    assert.equal(receiptIn(first.atKill, qTx)?.proof?.requestId, q, "after exactly one durable step the winner's own receipt exists: the receipt is the first durable write of the completion (R1-06 C3)");
    assert.equal(canonicalWithout(first.atKill, [[Categories.RECEIPT, qTx]]), canonicalWithout(windows[0].atKill, [[Categories.RECEIPT, qTx]]), "after exactly one durable step nothing but the winner's receipt is written (the manifest is not yet advanced)");
    for (const o of windows) {
      if (manifestIn(o.atKill, V.cp).latestTransitionTxId === qTx) assert.equal(receiptIn(o.atKill, qTx)?.proof?.requestId, q, `window ${o.k}: an advanced manifest implies the winner's receipt (R1-06 C3: receipt before manifest)`);
    }
  });
  t7("contested Close & recover (terminal): SIGKILL before every durable step; losers are settled before the terminal manifest at every kill point and the next Verify converges to the uninterrupted end state (loser leftovers only after its STALE write, plan §4); R1-06 C3 re-pin: a terminal manifest implies the winner's receipt (receipt before manifest) [GREEN-only; fails on C1] [RED on dc7552e]", async (opened) => {
    const { reference, windows } = await sweep(backend, "cr", opened);
    assert.ok(windows.filter((o) => o.killed).length >= 6, "the settlement spans several durable steps (losers and winner)");
    const held = baseClaim("cr");
    for (const o of windows) {
      if (stateIn(o.atKill, B.cr.d) === "PREFLIGHT_VERIFIED") assert.deepEqual(recordIn(o.atKill, Categories.TRANSITION_CLAIM, held.key), held.claim, `window ${o.k}: a loser not yet superseded keeps its claim byte-identical (sabotage l)`);
      const m = manifestIn(o.atKill, V.cr);
      if (m.status === "RECOVERED") assert.equal(stateIn(o.atKill, B.cr.d), "STALE", `window ${o.k}: a terminal manifest implies the loser is already STALE (losers first, sabotage x)`);
      assertConverged(o, "cr", reference);
      assert.ok(o.stable, `window ${o.k}: a further Verify writes nothing`);
    }
    // RC45 R1-06 C3 (declared changed-by-design re-pin): the winner's receipt precedes its terminal manifest. The
    // receipt's position relative to the losers is not pinned (the plan fixes only receipt-before-manifest here).
    const qTx = recordIn(history, Categories.REQUEST, B.cr.q).txId;
    for (const o of windows) {
      if (manifestIn(o.atKill, V.cr).status === "RECOVERED") assert.equal(receiptIn(o.atKill, qTx)?.proof?.requestId, B.cr.q, `window ${o.k}: a terminal manifest implies the winner's receipt (R1-06 C3: receipt before manifest)`);
    }
  });
  t7("recover winner (CR-M3): SIGKILL right after the terminal manifest write leaves the loser STALE and (R1-06 C3 re-pin) the winner's receipt already written; the next Verify finishes the owner's record with no node call (finishRecorded, sabotage y) [GREEN-only; fails on C1] [RED on dc7552e]", async (opened) => {
    const x = await fresh(backend, "cr"); opened.push(x);
    const run = K.verifyInChild(x, V.cr, { killAfterTerminalManifest: true, pg: PG });
    assert.equal(run.signal, "SIGKILL", `the child was killed right after the terminal manifest write (child answered ${JSON.stringify(run.result)}; ${run.stderr})`);
    const m = await x.rawManifest(V.cr);
    assert.equal(m.status, "RECOVERED"); assert.equal(m.live, null);
    assert.equal((await x.rawRequest(B.cr.d)).state, "STALE", "losers are settled before the terminal manifest (sabotage x)");
    const q = await x.rawRequest(B.cr.q);
    assert.notEqual(q.state, "CHAIN_VERIFIED", "the owner's record is not yet complete at the kill point");
    assert.equal((await x.receipt(q.txId))?.proof?.requestId, q.requestId, "the winner's receipt precedes the terminal manifest (R1-06 C3: the receipt is the first durable write of the completion)");
    const calls = x.model.calls.length;
    const next = await resolved(() => x.verify(V.cr), "the next Verify answers");
    assert.equal(next.status, "TERMINAL");
    assert.equal(x.model.calls.length, calls, "finishing a recorded advancement needs no node call");
    assert.equal((await x.rawRequest(B.cr.q)).state, "CHAIN_VERIFIED", "the owner's record is finished (step 3 finishRecorded)");
    assert.equal((await x.receipt(q.txId)).proof.requestId, q.requestId);
  });

  /* ---------------- RC45 R1-06 (ST-03; C2, C3, K4, K5): probe C as a permanent T7 leg ---------------- */
  /* After the strand, a submit of W must never label the executed W STALE: W's own receipt (receiptMatches: proof.requestId,
   * the expected outpoint and value) answers 422 RECONCILIATION_REQUIRED with nothing written, before
   * predecessorDispositionV4 and so before any node call (K4); the next Verify finishes W CHAIN_VERIFIED from its
   * recorded proof in any hop position (C2). */
  async function submitRefusedThenFinished(x, d, receipt) {
    const before = await x.snap(), calls = x.model.calls.length;
    const sub = await settle(x.submit(d.requestId));
    assert.equal(sub.error?.code, "RECONCILIATION_REQUIRED", `a submit of the executed W answers 422 RECONCILIATION_REQUIRED from the receipt guard, whatever the staleness verdict (got ${said(sub)})`);
    assert.deepEqual(await x.snap(), before, "the refused submit writes nothing (W is never labelled STALE)");
    assert.equal(x.model.calls.length, calls, "the receipt guard answers before any node call");
    x.model.advance(SETTLE_DEPTH_DAA);
    await resolved(() => x.verify(V.cp), "the next Verify at D answers");
    assert.equal((await x.rawRequest(d.requestId)).state, "CHAIN_VERIFIED", "the next Verify finishes the executed W CHAIN_VERIFIED from its recorded proof (C2, any hop position)");
    assert.deepEqual(await x.receipt(d.txId), receipt, "W's own receipt is kept byte-identical (H-40)");
    const settledSnap = await x.snap();
    await resolved(() => x.verify(V.cp), "a further Verify answers");
    assert.deepEqual(await x.snap(), settledSnap, "a further Verify writes nothing");
  }
  t7("R1-06 probe C, the review's fault (review-settlement-c-strand, review-lead-closeout-strand B): Verify's completion of the executed delegate spend W (CONFIRMED at D over the owner's contested Pause) faults at W's CHAIN_VERIFIED relabel, leaving W PREFLIGHT_VERIFIED with its own receipt; an ordinary spend P2 then completes on L1 at zero depth; a later submit of W answers 422 RECONCILIATION_REQUIRED with nothing written and no node call (never STALE); the next Verify at D finishes W CHAIN_VERIFIED, its receipt byte-identical; a further Verify writes nothing [RED on dc7552e]", async (opened) => {
    const { x, d } = await probeC(backend, opened, atRelabel, "probe C (relabel fault)");
    const receipt = await x.receipt(d.txId);
    assert.equal(receipt?.proof?.requestId, d.requestId, "W's own receipt is written before the faulted relabel");
    await submitRefusedThenFinished(x, d, receipt);
  });
  t7("R1-06 probe C, fault right after the manifest write: the receipt precedes the manifest (C3), so W's own receipt exists when the completion stops after the manifest advance; after an ordinary spend P2 completes on L1 at zero depth, a submit of W answers 422 RECONCILIATION_REQUIRED with nothing written and no node call (never STALE); the next Verify at D finishes W CHAIN_VERIFIED, its receipt byte-identical; a further Verify writes nothing [RED on dc7552e]", async (opened) => {
    const { x, d } = await probeC(backend, opened, (r) => afterManifest(V.cp), "probe C (fault after the manifest write)");
    const receipt = await x.receipt(d.txId);
    assert.equal(receipt?.proof?.requestId, d.requestId, "the receipt is the first durable write of the completion, so a stop after the manifest advance leaves W's own receipt (R1-06 C3)");
    await submitRefusedThenFinished(x, d, receipt);
  });
  t7("R1-06 probe C, Verify alone (review-lead-closeout-strand A): after the review's fault and P2's zero-depth completion on L1, the owner's next Verify at D finishes the executed W (two hops back) CHAIN_VERIFIED from its recorded proof with its receipt byte-identical, and a further Verify writes nothing [RED on dc7552e]", async (opened) => {
    const { x, d } = await probeC(backend, opened, atRelabel, "probe C (relabel fault)");
    const receipt = await x.receipt(d.txId);
    assert.equal(receipt?.proof?.requestId, d.requestId);
    x.model.advance(SETTLE_DEPTH_DAA);
    await resolved(() => x.verify(V.cp), "the owner's next Verify answers");
    assert.equal((await x.rawRequest(d.requestId)).state, "CHAIN_VERIFIED", "Verify finishes the stranded executed W in any hop position (C2)");
    assert.deepEqual(await x.receipt(d.txId), receipt, "W's own receipt is kept byte-identical");
    const settledSnap = await x.snap();
    await resolved(() => x.verify(V.cp), "a further Verify answers");
    assert.deepEqual(await x.snap(), settledSnap, "a further Verify writes nothing");
  });

  t7("R1-06 probe C, a winner in another SIGNED_OR_REJECTED state (C2): the owner's contested Pause Q is submitted (contested: SUBMITTED, no poll) and lands; Verify's completion of Q at D faults at Q's CHAIN_VERIFIED relabel (Q SUBMITTED with its own receipt); the owner's ordinary ownerUnpause then completes on Q's successor at zero depth; the next Verify at D finishes the SUBMITTED Q CHAIN_VERIFIED from its recorded proof, its receipt byte-identical; a further Verify writes nothing [RED on dc7552e]", async (opened) => {
    const x = await openCase(backend); opened.push(x);
    const q = await x.req(B.cp.q);
    x.model.seedInputs(frozenOf(q), q.covenantId); x.model.know(q);
    const sub = await settle(x.submit(q.requestId));
    assert.equal(sub.error, null, `the owner's contested Pause is submitted (${said(sub)})`);
    assert.equal(sub.value.request.state, "SUBMITTED", "a contested break-glass submit returns at SUBMITTED");
    x.model.confirm(frozenOf(q), q.txId); x.model.advance(SETTLE_DEPTH_DAA);
    await faultedVerify(x, V.cp, atRelabel(q), "contested Pause (relabel fault)");
    assert.equal((await x.rawManifest(V.cp)).latestTransitionTxId, q.txId);
    assert.equal((await x.rawRequest(q.requestId)).state, "SUBMITTED", "Q keeps its SUBMITTED label");
    const receipt = await x.receipt(q.txId);
    assert.equal(receipt?.proof?.requestId, q.requestId, "Q's own receipt is written before the faulted relabel");
    const u = await x.k.finalize(await x.k.ownerOp(V.cp, "ownerUnpause", "fuel2"), w.owner);
    assert.equal(u.state, "PREFLIGHT_VERIFIED", "the owner's ordinary ownerUnpause on Q's successor finalizes");
    frozenOf(u).inputs.forEach((i, index) => { if (index > 0) x.model.add(i.previousOutpoint, i.utxo.amount, i.utxo.scriptPublicKey, null, x.model.virtualDaaScore - 5000n); }); // the owner's fuel
    x.model.know(u); x.model.confirmOnSubmit = true;
    let run;
    try { run = await settle(x.submit(u.requestId)); } finally { x.model.confirmOnSubmit = false; }
    assert.equal(run.error, null, `the ordinary ownerUnpause completes (${said(run)})`);
    assert.equal(run.value.request.state, "CHAIN_VERIFIED");
    assert.equal((await x.rawManifest(V.cp)).latestTransitionTxId, u.txId, "the manifest moved past Q's successor");
    x.model.advance(SETTLE_DEPTH_DAA);
    await resolved(() => x.verify(V.cp), "the next Verify at D answers");
    assert.equal((await x.rawRequest(q.requestId)).state, "CHAIN_VERIFIED", "Verify finishes the executed SUBMITTED Q from its recorded proof (C2: any SIGNED_OR_REJECTED state, any hop position)");
    assert.deepEqual(await x.receipt(q.txId), receipt, "Q's own receipt is kept byte-identical");
    const settledSnap = await x.snap();
    await resolved(() => x.verify(V.cp), "a further Verify answers");
    assert.deepEqual(await x.snap(), settledSnap, "a further Verify writes nothing");
  });

  /* ---------------- RC45 R1-06 K4: the receipt-first crash window (receipt written, manifest not advanced) ---------------- */
  const unsignedCase = async (opened) => {
    const x = await openCase(backend); opened.push(x);
    const u = await x.req(B.uw.u);
    assert.equal(u.state, "BUILT"); assert.equal(u.finalTransaction, undefined, "never signed through PolicyVault");
    x.model.confirm(frozenOf(u), u.txId); x.model.advance(SETTLE_DEPTH_DAA); // signed outside PolicyVault; landed at depth D
    return { x, u };
  };
  async function uninterrupted(open, v, label) {
    const ref = await open();
    const done = await resolved(() => ref.x.verify(v), `${label}: the uninterrupted Verify answers`);
    assert.equal(done.status, "ADVANCED", `${label}: the uninterrupted Verify completes the winner at D`);
    return ref.x.snap();
  }
  async function assertReceiptOnly(x, base, r, label) {
    const atFault = await x.snap();
    assert.equal(receiptIn(atFault, r.txId)?.proof?.requestId, r.requestId, `${label}: the winner's own receipt is written before the manifest advance (R1-06 C3: the receipt is the first durable write of a completion)`);
    assert.equal(canonicalWithout(atFault, [[Categories.RECEIPT, r.txId]]), canonicalWithout(base, [[Categories.RECEIPT, r.txId]]), `${label}: nothing but the receipt is written; the manifest is not advanced`);
    return atFault;
  }
  async function signedWindowSubmit(x, q, atWindow, reference) {
    const calls = x.model.calls.length;
    const sub = await settle(x.submit(q.requestId));
    assert.equal(sub.error?.code, "RECONCILIATION_REQUIRED", `a submit of the signed winner in the crash window answers 422 RECONCILIATION_REQUIRED (got ${said(sub)})`);
    assert.deepEqual(await x.snap(), atWindow, "the refused submit writes nothing");
    assert.equal(x.model.calls.length, calls, "the receipt guard runs before predecessorDispositionV4, so before any node call");
    await resolved(() => x.verify(V.cp), "the next Verify answers");
    assert.equal(K.canonicalState(await x.snap()), K.canonicalState(reference), "the next Verify converges to the uninterrupted end state");
  }
  async function unsignedWindowFinalize(x, u, atWindow, reference) {
    const fin = await settle(x.k.finalize(u, w.agent));
    assert.equal(fin.error?.code, "RECONCILIATION_REQUIRED", `a finalize of the unsigned winner (the agent's real TEST-key signature) in the crash window answers 422 RECONCILIATION_REQUIRED (got ${said(fin)})`);
    assert.deepEqual(await x.snap(), atWindow, "the refused finalize writes nothing (no bytes, no claim, no relabel)");
    await resolved(() => x.verify(V.uw), "the next Verify answers");
    assert.equal(K.canonicalState(await x.snap()), K.canonicalState(reference), "the next Verify converges to the uninterrupted end state");
  }
  t7("R1-06 crash window (K4), signed winner: Verify's completion of the owner's Pause Q (CONFIRMED at D over the delegate's spend) stops AT its manifest advance; exactly Q's receipt has been written (the receipt is the first durable write of a completion) and the manifest is not advanced; a submit of Q then answers 422 RECONCILIATION_REQUIRED with nothing written and no node call; the next Verify converges to the uninterrupted end state [RED on dc7552e]", async (opened) => {
    const reference = await uninterrupted(async () => { const x = await fresh(backend, "cp"); opened.push(x); return { x }; }, V.cp, "signed winner");
    const x = await fresh(backend, "cp"); opened.push(x);
    const q = await x.req(B.cp.q), base = await x.snap();
    await faultedVerify(x, V.cp, atManifest(V.cp), "signed winner (fault at the manifest advance)");
    const atWindow = await assertReceiptOnly(x, base, q, "signed winner");
    await signedWindowSubmit(x, q, atWindow, reference);
  });
  t7("R1-06 crash window (K4), unsigned winner: Verify's completion of an ordinary BUILT agent spend (signed outside PolicyVault, landed at D) stops AT its manifest advance; exactly its receipt has been written and the manifest is not advanced; a finalize of that winner then answers 422 RECONCILIATION_REQUIRED with nothing written; the next Verify converges to the uninterrupted end state [RED on dc7552e]", async (opened) => {
    const reference = await uninterrupted(() => unsignedCase(opened), V.uw, "unsigned winner");
    const { x, u } = await unsignedCase(opened);
    const base = await x.snap();
    await faultedVerify(x, V.uw, atManifest(V.uw), "unsigned winner (fault at the manifest advance)");
    const atWindow = await assertReceiptOnly(x, base, u, "unsigned winner");
    await unsignedWindowFinalize(x, u, atWindow, reference);
  });
  t7("R1-06 crash window (K4), SYNTHETIC receipt-first state for the unsigned winner (the receipt exactly as the completion writes it, create-only; the manifest not advanced): a finalize of the winner answers 422 RECONCILIATION_REQUIRED with nothing written; the next Verify converges to the uninterrupted end state [RED on dc7552e]", async (opened) => {
    const reference = await uninterrupted(() => unsignedCase(opened), V.uw, "unsigned winner");
    const { x, u } = await unsignedCase(opened);
    assert.equal(await x.store.createExclusive(Categories.RECEIPT, u.txId, await completionReceipt(x, u)), true, "SYNTHETIC: the receipt-first completion's first durable write");
    await unsignedWindowFinalize(x, u, await x.snap(), reference);
  });
  t7("R1-06 crash window (K4), SYNTHETIC receipt-first state for the signed winner (the owner's Pause Q's receipt exactly as the completion writes it, create-only; the manifest not advanced): a submit of Q answers 422 RECONCILIATION_REQUIRED with nothing written and no node call; the next Verify converges to the uninterrupted end state [RED on dc7552e]", async (opened) => {
    const reference = await uninterrupted(async () => { const x = await fresh(backend, "cp"); opened.push(x); return { x }; }, V.cp, "signed winner");
    const x = await fresh(backend, "cp"); opened.push(x);
    const q = await x.req(B.cp.q);
    assert.equal(await x.store.createExclusive(Categories.RECEIPT, q.txId, await completionReceipt(x, q)), true, "SYNTHETIC: the receipt-first completion's first durable write");
    await signedWindowSubmit(x, q, await x.snap(), reference);
  });
}
test("RC45 T7 JSON/PostgreSQL canonical parity: the uninterrupted and the crash-converged end states of both settlements are identical on both stores [GREEN-only; fails on C1]", { skip: PG_SKIP }, async () => {
  const opened = [];
  try {
    for (const tag of ["cp", "cr"]) {
      const states = {};
      for (const backend of ["JSON", "PostgreSQL"]) {
        const x = await fresh(backend, tag); opened.push(x);
        const out = await resolved(() => x.verify(V[tag]), `${backend}: the Verify answers`);
        assert.equal(out.status, "ADVANCED", `${backend}: the settlement runs`);
        // Full-convergence windows (plan §4): non-terminal, right after the first durable step (at dc7552e the manifest
        // write, then settleOneHop finishes; after RC45 R1-06 C3 the winner's receipt, then the next Verify re-enters
        // step 7 and completes); terminal, right after the RECOVERED manifest write (then finishRecorded finishes).
        const y = await fresh(backend, tag); opened.push(y);
        const run = K.verifyInChild(y, V[tag], tag === "cr" ? { killAfterTerminalManifest: true, pg: PG } : { killBefore: 1, pg: PG });
        assert.equal(run.signal, "SIGKILL", `${backend}: the crash window exists`);
        await resolved(() => y.verify(V[tag]), `${backend}: the next Verify converges`);
        states[backend] = { clean: K.canonicalState(await x.snap()), crashed: K.canonicalState(await y.snap()) };
      }
      assert.equal(states.JSON.clean, states.PostgreSQL.clean, `${tag}: JSON and PostgreSQL settle to the same canonical state`);
      assert.equal(states.JSON.crashed, states.PostgreSQL.crashed, `${tag}: and converge to it after the same crash window`);
      assert.equal(states.JSON.crashed, states.JSON.clean, `${tag}: the crash window converges to the clean state`);
    }
  } finally { for (const x of opened) await release(x); }
});
