"use strict";
/*
 * RC45 T4 — THE FINALIZE CRASH GAP (fix item F4 RC45-L5-FINALIZE-GAP; plan
 * rc45-simplified-plan-r2 §1 O2, §2.0 claim-error rule, §2.1(3)-(4), §2.3
 * finalize row, §2.4 (1)-(4) and "historical shapes", §4 finalize rows and
 * crash windows, L-9, L-16, §8 T4, §8.2 sabotage d/u1/u2/w). Internal RED-first
 * regression material for the RC45 candidate; not an audit.
 *
 * RED on C1 e62b1973 (finalize persists FINALIZED before its VM preflight and
 * claims; its claim catch sends every error to failRequestClosed(CLAIM_CONFLICT);
 * every close saves the load-time snapshot; submit refuses a PREFLIGHT_VERIFIED
 * record whose own claim is missing; Verify cannot complete a byte-less record
 * by its txid). GREEN after F4 (with F2's scoped guard, F3's contest and F5's
 * Verify settlement where a leg names them):
 *   - finalize never writes FINALIZED; its first request write is
 *     PREFLIGHT_VERIFIED with the bytes; an ordinary finalize claims first
 *     (W2 -> W1 -> W3 -> W4 -> audit), a break-glass one writes W1 first
 *     (W1 -> W2 absent/same/foreign -> W3 -> W4 -> audit);
 *   - a VM harness throw leaves the record BUILT with no write;
 *   - claim-error rule: after a claimTransition error the claim is read back:
 *     a foreign txid is a conflict (ordinary: CLAIM_CONFLICT close while BUILT,
 *     no bytes; break-glass: contested, never relabelled), the same txid is own,
 *     anything else (absent, store or read error) is rethrown with no write;
 *   - re-reads before the first durable write and before W1 fail closed with no
 *     further write when the record is no longer BUILT (reject / Verify races);
 *     every finalize close re-reads and writes only an unchanged BUILT record;
 *   - after W1 submit completes, re-creating a missing own claim;
 *   - RC44's byte-less FINALIZED completes by its txid at depth D = 1000 DAA or
 *     loses to an owner Pause (STALE).
 *
 * Layers: SDK. Real v0.4.1 compiler, pv_call_encoder, TEST-key signatures
 * (deterministic dev signer) and pv_vm_preflight for every consensus byte.
 * Node observations come ONLY from the explicit chain model below (UTXO sets
 * with blockDaaScore, a virtualDaaScore, a mempool with conflict detection,
 * rusty-kaspa v2.0.1 wire texts); every config names ws://127.0.0.1:1, so
 * nothing can dial a node. SIGKILL crash windows run the candidate finalize in
 * a FRESH child process (this file in "rc45-t4-finalize-child" mode) against
 * the same JSON root or PostgreSQL database and kill it at a durable step.
 *
 * RC44-written shapes (CR-M13): the byte-less FINALIZED and the age-released
 * PREFLIGHT_VERIFIED come from the pinned df5b8de writers in
 * POLICYVAULT_TEST_RC44_TREE (sdk/testutil/rc45-rc44-history.js; a missing or
 * mismatched tree FAILS, never skips). Candidate-written bases are labelled.
 *
 * Both stores: JSON always; PostgreSQL with POLICYVAULT_TEST_PG_{PORT,USER,
 * DATABASE} (the rc45 runner's pg mode; a skipped PostgreSQL leg there is a
 * FAIL). TEST keys only; no production data, credentials or endpoints.
 */
const path = require("node:path"), fs = require("node:fs");
const assert = require("node:assert/strict");
const H44 = require("../testutil/rc45-rc44-history");
const { KAS, LOOPBACK, T4_VAULTS: V, modulesOf, walletsFor, seedVault, kitFor, clone } = H44;

const CHILD_MODE = "rc45-t4-finalize-child", CHILD_TAG = "RC45-T4-CHILD-RESULT ";
const SETTLE_DEPTH_DAA = 1000n; // plan r2 §2.0 D
const ANCHOR = "31".repeat(32);
const frozenOf = (request) => JSON.parse(request.build.frozenCanonicalJson);

/* THE CHAIN MODEL (plan r2 §8 rules). UTXOs carry blockDaaScore; the DAG
 * reports a virtualDaaScore; submitTransaction admits a registered
 * transaction to the mempool only when every input is unspent and unclaimed
 * by another mempool transaction, answering as rusty-kaspa v2.0.1 does
 * (rpc/core/src/error.rs "Rejected transaction {id}: {reason}" over
 * mining/errors/src/mempool.rs reasons). Outputs appear only through
 * confirm() (or confirmOnSubmit). Historical acceptance and mempool bodies
 * are not modelled and answer as unavailable (fail closed). */
function chainModel(config) {
  const kaspa = require(config.rustyKaspaModule);
  const utxos = new Map(), mempool = new Map(), known = new Map(), calls = [], broadcasts = [];
  const state = { virtualDaaScore: 90_000_000n, confirmOnSubmit: false };
  const key = (o) => `${String(o.transactionId).toLowerCase()}:${Number(o.index)}`;
  const addressOf = (spk) => kaspa.addressFromScriptPublicKey({ version: Number(spk.version), script: spk.scriptHex }, config.networkId).toString();
  function add(outpoint, amount, spk, covenantId, blockDaaScore = state.virtualDaaScore) {
    utxos.set(key(outpoint), { address: addressOf(spk), outpoint: { transactionId: String(outpoint.transactionId).toLowerCase(), index: Number(outpoint.index) }, amount: String(amount),
      scriptPublicKey: { version: Number(spk.version), script: spk.scriptHex }, covenantId: covenantId ?? null, blockDaaScore: String(blockDaaScore), isCoinbase: false });
  }
  /* The inputs of `tx` as settled UTXOs (deep: 5,000 DAA below the virtual). */
  function seedInputs(tx, covenantId) {
    tx.inputs.forEach((i, index) => add(i.previousOutpoint, i.utxo.amount, i.utxo.scriptPublicKey, index === 0 ? covenantId : (i.utxo.covenantId ?? null), state.virtualDaaScore - 5000n));
  }
  /* `tx` accepted in a block at `blockDaaScore` (default: the current virtual score, depth 0). */
  function confirm(tx, txId, blockDaaScore = state.virtualDaaScore) {
    for (const i of tx.inputs) utxos.delete(key(i.previousOutpoint));
    mempool.delete(txId);
    tx.outputs.forEach((o, index) => add({ transactionId: txId, index }, o.value, o.scriptPublicKey, o.covenant?.covenantId ?? null, blockDaaScore));
  }
  const rpc = {
    async getUtxosByAddresses({ addresses }) {
      calls.push("getUtxosByAddresses");
      const wanted = new Set(addresses.map(String));
      return { entries: [...utxos.values()].filter((u) => wanted.has(u.address)).map(clone) };
    },
    async getBlockDagInfo() { calls.push("getBlockDagInfo"); return { networkName: `kaspa-${config.networkId}`, sink: ANCHOR, virtualDaaScore: String(state.virtualDaaScore) }; },
    async getMempoolEntry({ transactionId }) {
      calls.push("getMempoolEntry");
      const id = String(transactionId).toLowerCase();
      if (!mempool.has(id)) throw new Error(`Transaction ${id} not found`);
      throw new Error("TEST chain model: mempool entry bodies are not modelled (unavailable)");
    },
    async getVirtualChainFromBlock() { calls.push("getVirtualChainFromBlock"); throw new Error("TEST chain model: virtual-chain acceptance history is not modelled (unavailable)"); },
    async submitTransaction({ transaction }) {
      calls.push("submitTransaction");
      const id = transaction.finalize().toString().toLowerCase();
      broadcasts.push(id);
      const tx = known.get(id);
      if (!tx) throw new Error(`TEST chain model: transaction ${id} was never registered with the model`);
      if (mempool.has(id)) throw new Error(`Rejected transaction ${id}: transaction ${id} is already in the mempool`);
      for (const i of tx.inputs) {
        for (const [other, entry] of mempool) {
          if (entry.spends.includes(key(i.previousOutpoint))) throw new Error(`Rejected transaction ${id}: output (${i.previousOutpoint.transactionId}, ${i.previousOutpoint.index}) already spent by transaction ${other} in the mempool`);
        }
      }
      if (tx.inputs.some((i) => !utxos.has(key(i.previousOutpoint)))) throw new Error(`Rejected transaction ${id}: transaction ${id} is an orphan where orphan is disallowed`);
      mempool.set(id, { spends: tx.inputs.map((i) => key(i.previousOutpoint)) });
      if (state.confirmOnSubmit) confirm(tx, id);
      return { transactionId: id };
    },
    async disconnect() { calls.push("disconnect"); }
  };
  return {
    rpc, add, seedInputs, confirm, calls, broadcasts,
    know(request) { known.set(request.txId, clone(request.finalTransaction)); },
    advance(daa) { state.virtualDaaScore += BigInt(daa); },
    set confirmOnSubmit(value) { state.confirmOnSubmit = value === true; },
    get virtualDaaScore() { return state.virtualDaaScore; }
  };
}

/* The transition claim a finalize takes for `r` (shape of wallet-requests-v4 finalize). */
function claimArgsFor(r) {
  const b = r.build, index = b.frozen.outputs.findIndex((o) => o.covenant !== null);
  const expected = { kind: "successor", txId: r.txId, index, valueSompi: (BigInt(b.successorState.protectedValue) + BigInt(b.successorState.feeReserve)).toString(), covenantId: r.covenantId,
    scriptSha256: b.successorScriptSha256, stateId: r.successorStateId, state: b.successorState, newRegistry: r.newRegistry, action: r.sdkAction, contractVersion: r.contractVersion };
  return { outpoint: r.predecessorOutpoint, action: r.action, txId: r.txId, vaultId: r.vaultId, stateId: r.predecessorStateId, expected };
}

/* ======================================================================
 * FINALIZE CHILD (fresh process): the candidate finalize, killed with
 * SIGKILL at a chosen durable step. Every store mutation (write,
 * createExclusive, remove, appendAudit) is one durable step; `killBefore = k`
 * kills before step k+1 (i.e. after k durable steps); `killAfterClaim` kills
 * right after the transition claim on the predecessor outpoint is durable.
 * ==================================================================== */
async function finalizeChild(input) {
  const cand = modulesOf(path.join(__dirname, "..", "src"));
  let config;
  if (input.pg) {
    config = cand.config.loadConfig({ persistenceBackend: "postgres", pgHost: input.pg.host, pgPort: input.pg.port, pgUser: input.pg.user, pgDatabase: input.pg.database, pgNoTls: true, hostedDevOpen: true, dataRoot: input.dataRoot, rpcUrl: LOOPBACK });
    await cand.store.openPgStore(config, { migrate: false });
  } else config = cand.config.loadConfig({ dataRoot: input.dataRoot, rpcUrl: LOOPBACK });
  assert.equal(config.networkId, "testnet-10");
  const store = cand.store.getStore(config), C = cand.store.Categories;
  let steps = 0;
  const die = () => { process.kill(process.pid, "SIGKILL"); return new Promise(() => {}); };
  for (const name of ["write", "createExclusive", "remove", "appendAudit"]) {
    const original = store[name].bind(store);
    store[name] = async (...args) => {
      if (input.killBefore === steps) await die();
      steps += 1;
      const out = await original(...args);
      if (input.killAfterClaim && name === "createExclusive" && args[0] === C.TRANSITION_CLAIM && args[1] === input.claimKey && out === true) await die();
      return out;
    };
  }
  let result;
  try {
    const done = await cand.wr4.finalizeWalletRequestV4({ config, requestId: input.requestId, signedSafeJson: input.signedSafeJson });
    result = { ok: true, state: done.state, steps };
  } catch (error) {
    result = { ok: false, code: error.code ?? null, message: String(error.message), steps };
  }
  if (input.pg) await store.close();
  return result;
}

if (process.argv[2] === CHILD_MODE) {
  finalizeChild(JSON.parse(process.argv[3])).then(
    (result) => { process.stdout.write(`${CHILD_TAG}${JSON.stringify(result)}\n`); },
    (error) => { process.stderr.write(`${error && error.stack ? error.stack : error}\n`); process.exitCode = 1; }
  );
} else {
  const { test, before, after } = require("node:test");
  const cp = require("node:child_process");
  const cand = modulesOf(path.join(__dirname, "..", "src"));
  const { Categories } = cand.store;
  const TOOLCHAIN = require("../testutil/org-root-durable-fixture").toolchainAvailable();
  const PG = { host: process.env.POLICYVAULT_TEST_PG_HOST || "127.0.0.1", port: Number(process.env.POLICYVAULT_TEST_PG_PORT || 0), user: process.env.POLICYVAULT_TEST_PG_USER, database: process.env.POLICYVAULT_TEST_PG_DATABASE };
  const PG_AVAILABLE = Boolean(PG.port && PG.user && PG.database);
  const CATEGORIES = [Categories.VAULT, Categories.REQUEST, Categories.SUBMISSION_CLAIM, Categories.TRANSITION_CLAIM, Categories.RECEIPT];
  const roots = [], stores = [], databases = [];
  let admin = null, serial = 0, history = null, H = null, B = null, w = null;
  const mk = (prefix) => { const dir = H44.ownedTempRoot(prefix); roots.push(dir); return dir; };

  async function records(config) {
    const s = cand.store.getStore(config), out = {};
    for (const c of CATEGORIES) out[c] = await Promise.all((await s.listKeys(c)).sort().map(async (k) => [k, await s.read(c, k)]));
    return out;
  }
  async function snapshot(config) { return { records: await records(config), audit: await cand.store.getStore(config).readAudit({ limit: 5000 }) }; }
  async function install(config, snap) {
    const s = cand.store.getStore(config);
    for (const [c, entries] of Object.entries(snap.records)) for (const [k, v] of entries) await s.write(c, k, clone(v));
    for (const row of [...snap.audit].reverse()) await s.appendAudit(clone(row));
  }
  const inSnap = (snap, category, key) => (snap.records[category].find(([k]) => k === key) ?? [null, null])[1];
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
  async function until(predicate, ms = 240000) {
    const end = Date.now() + ms;
    while (!predicate()) { if (Date.now() > end) return false; await new Promise((resolve) => setTimeout(resolve, 10)); }
    return true;
  }
  const storeFault = (what) => Object.assign(new Error(`TEST store fault: connection terminated during ${what}`), { code: "ECONNRESET" });

  before(async () => {
    assert.ok(TOOLCHAIN, "real compiler, encoder and VM are required (a missing VM toolchain is a FAIL, never a SKIP)");
    // (1) RC44-written histories, by the pinned df5b8de writers only (fz: byte-less FINALIZED; ag: age-released PREFLIGHT_VERIFIED).
    const rc44 = H44.runRc44Scenario("t4", { track: (root) => roots.push(root) });
    H = rc44.result.hist;
    // (2) One template root: the RC44 records plus the candidate-written bases.
    const template = cand.config.loadConfig({ dataRoot: mk("pv-rc45-t4-template-"), rpcUrl: LOOPBACK });
    await install(template, await snapshot(cand.config.loadConfig({ dataRoot: rc44.dataRoot, rpcUrl: LOOPBACK })));
    w = walletsFor(template);
    const k = kitFor(cand, template, w), pick = (r) => ({ requestId: r.requestId, txId: r.txId, predecessorOutpoint: r.predecessorOutpoint });
    B = {};
    { await seedVault(cand, template, V.ord, w); const r = await k.agentSpend(V.ord, 4); assert.equal(r.state, "BUILT"); B.ord = { r: pick(r) }; }
    { await seedVault(cand, template, V.race, w);
      const r1 = await k.agentSpend(V.race, 3), r2 = await k.agentSpend(V.race, 4);
      assert.notEqual(r1.txId, r2.txId); B.race = { r1: pick(r1), r2: pick(r2) }; }
    { await seedVault(cand, template, V.bg, w); const q = await k.ownerOp(V.bg, "ownerPause"); assert.equal(q.state, "BUILT"); B.bg = { q: pick(q) }; }
    { await seedVault(cand, template, V.bgc, w);
      const q = await k.ownerOp(V.bgc, "ownerPause"), d = await k.agentSpend(V.bgc, 2);
      assert.equal(q.state, "BUILT"); assert.equal(d.state, "BUILT"); B.bgc = { q: pick(q), d: pick(d) }; }
    { // twin: A and its same-txid twin T built on L0; A finalized (A holds the one claim), T stays BUILT.
      await seedVault(cand, template, V.twin, w);
      const a0 = await k.agentSpend(V.twin, 4), t = await k.agentSpend(V.twin, 4);
      assert.equal(t.txId, a0.txId, "the same spend on the same live state freezes the same transaction (twin)");
      const a = await k.finalize(a0, w.agent); assert.equal(a.state, "PREFLIGHT_VERIFIED");
      B.twin = { a: pick(a), t: pick(t) }; }
    history = await snapshot(template);
    if (PG_AVAILABLE) admin = new (require("pg").Pool)(PG);
  });
  after(async () => {
    for (const s of stores) { try { await s.close(); } catch { /* closed */ } }
    if (admin) { for (const db of databases) await admin.query(`DROP DATABASE IF EXISTS ${db} WITH (FORCE)`); await admin.end(); }
    for (const root of roots) H44.removeOwnedRoot(root);
  });

  async function fresh(backend) {
    const dataRoot = mk("pv-rc45-t4-case-");
    let config, pgDatabase = null;
    if (backend === "PostgreSQL") {
      pgDatabase = `pv_rc45_t4_${process.pid}_${++serial}`;
      await admin.query(`CREATE DATABASE ${pgDatabase}`); databases.push(pgDatabase);
      config = cand.config.loadConfig({ persistenceBackend: "postgres", pgHost: PG.host, pgPort: PG.port, pgUser: PG.user, pgDatabase, pgNoTls: true, hostedDevOpen: true, dataRoot, rpcUrl: LOOPBACK });
      stores.push(await cand.store.openPgStore(config, { migrate: true }));
      assert.equal(cand.store.getStore(config).kind, "postgres");
    } else config = cand.config.loadConfig({ dataRoot, rpcUrl: LOOPBACK });
    await install(config, history);
    const store = cand.store.getStore(config), model = chainModel(config);
    const x = {
      config, store, model, pgDatabase, k: kitFor(cand, config, w),
      req: (requestId) => cand.wr4.loadRequest(config, requestId),
      rawRequest: (requestId) => store.read(Categories.REQUEST, requestId),
      rawManifest: (v) => store.read(Categories.VAULT, v.vaultId),
      claimOn: (outpoint) => store.read(Categories.TRANSITION_CLAIM, cand.claims.transitionClaimKey(outpoint)),
      submissionClaim: (txId) => store.read(Categories.SUBMISSION_CLAIM, txId),
      reservationOf: (r) => store.read(Categories.TRANSITION_CLAIM, cand.budget.reservationKey(r)),
      audit: () => store.readAudit({ limit: 5000 }),
      snap: () => snapshot(config),
      submit: (requestId) => cand.submit4.submitWalletRequestV4({ config, requestId, rpc: model.rpc, pollAttempts: 1, pollDelayMs: 0 }),
      verify: (v) => cand.reconcile4.reconcileVaultV4(config, v.vaultId, { rpc: model.rpc })
    };
    return x;
  }
  /* Close a case's PostgreSQL pool as soon as its test ends (the database itself is dropped in after()). */
  async function release(x) {
    if (!x.pgDatabase) return;
    const i = stores.indexOf(x.store);
    if (i >= 0) { stores.splice(i, 1); await x.store.close(); }
  }
  /* Run the candidate finalize in a fresh child against x's store (killed with SIGKILL as asked). */
  function finalizeInChild(x, input) {
    const payload = { requestId: input.requestId, signedSafeJson: input.signedSafeJson, killBefore: input.killBefore ?? null, killAfterClaim: input.killAfterClaim === true,
      claimKey: input.claimKey ?? null, dataRoot: x.config.dataRoot, pg: x.pgDatabase ? { host: PG.host, port: PG.port, user: PG.user, database: x.pgDatabase } : null };
    const env = { ...process.env, ...(input.env ?? {}) };
    const child = cp.spawnSync(process.execPath, [__filename, CHILD_MODE, JSON.stringify(payload)], { encoding: "utf8", timeout: 300000, maxBuffer: 16 * 1024 * 1024, env });
    const line = (child.stdout || "").split("\n").find((l) => l.startsWith(CHILD_TAG));
    return { signal: child.signal, status: child.status, stderr: (child.stderr || "").slice(-4000), result: line ? JSON.parse(line.slice(CHILD_TAG.length)) : null };
  }

  /* One SIGKILL sweep: a fresh root per crash window, k = 0, 1, ... until the child completes. */
  async function crashSweep(backend, requestId, opened) {
    const windows = [];
    for (let k = 0; ; k++) {
      assert.ok(k <= 24, "the finalize completes within 24 durable steps");
      const x = await fresh(backend); opened.push(x);
      const r = await x.req(requestId), before = await x.rawRequest(requestId), audit = await x.audit();
      const signer = r.signerRole === "owner" ? w.owner : w.agent, signedSafeJson = x.k.sign(r, signer);
      const run = finalizeInChild(x, { requestId, signedSafeJson, killBefore: k });
      const killed = run.signal === "SIGKILL";
      if (!killed) {
        assert.equal(run.signal, null, `window ${k}: the child ended by ${run.signal}: ${run.stderr}`);
        assert.equal(run.status, 0, `window ${k}: the child failed: ${run.stderr}`);
        assert.ok(run.result && run.result.ok === true, `window ${k}: the uninterrupted finalize completes (${JSON.stringify(run.result)})`);
      }
      windows.push({ k, killed, x, r, signer, signedSafeJson, before, auditBefore: audit.length,
        request: await x.rawRequest(requestId), claim: await x.claimOn(r.predecessorOutpoint), submission: await x.submissionClaim(r.txId),
        reservation: r.sdkAction === "agentSpend" ? await x.reservationOf(r) : null, auditAfter: (await x.audit()).length });
      if (!killed) break;
    }
    return windows;
  }

  const PG_SKIP = PG_AVAILABLE ? undefined : "REQUIREMENT_NOT_AVAILABLE in this process: isolated PostgreSQL (the rc45 runner's pg mode runs these legs; a skipped PostgreSQL leg there is a FAIL)";
  for (const [backend, skip] of [["JSON", undefined], ["PostgreSQL", PG_SKIP]]) {
    const t4 = (name, fn) => test(`RC45 T4 ${backend}: ${name}`, { skip }, async () => { const x = await fresh(backend); try { await fn(x); } finally { await release(x); } });
    const t4sweep = (name, fn) => test(`RC45 T4 ${backend}: ${name}`, { skip }, async () => { const opened = []; try { await fn(opened); } finally { for (const x of opened) await release(x); } });

    /* ---------------- SIGKILL crash windows (sabotage d, u2) ---------------- */
    t4sweep("SIGKILL at each durable step of an ordinary finalize never leaves FINALIZED; before W1 the record is untouched, after W1 it carries its own claim; every window converges (retry or submit) [RED on C1]", async (opened) => {
      const windows = await crashSweep(backend, B.ord.r.requestId, opened);
      assert.ok(windows.length >= 3 && windows.some((o) => o.killed), "several crash windows were exercised");
      assert.deepEqual(windows.filter((o) => ["FINALIZED", "SIGNED"].includes(o.request.state)).map((o) => o.k), [],
        "no crash window leaves FINALIZED (or SIGNED): the only FINALIZED writer is deleted (plan §2.4(1))");
      for (const o of windows) {
        assert.ok(["BUILT", "PREFLIGHT_VERIFIED"].includes(o.request.state), `window ${o.k}: ${o.request.state} is neither BUILT nor PREFLIGHT_VERIFIED`);
        if (o.claim) assert.equal(o.claim.txId, o.r.txId, `window ${o.k}: a claim on the predecessor is this finalize's own`);
        assert.ok(o.reservation, `window ${o.k}: a crashed finalize never releases its reservation`);
        if (o.request.state === "BUILT") {
          assert.deepEqual(o.request, o.before, `window ${o.k}: before W1 the request record is byte-identical (its first request write is PREFLIGHT_VERIFIED)`);
          assert.equal(o.submission, null, `window ${o.k}: no submission claim before W1`);
          assert.equal(o.auditAfter, o.auditBefore, `window ${o.k}: no audit row before W1`);
        } else {
          assert.ok(o.request.finalTransaction, `window ${o.k}: PREFLIGHT_VERIFIED carries the signed bytes`);
          assert.equal(o.request.txId, o.r.txId);
          assert.ok(o.claim, `window ${o.k}: an ordinary PREFLIGHT_VERIFIED record always has its own claim (W2 precedes W1, sabotage u2)`);
        }
      }
      assert.deepEqual(windows.map((o) => o.request.state).filter((s, i, a) => a.indexOf(s) === i), ["BUILT", "PREFLIGHT_VERIFIED"], "the windows move BUILT -> PREFLIGHT_VERIFIED once");
      for (const o of windows) {
        if (o.request.state === "BUILT") {
          const done = await resolved(() => cand.wr4.finalizeWalletRequestV4({ config: o.x.config, requestId: o.r.requestId, signedSafeJson: o.signedSafeJson }), `window ${o.k}: the retry finalizes (a left claim is its own)`);
          assert.equal(done.state, "PREFLIGHT_VERIFIED");
          assert.equal((await o.x.claimOn(o.r.predecessorOutpoint)).txId, o.r.txId);
        }
        const stored = await o.x.req(o.r.requestId);
        o.x.model.know(stored); o.x.model.seedInputs(frozenOf(stored), stored.covenantId); o.x.model.confirmOnSubmit = true;
        const submitted = await resolved(() => o.x.submit(o.r.requestId), `window ${o.k}: after W1 submit completes (a missing claim or submission claim is re-created)`);
        assert.equal(submitted.request.state, "CHAIN_VERIFIED");
        assert.deepEqual(o.x.model.broadcasts, [o.r.txId]);
        assert.equal((await o.x.rawManifest(V.ord)).latestTransitionTxId, o.r.txId);
      }
    });
    t4sweep("SIGKILL at each durable step of an owner break-glass finalize never leaves FINALIZED; after W1 (no claim yet) submit re-creates the claim and completes [RED on C1]", async (opened) => {
      const windows = await crashSweep(backend, B.bg.q.requestId, opened);
      assert.ok(windows.length >= 3 && windows.some((o) => o.killed), "several crash windows were exercised");
      assert.deepEqual(windows.filter((o) => ["FINALIZED", "SIGNED"].includes(o.request.state)).map((o) => o.k), [],
        "no crash window leaves FINALIZED (or SIGNED): the only FINALIZED writer is deleted (plan §2.4(1))");
      for (const o of windows) {
        assert.ok(["BUILT", "PREFLIGHT_VERIFIED"].includes(o.request.state), `window ${o.k}: ${o.request.state} is neither BUILT nor PREFLIGHT_VERIFIED`);
        if (o.claim) assert.equal(o.claim.txId, o.r.txId, `window ${o.k}: a claim on the predecessor is this finalize's own`);
        if (o.request.state === "BUILT") {
          assert.deepEqual(o.request, o.before, `window ${o.k}: before W1 the request record is byte-identical`);
          assert.equal(o.claim, null, `window ${o.k}: break-glass writes W1 before its claim`);
        } else assert.ok(o.request.finalTransaction, `window ${o.k}: PREFLIGHT_VERIFIED carries the signed bytes`);
      }
      assert.ok(windows.some((o) => o.killed && o.request.state === "PREFLIGHT_VERIFIED" && o.claim === null), "a window after W1 and before W2 leaves PREFLIGHT_VERIFIED without a claim (break-glass order W1 -> W2)");
      for (const o of windows) {
        if (o.request.state === "BUILT") {
          const done = await resolved(() => cand.wr4.finalizeWalletRequestV4({ config: o.x.config, requestId: o.r.requestId, signedSafeJson: o.signedSafeJson }), `window ${o.k}: the retry finalizes`);
          assert.equal(done.state, "PREFLIGHT_VERIFIED");
        }
        const stored = await o.x.req(o.r.requestId);
        o.x.model.know(stored); o.x.model.seedInputs(frozenOf(stored), stored.covenantId); o.x.model.confirmOnSubmit = true;
        const submitted = await resolved(() => o.x.submit(o.r.requestId), `window ${o.k}: after W1 the uncontested Pause submit completes, re-creating its own claim`);
        assert.equal(submitted.request.state, "CHAIN_VERIFIED");
        assert.deepEqual(o.x.model.broadcasts, [o.r.txId]);
        const m = await o.x.rawManifest(V.bg);
        assert.equal(m.status, "PAUSED"); assert.equal(m.latestTransitionTxId, o.r.txId);
      }
    });
    t4("claim-then-crash: SIGKILL right after the ordinary claim is durable leaves BUILT + its own claim; the retry reads the claim back as its own and finalizes [RED on C1]", async (x) => {
      const r = await x.req(B.ord.r.requestId), before = await x.rawRequest(r.requestId), key = cand.claims.transitionClaimKey(r.predecessorOutpoint);
      const signedSafeJson = x.k.sign(r, w.agent);
      const run = finalizeInChild(x, { requestId: r.requestId, signedSafeJson, killAfterClaim: true, claimKey: key });
      assert.equal(run.signal, "SIGKILL", `the child was killed right after the claim (${run.stderr})`);
      assert.deepEqual(await x.rawRequest(r.requestId), before, "the request is still BUILT and byte-identical: no request write precedes the ordinary claim (W2 -> W1)");
      const claim = await x.claimOn(r.predecessorOutpoint);
      assert.equal(claim.txId, r.txId, "the claim is the finalize's own");
      assert.equal((await x.reservationOf(r)).status, "ACTIVE", "the reservation is not yet consumed");
      const done = await resolved(() => cand.wr4.finalizeWalletRequestV4({ config: x.config, requestId: r.requestId, signedSafeJson }), "retry own: the same-txid claim is read back as its own");
      assert.equal(done.state, "PREFLIGHT_VERIFIED"); assert.ok(done.finalTransaction);
      assert.deepEqual(await x.claimOn(r.predecessorOutpoint), claim, "the one claim is byte-identical (no second claim)");
      assert.equal((await x.reservationOf(r)).status, "CONSUMED");
    });

    /* ---------------- harness throw leaves BUILT (sabotage d) ---------------- */
    t4("a VM harness throw (the preflight binary fails to run) leaves the record BUILT with no write; the retry finalizes [RED on C1]", async (x) => {
      const r = await x.req(B.ord.r.requestId), signedSafeJson = x.k.sign(r, w.agent), before = await x.snap();
      const dir = mk("pv-rc45-t4-harness-"), harness = path.join(dir, "pv_vm_preflight_failing");
      fs.writeFileSync(harness, "#!/bin/sh\necho 'TEST harness: engine unavailable' 1>&2\nexit 3\n", { mode: 0o755 });
      const run = finalizeInChild(x, { requestId: r.requestId, signedSafeJson, env: { POLICYVAULT_PV_VM_PREFLIGHT_PATH: harness } });
      assert.equal(run.signal, null); assert.equal(run.status, 0, run.stderr);
      assert.equal(run.result.ok, false, "the harness failure refuses the finalize");
      assert.match(run.result.message, /harness/, "the refusal is the harness spawn failure (vm-preflight.js:46-59)");
      assert.deepEqual(await x.snap(), before, "a harness throw writes nothing: the request stays BUILT, no claim, reservation and audit unchanged");
      const done = await resolved(() => cand.wr4.finalizeWalletRequestV4({ config: x.config, requestId: r.requestId, signedSafeJson }), "the retry with a working harness finalizes");
      assert.equal(done.state, "PREFLIGHT_VERIFIED");
    });

    /* ---------------- RC44-written byte-less FINALIZED (historical shapes) ---------------- */
    t4("an RC44-written byte-less FINALIZED on the live outpoint blocks ordinary builds and completes by its txid once SEEN at depth D (no write below D) [RED on C1]", async (x) => {
      const r = await x.req(H.fz.r.requestId);
      assert.equal(r.state, "FINALIZED"); assert.equal(r.finalTransaction, undefined, "the RC44 writer left no signed bytes");
      assert.equal(await x.claimOn(r.predecessorOutpoint), null, "RC44 took no claim before the crash");
      await assert.rejects(x.k.agentSpend(V.fz, 1), { code: "REQUEST_RECOVERY_REQUIRED" }, "it blocks ordinary builds on the live outpoint");
      const frozen = frozenOf(r), index = frozen.outputs.findIndex((o) => o.covenant !== null);
      x.model.confirm(frozen, r.txId); // the signer broadcast the signed transaction out of band; it spent L0
      x.model.advance(SETTLE_DEPTH_DAA - 1n);
      const below = await x.snap();
      await settle(x.verify(V.fz));
      assert.deepEqual(await x.snap(), below, "depth D-1: nothing is written");
      x.model.advance(1n);
      const out = await resolved(() => x.verify(V.fz), "Verify at depth D");
      assert.equal(out.status, "ADVANCED", "the byte-less record completes by its txid (SEEN at depth D)");
      assert.equal(out.txId, r.txId);
      const after = await x.rawRequest(r.requestId);
      assert.equal(after.state, "CHAIN_VERIFIED"); assert.equal(after.finalTransaction, undefined, "no bytes are invented");
      const m = await x.rawManifest(V.fz);
      assert.equal(m.latestTransitionTxId, r.txId); assert.deepEqual(m.live.outpoint, { transactionId: r.txId, index });
      assert.equal((await x.store.read(Categories.RECEIPT, r.txId)).proof.requestId, r.requestId, "the receipt names the request");
      assert.equal(await x.reservationOf(r), null, "its reservation is released");
    });
    t4("an RC44-written byte-less FINALIZED loses to an owner Pause: the Pause completes at depth D and the FINALIZED record becomes STALE [RED on C1]", async (x) => {
      const r = await x.req(H.fz.r.requestId);
      assert.equal(r.state, "FINALIZED"); assert.equal(r.finalTransaction, undefined);
      x.model.seedInputs(frozenOf(r), r.covenantId); // L0 live
      const built = await resolved(() => x.k.ownerOp(V.fz, "ownerPause"), "the owner's Pause is never refused on a live vault");
      const q = await resolved(() => x.k.finalize(built, w.owner), "the Pause finalizes");
      assert.equal(q.state, "PREFLIGHT_VERIFIED");
      x.model.know(q); x.model.seedInputs(frozenOf(q), q.covenantId);
      await settle(x.submit(q.requestId));
      assert.deepEqual(x.model.broadcasts, [q.txId], "the signed Pause reached the node once");
      x.model.confirm(frozenOf(q), q.txId); x.model.advance(SETTLE_DEPTH_DAA);
      await resolved(() => x.verify(V.fz), "Verify at depth D");
      const loser = await x.rawRequest(r.requestId);
      assert.equal(loser.state, "STALE", "the byte-less FINALIZED lost to the confirmed Pause");
      assert.equal(loser.finalTransaction, undefined);
      assert.equal((await x.rawRequest(q.requestId)).state, "CHAIN_VERIFIED");
      const m = await x.rawManifest(V.fz);
      assert.equal(m.status, "PAUSED"); assert.equal(m.latestTransitionTxId, q.txId);
      const superseded = (await x.audit()).filter((e) => e.action === "transition_superseded");
      assert.equal(superseded.length, 1, "one transition_superseded row");
      assert.equal(superseded[0].requestId, r.requestId); assert.equal(superseded[0].txId, r.txId); assert.equal(superseded[0].winnerTxId, q.txId);
      assert.equal(await x.reservationOf(r), null, "the loser's reservation is released");
    });
    t4("after W1: an RC44 PREFLIGHT_VERIFIED whose claims RC44 released by age — submit re-creates its own claim and completes [RED on C1]", async (x) => {
      const a = await x.req(H.ag.a.requestId);
      assert.equal(a.state, "PREFLIGHT_VERIFIED"); assert.ok(a.finalTransaction);
      assert.equal(await x.claimOn(a.predecessorOutpoint), null, "RC44 released the claim by age (case C)");
      x.model.know(a); x.model.seedInputs(frozenOf(a), a.covenantId); x.model.confirmOnSubmit = true;
      const done = await resolved(() => x.submit(a.requestId), "submit re-creates the missing own claim");
      assert.equal(done.request.state, "CHAIN_VERIFIED");
      assert.deepEqual(x.model.broadcasts, [a.txId]);
      assert.equal((await x.rawManifest(V.ag)).latestTransitionTxId, a.txId);
    });

    /* ---------------- races (CR-H1, CR2-L8; sabotage u2) ---------------- */
    t4("race: two ordinary finalizes held past the guard and first re-read before either W2 -> one PREFLIGHT_VERIFIED, the loser CLAIM_CONFLICT while BUILT with no bytes [RED on C1]", async (x) => {
      const r1 = await x.req(B.race.r1.requestId), r2 = await x.req(B.race.r2.requestId), key = cand.claims.transitionClaimKey(r1.predecessorOutpoint);
      assert.deepEqual(r2.predecessorOutpoint, r1.predecessorOutpoint, "both spend the live L0");
      const before = { [r1.txId]: await x.rawRequest(r1.requestId), [r2.txId]: await x.rawRequest(r2.requestId) };
      const s1 = x.k.sign(r1, w.agent), s2 = x.k.sign(r2, w.agent);
      const s = x.store, create = s.createExclusive.bind(s), atBarrier = {};
      let open; const gate = new Promise((resolve) => { open = resolve; });
      s.createExclusive = async (c, k, v) => {
        if (c === Categories.TRANSITION_CLAIM && k === key) {
          const rec = v.txId === r1.txId ? r1 : r2;
          atBarrier[v.txId] = await s.read(Categories.REQUEST, rec.requestId);
          await gate;
        }
        return create(c, k, v);
      };
      let p1 = null, p2 = null, done1 = false, done2 = false;
      try {
        p1 = settle(cand.wr4.finalizeWalletRequestV4({ config: x.config, requestId: r1.requestId, signedSafeJson: s1 })).then((o) => { done1 = true; return o; });
        await until(() => r1.txId in atBarrier || done1);
        p2 = settle(cand.wr4.finalizeWalletRequestV4({ config: x.config, requestId: r2.requestId, signedSafeJson: s2 })).then((o) => { done2 = true; return o; });
        await until(() => r2.txId in atBarrier || done2);
      } finally { open(); }
      const [o1, o2] = await Promise.all([p1, p2]);
      s.createExclusive = create;
      assert.ok(r1.txId in atBarrier, "the first finalize reached W2 (its claim)");
      assert.deepEqual(atBarrier[r1.txId], before[r1.txId], "at W2 the first finalize's record is still BUILT and byte-identical (no request write precedes an ordinary claim)");
      assert.ok(r2.txId in atBarrier, `the second finalize also passed the guard and its first re-read (it was ${o2.error ? `refused ${o2.error.code}` : "not held"})`);
      assert.deepEqual(atBarrier[r2.txId], before[r2.txId], "at W2 the second record is BUILT and byte-identical too");
      const outcomes = [[r1, o1], [r2, o2]], winners = outcomes.filter(([, o]) => !o.error), losers = outcomes.filter(([, o]) => o.error);
      assert.equal(winners.length, 1, "exactly one finalize wins"); assert.equal(losers.length, 1);
      const [winner, win] = winners[0], [loser, lose] = losers[0];
      assert.equal(win.value.state, "PREFLIGHT_VERIFIED"); assert.ok(win.value.finalTransaction);
      assert.equal(lose.error.code, "CLAIM_CONFLICT");
      assert.equal((await x.claimOn(winner.predecessorOutpoint)).txId, winner.txId, "the claim names the winner");
      const lost = await x.rawRequest(loser.requestId), { state, error, ...rest } = lost, { state: s0, error: e0, ...rest0 } = before[loser.txId];
      assert.equal(state, "CLAIM_CONFLICT", "the loser is closed CLAIM_CONFLICT while BUILT");
      assert.equal(lost.finalTransaction, undefined, "the loser never carries signed bytes");
      assert.deepEqual(rest, rest0, "the close changes only the label and error (the build txId is kept)");
      assert.equal(await x.reservationOf(loser), null, "the loser's reservation is released");
      assert.equal((await x.reservationOf(winner)).status, "CONSUMED");
      void s0; void e0; void error;
    });
    t4("break-glass race: a delegate claim injected after the owner's pre-read — the Pause is contested, reaches PREFLIGHT_VERIFIED with its bytes and is never relabelled; the delegate claim is untouched [RED on C1]", async (x) => {
      const q = await x.req(B.bgc.q.requestId), d = await x.req(B.bgc.d.requestId), key = cand.claims.transitionClaimKey(q.predecessorOutpoint);
      const heldD = await x.rawRequest(d.requestId), auditBefore = (await x.audit()).length;
      const s = x.store, write = s.write.bind(s), qWrites = []; let injected = null;
      s.write = async (c, k, v) => {
        if (c === Categories.REQUEST && k === q.requestId) {
          qWrites.push(v.state);
          if (!injected) { await cand.claims.claimTransition(x.config, claimArgsFor(d)); injected = await s.read(Categories.TRANSITION_CLAIM, key); }
        }
        return write(c, k, v);
      };
      let done;
      try { done = await resolved(() => x.k.finalize(q, w.owner), "a contested break-glass finalize is not refused"); } finally { s.write = write; }
      assert.ok(injected, "the delegate claim was taken after the owner's pre-read, before W1");
      assert.equal(done.state, "PREFLIGHT_VERIFIED"); assert.ok(done.finalTransaction);
      assert.deepEqual(qWrites.filter((st) => st !== "PREFLIGHT_VERIFIED"), [], "every request write of the Pause is PREFLIGHT_VERIFIED: never FINALIZED, never relabelled after W1");
      const stored = await x.rawRequest(q.requestId);
      assert.equal(stored.state, "PREFLIGHT_VERIFIED"); assert.ok(stored.finalTransaction);
      assert.deepEqual(await x.claimOn(q.predecessorOutpoint), injected, "the delegate's claim is byte-identical (contested: no seizure)");
      assert.deepEqual(await x.rawRequest(d.requestId), heldD, "the delegate request is untouched");
      assert.ok((await x.audit()).length > auditBefore, "the finalize audit row is written");
    });

    /* ---------------- claim-error rule: store errors (CR-H1; sabotage u1) ---------------- */
    t4("store error at the ordinary claim (not written) -> rethrown, no write: BUILT, no claim, reservation and audit unchanged; the retry finalizes [RED on C1]", async (x) => {
      const r = await x.req(B.ord.r.requestId), key = cand.claims.transitionClaimKey(r.predecessorOutpoint), signedSafeJson = x.k.sign(r, w.agent);
      const s = x.store, create = s.createExclusive.bind(s), fault = storeFault("the transition-claim insert"); let fired = false;
      s.createExclusive = async (c, k, v) => { if (c === Categories.TRANSITION_CLAIM && k === key && !fired) { fired = true; throw fault; } return create(c, k, v); };
      const before = await x.snap();
      let error;
      try { error = await rejection(cand.wr4.finalizeWalletRequestV4({ config: x.config, requestId: r.requestId, signedSafeJson })); } finally { s.createExclusive = create; }
      assert.equal(fired, true);
      assert.notEqual(error.code, "CLAIM_CONFLICT", "a store error is never mapped to a claim conflict");
      assert.match(String(error.message), /TEST store fault/, "the store error is rethrown");
      assert.deepEqual(await x.snap(), before, "no write: the ordinary record stays BUILT and retryable");
      const done = await resolved(() => cand.wr4.finalizeWalletRequestV4({ config: x.config, requestId: r.requestId, signedSafeJson }), "the retry finalizes");
      assert.equal(done.state, "PREFLIGHT_VERIFIED");
    });
    t4("store error after the ordinary claim committed (lost acknowledgement) -> the claim reads back as its own -> PREFLIGHT_VERIFIED [RED on C1]", async (x) => {
      const r = await x.req(B.ord.r.requestId), key = cand.claims.transitionClaimKey(r.predecessorOutpoint);
      const s = x.store, create = s.createExclusive.bind(s), fault = storeFault("the transition-claim acknowledgement"); let fired = false;
      s.createExclusive = async (c, k, v) => { const out = await create(c, k, v); if (c === Categories.TRANSITION_CLAIM && k === key && !fired) { fired = true; throw fault; } return out; };
      let done;
      try { done = await resolved(() => x.k.finalize(r, w.agent), "same txid = own"); } finally { s.createExclusive = create; }
      assert.equal(fired, true);
      assert.equal(done.state, "PREFLIGHT_VERIFIED"); assert.ok(done.finalTransaction);
      assert.equal((await x.claimOn(r.predecessorOutpoint)).txId, r.txId);
    });
    t4("store error at the ordinary claim and at its read-back -> rethrown, no write [RED on C1]", async (x) => {
      const r = await x.req(B.ord.r.requestId), key = cand.claims.transitionClaimKey(r.predecessorOutpoint);
      const s = x.store, create = s.createExclusive.bind(s), read = s.read.bind(s); let fired = false;
      s.createExclusive = async (c, k, v) => { if (c === Categories.TRANSITION_CLAIM && k === key && !fired) { fired = true; throw storeFault("the transition-claim insert"); } return create(c, k, v); };
      s.read = async (c, k) => { if (fired && c === Categories.TRANSITION_CLAIM && k === key) throw storeFault("the transition-claim read-back"); return read(c, k); };
      const before = await x.snap();
      let error;
      try { error = await rejection(x.k.finalize(r, w.agent)); } finally { s.createExclusive = create; s.read = read; }
      assert.equal(fired, true);
      assert.notEqual(error.code, "CLAIM_CONFLICT");
      assert.match(String(error.message), /TEST store fault/, "a store or read error is rethrown");
      assert.deepEqual(await x.snap(), before, "no write");
    });
    t4("store error at the break-glass claim -> rethrown; the Pause stays PREFLIGHT_VERIFIED with its bytes and no claim; submit re-creates the claim and completes [RED on C1]", async (x) => {
      const q = await x.req(B.bg.q.requestId), key = cand.claims.transitionClaimKey(q.predecessorOutpoint);
      const s = x.store, create = s.createExclusive.bind(s), write = s.write.bind(s), qWrites = []; let fired = false;
      s.createExclusive = async (c, k, v) => { if (c === Categories.TRANSITION_CLAIM && k === key && !fired) { fired = true; throw storeFault("the transition-claim insert"); } return create(c, k, v); };
      s.write = async (c, k, v) => { if (c === Categories.REQUEST && k === q.requestId) qWrites.push(v.state); return write(c, k, v); };
      const auditBefore = (await x.audit()).length;
      let error;
      try { error = await rejection(x.k.finalize(q, w.owner)); } finally { s.createExclusive = create; s.write = write; }
      assert.equal(fired, true);
      assert.notEqual(error.code, "CLAIM_CONFLICT"); assert.match(String(error.message), /TEST store fault/);
      const stored = await x.rawRequest(q.requestId);
      assert.equal(stored.state, "PREFLIGHT_VERIFIED", "break-glass stays PREFLIGHT_VERIFIED (W1 precedes its claim)");
      assert.ok(stored.finalTransaction, "with its signed bytes");
      assert.deepEqual(qWrites.filter((st) => st !== "PREFLIGHT_VERIFIED"), [], "never FINALIZED, never relabelled");
      assert.equal(await x.claimOn(q.predecessorOutpoint), null, "no claim was written");
      assert.equal((await x.audit()).length, auditBefore, "no further write after the rethrown error");
      x.model.know(stored); x.model.seedInputs(frozenOf(stored), stored.covenantId); x.model.confirmOnSubmit = true;
      const submitted = await resolved(() => x.submit(q.requestId), "submit re-creates the missing own claim");
      assert.equal(submitted.request.state, "CHAIN_VERIFIED");
      assert.equal((await x.rawManifest(V.bg)).status, "PAUSED");
    });
    t4("a same-txid twin finalizes while its twin holds the claim: the claim reads back as its own -> PREFLIGHT_VERIFIED; the one claim byte-identical [RED on C1]", async (x) => {
      const a = await x.req(B.twin.a.requestId), t = await x.req(B.twin.t.requestId), heldA = await x.rawRequest(a.requestId);
      const claim = await x.claimOn(a.predecessorOutpoint);
      assert.equal(claim.txId, a.txId); assert.equal(t.txId, a.txId);
      const done = await resolved(() => x.k.finalize(t, w.agent), "the twin is never refused and its same-txid claim is its own");
      assert.equal(done.state, "PREFLIGHT_VERIFIED"); assert.ok(done.finalTransaction);
      assert.deepEqual(await x.claimOn(a.predecessorOutpoint), claim, "no second claim: the one claim is byte-identical");
      assert.deepEqual(await x.rawRequest(a.requestId), heldA, "the twin holding the claim is untouched");
    });

    /* ---------------- concurrent valid + invalid finalize (CR2-M1; sabotage w) ---------------- */
    for (const [variant, badOf] of [
      ["a wrong-key signature (VM verdict)", (x, r) => x.k.sign(r, w.recipient)],
      ["an unparseable package (SIGNATURE_INVALID verdict)", () => "{ not a signed package"]
    ]) {
      t4(`concurrent valid and invalid finalize of one request (${variant}; the invalid call loads before the valid call's W1) -> the record stays PREFLIGHT_VERIFIED with its bytes and reservation [RED on C1]`, async (x) => {
        const r = await x.req(B.ord.r.requestId), good = x.k.sign(r, w.agent), bad = badOf(x, r);
        const s = x.store, read = s.read.bind(s); let armed = true, loaded = false, releaseInvalid;
        const hold = new Promise((resolve) => { releaseInvalid = resolve; });
        s.read = async (c, k) => { const value = await read(c, k); if (armed && c === Categories.REQUEST && k === r.requestId) { armed = false; loaded = true; await hold; } return value; };
        let invalid, valid, afterValid;
        try {
          invalid = settle(cand.wr4.finalizeWalletRequestV4({ config: x.config, requestId: r.requestId, signedSafeJson: bad }));
          assert.ok(await until(() => loaded), "the invalid call loaded the BUILT record");
          valid = await settle(cand.wr4.finalizeWalletRequestV4({ config: x.config, requestId: r.requestId, signedSafeJson: good }));
          afterValid = await x.snap();
        } finally { releaseInvalid(); }
        const outcome = await invalid;
        s.read = read;
        assert.equal(valid.error, null, `the valid finalize completes (${valid.error && valid.error.message})`);
        assert.equal(valid.value.state, "PREFLIGHT_VERIFIED");
        assert.deepEqual(await x.snap(), afterValid, "the invalid call writes nothing over the finalized record (every close re-reads and writes only an unchanged BUILT record)");
        assert.ok(outcome.error, "the invalid finalize is refused");
        const stored = await x.rawRequest(r.requestId);
        assert.equal(stored.state, "PREFLIGHT_VERIFIED"); assert.deepEqual(stored.finalTransaction, valid.value.finalTransaction);
        assert.equal((await x.reservationOf(r)).status, "CONSUMED", "the reservation stays consumed by the valid finalize");
      });
    }

    /* ---------------- re-reads (CR-L11): reject or Verify mid-finalize ---------------- */
    t4("re-read: a reject between the ordinary finalize's load and its first durable write -> fail closed, no write [RED on C1]", async (x) => {
      const r = await x.req(B.ord.r.requestId), s = x.store, read = s.read.bind(s); let armed = true, afterReject = null;
      s.read = async (c, k) => { const value = await read(c, k); if (armed && c === Categories.REQUEST && k === r.requestId) { armed = false; await cand.wr4.markWalletRejected(x.config, r.requestId); afterReject = await x.snap(); } return value; };
      let outcome;
      try { outcome = await settle(x.k.finalize(r, w.agent)); } finally { s.read = read; }
      assert.ok(afterReject, "the reject ran after the finalize loaded the record");
      assert.equal(inSnap(afterReject, Categories.REQUEST, r.requestId).state, "WALLET_REJECTED");
      assert.deepEqual(await x.snap(), afterReject, "the finalize writes nothing after the reject (no claim, no bytes, no relabel)");
      assert.ok(outcome.error, "the finalize fails closed");
    });
    t4("re-read: a reject after the ordinary claim and before W1 -> fail closed with no further write [RED on C1]", async (x) => {
      const r = await x.req(B.ord.r.requestId), key = cand.claims.transitionClaimKey(r.predecessorOutpoint);
      const s = x.store, create = s.createExclusive.bind(s); let afterReject = null;
      s.createExclusive = async (c, k, v) => {
        const out = await create(c, k, v);
        if (!afterReject && out === true && c === Categories.TRANSITION_CLAIM && k === key) { await cand.wr4.markWalletRejected(x.config, r.requestId); afterReject = await x.snap(); }
        return out;
      };
      let outcome;
      try { outcome = await settle(x.k.finalize(r, w.agent)); } finally { s.createExclusive = create; }
      assert.ok(afterReject, "the reject ran right after the claim was durable");
      assert.equal(inSnap(afterReject, Categories.REQUEST, r.requestId).state, "WALLET_REJECTED", "the reject found the request still BUILT (no request write precedes W1)");
      assert.deepEqual(await x.snap(), afterReject, "no W1, no submission claim, no reservation consumption, no audit after the reject");
      assert.ok(outcome.error, "the finalize fails closed");
    });
    t4("re-read: a reject between a break-glass finalize's load and W1 -> fail closed, no write [RED on C1]", async (x) => {
      const q = await x.req(B.bg.q.requestId), s = x.store, read = s.read.bind(s); let armed = true, afterReject = null;
      s.read = async (c, k) => { const value = await read(c, k); if (armed && c === Categories.REQUEST && k === q.requestId) { armed = false; await cand.wr4.markWalletRejected(x.config, q.requestId); afterReject = await x.snap(); } return value; };
      let outcome;
      try { outcome = await settle(x.k.finalize(q, w.owner)); } finally { s.read = read; }
      assert.ok(afterReject);
      assert.equal(inSnap(afterReject, Categories.REQUEST, q.requestId).state, "WALLET_REJECTED");
      assert.deepEqual(await x.snap(), afterReject, "the break-glass pre-read before W1 fails closed: no bytes, no claim, no relabel");
      assert.ok(outcome.error, "the finalize fails closed");
    });
    t4("re-read: Verify completes the request by its txid after the ordinary claim and before W1 -> the finalize fails closed with no further write [RED on C1]", async (x) => {
      const r = await x.req(B.ord.r.requestId), key = cand.claims.transitionClaimKey(r.predecessorOutpoint);
      x.model.confirm(frozenOf(r), r.txId); x.model.advance(SETTLE_DEPTH_DAA); // the signed transaction landed out of band, at depth D
      const s = x.store, create = s.createExclusive.bind(s); let afterVerify = null, verified = null;
      s.createExclusive = async (c, k, v) => {
        const out = await create(c, k, v);
        if (!afterVerify && out === true && c === Categories.TRANSITION_CLAIM && k === key) { verified = await settle(x.verify(V.ord)); afterVerify = await x.snap(); }
        return out;
      };
      let outcome;
      try { outcome = await settle(x.k.finalize(r, w.agent)); } finally { s.createExclusive = create; }
      assert.ok(afterVerify, "Verify ran right after the claim was durable");
      assert.deepEqual(await x.snap(), afterVerify, "the finalize writes nothing after Verify (no W1 over the completed record)");
      assert.ok(outcome.error, "the finalize fails closed");
      assert.equal(verified.error, null, `Verify answered (${verified.error && verified.error.message})`);
      assert.equal(inSnap(afterVerify, Categories.REQUEST, r.requestId).state, "CHAIN_VERIFIED", "Verify completed the BUILT request by its txid at depth D (F5)");
      assert.equal(inSnap(afterVerify, Categories.REQUEST, r.requestId).finalTransaction, undefined);
    });
  }
}
