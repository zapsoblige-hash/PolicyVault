"use strict";
/*
 * RC45 R1-05 — INVALID DEPTH EVIDENCE FAILS CLOSED, FOR JUDGED ENTRIES ONLY
 * (the Verify settlement pass). Finding ST-02 = RC45-REV-SET-02 (= lead I-2) of
 * the independent candidate review rc45-patch-independent-01; remediation plan
 * R1 revision 2, R1-05 with conditions C4 and K1 and the INFO implementation
 * note RC1-12. Internal RED-first regression material for the RC45 successor
 * candidate; not an audit. Adapted from the review-only probe
 * review-settlement-b-depth (settlement reviewer, sha256 6953a737...). The
 * journaled-history observation (sdk/src/wallet-recovery-v4.js:598) is pinned
 * in sdk/test/rc45-r1-05-journal-observation.test.js.
 *
 * The rule (plan R1-05): the RAW, uncoerced blockDaaScore of the node's UTXO
 * answer is validated for JUDGED entries only — the recorded outpoint Lref
 * (step 6), the SEEN hits of a recorded group (step 7), the C-bound step-8
 * candidate Y and the step-9 hit of the owner-pasted recover. A canonical raw
 * value is exactly one of (K1): a non-negative JS bigint (the rusty-kaspa
 * v2.0.1 WASM getter encoding of the u64 field), a non-negative safe integer,
 * or a string matching /^[0-9]+$/. Anything else (missing, empty, hex, signed,
 * fractional, padded, any other type) is an observation failure: 422
 * RECONCILE_FAILED with nothing written. A judged value greater than the
 * virtual DAA score read first is below depth (CLAIM_PENDING, nothing
 * written). Entries that are not judged (decoys, unrelated outputs at a read
 * address) are never validated (PA-01 r1 rule 2; RC1-12: non-throwing
 * coercion): an invalid value there keeps the answer the pass gives without it.
 *
 * At the SDK a 422 is a rejected reconcileVaultV4 carrying code
 * RECONCILE_FAILED or the pass's observation-failure marker (observationError);
 * the hosted route answers every such rejection 422 RECONCILE_FAILED
 * (server/src/api.js) and request-scoped recovery answers it
 * PROTECTED_UNRESOLVED with no further write (CR2-L10); both are pinned below.
 *
 * RED on dc7552e: depthOf = vDaa - (u.blockDaaScore ?? 0n) over chain.js's
 * coercion (absent -> null, BigInt("") === 0n, BigInt("0x0") === 0n,
 * BigInt("-1") === -1n, BigInt(true) === 1n, BigInt([n]) === n, BigInt(" n")
 * === n, BigInt("+n") === n), so a spender accepted at TRUE depth 0 is CONFIRMED
 * and Verify writes RECOVERED / CHAIN_VERIFIED / STALE / an adoption / a
 * restore (or answers CLAIM_PENDING / CONSISTENT instead of refusing);
 * chain.js's BigInt throws for a DECOY's fractional, null or object value, so
 * one unrelated output fails the whole read (422 or no SEEN). HOLDS on
 * dc7552e (and must keep holding): a judged value that already makes BigInt
 * throw (fractional, null, object) is refused; exact answers; a judged value
 * > vDaa is CLAIM_PENDING; bigint and safe-integer raw values on every judged
 * kind are judged normally (K1); decoys whose value BigInt accepts.
 *
 * Population (TEST keys only; every config names ws://127.0.0.1:1; node
 * observations only from the explicit chain model of
 * sdk/testutil/rc45-f5-kit.js, whose getUtxosByAddresses answer is
 * post-processed for the entries under test only, every other field exact):
 *   cr  CANDIDATE-WRITTEN contested Close & recover (the probe's setup): the
 *       delegate's agentSpend D holds the only claim on L0, the owner's
 *       ownerRecover Q is finalized apart (real compiler, pv_call_encoder,
 *       deterministic dev signer, pinned pv_vm_preflight) — SEEN hits;
 *   ad  an out-of-app TEST-key owner Pause Y of L0, built and finalized in a
 *       side root (its record never reaches the tested root) — the C-bound
 *       step-8 candidate (as rc45-t5-adoption);
 *   rc  an out-of-app TEST-key owner Close & recover X of L0, hosted-built and
 *       finalized in a side root, pasted as Safe JSON — the step-9 hit; the
 *       same vault with L0 live is the plain live Lref;
 *   tuW RC44-written TERMINATED_UNKNOWN (pinned df5b8de writers,
 *       sdk/testutil/rc45-f5-rc44-history.js scenario t5; a missing or
 *       mismatched POLICYVAULT_TEST_RC44_TREE FAILS) — Lref restored at depth.
 * Decoys are covenant-less TEST outputs at a read address (anyone can pay one
 * there): address(S), the recorded successor's address, the owner's P2PK
 * address and the flip address.
 *
 * Layers: SDK (reconcileVaultV4, reconcileTransitionWalletRequestV4) and API
 * (self-hosted POST /vaults/:id/reconcile through server/src/api.js handle,
 * the real reconcileVaultV4 wrapped only to pass the model's rpc, plan r2 §8
 * rules CR-M14, CR2-L12). Both stores: JSON always; PostgreSQL with
 * POLICYVAULT_TEST_PG_{PORT,USER,DATABASE} (the rc45 runner's pg mode; a
 * skipped PostgreSQL leg there is a FAIL).
 */
const path = require("node:path");
const assert = require("node:assert/strict");
const { test, before, after } = require("node:test");
const K = require("../testutil/rc45-f5-kit");
const H5 = require("../testutil/rc45-f5-rc44-history");
const F3 = require("../testutil/rc45-f3-kit");
const F6 = require("../testutil/rc45-f6-kit");
const { KAS, LOOPBACK, SETTLE_DEPTH_DAA, frozenOf, jsonSafe } = K;

const SDK_SRC = path.join(__dirname, "..", "src");
const cand = K.modulesOf(SDK_SRC);
const recovery = require(path.join(SDK_SRC, "wallet-recovery-v4.js"));
const { Categories } = cand.store;
const TOOLCHAIN = require("../testutil/org-root-durable-fixture").toolchainAvailable();
const PG = K.pgFromEnv();
const PG_AVAILABLE = Boolean(PG.port && PG.user && PG.database);
const V = Object.freeze({ cr: K.vault("r105-cr"), ad: K.vault("r105-ad"), rc: K.vault("r105-rc"), tuW: H5.F5_RC44_VAULTS.tuW });
const roots = [], stores = [], databases = [];
let admin = null, serial = 0, history = null, H = null, B = null, w = null, templateRoot = null;
const mk = (prefix) => { const dir = K.ownedTempRoot(prefix); roots.push(dir); return dir; };
const track = (root) => roots.push(root);
const settle = (promise) => promise.then((value) => ({ value, error: null }), (error) => ({ value: null, error }));
async function resolved(fn, message) {
  let value;
  await assert.doesNotReject(async () => { value = await fn(); }, message);
  return value;
}
/* A signed transaction the owner makes OUTSIDE PolicyVault: built, TEST-key signed and VM-preflighted in a side root. */
const outOfApp = (r) => ({ txId: r.txId, frozen: frozenOf(r), successorStateId: r.successorStateId, predecessorStateId: r.predecessorStateId, scriptSha256: r.build.successorScriptSha256 });

before(async () => {
  assert.ok(TOOLCHAIN, "real compiler, encoder and VM are required (a missing VM toolchain is a FAIL, never a SKIP)");
  const rc44 = H5.runF5Rc44Scenario("t5", { track });
  H = rc44.result.hist;
  const template = cand.config.loadConfig({ dataRoot: mk("pv-rc45-r105-template-"), rpcUrl: LOOPBACK });
  await K.install(cand, template, await K.snapshot(cand, cand.config.loadConfig({ dataRoot: rc44.dataRoot, rpcUrl: LOOPBACK })));
  w = K.walletsFor(template);
  const k = K.kitFor(cand, template, w), sides = [];
  const side = async (v) => {
    const config = cand.config.loadConfig({ dataRoot: mk("pv-rc45-r105-side-"), rpcUrl: LOOPBACK });
    await K.seedVault(cand, config, v, w);
    sides.push(config.dataRoot);
    return { config, k: K.kitFor(cand, config, w) };
  };
  B = {};
  { // cr: contested Close & recover (CANDIDATE-WRITTEN, finalized apart and merged): D holds the only claim on L0.
    const v = V.cr; await K.seedVault(cand, template, v, w);
    const d = await k.agentSpend(v, 4); await K.sleep(3);
    const q = await k.ownerOp(v, "ownerRecover"); await K.sleep(3);
    await K.finalizeApart(cand, template, [{ requestId: d.requestId, signer: w.agent }, { requestId: q.requestId, signer: w.owner }], { claimHolder: d.requestId, track });
    B.cr = { d: d.requestId, q: q.requestId };
  }
  { // ad: ACTIVE S at L0; side root: the owner's Pause Y (fuel2), finalized there, broadcast outside PolicyVault.
    const v = V.ad; await K.seedVault(cand, template, v, w);
    const s = await side(v);
    const p = await s.k.finalize(await s.k.ownerOp(v, "ownerPause", "fuel2"), w.owner);
    assert.equal(p.state, "PREFLIGHT_VERIFIED");
    B.ad = { y: outOfApp(p), stateId: (await cand.manifest4.loadManifestV4(template, v.vaultId)).live.stateId };
  }
  { // rc: ACTIVE S at L0; side root: the owner's hosted-built Close & recover X of L0 (fuel2), pasted as Safe JSON.
    const v = V.rc; await K.seedVault(cand, template, v, w);
    const s = await side(v);
    const x = await s.k.finalize(await s.k.ownerOp(v, "ownerRecover", "fuel2"), w.owner);
    assert.equal(x.state, "PREFLIGHT_VERIFIED");
    assert.deepEqual(x.predecessorOutpoint, { transactionId: v.out, index: 0 }, "the recover spends the recorded outpoint L0");
    const xf = frozenOf(x);
    B.rc = { here: xf.inputs[0].utxo.scriptPublicKey, value: xf.inputs[0].utxo.amount,
      x: { txId: x.txId, frozen: xf, safe: F6.safeJsonOf(s.config, x.finalTransaction), L: x.predecessorOutpoint, oldStateId: x.predecessorStateId } };
  }
  for (const root of sides) K.warmCompileCache(root, template.dataRoot);
  const b = await cand.wr4.loadRequest(template, H.tuW.b.requestId);
  for (const st of [b.build.stateJson, b.build.successorState]) cand.submit4.successorAddressAndScript(template, b.build.template, st, b.contractVersion);
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
  const dataRoot = mk("pv-rc45-r105-case-");
  K.warmCompileCache(templateRoot, dataRoot);
  let config, pgDatabase = null;
  if (backend === "PostgreSQL") {
    pgDatabase = `pv_rc45_r105_${process.pid}_${++serial}`;
    await admin.query(`CREATE DATABASE ${pgDatabase}`); databases.push(pgDatabase);
    config = cand.config.loadConfig({ persistenceBackend: "postgres", pgHost: PG.host, pgPort: PG.port, pgUser: PG.user, pgDatabase, pgNoTls: true, hostedDevOpen: true, dataRoot, rpcUrl: LOOPBACK });
    stores.push(await cand.store.openPgStore(config, { migrate: true }));
    assert.equal(cand.store.getStore(config).kind, "postgres");
  } else config = cand.config.loadConfig({ dataRoot, rpcUrl: LOOPBACK });
  assert.equal(config.networkId, "testnet-10");
  await K.install(cand, config, history);
  const store = cand.store.getStore(config), model = K.chainModel(config), api = F3.apiFor(config);
  const x = {
    config, store, model, pgDatabase, api,
    req: (requestId) => cand.wr4.loadRequest(config, requestId),
    rawRequest: (requestId) => store.read(Categories.REQUEST, requestId),
    rawManifest: (v) => store.read(Categories.VAULT, v.vaultId),
    claimOn: (outpoint) => store.read(Categories.TRANSITION_CLAIM, cand.claims.transitionClaimKey(outpoint)),
    receipt: (txId) => store.read(Categories.RECEIPT, txId),
    audit: () => store.readAudit({ limit: 5000 }),
    events: async () => (await require("../../server/src/events-store").getEventsStore(config).listEventsAfter({ cursor: "0", limit: 500 })).map((r) => JSON.stringify(r.event)),
    snap: () => K.snapshot(cand, config),
    verify: (v) => cand.reconcile4.reconcileVaultV4(config, v.vaultId, { rpc: model.rpc }),
    paste: (v, outOfAppTransaction) => cand.reconcile4.reconcileVaultV4(config, v.vaultId, { rpc: model.rpc, outOfAppTransaction }),
    recover: (requestId) => recovery.reconcileTransitionWalletRequestV4({ config, requestId, rpc: model.rpc })
  };
  /* POST /vaults/:id/reconcile (self-hosted) through the REAL reconcileVaultV4 wrapped with the explicit chain model's rpc. */
  x.verifyRoute = async (v, body = {}) => {
    const m4 = require(path.join(SDK_SRC, "reconcile-v4.js")), real4 = m4.reconcileVaultV4;
    m4.reconcileVaultV4 = (c, vid, options = {}) => real4(c, vid, { ...options, rpc: model.rpc });
    try { return await api.call("POST", ["vaults", v.vaultId, "reconcile"], body); } finally { m4.reconcileVaultV4 = real4; }
  };
  return x;
}
async function release(x) {
  if (!x.pgDatabase) return;
  const i = stores.indexOf(x.store);
  if (i >= 0) { stores.splice(i, 1); await x.store.close(); }
}

/* Post-process the model's getUtxosByAddresses answer: `mutate` runs on every entry `pick` selects (raw node fields). */
function rewriteAnswer(x, pick, mutate) {
  const inner = x.model.rpc.getUtxosByAddresses.bind(x.model.rpc);
  let touched = 0;
  x.model.rpc.getUtxosByAddresses = async (args) => {
    const out = await inner(args);
    for (const e of out.entries) if (pick(e)) { mutate(e, x.model.virtualDaaScore); touched += 1; }
    return out;
  };
  return { get touched() { return touched; } };
}
const L0 = (v) => ({ transactionId: v.out, index: 0 });
const ownerSpk = () => ({ version: 0, scriptHex: `20${w.owner.xonly}ac` });

/*
 * The judged entry kinds. land(x) puts the judged entries on the model at TRUE depth 0 (lrefLive: deep) and returns
 * { pick, decoySpk }; run(x) is the Verify that judges them; gated says whether the kind's depth gates a write (else
 * the exact answer is CONSISTENT); atDepth(x, out) asserts the exact settlement at depth D.
 */
const KINDS = {
  lrefLive: {
    label: "the recorded live outpoint Lref of a plain live vault (step 6)", v: V.rc, gated: false,
    async land(x) {
      x.model.add(L0(V.rc), B.rc.value, B.rc.here, V.rc.cov, x.model.virtualDaaScore - 5000n);
      return { pick: (e) => e.outpoint.transactionId === V.rc.out && Number(e.outpoint.index) === 0, decoySpk: B.rc.here };
    },
    run: (x) => x.verify(V.rc),
    async atDepth(x, out, before) {
      assert.equal(out.status, "CONSISTENT", `the plain live vault is consistent (got ${JSON.stringify(jsonSafe(out))})`);
      assert.deepEqual(await x.snap(), before, "nothing is written");
    }
  },
  lrefRestore: {
    label: "the recorded outpoint Lref of an RC44-written TERMINATED_UNKNOWN vault (step 6 restore)", v: V.tuW, gated: true,
    async land(x) {
      const b = await x.req(H.tuW.b.requestId), m = await x.rawManifest(V.tuW);
      assert.equal(m.status, "TERMINATED_UNKNOWN"); assert.equal(m.live, null); assert.equal(m.lastTransition.txId, b.txId);
      const index = frozenOf(b).outputs.findIndex((o) => o.covenant !== null), out = frozenOf(b).outputs[index];
      const L1 = { transactionId: b.txId, index };
      x.model.add(L1, out.value, out.scriptPublicKey, b.covenantId);
      x.tuW = { b, L1, out };
      return { pick: (e) => e.outpoint.transactionId === L1.transactionId && Number(e.outpoint.index) === index, decoySpk: out.scriptPublicKey };
    },
    run: (x) => x.verify(V.tuW),
    async atDepth(x, out) {
      assert.ok(["CONSISTENT", "ADVANCED"].includes(out.status), `the restored vault is consistent (got ${JSON.stringify(jsonSafe(out))})`);
      const r = await x.rawManifest(V.tuW);
      assert.equal(r.status, "ACTIVE"); assert.deepEqual(r.live.outpoint, x.tuW.L1); assert.equal(r.live.stateId, x.tuW.b.successorStateId);
      assert.equal((await x.audit()).filter((e) => e.action === "reconciled_advanced" && e.via === "restored").length, 1, "one reconciled_advanced {via: restored}");
    }
  },
  seen: {
    label: "the SEEN hits of the owner's contested Close & recover (step 7)", v: V.cr, gated: true,
    async land(x) {
      const q = await x.req(B.cr.q);
      x.model.seedInputs(frozenOf(q), q.covenantId); x.model.confirm(frozenOf(q), q.txId);
      return { pick: (e) => e.outpoint.transactionId === q.txId, decoySpk: ownerSpk() };
    },
    run: (x) => x.verify(V.cr),
    async atDepth(x, out) {
      const q = await x.req(B.cr.q), d = await x.req(B.cr.d);
      assert.equal(out.status, "ADVANCED", `the recover settles at D (got ${JSON.stringify(jsonSafe(out))})`); assert.equal(out.to, "RECOVERED"); assert.equal(out.txId, q.txId);
      assert.equal((await x.rawManifest(V.cr)).status, "RECOVERED");
      assert.equal((await x.rawRequest(q.requestId)).state, "CHAIN_VERIFIED"); assert.equal((await x.rawRequest(d.requestId)).state, "STALE");
    }
  },
  step8: {
    label: "the C-bound step-8 candidate Y (an out-of-app owner Pause)", v: V.ad, gated: true,
    async land(x) {
      const y = B.ad.y;
      x.model.seedInputs(y.frozen, V.ad.cov); x.model.confirm(y.frozen, y.txId);
      return { pick: (e) => e.outpoint.transactionId === y.txId, decoySpk: y.frozen.outputs[0].scriptPublicKey };
    },
    run: (x) => x.verify(V.ad),
    async atDepth(x, out) {
      const y = B.ad.y;
      assert.equal(out.status, "ADVANCED", `Y is adopted at D (got ${JSON.stringify(jsonSafe(out))})`); assert.equal(out.txId, y.txId);
      const m = await x.rawManifest(V.ad);
      assert.equal(m.status, "PAUSED"); assert.deepEqual(m.live.outpoint, { transactionId: y.txId, index: 0 }); assert.equal(m.lastTransition.action, "ownerPause");
    }
  },
  step9: {
    label: "the step-9 hit of the owner-pasted recover X", v: V.rc, gated: true,
    async land(x) {
      const p = B.rc.x;
      x.model.confirm(p.frozen, p.txId);
      return { pick: (e) => e.outpoint.transactionId === p.txId, decoySpk: ownerSpk() };
    },
    run: (x) => x.paste(V.rc, B.rc.x.safe),
    async atDepth(x, out) {
      const p = B.rc.x;
      assert.equal(out.status, "ADVANCED", `the pasted recover settles at D (got ${JSON.stringify(jsonSafe(out))})`); assert.equal(out.to, "RECOVERED"); assert.equal(out.txId, p.txId);
      const m = await x.rawManifest(V.rc);
      assert.equal(m.status, "RECOVERED"); assert.equal(m.live, null); assert.equal(m.latestTransitionTxId, p.txId);
    }
  }
};

/* Raw blockDaaScore values outside the canonical set (K1). `throws`: chain.js's BigInt coercion throws on it at dc7552e. */
const INVALID = [
  ["absent", (e) => { delete e.blockDaaScore; }, false],
  ["the empty string", (e) => { e.blockDaaScore = ""; }, false],
  ["the hex string 0x0", (e) => { e.blockDaaScore = "0x0"; }, false],
  ["the signed string -1", (e) => { e.blockDaaScore = "-1"; }, false],
  ["the plus-signed decimal string +<score>", (e) => { e.blockDaaScore = `+${e.blockDaaScore}`; }, false],
  ["the space-padded decimal string ' <score>'", (e) => { e.blockDaaScore = ` ${e.blockDaaScore}`; }, false],
  ["the fractional string 0.5", (e) => { e.blockDaaScore = "0.5"; }, true],
  ["the negative number -1", (e) => { e.blockDaaScore = -1; }, false],
  ["the fractional number 0.5", (e) => { e.blockDaaScore = 0.5; }, true],
  ["the unsafe integer number 2^53", (e) => { e.blockDaaScore = 2 ** 53; }, false],
  ["the negative bigint -1n", (e) => { e.blockDaaScore = -1n; }, false],
  ["the boolean true", (e) => { e.blockDaaScore = true; }, false],
  ["null", (e) => { e.blockDaaScore = null; }, true],
  ["an object {}", (e) => { e.blockDaaScore = {}; }, true],
  ["a one-element array [<score>]", (e) => { e.blockDaaScore = [e.blockDaaScore]; }, false]
];
/* Canonical non-string raw encodings of the entry's own score (K1). */
const CANONICAL = [
  ["a non-negative bigint (the rusty-kaspa v2.0.1 WASM getter encoding)", (e) => { e.blockDaaScore = BigInt(e.blockDaaScore); }],
  ["a non-negative safe-integer number", (e) => { e.blockDaaScore = Number(e.blockDaaScore); }]
];
/* The SDK form of a 422: a rejection carrying RECONCILE_FAILED or the pass's observation-failure marker. */
async function assertRefused422(promise, what) {
  const run = await settle(promise);
  assert.ok(run.error, `${what} is an observation failure: Verify must refuse with 422 RECONCILE_FAILED (observed ${JSON.stringify(jsonSafe(run.value))})`);
  assert.ok(run.error.code === "RECONCILE_FAILED" || run.error.observationError === true,
    `the refusal is RECONCILE_FAILED or a marked observation failure (got code ${run.error.code}: ${String(run.error.message).slice(0, 200)})`);
}
const red = (claim) => (claim ? " [RED on dc7552e]" : "");

const PG_SKIP = PG_AVAILABLE ? undefined : "REQUIREMENT_NOT_AVAILABLE in this process: isolated PostgreSQL (the rc45 runner's pg mode runs these legs; a skipped PostgreSQL leg there is a FAIL)";
for (const [backend, skip] of [["JSON", undefined], ["PostgreSQL", PG_SKIP]]) {
  const leg = (name, fn) => test(`RC45 R1-05 ${backend}: ${name}`, { skip }, async () => { const x = await fresh(backend); try { await fn(x); } finally { await release(x); } });

  for (const [kindName, kind] of Object.entries(KINDS)) {
    /* ---------------- controls ---------------- */
    leg(`${kindName} control: ${kind.label} with the node's exact answer ${kind.gated ? "at TRUE depth 0 answers CLAIM_PENDING" : "answers CONSISTENT"} with nothing written`, async (x) => {
      await kind.land(x);
      const before = await x.snap();
      const out = await resolved(() => kind.run(x), "the exact answer is judged");
      if (kind.gated) { assert.equal(out.status, "CLAIM_PENDING", `below D (got ${JSON.stringify(jsonSafe(out))})`); assert.equal(String(out.depth), "0"); assert.deepEqual(await x.snap(), before); } else await kind.atDepth(x, out, before);
    });

    /* ---------------- invalid raw values on judged entries -> 422, nothing written ---------------- */
    for (const [label, mutate, throwsOnDc] of INVALID) {
      leg(`${kindName}: ${kind.label} ${kind.gated ? "accepted at TRUE depth 0 " : ""}with the node's raw blockDaaScore ${label} is invalid depth evidence: Verify refuses 422 RECONCILE_FAILED with nothing written${red(!throwsOnDc)}`, async (x) => {
        const { pick } = await kind.land(x);
        const seam = rewriteAnswer(x, pick, mutate);
        const before = await x.snap();
        await assertRefused422(kind.run(x), `a judged blockDaaScore of ${label}`);
        assert.ok(seam.touched >= 1, "the judged entry was answered with the invalid value");
        assert.deepEqual(await x.snap(), before, "nothing is written on invalid depth evidence");
      });
    }

    /* ---------------- canonical raw encodings are judged normally (K1) ---------------- */
    for (const [label, mutate] of CANONICAL) {
      leg(`${kindName} (K1): ${kind.label} with the node's raw blockDaaScore as ${label} is judged normally, never a 422: ${kind.gated ? "CLAIM_PENDING{depth 999} with nothing written below D, the exact settlement at D" : "CONSISTENT, nothing written"}`, async (x) => {
        const { pick } = await kind.land(x);
        const seam = rewriteAnswer(x, pick, mutate);
        if (kind.gated) {
          x.model.advance(SETTLE_DEPTH_DAA - 1n);
          const below = await x.snap();
          const pending = await resolved(() => kind.run(x), "a canonical raw value is no 422");
          assert.equal(pending.status, "CLAIM_PENDING", `depth 999 < D (got ${JSON.stringify(jsonSafe(pending))})`); assert.equal(String(pending.depth), "999");
          assert.deepEqual(await x.snap(), below, "nothing is written below D");
          x.model.advance(1n);
        }
        const before = await x.snap();
        const out = await resolved(() => kind.run(x), "a canonical raw value is no 422");
        await kind.atDepth(x, out, before);
        assert.ok(seam.touched >= 1, "the judged entry was answered with the canonical non-string value");
      });
    }

    /* ---------------- a judged value greater than vDaa is below depth ---------------- */
    if (kind.gated) {
      leg(`${kindName}: ${kind.label} whose canonical raw blockDaaScore is GREATER than the virtual DAA score read first (an accepting block after the virtual read) is below depth: CLAIM_PENDING with nothing written, never a 422`, async (x) => {
        const { pick } = await kind.land(x);
        x.model.advance(SETTLE_DEPTH_DAA);
        const seam = rewriteAnswer(x, pick, (e, vDaa) => { e.blockDaaScore = String(vDaa + 5n); });
        const before = await x.snap();
        const out = await resolved(() => kind.run(x), "a judged value above vDaa is no 422");
        assert.equal(out.status, "CLAIM_PENDING", `a judged value above vDaa is below depth (got ${JSON.stringify(jsonSafe(out))})`);
        assert.deepEqual(await x.snap(), before, "nothing is written");
        assert.ok(seam.touched >= 1);
      });
    }

    /* ---------------- decoys: never validated, the answer is kept ---------------- */
    for (const [label, mutate, throwsOnDc] of INVALID) {
      leg(`${kindName} decoy: a covenant-less TEST output at the address read for ${kind.label}, carrying the raw blockDaaScore ${label}, is not judged: the answer is exactly the one without it (${kind.gated ? "the settlement at D" : "CONSISTENT"})${red(throwsOnDc)}`, async (x) => {
        const { decoySpk } = await kind.land(x);
        if (kind.gated) x.model.advance(SETTLE_DEPTH_DAA);
        const decoy = { transactionId: K.hex(`r105-decoy-${kindName}`), index: 0 };
        x.model.add(decoy, KAS, decoySpk, null, x.model.virtualDaaScore - 2000n);
        const seam = rewriteAnswer(x, (e) => e.outpoint.transactionId === decoy.transactionId, mutate);
        const before = await x.snap();
        const run = await settle(kind.run(x));
        assert.ok(run.error === null, `an unjudged output never fails the pass (got ${run.error && `${run.error.code}: ${String(run.error.message).slice(0, 200)}`})`);
        await kind.atDepth(x, run.value, before);
        assert.ok(seam.touched >= 1, "the decoy was in the node's answer");
      });
    }
  }

  /* ---------------- every caller: the hosted route and request-scoped recovery ---------------- */
  leg("hosted Verify route (self-hosted POST /vaults/:id/reconcile): the owner's contested Close & recover accepted at TRUE depth 0 with its blockDaaScore absent answers 422 RECONCILE_FAILED with nothing written and no vault.reconciled event (never RECOVERED at depth 0) [RED on dc7552e]", async (x) => {
    const { pick } = await KINDS.seen.land(x);
    rewriteAnswer(x, pick, (e) => { delete e.blockDaaScore; });
    const before = await x.snap(), events = await x.events();
    const out = await x.verifyRoute(V.cr);
    assert.equal(out.status, 422, `the route refuses (observed ${out.status} ${JSON.stringify(jsonSafe(out.body?.reconcile ?? out.message))})`);
    assert.equal(out.code, "RECONCILE_FAILED");
    assert.deepEqual(await x.snap(), before, "nothing is written"); assert.deepEqual(await x.events(), events, "no vault.reconciled event");
  });
  leg("hosted Verify route with the owner-pasted recover (body outOfAppTransaction): X accepted at TRUE depth 0 with its blockDaaScore the empty string answers 422 RECONCILE_FAILED with nothing written and no event (never RECOVERED at depth 0) [RED on dc7552e]", async (x) => {
    const { pick } = await KINDS.step9.land(x);
    rewriteAnswer(x, pick, (e) => { e.blockDaaScore = ""; });
    const before = await x.snap(), events = await x.events();
    const out = await x.verifyRoute(V.rc, { outOfAppTransaction: B.rc.x.safe });
    assert.equal(out.status, 422, `the route refuses (observed ${out.status} ${JSON.stringify(jsonSafe(out.body?.reconcile ?? out.message))})`);
    assert.equal(out.code, "RECONCILE_FAILED");
    assert.deepEqual(await x.snap(), before, "nothing is written"); assert.deepEqual(await x.events(), events, "no event");
  });
  for (const [label, mutate, throwsOnDc] of INVALID.filter(([l]) => ["absent", "the empty string", "the hex string 0x0", "the signed string -1", "the negative bigint -1n", "the boolean true", "the fractional string 0.5", "null"].includes(l))) {
    leg(`request-scoped recovery of the delegate loser (journal-free; the pass runs inside it, CR2-L10): the owner's recover accepted at TRUE depth 0 with its blockDaaScore ${label} answers PROTECTED_UNRESOLVED with nothing written (never STALE by a depth-0 winner)${red(!throwsOnDc)}`, async (x) => {
      const { pick } = await KINDS.seen.land(x);
      rewriteAnswer(x, pick, mutate);
      const before = await x.snap();
      const out = await resolved(() => x.recover(B.cr.d), "request-scoped recovery answers");
      assert.equal(out.outcome, "PROTECTED_UNRESOLVED", `invalid depth evidence settles nothing (got ${out.outcome}: ${out.detail})`);
      assert.deepEqual(await x.snap(), before, "nothing is written");
    });
  }
}
