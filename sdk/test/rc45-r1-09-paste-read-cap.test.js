"use strict";
/*
 * RC45 R1-09 — VERIFY STEP 9 READ CAP FOR THE OWNER-PASTED TRANSACTION
 * (remediation plan R1 revision 2 §2 R1-09, condition C9, implementation note
 * RC1-11, §4 R1-09; finding S-03 of the independent review
 * rc45-patch-independent-01; plan rc45-simplified-plan-r2 §2.2 steps 0, 9-11,
 * §2.5(3), §5 A5). Adapted from the review probe review-surface-paste-reads.
 * Internal RED-first regression material for the RC45 successor candidate;
 * not an audit.
 *
 * RED on dc7552e: Verify step 9 (reconcile-v4.js recoverEvidence) reads the
 * node once per DISTINCT output address of the pasted transaction with no cap
 * (the review read 503 addresses in one Verify), and a paste with more than
 * 64 outputs is accepted by the shape check. GREEN after R1-09:
 *   - more than 64 outputs in the pasted transaction is refused at step 0 /
 *     in the Verify route's shape check with BAD_FORMAT (hosted: 400
 *     BAD_FORMAT, the existing body-shape code), before any node read, with
 *     nothing written and (at the route) no reconcile;
 *   - step 9 reads outputs[0]'s address first, then at most 4 further
 *     distinct output addresses (counted as getUtxosByAddresses calls over a
 *     no-paste Verify of the same chain state, and as distinct addresses of
 *     the paste read); an over-cap paste with no observed output is a
 *     mismatch with `unchecked` counted (UNKNOWN{unchecked} above the no-paste
 *     answer's), nothing written;
 *   - steps 10-11 still run after an over-cap mismatch: a contradiction (the
 *     recorded old outpoint live again) is still CHAIN_CONTRADICTION.
 * HOLDS (dc7552e and after): a paste within the cap (outputs[0]'s address
 * plus exactly 4 further distinct addresses) reads every one of them or
 * counts what it skips; an over-cap paste whose outputs[0] is observed
 * exactly at depth D still settles RECOVERED (the cap never refuses an
 * accepted recover); an unparseable paste keeps the mismatch path (UNKNOWN,
 * nothing written, no read of any paste address), at the SDK and at the route.
 *
 * Layers: SDK (the real reconcileVaultV4 with the explicit chain model) and API
 * (the real server/src/api.js handle in hosted mode with TEST-key wallet
 * sessions, sdk/testutil/rc45-f3-kit.js apiFor). The route cannot pass `rpc`,
 * so, as plan r2 §8 rules allow for route-level Verify (CR-M14, CR2-L12) and as
 * sdk/test/rc45-t8-recover-evidence-route.test.js does, the module-cache
 * export of the REAL reconcileVaultV4 is wrapped to call itself with the
 * explicit chain model's rpc (never a stub), recording each call, and restored
 * afterwards. Real v0.4.1 compiler, pv_call_encoder, TEST-key signatures and
 * pv_vm_preflight for every consensus byte: the recovers of L (clean vault) and
 * of L1 (after a recorded delegate spend W1, submitted through the candidate
 * submit) are hosted-built and finalized in side roots (their records never
 * reach the tested store). SYNTHETIC (labelled): the pastes with extra outputs
 * are those real recovers with outputs to distinct deterministic TEST P2PK
 * addresses appended and the signature scripts emptied (the txid never
 * commits to them), so they are not consensus-valid; where one is shown
 * accepted on the chain model it is an inconsistent indexer view. Node
 * observations come ONLY from the explicit chain model of
 * sdk/testutil/rc45-f5-kit.js; every config names ws://127.0.0.1:1; nothing
 * dials a node.
 *
 * Both stores: JSON always; PostgreSQL with POLICYVAULT_TEST_PG_{PORT,USER,
 * DATABASE} (the rc45 runner's pg mode; a skipped PostgreSQL leg there is a
 * FAIL). TEST keys only; no production data, credentials or endpoints.
 */
const path = require("node:path");
const assert = require("node:assert/strict");
const { test, before, after } = require("node:test");
const K = require("../testutil/rc45-f5-kit");
const F3 = require("../testutil/rc45-f3-kit");
const F6 = require("../testutil/rc45-f6-kit");
const { LOOPBACK, SETTLE_DEPTH_DAA, frozenOf } = K;

const cand = K.modulesOf(path.join(__dirname, "..", "src"));
const { Categories } = cand.store;
const TOOLCHAIN = require("../testutil/org-root-durable-fixture").toolchainAvailable();
const PG = K.pgFromEnv();
const PG_AVAILABLE = Boolean(PG.port && PG.user && PG.database);
const PASTE_LIMIT = 64 * 1024;
const MAX_OUTPUTS = 64; // plan R1 §2 R1-09: more than 64 outputs is refused
const READ_CAP = 1 + 4; // outputs[0]'s address, then at most 4 further distinct output addresses
const V = Object.freeze({ cl: K.vault("r109-cl"), ct: K.vault("r109-ct") });
const roots = [], stores = [], databases = [];
let admin = null, serial = 0, history = null, B = null, w = null, templateRoot = null;
const mk = (prefix) => { const dir = K.ownedTempRoot(prefix); roots.push(dir); return dir; };
const said = (r) => `${r.status} ${r.code ?? ""} ${r.message ?? ""}`.trim();

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

/* The address of a frozen output's script (the chain model's own address function). */
function addressOfSpk(config, spk) {
  const kaspa = require(config.rustyKaspaModule);
  return kaspa.addressFromScriptPublicKey({ version: Number(spk.version), script: spk.scriptHex }, config.networkId).toString();
}
/* A paste: the real recover `r` with `extra` outputs to distinct TEST P2PK addresses appended and the signature
 * scripts emptied (SYNTHETIC: not consensus-valid). `outputs`/`addresses` describe the document's outputs. */
function fabricated(config, r, extra) {
  const spam = K.spamRecipients(config, extra);
  const s = F6.synthetic(config, r.finalTransaction, (json) => {
    for (const input of json.inputs) input.signatureScript = "";
    for (const x of spam) json.outputs.push({ value: "1000", scriptPublicKey: { version: 0, scriptHex: `20${x.xonly}ac` }, covenant: null });
  });
  const addresses = s.frozen.outputs.map((o) => addressOfSpk(config, o.scriptPublicKey));
  return { ...s, outputs: s.frozen.outputs.length, addresses, first: addresses[0], further: new Set(addresses.filter((a) => a !== addresses[0])).size, bytes: Buffer.byteLength(s.safe, "utf8") };
}
/* Pastes of the real recover `r`: `k` further distinct addresses beyond outputs[0]'s, exactly `n` outputs, the largest that fits 64 KiB. */
function pastesOf(config, r) {
  const base = fabricated(config, r, 0);
  const further = (k) => { const p = fabricated(config, r, k - base.further); assert.equal(p.further, k); return p; };
  const outputs = (n) => { const p = fabricated(config, r, n - base.outputs); assert.equal(p.outputs, n); return p; };
  let max = null;
  for (const n of [600, 500, 450, 400, 350, 300, 250, 200]) { const p = outputs(n); if (p.bytes <= PASTE_LIMIT) { max = p; break; } }
  assert.ok(max, "a many-output paste fits the 64 KiB limit");
  const p64 = outputs(MAX_OUTPUTS), p65 = outputs(MAX_OUTPUTS + 1), p100 = outputs(100);
  for (const p of [p64, p65, p100]) assert.ok(p.bytes <= PASTE_LIMIT, `a ${p.outputs}-output paste fits the 64 KiB limit (${p.bytes} bytes)`);
  assert.ok(p64.further > READ_CAP - 1, "the 64-output paste names more distinct addresses than the read cap");
  return { base, within: further(READ_CAP - 1), over: further(READ_CAP), p64, p65, max,
    truncated: p100.safe.slice(0, Math.floor(p100.safe.length / 2)) };
}

before(async () => {
  assert.ok(TOOLCHAIN, "real compiler, encoder and VM are required (a missing VM toolchain is a FAIL, never a SKIP)");
  const template = cand.config.loadConfig({ dataRoot: mk("pv-rc45-r109-template-"), rpcUrl: LOOPBACK });
  w = K.walletsFor(template);
  const k = K.kitFor(cand, template, w), sides = [];
  B = {};
  { // cl: a clean live vault at L. Side root: the owner's hosted-built Close & recover of L (fuel2), finalized there.
    const v = V.cl; await K.seedVault(cand, template, v, w);
    const side = cand.config.loadConfig({ dataRoot: mk("pv-rc45-r109-side-"), rpcUrl: LOOPBACK }); sides.push(side.dataRoot);
    K.warmCompileCache(template.dataRoot, side.dataRoot);
    await K.seedVault(cand, side, v, w);
    const sk = K.kitFor(cand, side, w);
    const x = await sk.finalize(await sk.ownerOp(v, "ownerRecover", "fuel2"), w.owner);
    assert.equal(x.state, "PREFLIGHT_VERIFIED");
    assert.deepEqual(x.predecessorOutpoint, { transactionId: v.out, index: 0 }, "the recover spends the recorded outpoint L");
    B.cl = { recover: x, P: pastesOf(template, x) };
  }
  { // ct: a delegate spend W1 completed L0 -> L1 by the candidate submit (uncontested, zero depth). Side root (a copy of the
    // template at that point): the owner's hosted-built Close & recover of L1 (fuel2), finalized there.
    const v = V.ct; await K.seedVault(cand, template, v, w);
    const a = await k.finalize(await k.agentSpend(v, 4), w.agent); assert.equal(a.state, "PREFLIGHT_VERIFIED");
    const model = K.chainModel(template); model.know(a); model.seedInputs(frozenOf(a), a.covenantId); model.confirmOnSubmit = true;
    const done = await cand.submit4.submitWalletRequestV4({ config: template, requestId: a.requestId, rpc: model.rpc, pollAttempts: 1, pollDelayMs: 0 });
    assert.equal(done.request.state, "CHAIN_VERIFIED", "W1 completes at submit");
    const fa = frozenOf(a), idx = fa.outputs.findIndex((o) => o.covenant !== null);
    const side = cand.config.loadConfig({ dataRoot: mk("pv-rc45-r109-side-"), rpcUrl: LOOPBACK }); sides.push(side.dataRoot);
    K.warmCompileCache(template.dataRoot, side.dataRoot);
    await K.install(cand, side, await K.snapshot(cand, template));
    const sk = K.kitFor(cand, side, w);
    const x = await sk.finalize(await sk.ownerOp(v, "ownerRecover", "fuel2"), w.owner);
    assert.equal(x.state, "PREFLIGHT_VERIFIED");
    const L1 = { transactionId: a.txId, index: idx };
    assert.deepEqual(x.predecessorOutpoint, L1, "the recover spends the recorded successor L1");
    B.ct = { w1: a.requestId, L1, L0: fa.inputs[0].previousOutpoint, L0utxo: fa.inputs[0].utxo, model: model.serialize(), recover: x, P: pastesOf(template, x) };
  }
  for (const root of sides) K.warmCompileCache(root, template.dataRoot);
  // Warm the template's compile cache with the states step 8 compiles; one Verify per vault on a throwaway model with
  // the recorded outpoint spent, asserted to write nothing.
  for (const [v, init, L] of [[V.cl, null, null], [V.ct, B.ct.model, B.ct.L1]]) {
    const before = await K.snapshot(cand, template), model = K.chainModel(template, init);
    if (L) model.remove(L);
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

/* A fresh case: SDK (hosted false) or hosted (authMode enabled; owner signed in with the TEST key). */
async function fresh(backend, { hosted = false, init = null } = {}) {
  const dataRoot = mk("pv-rc45-r109-case-");
  K.warmCompileCache(templateRoot, dataRoot);
  const mode = hosted ? { authMode: "enabled", authCookieInsecure: true } : {};
  let config, pgDatabase = null;
  if (backend === "PostgreSQL") {
    pgDatabase = `pv_rc45_r109_${process.pid}_${++serial}`;
    await admin.query(`CREATE DATABASE ${pgDatabase}`); databases.push(pgDatabase);
    config = cand.config.loadConfig({ persistenceBackend: "postgres", pgHost: PG.host, pgPort: PG.port, pgUser: PG.user, pgDatabase, pgNoTls: true, ...(hosted ? {} : { hostedDevOpen: true }), ...mode, dataRoot, rpcUrl: LOOPBACK });
    stores.push(await cand.store.openPgStore(config, { migrate: true }));
    assert.equal(cand.store.getStore(config).kind, "postgres");
  } else config = cand.config.loadConfig({ ...mode, dataRoot, rpcUrl: LOOPBACK });
  if (hosted) assert.equal(config.tenancyEnforced, true);
  await K.install(cand, config, history);
  const store = cand.store.getStore(config), model = K.chainModel(config, init);
  const x = {
    config, store, model, pgDatabase,
    rawManifest: (v) => store.read(Categories.VAULT, v.vaultId),
    receipt: (txId) => store.read(Categories.RECEIPT, txId),
    snap: () => K.snapshot(cand, config),
    sdk: (v, outOfAppTransaction) => cand.reconcile4.reconcileVaultV4(config, v.vaultId, outOfAppTransaction === undefined ? { rpc: model.rpc } : { rpc: model.rpc, outOfAppTransaction })
  };
  if (hosted) {
    const api = F3.apiFor(config), owner = await api.signIn(w.owner);
    /* POST /vaults/:id/reconcile through the REAL reconciler wrapped with the explicit chain model's rpc. */
    x.route = async (v, body) => {
      const m4 = require(path.join(F6.SDK_SRC, "reconcile-v4.js")), real4 = m4.reconcileVaultV4, seen = [];
      m4.reconcileVaultV4 = (c, id, options = {}) => { seen.push({ vaultId: id, options: { ...options } }); return real4(c, id, { ...options, rpc: model.rpc }); };
      try { return { r: await api.call("POST", ["vaults", v.vaultId, "reconcile"], body, owner), seen }; } finally { m4.reconcileVaultV4 = real4; }
    };
  }
  return x;
}
async function release(x) {
  if (!x.pgDatabase) return;
  const i = stores.indexOf(x.store);
  if (i >= 0) { stores.splice(i, 1); await x.store.close(); }
}

/* Run `fn` and measure the node reads it caused: getUtxosByAddresses calls, the addresses read in order, all calls. */
async function measured(x, fn) {
  const from = x.model.reads.length, calls = x.model.calls.length;
  const value = await fn();
  return { value, reads: x.model.reads.length - from, addresses: x.model.readAddresses(from), calls: x.model.calls.length - calls };
}
/* The step-9 read cap (plan R1-09): over a no-paste Verify of the same chain state, the paste adds at most 1 + 4
 * getUtxosByAddresses calls; at most 1 + 4 distinct addresses of the paste are read; outputs[0]'s address first. */
function assertCapped(p, base, run, label) {
  assert.ok(run.reads - base.reads <= READ_CAP, `${label}: the paste adds at most ${READ_CAP} getUtxosByAddresses calls over a no-paste Verify (no-paste ${base.reads}, with the paste ${run.reads})`);
  const pasteReads = run.addresses.filter((a) => p.addresses.includes(a));
  assert.ok(new Set(pasteReads).size <= READ_CAP, `${label}: at most ${READ_CAP} distinct addresses of the paste are read (read ${new Set(pasteReads).size} of ${new Set(p.addresses).size})`);
  assert.ok(pasteReads.length >= 1, `${label}: the paste's outputs are read`);
  assert.equal(pasteReads[0], p.first, `${label}: outputs[0]'s address is read first`);
}
/* An over-cap mismatch: UNKNOWN (step 11) naming the paste as settling nothing, `unchecked` counted, nothing written. */
function assertOverCapMismatch(out, base, label) {
  assert.equal(out.status, "UNKNOWN", `${label}: the over-cap paste with no observed output is a mismatch; the pass continues to step 11 (got ${JSON.stringify(out)})`);
  assert.match(String(out.reason), /settles nothing/, `${label}: the answer says the pasted transaction settles nothing`);
  assert.ok(Number.isSafeInteger(out.unchecked) && out.unchecked > base.unchecked, `${label}: the unread output addresses are counted as unchecked (no-paste unchecked ${base.unchecked}, with the paste ${out.unchecked})`);
}

const PG_SKIP = PG_AVAILABLE ? undefined : "REQUIREMENT_NOT_AVAILABLE in this process: isolated PostgreSQL (the rc45 runner's pg mode runs these legs; a skipped PostgreSQL leg there is a FAIL)";
for (const [backend, skip] of [["JSON", undefined], ["PostgreSQL", PG_SKIP]]) {
  const r109 = (name, options, fn) => test(`RC45 R1-09 ${backend}: ${name}`, { skip }, async () => { const x = await fresh(backend, options()); try { await fn(x); } finally { await release(x); } });
  const sdkOverCap = (label, p) => async (x) => {
    const before = await x.snap();
    const base = await measured(x, () => resolved(() => x.sdk(V.cl), "Verify without a paste"));
    assert.equal(base.value.status, "UNKNOWN", "without a paste the spent recorded outpoint answers UNKNOWN");
    const run = await measured(x, () => resolved(() => x.sdk(V.cl, p.safe), `Verify with ${label}`));
    assert.deepEqual(await x.snap(), before, `${label}: nothing is written`);
    assertCapped(p, base, run, label);
    assertOverCapMismatch(run.value, base.value, label);
  };

  /* ---------------- SDK: more than 64 outputs -> BAD_FORMAT at step 0, before any read ---------------- */
  r109("SDK step 0: a pasted transaction with more than 64 outputs (65, and the largest that fits 64 KiB) is refused BAD_FORMAT before any node call, nothing written [RED on dc7552e]", () => ({}), async (x) => {
    const { p65, max } = B.cl.P;
    for (const p of [p65, max]) {
      assert.ok(p.outputs > MAX_OUTPUTS && p.bytes <= PASTE_LIMIT);
      const before = await x.snap(), calls = x.model.calls.length;
      const e = await rejection(x.sdk(V.cl, p.safe), `a ${p.outputs}-output paste is refused (more than ${MAX_OUTPUTS} outputs)`);
      assert.equal(e.code, "BAD_FORMAT", `a ${p.outputs}-output paste: BAD_FORMAT (got ${e.code}: ${e.message})`);
      assert.equal(x.model.calls.length, calls, `a ${p.outputs}-output paste: refused before any node call`);
      assert.deepEqual(await x.snap(), before, `a ${p.outputs}-output paste: nothing is written`);
    }
  });

  /* ---------------- SDK: the step-9 read cap (C9) ---------------- */
  r109("SDK step 9: a 64-output paste (SYNTHETIC: the real recover of L with outputs to distinct TEST addresses appended) with no output observed reads outputs[0]'s address first and at most 4 further distinct output addresses (counted node calls over a no-paste Verify), and is a mismatch with unchecked counted: UNKNOWN, nothing written [RED on dc7552e]", () => ({}), async (x) => {
    assert.equal(B.cl.P.p64.outputs, MAX_OUTPUTS);
    await sdkOverCap("a 64-output paste", B.cl.P.p64)(x);
  });
  r109("SDK step 9: a paste one address over the read cap (outputs[0]'s address plus 5 further distinct addresses; SYNTHETIC) with no output observed reads at most 1 + 4 of them and is a mismatch with unchecked counted: UNKNOWN, nothing written [RED on dc7552e]", () => ({}), async (x) => {
    assert.equal(B.cl.P.over.further, READ_CAP);
    await sdkOverCap("a paste one address over the cap", B.cl.P.over)(x);
  });
  r109("SDK step 9 boundary: a paste within the read cap (outputs[0]'s address plus exactly 4 further distinct addresses; SYNTHETIC) with no output observed reads every one of them or counts what it skips: UNKNOWN, nothing written [holds on dc7552e]", () => ({}), async (x) => {
    const p = B.cl.P.within, distinct = new Set(p.addresses).size;
    assert.equal(p.further, READ_CAP - 1); assert.equal(distinct, READ_CAP);
    const before = await x.snap();
    const base = await measured(x, () => resolved(() => x.sdk(V.cl), "Verify without a paste"));
    const run = await measured(x, () => resolved(() => x.sdk(V.cl, p.safe), "Verify with the paste within the cap"));
    assert.deepEqual(await x.snap(), before, "nothing is written");
    assert.equal(run.value.status, "UNKNOWN", `the mismatch answers UNKNOWN (got ${JSON.stringify(run.value)})`);
    assert.match(String(run.value.reason), /settles nothing/);
    assert.ok(run.reads - base.reads <= READ_CAP, `at most ${READ_CAP} reads over a no-paste Verify`);
    const read = new Set(run.addresses.filter((a) => p.addresses.includes(a))).size;
    assert.ok(read === distinct || run.value.unchecked > base.value.unchecked, `every output address is read (${read} of ${distinct}) or the unread ones are counted unchecked (${run.value.unchecked})`);
  });
  r109("SDK step 9: an over-cap paste whose outputs[0] is observed exactly at depth D (SYNTHETIC 64-output document shown accepted on the chain model) still settles the vault RECOVERED: the cap never refuses an accepted recover [holds on dc7552e]", () => ({}), async (x) => {
    const p = B.cl.P.p64;
    x.model.confirm(p.frozen, p.txId); x.model.advance(SETTLE_DEPTH_DAA);
    const base = await measured(x, () => resolved(() => x.sdk(V.cl), "Verify without a paste"));
    assert.equal(base.value.status, "UNKNOWN");
    const run = await measured(x, () => resolved(() => x.sdk(V.cl, p.safe), "Verify with the accepted 64-output paste"));
    assert.equal(run.value.status, "ADVANCED", `the observed outputs[0] settles the vault (got ${JSON.stringify(run.value)})`); assert.equal(run.value.to, "RECOVERED"); assert.equal(run.value.txId, p.txId);
    const m = await x.rawManifest(V.cl);
    assert.equal(m.status, "RECOVERED"); assert.equal(m.live, null); assert.equal(m.latestTransitionTxId, p.txId);
    assert.ok(await x.receipt(p.txId), "a case-B receipt is created for the pasted transaction");
    assert.ok(run.reads - base.reads <= READ_CAP, `at most ${READ_CAP} reads over a no-paste Verify`);
  });
  for (const [label, paste] of [["a non-JSON text", () => "this is not a signed transaction"], ["a truncated 100-output paste (unparseable JSON)", () => B.cl.P.truncated]]) {
    r109(`SDK step 9: an unparseable paste (${label}) keeps the mismatch path: UNKNOWN naming the paste, no read of any paste address beyond a no-paste Verify, nothing written [holds on dc7552e]`, () => ({}), async (x) => {
      const before = await x.snap();
      const base = await measured(x, () => resolved(() => x.sdk(V.cl), "Verify without a paste"));
      const run = await measured(x, () => resolved(() => x.sdk(V.cl, paste()), `Verify with ${label}`));
      assert.deepEqual(await x.snap(), before, "nothing is written");
      assert.equal(run.value.status, "UNKNOWN", `the unparseable paste is a mismatch (got ${JSON.stringify(run.value)})`);
      assert.match(String(run.value.reason), /settles nothing/);
      assert.match(String(run.value.reason), /not a readable signed transaction/);
      assert.equal(run.reads, base.reads, "no read beyond a no-paste Verify");
    });
  }

  /* ---------------- SDK: steps 10-11 still run after an over-cap mismatch ---------------- */
  r109("SDK steps 10-11 after an over-cap mismatch: after a recorded delegate spend W1 (L0 -> L1), L1 spent and the recorded old outpoint L0 live again, a 64-output paste of the recover of L1 (SYNTHETIC) reads at most 1 + 4 paste addresses and the contradiction is still detected: CHAIN_CONTRADICTION, nothing written [RED on dc7552e]", () => ({ init: B.ct.model }), async (x) => {
    const p = B.ct.P.p64, u = B.ct.L0utxo;
    x.model.remove(B.ct.L1); x.model.add(B.ct.L0, u.amount, u.scriptPublicKey, V.ct.cov, x.model.virtualDaaScore - 5000n); x.model.advance(SETTLE_DEPTH_DAA);
    const before = await x.snap();
    const base = await measured(x, () => resolved(() => x.sdk(V.ct), "Verify without a paste"));
    assert.equal(base.value.status, "CHAIN_CONTRADICTION", `without a paste step 10 finds L0 live again (got ${JSON.stringify(base.value)})`);
    const run = await measured(x, () => resolved(() => x.sdk(V.ct, p.safe), "Verify with the 64-output paste"));
    assert.equal(run.value.status, "CHAIN_CONTRADICTION", `steps 10-11 still run after the over-cap mismatch (got ${JSON.stringify(run.value)})`);
    assert.deepEqual(await x.snap(), before, "nothing is written");
    assertCapped(p, base, run, "a 64-output paste of the recover of L1");
  });
  r109("SDK steps 10-11 after an over-cap mismatch: after a recorded delegate spend W1 (L0 -> L1) and an out-of-app spend of L1 with no contradiction, a 64-output paste of the recover of L1 (SYNTHETIC) is UNKNOWN with unchecked counted and at most 1 + 4 paste addresses read, nothing written [RED on dc7552e]", () => ({ init: B.ct.model }), async (x) => {
    const p = B.ct.P.p64;
    x.model.remove(B.ct.L1); x.model.advance(SETTLE_DEPTH_DAA);
    const before = await x.snap();
    const base = await measured(x, () => resolved(() => x.sdk(V.ct), "Verify without a paste"));
    assert.equal(base.value.status, "UNKNOWN");
    const run = await measured(x, () => resolved(() => x.sdk(V.ct, p.safe), "Verify with the 64-output paste"));
    assert.deepEqual(await x.snap(), before, "nothing is written");
    assertCapped(p, base, run, "a 64-output paste of the recover of L1");
    assertOverCapMismatch(run.value, base.value, "a 64-output paste of the recover of L1");
  });

  /* ---------------- API: the Verify route's shape check and the capped reads ---------------- */
  r109("route POST /vaults/:id/reconcile: the owner's paste with more than 64 outputs (65, and the largest that fits 64 KiB) -> 400 BAD_FORMAT from the route's shape check: no reconcile, no node call, nothing written [RED on dc7552e]", () => ({ hosted: true }), async (x) => {
    const { p65, max } = B.cl.P;
    for (const p of [p65, max]) {
      const before = await x.snap(), calls = x.model.calls.length;
      const { r, seen } = await x.route(V.cl, { outOfAppTransaction: p.safe });
      assert.equal(r.status, 400, `a ${p.outputs}-output paste: 400 BAD_FORMAT (got ${said(r)})`);
      assert.equal(r.code, "BAD_FORMAT", `a ${p.outputs}-output paste: BAD_FORMAT`);
      assert.equal(seen.length, 0, `a ${p.outputs}-output paste: no reconcile runs`);
      assert.equal(x.model.calls.length, calls, `a ${p.outputs}-output paste: no node call`);
      assert.deepEqual(await x.snap(), before, `a ${p.outputs}-output paste: nothing is written`);
    }
  });
  r109("route POST /vaults/:id/reconcile: the owner's 64-output paste (SYNTHETIC) with no output observed -> 200 UNKNOWN, a mismatch with unchecked counted, at most 1 + 4 paste addresses read with outputs[0]'s first, nothing written [RED on dc7552e]", () => ({ hosted: true }), async (x) => {
    const p = B.cl.P.p64;
    const before = await x.snap();
    const base = await measured(x, () => x.route(V.cl, {}));
    assert.equal(base.value.r.status, 200, said(base.value.r)); assert.equal(base.value.r.body.reconcile.status, "UNKNOWN");
    const run = await measured(x, () => x.route(V.cl, { outOfAppTransaction: p.safe }));
    assert.equal(run.value.r.status, 200, said(run.value.r));
    assert.equal(run.value.seen.length, 1); assert.equal(run.value.seen[0].options.outOfAppTransaction, p.safe, "the route threads the exact paste");
    assert.deepEqual(await x.snap(), before, "nothing is written");
    assertCapped(p, base, run, "the route's 64-output paste");
    assertOverCapMismatch(run.value.r.body.reconcile, base.value.r.body.reconcile, "the route's 64-output paste");
  });
  for (const [label, paste] of [["a non-JSON text", () => "this is not a signed transaction"], ["a truncated 100-output paste (unparseable JSON)", () => B.cl.P.truncated]]) {
    r109(`route POST /vaults/:id/reconcile: an unparseable paste (${label}) keeps the mismatch path: 200 UNKNOWN naming the paste, no read beyond a no-paste Verify, nothing written [holds on dc7552e]`, () => ({ hosted: true }), async (x) => {
      const before = await x.snap();
      const base = await measured(x, () => x.route(V.cl, {}));
      const run = await measured(x, () => x.route(V.cl, { outOfAppTransaction: paste() }));
      assert.equal(run.value.r.status, 200, said(run.value.r));
      const out = run.value.r.body.reconcile;
      assert.equal(out.status, "UNKNOWN", `the unparseable paste is a mismatch (got ${JSON.stringify(out)})`);
      assert.match(String(out.reason), /settles nothing/); assert.match(String(out.reason), /not a readable signed transaction/);
      assert.equal(run.reads, base.reads, "no read beyond a no-paste Verify");
      assert.deepEqual(await x.snap(), before, "nothing is written");
    });
  }
}
