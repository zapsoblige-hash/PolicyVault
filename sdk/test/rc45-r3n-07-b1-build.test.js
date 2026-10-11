"use strict";
/*
 * RC45 R3N-B1 — THE BUILD-TIME OBSERVATION D6b, its marker and its refusals (contract rc45-l201-contract-03: addendum
 * v2b revision 3 §1.1-§1.2, §7 B1-00 (a)-(f), B1-02c (i), B1-02d (i), B1-14c; writer decisions WD-5 / WD-6; writer
 * amendment A1-3, which prevails). Internal RED-first regression material for the RC45 candidate; not an external
 * engagement of any kind.
 *
 * REQUIRED BEHAVIOUR: after D6 and before the first write, every root action makes ONE connection and reads, in order:
 * (1) the chain position (getBlockDagInfo: the virtual DAA v_b and the sink; then 20 selected-parent hops and a
 * header-bound getBlock of the 20th parent, isChainBlock true: the anchor A_b) — fail-soft, the anchor null on failure
 * with v_b kept if read; (2) one UTXO read per distinct address of every NON-ROOT frozen input, in frozen order —
 * fail-closed: each must classify LIVE (exactly one entry at the outpoint, equal amount, null-aware equal covenant id,
 * equal script and script version wherever reported); (3) the anchor again (header-bound, isChainBlock true) —
 * fail-soft, the anchor recorded null otherwise. A fee input not LIVE or unreadable -> 409 FEE_INPUT_NOT_LIVE with
 * extra.feeInput { index, outpoint, reason ABSENT | MISMATCH | READ_FAILED, detail }; a treasury or vault input not
 * LIVE -> 409 RECORDED_OUTPUT_SPENT (role treasury / vault); any other read failure -> that error, 422; and (A1-3) when
 * the anchor read or its recheck fails AND some non-root input is less than 1,000 DAA deep at build -> 422
 * OBSERVATION_ERROR. Nothing is written in every refused case. The build's existing first write carries the marker
 * inputObservation { schema "policyvault-input-observation/1", txId, virtualDaa, anchor { hash, daaScore } | null, at,
 * inputs [{ index, role, outpoint, blockDaaScore }] } (every non-root input in frozen order); it is not part of the
 * completion receipt pointer. The four named constants are exported and pinned (WD-6).
 *
 * Layers and labels as in sdk/test/rc45-r3n-07-b1-submit.test.js. TEST keys only; nothing dials a node.
 */
const KK = require("../testutil/rc45-r2-kas-kit");
KK.installNode(); // before anything loads server/src/api.js or the v7 request modules
const assert = require("node:assert/strict");
const { test, before, after } = require("node:test");
const B1 = require("../testutil/rc45-r3n-b1-kit");
const { KAS } = KK;
const { lower, sameOp, SCHEMAS, DEPTH } = B1;
const DF = require("../testutil/org-root-durable-fixture");
const TOOLCHAIN = DF.toolchainAvailable();

const S = B1.b1Scenario("b1bld");
const { ctx } = S;

before(async () => {
  assert.ok(TOOLCHAIN, "real compiler, encoder and VM are required (a missing VM toolchain is a FAIL, never a SKIP)");
  await S.setup();
});
after(async () => { await S.teardown(); });

/* the D6b reads of one build, as the node saw them (after D6's own reads) */
function walkOf(calls) {
  const i = calls.findIndex((c, k) => c.method === "getBlockDagInfo" && calls.slice(k + 1, k + 22).every((d) => d.method === "getBlock") && calls.slice(k + 1, k + 22).length === 21);
  return i;
}
const addrRead = (c, address) => c.method === "getUtxosByAddresses" && c.args && c.args.addresses.includes(address);

for (const [backend, skip] of [["JSON", undefined], ["PostgreSQL", S.S.PG_SKIP]]) {
  const leg = (name, fn) => test(`RC45 R3N-B1 ${backend}: ${name}`, { skip }, async () => { const x = await S.fresh(backend); try { await fn(x); } finally { await S.release(x); } });

  leg("B1-00 D6b on a v0.7-kas operation (T2 AUTHORIZE + pause, explicit fee input): the build reads the virtual DAA before the non-root input reads, walks 20 selected parents to the anchor A_b (header-bound, isChainBlock), reads the treasury and fee addresses, then re-reads A_b; the request carries inputObservation (schema, txId, virtualDaa = v_b, anchor = A_b with its header DAA, every non-root input in frozen order with role and blockDaaScore); the completion receipt pointer is identical with and without the marker [RED on 5b6d8e9: the request carries no inputObservation and the build makes no walk]", async (x) => {
    const fuel = S.seededFuel(x, "b100-fee");
    x.chain.sync();
    const vb = S.v(x), A_b = x.chain.ancestor(20);
    x.chain.resetCalls();
    const r = await S.build(x, S.vaultOpBody(ctx.T2, "ownerPause", "authorize", fuel));
    assert.equal(r.status, 201, `built (${S.said2(r)})`);
    const q = await x.rootReq(r.body.request.id);
    const m = q.inputObservation;
    assert.ok(m && typeof m === "object", "the request carries inputObservation");
    assert.equal(m.schema, SCHEMAS.observation);
    assert.equal(lower(m.txId), lower(q.txId), "names the request's txId");
    assert.equal(String(m.virtualDaa), String(vb), "virtualDaa is the virtual DAA read at build");
    assert.deepEqual(m.anchor, { hash: A_b.hash, daaScore: String(A_b.daa) }, "the anchor is the 20th selected parent of the sink with its own header DAA");
    const T = S.inputOf(x, q, "treasury"), F = S.inputOf(x, q, "fee");
    assert.deepEqual(m.inputs.map((e) => ({ index: e.index, role: e.role, outpoint: { transactionId: lower(e.outpoint.transactionId), index: Number(e.outpoint.index) } })), [T, F].sort((a, b) => a.index - b.index).map((i) => ({ index: i.index, role: i === T ? "treasury" : "fee", outpoint: i.outpoint })), "every non-root input in frozen order with its role and outpoint");
    const stampOf = (op) => String(x.node.entryAt(op).entry.daaStamp);
    for (const e of m.inputs) assert.equal(String(e.blockDaaScore), stampOf(e.outpoint), `input ${e.index}: the node's blockDaaScore`);
    const calls = x.chain.calls();
    const w = walkOf(calls);
    assert.ok(w >= 0, "a getBlockDagInfo followed by 21 getBlock (20 hops + the anchor)");
    const feeRead = calls.findIndex((c, k) => k > w + 21 && addrRead(c, F.address));
    assert.ok(feeRead > w + 21, "the fee address is read after the walk (v_b before the UTXO reads)");
    const recheck = calls.findIndex((c, k) => k > feeRead && c.method === "getBlock" && lower(c.args.hash) === A_b.hash);
    assert.ok(recheck > feeRead, "A_b is re-read after the non-root input reads");
    const wr7 = KK.lazy.wr7;
    const without = { ...q }; delete without.inputObservation;
    assert.deepEqual(wr7.completionReceiptPointer(q), wr7.completionReceiptPointer(without), "the marker is not part of the completion receipt pointer");
  });

  leg("B1-00 (a) the chain walk fails at build while every non-root input is at least 1,000 DAA deep: the build is admitted (fail-soft) with inputObservation.anchor null and virtualDaa kept [RED on 5b6d8e9: no inputObservation]", async (x) => {
    const fuel = S.seededFuel(x, "b100a-fee", { age: 5000n });
    const vb = S.v(x);
    x.chain.fault("getBlock", { nth: 1 });
    const r = await S.build(x, S.vaultOpBody(ctx.T2, "ownerPause", "authorize", fuel));
    assert.equal(r.status, 201, `admitted (${S.said2(r)})`);
    const m = (await x.rootReq(r.body.request.id)).inputObservation;
    assert.ok(m, "the marker is recorded");
    assert.equal(m.anchor, null, "the anchor is null");
    assert.equal(String(m.virtualDaa), String(vb), "v_b is kept");
  });

  leg("B1-00 (a) A1-3 variant: the chain walk (or the anchor's recheck) fails at build while a non-root input is less than 1,000 DAA deep: 422 OBSERVATION_ERROR, nothing written; with the walk restored the same build is admitted [RED on 5b6d8e9: the build is recorded (201)]", async (x) => {
    for (const [label, arm] of [["the walk fails", () => x.chain.fault("getBlock", { nth: 1 })], ["the anchor's recheck fails", () => x.chain.fault("getBlock", { nth: 22 })]]) {
      const fuel = S.seededFuel(x, `b100a3-${label.length}-fee`, { age: 999n });
      arm();
      await S.writesNothing(x, label, () => S.build(x, S.vaultOpBody(ctx.T2, "ownerPause", "authorize", fuel)), (r) => {
        assert.equal(r.status, 422, `${label}: refused 422 (${S.said2(r)})`);
        assert.equal(r.code, "OBSERVATION_ERROR", `${label}: OBSERVATION_ERROR (${S.said2(r)})`);
      });
      x.chain.clearFaults();
    }
    const ok = await S.build(x, S.vaultOpBody(ctx.T2, "ownerPause", "authorize", S.seededFuel(x, "b100a3-ok-fee", { age: 999n })));
    assert.equal(ok.status, 201, `with the walk readable the build is admitted (${S.said2(ok)})`);
    const okm = (await x.rootReq(ok.body.request.id)).inputObservation;
    assert.ok(okm && okm.anchor && /^[0-9a-f]{64}$/.test(okm.anchor.hash), "the admitted build carries an anchor");
  });

  leg("B1-00 (b) the explicit fee input ABSENT (never on the index), MISMATCH (another amount), or its address read failing: 409 FEE_INPUT_NOT_LIVE with extra.feeInput { index, outpoint, reason ABSENT | MISMATCH | READ_FAILED }, nothing written; and an autoFuel fee input spent between autoFuel's read and D6b's read: FEE_INPUT_NOT_LIVE ABSENT [RED on 5b6d8e9: each build is recorded (201)]", async (x) => {
    const feeRefusal = (label, reason, outpoint) => (r) => {
      assert.equal(r.status, 409, `${label}: 409 (${S.said2(r)})`);
      assert.equal(r.code, "FEE_INPUT_NOT_LIVE", `${label}: FEE_INPUT_NOT_LIVE (${S.said2(r)})`);
      const f = r.extra && r.extra.feeInput;
      assert.ok(f && typeof f === "object", `${label}: extra.feeInput (${S.said2(r)})`);
      assert.equal(f.reason, reason, `${label}: reason ${reason}`);
      assert.ok(Number.isInteger(Number(f.index)), `${label}: names the input's index`);
      assert.ok(sameOp(f.outpoint, outpoint), `${label}: names the fee outpoint`);
    };
    const absent = KK.p2pkUtxo(ctx.w.fee, "b1bld-b100b-absent");
    await S.writesNothing(x, "ABSENT", () => S.build(x, S.rootOnlyBody("freeze", absent)), feeRefusal("ABSENT", "ABSENT", absent.outpoint));
    const mism = S.seededFuel(x, "b100b-mismatch");
    x.node.mutateEntry(mism.outpoint, { amount: BigInt(mism.amount) + 1n });
    await S.writesNothing(x, "MISMATCH", () => S.build(x, S.rootOnlyBody("freeze", mism)), feeRefusal("MISMATCH", "MISMATCH", mism.outpoint));
    const unread = S.seededFuel(x, "b100b-unread");
    x.chain.fault("getUtxosByAddresses", { pred: (c) => c.args.addresses.includes(ctx.w.fee.address), always: true });
    await S.writesNothing(x, "READ_FAILED", () => S.build(x, S.rootOnlyBody("freeze", unread)), feeRefusal("READ_FAILED", "READ_FAILED", unread.outpoint));
    x.chain.clearFaults();
    /* autoFuel: owner 2 signs in and builds with its only ordinary UTXO; it is spent right after autoFuel read it */
    const o2 = ctx.w.o2;
    const own = S.seededFuel(x, "b100b-auto", { wallet: o2, amountKas: 40n });
    for (const [, es] of x.node.table()) for (const e of es) if (e.address === o2.address && !sameOp(e.outpoint, own.outpoint)) x.node.spendOutpoint(e.outpoint);
    x.chain.after("getUtxosByAddresses", (c) => c.args.addresses.includes(o2.address), 1, () => x.node.spendOutpoint(own.outpoint));
    await S.writesNothing(x, "autoFuel spent between the two reads", () => S.build(x, { action: "freeze", params: {}, vaultOperations: [], signerAddress: o2.address }, { cookie: x.cookie.o2 }), feeRefusal("autoFuel", "ABSENT", own.outpoint));
  });

  leg("B1-00 (c) T2's output spent between D6's read and D6b's read (the build's two treasury reads): 409 RECORDED_OUTPUT_SPENT naming the treasury input, nothing written [RED on 5b6d8e9: the build is recorded (201)]", async (x) => {
    const t2 = await x.vault(ctx.T2);
    const fuel = S.seededFuel(x, "b100c-fee");
    const addr = x.node.entryAt(t2.live.outpoint).address;
    x.chain.after("getUtxosByAddresses", (c) => c.args.addresses.includes(addr), 1, () => x.node.spendOutpoint(t2.live.outpoint));
    await S.writesNothing(x, "treasury spent between the reads", () => S.build(x, S.vaultOpBody(ctx.T2, "ownerPause", "authorize", fuel)), (r) => {
      assert.equal(r.status, 409, `refused (${S.said2(r)})`);
      assert.equal(r.code, "RECORDED_OUTPUT_SPENT", S.said2(r));
      assert.match(String(r.message), /treasury/i, "names the treasury input");
      assert.ok(lower(r.message).includes(`${lower(t2.live.outpoint.transactionId)}:${Number(t2.live.outpoint.index)}`), "names the outpoint");
    });
  });

  leg("B1-00 (d) a read failure on the treasury address in D6b (D6's own read succeeded): the node's error, 422, nothing written [RED on 5b6d8e9: the build is recorded (201)]", async (x) => {
    const t2 = await x.vault(ctx.T2);
    const fuel = S.seededFuel(x, "b100d-fee");
    const addr = x.node.entryAt(t2.live.outpoint).address;
    const MSG = "TEST node: the treasury address read failed (connection reset)";
    x.chain.fault("getUtxosByAddresses", { pred: (c) => c.args.addresses.includes(addr), nth: 2, message: MSG });
    await S.writesNothing(x, "treasury address read fails", () => S.build(x, S.vaultOpBody(ctx.T2, "ownerPause", "authorize", fuel)), (r) => {
      assert.equal(r.status, 422, `422 (${S.said2(r)})`);
      assert.ok(String(r.message).includes(MSG), `the node's error is carried (${S.said2(r)})`);
      assert.notEqual(r.code, "RECORDED_OUTPUT_SPENT");
    });
  });

  leg("B1-00 (e) A_b leaves the selected chain between D6b's walk and its recheck (inputs deep): the build is admitted with inputObservation.anchor null [RED on 5b6d8e9: no inputObservation]", async (x) => {
    const fuel = S.seededFuel(x, "b100e-fee", { age: 5000n });
    x.chain.after("getUtxosByAddresses", (c) => c.args.addresses.includes(ctx.w.fee.address), 1, () => {
      x.chain.freeze();
      x.chain.reorg({ depth: 22, blocks: Array.from({ length: 22 }, () => ({})) });
    });
    const r = await S.build(x, S.vaultOpBody(ctx.T2, "ownerPause", "authorize", fuel));
    x.chain.thaw();
    assert.equal(r.status, 201, `admitted (${S.said2(r)})`);
    const m = (await x.rootReq(r.body.request.id)).inputObservation;
    assert.ok(m, "the marker is recorded");
    assert.equal(m.anchor, null, "A_b left the chain before the recheck: the anchor is recorded null");
  });

  leg("B1-02c (i) (WD-5) an explicit params.fuel whose creating transaction F is withheld (never accepted: the output is on no index): 409 FEE_INPUT_NOT_LIVE (ABSENT), nothing written, the root not reserved [RED on 5b6d8e9: the build is recorded (201)]", async (x) => {
    const never = x.chain.fund(ctx.w.fee, 50n * KAS, { tag: "b1bld-b102c-withheld", accept: false });
    await S.writesNothing(x, "never-created fee input", () => S.build(x, S.rootOnlyBody("freeze", never.fuel)), (r) => {
      assert.equal(r.code, "FEE_INPUT_NOT_LIVE", S.said2(r));
      assert.equal(r.extra && r.extra.feeInput && r.extra.feeInput.reason, "ABSENT");
    });
    assert.equal((await S.rootRec(x)).pendingRequestId, null, "the root is not reserved");
  });

  leg("B1-02d (i) (WD-5) a fee input whose node entry has other contents (another script): 409 FEE_INPUT_NOT_LIVE (MISMATCH), nothing written [RED on 5b6d8e9: the build is recorded (201)]", async (x) => {
    const fuel = S.seededFuel(x, "b102d-fee");
    x.node.mutateEntry(fuel.outpoint, { scriptPublicKey: { version: 0, script: `20${"77".repeat(32)}ac` } });
    await S.writesNothing(x, "fee input with other contents", () => S.build(x, S.rootOnlyBody("freeze", fuel)), (r) => {
      assert.equal(r.code, "FEE_INPUT_NOT_LIVE", S.said2(r));
      assert.equal(r.extra && r.extra.feeInput && r.extra.feeInput.reason, "MISMATCH");
    });
  });
}

test("RC45 R3N-B1 JSON: B1-00 (f) a policyvault-0.7-payment vault input that the node does not report unspent at build (testnet profile; the fee input live): 409 RECORDED_OUTPUT_SPENT naming the vault role and outpoint, nothing written (the payment profile's records live in the shared durable fixture's JSON root) [RED on 5b6d8e9: the build is recorded]", async () => {
  const cfg = DF.freshJsonConfig("pv-r3n-b1-b100f-");
  const rpc = DF.mockRpc();
  const o = await DF.organization(cfg, rpc);
  const fuel = DF.fuelUtxoFor(cfg, o.fuelKey);
  const fuelAddr = KK.lazy.chain.loadKaspa(cfg).addressFromScriptPublicKey({ version: 0, script: fuel.scriptPublicKeyHex }, cfg.networkId).toString();
  rpc.seed(fuelAddr, DF.utxo(fuelAddr, fuel.outpoint.transactionId, fuel.outpoint.index, fuel.amount, null));
  const vault = await KK.lazy.wr7.loadRootedVaultAny(cfg, o.vaultId);
  assert.ok(vault && vault.live && vault.contractVersion === "policyvault-0.7-payment", "a live v0.7-payment vault");
  /* the node no longer reports the vault's recorded output (spent outside PolicyVault) */
  const node = { ...rpc, async getUtxosByAddresses(args) { const r = await rpc.getUtxosByAddresses(args); return { entries: r.entries.filter((e) => !sameOp(e.outpoint, vault.live.outpoint)) }; } };
  const before = KK.strictJson(await KK.kasRecords(cfg));
  const owner1 = DF.ADDR(cfg, o.owner1);
  let err = null;
  try { await KK.NODE().with(node, () => KK.lazy.wr7.buildRootActionRequest({ config: cfg, rootCovenantId: o.rootCovenantId, action: "authorize", params: { fuel }, vaultOperations: [{ vaultId: o.vaultId, action: "ownerPause", params: {} }], signerAddress: owner1 })); } catch (e) { err = e; }
  assert.ok(err, "the build is refused");
  assert.equal(err.code, "RECORDED_OUTPUT_SPENT", `RECORDED_OUTPUT_SPENT (${err && err.code} ${err && err.message})`);
  assert.equal(err.status, 409, "409 on the error");
  assert.match(String(err.message), /\bvault\b/i, "names the vault role");
  assert.ok(lower(err.message).includes(`${lower(vault.live.outpoint.transactionId)}:${Number(vault.live.outpoint.index)}`), "names the vault outpoint");
  assert.equal(KK.strictJson(await KK.kasRecords(cfg)), before, "nothing is written");
});

test("RC45 R3N-B1: B1-14c (WD-6) the four named constants are exported by sdk/src/wallet-requests-v7.js with their bound values: INPUT_SPENT_WITHDRAWAL_DEPTH_DAA = ATTRIBUTION_DEPTH_DAA = 1000n, CHAIN_ANCHOR_HOPS = 20, WITHDRAWAL_ANCHOR_MAX_AGE_DAA = 12000n, WITHDRAWAL_SCAN_MAX_BATCHES = 64 [RED on 5b6d8e9: the constants do not exist]", () => {
  const wr7 = KK.lazy.wr7;
  assert.equal(wr7.ATTRIBUTION_DEPTH_DAA, 1000n);
  assert.equal(wr7.INPUT_SPENT_WITHDRAWAL_DEPTH_DAA, 1000n, "the withdrawal depth");
  assert.equal(wr7.INPUT_SPENT_WITHDRAWAL_DEPTH_DAA, wr7.ATTRIBUTION_DEPTH_DAA, "equal to the attribution depth");
  assert.equal(wr7.CHAIN_ANCHOR_HOPS, 20, "the anchor hops");
  assert.equal(wr7.WITHDRAWAL_ANCHOR_MAX_AGE_DAA, 12000n, "the anchor's maximum age");
  assert.equal(wr7.WITHDRAWAL_SCAN_MAX_BATCHES, 64, "the scan budget");
  void DEPTH;
});
