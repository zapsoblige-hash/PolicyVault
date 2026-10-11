"use strict";
/*
 * RC45 R3N-B1 — THE TWO-STEP WITHDRAWAL OF A FINALIZED, NEVER-ATTEMPTED REQUEST WHOSE INPUT WAS SPENT BY ANOTHER
 * TRANSACTION (contract rc45-l201-contract-03: addendum v2b revision 3 §4 W1-W8, §6, §7 B1-02e (ii), B1-02f, B1-02j,
 * B1-06, B1-06b, B1-07, B1-07b, B1-07d, B1-07e, B1-07f, B1-07g, B1-07h; writer amendment A1-2 (K1'), A1-4 (dispatch)
 * and OS-03 (discriminating renewal legs), which prevail). Internal RED-first regression material for the RC45
 * candidate; not an external engagement of any kind.
 *
 * REQUIRED BEHAVIOUR: only a SIGNED request enters the new branch (A1-4); W1 record preconditions (rootAction, SIGNED,
 * a binding finalTransaction, no attempt evidence, the root binding to P = manifest.root.outpoint = root.live.outpoint,
 * a bound inputObservation) else CANNOT_REJECT RECORD; then one connection and the reads r0 (the 20-deep anchor A),
 * r1 (P LIVE and exact, else ROOT_INPUT_NOT_LIVE), r2 (the non-root inputs: MISMATCH -> INPUT_CONTRADICTED, none absent
 * -> INPUTS_LIVE, the absent ones with existence evidence E1 / E1s / E2 / E3 / recorded finalAt -> Ê, Ê empty ->
 * INPUT_EXISTENCE_UNPROVEN), r3 (X in the mempool: an exact miss or orphan-only, else IN_TRANSACTION_POOL /
 * MEMPOOL_UNCLEAR), r4 (P again, the same entry, else UNSTABLE), r5 (no entry under X at any frozen-output address,
 * else OWN_OUTPUT); any node error -> NODE_ERROR; every refusal writes nothing and carries extra.withdrawal.finding.
 * W6: no bound anchor -> write it (W7a) and answer 409 WITHDRAWAL_DEPTH_PENDING { earliestDaa = A + 1,000, latestDaa =
 * A + 12,000 }; age < 1,000 -> pending, nothing written; age > 12,000 -> renew; the continuing set K (anchored inputs of
 * Ê whose existence block lies at or below A1 and 1,000 DAA below v) empty -> renew; the acceptance window from A1
 * incomplete or throwing -> renew, accepting X -> CANNOT_REJECT; the block scan from A1 throwing -> CANNOT_REJECT
 * SCAN_UNCLEAR, incomplete or naming any spender other than X (inclusion, not acceptance) -> renew; otherwise REFUSED
 * (inputSpentWithdrawal), the pointer released by the existing tail. A reload check before every save (STORE_CHANGED).
 * K1': at the existing slot-request, slot-signature and finalize saves, fail-soft, existence of a non-root input without
 * E1 is recorded final (finalAt) only when the existence block is on the selected chain and 1,000 DAA deep.
 *
 * Layers and labels as in sdk/test/rc45-r3n-07-b1-submit.test.js. TEST keys only; nothing dials a node.
 */
const KK = require("../testutil/rc45-r2-kas-kit");
KK.installNode(); // before anything loads server/src/api.js or the v7 request modules
const assert = require("node:assert/strict");
const { test, before, after } = require("node:test");
const B1 = require("../testutil/rc45-r3n-b1-kit");
const { D, said, withAnchor } = KK;
const { lower, sameOp, DEPTH, MAX_AGE } = B1;
const TOOLCHAIN = require("../testutil/org-root-durable-fixture").toolchainAvailable();

const S = B1.b1Scenario("b1wd");
const { ctx } = S;

before(async () => {
  assert.ok(TOOLCHAIN, "real compiler, encoder and VM are required (a missing VM toolchain is a FAIL, never a SKIP)");
  await S.setup();
});
after(async () => { await S.teardown(); });

const finalizedT2 = (x, tag, fuelOpts = {}) => S.finalizedB(x, S.vaultOpBody(ctx.T2, "ownerPause", "authorize", S.seededFuel(x, `${tag}-fee`, fuelOpts)), tag);
const anchorOf = async (x, id) => { const m = (await x.rootReq(id)).inputSpentObservation; return m ? { hash: m.anchor.hash, daa: BigInt(m.anchor.daaScore), at: m.at } : null; };
/* B (T2 pause, deep fee) whose fee input was spent by C accepted `depthBlocks`-ish deep, at withdrawal step 1 with its anchor */
async function atStep1(x, tag, { advance = 100n } = {}) {
  const B = await finalizedT2(x, tag);
  const F = S.inputOf(x, B, "fee");
  const C = x.chain.conflictingSpend([F.outpoint], { tag: `${tag}-c` });
  for (let a = 0n; a < BigInt(advance); a += 100n) x.chain.advance(100n); // 21 chain blocks per 100 DAA
  const s1 = await S.withdraw(x, B.id);
  S.assertPending(s1, `${tag} step 1`);
  return { B, F, C, A1: await anchorOf(x, B.id) };
}
/* a step that must RENEW: 409 pending, B SIGNED, the reservation kept, a new anchor (the 20-deep ancestor at this call) */
async function assertRenews(x, id, label, { profile = null } = {}) {
  const prev = await anchorOf(x, id);
  x.chain.sync();
  const expect = x.chain.ancestor(20).hash;
  x.chain.resetCalls();
  const r = await S.withdraw(x, id);
  S.assertPending(r, `${label}: renewed`);
  const q = await x.rootReq(id);
  assert.equal(q.state, "SIGNED", `${label}: B stays SIGNED`);
  assert.equal((await S.rootRec(x)).pendingRequestId, id, `${label}: B keeps the reservation`);
  const now = await anchorOf(x, id);
  assert.notEqual(now.hash, prev.hash, `${label}: the anchor is renewed`);
  assert.equal(now.hash, expect, `${label}: renewed on this call's 20-deep ancestor`);
  if (profile) profile(x.chain.calls(), prev);
  return now;
}
/* OS-03: the renewal happened at step 4 — no acceptance window from A1 and no block scan. (A getVirtualChainFromBlock
 * from the request's build anchor A_b is an E3 existence read, not the window; when A1 happens to be A_b only the scan
 * count tells the steps apart: with a complete window, a step that passed step 4 always scans.) */
const renewedAtStep4 = (label, ab = null) => (calls, prev) => {
  assert.equal(calls.filter((c) => c.method === "getBlocks").length, 0, `${label}: no block scan (renewed before the window)`);
  if (prev.hash !== ab) assert.equal(calls.filter((c) => c.method === "getVirtualChainFromBlock" && lower(c.args.startHash) === prev.hash).length, 0, `${label}: no acceptance window from A1`);
};
async function stepRefused(x, id, label) {
  const r = await S.withdraw(x, id);
  assert.equal(r.status, 200, `${label}: withdrawn (${S.said2(r)})`);
  return S.assertWithdrawn(x, id, label);
}

for (const [backend, skip] of [["JSON", undefined], ["PostgreSQL", S.S.PG_SKIP]]) {
  const leg = (name, fn) => test(`RC45 R3N-B1 ${backend}: ${name}`, { skip }, async () => { const x = await S.fresh(backend); try { await fn(x); } finally { await S.release(x); } });

  /* ---------------------------------------- B1-06 the refusal matrix ---------------------------------------- */
  async function matrix(x, strict) {
    const B = await finalizedT2(x, "b106");
    const F = S.inputOf(x, B, "fee"), T = S.inputOf(x, B, "treasury"), P = S.inputOf(x, B, "root");
    const id = B.id;
    const refuse = async (label, finding, arm = null, disarm = null) => {
      if (arm) await arm();
      try {
        await S.writesNothing(x, label, () => S.withdraw(x, id), (r) => {
          assert.equal(r.code, "CANNOT_REJECT", `${label}: CANNOT_REJECT (${S.said2(r)})`);
          const got = r.extra && r.extra.withdrawal && r.extra.withdrawal.finding;
          if (strict || got !== undefined) assert.equal(got, finding, `${label}: finding ${finding} (${S.said2(r)})`);
        });
      } finally { if (disarm) await disarm(); x.chain.clearFaults(); for (const m of ["getBlockDagInfo", "getBlock", "getMempoolEntry", "getUtxosByAddresses", "getVirtualChainFromBlock", "getBlocks"]) x.chain.override(m, null); }
    };
    /* every input live */
    await refuse("every input LIVE", "INPUTS_LIVE");
    /* the fee input spent by C (deep): from here on a correct step would record the anchor, unless the condition holds */
    x.chain.conflictingSpend([F.outpoint], { tag: "b106-c" });
    x.chain.advance(100n);
    const edit = (fn) => x.editRootReq(id, fn);
    const snapshot = await x.rootReq(id);
    const restoreReq = () => x.editRootReq(id, (q) => { for (const k of Object.keys(q)) delete q[k]; Object.assign(q, structuredClone(snapshot)); });
    const C = () => KK.lazy.store.Categories;
    for (const [label, write, del] of [
      ["attempt evidence: submissionAttempt", () => edit((q) => { q.submissionAttempt = { id: "rc45-b1-test", phase: "PREPARING", requestFingerprint: "00", at: new Date().toISOString() }; }), restoreReq],
      ["attempt evidence: submissionOutcome", () => edit((q) => { q.submissionOutcome = { outcome: "NOT_BROADCAST" }; }), restoreReq],
      ["attempt evidence: a submission claim", () => x.store.write(C().SUBMISSION_CLAIM, lower(B.txId), { txId: lower(B.txId), vaultId: ctx.rootId, action: B.action }), () => x.store.remove(C().SUBMISSION_CLAIM, lower(B.txId))],
      ["attempt evidence: a receipt", () => x.store.write(C().RECEIPT, lower(B.txId), { txId: lower(B.txId) }), () => x.store.remove(C().RECEIPT, lower(B.txId))],
      ["attempt evidence: a root claim naming X", async () => { await require("../src/submission-claim").claimTransition(x.config, { outpoint: P.outpoint, action: B.action, txId: lower(B.txId), vaultId: ctx.rootId, stateId: null, expected: { kind: "orgRootRequest", requestId: id } }); }, () => x.store.remove(C().TRANSITION_CLAIM, require("../src/submission-claim").transitionClaimKey(P.outpoint))]
    ]) {
      await write();
      const scope0 = await x.scope();
      try {
        const r = await S.withdraw(x, id);
        assert.equal(r.code, "CANNOT_REJECT", `${label}: CANNOT_REJECT (${S.said2(r)})`);
        const got = r.extra && r.extra.withdrawal && r.extra.withdrawal.finding;
        if (strict || got !== undefined) assert.equal(got, "RECORD", `${label}: finding RECORD`);
        assert.equal(await x.scope(), scope0, `${label}: nothing is written`);
      } finally { await del(); }
    }
    const restoreEntry = (op) => { const e = x.node.entryAt(op); return () => { if (!x.node.entryAt(op)) x.node.putEntry(e.address, { ...e.entry }); }; };
    let undo = null;
    await refuse("P ABSENT", "ROOT_INPUT_NOT_LIVE", () => { undo = restoreEntry(P.outpoint); x.node.spendOutpoint(P.outpoint); }, () => undo());
    await refuse("P MISMATCH", "ROOT_INPUT_NOT_LIVE", () => { undo = x.node.mutateEntry(P.outpoint, { amount: BigInt(P.input.utxo.amount) + 1n }); }, () => undo());
    await refuse("U MISMATCH (T2 with another value)", "INPUT_CONTRADICTED", () => { undo = x.node.mutateEntry(T.outpoint, { amount: BigInt(T.input.utxo.amount) + 1n }); }, () => undo());
    await refuse("absent without existence: no marker", "RECORD", () => edit((q) => { delete q.inputObservation; }), restoreReq);
    await refuse("absent without existence: an unbound marker", "RECORD", () => edit((q) => { q.inputObservation = { ...q.inputObservation, schema: "policyvault-input-observation/0" }; }), restoreReq);
    await refuse("an entry under X at a frozen-output address", "OWN_OUTPUT", () => {
      const o = B.build.frozen.outputs[0];
      const addr = KK.lazy.chain.loadKaspa(x.config).addressFromScriptPublicKey({ version: o.scriptPublicKey.version, script: o.scriptPublicKey.scriptHex }, x.config.networkId).toString();
      x.node.putEntry(addr, { outpoint: { transactionId: lower(B.txId), index: 0 }, amount: BigInt(o.value), covenantId: o.covenant ? lower(o.covenant.covenantId) : null, scriptPublicKey: { version: o.scriptPublicKey.version, script: o.scriptPublicKey.scriptHex }, daaStamp: String(S.v(x)) });
    }, () => x.node.spendOutpoint({ transactionId: lower(B.txId), index: 0 }));
    x.chain.registerRequest(B);
    await refuse("X in the transaction pool", "IN_TRANSACTION_POOL", () => x.chain.toMempool(lower(B.txId)), () => x.chain.dropMempool(lower(B.txId)));
    await refuse("a malformed mempool answer", "MEMPOOL_UNCLEAR", () => x.chain.override("getMempoolEntry", async () => ({ mempoolEntry: { fee: 0n, transaction: { version: 1 }, isOrphan: true } })));
    await refuse("a non-boolean isOrphan", "MEMPOOL_UNCLEAR", () => { x.chain.toMempool(lower(B.txId)); x.chain.override("getMempoolEntry", async (a, real) => { const r = await real(); r.mempoolEntry.isOrphan = "yes"; return r; }); }, () => x.chain.dropMempool(lower(B.txId)));
    await refuse("P changing between r1 and r4", "UNSTABLE", () => {
      const addr = P.address;
      x.chain.after("getUtxosByAddresses", (c) => c.args.addresses.includes(addr), 1, () => { undo = x.node.mutateEntry(P.outpoint, { daaStamp: String(S.v(x)) }); });
    }, () => { if (undo) undo(); x.chain.state.hooks.length = 0; });
    const nodeCases = [
      ["r0 throws", () => x.chain.fault("getBlockDagInfo", { nth: 1 })],
      ["r0 hop throws", () => x.chain.fault("getBlock", { nth: 3 })],
      ["r1 throws", () => x.chain.fault("getUtxosByAddresses", { pred: (c) => c.args.addresses.includes(P.address), nth: 1 })],
      ["r2 throws", () => x.chain.fault("getUtxosByAddresses", { pred: (c) => c.args.addresses.includes(F.address), nth: 1 })],
      ["r3 throws (not an exact miss)", () => x.chain.fault("getMempoolEntry", { nth: 1, message: "TEST node: the mempool read failed (connection reset)" })],
      ["r4 throws", () => x.chain.fault("getUtxosByAddresses", { pred: (c) => c.args.addresses.includes(P.address), nth: 2 })]
    ];
    for (const [label, arm] of nodeCases) await refuse(label, "NODE_ERROR", arm);
    {
      const kaspa = KK.lazy.chain.loadKaspa(x.config);
      const inAddrs = new Set([P.address, T.address, F.address]);
      const outAddr = B.build.frozen.outputs.map((o) => kaspa.addressFromScriptPublicKey({ version: o.scriptPublicKey.version, script: o.scriptPublicKey.scriptHex }, x.config.networkId).toString()).find((a) => !inAddrs.has(a));
      await refuse("r5 throws", "NODE_ERROR", () => x.chain.fault("getUtxosByAddresses", { pred: (c) => c.args.addresses.includes(outAddr), always: true }));
    }
    /* the node unreachable: the real connect over a TEST client that refuses the connection */
    {
      const scope0 = await x.scope();
      const r = await KK.R.withNodeClient(x.config, { connectError: "TEST node refused the connection (ECONNREFUSED 127.0.0.1:1)" }, () => x.call("POST", ["org-roots", ctx.rootId, "requests", id, "reject"], { reason: "RC45 R3N-B1 TEST" }, x.cookie.o1));
      assert.equal(r.code, "CANNOT_REJECT", `the node unreachable: CANNOT_REJECT (${S.said2(r)})`);
      const got = r.extra && r.extra.withdrawal && r.extra.withdrawal.finding;
      if (strict || got !== undefined) assert.equal(got, "NODE_ERROR", "the node unreachable: NODE_ERROR");
      assert.equal(await x.scope(), scope0, "the node unreachable: nothing is written");
    }
    await refuse("the root record not at P", "RECORD", async () => { await x.store.write(KK.lazy.store.Categories.ORG_ROOT, ctx.rootId, { ...(await S.rootRec(x)), live: { ...(await S.rootRec(x)).live, outpoint: { transactionId: "ee".repeat(32), index: 0 } } }); }, async () => { const r = await S.rootRec(x); await x.store.write(KK.lazy.store.Categories.ORG_ROOT, ctx.rootId, { ...r, live: { ...r.live, outpoint: P.outpoint } }); });
    await refuse("a damaged finalTransaction", "RECORD", () => edit((q) => { q.finalTransaction = { ...q.finalTransaction, outputs: q.finalTransaction.outputs.slice(1) }; }), restoreReq);
    await refuse("a frozen root input that is not manifest.root.outpoint", "RECORD", () => edit((q) => { q.manifest = { ...q.manifest, root: { ...q.manifest.root, outpoint: { transactionId: "ef".repeat(32), index: 0 } } }; }), restoreReq);
    /* the state not SIGNED (BROADCAST: attempted) takes the existing path: CANNOT_REJECT */
    {
      await edit((q) => { q.state = "BROADCAST"; });
      const scope0 = await x.scope();
      const r = await S.withdraw(x, id);
      assert.equal(r.code, "CANNOT_REJECT", `the state not SIGNED: CANNOT_REJECT (${S.said2(r)})`);
      assert.equal(await x.scope(), scope0, "the state not SIGNED: nothing is written");
      await restoreReq();
    }
    return { B, F };
  }

  leg("B1-06 (sabotage matrix) every withdrawal refusal of a finalized B answers CANNOT_REJECT and writes nothing: every input live; each kind of attempt evidence; P absent or with other contents; U with other contents; no or an unbound marker; an entry under X; X in the transaction pool; a malformed mempool answer; P changing between r1 and r4; r0-r5 each throwing; the node unreachable; the root record not at P; a damaged finalTransaction; a frozen root input not manifest.root.outpoint; the state not SIGNED (when the answer names a finding, it is the contract's) [PIN: holds on 5b6d8e9]", async (x) => {
    await matrix(x, false);
  });

  leg("B1-06 (findings) each refusal of the matrix names its finding in extra.withdrawal.finding (INPUTS_LIVE, RECORD, ROOT_INPUT_NOT_LIVE, INPUT_CONTRADICTED, OWN_OUTPUT, IN_TRANSACTION_POOL, MEMPOOL_UNCLEAR, UNSTABLE, NODE_ERROR); then, with every condition cleared, the same request's step 1 records the anchor (the positive control) [RED on 5b6d8e9: no finding; a SIGNED request is never withdrawable]", async (x) => {
    const { B } = await matrix(x, true);
    const s1 = await S.withdraw(x, B.id);
    S.assertPending(s1, "the positive control");
  });

  for (const variant of ["creator not located", "anchor off the chain"]) {
    leg(`B1-06 (absent without existence: ${variant}) a fee input created 10 DAA before the build (only E3 could establish it) is absent at withdrawal ${variant === "creator not located" ? "because its creator's block left the chain and the creator is never accepted again" : "after a conflicting spend, with A_b off the selected chain"}: Withdraw answers CANNOT_REJECT INPUT_EXISTENCE_UNPROVEN, writing nothing [RED on 5b6d8e9: the build records no inputObservation (no D6b marker or anchor A_b); a SIGNED request is never withdrawable]`, async (x) => {
      const c = S.createdFuel(x, `b106e-${variant.length}`);
      x.chain.advance(10n);
      const B = await S.finalizedB(x, S.rootOnlyBody("freeze", c.fuel), `B1-06 ${variant}`);
      const F = S.inputOf(x, B, "fee");
      S.buildAnchor(B); // the marker E2/E3 would read
      if (variant === "creator not located") {
        x.chain.freeze();
        x.chain.reorg({ depth: x.chain.state.chain.length - x.chain.state.chain.indexOf(c.K.hash), blocks: [{}, {}] });
        x.chain.thaw();
        assert.equal(x.node.entryAt(F.outpoint), null, "the creator is gone: the input is absent");
      } else {
        const C = x.chain.conflictingSpend([F.outpoint], { tag: "b106e-c" });
        x.chain.freeze();
        const ab = S.buildAnchor(B);
        x.chain.reorg({ depth: x.chain.state.chain.length - x.chain.state.chain.indexOf(ab), blocks: [{ txs: [c.F], accept: [c.F] }, { txs: [C.id] }, {}] });
        x.chain.thaw();
        assert.equal(x.chain.onChain(ab), false, "A_b left the chain");
        assert.equal(x.node.entryAt(F.outpoint), null, "the input is spent");
      }
      x.chain.advance(100n);
      await S.writesNothing(x, variant, () => S.withdraw(x, B.id), (r) => S.assertCannotReject(r, "INPUT_EXISTENCE_UNPROVEN", variant));
    });
  }

  leg("B1-06b (case 3b) X only in the orphan pool (its fee input missing: spent by C), re-relayed there: both steps proceed and end at REFUSED (an orphan X cannot be accepted while the input stays spent) [RED on 5b6d8e9: a SIGNED request is never withdrawable]", async (x) => {
    const B = await finalizedT2(x, "b106b");
    const F = S.inputOf(x, B, "fee");
    x.chain.conflictingSpend([F.outpoint], { tag: "b106b-c" });
    x.chain.registerRequest(B);
    x.chain.toMempool(lower(B.txId), { isOrphan: true });
    x.chain.advance(100n);
    const s1 = await S.withdraw(x, B.id);
    S.assertPending(s1, "B1-06b step 1");
    const A1 = await anchorOf(x, B.id);
    x.node.state.daa = A1.daa + DEPTH;
    await stepRefused(x, B.id, "B1-06b step 2");
  });

  /* ---------------------------------------- B1-07 two steps, renewals ---------------------------------------- */
  leg("B1-07 (the two steps and the boundary) step 1 writes only the anchor, whose DAA is A1's own header DAA (37 below the virtual in this mock, never the virtual DAA, never the sink); at A1 + 999 the step answers pending writing nothing; at A1 + 1,000 REFUSED; earliestDaa = A1 + 1,000 and latestDaa = A1 + 12,000 [RED on 5b6d8e9: a SIGNED request is never withdrawable]", async (x) => {
    const B = await finalizedT2(x, "b107");
    const F = S.inputOf(x, B, "fee");
    x.chain.conflictingSpend([F.outpoint], { tag: "b107-c" });
    x.chain.advance(100n);
    x.chain.sync();
    const v1 = S.v(x), sink = x.chain.sink().hash;
    const before = await x.snap();
    const s1 = await S.withdraw(x, B.id);
    const A1 = await anchorOf(x, B.id);
    S.assertPending(s1, "B1-07 step 1", { anchorDaa: A1 ? A1.daa : 0n });
    assert.equal(v1 - A1.daa, 37n, "A1's header DAA is 37 below the virtual in this mock");
    assert.notEqual(A1.hash, sink, "the anchor is not the sink");
    await S.onlyFieldsChanged(x, before, B.id, ["inputSpentObservation"], "step 1");
    x.node.state.daa = A1.daa + 999n;
    await S.writesNothing(x, "+999", () => S.withdraw(x, B.id), (r) => S.assertPending(r, "+999", { anchorDaa: A1.daa }));
    x.node.state.daa = A1.daa + 1000n;
    await stepRefused(x, B.id, "+1,000");
  });

  leg("B1-07b (renewals) on one request: the anchor removed by a reorganization renews; a spender of B's input included after the anchor without being accepted by any window chain block renews (inclusion, not acceptance); an accepted spender after the anchor renews; an incomplete acceptance window renews; an incomplete block scan renews; a step later than 12,000 DAA renews without any window or scan read; X itself included after the anchor without being accepted does NOT renew — that step answers REFUSED [RED on 5b6d8e9: a SIGNED request is never withdrawable]", async (x) => {
    const { B, F } = await atStep1(x, "b107b", { advance: 200n });
    /* (1) the anchor removed */
    let A = await anchorOf(x, B.id);
    x.chain.freeze();
    x.chain.reorg({ depth: x.chain.state.chain.length - x.chain.state.chain.indexOf(A.hash) + 1, blocks: [{}, {}, {}] });
    x.chain.thaw();
    assert.equal(x.chain.onChain(A.hash), false);
    x.node.state.daa = A.daa + DEPTH;
    A = await assertRenews(x, B.id, "anchor removed");
    /* (2) inclusion only: a block after the anchor carries a transaction naming the (already spent) fee input; a chain
     * block merges it without accepting it */
    const fake = x.chain.syntheticTx({ spend: [F.outpoint], tag: "b107b-inclusion" });
    const side = x.chain.sideBlock({ txs: [fake.id] });
    x.chain.mine({ merge: [side.hash], accept: [] });
    x.node.state.daa = A.daa + DEPTH;
    A = await assertRenews(x, B.id, "an unaccepted spender included after the anchor");
    /* (3) an accepted spender after the anchor (T2's output, spent by C2 above the anchor) */
    x.node.state.daa = A.daa + 50n;
    x.chain.sync();
    const C2 = x.chain.conflictingSpend([S.inputOf(x, B, "treasury").outpoint], { tag: "b107b-c2" });
    x.node.state.daa = A.daa + DEPTH;
    A = await assertRenews(x, B.id, "an accepted spender after the anchor");
    void C2;
    /* (4) an incomplete acceptance window */
    x.node.state.daa = A.daa + DEPTH;
    { const a = A; x.chain.override("getVirtualChainFromBlock", async (args, real) => (lower(args.startHash) === a.hash ? { removedChainBlockHashes: [], addedChainBlockHashes: [], acceptedTransactionIds: [] } : real())); }
    A = await assertRenews(x, B.id, "an incomplete acceptance window");
    x.chain.override("getVirtualChainFromBlock", null);
    /* (5) an incomplete block scan (the node makes no progress past lowHash) */
    x.node.state.daa = A.daa + DEPTH;
    x.chain.override("getBlocks", async (args, real) => { const r = await real(); return { blockHashes: r.blockHashes.slice(0, 1), blocks: r.blocks.slice(0, 1) }; });
    A = await assertRenews(x, B.id, "an incomplete block scan");
    x.chain.override("getBlocks", null);
    /* (6) later than 12,000 DAA: no window, no scan */
    x.node.state.daa = A.daa + MAX_AGE + 1n;
    A = await assertRenews(x, B.id, "later than 12,000 DAA", { profile: renewedAtStep4("late") });
    /* (7) X itself included after the anchor, never accepted: ignored — REFUSED */
    x.chain.registerRequest(B);
    const sx = x.chain.sideBlock({ txs: [lower(B.txId)] });
    x.chain.mine({ merge: [sx.hash], accept: [] });
    x.node.state.daa = A.daa + DEPTH;
    await stepRefused(x, B.id, "X included, not accepted");
  });

  leg("B1-07b (continuing set empty; NB38) B (T2 AUTHORIZE + unpause) spends the fee input (deep) and T2's output created by the previous owner operation on T2 (a sibling of P, E1s once 1,000 DAA deep); both are spent at once and A_b leaves the retained history; at step 1 only the fee input has existence evidence (the anchor names it alone); the fee input is then restored and at step 2 only T2's output is absent (now established by E1s): the continuing set is empty, so the step renews AT STEP 4 (no acceptance window from A1, no block scan) — never REFUSED although no spender lies above A1 [RED on 5b6d8e9: the build records no inputObservation (no D6b marker or anchor A_b); a SIGNED request is never withdrawable]", async (x) => {
    await S.hostedOp(x, S.vaultOpBody(ctx.T2, "ownerPause", "authorize", S.seededFuel(x, "b107bk-prev-fee")), "B1-07b (k) previous T2 pause");
    x.chain.advance(10n);
    const B = await S.finalizedB(x, S.vaultOpBody(ctx.T2, "ownerUnpause", "authorize", S.seededFuel(x, "b107bk-fee")), "B1-07b (k)");
    const F = S.inputOf(x, B, "fee"), T = S.inputOf(x, B, "treasury");
    x.chain.conflictingSpend([F.outpoint], { tag: "b107bk-c1" });
    x.chain.conflictingSpend([T.outpoint], { tag: "b107bk-c3" });
    x.chain.advance(100n);
    x.chain.prune(S.buildAnchor(B));
    const s1 = await S.withdraw(x, B.id);
    S.assertPending(s1, "step 1");
    const m = (await x.rootReq(B.id)).inputSpentObservation;
    assert.deepEqual(m.spent.map((e) => e.role), ["fee"], "the anchor names only the fee input (T2's output had no existence evidence yet)");
    const input = B.build.frozen.inputs[F.index];
    x.node.putEntry(F.address, { outpoint: F.outpoint, amount: BigInt(input.utxo.amount), covenantId: null, scriptPublicKey: { version: 0, script: input.utxo.scriptPublicKey.scriptHex }, daaStamp: String(S.v(x) - 50000n) });
    const A = await anchorOf(x, B.id);
    x.node.state.daa = A.daa + DEPTH;
    await assertRenews(x, B.id, "the continuing set empty", { profile: renewedAtStep4("continuing set", S.buildAnchor(B)) });
  });

  leg("B1-07b (contradictions and a damaged anchor) the acceptance window from A1 accepting X answers CANNOT_REJECT (ACCEPTED_IN_WINDOW) writing nothing; a malformed block scan answers CANNOT_REJECT (SCAN_UNCLEAR) writing nothing; an anchor damaged in its schema, txId, requestId or existence is treated as absent (the step records a fresh anchor) [RED on 5b6d8e9: a SIGNED request is never withdrawable]", async (x) => {
    const { B } = await atStep1(x, "b107bc");
    let A = await anchorOf(x, B.id);
    x.node.state.daa = A.daa + DEPTH;
    const X = lower(B.txId);
    x.chain.override("getVirtualChainFromBlock", async (args, real) => { const r = await real(); if (lower(args.startHash) === A.hash && r.acceptedTransactionIds.length) r.acceptedTransactionIds[0] = { ...r.acceptedTransactionIds[0], acceptedTransactionIds: [...r.acceptedTransactionIds[0].acceptedTransactionIds, X] }; return r; });
    await S.writesNothing(x, "the window accepts X", () => S.withdraw(x, B.id), (r) => S.assertCannotReject(r, "ACCEPTED_IN_WINDOW", "window accepts X"));
    x.chain.override("getVirtualChainFromBlock", null);
    x.chain.override("getBlocks", async (args, real) => { const r = await real(); return { blockHashes: ["ab".repeat(32), ...r.blockHashes.slice(1)], blocks: r.blocks }; });
    await S.writesNothing(x, "a malformed scan", () => S.withdraw(x, B.id), (r) => S.assertCannotReject(r, "SCAN_UNCLEAR", "malformed scan"));
    x.chain.override("getBlocks", null);
    for (const [label, damage] of [
      ["schema", (m) => { m.schema = "policyvault-input-spent-observation/0"; }],
      ["txId", (m) => { m.txId = "cd".repeat(32); }],
      ["requestId", (m) => { m.requestId = "another-request"; }],
      ["existence", (m) => { m.spent = m.spent.map((s) => ({ ...s, existence: { ...s.existence, path: "E9" } })); }]
    ]) {
      await x.editRootReq(B.id, (q) => damage(q.inputSpentObservation));
      x.chain.sync();
      const expect = x.chain.ancestor(20).hash;
      const r = await S.withdraw(x, B.id);
      S.assertPending(r, `damaged ${label}: treated as absent`);
      const m = (await x.rootReq(B.id)).inputSpentObservation;
      assert.equal(m.anchor.hash, expect, `damaged ${label}: a fresh anchor is recorded`);
      assert.equal(m.schema, "policyvault-input-spent-observation/1");
      x.chain.advance(10n);
    }
    void A;
  });

  leg("B1-07d (i) (the final scan batch truncated past W.sink without the anticone) C1 accepted in past(A1) and an unread fake spender of B's input in the sink's anticone: step 2 answers REFUSED [RED on 5b6d8e9: a SIGNED request is never withdrawable]", async (x) => {
    x.chain.setAnticone("omit");
    const { B, F } = await atStep1(x, "b107d1");
    const A = await anchorOf(x, B.id);
    const fake = x.chain.syntheticTx({ spend: [F.outpoint], tag: "b107d1-anticone" });
    x.node.state.daa = A.daa + DEPTH;
    x.chain.sync();
    x.chain.sideBlock({ txs: [fake.id] });
    await stepRefused(x, B.id, "(i) anticone not read");
  });

  leg("B1-07d (ii) C1 accepted outside past(A1) (above the anchor step 1 records): the scan from A1 finds it and step 2 renews [RED on 5b6d8e9: a SIGNED request is never withdrawable]", async (x) => {
    x.chain.setAnticone("omit");
    const B = await finalizedT2(x, "b107d2");
    const F = S.inputOf(x, B, "fee");
    const C1 = x.chain.conflictingSpend([F.outpoint], { tag: "b107d2-c1" }); // accepted at the top: above the anchor of step 1
    const s1 = await S.withdraw(x, B.id);
    S.assertPending(s1, "(ii) step 1");
    const A = await anchorOf(x, B.id);
    assert.ok(C1.block.daa > A.daa, "C1 lies above A1");
    x.node.state.daa = A.daa + DEPTH;
    await assertRenews(x, B.id, "(ii) C1 outside past(A1)");
  });

  leg("B1-07d (iii) (SK-02) C1 accepted only by the step-1 virtual's own mergeset (its block a tip no chain block merged yet), merged by a chain block above A1 before step 2: the scan finds it and step 2 renews [RED on 5b6d8e9: a SIGNED request is never withdrawable]", async (x) => {
    x.chain.setAnticone("omit");
    const B = await finalizedT2(x, "b107d3");
    const F = S.inputOf(x, B, "fee");
    const C1 = x.chain.syntheticTx({ spend: [F.outpoint], tag: "b107d3-c1" });
    const vb = x.chain.acceptByVirtual(C1.id);
    assert.equal(x.node.entryAt(F.outpoint), null, "the virtual's mergeset spent the fee input");
    const s1 = await S.withdraw(x, B.id);
    S.assertPending(s1, "(iii) step 1");
    const A = await anchorOf(x, B.id);
    x.node.state.daa = A.daa + 200n;
    x.chain.sync();
    x.chain.mine({ merge: [vb.hash], accept: [C1.id] });
    x.node.state.daa = A.daa + DEPTH;
    await assertRenews(x, B.id, "(iii) the virtual-only spender, merged later");
  });

  leg("B1-07e (late, removed, budget) a step 2 later than 12,000 DAA renews and the next step succeeds; an anchor removed by a reorganization renews and the next step succeeds; with one new block per getBlocks batch, 65 blocks between A1 and the sink exceed the 64-batch scan budget (renew) and the next step, within budget, succeeds [RED on 5b6d8e9: a SIGNED request is never withdrawable]", async (x) => {
    {
      const { B } = await atStep1(x, "b107e1");
      const A = await anchorOf(x, B.id);
      x.node.state.daa = A.daa + MAX_AGE + 1n;
      const A2 = await assertRenews(x, B.id, "late", { profile: renewedAtStep4("late") });
      x.node.state.daa = A2.daa + DEPTH;
      await stepRefused(x, B.id, "after the late renewal");
    }
    {
      const { B } = await atStep1(x, "b107e2", { advance: 200n });
      const A = await anchorOf(x, B.id);
      x.chain.freeze();
      x.chain.reorg({ depth: x.chain.state.chain.length - x.chain.state.chain.indexOf(A.hash) + 1, blocks: [{}, {}] });
      x.chain.thaw();
      x.node.state.daa = A.daa + DEPTH;
      const A2 = await assertRenews(x, B.id, "anchor removed");
      x.node.state.daa = A2.daa + DEPTH;
      await stepRefused(x, B.id, "after the removed-anchor renewal");
    }
  });

  for (const blocksAfter of [64, 65]) {
    leg(`B1-07e / B1-14c (the 64-batch scan budget, pinned) with one new block per getBlocks batch and exactly ${blocksAfter} blocks between A1 and the sink, step 2 ${blocksAfter === 64 ? "completes its scan within the budget and answers REFUSED" : "cannot complete its scan within 64 batches and renews; the next step (within budget) answers REFUSED"} [RED on 5b6d8e9: a SIGNED request is never withdrawable]`, async (x) => {
      const { B } = await atStep1(x, `b107e-${blocksAfter}`);
      const A = await anchorOf(x, B.id);
      x.chain.freeze();
      const have = x.chain.state.chain.length - 1 - x.chain.state.chain.indexOf(A.hash);
      const need = blocksAfter - have;
      assert.ok(need > 0, "more blocks are needed above the anchor");
      for (let i = 1; i <= need; i++) x.chain.mine({ daa: A.daa + 40n + BigInt(Math.ceil((1000 * i) / need)) });
      x.node.state.daa = x.chain.sink().daa + 1n;
      assert.equal(x.chain.state.chain.length - 1 - x.chain.state.chain.indexOf(A.hash), blocksAfter, `${blocksAfter} blocks above A1`);
      assert.ok(S.v(x) - A.daa >= DEPTH, "at least 1,000 DAA after A1");
      x.chain.setBatchLimit(2);
      if (blocksAfter === 64) {
        await stepRefused(x, B.id, "64 blocks: within the budget");
        assert.equal(x.chain.callCount("getBlocks") >= 64, true);
      } else {
        const A2 = await assertRenews(x, B.id, "65 blocks: past the budget");
        x.chain.thaw();
        x.chain.setBatchLimit(249);
        x.node.state.daa = A2.daa + DEPTH;
        await stepRefused(x, B.id, "the next step");
      }
    });
  }

  leg("B1-07f (W7a) (i) E3 evidence recorded final (finalAt) at step 1 — the creator's block was already 1,000 DAA deep — then A_b leaves the retained history: a late step renews carrying the recorded evidence and the next step 2 answers REFUSED; (ii) E3 evidence NOT final at step 1 and A_b unreadable at step 2: CANNOT_REJECT INPUT_EXISTENCE_UNPROVEN, nothing written (recorded evidence without finalAt is never reused) [RED on 5b6d8e9: a SIGNED request is never withdrawable]", async (x) => {
    /* (i) */
    {
      const c = S.createdFuel(x, "b107f1");
      x.chain.advance(10n);
      const B = await S.finalizedB(x, S.rootOnlyBody("freeze", c.fuel), "B1-07f (i)");
      const F = S.inputOf(x, B, "fee");
      x.chain.conflictingSpend([F.outpoint], { tag: "b107f1-c" });
      x.chain.advance(1100n);
      const s1 = await S.withdraw(x, B.id);
      S.assertPending(s1, "(i) step 1");
      const m = (await x.rootReq(B.id)).inputSpentObservation;
      const ex = m.spent.find((s) => sameOp(s.outpoint, F.outpoint)).existence;
      assert.equal(ex.path, "E3", "(i) the evidence is E3");
      assert.ok(/^[0-9]+$/.test(String(ex.finalAt)), "(i) recorded final (finalAt)");
      x.chain.prune(S.buildAnchor(B));
      const A = await anchorOf(x, B.id);
      x.node.state.daa = A.daa + MAX_AGE + 1n;
      const A2 = await assertRenews(x, B.id, "(i) late renewal with recorded evidence");
      x.node.state.daa = A2.daa + DEPTH;
      await stepRefused(x, B.id, "(i) step 2 on recorded evidence");
    }
    /* (ii) */
    {
      const c = S.createdFuel(x, "b107f2");
      x.chain.advance(10n);
      const B = await S.finalizedB(x, S.rootOnlyBody("freeze", c.fuel), "B1-07f (ii)");
      const F = S.inputOf(x, B, "fee");
      x.chain.conflictingSpend([F.outpoint], { tag: "b107f2-c" });
      x.chain.advance(100n);
      const s1 = await S.withdraw(x, B.id);
      S.assertPending(s1, "(ii) step 1");
      const ex = (await x.rootReq(B.id)).inputSpentObservation.spent.find((s) => sameOp(s.outpoint, F.outpoint)).existence;
      assert.equal(ex.finalAt, null, "(ii) the evidence was not final at step 1");
      x.chain.prune(S.buildAnchor(B));
      const A = await anchorOf(x, B.id);
      x.node.state.daa = A.daa + DEPTH;
      await S.writesNothing(x, "(ii) step 2", () => S.withdraw(x, B.id), (r) => S.assertCannotReject(r, "INPUT_EXISTENCE_UNPROVEN", "(ii) step 2"));
    }
  });

  leg("B1-07g (WD-9, the acceptance-only counterexample) C1 accepted above A1 at step 1; before step 2 a reorganization lets the window chain merge C1's block WITHOUT accepting C1, and a new spender D is accepted only by the virtual's own mergeset (outside past(W.sink); the anticone is not read): step 2 renews (C1 found by inclusion) — never REFUSED [RED on 5b6d8e9: a SIGNED request is never withdrawable]", async (x) => {
    x.chain.setAnticone("omit");
    const B = await finalizedT2(x, "b107g");
    const F = S.inputOf(x, B, "fee");
    const C1 = x.chain.conflictingSpend([F.outpoint], { tag: "b107g-c1" });
    const s1 = await S.withdraw(x, B.id);
    S.assertPending(s1, "step 1");
    const A = await anchorOf(x, B.id);
    assert.ok(C1.block.daa > A.daa, "C1 lies above A1");
    x.chain.freeze();
    x.chain.reorg({ depth: x.chain.state.chain.length - x.chain.state.chain.indexOf(C1.block.hash), blocks: [{ merge: [C1.block.hash], accept: [] }, {}] });
    x.chain.thaw();
    assert.ok(x.node.entryAt(F.outpoint), "C1 is no longer accepted: the fee input is unspent on the selected chain");
    const Dtx = x.chain.syntheticTx({ spend: [F.outpoint], tag: "b107g-d" });
    x.node.state.daa = A.daa + DEPTH;
    x.chain.sync();
    x.chain.acceptByVirtual(Dtx.id);
    await assertRenews(x, B.id, "C1 found by inclusion");
  });

  leg("B1-07h (existence timing at step 1) B's fee input U is absent at the step-1 UTXO read because its creator F is no longer accepted; right after that read F is accepted again in a new chain block K' and the chain advances by 21 chain blocks, so E3 holds when step 1 evaluates it (the anchor A1 was read FIRST: K' lies above A1); at step 2 (A1 + 1,500) U is absent only because a spender D is accepted by the virtual's own mergeset (the anticone is not read), and the scan finds no spender: step 2 renews because K' is not at or below A1 — never REFUSED [RED on 5b6d8e9: a SIGNED request is never withdrawable]", async (x) => {
    x.chain.setAnticone("omit");
    const c = S.createdFuel(x, "b107h");
    x.chain.advance(10n);
    const B = await S.finalizedB(x, S.rootOnlyBody("freeze", c.fuel), "B1-07h");
    const F = S.inputOf(x, B, "fee");
    x.chain.freeze();
    x.chain.reorg({ depth: x.chain.state.chain.length - x.chain.state.chain.indexOf(c.K.hash), blocks: [{}, {}] });
    x.chain.thaw();
    assert.equal(x.node.entryAt(F.outpoint), null, "U is absent: F is not accepted");
    x.chain.advance(10n); // step 1's anchor lies above A_b
    let fired = false;
    x.chain.after("getUtxosByAddresses", (call) => call.args.addresses.includes(F.address), 1, () => {
      fired = true;
      x.chain.freeze();
      x.chain.mine({ txs: [c.F], accept: [c.F] });
      for (let i = 0; i < 21; i++) x.chain.mine({});
      x.chain.thaw();
    });
    const s1 = await S.withdraw(x, B.id);
    assert.ok(fired, "F was accepted right after the step-1 UTXO read");
    S.assertPending(s1, "step 1 (E3 from K')");
    const A = await anchorOf(x, B.id);
    const Kp = x.chain.blockOfTx(c.F);
    assert.ok(Kp.daa > A.daa, "K' lies above A1 (the anchor was read before the inputs)");
    const Dtx = x.chain.syntheticTx({ spend: [F.outpoint], tag: "b107h-d" });
    x.node.state.daa = A.daa + 1500n;
    x.chain.sync();
    x.chain.acceptByVirtual(Dtx.id);
    assert.notEqual(A.hash, S.buildAnchor(B), "A1 is not A_b");
    await assertRenews(x, B.id, "K' above A1", { profile: renewedAtStep4("B1-07h", S.buildAnchor(B)) });
  });

  /* ---------------------------------------- existence at the anchor ---------------------------------------- */
  const removeAb = (x, B, blocks) => {
    const ab = S.buildAnchor(B);
    x.chain.freeze();
    x.chain.reorg({ depth: x.chain.state.chain.length - x.chain.state.chain.indexOf(ab), blocks });
    x.chain.thaw();
    assert.equal(x.chain.onChain(ab), false, "A_b left the chain");
  };
  leg("B1-02f (i) (A_b off the selected chain at withdrawal; E2 only) B's fee input created 60 DAA before the build (below A_b), spent; a reorganization removes A_b (keeping the creator's block and re-accepting the spend): Withdraw answers CANNOT_REJECT INPUT_EXISTENCE_UNPROVEN, nothing written [RED on 5b6d8e9: the build records no inputObservation (no D6b marker or anchor A_b); a SIGNED request is never withdrawable]", async (x) => {
    const c = S.createdFuel(x, "b102f1");
    x.chain.advance(60n);
    const B = await S.finalizedB(x, S.rootOnlyBody("freeze", c.fuel), "B1-02f (i)");
    const F = S.inputOf(x, B, "fee");
    const C = x.chain.conflictingSpend([F.outpoint], { tag: "b102f1-c" });
    removeAb(x, B, [{ txs: [C.id] }, {}]);
    x.chain.advance(100n);
    await S.writesNothing(x, "(i)", () => S.withdraw(x, B.id), (r) => S.assertCannotReject(r, "INPUT_EXISTENCE_UNPROVEN", "(i) E2 only"));
  });

  leg("B1-02f (ii) (A_b off the selected chain at withdrawal; E1 also true) B's deep fee input spent; A_b removed by a reorganization: eligible — step 1 records the anchor [RED on 5b6d8e9: the build records no inputObservation (no D6b marker or anchor A_b); a SIGNED request is never withdrawable]", async (x) => {
    const B = await S.finalizedB(x, S.rootOnlyBody("freeze", S.seededFuel(x, "b102f2-fee")), "B1-02f (ii)");
    const F = S.inputOf(x, B, "fee");
    const C = x.chain.conflictingSpend([F.outpoint], { tag: "b102f2-c" });
    removeAb(x, B, [{ txs: [C.id] }, {}]);
    x.chain.advance(100n);
    const s1 = await S.withdraw(x, B.id);
    S.assertPending(s1, "(ii) E1: eligible");
  });

  leg("B1-02f (iii) (A_b off the selected chain at withdrawal; E3 only) B's fee input created 10 DAA before the build (above A_b), spent; a reorganization removes A_b and re-accepts the creator F and the spend on the new chain: getVirtualChainFromBlock from A_b answers a non-empty removed list (F found only in the new chain's added part) and Withdraw answers CANNOT_REJECT INPUT_EXISTENCE_UNPROVEN, nothing written [RED on 5b6d8e9: the build records no inputObservation (no D6b marker or anchor A_b); a SIGNED request is never withdrawable]", async (x) => {
    const c = S.createdFuel(x, "b102f3");
    x.chain.advance(10n);
    const B = await S.finalizedB(x, S.rootOnlyBody("freeze", c.fuel), "B1-02f (iii)");
    const F = S.inputOf(x, B, "fee");
    const C = x.chain.conflictingSpend([F.outpoint], { tag: "b102f3-c" });
    removeAb(x, B, [{ txs: [c.F], accept: [c.F] }, { txs: [C.id] }, {}]);
    x.chain.advance(100n);
    assert.ok(x.chain.blockOfTx(c.F) && x.chain.onChain(x.chain.blockOfTx(c.F).hash), "F is accepted on the new chain");
    await S.writesNothing(x, "(iii)", () => S.withdraw(x, B.id), (r) => S.assertCannotReject(r, "INPUT_EXISTENCE_UNPROVEN", "(iii) E3 with a removed list"));
  });

  leg("B1-02j (WD-3; OS-03) a reorganization leaves A_b on the chain with only one block above it, so the step-1 walk returns an anchor A1 below A_b (DAA(A1) < DAA(A_b)); E2 holds at both steps; step 2 at DAA(A1) + 1,500 renews AT STEP 4 (no acceptance window from A1, no block scan: A_b is not at or below A1); the later step 2 answers REFUSED [RED on 5b6d8e9: the build records no inputObservation (no D6b marker or anchor A_b); a SIGNED request is never withdrawable]", async (x) => {
    const c = S.createdFuel(x, "b102j");
    x.chain.advance(60n);
    const B = await S.finalizedB(x, S.rootOnlyBody("freeze", c.fuel), "B1-02j");
    const F = S.inputOf(x, B, "fee");
    const ab = S.buildAnchor(B);
    const C = x.chain.conflictingSpend([F.outpoint], { tag: "b102j-c" });
    x.chain.freeze();
    const keep = x.chain.state.chain.indexOf(ab) + 1; // A_b and one block above it stay
    x.chain.reorg({ depth: x.chain.state.chain.length - 1 - keep, blocks: [{ txs: [C.id] }] });
    const s1 = await S.withdraw(x, B.id);
    x.chain.thaw();
    S.assertPending(s1, "step 1");
    const A = await anchorOf(x, B.id);
    assert.ok(A.daa < x.chain.block(ab).daa, "DAA(A1) < DAA(A_b)");
    assert.equal(x.chain.onChain(ab), true, "A_b stays on the chain");
    x.node.state.daa = A.daa + 1500n;
    const A2 = await assertRenews(x, B.id, "A_b above A1", { profile: renewedAtStep4("B1-02j", ab) });
    x.node.state.daa = A2.daa + DEPTH;
    await stepRefused(x, B.id, "the later step 2");
  });

  leg("B1-02e (ii) (WD-1; OS-03) owner 2's autoFuel fee input is the previous action's change accepted in K' 10 DAA before the build; it is spent and withdrawal step 1 runs at once, so A1 lies below K'; step 2 at DAA(A1) + 1,500 — where K' is more than 1,000 DAA deep — renews AT STEP 4 (no acceptance window from A1, no block scan: K' is not at or below A1, whichever existence path, E3 or E1s, establishes the input); the next step 2 answers REFUSED [RED on 5b6d8e9: a SIGNED request is never withdrawable]", async (x) => {
    const p = await S.previousAction(x, "b102e2");
    x.chain.advance(10n);
    const B = await S.finalizedB(x, S.autoFuelBody(ctx.T1, "ownerUnpause"), "B1-02e (ii)", { feeWallet: ctx.w.o2, cookie: x.cookie.o2 });
    const F = S.inputOf(x, B, "fee");
    assert.ok(sameOp(F.outpoint, p.change.outpoint));
    x.chain.conflictingSpend([F.outpoint], { tag: "b102e2-c" });
    const s1 = await S.withdraw(x, B.id);
    S.assertPending(s1, "step 1");
    const A = await anchorOf(x, B.id);
    assert.ok(p.K0.daa > A.daa, "K' lies above A1");
    x.node.state.daa = A.daa + 1500n;
    assert.ok(S.v(x) - p.K0.daa >= DEPTH, "K' is more than 1,000 DAA deep at step 2");
    const A2 = await assertRenews(x, B.id, "K' above A1", { profile: renewedAtStep4("B1-02e (ii)", S.buildAnchor(B)) });
    x.node.state.daa = A2.daa + DEPTH;
    await stepRefused(x, B.id, "the next step 2");
  });

  /* ---------------------------------------- A1-2 K1' ---------------------------------------- */
  const hasFinalAt = (m) => JSON.stringify(m ?? null).match(/"finalAt":"?([0-9]+)"?/) !== null;
  leg("A1-2 (K1') (a) B's fee input created 10 DAA before the build (E3 only); the owners sign at once (no evidence recorded: the creator not yet 1,000 DAA deep); the finalize save more than 1,000 DAA (about 100 s) after the build records the existence evidence final (finalAt) in inputObservation; the input is then spent and A_b leaves the retained history: Submit 409 CONFLICTING_SPEND, the two-step withdrawal ends REFUSED and a root FREEZE reaches CHAIN_VERIFIED [RED on 5b6d8e9: nothing is recorded at the saves]", async (x) => {
    const c = S.createdFuel(x, "a12a");
    x.chain.advance(10n);
    const b = await S.build(x, S.rootOnlyBody("freeze", c.fuel));
    assert.equal(b.status, 201, S.said2(b));
    const id = b.body.request.id;
    await S.sign(x, id, [1]);
    assert.equal(hasFinalAt((await x.rootReq(id)).inputObservation), false, "the early slot-signature save records nothing (not yet final)");
    x.chain.advance(1100n);
    const f = await S.finalize(x, id);
    assert.equal(f.status, 200, S.said2(f));
    const B = await x.rootReq(id);
    assert.equal(hasFinalAt(B.inputObservation), true, `the finalize save recorded the evidence final (${JSON.stringify(B.inputObservation)})`);
    const F = S.inputOf(x, B, "fee");
    x.chain.conflictingSpend([F.outpoint], { tag: "a12a-c" });
    x.chain.advance(100n);
    x.chain.prune(S.buildAnchor(B));
    await S.demonstrate(x, B, { role: "fee", outpoint: F.outpoint, existence: ["E3", "E2"], tag: "A1-2 (a)" });
  });

  leg("A1-2 (K1') (b) a failed evaluation at the finalize save (the node's getVirtualChainFromBlock fails) leaves the save unchanged: finalize succeeds (SIGNED) with inputObservation byte-identical; after the spend and A_b's pruning, Withdraw answers CANNOT_REJECT INPUT_EXISTENCE_UNPROVEN writing nothing [RED on 5b6d8e9: the build records no inputObservation (no D6b marker or anchor A_b); a SIGNED request is never withdrawable]", async (x) => {
    const c = S.createdFuel(x, "a12b");
    x.chain.advance(10n);
    const b = await S.build(x, S.rootOnlyBody("freeze", c.fuel));
    const id = b.body.request.id;
    await S.sign(x, id, [1]);
    const m0 = KK.strictJson((await x.rootReq(id)).inputObservation);
    x.chain.advance(1100n);
    x.chain.fault("getVirtualChainFromBlock", { always: true });
    x.chain.fault("getBlock", { always: true });
    const f = await S.finalize(x, id);
    x.chain.clearFaults();
    assert.equal(f.status, 200, `finalize is never refused by K1' (${S.said2(f)})`);
    const B = await x.rootReq(id);
    assert.equal(B.state, "SIGNED");
    assert.equal(KK.strictJson(B.inputObservation), m0, "inputObservation is unchanged");
    const F = S.inputOf(x, B, "fee");
    x.chain.conflictingSpend([F.outpoint], { tag: "a12b-c" });
    x.chain.advance(100n);
    x.chain.prune(S.buildAnchor(B));
    await S.writesNothing(x, "Withdraw", () => S.withdraw(x, id), (r) => S.assertCannotReject(r, "INPUT_EXISTENCE_UNPROVEN", "K1' (b)"));
  });

  leg("A1-2 (K1') (c) (the depth check) every save of B (slot request, slot signature, finalize) happens less than 1,000 DAA after the creator's block: nothing is recorded final; after the spend and A_b's pruning Withdraw answers CANNOT_REJECT INPUT_EXISTENCE_UNPROVEN writing nothing [RED on 5b6d8e9: the build records no inputObservation (no D6b marker or anchor A_b); a SIGNED request is never withdrawable]", async (x) => {
    const c = S.createdFuel(x, "a12c");
    x.chain.advance(10n);
    const B = await S.finalizedB(x, S.rootOnlyBody("freeze", c.fuel), "K1' (c)");
    assert.equal(hasFinalAt(B.inputObservation), false, "nothing recorded final at the early saves");
    const F = S.inputOf(x, B, "fee");
    x.chain.conflictingSpend([F.outpoint], { tag: "a12c-c" });
    x.chain.advance(1100n);
    x.chain.prune(S.buildAnchor(B));
    await S.writesNothing(x, "Withdraw", () => S.withdraw(x, B.id), (r) => S.assertCannotReject(r, "INPUT_EXISTENCE_UNPROVEN", "K1' (c)"));
  });

  leg("A1-2 (K1') (d) (the on-chain check) B's fee input created 60 DAA before the build (E2: below A_b); a reorganization then removes A_b (keeping the creator's block); the finalize save more than 1,000 DAA later records nothing final (A_b is not on the selected chain); after the spend Withdraw answers CANNOT_REJECT INPUT_EXISTENCE_UNPROVEN writing nothing [RED on 5b6d8e9: the build records no inputObservation (no D6b marker or anchor A_b); a SIGNED request is never withdrawable]", async (x) => {
    const c = S.createdFuel(x, "a12d");
    x.chain.advance(60n);
    const b = await S.build(x, S.rootOnlyBody("freeze", c.fuel));
    const id = b.body.request.id;
    await S.sign(x, id, [1]);
    const ab = S.buildAnchor(await x.rootReq(id));
    x.chain.freeze();
    x.chain.reorg({ depth: x.chain.state.chain.length - x.chain.state.chain.indexOf(ab), blocks: [{}, {}] });
    x.chain.thaw();
    assert.equal(x.chain.onChain(ab), false);
    x.chain.advance(1100n);
    const f = await S.finalize(x, id);
    assert.equal(f.status, 200, S.said2(f));
    const B = await x.rootReq(id);
    assert.equal(hasFinalAt(B.inputObservation), false, "nothing is recorded from an anchor off the chain");
    const F = S.inputOf(x, B, "fee");
    x.chain.conflictingSpend([F.outpoint], { tag: "a12d-c" });
    x.chain.advance(100n);
    await S.writesNothing(x, "Withdraw", () => S.withdraw(x, id), (r) => S.assertCannotReject(r, "INPUT_EXISTENCE_UNPROVEN", "K1' (d)"));
  });

  /* ---------------------------------------- A1-4 dispatch ---------------------------------------- */
  leg("A1-4 (dispatch) the existing withdrawals are byte-unchanged: an unsigned AUTHORIZED request is withdrawn (REFUSED, its reservation released) with zero node calls and no B1 field written; a slot-signed, never-finalized v0.7-kas delegate-rule change whose period start aged out is withdrawn on its existing path (REFUSED, reservation released) with no B1 field written [PIN: holds on 5b6d8e9]", async (x) => {
    const b = await S.build(x, S.vaultOpBody(ctx.T2, "ownerPause", "authorize", S.seededFuel(x, "a14-fee")));
    assert.equal(b.status, 201, S.said2(b));
    const before = await x.snap();
    x.chain.resetCalls();
    const w = await S.withdraw(x, b.body.request.id);
    assert.equal(w.status, 200, S.said2(w));
    assert.equal(w.body.request.state, "REFUSED");
    assert.equal(x.chain.calls().filter((c) => c.method !== "disconnect").length, 0, "zero node calls");
    await S.onlyFieldsChanged(x, before, b.body.request.id, ["state", "error", "pendingRequestId"], "the unsigned withdrawal");
    const q = await x.rootReq(b.body.request.id);
    assert.equal(q.inputSpentObservation, undefined);
    assert.equal(q.inputSpentWithdrawal, undefined);
    /* the aged-out delegate-rule withdrawal (built through the B1 node, refused at finalize, withdrawn) */
    let id = null;
    await withAnchor(D, async () => {
      const r = await S.build(x, S.vaultOpBody(ctx.T1, "ownerSetAgentRoot", "authorize", S.seededFuel(x, "a14-a-fee"), { agents: S.newRules() }));
      assert.equal(r.status, 201, said(r));
      id = r.body.request.id;
      await S.sign(x, id, [1, 2]);
    });
    x.node.state.daa = B1.SC.STALE;
    await withAnchor(B1.SC.STALE, async () => {
      const f = await S.finalize(x, id);
      assert.equal(f.code, "PERIOD_START_STALE", said(f));
      const before2 = await x.snap();
      x.chain.resetCalls();
      const wd = await S.withdraw(x, id);
      assert.equal(wd.status, 200, `the aged-out withdrawal (${S.said2(wd)})`);
      assert.equal(wd.body.request.state, "REFUSED");
      assert.equal(x.chain.calls().filter((c) => c.method !== "disconnect").length, 0, "no B1 node read (the position comes from the existing DAA read)");
      await S.onlyFieldsChanged(x, before2, id, ["state", "error", "pendingRequestId"], "the aged-out withdrawal");
    });
  });
}
