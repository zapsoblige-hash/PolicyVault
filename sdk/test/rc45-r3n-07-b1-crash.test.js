"use strict";
/*
 * RC45 R3N-B1 — CRASH POINTS, RETRIES AND KEYS, RACES of the submit read and the two-step withdrawal (contract
 * rc45-l201-contract-03: addendum v2b revision 3 §5 R1-R4, §6 crash and race tables, §7 B1-08 (a)-(f), B1-09b,
 * B1-11a-d / f; writer amendment A1, which prevails). Internal RED-first regression material for the RC45 candidate;
 * not an external engagement of any kind.
 *
 * REQUIRED BEHAVIOUR: a fault at the anchor save leaves the store unchanged and the next call records the anchor; a
 * fault at the REFUSED save leaves B SIGNED with its anchor and the reservation, and the next call at depth withdraws;
 * a crash between the REFUSED save and the pointer save leaves root builds refused ROOT_PENDING_REQUEST (a plain Verify
 * does not clear the pointer) and a repeated Withdraw (W8: a REFUSED request with a bound inputSpentWithdrawal and a
 * finalTransaction) clears it with ZERO node calls, after which a root FREEZE builds; a repeat after completion makes
 * zero node calls; a write interleaved between the load and the save (a submissionAttempt) answers CANNOT_REJECT
 * STORE_CHANGED writing nothing; a REFUSED request with a finalTransaction and an absent or damaged
 * inputSpentWithdrawal answers CANNOT_REJECT and leaves the pointer untouched. A same-key retry of a withdrawal step
 * replays or resolves without a second anchor write; a new key is used only after the state was read. Races: X
 * accepted after r1 (outputs moved on) -> UNSTABLE; X accepted between r4 and r5 -> OWN_OUTPUT; the anchored input
 * restored and spent again after A1 -> renew; A1 reorganized out -> renew; a Submit concurrent with a Withdraw in one
 * process waits for the root lock and sees the Withdraw's write.
 *
 * Layers and labels as in sdk/test/rc45-r3n-07-b1-submit.test.js. TEST keys only; nothing dials a node.
 */
const KK = require("../testutil/rc45-r2-kas-kit");
KK.installNode(); // before anything loads server/src/api.js or the v7 request modules
const assert = require("node:assert/strict");
const { test, before, after } = require("node:test");
const B1 = require("../testutil/rc45-r3n-b1-kit");
const { lower, sameOp, DEPTH } = B1;
const TOOLCHAIN = require("../testutil/org-root-durable-fixture").toolchainAvailable();

const S = B1.b1Scenario("b1crash");
const { ctx } = S;
const Cat = () => KK.lazy.store.Categories;

before(async () => {
  assert.ok(TOOLCHAIN, "real compiler, encoder and VM are required (a missing VM toolchain is a FAIL, never a SKIP)");
  await S.setup();
});
after(async () => { await S.teardown(); });

const finalizedT2 = (x, tag) => S.finalizedB(x, S.vaultOpBody(ctx.T2, "ownerPause", "authorize", S.seededFuel(x, `${tag}-fee`)), tag);
const anchorOf = async (x, id) => { const m = (await x.rootReq(id)).inputSpentObservation; return m ? { hash: m.anchor.hash, daa: BigInt(m.anchor.daaScore), at: m.at } : null; };
const isReqWrite = (id, pred) => (op) => op.kind === "write" && op.category === Cat().ORG_ROOT_REQUEST && op.key === id && pred(op.value);
const nodeCalls = (x) => x.chain.calls().filter((c) => c.method !== "disconnect").length;
/* B whose deep fee input was spent by C accepted 21+ chain blocks before step 1 */
async function spentB(x, tag) {
  const B = await finalizedT2(x, tag);
  const F = S.inputOf(x, B, "fee");
  const C = x.chain.conflictingSpend([F.outpoint], { tag: `${tag}-c` });
  x.chain.advance(100n);
  return { B, F, C };
}

for (const [backend, skip] of [["JSON", undefined], ["PostgreSQL", S.S.PG_SKIP]]) {
  const leg = (name, fn) => test(`RC45 R3N-B1 ${backend}: ${name}`, { skip }, async () => { const x = await S.fresh(backend); try { await fn(x); } finally { await S.release(x); } });

  leg("B1-08 (a) a fault at the anchor save: the withdrawal step fails, the store is unchanged (no anchor, B SIGNED, the reservation kept); the next call records the anchor [RED on 5b6d8e9: a SIGNED request is never withdrawable]", async (x) => {
    const { B } = await spentB(x, "b108a");
    const scope0 = await x.scope();
    const f = S.storeFaults(x);
    f.crashAt(isReqWrite(B.id, (v) => v && v.inputSpentObservation));
    const r = await S.withdraw(x, B.id);
    const failures = f.failures();
    f.restore();
    assert.notEqual(r.code, "WITHDRAWAL_DEPTH_PENDING", `the step did not complete (${S.said2(r)})`);
    assert.equal(failures > 0, true, "the anchor save was attempted and failed");
    assert.equal(await x.scope(), scope0, "the store is unchanged");
    const r2 = await S.withdraw(x, B.id);
    S.assertPending(r2, "the next call records the anchor");
    assert.ok(await anchorOf(x, B.id));
  });

  leg("B1-08 (b) a fault at the REFUSED save: B stays SIGNED with its anchor and the reservation; the next call at depth withdraws (REFUSED, reservation released) [RED on 5b6d8e9: a SIGNED request is never withdrawable]", async (x) => {
    const { B } = await spentB(x, "b108b");
    S.assertPending(await S.withdraw(x, B.id), "step 1");
    const A = await anchorOf(x, B.id);
    x.node.state.daa = A.daa + DEPTH;
    const f = S.storeFaults(x);
    f.crashAt(isReqWrite(B.id, (v) => v && v.state === "REFUSED"));
    await S.withdraw(x, B.id);
    const failures = f.failures();
    f.restore();
    assert.ok(failures > 0, "the REFUSED save was attempted and failed");
    const q = await x.rootReq(B.id);
    assert.equal(q.state, "SIGNED", "B stays SIGNED");
    assert.ok(q.inputSpentObservation, "with its anchor");
    assert.equal((await S.rootRec(x)).pendingRequestId, B.id, "the reservation is kept");
    const r = await S.withdraw(x, B.id);
    assert.equal(r.status, 200, S.said2(r));
    await S.assertWithdrawn(x, B.id, "the next call");
  });

  leg("B1-08 (c)/(d) a crash between the REFUSED save and the pointer save: B is REFUSED (bound inputSpentWithdrawal) but the pointer still names it — a root build answers ROOT_PENDING_REQUEST and a plain Verify does not clear it; a repeated Withdraw (W8) clears the pointer with ZERO node calls; a further repeat also makes zero node calls; a root FREEZE then builds and reaches CHAIN_VERIFIED [RED on 5b6d8e9: a SIGNED request is never withdrawable]", async (x) => {
    const { B } = await spentB(x, "b108c");
    S.assertPending(await S.withdraw(x, B.id), "step 1");
    const A = await anchorOf(x, B.id);
    x.node.state.daa = A.daa + DEPTH;
    const f = S.storeFaults(x);
    f.crashAfter(isReqWrite(B.id, (v) => v && v.state === "REFUSED"));
    await S.withdraw(x, B.id);
    const interrupted = f.interrupted();
    f.restore();
    assert.ok(interrupted, "the pointer save failed after the REFUSED save");
    const q = await x.rootReq(B.id);
    assert.equal(q.state, "REFUSED");
    assert.ok(q.inputSpentWithdrawal, "B carries its inputSpentWithdrawal");
    assert.equal((await S.rootRec(x)).pendingRequestId, B.id, "the pointer still names B");
    await S.writesNothing(x, "a root build", () => S.build(x, S.rootOnlyBody("freeze", S.seededFuel(x, "b108c-held"))), (r) => assert.equal(r.code, "ROOT_PENDING_REQUEST", S.said2(r)));
    await S.verify(x);
    assert.equal((await S.rootRec(x)).pendingRequestId, B.id, "a plain Verify does not clear it");
    x.chain.resetCalls();
    const r = await S.withdraw(x, B.id);
    assert.equal(r.status, 200, `W8 finishes the withdrawal (${S.said2(r)})`);
    assert.equal(nodeCalls(x), 0, "W8 makes zero node calls");
    assert.equal((await S.rootRec(x)).pendingRequestId, null, "the pointer is cleared");
    x.chain.resetCalls();
    const again = await S.withdraw(x, B.id);
    assert.equal(again.status, 200, `a repeat after completion (${S.said2(again)})`);
    assert.equal(nodeCalls(x), 0, "(d) a repeat makes zero node calls");
    await S.ops.rootFreeze(x, "b108c-fz");
  });

  leg("B1-08 (e) a write interleaved between the withdrawal's load and its save (another writer records a submissionAttempt while the step reads the node): CANNOT_REJECT STORE_CHANGED and the withdrawal writes nothing [RED on 5b6d8e9: a SIGNED request is never withdrawable]", async (x) => {
    const { B } = await spentB(x, "b108e");
    let scopeAfterHook = null;
    x.chain.after("getMempoolEntry", null, 1, async () => {
      await x.editRootReq(B.id, (q) => { q.submissionAttempt = { id: "rc45-b1-other-writer", phase: "PREPARING", requestFingerprint: "00", at: new Date().toISOString() }; });
      scopeAfterHook = await x.scope();
    });
    const r = await S.withdraw(x, B.id);
    assert.ok(scopeAfterHook, "the other writer wrote during the step");
    S.assertCannotReject(r, "STORE_CHANGED", "interleaved write");
    assert.equal(await x.scope(), scopeAfterHook, "the withdrawal wrote nothing after the interleaved write");
    assert.equal((await x.rootReq(B.id)).inputSpentObservation, undefined, "no anchor");
  });

  leg("B1-08 (f) (SK-06) a REFUSED request that carries a finalTransaction but no inputSpentWithdrawal, or a damaged one (wrong schema), is not finished by W8: Withdraw answers CANNOT_REJECT and the root's pointer naming it is untouched [PIN: holds on 5b6d8e9]", async (x) => {
    const B = await finalizedT2(x, "b108f");
    await x.editRootReq(B.id, (q) => { q.state = "REFUSED"; });
    const r1 = await S.withdraw(x, B.id);
    assert.equal(r1.code, "CANNOT_REJECT", `no inputSpentWithdrawal (${S.said2(r1)})`);
    assert.equal((await S.rootRec(x)).pendingRequestId, B.id, "the pointer is untouched");
    await x.editRootReq(B.id, (q) => { q.inputSpentWithdrawal = { schema: "policyvault-input-spent-withdrawal/0", requestId: B.id, txId: lower(B.txId) }; });
    const r2 = await S.withdraw(x, B.id);
    assert.equal(r2.code, "CANNOT_REJECT", `a damaged inputSpentWithdrawal (${S.said2(r2)})`);
    assert.equal((await S.rootRec(x)).pendingRequestId, B.id, "the pointer is untouched");
  });

  leg("B1-09b withdrawal retry and key: step 1 with key w1 -> 409 pending (anchor written); a same-key retry replays it with zero node calls and no second anchor write; a step whose anchor save crashes under key w2 is not re-executed by a same-key retry (an idempotency refusal, zero node calls, no anchor); after the state is read, a new key w3 records the anchor exactly once [RED on 5b6d8e9: a SIGNED request is never withdrawable]", async (x) => {
    const key = (n) => `rc45-r3n-b1-b109b-${x.pgDatabase ?? "json"}-${n}`;
    {
      const { B } = await spentB(x, "b109b1");
      const r1 = await S.withdraw(x, B.id, { key: key(1) });
      S.assertPending(r1, "w1");
      const m1 = KK.strictJson((await x.rootReq(B.id)).inputSpentObservation);
      x.chain.resetCalls();
      const r1b = await S.withdraw(x, B.id, { key: key(1) });
      assert.equal(r1b.code, "WITHDRAWAL_DEPTH_PENDING", `the same key replays (${S.said2(r1b)})`);
      assert.equal(r1b.extra && r1b.extra.idempotency && r1b.extra.idempotency.replayed, true, "a replay");
      assert.equal(nodeCalls(x), 0, "the replay reads nothing from the node");
      assert.equal(KK.strictJson((await x.rootReq(B.id)).inputSpentObservation), m1, "no second anchor write");
      /* release B for the second request (withdrawn at depth) */
      x.node.state.daa = (await anchorOf(x, B.id)).daa + DEPTH;
      assert.equal((await S.withdraw(x, B.id, { key: key(9) })).status, 200);
    }
    {
      const { B } = await spentB(x, "b109b2");
      const f = S.storeFaults(x);
      f.crashAt(isReqWrite(B.id, (v) => v && v.inputSpentObservation));
      const r2 = await S.withdraw(x, B.id, { key: key(2) });
      f.restore();
      assert.notEqual(r2.code, "WITHDRAWAL_DEPTH_PENDING", `the crashed step did not answer pending (${S.said2(r2)})`);
      x.chain.resetCalls();
      const r2b = await S.withdraw(x, B.id, { key: key(2) });
      assert.ok(/^IDEMPOTENCY_/.test(String(r2b.code)) || (r2b.code === r2.code && r2b.extra && r2b.extra.idempotency && r2b.extra.idempotency.replayed === true), `the same key replays or resolves, never re-executes (${S.said2(r2b)})`);
      assert.equal(nodeCalls(x), 0, "zero node calls");
      const q = await x.rootReq(B.id);
      assert.equal(q.state, "SIGNED");
      assert.equal(q.inputSpentObservation, undefined, "no anchor was written");
      const r3 = await S.withdraw(x, B.id, { key: key(3) });
      S.assertPending(r3, "a new key after the state was read");
      assert.ok((await x.rootReq(B.id)).inputSpentObservation, "the anchor is written once");
    }
  });

  leg("B1-11a X accepted right after r1 (all of B's inputs were unspent) with its outputs spent onward before r5: the absent inputs now read spent by X itself, and r4 sees the root output gone — CANNOT_REJECT UNSTABLE, nothing written [RED on 5b6d8e9: no finding]", async (x) => {
    const B = await finalizedT2(x, "b111a");
    x.chain.registerRequest(B);
    const P = S.inputOf(x, B, "root");
    let fired = false;
    x.chain.after("getUtxosByAddresses", (c) => c.args.addresses.includes(P.address), 1, () => {
      fired = true;
      x.chain.accept(lower(B.txId));
      x.chain.conflictingSpend(B.build.frozen.outputs.map((_, i) => ({ transactionId: lower(B.txId), index: i })), { tag: "b111a-onward" });
    });
    await S.writesNothing(x, "the step", () => S.withdraw(x, B.id), (r) => { assert.ok(fired, "X accepted after r1"); S.assertCannotReject(r, "UNSTABLE", "B1-11a"); });
  });

  leg("B1-11b X accepted between r4 and r5 (a reorganization reverses the conflicting spend C and accepts X while the step reads): r5 sees X's own output — CANNOT_REJECT OWN_OUTPUT, nothing written [RED on 5b6d8e9: no finding]", async (x) => {
    const { B, C } = await spentB(x, "b111b");
    x.chain.registerRequest(B);
    const P = S.inputOf(x, B, "root");
    let fired = false;
    x.chain.after("getUtxosByAddresses", (c) => c.args.addresses.includes(P.address), 2, () => {
      fired = true;
      x.chain.freeze();
      x.chain.reorg({ depth: x.chain.state.chain.length - x.chain.state.chain.indexOf(C.block.hash), blocks: [{ txs: [lower(B.txId)] }] });
      x.chain.thaw();
    });
    await S.writesNothing(x, "the step", () => S.withdraw(x, B.id), (r) => { assert.ok(fired, "X accepted between r4 and r5"); S.assertCannotReject(r, "OWN_OUTPUT", "B1-11b"); });
  });

  leg("B1-11c the anchored fee input restored during the wait and then spent again by C' accepted after A1: step 2 finds C' in its block scan and renews (never REFUSED on a spend not final below A1) [RED on 5b6d8e9: a SIGNED request is never withdrawable]", async (x) => {
    const { B, F } = await spentB(x, "b111c");
    S.assertPending(await S.withdraw(x, B.id), "step 1");
    const A = await anchorOf(x, B.id);
    const input = B.build.frozen.inputs.find((i) => sameOp(i.previousOutpoint, F.outpoint));
    x.node.putEntry(F.address, { outpoint: F.outpoint, amount: BigInt(input.utxo.amount), covenantId: null, scriptPublicKey: { version: 0, script: input.utxo.scriptPublicKey.scriptHex }, daaStamp: String(A.daa - 5000n) });
    x.chain.conflictingSpend([F.outpoint], { tag: "b111c-c2" });
    x.node.state.daa = A.daa + DEPTH;
    x.chain.sync();
    const r = await S.withdraw(x, B.id);
    S.assertPending(r, "renewed");
    const now = await anchorOf(x, B.id);
    assert.notEqual(now.hash, A.hash, "a new anchor");
    assert.equal((await x.rootReq(B.id)).state, "SIGNED");
  });

  leg("B1-11d A1 reorganized out during the wait: step 2's acceptance window from A1 fails and the step renews; the next step answers REFUSED [RED on 5b6d8e9: a SIGNED request is never withdrawable]", async (x) => {
    const { B } = await spentB(x, "b111d");
    x.chain.advance(100n);
    S.assertPending(await S.withdraw(x, B.id), "step 1");
    const A = await anchorOf(x, B.id);
    x.chain.freeze();
    x.chain.reorg({ depth: x.chain.state.chain.length - x.chain.state.chain.indexOf(A.hash) + 1, blocks: [{}, {}] });
    x.chain.thaw();
    x.node.state.daa = A.daa + DEPTH;
    x.chain.sync();
    const r = await S.withdraw(x, B.id);
    S.assertPending(r, "renewed");
    const A2 = await anchorOf(x, B.id);
    assert.notEqual(A2.hash, A.hash);
    x.node.state.daa = A2.daa + DEPTH;
    const r2 = await S.withdraw(x, B.id);
    assert.equal(r2.status, 200, S.said2(r2));
    await S.assertWithdrawn(x, B.id, "after the renewal");
  });

  leg("B1-11f a Submit started while a Withdraw step 2 holds the root lock (started from inside the step's mempool read) waits, then sees the Withdraw's write: the Withdraw answers REFUSED and the Submit answers 409 'not SIGNED' (REFUSED) without any node read of its own or any broadcast [RED on 5b6d8e9: a SIGNED request is never withdrawable]", async (x) => {
    const { B } = await spentB(x, "b111f");
    S.assertPending(await S.withdraw(x, B.id), "step 1");
    x.node.state.daa = (await anchorOf(x, B.id)).daa + DEPTH;
    x.chain.registerRequest(B);
    let pS = null, callsAtSubmitStart = null;
    x.chain.after("getMempoolEntry", null, 1, () => {
      callsAtSubmitStart = x.chain.calls().length;
      pS = x.call("POST", ["org-roots", ctx.rootId, "requests", B.id, "submit"], {}, x.cookie.o1);
    });
    const [w, s] = await KK.NODE().with(x.chain.rpc, async () => {
      const wr = await x.call("POST", ["org-roots", ctx.rootId, "requests", B.id, "reject"], { reason: "RC45 R3N-B1 TEST" }, x.cookie.o1);
      return [wr, await pS];
    });
    assert.equal(w.status, 200, `the Withdraw (${S.said2(w)})`);
    assert.equal(w.body.request.state, "REFUSED");
    assert.ok(pS, "the Submit was started during the Withdraw");
    assert.equal(s.code, "REFUSED", `the Submit saw the Withdraw's write (${S.said2(s)})`);
    assert.equal(x.node.state.broadcasts.filter((t) => t === lower(B.txId)).length, 0, "nothing was broadcast");
    void callsAtSubmitStart;
  });
}
