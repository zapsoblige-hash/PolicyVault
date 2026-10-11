"use strict";
/*
 * RC45 R3N-B1 — THE SUBMIT READ RULES (contract rc45-l201-contract-03: addendum v2b revision 3 §2 S1-S5, §6 races, §7
 * B1-04, B1-04b, B1-04c, B1-04d, B1-05, B1-05b, B1-05c, B1-05d, B1-09, B1-12; writer amendment A1, which prevails).
 * Internal RED-first regression material for the RC45 candidate; not an external engagement of any kind.
 *
 * REQUIRED BEHAVIOUR (S1/S2): in submitRootAction, after the claim check and before the first submit-state write, on the
 * submit's open connection: (a) the start A_s = the sink's 20th selected parent (getBlockDagInfo, 20 hops, a
 * header-bound getBlock with isChainBlock) — unreadable -> 422 OBSERVATION_ERROR, nothing written; (b) one UTXO read
 * per distinct address of every non-root frozen input in frozen order, then the root input's address LAST; (c) only if
 * some input is not LIVE: one read per distinct frozen-output address (OWN when any entry carries X, exact or not);
 * (d) existence for the absent non-root inputs. Rows: every input LIVE -> the C3 route with submitStartHash = A_s; OWN
 * -> the C3 route (the GAP-16 route); P not LIVE -> 409 SUBMIT_INPUT_UNRESOLVED ROOT_INPUT_NOT_LIVE; a non-root
 * MISMATCH -> INPUT_CONTRADICTED; absent with existence -> 409 RECORDED_OUTPUT_SPENT CONFLICTING_SPEND; absent without
 * existence -> INPUT_EXISTENCE_UNPROVEN; a node error in (a)-(c) -> that error, 422 (a failed E2/E3 read only makes E
 * false). Nothing is written and nothing is broadcast on every refusal; the answers are definitive (same key replays,
 * a new key re-reads and can only refuse again or send exactly X).
 *
 * Layers and labels as in sdk/test/rc45-r3n-07-b1-submit.test.js. TEST keys only; nothing dials a node.
 */
const KK = require("../testutil/rc45-r2-kas-kit");
KK.installNode(); // before anything loads server/src/api.js or the v7 request modules
const assert = require("node:assert/strict");
const { test, before, after } = require("node:test");
const B1 = require("../testutil/rc45-r3n-b1-kit");
const { said } = KK;
const { lower, sameOp, DEPTH } = B1;
const TOOLCHAIN = require("../testutil/org-root-durable-fixture").toolchainAvailable();

const S = B1.b1Scenario("b1read");
const { ctx } = S;

before(async () => {
  assert.ok(TOOLCHAIN, "real compiler, encoder and VM are required (a missing VM toolchain is a FAIL, never a SKIP)");
  await S.setup();
});
after(async () => { await S.teardown(); });

/* B: T2 AUTHORIZE + pause with a deep fee input, finalized (SIGNED, never attempted) */
const finalizedT2 = (x, tag) => S.finalizedB(x, S.vaultOpBody(ctx.T2, "ownerPause", "authorize", S.seededFuel(x, `${tag}-fee`)), tag);
const broadcastsOf = (x, rec) => x.node.state.broadcasts.filter((t) => t === lower(rec.txId)).length;
/* X's own outputs spent onward outside PolicyVault (case 2) */
function spendOnward(x, rec, tag) {
  const outs = rec.build.frozen.outputs.map((_, i) => ({ transactionId: lower(rec.txId), index: i }));
  return x.chain.conflictingSpend(outs, { tag });
}

for (const [backend, skip] of [["JSON", undefined], ["PostgreSQL", S.S.PG_SKIP]]) {
  const leg = (name, fn) => test(`RC45 R3N-B1 ${backend}: ${name}`, { skip }, async () => { const x = await S.fresh(backend); try { await fn(x); } finally { await S.release(x); } });

  leg("B1-04 every input of a finalized B (T2 AUTHORIZE + pause) reported unspent at submit: the C3 route is unchanged — exactly one broadcast of X, CHAIN_VERIFIED, T2 and the root follow X, the reservation released [PIN: holds on 5b6d8e9]", async (x) => {
    const B = await finalizedT2(x, "b104");
    const sub = await S.submit(x, B.id);
    assert.equal(sub.status, 200, `submitted (${S.said2(sub)})`);
    assert.equal(sub.body.request.state, "CHAIN_VERIFIED");
    assert.equal(broadcastsOf(x, B), 1, "exactly one broadcast of X");
    const root = await S.rootRec(x);
    assert.equal(lower(root.live.outpoint.transactionId), lower(B.txId), "the root follows X");
    assert.equal(root.pendingRequestId, null);
    assert.equal(lower((await x.vault(ctx.T2)).live.outpoint.transactionId), lower(B.txId), "T2 follows X");
  });

  leg("B1-04b the submit read order: getBlockDagInfo, then 21 getBlock (20 selected-parent hops and the anchor), then the non-root input addresses in frozen order, then the root input's address — each exactly once before submitTransaction; submitStartHash is the sink's 20th selected parent [RED on 5b6d8e9: the submit reads only getBlockDagInfo and records the sink as its start]", async (x) => {
    const B = await finalizedT2(x, "b104b");
    x.chain.sync();
    const A_s = x.chain.ancestor(20).hash;
    const nonRoot = [S.inputOf(x, B, "treasury"), S.inputOf(x, B, "fee")].sort((a, b) => a.index - b.index).map((i) => i.address);
    const rootAddr = S.inputOf(x, B, "root").address;
    x.chain.resetCalls();
    const sub = await S.submit(x, B.id);
    assert.equal(sub.status, 200, S.said2(sub));
    const calls = x.chain.calls();
    const upto = calls.findIndex((c) => c.method === "submitTransaction");
    assert.ok(upto > 0, "X is broadcast");
    const seen = calls.slice(0, upto).filter((c) => c.method !== "disconnect").map((c) => c.method === "getUtxosByAddresses" ? `utxos:${c.args.addresses.join(",")}` : c.method);
    const want = ["getBlockDagInfo", ...Array(21).fill("getBlock"), ...[...new Set(nonRoot)].map((a) => `utxos:${a}`), `utxos:${rootAddr}`];
    assert.deepEqual(seen, want, "the reads before the broadcast, in order, each once");
    assert.equal((await x.rootReq(B.id)).submitStartHash, A_s, "submitStartHash is the 20-deep selected-chain ancestor, never the sink");
  });

  leg("B1-04c (a) B's fee input spent by another transaction accepted after the start read and before the input read: 409 RECORDED_OUTPUT_SPENT, nothing written, nothing broadcast [RED on 5b6d8e9: the C3 route writes]", async (x) => {
    const B = await finalizedT2(x, "b104ca");
    const F = S.inputOf(x, B, "fee");
    x.chain.after("getBlock", null, 21, () => { x.chain.conflictingSpend([F.outpoint], { tag: "b104ca-c" }); });
    await S.writesNothing(x, "Submit", () => S.submit(x, B.id), (r) => S.assertSubmitRead(r, { code: "RECORDED_OUTPUT_SPENT", finding: "CONFLICTING_SPEND", role: "fee", outpoint: F.outpoint, withdrawal: "TWO_STEP" }, "B1-04c (a)"));
    assert.equal(broadcastsOf(x, B), 0);
  });

  leg("B1-04c (b) (liveness pin) a competing spend C of B's fee input sits only in the mempool at the input read: Submit takes the C3 route and the node refuses X as a mempool double spend (not a bound rejection); C is then accepted after A_s and the submit-time sink is later removed by a shallow reorganization: Verify proves SUPERSEDED from the 20-deep start and answers CLAIM_RELEASED — B's claims and the reservation released [RED on 5b6d8e9: the start is the removed submit-time sink, so Verify answers CLAIM_PENDING every time]", async (x) => {
    const B = await finalizedT2(x, "b104cb");
    const F = S.inputOf(x, B, "fee");
    const C = x.chain.syntheticTx({ spend: [F.outpoint], tag: "b104cb-c" });
    x.chain.toMempool(C.id);
    x.chain.sync();
    const sinkAtSubmit = x.chain.sink().hash;
    const sub = await S.submit(x, B.id);
    assert.equal(sub.code, "RECONCILIATION_REQUIRED", `the C3 route; X refused as a mempool double spend (${S.said2(sub)})`);
    assert.equal(x.chain.callCount("submitTransaction"), 1, "X was handed to the node once");
    /* C accepted after A_s; then the submit-time sink and the block accepting C leave the chain and C is accepted again */
    const kc = x.chain.accept(C.id);
    x.chain.freeze();
    const depth = x.chain.state.chain.length - x.chain.state.chain.indexOf(sinkAtSubmit);
    x.chain.reorg({ depth, blocks: [{ txs: [C.id] }, {}, {}] });
    x.chain.thaw();
    assert.equal(x.chain.onChain(sinkAtSubmit), false, "the submit-time sink was removed");
    assert.equal(x.chain.onChain((await x.rootReq(B.id)).submitStartHash), true, "the 20-deep start stays on the chain");
    void kc;
    x.chain.advance(100n);
    const r = await S.verify(x);
    assert.equal(r.root.status, "CLAIM_RELEASED", `Verify (${r.root.status} ${r.root.reason ?? ""})`);
    assert.equal(r.root.outcome, "SUPERSEDED");
    assert.equal((await x.rootReq(B.id)).state, "SUPERSEDED");
    assert.equal((await S.rootRec(x)).pendingRequestId, null, "the reservation is released");
  });

  leg("B1-04c (c) (records r2) as (b), with a reorganization deep enough to remove the 20-deep start A_s itself: Verify answers CLAIM_PENDING — no negative outcome is proved from a removed start, B keeps its claims and the reservation [PIN: holds on 5b6d8e9]", async (x) => {
    const B = await finalizedT2(x, "b104cc");
    const F = S.inputOf(x, B, "fee");
    const C = x.chain.syntheticTx({ spend: [F.outpoint], tag: "b104cc-c" });
    x.chain.toMempool(C.id);
    const sub = await S.submit(x, B.id);
    assert.equal(sub.code, "RECONCILIATION_REQUIRED", S.said2(sub));
    const start = (await x.rootReq(B.id)).submitStartHash;
    x.chain.accept(C.id);
    x.chain.freeze();
    const depth = x.chain.state.chain.length - Math.max(0, x.chain.state.chain.indexOf(start)) + 1;
    x.chain.reorg({ depth, blocks: [{ txs: [C.id] }, {}, {}] });
    x.chain.thaw();
    if (start) assert.equal(x.chain.onChain(start), false, "the recorded start was removed");
    x.chain.advance(100n);
    const r = await S.verify(x);
    assert.equal(r.root.status, "CLAIM_PENDING", `Verify (${r.root.status} ${r.root.reason ?? ""})`);
    assert.equal((await S.rootRec(x)).pendingRequestId, B.id, "B keeps the reservation");
  });

  leg("B1-04d (SK-06) X is accepted right after the first non-root input read and its outputs are spent onward before the remaining reads: Submit answers 409 SUBMIT_INPUT_UNRESOLVED ROOT_INPUT_NOT_LIVE (the root input is read last), never RECORDED_OUTPUT_SPENT, writing nothing [RED on 5b6d8e9: the submit reads no input before its broadcast; it takes the C3 route]", async (x) => {
    const B = await finalizedT2(x, "b104d");
    x.chain.registerRequest(B);
    const first = [S.inputOf(x, B, "treasury"), S.inputOf(x, B, "fee")].sort((a, b) => a.index - b.index)[0].address;
    let fired = false, broadcastsAtHook = null;
    x.chain.after("getUtxosByAddresses", (c) => c.args.addresses.includes(first), 1, () => { fired = true; broadcastsAtHook = x.chain.callCount("submitTransaction"); x.chain.accept(lower(B.txId)); spendOnward(x, B, "b104d-onward"); });
    await S.writesNothing(x, "Submit", () => S.submit(x, B.id), (r) => {
      assert.ok(fired && broadcastsAtHook === 0, `X was accepted between the submit's input reads, before any broadcast (fired ${fired}, broadcasts before ${broadcastsAtHook})`);
      S.assertSubmitRead(r, { code: "SUBMIT_INPUT_UNRESOLVED", finding: "ROOT_INPUT_NOT_LIVE", role: "root", withdrawal: "NONE" }, "B1-04d");
      assert.notEqual(r.code, "RECORDED_OUTPUT_SPENT");
    });
  });

  leg("B1-05 the start read refused, writing nothing and broadcasting nothing: getBlockDagInfo throws or answers a malformed sink; a hop throws, answers another hash or a malformed selectedParentHash; the anchor answers isChainBlock false or a header that does not hash to it -> 422 OBSERVATION_ERROR; an input read or an output read throws -> the node's error, 422; a failing E2/E3 read only makes existence false (row 6) [RED on 5b6d8e9: the submit takes the C3 route and writes]", async (x) => {
    const B = await finalizedT2(x, "b105");
    let n = 0;
    const startCases = [
      ["getBlockDagInfo throws", () => x.chain.fault("getBlockDagInfo", { nth: 1 })],
      ["a malformed sink", () => x.chain.override("getBlockDagInfo", async (a, real) => ({ ...(await real()), sink: "zz" }))],
      ["a hop throws", () => x.chain.fault("getBlock", { nth: 5 })],
      ["a hop answers another hash", () => { let k = 0; x.chain.override("getBlock", async (a, real) => { const r = await real(); k += 1; if (k === 7) r.block.verboseData.hash = "ab".repeat(32); return r; }); }],
      ["a malformed selectedParentHash", () => { let k = 0; x.chain.override("getBlock", async (a, real) => { const r = await real(); k += 1; if (k === 3) r.block.verboseData.selectedParentHash = "not-a-hash"; return r; }); }],
      ["the anchor is not a chain block", () => { let k = 0; x.chain.override("getBlock", async (a, real) => { const r = await real(); k += 1; if (k === 21) r.block.verboseData.isChainBlock = false; return r; }); }],
      ["the anchor's header does not hash to it", () => { let k = 0; x.chain.override("getBlock", async (a, real) => { const r = await real(); k += 1; if (k === 21) r.block.header = { ...r.block.header, nonce: r.block.header.nonce + 1n }; return r; }); }]
    ];
    for (const [label, arm] of startCases) {
      arm();
      await S.writesNothing(x, label, () => S.submit(x, B.id), (r) => {
        assert.equal(r.status, 422, `${label}: 422 (${S.said2(r)})`);
        assert.equal(r.code, "OBSERVATION_ERROR", `${label}: OBSERVATION_ERROR (${S.said2(r)})`);
      });
      x.chain.clearFaults(); x.chain.override("getBlockDagInfo", null); x.chain.override("getBlock", null);
      n += 1;
    }
    const MSG = "TEST node: the read failed (connection reset)";
    const F = S.inputOf(x, B, "fee");
    x.chain.fault("getUtxosByAddresses", { pred: (c) => c.args.addresses.includes(F.address), message: MSG });
    await S.writesNothing(x, "an input read throws", () => S.submit(x, B.id), (r) => { assert.equal(r.status, 422, S.said2(r)); assert.ok(String(r.message).includes(MSG), S.said2(r)); });
    x.chain.clearFaults();
    x.chain.conflictingSpend([F.outpoint], { tag: "b105-c" });
    const kaspa = KK.lazy.chain.loadKaspa(x.config);
    const inAddrs = new Set(["root", "treasury", "fee"].map((role) => S.inputOf(x, B, role).address));
    const outAddr = B.build.frozen.outputs.map((o) => kaspa.addressFromScriptPublicKey({ version: o.scriptPublicKey.version, script: o.scriptPublicKey.scriptHex }, x.config.networkId).toString()).find((a) => !inAddrs.has(a));
    assert.ok(outAddr, "an output address that is no input's address");
    x.chain.fault("getUtxosByAddresses", { pred: (c) => c.args.addresses.includes(outAddr), always: true, message: MSG });
    await S.writesNothing(x, "an output read throws", () => S.submit(x, B.id), (r) => { assert.equal(r.status, 422, S.said2(r)); assert.ok(String(r.message).includes(MSG), S.said2(r)); });
    x.chain.clearFaults();
    assert.equal(broadcastsOf(x, B), 0, "nothing was broadcast");
    assert.equal(n, startCases.length);
  });

  leg("B1-05 (E reads fail-soft) B's fee input created 10 DAA before the build (only E3 could establish it) and spent; every getVirtualChainFromBlock and the A_b read fail at submit: existence is false, Submit answers 409 SUBMIT_INPUT_UNRESOLVED INPUT_EXISTENCE_UNPROVEN (never a 422, never RECORDED_OUTPUT_SPENT), nothing written [RED on 5b6d8e9: the build records no inputObservation (no D6b marker or anchor A_b); Submit takes the C3 route]", async (x) => {
    const c = S.createdFuel(x, "b105e");
    x.chain.advance(10n);
    const B = await S.finalizedB(x, S.rootOnlyBody("freeze", c.fuel), "B1-05 E");
    const F = S.inputOf(x, B, "fee");
    x.chain.conflictingSpend([F.outpoint], { tag: "b105e-c" });
    x.chain.advance(100n);
    const A_b = S.buildAnchor(B);
    x.chain.fault("getVirtualChainFromBlock", { always: true });
    x.chain.fault("getBlock", { pred: (call) => lower(call.args.hash) === A_b, always: true });
    await S.writesNothing(x, "Submit", () => S.submit(x, B.id), (r) => S.assertSubmitRead(r, { code: "SUBMIT_INPUT_UNRESOLVED", finding: "INPUT_EXISTENCE_UNPROVEN", role: "fee", outpoint: F.outpoint, withdrawal: "NONE" }, "B1-05 E fail-soft"));
  });

  leg("B1-05b (SK-06) B's root input P spent by an attributable A (the case-5 delegate-rule change, confirmed outside PolicyVault) between B's finalize and its submit: Submit answers 409 SUBMIT_INPUT_UNRESOLVED ROOT_INPUT_NOT_LIVE writing nothing; Verify at depth answers ADVANCED via attribution and settles B SUPERSEDED in one save, clearing the reservation; a root FREEZE then reaches CHAIN_VERIFIED [RED on 5b6d8e9: Submit takes the C3 route]", async (x) => {
    const recA = await S.staleA(x, "b105b");
    const B = await finalizedT2(x, "b105b-b");
    const confirmedAt = S.v(x);
    const X = KK.confirmOutOfBand(x, recA);
    await S.writesNothing(x, "Submit", () => S.submit(x, B.id), (r) => {
      S.assertSubmitRead(r, { code: "SUBMIT_INPUT_UNRESOLVED", finding: "ROOT_INPUT_NOT_LIVE", role: "root", withdrawal: "NONE" }, "B1-05b");
      assert.notEqual(r.code, "RECORDED_OUTPUT_SPENT");
    });
    x.node.state.daa = confirmedAt + DEPTH;
    const r = await S.verify(x);
    assert.equal(r.root.status, "ADVANCED", `Verify (${r.root.status} ${r.root.reason ?? ""} ${JSON.stringify(r.root.attribution ?? null)})`);
    assert.equal(r.root.via, "attribution");
    assert.equal(lower(r.root.txId), X);
    const b = await x.rootReq(B.id);
    assert.equal(b.state, "SUPERSEDED", "B is settled SUPERSEDED by the attribution");
    assert.equal(b.submissionOutcome?.proof?.via, "attribution");
    assert.equal((await S.rootRec(x)).pendingRequestId, null, "the reservation is cleared");
    await S.ops.rootFreeze(x, "b105b-fz");
  });

  leg("B1-05c B's root input P spent by an unrecorded transaction: Submit 409 SUBMIT_INPUT_UNRESOLVED ROOT_INPUT_NOT_LIVE writing nothing; Verify answers UNKNOWN (no attributable candidate: NO_CANDIDATE) writing nothing; Withdraw answers CANNOT_REJECT (ROOT_INPUT_NOT_LIVE) writing nothing [RED on 5b6d8e9: Submit takes the C3 route]", async (x) => {
    const B = await finalizedT2(x, "b105c");
    const P = S.inputOf(x, B, "root");
    x.chain.conflictingSpend([P.outpoint], { tag: "b105c-p" });
    x.chain.advance(100n);
    await S.writesNothing(x, "Submit", () => S.submit(x, B.id), (r) => S.assertSubmitRead(r, { code: "SUBMIT_INPUT_UNRESOLVED", finding: "ROOT_INPUT_NOT_LIVE", role: "root", withdrawal: "NONE" }, "B1-05c"));
    x.chain.advance(DEPTH);
    await S.writesNothing(x, "Verify", () => S.verify(x), (r) => {
      assert.equal(r.root.status, "UNKNOWN", `Verify (${r.root.status})`);
      if (r.root.attribution) assert.equal(r.root.attribution.outcome, "NO_CANDIDATE", JSON.stringify(r.root.attribution));
    });
    await S.writesNothing(x, "Withdraw", () => S.withdraw(x, B.id), (r) => S.assertCannotReject(r, "ROOT_INPUT_NOT_LIVE", "B1-05c withdraw"));
  });

  leg("B1-05d the treasury input reported with a different value at submit: 409 SUBMIT_INPUT_UNRESOLVED INPUT_CONTRADICTED naming the treasury input, nothing written, nothing broadcast [RED on 5b6d8e9: Submit takes the C3 route]", async (x) => {
    const B = await finalizedT2(x, "b105d");
    const T = S.inputOf(x, B, "treasury");
    x.node.mutateEntry(T.outpoint, { amount: BigInt(T.input.utxo.amount) + 1n });
    await S.writesNothing(x, "Submit", () => S.submit(x, B.id), (r) => S.assertSubmitRead(r, { code: "SUBMIT_INPUT_UNRESOLVED", finding: "INPUT_CONTRADICTED", role: "treasury", outpoint: T.outpoint, withdrawal: "NONE" }, "B1-05d"));
    assert.equal(broadcastsOf(x, B), 0);
  });

  leg("B1-12 X accepted between the input reads and the output reads (after the first non-root input read; its outputs stay unspent): OWN, so the C3 route — Submit answers RECONCILIATION_REQUIRED (the node: already accepted), never a 409 input refusal; Verify then proves X (ADVANCED) and B is CHAIN_VERIFIED [RED on 5b6d8e9: the submit reads no input before its broadcast]", async (x) => {
    const B = await finalizedT2(x, "b112");
    x.chain.registerRequest(B);
    const first = [S.inputOf(x, B, "treasury"), S.inputOf(x, B, "fee")].sort((a, b) => a.index - b.index)[0].address;
    let fired = false, broadcastsAtHook = null;
    x.chain.after("getUtxosByAddresses", (c) => c.args.addresses.includes(first), 1, () => { fired = true; broadcastsAtHook = x.chain.callCount("submitTransaction"); x.chain.accept(lower(B.txId)); });
    const sub = await S.submit(x, B.id);
    assert.ok(fired && broadcastsAtHook === 0, `X was accepted between the submit's input reads and its output reads, before any broadcast (fired ${fired}, broadcasts before ${broadcastsAtHook})`);
    assert.equal(sub.code, "RECONCILIATION_REQUIRED", `the C3 route (${S.said2(sub)})`);
    const r = await S.verify(x);
    assert.equal(r.root.status, "ADVANCED", `Verify (${r.root.status} ${r.root.reason ?? ""})`);
    assert.equal((await x.rootReq(B.id)).state, "CHAIN_VERIFIED");
  });

  leg("B1-09 submit retry and key: B's deep fee input spent; Submit with key k1 -> 409 RECORDED_OUTPUT_SPENT; the same key replays it (no node read, nothing written); a new key reads again and gets the same 409; a build during the hold answers ROOT_PENDING_REQUEST; once the spend is reversed (a reorganization restores the fee input) a new-key Submit sends exactly X and B reaches CHAIN_VERIFIED [RED on 5b6d8e9: the first Submit takes the C3 route]", async (x) => {
    const B = await finalizedT2(x, "b109");
    const F = S.inputOf(x, B, "fee");
    const C = x.chain.conflictingSpend([F.outpoint], { tag: "b109-c" });
    const k = (n) => `rc45-r3n-b1-b109-${x.pgDatabase ?? "json"}-${n}`;
    await S.writesNothing(x, "k1", () => S.submit(x, B.id, { key: k(1) }), (r) => S.assertSubmitRead(r, { code: "RECORDED_OUTPUT_SPENT", finding: "CONFLICTING_SPEND", role: "fee", outpoint: F.outpoint, withdrawal: "TWO_STEP" }, "k1"));
    x.chain.resetCalls();
    await S.writesNothing(x, "k1 again", () => S.submit(x, B.id, { key: k(1) }), (r) => {
      assert.equal(r.status, 409, S.said2(r));
      assert.equal(r.code, "RECORDED_OUTPUT_SPENT", "the stored answer is replayed");
      assert.equal(r.extra && r.extra.idempotency && r.extra.idempotency.replayed, true, "a replay");
      assert.equal(r.extra && r.extra.submitRead && r.extra.submitRead.finding, "CONFLICTING_SPEND", "the replay carries the stored finding");
    });
    assert.equal(x.chain.calls().filter((c) => c.method !== "disconnect").length, 0, "a replay reads nothing from the node");
    await S.writesNothing(x, "k2", () => S.submit(x, B.id, { key: k(2) }), (r) => S.assertSubmitRead(r, { code: "RECORDED_OUTPUT_SPENT", finding: "CONFLICTING_SPEND", role: "fee", outpoint: F.outpoint, withdrawal: "TWO_STEP" }, "k2"));
    await S.writesNothing(x, "a build during the hold", () => S.build(x, S.rootOnlyBody("freeze", S.seededFuel(x, "b109-held"))), (r) => assert.equal(r.code, "ROOT_PENDING_REQUEST", S.said2(r)));
    x.chain.freeze();
    const depth = x.chain.state.chain.length - x.chain.state.chain.indexOf(C.block.hash);
    x.chain.reorg({ depth, blocks: [{}, {}] });
    x.chain.thaw();
    assert.ok(x.node.entryAt(F.outpoint), "the fee input is unspent again");
    const sub = await S.submit(x, B.id, { key: k(3) });
    assert.equal(sub.status, 200, `a new key sends X (${S.said2(sub)})`);
    assert.equal(sub.body.request.state, "CHAIN_VERIFIED");
    assert.deepEqual(x.node.state.broadcasts.filter((t) => t === lower(B.txId)), [lower(B.txId)], "exactly X, once");
  });

  leg("B1-09 (after REFUSED) once B is withdrawn by the input-spent withdrawal, Submit answers 409 (REFUSED: 'not SIGNED') and Finalize is refused, both writing nothing and broadcasting nothing; a root build is admitted [RED on 5b6d8e9: a SIGNED request is never withdrawable]", async (x) => {
    const B = await finalizedT2(x, "b109r");
    const F = S.inputOf(x, B, "fee");
    x.chain.conflictingSpend([F.outpoint], { tag: "b109r-c" });
    x.chain.advance(100n);
    const s1 = await S.withdraw(x, B.id);
    S.assertPending(s1, "step 1");
    x.node.state.daa = BigInt((await x.rootReq(B.id)).inputSpentObservation.anchor.daaScore) + DEPTH;
    const s2 = await S.withdraw(x, B.id);
    assert.equal(s2.status, 200, S.said2(s2));
    await S.assertWithdrawn(x, B.id, "withdrawn");
    await S.writesNothing(x, "Submit after REFUSED", () => S.submit(x, B.id), (r) => { assert.equal(r.status, 409, S.said2(r)); assert.equal(r.code, "REFUSED", S.said2(r)); });
    await S.writesNothing(x, "Finalize after REFUSED", () => S.finalize(x, B.id), (r) => { assert.equal(r.status, 409, S.said2(r)); assert.equal(r.code, "REFUSED", S.said2(r)); });
    assert.equal(broadcastsOf(x, B), 0, "nothing was broadcast");
    const fz = await S.build(x, S.rootOnlyBody("freeze", S.seededFuel(x, "b109r-fz")));
    assert.equal(fz.status, 201, `a root build is admitted (${S.said2(fz)})`);
  });
}
