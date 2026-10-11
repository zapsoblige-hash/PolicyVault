"use strict";
/*
 * RC45 R3N-B1 — A SUCCESSION REQUEST WHOSE FEE INPUT IS SPENT (contract rc45-l201-contract-03: addendum v2b revision 3
 * §4 W1 "any action, succession included", §7 B1-02b; writer amendment A1, which prevails). Internal RED-first
 * regression material for the RC45 candidate; not an external engagement of any kind.
 *
 * REQUIRED BEHAVIOUR: a succession built by the pinned successor (its own fee input), signed by the successor (SIGNED,
 * finalTransaction) and never attempted, whose fee input is then spent by another transaction: Submit answers 409
 * RECORDED_OUTPUT_SPENT (CONFLICTING_SPEND, TWO_STEP) writing nothing; the successor (the request's creator) withdraws
 * it in two steps at least 1,000 DAA apart (only the anchor at step 1; REFUSED at step 2, the root's reservation
 * released, never SUPERSEDED, no claim); the owners' root FREEZE then reaches CHAIN_VERIFIED.
 *
 * Layers and labels as in sdk/test/rc45-r3n-07-b1-submit.test.js. TEST keys only; nothing dials a node.
 */
const KK = require("../testutil/rc45-r2-kas-kit");
KK.installNode(); // before anything loads server/src/api.js or the v7 request modules
const assert = require("node:assert/strict");
const { test, before, after } = require("node:test");
const B1 = require("../testutil/rc45-r3n-b1-kit");
const { KAS, said } = KK;
const { lower, sameOp, DEPTH, OWNER_SENTENCE } = B1;
const TOOLCHAIN = require("../testutil/org-root-durable-fixture").toolchainAvailable();
const { OWNER_SLOTS_V7, INACTIVE_SLOT_KEY } = require("../../core/model/owner-set-v7");

const SS = B1.b1SuccessionScenario("b1succ");
const { ctx } = SS;

before(async () => {
  assert.ok(TOOLCHAIN, "real compiler, encoder and VM are required (a missing VM toolchain is a FAIL, never a SKIP)");
  await SS.setup();
});
after(async () => { await SS.teardown(); });

const said2 = (r) => `${said(r)}${r && r.extra ? ` extra=${JSON.stringify(r.extra)}` : ""}`;
const dense = (keys) => { const out = []; for (let i = 0; i < OWNER_SLOTS_V7; i += 1) out.push(i < keys.length ? keys[i] : INACTIVE_SLOT_KEY); return out; };
const onNode = (x, fn) => KK.NODE().with(x.chain.rpc, fn);
const events = async (x) => (await x.store.readAudit({ limit: 5000 })).length;
async function writesNothing(x, label, fn, check) {
  const scope0 = await x.scope(), ev0 = await events(x);
  const out = await fn();
  if (check) await check(out);
  assert.equal(await x.scope(), scope0, `${label}: nothing is written`);
  assert.equal(await events(x), ev0, `${label}: no event line`);
  return out;
}
function seeded(x, wallet, tag, age = 5000n) {
  const fuel = KK.p2pkUtxo(wallet, `b1succ-${tag}`, 50n);
  x.node.putEntry(wallet.address, { outpoint: fuel.outpoint, amount: BigInt(fuel.amount), covenantId: null, scriptPublicKey: { version: 0, script: `20${wallet.xonly}ac` }, daaStamp: String(BigInt(x.node.state.daa) - age) });
  return fuel;
}
const route = (x, id, verb, body, cookie) => onNode(x, () => x.call("POST", ["org-roots", ctx.rootId, "requests", id, verb], body, cookie));

for (const [backend, skip] of [["JSON", undefined], ["PostgreSQL", SS.S.PG_SKIP]]) {
  const leg = (name, fn) => test(`RC45 R3N-B1 ${backend}: ${name}`, { skip }, async () => { const x = await SS.fresh(backend); try { await fn(x); } finally { await SS.release(x); } });

  leg("B1-02b a SUCCESSION signed by the pinned successor (its fee input deep) and never attempted, whose fee input is then spent by another transaction: Submit 409 RECORDED_OUTPUT_SPENT (CONFLICTING_SPEND, TWO_STEP) writing nothing; the successor withdraws it in two steps (anchor only, then REFUSED at +1,000 DAA, the reservation released, never SUPERSEDED, no claim); the owners' root FREEZE reaches CHAIN_VERIFIED [RED on 5b6d8e9: Submit takes the C3 route]", async (x) => {
    const w = ctx.w, succ = ctx.successor;
    const fuel = seeded(x, succ, "fee");
    const n1 = KK.walletOf(x.config, 0x81), n2 = KK.walletOf(x.config, 0x82), n3 = KK.walletOf(x.config, 0x83);
    const b = await onNode(x, () => x.rootBuild(ctx.rootId, { action: "succession", params: { fuel, newOwnerSet: { owners: dense([n1.xonly, n2.xonly, n3.xonly]), ownerM: "2", emergencyK: "1", recoveryM: "1" } }, vaultOperations: [], signerAddress: succ.address }, x.cookie.successor));
    assert.equal(b.status, 201, `the succession is built (${said2(b)})`);
    const id = b.body.request.id;
    const q0 = await x.rootReq(id);
    const sig = await route(x, id, "signature", { signedSafeJson: KK.signInputs(x.config, q0.transaction.unsignedSafeJson, q0.transaction.signInputs, succ) }, x.cookie.successor);
    assert.equal(sig.status, 200, `signed by the successor on the real VM (${said2(sig)})`);
    const B = await x.rootReq(id);
    assert.equal(B.state, "SIGNED");
    assert.ok(B.finalTransaction, "finalized");
    const feeIn = B.build.frozen.inputs.find((i) => i.utxo.covenantId == null);
    x.chain.conflictingSpend([feeIn.previousOutpoint], { tag: "b1succ-c" });
    x.chain.advance(100n);
    x.chain.registerRequest(B);
    await writesNothing(x, "Submit", () => route(x, id, "submit", {}, x.cookie.successor), (r) => {
      assert.equal(r.status, 409, `refused (${said2(r)})`);
      assert.equal(r.code, "RECORDED_OUTPUT_SPENT", said2(r));
      assert.equal(r.extra && r.extra.submitRead && r.extra.submitRead.finding, "CONFLICTING_SPEND");
      assert.equal(r.extra.submitRead.withdrawal, "TWO_STEP");
      assert.equal(r.extra.submitRead.role, "fee");
      assert.ok(sameOp(r.extra.submitRead.outpoint, feeIn.previousOutpoint), "names the fee outpoint");
    });
    const s1 = await route(x, id, "reject", { reason: "RC45 R3N-B1 TEST" }, x.cookie.successor);
    assert.equal(s1.code, "WITHDRAWAL_DEPTH_PENDING", `step 1 (${said2(s1)})`);
    assert.ok(String(s1.message).includes(OWNER_SENTENCE), "the owner's sentence");
    const m = (await x.rootReq(id)).inputSpentObservation;
    assert.ok(m && m.anchor, "the anchor is recorded");
    x.node.state.daa = BigInt(m.anchor.daaScore) + DEPTH;
    const s2 = await route(x, id, "reject", { reason: "RC45 R3N-B1 TEST" }, x.cookie.successor);
    assert.equal(s2.status, 200, `step 2 (${said2(s2)})`);
    const done = await x.rootReq(id);
    assert.equal(done.state, "REFUSED");
    assert.equal(done.submissionOutcome, undefined, "never settled");
    assert.ok(done.inputSpentWithdrawal, "the withdrawal record");
    assert.equal((await x.rootRecord(ctx.rootId)).pendingRequestId, null, "the reservation is released");
    assert.equal(x.node.state.broadcasts.filter((t) => t === lower(B.txId)).length, 0, "nothing broadcast");
    /* the owners' root FREEZE (slot 1, emergency quorum 1) */
    const fz = await onNode(x, () => x.rootBuild(ctx.rootId, { action: "freeze", params: { fuel: seeded(x, w.fee, "fz-fee") }, vaultOperations: [], signerAddress: w.o1.address }, x.cookie.o1));
    assert.equal(fz.status, 201, `a root FREEZE builds (${said2(fz)})`);
    const fid = fz.body.request.id;
    await onNode(x, () => x.slotSign(ctx.rootId, fid, 1, w.o1, x.cookie.o1));
    const fin = await onNode(x, () => x.rootFinalize(ctx.rootId, fid, w.fee));
    assert.equal(fin.status, 200, said2(fin));
    x.chain.registerRequest(await x.rootReq(fid));
    const sub = await route(x, fid, "submit", {}, x.cookie.o1);
    assert.equal(sub.status, 200, said2(sub));
    assert.equal(sub.body.request.state, "CHAIN_VERIFIED", "the root FREEZE is CHAIN_VERIFIED");
    void KAS;
  });
}
