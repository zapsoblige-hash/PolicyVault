"use strict";
/*
 * RC45 L2-01 (Narrowed C + guard) — VERIFY / FINALIZE / SUBMIT RACES around a case-5 root move confirmed outside
 * PolicyVault, including the GAP-16 route (a finalized, never-attempted request whose transaction is already on the
 * chain is re-attached by the ordinary Submit -> Verify path, verified here rather than assumed). Internal RED-first
 * regression material for the RC45 candidate; not an external engagement of any kind.
 *
 * REQUIRED BEHAVIOUR (contract revision 2 §2 RACE legs; AC-3b, AC-6): back-to-back and concurrent Verify complete A
 * exactly once; a finalized never-attempted A answers UNKNOWN SUBMIT_TO_RECORD naming it, and Submit (answered orphan or
 * RejectAlreadyAccepted) then Verify re-attach it through C3's claim path (RACE-02/02b must pass on C3 as well: a
 * failure there is a finding); a treasury output spent before that Submit leaves the root usable and T1 refused; a
 * Finalize after the attribution is refused writing nothing; a hosted B that beat A leaves A REFUSED and Verify
 * CONSISTENT; a B submitted while A is below the depth is settled at the depth. No race settles a request falsely or
 * closes a treasury whose recorded output is live.
 *
 * Layers and labels as in sdk/test/rc45-r3n-01-attribution.test.js. The submit answers come from the outcome-
 * arbitration mock (KK.outcomeRpc: rusty-kaspa's disallowed-orphan and RejectAlreadyAccepted answers). TEST keys only.
 */
const KK = require("../testutil/rc45-r2-kas-kit");
KK.installNode(); // before anything loads server/src/api.js or the v7 request modules
const assert = require("node:assert/strict");
const { test, before, after } = require("node:test");
const SC = require("../testutil/rc45-r3n-scenario");
const { D, said, withAnchor } = KK;
const { DEPTH, STALE, lower, sameOp } = SC;
const TOOLCHAIN = require("../testutil/org-root-durable-fixture").toolchainAvailable();

const X_ = SC.scenario("r3n04");
const { ctx } = X_;

before(async () => {
  assert.ok(TOOLCHAIN, "real compiler, encoder and VM are required (a missing VM toolchain is a FAIL, never a SKIP)");
  await X_.setup();
});
after(async () => { await X_.teardown(); });

async function writesNothing(x, label, fn) {
  const scope0 = await x.scope(), ev0 = await X_.eventCount(x);
  const out = await fn();
  assert.equal(await x.scope(), scope0, `${label}: nothing is written (every request, root, vault, claim and receipt record is byte-identical)`);
  assert.equal(await X_.eventCount(x), ev0, `${label}: no event line is added`);
  return out;
}
async function refused(x, label, call, status, code) {
  return writesNothing(x, label, async () => {
    const r = await call();
    assert.equal(r.status, status, `${label} (${said(r)})`);
    assert.equal(r.code, code, `${label}: ${code} (${said(r)})`);
    return r;
  });
}
/* A fresh (never stale) delegate-rule change on T1, owner quorum attached (AUTHORIZED), fee input seeded */
async function freshA(x, tag) {
  let id = null;
  await withAnchor(D, async () => {
    const r = await X_.vaultOp(x, ctx.T1, "ownerSetAgentRoot", "authorize", tag, { agents: X_.newRules() });
    assert.equal(r.status, 201, `${tag}: A is built (${said(r)})`);
    id = r.body.request.id;
    await X_.sign(x, id, [1, 2]);
  });
  const q = await x.rootReq(id);
  assert.equal(q.state, "AUTHORIZED");
  KK.seedFee(x, q);
  return q;
}
const submitWith = (x, id, rpc) => KK.NODE().with(rpc, () => x.call("POST", ["org-roots", ctx.rootId, "requests", id, "submit"], {}, x.cookie.o1));

/* RACE-02 / 02b / 03 shared: A quorum-signed, confirmed outside PolicyVault, then finalized by the hosted Finalize (the
 * finalize race); the node then at depth. Returns A's facts. */
async function finalizedAfterConfirm(x, tag) {
  const q = await freshA(x, tag);
  const f = await X_.confirmCase(x, q, { depth: 0n });
  const fin = await withAnchor(D + 10n, () => x.rootFinalize(ctx.rootId, q.id));
  assert.equal(fin.status, 200, `${tag}: the hosted Finalize of A (${said(fin)})`);
  assert.equal(fin.body.request.state, "SIGNED");
  x.node.state.daa = f.confirmedAt + DEPTH;
  return f;
}
async function gap16Route(x, f, submitAnswer, label) {
  const sub = await submitWith(x, f.A, KK.outcomeRpc(x, { submitAnswer }));
  assert.equal(sub.code, "RECONCILIATION_REQUIRED", `${label}: Submit (${said(sub)})`);
  assert.equal((await x.rootReq(f.A)).state, "RECONCILIATION_REQUIRED");
  const r = await X_.verify(x);
  assert.equal(r.root.status, "ADVANCED", `${label}: Verify re-attaches A through the claim path (${r.root.status} ${r.root.reason ?? ""})`);
  assert.equal((await x.rootReq(f.A)).state, "CHAIN_VERIFIED", `${label}: A is CHAIN_VERIFIED`);
  const root = await X_.rootRec(x);
  assert.ok(sameOp(root.live.outpoint, f.rootOut), `${label}: the root follows A's successor`);
  assert.equal(root.pendingRequestId, null, `${label}: nothing holds the root`);
  return r;
}

for (const [backend, skip] of [["JSON", undefined], ["PostgreSQL", X_.S.PG_SKIP]]) {
  const leg = (name, fn) => test(`RC45 L2-01 ${backend}: ${name}`, { skip }, async () => { const x = await X_.fresh(backend); try { await fn(x); } finally { await X_.release(x); } });

  leg("RACE-01 a second Verify started while the first is reading A's root successor, then a back-to-back Verify: exactly one answers ADVANCED via attribution, the others CONSISTENT; A completes exactly once (one root and one T1 generation, one receipt, one event line) and the last Verify writes nothing [RED on 8877dee]", async (x) => {
    const rootGen0 = Number((await X_.rootRec(x)).generation ?? 0), t1Gen0 = Number((await x.vault(ctx.T1)).generation ?? 0);
    const f = await X_.caseFive(x, "race01");
    const succ = X_.rootSuccessorAddress(x, f.recA), live = (await X_.rootRec(x)).live.address;
    let second = null;
    x.node.afterRead((c) => c.method === "getUtxosByAddresses" && c.addresses.includes(succ), succ === live ? 2 : 1, () => { second = X_.verify(x).catch((e) => ({ thrown: e })); });
    const r1 = await X_.verify(x);
    const r2 = second ? await second : await X_.verify(x);
    assert.ok(!r2.thrown, `the concurrent Verify does not fail (${r2.thrown?.message})`);
    assert.deepEqual([r1.root.status, r2.root.status].sort(), ["ADVANCED", "CONSISTENT"], `exactly one ADVANCED (${r1.root.status}, ${r2.root.status})`);
    const advanced = r1.root.status === "ADVANCED" ? r1 : r2;
    X_.assertAttributedAdvanced(advanced, f);
    const r3 = await writesNothing(x, "a back-to-back Verify", () => X_.verify(x));
    assert.equal(r3.root.status, "CONSISTENT");
    await X_.assertCompletedOnce(x, f);
    assert.equal(Number((await X_.rootRec(x)).generation ?? 0), rootGen0 + 1);
    assert.equal(Number((await x.vault(ctx.T1)).generation ?? 0), t1Gen0 + 1);
  });

  leg("RACE-02 (GAP-16 route) a fresh A carrying its owner quorum, confirmed outside PolicyVault and then finalized by the hosted Finalize: Verify answers UNKNOWN writing nothing; Submit (the node answers orphan) -> RECONCILIATION_REQUIRED; Verify -> ADVANCED through the claim path, A CHAIN_VERIFIED; FREEZE (K) + emergency pause on T1 and on T2 reach CHAIN_VERIFIED and no request is left stranded [PIN: holds on 8877dee]", async (x) => {
    const f = await finalizedAfterConfirm(x, "race02");
    const r1 = await writesNothing(x, "Verify before Submit", () => X_.verify(x));
    X_.assertUnknown(r1, "before Submit");
    X_.ifAttribution(r1, "SUBMIT_TO_RECORD", "before Submit");
    await gap16Route(x, f, "orphan", "RACE-02");
    await X_.ops.emergencyPause(x, ctx.T1, "race02-ep1");
    await X_.ops.unfreeze(x, "race02-uf");
    await X_.ops.emergencyPause(x, ctx.T2, "race02-ep2");
    const root = await X_.rootRec(x);
    assert.equal(root.pendingRequestId, null);
    assert.deepEqual((await KK.lazy.wr7.pendingRootRequests(x.config, root)).map((q) => q.id), [], "no request is left stranded");
  });

  leg("RACE-02 (SUBMIT_TO_RECORD) the same finalized, never-attempted A whose transaction is on the chain: the Verify before Submit answers UNKNOWN SUBMIT_TO_RECORD naming A and its txid, writing nothing [RED on 8877dee]", async (x) => {
    const f = await finalizedAfterConfirm(x, "race02s");
    const r1 = await writesNothing(x, "Verify before Submit", () => X_.verify(x));
    X_.assertUnknown(r1, "before Submit");
    X_.assertAttributionOutcome(r1, "SUBMIT_TO_RECORD", { requestId: f.A, label: "before Submit" });
    assert.equal(lower(r1.root.attribution.txId), f.X, "names A's txid");
  });

  leg("RACE-02b (GAP-16 route) as RACE-02 with the node answering the Submit RejectAlreadyAccepted ('was already accepted by the consensus'): RECONCILIATION_REQUIRED, then Verify ADVANCED through the claim path; FREEZE (K) + emergency pause on T1 and on T2 reach CHAIN_VERIFIED [PIN: holds on 8877dee]", async (x) => {
    const f = await finalizedAfterConfirm(x, "race02b");
    X_.assertUnknown(await X_.verify(x), "before Submit");
    await gap16Route(x, f, "alreadyAccepted", "RACE-02b");
    await X_.ops.emergencyPause(x, ctx.T1, "race02b-ep1");
    await X_.ops.unfreeze(x, "race02b-uf");
    await X_.ops.emergencyPause(x, ctx.T2, "race02b-ep2");
  });

  leg("RACE-03 as RACE-02 with T1's new output spent outside PolicyVault before the Submit: the root is ADVANCED and T1 is recorded at the spent successor (C3's unobserved T1 write); T1 then answers UNKNOWN and a T1 build is refused 409 RECORDED_OUTPUT_SPENT writing nothing, while the root and T2 stay usable (T2 AUTHORIZE + pause, root FREEZE) [RED on 8877dee]", async (x) => {
    const f = await finalizedAfterConfirm(x, "race03");
    const t1 = await x.vault(ctx.T1);
    KK.outOfAppAgentSpend(x, { template: t1.template, state: f.recA.build.successorState, outpoint: f.vaultOut, covenantId: t1.live.covenantId, registry: f.recA.newRegistry, delegate: ctx.w.n1, recipient: ctx.w.recipient.xonly });
    const r = await gap16Route(x, f, "orphan", "RACE-03");
    assert.ok(sameOp((await x.vault(ctx.T1)).live.outpoint, f.vaultOut), "T1 is recorded at A's (spent) successor");
    assert.equal(X_.vaultResult(r, ctx.T1)?.status, "UNKNOWN", "T1 answers UNKNOWN");
    await X_.ops.pause(x, ctx.T2, "race03-pz2");
    await refused(x, "a T1 build at its spent recorded output", () => X_.vaultOp(x, ctx.T1, "ownerPause", "authorize", "race03-pz1"), 409, "RECORDED_OUTPUT_SPENT");
    await X_.ops.rootFreeze(x, "race03-fz");
  });

  leg("RACE-04 a fresh A (AUTHORIZED, never finalized) confirmed outside PolicyVault and attributed at depth: a hosted Finalize afterwards is refused writing nothing [RED on 8877dee]", async (x) => {
    const q = await freshA(x, "race04");
    const f = await X_.confirmCase(x, q);
    X_.assertAttributedAdvanced(await X_.verify(x), f);
    await refused(x, "Finalize after the attribution", () => withAnchor(D + DEPTH, () => x.rootFinalize(ctx.rootId, q.id)), 409, "CHAIN_VERIFIED");
  });

  leg("RACE-05 a hosted request B (T2 AUTHORIZE + pause) reaches CHAIN_VERIFIED before A is broadcast: A can never be accepted (its root input is spent), A stays REFUSED and Verify answers CONSISTENT writing nothing [PIN: holds on 8877dee]", async (x) => {
    const recA = await X_.caseFiveA(x, "race05");
    await X_.ops.pause(x, ctx.T2, "race05-b");
    const missing = recA.build.frozen.inputs.filter((i) => !KK.inTable(x, i.previousOutpoint)).map((i) => lower(i.utxo.covenantId ?? "fee"));
    assert.ok(missing.includes(ctx.rootId), "A's root input is spent by B");
    x.node.state.daa += 2n * DEPTH;
    const r = await writesNothing(x, "Verify after B", () => X_.verify(x));
    assert.equal(r.root.status, "CONSISTENT");
    assert.equal((await x.rootReq(recA.id)).state, "REFUSED");
  });

  leg("RACE-06 a finalized B submitted while A is below the depth: with R3N-B1 (contract-03 S2 row 3, B1-05b) B's submit is refused at its submit read — 409 SUBMIT_INPUT_UNRESOLVED (ROOT_INPUT_NOT_LIVE), writing nothing, no claim taken; the Verify below the depth writes nothing; the Verify at depth attributes A and settles B SUPERSEDED (no claim of B exists) and releases the reservation [RED on 69ff7bc]", async (x) => {
    const recA = await X_.caseFiveA(x, "race06");
    const b = await X_.vaultOp(x, ctx.T2, "ownerPause", "authorize", "race06-b");
    assert.equal(b.status, 201, said(b));
    const bId = b.body.request.id;
    await X_.sign(x, bId, [1, 2]);
    assert.equal((await x.rootFinalize(ctx.rootId, bId)).status, 200);
    const bq = await x.rootReq(bId);
    KK.seedFee(x, bq);
    const f = await X_.confirmCase(x, recA, { depth: DEPTH / 2n });
    X_.assertUnknown(await writesNothing(x, "Verify below the depth", () => X_.verify(x)), "below the depth");
    /* R3N-B1a inventory re-pin: A already spent the root output B spends and no output of B's own transaction exists, so
     * the submit read refuses it before any write (the C3 route answered orphan, RECONCILIATION_REQUIRED with claims) */
    const scope0 = await x.scope();
    const sub = await submitWith(x, bId, KK.outcomeRpc(x, { submitAnswer: "strict", frozen: bq.build.frozen }));
    assert.equal(sub.status, 409, `B's submit below the depth is refused 409 (${said(sub)})`);
    assert.equal(sub.code, "SUBMIT_INPUT_UNRESOLVED", `B's submit below the depth (${said(sub)})`);
    assert.equal(sub.extra && sub.extra.submitRead && sub.extra.submitRead.finding, "ROOT_INPUT_NOT_LIVE", `the root output is not reported unspent (${said(sub)})`);
    assert.equal(await x.scope(), scope0, "the refused submit writes nothing");
    x.node.state.daa += DEPTH / 2n;
    const r = await X_.verify(x);
    X_.assertAttributedAdvanced(r, f);
    X_.assertSupersededBy(await x.rootReq(bId), f, "B");
    assert.equal(await X_.transitionClaim(x, f.P), null, "B's root claim is released");
    assert.equal(await X_.submissionClaim(x, bq.txId), null, "B's submission claim is released");
    assert.equal((await X_.rootRec(x)).pendingRequestId, null);
    void STALE;
  });
}
