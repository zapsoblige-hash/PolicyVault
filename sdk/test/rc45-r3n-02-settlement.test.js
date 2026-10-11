"use strict";
/*
 * RC45 L2-01 (Narrowed C + guard) — SETTLEMENT of the requests stranded by an attributed case-5 root move, the holds
 * and buildability derived from the records after settlement, and the settlement hook. Internal RED-first regression
 * material for the RC45 candidate; not an external engagement of any kind.
 *
 * THE DEFECT (8877dee): once A (a stale delegate-rule change on T1) is confirmed outside PolicyVault, every other root
 * request built on the root's recorded outpoint P (B: AUTHORIZED, SIGNED, or submitted after A and RECONCILIATION_
 * REQUIRED) and every unfinished delegate request sharing an input with A (D) can never be accepted, yet nothing
 * settles them: they keep the root's reservation (ROOT_PENDING_REQUEST) and the treasury guards forever.
 *
 * REQUIRED BEHAVIOUR (contract revision 2 §1 D4, D4b; the RED list legs named in each title):
 *   - D4: after A's attributed completion, in the same Verify, a root request S != A on P (S.txId != A.txId; AUTHORIZED,
 *     SIGNED, BROADCAST, CHAIN_SEEN or RECONCILIATION_REQUIRED) with no output under S.txId is settled SUPERSEDED with
 *     submissionOutcome { outcome: "SUPERSEDED", proof: { via: "attribution", acceptedConflictingTxId, attributedRequestId,
 *     spentOutpoint, depthDaa } } — an unattempted claimless S in ONE save, an attempted or claimed S in the claim
 *     path's order releasing only its own claims — and the root's pointer is cleared only when it names S; an unfinished
 *     delegate request D sharing a frozen input with A is settled the same way; nothing else is ever settled (an S with
 *     an observed output, a BUILT or unattempted SIGNED D, a D on another treasury, a claim naming another request);
 *   - D4b: holds / buildable are derived from the records AFTER settlement (the pointer and pendingRootRequests, plus
 *     each UNRESOLVED treasury); a request still holding the root is named and root builds stay refused
 *     ROOT_PENDING_REQUEST;
 *   - D4 (ii) the hook: in the live branch, only with allowClaimRelease and a CHAIN_VERIFIED marked request on the live
 *     transaction AND a settlement candidate left in the records, it finishes an interrupted settlement; its errors
 *     become `unsettled: [{ step: "hook", ... }]` beside C3's own answer; no hook I/O otherwise.
 *
 * Layers and labels as in sdk/test/rc45-r3n-01-attribution.test.js. TEST keys only; nothing dials a node.
 */
const KK = require("../testutil/rc45-r2-kas-kit");
KK.installNode(); // before anything loads server/src/api.js or the v7 request modules
const assert = require("node:assert/strict");
const { test, before, after } = require("node:test");
const SC = require("../testutil/rc45-r3n-scenario");
const { K, KAS, said } = KK;
const { lower, sameOp } = SC;
const TOOLCHAIN = require("../testutil/org-root-durable-fixture").toolchainAvailable();

const X_ = SC.scenario("r3n02");
const { ctx } = X_;
const C = () => KK.lazy.store.Categories;

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
/* B: an ownerPause on T2 built after A was withdrawn (on the root's outpoint P), signed by the owners' quorum */
async function strandedB(x, tag, { finalize = false } = {}) {
  const b = await X_.vaultOp(x, ctx.T2, "ownerPause", "authorize", tag);
  assert.equal(b.status, 201, `${tag}: B is built (${said(b)})`);
  const id = b.body.request.id;
  await X_.sign(x, id, [1, 2]);
  if (finalize) {
    const f = await x.rootFinalize(ctx.rootId, id);
    assert.equal(f.status, 200, `${tag}: B is finalized (${said(f)})`);
    assert.equal(f.body.request.state, "SIGNED");
  }
  assert.equal((await X_.rootRec(x)).pendingRequestId, id, `${tag}: B holds the root's reservation`);
  return id;
}
const submitStrict = async (x, id) => {
  const q = await x.rootReq(id);
  return KK.NODE().with(KK.outcomeRpc(x, { submitAnswer: "strict", frozen: q.build.frozen }), () => x.call("POST", ["org-roots", ctx.rootId, "requests", id, "submit"], {}, x.cookie.o1));
};
/* R3N-B1a inventory re-pin (SET-03, SET-09; contract-03 §2 S2, §6): A is accepted AFTER B's submit read and before the
 * node answers B's broadcast (A's confirmation is applied when B's transaction reaches the node, which then answers
 * orphan) — the timing in which a B RECONCILIATION_REQUIRED holding its own claims still arises with R3N-B1. (B
 * submitted after A's acceptance is refused at its submit read, nothing written: B1-05b in rc45-r3n-07-b1-submit.) */
async function submitRacingA(x, id, recA) {
  const q = await x.rootReq(id);
  const rpc = KK.outcomeRpc(x, { submitAnswer: "strict", frozen: q.build.frozen });
  const send = rpc.submitTransaction;
  let f = null;
  rpc.submitTransaction = async (args) => { f = await X_.confirmCase(x, recA); return send.call(rpc, args); };
  const sub = await KK.NODE().with(rpc, () => x.call("POST", ["org-roots", ctx.rootId, "requests", id, "submit"], {}, x.cookie.o1));
  assert.ok(f, "A is accepted when B's transaction reaches the node");
  return { sub, f };
}
const hasRootHold = (holds, id, state) => Array.isArray(holds) && holds.some((h) => h && h.scope === "root" && h.requestId === id && (state === undefined || h.state === state));

for (const [backend, skip] of [["JSON", undefined], ["PostgreSQL", X_.S.PG_SKIP]]) {
  const leg = (name, fn) => test(`RC45 L2-01 ${backend}: ${name}`, { skip }, async () => { const x = await X_.fresh(backend); try { await fn(x); } finally { await X_.release(x); } });

  leg("SET-01 B (AUTHORIZED, slot-signed, holding the root's reservation) on the root outpoint A spent: the attribution Verify settles B SUPERSEDED in one save with the attribution proof, clears the reservation, lists B as settled, and the holds derived after settlement are empty (buildable.root true) [RED on 8877dee]", async (x) => {
    let bId = null;
    const f = await X_.caseFive(x, "set01", { beforeConfirm: async () => { bId = await strandedB(x, "set01-b"); } });
    const log = X_.storeFaults(x); // a write log only (no crash rule)
    const r = await X_.verify(x);
    const bWrites = log.log().filter((op) => op.category === C().ORG_ROOT_REQUEST && op.key === bId).length;
    log.restore();
    X_.assertAttributedAdvanced(r, f);
    X_.assertSupersededBy(await x.rootReq(bId), f, "B");
    assert.equal(bWrites, 1, "an unattempted, claimless B is settled in exactly one save");
    assert.ok(JSON.stringify(r.root.settled).includes(bId), "B is listed as settled");
    assert.deepEqual(r.root.holds, [], "holds are derived after settlement: nothing holds the root");
    assert.equal(r.root.buildable.root, true);
    assert.equal((await X_.rootRec(x)).pendingRequestId, null, "the reservation is cleared");
  });

  leg("SET-02 B SIGNED (finalized, never submitted): settled SUPERSEDED in one save keeping its final transaction; a later Submit of B is refused and broadcasts nothing [RED on 8877dee]", async (x) => {
    let bId = null;
    const f = await X_.caseFive(x, "set02", { beforeConfirm: async () => { bId = await strandedB(x, "set02-b", { finalize: true }); } });
    const b0 = await x.rootReq(bId);
    const log = X_.storeFaults(x); // a write log only (no crash rule)
    const r = await X_.verify(x);
    const bWrites = log.log().filter((op) => op.category === C().ORG_ROOT_REQUEST && op.key === bId).length;
    log.restore();
    X_.assertAttributedAdvanced(r, f);
    const b = await x.rootReq(bId);
    X_.assertSupersededBy(b, f, "B");
    assert.equal(bWrites, 1, "an unattempted, claimless SIGNED B is settled in exactly one save");
    assert.ok(b.finalTransaction, "B keeps its final transaction");
    assert.deepEqual(b.finalTransaction, b0.finalTransaction, "B's final transaction is unchanged");
    assert.equal((await X_.rootRec(x)).pendingRequestId, null);
    const sent = x.node.broadcasts();
    const sub = await KK.NODE().with(x.node.rpc, () => x.call("POST", ["org-roots", ctx.rootId, "requests", bId, "submit"], {}, x.cookie.o1));
    assert.notEqual(sub.status, 200, `a SUPERSEDED request is never submitted (${said(sub)})`);
    assert.equal(x.node.broadcasts(), sent, "nothing is broadcast");
    assert.equal((await x.rootReq(bId)).state, "SUPERSEDED");
  });

  leg("SET-03 B finalized and submitted while A is accepted (after B's submit read, before the node answers B's broadcast: orphan, RECONCILIATION_REQUIRED with its claims): the attribution Verify settles B SUPERSEDED, releases B's own root claim and submission claim, and clears the reservation [RED on 8877dee]", async (x) => {
    let bId = null;
    const recA = await X_.caseFiveA(x, "set03");
    bId = await strandedB(x, "set03-b", { finalize: true });
    const { sub, f } = await submitRacingA(x, bId, recA);
    assert.equal(sub.code, "RECONCILIATION_REQUIRED", `B's submit racing A (${said(sub)})`);
    const b0 = await x.rootReq(bId);
    assert.equal((await X_.transitionClaim(x, f.P))?.txId, lower(b0.txId), "precondition: B holds the root claim on P");
    assert.ok(await X_.submissionClaim(x, b0.txId), "precondition: B holds its submission claim");
    const r = await X_.verify(x);
    X_.assertAttributedAdvanced(r, f);
    X_.assertSupersededBy(await x.rootReq(bId), f, "B");
    assert.equal(await X_.transitionClaim(x, f.P), null, "B's root claim is released");
    assert.equal(await X_.submissionClaim(x, b0.txId), null, "B's submission claim is released");
    assert.equal((await X_.rootRec(x)).pendingRequestId, null);
    assert.deepEqual(r.root.holds, []);
  });

  leg("SET-04 an unfinished delegate request D on T1 (submitted after A, RECONCILIATION_REQUIRED with its claims; it shares T1's predecessor with A): settled SUPERSEDED with the attribution proof, its own claims released; then T1 owner actions (AUTHORIZE + pause, AUTHORIZE + unpause) reach CHAIN_VERIFIED and a T1 delegate request builds (FULL) [RED on 8877dee]", async (x) => {
    const recA = await X_.caseFiveA(x, "set04");
    const d = await X_.delegateBuild(x, ctx.T1);
    assert.equal(d.status, 201, `D is built (${said(d)})`);
    const dId = d.body.request.requestId;
    assert.equal((await X_.delegateSign(x, dId)).status, 200, "D is signed");
    const f = await X_.confirmCase(x, recA);
    const dRec = await x.kasReq(dId);
    const sub = await X_.delegateSubmitWith(x, dId, KK.outcomeRpc(x, { submitAnswer: "strict", frozen: dRec.build.frozen }));
    assert.equal(sub.code, "RECONCILIATION_REQUIRED", `D's submit after A (${said(sub)})`);
    const t1Pred = (await x.kasReq(dId)).predecessorOutpoint;
    assert.equal((await X_.transitionClaim(x, t1Pred))?.txId, lower(dRec.txId), "precondition: D holds the claim on T1's predecessor");
    const r = await X_.verify(x);
    X_.assertAttributedAdvanced(r, f);
    const d1 = await x.kasReq(dId);
    assert.equal(d1.state, "SUPERSEDED", `D is settled SUPERSEDED (${d1.state})`);
    assert.equal(d1.submissionOutcome?.outcome, "SUPERSEDED");
    const proof = d1.submissionOutcome.proof ?? {};
    assert.equal(proof.via, "attribution");
    assert.equal(lower(proof.acceptedConflictingTxId), f.X);
    assert.equal(proof.attributedRequestId, f.A, "D's proof names A");
    /* the same proof on the input D shares with A (T1's predecessor, or A's fee input) */
    const shared = dRec.build.frozen.inputs.map((i) => i.previousOutpoint).filter((o) => f.recA.build.frozen.inputs.some((i) => sameOp(i.previousOutpoint, o)));
    assert.ok(shared.some((o) => sameOp(o, t1Pred)), "precondition: D shares T1's predecessor with A");
    assert.ok(shared.some((o) => sameOp(proof.spentOutpoint, o)), `D's proof names an input it shares with A (${JSON.stringify(proof.spentOutpoint)})`);
    assert.equal(String(proof.depthDaa), "1000", "D's proof states the depth");
    assert.equal(await X_.transitionClaim(x, t1Pred), null, "D's claim is released");
    assert.equal(await X_.submissionClaim(x, dRec.txId), null, "D's submission claim is released");
    assert.ok(JSON.stringify(r.root.settled).includes(dId), "D is listed as settled");
    await X_.ops.pause(x, ctx.T1, "set04-pz1");
    await X_.ops.unpause(x, ctx.T1, "set04-up1");
    const next = await X_.delegateBuild(x, ctx.T1);
    assert.equal(next.status, 201, `a T1 delegate request builds (${said(next)})`);
  });

  leg("SET-05 a delegate request D2 on T2 funded by its own fuel input (it shares no input with A), left RECONCILIATION_REQUIRED by a lost node response: the Verify after A's confirmation never settles it — state, outcome and claims untouched [PIN: holds on 8877dee]", async (x) => {
    const fuelUtxo = KK.p2pkUtxo(ctx.w.agentA, "r3n02-set05-fuel", 20n);
    x.node.seedP2pk(ctx.w.agentA, fuelUtxo.outpoint, BigInt(fuelUtxo.amount));
    const d = await X_.delegateBuild(x, ctx.T2, { fuelUtxo });
    assert.equal(d.status, 201, `D2 is built with its own fuel (${said(d)})`);
    const dId = d.body.request.requestId;
    assert.equal((await X_.delegateSign(x, dId)).status, 200);
    const sub = await X_.delegateSubmitWith(x, dId, KK.outcomeRpc(x, { submitAnswer: "lost" }));
    assert.equal(sub.code, "RECONCILIATION_REQUIRED", `the node's response is lost (${said(sub)})`);
    const d0 = await x.kasReq(dId);
    const f = await X_.caseFive(x, "set05");
    const r = await X_.verify(x);
    void r; void f;
    const d1 = await x.kasReq(dId);
    assert.equal(d1.state, "RECONCILIATION_REQUIRED", "D2 is not settled");
    assert.equal(d1.submissionOutcome, undefined, "D2 carries no outcome");
    assert.equal((await X_.transitionClaim(x, d0.predecessorOutpoint))?.txId, lower(d0.txId), "D2's claim is kept");
    assert.ok(await X_.submissionClaim(x, d0.txId), "D2's submission claim is kept");
  });

  leg("SET-06 B (AUTHORIZED on P) with an output observed under its own txid: the Verify after A's confirmation never settles it (state and outcome unchanged; an attributed answer names it unsettled, CONTRADICTION) [PIN: holds on 8877dee]", async (x) => {
    let bId = null;
    const f = await X_.caseFive(x, "set06", { beforeConfirm: async () => { bId = await strandedB(x, "set06-b"); } });
    const b0 = await x.rootReq(bId);
    const last = b0.build.frozen.outputs.length - 1, out = b0.build.frozen.outputs[last];
    x.node.putEntry(SC.spkAddress(x.config, out.scriptPublicKey), { outpoint: { transactionId: b0.txId, index: last }, amount: BigInt(out.value), covenantId: null, scriptPublicKey: { version: out.scriptPublicKey.version, script: out.scriptPublicKey.scriptHex } });
    const r = await X_.verify(x);
    const b1 = await x.rootReq(bId);
    assert.equal(b1.state, "AUTHORIZED", "B is not settled");
    assert.equal(b1.submissionOutcome, undefined);
    if (r.root.status === "ADVANCED") {
      const u = (r.root.unsettled ?? []).find((e) => e && e.requestId === bId);
      assert.ok(u, "an attributed answer names B unsettled");
      assert.match(JSON.stringify(u), /CONTRADICTION/);
    }
    void f;
  });

  leg("SET-06b that unsettled B still holds the root's reservation: holds names B (scope root, AUTHORIZED), buildable.root is false, and a hosted root build is refused 409 ROOT_PENDING_REQUEST writing nothing [RED on 8877dee]", async (x) => {
    let bId = null;
    const f = await X_.caseFive(x, "set06b", { beforeConfirm: async () => { bId = await strandedB(x, "set06b-b"); } });
    const b0 = await x.rootReq(bId);
    const last = b0.build.frozen.outputs.length - 1, out = b0.build.frozen.outputs[last];
    x.node.putEntry(SC.spkAddress(x.config, out.scriptPublicKey), { outpoint: { transactionId: b0.txId, index: last }, amount: BigInt(out.value), covenantId: null, scriptPublicKey: { version: out.scriptPublicKey.version, script: out.scriptPublicKey.scriptHex } });
    const r = await X_.verify(x);
    X_.assertAttributedAdvanced(r, f);
    assert.ok(hasRootHold(r.root.holds, bId, "AUTHORIZED"), `holds names B (${JSON.stringify(r.root.holds)})`);
    assert.equal(r.root.buildable.root, false, "the root is not called buildable while B holds it");
    assert.equal((await X_.rootRec(x)).pendingRequestId, bId);
    await refused(x, "a hosted root FREEZE while B holds the root", () => X_.rootOnly(x, "freeze", "set06b-fz"), 409, "ROOT_PENDING_REQUEST");
  });

  leg("SET-07 a crash right after B's SUPERSEDED save (before the reservation is cleared): the next Verify (live branch) runs the hook, which finishes the settlement — the reservation is cleared and the answer keeps C3's CONSISTENT [RED on 8877dee]", async (x) => {
    let bId = null;
    const f = await X_.caseFive(x, "set07", { beforeConfirm: async () => { bId = await strandedB(x, "set07-b"); } });
    const faults = X_.storeFaults(x);
    faults.crashAfter((op) => op.category === C().ORG_ROOT_REQUEST && op.key === bId && op.value?.state === "SUPERSEDED");
    await X_.verifySettled(x);
    const crashed = faults.crashed();
    faults.restore();
    assert.ok(crashed, "the Verify reached B's SUPERSEDED save (the crash is injected right after it)");
    assert.equal((await X_.rootRec(x)).pendingRequestId, bId, "the crash left B's reservation");
    const r = await X_.verify(x);
    assert.equal(r.root.status, "CONSISTENT", `the live branch keeps its own answer (${r.root.status})`);
    assert.equal((await X_.rootRec(x)).pendingRequestId, null, "the hook cleared the reservation");
    X_.assertSupersededBy(await x.rootReq(bId), f, "B");
  });

  leg("SET-08 a BUILT and a SIGNED (never attempted) delegate request on T1 are never settled: after the FULL attribution Verify both records are byte-identical [PIN: holds on 8877dee]", async (x) => {
    const db = await X_.delegateBuild(x, ctx.T1);
    assert.equal(db.status, 201, said(db));
    const ds = await X_.delegateBuild(x, ctx.T1, { payKas: 2n });
    assert.equal(ds.status, 201, said(ds));
    assert.equal((await X_.delegateSign(x, ds.body.request.requestId)).status, 200);
    const ids = [db.body.request.requestId, ds.body.request.requestId];
    const f = await X_.caseFive(x, "set08");
    const before = await Promise.all(ids.map((id) => x.recordJson("REQUEST", id)));
    await X_.verify(x);
    assert.deepEqual(await Promise.all(ids.map((id) => x.recordJson("REQUEST", id))), before, "the BUILT and the SIGNED delegate requests are untouched");
    void f;
  });

  leg("SET-08 (at broadcast) after the FULL attribution, the never-attempted SIGNED T1 delegate request is refused at broadcast 409 STALE (T1 moved on) and nothing is broadcast [RED on 8877dee]", async (x) => {
    const ds = await X_.delegateBuild(x, ctx.T1, { payKas: 2n });
    assert.equal(ds.status, 201, said(ds));
    const dsId = ds.body.request.requestId;
    assert.equal((await X_.delegateSign(x, dsId)).status, 200);
    const f = await X_.caseFive(x, "set08b");
    X_.assertAttributedAdvanced(await X_.verify(x), f);
    const sent = x.node.state.broadcasts.length;
    const dsRec = await x.kasReq(dsId);
    const sub = await X_.delegateSubmitWith(x, dsId, KK.outcomeRpc(x, { submitAnswer: "strict", frozen: dsRec.build.frozen }));
    assert.equal(sub.status, 409, said(sub));
    assert.equal(sub.code, "STALE", said(sub));
    assert.equal(x.node.state.broadcasts.length, sent, "nothing is broadcast");
  });

  leg("SET-09 B RECONCILIATION_REQUIRED (its submit racing A's acceptance: after B's submit read, before the node answers its broadcast) whose root claim names ANOTHER request (and no pointer): the attribution Verify leaves it unsettled (named), holds names it through the pending root requests, buildable.root is false, and a hosted root build is refused 409 ROOT_PENDING_REQUEST writing nothing [RED on 8877dee]", async (x) => {
    const recA = await X_.caseFiveA(x, "set09");
    const bId = await strandedB(x, "set09-b", { finalize: true });
    const { sub, f } = await submitRacingA(x, bId, recA);
    assert.equal(sub.code, "RECONCILIATION_REQUIRED", said(sub));
    await X_.editTransitionClaim(x, f.P, (c) => { c.expected = { ...c.expected, requestId: K.hex("rc45-l201-set09-another-request").slice(0, 36) }; });
    const root = await x.store.read(C().ORG_ROOT, ctx.rootId);
    root.pendingRequestId = null;
    await x.store.write(C().ORG_ROOT, ctx.rootId, root);
    const r = await X_.verify(x);
    X_.assertAttributedAdvanced(r, f);
    assert.equal((await x.rootReq(bId)).state, "RECONCILIATION_REQUIRED", "B is not settled");
    assert.ok((r.root.unsettled ?? []).some((e) => e && e.requestId === bId), "the answer names B unsettled");
    assert.ok(hasRootHold(r.root.holds, bId, "RECONCILIATION_REQUIRED"), `holds names B (${JSON.stringify(r.root.holds)})`);
    assert.equal(r.root.buildable.root, false);
    await refused(x, "a hosted root FREEZE while B is pending", () => X_.rootOnly(x, "freeze", "set09-fz"), 409, "ROOT_PENDING_REQUEST");
  });

  leg("SET-10 the hook: B's settlement save fails (B unsettled, still holding the reservation); a Verify whose hook read fails answers C3's CONSISTENT with unsettled [{ step: hook }] and writes nothing; with allowClaimRelease false there is no hook I/O at all; a normal Verify then settles B [RED on 8877dee]", async (x) => {
    let bId = null;
    const f = await X_.caseFive(x, "set10", { beforeConfirm: async () => { bId = await strandedB(x, "set10-b"); } });
    const faults = X_.storeFaults(x);
    faults.crashAt((op) => op.category === C().ORG_ROOT_REQUEST && op.key === bId);
    const first = await X_.verifySettled(x);
    faults.restore();
    assert.ok(first.result, `B's failed settlement never turns A's completion into an error (${first.thrown?.message})`);
    X_.assertAttributedAdvanced(first.result, f);
    assert.ok((first.result.root.unsettled ?? []).some((e) => e && e.requestId === bId), "B is named unsettled");
    assert.equal((await x.rootReq(bId)).state, "AUTHORIZED");
    const b = await x.rootReq(bId);
    const bOut = b.build.frozen.outputs.map((o) => SC.spkAddress(x.config, o.scriptPublicKey));
    const liveAddr = (await X_.rootRec(x)).live.address;
    const hookOnly = bOut.filter((a) => a !== liveAddr);
    const failing = X_.faultyRpc(x.node.rpc, { method: "getUtxosByAddresses", pred: ({ addresses }) => addresses.map(String).some((a) => hookOnly.includes(a)), always: true });
    const r2 = await writesNothing(x, "a Verify whose hook read fails", () => X_.verify(x, { rpc: failing }));
    assert.equal(r2.root.status, "CONSISTENT", `C3's own answer is kept (${r2.root.status})`);
    assert.ok((r2.root.unsettled ?? []).some((e) => e && e.step === "hook"), `the hook failure is reported (${JSON.stringify(r2.root.unsettled)})`);
    const from = x.node.reads().length;
    const r3 = await writesNothing(x, "a Verify without claim release", () => X_.verify(x, { allowClaimRelease: false }));
    assert.equal(r3.root.status, "CONSISTENT");
    assert.equal(x.node.reads().slice(from).filter((c) => c.method === "getUtxosByAddresses" && c.addresses.some((a) => hookOnly.includes(a))).length, 0, "no hook I/O without claim release");
    await X_.verify(x);
    X_.assertSupersededBy(await x.rootReq(bId), f, "B");
    assert.equal((await X_.rootRec(x)).pendingRequestId, null);
  });

  leg("SET-10 (hook scope, no candidate) after the FULL attribution a new root request B2 (T2 AUTHORIZE + pause, quorum-signed) is built on A's root successor and holds the reservation; the next Verify (live branch, A CHAIN_VERIFIED with its bound marker, no settlement candidate left) answers CONSISTENT, writes nothing and makes no hook read: B2 stays AUTHORIZED, unsettled, holding the reservation [RED on 8877dee]", async (x) => {
    const f = await X_.caseFive(x, "set10s");
    X_.assertAttributedAdvanced(await X_.verify(x), f);
    const b2Id = await strandedB(x, "set10s-b2");
    const b2 = await x.rootReq(b2Id);
    assert.ok(sameOp(b2.manifest.root.outpoint, f.rootOut), "precondition: B2 is built on A's root successor (not on P)");
    const b2Json = await x.recordJson("ORG_ROOT_REQUEST", b2Id);
    const root = await X_.rootRec(x), t1 = await x.vault(ctx.T1), t2 = await x.vault(ctx.T2);
    const ordinary = new Set([root.live.address, x.node.entryAt(t1.live.outpoint)?.address, x.node.entryAt(t2.live.outpoint)?.address].filter(Boolean));
    const b2Only = b2.build.frozen.outputs.map((o) => SC.spkAddress(x.config, o.scriptPublicKey)).filter((a) => !ordinary.has(a));
    const from = x.node.reads().length;
    const r = await writesNothing(x, "the Verify after B2's build", () => X_.verify(x));
    assert.equal(r.root.status, "CONSISTENT", `the live branch keeps its own answer (${r.root.status})`);
    assert.equal(x.node.reads().slice(from).filter((c) => c.method === "getUtxosByAddresses" && c.addresses.some((a) => b2Only.includes(a))).length, 0, "no hook read: B2 is no settlement candidate (not on P)");
    assert.equal(await x.recordJson("ORG_ROOT_REQUEST", b2Id), b2Json, "B2 is untouched");
    assert.equal((await x.rootReq(b2Id)).state, "AUTHORIZED");
    assert.equal((await X_.rootRec(x)).pendingRequestId, b2Id, "B2 keeps the root's reservation");
  });

  leg("SET-10 (hook scope, candidate left) a delegate request D on T1 (submitted after A, RECONCILIATION_REQUIRED) whose settlement save fails in the attribution Verify stays a settlement candidate; a new root request B2 (root FREEZE (K), slot-signed) is then built on A's root successor and holds the reservation; the next Verify runs the hook, which settles D SUPERSEDED but never settles or releases B2: B2 stays AUTHORIZED and byte-identical, holding the reservation [RED on 8877dee]", async (x) => {
    const recA = await X_.caseFiveA(x, "set10c");
    const d = await X_.delegateBuild(x, ctx.T1);
    assert.equal(d.status, 201, `D is built (${said(d)})`);
    const dId = d.body.request.requestId;
    assert.equal((await X_.delegateSign(x, dId)).status, 200, "D is signed");
    const f = await X_.confirmCase(x, recA);
    const dRec = await x.kasReq(dId);
    const sub = await X_.delegateSubmitWith(x, dId, KK.outcomeRpc(x, { submitAnswer: "strict", frozen: dRec.build.frozen }));
    assert.equal(sub.code, "RECONCILIATION_REQUIRED", `D's submit after A (${said(sub)})`);
    const faults = X_.storeFaults(x);
    faults.crashAt((op) => op.category === C().REQUEST && op.key === dId);
    const first = await X_.verifySettled(x);
    faults.restore();
    assert.ok(first.result, `D's failed settlement never turns A's completion into an error (${first.thrown?.message})`);
    X_.assertAttributedAdvanced(first.result, f);
    assert.notEqual((await x.kasReq(dId)).state, "SUPERSEDED", "precondition: D is left unsettled (a settlement candidate)");
    const b = await X_.rootOnly(x, "freeze", "set10c-b2");
    assert.equal(b.status, 201, `B2 is built (${said(b)})`);
    const b2Id = b.body.request.id;
    await X_.sign(x, b2Id, X_.slotsFor("freeze"));
    const b2 = await x.rootReq(b2Id);
    assert.equal(b2.state, "AUTHORIZED");
    assert.ok(sameOp(b2.manifest.root.outpoint, f.rootOut), "precondition: B2 is built on A's root successor (not on P)");
    assert.equal((await X_.rootRec(x)).pendingRequestId, b2Id, "precondition: B2 holds the reservation");
    const b2Json = await x.recordJson("ORG_ROOT_REQUEST", b2Id);
    const r = await X_.verify(x);
    assert.equal(r.root.status, "CONSISTENT", `the live branch keeps its own answer (${r.root.status})`);
    assert.equal((await x.kasReq(dId)).state, "SUPERSEDED", "the hook ran and settled the candidate D");
    assert.equal(await x.recordJson("ORG_ROOT_REQUEST", b2Id), b2Json, "B2 is untouched by the hook");
    assert.equal((await x.rootReq(b2Id)).state, "AUTHORIZED");
    assert.equal((await X_.rootRec(x)).pendingRequestId, b2Id, "the hook never clears a reservation that names a request off P");
  });

  /* C4-03 item check F-04 (RC45 C4-03a, tests only): the hook's bound-marker gate with a settlement candidate present
   * (REG-06 has no candidate, so it reads nothing whether the gate is there or not). Label names the C4-03 head. */
  leg("SET-11 (hook marker gate) a settlement candidate is left (B: T2 AUTHORIZE + pause on P, quorum-signed; its settlement save failed in the attribution Verify; the root's reservation then released by a store edit, so discovery has no pending request to classify) while A — the root's live transaction, CHAIN_VERIFIED — carries no bound marker (its marker removed, or of an unknown version): the next Verify answers CONSISTENT, writes nothing (named) and makes no hook read (B untouched); with A's bound marker back the hook settles B SUPERSEDED [PIN: holds on d79f710]", async (x) => {
    let bId = null;
    const f = await X_.caseFive(x, "set11", { beforeConfirm: async () => { bId = await strandedB(x, "set11-b"); } });
    const faults = X_.storeFaults(x);
    faults.crashAt((op) => op.category === C().ORG_ROOT_REQUEST && op.key === bId);
    const first = await X_.verifySettled(x);
    faults.restore();
    assert.ok(first.result, `B's failed settlement never turns A's completion into an error (${first.thrown?.message})`);
    X_.assertAttributedAdvanced(first.result, f);
    assert.equal((await x.rootReq(bId)).state, "AUTHORIZED", "precondition: B is left unsettled (a settlement candidate)");
    assert.equal((await X_.rootRec(x)).pendingRequestId, bId, "precondition: B still holds the reservation");
    /* release the reservation (store edit): with a pending request, discovery classifies it against the completed
     * request of the live transaction, which needs A's binding (a request without a final transaction or a bound marker
     * is refused there, before any hook); without one, the hook's own gate is what this leg isolates */
    const held = await x.store.read(C().ORG_ROOT, ctx.rootId);
    held.pendingRequestId = null;
    await x.store.write(C().ORG_ROOT, ctx.rootId, held);
    const aBound = await x.store.read(C().ORG_ROOT_REQUEST, f.A);
    assert.ok(KK.lazy.wr7.boundAttributionMarker(aBound), "precondition: A carries its bound marker");
    const b = await x.rootReq(bId);
    const root = await X_.rootRec(x), t1 = await x.vault(ctx.T1), t2 = await x.vault(ctx.T2);
    const ordinary = new Set([root.live.address, x.node.entryAt(t1.live.outpoint)?.address, x.node.entryAt(t2.live.outpoint)?.address].filter(Boolean));
    const hookOnly = [...new Set(b.build.frozen.outputs.map((o) => SC.spkAddress(x.config, o.scriptPublicKey)))].filter((a) => !ordinary.has(a));
    assert.ok(hookOnly.length > 0, "precondition: the hook's proof would read an address no ordinary Verify reads");
    const bJson = await x.recordJson("ORG_ROOT_REQUEST", bId);
    /* the records written by `fn`, named (category, key and the top-level fields that changed) */
    const changedBy = async (fn) => {
      const before = await KK.kasRecords(x.config), out = await fn(), after = await KK.kasRecords(x.config), changed = [];
      for (const c of Object.keys(after)) {
        const bm = new Map(before[c] ?? []), am = new Map(after[c]);
        for (const k of new Set([...bm.keys(), ...am.keys()])) {
          const vb = bm.get(k), va = am.get(k);
          if (KK.strictJson(vb) === KK.strictJson(va)) continue;
          const fields = vb && va && typeof vb === "object" && typeof va === "object" ? [...new Set([...Object.keys(vb), ...Object.keys(va)])].filter((fl) => KK.strictJson(vb[fl]) !== KK.strictJson(va[fl])) : ["(record added or removed)"];
          changed.push(`${c}/${k}: ${fields.join(", ")}`);
        }
      }
      return { out, changed };
    };
    for (const [label, edit] of [
      ["A's marker removed", (q) => { delete q.outOfBandAttribution; }],
      ["A's marker of an unknown version", (q) => { q.outOfBandAttribution = { ...q.outOfBandAttribution, schema: "policyvault-oob-attribution/2" }; }]
    ]) {
      await x.editRootReq(f.A, edit);
      const from = x.node.reads().length, ev0 = await X_.eventCount(x);
      const { out: r, changed } = await changedBy(() => X_.verify(x));
      assert.deepEqual(changed, [], `${label}: nothing is written`);
      assert.equal(await X_.eventCount(x), ev0, `${label}: no event line is added`);
      assert.equal(r.root.status, "CONSISTENT", `${label}: the live branch keeps its own answer (${r.root.status})`);
      assert.equal(r.root.settled, undefined, `${label}: nothing is settled`);
      assert.equal(r.root.unsettled, undefined, `${label}: no hook result`);
      assert.equal(x.node.reads().slice(from).filter((c) => c.method === "getUtxosByAddresses" && c.addresses.some((a) => hookOnly.includes(a))).length, 0, `${label}: no hook read`);
      assert.equal(await x.recordJson("ORG_ROOT_REQUEST", bId), bJson, `${label}: B is untouched`);
      await x.store.write(C().ORG_ROOT_REQUEST, f.A, aBound);
    }
    const r = await X_.verify(x);
    assert.equal(r.root.status, "CONSISTENT", `with the bound marker back the live branch keeps its own answer (${r.root.status})`);
    X_.assertSupersededBy(await x.rootReq(bId), f, "B (settled by the hook once A's bound marker is back)");
  });

  leg("REG-06 a root whose live transaction is an ordinary hosted request (no attribution marker): Verify answers CONSISTENT with exactly the unchanged node reads (the root and each treasury address once, no DAA read) — no hook I/O [PIN: holds on 8877dee]", async (x) => {
    await X_.ops.pause(x, ctx.T2, "reg06-pz2");
    const root = await X_.rootRec(x), t1 = await x.vault(ctx.T1), t2 = await x.vault(ctx.T2);
    const expected = [root.live.address, x.node.entryAt(t1.live.outpoint).address, x.node.entryAt(t2.live.outpoint).address].sort();
    const from = x.node.reads().length;
    const r = await writesNothing(x, "Verify of an ordinary root", () => X_.verify(x));
    assert.equal(r.root.status, "CONSISTENT");
    const reads = x.node.reads().slice(from);
    assert.deepEqual(reads.filter((c) => c.method === "getUtxosByAddresses").flatMap((c) => c.addresses).sort(), expected, "only the unchanged UTXO reads");
    assert.equal(reads.filter((c) => c.method === "getBlockDagInfo").length, 0, "no DAA read");
    void KAS; void sameOp;
  });
}
