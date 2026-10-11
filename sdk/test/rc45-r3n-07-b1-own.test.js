"use strict";
/*
 * RC45 R3N-B1 — THIS REQUEST'S OWN TRANSACTION X BROADCAST OUTSIDE POLICYVAULT, told apart from a conflicting spend
 * (contract rc45-l201-contract-03: addendum v2b revision 3 §3 cases 1-7 and proof obligations (a)-(g), §7 B1-03,
 * B1-02c (ii), B1-02d (ii), B1-02h, B1-07c, B1-13; the owner's direction: "Never attempted by the server" does not
 * establish that no external broadcast occurred; if this request spent the input, preserve its completion,
 * attribution or reconciliation path; uncertainty must not justify withdrawal, premature claim release, or retrying
 * under a new key). Internal RED-first regression material for the RC45 candidate; not an external engagement of any
 * kind.
 *
 * REQUIRED BEHAVIOUR: X accepted with an output of its own observed -> Submit takes the C3 route (the GAP-16 route) and
 * Verify completes it (ADVANCED, CHAIN_VERIFIED); X accepted and its outputs moved on -> Submit 409
 * SUBMIT_INPUT_UNRESOLVED ROOT_INPUT_NOT_LIVE, never "spent by another transaction", Withdraw CANNOT_REJECT; X in the
 * transaction pool -> Withdraw CANNOT_REJECT, Submit's C3 claims are kept until X is proven; X accepted and then
 * reorganized out while a conflicting spend C is accepted -> Submit 409 CONFLICTING_SPEND and the withdrawal proceeds
 * only once C is final; X winning again during the wait -> CANNOT_REJECT, then SUBMIT_TO_RECORD, Submit, CHAIN_VERIFIED;
 * a creator that is not (or no longer) accepted, or a legacy record, never makes an input "spent". In every case:
 * never a withdrawal while X can still be accepted, never a premature claim release, never a false settlement, never a
 * rebuild offered (every build stays refused ROOT_PENDING_REQUEST while B holds the root).
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

const S = B1.b1Scenario("b1own");
const { ctx } = S;

before(async () => {
  assert.ok(TOOLCHAIN, "real compiler, encoder and VM are required (a missing VM toolchain is a FAIL, never a SKIP)");
  await S.setup();
});
after(async () => { await S.teardown(); });

const finalizedT2 = (x, tag, fuelOpts = {}) => S.finalizedB(x, S.vaultOpBody(ctx.T2, "ownerPause", "authorize", S.seededFuel(x, `${tag}-fee`, fuelOpts)), tag);
/* X (B's own transaction) accepted by a chain block, as an outside party holding B's signatures would broadcast it */
function acceptX(x, B) { x.chain.registerRequest(B); return x.chain.accept(lower(B.txId)); }
const outpointsOfX = (B) => B.build.frozen.outputs.map((_, i) => ({ transactionId: lower(B.txId), index: i }));
const rootOutIdx = (B) => B.build.frozen.outputs.findIndex((o) => o.covenant && lower(o.covenant.covenantId) === lower(ctx.rootId));
async function heldNoRebuild(x, tag) {
  await S.writesNothing(x, `${tag}: a build while B holds the root`, () => S.build(x, S.rootOnlyBody("freeze", S.seededFuel(x, `${tag}-held`))), (r) => assert.equal(r.code, "ROOT_PENDING_REQUEST", `${tag}: no rebuild or replacement while B holds the root (${S.said2(r)})`));
}
async function noClaims(x, B, tag) {
  assert.equal(await S.transitionClaim(x, B.manifest.root.outpoint), null, `${tag}: no root claim`);
  assert.equal(await S.submissionClaim(x, B.txId), null, `${tag}: no submission claim`);
}

for (const [backend, skip] of [["JSON", undefined], ["PostgreSQL", S.S.PG_SKIP]]) {
  const leg = (name, fn) => test(`RC45 R3N-B1 ${backend}: ${name}`, { skip }, async () => { const x = await S.fresh(backend); try { await fn(x); } finally { await S.release(x); } });

  for (const answer of ["alreadyAccepted", "orphan"]) {
    leg(`B1-03 (a) (case 1, GAP-16 route; node answer ${answer}) B's own transaction X accepted outside PolicyVault with its outputs unspent: Verify answers UNKNOWN writing nothing; Submit takes the C3 route (RECONCILIATION_REQUIRED, B's claims written); Verify then proves X through the claim path (ADVANCED) and B is CHAIN_VERIFIED, the root following X and the reservation released [PIN: holds on 5b6d8e9]`, async (x) => {
      const B = await finalizedT2(x, `b103a-${answer}`);
      acceptX(x, B);
      x.chain.advance(100n);
      await S.writesNothing(x, "Verify before Submit", () => S.verify(x), (r) => {
        assert.equal(r.root.status, "UNKNOWN", `Verify (${r.root.status})`);
        if (r.root.attribution) assert.equal(r.root.attribution.outcome, "SUBMIT_TO_RECORD", JSON.stringify(r.root.attribution));
      });
      x.chain.setSubmit(answer);
      const sub = await S.submit(x, B.id);
      assert.equal(sub.code, "RECONCILIATION_REQUIRED", `the C3 route (${S.said2(sub)})`);
      const q = await x.rootReq(B.id);
      assert.equal(q.state, "RECONCILIATION_REQUIRED");
      assert.equal((await S.transitionClaim(x, B.manifest.root.outpoint))?.txId, lower(B.txId), "B's root claim is held (never released before X is proven)");
      const r = await S.verify(x);
      assert.equal(r.root.status, "ADVANCED", `Verify (${r.root.status} ${r.root.reason ?? ""})`);
      assert.equal((await x.rootReq(B.id)).state, "CHAIN_VERIFIED");
      const root = await S.rootRec(x);
      assert.equal(lower(root.live.outpoint.transactionId), lower(B.txId), "the root follows X");
      assert.equal(root.pendingRequestId, null);
    });
  }

  leg("B1-03 (a) (case 1, withdrawal) X accepted with its outputs unspent: Withdraw answers CANNOT_REJECT (ROOT_INPUT_NOT_LIVE) writing nothing, B stays SIGNED, no claim is released or created, and every build stays refused ROOT_PENDING_REQUEST [RED on 5b6d8e9: the refusal carries no withdrawal finding]", async (x) => {
    const B = await finalizedT2(x, "b103aw");
    acceptX(x, B);
    x.chain.advance(100n);
    await S.writesNothing(x, "Withdraw", () => S.withdraw(x, B.id), (r) => S.assertCannotReject(r, "ROOT_INPUT_NOT_LIVE", "case 1 withdraw"));
    assert.equal((await x.rootReq(B.id)).state, "SIGNED");
    await noClaims(x, B, "case 1");
    await heldNoRebuild(x, "case 1");
  });

  leg("B1-03 (b) (records GAP-1) X accepted, its root successor spent onward while the fee change under X is still unspent: Submit sees X's own output and takes the C3 route (RECONCILIATION_REQUIRED, claims kept); Verify answers UNKNOWN and releases nothing [PIN: holds on 5b6d8e9]", async (x) => {
    const B = await finalizedT2(x, "b103b");
    acceptX(x, B);
    x.chain.conflictingSpend([outpointsOfX(B)[rootOutIdx(B)]], { tag: "b103b-onward" });
    x.chain.advance(100n);
    x.chain.setSubmit("alreadyAccepted");
    const sub = await S.submit(x, B.id);
    assert.equal(sub.code, "RECONCILIATION_REQUIRED", `the C3 route (${S.said2(sub)})`);
    const r = await S.verify(x);
    assert.equal(r.root.status, "UNKNOWN", `Verify (${r.root.status} ${r.root.reason ?? ""})`);
    assert.equal((await S.transitionClaim(x, B.manifest.root.outpoint))?.txId, lower(B.txId), "B's claim is kept");
    assert.equal((await S.rootRec(x)).pendingRequestId, B.id, "the reservation is kept");
  });

  leg("B1-03 (c) X accepted, its root successor spent onward, and the only entry under X observed at submit is NOT exact (another amount): it still names X, so Submit takes the C3 route (RECONCILIATION_REQUIRED) — never a 409 input refusal [PIN: holds on 5b6d8e9]", async (x) => {
    const B = await finalizedT2(x, "b103c");
    acceptX(x, B);
    const outs = outpointsOfX(B), ri = rootOutIdx(B);
    x.chain.conflictingSpend(outs.filter((_, i) => i !== outs.length - 1), { tag: "b103c-onward" });
    const last = outs[outs.length - 1];
    const e = x.node.entryAt(last);
    assert.ok(e, "one output of X is still unspent");
    x.node.mutateEntry(last, { amount: BigInt(e.entry.amount) + 7n });
    void ri;
    x.chain.advance(100n);
    x.chain.setSubmit("alreadyAccepted");
    const sub = await S.submit(x, B.id);
    assert.equal(sub.code, "RECONCILIATION_REQUIRED", `the C3 route, never a 409 input refusal (${S.said2(sub)})`);
  });

  leg("B1-03 (d) (case 2 on a v0.7-kas operation) X accepted and every output of X spent onward: Submit answers 409 SUBMIT_INPUT_UNRESOLVED ROOT_INPUT_NOT_LIVE — never RECORDED_OUTPUT_SPENT (never 'spent by another transaction') — writing nothing; Withdraw answers CANNOT_REJECT (ROOT_INPUT_NOT_LIVE) writing nothing; no claim, no rebuild [RED on 5b6d8e9: Submit takes the C3 route]", async (x) => {
    const B = await finalizedT2(x, "b103d");
    acceptX(x, B);
    x.chain.conflictingSpend(outpointsOfX(B), { tag: "b103d-onward" });
    x.chain.advance(100n);
    await S.writesNothing(x, "Submit", () => S.submit(x, B.id), (r) => {
      S.assertSubmitRead(r, { code: "SUBMIT_INPUT_UNRESOLVED", finding: "ROOT_INPUT_NOT_LIVE", role: "root", withdrawal: "NONE" }, "case 2");
      assert.notEqual(r.code, "RECORDED_OUTPUT_SPENT");
      assert.doesNotMatch(String(r.message), /spent by another transaction/i, "never 'spent by another transaction'");
    });
    await S.writesNothing(x, "Withdraw", () => S.withdraw(x, B.id), (r) => S.assertCannotReject(r, "ROOT_INPUT_NOT_LIVE", "case 2 withdraw"));
    await noClaims(x, B, "case 2");
    await heldNoRebuild(x, "case 2");
  });

  leg("B1-03 (case 3a) X sits in the node's transaction pool (every input of B still reported unspent): Verify CONSISTENT; Withdraw CANNOT_REJECT (INPUTS_LIVE) writing nothing; Submit takes the C3 route (the node answers that X is already in the mempool: RECONCILIATION_REQUIRED) and keeps B's claims while X is pending (Verify CLAIM_PENDING, nothing released); once X is accepted Verify proves it (ADVANCED) and B is CHAIN_VERIFIED [RED on 5b6d8e9: the withdrawal refusal carries no finding]", async (x) => {
    const B = await finalizedT2(x, "b103m");
    x.chain.registerRequest(B);
    x.chain.toMempool(lower(B.txId));
    await S.writesNothing(x, "Verify", () => S.verify(x), (r) => assert.equal(r.root.status, "CONSISTENT", `Verify (${r.root.status})`));
    await S.writesNothing(x, "Withdraw", () => S.withdraw(x, B.id), (r) => S.assertCannotReject(r, "INPUTS_LIVE", "case 3a withdraw"));
    const sub = await S.submit(x, B.id);
    assert.equal(sub.code, "RECONCILIATION_REQUIRED", `the C3 route (${S.said2(sub)})`);
    const r1 = await S.verify(x);
    assert.equal(r1.root.status, "CLAIM_PENDING", `X pending: nothing is released (${r1.root.status} ${r1.root.reason ?? ""})`);
    assert.equal((await S.transitionClaim(x, B.manifest.root.outpoint))?.txId, lower(B.txId), "B's claim is kept");
    x.chain.accept(lower(B.txId));
    const r2 = await S.verify(x);
    assert.equal(r2.root.status, "ADVANCED", `Verify (${r2.root.status} ${r2.root.reason ?? ""})`);
    assert.equal((await x.rootReq(B.id)).state, "CHAIN_VERIFIED");
  });

  leg("B1-03 (case 4) X accepted, then reorganized out while a conflicting spend C of B's fee input is accepted: Verify CONSISTENT; Submit 409 RECORDED_OUTPUT_SPENT (CONFLICTING_SPEND) writing nothing; the withdrawal is completed only once C is final at 1,000 DAA (two steps) — REFUSED, never SUPERSEDED, no claim; a root FREEZE reaches CHAIN_VERIFIED [RED on 5b6d8e9: Submit takes the C3 route]", async (x) => {
    const B = await finalizedT2(x, "b103r");
    const F = S.inputOf(x, B, "fee");
    const kx = acceptX(x, B);
    const C = x.chain.syntheticTx({ spend: [F.outpoint], tag: "b103r-c" });
    x.chain.freeze();
    const depth = x.chain.state.chain.length - x.chain.state.chain.indexOf(kx.hash);
    x.chain.reorg({ depth, blocks: [{ txs: [C.id] }, {}] });
    x.chain.thaw();
    assert.ok(x.node.entryAt(S.inputOf(x, B, "root").outpoint), "X reorganized out: P is unspent again");
    assert.equal(x.node.entryAt(F.outpoint), null, "C spent the fee input");
    x.chain.advance(100n);
    await S.writesNothing(x, "Verify", () => S.verify(x), (r) => assert.equal(r.root.status, "CONSISTENT", `Verify (${r.root.status})`));
    await S.demonstrate(x, B, { role: "fee", outpoint: F.outpoint, existence: "E1", tag: "case 4" });
  });

  leg("B1-07c / B1-11e (case 4, X wins during the wait) B's fee input spent by C, Submit 409, withdrawal step 1 records the anchor; a reorganization then reverses C and accepts X: step 2 answers CANNOT_REJECT (ROOT_INPUT_NOT_LIVE) writing nothing (the anchor is never trusted without a fresh observation); Verify answers UNKNOWN SUBMIT_TO_RECORD naming B; Submit takes the C3 route and Verify completes B (CHAIN_VERIFIED) — B was never withdrawn [RED on 5b6d8e9: Submit takes the C3 route and the withdrawal is refused outright]", async (x) => {
    const B = await finalizedT2(x, "b107c");
    const F = S.inputOf(x, B, "fee");
    const C = x.chain.conflictingSpend([F.outpoint], { tag: "b107c-c" });
    x.chain.advance(100n);
    await S.writesNothing(x, "Submit", () => S.submit(x, B.id), (r) => S.assertSubmitRead(r, { code: "RECORDED_OUTPUT_SPENT", finding: "CONFLICTING_SPEND", role: "fee", withdrawal: "TWO_STEP" }, "B1-07c submit"));
    const s1 = await S.withdraw(x, B.id);
    S.assertPending(s1, "B1-07c step 1");
    const A1 = BigInt((await x.rootReq(B.id)).inputSpentObservation.anchor.daaScore);
    /* X wins: C's block leaves the chain and X is accepted instead */
    x.chain.registerRequest(B);
    x.chain.freeze();
    const depth = x.chain.state.chain.length - x.chain.state.chain.indexOf(C.block.hash);
    x.chain.reorg({ depth, blocks: [{ txs: [lower(B.txId)] }, {}] });
    x.chain.thaw();
    assert.equal(x.chain.acceptedBy(lower(B.txId)) !== null, true, "X is accepted");
    x.node.state.daa = A1 + 1000n;
    await S.writesNothing(x, "step 2 after X won", () => S.withdraw(x, B.id), (r) => S.assertCannotReject(r, "ROOT_INPUT_NOT_LIVE", "B1-07c step 2"));
    assert.equal((await x.rootReq(B.id)).state, "SIGNED", "B is never withdrawn while X won");
    await S.writesNothing(x, "Verify", () => S.verify(x), (r) => {
      assert.equal(r.root.status, "UNKNOWN", `Verify (${r.root.status})`);
      assert.equal(r.root.attribution && r.root.attribution.outcome, "SUBMIT_TO_RECORD", JSON.stringify(r.root.attribution ?? null));
      assert.equal(r.root.attribution.requestId, B.id, "names B");
    });
    x.chain.setSubmit("alreadyAccepted");
    const sub = await S.submit(x, B.id);
    assert.equal(sub.code, "RECONCILIATION_REQUIRED", `the C3 route (${S.said2(sub)})`);
    const r = await S.verify(x);
    assert.equal(r.root.status, "ADVANCED", `Verify (${r.root.status} ${r.root.reason ?? ""})`);
    assert.equal((await x.rootReq(B.id)).state, "CHAIN_VERIFIED");
  });

  leg("B1-02c (ii) a legacy record (no inputObservation) whose fee input's creating transaction is not accepted: Submit answers 409 SUBMIT_INPUT_UNRESOLVED INPUT_EXISTENCE_UNPROVEN with existenceGap NO_MARKER writing nothing; Withdraw answers CANNOT_REJECT writing nothing; once the creator is accepted (the fee input reported unspent) a Submit takes the C3 route and B reaches CHAIN_VERIFIED [RED on 5b6d8e9: Submit takes the C3 route while the input is missing]", async (x) => {
    const B = await finalizedT2(x, "b102c2");
    const F = S.inputOf(x, B, "fee");
    await x.editRootReq(B.id, (q) => { delete q.inputObservation; });
    const saved = x.node.entryAt(F.outpoint);
    x.node.spendOutpoint(F.outpoint); // the creator is not (or no longer) accepted: the index has no entry
    await S.writesNothing(x, "Submit", () => S.submit(x, B.id), (r) => S.assertSubmitRead(r, { code: "SUBMIT_INPUT_UNRESOLVED", finding: "INPUT_EXISTENCE_UNPROVEN", role: "fee", outpoint: F.outpoint, withdrawal: "NONE", existenceGap: "NO_MARKER" }, "B1-02c (ii)"));
    await S.writesNothing(x, "Withdraw", () => S.withdraw(x, B.id), (r) => S.assertCannotReject(r, null, "B1-02c (ii) withdraw"));
    x.node.putEntry(saved.address, { ...saved.entry });
    const sub = await S.submit(x, B.id);
    assert.equal(sub.status, 200, `the C3 route once the input exists (${S.said2(sub)})`);
    assert.equal(sub.body.request.state, "CHAIN_VERIFIED");
  });

  leg("B1-02d (ii) (records r12) a legacy record (no inputObservation) whose fee input is reported with other contents: Submit answers 409 SUBMIT_INPUT_UNRESOLVED INPUT_CONTRADICTED writing nothing; Withdraw answers CANNOT_REJECT writing nothing (B keeps holding the root: r12) [RED on 5b6d8e9: Submit takes the C3 route]", async (x) => {
    const B = await finalizedT2(x, "b102d2");
    const F = S.inputOf(x, B, "fee");
    await x.editRootReq(B.id, (q) => { delete q.inputObservation; });
    x.node.mutateEntry(F.outpoint, { amount: BigInt(F.input.utxo.amount) + 1n });
    await S.writesNothing(x, "Submit", () => S.submit(x, B.id), (r) => S.assertSubmitRead(r, { code: "SUBMIT_INPUT_UNRESOLVED", finding: "INPUT_CONTRADICTED", role: "fee", outpoint: F.outpoint, withdrawal: "NONE" }, "B1-02d (ii)"));
    await S.writesNothing(x, "Withdraw", () => S.withdraw(x, B.id), (r) => S.assertCannotReject(r, null, "B1-02d (ii) withdraw"));
    assert.equal((await S.rootRec(x)).pendingRequestId, B.id, "r12: B keeps holding the root");
  });

  leg("B1-02h (WD-1, r13 (c)) B's fee input's creator F, accepted at build (above A_b), is replaced on the selected chain by a conflicting F' (F's own input spent by F'): Submit answers 409 SUBMIT_INPUT_UNRESOLVED INPUT_EXISTENCE_UNPROVEN with existenceGap CREATOR_NOT_LOCATED; Withdraw answers CANNOT_REJECT (INPUT_EXISTENCE_UNPROVEN) at +0, +1,000 and +5,000 DAA, writing nothing [RED on 5b6d8e9: Submit takes the C3 route]", async (x) => {
    const c = S.createdFuel(x, "b102h");
    x.chain.advance(10n);
    const B = await S.finalizedB(x, S.rootOnlyBody("freeze", c.fuel), "B1-02h");
    const F = S.inputOf(x, B, "fee");
    const fInput = x.chain.state.effects.get(c.F).body.inputs[0].previousOutpoint;
    const F2 = x.chain.syntheticTx({ spend: [fInput], tag: "b102h-fprime" });
    x.chain.freeze();
    const depth = x.chain.state.chain.length - x.chain.state.chain.indexOf(c.K.hash);
    x.chain.reorg({ depth, blocks: [{ txs: [F2.id], accept: [F2.id] }, {}] });
    x.chain.thaw();
    assert.equal(x.node.entryAt(F.outpoint), null, "F's output no longer exists");
    x.chain.advance(100n);
    await S.writesNothing(x, "Submit", () => S.submit(x, B.id), (r) => S.assertSubmitRead(r, { code: "SUBMIT_INPUT_UNRESOLVED", finding: "INPUT_EXISTENCE_UNPROVEN", role: "fee", outpoint: F.outpoint, withdrawal: "NONE", existenceGap: "CREATOR_NOT_LOCATED" }, "B1-02h"));
    for (const plus of [0n, DEPTH, 5000n]) {
      x.chain.advance(plus);
      await S.writesNothing(x, `Withdraw at +${plus}`, () => S.withdraw(x, B.id), (r) => S.assertCannotReject(r, "INPUT_EXISTENCE_UNPROVEN", `B1-02h withdraw +${plus}`));
    }
  });

  leg("B1-13 (records r4) after a completed withdrawal (REFUSED, the spend final at 1,000 DAA), a reorganization deeper than the withdrawal's assumptions reverses C and accepts X: Verify answers UNKNOWN NOT_IN_SCOPE naming B, writing nothing [RED on 5b6d8e9: the withdrawal is refused, so the leg never reaches the reorganization]", async (x) => {
    const B = await finalizedT2(x, "b113");
    const F = S.inputOf(x, B, "fee");
    const C = x.chain.conflictingSpend([F.outpoint], { tag: "b113-c" });
    x.chain.advance(100n);
    const s1 = await S.withdraw(x, B.id);
    S.assertPending(s1, "B1-13 step 1");
    const A1 = BigInt((await x.rootReq(B.id)).inputSpentObservation.anchor.daaScore);
    x.node.state.daa = A1 + DEPTH;
    const s2 = await S.withdraw(x, B.id);
    assert.equal(s2.status, 200, `withdrawn (${S.said2(s2)})`);
    await S.assertWithdrawn(x, B.id, "B1-13");
    x.chain.registerRequest(B);
    x.chain.freeze();
    const depth = x.chain.state.chain.length - x.chain.state.chain.indexOf(C.block.hash);
    x.chain.reorg({ depth, blocks: [{ txs: [lower(B.txId)] }, {}] });
    x.chain.thaw();
    x.chain.advance(DEPTH + 100n);
    await S.writesNothing(x, "Verify", () => S.verify(x), (r) => {
      assert.equal(r.root.status, "UNKNOWN", `Verify (${r.root.status})`);
      assert.equal(r.root.attribution && r.root.attribution.outcome, "NOT_IN_SCOPE", JSON.stringify(r.root.attribution ?? null));
      assert.equal(r.root.attribution.requestId, B.id, "names B");
    });
  });
}

void sameOp;
