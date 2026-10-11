"use strict";
/*
 * RC45 R3N-B1 — THE SUBMIT READ AND THE DEMONSTRATIONS (contract rc45-l201-contract-03: addendum v2b revision 3 §2,
 * §4, §7 B1-01 / B1-02 / B1-02b / B1-02e / B1-02g / B1-04..B1-05d / B1-12, writer amendment A1-1 (E1s), which prevails;
 * contract-02 §7 B1-01 / B1-02 / B1-04 intent). Internal RED-first regression material for the RC45 candidate; not an
 * external engagement of any kind.
 *
 * THE DEFECT (B-1, pre-existing; repaired at the owner's direction): an input of a finalized, never-attempted root
 * request spent by another transaction between its build and its submit start leaves the request
 * RECONCILIATION_REQUIRED with its claim and the root's reservation, and every Verify answers CLAIM_PENDING: a
 * root-wide hold, FREEZE included (GRD-06 (c)/(d) record that C3 answer).
 *
 * REQUIRED BEHAVIOUR: Submit reads, before its first write, the chain position (a 20-deep selected-chain ancestor A_s)
 * and every frozen input (non-root inputs in frozen order, the root input last), and, when an input is not reported
 * unspent, every frozen output address (an output of this request's own transaction X sends it to the C3 route).
 * A non-root input absent while the root input is still unspent, with existence evidence (E1 / E1s / E2 / E3) ->
 * 409 RECORDED_OUTPUT_SPENT (CONFLICTING_SPEND, withdrawal TWO_STEP) writing nothing; the root input not unspent and no
 * own output -> 409 SUBMIT_INPUT_UNRESOLVED ROOT_INPUT_NOT_LIVE; a non-root input with other contents ->
 * INPUT_CONTRADICTED; absent without existence evidence -> INPUT_EXISTENCE_UNPROVEN; an unreadable chain position ->
 * 422 OBSERVATION_ERROR; a node error -> that error, 422. Nothing is written in every refused case. The request is
 * then withdrawable in two steps at least 1,000 DAA apart (only the anchor written at step 1; at step 2 REFUSED and the
 * reservation released, never SUPERSEDED, no claim, no outcome), after which a root FREEZE reaches CHAIN_VERIFIED.
 *
 * Layers: SDK + API (hosted routes over the real api handler), real compiler / encoder / VM (finalize runs the pinned
 * VM preflight), the B1 mock chain (sdk/testutil/rc45-r3n-b1-chain.js); every leg in JSON and in PostgreSQL. Labels:
 * [RED on 5b6d8e9] fails on the C4-05 head for the reason its title states; [PIN: holds on 5b6d8e9] holds there and
 * must keep holding. TEST keys only; nothing dials a node.
 */
const KK = require("../testutil/rc45-r2-kas-kit");
KK.installNode(); // before anything loads server/src/api.js or the v7 request modules
const assert = require("node:assert/strict");
const { test, before, after } = require("node:test");
const B1 = require("../testutil/rc45-r3n-b1-kit");
const { said } = KK;
const { lower, sameOp } = B1;
const TOOLCHAIN = require("../testutil/org-root-durable-fixture").toolchainAvailable();

const S = B1.b1Scenario("b1sub");
const { ctx } = S;

before(async () => {
  assert.ok(TOOLCHAIN, "real compiler, encoder and VM are required (a missing VM toolchain is a FAIL, never a SKIP)");
  await S.setup();
});
after(async () => { await S.teardown(); });

for (const [backend, skip] of [["JSON", undefined], ["PostgreSQL", S.S.PG_SKIP]]) {
  const leg = (name, fn) => test(`RC45 R3N-B1 ${backend}: ${name}`, { skip }, async () => { const x = await S.fresh(backend); try { await fn(x); } finally { await S.release(x); } });

  leg("B1-01 (treasury, E1; GRD-06 (c) re-pinned) T2's recorded output, accepted long before the build, is spent outside PolicyVault between B's build (an ownerPause on T2) and its submit: Submit 409 RECORDED_OUTPUT_SPENT (CONFLICTING_SPEND, TWO_STEP, E1) naming the treasury input, writing nothing and broadcasting nothing; Verify CONSISTENT; a root FREEZE build refused ROOT_PENDING_REQUEST; Withdraw step 1 409 WITHDRAWAL_DEPTH_PENDING writing only the anchor (A1's own header DAA); +999 pending writing nothing; +1,000 REFUSED, the reservation released, never SUPERSEDED, no claim; T2's record byte-identical; a root FREEZE, then UNFREEZE and a T1 FREEZE (K) + emergency pause reach CHAIN_VERIFIED; a T2 owner operation is refused RECORDED_OUTPUT_SPENT (no spent-state adoption) [RED on 5b6d8e9: Submit takes the C3 route — RECONCILIATION_REQUIRED with claims written — and the withdrawal answers CANNOT_REJECT]", async (x) => {
    const t2 = await x.vault(ctx.T2);
    const B = await S.finalizedB(x, S.vaultOpBody(ctx.T2, "ownerPause", "authorize", S.seededFuel(x, "b101-fee")), "B1-01");
    const T = S.inputOf(x, B, "treasury");
    assert.ok(sameOp(T.outpoint, t2.live.outpoint), "B spends T2's recorded output");
    const C = x.chain.conflictingSpend([T.outpoint], { tag: "b101-c" });
    x.chain.advance(100n); // 21 chain blocks above C's block before the submit
    const t2Json = await x.recordJson("VAULT", ctx.T2);
    await S.demonstrate(x, B, { role: "treasury", outpoint: T.outpoint, existence: "E1", tag: "B1-01" });
    assert.equal(await x.recordJson("VAULT", ctx.T2), t2Json, "T2's record is byte-identical (no spent-state adoption)");
    await S.ops.unfreeze(x, "b101-uf");
    await S.writesNothing(x, "a T2 owner operation at its spent recorded output", () => S.build(x, S.vaultOpBody(ctx.T2, "ownerPause", "authorize", S.seededFuel(x, "b101-t2"))), (r) => {
      assert.equal(r.code, "RECORDED_OUTPUT_SPENT", `refused by D6 (${S.said2(r)})`);
    });
    await S.ops.emergencyPause(x, ctx.T1, "b101-ep1");
    void C;
  });

  /* a fee-input variant of the demonstration: B built with `fuel`, its fee input spent by another transaction accepted
   * on the chain, then 21 chain blocks; `existence` the path the Submit must name */
  async function feeDemo(x, body, tag, existence, { slots = null } = {}) {
    const B = await S.finalizedB(x, body, tag, { slots });
    const F = S.inputOf(x, B, "fee");
    x.chain.conflictingSpend([F.outpoint], { tag: `${tag}-c` });
    x.chain.advance(100n);
    await S.demonstrate(x, B, { role: "fee", outpoint: F.outpoint, existence, tag });
    return B;
  }

  leg("B1-02 (fee, E1, root-only; GRD-06 (d) re-pinned) a root-only FREEZE B whose explicit fee input was accepted long before the build is finalized; the fee input is then spent by another transaction: Submit 409 RECORDED_OUTPUT_SPENT (CONFLICTING_SPEND, TWO_STEP, E1) naming the fee input, nothing written; two-step withdrawal (anchor only; +999 nothing; +1,000 REFUSED, reservation released, no claim, never SUPERSEDED); a root FREEZE reaches CHAIN_VERIFIED [RED on 5b6d8e9: Submit takes the C3 route (RECONCILIATION_REQUIRED)]", async (x) => {
    await feeDemo(x, S.rootOnlyBody("freeze", S.seededFuel(x, "b102-ro-fee")), "B1-02 root-only E1", "E1");
  });

  leg("B1-02 (fee, E1, v0.7-kas operation) a T2 AUTHORIZE + pause B whose deep fee input is spent by another transaction: Submit 409 CONFLICTING_SPEND (E1) naming the fee input, nothing written; two-step withdrawal; a root FREEZE reaches CHAIN_VERIFIED [RED on 5b6d8e9: Submit takes the C3 route]", async (x) => {
    await feeDemo(x, S.vaultOpBody(ctx.T2, "ownerPause", "authorize", S.seededFuel(x, "b102-kas-fee")), "B1-02 KAS E1", "E1");
  });

  leg("B1-02 (fee, E1 boundary) the fee input accepted exactly 1,000 DAA below the virtual DAA read at build (v_b - d = 1000): E1 holds — Submit names existence E1 — and the two-step withdrawal ends REFUSED, then a root FREEZE reaches CHAIN_VERIFIED [RED on 5b6d8e9: Submit takes the C3 route]", async (x) => {
    await feeDemo(x, S.rootOnlyBody("freeze", S.seededFuel(x, "b102-e1b-fee", { age: 1000n })), "B1-02 E1 boundary 1000", "E1");
  });

  leg("B1-02 (fee, E1 boundary) the fee input accepted 999 DAA below the virtual DAA read at build: E1 does NOT hold (never judged on the current virtual DAA); the input lies below A_b, so the existence path is E2 — Submit names existence E2 — and the withdrawal ends REFUSED, then a root FREEZE reaches CHAIN_VERIFIED [RED on 5b6d8e9: Submit takes the C3 route]", async (x) => {
    await feeDemo(x, S.rootOnlyBody("freeze", S.seededFuel(x, "b102-e1n-fee", { age: 999n })), "B1-02 E1 boundary 999", "E2");
  });

  leg("B1-02 (fee, E2) the fee input created by a transaction accepted 60 DAA before the build (below A_b, not 1,000 DAA deep): Submit 409 CONFLICTING_SPEND naming existence E2; the two-step withdrawal ends REFUSED; a root FREEZE reaches CHAIN_VERIFIED [RED on 5b6d8e9: Submit takes the C3 route]", async (x) => {
    const c = S.createdFuel(x, "b102-e2");
    x.chain.advance(60n);
    x.chain.sync();
    assert.ok(c.K.daa <= x.chain.ancestor(20).daa, "the creating block lies at or below A_b");
    await feeDemo(x, S.rootOnlyBody("freeze", c.fuel), "B1-02 E2", "E2");
  });

  leg("B1-02 (fee, E2 boundary) the fee input created by the chain block A_b itself (d = DAA(A_b)): E2 holds with d <= DAA(A_b) — Submit names existence E2 — and the withdrawal ends REFUSED; a root FREEZE reaches CHAIN_VERIFIED [RED on 5b6d8e9: the build records no inputObservation (no D6b marker or anchor A_b); Submit takes the C3 route]", async (x) => {
    const c = S.createdFuel(x, "b102-e2b");
    x.node.state.daa = c.K.daa + 37n; // exactly 20 pattern blocks above K: the 20th selected parent of the sink is K
    x.chain.sync();
    assert.equal(x.chain.ancestor(20).hash, c.K.hash, "A_b at build will be the creating block itself");
    const B = await S.finalizedB(x, S.rootOnlyBody("freeze", c.fuel), "B1-02 E2 boundary");
    assert.equal(S.buildAnchor(B), c.K.hash, "the build's anchor is the creating block");
    const F = S.inputOf(x, B, "fee");
    assert.equal(String(S.markerInput(B, "fee").blockDaaScore), String(c.K.daa), "d = DAA(A_b)");
    x.chain.conflictingSpend([F.outpoint], { tag: "b102-e2b-c" });
    x.chain.advance(100n);
    await S.demonstrate(x, B, { role: "fee", outpoint: F.outpoint, existence: "E2", tag: "B1-02 E2 boundary" });
  });

  leg("B1-02e (E3, fee; SK-01) owner 2's autoFuel fee input is the change of the previous root action on this root, accepted about 10 DAA before the build (above A_b: neither E1 nor E2), then spent by another transaction: Submit 409 CONFLICTING_SPEND naming existence E3 (the creator located from A_b by getVirtualChainFromBlock and confirmed on the chain), nothing written; the two-step withdrawal ends REFUSED; a root FREEZE reaches CHAIN_VERIFIED [RED on 5b6d8e9: the build records no inputObservation (no D6b marker or anchor A_b); Submit takes the C3 route]", async (x) => {
    const p = await S.previousAction(x, "b102e");
    x.chain.advance(10n);
    const B = await S.finalizedB(x, S.autoFuelBody(ctx.T1, "ownerUnpause"), "B1-02e", { feeWallet: ctx.w.o2, cookie: x.cookie.o2 });
    const F = S.inputOf(x, B, "fee");
    assert.ok(sameOp(F.outpoint, p.change.outpoint), "autoFuel picked the previous action's change");
    S.buildAnchor(B);
    assert.ok(BigInt(S.markerInput(B, "fee").blockDaaScore) > BigInt(B.inputObservation.anchor.daaScore), "the change was accepted above A_b (d > DAA(A_b))");
    x.chain.conflictingSpend([F.outpoint], { tag: "b102e-c" });
    x.chain.advance(100n);
    await S.demonstrate(x, B, { role: "fee", outpoint: F.outpoint, existence: "E3", tag: "B1-02e" });
  });

  leg("B1-02g (E3, treasury; SK-01) T2's output created by a just-completed owner operation (T2 AUTHORIZE + pause) about 10 DAA before B's build (B: T2 AUTHORIZE + unpause, its fee input deep), then spent outside PolicyVault: Submit 409 CONFLICTING_SPEND naming the treasury input with existence E3; the two-step withdrawal ends REFUSED; a root FREEZE reaches CHAIN_VERIFIED [RED on 5b6d8e9: Submit takes the C3 route]", async (x) => {
    const prev = await S.hostedOp(x, S.vaultOpBody(ctx.T2, "ownerPause", "authorize", S.seededFuel(x, "b102g-prev-fee")), "B1-02g previous T2 pause");
    x.chain.advance(10n);
    const B = await S.finalizedB(x, S.vaultOpBody(ctx.T2, "ownerUnpause", "authorize", S.seededFuel(x, "b102g-fee")), "B1-02g");
    const T = S.inputOf(x, B, "treasury");
    assert.equal(lower(T.outpoint.transactionId), lower(prev.txId), "B spends the treasury output the previous operation created");
    x.chain.conflictingSpend([T.outpoint], { tag: "b102g-c" });
    x.chain.advance(100n);
    await S.demonstrate(x, B, { role: "treasury", outpoint: T.outpoint, existence: "E3", tag: "B1-02g" });
  });

  leg("A1-1 (E1s, fee) the fee input is the previous same-root action's change (a sibling of the root output P B spends), spent by another transaction (as another root's autoFuel request would); B's build anchor A_b then leaves the node's retained history (getBlock not found; getVirtualChainFromBlock refuses it) and only then, more than 1,000 DAA after the change was accepted, are Submit and withdrawal step 1 run: existence comes from P's own entry (E1s; no E2/E3 read can succeed), Submit 409 CONFLICTING_SPEND, the two-step withdrawal ends REFUSED and a root FREEZE reaches CHAIN_VERIFIED [RED on 5b6d8e9: the build records no inputObservation (no D6b marker or anchor A_b); Submit takes the C3 route]", async (x) => {
    const p = await S.previousAction(x, "a11f");
    x.chain.advance(10n);
    const B = await S.finalizedB(x, S.autoFuelBody(ctx.T1, "ownerUnpause"), "A1-1 fee", { feeWallet: ctx.w.o2, cookie: x.cookie.o2 });
    const F = S.inputOf(x, B, "fee");
    assert.ok(sameOp(F.outpoint, p.change.outpoint));
    x.chain.conflictingSpend([F.outpoint], { tag: "a11f-c" });
    x.chain.advance(1100n);
    x.chain.prune(S.buildAnchor(B));
    await S.demonstrate(x, B, { role: "fee", outpoint: F.outpoint, existence: ["E1s", "E1"], tag: "A1-1 E1s fee" });
  });

  leg("A1-1 (E1s, treasury) B (T2 AUTHORIZE + unpause) spends T2's output created by the previous owner operation on T2 (a sibling of P); that output is spent outside PolicyVault; A_b leaves the retained history; more than 1,000 DAA later Submit names E1s (from P's entry) and the two-step withdrawal ends REFUSED; a root FREEZE reaches CHAIN_VERIFIED [RED on 5b6d8e9: the build records no inputObservation (no D6b marker or anchor A_b); Submit takes the C3 route]", async (x) => {
    const prev = await S.hostedOp(x, S.vaultOpBody(ctx.T2, "ownerPause", "authorize", S.seededFuel(x, "a11t-prev-fee")), "A1-1 treasury previous T2 pause");
    x.chain.advance(10n);
    const B = await S.finalizedB(x, S.vaultOpBody(ctx.T2, "ownerUnpause", "authorize", S.seededFuel(x, "a11t-fee")), "A1-1 treasury");
    const T = S.inputOf(x, B, "treasury");
    assert.equal(lower(T.outpoint.transactionId), lower(prev.txId), "the treasury input is P's sibling");
    x.chain.conflictingSpend([T.outpoint], { tag: "a11t-c" });
    x.chain.advance(1100n);
    x.chain.prune(S.buildAnchor(B));
    await S.demonstrate(x, B, { role: "treasury", outpoint: T.outpoint, existence: ["E1s", "E1"], tag: "A1-1 E1s treasury" });
  });

  leg("A1-1 (E1s depth from the read before the UTXO reads) the fee input is the previous action's change, spent by another transaction; A_b is pruned; at Submit the chain position read (S1 (a)) answers a virtual DAA exactly 999 above P's entry and the virtual moves +10 before the UTXO reads: E1s does not hold (the depth is v read BEFORE the UTXO reads), so Submit answers 409 SUBMIT_INPUT_UNRESOLVED INPUT_EXISTENCE_UNPROVEN, nothing written [RED on 5b6d8e9: the build records no inputObservation (no D6b marker or anchor A_b); Submit takes the C3 route]", async (x) => {
    const p = await S.previousAction(x, "a11d");
    x.chain.advance(10n);
    const B = await S.finalizedB(x, S.autoFuelBody(ctx.T1, "ownerUnpause"), "A1-1 depth", { feeWallet: ctx.w.o2, cookie: x.cookie.o2 });
    const F = S.inputOf(x, B, "fee");
    x.chain.conflictingSpend([F.outpoint], { tag: "a11d-c" });
    x.chain.prune(S.buildAnchor(B));
    const dP = BigInt(x.node.entryAt(p.P).entry.daaStamp);
    x.node.state.daa = dP + 999n;
    x.chain.sync();
    x.chain.after("getBlock", null, 21, () => { x.node.state.daa += 10n; });
    await S.writesNothing(x, "Submit", () => S.submit(x, B.id), (r) => S.assertSubmitRead(r, { code: "SUBMIT_INPUT_UNRESOLVED", finding: "INPUT_EXISTENCE_UNPROVEN", role: "fee", outpoint: F.outpoint, withdrawal: "NONE" }, "A1-1 depth"));
  });
}
