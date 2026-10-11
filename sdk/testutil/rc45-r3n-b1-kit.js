"use strict";
/*
 * RC45 R3N-B1 (contract rc45-l201-contract-03: addendum v2b revision 3 + writer decisions WD-1..WD-13 + writer amendment
 * A1, which prevails) — shared scenario support for the B1 legs of
 *   sdk/test/rc45-r3n-07-b1-build.test.js      D6b (the build-time observation), FEE_INPUT_NOT_LIVE, the anchor, A1-3
 *   sdk/test/rc45-r3n-07-b1-submit.test.js     the submit read (S1/S2) and the demonstrations (B1-01, B1-02, E1s, E3)
 *   sdk/test/rc45-r3n-07-b1-own.test.js        this request's own transaction broadcast outside PolicyVault
 *   sdk/test/rc45-r3n-07-b1-withdraw.test.js   the two-step withdrawal (W1-W8), its matrix, renewals, K1', dispatch
 *   sdk/test/rc45-r3n-07-b1-crash.test.js      crash points, retries and keys, races
 * Internal RED-first regression material for the RC45 candidate; not an external engagement of any kind.
 *
 * On top of the L2-01 scenario (sdk/testutil/rc45-r3n-scenario.js: one organizational root, owners 0x71/0x72/0x73,
 * 2-of-3, emergency quorum 1, and two rooted v0.7-kas treasuries T1 and T2, all CHAIN_VERIFIED in a self-hosted JSON
 * template; fresh HOSTED cases on the JSON store or a fresh PostgreSQL database) it provides:
 *   - a fresh case whose UTXO index reports every template output with the accepting DAA score of its (long past)
 *     creation, as a real node does (the kit default answers the read-time DAA, i.e. depth 0), and whose node is the
 *     arbitration-capable B1 mock chain (sdk/testutil/rc45-r3n-b1-chain.js) — route-level calls reach it through the
 *     kit's connectVerified patch (KK.NODE().with);
 *   - fee inputs that exist on the index (deep: created long before the build; or created by a transaction accepted
 *     on the mock chain at a chosen moment, for the E2 / E3 / E1s existence paths);
 *   - the hosted flow driven through that node: build, owner slot signatures, M-of-N finalize on the real VM, submit,
 *     withdrawal (with or without an Idempotency-Key), Verify;
 *   - the B1 assertions: nothing written (every request, root, vault, claim and receipt record byte-identical, no event
 *     line), the submit answers (status, code, extra.submitRead), the withdrawal answers (CANNOT_REJECT with
 *     extra.withdrawal.finding, WITHDRAWAL_DEPTH_PENDING with earliestDaa / latestDaa), the anchor-only write;
 *   - the demonstration of contract-03 §7 (B1-01 / B1-02 and the owner's direction): an input spent between
 *     build and submit -> Submit 409 RECORDED_OUTPUT_SPENT writing nothing -> Withdraw step 1 -> 409
 *     WITHDRAWAL_DEPTH_PENDING (only the anchor written) -> at +999 DAA 409 writing nothing -> at +1,000 DAA REFUSED,
 *     the reservation released, no claim, no settlement -> a root FREEZE built, signed, finalized, submitted and
 *     CHAIN_VERIFIED.
 *
 * Nothing dials a node: every config names ws://127.0.0.1:1 and every node observation comes from an explicit mock.
 * TEST keys only.
 */
const path = require("node:path");
const assert = require("node:assert/strict");
const SC = require("./rc45-r3n-scenario");
const { b1Chain, spkAddress, sameOp, lower } = require("./rc45-r3n-b1-chain");
const KK = SC.KK;
const { K, KAS, D, said } = KK;

const SDK_SRC = path.join(__dirname, "..", "src");
const sdk = (name) => require(path.join(SDK_SRC, name));
const DEPTH = 1000n;
const MAX_AGE = 12000n;
/* the owner's sentence (criterion 5 of the owner's direction), verbatim */
const OWNER_SENTENCE = "Withdrawal does not revoke signatures or prevent an otherwise valid out-of-app broadcast.";
/* writer amendment A1-6: the hold wording of D8's FULL warning and the B1 served texts */
const HOLD_CLAUSE = "holds the root until it is withdrawn (two steps, at least 1,000 DAA apart), or longer in the disclosed cases where a withdrawal cannot be proven safe";
const SCHEMAS = Object.freeze({ observation: "policyvault-input-observation/1", spent: "policyvault-input-spent-observation/1", withdrawal: "policyvault-input-spent-withdrawal/1" });
/* every template output was accepted this far below the case's starting virtual DAA (deep: E1 at any later build) */
const TEMPLATE_AGE = 100000n;

function b1Scenario(prefix) {
  const X_ = SC.scenario(prefix);
  const { ctx } = X_;

  /* A fresh HOSTED case on the B1 mock chain; template outputs carry their (old) accepting DAA. */
  async function fresh(backend, chainOpts = {}) {
    const x = await X_.fresh(backend);
    const old = String(BigInt(x.node.state.daa) - TEMPLATE_AGE);
    for (const entries of x.node.table().values()) for (const e of entries) if (e.daaStamp === undefined) x.node.mutateEntry(e.outpoint, { daaStamp: old });
    x.chain = b1Chain(x, chainOpts);
    return x;
  }
  const v = (x) => BigInt(x.node.state.daa);

  /* ---------------- fee inputs ---------------- */
  /* a P2PK fee UTXO of `wallet` on the index, accepted `age` DAA below the current virtual (deep by default) */
  function seededFuel(x, tag, { wallet = ctx.w.fee, age = 5000n, amountKas = 50n } = {}) {
    const fuel = KK.p2pkUtxo(wallet, `${prefix}-${tag}`, amountKas);
    x.node.putEntry(wallet.address, { outpoint: fuel.outpoint, amount: BigInt(fuel.amount), covenantId: null, scriptPublicKey: { version: 0, script: `20${wallet.xonly}ac` }, daaStamp: String(v(x) - BigInt(age)) });
    return fuel;
  }
  /* a fee UTXO created by a transaction F accepted on the mock chain NOW (block K'); returns { fuel, F, K } */
  function createdFuel(x, tag, { wallet = ctx.w.fee, amountKas = 50n, extra = [] } = {}) {
    const f = x.chain.fund(wallet, BigInt(amountKas) * KAS, { tag: `${prefix}-${tag}`, extra });
    return { fuel: f.fuel, F: f.id, K: f.block, outpoints: f.outpoints };
  }

  /* ---------------- bodies ---------------- */
  const rootOnlyBody = (action, fuel, signer = ctx.w.o1) => ({ action, params: fuel ? { fuel } : {}, vaultOperations: [], signerAddress: signer.address });
  const vaultOpBody = (vaultId, op, rootAction, fuel, params = {}, signer = ctx.w.o1) => ({ action: rootAction, params: fuel ? { fuel } : {}, vaultOperations: [{ vaultId, action: op, params }], signerAddress: signer.address });

  /* ---------------- route-level calls through the B1 node ---------------- */
  const onNode = (x, fn) => KK.NODE().with(x.chain.rpc, fn);
  const headers = (x, cookie, key) => (key ? { cookie: cookie ?? x.cookie.o1, idempotencyKey: key } : cookie ?? x.cookie.o1);
  const build = (x, body, { cookie = null } = {}) => onNode(x, () => x.rootBuild(ctx.rootId, body, cookie ?? x.cookie.o1));
  async function sign(x, id, slots) { for (const s of slots) await onNode(x, () => x.slotSign(ctx.rootId, id, s, ctx.w[`o${s}`], x.cookie[`o${s}`])); }
  const finalize = (x, id, { feeWallet = ctx.w.fee } = {}) => onNode(x, () => x.rootFinalize(ctx.rootId, id, feeWallet));
  async function submit(x, id, { key = null, cookie = null } = {}) {
    const q = await x.rootReq(id);
    if (q && q.build && q.build.frozen) x.chain.registerRequest(q);
    return onNode(x, () => x.call("POST", ["org-roots", ctx.rootId, "requests", id, "submit"], {}, headers(x, cookie, key)));
  }
  const withdraw = (x, id, { key = null, cookie = null, reason = "RC45 R3N-B1 TEST withdrawal" } = {}) => onNode(x, () => x.call("POST", ["org-roots", ctx.rootId, "requests", id, "reject"], { reason }, headers(x, cookie, key)));
  const verify = (x, opts = {}) => sdk("reconcile-v7.js").reconcileOrgRootV7(x.config, ctx.rootId, { rpc: x.chain.rpc, stalePendingMinimumMs: 0, ...opts });
  const slotsFor = (action) => (action === "freeze" ? [1] : [1, 2]);

  /* build -> owner slot signatures -> M-of-N finalize -> submit -> CHAIN_VERIFIED (fee input deep on the index) */
  async function hostedOp(x, body, tag, { slots = null, feeWallet = ctx.w.fee, cookie = null } = {}) {
    const b = await build(x, body, { cookie });
    assert.equal(b.status, 201, `${tag}: the hosted root request is built (${said(b)})`);
    const id = b.body.request.id;
    await sign(x, id, slots ?? slotsFor(body.action));
    const f = await finalize(x, id, { feeWallet });
    assert.equal(f.status, 200, `${tag}: finalized on the real VM (${said(f)})`);
    const sub = await submit(x, id);
    assert.equal(sub.status, 200, `${tag}: submitted (${said(sub)})`);
    assert.equal(sub.body.request.state, "CHAIN_VERIFIED", `${tag}: CHAIN_VERIFIED (${sub.body.request.state} ${sub.body.request.error ?? ""})`);
    return x.rootReq(id);
  }
  const ops = {
    rootFreeze: (x, tag) => hostedOp(x, rootOnlyBody("freeze", seededFuel(x, `${tag}-fee`)), `${tag} root FREEZE (K)`),
    unfreeze: (x, tag) => hostedOp(x, rootOnlyBody("unfreeze", seededFuel(x, `${tag}-fee`)), `${tag} UNFREEZE (M)`),
    emergencyPause: (x, vaultId, tag) => hostedOp(x, vaultOpBody(vaultId, "ownerEmergencyPause", "freeze", seededFuel(x, `${tag}-fee`)), `${tag} FREEZE (K) + emergency pause`),
    pause: (x, vaultId, tag) => hostedOp(x, vaultOpBody(vaultId, "ownerPause", "authorize", seededFuel(x, `${tag}-fee`)), `${tag} AUTHORIZE + pause`),
    unpause: (x, vaultId, tag) => hostedOp(x, vaultOpBody(vaultId, "ownerUnpause", "authorize", seededFuel(x, `${tag}-fee`)), `${tag} AUTHORIZE + unpause`)
  };

  /* B: built (fee input `fuel`), owner quorum attached, M-of-N finalized — SIGNED, never attempted. Returns the record. */
  async function finalizedB(x, body, tag, { slots = null, feeWallet = ctx.w.fee, cookie = null } = {}) {
    const b = await build(x, body, { cookie });
    assert.equal(b.status, 201, `${tag}: B is built (${said(b)})`);
    const id = b.body.request.id;
    await sign(x, id, slots ?? slotsFor(body.action));
    const f = await finalize(x, id, { feeWallet });
    assert.equal(f.status, 200, `${tag}: B is finalized (${said(f)})`);
    const q = await x.rootReq(id);
    assert.equal(q.state, "SIGNED", `${tag}: B is SIGNED`);
    assert.equal((await X_.rootRec(x)).pendingRequestId, id, `${tag}: B reserves the root`);
    return q;
  }
  /*
   * The previous root action by owner 2 with an autoFuel fee input (owner 2 holds exactly one deep ordinary UTXO): a T1
   * AUTHORIZE + pause (or `op` on `vaultId`) driven to CHAIN_VERIFIED on the mock chain. Its transaction X0 is accepted
   * by chain block K0; its change pays owner 2 (the fee input an autoFuel build by owner 2 picks next) and its root
   * successor P is the root's live output (a sibling of that change: E1s). Returns { prev, X0, K0, change, P, vaultOut }.
   */
  async function previousAction(x, tag, { vaultId = null, op = "ownerPause" } = {}) {
    const o2 = ctx.w.o2;
    for (const es of x.node.table().values()) for (const e of es) if (e.address === o2.address) x.node.spendOutpoint(e.outpoint);
    seededFuel(x, `${tag}-o2-funding`, { wallet: o2, amountKas: 40n });
    const prev = await hostedOp(x, vaultOpBody(vaultId ?? ctx.T1, op, "authorize", null, {}, o2), `${tag} previous ${op}`, { feeWallet: o2, cookie: x.cookie.o2 });
    const X0 = lower(prev.txId);
    const K0 = x.chain.blockOfTx(X0);
    assert.ok(K0 && x.chain.onChain(K0.hash), `${tag}: the previous action is accepted by a chain block`);
    const change = [...x.node.table().values()].flat().find((e) => e.address === o2.address && lower(e.outpoint.transactionId) === X0);
    assert.ok(change, `${tag}: the previous action's change pays owner 2`);
    const P = (await X_.rootRec(x)).live.outpoint;
    assert.equal(lower(P.transactionId), X0, `${tag}: the root's live output is the previous action's root successor`);
    const vIdx = sdk("rooted-kas-profile-v7.js").vaultSuccessorIndexOf(prev);
    return { prev, X0, K0, change: { outpoint: { transactionId: X0, index: Number(change.outpoint.index) }, amount: String(change.amount) }, P, vaultOut: { transactionId: X0, index: Number(vIdx) } };
  }
  /* B by owner 2 with an autoFuel fee input (owner 2's only UTXO: the previous action's change) */
  const autoFuelBody = (vaultId, op, rootAction = "authorize") => vaultOpBody(vaultId, op, rootAction, null, {}, ctx.w.o2);
  /*
   * The case-5 request A through the B1 node (fee input deep on the index): a v0.7-kas delegate-rule change on T1 adding
   * delegate N1, built at D with the owners' slot signatures, refused at finalize PERIOD_START_STALE at STALE (the node's
   * DAA moved there) and withdrawn on the existing aged-out path. Returns A's record.
   */
  async function staleA(x, tag) {
    let id = null;
    await KK.withAnchor(D, async () => {
      const r = await build(x, vaultOpBody(ctx.T1, "ownerSetAgentRoot", "authorize", seededFuel(x, `${tag}-a-fee`), { agents: X_.newRules() }));
      assert.equal(r.status, 201, `${tag}: A is built (${said(r)})`);
      id = r.body.request.id;
      await sign(x, id, [1, 2]);
    });
    x.node.state.daa = SC.STALE;
    x.chain.sync();
    await KK.withAnchor(SC.STALE, async () => {
      const f = await finalize(x, id);
      assert.equal(f.code, "PERIOD_START_STALE", `${tag}: A is not finalized (${said(f)})`);
      const wd = await withdraw(x, id);
      assert.equal(wd.status, 200, `${tag}: A is withdrawn on the aged-out path (${said(wd)})`);
    });
    return x.rootReq(id);
  }

  /* the frozen input of B with this role (first in frozen order): { index, outpoint, input, address } */
  function inputOf(x, rec, role) {
    const rootId = lower(ctx.rootId);
    const ins = rec.build.frozen.inputs.map((input, index) => ({ input, index, cov: input.utxo.covenantId == null ? null : lower(input.utxo.covenantId) }));
    const pick = role === "root" ? ins.find((i) => i.cov === rootId) : role === "fee" ? ins.find((i) => i.cov === null) : ins.find((i) => i.cov !== null && i.cov !== rootId);
    assert.ok(pick, `B has a ${role} input`);
    return { index: pick.index, outpoint: { transactionId: lower(pick.input.previousOutpoint.transactionId), index: Number(pick.input.previousOutpoint.index) }, input: pick.input, address: spkAddress(x.config, pick.input.utxo.scriptPublicKey) };
  }

  /* B's build anchor A_b (D6b's marker), asserted present */
  function buildAnchor(B) {
    const m = B && B.inputObservation;
    assert.ok(m && m.anchor && /^[0-9a-f]{64}$/.test(String(m.anchor.hash)), `B's build recorded inputObservation with its chain anchor A_b (D6b) (${JSON.stringify(m ?? null).slice(0, 160)})`);
    return m.anchor.hash;
  }
  /* B's marker entry for the first non-root input with this role, asserted present */
  function markerInput(B, role) {
    const m = B && B.inputObservation;
    assert.ok(m && Array.isArray(m.inputs), `B's build recorded inputObservation (D6b) (${JSON.stringify(m ?? null).slice(0, 160)})`);
    const e = m.inputs.find((i) => i.role === role);
    assert.ok(e, `the marker lists the ${role} input`);
    return e;
  }

  /* ---------------- assertions ---------------- */
  /* `check(out)` runs first (the answer's own assertions), then nothing written is asserted */
  async function writesNothing(x, label, fn, check = null) {
    const scope0 = await x.scope(), ev0 = await X_.eventCount(x);
    const out = await fn();
    if (check) await check(out);
    assert.equal(await x.scope(), scope0, `${label}: nothing is written (every request, root, vault, claim and receipt record is byte-identical)`);
    assert.equal(await X_.eventCount(x), ev0, `${label}: no event line is added`);
    return out;
  }
  /* the request records other than B, every root / vault / claim / receipt record: byte-identical; B differs only in `fields` */
  async function onlyFieldsChanged(x, before, id, fields, label) {
    const after = await x.snap();
    const C = KK.lazy.store.Categories;
    for (const c of KK.kasCategories()) {
      const a = before.records[c], b = after.records[c];
      if (c !== C.ORG_ROOT_REQUEST && c !== C.ORG_ROOT) { assert.equal(KK.strictJson(b), KK.strictJson(a), `${label}: the ${c} records are byte-identical`); continue; }
      assert.deepEqual(b.map(([k]) => k), a.map(([k]) => k), `${label}: no ${c} record is added or removed`);
      for (let i = 0; i < a.length; i++) {
        const [key, va] = a[i], vb = b[i][1];
        const allowed = c === C.ORG_ROOT_REQUEST && key === id ? [...fields, "updatedAt"] : c === C.ORG_ROOT ? (fields.includes("pendingRequestId") ? ["pendingRequestId", "updatedAt"] : []) : [];
        const strip = (o) => { const out = { ...o }; for (const f of allowed) delete out[f]; return KK.strictJson(out); };
        assert.equal(strip(vb), strip(va), `${label}: ${c} ${key.slice(0, 12)} differs only in ${allowed.join(", ") || "nothing"}`);
      }
    }
    assert.equal(after.audit.length, before.audit.length, `${label}: no event line is added`);
    return after;
  }
  const said2 = (r) => `${said(r)}${r && r.extra ? ` extra=${JSON.stringify(r.extra)}` : ""}`;
  function assertSubmitRead(r, { code, finding, role = undefined, outpoint = undefined, withdrawal = undefined, existence = undefined, existenceGap = undefined }, label) {
    assert.equal(r.status, 409, `${label}: Submit is refused 409, not taken to the C3 route (${said2(r)})`);
    assert.equal(r.code, code, `${label}: ${code} (${said2(r)})`);
    const s = r.extra && r.extra.submitRead;
    assert.ok(s && typeof s === "object", `${label}: the answer carries extra.submitRead (${said2(r)})`);
    assert.equal(s.finding, finding, `${label}: finding ${finding} (${JSON.stringify(s)})`);
    if (role !== undefined) assert.equal(s.role, role, `${label}: names the ${role} input`);
    if (outpoint !== undefined) assert.ok(sameOp(s.outpoint, outpoint), `${label}: names the outpoint ${outpoint.transactionId}:${outpoint.index} (${JSON.stringify(s.outpoint)})`);
    if (withdrawal !== undefined) assert.equal(s.withdrawal, withdrawal, `${label}: withdrawal ${withdrawal}`);
    if (existence !== undefined) assert.ok([].concat(existence).includes(s.existence), `${label}: existence ${[].concat(existence).join(" | ")} (got ${s.existence})`);
    if (existenceGap !== undefined) assert.equal(s.existenceGap, existenceGap, `${label}: existenceGap ${existenceGap}`);
    return s;
  }
  function assertCannotReject(r, finding, label) {
    assert.equal(r.status, 409, `${label}: refused 409 (${said2(r)})`);
    assert.equal(r.code, "CANNOT_REJECT", `${label}: CANNOT_REJECT (${said2(r)})`);
    if (finding !== null) assert.equal(r.extra && r.extra.withdrawal && r.extra.withdrawal.finding, finding, `${label}: finding ${finding} (${said2(r)})`);
  }
  function assertPending(r, label, { anchorDaa = null } = {}) {
    assert.equal(r.status, 409, `${label}: 409 (${said2(r)})`);
    assert.equal(r.code, "WITHDRAWAL_DEPTH_PENDING", `${label}: WITHDRAWAL_DEPTH_PENDING (${said2(r)})`);
    assert.ok(String(r.message).includes(OWNER_SENTENCE), `${label}: the pending message ends with the owner's sentence verbatim (${r.message})`);
    if (anchorDaa !== null) {
      assert.equal(String(r.extra && r.extra.earliestDaa), String(BigInt(anchorDaa) + DEPTH), `${label}: earliestDaa = anchor DAA + 1,000 (${said2(r)})`);
      assert.equal(String(r.extra && r.extra.latestDaa), String(BigInt(anchorDaa) + MAX_AGE), `${label}: latestDaa = anchor DAA + 12,000 (${said2(r)})`);
    }
  }
  /* the anchor B carries after a step: bound, anchored on the 20th selected parent of the sink at that step */
  function assertAnchor(rec, chain, { label, expectHash = null }) {
    const m = rec.inputSpentObservation;
    assert.ok(m && typeof m === "object", `${label}: B carries inputSpentObservation`);
    assert.equal(m.schema, SCHEMAS.spent, `${label}: its schema`);
    assert.equal(m.requestId, rec.id, `${label}: names B`);
    assert.equal(lower(m.txId), lower(rec.txId), `${label}: names X`);
    assert.ok(/^[0-9a-f]{64}$/.test(m.anchor.hash), `${label}: a 64-hex anchor hash`);
    const blk = chain.block(m.anchor.hash);
    assert.ok(blk, `${label}: the anchor is a block of the node`);
    assert.equal(String(m.anchor.daaScore), String(blk.daa), `${label}: the anchor's DAA is the anchor block's own header DAA (never the virtual DAA)`);
    if (expectHash) assert.equal(m.anchor.hash, expectHash, `${label}: the anchor is the 20th selected parent of the sink at that step`);
    assert.ok(Array.isArray(m.spent) && m.spent.length > 0, `${label}: a non-empty spent list`);
    return m;
  }
  /* B withdrawn by the input-spent withdrawal: REFUSED, never SUPERSEDED, no submission outcome, the record bound */
  async function assertWithdrawn(x, id, label) {
    const q = await x.rootReq(id);
    assert.equal(q.state, "REFUSED", `${label}: B is REFUSED (withdrawn), not ${q.state}`);
    assert.equal(q.submissionOutcome, undefined, `${label}: no submission outcome (nothing is settled)`);
    assert.equal(q.submissionAttempt, undefined, `${label}: never attempted`);
    const w = q.inputSpentWithdrawal;
    assert.ok(w && w.schema === SCHEMAS.withdrawal && w.requestId === id && lower(w.txId) === lower(q.txId), `${label}: B carries its bound inputSpentWithdrawal`);
    assert.equal(await X_.transitionClaim(x, q.manifest.root.outpoint), null, `${label}: no root claim exists`);
    assert.equal(await X_.submissionClaim(x, q.txId), null, `${label}: no submission claim exists`);
    assert.equal(await X_.receiptOf(x, q.txId), null, `${label}: no receipt exists`);
    assert.equal((await X_.rootRec(x)).pendingRequestId, null, `${label}: the root's reservation is released`);
    return q;
  }

  /*
   * THE DEMONSTRATION (contract-03 §7 B1-01 / B1-02; the owner's direction). `rec` is the SIGNED B whose
   * `spent` input (role, outpoint) was spent by another transaction accepted on the chain at least 21 chain blocks
   * before this call. Returns { anchor, refused }.
   */
  async function demonstrate(x, rec, { role, outpoint, existence, tag, freeze = true, afterRefused = null }) {
    const id = rec.id;
    /* Submit: refused 409, nothing written */
    await writesNothing(x, `${tag}: Submit`, () => submit(x, id), (sub) => assertSubmitRead(sub, { code: "RECORDED_OUTPUT_SPENT", finding: "CONFLICTING_SPEND", role, outpoint, withdrawal: "TWO_STEP", existence }, `${tag}: Submit`));
    assert.equal(x.node.state.broadcasts.filter((t) => t === lower(rec.txId)).length, 0, `${tag}: X was never broadcast`);
    assert.equal((await x.rootReq(id)).state, "SIGNED", `${tag}: B stays SIGNED`);
    /* Verify: CONSISTENT, writing nothing; the root stays held */
    await writesNothing(x, `${tag}: Verify`, () => verify(x), (r0) => assert.equal(r0.root.status, "CONSISTENT", `${tag}: Verify answers CONSISTENT (${r0.root.status} ${r0.root.reason ?? ""})`));
    const heldFuel = seededFuel(x, `${tag}-held-fee`);
    await writesNothing(x, `${tag}: a root FREEZE while B holds the root`, () => build(x, rootOnlyBody("freeze", heldFuel)), (held) => assert.equal(held.code, "ROOT_PENDING_REQUEST", `${tag}: the hold before the withdrawal (${said2(held)})`));
    /* Withdraw step 1: 409 pending; only the anchor is written */
    const before1 = await x.snap();
    x.chain.sync();
    const anchorHash = x.chain.ancestor(20).hash; // the sink is stable within this call's reads (no virtual move)
    const s1 = await withdraw(x, id);
    const q1 = await x.rootReq(id);
    const m = assertAnchor(q1, x.chain, { label: `${tag}: step 1`, expectHash: anchorHash });
    assertPending(s1, `${tag}: step 1`, { anchorDaa: m.anchor.daaScore });
    await onlyFieldsChanged(x, before1, id, ["inputSpentObservation"], `${tag}: step 1 writes only the anchor`);
    const A1 = BigInt(m.anchor.daaScore);
    assert.ok(A1 < v(x), `${tag}: the anchor lies below the virtual`);
    /* at +999 from the anchor's header DAA: pending, nothing written */
    x.chain.advance(A1 + 999n - v(x));
    await writesNothing(x, `${tag}: step 2 at +999`, () => withdraw(x, id), (s2a) => assertPending(s2a, `${tag}: step 2 at +999`, { anchorDaa: A1 }));
    /* at +1,000: REFUSED, the reservation released */
    x.chain.advance(A1 + 1000n - v(x));
    const before2 = await x.snap();
    const s2 = await withdraw(x, id);
    assert.equal(s2.status, 200, `${tag}: step 2 at +1,000 withdraws B (${said2(s2)})`);
    assert.equal(s2.body.request.state, "REFUSED");
    const refused = await assertWithdrawn(x, id, `${tag}: after step 2`);
    await onlyFieldsChanged(x, before2, id, ["state", "error", "inputSpentWithdrawal", "pendingRequestId"], `${tag}: step 2 writes only B and the root's pointer`);
    if (afterRefused) await afterRefused(refused);
    /* the hold is removed: a root FREEZE builds, signs, finalizes, submits and is CHAIN_VERIFIED */
    if (freeze) await ops.rootFreeze(x, `${tag}-fz`);
    return { anchor: m.anchor, refused };
  }
  return {
    ...X_, X_, ctx, fresh, v,
    buildAnchor, markerInput, seededFuel, createdFuel, rootOnlyBody, vaultOpBody, previousAction, autoFuelBody, staleA, onNode, build, sign, finalize, submit, withdraw, verify, slotsFor, hostedOp, ops, finalizedB,
    inputOf,
    writesNothing, onlyFieldsChanged, assertSubmitRead, assertCannotReject, assertPending, assertAnchor, assertWithdrawn, demonstrate, said2
  };
}

/*
 * The SUCCESSION scenario (contract-03 §7 B1-02b): a self-hosted JSON template holding ONE organizational root (owners
 * 0x71 / 0x72 / 0x73, 2-of-3, emergency quorum 1) that pins a successor key (TEST key 0x5c, succession delay 600 DAA),
 * CHAIN_VERIFIED against the explicit mock chain; fresh HOSTED cases on the B1 mock chain with the owners and the
 * successor signed in.
 */
function b1SuccessionScenario(prefix) {
  const S0 = KK.kasSuite(prefix);
  const ctx = { w: null, rootId: null, successor: null };
  async function setup() {
    await S0.setup(async (template, node) => {
      const w = KK.kasWallets(template);
      ctx.w = w;
      ctx.successor = KK.walletOf(template, 0x5c);
      const restore = KK.useAnchorDaa(0n);
      try {
        const wr7 = KK.lazy.wr7;
        const funding = KK.p2pkUtxo(w.o1, `${prefix}-root-funding`, 20n);
        node.seedP2pk(w.o1, funding.outpoint, funding.amount);
        const req = await wr7.buildRootGenesisRequest({
          config: template, label: `RC45 ${prefix} TEST root`,
          owners: [{ slot: 1, publicKey: w.o1.xonly }, { slot: 2, publicKey: w.o2.xonly }, { slot: 3, publicKey: w.o3.xonly }],
          ownerM: 2, emergencyK: 1, recoveryM: 1, recoveryDelayDaa: "600", successionDelayDaa: "600", successorAddress: ctx.successor.address,
          rootValueKas: "2", rootMaxFeePerTxKas: "0.01", signerAddress: w.o1.address, funding: [funding]
        });
        const signed = await wr7.submitOrgRootRequestSignature({ config: template, requestId: req.id, signedSafeJson: KK.signInputs(template, req.transaction.unsignedSafeJson, req.transaction.signInputs, w.o1) });
        node.expectFrozen(signed.build.frozen, signed.txId);
        const done = await wr7.submitOrgRootRequest({ config: template, requestId: req.id, rpc: node.rpc, pollAttempts: 1, pollDelayMs: 0 });
        assert.equal(done.state, "CHAIN_VERIFIED", `template root genesis: ${done.error ?? ""}`);
        ctx.rootId = req.rootCovenantId;
      } finally { restore(); }
    });
  }
  async function fresh(backend) {
    const x = await S0.fresh(backend, ctx.w, { stampAcceptingDaa: true });
    const old = String(BigInt(x.node.state.daa) - TEMPLATE_AGE);
    for (const entries of x.node.table().values()) for (const e of entries) if (e.daaStamp === undefined) x.node.mutateEntry(e.outpoint, { daaStamp: old });
    x.chain = b1Chain(x);
    x.cookie.successor = await x.api.signIn(ctx.successor);
    return x;
  }
  return { S: S0, ctx, setup, fresh, teardown: () => S0.teardown(), release: (x) => S0.release(x) };
}

module.exports = { KK, SC, b1Scenario, b1SuccessionScenario, DEPTH, MAX_AGE, OWNER_SENTENCE, HOLD_CLAUSE, SCHEMAS, TEMPLATE_AGE, lower, sameOp };
