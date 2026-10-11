"use strict";
/*
 * RC45 L2-01 (Narrowed C + guard) — shared scenario support for the RED-first legs of
 *   sdk/test/rc45-r3n-01-attribution.test.js   attribution, completion, PARTIAL / UNRESOLVED, contradictions, boundaries
 *   sdk/test/rc45-r3n-02-settlement.test.js    settlement of stranded requests, holds and buildability, the hook
 *   sdk/test/rc45-r3n-03-guard.test.js         the build-time liveness guard
 *   sdk/test/rc45-r3n-04-races.test.js         Verify / finalize / submit races
 *   sdk/test/rc45-r3n-05-api.test.js           served routes and summaries
 * Internal RED-first regression material; not an external engagement of any kind.
 *
 * On top of the R2 KAS kit (sdk/testutil/rc45-r2-kas-kit.js, with its opt-ins: accepting-DAA stamps, afterRead,
 * table edits, the promoted out-of-band helpers) it provides:
 *   - scenario(prefix): a self-hosted JSON template holding ONE organizational root (owners 0x71/0x72/0x73, 2-of-3,
 *     emergency quorum 1) and TWO rooted v0.7-kas treasuries T1 and T2 (installed delegates A 0x62 and B 0x66), all
 *     CHAIN_VERIFIED against the explicit mock chain; fresh HOSTED cases (JSON store or a fresh PostgreSQL database)
 *     whose mock node stamps every output it creates with its accepting DAA;
 *   - the case-5 request A (a delegate-rule change on T1 adding delegate N1, signed by the owners, refused at finalize
 *     PERIOD_START_STALE, optionally withdrawn) and its confirmation outside PolicyVault; the PARTIAL variant, in which
 *     a delegate of A pays from T1's new output outside PolicyVault before any Verify;
 *   - Verify (reconcileOrgRootV7 over an explicit node), hosted root operations driven end to end (build inside the
 *     route-level node, owner slot signatures, M-of-N finalize on the real VM, submit), delegate requests;
 *   - a store fault injector modelling a crash after (or at) a chosen durable write: once it fires, every later
 *     mutation fails until restore().
 *
 * Nothing dials a node: every config names ws://127.0.0.1:1 and every node observation comes from an explicit mock.
 * TEST keys only.
 */
const path = require("node:path");
const assert = require("node:assert/strict");
const KK = require("./rc45-r2-kas-kit");
const { K, KAS, D, DAY, said, withAnchor, windowDaa, useAnchorDaa } = KK;

const SDK_SRC = path.join(__dirname, "..", "src");
const sdk = (name) => require(path.join(SDK_SRC, name));
const DEPTH = 1000n; // the attribution depth (DAA) the repair requires
const W_DAY = windowDaa(DAY);
const STALE = D + W_DAY + 1n; // a daily delegate anchored at D is stale here (finalize refuses PERIOD_START_STALE)
const OOB_SCHEMA = "policyvault-oob-attribution/1";
/* The withdrawal text S of the contract (served verbatim by the web surfaces). */
const WITHDRAWAL_TEXT = "Withdrawing marks this request withdrawn in PolicyVault and releases the root's reservation. It does not revoke the owner signatures already given: anyone holding them and the fee-input signature can still broadcast this exact transaction outside PolicyVault while the outputs it spends are unspent. Withdrawing broadcasts nothing.";

function spkAddress(config, spk) {
  return KK.lazy.chain.loadKaspa(config).addressFromScriptPublicKey({ version: spk.version, script: spk.scriptHex }, config.networkId).toString();
}
const lower = (s) => String(s).toLowerCase();
const sameOp = (a, b) => Boolean(a && b) && lower(a.transactionId) === lower(b.transactionId) && Number(a.index) === Number(b.index);

function scenario(prefix) {
  const S = KK.kasSuite(prefix);
  const ctx = { w: null, rootId: null, T1: null, T2: null, A_: null, B_: null };

  async function setup() {
    await S.setup(async (template, node) => {
      const w = KK.kasWallets(template);
      ctx.w = w;
      ctx.A_ = KK.kasDelegate(w.agentA.xonly, [w.recipient.xonly], { periodStartDaa: (D - 5n * DAY).toString(), periodSpent: (3n * KAS).toString() });
      ctx.B_ = KK.kasDelegate(w.agentB.xonly, [w.recipient.xonly], { periodStartDaa: (D - 1000n).toString() });
      const T = await KK.buildRootAndTreasury(template, w, node, { label: `RC45 ${prefix} TEST`, agents: [ctx.A_, ctx.B_], kasVaultId: K.hex(`${prefix}-treasury-1`) });
      ctx.rootId = T.rootId;
      ctx.T1 = T.vaultId;
      /* a SECOND treasury pinned to the same root */
      const restore = useAnchorDaa(0n);
      try {
        const wr7kas = KK.lazy.wr7kas;
        const f = KK.p2pkUtxo(w.o1, `${prefix}-t2-funding`, 200n);
        node.seedP2pk(w.o1, f.outpoint, f.amount);
        const req = await wr7kas.buildKasVaultGenesisRequest({ config: template, rootCovenantId: ctx.rootId, label: `RC45 ${prefix} TEST treasury 2`, agents: [ctx.A_, ctx.B_], approvers: [], approvalM: 0, recoveryAddress: w.recovery.address, depositKas: "100", feeReserveKas: "5", signerAddress: w.o1.address, funding: [f], vaultId: K.hex(`${prefix}-treasury-2`) });
        const signed = await wr7kas.finalizeKasWalletRequest({ config: template, requestId: req.requestId, signedSafeJson: KK.signInputs(template, req.transaction.unsignedSafeJson, req.transaction.signInputs, w.o1) });
        node.expectFrozen(signed.build.frozen, signed.txId);
        const done = await wr7kas.submitKasWalletRequest({ config: template, requestId: req.requestId, rpc: node.rpc, pollAttempts: 1, pollDelayMs: 0 });
        assert.equal(done.state, "CHAIN_VERIFIED", `template treasury 2 genesis: ${done.error ?? ""}`);
        ctx.T2 = req.vaultId;
      } finally { restore(); }
    });
  }

  /* A fresh HOSTED case: the template installed, owners o1..o3 and the installed delegate A signed in, the node
   * stamping every output it creates with its accepting DAA. */
  async function fresh(backend) {
    const x = await S.fresh(backend, ctx.w, { stampAcceptingDaa: true });
    x.cookie.agentA = await x.api.signIn(ctx.w.agentA);
    return x;
  }

  /* ---------------- records ---------------- */
  const eventCount = async (x) => (await x.store.readAudit({ limit: 5000 })).length;
  const eventsFor = async (x, txId) => (await x.store.readAudit({ limit: 5000 })).filter((e) => e && lower(e.txId ?? "") === lower(txId));
  const receiptOf = (x, txId) => x.store.read(KK.lazy.store.Categories.RECEIPT, txId);
  const transitionClaim = (x, outpoint) => require(path.join(SDK_SRC, "submission-claim.js")).loadTransitionClaim(x.config, outpoint);
  const submissionClaim = (x, txId) => x.store.read(KK.lazy.store.Categories.SUBMISSION_CLAIM, txId);
  const rootRec = (x) => x.rootRecord(ctx.rootId);

  /* ---------------- the request's own facts ---------------- */
  const rootOutIdx = (rec) => rec.build.frozen.outputs.findIndex((o) => o.covenant && lower(o.covenant.covenantId) === ctx.rootId);
  const vIdx = (rec) => sdk("rooted-kas-profile-v7.js").vaultSuccessorIndexOf(rec);
  const rootSuccessorOutpoint = (rec) => ({ transactionId: lower(rec.txId), index: rootOutIdx(rec) });
  const vaultSuccessorOutpoint = (rec) => ({ transactionId: lower(rec.txId), index: vIdx(rec) });
  const rootSuccessorAddress = (x, rec) => spkAddress(x.config, rec.build.frozen.outputs[rootOutIdx(rec)].scriptPublicKey);
  const vaultSuccessorAddress = (x, rec) => spkAddress(x.config, rec.build.frozen.outputs[vIdx(rec)].scriptPublicKey);
  const predecessorOf = (rec) => ({ transactionId: lower(rec.manifest.root.outpoint.transactionId), index: Number(rec.manifest.root.outpoint.index) });

  /* ---------------- bodies and route-level calls ---------------- */
  const fuel = (tag) => KK.p2pkUtxo(ctx.w.fee, `${prefix}-${tag}-fee`);
  const rootOnlyBody = (action, tag) => ({ action, params: { fuel: fuel(tag) }, vaultOperations: [], signerAddress: ctx.w.o1.address });
  const vaultOpBody = (vaultId, op, rootAction, tag, params = {}) => ({ action: rootAction, params: { fuel: fuel(tag) }, vaultOperations: [{ vaultId, action: op, params }], signerAddress: ctx.w.o1.address });
  /* every root build runs inside the route-level node (a build-time node read reaches the explicit mock); R3N-B1a
   * inventory: a supplied fee UTXO is on the case's node before the build reads it (kit node.seedFuel) */
  const build = (x, body, { rpc = null, cookie = null } = {}) => {
    if (body && body.params && body.params.fuel) x.node.seedFuel(body.params.fuel);
    return KK.NODE().with(rpc ?? x.node.rpc, () => x.rootBuild(ctx.rootId, body, cookie ?? x.cookie.o1));
  };
  const rootOnly = (x, action, tag, opts) => build(x, rootOnlyBody(action, tag), opts);
  const vaultOp = (x, vaultId, op, rootAction, tag, params = {}, opts) => build(x, vaultOpBody(vaultId, op, rootAction, tag, params), opts);
  const slotsFor = (action) => (action === "freeze" ? [1] : [1, 2]);
  async function sign(x, id, slots) { for (const s of slots) await x.slotSign(ctx.rootId, id, s, ctx.w[`o${s}`], x.cookie[`o${s}`]); }
  /* build -> owner slot signatures -> M-of-N finalize (real VM) -> submit; asserts CHAIN_VERIFIED */
  async function hostedOp(x, body, tag, { slots = null } = {}) {
    const b = await build(x, body);
    assert.equal(b.status, 201, `${tag}: the hosted root request is built (${said(b)})`);
    const id = b.body.request.id;
    await sign(x, id, slots ?? slotsFor(body.action));
    const f = await x.rootFinalize(ctx.rootId, id);
    assert.equal(f.status, 200, `${tag}: finalized on the real VM (${said(f)})`);
    const sub = await x.rootSubmit(ctx.rootId, id);
    assert.equal(sub.status, 200, `${tag}: submitted (${said(sub)})`);
    assert.equal(sub.body.request.state, "CHAIN_VERIFIED", `${tag}: CHAIN_VERIFIED`);
    return x.rootReq(id);
  }
  const ops = {
    rootFreeze: (x, tag) => hostedOp(x, rootOnlyBody("freeze", tag), `${tag} root FREEZE (K)`),
    unfreeze: (x, tag) => hostedOp(x, rootOnlyBody("unfreeze", tag), `${tag} UNFREEZE (M)`),
    emergencyPause: (x, vaultId, tag) => hostedOp(x, vaultOpBody(vaultId, "ownerEmergencyPause", "freeze", tag), `${tag} FREEZE (K) + emergency pause`),
    pause: (x, vaultId, tag) => hostedOp(x, vaultOpBody(vaultId, "ownerPause", "authorize", tag), `${tag} AUTHORIZE + pause`),
    unpause: (x, vaultId, tag) => hostedOp(x, vaultOpBody(vaultId, "ownerUnpause", "authorize", tag), `${tag} AUTHORIZE + unpause`)
  };

  /* ---------------- delegate requests (the installed delegate A on a treasury) ---------------- */
  const delegateBuild = (x, vaultId, { payKas = 1n, fuelUtxo = null } = {}) => x.call("POST", ["wallet", "v7", "requests"], { vaultId, action: "agentSpend", params: { recipient: ctx.w.recipient.xonly, payAmountSompi: (BigInt(payKas) * KAS).toString(), ...(fuelUtxo ? { fuel: fuelUtxo } : {}) }, signerAddress: ctx.w.agentA.address }, x.cookie.agentA);
  const delegateSign = (x, requestId) => x.kasSign(requestId, ctx.w.agentA, x.cookie.agentA);
  const delegateSubmitWith = (x, requestId, rpc) => KK.NODE().with(rpc, () => x.call("POST", ["wallet", "v7", "requests", requestId, "submit"], {}, x.cookie.agentA));

  /* ---------------- the case-5 request A ---------------- */
  const row = (wallet, start, over = {}) => KK.kasDelegate(wallet.xonly, [ctx.w.recipient.xonly], { periodStartDaa: String(start), ...over });
  const newRules = () => [ctx.A_, ctx.B_, row(ctx.w.n1, D)];
  /* A built at D, signed by owners 1 and 2, refused at finalize PERIOD_START_STALE at STALE, withdrawn unless told otherwise */
  async function caseFiveA(x, tag, { withdraw = true } = {}) {
    const { recA } = await KK.staleWithdrawnA(x, { rootId: ctx.rootId, vaultId: ctx.T1, agents: newRules(), tag, buildDaa: D, staleDaa: STALE, withdraw });
    return recA;
  }
  /* A delegate of A pays from T1's new output outside PolicyVault (T1's successor under A's txid is spent). */
  async function spendT1Successor(x, recA, { delegate = null } = {}) {
    const vrec = await x.vault(ctx.T1);
    return KK.outOfAppAgentSpend(x, { template: vrec.template, state: recA.build.successorState, outpoint: vaultSuccessorOutpoint(recA), covenantId: vrec.live.covenantId, registry: recA.newRegistry, delegate: delegate ?? ctx.w.n1, recipient: ctx.w.recipient.xonly, payKas: 1n });
  }
  /* The whole case: A (withdrawn unless told otherwise) confirmed outside PolicyVault at STALE, PARTIAL when a delegate
   * then pays from T1's new output, and the node's DAA set `depth` past the confirmation. Returns A's facts. */
  async function caseFive(x, tag, { withdraw = true, mode = "FULL", depth = DEPTH, beforeConfirm = null } = {}) {
    const recA = await caseFiveA(x, tag, { withdraw });
    if (beforeConfirm) await beforeConfirm(recA);
    return confirmCase(x, recA, { mode, depth });
  }
  /* A (re-read) confirmed outside PolicyVault at the node's current DAA, PARTIAL when told, then the node's DAA set
   * `depth` past the confirmation. */
  async function confirmCase(x, recA0, { mode = "FULL", depth = DEPTH } = {}) {
    const recA = await x.rootReq(recA0.id);
    const P = predecessorOf(recA);
    const at = x.node.state.daa;
    const X = KK.confirmOutOfBand(x, recA);
    let spend = null;
    if (mode === "PARTIAL") spend = await spendT1Successor(x, recA);
    x.node.state.daa = at + BigInt(depth);
    return { recA, A: recA.id, X, P, spend, rootOut: rootSuccessorOutpoint(recA), vaultOut: vaultSuccessorOutpoint(recA), confirmedAt: at };
  }
  /* edit a stored transition claim (store-damage / legacy modelling) */
  async function editTransitionClaim(x, outpoint, fn) {
    const key = require(path.join(SDK_SRC, "submission-claim.js")).transitionClaimKey(outpoint);
    const C = KK.lazy.store.Categories;
    const rec = await x.store.read(C.TRANSITION_CLAIM, key);
    assert.ok(rec, "editTransitionClaim: the claim exists");
    fn(rec);
    await x.store.write(C.TRANSITION_CLAIM, key, rec);
    return rec;
  }
  /* B settled SUPERSEDED by the attribution of A, with its proof */
  function assertSupersededBy(b, f, label = "B") {
    assert.equal(b.state, "SUPERSEDED", `${label} is settled SUPERSEDED (state ${b.state})`);
    assert.equal(b.submissionOutcome?.outcome, "SUPERSEDED", `${label}: the outcome is SUPERSEDED`);
    const p = b.submissionOutcome.proof ?? {};
    assert.equal(p.via, "attribution", `${label}: proven via attribution`);
    assert.equal(lower(p.acceptedConflictingTxId), f.X, `${label}: A's transaction is the accepted conflict`);
    assert.equal(p.attributedRequestId, f.A, `${label}: names A`);
    assert.ok(sameOp(p.spentOutpoint, f.P), `${label}: names the spent root outpoint P`);
    assert.equal(String(p.depthDaa), "1000", `${label}: at depth 1,000`);
  }
  const verify = (x, { rpc = null, ...opts } = {}) => sdk("reconcile-v7.js").reconcileOrgRootV7(x.config, ctx.rootId, { rpc: rpc ?? x.node.rpc, stalePendingMinimumMs: 0, ...opts });
  const verifyRoute = (x, { rpc = null, cookie = null, auth = null } = {}) => KK.NODE().with(rpc ?? x.node.rpc, () => x.call("POST", ["org-roots", ctx.rootId, "reconcile"], {}, auth ?? cookie ?? x.cookie.o1));
  /* Verify, capturing a throw as { thrown } instead of rejecting */
  async function verifySettled(x, opts) { try { return { result: await verify(x, opts) }; } catch (e) { return { thrown: e }; } }

  /* ---------------- shared assertions ---------------- */
  const vaultResult = (r, vaultId) => (r.vaults ?? []).find((v) => v.vaultId === vaultId) ?? null;
  /* `replay`: a discovery replay of a bound marker (addendum a item 5) answers with the attribution fields keyed on the
   * marker — via, mode, A, its txid, holds and buildability; the depth / treasury / settlement lists are checked only for
   * the attributed completion itself. */
  function assertAttributedAdvanced(r, f, { mode = "FULL", depth = "1000", label = "Verify", replay = false } = {}) {
    assert.ok(r && r.root, `${label}: an answer with a root result`);
    assert.equal(r.root.status, "ADVANCED", `${label}: ADVANCED via attribution, not ${r.root.status} (${r.root.reason ?? ""}${r.root.attribution ? ` ${JSON.stringify(r.root.attribution)}` : ""})`);
    assert.equal(r.root.via, "attribution", `${label}: via attribution`);
    assert.equal(r.root.mode, mode, `${label}: mode ${mode}`);
    assert.equal(r.root.requestId, f.A, `${label}: names A`);
    assert.equal(lower(r.root.txId), f.X, `${label}: names A's transaction`);
    if (replay) {
      assert.ok(Array.isArray(r.root.holds) || r.root.holds === null, `${label}: holds are answered (D4b)`);
      assert.ok(r.root.buildable === null || (r.root.buildable && typeof r.root.buildable === "object"), `${label}: buildability is answered (D4b)`);
      return;
    }
    assert.equal(String(r.root.depthDaa), String(depth), `${label}: depth ${depth}`);
    assert.equal(String(r.root.requiredDepthDaa), "1000", `${label}: the required depth`);
    assert.deepEqual(r.root.treasury, { vaultId: ctx.T1, state: mode === "FULL" ? "ADVANCED" : "UNRESOLVED" }, `${label}: the changed treasury`);
    assert.ok(Array.isArray(r.root.settled) && Array.isArray(r.root.unsettled), `${label}: settled and unsettled lists`);
  }
  function assertUnknown(r, label) {
    assert.ok(r && r.root, `${label}: an answer with a root result`);
    assert.equal(r.root.status, "UNKNOWN", `${label}: UNKNOWN (got ${r.root.status} ${r.root.via ?? ""})`);
  }
  /* RED detail of an UNKNOWN attribution answer */
  function assertAttributionOutcome(r, outcome, { requestId, label = "Verify" } = {}) {
    assert.ok(r.root.attribution && typeof r.root.attribution === "object", `${label}: the UNKNOWN answer carries the attribution detail (${JSON.stringify(r.root)})`);
    assert.equal(r.root.attribution.outcome, outcome, `${label}: attribution outcome ${outcome} (${JSON.stringify(r.root.attribution)})`);
    assert.equal(String(r.root.attribution.requiredDepthDaa), "1000", `${label}: the required depth is stated`);
    if (requestId !== undefined) assert.equal(r.root.attribution.requestId, requestId, `${label}: names the request`);
  }
  /* PIN-side check of a C4-only detail: when the answer carries it, it must say `outcome` */
  function ifAttribution(r, outcome, label) {
    if (r && r.root && r.root.attribution) assert.equal(r.root.attribution.outcome, outcome, `${label}: when present, the attribution outcome is ${outcome}`);
  }
  async function assertMarker(x, f, { mode = "FULL", label = "A" } = {}) {
    const a = await x.rootReq(f.A);
    assert.equal(a.state, "CHAIN_VERIFIED", `${label}: A is CHAIN_VERIFIED`);
    const m = a.outOfBandAttribution;
    assert.ok(m && typeof m === "object", `${label}: A carries the attribution marker`);
    assert.equal(m.schema, OOB_SCHEMA);
    assert.equal(m.via, "attribution");
    assert.equal(lower(m.txId), f.X);
    assert.equal(m.requestId, f.A);
    assert.equal(m.mode, mode);
    assert.equal(String(m.requiredDepthDaa), "1000");
    assert.equal(m.treasury && m.treasury.vaultId, ctx.T1);
    if (mode === "PARTIAL") assert.equal(m.treasury.state, "UNRESOLVED", `${label}: the PARTIAL marker records T1 UNRESOLVED`);
    else assert.notEqual(m.treasury.state, "UNRESOLVED", `${label}: a FULL marker never records T1 UNRESOLVED`);
    assert.ok(sameOp(m.treasury.predecessorOutpoint, a.vaultOperations[0].predecessor.outpoint), `${label}: the marker names T1's predecessor`);
    assert.equal(a.finalTransaction, undefined, `${label}: no final transaction was invented`);
    return a;
  }
  /* exactly one completion: one receipt (reconciled), one CHAIN_VERIFIED event for A's txid */
  /* `via`: the event line's via — "attribution" for the attributed completion; a replay may run through the
   * discovery ("reconcile") or Submit ("submit-recovery") entry, so a replay leg passes the accepted list. */
  async function assertCompletedOnce(x, f, label = "A", { via = ["attribution"] } = {}) {
    const receipt = await receiptOf(x, f.X);
    assert.ok(receipt, `${label}: A's receipt exists`);
    assert.equal(receipt.proof && receipt.proof.requestId, f.A, `${label}: the receipt names A`);
    assert.equal(receipt.proof.reconciled, true, `${label}: the receipt is a reconciled one`);
    const verified = (await eventsFor(x, f.X)).filter((e) => e.result === "CHAIN_VERIFIED");
    assert.equal(verified.length, 1, `${label}: exactly one CHAIN_VERIFIED event line for A's txid`);
    assert.ok([].concat(via).includes(verified[0].via), `${label}: the event line's via (${verified[0].via}) is one of ${[].concat(via).join(", ")}`);
    assert.equal(verified[0].actor, "system", `${label}: the event line's actor is the system`);
  }

  /* ---------------- faults ---------------- */
  /* A store fault injector over the case's store object (JSON or PostgreSQL). crashAfter(pred): the matching mutation is
   * performed, then every later mutation fails (a crash right after it); crashAt(pred): the matching mutation fails and
   * so does every later one. pred(op, log) with op = { kind, category, key, value }. restore() removes the wrapper.
   * failures() counts the mutations that actually failed: a crashAfter rule that fired on the LAST write of an operation
   * fails nothing, so that operation ran to completion (interrupted() is false) — the caller must not treat it as a crash. */
  function storeFaults(x) {
    const s = x.store, wrapped = [], log = [], failed = [];
    let rule = null, crashed = false;
    const crashError = (op) => { failed.push(op); return Object.assign(new Error(`TEST crash: the store is unavailable (${op.kind} ${op.category}${op.key ? ` ${op.key}` : ""})`), { code: "TEST_CRASH" }); };
    for (const name of ["write", "createExclusive", "remove", "appendAudit"]) {
      const original = Object.getPrototypeOf(s)[name];
      if (typeof original !== "function") continue;
      wrapped.push(name);
      s[name] = async function faulty(...args) {
        const op = name === "appendAudit" ? { kind: name, category: "EVENT_LOG", key: null, value: args[0] } : { kind: name, category: args[0], key: args[1], value: args[2] };
        if (crashed) throw crashError(op);
        if (rule && rule.at && rule.pred(op, log)) { crashed = true; throw crashError(op); }
        const out = await original.apply(s, args);
        log.push(op);
        if (rule && !rule.at && rule.pred(op, log)) crashed = true;
        return out;
      };
    }
    return {
      crashAfter(pred) { rule = { pred, at: false }; },
      crashAt(pred) { rule = { pred, at: true }; },
      crashed: () => crashed,
      failures: () => failed.length,
      interrupted: () => crashed && failed.length > 0,
      log: () => log.slice(),
      restore() { for (const name of wrapped) delete s[name]; rule = null; crashed = false; }
    };
  }
  /* An rpc whose `method` call throws on the nth call matching pred (the rest pass through). */
  function faultyRpc(base, { method, pred = () => true, nth = 1, always = false, message = "TEST node: the read failed (connection reset)" }) {
    let count = 0;
    const out = { ...base };
    out[method] = async function (...args) {
      if (pred(...args)) { count += 1; if (always ? count >= nth : count === nth) throw new Error(message); }
      return base[method].apply(base, args);
    };
    return out;
  }

  return {
    S, ctx, setup, fresh,
    teardown: () => S.teardown(), release: (x) => S.release(x),
    eventCount, eventsFor, receiptOf, transitionClaim, submissionClaim, rootRec,
    rootOutIdx, vIdx, rootSuccessorOutpoint, vaultSuccessorOutpoint, rootSuccessorAddress, vaultSuccessorAddress, predecessorOf,
    fuel, rootOnlyBody, vaultOpBody, build, rootOnly, vaultOp, slotsFor, sign, hostedOp, ops,
    delegateBuild, delegateSign, delegateSubmitWith,
    row, newRules, caseFiveA, spendT1Successor, caseFive, confirmCase, editTransitionClaim, assertSupersededBy, verify, verifyRoute, verifySettled,
    vaultResult, assertAttributedAdvanced, assertUnknown, assertAttributionOutcome, ifAttribution, assertMarker, assertCompletedOnce,
    storeFaults, faultyRpc
  };
}

module.exports = { KK, DEPTH, STALE, W_DAY, OOB_SCHEMA, WITHDRAWAL_TEXT, spkAddress, sameOp, lower, scenario };
