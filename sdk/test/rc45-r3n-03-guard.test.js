"use strict";
/*
 * RC45 L2-01 (Narrowed C + guard) — the BUILD-TIME LIVENESS GUARD of a root request, what it does and does not
 * prevent, and the unchanged fresh path. Internal RED-first regression material for the RC45 candidate; not an
 * external engagement of any kind.
 *
 * THE DEFECT (8877dee, G3): a hosted root request is built, recorded and RESERVES the root even when the root output
 * (or the v0.7-kas treasury output) it spends is no longer unspent — e.g. after A was confirmed outside PolicyVault,
 * below the attribution depth. Its orphaned submit then leaves a claim and a reservation C3 cannot release: every
 * hosted action on the root, FREEZE included, is refused ROOT_PENDING_REQUEST.
 *
 * REQUIRED BEHAVIOUR (contract revision 2 §1 D6; the RED list legs named in each title): in buildRootActionRequest,
 * after every existing refusal and before the first write, one connection to the configured synced node and one read
 * per distinct address: every frozen input whose covenant id is the root's or (v0.7-kas operation) the treasury's
 * must appear exactly once at its previous outpoint with equal amount, covenant id and (when reported) script, else
 * 409 RECORDED_OUTPUT_SPENT naming the role and the outpoint, with nothing written; a node that cannot be used refuses
 * with its error, nothing written. It never refuses a live output (stateless), and does not prevent: spends after the
 * read, mempool-only spends, fee and payment-profile inputs. The spent-after-build sub-cases are recorded with their
 * actual answers (GRD-06). The B-1 sub-cases (c)/(d) characterized C3's answer while R3N-B1 was not approved; the owner
 * approved R3N-B1 (the owner's direction), so they are re-pinned to the bound B1 answer
 * (contract rc45-l201-contract-03 §7 B1-01 / B1-02; R3N-B1a-inventory, RENAMES.json): RED until R3N-B1b.
 *
 * Layers and labels as in sdk/test/rc45-r3n-01-attribution.test.js. TEST keys only; nothing dials a node (the
 * unreachable node of GRD-07 is a TEST node client whose connect fails).
 */
const KK = require("../testutil/rc45-r2-kas-kit");
KK.installNode(); // before anything loads server/src/api.js or the v7 request modules
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { test, before, after } = require("node:test");
const SC = require("../testutil/rc45-r3n-scenario");
const { K, KAS, D, said, withAnchor } = KK;
const { DEPTH, STALE, lower, sameOp } = SC;
const DF = require("../testutil/org-root-durable-fixture");
const TOOLCHAIN = DF.toolchainAvailable();
const REPO = path.join(__dirname, "..", "..");

const X_ = SC.scenario("r3n03");
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
async function spentRefusal(x, label, call, role, outpoint) {
  return writesNothing(x, label, async () => {
    const r = await call();
    assert.equal(r.status, 409, `${label} is refused (${said(r)})`);
    assert.equal(r.code, "RECORDED_OUTPUT_SPENT", `${label}: RECORDED_OUTPUT_SPENT (${said(r)})`);
    assert.match(String(r.message), new RegExp(role, "i"), `${label}: names the ${role} input`);
    assert.ok(lower(r.message).includes(`${lower(outpoint.transactionId)}:${Number(outpoint.index)}`), `${label}: names the outpoint ${outpoint.transactionId}:${outpoint.index} (${r.message})`);
    return r;
  });
}
const withdraw = async (x, r) => { const wd = await x.rootReject(ctx.rootId, r.body.request.id); assert.equal(wd.status, 200, `withdrawn (${said(wd)})`); };
/* B: an ownerPause on T2, quorum-signed and finalized, its fee input seeded */
async function finalizedB(x, tag) {
  const b = await X_.vaultOp(x, ctx.T2, "ownerPause", "authorize", tag);
  assert.equal(b.status, 201, `${tag}: B is built (${said(b)})`);
  const id = b.body.request.id;
  await X_.sign(x, id, [1, 2]);
  const fin = await x.rootFinalize(ctx.rootId, id);
  assert.equal(fin.status, 200, `${tag}: B is finalized (${said(fin)})`);
  const q = await x.rootReq(id);
  KK.seedFee(x, q);
  return q;
}

for (const [backend, skip] of [["JSON", undefined], ["PostgreSQL", X_.S.PG_SKIP]]) {
  const leg = (name, fn) => test(`RC45 L2-01 ${backend}: ${name}`, { skip }, async () => { const x = await X_.fresh(backend); try { await fn(x); } finally { await X_.release(x); } });

  leg("GRD-01 the root's recorded output spent (A confirmed outside PolicyVault, below the attribution depth): a root-only FREEZE build and a T2 AUTHORIZE + pause build are refused 409 RECORDED_OUTPUT_SPENT naming the root input and its outpoint, writing nothing (no request, no reservation) [RED on 8877dee]", async (x) => {
    const f = await X_.caseFive(x, "grd01", { depth: 10n });
    await spentRefusal(x, "a root-only FREEZE", () => X_.rootOnly(x, "freeze", "grd01-fz"), "root", f.P);
    await spentRefusal(x, "a T2 AUTHORIZE + pause", () => X_.vaultOp(x, ctx.T2, "ownerPause", "authorize", "grd01-pz2"), "root", f.P);
    assert.equal((await X_.rootRec(x)).pendingRequestId, null, "nothing reserves the root");
  });

  leg("GRD-02 T2's recorded output spent outside PolicyVault (the root's live): a T2 AUTHORIZE + pause build is refused 409 RECORDED_OUTPUT_SPENT naming the treasury input and its outpoint, writing nothing [RED on 8877dee]", async (x) => {
    const t2 = await x.vault(ctx.T2);
    x.node.spendOutpoint(t2.live.outpoint);
    await spentRefusal(x, "a T2 AUTHORIZE + pause", () => X_.vaultOp(x, ctx.T2, "ownerPause", "authorize", "grd02-pz2"), "treasury", t2.live.outpoint);
  });

  leg("GRD-03 an entry that is not exact at the recorded outpoint (the root's value or covenant id or reported script differs; T2's value or covenant id differs): the build is refused 409 RECORDED_OUTPUT_SPENT, writing nothing [RED on 8877dee]", async (x) => {
    const root = await X_.rootRec(x), t2 = await x.vault(ctx.T2);
    const rootE = x.node.entryAt(root.live.outpoint).entry, t2E = x.node.entryAt(t2.live.outpoint).entry;
    const cases = [
      ["the root's value", root.live.outpoint, { amount: rootE.amount + 1n }, "root", (tag) => X_.rootOnly(x, "freeze", tag)],
      ["the root's covenant id", root.live.outpoint, { covenantId: K.hex("rc45-l201-grd03-other-covenant") }, "root", (tag) => X_.rootOnly(x, "freeze", tag)],
      ["the root's reported script", root.live.outpoint, { scriptPublicKey: { version: 0, script: `aa20${"11".repeat(32)}87` } }, "root", (tag) => X_.rootOnly(x, "freeze", tag)],
      ["T2's value", t2.live.outpoint, { amount: t2E.amount + 1n }, "treasury", (tag) => X_.vaultOp(x, ctx.T2, "ownerPause", "authorize", tag)],
      ["T2's covenant id", t2.live.outpoint, { covenantId: K.hex("rc45-l201-grd03-other-covenant-2") }, "treasury", (tag) => X_.vaultOp(x, ctx.T2, "ownerPause", "authorize", tag)]
    ];
    let n = 0;
    for (const [what, outpoint, patch, role, call] of cases) {
      const restore = x.node.mutateEntry(outpoint, patch);
      await spentRefusal(x, `${what} differs`, () => call(`grd03-${++n}`), role, outpoint);
      restore();
    }
  });

  leg("GRD-04 live, exact outputs are admitted: a root-only FREEZE build and a T1 AUTHORIZE + pause (v0.7-kas operation) build both succeed with the guard's read, each withdrawn afterwards [PIN: holds on 8877dee]", async (x) => {
    const a = await X_.rootOnly(x, "freeze", "grd04-fz");
    assert.equal(a.status, 201, `a root-only FREEZE builds (${said(a)})`);
    await withdraw(x, a);
    const b = await X_.vaultOp(x, ctx.T1, "ownerPause", "authorize", "grd04-pz1");
    assert.equal(b.status, 201, `a v0.7-kas operation builds (${said(b)})`);
    await withdraw(x, b);
  });

  leg("GRD-05 below the depth a root build is refused 409 RECORDED_OUTPUT_SPENT writing nothing; after the Verify at depth attributes A, the same build is admitted (built on A's root successor) [RED on 8877dee]", async (x) => {
    const f = await X_.caseFive(x, "grd05", { depth: DEPTH / 2n });
    await spentRefusal(x, "a root FREEZE below the depth", () => X_.rootOnly(x, "freeze", "grd05-fz1"), "root", f.P);
    x.node.state.daa += DEPTH / 2n;
    X_.assertAttributedAdvanced(await X_.verify(x), f);
    const b = await X_.rootOnly(x, "freeze", "grd05-fz2");
    assert.equal(b.status, 201, `admitted after the attribution (${said(b)})`);
    assert.ok(sameOp(b.body.request.manifest.root.outpoint, f.rootOut), "built on A's root successor");
  });

  leg("GRD-06 (a) the root spent by A AFTER B's build (B unsigned AUTHORIZED on P): the attribution Verify at depth settles B SUPERSEDED and clears its reservation [RED on 8877dee]", async (x) => {
    let bId = null;
    const f = await X_.caseFive(x, "grd06a", {
      beforeConfirm: async () => {
        const b = await X_.vaultOp(x, ctx.T2, "ownerPause", "authorize", "grd06a-b");
        assert.equal(b.status, 201, said(b));
        bId = b.body.request.id;
      }
    });
    X_.assertAttributedAdvanced(await X_.verify(x), f);
    X_.assertSupersededBy(await x.rootReq(bId), f, "B");
    assert.equal((await X_.rootRec(x)).pendingRequestId, null);
  });

  leg("GRD-06 (b) T2's output spent by an accepted competing transaction AFTER B's submit start: B's submit is answered orphan (RECONCILIATION_REQUIRED) and the next Verify proves SUPERSEDED and answers CLAIM_RELEASED — B's claims and reservation released [PIN: holds on 8877dee]", async (x) => {
    const t2 = await x.vault(ctx.T2);
    const q = await finalizedB(x, "grd06b-b");
    const rpc = KK.outcomeRpc(x, { submitAnswer: "strict", frozen: q.build.frozen, conflict: { outpoint: t2.live.outpoint, payToXOnly: ctx.w.stranger.xonly } });
    const sub = await KK.NODE().with(rpc, () => x.call("POST", ["org-roots", ctx.rootId, "requests", q.id, "submit"], {}, x.cookie.o1));
    assert.equal(sub.code, "RECONCILIATION_REQUIRED", `B's submit (${said(sub)})`);
    const r = await X_.verify(x, { rpc });
    assert.equal(r.root.status, "CLAIM_RELEASED", `the competing spend after submit start is proven (${r.root.status} ${r.root.reason ?? ""})`);
    assert.equal(r.root.outcome, "SUPERSEDED");
    assert.equal((await x.rootReq(q.id)).state, "SUPERSEDED");
    assert.equal(await X_.transitionClaim(x, q.manifest.root.outpoint), null, "B's root claim is released");
    assert.equal(await X_.submissionClaim(x, q.txId), null, "B's submission claim is released");
    assert.equal((await X_.rootRec(x)).pendingRequestId, null, "B's reservation is released");
  });

  /* the bound B1 answer of a spend between B's build and its submit (contract-03 §2 S2 row 5, §7 B1-01 / B1-02): Submit
   * is refused 409 RECORDED_OUTPUT_SPENT naming the spent input, writing nothing and broadcasting nothing; B stays SIGNED,
   * never attempted, holding the root's reservation (the two-step withdrawal that releases it is pinned by B1-01 /
   * B1-02 in sdk/test/rc45-r3n-07-b1-submit.test.js); Verify answers CONSISTENT, writing nothing */
  async function b1SpentAnswer(x, q, rpc, { role, outpoint, label }) {
    const broadcasts0 = x.node.broadcasts();
    const sub = await writesNothing(x, `${label}: B's submit`, () => KK.NODE().with(rpc, () => x.call("POST", ["org-roots", ctx.rootId, "requests", q.id, "submit"], {}, x.cookie.o1)));
    assert.equal(sub.status, 409, `${label}: B's submit is refused 409, never taken to the C3 route (${said(sub)})`);
    assert.equal(sub.code, "RECORDED_OUTPUT_SPENT", `${label}: RECORDED_OUTPUT_SPENT (${said(sub)})`);
    const read = sub.extra && sub.extra.submitRead;
    assert.ok(read && typeof read === "object", `${label}: the answer carries extra.submitRead (${said(sub)})`);
    assert.equal(read.finding, "CONFLICTING_SPEND", `${label}: finding CONFLICTING_SPEND`);
    assert.equal(read.role, role, `${label}: names the ${role} input`);
    assert.ok(sameOp(read.outpoint, outpoint), `${label}: names the outpoint ${outpoint.transactionId}:${outpoint.index}`);
    assert.equal(read.withdrawal, "TWO_STEP", `${label}: the two-step withdrawal is offered`);
    assert.equal(read.existence, "E1", `${label}: existence E1 (the input was accepted long before the build)`);
    assert.equal(x.node.broadcasts(), broadcasts0, `${label}: nothing is broadcast`);
    const after = await x.rootReq(q.id);
    assert.equal(after.state, "SIGNED", `${label}: B stays SIGNED`);
    assert.equal(after.submissionAttempt ?? null, null, `${label}: B carries no attempt`);
    assert.equal(await X_.transitionClaim(x, q.manifest.root.outpoint), null, `${label}: no root claim is taken`);
    assert.equal(await X_.submissionClaim(x, q.txId), null, `${label}: no submission claim is taken`);
    assert.equal((await X_.rootRec(x)).pendingRequestId, q.id, `${label}: B keeps the reservation until it is withdrawn`);
    const r = await writesNothing(x, `${label}: Verify`, () => X_.verify(x, { rpc }));
    assert.equal(r.root.status, "CONSISTENT", `${label}: Verify answers CONSISTENT (${r.root.status} ${r.root.reason ?? ""})`);
  }

  leg("GRD-06 (c) T2's output, accepted long before the build, spent BETWEEN B's build and its submit start (the competing spend precedes the start hash): with R3N-B1 (contract-03 B1-01) B's submit is refused 409 RECORDED_OUTPUT_SPENT (CONFLICTING_SPEND, TWO_STEP, E1) naming the treasury input, writing and broadcasting nothing; B stays SIGNED with no claim and keeps the reservation; Verify answers CONSISTENT; a root FREEZE build is refused ROOT_PENDING_REQUEST until B is withdrawn in two steps (B1-01) [RED on 69ff7bc]", async (x) => {
    const t2 = await x.vault(ctx.T2);
    /* R3N-B1a inventory: T2's output carries the accepting DAA a real node reports for it (accepted long before the
     * build; the kit answers an unstamped template entry's read-time DAA) */
    x.node.mutateEntry(t2.live.outpoint, { daaStamp: String(x.node.state.daa - 100000n) });
    const q = await finalizedB(x, "grd06c-b");
    x.node.spendOutpoint(t2.live.outpoint);
    const rpc = KK.outcomeRpc(x, { submitAnswer: "strict", frozen: q.build.frozen });
    await b1SpentAnswer(x, q, rpc, { role: "treasury", outpoint: t2.live.outpoint, label: "GRD-06 (c)" });
    const fz = await X_.rootOnly(x, "freeze", "grd06c-fz");
    assert.equal(fz.code, "ROOT_PENDING_REQUEST", `the hold until B is withdrawn (${said(fz)})`);
  });

  leg("GRD-06 (d) B's fee input, accepted long before the build, spent between its build and its submit start: with R3N-B1 (contract-03 B1-02) B's submit is refused 409 RECORDED_OUTPUT_SPENT (CONFLICTING_SPEND, TWO_STEP, E1) naming the fee input, writing and broadcasting nothing; B stays SIGNED with no claim and keeps the reservation; Verify answers CONSISTENT (the two-step withdrawal: B1-02) [RED on 69ff7bc]", async (x) => {
    const q = await finalizedB(x, "grd06d-b");
    const feeIn = q.build.frozen.inputs[q.build.frozen.inputs.length - 1].previousOutpoint;
    x.node.spendOutpoint(feeIn);
    const rpc = KK.outcomeRpc(x, { submitAnswer: "strict", frozen: q.build.frozen });
    await b1SpentAnswer(x, q, rpc, { role: "fee", outpoint: feeIn, label: "GRD-06 (d)" });
  });

  leg("GRD-07 a node that cannot be used at build time (the connection is refused; or the UTXO read fails): the root build is refused with the node's error (its message carried, never answered as RECORDED_OUTPUT_SPENT or as a success), writing nothing [RED on 8877dee]", async (x) => {
    /* the node's own error reaches the client: its message is carried (a wrapper may add a code or a prefix); a node
     * that cannot be read is never reported as a spent output */
    const nodeError = (r, label, text) => {
      assert.notEqual(r.status, 201, `${label}: refused without a usable node (${said(r)})`);
      assert.ok(r.status >= 400, `${label}: an error status (${said(r)})`);
      assert.notEqual(r.code, "RECORDED_OUTPUT_SPENT", `${label}: an unusable node is not a spent output (${said(r)})`);
      assert.ok(String(r.message).includes(text), `${label}: the node's error is carried (${said(r)})`);
    };
    const CONNECT = "TEST node refused the connection (ECONNREFUSED 127.0.0.1:1)", READ = "TEST node: the read failed (connection reset)";
    await writesNothing(x, "a refused node connection", async () => {
      const r = await KK.R.withNodeClient(x.config, { connectError: CONNECT }, () => x.rootBuild(ctx.rootId, X_.rootOnlyBody("freeze", "grd07-fz1"), x.cookie.o1));
      nodeError(r, "a refused node connection", "ECONNREFUSED");
    });
    await writesNothing(x, "a failing UTXO read", async () => {
      const r = await X_.rootOnly(x, "freeze", "grd07-fz2", { rpc: X_.faultyRpc(x.node.rpc, { method: "getUtxosByAddresses", always: true, message: READ }) });
      nodeError(r, "a failing UTXO read", READ);
    });
  });

  leg("GRD-08 a spend of the root output that sits only in the mempool (the UTXO index still reports the output): the build is admitted [PIN: holds on 8877dee]", async (x) => {
    const root = await X_.rootRec(x);
    const mempoolSpender = { ...x.node.rpc, async getMempoolEntry() { return { transaction: { inputs: [{ previousOutpoint: { ...root.live.outpoint } }] }, isOrphan: false }; }, async getMempoolEntries() { return { mempoolEntries: [{ transaction: { inputs: [{ previousOutpoint: { ...root.live.outpoint } }] } }] }; } };
    const r = await X_.rootOnly(x, "freeze", "grd08-fz", { rpc: mempoolSpender });
    assert.equal(r.status, 201, `admitted (${said(r)})`);
  });

  leg("REG-01 the fresh request path is unchanged: a root FREEZE, UNFREEZE, T1 AUTHORIZE + pause and a fresh T1 delegate-rule change each reach CHAIN_VERIFIED [PIN: holds on 8877dee]", async (x) => {
    await X_.ops.rootFreeze(x, "reg01-fz");
    await X_.ops.unfreeze(x, "reg01-uf");
    await X_.ops.pause(x, ctx.T1, "reg01-pz1");
    await withAnchor(D, async () => {
      await X_.hostedOp(x, X_.vaultOpBody(ctx.T1, "ownerSetAgentRoot", "authorize", "reg01-set", { agents: X_.newRules() }), "reg01 delegate-rule change");
    });
    assert.deepEqual((await x.installed(ctx.T1)).map((e) => e.agentPk).sort(), X_.newRules().map((e) => e.agentPk).sort());
  });
}

test("RC45 L2-01: REG-05 the frozen covenant bytes (v0.7 root 69417514…, v0.7-kas 393f2130…), the migrations tree and schema 011 are byte-identical to C3 [PIN: holds on 8877dee]", () => {
  const sha = (rel) => crypto.createHash("sha256").update(fs.readFileSync(path.join(REPO, rel))).digest("hex");
  assert.equal(sha("contracts/PolicyVault.v0.7-root.sil"), "69417514f90d61b0281ea673e6fb5a5fd858c2bd50e14a4eb9043d5fdf17f8ce");
  assert.equal(sha("contracts/PolicyVault.v0.7-kas.sil"), "393f2130b48d06ba4d5b29ad8846098dd16ae89ebfd658a2df163f0801ac1d8b");
  assert.equal(sha("server/migrations/011_org_roots.sql"), "9b0655f1c6de0eed7d2bd50b93bf81d775bd214ce0d71d522c0c8cb7b9822daf", "schema 011");
  const dir = path.join(REPO, "server", "migrations"), files = fs.readdirSync(dir).sort();
  const listing = files.map((f) => `${f} ${crypto.createHash("sha256").update(fs.readFileSync(path.join(dir, f))).digest("hex")}`).join("\n");
  assert.equal(files.length, 11, "eleven migrations");
  assert.equal(crypto.createHash("sha256").update(listing).digest("hex"), "34f3da18cdd1336904d0e81e60215cbd436552adf1e21657d4549d0833cbc36e", "the migrations tree");
});

test("RC45 L2-01 JSON: GRD-04 (payment profile) a root request carrying a policyvault-0.7-payment vault operation over live outputs is admitted with the guard's read (the guard checks only the root and v0.7-kas treasury inputs) [PIN: holds on 8877dee]", async () => {
  const cfg = DF.freshJsonConfig("pv-l201-grd04p-"); // the shared durable fixture's own temporary data root (as its suites use it)
  const rpc = DF.mockRpc();
  const o = await DF.organization(cfg, rpc);
  const fuelKeyX = o.fuelKey.toPublicKey().toXOnlyPublicKey().toString().toLowerCase();
  const fuel = { outpoint: { transactionId: K.hex("rc45-l201-grd04p-fuel"), index: 0 }, amount: (50n * KAS).toString(), scriptPublicKeyHex: `20${fuelKeyX}ac` };
  require("../testutil/guard-node").seedFixtureFuel(cfg, fuel, { rpc }); // R3N-B1a inventory: the supplied fee UTXO is on the fixture node before the build reads it
  const owner1 = o.owner1.toPublicKey().toAddress(cfg.networkId).toString();
  const req = await KK.NODE().with(rpc, () => KK.lazy.wr7.buildRootActionRequest({ config: cfg, rootCovenantId: o.rootCovenantId, action: "authorize", params: { fuel }, vaultOperations: [{ vaultId: o.vaultId, action: "ownerPause", params: {} }], signerAddress: owner1 }));
  assert.equal(req.state, "AUTHORIZED", "the payment-profile operation is admitted");
  assert.equal(req.vaultOperations[0].profile, "policyvault-0.7-payment");
});
