"use strict";
/*
 * RC45 F7 test support: RC44-written record shapes for request-scoped recovery
 * (fix item F7 RC45-RV-SRR-01; plan rc45-simplified-plan-r2 §2.6, §8 T6 and
 * the §8.1 journal pins, CR-M13), from the pinned df5b8de writers. Internal
 * RED-first regression material for the RC45 candidate; not an audit.
 *
 * The parent (a candidate test) never loads an RC44 module. It verifies the
 * read-only extraction named by POLICYVAULT_TEST_RC44_TREE against the plan's
 * five writer sha256 pins and the df5b8de sdk/src git tree (a missing or
 * mismatched tree FAILS, never skips), builds the same test-local overlay as
 * sdk/testutil/rc45-rc44-history.js (reused unchanged), and runs THIS file as
 * a child that loads ONLY the overlay's RC44 modules and writes a JSON data
 * root; the parent reads it through the candidate store. Node observations in
 * the child come only from the explicit chain model of
 * sdk/testutil/rc45-f5-kit.js (reused unchanged); every config names
 * ws://127.0.0.1:1, so nothing can dial a node. TEST keys only.
 *
 * Scenarios:
 *   t6       the RV-SRR-01 shapes (review rc44-patch-independent-01 SR-A..SR-D)
 *            and closed labels, all written by the RC44 writers:
 *            sra  SR-A: an agent spend finalized, then REJECTED by the RC44
 *                 submit against the model's mempool-conflict wire text; the
 *                 rejection is an ESTABLISHED bound negative (claims and
 *                 reservation released); the vault is not advanced.
 *            srb  SR-B: the same established rejection, then an owner Pause
 *                 completed by RC44 at zero depth (its own claim retained on
 *                 the old predecessor); a delegate spend built before the
 *                 Pause and finalized after it is closed STALE by RC44.
 *            src  SR-C / SR-D: two agent spends completed by RC44 at zero
 *                 depth in sequence (c1 the older, c2 the latest
 *                 CHAIN_VERIFIED transition), claims retained by RC44.
 *            sag  an agent spend finalized, then age-released by RC44 Verify
 *                 case C (claims and reservation released; the record stays
 *                 PREFLIGHT_VERIFIED on the live outpoint).
 *            scl  closed labels written by RC44 finalize / reject:
 *                 WALLET_REJECTED (reject of a BUILT request),
 *                 SIGNATURE_INVALID (signed Safe JSON that is not JSON),
 *                 a spend signed by the wrong TEST key (RC44 closes it
 *                 PREFLIGHT_FAILED or SIGNATURE_INVALID; the label is
 *                 reported), CLAIM_CONFLICT (finalize against a SYNTHETIC
 *                 orphan claim written with RC44's own claim writer on the
 *                 live outpoint), and one request left BUILT.
 *   journal  the protection journal of RC44 request-scoped recovery: the
 *            candidate fixture snapshot passed in a file is installed with the
 *            RC44 store, and RC44 reconcileTransitionWalletRequestV4 runs with
 *            the recorded outpoint live (PROTECTED_UNRESOLVED: the record
 *            becomes RECONCILIATION_REQUIRED with a PROTECTED journal and its
 *            claims re-created) — the historical shape RC45 never writes.
 */
const path = require("node:path"), fs = require("node:fs");
const assert = require("node:assert/strict");
const H44 = require("./rc45-rc44-history");
const K = require("./rc45-f5-kit");
const { KAS, LOOPBACK, clone } = H44;

const RESULT_TAG = "RC45-F7-RC44-WRITER-RESULT ";
/* RC44-written vaults (tags distinct from every candidate-written vault of the F7 suites). */
const F7_RC44_VAULTS = Object.freeze({ sra: K.vault("f7-r44-sra"), srb: K.vault("f7-r44-srb"), src: K.vault("f7-r44-src"), sag: K.vault("f7-r44-sag"), scl: K.vault("f7-r44-scl") });

const pick = (r) => ({ requestId: r.requestId, txId: r.txId, state: r.state, action: r.action, predecessorOutpoint: r.predecessorOutpoint, covenantId: r.covenantId });

function toolsFor(m, config, tree) {
  const w = K.walletsFor(config), k = K.kitFor(m, config, w);
  const sc = require(path.join(tree, "sdk", "src", "submission-classification.js"));
  const expectState = (r, s) => { assert.equal(r.state, s, `${r.action} ${r.requestId} is ${r.state}, expected ${s}`); return r; };
  const fin = async (r, signer) => expectState(await k.finalize(r, signer), "PREFLIGHT_VERIFIED");
  const submit = (r, model) => m.submit4.submitWalletRequestV4({ config, requestId: r.requestId, rpc: model.rpc, pollAttempts: 1, pollDelayMs: 0 });
  // RC44 submit REJECTED branch: an out-of-app spend of L waits in the mempool; the node answers the rusty-kaspa wire text.
  const rejectEstablished = async (r, tag) => {
    const model = K.chainModel(config); model.know(r); model.seedInputs(r.finalTransaction, r.covenantId);
    model.mempoolAdd(K.hex(`rc45-f7-${tag}-out-of-app-spend`), [r.predecessorOutpoint]);
    await assert.rejects(submit(r, model), (e) => e.code === "SUBMISSION_REJECTED", "RC44 classifies the mempool conflict as a rejection");
    const q = expectState(await m.wr4.loadRequest(config, r.requestId), "SUBMISSION_REJECTED");
    assert.equal(sc.recordedNegativeIsEstablished(q), true, "RC44 recorded an ESTABLISHED bound negative");
    const s = m.store.getStore(config);
    assert.equal(await s.read(m.store.Categories.TRANSITION_CLAIM, m.claims.transitionClaimKey(q.predecessorOutpoint)), null, "RC44 released the transition claim");
    assert.equal(await s.read(m.store.Categories.SUBMISSION_CLAIM, q.txId), null, "RC44 released the submission claim");
    return q;
  };
  // RC44 submit: accepted and observed at zero depth -> CHAIN_VERIFIED (the RC44 standard; RC44 retains its own claim).
  const submitObserved = async (r) => {
    const model = K.chainModel(config); model.know(r); model.seedInputs(r.finalTransaction, r.covenantId); model.confirmOnSubmit = true;
    return expectState((await submit(r, model)).request, "CHAIN_VERIFIED");
  };
  // RC44 case C: live predecessor + effect absent + claim age >= minimum -> releases the claims and reservation.
  const ageRelease = async (v, r) => {
    const model = K.chainModel(config); model.seedInputs(r.finalTransaction, r.covenantId);
    const status = await m.reconcile4.reconcileVaultV4(config, v.vaultId, { rpc: model.rpc, stalePendingMinimumMs: 0 });
    assert.equal(status.status, "CLAIM_RELEASED"); assert.equal(status.claimTxId, r.txId);
  };
  return { w, k, sc, fin, expectState, rejectEstablished, submitObserved, ageRelease };
}

const SCENARIOS = {
  async t6(m, config, _input, tree) {
    const { w, k, fin, expectState, rejectEstablished, submitObserved, ageRelease } = toolsFor(m, config, tree), V = F7_RC44_VAULTS, hist = {};
    const C = m.store.Categories, s = m.store.getStore(config);
    { const v = V.sra; await K.seedVault(m, config, v, w, { label: "RC45 F7 RC44" });
      const a = await rejectEstablished(await fin(await k.agentSpend(v, 4), w.agent), "sra");
      hist.sra = { a: pick(a) };
    }
    { const v = V.srb; await K.seedVault(m, config, v, w, { label: "RC45 F7 RC44" });
      const a = await rejectEstablished(await fin(await k.agentSpend(v, 4), w.agent), "srb");
      const x = expectState(await k.agentSpend(v, 2), "BUILT");
      const p = await submitObserved(await fin(await k.ownerOp(v, "ownerPause"), w.owner));
      const mf = await s.read(C.VAULT, v.vaultId);
      assert.equal(mf.status, "PAUSED"); assert.equal(mf.latestTransitionTxId, p.txId);
      assert.equal((await s.read(C.TRANSITION_CLAIM, m.claims.transitionClaimKey(a.predecessorOutpoint))).txId, p.txId, "RC44 retained the Pause's own claim on the old predecessor");
      await assert.rejects(k.finalize(x, w.agent), (e) => e.code === "STALE", "RC44 finalize closes the pre-Pause spend STALE");
      const stale = expectState(await m.wr4.loadRequest(config, x.requestId), "STALE");
      hist.srb = { a: pick(a), p: pick(p), stale: pick(stale) };
    }
    { const v = V.src; await K.seedVault(m, config, v, w, { label: "RC45 F7 RC44" });
      const c1 = await submitObserved(await fin(await k.agentSpend(v, 3), w.agent));
      const c2 = await submitObserved(await fin(await k.agentSpend(v, 2), w.agent));
      const mf = await s.read(C.VAULT, v.vaultId);
      assert.equal(mf.latestTransitionTxId, c2.txId); assert.equal(mf.live.outpoint.transactionId, c2.txId);
      hist.src = { c1: pick(c1), c2: pick(c2) };
    }
    { const v = V.sag; await K.seedVault(m, config, v, w, { label: "RC45 F7 RC44" });
      const a = await fin(await k.agentSpend(v, 4), w.agent);
      await ageRelease(v, a);
      const aged = expectState(await m.wr4.loadRequest(config, a.requestId), "PREFLIGHT_VERIFIED");
      assert.equal(await s.read(C.TRANSITION_CLAIM, m.claims.transitionClaimKey(aged.predecessorOutpoint)), null, "RC44 case C released the claim by age");
      hist.sag = { a: pick(aged) };
    }
    { const v = V.scl; await K.seedVault(m, config, v, w, { label: "RC45 F7 RC44" });
      const b = [];
      for (const kas of [1n, 2n, 3n, 4n]) b.push(expectState(await k.agentSpendSompi(v, kas * KAS), "BUILT"));
      const built = expectState(await k.agentSpendSompi(v, 3n * KAS / 2n), "BUILT");
      await m.wr4.markWalletRejected(config, b[0].requestId);
      const rejected = expectState(await m.wr4.loadRequest(config, b[0].requestId), "WALLET_REJECTED");
      await assert.rejects(m.wr4.finalizeWalletRequestV4({ config, requestId: b[1].requestId, signedSafeJson: "TEST: not a signed Safe JSON" }), (e) => e.code === "SIGNATURE_INVALID");
      const invalid = expectState(await m.wr4.loadRequest(config, b[1].requestId), "SIGNATURE_INVALID");
      await assert.rejects(k.finalize(b[2], w.owner), (e) => ["PREFLIGHT_FAILED", "SIGNATURE_INVALID"].includes(e.code), "a spend signed by the wrong TEST key is closed");
      const wrongKey = await m.wr4.loadRequest(config, b[2].requestId);
      assert.ok(["PREFLIGHT_FAILED", "SIGNATURE_INVALID"].includes(wrongKey.state), `wrong-key close label ${wrongKey.state}`);
      // SYNTHETIC orphan claim on the live outpoint (RC44's own claim writer; no request records it).
      const live = (await s.read(C.VAULT, v.vaultId)).live;
      await m.claims.claimTransition(config, { outpoint: live.outpoint, action: "agentSpend", txId: K.hex("rc45-f7-scl-orphan-claim"), vaultId: v.vaultId, stateId: live.stateId, expected: null });
      await assert.rejects(k.finalize(b[3], w.agent), (e) => e.code === "CLAIM_CONFLICT", "RC44 finalize closes CLAIM_CONFLICT against the orphan claim");
      const conflict = expectState(await m.wr4.loadRequest(config, b[3].requestId), "CLAIM_CONFLICT");
      hist.scl = { rejected: pick(rejected), invalid: pick(invalid), wrongKey: pick(wrongKey), conflict: pick(conflict), built: pick(built) };
    }
    return { hist };
  },
  async journal(m, config, input, tree) {
    const snap = JSON.parse(fs.readFileSync(input.snapshotFile, "utf8"));
    await K.install(m, config, snap);
    const r = await m.wr4.loadRequest(config, input.requestId);
    const model = K.chainModel(config); model.seedInputs(r.finalTransaction, r.covenantId); // the recorded outpoint live and deep
    const recovery = require(path.join(tree, "sdk", "src", "wallet-recovery-v4.js"));
    const out = await recovery.reconcileTransitionWalletRequestV4({ config, requestId: r.requestId, rpc: model.rpc });
    assert.equal(out.outcome, "PROTECTED_UNRESOLVED");
    const after = await m.wr4.loadRequest(config, r.requestId);
    assert.equal(after.state, "RECONCILIATION_REQUIRED"); assert.equal(after.transitionRecovery.phase, "PROTECTED");
    const s = m.store.getStore(config);
    assert.ok(await s.read(m.store.Categories.TRANSITION_CLAIM, m.claims.transitionClaimKey(r.predecessorOutpoint)), "RC44 re-created the transition claim");
    return { outcome: out.outcome, state: after.state, phase: after.transitionRecovery.phase };
  }
};

async function rc44Child(input) {
  H44.verifyRc44Tree(input.tree);
  const m = H44.modulesOf(path.join(input.tree, "sdk", "src"));
  const config = m.config.loadConfig({ dataRoot: input.dataRoot, rpcUrl: LOOPBACK });
  assert.equal(config.networkId, "testnet-10");
  const scenario = SCENARIOS[input.scenario];
  assert.equal(typeof scenario, "function", `unknown RC44 scenario ${input.scenario}`);
  return scenario(m, config, input.input ?? {}, input.tree);
}

/* Parent side: verify the tree, build the overlay, run one scenario in a child that loads only the overlay's RC44
 * modules; returns { dataRoot, overlay, result } (all roots test-owned; `track` receives each root). A snapshot
 * input is written to a file in a test-owned root (argument size), never passed on the command line. */
function runF7Rc44Scenario(scenario, { snapshot = null, requestId = null, tree = process.env.POLICYVAULT_TEST_RC44_TREE || "", track = () => {} } = {}) {
  H44.verifyRc44Tree(tree);
  const dataRoot = H44.ownedTempRoot("pv-rc45-f7-rc44-data-"); track(dataRoot);
  const overlayRoot = H44.ownedTempRoot("pv-rc45-f7-rc44-overlay-"); track(overlayRoot);
  const overlay = H44.rc44Overlay(tree, overlayRoot);
  const input = {};
  if (snapshot) {
    const inputRoot = H44.ownedTempRoot("pv-rc45-f7-rc44-input-"); track(inputRoot);
    input.snapshotFile = path.join(inputRoot, "snapshot.json");
    fs.writeFileSync(input.snapshotFile, JSON.stringify(snapshot));
    input.requestId = requestId;
  }
  const env = { ...process.env }; delete env.POLICYVAULT_PV_VM_PREFLIGHT_PATH; delete env.POLICYVAULT_PV_CALL_ENCODER_PATH;
  const child = require("node:child_process").spawnSync(process.execPath, [__filename, JSON.stringify({ tree: overlay, dataRoot, scenario, input })], { encoding: "utf8", timeout: 600000, maxBuffer: 64 * 1024 * 1024, env });
  assert.equal(child.status, 0, `RC44 writer (${scenario}) failed: ${(child.stderr || "").slice(-4000)}`);
  const line = (child.stdout || "").split("\n").find((l) => l.startsWith(RESULT_TAG));
  assert.ok(line, `the RC44 writer (${scenario}) reported its result`);
  return { dataRoot, overlay, result: JSON.parse(line.slice(RESULT_TAG.length)) };
}

if (require.main === module) {
  rc44Child(JSON.parse(process.argv[2])).then(
    (result) => { process.stdout.write(`${RESULT_TAG}${JSON.stringify(result)}\n`); },
    (error) => { process.stderr.write(`${error && error.stack ? error.stack : error}\n`); process.exitCode = 1; }
  );
}

module.exports = { F7_RC44_VAULTS, runF7Rc44Scenario, clone };
