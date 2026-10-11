"use strict";
/*
 * RC45 F5 test support: RC44-written record shapes for the Verify settlement
 * suites (plan rc45-simplified-plan-r2 §8 rules, CR-M13), from the pinned
 * df5b8de writers. Internal RED-first regression material for the RC45
 * candidate; not an audit.
 *
 * The parent (a candidate test) never loads an RC44 module. It verifies the
 * read-only extraction named by POLICYVAULT_TEST_RC44_TREE against the plan's
 * five writer sha256 pins and the df5b8de sdk/src git tree (a missing or
 * mismatched tree FAILS, never skips), builds the same test-local overlay as
 * sdk/testutil/rc45-rc44-history.js (reused unchanged: byte copies of the RC44
 * sdk/src, core and contracts with the pins re-verified on the copy, links to
 * the remaining RC44 directories and dependencies, links to this tree's
 * pv_tx_probe / pv_call_encoder / pv_vm_preflight), and runs THIS file as a
 * child that loads ONLY the overlay's RC44 modules and writes a JSON data
 * root; the parent reads it through the candidate store.
 *
 * Scenarios (all TEST keys, every config ws://127.0.0.1:1, node observations
 * only from the explicit chain model of sdk/testutil/rc45-f5-kit.js):
 *   t3    hop: A (agentSpend 4 KAS) finalized on L0 and age-released by RC44
 *         case C; B (3 KAS) finalized and age-released; T (B's same-txid twin)
 *         finalized, holding the L0 claim; B submitted and completed at zero
 *         depth by RC44 (L0 -> L1). A is a PENDING ancestor record, T a
 *         signed W1-txid twin without CHAIN_VERIFIED.
 *   t5    tuW: B (3 KAS) completed L0 -> L1 by RC44, then RC44 Verify with
 *         nothing indexed wrote case E TERMINATED_UNKNOWN (lastTransition
 *         kept). tuG: RC44 case E on a vault with no lastTransition and no
 *         genesis request.
 *   rc40  the winning owner recovery of v4-foreign-recovery-rc40 (plan §8.1
 *         CR-H2 "RC40 before() :49-54"): the fixture's closed-vault manifest,
 *         an ownerRecover with fuel 54..:1 finalized and submitted by RC44,
 *         completed at zero depth (RECOVERED) with RC44's retained own claim.
 */
const path = require("node:path");
const assert = require("node:assert/strict");
const H44 = require("./rc45-rc44-history");
const K = require("./rc45-f5-kit");
const { KAS, LOOPBACK, clone } = H44;

const RESULT_TAG = "RC45-F5-RC44-WRITER-RESULT ";
/* RC44-written vaults (tags are distinct from every candidate-written vault of the F5 suites). */
const F5_RC44_VAULTS = Object.freeze({ hop: K.vault("r44-hop"), tuW: K.vault("r44-tuW"), tuG: K.vault("r44-tuG") });

const pick = (r) => ({ requestId: r.requestId, txId: r.txId, state: r.state, action: r.action, predecessorOutpoint: r.predecessorOutpoint, covenantId: r.covenantId });

function toolsFor(m, config) {
  const w = K.walletsFor(config), k = K.kitFor(m, config, w);
  const expectState = (r, s) => { assert.equal(r.state, s, `${r.action} ${r.requestId} is ${r.state}, expected ${s}`); return r; };
  const fin = async (r, signer) => expectState(await k.finalize(r, signer), "PREFLIGHT_VERIFIED");
  const reconcile = (v, model, extra = {}) => m.reconcile4.reconcileVaultV4(config, v.vaultId, { rpc: model.rpc, ...extra });
  // RC44 case C: live predecessor + effect absent + claim age >= minimum -> releases the claims and reservation.
  const ageRelease = async (v, r) => {
    const model = K.chainModel(config); model.seedInputs(r.finalTransaction, r.covenantId);
    const status = await reconcile(v, model, { stalePendingMinimumMs: 0 });
    assert.equal(status.status, "CLAIM_RELEASED"); assert.equal(status.claimTxId, r.txId);
  };
  // RC44 submit: accepted and observed at zero depth -> CHAIN_VERIFIED (the RC44 standard).
  const submitObserved = async (r) => {
    const model = K.chainModel(config); model.know(r); model.seedInputs(r.finalTransaction, r.covenantId); model.confirmOnSubmit = true;
    const done = await m.submit4.submitWalletRequestV4({ config, requestId: r.requestId, rpc: model.rpc, pollAttempts: 1, pollDelayMs: 0 });
    return expectState(done.request, "CHAIN_VERIFIED");
  };
  const manifest = (v) => m.store.getStore(config).read(m.store.Categories.VAULT, v.vaultId);
  return { w, k, fin, reconcile, ageRelease, submitObserved, manifest, expectState };
}

const SCENARIOS = {
  async t3(m, config) {
    const { w, k, fin, ageRelease, submitObserved, manifest } = toolsFor(m, config), V = F5_RC44_VAULTS, hist = {};
    { const v = V.hop; await K.seedVault(m, config, v, w, { label: "RC45 F5 RC44" });
      const a = await fin(await k.agentSpend(v, 4), w.agent); await ageRelease(v, a);
      const b = await fin(await k.agentSpend(v, 3), w.agent); await ageRelease(v, b);
      const t = await fin(await k.agentSpend(v, 3), w.agent);
      assert.equal(t.txId, b.txId, "the same spend on the same live state freezes the same transaction (twin)");
      const done = await submitObserved(b);
      const mf = await manifest(v);
      assert.equal(mf.latestTransitionTxId, b.txId); assert.equal(mf.live.outpoint.transactionId, b.txId);
      hist.hop = { a: pick(a), b: pick(done), t: pick(await m.wr4.loadRequest(config, t.requestId)) };
    }
    return { hist };
  },
  async t5(m, config) {
    const { w, k, fin, reconcile, submitObserved, manifest } = toolsFor(m, config), V = F5_RC44_VAULTS, hist = {};
    { const v = V.tuW; await K.seedVault(m, config, v, w, { label: "RC45 F5 RC44" });
      const b = await submitObserved(await fin(await k.agentSpend(v, 3), w.agent));
      const status = await reconcile(v, K.chainModel(config)); // nothing indexed: RC44 case E
      assert.equal(status.status, "UNKNOWN");
      const mf = await manifest(v);
      assert.equal(mf.status, "TERMINATED_UNKNOWN"); assert.equal(mf.live, null); assert.equal(mf.lastTransition.txId, b.txId);
      hist.tuW = { b: pick(b) };
    }
    { const v = V.tuG; await K.seedVault(m, config, v, w, { label: "RC45 F5 RC44" });
      const status = await reconcile(v, K.chainModel(config));
      assert.equal(status.status, "UNKNOWN");
      const mf = await manifest(v);
      assert.equal(mf.status, "TERMINATED_UNKNOWN"); assert.equal(mf.lastTransition, null);
      hist.tuG = {};
    }
    return { hist };
  },
  async rc40(m, config, input) {
    const { w } = toolsFor(m, config);
    const manifest = input.manifest;
    await m.store.getStore(config).write(m.store.Categories.VAULT, manifest.vaultId, clone(manifest));
    const fuel = { outpoint: { transactionId: "54".repeat(32), index: 1 }, amount: (100n * KAS).toString(), scriptPublicKeyHex: `20${w.owner.xonly}ac` };
    const request = await m.wr4.buildWalletRequestV4({ config, vaultId: manifest.vaultId, action: "ownerRecover", params: { fuel }, signerAddress: w.owner.address });
    const signed = m.signer.makeDevSigner(config, { secretHex: w.owner.secretHex, expectedAddress: w.owner.address }).signInputs(request.transaction.unsignedSafeJson, request.transaction.signInputs);
    const winning = await m.wr4.finalizeWalletRequestV4({ config, requestId: request.requestId, signedSafeJson: signed });
    assert.equal(winning.state, "PREFLIGHT_VERIFIED");
    const model = K.chainModel(config); model.know(winning); model.seedInputs(winning.finalTransaction, winning.covenantId); model.confirmOnSubmit = true;
    const result = await m.submit4.submitWalletRequestV4({ config, requestId: winning.requestId, rpc: model.rpc, pollAttempts: 1, pollDelayMs: 0 });
    assert.equal(result.request.state, "CHAIN_VERIFIED", "RC44 completes an uncontested owner recovery at zero depth");
    return { requestId: winning.requestId, txId: winning.txId };
  }
};

async function rc44Child(input) {
  H44.verifyRc44Tree(input.tree);
  const m = H44.modulesOf(path.join(input.tree, "sdk", "src"));
  const config = m.config.loadConfig({ dataRoot: input.dataRoot, rpcUrl: LOOPBACK });
  assert.equal(config.networkId, "testnet-10");
  const scenario = SCENARIOS[input.scenario];
  assert.equal(typeof scenario, "function", `unknown RC44 scenario ${input.scenario}`);
  return scenario(m, config, input.input ?? {});
}

/* Parent side: verify the tree, build the overlay, run one scenario in a child that loads only the overlay's RC44
 * modules; returns { dataRoot, overlay, result } (both roots test-owned; `track` receives each root). */
function runF5Rc44Scenario(scenario, { input = {}, tree = process.env.POLICYVAULT_TEST_RC44_TREE || "", track = () => {} } = {}) {
  H44.verifyRc44Tree(tree);
  const dataRoot = H44.ownedTempRoot("pv-rc45-f5-rc44-data-"); track(dataRoot);
  const overlayRoot = H44.ownedTempRoot("pv-rc45-f5-rc44-overlay-"); track(overlayRoot);
  const overlay = H44.rc44Overlay(tree, overlayRoot);
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

module.exports = { F5_RC44_VAULTS, runF5Rc44Scenario };
