"use strict";
/*
 * SDK / CRASH-RECOVERY — legacy F4 + RC35-REC-01 parity for the token generations (independent RC35 affected review,
 * 2026-09-11; owner repair directive of the same day).
 *
 * The reviewer's F4: a v0.5 / v0.6 genesis whose broadcast outcome stayed uncertain (or whose completion conflicted) had
 * no automated re-observation — their submit paths required SIGNED and their reconcilers completed transitions only —
 * so existing source / testnet users of these NON-mainnet generations had no recovery route. These regressions drive
 * the REAL v0.5 / v0.6 pipelines (build -> funder signature -> submit -> observation -> create-only completion) and the
 * v0.7-payment-hd pipeline against an in-process mock node (TEST keys; nothing leaves the process): a lost response
 * completes by observation through the SAME request (one broadcast total, identical request / txid / signed bytes,
 * record create-only, receipt, claim released); a persisted false negative is protected and then completed; a historical bare rejection stays unresolved, while an
 * authoritative rejection proof stays negative; recovery of these generations is REFUSED on a mainnet-labelled configuration
 * (they were never mainnet-creatable, so no mainnet state of theirs can exist — nothing is enabled for mainnet).
 * REQUIREMENT_NOT_AVAILABLE (skipped, never silently passed) without silverc / the encoder / pv_tx_probe.
 */
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { loadConfig } = require("../src/config");
const { getStore, Categories } = require("../src/store");
const { covenantAddress } = require("../src/chain");
const wr5 = require("../src/wallet-requests-v5");
const wr6 = require("../src/wallet-requests-v6");
const wr7hd = require("../src/wallet-requests-v7-hd");
const { loadManifestV5 } = require("../src/manifest-v5");
const { loadManifestV6 } = require("../src/manifest-v6");
const { loadManifestV7Hd } = require("../src/manifest-v7-hd");
const { createHarness } = require("./helpers/v7-kas-mock-harness");
const { toolchainSkip, mainnetConfig, tokenFixture, tokenPolicyFor, hdLeafFor, answers, scriptedRpc, persistLegacyNegative } = require("./helpers/rc35-recovery-fixtures");

const { negativeRpc } = require("./helpers/negative-proof-fixtures");

const SKIP = toolchainSkip("pv-f4-probe-");

async function setup(t) {
  const cfg = loadConfig({ dataRoot: fs.mkdtempSync(path.join(os.tmpdir(), "pv-f4-")) });
  const H = createHarness(cfg);
  const c = H.ctx();
  const rpc = H.mockRpc();
  t.after(() => fs.rmSync(cfg.dataRoot, { recursive: true, force: true }));
  const store = getStore(cfg);
  const { descriptor } = tokenFixture(cfg);
  const families = {
    "v0.5": {
      build: () => wr5.buildCreateWalletRequestV5({ config: cfg, label: "ctl", descriptor, templateIndex: 0, initialAgents: [tokenPolicyFor(H, c.agentKey, c.recipientKey)], feeReserveKas: "5", signerAddress: H.ADDR(c.funder), funding: [H.fuelUtxoFor(c.funder)] }),
      sign: (r) => wr5.submitSignatureV5({ config: cfg, requestId: r.requestId, signedSafeJson: H.signAll(r.transaction.unsignedSafeJson, r.transaction.signInputs.map((s) => [s.index, c.funder])) }),
      load: (r) => wr5.loadWalletRequestV5(cfg, r.requestId),
      submit: (r, useRpc, config = cfg) => wr5.submitWalletRequestV5({ config, requestId: r.requestId, rpc: useRpc, pollAttempts: 1, pollDelayMs: 0 }),
      seed: (fin) => { const addr = covenantAddress(cfg, Buffer.from(fin.build.controllerScriptHex, "hex")); rpc.seed(addr, H.utxo(addr, fin.txId, fin.build.controllerOutputIndex, fin.build.frozen.outputs[fin.build.controllerOutputIndex].value, fin.build.covenantId)); },
      manifest: (id) => loadManifestV5(cfg, id),
      receiptAction: "createTokenController",
      generation: "policyvault-0.5"
    },
    "v0.6": {
      build: () => wr6.buildCreateWalletRequestV6({ config: cfg, label: "ctl6", descriptor, templateIndex: 0, initialAgents: [tokenPolicyFor(H, c.agentKey, c.recipientKey)], initialSwapPolicies: [], feeReserveKas: "5", swapPrincipalKas: "0", signerAddress: H.ADDR(c.funder), funding: [H.fuelUtxoFor(c.funder)] }),
      sign: (r) => wr6.submitSignatureV6({ config: cfg, requestId: r.requestId, signedSafeJson: H.signAll(r.transaction.unsignedSafeJson, r.transaction.signInputs.map((s) => [s.index, c.funder])) }),
      load: (r) => wr6.loadWalletRequestV6(cfg, r.requestId),
      submit: (r, useRpc, config = cfg) => wr6.submitWalletRequestV6({ config, requestId: r.requestId, rpc: useRpc, pollAttempts: 1, pollDelayMs: 0 }),
      seed: (fin) => { const addr = covenantAddress(cfg, Buffer.from(fin.build.controllerScriptHex, "hex")); rpc.seed(addr, H.utxo(addr, fin.txId, fin.build.controllerOutputIndex, fin.build.frozen.outputs[fin.build.controllerOutputIndex].value, fin.build.covenantId)); },
      manifest: (id) => loadManifestV6(cfg, id),
      receiptAction: "createTokenController",
      generation: "policyvault-0.6"
    }
  };
  return { cfg, H, c, rpc, store, descriptor, families };
}

for (const family of ["v0.5", "v0.6"]) {
  test(`legacy F4 (${family}): a genesis accepted with a LOST response completes by observation through the SAME request — one broadcast, create-only record, receipt, claim released; a persisted false negative is protected then completed; a bare historical rejection is protected; a proven negative stays; mainnet-labelled recovery is refused (never mainnet-authorized)`, { skip: SKIP }, async (t) => {
    const x = await setup(t);
    const F = x.families[family];
    const r = await F.build();
    const fin = await F.sign(r);
    assert.equal(fin.state, "SIGNED");
    const original = await F.load(r);
    const s = scriptedRpc(x.rpc);
    s.answers.push({ before: () => F.seed(fin), throw: answers.transportLost() });
    await assert.rejects(() => F.submit(r, s.rpc), (e) => e.code === "RECONCILIATION_REQUIRED");
    assert.equal(s.calls, 1);
    assert.equal((await F.load(r)).state, "RECONCILIATION_REQUIRED");
    assert.ok(await x.store.read(Categories.SUBMISSION_CLAIM, fin.txId), "claim held");
    assert.equal(await F.manifest(r.vaultId), null, "no record before proof");
    /* the previously missing route: a repeated submit of an unresolved genesis observes and completes */
    const done = await F.submit(r, s.rpc);
    assert.equal(s.calls, 1, "observed, never rebroadcast");
    assert.equal(done.state, "CHAIN_VERIFIED");
    assert.equal(done.requestId, r.requestId);
    assert.equal(done.txId, original.txId);
    assert.equal((await F.load(r)).signedSafeJson, original.signedSafeJson);
    const manifest = await F.manifest(r.vaultId);
    assert.equal(manifest.creationTxId, fin.txId);
    assert.equal((await x.store.read(Categories.RECEIPT, fin.txId)).action, F.receiptAction);
    assert.equal(await x.store.read(Categories.SUBMISSION_CLAIM, fin.txId), null, "released by chain proof");
    assert.equal((await F.submit(r, s.rpc)).state, "CHAIN_VERIFIED", "idempotent");
    assert.equal(s.calls, 1);
    /* persisted false negative */
    const r2 = await F.build();
    const fin2 = await F.sign(r2);
    await persistLegacyNegative(x.store, Categories.REQUEST, r2.requestId, await F.load(r2), answers.alreadyAccepted(fin2.txId));
    const dark = scriptedRpc(x.H.mockRpc());
    await assert.rejects(() => F.submit(r2, dark.rpc), (e) => e.code === "RECONCILIATION_REQUIRED");
    assert.equal(dark.calls, 0);
    assert.ok(await x.store.read(Categories.SUBMISSION_CLAIM, fin2.txId), "protected: claim re-established");
    F.seed(fin2);
    const s2 = scriptedRpc(x.rpc);
    assert.equal((await F.submit(r2, s2.rpc)).state, "CHAIN_VERIFIED");
    assert.equal(s2.calls, 0);
    assert.equal((await F.manifest(r2.vaultId)).creationTxId, fin2.txId);
    /* A historical bare error has no original acceptance anchor or proof: never release on current absence. */
    const r3 = await F.build();
    const fin3 = await F.sign(r3);
    await persistLegacyNegative(x.store, Categories.REQUEST, r3.requestId, await F.load(r3), answers.nonStandard(fin3.txId));
    await assert.rejects(() => F.submit(r3, s2.rpc), (e) => e.code === "RECONCILIATION_REQUIRED");
    const protected3 = await F.load(r3);
    assert.equal(protected3.state, "RECONCILIATION_REQUIRED");
    assert.equal(protected3.signedSafeJson, fin3.signedSafeJson);
    assert.equal(protected3.txId, fin3.txId);
    assert.equal(protected3.submitStartHash, undefined, "no invented historical acceptance anchor");
    assert.equal(s2.calls, 0);
    assert.ok(await x.store.read(Categories.SUBMISSION_CLAIM, fin3.txId), "weak historical rejection remains protected");
    F.seed(fin3);
    assert.equal((await F.submit(r3, s2.rpc)).state, "CHAIN_VERIFIED", "positive observation still recovers that same original request");
    assert.equal(s2.calls, 0);
    /* A genuine bound rejection requires a saved original anchor, complete acceptance history, exact funding and all-pools mempool absence. */
    const r4 = await F.build();
    const fin4 = await F.sign(r4);
    const s4 = scriptedRpc(x.rpc);
    s4.answers.push({ throw: answers.nonStandard(fin4.txId) });
    const negative4 = negativeRpc(x.cfg, fin4, { baseRpc: s4.rpc, captureAtSubmission: true });
    await assert.rejects(() => F.submit(r4, negative4.rpc), (e) => e.code === "SUBMISSION_REJECTED");
    const rejected4 = await F.load(r4);
    assert.equal(rejected4.submissionOutcome.proof.outputsAbsent, true);
    assert.equal(rejected4.submissionOutcome.proof.completeAcceptanceWindow, true);
    assert.equal(rejected4.submissionOutcome.proof.allInputsUnspent, true);
    assert.equal(rejected4.submissionOutcome.proof.exactMempoolMiss, true);
    assert.equal(rejected4.submissionOutcome.proof.startHash, rejected4.submitStartHash);
    assert.equal((await F.submit(r4, negative4.rpc)).state, "SUBMISSION_REJECTED", "an established proof stays negative on same-request retry");
    assert.equal(s4.calls, 1, "proven rejection retry never rebroadcasts");
    assert.equal(await x.store.read(Categories.SUBMISSION_CLAIM, fin4.txId), null);
    const r5 = await F.build();
    const fin5 = await F.sign(r5);
    const s5 = scriptedRpc(x.rpc);
    s5.answers.push({ before: () => F.seed(fin5), throw: answers.alreadyInMempool(fin5.txId) });
    assert.equal((await F.submit(r5, s5.rpc)).state, "CHAIN_VERIFIED");
    assert.equal(s5.calls, 1);
    /* mainnet-labelled: recovery of a never-mainnet-authorized generation is refused before any read of the node */
    const r6 = await F.build();
    await F.sign(r6);
    const s6 = scriptedRpc(x.rpc);
    s6.answers.push({ throw: answers.transportLost() });
    await assert.rejects(() => F.submit(r6, s6.rpc), (e) => e.code === "RECONCILIATION_REQUIRED");
    const mainnetCfg = mainnetConfig({ dataRoot: x.cfg.dataRoot });
    const s7 = scriptedRpc(x.rpc);
    await assert.rejects(() => F.submit(r6, s7.rpc, mainnetCfg), (e) => e.code === "NETWORK_MISMATCH" && /NOT owner-authorized for mainnet/.test(e.message));
    assert.equal(s7.calls, 0);
    assert.equal((await F.load(r6)).state, "RECONCILIATION_REQUIRED", "the record is untouched by the refusal");
  });
}

test("legacy F4 parity (v0.7-payment-hd): a persisted false negative of an HD genesis is protected then completed by observation; a bare historical rejection is protected; a proven negative stays", { skip: SKIP }, async (t) => {
  const x = await setup(t);
  const root = await x.H.rootGenesis(x.cfg, x.c, x.rpc);
  const build = () => wr7hd.buildHdVaultGenesisRequest({ config: x.cfg, rootCovenantId: root, label: "hd", descriptor: x.descriptor, templateIndex: 0, initialAgents: [hdLeafFor(x.H, x.c.agentKey, x.c.recipientKey)], recoveryAddress: x.H.ADDR(x.c.recoveryKey), feeReserveKas: "5", signerAddress: x.H.ADDR(x.c.funder), funding: [x.H.fuelUtxoFor(x.c.funder)] });
  const sign = (r) => wr7hd.finalizeHdWalletRequest({ config: x.cfg, requestId: r.requestId, signedSafeJson: x.H.signAll(r.transaction.unsignedSafeJson, r.transaction.signInputs.map((s) => [s.index, x.c.funder])) });
  const seed = (fin) => { const addr = covenantAddress(x.cfg, Buffer.from(fin.build.vaultScriptHex, "hex")); x.rpc.seed(addr, x.H.utxo(addr, fin.txId, fin.build.vaultOutputIndex, fin.build.frozen.outputs[fin.build.vaultOutputIndex].value, fin.build.covenantId)); };
  const submit = (r, useRpc) => wr7hd.submitHdWalletRequest({ config: x.cfg, requestId: r.requestId, rpc: useRpc, pollAttempts: 1, pollDelayMs: 0 });
  const r = await build();
  const fin = await sign(r);
  await persistLegacyNegative(x.store, Categories.REQUEST, r.requestId, await wr7hd.loadHdWalletRequest(x.cfg, r.requestId), answers.alreadyAccepted(fin.txId));
  const dark = scriptedRpc(x.H.mockRpc());
  await assert.rejects(() => submit(r, dark.rpc), (e) => e.code === "RECONCILIATION_REQUIRED");
  assert.equal(dark.calls, 0);
  assert.ok(await x.store.read(Categories.SUBMISSION_CLAIM, fin.txId), "protected: claim re-established");
  seed(fin);
  const s = scriptedRpc(x.rpc);
  const done = await submit(r, s.rpc);
  assert.equal(done.state, "CHAIN_VERIFIED");
  assert.equal(s.calls, 0);
  assert.equal((await loadManifestV7Hd(x.cfg, r.vaultId)).creationTxId, fin.txId);
  const r2 = await build();
  const fin2 = await sign(r2);
  await persistLegacyNegative(x.store, Categories.REQUEST, r2.requestId, await wr7hd.loadHdWalletRequest(x.cfg, r2.requestId), answers.nonStandard(fin2.txId));
  await assert.rejects(() => submit(r2, s.rpc), (e) => e.code === "RECONCILIATION_REQUIRED");
  const protected2 = await wr7hd.loadHdWalletRequest(x.cfg, r2.requestId);
  assert.equal(protected2.state, "RECONCILIATION_REQUIRED");
  assert.equal(protected2.signedSafeJson, fin2.signedSafeJson);
  assert.equal(protected2.txId, fin2.txId);
  assert.equal(protected2.submitStartHash, undefined, "no invented historical acceptance anchor");
  assert.equal(s.calls, 0);
  assert.ok(await x.store.read(Categories.SUBMISSION_CLAIM, fin2.txId));
  seed(fin2);
  assert.equal((await submit(r2, s.rpc)).state, "CHAIN_VERIFIED", "positive observation recovers the original weak-negative request");
  assert.equal(s.calls, 0);
  const r3 = await build();
  const fin3 = await sign(r3);
  const s3 = scriptedRpc(x.rpc);
  s3.answers.push({ throw: answers.nonStandard(fin3.txId) });
  const negative3 = negativeRpc(x.cfg, fin3, { baseRpc: s3.rpc, captureAtSubmission: true });
  await assert.rejects(() => submit(r3, negative3.rpc), (e) => e.code === "SUBMISSION_REJECTED");
  const rejected3 = await wr7hd.loadHdWalletRequest(x.cfg, r3.requestId);
  assert.equal(rejected3.submissionOutcome.proof.completeAcceptanceWindow, true);
  assert.equal(rejected3.submissionOutcome.proof.allInputsUnspent, true);
  assert.equal(rejected3.submissionOutcome.proof.exactMempoolMiss, true);
  assert.equal(rejected3.submissionOutcome.proof.startHash, rejected3.submitStartHash);
  assert.equal((await submit(r3, negative3.rpc)).state, "SUBMISSION_REJECTED");
  assert.equal(s3.calls, 1, "same proven-negative request retries observation only");
  assert.equal(await x.store.read(Categories.SUBMISSION_CLAIM, fin3.txId), null);
});
