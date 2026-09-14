"use strict";
/*
 * SDK / CRASH-RECOVERY — RC35-REC-02 + legacy F4 (independent RC35 affected review, 2026-09-11; owner repair directive of
 * the same day).
 *
 * The reviewer's finding (exact-image reproduction root-genesis-recovery.json): an accepted organizational-root genesis
 * whose node response was lost kept its request / signature / txid / claim (RECONCILIATION_REQUIRED) but could not be
 * completed — the same-request submit refused, reconcile answered ROOT_NOT_FOUND, and no root record was ever created
 * although the covenant output existed. Rooted-vault genesis (v0.7-payment) had the same liveness gap (legacy F4).
 *
 * These regressions drive the REAL org-root pipeline (buildRootGenesisRequest -> funder signature -> submit -> observation
 * -> create-only completion) against an in-process mock node (TEST keys; nothing leaves the process). They prove: the
 * SAME request completes by observation after a lost response (no pre-existing root record needed; one broadcast total;
 * root record, receipt and audit created; claim released by proof; identical request id / txid / signed bytes);
 * reconciliation of a missing root routes to the same observation-only completion; a crash between the root record and
 * the request write is replayed idempotently (the root record is never overwritten — byte-identical); repeated
 * observation is idempotent; a root that advanced beyond genesis is preserved (ALREADY_PRESENT by lineage); a DIFFERENT
 * record under the same covenant id is never replaced; recovery keeps working with new root creation disabled (kill
 * switch, mainnet-labelled); a persisted false negative recovers; the rooted-vault (v0.7-payment) genesis recovers the
 * same way. REQUIREMENT_NOT_AVAILABLE (skipped, never silently passed) without silverc / the encoder / pv_tx_probe.
 */
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { loadConfig } = require("../src/config");
const { getStore, Categories } = require("../src/store");
const { covenantAddress } = require("../src/chain");
const wr7 = require("../src/wallet-requests-v7");
const { reconcileOrgRootV7 } = require("../src/reconcile-v7");
const { loadManifestV7 } = require("../src/manifest-v7");
const { readAudit } = require("../src/audit");
const { createHarness } = require("./helpers/v7-kas-mock-harness");
const { toolchainSkip, mainnetConfig, tokenFixture, tokenPolicyFor, answers, scriptedRpc, persistLegacyNegative } = require("./helpers/rc35-recovery-fixtures");

const SKIP = toolchainSkip("pv-rec02-probe-");
const ROOT_V = "policyvault-0.7-root";
const { negativeRpc } = require("./helpers/negative-proof-fixtures");

async function setup(t, cfgOverride = null) {
  const cfg = cfgOverride ?? loadConfig({ dataRoot: fs.mkdtempSync(path.join(os.tmpdir(), "pv-rec02-")) });
  const H = createHarness(cfg);
  const c = H.ctx();
  const rpc = H.mockRpc();
  t.after(() => fs.rmSync(cfg.dataRoot, { recursive: true, force: true }));
  const store = getStore(cfg);
  const buildRoot = (label = "rec02 root") => wr7.buildRootGenesisRequest({
    config: cfg, label,
    owners: [{ slot: 1, publicKey: H.XO(c.owner1) }, { slot: 2, publicKey: H.XO(c.owner2) }, { slot: 3, publicKey: H.XO(c.owner3) }],
    ownerM: 2, emergencyK: 1, recoveryM: 1, recoveryDelayDaa: "600", successionDelayDaa: "600", successorAddress: null,
    rootValueKas: "2", rootMaxFeePerTxKas: "0.01", signerAddress: H.ADDR(c.funder), funding: [H.fuelUtxoFor(c.funder)]
  });
  const sign = (r) => wr7.submitOrgRootRequestSignature({ config: cfg, requestId: r.id, signedSafeJson: H.signAll(r.transaction.unsignedSafeJson, r.transaction.signInputs.map((s) => [s.index, c.funder])) });
  const seedRoot = (r) => { const addr = covenantAddress(cfg, Buffer.from(r.build.rootScriptHex, "hex")); rpc.seed(addr, H.utxo(addr, r.txId, r.build.rootOutputIndex, r.build.accounting.kas.rootValue, r.rootCovenantId)); };
  const submit = (r, useRpc, over = {}) => wr7.submitOrgRootRequest({ config: cfg, requestId: r.id, rpc: useRpc, pollAttempts: 1, pollDelayMs: 0, ...over });
  const load = (r) => wr7.loadOrgRootRequest(cfg, r.id);
  const claim = (r) => store.read(Categories.SUBMISSION_CLAIM, r.txId);
  async function signedRoot(label) { const r = await buildRoot(label); await sign(r); return load(r); }
  /* the reviewer's scenario: the node accepts (the output lands) but the response is lost */
  async function lostResponse(r) {
    const s = scriptedRpc(rpc);
    s.answers.push({ before: () => seedRoot(r), throw: answers.transportLost() });
    await assert.rejects(() => submit(r, s.rpc), (e) => e.code === "RECONCILIATION_REQUIRED");
    assert.equal(s.calls, 1, "exactly one broadcast");
    const pending = await load(r);
    assert.equal(pending.state, "RECONCILIATION_REQUIRED");
    assert.ok(await claim(r), "the claim is held");
    assert.equal(await wr7.loadOrgRoot(cfg, r.rootCovenantId), null, "no root record exists yet");
    return s;
  }
  return { cfg, H, c, rpc, store, buildRoot, sign, seedRoot, submit, load, claim, signedRoot, lostResponse };
}

async function assertRootComplete(x, r, { via } = {}) {
  const root = await wr7.loadOrgRoot(x.cfg, r.rootCovenantId);
  assert.ok(root, "the root record exists");
  assert.equal(root.generation, 0);
  assert.equal(root.live.outpoint.transactionId, r.txId);
  assert.equal(Number(root.live.outpoint.index), Number(r.build.rootOutputIndex));
  assert.equal(root.orgId, r.orgId);
  const receipt = await x.store.read(Categories.RECEIPT, r.txId);
  assert.equal(receipt.action, "rootGenesis");
  assert.equal(receipt.vaultId, r.rootCovenantId);
  const audit = (await readAudit(x.cfg, { vaultId: r.rootCovenantId, txId: r.txId, limit: 100 })).filter((e) => e.action === "rootGenesis" && e.result === "CHAIN_VERIFIED");
  assert.equal(audit.length, 1, "exactly one audit line");
  if (via) assert.equal(audit[0].via, via);
  assert.equal(await x.claim(r), null, "the claim is released by chain proof");
  const after = await x.load(r);
  assert.equal(after.state, "CHAIN_VERIFIED");
  assert.equal(after.chain.successorOutpoint, `${r.txId}:${r.build.rootOutputIndex}`);
  return root;
}

test("REC-02 (the reviewer's case): a root genesis accepted by the node with a LOST response completes by observation through the SAME public submit entry — no root record needed first; one broadcast total; identical request id / txid / signed bytes; root record + receipt + audit created; claim released by proof", { skip: SKIP }, async (t) => {
  const x = await setup(t);
  const r = await x.signedRoot();
  const s = await x.lostResponse(r);
  /* a repeated submit before the output is observed stays truthfully unresolved and never rebroadcasts */
  const dark = scriptedRpc(x.H.mockRpc());
  await assert.rejects(() => x.submit(r, dark.rpc), (e) => e.code === "RECONCILIATION_REQUIRED");
  assert.equal(dark.calls, 0);
  assert.ok(await x.claim(r));
  /* the same request completes by observation */
  const done = await x.submit(r, s.rpc);
  assert.equal(s.calls, 1, "settlement is observed, never rebroadcast");
  assert.equal(done.state, "CHAIN_VERIFIED");
  assert.equal(done.id, r.id);
  assert.equal(done.txId, r.txId);
  assert.equal(done.signedSafeJson, r.signedSafeJson);
  await assertRootComplete(x, r, { via: "org-roots/submit-recovery" });
  /* the recovered root is a working root: reconcile is CONSISTENT and a rooted KAS treasury can be created under it */
  const rec = await reconcileOrgRootV7(x.cfg, r.rootCovenantId, { rpc: x.rpc });
  assert.equal(rec.root.status, "CONSISTENT");
  const { vaultId } = await x.H.kasGenesis(x.cfg, x.c, x.rpc, r.rootCovenantId);
  assert.ok((await wr7.loadOrgRoot(x.cfg, r.rootCovenantId)).vaults.includes(vaultId));
});

test("REC-02: reconciliation of a root with NO record routes to the same observation-only completion — GENESIS_PENDING while unobserved (claim kept), ADVANCED once the covenant output is observed; a covenant id with no genesis request at all stays ROOT_NOT_FOUND", { skip: SKIP }, async (t) => {
  const x = await setup(t);
  const r = await x.signedRoot();
  const dark = x.H.mockRpc();
  const s = scriptedRpc(dark);
  s.answers.push({ throw: answers.transportLost() }); // accepted-or-not unknown; nothing observed on this node view
  await assert.rejects(() => x.submit(r, s.rpc), (e) => e.code === "RECONCILIATION_REQUIRED");
  const pending = await reconcileOrgRootV7(x.cfg, r.rootCovenantId, { rpc: dark });
  assert.equal(pending.root.status, "GENESIS_PENDING", JSON.stringify(pending));
  assert.equal(pending.root.attempts.length, 1);
  assert.equal(pending.root.attempts[0].requestId, r.id);
  assert.ok(await x.claim(r), "the claim is kept");
  assert.equal(await wr7.loadOrgRoot(x.cfg, r.rootCovenantId), null);
  /* now the output is observed on the node */
  x.seedRoot(r);
  const advanced = await reconcileOrgRootV7(x.cfg, r.rootCovenantId, { rpc: x.rpc });
  assert.equal(advanced.root.status, "ADVANCED", JSON.stringify(advanced));
  assert.equal(advanced.root.requestId, r.id);
  assert.equal(s.calls, 1, "nothing was rebroadcast by reconciliation");
  await assertRootComplete(x, r, { via: "org-roots/reconcile" });
  /* a covenant id without any genesis request is still simply not found */
  await assert.rejects(() => reconcileOrgRootV7(x.cfg, "77".repeat(32), { rpc: x.rpc }), (e) => e.code === "ROOT_NOT_FOUND");
});

test("REC-02 (interruption between completion steps): a crash after the root record was created but before the receipt / request were written is replayed idempotently — the root record is NEVER overwritten (byte-identical), receipt and audit are written exactly once, repeated observation is a no-op", { skip: SKIP }, async (t) => {
  const x = await setup(t);
  const r = await x.signedRoot();
  const s = await x.lostResponse(r);
  /* inject the crash: the RECEIPT write (the step right after the create-only root record) fails once */
  const store = x.store;
  const origWrite = store.write.bind(store);
  let tripped = false;
  store.write = async (category, key, value) => {
    if (category === Categories.RECEIPT && key === r.txId && !tripped) { tripped = true; throw new Error("TEST CRASH after the root record was created"); }
    return origWrite(category, key, value);
  };
  try {
    await assert.rejects(() => x.submit(r, s.rpc), /TEST CRASH/);
  } finally {
    store.write = origWrite;
  }
  assert.equal(tripped, true);
  const rootAfterCrash = await wr7.loadOrgRoot(x.cfg, r.rootCovenantId);
  assert.ok(rootAfterCrash, "the root record was created before the crash");
  assert.equal(await x.store.read(Categories.RECEIPT, r.txId), null, "no receipt yet");
  assert.equal((await x.load(r)).state, "RECONCILIATION_REQUIRED", "the request was not advanced");
  assert.ok(await x.claim(r), "the claim is still held");
  /* replay: same request, same observation */
  const done = await x.submit(r, s.rpc);
  assert.equal(done.state, "CHAIN_VERIFIED");
  assert.equal(done.chain.completion.root, "ALREADY_PRESENT", "the existing root record is accepted as this genesis's own — not rewritten");
  assert.deepEqual(await wr7.loadOrgRoot(x.cfg, r.rootCovenantId), rootAfterCrash, "the root record is byte-identical (never overwritten)");
  await assertRootComplete(x, r);
  assert.equal(s.calls, 1);
  /* repeated observation: idempotent, nothing changes, nothing broadcast */
  const snapshot = JSON.stringify(await x.load(r));
  const again = await x.submit(r, s.rpc);
  assert.equal(again.state, "CHAIN_VERIFIED");
  assert.equal(s.calls, 1);
  assert.deepEqual(await wr7.loadOrgRoot(x.cfg, r.rootCovenantId), rootAfterCrash);
  assert.equal(JSON.stringify(await x.load(r)), snapshot, "a complete request is not rewritten");
  assert.equal((await readAudit(x.cfg, { vaultId: r.rootCovenantId, txId: r.txId, limit: 100 })).filter((e) => e.action === "rootGenesis").length, 1);
});

test("REC-02 (never overwrite): an unproven advanced root is preserved and recovery refused despite a genuine genesis receipt; a DIFFERENT record under the same covenant id is never replaced and the genesis stays on its request with its claim", { skip: SKIP }, async (t) => {
  const x = await setup(t);
  /* advanced root */
  const r = await x.signedRoot();
  const s = await x.lostResponse(r);
  await x.submit(r, s.rpc);
  const stored = await wr7.loadOrgRoot(x.cfg, r.rootCovenantId);
  const advanced = { ...stored, generation: 1, live: { ...stored.live, outpoint: { transactionId: "ff".repeat(32), index: 0 } }, updatedAt: new Date().toISOString() };
  await wr7.saveOrgRoot(x.cfg, advanced);
  const stale = await x.load(r);
  stale.state = "RECONCILIATION_REQUIRED"; // a stale label on a request whose completion already happened
  await wr7.saveOrgRootRequest(x.cfg, stale);
  await assert.rejects(() => x.submit(r, s.rpc), (e) => e.code === "RECONCILIATION_REQUIRED");
  assert.ok(await x.claim(r), "the unproven advanced record cannot release the restored own claim");
  const kept = await wr7.loadOrgRoot(x.cfg, r.rootCovenantId);
  assert.equal(kept.generation, 1, "the advanced root is preserved");
  assert.equal(kept.live.outpoint.transactionId, "ff".repeat(32));
  assert.equal(s.calls, 1);
  /* a different record under the same covenant id */
  const r2 = await x.signedRoot("second");
  const s2 = await x.lostResponse(r2);
  const foreign = { ...stored, rootCovenantId: r2.rootCovenantId, orgId: "0d".repeat(32), label: "FOREIGN", updatedAt: new Date().toISOString() };
  await x.store.write(Categories.ORG_ROOT, r2.rootCovenantId, foreign);
  await assert.rejects(() => x.submit(r2, s2.rpc), (e) => e.code === "RECONCILIATION_REQUIRED" && /different durable record/.test(e.message));
  assert.deepEqual(await x.store.read(Categories.ORG_ROOT, r2.rootCovenantId), foreign, "the foreign record is preserved untouched");
  const after = await x.load(r2);
  assert.equal(after.state, "RECONCILIATION_REQUIRED");
  assert.equal(after.txId, r2.txId);
  assert.equal(after.signedSafeJson, r2.signedSafeJson);
  assert.ok(await x.claim(r2), "the claim is held for reconciliation");
  assert.equal(s2.calls, 1);
});

test("REC-02 (creation disabled): recovery of a pending root genesis keeps working with NEW root creation switched off (mainnet-labelled kill switch), while a new root genesis is refused before any durable write", { skip: SKIP }, async (t) => {
  const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "pv-rec02-mainnet-"));
  const cfgOn = mainnetConfig({ dataRoot });
  const x = await setup(t, cfgOn);
  const r = await x.signedRoot();
  const s = await x.lostResponse(r);
  const cfgOff = mainnetConfig({ dataRoot, mainnetCreationDisabled: [ROOT_V] });
  const Hoff = createHarness(cfgOff);
  const rows = (await getStore(cfgOff).listValues(Categories.ORG_ROOT_REQUEST, { strict: true })).length;
  await assert.rejects(() => Hoff.rootGenesis(cfgOff, Hoff.ctx(), x.rpc), (e) => /DISABLED by operator configuration/.test(e.message));
  assert.equal((await getStore(cfgOff).listValues(Categories.ORG_ROOT_REQUEST, { strict: true })).length, rows, "a refused creation writes nothing");
  const done = await wr7.submitOrgRootRequest({ config: cfgOff, requestId: r.id, rpc: s.rpc, pollAttempts: 1, pollDelayMs: 0 });
  assert.equal(done.state, "CHAIN_VERIFIED", "recovery belongs to the OPERABLE set");
  assert.equal(s.calls, 1);
  assert.ok(await wr7.loadOrgRoot(cfgOff, r.rootCovenantId));
});

test("REC-02 + REC-01 (persisted false negative): a root genesis the pre-correction runtime persisted SUBMISSION_REJECTED for an already-accepted answer is protected when unobserved (claim re-established) and completed when observed — no broadcast, no replacement", { skip: SKIP }, async (t) => {
  const x = await setup(t);
  const r = await x.signedRoot();
  await persistLegacyNegative(x.store, Categories.ORG_ROOT_REQUEST, r.id, await x.load(r), answers.alreadyAccepted(r.txId));
  assert.equal(await x.claim(r), null);
  const dark = scriptedRpc(x.H.mockRpc());
  await assert.rejects(() => x.submit(r, dark.rpc), (e) => e.code === "RECONCILIATION_REQUIRED");
  assert.equal(dark.calls, 0);
  const protectedRecord = await x.load(r);
  assert.equal(protectedRecord.state, "RECONCILIATION_REQUIRED");
  assert.match(protectedRecord.error, /already held or accepted/);
  assert.ok(await x.claim(r), "claim re-established");
  x.seedRoot(r);
  const s = scriptedRpc(x.rpc);
  const done = await x.submit(r, s.rpc);
  assert.equal(done.state, "CHAIN_VERIFIED");
  assert.equal(s.calls, 0);
  await assertRootComplete(x, r);
  /* a historical error without authoritative proof remains protected */
  const r2 = await x.signedRoot("negative");
  await persistLegacyNegative(x.store, Categories.ORG_ROOT_REQUEST, r2.id, await x.load(r2), answers.nonStandard(r2.txId));
  await assert.rejects(() => x.submit(r2, s.rpc), (e) => e.code === "RECONCILIATION_REQUIRED");
  assert.equal(s.calls, 0);
  assert.ok(await x.claim(r2));
  assert.equal(await wr7.loadOrgRoot(x.cfg, r2.rootCovenantId), null);
});

test("REC-02 (genuine negative for a root genesis): a bound rejection with complete original-anchor history and exact funding/mempool evidence settles SUBMISSION_REJECTED with proof and releases the claim; an already-in-mempool answer is observed like an accepted response", { skip: SKIP }, async (t) => {
  const x = await setup(t);
  const r = await x.signedRoot();
  const s = scriptedRpc(x.rpc);
  s.answers.push({ throw: answers.nonStandard(r.txId) });
  const negativeNode = negativeRpc(x.cfg, r, { baseRpc: s.rpc, captureAtSubmission: true });
  await assert.rejects(() => x.submit(r, negativeNode.rpc), (e) => e.code === "SUBMISSION_REJECTED");
  const negative = await x.load(r);
  assert.equal(negative.state, "SUBMISSION_REJECTED");
  assert.equal(negative.submissionOutcome.proof.outputsAbsent, true);
  assert.equal(await x.claim(r), null);
  const r2 = await x.signedRoot("mempool");
  const s2 = scriptedRpc(x.rpc);
  s2.answers.push({ before: () => x.seedRoot(r2), throw: answers.alreadyInMempool(r2.txId) });
  const done = await x.submit(r2, s2.rpc);
  assert.equal(done.state, "CHAIN_VERIFIED");
  assert.equal(done.submissionResponse.kind, "ALREADY_KNOWN");
  assert.equal(s2.calls, 1);
  await assertRootComplete(x, r2, { via: "org-roots" });
});

test("legacy F4 (rooted-vault genesis, v0.7-payment): a rooted-vault genesis accepted with a LOST response completes by observation through the same request — vault record (create-only), root membership, receipt, audit, claim released; nothing rebroadcast; a persisted false negative recovers the same way", { skip: SKIP }, async (t) => {
  const x = await setup(t);
  const root = await x.H.rootGenesis(x.cfg, x.c, x.rpc);
  const { descriptor } = tokenFixture(x.cfg);
  const buildVault = () => wr7.buildRootedVaultGenesisRequest({ config: x.cfg, rootCovenantId: root, label: "rooted", descriptor, templateIndex: 0, agents: [tokenPolicyFor(x.H, x.c.agentKey, x.c.recipientKey)], recoveryAddress: x.H.ADDR(x.c.recoveryKey), depositKas: "0", feeReserveKas: "5", signerAddress: x.H.ADDR(x.c.funder), funding: [x.H.fuelUtxoFor(x.c.funder)] });
  const seedVault = (r) => { const addr = covenantAddress(x.cfg, Buffer.from(r.build.vaultScriptHex, "hex")); x.rpc.seed(addr, x.H.utxo(addr, r.txId, r.build.vaultOutputIndex, r.build.frozen.outputs[r.build.vaultOutputIndex].value, r.build.covenantId)); };
  const r = await buildVault();
  await x.sign(r);
  const signed = await x.load(r);
  const vaultId = signed.build.template.vaultId;
  const s = scriptedRpc(x.rpc);
  s.answers.push({ before: () => seedVault(signed), throw: answers.transportLost() });
  await assert.rejects(() => x.submit(signed, s.rpc), (e) => e.code === "RECONCILIATION_REQUIRED");
  assert.equal(s.calls, 1);
  assert.ok(await x.claim(signed));
  assert.equal(await loadManifestV7(x.cfg, vaultId), null);
  const done = await x.submit(signed, s.rpc);
  assert.equal(s.calls, 1, "observed, never rebroadcast");
  assert.equal(done.state, "CHAIN_VERIFIED");
  assert.equal(done.id, signed.id);
  assert.equal(done.txId, signed.txId);
  const manifest = await loadManifestV7(x.cfg, vaultId);
  assert.equal(manifest.creationTxId, signed.txId);
  assert.ok((await wr7.loadOrgRoot(x.cfg, root)).vaults.includes(vaultId));
  assert.equal((await x.store.read(Categories.RECEIPT, signed.txId)).action, "rootedVaultGenesis");
  assert.equal(await x.claim(signed), null);
  /* idempotent */
  assert.equal((await x.submit(signed, s.rpc)).state, "CHAIN_VERIFIED");
  assert.equal(s.calls, 1);
  /* persisted false negative */
  const r2 = await buildVault();
  await x.sign(r2);
  const signed2 = await x.load(r2);
  await persistLegacyNegative(x.store, Categories.ORG_ROOT_REQUEST, signed2.id, signed2, answers.alreadyAccepted(signed2.txId));
  const dark = scriptedRpc(x.H.mockRpc());
  await assert.rejects(() => x.submit(signed2, dark.rpc), (e) => e.code === "RECONCILIATION_REQUIRED");
  assert.equal(dark.calls, 0);
  assert.ok(await x.claim(signed2), "protected: claim re-established");
  seedVault(signed2);
  const s2 = scriptedRpc(x.rpc);
  assert.equal((await x.submit(signed2, s2.rpc)).state, "CHAIN_VERIFIED");
  assert.equal(s2.calls, 0);
  assert.equal((await loadManifestV7(x.cfg, signed2.build.template.vaultId)).creationTxId, signed2.txId);
});


test("RC36 root recovery: spent genesis completes only through actual bound transition history; altered receipt preserves the advanced root and claim", { skip: SKIP }, async (t) => {
  const x = await setup(t), r = await x.signedRoot(), s = await x.lostResponse(r);
  await x.submit(r, s.rpc);
  const q = await wr7.buildRootActionRequest({ config: x.cfg, rootCovenantId: r.rootCovenantId, action: "authorize", params: { fuel: x.H.fuelUtxoFor(x.c.fuelKey) }, signerAddress: x.H.ADDR(x.c.owner1) });
  await x.H.slotSign(x.cfg, q, 1, x.c.owner1); await x.H.slotSign(x.cfg, q, 2, x.c.owner2);
  const after = await wr7.loadOrgRootRequest(x.cfg, q.id);
  const fuelSignatureScriptHex = x.H.kaspa.createInputSignature(x.H.kaspa.Transaction.deserializeFromSafeJSON(q.transaction.unsignedSafeJson), after.build.frozen.inputs.length - 1, x.c.fuelKey);
  const fin = await wr7.finalizeOrgRootRequest({ config: x.cfg, requestId: q.id, fuelSignatureScriptHex });
  x.H.seedRootAction(x.cfg, x.rpc, fin);
  await wr7.submitOrgRootRequest({ config: x.cfg, requestId: q.id, rpc: s.rpc, pollAttempts: 1, pollDelayMs: 0 });
  const root = await wr7.loadOrgRoot(x.cfg, r.rootCovenantId), calls = s.calls;
  const rewind = async () => {
    const stale = await x.load(r); stale.state = "RECONCILIATION_REQUIRED"; await wr7.saveOrgRootRequest(x.cfg, stale);
    await require("../src/submission-claim").claimSubmission(x.cfg, { txId: r.txId, vaultId: r.rootCovenantId, action: r.kind });
  };
  await rewind();
  assert.equal((await x.submit(r, s.rpc)).state, "CHAIN_VERIFIED");
  assert.deepEqual(await wr7.loadOrgRoot(x.cfg, r.rootCovenantId), root);
  assert.equal(await x.claim(r), null); assert.equal(s.calls, calls);
  const receipt = await x.store.read(Categories.RECEIPT, fin.txId);
  receipt.proof.requestFingerprint = "00".repeat(32);
  await x.store.write(Categories.RECEIPT, fin.txId, receipt); await rewind();
  await assert.rejects(() => x.submit(r, s.rpc), (e) => e.code === "RECONCILIATION_REQUIRED");
  assert.deepEqual(await wr7.loadOrgRoot(x.cfg, r.rootCovenantId), root);
  assert.ok(await x.claim(r)); assert.equal(s.calls, calls);
});

test("RC36 root recovery validates signed consensus fields and exact generation-zero state even beside a terminal label", { skip: SKIP }, async (t) => {
  const x = await setup(t), r = await x.signedRoot(), s = await x.lostResponse(r);
  const saved = await x.load(r), changed = JSON.parse(saved.signedSafeJson);
  changed.lockTime = String(BigInt(changed.lockTime ?? 0) + 1n);
  await wr7.saveOrgRootRequest(x.cfg, { ...saved, signedSafeJson: JSON.stringify(changed) });
  await assert.rejects(() => x.submit(r, s.rpc), (e) => e.code === "SIGNATURE_INVALID");
  assert.ok(await x.claim(r)); assert.equal(await wr7.loadOrgRoot(x.cfg, r.rootCovenantId), null);
  await wr7.saveOrgRootRequest(x.cfg, saved); await x.submit(r, s.rpc);
  const completed = await x.load(r);
  await wr7.saveOrgRootRequest(x.cfg, { ...completed, signedSafeJson: JSON.stringify(changed) });
  await assert.rejects(() => x.submit(r, s.rpc), (e) => e.code === "SIGNATURE_INVALID");
  await wr7.saveOrgRootRequest(x.cfg, completed);
  const root = await wr7.loadOrgRoot(x.cfg, r.rootCovenantId);
  const corrupt = { ...root, live: { ...root.live, value: String(BigInt(root.live.value) + 1n) } };
  await wr7.saveOrgRoot(x.cfg, corrupt);
  await assert.rejects(() => x.submit(r, s.rpc), (e) => e.code === "RECONCILIATION_REQUIRED");
  assert.deepEqual(await wr7.loadOrgRoot(x.cfg, r.rootCovenantId), corrupt);
  assert.ok(await x.claim(r)); assert.equal(s.calls, 1);
});
