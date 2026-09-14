"use strict";
/*
 * SDK / CRASH-RECOVERY — RC35-REC-01 (independent RC35 affected review, 2026-09-11; owner repair directive of the same day).
 *
 * The reviewer's finding (exact-image reproduction rejection-recovery-02.json): the node's ALREADY-ACCEPTED answer to a
 * KAS genesis broadcast ("Rejected transaction {id}: transaction {id} was already accepted by the consensus" — the exact
 * RejectAlreadyAccepted wording of the retained node source) was classified as a definitive rejection: the submission
 * claim was released, the request persisted SUBMISSION_REJECTED, the identity arbiter treated it as uncommitted and the
 * request's own observation could not complete although its vault output existed.
 *
 * These regressions drive the REAL KAS request pipeline (build -> funder signature -> submit -> observation -> create-only
 * completion) against an in-process mock node (TEST keys; nothing leaves the process), with the node's EXACT answer
 * strings. They prove: an already-known answer is observed like an accepted response (claim kept, one broadcast total, the
 * same request settles); a genuine bound rejection settles ONLY with an original-anchor complete acceptance window, exact repeated funding and mempool observations, and outputs absent
 * (claim released, proof recorded, the build-phase reservation retained, the commit-phase reservation released); a
 * contradiction, an envelope naming another transaction and a transport failure keep the claim; ALREADY-PERSISTED false
 * negatives written by the pre-correction runtime recover by observation through the same request (claim re-established,
 * nothing rebroadcast, identical request / txid / signed bytes) — also with new creation disabled by the kill switch;
 * a historical bare rejection remains protected; the identity arbiter blocks a false negative at commit time and does
 * not block an established negative; the delegate path settles a rejection only with chain confirmation.
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
const K = require("../src/wallet-requests-v7-kas");
const wr7 = require("../src/wallet-requests-v7");
const { loadManifestV7Kas } = require("../src/manifest-v7-kas");
const { findVaultIdentityReservation, requestProvablyUncommitted } = require("../src/vault-identity");
const { createHarness } = require("./helpers/v7-kas-mock-harness");
const { KAS, toolchainSkip, mainnetConfig, answers, scriptedRpc, persistLegacyNegative } = require("./helpers/rc35-recovery-fixtures");

const SKIP = toolchainSkip("pv-rec01-probe-");
const KAS_V = "policyvault-0.7-kas";
const { negativeRpc } = require("./helpers/negative-proof-fixtures");

async function setup(t, cfgOverride = null) {
  const cfg = cfgOverride ?? loadConfig({ dataRoot: fs.mkdtempSync(path.join(os.tmpdir(), "pv-rec01-")) });
  const H = createHarness(cfg);
  const c = H.ctx();
  const rpc = H.mockRpc();
  const root = await H.rootGenesis(cfg, c, rpc);
  t.after(() => fs.rmSync(cfg.dataRoot, { recursive: true, force: true }));
  const store = getStore(cfg);
  const build = (over = {}) => K.buildKasVaultGenesisRequest({ config: cfg, rootCovenantId: root, label: "rec01", agents: [c.policy], approvers: [], approvalM: 0, recoveryAddress: H.ADDR(c.recoveryKey), depositKas: "3", feeReserveKas: "0.5", signerAddress: H.ADDR(c.funder), funding: [H.fuelUtxoFor(c.funder, 20n * KAS)], ...over });
  const sign = (r) => K.finalizeKasWalletRequest({ config: cfg, requestId: r.requestId, signedSafeJson: H.signAll(r.transaction.unsignedSafeJson, r.transaction.signInputs.map((x) => [x.index, c.funder])) });
  const seed = (r) => { const address = covenantAddress(cfg, Buffer.from(r.build.vaultScriptHex, "hex")); rpc.seed(address, H.utxo(address, r.txId, r.build.vaultOutputIndex, r.build.frozen.outputs[r.build.vaultOutputIndex].value, r.build.covenantId)); };
  const submit = (r, useRpc, over = {}) => K.submitKasWalletRequest({ config: cfg, requestId: r.requestId, rpc: useRpc, pollAttempts: 1, pollDelayMs: 0, ...over });
  const claim = (r) => store.read(Categories.SUBMISSION_CLAIM, r.txId);
  const load = (r) => K.loadKasWalletRequest(cfg, r.requestId);
  async function signedGenesis(over = {}) { const r = await build(over); await sign(r); return { ...r, ...(await load(r)) }; }
  return { cfg, H, c, rpc, root, store, build, sign, seed, submit, claim, load, signedGenesis };
}

test("REC-01 (the reviewer's case): the node's ALREADY-ACCEPTED answer is observed like an accepted response — claim kept, the same request settles CHAIN_VERIFIED, exactly one broadcast, the answer recorded truthfully", { skip: SKIP }, async (t) => {
  const x = await setup(t);
  const r = await x.signedGenesis();
  const original = await x.load(r);
  const s = scriptedRpc(x.rpc);
  s.answers.push({ before: () => x.seed(r), throw: answers.alreadyAccepted(r.txId) });
  const settled = await x.submit(r, s.rpc);
  assert.equal(s.calls, 1, "exactly one broadcast");
  assert.equal(settled.state, "CHAIN_VERIFIED");
  const after = await x.load(r);
  assert.equal(after.state, "CHAIN_VERIFIED");
  assert.equal(after.submissionResponse.kind, "ALREADY_KNOWN");
  assert.equal(after.submissionResponse.variant, "RejectAlreadyAccepted");
  assert.equal(after.txId, original.txId);
  assert.equal(after.signedSafeJson, original.signedSafeJson);
  assert.equal(await x.claim(r), null, "the claim is released by chain proof, never by the node's answer");
  const manifest = await loadManifestV7Kas(x.cfg, r.vaultId);
  assert.equal(manifest.creationTxId, r.txId);
  assert.ok((await wr7.loadOrgRoot(x.cfg, x.root)).vaults.includes(r.vaultId));
  /* the JS/WASM transport envelope form of the same answer behaves identically */
  const r2 = await x.signedGenesis();
  const s2 = scriptedRpc(x.rpc);
  s2.answers.push({ before: () => x.seed(r2), throw: answers.wrapped(answers.alreadyInMempool(r2.txId)) });
  assert.equal((await x.submit(r2, s2.rpc)).state, "CHAIN_VERIFIED");
  assert.equal((await x.load(r2)).submissionResponse.variant, "RejectDuplicate");
});

test("REC-01: ALREADY-IN-MEMPOOL with the output not yet observed keeps the claim as RECONCILIATION_REQUIRED; the same request later settles by observation with no further broadcast", { skip: SKIP }, async (t) => {
  const x = await setup(t);
  const r = await x.signedGenesis();
  const s = scriptedRpc(x.rpc);
  s.answers.push({ throw: answers.alreadyInMempool(r.txId) });
  await assert.rejects(() => x.submit(r, s.rpc), (e) => e.code === "RECONCILIATION_REQUIRED");
  assert.equal(s.calls, 1);
  const pending = await x.load(r);
  assert.equal(pending.state, "RECONCILIATION_REQUIRED");
  assert.equal(pending.submissionResponse.kind, "ALREADY_KNOWN");
  assert.ok(await x.claim(r), "the claim is held while the outcome is unresolved");
  assert.deepEqual(await findVaultIdentityReservation(x.cfg, r.vaultId, { phase: "commit" }), { kind: "REQUEST" }, "the unresolved request reserves its identity at commit time");
  x.seed(r);
  const settled = await x.submit(r, s.rpc);
  assert.equal(s.calls, 1, "settlement is observed, never rebroadcast");
  assert.equal(settled.state, "CHAIN_VERIFIED");
  assert.equal(await x.claim(r), null);
});

test("REC-01: a GENUINE bound rejection with complete original-anchor acceptance and exact funding proof settles the negative — claim released, proof recorded, build-phase reservation retained, commit-phase reservation released, repeated submits stay negative with no broadcast", { skip: SKIP }, async (t) => {
  const x = await setup(t);
  const r = await x.signedGenesis();
  const s = scriptedRpc(x.rpc);
  s.answers.push({ throw: answers.nonStandard(r.txId) });
  const evidence = negativeRpc(x.cfg, r, { baseRpc: s.rpc, captureAtSubmission: true });
  await assert.rejects(() => x.submit(r, evidence.rpc), (e) => e.code === "SUBMISSION_REJECTED");
  assert.equal(s.calls, 1);
  const negative = await x.load(r);
  assert.equal(negative.state, "SUBMISSION_REJECTED");
  assert.equal(negative.submissionOutcome.outcome, "SUBMISSION_REJECTED");
  assert.equal(negative.submissionOutcome.txId, r.txId);
  assert.equal(negative.submissionOutcome.proof.outputsAbsent, true, "the negative carries the output-absent proof");
  assert.equal(negative.submissionOutcome.proof.boundRejection, true);
  assert.equal(negative.submissionOutcome.proof.schema, "policyvault-negative-proof/v2");
  assert.equal(negative.submissionOutcome.proof.allInputsUnspent, true);
  assert.equal(negative.submissionOutcome.proof.completeAcceptanceWindow, true);
  assert.equal(negative.submissionOutcome.proof.exactMempoolMiss, true);
  assert.equal(await x.claim(r), null, "a proven negative releases the claim");
  assert.equal(await loadManifestV7Kas(x.cfg, r.vaultId), null);
  assert.deepEqual(await findVaultIdentityReservation(x.cfg, r.vaultId), { kind: "REQUEST" }, "identities are never recycled: the build-phase reservation stays");
  assert.equal(await findVaultIdentityReservation(x.cfg, r.vaultId, { phase: "commit" }), null, "an ESTABLISHED negative does not block a legitimate sibling at commit time");
  assert.equal(requestProvablyUncommitted(negative), true);
  const again = await x.submit(r, evidence.rpc);
  assert.equal(again.state, "SUBMISSION_REJECTED", "a repeated submit of an established negative changes nothing");
  assert.equal(s.calls, 1, "and never rebroadcasts");
  assert.equal(await x.claim(r), null);
  /* a double-spend rejection (another mempool transaction spends our input) is a rejection of THIS attempt too */
  const r2 = await x.signedGenesis();
  const s2 = scriptedRpc(x.rpc);
  s2.answers.push({ throw: answers.doubleSpendInMempool(r2.txId, "cd".repeat(32)) });
  const evidence2 = negativeRpc(x.cfg, r2, { baseRpc: s2.rpc, captureAtSubmission: true });
  await assert.rejects(() => x.submit(r2, evidence2.rpc), (e) => e.code === "SUBMISSION_REJECTED");
  assert.equal((await x.load(r2)).submissionOutcome.proof.outputsAbsent, true);
});

test("REC-01: a bound rejection whose vault output IS observed (contradiction), an envelope naming ANOTHER transaction, and a transport failure all keep the claim; the contradiction then settles by observation", { skip: SKIP }, async (t) => {
  const x = await setup(t);
  /* contradiction */
  const r = await x.signedGenesis();
  const s = scriptedRpc(x.rpc);
  s.answers.push({ before: () => x.seed(r), throw: answers.nonStandard(r.txId) });
  await assert.rejects(() => x.submit(r, s.rpc), (e) => e.code === "RECONCILIATION_REQUIRED");
  const contradicted = await x.load(r);
  assert.equal(contradicted.state, "RECONCILIATION_REQUIRED");
  assert.match(contradicted.error, /claim kept|verification unavailable/);
  assert.ok(await x.claim(r), "the claim is kept — the chain contradicts the node's answer");
  assert.equal((await x.submit(r, s.rpc)).state, "CHAIN_VERIFIED", "the same request settles by observation");
  assert.equal(s.calls, 1, "nothing was rebroadcast");
  /* another transaction's rejection */
  const r2 = await x.signedGenesis();
  const s2 = scriptedRpc(x.rpc);
  s2.answers.push({ throw: answers.nonStandard("ab".repeat(32)) });
  await assert.rejects(() => x.submit(r2, s2.rpc), (e) => e.code === "RECONCILIATION_REQUIRED");
  assert.equal((await x.load(r2)).state, "RECONCILIATION_REQUIRED");
  assert.match((await x.load(r2)).error, /no bound node rejection/);
  assert.ok(await x.claim(r2));
  /* transport failure (unchanged behaviour) */
  const r3 = await x.signedGenesis();
  const s3 = scriptedRpc(x.rpc);
  s3.answers.push({ throw: answers.transportLost() });
  await assert.rejects(() => x.submit(r3, s3.rpc), (e) => e.code === "RECONCILIATION_REQUIRED");
  assert.equal((await x.load(r3)).state, "RECONCILIATION_REQUIRED");
  assert.ok(await x.claim(r3));
});

test("REC-01 (already persisted false negative): a request the PRE-CORRECTION runtime persisted SUBMISSION_REJECTED for an already-accepted answer recovers by OBSERVATION through the same request — the identity arbiter blocks it at commit time, an unobserved output PROTECTS it (claim re-established, RECONCILIATION_REQUIRED), an observed output completes it with no broadcast and identical request / txid / signed bytes", { skip: SKIP }, async (t) => {
  const x = await setup(t);
  const r = await x.signedGenesis();
  const signedBytes = (await x.load(r)).signedSafeJson;
  const legacy = await persistLegacyNegative(x.store, Categories.REQUEST, r.requestId, await x.load(r), answers.alreadyAccepted(r.txId));
  assert.equal(legacy.state, "SUBMISSION_REJECTED");
  assert.equal(await x.claim(r), null, "the pre-correction runtime had released the claim");
  /* the arbiter: a false negative is NOT provably uncommitted — it reserves the identity at commit time */
  assert.equal(requestProvablyUncommitted(legacy), false);
  assert.deepEqual(await findVaultIdentityReservation(x.cfg, r.vaultId, { phase: "commit" }), { kind: "REQUEST" });
  /* unobserved: PROTECT — nothing rebroadcast, claim re-established, truthful reason */
  const s = scriptedRpc(x.rpc);
  await assert.rejects(() => x.submit(r, s.rpc), (e) => e.code === "RECONCILIATION_REQUIRED");
  assert.equal(s.calls, 0, "recovery never broadcasts");
  const protectedRecord = await x.load(r);
  assert.equal(protectedRecord.state, "RECONCILIATION_REQUIRED");
  assert.match(protectedRecord.error, /already held or accepted/);
  const claim = await x.claim(r);
  assert.ok(claim, "the submission claim is re-established");
  assert.equal(claim.vaultId, r.vaultId);
  assert.equal(claim.action, K.GENESIS_ACTION);
  assert.equal(protectedRecord.txId, r.txId);
  assert.equal(protectedRecord.signedSafeJson, signedBytes);
  /* observed: completes through the same request */
  x.seed(r);
  const settled = await x.submit(r, s.rpc);
  assert.equal(s.calls, 0);
  assert.equal(settled.state, "CHAIN_VERIFIED");
  assert.equal(settled.requestId, r.requestId);
  assert.equal(settled.txId, r.txId);
  assert.equal((await x.load(r)).signedSafeJson, signedBytes);
  assert.equal(await x.claim(r), null, "released by chain proof");
  assert.equal((await loadManifestV7Kas(x.cfg, r.vaultId)).creationTxId, r.txId);
  assert.ok((await wr7.loadOrgRoot(x.cfg, x.root)).vaults.includes(r.vaultId));
  assert.equal((await K.listKasWalletRequests(x.cfg, {})).filter((q) => q.kind === "kasGenesis" && q.vaultId === r.vaultId).length, 1, "no replacement request was ever created");
  /* a false negative recovered DIRECTLY from the observed output (no protect step first) also works */
  const r2 = await x.signedGenesis();
  await persistLegacyNegative(x.store, Categories.REQUEST, r2.requestId, await x.load(r2), answers.alreadyInMempool(r2.txId));
  x.seed(r2);
  assert.equal((await x.submit(r2, s.rpc)).state, "CHAIN_VERIFIED");
  assert.equal(s.calls, 0);
});

test("REC-01 (historical records): a historical bare bound rejection without its original anchor stays protected; a legacy record with NO recorded answer is protected", { skip: SKIP }, async (t) => {
  const x = await setup(t);
  const r = await x.signedGenesis();
  const legacy = await persistLegacyNegative(x.store, Categories.REQUEST, r.requestId, await x.load(r), answers.nonStandard(r.txId));
  assert.equal(requestProvablyUncommitted(legacy), false, "a bound answer without the original acceptance/funding proof is not established");
  assert.deepEqual(await findVaultIdentityReservation(x.cfg, r.vaultId, { phase: "commit" }), { kind: "REQUEST" });
  const s = scriptedRpc(x.rpc);
  await assert.rejects(() => x.submit(r, s.rpc), (e) => e.code === "RECONCILIATION_REQUIRED");
  assert.equal((await x.load(r)).state, "RECONCILIATION_REQUIRED");
  assert.equal(s.calls, 0);
  assert.ok(await x.claim(r), "historical uncertainty reacquires its own claim");
  /* A protected historical request completes when its exact output is observed. */
  x.seed(r);
  assert.equal((await x.submit(r, s.rpc)).state, "CHAIN_VERIFIED");
  assert.equal(s.calls, 0);
  /* a legacy record without any recorded answer */
  const r2 = await x.signedGenesis();
  await persistLegacyNegative(x.store, Categories.REQUEST, r2.requestId, await x.load(r2), undefined);
  assert.deepEqual(await findVaultIdentityReservation(x.cfg, r2.vaultId, { phase: "commit" }), { kind: "REQUEST" });
  await assert.rejects(() => x.submit(r2, s.rpc), (e) => e.code === "RECONCILIATION_REQUIRED");
  assert.equal((await x.load(r2)).state, "RECONCILIATION_REQUIRED");
  assert.ok(await x.claim(r2));
});

test("REC-01 (creation disabled): recovery of a persisted false negative works on the SAME data with the KAS profile removed from the creatable set (mainnet-labelled; kill switch), while a NEW treasury is refused before any durable write", { skip: SKIP }, async (t) => {
  const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "pv-rec01-mainnet-"));
  const cfgOn = mainnetConfig({ dataRoot });
  const x = await setup(t, cfgOn);
  const r = await x.signedGenesis();
  await persistLegacyNegative(x.store, Categories.REQUEST, r.requestId, await x.load(r), answers.alreadyAccepted(r.txId));
  const cfgOff = mainnetConfig({ dataRoot, mainnetCreationDisabled: [KAS_V] });
  assert.ok(cfgOff.mainnetCreationDisabled.has(KAS_V));
  const Hoff = createHarness(cfgOff);
  const rows = (await getStore(cfgOff).listValues(Categories.REQUEST, { strict: true })).length;
  await assert.rejects(() => K.buildKasVaultGenesisRequest({ config: cfgOff, rootCovenantId: x.root, label: "refused", agents: [x.c.policy], approvers: [], approvalM: 0, recoveryAddress: Hoff.ADDR(x.c.recoveryKey), depositKas: "3", feeReserveKas: "0.5", signerAddress: Hoff.ADDR(x.c.funder), funding: [Hoff.fuelUtxoFor(x.c.funder, 20n * KAS)] }), (e) => e.code === "GENERATION_NOT_MAINNET_AUTHORIZED");
  assert.equal((await getStore(cfgOff).listValues(Categories.REQUEST, { strict: true })).length, rows);
  const s = scriptedRpc(x.rpc);
  await assert.rejects(() => K.submitKasWalletRequest({ config: cfgOff, requestId: r.requestId, rpc: s.rpc, pollAttempts: 1, pollDelayMs: 0 }), (e) => e.code === "RECONCILIATION_REQUIRED");
  assert.equal(s.calls, 0);
  assert.ok(await getStore(cfgOff).read(Categories.SUBMISSION_CLAIM, r.txId), "protected on the disabled image");
  x.seed(r);
  const settled = await K.submitKasWalletRequest({ config: cfgOff, requestId: r.requestId, rpc: s.rpc, pollAttempts: 1, pollDelayMs: 0 });
  assert.equal(settled.state, "CHAIN_VERIFIED", "recovery belongs to the OPERABLE set");
  assert.equal(s.calls, 0);
  assert.equal((await loadManifestV7Kas(cfgOff, r.vaultId)).creationTxId, r.txId);
});

test("REC-01 (delegate path): an already-in-mempool answer to a delegate payment is observed and completes; a bound rejection settles only with the vault input still unspent AND every output absent; a rejection the chain contradicts keeps both claims and is completed by reconciliation", { skip: SKIP }, async (t) => {
  const x = await setup(t);
  const { vaultId } = await x.H.kasGenesis(x.cfg, x.c, x.rpc, x.root);
  /* already in the mempool (outputs seeded by the harness) -> observed -> CHAIN_VERIFIED, one broadcast attempt */
  const s1 = scriptedRpc(x.rpc);
  s1.answers.push({ throw: null }); // placeholder replaced below: the answer needs the txid, which the harness computes at finalize
  s1.rpc.submitTransaction = async (a) => { s1.calls += 1; const txId = a.transaction.finalize().toString().toLowerCase(); throw new Error(answers.alreadyInMempool(txId)); };
  const paid = await x.H.driveSpend(x.cfg, s1.rpc, x.c, vaultId, { amountSompi: 1n * KAS, seed: true, pollAttempts: 1 });
  assert.equal(paid.state, "CHAIN_VERIFIED", paid.error ?? "");
  assert.equal(s1.calls, 1);
  assert.equal(paid.submissionResponse.kind, "ALREADY_KNOWN");
  /* genuine rejection: predecessor still live (nothing seeded), outputs absent -> SUBMISSION_REJECTED with proof, claims released */
  const s2 = scriptedRpc(x.rpc);
  s2.rpc.submitTransaction = async (a) => { s2.calls += 1; throw new Error(answers.nonStandard(a.transaction.finalize().toString().toLowerCase())); };
  const draft = await K.buildKasWalletRequest({ config: x.cfg, vaultId, action: "agentSpend", params: { payAmountSompi: KAS.toString(), recipient: x.H.XO(x.c.recipientKey) }, signerAddress: x.H.ADDR(x.c.agentKey) });
  const signed = await K.finalizeKasWalletRequest({ config: x.cfg, requestId: draft.requestId, signedSafeJson: x.H.signAll(draft.transaction.unsignedSafeJson, [[0, x.c.agentKey]]) });
  const evidence = negativeRpc(x.cfg, signed, { baseRpc: s2.rpc, captureAtSubmission: true });
  await assert.rejects(() => K.submitKasWalletRequest({ config: x.cfg, requestId: signed.requestId, rpc: evidence.rpc, pollAttempts: 1, pollDelayMs: 0 }), (e) => e.code === "SUBMISSION_REJECTED");
  const rejected = (await K.listKasWalletRequests(x.cfg, { vaultId })).find((q) => q.state === "SUBMISSION_REJECTED");
  assert.ok(rejected);
  assert.equal(rejected.submissionOutcome.proof.outputsAbsent, true);
  assert.equal(rejected.submissionOutcome.proof.allInputsUnspent, true);
  assert.equal(rejected.submissionOutcome.proof.completeAcceptanceWindow, true);
  assert.equal(await x.store.read(Categories.SUBMISSION_CLAIM, rejected.txId), null);
  assert.equal(await x.store.read(Categories.TRANSITION_CLAIM, `${rejected.predecessorOutpoint.transactionId}-${rejected.predecessorOutpoint.index}`), null, "the transition claim is released only with chain confirmation");
  /* the vault is still usable: a further payment succeeds */
  const ok = await x.H.driveSpend(x.cfg, x.rpc, x.c, vaultId, { amountSompi: 1n * KAS, seed: true, pollAttempts: 1 });
  assert.equal(ok.state, "CHAIN_VERIFIED", ok.error ?? "");
  /* contradiction: the node says rejected but the successor IS observed (and the predecessor consumed) -> claims kept, attempt recorded, reconciliation completes */
  const s3 = scriptedRpc(x.rpc);
  s3.rpc.submitTransaction = async (a) => { s3.calls += 1; throw new Error(answers.nonStandard(a.transaction.finalize().toString().toLowerCase())); };
  await assert.rejects(() => x.H.driveSpend(x.cfg, s3.rpc, x.c, vaultId, { amountSompi: 1n * KAS, seed: true, pollAttempts: 1 }), (e) => e.code === "RECONCILIATION_REQUIRED");
  const contradicted = (await K.listKasWalletRequests(x.cfg, { vaultId })).find((q) => q.state === "RECONCILIATION_REQUIRED");
  assert.ok(contradicted);
  assert.equal(contradicted.submissionAttempt.phase, "REJECTED_RESPONSE");
  assert.ok(await x.store.read(Categories.SUBMISSION_CLAIM, contradicted.txId), "submission claim kept");
  assert.ok(await x.store.read(Categories.TRANSITION_CLAIM, `${contradicted.predecessorOutpoint.transactionId}-${contradicted.predecessorOutpoint.index}`), "transition claim kept");
  const reconciled = await K.reconcileKasVault(x.cfg, x.rpc, vaultId);
  assert.equal(reconciled.status, "ADVANCED", JSON.stringify(reconciled));
  assert.equal((await K.loadKasWalletRequest(x.cfg, contradicted.requestId)).state, "CHAIN_VERIFIED");
});
