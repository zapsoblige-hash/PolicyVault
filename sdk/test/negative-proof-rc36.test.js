"use strict";
// RC36 affected regression: current UTXO absence is not historical nonacceptance.
// Real frozen transaction identities and real SDK KAS recovery; all node replies
// are bounded in-process fixtures with explicit funding/acceptance evidence.
const test = require("node:test"), assert = require("node:assert/strict");
const fs = require("node:fs"), os = require("node:os"), path = require("node:path");
const { loadConfig } = require("../src/config");
const { getStore, Categories } = require("../src/store");
const { getAddressUtxos } = require("../src/chain");
const { settleGenesisSubmitError } = require("../src/genesis-recovery");
const { recordedNegativeIsEstablished, classifyRecordedNegative, negativeEvidenceBinding } = require("../src/submission-classification");
const { fundingRequest, negativeRpc, provenNegative, START, OTHER } = require("./helpers/negative-proof-fixtures");
const { createHarness } = require("./helpers/v7-kas-mock-harness");
const { KAS, answers, scriptedRpc, toolchainSkip } = require("./helpers/rc35-recovery-fixtures");
const K = require("../src/wallet-requests-v7-kas");
const { findVaultIdentityReservation } = require("../src/vault-identity");
const SKIP = toolchainSkip("pv-negative-proof-rc36-prereq-");
function configFor(t) {
  const config = loadConfig({ dataRoot: fs.mkdtempSync(path.join(os.tmpdir(), "pv-negative-proof-rc36-")) });
  t.after(() => fs.rmSync(config.dataRoot, { recursive: true, force: true }));
  return config;
}
const settle = (config, request, rpc, message = answers.nonStandard(request.txId)) => settleGenesisSubmitError({ config, request, rpc, message, txId: request.txId });

test("RC36 negative proof: genuine exact funding, two exact mempool misses and complete original-anchor acceptance window produce a bound durable proof", async (t) => {
  const config = configFor(t), request = fundingRequest(config), x = negativeRpc(config, request);
  const result = await settle(config, request, x.rpc);
  assert.equal(result.decision, "REJECTED", result.reason);
  assert.equal(result.proof.schema, "policyvault-negative-proof/v2");
  assert.equal(result.proof.txId, request.txId);
  assert.equal(result.proof.startHash, START);
  assert.equal(result.proof.requestBinding, negativeEvidenceBinding(request));
  assert.equal(result.proof.completeAcceptanceWindow, true);
  assert.equal(result.proof.allInputsUnspent, true);
  assert.equal(result.proof.exactMempoolMiss, true);
  assert.ok(x.state.fundingReads >= 2);
  assert.equal(x.state.mempoolReads, 2);
  assert.deepEqual(x.state.windows, [{ startHash: START, includeAcceptedTransactionIds: true }]);
});

for (const mode of ["funding-spent", "funding-disappears", "funding-amount", "funding-script", "funding-covenant", "funding-duplicate",
  "output-observed", "utxo-error", "utxo-error-field", "utxo-malformed", "mempool-error", "mempool-wrong-id", "mempool-malformed",
  "window-error", "window-error-field", "window-malformed", "window-incomplete", "anchor-reorg", "tip-moved", "dag-error", "dag-error-field"]) {
  test(`RC36 negative proof: ${mode} cannot release a claim despite a bound node rejection`, async (t) => {
    const config = configFor(t), request = fundingRequest(config), x = negativeRpc(config, request);
    x.state.mode = mode;
    const result = await settle(config, request, x.rpc);
    assert.equal(result.decision, "UNCERTAIN", JSON.stringify(result));
    assert.equal(result.proof, undefined);
  });
}

test("RC36 negative proof: an acceptance-history hit defeats a lagging UTXO index even when all inputs still appear unspent and outputs are missing", async (t) => {
  const config = configFor(t), request = fundingRequest(config), x = negativeRpc(config, request);
  x.state.accepted = true;
  const result = await settle(config, request, x.rpc);
  assert.equal(result.decision, "UNCERTAIN");
  assert.equal(result.proof, undefined);
  assert.equal(x.state.windows.length, 1);
  assert.equal(x.state.fundingReads, 0, "acceptance is detected before contradictory current-index negatives are used");
});

test("RC36 negative proof: a missing original anchor cannot be replaced by a new reconcile anchor or a historical bare error", async (t) => {
  const config = configFor(t), request = fundingRequest(config);
  delete request.submitStartHash;
  request.reconcileStartHash = START;
  request.error = answers.nonStandard(request.txId);
  const result = await settle(config, request, negativeRpc(config, request).rpc);
  assert.equal(result.decision, "UNCERTAIN");
  assert.equal(recordedNegativeIsEstablished(request), false);
  assert.equal(classifyRecordedNegative(request), "UNKNOWN");
  assert.equal(request.submitStartHash, undefined, "no original submission anchor invented");
});

test("RC36 UTXO response errors/malformed success are unavailable observations, never empty UTXO sets", async () => {
  for (const response of [undefined, null, {}, { error: { message: "TEST failure" }, entries: [] }, { entries: null }, { entries: {} }]) {
    await assert.rejects(() => getAddressUtxos({ getUtxosByAddresses: async () => response }, "kaspatest:unused"), /error or malformed/);
  }
  assert.deepEqual(await getAddressUtxos({ getUtxosByAddresses: async () => ({ entries: [] }) }, "kaspatest:unused"), []);
});

test("RC36 persisted proof: genuine observer proof survives PostgreSQL JSONB key ordering, but changed request/anchor/txid/funding or partial historical proof remains protected", async (t) => {
  const config = configFor(t), negative = await provenNegative(config, fundingRequest(config));
  assert.equal(recordedNegativeIsEstablished(negative), true);
  const reverseKeys = (v) => Array.isArray(v) ? v.map(reverseKeys) : v && typeof v === "object" ? Object.fromEntries(Object.keys(v).reverse().map((k) => [k, reverseKeys(v[k])])) : v;
  const reordered = reverseKeys(JSON.parse(JSON.stringify(negative)));
  assert.equal(recordedNegativeIsEstablished(reordered), true, "object insertion order is not a different request binding");
  for (const mutate of [r => r.requestId = "another-request", r => r.txId = OTHER, r => r.submitStartHash = OTHER,
    r => r.submissionOutcome.proof.startHash = OTHER, r => r.build.frozen.inputs[0].utxo.amount = "9",
    r => r.submissionRejection.message = answers.nonStandard(OTHER), r => r.submissionRejection.submitStartHash = OTHER,
    r => r.submissionOutcome.proof.nodeAnswer = answers.nonStandard(OTHER), r => r.submissionOutcome.proof.completeAcceptanceWindow = false,
    r => r.submissionOutcome.proof.initialAnchorReorg = true, r => r.submissionOutcome.proof.repeatedFundingQueries = false]) {
    const changed = JSON.parse(JSON.stringify(negative)); mutate(changed);
    assert.equal(recordedNegativeIsEstablished(changed), false);
  }
  for (const proof of [{ outputsAbsent: true }, { txId: negative.txId, boundRejection: true, outputsAbsent: true }]) {
    const old = { ...negative, submissionOutcome: { outcome: "SUBMISSION_REJECTED", txId: negative.txId, proof } };
    assert.equal(recordedNegativeIsEstablished(old), false);
    assert.equal(classifyRecordedNegative(old), "UNKNOWN");
  }
});

test("RC36 KAS recovery: two incomplete retries preserve the original rejection/anchor; later complete acceptance history settles the same signed request without rebroadcast and repeats idempotently", { skip: SKIP }, async (t) => {
  const config = configFor(t), H = createHarness(config), c = H.ctx(), base = H.mockRpc();
  const root = await H.rootGenesis(config, c, base), store = getStore(config);
  const built = await K.buildKasVaultGenesisRequest({ config, rootCovenantId: root, label: "RC36 retry proof", agents: [c.policy], approvers: [], approvalM: 0,
    recoveryAddress: H.ADDR(c.recoveryKey), depositKas: "3", feeReserveKas: "0.5", signerAddress: H.ADDR(c.funder), funding: [H.fuelUtxoFor(c.funder, 20n * KAS)] });
  const signed = await K.finalizeKasWalletRequest({ config, requestId: built.requestId, signedSafeJson: H.signAll(built.transaction.unsignedSafeJson, built.transaction.signInputs.map((s) => [s.index, c.funder])) });
  const scripted = scriptedRpc(base);
  scripted.answers.push({ throw: answers.nonStandard(signed.txId) });
  const x = negativeRpc(config, signed, { baseRpc: scripted.rpc, captureAtSubmission: true });
  x.state.mode = "window-incomplete";
  const submit = () => K.submitKasWalletRequest({ config, requestId: signed.requestId, rpc: x.rpc, pollAttempts: 1, pollDelayMs: 0 });
  await assert.rejects(submit, { code: "RECONCILIATION_REQUIRED" });
  const original = await K.loadKasWalletRequest(config, signed.requestId);
  assert.equal(original.submitStartHash, START);
  assert.equal(original.submissionRejection.txId, signed.txId);
  assert.equal(original.submissionRejection.message, answers.nonStandard(signed.txId));
  for (let retry = 0; retry < 2; retry++) {
    await assert.rejects(submit, { code: "RECONCILIATION_REQUIRED" });
    const pending = await K.loadKasWalletRequest(config, signed.requestId);
    assert.deepEqual(pending.submissionRejection, original.submissionRejection);
    assert.equal(pending.submitStartHash, START);
    assert.equal(pending.signedSafeJson, signed.signedSafeJson);
    assert.ok(await store.read(Categories.SUBMISSION_CLAIM, signed.txId));
  }
  x.state.mode = "honest";
  const settled = await submit();
  assert.equal(settled.state, "SUBMISSION_REJECTED");
  const after = await K.loadKasWalletRequest(config, signed.requestId);
  assert.equal(recordedNegativeIsEstablished(after), true);
  assert.equal(after.txId, signed.txId);
  assert.equal(after.signedSafeJson, signed.signedSafeJson);
  assert.deepEqual(after.submissionRejection, original.submissionRejection);
  assert.equal(await store.read(Categories.SUBMISSION_CLAIM, signed.txId), null);
  assert.equal(await findVaultIdentityReservation(config, signed.vaultId, { phase: "commit" }), null);
  assert.equal(scripted.calls, 1, "one original mocked submission; all recovery calls only observe");
  await submit();
  assert.deepEqual(await K.loadKasWalletRequest(config, signed.requestId), after, "settled same-request retry writes nothing");
  assert.equal(scripted.calls, 1);
});
