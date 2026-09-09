"use strict";

/*
 * API — EXPORTABLE EXECUTION ATTESTATIONS
 * (server/src/attestations.js + the /attestations routes in
 * server/src/api.js; record + verifier in core/attest).
 *
 * Proves, over the REAL server handler and REAL durable records:
 *   1. a freshly built v0.4 request exports an attestation that reaches
 *      exactly AUTHORIZED — no signature, no broadcast, no chain claim;
 *   2. as the durable evidence advances (external signature, node submit,
 *      chain-proof receipt), the exported ladder advances with it and
 *      NEVER out-runs it — and VERIFIED_OUTCOME is never synthesized;
 *   3. the exported record is assembled from the SAME durable evidence the
 *      finalize/submit gate uses (the G-2-checked, re-verified-now intent
 *      manifest), and carries the exact successor output address a third
 *      party must query to re-check it;
 *   4. a refused execution exports as REFUSED evidence with no ladder
 *      state and no transaction id;
 *   5. every export round-trips through the canonical/NDJSON formats and
 *      re-verifies in a reader's hands; tampering with an exported record
 *      is caught by the shared verifier, not by the issuer;
 *   6. the export is scope-gated deny-by-default (read:attestations) and
 *      tenancy-gated in hosted mode;
 *   7. NO-SECRET SWEEP over the exported document, and the rendered human
 *      summary uses none of the forbidden vocabulary.
 *
 * Layers: API + SDK + UNIT (JSON backend; no node, no VM, no network —
 * the chain-fact RE-CHECK is the reader's job and is covered by
 * core/attest/test/chain-facts.test.js plus tools/attestation-verify.js).
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");
const os = require("os");

const { handle, loadConfig } = require("../../server/src/api");
const attest = require("../../core/attest");
const wr4 = require("../src/wallet-requests-v4");
const { persistReceipt } = require("../src/submission-claim");
const { buildAgentTreeV4, normalizeAgentPolicyV4 } = require("../src/agent-merkle-v4");
const { buildRecipientTree } = require("../src/recipient-merkle-v3");
const { normalizeStateV4, computeStateIdV4, stateToJsonV4, CONTRACT_VERSION_V4 } = require("../src/vault-state-v4");
const { compileExactStateV4 } = require("../src/contract-compiler-v4");
const { MANIFEST_SCHEMA_V4, persistManifestV4 } = require("../src/manifest-v4");
const { requiredScopesFor, SCOPES } = require("../../server/src/scopes");

const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "pv-attest-"));
const config = loadConfig({ dataRoot, buildId: "attest-test-build" });
const kaspa = require(config.rustyKaspaModule);
const KEY = (v) => new kaspa.PrivateKey(v.toString(16).padStart(2, "0").repeat(32));
const XO = (p) => p.toPublicKey().toXOnlyPublicKey().toString().toLowerCase();
const ADDR = (p) => p.toPublicKey().toAddress(config.networkId).toString();
const KAS = 100000000n;

const owner = KEY(1);
const agentA = KEY(0x1e);
const recipient = KEY(0x28);

const REGISTRY = [
  {
    agentPk: XO(agentA), maxPerSpend: (20n * KAS).toString(), periodBudget: (50n * KAS).toString(),
    periodLengthDaa: "864000", periodStartDaa: "541000000", periodSpent: "0",
    approvalThreshold: (50n * KAS).toString(), agentMaxFeePerTx: (1n * KAS).toString(), recipients: [XO(recipient)]
  }
];

let seedCounter = 0;
async function seed(vaultId) {
  seedCounter += 1;
  const outTxId = (0x70 + seedCounter).toString(16).padStart(2, "0").repeat(32).slice(0, 64);
  const template = { owner: XO(owner), vaultId };
  const policies = REGISTRY.map((e) => normalizeAgentPolicyV4({ ...e, agentRecipientRoot: buildRecipientTree(e.recipients).root }));
  const state = normalizeStateV4({
    protectedValue: (1000n * KAS).toString(), feeReserve: (5n * KAS).toString(), paused: "0",
    agentRoot: buildAgentTreeV4(policies).root, approvers: [], approvalM: "0", policyNonce: "0"
  });
  const compiled = compileExactStateV4({ config, template, state });
  const stateId = computeStateIdV4({ networkId: config.networkId, template, state });
  return await persistManifestV4(config, {
    schema: MANIFEST_SCHEMA_V4, contractVersion: CONTRACT_VERSION_V4, networkId: config.networkId, vaultId,
    label: "attest", status: "ACTIVE", template, agentRegistry: REGISTRY,
    live: {
      state: stateToJsonV4(state), stateId, outpoint: { transactionId: outTxId, index: 0 },
      outpointValue: (state.protectedValue + state.feeReserve).toString(), scriptSha256: compiled.scriptSha256, covenantId: "41".repeat(32)
    },
    creationTxId: "42".repeat(32), latestTransitionTxId: null, lastTransition: null
  });
}

const POST = (segs, body, ctx) => handle(config, "POST", segs, {}, body, ctx ?? {});
const GET = (segs, query, cfg) => handle(cfg ?? config, "GET", segs, query ?? {}, null, {});

async function expectThrow(promise, status, code) {
  try {
    await promise;
    assert.fail("expected an API error");
  } catch (e) {
    if (e.code === "ERR_ASSERTION") throw e;
    if (status !== undefined) assert.equal(e.status, status, `status ${e.status} != ${status}: ${e.message}`);
    if (code !== undefined) assert.equal(e.code, code, `code ${e.code} != ${code}: ${e.message}`);
    return e;
  }
}

const spend = (vaultId, amountKas) => POST(["wallet", "v4", "requests"], {
  vaultId, action: "agentSpend",
  params: { payAmountSompi: (amountKas * KAS).toString(), agentPk: XO(agentA), recipient: XO(recipient) },
  signerAddress: ADDR(agentA)
});
/* The API response presents a request; the DURABLE record is what the
 * attestation export reads, so tests assert against that. */
const buildSpend = async (vaultId, amountKas) => wr4.loadRequest(config, (await spend(vaultId, amountKas)).body.request.requestId);

/* Advance the DURABLE evidence exactly as the real pipeline would, then
 * let the export read it back. Nothing here touches the exporter. */
async function advanceToChainVerified(request) {
  const manifestBody = (await GET(["manifests", request.manifestHash])).body.manifest;
  const successorIndex = manifestBody.effects.outputs.findIndex((o) => o.kind === "successor");
  assert.ok(successorIndex >= 0, "the recorded manifest classifies a successor output");
  await persistReceipt(config, {
    txId: request.txId,
    vaultId: request.vaultId,
    action: request.action,
    proof: {
      requestId: request.requestId,
      successorOutpoint: `${request.txId}:${successorIndex}`,
      value: manifestBody.transaction.outputs[successorIndex].value,
      requiredFeeSompi: request.build.accounting.fee,
      actualFeeSompi: request.build.accounting.fee
    }
  });
  const stored = await wr4.loadRequest(config, request.requestId);
  stored.state = wr4.RequestState.CHAIN_VERIFIED;
  await wr4.saveRequest(config, stored);
  return { successorIndex, manifestBody };
}

/* -------------------------------------------------------------------- */
/* 1. a freshly built request exports AUTHORIZED and nothing more        */
/* -------------------------------------------------------------------- */

test("a freshly built request exports an attestation that reaches exactly AUTHORIZED — no signature, no broadcast, no chain claim", async () => {
  const V = "d1".repeat(32);
  await seed(V);
  const request = await buildSpend(V, 3n);

  const body = (await GET(["attestations", "requests", request.requestId])).body;
  const rec = body.attestation;

  assert.equal(rec.attestationVersion, attest.ATTESTATION_VERSION_1);
  assert.equal(rec.subject.requestId, request.requestId);
  assert.equal(rec.subject.vaultId, V);
  assert.equal(rec.subject.networkId, config.networkId);
  assert.equal(rec.subject.contractVersion, request.contractVersion);
  assert.equal(rec.subject.policyNonce, "0");
  assert.equal(rec.producer.buildId, "attest-test-build");
  assert.ok(rec.producer.sources.includes("policyvault-wallet-request/v4"));
  assert.ok(rec.producer.sources.includes("policyvault-intent-manifest-record/v1"));

  assert.equal(rec.authorization.decision, "AUTHORIZED");
  assert.equal(rec.authorization.refusalCode, null);
  assert.equal(rec.authorization.intentManifestHash, request.manifestHash);
  assert.equal(rec.authorization.intentManifestVerdict, "VERIFIED_EXACT");
  assert.equal(rec.authorization.signerVisibleDigest, request.build.covenantSighash);
  assert.equal(rec.authorization.signerXOnly, XO(agentA));

  assert.deepEqual(rec.outcome.reached.map((r) => r.state), ["AUTHORIZED"]);
  assert.equal(rec.outcome.state, "AUTHORIZED");
  assert.equal(rec.outcome.disposition, "IN_PROGRESS");
  assert.equal(rec.outcome.txId, null, "a built-but-unsigned request has broadcast no transaction");
  assert.deepEqual(rec.outcome.chain.outputs, []);
  assert.equal(rec.amounts.amount, (3n * KAS).toString());
  assert.equal(rec.amounts.networkFeeSompi, request.build.accounting.fee);
  assert.equal(rec.destination.kind, "RECIPIENT_XONLY");
  assert.equal(rec.destination.identity, XO(recipient));

  assert.equal(body.verification.verdict, attest.VERDICTS.STRUCTURE_VERIFIED);
  assert.equal(body.verification.chainConfirmed, false);
  assert.deepEqual(body.verification.failureCodes, []);
});

/* -------------------------------------------------------------------- */
/* 2. the ladder advances with the durable evidence, never ahead of it   */
/* -------------------------------------------------------------------- */

test("the exported ladder advances only as the durable evidence advances, and CHAIN_VERIFIED names the exact output a third party must re-check", async () => {
  const V = "d2".repeat(32);
  await seed(V);
  const request = await buildSpend(V, 4n);

  /* signature returned, nothing broadcast */
  let stored = await wr4.loadRequest(config, request.requestId);
  stored.state = wr4.RequestState.FINALIZED;
  await wr4.saveRequest(config, stored);
  let rec = (await GET(["attestations", "requests", request.requestId])).body.attestation;
  assert.deepEqual(rec.outcome.reached.map((r) => r.state), ["AUTHORIZED", "SIGNED"]);
  assert.equal(rec.outcome.txId, null, "SIGNED is not BROADCAST");
  assert.equal(rec.outcome.disposition, "IN_PROGRESS");

  /* the node accepted the frozen bytes; still no chain proof */
  stored = await wr4.loadRequest(config, request.requestId);
  stored.state = wr4.RequestState.SUBMITTED;
  await wr4.saveRequest(config, stored);
  rec = (await GET(["attestations", "requests", request.requestId])).body.attestation;
  assert.deepEqual(rec.outcome.reached.map((r) => r.state), ["AUTHORIZED", "SIGNED", "BROADCAST"]);
  assert.equal(rec.outcome.txId, request.txId);
  assert.equal(rec.outcome.disposition, "IN_PROGRESS", "BROADCAST is not success");
  assert.deepEqual(rec.outcome.chain.outputs, []);

  /* the exact expected effect was proven on chain */
  const { successorIndex, manifestBody } = await advanceToChainVerified(request);
  const body = (await GET(["attestations", "requests", request.requestId])).body;
  rec = body.attestation;
  assert.deepEqual(rec.outcome.reached.map((r) => r.state), ["AUTHORIZED", "SIGNED", "BROADCAST", "CHAIN_SEEN", "CHAIN_VERIFIED"]);
  assert.equal(rec.outcome.state, "CHAIN_VERIFIED");
  assert.equal(rec.outcome.disposition, "SETTLED");
  assert.equal(rec.outcome.failureCode, null);
  assert.equal(rec.outcome.chain.successorOutpoint.transactionId, request.txId);
  assert.equal(rec.outcome.chain.successorOutpoint.index, successorIndex);
  assert.equal(rec.outcome.chain.successorStateId, request.successorStateId);
  assert.equal(rec.outcome.chain.outputs.length, 1);

  /* the named address is the REAL address of the committed script, so a
   * reader can query it without asking this server anything */
  const out = rec.outcome.chain.outputs[0];
  const expectedAddress = require("../src/tx-identity").addressForScriptPublicKey(
    config,
    manifestBody.transaction.outputs[successorIndex].scriptPublicKey.scriptHex
  );
  assert.equal(out.address, expectedAddress);
  assert.equal(out.valueSompi, manifestBody.transaction.outputs[successorIndex].value);
  assert.equal(out.covenantId, manifestBody.transaction.outputs[successorIndex].covenant.covenantId);
  assert.deepEqual(attest.addressesToQuery(rec), [expectedAddress]);

  /* what PolicyVault does NOT have, it says it does not have */
  assert.equal(out.blockDaaScore, null);
  assert.equal(rec.outcome.chain.acceptingBlockDaaScore, null);
  assert.ok(body.verification.warnings.some((w) => w.code === "ACCEPTING_DAA_NOT_RECORDED"));

  /* VERIFIED_OUTCOME is NEVER synthesized from a successor receipt */
  assert.ok(!rec.outcome.reached.some((r) => r.state === "VERIFIED_OUTCOME"));
  assert.equal(body.verification.chainConfirmed, false, "the issuer never confirms its own chain claims");
});

/* -------------------------------------------------------------------- */
/* 3. refusals are exportable evidence too                              */
/* -------------------------------------------------------------------- */

test("an execution PolicyVault refused exports as REFUSED evidence: a named refusal code, no ladder state, no transaction id", async () => {
  const V = "d3".repeat(32);
  await seed(V);
  const request = await buildSpend(V, 5n);
  const stored = await wr4.loadRequest(config, request.requestId);
  stored.state = wr4.RequestState.AUTHORIZATION_FAILED;
  await wr4.saveRequest(config, stored);

  const body = (await GET(["attestations", "requests", request.requestId])).body;
  const rec = body.attestation;
  assert.equal(rec.authorization.decision, "REFUSED");
  assert.equal(rec.authorization.refusalCode, "AUTHORIZATION_FAILED");
  assert.deepEqual(rec.outcome.reached, []);
  assert.equal(rec.outcome.state, "REFUSED");
  assert.equal(rec.outcome.disposition, "REFUSED");
  assert.equal(rec.outcome.txId, null, "a refused execution never carries a transaction id");
  /* the intent bytes may still have matched their description exactly —
   * PolicyVault refused on AUTHORITY, and the record says which */
  assert.equal(rec.authorization.intentManifestVerdict, "VERIFIED_EXACT");
  assert.equal(body.verification.verdict, attest.VERDICTS.STRUCTURE_VERIFIED);
});

test("a signer's own refusal is NEVER misattributed to PolicyVault: decision AUTHORIZED, disposition FAILED, the exact failure code", async () => {
  const V = "da".repeat(32);
  await seed(V);
  for (const [state, expectedLadder] of [
    [wr4.RequestState.WALLET_REJECTED, ["AUTHORIZED"]],
    [wr4.RequestState.SIGNATURE_INVALID, ["AUTHORIZED"]],
    [wr4.RequestState.STALE, ["AUTHORIZED"]],
    [wr4.RequestState.SUBMISSION_REJECTED, ["AUTHORIZED", "SIGNED"]]
  ]) {
    const request = await buildSpend(V, 2n);
    const stored = await wr4.loadRequest(config, request.requestId);
    stored.state = state;
    await wr4.saveRequest(config, stored);
    const rec = (await GET(["attestations", "requests", request.requestId])).body.attestation;
    assert.equal(rec.authorization.decision, "AUTHORIZED", state);
    assert.equal(rec.authorization.refusalCode, null, state);
    assert.equal(rec.outcome.disposition, "FAILED", state);
    assert.equal(rec.outcome.failureCode, state, state);
    assert.deepEqual(rec.outcome.reached.map((r) => r.state), expectedLadder, state);
    assert.equal(rec.outcome.txId, null, `${state}: nothing was proven on chain`);
    assert.equal(attest.verifyAttestation(rec).verdict, attest.VERDICTS.STRUCTURE_VERIFIED, state);
  }
});

test("a request whose intent derivation FAILED exports as REFUSED — never mistakable for one that predates manifest recording", async () => {
  const V = "d4".repeat(32);
  await seed(V);
  const request = await buildSpend(V, 6n);
  const stored = await wr4.loadRequest(config, request.requestId);
  stored.intentRecording = "FAILED";
  await wr4.saveRequest(config, stored);

  const rec = (await GET(["attestations", "requests", request.requestId])).body.attestation;
  assert.equal(rec.authorization.decision, "REFUSED");
  assert.equal(rec.authorization.refusalCode, "INTENT_DERIVATION_FAILED");
  assert.deepEqual(rec.outcome.reached, []);
});

/* -------------------------------------------------------------------- */
/* 3b. genesis: a DIFFERENT durable shape, mapped explicitly            */
/* -------------------------------------------------------------------- */

test("a GENESIS request exports correctly despite carrying a different accounting shape — never a coerced or invented value", async () => {
  const VAULT = "db".repeat(32);
  const spk = require("../src/tx-identity").scriptPublicKeyForAddress(config, ADDR(owner));
  const created = await POST(["wallet", "v4", "create"], {
    templateInput: { owner: XO(owner), vaultId: VAULT },
    initialAgents: [{
      agentPk: XO(agentA), maxPerSpend: (20n * KAS).toString(), periodBudget: (50n * KAS).toString(),
      periodLengthDaa: "864000", periodStartDaa: "541000000", periodSpent: "0",
      approvalThreshold: (50n * KAS).toString(), agentMaxFeePerTx: (1n * KAS).toString(), recipients: [XO(recipient)]
    }],
    initialState: { protectedValue: (100n * KAS).toString(), feeReserve: (5n * KAS).toString(), approvers: [], approvalM: "0" },
    signerAddress: ADDR(owner),
    funding: [{ outpoint: { transactionId: "cd".repeat(32), index: 0 }, amount: (200n * KAS).toString(), scriptPublicKeyHex: typeof spk === "string" ? spk : spk.scriptHex }]
  });
  const request = await wr4.loadRequest(config, created.body.request.requestId);
  assert.equal(request.kind, "genesis");

  const body = (await GET(["attestations", "requests", request.requestId])).body;
  const rec = body.attestation;
  assert.equal(body.verification.verdict, attest.VERDICTS.STRUCTURE_VERIFIED);
  assert.deepEqual(body.verification.failureCodes, []);
  assert.equal(rec.action.type, "createVault");
  assert.equal(rec.action.role, "owner");
  assert.equal(rec.subject.stateBefore, null, "a genesis has no predecessor state");
  assert.equal(rec.subject.stateAfter, request.build.stateId);
  assert.equal(rec.amounts.amount, request.build.accounting.vaultValue, "the value locked into the new vault");
  assert.equal(rec.amounts.networkFeeSompi, request.build.requiredFeeSompi);
  assert.equal(rec.destination.kind, "COVENANT_SUCCESSOR");
  /* a genesis spends ordinary fuel: there is NO covenant sighash, and the
   * record says so instead of inventing one — while the signing identity
   * still comes from the committed manifest */
  assert.equal(rec.authorization.signerVisibleDigest, attest.NOT_AVAILABLE);
  assert.equal(rec.authorization.signerXOnly, XO(owner));
  assert.equal(rec.authorization.intentManifestVerdict, "VERIFIED_EXACT");
  assert.deepEqual(rec.outcome.reached.map((r) => r.state), ["AUTHORIZED"]);
  /* no financial field may ever be a coerced "undefined"/"null" string */
  assert.ok(!JSON.stringify(rec.amounts).includes("undefined"));

  /* advance to the proven genesis effect (the receipt records `outpoint`,
   * not `successorOutpoint`) and the ladder completes with a real address */
  const stored = await wr4.loadRequest(config, request.requestId);
  stored.state = wr4.RequestState.CHAIN_VERIFIED;
  await wr4.saveRequest(config, stored);
  await persistReceipt(config, {
    txId: request.txId, vaultId: VAULT, action: "createVault",
    proof: { requestId: request.requestId, outpoint: `${request.txId}:${request.vaultOutputIndex}`, covenantId: request.covenantId }
  });
  const settled = (await GET(["attestations", "requests", request.requestId])).body;
  assert.deepEqual(settled.attestation.outcome.reached.map((r) => r.state), ["AUTHORIZED", "SIGNED", "BROADCAST", "CHAIN_SEEN", "CHAIN_VERIFIED"]);
  assert.equal(settled.attestation.outcome.disposition, "SETTLED");
  assert.equal(settled.attestation.outcome.chain.successorStateId, request.build.stateId);
  assert.equal(settled.attestation.outcome.chain.outputs.length, 1);
  assert.equal(settled.attestation.outcome.chain.outputs[0].covenantId, request.covenantId);
  assert.match(settled.attestation.outcome.chain.outputs[0].address, /^kaspatest:/);
  assert.deepEqual(settled.verification.failureCodes, []);
});

/* -------------------------------------------------------------------- */
/* 4. exports round-trip and re-verify in a READER's hands              */
/* -------------------------------------------------------------------- */

test("an exported attestation round-trips through the canonical and NDJSON formats and re-verifies offline", async () => {
  const V = "d5".repeat(32);
  await seed(V);
  const request = await buildSpend(V, 7n);
  await advanceToChainVerified(request);

  const rec = (await GET(["attestations", "requests", request.requestId])).body.attestation;
  const canonical = attest.exportAttestationJson(rec);
  const back = attest.parseAttestationJson(canonical);
  assert.equal(attest.recomputeAttestationHash(back), rec.attestationHash);
  assert.equal(attest.verifyAttestation(back).verdict, attest.VERDICTS.STRUCTURE_VERIFIED);

  const ndjsonResponse = await GET(["attestations", "requests", request.requestId], { format: "ndjson" });
  assert.equal(ndjsonResponse.headers["Content-Type"], "application/x-ndjson; charset=utf-8");
  const parsed = attest.parseAttestationBatchNdjson(ndjsonResponse.rawBody);
  assert.equal(parsed.length, 1);
  assert.equal(attest.verifyAttestation(parsed[0]).verdict, attest.VERDICTS.STRUCTURE_VERIFIED);
  /* An attestation is a POINT-IN-TIME observation, so a second export of
   * the same request is a DIFFERENT record with its own identity — while
   * every underlying fact (the transaction, the manifest, the ladder) is
   * unchanged. That is the honest behaviour, and it is asserted here so a
   * future "optimisation" cannot silently make it a stale cached claim. */
  assert.notEqual(parsed[0].attestationHash, rec.attestationHash);
  assert.equal(parsed[0].outcome.txId, rec.outcome.txId);
  assert.equal(parsed[0].authorization.intentManifestHash, rec.authorization.intentManifestHash);
  assert.deepEqual(parsed[0].outcome.reached.map((r) => r.state), rec.outcome.reached.map((r) => r.state));

  /* the reader — not the issuer — catches tampering */
  const tampered = JSON.parse(canonical);
  tampered.amounts.amount = "1";
  const bad = attest.verifyAttestation(tampered);
  assert.equal(bad.verdict, attest.VERDICTS.INVALID);
  assert.deepEqual(bad.failureCodes, ["HASH_MISMATCH"]);

  /* and a pinned expectation catches a re-hashed substitution */
  tampered.attestationHash = attest.recomputeAttestationHash(tampered);
  const rehashed = attest.verifyAttestation(tampered, { expect: { requestId: request.requestId, vaultId: V, networkId: config.networkId } });
  assert.equal(rehashed.structural.ok, true, "integrity is intact — truth is not integrity");
  const wrongVault = attest.verifyAttestation(tampered, { expect: { vaultId: "ff".repeat(32) } });
  assert.ok(wrongVault.failureCodes.includes("EXPECTED_VAULT_MISMATCH"));
});

test("the batch export is bounded, ordered, digest-committed, and every line verifies", async () => {
  const V = "d6".repeat(32);
  await seed(V);
  const first = await buildSpend(V, 1n);
  await spend(V, 2n);
  await advanceToChainVerified(first);

  const body = (await GET(["attestations", "export"], { vaultId: V })).body;
  assert.equal(body.attestationVersion, attest.ATTESTATION_VERSION_1);
  assert.equal(body.count, 2);
  assert.deepEqual(body.vaults, [V]);
  assert.match(body.batchDigest, /^[0-9a-f]{64}$/);
  for (const entry of body.records) {
    assert.equal(entry.verification.verdict, attest.VERDICTS.STRUCTURE_VERIFIED);
    assert.equal(entry.attestation.subject.vaultId, V);
  }
  assert.equal(body.batchDigest, attest.computeBatchDigest(body.records.map((r) => r.attestation)));

  const nd = await GET(["attestations", "export"], { vaultId: V, format: "ndjson" });
  const parsed = attest.parseAttestationBatchNdjson(nd.rawBody);
  assert.equal(parsed.length, 2);
  for (const record of parsed) assert.equal(attest.verifyAttestation(record).verdict, attest.VERDICTS.STRUCTURE_VERIFIED);
  assert.deepEqual(parsed.map((r) => r.subject.requestId), body.records.map((r) => r.attestation.subject.requestId));

  const limited = (await GET(["attestations", "export"], { vaultId: V, limit: "1" })).body;
  assert.equal(limited.count, 1);
});

test("the batch export can be scoped by ORGANIZATION, and an org row only narrows to vaults the caller could already read", async () => {
  const V1 = "dc".repeat(32);
  const V2 = "dd".repeat(32);
  await seed(V1);
  await seed(V2);
  await buildSpend(V1, 1n);
  await buildSpend(V2, 2n);

  const orgId = (await POST(["organizations"], { name: "attest-org" })).body.organization.orgId;
  const assignments = (await GET(["organizations", orgId])).body;
  await POST(["organizations", orgId, "vaults"], { vaultId: V1, expectedVersion: assignments.assignmentsVersion ?? 0 });

  const body = (await GET(["attestations", "export"], { organizationId: orgId })).body;
  assert.deepEqual(body.vaults, [V1], "only the ASSIGNED vault is in scope");
  assert.equal(body.count, 1);
  assert.equal(body.records[0].attestation.subject.vaultId, V1);
  assert.equal(body.records[0].attestation.subject.organizationId, orgId, "the assignment is reported on the record");
  assert.equal(body.records[0].verification.verdict, attest.VERDICTS.STRUCTURE_VERIFIED);

  /* the unassigned vault's own export is unaffected and reports no org */
  const solo = (await GET(["attestations", "export"], { vaultId: V2 })).body;
  assert.equal(solo.records[0].attestation.subject.organizationId, null);

  await expectThrow(GET(["attestations", "export"], { organizationId: "11111111-2222-4333-8444-555555555555" }), 404, "ORG_NOT_FOUND");
});

test("the batch export refuses an ambiguous or missing scope, an unknown format, and an unknown route", async () => {
  const V = "d7".repeat(32);
  await seed(V);
  await expectThrow(GET(["attestations", "export"], {}), 400, "ATTESTATION_SCOPE_REQUIRED");
  await expectThrow(GET(["attestations", "export"], { vaultId: V, organizationId: "11111111-2222-4333-8444-555555555555" }), 400, "ATTESTATION_SCOPE_REQUIRED");
  await expectThrow(GET(["attestations", "export"], { vaultId: V, format: "csv" }), 400, "BAD_FORMAT");
  await expectThrow(GET(["attestations", "export"], { vaultId: "ee".repeat(32) }), 404, "VAULT_NOT_FOUND");
  await expectThrow(GET(["attestations", "requests", "11111111-2222-4333-8444-999999999999"]), 404, "REQUEST_NOT_FOUND");
  await expectThrow(GET(["attestations", "nonsense"]), 404, "NOT_FOUND");
});

/* -------------------------------------------------------------------- */
/* 5. scope + tenancy gating                                            */
/* -------------------------------------------------------------------- */

test("attestation export is DENY-BY-DEFAULT for machine credentials: a dedicated read:attestations scope, implied by nothing else", () => {
  assert.ok(SCOPES.includes("read:attestations"));
  assert.deepEqual(requiredScopesFor("GET", ["attestations", "requests", "x"], null), ["read:attestations"]);
  assert.deepEqual(requiredScopesFor("GET", ["attestations", "export"], null), ["read:attestations"]);
  /* neither read:requests nor read:manifests may stand in for it */
  assert.deepEqual(requiredScopesFor("GET", ["wallet", "v4", "requests", "x"], null), ["read:requests"]);
  assert.deepEqual(requiredScopesFor("GET", ["manifests", "x"], null), ["read:manifests"]);
  /* mutation over the attestations namespace is unreachable at any scope */
  assert.equal(requiredScopesFor("POST", ["attestations", "export"], null), null);
});

test("hosted mode requires an authenticated principal for every attestation route", async () => {
  const hosted = loadConfig({ dataRoot, authMode: "enabled", authCookieInsecure: true });
  assert.equal(hosted.tenancyEnforced, true);
  await expectThrow(GET(["attestations", "requests", "11111111-2222-4333-8444-555555555555"], {}, hosted), 401);
  await expectThrow(GET(["attestations", "export"], { vaultId: "d1".repeat(32) }, hosted), 401);
});

/* -------------------------------------------------------------------- */
/* 6. no secrets, and no forbidden language                             */
/* -------------------------------------------------------------------- */

test("NO-SECRET SWEEP: an exported attestation document carries no key material, credential, or raw signature", async () => {
  const V = "d8".repeat(32);
  await seed(V);
  const request = await buildSpend(V, 8n);
  await advanceToChainVerified(request);
  const body = (await GET(["attestations", "export"], { vaultId: V })).body;
  const text = JSON.stringify(body);

  for (const banned of ["privateKey", "secret", "seed", "mnemonic", "Bearer", "token_hash", "cookie", "password", "signatureScript", "unsignedSafeJson", "finalTransaction"]) {
    assert.ok(!text.includes(banned), `an attestation export must never carry ${banned}`);
  }
  /* the private half of every test key stays out of the document */
  for (const key of [owner, agentA, recipient]) {
    assert.ok(!text.includes(key.toString()), "no private key material may appear");
  }
  /* public identities that the covenant itself binds are expected */
  assert.ok(text.includes(XO(agentA)), "the signing identity is a public identifier and is part of the evidence");
});

test("the rendered human summary of an exported attestation uses none of the forbidden vocabulary", async () => {
  const V = "d9".repeat(32);
  await seed(V);
  const request = await buildSpend(V, 9n);
  await advanceToChainVerified(request);
  const rec = (await GET(["attestations", "requests", request.requestId])).body.attestation;
  const verification = attest.verifyAttestation(rec);
  const text = attest.attestationSummary.humanReadable(rec, verification);
  assert.deepEqual(attest.forbiddenLanguageHits(text), []);
  assert.ok(text.includes("PolicyVault policy-execution attestation"));
  assert.ok(text.includes("VERIFIED CHAIN OUTCOME"));
});
