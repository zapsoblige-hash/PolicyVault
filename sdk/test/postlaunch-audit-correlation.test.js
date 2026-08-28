"use strict";

/*
 * POSTLAUNCH AUDIT CORRELATION — server writes + G-2 read discipline
 * (completion-standard item 7; docs/postlaunch/audit-correlation-spec.md).
 *
 * Real server api.handle + real v0.4 builds over a temp JSON data root:
 *   - the build routes persist ONE intent-manifest record per build,
 *     keyed by the representation-independent manifestHash, embedding
 *     the requested intent, with the verification verdict recorded;
 *   - the wallet request is stamped with manifestHash (correlation
 *     spine: requestId -> manifestHash -> txId);
 *   - audit events carry the correlation fields inline (requestId,
 *     manifestHash, txId, actorXOnly);
 *   - READ-SIDE RE-HASH (G-2): a tampered stored manifest fails closed
 *     on read AND blocks finalize (INTENT_MANIFEST_INTEGRITY);
 *   - a request whose manifest record was deleted fails closed at
 *     finalize (INTENT_MANIFEST_MISSING);
 *   - requests PREDATING manifest recording (no manifestHash) pass the
 *     finalize gate unchanged — verification claims are never
 *     backfilled and old requests are never blocked (spec §10);
 *   - the finalize gate re-runs the verifier NOW (never merely trusting
 *     the recorded verdict).
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");
const os = require("os");

const { handle, loadConfig } = require("../../server/src/api");
const { buildAgentTreeV4, normalizeAgentPolicyV4 } = require("../src/agent-merkle-v4");
const { buildRecipientTree } = require("../src/recipient-merkle-v3");
const { normalizeStateV4, computeStateIdV4, stateToJsonV4, CONTRACT_VERSION_V4 } = require("../src/vault-state-v4");
const { compileExactStateV4 } = require("../src/contract-compiler-v4");
const { MANIFEST_SCHEMA_V4, persistManifestV4 } = require("../src/manifest-v4");
const { makeDevSigner } = require("../src/signer-dev");
const { readAudit } = require("../src/audit");
const { loadManifestRecord } = require("../../server/src/intent-records");
const { computeManifestHashV1 } = require("../../core/intent");

const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "pv-corr-"));
const config = loadConfig({ dataRoot });
const kaspa = require(config.rustyKaspaModule);
const KEY = (v) => new kaspa.PrivateKey(v.toString(16).padStart(2, "0").repeat(32));
const SEC = (v) => v.toString(16).padStart(2, "0").repeat(32);
const XO = (p) => p.toPublicKey().toXOnlyPublicKey().toString().toLowerCase();
const ADDR = (p) => p.toPublicKey().toAddress(config.networkId).toString();
const KAS = 100000000n;

const owner = KEY(1);
const agentA = KEY(0x1e);
const recipient = KEY(0x28);

const VAULT_ID = "37".repeat(32);
const template = { owner: XO(owner), vaultId: VAULT_ID };
const REGISTRY = [
  {
    agentPk: XO(agentA), maxPerSpend: (20n * KAS).toString(), periodBudget: (50n * KAS).toString(),
    periodLengthDaa: "864000", periodStartDaa: "541000000", periodSpent: "0",
    approvalThreshold: (50n * KAS).toString(), agentMaxFeePerTx: (1n * KAS).toString(),
    recipients: [XO(recipient)]
  }
];

let seedCounter = 0;
async function seed() {
  seedCounter += 1;
  const outTxId = (0x50 + seedCounter).toString(16).padStart(2, "0").repeat(32).slice(0, 64);
  const policies = REGISTRY.map((e) => normalizeAgentPolicyV4({ ...e, agentRecipientRoot: buildRecipientTree(e.recipients).root }));
  const agentRoot = buildAgentTreeV4(policies).root;
  const state = normalizeStateV4({ protectedValue: (1000n * KAS).toString(), feeReserve: (5n * KAS).toString(), paused: "0", agentRoot, approvers: [], approvalM: "0", policyNonce: "0" });
  const compiled = compileExactStateV4({ config, template, state });
  const stateId = computeStateIdV4({ networkId: config.networkId, template, state });
  return await persistManifestV4(config, {
    schema: MANIFEST_SCHEMA_V4, contractVersion: CONTRACT_VERSION_V4, networkId: config.networkId, vaultId: VAULT_ID,
    label: "correlation test", status: "ACTIVE", template, agentRegistry: REGISTRY,
    live: { state: stateToJsonV4(state), stateId, outpoint: { transactionId: outTxId, index: 0 }, outpointValue: (state.protectedValue + state.feeReserve).toString(), scriptSha256: compiled.scriptSha256, covenantId: "41".repeat(32) },
    creationTxId: "42".repeat(32), latestTransitionTxId: null, lastTransition: null
  });
}

const POST = (segs, body) => handle(config, "POST", segs, {}, body);
const GET = (segs) => handle(config, "GET", segs, {}, null);
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
function devSignAll(request, kp, secret) {
  const signer = makeDevSigner(config, { secretHex: SEC(secret), expectedAddress: ADDR(kp) });
  return signer.signInputs(request.transaction.unsignedSafeJson, request.transaction.signInputs);
}
const spend = () => POST(["wallet", "v4", "requests"], {
  vaultId: VAULT_ID, action: "agentSpend",
  params: { payAmountSompi: (4n * KAS).toString(), agentPk: XO(agentA), recipient: XO(recipient) },
  signerAddress: ADDR(agentA)
});
const manifestFile = (hash) => path.join(dataRoot, "manifests", `${hash}.json`);

test("build persists the manifest record; the correlation spine holds request -> manifest -> tx; audit carries the fields", async () => {
  await seed();
  const built = await spend();
  assert.equal(built.status, 201);
  const req = built.body.request;
  assert.match(req.manifestHash, /^[0-9a-f]{64}$/);

  // the durable record exists, keyed by the hash, embedding the intent
  const record = await loadManifestRecord(config, req.manifestHash);
  assert.equal(record.requestId, req.requestId);
  assert.equal(record.txId, req.txId);
  assert.equal(record.vaultId, VAULT_ID);
  assert.equal(record.verification.verdict, "VERIFIED_EXACT");
  assert.equal(record.manifest.requested.intentVersion, "policyvault-requested-intent/1");
  assert.equal(record.manifest.requested.action, "agentSpend");
  assert.equal(record.manifest.transaction.txId, req.txId);

  // representation independence: recompute over the stored body
  const { manifestHash, ...body } = record.manifest;
  assert.equal(computeManifestHashV1(body), req.manifestHash);

  // the wallet request row itself is stamped (wallet_requests_manifest_idx target)
  const stored = JSON.parse(fs.readFileSync(path.join(dataRoot, "requests", `${req.requestId}.json`), "utf8"));
  assert.equal(stored.manifestHash, req.manifestHash);

  // audit evidence carries the correlation fields inline
  const events = await readAudit(config, { vaultId: VAULT_ID, limit: 50 });
  const ev = events.find((e) => e.kind === "intent" && e.requestId === req.requestId);
  assert.ok(ev, "an intent audit event exists for the build");
  assert.equal(ev.manifestHash, req.manifestHash);
  assert.equal(ev.txId, req.txId);
  assert.equal(ev.actorXOnly, XO(agentA));

  // the read endpoint re-verifies NOW
  const readback = await GET(["manifests", req.manifestHash]);
  assert.equal(readback.body.liveVerification.ok, true);
});

test("G-2 read-side re-hash: a tampered stored manifest fails closed on read AND blocks finalize", async () => {
  await seed();
  const built = await spend();
  const req = built.body.request;
  const file = manifestFile(req.manifestHash);
  const record = JSON.parse(fs.readFileSync(file, "utf8"));
  record.manifest.payment.amountSompi = (999n * KAS).toString(); // tamper one committed value
  fs.writeFileSync(file, JSON.stringify(record));

  await expectThrow(GET(["manifests", req.manifestHash]), 409, "INTENT_MANIFEST_INTEGRITY");
  const signed = devSignAll(req, agentA, 0x1e);
  await expectThrow(POST(["wallet", "v4", "requests", req.requestId, "signature"], { signedSafeJson: signed }), 409, "INTENT_MANIFEST_INTEGRITY");
});

test("a deleted manifest record fails closed at finalize (INTENT_MANIFEST_MISSING)", async () => {
  await seed();
  const built = await spend();
  const req = built.body.request;
  fs.unlinkSync(manifestFile(req.manifestHash));
  const signed = devSignAll(req, agentA, 0x1e);
  await expectThrow(POST(["wallet", "v4", "requests", req.requestId, "signature"], { signedSafeJson: signed }), 409, "INTENT_MANIFEST_MISSING");
});

test("backward compatibility: a request predating manifest recording (no manifestHash) finalizes unchanged", async () => {
  await seed();
  const built = await spend();
  const req = built.body.request;
  // simulate a pre-upgrade request: strip the stamp from the durable row
  const reqFile = path.join(dataRoot, "requests", `${req.requestId}.json`);
  const stored = JSON.parse(fs.readFileSync(reqFile, "utf8"));
  delete stored.manifestHash;
  fs.writeFileSync(reqFile, JSON.stringify(stored));
  const signed = devSignAll(req, agentA, 0x1e);
  const done = await POST(["wallet", "v4", "requests", req.requestId, "signature"], { signedSafeJson: signed });
  assert.equal(done.status, 200);
  assert.equal(done.body.request.state, "PREFLIGHT_VERIFIED");
});

test("an intact manifest-stamped request finalizes through the gate to PREFLIGHT_VERIFIED", async () => {
  await seed();
  const built = await spend();
  const req = built.body.request;
  const signed = devSignAll(req, agentA, 0x1e);
  const done = await POST(["wallet", "v4", "requests", req.requestId, "signature"], { signedSafeJson: signed });
  assert.equal(done.status, 200);
  assert.equal(done.body.request.state, "PREFLIGHT_VERIFIED");
  // the PREFLIGHT_VERIFIED audit event (SDK writer) still correlates by txId
  const events = await readAudit(config, { vaultId: VAULT_ID, limit: 50 });
  assert.ok(events.some((e) => e.result === "PREFLIGHT_VERIFIED" && e.txId === req.txId));
});

test("a request marked intentRecording FAILED (derivation failure at build) is refused at the finalize/submit gate", async () => {
  const { assertRequestManifestVerified } = require("../../server/src/intent-records");
  // A derivation failure must never be mistakable for a request that
  // merely predates manifest recording: the marker fails closed.
  await assert.rejects(
    () => assertRequestManifestVerified(config, { requestId: "r", vaultId: VAULT_ID, intentRecording: "FAILED" }),
    (e) => e.code === "INTENT_VERIFICATION_FAILED" && e.status === 409
  );
  // …while a request with neither marker nor manifestHash still passes
  // (the honest predates-recording allowance).
  assert.equal(await assertRequestManifestVerified(config, { requestId: "r", vaultId: VAULT_ID }), null);
});

test("genesis create persists a VERIFIED_EXACT genesis manifest record too", async () => {
  const funding = [{ outpoint: { transactionId: "66".repeat(32), index: 0 }, amount: (2000n * KAS).toString(), scriptPublicKeyHex: `20${XO(owner)}ac` }];
  const created = await POST(["wallet", "v4", "create"], {
    templateInput: { owner: XO(owner), vaultId: "38".repeat(32) },
    initialAgents: REGISTRY,
    initialState: { protectedValue: (900n * KAS).toString(), feeReserve: (5n * KAS).toString(), approvers: [], approvalM: "0" },
    signerAddress: ADDR(owner),
    funding
  });
  assert.equal(created.status, 201);
  const req = created.body.request;
  assert.match(req.manifestHash, /^[0-9a-f]{64}$/);
  const record = await loadManifestRecord(config, req.manifestHash);
  assert.equal(record.verification.verdict, "VERIFIED_EXACT");
  assert.equal(record.manifest.requested.action, "createVault");
});
