"use strict";

/*
 * RC-LC-1 REGRESSION + ADVERSARIAL SUITE (JSON store) — finding from the
 * fullscale-rc1 controlled-mainnet acceptance
 * (docs/postlaunch/rc-mainnet-acceptance-evidence.md §5.3).
 *
 * THE DEFECT (frozen fullscale-rc1 behavior this suite is RED on):
 * store.createExclusive() returns false on an existing key, and
 * recordManifestForRequest() never checked the return — a rebuild of an
 * identical intent after a reject silently "recorded" nothing, appended
 * a misleading "recorded (VERIFIED_EXACT)" audit row, let the WALLET
 * SIGNATURE happen, and only then refused at finalize with
 * INTENT_MANIFEST_INTEGRITY, because the finalize gate bound the
 * content-addressed record to its CREATOR's requestId. Live cost: two
 * consumed owner signatures with zero broadcasts + an operator store
 * intervention.
 *
 * FIXED SEMANTICS (v2 — aligned with the binding conformance contract):
 * manifest records are CONTENT-ADDRESSED SHARED EVIDENCE. Any number of
 * byte-identical requests (multi-path builds, rebuilds after reject,
 * concurrent identical drives — conformance C05/C06/C14) legitimately
 * share the one record; the finalize gate binds by CONTENT (the
 * manifest's committed txId must equal the request's own frozen txId),
 * which preserves the anti-repoint tamper property exactly. false from
 * createExclusive is handled explicitly (G-2-verified share, truthful
 * audit: created / shared-from / reused are distinct; an idempotent
 * same-request replay appends nothing).
 *
 * Harness: REAL server api.handle over a temp JSON data root, REAL v0.4
 * build pipeline + encoder + VM preflight, deterministic dev signer
 * (KasWare signPskt contract). Offline; nothing is ever broadcast.
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
const { getStore, Categories } = require("../src/store");

const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "pv-rclc1-"));
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

const template = (vaultId) => ({ owner: XO(owner), vaultId });

function agentEntry(kp, recipients) {
  return {
    agentPk: XO(kp), maxPerSpend: (20n * KAS).toString(), periodBudget: (50n * KAS).toString(),
    periodLengthDaa: "864000", periodStartDaa: "541000000", periodSpent: "0",
    approvalThreshold: (30n * KAS).toString(), agentMaxFeePerTx: (1n * KAS).toString(),
    recipients: recipients.map(XO)
  };
}

let seedCounter = 0;
async function seed(vaultId) {
  seedCounter += 1;
  const outTxId = seedCounter.toString(16).padStart(2, "0").repeat(32).slice(0, 64);
  const registry = [agentEntry(agentA, [recipient])];
  const policies = registry.map((e) => normalizeAgentPolicyV4({ ...e, agentRecipientRoot: buildRecipientTree(e.recipients).root }));
  const agentRoot = buildAgentTreeV4(policies).root;
  const state = normalizeStateV4({
    protectedValue: (1000n * KAS).toString(), feeReserve: (5n * KAS).toString(),
    paused: "0", agentRoot, approvers: [], approvalM: "0", policyNonce: "0"
  });
  const compiled = compileExactStateV4({ config, template: template(vaultId), state });
  const stateId = computeStateIdV4({ networkId: config.networkId, template: template(vaultId), state });
  await persistManifestV4(config, {
    schema: MANIFEST_SCHEMA_V4, contractVersion: CONTRACT_VERSION_V4, networkId: config.networkId, vaultId,
    label: "rc-lc1", status: "ACTIVE", template: template(vaultId), agentRegistry: registry,
    live: { state: stateToJsonV4(state), stateId, outpoint: { transactionId: outTxId, index: 0 }, outpointValue: (state.protectedValue + state.feeReserve).toString(), scriptSha256: compiled.scriptSha256, covenantId: "41".repeat(32) },
    creationTxId: "42".repeat(32), latestTransitionTxId: null, lastTransition: null
  });
  return vaultId;
}

const POST = (segs, body) => handle(config, "POST", segs, {}, body);

async function expectThrow(promise, status, code) {
  try {
    await promise;
    assert.fail("expected an API error");
  } catch (e) {
    if (status !== undefined) assert.equal(e.status, status, `status ${e.status} != ${status}: ${e.message}`);
    if (code !== undefined) assert.equal(e.code, code, `code ${e.code} != ${code}: ${e.message}`);
    return e;
  }
}

/* SIGNER INVOCATION COUNTER (owner requirement): every wallet-contract
 * signing in this suite goes through here; scenarios assert exact
 * counts — a conflict detectable pre-sign must never consume one. */
let signerCalls = 0;
function devSignAll(request, kp, secret) {
  signerCalls += 1;
  const signer = makeDevSigner(config, { secretHex: SEC(secret), expectedAddress: ADDR(kp) });
  return signer.signInputs(request.transaction.unsignedSafeJson, request.transaction.signInputs);
}
const signAgent = (req) => devSignAll(req, agentA, 0x1e);
const signOwner = (req) => devSignAll(req, owner, 1);

const spendBody = (vaultId, paySompi) => ({
  vaultId, action: "agentSpend",
  params: { payAmountSompi: paySompi.toString(), agentPk: XO(agentA), recipient: XO(recipient) },
  signerAddress: ADDR(agentA)
});
const ownerFuel = (n) => ({ outpoint: { transactionId: n.toString(16).padStart(2, "0").repeat(32).slice(0, 64), index: 1 }, amount: (100n * KAS).toString(), scriptPublicKeyHex: `20${XO(owner)}ac` });
const pauseBody = (vaultId, fuelN) => ({ vaultId, action: "ownerPause", params: { fuel: ownerFuel(fuelN) }, signerAddress: ADDR(owner) });

const store = () => getStore(config);
const auditLines = () => {
  const p = path.join(dataRoot, "audit", "events.log");
  return fs.existsSync(p) ? fs.readFileSync(p, "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l)) : [];
};
const reservationFiles = () => {
  const p = path.join(dataRoot, "claims", "transition");
  return fs.existsSync(p) ? fs.readdirSync(p).filter((f) => f.startsWith("resv-")) : [];
};
async function manifestRecord(hash) {
  return store().read(Categories.INTENT_MANIFEST, hash);
}

/* =================== THE ORIGINAL FAILURE SEQUENCE ===================
 * RED on frozen fullscale-rc1 (audit misled + the finalize gate refused
 * AFTER the signature). GREEN on v2: the rebuild SHARES the
 * content-addressed record and finalizes, with exactly one signer
 * invocation and truthful audit. */
test("RC-LC-1: build -> reject -> IDENTICAL rebuild -> sign -> finalize succeeds (shared content-addressed record, one signature)", async () => {
  const vaultId = await seed("a1".repeat(32));
  const r1 = (await POST(["wallet", "v4", "requests"], spendBody(vaultId, 4n * KAS))).body.request;
  assert.equal(r1.state, "BUILT");
  const rej = await POST(["wallet", "v4", "requests", r1.requestId, "reject"], {});
  assert.equal(rej.body.request.state, "WALLET_REJECTED");
  assert.equal(reservationFiles().length, 0, "reject released the reservation");

  const before = signerCalls;
  const r2 = (await POST(["wallet", "v4", "requests"], spendBody(vaultId, 4n * KAS))).body.request;
  assert.equal(r2.state, "BUILT");
  assert.notEqual(r2.requestId, r1.requestId);
  assert.equal(r2.manifestHash, r1.manifestHash, "identical intent derives the identical manifest hash");
  assert.equal(r2.txId, r1.txId, "deterministic rebuild is byte-identical");

  // Content-addressed evidence: ONE record, creator provenance intact.
  const rec = await manifestRecord(r2.manifestHash);
  assert.equal(rec.requestId, r1.requestId, "the record keeps its creator provenance (content-addressed, shared)");

  // Audit truth: one real "recorded" row + one "shared" row naming the
  // creator; never a second creation claim.
  const rows = auditLines().filter((r) => r.manifestHash === r2.manifestHash);
  assert.equal(rows.filter((r) => String(r.detail ?? "").includes("recorded (")).length, 1, "exactly one true 'recorded' row");
  const shared = rows.filter((r) => String(r.detail ?? "").includes("shared as this request"));
  assert.equal(shared.length, 1, "exactly one truthful 'shared' row for the rebuild");
  assert.ok(String(shared[0].detail).includes(r1.requestId), "the share names the creating request");
  assert.equal(shared[0].requestId, r2.requestId);

  // Sign ONCE; the finalize gate binds by CONTENT and passes.
  const done = await POST(["wallet", "v4", "requests", r2.requestId, "signature"], { signedSafeJson: signAgent(r2) });
  assert.equal(done.body.request.state, "PREFLIGHT_VERIFIED");
  assert.equal(signerCalls - before, 1, "EXACTLY ONE signer invocation for the whole reject->rebuild->finalize journey");
});

test("RC-LC-1: rebuild with CHANGED intent creates a fresh record; the rejected request's record stays intact as evidence", async () => {
  const vaultId = await seed("a2".repeat(32));
  const r1 = (await POST(["wallet", "v4", "requests"], spendBody(vaultId, 4n * KAS))).body.request;
  await POST(["wallet", "v4", "requests", r1.requestId, "reject"], {});
  const r2 = (await POST(["wallet", "v4", "requests"], spendBody(vaultId, 3n * KAS))).body.request;
  assert.notEqual(r2.manifestHash, r1.manifestHash, "changed intent => different manifest hash");
  assert.equal((await manifestRecord(r1.manifestHash)).requestId, r1.requestId, "history preserved");
  assert.equal((await manifestRecord(r2.manifestHash)).requestId, r2.requestId);
  const done = await POST(["wallet", "v4", "requests", r2.requestId, "signature"], { signedSafeJson: signAgent(r2) });
  assert.equal(done.body.request.state, "PREFLIGHT_VERIFIED");
});

/* The conformance C05 contract at the unit boundary: concurrent LIVE
 * identical builds are PERMITTED, each a distinct durable request
 * sharing the one content-addressed record. Broadcast exclusivity is
 * arbitrated at the DESIGNED layer: the first finalize takes the
 * predecessor transition claim; the duplicate refuses CLAIM_CONFLICT
 * fail-closed (C14 honesty) — never two broadcastable packages. */
test("RC-LC-1: two LIVE identical builds coexist (C05 contract) sharing one record; finalize exclusivity stays with the claim arbiter", async () => {
  const vaultId = await seed("a3".repeat(32));
  const p1 = (await POST(["wallet", "v4", "requests"], pauseBody(vaultId, 0x51))).body.request;
  const p2 = (await POST(["wallet", "v4", "requests"], pauseBody(vaultId, 0x51))).body.request;
  assert.notEqual(p1.requestId, p2.requestId, "distinct durable requests");
  assert.equal(p1.txId, p2.txId, "identical transition freezes the identical transaction");
  assert.equal(p1.manifestHash, p2.manifestHash);
  assert.equal((await manifestRecord(p1.manifestHash)).requestId, p1.requestId, "creator provenance");
  const d1 = await POST(["wallet", "v4", "requests", p1.requestId, "signature"], { signedSafeJson: signOwner(p1) });
  assert.equal(d1.body.request.state, "PREFLIGHT_VERIFIED");
  // The duplicate passes the CONTENT gate but the transition-claim
  // arbiter (first-finalize-wins) refuses it fail-closed — the designed
  // broadcast-exclusivity layer, untouched by this remediation.
  await expectThrow(
    POST(["wallet", "v4", "requests", p2.requestId, "signature"], { signedSafeJson: signOwner(p2) }),
    undefined,
    "CLAIM_CONFLICT"
  );
  const p2After = await store().read(Categories.REQUEST, p2.requestId);
  assert.equal(p2After.state, "CLAIM_CONFLICT", "the losing duplicate is closed fail-closed");
});

/* Anti-repoint tamper property (the hostile-manifest 106 class): a
 * request stamped with a DIFFERENT intent's hash must refuse — the
 * content binding (manifest.transaction.txId == request.txId) is the
 * gate that survives the shared-evidence redesign. */
test("RC-LC-1: a repointed manifestHash (different transaction) refuses INTENT_MANIFEST_INTEGRITY at finalize", async () => {
  const vaultId = await seed("a4".repeat(32));
  const r1 = (await POST(["wallet", "v4", "requests"], spendBody(vaultId, 4n * KAS))).body.request;
  const r2 = (await POST(["wallet", "v4", "requests"], spendBody(vaultId, 3n * KAS))).body.request;
  const raw = await store().read(Categories.REQUEST, r2.requestId);
  raw.manifestHash = r1.manifestHash; // hostile repoint
  await store().write(Categories.REQUEST, r2.requestId, raw);
  await expectThrow(
    POST(["wallet", "v4", "requests", r2.requestId, "signature"], { signedSafeJson: signAgent(r2) }),
    409,
    "INTENT_MANIFEST_INTEGRITY"
  );
});

test("RC-LC-1: recovery after a vanished record (crash boundary) — the rebuild recreates it cleanly", async () => {
  const vaultId = await seed("a6".repeat(32));
  const r1 = (await POST(["wallet", "v4", "requests"], spendBody(vaultId, 4n * KAS))).body.request;
  await POST(["wallet", "v4", "requests", r1.requestId, "reject"], {});
  await store().remove(Categories.INTENT_MANIFEST, r1.manifestHash);
  const r2 = (await POST(["wallet", "v4", "requests"], spendBody(vaultId, 4n * KAS))).body.request;
  assert.equal((await manifestRecord(r2.manifestHash)).requestId, r2.requestId, "recreated with the rebuild as creator");
  const done = await POST(["wallet", "v4", "requests", r2.requestId, "signature"], { signedSafeJson: signAgent(r2) });
  assert.equal(done.body.request.state, "PREFLIGHT_VERIFIED");
});

test("RC-LC-1: idempotent replay of the SAME request reuses its own record silently (no duplicate audit rows)", async () => {
  const vaultId = await seed("a7".repeat(32));
  const r1 = (await POST(["wallet", "v4", "requests"], spendBody(vaultId, 4n * KAS))).body.request;
  const { recordManifestForRequest } = require("../../server/src/intent-records");
  const wr4 = require("../src/wallet-requests-v4");
  const durable = await wr4.loadRequest(config, r1.requestId);
  const replay = await recordManifestForRequest(config, durable, { proposalId: null });
  assert.equal(replay.ok, true);
  assert.equal((await manifestRecord(r1.manifestHash)).requestId, r1.requestId, "binding unchanged on idempotent replay");
  const rows = auditLines().filter((r) => r.manifestHash === r1.manifestHash);
  assert.equal(rows.filter((r) => String(r.detail ?? "").includes("recorded (")).length, 1, "replay never claims a second creation");
  assert.equal(rows.filter((r) => String(r.detail ?? "").includes("shared as this request")).length, 0, "a same-request replay is not a share");
});

test("RC-LC-1: a tampered stored record refuses at BUILD (before any signer invocation) via the G-2 re-hash", async () => {
  const vaultId = await seed("a8".repeat(32));
  const r1 = (await POST(["wallet", "v4", "requests"], spendBody(vaultId, 4n * KAS))).body.request;
  await POST(["wallet", "v4", "requests", r1.requestId, "reject"], {});
  const rec = await manifestRecord(r1.manifestHash);
  rec.manifest.requested.params.payAmountSompi = (9n * KAS).toString(); // tamper the content
  await store().write(Categories.INTENT_MANIFEST, r1.manifestHash, rec);
  const before = signerCalls;
  // surfaces via the derivation-failure wrapper (422) with the
  // integrity code preserved — the essential property is that it fires
  // at BUILD, before any signer invocation
  await expectThrow(POST(["wallet", "v4", "requests"], spendBody(vaultId, 4n * KAS)), 422, "INTENT_MANIFEST_INTEGRITY");
  assert.equal(signerCalls, before, "tampering is detected at BUILD — zero signer invocations");
  await store().remove(Categories.INTENT_MANIFEST, r1.manifestHash); // clean up the tampered record
});

/* =================== SABOTAGE / MUTATION SENSITIVITY ===================
 * Neutralize the finalize CONTENT binding: the hostile repoint must then
 * pass finalize (the property this suite protects would be lost),
 * proving the regression is sensitive to exactly this guard. */
test("RC-LC-1 sabotage: removing the finalize content-binding lets a repointed request finalize (guard sensitivity)", async () => {
  const srcPath = require.resolve("../../server/src/intent-records.js");
  const original = fs.readFileSync(srcPath, "utf8");
  const TARGET = "if (!record.manifest || !record.manifest.transaction || record.manifest.transaction.txId !== request.txId) {";
  assert.ok(original.includes(TARGET), "content-binding guard present before sabotage");
  const sabotaged = original.replace(TARGET, "if (false) {");
  fs.writeFileSync(srcPath, sabotaged);
  try {
    for (const k of Object.keys(require.cache)) {
      if (k.endsWith(`${path.sep}intent-records.js`) || k.endsWith(`${path.sep}api.js`)) delete require.cache[k];
    }
    const { handle: h2 } = require("../../server/src/api");
    const P2 = (segs, body) => h2(config, "POST", segs, {}, body);
    const vaultId = await seed("a9".repeat(32));
    const r1 = (await P2(["wallet", "v4", "requests"], spendBody(vaultId, 4n * KAS))).body.request;
    const r2 = (await P2(["wallet", "v4", "requests"], spendBody(vaultId, 3n * KAS))).body.request;
    const raw = await store().read(Categories.REQUEST, r2.requestId);
    raw.manifestHash = r1.manifestHash; // hostile repoint
    await store().write(Categories.REQUEST, r2.requestId, raw);
    const done = await P2(["wallet", "v4", "requests", r2.requestId, "signature"], { signedSafeJson: signAgent(r2) });
    assert.equal(done.body.request.state, "PREFLIGHT_VERIFIED", "sabotaged gate accepts the repoint — the guard is what stops it");
  } finally {
    fs.writeFileSync(srcPath, original);
    for (const k of Object.keys(require.cache)) {
      if (k.endsWith(`${path.sep}intent-records.js`) || k.endsWith(`${path.sep}api.js`)) delete require.cache[k];
    }
  }
});
