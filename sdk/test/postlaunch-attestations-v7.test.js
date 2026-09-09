"use strict";

/*
 * SDK/INTEGRATION: v0.7 ORGANIZATIONAL ROOT execution attestations
 * (Wave 2, Track G) — `server/src/attestations-v7.js` mapping REAL
 * `policyvault-org-root-manifest/1` / `policyvault-rooted-vault-manifest/1`
 * objects (built through the REAL v0.7 SDK builders: silverc, the
 * production pv_call_encoder, pv_tx_probe) into
 * `policyvault-execution-attestation/1` records, then re-verified through
 * the SAME shared verifier (`core/attest`) every other generation uses.
 * Classified REQUIREMENT_NOT_AVAILABLE (skipped, never silently passed)
 * when those binaries are absent — the same availability gate as
 * `sdk/test/vault-builders-v7.test.js` and `sdk/test/org-root-manifest-v7
 * .test.js`.
 *
 * The `ORG_ROOT_REQUEST` durable record this file wraps a manifest in is
 * a HAND-BUILT FIXTURE matching docs/postlaunch/v0.7-app-surface-
 * contract.md §1 exactly (`server/src/org-roots.js` does not exist yet on
 * this lane — see server/src/attestations-v7.js's header residual #1);
 * every FINANCIAL fact inside that fixture is copied verbatim from the
 * REAL manifest the SDK builders produced, never invented.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");
const { spawnSync } = require("child_process");

const { loadConfig } = require("../src/config");
const assets = require("../../core/assets");
const { compileKcc20Program } = require("../src/token-program-kcc20");
const { buildTokenAgentTreeV5 } = require("../src/agent-merkle-v5");
const { buildRecipientTree } = require("../src/recipient-merkle-v3");
const { deriveRootPinsV7 } = require("../src/contract-compiler-v7");
const { buildV7Transaction } = require("../src/vault-builders-v7");
const { buildOrgRootIntentManifest, buildRootedVaultManifestV7 } = require("../../core/intent/org-root-manifest-v7");
const { OWNER_SLOTS_V7, INACTIVE_SLOT_KEY } = require("../../core/model/owner-set-v7");
const { computeManifestHashV1 } = require("../../core/intent/canonical");
const { ENCODER_PATH } = require("../src/vault-builders-v4");
const attest = require("../../core/attest");
const attestations = require("../../server/src/attestations");
const attestationsV7 = require("../../server/src/attestations-v7");

const config = loadConfig({ dataRoot: fs.mkdtempSync(path.join(os.tmpdir(), "pv7-attest-")) });
const available = fs.existsSync(config.silvercPath) && fs.existsSync(ENCODER_PATH) && fs.existsSync(path.join(config.repoRoot, "tests/vm/target/debug/pv_tx_probe"));
const SKIP = !available && "REQUIREMENT_NOT_AVAILABLE: silverc / pv_call_encoder / pv_tx_probe";

const KAS = 100000000n;
const H = (b) => b.toString(16).padStart(2, "0").repeat(32);
const ORG_ID = H(0xc1);
const ROOT_ID = H(0xc2);
const VAULT_COV_ID = H(0xc3);
const TOKEN_FAMILY = H(0xc4);
const FUEL = H(0xc5);
const AGENT = H(0xc6);
const RECIPIENT = H(0xc7);
const RECOVERY = H(0xc8);
const ROOT_KAS = 3n * KAS;

function slots(keys) {
  const out = [];
  for (let i = 0; i < OWNER_SLOTS_V7; i += 1) out.push(i < keys.length ? keys[i] : INACTIVE_SLOT_KEY);
  return out;
}
const OWNERS = [H(0xd1), H(0xd2), H(0xd3)];

function ctx() {
  const rootTemplate = { orgId: ORG_ID, recoveryDelayDaa: "1000", successorPk: H(0xd7), successionDelayDaa: "2000", rootMaxFeePerTx: "200000" };
  const ownerSet = { owners: slots(OWNERS), ownerM: 2, emergencyK: 1, recoveryM: 2 };
  const rootState = (over = {}) => ({ boundOrgId: ORG_ID, ...ownerSet, frozen: 0, rootNonce: 0, ...over });
  const ref = compileKcc20Program({ config, state: assets.kcc20.ZERO_STATE, familyBound: 2 });
  const descriptor = {
    schema: "policyvault-asset-descriptor/1",
    assetId: H(0xd9),
    displayName: "Attest Track Token",
    tokenStandard: "kcc20/1",
    tokenCovenantId: TOKEN_FAMILY,
    acceptedTransferTemplates: [{ templateVmHashBlake2b256: ref.templateVmHashBlake2b256, prefixLen: ref.geometry.prefixLen, suffixLen: ref.geometry.suffixLen, stateLayout: "kcc20-state/1" }],
    decimalsDisplay: 2,
    issuerPowers: { mint: false, burn: false, freeze: false, blacklist: false, redemptionControl: false, upgradeMigration: false, controllerRotation: false, emergencyControl: false }
  };
  const rootPins = deriveRootPinsV7({ config, template: rootTemplate, ownerSet, covenantId: ROOT_ID });
  const vaultTemplate = {
    vaultId: H(0xda),
    descriptorHash: assets.computeDescriptorHash(descriptor),
    tokenCovenantId: TOKEN_FAMILY,
    templateVmHash: ref.templateVmHashBlake2b256,
    templatePrefixLen: ref.geometry.prefixLen,
    templateStateLen: ref.geometry.stateLen,
    templateSuffixLen: ref.geometry.suffixLen,
    ...rootPins,
    recoveryPk: RECOVERY
  };
  const rTree = buildRecipientTree([RECIPIENT]);
  const policy = { agentPk: AGENT, tokenMaxPerSpend: "250", tokenPeriodBudget: "400", periodLengthDaa: "1000", periodStartDaa: "5000", tokenPeriodSpent: "0", agentMaxFeePerTx: (1n * KAS).toString(), agentMaxCarryKas: (KAS / 4n).toString(), agentRecipientRoot: rTree.root };
  const tree = buildTokenAgentTreeV5([policy]);
  const vaultStateJson = (over = {}) => ({ feeReserve: (5n * KAS).toString(), paused: "0", agentRoot: tree.root, policyNonce: "0", ...over });
  const fuel = { outpoint: { transactionId: H(0xdb), index: 0 }, amount: (1n * KAS).toString(), scriptPublicKeyHex: `20${FUEL}ac` };
  const rootInput = { template: rootTemplate, state: rootState(), outpoint: { transactionId: H(0xdc), index: 0 }, covenantId: ROOT_ID, value: ROOT_KAS.toString() };
  const vaultChain = (over = {}) => ({ predecessorOutpoint: { transactionId: H(0xdd), index: 0 }, covenantId: VAULT_COV_ID, predecessorValue: (5n * KAS).toString(), fuel, ...over });
  const tokenPosition = () => {
    const st = { ownerIdentifier: VAULT_COV_ID, identifierType: 2, amount: "300", isMinter: false };
    const program = compileKcc20Program({ config, state: st, familyBound: 2 });
    return { outpoint: { transactionId: H(0xde), index: 0 }, value: (2n * KAS).toString(), scriptPublicKeyHex: program.p2shSpkHex, covenantId: TOKEN_FAMILY, state: st };
  };
  return { rootTemplate, ownerSet, rootState, descriptor, vaultTemplate, policy, rTree, vaultStateJson, rootInput, vaultChain, tokenPosition };
}

/* deep clone + re-hash the ATTESTATION so a tamper is HASH-CONSISTENT — the
 * point of each row is the SEMANTIC check, never the hash check (asserted
 * separately by the "naive" rows). */
function rehash(record, mutate) {
  const { attestationHash, signature, ...body } = JSON.parse(JSON.stringify(record));
  void attestationHash;
  void signature;
  mutate(body);
  return { ...body, attestationHash: attest.computeAttestationHashV1(body), signature: null };
}

function naive(record, mutate) {
  const copy = JSON.parse(JSON.stringify(record));
  mutate(copy);
  return copy;
}

/* One real root AUTHORIZE carrying ONE embedded owner op (ownerPause). */
function buildRootActionWithVaultOp(c) {
  const build = buildV7Transaction({
    config,
    templateInput: c.vaultTemplate,
    stateInput: c.vaultStateJson(),
    action: "ownerPause",
    chain: c.vaultChain({ root: c.rootInput }),
    changeXOnly: FUEL,
    descriptor: c.descriptor
  });
  const manifest = buildOrgRootIntentManifest({ build, vaultOperations: [{ build, descriptor: c.descriptor }], satisfiedApprovals: 2 });
  ATTEST_CARRIAGE.set(manifest.manifestHash, { descriptors: { [build.covenantId]: c.descriptor }, redeemScripts: { [build.covenantId]: build.vaultRedeemScriptHex } });
  return { build, manifest };
}

/* One real standalone delegate spend — NO root input at all. */
function buildStandaloneSpend(c) {
  const build = buildV7Transaction({
    config,
    templateInput: c.vaultTemplate,
    stateInput: c.vaultStateJson(),
    action: "tokenAgentSpend",
    params: { spendAmount: "200", agentPk: AGENT, agents: [c.policy], recipient: RECIPIENT, recipients: [...c.rTree.recipients], recipientCarryKasSompi: (KAS / 5n).toString(), reserveConsumedSompi: "50000" },
    chain: c.vaultChain({ tokenPosition: c.tokenPosition() }),
    changeXOnly: FUEL,
    descriptor: c.descriptor
  });
  const manifest = buildRootedVaultManifestV7({ build, descriptor: c.descriptor });
  return { build, manifest };
}

/* Codex checkpoint 6: a real request record carries the descriptors + predecessor redeem scripts its verification used */
const ATTEST_CARRIAGE = new Map();
function orgRootRequestFixture({ manifest, state, chain = null, requiredApprovals, signedSlotCount = 2 }) {
  const slotsFixture = manifest.action.expectedSignerSlots.map((s, i) => ({
    slot: s.slot,
    publicKey: s.publicKey,
    address: `kaspatest:owner${s.slot}`,
    label: null,
    status: i < signedSlotCount ? "SIGNED" : "PENDING",
    signedAt: i < signedSlotCount ? "2026-09-03T00:00:00.000Z" : null,
    responseEnvelopeHash: i < signedSlotCount ? H(0xe0 + i) : null
  }));
  return {
    schemaVersion: attestationsV7.ORG_ROOT_REQUEST_SCHEMA_V1,
    id: crypto.randomUUID(),
    rootCovenantId: manifest.root.covenantId,
    orgId: manifest.root.orgId,
    contractVersion: "policyvault-0.7-root",
    kind: "rootAction",
    action: manifest.action.name,
    actionClass: manifest.action.authorityClass,
    vaultOperations: [],
    manifest,
    ...(ATTEST_CARRIAGE.get(manifest.manifestHash) || {}),
    manifestHash: manifest.manifestHash,
    signerVisibleDigest: null,
    requiredApprovals: requiredApprovals ?? manifest.action.requiredApprovals,
    slots: slotsFixture,
    signaturesPresent: signedSlotCount,
    state,
    build: null,
    finalizedTxHex: null,
    txId: manifest.transaction.txId,
    chain,
    warnings: [],
    createdBy: "test-fixture",
    createdAt: "2026-09-03T00:00:00.000Z",
    updatedAt: "2026-09-03T00:00:00.000Z"
  };
}

function rootChainFacts(manifest) {
  const frozen = JSON.parse(manifest.transaction.frozenCanonicalJson);
  const idx = frozen.outputs.findIndex((o) => o.covenant && o.covenant.covenantId === manifest.root.covenantId);
  return {
    predecessorOutpoint: manifest.root.outpoint,
    successorOutpoint: { transactionId: manifest.transaction.txId, index: idx },
    observedAt: "2026-09-03T00:05:00.000Z",
    virtualDaa: "600000000"
  };
}

/* ------------------------------------------------------------------ */

test("v0.7 attestations: a root action reaching every ladder rung produces a STRUCTURE_VERIFIED policyvault-0.7-root record", { skip: SKIP }, () => {
  const c = ctx();
  const { manifest } = buildRootActionWithVaultOp(c);
  const chain = rootChainFacts(manifest);

  for (const state of ["AUTHORIZED", "SIGNED", "BROADCAST", "CHAIN_SEEN", "CHAIN_VERIFIED", "VERIFIED_OUTCOME"]) {
    const request = orgRootRequestFixture({ manifest, state, chain: state === "AUTHORIZED" || state === "SIGNED" ? null : chain });
    const { attestation, sources } = attestationsV7.buildAttestationForOrgRootRequest(config, request);
    assert.ok(sources.includes("policyvault-org-root-request/1"));
    assert.ok(sources.includes("policyvault-org-root-manifest/1"));
    assert.equal(attestation.subject.contractVersion, "policyvault-0.7-root");
    assert.equal(attestation.subject.vaultId, manifest.root.covenantId);
    assert.equal(attestation.action.type, "authorize");
    assert.equal(attestation.action.highLevel, "AUTHORITY-NEUTRAL");
    assert.equal(attestation.action.aboveThreshold, true);
    assert.equal(attestation.authorization.decision, "AUTHORIZED");
    assert.equal(attestation.authorization.intentManifestVerdict, "VERIFIED_EXACT");
    assert.equal(attestation.approvals.required, "2");
    assert.equal(attestation.approvals.collected, "2");
    assert.equal(attestation.approvals.approvalDigests.length, 2);

    const v = attest.verifyAttestation(attestation);
    assert.equal(v.verdict, attest.VERDICTS.STRUCTURE_VERIFIED, `state ${state}: ${JSON.stringify(v.structural.failures)}`);
    assert.equal(v.structural.ok, true);
    const expectedTop = state === "VERIFIED_OUTCOME" ? "CHAIN_VERIFIED" : state;
    assert.equal(attestation.outcome.state, expectedTop, `state ${state}: never claims VERIFIED_OUTCOME from the server`);
    if (state === "CHAIN_SEEN" || state === "CHAIN_VERIFIED" || state === "VERIFIED_OUTCOME") {
      assert.equal(attestation.outcome.chain.outputs.length, 1);
      assert.match(attestation.outcome.chain.outputs[0].address, /^kaspatest:/);
    }
  }
  console.log("v0.7 root-action ladder states verified: 6");
});

test("v0.7 attestations: a REFUSED root action and a post-authorization FAILED state attribute correctly", { skip: SKIP }, () => {
  const c = ctx();
  const { manifest } = buildRootActionWithVaultOp(c);

  const refused = orgRootRequestFixture({ manifest, state: "REFUSED", signedSlotCount: 0 });
  const { attestation: refAtt } = attestationsV7.buildAttestationForOrgRootRequest(config, refused);
  assert.equal(refAtt.authorization.decision, "REFUSED");
  assert.equal(refAtt.outcome.reached.length, 0);
  assert.equal(refAtt.outcome.txId, null);
  const vr = attest.verifyAttestation(refAtt);
  assert.equal(vr.verdict, attest.VERDICTS.STRUCTURE_VERIFIED, JSON.stringify(vr.structural.failures));

  const failed = orgRootRequestFixture({ manifest, state: "FAILED", signedSlotCount: 2 });
  const { attestation: failAtt } = attestationsV7.buildAttestationForOrgRootRequest(config, failed);
  assert.equal(failAtt.authorization.decision, "AUTHORIZED", "PolicyVault DID authorize; something afterwards went wrong");
  assert.equal(failAtt.outcome.disposition, "FAILED");
  assert.equal(failAtt.outcome.failureCode, "ORG_ROOT_REQUEST_FAILED");
  assert.deepEqual(failAtt.outcome.reached.map((r) => r.state), ["AUTHORIZED"]);
  const vf = attest.verifyAttestation(failAtt);
  assert.equal(vf.verdict, attest.VERDICTS.STRUCTURE_VERIFIED, JSON.stringify(vf.structural.failures));
});

test("v0.7 attestations: dispatch through the SHARED buildAttestationForRequest picks the org-root mapping by schemaVersion", { skip: SKIP }, async () => {
  const c = ctx();
  const { manifest } = buildRootActionWithVaultOp(c);
  const request = orgRootRequestFixture({ manifest, state: "AUTHORIZED", signedSlotCount: 0 });
  const { attestation } = await attestations.buildAttestationForRequest(config, request);
  assert.equal(attestation.subject.contractVersion, "policyvault-0.7-root");
});

test("v0.7 attestations: a rooted-vault owner operation riding IN a root action gets its OWN policyvault-0.7-payment attestation", { skip: SKIP }, () => {
  const c = ctx();
  const { manifest } = buildRootActionWithVaultOp(c);
  const chain = rootChainFacts(manifest);
  const request = orgRootRequestFixture({ manifest, state: "CHAIN_VERIFIED", chain });

  const opAttestations = attestationsV7.buildAttestationsForOrgRootRequestVaultOps(config, request);
  assert.equal(opAttestations.length, 1);
  const { attestation } = opAttestations[0];
  assert.equal(attestation.subject.contractVersion, "policyvault-0.7-payment");
  assert.equal(attestation.subject.vaultId, manifest.vaultOperations[0].covenantId);
  assert.equal(attestation.action.type, "ownerPause");
  assert.equal(attestation.action.highLevel, "AUTHORITY-REDUCING");
  assert.equal(attestation.action.aboveThreshold, false, "authority is inherited from the ROOT action's own attestation");
  assert.equal(attestation.asset.kind, "KAS");
  assert.equal(attestation.outcome.state, "CHAIN_VERIFIED");
  assert.equal(attestation.outcome.txId, manifest.transaction.txId, "the SAME transaction as the parent root action");

  const v = attest.verifyAttestation(attestation);
  assert.equal(v.verdict, attest.VERDICTS.STRUCTURE_VERIFIED, JSON.stringify(v.structural.failures));
});

test("v0.7 attestations: a STANDALONE delegate spend (no root input) gets a policyvault-0.7-payment attestation with the TOKEN asset domain", { skip: SKIP }, () => {
  const c = ctx();
  const { build, manifest } = buildStandaloneSpend(c);
  assert.equal(manifest.action.requiresRootInput, false);

  const record = {
    manifest,
    requestId: crypto.randomUUID(),
    organizationId: null,
    state: "CHAIN_VERIFIED",
    txId: manifest.transaction.txId,
    chain: { successorOutpoint: null },
    signerVisibleDigest: H(0xf1),
    signerXOnly: AGENT,
    /* the rooted-vault manifest's OWN `transaction` field carries no
     * frozenCanonicalJson (only the org-root manifest does) — the frozen
     * transaction JSON comes from the SDK build object itself. */
    frozenCanonicalJson: build.frozenCanonicalJson
  };
  const { attestation, sources } = attestationsV7.buildAttestationForRootedVaultRequest(config, record);
  assert.ok(sources.includes(ROOTED_VAULT_MANIFEST_VERSION()));
  assert.equal(attestation.subject.contractVersion, "policyvault-0.7-payment");
  assert.equal(attestation.action.type, "tokenAgentSpend");
  assert.equal(attestation.action.role, "agent");
  assert.equal(attestation.asset.kind, "TOKEN");
  assert.equal(attestation.asset.familyId, manifest.vault.tokenCovenantId);
  assert.equal(attestation.destination.kind, "RECIPIENT_XONLY");
  assert.equal(attestation.destination.identity, RECIPIENT);
  assert.equal(attestation.amounts.amount, manifest.accounting.token.spendAmount);
  assert.equal(attestation.authorization.signerXOnly, AGENT);
  assert.equal(attestation.outcome.state, "CHAIN_VERIFIED");
  assert.equal(attestation.outcome.chain.outputs[0].valueSompi, manifest.accounting.token.spendAmount);

  const v = attest.verifyAttestation(attestation);
  assert.equal(v.verdict, attest.VERDICTS.STRUCTURE_VERIFIED, JSON.stringify(v.structural.failures));
});

function ROOTED_VAULT_MANIFEST_VERSION() {
  return require("../../core/intent/org-root-manifest-v7").ROOTED_VAULT_MANIFEST_VERSION_1;
}

test("v0.7 attestations TAMPER MATRIX: 12+ new classes, each caught NAIVE (HASH_MISMATCH or a shape code) and RE-HASHED (semantic refusal)", { skip: SKIP }, () => {
  const c = ctx();
  const { manifest } = buildRootActionWithVaultOp(c);
  const chain = rootChainFacts(manifest);
  const request = orgRootRequestFixture({ manifest, state: "CHAIN_VERIFIED", chain });
  const { attestation: good } = attestationsV7.buildAttestationForOrgRootRequest(config, request);
  assert.equal(attest.verifyAttestation(good).verdict, attest.VERDICTS.STRUCTURE_VERIFIED);

  /*
   * Every row here has a REAL structural cross-consistency check in
   * core/attest/verify.js's checkConsistency (or checkShape, for the one
   * shape-level row) — asserted below by BARE re-verification, no
   * `expect` pin needed. Rows whose field has no self-consistent twin
   * inside the SAME record (an identity substitution like subject.vaultId
   * or subject.contractVersion swapped to another REAL, well-formed
   * value) are DELIBERATELY not mixed in here: those are caught by the
   * EXPECTATION-BINDING layer instead (core/attest/verify.js EXPECTATIONS
   * map) and are exercised in the SEPARATE test below, matching exactly
   * how core/attest/test/tamper.test.js's own "tamper/version" /
   * "tamper/vault" classes are structured (naive HASH_MISMATCH; the
   * re-hashed form needs the reader's OWN expectation, not bare
   * re-verification, because the record stays internally self-consistent).
   */
  const rows = [
    ["CONTRACT VERSION substituted to an unknown v0.7 string", (b) => { b.subject.contractVersion = "policyvault-0.7-root-fake"; }, "CONTRACT_VERSION_UNSUPPORTED"],
    ["MANIFEST VERDICT forged REFUSED while decision stays AUTHORIZED", (b) => { b.authorization.intentManifestVerdict = "REFUSED"; }, "MANIFEST_VERDICT_INCONSISTENT"],
    ["approvals.required RAISED above what was actually collected", (b) => { b.approvals.required = "3"; }, "APPROVALS_INSUFFICIENT"],
    ["approvals.collected INFLATED beyond the digest count", (b) => { b.approvals.collected = "3"; }, "APPROVALS_COUNT_MISMATCH"],
    ["an approval digest ATTRIBUTED to a key outside the approver set", (b) => { b.approvals.approvalDigests[0].approverXOnly = H(0xfd); }, "APPROVER_SLOT_UNKNOWN"],
    ["LADDER OVER-CLAIM — VERIFIED_OUTCOME inserted without CHAIN_VERIFIED between AUTHORIZED and it", (b) => { b.outcome.reached = [{ state: "AUTHORIZED", source: "x", note: null }, { state: "VERIFIED_OUTCOME", source: "x", note: null }]; }, "LADDER_ORDER_INVALID"],
    ["LADDER STATE MISMATCH — outcome.state disagrees with the highest reached rung", (b) => { b.outcome.state = "BROADCAST"; }, "LADDER_STATE_MISMATCH"],
    ["successorOutpoint's txid moved to a DIFFERENT transaction than outcome.txId", (b) => { b.outcome.chain.successorOutpoint.transactionId = H(0xfc); }, "TXID_MISMATCH"],
    ["predecessorOutpoint forged to belong to THIS SAME transaction (self-consumption)", (b) => { b.outcome.chain.predecessorOutpoint = { transactionId: b.outcome.txId, index: 0 }; }, "TXID_MISMATCH"],
    ["NETWORK MISMATCH between outcome.networkId and subject.networkId", (b) => { b.outcome.networkId = "mainnet"; }, "NETWORK_MISMATCH"],
    ["DISPOSITION forged SETTLED after stripping CHAIN_VERIFIED from the ladder", (b) => { b.outcome.disposition = "SETTLED"; b.outcome.reached = b.outcome.reached.filter((r) => r.state !== "CHAIN_VERIFIED"); b.outcome.state = "CHAIN_SEEN"; }, "DISPOSITION_INCONSISTENT"],
    ["CHAIN_SEEN claimed with the observed-outputs list emptied", (b) => { b.outcome.chain.outputs = []; }, "CHAIN_SEEN_WITHOUT_OUTPUTS"],
    ["BROADCAST claimed with the transaction id nulled", (b) => { b.outcome.txId = null; }, "BROADCAST_WITHOUT_TXID"],
    ["decision forged REFUSED while the reached ladder is left non-empty", (b) => { b.authorization.decision = "REFUSED"; b.authorization.refusalCode = "FORGED_REFUSAL"; }, "REFUSAL_WITH_LADDER"],
    ["decision AUTHORIZED with the reached ladder emptied", (b) => { b.outcome.reached = []; b.outcome.state = "REFUSED"; }, "AUTHORIZED_WITHOUT_LADDER"]
  ];

  let naiveCaught = 0;
  let rehashedCaught = 0;
  for (const [label, mutate, expectedCode] of rows) {
    const naiveRecord = naive(good, mutate);
    const nv = attest.verifyAttestation(naiveRecord);
    assert.equal(nv.verdict, attest.VERDICTS.INVALID, `${label} (naive): must be invalid`);
    /*
     * checkShape runs BEFORE the hash re-check (core/attest/verify.js:
     * `if (f.ok) { recompute hash }`), so a mutation that ALSO breaks
     * SHAPE validity on its own (an unknown enum value) is refused on
     * that shape code even before hashing is reached — HASH_MISMATCH is
     * never computed in that case. Every other row here stays
     * shape-valid, so its naive (un-rehashed) form is caught by
     * HASH_MISMATCH alone.
     */
    if (expectedCode === "CONTRACT_VERSION_UNSUPPORTED") {
      assert.ok(nv.failureCodes.includes(expectedCode), `${label} (naive, shape-breaking): got ${nv.failureCodes.join(",")}`);
    } else {
      assert.ok(nv.failureCodes.includes("HASH_MISMATCH"), `${label} (naive): expected HASH_MISMATCH, got ${nv.failureCodes.join(",")}`);
    }
    naiveCaught += 1;

    const rehashedRecord = rehash(good, mutate);
    const rv = attest.verifyAttestation(rehashedRecord);
    assert.equal(rv.verdict, attest.VERDICTS.INVALID, `${label} (re-hashed): must still be invalid`);
    assert.ok(rv.failureCodes.includes(expectedCode), `${label} (re-hashed): expected ${expectedCode}, got ${rv.failureCodes.join(",")}`);
    rehashedCaught += 1;
  }
  assert.equal(naiveCaught, rows.length);
  assert.equal(rehashedCaught, rows.length);
  console.log(`v0.7 attestation structural tamper rows: ${rows.length} naive + ${rehashedCaught} re-hashed-and-code-checked`);
});

test("v0.7 attestations TAMPER MATRIX (expectation binding): an internally self-consistent identity substitution is caught ONLY by the reader's OWN pin", { skip: SKIP }, () => {
  const c = ctx();
  const { manifest } = buildRootActionWithVaultOp(c);
  const chain = rootChainFacts(manifest);
  const request = orgRootRequestFixture({ manifest, state: "CHAIN_VERIFIED", chain });
  const { attestation: good } = attestationsV7.buildAttestationForOrgRootRequest(config, request);

  const rows = [
    ["ROOT COVENANT ID (subject.vaultId) substituted for a different well-formed hex64", (b) => { b.subject.vaultId = H(0xff); }, { vaultId: good.subject.vaultId }, "EXPECTED_VAULT_MISMATCH"],
    ["CONTRACT VERSION substituted to a DIFFERENT real, well-formed generation", (b) => { b.subject.contractVersion = "policyvault-0.7-payment"; }, { contractVersion: "policyvault-0.7-root" }, "EXPECTED_CONTRACT_VERSION_MISMATCH"],
    ["NETWORK substituted to another well-formed network, both sides moved together", (b) => { b.subject.networkId = "mainnet"; b.outcome.networkId = "mainnet"; }, { networkId: good.subject.networkId }, "EXPECTED_NETWORK_MISMATCH"],
    ["TRANSACTION ID substituted for a different well-formed hex64", (b) => { b.outcome.txId = H(0xf9); b.outcome.chain.successorOutpoint.transactionId = H(0xf9); }, { txId: good.outcome.txId }, "EXPECTED_TXID_MISMATCH"]
  ];

  let caught = 0;
  for (const [label, mutate, expect, expectedCode] of rows) {
    const rehashedRecord = rehash(good, mutate);
    const bare = attest.verifyAttestation(rehashedRecord);
    assert.equal(bare.verdict, attest.VERDICTS.STRUCTURE_VERIFIED, `${label}: internally self-consistent — integrity is intact, truth is not integrity`);
    const pinned = attest.verifyAttestation(rehashedRecord, { expect });
    assert.equal(pinned.verdict, attest.VERDICTS.INVALID, `${label} (pinned): must be invalid`);
    assert.ok(pinned.failureCodes.includes(expectedCode), `${label} (pinned): expected ${expectedCode}, got ${pinned.failureCodes.join(",")}`);
    caught += 1;
  }
  assert.equal(caught, rows.length);
  console.log(`v0.7 attestation expectation-binding tamper rows: ${rows.length}`);
});

test("v0.7 attestations: the forbidden-vocabulary language rule holds over the rendered summary", { skip: SKIP }, () => {
  const c = ctx();
  const { manifest } = buildRootActionWithVaultOp(c);
  const request = orgRootRequestFixture({ manifest, state: "AUTHORIZED", signedSlotCount: 0 });
  const { attestation } = attestationsV7.buildAttestationForOrgRootRequest(config, request);
  const verification = attest.verifyAttestation(attestation);
  const summary = attest.attestationSummary.humanReadable(attestation, verification);
  assert.doesNotThrow(() => attest.assertNoForbiddenLanguage(summary));
  assert.equal(attest.forbiddenLanguageHits(summary).length, 0);
  for (const term of ["audited", "certified", "compliant", "regulator", "guaranteed"]) {
    assert.doesNotMatch(summary.toLowerCase(), new RegExp(term));
  }
});

test("v0.7 attestations: the independent CLI verifier (tools/attestation-verify.js) accepts a real v0.7 record", { skip: SKIP }, () => {
  const c = ctx();
  const { manifest } = buildRootActionWithVaultOp(c);
  const request = orgRootRequestFixture({ manifest, state: "AUTHORIZED", signedSlotCount: 0 });
  const { attestation } = attestationsV7.buildAttestationForOrgRootRequest(config, request);
  const file = path.join(config.dataRoot, "v7-attestation.json");
  fs.writeFileSync(file, attest.exportAttestationJson(attestation));
  const result = spawnSync(process.execPath, [path.join(config.repoRoot, "tools/attestation-verify.js"), file, "--quiet"], { encoding: "utf8" });
  assert.equal(result.status, 0, `stdout=${result.stdout} stderr=${result.stderr}`);
});
