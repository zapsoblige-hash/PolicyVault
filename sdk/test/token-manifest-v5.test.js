"use strict";

/*
 * SDK/INTEGRATION: the v0.5 token intent manifest + deterministic local
 * verification + explain, driven by the REAL builder (silverc, the
 * production encoder, pv_tx_probe). Classified REQUIREMENT_NOT_AVAILABLE
 * (skipped, never silently passed) when those binaries are absent.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const { loadConfig } = require("../src/config");
const assets = require("../../core/assets");
const { compileKcc20Program } = require("../src/token-program-kcc20");
const { buildTokenAgentTreeV5 } = require("../src/agent-merkle-v5");
const { buildRecipientTree } = require("../src/recipient-merkle-v3");
const { buildV5Transaction, buildTokenDepositV5 } = require("../src/vault-builders-v5");
const { buildTokenIntentManifest, verifyTokenIntentManifest } = require("../../core/intent/token-manifest-v5");
const { explainTokenIntent } = require("../../core/explain/token-explain");
const { ENCODER_PATH } = require("../src/vault-builders-v4");

const config = loadConfig({ dataRoot: fs.mkdtempSync(path.join(os.tmpdir(), "pv5-tm-")) });
const available = fs.existsSync(config.silvercPath) && fs.existsSync(ENCODER_PATH) && fs.existsSync(path.join(config.repoRoot, "tests/vm/target/debug/pv_tx_probe"));

const KAS = 100000000n;
const CONTROLLER_ID = "43".repeat(32);
const TOKEN_FAMILY = "54".repeat(32);
const OWNER = "11".repeat(32);
const AGENT = "22".repeat(32);
const RECIPIENT = "33".repeat(32);
const FUEL = "64".repeat(32);

test("token intent manifest: build -> VERIFIED; tampering -> REFUSED with the failing check named; explain sections separate the domains", { skip: !available && "REQUIREMENT_NOT_AVAILABLE: silverc / pv_call_encoder / pv_tx_probe" }, () => {
  const ref = compileKcc20Program({ config, state: assets.kcc20.ZERO_STATE, familyBound: 2 });
  const descriptor = {
    schema: "policyvault-asset-descriptor/1",
    assetId: "11".repeat(32),
    displayName: "Manifest Token",
    tokenStandard: "kcc20/1",
    tokenCovenantId: TOKEN_FAMILY,
    acceptedTransferTemplates: [{ templateVmHashBlake2b256: ref.templateVmHashBlake2b256, prefixLen: ref.geometry.prefixLen, suffixLen: ref.geometry.suffixLen, stateLayout: "kcc20-state/1" }],
    decimalsDisplay: 2,
    issuerPowers: { mint: true, burn: false, freeze: false, blacklist: false, redemptionControl: false, upgradeMigration: false, controllerRotation: false, emergencyControl: false }
  };
  const descriptorHash = assets.computeDescriptorHash(descriptor);
  const template = { owner: OWNER, vaultId: "44".repeat(32), descriptorHash, tokenCovenantId: TOKEN_FAMILY, templateVmHash: ref.templateVmHashBlake2b256, templatePrefixLen: ref.geometry.prefixLen, templateStateLen: ref.geometry.stateLen, templateSuffixLen: ref.geometry.suffixLen };
  const rTree = buildRecipientTree([RECIPIENT]);
  const policy = { agentPk: AGENT, tokenMaxPerSpend: "250", tokenPeriodBudget: "400", periodLengthDaa: "1000", periodStartDaa: "5000", tokenPeriodSpent: "0", agentMaxFeePerTx: (1n * KAS).toString(), agentMaxCarryKas: (KAS / 4n).toString(), agentRecipientRoot: rTree.root };
  const tree = buildTokenAgentTreeV5([policy]);
  const state = { feeReserve: (5n * KAS).toString(), paused: "0", agentRoot: tree.root, policyNonce: "0" };
  const posState = { ownerIdentifier: CONTROLLER_ID, identifierType: 2, amount: "300", isMinter: false };
  const posProgram = compileKcc20Program({ config, state: posState, familyBound: 2 });
  const chain = {
    predecessorOutpoint: { transactionId: "01".repeat(32), index: 0 },
    predecessorValue: state.feeReserve,
    covenantId: CONTROLLER_ID,
    fuel: { outpoint: { transactionId: "03".repeat(32), index: 0 }, amount: (1n * KAS).toString(), scriptPublicKeyHex: `20${FUEL}ac` },
    tokenPosition: { outpoint: { transactionId: "02".repeat(32), index: 0 }, value: (2n * KAS).toString(), scriptPublicKeyHex: posProgram.p2shSpkHex, covenantId: TOKEN_FAMILY, state: posState }
  };
  const build = buildV5Transaction({ config, templateInput: template, stateInput: state, action: "tokenAgentSpend", params: { spendAmount: "200", agentPk: AGENT, agents: [policy], recipient: RECIPIENT, recipients: [RECIPIENT], recipientCarryKasSompi: (KAS / 5n).toString(), reserveConsumedSompi: "50000" }, chain, changeXOnly: FUEL, descriptor });

  const manifest = buildTokenIntentManifest({ build, descriptor, agentPolicy: policy, recipients: [RECIPIENT] });
  const v = verifyTokenIntentManifest({ manifest, descriptor });
  assert.equal(v.verdict, "VERIFIED", JSON.stringify(v.failures));
  assert.ok(v.checks.length >= 20);
  assert.equal(manifest.accounting.token.spendAmount, "200");
  assert.equal(manifest.accounting.token.positionAfter, "100");
  assert.equal(manifest.accounting.kas.reserveConsumed, "50000");
  assert.equal(manifest.asset.trust, "ISSUER_CONTROLLED");

  const explain = explainTokenIntent({ manifest, descriptor });
  assert.equal(explain.verdict, "VERIFIED");
  const titles = explain.sections.map((s) => s.title);
  assert.ok(titles.some((t) => t.startsWith("TOKEN ASSET IDENTITY")) && titles.some((t) => t.startsWith("KAS FEE AND RESERVE")) && titles.some((t) => t.startsWith("ISSUER")));
  assert.ok(explain.sections[2].lines.some((l) => l.includes("display: 2.00")));
  assert.ok(explain.sections[4].lines[0].includes("mint") && explain.sections[4].lines[0].includes("ISSUER-CONTROLLED"));

  /* tampering: each mutation must REFUSE and name a failing check */
  const tamper = (mutate) => {
    const m = JSON.parse(JSON.stringify(manifest));
    mutate(m);
    return verifyTokenIntentManifest({ manifest: m, descriptor });
  };
  const names = (r) => r.failures.map((f) => f.name);
  assert.ok(names(tamper((m) => { m.accounting.token.spendAmount = "199"; })).includes("manifestHash"));
  const rehash = (mutate) => {
    const m = JSON.parse(JSON.stringify(manifest));
    mutate(m);
    const { manifestHash: _h, ...body } = m;
    m.manifestHash = require("../../core/intent/canonical").computeManifestHashV1(body);
    return verifyTokenIntentManifest({ manifest: m, descriptor });
  };
  assert.ok(names(rehash((m) => { m.accounting.token.spendAmount = "199"; })).includes("tokenConservation"));
  assert.ok(names(rehash((m) => { m.policy.recipient = "99".repeat(32); })).some((n) => n === "recipientContinuationReconstructed" || n === "recipientAllowlisted"));
  assert.ok(names(rehash((m) => { m.accounting.kas.fee = "1"; })).includes("feeExact"));
  assert.ok(names(rehash((m) => { m.stateAfter.state.feeReserve = "1"; })).includes("successorOutput"));
  assert.ok(names(rehash((m) => { const f = JSON.parse(m.transaction.frozenCanonicalJson); f.outputs[2].value = "1"; m.transaction.frozenCanonicalJson = JSON.stringify(f); })).some((n) => n === "tokenFamilyKasNoLeak" || n === "feeExact"));
  /* descriptor substitution at verification time */
  const swapped = verifyTokenIntentManifest({ manifest, descriptor: { ...descriptor, issuerPowers: { ...descriptor.issuerPowers, freeze: true } } });
  assert.equal(swapped.verdict, "REFUSED");
  assert.ok(names(swapped).includes("descriptorHashPin"));
  assert.equal(verifyTokenIntentManifest({ manifest: { ...manifest, manifestVersion: "policyvault-token-intent-manifest/2" }, descriptor }).verdict, "REFUSED");
});

test("token DEPOSIT intent manifest: build -> VERIFIED; tampering -> REFUSED", { skip: !available && "REQUIREMENT_NOT_AVAILABLE: silverc / pv_call_encoder / pv_tx_probe" }, () => {
  const ref = compileKcc20Program({ config, state: assets.kcc20.ZERO_STATE, familyBound: 2 });
  const descriptor = {
    schema: "policyvault-asset-descriptor/1", assetId: "12".repeat(32), displayName: "Deposit Token", tokenStandard: "kcc20/1", tokenCovenantId: TOKEN_FAMILY,
    acceptedTransferTemplates: [{ templateVmHashBlake2b256: ref.templateVmHashBlake2b256, prefixLen: ref.geometry.prefixLen, suffixLen: ref.geometry.suffixLen, stateLayout: "kcc20-state/1" }],
    decimalsDisplay: 0, issuerPowers: { mint: false, burn: false, freeze: false, blacklist: false, redemptionControl: false, upgradeMigration: false, controllerRotation: false, emergencyControl: false }
  };
  const template = { owner: OWNER, vaultId: "44".repeat(32), descriptorHash: assets.computeDescriptorHash(descriptor), tokenCovenantId: TOKEN_FAMILY, templateVmHash: ref.templateVmHashBlake2b256, templatePrefixLen: ref.geometry.prefixLen, templateStateLen: ref.geometry.stateLen, templateSuffixLen: ref.geometry.suffixLen };
  const USER = "66".repeat(32);
  const userState = { ownerIdentifier: USER, identifierType: 0, amount: "1000", isMinter: false };
  const userProgram = compileKcc20Program({ config, state: userState, familyBound: 2 });
  const build = buildTokenDepositV5({ config, descriptor, controller: { covenantId: CONTROLLER_ID, template }, chain: { userPosition: { outpoint: { transactionId: "06".repeat(32), index: 0 }, value: (3n * KAS).toString(), scriptPublicKeyHex: userProgram.p2shSpkHex, covenantId: TOKEN_FAMILY, state: userState }, fuel: { outpoint: { transactionId: "07".repeat(32), index: 0 }, amount: (1n * KAS).toString(), scriptPublicKeyHex: `20${FUEL}ac` } }, params: { depositAmount: "400", depositCarryKasSompi: (1n * KAS).toString() }, changeXOnly: FUEL });
  const manifest = buildTokenIntentManifest({ build, descriptor });
  const v = verifyTokenIntentManifest({ manifest, descriptor });
  assert.equal(v.verdict, "VERIFIED", JSON.stringify(v.failures));
  assert.equal(manifest.accounting.token.deposit, "400");
  assert.equal(manifest.accounting.token.remainderToUser, "600");
  const explain = explainTokenIntent({ manifest, descriptor });
  assert.equal(explain.verdict, "VERIFIED");
  const rehash = (mutate) => {
    const m = JSON.parse(JSON.stringify(manifest));
    mutate(m);
    const { manifestHash: _h, ...body } = m;
    m.manifestHash = require("../../core/intent/canonical").computeManifestHashV1(body);
    return verifyTokenIntentManifest({ manifest: m, descriptor });
  };
  const names = (r) => r.failures.map((f) => f.name);
  assert.ok(names(rehash((m) => { m.accounting.token.deposit = "401"; })).includes("tokenConservation"));
  assert.ok(names(rehash((m) => { m.policy.tokenNewStates[0].ownerIdentifier = "99".repeat(32); })).includes("depositOwnerIsController"));
  assert.ok(names(rehash((m) => { const f = JSON.parse(m.transaction.frozenCanonicalJson); f.outputs[0].value = "1"; m.transaction.frozenCanonicalJson = JSON.stringify(f); })).some((n) => n === "familyKasConserved" || n === "feeExact"));
  assert.equal(verifyTokenIntentManifest({ manifest, descriptor: { ...descriptor, issuerPowers: { ...descriptor.issuerPowers, mint: true } } }).verdict, "REFUSED");
});
