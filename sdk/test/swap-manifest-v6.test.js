"use strict";
/*
 * SDK layer — the v0.6 swap intent manifest + pre-sign verifier over REAL
 * builds (silverc + pv_call_encoder). Requires the local toolchain; skips
 * with REQUIREMENT_NOT_AVAILABLE otherwise.
 */
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");
const os = require("os");

const { loadConfig } = require("../src/config");
const config = loadConfig({ dataRoot: fs.mkdtempSync(path.join(os.tmpdir(), "pv6-manifest-")) });
const available = fs.existsSync(config.silvercPath) && fs.existsSync(path.join(__dirname, "..", "..", "tests/vm/target/debug/pv_call_encoder"));

const assets = require("../../core/assets");
const { compileKcc20Program } = require("../src/token-program-kcc20");
const { buildTokenAgentTreeV6 } = require("../src/agent-merkle-v6");
const { buildSwapPolicyTreeV6, swapPolicyFromProfileV6 } = require("../src/swap-policy-v6");
const { compilePoolFixtureV6, poolFixtureVenueProfile } = require("../src/swap-pool-fixture-v6");
const { buildV6Transaction } = require("../src/vault-builders-v6");
const { buildSwapIntentManifest, verifySwapIntentManifest } = require("../../core/intent/swap-manifest-v6");

const KAS = 100000000n;
const OWNER = "61".repeat(32);
const AGENT = "62".repeat(32);
const RECIPIENT = "63".repeat(32);
const POOL_FEE = "66".repeat(32);
const CONTROLLER_ID = "43".repeat(32);
const TOKEN_FAMILY = "54".repeat(32);
const POOL_ID = "50".repeat(32);

function fixture() {
  const refProgram = compileKcc20Program({ config, state: assets.kcc20.ZERO_STATE, familyBound: 2 });
  const descriptor = {
    schema: "policyvault-asset-descriptor/1",
    assetId: "11".repeat(32),
    displayName: "Manifest Token",
    tokenStandard: "kcc20/1",
    tokenCovenantId: TOKEN_FAMILY,
    acceptedTransferTemplates: [{ templateVmHashBlake2b256: refProgram.templateVmHashBlake2b256, prefixLen: refProgram.geometry.prefixLen, suffixLen: refProgram.geometry.suffixLen, stateLayout: "kcc20-state/1" }],
    decimalsDisplay: 8,
    issuerPowers: { mint: false, burn: false, freeze: false, blacklist: false, redemptionControl: false, upgradeMigration: false, controllerRotation: false, emergencyControl: false }
  };
  const template = { owner: OWNER, vaultId: "44".repeat(32), descriptorHash: assets.computeDescriptorHash(descriptor), tokenCovenantId: TOKEN_FAMILY, templateVmHash: refProgram.templateVmHashBlake2b256, templatePrefixLen: refProgram.geometry.prefixLen, templateStateLen: refProgram.geometry.stateLen, templateSuffixLen: refProgram.geometry.suffixLen };
  const poolState = { kasReserve: (10_000n * KAS).toString(), tokenReserve: "10000", feeBps: "30", nonce: "0" };
  const pool0 = compilePoolFixtureV6({ config, params: { tokenCovenantId: TOKEN_FAMILY, kcc20: { prefixHex: refProgram.prefixHex, suffixHex: refProgram.suffixHex, templateVmHashBlake2b256: refProgram.templateVmHashBlake2b256 }, protocolFeePk: POOL_FEE, protocolFeeBps: "20", ...poolState } });
  const venueProfile = poolFixtureVenueProfile({ networkId: config.networkId, poolCovenantId: POOL_ID, compiled: pool0 });
  const ownerA = { maxProtocolFeeKas: (5n * KAS).toString(), sellFloorNum: (9n * KAS / 10n).toString(), sellFloorDen: "1", buyCeilNum: (11n * KAS / 10n).toString(), buyCeilDen: "1", directionMask: "3", destScheme: 0x02 };
  const swapA = swapPolicyFromProfileV6(venueProfile, ownerA);
  const swapB = swapPolicyFromProfileV6(venueProfile, { ...ownerA, directionMask: "1", destScheme: 0x00, destIdentity: RECIPIENT });
  const swapPolicies = [swapA, swapB];
  const swapTree = buildSwapPolicyTreeV6(swapPolicies);
  const agentPolicy = { agentPk: AGENT, tokenMaxPerSpend: "600", tokenPeriodBudget: "1000", periodLengthDaa: "1000", periodStartDaa: "5000", tokenPeriodSpent: "0", agentMaxFeePerTx: KAS.toString(), agentMaxCarryKas: (KAS / 4n).toString(), kasMaxPerSwap: (500n * KAS).toString(), kasPeriodBudget: (800n * KAS).toString(), kasPeriodSpent: "0", agentRecipientRoot: "00".repeat(32) };
  const agents = [agentPolicy];
  const tree = buildTokenAgentTreeV6(agents);
  const state = { feeReserve: (5n * KAS).toString(), swapPrincipal: (1000n * KAS).toString(), paused: "0", agentRoot: tree.root, swapRoot: swapTree.root, policyNonce: "0" };
  const posState = { ownerIdentifier: CONTROLLER_ID, identifierType: 2, amount: "3000", isMinter: false };
  const posProgram = compileKcc20Program({ config, state: posState, familyBound: 2 });
  const noteState = { ownerIdentifier: POOL_ID, identifierType: 2, amount: "10000", isMinter: false };
  const noteProgram = compileKcc20Program({ config, state: noteState, familyBound: 2 });
  const chain = {
    predecessorOutpoint: { transactionId: "01".repeat(32), index: 0 },
    predecessorValue: (1005n * KAS).toString(),
    covenantId: CONTROLLER_ID,
    tokenPosition: { outpoint: { transactionId: "02".repeat(32), index: 0 }, value: (2n * KAS).toString(), scriptPublicKeyHex: posProgram.p2shSpkHex, covenantId: TOKEN_FAMILY, state: posState },
    poolNote: { outpoint: { transactionId: "08".repeat(32), index: 0 }, value: (2n * KAS).toString(), scriptPublicKeyHex: noteProgram.p2shSpkHex, covenantId: TOKEN_FAMILY, state: noteState },
    pool: { outpoint: { transactionId: "09".repeat(32), index: 0 }, value: (10_000n * KAS).toString(), scriptPublicKeyHex: pool0.p2shSpkHex, covenantId: POOL_ID, state: poolState }
  };
  const common = { agentPk: AGENT, agents, swapPolicies, venueProfile, deadlineDaa: "10000000" };
  return { descriptor, template, state, chain, common, swapA, swapB, agentPolicy };
}

test("swap manifest: SELL A / SELL B / BUY build, verify, and refuse tampering", { skip: !available && "REQUIREMENT_NOT_AVAILABLE: silverc + pv_call_encoder" }, () => {
  const f = fixture();
  const sell = buildV6Transaction({ config, templateInput: f.template, stateInput: f.state, action: "tokenAtomicSell", params: { ...f.common, swapPolicy: f.swapA, amountIn: "500", minKasOut: (400n * KAS).toString() }, chain: f.chain, changeXOnly: AGENT, descriptor: f.descriptor });
  const mS = buildSwapIntentManifest({ build: sell, descriptor: f.descriptor, agentPolicy: f.agentPolicy });
  const vS = verifySwapIntentManifest({ manifest: mS, descriptor: f.descriptor, currentDaaScore: "9999999" });
  assert.equal(vS.verdict, "VERIFIED", JSON.stringify(vS.failures));
  assert.ok(vS.checks.length >= 40);
  assert.ok(mS.explanation.length >= 9 && /FRESHNESS/.test(mS.explanation[8]));
  assert.ok(/kill switch/.test(mS.freshness.statement) && /remains consensus-valid/.test(mS.freshness.residual));
  assert.equal(mS.economics.swapValueSompi, mS.quote.netProceeds);
  assert.match(mS.economics.feeBpsOfSwapValue, /^[0-9]+$/);

  const sellB = buildV6Transaction({ config, templateInput: f.template, stateInput: f.state, action: "tokenAtomicSell", params: { ...f.common, swapPolicy: f.swapB, amountIn: "500", minKasOut: (400n * KAS).toString() }, chain: f.chain, changeXOnly: AGENT, descriptor: f.descriptor });
  const mB = buildSwapIntentManifest({ build: sellB, descriptor: f.descriptor, agentPolicy: f.agentPolicy });
  assert.equal(verifySwapIntentManifest({ manifest: mB, descriptor: f.descriptor }).verdict, "VERIFIED");
  assert.equal(mB.destination.type, "B");

  const buy = buildV6Transaction({ config, templateInput: f.template, stateInput: f.state, action: "tokenAtomicBuy", params: { ...f.common, swapPolicy: f.swapA, tokensOut: "400", maxKasIn: (450n * KAS).toString() }, chain: f.chain, changeXOnly: AGENT, descriptor: f.descriptor });
  const mBuy = buildSwapIntentManifest({ build: buy, descriptor: f.descriptor, agentPolicy: f.agentPolicy });
  const vBuy = verifySwapIntentManifest({ manifest: mBuy, descriptor: f.descriptor });
  assert.equal(vBuy.verdict, "VERIFIED", JSON.stringify(vBuy.failures));
  assert.equal(mBuy.economics.swapValueSompi, mBuy.quote.kasSpend);

  /* tampering: every mutation must REFUSE */
  const tamper = (m, f2) => { const j = JSON.parse(JSON.stringify(m)); f2(j); return j; };
  const refused = (m) => verifySwapIntentManifest({ manifest: m, descriptor: f.descriptor }).verdict === "REFUSED";
  assert.ok(refused(tamper(mS, (j) => { j.quote.netProceeds = (BigInt(j.quote.netProceeds) + 1n).toString(); })), "quote tamper");
  assert.ok(refused(tamper(mS, (j) => { j.freshness.deadlineDaa = "1"; j.manifestHash = "00".repeat(32); })), "hash tamper");
  assert.ok(refused(tamper(mS, (j) => { const tx = JSON.parse(j.transaction.frozenCanonicalJson); tx.outputs[4].scriptPublicKey.scriptHex = `20${"99".repeat(32)}ac`; j.transaction.frozenCanonicalJson = JSON.stringify(tx); })), "protocol fee redirected");
  assert.ok(refused(tamper(mB, (j) => { const tx = JSON.parse(j.transaction.frozenCanonicalJson); tx.outputs[5].scriptPublicKey.scriptHex = `20${"99".repeat(32)}ac`; j.transaction.frozenCanonicalJson = JSON.stringify(tx); })), "proceeds redirected");
  assert.ok(refused(tamper(mS, (j) => { j.venue.swapPolicy.maxProtocolFeeKas = "999999999999"; })), "unapproved leaf");
  assert.ok(refused(tamper(mS, (j) => { j.venue.profile.feeModel.protocolFeeBps = "10"; })), "profile substituted");
  assert.ok(refused(tamper(mS, (j) => { const tx = JSON.parse(j.transaction.frozenCanonicalJson); tx.inputs.push(JSON.parse(JSON.stringify(tx.inputs[0]))); j.transaction.frozenCanonicalJson = JSON.stringify(tx); })), "extra input");
  assert.ok(refused(tamper(mS, (j) => { j.stateAfter.state.swapPrincipal = (BigInt(j.stateAfter.state.swapPrincipal) + 1n).toString(); })), "principal tamper");
  assert.ok(refused(tamper(mS, (j) => { j.policy.agentPolicy.kasMaxPerSwap = "1"; })), "forged agent policy");
  assert.equal(verifySwapIntentManifest({ manifest: mS, descriptor: f.descriptor, currentDaaScore: "10000001" }).verdict, "REFUSED", "deadline passed");
  assert.equal(verifySwapIntentManifest({ manifest: mS, descriptor: { ...f.descriptor, issuerPowers: { ...f.descriptor.issuerPowers, freeze: true } } }).verdict, "REFUSED", "descriptor substitution");
});
