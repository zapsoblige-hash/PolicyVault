"use strict";

/*
 * SDK/INTEGRATION: the v0.6 CONTROLLER intent manifest
 * (policyvault-controller-intent-manifest/1) + its deterministic local
 * pre-sign verifier, driven by the REAL v0.6 builder (silverc, the
 * production pv_call_encoder, pv_tx_probe) over every NON-SWAP v0.6
 * operation: tokenAgentSpend (fuel-funded and reserve-funded), all six
 * owner control operations, ownerRecover (with and without a token
 * position), and a v0.6-labelled tokenDeposit.
 *
 * This is the integration proof for the gap
 * docs/postlaunch/v0.6-byte-freeze-readiness.md limitation 8 recorded:
 * before this manifest existed, none of these operations had ANY
 * signer-side independent recomputation (the v0.5 token manifest is
 * version-pinned to policyvault-0.5 and the v0.6 swap manifest requires a
 * swap build), so the only local statement of what they do was the
 * builder's own.
 *
 * Classified REQUIREMENT_NOT_AVAILABLE (skipped, never silently passed)
 * when the toolchain binaries are absent.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const { loadConfig } = require("../src/config");
const assets = require("../../core/assets");
const { compileKcc20Program } = require("../src/token-program-kcc20");
const { buildTokenAgentTreeV6 } = require("../src/agent-merkle-v6");
const { buildSwapPolicyTreeV6, swapPolicyFromProfileV6 } = require("../src/swap-policy-v6");
const { compilePoolFixtureV6, poolFixtureVenueProfile } = require("../src/swap-pool-fixture-v6");
const { buildRecipientTree } = require("../src/recipient-merkle-v3");
const { buildV6Transaction, buildTokenDepositV6 } = require("../src/vault-builders-v6");
const { buildControllerIntentManifestV6, verifyControllerIntentManifestV6, CONTROLLER_MANIFEST_VERSION_1 } = require("../../core/intent/token-manifest-v6");
const router = require("../../core/intent/router");
const { ENCODER_PATH } = require("../src/vault-builders-v4");

const config = loadConfig({ dataRoot: fs.mkdtempSync(path.join(os.tmpdir(), "pv6-cm-")) });
const available = fs.existsSync(config.silvercPath) && fs.existsSync(ENCODER_PATH) && fs.existsSync(path.join(config.repoRoot, "tests/vm/target/debug/pv_tx_probe"));
const skip = !available && "REQUIREMENT_NOT_AVAILABLE: silverc / pv_call_encoder / pv_tx_probe";

const KAS = 100000000n;
const OWNER = "61".repeat(32);
const AGENT = "62".repeat(32);
const RECIPIENT = "63".repeat(32);
const POOL_FEE = "66".repeat(32);
const FUEL = "64".repeat(32);
const CONTROLLER_ID = "43".repeat(32);
const TOKEN_FAMILY = "54".repeat(32);
const POOL_ID = "50".repeat(32);

/* One shared fixture: a real compiled kcc20 family, a real v0.6 agent tree,
 * a real swap-policy tree (so ownerSetSwapRoot has something to replace),
 * and a real token position owned by the controller. */
function fixture() {
  const ref = compileKcc20Program({ config, state: assets.kcc20.ZERO_STATE, familyBound: 2 });
  const descriptor = {
    schema: "policyvault-asset-descriptor/1",
    assetId: "11".repeat(32),
    displayName: "Controller Token",
    tokenStandard: "kcc20/1",
    tokenCovenantId: TOKEN_FAMILY,
    acceptedTransferTemplates: [{ templateVmHashBlake2b256: ref.templateVmHashBlake2b256, prefixLen: ref.geometry.prefixLen, suffixLen: ref.geometry.suffixLen, stateLayout: "kcc20-state/1" }],
    decimalsDisplay: 2,
    issuerPowers: { mint: true, burn: false, freeze: false, blacklist: false, redemptionControl: false, upgradeMigration: false, controllerRotation: false, emergencyControl: false }
  };
  const descriptorHash = assets.computeDescriptorHash(descriptor);
  const template = { owner: OWNER, vaultId: "44".repeat(32), descriptorHash, tokenCovenantId: TOKEN_FAMILY, templateVmHash: ref.templateVmHashBlake2b256, templatePrefixLen: ref.geometry.prefixLen, templateStateLen: ref.geometry.stateLen, templateSuffixLen: ref.geometry.suffixLen };

  const rTree = buildRecipientTree([RECIPIENT]);
  const agentPolicy = {
    agentPk: AGENT,
    tokenMaxPerSpend: "250",
    tokenPeriodBudget: "400",
    periodLengthDaa: "1000",
    periodStartDaa: "5000",
    tokenPeriodSpent: "0",
    agentMaxFeePerTx: KAS.toString(),
    agentMaxCarryKas: (KAS / 4n).toString(),
    kasMaxPerSwap: (500n * KAS).toString(),
    kasPeriodBudget: (800n * KAS).toString(),
    kasPeriodSpent: "0",
    agentRecipientRoot: rTree.root
  };
  const agentTree = buildTokenAgentTreeV6([agentPolicy]);

  const pool0 = compilePoolFixtureV6({
    config,
    params: { tokenCovenantId: TOKEN_FAMILY, kcc20: { prefixHex: ref.prefixHex, suffixHex: ref.suffixHex, templateVmHashBlake2b256: ref.templateVmHashBlake2b256 }, protocolFeePk: POOL_FEE, protocolFeeBps: "20", kasReserve: (10_000n * KAS).toString(), tokenReserve: "10000", feeBps: "30", nonce: "0" }
  });
  const venueProfile = poolFixtureVenueProfile({ networkId: config.networkId, poolCovenantId: POOL_ID, compiled: pool0 });
  const swapPolicy = swapPolicyFromProfileV6(venueProfile, { maxProtocolFeeKas: (5n * KAS).toString(), sellFloorNum: (9n * KAS / 10n).toString(), sellFloorDen: "1", buyCeilNum: (11n * KAS / 10n).toString(), buyCeilDen: "1", directionMask: "3", destScheme: 0x02 });
  const swapTree = buildSwapPolicyTreeV6([swapPolicy]);

  const state = { feeReserve: (5n * KAS).toString(), swapPrincipal: (100n * KAS).toString(), paused: "0", agentRoot: agentTree.root, swapRoot: swapTree.root, policyNonce: "0" };
  const posState = { ownerIdentifier: CONTROLLER_ID, identifierType: 2, amount: "300", isMinter: false };
  const posProgram = compileKcc20Program({ config, state: posState, familyBound: 2 });
  const chain = {
    predecessorOutpoint: { transactionId: "01".repeat(32), index: 0 },
    predecessorValue: (105n * KAS).toString(),
    covenantId: CONTROLLER_ID,
    fuel: { outpoint: { transactionId: "03".repeat(32), index: 0 }, amount: (10n * KAS).toString(), scriptPublicKeyHex: `20${FUEL}ac` },
    tokenPosition: { outpoint: { transactionId: "02".repeat(32), index: 0 }, value: (2n * KAS).toString(), scriptPublicKeyHex: posProgram.p2shSpkHex, covenantId: TOKEN_FAMILY, state: posState }
  };
  return { ref, descriptor, template, agentPolicy, agentTree, swapPolicy, swapTree, state, chain, posState, posProgram };
}

function ownerBuild(f, action, params) {
  return buildV6Transaction({ config, templateInput: f.template, stateInput: f.state, action, params, chain: { predecessorOutpoint: f.chain.predecessorOutpoint, predecessorValue: f.chain.predecessorValue, covenantId: CONTROLLER_ID, fuel: f.chain.fuel }, changeXOnly: FUEL, descriptor: f.descriptor });
}

test("v0.6 controller manifest: tokenAgentSpend (fuel-funded AND reserve-funded) builds, VERIFIES, and refuses every tamper class", { skip }, () => {
  const f = fixture();
  const spendParams = { spendAmount: "200", agentPk: AGENT, agents: [f.agentPolicy], recipient: RECIPIENT, recipients: [RECIPIENT], recipientCarryKasSompi: (KAS / 5n).toString() };

  /* fuel-funded: the fee comes from an ordinary UTXO; reserveConsumed is the owner's choice, bounded by the fee */
  const fuelled = buildV6Transaction({ config, templateInput: f.template, stateInput: f.state, action: "tokenAgentSpend", params: { ...spendParams, reserveConsumedSompi: "50000" }, chain: f.chain, changeXOnly: FUEL, descriptor: f.descriptor });
  const m = buildControllerIntentManifestV6({ build: fuelled, descriptor: f.descriptor, agentPolicy: f.agentPolicy, recipients: [RECIPIENT] });
  const v = verifyControllerIntentManifestV6({ manifest: m, descriptor: f.descriptor });
  assert.equal(v.verdict, "VERIFIED", JSON.stringify(v.failures));
  assert.ok(v.checks.length >= 25, `expected a substantial check catalogue, got ${v.checks.length}`);
  assert.equal(m.manifestVersion, CONTROLLER_MANIFEST_VERSION_1);
  assert.equal(m.controller.contractVersion, "policyvault-0.6");
  assert.equal(m.action.role, "agent");
  assert.equal(m.accounting.token.spendAmount, "200");
  assert.equal(m.accounting.token.positionAfter, "100");
  /* the two v0.6-only domains are surfaced separately and untouched by a spend */
  assert.equal(m.accounting.kas.predecessorSwapPrincipal, (100n * KAS).toString());
  assert.equal(m.accounting.kas.successorSwapPrincipal, (100n * KAS).toString());
  assert.equal(m.accounting.kas.principalDelta, "0");
  assert.match(m.transaction.storageMass, /^[0-9]+$/);

  /* reserve-funded: NO fuel input; the reserve pays exactly the network fee */
  const reserved = buildV6Transaction({ config, templateInput: f.template, stateInput: f.state, action: "tokenAgentSpend", params: spendParams, chain: { ...f.chain, fuel: undefined }, changeXOnly: FUEL, descriptor: f.descriptor });
  const mR = buildControllerIntentManifestV6({ build: reserved, descriptor: f.descriptor, agentPolicy: f.agentPolicy, recipients: [RECIPIENT] });
  const vR = verifyControllerIntentManifestV6({ manifest: mR, descriptor: f.descriptor });
  assert.equal(vR.verdict, "VERIFIED", JSON.stringify(vR.failures));
  assert.equal(mR.accounting.kas.reserveConsumed, mR.accounting.kas.fee, "reserve-funded: consumed == exact fee");

  /* TAMPER MATRIX — every mutation must REFUSE, and name a failing check */
  const tamper = (base, mut) => { const j = JSON.parse(JSON.stringify(base)); mut(j); return j; };
  const refusedBy = (mut, label) => {
    const r = verifyControllerIntentManifestV6({ manifest: tamper(m, mut), descriptor: f.descriptor });
    assert.equal(r.verdict, "REFUSED", `${label} must refuse`);
    assert.ok(r.failures.length > 0, `${label} must name a failing check`);
    return r.failures.map((x) => x.name);
  };
  refusedBy((j) => { j.accounting.kas.fee = (BigInt(j.accounting.kas.fee) + 1n).toString(); }, "declared fee inflated");
  refusedBy((j) => { j.accounting.token.spendAmount = "201"; }, "spend amount restated");
  refusedBy((j) => { j.policy.recipient = "99".repeat(32); }, "recipient substituted");
  refusedBy((j) => { j.policy.agentPolicy.tokenMaxPerSpend = "999999"; }, "agent cap forged");
  refusedBy((j) => { j.policy.agentPolicy.agentRecipientRoot = "00".repeat(32); }, "recipient allowlist forged");
  refusedBy((j) => { j.stateAfter.state.swapPrincipal = (BigInt(j.stateAfter.state.swapPrincipal) + 1n).toString(); }, "principal silently moved by a spend");
  refusedBy((j) => { j.stateAfter.state.swapRoot = "aa".repeat(32); }, "venue approval silently changed by a spend");
  refusedBy((j) => { j.stateAfter.state.policyNonce = "1"; }, "nonce advanced by a spend");
  refusedBy((j) => { const tx = JSON.parse(j.transaction.frozenCanonicalJson); tx.outputs[2].value = (BigInt(tx.outputs[2].value) * 2n).toString(); j.transaction.frozenCanonicalJson = JSON.stringify(tx); }, "recipient carry inflated in the bytes");
  refusedBy((j) => { const tx = JSON.parse(j.transaction.frozenCanonicalJson); tx.outputs.push({ value: "1000", scriptPublicKey: { version: 0, scriptHex: `20${"99".repeat(32)}ac` }, covenant: null }); j.transaction.frozenCanonicalJson = JSON.stringify(tx); }, "hidden extra output");
  refusedBy((j) => { j.manifestHash = "00".repeat(32); }, "manifest hash replaced");
  refusedBy((j) => { j.action.role = "owner"; j.manifestHash = require("../../core/intent/canonical").computeManifestHashV1((({ manifestHash, ...b }) => b)(j)); }, "agent action relabelled owner with a recomputed hash");

  /* descriptor substitution (issuer powers widened after the fact) */
  assert.equal(verifyControllerIntentManifestV6({ manifest: m, descriptor: { ...f.descriptor, issuerPowers: { ...f.descriptor.issuerPowers, freeze: true } } }).verdict, "REFUSED", "descriptor substitution");
  /* unknown manifest version */
  assert.equal(verifyControllerIntentManifestV6({ manifest: { ...m, manifestVersion: "policyvault-controller-intent-manifest/2" }, descriptor: f.descriptor }).verdict, "REFUSED", "unknown manifest version");
});

test("v0.6 controller manifest: all six owner control operations VERIFY and pin their own field", { skip }, () => {
  const f = fixture();
  const cases = [
    ["ownerSetAgentRoot", { newAgentRoot: "ab".repeat(32) }, (m) => assert.equal(m.stateAfter.state.policyNonce, "1")],
    ["ownerSetSwapRoot", { newSwapRoot: "cd".repeat(32) }, (m) => assert.equal(m.stateAfter.state.policyNonce, "1")],
    ["ownerTopUpReserve", { topUpReserveAmountSompi: (2n * KAS).toString() }, (m) => assert.equal(BigInt(m.accounting.kas.successorFeeReserve) - BigInt(m.accounting.kas.predecessorFeeReserve), 2n * KAS)],
    ["ownerFundSwapPrincipal", { fundSwapPrincipalSompi: (3n * KAS).toString() }, (m) => assert.equal(m.accounting.kas.principalDelta, (3n * KAS).toString())],
    ["ownerPause", {}, (m) => assert.equal(m.stateAfter.state.paused, "1")],
    ["ownerUnpause", {}, (m) => assert.equal(m.stateAfter.state.paused, "0")]
  ];
  for (const [action, params, extra] of cases) {
    const stateIn = action === "ownerUnpause" ? { ...f.state, paused: "1" } : f.state;
    const build = buildV6Transaction({ config, templateInput: f.template, stateInput: stateIn, action, params, chain: { predecessorOutpoint: f.chain.predecessorOutpoint, predecessorValue: f.chain.predecessorValue, covenantId: CONTROLLER_ID, fuel: f.chain.fuel }, changeXOnly: FUEL, descriptor: f.descriptor });
    const m = buildControllerIntentManifestV6({ build, descriptor: f.descriptor });
    const v = verifyControllerIntentManifestV6({ manifest: m, descriptor: f.descriptor });
    assert.equal(v.verdict, "VERIFIED", `${action}: ${JSON.stringify(v.failures)}`);
    assert.equal(m.action.role, "owner");
    assert.equal(m.action.opSelector, require("../../core/model/vault-state-v6").OWNER_OP_SELECTOR_V6[action]);
    extra(m);

    /* an owner op relabelled as a DIFFERENT owner op must refuse: the state
     * equations of the claimed action no longer hold. */
    const other = action === "ownerPause" ? "ownerUnpause" : "ownerPause";
    const relabelled = JSON.parse(JSON.stringify(m));
    relabelled.action.sdkAction = other;
    relabelled.action.opSelector = require("../../core/model/vault-state-v6").OWNER_OP_SELECTOR_V6[other];
    relabelled.manifestHash = require("../../core/intent/canonical").computeManifestHashV1((({ manifestHash, ...b }) => b)(relabelled));
    assert.equal(verifyControllerIntentManifestV6({ manifest: relabelled, descriptor: f.descriptor }).verdict, "REFUSED", `${action} relabelled ${other}`);
  }
});

test("v0.6 controller manifest: ownerTopUpReserve funding cannot be diverted into the swap principal", { skip }, () => {
  const f = fixture();
  const build = ownerBuild(f, "ownerTopUpReserve", { topUpReserveAmountSompi: (2n * KAS).toString() });
  const m = buildControllerIntentManifestV6({ build, descriptor: f.descriptor });
  assert.equal(verifyControllerIntentManifestV6({ manifest: m, descriptor: f.descriptor }).verdict, "VERIFIED");
  /* claim the same transaction funded the principal instead */
  const diverted = JSON.parse(JSON.stringify(m));
  diverted.stateAfter.state.feeReserve = f.state.feeReserve;
  diverted.stateAfter.state.swapPrincipal = (BigInt(f.state.swapPrincipal) + 2n * KAS).toString();
  const r = verifyControllerIntentManifestV6({ manifest: diverted, descriptor: f.descriptor });
  assert.equal(r.verdict, "REFUSED", "reserve top-up diverted to principal must refuse");
});

test("v0.6 controller manifest: ownerRecover returns BOTH KAS domains and the token position to the owner", { skip }, () => {
  const f = fixture();
  const build = buildV6Transaction({ config, templateInput: f.template, stateInput: f.state, action: "ownerRecover", params: {}, chain: f.chain, changeXOnly: FUEL, descriptor: f.descriptor });
  const m = buildControllerIntentManifestV6({ build, descriptor: f.descriptor });
  const v = verifyControllerIntentManifestV6({ manifest: m, descriptor: f.descriptor });
  assert.equal(v.verdict, "VERIFIED", JSON.stringify(v.failures));
  assert.equal(m.action.terminal, true);
  assert.equal(m.stateAfter, null);
  assert.equal(m.accounting.kas.terminalPayout, (105n * KAS).toString(), "reserve + principal");
  assert.equal(m.accounting.token.recoveredToOwner, "300");

  /* payout redirected away from the owner key */
  const redirected = JSON.parse(JSON.stringify(m));
  const tx = JSON.parse(redirected.transaction.frozenCanonicalJson);
  tx.outputs[0].scriptPublicKey.scriptHex = `20${"99".repeat(32)}ac`;
  redirected.transaction.frozenCanonicalJson = JSON.stringify(tx);
  assert.equal(verifyControllerIntentManifestV6({ manifest: redirected, descriptor: f.descriptor }).verdict, "REFUSED", "payout redirected");

  /* recover WITHOUT a token position */
  const noToken = buildV6Transaction({ config, templateInput: f.template, stateInput: f.state, action: "ownerRecover", params: {}, chain: { predecessorOutpoint: f.chain.predecessorOutpoint, predecessorValue: f.chain.predecessorValue, covenantId: CONTROLLER_ID, fuel: f.chain.fuel }, changeXOnly: FUEL, descriptor: f.descriptor });
  const mN = buildControllerIntentManifestV6({ build: noToken, descriptor: f.descriptor });
  assert.equal(verifyControllerIntentManifestV6({ manifest: mN, descriptor: f.descriptor }).verdict, "VERIFIED");
});

test("v0.6 controller manifest: BREAK-GLASS ownerRecover from a MALFORMED state verifies, and the fallback parse is never silent", { skip }, () => {
  const f = fixture();
  /* policyNonce above the strict v0.6 bound (1e9): normalizeStateV6 refuses
   * it, and the builder accepts it ONLY under allowMalformedState +
   * ownerRecover. Without the quarantined fallback the manifest would refuse
   * to describe a legitimate recovery, pushing the owner to sign blind. */
  const malformed = { ...f.state, policyNonce: "2000000000" };
  assert.throws(() => require("../../core/model/vault-state-v6").normalizeStateV6(malformed), /policyNonce/);

  const build = buildV6Transaction({ config, templateInput: f.template, stateInput: malformed, action: "ownerRecover", params: { allowMalformedState: true }, chain: { predecessorOutpoint: f.chain.predecessorOutpoint, predecessorValue: f.chain.predecessorValue, covenantId: CONTROLLER_ID, fuel: f.chain.fuel }, changeXOnly: FUEL, descriptor: f.descriptor });
  const m = buildControllerIntentManifestV6({ build, descriptor: f.descriptor });
  const v = verifyControllerIntentManifestV6({ manifest: m, descriptor: f.descriptor });
  assert.equal(v.verdict, "VERIFIED", JSON.stringify(v.failures));
  const stateParse = v.checks.find((c) => c.name === "stateParse");
  assert.ok(stateParse && stateParse.ok, "stateParse must always be reported");
  assert.match(stateParse.detail, /BREAK-GLASS/, "a shape-only parse must be surfaced loudly, never silently");
  assert.equal(m.accounting.kas.terminalPayout, (105n * KAS).toString(), "the payout is still proven from the frozen bytes");

  /* the same malformed state on a CONTINUING action must still REFUSE (the
   * quarantine holds: only ownerRecover may consume a malformed state) */
  const spend = buildV6Transaction({ config, templateInput: f.template, stateInput: f.state, action: "tokenAgentSpend", params: { spendAmount: "200", agentPk: AGENT, agents: [f.agentPolicy], recipient: RECIPIENT, recipients: [RECIPIENT], recipientCarryKasSompi: (KAS / 5n).toString() }, chain: { ...f.chain, fuel: undefined }, changeXOnly: FUEL, descriptor: f.descriptor });
  const spendManifest = buildControllerIntentManifestV6({ build: spend, descriptor: f.descriptor, agentPolicy: f.agentPolicy, recipients: [RECIPIENT] });
  assert.equal(verifyControllerIntentManifestV6({ manifest: spendManifest, descriptor: f.descriptor }).verdict, "VERIFIED");
  const malformedSpend = JSON.parse(JSON.stringify(spendManifest));
  malformedSpend.stateBefore.state.policyNonce = "2000000000";
  assert.equal(verifyControllerIntentManifestV6({ manifest: malformedSpend, descriptor: f.descriptor }).verdict, "REFUSED", "a continuing action must never fall back to the shape-only parse");
});

test("v0.6 controller manifest: a v0.6-labelled tokenDeposit now HAS a manifest (it previously had none)", { skip }, () => {
  const f = fixture();
  const userPk = "71".repeat(32);
  const userState = { ownerIdentifier: userPk, identifierType: 0, amount: "1000", isMinter: false };
  const userProgram = compileKcc20Program({ config, state: userState, familyBound: 2 });
  const build = buildTokenDepositV6({
    config,
    descriptor: f.descriptor,
    controller: { covenantId: CONTROLLER_ID, template: f.template },
    chain: { userPosition: { outpoint: { transactionId: "05".repeat(32), index: 0 }, value: (2n * KAS).toString(), scriptPublicKeyHex: userProgram.p2shSpkHex, covenantId: TOKEN_FAMILY, state: userState }, fuel: f.chain.fuel },
    params: { depositAmount: "600", depositCarryKasSompi: KAS.toString() },
    changeXOnly: FUEL
  });
  assert.equal(build.contractVersion, "policyvault-0.6");
  assert.equal(build.depositMechanics, "policyvault-0.5");

  /* the v0.5 token manifest REFUSES this build — that refusal is exactly the gap this module closes */
  assert.throws(() => require("../../core/intent/token-manifest-v5").buildTokenIntentManifest({ build, descriptor: f.descriptor }), /v0\.5 transition/);

  const m = buildControllerIntentManifestV6({ build, descriptor: f.descriptor });
  const v = verifyControllerIntentManifestV6({ manifest: m, descriptor: f.descriptor });
  assert.equal(v.verdict, "VERIFIED", JSON.stringify(v.failures));
  assert.equal(m.accounting.token.deposit, "600");
  assert.equal(m.accounting.token.remainderToUser, "400");

  const tampered = JSON.parse(JSON.stringify(m));
  tampered.policy.tokenNewStates[0].ownerIdentifier = "99".repeat(32);
  assert.equal(verifyControllerIntentManifestV6({ manifest: tampered, descriptor: f.descriptor }).verdict, "REFUSED", "deposit redirected away from the controller");
});

test("v0.6 controller manifest: swap builds are REFUSED here and routed to the swap manifest", { skip }, () => {
  const f = fixture();
  const ref = f.ref;
  const pool0 = compilePoolFixtureV6({ config, params: { tokenCovenantId: TOKEN_FAMILY, kcc20: { prefixHex: ref.prefixHex, suffixHex: ref.suffixHex, templateVmHashBlake2b256: ref.templateVmHashBlake2b256 }, protocolFeePk: POOL_FEE, protocolFeeBps: "20", kasReserve: (10_000n * KAS).toString(), tokenReserve: "10000", feeBps: "30", nonce: "0" } });
  const venueProfile = poolFixtureVenueProfile({ networkId: config.networkId, poolCovenantId: POOL_ID, compiled: pool0 });
  const noteState = { ownerIdentifier: POOL_ID, identifierType: 2, amount: "10000", isMinter: false };
  const noteProgram = compileKcc20Program({ config, state: noteState, familyBound: 2 });
  const chain = {
    ...f.chain,
    fuel: undefined,
    poolNote: { outpoint: { transactionId: "08".repeat(32), index: 0 }, value: (2n * KAS).toString(), scriptPublicKeyHex: noteProgram.p2shSpkHex, covenantId: TOKEN_FAMILY, state: noteState },
    pool: { outpoint: { transactionId: "09".repeat(32), index: 0 }, value: (10_000n * KAS).toString(), scriptPublicKeyHex: pool0.p2shSpkHex, covenantId: POOL_ID, state: { kasReserve: (10_000n * KAS).toString(), tokenReserve: "10000", feeBps: "30", nonce: "0" } }
  };
  const sell = buildV6Transaction({ config, templateInput: f.template, stateInput: f.state, action: "tokenAtomicSell", params: { agentPk: AGENT, agents: [f.agentPolicy], swapPolicies: [f.swapPolicy], swapPolicy: f.swapPolicy, venueProfile, deadlineDaa: "10000000", amountIn: "200", minKasOut: "1" }, chain, changeXOnly: AGENT, descriptor: f.descriptor });

  assert.throws(() => buildControllerIntentManifestV6({ build: sell, descriptor: f.descriptor, agentPolicy: f.agentPolicy }), (e) => e.code === "WRONG_MANIFEST_FOR_ACTION");
  assert.equal(router.routeBuild(sell).module, "core/intent/swap-manifest-v6.js");

  /* the router builds and verifies the RIGHT manifest for every v0.6 shape */
  const spend = buildV6Transaction({ config, templateInput: f.template, stateInput: f.state, action: "tokenAgentSpend", params: { spendAmount: "200", agentPk: AGENT, agents: [f.agentPolicy], recipient: RECIPIENT, recipients: [RECIPIENT], recipientCarryKasSompi: (KAS / 5n).toString() }, chain: { ...f.chain, fuel: undefined }, changeXOnly: FUEL, descriptor: f.descriptor });
  const routed = router.buildManifestForBuild({ build: spend, descriptor: f.descriptor, agentPolicy: f.agentPolicy, recipients: [RECIPIENT] });
  assert.equal(routed.manifestVersion, CONTROLLER_MANIFEST_VERSION_1);
  assert.equal(router.verifyManifest({ manifest: routed, descriptor: f.descriptor }).verdict, "VERIFIED");

  const routedSwap = router.buildManifestForBuild({ build: sell, descriptor: f.descriptor, agentPolicy: f.agentPolicy });
  assert.equal(routedSwap.manifestVersion, "policyvault-swap-intent-manifest/1");
  assert.equal(router.verifyManifest({ manifest: routedSwap, descriptor: f.descriptor }).verdict, "VERIFIED");
});
