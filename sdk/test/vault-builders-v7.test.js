"use strict";

/*
 * SDK/INTEGRATION: the v0.7 contract compiler + builders + finalizers,
 * driven by the REAL toolchain (silverc, the production pv_call_encoder,
 * pv_tx_probe). Classified REQUIREMENT_NOT_AVAILABLE (skipped, never
 * silently passed) when those binaries are absent.
 *
 * What this file holds that the production-byte suite cannot:
 *   - the COMPILER's geometry gate (a drifting root state region is refused
 *     at build time, not discovered at spend time);
 *   - the EXACT-FEE FREEZE across M-of-N signature collection — the 780-byte
 *     blob's length is constant for every threshold, so a build frozen with
 *     placeholders finalizes to the identical byte length;
 *   - the TRANSACTION SHAPES the authority model requires (a root input on
 *     every owner path, none on the agent path, the recovery payout at
 *     output 0);
 *   - the pipeline discipline: builders never broadcast, and a finalizer
 *     never advances chain state.
 *
 * The real-engine execution of these exact bytes is
 * tests/vm/tests/v7_sdk_integration.rs (the production-byte rule).
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
const { compileExactStateV7Root, compileExactStateV7, deriveRootPinsV7, assertRootPinsMatchV7 } = require("../src/contract-compiler-v7");
const { buildCreateV7Root, buildV7RootTransaction, finalizeV7RootTransaction, buildCreateV7Vault, buildV7Transaction, finalizeV7Transaction } = require("../src/vault-builders-v7");
const { frozenToWasmTransaction } = require("../src/frozen-tx-v3");
const { OWNER_SLOTS_V7, INACTIVE_SLOT_KEY, SIG_BLOB_LEN_V7, PLACEHOLDER_SLOT_HEX_V7 } = require("../../core/model/owner-set-v7");
const { ROOT_STATE_LEN_V7, ROOT_TAIL_LEN_V7, serializeRootStateHexV7, rootStateTailHexV7 } = require("../../core/model/vault-state-v7-root");
const { ENCODER_PATH } = require("../src/vault-builders-v4");

const config = loadConfig({ dataRoot: fs.mkdtempSync(path.join(os.tmpdir(), "pv7-build-")) });
const available = fs.existsSync(config.silvercPath) && fs.existsSync(ENCODER_PATH) && fs.existsSync(path.join(config.repoRoot, "tests/vm/target/debug/pv_tx_probe"));
const SKIP = !available && "REQUIREMENT_NOT_AVAILABLE: silverc / pv_call_encoder / pv_tx_probe";

const kaspa = available ? require(config.rustyKaspaModule) : null;
const KAS = 100000000n;
const KEY = (v) => new kaspa.PrivateKey(v.toString(16).padStart(2, "0").repeat(32));
const XO = (p) => p.toPublicKey().toXOnlyPublicKey().toString().toLowerCase();
const H = (b) => b.toString(16).padStart(2, "0").repeat(32);

const ORG_ID = H(0xa7);
const ROOT_ID = H(0x52);
const VAULT_COV_ID = H(0x43);
const TOKEN_FAMILY = H(0x54);
const ROOT_KAS = 3n * KAS;

function ctx() {
  const ownerKeys = [KEY(0x71), KEY(0x72), KEY(0x73)];
  const fuelKey = KEY(0x64);
  const agentKey = KEY(0x62);
  const recipientKey = KEY(0x63);
  const owners = [];
  for (let i = 0; i < OWNER_SLOTS_V7; i += 1) owners.push(i < 3 ? XO(ownerKeys[i]) : INACTIVE_SLOT_KEY);
  const rootTemplate = { orgId: ORG_ID, recoveryDelayDaa: "1000", successorPk: XO(KEY(0x7f)), successionDelayDaa: "2000", rootMaxFeePerTx: "200000" };
  const ownerSet = { owners, ownerM: 2, emergencyK: 1, recoveryM: 2 };
  const rootState = (over = {}) => ({ boundOrgId: ORG_ID, ...ownerSet, frozen: 0, rootNonce: 0, ...over });

  const ref = compileKcc20Program({ config, state: assets.kcc20.ZERO_STATE, familyBound: 2 });
  const descriptor = {
    schema: "policyvault-asset-descriptor/1",
    assetId: H(0x11),
    displayName: "Builder Token",
    tokenStandard: "kcc20/1",
    tokenCovenantId: TOKEN_FAMILY,
    acceptedTransferTemplates: [{ templateVmHashBlake2b256: ref.templateVmHashBlake2b256, prefixLen: ref.geometry.prefixLen, suffixLen: ref.geometry.suffixLen, stateLayout: "kcc20-state/1" }],
    decimalsDisplay: 2,
    issuerPowers: { mint: false, burn: false, freeze: false, blacklist: false, redemptionControl: false, upgradeMigration: false, controllerRotation: false, emergencyControl: false }
  };
  const rootPins = deriveRootPinsV7({ config, template: rootTemplate, ownerSet, covenantId: ROOT_ID });
  const vaultTemplate = {
    vaultId: H(0x44),
    descriptorHash: assets.computeDescriptorHash(descriptor),
    tokenCovenantId: TOKEN_FAMILY,
    templateVmHash: ref.templateVmHashBlake2b256,
    templatePrefixLen: ref.geometry.prefixLen,
    templateStateLen: ref.geometry.stateLen,
    templateSuffixLen: ref.geometry.suffixLen,
    ...rootPins,
    recoveryPk: XO(KEY(0x51))
  };
  const rTree = buildRecipientTree([XO(recipientKey)]);
  const policy = { agentPk: XO(agentKey), tokenMaxPerSpend: "250", tokenPeriodBudget: "400", periodLengthDaa: "1000", periodStartDaa: "5000", tokenPeriodSpent: "0", agentMaxFeePerTx: (1n * KAS).toString(), agentMaxCarryKas: (KAS / 4n).toString(), agentRecipientRoot: rTree.root };
  const tree = buildTokenAgentTreeV5([policy]);
  const vaultStateJson = (over = {}) => ({ feeReserve: (5n * KAS).toString(), paused: "0", agentRoot: tree.root, policyNonce: "0", ...over });
  const fuel = { outpoint: { transactionId: H(0x03), index: 0 }, amount: (1n * KAS).toString(), scriptPublicKeyHex: `20${XO(fuelKey)}ac` };
  const rootChain = { predecessorOutpoint: { transactionId: H(0x01), index: 0 }, covenantId: ROOT_ID, predecessorValue: ROOT_KAS.toString(), fuel };
  const rootInput = { template: rootTemplate, state: rootState(), outpoint: { transactionId: H(0x04), index: 0 }, covenantId: ROOT_ID, value: ROOT_KAS.toString() };
  const vaultChain = (over = {}) => ({ predecessorOutpoint: { transactionId: H(0x0a), index: 0 }, covenantId: VAULT_COV_ID, predecessorValue: (5n * KAS).toString(), fuel, ...over });
  const tokenPosition = () => {
    const st = { ownerIdentifier: VAULT_COV_ID, identifierType: 2, amount: "300", isMinter: false };
    const program = compileKcc20Program({ config, state: st, familyBound: 2 });
    return { outpoint: { transactionId: H(0x02), index: 0 }, value: (2n * KAS).toString(), scriptPublicKeyHex: program.p2shSpkHex, covenantId: TOKEN_FAMILY, state: st };
  };
  return { ownerKeys, fuelKey, agentKey, recipientKey, rootTemplate, ownerSet, rootState, descriptor, rootPins, vaultTemplate, policy, rTree, vaultStateJson, rootChain, rootInput, vaultChain, tokenPosition };
}

const sign = (build, i, k) => kaspa.createInputSignature(frozenToWasmTransaction(config, build.frozen), i, k).slice(2);
const signScript = (build, i, k) => kaspa.createInputSignature(frozenToWasmTransaction(config, build.frozen), i, k);

function refuses(fn, code) {
  assert.throws(fn, (e) => {
    assert.equal(e.code, code, `expected ${code}, got ${e.code}: ${e.message}`);
    return true;
  });
}

test("compiler: the root's live state IS its constructor args, and the geometry gate holds for every reachable state", { skip: SKIP }, () => {
  const c = ctx();
  const lens = new Set();
  const redeems = new Set();
  const identities = new Set();
  for (const over of [{}, { frozen: 1, rootNonce: 1 }, { rootNonce: 4294967295 }, { ownerM: 3, emergencyK: 3, recoveryM: 3 }]) {
    const compiled = compileExactStateV7Root({ config, template: c.rootTemplate, state: c.rootState(over) });
    assert.equal(compiled.contractName, "PolicyVaultOrgRoot");
    assert.equal(compiled.rootStateLen, ROOT_STATE_LEN_V7);
    assert.equal(compiled.stateRegionHex, serializeRootStateHexV7(c.rootState(over)), "the compiled region IS the core serializer's bytes");
    assert.equal(compiled.stateRegionHex.slice(-ROOT_TAIL_LEN_V7 * 2), rootStateTailHexV7({ frozen: BigInt(over.frozen ?? 0), rootNonce: BigInt(over.rootNonce ?? 0) }));
    lens.add(compiled.rootStateLen);
    redeems.add(compiled.scriptBytes.length);
    identities.add(compiled.rootTemplateVmHash);
  }
  assert.equal(lens.size, 1, "the state region length must be CONSTANT");
  assert.equal(redeems.size, 1, "the redeem length must not depend on the live state");
  assert.equal(identities.size, 1, "the template identity must not depend on the live state");
  /* a state whose bound org id is not the template's would compile to a root
   * no vault could ever authorize against */
  refuses(() => compileExactStateV7Root({ config, template: c.rootTemplate, state: c.rootState({ boundOrgId: H(0xb7) }) }), "ORG_ID_MISMATCH");
});

test("compiler: a rooted vault's pinned root template is cross-checked against a REAL compiled root", { skip: SKIP }, () => {
  const c = ctx();
  const compiled = assertRootPinsMatchV7({ config, vaultTemplate: c.vaultTemplate, rootTemplate: c.rootTemplate, rootOwnerSet: c.ownerSet });
  assert.equal(compiled.rootTemplateVmHash, c.vaultTemplate.rootTemplateVmHash);
  for (const bad of [{ rootTemplateVmHash: H(0xee) }, { rootPrefixLen: 2 }, { rootSuffixLen: c.vaultTemplate.rootSuffixLen + 1 }]) {
    refuses(() => assertRootPinsMatchV7({ config, vaultTemplate: { ...c.vaultTemplate, ...bad }, rootTemplate: c.rootTemplate, rootOwnerSet: c.ownerSet }), "ROOT_PIN_DRIFT");
  }
  /* a DIFFERENT root template constant is a different root version entirely */
  refuses(() => assertRootPinsMatchV7({ config, vaultTemplate: c.vaultTemplate, rootTemplate: { ...c.rootTemplate, rootMaxFeePerTx: "200001" }, rootOwnerSet: c.ownerSet }), "ROOT_PIN_DRIFT");
  const vault = compileExactStateV7({ config, template: c.vaultTemplate, state: c.vaultStateJson() });
  assert.equal(vault.contractName, "PolicyVaultRootedToken");
  assert.ok(vault.scriptBytes.length > 9000, "the rooted vault redeem is the v0.5 controller plus the root-authorization block");
});

test("root genesis derives the covenant id AND the pins every rooted vault must carry", { skip: SKIP }, () => {
  const c = ctx();
  const build = buildCreateV7Root({
    config,
    template: c.rootTemplate,
    ownerSet: c.ownerSet,
    rootValueSompi: ROOT_KAS.toString(),
    funding: [{ outpoint: { transactionId: H(0x05), index: 0 }, amount: (10n * KAS).toString(), scriptPublicKeyHex: `20${XO(c.fuelKey)}ac` }],
    changeXOnly: XO(c.fuelKey)
  });
  assert.equal(build.kind, "orgRootGenesis");
  assert.match(build.covenantId, /^[0-9a-f]{64}$/);
  assert.equal(build.rootPins.orgRootCovenantId, build.covenantId);
  assert.equal(build.rootPins.rootStateLen, ROOT_STATE_LEN_V7);
  assert.equal(build.initialState.rootNonce, "0");
  assert.equal(build.initialState.frozen, "0");
  assert.equal(build.frozen.outputs[0].covenant.covenantId, build.covenantId);
  assert.equal(build.frozen.outputs[0].value, ROOT_KAS);
  assert.equal(build.ownerSlots.length, 3);
  /* builders never broadcast and never carry a submitted flag */
  assert.equal(build.frozen.inputs[0].signatureScript, undefined);
  assert.ok(!("submitted" in build) && !("txid" in build));
});

test("the exact-fee freeze survives M-of-N signature collection (the blob length is constant)", { skip: SKIP }, () => {
  const c = ctx();
  const build = buildV7RootTransaction({ config, templateInput: c.rootTemplate, stateInput: c.rootState(), action: "authorize", chain: c.rootChain, changeXOnly: XO(c.fuelKey) });
  assert.equal(build.requiredApprovals, "2");
  assert.equal(build.authorityClass, "AUTHORITY-NEUTRAL");
  assert.equal(build.minSequence, "0");
  const s1 = sign(build, 0, c.ownerKeys[0]);
  const s2 = sign(build, 0, c.ownerKeys[1]);
  const s3 = sign(build, 0, c.ownerKeys[2]);
  const fuelScript = signScript(build, 1, c.fuelKey);

  const two = finalizeV7RootTransaction({ build, approvals: [{ slot: 1, signatureHex: s1 }, { slot: 2, signatureHex: s2 }], fuelSignatureScriptHex: fuelScript });
  const three = finalizeV7RootTransaction({ build, approvals: [{ slot: 1, signatureHex: s1 }, { slot: 2, signatureHex: s2 }, { slot: 3, signatureHex: s3 }], fuelSignatureScriptHex: fuelScript });
  assert.equal(two.finalTransaction.inputs[0].signatureScript.length, three.finalTransaction.inputs[0].signatureScript.length, "2-of-3 and 3-of-3 must produce the SAME byte length");
  assert.equal(two.txId, three.txId, "the frozen transaction id does not depend on which slots signed");
  assert.equal(two.ownerSigsBlobHex.length, SIG_BLOB_LEN_V7 * 2);
  assert.deepEqual(two.signedSlots, [1, 2]);
  assert.deepEqual(three.signedSlots, [1, 2, 3]);
  assert.ok(two.ownerSigsBlobHex.includes(PLACEHOLDER_SLOT_HEX_V7), "an abstaining slot carries the canonical placeholder");
  /* the 9 INACTIVE slots always hold the placeholder; only slot 3 differs
   * between the two blobs, so the 2-of-3 blob has exactly one more of them */
  const countPlaceholders = (hex) => hex.match(new RegExp(PLACEHOLDER_SLOT_HEX_V7, "g")).length;
  assert.equal(countPlaceholders(two.ownerSigsBlobHex), countPlaceholders(three.ownerSigsBlobHex) + 1);

  /* the finalizer refuses an under-quorum blob before any bytes leave */
  refuses(() => finalizeV7RootTransaction({ build, approvals: [{ slot: 1, signatureHex: s1 }], fuelSignatureScriptHex: fuelScript }), "UNDER_QUORUM");
  refuses(() => finalizeV7RootTransaction({ build, approvals: [{ slot: 1, signatureHex: s1 }, { slot: 2, signatureHex: s1 }], fuelSignatureScriptHex: fuelScript }), "SIGNATURE_REUSED");
  refuses(() => finalizeV7RootTransaction({ build, approvals: [{ slot: 1, signatureHex: s1 }, { slot: 1, signatureHex: s2 }], fuelSignatureScriptHex: fuelScript }), "DUPLICATE_SLOT");
  refuses(() => finalizeV7RootTransaction({ build, approvals: [{ slot: 1, signatureHex: s1 }, { publicKey: XO(KEY(0x6f)), signatureHex: s2 }], fuelSignatureScriptHex: fuelScript }), "OWNER_NOT_IN_SET");
  refuses(() => finalizeV7RootTransaction({ build, approvals: [{ slot: 1, signatureHex: s1.slice(0, -2) + "02" }, { slot: 2, signatureHex: s2 }], fuelSignatureScriptHex: fuelScript }), "SIGHASH_NOT_ALL");
});

test("the age-gated paths set the covenant input's sequence; the value rule is asserted at build time", { skip: SKIP }, () => {
  const c = ctx();
  const recover = buildV7RootTransaction({
    config,
    templateInput: c.rootTemplate,
    stateInput: c.rootState(),
    action: "ownerRecover",
    params: { newOwnerSet: { owners: [XO(KEY(0x81)), XO(KEY(0x82)), ...new Array(10).fill(INACTIVE_SLOT_KEY)], ownerM: 2, emergencyK: 1, recoveryM: 1 } },
    chain: c.rootChain,
    changeXOnly: XO(c.fuelKey)
  });
  assert.equal(recover.minSequence, "1000");
  assert.equal(recover.frozen.inputs[0].sequence, 1000n, "the covenant input carries the relative idle age");
  assert.equal(recover.successorState.frozen, "1", "decision D6");
  assert.equal(recover.accounting.kas.rootValueLoss, "0", "the fuel pays the fee, so the root loses nothing");
  assert.equal(recover.accounting.kas.rootValueBefore, recover.accounting.kas.rootValueAfter);

  const succession = buildV7RootTransaction({
    config,
    templateInput: c.rootTemplate,
    stateInput: c.rootState(),
    action: "succession",
    params: { newOwnerSet: { owners: [XO(KEY(0x81)), XO(KEY(0x82)), ...new Array(10).fill(INACTIVE_SLOT_KEY)], ownerM: 2, emergencyK: 1, recoveryM: 1 } },
    chain: c.rootChain,
    changeXOnly: XO(c.fuelKey)
  });
  assert.equal(succession.frozen.inputs[0].sequence, 2000n);
  assert.equal(succession.encoderFunction, "rootSuccession");
  assert.equal(succession.classForPreviousSet, "TERMINAL");
  refuses(() => finalizeV7RootTransaction({ build: succession, approvals: [], fuelSignatureScriptHex: signScript(succession, 1, c.fuelKey) }), "SUCCESSION_TAKES_NO_APPROVALS");
});

test("owner operations carry the root as an INPUT and no signature of their own; the agent path carries neither", { skip: SKIP }, () => {
  const c = ctx();
  for (const [action, params, prevOver, expectRootAction, expectSelector] of [
    ["ownerSetAgentRoot", { agents: [{ ...c.policy, agentPk: H(0x71), recipients: [...c.rTree.recipients] }] }, {}, "authorize", 0], // STALE ASSUMPTION corrected (rc27, R7-02): the builder now REQUIRES the full new policy set WITH recipients and DERIVES the root — a bare newAgentRoot is refused (asserted in org-root-hostile-matrix-v7); this test's own claim (root as an INPUT, no owner-op signature) is unchanged
    ["ownerTopUpReserve", { topUpReserveAmountSompi: (KAS / 2n).toString() }, {}, "authorize", 1],
    ["ownerPause", {}, {}, "authorize", 2],
    ["ownerUnpause", {}, { paused: "1" }, "authorize", 3],
    ["ownerEmergencyPause", {}, {}, "freeze", 4]
  ]) {
    const build = buildV7Transaction({ config, templateInput: c.vaultTemplate, stateInput: c.vaultStateJson(prevOver), action, params, chain: c.vaultChain({ root: c.rootInput }), changeXOnly: XO(c.fuelKey), descriptor: c.descriptor });
    assert.equal(build.hasRootInput, true, `${action}: an owner operation MUST spend the root`);
    assert.equal(build.callExtra.opSelector, expectSelector);
    assert.equal(build.rootAuthority.rootActionName, expectRootAction, `${action} rides a ${expectRootAction} root`);
    assert.equal(build.rootAuthority.expectFrozenAfter, expectRootAction === "freeze" ? "1" : "0");
    assert.equal(build.rootAuthority.inputIndex, 1);
    assert.equal(build.frozen.inputs.length, 3, `${action}: vault + root + fuel`);
    assert.equal(build.frozen.outputs.length, 3, `${action}: vault successor + root successor + change`);
    assert.equal(build.frozen.outputs[1].covenant.covenantId, ROOT_ID);
    const signers = expectRootAction === "freeze" ? [0] : [0, 1];
    const approvals = signers.map((i) => ({ slot: i + 1, signatureHex: sign(build, 1, c.ownerKeys[i]) }));
    const fin = finalizeV7Transaction({ build, approvals, fuelSignatureScriptHex: signScript(build, 2, c.fuelKey) });
    assert.equal(fin.satisfiedApprovals, String(signers.length));
    assert.ok(fin.finalTransaction.inputs[0].signatureScript.length > 0);
    assert.ok(fin.finalTransaction.inputs[1].signatureScript.length > 0);
    /* the vault path carries NO signature — the root input is the authority */
    refuses(() => finalizeV7Transaction({ build, agentSignatureHex: sign(build, 0, c.ownerKeys[0]), approvals, fuelSignatureScriptHex: signScript(build, 2, c.fuelKey) }), "OWNER_PATH_TAKES_NO_SIGNATURE");
  }

  /* the DELEGATE path never touches the root, in either direction */
  const spend = buildV7Transaction({
    config,
    templateInput: c.vaultTemplate,
    stateInput: c.vaultStateJson(),
    action: "tokenAgentSpend",
    params: { spendAmount: "200", agentPk: XO(c.agentKey), agents: [c.policy], recipient: XO(c.recipientKey), recipients: [...c.rTree.recipients], recipientCarryKasSompi: (KAS / 5n).toString(), reserveConsumedSompi: "50000" },
    chain: c.vaultChain({ tokenPosition: c.tokenPosition() }),
    changeXOnly: XO(c.fuelKey),
    descriptor: c.descriptor
  });
  assert.equal(spend.hasRootInput, false);
  assert.equal(spend.rootAuthority, null);
  refuses(() => finalizeV7Transaction({ build: spend, agentSignatureHex: sign(spend, 0, c.agentKey), approvals: [{ slot: 1, signatureHex: sign(spend, 0, c.ownerKeys[0]) }], fuelSignatureScriptHex: signScript(spend, 2, c.fuelKey) }), "AGENT_PATH_TAKES_NO_APPROVALS");
  refuses(() => buildV7Transaction({ config, templateInput: c.vaultTemplate, stateInput: c.vaultStateJson(), action: "tokenAgentSpend", params: { spendAmount: "200", agentPk: XO(c.agentKey), agents: [c.policy], recipient: XO(c.recipientKey), recipients: [...c.rTree.recipients], recipientCarryKasSompi: (KAS / 5n).toString() }, chain: c.vaultChain({ root: c.rootInput, tokenPosition: c.tokenPosition() }), changeXOnly: XO(c.fuelKey), descriptor: c.descriptor }), "AGENT_PATH_TAKES_NO_ROOT");
});

test("break-glass recovery pays the GENESIS-PINNED destination at output 0 and cannot be redirected by a builder caller", { skip: SKIP }, () => {
  const c = ctx();
  const build = buildV7Transaction({ config, templateInput: c.vaultTemplate, stateInput: c.vaultStateJson(), action: "ownerRecover", params: { recoveryPk: H(0xbb) /* ignored by construction */ }, chain: c.vaultChain({ root: c.rootInput, tokenPosition: c.tokenPosition() }), changeXOnly: XO(c.fuelKey), descriptor: c.descriptor });
  assert.equal(build.frozen.outputs[0].scriptPublicKey.scriptHex, `20${c.vaultTemplate.recoveryPk}ac`, "the destination is a TEMPLATE CONSTANT, never a parameter");
  assert.equal(build.frozen.outputs[0].value, 5n * KAS);
  assert.equal(build.successorState, null, "recovery is TERMINAL");
  assert.equal(build.accounting.token.recoveredToRecoveryPk, "300");
  assert.equal(build.rootAuthority.rootActionName, "authorize", "terminating a vault needs the FULL quorum");
  assert.equal(build.hasTokenInput, true);
  const fin = finalizeV7Transaction({ build, approvals: [0, 1].map((i) => ({ slot: i + 1, signatureHex: sign(build, 1, c.ownerKeys[i]) })), fuelSignatureScriptHex: signScript(build, 3, c.fuelKey) });
  assert.equal(fin.finalTransaction.inputs.length, 4);
  assert.ok(fin.finalTransaction.inputs.every((i) => typeof i.signatureScript === "string" && i.signatureScript.length > 0), "every input is signed at finalize");
});

test("rooted vault genesis pins the root covenant id and the root template identity", { skip: SKIP }, () => {
  const c = ctx();
  const build = buildCreateV7Vault({
    config,
    templateInput: c.vaultTemplate,
    initialStateInput: c.vaultStateJson(),
    funding: [{ outpoint: { transactionId: H(0x06), index: 0 }, amount: (10n * KAS).toString(), scriptPublicKeyHex: `20${XO(c.fuelKey)}ac` }],
    changeXOnly: XO(c.fuelKey),
    descriptor: c.descriptor
  });
  assert.equal(build.kind, "genesis");
  assert.equal(build.orgRootCovenantId, ROOT_ID);
  assert.equal(build.template.rootStateLen, ROOT_STATE_LEN_V7);
  assert.equal(build.frozen.outputs[0].covenant.covenantId, build.covenantId);
  assert.throws(() => buildCreateV7Vault({ config, templateInput: c.vaultTemplate, initialStateInput: c.vaultStateJson({ policyNonce: "1" }), funding: [{ outpoint: { transactionId: H(0x06), index: 0 }, amount: (10n * KAS).toString(), scriptPublicKeyHex: `20${XO(c.fuelKey)}ac` }], changeXOnly: XO(c.fuelKey), descriptor: c.descriptor }), /policyNonce 0/);
});
