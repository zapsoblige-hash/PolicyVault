"use strict";

/*
 * PolicyVault v0.7 ORGANIZATIONAL ROOT + ROOTED VAULT transaction builders.
 *
 * Builds (and FREEZES) every v0.7 transition offline from consensus-visible
 * bytes only, then finalizes it with externally-produced signatures. Same
 * discipline as the v0.5/v0.6 builders and the same hard rules:
 *   BUILDERS NEVER BROADCAST. The frozen form is the security object. The
 *   exact fee is computed from the final byte shape, the production
 *   pv_call_encoder produces every covenant-call byte, and ANY drift between
 *   planned and final bytes fails closed.
 *
 * WHAT IS NEW IN v0.7 — the owner authority is an INPUT, not a key:
 *
 *   root-only        in: [root(sequence), fuel]         out: [root', change]
 *   rooted owner op  in: [vault, root(seq), fuel]       out: [vault', root', change]
 *   rooted recover    in: [vault, root, token?, fuel]   out: [payout(recoveryPk),
 *                                                            root', token->recoveryPk?,
 *                                                            change]
 *   delegate spend   in: [vault, token, fuel?]          out: [vault', token self,
 *                                                            token recipient, change?]
 *                    — NO root input; byte-for-byte the frozen v0.5 shape
 *   root genesis     in: [funding...]                   out: [root, change]
 *   vault genesis    in: [funding...]                   out: [vault, change]
 *   token deposit    in: [user token, fuel]             out: [deposit(+remainder), change]
 *
 * The M-of-N owner signatures are collected OUT OF BAND into the root's
 * 780-byte blob. Because that blob's LENGTH is constant for every threshold
 * (abstaining slots carry the canonical placeholder), the exact-fee freeze
 * survives signature collection untouched: the build freezes against an
 * all-placeholder blob and the finalizer swaps in the real one, asserting the
 * call length is identical.
 *
 * FEES. Every v0.7 owner path takes its network fee from an ordinary FUEL
 * UTXO, exactly as the frozen v0.5 owner path does: an owner operation pins
 * every covenant value, so the fee cannot come from a covenant output. The
 * root therefore never loses value (successor value == input value), which
 * satisfies the covenant's `value >= input - rootMaxFeePerTx` rule with the
 * whole allowance to spare — and the allowance is still asserted, so a build
 * can never quietly exceed it.
 *
 * Status: IMPLEMENTED (SDK). Production-byte proof:
 * sdk/tools/gen-v7-vectors.js + tests/vm/tests/v7_sdk_integration.rs execute
 * every built shape on the real engine.
 */

const fs = require("fs");
const path = require("path");

const { parseSompi, parsePositiveSompi } = require("./amounts");
const { normalizeHex, normalizeXOnlyPubkey } = require("./vault-state");
const {
  CONTRACT_VERSION_V7,
  resolveV7Abi,
  resolveOwnerOpAuthorityV7,
  normalizeTemplateV7,
  normalizeStateV7,
  normalizeStateV7ForRecovery,
  computeStateIdV7,
  stateToJsonV7
} = require("../../core/model/vault-state-v7");
const {
  CONTRACT_VERSION_V7_ROOT,
  resolveV7RootAbi,
  normalizeRootTemplateV7,
  normalizeRootStateV7,
  genesisRootStateV7,
  computeRootStateIdV7,
  computeRootStateDigestV7,
  rootStateToJsonV7,
  rootTemplateToJsonV7,
  serializeRootStateHexV7
} = require("../../core/model/vault-state-v7-root");
const { rootTransitionV7, assertRootValueRuleV7 } = require("../../core/model/vault-transitions-v7-root");
const {
  tokenAgentSpendSuccessorV7,
  tokenContinuationStatesV7,
  recoverPlanV7,
  ownerOpSuccessorV7
} = require("../../core/model/vault-transitions-v7");
const {
  OWNER_SLOTS_V7,
  SIG_BLOB_LEN_V7,
  normalizeOwnerSetV7,
  activeOwnerSlotsV7,
  assembleOwnerSigsBlobV7,
  placeholderOwnerSigsBlobV7,
  resolveRootActionV7,
  normalizeSlotSignatureHex
} = require("../../core/model/owner-set-v7");
const { V7_BUDGET, selectComputeBudgetV7, selectRootComputeBudgetV7, selectTokenInputBudgetV7 } = require("../../core/model/compute-budget-v7");
const { buildTokenAgentTreeV5, generateTokenAgentProofV5, verifyTokenAgentProofV5 } = require("./agent-merkle-v5");
const { buildRecipientTree, generateRecipientProof, verifyRecipientProof } = require("./recipient-merkle-v3");
const { compileExactStateV7, compileExactStateV7Root } = require("./contract-compiler-v7");
const { normalizeFrozenTxV3, describeFrozenTx, feeDescriptorFromFrozen, canonicalFrozenTxJson } = require("./frozen-tx-v3");
const { calculateRequiredFee } = require("./fee-mass");
const { covenantSigscript } = require("./spend-vault");
const { p2pkScriptHex } = require("./approval-package-v4");
const { runEncoderV4, PLACEHOLDER_SIG_HEX, MAX_TX_FEE_IO } = require("./vault-builders-v4");
const { encodeTokenTransfer } = require("./vault-builders-v5");
const assets = require("../../core/assets");
const { verifiedTokenPosition, compileKcc20Program } = require("./token-program-kcc20");
const { assertStorageMassWithinLimit } = require("./storage-mass-preflight");

const ORDINARY_SIGSCRIPT_LEN = 66;
const OWNER_CONTROL_ACTIONS_V7 = new Set(["ownerSetAgentRoot", "ownerTopUpReserve", "ownerPause", "ownerUnpause", "ownerEmergencyPause"]);
const SPEND_ACTIONS_V7 = new Set(["tokenAgentSpend"]);
const ROOT_ACTIONS_V7_NAMES = new Set(["authorize", "rotate", "freeze", "unfreeze", "ownerRecover", "succession"]);

function fail(message, code) {
  const e = new Error(`vault-builders-v7: ${message}`);
  if (code) e.code = code;
  throw e;
}

function deepFreeze(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const key of Object.keys(value)) deepFreeze(value[key]);
  }
  return value;
}

function normalizeOutpoint(op, label) {
  const transactionId = normalizeHex(op?.transactionId, 32, `${label}.transactionId`);
  const index = Number(op?.index);
  if (!Number.isInteger(index) || index < 0 || index > 0xffffffff) fail(`${label}.index out of range`);
  return { transactionId, index };
}

function normalizeFuel(fuel) {
  if (!fuel || typeof fuel !== "object") fail("chain.fuel { outpoint, amount, scriptPublicKeyHex } is required for this operation (ordinary fee UTXO)", "FUEL_REQUIRED");
  const scriptPublicKeyHex = String(fuel.scriptPublicKeyHex ?? "").toLowerCase();
  if (!/^[0-9a-f]+$/.test(scriptPublicKeyHex) || scriptPublicKeyHex.length % 2 !== 0) fail("chain.fuel.scriptPublicKeyHex must be hex");
  return { outpoint: normalizeOutpoint(fuel.outpoint, "chain.fuel.outpoint"), amount: parsePositiveSompi(fuel.amount, "chain.fuel.amount"), scriptPublicKeyHex };
}

function exactFee(draft, sigScriptLengths) {
  const probe = normalizeFrozenTxV3(draft);
  return calculateRequiredFee(feeDescriptorFromFrozen(probe, sigScriptLengths)).minimumRequiredFee;
}

function p2shOf(config, scriptBytes) {
  const { loadKaspa } = require("./chain");
  const kaspa = loadKaspa(config);
  return String(kaspa.payToScriptHashScript(scriptBytes.toString("hex")).script).toLowerCase();
}

/* ------------------------------------------------------------------ */
/* encoder call JSON                                                    */
/* ------------------------------------------------------------------ */

/* The root successor in the encoder's field names (boundOrgId comes from the
 * constructor arg, exactly as boundVaultId does in every vault generation). */
function rootSuccessorCallJsonV7(state) {
  const s = normalizeRootStateV7(state);
  const out = {};
  for (let i = 0; i < OWNER_SLOTS_V7; i += 1) out[`owner${i + 1}`] = s.owners[i];
  out.ownerM = s.ownerM.toString();
  out.emergencyK = s.emergencyK.toString();
  out.recoveryM = s.recoveryM.toString();
  out.frozen = s.frozen.toString();
  out.rootNonce = s.rootNonce.toString();
  return out;
}

function successorCallJsonV7(stateJson) {
  return { feeReserve: stateJson.feeReserve, paused: Number(stateJson.paused), agentRoot: stateJson.agentRoot, policyNonce: stateJson.policyNonce };
}

function kcc20StateJson(s) {
  return { ownerIdentifier: s.ownerIdentifier, identifierType: s.identifierType, amount: s.amount.toString(), isMinter: s.isMinter };
}

/* ------------------------------------------------------------------ */
/* ROOT: genesis                                                        */
/* ------------------------------------------------------------------ */

/*
 * GENESIS of an organizational root: ordinary funding inputs -> [the root
 * output holding the organization's fee float, change]. The covenant id the
 * whole organization will be pinned to is DERIVED here from the first
 * funding outpoint + the unbound output, exactly as every prior generation
 * derives a controller's covenant id.
 */
function buildCreateV7Root({ config, template: templateInput, ownerSet: ownerSetInput, rootValueSompi, funding, changeXOnly, contractVersion }) {
  const abi = resolveV7RootAbi(contractVersion ?? CONTRACT_VERSION_V7_ROOT);
  const template = normalizeRootTemplateV7(templateInput);
  const ownerSet = normalizeOwnerSetV7(ownerSetInput);
  const state = genesisRootStateV7({ template, ownerSet });
  const value = parsePositiveSompi(rootValueSompi, "rootValueSompi");
  if (!Array.isArray(funding) || funding.length === 0) fail("funding must be a non-empty array of ordinary UTXOs ({ outpoint, amount, scriptPublicKeyHex })");
  const fundingInputs = funding.map((f, i) => {
    const spk = String(f.scriptPublicKeyHex ?? "").toLowerCase();
    if (!/^[0-9a-f]+$/.test(spk) || spk.length % 2 !== 0) fail(`funding[${i}].scriptPublicKeyHex must be hex`);
    return { outpoint: normalizeOutpoint(f.outpoint, `funding[${i}].outpoint`), amount: parsePositiveSompi(f.amount, `funding[${i}].amount`), scriptPublicKeyHex: spk };
  });
  const change = normalizeHex(changeXOnly, 32, "changeXOnly");

  const compiled = compileExactStateV7Root({ config, template, state, contractVersion: abi.version });
  const { loadKaspa } = require("./chain");
  const kaspa = loadKaspa(config);
  const spkHex = p2shOf(config, compiled.scriptBytes);
  const outputs = [
    { value, scriptPublicKey: { version: 0, scriptHex: spkHex }, covenant: null },
    { value: 1n, scriptPublicKey: { version: 0, scriptHex: p2pkScriptHex(change) }, covenant: null }
  ];
  const unbound = new kaspa.TransactionOutput(value, kaspa.payToScriptHashScript(compiled.scriptBytes.toString("hex")));
  const genesisCovenantId = kaspa
    .covenantId({ transactionId: fundingInputs[0].outpoint.transactionId, index: fundingInputs[0].outpoint.index }, [{ index: 0, output: unbound }])
    .toString()
    .toLowerCase();
  outputs[0] = { ...outputs[0], covenant: { authorizingInput: 0, covenantId: genesisCovenantId } };

  const inputs = fundingInputs.map((f) => ({ previousOutpoint: f.outpoint, sequence: 0n, computeBudget: V7_BUDGET.ORDINARY_INPUT, utxo: { amount: f.amount, scriptPublicKey: { version: 0, scriptHex: f.scriptPublicKeyHex }, covenantId: null, blockDaaScore: 0n } }));
  const draft = { version: 1, inputs, outputs, lockTime: 0n, subnetworkId: "00".repeat(20), gas: 0n, payload: "" };
  const requiredFee = exactFee(draft, inputs.map(() => ORDINARY_SIGSCRIPT_LEN));
  const totalFunding = fundingInputs.reduce((s, f) => s + f.amount, 0n);
  const changeValue = totalFunding - value - requiredFee;
  if (changeValue <= 0n) fail(`funding ${totalFunding} cannot cover the root value ${value} + fee ${requiredFee}`, "INSUFFICIENT_FUEL");
  outputs[1] = { ...outputs[1], value: changeValue };
  const frozen = normalizeFrozenTxV3({ ...draft, outputs });
  assertStorageMassWithinLimit(frozen, "policyvault-0.7 builder");
  const described = describeFrozenTx(frozen);

  return deepFreeze({
    kind: "orgRootGenesis",
    contractVersion: abi.version,
    networkId: config.networkId,
    action: "createOrgRoot",
    template: rootTemplateToJsonV7(template),
    ownerSlots: activeOwnerSlotsV7(ownerSet),
    initialState: rootStateToJsonV7(state),
    stateId: compiled.stateId,
    stateDigest: computeRootStateDigestV7(state),
    rootOutputIndex: 0,
    changeIndex: 1,
    covenantId: genesisCovenantId,
    scriptSha256: compiled.scriptSha256,
    rootScriptHex: compiled.scriptHex,
    /* the pins a rooted vault must carry to authorize against THIS root */
    rootPins: Object.freeze({
      orgRootCovenantId: genesisCovenantId,
      rootTemplateVmHash: compiled.rootTemplateVmHash,
      rootPrefixLen: compiled.rootPrefixLen,
      rootStateLen: compiled.rootStateLen,
      rootSuffixLen: compiled.rootSuffixLen
    }),
    accounting: Object.freeze({ kas: Object.freeze({ rootValue: value.toString(), fee: requiredFee.toString() }) }),
    frozen,
    frozenCanonicalJson: canonicalFrozenTxJson(frozen),
    txId: described.txId,
    requiredFeeSompi: requiredFee.toString(),
    encoderBuildDir: compiled.buildDir
  });
}

/* ------------------------------------------------------------------ */
/* ROOT: one governance transition                                      */
/* ------------------------------------------------------------------ */

/*
 * Build (and FREEZE) ONE root-only transition.
 *   action  authorize | rotate | freeze | unfreeze | ownerRecover | succession
 *   params  { newOwnerSet } for the set-changing paths
 *   chain   { predecessorOutpoint, covenantId, predecessorValue, fuel }
 *
 * The covenant input's `sequence` carries the RELATIVE INPUT AGE the two
 * dead-man's-switch paths require (`this.age >= D`, compiled to
 * OpCheckSequenceVerify). The consensus-level UTXO-age rule behind it
 * (check_sequence_lock) is NOT exercised by a script engine and is proven
 * live on testnet-10 at gate I5.
 */
function buildV7RootTransaction({ config, contractVersion, templateInput, stateInput, action, params = {}, chain, changeXOnly }) {
  const abi = resolveV7RootAbi(contractVersion ?? CONTRACT_VERSION_V7_ROOT);
  if (!ROOT_ACTIONS_V7_NAMES.has(action)) fail(`unknown v0.7 root action ${JSON.stringify(action)} — failing closed`, "UNKNOWN_ROOT_ACTION");
  const template = normalizeRootTemplateV7(templateInput);
  const state = normalizeRootStateV7(stateInput);

  const predecessorOutpoint = normalizeOutpoint(chain?.predecessorOutpoint, "chain.predecessorOutpoint");
  const covenantId = normalizeHex(chain?.covenantId, 32, "chain.covenantId");
  const predecessorValue = parsePositiveSompi(chain?.predecessorValue, "chain.predecessorValue");
  const fuel = normalizeFuel(chain?.fuel);
  const change = normalizeHex(changeXOnly, 32, "changeXOnly");

  const plan = rootTransitionV7(action, state, { ...params, template });
  const current = compileExactStateV7Root({ config, template, state, contractVersion: abi.version });
  const next = compileExactStateV7Root({ config, template, state: plan.successor, contractVersion: abi.version });

  /* the root never loses value here — the fuel pays the fee — but the
   * covenant's allowance is asserted anyway so a build can never exceed it */
  const valueRule = assertRootValueRuleV7({ inputValue: predecessorValue, successorValue: predecessorValue, rootMaxFeePerTx: template.rootMaxFeePerTx });

  const budget = selectRootComputeBudgetV7({ actionName: action, activeOwnerSlots: state.activeCount });
  const encoderPaths = { sourcePath: path.join(current.buildDir, "PolicyVault.state.sil"), constructorArgsPath: path.join(current.buildDir, "constructor-args.json") };
  const successorJson = rootSuccessorCallJsonV7(plan.successor);
  const placeholderCall =
    action === "succession"
      ? { function: "rootSuccession", successor: successorJson, successorSig: PLACEHOLDER_SIG_HEX }
      : { function: "rootAction", successor: successorJson, action: plan.action, ownerSigs: placeholderOwnerSigsBlobV7() };
  const callHex = runEncoderV4({ ...encoderPaths, call: placeholderCall, contractVersion: abi.version });
  const covenantSigscriptLen = covenantSigscript(callHex, current.scriptBytes).length / 2;

  const inputs = [
    { previousOutpoint: predecessorOutpoint, sequence: plan.minSequence, computeBudget: budget, utxo: { amount: predecessorValue, scriptPublicKey: { version: 0, scriptHex: p2shOf(config, current.scriptBytes) }, covenantId, blockDaaScore: 0n } },
    { previousOutpoint: fuel.outpoint, sequence: 0n, computeBudget: V7_BUDGET.ORDINARY_INPUT, utxo: { amount: fuel.amount, scriptPublicKey: { version: 0, scriptHex: fuel.scriptPublicKeyHex }, covenantId: null, blockDaaScore: 0n } }
  ];
  const outputs = [
    { value: predecessorValue, scriptPublicKey: { version: 0, scriptHex: p2shOf(config, next.scriptBytes) }, covenant: { authorizingInput: 0, covenantId } },
    { value: 1n, scriptPublicKey: { version: 0, scriptHex: p2pkScriptHex(change) }, covenant: null }
  ];
  const draft = { version: 1, inputs, outputs, lockTime: 0n, subnetworkId: "00".repeat(20), gas: 0n, payload: "" };
  const fee = exactFee(draft, [covenantSigscriptLen, ORDINARY_SIGSCRIPT_LEN]);
  const changeValue = fuel.amount - fee;
  if (changeValue <= 0n) fail(`fuel ${fuel.amount} cannot cover fee ${fee}`, "INSUFFICIENT_FUEL");
  outputs[1] = { ...outputs[1], value: changeValue };

  const frozen = normalizeFrozenTxV3({ ...draft, outputs });
  assertStorageMassWithinLimit(frozen, "policyvault-0.7 builder");
  const described = describeFrozenTx(frozen);
  const totalIn = frozen.inputs.reduce((s, i) => s + i.utxo.amount, 0n);
  const totalOut = frozen.outputs.reduce((s, o) => s + o.value, 0n);
  if (totalIn - totalOut !== fee) fail("internal: realized fee != required fee");

  return deepFreeze({
    kind: "orgRootTransition",
    contractVersion: abi.version,
    encoderFunction: placeholderCall.function,
    networkId: config.networkId,
    action,
    rootAction: plan.action,
    authorityClass: plan.class,
    classForPreviousSet: plan.classForPreviousSet,
    quorumSource: plan.quorumSource,
    requiredApprovals: plan.requiredApprovals.toString(),
    expectedSignerSlots: plan.expectedSignerSlots,
    minSequence: plan.minSequence.toString(),
    role: action === "succession" ? "successor" : "owners",
    template: rootTemplateToJsonV7(template),
    covenantId,
    predecessorOutpoint,
    predecessorStateId: current.stateId,
    predecessorStateDigest: plan.prevStateDigest,
    stateJson: rootStateToJsonV7(state),
    successorState: rootStateToJsonV7(plan.successor),
    successorStateId: next.stateId,
    successorStateDigest: plan.newStateDigest,
    successorStateRegionHex: serializeRootStateHexV7(plan.successor),
    successorTailHex: plan.tailHex,
    successorScriptSha256: next.scriptSha256,
    ownerSet: Object.freeze({ activeCount: state.activeCount, ownerM: state.ownerM.toString(), emergencyK: state.emergencyK.toString(), recoveryM: state.recoveryM.toString(), slots: activeOwnerSlotsV7(state) }),
    accounting: Object.freeze({
      kas: Object.freeze({
        rootValueBefore: valueRule.inputValue.toString(),
        rootValueAfter: valueRule.successorValue.toString(),
        rootMaxFeePerTx: valueRule.rootMaxFeePerTx.toString(),
        rootValueLoss: valueRule.maxLoss.toString(),
        externalIn: fuel.amount.toString(),
        externalOut: changeValue.toString(),
        fee: fee.toString()
      })
    }),
    frozen,
    frozenCanonicalJson: canonicalFrozenTxJson(frozen),
    txId: described.txId,
    rootSighash: described.sighashAll[0],
    computeBudget: budget,
    requiredFeeSompi: fee.toString(),
    encoderBuildDir: current.buildDir,
    plannedCallHexLength: callHex.length,
    hasFuelInput: true
  });
}

/*
 * FINALIZE a root transition (NO broadcasting): the M-of-N owner signatures
 * are placed into the 780-byte blob (or the successor's single signature for
 * a succession), the real covenant call bytes are produced by the production
 * encoder, and the call length is asserted identical to the frozen plan.
 */
function finalizeV7RootTransaction({ build, approvals, successorSignatureHex, fuelSignatureScriptHex }) {
  if (build.kind !== "orgRootTransition") fail("finalizeV7RootTransaction takes an orgRootTransition build");
  const call = { function: build.encoderFunction, successor: rootSuccessorCallJsonV7(build.successorState) };
  let blob = null;
  if (build.action === "succession") {
    if (approvals !== undefined && approvals !== null) fail("a succession carries the successor's own signature, never owner approvals", "SUCCESSION_TAKES_NO_APPROVALS");
    call.successorSig = normalizeSlotSignatureHex(successorSignatureHex, "successorSignatureHex");
  } else {
    if (successorSignatureHex !== undefined) fail("only a succession carries a successor signature", "UNEXPECTED_SUCCESSOR_SIGNATURE");
    blob = assembleOwnerSigsBlobV7({
      ownerSet: { owners: build.ownerSet.slots.map((s) => s.publicKey).concat(new Array(OWNER_SLOTS_V7 - build.ownerSet.slots.length).fill("00".repeat(32))), ownerM: build.ownerSet.ownerM, emergencyK: build.ownerSet.emergencyK, recoveryM: build.ownerSet.recoveryM },
      actionName: build.action,
      approvals: approvals ?? []
    });
    if (blob.blobHex.length !== SIG_BLOB_LEN_V7 * 2) fail("internal: the assembled owner blob is not 780 bytes");
    call.action = build.rootAction;
    call.ownerSigs = blob.blobHex;
  }
  const callHex = runEncoderV4({
    sourcePath: path.join(build.encoderBuildDir, "PolicyVault.state.sil"),
    constructorArgsPath: path.join(build.encoderBuildDir, "constructor-args.json"),
    call,
    contractVersion: build.contractVersion
  });
  if (callHex.length !== build.plannedCallHexLength) {
    fail(`final covenant call length ${callHex.length / 2} != planned ${build.plannedCallHexLength / 2} — the exact-fee freeze is violated; refusing`, "FEE_DRIFT");
  }
  const artifact = JSON.parse(fs.readFileSync(path.join(build.encoderBuildDir, "artifact.json")));
  const json = JSON.parse(build.frozenCanonicalJson);
  json.inputs[0].signatureScript = covenantSigscript(callHex, Buffer.from(artifact.script));
  if (typeof fuelSignatureScriptHex !== "string" || !/^[0-9a-f]+$/.test(fuelSignatureScriptHex) || fuelSignatureScriptHex.length / 2 !== ORDINARY_SIGSCRIPT_LEN) {
    fail(`fuel signature script must be exactly ${ORDINARY_SIGSCRIPT_LEN} bytes`);
  }
  json.inputs[1].signatureScript = fuelSignatureScriptHex;
  return Object.freeze({
    txId: build.txId,
    requiredFeeSompi: build.requiredFeeSompi,
    finalTransaction: json,
    covenantCallHex: callHex,
    ownerSigsBlobHex: blob ? blob.blobHex : null,
    signedSlots: blob ? blob.signedSlots : Object.freeze([]),
    requiredApprovals: blob ? blob.requiredApprovals.toString() : "1",
    satisfiedApprovals: blob ? blob.satisfiedApprovals.toString() : "1"
  });
}

/* ------------------------------------------------------------------ */
/* ROOTED VAULT: shared resolution helpers                              */
/* ------------------------------------------------------------------ */

function resolveTokenPositionV7({ config, descriptor, templateIndex, position, covenantId, template }) {
  if (!position || typeof position !== "object") fail("chain.tokenPosition { outpoint, value, scriptPublicKeyHex, covenantId, state } is required", "TOKEN_POSITION_REQUIRED");
  const familyId = normalizeHex(position.covenantId, 32, "chain.tokenPosition.covenantId");
  if (familyId !== template.tokenCovenantId) fail("chain.tokenPosition.covenantId is not the vault's pinned tokenCovenantId — wrong asset family; failing closed", "WRONG_TOKEN_FAMILY");
  const validated = assets.validateAssetDescriptor(descriptor);
  if (validated.tokenCovenantId !== template.tokenCovenantId) fail("descriptor.tokenCovenantId != the vault's pinned tokenCovenantId — descriptor substitution; failing closed", "DESCRIPTOR_MISMATCH");
  const tpl = validated.acceptedTransferTemplates[templateIndex];
  if (!tpl || tpl.templateVmHashBlake2b256 !== template.templateVmHash || tpl.prefixLen !== template.templatePrefixLen || tpl.suffixLen !== template.templateSuffixLen) {
    fail("the selected descriptor template does not equal the vault's pinned template hash/geometry — failing closed", "TEMPLATE_PIN_MISMATCH");
  }
  const program = verifiedTokenPosition({ config, descriptor: validated, templateIndex, state: position.state, scriptPublicKeyHex: position.scriptPublicKeyHex });
  if (program.state.ownerIdentifier !== covenantId || program.state.identifierType !== assets.kcc20.OWNER_SCHEMES.COVENANT_ID) {
    fail("the token position is not owned by this vault's covenant id (covenant-id/v1 scheme) — failing closed", "TOKEN_NOT_OWNED");
  }
  if (program.state.isMinter) fail("the vault's token position must not be a minter position", "TOKEN_MINTER_POSITION");
  return {
    outpoint: normalizeOutpoint(position.outpoint, "chain.tokenPosition.outpoint"),
    value: parsePositiveSompi(position.value, "chain.tokenPosition.value"),
    scriptPublicKeyHex: String(position.scriptPublicKeyHex).toLowerCase(),
    covenantId: familyId,
    program,
    descriptor: validated,
    descriptorHash: assets.computeDescriptorHash(validated),
    templateIndex
  };
}

function resolveAgentProofV7(state, params) {
  const agentPk = normalizeXOnlyPubkey(params.agentPk, "params.agentPk");
  if (params.agents !== undefined) {
    const tree = buildTokenAgentTreeV5(params.agents);
    if (tree.root !== state.agentRoot) fail("the supplied agent set does not reproduce the live agentRoot — refusing to build", "AGENT_ROOT_MISMATCH");
    const proof = generateTokenAgentProofV5(tree, agentPk);
    return { policy: proof.policy, proof };
  }
  if (params.agentPolicy !== undefined && params.agentProof !== undefined) {
    const proof = {
      agentPk,
      root: normalizeHex(params.agentProof.root ?? state.agentRoot, 32, "agentProof.root"),
      siblingsHex: String(params.agentProof.siblingsHex ?? "").toLowerCase(),
      pathBits: parseSompi(params.agentProof.pathBits ?? 0n, "agentProof.pathBits")
    };
    if (proof.root !== state.agentRoot) fail("agent proof root does not match the live agentRoot", "AGENT_ROOT_MISMATCH");
    if (!verifyTokenAgentProofV5({ root: state.agentRoot, policy: params.agentPolicy, siblingsHex: proof.siblingsHex, pathBits: proof.pathBits })) {
      fail("agent proof does not verify for this policy under the live agentRoot", "AGENT_PROOF_INVALID");
    }
    return { policy: params.agentPolicy, proof };
  }
  return fail("tokenAgentSpend requires either params.agents (full set) or params.agentPolicy + params.agentProof");
}

function resolveRecipientProofV7(agentRecipientRoot, params) {
  const recipient = normalizeHex(params.recipient, 32, "params.recipient");
  let proof;
  if (params.recipients !== undefined) {
    const tree = buildRecipientTree(params.recipients);
    if (tree.root !== agentRecipientRoot) fail("the supplied recipient list does not reproduce this agent's agentRecipientRoot — refusing to build", "RECIPIENT_ROOT_MISMATCH");
    proof = generateRecipientProof(tree, recipient);
  } else if (params.recipientProof !== undefined) {
    proof = {
      recipient,
      root: normalizeHex(params.recipientProof.root, 32, "recipientProof.root"),
      siblingsHex: String(params.recipientProof.siblingsHex ?? "").toLowerCase(),
      pathBits: parseSompi(params.recipientProof.pathBits ?? 0n, "recipientProof.pathBits")
    };
  } else {
    fail("tokenAgentSpend requires either params.recipients (full list) or params.recipientProof");
  }
  if (proof.root !== agentRecipientRoot) fail("recipient proof root does not match this agent's agentRecipientRoot", "RECIPIENT_ROOT_MISMATCH");
  if (!verifyRecipientProof({ root: proof.root, recipient, siblingsHex: proof.siblingsHex, pathBits: BigInt(proof.pathBits) })) {
    fail("recipient proof does not verify for this recipient", "RECIPIENT_PROOF_INVALID");
  }
  return { recipient, proof };
}

/*
 * The ROOT SIDE of a rooted-vault owner operation: the exact root path the
 * vault's covenant will pin, planned and compiled from the live root state.
 * A caller can never choose the root path independently of the vault
 * operation — that pairing IS the authority model.
 */
function resolveRootSide({ config, action, root }) {
  const authority = resolveOwnerOpAuthorityV7(action);
  if (!root || typeof root !== "object") fail("chain.root { template, state, outpoint, covenantId, value } is required — a rooted vault's owner authority IS the root input", "ROOT_INPUT_REQUIRED");
  const template = normalizeRootTemplateV7(root.template);
  const state = normalizeRootStateV7(root.state);
  const outpoint = normalizeOutpoint(root.outpoint, "chain.root.outpoint");
  const covenantId = normalizeHex(root.covenantId, 32, "chain.root.covenantId");
  const value = parsePositiveSompi(root.value, "chain.root.value");
  const plan = rootTransitionV7(authority.rootActionName, state, { template });
  if (plan.successor.frozen !== authority.expectFrozenAfter) fail("internal: the planned root successor does not carry the frozen byte this vault operation pins");
  const current = compileExactStateV7Root({ config, template, state });
  const next = compileExactStateV7Root({ config, template, state: plan.successor });
  assertRootValueRuleV7({ inputValue: value, successorValue: value, rootMaxFeePerTx: template.rootMaxFeePerTx });
  return {
    authority,
    template,
    state,
    plan,
    outpoint,
    covenantId,
    value,
    current,
    next,
    budget: selectRootComputeBudgetV7({ actionName: authority.rootActionName, activeOwnerSlots: state.activeCount })
  };
}

/* ------------------------------------------------------------------ */
/* ROOTED VAULT: genesis                                                */
/* ------------------------------------------------------------------ */

function buildCreateV7Vault({ config, templateInput, initialStateInput, funding, changeXOnly, contractVersion, descriptor }) {
  const abi = resolveV7Abi(contractVersion ?? CONTRACT_VERSION_V7);
  const template = normalizeTemplateV7(templateInput);
  const state = normalizeStateV7(initialStateInput);
  if (state.policyNonce !== 0n) fail("a v0.7 genesis state must carry policyNonce 0");
  if (state.paused !== 0n) fail("a v0.7 genesis state must start unpaused");
  if (descriptor !== undefined && assets.computeDescriptorHash(descriptor) !== template.descriptorHash) fail("descriptor hash != template.descriptorHash — failing closed", "DESCRIPTOR_PIN_MISMATCH");
  if (!Array.isArray(funding) || funding.length === 0) fail("funding must be a non-empty array of ordinary UTXOs ({ outpoint, amount, scriptPublicKeyHex })");
  const fundingInputs = funding.map((f, i) => {
    const spk = String(f.scriptPublicKeyHex ?? "").toLowerCase();
    if (!/^[0-9a-f]+$/.test(spk) || spk.length % 2 !== 0) fail(`funding[${i}].scriptPublicKeyHex must be hex`);
    return { outpoint: normalizeOutpoint(f.outpoint, `funding[${i}].outpoint`), amount: parsePositiveSompi(f.amount, `funding[${i}].amount`), scriptPublicKeyHex: spk };
  });
  const change = normalizeHex(changeXOnly, 32, "changeXOnly");
  const compiled = compileExactStateV7({ config, template, state, contractVersion: abi.version });
  const stateId = computeStateIdV7({ networkId: config.networkId, template, state, contractVersion: abi.version });
  const { loadKaspa } = require("./chain");
  const kaspa = loadKaspa(config);
  const spkHex = p2shOf(config, compiled.scriptBytes);
  const outputs = [
    { value: state.feeReserve, scriptPublicKey: { version: 0, scriptHex: spkHex }, covenant: null },
    { value: 1n, scriptPublicKey: { version: 0, scriptHex: p2pkScriptHex(change) }, covenant: null }
  ];
  const unbound = new kaspa.TransactionOutput(state.feeReserve, kaspa.payToScriptHashScript(compiled.scriptBytes.toString("hex")));
  const genesisCovenantId = kaspa
    .covenantId({ transactionId: fundingInputs[0].outpoint.transactionId, index: fundingInputs[0].outpoint.index }, [{ index: 0, output: unbound }])
    .toString()
    .toLowerCase();
  outputs[0] = { ...outputs[0], covenant: { authorizingInput: 0, covenantId: genesisCovenantId } };
  const inputs = fundingInputs.map((f) => ({ previousOutpoint: f.outpoint, sequence: 0n, computeBudget: V7_BUDGET.ORDINARY_INPUT, utxo: { amount: f.amount, scriptPublicKey: { version: 0, scriptHex: f.scriptPublicKeyHex }, covenantId: null, blockDaaScore: 0n } }));
  const draft = { version: 1, inputs, outputs, lockTime: 0n, subnetworkId: "00".repeat(20), gas: 0n, payload: "" };
  const requiredFee = exactFee(draft, inputs.map(() => ORDINARY_SIGSCRIPT_LEN));
  const totalFunding = fundingInputs.reduce((s, f) => s + f.amount, 0n);
  const changeValue = totalFunding - state.feeReserve - requiredFee;
  if (changeValue <= 0n) fail(`funding ${totalFunding} cannot cover the fee reserve ${state.feeReserve} + fee ${requiredFee}`, "INSUFFICIENT_FUEL");
  outputs[1] = { ...outputs[1], value: changeValue };
  const frozen = normalizeFrozenTxV3({ ...draft, outputs });
  assertStorageMassWithinLimit(frozen, "policyvault-0.7 builder");
  const described = describeFrozenTx(frozen);
  return deepFreeze({
    kind: "genesis",
    contractVersion: abi.version,
    networkId: config.networkId,
    action: "createRootedVault",
    template,
    initialState: stateToJsonV7(state),
    stateId,
    vaultOutputIndex: 0,
    changeIndex: 1,
    covenantId: genesisCovenantId,
    orgRootCovenantId: template.orgRootCovenantId,
    scriptSha256: compiled.scriptSha256,
    vaultScriptHex: compiled.scriptHex,
    accounting: Object.freeze({ kas: Object.freeze({ feeReserve: state.feeReserve.toString() }), token: Object.freeze({ positionBefore: "0", positionAfter: "0" }) }),
    frozen,
    frozenCanonicalJson: canonicalFrozenTxJson(frozen),
    txId: described.txId,
    requiredFeeSompi: requiredFee.toString(),
    encoderBuildDir: compiled.buildDir
  });
}

/* ------------------------------------------------------------------ */
/* ROOTED VAULT: one transition                                         */
/* ------------------------------------------------------------------ */

function buildV7Transaction({ config, contractVersion, templateInput, stateInput, action, params = {}, chain, changeXOnly, descriptor, templateIndex = 0 }) {
  const abi = resolveV7Abi(contractVersion ?? CONTRACT_VERSION_V7);
  if (!OWNER_CONTROL_ACTIONS_V7.has(action) && !SPEND_ACTIONS_V7.has(action) && action !== "ownerRecover") fail(`unknown v0.7 action ${JSON.stringify(action)} — failing closed`, "UNKNOWN_ACTION");
  const template = normalizeTemplateV7(templateInput);
  const state = action === "ownerRecover" && params.allowMalformedState === true ? normalizeStateV7ForRecovery(stateInput) : normalizeStateV7(stateInput);

  const predecessorOutpoint = normalizeOutpoint(chain?.predecessorOutpoint, "chain.predecessorOutpoint");
  const covenantId = normalizeHex(chain?.covenantId, 32, "chain.covenantId");
  const predecessorValue = parseSompi(chain?.predecessorValue, "chain.predecessorValue");
  if (predecessorValue !== state.feeReserve) fail(`chain.predecessorValue ${predecessorValue} != state.feeReserve ${state.feeReserve} — stale or inconsistent state`, "STALE");
  const change = normalizeHex(changeXOnly, 32, "changeXOnly");
  const isSpend = SPEND_ACTIONS_V7.has(action);
  const terminal = action === "ownerRecover";
  const hasFuel = chain?.fuel !== undefined && chain?.fuel !== null;
  if (!isSpend && !hasFuel) fail("owner operations pin every covenant value, so the network fee MUST come from an ordinary fuel UTXO — provide chain.fuel", "FUEL_REQUIRED");
  const fuel = hasFuel ? normalizeFuel(chain.fuel) : null;

  if (descriptor !== undefined) {
    const dh = assets.computeDescriptorHash(descriptor);
    if (dh !== template.descriptorHash) fail("descriptor hash != the vault's pinned descriptorHash — descriptor substitution/downgrade; failing closed", "DESCRIPTOR_PIN_MISMATCH");
  }

  const current = compileExactStateV7({ config, template, state, contractVersion: abi.version });
  const currentSpkHex = p2shOf(config, current.scriptBytes);
  const encoderPaths = { sourcePath: path.join(current.buildDir, "PolicyVault.state.sil"), constructorArgsPath: path.join(current.buildDir, "constructor-args.json") };
  const vaultIn = (budget) => ({ previousOutpoint: predecessorOutpoint, sequence: 0n, computeBudget: budget, utxo: { amount: predecessorValue, scriptPublicKey: { version: 0, scriptHex: currentSpkHex }, covenantId, blockDaaScore: 0n } });
  const fuelIn = () => ({ previousOutpoint: fuel.outpoint, sequence: 0n, computeBudget: V7_BUDGET.ORDINARY_INPUT, utxo: { amount: fuel.amount, scriptPublicKey: { version: 0, scriptHex: fuel.scriptPublicKeyHex }, covenantId: null, blockDaaScore: 0n } });
  const geometry = { templatePrefixLen: template.templatePrefixLen, templateSuffixLen: template.templateSuffixLen, rootPrefixLen: template.rootPrefixLen, rootSuffixLen: template.rootSuffixLen };

  /* ---------------- DELEGATE SPEND (no root input at all) ---------------- */
  if (isSpend) {
    if (descriptor === undefined) fail("tokenAgentSpend requires the accepted asset descriptor", "DESCRIPTOR_REQUIRED");
    if (chain?.root !== undefined && chain?.root !== null) fail("a delegate spend never touches the organizational root — refusing to build a root input into an agent transaction", "AGENT_PATH_TAKES_NO_ROOT");
    const position = resolveTokenPositionV7({ config, descriptor, templateIndex, position: chain?.tokenPosition, covenantId, template });
    const { policy, proof } = resolveAgentProofV7(state, params);
    const { recipient, proof: rProof } = resolveRecipientProofV7(normalizeHex(policy.agentRecipientRoot, 32, "agentPolicy.agentRecipientRoot"), params);
    const periods = parseSompi(params.periodsElapsed ?? 0n, "periodsElapsed");
    const recipientCarry = parseSompi(params.recipientCarryKasSompi, "recipientCarryKasSompi");
    if (recipientCarry >= position.value) fail("recipient carry KAS must leave the token position with KAS", "CARRY_TOO_LARGE");
    const selfCarry = position.value - recipientCarry;
    if (!hasFuel && params.reserveConsumedSompi !== undefined) fail("without chain.fuel the reserve consumption IS the exact network fee and is derived by the builder — do not supply reserveConsumedSompi");
    const requestedConsumed = hasFuel ? parseSompi(params.reserveConsumedSompi ?? 0n, "reserveConsumedSompi") : null;
    const budget = selectComputeBudgetV7({ operation: action, ...geometry });

    const shapeFor = (consumed) => {
      const spend = tokenAgentSpendSuccessorV7(state, {
        agentPolicy: policy,
        agentProof: { siblingsHex: proof.siblingsHex, pathBits: proof.pathBits },
        spendAmount: params.spendAmount,
        tokenPositionAmount: position.program.state.amount,
        periodsElapsed: periods,
        reserveConsumed: consumed,
        tokenInputKas: position.value,
        selfCarryKas: selfCarry,
        recipientCarryKas: recipientCarry
      });
      const states = tokenContinuationStatesV7({ controllerCovenantId: covenantId, recipientPk: recipient, plan: spend });
      const next = compileExactStateV7({ config, template, state: spend.successor, contractVersion: abi.version });
      const selfProgram = compileKcc20Program({ config, state: states.selfNew, familyBound: position.program.familyBound });
      const recipientProgram = compileKcc20Program({ config, state: states.recipientNew, familyBound: position.program.familyBound });
      const spendCallExtra = {
        selfNew: kcc20StateJson(states.selfNew),
        recipientNew: kcc20StateJson(states.recipientNew),
        agentPk: spend.previousPolicy.agentPk,
        tokenMaxPerSpend: spend.previousPolicy.tokenMaxPerSpend.toString(),
        tokenPeriodBudget: spend.previousPolicy.tokenPeriodBudget.toString(),
        periodLengthDaa: spend.previousPolicy.periodLengthDaa.toString(),
        periodStartDaa: spend.previousPolicy.periodStartDaa.toString(),
        tokenPeriodSpent: spend.previousPolicy.tokenPeriodSpent.toString(),
        agentMaxFeePerTx: spend.previousPolicy.agentMaxFeePerTx.toString(),
        agentMaxCarryKas: spend.previousPolicy.agentMaxCarryKas.toString(),
        agentRecipientRoot: spend.previousPolicy.agentRecipientRoot,
        policySiblings: proof.siblingsHex,
        policyPathBits: BigInt(proof.pathBits).toString(),
        periodsElapsed: periods.toString(),
        recipientPk: recipient,
        recipientSiblings: rProof.siblingsHex,
        recipientPathBits: BigInt(rProof.pathBits).toString()
      };
      const placeholderCall = { function: action, signature: PLACEHOLDER_SIG_HEX, successor: successorCallJsonV7(stateToJsonV7(spend.successor)), ...spendCallExtra };
      const callHex = runEncoderV4({ ...encoderPaths, call: placeholderCall, contractVersion: abi.version });
      const covenantSigscriptLen = covenantSigscript(callHex, current.scriptBytes).length / 2;
      const tokenCallHex = encodeTokenTransfer({ program: position.program, newStates: [states.selfNew, states.recipientNew], witnessesHex: "00" });
      const tokenSigscriptHex = covenantSigscript(tokenCallHex, Buffer.from(position.program.scriptHex, "hex"));
      const inputs = [
        vaultIn(budget),
        { previousOutpoint: position.outpoint, sequence: 0n, computeBudget: selectTokenInputBudgetV7({ templatePrefixLen: template.templatePrefixLen, templateSuffixLen: template.templateSuffixLen }), utxo: { amount: position.value, scriptPublicKey: { version: 0, scriptHex: position.scriptPublicKeyHex }, covenantId: position.covenantId, blockDaaScore: 0n } }
      ];
      const sigLens = [covenantSigscriptLen, tokenSigscriptHex.length / 2];
      if (fuel) {
        inputs.push(fuelIn());
        sigLens.push(ORDINARY_SIGSCRIPT_LEN);
      }
      const outputs = [
        { value: spend.successor.feeReserve, scriptPublicKey: { version: 0, scriptHex: p2shOf(config, next.scriptBytes) }, covenant: { authorizingInput: 0, covenantId } },
        { value: selfCarry, scriptPublicKey: { version: 0, scriptHex: selfProgram.p2shSpkHex }, covenant: { authorizingInput: 1, covenantId: position.covenantId } },
        { value: recipientCarry, scriptPublicKey: { version: 0, scriptHex: recipientProgram.p2shSpkHex }, covenant: { authorizingInput: 1, covenantId: position.covenantId } }
      ];
      if (fuel) outputs.push({ value: 1n, scriptPublicKey: { version: 0, scriptHex: p2pkScriptHex(change) }, covenant: null });
      const draft = { version: 1, inputs, outputs, lockTime: spend.lockTime, subnetworkId: "00".repeat(20), gas: 0n, payload: "" };
      return { spend, states, next, draft, fee: exactFee(draft, sigLens), budget, callHex, covenantSigscriptLen, tokenSigscriptHex, spendCallExtra, recipient, rProof, sigLens };
    };

    let shape;
    if (fuel) {
      shape = shapeFor(requestedConsumed);
      if (requestedConsumed > shape.fee) fail(`reserveConsumed ${requestedConsumed} exceeds the exact network fee ${shape.fee} — the covenant requires reserveConsumed <= fee`, "RESERVE_OVER_FEE");
      const changeValue = fuel.amount - (shape.fee - requestedConsumed);
      if (changeValue <= 0n) fail(`fuel ${fuel.amount} cannot cover fee ${shape.fee} minus reserveConsumed ${requestedConsumed}`, "INSUFFICIENT_FUEL");
      shape.draft.outputs[3] = { ...shape.draft.outputs[3], value: changeValue };
    } else {
      let consumed = 0n;
      let iterations = 0;
      for (;;) {
        shape = shapeFor(consumed);
        if (shape.fee === consumed) break;
        consumed = shape.fee;
        iterations += 1;
        if (iterations > 4) fail("reserve-funded fee fixed point did not converge — failing closed", "FEE_FIXPOINT");
      }
    }
    return finishBuild({
      config,
      abi,
      action,
      role: "agent",
      encoderFunction: "tokenAgentSpend",
      template,
      state,
      covenantId,
      predecessorOutpoint,
      current,
      plan: { successor: shape.spend.successor, next: shape.next, terminal: false, budget: shape.budget, covenantSigscriptLen: shape.covenantSigscriptLen, plannedCallHexLength: shape.callHex.length, externalFunding: 0n },
      draft: shape.draft,
      fee: shape.fee,
      callExtra: shape.spendCallExtra,
      rootSide: null,
      tokenSide: { position, states: shape.states, tokenSigscriptHex: shape.tokenSigscriptHex, recipient: shape.recipient, recipientProof: shape.rProof, recipientCarry, selfCarry },
      spend: shape.spend,
      fuel,
      templateIndex
    });
  }

  /* ---------------- OWNER OPERATIONS (root input required) ---------------- */
  const rootSide = resolveRootSide({ config, action, root: chain?.root });
  const budget = selectComputeBudgetV7({ operation: action, ...geometry });
  const rootInput = (idx) => ({ previousOutpoint: rootSide.outpoint, sequence: 0n, computeBudget: rootSide.budget, utxo: { amount: rootSide.value, scriptPublicKey: { version: 0, scriptHex: p2shOf(config, rootSide.current.scriptBytes) }, covenantId: rootSide.covenantId, blockDaaScore: 0n }, __rootIndex: idx });
  const rootOutput = (authorizingInput) => ({ value: rootSide.value, scriptPublicKey: { version: 0, scriptHex: p2shOf(config, rootSide.next.scriptBytes) }, covenant: { authorizingInput, covenantId: rootSide.covenantId } });

  if (!terminal) {
    /* rc26 round-7 review R7-02: ownerSetAgentRoot is built from the FULL new delegate policy set — the owners approve the
     * RULES, never a bare root. The root the covenant installs is DERIVED here (core/model/agent-merkle-v5, the same fold
     * the verifier re-runs); a supplied `newAgentRoot` must equal that fold or the build refuses. The normalized set
     * travels on the build (`agentSet`) into the manifest, the explanation and the durable registry. */
    let agentSet = null;
    if (action === "ownerSetAgentRoot") {
      if (!Array.isArray(params.agents)) fail("ownerSetAgentRoot requires params.agents — the FULL new delegate policy set (never a bare root)", "AGENT_SET_REQUIRED");
      /* Codex checkpoint 11 (R7-02, recipients): every policy MUST come with its complete recipient set — the owners
       * approve DESTINATIONS, not an opaque allowlist root. `agentRecipientRoot` is DERIVED from the recipients here
       * (a supplied one must agree); the recipients travel with the policy into the manifest. */
      const entries = params.agents.map((a, i) => {
        if (!a || typeof a !== "object") fail(`agents[${i}] must be an object`, "AGENT_SET_INVALID");
        const { recipients, ...policy } = a;
        if (!Array.isArray(recipients) || recipients.length === 0) fail(`agents[${i}].recipients must be a non-empty array of x-only recipient keys — a policy without visible recipients cannot be reviewed`, "AGENT_RECIPIENTS_REQUIRED");
        const recipientKeys = recipients.map((r, j) => normalizeHex(r, 32, `agents[${i}].recipients[${j}]`));
        const recipientRoot = buildRecipientTree(recipientKeys).root;
        if (policy.agentRecipientRoot !== undefined && normalizeHex(policy.agentRecipientRoot, 32, `agents[${i}].agentRecipientRoot`) !== recipientRoot) fail(`agents[${i}].agentRecipientRoot does not match its recipient set`, "AGENT_RECIPIENTS_MISMATCH");
        return { policy: { ...policy, agentRecipientRoot: recipientRoot }, recipients: recipientKeys };
      });
      const tree = buildTokenAgentTreeV5(entries.map((e) => e.policy));
      if (params.newAgentRoot !== undefined && normalizeHex(params.newAgentRoot, 32, "params.newAgentRoot") !== tree.root) fail(`params.newAgentRoot is not the Merkle root of params.agents (${tree.root})`, "AGENT_ROOT_MISMATCH");
      params = { ...params, agents: entries.map((e) => e.policy), newAgentRoot: tree.root };
      const recipientsByAgent = new Map(entries.map((e) => [normalizeHex(e.policy.agentPk, 32, "agentPk"), e.recipients]));
      agentSet = tree.agents.map((a) => ({ ...Object.fromEntries(Object.entries(a).map(([k, v]) => [k, typeof v === "bigint" ? v.toString() : v])), recipients: [...recipientsByAgent.get(a.agentPk)] }));
    }
    const owner = ownerOpSuccessorV7(action, state, params);
    const next = compileExactStateV7({ config, template, state: owner.successor, contractVersion: abi.version });
    const placeholderCall = { function: "ownerControl", opSelector: owner.opSelector, successor: successorCallJsonV7(stateToJsonV7(owner.successor)) };
    const callHex = runEncoderV4({ ...encoderPaths, call: placeholderCall, contractVersion: abi.version });
    const covenantSigscriptLen = covenantSigscript(callHex, current.scriptBytes).length / 2;
    const rootCallHex = runEncoderV4({
      sourcePath: path.join(rootSide.current.buildDir, "PolicyVault.state.sil"),
      constructorArgsPath: path.join(rootSide.current.buildDir, "constructor-args.json"),
      call: { function: "rootAction", successor: rootSuccessorCallJsonV7(rootSide.plan.successor), action: rootSide.plan.action, ownerSigs: placeholderOwnerSigsBlobV7() },
      contractVersion: CONTRACT_VERSION_V7_ROOT
    });
    const rootSigscriptLen = covenantSigscript(rootCallHex, rootSide.current.scriptBytes).length / 2;
    const inputs = [vaultIn(budget), rootInput(1), fuelIn()];
    const outputs = [
      { value: owner.successor.feeReserve, scriptPublicKey: { version: 0, scriptHex: p2shOf(config, next.scriptBytes) }, covenant: { authorizingInput: 0, covenantId } },
      rootOutput(1),
      { value: 1n, scriptPublicKey: { version: 0, scriptHex: p2pkScriptHex(change) }, covenant: null }
    ];
    const draft = { version: 1, inputs, outputs, lockTime: 0n, subnetworkId: "00".repeat(20), gas: 0n, payload: "" };
    const fee = exactFee(draft, [covenantSigscriptLen, rootSigscriptLen, ORDINARY_SIGSCRIPT_LEN]);
    const changeValue = fuel.amount - fee - owner.externalFunding;
    if (changeValue <= 0n) fail(`fuel ${fuel.amount} cannot cover fee ${fee} + external funding ${owner.externalFunding}`, "INSUFFICIENT_FUEL");
    outputs[2] = { ...outputs[2], value: changeValue };
    return finishBuild({
      config,
      abi,
      action,
      role: "owners",
      encoderFunction: "ownerControl",
      template,
      state,
      covenantId,
      predecessorOutpoint,
      current,
      plan: { successor: owner.successor, next, terminal: false, budget, covenantSigscriptLen, plannedCallHexLength: callHex.length, externalFunding: owner.externalFunding },
      draft: { ...draft, outputs },
      fee,
      callExtra: { opSelector: owner.opSelector },
      agentSet,
      rootSide: { ...rootSide, plannedCallHexLength: rootCallHex.length, sigscriptLen: rootSigscriptLen, inputIndex: 1 },
      tokenSide: null,
      spend: null,
      fuel,
      templateIndex
    });
  }

  /* ---------------- ownerRecover (TERMINAL) ---------------- */
  const hasPosition = chain?.tokenPosition !== undefined && chain?.tokenPosition !== null;
  let position = null;
  let recipientProgram = null;
  let tokenSigscriptHex = null;
  let recover;
  if (hasPosition) {
    if (descriptor === undefined) fail("ownerRecover with a token position requires the accepted asset descriptor", "DESCRIPTOR_REQUIRED");
    position = resolveTokenPositionV7({ config, descriptor, templateIndex, position: chain.tokenPosition, covenantId, template });
    recover = recoverPlanV7(state, template, position.program.state.amount);
    recipientProgram = compileKcc20Program({ config, state: recover.tokenRecipient, familyBound: position.program.familyBound });
    const tokenCallHex = encodeTokenTransfer({ program: position.program, newStates: [recover.tokenRecipient], witnessesHex: "00" });
    tokenSigscriptHex = covenantSigscript(tokenCallHex, Buffer.from(position.program.scriptHex, "hex"));
  } else {
    recover = recoverPlanV7(state, template, null);
  }
  const recipientNewJson = recover.tokenRecipient ? kcc20StateJson(recover.tokenRecipient) : { ownerIdentifier: template.recoveryPk, identifierType: 0, amount: "0", isMinter: false };
  const placeholderCall = { function: "ownerRecover", recipientNew: recipientNewJson };
  const callHex = runEncoderV4({ ...encoderPaths, call: placeholderCall, contractVersion: abi.version });
  const covenantSigscriptLen = covenantSigscript(callHex, current.scriptBytes).length / 2;
  const rootCallHex = runEncoderV4({
    sourcePath: path.join(rootSide.current.buildDir, "PolicyVault.state.sil"),
    constructorArgsPath: path.join(rootSide.current.buildDir, "constructor-args.json"),
    call: { function: "rootAction", successor: rootSuccessorCallJsonV7(rootSide.plan.successor), action: rootSide.plan.action, ownerSigs: placeholderOwnerSigsBlobV7() },
    contractVersion: CONTRACT_VERSION_V7_ROOT
  });
  const rootSigscriptLen = covenantSigscript(rootCallHex, rootSide.current.scriptBytes).length / 2;

  const recoverBudget = selectComputeBudgetV7({ operation: action, ...geometry });
  const inputs = [vaultIn(recoverBudget), rootInput(1)];
  const sigLens = [covenantSigscriptLen, rootSigscriptLen];
  let tokenInputIndex = null;
  if (position) {
    tokenInputIndex = inputs.length;
    inputs.push({ previousOutpoint: position.outpoint, sequence: 0n, computeBudget: selectTokenInputBudgetV7({ templatePrefixLen: template.templatePrefixLen, templateSuffixLen: template.templateSuffixLen }), utxo: { amount: position.value, scriptPublicKey: { version: 0, scriptHex: position.scriptPublicKeyHex }, covenantId: position.covenantId, blockDaaScore: 0n } });
    sigLens.push(tokenSigscriptHex.length / 2);
  }
  inputs.push(fuelIn());
  sigLens.push(ORDINARY_SIGSCRIPT_LEN);
  /* output 0 MUST be P2PK(recoveryPk) carrying exactly the fee reserve */
  const outputs = [{ value: recover.payout, scriptPublicKey: { version: 0, scriptHex: p2pkScriptHex(recover.payoutTo) }, covenant: null }, rootOutput(1)];
  if (position) outputs.push({ value: position.value, scriptPublicKey: { version: 0, scriptHex: recipientProgram.p2shSpkHex }, covenant: { authorizingInput: tokenInputIndex, covenantId: position.covenantId } });
  outputs.push({ value: 1n, scriptPublicKey: { version: 0, scriptHex: p2pkScriptHex(change) }, covenant: null });
  const draft = { version: 1, inputs, outputs, lockTime: 0n, subnetworkId: "00".repeat(20), gas: 0n, payload: "" };
  const fee = exactFee(draft, sigLens);
  const changeValue = fuel.amount - fee;
  if (changeValue <= 0n) fail(`fuel ${fuel.amount} cannot cover fee ${fee}`, "INSUFFICIENT_FUEL");
  outputs[outputs.length - 1] = { ...outputs[outputs.length - 1], value: changeValue };
  return finishBuild({
    config,
    abi,
    action,
    role: "owners",
    encoderFunction: "ownerRecover",
    template,
    state,
    covenantId,
    predecessorOutpoint,
    current,
    plan: { successor: null, next: null, terminal: true, budget: recoverBudget, covenantSigscriptLen, plannedCallHexLength: callHex.length, externalFunding: 0n, recover },
    draft: { ...draft, outputs },
    fee,
    callExtra: { recipientNew: recipientNewJson },
    rootSide: { ...rootSide, plannedCallHexLength: rootCallHex.length, sigscriptLen: rootSigscriptLen, inputIndex: 1 },
    tokenSide: position ? { position, states: { recipientNew: recover.tokenRecipient }, tokenSigscriptHex, recipient: template.recoveryPk, recipientProof: null, recipientCarry: position.value, selfCarry: 0n } : null,
    spend: null,
    fuel,
    templateIndex
  });
}

/* Shared freeze + describe + invariant checks for every rooted-vault build. */
function finishBuild({ config, abi, action, role, encoderFunction, template, state, covenantId, predecessorOutpoint, current, plan, draft, fee, callExtra, agentSet = null, rootSide, tokenSide, spend, fuel, templateIndex }) {
  if (draft.inputs.length > MAX_TX_FEE_IO || draft.outputs.length > MAX_TX_FEE_IO) fail(`transaction shape exceeds the covenant fee-introspection bound of ${MAX_TX_FEE_IO} inputs/outputs`);
  const cleanInputs = draft.inputs.map((i) => {
    const { __rootIndex, ...rest } = i;
    void __rootIndex;
    return rest;
  });
  const frozen = normalizeFrozenTxV3({ ...draft, inputs: cleanInputs });
  assertStorageMassWithinLimit(frozen, "policyvault-0.7 builder");
  const described = describeFrozenTx(frozen);
  const totalIn = frozen.inputs.reduce((s, i) => s + i.utxo.amount, 0n);
  const totalOut = frozen.outputs.reduce((s, o) => s + o.value, 0n);
  if (totalIn - totalOut !== fee) fail("internal: realized fee != required fee");
  if (!plan.terminal) {
    const succ = frozen.outputs.filter((o) => o.covenant !== null && o.covenant.covenantId === covenantId);
    if (succ.length !== 1 || succ[0].value !== plan.successor.feeReserve) fail("internal: successor output does not carry exactly feeReserve");
  }
  if (rootSide) {
    const rootOuts = frozen.outputs.filter((o) => o.covenant !== null && o.covenant.covenantId === rootSide.covenantId);
    if (rootOuts.length !== 1) fail("internal: exactly one root continuation output is required");
    const rootIns = frozen.inputs.filter((i) => i.utxo.covenantId === rootSide.covenantId);
    if (rootIns.length !== 1) fail("internal: exactly one root input is required");
  }
  const successorStateId = plan.terminal ? null : computeStateIdV7({ networkId: config.networkId, template, state: plan.successor, contractVersion: abi.version });
  const reserveConsumed = spend ? spend.reserveConsumed : 0n;
  const externalIn = fuel ? fuel.amount : 0n;
  const externalOut = fuel ? frozen.outputs[frozen.outputs.length - 1].value : 0n;

  return deepFreeze({
    kind: "transition",
    contractVersion: abi.version,
    encoderFunction,
    networkId: config.networkId,
    action,
    role,
    template,
    predecessorOutpoint,
    predecessorStateId: current.stateId,
    covenantId,
    stateJson: stateToJsonV7(state),
    successorState: plan.terminal ? null : stateToJsonV7(plan.successor),
    successorStateId,
    successorScriptSha256: plan.terminal ? null : plan.next.scriptSha256,
    /* rc26 round-7 review R7-02: the full new delegate policy set an ownerSetAgentRoot installs (null for every other action). */
    agentSet: agentSet ? agentSet.map((policy) => ({ ...policy })) : null,
    /* Codex checkpoint 6 (UX-02 / UX-13): the PREDECESSOR redeem script (prefix || state region || suffix) travels with
     * the build so the shared core can rebuild the successor locking script around the reviewed successor state and
     * bind the successor output to it before anyone signs (core/intent/vault-script-v7.js). Bound by P2SH == the vault
     * input's locking script and by its state region == stateBefore; never trusted on its own. */
    vaultRedeemScriptHex: current.scriptHex,
    vaultStateRegionHex: current.stateRegionHex,
    rootAuthority: rootSide
      ? Object.freeze({
          covenantId: rootSide.covenantId,
          outpoint: rootSide.outpoint,
          inputIndex: rootSide.inputIndex,
          rootActionName: rootSide.authority.rootActionName,
          rootAction: rootSide.plan.action,
          authorityClass: rootSide.plan.class,
          quorumSource: rootSide.plan.quorumSource,
          requiredApprovals: rootSide.plan.requiredApprovals.toString(),
          expectedSignerSlots: rootSide.plan.expectedSignerSlots,
          expectFrozenAfter: rootSide.authority.expectFrozenAfter.toString(),
          prevStateDigest: rootSide.plan.prevStateDigest,
          newStateDigest: rootSide.plan.newStateDigest,
          successorTailHex: rootSide.plan.tailHex,
          prevState: rootStateToJsonV7(rootSide.state),
          newState: rootStateToJsonV7(rootSide.plan.successor),
          template: rootTemplateToJsonV7(rootSide.template),
          value: rootSide.value.toString(),
          computeBudget: rootSide.budget,
          plannedCallHexLength: rootSide.plannedCallHexLength,
          buildDir: rootSide.current.buildDir
        })
      : null,
    asset: tokenSide
      ? Object.freeze({
          descriptorHash: tokenSide.position.descriptorHash,
          assetId: tokenSide.position.descriptor.assetId,
          tokenCovenantId: tokenSide.position.covenantId,
          templateVmHashBlake2b256: tokenSide.position.program.templateVmHashBlake2b256,
          familyBound: tokenSide.position.program.familyBound,
          templateIndex,
          issuerPowers: tokenSide.position.descriptor.issuerPowers,
          displayName: tokenSide.position.descriptor.displayName,
          decimalsDisplay: tokenSide.position.descriptor.decimalsDisplay
        })
      : null,
    accounting: Object.freeze({
      token: Object.freeze({
        positionBefore: tokenSide ? tokenSide.position.program.state.amount.toString() : null,
        spendAmount: spend ? spend.spendAmount.toString() : "0",
        positionAfter: spend ? spend.tokenSelfAfter.toString() : plan.terminal && tokenSide ? "0" : tokenSide ? tokenSide.position.program.state.amount.toString() : null,
        recipient: tokenSide ? tokenSide.recipient : null,
        recoveredToRecoveryPk: plan.terminal && tokenSide ? tokenSide.position.program.state.amount.toString() : "0"
      }),
      kas: Object.freeze({
        predecessorFeeReserve: state.feeReserve.toString(),
        reserveConsumed: reserveConsumed.toString(),
        successorFeeReserve: plan.terminal ? "0" : plan.successor.feeReserve.toString(),
        externalIn: externalIn.toString(),
        externalOut: externalOut.toString(),
        externalFunding: plan.externalFunding.toString(),
        tokenInputKas: tokenSide ? tokenSide.position.value.toString() : "0",
        tokenSelfCarryKas: tokenSide ? tokenSide.selfCarry.toString() : "0",
        tokenRecipientCarryKas: tokenSide ? tokenSide.recipientCarry.toString() : "0",
        fee: fee.toString(),
        terminalPayout: plan.terminal ? plan.recover.payout.toString() : "0"
      })
    }),
    frozen,
    frozenCanonicalJson: canonicalFrozenTxJson(frozen),
    txId: described.txId,
    covenantSighash: described.sighashAll[0],
    rootSighash: rootSide ? described.sighashAll[rootSide.inputIndex] : null,
    computeBudget: plan.budget,
    requiredFeeSompi: fee.toString(),
    encoderBuildDir: current.buildDir,
    plannedCallHexLength: plan.plannedCallHexLength,
    callExtra,
    hasFuelInput: fuel !== null,
    hasRootInput: rootSide !== null,
    hasTokenInput: tokenSide !== null,
    tokenInputIndex: tokenSide ? frozen.inputs.findIndex((i) => i.utxo.covenantId === tokenSide.position.covenantId) : null,
    tokenSignatureScriptHex: tokenSide ? tokenSide.tokenSigscriptHex : null,
    agentProof: spend ? Object.freeze({ root: state.agentRoot, siblingsHex: spend.agentProof.siblingsHex, pathBits: BigInt(spend.agentProof.pathBits).toString() }) : null,
    recipientProof: spend ? Object.freeze({ root: tokenSide.recipientProof.root, siblingsHex: tokenSide.recipientProof.siblingsHex, pathBits: BigInt(tokenSide.recipientProof.pathBits).toString() }) : null,
    payment: spend ? { recipient: tokenSide.recipient, tokenAmount: spend.spendAmount.toString(), carryKasSompi: tokenSide.recipientCarry.toString() } : null
  });
}

function extractSchnorr65(signatureHex, label) {
  if (typeof signatureHex !== "string" || !/^[0-9a-f]+$/.test(signatureHex)) fail(`${label} must be lowercase hex`, "SIGNATURE_INVALID");
  let sig = signatureHex;
  if (sig.length === 132 && sig.startsWith("41")) sig = sig.slice(2);
  if (sig.length !== 130) fail(`${label} has unexpected length ${sig.length / 2} bytes (need 65)`, "SIGNATURE_INVALID");
  if (!sig.endsWith("01")) fail(`${label} sighash byte 0x${sig.slice(-2)} != 0x01 — PolicyVault signs SIG_HASH_ALL only`, "SIGHASH_NOT_ALL");
  return sig;
}

/*
 * FINALIZE a rooted-vault transition (NO broadcasting).
 *   agentSignatureHex   the delegate's 65-byte SIGHASH_ALL signature (spend only)
 *   approvals           the M-of-N owner approvals for the ROOT input (owner ops)
 *   fuelSignatureScriptHex  the ordinary fuel input's signature script
 *
 * The vault input itself carries NO signature: its authority is the root
 * input, which is exactly what makes an owner operation impossible without
 * the organization's quorum.
 */
function finalizeV7Transaction({ build, agentSignatureHex, approvals, fuelSignatureScriptHex }) {
  if (build.kind !== "transition" || build.contractVersion !== CONTRACT_VERSION_V7) fail("finalizeV7Transaction takes a v0.7 rooted-vault transition build");
  const isSpend = build.action === "tokenAgentSpend";
  const call = { function: build.encoderFunction, ...build.callExtra };
  if (isSpend) {
    call.signature = extractSchnorr65(agentSignatureHex, "agent signature");
    call.successor = successorCallJsonV7(build.successorState);
    if (approvals !== undefined && approvals !== null) fail("a delegate spend carries no owner approvals — the agent path never touches the root", "AGENT_PATH_TAKES_NO_APPROVALS");
  } else {
    if (agentSignatureHex !== undefined) fail("a v0.7 owner path carries NO signature — the root input is the authority", "OWNER_PATH_TAKES_NO_SIGNATURE");
    if (build.encoderFunction === "ownerControl") call.successor = successorCallJsonV7(build.successorState);
  }
  const callHex = runEncoderV4({
    sourcePath: path.join(build.encoderBuildDir, "PolicyVault.state.sil"),
    constructorArgsPath: path.join(build.encoderBuildDir, "constructor-args.json"),
    call,
    contractVersion: build.contractVersion
  });
  if (callHex.length !== build.plannedCallHexLength) fail(`final covenant call length ${callHex.length / 2} != planned ${build.plannedCallHexLength / 2} — the exact-fee freeze is violated; refusing`, "FEE_DRIFT");
  const artifact = JSON.parse(fs.readFileSync(path.join(build.encoderBuildDir, "artifact.json")));
  const json = JSON.parse(build.frozenCanonicalJson);
  json.inputs[0].signatureScript = covenantSigscript(callHex, Buffer.from(artifact.script));

  let blob = null;
  if (build.hasRootInput) {
    const ra = build.rootAuthority;
    const slots = ra.expectedSignerSlots.map((s) => s.publicKey);
    while (slots.length < OWNER_SLOTS_V7) slots.push("00".repeat(32));
    blob = assembleOwnerSigsBlobV7({
      ownerSet: { owners: slots, ownerM: ra.prevState.ownerM, emergencyK: ra.prevState.emergencyK, recoveryM: ra.prevState.recoveryM },
      actionName: ra.rootActionName,
      approvals: approvals ?? []
    });
    const rootCallHex = runEncoderV4({
      sourcePath: path.join(ra.buildDir, "PolicyVault.state.sil"),
      constructorArgsPath: path.join(ra.buildDir, "constructor-args.json"),
      call: { function: "rootAction", successor: rootSuccessorCallJsonV7(ra.newState), action: ra.rootAction, ownerSigs: blob.blobHex },
      contractVersion: CONTRACT_VERSION_V7_ROOT
    });
    if (rootCallHex.length !== ra.plannedCallHexLength) fail(`final root call length ${rootCallHex.length / 2} != planned ${ra.plannedCallHexLength / 2} — the exact-fee freeze is violated; refusing`, "FEE_DRIFT");
    const rootArtifact = JSON.parse(fs.readFileSync(path.join(ra.buildDir, "artifact.json")));
    json.inputs[ra.inputIndex].signatureScript = covenantSigscript(rootCallHex, Buffer.from(rootArtifact.script));
  } else if (approvals !== undefined && approvals !== null) {
    fail("this build has no root input — do not supply owner approvals", "NO_ROOT_INPUT");
  }

  if (build.hasTokenInput) json.inputs[build.tokenInputIndex].signatureScript = build.tokenSignatureScriptHex;
  if (build.hasFuelInput) {
    if (typeof fuelSignatureScriptHex !== "string" || !/^[0-9a-f]+$/.test(fuelSignatureScriptHex) || fuelSignatureScriptHex.length / 2 !== ORDINARY_SIGSCRIPT_LEN) {
      fail(`fuel signature script must be exactly ${ORDINARY_SIGSCRIPT_LEN} bytes`);
    }
    json.inputs[json.inputs.length - 1].signatureScript = fuelSignatureScriptHex;
  } else if (fuelSignatureScriptHex !== undefined) {
    fail("this build has no fuel input — do not supply a fuel signature");
  }
  return Object.freeze({
    txId: build.txId,
    requiredFeeSompi: build.requiredFeeSompi,
    finalTransaction: json,
    covenantCallHex: callHex,
    ownerSigsBlobHex: blob ? blob.blobHex : null,
    signedSlots: blob ? blob.signedSlots : Object.freeze([]),
    requiredApprovals: blob ? blob.requiredApprovals.toString() : null,
    satisfiedApprovals: blob ? blob.satisfiedApprovals.toString() : null
  });
}

/* ------------------------------------------------------------------ */
/* TOKEN DEPOSIT (the vault is not an input; the family leader signs)   */
/* ------------------------------------------------------------------ */

function buildTokenDepositV7({ config, descriptor, templateIndex = 0, vault, chain, params = {}, changeXOnly }) {
  if (!vault || typeof vault !== "object") fail("vault { covenantId, template } is required", "VAULT_REQUIRED");
  const vaultCovenantId = normalizeHex(vault.covenantId, 32, "vault.covenantId");
  const template = normalizeTemplateV7(vault.template);
  const validated = assets.validateAssetDescriptor(descriptor);
  const descriptorHash = assets.computeDescriptorHash(validated);
  if (descriptorHash !== template.descriptorHash) fail("descriptor hash != the vault's pinned descriptorHash — descriptor substitution/downgrade; failing closed", "DESCRIPTOR_PIN_MISMATCH");
  if (validated.tokenCovenantId !== template.tokenCovenantId) fail("descriptor.tokenCovenantId != the vault's pinned tokenCovenantId — failing closed", "DESCRIPTOR_MISMATCH");
  const tpl = validated.acceptedTransferTemplates[templateIndex];
  if (!tpl || tpl.templateVmHashBlake2b256 !== template.templateVmHash || tpl.prefixLen !== template.templatePrefixLen || tpl.suffixLen !== template.templateSuffixLen) {
    fail("the selected descriptor template does not equal the vault's pinned template hash/geometry — failing closed", "TEMPLATE_PIN_MISMATCH");
  }
  const up = chain?.userPosition;
  if (!up || typeof up !== "object") fail("chain.userPosition { outpoint, value, scriptPublicKeyHex, covenantId, state } is required", "USER_POSITION_REQUIRED");
  const familyId = normalizeHex(up.covenantId, 32, "chain.userPosition.covenantId");
  if (familyId !== template.tokenCovenantId) fail("chain.userPosition.covenantId is not the vault's pinned token family — wrong asset; failing closed", "WRONG_TOKEN_FAMILY");
  const program = verifiedTokenPosition({ config, descriptor: validated, templateIndex, state: up.state, scriptPublicKeyHex: up.scriptPublicKeyHex });
  if (program.state.identifierType !== assets.kcc20.OWNER_SCHEMES.P2PK) fail("deposits are built from a p2pk-owned (user) token position only — failing closed", "USER_POSITION_NOT_P2PK");
  if (program.state.isMinter) fail("a minter position cannot be deposited into a vault", "TOKEN_MINTER_POSITION");
  const userPk = program.state.ownerIdentifier;
  const positionOutpoint = normalizeOutpoint(up.outpoint, "chain.userPosition.outpoint");
  const positionValue = parsePositiveSompi(up.value, "chain.userPosition.value");
  const fuel = normalizeFuel(chain?.fuel);
  const change = normalizeHex(changeXOnly, 32, "changeXOnly");

  const deposit = assets.kcc20.parseAtomicAmount(params.depositAmount, "depositAmount");
  if (deposit <= 0n) fail("depositAmount must be > 0", "ZERO_DEPOSIT");
  if (deposit > program.state.amount) fail("depositAmount exceeds the user's token position — conservation would break", "INSUFFICIENT_TOKENS");
  const remainder = program.state.amount - deposit;
  const depositState = { ownerIdentifier: vaultCovenantId, identifierType: assets.kcc20.OWNER_SCHEMES.COVENANT_ID, amount: deposit, isMinter: false };
  const remainderState = remainder > 0n ? { ownerIdentifier: userPk, identifierType: assets.kcc20.OWNER_SCHEMES.P2PK, amount: remainder, isMinter: false } : null;
  const depositCarry = remainderState ? parsePositiveSompi(params.depositCarryKasSompi, "depositCarryKasSompi") : parseSompi(params.depositCarryKasSompi ?? positionValue, "depositCarryKasSompi");
  if (!remainderState && depositCarry !== positionValue) fail("a full deposit moves the position's entire KAS carry with it (depositCarryKasSompi must equal the position value)", "CARRY_MISMATCH");
  if (remainderState && depositCarry >= positionValue) fail("depositCarryKasSompi must leave KAS for the remainder output", "CARRY_TOO_LARGE");
  const remainderCarry = positionValue - depositCarry;

  const depositProgram = compileKcc20Program({ config, state: depositState, familyBound: program.familyBound });
  const remainderProgram = remainderState ? compileKcc20Program({ config, state: remainderState, familyBound: program.familyBound }) : null;
  const newStates = remainderState ? [depositState, remainderState] : [depositState];
  const tokenBudget = selectTokenInputBudgetV7({ templatePrefixLen: template.templatePrefixLen, templateSuffixLen: template.templateSuffixLen, signerOwned: true });
  const placeholderCallHex = runEncoderV4({
    sourcePath: program.sourcePath,
    constructorArgsPath: program.constructorArgsPath,
    call: { function: "transfer", signature: PLACEHOLDER_SIG_HEX, newStates: newStates.map(kcc20StateJson), sigs: [PLACEHOLDER_SIG_HEX], witnesses: "00" },
    contractVersion: "kcc20/1"
  });
  const tokenSigscriptLen = covenantSigscript(placeholderCallHex, Buffer.from(program.scriptHex, "hex")).length / 2;
  const inputs = [
    { previousOutpoint: positionOutpoint, sequence: 0n, computeBudget: tokenBudget, utxo: { amount: positionValue, scriptPublicKey: { version: 0, scriptHex: program.p2shSpkHex }, covenantId: familyId, blockDaaScore: 0n } },
    { previousOutpoint: fuel.outpoint, sequence: 0n, computeBudget: V7_BUDGET.ORDINARY_INPUT, utxo: { amount: fuel.amount, scriptPublicKey: { version: 0, scriptHex: fuel.scriptPublicKeyHex }, covenantId: null, blockDaaScore: 0n } }
  ];
  const outputs = [{ value: depositCarry, scriptPublicKey: { version: 0, scriptHex: depositProgram.p2shSpkHex }, covenant: { authorizingInput: 0, covenantId: familyId } }];
  if (remainderState) outputs.push({ value: remainderCarry, scriptPublicKey: { version: 0, scriptHex: remainderProgram.p2shSpkHex }, covenant: { authorizingInput: 0, covenantId: familyId } });
  outputs.push({ value: 1n, scriptPublicKey: { version: 0, scriptHex: p2pkScriptHex(change) }, covenant: null });
  const draft = { version: 1, inputs, outputs, lockTime: 0n, subnetworkId: "00".repeat(20), gas: 0n, payload: "" };
  const fee = exactFee(draft, [tokenSigscriptLen, ORDINARY_SIGSCRIPT_LEN]);
  const changeValue = fuel.amount - fee;
  if (changeValue <= 0n) fail(`fuel ${fuel.amount} cannot cover fee ${fee}`, "INSUFFICIENT_FUEL");
  outputs[outputs.length - 1] = { ...outputs[outputs.length - 1], value: changeValue };
  const frozen = normalizeFrozenTxV3({ ...draft, outputs });
  assertStorageMassWithinLimit(frozen, "policyvault-0.7 builder");
  const described = describeFrozenTx(frozen);
  return deepFreeze({
    kind: "tokenDeposit",
    contractVersion: CONTRACT_VERSION_V7,
    networkId: config.networkId,
    action: "tokenDeposit",
    role: "tokenOwner",
    vault: Object.freeze({ covenantId: vaultCovenantId, template }),
    asset: Object.freeze({ descriptorHash, assetId: validated.assetId, tokenCovenantId: familyId, templateVmHashBlake2b256: program.templateVmHashBlake2b256, familyBound: program.familyBound, templateIndex, issuerPowers: validated.issuerPowers, displayName: validated.displayName, decimalsDisplay: validated.decimalsDisplay }),
    userPk,
    accounting: Object.freeze({
      token: Object.freeze({ positionBefore: program.state.amount.toString(), deposit: deposit.toString(), remainderToUser: remainder.toString() }),
      kas: Object.freeze({ positionKas: positionValue.toString(), depositCarryKas: depositCarry.toString(), remainderCarryKas: remainderCarry.toString(), externalIn: fuel.amount.toString(), externalOut: changeValue.toString(), fee: fee.toString() })
    }),
    frozen,
    frozenCanonicalJson: canonicalFrozenTxJson(frozen),
    txId: described.txId,
    tokenInputSighash: described.sighashAll[0],
    requiredFeeSompi: fee.toString(),
    tokenProgram: Object.freeze({ sourcePath: program.sourcePath, constructorArgsPath: program.constructorArgsPath, scriptHex: program.scriptHex }),
    tokenNewStates: Object.freeze(newStates.map(kcc20StateJson)),
    plannedTokenCallHexLength: placeholderCallHex.length
  });
}

function finalizeTokenDepositV7({ build, tokenOwnerSignatureHex, fuelSignatureScriptHex }) {
  if (build.kind !== "tokenDeposit" || build.contractVersion !== CONTRACT_VERSION_V7) fail("finalizeTokenDepositV7 takes a v0.7 tokenDeposit build");
  const sig = extractSchnorr65(tokenOwnerSignatureHex, "token owner signature");
  const callHex = runEncoderV4({
    sourcePath: build.tokenProgram.sourcePath,
    constructorArgsPath: build.tokenProgram.constructorArgsPath,
    call: { function: "transfer", signature: sig, newStates: [...build.tokenNewStates], sigs: [sig], witnesses: "00" },
    contractVersion: "kcc20/1"
  });
  if (callHex.length !== build.plannedTokenCallHexLength) fail("final token call length != planned — exact-fee freeze violated; refusing", "FEE_DRIFT");
  const json = JSON.parse(build.frozenCanonicalJson);
  json.inputs[0].signatureScript = covenantSigscript(callHex, Buffer.from(build.tokenProgram.scriptHex, "hex"));
  if (typeof fuelSignatureScriptHex !== "string" || !/^[0-9a-f]+$/.test(fuelSignatureScriptHex) || fuelSignatureScriptHex.length / 2 !== ORDINARY_SIGSCRIPT_LEN) fail(`fuel signature script must be exactly ${ORDINARY_SIGSCRIPT_LEN} bytes`);
  json.inputs[1].signatureScript = fuelSignatureScriptHex;
  return Object.freeze({ txId: build.txId, requiredFeeSompi: build.requiredFeeSompi, finalTransaction: json, tokenCallHex: callHex });
}

module.exports = {
  buildCreateV7Root,
  buildV7RootTransaction,
  finalizeV7RootTransaction,
  buildCreateV7Vault,
  buildV7Transaction,
  finalizeV7Transaction,
  buildTokenDepositV7,
  finalizeTokenDepositV7,
  rootSuccessorCallJsonV7,
  successorCallJsonV7,
  OWNER_CONTROL_ACTIONS_V7,
  SPEND_ACTIONS_V7,
  ROOT_ACTIONS_V7_NAMES,
  resolveRootActionV7
};
