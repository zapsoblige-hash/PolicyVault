"use strict";

/*
 * PolicyVault v0.6 ATOMIC-COMPOSABILITY TOKEN CONTROLLER transaction
 * builders (SDK layer). Builds (and FREEZES) every PolicyVault.v0.6.sil
 * transition offline, entirely from consensus-visible bytes + the accepted
 * asset descriptor + the owner-approved swap policy + the venue profile's
 * protocol facts, then finalizes it with externally-produced signatures.
 * Same discipline as v0.5: builders never broadcast; the frozen form is the
 * security object; the exact fee is computed from the final byte shape; the
 * production pv_call_encoder produces every covenant-call byte; any drift
 * between planned and final bytes fails closed. Covenant generation v0.6 is
 * unrelated to application release v1.6.0.
 *
 * Dependency direction (architecture freeze): raw tx/state -> canonical
 * token parser (core/assets) -> descriptor validation -> asset adapter ->
 * venue profile (protocol facts) -> owner swap policy (authority) ->
 * policy evaluation (core/model v6, exact pool quote from revealed pool
 * state) -> this builder -> swap manifest/explain -> local verification ->
 * external signer (SIGHASH_ALL only) -> covenant enforcement -> chain
 * reconciliation.
 *
 * THREE accounting domains surfaced separately in `accounting`:
 *   token — amounts in/out, positions before/after (atomic units);
 *   kas.principal — the protected swap principal (consideration source /
 *           type-A proceeds sink);
 *   kas.reserve — fee reserve before/after, reserve consumed (= the exact
 *           network fee on a swap: swaps carry NO fuel input);
 *   kas.notes/protocolFee/proceeds — token-note carries, the venue's fee
 *           output, the type-B proceeds output.
 *
 * Transaction shapes:
 *   tokenAgentSpend   in: [controller, token position, fuel?]
 *                     out: [successor, token self, token recipient, change?]
 *   tokenAtomicSell   in: [controller, our note (family leader),
 *                          pool note (family delegate), pool]
 *                     out: [successor, our note, pool note, pool successor,
 *                          protocol fee, (type B) proceeds]
 *   tokenAtomicBuy    same shape as sell, five outputs
 *   ownerControl      in: [controller, fuel]        out: [successor, change]
 *   ownerRecover      in: [controller, token?, fuel] out: [owner payout, token->owner?, change]
 *   create (genesis)  in: [funding...]              out: [controller, change]
 *
 * FRESHNESS (owner addendum 2026-09-03 §B): a built swap binds the EXACT
 * pool outpoint and the EXACT controller outpoint; spending either (a pool
 * transition, or another valid controller transition) is a transaction-level
 * stale-swap kill switch. `deadlineDaa` is a PRE-SIGN freshness boundary:
 * the finalizer/signer path refuses after it; Kaspa lockTime gives no upper
 * bound, so an already-signed swap stays consensus-valid while both
 * outpoints remain unspent. Intended workflow: verify -> sign -> broadcast
 * immediately; never store signed swaps for later broadcast.
 *
 * Status: IMPLEMENTED (SDK). Production-byte proof: sdk/tools/gen-v6-vectors.js
 * + tests/vm/tests/v6_sdk_integration.rs execute every built shape on the
 * real engine.
 */

const fs = require("fs");
const path = require("path");

const { parseSompi, parsePositiveSompi } = require("./amounts");
const { normalizeHex, normalizeXOnlyPubkey } = require("./vault-state");
const {
  CONTRACT_VERSION_V6,
  resolveV6Abi,
  OWNER_OP_SELECTOR_V6,
  normalizeTemplateV6,
  normalizeStateV6,
  normalizeStateV6ForRecovery,
  controllerValueV6,
  computeStateIdV6,
  stateToJsonV6
} = require("./vault-state-v6");
const {
  tokenAgentSpendSuccessorV6,
  tokenAtomicSellSuccessorV6,
  tokenAtomicBuySuccessorV6,
  tokenContinuationStatesV6,
  swapContinuationStatesV6,
  setAgentRootSuccessorV6,
  topUpReserveSuccessorV6,
  pauseSuccessorV6,
  setSwapRootSuccessorV6,
  fundSwapPrincipalSuccessorV6,
  recoverPlanV6,
  SWAP_INPUT_COUNT
} = require("./vault-transitions-v6");
const { buildTokenAgentTreeV6, generateTokenAgentProofV6, verifyTokenAgentProofV6 } = require("./agent-merkle-v6");
const { buildSwapPolicyTreeV6, generateSwapPolicyProofV6, verifySwapPolicyProofV6, normalizeSwapPolicyV6, normalizeSwapVenueProfile, computeSwapVenueProfileHash, swapPolicyToJsonV6, DEST_SCHEME } = require("./swap-policy-v6");
const { buildRecipientTree, generateRecipientProof, verifyRecipientProof } = require("./recipient-merkle-v3");
const { compileExactStateV6 } = require("./contract-compiler-v6");
const { selectComputeBudgetV6, selectTokenInputBudgetV6, selectPoolInputBudgetV6, V6_BUDGET } = require("./compute-budget-v6");
const { normalizeFrozenTxV3, describeFrozenTx, feeDescriptorFromFrozen, canonicalFrozenTxJson } = require("./frozen-tx-v3");
const { calculateRequiredFee } = require("./fee-mass");
const { calcStorageMass, minimumOutputValueForLimit, cellsOfFrozenTx, STORAGE_MASS_LIMIT } = require("../../core/model/storage-mass");
const { covenantSigscript } = require("./spend-vault");
const { p2pkScriptHex } = require("./approval-package-v4");
const { runEncoderV4, PLACEHOLDER_SIG_HEX, MAX_TX_FEE_IO } = require("./vault-builders-v4");
const { encodeTokenTransfer, buildTokenDepositV5, finalizeTokenDepositV5 } = require("./vault-builders-v5");
const assets = require("../../core/assets");
const { verifiedTokenPosition, compileKcc20Program } = require("./token-program-kcc20");
const { compilePoolFixtureV6, POOL_FIXTURE_VERSION } = require("./swap-pool-fixture-v6");
const { assertStorageMassWithinLimit } = require("./storage-mass-preflight");

const ORDINARY_SIGSCRIPT_LEN = 66;
const OWNER_CONTROL_ACTIONS = new Set(["ownerSetAgentRoot", "ownerTopUpReserve", "ownerPause", "ownerUnpause", "ownerSetSwapRoot", "ownerFundSwapPrincipal"]);
const SPEND_ACTIONS = new Set(["tokenAgentSpend"]);
const SWAP_ACTIONS = new Set(["tokenAtomicSell", "tokenAtomicBuy"]);
const FRESHNESS_STATEMENT =
  "A signed swap is usable only while BOTH the exact pool outpoint and the exact controller outpoint remain unspent; spending either is a transaction-level kill switch. deadlineDaa is a pre-sign freshness boundary enforced by the core and the signer path, not a consensus expiry: after it passes, an already-signed transaction remains consensus-valid while both outpoints are unspent. Workflow: verify -> sign -> broadcast immediately.";

function fail(message, code) {
  const e = new Error(`vault-builders-v6: ${message}`);
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
function kcc20StateJson(s) {
  return { ownerIdentifier: s.ownerIdentifier, identifierType: s.identifierType, amount: s.amount.toString(), isMinter: s.isMinter };
}
function successorCallJsonV6(stateJson) {
  return { feeReserve: stateJson.feeReserve, swapPrincipal: stateJson.swapPrincipal, paused: Number(stateJson.paused), agentRoot: stateJson.agentRoot, swapRoot: stateJson.swapRoot, policyNonce: stateJson.policyNonce };
}
function exactFee(draft, sigScriptLengths) {
  const probe = normalizeFrozenTxV3(draft);
  return calculateRequiredFee(feeDescriptorFromFrozen(probe, sigScriptLengths)).minimumRequiredFee;
}

/* ---- token positions (ours / the pool's reserve note), PROVEN before use ---- */
function validateDescriptorAgainstTemplate({ descriptor, templateIndex, template }) {
  const validated = assets.validateAssetDescriptor(descriptor);
  if (validated.tokenCovenantId !== template.tokenCovenantId) fail("descriptor.tokenCovenantId != the controller's pinned tokenCovenantId — descriptor substitution; failing closed", "DESCRIPTOR_MISMATCH");
  const tpl = validated.acceptedTransferTemplates[templateIndex];
  if (!tpl || tpl.templateVmHashBlake2b256 !== template.templateVmHash || tpl.prefixLen !== template.templatePrefixLen || tpl.suffixLen !== template.templateSuffixLen) {
    fail("the selected descriptor template does not equal the controller's pinned template hash/geometry — failing closed", "TEMPLATE_PIN_MISMATCH");
  }
  return validated;
}
function resolveNote({ config, validated, templateIndex, note, template, label, expectedOwner, expectedScheme }) {
  if (!note || typeof note !== "object") fail(`${label} { outpoint, value, scriptPublicKeyHex, covenantId, state } is required`, "TOKEN_POSITION_REQUIRED");
  const familyId = normalizeHex(note.covenantId, 32, `${label}.covenantId`);
  if (familyId !== template.tokenCovenantId) fail(`${label}.covenantId is not the controller's pinned tokenCovenantId — wrong asset family; failing closed`, "WRONG_TOKEN_FAMILY");
  const program = verifiedTokenPosition({ config, descriptor: validated, templateIndex, state: note.state, scriptPublicKeyHex: note.scriptPublicKeyHex });
  if (program.state.ownerIdentifier !== expectedOwner || program.state.identifierType !== expectedScheme) fail(`${label} is not owned by the expected covenant id (covenant-id/v1 scheme) — failing closed`, "TOKEN_NOT_OWNED");
  if (program.state.isMinter) fail(`${label} must not be a minter position`, "TOKEN_MINTER_POSITION");
  return {
    outpoint: normalizeOutpoint(note.outpoint, `${label}.outpoint`),
    value: parsePositiveSompi(note.value, `${label}.value`),
    scriptPublicKeyHex: String(note.scriptPublicKeyHex).toLowerCase(),
    covenantId: familyId,
    program,
    descriptor: validated,
    descriptorHash: assets.computeDescriptorHash(validated),
    templateIndex
  };
}
function resolveTokenPosition({ config, descriptor, templateIndex, chain, covenantId, template }) {
  const validated = validateDescriptorAgainstTemplate({ descriptor, templateIndex, template });
  return resolveNote({ config, validated, templateIndex, note: chain?.tokenPosition, template, label: "chain.tokenPosition", expectedOwner: covenantId, expectedScheme: assets.kcc20.OWNER_SCHEMES.COVENANT_ID });
}

function resolveAgentProof(state, params) {
  const agentPk = normalizeXOnlyPubkey(params.agentPk, "params.agentPk");
  if (params.agents !== undefined) {
    const tree = buildTokenAgentTreeV6(params.agents);
    if (tree.root !== state.agentRoot) fail("the supplied agent set does not reproduce the live agentRoot — refusing to build", "AGENT_ROOT_MISMATCH");
    const proof = generateTokenAgentProofV6(tree, agentPk);
    return { policy: proof.policy, proof };
  }
  if (params.agentPolicy !== undefined && params.agentProof !== undefined) {
    const proof = { agentPk, root: normalizeHex(params.agentProof.root ?? state.agentRoot, 32, "agentProof.root"), siblingsHex: String(params.agentProof.siblingsHex ?? "").toLowerCase(), pathBits: parseSompi(params.agentProof.pathBits ?? 0n, "agentProof.pathBits") };
    if (proof.root !== state.agentRoot) fail("agent proof root does not match the live agentRoot", "AGENT_ROOT_MISMATCH");
    if (!verifyTokenAgentProofV6({ root: state.agentRoot, policy: params.agentPolicy, siblingsHex: proof.siblingsHex, pathBits: proof.pathBits })) fail("agent proof does not verify for this policy under the live agentRoot", "AGENT_PROOF_INVALID");
    return { policy: params.agentPolicy, proof };
  }
  fail("this action requires either params.agents (full set) or params.agentPolicy + params.agentProof");
}
function resolveSwapProof(state, params) {
  if (params.swapPolicies !== undefined) {
    if (params.swapPolicy === undefined) fail("params.swapPolicy (the leaf to use) is required alongside params.swapPolicies");
    const tree = buildSwapPolicyTreeV6(params.swapPolicies);
    if (tree.root !== state.swapRoot) fail("the supplied swap policy set does not reproduce the live swapRoot — refusing to build", "SWAP_ROOT_MISMATCH");
    const proof = generateSwapPolicyProofV6(tree, params.swapPolicy);
    return { swapPolicy: proof.policy, proof };
  }
  if (params.swapPolicy !== undefined && params.swapProof !== undefined) {
    const policy = normalizeSwapPolicyV6(params.swapPolicy);
    const proof = { root: normalizeHex(params.swapProof.root ?? state.swapRoot, 32, "swapProof.root"), siblingsHex: String(params.swapProof.siblingsHex ?? "").toLowerCase(), pathBits: parseSompi(params.swapProof.pathBits ?? 0n, "swapProof.pathBits") };
    if (proof.root !== state.swapRoot) fail("swap proof root does not match the live swapRoot", "SWAP_ROOT_MISMATCH");
    if (!verifySwapPolicyProofV6({ root: state.swapRoot, policy, siblingsHex: proof.siblingsHex, pathBits: proof.pathBits })) fail("swap proof does not verify for this policy under the live swapRoot — unapproved venue/pool policy", "SWAP_PROOF_INVALID");
    return { swapPolicy: policy, proof };
  }
  fail("swaps require either params.swapPolicies (full set) + params.swapPolicy, or params.swapPolicy + params.swapProof");
}
function resolveRecipientProof(agentRecipientRoot, params) {
  const recipient = normalizeHex(params.recipient, 32, "params.recipient");
  let proof;
  if (params.recipients !== undefined) {
    const tree = buildRecipientTree(params.recipients);
    if (tree.root !== agentRecipientRoot) fail("the supplied recipient list does not reproduce this agent's agentRecipientRoot — refusing to build", "RECIPIENT_ROOT_MISMATCH");
    proof = generateRecipientProof(tree, recipient);
  } else if (params.recipientProof !== undefined) {
    proof = { recipient, root: normalizeHex(params.recipientProof.root, 32, "recipientProof.root"), siblingsHex: String(params.recipientProof.siblingsHex ?? "").toLowerCase(), pathBits: parseSompi(params.recipientProof.pathBits ?? 0n, "recipientProof.pathBits") };
  } else fail("tokenAgentSpend requires either params.recipients (full list) or params.recipientProof");
  if (proof.root !== agentRecipientRoot) fail("recipient proof root does not match this agent's agentRecipientRoot", "RECIPIENT_ROOT_MISMATCH");
  if (!verifyRecipientProof({ root: proof.root, recipient, siblingsHex: proof.siblingsHex, pathBits: BigInt(proof.pathBits) })) fail("recipient proof does not verify for this recipient", "RECIPIENT_PROOF_INVALID");
  return { recipient, proof };
}

/*
 * The VENUE PROFILE (protocol facts) pinned by the owner's swap policy leaf,
 * and the live POOL position PROVEN against it: the profile's template
 * identity + geometry + fee key must equal the leaf's; the claimed pool
 * state compiled through the fixture program must reproduce the live UTXO's
 * P2SH; the UTXO value must equal the declared KAS reserve.
 */
function resolveVenue({ config, params, swapPolicy, template, ourProgram, chain }) {
  const profile = normalizeSwapVenueProfile(params.venueProfile);
  const profileHash = computeSwapVenueProfileHash(profile);
  if (profileHash !== swapPolicy.profileHash) fail("venue profile hash != the swap policy leaf's pinned profileHash — profile substitution; failing closed", "PROFILE_PIN_MISMATCH");
  if (profile.networkId !== config.networkId) fail(`venue profile network ${profile.networkId} != ${config.networkId} — failing closed`, "NETWORK_MISMATCH");
  if (profile.tokenCovenantId !== template.tokenCovenantId) fail("venue profile token family != the controller's pinned tokenCovenantId — pair mismatch; failing closed", "PAIR_MISMATCH");
  if (profile.poolCovenantId !== swapPolicy.poolCovenantId || profile.poolTemplateVmHashBlake2b256 !== swapPolicy.poolTemplateVmHash) fail("venue profile pool identity != the swap policy leaf's pinned pool family/template — failing closed", "POOL_PIN_MISMATCH");
  if (BigInt(profile.poolTemplateGeometry.prefixLen) !== swapPolicy.poolPrefixLen || BigInt(profile.poolTemplateGeometry.suffixLen) !== swapPolicy.poolSuffixLen) fail("venue profile pool geometry != the swap policy leaf's — failing closed", "POOL_PIN_MISMATCH");
  if (profile.feeModel.protocolFeePk !== swapPolicy.poolFeePk) fail("venue profile protocol-fee key != the swap policy leaf's poolFeePk — failing closed", "POOL_PIN_MISMATCH");

  const pool = chain?.pool;
  if (!pool || typeof pool !== "object") fail("chain.pool { outpoint, value, scriptPublicKeyHex, covenantId, state } is required for a swap", "POOL_REQUIRED");
  const poolId = normalizeHex(pool.covenantId, 32, "chain.pool.covenantId");
  if (poolId !== swapPolicy.poolCovenantId) fail("chain.pool.covenantId is not the approved pool family — wrong venue; failing closed", "WRONG_POOL_FAMILY");
  const st = pool.state;
  if (!st || typeof st !== "object") fail("chain.pool.state { kasReserve, tokenReserve, feeBps, nonce } is required");
  const poolState = { kasReserve: parsePositiveSompi(st.kasReserve, "chain.pool.state.kasReserve"), tokenReserve: assets.kcc20.parseAtomicAmount(st.tokenReserve, "chain.pool.state.tokenReserve"), feeBps: parseSompi(st.feeBps, "chain.pool.state.feeBps"), nonce: parseSompi(st.nonce ?? 0n, "chain.pool.state.nonce") };
  if (poolState.feeBps !== profile.feeModel.poolFeeBps) fail("chain.pool.state.feeBps != the venue profile's poolFeeBps — failing closed", "POOL_FEE_MISMATCH");
  const compiled = compilePoolFixtureV6({
    config,
    params: {
      tokenCovenantId: template.tokenCovenantId,
      kcc20: { prefixHex: ourProgram.prefixHex, suffixHex: ourProgram.suffixHex, templateVmHashBlake2b256: ourProgram.templateVmHashBlake2b256 },
      protocolFeePk: profile.feeModel.protocolFeePk,
      protocolFeeBps: profile.feeModel.protocolFeeBps,
      kasReserve: poolState.kasReserve,
      tokenReserve: poolState.tokenReserve,
      feeBps: poolState.feeBps,
      nonce: poolState.nonce
    }
  });
  if (compiled.templateVmHashBlake2b256 !== swapPolicy.poolTemplateVmHash || BigInt(compiled.geometry.prefixLen) !== swapPolicy.poolPrefixLen || BigInt(compiled.geometry.suffixLen) !== swapPolicy.poolSuffixLen) {
    fail("the venue program does not reproduce the approved pool template identity/geometry — unsupported venue variant; failing closed", "POOL_TEMPLATE_MISMATCH");
  }
  const liveSpk = String(pool.scriptPublicKeyHex ?? "").toLowerCase();
  if (compiled.p2shSpkHex !== liveSpk) fail("the claimed pool state does not reproduce the live pool UTXO's script — stale or forged pool state; failing closed", "POOL_STATE_MISMATCH");
  const value = parsePositiveSompi(pool.value, "chain.pool.value");
  if (value !== poolState.kasReserve) fail("chain.pool.value != the pool's declared kasReserve — failing closed", "POOL_VALUE_MISMATCH");
  return { profile, profileHash, poolId, outpoint: normalizeOutpoint(pool.outpoint, "chain.pool.outpoint"), value, scriptPublicKeyHex: liveSpk, state: poolState, compiled };
}

function planOwnerOp(state, action, params) {
  switch (action) {
    case "ownerSetAgentRoot": {
      let newRoot;
      if (params.newAgents !== undefined) newRoot = buildTokenAgentTreeV6(params.newAgents).root;
      else if (params.newAgentRoot !== undefined) newRoot = normalizeHex(params.newAgentRoot, 32, "params.newAgentRoot");
      else fail("ownerSetAgentRoot requires params.newAgents (canonical set) or params.newAgentRoot");
      return { ...setAgentRootSuccessorV6(state, newRoot), externalFunding: 0n };
    }
    case "ownerTopUpReserve": {
      const amount = parsePositiveSompi(params.topUpReserveAmountSompi, "topUpReserveAmountSompi");
      return { ...topUpReserveSuccessorV6(state, amount), externalFunding: amount };
    }
    case "ownerPause":
      return { ...pauseSuccessorV6(state, true), externalFunding: 0n };
    case "ownerUnpause":
      return { ...pauseSuccessorV6(state, false), externalFunding: 0n };
    case "ownerSetSwapRoot": {
      let newRoot;
      if (params.newSwapPolicies !== undefined) newRoot = buildSwapPolicyTreeV6(params.newSwapPolicies).root;
      else if (params.newSwapRoot !== undefined) newRoot = normalizeHex(params.newSwapRoot, 32, "params.newSwapRoot");
      else fail("ownerSetSwapRoot requires params.newSwapPolicies (canonical set) or params.newSwapRoot");
      return { ...setSwapRootSuccessorV6(state, newRoot), externalFunding: 0n };
    }
    case "ownerFundSwapPrincipal": {
      const amount = parsePositiveSompi(params.fundSwapPrincipalSompi, "fundSwapPrincipalSompi");
      return { ...fundSwapPrincipalSuccessorV6(state, amount), externalFunding: amount };
    }
    default:
      fail(`unknown v0.6 owner action ${JSON.stringify(action)} — failing closed`);
  }
}

/*
 * Build (and FREEZE) one v0.6 covenant transition.
 *   config, contractVersion ("policyvault-0.6"), templateInput, stateInput,
 *   action, params, chain { predecessorOutpoint, covenantId, predecessorValue,
 *   fuel?, tokenPosition?, poolNote?, pool? }, changeXOnly, descriptor (+ templateIndex).
 */
function buildV6Transaction({ config, contractVersion, templateInput, stateInput, action, params = {}, chain, changeXOnly, descriptor, templateIndex = 0 }) {
  const abi = resolveV6Abi(contractVersion ?? CONTRACT_VERSION_V6);
  const isOwner = OWNER_CONTROL_ACTIONS.has(action);
  const isSpend = SPEND_ACTIONS.has(action);
  const isSwap = SWAP_ACTIONS.has(action);
  const terminal = action === "ownerRecover";
  if (!isOwner && !isSpend && !isSwap && !terminal) fail(`unknown v0.6 action ${JSON.stringify(action)} — failing closed`);
  const template = normalizeTemplateV6(templateInput);

  let state;
  if (terminal && params.allowMalformedState === true) state = normalizeStateV6ForRecovery(stateInput);
  else state = normalizeStateV6(stateInput);

  const predecessorOutpoint = normalizeOutpoint(chain?.predecessorOutpoint, "chain.predecessorOutpoint");
  const covenantId = normalizeHex(chain?.covenantId, 32, "chain.covenantId");
  const predecessorValue = parseSompi(chain?.predecessorValue, "chain.predecessorValue");
  const expectedValue = state.feeReserve + state.swapPrincipal;
  if (predecessorValue !== expectedValue) fail(`chain.predecessorValue ${predecessorValue} != feeReserve + swapPrincipal ${expectedValue} — stale or inconsistent state`, "STALE");
  const change = normalizeHex(changeXOnly, 32, "changeXOnly");

  const hasFuel = chain?.fuel !== undefined && chain?.fuel !== null;
  if ((isOwner || terminal) && !hasFuel) fail("owner operations pin every covenant value, so the network fee MUST come from an ordinary fuel UTXO — provide chain.fuel", "FUEL_REQUIRED");
  if (isSwap && hasFuel) fail(`a swap carries EXACTLY ${SWAP_INPUT_COUNT} inputs and pays its exact fee from the fee reserve — no fuel input is admitted`, "FUEL_FORBIDDEN");
  const fuel = hasFuel ? normalizeFuel(chain.fuel) : null;

  if (descriptor !== undefined) {
    const dh = assets.computeDescriptorHash(descriptor);
    if (dh !== template.descriptorHash) fail("descriptor hash != the controller's pinned descriptorHash — descriptor substitution/downgrade; failing closed", "DESCRIPTOR_PIN_MISMATCH");
  }

  const current = compileExactStateV6({ config, template, state, contractVersion: abi.version });
  const { loadKaspa } = require("./chain");
  const kaspa = loadKaspa(config);
  const p2sh = (scriptBytes) => String(kaspa.payToScriptHashScript(scriptBytes.toString("hex")).script).toLowerCase();
  const currentSpkHex = p2sh(current.scriptBytes);
  const encoderPaths = { sourcePath: path.join(current.buildDir, "PolicyVault.state.sil"), constructorArgsPath: path.join(current.buildDir, "constructor-args.json") };
  const covIn = (budget) => ({ previousOutpoint: predecessorOutpoint, sequence: 0n, computeBudget: budget, utxo: { amount: predecessorValue, scriptPublicKey: { version: 0, scriptHex: currentSpkHex }, covenantId, blockDaaScore: 0n } });
  const fuelIn = () => ({ previousOutpoint: fuel.outpoint, sequence: 0n, computeBudget: V6_BUDGET.ORDINARY_INPUT, utxo: { amount: fuel.amount, scriptPublicKey: { version: 0, scriptHex: fuel.scriptPublicKeyHex }, covenantId: null, blockDaaScore: 0n } });
  const noteIn = (note, budget) => ({ previousOutpoint: note.outpoint, sequence: 0n, computeBudget: budget, utxo: { amount: note.value, scriptPublicKey: { version: 0, scriptHex: note.scriptPublicKeyHex }, covenantId: note.covenantId, blockDaaScore: 0n } });
  const geometry = { templatePrefixLen: template.templatePrefixLen, templateSuffixLen: template.templateSuffixLen };
  const tokenBudget = selectTokenInputBudgetV6(geometry);

  let plan;
  let callExtra = {};
  let tokenSide = null;
  let swapSide = null;
  let inputLayout;
  const controllerValueOf = (s) => s.feeReserve + s.swapPrincipal;

  if (isSpend) {
    if (descriptor === undefined) fail("tokenAgentSpend requires the accepted asset descriptor", "DESCRIPTOR_REQUIRED");
    const position = resolveTokenPosition({ config, descriptor, templateIndex, chain, covenantId, template });
    const { policy, proof } = resolveAgentProof(state, params);
    const { recipient, proof: rProof } = resolveRecipientProof(normalizeHex(policy.agentRecipientRoot, 32, "agentPolicy.agentRecipientRoot"), params);
    const periods = parseSompi(params.periodsElapsed ?? 0n, "periodsElapsed");
    const recipientCarry = parseSompi(params.recipientCarryKasSompi, "recipientCarryKasSompi");
    if (recipientCarry >= position.value) fail("recipient carry KAS must leave the token position with KAS", "CARRY_TOO_LARGE");
    const selfCarry = position.value - recipientCarry;
    if (!hasFuel && params.reserveConsumedSompi !== undefined) fail("without chain.fuel the reserve consumption IS the exact network fee and is derived by the builder — do not supply reserveConsumedSompi");
    const requestedConsumed = hasFuel ? parseSompi(params.reserveConsumedSompi ?? 0n, "reserveConsumedSompi") : null;
    const budget = selectComputeBudgetV6({ operation: action, ...geometry });

    const shapeFor = (consumed) => {
      const spend = tokenAgentSpendSuccessorV6(state, {
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
      const states = tokenContinuationStatesV6({ controllerCovenantId: covenantId, recipientPk: recipient, plan: spend });
      const next = compileExactStateV6({ config, template, state: spend.successor, contractVersion: abi.version });
      const selfProgram = compileKcc20Program({ config, state: states.selfNew, familyBound: position.program.familyBound });
      const recipientProgram = compileKcc20Program({ config, state: states.recipientNew, familyBound: position.program.familyBound });
      const p = spend.previousPolicy;
      const spendCallExtra = {
        selfNew: kcc20StateJson(states.selfNew),
        recipientNew: kcc20StateJson(states.recipientNew),
        agentPk: p.agentPk,
        tokenMaxPerSpend: p.tokenMaxPerSpend.toString(),
        tokenPeriodBudget: p.tokenPeriodBudget.toString(),
        periodLengthDaa: p.periodLengthDaa.toString(),
        periodStartDaa: p.periodStartDaa.toString(),
        tokenPeriodSpent: p.tokenPeriodSpent.toString(),
        agentMaxFeePerTx: p.agentMaxFeePerTx.toString(),
        agentMaxCarryKas: p.agentMaxCarryKas.toString(),
        kasMaxPerSwap: p.kasMaxPerSwap.toString(),
        kasPeriodBudget: p.kasPeriodBudget.toString(),
        kasPeriodSpent: p.kasPeriodSpent.toString(),
        agentRecipientRoot: p.agentRecipientRoot,
        policySiblings: proof.siblingsHex,
        policyPathBits: BigInt(proof.pathBits).toString(),
        periodsElapsed: periods.toString(),
        recipientPk: recipient,
        recipientSiblings: rProof.siblingsHex,
        recipientPathBits: BigInt(rProof.pathBits).toString()
      };
      const placeholderCall = { function: action, signature: PLACEHOLDER_SIG_HEX, successor: successorCallJsonV6(stateToJsonV6(spend.successor)), ...spendCallExtra };
      const callHex = runEncoderV4({ ...encoderPaths, call: placeholderCall, contractVersion: abi.version });
      const covenantSigscriptLen = covenantSigscript(callHex, current.scriptBytes).length / 2;
      const tokenCallHex = encodeTokenTransfer({ program: position.program, newStates: [states.selfNew, states.recipientNew], witnessesHex: "00" });
      const tokenSigscriptHex = covenantSigscript(tokenCallHex, Buffer.from(position.program.scriptHex, "hex"));
      const inputs = [covIn(budget), noteIn(position, tokenBudget)];
      const sigLens = [covenantSigscriptLen, tokenSigscriptHex.length / 2];
      if (fuel) {
        inputs.push(fuelIn());
        sigLens.push(ORDINARY_SIGSCRIPT_LEN);
      }
      const outputs = [
        { value: controllerValueOf(spend.successor), scriptPublicKey: { version: 0, scriptHex: p2sh(next.scriptBytes) }, covenant: { authorizingInput: 0, covenantId } },
        { value: selfCarry, scriptPublicKey: { version: 0, scriptHex: selfProgram.p2shSpkHex }, covenant: { authorizingInput: 1, covenantId: position.covenantId } },
        { value: recipientCarry, scriptPublicKey: { version: 0, scriptHex: recipientProgram.p2shSpkHex }, covenant: { authorizingInput: 1, covenantId: position.covenantId } }
      ];
      if (fuel) outputs.push({ value: 1n, scriptPublicKey: { version: 0, scriptHex: p2pkScriptHex(change) }, covenant: null });
      const draft = { version: 1, inputs, outputs, lockTime: spend.lockTime, subnetworkId: "00".repeat(20), gas: 0n, payload: "" };
      const fee = exactFee(draft, sigLens);
      return { spend, states, next, draft, fee, budget, callHex, covenantSigscriptLen, tokenSigscriptHex, spendCallExtra, recipient, rProof, sigLens };
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
    callExtra = shape.spendCallExtra;
    tokenSide = { position, states: shape.states, tokenSigscriptHex: shape.tokenSigscriptHex, recipient: shape.recipient, recipientProof: shape.rProof, recipientCarry, selfCarry };
    inputLayout = fuel ? ["controller", "token", "fuel"] : ["controller", "token"];
    plan = { kind: "spend", spend: shape.spend, successor: shape.spend.successor, next: shape.next, draft: shape.draft, fee: shape.fee, budget: shape.budget, covenantSigscriptLen: shape.covenantSigscriptLen, plannedCallHexLength: shape.callHex.length, lockTime: shape.spend.lockTime, externalFunding: 0n, reserveConsumed: shape.spend.reserveConsumed };
  } else if (isSwap) {
    const sell = action === "tokenAtomicSell";
    if (descriptor === undefined) fail(`${action} requires the accepted asset descriptor`, "DESCRIPTOR_REQUIRED");
    const position = resolveTokenPosition({ config, descriptor, templateIndex, chain, covenantId, template });
    const { policy, proof } = resolveAgentProof(state, params);
    const { swapPolicy, proof: sProof } = resolveSwapProof(state, params);
    const venue = resolveVenue({ config, params, swapPolicy, template, ourProgram: position.program, chain });
    const poolNote = resolveNote({ config, validated: position.descriptor, templateIndex, note: chain?.poolNote, template, label: "chain.poolNote", expectedOwner: venue.poolId, expectedScheme: assets.kcc20.OWNER_SCHEMES.COVENANT_ID });
    if (poolNote.program.state.amount !== venue.state.tokenReserve) fail("the pool's reserve note amount != its declared tokenReserve — the pool would refuse; failing closed", "POOL_STATE_MISMATCH");
    const deadlineDaa = parsePositiveSompi(params.deadlineDaa, "deadlineDaa");
    const periods = parseSompi(params.periodsElapsed ?? 0n, "periodsElapsed");
    const budget = selectComputeBudgetV6({ operation: action, ...geometry, poolPrefixLen: venue.compiled.geometry.prefixLen, poolSuffixLen: venue.compiled.geometry.suffixLen });
    const poolBudget = selectPoolInputBudgetV6({ ...geometry, poolPrefixLen: venue.compiled.geometry.prefixLen, poolSuffixLen: venue.compiled.geometry.suffixLen });

    const shapeFor = (consumed, protocolFeeSompi) => {
      const common = {
        agentPolicy: policy,
        agentProof: { siblingsHex: proof.siblingsHex, pathBits: proof.pathBits },
        swapPolicy,
        swapProof: { siblingsHex: sProof.siblingsHex, pathBits: sProof.pathBits },
        pool: venue.state,
        protocolFeeBps: venue.profile.feeModel.protocolFeeBps,
        protocolFeeSompi,
        tokenPositionAmount: position.program.state.amount,
        poolNoteAmount: poolNote.program.state.amount,
        periodsElapsed: periods,
        reserveConsumed: consumed,
        ourNoteKas: position.value
      };
      const sw = sell ? tokenAtomicSellSuccessorV6(state, { ...common, amountIn: params.amountIn, minKasOut: params.minKasOut }) : tokenAtomicBuySuccessorV6(state, { ...common, tokensOut: params.tokensOut, maxKasIn: params.maxKasIn });
      const states = swapContinuationStatesV6({ controllerCovenantId: covenantId, plan: sw });
      const next = compileExactStateV6({ config, template, state: sw.successor, contractVersion: abi.version });
      const selfProgram = compileKcc20Program({ config, state: states.selfNew, familyBound: position.program.familyBound });
      const poolNoteProgram = compileKcc20Program({ config, state: states.poolNoteNew, familyBound: position.program.familyBound });
      const poolNext = compilePoolFixtureV6({ config, params: { ...venue.compiled.params, kasReserve: sw.quote.newKasReserve, tokenReserve: sw.quote.newTokenReserve, nonce: sw.quote.newNonce } });
      const p = sw.previousPolicy;
      const sp = sw.swapPolicy;
      const typeB = sw.destination.type === "B";
      const feeOutIdx = 4;
      const proceedsOutIdx = typeB ? 5 : 0;
      const swapCallExtra = {
        selfNew: kcc20StateJson(states.selfNew),
        poolNoteNew: kcc20StateJson(states.poolNoteNew),
        agentPk: p.agentPk,
        tokenMaxPerSpend: p.tokenMaxPerSpend.toString(),
        tokenPeriodBudget: p.tokenPeriodBudget.toString(),
        periodLengthDaa: p.periodLengthDaa.toString(),
        periodStartDaa: p.periodStartDaa.toString(),
        tokenPeriodSpent: p.tokenPeriodSpent.toString(),
        agentMaxFeePerTx: p.agentMaxFeePerTx.toString(),
        agentMaxCarryKas: p.agentMaxCarryKas.toString(),
        kasMaxPerSwap: p.kasMaxPerSwap.toString(),
        kasPeriodBudget: p.kasPeriodBudget.toString(),
        kasPeriodSpent: p.kasPeriodSpent.toString(),
        agentRecipientRoot: p.agentRecipientRoot,
        policySiblings: proof.siblingsHex,
        policyPathBits: BigInt(proof.pathBits).toString(),
        periodsElapsed: periods.toString(),
        profileHash: sp.profileHash,
        poolCovenantId: sp.poolCovenantId,
        poolTemplateVmHash: sp.poolTemplateVmHash,
        poolPrefixLen: sp.poolPrefixLen.toString(),
        poolSuffixLen: sp.poolSuffixLen.toString(),
        poolFeePk: sp.poolFeePk,
        maxProtocolFeeKas: sp.maxProtocolFeeKas.toString(),
        sellFloorNum: sp.sellFloorNum.toString(),
        sellFloorDen: sp.sellFloorDen.toString(),
        buyCeilNum: sp.buyCeilNum.toString(),
        buyCeilDen: sp.buyCeilDen.toString(),
        directionMask: sp.directionMask.toString(),
        destScheme: sp.destScheme,
        destIdentity: sp.destIdentity,
        swapSiblings: sProof.siblingsHex,
        swapPathBits: BigInt(sProof.pathBits).toString(),
        ...(sell ? { amountIn: sw.amountIn.toString(), minKasOut: sw.minKasOut.toString(), proceedsOutIdx: String(proceedsOutIdx), feeOutIdx: String(feeOutIdx) } : { tokensOut: sw.tokensOut.toString(), maxKasIn: sw.maxKasIn.toString(), feeOutIdx: String(feeOutIdx) })
      };
      const placeholderCall = { function: action, signature: PLACEHOLDER_SIG_HEX, successor: successorCallJsonV6(stateToJsonV6(sw.successor)), ...swapCallExtra };
      const callHex = runEncoderV4({ ...encoderPaths, call: placeholderCall, contractVersion: abi.version });
      const covenantSigscriptLen = covenantSigscript(callHex, current.scriptBytes).length / 2;
      /* token family: OUR note is the leader (input 1; witnesses = the owners' input indices: controller 0, pool 3), the pool note the delegate (input 2) */
      const leaderCallHex = encodeTokenTransfer({ program: position.program, newStates: [states.selfNew, states.poolNoteNew], witnessesHex: "0003" });
      const leaderSigscriptHex = covenantSigscript(leaderCallHex, Buffer.from(position.program.scriptHex, "hex"));
      const delegateCallHex = runEncoderV4({ sourcePath: poolNote.program.sourcePath, constructorArgsPath: poolNote.program.constructorArgsPath, call: { function: "transfer", signature: PLACEHOLDER_SIG_HEX, delegate: true }, contractVersion: "kcc20/1" });
      const delegateSigscriptHex = covenantSigscript(delegateCallHex, Buffer.from(poolNote.program.scriptHex, "hex"));
      const poolCallHex = runEncoderV4({
        sourcePath: venue.compiled.sourcePath,
        constructorArgsPath: venue.compiled.constructorArgsPath,
        call: {
          function: sell ? "sellSwap" : "buySwap",
          signature: PLACEHOLDER_SIG_HEX,
          newState: { kasReserve: sw.quote.newKasReserve.toString(), tokenReserve: sw.quote.newTokenReserve.toString(), feeBps: venue.state.feeBps.toString(), nonce: sw.quote.newNonce.toString() },
          amount: sell ? sw.amountIn.toString() : sw.kasIn.toString(),
          reserveOutIdx: "1",
          feeOutIdx: String(feeOutIdx),
          reserveNew: kcc20StateJson(states.poolNoteNew)
        },
        contractVersion: POOL_FIXTURE_VERSION
      });
      const poolSigscriptHex = covenantSigscript(poolCallHex, Buffer.from(venue.compiled.scriptHex, "hex"));
      const inputs = [covIn(budget), noteIn(position, tokenBudget), noteIn(poolNote, tokenBudget), { previousOutpoint: venue.outpoint, sequence: 0n, computeBudget: poolBudget, utxo: { amount: venue.value, scriptPublicKey: { version: 0, scriptHex: venue.scriptPublicKeyHex }, covenantId: venue.poolId, blockDaaScore: 0n } }];
      const sigLens = [covenantSigscriptLen, leaderSigscriptHex.length / 2, delegateSigscriptHex.length / 2, poolSigscriptHex.length / 2];
      const outputs = [
        { value: controllerValueOf(sw.successor), scriptPublicKey: { version: 0, scriptHex: p2sh(next.scriptBytes) }, covenant: { authorizingInput: 0, covenantId } },
        { value: position.value, scriptPublicKey: { version: 0, scriptHex: selfProgram.p2shSpkHex }, covenant: { authorizingInput: 1, covenantId: position.covenantId } },
        { value: poolNote.value, scriptPublicKey: { version: 0, scriptHex: poolNoteProgram.p2shSpkHex }, covenant: { authorizingInput: 1, covenantId: position.covenantId } },
        { value: sw.quote.newKasReserve, scriptPublicKey: { version: 0, scriptHex: poolNext.p2shSpkHex }, covenant: { authorizingInput: 3, covenantId: venue.poolId } },
        { value: sw.protocolFee, scriptPublicKey: { version: 0, scriptHex: p2pkScriptHex(sp.poolFeePk) }, covenant: null }
      ];
      if (typeB) outputs.push({ value: sw.netProceeds, scriptPublicKey: { version: 0, scriptHex: p2pkScriptHex(sp.destIdentity) }, covenant: null });
      const draft = { version: 1, inputs, outputs, lockTime: sw.lockTime, subnetworkId: "00".repeat(20), gas: 0n, payload: "" };
      const fee = exactFee(draft, sigLens);
      return { sw, states, next, poolNext, draft, fee, budget, poolBudget, callHex, covenantSigscriptLen, swapCallExtra, leaderSigscriptHex, delegateSigscriptHex, poolSigscriptHex, sigLens, feeOutIdx, proceedsOutIdx };
    };

    /* the reserve pays EXACTLY the fee (fixed point); the protocol-fee output is padded only when
     * KIP-9 storage mass would otherwise exceed the block-fit limit (explicit, surfaced cost) */
    const requestedProto = params.protocolFeeSompi !== undefined ? parseSompi(params.protocolFeeSompi, "protocolFeeSompi") : undefined;
    let shape;
    let consumed = 0n;
    let iterations = 0;
    for (;;) {
      shape = shapeFor(consumed, requestedProto);
      if (shape.fee === consumed) break;
      consumed = shape.fee;
      iterations += 1;
      if (iterations > 4) fail("reserve-funded fee fixed point did not converge — failing closed", "FEE_FIXPOINT");
    }
    const { inputCells: inVals, outputCells: outCellsV6 } = cellsOfFrozenTx(shape.draft);
    const outVals = outCellsV6; /* cells (amount + plurality); .amount is the value */
    const storage = calcStorageMass(inVals, outVals);
    if (storage > STORAGE_MASS_LIMIT) {
      let smallest = 0;
      outVals.forEach((c, i) => { if (c.amount < outVals[smallest].amount) smallest = i; });
      const remedy = smallest === shape.feeOutIdx ? `the protocol-fee output (${shape.sw.protocolFee} sompi) is dust for this swap size; pad it via params.protocolFeeSompi >= ${minimumOutputValueForLimit(inVals, outVals, shape.feeOutIdx) ?? "n/a"} (<= the owner's maxProtocolFeeKas) or increase the swap size` : `output ${smallest} (${outVals[smallest].amount} sompi, plurality ${outVals[smallest].plurality}) is dust; token-note carries must be sized for storage mass before a swap`;
      fail(`KIP-9 storage mass ${storage} exceeds the ${STORAGE_MASS_LIMIT}-gram block-fit limit — the transaction would be INVALID: ${remedy}`, "STORAGE_MASS_OVER_LIMIT");
    }
    callExtra = shape.swapCallExtra;
    tokenSide = { position, states: shape.states, tokenSigscriptHex: shape.leaderSigscriptHex, recipient: null, recipientProof: null, recipientCarry: 0n, selfCarry: position.value };
    swapSide = { venue, poolNote, sw: shape.sw, poolNext: shape.poolNext, delegateSigscriptHex: shape.delegateSigscriptHex, poolSigscriptHex: shape.poolSigscriptHex, swapProof: sProof, deadlineDaa, storageMass: storage, poolBudget: shape.poolBudget, feeOutIdx: shape.feeOutIdx, proceedsOutIdx: shape.proceedsOutIdx };
    inputLayout = ["controller", "tokenLeader", "tokenDelegate", "pool"];
    plan = { kind: "swap", successor: shape.sw.successor, next: shape.next, draft: shape.draft, fee: shape.fee, budget: shape.budget, covenantSigscriptLen: shape.covenantSigscriptLen, plannedCallHexLength: shape.callHex.length, lockTime: shape.sw.lockTime, externalFunding: 0n, reserveConsumed: shape.sw.reserveConsumed };
  } else if (!terminal) {
    const owner = planOwnerOp(state, action, params);
    const next = compileExactStateV6({ config, template, state: owner.successor, contractVersion: abi.version });
    const budget = selectComputeBudgetV6({ operation: action, ...geometry });
    const placeholderCall = { function: "ownerControl", opSelector: owner.opSelector, signature: PLACEHOLDER_SIG_HEX, successor: successorCallJsonV6(stateToJsonV6(owner.successor)) };
    const callHex = runEncoderV4({ ...encoderPaths, call: placeholderCall, contractVersion: abi.version });
    const covenantSigscriptLen = covenantSigscript(callHex, current.scriptBytes).length / 2;
    const inputs = [covIn(budget), fuelIn()];
    const outputs = [
      { value: controllerValueOf(owner.successor), scriptPublicKey: { version: 0, scriptHex: p2sh(next.scriptBytes) }, covenant: { authorizingInput: 0, covenantId } },
      { value: 1n, scriptPublicKey: { version: 0, scriptHex: p2pkScriptHex(change) }, covenant: null }
    ];
    const draft = { version: 1, inputs, outputs, lockTime: 0n, subnetworkId: "00".repeat(20), gas: 0n, payload: "" };
    const fee = exactFee(draft, [covenantSigscriptLen, ORDINARY_SIGSCRIPT_LEN]);
    const changeValue = fuel.amount - fee - owner.externalFunding;
    if (changeValue <= 0n) fail(`fuel ${fuel.amount} cannot cover fee ${fee} + external funding ${owner.externalFunding}`, "INSUFFICIENT_FUEL");
    outputs[1] = { ...outputs[1], value: changeValue };
    callExtra = { opSelector: owner.opSelector };
    inputLayout = ["controller", "fuel"];
    plan = { kind: "owner", successor: owner.successor, next, draft: { ...draft, outputs }, fee, budget, covenantSigscriptLen, plannedCallHexLength: callHex.length, lockTime: 0n, externalFunding: owner.externalFunding, reserveConsumed: 0n, opSelector: owner.opSelector };
  } else {
    const hasPosition = chain?.tokenPosition !== undefined && chain?.tokenPosition !== null;
    let position = null;
    let recover;
    let recipientProgram = null;
    let tokenSigscriptHex = null;
    if (hasPosition) {
      if (descriptor === undefined) fail("ownerRecover with a token position requires the accepted asset descriptor", "DESCRIPTOR_REQUIRED");
      position = resolveTokenPosition({ config, descriptor, templateIndex, chain, covenantId, template });
      recover = recoverPlanV6(state, template.owner, position.program.state.amount);
      recipientProgram = compileKcc20Program({ config, state: recover.tokenRecipient, familyBound: position.program.familyBound });
      const tokenCallHex = encodeTokenTransfer({ program: position.program, newStates: [recover.tokenRecipient], witnessesHex: "00" });
      tokenSigscriptHex = covenantSigscript(tokenCallHex, Buffer.from(position.program.scriptHex, "hex"));
    } else recover = recoverPlanV6(state, template.owner, null);
    const budget = selectComputeBudgetV6({ operation: action, ...geometry });
    const recipientNewJson = recover.tokenRecipient ? kcc20StateJson(recover.tokenRecipient) : { ownerIdentifier: template.owner, identifierType: 0, amount: "0", isMinter: false };
    const placeholderCall = { function: "ownerRecover", signature: PLACEHOLDER_SIG_HEX, recipientNew: recipientNewJson };
    const callHex = runEncoderV4({ ...encoderPaths, call: placeholderCall, contractVersion: abi.version });
    const covenantSigscriptLen = covenantSigscript(callHex, current.scriptBytes).length / 2;
    const inputs = [covIn(budget)];
    const sigLens = [covenantSigscriptLen];
    if (position) {
      inputs.push(noteIn(position, tokenBudget));
      sigLens.push(tokenSigscriptHex.length / 2);
    }
    inputs.push(fuelIn());
    sigLens.push(ORDINARY_SIGSCRIPT_LEN);
    const outputs = [{ value: recover.payout, scriptPublicKey: { version: 0, scriptHex: p2pkScriptHex(recover.payoutTo) }, covenant: null }];
    if (position) outputs.push({ value: position.value, scriptPublicKey: { version: 0, scriptHex: recipientProgram.p2shSpkHex }, covenant: { authorizingInput: 1, covenantId: position.covenantId } });
    outputs.push({ value: 1n, scriptPublicKey: { version: 0, scriptHex: p2pkScriptHex(change) }, covenant: null });
    const draft = { version: 1, inputs, outputs, lockTime: 0n, subnetworkId: "00".repeat(20), gas: 0n, payload: "" };
    const fee = exactFee(draft, sigLens);
    const changeValue = fuel.amount - fee;
    if (changeValue <= 0n) fail(`fuel ${fuel.amount} cannot cover fee ${fee}`, "INSUFFICIENT_FUEL");
    outputs[outputs.length - 1] = { ...outputs[outputs.length - 1], value: changeValue };
    callExtra = { recipientNew: recipientNewJson };
    tokenSide = position ? { position, states: { recipientNew: recover.tokenRecipient }, tokenSigscriptHex, recipient: template.owner, recipientProof: null, recipientCarry: position.value, selfCarry: 0n } : null;
    inputLayout = position ? ["controller", "token", "fuel"] : ["controller", "fuel"];
    plan = { kind: "recover", terminal: true, recover, successor: null, next: null, draft: { ...draft, outputs }, fee, budget, covenantSigscriptLen, plannedCallHexLength: callHex.length, lockTime: 0n, externalFunding: 0n, reserveConsumed: 0n };
  }

  if (plan.draft.inputs.length > MAX_TX_FEE_IO || plan.draft.outputs.length > MAX_TX_FEE_IO) fail(`transaction shape exceeds the covenant fee-introspection bound of ${MAX_TX_FEE_IO} inputs/outputs`);
  const frozen = normalizeFrozenTxV3(plan.draft);
  assertStorageMassWithinLimit(frozen, "policyvault-0.6 builder");
  const described = describeFrozenTx(frozen);
  const totalIn = frozen.inputs.reduce((s, i) => s + i.utxo.amount, 0n);
  const totalOut = frozen.outputs.reduce((s, o) => s + o.value, 0n);
  if (totalIn - totalOut !== plan.fee) fail("internal: realized fee != required fee");
  if (!plan.terminal) {
    const succ = frozen.outputs.filter((o) => o.covenant !== null && o.covenant.covenantId === covenantId);
    if (succ.length !== 1 || succ[0].value !== controllerValueOf(plan.successor)) fail("internal: successor output does not carry exactly feeReserve + swapPrincipal");
  }
  if (isSwap && frozen.inputs.length !== SWAP_INPUT_COUNT) fail("internal: swap input count");

  const successorStateId = plan.terminal ? null : computeStateIdV6({ networkId: config.networkId, template, state: plan.successor, contractVersion: abi.version });
  const externalIn = fuel ? fuel.amount : 0n;
  const externalOut = fuel ? frozen.outputs[frozen.outputs.length - 1].value : 0n;
  const sw = swapSide ? swapSide.sw : null;

  return deepFreeze({
    kind: "transition",
    contractVersion: abi.version,
    encoderFunction: isSpend || isSwap ? action : terminal ? "ownerRecover" : "ownerControl",
    networkId: config.networkId,
    action,
    role: isOwner || terminal ? "owner" : "agent",
    template,
    predecessorOutpoint,
    predecessorStateId: current.stateId,
    covenantId,
    stateJson: stateToJsonV6(state),
    successorState: plan.terminal ? null : stateToJsonV6(plan.successor),
    successorStateId,
    successorScriptSha256: plan.terminal ? null : plan.next.scriptSha256,
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
    swap: swapSide
      ? Object.freeze({
          direction: sw.direction,
          venueProfileHash: swapSide.venue.profileHash,
          venueProfile: Object.freeze(JSON.parse(JSON.stringify(require("./swap-policy-v6").swapVenueProfileToJson(swapSide.venue.profile)))),
          swapPolicy: swapPolicyToJsonV6(sw.swapPolicy),
          swapProof: Object.freeze({ root: state.swapRoot, siblingsHex: swapSide.swapProof.siblingsHex, pathBits: BigInt(swapSide.swapProof.pathBits).toString() }),
          pool: Object.freeze({
            covenantId: swapSide.venue.poolId,
            outpoint: swapSide.venue.outpoint,
            stateBefore: Object.freeze({ kasReserve: swapSide.venue.state.kasReserve.toString(), tokenReserve: swapSide.venue.state.tokenReserve.toString(), feeBps: swapSide.venue.state.feeBps.toString(), nonce: swapSide.venue.state.nonce.toString() }),
            stateAfter: Object.freeze({ kasReserve: sw.quote.newKasReserve.toString(), tokenReserve: sw.quote.newTokenReserve.toString(), feeBps: swapSide.venue.state.feeBps.toString(), nonce: sw.quote.newNonce.toString() }),
            scriptSha256Before: swapSide.venue.compiled.scriptSha256,
            scriptSha256After: swapSide.poolNext.scriptSha256,
            templateVmHashBlake2b256: swapSide.venue.compiled.templateVmHashBlake2b256,
            fixtureVersion: swapSide.venue.compiled.fixtureVersion
          }),
          poolNote: Object.freeze({ outpoint: swapSide.poolNote.outpoint, value: swapSide.poolNote.value.toString(), amountBefore: sw.poolNoteAmount.toString(), amountAfter: sw.poolNoteAfter.toString() }),
          quote: Object.freeze(sw.direction === "SELL" ? { amountIn: sw.amountIn.toString(), kasOut: sw.quote.kasOut.toString(), protocolFeeMinimum: sw.protocolFeeMinimum.toString(), protocolFee: sw.protocolFee.toString(), netProceeds: sw.netProceeds.toString(), minKasOut: sw.minKasOut.toString() } : { tokensOut: sw.tokensOut.toString(), kasIn: sw.kasIn.toString(), protocolFeeMinimum: sw.protocolFeeMinimum.toString(), protocolFee: sw.protocolFee.toString(), kasSpend: sw.kasSpend.toString(), maxKasIn: sw.maxKasIn.toString() }),
          destination: Object.freeze({ ...sw.destination }),
          outputIndexes: Object.freeze({ successor: 0, ourNote: 1, poolNote: 2, poolSuccessor: 3, protocolFee: swapSide.feeOutIdx, proceeds: sw.destination.type === "B" ? swapSide.proceedsOutIdx : null }),
          storageMass: swapSide.storageMass.toString(),
          freshness: Object.freeze({ poolOutpoint: swapSide.venue.outpoint, controllerOutpoint: predecessorOutpoint, deadlineDaa: swapSide.deadlineDaa.toString(), statement: FRESHNESS_STATEMENT })
        })
      : null,
    accounting: Object.freeze({
      token: Object.freeze({
        positionBefore: tokenSide ? tokenSide.position.program.state.amount.toString() : null,
        spendAmount: plan.kind === "spend" ? plan.spend.spendAmount.toString() : "0",
        amountIn: sw && sw.direction === "SELL" ? sw.amountIn.toString() : "0",
        amountOut: sw && sw.direction === "BUY" ? sw.tokensOut.toString() : "0",
        positionAfter: plan.kind === "spend" ? plan.spend.tokenSelfAfter.toString() : sw ? sw.tokenSelfAfter.toString() : plan.terminal && tokenSide ? "0" : tokenSide ? tokenSide.position.program.state.amount.toString() : null,
        recipient: tokenSide ? tokenSide.recipient : null,
        recoveredToOwner: plan.terminal && tokenSide ? tokenSide.position.program.state.amount.toString() : "0"
      }),
      kas: Object.freeze({
        predecessorFeeReserve: state.feeReserve.toString(),
        reserveConsumed: plan.reserveConsumed.toString(),
        successorFeeReserve: plan.terminal ? "0" : plan.successor.feeReserve.toString(),
        predecessorSwapPrincipal: state.swapPrincipal.toString(),
        successorSwapPrincipal: plan.terminal ? "0" : plan.successor.swapPrincipal.toString(),
        principalDelta: sw ? sw.kas.principalDelta.toString() : plan.kind === "owner" && plan.opSelector === OWNER_OP_SELECTOR_V6.ownerFundSwapPrincipal ? plan.externalFunding.toString() : "0",
        consideration: sw && sw.direction === "BUY" ? sw.kasSpend.toString() : "0",
        proceeds: sw && sw.direction === "SELL" ? sw.netProceeds.toString() : "0",
        protocolFee: sw ? sw.protocolFee.toString() : "0",
        externalIn: externalIn.toString(),
        externalOut: externalOut.toString(),
        externalFunding: plan.externalFunding.toString(),
        tokenInputKas: tokenSide ? tokenSide.position.value.toString() : "0",
        tokenSelfCarryKas: tokenSide ? tokenSide.selfCarry.toString() : "0",
        tokenRecipientCarryKas: tokenSide ? tokenSide.recipientCarry.toString() : "0",
        poolNoteKas: swapSide ? swapSide.poolNote.value.toString() : "0",
        poolKasBefore: swapSide ? swapSide.venue.value.toString() : "0",
        poolKasAfter: sw ? sw.quote.newKasReserve.toString() : "0",
        fee: plan.fee.toString(),
        terminalPayout: plan.terminal ? plan.recover.payout.toString() : "0"
      })
    }),
    frozen,
    frozenCanonicalJson: canonicalFrozenTxJson(frozen),
    txId: described.txId,
    covenantSighash: described.sighashAll[0],
    computeBudget: plan.budget,
    poolComputeBudget: swapSide ? swapSide.poolBudget : null,
    requiredFeeSompi: plan.fee.toString(),
    encoderBuildDir: current.buildDir,
    plannedCallHexLength: plan.plannedCallHexLength,
    callExtra,
    inputLayout: Object.freeze(inputLayout),
    hasFuelInput: fuel !== null,
    hasTokenInput: tokenSide !== null,
    tokenSignatureScriptHex: tokenSide ? tokenSide.tokenSigscriptHex : null,
    poolNoteSignatureScriptHex: swapSide ? swapSide.delegateSigscriptHex : null,
    poolSignatureScriptHex: swapSide ? swapSide.poolSigscriptHex : null,
    deadlineDaa: swapSide ? swapSide.deadlineDaa.toString() : null,
    agentProof: plan.kind === "spend" ? Object.freeze({ root: state.agentRoot, siblingsHex: plan.spend.agentProof.siblingsHex, pathBits: BigInt(plan.spend.agentProof.pathBits).toString() }) : sw ? Object.freeze({ root: state.agentRoot, siblingsHex: sw.agentProof.siblingsHex, pathBits: BigInt(sw.agentProof.pathBits).toString() }) : null,
    recipientProof: plan.kind === "spend" ? Object.freeze({ root: tokenSide.recipientProof.root, siblingsHex: tokenSide.recipientProof.siblingsHex, pathBits: BigInt(tokenSide.recipientProof.pathBits).toString() }) : null,
    payment: plan.kind === "spend" ? { recipient: tokenSide.recipient, tokenAmount: plan.spend.spendAmount.toString(), carryKasSompi: tokenSide.recipientCarry.toString() } : null
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
 * FINALIZE a frozen build (NO broadcasting): real covenant call bytes through
 * pv_call_encoder + every signature script. For swaps, `currentDaaScore` is
 * REQUIRED and must not exceed the build's deadlineDaa (pre-sign freshness;
 * the signer path calls this right before broadcasting).
 */
function finalizeV6Transaction({ build, covenantSignatureHex, fuelSignatureScriptHex, currentDaaScore }) {
  if (build.kind !== "transition" || build.contractVersion !== CONTRACT_VERSION_V6) fail("finalizeV6Transaction takes a v0.6 transition build");
  if (build.swap) {
    if (currentDaaScore === undefined || currentDaaScore === null) fail("finalizing a swap requires currentDaaScore (the node-verified DAA score) to enforce the pre-sign deadline", "DAA_REQUIRED");
    const now = parseSompi(currentDaaScore, "currentDaaScore");
    if (now > BigInt(build.deadlineDaa)) fail(`swap deadline ${build.deadlineDaa} passed (current DAA ${now}) — refusing to finalize; rebuild with a fresh quote`, "DEADLINE_PASSED");
  }
  const covenantSig = extractSchnorr65(covenantSignatureHex, "covenant signature");
  const terminal = build.action === "ownerRecover";
  const call = { function: build.encoderFunction, signature: covenantSig, ...build.callExtra };
  if (!terminal) call.successor = successorCallJsonV6(build.successorState);
  const callHex = runEncoderV4({ sourcePath: path.join(build.encoderBuildDir, "PolicyVault.state.sil"), constructorArgsPath: path.join(build.encoderBuildDir, "constructor-args.json"), call, contractVersion: build.contractVersion });
  if (callHex.length !== build.plannedCallHexLength) fail(`final covenant call length ${callHex.length / 2} != planned ${build.plannedCallHexLength / 2} — the exact-fee freeze is violated; refusing`, "FEE_DRIFT");
  const artifact = JSON.parse(fs.readFileSync(path.join(build.encoderBuildDir, "artifact.json")));
  const covenantScript = covenantSigscript(callHex, Buffer.from(artifact.script));
  const json = JSON.parse(build.frozenCanonicalJson);
  build.inputLayout.forEach((role, i) => {
    switch (role) {
      case "controller":
        json.inputs[i].signatureScript = covenantScript;
        break;
      case "token":
      case "tokenLeader":
        json.inputs[i].signatureScript = build.tokenSignatureScriptHex;
        break;
      case "tokenDelegate":
        json.inputs[i].signatureScript = build.poolNoteSignatureScriptHex;
        break;
      case "pool":
        json.inputs[i].signatureScript = build.poolSignatureScriptHex;
        break;
      case "fuel":
        if (typeof fuelSignatureScriptHex !== "string" || !/^[0-9a-f]+$/.test(fuelSignatureScriptHex) || fuelSignatureScriptHex.length / 2 !== ORDINARY_SIGSCRIPT_LEN) fail(`fuel signature script must be exactly ${ORDINARY_SIGSCRIPT_LEN} bytes`);
        json.inputs[i].signatureScript = fuelSignatureScriptHex;
        break;
      default:
        fail(`unknown input role ${role}`);
    }
  });
  if (!build.hasFuelInput && fuelSignatureScriptHex !== undefined) fail("this build has no fuel input — do not supply a fuel signature");
  return Object.freeze({ txId: build.txId, requiredFeeSompi: build.requiredFeeSompi, finalTransaction: json, covenantCallHex: callHex });
}

/* GENESIS: ordinary funding inputs -> [controller output holding feeReserve + swapPrincipal, change]. */
function buildCreateV6({ config, templateInput, initialStateInput, funding, changeXOnly, contractVersion, descriptor }) {
  const abi = resolveV6Abi(contractVersion ?? CONTRACT_VERSION_V6);
  const template = normalizeTemplateV6(templateInput);
  const state = normalizeStateV6(initialStateInput);
  if (state.policyNonce !== 0n) fail("a v0.6 genesis state must carry policyNonce 0");
  if (state.paused !== 0n) fail("a v0.6 genesis state must start unpaused");
  if (descriptor !== undefined && assets.computeDescriptorHash(descriptor) !== template.descriptorHash) fail("descriptor hash != template.descriptorHash — failing closed", "DESCRIPTOR_PIN_MISMATCH");
  if (!Array.isArray(funding) || funding.length === 0) fail("funding must be a non-empty array of ordinary UTXOs ({ outpoint, amount, scriptPublicKeyHex })");
  const fundingInputs = funding.map((f, i) => {
    const spk = String(f.scriptPublicKeyHex ?? "").toLowerCase();
    if (!/^[0-9a-f]+$/.test(spk) || spk.length % 2 !== 0) fail(`funding[${i}].scriptPublicKeyHex must be hex`);
    return { outpoint: normalizeOutpoint(f.outpoint, `funding[${i}].outpoint`), amount: parsePositiveSompi(f.amount, `funding[${i}].amount`), scriptPublicKeyHex: spk };
  });
  const change = normalizeHex(changeXOnly, 32, "changeXOnly");
  const compiled = compileExactStateV6({ config, template, state, contractVersion: abi.version });
  const stateId = computeStateIdV6({ networkId: config.networkId, template, state, contractVersion: abi.version });
  const { loadKaspa } = require("./chain");
  const kaspa = loadKaspa(config);
  const spkHex = String(kaspa.payToScriptHashScript(compiled.scriptBytes.toString("hex")).script).toLowerCase();
  const value = controllerValueV6(state);
  const outputs = [{ value, scriptPublicKey: { version: 0, scriptHex: spkHex }, covenant: null }, { value: 1n, scriptPublicKey: { version: 0, scriptHex: p2pkScriptHex(change) }, covenant: null }];
  const unbound = new kaspa.TransactionOutput(value, kaspa.payToScriptHashScript(compiled.scriptBytes.toString("hex")));
  const genesisCovenantId = kaspa.covenantId({ transactionId: fundingInputs[0].outpoint.transactionId, index: fundingInputs[0].outpoint.index }, [{ index: 0, output: unbound }]).toString().toLowerCase();
  outputs[0] = { ...outputs[0], covenant: { authorizingInput: 0, covenantId: genesisCovenantId } };
  const inputs = fundingInputs.map((f) => ({ previousOutpoint: f.outpoint, sequence: 0n, computeBudget: V6_BUDGET.ORDINARY_INPUT, utxo: { amount: f.amount, scriptPublicKey: { version: 0, scriptHex: f.scriptPublicKeyHex }, covenantId: null, blockDaaScore: 0n } }));
  const draft = { version: 1, inputs, outputs, lockTime: 0n, subnetworkId: "00".repeat(20), gas: 0n, payload: "" };
  const requiredFee = exactFee(draft, inputs.map(() => ORDINARY_SIGSCRIPT_LEN));
  const totalFunding = fundingInputs.reduce((s, f) => s + f.amount, 0n);
  const changeValue = totalFunding - value - requiredFee;
  if (changeValue <= 0n) fail(`funding ${totalFunding} cannot cover feeReserve + swapPrincipal ${value} + fee ${requiredFee}`, "INSUFFICIENT_FUEL");
  outputs[1] = { ...outputs[1], value: changeValue };
  const frozen = normalizeFrozenTxV3({ ...draft, outputs });
  assertStorageMassWithinLimit(frozen, "policyvault-0.6 builder");
  const described = describeFrozenTx(frozen);
  return deepFreeze({
    kind: "genesis",
    contractVersion: abi.version,
    networkId: config.networkId,
    action: "createTokenController",
    template,
    initialState: stateToJsonV6(state),
    stateId,
    controllerOutputIndex: 0,
    changeIndex: 1,
    covenantId: genesisCovenantId,
    scriptSha256: compiled.scriptSha256,
    controllerScriptHex: compiled.scriptHex,
    accounting: Object.freeze({ kas: Object.freeze({ feeReserve: state.feeReserve.toString(), swapPrincipal: state.swapPrincipal.toString(), controllerValue: value.toString() }), token: Object.freeze({ positionBefore: "0", positionAfter: "0" }) }),
    frozen,
    frozenCanonicalJson: canonicalFrozenTxJson(frozen),
    txId: described.txId,
    requiredFeeSompi: requiredFee.toString(),
    encoderBuildDir: compiled.buildDir
  });
}

/*
 * TOKEN DEPOSIT into a v0.6 controller — identical family mechanics to v0.5
 * (the controller is not an input; the user's signature authorizes the
 * family leader). The v0.5 builder is reused byte-for-byte; only the
 * contract-version label of the build changes so manifests never conflate
 * the lineages. Also used, with the pool's covenant id as `controller`, to
 * seed a fixture pool's reserve note in the live proof.
 */
function buildTokenDepositV6(args) {
  const build = buildTokenDepositV5(args);
  return deepFreeze({ ...build, contractVersion: CONTRACT_VERSION_V6, depositMechanics: "policyvault-0.5" });
}
function finalizeTokenDepositV6(args) {
  return finalizeTokenDepositV5(args);
}

module.exports = {
  buildV6Transaction,
  buildCreateV6,
  finalizeV6Transaction,
  buildTokenDepositV6,
  finalizeTokenDepositV6,
  successorCallJsonV6,
  FRESHNESS_STATEMENT,
  OWNER_CONTROL_ACTIONS,
  SPEND_ACTIONS,
  SWAP_ACTIONS,
  OWNER_OP_SELECTOR_V6
};
