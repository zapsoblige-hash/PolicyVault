"use strict";
const { ownGet } = require("../../core/model/own-get");

/*
 * PolicyVault v0.7 ROOTED HIERARCHICAL DELEGATION vault transaction builders
 * (contracts/PolicyVault.v0.7-payment-hd.sil, contract
 * `PolicyVaultRootedTokenHD`, tools/gen_v7_payment_hd.js).
 *
 * Wave 2 Track D, gate I2 — the SDK builder layer around the production-byte
 * `policyvault-0.7-payment-hd` pv_call_encoder arm (already VM-proven by
 * tests/vm/tests/v7_hd_production.rs). This is a NEW candidate module, NOT a
 * modification of contracts/PolicyVault.v0.7-payment.sil /
 * sdk/src/vault-builders-v7.js (never edited — see the header of that file
 * and CLAUDE.md's production-byte rule).
 *
 * SAME hard rules as every prior builder generation: BUILDERS NEVER
 * BROADCAST; the frozen transaction is the security object; the exact fee is
 * computed from the final byte shape; the production `pv_call_encoder`
 * produces every covenant-call byte; any drift between planned and final
 * bytes fails closed (FEE_DRIFT).
 *
 * REUSE, NOT REIMPLEMENTATION, per the design-freeze implementation contract
 * and this wave's task packet:
 *   - the vault's live-state TEMPLATE/STATE shape is byte-identical to
 *     v0.7-payment's, so normalizeTemplateV7/normalizeStateV7/
 *     normalizeStateV7ForRecovery/stateToJsonV7 (core/model/vault-state-v7.js)
 *     are reused UNCHANGED — those functions do not gate on contractVersion;
 *   - the OWNER OPERATIONS (ownerControl 0..4 / ownerRecover) are
 *     BYTE-IDENTICAL to v0.7-payment's, so ownerOpSuccessorV7/recoverPlanV7
 *     (core/model/vault-transitions-v7.js) and the compute-budget model for
 *     those operations (core/model/compute-budget-v7.js) are reused
 *     UNCHANGED;
 *   - the ORGANIZATIONAL ROOT side of an owner operation (the root's own
 *     transition math, M-of-N signature-blob assembly, and standalone root
 *     governance) reuses core/model/vault-transitions-v7-root.js +
 *     core/model/owner-set-v7.js directly, and this module RE-EXPORTS
 *     sdk/src/vault-builders-v7.js's `buildCreateV7Root` /
 *     `buildV7RootTransaction` / `finalizeV7RootTransaction` /
 *     `resolveRootActionV7` unchanged rather than rebuilding them — a
 *     rooted HD vault's owner authority is the SAME organizational root a
 *     rooted payment vault uses;
 *   - TOKEN DEPOSIT never touches the vault covenant at all (only its
 *     covenantId + template), so `buildTokenDepositV7` /
 *     `finalizeTokenDepositV7` are re-exported unchanged;
 *   - the HD leaf/tree math (encode/hash/fold/chain proofs/effective
 *     authority/nested refold) is core/model/hd-leaf-v7.js, never restated
 *     here;
 *   - the compute budget for the five HD entrypoints is
 *     core/model/compute-budget-v7-hd.js (selectHdComputeBudgetV7).
 *
 * WHAT IS NEW HERE: the vault-side compile path for the NEW contractVersion
 * `policyvault-0.7-payment-hd` (sdk/src/contract-compiler-v7.js's additive
 * `compileExactStateV7Hd`), and the five HD entrypoints' own call-argument
 * shapes (hdSpend / childSpendL2 / childSpendL3 / delegateSetChildRoot1 /
 * delegateSetChildRoot2), which do not exist anywhere else.
 *
 * SIMPLIFICATIONS relative to sdk/src/vault-builders-v7.js's tokenAgentSpend
 * builder, recorded honestly (never claimed proven beyond what is built):
 *   - an HD spend ALWAYS takes its network fee from an ordinary fuel UTXO
 *     (chain.fuel is required); the reserve-funded fixed-point fee mode
 *     v0.7-payment's delegate path supports is NOT implemented here;
 *   - a delegation op never moves the fee reserve or rides a token position
 *     in the same transaction (the VM suite's `dscTokensRide` stress
 *     variant is a real-engine-only probe, not a product requirement here).
 *
 * Status: IMPLEMENTED (SDK). Production-byte proof: sdk/tools/gen-v7-hd-vectors.js
 * + tests/vm/tests/v7_hd_sdk_integration.rs execute every built shape on the
 * real engine. NOT covenant-byte-frozen, NOT production, NOT authorized for
 * mainnet use.
 */

const fs = require("fs");
const path = require("path");

const { parseSompi, parsePositiveSompi } = require("./amounts");
const { normalizeHex, normalizeXOnlyPubkey } = require("./vault-state");
const { normalizeTemplateV7, normalizeStateV7, normalizeStateV7ForRecovery, stateToJsonV7, resolveOwnerOpAuthorityV7 } = require("../../core/model/vault-state-v7");
const { normalizeRootTemplateV7, normalizeRootStateV7 } = require("../../core/model/vault-state-v7-root");
const { rootTransitionV7, assertRootValueRuleV7 } = require("../../core/model/vault-transitions-v7-root");
const { ownerOpSuccessorV7, recoverPlanV7 } = require("../../core/model/vault-transitions-v7");
const { OWNER_SLOTS_V7, SIG_BLOB_LEN_V7, assembleOwnerSigsBlobV7, placeholderOwnerSigsBlobV7, normalizeSlotSignatureHex } = require("../../core/model/owner-set-v7");
const { V7_BUDGET, selectRootComputeBudgetV7, selectTokenInputBudgetV7 } = require("../../core/model/compute-budget-v7");
const { selectHdComputeBudgetV7, selectHdOwnerComputeBudgetV7 } = require("../../core/model/compute-budget-v7-hd");
const hd = require("../../core/model/hd-leaf-v7");
const { buildRecipientTree, generateRecipientProof, verifyRecipientProof } = require("./recipient-merkle-v3");
const { compileExactStateV7Hd, compileExactStateV7Root, CONTRACT_VERSION_V7_HD } = require("./contract-compiler-v7");
const { normalizeFrozenTxV3, describeFrozenTx, feeDescriptorFromFrozen, canonicalFrozenTxJson } = require("./frozen-tx-v3");
const { calculateRequiredFee } = require("./fee-mass");
const { covenantSigscript } = require("./spend-vault");
const { p2pkScriptHex } = require("./approval-package-v4");
const { runEncoderV4, PLACEHOLDER_SIG_HEX, MAX_TX_FEE_IO } = require("./vault-builders-v4");
const { encodeTokenTransfer } = require("./vault-builders-v5");
const assets = require("../../core/assets");
const { verifiedTokenPosition, compileKcc20Program } = require("./token-program-kcc20");
const { assertStorageMassWithinLimit } = require("./storage-mass-preflight");
const {
  buildCreateV7Root,
  buildV7RootTransaction,
  finalizeV7RootTransaction,
  buildTokenDepositV7,
  finalizeTokenDepositV7,
  successorCallJsonV7,
  rootSuccessorCallJsonV7,
  resolveRootActionV7
} = require("./vault-builders-v7");

const ORDINARY_SIGSCRIPT_LEN = 66;
const HD_SPEND_LEVEL = Object.freeze({ hdSpend: 1, childSpendL2: 2, childSpendL3: 3 });
const HD_DELEGATION_LEVEL = Object.freeze({ delegateSetChildRoot1: 1, delegateSetChildRoot2: 2 });
const OWNER_CONTROL_ACTIONS_V7_HD = new Set(["ownerSetAgentRoot", "ownerTopUpReserve", "ownerPause", "ownerUnpause", "ownerEmergencyPause"]);

function fail(message, code) {
  const e = new Error(`vault-builders-v7-hd: ${message}`);
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

function kcc20StateJson(s) {
  return { ownerIdentifier: s.ownerIdentifier, identifierType: s.identifierType, amount: s.amount.toString(), isMinter: s.isMinter };
}

function extractSchnorr65(signatureHex, label) {
  if (typeof signatureHex !== "string" || !/^[0-9a-f]+$/.test(signatureHex)) fail(`${label} must be lowercase hex`, "SIGNATURE_INVALID");
  let sig = signatureHex;
  if (sig.length === 132 && sig.startsWith("41")) sig = sig.slice(2);
  if (sig.length !== 130) fail(`${label} has unexpected length ${sig.length / 2} bytes (need 65)`, "SIGNATURE_INVALID");
  if (!sig.endsWith("01")) fail(`${label} sighash byte 0x${sig.slice(-2)} != 0x01 — PolicyVault signs SIG_HASH_ALL only`, "SIGHASH_NOT_ALL");
  return sig;
}

/* ------------------------------------------------------------------ */
/* HD chain resolution (shared by spend + delegation builders)          */
/* ------------------------------------------------------------------ */

/*
 * Resolve the presented ancestor chain against the LIVE agentRoot.
 * `params.tree` (level-1 forest, hd-leaf-v7 tree format `{leaf, kids}`) +
 * `params.path` (child index per level) is the primary mode: the whole tree
 * is supplied, the SDK reproduces `agentRoot` from it (refusing to build on
 * a mismatch) and derives the exact co-path proof at every level. The
 * alternate `params.chain` mode accepts an ALREADY-COMPUTED chain (one
 * `{leaf, siblingsHex, pathBits, level}` per level, oldest ancestor first)
 * for callers who keep proofs out of band; the SDK independently refolds it
 * to confirm it reproduces `agentRoot` before ever asking for a signature.
 * NEITHER mode is the security boundary — the covenant re-derives and
 * enforces membership independently from the proven leaves at spend time.
 */
function resolveHdChain(state, params, maxLevel) {
  if (params.tree !== undefined && params.path !== undefined) {
    if (!Array.isArray(params.path) || params.path.length !== maxLevel) fail(`params.path must have exactly ${maxLevel} entries for this entrypoint`, "LEVEL_OUT_OF_RANGE");
    const root = hd.forestRoot(params.tree);
    if (root !== state.agentRoot) fail("the supplied tree does not reproduce the live agentRoot — refusing to build", "AGENT_ROOT_MISMATCH");
    return hd.chainProofs(params.tree, params.path);
  }
  if (params.chain !== undefined) {
    if (!Array.isArray(params.chain) || params.chain.length !== maxLevel) fail(`params.chain must carry exactly ${maxLevel} ancestor level(s) for this entrypoint`, "LEVEL_OUT_OF_RANGE");
    const chain = params.chain.map((entry, i) => ({ leaf: hd.normalizeHdLeaf(entry.leaf), siblingsHex: String(entry.siblingsHex ?? "").toLowerCase(), pathBits: typeof entry.pathBits === "bigint" ? entry.pathBits : BigInt(entry.pathBits), level: entry.level ?? i + 1 }));
    let carriedHex = null;
    for (let i = chain.length - 1; i >= 0; i--) {
      const entry = chain[i];
      if (entry.level !== i + 1) fail(`params.chain[${i}].level ${entry.level} does not match its chain position ${i + 1}`, "LEVEL_OUT_OF_RANGE");
      const maxDepth = entry.level === 1 ? hd.MAX_AGENT_DEPTH : hd.MAX_CHILD_DEPTH;
      carriedHex = hd.foldHdLeafHex(hd.hdLeafHash(entry.leaf, entry.level), entry.siblingsHex, entry.pathBits, maxDepth);
      if (carriedHex === null) fail(`internal: the fold at level ${entry.level} did not fully consume pathBits`);
    }
    if (carriedHex !== state.agentRoot) fail("the supplied chain does not fold to the live agentRoot — refusing to build", "AGENT_ROOT_MISMATCH");
    return chain;
  }
  fail("requires either params.tree + params.path (full level-1 forest) or params.chain (a precomputed ancestor proof)", "CHAIN_REQUIRED");
  return null;
}

function resolveRecipientProofsByLevel(chain, recipientXOnly, params) {
  if (Array.isArray(params.recipientProofsByLevel)) {
    if (params.recipientProofsByLevel.length !== chain.length) fail("params.recipientProofsByLevel must carry exactly one entry per chain level");
    return chain.map((entry, i) => {
      const p = params.recipientProofsByLevel[i];
      const siblingsHex = String(p.siblingsHex ?? "").toLowerCase();
      const pathBits = typeof p.pathBits === "bigint" ? p.pathBits : BigInt(p.pathBits);
      if (!verifyRecipientProof({ root: entry.leaf.recipientRoot, recipient: recipientXOnly, siblingsHex, pathBits })) fail(`recipient proof at level ${i + 1} does not verify under that level's recipientRoot`, "RECIPIENT_PROOF_INVALID");
      return { siblingsHex, pathBits };
    });
  }
  if (Array.isArray(params.recipientListsByLevel)) {
    if (params.recipientListsByLevel.length !== chain.length) fail("params.recipientListsByLevel must carry exactly one entry per chain level");
    return chain.map((entry, i) => {
      const tree = buildRecipientTree(params.recipientListsByLevel[i]);
      if (tree.root !== entry.leaf.recipientRoot) fail(`the supplied recipient list at level ${i + 1} does not reproduce that level's recipientRoot — refusing to build`, "RECIPIENT_ROOT_MISMATCH");
      const proof = generateRecipientProof(tree, recipientXOnly);
      return { siblingsHex: proof.siblingsHex, pathBits: BigInt(proof.pathBits) };
    });
  }
  return fail("requires either params.recipientProofsByLevel or params.recipientListsByLevel (one entry per chain level)");
}

function resolveTokenPositionV7Hd({ config, descriptor, templateIndex, position, covenantId, template }) {
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

/* ------------------------------------------------------------------ */
/* GENESIS of a rooted HD vault                                         */
/* ------------------------------------------------------------------ */

function buildCreateV7HdVault({ config, templateInput, initialStateInput, funding, changeXOnly, descriptor }) {
  const template = normalizeTemplateV7(templateInput);
  const state = normalizeStateV7(initialStateInput);
  if (state.policyNonce !== 0n) fail("a v0.7-payment-hd genesis state must carry policyNonce 0");
  if (state.paused !== 0n) fail("a v0.7-payment-hd genesis state must start unpaused");
  if (descriptor !== undefined && assets.computeDescriptorHash(descriptor) !== template.descriptorHash) fail("descriptor hash != template.descriptorHash — failing closed", "DESCRIPTOR_PIN_MISMATCH");
  if (!Array.isArray(funding) || funding.length === 0) fail("funding must be a non-empty array of ordinary UTXOs ({ outpoint, amount, scriptPublicKeyHex })");
  const fundingInputs = funding.map((f, i) => {
    const spk = String(f.scriptPublicKeyHex ?? "").toLowerCase();
    if (!/^[0-9a-f]+$/.test(spk) || spk.length % 2 !== 0) fail(`funding[${i}].scriptPublicKeyHex must be hex`);
    return { outpoint: normalizeOutpoint(f.outpoint, `funding[${i}].outpoint`), amount: parsePositiveSompi(f.amount, `funding[${i}].amount`), scriptPublicKeyHex: spk };
  });
  const change = normalizeHex(changeXOnly, 32, "changeXOnly");
  const compiled = compileExactStateV7Hd({ config, template, state });
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
  assertStorageMassWithinLimit(frozen, "policyvault-0.7-payment-hd builder");
  const described = describeFrozenTx(frozen);
  return deepFreeze({
    kind: "hdGenesis",
    contractVersion: CONTRACT_VERSION_V7_HD,
    networkId: config.networkId,
    action: "createRootedHdVault",
    template,
    initialState: stateToJsonV7(state),
    stateId: compiled.stateId,
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
/* HD SPEND (hdSpend / childSpendL2 / childSpendL3) — never touches root */
/* ------------------------------------------------------------------ */

function buildHdSpendTransaction({ config, templateInput, stateInput, action, params = {}, chain, changeXOnly, descriptor, templateIndex = 0 }) {
  const level = ownGet(HD_SPEND_LEVEL, action); // own-property only (F-05)
  if (!level) fail(`unknown HD spend action ${JSON.stringify(action)} — failing closed`, "UNKNOWN_ACTION");
  const template = normalizeTemplateV7(templateInput);
  const state = normalizeStateV7(stateInput);
  if (state.paused !== 0n) fail("a spend is refused while the vault is paused (mirrors the covenant's prevState.paused == 0 check)", "PAUSED");

  const predecessorOutpoint = normalizeOutpoint(chain?.predecessorOutpoint, "chain.predecessorOutpoint");
  const covenantId = normalizeHex(chain?.covenantId, 32, "chain.covenantId");
  const predecessorValue = parseSompi(chain?.predecessorValue, "chain.predecessorValue");
  if (predecessorValue !== state.feeReserve) fail(`chain.predecessorValue ${predecessorValue} != state.feeReserve ${state.feeReserve} — stale or inconsistent state`, "STALE");
  const change = normalizeHex(changeXOnly, 32, "changeXOnly");
  if (chain?.root !== undefined && chain?.root !== null) fail("an HD spend never touches the organizational root — refusing to build a root input into a spend transaction", "SPEND_PATH_TAKES_NO_ROOT");
  if (descriptor === undefined) fail(`${action} requires the accepted asset descriptor`, "DESCRIPTOR_REQUIRED");
  const fuel = normalizeFuel(chain?.fuel);

  const position = resolveTokenPositionV7Hd({ config, descriptor, templateIndex, position: chain?.tokenPosition, covenantId, template });
  const hdChain = resolveHdChain(state, params, level);
  const recipient = normalizeHex(params.recipient, 32, "params.recipient");
  const recipProofs = resolveRecipientProofsByLevel(hdChain, recipient, params);
  const periodsElapsedByLevel = Array.isArray(params.periodsElapsedByLevel) ? params.periodsElapsedByLevel.map((v) => (typeof v === "bigint" ? v : BigInt(v))) : hdChain.map(() => 0n);
  if (periodsElapsedByLevel.length !== hdChain.length) fail("params.periodsElapsedByLevel must carry exactly one entry per chain level");

  const spendAmount = assets.kcc20.parseAtomicAmount(params.spendAmount, "spendAmount");
  if (spendAmount <= 0n) fail("spendAmount must be > 0", "ZERO_SPEND");
  const recipientCarry = parseSompi(params.recipientCarryKasSompi, "recipientCarryKasSompi");
  if (recipientCarry >= position.value) fail("recipient carry KAS must leave the token position with KAS", "CARRY_TOO_LARGE");
  const selfCarry = position.value - recipientCarry;
  const reserveConsumed = parseSompi(params.reserveConsumedSompi ?? 0n, "reserveConsumedSompi");

  /* PRE-SIGN ENFORCEMENT of the whole ancestor intersection (the covenant
   * re-derives and enforces the same rules in-VM; the SDK refuses FIRST so a
   * signature is never spent on a transaction consensus would refuse) */
  {
    const positions = hd.verifyChainPositions(hdChain);
    if (positions && positions.ok === false) fail(`ancestor chain positions are inconsistent at level ${positions.level ?? "?"}`, "HD_CHAIN_STALE");
    const expiry = hd.verifyExpiryMonotone(hdChain);
    if (expiry && expiry.ok === false) fail(`expiryDaa is not monotone descending the chain (level ${expiry.level ?? "?"}) — expiry is a consistency rule enforced by the core and by revocation, not by consensus`, "EXPIRY_INVERSION");
    const guard = hd.verifySpendWithinEffectiveAuthority(hdChain, { amount: spendAmount, feeSompi: reserveConsumed, carrySompi: recipientCarry, periodsElapsedByLevel });
    if (!guard.ok) {
      const v = guard.violations;
      const code = v.some((x) => x.startsWith("periodBudget")) ? "OVER_BUDGET" : v.includes("maxPerSpend") ? "OVER_CAP" : v.includes("maxFeePerTx") ? "OVER_AGENT_FEE_CAP" : "OVER_CARRY_CAP";
      fail(`${action}: spend exceeds the effective authority of the ancestor chain (${v.join(", ")}) — AUTHORITY MAY NEVER INCREASE DESCENDING`, code);
    }
  }
  const newRoot = hd.nestedRefoldAfterSpend(hdChain, spendAmount, periodsElapsedByLevel);
  const successorReserve = state.feeReserve - reserveConsumed;
  if (successorReserve < 0n) fail("reserveConsumedSompi exceeds the live feeReserve", "RESERVE_UNDERFLOW");
  const successor = Object.freeze({ feeReserve: successorReserve, paused: state.paused, agentRoot: newRoot, policyNonce: state.policyNonce });

  const current = compileExactStateV7Hd({ config, template, state });
  const next = compileExactStateV7Hd({ config, template, state: successor });
  const currentSpkHex = p2shOf(config, current.scriptBytes);
  const encoderPaths = { sourcePath: path.join(current.buildDir, "PolicyVault.state.sil"), constructorArgsPath: path.join(current.buildDir, "constructor-args.json") };

  const selfAfter = position.program.state.amount - spendAmount;
  if (selfAfter < 0n) fail("spendAmount exceeds the token position amount", "INSUFFICIENT_TOKENS");
  const selfNew = { ownerIdentifier: covenantId, identifierType: assets.kcc20.OWNER_SCHEMES.COVENANT_ID, amount: selfAfter, isMinter: false };
  const recipientNew = { ownerIdentifier: recipient, identifierType: assets.kcc20.OWNER_SCHEMES.P2PK, amount: spendAmount, isMinter: false };
  const selfProgram = compileKcc20Program({ config, state: selfNew, familyBound: position.program.familyBound });
  const recipientProgram = compileKcc20Program({ config, state: recipientNew, familyBound: position.program.familyBound });

  const chainCallJson = hdChain.map((entry, i) => ({
    leaf: hd.encodeHdLeafBodyHex(entry.leaf),
    siblings: entry.siblingsHex,
    pathBits: Number(entry.pathBits),
    periodsElapsed: Number(periodsElapsedByLevel[i]),
    recipientSiblings: recipProofs[i].siblingsHex,
    recipientPathBits: Number(recipProofs[i].pathBits)
  }));
  const placeholderCall = { function: action, successor: successorCallJsonV7(stateToJsonV7(successor)), selfNew: kcc20StateJson(selfNew), recipientNew: kcc20StateJson(recipientNew), chain: chainCallJson, recipientPk: recipient, signature: PLACEHOLDER_SIG_HEX };
  const callHex = runEncoderV4({ ...encoderPaths, call: placeholderCall, contractVersion: CONTRACT_VERSION_V7_HD });
  const covenantSigscriptLen = covenantSigscript(callHex, current.scriptBytes).length / 2;
  const tokenCallHex = encodeTokenTransfer({ program: position.program, newStates: [selfNew, recipientNew], witnessesHex: "00" });
  const tokenSigscriptHex = covenantSigscript(tokenCallHex, Buffer.from(position.program.scriptHex, "hex"));

  const budget = selectHdComputeBudgetV7({ operation: action, atMaxDepth: params.atMaxDepth !== false });
  const inputs = [
    { previousOutpoint: predecessorOutpoint, sequence: 0n, computeBudget: budget, utxo: { amount: predecessorValue, scriptPublicKey: { version: 0, scriptHex: currentSpkHex }, covenantId, blockDaaScore: 0n } },
    { previousOutpoint: position.outpoint, sequence: 0n, computeBudget: selectTokenInputBudgetV7({ templatePrefixLen: template.templatePrefixLen, templateSuffixLen: template.templateSuffixLen }), utxo: { amount: position.value, scriptPublicKey: { version: 0, scriptHex: position.scriptPublicKeyHex }, covenantId: position.covenantId, blockDaaScore: 0n } },
    { previousOutpoint: fuel.outpoint, sequence: 0n, computeBudget: V7_BUDGET.ORDINARY_INPUT, utxo: { amount: fuel.amount, scriptPublicKey: { version: 0, scriptHex: fuel.scriptPublicKeyHex }, covenantId: null, blockDaaScore: 0n } }
  ];
  const sigLens = [covenantSigscriptLen, tokenSigscriptHex.length / 2, ORDINARY_SIGSCRIPT_LEN];
  const outputs = [
    { value: successorReserve, scriptPublicKey: { version: 0, scriptHex: p2shOf(config, next.scriptBytes) }, covenant: { authorizingInput: 0, covenantId } },
    { value: selfCarry, scriptPublicKey: { version: 0, scriptHex: selfProgram.p2shSpkHex }, covenant: { authorizingInput: 1, covenantId: position.covenantId } },
    { value: recipientCarry, scriptPublicKey: { version: 0, scriptHex: recipientProgram.p2shSpkHex }, covenant: { authorizingInput: 1, covenantId: position.covenantId } },
    { value: 1n, scriptPublicKey: { version: 0, scriptHex: p2pkScriptHex(change) }, covenant: null }
  ];
  const draft = { version: 1, inputs, outputs, lockTime: parseSompi(params.lockTime ?? 0n, "lockTime"), subnetworkId: "00".repeat(20), gas: 0n, payload: "" };
  const fee = exactFee(draft, sigLens);
  const changeValue = fuel.amount - fee;
  if (changeValue <= 0n) fail(`fuel ${fuel.amount} cannot cover fee ${fee}`, "INSUFFICIENT_FUEL");
  outputs[3] = { ...outputs[3], value: changeValue };

  if (draft.inputs.length > MAX_TX_FEE_IO || outputs.length > MAX_TX_FEE_IO) fail(`transaction shape exceeds the covenant fee-introspection bound of ${MAX_TX_FEE_IO} inputs/outputs`);
  const frozen = normalizeFrozenTxV3({ ...draft, outputs });
  assertStorageMassWithinLimit(frozen, "policyvault-0.7-payment-hd builder");
  const described = describeFrozenTx(frozen);
  const totalIn = frozen.inputs.reduce((s, i) => s + i.utxo.amount, 0n);
  const totalOut = frozen.outputs.reduce((s, o) => s + o.value, 0n);
  if (totalIn - totalOut !== fee) fail("internal: realized fee != required fee");

  return deepFreeze({
    kind: "hdTransition",
    contractVersion: CONTRACT_VERSION_V7_HD,
    encoderFunction: action,
    networkId: config.networkId,
    action,
    role: "delegate",
    level,
    template,
    predecessorOutpoint,
    predecessorStateId: current.stateId,
    covenantId,
    stateJson: stateToJsonV7(state),
    successorState: stateToJsonV7(successor),
    successorStateId: next.stateId,
    successorScriptSha256: next.scriptSha256,
    ancestorChain: Object.freeze(hdChain.map((entry, i) => Object.freeze({ level: entry.level, leaf: hd.hdLeafToJson(entry.leaf), siblingsHex: entry.siblingsHex, pathBits: entry.pathBits.toString(), periodsElapsed: periodsElapsedByLevel[i].toString(), recipientSiblingsHex: recipProofs[i].siblingsHex, recipientPathBits: recipProofs[i].pathBits.toString() }))),
    effectiveAuthority: (() => {
      const eff = hd.effectiveAuthority(hdChain);
      return Object.freeze({ level: eff.level, maxPerSpend: eff.maxPerSpend.toString(), maxFeePerTx: eff.maxFeePerTx.toString(), maxCarryKas: eff.maxCarryKas.toString(), expiryDaa: eff.expiryDaa.toString(), expiryIsNotConsensusEnforced: eff.expiryIsNotConsensusEnforced });
    })(),
    asset: Object.freeze({ descriptorHash: position.descriptorHash, assetId: position.descriptor.assetId, tokenCovenantId: position.covenantId, templateVmHashBlake2b256: position.program.templateVmHashBlake2b256, familyBound: position.program.familyBound, templateIndex, issuerPowers: position.descriptor.issuerPowers, displayName: position.descriptor.displayName, decimalsDisplay: position.descriptor.decimalsDisplay }),
    accounting: Object.freeze({
      token: Object.freeze({ positionBefore: position.program.state.amount.toString(), spendAmount: spendAmount.toString(), positionAfter: selfAfter.toString(), recipient }),
      kas: Object.freeze({ predecessorFeeReserve: state.feeReserve.toString(), reserveConsumed: reserveConsumed.toString(), successorFeeReserve: successorReserve.toString(), externalIn: fuel.amount.toString(), externalOut: changeValue.toString(), tokenInputKas: position.value.toString(), tokenSelfCarryKas: selfCarry.toString(), tokenRecipientCarryKas: recipientCarry.toString(), fee: fee.toString() })
    }),
    frozen,
    frozenCanonicalJson: canonicalFrozenTxJson(frozen),
    txId: described.txId,
    covenantSighash: described.sighashAll[0],
    computeBudget: budget,
    requiredFeeSompi: fee.toString(),
    encoderBuildDir: current.buildDir,
    plannedCallHexLength: callHex.length,
    hasFuelInput: true,
    hasRootInput: false,
    hasTokenInput: true,
    tokenInputIndex: 1,
    tokenSignatureScriptHex: tokenSigscriptHex,
    recipient,
    templateIndex
  });
}

/* ------------------------------------------------------------------ */
/* DELEGATION (delegateSetChildRoot1 / delegateSetChildRoot2)           */
/* ------------------------------------------------------------------ */

function buildHdDelegationTransaction({ config, templateInput, stateInput, action, params = {}, chain, changeXOnly }) {
  const level = ownGet(HD_DELEGATION_LEVEL, action); // own-property only (F-05)
  if (!level) fail(`unknown HD delegation action ${JSON.stringify(action)} — failing closed`, "UNKNOWN_ACTION");
  const template = normalizeTemplateV7(templateInput);
  const state = normalizeStateV7(stateInput);
  if (state.paused !== 0n) fail("delegation is refused while the vault is paused (mirrors the covenant's prevState.paused == 0 check; a FROZEN root reaches delegation THROUGH this flag via EMERGENCY pause)", "PAUSED");

  const predecessorOutpoint = normalizeOutpoint(chain?.predecessorOutpoint, "chain.predecessorOutpoint");
  const covenantId = normalizeHex(chain?.covenantId, 32, "chain.covenantId");
  const predecessorValue = parseSompi(chain?.predecessorValue, "chain.predecessorValue");
  if (predecessorValue !== state.feeReserve) fail(`chain.predecessorValue ${predecessorValue} != state.feeReserve ${state.feeReserve} — stale or inconsistent state`, "STALE");
  const change = normalizeHex(changeXOnly, 32, "changeXOnly");
  if (chain?.root !== undefined && chain?.root !== null) fail("a delegation never touches the organizational root — refusing to build a root input into a delegation transaction", "DELEGATION_PATH_TAKES_NO_ROOT");
  const fuel = normalizeFuel(chain?.fuel);

  const hdChain = resolveHdChain(state, params, level);
  const newChildRoot = normalizeHex(params.newChildRoot, 32, "params.newChildRoot");
  const check = hd.verifyDelegationOnlyChangesChildRoot(hdChain[level - 1].leaf, { ...hd.normalizeHdLeaf(hdChain[level - 1].leaf), childRoot: newChildRoot });
  if (!check.ok) fail(`internal: the delegation splice unexpectedly touched ${check.violations.join(", ")}`, "DELEGATION_SPLICE_INVALID");

  const newRoot = hd.nestedRefoldAfterDelegation(hdChain, newChildRoot);
  const successor = Object.freeze({ feeReserve: state.feeReserve, paused: state.paused, agentRoot: newRoot, policyNonce: state.policyNonce });

  const current = compileExactStateV7Hd({ config, template, state });
  const next = compileExactStateV7Hd({ config, template, state: successor });
  const currentSpkHex = p2shOf(config, current.scriptBytes);
  const encoderPaths = { sourcePath: path.join(current.buildDir, "PolicyVault.state.sil"), constructorArgsPath: path.join(current.buildDir, "constructor-args.json") };

  const successorJson = successorCallJsonV7(stateToJsonV7(successor));
  const parentLeafHex = hd.encodeHdLeafBodyHex(hdChain[level - 1].leaf);
  let placeholderCall;
  if (level === 1) {
    placeholderCall = { function: action, successor: successorJson, parentLeaf: parentLeafHex, siblings: hdChain[0].siblingsHex, pathBits: Number(hdChain[0].pathBits), newChildRoot, signature: PLACEHOLDER_SIG_HEX };
  } else {
    placeholderCall = {
      function: action,
      successor: successorJson,
      chain: [{ leaf: hd.encodeHdLeafBodyHex(hdChain[0].leaf), siblings: hdChain[0].siblingsHex, pathBits: Number(hdChain[0].pathBits) }],
      parentLeaf: parentLeafHex,
      siblings2: hdChain[1].siblingsHex,
      pathBits2: Number(hdChain[1].pathBits),
      newChildRoot,
      signature: PLACEHOLDER_SIG_HEX
    };
  }
  const callHex = runEncoderV4({ ...encoderPaths, call: placeholderCall, contractVersion: CONTRACT_VERSION_V7_HD });
  const covenantSigscriptLen = covenantSigscript(callHex, current.scriptBytes).length / 2;

  const budget = selectHdComputeBudgetV7({ operation: action, atMaxDepth: params.atMaxDepth !== false });
  const inputs = [
    { previousOutpoint: predecessorOutpoint, sequence: 0n, computeBudget: budget, utxo: { amount: predecessorValue, scriptPublicKey: { version: 0, scriptHex: currentSpkHex }, covenantId, blockDaaScore: 0n } },
    { previousOutpoint: fuel.outpoint, sequence: 0n, computeBudget: V7_BUDGET.ORDINARY_INPUT, utxo: { amount: fuel.amount, scriptPublicKey: { version: 0, scriptHex: fuel.scriptPublicKeyHex }, covenantId: null, blockDaaScore: 0n } }
  ];
  const sigLens = [covenantSigscriptLen, ORDINARY_SIGSCRIPT_LEN];
  const outputs = [
    { value: successor.feeReserve, scriptPublicKey: { version: 0, scriptHex: p2shOf(config, next.scriptBytes) }, covenant: { authorizingInput: 0, covenantId } },
    { value: 1n, scriptPublicKey: { version: 0, scriptHex: p2pkScriptHex(change) }, covenant: null }
  ];
  const draft = { version: 1, inputs, outputs, lockTime: 0n, subnetworkId: "00".repeat(20), gas: 0n, payload: "" };
  const fee = exactFee(draft, sigLens);
  const changeValue = fuel.amount - fee;
  if (changeValue <= 0n) fail(`fuel ${fuel.amount} cannot cover fee ${fee}`, "INSUFFICIENT_FUEL");
  outputs[1] = { ...outputs[1], value: changeValue };

  const frozen = normalizeFrozenTxV3({ ...draft, outputs });
  assertStorageMassWithinLimit(frozen, "policyvault-0.7-payment-hd builder");
  const described = describeFrozenTx(frozen);
  const totalIn = frozen.inputs.reduce((s, i) => s + i.utxo.amount, 0n);
  const totalOut = frozen.outputs.reduce((s, o) => s + o.value, 0n);
  if (totalIn - totalOut !== fee) fail("internal: realized fee != required fee");

  return deepFreeze({
    kind: "hdTransition",
    contractVersion: CONTRACT_VERSION_V7_HD,
    encoderFunction: action,
    networkId: config.networkId,
    action,
    role: "parent",
    level,
    template,
    predecessorOutpoint,
    predecessorStateId: current.stateId,
    covenantId,
    stateJson: stateToJsonV7(state),
    successorState: stateToJsonV7(successor),
    successorStateId: next.stateId,
    successorScriptSha256: next.scriptSha256,
    ancestorChain: Object.freeze(hdChain.map((entry) => Object.freeze({ level: entry.level, leaf: hd.hdLeafToJson(entry.leaf), siblingsHex: entry.siblingsHex, pathBits: entry.pathBits.toString() }))),
    delegatingParentLevel: level,
    newChildRoot,
    asset: null,
    accounting: Object.freeze({ token: Object.freeze({ positionBefore: null, spendAmount: "0", positionAfter: null, recipient: null }), kas: Object.freeze({ predecessorFeeReserve: state.feeReserve.toString(), reserveConsumed: "0", successorFeeReserve: successor.feeReserve.toString(), externalIn: fuel.amount.toString(), externalOut: changeValue.toString(), fee: fee.toString() }) }),
    frozen,
    frozenCanonicalJson: canonicalFrozenTxJson(frozen),
    txId: described.txId,
    covenantSighash: described.sighashAll[0],
    computeBudget: budget,
    requiredFeeSompi: fee.toString(),
    encoderBuildDir: current.buildDir,
    plannedCallHexLength: callHex.length,
    hasFuelInput: true,
    hasRootInput: false,
    hasTokenInput: false,
    tokenInputIndex: null,
    tokenSignatureScriptHex: null
  });
}

/* ------------------------------------------------------------------ */
/* FINALIZE a spend or delegation build (delegate's own signature only) */
/* ------------------------------------------------------------------ */

/* build.ancestorChain leaves were stored via hd.hdLeafToJson (I2 manifest
 * display convenience — see the spend/delegation builders above), which adds
 * the human-readable `expiryIsNotConsensusEnforced` disclaimer field on top
 * of the closed HD leaf layout. Strip it before feeding the leaf back into
 * encodeHdLeafBodyHex, which enforces the closed layout strictly. */
function leafBodyHexFromStoredJson(leafJson) {
  const { expiryIsNotConsensusEnforced, ...leaf } = leafJson;
  void expiryIsNotConsensusEnforced;
  return hd.encodeHdLeafBodyHex(leaf);
}

function finalizeHdTransaction({ build, signatureHex, approvals, fuelSignatureScriptHex }) {
  if (build.kind !== "hdTransition" || build.contractVersion !== CONTRACT_VERSION_V7_HD) fail("finalizeHdTransaction takes a v0.7-payment-hd hdTransition build");
  if (approvals !== undefined && approvals !== null) fail("an HD spend/delegation carries no owner approvals — neither path ever touches the root", "HD_PATH_TAKES_NO_APPROVALS");
  const isSpend = HD_SPEND_LEVEL[build.action] !== undefined;
  const call = { function: build.action, successor: successorCallJsonV7(build.successorState) };
  if (isSpend) {
    call.selfNew = kcc20StateJson({ ownerIdentifier: build.covenantId, identifierType: assets.kcc20.OWNER_SCHEMES.COVENANT_ID, amount: BigInt(build.accounting.token.positionAfter), isMinter: false });
    call.recipientNew = kcc20StateJson({ ownerIdentifier: build.recipient, identifierType: assets.kcc20.OWNER_SCHEMES.P2PK, amount: BigInt(build.accounting.token.spendAmount), isMinter: false });
    call.chain = build.ancestorChain.map((entry) => ({ leaf: leafBodyHexFromStoredJson(entry.leaf), siblings: entry.siblingsHex, pathBits: Number(BigInt(entry.pathBits)), periodsElapsed: Number(BigInt(entry.periodsElapsed)), recipientSiblings: entry.recipientSiblingsHex, recipientPathBits: Number(BigInt(entry.recipientPathBits)) }));
    call.recipientPk = build.recipient;
  } else if (build.level === 1) {
    call.parentLeaf = leafBodyHexFromStoredJson(build.ancestorChain[0].leaf);
    call.siblings = build.ancestorChain[0].siblingsHex;
    call.pathBits = Number(BigInt(build.ancestorChain[0].pathBits));
    call.newChildRoot = build.newChildRoot;
  } else {
    call.chain = [{ leaf: leafBodyHexFromStoredJson(build.ancestorChain[0].leaf), siblings: build.ancestorChain[0].siblingsHex, pathBits: Number(BigInt(build.ancestorChain[0].pathBits)) }];
    call.parentLeaf = leafBodyHexFromStoredJson(build.ancestorChain[1].leaf);
    call.siblings2 = build.ancestorChain[1].siblingsHex;
    call.pathBits2 = Number(BigInt(build.ancestorChain[1].pathBits));
    call.newChildRoot = build.newChildRoot;
  }
  call.signature = extractSchnorr65(signatureHex, isSpend ? "the spending leaf's signature" : "the delegating parent's signature");

  const callHex = runEncoderV4({ sourcePath: path.join(build.encoderBuildDir, "PolicyVault.state.sil"), constructorArgsPath: path.join(build.encoderBuildDir, "constructor-args.json"), call, contractVersion: CONTRACT_VERSION_V7_HD });
  if (callHex.length !== build.plannedCallHexLength) fail(`final covenant call length ${callHex.length / 2} != planned ${build.plannedCallHexLength / 2} — the exact-fee freeze is violated; refusing`, "FEE_DRIFT");
  const artifact = JSON.parse(fs.readFileSync(path.join(build.encoderBuildDir, "artifact.json")));
  const json = JSON.parse(build.frozenCanonicalJson);
  json.inputs[0].signatureScript = covenantSigscript(callHex, Buffer.from(artifact.script));
  if (build.hasTokenInput) json.inputs[build.tokenInputIndex].signatureScript = build.tokenSignatureScriptHex;
  if (typeof fuelSignatureScriptHex !== "string" || !/^[0-9a-f]+$/.test(fuelSignatureScriptHex) || fuelSignatureScriptHex.length / 2 !== ORDINARY_SIGSCRIPT_LEN) fail(`fuel signature script must be exactly ${ORDINARY_SIGSCRIPT_LEN} bytes`);
  json.inputs[json.inputs.length - 1].signatureScript = fuelSignatureScriptHex;
  return Object.freeze({ txId: build.txId, requiredFeeSompi: build.requiredFeeSompi, finalTransaction: json, covenantCallHex: callHex });
}

/* ------------------------------------------------------------------ */
/* ROOTED owner ops + ownerRecover — through the FROZEN root's builders */
/* ------------------------------------------------------------------ */

/*
 * The root side of a rooted HD vault's owner operation. Byte-identical
 * pairing rule to v0.7-payment's (private) `resolveRootSide`: a caller can
 * never choose the root path independently of the vault operation, because
 * that pairing IS the authority model. Reuses the SAME core root-transition
 * primitives (`rootTransitionV7`, `assertRootValueRuleV7`,
 * `compileExactStateV7Root`, `selectRootComputeBudgetV7`) that
 * sdk/src/vault-builders-v7.js's private helper uses, so the root's own
 * math is never restated.
 */
function resolveRootSideHd({ config, action, root }) {
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
  return { authority, template, state, plan, outpoint, covenantId, value, current, next, budget: selectRootComputeBudgetV7({ actionName: authority.rootActionName, activeOwnerSlots: state.activeCount }) };
}

function buildV7HdOwnerTransaction({ config, templateInput, stateInput, action, params = {}, chain, changeXOnly, descriptor, templateIndex = 0 }) {
  if (!OWNER_CONTROL_ACTIONS_V7_HD.has(action) && action !== "ownerRecover") fail(`unknown v0.7-payment-hd owner action ${JSON.stringify(action)} — failing closed`, "UNKNOWN_ACTION");
  const template = normalizeTemplateV7(templateInput);
  const terminal = action === "ownerRecover";
  const state = terminal && params.allowMalformedState === true ? normalizeStateV7ForRecovery(stateInput) : normalizeStateV7(stateInput);

  const predecessorOutpoint = normalizeOutpoint(chain?.predecessorOutpoint, "chain.predecessorOutpoint");
  const covenantId = normalizeHex(chain?.covenantId, 32, "chain.covenantId");
  const predecessorValue = parseSompi(chain?.predecessorValue, "chain.predecessorValue");
  if (predecessorValue !== state.feeReserve) fail(`chain.predecessorValue ${predecessorValue} != state.feeReserve ${state.feeReserve} — stale or inconsistent state`, "STALE");
  const change = normalizeHex(changeXOnly, 32, "changeXOnly");
  const fuel = normalizeFuel(chain?.fuel);
  if (descriptor !== undefined) {
    const dh = assets.computeDescriptorHash(descriptor);
    if (dh !== template.descriptorHash) fail("descriptor hash != the vault's pinned descriptorHash — descriptor substitution/downgrade; failing closed", "DESCRIPTOR_PIN_MISMATCH");
  }

  const current = compileExactStateV7Hd({ config, template, state });
  const currentSpkHex = p2shOf(config, current.scriptBytes);
  const encoderPaths = { sourcePath: path.join(current.buildDir, "PolicyVault.state.sil"), constructorArgsPath: path.join(current.buildDir, "constructor-args.json") };
  const geometry = { templatePrefixLen: template.templatePrefixLen, templateSuffixLen: template.templateSuffixLen, rootPrefixLen: template.rootPrefixLen, rootSuffixLen: template.rootSuffixLen };
  const vaultIn = (budget) => ({ previousOutpoint: predecessorOutpoint, sequence: 0n, computeBudget: budget, utxo: { amount: predecessorValue, scriptPublicKey: { version: 0, scriptHex: currentSpkHex }, covenantId, blockDaaScore: 0n } });
  const fuelIn = () => ({ previousOutpoint: fuel.outpoint, sequence: 0n, computeBudget: V7_BUDGET.ORDINARY_INPUT, utxo: { amount: fuel.amount, scriptPublicKey: { version: 0, scriptHex: fuel.scriptPublicKeyHex }, covenantId: null, blockDaaScore: 0n } });

  const rootSide = resolveRootSideHd({ config, action, root: chain?.root });
  /* the HD candidate's redeem script is ~4.4x v0.7-payment's (five extra HD
   * entrypoints), so the reused v0.7 owner-op budget model alone UNDER-
   * COMMITS — see core/model/compute-budget-v7-hd.js's selectHdOwnerComputeBudgetV7
   * header for the measured correction (gate I2 SDK integration finding). */
  const budget = selectHdOwnerComputeBudgetV7({ operation: action, ...geometry });
  const rootInput = () => ({ previousOutpoint: rootSide.outpoint, sequence: 0n, computeBudget: rootSide.budget, utxo: { amount: rootSide.value, scriptPublicKey: { version: 0, scriptHex: p2shOf(config, rootSide.current.scriptBytes) }, covenantId: rootSide.covenantId, blockDaaScore: 0n } });
  const rootOutput = (authorizingInput) => ({ value: rootSide.value, scriptPublicKey: { version: 0, scriptHex: p2shOf(config, rootSide.next.scriptBytes) }, covenant: { authorizingInput, covenantId: rootSide.covenantId } });

  if (!terminal) {
    const owner = ownerOpSuccessorV7(action, state, params);
    const next = compileExactStateV7Hd({ config, template, state: owner.successor });
    const placeholderCall = { function: "ownerControl", opSelector: owner.opSelector, successor: successorCallJsonV7(stateToJsonV7(owner.successor)) };
    const callHex = runEncoderV4({ ...encoderPaths, call: placeholderCall, contractVersion: CONTRACT_VERSION_V7_HD });
    const covenantSigscriptLen = covenantSigscript(callHex, current.scriptBytes).length / 2;
    const rootCallHex = runEncoderV4({
      sourcePath: path.join(rootSide.current.buildDir, "PolicyVault.state.sil"),
      constructorArgsPath: path.join(rootSide.current.buildDir, "constructor-args.json"),
      call: { function: "rootAction", successor: rootSuccessorCallJsonV7(rootSide.plan.successor), action: rootSide.plan.action, ownerSigs: placeholderOwnerSigsBlobV7() },
      contractVersion: "policyvault-0.7-root"
    });
    const rootSigscriptLen = covenantSigscript(rootCallHex, rootSide.current.scriptBytes).length / 2;
    const inputs = [vaultIn(budget), rootInput(), fuelIn()];
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
    return finishOwnerBuild({ config, action, role: "owners", encoderFunction: "ownerControl", template, state, covenantId, predecessorOutpoint, current, plan: { successor: owner.successor, next, terminal: false, budget, covenantSigscriptLen, plannedCallHexLength: callHex.length, externalFunding: owner.externalFunding }, draft: { ...draft, outputs }, fee, callExtra: { opSelector: owner.opSelector }, rootSide: { ...rootSide, plannedCallHexLength: rootCallHex.length, sigscriptLen: rootSigscriptLen, inputIndex: 1 }, tokenSide: null, fuel, templateIndex });
  }

  /* ---- ownerRecover (TERMINAL) ---- */
  const hasPosition = chain?.tokenPosition !== undefined && chain?.tokenPosition !== null;
  let position = null;
  let recipientProgram = null;
  let tokenSigscriptHex = null;
  let recover;
  if (hasPosition) {
    if (descriptor === undefined) fail("ownerRecover with a token position requires the accepted asset descriptor", "DESCRIPTOR_REQUIRED");
    position = resolveTokenPositionV7Hd({ config, descriptor, templateIndex, position: chain.tokenPosition, covenantId, template });
    recover = recoverPlanV7(state, template, position.program.state.amount);
    recipientProgram = compileKcc20Program({ config, state: recover.tokenRecipient, familyBound: position.program.familyBound });
    const tokenCallHex = encodeTokenTransfer({ program: position.program, newStates: [recover.tokenRecipient], witnessesHex: "00" });
    tokenSigscriptHex = covenantSigscript(tokenCallHex, Buffer.from(position.program.scriptHex, "hex"));
  } else {
    recover = recoverPlanV7(state, template, null);
  }
  const recipientNewJson = recover.tokenRecipient ? kcc20StateJson(recover.tokenRecipient) : { ownerIdentifier: template.recoveryPk, identifierType: 0, amount: "0", isMinter: false };
  const placeholderCall = { function: "ownerRecover", recipientNew: recipientNewJson };
  const callHex = runEncoderV4({ ...encoderPaths, call: placeholderCall, contractVersion: CONTRACT_VERSION_V7_HD });
  const covenantSigscriptLen = covenantSigscript(callHex, current.scriptBytes).length / 2;
  const rootCallHex = runEncoderV4({
    sourcePath: path.join(rootSide.current.buildDir, "PolicyVault.state.sil"),
    constructorArgsPath: path.join(rootSide.current.buildDir, "constructor-args.json"),
    call: { function: "rootAction", successor: rootSuccessorCallJsonV7(rootSide.plan.successor), action: rootSide.plan.action, ownerSigs: placeholderOwnerSigsBlobV7() },
    contractVersion: "policyvault-0.7-root"
  });
  const rootSigscriptLen = covenantSigscript(rootCallHex, rootSide.current.scriptBytes).length / 2;

  const inputs = [vaultIn(budget), rootInput()];
  const sigLens = [covenantSigscriptLen, rootSigscriptLen];
  let tokenInputIndex = null;
  if (position) {
    tokenInputIndex = inputs.length;
    inputs.push({ previousOutpoint: position.outpoint, sequence: 0n, computeBudget: selectTokenInputBudgetV7({ templatePrefixLen: template.templatePrefixLen, templateSuffixLen: template.templateSuffixLen }), utxo: { amount: position.value, scriptPublicKey: { version: 0, scriptHex: position.scriptPublicKeyHex }, covenantId: position.covenantId, blockDaaScore: 0n } });
    sigLens.push(tokenSigscriptHex.length / 2);
  }
  inputs.push(fuelIn());
  sigLens.push(ORDINARY_SIGSCRIPT_LEN);
  const outputs = [{ value: recover.payout, scriptPublicKey: { version: 0, scriptHex: p2pkScriptHex(recover.payoutTo) }, covenant: null }, rootOutput(1)];
  if (position) outputs.push({ value: position.value, scriptPublicKey: { version: 0, scriptHex: recipientProgram.p2shSpkHex }, covenant: { authorizingInput: tokenInputIndex, covenantId: position.covenantId } });
  outputs.push({ value: 1n, scriptPublicKey: { version: 0, scriptHex: p2pkScriptHex(change) }, covenant: null });
  const draft = { version: 1, inputs, outputs, lockTime: 0n, subnetworkId: "00".repeat(20), gas: 0n, payload: "" };
  const fee = exactFee(draft, sigLens);
  const changeValue = fuel.amount - fee;
  if (changeValue <= 0n) fail(`fuel ${fuel.amount} cannot cover fee ${fee}`, "INSUFFICIENT_FUEL");
  outputs[outputs.length - 1] = { ...outputs[outputs.length - 1], value: changeValue };
  return finishOwnerBuild({
    config,
    action,
    role: "owners",
    encoderFunction: "ownerRecover",
    template,
    state,
    covenantId,
    predecessorOutpoint,
    current,
    plan: { successor: null, next: null, terminal: true, budget, covenantSigscriptLen, plannedCallHexLength: callHex.length, externalFunding: 0n, recover },
    draft: { ...draft, outputs },
    fee,
    callExtra: { recipientNew: recipientNewJson },
    rootSide: { ...rootSide, plannedCallHexLength: rootCallHex.length, sigscriptLen: rootSigscriptLen, inputIndex: 1 },
    tokenSide: position ? { position, recover, tokenSigscriptHex } : null,
    fuel,
    templateIndex
  });
}

function finishOwnerBuild({ config, action, role, encoderFunction, template, state, covenantId, predecessorOutpoint, current, plan, draft, fee, callExtra, rootSide, tokenSide, fuel, templateIndex }) {
  if (draft.inputs.length > MAX_TX_FEE_IO || draft.outputs.length > MAX_TX_FEE_IO) fail(`transaction shape exceeds the covenant fee-introspection bound of ${MAX_TX_FEE_IO} inputs/outputs`);
  const frozen = normalizeFrozenTxV3(draft);
  assertStorageMassWithinLimit(frozen, "policyvault-0.7-payment-hd builder");
  const described = describeFrozenTx(frozen);
  const totalIn = frozen.inputs.reduce((s, i) => s + i.utxo.amount, 0n);
  const totalOut = frozen.outputs.reduce((s, o) => s + o.value, 0n);
  if (totalIn - totalOut !== fee) fail("internal: realized fee != required fee");
  if (!plan.terminal) {
    const succ = frozen.outputs.filter((o) => o.covenant !== null && o.covenant.covenantId === covenantId);
    if (succ.length !== 1 || succ[0].value !== plan.successor.feeReserve) fail("internal: successor output does not carry exactly feeReserve");
  }
  const rootOuts = frozen.outputs.filter((o) => o.covenant !== null && o.covenant.covenantId === rootSide.covenantId);
  if (rootOuts.length !== 1) fail("internal: exactly one root continuation output is required");
  const rootIns = frozen.inputs.filter((i) => i.utxo.covenantId === rootSide.covenantId);
  if (rootIns.length !== 1) fail("internal: exactly one root input is required");
  const successorStateId = plan.terminal ? null : compileExactStateV7Hd({ config, template, state: plan.successor }).stateId;

  return deepFreeze({
    kind: "hdOwnerTransition",
    contractVersion: CONTRACT_VERSION_V7_HD,
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
    rootAuthority: Object.freeze({
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
      prevState: rootSide.state,
      newState: rootSide.plan.successor,
      template: rootSide.template,
      value: rootSide.value.toString(),
      computeBudget: rootSide.budget,
      plannedCallHexLength: rootSide.plannedCallHexLength,
      buildDir: rootSide.current.buildDir
    }),
    asset: tokenSide ? Object.freeze({ tokenCovenantId: tokenSide.position.covenantId, templateIndex }) : null,
    accounting: Object.freeze({
      kas: Object.freeze({ predecessorFeeReserve: state.feeReserve.toString(), reserveConsumed: (plan.terminal ? state.feeReserve : state.feeReserve > plan.successor.feeReserve ? state.feeReserve - plan.successor.feeReserve : 0n).toString(), successorFeeReserve: plan.terminal ? "0" : plan.successor.feeReserve.toString(), externalFunding: plan.externalFunding.toString(), fee: fee.toString(), terminalPayout: plan.terminal ? plan.recover.payout.toString() : "0" })
    }),
    frozen,
    frozenCanonicalJson: canonicalFrozenTxJson(frozen),
    txId: described.txId,
    covenantSighash: described.sighashAll[0],
    rootSighash: described.sighashAll[rootSide.inputIndex],
    computeBudget: plan.budget,
    requiredFeeSompi: fee.toString(),
    encoderBuildDir: current.buildDir,
    plannedCallHexLength: plan.plannedCallHexLength,
    callExtra,
    hasFuelInput: true,
    hasRootInput: true,
    hasTokenInput: tokenSide !== null,
    tokenInputIndex: tokenSide ? frozen.inputs.findIndex((i) => i.utxo.covenantId === tokenSide.position.covenantId) : null,
    tokenSignatureScriptHex: tokenSide ? tokenSide.tokenSigscriptHex : null
  });
}

/*
 * FINALIZE a rooted HD vault owner/recover build (NO broadcasting). Reuses
 * the SAME M-of-N signature-blob primitive (`assembleOwnerSigsBlobV7`,
 * core/model/owner-set-v7.js) sdk/src/vault-builders-v7.js's finalizer uses
 * — the root's threshold math is never restated.
 */
function finalizeV7HdOwnerTransaction({ build, approvals, fuelSignatureScriptHex }) {
  if (build.kind !== "hdOwnerTransition" || build.contractVersion !== CONTRACT_VERSION_V7_HD) fail("finalizeV7HdOwnerTransaction takes a v0.7-payment-hd hdOwnerTransition build");
  const call = { function: build.encoderFunction, ...build.callExtra };
  if (build.encoderFunction === "ownerControl") call.successor = successorCallJsonV7(build.successorState);
  const callHex = runEncoderV4({ sourcePath: path.join(build.encoderBuildDir, "PolicyVault.state.sil"), constructorArgsPath: path.join(build.encoderBuildDir, "constructor-args.json"), call, contractVersion: CONTRACT_VERSION_V7_HD });
  if (callHex.length !== build.plannedCallHexLength) fail(`final covenant call length ${callHex.length / 2} != planned ${build.plannedCallHexLength / 2} — the exact-fee freeze is violated; refusing`, "FEE_DRIFT");
  const artifact = JSON.parse(fs.readFileSync(path.join(build.encoderBuildDir, "artifact.json")));
  const json = JSON.parse(build.frozenCanonicalJson);
  json.inputs[0].signatureScript = covenantSigscript(callHex, Buffer.from(artifact.script));

  const ra = build.rootAuthority;
  const slots = ra.expectedSignerSlots.map((s) => s.publicKey);
  while (slots.length < OWNER_SLOTS_V7) slots.push("00".repeat(32));
  const blob = assembleOwnerSigsBlobV7({ ownerSet: { owners: slots, ownerM: ra.prevState.ownerM, emergencyK: ra.prevState.emergencyK, recoveryM: ra.prevState.recoveryM }, actionName: ra.rootActionName, approvals: approvals ?? [] });
  if (blob.blobHex.length !== SIG_BLOB_LEN_V7 * 2) fail("internal: the assembled owner blob is not 780 bytes");
  const rootCallHex = runEncoderV4({ sourcePath: path.join(ra.buildDir, "PolicyVault.state.sil"), constructorArgsPath: path.join(ra.buildDir, "constructor-args.json"), call: { function: "rootAction", successor: rootSuccessorCallJsonV7(ra.newState), action: ra.rootAction, ownerSigs: blob.blobHex }, contractVersion: "policyvault-0.7-root" });
  if (rootCallHex.length !== ra.plannedCallHexLength) fail(`final root call length ${rootCallHex.length / 2} != planned ${ra.plannedCallHexLength / 2} — the exact-fee freeze is violated; refusing`, "FEE_DRIFT");
  const rootArtifact = JSON.parse(fs.readFileSync(path.join(ra.buildDir, "artifact.json")));
  json.inputs[ra.inputIndex].signatureScript = covenantSigscript(rootCallHex, Buffer.from(rootArtifact.script));

  if (build.hasTokenInput) json.inputs[build.tokenInputIndex].signatureScript = build.tokenSignatureScriptHex;
  if (typeof fuelSignatureScriptHex !== "string" || !/^[0-9a-f]+$/.test(fuelSignatureScriptHex) || fuelSignatureScriptHex.length / 2 !== ORDINARY_SIGSCRIPT_LEN) fail(`fuel signature script must be exactly ${ORDINARY_SIGSCRIPT_LEN} bytes`);
  json.inputs[json.inputs.length - 1].signatureScript = fuelSignatureScriptHex;
  return Object.freeze({ txId: build.txId, requiredFeeSompi: build.requiredFeeSompi, finalTransaction: json, covenantCallHex: callHex, ownerSigsBlobHex: blob.blobHex, signedSlots: blob.signedSlots, requiredApprovals: blob.requiredApprovals.toString(), satisfiedApprovals: blob.satisfiedApprovals.toString() });
}

module.exports = {
  CONTRACT_VERSION_V7_HD,
  HD_SPEND_LEVEL,
  HD_DELEGATION_LEVEL,
  OWNER_CONTROL_ACTIONS_V7_HD,
  buildCreateV7HdVault,
  buildHdSpendTransaction,
  buildHdDelegationTransaction,
  finalizeHdTransaction,
  buildV7HdOwnerTransaction,
  finalizeV7HdOwnerTransaction,
  /* re-exported unchanged — see the file header's "REUSE, NOT REIMPLEMENTATION" note */
  buildCreateV7Root,
  buildV7RootTransaction,
  finalizeV7RootTransaction,
  buildTokenDepositV7,
  finalizeTokenDepositV7,
  resolveRootActionV7
};
