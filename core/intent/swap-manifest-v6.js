"use strict";

/*
 * policyvault-swap-intent-manifest/1 — the closed-schema, hash-committed
 * description of ONE frozen v0.6 ATOMIC SWAP transaction (tokenAtomicSell /
 * tokenAtomicBuy) plus its deterministic LOCAL PRE-SIGN VERIFICATION against
 * the frozen transaction bytes. Additive beside the v0.5 token manifest.
 *
 * What a signer/verifier gets, as SEPARATE sections: controller identity;
 * token asset identity + issuer trust; VENUE (profile hash + protocol facts,
 * the exact pool outpoint/state before/after, the owner's swap-policy leaf
 * and its proof); the exact QUOTE recomputed from the pool's revealed state
 * (never an API); DESTINATION; the three KAS domains (principal / reserve /
 * carries) and the token domain; FRESHNESS (both outpoint kill switches +
 * the pre-sign deadline and the honest post-signature residual);
 * ECONOMICS (network fee as a fraction of swap value); a deterministic
 * EXPLANATION. NOTHING here is trusted as stated: verify() recomputes every
 * financial fact from the frozen transaction + descriptor + profile + the
 * core's own codecs and refuses on any mismatch.
 *
 * Status: IMPLEMENTED + UNIT-TESTED (core/intent/test/swap-manifest-v6.test.js);
 * the same codecs are executed byte-for-byte by tests/vm/tests/v6_sdk_integration.rs.
 */

const { canonicalJsonStringify, computeManifestHashV1 } = require("./canonical");
const { ownGet } = require("../model/own-get"); // rc12 review R-02: own-property action lookups (prototype keys fail closed)
const assets = require("../assets");
const { kcc20 } = assets;
const { normalizeTokenAgentPolicyV6, verifyTokenAgentProofV6, foldTokenAgentPolicyV6 } = require("../model/agent-merkle-v6");
const { normalizeSwapPolicyV6, verifySwapPolicyProofV6, normalizeSwapVenueProfile, computeSwapVenueProfileHash, swapPolicyToJsonV6, swapVenueProfileToJson, DIRECTION, DEST_SCHEME } = require("../model/swap-policy-v6");
const { normalizeStateV6 } = require("../model/vault-state-v6");
const { poolSellQuote, poolBuyQuote, SWAP_INPUT_COUNT } = require("../model/vault-transitions-v6");
const { calcStorageMass, cellsOfFrozenTx, STORAGE_MASS_LIMIT } = require("../model/storage-mass");
const { OWNER_SCHEMES } = require("../model/token-amounts");

const SWAP_MANIFEST_VERSION_1 = "policyvault-swap-intent-manifest/1";
const ACTIONS = Object.freeze({ tokenAtomicSell: Object.freeze({ direction: "SELL", role: "agent", terminal: false }), tokenAtomicBuy: Object.freeze({ direction: "BUY", role: "agent", terminal: false }) });
const VERIFIED_STATEMENT = "AI MAY REQUEST. POLICYVAULT DETERMINISTICALLY DECIDES. THE COVENANT ENFORCES. SIGNERS RETAIN CUSTODY.";
const RESIDUAL_STATEMENT = "After the pre-sign deadline passes, an already-signed swap remains consensus-valid while both the pool outpoint and the controller outpoint are unspent; Kaspa lockTime supplies no upper bound. Spending either outpoint kills the swap. Sign only to broadcast immediately.";

function refuse(code, message) {
  const e = new Error(message);
  e.code = code;
  throw e;
}
function digits(v, where) {
  if (typeof v !== "string" || !/^(0|[1-9][0-9]*)$/.test(v)) refuse("SCHEMA_INVALID", `${where} must be a non-negative digit string`);
  return BigInt(v);
}
function deepFreeze(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const k of Object.keys(value)) deepFreeze(value[k]);
  }
  return value;
}
function p2pkSpk(pk) {
  return `20${pk}ac`;
}
function bps(fee, value) {
  return value > 0n ? ((fee * 10_000n + value - 1n) / value).toString() : null;
}

/* Build the manifest from a v0.6 SDK swap build + descriptor + the agent policy the build used. */
function buildSwapIntentManifest({ build, descriptor, agentPolicy }) {
  if (!build || build.contractVersion !== "policyvault-0.6" || build.kind !== "transition" || !build.swap) refuse("SCHEMA_INVALID", "a v0.6 swap transition build is required");
  const info = ownGet(ACTIONS, build.action);
  if (!info) refuse("UNKNOWN_ACTION", `unknown swap action ${JSON.stringify(build.action)} — failing closed`);
  const validated = assets.validateAssetDescriptor(descriptor);
  const descriptorHash = assets.computeDescriptorHash(validated);
  if (descriptorHash !== build.template.descriptorHash) refuse("DESCRIPTOR_PIN_MISMATCH", "descriptor hash != the controller's pinned descriptorHash");
  const tpl = validated.acceptedTransferTemplates[build.asset?.templateIndex ?? 0];
  const policy = normalizeTokenAgentPolicyV6(agentPolicy);
  const fee = digits(build.requiredFeeSompi, "requiredFeeSompi");
  const swapValue = info.direction === "SELL" ? digits(build.swap.quote.netProceeds, "quote.netProceeds") : digits(build.swap.quote.kasSpend, "quote.kasSpend");
  const body = {
    manifestVersion: SWAP_MANIFEST_VERSION_1,
    network: { networkId: build.networkId },
    controller: {
      contractVersion: build.contractVersion,
      vaultId: build.template.vaultId,
      owner: build.template.owner,
      covenantId: build.covenantId,
      descriptorHash: build.template.descriptorHash,
      tokenCovenantId: build.template.tokenCovenantId,
      templateVmHashBlake2b256: build.template.templateVmHash,
      templateGeometry: { prefixLen: build.template.templatePrefixLen, stateLen: build.template.templateStateLen, suffixLen: build.template.templateSuffixLen }
    },
    asset: {
      descriptorHash,
      assetId: validated.assetId,
      displayName: validated.displayName,
      tokenStandard: validated.tokenStandard,
      decimalsDisplay: validated.decimalsDisplay,
      templateIndex: build.asset?.templateIndex ?? 0,
      templateVmHashBlake2b256: tpl ? tpl.templateVmHashBlake2b256 : null,
      issuerPowers: { ...validated.issuerPowers },
      trust: Object.values(validated.issuerPowers).some(Boolean) ? "ISSUER_CONTROLLED" : "NO_DECLARED_ISSUER_POWERS"
    },
    venue: {
      profileHash: build.swap.venueProfileHash,
      profile: JSON.parse(JSON.stringify(build.swap.venueProfile)),
      pool: JSON.parse(JSON.stringify(build.swap.pool)),
      poolNote: JSON.parse(JSON.stringify(build.swap.poolNote)),
      swapPolicy: { ...build.swap.swapPolicy },
      swapProof: { ...build.swap.swapProof },
      endorsement: "NONE — the profile describes a venue; PolicyVault never blesses, runs, or custodies one"
    },
    action: { sdkAction: build.action, direction: info.direction, role: info.role, terminal: false },
    transaction: { txId: build.txId, frozenCanonicalJson: build.frozenCanonicalJson, computeBudget: build.computeBudget, poolComputeBudget: build.poolComputeBudget, requiredFeeSompi: build.requiredFeeSompi, storageMass: build.swap.storageMass },
    stateBefore: { stateId: build.predecessorStateId, state: build.stateJson, outpoint: build.predecessorOutpoint },
    stateAfter: { stateId: build.successorStateId, state: build.successorState },
    accounting: { token: { ...build.accounting.token }, kas: { ...build.accounting.kas } },
    quote: { ...build.swap.quote },
    destination: { ...build.swap.destination },
    policy: {
      agentPolicy: { ...agentPolicy },
      agentProof: build.agentProof ? { ...build.agentProof } : null,
      periodsElapsed: build.callExtra.periodsElapsed,
      lockTime: build.frozen.lockTime.toString()
    },
    freshness: { ...build.swap.freshness, residual: RESIDUAL_STATEMENT, workflow: "verify -> sign -> broadcast immediately; never store a signed swap" },
    economics: { networkFeeSompi: fee.toString(), swapValueSompi: swapValue.toString(), feeBpsOfSwapValue: bps(fee, swapValue), protocolFeeSompi: build.swap.quote.protocolFee, protocolFeePaddingSompi: (digits(build.swap.quote.protocolFee, "protocolFee") - digits(build.swap.quote.protocolFeeMinimum, "protocolFeeMinimum")).toString() },
    signatureScripts: { tokenLeader: build.tokenSignatureScriptHex, tokenDelegate: build.poolNoteSignatureScriptHex, pool: build.poolSignatureScriptHex },
    explanation: explain({ direction: info.direction, build, policy, fee, swapValue })
  };
  const manifest = { ...body, manifestHash: computeManifestHashV1(body) };
  return deepFreeze(manifest);
}

/* Deterministic human-readable explanation (fixed order, fixed wording; every number from the build). */
function explain({ direction, build, policy, fee, swapValue }) {
  const q = build.swap.quote;
  const lines = [];
  lines.push(`ACTION ${direction === "SELL" ? "tokenAtomicSell" : "tokenAtomicBuy"} on controller ${build.covenantId} (policyvault-0.6 CANDIDATE) for asset ${build.asset.assetId}.`);
  if (direction === "SELL") lines.push(`GIVE UP exactly ${q.amountIn} atomic token units to the approved pool ${build.swap.pool.covenantId}; RECEIVE net ${q.netProceeds} sompi (pool pays ${q.kasOut}, venue protocol fee ${q.protocolFee}); minimum accepted ${q.minKasOut}.`);
  else lines.push(`PAY exactly ${q.kasSpend} sompi of consideration from the protected swap principal (pool receives ${q.kasIn}, venue protocol fee ${q.protocolFee}); RECEIVE exactly ${q.tokensOut} atomic token units into the controller's own position; maximum accepted ${q.maxKasIn}.`);
  lines.push(`DESTINATION type ${build.swap.destination.type}: ${build.swap.destination.type === "A" ? "PolicyVault-controlled successor (principal / own position)" : `owner-allowlisted P2PK ${build.swap.destination.identity}`}.`);
  lines.push(`AGENT ${policy.agentPk}: token cap ${policy.tokenMaxPerSpend}/budget ${policy.tokenPeriodBudget} (spent ${policy.tokenPeriodSpent}); KAS cap ${policy.kasMaxPerSwap}/budget ${policy.kasPeriodBudget} (spent ${policy.kasPeriodSpent}); fee cap ${policy.agentMaxFeePerTx}.`);
  lines.push(`OWNER POLICY: floor ${build.swap.swapPolicy.sellFloorNum}/${build.swap.swapPolicy.sellFloorDen}, ceiling ${build.swap.swapPolicy.buyCeilNum}/${build.swap.swapPolicy.buyCeilDen} sompi per token; protocol fee cap ${build.swap.swapPolicy.maxProtocolFeeKas}; directions ${build.swap.swapPolicy.directionMask}.`);
  lines.push(`KAS DOMAINS: fee reserve ${build.accounting.kas.predecessorFeeReserve} -> ${build.accounting.kas.successorFeeReserve} (network fee ${fee} paid from the reserve only); swap principal ${build.accounting.kas.predecessorSwapPrincipal} -> ${build.accounting.kas.successorSwapPrincipal}; token-note carries unchanged; no fuel input.`);
  lines.push(`TOKEN DOMAIN: position ${build.accounting.token.positionBefore} -> ${build.accounting.token.positionAfter}; pool note ${build.swap.poolNote.amountBefore} -> ${build.swap.poolNote.amountAfter}; exact conservation.`);
  lines.push(`NETWORK FEE ${fee} sompi = ${bps(fee, swapValue)} bps of the swap value ${swapValue} sompi; KIP-9 storage mass ${build.swap.storageMass} (limit ${STORAGE_MASS_LIMIT}).`);
  lines.push(`FRESHNESS: usable only while pool outpoint ${build.swap.freshness.poolOutpoint.transactionId}:${build.swap.freshness.poolOutpoint.index} AND controller outpoint ${build.swap.freshness.controllerOutpoint.transactionId}:${build.swap.freshness.controllerOutpoint.index} are unspent; pre-sign deadline DAA ${build.swap.freshness.deadlineDaa}; sign only to broadcast immediately.`);
  lines.push("AUTHORIZATION: SIGHASH_ALL by the agent key only; the covenant enforces every rule above; PolicyVault signs nothing.");
  return lines;
}

/*
 * Deterministic local PRE-SIGN verification: recompute every financial fact
 * from the frozen transaction + descriptor + venue profile + core codecs.
 * `currentDaaScore` (optional) enforces the pre-sign deadline.
 * Returns { verdict: "VERIFIED" | "REFUSED", checks, failures, explanation }.
 */
function verifySwapIntentManifest({ manifest, descriptor, currentDaaScore }) {
  const checks = [];
  const failures = [];
  const check = (name, ok, detail) => {
    checks.push({ name, ok: !!ok, detail: detail ?? null });
    if (!ok) failures.push({ name, detail: detail ?? null });
  };
  try {
    if (manifest.manifestVersion !== SWAP_MANIFEST_VERSION_1) refuse("UNKNOWN_MANIFEST_VERSION", "unknown swap manifest version — failing closed");
    const { manifestHash, ...body } = manifest;
    check("manifestHash", computeManifestHashV1(body) === manifestHash, "manifest hash recomputed");
    const info = ownGet(ACTIONS, manifest.action?.sdkAction);
    if (!info) refuse("UNKNOWN_ACTION", "unknown action");
    const sell = info.direction === "SELL";
    check("actionDirection", info.direction === manifest.action.direction && manifest.action.role === "agent" && manifest.action.terminal === false, "direction/role derived from the action table");
    check("contractVersion", manifest.controller.contractVersion === "policyvault-0.6", "v0.6 lineage only");

    /* asset + descriptor pins */
    const validated = assets.validateAssetDescriptor(descriptor);
    const dh = assets.computeDescriptorHash(validated);
    check("descriptorHashPin", dh === manifest.asset.descriptorHash && dh === manifest.controller.descriptorHash, "descriptor hash == asset.descriptorHash == controller pin");
    check("descriptorFamily", validated.tokenCovenantId === manifest.controller.tokenCovenantId, "descriptor family == controller pin");
    const tpl = validated.acceptedTransferTemplates[manifest.asset.templateIndex];
    check("templatePin", !!tpl && tpl.templateVmHashBlake2b256 === manifest.controller.templateVmHashBlake2b256 && tpl.prefixLen === manifest.controller.templateGeometry.prefixLen && tpl.suffixLen === manifest.controller.templateGeometry.suffixLen, "descriptor template == controller pin (hash + geometry)");
    check("issuerPowersVerbatim", JSON.stringify(manifest.asset.issuerPowers) === JSON.stringify(validated.issuerPowers), "issuer powers surfaced verbatim");

    /* venue profile (protocol facts) + owner swap policy (authority) */
    const profile = normalizeSwapVenueProfile(manifest.venue.profile);
    const profileHash = computeSwapVenueProfileHash(profile);
    const leaf = normalizeSwapPolicyV6(manifest.venue.swapPolicy);
    check("profileHashPin", profileHash === manifest.venue.profileHash && profileHash === leaf.profileHash, "venue profile hash == leaf pin");
    check("profileNetwork", profile.networkId === manifest.network.networkId, "profile network == manifest network");
    check("profilePair", profile.tokenCovenantId === manifest.controller.tokenCovenantId, "profile token family == controller pin (exact pair)");
    check("profilePoolPins", profile.poolCovenantId === leaf.poolCovenantId && profile.poolTemplateVmHashBlake2b256 === leaf.poolTemplateVmHash && BigInt(profile.poolTemplateGeometry.prefixLen) === leaf.poolPrefixLen && BigInt(profile.poolTemplateGeometry.suffixLen) === leaf.poolSuffixLen && profile.feeModel.protocolFeePk === leaf.poolFeePk, "profile pool family/template/geometry/fee key == leaf");
    const before = normalizeStateV6(manifest.stateBefore.state);
    const after = normalizeStateV6(manifest.stateAfter.state);
    check("swapPolicyCommitted", verifySwapPolicyProofV6({ root: before.swapRoot, policy: leaf, siblingsHex: manifest.venue.swapProof.siblingsHex, pathBits: BigInt(manifest.venue.swapProof.pathBits) }) && manifest.venue.swapProof.root === before.swapRoot, "swap policy leaf verifies under the live swapRoot");
    check("directionAllowed", (leaf.directionMask & (sell ? DIRECTION.SELL : DIRECTION.BUY)) !== 0n, "leaf allows this direction");
    const typeB = leaf.destScheme === DEST_SCHEME.P2PK;
    check("destinationType", (manifest.destination.type === "B") === typeB && (!typeB || sell) && (typeB ? manifest.destination.identity === leaf.destIdentity : manifest.destination.identity === null), "destination type/identity from the leaf; type B is SELL-only");

    /* agent policy + proof + successor root */
    const policy = normalizeTokenAgentPolicyV6(manifest.policy.agentPolicy);
    check("agentPolicyCommitted", verifyTokenAgentProofV6({ root: before.agentRoot, policy, siblingsHex: manifest.policy.agentProof.siblingsHex, pathBits: BigInt(manifest.policy.agentProof.pathBits) }) && manifest.policy.agentProof.root === before.agentRoot, "agent policy leaf verifies under the live agentRoot");

    /* frozen transaction shape */
    const frozen = JSON.parse(manifest.transaction.frozenCanonicalJson);
    const inputs = frozen.inputs;
    const outputs = frozen.outputs;
    const totalIn = inputs.reduce((s, i) => s + BigInt(i.utxo.amount), 0n);
    const totalOut = outputs.reduce((s, o) => s + BigInt(o.value), 0n);
    const fee = totalIn - totalOut;
    check("feeExact", fee.toString() === manifest.accounting.kas.fee && fee.toString() === manifest.transaction.requiredFeeSompi, `fee ${fee}`);
    check("inputCount", inputs.length === SWAP_INPUT_COUNT, `exactly ${SWAP_INPUT_COUNT} inputs (no external KAS input)`);
    check("outputCount", outputs.length === (typeB ? 6 : 5), "exact output count (no hidden outputs)");
    const family = manifest.controller.tokenCovenantId;
    const poolId = leaf.poolCovenantId;
    const ctrlIn = inputs[0];
    check("controllerInput", ctrlIn.utxo.covenantId === manifest.controller.covenantId && BigInt(ctrlIn.utxo.amount) === before.feeReserve + before.swapPrincipal, "controller input carries feeReserve + swapPrincipal");
    check("familyInputs", inputs[1].utxo.covenantId === family && inputs[2].utxo.covenantId === family, "inputs 1 and 2 are the pinned token family");
    check("poolInput", inputs[3].utxo.covenantId === poolId && BigInt(inputs[3].utxo.amount) === digits(manifest.venue.pool.stateBefore.kasReserve, "pool.stateBefore.kasReserve"), "input 3 is the approved pool carrying its declared KAS reserve");
    check("noForeignCovenantInputs", inputs.every((i, idx) => idx === 0 || i.utxo.covenantId === family || i.utxo.covenantId === poolId), "no third covenant family");
    check("successorOutput", outputs[0].covenant && outputs[0].covenant.covenantId === manifest.controller.covenantId && BigInt(outputs[0].value) === after.feeReserve + after.swapPrincipal, "output 0 is the successor carrying feeReserve' + swapPrincipal'");
    check("poolSuccessorOutput", outputs[3].covenant && outputs[3].covenant.covenantId === poolId && outputs[3].value === manifest.venue.pool.stateAfter.kasReserve, "output 3 is the pool successor carrying its new KAS reserve");
    check("statePreserved", before.paused === 0n && after.paused === 0n && before.policyNonce === after.policyNonce && before.swapRoot === after.swapRoot && before.agentRoot !== after.agentRoot, "unpaused; nonce/swapRoot preserved; agentRoot advanced");

    /* the revealed token redeems: OUR note (leader) and the POOL's note (delegate) */
    const ourRedeem = assets.verifyTokenInputRedeem({ descriptor: validated, redeemHex: assets.redeemFromSignatureScript(manifest.signatureScripts.tokenLeader) });
    const poolRedeem = assets.verifyTokenInputRedeem({ descriptor: validated, redeemHex: assets.redeemFromSignatureScript(manifest.signatureScripts.tokenDelegate) });
    check("ourNoteRedeem", ourRedeem.p2shSpkHex === inputs[1].utxo.scriptPublicKey.scriptHex.toLowerCase() && ourRedeem.state.ownerIdentifier === manifest.controller.covenantId && ourRedeem.state.identifierType === OWNER_SCHEMES.COVENANT_ID && !ourRedeem.state.isMinter, "input 1 revealed redeem reproduces the UTXO and is owned by the controller");
    check("poolNoteRedeem", poolRedeem.p2shSpkHex === inputs[2].utxo.scriptPublicKey.scriptHex.toLowerCase() && poolRedeem.state.ownerIdentifier === poolId && poolRedeem.state.identifierType === OWNER_SCHEMES.COVENANT_ID && !poolRedeem.state.isMinter, "input 2 revealed redeem reproduces the UTXO and is owned by the pool");
    const positionBefore = ourRedeem.state.amount;
    const poolNoteBefore = poolRedeem.state.amount;
    check("poolNoteMatchesReserve", poolNoteBefore.toString() === manifest.venue.pool.stateBefore.tokenReserve && poolNoteBefore.toString() === manifest.venue.poolNote.amountBefore, "pool note amount == declared tokenReserve");

    /* the exact quote, recomputed from the pool's revealed state */
    const poolBefore = { kasReserve: manifest.venue.pool.stateBefore.kasReserve, tokenReserve: manifest.venue.pool.stateBefore.tokenReserve, feeBps: manifest.venue.pool.stateBefore.feeBps, nonce: manifest.venue.pool.stateBefore.nonce };
    check("poolFeeBps", BigInt(poolBefore.feeBps) === profile.feeModel.poolFeeBps, "pool fee bps == profile");
    const q = manifest.quote;
    let amountDelta;
    let principalDelta;
    let protoPaid;
    if (sell) {
      const quote = poolSellQuote(poolBefore, q.amountIn, profile.feeModel.protocolFeeBps);
      protoPaid = digits(q.protocolFee, "quote.protocolFee");
      const net = quote.kasOut - protoPaid;
      check("quoteRecomputed", quote.newKasReserve.toString() === manifest.venue.pool.stateAfter.kasReserve && quote.newTokenReserve.toString() === manifest.venue.pool.stateAfter.tokenReserve && quote.kasOut.toString() === q.kasOut && quote.protocolFee.toString() === q.protocolFeeMinimum && net.toString() === q.netProceeds, "sell quote == pool state after / kasOut / net proceeds");
      check("minOut", net >= digits(q.minKasOut, "quote.minKasOut"), "net proceeds >= minKasOut");
      check("floor", net * leaf.sellFloorDen >= quote.amountIn * leaf.sellFloorNum, "net proceeds respect the owner floor");
      check("tokenCap", quote.amountIn <= policy.tokenMaxPerSpend && quote.amountIn > 0n, "amountIn <= tokenMaxPerSpend");
      amountDelta = quote.amountIn;
      principalDelta = typeB ? 0n : net;
      check("proceedsOutput", typeB ? outputs[5].covenant === null && outputs[5].scriptPublicKey.scriptHex.toLowerCase() === p2pkSpk(leaf.destIdentity) && BigInt(outputs[5].value) === net : outputs.length === 5, typeB ? "type-B proceeds output exact" : "type A: no proceeds output");
      check("swapValue", manifest.economics.swapValueSompi === net.toString(), "swap value = net proceeds");
    } else {
      const quote = poolBuyQuote(poolBefore, q.tokensOut, profile.feeModel.protocolFeeBps);
      protoPaid = digits(q.protocolFee, "quote.protocolFee");
      const kasSpend = quote.kasIn + protoPaid;
      check("quoteRecomputed", quote.newKasReserve.toString() === manifest.venue.pool.stateAfter.kasReserve && quote.newTokenReserve.toString() === manifest.venue.pool.stateAfter.tokenReserve && quote.kasIn.toString() === q.kasIn && quote.protocolFee.toString() === q.protocolFeeMinimum && kasSpend.toString() === q.kasSpend, "buy quote == pool state after / kasIn / consideration");
      check("maxIn", kasSpend <= digits(q.maxKasIn, "quote.maxKasIn"), "consideration <= maxKasIn");
      check("ceiling", kasSpend * leaf.buyCeilDen <= quote.tokensOut * leaf.buyCeilNum, "consideration respects the owner ceiling");
      check("kasCap", kasSpend <= policy.kasMaxPerSwap, "consideration <= kasMaxPerSwap");
      check("principalCovers", kasSpend <= before.swapPrincipal, "consideration <= protected principal");
      amountDelta = -quote.tokensOut;
      principalDelta = -kasSpend;
      check("swapValue", manifest.economics.swapValueSompi === kasSpend.toString(), "swap value = consideration");
    }
    check("protocolFeeOutput", outputs[4].covenant === null && outputs[4].scriptPublicKey.scriptHex.toLowerCase() === p2pkSpk(leaf.poolFeePk) && BigInt(outputs[4].value) === protoPaid && protoPaid >= digits(q.protocolFeeMinimum, "quote.protocolFeeMinimum") && protoPaid <= leaf.maxProtocolFeeKas, "protocol fee output to the profile key, >= venue minimum, <= owner cap");
    check("poolValueDelta", BigInt(inputs[3].utxo.amount) - BigInt(outputs[3].value) === (sell ? digits(q.kasOut, "quote.kasOut") : -digits(q.kasIn, "quote.kasIn")), "pool KAS delta == quote");
    check("principalDelta", after.swapPrincipal - before.swapPrincipal === principalDelta && manifest.accounting.kas.principalDelta === principalDelta.toString(), `principal delta ${principalDelta}`);
    const consumed = before.feeReserve - after.feeReserve;
    check("reserveConsumed", consumed === fee && consumed <= policy.agentMaxFeePerTx && manifest.accounting.kas.reserveConsumed === consumed.toString(), `reserve pays exactly the fee ${fee} <= agentMaxFeePerTx`);

    /* token conservation + reconstructed continuation outputs */
    const positionAfter = positionBefore - amountDelta;
    const poolNoteAfter = poolNoteBefore + amountDelta;
    check("tokenConservation", positionAfter >= 0n && poolNoteAfter >= 0n && manifest.accounting.token.positionBefore === positionBefore.toString() && manifest.accounting.token.positionAfter === positionAfter.toString() && manifest.venue.poolNote.amountAfter === poolNoteAfter.toString(), `${positionBefore} -> ${positionAfter}; pool ${poolNoteBefore} -> ${poolNoteAfter}`);
    const selfState = kcc20.encodeState({ ownerIdentifier: manifest.controller.covenantId, identifierType: OWNER_SCHEMES.COVENANT_ID, amount: positionAfter, isMinter: false });
    const poolState = kcc20.encodeState({ ownerIdentifier: poolId, identifierType: OWNER_SCHEMES.COVENANT_ID, amount: poolNoteAfter, isMinter: false });
    check("ourContinuationReconstructed", outputs[1].scriptPublicKey.scriptHex.toLowerCase() === kcc20.p2shSpkHex(kcc20.reconstructRedeem(ourRedeem.prefixHex, selfState, ourRedeem.suffixHex)) && outputs[1].covenant.covenantId === family, "family output 0 == template(our state after)");
    check("poolContinuationReconstructed", outputs[2].scriptPublicKey.scriptHex.toLowerCase() === kcc20.p2shSpkHex(kcc20.reconstructRedeem(ourRedeem.prefixHex, poolState, ourRedeem.suffixHex)) && outputs[2].covenant.covenantId === family, "family output 1 == template(pool state after)");
    check("carriesPreserved", outputs[1].value === inputs[1].utxo.amount && outputs[2].value === inputs[2].utxo.amount, "token-note KAS carries unchanged (never consideration, never fee)");

    /* successor agent root = the advanced leaf folded up the same co-path */
    const periods = digits(manifest.policy.periodsElapsed, "policy.periodsElapsed");
    let newStart = policy.periodStartDaa;
    let newTok = policy.tokenPeriodSpent + (sell ? amountDelta : 0n);
    let newKas = policy.kasPeriodSpent + (sell ? 0n : -principalDelta);
    if (periods >= 1n) {
      newStart = policy.periodStartDaa + periods * policy.periodLengthDaa;
      newTok = sell ? amountDelta : 0n;
      newKas = sell ? 0n : -principalDelta;
    }
    check("budgets", newTok <= policy.tokenPeriodBudget && newKas <= policy.kasPeriodBudget, "period budgets respected");
    const newPolicy = { ...manifest.policy.agentPolicy, periodStartDaa: newStart.toString(), tokenPeriodSpent: newTok.toString(), kasPeriodSpent: newKas.toString() };
    check("successorAgentRoot", foldTokenAgentPolicyV6(newPolicy, manifest.policy.agentProof.siblingsHex, BigInt(manifest.policy.agentProof.pathBits)) === after.agentRoot, "successor agentRoot == fold(advanced leaf)");
    check("lockTime", BigInt(frozen.lockTime) === (periods >= 1n ? newStart : 0n) && manifest.policy.lockTime === frozen.lockTime, "lockTime == rollover start (or 0)");

    /* freshness + economics + storage */
    const f = manifest.freshness;
    check("freshnessOutpoints", f.poolOutpoint.transactionId === inputs[3].previousOutpoint.transactionId && Number(f.poolOutpoint.index) === Number(inputs[3].previousOutpoint.index) && f.controllerOutpoint.transactionId === inputs[0].previousOutpoint.transactionId && Number(f.controllerOutpoint.index) === Number(inputs[0].previousOutpoint.index), "both kill-switch outpoints are the transaction's own inputs");
    check("freshnessResidualStated", typeof f.residual === "string" && f.residual.length > 0 && typeof f.statement === "string" && /kill switch/.test(f.statement), "residual + kill switches stated");
    if (currentDaaScore !== undefined && currentDaaScore !== null) {
      const now = BigInt(currentDaaScore);
      check("deadlineNotPassed", now <= digits(f.deadlineDaa, "freshness.deadlineDaa"), `current DAA ${now} <= deadline ${f.deadlineDaa}`);
    }
    const swapValue = digits(manifest.economics.swapValueSompi, "economics.swapValueSompi");
    check("economicsFeeBps", manifest.economics.networkFeeSompi === fee.toString() && manifest.economics.feeBpsOfSwapValue === bps(fee, swapValue), "fee-as-bps recomputed");
    const storage = (() => { const c = cellsOfFrozenTx({ inputs, outputs }); return calcStorageMass(c.inputCells, c.outputCells); })();
    check("storageMass", storage <= STORAGE_MASS_LIMIT && storage.toString() === manifest.transaction.storageMass, `KIP-9 storage mass ${storage} <= ${STORAGE_MASS_LIMIT}`);
  } catch (e) {
    failures.push({ name: "exception", detail: `${e.code ?? "ERROR"}: ${e.message}` });
  }
  const verdict = failures.length === 0 ? "VERIFIED" : "REFUSED";
  return deepFreeze({ verdict, statement: verdict === "VERIFIED" ? VERIFIED_STATEMENT : null, checks, failures, manifestHash: manifest.manifestHash ?? null, explanation: manifest.explanation ?? null });
}

module.exports = { SWAP_MANIFEST_VERSION_1, ACTIONS, VERIFIED_STATEMENT, RESIDUAL_STATEMENT, buildSwapIntentManifest, verifySwapIntentManifest, canonicalJsonStringify };
