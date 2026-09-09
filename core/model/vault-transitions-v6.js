"use strict";

/*
 * v0.6 atomic-composability controller transition planner — deterministic
 * successor derivation for every PolicyVault.v0.6.sil entrypoint, mirroring
 * the covenant's rules EXACTLY so the core refuses locally what consensus
 * would refuse (local pre-check ONLY; the covenant remains the authority).
 *
 * THREE accounting domains, never mixed:
 *   TOKEN — spend / sell amounts, buy proceeds, positions: atomic units;
 *           conservation verified HERE from revealed note states, never an
 *           indexer;
 *   KAS consideration — swapPrincipal (sompi): the ONLY BUY consideration
 *           source and the type-A SELL proceeds sink; per-agent kasMaxPerSwap
 *           / kasPeriodBudget;
 *   KAS fee reserve — feeReserve (sompi): may only become network fee
 *           (agentMaxFeePerTx, exact fee).
 *
 * POOL QUOTES are computed HERE from the pool's revealed on-chain state with
 * the venue profile's constant-product-bps-fee/1 integer arithmetic (the
 * exact expressions of contracts/experiments/V6PoolFixture.sil) — never from
 * a DEX API, indexer or hosted quote. A quote is bound to the exact pool
 * outpoint by the builder; any pool transition makes it unusable.
 *
 * Status: IMPLEMENTED + UNIT-TESTED (core/model/test/vault-transitions-v6.test.js).
 */

const { parseSompi, parsePositiveSompi } = require("./amounts");
const { normalizeHex, normalizeXOnlyPubkey } = require("./vault-state");
const { normalizeStateV6, OWNER_OP_SELECTOR_V6 } = require("./vault-state-v6");
const { normalizeTokenAgentPolicyV6, verifyTokenAgentProofV6, foldTokenAgentPolicyV6 } = require("./agent-merkle-v6");
const { normalizeSwapPolicyV6, verifySwapPolicyProofV6, DIRECTION, DEST_SCHEME } = require("./swap-policy-v6");
const { parseAtomicAmount, OWNER_SCHEMES } = require("./token-amounts");

const MAX_PERIODS_ELAPSED = 1000n;
const BPS = 10_000n;
/* swaps carry EXACTLY these inputs/outputs (pinned in-covenant) */
const SWAP_INPUT_COUNT = 4;
const SWAP_OUTPUTS_TYPE_A = 5;
const SWAP_OUTPUTS_TYPE_B = 6;

function fail(message, code) {
  const e = new Error(`vault-transitions-v6: ${message}`);
  if (code) e.code = code;
  throw e;
}
function ceilDiv(a, b) {
  if (b <= 0n) fail("internal: ceilDiv by non-positive");
  return (a + b - 1n) / b;
}
function requireContinuingState(state, label) {
  if (!state || typeof state !== "object") fail(`${label}: state is required`);
  if (state.recoveryParse === true) fail(`${label}: a recovery-mode (shape-only) state may only be used by ownerRecover — refusing to derive a successor from it`, "RECOVERY_STATE_ONLY");
  return normalizeStateV6(state);
}
function withChanges(state, changes) {
  return normalizeStateV6({ ...state, ...changes });
}
function resolveAgent(s, params, label) {
  const policy = normalizeTokenAgentPolicyV6(params.agentPolicy);
  const proofIn = params.agentProof;
  if (!proofIn || typeof proofIn !== "object") fail(`${label}: agentProof { siblingsHex, pathBits } is required`);
  const proof = { siblingsHex: String(proofIn.siblingsHex ?? "").toLowerCase(), pathBits: typeof proofIn.pathBits === "bigint" ? proofIn.pathBits : BigInt(proofIn.pathBits) };
  if (!verifyTokenAgentProofV6({ root: s.agentRoot, policy, siblingsHex: proof.siblingsHex, pathBits: proof.pathBits })) {
    fail(`${label}: the agent policy proof does not verify against the live agentRoot — stale tree or forged policy`, "AGENT_PROOF_INVALID");
  }
  return { policy, proof: Object.freeze(proof) };
}
function resolveSwapPolicy(s, params, label) {
  const policy = normalizeSwapPolicyV6(params.swapPolicy);
  const proofIn = params.swapProof;
  if (!proofIn || typeof proofIn !== "object") fail(`${label}: swapProof { siblingsHex, pathBits } is required`);
  const proof = { siblingsHex: String(proofIn.siblingsHex ?? "").toLowerCase(), pathBits: typeof proofIn.pathBits === "bigint" ? proofIn.pathBits : BigInt(proofIn.pathBits) };
  if (!verifySwapPolicyProofV6({ root: s.swapRoot, policy, siblingsHex: proof.siblingsHex, pathBits: proof.pathBits })) {
    fail(`${label}: the swap policy proof does not verify against the live swapRoot — stale tree or unapproved venue/pool policy`, "SWAP_PROOF_INVALID");
  }
  return { policy, proof: Object.freeze(proof) };
}

/* Agent accounting advance shared by spend / sell / buy (mirrors requireAgentTransition). */
function advanceAgent(policy, { tokenSpend, kasSpend, periodsElapsed }, proof, label) {
  if (tokenSpend > policy.tokenMaxPerSpend) fail(`${label}: token amount exceeds this agent's tokenMaxPerSpend`, "OVER_CAP");
  if (kasSpend > policy.kasMaxPerSwap) fail(`${label}: KAS consideration exceeds this agent's kasMaxPerSwap`, "OVER_KAS_CAP");
  const periods = parseSompi(periodsElapsed ?? 0n, "periodsElapsed");
  if (periods > MAX_PERIODS_ELAPSED) fail(`${label}: periodsElapsed out of range [0, ${MAX_PERIODS_ELAPSED}]`);
  let newStart = policy.periodStartDaa;
  let newTokenSpent = policy.tokenPeriodSpent + tokenSpend;
  let newKasSpent = policy.kasPeriodSpent + kasSpend;
  let lockTime = 0n;
  if (periods >= 1n) {
    newStart = policy.periodStartDaa + periods * policy.periodLengthDaa;
    newTokenSpent = tokenSpend;
    newKasSpent = kasSpend;
    lockTime = newStart;
  }
  if (newTokenSpent > policy.tokenPeriodBudget) fail(`${label}: token amount exceeds this agent's remaining token period budget`, "OVER_BUDGET");
  if (newKasSpent > policy.kasPeriodBudget) fail(`${label}: KAS consideration exceeds this agent's remaining KAS period budget`, "OVER_KAS_BUDGET");
  const newPolicy = normalizeTokenAgentPolicyV6({ ...policy, periodStartDaa: newStart, tokenPeriodSpent: newTokenSpent, kasPeriodSpent: newKasSpent });
  const newRoot = foldTokenAgentPolicyV6(newPolicy, proof.siblingsHex, proof.pathBits);
  if (newRoot === null) fail(`${label}: internal — successor-root fold left unconsumed path bits`);
  return { newPolicy, newRoot, newStart, newTokenSpent, newKasSpent, lockTime };
}

/*
 * The protocol fee actually PAID to the venue's fee key: at least the venue's
 * minimum (bps of the swap), optionally padded (params.protocolFeeSompi) so
 * the fee output clears KIP-9 storage mass, never above the owner's
 * maxProtocolFeeKas. Padding is a real cost surfaced in the plan.
 */
function resolveProtocolFee(quote, swap, params, label) {
  let paid = quote.protocolFee;
  if (params.protocolFeeSompi !== undefined && params.protocolFeeSompi !== null) {
    paid = parseSompi(params.protocolFeeSompi, "protocolFeeSompi");
    if (paid < quote.protocolFee) fail(`${label}: protocolFeeSompi ${paid} is below the venue's minimum ${quote.protocolFee} — the pool would refuse`, "PROTOCOL_FEE_BELOW_MIN");
  }
  if (paid > swap.maxProtocolFeeKas) fail(`${label}: the protocol fee ${paid} exceeds the owner's maxProtocolFeeKas ${swap.maxProtocolFeeKas}`, "PROTOCOL_FEE_OVER_MAX");
  return paid;
}

/* Fee-reserve domain (mirrors requireFeeReserveDomain's local half). */
function consumeReserve(s, policy, reserveConsumed, label) {
  const consumed = parseSompi(reserveConsumed ?? 0n, "reserveConsumed");
  if (consumed > policy.agentMaxFeePerTx) fail(`${label}: reserveConsumed exceeds this agent's agentMaxFeePerTx`, "OVER_AGENT_FEE_CAP");
  if (consumed > s.feeReserve) fail(`${label}: reserveConsumed exceeds the available fee reserve`, "INSUFFICIENT_RESERVE");
  return consumed;
}

/* ---------------- pool quotes (constant-product-bps-fee/1, exact integers) ---------------- */

function normalizePool(input) {
  if (!input || typeof input !== "object") fail("pool state { kasReserve, tokenReserve, feeBps, nonce } is required");
  const pool = Object.freeze({
    kasReserve: parsePositiveSompi(input.kasReserve, "pool.kasReserve"),
    tokenReserve: parseAtomicAmount(input.tokenReserve, "pool.tokenReserve"),
    feeBps: parseSompi(input.feeBps, "pool.feeBps"),
    nonce: parseSompi(input.nonce ?? 0n, "pool.nonce")
  });
  if (pool.tokenReserve <= 0n) fail("pool.tokenReserve must be > 0");
  if (pool.feeBps >= BPS) fail("pool.feeBps must be < 10000");
  return pool;
}
function normalizeBps(value, field) {
  const n = parseSompi(value, field);
  if (n > BPS) fail(`${field} out of range`);
  return n;
}

/* SELL amountIn tokens: the pool's exact successor and the trader's net KAS. */
function poolSellQuote(poolInput, amountInInput, protocolFeeBpsInput) {
  const pool = normalizePool(poolInput);
  const amountIn = parseAtomicAmount(amountInInput, "amountIn");
  if (amountIn <= 0n) fail("amountIn must be > 0", "ZERO_SPEND");
  const protocolFeeBps = normalizeBps(protocolFeeBpsInput, "protocolFeeBps");
  const feeTok = ceilDiv(amountIn * pool.feeBps, BPS);
  const netIn = amountIn - feeTok;
  if (netIn <= 0n) fail("amountIn is consumed entirely by the pool fee — no quote", "QUOTE_TOO_SMALL");
  const k = pool.kasReserve * pool.tokenReserve;
  const newTokenReserve = pool.tokenReserve + amountIn;
  const newKasReserve = ceilDiv(k, pool.tokenReserve + netIn);
  if (newKasReserve <= 0n || newKasReserve > pool.kasReserve) fail("internal: sell quote produced a non-decreasing KAS reserve");
  const kasOut = pool.kasReserve - newKasReserve;
  if (kasOut <= 0n) fail("the pool would pay nothing for this amount — no quote", "QUOTE_TOO_SMALL");
  const protocolFee = ceilDiv(kasOut * protocolFeeBps, BPS);
  if (protocolFee >= kasOut) fail("the protocol fee would consume the whole proceeds — no quote", "QUOTE_TOO_SMALL");
  return Object.freeze({ direction: "SELL", amountIn, newKasReserve, newTokenReserve, newNonce: pool.nonce + 1n, kasOut, protocolFee, netProceeds: kasOut - protocolFee, pool });
}

/* BUY tokensOut tokens: the smallest KAS the pool accepts + the protocol fee. */
function poolBuyQuote(poolInput, tokensOutInput, protocolFeeBpsInput) {
  const pool = normalizePool(poolInput);
  const tokensOut = parseAtomicAmount(tokensOutInput, "tokensOut");
  if (tokensOut <= 0n) fail("tokensOut must be > 0", "ZERO_SPEND");
  const protocolFeeBps = normalizeBps(protocolFeeBpsInput, "protocolFeeBps");
  const newTokenReserve = pool.tokenReserve - tokensOut;
  if (newTokenReserve <= 0n) fail("tokensOut would drain the pool's reserve — no quote", "QUOTE_TOO_LARGE");
  const k = pool.kasReserve * pool.tokenReserve;
  let target = ceilDiv(k, newTokenReserve) - pool.kasReserve; // minimum net KAS the invariant needs
  if (target < 1n) target = 1n;
  let kasIn = ceilDiv(target * BPS, BPS - pool.feeBps);
  for (let guard = 0; guard < 8; guard++) {
    const netIn = kasIn - ceilDiv(kasIn * pool.feeBps, BPS);
    if (netIn >= target) break;
    kasIn += 1n;
  }
  const netIn = kasIn - ceilDiv(kasIn * pool.feeBps, BPS);
  if (netIn < target || netIn <= 0n) fail("internal: buy quote search did not converge");
  if (newTokenReserve * (pool.kasReserve + netIn) < k) fail("internal: buy quote violates the invariant");
  const protocolFee = ceilDiv(kasIn * protocolFeeBps, BPS);
  return Object.freeze({ direction: "BUY", tokensOut, newKasReserve: pool.kasReserve + kasIn, newTokenReserve, newNonce: pool.nonce + 1n, kasIn, protocolFee, kasSpend: kasIn + protocolFee, pool });
}

/* ---------------- entrypoint successors ---------------- */

/*
 * tokenAgentSpend (v0.5 semantics; swapPrincipal / swapRoot preserved).
 */
function tokenAgentSpendSuccessorV6(state, params) {
  const s = requireContinuingState(state, "tokenAgentSpend");
  if (s.paused !== 0n) fail("tokenAgentSpend: controller is paused", "PAUSED");
  const { policy, proof } = resolveAgent(s, params, "tokenAgentSpend");
  const spend = parseAtomicAmount(params.spendAmount, "spendAmount");
  if (spend <= 0n) fail("tokenAgentSpend: spendAmount must be > 0", "ZERO_SPEND");
  const position = parseAtomicAmount(params.tokenPositionAmount, "tokenPositionAmount");
  if (spend > position) fail("tokenAgentSpend: spendAmount exceeds the controller's token position — conservation would break", "INSUFFICIENT_TOKENS");
  const adv = advanceAgent(policy, { tokenSpend: spend, kasSpend: 0n, periodsElapsed: params.periodsElapsed }, proof, "tokenAgentSpend");
  const consumed = consumeReserve(s, policy, params.reserveConsumed, "tokenAgentSpend");
  const tokenInputKas = parseSompi(params.tokenInputKas, "tokenInputKas");
  const selfCarryKas = parseSompi(params.selfCarryKas, "selfCarryKas");
  const recipientCarryKas = parseSompi(params.recipientCarryKas, "recipientCarryKas");
  if (recipientCarryKas > policy.agentMaxCarryKas) fail("tokenAgentSpend: recipient carry KAS exceeds this agent's agentMaxCarryKas", "OVER_CARRY_CAP");
  if (selfCarryKas + recipientCarryKas < tokenInputKas) fail("tokenAgentSpend: the token family's KAS would leak (self + recipient carry < token input KAS)", "TOKEN_FAMILY_KAS_LEAK");
  const successor = withChanges(s, { feeReserve: s.feeReserve - consumed, agentRoot: adv.newRoot });
  return Object.freeze({
    action: "tokenAgentSpend",
    successor,
    previousPolicy: policy,
    newPolicy: adv.newPolicy,
    newStart: adv.newStart,
    newSpent: adv.newTokenSpent,
    lockTime: adv.lockTime,
    spendAmount: spend,
    tokenPositionAmount: position,
    tokenSelfAfter: position - spend,
    reserveConsumed: consumed,
    kas: Object.freeze({ tokenInputKas, selfCarryKas, recipientCarryKas }),
    agentProof: proof
  });
}

/*
 * tokenAtomicSell. params: agentPolicy, agentProof, swapPolicy, swapProof,
 * pool { kasReserve, tokenReserve, feeBps, nonce }, protocolFeeBps, amountIn,
 * tokenPositionAmount, poolNoteAmount, minKasOut, periodsElapsed,
 * reserveConsumed, ourNoteKas, ourNoteKasAfter (>= ourNoteKas).
 */
function tokenAtomicSellSuccessorV6(state, params) {
  const s = requireContinuingState(state, "tokenAtomicSell");
  if (s.paused !== 0n) fail("tokenAtomicSell: controller is paused", "PAUSED");
  const { policy, proof } = resolveAgent(s, params, "tokenAtomicSell");
  const { policy: swap, proof: swapProof } = resolveSwapPolicy(s, params, "tokenAtomicSell");
  if ((swap.directionMask & DIRECTION.SELL) === 0n) fail("tokenAtomicSell: this swap policy does not allow SELL", "DIRECTION_FORBIDDEN");
  const quote = poolSellQuote(params.pool, params.amountIn, params.protocolFeeBps);
  const position = parseAtomicAmount(params.tokenPositionAmount, "tokenPositionAmount");
  if (quote.amountIn > position) fail("tokenAtomicSell: amountIn exceeds the controller's token position — conservation would break", "INSUFFICIENT_TOKENS");
  const poolNoteAmount = parseAtomicAmount(params.poolNoteAmount, "poolNoteAmount");
  if (poolNoteAmount !== quote.pool.tokenReserve) fail("tokenAtomicSell: the pool's reserve note amount != its declared tokenReserve — the pool would refuse; failing closed", "POOL_STATE_MISMATCH");
  const minKasOut = parsePositiveSompi(params.minKasOut, "minKasOut");
  const protocolFee = resolveProtocolFee(quote, swap, params, "tokenAtomicSell");
  if (protocolFee >= quote.kasOut) fail("tokenAtomicSell: the protocol fee would consume the whole proceeds", "QUOTE_TOO_SMALL");
  const netProceeds = quote.kasOut - protocolFee;
  if (netProceeds < minKasOut) fail(`tokenAtomicSell: net proceeds ${netProceeds} below minKasOut ${minKasOut}`, "BELOW_MIN_OUT");
  if (netProceeds * swap.sellFloorDen < quote.amountIn * swap.sellFloorNum) fail("tokenAtomicSell: net proceeds below the owner's floor price", "BELOW_FLOOR");
  const adv = advanceAgent(policy, { tokenSpend: quote.amountIn, kasSpend: 0n, periodsElapsed: params.periodsElapsed }, proof, "tokenAtomicSell");
  const consumed = consumeReserve(s, policy, params.reserveConsumed, "tokenAtomicSell");
  const ourNoteKas = parseSompi(params.ourNoteKas, "ourNoteKas");
  const ourNoteKasAfter = parseSompi(params.ourNoteKasAfter ?? params.ourNoteKas, "ourNoteKasAfter");
  if (ourNoteKasAfter < ourNoteKas) fail("tokenAtomicSell: our token note's KAS carry would leak", "TOKEN_FAMILY_KAS_LEAK");
  if (ourNoteKasAfter > ourNoteKas) fail("tokenAtomicSell: our token note's KAS carry may not grow (the fee reserve is never token backing and no external input exists)", "CARRY_GROWTH");
  const typeA = swap.destScheme === DEST_SCHEME.CONTROLLER;
  const successor = withChanges(s, {
    feeReserve: s.feeReserve - consumed,
    swapPrincipal: typeA ? s.swapPrincipal + netProceeds : s.swapPrincipal,
    agentRoot: adv.newRoot
  });
  return Object.freeze({
    action: "tokenAtomicSell",
    direction: "SELL",
    successor,
    previousPolicy: policy,
    newPolicy: adv.newPolicy,
    newStart: adv.newStart,
    newTokenSpent: adv.newTokenSpent,
    newKasSpent: adv.newKasSpent,
    lockTime: adv.lockTime,
    swapPolicy: swap,
    swapProof,
    agentProof: proof,
    quote,
    amountIn: quote.amountIn,
    tokenPositionAmount: position,
    tokenSelfAfter: position - quote.amountIn,
    poolNoteAmount,
    poolNoteAfter: poolNoteAmount + quote.amountIn,
    minKasOut,
    netProceeds,
    protocolFee,
    protocolFeeMinimum: quote.protocolFee,
    destination: Object.freeze(typeA ? { type: "A", scheme: DEST_SCHEME.CONTROLLER, identity: null, outputs: SWAP_OUTPUTS_TYPE_A } : { type: "B", scheme: DEST_SCHEME.P2PK, identity: swap.destIdentity, outputs: SWAP_OUTPUTS_TYPE_B }),
    reserveConsumed: consumed,
    kas: Object.freeze({ ourNoteKas, ourNoteKasAfter, principalDelta: typeA ? netProceeds : 0n }),
    inputs: SWAP_INPUT_COUNT
  });
}

/*
 * tokenAtomicBuy. params: agentPolicy, agentProof, swapPolicy, swapProof,
 * pool, protocolFeeBps, tokensOut, tokenPositionAmount, poolNoteAmount,
 * maxKasIn, periodsElapsed, reserveConsumed, ourNoteKas, ourNoteKasAfter.
 */
function tokenAtomicBuySuccessorV6(state, params) {
  const s = requireContinuingState(state, "tokenAtomicBuy");
  if (s.paused !== 0n) fail("tokenAtomicBuy: controller is paused", "PAUSED");
  const { policy, proof } = resolveAgent(s, params, "tokenAtomicBuy");
  const { policy: swap, proof: swapProof } = resolveSwapPolicy(s, params, "tokenAtomicBuy");
  if ((swap.directionMask & DIRECTION.BUY) === 0n) fail("tokenAtomicBuy: this swap policy does not allow BUY", "DIRECTION_FORBIDDEN");
  if (swap.destScheme !== DEST_SCHEME.CONTROLLER) fail("tokenAtomicBuy: a buy always accrues tokens to the controller's own position (type A) — failing closed", "DESTINATION_FORBIDDEN");
  const quote = poolBuyQuote(params.pool, params.tokensOut, params.protocolFeeBps);
  const position = parseAtomicAmount(params.tokenPositionAmount, "tokenPositionAmount");
  const poolNoteAmount = parseAtomicAmount(params.poolNoteAmount, "poolNoteAmount");
  if (poolNoteAmount !== quote.pool.tokenReserve) fail("tokenAtomicBuy: the pool's reserve note amount != its declared tokenReserve — the pool would refuse; failing closed", "POOL_STATE_MISMATCH");
  const maxKasIn = parsePositiveSompi(params.maxKasIn, "maxKasIn");
  const protocolFee = resolveProtocolFee(quote, swap, params, "tokenAtomicBuy");
  const kasSpend = quote.kasIn + protocolFee;
  if (kasSpend > maxKasIn) fail(`tokenAtomicBuy: consideration ${kasSpend} exceeds maxKasIn ${maxKasIn}`, "ABOVE_MAX_IN");
  if (kasSpend * swap.buyCeilDen > quote.tokensOut * swap.buyCeilNum) fail("tokenAtomicBuy: consideration above the owner's ceiling price", "ABOVE_CEILING");
  if (kasSpend > s.swapPrincipal) fail("tokenAtomicBuy: consideration exceeds the protected swap principal — the fee reserve and token backing are never consideration", "INSUFFICIENT_PRINCIPAL");
  const adv = advanceAgent(policy, { tokenSpend: 0n, kasSpend, periodsElapsed: params.periodsElapsed }, proof, "tokenAtomicBuy");
  const consumed = consumeReserve(s, policy, params.reserveConsumed, "tokenAtomicBuy");
  const ourNoteKas = parseSompi(params.ourNoteKas, "ourNoteKas");
  const ourNoteKasAfter = parseSompi(params.ourNoteKasAfter ?? params.ourNoteKas, "ourNoteKasAfter");
  if (ourNoteKasAfter < ourNoteKas) fail("tokenAtomicBuy: our token note's KAS carry would leak", "TOKEN_FAMILY_KAS_LEAK");
  if (ourNoteKasAfter > ourNoteKas) fail("tokenAtomicBuy: our token note's KAS carry may not grow", "CARRY_GROWTH");
  const successor = withChanges(s, { feeReserve: s.feeReserve - consumed, swapPrincipal: s.swapPrincipal - kasSpend, agentRoot: adv.newRoot });
  return Object.freeze({
    action: "tokenAtomicBuy",
    direction: "BUY",
    successor,
    previousPolicy: policy,
    newPolicy: adv.newPolicy,
    newStart: adv.newStart,
    newTokenSpent: adv.newTokenSpent,
    newKasSpent: adv.newKasSpent,
    lockTime: adv.lockTime,
    swapPolicy: swap,
    swapProof,
    agentProof: proof,
    quote,
    tokensOut: quote.tokensOut,
    tokenPositionAmount: position,
    tokenSelfAfter: position + quote.tokensOut,
    poolNoteAmount,
    poolNoteAfter: poolNoteAmount - quote.tokensOut,
    maxKasIn,
    kasIn: quote.kasIn,
    protocolFee,
    protocolFeeMinimum: quote.protocolFee,
    kasSpend,
    destination: Object.freeze({ type: "A", scheme: DEST_SCHEME.CONTROLLER, identity: null, outputs: SWAP_OUTPUTS_TYPE_A }),
    reserveConsumed: consumed,
    kas: Object.freeze({ ourNoteKas, ourNoteKasAfter, principalDelta: -kasSpend }),
    inputs: SWAP_INPUT_COUNT
  });
}

/* The token continuation states the covenant will template-verify. */
function tokenContinuationStatesV6({ controllerCovenantId, recipientPk, plan }) {
  const covid = normalizeHex(controllerCovenantId, 32, "controllerCovenantId");
  const recipient = normalizeXOnlyPubkey(recipientPk, "recipientPk");
  return Object.freeze({
    selfNew: Object.freeze({ ownerIdentifier: covid, identifierType: OWNER_SCHEMES.COVENANT_ID, amount: plan.tokenSelfAfter, isMinter: false }),
    recipientNew: Object.freeze({ ownerIdentifier: recipient, identifierType: OWNER_SCHEMES.P2PK, amount: plan.spendAmount, isMinter: false })
  });
}
function swapContinuationStatesV6({ controllerCovenantId, plan }) {
  const covid = normalizeHex(controllerCovenantId, 32, "controllerCovenantId");
  const poolId = normalizeHex(plan.swapPolicy.poolCovenantId, 32, "swapPolicy.poolCovenantId");
  return Object.freeze({
    selfNew: Object.freeze({ ownerIdentifier: covid, identifierType: OWNER_SCHEMES.COVENANT_ID, amount: plan.tokenSelfAfter, isMinter: false }),
    poolNoteNew: Object.freeze({ ownerIdentifier: poolId, identifierType: OWNER_SCHEMES.COVENANT_ID, amount: plan.poolNoteAfter, isMinter: false })
  });
}

/* ---------------- owner operations ---------------- */

function setAgentRootSuccessorV6(state, newAgentRoot) {
  const s = requireContinuingState(state, "setAgentRoot");
  const agentRoot = normalizeHex(newAgentRoot, 32, "newAgentRoot");
  return Object.freeze({ successor: withChanges(s, { agentRoot, policyNonce: s.policyNonce + 1n }), opSelector: OWNER_OP_SELECTOR_V6.ownerSetAgentRoot });
}
function topUpReserveSuccessorV6(state, topUpAmount) {
  const s = requireContinuingState(state, "topUpReserve");
  const amount = parsePositiveSompi(topUpAmount, "topUpAmount");
  return Object.freeze({ successor: withChanges(s, { feeReserve: s.feeReserve + amount }), topUpAmount: amount, opSelector: OWNER_OP_SELECTOR_V6.ownerTopUpReserve });
}
function pauseSuccessorV6(state, pause) {
  const s = requireContinuingState(state, pause ? "pause" : "unpause");
  if (pause && s.paused !== 0n) fail("pause: controller is already paused");
  if (!pause && s.paused !== 1n) fail("unpause: controller is not paused");
  return Object.freeze({ successor: withChanges(s, { paused: pause ? 1n : 0n }), opSelector: pause ? OWNER_OP_SELECTOR_V6.ownerPause : OWNER_OP_SELECTOR_V6.ownerUnpause });
}
function setSwapRootSuccessorV6(state, newSwapRoot) {
  const s = requireContinuingState(state, "setSwapRoot");
  const swapRoot = normalizeHex(newSwapRoot, 32, "newSwapRoot");
  return Object.freeze({ successor: withChanges(s, { swapRoot, policyNonce: s.policyNonce + 1n }), opSelector: OWNER_OP_SELECTOR_V6.ownerSetSwapRoot });
}
function fundSwapPrincipalSuccessorV6(state, fundAmount) {
  const s = requireContinuingState(state, "fundSwapPrincipal");
  const amount = parsePositiveSompi(fundAmount, "fundAmount");
  return Object.freeze({ successor: withChanges(s, { swapPrincipal: s.swapPrincipal + amount }), fundAmount: amount, opSelector: OWNER_OP_SELECTOR_V6.ownerFundSwapPrincipal });
}

/* ownerRecover plan (terminal): reserve + principal pay out to the owner; tokens to the owner key. */
function recoverPlanV6(state, ownerXOnly, tokenPositionAmount) {
  if (!state || typeof state !== "object") fail("recover: state is required");
  const owner = normalizeXOnlyPubkey(ownerXOnly, "owner");
  const payout = parseSompi(state.feeReserve, "state.feeReserve") + parseSompi(state.swapPrincipal, "state.swapPrincipal");
  let tokenRecipient = null;
  if (tokenPositionAmount !== null && tokenPositionAmount !== undefined) {
    const amount = parseAtomicAmount(tokenPositionAmount, "tokenPositionAmount");
    tokenRecipient = Object.freeze({ ownerIdentifier: owner, identifierType: OWNER_SCHEMES.P2PK, amount, isMinter: false });
  }
  return Object.freeze({ terminal: true, payout, payoutTo: owner, tokenRecipient });
}

module.exports = {
  MAX_PERIODS_ELAPSED,
  SWAP_INPUT_COUNT,
  SWAP_OUTPUTS_TYPE_A,
  SWAP_OUTPUTS_TYPE_B,
  poolSellQuote,
  poolBuyQuote,
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
  recoverPlanV6
};
