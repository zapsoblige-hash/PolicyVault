"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const tr = require("../vault-transitions-v6");
const am = require("../agent-merkle-v6");
const sp = require("../swap-policy-v6");

/* the exact economics of tests/vm/tests/v6_production.rs (real-engine accepted) */
const POOL = { kasReserve: "1000000", tokenReserve: "10000", feeBps: "30", nonce: "0" };
const agentPk = "62".repeat(32);
const policy = {
  agentPk,
  tokenMaxPerSpend: "600",
  tokenPeriodBudget: "1000",
  periodLengthDaa: "1000",
  periodStartDaa: "5000",
  tokenPeriodSpent: "0",
  agentMaxFeePerTx: "60000",
  agentMaxCarryKas: "25000000",
  kasMaxPerSwap: "50000",
  kasPeriodBudget: "80000",
  kasPeriodSpent: "0",
  agentRecipientRoot: "00".repeat(32)
};
const swapA = {
  profileHash: "aa".repeat(32),
  poolCovenantId: "50".repeat(32),
  poolTemplateVmHash: "70".repeat(32),
  poolPrefixLen: 1,
  poolSuffixLen: 15189,
  poolFeePk: "66".repeat(32),
  maxProtocolFeeKas: "200",
  sellFloorNum: "90",
  sellFloorDen: "1",
  buyCeilNum: "110",
  buyCeilDen: "1",
  directionMask: "3",
  destScheme: 0x02,
  destIdentity: "00".repeat(32)
};
const swapB = { ...swapA, directionMask: "1", destScheme: 0x00, destIdentity: "63".repeat(32) };

function setup() {
  const agents = am.buildTokenAgentTreeV6([policy, { ...policy, agentPk: "65".repeat(32) }]);
  const swaps = sp.buildSwapPolicyTreeV6([swapA, swapB]);
  const state = { feeReserve: "500000000", swapPrincipal: "300000000", paused: "0", agentRoot: agents.root, swapRoot: swaps.root, policyNonce: "0" };
  const ap = am.generateTokenAgentProofV6(agents, agentPk);
  const spA = sp.generateSwapPolicyProofV6(swaps, swapA);
  const spB = sp.generateSwapPolicyProofV6(swaps, swapB);
  const common = { agentPolicy: policy, agentProof: { siblingsHex: ap.siblingsHex, pathBits: ap.pathBits }, pool: POOL, protocolFeeBps: "20", tokenPositionAmount: "3000", poolNoteAmount: "10000", periodsElapsed: 0n, reserveConsumed: "50000", ourNoteKas: "700" };
  return { agents, swaps, state, common, A: { swapPolicy: swapA, swapProof: { siblingsHex: spA.siblingsHex, pathBits: spA.pathBits } }, B: { swapPolicy: swapB, swapProof: { siblingsHex: spB.siblingsHex, pathBits: spB.pathBits } } };
}

test("pool quotes reproduce the real-engine constants exactly (integer arithmetic of the fixture)", () => {
  const s = tr.poolSellQuote(POOL, "500", "20");
  assert.deepEqual([s.newKasReserve, s.kasOut, s.protocolFee, s.netProceeds, s.newTokenReserve], [952_563n, 47_437n, 95n, 47_342n, 10_500n]);
  const b = tr.poolBuyQuote(POOL, "400", "20");
  assert.deepEqual([b.kasIn, b.protocolFee, b.kasSpend, b.newKasReserve, b.newTokenReserve], [41_793n, 84n, 41_877n, 1_041_793n, 9_600n]);
  /* one sompi less never satisfies the invariant the pool enforces */
  const k = 1_000_000n * 10_000n;
  const netLess = b.kasIn - 1n - ((b.kasIn - 1n) * 30n + 9_999n) / 10_000n;
  assert.ok(9_600n * (1_000_000n + netLess) < k);
  assert.throws(() => tr.poolBuyQuote(POOL, "10000", "20"), /drain/);
  assert.throws(() => tr.poolSellQuote(POOL, "1", "20"), /QUOTE_TOO_SMALL|consumed entirely|pay nothing/);
});

test("SELL type A: principal accrues net proceeds; token caps advance; refusals mirror the covenant", () => {
  const { state, common, A } = setup();
  const plan = tr.tokenAtomicSellSuccessorV6(state, { ...common, ...A, amountIn: "500", minKasOut: "47000" });
  assert.equal(plan.successor.swapPrincipal, 300_000_000n + 47_342n);
  assert.equal(plan.successor.feeReserve, 500_000_000n - 50_000n);
  assert.equal(plan.newTokenSpent, 500n);
  assert.equal(plan.newKasSpent, 0n);
  assert.equal(plan.destination.type, "A");
  assert.equal(plan.destination.outputs, 5);
  assert.equal(plan.tokenSelfAfter, 2_500n);
  assert.equal(plan.poolNoteAfter, 10_500n);
  assert.throws(() => tr.tokenAtomicSellSuccessorV6(state, { ...common, ...A, amountIn: "601", minKasOut: "1" }), /tokenMaxPerSpend/);
  assert.throws(() => tr.tokenAtomicSellSuccessorV6(state, { ...common, ...A, amountIn: "500", minKasOut: "47343" }), /below minKasOut/);
  assert.throws(() => tr.tokenAtomicSellSuccessorV6(state, { ...common, ...A, amountIn: "500", minKasOut: "1", poolNoteAmount: "9999" }), /POOL_STATE_MISMATCH|reserve note amount/);
  assert.throws(() => tr.tokenAtomicSellSuccessorV6(state, { ...common, ...A, amountIn: "500", minKasOut: "1", ourNoteKasAfter: "701" }), /may not grow/);
  assert.throws(() => tr.tokenAtomicSellSuccessorV6(state, { ...common, ...A, amountIn: "500", minKasOut: "1", reserveConsumed: "60001" }), /agentMaxFeePerTx/);
  assert.throws(() => tr.tokenAtomicSellSuccessorV6({ ...state, paused: "1" }, { ...common, ...A, amountIn: "500", minKasOut: "1" }), /paused/);
  /* floor: a worse pool (less KAS) drops net proceeds under 90 sompi/token */
  const worse = { ...POOL, kasReserve: "900000" };
  assert.throws(() => tr.tokenAtomicSellSuccessorV6(state, { ...common, ...A, pool: worse, amountIn: "500", minKasOut: "1" }), /floor/);
});

test("SELL type B: principal preserved, destination = allowlisted key, six outputs; BUY under type B refused", () => {
  const { state, common, B } = setup();
  const plan = tr.tokenAtomicSellSuccessorV6(state, { ...common, ...B, amountIn: "500", minKasOut: "47000" });
  assert.equal(plan.successor.swapPrincipal, 300_000_000n);
  assert.equal(plan.destination.type, "B");
  assert.equal(plan.destination.identity, "63".repeat(32));
  assert.equal(plan.destination.outputs, 6);
  assert.throws(() => tr.tokenAtomicBuySuccessorV6(state, { ...common, ...B, tokensOut: "400", maxKasIn: "42000" }), /does not allow BUY/);
});

test("BUY: consideration leaves the principal only; KAS caps advance; ceilings, max-in, exhaustion refuse", () => {
  const { state, common, A } = setup();
  const plan = tr.tokenAtomicBuySuccessorV6(state, { ...common, ...A, tokensOut: "400", maxKasIn: "42000" });
  assert.equal(plan.kasSpend, 41_877n);
  assert.equal(plan.successor.swapPrincipal, 300_000_000n - 41_877n);
  assert.equal(plan.successor.feeReserve, 500_000_000n - 50_000n);
  assert.equal(plan.newKasSpent, 41_877n);
  assert.equal(plan.newTokenSpent, 0n);
  assert.equal(plan.tokenSelfAfter, 3_400n);
  assert.equal(plan.poolNoteAfter, 9_600n);
  assert.throws(() => tr.tokenAtomicBuySuccessorV6(state, { ...common, ...A, tokensOut: "400", maxKasIn: "41876" }), /maxKasIn/);
  assert.throws(() => tr.tokenAtomicBuySuccessorV6(state, { ...common, ...A, tokensOut: "400", maxKasIn: "50000", pool: { ...POOL, kasReserve: "1100000" } }), /ceiling/);
  assert.throws(() => tr.tokenAtomicBuySuccessorV6({ ...state, swapPrincipal: "41876" }, { ...common, ...A, tokensOut: "400", maxKasIn: "42000" }), /protected swap principal/);
  const noBuy = { ...common, agentPolicy: { ...policy, kasMaxPerSwap: "0", kasPeriodBudget: "0" } };
  assert.throws(() => tr.tokenAtomicBuySuccessorV6(state, { ...noBuy, ...A, tokensOut: "400", maxKasIn: "42000" }), /AGENT_PROOF_INVALID|does not verify/);
  const capped = setupWith({ kasMaxPerSwap: "41876", kasPeriodBudget: "80000" });
  assert.throws(() => tr.tokenAtomicBuySuccessorV6(capped.state, { ...capped.common, ...capped.A, tokensOut: "400", maxKasIn: "42000" }), /kasMaxPerSwap/);
  const budgeted = setupWith({ kasPeriodSpent: "38124" });
  assert.throws(() => tr.tokenAtomicBuySuccessorV6(budgeted.state, { ...budgeted.common, ...budgeted.A, tokensOut: "400", maxKasIn: "42000" }), /KAS period budget/);
  /* rollover resets both counters */
  const roll = setupWith({ kasPeriodSpent: "80000", tokenPeriodSpent: "1000" });
  const p2 = tr.tokenAtomicBuySuccessorV6(roll.state, { ...roll.common, ...roll.A, tokensOut: "400", maxKasIn: "42000", periodsElapsed: 1n });
  assert.equal(p2.lockTime, 6000n);
  assert.equal(p2.newKasSpent, 41_877n);
  assert.equal(p2.newTokenSpent, 0n);
});
function setupWith(extra) {
  const p = { ...policy, ...extra };
  const agents = am.buildTokenAgentTreeV6([p, { ...policy, agentPk: "65".repeat(32) }]);
  const swaps = sp.buildSwapPolicyTreeV6([swapA, swapB]);
  const state = { feeReserve: "500000000", swapPrincipal: "300000000", paused: "0", agentRoot: agents.root, swapRoot: swaps.root, policyNonce: "0" };
  const ap = am.generateTokenAgentProofV6(agents, agentPk);
  const spA = sp.generateSwapPolicyProofV6(swaps, swapA);
  return { state, common: { agentPolicy: p, agentProof: { siblingsHex: ap.siblingsHex, pathBits: ap.pathBits }, pool: POOL, protocolFeeBps: "20", tokenPositionAmount: "3000", poolNoteAmount: "10000", periodsElapsed: 0n, reserveConsumed: "50000", ourNoteKas: "700" }, A: { swapPolicy: swapA, swapProof: { siblingsHex: spA.siblingsHex, pathBits: spA.pathBits } } };
}

test("stale or unapproved swap policy never plans; spend preserves the principal; owner ops; recover pays both domains", () => {
  const { state, common, A, swaps } = setup();
  const other = sp.buildSwapPolicyTreeV6([swapA]);
  const stale = { ...state, swapRoot: other.root };
  assert.throws(() => tr.tokenAtomicSellSuccessorV6(stale, { ...common, ...A, amountIn: "500", minKasOut: "1" }), /SWAP_PROOF_INVALID|does not verify/);
  assert.ok(swaps.root !== other.root);
  const spend = tr.tokenAgentSpendSuccessorV6(state, { agentPolicy: policy, agentProof: common.agentProof, spendAmount: "200", tokenPositionAmount: "3000", periodsElapsed: 0n, reserveConsumed: "50000", tokenInputKas: "200000000", selfCarryKas: "180000000", recipientCarryKas: "20000000" });
  assert.equal(spend.successor.swapPrincipal, 300_000_000n);
  assert.equal(tr.setSwapRootSuccessorV6(state, "22".repeat(32)).successor.policyNonce, 1n);
  assert.equal(tr.setSwapRootSuccessorV6(state, "22".repeat(32)).opSelector, 4);
  const fund = tr.fundSwapPrincipalSuccessorV6(state, "50000000");
  assert.equal(fund.successor.swapPrincipal, 350_000_000n);
  assert.equal(fund.opSelector, 5);
  assert.throws(() => tr.fundSwapPrincipalSuccessorV6(state, "0"), /greater than zero/);
  const rec = tr.recoverPlanV6(state, "aa".repeat(32), "3000");
  assert.equal(rec.payout, 800_000_000n);
  assert.equal(rec.tokenRecipient.amount, 3000n);
});
