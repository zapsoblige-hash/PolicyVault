"use strict";

/*
 * PolicyVault v0.6 PRODUCTION-BYTE vector generator.
 *
 * Drives the ACTUAL SDK code — core/assets, token-program-kcc20 (silverc on
 * the vendored KCC20 reference program), vault-state-v6, contract-compiler-v6
 * (silverc), agent-merkle-v6, swap-policy-v6 (venue profile + owner leaf),
 * recipient-merkle-v3, vault-transitions-v6 (exact pool quotes),
 * compute-budget-v6, storage-mass, frozen-tx-v3, swap-pool-fixture-v6,
 * vault-builders-v6, and the REAL pv_call_encoder (v0.6, kcc20/1 leader +
 * delegate, v6-pool-fixture/1 arms) — to construct fully-finalized v0.6
 * transactions with real Schnorr signatures (rusty-kaspa WASM
 * createInputSignature over deterministic TEST-ONLY keys).
 * tests/vm/tests/v6_sdk_integration.rs executes every emitted vector's EXACT
 * bytes on the real TxScriptEngine against the CANDIDATE PolicyVault.v0.6.sil,
 * the token family's own program and the pool fixture.
 *
 * Negative vectors are otherwise-valid transactions with ONE security field
 * mutated after freeze/finalize (the SDK itself refuses to build them) and
 * MUST be rejected by consensus (`rejectInput` names the refusing input).
 *
 * Usage: node gen-v6-vectors.js <output-dir>
 * TEST KEYS ONLY: secrets are the byte value repeated 32x. Never production material.
 */

const fs = require("fs");
const path = require("path");

const { loadConfig } = require("../src/config");
const assets = require("../../core/assets");
const { compileKcc20Program } = require("../src/token-program-kcc20");
const { buildTokenAgentTreeV6 } = require("../src/agent-merkle-v6");
const { buildRecipientTree } = require("../src/recipient-merkle-v3");
const { buildSwapPolicyTreeV6, swapPolicyFromProfileV6, computeSwapVenueProfileHash } = require("../src/swap-policy-v6");
const { compilePoolFixtureV6, poolFixtureVenueProfile } = require("../src/swap-pool-fixture-v6");
const { buildV6Transaction, buildCreateV6, finalizeV6Transaction, buildTokenDepositV6, finalizeTokenDepositV6 } = require("../src/vault-builders-v6");
const { frozenToWasmTransaction } = require("../src/frozen-tx-v3");

const outDir = process.argv[2];
if (!outDir) {
  console.error("usage: node gen-v6-vectors.js <output-dir>");
  process.exit(1);
}
fs.mkdirSync(outDir, { recursive: true });

const config = loadConfig({ dataRoot: path.join(outDir, "data") });
const kaspa = require(config.rustyKaspaModule);

const KAS = 100000000n;
const KEY = (v) => new kaspa.PrivateKey(v.toString(16).padStart(2, "0").repeat(32));
const XO = (p) => p.toPublicKey().toXOnlyPublicKey().toString().toLowerCase();

const owner = KEY(0x61);
const agent = KEY(0x62);
const recipient = KEY(0x63);
const fuelKey = KEY(0x64);
const other = KEY(0x65);
const poolFee = KEY(0x66);
const attacker = KEY(0x67);

const OWNER = XO(owner);
const CONTROLLER_ID = "43".repeat(32);
const TOKEN_FAMILY = "54".repeat(32);
const POOL_ID = "50".repeat(32);
const VAULT_ID = "44".repeat(32);
const FAMILY_BOUND = 2;

/* ---- the accepted asset descriptor, derived from the vendored program's real bytes ---- */
const refProgram = compileKcc20Program({ config, state: assets.kcc20.ZERO_STATE, familyBound: FAMILY_BOUND });
const descriptor = {
  schema: "policyvault-asset-descriptor/1",
  assetId: "11".repeat(32),
  displayName: "Vector Token",
  tokenStandard: "kcc20/1",
  tokenCovenantId: TOKEN_FAMILY,
  acceptedTransferTemplates: [{ templateVmHashBlake2b256: refProgram.templateVmHashBlake2b256, prefixLen: refProgram.geometry.prefixLen, suffixLen: refProgram.geometry.suffixLen, stateLayout: "kcc20-state/1" }],
  decimalsDisplay: 8,
  issuerPowers: { mint: false, burn: false, freeze: false, blacklist: false, redemptionControl: false, upgradeMigration: false, controllerRotation: false, emergencyControl: false }
};
const descriptorHash = assets.computeDescriptorHash(descriptor);
const template = { owner: OWNER, vaultId: VAULT_ID, descriptorHash, tokenCovenantId: TOKEN_FAMILY, templateVmHash: refProgram.templateVmHashBlake2b256, templatePrefixLen: refProgram.geometry.prefixLen, templateStateLen: refProgram.geometry.stateLen, templateSuffixLen: refProgram.geometry.suffixLen };

/* ---- pool economics (10,000 KAS / 10,000 tokens; 30 bps pool fee; 20 bps protocol fee) ---- */
const POOL_KAS = 10_000n * KAS;
const POOL_TOKENS = 10_000n;
const poolState = (over = {}) => ({ kasReserve: POOL_KAS.toString(), tokenReserve: POOL_TOKENS.toString(), feeBps: "30", nonce: "0", ...over });
function poolCompiled(state = poolState()) {
  return compilePoolFixtureV6({ config, params: { tokenCovenantId: TOKEN_FAMILY, kcc20: { prefixHex: refProgram.prefixHex, suffixHex: refProgram.suffixHex, templateVmHashBlake2b256: refProgram.templateVmHashBlake2b256 }, protocolFeePk: XO(poolFee), protocolFeeBps: "20", ...state } });
}
const pool0 = poolCompiled();
const venueProfile = poolFixtureVenueProfile({ networkId: config.networkId, poolCovenantId: POOL_ID, compiled: pool0, profileId: "vector-pool-fixture" });
const profileHash = computeSwapVenueProfileHash(venueProfile);
/* pool price = 1 KAS/token; owner floor 0.9 KAS/token (SELL), ceiling 1.1 KAS/token (BUY); protocol fee cap 5 KAS */
const ownerPolicyA = { maxProtocolFeeKas: (5n * KAS).toString(), sellFloorNum: (9n * KAS / 10n).toString(), sellFloorDen: "1", buyCeilNum: (11n * KAS / 10n).toString(), buyCeilDen: "1", directionMask: "3", destScheme: 0x02 };
const swapA = swapPolicyFromProfileV6(venueProfile, ownerPolicyA);
const swapB = swapPolicyFromProfileV6(venueProfile, { ...ownerPolicyA, directionMask: "1", destScheme: 0x00, destIdentity: XO(recipient) });
const swapBuyOnly = swapPolicyFromProfileV6(venueProfile, { ...ownerPolicyA, directionMask: "2" });
const swapPolicies = [swapA, swapB, swapBuyOnly];
const swapTree = buildSwapPolicyTreeV6(swapPolicies);

function recipTreeAtDepth(depth) {
  if (depth === 0) return buildRecipientTree([XO(recipient)]);
  const n = 1 << depth;
  const fillers = [];
  for (let i = 0; fillers.length < n - 1 && i <= 0xffffff; i++) {
    const k = i.toString(16).padStart(6, "0").repeat(11).slice(0, 64);
    if (k !== XO(recipient) && k !== XO(other)) fillers.push(k);
  }
  return buildRecipientTree([XO(recipient), ...fillers]);
}
function agentPolicy(pkHex, recipientRoot, over = {}) {
  return {
    agentPk: pkHex,
    tokenMaxPerSpend: "600",
    tokenPeriodBudget: "1000",
    periodLengthDaa: "1000",
    periodStartDaa: "5000",
    tokenPeriodSpent: "0",
    agentMaxFeePerTx: (1n * KAS).toString(),
    agentMaxCarryKas: (KAS / 4n).toString(),
    kasMaxPerSwap: (500n * KAS).toString(),
    kasPeriodBudget: (800n * KAS).toString(),
    kasPeriodSpent: "0",
    agentRecipientRoot: recipientRoot,
    ...over
  };
}
function agentSetAtDepth(depth, aPolicy) {
  if (depth === 0) return [aPolicy];
  const n = 1 << depth;
  const agents = [aPolicy];
  for (let i = 1; i < n; i++) {
    const pk = i.toString(16).padStart(8, "0").repeat(8);
    agents.push(agentPolicy(pk, ("f" + i.toString(16)).padStart(4, "0").repeat(16).slice(0, 64), { tokenMaxPerSpend: "1", tokenPeriodBudget: "1", kasMaxPerSwap: "0", kasPeriodBudget: "0" }));
  }
  return agents;
}
function state(agentRoot, over = {}) {
  return { feeReserve: (5n * KAS).toString(), swapPrincipal: (1000n * KAS).toString(), paused: "0", agentRoot, swapRoot: swapTree.root, policyNonce: "0", ...over };
}
function tokenPositionFor(amount) {
  const st = { ownerIdentifier: CONTROLLER_ID, identifierType: 2, amount: String(amount), isMinter: false };
  const program = compileKcc20Program({ config, state: st, familyBound: FAMILY_BOUND });
  return { outpoint: { transactionId: "02".repeat(32), index: 0 }, value: (2n * KAS).toString(), scriptPublicKeyHex: program.p2shSpkHex, covenantId: TOKEN_FAMILY, state: st };
}
function poolNoteFor(amount) {
  const st = { ownerIdentifier: POOL_ID, identifierType: 2, amount: String(amount), isMinter: false };
  const program = compileKcc20Program({ config, state: st, familyBound: FAMILY_BOUND });
  return { outpoint: { transactionId: "08".repeat(32), index: 0 }, value: (2n * KAS).toString(), scriptPublicKeyHex: program.p2shSpkHex, covenantId: TOKEN_FAMILY, state: st };
}
function chain({ reserve, principal = 1000n * KAS, fuel = true, position = true, tokenAmount = 3000, swap = false }) {
  const ctx = { predecessorOutpoint: { transactionId: "01".repeat(32), index: 0 }, predecessorValue: (BigInt(reserve) + principal).toString(), covenantId: CONTROLLER_ID };
  if (fuel && !swap) ctx.fuel = { outpoint: { transactionId: "03".repeat(32), index: 0 }, amount: (1n * KAS).toString(), scriptPublicKeyHex: `20${XO(fuelKey)}ac` };
  if (position) ctx.tokenPosition = tokenPositionFor(tokenAmount);
  if (swap) {
    ctx.poolNote = poolNoteFor(POOL_TOKENS);
    ctx.pool = { outpoint: { transactionId: "09".repeat(32), index: 0 }, value: POOL_KAS.toString(), scriptPublicKeyHex: pool0.p2shSpkHex, covenantId: POOL_ID, state: poolState() };
  }
  return ctx;
}
function signCov(build, kp) {
  return kaspa.createInputSignature(frozenToWasmTransaction(config, build.frozen), 0, kp).slice(2);
}
function signFuel(build) {
  return kaspa.createInputSignature(frozenToWasmTransaction(config, build.frozen), build.frozen.inputs.length - 1, fuelKey);
}
function finalize(build, kp, currentDaaScore = "9000000") {
  return finalizeV6Transaction({ build, covenantSignatureHex: signCov(build, kp), fuelSignatureScriptHex: build.hasFuelInput ? signFuel(build) : undefined, currentDaaScore: build.swap ? currentDaaScore : undefined }).finalTransaction;
}

const refusals = [];
function refuses(name, f, codeRe) {
  try {
    f();
    refusals.push({ name, refused: false });
  } catch (e) {
    refusals.push({ name, refused: true, code: e.code ?? null, message: String(e.message).slice(0, 200), ok: codeRe ? codeRe.test(e.code ?? e.message) : true });
  }
}
const vectors = [];
function emit(name, expect, build, finalTx, rejectInput = 0) {
  vectors.push({ name, expect });
  const dir = path.join(outDir, name);
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, "vector.json"), JSON.stringify({ name, expect, rejectInput, action: build?.action ?? "unknown", committedBudget: build?.computeBudget ?? null, requiredFeeSompi: build?.requiredFeeSompi ?? null, accounting: build?.accounting ?? null, swap: build?.swap ?? null, tx: finalTx }, null, 1));
}

/* ================================================================ POSITIVE */
const rTree0 = recipTreeAtDepth(0);
const policy0 = agentPolicy(XO(agent), rTree0.root);
const agents0 = [policy0, agentPolicy(XO(other), rTree0.root)];
const tree0 = buildTokenAgentTreeV6(agents0);

const spendParams = (agents, recips, over = {}) => ({ spendAmount: "200", agentPk: XO(agent), agents, recipient: XO(recipient), recipients: [...recips], recipientCarryKasSompi: (KAS / 5n).toString(), reserveConsumedSompi: "50000", ...over });
const swapCommon = (agents, over = {}) => ({ agentPk: XO(agent), agents, swapPolicies, swapPolicy: swapA, venueProfile, deadlineDaa: "10000000", ...over });
const RESERVE = (5n * KAS).toString();

/* 1. atomic SELL type A (proceeds accrue to the principal) */
{
  const build = buildV6Transaction({ config, templateInput: template, stateInput: state(tree0.root), action: "tokenAtomicSell", params: swapCommon(agents0, { amountIn: "500", minKasOut: (400n * KAS).toString() }), chain: chain({ reserve: RESERVE, swap: true }), changeXOnly: XO(fuelKey), descriptor });
  if (build.swap.destination.type !== "A" || build.frozen.outputs.length !== 5 || build.frozen.inputs.length !== 4) throw new Error("sell A shape");
  const tx = finalize(build, agent);
  emit("swap_sell_type_a", "accept", build, tx);
  const mut = (f) => { const j = JSON.parse(JSON.stringify(tx)); f(j); return j; };
  emit("neg_swap_principal_inflated", "reject", build, mut((j) => { j.outputs[0].value = (BigInt(j.outputs[0].value) + 1n).toString(); j.outputs[4].value = (BigInt(j.outputs[4].value) - 1n).toString(); }));
  emit("neg_swap_hidden_extra_output", "reject", build, mut((j) => { j.outputs[4].value = (BigInt(j.outputs[4].value) - 1000n).toString(); j.outputs.push({ value: "1000", scriptPublicKey: { version: 0, scriptHex: `20${XO(attacker)}ac` }, covenant: null }); }));
  emit("neg_swap_pool_family_swapped", "reject", build, mut((j) => { j.inputs[3].utxo.covenantId = "57".repeat(32); j.outputs[3].covenant.covenantId = "57".repeat(32); }));
  emit("neg_swap_external_kas_input", "reject", build, mut((j) => { j.inputs.push({ previousOutpoint: { transactionId: "0a".repeat(32), index: 0 }, signatureScript: "", sequence: "0", computeBudget: 10, utxo: { amount: KAS.toString(), scriptPublicKey: { version: 0, scriptHex: `20${XO(fuelKey)}ac` }, covenantId: null, blockDaaScore: "0" } }); j.outputs[4].value = (BigInt(j.outputs[4].value) + KAS).toString(); }));
  emit("neg_swap_our_note_kas_leak", "reject", build, mut((j) => { j.outputs[1].value = (BigInt(j.outputs[1].value) - 1n).toString(); j.outputs[4].value = (BigInt(j.outputs[4].value) + 1n).toString(); }));
  emit("neg_swap_protocol_fee_redirected", "reject", build, mut((j) => { j.outputs[4].scriptPublicKey.scriptHex = `20${XO(attacker)}ac`; }));
  emit("neg_swap_locktime_forged", "reject", build, mut((j) => { j.lockTime = "7000"; }));
  emit("neg_swap_wrong_signer", "reject", build, finalize(build, owner));
  emit("neg_swap_attacker_signer", "reject", build, finalize(build, attacker));
  /* the POOL refuses an invariant break the controller's envelope tolerates: the pool pays 1 KAS more than k allows */
  emit("neg_swap_pool_invariant_break", "reject", build, mut((j) => { j.outputs[3].value = (BigInt(j.outputs[3].value) - KAS).toString(); j.outputs[0].value = (BigInt(j.outputs[0].value) + KAS).toString(); }), 3);
}
/* 2. atomic SELL type B (proceeds to the allowlisted key) */
{
  const build = buildV6Transaction({ config, templateInput: template, stateInput: state(tree0.root), action: "tokenAtomicSell", params: swapCommon(agents0, { swapPolicy: swapB, amountIn: "500", minKasOut: (400n * KAS).toString() }), chain: chain({ reserve: RESERVE, swap: true }), changeXOnly: XO(fuelKey), descriptor });
  if (build.swap.destination.type !== "B" || build.frozen.outputs.length !== 6) throw new Error("sell B shape");
  const tx = finalize(build, agent);
  emit("swap_sell_type_b", "accept", build, tx);
  const mut = (f) => { const j = JSON.parse(JSON.stringify(tx)); f(j); return j; };
  emit("neg_swap_proceeds_redirected", "reject", build, mut((j) => { j.outputs[5].scriptPublicKey.scriptHex = `20${XO(attacker)}ac`; }));
  emit("neg_swap_proceeds_short_paid", "reject", build, mut((j) => { j.outputs[5].value = (BigInt(j.outputs[5].value) - 1n).toString(); j.outputs[4].value = (BigInt(j.outputs[4].value) + 1n).toString(); }));
}
/* 3. atomic BUY (consideration from the principal) */
{
  const build = buildV6Transaction({ config, templateInput: template, stateInput: state(tree0.root), action: "tokenAtomicBuy", params: swapCommon(agents0, { tokensOut: "400", maxKasIn: (450n * KAS).toString() }), chain: chain({ reserve: RESERVE, swap: true }), changeXOnly: XO(fuelKey), descriptor });
  if (build.frozen.outputs.length !== 5) throw new Error("buy shape");
  const tx = finalize(build, agent);
  emit("swap_buy", "accept", build, tx);
  const mut = (f) => { const j = JSON.parse(JSON.stringify(tx)); f(j); return j; };
  emit("neg_buy_consideration_mismatch", "reject", build, mut((j) => { j.outputs[3].value = (BigInt(j.outputs[3].value) + 1n).toString(); j.outputs[0].value = (BigInt(j.outputs[0].value) - 1n).toString(); }));
  emit("neg_buy_principal_kept", "reject", build, mut((j) => { j.outputs[0].value = (BigInt(j.outputs[0].value) + 1n).toString(); j.outputs[4].value = (BigInt(j.outputs[4].value) - 1n).toString(); }));
  emit("neg_buy_wrong_signer", "reject", build, finalize(build, owner));
}
/* 4. swaps at production tree depths (agent depth 12; swap tree depth 2) */
{
  const agents = agentSetAtDepth(12, policy0);
  const tree = buildTokenAgentTreeV6(agents);
  const sell = buildV6Transaction({ config, templateInput: template, stateInput: state(tree.root), action: "tokenAtomicSell", params: swapCommon(agents, { amountIn: "500", minKasOut: (400n * KAS).toString() }), chain: chain({ reserve: RESERVE, swap: true }), changeXOnly: XO(fuelKey), descriptor });
  emit("swap_sell_depth12", "accept", sell, finalize(sell, agent));
  const buy = buildV6Transaction({ config, templateInput: template, stateInput: state(tree.root), action: "tokenAtomicBuy", params: swapCommon(agents, { tokensOut: "400", maxKasIn: (450n * KAS).toString() }), chain: chain({ reserve: RESERVE, swap: true }), changeXOnly: XO(fuelKey), descriptor });
  emit("swap_buy_depth12", "accept", buy, finalize(buy, agent));
}
/* 5. swap after a period rollover (both counters reset) */
{
  const spent = agentPolicy(XO(agent), rTree0.root, { tokenPeriodSpent: "1000", kasPeriodSpent: (800n * KAS).toString() });
  const agents = [spent, agentPolicy(XO(other), rTree0.root)];
  const tree = buildTokenAgentTreeV6(agents);
  const build = buildV6Transaction({ config, templateInput: template, stateInput: state(tree.root), action: "tokenAtomicBuy", params: swapCommon(agents, { tokensOut: "400", maxKasIn: (450n * KAS).toString(), periodsElapsed: "2" }), chain: chain({ reserve: RESERVE, swap: true }), changeXOnly: XO(fuelKey), descriptor });
  if (build.frozen.lockTime !== 7000n) throw new Error("rollover lockTime must be 7000");
  emit("swap_buy_rollover", "accept", build, finalize(build, agent));
}
/* 6. v0.5-shaped token spend (fuel + reserve-funded) */
{
  const build = buildV6Transaction({ config, templateInput: template, stateInput: state(tree0.root), action: "tokenAgentSpend", params: spendParams(agents0, rTree0.recipients), chain: chain({ reserve: RESERVE }), changeXOnly: XO(fuelKey), descriptor });
  const tx = finalize(build, agent);
  emit("spend_fuel", "accept", build, tx);
  const mut = (f) => { const j = JSON.parse(JSON.stringify(tx)); f(j); return j; };
  emit("neg_spend_principal_drained_to_change", "reject", build, mut((j) => { j.outputs[0].value = (BigInt(j.outputs[0].value) - 1000000n).toString(); j.outputs[3].value = (BigInt(j.outputs[3].value) + 1000000n).toString(); }));
  const rf = buildV6Transaction({ config, templateInput: template, stateInput: state(tree0.root), action: "tokenAgentSpend", params: spendParams(agents0, rTree0.recipients, { reserveConsumedSompi: undefined }), chain: chain({ reserve: RESERVE, fuel: false }), changeXOnly: XO(fuelKey), descriptor });
  emit("spend_reserve_funded", "accept", rf, finalize(rf, agent));
}
/* 7. owner ops (all six selectors) */
{
  const st = state(tree0.root);
  for (const [name, action, params] of [
    ["owner_set_agent_root", "ownerSetAgentRoot", { newAgents: [agentPolicy(XO(other), rTree0.root)] }],
    ["owner_top_up_reserve", "ownerTopUpReserve", { topUpReserveAmountSompi: (KAS / 2n).toString() }],
    ["owner_pause", "ownerPause", {}],
    ["owner_set_swap_root", "ownerSetSwapRoot", { newSwapPolicies: [swapA] }],
    ["owner_fund_swap_principal", "ownerFundSwapPrincipal", { fundSwapPrincipalSompi: (KAS / 2n).toString() }]
  ]) {
    const build = buildV6Transaction({ config, templateInput: template, stateInput: st, action, params, chain: chain({ reserve: RESERVE, position: false }), changeXOnly: XO(fuelKey), descriptor });
    emit(name, "accept", build, finalize(build, owner));
    if (name === "owner_fund_swap_principal") emit("neg_owner_op_agent_signed", "reject", build, finalize(build, agent));
  }
  const paused = state(tree0.root, { paused: "1" });
  const build = buildV6Transaction({ config, templateInput: template, stateInput: paused, action: "ownerUnpause", params: {}, chain: chain({ reserve: RESERVE, position: false }), changeXOnly: XO(fuelKey), descriptor });
  emit("owner_unpause", "accept", build, finalize(build, owner));
}
/* 8. recover with and without a position: reserve + principal pay out */
{
  const st = state(tree0.root);
  const withPos = buildV6Transaction({ config, templateInput: template, stateInput: st, action: "ownerRecover", params: {}, chain: chain({ reserve: RESERVE }), changeXOnly: XO(fuelKey), descriptor });
  if (withPos.frozen.outputs[0].value !== 1005n * KAS) throw new Error("recover payout must be reserve + principal");
  emit("recover_with_position", "accept", withPos, finalize(withPos, owner));
  const noPos = buildV6Transaction({ config, templateInput: template, stateInput: st, action: "ownerRecover", params: {}, chain: chain({ reserve: RESERVE, position: false }), changeXOnly: XO(fuelKey), descriptor });
  emit("recover_without_position", "accept", noPos, finalize(noPos, owner));
  emit("neg_recover_agent_signed", "reject", withPos, finalize(withPos, agent));
}
/* 9. genesis */
{
  const build = buildCreateV6({ config, templateInput: template, initialStateInput: state(tree0.root), funding: [{ outpoint: { transactionId: "05".repeat(32), index: 0 }, amount: (1100n * KAS).toString(), scriptPublicKeyHex: `20${XO(fuelKey)}ac` }], changeXOnly: XO(fuelKey), descriptor });
  const wasm = frozenToWasmTransaction(config, build.frozen);
  const json = JSON.parse(build.frozenCanonicalJson);
  json.inputs[0].signatureScript = kaspa.createInputSignature(wasm, 0, fuelKey);
  emit("genesis_controller", "accept", build, json);
}
/* 10. deposit into a v0.6 controller (v0.5 mechanics, relabeled) */
{
  const user = KEY(0x68);
  const userState = { ownerIdentifier: XO(user), identifierType: 0, amount: "1000", isMinter: false };
  const userProgram = compileKcc20Program({ config, state: userState, familyBound: FAMILY_BOUND });
  const depositChain = { userPosition: { outpoint: { transactionId: "06".repeat(32), index: 0 }, value: (3n * KAS).toString(), scriptPublicKeyHex: userProgram.p2shSpkHex, covenantId: TOKEN_FAMILY, state: userState }, fuel: { outpoint: { transactionId: "07".repeat(32), index: 0 }, amount: (1n * KAS).toString(), scriptPublicKeyHex: `20${XO(fuelKey)}ac` } };
  const full = buildTokenDepositV6({ config, descriptor, controller: { covenantId: CONTROLLER_ID, template }, chain: depositChain, params: { depositAmount: "1000" }, changeXOnly: XO(fuelKey) });
  if (full.contractVersion !== "policyvault-0.6") throw new Error("deposit label");
  const tx = finalizeTokenDepositV6({ build: full, tokenOwnerSignatureHex: kaspa.createInputSignature(frozenToWasmTransaction(config, full.frozen), 0, user).slice(2), fuelSignatureScriptHex: kaspa.createInputSignature(frozenToWasmTransaction(config, full.frozen), 1, fuelKey) }).finalTransaction;
  emit("deposit_full", "accept", full, tx);
}

/* ================================================================ SDK REFUSALS (must throw before any bytes exist) */
const sellOk = (over = {}, chainOver = {}) => buildV6Transaction({ config, templateInput: template, stateInput: state(tree0.root), action: "tokenAtomicSell", params: swapCommon(agents0, { amountIn: "500", minKasOut: (400n * KAS).toString(), ...over }), chain: { ...chain({ reserve: RESERVE, swap: true }), ...chainOver }, changeXOnly: XO(fuelKey), descriptor });
const buyOk = (over = {}, chainOver = {}) => buildV6Transaction({ config, templateInput: template, stateInput: state(tree0.root), action: "tokenAtomicBuy", params: swapCommon(agents0, { tokensOut: "400", maxKasIn: (450n * KAS).toString(), ...over }), chain: { ...chain({ reserve: RESERVE, swap: true }), ...chainOver }, changeXOnly: XO(fuelKey), descriptor });
refuses("swap_sell_over_token_cap", () => sellOk({ amountIn: "601" }), /OVER_CAP/);
refuses("swap_sell_budget_exhausted", () => { const a = [agentPolicy(XO(agent), rTree0.root, { tokenPeriodSpent: "501" }), agents0[1]]; const t = buildTokenAgentTreeV6(a); buildV6Transaction({ config, templateInput: template, stateInput: state(t.root), action: "tokenAtomicSell", params: swapCommon(a, { amountIn: "500", minKasOut: (400n * KAS).toString() }), chain: chain({ reserve: RESERVE, swap: true }), changeXOnly: XO(fuelKey), descriptor }); }, /OVER_BUDGET/);
refuses("swap_sell_below_min_out", () => sellOk({ minKasOut: (480n * KAS).toString() }), /BELOW_MIN_OUT/);
refuses("swap_sell_below_floor", () => sellOk({ minKasOut: "1" }, { pool: { ...chain({ reserve: RESERVE, swap: true }).pool, value: (8_000n * KAS).toString(), state: poolState({ kasReserve: (8_000n * KAS).toString() }), scriptPublicKeyHex: poolCompiled(poolState({ kasReserve: (8_000n * KAS).toString() })).p2shSpkHex } }), /BELOW_FLOOR/);
refuses("swap_buy_above_ceiling", () => buyOk({ maxKasIn: (600n * KAS).toString() }, { pool: { ...chain({ reserve: RESERVE, swap: true }).pool, value: (12_000n * KAS).toString(), state: poolState({ kasReserve: (12_000n * KAS).toString() }), scriptPublicKeyHex: poolCompiled(poolState({ kasReserve: (12_000n * KAS).toString() })).p2shSpkHex } }), /ABOVE_CEILING/);
refuses("swap_buy_above_max_in", () => buyOk({ maxKasIn: (410n * KAS).toString() }), /ABOVE_MAX_IN/);
refuses("swap_buy_over_kas_cap", () => { const a = [agentPolicy(XO(agent), rTree0.root, { kasMaxPerSwap: (400n * KAS).toString() }), agents0[1]]; const t = buildTokenAgentTreeV6(a); buildV6Transaction({ config, templateInput: template, stateInput: state(t.root), action: "tokenAtomicBuy", params: swapCommon(a, { tokensOut: "400", maxKasIn: (450n * KAS).toString() }), chain: chain({ reserve: RESERVE, swap: true }), changeXOnly: XO(fuelKey), descriptor }); }, /OVER_KAS_CAP/);
refuses("swap_buy_principal_exhausted", () => buildV6Transaction({ config, templateInput: template, stateInput: state(tree0.root, { swapPrincipal: (400n * KAS).toString() }), action: "tokenAtomicBuy", params: swapCommon(agents0, { tokensOut: "400", maxKasIn: (450n * KAS).toString() }), chain: chain({ reserve: RESERVE, principal: 400n * KAS, swap: true }), changeXOnly: XO(fuelKey), descriptor }), /INSUFFICIENT_PRINCIPAL/);
refuses("swap_buy_under_sell_only_leaf", () => buyOk({ swapPolicy: swapB }), /DIRECTION_FORBIDDEN/);
refuses("swap_sell_under_buy_only_leaf", () => sellOk({ swapPolicy: swapBuyOnly }), /DIRECTION_FORBIDDEN/);
refuses("swap_unapproved_pool_family", () => sellOk({}, { pool: { ...chain({ reserve: RESERVE, swap: true }).pool, covenantId: "57".repeat(32) } }), /WRONG_POOL_FAMILY/);
refuses("swap_pool_state_stale", () => sellOk({}, { pool: { ...chain({ reserve: RESERVE, swap: true }).pool, state: poolState({ nonce: "1" }) } }), /POOL_STATE_MISMATCH/);
refuses("swap_profile_substituted", () => sellOk({ venueProfile: { ...venueProfile, feeModel: { ...venueProfile.feeModel, protocolFeeBps: "10" } } }), /PROFILE_PIN_MISMATCH/);
refuses("swap_stale_swap_root", () => buildV6Transaction({ config, templateInput: template, stateInput: state(tree0.root, { swapRoot: buildSwapPolicyTreeV6([swapA]).root }), action: "tokenAtomicSell", params: swapCommon(agents0, { amountIn: "500", minKasOut: (400n * KAS).toString() }), chain: chain({ reserve: RESERVE, swap: true }), changeXOnly: XO(fuelKey), descriptor }), /SWAP_ROOT_MISMATCH/);
refuses("swap_fuel_forbidden", () => sellOk({}, { fuel: { outpoint: { transactionId: "03".repeat(32), index: 0 }, amount: KAS.toString(), scriptPublicKeyHex: `20${XO(fuelKey)}ac` } }), /FUEL_FORBIDDEN/);
refuses("swap_deadline_missing", () => sellOk({ deadlineDaa: undefined }), /deadlineDaa/);
refuses("swap_pool_note_amount_mismatch", () => sellOk({}, { poolNote: poolNoteFor(9_999n) }), /POOL_STATE_MISMATCH/);
refuses("swap_storage_mass_dust_note_carry", () => sellOk({}, { tokenPosition: { ...tokenPositionFor(3000), value: "100000" } }), /STORAGE_MASS_OVER_LIMIT/);
refuses("swap_protocol_fee_over_owner_max", () => sellOk({ protocolFeeSompi: (6n * KAS).toString() }), /PROTOCOL_FEE_OVER_MAX/);
refuses("swap_paused", () => buildV6Transaction({ config, templateInput: template, stateInput: state(tree0.root, { paused: "1" }), action: "tokenAtomicSell", params: swapCommon(agents0, { amountIn: "500", minKasOut: (400n * KAS).toString() }), chain: chain({ reserve: RESERVE, swap: true }), changeXOnly: XO(fuelKey), descriptor }), /PAUSED/);
refuses("swap_deadline_passed_at_finalize", () => { const b = sellOk(); finalize(b, agent, "10000001"); }, /DEADLINE_PASSED/);
refuses("spend_over_cap", () => buildV6Transaction({ config, templateInput: template, stateInput: state(tree0.root), action: "tokenAgentSpend", params: spendParams(agents0, rTree0.recipients, { spendAmount: "601" }), chain: chain({ reserve: RESERVE }), changeXOnly: XO(fuelKey), descriptor }), /OVER_CAP/);
refuses("spend_with_v5_policy_shape", () => { const { kasMaxPerSwap, kasPeriodBudget, kasPeriodSpent, ...v5 } = policy0; buildV6Transaction({ config, templateInput: template, stateInput: state(tree0.root), action: "tokenAgentSpend", params: spendParams([v5, agents0[1]], rTree0.recipients), chain: chain({ reserve: RESERVE }), changeXOnly: XO(fuelKey), descriptor }); }, /kasMaxPerSwap|closed layout/);
refuses("stale_predecessor_value", () => sellOk({}, { predecessorValue: (1004n * KAS).toString() }), /STALE/);
refuses("unknown_version", () => buildV6Transaction({ config, contractVersion: "policyvault-0.5", templateInput: template, stateInput: state(tree0.root), action: "tokenAtomicSell", params: swapCommon(agents0, { amountIn: "500", minKasOut: "1" }), chain: chain({ reserve: RESERVE, swap: true }), changeXOnly: XO(fuelKey), descriptor }), /UNKNOWN_VERSION|unknown contract version/);

fs.writeFileSync(path.join(outDir, "index.json"), JSON.stringify({ generator: "gen-v6-vectors.js", contractVersion: "policyvault-0.6", profileHash, vectors, refusals }, null, 1));
const missing = refusals.filter((r) => !r.refused || r.ok === false);
if (missing.length) {
  console.error("SDK refusals NOT observed or mismatched:", JSON.stringify(missing, null, 1));
  process.exit(2);
}
console.log(`v6 vectors: ${vectors.length} (${vectors.filter((v) => v.expect === "accept").length} accept / ${vectors.filter((v) => v.expect === "reject").length} reject); SDK refusals: ${refusals.length}`);
