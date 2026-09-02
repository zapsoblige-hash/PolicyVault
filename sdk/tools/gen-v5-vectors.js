"use strict";

/*
 * PolicyVault v0.5 PRODUCTION-BYTE vector generator.
 *
 * Drives the ACTUAL production SDK code — core/assets (descriptor, KCC20
 * adapter, blake2b), token-program-kcc20 (vendored KCC20 reference program
 * via silverc), vault-state-v5, contract-compiler-v5 (silverc),
 * agent-merkle-v5, recipient-merkle-v3, vault-transitions-v5,
 * compute-budget-v5, frozen-tx-v3, vault-builders-v5, and the REAL
 * pv_call_encoder + pv_tx_probe binaries — to construct fully-finalized
 * v0.5 transactions with real Schnorr signatures (rusty-kaspa WASM
 * createInputSignature over deterministic TEST-ONLY keys).
 * tests/vm/tests/v5_sdk_integration.rs executes every emitted vector's
 * EXACT bytes on the real TxScriptEngine against the PRODUCTION
 * PolicyVault.v0.5.sil + the vendored KCC20 program.
 *
 * Negative vectors are otherwise-valid transactions with ONE security
 * field mutated after freeze/finalize (the SDK itself refuses to build
 * them) and MUST be rejected by consensus.
 *
 * Usage: node gen-v5-vectors.js <output-dir>
 * TEST KEYS ONLY: secrets are the byte value repeated 32x. Never production material.
 */

const fs = require("fs");
const path = require("path");

const { loadConfig } = require("../src/config");
const assets = require("../../core/assets");
const { compileKcc20Program } = require("../src/token-program-kcc20");
const { buildTokenAgentTreeV5 } = require("../src/agent-merkle-v5");
const { buildRecipientTree } = require("../src/recipient-merkle-v3");
const { buildV5Transaction, buildCreateV5, finalizeV5Transaction, buildTokenDepositV5, finalizeTokenDepositV5 } = require("../src/vault-builders-v5");
const { frozenToWasmTransaction } = require("../src/frozen-tx-v3");

const outDir = process.argv[2];
if (!outDir) {
  console.error("usage: node gen-v5-vectors.js <output-dir>");
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

const OWNER = XO(owner);
const CONTROLLER_ID = "43".repeat(32); // COV_CTRL in the Rust harness (b"CCCC…")
const TOKEN_FAMILY = "54".repeat(32); // COV_TOKEN (b"TTTT…")
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
  acceptedTransferTemplates: [
    { templateVmHashBlake2b256: refProgram.templateVmHashBlake2b256, prefixLen: refProgram.geometry.prefixLen, suffixLen: refProgram.geometry.suffixLen, stateLayout: "kcc20-state/1" }
  ],
  decimalsDisplay: 8,
  issuerPowers: { mint: false, burn: false, freeze: false, blacklist: false, redemptionControl: false, upgradeMigration: false, controllerRotation: false, emergencyControl: false }
};
const descriptorHash = assets.computeDescriptorHash(descriptor);
const template = {
  owner: OWNER,
  vaultId: VAULT_ID,
  descriptorHash,
  tokenCovenantId: TOKEN_FAMILY,
  templateVmHash: refProgram.templateVmHashBlake2b256,
  templatePrefixLen: refProgram.geometry.prefixLen,
  templateStateLen: refProgram.geometry.stateLen,
  templateSuffixLen: refProgram.geometry.suffixLen
};

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
function tokenAgentPolicy(pkHex, recipientRoot, over = {}) {
  return {
    agentPk: pkHex,
    tokenMaxPerSpend: "250",
    tokenPeriodBudget: "400",
    periodLengthDaa: "1000",
    periodStartDaa: "5000",
    tokenPeriodSpent: "0",
    agentMaxFeePerTx: (1n * KAS).toString(),
    agentMaxCarryKas: (KAS / 4n).toString(),
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
    agents.push(tokenAgentPolicy(pk, ("f" + i.toString(16)).padStart(4, "0").repeat(16).slice(0, 64), { tokenMaxPerSpend: "1", tokenPeriodBudget: "1" }));
  }
  return agents;
}
function state(agentRoot, over = {}) {
  return { feeReserve: (5n * KAS).toString(), paused: "0", agentRoot, policyNonce: "0", ...over };
}
function tokenPositionFor(amount) {
  const st = { ownerIdentifier: CONTROLLER_ID, identifierType: 2, amount: String(amount), isMinter: false };
  const program = compileKcc20Program({ config, state: st, familyBound: FAMILY_BOUND });
  return { outpoint: { transactionId: "02".repeat(32), index: 0 }, value: (2n * KAS).toString(), scriptPublicKeyHex: program.p2shSpkHex, covenantId: TOKEN_FAMILY, state: st };
}
function chain({ reserve, fuel = true, position = true, tokenAmount = 300 }) {
  const ctx = { predecessorOutpoint: { transactionId: "01".repeat(32), index: 0 }, predecessorValue: reserve, covenantId: CONTROLLER_ID };
  if (fuel) ctx.fuel = { outpoint: { transactionId: "03".repeat(32), index: 0 }, amount: (1n * KAS).toString(), scriptPublicKeyHex: `20${XO(fuelKey)}ac` };
  if (position) ctx.tokenPosition = tokenPositionFor(tokenAmount);
  return ctx;
}
function signCov(build, kp) {
  return kaspa.createInputSignature(frozenToWasmTransaction(config, build.frozen), 0, kp).slice(2);
}
function signFuel(build) {
  return kaspa.createInputSignature(frozenToWasmTransaction(config, build.frozen), build.frozen.inputs.length - 1, fuelKey);
}
function finalize(build, kp) {
  return finalizeV5Transaction({ build, covenantSignatureHex: signCov(build, kp), fuelSignatureScriptHex: build.hasFuelInput ? signFuel(build) : undefined }).finalTransaction;
}

const refusals = [];
function refuses(name, f, codeRe) {
  try {
    f();
    refusals.push({ name, refused: false });
  } catch (e) {
    refusals.push({ name, refused: true, code: e.code ?? null, message: String(e.message).slice(0, 160), ok: codeRe ? codeRe.test(e.code ?? e.message) : true });
  }
}
const vectors = [];
function emit(name, expect, build, finalTx) {
  vectors.push({ name, expect });
  const dir = path.join(outDir, name);
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, "vector.json"), JSON.stringify({ name, expect, action: build?.action ?? "unknown", committedBudget: build?.computeBudget ?? null, requiredFeeSompi: build?.requiredFeeSompi ?? null, accounting: build?.accounting ?? null, tx: finalTx }, null, 1));
}

/* ================================================================ POSITIVE */
const rTree0 = recipTreeAtDepth(0);
const policy0 = tokenAgentPolicy(XO(agent), rTree0.root);
const agents0 = [policy0, tokenAgentPolicy(XO(other), rTree0.root)];
const tree0 = buildTokenAgentTreeV5(agents0);

const spendParams = (agents, recips, over = {}) => ({ spendAmount: "200", agentPk: XO(agent), agents, recipient: XO(recipient), recipients: [...recips], recipientCarryKasSompi: (KAS / 5n).toString(), reserveConsumedSompi: "50000", ...over });

/* 1. fuel-funded spend, reserve partially consumed */
{
  const build = buildV5Transaction({ config, templateInput: template, stateInput: state(tree0.root), action: "tokenAgentSpend", params: spendParams(agents0, rTree0.recipients), chain: chain({ reserve: (5n * KAS).toString() }), changeXOnly: XO(fuelKey), descriptor });
  emit("spend_fuel_depth0", "accept", build, finalize(build, agent));
  /* negatives crafted from this accept vector (JSON-level, post-finalize) */
  const tx = finalize(build, agent);
  const mut = (f) => { const j = JSON.parse(JSON.stringify(tx)); f(j); return j; };
  emit("neg_successor_value_drained", "reject", build, mut((j) => { j.outputs[0].value = (BigInt(j.outputs[0].value) - 1000000n).toString(); j.outputs[3].value = (BigInt(j.outputs[3].value) + 1000000n).toString(); }));
  emit("neg_token_family_swapped", "reject", build, mut((j) => { j.inputs[1].utxo.covenantId = "57".repeat(32); j.outputs[1].covenant.covenantId = "57".repeat(32); j.outputs[2].covenant.covenantId = "57".repeat(32); }));
  emit("neg_recipient_carry_over_cap", "reject", build, mut((j) => { j.outputs[2].value = (KAS / 4n + 1n).toString(); j.outputs[1].value = (2n * KAS - KAS / 4n - 1n).toString(); }));
  emit("neg_token_kas_leak_to_change", "reject", build, mut((j) => { j.outputs[1].value = (BigInt(j.outputs[1].value) - 1n).toString(); j.outputs[3].value = (BigInt(j.outputs[3].value) + 1n).toString(); }));
  emit("neg_hidden_extra_family_output", "reject", build, mut((j) => { j.outputs.splice(3, 0, { ...j.outputs[2], value: "1000" }); j.outputs[4].value = (BigInt(j.outputs[4].value) - 1000n).toString(); }));
  emit("neg_recipient_output_swapped_to_other_program", "reject", build, mut((j) => { j.outputs[2].scriptPublicKey.scriptHex = j.outputs[1].scriptPublicKey.scriptHex; }));
  emit("neg_locktime_rollover_forged", "reject", build, mut((j) => { j.lockTime = "7000"; }));
}
/* 2. reserve-funded spend (no fuel): reserveConsumed == exact fee */
{
  const build = buildV5Transaction({ config, templateInput: template, stateInput: state(tree0.root), action: "tokenAgentSpend", params: spendParams(agents0, rTree0.recipients, { reserveConsumedSompi: undefined }), chain: chain({ reserve: (5n * KAS).toString(), fuel: false }), changeXOnly: XO(fuelKey), descriptor });
  emit("spend_reserve_funded", "accept", build, finalize(build, agent));
}
/* 3. deep proofs: agent depth 12 + recipient depth 16 */
{
  const rTree16 = recipTreeAtDepth(16);
  const policy = tokenAgentPolicy(XO(agent), rTree16.root);
  const agents = agentSetAtDepth(12, policy);
  const tree = buildTokenAgentTreeV5(agents);
  const build = buildV5Transaction({ config, templateInput: template, stateInput: state(tree.root), action: "tokenAgentSpend", params: spendParams(agents, rTree16.recipients), chain: chain({ reserve: (5n * KAS).toString() }), changeXOnly: XO(fuelKey), descriptor });
  emit("spend_fuel_depth12_16", "accept", build, finalize(build, agent));
}
/* 4. rollover after two periods */
{
  const spent = tokenAgentPolicy(XO(agent), rTree0.root, { tokenPeriodSpent: "350" });
  const agents = [spent, tokenAgentPolicy(XO(other), rTree0.root)];
  const tree = buildTokenAgentTreeV5(agents);
  const build = buildV5Transaction({ config, templateInput: template, stateInput: state(tree.root), action: "tokenAgentSpend", params: spendParams(agents, rTree0.recipients, { periodsElapsed: "2" }), chain: chain({ reserve: (5n * KAS).toString() }), changeXOnly: XO(fuelKey), descriptor });
  if (build.frozen.lockTime !== 7000n) throw new Error("rollover lockTime must be 7000");
  emit("spend_rollover", "accept", build, finalize(build, agent));
}
/* 5. owner ops */
{
  const st = state(tree0.root);
  for (const [name, action, params] of [
    ["owner_set_agent_root", "ownerSetAgentRoot", { newAgents: [tokenAgentPolicy(XO(other), rTree0.root)] }],
    ["owner_top_up_reserve", "ownerTopUpReserve", { topUpReserveAmountSompi: (KAS / 2n).toString() }],
    ["owner_pause", "ownerPause", {}]
  ]) {
    const build = buildV5Transaction({ config, templateInput: template, stateInput: st, action, params, chain: chain({ reserve: (5n * KAS).toString(), position: false }), changeXOnly: XO(fuelKey), descriptor });
    emit(name, "accept", build, finalize(build, owner));
    if (name === "owner_pause") {
      emit("neg_owner_op_agent_signed", "reject", build, finalize(build, agent));
    }
  }
  const paused = state(tree0.root, { paused: "1" });
  const build = buildV5Transaction({ config, templateInput: template, stateInput: paused, action: "ownerUnpause", params: {}, chain: chain({ reserve: (5n * KAS).toString(), position: false }), changeXOnly: XO(fuelKey), descriptor });
  emit("owner_unpause", "accept", build, finalize(build, owner));
}
/* 6. recover with and without a position */
{
  const st = state(tree0.root);
  const withPos = buildV5Transaction({ config, templateInput: template, stateInput: st, action: "ownerRecover", params: {}, chain: chain({ reserve: (5n * KAS).toString() }), changeXOnly: XO(fuelKey), descriptor });
  emit("recover_with_position", "accept", withPos, finalize(withPos, owner));
  const noPos = buildV5Transaction({ config, templateInput: template, stateInput: st, action: "ownerRecover", params: {}, chain: chain({ reserve: (5n * KAS).toString(), position: false }), changeXOnly: XO(fuelKey), descriptor });
  emit("recover_without_position", "accept", noPos, finalize(noPos, owner));
  emit("neg_recover_agent_signed", "reject", withPos, finalize(withPos, agent));
}
/* 7. genesis */
{
  const build = buildCreateV5({ config, templateInput: template, initialStateInput: state(tree0.root), funding: [{ outpoint: { transactionId: "05".repeat(32), index: 0 }, amount: (10n * KAS).toString(), scriptPublicKeyHex: `20${XO(fuelKey)}ac` }], changeXOnly: XO(fuelKey), descriptor });
  const wasm = frozenToWasmTransaction(config, build.frozen);
  const json = JSON.parse(build.frozenCanonicalJson);
  json.inputs[0].signatureScript = kaspa.createInputSignature(wasm, 0, fuelKey);
  emit("genesis_controller", "accept", build, json);
}

/* 8. token DEPOSIT: user-owned position -> controller covenant id (full and partial) */
{
  const user = KEY(0x66);
  const userState = { ownerIdentifier: XO(user), identifierType: 0, amount: "1000", isMinter: false };
  const userProgram = compileKcc20Program({ config, state: userState, familyBound: FAMILY_BOUND });
  const depositChain = (over = {}) => ({
    userPosition: { outpoint: { transactionId: "06".repeat(32), index: 0 }, value: (3n * KAS).toString(), scriptPublicKeyHex: userProgram.p2shSpkHex, covenantId: TOKEN_FAMILY, state: userState, ...over },
    fuel: { outpoint: { transactionId: "07".repeat(32), index: 0 }, amount: (1n * KAS).toString(), scriptPublicKeyHex: `20${XO(fuelKey)}ac` }
  });
  const signDeposit = (build) => finalizeTokenDepositV5({
    build,
    tokenOwnerSignatureHex: kaspa.createInputSignature(frozenToWasmTransaction(config, build.frozen), 0, user).slice(2),
    fuelSignatureScriptHex: kaspa.createInputSignature(frozenToWasmTransaction(config, build.frozen), 1, fuelKey)
  }).finalTransaction;
  const full = buildTokenDepositV5({ config, descriptor, controller: { covenantId: CONTROLLER_ID, template }, chain: depositChain(), params: { depositAmount: "1000" }, changeXOnly: XO(fuelKey) });
  emit("deposit_full", "accept", full, signDeposit(full));
  const partial = buildTokenDepositV5({ config, descriptor, controller: { covenantId: CONTROLLER_ID, template }, chain: depositChain(), params: { depositAmount: "400", depositCarryKasSompi: (1n * KAS).toString() }, changeXOnly: XO(fuelKey) });
  emit("deposit_partial_with_remainder", "accept", partial, signDeposit(partial));
  /* negatives: wrong signer (another key signs the user's position) */
  emit("neg_deposit_wrong_signer", "reject", full, finalizeTokenDepositV5({ build: full, tokenOwnerSignatureHex: kaspa.createInputSignature(frozenToWasmTransaction(config, full.frozen), 0, other).slice(2), fuelSignatureScriptHex: kaspa.createInputSignature(frozenToWasmTransaction(config, full.frozen), 1, fuelKey) }).finalTransaction);
  /* negatives: conservation break re-encoded through the real encoder (amount 401 deposited from 1000 with a 600 remainder) */
  {
    const tx = signDeposit(partial);
    const bad = JSON.parse(JSON.stringify(tx));
    const inflated = compileKcc20Program({ config, state: { ownerIdentifier: CONTROLLER_ID, identifierType: 2, amount: "401", isMinter: false }, familyBound: FAMILY_BOUND });
    bad.outputs[0].scriptPublicKey.scriptHex = inflated.p2shSpkHex;
    emit("neg_deposit_conservation_plus_one", "reject", partial, bad);
  }
  refuses("deposit_over_position", () => buildTokenDepositV5({ config, descriptor, controller: { covenantId: CONTROLLER_ID, template }, chain: depositChain(), params: { depositAmount: "1001" }, changeXOnly: XO(fuelKey) }), /INSUFFICIENT_TOKENS/);
  refuses("deposit_descriptor_substitution", () => buildTokenDepositV5({ config, descriptor: { ...descriptor, issuerPowers: { ...descriptor.issuerPowers, freeze: true } }, controller: { covenantId: CONTROLLER_ID, template }, chain: depositChain(), params: { depositAmount: "1000" }, changeXOnly: XO(fuelKey) }), /DESCRIPTOR_PIN_MISMATCH/);
  refuses("deposit_wrong_family", () => buildTokenDepositV5({ config, descriptor, controller: { covenantId: CONTROLLER_ID, template }, chain: depositChain({ covenantId: "57".repeat(32) }), params: { depositAmount: "1000" }, changeXOnly: XO(fuelKey) }), /WRONG_TOKEN_FAMILY/);
  refuses("deposit_stale_state(spk mismatch)", () => buildTokenDepositV5({ config, descriptor, controller: { covenantId: CONTROLLER_ID, template }, chain: depositChain({ state: { ...userState, amount: "999" } }), params: { depositAmount: "100" }, changeXOnly: XO(fuelKey) }), /TOKEN_POSITION_SPK_MISMATCH/);
  refuses("deposit_from_covenant_owned_position", () => { const st = { ownerIdentifier: CONTROLLER_ID, identifierType: 2, amount: "1000", isMinter: false }; const p = compileKcc20Program({ config, state: st, familyBound: FAMILY_BOUND }); buildTokenDepositV5({ config, descriptor, controller: { covenantId: CONTROLLER_ID, template }, chain: depositChain({ state: st, scriptPublicKeyHex: p.p2shSpkHex }), params: { depositAmount: "1000" }, changeXOnly: XO(fuelKey) }); }, /USER_POSITION_NOT_P2PK/);
  refuses("deposit_unsupported_program(bound 16 descriptor)", () => { const p16 = compileKcc20Program({ config, state: assets.kcc20.ZERO_STATE, familyBound: 15 }); const d16 = { ...descriptor, acceptedTransferTemplates: [{ templateVmHashBlake2b256: "ee".repeat(32), prefixLen: p16.geometry.prefixLen, suffixLen: p16.geometry.suffixLen + 608, stateLayout: "kcc20-state/1" }] }; const t16 = { ...template, descriptorHash: assets.computeDescriptorHash(d16), templateVmHash: "ee".repeat(32), templateSuffixLen: p16.geometry.suffixLen + 608 }; buildTokenDepositV5({ config, descriptor: d16, controller: { covenantId: CONTROLLER_ID, template: t16 }, chain: depositChain(), params: { depositAmount: "1000" }, changeXOnly: XO(fuelKey) }); }, /UNSUPPORTED_TOKEN_PROGRAM/);
}

/* ================================================================ SDK REFUSALS (must throw before any bytes exist) */
const okChain = () => chain({ reserve: (5n * KAS).toString() });
refuses("over_cap", () => buildV5Transaction({ config, templateInput: template, stateInput: state(tree0.root), action: "tokenAgentSpend", params: spendParams(agents0, rTree0.recipients, { spendAmount: "251" }), chain: okChain(), changeXOnly: XO(fuelKey), descriptor }), /OVER_CAP/);
refuses("conservation_insufficient_tokens", () => buildV5Transaction({ config, templateInput: template, stateInput: state(tree0.root), action: "tokenAgentSpend", params: spendParams(agents0, rTree0.recipients, { spendAmount: "200" }), chain: chain({ reserve: (5n * KAS).toString(), tokenAmount: 100 }), changeXOnly: XO(fuelKey), descriptor }), /INSUFFICIENT_TOKENS/);
refuses("recipient_not_allowlisted", () => buildV5Transaction({ config, templateInput: template, stateInput: state(tree0.root), action: "tokenAgentSpend", params: spendParams(agents0, rTree0.recipients, { recipient: XO(other) }), chain: okChain(), changeXOnly: XO(fuelKey), descriptor }), /not in|RECIPIENT/);
refuses("descriptor_substitution", () => buildV5Transaction({ config, templateInput: template, stateInput: state(tree0.root), action: "tokenAgentSpend", params: spendParams(agents0, rTree0.recipients), chain: okChain(), changeXOnly: XO(fuelKey), descriptor: { ...descriptor, issuerPowers: { ...descriptor.issuerPowers, mint: true } } }), /DESCRIPTOR_PIN_MISMATCH/);
refuses("descriptor_unknown_version", () => buildV5Transaction({ config, templateInput: template, stateInput: state(tree0.root), action: "tokenAgentSpend", params: spendParams(agents0, rTree0.recipients), chain: okChain(), changeXOnly: XO(fuelKey), descriptor: { ...descriptor, schema: "policyvault-asset-descriptor/2" } }), /DESCRIPTOR_UNKNOWN_VERSION/);
refuses("descriptor_unknown_field", () => buildV5Transaction({ config, templateInput: template, stateInput: state(tree0.root), action: "tokenAgentSpend", params: spendParams(agents0, rTree0.recipients), chain: okChain(), changeXOnly: XO(fuelKey), descriptor: { ...descriptor, transport: "witness" } }), /DESCRIPTOR_UNKNOWN_FIELD/);
refuses("issuer_property_omission", () => { const d = JSON.parse(JSON.stringify(descriptor)); delete d.issuerPowers.freeze; buildV5Transaction({ config, templateInput: template, stateInput: state(tree0.root), action: "tokenAgentSpend", params: spendParams(agents0, rTree0.recipients), chain: okChain(), changeXOnly: XO(fuelKey), descriptor: d }); }, /DESCRIPTOR_MALFORMED|issuerPowers/);
refuses("wrong_token_family_position", () => { const c = okChain(); c.tokenPosition.covenantId = "57".repeat(32); buildV5Transaction({ config, templateInput: template, stateInput: state(tree0.root), action: "tokenAgentSpend", params: spendParams(agents0, rTree0.recipients), chain: c, changeXOnly: XO(fuelKey), descriptor }); }, /WRONG_TOKEN_FAMILY/);
refuses("token_position_spk_mismatch(stale state)", () => { const c = okChain(); c.tokenPosition.state = { ...c.tokenPosition.state, amount: "301" }; buildV5Transaction({ config, templateInput: template, stateInput: state(tree0.root), action: "tokenAgentSpend", params: spendParams(agents0, rTree0.recipients), chain: c, changeXOnly: XO(fuelKey), descriptor }); }, /TOKEN_POSITION_SPK_MISMATCH/);
refuses("token_not_owned_by_controller", () => { const c = okChain(); const st = { ...c.tokenPosition.state, ownerIdentifier: XO(other), identifierType: 0 }; const p = compileKcc20Program({ config, state: st, familyBound: FAMILY_BOUND }); c.tokenPosition = { ...c.tokenPosition, state: st, scriptPublicKeyHex: p.p2shSpkHex }; buildV5Transaction({ config, templateInput: template, stateInput: state(tree0.root), action: "tokenAgentSpend", params: spendParams(agents0, rTree0.recipients), chain: c, changeXOnly: XO(fuelKey), descriptor }); }, /TOKEN_NOT_OWNED/);
refuses("wrong_vm_hash_pinned", () => buildV5Transaction({ config, templateInput: { ...template, templateVmHash: "ab".repeat(32) }, stateInput: state(tree0.root), action: "tokenAgentSpend", params: spendParams(agents0, rTree0.recipients), chain: okChain(), changeXOnly: XO(fuelKey), descriptor }), /TEMPLATE_PIN_MISMATCH/);
refuses("wrong_geometry_pinned", () => buildV5Transaction({ config, templateInput: { ...template, templateSuffixLen: template.templateSuffixLen + 1 }, stateInput: state(tree0.root), action: "tokenAgentSpend", params: spendParams(agents0, rTree0.recipients), chain: okChain(), changeXOnly: XO(fuelKey), descriptor }), /TEMPLATE_PIN_MISMATCH/);
refuses("carry_over_cap", () => buildV5Transaction({ config, templateInput: template, stateInput: state(tree0.root), action: "tokenAgentSpend", params: spendParams(agents0, rTree0.recipients, { recipientCarryKasSompi: (KAS / 4n + 1n).toString() }), chain: okChain(), changeXOnly: XO(fuelKey), descriptor }), /OVER_CARRY_CAP/);
refuses("reserve_over_agent_fee_cap", () => buildV5Transaction({ config, templateInput: template, stateInput: state(tree0.root), action: "tokenAgentSpend", params: spendParams(agents0, rTree0.recipients, { reserveConsumedSompi: (1n * KAS + 1n).toString() }), chain: okChain(), changeXOnly: XO(fuelKey), descriptor }), /OVER_AGENT_FEE_CAP/);
refuses("paused", () => buildV5Transaction({ config, templateInput: template, stateInput: state(tree0.root, { paused: "1" }), action: "tokenAgentSpend", params: spendParams(agents0, rTree0.recipients), chain: okChain(), changeXOnly: XO(fuelKey), descriptor }), /PAUSED/);
refuses("stale_predecessor_value", () => buildV5Transaction({ config, templateInput: template, stateInput: state(tree0.root), action: "tokenAgentSpend", params: spendParams(agents0, rTree0.recipients), chain: { ...okChain(), predecessorValue: (6n * KAS).toString() }, changeXOnly: XO(fuelKey), descriptor }), /STALE/);
refuses("unknown_version", () => buildV5Transaction({ config, contractVersion: "policyvault-0.4.1", templateInput: template, stateInput: state(tree0.root), action: "tokenAgentSpend", params: spendParams(agents0, rTree0.recipients), chain: okChain(), changeXOnly: XO(fuelKey), descriptor }), /UNKNOWN_VERSION|unknown contract version/);
refuses("unknown_action", () => buildV5Transaction({ config, templateInput: template, stateInput: state(tree0.root), action: "agentSpend", params: {}, chain: okChain(), changeXOnly: XO(fuelKey), descriptor }), /unknown v0.5 action/);
refuses("nonstandard_family_bound_descriptor", () => { const p16 = compileKcc20Program({ config, state: assets.kcc20.ZERO_STATE, familyBound: 15 }); void p16; assets.corroborateTemplate({ descriptor: { ...descriptor, acceptedTransferTemplates: [{ templateVmHashBlake2b256: "cd".repeat(32), prefixLen: 1, suffixLen: 10033, stateLayout: "kcc20-state/1" }] }, prefixHex: "6b", suffixHex: "00".repeat(10033) }); }, /TEMPLATE_HASH_MISMATCH|TEMPLATE_NONSTANDARD/);

fs.writeFileSync(path.join(outDir, "index.json"), JSON.stringify({ vectors, refusals, descriptorHash, template }, null, 1));
const unrefused = refusals.filter((r) => !r.refused || r.ok === false);
if (unrefused.length) {
  console.error("SDK did not refuse (or refused with the wrong code):", JSON.stringify(unrefused, null, 1));
  process.exit(2);
}
console.log(`emitted ${vectors.length} vectors (${vectors.filter((v) => v.expect === "accept").length} accept / ${vectors.filter((v) => v.expect === "reject").length} reject), ${refusals.length} SDK refusals`);
