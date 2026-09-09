"use strict";

/*
 * MEASURE the v0.7 organizational-root FEE/MASS shapes on PRODUCTION BYTES.
 *
 * Every row this tool emits comes from a transaction the REAL production SDK
 * built and froze — the real SilverScript compiler, the real pv_call_encoder
 * and pv_tx_probe binaries, the real state serializers and the real
 * compute-budget model. Nothing here is estimated: the tool reads the frozen
 * transaction's own input signature-script lengths, committed compute budgets
 * and output script sizes, and reports them alongside the fee the SDK itself
 * put in the transaction.
 *
 * The consensus arithmetic is NOT reimplemented here: the shapes are driven
 * through core/model/fee-mass.js (the source-backed reimplementation of
 * rusty-kaspa's mass and minimum-relay-fee rules) and core/model/storage-mass.js
 * (KIP-9), and the tool ASSERTS that the fee it derives equals the fee the SDK
 * committed for every row. A row where those disagree is a defect, not a
 * rounding difference, and the tool exits non-zero.
 *
 * THE THRESHOLD SWEEP. A root transaction's signature blob is a CONSTANT
 * 780 bytes for every threshold (abstaining slots carry the canonical
 * placeholder), so the serialized size does not move with M or N. What moves
 * is the committed COMPUTE BUDGET, because the covenant runs one `checkSig`
 * per ACTIVE owner slot. The sweep therefore builds a real root transaction at
 * EVERY active-slot count 1..12 and measures it, rather than extrapolating.
 *
 * Usage:
 *   node sdk/tools/measure-v7-fee-shapes.js [output.json]
 *
 * TEST KEYS ONLY. No network access; nothing is broadcast.
 */

const fs = require("fs");
const os = require("os");
const path = require("path");

const { loadConfig } = require("../src/config");
const assets = require("../../core/assets");
const { compileKcc20Program } = require("../src/token-program-kcc20");
const { buildTokenAgentTreeV5 } = require("../src/agent-merkle-v5");
const { buildRecipientTree } = require("../src/recipient-merkle-v3");
const { deriveRootPinsV7 } = require("../src/contract-compiler-v7");
const {
  buildCreateV7Root,
  buildV7RootTransaction,
  finalizeV7RootTransaction,
  buildCreateV7Vault,
  buildV7Transaction,
  finalizeV7Transaction,
  buildTokenDepositV7,
  finalizeTokenDepositV7
} = require("../src/vault-builders-v7");
const { frozenToWasmTransaction } = require("../src/frozen-tx-v3");
const { INACTIVE_SLOT_KEY, OWNER_SLOTS_V7 } = require("../../core/model/owner-set-v7");
const { calculateRequiredFee } = require("../../core/model/fee-mass");
const { calcStorageMass, STORAGE_MASS_LIMIT } = require("../../core/model/storage-mass");

const outPath = process.argv[2] || null;
const config = loadConfig({ dataRoot: fs.mkdtempSync(path.join(os.tmpdir(), "pv7-fee-")) });
const kaspa = require(config.rustyKaspaModule);

/* TEST KEYS ONLY: the secret is the byte value repeated 32x. */
const KEY = (v) => new kaspa.PrivateKey(v.toString(16).padStart(2, "0").repeat(32));
const XO = (k) => k.toPublicKey().toXOnlyPublicKey().toString().toLowerCase();
const wasmOf = (build) => frozenToWasmTransaction(config, build.frozen);
const signSlot = (build, index, key) => kaspa.createInputSignature(wasmOf(build), index, key).slice(2);
const signScript = (build, index, key) => kaspa.createInputSignature(wasmOf(build), index, key);

const KAS = 100000000n;
const H = (b) => b.toString(16).padStart(2, "0").repeat(32);
const ORG_ID = H(0xa7);
const ROOT_ID = H(0x52);
const VAULT_COV_ID = H(0x43);
const TOKEN_FAMILY = H(0x54);
let AGENT_PK = null;
let RECIPIENT_PK = null;
const ROOT_KAS = 3n * KAS;

function slots(keys) {
  const out = [];
  for (let i = 0; i < OWNER_SLOTS_V7; i += 1) out.push(i < keys.length ? keys[i] : INACTIVE_SLOT_KEY);
  return out;
}
/* 12 distinct TEST owner keys, and the fuel / agent / recipient keys */
const ownerPrivKeys = Array.from({ length: 12 }, (_, i) => KEY(0x71 + i));
const OWNER_KEYS = ownerPrivKeys.map(XO);
const successorKey = KEY(0x7f);
const fuelKey = KEY(0x64);
const agentKey = KEY(0x62);
const recipientKey = KEY(0x63);
const otherAgentKey = KEY(0x65);
const depositUserKey = KEY(0x66);
const FUEL = XO(fuelKey);
const rootTemplate = { orgId: ORG_ID, recoveryDelayDaa: "1000", successorPk: XO(successorKey), successionDelayDaa: "2000", rootMaxFeePerTx: "200000" };
const setOf = (n, m = n) => ({ owners: slots(OWNER_KEYS.slice(0, n)), ownerM: m, emergencyK: 1, recoveryM: Math.min(m, 2) });
const rootStateOf = (n, m = n, over = {}) => ({ boundOrgId: ORG_ID, ...setOf(n, m), frozen: 0, rootNonce: 0, ...over });
const rootChain = () => ({
  predecessorOutpoint: { transactionId: H(0x01), index: 0 },
  covenantId: ROOT_ID,
  predecessorValue: ROOT_KAS.toString(),
  fuel: { outpoint: { transactionId: H(0x03), index: 0 }, amount: (1n * KAS).toString(), scriptPublicKeyHex: `20${FUEL}ac` }
});

/* ---- the rooted vault ---- */
const ref = compileKcc20Program({ config, state: assets.kcc20.ZERO_STATE, familyBound: 2 });
const descriptor = {
  schema: "policyvault-asset-descriptor/1",
  assetId: H(0x11),
  displayName: "Org Treasury Token",
  tokenStandard: "kcc20/1",
  tokenCovenantId: TOKEN_FAMILY,
  acceptedTransferTemplates: [{ templateVmHashBlake2b256: ref.templateVmHashBlake2b256, prefixLen: ref.geometry.prefixLen, suffixLen: ref.geometry.suffixLen, stateLayout: "kcc20-state/1" }],
  decimalsDisplay: 2,
  issuerPowers: { mint: false, burn: false, freeze: false, blacklist: false, redemptionControl: false, upgradeMigration: false, controllerRotation: false, emergencyControl: false }
};
const ownerSet3 = setOf(3, 2);
const rootPins = deriveRootPinsV7({ config, template: rootTemplate, ownerSet: ownerSet3, covenantId: ROOT_ID });
const vaultTemplate = {
  vaultId: H(0x44),
  descriptorHash: assets.computeDescriptorHash(descriptor),
  tokenCovenantId: TOKEN_FAMILY,
  templateVmHash: ref.templateVmHashBlake2b256,
  templatePrefixLen: ref.geometry.prefixLen,
  templateStateLen: ref.geometry.stateLen,
  templateSuffixLen: ref.geometry.suffixLen,
  ...rootPins,
  recoveryPk: H(0x51)
};
AGENT_PK = XO(agentKey);
RECIPIENT_PK = XO(recipientKey);
const rTree = buildRecipientTree([RECIPIENT_PK]);
const agentPolicy = {
  agentPk: AGENT_PK,
  tokenMaxPerSpend: "250",
  tokenPeriodBudget: "400",
  periodLengthDaa: "1000",
  periodStartDaa: "5000",
  tokenPeriodSpent: "0",
  agentMaxFeePerTx: (1n * KAS).toString(),
  agentMaxCarryKas: (KAS / 4n).toString(),
  agentRecipientRoot: rTree.root
};
const agentTree = buildTokenAgentTreeV5([agentPolicy]);
const vaultState = (over = {}) => ({ feeReserve: (5n * KAS).toString(), paused: "0", agentRoot: agentTree.root, policyNonce: "0", ...over });
function tokenPosition(amount = 300) {
  const state = { ownerIdentifier: VAULT_COV_ID, identifierType: assets.kcc20.OWNER_SCHEMES.COVENANT_ID, amount: String(amount), isMinter: false };
  return { outpoint: { transactionId: H(0x0b), index: 0 }, value: (2n * KAS).toString(), scriptPublicKeyHex: compileKcc20Program({ config, state, familyBound: 2 }).p2shSpkHex, covenantId: TOKEN_FAMILY, state };
}
const vaultChain = (over = {}) => ({
  predecessorOutpoint: { transactionId: H(0x0a), index: 0 },
  covenantId: VAULT_COV_ID,
  predecessorValue: vaultState().feeReserve,
  fuel: { outpoint: { transactionId: H(0x03), index: 0 }, amount: (1n * KAS).toString(), scriptPublicKeyHex: `20${FUEL}ac` },
  root: { template: rootTemplate, state: rootStateOf(3, 2), outpoint: { transactionId: H(0x04), index: 0 }, covenantId: ROOT_ID, value: ROOT_KAS.toString() },
  ...over
});

/* ------------------------------------------------------------------ */

const rows = [];
let failed = 0;

/*
 * Measure a FINALIZED transaction: the exact bytes that would be broadcast.
 * `build.requiredFeeSompi` is the fee the SDK froze BEFORE signing, and the
 * derivation below must reproduce it exactly — a disagreement means the fee
 * model and the real bytes have drifted, which is a defect.
 */
function measure(kind, label, build, finalJson, notes = null) {
  const tx = finalJson;
  const descriptorTx = {
    version: Number(tx.version),
    payloadHex: tx.payload || "",
    inputs: tx.inputs.map((i) => ({ signatureScriptHex: i.signatureScript || "", computeBudget: i.computeBudget })),
    outputs: tx.outputs.map((o) => ({ scriptHex: o.scriptPublicKey.scriptHex, hasCovenant: !!o.covenant }))
  };
  const m = calculateRequiredFee(descriptorTx);
  const storage = calcStorageMass(
    tx.inputs.map((i) => BigInt(i.utxo.amount)),
    tx.outputs.map((o) => BigInt(o.value))
  );
  const derived = m.minimumRequiredFee.toString();
  const committed = build.requiredFeeSompi;
  if (derived !== committed) {
    console.error(`MISMATCH ${label}: derived ${derived} != SDK-committed ${committed}`);
    failed += 1;
  }
  rows.push({
    kind,
    label,
    inputs: tx.inputs.length,
    outputs: tx.outputs.length,
    sigscriptBytes: tx.inputs.map((i) => (i.signatureScript || "").length / 2),
    computeBudgets: tx.inputs.map((i) => i.computeBudget),
    outputScriptBytes: tx.outputs.map((o) => o.scriptPublicKey.scriptHex.length / 2),
    outputHasCovenant: tx.outputs.map((o) => !!o.covenant),
    payloadBytes: (tx.payload || "").length / 2,
    txBytes: Number(m.size),
    computeMass: Number(m.computeMass),
    transientMass: Number(m.transientMass),
    normalizedTransient: Number(m.normalizedTransient),
    feeMass: Number(m.feeMass),
    feeMassDominatedBy: m.computeMass > m.normalizedTransient ? "compute" : "transient",
    storageMass: Number(storage),
    storageWithinLimit: storage <= STORAGE_MASS_LIMIT,
    relayFloorFeeSompi: derived,
    sdkCommittedFeeSompi: committed,
    lockTime: String(tx.lockTime),
    notes
  });
}

/* sign a plain funding input in place (genesis shapes) */
function signedFunding(build, index = 0) {
  const json = JSON.parse(build.frozenCanonicalJson);
  json.inputs[index].signatureScript = signScript(build, index, fuelKey);
  return json;
}

/* ---- genesis ---- */
{
  const build = buildCreateV7Root({
    config,
    template: rootTemplate,
    ownerSet: ownerSet3,
    rootValueSompi: ROOT_KAS.toString(),
    funding: [{ outpoint: { transactionId: H(0x05), index: 0 }, amount: (10n * KAS).toString(), scriptPublicKeyHex: `20${FUEL}ac` }],
    changeXOnly: FUEL
  });
  measure("genesis", "organizational root genesis", build, signedFunding(build), "one-time: creates the organization's root UTXO");
}
{
  const build = buildCreateV7Vault({
    config,
    templateInput: vaultTemplate,
    initialStateInput: vaultState(),
    funding: [{ outpoint: { transactionId: H(0x06), index: 0 }, amount: (10n * KAS).toString(), scriptPublicKeyHex: `20${FUEL}ac` }],
    changeXOnly: FUEL,
    descriptor
  });
  measure("genesis", "rooted vault genesis", build, signedFunding(build), "one-time PER VAULT: creates one rooted vault under the existing root");
}

/* ---- root-only actions at the reference 2-of-3 ---- */
const approvalsFor = (build, index, keyIndexes) => keyIndexes.map((i) => ({ slot: i + 1, signatureHex: signSlot(build, index, ownerPrivKeys[i]) }));
for (const [action, params, over, signerIdx] of [
  ["authorize", {}, {}, [0, 1]],
  ["rotate", { newOwnerSet: setOf(4, 3) }, {}, [0, 1]],
  ["freeze", {}, {}, [0]],
  ["unfreeze", {}, { frozen: 1 }, [0, 1]],
  ["ownerRecover", { newOwnerSet: setOf(2, 2) }, {}, [0, 1]],
  ["succession", { newOwnerSet: { owners: slots([XO(successorKey)]), ownerM: 1, emergencyK: 1, recoveryM: 0 } }, {}, null]
]) {
  const build = buildV7RootTransaction({ config, templateInput: rootTemplate, stateInput: rootStateOf(3, 2, over), action, params, chain: rootChain(), changeXOnly: FUEL });
  const fin =
    action === "succession"
      ? finalizeV7RootTransaction({ build, successorSignatureHex: signSlot(build, 0, successorKey), fuelSignatureScriptHex: signScript(build, 1, fuelKey) })
      : finalizeV7RootTransaction({ build, approvals: approvalsFor(build, 0, signerIdx), fuelSignatureScriptHex: signScript(build, 1, fuelKey) });
  measure("root-only", `root ${action} (3 active owners)`, build, fin.finalTransaction, "the organization's own governance transaction; the root never pays anyone");
}

/* ---- THE THRESHOLD SWEEP: a real AUTHORIZE at every active-slot count ---- */
for (let n = 1; n <= OWNER_SLOTS_V7; n += 1) {
  const build = buildV7RootTransaction({ config, templateInput: rootTemplate, stateInput: rootStateOf(n, n), action: "authorize", chain: rootChain(), changeXOnly: FUEL });
  const fin = finalizeV7RootTransaction({
    build,
    approvals: approvalsFor(build, 0, Array.from({ length: n }, (_, i) => i)),
    fuelSignatureScriptHex: signScript(build, 1, fuelKey)
  });
  measure("threshold-sweep", `root authorize ${n}-of-${n}`, build, fin.finalTransaction, `${n} active owner slots; the covenant runs one checkSig per ACTIVE slot`);
}

/* ---- rooted owner operations (root + vault + fuel) ---- */
for (const [action, params, stateOver, signers] of [
  ["ownerSetAgentRoot", { newAgentRoot: H(0x99) }, {}, [0, 1]],
  ["ownerTopUpReserve", { topUpReserveAmountSompi: (KAS / 2n).toString() }, {}, [0, 1]],
  ["ownerPause", {}, {}, [0, 1]],
  ["ownerUnpause", {}, { paused: "1" }, [0, 1]],
  ["ownerEmergencyPause", {}, {}, [0]]
]) {
  const build = buildV7Transaction({ config, templateInput: vaultTemplate, stateInput: vaultState(stateOver), action, params, chain: vaultChain(), changeXOnly: FUEL, descriptor });
  const fin = finalizeV7Transaction({ build, approvals: approvalsFor(build, 1, signers), fuelSignatureScriptHex: signScript(build, 2, fuelKey) });
  measure("rooted-owner-op", `vault ${action} (root + vault + fuel)`, build, fin.finalTransaction, "ONE root input authorizes ONE vault operation in ONE transaction");
}
{
  const build = buildV7Transaction({ config, templateInput: vaultTemplate, stateInput: vaultState(), action: "ownerRecover", chain: vaultChain(), changeXOnly: FUEL, descriptor });
  const fin = finalizeV7Transaction({ build, approvals: approvalsFor(build, 1, [0, 1]), fuelSignatureScriptHex: signScript(build, 2, fuelKey) });
  measure("rooted-owner-op", "vault ownerRecover (no token position)", build, fin.finalTransaction, "TERMINAL: pays the reserve to the genesis-pinned recovery key");
}
{
  const build = buildV7Transaction({ config, templateInput: vaultTemplate, stateInput: vaultState(), action: "ownerRecover", chain: vaultChain({ tokenPosition: tokenPosition(300) }), changeXOnly: FUEL, descriptor });
  const fin = finalizeV7Transaction({ build, approvals: approvalsFor(build, 1, [0, 1]), fuelSignatureScriptHex: signScript(build, 3, fuelKey) });
  measure("rooted-owner-op", "vault ownerRecover (with token position)", build, fin.finalTransaction, "TERMINAL: reserve + the whole token position to the pinned recovery key");
}

/* ---- delegate spend (no root input at all) ---- */
const spendParams = (over = {}) => ({
  spendAmount: "200",
  agentPk: AGENT_PK,
  agents: [agentPolicy],
  recipient: RECIPIENT_PK,
  recipients: [...rTree.recipients],
  recipientCarryKasSompi: (KAS / 5n).toString(),
  reserveConsumedSompi: "50000",
  ...over
});
{
  const build = buildV7Transaction({ config, templateInput: vaultTemplate, stateInput: vaultState(), action: "tokenAgentSpend", params: spendParams(), chain: vaultChain({ tokenPosition: tokenPosition(300), root: undefined }), changeXOnly: FUEL, descriptor });
  const fin = finalizeV7Transaction({ build, agentSignatureHex: signSlot(build, 0, agentKey), fuelSignatureScriptHex: signScript(build, 2, fuelKey) });
  measure("delegate", "delegate spend (fuel-funded)", build, fin.finalTransaction, "the ORDINARY operating transaction; never touches the root");
}
{
  const build = buildV7Transaction({
    config,
    templateInput: vaultTemplate,
    stateInput: vaultState(),
    action: "tokenAgentSpend",
    params: spendParams({ reserveConsumedSompi: undefined }),
    chain: { predecessorOutpoint: { transactionId: H(0x0a), index: 0 }, covenantId: VAULT_COV_ID, predecessorValue: (5n * KAS).toString(), tokenPosition: tokenPosition(300) },
    changeXOnly: FUEL,
    descriptor
  });
  const fin = finalizeV7Transaction({ build, agentSignatureHex: signSlot(build, 0, agentKey) });
  measure("delegate", "delegate spend (reserve-funded)", build, fin.finalTransaction, "the vault's own fee reserve pays; no external fuel input");
}
{
  const spentLeaf = { ...agentPolicy, tokenPeriodSpent: "350" };
  const otherLeaf = { ...agentPolicy, agentPk: XO(otherAgentKey) };
  const tree = buildTokenAgentTreeV5([spentLeaf, otherLeaf]);
  const build = buildV7Transaction({
    config,
    templateInput: vaultTemplate,
    stateInput: vaultState({ agentRoot: tree.root }),
    action: "tokenAgentSpend",
    params: spendParams({ agents: [spentLeaf, otherLeaf], periodsElapsed: "2" }),
    chain: vaultChain({ tokenPosition: tokenPosition(300), root: undefined }),
    changeXOnly: FUEL,
    descriptor
  });
  const fin = finalizeV7Transaction({ build, agentSignatureHex: signSlot(build, 0, agentKey), fuelSignatureScriptHex: signScript(build, 2, fuelKey) });
  measure("delegate", "delegate spend (period rollover)", build, fin.finalTransaction, "a new budget period starts; lockTime pins the new period start");
}

/* ---- token deposit into a rooted vault (the vault is not an input) ---- */
{
  const userState = { ownerIdentifier: XO(depositUserKey), identifierType: assets.kcc20.OWNER_SCHEMES.P2PK, amount: "1000", isMinter: false };
  const build = buildTokenDepositV7({
    config,
    descriptor,
    vault: { covenantId: VAULT_COV_ID, template: vaultTemplate },
    chain: {
      userPosition: { outpoint: { transactionId: H(0x07), index: 0 }, value: (3n * KAS).toString(), scriptPublicKeyHex: compileKcc20Program({ config, state: userState, familyBound: 2 }).p2shSpkHex, covenantId: TOKEN_FAMILY, state: userState },
      fuel: { outpoint: { transactionId: H(0x08), index: 0 }, amount: (1n * KAS).toString(), scriptPublicKeyHex: `20${FUEL}ac` }
    },
    params: { depositAmount: "1000" },
    changeXOnly: FUEL
  });
  const fin = finalizeTokenDepositV7({ build, tokenOwnerSignatureHex: signSlot(build, 0, depositUserKey), fuelSignatureScriptHex: signScript(build, 1, fuelKey) });
  measure("deposit", "token deposit into a rooted vault", build, fin.finalTransaction, "a user funds the vault; the vault is not an input and the root is not involved");
}

const report = {
  measuredBy: "sdk/tools/measure-v7-fee-shapes.js",
  environment: "production SDK builders + the real silverc / pv_call_encoder / pv_tx_probe + real Schnorr signatures; consensus arithmetic from core/model/fee-mass.js + core/model/storage-mass.js",
  rows
};
if (outPath) {
  fs.mkdirSync(path.dirname(path.resolve(outPath)), { recursive: true });
  fs.writeFileSync(path.resolve(outPath), `${JSON.stringify(report, null, 1)}\n`);
  console.log(`wrote ${rows.length} measured shapes -> ${outPath}`);
} else {
  console.log(JSON.stringify(report, null, 1));
}
if (failed > 0) {
  console.error(`${failed} row(s) disagreed with the SDK's own committed fee — refusing`);
  process.exit(2);
}
console.error(`measured ${rows.length} production shapes; every derived relay-floor fee equals the SDK's committed fee`);
