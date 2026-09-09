"use strict";

/*
 * LIVE TESTNET-10 ORGANIZATIONAL-ROOT LIFECYCLE for the v0.7 CANDIDATE
 * covenants (docs/postlaunch/v0.7-organizational-root-design.md §11.1 gate
 * I5). Drives the REAL v0.7 SDK (core/model/owner-set-v7,
 * vault-state-v7-root, vault-state-v7, vault-transitions-v7*,
 * compute-budget-v7, contract-compiler-v7, vault-builders-v7,
 * core/intent/org-root-manifest-v7, token-program-kcc20 and the production
 * pv_call_encoder) against a LOCAL, VERIFIED testnet-10 node (connectVerified:
 * exact network + synced + utxoindex, never assumed).
 *
 * TEST ASSETS ONLY. TEST KEYS ONLY. NEVER MAINNET.
 *
 *   1.  KCC20 ISSUANCE (user-owned genesis note)             -> token family id
 *   2.  ORGANIZATIONAL ROOT GENESIS (2-of-3, K=1, R=1)       -> root covenant id
 *   3.  ROOTED PAYMENT VAULT GENESIS (pins the root's covenant id AND the
 *       root's template identity + geometry)                 -> vault covenant id
 *   4.  TOKEN DEPOSIT (user -> vault-owned position)
 *   5.  ORDINARY DELEGATED SPEND (agent key; NO root input at all)
 *   6.  AUTHORITY EXPANSION: ownerControl(0) setAgentRoot under root AUTHORIZE
 *   7.  AUTHORITY REDUCTION: ownerControl(4) emergency pause under root FREEZE (K=1)
 *   8.  GOVERNED UNFREEZE (full quorum)
 *   9.  ownerControl(3) unpause under root AUTHORIZE
 *   10. MEMBER ROTATION (2-of-3 -> a new set)
 *   11. THRESHOLD CHANGE (ROTATE with a new M)
 *   12. EMERGENCY FREEZE (K = 1)
 *   13. GOVERNED UNFREEZE (full quorum)
 *   14. AUTHORIZED TESTNET NEGATIVE VALIDATION (see below)
 *   15. OWNER-RECOVER after the idle delay — THE CONSENSUS PROOF: the EXACT
 *       SAME finalized bytes are submitted BEFORE the root UTXO is
 *       `recoveryDelayDaa` old (the node MUST reject: check_sequence_lock) and
 *       again after the age (the node MUST accept). Lands frozen (D6).
 *   16. UNFREEZE by the recovery-installed set
 *   17. SUCCESSION after its idle delay (same two-phase age proof)
 *   18. UNFREEZE by the succession-installed set
 *   19. VAULT ownerRecover under root AUTHORIZE — TERMINAL: the fee reserve and
 *       the whole token position move to the GENESIS-PINNED cold recoveryPk.
 *
 * NEGATIVE VALIDATION (step 14 + the age proof in step 15) is performed with
 * AUTHORIZED TESTNET NEGATIVE-VALIDATION TRANSACTIONS CONSTRUCTED
 * INDEPENDENTLY OF THE POLICYVAULT APPLICATION — the owner signature blob,
 * the covenant call bytes and the transaction outputs are assembled here from
 * the production encoder rather than by the SDK builders (which refuse to
 * build them at all) — verifying that consensus rejects policy-invalid
 * transactions even when correctly signed by the designated owners/delegate.
 *
 * Every accepted step is CHAIN-VERIFIED against the node's UTXO index (exact
 * value, address, covenant id), its predecessors must be CONSUMED, and the
 * ladder AUTHORIZED -> SIGNED -> BROADCAST -> CHAIN_SEEN -> CHAIN_VERIFIED ->
 * VERIFIED_OUTCOME is recorded for each. Evidence ->
 * docs/testnet-v7-org-root-evidence.json.
 *
 * --dry-run: exercise the whole build/verify/sign/finalize plumbing against
 * SYNTHETIC chain facts with NO RPC and NO broadcast (writes nothing under
 * docs/). Live:
 *   KASPA_NETWORK_ID=testnet-10 KASPA_RPC_URL=ws://127.0.0.1:18210 \
 *     node tools/testnet-v7-lifecycle.js
 */

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const { loadConfig } = require("../sdk/src/config");
const { loadOrCreateTestKeys } = require("../sdk/src/keys");
const { connectVerified, getAddressUtxos, getVirtualDaaScore } = require("../sdk/src/chain");
const assets = require("../core/assets");
const { compileKcc20Program } = require("../sdk/src/token-program-kcc20");
const { buildTokenAgentTreeV5 } = require("../sdk/src/agent-merkle-v5");
const { buildRecipientTree } = require("../sdk/src/recipient-merkle-v3");
const { compileExactStateV7Root, compileExactStateV7, assertRootPinsMatchV7 } = require("../sdk/src/contract-compiler-v7");
const {
  buildCreateV7Root,
  buildV7RootTransaction,
  finalizeV7RootTransaction,
  buildCreateV7Vault,
  buildV7Transaction,
  finalizeV7Transaction,
  buildTokenDepositV7,
  finalizeTokenDepositV7,
  rootSuccessorCallJsonV7,
  successorCallJsonV7
} = require("../sdk/src/vault-builders-v7");
const { runEncoderV4 } = require("../sdk/src/vault-builders-v4");
const { encodeTokenTransfer } = require("../sdk/src/vault-builders-v5");
const { covenantSigscript } = require("../sdk/src/spend-vault");
const { frozenToWasmTransaction, describeFrozenTx } = require("../sdk/src/frozen-tx-v3");
const { normalizeFrozenTxV3, canonicalFrozenTxJson, feeDescriptorFromFrozen } = require("../core/model/frozen-tx-v3");
const { calculateRequiredFee } = require("../sdk/src/fee-mass");
const { p2pkScriptHex } = require("../sdk/src/approval-package-v4");
const { OWNER_SLOTS_V7, INACTIVE_SLOT_KEY, PLACEHOLDER_SLOT_HEX_V7 } = require("../core/model/owner-set-v7");
const { normalizeRootStateV7 } = require("../core/model/vault-state-v7-root");
const { buildOrgRootIntentManifest, verifyOrgRootIntentManifest, buildRootedVaultManifestV7, verifyRootedVaultManifestV7 } = require("../core/intent/org-root-manifest-v7");

const DRY = process.argv.includes("--dry-run") || process.argv.includes("--dry");
const KAS = 100000000n;
const FAMILY_BOUND = 2;
const ROOT_DIR = path.join(__dirname, "..");
const DATA_ROOT = process.env.PV_LIVE_DATA_ROOT || (DRY ? fs.mkdtempSync("/tmp/pv7-dry-") : "/tmp/pv7-live-data");
const EVIDENCE_PATH = path.join(ROOT_DIR, "docs", "testnet-v7-org-root-evidence.json");

/* ---- SMALL live parameters (gate I5) ---- */
const ROOT_KAS = 2n * KAS; /* the root's own small KAS fee reserve */
const VAULT_RESERVE = 3n * KAS; /* the rooted vault's fee reserve */
const NOTE_CARRY = 1n * KAS; /* KAS carried by the vault's token position */
const SUPPLY = "1000000";
const DEPOSIT = "10000";
const RECOVERY_DELAY_DAA = 600n; /* ~62 s at the measured testnet-10 rate */
const SUCCESSION_DELAY_DAA = 600n;
const ROOT_MAX_FEE_PER_TX = 1000000n; /* 0.01 KAS — the ONLY value a root transition may lose */
const TOKEN_MAX_PER_SPEND = "250";
const TOKEN_PERIOD_BUDGET = "2000";
const PERIOD_LENGTH_DAA = "100000000";
const AGENT_MAX_FEE_PER_TX = (1n * KAS).toString();
const AGENT_MAX_CARRY_KAS = (KAS / 4n).toString();
const HONEST_SPEND = "200";
/* the over-cap negative-validation amount is derived LIVE as (on-chain cap + 1) */
const RECIPIENT_CARRY = KAS / 5n;
const RESERVE_CONSUMED = "50000";

/* ---- deterministic evidence ---- */
const evidence = {
  schema: "policyvault-testnet-v7-org-root-evidence/1",
  startedAt: new Date().toISOString(),
  finishedAt: null,
  dryRun: DRY,
  mainnet: false,
  network: null,
  covenant: { before: null, after: null },
  parameters: {
    rootKasSompi: ROOT_KAS.toString(),
    vaultFeeReserveSompi: VAULT_RESERVE.toString(),
    tokenPositionCarryKasSompi: NOTE_CARRY.toString(),
    tokenSupply: SUPPLY,
    tokenDeposit: DEPOSIT,
    recoveryDelayDaa: RECOVERY_DELAY_DAA.toString(),
    successionDelayDaa: SUCCESSION_DELAY_DAA.toString(),
    rootMaxFeePerTxSompi: ROOT_MAX_FEE_PER_TX.toString(),
    genesisQuorum: "2-of-3 (ownerM 2, emergencyK 1, recoveryM 1)"
  },
  organization: null,
  steps: [],
  negatives: [],
  ageProofs: [],
  notExercised: [],
  summary: null
};

function record(step, data) {
  const entry = { step, at: new Date().toISOString(), ...data };
  evidence.steps.push(entry);
  console.log(`[${step}]`, JSON.stringify(data));
  return entry;
}
function recordNegative(name, data) {
  const entry = { name, at: new Date().toISOString(), classification: "AUTHORIZED TESTNET NEGATIVE-VALIDATION TRANSACTION", ...data };
  evidence.negatives.push(entry);
  console.log(`[negative:${name}]`, JSON.stringify(data));
  return entry;
}
const sha256File = (p) => crypto.createHash("sha256").update(fs.readFileSync(p)).digest("hex");
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const COVENANT_FILES = {
  "PolicyVault.v0.5.sil": "c693aeffb59286d21d44452bde0943d78840b66cf480b629624b7747b4197dd9",
  "PolicyVault.v0.6.sil": "c7c5f22c54a55d933ec8440a28bc2c628b9b99262541d50dbe9ffbdd16ba025c",
  "PolicyVault.v0.7-root.sil": "69417514f90d61b0281ea673e6fb5a5fd858c2bd50e14a4eb9043d5fdf17f8ce",
  "PolicyVault.v0.7-payment.sil": "09cdbb6c284d8bd6c4cd2f4aad20d9682172eea3e048631176034b517be25091"
};
function verifyCovenantBytes(phase) {
  const out = {};
  for (const [file, expected] of Object.entries(COVENANT_FILES)) {
    const actual = sha256File(path.join(ROOT_DIR, "contracts", file));
    out[file] = actual;
    if (actual !== expected) throw new Error(`${phase}: ${file} sha256 ${actual} != expected ${expected} — a frozen/candidate covenant moved; STOP`);
  }
  return out;
}

async function main() {
  const config = loadConfig({ dataRoot: DATA_ROOT, ...(DRY ? { networkId: "testnet-10", rpcUrl: "ws://127.0.0.1:18210" } : {}) });
  if (config.networkId !== "testnet-10") throw new Error(`refusing: this script is testnet-10 only (configured ${config.networkId})`);
  if (/mainnet/i.test(String(config.rpcUrl))) throw new Error("refusing: the configured RPC URL names mainnet");
  evidence.covenant.before = verifyCovenantBytes("pre-flight");

  const kaspa = require(config.rustyKaspaModule);
  const keys = loadOrCreateTestKeys(config);
  const PK = (k) => new kaspa.PrivateKey(k.secret);
  const XO = (k) => PK(k).toPublicKey().toXOnlyPublicKey().toString().toLowerCase();
  /* deterministic TEST-ONLY governance keys: the byte value repeated 32x */
  const KEY = (v) => new kaspa.PrivateKey(v.toString(16).padStart(2, "0").repeat(32));
  const XOK = (p) => p.toPublicKey().toXOnlyPublicKey().toString().toLowerCase();

  const fuelKey = keys.funding ?? keys.owner; /* pays every network fee; receives every change */
  const agentKey = keys.delegate;
  const recipientKey = keys.recipient1;
  if (!fuelKey || !agentKey || !recipientKey) throw new Error("test key roles funding/delegate/recipient1 are required");

  const O = [KEY(0x71), KEY(0x72), KEY(0x73)]; /* genesis owner set A */
  const N1 = KEY(0x81); /* the member installed by the rotation */
  const REC = [KEY(0x91), KEY(0x92)]; /* the set an owner-recovery installs */
  const SUC = [KEY(0xa1), KEY(0xa2)]; /* the set a succession installs */
  const successorKey = KEY(0x7f);
  const outsiderKey = KEY(0x6f); /* never a member — negative validation only */
  const recoveryKey = KEY(0x51); /* the vault's genesis-pinned COLD recovery destination */

  const slots = (ks) => {
    const out = [];
    for (let i = 0; i < OWNER_SLOTS_V7; i += 1) out.push(i < ks.length ? XOK(ks[i]) : INACTIVE_SLOT_KEY);
    return out;
  };
  const ORG_ID = crypto.createHash("sha256").update("policyvault-v0.7-testnet-10-org-root-lifecycle").digest("hex");
  const VAULT_ID = crypto.createHash("sha256").update("policyvault-v0.7-testnet-10-rooted-payment-vault").digest("hex");

  const rootTemplate = {
    orgId: ORG_ID,
    recoveryDelayDaa: RECOVERY_DELAY_DAA.toString(),
    successorPk: XOK(successorKey),
    successionDelayDaa: SUCCESSION_DELAY_DAA.toString(),
    rootMaxFeePerTx: ROOT_MAX_FEE_PER_TX.toString()
  };
  const SET_A = { owners: slots(O), ownerM: 2, emergencyK: 1, recoveryM: 1 };
  const SET_B = { owners: slots([O[0], O[1], N1]), ownerM: 2, emergencyK: 1, recoveryM: 1 };
  const SET_C = { owners: slots([O[0], O[1], N1]), ownerM: 3, emergencyK: 1, recoveryM: 1 };
  const SET_D = { owners: slots(REC), ownerM: 2, emergencyK: 1, recoveryM: 1 };
  const SET_E = { owners: slots(SUC), ownerM: 2, emergencyK: 1, recoveryM: 1 };
  /* the private keys behind each set, in slot order (TEST ONLY) */
  let liveOwnerKeys = [...O];

  /* ---- node ---- */
  let rpc = null;
  if (!DRY) {
    const { rpc: client, serverInfo } = await connectVerified(config);
    rpc = client;
    evidence.network = {
      rpcUrl: config.rpcUrl,
      networkId: serverInfo.networkId,
      serverVersion: serverInfo.serverVersion,
      isSynced: serverInfo.isSynced,
      hasUtxoIndex: serverInfo.hasUtxoIndex,
      virtualDaaScoreAtStart: (await getVirtualDaaScore(rpc)).toString()
    };
    record("connect", evidence.network);
  } else {
    evidence.network = { networkId: "testnet-10", dryRun: true };
  }
  const daa = async () => (DRY ? 560000000n : await getVirtualDaaScore(rpc));

  /* ---- chain helpers ---- */
  const p2shAddress = (spkHex) => (DRY ? `dry:p2sh:${spkHex.slice(4, 20)}` : kaspa.addressFromScriptPublicKey({ version: 0, script: spkHex }, config.networkId).toString());
  const p2pkAddress = (pk) => (DRY ? `dry:p2pk:${pk.slice(0, 16)}` : kaspa.addressFromScriptPublicKey({ version: 0, script: p2pkScriptHex(pk) }, config.networkId).toString());
  const p2shOfBytes = (scriptBytes) => String(kaspa.payToScriptHashScript(Buffer.from(scriptBytes).toString("hex")).script).toLowerCase();
  const FUEL_SPK = `20${XO(fuelKey)}ac`;
  const FUEL_ADDRESS = p2pkAddress(XO(fuelKey));

  /* THE FUEL CHAIN. Every transaction this tool broadcasts sends its change to
   * P2PK(fuel) as its LAST output; the next transaction spends exactly that
   * change. No indexer guessing, no double-spend races. */
  let fuel = null;
  let lastAccepted = null; /* { label, txId, finalTransaction } — for the replay negative */
  async function primeFuel() {
    if (DRY) {
      fuel = { outpoint: { transactionId: "f0".repeat(32), index: 0 }, amount: 100000n * KAS, scriptPublicKeyHex: FUEL_SPK };
      return;
    }
    const utxos = (await getAddressUtxos(rpc, fuelKey.address)).filter((u) => u.covenantId === null && u.amount > 500n * KAS);
    if (!utxos.length) throw new Error(`no plain UTXO > 500 KAS on the test funding key — fund it before running gate I5`);
    const u = utxos.reduce((a, b) => (a.amount > b.amount ? a : b));
    fuel = { outpoint: u.outpoint, amount: u.amount, scriptPublicKeyHex: u.scriptPublicKeyHex };
    record("fuel-primed", { outpoint: `${u.outpoint.transactionId}:${u.outpoint.index}`, amountSompi: u.amount.toString(), address: fuelKey.address });
  }
  function advanceFuel(build, txId) {
    const outs = build.frozen.outputs;
    const last = outs[outs.length - 1];
    if (last.scriptPublicKey.scriptHex.toLowerCase() !== FUEL_SPK) throw new Error("internal: the last output is not the fuel change — the fuel chain would break");
    fuel = { outpoint: { transactionId: txId, index: outs.length - 1 }, amount: last.value, scriptPublicKeyHex: FUEL_SPK };
    return { index: outs.length - 1, value: last.value.toString() };
  }
  const fuelUtxo = () => ({ outpoint: fuel.outpoint, amount: fuel.amount.toString(), scriptPublicKeyHex: fuel.scriptPublicKeyHex });

  function finalToWasm(finalTx) {
    const { finalTxToWasm } = require("../sdk/src/wallet-submit-v4");
    return finalTxToWasm(config, finalTx);
  }
  async function submitAndProve(label, finalTx, expectations) {
    if (DRY) {
      record(`${label}:BROADCAST`, { dryRun: true, txId: expectations.txId, status: "DRY" });
      return { txId: expectations.txId, verified: [] };
    }
    const submitted = await rpc.submitTransaction({ transaction: finalToWasm(finalTx), allowOrphan: false });
    const txId = String(submitted.transactionId).toLowerCase();
    if (txId !== expectations.txId) throw new Error(`${label}: node txid ${txId} != planned ${expectations.txId}`);
    record(`${label}:BROADCAST`, { txId, status: "BROADCAST" });
    const verified = [];
    let seen = false;
    for (const e of expectations.expect) {
      let found = null;
      for (let i = 0; i < 60 && !found; i += 1) {
        const utxos = await getAddressUtxos(rpc, e.address);
        found = utxos.find((u) => u.outpoint.transactionId === txId && u.outpoint.index === e.index) || null;
        if (!found) await sleep(2000);
      }
      if (!found) throw new Error(`${label}: expected output ${txId}:${e.index} at ${e.address} did not appear`);
      if (!seen) {
        record(`${label}:CHAIN_SEEN`, { txId, status: "CHAIN_SEEN", firstOutputSeen: `${txId}:${e.index}`, blockDaaScore: found.blockDaaScore?.toString?.() ?? null });
        seen = true;
      }
      if (found.amount.toString() !== e.value) throw new Error(`${label}: output ${e.index} value ${found.amount} != ${e.value}`);
      if (e.covenantId !== undefined && String(found.covenantId ?? "").toLowerCase() !== e.covenantId) throw new Error(`${label}: output ${e.index} covenant id ${found.covenantId} != ${e.covenantId}`);
      verified.push({ label: e.label ?? null, outpoint: `${txId}:${e.index}`, address: e.address, valueSompi: e.value, covenantId: e.covenantId ?? null, blockDaaScore: found.blockDaaScore?.toString?.() ?? null });
    }
    for (const c of expectations.consumed ?? []) {
      const utxos = await getAddressUtxos(rpc, c.address);
      if (utxos.some((u) => u.outpoint.transactionId === c.transactionId && u.outpoint.index === c.index)) {
        throw new Error(`${label}: predecessor ${c.transactionId}:${c.index} is still unspent — the transition is NOT proven`);
      }
    }
    record(`${label}:CHAIN_VERIFIED`, { txId, status: "CHAIN_VERIFIED", verified, consumed: (expectations.consumed ?? []).map((c) => `${c.transactionId}:${c.index}`) });
    lastAccepted = { label, txId, finalTransaction: JSON.parse(JSON.stringify(finalTx)) };
    return { txId, verified };
  }
  async function expectRejected(name, finalTx, why, extra = {}) {
    if (DRY) {
      recordNegative(name, { dryRun: true, why, ...extra });
      return null;
    }
    let detail = null;
    try {
      await rpc.submitTransaction({ transaction: finalToWasm(finalTx), allowOrphan: false });
    } catch (e) {
      detail = String(e.message ?? e);
    }
    if (detail === null) throw new Error(`${name}: the node ACCEPTED a policy-invalid transaction — STOP`);
    recordNegative(name, { rejected: true, why, nodeRejection: detail, ...extra });
    return detail;
  }
  const signInputOf = (frozen, idx, key) => kaspa.createInputSignature(frozenToWasmTransaction(config, frozen), idx, key);
  const approvalsFor = (frozen, idx, keyIdxs) => keyIdxs.map((i) => ({ slot: i + 1, signatureHex: signInputOf(frozen, idx, liveOwnerKeys[i]).slice(2) }));

  /* =============================================================== 1. KCC20 ISSUANCE */
  await primeFuel();
  const userState = { ownerIdentifier: XO(fuelKey), identifierType: 0, amount: SUPPLY, isMinter: false };
  const userProgram = compileKcc20Program({ config, state: userState, familyBound: FAMILY_BOUND });
  const issuanceValue = 3n * KAS;
  function plainGenesis(funding, outputScriptHex, value, covId) {
    const draft = {
      version: 1,
      inputs: [{ previousOutpoint: funding.outpoint, sequence: 0n, computeBudget: 10, utxo: { amount: funding.amount, scriptPublicKey: { version: 0, scriptHex: funding.scriptPublicKeyHex }, covenantId: null, blockDaaScore: 0n } }],
      outputs: [
        { value, scriptPublicKey: { version: 0, scriptHex: outputScriptHex }, covenant: { authorizingInput: 0, covenantId: covId } },
        { value: 1n, scriptPublicKey: { version: 0, scriptHex: FUEL_SPK }, covenant: null }
      ],
      lockTime: 0n,
      subnetworkId: "00".repeat(20),
      gas: 0n,
      payload: ""
    };
    const fee = calculateRequiredFee(feeDescriptorFromFrozen(normalizeFrozenTxV3(draft), [66])).minimumRequiredFee;
    draft.outputs[1].value = funding.amount - value - fee;
    const frozen = normalizeFrozenTxV3(draft);
    const json = JSON.parse(canonicalFrozenTxJson(frozen));
    json.inputs[0].signatureScript = signInputOf(frozen, 0, PK(fuelKey));
    return { frozen, json, txId: describeFrozenTx(frozen).txId, fee };
  }
  const unboundNote = new kaspa.TransactionOutput(issuanceValue, kaspa.payToScriptHashScript(userProgram.scriptHex));
  const familyId = kaspa.covenantId({ transactionId: fuel.outpoint.transactionId, index: fuel.outpoint.index }, [{ index: 0, output: unboundNote }]).toString().toLowerCase();
  const issuance = plainGenesis(fuel, userProgram.p2shSpkHex, issuanceValue, familyId);
  record("01-kcc20-issuance:AUTHORIZED", { status: "AUTHORIZED", txId: issuance.txId, tokenFamilyId: familyId, supply: SUPPLY, templateVmHash: userProgram.templateVmHashBlake2b256, geometry: userProgram.geometry, feeSompi: issuance.fee.toString() });
  record("01-kcc20-issuance:SIGNED", { status: "SIGNED", txId: issuance.txId, sighash: "ALL" });
  await submitAndProve("01-kcc20-issuance", issuance.json, {
    txId: issuance.txId,
    expect: [
      { label: "user token position", address: p2shAddress(userProgram.p2shSpkHex), index: 0, value: issuanceValue.toString(), covenantId: familyId },
      { label: "fuel change", address: FUEL_ADDRESS, index: 1, value: issuance.frozen.outputs[1].value.toString() }
    ]
  });
  record("01-kcc20-issuance:VERIFIED_OUTCOME", { status: "VERIFIED_OUTCOME", txId: issuance.txId, tokenFamilyId: familyId, userPositionAmount: SUPPLY });
  advanceFuel(issuance, issuance.txId);
  let userPosition = { outpoint: { transactionId: issuance.txId, index: 0 }, value: issuanceValue, state: userState, program: userProgram };

  /* the accepted asset descriptor, from the vendored program's real bytes */
  const descriptor = {
    schema: "policyvault-asset-descriptor/1",
    assetId: familyId,
    displayName: "TN10 v0.7 Org Test Token",
    tokenStandard: "kcc20/1",
    tokenCovenantId: familyId,
    acceptedTransferTemplates: [{ templateVmHashBlake2b256: userProgram.templateVmHashBlake2b256, prefixLen: userProgram.geometry.prefixLen, suffixLen: userProgram.geometry.suffixLen, stateLayout: "kcc20-state/1" }],
    decimalsDisplay: 0,
    issuerPowers: { mint: false, burn: false, freeze: false, blacklist: false, redemptionControl: false, upgradeMigration: false, controllerRotation: false, emergencyControl: false }
  };
  const descriptorHash = assets.computeDescriptorHash(descriptor);
  assets.corroborateTemplate({ descriptor, prefixHex: userProgram.prefixHex, suffixHex: userProgram.suffixHex });

  /* =============================================================== 2. ROOT GENESIS */
  const rootGenesis = buildCreateV7Root({ config, template: rootTemplate, ownerSet: SET_A, rootValueSompi: ROOT_KAS.toString(), funding: [fuelUtxo()], changeXOnly: XO(fuelKey) });
  const rootId = rootGenesis.covenantId;
  const rootAddress = p2shAddress(p2shOfBytes(Buffer.from(rootGenesis.rootScriptHex, "hex")));
  {
    const json = JSON.parse(rootGenesis.frozenCanonicalJson);
    json.inputs[0].signatureScript = signInputOf(rootGenesis.frozen, 0, PK(fuelKey));
    record("02-root-genesis:AUTHORIZED", {
      status: "AUTHORIZED",
      txId: rootGenesis.txId,
      rootCovenantId: rootId,
      stateId: rootGenesis.stateId,
      stateDigest: rootGenesis.stateDigest,
      ownerSlots: rootGenesis.ownerSlots,
      initialState: rootGenesis.initialState,
      rootPins: rootGenesis.rootPins,
      scriptSha256: rootGenesis.scriptSha256,
      contractVersion: rootGenesis.contractVersion,
      feeSompi: rootGenesis.requiredFeeSompi
    });
    record("02-root-genesis:SIGNED", { status: "SIGNED", txId: rootGenesis.txId, sighash: "ALL" });
    await submitAndProve("02-root-genesis", json, {
      txId: rootGenesis.txId,
      expect: [
        { label: "organizational root", address: rootAddress, index: 0, value: ROOT_KAS.toString(), covenantId: rootId },
        { label: "fuel change", address: FUEL_ADDRESS, index: 1, value: rootGenesis.frozen.outputs[1].value.toString() }
      ]
    });
    record("02-root-genesis:VERIFIED_OUTCOME", { status: "VERIFIED_OUTCOME", txId: rootGenesis.txId, rootCovenantId: rootId, rootNonce: "0", frozen: "0", ownerM: "2", emergencyK: "1", recoveryM: "1" });
    advanceFuel(rootGenesis, rootGenesis.txId);
  }
  let root = { outpoint: { transactionId: rootGenesis.txId, index: 0 }, state: rootGenesis.initialState, ownerSet: SET_A, blockDaaScore: null };
  const rootHistory = [{ outpoint: { ...root.outpoint }, rootNonce: "0" }];

  /* =============================================================== 3. VAULT GENESIS */
  const agentPolicy = (over = {}) => ({
    agentPk: XO(agentKey),
    tokenMaxPerSpend: TOKEN_MAX_PER_SPEND,
    tokenPeriodBudget: TOKEN_PERIOD_BUDGET,
    periodLengthDaa: PERIOD_LENGTH_DAA,
    periodStartDaa: "0",
    tokenPeriodSpent: "0",
    agentMaxFeePerTx: AGENT_MAX_FEE_PER_TX,
    agentMaxCarryKas: AGENT_MAX_CARRY_KAS,
    agentRecipientRoot: buildRecipientTree([XO(recipientKey)]).root,
    ...over
  });
  const rTree = buildRecipientTree([XO(recipientKey)]);
  let agents = [agentPolicy()];
  const agentRoot0 = buildTokenAgentTreeV5(agents).root;
  const vaultTemplate = {
    vaultId: VAULT_ID,
    descriptorHash,
    tokenCovenantId: familyId,
    templateVmHash: userProgram.templateVmHashBlake2b256,
    templatePrefixLen: userProgram.geometry.prefixLen,
    templateStateLen: userProgram.geometry.stateLen,
    templateSuffixLen: userProgram.geometry.suffixLen,
    ...rootGenesis.rootPins,
    recoveryPk: XOK(recoveryKey)
  };
  assertRootPinsMatchV7({ config, vaultTemplate, rootTemplate, rootOwnerSet: SET_A });
  const vaultState0 = { feeReserve: VAULT_RESERVE.toString(), paused: "0", agentRoot: agentRoot0, policyNonce: "0" };
  const vaultGenesis = buildCreateV7Vault({ config, templateInput: vaultTemplate, initialStateInput: vaultState0, funding: [fuelUtxo()], changeXOnly: XO(fuelKey), descriptor });
  const vaultId = vaultGenesis.covenantId;
  {
    const json = JSON.parse(vaultGenesis.frozenCanonicalJson);
    json.inputs[0].signatureScript = signInputOf(vaultGenesis.frozen, 0, PK(fuelKey));
    record("03-vault-genesis:AUTHORIZED", {
      status: "AUTHORIZED",
      txId: vaultGenesis.txId,
      vaultCovenantId: vaultId,
      stateId: vaultGenesis.stateId,
      orgRootCovenantId: vaultGenesis.orgRootCovenantId,
      rootPinsCarried: { rootTemplateVmHash: vaultTemplate.rootTemplateVmHash, rootPrefixLen: vaultTemplate.rootPrefixLen, rootStateLen: vaultTemplate.rootStateLen, rootSuffixLen: vaultTemplate.rootSuffixLen },
      recoveryPk: vaultTemplate.recoveryPk,
      initialState: vaultGenesis.initialState,
      scriptSha256: vaultGenesis.scriptSha256,
      contractVersion: vaultGenesis.contractVersion,
      feeSompi: vaultGenesis.requiredFeeSompi
    });
    record("03-vault-genesis:SIGNED", { status: "SIGNED", txId: vaultGenesis.txId, sighash: "ALL" });
    await submitAndProve("03-vault-genesis", json, {
      txId: vaultGenesis.txId,
      expect: [
        { label: "rooted payment vault", address: p2shAddress(vaultGenesis.frozen.outputs[0].scriptPublicKey.scriptHex), index: 0, value: VAULT_RESERVE.toString(), covenantId: vaultId },
        { label: "fuel change", address: FUEL_ADDRESS, index: 1, value: vaultGenesis.frozen.outputs[1].value.toString() }
      ]
    });
    record("03-vault-genesis:VERIFIED_OUTCOME", { status: "VERIFIED_OUTCOME", txId: vaultGenesis.txId, vaultCovenantId: vaultId, pinnedRoot: rootId, feeReserve: VAULT_RESERVE.toString() });
    advanceFuel(vaultGenesis, vaultGenesis.txId);
  }
  let vault = { outpoint: { transactionId: vaultGenesis.txId, index: 0 }, state: vaultGenesis.initialState };

  evidence.organization = {
    orgId: ORG_ID,
    rootCovenantId: rootId,
    rootTemplate,
    rootPins: rootGenesis.rootPins,
    rootAddress,
    vaultCovenantId: vaultId,
    vaultId: VAULT_ID,
    vaultTemplate: { ...vaultTemplate },
    recoveryPk: vaultTemplate.recoveryPk,
    recoveryAddress: p2pkAddress(vaultTemplate.recoveryPk),
    tokenFamilyId: familyId,
    descriptorHash,
    successorPk: rootTemplate.successorPk
  };

  /* =============================================================== 4. TOKEN DEPOSIT */
  const deposit = buildTokenDepositV7({
    config,
    descriptor,
    vault: { covenantId: vaultId, template: vaultTemplate },
    chain: { userPosition: { outpoint: userPosition.outpoint, value: userPosition.value.toString(), scriptPublicKeyHex: userProgram.p2shSpkHex, covenantId: familyId, state: userState }, fuel: fuelUtxo() },
    params: { depositAmount: DEPOSIT, depositCarryKasSompi: NOTE_CARRY.toString() },
    changeXOnly: XO(fuelKey)
  });
  const positionState = { ownerIdentifier: vaultId, identifierType: 2, amount: DEPOSIT, isMinter: false };
  const positionProgram = compileKcc20Program({ config, state: positionState, familyBound: FAMILY_BOUND });
  const userRemainderState = { ...userState, amount: (BigInt(SUPPLY) - BigInt(DEPOSIT)).toString() };
  const userRemainderProgram = compileKcc20Program({ config, state: userRemainderState, familyBound: FAMILY_BOUND });
  {
    record("04-token-deposit:AUTHORIZED", { status: "AUTHORIZED", txId: deposit.txId, accounting: deposit.accounting, vaultCovenantId: vaultId, feeSompi: deposit.requiredFeeSompi });
    const finalTx = finalizeTokenDepositV7({ build: deposit, tokenOwnerSignatureHex: signInputOf(deposit.frozen, 0, PK(fuelKey)).slice(2), fuelSignatureScriptHex: signInputOf(deposit.frozen, 1, PK(fuelKey)) }).finalTransaction;
    record("04-token-deposit:SIGNED", { status: "SIGNED", txId: deposit.txId, sighash: "ALL" });
    await submitAndProve("04-token-deposit", finalTx, {
      txId: deposit.txId,
      expect: [
        { label: "vault-owned token position", address: p2shAddress(positionProgram.p2shSpkHex), index: 0, value: NOTE_CARRY.toString(), covenantId: familyId },
        { label: "user remainder", address: p2shAddress(userRemainderProgram.p2shSpkHex), index: 1, value: deposit.accounting.kas.remainderCarryKas, covenantId: familyId },
        { label: "fuel change", address: FUEL_ADDRESS, index: 2, value: deposit.frozen.outputs[2].value.toString() }
      ],
      consumed: [{ address: p2shAddress(userProgram.p2shSpkHex), ...userPosition.outpoint }]
    });
    record("04-token-deposit:VERIFIED_OUTCOME", { status: "VERIFIED_OUTCOME", txId: deposit.txId, positionAmount: DEPOSIT, ownedBy: vaultId, remainderToUser: deposit.accounting.token.remainderToUser });
    advanceFuel(deposit, deposit.txId);
  }
  let position = { outpoint: { transactionId: deposit.txId, index: 0 }, value: NOTE_CARRY, state: positionState, program: positionProgram };
  userPosition = { outpoint: { transactionId: deposit.txId, index: 1 }, value: BigInt(deposit.accounting.kas.remainderCarryKas), state: userRemainderState, program: userRemainderProgram };

  /* =============================================================== helpers for the governed steps */
  const rootSideOf = () => ({ template: rootTemplate, state: root.state, outpoint: root.outpoint, covenantId: rootId, value: ROOT_KAS.toString() });
  const rootChainOf = () => ({ predecessorOutpoint: root.outpoint, covenantId: rootId, predecessorValue: ROOT_KAS.toString(), fuel: fuelUtxo() });
  const rootAddrOf = (state) => p2shAddress(p2shOfBytes(compileExactStateV7Root({ config, template: rootTemplate, state }).scriptBytes));

  async function runRootOp(label, action, { newOwnerSet, signerIdx, useSuccessor = false, ageProof = false, newKeys } = {}) {
    const build = buildV7RootTransaction({
      config,
      templateInput: rootTemplate,
      stateInput: root.state,
      action,
      params: newOwnerSet ? { newOwnerSet } : {},
      chain: rootChainOf(),
      changeXOnly: XO(fuelKey)
    });
    const satisfied = useSuccessor ? 1 : signerIdx.length;
    const manifest = buildOrgRootIntentManifest({ build, vaultOperations: [], satisfiedApprovals: satisfied });
    const verdict = verifyOrgRootIntentManifest({ manifest });
    if (verdict.verdict !== "VERIFIED") throw new Error(`${label}: the org-root manifest did not verify locally: ${JSON.stringify(verdict.failures)}`);
    record(`${label}:AUTHORIZED`, {
      status: "AUTHORIZED",
      txId: build.txId,
      action,
      rootAction: String(build.rootAction),
      authorityClass: build.authorityClass,
      quorumSource: build.quorumSource,
      requiredApprovals: build.requiredApprovals,
      satisfiedApprovals: String(satisfied),
      minSequence: build.minSequence,
      predecessorOutpoint: `${build.predecessorOutpoint.transactionId}:${build.predecessorOutpoint.index}`,
      predecessorStateId: build.predecessorStateId,
      predecessorStateDigest: build.predecessorStateDigest,
      successorStateId: build.successorStateId,
      successorStateDigest: build.successorStateDigest,
      successorTailHex: build.successorTailHex,
      successorState: build.successorState,
      manifestHash: manifest.manifestHash,
      manifestVerdict: verdict.verdict,
      manifestChecks: verdict.checks.length,
      computeBudget: build.computeBudget,
      feeSompi: build.requiredFeeSompi,
      accounting: build.accounting.kas
    });
    const wasm = build.frozen;
    const fin = useSuccessor
      ? finalizeV7RootTransaction({ build, successorSignatureHex: signInputOf(wasm, 0, successorKey).slice(2), fuelSignatureScriptHex: signInputOf(wasm, 1, PK(fuelKey)) })
      : finalizeV7RootTransaction({ build, approvals: approvalsFor(wasm, 0, signerIdx), fuelSignatureScriptHex: signInputOf(wasm, 1, PK(fuelKey)) });
    record(`${label}:SIGNED`, { status: "SIGNED", txId: build.txId, sighash: "ALL", signedSlots: fin.signedSlots, requiredApprovals: fin.requiredApprovals, satisfiedApprovals: fin.satisfiedApprovals, signerRole: useSuccessor ? "pinned successor key" : "owner slots" });

    const successorAddress = rootAddrOf(build.successorState);
    const expectations = {
      txId: build.txId,
      expect: [
        { label: "root successor", address: successorAddress, index: 0, value: ROOT_KAS.toString(), covenantId: rootId },
        { label: "fuel change", address: FUEL_ADDRESS, index: 1, value: build.frozen.outputs[1].value.toString() }
      ],
      consumed: [{ address: rootAddrOf(root.state), ...root.outpoint }]
    };

    if (ageProof && !DRY) {
      /* THE CONSENSUS PROOF — the EXACT SAME finalized bytes, twice. */
      const before = await daa();
      const utxoDaa = BigInt(root.blockDaaScore);
      const age = before - utxoDaa;
      const requiredDelay = action === "succession" ? SUCCESSION_DELAY_DAA : RECOVERY_DELAY_DAA;
      if (age >= requiredDelay) throw new Error(`${label}: the root UTXO is already ${age} DAA old — the pre-age rejection cannot be proven; STOP`);
      const rejection = await expectRejected(`${label}-before-age`, fin.finalTransaction, `the SAME finalized bytes submitted while the root UTXO is only ${age} DAA old (< ${requiredDelay} required by the covenant's relative input-age lock, enforced by consensus check_sequence_lock)`, {
        txId: build.txId,
        rootUtxoBlockDaaScore: utxoDaa.toString(),
        virtualDaaScoreAtSubmit: before.toString(),
        ageDaa: age.toString(),
        requiredAgeDaa: requiredDelay.toString(),
        inputSequence: build.minSequence
      });
      const target = utxoDaa + requiredDelay + 10n; /* margin: the mempool's point-of-view DAA score is its own virtual score */
      let now = before;
      for (let i = 0; i < 400 && now < target; i += 1) {
        await sleep(3000);
        now = await daa();
      }
      if (now < target) throw new Error(`${label}: the chain did not reach DAA ${target}`);
      evidence.ageProofs.push({
        name: label,
        action,
        requiredAgeDaa: requiredDelay.toString(),
        inputSequence: build.minSequence,
        rootUtxoBlockDaaScore: utxoDaa.toString(),
        txId: build.txId,
        identicalBytes: true,
        phaseA: { virtualDaaScore: before.toString(), ageDaa: age.toString(), outcome: "REJECTED", nodeRejection: rejection },
        phaseB: { virtualDaaScore: now.toString(), ageDaa: (now - utxoDaa).toString(), outcome: "ACCEPTED" }
      });
      record(`${label}:AGE_REACHED`, { status: "AGE_REACHED", virtualDaaScore: now.toString(), rootUtxoBlockDaaScore: utxoDaa.toString(), ageDaa: (now - utxoDaa).toString(), requiredAgeDaa: requiredDelay.toString() });
    }

    const { verified } = await submitAndProve(label, fin.finalTransaction, expectations);
    const successorDaa = verified.length ? verified[0].blockDaaScore : null;
    record(`${label}:VERIFIED_OUTCOME`, {
      status: "VERIFIED_OUTCOME",
      txId: build.txId,
      action,
      rootNonce: { before: build.stateJson.rootNonce, after: build.successorState.rootNonce },
      frozen: { before: build.stateJson.frozen, after: build.successorState.frozen },
      ownerM: { before: build.stateJson.ownerM, after: build.successorState.ownerM },
      emergencyK: { before: build.stateJson.emergencyK, after: build.successorState.emergencyK },
      recoveryM: { before: build.stateJson.recoveryM, after: build.successorState.recoveryM },
      rootValue: { before: build.accounting.kas.rootValueBefore, after: build.accounting.kas.rootValueAfter, maxAllowedLoss: build.accounting.kas.rootMaxFeePerTx, actualLoss: "0" },
      successorOutpoint: `${build.txId}:0`,
      successorBlockDaaScore: successorDaa
    });
    rootHistory.push({ outpoint: { transactionId: build.txId, index: 0 }, rootNonce: build.successorState.rootNonce });
    root = { outpoint: { transactionId: build.txId, index: 0 }, state: build.successorState, ownerSet: newOwnerSet ?? root.ownerSet, blockDaaScore: successorDaa };
    if (newKeys) liveOwnerKeys = newKeys;
    advanceFuel(build, build.txId);
    return build;
  }

  async function runVaultOwnerOp(label, action, params, signerIdx) {
    const build = buildV7Transaction({
      config,
      templateInput: vaultTemplate,
      stateInput: vault.state,
      action,
      params,
      chain: { predecessorOutpoint: vault.outpoint, covenantId: vaultId, predecessorValue: vault.state.feeReserve, fuel: fuelUtxo(), root: rootSideOf() },
      changeXOnly: XO(fuelKey),
      descriptor
    });
    const manifest = buildOrgRootIntentManifest({ build, vaultOperations: [{ build, descriptor }], satisfiedApprovals: signerIdx.length });
    const verdict = verifyOrgRootIntentManifest({ manifest, descriptors: { [vaultId]: descriptor } });
    if (verdict.verdict !== "VERIFIED") throw new Error(`${label}: the org-root manifest did not verify locally: ${JSON.stringify(verdict.failures)}`);
    record(`${label}:AUTHORIZED`, {
      status: "AUTHORIZED",
      txId: build.txId,
      action,
      opSelector: String(build.callExtra.opSelector),
      rootAuthority: {
        rootActionName: build.rootAuthority.rootActionName,
        rootAction: String(build.rootAuthority.rootAction),
        authorityClass: build.rootAuthority.authorityClass,
        quorumSource: build.rootAuthority.quorumSource,
        requiredApprovals: build.rootAuthority.requiredApprovals,
        expectFrozenAfter: build.rootAuthority.expectFrozenAfter,
        rootOutpoint: `${build.rootAuthority.outpoint.transactionId}:${build.rootAuthority.outpoint.index}`,
        prevStateDigest: build.rootAuthority.prevStateDigest,
        newStateDigest: build.rootAuthority.newStateDigest,
        successorTailHex: build.rootAuthority.successorTailHex
      },
      predecessorOutpoint: `${build.predecessorOutpoint.transactionId}:${build.predecessorOutpoint.index}`,
      predecessorStateId: build.predecessorStateId,
      successorStateId: build.successorStateId,
      successorState: build.successorState,
      manifestHash: manifest.manifestHash,
      manifestVerdict: verdict.verdict,
      manifestChecks: verdict.checks.length,
      computeBudget: build.computeBudget,
      feeSompi: build.requiredFeeSompi
    });
    const fin = finalizeV7Transaction({ build, approvals: approvalsFor(build.frozen, 1, signerIdx), fuelSignatureScriptHex: signInputOf(build.frozen, 2, PK(fuelKey)) });
    record(`${label}:SIGNED`, { status: "SIGNED", txId: build.txId, sighash: "ALL", signedSlots: fin.signedSlots, requiredApprovals: fin.requiredApprovals, satisfiedApprovals: fin.satisfiedApprovals, note: "the vault operation itself carries NO signature — the root input IS the authority" });
    const rootSuccessorAddress = rootAddrOf(build.rootAuthority.newState);
    const { verified } = await submitAndProve(label, fin.finalTransaction, {
      txId: build.txId,
      expect: [
        { label: "vault successor", address: p2shAddress(build.frozen.outputs[0].scriptPublicKey.scriptHex), index: 0, value: build.successorState.feeReserve, covenantId: vaultId },
        { label: "root successor", address: rootSuccessorAddress, index: 1, value: ROOT_KAS.toString(), covenantId: rootId },
        { label: "fuel change", address: FUEL_ADDRESS, index: 2, value: build.frozen.outputs[2].value.toString() }
      ],
      consumed: [
        { address: p2shAddress(build.frozen.inputs[0].utxo.scriptPublicKey.scriptHex), ...vault.outpoint },
        { address: rootAddrOf(root.state), ...root.outpoint }
      ]
    });
    record(`${label}:VERIFIED_OUTCOME`, {
      status: "VERIFIED_OUTCOME",
      txId: build.txId,
      vault: { paused: { before: build.stateJson.paused, after: build.successorState.paused }, agentRoot: { before: build.stateJson.agentRoot, after: build.successorState.agentRoot }, feeReserve: { before: build.stateJson.feeReserve, after: build.successorState.feeReserve }, policyNonce: { before: build.stateJson.policyNonce, after: build.successorState.policyNonce } },
      root: { rootNonce: { before: build.rootAuthority.prevState.rootNonce, after: build.rootAuthority.newState.rootNonce }, frozen: { before: build.rootAuthority.prevState.frozen, after: build.rootAuthority.newState.frozen } },
      vaultSuccessorOutpoint: `${build.txId}:0`,
      rootSuccessorOutpoint: `${build.txId}:1`
    });
    rootHistory.push({ outpoint: { transactionId: build.txId, index: 1 }, rootNonce: build.rootAuthority.newState.rootNonce });
    vault = { outpoint: { transactionId: build.txId, index: 0 }, state: build.successorState };
    root = { outpoint: { transactionId: build.txId, index: 1 }, state: build.rootAuthority.newState, ownerSet: root.ownerSet, blockDaaScore: verified[1] ? verified[1].blockDaaScore : null };
    advanceFuel(build, build.txId);
    return build;
  }

  /* =============================================================== 5. DELEGATED SPEND (no root input) */
  let spendBuild;
  {
    const label = "05-delegated-spend";
    const build = buildV7Transaction({
      config,
      templateInput: vaultTemplate,
      stateInput: vault.state,
      action: "tokenAgentSpend",
      params: { spendAmount: HONEST_SPEND, agentPk: XO(agentKey), agents, recipient: XO(recipientKey), recipients: [...rTree.recipients], recipientCarryKasSompi: RECIPIENT_CARRY.toString(), reserveConsumedSompi: RESERVE_CONSUMED },
      chain: { predecessorOutpoint: vault.outpoint, covenantId: vaultId, predecessorValue: vault.state.feeReserve, fuel: fuelUtxo(), tokenPosition: { outpoint: position.outpoint, value: position.value.toString(), scriptPublicKeyHex: position.program.p2shSpkHex, covenantId: familyId, state: position.state } },
      changeXOnly: XO(fuelKey),
      descriptor
    });
    spendBuild = build;
    const vaultManifest = buildRootedVaultManifestV7({ build, descriptor });
    const failures = [];
    verifyRootedVaultManifestV7({ manifest: vaultManifest, frozen: JSON.parse(build.frozenCanonicalJson), descriptor, check: (n, ok, d) => { if (!ok) failures.push({ n, d }); } });
    if (failures.length) throw new Error(`${label}: the rooted-vault manifest did not verify locally: ${JSON.stringify(failures)}`);
    record(`${label}:AUTHORIZED`, {
      status: "AUTHORIZED",
      txId: build.txId,
      action: build.action,
      role: build.role,
      hasRootInput: build.hasRootInput,
      manifestHash: vaultManifest.manifestHash,
      manifestVerdict: "VERIFIED",
      payment: build.payment,
      accounting: build.accounting,
      agentProofRoot: build.agentProof.root,
      recipientProofRoot: build.recipientProof.root,
      computeBudget: build.computeBudget,
      feeSompi: build.requiredFeeSompi
    });
    const fin = finalizeV7Transaction({ build, agentSignatureHex: signInputOf(build.frozen, 0, PK(agentKey)).slice(2), fuelSignatureScriptHex: signInputOf(build.frozen, 2, PK(fuelKey)) });
    record(`${label}:SIGNED`, { status: "SIGNED", txId: build.txId, sighash: "ALL", signer: "delegate/agent key only", note: "the organizational root is NOT an input to an ordinary delegated spend" });
    const selfAfter = compileKcc20Program({ config, state: { ...position.state, amount: build.accounting.token.positionAfter }, familyBound: FAMILY_BOUND });
    const recipientAfter = compileKcc20Program({ config, state: { ownerIdentifier: XO(recipientKey), identifierType: 0, amount: HONEST_SPEND, isMinter: false }, familyBound: FAMILY_BOUND });
    await submitAndProve(label, fin.finalTransaction, {
      txId: build.txId,
      expect: [
        { label: "vault successor", address: p2shAddress(build.frozen.outputs[0].scriptPublicKey.scriptHex), index: 0, value: build.successorState.feeReserve, covenantId: vaultId },
        { label: "vault token continuation", address: p2shAddress(selfAfter.p2shSpkHex), index: 1, value: build.accounting.kas.tokenSelfCarryKas, covenantId: familyId },
        { label: "recipient token payment", address: p2shAddress(recipientAfter.p2shSpkHex), index: 2, value: build.accounting.kas.tokenRecipientCarryKas, covenantId: familyId },
        { label: "fuel change", address: FUEL_ADDRESS, index: 3, value: build.frozen.outputs[3].value.toString() }
      ],
      consumed: [
        { address: p2shAddress(build.frozen.inputs[0].utxo.scriptPublicKey.scriptHex), ...vault.outpoint },
        { address: p2shAddress(position.program.p2shSpkHex), ...position.outpoint }
      ]
    });
    record(`${label}:VERIFIED_OUTCOME`, {
      status: "VERIFIED_OUTCOME",
      txId: build.txId,
      tokenPosition: { before: build.accounting.token.positionBefore, after: build.accounting.token.positionAfter },
      paidToRecipient: build.accounting.token.spendAmount,
      recipientPk: XO(recipientKey),
      feeReserve: { before: build.stateJson.feeReserve, after: build.successorState.feeReserve, consumed: build.accounting.kas.reserveConsumed },
      agentRoot: { before: build.stateJson.agentRoot, after: build.successorState.agentRoot },
      rootTouched: false
    });
    vault = { outpoint: { transactionId: build.txId, index: 0 }, state: build.successorState };
    position = { outpoint: { transactionId: build.txId, index: 1 }, value: BigInt(build.accounting.kas.tokenSelfCarryKas), state: { ...position.state, amount: build.accounting.token.positionAfter }, program: selfAfter };
    agents = [{ ...agents[0], tokenPeriodSpent: (BigInt(agents[0].tokenPeriodSpent) + BigInt(HONEST_SPEND)).toString() }];
    if (buildTokenAgentTreeV5(agents).root !== vault.state.agentRoot) throw new Error("the local agent registry does not reproduce the successor agentRoot");
    advanceFuel(build, build.txId);
  }

  /* =============================================================== 6. AUTHORITY EXPANSION */
  const expandedAgents = [{ ...agents[0], tokenMaxPerSpend: "500" }];
  const expandedRoot = buildTokenAgentTreeV5(expandedAgents).root;
  await runVaultOwnerOp("06-authority-expansion-set-agent-root", "ownerSetAgentRoot", { newAgentRoot: expandedRoot }, [0, 1]);
  agents = expandedAgents;

  /* =============================================================== 7. AUTHORITY REDUCTION (root FREEZE, K=1) */
  await runVaultOwnerOp("07-authority-reduction-emergency-pause", "ownerEmergencyPause", {}, [0]);

  /* =============================================================== 8. GOVERNED UNFREEZE */
  await runRootOp("08-governed-unfreeze", "unfreeze", { signerIdx: [0, 1] });

  /* =============================================================== 9. UNPAUSE (selector 3) */
  await runVaultOwnerOp("09-governed-unpause", "ownerUnpause", {}, [0, 1]);

  /* =============================================================== 10. MEMBER ROTATION */
  await runRootOp("10-member-rotation", "rotate", { newOwnerSet: SET_B, signerIdx: [0, 1], newKeys: [O[0], O[1], N1] });

  /* =============================================================== 11. THRESHOLD CHANGE */
  await runRootOp("11-threshold-change", "rotate", { newOwnerSet: SET_C, signerIdx: [0, 1], newKeys: [O[0], O[1], N1] });

  /* =============================================================== 12. EMERGENCY FREEZE (K=1) */
  await runRootOp("12-emergency-freeze", "freeze", { signerIdx: [2] });

  /* =============================================================== 13. GOVERNED UNFREEZE (M=3) */
  await runRootOp("13-governed-unfreeze-3of3", "unfreeze", { signerIdx: [0, 1, 2] });

  /* =============================================================== 14. AUTHORIZED TESTNET NEGATIVE VALIDATION */
  {
    /* Every transaction below is built here, byte by byte, from the production
     * pv_call_encoder — NOT by the PolicyVault SDK builders/finalizers, which
     * refuse to produce any of them. Each is correctly signed by the
     * designated owners / delegate. Consensus must reject every one. */
    const honest = buildV7RootTransaction({ config, templateInput: rootTemplate, stateInput: root.state, action: "authorize", chain: rootChainOf(), changeXOnly: XO(fuelKey) });
    const artifact = JSON.parse(fs.readFileSync(path.join(honest.encoderBuildDir, "artifact.json")));
    const fuelSig = signInputOf(honest.frozen, 1, PK(fuelKey));
    const slotSig = (key) => signInputOf(honest.frozen, 0, key).slice(2);
    function assembleIndependently(build, slotHexes, buildArtifact, fuelSignature) {
      const blobHex = slotHexes.join("");
      if (blobHex.length !== 780 * 2) throw new Error("internal: the independently assembled owner blob is not 780 bytes");
      const callHex = runEncoderV4({
        sourcePath: path.join(build.encoderBuildDir, "PolicyVault.state.sil"),
        constructorArgsPath: path.join(build.encoderBuildDir, "constructor-args.json"),
        call: { function: "rootAction", successor: rootSuccessorCallJsonV7(build.successorState), action: build.rootAction, ownerSigs: blobHex },
        contractVersion: build.contractVersion
      });
      const json = JSON.parse(build.frozenCanonicalJson);
      json.inputs[0].signatureScript = covenantSigscript(callHex, Buffer.from(buildArtifact.script));
      json.inputs[1].signatureScript = fuelSignature;
      return json;
    }
    const pad = (entries) => {
      const out = new Array(OWNER_SLOTS_V7).fill(PLACEHOLDER_SLOT_HEX_V7);
      for (const [i, hex] of entries) out[i] = hex;
      return out;
    };

    /* 14a. INVALID QUORUM — M-1 correct signatures (M = 3 after the threshold change) */
    await expectRejected(
      "14a-invalid-quorum-M-minus-1",
      assembleIndependently(honest, pad([[0, slotSig(liveOwnerKeys[0])], [1, slotSig(liveOwnerKeys[1])]]), artifact, fuelSig),
      `a root AUTHORIZE carrying only ${Number(honest.requiredApprovals) - 1} of the ${honest.requiredApprovals} required owner signatures (the abstaining slots carry the canonical placeholder); every present signature is a real SIGHASH_ALL Schnorr signature by a real member`,
      { txId: honest.txId, rootOutpoint: `${root.outpoint.transactionId}:${root.outpoint.index}`, requiredApprovals: honest.requiredApprovals, suppliedApprovals: "2" }
    );

    /* 14b. WRONG MEMBER — an outsider key occupying an owner slot */
    await expectRejected(
      "14b-wrong-member-outsider-in-slot",
      assembleIndependently(honest, pad([[0, slotSig(liveOwnerKeys[0])], [1, slotSig(liveOwnerKeys[1])], [2, slotSig(outsiderKey)]]), artifact, fuelSig),
      "a root AUTHORIZE whose third slot carries a real Schnorr signature produced by a key that is NOT in the installed owner set; the slot is verified against exactly one key, so the count stays below the threshold",
      { txId: honest.txId, rootOutpoint: `${root.outpoint.transactionId}:${root.outpoint.index}`, requiredApprovals: honest.requiredApprovals, outsiderPk: XOK(outsiderKey) }
    );

    /* 14c. DUPLICATE SLOT — one member's signature copied into a second slot */
    {
      const s1 = slotSig(liveOwnerKeys[0]);
      await expectRejected(
        "14c-duplicate-signature-across-slots",
        assembleIndependently(honest, pad([[0, s1], [1, s1], [2, s1]]), artifact, fuelSig),
        "one member's signature copied into three slots: each slot verifies against exactly one distinct owner key, so a duplicated signature can never be counted twice",
        { txId: honest.txId, requiredApprovals: honest.requiredApprovals }
      );
    }

    /* 14d. STALE QUORUM — a correctly signed, full-quorum AUTHORIZE against the PREVIOUS root outpoint */
    {
      const stale = rootHistory[rootHistory.length - 2];
      const staleStateNonce = stale.rootNonce;
      const staleState = normalizeRootStateV7({ ...root.state, rootNonce: staleStateNonce, frozen: "1" });
      /* rebuild the exact predecessor state that outpoint carried: nonce n, frozen 1 (step 12's successor) */
      const staleBuild = buildV7RootTransaction({
        config,
        templateInput: rootTemplate,
        stateInput: staleState,
        action: "unfreeze",
        chain: { predecessorOutpoint: stale.outpoint, covenantId: rootId, predecessorValue: ROOT_KAS.toString(), fuel: fuelUtxo() },
        changeXOnly: XO(fuelKey)
      });
      const staleFin = finalizeV7RootTransaction({ build: staleBuild, approvals: approvalsFor(staleBuild.frozen, 0, [0, 1, 2]), fuelSignatureScriptHex: signInputOf(staleBuild.frozen, 1, PK(fuelKey)) });
      await expectRejected(
        "14d-stale-quorum-spent-root-outpoint",
        staleFin.finalTransaction,
        `a DISTINCT, correctly signed FULL-QUORUM root transition referencing the PREVIOUS root outpoint ${stale.outpoint.transactionId}:${stale.outpoint.index} (root nonce ${staleStateNonce}), which was already consumed by the accepted successor — the root outpoint is the organization's freshness kill switch`,
        { txId: staleBuild.txId, staleRootOutpoint: `${stale.outpoint.transactionId}:${stale.outpoint.index}`, staleRootNonce: staleStateNonce, liveRootOutpoint: `${root.outpoint.transactionId}:${root.outpoint.index}`, liveRootNonce: root.state.rootNonce }
      );
    }

    /* 14e. SUCCESSOR SUBSTITUTION — a vault owner operation whose root successor is a ROTATION */
    {
      const opBuild = buildV7Transaction({
        config,
        templateInput: vaultTemplate,
        stateInput: vault.state,
        action: "ownerPause",
        params: {},
        chain: { predecessorOutpoint: vault.outpoint, covenantId: vaultId, predecessorValue: vault.state.feeReserve, fuel: fuelUtxo(), root: rootSideOf() },
        changeXOnly: XO(fuelKey),
        descriptor
      });
      const opFin = finalizeV7Transaction({ build: opBuild, approvals: approvalsFor(opBuild.frozen, 1, [0, 1, 2]), fuelSignatureScriptHex: signInputOf(opBuild.frozen, 2, PK(fuelKey)) });
      const rotatedSuccessor = compileExactStateV7Root({
        config,
        template: rootTemplate,
        state: normalizeRootStateV7({ ...root.state, ...SET_D, rootNonce: (BigInt(root.state.rootNonce) + 1n).toString() })
      });
      const tampered = JSON.parse(JSON.stringify(opFin.finalTransaction));
      tampered.outputs[1].scriptPublicKey.scriptHex = p2shOfBytes(rotatedSuccessor.scriptBytes);
      await expectRejected(
        "14e-root-successor-substituted-with-a-rotation",
        tampered,
        "a correctly signed vault owner operation whose ROOT continuation output was replaced with a ROTATION successor (a different owner set) — the rooted vault pins the root's exact successor bytes, so a governance change can never ride inside a vault operation",
        { txId: opBuild.txId, expectedRootSuccessorDigest: opBuild.rootAuthority.newStateDigest, substitutedOwnerSet: "the owner-recovery set" }
      );
    }

    /* 14f. REPLAY of accepted bytes */
    if (lastAccepted) {
      await expectRejected(
        "14f-replay-accepted-bytes",
        lastAccepted.finalTransaction,
        `the EXACT bytes of the already-accepted transaction from step ${lastAccepted.label} resubmitted — every input it names is consumed, so consensus refuses the replay`,
        { txId: lastAccepted.txId, originalStep: lastAccepted.label }
      );
    }

    /* 14g. DELEGATE OVER-CAP SPEND, re-encoded through the production encoder */
    {
      const cap = BigInt(agents[0].tokenMaxPerSpend);
      const over = cap + 1n; /* the smallest amount the live on-chain policy forbids */
      if (over > BigInt(position.state.amount)) throw new Error("internal: the over-cap negative must fit inside the live token position");
      /* an honest spend at the cap gives us the exact byte SHAPE; every byte
       * that encodes the amount is then rewritten here (outputs, call
       * arguments, successor agent root) and re-signed by the delegate, so the
       * transaction is internally consistent and its ONLY policy defect is
       * that the amount exceeds the agent's tokenMaxPerSpend. */
      const shape = buildV7Transaction({
        config,
        templateInput: vaultTemplate,
        stateInput: vault.state,
        action: "tokenAgentSpend",
        params: { spendAmount: cap.toString(), agentPk: XO(agentKey), agents, recipient: XO(recipientKey), recipients: [...rTree.recipients], recipientCarryKasSompi: RECIPIENT_CARRY.toString(), reserveConsumedSompi: RESERVE_CONSUMED },
        chain: { predecessorOutpoint: vault.outpoint, covenantId: vaultId, predecessorValue: vault.state.feeReserve, fuel: fuelUtxo(), tokenPosition: { outpoint: position.outpoint, value: position.value.toString(), scriptPublicKeyHex: position.program.p2shSpkHex, covenantId: familyId, state: position.state } },
        changeXOnly: XO(fuelKey),
        descriptor
      });
      const positionBefore = BigInt(position.state.amount);
      const selfOver = { ownerIdentifier: vaultId, identifierType: 2, amount: (positionBefore - over).toString(), isMinter: false };
      const recipOver = { ownerIdentifier: XO(recipientKey), identifierType: 0, amount: over.toString(), isMinter: false };
      const selfOverProgram = compileKcc20Program({ config, state: selfOver, familyBound: FAMILY_BOUND });
      const recipOverProgram = compileKcc20Program({ config, state: recipOver, familyBound: FAMILY_BOUND });
      const agentsOver = [{ ...agents[0], tokenPeriodSpent: (BigInt(agents[0].tokenPeriodSpent) + over).toString() }];
      const successorOver = { ...shape.successorState, agentRoot: buildTokenAgentTreeV5(agentsOver).root };
      const nextOver = compileExactStateV7({ config, template: vaultTemplate, state: successorOver });
      const j = JSON.parse(shape.frozenCanonicalJson);
      j.outputs[0].scriptPublicKey.scriptHex = p2shOfBytes(nextOver.scriptBytes);
      j.outputs[1].scriptPublicKey.scriptHex = selfOverProgram.p2shSpkHex;
      j.outputs[2].scriptPublicKey.scriptHex = recipOverProgram.p2shSpkHex;
      const frozenOver = normalizeFrozenTxV3(j);
      const agentSig = signInputOf(frozenOver, 0, PK(agentKey)).slice(2);
      const callOver = {
        function: "tokenAgentSpend",
        signature: agentSig,
        ...shape.callExtra,
        selfNew: { ownerIdentifier: selfOver.ownerIdentifier, identifierType: selfOver.identifierType, amount: selfOver.amount, isMinter: selfOver.isMinter },
        recipientNew: { ownerIdentifier: recipOver.ownerIdentifier, identifierType: recipOver.identifierType, amount: recipOver.amount, isMinter: recipOver.isMinter },
        successor: successorCallJsonV7(successorOver)
      };
      const callHexOver = runEncoderV4({
        sourcePath: path.join(shape.encoderBuildDir, "PolicyVault.state.sil"),
        constructorArgsPath: path.join(shape.encoderBuildDir, "constructor-args.json"),
        call: callOver,
        contractVersion: shape.contractVersion
      });
      const vaultArtifact = JSON.parse(fs.readFileSync(path.join(shape.encoderBuildDir, "artifact.json")));
      const tokenCallOver = encodeTokenTransfer({ program: position.program, newStates: [selfOver, recipOver], witnessesHex: "00" });
      const outTx = JSON.parse(canonicalFrozenTxJson(frozenOver));
      outTx.inputs[0].signatureScript = covenantSigscript(callHexOver, Buffer.from(vaultArtifact.script));
      outTx.inputs[1].signatureScript = covenantSigscript(tokenCallOver, Buffer.from(position.program.scriptHex, "hex"));
      outTx.inputs[2].signatureScript = signInputOf(frozenOver, 2, PK(fuelKey));
      await expectRejected(
        "14g-delegate-over-cap-spend",
        outTx,
        `a fully self-consistent delegated spend of ${over} tokens — outputs, covenant-call arguments, successor agent root and the delegate's SIGHASH_ALL signature all agree — whose only policy defect is that ${over} exceeds the agent's on-chain tokenMaxPerSpend of ${cap}`,
        { txId: describeFrozenTx(frozenOver).txId, spendAmount: over.toString(), tokenMaxPerSpend: cap.toString(), signer: "the designated delegate key" }
      );
    }
  }

  /* ---- heartbeat: refresh the root outpoint so the pre-age rejection in step
   * 15 is provable (§2.4 — an AUTHORIZE is the organization's heartbeat) ---- */
  await runRootOp("14h-root-authorize-heartbeat", "authorize", { signerIdx: [0, 1, 2] });

  /* =============================================================== 15. OWNER-RECOVER after the idle delay */
  await runRootOp("15-owner-recover-after-idle-delay", "ownerRecover", { newOwnerSet: SET_D, signerIdx: [0], ageProof: true, newKeys: [...REC] });

  /* =============================================================== 16. UNFREEZE by the installed set */
  await runRootOp("16-unfreeze-by-recovery-installed-set", "unfreeze", { signerIdx: [0, 1] });

  /* =============================================================== 17. SUCCESSION after its idle delay */
  await runRootOp("17-succession-after-idle-delay", "succession", { newOwnerSet: SET_E, useSuccessor: true, ageProof: true, newKeys: [...SUC] });

  /* =============================================================== 18. UNFREEZE by the succession-installed set */
  await runRootOp("18-unfreeze-by-succession-installed-set", "unfreeze", { signerIdx: [0, 1] });

  /* =============================================================== 19. VAULT ownerRecover (TERMINAL) */
  {
    const label = "19-vault-owner-recover-terminal";
    const build = buildV7Transaction({
      config,
      templateInput: vaultTemplate,
      stateInput: vault.state,
      action: "ownerRecover",
      params: {},
      chain: {
        predecessorOutpoint: vault.outpoint,
        covenantId: vaultId,
        predecessorValue: vault.state.feeReserve,
        fuel: fuelUtxo(),
        root: rootSideOf(),
        tokenPosition: { outpoint: position.outpoint, value: position.value.toString(), scriptPublicKeyHex: position.program.p2shSpkHex, covenantId: familyId, state: position.state }
      },
      changeXOnly: XO(fuelKey),
      descriptor
    });
    const manifest = buildOrgRootIntentManifest({ build, vaultOperations: [{ build, descriptor }], satisfiedApprovals: 2 });
    const verdict = verifyOrgRootIntentManifest({ manifest, descriptors: { [vaultId]: descriptor } });
    if (verdict.verdict !== "VERIFIED") throw new Error(`${label}: the org-root manifest did not verify locally: ${JSON.stringify(verdict.failures)}`);
    record(`${label}:AUTHORIZED`, {
      status: "AUTHORIZED",
      txId: build.txId,
      action: build.action,
      terminal: true,
      recoveryPk: vaultTemplate.recoveryPk,
      rootAuthority: { rootActionName: build.rootAuthority.rootActionName, requiredApprovals: build.rootAuthority.requiredApprovals, rootOutpoint: `${build.rootAuthority.outpoint.transactionId}:${build.rootAuthority.outpoint.index}`, newStateDigest: build.rootAuthority.newStateDigest },
      accounting: build.accounting,
      manifestHash: manifest.manifestHash,
      manifestVerdict: verdict.verdict,
      manifestChecks: verdict.checks.length,
      feeSompi: build.requiredFeeSompi
    });
    const fin = finalizeV7Transaction({ build, approvals: approvalsFor(build.frozen, 1, [0, 1]), fuelSignatureScriptHex: signInputOf(build.frozen, 3, PK(fuelKey)) });
    record(`${label}:SIGNED`, { status: "SIGNED", txId: build.txId, sighash: "ALL", signedSlots: fin.signedSlots, satisfiedApprovals: fin.satisfiedApprovals });
    const recoveredToken = compileKcc20Program({ config, state: { ownerIdentifier: vaultTemplate.recoveryPk, identifierType: 0, amount: position.state.amount, isMinter: false }, familyBound: FAMILY_BOUND });
    await submitAndProve(label, fin.finalTransaction, {
      txId: build.txId,
      expect: [
        { label: "fee reserve to the pinned cold recoveryPk", address: p2pkAddress(vaultTemplate.recoveryPk), index: 0, value: build.accounting.kas.terminalPayout },
        { label: "root successor", address: rootAddrOf(build.rootAuthority.newState), index: 1, value: ROOT_KAS.toString(), covenantId: rootId },
        { label: "token position to the pinned cold recoveryPk", address: p2shAddress(recoveredToken.p2shSpkHex), index: 2, value: position.value.toString(), covenantId: familyId },
        { label: "fuel change", address: FUEL_ADDRESS, index: 3, value: build.frozen.outputs[3].value.toString() }
      ],
      consumed: [
        { address: p2shAddress(build.frozen.inputs[0].utxo.scriptPublicKey.scriptHex), ...vault.outpoint },
        { address: rootAddrOf(root.state), ...root.outpoint },
        { address: p2shAddress(position.program.p2shSpkHex), ...position.outpoint }
      ]
    });
    record(`${label}:VERIFIED_OUTCOME`, {
      status: "VERIFIED_OUTCOME",
      txId: build.txId,
      terminal: true,
      feeReserveRecovered: build.accounting.kas.terminalPayout,
      tokensRecovered: build.accounting.token.recoveredToRecoveryPk,
      destination: vaultTemplate.recoveryPk,
      destinationAddress: p2pkAddress(vaultTemplate.recoveryPk),
      note: "recoveryPk is a GENESIS-PINNED template constant, not a session choice",
      rootStillLive: `${build.txId}:1`
    });
    root = { outpoint: { transactionId: build.txId, index: 1 }, state: build.rootAuthority.newState, ownerSet: SET_E, blockDaaScore: null };
    advanceFuel(build, build.txId);
  }

  /* =============================================================== close out */
  evidence.covenant.after = verifyCovenantBytes("post-flight");
  evidence.finishedAt = new Date().toISOString();
  if (!DRY) evidence.network.virtualDaaScoreAtEnd = (await daa()).toString();
  evidence.summary = {
    lifecycleStepsAccepted: evidence.steps.filter((s) => s.status === "CHAIN_VERIFIED").length,
    negativeValidationsRejected: evidence.negatives.filter((n) => n.rejected === true).length,
    ageProofs: evidence.ageProofs.length,
    rootCovenantId: rootId,
    vaultCovenantId: vaultId,
    tokenFamilyId: familyId,
    finalRootOutpoint: `${root.outpoint.transactionId}:${root.outpoint.index}`,
    finalRootState: root.state,
    byteFrozen: false,
    mainnet: false,
    externallyReviewed: false,
    claimLabel: "DESIGNED · PROBED · IMPLEMENTED (candidate bytes) · VM-VERIFIED · SDK/PRODUCTION-BYTE-VERIFIED · TESTNET-VERIFIED (candidate)"
  };
  if (!DRY) {
    fs.writeFileSync(EVIDENCE_PATH, JSON.stringify(evidence, null, 2) + "\n");
    console.log(`LIVE v0.7 ORGANIZATIONAL-ROOT LIFECYCLE COMPLETE — evidence ${EVIDENCE_PATH}`);
  } else {
    console.log("DRY RUN COMPLETE (no chain interaction, nothing broadcast, no evidence written)");
  }
  if (rpc) await rpc.disconnect();
}

main().catch((e) => {
  console.error("FAILED:", e.message);
  process.exit(1);
});
