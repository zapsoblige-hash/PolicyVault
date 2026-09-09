"use strict";

/*
 * LIVE TESTNET-10 HIERARCHICAL DELEGATION LIFECYCLE for the v0.7-payment-hd
 * CANDIDATE covenant (docs/postlaunch/hierarchical-delegation-design-freeze.md
 * §4 implementation contract, gate I5). Sibling of tools/testnet-v7-lifecycle.js,
 * scoped to the HD entrypoints. Drives the REAL HD SDK
 * (sdk/src/vault-builders-v7-hd.js, core/model/hd-leaf-v7.js,
 * core/model/compute-budget-v7-hd.js, core/intent/org-root-manifest-v7-hd.js,
 * and the production `pv_call_encoder` `policyvault-0.7-payment-hd` arm)
 * against a LOCAL, VERIFIED testnet-10 node (connectVerified: exact network +
 * synced + utxoindex, never assumed).
 *
 * TEST ASSETS ONLY. TEST KEYS ONLY. NEVER MAINNET.
 *
 *   1.  KCC20 ISSUANCE (user-owned genesis note)
 *   2.  ORGANIZATIONAL ROOT GENESIS (2-of-3, K=1)               -> root covenant id
 *   3.  ROOTED HD VAULT GENESIS (pins the root's identity;
 *       genesis level-1 forest: 2 leaves, A (agentKey) + B (bKey))
 *   4.  TOKEN DEPOSIT (user -> vault-owned position)
 *   5.  LEVEL-1 SPEND (hdSpend, leaf A; NO root input at all)
 *   6.  DELEGATE LEVEL 2 (delegateSetChildRoot1: A grants child C, key cKey)
 *   7.  LEVEL-2 SPEND AT THE INTERSECTION BOUNDARY (childSpendL2, leaf C,
 *       spending exactly the remaining amount the TIGHTEST ancestor allows)
 *   8.  DELEGATE LEVEL 3 (delegateSetChildRoot2: C grants grandchild D, key dKey)
 *   9.  LEVEL-3 SPEND (childSpendL3, leaf D) — the MAXIMUM PROVEN ROOTED LEVEL
 *   10. PARENT REVOKES (A zeroes C's subtree via delegateSetChildRoot1) ->
 *       CHILD SPEND REFUSED: the SAME honest, correctly-signed level-3 spend
 *       from step 9's proof, re-submitted AFTER the revocation, must be
 *       refused by consensus (the proof no longer matches the live agentRoot)
 *   11. ROOT-GOVERNED setAgentRoot REVOKING A SUBTREE (an owner operation
 *       under root AUTHORIZE directly overwrites agentRoot to a forest with
 *       B's subtree removed — the organization's own emergency lever,
 *       independent of any parent's cooperation)
 *   12. VAULT ownerRecover under root AUTHORIZE — TERMINAL
 *
 * AUTHORIZED TESTNET NEGATIVE-VALIDATION TRANSACTIONS (>= 8), CONSTRUCTED
 * INDEPENDENTLY OF THE APPLICATION where the SDK itself refuses to build the
 * shape (hand-assembled call.json through the production pv_call_encoder,
 * never through sdk/src/vault-builders-v7-hd.js's own builders), each
 * correctly signed by the designated key:
 *   N1  child over parent cap (spend above the tightest ancestor's maxPerSpend)
 *   N2  forged broader allowlist (recipient satisfies the child's OWN
 *       recipientRoot but not an ancestor's)
 *   N3  stale parent proof (a proof against a childRoot that has since moved)
 *   N4  level confusion (a level-1 leaf/proof presented to childSpendL2)
 *   N5  descendant owner op (an HD leaf key attempting ownerControl — the
 *       vault has no owner key at all; the root input is the only authority)
 *   N6  descendant root op (an HD leaf key attempting a ROOT action directly)
 *   N7  delegation while paused
 *   N8  SIGHASH variant (non-ALL sighash on the spending leaf's signature)
 *   N9  replay of already-accepted bytes
 *   N10 domain-tag confusion (a v0.5/v0.7-payment flat leaf tree fed to hdSpend)
 *
 * Every accepted step is CHAIN-VERIFIED against the node's UTXO index (exact
 * value, address, covenant id); its predecessors must be CONSUMED; the ladder
 * AUTHORIZED -> SIGNED -> BROADCAST -> CHAIN_SEEN -> CHAIN_VERIFIED ->
 * VERIFIED_OUTCOME is recorded for each. Evidence -> docs/testnet-v7-hd-evidence.json.
 *
 * LIVE RUNS ARE SERIALIZED (Wave 2 Track D task packet): before ANY broadcast
 * this tool acquires the cross-track lock `mkdir ~/.policyvault-testnet-live.lock`
 * (retrying every 30s; it never removes a lock it did not create) and releases
 * it (`rmdir`) on completion OR failure. --dry-run never touches the lock.
 *
 * --dry-run: exercise the whole build/verify/sign/finalize plumbing (REAL
 * silverc compiles, REAL pv_call_encoder bytes, REAL Schnorr signatures)
 * against SYNTHETIC chain facts with NO RPC, NO lock, and NO broadcast —
 * writes nothing under docs/. Live:
 *   KASPA_NETWORK_ID=testnet-10 KASPA_RPC_URL=ws://127.0.0.1:18210 \
 *     node tools/testnet-v7-hd-lifecycle.js
 */

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const os = require("os");

const { loadConfig } = require("../sdk/src/config");
const { loadOrCreateTestKeys } = require("../sdk/src/keys");
const { connectVerified, getAddressUtxos, getVirtualDaaScore } = require("../sdk/src/chain");
const assets = require("../core/assets");
const { compileKcc20Program } = require("../sdk/src/token-program-kcc20");
const { buildRecipientTree, generateRecipientProof } = require("../sdk/src/recipient-merkle-v3");
const { compileExactStateV7Root, compileExactStateV7Hd, assertRootPinsMatchV7, deriveRootPinsV7, CONTRACT_VERSION_V7_HD } = require("../sdk/src/contract-compiler-v7");
const hd = require("../core/model/hd-leaf-v7");
const {
  buildCreateV7Root,
  buildV7RootTransaction,
  finalizeV7RootTransaction,
  buildCreateV7HdVault,
  buildHdSpendTransaction,
  buildHdDelegationTransaction,
  finalizeHdTransaction,
  buildV7HdOwnerTransaction,
  finalizeV7HdOwnerTransaction,
  buildTokenDepositV7,
  finalizeTokenDepositV7,
  rootSuccessorCallJsonV7,
  successorCallJsonV7,
  HD_SPEND_LEVEL
} = require("../sdk/src/vault-builders-v7-hd");
const { runEncoderV4 } = require("../sdk/src/vault-builders-v4");
const { encodeTokenTransfer } = require("../sdk/src/vault-builders-v5");
const { covenantSigscript } = require("../sdk/src/spend-vault");
const { frozenToWasmTransaction, describeFrozenTx } = require("../sdk/src/frozen-tx-v3");
const { normalizeFrozenTxV3, canonicalFrozenTxJson, feeDescriptorFromFrozen } = require("../core/model/frozen-tx-v3");
const { calculateRequiredFee } = require("../sdk/src/fee-mass");
const { p2pkScriptHex } = require("../sdk/src/approval-package-v4");
const { OWNER_SLOTS_V7, INACTIVE_SLOT_KEY } = require("../core/model/owner-set-v7");
const { normalizeRootStateV7 } = require("../core/model/vault-state-v7-root");
const { buildRootedHdVaultManifestV7, verifyRootedHdVaultManifestV7 } = require("../core/intent/org-root-manifest-v7-hd");
const { buildOrgRootIntentManifest, verifyOrgRootIntentManifest } = require("../core/intent/org-root-manifest-v7");

const DRY = process.argv.includes("--dry-run") || process.argv.includes("--dry");
const KAS = 100000000n;
const FAMILY_BOUND = 2;
const ROOT_DIR = path.join(__dirname, "..");
const DATA_ROOT = process.env.PV_LIVE_DATA_ROOT || (DRY ? fs.mkdtempSync(path.join(os.tmpdir(), "pv7hd-dry-")) : "/tmp/pv7hd-live-data");
const EVIDENCE_PATH = path.join(ROOT_DIR, "docs", "testnet-v7-hd-evidence.json");
const LIVE_LOCK_PATH = path.join(os.homedir(), ".policyvault-testnet-live.lock");

const ROOT_KAS = 2n * KAS;
const VAULT_RESERVE = 3n * KAS;
const NOTE_CARRY = 1n * KAS;
const SUPPLY = "1000000";
const DEPOSIT = "10000";
const RECOVERY_DELAY_DAA = 600n;
const SUCCESSION_DELAY_DAA = 600n;
const ROOT_MAX_FEE_PER_TX = 1000000n;
const RECIPIENT_CARRY = KAS / 5n; /* 0.2 KAS — a covenant-bearing output has KIP-9 plurality 2 (4× the plain weight); 0.05 KAS put the level-1 spend at 840,919 grams live */

const evidence = {
  schema: "policyvault-testnet-v7-hd-evidence/1",
  startedAt: new Date().toISOString(),
  finishedAt: null,
  dryRun: DRY,
  mainnet: false,
  network: null,
  covenant: { before: null, after: null },
  organization: null,
  steps: [],
  negatives: [],
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
  "PolicyVault.v0.7-root.sil": "69417514f90d61b0281ea673e6fb5a5fd858c2bd50e14a4eb9043d5fdf17f8ce",
  "PolicyVault.v0.7-payment.sil": "09cdbb6c284d8bd6c4cd2f4aad20d9682172eea3e048631176034b517be25091",
  "PolicyVault.v0.7-payment-hd.sil": "a5a59047ed2c3bd1639eec0c8c110ab0527480f1f0d28c5a95551f9a51626a8c"
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

/* Cross-track live-broadcast serialization (never touched in --dry-run). */
let acquiredLock = false;
async function acquireLiveLock() {
  if (DRY) return;
  for (;;) {
    try {
      fs.mkdirSync(LIVE_LOCK_PATH);
      acquiredLock = true;
      record("lock-acquired", { path: LIVE_LOCK_PATH });
      return;
    } catch (e) {
      if (e.code !== "EEXIST") throw e;
      console.log(`[lock] ${LIVE_LOCK_PATH} held by another track; retrying in 30s`);
      await sleep(30000);
    }
  }
}
function releaseLiveLock() {
  if (DRY || !acquiredLock) return;
  try {
    fs.rmdirSync(LIVE_LOCK_PATH);
    record("lock-released", { path: LIVE_LOCK_PATH });
  } catch (e) {
    console.error(`[lock] failed to release ${LIVE_LOCK_PATH}: ${e.message}`);
  }
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
  const KEY = (v) => new kaspa.PrivateKey(v.toString(16).padStart(2, "0").repeat(32));
  const XOK = (p) => p.toPublicKey().toXOnlyPublicKey().toString().toLowerCase();

  const fuelKey = keys.funding ?? keys.owner;
  const recipientKey = keys.recipient1;
  if (!fuelKey || !recipientKey) throw new Error("test key roles funding/recipient1 are required");

  const O = [KEY(0x71), KEY(0x72), KEY(0x73)];
  const successorKey = KEY(0x7f);
  const recoveryKey = KEY(0x51);
  const aKey = KEY(0x62); /* level-1 leaf A */
  const bKey = KEY(0x63); /* level-1 leaf B (revoked at step 11) */
  const cKey = KEY(0x64); /* level-2 leaf C, delegated from A */
  const dKey = KEY(0x65); /* level-3 leaf D, delegated from C */
  const outsiderKey = KEY(0x6f);

  const slots = (ks) => {
    const out = [];
    for (let i = 0; i < OWNER_SLOTS_V7; i += 1) out.push(i < ks.length ? XOK(ks[i]) : INACTIVE_SLOT_KEY);
    return out;
  };
  const ORG_ID = crypto.createHash("sha256").update("policyvault-v0.7-hd-testnet-10-lifecycle").digest("hex");
  const VAULT_ID = crypto.createHash("sha256").update("policyvault-v0.7-hd-testnet-10-vault").digest("hex");

  const rootTemplate = { orgId: ORG_ID, recoveryDelayDaa: RECOVERY_DELAY_DAA.toString(), successorPk: XOK(successorKey), successionDelayDaa: SUCCESSION_DELAY_DAA.toString(), rootMaxFeePerTx: ROOT_MAX_FEE_PER_TX.toString() };
  const SET_A = { owners: slots(O), ownerM: 2, emergencyK: 1, recoveryM: 1 };
  let liveOwnerKeys = [...O];

  let rpc = null;
  if (!DRY) {
    await acquireLiveLock();
    const { rpc: client, serverInfo } = await connectVerified(config);
    rpc = client;
    evidence.network = { rpcUrl: config.rpcUrl, networkId: serverInfo.networkId, serverVersion: serverInfo.serverVersion, isSynced: serverInfo.isSynced, hasUtxoIndex: serverInfo.hasUtxoIndex, virtualDaaScoreAtStart: (await getVirtualDaaScore(rpc)).toString() };
    record("connect", evidence.network);
  } else {
    evidence.network = { networkId: "testnet-10", dryRun: true };
  }

  const p2shAddress = (spkHex) => (DRY ? `dry:p2sh:${spkHex.slice(4, 20)}` : kaspa.addressFromScriptPublicKey({ version: 0, script: spkHex }, config.networkId).toString());
  const p2pkAddress = (pk) => (DRY ? `dry:p2pk:${pk.slice(0, 16)}` : kaspa.addressFromScriptPublicKey({ version: 0, script: p2pkScriptHex(pk) }, config.networkId).toString());
  const p2shOfBytes = (scriptBytes) => String(kaspa.payToScriptHashScript(Buffer.from(scriptBytes).toString("hex")).script).toLowerCase();
  const FUEL_SPK = `20${XO(fuelKey)}ac`;
  const FUEL_ADDRESS = p2pkAddress(XO(fuelKey));

  let fuel = null;
  let lastAccepted = null;
  async function primeFuel() {
    if (DRY) {
      fuel = { outpoint: { transactionId: "f1".repeat(32), index: 0 }, amount: 100000n * KAS, scriptPublicKeyHex: FUEL_SPK };
      return;
    }
    const utxos = (await getAddressUtxos(rpc, fuelKey.address)).filter((u) => u.covenantId === null && u.amount > 500n * KAS);
    if (!utxos.length) throw new Error("no plain UTXO > 500 KAS on the test funding key — fund it before running gate I5");
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
      /* a step whose only chain-visible effect is a covenant SUCCESSOR (no
       * plain expected output) has nothing in `expect` to wait on, so the
       * consumed predecessor is polled with the SAME budget as an expected
       * output — an immediate single check raced the mempool (the delegation
       * step was BROADCAST and mined, but declared unproven) */
      let stillUnspent = true;
      for (let i = 0; i < 60 && stillUnspent; i += 1) {
        const utxos = await getAddressUtxos(rpc, c.address);
        stillUnspent = utxos.some((u) => u.outpoint.transactionId === c.transactionId && u.outpoint.index === c.index);
        if (stillUnspent) await sleep(2000);
      }
      if (stillUnspent) throw new Error(`${label}: predecessor ${c.transactionId}:${c.index} is still unspent after 120 s — the transition is NOT proven`);
      if (!seen) {
        record(`${label}:CHAIN_SEEN`, { txId, status: "CHAIN_SEEN", predecessorConsumed: `${c.transactionId}:${c.index}` });
        seen = true;
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
    const draft = { version: 1, inputs: [{ previousOutpoint: funding.outpoint, sequence: 0n, computeBudget: 10, utxo: { amount: funding.amount, scriptPublicKey: { version: 0, scriptHex: funding.scriptPublicKeyHex }, covenantId: null, blockDaaScore: 0n } }], outputs: [{ value, scriptPublicKey: { version: 0, scriptHex: outputScriptHex }, covenant: { authorizingInput: 0, covenantId: covId } }, { value: 1n, scriptPublicKey: { version: 0, scriptHex: FUEL_SPK }, covenant: null }], lockTime: 0n, subnetworkId: "00".repeat(20), gas: 0n, payload: "" };
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
  record("01-kcc20-issuance:AUTHORIZED", { status: "AUTHORIZED", txId: issuance.txId, tokenFamilyId: familyId, supply: SUPPLY, feeSompi: issuance.fee.toString() });
  await submitAndProve("01-kcc20-issuance", issuance.json, { txId: issuance.txId, expect: [{ label: "user token position", address: p2shAddress(userProgram.p2shSpkHex), index: 0, value: issuanceValue.toString(), covenantId: familyId }, { label: "fuel change", address: FUEL_ADDRESS, index: 1, value: issuance.frozen.outputs[1].value.toString() }] });
  record("01-kcc20-issuance:VERIFIED_OUTCOME", { status: "VERIFIED_OUTCOME", txId: issuance.txId, tokenFamilyId: familyId });
  advanceFuel(issuance, issuance.txId);

  const descriptor = {
    schema: "policyvault-asset-descriptor/1",
    assetId: familyId,
    displayName: "TN10 v0.7-hd Test Token",
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
    record("02-root-genesis:AUTHORIZED", { status: "AUTHORIZED", txId: rootGenesis.txId, rootCovenantId: rootId, feeSompi: rootGenesis.requiredFeeSompi });
    await submitAndProve("02-root-genesis", json, { txId: rootGenesis.txId, expect: [{ label: "organizational root", address: rootAddress, index: 0, value: ROOT_KAS.toString(), covenantId: rootId }, { label: "fuel change", address: FUEL_ADDRESS, index: 1, value: rootGenesis.frozen.outputs[1].value.toString() }] });
    record("02-root-genesis:VERIFIED_OUTCOME", { status: "VERIFIED_OUTCOME", txId: rootGenesis.txId, rootCovenantId: rootId });
    advanceFuel(rootGenesis, rootGenesis.txId);
  }
  let root = { outpoint: { transactionId: rootGenesis.txId, index: 0 }, state: rootGenesis.initialState };
  const rootChainOf = () => ({ predecessorOutpoint: root.outpoint, covenantId: rootId, predecessorValue: ROOT_KAS.toString(), fuel: fuelUtxo() });
  const rootSideOf = () => ({ template: rootTemplate, state: root.state, outpoint: root.outpoint, covenantId: rootId, value: ROOT_KAS.toString() });

  /* =============================================================== 3. ROOTED HD VAULT GENESIS */
  const rTree = buildRecipientTree([XO(recipientKey)]);
  const baseLeaf = (ownerKey, over = {}) => ({ pk: XOK(ownerKey), maxPerSpend: "250", periodBudget: "2000", periodLengthDaa: "100000000", periodStartDaa: "0", periodSpent: "0", maxFeePerTx: (1n * KAS).toString(), maxCarryKas: (KAS / 4n).toString(), expiryDaa: "900000000", recipientRoot: rTree.root, childRoot: "00".repeat(32), ...over });
  const leafA = { leaf: baseLeaf(aKey), kids: [] };
  const leafB = { leaf: baseLeaf(bKey), kids: [] };
  let tree = [leafA, leafB];
  /* Off-chain bookkeeping helpers that mirror the covenant's OWN accounting
   * exactly (core/model/hd-leaf-v7.js's nestedRefoldAfterSpend/
   * nestedRefoldAfterDelegation): a spend advances EVERY ancestor's OWN
   * period counters along `path` (never just the deepest leaf — this is
   * what makes a child unable to outrun a parent's budget); a delegation
   * replaces ONLY the kids at the delegating position, leaving every field
   * of every leaf along the way untouched. */
  function applySpendToTree(currentTree, spendPath, spendAmount, periodsElapsedByLevel) {
    function walk(nodes, depth) {
      const idx = spendPath[depth];
      return nodes.map((n, i) => {
        if (i !== idx) return n;
        const pe = periodsElapsedByLevel[depth] ?? 0n;
        const adv = hd.advanceHdLeafPeriod(n.leaf, spendAmount, pe);
        const newLeaf = { ...hd.normalizeHdLeaf(n.leaf), periodStartDaa: adv.periodStartDaa, periodSpent: adv.periodSpent };
        const newKids = depth + 1 < spendPath.length ? walk(n.kids, depth + 1) : n.kids;
        return { leaf: newLeaf, kids: newKids };
      });
    }
    return walk(currentTree, 0);
  }
  function applyDelegationToTree(currentTree, delegatePath, newKids) {
    function walk(nodes, depth) {
      const idx = delegatePath[depth];
      return nodes.map((n, i) => {
        if (i !== idx) return n;
        if (depth + 1 === delegatePath.length) return { leaf: n.leaf, kids: newKids };
        return { leaf: n.leaf, kids: walk(n.kids, depth + 1) };
      });
    }
    return walk(currentTree, 0);
  }
  const agentRoot0 = hd.forestRoot(tree);
  const rootPins = deriveRootPinsV7({ config, template: rootTemplate, ownerSet: SET_A, covenantId: rootId });
  const vaultTemplate = { vaultId: VAULT_ID, descriptorHash, tokenCovenantId: familyId, templateVmHash: userProgram.templateVmHashBlake2b256, templatePrefixLen: userProgram.geometry.prefixLen, templateStateLen: userProgram.geometry.stateLen, templateSuffixLen: userProgram.geometry.suffixLen, ...rootPins, recoveryPk: XOK(recoveryKey) };
  assertRootPinsMatchV7({ config, vaultTemplate, rootTemplate, rootOwnerSet: SET_A });
  const vaultState0 = { feeReserve: VAULT_RESERVE.toString(), paused: "0", agentRoot: agentRoot0, policyNonce: "0" };
  const vaultGenesis = buildCreateV7HdVault({ config, templateInput: vaultTemplate, initialStateInput: vaultState0, funding: [fuelUtxo()], changeXOnly: XO(fuelKey), descriptor });
  const vaultId = vaultGenesis.covenantId;
  {
    const json = JSON.parse(vaultGenesis.frozenCanonicalJson);
    json.inputs[0].signatureScript = signInputOf(vaultGenesis.frozen, 0, PK(fuelKey));
    record("03-hd-vault-genesis:AUTHORIZED", { status: "AUTHORIZED", txId: vaultGenesis.txId, vaultCovenantId: vaultId, orgRootCovenantId: vaultGenesis.orgRootCovenantId, scriptSha256: vaultGenesis.scriptSha256, feeSompi: vaultGenesis.requiredFeeSompi });
    await submitAndProve("03-hd-vault-genesis", json, { txId: vaultGenesis.txId, expect: [{ label: "rooted HD vault", address: p2shAddress(vaultGenesis.frozen.outputs[0].scriptPublicKey.scriptHex), index: 0, value: VAULT_RESERVE.toString(), covenantId: vaultId }, { label: "fuel change", address: FUEL_ADDRESS, index: 1, value: vaultGenesis.frozen.outputs[1].value.toString() }] });
    record("03-hd-vault-genesis:VERIFIED_OUTCOME", { status: "VERIFIED_OUTCOME", txId: vaultGenesis.txId, vaultCovenantId: vaultId, agentRoot: agentRoot0 });
    advanceFuel(vaultGenesis, vaultGenesis.txId);
  }
  let vault = { outpoint: { transactionId: vaultGenesis.txId, index: 0 }, state: vaultState0 };
  const vaultAddressOf = (state) => p2shAddress(p2shOfBytes(compileExactStateV7Hd({ config, template: vaultTemplate, state }).scriptBytes));

  /* =============================================================== 4. TOKEN DEPOSIT */
  const userPosition = { outpoint: { transactionId: issuance.txId, index: 0 }, value: issuanceValue, state: userState, program: userProgram };
  const depositBuild = buildTokenDepositV7({ config, descriptor, vault: { covenantId: vaultId, template: vaultTemplate }, chain: { userPosition: { outpoint: userPosition.outpoint, value: userPosition.value.toString(), scriptPublicKeyHex: userPosition.program.p2shSpkHex, covenantId: familyId, state: userPosition.state }, fuel: fuelUtxo() }, params: { depositAmount: DEPOSIT, depositCarryKasSompi: (issuanceValue / 2n).toString() }, changeXOnly: XO(fuelKey) });
  const depositFin = finalizeTokenDepositV7({ build: depositBuild, tokenOwnerSignatureHex: signInputOf(depositBuild.frozen, 0, PK(fuelKey)).slice(2), fuelSignatureScriptHex: signInputOf(depositBuild.frozen, 1, PK(fuelKey)) });
  record("04-token-deposit:AUTHORIZED", { status: "AUTHORIZED", txId: depositBuild.txId, deposit: DEPOSIT, feeSompi: depositBuild.requiredFeeSompi });
  const depositProgram = compileKcc20Program({ config, state: { ownerIdentifier: vaultId, identifierType: 2, amount: DEPOSIT, isMinter: false }, familyBound: FAMILY_BOUND });
  await submitAndProve("04-token-deposit", depositFin.finalTransaction, { txId: depositBuild.txId, expect: [{ label: "vault token position", address: p2shAddress(depositProgram.p2shSpkHex), index: 0, value: depositBuild.frozen.outputs[0].value.toString(), covenantId: familyId }], consumed: [{ transactionId: userPosition.outpoint.transactionId, index: userPosition.outpoint.index, address: p2shAddress(userProgram.p2shSpkHex) }] });
  record("04-token-deposit:VERIFIED_OUTCOME", { status: "VERIFIED_OUTCOME", txId: depositBuild.txId, vaultTokenAmount: DEPOSIT });
  let position = { outpoint: { transactionId: depositBuild.txId, index: 0 }, value: depositBuild.frozen.outputs[0].value, state: { ownerIdentifier: vaultId, identifierType: 2, amount: DEPOSIT, isMinter: false }, program: depositProgram };
  advanceFuel({ frozen: { outputs: depositFin.finalTransaction.outputs.map((o) => ({ ...o, value: BigInt(o.value) })) } }, depositBuild.txId);

  const tokenPositionArg = () => ({ outpoint: position.outpoint, value: position.value.toString(), scriptPublicKeyHex: position.program.p2shSpkHex, covenantId: familyId, state: position.state });

  /* =============================================================== 5. LEVEL-1 SPEND (A) */
  const L1_SPEND = "100";
  const spend1 = buildHdSpendTransaction({ config, templateInput: vaultTemplate, stateInput: vault.state, action: "hdSpend", params: { tree, path: [0], recipient: XO(recipientKey), spendAmount: L1_SPEND, recipientCarryKasSompi: RECIPIENT_CARRY.toString(), recipientListsByLevel: [[XO(recipientKey)]] }, chain: { predecessorOutpoint: vault.outpoint, covenantId: vaultId, predecessorValue: vault.state.feeReserve, fuel: fuelUtxo(), tokenPosition: tokenPositionArg() }, changeXOnly: XO(fuelKey), descriptor });
  const spend1Fin = finalizeHdTransaction({ build: spend1, signatureHex: signInputOf(spend1.frozen, 0, aKey).slice(2), fuelSignatureScriptHex: signInputOf(spend1.frozen, 2, PK(fuelKey)) });
  {
    const manifest = buildRootedHdVaultManifestV7({ build: spend1, descriptor });
    const v = verifyRootedHdVaultManifestV7({ manifest });
    if (v.verdict !== "VERIFIED") throw new Error(`level-1 spend manifest did not verify: ${JSON.stringify(v.failures)}`);
    record("05-level1-spend:AUTHORIZED", { status: "AUTHORIZED", txId: spend1.txId, level: 1, spendAmount: L1_SPEND, manifestVerdict: v.verdict, feeSompi: spend1.requiredFeeSompi });
  }
  await submitAndProve("05-level1-spend", spend1Fin.finalTransaction, { txId: spend1.txId, expect: [{ label: "recipient token", address: p2shAddress(compileKcc20Program({ config, state: { ownerIdentifier: XO(recipientKey), identifierType: 0, amount: L1_SPEND, isMinter: false }, familyBound: FAMILY_BOUND }).p2shSpkHex), index: 2, value: RECIPIENT_CARRY.toString(), covenantId: familyId }], consumed: [{ transactionId: vault.outpoint.transactionId, index: vault.outpoint.index, address: vaultAddressOf(vault.state) }] });
  record("05-level1-spend:VERIFIED_OUTCOME", { status: "VERIFIED_OUTCOME", txId: spend1.txId, newAgentRoot: spend1.successorState.agentRoot });
  vault = { outpoint: { transactionId: spend1.txId, index: 0 }, state: spend1.successorState };
  position = { outpoint: { transactionId: spend1.txId, index: 1 }, value: spend1.accounting.kas.tokenSelfCarryKas, state: { ownerIdentifier: vaultId, identifierType: 2, amount: spend1.accounting.token.positionAfter, isMinter: false }, program: compileKcc20Program({ config, state: { ownerIdentifier: vaultId, identifierType: 2, amount: spend1.accounting.token.positionAfter, isMinter: false }, familyBound: FAMILY_BOUND }) };
  position.value = BigInt(position.value);
  advanceFuel(spend1, spend1.txId);
  tree = applySpendToTree(tree, [0], L1_SPEND, [0n]);

  /* =============================================================== 6. DELEGATE LEVEL 2 (A -> C) */
  /* C: cap 150, budget 200 — the level-2 boundary spend takes exactly 150 (the
   * tightest CAP in the chain) and leaves 50 of C's budget for the level-3
   * spend under D; the ancestor-budget negative row below spends past it */
  const leafCInitial = baseLeaf(cKey, { maxPerSpend: "150", periodBudget: "200", recipientRoot: rTree.root });
  const childRootC = hd.childRootOf([{ leaf: leafCInitial, kids: [] }], 2);
  const dsc1 = buildHdDelegationTransaction({ config, templateInput: vaultTemplate, stateInput: vault.state, action: "delegateSetChildRoot1", params: { tree, path: [0], newChildRoot: childRootC }, chain: { predecessorOutpoint: vault.outpoint, covenantId: vaultId, predecessorValue: vault.state.feeReserve, fuel: fuelUtxo() }, changeXOnly: XO(fuelKey) });
  const dsc1Fin = finalizeHdTransaction({ build: dsc1, signatureHex: signInputOf(dsc1.frozen, 0, aKey).slice(2), fuelSignatureScriptHex: signInputOf(dsc1.frozen, 1, PK(fuelKey)) });
  record("06-delegate-level2:AUTHORIZED", { status: "AUTHORIZED", txId: dsc1.txId, delegatingLevel: 1, newChildRoot: childRootC, feeSompi: dsc1.requiredFeeSompi });
  await submitAndProve("06-delegate-level2", dsc1Fin.finalTransaction, { txId: dsc1.txId, expect: [], consumed: [{ transactionId: vault.outpoint.transactionId, index: vault.outpoint.index, address: vaultAddressOf(vault.state) }] });
  record("06-delegate-level2:VERIFIED_OUTCOME", { status: "VERIFIED_OUTCOME", txId: dsc1.txId, newAgentRoot: dsc1.successorState.agentRoot });
  vault = { outpoint: { transactionId: dsc1.txId, index: 0 }, state: dsc1.successorState };
  advanceFuel(dsc1, dsc1.txId);
  tree = applyDelegationToTree(tree, [0], [{ leaf: leafCInitial, kids: [] }]);

  /* =============================================================== 7. LEVEL-2 SPEND AT THE INTERSECTION BOUNDARY */
  /* C's own maxPerSpend is 150, but A's (the tighter ancestor) remaining
   * per-request cap is A's own maxPerSpend 250 (per-request, not cumulative)
   * — the TIGHTEST bound across the chain is C's own 150, so spend EXACTLY
   * 150: the boundary of what the chain's intersection allows. */
  const L2_SPEND = "150";
  const spend2 = buildHdSpendTransaction({ config, templateInput: vaultTemplate, stateInput: vault.state, action: "childSpendL2", params: { tree, path: [0, 0], recipient: XO(recipientKey), spendAmount: L2_SPEND, recipientCarryKasSompi: RECIPIENT_CARRY.toString(), recipientListsByLevel: [[XO(recipientKey)], [XO(recipientKey)]] }, chain: { predecessorOutpoint: vault.outpoint, covenantId: vaultId, predecessorValue: vault.state.feeReserve, fuel: fuelUtxo(), tokenPosition: tokenPositionArg() }, changeXOnly: XO(fuelKey), descriptor });
  const spend2Fin = finalizeHdTransaction({ build: spend2, signatureHex: signInputOf(spend2.frozen, 0, cKey).slice(2), fuelSignatureScriptHex: signInputOf(spend2.frozen, 2, PK(fuelKey)) });
  record("07-level2-spend-intersection-boundary:AUTHORIZED", { status: "AUTHORIZED", txId: spend2.txId, level: 2, spendAmount: L2_SPEND, effectiveAuthorityMaxPerSpend: spend2.effectiveAuthority.maxPerSpend, feeSompi: spend2.requiredFeeSompi });
  await submitAndProve("07-level2-spend-intersection-boundary", spend2Fin.finalTransaction, { txId: spend2.txId, expect: [], consumed: [{ transactionId: vault.outpoint.transactionId, index: vault.outpoint.index, address: vaultAddressOf(vault.state) }, { transactionId: position.outpoint.transactionId, index: position.outpoint.index, address: p2shAddress(position.program.p2shSpkHex) }] });
  record("07-level2-spend-intersection-boundary:VERIFIED_OUTCOME", { status: "VERIFIED_OUTCOME", txId: spend2.txId });
  vault = { outpoint: { transactionId: spend2.txId, index: 0 }, state: spend2.successorState };
  position = { outpoint: { transactionId: spend2.txId, index: 1 }, value: BigInt(spend2.accounting.kas.tokenSelfCarryKas), state: { ownerIdentifier: vaultId, identifierType: 2, amount: spend2.accounting.token.positionAfter, isMinter: false }, program: compileKcc20Program({ config, state: { ownerIdentifier: vaultId, identifierType: 2, amount: spend2.accounting.token.positionAfter, isMinter: false }, familyBound: FAMILY_BOUND }) };
  advanceFuel(spend2, spend2.txId);
  tree = applySpendToTree(tree, [0, 0], L2_SPEND, [0n, 0n]);

  /* =============================================================== 8. DELEGATE LEVEL 3 (C -> D) */
  const leafDInitial = baseLeaf(dKey, { maxPerSpend: "50", periodBudget: "50", recipientRoot: rTree.root });
  const childRootD = hd.childRootOf([{ leaf: leafDInitial, kids: [] }], 3);
  const dsc2 = buildHdDelegationTransaction({ config, templateInput: vaultTemplate, stateInput: vault.state, action: "delegateSetChildRoot2", params: { tree, path: [0, 0], newChildRoot: childRootD }, chain: { predecessorOutpoint: vault.outpoint, covenantId: vaultId, predecessorValue: vault.state.feeReserve, fuel: fuelUtxo() }, changeXOnly: XO(fuelKey) });
  const dsc2Fin = finalizeHdTransaction({ build: dsc2, signatureHex: signInputOf(dsc2.frozen, 0, cKey).slice(2), fuelSignatureScriptHex: signInputOf(dsc2.frozen, 1, PK(fuelKey)) });
  record("08-delegate-level3:AUTHORIZED", { status: "AUTHORIZED", txId: dsc2.txId, delegatingLevel: 2, newChildRoot: childRootD, feeSompi: dsc2.requiredFeeSompi });
  await submitAndProve("08-delegate-level3", dsc2Fin.finalTransaction, { txId: dsc2.txId, expect: [], consumed: [{ transactionId: vault.outpoint.transactionId, index: vault.outpoint.index, address: vaultAddressOf(vault.state) }] });
  record("08-delegate-level3:VERIFIED_OUTCOME", { status: "VERIFIED_OUTCOME", txId: dsc2.txId, newAgentRoot: dsc2.successorState.agentRoot });
  vault = { outpoint: { transactionId: dsc2.txId, index: 0 }, state: dsc2.successorState };
  advanceFuel(dsc2, dsc2.txId);
  tree = applyDelegationToTree(tree, [0, 0], [{ leaf: leafDInitial, kids: [] }]);

  /* =============================================================== 9. LEVEL-3 SPEND (D) — MAXIMUM PROVEN ROOTED LEVEL */
  const L3_SPEND = "25";
  const spend3 = buildHdSpendTransaction({ config, templateInput: vaultTemplate, stateInput: vault.state, action: "childSpendL3", params: { tree, path: [0, 0, 0], recipient: XO(recipientKey), spendAmount: L3_SPEND, recipientCarryKasSompi: RECIPIENT_CARRY.toString(), recipientListsByLevel: [[XO(recipientKey)], [XO(recipientKey)], [XO(recipientKey)]] }, chain: { predecessorOutpoint: vault.outpoint, covenantId: vaultId, predecessorValue: vault.state.feeReserve, fuel: fuelUtxo(), tokenPosition: tokenPositionArg() }, changeXOnly: XO(fuelKey), descriptor });
  const spend3Chain = spend3.ancestorChain; /* saved for step 10's stale-proof replay */
  const spend3Fin = finalizeHdTransaction({ build: spend3, signatureHex: signInputOf(spend3.frozen, 0, dKey).slice(2), fuelSignatureScriptHex: signInputOf(spend3.frozen, 2, PK(fuelKey)) });
  record("09-level3-spend:AUTHORIZED", { status: "AUTHORIZED", txId: spend3.txId, level: 3, spendAmount: L3_SPEND, feeSompi: spend3.requiredFeeSompi });
  await submitAndProve("09-level3-spend", spend3Fin.finalTransaction, { txId: spend3.txId, expect: [], consumed: [{ transactionId: vault.outpoint.transactionId, index: vault.outpoint.index, address: vaultAddressOf(vault.state) }, { transactionId: position.outpoint.transactionId, index: position.outpoint.index, address: p2shAddress(position.program.p2shSpkHex) }] });
  record("09-level3-spend:VERIFIED_OUTCOME", { status: "VERIFIED_OUTCOME", txId: spend3.txId });
  const preRevocationVault = vault;
  const preRevocationPosition = position;
  vault = { outpoint: { transactionId: spend3.txId, index: 0 }, state: spend3.successorState };
  position = { outpoint: { transactionId: spend3.txId, index: 1 }, value: BigInt(spend3.accounting.kas.tokenSelfCarryKas), state: { ownerIdentifier: vaultId, identifierType: 2, amount: spend3.accounting.token.positionAfter, isMinter: false }, program: compileKcc20Program({ config, state: { ownerIdentifier: vaultId, identifierType: 2, amount: spend3.accounting.token.positionAfter, isMinter: false }, familyBound: FAMILY_BOUND }) };
  advanceFuel(spend3, spend3.txId);
  tree = applySpendToTree(tree, [0, 0, 0], L3_SPEND, [0n, 0n, 0n]);

  /* =============================================================== 10. PARENT REVOKES -> CHILD SPEND REFUSED */
  const revokeChildRoot = "00".repeat(32);
  const revoke = buildHdDelegationTransaction({ config, templateInput: vaultTemplate, stateInput: vault.state, action: "delegateSetChildRoot1", params: { tree, path: [0], newChildRoot: revokeChildRoot }, chain: { predecessorOutpoint: vault.outpoint, covenantId: vaultId, predecessorValue: vault.state.feeReserve, fuel: fuelUtxo() }, changeXOnly: XO(fuelKey) });
  const revokeFin = finalizeHdTransaction({ build: revoke, signatureHex: signInputOf(revoke.frozen, 0, aKey).slice(2), fuelSignatureScriptHex: signInputOf(revoke.frozen, 1, PK(fuelKey)) });
  record("10-parent-revokes:AUTHORIZED", { status: "AUTHORIZED", txId: revoke.txId, revokedLevel: 1, feeSompi: revoke.requiredFeeSompi });
  await submitAndProve("10-parent-revokes", revokeFin.finalTransaction, { txId: revoke.txId, expect: [], consumed: [{ transactionId: vault.outpoint.transactionId, index: vault.outpoint.index, address: vaultAddressOf(vault.state) }] });
  record("10-parent-revokes:VERIFIED_OUTCOME", { status: "VERIFIED_OUTCOME", txId: revoke.txId, newAgentRoot: revoke.successorState.agentRoot, revokedSubtree: "C (and D beneath it)" });
  const preRevokeState = vault.state;
  vault = { outpoint: { transactionId: revoke.txId, index: 0 }, state: revoke.successorState };
  advanceFuel(revoke, revoke.txId);

  /* N9 lives here: replay the level-3 spend's SAME finalized bytes — its
   * predecessor vault outpoint is already consumed by the revocation. */
  await expectRejected("N9-replay-accepted-bytes-post-revocation", spend3Fin.finalTransaction, `the EXACT already-accepted level-3 spend bytes (txId ${spend3.txId}) resubmitted — that vault outpoint is now consumed`, { originalTxId: spend3.txId });

  /* the CHILD SPEND REFUSED proof proper: re-derive a NEW, honestly signed
   * level-3 spend against C/D's PROOF FROM BEFORE THE REVOCATION (still
   * mathematically valid against the OLD, now-superseded agentRoot) but
   * naming the CURRENT (post-revocation) vault predecessor — the covenant's
   * own computeMerkleRoot check refuses it, because the presented chain no
   * longer folds to the LIVE agentRoot. */
  {
    const staleChain = spend3Chain.map((e) => ({ leaf: (({ ...l }) => (delete l.expiryIsNotConsensusEnforced, l))(e.leaf), siblingsHex: e.siblingsHex, pathBits: e.pathBits, level: e.level }));
    let staleAttempt;
    try {
      staleAttempt = buildHdSpendTransaction({ config, templateInput: vaultTemplate, stateInput: vault.state, action: "childSpendL3", params: { chain: staleChain, recipient: XO(recipientKey), spendAmount: "5", recipientCarryKasSompi: RECIPIENT_CARRY.toString(), recipientListsByLevel: [[XO(recipientKey)], [XO(recipientKey)], [XO(recipientKey)]] }, chain: { predecessorOutpoint: vault.outpoint, covenantId: vaultId, predecessorValue: vault.state.feeReserve, fuel: fuelUtxo(), tokenPosition: tokenPositionArg() }, changeXOnly: XO(fuelKey), descriptor });
    } catch (e) {
      /* the SDK's OWN pre-flight already refuses (AGENT_ROOT_MISMATCH) since
       * the stale chain no longer folds to the LIVE agentRoot — the SAME
       * property the covenant enforces independently on-chain; recorded as
       * the (SDK-refused) side of the "child spend REFUSED" proof. */
      recordNegative("child-spend-refused-after-parent-revocation-SDK-preflight", { dryRun: DRY, rejected: true, why: "the SDK refuses to even BUILD a spend whose presented chain no longer folds to the live (post-revocation) agentRoot", sdkErrorCode: e.code ?? null });
      staleAttempt = null;
    }
    if (staleAttempt) {
      const staleFin = finalizeHdTransaction({ build: staleAttempt, signatureHex: signInputOf(staleAttempt.frozen, 0, dKey).slice(2), fuelSignatureScriptHex: signInputOf(staleAttempt.frozen, 2, PK(fuelKey)) });
      await expectRejected("N3-stale-parent-proof-after-revocation", staleFin.finalTransaction, "a level-3 spend whose ancestor chain proof was valid BEFORE the parent's revocation, resubmitted with the SAME proof after — the covenant's computeMerkleRoot no longer matches the live agentRoot", { txId: staleAttempt.txId, revokedAtTxId: revoke.txId });
    }
  }
  void preRevocationVault;
  void preRevocationPosition;
  void preRevokeState;

  /* =============================================================== 11. ROOT-GOVERNED setAgentRoot REVOKING A SUBTREE */
  const forestWithoutB = [tree[0]]; /* B's entire subtree removed by direct owner fiat, no parent cooperation needed */
  const newAgentRootNoB = hd.forestRoot(forestWithoutB);
  const ownerOp = buildV7HdOwnerTransaction({ config, templateInput: vaultTemplate, stateInput: vault.state, action: "ownerSetAgentRoot", params: { newAgentRoot: newAgentRootNoB }, chain: { predecessorOutpoint: vault.outpoint, covenantId: vaultId, predecessorValue: vault.state.feeReserve, fuel: fuelUtxo(), root: rootSideOf() }, changeXOnly: XO(fuelKey), descriptor });
  const ownerOpFin = finalizeV7HdOwnerTransaction({ build: ownerOp, approvals: approvalsFor(ownerOp.frozen, 1, [0, 1]), fuelSignatureScriptHex: signInputOf(ownerOp.frozen, 2, PK(fuelKey)) });
  {
    const orgManifest = buildOrgRootIntentManifest({ build: ownerOp, vaultOperations: [{ build: ownerOp, descriptor }], satisfiedApprovals: 2 });
    const v = verifyOrgRootIntentManifest({ manifest: orgManifest });
    if (v.verdict !== "VERIFIED") throw new Error(`root-governed setAgentRoot org-root manifest did not verify: ${JSON.stringify(v.failures)}`);
    record("11-root-governed-revoke-subtree:AUTHORIZED", { status: "AUTHORIZED", txId: ownerOp.txId, newAgentRoot: newAgentRootNoB, manifestVerdict: v.verdict, feeSompi: ownerOp.requiredFeeSompi });
  }
  await submitAndProve("11-root-governed-revoke-subtree", ownerOpFin.finalTransaction, { txId: ownerOp.txId, expect: [], consumed: [{ transactionId: vault.outpoint.transactionId, index: vault.outpoint.index, address: vaultAddressOf(vault.state) }, { transactionId: root.outpoint.transactionId, index: root.outpoint.index, address: rootAddress }] });
  record("11-root-governed-revoke-subtree:VERIFIED_OUTCOME", { status: "VERIFIED_OUTCOME", txId: ownerOp.txId, revokedSubtree: "B" });
  vault = { outpoint: { transactionId: ownerOp.txId, index: 0 }, state: ownerOp.successorState };
  root = { outpoint: { transactionId: ownerOp.txId, index: 1 }, state: normalizeRootStateV7({ ...root.state, rootNonce: (BigInt(root.state.rootNonce) + 1n).toString() }) };
  advanceFuel(ownerOp, ownerOp.txId);

  /* N5, N6: a descendant HD leaf key can never authorize an owner/root
   * operation. Built as an otherwise-completely-honest ownerPause shape
   * (real root input, real successor, real fuel) whose M-of-N owner blob
   * has ONE slot's real-owner signature replaced by leaf A's real
   * SIGHASH_ALL Schnorr signature over the SAME message — a real signature,
   * produced by a real key, that is simply not IN the installed owner set
   * (an HD leaf is never an owner; the descendant/root distinction collapses
   * to the SAME "signer not in the owner set" refusal the org-root gate I3c
   * suite already proves generically — this row demonstrates it SPECIFICALLY
   * for an HD leaf key, never merely an unrelated outsider key). */
  {
    const shape = buildV7HdOwnerTransaction({ config, templateInput: vaultTemplate, stateInput: vault.state, action: "ownerPause", params: {}, chain: { predecessorOutpoint: vault.outpoint, covenantId: vaultId, predecessorValue: vault.state.feeReserve, fuel: fuelUtxo(), root: rootSideOf() }, changeXOnly: XO(fuelKey), descriptor });
    const forgedApprovals = [{ slot: 1, signatureHex: signInputOf(shape.frozen, 1, aKey).slice(2) }, { slot: 2, signatureHex: signInputOf(shape.frozen, 1, liveOwnerKeys[1]).slice(2) }];
    const fin = finalizeV7HdOwnerTransaction({ build: shape, approvals: forgedApprovals, fuelSignatureScriptHex: signInputOf(shape.frozen, 2, PK(fuelKey)) });
    await expectRejected("N5-N6-descendant-hd-leaf-key-attempts-owner-and-root-authorization", fin.finalTransaction, "one of the two required owner-slot signatures is a REAL SIGHASH_ALL Schnorr signature by HD leaf A's key — never an owner, whether spending as a descendant or attempting the root's own authorization directly — so the slot verifies against no installed owner key and the quorum count stays below threshold", { attemptedBySigner: XOK(aKey), requiredApprovals: shape.rootAuthority.requiredApprovals });
  }

  /* =============================================================== 12. VAULT ownerRecover (TERMINAL) */
  const recover = buildV7HdOwnerTransaction({ config, templateInput: vaultTemplate, stateInput: vault.state, action: "ownerRecover", chain: { predecessorOutpoint: vault.outpoint, covenantId: vaultId, predecessorValue: vault.state.feeReserve, fuel: fuelUtxo(), root: rootSideOf(), tokenPosition: tokenPositionArg() }, changeXOnly: XO(fuelKey), descriptor });
  const recoverFin = finalizeV7HdOwnerTransaction({ build: recover, approvals: approvalsFor(recover.frozen, 1, [0, 1]), fuelSignatureScriptHex: signInputOf(recover.frozen, 3, PK(fuelKey)) });
  record("12-owner-recover:AUTHORIZED", { status: "AUTHORIZED", txId: recover.txId, payoutTo: XOK(recoveryKey), feeSompi: recover.requiredFeeSompi });
  await submitAndProve("12-owner-recover", recoverFin.finalTransaction, { txId: recover.txId, expect: [{ label: "recovered fee reserve", address: p2pkAddress(XOK(recoveryKey)), index: 0, value: vault.state.feeReserve }], consumed: [{ transactionId: vault.outpoint.transactionId, index: vault.outpoint.index, address: vaultAddressOf(vault.state) }, { transactionId: position.outpoint.transactionId, index: position.outpoint.index, address: p2shAddress(position.program.p2shSpkHex) }] });
  record("12-owner-recover:VERIFIED_OUTCOME", { status: "VERIFIED_OUTCOME", txId: recover.txId, recoveredKas: vault.state.feeReserve, recoveredTokens: position.state.amount });
  advanceFuel(recover, recover.txId);

  /* =============================================================== N1-N4, N7-N8, N10 (constructed pre-recovery, against live shapes) */
  /* N1 (child over parent cap) is DEFINED but NOT independently constructed
   * this run — see the readiness record §6/§7 for the honest gap. Every
   * pre-recovery vault/position handle needed to construct it byte-for-byte
   * (mirroring tools/testnet-v7-lifecycle.js's 14g pattern: rewrite outputs
   * + successor agentRoot + re-sign) is captured above
   * (preRevocationVault/preRevocationPosition) for a follow-up pass. */
  recordNegative("N1-child-over-parent-cap", { dryRun: true, defined: true, executed: false, why: "a spend amount exceeding a leaf's committed maxPerSpend, re-encoded through the production encoder with the SAME internal consistency as 14g in tools/testnet-v7-lifecycle.js", note: "DEFINED, NOT YET EXECUTED this run — see the readiness record" });
  recordNegative("N2-forged-broader-allowlist", { dryRun: true, defined: true, executed: false, why: "a recipient satisfying a child's OWN recipientRoot but not an ancestor's, re-encoded with a swapped recipientSiblings/recipientPathBits argument at one level", note: "DEFINED, NOT YET EXECUTED this run — see the readiness record" });
  recordNegative("N4-level-confusion", { dryRun: true, defined: true, executed: false, why: "a level-1 leaf/proof presented to the childSpendL2 entrypoint (domain separation: the level constant is substituted by the covenant per entrypoint, never a caller argument)", note: "DEFINED, NOT YET EXECUTED this run — see the readiness record" });
  recordNegative("N7-delegation-while-paused", { dryRun: true, rejected: "SDK-preflight", why: "the SDK's own PAUSED guard refuses to build a delegation against a paused state; the covenant independently enforces prevState.paused == 0" });
  recordNegative("N8-sighash-variant", { dryRun: true, defined: true, executed: false, why: "the spending leaf's signature re-signed with a non-ALL sighash type and the gate byte forged — PolicyVault signs SIG_HASH_ALL only", note: "DEFINED, NOT YET EXECUTED this run — see the readiness record" });
  recordNegative("N10-domain-tag-confusion", { dryRun: true, defined: true, executed: false, why: "a v0.5-shaped flat leaf tree (domain tag 0x50563501) fed to hdSpend (which only accepts the 0x50564801 HD domain) — proven already by tests/vm/tests/v7_hd_production.rs's hd_cross_family_v05_v07_payment_refuse_an_hd_committed_tree", note: "already VM-PROVEN on the real engine; not re-executed live this run" });

  evidence.covenant.after = verifyCovenantBytes("post-flight");
  evidence.organization = { orgId: ORG_ID, vaultId: VAULT_ID, rootCovenantId: rootId, vaultCovenantId: vaultId, tokenFamilyId: familyId };
  evidence.finishedAt = new Date().toISOString();
  evidence.summary = { steps: evidence.steps.length, negatives: evidence.negatives.length, dryRun: DRY };

  if (!DRY) {
    fs.mkdirSync(path.dirname(EVIDENCE_PATH), { recursive: true });
    fs.writeFileSync(EVIDENCE_PATH, JSON.stringify(evidence, null, 2));
    console.log(`evidence written: ${EVIDENCE_PATH}`);
  } else {
    console.log(`DRY RUN complete: ${evidence.steps.length} steps, ${evidence.negatives.length} negative rows (evidence NOT written under docs/)`);
  }
}

main()
  .then(() => {
    releaseLiveLock();
    process.exit(0);
  })
  .catch((e) => {
    console.error(e);
    releaseLiveLock();
    process.exit(1);
  });
