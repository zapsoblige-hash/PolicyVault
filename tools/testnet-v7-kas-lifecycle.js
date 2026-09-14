"use strict";

/*
 * LIVE TESTNET-10 ROOTED KAS SAFE-PAYMENT VAULT LIFECYCLE for the v0.7-kas
 * CANDIDATE covenant (docs/postlaunch/v0.7-kas-profile-readiness.md gate
 * I5). Sibling of tools/testnet-v7-lifecycle.js (the rooted PAYMENT
 * profile's own lifecycle tool). Drives the REAL v0.7-kas SDK
 * (core/model/vault-state-v7-kas, vault-transitions-v7-kas,
 * compute-budget-v7-kas, sdk/src/contract-compiler-v7(-kas),
 * sdk/src/vault-builders-v7-kas, core/intent/org-root-manifest-v7-kas and
 * the production pv_call_encoder) against a LOCAL, VERIFIED testnet-10 node
 * (connectVerified: exact network + synced + utxoindex, never assumed).
 *
 * TEST ASSETS ONLY. TEST KEYS ONLY. NEVER MAINNET.
 *
 *    1. ORGANIZATIONAL ROOT GENESIS (2-of-3, K=1, R=1)
 *    2. ROOTED KAS VAULT GENESIS (pins the root's covenant id AND the
 *       root's template identity + geometry)
 *    3. ownerControl(3) topUpReserve under root AUTHORIZE — adds funds
 *       after genesis (this profile's analog of a deposit: there is no
 *       separate token-deposit concept for plain KAS)
 *    4. ownerControl(1) setApprovers under root AUTHORIZE — configures the
 *       vault-level M-of-N approver tier (3 approvers, M=2) so step 6 has
 *       something to approve against
 *    5. ORDINARY DELEGATED SPEND below the agent's approvalThreshold
 *       (agent key only; NO root input at all)
 *    6. DELEGATED SPEND ABOVE the agent's approvalThreshold, with 2-of-3
 *       vault-level approver signatures (a COMPLETELY SEPARATE M-of-N from
 *       the organizational root's)
 *    7. AUTHORITY EXPANSION: ownerControl(0) setAgentRoot under root
 *       AUTHORIZE
 *    8. AUTHORITY REDUCTION: ownerControl(6) EMERGENCY pause under root
 *       FREEZE (K=1)
 *    9. GOVERNED UNFREEZE (full quorum, a standalone root transition)
 *   10. ownerControl(5) unpause under root AUTHORIZE
 *   11. AUTHORIZED TESTNET NEGATIVE VALIDATION (see below) — >= 6 rows
 *   12. TERMINAL ownerControl-adjacent ownerRecover under root AUTHORIZE:
 *       protectedValue + feeReserve move to the GENESIS-PINNED cold
 *       recoveryPk.
 *
 * NEGATIVE VALIDATION (step 11) is performed with AUTHORIZED TESTNET
 * NEGATIVE-VALIDATION TRANSACTIONS CONSTRUCTED INDEPENDENTLY OF THE
 * POLICYVAULT APPLICATION — the covenant call bytes and/or the owner
 * signature blob are assembled here directly from the production encoder
 * rather than by the SDK builders/finalizers (which refuse to build them at
 * all) — verifying that consensus rejects policy-invalid transactions even
 * when correctly signed by the designated owners/delegate/approvers:
 *   11a. over-cap delegate spend (re-encoded, self-consistent, signed)
 *   11b. approval shortfall (one of the two required vault-level approvals
 *        replaced with the canonical placeholder)
 *   11c. wrong root path (the EMERGENCY selector's sigscript spliced onto a
 *        full-quorum op's transaction, and vice versa — the "selector
 *        cross-over" proof)
 *   11d. no root input at all on an owner operation (the root input+output
 *        pair removed from an otherwise-honest, correctly-encoded
 *        ownerControl transaction)
 *   11e. stale root outpoint (a correctly signed, full-quorum root
 *        transition referencing the PREVIOUS, already-consumed root
 *        outpoint)
 *   11f. replay of the exact bytes of an already-accepted transaction
 *
 * Every accepted step is CHAIN-VERIFIED against the node's UTXO index
 * (exact value, address, covenant id), its predecessors must be CONSUMED,
 * and the ladder AUTHORIZED -> SIGNED -> BROADCAST -> CHAIN_SEEN ->
 * CHAIN_VERIFIED -> VERIFIED_OUTCOME is recorded for each. Evidence ->
 * docs/testnet-v7-kas-evidence.json.
 *
 * LIVE RUNS ARE SERIALIZED across every PolicyVault lane sharing this
 * testnet-10 node: before any broadcast, acquire the lock directory
 * ~/.policyvault-testnet-live.lock (mkdir; retry every 30s;
 * NEVER delete a lock this process did not create), and rmdir it on both
 * success and failure.
 *
 * --dry-run: exercise the whole build/verify/sign/finalize plumbing against
 * SYNTHETIC chain facts with NO RPC and NO broadcast, and NO lock
 * acquisition (writes nothing under docs/). Live:
 *   KASPA_NETWORK_ID=testnet-10 KASPA_RPC_URL=ws://127.0.0.1:18210 \
 *     node tools/testnet-v7-kas-lifecycle.js
 */

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const { loadConfig } = require("../sdk/src/config");
const { loadOrCreateTestKeys } = require("../sdk/src/keys");
const { connectVerified, getAddressUtxos, getVirtualDaaScore } = require("../sdk/src/chain");
const { buildAgentTreeV4 } = require("../sdk/src/agent-merkle-v4");
const { buildRecipientTree } = require("../sdk/src/recipient-merkle-v3");
const { compileExactStateV7Root } = require("../sdk/src/contract-compiler-v7");
const { assertRootPinsMatchV7Kas } = require("../sdk/src/contract-compiler-v7-kas");
const {
  buildCreateV7Root,
  buildV7RootTransaction,
  finalizeV7RootTransaction,
  buildCreateV7KasVault,
  buildV7KasTransaction,
  finalizeV7KasTransaction,
  successorCallJsonV7Kas
} = require("../sdk/src/vault-builders-v7-kas");
const { runEncoderV4 } = require("../sdk/src/vault-builders-v4");
const { covenantSigscript } = require("../sdk/src/spend-vault");
const { frozenToWasmTransaction, describeFrozenTx } = require("../sdk/src/frozen-tx-v3");
const { normalizeFrozenTxV3, canonicalFrozenTxJson, feeDescriptorFromFrozen } = require("../core/model/frozen-tx-v3");
const { calculateRequiredFee } = require("../sdk/src/fee-mass");
const { p2pkScriptHex } = require("../sdk/src/approval-package-v4");
const { OWNER_SLOTS_V7, INACTIVE_SLOT_KEY, PLACEHOLDER_SLOT_HEX_V7 } = require("../core/model/owner-set-v7");
const { normalizeRootStateV7 } = require("../core/model/vault-state-v7-root");
const { buildOrgRootIntentManifestV7Kas, verifyOrgRootIntentManifestV7Kas } = require("../core/intent/org-root-manifest-v7-kas");

const DRY = process.argv.includes("--dry-run") || process.argv.includes("--dry");
const KAS = 100000000n;
const ROOT_DIR = path.join(__dirname, "..");
const DATA_ROOT = process.env.PV_LIVE_DATA_ROOT || (DRY ? fs.mkdtempSync("/tmp/pv7kas-dry-") : "/tmp/pv7kas-live-data");
const EVIDENCE_PATH = path.join(ROOT_DIR, "docs", "testnet-v7-kas-evidence.json");
const LOCK_PATH = path.join(require("os").homedir(), ".policyvault-testnet-live.lock");
const LOCK_DISPLAY = "~/.policyvault-testnet-live.lock";

/* ---- SMALL live parameters (gate I5) ---- */
const ROOT_KAS = 2n * KAS;
const VAULT_PROTECTED = 100n * KAS; /* must cover every honest delegate spend below + the over-cap negative's build-time shape */
const VAULT_RESERVE = 3n * KAS;
const RECOVERY_DELAY_DAA = 600n;
const SUCCESSION_DELAY_DAA = 600n;
const ROOT_MAX_FEE_PER_TX = 1000000n;
const AGENT_MAX_PER_SPEND = (20n * KAS).toString(); /* well above HONEST_SPEND_ABOVE, so only the leaf's approvalThreshold gates step 6 */
const AGENT_PERIOD_BUDGET = (30n * KAS).toString(); /* >= maxPerSpend (so an honest single spend AT the cap is constructible for 11a) and covers HONEST_SPEND_BELOW + HONEST_SPEND_ABOVE (2 + 8 KAS) in one period */
const PERIOD_LENGTH_DAA = "100000000";
const AGENT_MAX_FEE_PER_TX = (1n * KAS).toString();
const AGENT_APPROVAL_THRESHOLD_LOW = (500000000n).toString(); // 5 KAS: the honest low spend stays under; the approved spend goes over
const HONEST_SPEND_BELOW = (200000000n).toString(); // 2 KAS
const HONEST_SPEND_ABOVE = (800000000n).toString(); // 8 KAS: above the 5 KAS threshold, under the 20 KAS cap
const RESERVE_CONSUMED = "50000";
const TOP_UP_RESERVE_AMOUNT = (5n * KAS / 10n).toString(); // 0.5 KAS

/* ---- deterministic evidence ---- */
const evidence = {
  schema: "policyvault-testnet-v7-kas-evidence/1",
  startedAt: new Date().toISOString(),
  finishedAt: null,
  dryRun: DRY,
  mainnet: false,
  network: null,
  covenant: { before: null, after: null },
  parameters: {
    rootKasSompi: ROOT_KAS.toString(),
    vaultProtectedSompi: VAULT_PROTECTED.toString(),
    vaultFeeReserveSompi: VAULT_RESERVE.toString(),
    recoveryDelayDaa: RECOVERY_DELAY_DAA.toString(),
    successionDelayDaa: SUCCESSION_DELAY_DAA.toString(),
    rootMaxFeePerTxSompi: ROOT_MAX_FEE_PER_TX.toString(),
    genesisQuorum: "2-of-3 (ownerM 2, emergencyK 1, recoveryM 1)",
    vaultApproverQuorum: "2-of-3 (approvalM 2) — SEPARATE from the root's own M-of-N"
  },
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
  "PolicyVault.v0.4.1.sil": "421bfed824cf66a9e989f90c5b86fc7359faa070a5d94aace3c325f35ad1da4e",
  "PolicyVault.v0.7-root.sil": "69417514f90d61b0281ea673e6fb5a5fd858c2bd50e14a4eb9043d5fdf17f8ce",
  "PolicyVault.v0.7-kas.sil": "393f2130b48d06ba4d5b29ad8846098dd16ae89ebfd658a2df163f0801ac1d8b"
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

/* ---- the live-broadcast serialization lock (never acquired in --dry-run) ---- */
let lockHeld = false;
async function acquireLock() {
  if (DRY) return;
  for (;;) {
    try {
      fs.mkdirSync(LOCK_PATH);
      lockHeld = true;
      record("lock:ACQUIRED", { path: LOCK_DISPLAY }); // display form: the evidence record never carries an absolute home path (publication privacy)
      return;
    } catch (e) {
      if (e.code !== "EEXIST") throw e;
      console.log(`[lock] ${LOCK_PATH} held by another process; retrying in 30s`);
      await sleep(30000);
    }
  }
}
function releaseLock() {
  if (!lockHeld) return;
  try {
    fs.rmdirSync(LOCK_PATH);
    record("lock:RELEASED", { path: LOCK_DISPLAY });
  } catch (e) {
    console.error(`[lock] failed to release ${LOCK_PATH}: ${e.message}`);
  } finally {
    lockHeld = false;
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
  const agentKey = keys.delegate;
  const recipientKey = keys.recipient1;
  if (!fuelKey || !agentKey || !recipientKey) throw new Error("test key roles funding/delegate/recipient1 are required");

  const O = [KEY(0x71), KEY(0x72), KEY(0x73)];
  const successorKey = KEY(0x7f);
  const recoveryKey = KEY(0x51);
  const approverKeys = [KEY(0x91), KEY(0x92), KEY(0x93)];

  const slots = (ks) => {
    const out = [];
    for (let i = 0; i < OWNER_SLOTS_V7; i += 1) out.push(i < ks.length ? XOK(ks[i]) : INACTIVE_SLOT_KEY);
    return out;
  };
  const ORG_ID = crypto.createHash("sha256").update("policyvault-v0.7-kas-testnet-10-org-root-lifecycle").digest("hex");
  const VAULT_ID = crypto.createHash("sha256").update("policyvault-v0.7-kas-testnet-10-rooted-vault").digest("hex");

  const rootTemplate = { orgId: ORG_ID, recoveryDelayDaa: RECOVERY_DELAY_DAA.toString(), successorPk: XOK(successorKey), successionDelayDaa: SUCCESSION_DELAY_DAA.toString(), rootMaxFeePerTx: ROOT_MAX_FEE_PER_TX.toString() };
  const SET_A = { owners: slots(O), ownerM: 2, emergencyK: 1, recoveryM: 1 };
  const liveOwnerKeys = [...O];

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

  const p2shAddress = (spkHex) => (DRY ? `dry:p2sh:${spkHex.slice(4, 20)}` : kaspa.addressFromScriptPublicKey({ version: 0, script: spkHex }, config.networkId).toString());
  const p2pkAddress = (pk) => (DRY ? `dry:p2pk:${pk.slice(0, 16)}` : kaspa.addressFromScriptPublicKey({ version: 0, script: p2pkScriptHex(pk) }, config.networkId).toString());
  const p2shOfBytes = (scriptBytes) => String(kaspa.payToScriptHashScript(Buffer.from(scriptBytes).toString("hex")).script).toLowerCase();
  const FUEL_SPK = `20${XO(fuelKey)}ac`;
  const FUEL_ADDRESS = p2pkAddress(XO(fuelKey));

  let fuel = null;
  let lastAccepted = null;
  async function primeFuel() {
    if (DRY) {
      fuel = { outpoint: { transactionId: "f0".repeat(32), index: 0 }, amount: 100000n * KAS, scriptPublicKeyHex: FUEL_SPK };
      return;
    }
    const utxos = (await getAddressUtxos(rpc, fuelKey.address)).filter((u) => u.covenantId === null && u.amount > 50n * KAS);
    if (!utxos.length) throw new Error("no plain UTXO > 50 KAS on the test funding key — fund it before running gate I5");
    const u = utxos.reduce((a, b) => (a.amount > b.amount ? a : b));
    fuel = { outpoint: u.outpoint, amount: u.amount, scriptPublicKeyHex: u.scriptPublicKeyHex };
    record("fuel-primed", { outpoint: `${u.outpoint.transactionId}:${u.outpoint.index}`, amountSompi: u.amount.toString(), address: fuelKey.address });
  }
  function advanceFuel(build) {
    const outs = build.frozen.outputs;
    const last = outs[outs.length - 1];
    if (last.scriptPublicKey.scriptHex.toLowerCase() !== FUEL_SPK) throw new Error("internal: the last output is not the fuel change — the fuel chain would break");
    fuel = { outpoint: { transactionId: build.txId, index: outs.length - 1 }, amount: last.value, scriptPublicKeyHex: FUEL_SPK };
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
  const approvalsFor = (frozen, idx, keyIdxs, keySet) => keyIdxs.map((i) => ({ slot: i + 1, signatureHex: signInputOf(frozen, idx, keySet[i]).slice(2) }));

  await acquireLock();
  try {
    await primeFuel();

    /* =============================================================== 1. ROOT GENESIS */
    const rootGenesis = buildCreateV7Root({ config, template: rootTemplate, ownerSet: SET_A, rootValueSompi: ROOT_KAS.toString(), funding: [fuelUtxo()], changeXOnly: XO(fuelKey) });
    const rootId = rootGenesis.covenantId;
    const rootAddress = p2shAddress(p2shOfBytes(Buffer.from(rootGenesis.rootScriptHex, "hex")));
    /* LIVE addresses of the root and vault UTXOs — every transition moves a
     * covenant to a NEW P2SH address (the state is inside the script), so the
     * genesis addresses are only valid until the first transition; every
     * expectation below derives successor addresses from the FROZEN outputs
     * and tracks the live predecessor addresses here. */
    let rootLiveAddress = rootAddress;
    let vaultLiveAddress = null;
    {
      const json = JSON.parse(rootGenesis.frozenCanonicalJson);
      json.inputs[0].signatureScript = signInputOf(rootGenesis.frozen, 0, PK(fuelKey));
      record("01-root-genesis:AUTHORIZED", { status: "AUTHORIZED", txId: rootGenesis.txId, rootCovenantId: rootId, stateId: rootGenesis.stateId, ownerSlots: rootGenesis.ownerSlots, rootPins: rootGenesis.rootPins, scriptSha256: rootGenesis.scriptSha256, feeSompi: rootGenesis.requiredFeeSompi });
      record("01-root-genesis:SIGNED", { status: "SIGNED", txId: rootGenesis.txId, sighash: "ALL" });
      await submitAndProve("01-root-genesis", json, {
        txId: rootGenesis.txId,
        expect: [
          { label: "organizational root", address: rootAddress, index: 0, value: ROOT_KAS.toString(), covenantId: rootId },
          { label: "fuel change", address: FUEL_ADDRESS, index: 1, value: rootGenesis.frozen.outputs[1].value.toString() }
        ]
      });
      record("01-root-genesis:VERIFIED_OUTCOME", { status: "VERIFIED_OUTCOME", txId: rootGenesis.txId, rootCovenantId: rootId, rootNonce: "0" });
      advanceFuel(rootGenesis);
    }
    let root = { outpoint: { transactionId: rootGenesis.txId, index: 0 }, state: rootGenesis.initialState };
    const rootHistory = [{ outpoint: { ...root.outpoint }, rootNonce: "0", stateOverride: null }];
    const rootChainOf = () => ({ predecessorOutpoint: root.outpoint, covenantId: rootId, predecessorValue: ROOT_KAS.toString(), fuel: fuelUtxo() });
    const rootSideOf = () => ({ template: rootTemplate, state: root.state, outpoint: root.outpoint, covenantId: rootId, value: ROOT_KAS.toString() });

    /* =============================================================== 2. VAULT GENESIS */
    const rootPins = rootGenesis.rootPins;
    const vaultTemplate = { vaultId: VAULT_ID, ...rootPins, recoveryPk: XOK(recoveryKey) };
    assertRootPinsMatchV7Kas({ config, vaultTemplate, rootTemplate, rootOwnerSet: SET_A });

    const rTree = buildRecipientTree([XO(recipientKey)]);
    const agentPolicy = (over = {}) => ({ agentPk: XO(agentKey), maxPerSpend: AGENT_MAX_PER_SPEND, periodBudget: AGENT_PERIOD_BUDGET, periodLengthDaa: PERIOD_LENGTH_DAA, periodStartDaa: "0", periodSpent: "0", approvalThreshold: AGENT_APPROVAL_THRESHOLD_LOW, agentMaxFeePerTx: AGENT_MAX_FEE_PER_TX, agentRecipientRoot: rTree.root, ...over });
    let agents = [agentPolicy()];
    const agentTree0 = buildAgentTreeV4(agents);
    const vaultState0 = { protectedValue: VAULT_PROTECTED.toString(), feeReserve: VAULT_RESERVE.toString(), paused: "0", agentRoot: agentTree0.root, approvers: [], approvalM: "0", policyNonce: "0" };
    const vaultGenesis = buildCreateV7KasVault({ config, templateInput: vaultTemplate, initialStateInput: vaultState0, funding: [fuelUtxo()], changeXOnly: XO(fuelKey) });
    const vaultId = vaultGenesis.covenantId;
    {
      const json = JSON.parse(vaultGenesis.frozenCanonicalJson);
      json.inputs[0].signatureScript = signInputOf(vaultGenesis.frozen, 0, PK(fuelKey));
      record("02-vault-genesis:AUTHORIZED", { status: "AUTHORIZED", txId: vaultGenesis.txId, vaultCovenantId: vaultId, stateId: vaultGenesis.stateId, orgRootCovenantId: vaultTemplate.orgRootCovenantId, recoveryPk: vaultTemplate.recoveryPk, initialState: vaultGenesis.initialState, scriptSha256: vaultGenesis.scriptSha256, feeSompi: vaultGenesis.requiredFeeSompi });
      record("02-vault-genesis:SIGNED", { status: "SIGNED", txId: vaultGenesis.txId, sighash: "ALL" });
      await submitAndProve("02-vault-genesis", json, {
        txId: vaultGenesis.txId,
        expect: [
          { label: "rooted kas vault", address: p2shAddress(vaultGenesis.frozen.outputs[0].scriptPublicKey.scriptHex), index: 0, value: (VAULT_PROTECTED + VAULT_RESERVE).toString(), covenantId: vaultId },
          { label: "fuel change", address: FUEL_ADDRESS, index: 1, value: vaultGenesis.frozen.outputs[1].value.toString() }
        ]
      });
      record("02-vault-genesis:VERIFIED_OUTCOME", { status: "VERIFIED_OUTCOME", txId: vaultGenesis.txId, vaultCovenantId: vaultId, pinnedRoot: rootId, protectedValue: VAULT_PROTECTED.toString(), feeReserve: VAULT_RESERVE.toString() });
      vaultLiveAddress = p2shAddress(vaultGenesis.frozen.outputs[0].scriptPublicKey.scriptHex);
      advanceFuel(vaultGenesis);
    }
    let vault = { outpoint: { transactionId: vaultGenesis.txId, index: 0 }, state: vaultGenesis.initialState };
    const vaultChainOf = (over = {}) => ({ predecessorOutpoint: vault.outpoint, covenantId: vaultId, predecessorValue: (BigInt(vault.state.protectedValue) + BigInt(vault.state.feeReserve)).toString(), fuel: fuelUtxo(), root: rootSideOf(), ...over });

    evidence.organization = { orgId: ORG_ID, rootCovenantId: rootId, rootTemplate, rootPins, rootAddress, vaultCovenantId: vaultId, vaultId: VAULT_ID, vaultTemplate: { ...vaultTemplate }, recoveryPk: vaultTemplate.recoveryPk, recoveryAddress: p2pkAddress(vaultTemplate.recoveryPk), successorPk: rootTemplate.successorPk };

    /* generic helper: one owner op requiring the root's AUTHORIZE (full) or FREEZE (emergency) quorum */
    async function ownerOp(stepLabel, action, params, quorumIdxs) {
      const build = buildV7KasTransaction({ config, templateInput: vaultTemplate, stateInput: vault.state, action, params, chain: vaultChainOf(), changeXOnly: XO(fuelKey) });
      const fin = finalizeV7KasTransaction({ build, approvals: approvalsFor(build.frozen, 1, quorumIdxs, liveOwnerKeys), fuelSignatureScriptHex: signInputOf(build.frozen, 2, PK(fuelKey)) });
      record(`${stepLabel}:AUTHORIZED`, { status: "AUTHORIZED", txId: build.txId, action, opSelector: build.callExtra.opSelector, rootAction: build.rootAuthority.rootAction, requiredApprovals: build.rootAuthority.requiredApprovals, feeSompi: build.requiredFeeSompi });
      const manifest = buildOrgRootIntentManifestV7Kas({ build, vaultOperations: [{ build }], satisfiedApprovals: quorumIdxs.length });
      const verdict = verifyOrgRootIntentManifestV7Kas({ manifest, redeemScripts: { [build.covenantId]: build.vaultRedeemScriptHex } }); // R7-04: the predecessor redeem is bound pre-sign
      if (verdict.verdict !== "VERIFIED") throw new Error(`${stepLabel}: the org-root-kas manifest failed to verify: ${JSON.stringify(verdict.failures)}`);
      record(`${stepLabel}:SIGNED`, { status: "SIGNED", txId: build.txId, ownerSighash: "ALL", manifestVerdict: verdict.verdict });
      await submitAndProve(stepLabel, fin.finalTransaction, {
        txId: build.txId,
        expect: [
          { label: "vault successor", address: p2shAddress(build.frozen.outputs[0].scriptPublicKey.scriptHex), index: 0, value: build.frozen.outputs[0].value.toString(), covenantId: vaultId },
          { label: "root successor", address: p2shAddress(build.frozen.outputs[1].scriptPublicKey.scriptHex), index: 1, value: ROOT_KAS.toString(), covenantId: rootId },
          { label: "fuel change", address: FUEL_ADDRESS, index: 2, value: build.frozen.outputs[2].value.toString() }
        ],
        consumed: [
          { transactionId: vault.outpoint.transactionId, index: vault.outpoint.index, address: vaultLiveAddress },
          { transactionId: root.outpoint.transactionId, index: root.outpoint.index, address: rootLiveAddress }
        ]
      });
      record(`${stepLabel}:VERIFIED_OUTCOME`, { status: "VERIFIED_OUTCOME", txId: build.txId, action, successorState: build.successorState });
      advanceFuel(build);
      vault = { outpoint: { transactionId: build.txId, index: 0 }, state: build.successorState };
      vaultLiveAddress = p2shAddress(build.frozen.outputs[0].scriptPublicKey.scriptHex);
      root = { outpoint: { transactionId: build.txId, index: 1 }, state: build.rootAuthority.newState };
      rootLiveAddress = p2shAddress(build.frozen.outputs[1].scriptPublicKey.scriptHex);
      rootHistory.push({ outpoint: { ...root.outpoint }, rootNonce: root.state.rootNonce, stateOverride: null });
      return build;
    }

    /* =============================================================== 3. TOP-UP RESERVE (the deposit analog) */
    await ownerOp("03-owner-top-up-reserve", "ownerTopUpReserve", { topUpReserveAmountSompi: TOP_UP_RESERVE_AMOUNT }, [0, 1]);

    /* =============================================================== 4. SET APPROVERS (the vault-level M-of-N tier) */
    await ownerOp("04-owner-set-approvers", "ownerSetApprovers", { approvers: approverKeys.map(XOK), approvalM: "2" }, [0, 1]);

    /* =============================================================== 5. DELEGATE SPEND BELOW THRESHOLD */
    {
      const spendBuild = buildV7KasTransaction({ config, templateInput: vaultTemplate, stateInput: vault.state, action: "agentSpend", params: { payAmountSompi: HONEST_SPEND_BELOW, agentPk: XO(agentKey), agents, recipient: XO(recipientKey), recipients: [...rTree.recipients], reserveConsumedSompi: RESERVE_CONSUMED }, chain: { predecessorOutpoint: vault.outpoint, covenantId: vaultId, predecessorValue: (BigInt(vault.state.protectedValue) + BigInt(vault.state.feeReserve)).toString(), fuel: fuelUtxo() }, changeXOnly: XO(fuelKey) });
      const fin = finalizeV7KasTransaction({ build: spendBuild, agentSignatureHex: signInputOf(spendBuild.frozen, 0, PK(agentKey)), fuelSignatureScriptHex: signInputOf(spendBuild.frozen, 1, PK(fuelKey)) });
      record("05-delegate-spend-below-threshold:AUTHORIZED", { status: "AUTHORIZED", txId: spendBuild.txId, payAmountSompi: HONEST_SPEND_BELOW, hasRootInput: spendBuild.hasRootInput });
      record("05-delegate-spend-below-threshold:SIGNED", { status: "SIGNED", txId: spendBuild.txId, sighash: "ALL" });
      await submitAndProve("05-delegate-spend-below-threshold", fin.finalTransaction, {
        txId: spendBuild.txId,
        expect: [
          { label: "recipient payout", address: p2pkAddress(XO(recipientKey)), index: 0, value: HONEST_SPEND_BELOW },
          { label: "vault successor", address: p2shAddress(spendBuild.frozen.outputs[1].scriptPublicKey.scriptHex), index: 1, value: spendBuild.frozen.outputs[1].value.toString(), covenantId: vaultId },
          { label: "fuel change", address: FUEL_ADDRESS, index: 2, value: spendBuild.frozen.outputs[2].value.toString() }
        ],
        consumed: [{ transactionId: vault.outpoint.transactionId, index: vault.outpoint.index, address: vaultLiveAddress }]
      });
      record("05-delegate-spend-below-threshold:VERIFIED_OUTCOME", { status: "VERIFIED_OUTCOME", txId: spendBuild.txId, hasRootInput: false });
      advanceFuel(spendBuild);
      vault = { outpoint: { transactionId: spendBuild.txId, index: 1 }, state: spendBuild.successorState };
      vaultLiveAddress = p2shAddress(spendBuild.frozen.outputs[1].scriptPublicKey.scriptHex);
      agents = [{ ...agents[0], periodSpent: (BigInt(agents[0].periodSpent) + BigInt(HONEST_SPEND_BELOW)).toString() }];
    }

    /* =============================================================== 6. DELEGATE SPEND ABOVE THRESHOLD (vault-level 2-of-3) */
    {
      const spendBuild = buildV7KasTransaction({ config, templateInput: vaultTemplate, stateInput: vault.state, action: "agentSpend", params: { payAmountSompi: HONEST_SPEND_ABOVE, agentPk: XO(agentKey), agents, recipient: XO(recipientKey), recipients: [...rTree.recipients], reserveConsumedSompi: RESERVE_CONSUMED }, chain: { predecessorOutpoint: vault.outpoint, covenantId: vaultId, predecessorValue: (BigInt(vault.state.protectedValue) + BigInt(vault.state.feeReserve)).toString(), fuel: fuelUtxo() }, changeXOnly: XO(fuelKey) });
      if (!spendBuild.aboveThreshold) throw new Error("internal: step 6 must be above the leaf's approvalThreshold");
      const { createApprovalPackageForBuildV7Kas } = require("../sdk/src/vault-builders-v7-kas");
      const { submitApprovalV4, approvalsBlobV4 } = require("../sdk/src/approval-package-v4");
      let pkg = createApprovalPackageForBuildV7Kas(spendBuild);
      for (const i of [0, 1]) pkg = submitApprovalV4(pkg, { signatureHex: signInputOf(spendBuild.frozen, 0, approverKeys[i]).slice(2), approverXOnly: XOK(approverKeys[i]) });
      const blobHex = approvalsBlobV4(pkg);
      if (blobHex.length !== 650 * 2) throw new Error("internal: the assembled vault-level approvals blob is not 650 bytes");
      const fin = finalizeV7KasTransaction({ build: spendBuild, agentSignatureHex: signInputOf(spendBuild.frozen, 0, PK(agentKey)), approvalPackage: pkg, fuelSignatureScriptHex: signInputOf(spendBuild.frozen, 1, PK(fuelKey)) });
      record("06-delegate-spend-above-threshold:AUTHORIZED", { status: "AUTHORIZED", txId: spendBuild.txId, payAmountSompi: HONEST_SPEND_ABOVE, approvalThreshold: agents[0].approvalThreshold, approvalM: "2", satisfiedApprovals: "2" });
      record("06-delegate-spend-above-threshold:SIGNED", { status: "SIGNED", txId: spendBuild.txId, sighash: "ALL", vaultLevelApprovers: [XOK(approverKeys[0]), XOK(approverKeys[1])] });
      await submitAndProve("06-delegate-spend-above-threshold", fin.finalTransaction, {
        txId: spendBuild.txId,
        expect: [
          { label: "recipient payout", address: p2pkAddress(XO(recipientKey)), index: 0, value: HONEST_SPEND_ABOVE },
          { label: "vault successor", address: p2shAddress(spendBuild.frozen.outputs[1].scriptPublicKey.scriptHex), index: 1, value: spendBuild.frozen.outputs[1].value.toString(), covenantId: vaultId },
          { label: "fuel change", address: FUEL_ADDRESS, index: 2, value: spendBuild.frozen.outputs[2].value.toString() }
        ],
        consumed: [{ transactionId: vault.outpoint.transactionId, index: vault.outpoint.index, address: vaultLiveAddress }]
      });
      record("06-delegate-spend-above-threshold:VERIFIED_OUTCOME", { status: "VERIFIED_OUTCOME", txId: spendBuild.txId, vaultLevelQuorumSatisfied: true });
      advanceFuel(spendBuild);
      vault = { outpoint: { transactionId: spendBuild.txId, index: 1 }, state: spendBuild.successorState };
      vaultLiveAddress = p2shAddress(spendBuild.frozen.outputs[1].scriptPublicKey.scriptHex);
      agents = [{ ...agents[0], periodSpent: (BigInt(agents[0].periodSpent) + BigInt(HONEST_SPEND_ABOVE)).toString() }];
    }

    /* =============================================================== 7. AUTHORITY EXPANSION: setAgentRoot */
    const freshAgent = agentPolicy({ periodSpent: "0" });
    const freshAgentRoot = buildAgentTreeV4([freshAgent]).root;
    /* STALE ASSUMPTION corrected (v0.7 enablement, 2026-09-10): since the rc26 R7-02 parity hardening the builder DERIVES the
     * agent root from the FULL new policy set (with each delegate's recipients) and refuses a bare root — the tool passes
     * the set; the derived root must still equal the locally computed one. */
    await ownerOp("07-owner-set-agent-root", "ownerSetAgentRoot", { agents: [{ ...freshAgent, recipients: [...rTree.recipients] }], newAgentRoot: freshAgentRoot }, [0, 1]);
    agents = [freshAgent];

    /* =============================================================== 8. AUTHORITY REDUCTION: EMERGENCY pause */
    await ownerOp("08-owner-emergency-pause", "ownerEmergencyPause", {}, [0]);

    /* =============================================================== 9. GOVERNED UNFREEZE (standalone root transition) */
    {
      const build = buildV7RootTransaction({ config, templateInput: rootTemplate, stateInput: root.state, action: "unfreeze", chain: rootChainOf(), changeXOnly: XO(fuelKey) });
      const fin = finalizeV7RootTransaction({ build, approvals: approvalsFor(build.frozen, 0, [0, 1], liveOwnerKeys), fuelSignatureScriptHex: signInputOf(build.frozen, 1, PK(fuelKey)) });
      record("09-root-unfreeze:AUTHORIZED", { status: "AUTHORIZED", txId: build.txId, rootAction: "unfreeze", requiredApprovals: build.requiredApprovals });
      record("09-root-unfreeze:SIGNED", { status: "SIGNED", txId: build.txId, sighash: "ALL" });
      await submitAndProve("09-root-unfreeze", fin.finalTransaction, {
        txId: build.txId,
        expect: [
          { label: "root successor", address: p2shAddress(build.frozen.outputs[0].scriptPublicKey.scriptHex), index: 0, value: ROOT_KAS.toString(), covenantId: rootId },
          { label: "fuel change", address: FUEL_ADDRESS, index: 1, value: build.frozen.outputs[1].value.toString() }
        ],
        consumed: [{ transactionId: root.outpoint.transactionId, index: root.outpoint.index, address: rootLiveAddress }]
      });
      record("09-root-unfreeze:VERIFIED_OUTCOME", { status: "VERIFIED_OUTCOME", txId: build.txId, frozen: build.successorState.frozen });
      advanceFuel(build);
      root = { outpoint: { transactionId: build.txId, index: 0 }, state: build.successorState };
      rootLiveAddress = p2shAddress(build.frozen.outputs[0].scriptPublicKey.scriptHex);
      rootHistory.push({ outpoint: { ...root.outpoint }, rootNonce: root.state.rootNonce, stateOverride: null });
    }

    /* =============================================================== 10. ownerUnpause under root AUTHORIZE */
    await ownerOp("10-owner-unpause", "ownerUnpause", {}, [0, 1]);

    /* =============================================================== 11. AUTHORIZED TESTNET NEGATIVE VALIDATION */
    {
      /* 11a. over-cap delegate spend, re-encoded self-consistently and signed */
      {
        const cap = BigInt(agents[0].maxPerSpend);
        const over = cap + 1n;
        const shape = buildV7KasTransaction({ config, templateInput: vaultTemplate, stateInput: vault.state, action: "agentSpend", params: { payAmountSompi: cap.toString(), agentPk: XO(agentKey), agents, recipient: XO(recipientKey), recipients: [...rTree.recipients], reserveConsumedSompi: RESERVE_CONSUMED }, chain: { predecessorOutpoint: vault.outpoint, covenantId: vaultId, predecessorValue: (BigInt(vault.state.protectedValue) + BigInt(vault.state.feeReserve)).toString(), fuel: fuelUtxo() }, changeXOnly: XO(fuelKey) });
        const agentsOver = [{ ...agents[0], periodSpent: (BigInt(agents[0].periodSpent) + over).toString() }];
        const successorOver = { ...shape.successorState, protectedValue: (BigInt(vault.state.protectedValue) - over).toString(), agentRoot: buildAgentTreeV4(agentsOver).root };
        const nextOver = require("../sdk/src/contract-compiler-v7-kas").compileExactStateV7Kas({ config, template: vaultTemplate, state: require("../core/model/vault-state-v4").normalizeStateV4(successorOver) });
        const j = JSON.parse(shape.frozenCanonicalJson);
        j.outputs[0].value = over.toString();
        j.outputs[1].value = (BigInt(j.outputs[1].value) - (over - cap)).toString();
        j.outputs[1].scriptPublicKey.scriptHex = p2shOfBytes(nextOver.scriptBytes);
        const frozenOver = normalizeFrozenTxV3(j);
        const agentSig = signInputOf(frozenOver, 0, PK(agentKey)).slice(2);
        const callOver = { function: "agentSpend", signature: agentSig, ...shape.callExtra, payAmount: over.toString(), successor: successorCallJsonV7Kas(successorOver), approvals: "00".repeat(650) };
        const callHexOver = runEncoderV4({ sourcePath: path.join(shape.encoderBuildDir, "PolicyVault.state.sil"), constructorArgsPath: path.join(shape.encoderBuildDir, "constructor-args.json"), call: callOver, contractVersion: shape.contractVersion });
        const artifact = JSON.parse(fs.readFileSync(path.join(shape.encoderBuildDir, "artifact.json")));
        const outTx = JSON.parse(canonicalFrozenTxJson(frozenOver));
        outTx.inputs[0].signatureScript = covenantSigscript(callHexOver, Buffer.from(artifact.script));
        outTx.inputs[1].signatureScript = signInputOf(frozenOver, 1, PK(fuelKey));
        await expectRejected("11a-delegate-over-cap-spend", outTx, `a fully self-consistent delegated spend of ${over} sompi — outputs, covenant-call arguments, successor agent root and the delegate's SIGHASH_ALL signature all agree — whose only policy defect is that ${over} exceeds the agent's on-chain maxPerSpend of ${cap}`, { spendAmountSompi: over.toString(), maxPerSpendSompi: cap.toString() });
      }

      /* 11b. approval shortfall — one of the two required vault-level approvals abstains */
      {
        const spendBuild = buildV7KasTransaction({ config, templateInput: vaultTemplate, stateInput: vault.state, action: "agentSpend", params: { payAmountSompi: HONEST_SPEND_ABOVE, agentPk: XO(agentKey), agents, recipient: XO(recipientKey), recipients: [...rTree.recipients], reserveConsumedSompi: RESERVE_CONSUMED }, chain: { predecessorOutpoint: vault.outpoint, covenantId: vaultId, predecessorValue: (BigInt(vault.state.protectedValue) + BigInt(vault.state.feeReserve)).toString(), fuel: fuelUtxo() }, changeXOnly: XO(fuelKey) });
        const { createApprovalPackageForBuildV7Kas } = require("../sdk/src/vault-builders-v7-kas");
        const { submitApprovalV4 } = require("../sdk/src/approval-package-v4");
        let pkg = createApprovalPackageForBuildV7Kas(spendBuild);
        /* the vault-level approver tier's normalizeStateV4 canonicalizes
         * (sorts) the approver slots — approverKeys[0] is NOT necessarily
         * slot 0, so submitApprovalV4's own indexOf lookup is what places
         * the signature in the CORRECT slot; only ONE of the two required
         * approvals is submitted here, on purpose (the shortfall). */
        pkg = submitApprovalV4(pkg, { signatureHex: signInputOf(spendBuild.frozen, 0, approverKeys[0]).slice(2), approverXOnly: XOK(approverKeys[0]) });
        const placeholder65 = PLACEHOLDER_SLOT_HEX_V7.length === 130 ? PLACEHOLDER_SLOT_HEX_V7 : "00".repeat(64) + "01";
        const blobHex = pkg.approvals.map((a) => a ?? placeholder65).join("");
        if (blobHex.length !== 650 * 2) throw new Error("internal: the 11b approvals blob is not 650 bytes");
        const agentSig = signInputOf(spendBuild.frozen, 0, PK(agentKey)).slice(2);
        const call = { function: "agentSpend", signature: agentSig, ...spendBuild.callExtra, successor: successorCallJsonV7Kas(spendBuild.successorState), approvals: blobHex };
        const callHex = runEncoderV4({ sourcePath: path.join(spendBuild.encoderBuildDir, "PolicyVault.state.sil"), constructorArgsPath: path.join(spendBuild.encoderBuildDir, "constructor-args.json"), call, contractVersion: spendBuild.contractVersion });
        const artifact = JSON.parse(fs.readFileSync(path.join(spendBuild.encoderBuildDir, "artifact.json")));
        const outTx = JSON.parse(spendBuild.frozenCanonicalJson);
        outTx.inputs[0].signatureScript = covenantSigscript(callHex, Buffer.from(artifact.script));
        outTx.inputs[1].signatureScript = signInputOf(spendBuild.frozen, 1, PK(fuelKey));
        await expectRejected("11b-vault-approval-shortfall", outTx, "an above-threshold delegate spend carrying only 1 of the 2 required vault-level approver signatures (the abstaining slot carries the canonical placeholder); this is a SEPARATE M-of-N from the organizational root's own quorum", { requiredApprovals: "2", suppliedApprovals: "1" });
      }

      /* 11c. wrong root path — the EMERGENCY selector's sigscript spliced onto a full-quorum op's transaction */
      {
        const pauseLikeBuild = buildV7KasTransaction({ config, templateInput: vaultTemplate, stateInput: vault.state, action: "ownerPause", params: {}, chain: vaultChainOf(), changeXOnly: XO(fuelKey) });
        const pauseFin = finalizeV7KasTransaction({ build: pauseLikeBuild, approvals: approvalsFor(pauseLikeBuild.frozen, 1, [0, 1], liveOwnerKeys), fuelSignatureScriptHex: signInputOf(pauseLikeBuild.frozen, 2, PK(fuelKey)) });
        const unpausedForEmergency = { ...vault.state, paused: "0" };
        const emergencyBuild = buildV7KasTransaction({ config, templateInput: vaultTemplate, stateInput: unpausedForEmergency, action: "ownerEmergencyPause", params: {}, chain: { predecessorOutpoint: vault.outpoint, covenantId: vaultId, predecessorValue: (BigInt(vault.state.protectedValue) + BigInt(vault.state.feeReserve)).toString(), fuel: fuelUtxo(), root: rootSideOf() }, changeXOnly: XO(fuelKey) });
        const emergencyFin = finalizeV7KasTransaction({ build: emergencyBuild, approvals: approvalsFor(emergencyBuild.frozen, 1, [0], liveOwnerKeys), fuelSignatureScriptHex: signInputOf(emergencyBuild.frozen, 2, PK(fuelKey)) });
        const tampered = JSON.parse(JSON.stringify(pauseFin.finalTransaction));
        tampered.inputs[0].signatureScript = emergencyFin.finalTransaction.inputs[0].signatureScript;
        await expectRejected("11c-wrong-root-path-emergency-selector-under-authorize-root", tampered, "the EMERGENCY-pause selector's covenant call bytes (opSelector 6) spliced onto a transaction whose ROOT input proves a full-quorum AUTHORIZE (not the lighter FREEZE) — the vault pins WHICH root path ran, not merely that a root is present", { pauseTxId: pauseLikeBuild.txId, emergencyTxId: emergencyBuild.txId });
      }

      /* 11d. no root input at all on an owner operation */
      {
        const build = buildV7KasTransaction({ config, templateInput: vaultTemplate, stateInput: vault.state, action: "ownerPause", params: {}, chain: vaultChainOf(), changeXOnly: XO(fuelKey) });
        const fin = finalizeV7KasTransaction({ build, approvals: approvalsFor(build.frozen, 1, [0, 1], liveOwnerKeys), fuelSignatureScriptHex: signInputOf(build.frozen, 2, PK(fuelKey)) });
        const j = JSON.parse(JSON.stringify(fin.finalTransaction));
        j.inputs.splice(1, 1); // remove the root input
        j.outputs.splice(1, 1); // remove the root's continuation output (value-neutral: root value in == value out)
        await expectRejected("11d-owner-op-with-no-root-input", j, "a correctly-encoded ownerControl(4 pause) call (no signature of its own — the vault input carries none) with the organizational-root input AND its continuation output both removed; requireRootAuthorization's OpCovInputCount(orgRootCovenantId) == 1 check fails closed with zero root inputs present", { txId: build.txId });
      }

      /* 11e. stale root outpoint — a correctly signed, full-quorum root transition referencing a PREVIOUS, already-consumed root outpoint */
      {
        const stale = rootHistory[rootHistory.length - 3] ?? rootHistory[0];
        const staleState = normalizeRootStateV7({ ...root.state, rootNonce: stale.rootNonce, frozen: "0" });
        const staleBuild = buildV7RootTransaction({ config, templateInput: rootTemplate, stateInput: staleState, action: "authorize", chain: { predecessorOutpoint: stale.outpoint, covenantId: rootId, predecessorValue: ROOT_KAS.toString(), fuel: fuelUtxo() }, changeXOnly: XO(fuelKey) });
        const staleFin = finalizeV7RootTransaction({ build: staleBuild, approvals: approvalsFor(staleBuild.frozen, 0, [0, 1], liveOwnerKeys), fuelSignatureScriptHex: signInputOf(staleBuild.frozen, 1, PK(fuelKey)) });
        await expectRejected("11e-stale-root-outpoint", staleFin.finalTransaction, `a correctly signed, full-quorum AUTHORIZE referencing the PREVIOUS root outpoint ${stale.outpoint.transactionId}:${stale.outpoint.index} (root nonce ${stale.rootNonce}), already consumed by an accepted successor — the root outpoint is the organization's freshness kill switch`, { staleRootOutpoint: `${stale.outpoint.transactionId}:${stale.outpoint.index}`, liveRootOutpoint: `${root.outpoint.transactionId}:${root.outpoint.index}` });
      }

      /* 11f. replay of the exact bytes of an already-accepted transaction */
      if (lastAccepted) {
        await expectRejected("11f-replay-accepted-bytes", lastAccepted.finalTransaction, `the EXACT bytes of the already-accepted transaction from step ${lastAccepted.label} resubmitted — every input it names is consumed, so consensus refuses the replay`, { txId: lastAccepted.txId, originalStep: lastAccepted.label });
      }
    }

    /* =============================================================== 12. TERMINAL ownerRecover */
    {
      const build = buildV7KasTransaction({ config, templateInput: vaultTemplate, stateInput: vault.state, action: "ownerRecover", params: {}, chain: vaultChainOf(), changeXOnly: XO(fuelKey) });
      const fin = finalizeV7KasTransaction({ build, approvals: approvalsFor(build.frozen, 1, [0, 1], liveOwnerKeys), fuelSignatureScriptHex: signInputOf(build.frozen, 2, PK(fuelKey)) });
      const payout = (BigInt(vault.state.protectedValue) + BigInt(vault.state.feeReserve)).toString();
      record("12-vault-owner-recover:AUTHORIZED", { status: "AUTHORIZED", txId: build.txId, payoutSompi: payout, recoveryPk: vaultTemplate.recoveryPk });
      record("12-vault-owner-recover:SIGNED", { status: "SIGNED", txId: build.txId, sighash: "ALL" });
      await submitAndProve("12-vault-owner-recover", fin.finalTransaction, {
        txId: build.txId,
        expect: [
          { label: "recovery payout", address: p2pkAddress(vaultTemplate.recoveryPk), index: 0, value: payout },
          { label: "root successor", address: p2shAddress(build.frozen.outputs[1].scriptPublicKey.scriptHex), index: 1, value: ROOT_KAS.toString(), covenantId: rootId },
          { label: "fuel change", address: FUEL_ADDRESS, index: 2, value: build.frozen.outputs[2].value.toString() }
        ],
        consumed: [
          { transactionId: vault.outpoint.transactionId, index: vault.outpoint.index, address: vaultLiveAddress },
          { transactionId: root.outpoint.transactionId, index: root.outpoint.index, address: rootLiveAddress }
        ]
      });
      record("12-vault-owner-recover:VERIFIED_OUTCOME", { status: "VERIFIED_OUTCOME", txId: build.txId, terminal: true, payoutSompi: payout });
      advanceFuel(build);
      root = { outpoint: { transactionId: build.txId, index: 1 }, state: build.rootAuthority.newState };
    }

    evidence.covenant.after = verifyCovenantBytes("post-flight");
    evidence.summary = { stepsRecorded: evidence.steps.length, negativesRecorded: evidence.negatives.length, dryRun: DRY, finalRootNonce: root.state.rootNonce };
    evidence.finishedAt = new Date().toISOString();
    if (!DRY) {
      fs.mkdirSync(path.dirname(EVIDENCE_PATH), { recursive: true });
      fs.writeFileSync(EVIDENCE_PATH, JSON.stringify(evidence, null, 2));
      console.log(`\nevidence written to ${EVIDENCE_PATH}`);
    } else {
      console.log(`\nDRY RUN complete: ${evidence.steps.length} steps, ${evidence.negatives.length} negatives recorded (nothing written under docs/)`);
    }
  } finally {
    releaseLock();
  }
}

main().catch((e) => {
  releaseLock();
  console.error("FATAL:", e);
  process.exitCode = 1;
});
