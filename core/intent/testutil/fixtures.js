"use strict";

/*
 * Shared UNIT-TEST fixtures for the intent-manifest suites: coherent
 * synthetic manifests for every supported action, built through the real
 * buildIntentManifest (so hashes and derived sections are genuine).
 *
 * All values are synthetic test vectors (repeated-byte hex identities,
 * round sompi figures). They mirror the REAL structural shapes
 * (stateToJsonV4, agent-merkle-v4 policy leaves, canonicalFrozenTxJson,
 * builder accounting) but are NOT live-chain data: this layer is
 * UNIT-TESTED only — txIds/scripts here are placeholders whose
 * consensus-grade counterparts come from rusty-kaspa via the SDK.
 */

const { buildIntentManifest, p2pkScriptHex } = require("../manifest");
const { computeManifestHashV1 } = require("../canonical");

const HEX = (b) => b.repeat(32);
const OWNER = HEX("11");
const AGENT = HEX("22");
const RECIPIENT = HEX("33");
const K1 = HEX("44");
const K2 = HEX("55");
const K3 = HEX("66");
const K4 = HEX("77");
const ATTACKER = HEX("99");
const COVENANT_ID = HEX("aa");
const AGENT_ROOT_1 = HEX("bb");
const AGENT_ROOT_2 = HEX("cc");
const RECIP_ROOT = HEX("dd");
const VAULT_ID = HEX("ee");
const PREV_TXID = HEX("f1");
const FUEL_TXID = HEX("f2");
const FUND_TXID = HEX("f3");
const STATE_ID_BEFORE = HEX("e1");
const STATE_ID_AFTER = HEX("e2");
const SENTINEL = HEX("00");
const COV_SPK = "ab".repeat(35); // predecessor covenant P2SH spk (placeholder bytes)
const SUCC_SPK = "cd".repeat(35); // successor covenant P2SH spk (placeholder bytes)

const NETWORK = "testnet-10";
const COVENANT_VERSION = "policyvault-0.4.1";

function slots(...active) {
  const out = [...active];
  while (out.length < 10) out.push(SENTINEL);
  return out;
}

function clone(value) {
  return structuredClone(value);
}

/* Recompute the manifest hash after a deliberate tamper — models a
 * policy-invalid adversarial test manifest whose author controls the hash
 * field (the hash proves integrity, the detectors prove honesty). */
function rehash(manifest) {
  const body = { ...manifest };
  delete body.manifestHash;
  return { ...body, manifestHash: computeManifestHashV1(body) };
}

const STATE_BEFORE = Object.freeze({
  protectedValue: "50000000000",
  feeReserve: "100000000",
  paused: "0",
  agentRoot: AGENT_ROOT_1,
  approverSlots: slots(K1, K2, K3),
  approvalM: "2",
  policyNonce: "7"
});

const POLICY_BEFORE = Object.freeze({
  agentPk: AGENT,
  maxPerSpend: "2000000000",
  periodBudget: "5000000000",
  periodLengthDaa: "86400",
  periodStartDaa: "1000000",
  periodSpent: "500000000",
  approvalThreshold: "1500000000",
  agentMaxFeePerTx: "100000",
  agentRecipientRoot: RECIP_ROOT
});

function covenantInput(amount) {
  return {
    previousOutpoint: { transactionId: PREV_TXID, index: 0 },
    sequence: "0",
    computeBudget: 4000,
    utxo: {
      amount,
      scriptPublicKey: { version: 0, scriptHex: COV_SPK },
      covenantId: COVENANT_ID,
      blockDaaScore: "0"
    }
  };
}

function externalInput(txid, index, amount, xOnly) {
  return {
    previousOutpoint: { transactionId: txid, index },
    sequence: "0",
    computeBudget: 10,
    utxo: {
      amount,
      scriptPublicKey: { version: 0, scriptHex: p2pkScriptHex(xOnly) },
      covenantId: null,
      blockDaaScore: "0"
    }
  };
}

function successorOutput(value) {
  return {
    value,
    scriptPublicKey: { version: 0, scriptHex: SUCC_SPK },
    covenant: { authorizingInput: 0, covenantId: COVENANT_ID }
  };
}

function p2pkOutput(value, xOnly) {
  return { value, scriptPublicKey: { version: 0, scriptHex: p2pkScriptHex(xOnly) }, covenant: null };
}

function intentDoc(action, params, maxFeeSompi = "10000") {
  return {
    intentVersion: "policyvault-requested-intent/1",
    networkId: NETWORK,
    vaultId: VAULT_ID,
    covenantVersion: COVENANT_VERSION,
    action,
    params,
    maxFeeSompi
  };
}

const NETWORK_DOC = Object.freeze({ networkId: NETWORK });
const VAULT_DOC = Object.freeze({ vaultId: VAULT_ID, owner: OWNER, covenantVersion: COVENANT_VERSION, covenantId: COVENANT_ID });

/* --------------------------------------------------------------- */
/* agentSpend — reserve-funded, below the approval threshold        */
/* --------------------------------------------------------------- */
function agentSpendFixture() {
  const requestedIntent = intentDoc("agentSpend", {
    agentPk: AGENT,
    recipient: RECIPIENT,
    payAmountSompi: "1000000000",
    periodsElapsed: "0",
    reserveConsumedSompi: "5000"
  });
  const transaction = {
    txId: HEX("0a"),
    version: 1,
    inputs: [covenantInput("50100000000")],
    /* Real SDK builder order: payment (P2PK) is output 0, the covenant-
     * bound successor is output 1 (sdk/src/vault-builders-v4.js). */
    outputs: [p2pkOutput("1000000000", RECIPIENT), successorOutput("49099995000")],
    lockTime: "0",
    subnetworkId: "00".repeat(20),
    gas: "0",
    payload: ""
  };
  const stateAfter = {
    stateId: STATE_ID_AFTER,
    state: {
      ...clone(STATE_BEFORE),
      protectedValue: "49000000000",
      feeReserve: "99995000",
      agentRoot: AGENT_ROOT_2
    }
  };
  const buildInputs = {
    requestedIntent,
    network: clone(NETWORK_DOC),
    vault: clone(VAULT_DOC),
    signerXOnly: AGENT,
    transaction,
    effects: { inputs: ["covenant"], outputs: ["payment", "successor"] },
    stateBefore: { outpoint: { transactionId: PREV_TXID, index: 0 }, stateId: STATE_ID_BEFORE, state: clone(STATE_BEFORE) },
    stateAfter,
    accounting: {
      predecessorProtected: "50000000000",
      predecessorFeeReserve: "100000000",
      payAmount: "1000000000",
      reserveConsumed: "5000",
      externalIn: "0",
      externalOut: "0",
      fee: "5000",
      successorProtected: "49000000000",
      successorFeeReserve: "99995000",
      successorTotal: "49099995000",
      terminalPayout: "0"
    },
    payment: { recipientXOnly: RECIPIENT, amountSompi: "1000000000", outputIndex: 0 },
    allowlist: { agentRecipientRoot: RECIP_ROOT, recipientAllowlisted: true, proofSupplied: true },
    approvals: { aboveThreshold: false, approvalThreshold: "1500000000", requiredM: "2" },
    limits: {
      policyBefore: clone(POLICY_BEFORE),
      policyAfter: { ...clone(POLICY_BEFORE), periodSpent: "1500000000" },
      periodsElapsed: "0"
    },
    warnings: [],
    unexpectedEffects: []
  };
  const manifest = clone(buildIntentManifest(buildInputs));
  return { requestedIntent, buildInputs, manifest, decodedTransaction: clone(transaction) };
}

/* --------------------------------------------------------------- */
/* ownerTopUp — fuel-funded, value flows INTO the covenant          */
/* --------------------------------------------------------------- */
function ownerTopUpFixture() {
  const requestedIntent = intentDoc("ownerTopUp", { topUpAmountSompi: "5000000000" });
  const transaction = {
    txId: HEX("0b"),
    version: 1,
    inputs: [covenantInput("50100000000"), externalInput(FUEL_TXID, 1, "5000010000", OWNER)],
    outputs: [successorOutput("55100000000"), p2pkOutput("5000", OWNER)],
    lockTime: "0",
    subnetworkId: "00".repeat(20),
    gas: "0",
    payload: ""
  };
  const buildInputs = {
    requestedIntent,
    network: clone(NETWORK_DOC),
    vault: clone(VAULT_DOC),
    signerXOnly: OWNER,
    transaction,
    effects: { inputs: ["covenant", "external"], outputs: ["successor", "change"] },
    stateBefore: { outpoint: { transactionId: PREV_TXID, index: 0 }, stateId: STATE_ID_BEFORE, state: clone(STATE_BEFORE) },
    stateAfter: { stateId: STATE_ID_AFTER, state: { ...clone(STATE_BEFORE), protectedValue: "55000000000" } },
    accounting: {
      predecessorProtected: "50000000000",
      predecessorFeeReserve: "100000000",
      payAmount: "0",
      reserveConsumed: "0",
      externalIn: "5000010000",
      externalOut: "5000",
      fee: "5000",
      successorProtected: "55000000000",
      successorFeeReserve: "100000000",
      successorTotal: "55100000000",
      terminalPayout: "0"
    },
    payment: null,
    allowlist: null,
    approvals: null,
    limits: null,
    warnings: [],
    unexpectedEffects: []
  };
  const manifest = clone(buildIntentManifest(buildInputs));
  return { requestedIntent, buildInputs, manifest, decodedTransaction: clone(transaction) };
}

/* --------------------------------------------------------------- */
/* ownerPause                                                       */
/* --------------------------------------------------------------- */
function ownerPauseFixture() {
  const requestedIntent = intentDoc("ownerPause", {});
  const transaction = {
    txId: HEX("0c"),
    version: 1,
    inputs: [covenantInput("50100000000"), externalInput(FUEL_TXID, 2, "10000", OWNER)],
    outputs: [successorOutput("50100000000"), p2pkOutput("5000", OWNER)],
    lockTime: "0",
    subnetworkId: "00".repeat(20),
    gas: "0",
    payload: ""
  };
  const buildInputs = {
    requestedIntent,
    network: clone(NETWORK_DOC),
    vault: clone(VAULT_DOC),
    signerXOnly: OWNER,
    transaction,
    effects: { inputs: ["covenant", "external"], outputs: ["successor", "change"] },
    stateBefore: { outpoint: { transactionId: PREV_TXID, index: 0 }, stateId: STATE_ID_BEFORE, state: clone(STATE_BEFORE) },
    stateAfter: { stateId: STATE_ID_AFTER, state: { ...clone(STATE_BEFORE), paused: "1" } },
    accounting: {
      predecessorProtected: "50000000000",
      predecessorFeeReserve: "100000000",
      payAmount: "0",
      reserveConsumed: "0",
      externalIn: "10000",
      externalOut: "5000",
      fee: "5000",
      successorProtected: "50000000000",
      successorFeeReserve: "100000000",
      successorTotal: "50100000000",
      terminalPayout: "0"
    },
    payment: null,
    allowlist: null,
    approvals: null,
    limits: null,
    warnings: [],
    unexpectedEffects: []
  };
  const manifest = clone(buildIntentManifest(buildInputs));
  return { requestedIntent, buildInputs, manifest, decodedTransaction: clone(transaction) };
}

/* --------------------------------------------------------------- */
/* ownerSetApprovers — policyNonce increments                       */
/* --------------------------------------------------------------- */
function ownerSetApproversFixture() {
  const newSlots = slots(K1, K2, K3, K4);
  const requestedIntent = intentDoc("ownerSetApprovers", { newApproverSlots: newSlots, newApprovalM: "3" });
  const transaction = {
    txId: HEX("0d"),
    version: 1,
    inputs: [covenantInput("50100000000"), externalInput(FUEL_TXID, 3, "10000", OWNER)],
    outputs: [successorOutput("50100000000"), p2pkOutput("5000", OWNER)],
    lockTime: "0",
    subnetworkId: "00".repeat(20),
    gas: "0",
    payload: ""
  };
  const buildInputs = {
    requestedIntent,
    network: clone(NETWORK_DOC),
    vault: clone(VAULT_DOC),
    signerXOnly: OWNER,
    transaction,
    effects: { inputs: ["covenant", "external"], outputs: ["successor", "change"] },
    stateBefore: { outpoint: { transactionId: PREV_TXID, index: 0 }, stateId: STATE_ID_BEFORE, state: clone(STATE_BEFORE) },
    stateAfter: {
      stateId: STATE_ID_AFTER,
      state: { ...clone(STATE_BEFORE), approverSlots: newSlots, approvalM: "3", policyNonce: "8" }
    },
    accounting: {
      predecessorProtected: "50000000000",
      predecessorFeeReserve: "100000000",
      payAmount: "0",
      reserveConsumed: "0",
      externalIn: "10000",
      externalOut: "5000",
      fee: "5000",
      successorProtected: "50000000000",
      successorFeeReserve: "100000000",
      successorTotal: "50100000000",
      terminalPayout: "0"
    },
    payment: null,
    allowlist: null,
    approvals: null,
    limits: null,
    warnings: [],
    unexpectedEffects: []
  };
  const manifest = clone(buildIntentManifest(buildInputs));
  return { requestedIntent, buildInputs, manifest, decodedTransaction: clone(transaction) };
}

/* --------------------------------------------------------------- */
/* ownerSetAgentRoot — direct or via a high-level lifecycle action  */
/* (addAgent / removeAgent / rotateAgent / rePolicyAgent)           */
/* --------------------------------------------------------------- */
function ownerSetAgentRootFixture(requestedAction = "ownerSetAgentRoot") {
  const requestedIntent = intentDoc(requestedAction, { newAgentRoot: AGENT_ROOT_2 });
  const transaction = {
    txId: HEX("1b"),
    version: 1,
    inputs: [covenantInput("50100000000"), externalInput(FUEL_TXID, 5, "10000", OWNER)],
    outputs: [successorOutput("50100000000"), p2pkOutput("5000", OWNER)],
    lockTime: "0",
    subnetworkId: "00".repeat(20),
    gas: "0",
    payload: ""
  };
  const buildInputs = {
    requestedIntent,
    network: clone(NETWORK_DOC),
    vault: clone(VAULT_DOC),
    signerXOnly: OWNER,
    transaction,
    effects: { inputs: ["covenant", "external"], outputs: ["successor", "change"] },
    stateBefore: { outpoint: { transactionId: PREV_TXID, index: 0 }, stateId: STATE_ID_BEFORE, state: clone(STATE_BEFORE) },
    stateAfter: { stateId: STATE_ID_AFTER, state: { ...clone(STATE_BEFORE), agentRoot: AGENT_ROOT_2, policyNonce: "8" } },
    accounting: {
      predecessorProtected: "50000000000",
      predecessorFeeReserve: "100000000",
      payAmount: "0",
      reserveConsumed: "0",
      externalIn: "10000",
      externalOut: "5000",
      fee: "5000",
      successorProtected: "50000000000",
      successorFeeReserve: "100000000",
      successorTotal: "50100000000",
      terminalPayout: "0"
    },
    payment: null,
    allowlist: null,
    approvals: null,
    limits: null,
    warnings: [],
    unexpectedEffects: []
  };
  const manifest = clone(buildIntentManifest(buildInputs));
  return { requestedIntent, buildInputs, manifest, decodedTransaction: clone(transaction) };
}

/* --------------------------------------------------------------- */
/* ownerRecover — terminal                                          */
/* --------------------------------------------------------------- */
function ownerRecoverFixture() {
  const requestedIntent = intentDoc("ownerRecover", {});
  const transaction = {
    txId: HEX("0e"),
    version: 1,
    inputs: [covenantInput("50100000000"), externalInput(FUEL_TXID, 4, "10000", OWNER)],
    outputs: [p2pkOutput("50100000000", OWNER), p2pkOutput("5000", OWNER)],
    lockTime: "0",
    subnetworkId: "00".repeat(20),
    gas: "0",
    payload: ""
  };
  const buildInputs = {
    requestedIntent,
    network: clone(NETWORK_DOC),
    vault: clone(VAULT_DOC),
    signerXOnly: OWNER,
    transaction,
    effects: { inputs: ["covenant", "external"], outputs: ["recoverPayout", "change"] },
    stateBefore: { outpoint: { transactionId: PREV_TXID, index: 0 }, stateId: STATE_ID_BEFORE, state: clone(STATE_BEFORE) },
    stateAfter: null,
    accounting: {
      predecessorProtected: "50000000000",
      predecessorFeeReserve: "100000000",
      payAmount: "0",
      reserveConsumed: "0",
      externalIn: "10000",
      externalOut: "5000",
      fee: "5000",
      successorProtected: "0",
      successorFeeReserve: "0",
      successorTotal: "0",
      terminalPayout: "50100000000"
    },
    payment: null,
    allowlist: null,
    approvals: null,
    limits: null,
    warnings: [],
    unexpectedEffects: []
  };
  const manifest = clone(buildIntentManifest(buildInputs));
  return { requestedIntent, buildInputs, manifest, decodedTransaction: clone(transaction) };
}

/* --------------------------------------------------------------- */
/* createVault — genesis                                            */
/* --------------------------------------------------------------- */
function createVaultFixture() {
  const initialState = {
    protectedValue: "50000000000",
    feeReserve: "100000000",
    paused: "0",
    agentRoot: AGENT_ROOT_1,
    approverSlots: slots(K1, K2, K3),
    approvalM: "2",
    policyNonce: "0"
  };
  const requestedIntent = intentDoc("createVault", { owner: OWNER, initialState: clone(initialState), agentFuel: null });
  const transaction = {
    txId: HEX("1a"),
    version: 1,
    inputs: [externalInput(FUND_TXID, 0, "50100006000", OWNER)],
    outputs: [successorOutput("50100000000"), p2pkOutput("1000", OWNER)],
    lockTime: "0",
    subnetworkId: "00".repeat(20),
    gas: "0",
    payload: ""
  };
  const buildInputs = {
    requestedIntent,
    network: clone(NETWORK_DOC),
    vault: clone(VAULT_DOC),
    signerXOnly: OWNER,
    transaction,
    effects: { inputs: ["external"], outputs: ["genesisVault", "change"] },
    stateBefore: null,
    stateAfter: { stateId: STATE_ID_AFTER, state: clone(initialState) },
    accounting: {
      predecessorProtected: "0",
      predecessorFeeReserve: "0",
      payAmount: "0",
      reserveConsumed: "0",
      externalIn: "50100006000",
      externalOut: "1000",
      fee: "5000",
      successorProtected: "50000000000",
      successorFeeReserve: "100000000",
      successorTotal: "50100000000",
      terminalPayout: "0"
    },
    payment: null,
    allowlist: null,
    approvals: null,
    limits: null,
    warnings: [],
    unexpectedEffects: []
  };
  const manifest = clone(buildIntentManifest(buildInputs));
  return { requestedIntent, buildInputs, manifest, decodedTransaction: clone(transaction) };
}

module.exports = {
  OWNER,
  AGENT,
  RECIPIENT,
  K1,
  K2,
  K3,
  K4,
  ATTACKER,
  COVENANT_ID,
  AGENT_ROOT_1,
  AGENT_ROOT_2,
  RECIP_ROOT,
  VAULT_ID,
  PREV_TXID,
  FUEL_TXID,
  FUND_TXID,
  STATE_ID_BEFORE,
  STATE_ID_AFTER,
  SENTINEL,
  NETWORK,
  COVENANT_VERSION,
  STATE_BEFORE,
  POLICY_BEFORE,
  slots,
  clone,
  rehash,
  p2pkOutput,
  agentSpendFixture,
  ownerTopUpFixture,
  ownerPauseFixture,
  ownerSetApproversFixture,
  ownerSetAgentRootFixture,
  ownerRecoverFixture,
  createVaultFixture
};
