"use strict";

/*
 * Shared fixtures for the web/test suites: coherent SERVER-DOCUMENT-shaped
 * scenarios (vault presentation, wallet-request document, unsigned Safe
 * JSON string) mirroring the real presentVaultV4 / presentRequest /
 * kaspa-wasm serializeToSafeJSON shapes, plus tamper helpers for the
 * policy-invalid adversarial test transactions of the hostile matrix.
 *
 * All values are synthetic test vectors (repeated-byte hex identities,
 * round sompi figures) mirroring core/intent/testutil/fixtures.js.
 */

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
const VAULT_ID = HEX("ee");

/*
 * TRUE Merkle roots (F1 wave): verify-intent now INDEPENDENTLY RECOMPUTES
 * the recipient-allowlist root and the agent-registry root (predecessor
 * AND successors) from the displayed leaf data, so these fixtures carry
 * the REAL roots of the displayed registry — computed here through the
 * same byte-native core modules the browser bundle embeds.
 */
const { buildRecipientTree } = require("../../core/model/recipient-merkle-v3.js");
const { buildAgentTreeV4, applyAgentSpendV4, addAgentV4 } = require("../../core/model/agent-merkle-v4.js");
/* Fee/state recomputation wave: fixtures now carry TRUE recomputed
 * values everywhere the browser verifier independently recomputes —
 * consensus fee floors/exacts (core fee-mass over the canonical frozen
 * descriptor, the identical SDK call path), canonical proven-safe
 * compute-budget tiers, and canonical v0.4 state ids. */
const { calculateRequiredFee } = require("../../core/model/fee-mass.js");
const { normalizeFrozenTxV3, feeDescriptorFromFrozen } = require("../../core/model/frozen-tx-v3.js");
const { computeStateIdV4, normalizeStateV4, normalizeTemplateV4 } = require("../../core/model/vault-state-v4.js");
const { V4_BUDGET } = require("../../core/model/compute-budget-v4.js");
const { sompiToKas } = require("../../core/model/amounts.js");

const RECIP_ROOT = buildRecipientTree([RECIPIENT]).root;
/* The displayed agent's exact policy tuple (sompi mirror of the KAS
 * strings in baseVault below). agentMaxFeePerTx must cover the TRUE
 * recomputed reserve-funded fee (the browser now enforces the real
 * consensus fee floor). */
const AGENT_POLICY_1 = Object.freeze({
  agentPk: AGENT,
  maxPerSpend: "2000000000", // 20 KAS
  periodBudget: "5000000000", // 50 KAS
  periodLengthDaa: "86400",
  periodStartDaa: "1000000",
  periodSpent: "500000000", // 5 KAS
  approvalThreshold: "1500000000", // 15 KAS
  agentMaxFeePerTx: "10000000", // 0.1 KAS
  agentRecipientRoot: RECIP_ROOT
});
const AGENT_TREE_1 = buildAgentTreeV4([AGENT_POLICY_1]);
const AGENT_ROOT_1 = AGENT_TREE_1.root;
/* Successor roots for the two spend scenarios (no rollover; periodSpent
 * advances by the payment). */
const SPEND_SUCC_ROOT = applyAgentSpendV4(AGENT_TREE_1, AGENT, { newPeriodStartDaa: "1000000", newPeriodSpent: "1500000000" }).tree.root; // 5 + 10 KAS
const ABOVE_SUCC_ROOT = applyAgentSpendV4(AGENT_TREE_1, AGENT, { newPeriodStartDaa: "1000000", newPeriodSpent: "2500000000" }).tree.root; // 5 + 20 KAS
/* addAgent scenario: the NEW agent the client types (full policy) and the
 * true successor root the request must claim. */
const NEW_AGENT_RECIPIENTS = Object.freeze([RECIPIENT, K4]);
const NEW_AGENT_PARAM = Object.freeze({
  agentPk: HEX("88"),
  maxPerSpend: "1000000000",
  periodBudget: "3000000000",
  periodLengthDaa: "864000",
  periodStartDaa: "1200000",
  periodSpent: "0",
  approvalThreshold: "0",
  agentMaxFeePerTx: "10000000",
  recipients: NEW_AGENT_RECIPIENTS
});
const ADD_AGENT_SUCC_ROOT = addAgentV4(AGENT_TREE_1, {
  agentPk: NEW_AGENT_PARAM.agentPk,
  maxPerSpend: NEW_AGENT_PARAM.maxPerSpend,
  periodBudget: NEW_AGENT_PARAM.periodBudget,
  periodLengthDaa: NEW_AGENT_PARAM.periodLengthDaa,
  periodStartDaa: NEW_AGENT_PARAM.periodStartDaa,
  periodSpent: NEW_AGENT_PARAM.periodSpent,
  approvalThreshold: NEW_AGENT_PARAM.approvalThreshold,
  agentMaxFeePerTx: NEW_AGENT_PARAM.agentMaxFeePerTx,
  agentRecipientRoot: buildRecipientTree([...NEW_AGENT_RECIPIENTS]).root
}).root;
/* Legacy fixture name: the 10-KAS-spend successor root. In scenarios whose
 * true root is a DIFFERENT value (e.g. a registry-preserving owner op,
 * whose successor root is AGENT_ROOT_1) it doubles as the hostile
 * wrong-root claim. */
const AGENT_ROOT_2 = SPEND_SUCC_ROOT;
const PREV_TXID = HEX("f1");
const FUEL_TXID = HEX("f2");
const FUND_TXID = HEX("f3");
const SENTINEL = HEX("00");
const COV_SPK = "ab".repeat(35);
const NETWORK = "testnet-10";
const VERSION = "policyvault-0.4.1";

const OWNER_ADDR = "kaspatest:owner0000000000000000000000000000000000000000000000000000000000";
const AGENT_ADDR = "kaspatest:agent0000000000000000000000000000000000000000000000000000000000";

function slots(...active) {
  const out = [...active];
  while (out.length < 10) out.push(SENTINEL);
  return out;
}

/* ---- TRUE canonical state ids (fee/state recomputation wave) ----
 * The browser verifier recomputes every v0.4 state id with
 * core/model/vault-state-v4 computeStateIdV4; fixture ids are therefore
 * the REAL commitments of the fixture states. */
function stateIdOf(state) {
  return computeStateIdV4({
    networkId: NETWORK,
    template: normalizeTemplateV4({ owner: OWNER, vaultId: VAULT_ID }),
    state: normalizeStateV4(state),
    contractVersion: VERSION
  });
}

/* The base vault's exact live state tuple (sompi mirror of baseVault). */
const BASE_STATE = Object.freeze({
  protectedValue: "50000000000", // 500 KAS
  feeReserve: "100000000", // 1 KAS
  paused: "0",
  agentRoot: AGENT_ROOT_1,
  approverSlots: slots(K1, K2, K3),
  approvalM: "2",
  policyNonce: "7"
});
const STATE_ID_BEFORE = stateIdOf(BASE_STATE);

/* ---- TRUE recomputed consensus fees (fee/state recomputation wave) ----
 * requiredFeeForSafeTx mirrors web/verify-intent.js recomputeFeeRequirement
 * EXACTLY: the canonical frozen descriptor (core frozen-tx-v3) fed to core
 * fee-mass calculateRequiredFee, with covenant inputs at signature-script
 * length 0 (their final covenant signature script is undisclosed — the
 * result is the enforced floor) and ordinary inputs at their exact final
 * 66-byte length (EXACT for all-ordinary shapes, e.g. genesis). Values
 * never affect the fee (fixed-width u64), so shapes can be priced before
 * final values are assigned. */
function requiredFeeForSafeTx(tx, covenantOutpoints) {
  const isCov = (i) => covenantOutpoints.some((op) => op.transactionId === i.transactionId && op.index === i.index);
  const frozen = normalizeFrozenTxV3({
    version: 1,
    inputs: tx.inputs.map((i) => ({
      previousOutpoint: { transactionId: i.transactionId, index: i.index },
      sequence: i.sequence,
      computeBudget: i.computeBudget,
      utxo: {
        amount: i.utxo.amount,
        scriptPublicKey: { version: 0, scriptHex: i.utxo.scriptPublicKey.slice(4) },
        covenantId: null,
        blockDaaScore: i.utxo.blockDaaScore
      }
    })),
    outputs: tx.outputs.map((o) => ({
      value: o.value,
      scriptPublicKey: { version: 0, scriptHex: o.scriptPublicKey.slice(4) },
      covenant: o.covenant
    })),
    lockTime: tx.lockTime,
    subnetworkId: tx.subnetworkId,
    gas: "0",
    payload: ""
  });
  const sigLens = tx.inputs.map((i) => (isCov(i) ? 0 : 66));
  return calculateRequiredFee(feeDescriptorFromFrozen(frozen, sigLens)).minimumRequiredFee;
}

/* Fixture fees for COVENANT transitions sit this far above the recomputed
 * floor, modeling the fee contribution of the real (undisclosed) covenant
 * signature-script bytes. Any fee >= the floor passes the browser's bound;
 * the headroom keeps tamper fixtures that slightly grow the floor (an
 * added output) from tripping the fee bound instead of the detector under
 * test. */
const COVENANT_FEE_HEADROOM = 100000n;

const p2pk = (x) => `20${x}ac`;
const spkWire = (scriptHex) => `0000${scriptHex}`; // u16 version 0 (BE) + script

function clone(v) {
  return structuredClone(v);
}

/* ---- unsigned Safe JSON (kaspa-wasm string-serializable shape) ---- */

function safeInput({ transactionId, index, amount, scriptHex, computeBudget = 10, blockDaaScore = "0" }) {
  return {
    transactionId,
    index,
    sequence: "0",
    sigOpCount: 0,
    computeBudget,
    signatureScript: "",
    utxo: {
      address: null,
      amount,
      scriptPublicKey: spkWire(scriptHex),
      blockDaaScore,
      isCoinbase: false,
      covenantId: null // the server's Safe JSON does not populate input covenantIds
    }
  };
}

function safeOutput({ value, scriptHex, covenant = null }) {
  return { value, scriptPublicKey: spkWire(scriptHex), covenant };
}

function safeTx({ id, inputs, outputs, lockTime = "0" }) {
  return {
    id,
    version: 1,
    inputs,
    outputs,
    subnetworkId: "00".repeat(20),
    lockTime,
    gas: "0",
    storageMass: "0",
    payload: ""
  };
}

const safeJson = (tx) => JSON.stringify(tx);

/* ---- the client's vault presentation (presentVaultV4 shape) ---- */

function baseVault() {
  return {
    vaultId: VAULT_ID,
    label: "web-test vault",
    status: "ACTIVE",
    networkId: NETWORK,
    contractVersion: VERSION,
    owner: OWNER,
    ownerAddress: OWNER_ADDR,
    agentRegistryRoot: AGENT_ROOT_1,
    agents: [
      {
        agentPk: AGENT,
        agentAddress: AGENT_ADDR,
        maxPerSpendKas: "20",
        periodBudgetKas: "50",
        periodSpentKas: "5",
        remainingBudgetKas: "45",
        periodLengthDaa: "86400",
        periodStartDaa: "1000000",
        approvalThresholdKas: "15",
        agentMaxFeePerTxKas: "0.1",
        agentRecipientRoot: RECIP_ROOT,
        recipients: [RECIPIENT],
        recipientAddresses: ["kaspatest:recipient0"]
      }
    ],
    approverSlots: slots(K1, K2, K3),
    approvalM: "2",
    activeApproverCount: 3,
    live: {
      protectedValueKas: "500",
      feeReserveKas: "1",
      covenantValueKas: "501",
      paused: false,
      agentRoot: AGENT_ROOT_1,
      approvalM: "2",
      policyNonce: "7",
      stateId: STATE_ID_BEFORE,
      outpoint: { transactionId: PREV_TXID, index: 0 },
      covenantId: COVENANT_ID
    }
  };
}

/* ---- request documents (presentRequest shape) ---- */

function baseRequest(overrides) {
  return Object.assign(
    {
      schema: "policyvault-wallet-request/4",
      requestId: "req-web-test",
      state: "BUILT",
      contractVersion: VERSION,
      networkId: NETWORK,
      vaultId: VAULT_ID,
      signerRole: "owner",
      signerAddress: OWNER_ADDR,
      signerXOnly: OWNER,
      agentPk: null,
      aboveThreshold: false,
      predecessorOutpoint: { transactionId: PREV_TXID, index: 0 },
      predecessorStateId: STATE_ID_BEFORE,
      covenantId: COVENANT_ID,
      createdAt: "2026-08-26T00:00:00.000Z"
    },
    overrides
  );
}

/* ---------------- scenarios ---------------- */

/* Build the RESERVE-FUNDED spend shape: [covenant] -> [payment, successor].
 * fee == reserveConsumed (drawdown minus payment); values assigned after
 * the shape is priced. */
function reserveSpendTx(id, budget, paySompi, succValueSompi) {
  return safeTx({
    id,
    inputs: [safeInput({ transactionId: PREV_TXID, index: 0, amount: "50100000000", scriptHex: COV_SPK, computeBudget: budget })],
    outputs: [
      safeOutput({ value: paySompi.toString(), scriptHex: p2pk(RECIPIENT) }),
      safeOutput({ value: succValueSompi.toString(), scriptHex: COV_SPK, covenant: { authorizingInput: 0, covenantId: COVENANT_ID } })
    ]
  });
}
const COVENANT_OUTPOINTS = [{ transactionId: PREV_TXID, index: 0 }];

/* agentSpend — reserve-funded, 10 KAS to RECIPIENT; fee = the TRUE
 * recomputed floor + covenant-signature headroom, consumed from the
 * reserve (fee == reserveConsumed in reserve mode). */
const SPEND_FEE_SOMPI = requiredFeeForSafeTx(reserveSpendTx(HEX("0a"), V4_BUDGET.SPEND_NO_APPROVALS, 1n, 1n), COVENANT_OUTPOINTS) + COVENANT_FEE_HEADROOM;
const SPEND_SUCC_STATE = Object.freeze({
  ...BASE_STATE,
  protectedValue: "49000000000",
  feeReserve: (100000000n - SPEND_FEE_SOMPI).toString(),
  agentRoot: SPEND_SUCC_ROOT
});
const SPEND_SUCC_STATE_ID = stateIdOf(SPEND_SUCC_STATE);

function spendScenario() {
  const pay = 1000000000n; // 10 KAS
  const fee = SPEND_FEE_SOMPI;
  const tx = reserveSpendTx(HEX("0a"), V4_BUDGET.SPEND_NO_APPROVALS, pay, 50100000000n - pay - fee);
  const request = baseRequest({
    action: "agentSpend",
    sdkAction: "agentSpend",
    signerRole: "agent",
    signerAddress: AGENT_ADDR,
    signerXOnly: AGENT,
    agentPk: AGENT,
    aboveThreshold: false,
    successorStateId: SPEND_SUCC_STATE_ID,
    review: {
      action: "agentSpend",
      network: NETWORK,
      vaultId: VAULT_ID,
      predecessorOutpoint: { transactionId: PREV_TXID, index: 0 },
      predecessorStateId: STATE_ID_BEFORE,
      policyNonceBefore: "7",
      protectedBeforeKas: "500",
      reserveBeforeKas: "1",
      feeKas: sompiToKas(fee),
      feeSompi: fee.toString(),
      computeBudget: V4_BUDGET.SPEND_NO_APPROVALS,
      protectedAfterKas: "490",
      reserveAfterKas: sompiToKas(100000000n - fee),
      reserveConsumedKas: sompiToKas(fee),
      externalFuelKas: "0",
      policyNonceAfter: "7",
      successorAgentRoot: AGENT_ROOT_2,
      successorStateId: SPEND_SUCC_STATE_ID,
      recipient: RECIPIENT,
      recipientAddress: "kaspatest:recipient0",
      paymentKas: "10",
      fundingMode: "RESERVE-FUNDED"
    },
    transaction: { unsignedSafeJson: safeJson(tx), signInputs: [{ index: 0, sighashType: 1 }], covenantInputIndex: 0 },
    txId: HEX("0a")
  });
  return {
    tx,
    request,
    vault: baseVault(),
    clientAction: "agentSpend",
    clientParams: { agentPk: AGENT, recipient: RECIPIENT, payAmountSompi: "1000000000" },
    sessionNetwork: NETWORK,
    sessionXOnly: AGENT
  };
}

/* agentSpend ABOVE the approval threshold (20 KAS > 15 KAS) — the durable
 * approval workflow request (AWAITING_APPROVALS; approver + resumed agent
 * signing flows reconstruct intent from this document). */
const ABOVE_FEE_SOMPI = requiredFeeForSafeTx(reserveSpendTx(HEX("2a"), V4_BUDGET.SPEND_WITH_APPROVALS, 1n, 1n), COVENANT_OUTPOINTS) + COVENANT_FEE_HEADROOM;
const ABOVE_SUCC_STATE = Object.freeze({
  ...BASE_STATE,
  protectedValue: "48000000000",
  feeReserve: (100000000n - ABOVE_FEE_SOMPI).toString(),
  agentRoot: ABOVE_SUCC_ROOT
});
const ABOVE_SUCC_STATE_ID = stateIdOf(ABOVE_SUCC_STATE);

function aboveSpendScenario() {
  const pay = 2000000000n; // 20 KAS
  const fee = ABOVE_FEE_SOMPI;
  const tx = reserveSpendTx(HEX("2a"), V4_BUDGET.SPEND_WITH_APPROVALS, pay, 50100000000n - pay - fee);
  const request = baseRequest({
    requestId: "req-web-test-above",
    state: "AWAITING_APPROVALS",
    action: "agentSpend",
    sdkAction: "agentSpend",
    signerRole: "agent",
    signerAddress: AGENT_ADDR,
    signerXOnly: AGENT,
    agentPk: AGENT,
    aboveThreshold: true,
    successorStateId: ABOVE_SUCC_STATE_ID,
    approvalProgress: { collected: 0, required: 2, approverSlots: null, approvedSlots: null, complete: false },
    review: {
      action: "agentSpend",
      network: NETWORK,
      vaultId: VAULT_ID,
      policyNonceBefore: "7",
      protectedBeforeKas: "500",
      reserveBeforeKas: "1",
      feeSompi: fee.toString(),
      computeBudget: V4_BUDGET.SPEND_WITH_APPROVALS,
      protectedAfterKas: "480",
      reserveAfterKas: sompiToKas(100000000n - fee),
      reserveConsumedKas: sompiToKas(fee),
      externalFuelKas: "0",
      policyNonceAfter: "7",
      successorAgentRoot: ABOVE_SUCC_ROOT,
      successorStateId: ABOVE_SUCC_STATE_ID,
      recipient: RECIPIENT,
      recipientAddress: "kaspatest:recipient0",
      paymentKas: "20",
      fundingMode: "RESERVE-FUNDED",
      approvalsRequired: "2"
    },
    transaction: { unsignedSafeJson: safeJson(tx), signInputs: [{ index: 0, sighashType: 1 }], covenantInputIndex: 0 },
    txId: HEX("2a")
  });
  return {
    tx,
    request,
    vault: baseVault(),
    sessionNetwork: NETWORK,
    sessionXOnly: AGENT // the acting agent; approver tests override with K1
  };
}

/* Build a fuel-funded owner-op shape: [covenant(OWNER_OP), fuel(10)] ->
 * [successor, change]. The fee is the TRUE recomputed floor + headroom;
 * the fuel covers exactly fee + change. */
function ownerOpTx(id, fuelIndex, succValueSompi, { fuelAmount, changeValue, payoutScriptHex } = {}) {
  return safeTx({
    id,
    inputs: [
      safeInput({ transactionId: PREV_TXID, index: 0, amount: "50100000000", scriptHex: COV_SPK, computeBudget: V4_BUDGET.OWNER_OP }),
      safeInput({ transactionId: FUEL_TXID, index: fuelIndex, amount: (fuelAmount ?? 1n).toString(), scriptHex: p2pk(OWNER) })
    ],
    outputs: [
      payoutScriptHex
        ? safeOutput({ value: succValueSompi.toString(), scriptHex: payoutScriptHex })
        : safeOutput({ value: succValueSompi.toString(), scriptHex: COV_SPK, covenant: { authorizingInput: 0, covenantId: COVENANT_ID } }),
      safeOutput({ value: (changeValue ?? 1n).toString(), scriptHex: p2pk(OWNER) })
    ]
  });
}
const OWNER_OP_CHANGE = 1000n;
const OWNER_OP_FEE_SOMPI = requiredFeeForSafeTx(ownerOpTx(HEX("0b"), 1, 1n), COVENANT_OUTPOINTS) + COVENANT_FEE_HEADROOM;

/* ownerTopUp — 50 KAS, fuel-funded */
const TOPUP_SUCC_STATE = Object.freeze({ ...BASE_STATE, protectedValue: "55000000000" });
const TOPUP_SUCC_STATE_ID = stateIdOf(TOPUP_SUCC_STATE);
function topUpScenario() {
  const fee = OWNER_OP_FEE_SOMPI;
  const fuel = 5000000000n + fee + OWNER_OP_CHANGE;
  const tx = ownerOpTx(HEX("0b"), 1, 55100000000n, { fuelAmount: fuel, changeValue: OWNER_OP_CHANGE });
  const request = baseRequest({
    action: "ownerTopUp",
    sdkAction: "ownerTopUp",
    successorStateId: TOPUP_SUCC_STATE_ID,
    review: {
      action: "ownerTopUp",
      network: NETWORK,
      vaultId: VAULT_ID,
      policyNonceBefore: "7",
      protectedBeforeKas: "500",
      reserveBeforeKas: "1",
      feeKas: sompiToKas(fee),
      feeSompi: fee.toString(),
      computeBudget: V4_BUDGET.OWNER_OP,
      protectedAfterKas: "550",
      reserveAfterKas: "1",
      reserveConsumedKas: "0",
      externalFuelKas: sompiToKas(fuel),
      policyNonceAfter: "7",
      successorAgentRoot: AGENT_ROOT_1,
      successorStateId: TOPUP_SUCC_STATE_ID
    },
    transaction: { unsignedSafeJson: safeJson(tx), signInputs: [{ index: 0, sighashType: 1 }, { index: 1, sighashType: 1 }], covenantInputIndex: 0 },
    txId: HEX("0b")
  });
  return {
    tx,
    request,
    vault: baseVault(),
    clientAction: "ownerTopUp",
    clientParams: { topUpAmountSompi: "5000000000" },
    clientFuel: { outpoint: { transactionId: FUEL_TXID, index: 1 }, amount: fuel.toString(), scriptPublicKeyHex: spkWire(p2pk(OWNER)) },
    sessionNetwork: NETWORK,
    sessionXOnly: OWNER
  };
}

/* ownerPause — fuel-funded, value-preserving */
const PAUSE_SUCC_STATE = Object.freeze({ ...BASE_STATE, paused: "1" });
const PAUSE_SUCC_STATE_ID = stateIdOf(PAUSE_SUCC_STATE);
function pauseScenario() {
  const fee = OWNER_OP_FEE_SOMPI;
  const fuel = fee + OWNER_OP_CHANGE;
  const tx = ownerOpTx(HEX("0c"), 2, 50100000000n, { fuelAmount: fuel, changeValue: OWNER_OP_CHANGE });
  const request = baseRequest({
    action: "ownerPause",
    sdkAction: "ownerPause",
    successorStateId: PAUSE_SUCC_STATE_ID,
    review: {
      action: "ownerPause",
      network: NETWORK,
      vaultId: VAULT_ID,
      policyNonceBefore: "7",
      protectedBeforeKas: "500",
      reserveBeforeKas: "1",
      feeSompi: fee.toString(),
      protectedAfterKas: "500",
      reserveAfterKas: "1",
      policyNonceAfter: "7",
      successorAgentRoot: AGENT_ROOT_1,
      successorStateId: PAUSE_SUCC_STATE_ID
    },
    transaction: { unsignedSafeJson: safeJson(tx), signInputs: [{ index: 0, sighashType: 1 }, { index: 1, sighashType: 1 }], covenantInputIndex: 0 },
    txId: HEX("0c")
  });
  return {
    tx,
    request,
    vault: baseVault(),
    clientAction: "ownerPause",
    clientParams: {},
    clientFuel: { outpoint: { transactionId: FUEL_TXID, index: 2 }, amount: fuel.toString() },
    sessionNetwork: NETWORK,
    sessionXOnly: OWNER
  };
}

/* ownerSetApprovers — K1..K4, M=3 (nonce increments) */
const SETAPPROVERS_SUCC_STATE = Object.freeze({ ...BASE_STATE, approverSlots: slots(K1, K2, K3, K4), approvalM: "3", policyNonce: "8" });
const SETAPPROVERS_SUCC_STATE_ID = stateIdOf(SETAPPROVERS_SUCC_STATE);
function setApproversScenario() {
  const fee = OWNER_OP_FEE_SOMPI;
  const fuel = fee + OWNER_OP_CHANGE;
  const tx = ownerOpTx(HEX("0d"), 3, 50100000000n, { fuelAmount: fuel, changeValue: OWNER_OP_CHANGE });
  const request = baseRequest({
    action: "ownerSetApprovers",
    sdkAction: "ownerSetApprovers",
    successorStateId: SETAPPROVERS_SUCC_STATE_ID,
    review: {
      action: "ownerSetApprovers",
      network: NETWORK,
      vaultId: VAULT_ID,
      policyNonceBefore: "7",
      protectedBeforeKas: "500",
      reserveBeforeKas: "1",
      feeSompi: fee.toString(),
      protectedAfterKas: "500",
      reserveAfterKas: "1",
      policyNonceAfter: "8",
      successorAgentRoot: AGENT_ROOT_1,
      successorStateId: SETAPPROVERS_SUCC_STATE_ID
    },
    transaction: { unsignedSafeJson: safeJson(tx), signInputs: [{ index: 0, sighashType: 1 }, { index: 1, sighashType: 1 }], covenantInputIndex: 0 },
    txId: HEX("0d")
  });
  return {
    tx,
    request,
    vault: baseVault(),
    clientAction: "ownerSetApprovers",
    clientParams: { newApprovers: { approvers: [K1, K2, K3, K4], approvalM: "3" } },
    clientFuel: { outpoint: { transactionId: FUEL_TXID, index: 3 }, amount: fuel.toString() },
    sessionNetwork: NETWORK,
    sessionXOnly: OWNER
  };
}

/* addAgent (high-level -> ownerSetAgentRoot; the successor root is
 * INDEPENDENTLY RECOMPUTED from the client's full typed agent params and
 * the request's claim must match it) */
const ADDAGENT_SUCC_STATE = Object.freeze({ ...BASE_STATE, agentRoot: ADD_AGENT_SUCC_ROOT, policyNonce: "8" });
const ADDAGENT_SUCC_STATE_ID = stateIdOf(ADDAGENT_SUCC_STATE);
function addAgentScenario() {
  const fee = OWNER_OP_FEE_SOMPI;
  const fuel = fee + OWNER_OP_CHANGE;
  const tx = ownerOpTx(HEX("1b"), 5, 50100000000n, { fuelAmount: fuel, changeValue: OWNER_OP_CHANGE });
  const request = baseRequest({
    action: "addAgent",
    sdkAction: "ownerSetAgentRoot",
    highLevel: "addAgent",
    successorStateId: ADDAGENT_SUCC_STATE_ID,
    review: {
      action: "addAgent",
      network: NETWORK,
      vaultId: VAULT_ID,
      policyNonceBefore: "7",
      protectedBeforeKas: "500",
      reserveBeforeKas: "1",
      feeSompi: fee.toString(),
      protectedAfterKas: "500",
      reserveAfterKas: "1",
      policyNonceAfter: "8",
      successorAgentRoot: ADD_AGENT_SUCC_ROOT,
      successorStateId: ADDAGENT_SUCC_STATE_ID
    },
    transaction: { unsignedSafeJson: safeJson(tx), signInputs: [{ index: 0, sighashType: 1 }, { index: 1, sighashType: 1 }], covenantInputIndex: 0 },
    txId: HEX("1b")
  });
  return {
    tx,
    request,
    vault: baseVault(),
    clientAction: "addAgent",
    clientParams: { agent: clone(NEW_AGENT_PARAM) }, // the FULL typed policy — the successor root is recomputed from exactly this
    clientFuel: { outpoint: { transactionId: FUEL_TXID, index: 5 }, amount: fuel.toString() },
    sessionNetwork: NETWORK,
    sessionXOnly: OWNER
  };
}

/* ownerRecover — terminal ([covenant(RECOVER), fuel] -> [payout, change]) */
const RECOVER_FEE_SOMPI = (() => {
  const shape = safeTx({
    id: HEX("0e"),
    inputs: [
      safeInput({ transactionId: PREV_TXID, index: 0, amount: "50100000000", scriptHex: COV_SPK, computeBudget: V4_BUDGET.RECOVER }),
      safeInput({ transactionId: FUEL_TXID, index: 4, amount: "1", scriptHex: p2pk(OWNER) })
    ],
    outputs: [
      safeOutput({ value: "50100000000", scriptHex: p2pk(OWNER) }),
      safeOutput({ value: "1", scriptHex: p2pk(OWNER) })
    ]
  });
  return requiredFeeForSafeTx(shape, COVENANT_OUTPOINTS) + COVENANT_FEE_HEADROOM;
})();
function recoverScenario() {
  const fee = RECOVER_FEE_SOMPI;
  const fuel = fee + OWNER_OP_CHANGE;
  const tx = safeTx({
    id: HEX("0e"),
    inputs: [
      safeInput({ transactionId: PREV_TXID, index: 0, amount: "50100000000", scriptHex: COV_SPK, computeBudget: V4_BUDGET.RECOVER }),
      safeInput({ transactionId: FUEL_TXID, index: 4, amount: fuel.toString(), scriptHex: p2pk(OWNER) })
    ],
    outputs: [
      safeOutput({ value: "50100000000", scriptHex: p2pk(OWNER) }),
      safeOutput({ value: OWNER_OP_CHANGE.toString(), scriptHex: p2pk(OWNER) })
    ]
  });
  const request = baseRequest({
    action: "ownerRecover",
    sdkAction: "ownerRecover",
    successorStateId: null,
    review: {
      action: "ownerRecover",
      network: NETWORK,
      vaultId: VAULT_ID,
      policyNonceBefore: "7",
      protectedBeforeKas: "500",
      reserveBeforeKas: "1",
      feeSompi: fee.toString(),
      computeBudget: V4_BUDGET.RECOVER,
      terminal: "VAULT CLOSED — protected value + fee reserve return to the owner wallet",
      recoveredKas: "501",
      protectedAfterKas: "0",
      reserveAfterKas: "0"
    },
    transaction: { unsignedSafeJson: safeJson(tx), signInputs: [{ index: 0, sighashType: 1 }, { index: 1, sighashType: 1 }], covenantInputIndex: 0 },
    txId: HEX("0e")
  });
  return {
    tx,
    request,
    vault: baseVault(),
    clientAction: "ownerRecover",
    clientParams: {},
    clientFuel: { outpoint: { transactionId: FUEL_TXID, index: 4 }, amount: fuel.toString() },
    sessionNetwork: NETWORK,
    sessionXOnly: OWNER
  };
}

/* createVault — genesis (client-generated vaultId; owner = session
 * identity). ALL inputs are ordinary, so the browser recomputes the fee
 * EXACTLY: the fixture funding is derived from the true requirement. */
const CREATE_FEE_SOMPI = requiredFeeForSafeTx(
  safeTx({
    id: HEX("1a"),
    inputs: [safeInput({ transactionId: FUND_TXID, index: 0, amount: "1", scriptHex: p2pk(OWNER) })],
    outputs: [
      safeOutput({ value: "1", scriptHex: COV_SPK, covenant: { authorizingInput: 0, covenantId: COVENANT_ID } }),
      safeOutput({ value: "1", scriptHex: p2pk(OWNER) })
    ]
  }),
  [] // no covenant inputs: the recomputed fee is EXACT
);
const CREATE_CHANGE = 1000n;
const CREATE_FUNDING = 50100000000n + CREATE_FEE_SOMPI + CREATE_CHANGE;
function createScenario() {
  const tx = safeTx({
    id: HEX("1a"),
    inputs: [safeInput({ transactionId: FUND_TXID, index: 0, amount: CREATE_FUNDING.toString(), scriptHex: p2pk(OWNER) })],
    outputs: [
      safeOutput({ value: "50100000000", scriptHex: COV_SPK, covenant: { authorizingInput: 0, covenantId: COVENANT_ID } }),
      safeOutput({ value: CREATE_CHANGE.toString(), scriptHex: p2pk(OWNER) })
    ]
  });
  const initialState = {
    protectedValue: "50000000000",
    feeReserve: "100000000",
    paused: "0",
    agentRoot: AGENT_ROOT_1,
    approverSlots: slots(K1, K2, K3),
    approvalM: "2",
    policyNonce: "0"
  };
  const request = baseRequest({
    action: "createVault",
    kind: "genesis",
    signerRole: "owner",
    predecessorOutpoint: undefined,
    predecessorStateId: undefined,
    successorStateId: undefined,
    template: { owner: OWNER, vaultId: VAULT_ID },
    initialState,
    /* the DISCLOSED genesis registry leaf tuples (residuals wave): the
     * browser recomputes initialState.agentRoot from these — the fixture
     * tuple is the TRUE preimage of AGENT_ROOT_1 */
    initialRegistry: [{ ...AGENT_POLICY_1, recipients: [RECIPIENT] }],
    vaultOutputIndex: 0,
    review: {
      action: "createVault",
      network: NETWORK,
      depositKas: "500",
      reserveKas: "1",
      agentCount: 1,
      approvalPolicy: "2 of 3 approvers",
      agents: [{ agentPk: AGENT, maxPerSpendKas: "20", recipients: [RECIPIENT] }],
      covenantId: COVENANT_ID,
      technical: { approvalM: "2" }
    },
    transaction: { unsignedSafeJson: safeJson(tx), signInputs: [{ index: 0, sighashType: 1 }], covenantInputIndex: null },
    txId: HEX("1a")
  });
  delete request.predecessorOutpoint;
  delete request.predecessorStateId;
  delete request.successorStateId;
  return {
    tx,
    request,
    createContext: {
      vaultId: VAULT_ID,
      depositKas: "500",
      feeReserveKas: "1",
      approvalM: "2",
      approverXOnlys: [K1, K2, K3],
      agentXOnly: AGENT,
      /* typed agent policy (KAS mirrors of AGENT_POLICY_1) + resolved
       * recipient identities — pins the disclosed genesis tuple */
      agentMaxPerSpendKas: "20",
      agentBudgetKas: "50",
      agentApprovalThresholdKas: "15",
      agentMaxFeePerTxKas: "0.1",
      agentRecipientXOnlys: [RECIPIENT]
    },
    sessionNetwork: NETWORK,
    sessionXOnly: OWNER
  };
}

/*
 * A vault view whose displayed allowlist AND all Merkle commitments are
 * ROOT-CONSISTENT for a different recipient set (the agent's
 * agentRecipientRoot, the policy leaf, and live.agentRoot are all
 * recomputed) — for distinguishing "consistent view, recipient simply not
 * listed" (ALLOWLIST_NOT_PROVEN) from "view inconsistent with the
 * commitment" (ALLOWLIST_ROOT_MISMATCH).
 */
function vaultWithConsistentRecipients(recipients) {
  const vault = baseVault();
  const recipRoot = buildRecipientTree([...recipients]).root;
  vault.agents[0].recipients = [...recipients];
  vault.agents[0].agentRecipientRoot = recipRoot;
  vault.live.agentRoot = buildAgentTreeV4([{ ...AGENT_POLICY_1, agentRecipientRoot: recipRoot }]).root;
  /* keep the view's state id the TRUE commitment of the modified state
   * (the browser now recomputes it) */
  vault.live.stateId = stateIdOf({ ...BASE_STATE, agentRoot: vault.live.agentRoot });
  return vault;
}

/* re-serialize a tampered Safe JSON tx into the scenario's request (the
 * adversarial author controls the request document too, so the embedded
 * txId claim is kept consistent with the tampered payload unless a test
 * deliberately desynchronizes them). */
function withTamperedTx(scenario, mutate, { keepTxIdClaim = true } = {}) {
  const s = clone(scenario);
  const tx = JSON.parse(s.request.transaction.unsignedSafeJson);
  mutate(tx);
  s.request.transaction.unsignedSafeJson = JSON.stringify(tx);
  if (keepTxIdClaim) s.request.txId = tx.id;
  s.tx = tx;
  return s;
}

module.exports = {
  HEX,
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
  SENTINEL,
  COV_SPK,
  NETWORK,
  VERSION,
  OWNER_ADDR,
  AGENT_ADDR,
  AGENT_POLICY_1,
  BASE_STATE,
  stateIdOf,
  requiredFeeForSafeTx,
  COVENANT_OUTPOINTS,
  COVENANT_FEE_HEADROOM,
  SPEND_FEE_SOMPI,
  SPEND_SUCC_STATE,
  SPEND_SUCC_STATE_ID,
  ABOVE_FEE_SOMPI,
  ABOVE_SUCC_STATE_ID,
  OWNER_OP_FEE_SOMPI,
  OWNER_OP_CHANGE,
  RECOVER_FEE_SOMPI,
  CREATE_FEE_SOMPI,
  CREATE_FUNDING,
  CREATE_CHANGE,
  SPEND_SUCC_ROOT,
  ABOVE_SUCC_ROOT,
  ADD_AGENT_SUCC_ROOT,
  NEW_AGENT_PARAM,
  vaultWithConsistentRecipients,
  slots,
  p2pk,
  spkWire,
  clone,
  safeInput,
  safeOutput,
  safeTx,
  safeJson,
  baseVault,
  baseRequest,
  spendScenario,
  aboveSpendScenario,
  topUpScenario,
  pauseScenario,
  setApproversScenario,
  addAgentScenario,
  recoverScenario,
  createScenario,
  withTamperedTx
};
