"use strict";

/*
 * Shared BRIDGE-TEST fixtures: builder-output-shaped objects that mirror
 * EXACTLY what sdk/src/vault-builders-v4.js emits (captured from real
 * builds: agentSpend outputs [payment(0), successor(1)(, change)], owner
 * ops [successor, change], the §E4 11-field accounting, callExtra = the
 * proven agent leaf + co-path). Used by derive-offline.test.js and
 * derive-pg-jsonb.test.js; the real-toolchain proof lives in
 * derive-real-builder.test.js.
 *
 * The agent-leaf co-path is a REAL single-leaf fold (a depth-0 tree: the
 * agentRoot IS the leaf hash), computed with the real
 * sdk/src/agent-merkle-v4.js — so the bridge's fold cross-check is genuine.
 * All values are synthetic test vectors (repeated-byte hex, round sompi);
 * txIds/spk bytes are placeholders whose consensus-grade counterparts come
 * from the real toolchain in derive-real-builder.test.js.
 */

const path = require("path");

const SDK = path.resolve(__dirname, "../../../../sdk");
const { agentLeafHash, foldAgentPolicyV4 } = require(path.join(SDK, "src/agent-merkle-v4"));

const HEX = (b) => b.repeat(32);
const OWNER = HEX("11");
const AGENT = HEX("22");
const RECIPIENT = HEX("33");
const COVENANT_ID = HEX("aa");
const RECIP_ROOT = HEX("dd");
const VAULT_ID = HEX("ee");
const PREV_TXID = HEX("f1");
const TXID = HEX("0a");
const NETWORK = "testnet-10";
const VERSION = "policyvault-0.4.1";
const p2pk = (x) => `20${x}ac`;
const covSpk = "aa" + "20" + HEX("bd").slice(0, 64) + "87"; // placeholder P2SH-ish

/* A depth-0 agent policy: the leaf hash IS the agentRoot; the successor
 * root is the updated leaf hash (empty co-path). */
const POLICY_BEFORE = {
  agentPk: AGENT,
  maxPerSpend: "2000000000",
  periodBudget: "5000000000",
  periodLengthDaa: "86400",
  periodStartDaa: "1000000",
  periodSpent: "500000000",
  approvalThreshold: "1500000000",
  agentMaxFeePerTx: "100000",
  agentRecipientRoot: RECIP_ROOT
};
const AGENT_ROOT_BEFORE = agentLeafHash(POLICY_BEFORE).toString("hex");
const POLICY_AFTER = { ...POLICY_BEFORE, periodSpent: "1500000000" }; // periodsElapsed 0: spent += pay(1e9)
const AGENT_ROOT_AFTER = foldAgentPolicyV4(POLICY_AFTER, "", 0n);

function frozenJson(inputs, outputs) {
  return JSON.stringify({ version: 1, inputs, outputs, lockTime: "0", subnetworkId: "00".repeat(20), gas: "0", payload: "" });
}
function covInput(amount) {
  return { previousOutpoint: { transactionId: PREV_TXID, index: 0 }, sequence: "0", computeBudget: 4000, utxo: { amount, scriptPublicKey: { version: 0, scriptHex: covSpk }, covenantId: COVENANT_ID, blockDaaScore: "0" } };
}
function extInput(amount, x) {
  return { previousOutpoint: { transactionId: HEX("f2"), index: 1 }, sequence: "0", computeBudget: 10, utxo: { amount, scriptPublicKey: { version: 0, scriptHex: p2pk(x) }, covenantId: null, blockDaaScore: "0" } };
}
function out(value, scriptHex, covenant = null) {
  return { value, scriptPublicKey: { version: 0, scriptHex }, covenant };
}

/*
 * A reserve-funded agentSpend build shaped exactly like buildV4Transaction:
 * outputs [payment(0), successor(1)], 1 covenant input, §E4 accounting,
 * callExtra = the proven leaf + empty co-path. Pay 1e9, reserveConsumed
 * 5000 (= fee), no fuel.
 */
function spendBuild() {
  const pay = 1000000000n;
  const predProtected = 50000000000n;
  const predReserve = 100000000n;
  const reserveConsumed = 5000n;
  const succProtected = predProtected - pay;
  const succReserve = predReserve - reserveConsumed;
  const succTotal = succProtected + succReserve;
  const outputs = [out(pay.toString(), p2pk(RECIPIENT)), out(succTotal.toString(), covSpk, { authorizingInput: 0, covenantId: COVENANT_ID })];
  return {
    kind: "transition",
    contractVersion: VERSION,
    networkId: NETWORK,
    action: "agentSpend",
    role: "agent",
    template: { owner: OWNER, vaultId: VAULT_ID },
    predecessorOutpoint: { transactionId: PREV_TXID, index: 0 },
    predecessorStateId: HEX("e1"),
    covenantId: COVENANT_ID,
    stateJson: { protectedValue: predProtected.toString(), feeReserve: predReserve.toString(), paused: "0", agentRoot: AGENT_ROOT_BEFORE, approverSlots: Array(10).fill(HEX("00")), approvalM: "0", policyNonce: "7" },
    successorState: { protectedValue: succProtected.toString(), feeReserve: succReserve.toString(), paused: "0", agentRoot: AGENT_ROOT_AFTER, approverSlots: Array(10).fill(HEX("00")), approvalM: "0", policyNonce: "7" },
    successorStateId: HEX("e2"),
    successorScriptSha256: HEX("ab"),
    accounting: {
      predecessorProtected: predProtected.toString(), predecessorFeeReserve: predReserve.toString(),
      payAmount: pay.toString(), reserveConsumed: reserveConsumed.toString(), externalIn: "0", externalOut: "0",
      fee: reserveConsumed.toString(), successorProtected: succProtected.toString(), successorFeeReserve: succReserve.toString(),
      successorTotal: succTotal.toString(), terminalPayout: "0"
    },
    frozen: null,
    frozenCanonicalJson: frozenJson([covInput((predProtected + predReserve).toString())], outputs),
    txId: TXID,
    aboveThreshold: false,
    callExtra: { ...POLICY_BEFORE, payAmount: pay.toString(), policySiblings: "", policyPathBits: "0", periodsElapsed: "0", recipientPk: RECIPIENT, recipientSiblings: "", recipientPathBits: "0" },
    hasFuelInput: false,
    payment: { recipient: RECIPIENT, value: pay.toString() }
  };
}

/* An owner ownerTopUp build: [successor(0), change(1)], covenant+fuel in. */
function ownerTopUpBuild() {
  const predProtected = 50000000000n, predReserve = 100000000n, topUp = 5000000000n, fee = 5000n;
  const succProtected = predProtected + topUp;
  const succTotal = succProtected + predReserve;
  const fuel = 5000010000n;
  const change = fuel - topUp - fee;
  const outputs = [out(succTotal.toString(), covSpk, { authorizingInput: 0, covenantId: COVENANT_ID }), out(change.toString(), p2pk(OWNER))];
  return {
    kind: "transition", contractVersion: VERSION, networkId: NETWORK, action: "ownerTopUp", role: "owner",
    template: { owner: OWNER, vaultId: VAULT_ID }, predecessorOutpoint: { transactionId: PREV_TXID, index: 0 }, predecessorStateId: HEX("e1"), covenantId: COVENANT_ID,
    stateJson: { protectedValue: predProtected.toString(), feeReserve: predReserve.toString(), paused: "0", agentRoot: AGENT_ROOT_BEFORE, approverSlots: Array(10).fill(HEX("00")), approvalM: "0", policyNonce: "7" },
    successorState: { protectedValue: succProtected.toString(), feeReserve: predReserve.toString(), paused: "0", agentRoot: AGENT_ROOT_BEFORE, approverSlots: Array(10).fill(HEX("00")), approvalM: "0", policyNonce: "7" },
    successorStateId: HEX("e2"), successorScriptSha256: HEX("ab"),
    accounting: { predecessorProtected: predProtected.toString(), predecessorFeeReserve: predReserve.toString(), payAmount: "0", reserveConsumed: "0", externalIn: fuel.toString(), externalOut: change.toString(), fee: fee.toString(), successorProtected: succProtected.toString(), successorFeeReserve: predReserve.toString(), successorTotal: succTotal.toString(), terminalPayout: "0" },
    frozenCanonicalJson: frozenJson([covInput((predProtected + predReserve).toString()), extInput(fuel.toString(), OWNER)], outputs),
    txId: HEX("0b"), aboveThreshold: false, callExtra: {}, hasFuelInput: true, payment: null
  };
}

module.exports = {
  HEX,
  OWNER,
  AGENT,
  RECIPIENT,
  COVENANT_ID,
  RECIP_ROOT,
  VAULT_ID,
  PREV_TXID,
  TXID,
  NETWORK,
  VERSION,
  POLICY_BEFORE,
  AGENT_ROOT_BEFORE,
  AGENT_ROOT_AFTER,
  spendBuild,
  ownerTopUpBuild
};
