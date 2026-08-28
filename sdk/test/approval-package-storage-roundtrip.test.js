"use strict";

/*
 * UNIT/ADVERSARIAL — approval-package commitment vs storage representation
 * (Phase G defect G-2 regression, versions v0.3 AND v0.4).
 *
 * PostgreSQL jsonb re-orders object keys (length, then bytewise) while
 * preserving every value. The package commitment must be a function of the
 * VALUES only: a jsonb-shaped key re-ordering of a frozen package MUST
 * recompute to the SAME commitment (pre-fix behavior: it did not — the
 * real Phase G hosted approval finalize failed PACKAGE_MUTATED with every
 * value provably intact), while ANY value mutation MUST still change it
 * (the guard is not weakened).
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");

const { packageCommitmentV4 } = require("../src/approval-package-v4");
const { packageCommitmentV3 } = require("../src/approval-package-v3");

/* Faithful model of PostgreSQL jsonb object-key ordering: shorter keys
 * first, equal lengths bytewise. Applied recursively; arrays keep order. */
function jsonbReorder(value) {
  if (Array.isArray(value)) return value.map(jsonbReorder);
  if (value && typeof value === "object") {
    const keys = Object.keys(value).sort((a, b) => (a.length - b.length) || (a < b ? -1 : a > b ? 1 : 0));
    const out = {};
    for (const k of keys) out[k] = jsonbReorder(value[k]);
    return out;
  }
  return value;
}

/* A fully-shaped v0.4 package (values synthetic; the commitment is a pure
 * function over fields — validity of the tx itself is asserted elsewhere).
 * Field insertion order here deliberately mimics the BUILDER's order. */
function syntheticV4() {
  return {
    schema: "policyvault-approval-package/v4",
    contractVersion: "policyvault-0.4",
    networkId: "testnet-10",
    vaultId: "cf".repeat(32),
    action: "agentSpend",
    predecessorOutpoint: { transactionId: "20".repeat(32), index: 0 },
    predecessorStateId: "85".repeat(32),
    successorStateId: "21".repeat(32),
    policyNonce: "0",
    txId: "42".repeat(32),
    covenantInputIndex: 0,
    covenantSighash: "57".repeat(32),
    frozenTransaction: {
      version: 0,
      inputs: [{ previousOutpoint: { transactionId: "20".repeat(32), index: 0 }, signatureScript: "", sequence: "0", sigOpCount: 1 }],
      outputs: [{ value: "150000000", scriptPublicKey: { version: 0, scriptHex: "20" + "12".repeat(32) + "ac" } }],
      lockTime: "0",
      subnetworkId: "00".repeat(20),
      gas: "0",
      payload: ""
    },
    agentPolicy: {
      agentPk: "4a".repeat(32),
      maxPerSpend: "200000000",
      periodBudget: "1000000000",
      periodLengthDaa: "864000",
      periodStartDaa: "552739801",
      periodSpent: "50000000",
      approvalThreshold: "100000000",
      agentMaxFeePerTx: "10000000",
      agentRecipientRoot: "7c".repeat(32)
    },
    agentProof: { root: "c0".repeat(32), siblingsHex: "ab".repeat(32), pathBits: "0" },
    successorAgentRoot: "26".repeat(32),
    periodsElapsed: "0",
    recipient: "12".repeat(32),
    payAmountSompi: "150000000",
    recipientProof: { root: "7c".repeat(32), siblingsHex: "", pathBits: "0" },
    reserveConsumedSompi: "3708400",
    approvalM: "1",
    approverSlots: ["e9".repeat(32)].concat(Array(9).fill("00".repeat(32))),
    computeBudget: 134,
    requiredFeeSompi: "3708400",
    approvals: [null, null, null, null, null, null, null, null, null, null],
    createdAt: "2026-08-25T05:00:00.000Z"
  };
}

function syntheticV3() {
  return {
    schema: "policyvault-approval-package/v3",
    contractVersion: "policyvault-0.3",
    networkId: "testnet-10",
    vaultId: "ab".repeat(32),
    action: "delegateSpend",
    predecessorOutpoint: { transactionId: "30".repeat(32), index: 0 },
    predecessorStateId: "31".repeat(32),
    successorStateId: "32".repeat(32),
    policyNonce: "7",
    txId: "33".repeat(32),
    covenantInputIndex: 0,
    covenantSighash: "34".repeat(32),
    frozenTransaction: {
      version: 0,
      inputs: [{ previousOutpoint: { transactionId: "30".repeat(32), index: 0 }, signatureScript: "", sequence: "0", sigOpCount: 1 }],
      outputs: [{ value: "600000000", scriptPublicKey: { version: 0, scriptHex: "20" + "35".repeat(32) + "ac" } }],
      lockTime: "0",
      subnetworkId: "00".repeat(20),
      gas: "0",
      payload: ""
    },
    recipient: "35".repeat(32),
    payAmountSompi: "600000000",
    recipientProof: { root: "36".repeat(32), siblingsHex: "", pathBits: "0" },
    approvalThresholdAmount: "500000000",
    approvalM: "2",
    approverSlots: ["37".repeat(32), "38".repeat(32)].concat(Array(8).fill("00".repeat(32))),
    computeBudget: 120,
    requiredFeeSompi: "2000000",
    approvals: [null, null, null, null, null, null, null, null, null, null],
    createdAt: "2026-08-25T05:00:00.000Z"
  };
}

test("v4 commitment is IDENTICAL across a jsonb-shaped key re-ordering (values intact)", () => {
  const pkg = syntheticV4();
  const original = packageCommitmentV4(pkg);
  const roundTripped = jsonbReorder(pkg);
  assert.notDeepEqual(Object.keys(roundTripped.frozenTransaction), Object.keys(pkg.frozenTransaction),
    "the transform must actually change key order for this regression to mean anything");
  assert.equal(packageCommitmentV4(roundTripped), original,
    "a storage-representation change with every value intact must NOT change the commitment (G-2)");
});

test("v4 commitment STILL changes on any value mutation (guard not weakened)", () => {
  const pkg = syntheticV4();
  const original = packageCommitmentV4(pkg);
  const mutations = [
    (p) => { p.payAmountSompi = "150000001"; },
    (p) => { p.frozenTransaction.outputs[0].value = "150000001"; },
    (p) => { p.recipient = "13".repeat(32); },
    (p) => { p.approverSlots[0] = "ea".repeat(32); },
    (p) => { p.txId = "43".repeat(32); },
    (p) => { p.agentPolicy.maxPerSpend = "200000001"; },
    (p) => { p.successorAgentRoot = "27".repeat(32); },
    (p) => { p.reserveConsumedSompi = "3708401"; }
  ];
  for (const [i, mutate] of mutations.entries()) {
    const copy = JSON.parse(JSON.stringify(pkg));
    mutate(copy);
    assert.notEqual(packageCommitmentV4(copy), original, `mutation ${i} must change the commitment`);
  }
});

test("v3 commitment is IDENTICAL across a jsonb-shaped key re-ordering, and still binds values", () => {
  const pkg = syntheticV3();
  const original = packageCommitmentV3(pkg);
  assert.equal(packageCommitmentV3(jsonbReorder(pkg)), original,
    "v0.3 has the same storage-representation independence requirement (same defect class)");
  const mutated = JSON.parse(JSON.stringify(pkg));
  mutated.approvalM = "1";
  assert.notEqual(packageCommitmentV3(mutated), original, "value mutation must change the v3 commitment");
});
