"use strict";

/*
 * Shared-core extraction step 3 — golden battery over the INTERFACE-SPLIT
 * modules: frozen-tx-v3, approval-package-v3, approval-package-v4.
 *
 * Unlike steps 1/2 (verbatim whole-module moves), step 3 splits each
 * module into a pure core (core/model/) and an impure sdk shell
 * (probe/WASM/Date members). API identity therefore cannot be proven by
 * whole-module object identity; it is proven MEMBER-BY-MEMBER:
 *
 *   - computeGolden3Pure(mods)   — every PURE exported member's outputs
 *     (incl. the exact commitment bytes) over representative inputs.
 *     Post-split this battery must reproduce the pre-split fixture
 *     byte-for-byte through BOTH require roots (core/model directly and
 *     sdk/src through the composition modules).
 *   - computeGolden3Impure(mods) — the deterministic outputs and
 *     fail-closed error surfaces of every IMPURE exported member
 *     (pv_tx_probe-backed txId/sighash/verification, package creation,
 *     integrity gates, blob emission, JSON round-trip). Runs only against
 *     the sdk modules (the impure shell); requires the built pv_tx_probe.
 *   - captureApiSurface(mods)    — exported key + typeof sets of the three
 *     sdk modules (must be UNCHANGED by the split).
 *
 * Everything here is deterministic: fixed inputs, fixed field orders,
 * BigInt-free capture values (digit strings), createdAt normalized via a
 * fixed timestamp override on the created package (the commitment
 * explicitly excludes createdAt, so overriding it keeps integrity).
 * No environment paths are captured (TX_PROBE_PATH is captured as a
 * repo-relative suffix check only).
 */

const HEX = (byte, len = 32) => byte.repeat(len);

/* ---------------------------------------------------------------- */
/* deterministic input material                                     */
/* ---------------------------------------------------------------- */

const RECIPIENT = HEX("aa");
const RECIPIENT2 = HEX("ab");
const RECIPIENT3 = HEX("ac");
const AGENT_PK = HEX("b1");
const AGENT_PK2 = HEX("b2");
const APPROVER1 = HEX("c1");
const APPROVER2 = HEX("c2");
const APPROVER3 = HEX("c3");
const SENTINEL = HEX("00");
const VAULT_ID = HEX("d1");
const COVENANT_ID = HEX("22");
const PRED_TXID = HEX("11");
const FUEL_TXID = HEX("33");

const FIXED_CREATED_AT = "2026-01-01T00:00:00.000Z";
const FAKE_SIG_1 = HEX("cd", 64) + "01";
const FAKE_SIG_2 = HEX("ef", 64) + "01";

function p2pk(xOnly) {
  return `20${xOnly}ac`;
}

/* v3 frozen transaction: covenant input + fuel input; pay + successor +
 * change outputs; fee = 100000 sompi. */
function frozenV3Input() {
  return {
    version: 1,
    inputs: [
      {
        previousOutpoint: { transactionId: PRED_TXID, index: 0 },
        sequence: "0",
        computeBudget: 1200,
        utxo: {
          amount: "50000000000",
          scriptPublicKey: { version: 0, scriptHex: "51" },
          covenantId: COVENANT_ID,
          blockDaaScore: "1000"
        }
      },
      {
        previousOutpoint: { transactionId: FUEL_TXID, index: 1 },
        sequence: "0",
        computeBudget: 0,
        utxo: {
          amount: "100000000",
          scriptPublicKey: { version: 0, scriptHex: p2pk(HEX("fe")) },
          covenantId: null,
          blockDaaScore: "999"
        }
      }
    ],
    outputs: [
      { value: "30000000000", scriptPublicKey: { version: 0, scriptHex: p2pk(RECIPIENT) }, covenant: null },
      {
        value: "20000000000",
        scriptPublicKey: { version: 0, scriptHex: "52" },
        covenant: { authorizingInput: 0, covenantId: COVENANT_ID }
      },
      { value: "99900000", scriptPublicKey: { version: 0, scriptHex: p2pk(HEX("fe")) }, covenant: null }
    ],
    lockTime: "0",
    subnetworkId: "00".repeat(20),
    gas: "0",
    payload: ""
  };
}

/* v4 frozen transaction: covenant input carries protected 40000000000 +
 * reserve 200000; consumed 1000; fee = 101000. */
function frozenV4Input() {
  return {
    version: 1,
    inputs: [
      {
        previousOutpoint: { transactionId: PRED_TXID, index: 0 },
        sequence: "0",
        computeBudget: 2500,
        utxo: {
          amount: "40000200000",
          scriptPublicKey: { version: 0, scriptHex: "53" },
          covenantId: COVENANT_ID,
          blockDaaScore: "2000"
        }
      },
      {
        previousOutpoint: { transactionId: FUEL_TXID, index: 2 },
        sequence: "0",
        computeBudget: 0,
        utxo: {
          amount: "100000000",
          scriptPublicKey: { version: 0, scriptHex: p2pk(HEX("fd")) },
          covenantId: null,
          blockDaaScore: "1999"
        }
      }
    ],
    outputs: [
      { value: "5000000000", scriptPublicKey: { version: 0, scriptHex: p2pk(RECIPIENT) }, covenant: null },
      {
        value: "35000199000",
        scriptPublicKey: { version: 0, scriptHex: "54" },
        covenant: { authorizingInput: 0, covenantId: COVENANT_ID }
      },
      { value: "99900000", scriptPublicKey: { version: 0, scriptHex: p2pk(HEX("fd")) }, covenant: null }
    ],
    lockTime: "0",
    subnetworkId: "00".repeat(20),
    gas: "0",
    payload: ""
  };
}

/* Denormalized variant: uppercase hex + numeric fields as numbers +
 * omitted defaults — must normalize to the same canonical form. */
function frozenV3Denormalized() {
  return {
    version: 1,
    inputs: [
      {
        previousOutpoint: { transactionId: PRED_TXID.toUpperCase(), index: 0 },
        computeBudget: 1200,
        utxo: {
          amount: 50000000000n,
          scriptPublicKey: { version: 0, scriptHex: "51" },
          covenantId: COVENANT_ID.toUpperCase(),
          blockDaaScore: 1000n
        }
      },
      {
        previousOutpoint: { transactionId: FUEL_TXID, index: 1 },
        sequence: 0n,
        computeBudget: 0,
        utxo: {
          amount: 100000000n,
          scriptPublicKey: { version: 0, scriptHex: p2pk(HEX("fe")).toUpperCase() },
          covenantId: null,
          blockDaaScore: "999"
        }
      }
    ],
    outputs: [
      { value: 30000000000n, scriptPublicKey: { version: 0, scriptHex: p2pk(RECIPIENT) } },
      {
        value: "20000000000",
        scriptPublicKey: { version: 0, scriptHex: "52" },
        covenant: { authorizingInput: 0, covenantId: COVENANT_ID }
      },
      { value: "99900000", scriptPublicKey: { version: 0, scriptHex: p2pk(HEX("fe")) } }
    ]
  };
}

/* Synthetic v3 package for the PURE commitment battery: a full plain
 * object carrying every preimage field (cross-field consistency is not
 * required by packageCommitmentV3 — it hashes stated values). */
function syntheticPackageV3() {
  return {
    schema: "policyvault-approval-package/v1",
    contractVersion: "policyvault-0.3",
    networkId: "kaspa-testnet-10",
    vaultId: VAULT_ID,
    action: "delegateSpend",
    predecessorOutpoint: { transactionId: PRED_TXID, index: 0 },
    predecessorStateId: "state-pred-1",
    successorStateId: "state-succ-1",
    policyNonce: "7",
    txId: HEX("e1"),
    covenantInputIndex: 0,
    covenantSighash: HEX("e2"),
    frozenTransaction: { version: 1, note: "synthetic-frozen-doc" },
    recipient: RECIPIENT,
    payAmountSompi: "30000000000",
    recipientProof: { root: HEX("e3"), siblingsHex: HEX("e4"), pathBits: "0" },
    approvalThresholdAmount: "10000000000",
    approvalM: "2",
    approverSlots: [APPROVER1, APPROVER2, APPROVER3, SENTINEL, SENTINEL, SENTINEL, SENTINEL, SENTINEL, SENTINEL, SENTINEL],
    computeBudget: 1200,
    requiredFeeSompi: "100000",
    createdAt: FIXED_CREATED_AT,
    approvals: [null, null, null, null, null, null, null, null, null, null],
    commitment: "ignored-by-commitment"
  };
}

/* Synthetic v4 package for the PURE commitment battery. */
function syntheticPackageV4() {
  return {
    schema: "policyvault-approval-package/v4",
    contractVersion: "policyvault-0.4",
    networkId: "kaspa-testnet-10",
    vaultId: VAULT_ID,
    action: "agentSpend",
    predecessorOutpoint: { transactionId: PRED_TXID, index: 0 },
    predecessorStateId: "state-pred-4",
    successorStateId: "state-succ-4",
    policyNonce: "9",
    txId: HEX("e5"),
    covenantInputIndex: 0,
    covenantSighash: HEX("e6"),
    frozenTransaction: { version: 1, note: "synthetic-frozen-doc-v4" },
    agentPolicy: {
      agentPk: AGENT_PK,
      maxPerSpend: "10000000000",
      periodBudget: "20000000000",
      periodLengthDaa: "1000",
      periodStartDaa: "5000",
      periodSpent: "100000",
      approvalThreshold: "1000000000",
      agentMaxFeePerTx: "5000",
      agentRecipientRoot: HEX("e7")
    },
    agentProof: { root: HEX("e8"), siblingsHex: HEX("e9"), pathBits: "0" },
    successorAgentRoot: HEX("ea"),
    periodsElapsed: "0",
    recipient: RECIPIENT,
    payAmountSompi: "5000000000",
    recipientProof: { root: HEX("e7"), siblingsHex: HEX("eb"), pathBits: "1" },
    reserveConsumedSompi: "1000",
    approvalM: "1",
    approverSlots: [APPROVER1, APPROVER2, SENTINEL, SENTINEL, SENTINEL, SENTINEL, SENTINEL, SENTINEL, SENTINEL, SENTINEL],
    computeBudget: 2500,
    requiredFeeSompi: "101000",
    createdAt: FIXED_CREATED_AT,
    approvals: [null, null, null, null, null, null, null, null, null, null],
    commitment: "ignored-by-commitment"
  };
}

/* Deep clone with object keys REVERSED at every level — commitments must
 * be key-order-independent (the G-2 rule). */
function reorderKeys(value) {
  if (Array.isArray(value)) return value.map(reorderKeys);
  if (value && typeof value === "object") {
    const out = {};
    for (const key of Object.keys(value).reverse()) {
      out[key] = reorderKeys(value[key]);
    }
    return out;
  }
  return value;
}

function captureError(fn) {
  try {
    const value = fn();
    return { threw: false, value: typeof value === "string" ? value : "(non-string result)" };
  } catch (error) {
    return { threw: true, message: error.message, code: error.code ?? null };
  }
}

/* ---------------------------------------------------------------- */
/* PURE battery — must reproduce through BOTH require roots          */
/* ---------------------------------------------------------------- */

function computeGolden3Pure({ frozenTx, apV3, apV4 }) {
  const out = {};

  /* ---- frozen-tx-v3 pure members ---- */
  const f1 = frozenTx.normalizeFrozenTxV3(frozenV3Input());
  const f2 = frozenTx.normalizeFrozenTxV3(frozenV4Input());
  const f1canon = frozenTx.canonicalFrozenTxJson(f1);
  out.frozenTx = {
    canonicalJsonV3: f1canon,
    canonicalJsonV4: frozenTx.canonicalFrozenTxJson(f2),
    commitmentV3: frozenTx.frozenTxCommitment(f1),
    commitmentV4: frozenTx.frozenTxCommitment(f2),
    denormalizedMatchesCanonical:
      frozenTx.canonicalFrozenTxJson(frozenTx.normalizeFrozenTxV3(frozenV3Denormalized())) === f1canon,
    roundTripStable:
      frozenTx.canonicalFrozenTxJson(frozenTx.normalizeFrozenTxV3(JSON.parse(f1canon))) === f1canon,
    feeDescriptor: frozenTx.feeDescriptorFromFrozen(f1, [66, 0]),
    feeDescriptorEmptySigs: frozenTx.feeDescriptorFromFrozen(f2, [0, 0]),
    rejects: {}
  };

  const rejectVectors = {
    notObject: () => frozenTx.normalizeFrozenTxV3(null),
    badVersion: () => frozenTx.normalizeFrozenTxV3({ ...frozenV3Input(), version: 2 }),
    noInputs: () => frozenTx.normalizeFrozenTxV3({ ...frozenV3Input(), inputs: [] }),
    noOutputs: () => frozenTx.normalizeFrozenTxV3({ ...frozenV3Input(), outputs: [] }),
    signatureScriptPresent: () => {
      const doc = frozenV3Input();
      doc.inputs[0].signatureScript = "ff";
      return frozenTx.normalizeFrozenTxV3(doc);
    },
    missingOutpoint: () => {
      const doc = frozenV3Input();
      delete doc.inputs[0].previousOutpoint;
      return frozenTx.normalizeFrozenTxV3(doc);
    },
    outpointIndexNegative: () => {
      const doc = frozenV3Input();
      doc.inputs[0].previousOutpoint.index = -1;
      return frozenTx.normalizeFrozenTxV3(doc);
    },
    outpointIndexOverflow: () => {
      const doc = frozenV3Input();
      doc.inputs[0].previousOutpoint.index = 0x100000000;
      return frozenTx.normalizeFrozenTxV3(doc);
    },
    budgetNegative: () => {
      const doc = frozenV3Input();
      doc.inputs[0].computeBudget = -1;
      return frozenTx.normalizeFrozenTxV3(doc);
    },
    budgetOverflow: () => {
      const doc = frozenV3Input();
      doc.inputs[0].computeBudget = 0x10000;
      return frozenTx.normalizeFrozenTxV3(doc);
    },
    missingUtxo: () => {
      const doc = frozenV3Input();
      delete doc.inputs[0].utxo;
      return frozenTx.normalizeFrozenTxV3(doc);
    },
    oddSpkHex: () => {
      const doc = frozenV3Input();
      doc.outputs[0].scriptPublicKey = { version: 0, scriptHex: "abc" };
      return frozenTx.normalizeFrozenTxV3(doc);
    },
    spkVersionRange: () => {
      const doc = frozenV3Input();
      doc.outputs[0].scriptPublicKey = { version: -1, scriptHex: "51" };
      return frozenTx.normalizeFrozenTxV3(doc);
    },
    covenantAuthorizingRange: () => {
      const doc = frozenV3Input();
      doc.outputs[1].covenant.authorizingInput = 0x10000;
      return frozenTx.normalizeFrozenTxV3(doc);
    },
    badCovenantId: () => {
      const doc = frozenV3Input();
      doc.outputs[1].covenant.covenantId = "zz";
      return frozenTx.normalizeFrozenTxV3(doc);
    },
    wrongSubnetwork: () => frozenTx.normalizeFrozenTxV3({ ...frozenV3Input(), subnetworkId: "01".repeat(20) }),
    gasNonzero: () => frozenTx.normalizeFrozenTxV3({ ...frozenV3Input(), gas: "5" }),
    payloadNonempty: () => frozenTx.normalizeFrozenTxV3({ ...frozenV3Input(), payload: "aabb" }),
    negativeAmount: () => {
      const doc = frozenV3Input();
      doc.inputs[0].utxo.amount = "-1";
      return frozenTx.normalizeFrozenTxV3(doc);
    },
    floatAmount: () => {
      const doc = frozenV3Input();
      doc.outputs[0].value = "1.5";
      return frozenTx.normalizeFrozenTxV3(doc);
    },
    feeDescriptorWrongLength: () => frozenTx.feeDescriptorFromFrozen(f1, [66]),
    feeDescriptorNegativeLen: () => frozenTx.feeDescriptorFromFrozen(f1, [66, -1]),
    feeDescriptorNonInteger: () => frozenTx.feeDescriptorFromFrozen(f1, [66, 1.5])
  };
  for (const [name, fn] of Object.entries(rejectVectors)) {
    out.frozenTx.rejects[name] = captureError(fn);
  }

  /* ---- approval-package-v3 pure members ---- */
  const sp3 = syntheticPackageV3();
  const sp3Mutated = { ...syntheticPackageV3(), payAmountSompi: "30000000001" };
  out.apV3 = {
    schema: apV3.APPROVAL_PACKAGE_SCHEMA,
    placeholderApproval: apV3.PLACEHOLDER_APPROVAL,
    p2pkScript: apV3.p2pkScriptHex(RECIPIENT),
    placeholderBlob: apV3.placeholderApprovalsBlob(),
    syntheticCommitment: apV3.packageCommitmentV3(sp3),
    syntheticCommitmentMutated: apV3.packageCommitmentV3(sp3Mutated),
    commitmentKeyOrderIndependent: apV3.packageCommitmentV3(reorderKeys(syntheticPackageV3())) === apV3.packageCommitmentV3(sp3),
    commitmentIgnoresCreatedAtAndApprovals:
      apV3.packageCommitmentV3({ ...syntheticPackageV3(), createdAt: "1999-01-01T00:00:00.000Z", approvals: [FAKE_SIG_1, null, null, null, null, null, null, null, null, null], commitment: "x" }) ===
      apV3.packageCommitmentV3(sp3),
    collected: {
      empty: apV3.collectedCount(sp3),
      one: apV3.collectedCount({ ...sp3, approvals: [FAKE_SIG_1, null, null, null, null, null, null, null, null, null] }),
      two: apV3.collectedCount({ ...sp3, approvals: [FAKE_SIG_1, null, FAKE_SIG_2, null, null, null, null, null, null, null] })
    },
    missing: {
      empty: apV3.missingSlots(sp3),
      afterOne: apV3.missingSlots({ ...sp3, approvals: [FAKE_SIG_1, null, null, null, null, null, null, null, null, null] })
    },
    complete: {
      empty: apV3.isCompleteV3(sp3),
      one: apV3.isCompleteV3({ ...sp3, approvals: [FAKE_SIG_1, null, null, null, null, null, null, null, null, null] }),
      two: apV3.isCompleteV3({ ...sp3, approvals: [FAKE_SIG_1, null, FAKE_SIG_2, null, null, null, null, null, null, null] })
    }
  };

  /* ---- approval-package-v4 pure members ---- */
  const sp4 = syntheticPackageV4();
  const sp4Mutated = { ...syntheticPackageV4(), reserveConsumedSompi: "1001" };
  out.apV4 = {
    schema: apV4.APPROVAL_PACKAGE_SCHEMA_V4,
    placeholderApproval: apV4.PLACEHOLDER_APPROVAL,
    p2pkScript: apV4.p2pkScriptHex(RECIPIENT2),
    placeholderBlob: apV4.placeholderApprovalsBlob(),
    syntheticCommitment: apV4.packageCommitmentV4(sp4),
    syntheticCommitmentMutated: apV4.packageCommitmentV4(sp4Mutated),
    commitmentKeyOrderIndependent: apV4.packageCommitmentV4(reorderKeys(syntheticPackageV4())) === apV4.packageCommitmentV4(sp4),
    commitmentIgnoresCreatedAtAndApprovals:
      apV4.packageCommitmentV4({ ...syntheticPackageV4(), createdAt: "1999-01-01T00:00:00.000Z", approvals: [FAKE_SIG_1, null, null, null, null, null, null, null, null, null], commitment: "x" }) ===
      apV4.packageCommitmentV4(sp4),
    collected: {
      empty: apV4.collectedCountV4(sp4),
      one: apV4.collectedCountV4({ ...sp4, approvals: [FAKE_SIG_1, null, null, null, null, null, null, null, null, null] })
    },
    missing: {
      empty: apV4.missingSlotsV4(sp4),
      afterOne: apV4.missingSlotsV4({ ...sp4, approvals: [FAKE_SIG_1, null, null, null, null, null, null, null, null, null] })
    },
    complete: {
      empty: apV4.isCompleteV4(sp4),
      one: apV4.isCompleteV4({ ...sp4, approvals: [FAKE_SIG_1, null, null, null, null, null, null, null, null, null] })
    }
  };

  return out;
}

/* ---------------------------------------------------------------- */
/* representative REAL package construction (impure: probe-backed)   */
/* ---------------------------------------------------------------- */

function buildRealPackageV3({ apV3, recipientMerkle }) {
  const tree = recipientMerkle.buildRecipientTree([RECIPIENT, RECIPIENT2, RECIPIENT3]);
  const proof = recipientMerkle.generateRecipientProof(tree, RECIPIENT);
  return {
    args: {
      networkId: "kaspa-testnet-10",
      vaultId: VAULT_ID,
      action: "delegateSpend",
      predecessorOutpoint: { transactionId: PRED_TXID, index: 0 },
      predecessorStateId: "state-pred-1",
      successorStateId: "state-succ-1",
      policyNonce: "7",
      frozenTransaction: frozenV3Input(),
      covenantInputIndex: 0,
      recipient: RECIPIENT,
      payAmountSompi: "30000000000",
      recipientProof: { root: proof.root, siblingsHex: proof.siblingsHex, pathBits: proof.pathBits.toString() },
      approvalThresholdAmount: "10000000000",
      approvalM: "2",
      approverSlots: [APPROVER1, APPROVER2, APPROVER3, SENTINEL, SENTINEL, SENTINEL, SENTINEL, SENTINEL, SENTINEL, SENTINEL],
      requiredFeeSompi: "100000"
    },
    create(overrides = {}) {
      return apV3.createApprovalPackageV3({ ...this.args, ...overrides });
    }
  };
}

function buildRealPackageV4({ apV4, recipientMerkle, agentMerkle }) {
  const recipientTree = recipientMerkle.buildRecipientTree([RECIPIENT, RECIPIENT2]);
  const rProof = recipientMerkle.generateRecipientProof(recipientTree, RECIPIENT);
  const policy = {
    agentPk: AGENT_PK,
    maxPerSpend: "10000000000",
    periodBudget: "20000000000",
    periodLengthDaa: "1000",
    periodStartDaa: "5000",
    periodSpent: "100000",
    approvalThreshold: "1000000000",
    agentMaxFeePerTx: "5000",
    agentRecipientRoot: recipientTree.root
  };
  const policy2 = { ...policy, agentPk: AGENT_PK2 };
  const agentTree = agentMerkle.buildAgentTreeV4([policy, policy2]);
  const aProof = agentMerkle.generateAgentProofV4(agentTree, AGENT_PK);
  const newPolicy = { ...policy, periodSpent: (100000n + 5000000000n).toString() };
  const successorAgentRoot = agentMerkle.foldAgentPolicyV4(newPolicy, aProof.siblingsHex, aProof.pathBits);
  return {
    args: {
      networkId: "kaspa-testnet-10",
      vaultId: VAULT_ID,
      predecessorOutpoint: { transactionId: PRED_TXID, index: 0 },
      predecessorStateId: "state-pred-4",
      successorStateId: "state-succ-4",
      policyNonce: "9",
      predecessorProtectedSompi: "40000000000",
      predecessorFeeReserveSompi: "200000",
      frozenTransaction: frozenV4Input(),
      covenantInputIndex: 0,
      agentPolicy: policy,
      agentProof: { root: aProof.root, siblingsHex: aProof.siblingsHex, pathBits: aProof.pathBits.toString() },
      successorAgentRoot,
      periodsElapsed: "0",
      recipient: RECIPIENT,
      payAmountSompi: "5000000000",
      recipientProof: { root: rProof.root, siblingsHex: rProof.siblingsHex, pathBits: rProof.pathBits.toString() },
      reserveConsumedSompi: "1000",
      approvalM: "1",
      approverSlots: [APPROVER1, APPROVER2, SENTINEL, SENTINEL, SENTINEL, SENTINEL, SENTINEL, SENTINEL, SENTINEL, SENTINEL],
      requiredFeeSompi: "101000"
    },
    policy,
    aProof,
    create(overrides = {}) {
      return apV4.createApprovalPackageV4({ ...this.args, ...overrides });
    }
  };
}

function withoutCreatedAt(pkg) {
  const { createdAt, ...rest } = pkg;
  return rest;
}

/* ---------------------------------------------------------------- */
/* IMPURE battery — sdk modules only (probe-backed, deterministic)   */
/* ---------------------------------------------------------------- */

function computeGolden3Impure({ frozenTx, apV3, apV4, recipientMerkle, agentMerkle }) {
  const path = require("path");
  const out = {};

  const f1 = frozenTx.normalizeFrozenTxV3(frozenV3Input());
  const f2 = frozenTx.normalizeFrozenTxV3(frozenV4Input());

  /* ---- frozen-tx-v3 impure members ---- */
  const d1 = frozenTx.describeFrozenTx(f1);
  const d2 = frozenTx.describeFrozenTx(f2);
  out.frozenTx = {
    probePathSuffixOk: frozenTx.TX_PROBE_PATH.endsWith(path.join("tests", "vm", "target", "debug", "pv_tx_probe")),
    describeV3: { txId: d1.txId, sighashAll: [...d1.sighashAll] },
    describeV4: { txId: d2.txId, sighashAll: [...d2.sighashAll] },
    verify: {
      indexOutOfRange: captureError(() => frozenTx.verifyApprovalSignature(f1, 9, FAKE_SIG_1, APPROVER1)),
      badKey: captureError(() => frozenTx.verifyApprovalSignature(f1, 0, FAKE_SIG_1, "zz")),
      nonHexSignature: frozenTx.verifyApprovalSignature(f1, 0, "not-hex", APPROVER1),
      oddHexSignature: frozenTx.verifyApprovalSignature(f1, 0, "abc", APPROVER1),
      cryptographicallyInvalid: frozenTx.verifyApprovalSignature(f1, 0, FAKE_SIG_1, APPROVER1)
    }
  };

  /* ---- approval-package-v3 impure members ---- */
  const real3 = buildRealPackageV3({ apV3, recipientMerkle });
  const created3 = real3.create();
  const pkg3 = { ...created3, createdAt: FIXED_CREATED_AT };
  const integral3 = apV3.assertPackageIntegrity(pkg3);
  const complete3 = {
    ...pkg3,
    approvals: pkg3.approvals.map((entry, i) => (i === 0 ? FAKE_SIG_1 : i === 2 ? FAKE_SIG_2 : entry))
  };
  const json3 = apV3.approvalPackageToJson(pkg3);
  out.apV3 = {
    createdPackage: withoutCreatedAt(created3),
    createdAtIsNonSecurity: apV3.packageCommitmentV3(pkg3) === created3.commitment,
    integrityReturnsFrozen: frozenTx.canonicalFrozenTxJson(integral3),
    toJson: json3,
    loadRoundTrip: withoutCreatedAt(apV3.loadApprovalPackage(json3)),
    completeBlob: apV3.approvalsBlobV3(complete3),
    createRejects: {},
    integrityRejects: {
      unknownSchema: captureError(() => apV3.assertPackageIntegrity({ ...pkg3, schema: "policyvault-approval-package/v9" })),
      unknownContractVersion: captureError(() => apV3.assertPackageIntegrity({ ...pkg3, contractVersion: "policyvault-9.9" })),
      mutatedField: captureError(() => apV3.assertPackageIntegrity({ ...pkg3, payAmountSompi: "30000000001" })),
      mutatedFrozenBody: captureError(() => {
        /* attacker mutates the frozen body AND recomputes the commitment:
         * branch 2 (real-consensus txId re-derivation) must still catch it */
        const frozenDoc = JSON.parse(JSON.stringify(pkg3.frozenTransaction));
        frozenDoc.lockTime = "1";
        const tampered = { ...pkg3, frozenTransaction: frozenDoc };
        tampered.commitment = apV3.packageCommitmentV3(tampered);
        return apV3.assertPackageIntegrity(tampered);
      })
    },
    submitRejects: {
      unknownApprover: captureError(() => apV3.submitApprovalV3(pkg3, { signatureHex: FAKE_SIG_1, approverXOnly: HEX("dd") })),
      sentinelSigner: captureError(() => apV3.submitApprovalV3(pkg3, { signatureHex: FAKE_SIG_1, approverXOnly: SENTINEL })),
      wrongSlot: captureError(() => apV3.submitApprovalV3(pkg3, { signatureHex: FAKE_SIG_1, approverXOnly: APPROVER1, slotIndex: 1 })),
      duplicateSlot: captureError(() =>
        apV3.submitApprovalV3(
          { ...pkg3, approvals: pkg3.approvals.map((entry, i) => (i === 0 ? FAKE_SIG_1 : entry)) },
          { signatureHex: FAKE_SIG_2, approverXOnly: APPROVER1 }
        )
      ),
      badHex: captureError(() => apV3.submitApprovalV3(pkg3, { signatureHex: "XYZ", approverXOnly: APPROVER1 })),
      wrongLength: captureError(() => apV3.submitApprovalV3(pkg3, { signatureHex: "aabb", approverXOnly: APPROVER1 })),
      wrongSighashByte: captureError(() =>
        apV3.submitApprovalV3(pkg3, { signatureHex: HEX("cd", 64) + "02", approverXOnly: APPROVER1 })
      ),
      placeholderSignature: captureError(() =>
        apV3.submitApprovalV3(pkg3, { signatureHex: apV3.PLACEHOLDER_APPROVAL, approverXOnly: APPROVER1 })
      ),
      schnorrInvalid: captureError(() => apV3.submitApprovalV3(pkg3, { signatureHex: FAKE_SIG_1, approverXOnly: APPROVER1 }))
    },
    blobRejects: {
      insufficient: captureError(() => apV3.approvalsBlobV3(pkg3))
    },
    loadRejects: {
      invalidJson: captureError(() => apV3.loadApprovalPackage("{not json")),
      tamperedJson: captureError(() => apV3.loadApprovalPackage(JSON.stringify({ ...pkg3, requiredFeeSompi: "999" }))),
      malformedApprovals: captureError(() => {
        const doc = JSON.parse(json3);
        doc.approvals = [null];
        return apV3.loadApprovalPackage(JSON.stringify(doc));
      })
    }
  };
  const v3CreateRejects = {
    missingNetworkId: () => real3.create({ networkId: "" }),
    badAction: () => real3.create({ action: "spend" }),
    covenantIndexRange: () => real3.create({ covenantInputIndex: 5 }),
    outpointMismatch: () => real3.create({ predecessorOutpoint: { transactionId: FUEL_TXID, index: 0 } }),
    notAboveThreshold: () => real3.create({ approvalThresholdAmount: "30000000000" }),
    output0NotP2pkRecipient: () => real3.create({ recipient: RECIPIENT2 }),
    missingProof: () => real3.create({ recipientProof: null }),
    proofDoesNotVerify: () => real3.create({ recipientProof: { ...real3.args.recipientProof, root: HEX("77") } }),
    slotsWrongLength: () => real3.create({ approverSlots: [APPROVER1] }),
    duplicateApprover: () =>
      real3.create({ approverSlots: [APPROVER1, APPROVER1, APPROVER3, SENTINEL, SENTINEL, SENTINEL, SENTINEL, SENTINEL, SENTINEL, SENTINEL] }),
    approvalMZero: () => real3.create({ approvalM: "0" }),
    approvalMTooHigh: () => real3.create({ approvalM: "4" }),
    feeMismatch: () => real3.create({ requiredFeeSompi: "100001" }),
    missingPredecessorStateId: () => real3.create({ predecessorStateId: "" }),
    missingSuccessorStateId: () => real3.create({ successorStateId: "" })
  };
  for (const [name, fn] of Object.entries(v3CreateRejects)) {
    out.apV3.createRejects[name] = captureError(fn);
  }

  /* ---- approval-package-v4 impure members ---- */
  const real4 = buildRealPackageV4({ apV4, recipientMerkle, agentMerkle });
  const created4 = real4.create();
  const pkg4 = { ...created4, createdAt: FIXED_CREATED_AT };
  const integral4 = apV4.assertPackageIntegrityV4(pkg4);
  const complete4 = {
    ...pkg4,
    approvals: pkg4.approvals.map((entry, i) => (i === 1 ? FAKE_SIG_2 : entry))
  };
  const json4 = apV4.approvalPackageToJsonV4(pkg4);

  /* periods >= 1 variant: rollover accounting inside create */
  const rolledPolicyNew = { ...real4.policy, periodStartDaa: "7000", periodSpent: "5000000000" };
  const rolledSuccessorRoot = agentMerkle.foldAgentPolicyV4(rolledPolicyNew, real4.aProof.siblingsHex, real4.aProof.pathBits);
  const created4Rolled = real4.create({ periodsElapsed: "2", successorAgentRoot: rolledSuccessorRoot });

  out.apV4 = {
    createdPackage: withoutCreatedAt(created4),
    createdPackageRolled: withoutCreatedAt(created4Rolled),
    createdAtIsNonSecurity: apV4.packageCommitmentV4(pkg4) === created4.commitment,
    integrityReturnsFrozen: frozenTx.canonicalFrozenTxJson(integral4),
    toJson: json4,
    loadRoundTrip: withoutCreatedAt(apV4.loadApprovalPackageV4(json4)),
    completeBlob: apV4.approvalsBlobV4(complete4),
    createRejects: {},
    integrityRejects: {
      unknownSchema: captureError(() => apV4.assertPackageIntegrityV4({ ...pkg4, schema: "policyvault-approval-package/v1" })),
      unknownContractVersion: captureError(() => apV4.assertPackageIntegrityV4({ ...pkg4, contractVersion: "policyvault-0.3" })),
      mutatedField: captureError(() => apV4.assertPackageIntegrityV4({ ...pkg4, reserveConsumedSompi: "2000" }))
    },
    submitRejects: {
      unknownApprover: captureError(() => apV4.submitApprovalV4(pkg4, { signatureHex: FAKE_SIG_1, approverXOnly: HEX("dd") })),
      wrongSlot: captureError(() => apV4.submitApprovalV4(pkg4, { signatureHex: FAKE_SIG_1, approverXOnly: APPROVER2, slotIndex: 0 })),
      wrongSighashByte: captureError(() =>
        apV4.submitApprovalV4(pkg4, { signatureHex: HEX("cd", 64) + "00", approverXOnly: APPROVER1 })
      ),
      placeholderSignature: captureError(() =>
        apV4.submitApprovalV4(pkg4, { signatureHex: apV4.PLACEHOLDER_APPROVAL, approverXOnly: APPROVER1 })
      ),
      schnorrInvalid: captureError(() => apV4.submitApprovalV4(pkg4, { signatureHex: FAKE_SIG_2, approverXOnly: APPROVER1 }))
    },
    blobRejects: {
      insufficient: captureError(() => apV4.approvalsBlobV4(pkg4))
    },
    loadRejects: {
      invalidJson: captureError(() => apV4.loadApprovalPackageV4("[")),
      tamperedJson: captureError(() => apV4.loadApprovalPackageV4(JSON.stringify({ ...pkg4, successorAgentRoot: HEX("00") })))
    }
  };
  const v4CreateRejects = {
    missingNetworkId: () => real4.create({ networkId: "" }),
    covenantIndexRange: () => real4.create({ covenantInputIndex: 2 }),
    outpointMismatch: () => real4.create({ predecessorOutpoint: { transactionId: FUEL_TXID, index: 0 } }),
    inputValueMismatch: () => real4.create({ predecessorProtectedSompi: "40000000001" }),
    notAboveThreshold: () => real4.create({ payAmountSompi: "1000000000", requiredFeeSompi: "101000" }),
    consumedAboveAgentMaxFee: () => real4.create({ reserveConsumedSompi: "5001" }),
    consumedAboveReserve: () => real4.create({ reserveConsumedSompi: "200001" }),
    missingAgentProof: () => real4.create({ agentProof: null }),
    agentProofDoesNotVerify: () => real4.create({ agentProof: { ...real4.args.agentProof, root: HEX("77") } }),
    successorRootNotFold: () => real4.create({ successorAgentRoot: HEX("78") }),
    output0NotP2pkRecipient: () => real4.create({ recipient: RECIPIENT2 }),
    recipientRootNotAgents: () => {
      const foreignTree = recipientMerkle.buildRecipientTree([RECIPIENT, HEX("ad")]);
      const foreignProof = recipientMerkle.generateRecipientProof(foreignTree, RECIPIENT);
      return real4.create({
        recipientProof: { root: foreignProof.root, siblingsHex: foreignProof.siblingsHex, pathBits: foreignProof.pathBits.toString() }
      });
    },
    slotsWrongLength: () => real4.create({ approverSlots: [APPROVER1, APPROVER2] }),
    duplicateApprover: () =>
      real4.create({ approverSlots: [APPROVER1, APPROVER1, SENTINEL, SENTINEL, SENTINEL, SENTINEL, SENTINEL, SENTINEL, SENTINEL, SENTINEL] }),
    approvalMZero: () => real4.create({ approvalM: "0" }),
    approvalMTooHigh: () => real4.create({ approvalM: "3" }),
    feeMismatch: () => real4.create({ requiredFeeSompi: "101001" }),
    /* 150000 trips the agentMaxFeePerTx bound first (5000) — captures that
     * deterministic first-failing branch, not the later fee comparison */
    consumedFarAboveLimits: () => real4.create({ reserveConsumedSompi: "150000" }),
    missingPredecessorStateId: () => real4.create({ predecessorStateId: "" })
  };
  for (const [name, fn] of Object.entries(v4CreateRejects)) {
    out.apV4.createRejects[name] = captureError(fn);
  }

  return out;
}

/* ---------------------------------------------------------------- */
/* API surface — sdk modules must be UNCHANGED by the split          */
/* ---------------------------------------------------------------- */

function captureApiSurface({ frozenTx, apV3, apV4 }) {
  const surface = (mod) => {
    const keys = Object.keys(mod).sort();
    const types = {};
    for (const key of keys) types[key] = typeof mod[key];
    return { keys, types };
  };
  return { frozenTx: surface(frozenTx), apV3: surface(apV3), apV4: surface(apV4) };
}

module.exports = {
  computeGolden3Pure,
  computeGolden3Impure,
  captureApiSurface,
  fixtures: { frozenV3Input, frozenV4Input, syntheticPackageV3, syntheticPackageV4 }
};
