"use strict";

/* SDK — approval package + collection protocol (20D/20E/20F/20G at the
 * SDK layer): freeze-before-collect, fixed-slot binding, 65-byte
 * SIG_HASH_ALL-only acceptance, duplicate/unknown/wrong-slot rejection,
 * full mutation/replay/substitution matrix, completeness gating, and the
 * canonical 650-byte blob. Offline; verification is authoritative via
 * pv_tx_probe. */

const { test } = require("node:test");
const assert = require("node:assert/strict");

const { loadConfig } = require("../src/config");
const { buildRecipientTree, generateRecipientProof } = require("../src/recipient-merkle-v3");
const { frozenToWasmTransaction, normalizeFrozenTxV3 } = require("../src/frozen-tx-v3");
const {
  createApprovalPackageV3,
  packageCommitmentV3,
  assertPackageIntegrity,
  submitApprovalV3,
  approvalsBlobV3,
  placeholderApprovalsBlob,
  missingSlots,
  isCompleteV3,
  approvalPackageToJson,
  loadApprovalPackage,
  PLACEHOLDER_APPROVAL,
  p2pkScriptHex
} = require("../src/approval-package-v3");
const { APPROVER_SENTINEL } = require("../src/vault-state-v3");

const config = loadConfig({});
const kaspa = require(config.rustyKaspaModule);

const KEY = (v) => new kaspa.PrivateKey(v.toString(16).padStart(2, "0").repeat(32));
const XO = (p) => p.toPublicKey().toXOnlyPublicKey().toString().toLowerCase();

const a1 = KEY(20);
const a2 = KEY(21);
const a3 = KEY(22);
const outsider = KEY(99);
const recipientKey = KEY(40);
const RECIPIENT = XO(recipientKey);

/* 4 DISTINCT recipients: no duplicate-padding, so every path bit is
 * significant (with a duplicated padding leaf, a node equal to its own
 * sibling hashes identically in both orders — harmless malleability for
 * the same recipient, but it would defeat the bit-flip negative below). */
const tree = buildRecipientTree([RECIPIENT, XO(KEY(41)), XO(KEY(42)), XO(KEY(43))]);
const proof = generateRecipientProof(tree, RECIPIENT);
const SLOTS = (() => {
  const active = [XO(a1), XO(a2), XO(a3)].sort();
  return [...active, ...Array.from({ length: 7 }, () => APPROVER_SENTINEL)];
})();

const PAY = 15000000000n;
const FEE = 6100000n;

function frozenSpendTx(over = {}) {
  return {
    version: 1,
    inputs: [
      {
        previousOutpoint: { transactionId: "42".repeat(32), index: 0 },
        sequence: "0",
        computeBudget: 135,
        utxo: { amount: "100000000000", scriptPublicKey: { version: 0, scriptHex: "aa".repeat(40) }, covenantId: "41".repeat(32), blockDaaScore: "0" }
      },
      {
        previousOutpoint: { transactionId: "43".repeat(32), index: 1 },
        sequence: "0",
        computeBudget: 10,
        utxo: { amount: "1000000000", scriptPublicKey: { version: 0, scriptHex: p2pkScriptHex(XO(KEY(3))) }, covenantId: null, blockDaaScore: "0" }
      }
    ],
    outputs: [
      { value: PAY.toString(), scriptPublicKey: { version: 0, scriptHex: p2pkScriptHex(RECIPIENT) }, covenant: null },
      { value: (100000000000n - PAY).toString(), scriptPublicKey: { version: 0, scriptHex: "bb".repeat(40) }, covenant: { authorizingInput: 0, covenantId: "41".repeat(32) } },
      { value: (1000000000n - FEE).toString(), scriptPublicKey: { version: 0, scriptHex: p2pkScriptHex(XO(KEY(3))) }, covenant: null }
    ],
    lockTime: "0",
    ...over
  };
}

function packageArgs(over = {}) {
  return {
    networkId: "testnet-10",
    vaultId: "22".repeat(32),
    action: "delegateSpend",
    predecessorOutpoint: { transactionId: "42".repeat(32), index: 0 },
    predecessorStateId: "11".repeat(32),
    successorStateId: "12".repeat(32),
    policyNonce: "0",
    frozenTransaction: frozenSpendTx(),
    covenantInputIndex: 0,
    recipient: RECIPIENT,
    payAmountSompi: PAY.toString(),
    recipientProof: { root: tree.root, siblingsHex: proof.siblingsHex, pathBits: proof.pathBits.toString() },
    approvalThresholdAmount: "5000000000",
    approvalM: "2",
    approverSlots: SLOTS,
    requiredFeeSompi: FEE.toString(),
    ...over
  };
}

function signSlot(pkg, keypair) {
  const frozen = normalizeFrozenTxV3(pkg.frozenTransaction);
  const wtx = frozenToWasmTransaction(config, frozen);
  return kaspa.createInputSignature(wtx, 0, keypair).slice(2);
}

test("package creation asserts full cross-field consistency (fail closed)", () => {
  const pkg = createApprovalPackageV3(packageArgs());
  assert.equal(pkg.commitment, packageCommitmentV3(pkg));
  assert.match(pkg.txId, /^[0-9a-f]{64}$/);
  assert.match(pkg.covenantSighash, /^[0-9a-f]{64}$/);
  assert.equal(pkg.approvals.filter((a) => a === null).length, 10);

  // outpoint mismatch
  assert.throws(() => createApprovalPackageV3(packageArgs({ predecessorOutpoint: { transactionId: "40".repeat(32), index: 0 } })), /predecessor outpoint/);
  // output 0 is not the stated recipient/amount
  assert.throws(() => createApprovalPackageV3(packageArgs({ recipient: XO(KEY(41)) })), /P2PK\(recipient\)|proof/);
  assert.throws(() => createApprovalPackageV3(packageArgs({ payAmountSompi: (PAY + 1n).toString() })), /value|payAmount/);
  // proof does not verify
  assert.throws(() => createApprovalPackageV3(packageArgs({ recipientProof: { root: tree.root, siblingsHex: proof.siblingsHex, pathBits: (proof.pathBits ^ 1n).toString() } })), /proof/);
  // below threshold — packages must not exist
  assert.throws(() => createApprovalPackageV3(packageArgs({ approvalThresholdAmount: PAY.toString() })), /not above approvalThresholdAmount/);
  // malformed predecessor approver set fails EARLY
  assert.throws(() => createApprovalPackageV3(packageArgs({ approverSlots: [SLOTS[0], SLOTS[0], ...SLOTS.slice(2)] })), /duplicates an active approver key/);
  assert.throws(() => createApprovalPackageV3(packageArgs({ approvalM: "0" })), /approvalM < 1/);
  assert.throws(() => createApprovalPackageV3(packageArgs({ approvalM: "4" })), /exceeds the active approver count/);
  // fee inconsistency
  assert.throws(() => createApprovalPackageV3(packageArgs({ requiredFeeSompi: (FEE + 1n).toString() })), /fee/);
  // unknown action
  assert.throws(() => createApprovalPackageV3(packageArgs({ action: "ownerPause" })), /spend entrypoints/);
});

test("collection: fixed-slot binding, duplicates, unknown signers, sentinel", () => {
  let pkg = createApprovalPackageV3(packageArgs());
  const sig1 = signSlot(pkg, a1);

  // valid approval lands in the signer's canonical slot
  pkg = submitApprovalV3(pkg, { signatureHex: sig1, approverXOnly: XO(a1) });
  const slot1 = pkg.approverSlots.indexOf(XO(a1));
  assert.equal(pkg.approvals[slot1], sig1);
  assert.equal(isCompleteV3(pkg), false);
  assert.equal(missingSlots(pkg).length, 2);

  // unknown signer
  assert.throws(() => submitApprovalV3(pkg, { signatureHex: signSlot(pkg, outsider), approverXOnly: XO(outsider) }), /not a configured approver/);
  // correct signer, wrong claimed slot
  assert.throws(() => submitApprovalV3(pkg, { signatureHex: signSlot(pkg, a2), approverXOnly: XO(a2), slotIndex: slot1 }), /fixed-slot-bound/);
  // duplicate submission into the same slot
  assert.throws(() => submitApprovalV3(pkg, { signatureHex: sig1, approverXOnly: XO(a1) }), /already holds an approval/);
  // a1's signature presented under a2's identity fails verification
  assert.throws(() => submitApprovalV3(pkg, { signatureHex: sig1, approverXOnly: XO(a2) }), /approval rejected/);
  // sentinel is not a signer
  assert.throws(() => submitApprovalV3(pkg, { signatureHex: sig1, approverXOnly: APPROVER_SENTINEL }), /sentinel/);

  // completing with a2
  pkg = submitApprovalV3(pkg, { signatureHex: signSlot(pkg, a2), approverXOnly: XO(a2) });
  assert.equal(isCompleteV3(pkg), true);
});

test("signature shape matrix: only 65-byte SIG_HASH_ALL accepted (20F)", () => {
  const pkg = createApprovalPackageV3(packageArgs());
  const sig = signSlot(pkg, a1);
  const cases = [
    ["truncated 64-byte", sig.slice(0, 128)],
    ["extended 66-byte", sig + "00"],
    ["empty", ""],
    ["placeholder", PLACEHOLDER_APPROVAL],
    ["NONE code", sig.slice(0, -2) + "02"],
    ["SINGLE code", sig.slice(0, -2) + "03"],
    ["ALL|ACP code", sig.slice(0, -2) + "81"],
    ["NONE|ACP code", sig.slice(0, -2) + "82"],
    ["SINGLE|ACP code", sig.slice(0, -2) + "83"],
    ["arbitrary trailer", sig.slice(0, -2) + "7f"]
  ];
  for (const [name, bad] of cases) {
    assert.throws(() => submitApprovalV3(pkg, { signatureHex: bad, approverXOnly: XO(a1) }), Error, `${name} must be rejected`);
  }
  // REAL non-ALL signatures (properly signed for their type) also rejected
  const frozen = normalizeFrozenTxV3(pkg.frozenTransaction);
  const wtx = frozenToWasmTransaction(config, frozen);
  for (const ty of [kaspa.SighashType.None, kaspa.SighashType.Single, kaspa.SighashType.AllAnyOneCanPay]) {
    const realBad = kaspa.createInputSignature(wtx, 0, a1, ty).slice(2);
    assert.throws(() => submitApprovalV3(pkg, { signatureHex: realBad, approverXOnly: XO(a1) }), /SIG_HASH_ALL|approval rejected/);
  }
});

test("mutation matrix: every protected field change voids the package (20G)", () => {
  const base = createApprovalPackageV3(packageArgs());
  const withOne = submitApprovalV3(base, { signatureHex: signSlot(base, a1), approverXOnly: XO(a1) });

  const mutations = [
    ["recipient", (p) => (p.recipient = XO(KEY(41)))],
    ["payAmount", (p) => (p.payAmountSompi = (PAY + 1n).toString())],
    ["predecessor outpoint", (p) => (p.predecessorOutpoint = { transactionId: "40".repeat(32), index: 0 })],
    ["predecessor stateId", (p) => (p.predecessorStateId = "13".repeat(32))],
    ["successor stateId", (p) => (p.successorStateId = "14".repeat(32))],
    ["policyNonce", (p) => (p.policyNonce = "1")],
    ["fee", (p) => (p.requiredFeeSompi = (FEE + 1n).toString())],
    ["compute budget", (p) => (p.computeBudget = 20)],
    ["Merkle root", (p) => (p.recipientProof = { ...p.recipientProof, root: "99".repeat(32) })],
    ["Merkle sibling", (p) => (p.recipientProof = { ...p.recipientProof, siblingsHex: "00".repeat(32) + p.recipientProof.siblingsHex.slice(64) })],
    ["pathBits", (p) => (p.recipientProof = { ...p.recipientProof, pathBits: "3" })],
    ["vaultId", (p) => (p.vaultId = "23".repeat(32))],
    ["contractVersion", (p) => (p.contractVersion = "policyvault-0.2")],
    ["network", (p) => (p.networkId = "mainnet")],
    ["approver slot", (p) => (p.approverSlots = [XO(outsider), ...p.approverSlots.slice(1)])],
    ["approvalM", (p) => (p.approvalM = "1")],
    ["threshold", (p) => (p.approvalThresholdAmount = "1")],
    ["txId", (p) => (p.txId = "77".repeat(32))],
    ["sighash", (p) => (p.covenantSighash = "78".repeat(32))],
    ["frozen output value", (p) => (p.frozenTransaction = { ...p.frozenTransaction, outputs: p.frozenTransaction.outputs.map((o, i) => (i === 2 ? { ...o, value: (BigInt(o.value) - 1n).toString() } : o)) })],
    ["frozen lockTime", (p) => (p.frozenTransaction = { ...p.frozenTransaction, lockTime: "541000000" })],
    ["frozen sequence", (p) => (p.frozenTransaction = { ...p.frozenTransaction, inputs: p.frozenTransaction.inputs.map((x, i) => (i === 0 ? { ...x, sequence: "1" } : x)) })],
    ["frozen output order", (p) => (p.frozenTransaction = { ...p.frozenTransaction, outputs: [p.frozenTransaction.outputs[1], p.frozenTransaction.outputs[0], p.frozenTransaction.outputs[2]] })]
  ];
  for (const [name, mutate] of mutations) {
    const doc = JSON.parse(approvalPackageToJson(withOne));
    mutate(doc);
    assert.throws(() => assertPackageIntegrity(doc), Error, `${name} mutation must void the package`);
    assert.throws(
      () => submitApprovalV3(doc, { signatureHex: signSlot(withOne, a2), approverXOnly: XO(a2) }),
      Error,
      `${name}: no further approvals may be collected into a mutated package`
    );
    assert.throws(() => approvalsBlobV3(doc), Error, `${name}: a mutated package must never emit a blob`);
  }
});

test("approval reuse across packages fails: different tx intent kills the signature", () => {
  const pkgA = createApprovalPackageV3(packageArgs());
  const sigA = signSlot(pkgA, a1);

  // Same shape, different payAmount (and consistent outputs/fee).
  const otherTx = frozenSpendTx();
  otherTx.outputs[0].value = (PAY + 1000n).toString();
  otherTx.outputs[1].value = (100000000000n - PAY - 1000n).toString();
  const pkgB = createApprovalPackageV3(packageArgs({ frozenTransaction: otherTx, payAmountSompi: (PAY + 1000n).toString() }));
  assert.throws(() => submitApprovalV3(pkgB, { signatureHex: sigA, approverXOnly: XO(a1) }), /approval rejected/);

  // Different predecessor outpoint (another vault instance / stale state).
  const stale = frozenSpendTx();
  stale.inputs[0].previousOutpoint = { transactionId: "40".repeat(32), index: 0 };
  const pkgC = createApprovalPackageV3(
    packageArgs({ frozenTransaction: stale, predecessorOutpoint: { transactionId: "40".repeat(32), index: 0 } })
  );
  assert.throws(() => submitApprovalV3(pkgC, { signatureHex: sigA, approverXOnly: XO(a1) }), /approval rejected/);
});

test("completeness gate + canonical 650-byte blob with exact placeholders (20D)", () => {
  let pkg = createApprovalPackageV3(packageArgs());
  assert.throws(() => approvalsBlobV3(pkg), /insufficient approvals/i);
  pkg = submitApprovalV3(pkg, { signatureHex: signSlot(pkg, a1), approverXOnly: XO(a1) });
  assert.throws(() => approvalsBlobV3(pkg), /insufficient approvals/i); // M-1
  pkg = submitApprovalV3(pkg, { signatureHex: signSlot(pkg, a2), approverXOnly: XO(a2) }); // exactly M
  const blob = approvalsBlobV3(pkg);
  assert.equal(blob.length / 2, 650);
  for (let i = 0; i < 10; i++) {
    const slot = blob.slice(i * 130, (i + 1) * 130);
    if (pkg.approvals[i]) {
      assert.equal(slot, pkg.approvals[i]);
    } else {
      assert.equal(slot, PLACEHOLDER_APPROVAL, `slot ${i} must carry the canonical placeholder`);
    }
    assert.equal(slot.slice(-2), "01", `slot ${i} trailing byte`);
  }
  assert.equal(placeholderApprovalsBlob(), PLACEHOLDER_APPROVAL.repeat(10));
});

test("durable JSON round-trip preserves integrity; corrupted payloads fail closed", () => {
  let pkg = createApprovalPackageV3(packageArgs());
  pkg = submitApprovalV3(pkg, { signatureHex: signSlot(pkg, a1), approverXOnly: XO(a1) });
  const json = approvalPackageToJson(pkg);
  const back = loadApprovalPackage(json);
  assert.equal(back.commitment, pkg.commitment);
  assert.throws(() => loadApprovalPackage(json.replace("policyvault-approval-package/v1", "policyvault-approval-package/v2")), /schema|commitment/);
  assert.throws(() => loadApprovalPackage("{not json"), /not valid JSON/);
});
