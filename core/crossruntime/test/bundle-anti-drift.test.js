"use strict";

/*
 * Bundle anti-drift + browser-global-branch sanity (PostLaunchUpgradeOG
 * cross-runtime equivalence). web/test/core-bundle.test.js already pins
 * byte-identical regeneration via a plain require() of the bundle (the
 * CommonJS `module.exports` escape hatch); this file re-confirms the
 * SAME anti-drift property from this suite's own sandbox harness, and
 * additionally proves the bundle's ACTUAL browser branch
 * (`window.PolicyVaultCore`) is what gets exercised for every other test
 * in this directory — not the CommonJS branch.
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");

const { generateBundle, OUT_PATH } = require("../../../web/tools/build-core-bundle.js");
const { loadCommittedBundleInBrowserGlobal, BUNDLE_PATH } = require("../sandbox.js");

test("ANTI-DRIFT: the committed web/core-bundle.js is byte-identical to a fresh regeneration", () => {
  const committed = fs.readFileSync(OUT_PATH, "utf8");
  const regenerated = generateBundle();
  assert.equal(committed, regenerated, "web/core-bundle.js has drifted from core/intent, core/explain, core/signer — run node web/tools/build-core-bundle.js");
  assert.equal(BUNDLE_PATH, OUT_PATH, "the sandbox harness must read the SAME file path the generator writes");
});

test("BROWSER-GLOBAL: loading the bundle in an isolated vm context with no require/module/process/Buffer populates window.PolicyVaultCore", () => {
  const { global: sandboxGlobal, PolicyVaultCore } = loadCommittedBundleInBrowserGlobal();

  assert.equal(sandboxGlobal.window, sandboxGlobal, "window must alias the global scope, as in a real browser tab");
  assert.equal(typeof sandboxGlobal.require, "undefined", "no Node require must leak into the simulated browser global");
  assert.equal(typeof sandboxGlobal.module, "undefined", "no Node module object must leak into the simulated browser global");
  assert.equal(typeof sandboxGlobal.process, "undefined", "no Node process must leak into the simulated browser global");
  assert.equal(typeof sandboxGlobal.Buffer, "undefined", "no Node Buffer must leak into the simulated browser global");

  assert.deepEqual(Object.keys(PolicyVaultCore).sort(), [
    "agentMerkle",
    "computeBudgetV3",
    "computeBudgetV4",
    "explainKas",
    "feeMass",
    "frozenTx",
    "governance",
    "governanceExplain",
    "intent",
    "intentExplain",
    "recipientMerkle",
    "require",
    "riskExplain",
    "signerErrors",
    "signerInterface",
    "vaultStateV4",
    "vaultTransitionsV4"
  ]);
  assert.equal(PolicyVaultCore.intent.MANIFEST_VERSION_1, "policyvault-intent-manifest/1");
  assert.equal(PolicyVaultCore.signerInterface.SIGNER_INTERFACE_VERSION, "policyvault-signer/1");
  /* F1: the byte-native Merkle modules load INSIDE the Buffer-free vm
   * context and produce real roots (module-load-time PADDING_LEAF hashing
   * through the byte-mode crypto shim). */
  assert.match(PolicyVaultCore.agentMerkle.PADDING_LEAF_HEX, /^[0-9a-f]{64}$/);
  assert.equal(PolicyVaultCore.agentMerkle.buildAgentTreeV4([]).root, PolicyVaultCore.agentMerkle.PADDING_LEAF_HEX);
  assert.equal(typeof PolicyVaultCore.recipientMerkle.buildRecipientTree, "function");
  /* Fee/state recomputation wave: the fee-mass, frozen-tx, compute-budget,
   * vault-state-v4, and vault-transitions-v4 modules load INSIDE the
   * Buffer-free vm context (BigInt arithmetic; string-mode crypto shim for
   * state ids). */
  assert.equal(PolicyVaultCore.feeMass.MINIMUM_RELAY_TRANSACTION_FEE, 100000n);
  assert.equal(PolicyVaultCore.computeBudgetV4.V4_BUDGET.ORDINARY_INPUT, 10);
  assert.equal(PolicyVaultCore.computeBudgetV3.V3_BUDGET.ORDINARY_INPUT, 10);
  assert.equal(typeof PolicyVaultCore.frozenTx.feeDescriptorFromFrozen, "function");
  assert.equal(typeof PolicyVaultCore.vaultStateV4.computeStateIdV4, "function");
  assert.equal(typeof PolicyVaultCore.vaultTransitionsV4.agentSpendSuccessorV4, "function");
  /* Residuals wave: the governance classifier + explanation renderer load
   * INSIDE the Buffer-free vm context. */
  assert.equal(typeof PolicyVaultCore.governance.classifyPolicyDelta, "function");
  assert.equal(typeof PolicyVaultCore.governanceExplain.humanReadable, "function");
  assert.equal(PolicyVaultCore.governanceExplain.GOVERNANCE_EXPLANATION_VERSION_1, "policyvault-governance-explanation/1");
  /* W4-refinements: the risk-evaluation explanation renderer loads INSIDE
   * the Buffer-free vm context (dependency-free module). */
  assert.equal(typeof PolicyVaultCore.riskExplain.humanReadable, "function");
  assert.equal(PolicyVaultCore.riskExplain.RISK_EXPLANATION_VERSION_1, "policyvault-risk-explanation/1");
});

/* Byte-equivalence of the NEW bundled modules through the bundle's ACTUAL
 * browser branch (window.PolicyVaultCore in the Buffer-free vm context)
 * against a direct Node require of the same sources — the same pattern F1
 * pinned for the Merkle modules. Values are re-homed where realm identity
 * matters; every compared value is rendered to strings/JSON first. */
test("BROWSER-GLOBAL EQUIVALENCE: fee/mass, compute budgets, state ids, and canonical transitions are byte-identical node-vs-sandbox", () => {
  const { PolicyVaultCore } = loadCommittedBundleInBrowserGlobal();
  const { rehomeInto } = require("../sandbox.js");
  const sb = loadCommittedBundleInBrowserGlobal();
  const S = sb.PolicyVaultCore;
  const nodeFeeMass = require("../../model/fee-mass.js");
  const nodeFrozen = require("../../model/frozen-tx-v3.js");
  const nodeStateV4 = require("../../model/vault-state-v4.js");
  const nodeTransitions = require("../../model/vault-transitions-v4.js");
  const nodeBudget = require("../../model/compute-budget-v4.js");
  void PolicyVaultCore;

  const draft = {
    version: 1,
    inputs: [
      { previousOutpoint: { transactionId: "f1".repeat(32), index: 0 }, sequence: "0", computeBudget: 134, utxo: { amount: "50100000000", scriptPublicKey: { version: 0, scriptHex: "ab".repeat(35) }, covenantId: "aa".repeat(32), blockDaaScore: "0" } },
      { previousOutpoint: { transactionId: "f2".repeat(32), index: 1 }, sequence: "0", computeBudget: 10, utxo: { amount: "1000000", scriptPublicKey: { version: 0, scriptHex: "20" + "11".repeat(32) + "ac" }, covenantId: null, blockDaaScore: "0" } }
    ],
    outputs: [
      { value: "1000000000", scriptPublicKey: { version: 0, scriptHex: "20" + "33".repeat(32) + "ac" }, covenant: null },
      { value: "49099000000", scriptPublicKey: { version: 0, scriptHex: "ab".repeat(35) }, covenant: { authorizingInput: 0, covenantId: "aa".repeat(32) } }
    ],
    lockTime: "0",
    subnetworkId: "00".repeat(20),
    gas: "0",
    payload: ""
  };
  for (const sigLens of [[0, 66], [21000, 66]]) {
    const inSb = S.feeMass.calculateRequiredFee(S.frozenTx.feeDescriptorFromFrozen(S.frozenTx.normalizeFrozenTxV3(rehomeInto(sb.global, draft)), rehomeInto(sb.global, sigLens)));
    const inNode = nodeFeeMass.calculateRequiredFee(nodeFrozen.feeDescriptorFromFrozen(nodeFrozen.normalizeFrozenTxV3(draft), sigLens));
    for (const k of ["size", "computeMass", "transientMass", "normalizedTransient", "feeMass", "minimumRequiredFee"]) {
      assert.equal(inSb[k].toString(), inNode[k].toString(), `sandbox fee fact ${k} (sigLens ${sigLens})`);
    }
  }

  for (const op of ["agentSpend", "ownerSetAgentRoot", "ownerSetApprovers", "ownerTopUp", "ownerTopUpReserve", "ownerPause", "ownerUnpause", "ownerRecover"]) {
    const argsList = op === "agentSpend" ? [{ operation: op, aboveThreshold: false }, { operation: op, aboveThreshold: true }] : [{ operation: op }];
    for (const a of argsList) {
      assert.equal(S.computeBudgetV4.selectComputeBudgetV4(rehomeInto(sb.global, a)), nodeBudget.selectComputeBudgetV4(a), `sandbox budget tier ${JSON.stringify(a)}`);
    }
  }

  const policy = {
    agentPk: "22".repeat(32),
    maxPerSpend: "2000000000",
    periodBudget: "5000000000",
    periodLengthDaa: "86400",
    periodStartDaa: "1000000",
    periodSpent: "500000000",
    approvalThreshold: "1500000000",
    agentMaxFeePerTx: "10000000",
    agentRecipientRoot: "cd".repeat(32)
  };
  const treeSb = S.agentMerkle.buildAgentTreeV4(rehomeInto(sb.global, [policy]));
  const nodeAgent = require("../../model/agent-merkle-v4.js");
  const treeNode = nodeAgent.buildAgentTreeV4([policy]);
  assert.equal(treeSb.root, treeNode.root);
  const stateJson = {
    protectedValue: "50000000000",
    feeReserve: "100000000",
    paused: "0",
    agentRoot: treeNode.root,
    approverSlots: ["44".repeat(32), "55".repeat(32), ...Array.from({ length: 8 }, () => "00".repeat(32))],
    approvalM: "2",
    policyNonce: "7"
  };
  const template = { owner: "11".repeat(32), vaultId: "ee".repeat(32) };
  for (const version of ["policyvault-0.4", "policyvault-0.4.1"]) {
    const idSb = S.vaultStateV4.computeStateIdV4({
      networkId: "testnet-10",
      template: S.vaultStateV4.normalizeTemplateV4(rehomeInto(sb.global, template)),
      state: S.vaultStateV4.normalizeStateV4(rehomeInto(sb.global, stateJson)),
      contractVersion: version
    });
    const idNode = nodeStateV4.computeStateIdV4({
      networkId: "testnet-10",
      template: nodeStateV4.normalizeTemplateV4(template),
      state: nodeStateV4.normalizeStateV4(stateJson),
      contractVersion: version
    });
    assert.equal(idSb, idNode, `sandbox state id (${version})`);
  }

  const proofSb = S.agentMerkle.generateAgentProofV4(treeSb, policy.agentPk);
  const proofNode = nodeAgent.generateAgentProofV4(treeNode, policy.agentPk);
  const spendSb = S.vaultTransitionsV4.agentSpendSuccessorV4(S.vaultStateV4.normalizeStateV4(rehomeInto(sb.global, stateJson)), rehomeInto(sb.global, {
    agentPolicy: policy,
    agentProof: { siblingsHex: proofSb.siblingsHex, pathBits: proofSb.pathBits.toString() },
    payAmount: "1000000000",
    periodsElapsed: "0",
    reserveConsumed: "521700"
  }));
  const spendNode = nodeTransitions.agentSpendSuccessorV4(nodeStateV4.normalizeStateV4(stateJson), {
    agentPolicy: policy,
    agentProof: { siblingsHex: proofNode.siblingsHex, pathBits: proofNode.pathBits.toString() },
    payAmount: "1000000000",
    periodsElapsed: "0",
    reserveConsumed: "521700"
  });
  assert.equal(
    JSON.stringify(S.vaultStateV4.stateToJsonV4(spendSb.successor)),
    JSON.stringify(nodeStateV4.stateToJsonV4(spendNode.successor)),
    "sandbox canonical spend successor byte-identical"
  );
  assert.equal(spendSb.aboveThreshold, spendNode.aboveThreshold);

  /* reject-path equivalence: the over-budget refusal is byte-identical */
  const tired = { ...policy, periodSpent: "4000000000" };
  const tiredTreeSb = S.agentMerkle.buildAgentTreeV4(rehomeInto(sb.global, [tired]));
  const tiredTreeNode = nodeAgent.buildAgentTreeV4([tired]);
  const tiredProofSb = S.agentMerkle.generateAgentProofV4(tiredTreeSb, policy.agentPk);
  const tiredProofNode = nodeAgent.generateAgentProofV4(tiredTreeNode, policy.agentPk);
  let mSb = null, mNode = null;
  try {
    S.vaultTransitionsV4.agentSpendSuccessorV4(S.vaultStateV4.normalizeStateV4(rehomeInto(sb.global, { ...stateJson, agentRoot: tiredTreeSb.root })), rehomeInto(sb.global, { agentPolicy: tired, agentProof: { siblingsHex: tiredProofSb.siblingsHex, pathBits: tiredProofSb.pathBits.toString() }, payAmount: "2000000000", periodsElapsed: "0", reserveConsumed: "0" }));
  } catch (e) { mSb = `${e.message}|${e.code}`; }
  try {
    nodeTransitions.agentSpendSuccessorV4(nodeStateV4.normalizeStateV4({ ...stateJson, agentRoot: tiredTreeNode.root }), { agentPolicy: tired, agentProof: { siblingsHex: tiredProofNode.siblingsHex, pathBits: tiredProofNode.pathBits.toString() }, payAmount: "2000000000", periodsElapsed: "0", reserveConsumed: "0" });
  } catch (e) { mNode = `${e.message}|${e.code}`; }
  assert.match(mNode, /remaining period budget/);
  assert.equal(mSb, mNode, "sandbox over-budget refusal identical");
});

/* Residuals wave: governance classification + explanation byte-equivalence
 * node-vs-sandbox (accept AND refusal paths), plus the deliberate
 * fail-closed pin for the ONE browser-unportable function in the bundled
 * governance closure (canonical.js governanceProposalDigest uses
 * Buffer.from — it must THROW in the Buffer-free runtime, never produce a
 * wrong digest; the explain path never calls it). */
test("BROWSER-GLOBAL EQUIVALENCE: governance classifyPolicyDelta + governanceExplain are byte-identical node-vs-sandbox; proposal digest fails closed without Buffer", () => {
  const sb = loadCommittedBundleInBrowserGlobal();
  const { rehomeInto } = require("../sandbox.js");
  const S = sb.PolicyVaultCore;
  const nodeGov = require("../../governance");
  const nodeExplain = require("../../explain/governance-explain.js");

  const v4Tuple = (agentOverrides = {}) => ({
    paused: "0",
    approvalM: "2",
    approvers: ["44".repeat(32), "55".repeat(32)],
    agents: [
      {
        agentPk: "22".repeat(32),
        maxPerSpend: "2000000000",
        periodBudget: "5000000000",
        periodLengthDaa: "86400",
        periodStartDaa: "1000000",
        periodSpent: "500000000",
        approvalThreshold: "1500000000",
        agentMaxFeePerTx: "100000",
        recipients: ["66".repeat(32)],
        ...agentOverrides
      }
    ]
  });

  const args = {
    covenantVersion: "policyvault-0.4.1",
    before: v4Tuple(),
    after: v4Tuple({ maxPerSpend: "3000000000" })
  };
  const deltaSb = S.governance.classifyPolicyDelta(rehomeInto(sb.global, args));
  const deltaNode = nodeGov.classifyPolicyDelta(args);
  assert.equal(JSON.stringify(deltaSb), JSON.stringify(deltaNode), "sandbox classification byte-identical");
  assert.equal(deltaNode.classification, "EXPANSION");

  assert.equal(
    JSON.stringify(S.governanceExplain.humanReadable(rehomeInto(sb.global, deltaNode))),
    JSON.stringify(nodeExplain.humanReadable(deltaNode)),
    "sandbox humanReadable byte-identical"
  );
  assert.equal(
    JSON.stringify(S.governanceExplain.structured(rehomeInto(sb.global, deltaNode))),
    JSON.stringify(nodeExplain.structured(deltaNode)),
    "sandbox structured byte-identical"
  );

  /* refusal path: a TAMPERED aggregate label (stored-label distrust —
   * governance-spec §7.1) refuses identically in both runtimes */
  const tampered = { ...deltaNode, classification: "REDUCTION" };
  const refusedSb = S.governanceExplain.structured(rehomeInto(sb.global, tampered));
  const refusedNode = nodeExplain.structured(tampered);
  assert.equal(refusedNode.verdict, "REFUSED");
  assert.ok(JSON.stringify(refusedNode).includes("CLASSIFICATION_MISMATCH"), "the label tamper is named");
  assert.equal(JSON.stringify(refusedSb), JSON.stringify(refusedNode), "sandbox refusal byte-identical");

  /* Buffer-dependent digest: WORKS in Node, THROWS in the sandbox. */
  const proposal = null; // the digest validates shape first; feed a schema-true minimal proposal via node to get a real digest
  void proposal;
  const canonicalNode = require("../../governance/canonical.js");
  const canonicalSb = S.require("core/governance/canonical");
  const schemaProbe = { schema: canonicalNode.GOVERNANCE_PROPOSAL_SCHEMA };
  const nodeDigest = canonicalNode.governanceProposalDigest(schemaProbe);
  assert.match(nodeDigest, /^[0-9a-f]{64}$/);
  assert.throws(
    () => canonicalSb.governanceProposalDigest(rehomeInto(sb.global, schemaProbe)),
    /Buffer/,
    "governanceProposalDigest must FAIL CLOSED (throw) in the Buffer-free browser runtime — never a wrong digest"
  );
});

/* W4-refinements: risk-evaluation explanation byte-equivalence
 * node-vs-sandbox (explained AND refused paths). The refused path is the
 * risk analog of the governance §7.1 stored-label distrust: a stored
 * composed decision diverging from the deny-wins recomputation over the
 * stored per-adapter verdicts refuses (DECISION_MISMATCH) identically in
 * both runtimes. */
test("BROWSER-GLOBAL EQUIVALENCE: riskExplain structured/humanReadable are byte-identical node-vs-sandbox; a tampered stored decision refuses in both", () => {
  const sb = loadCommittedBundleInBrowserGlobal();
  const { rehomeInto } = require("../sandbox.js");
  const S = sb.PolicyVaultCore;
  const nodeRiskExplain = require("../../explain/risk-explain.js");

  const evaluation = {
    schema: "policyvault-risk-evaluation/v1",
    evaluationId: "11111111-2222-4333-8444-555555555555",
    intentHash: "bd".repeat(32),
    decision: "REVIEW",
    status: "REVIEW_HELD",
    results: [
      { adapter: "threshold-guard", adapterVersion: "1.0.0", status: "OK", verdict: "REVIEW", reasons: [{ code: "THRESHOLD_EXCEEDED", message: "amount above the configured threshold" }] },
      { adapter: "flaky", adapterVersion: "1.0.0", status: "TIMEOUT", errorCode: "ADAPTER_TIMEOUT", verdict: "REVIEW", reasons: [{ code: "ADAPTER_TIMEOUT", message: "adapter flaky exceeded 250ms and was mapped to REVIEW (never ALLOW)" }] }
    ],
    codes: ["ADAPTER_TIMEOUT", "THRESHOLD_EXCEEDED"],
    config: { onAdapterError: "REVIEW", onEmpty: "ALLOW", timeoutMs: 250, reviewRequired: false }
  };
  assert.equal(
    JSON.stringify(S.riskExplain.humanReadable(rehomeInto(sb.global, evaluation))),
    JSON.stringify(nodeRiskExplain.humanReadable(evaluation)),
    "sandbox humanReadable byte-identical"
  );
  assert.equal(
    JSON.stringify(S.riskExplain.structured(rehomeInto(sb.global, evaluation))),
    JSON.stringify(nodeRiskExplain.structured(evaluation)),
    "sandbox structured byte-identical"
  );

  const tampered = { ...evaluation, decision: "ALLOW" }; // hostile: label flipped, per-adapter verdicts say REVIEW
  const refusedSb = S.riskExplain.structured(rehomeInto(sb.global, tampered));
  const refusedNode = nodeRiskExplain.structured(tampered);
  assert.equal(refusedNode.verdict, "REFUSED");
  assert.ok(JSON.stringify(refusedNode).includes("DECISION_MISMATCH"), "the decision tamper is named");
  assert.equal(JSON.stringify(refusedSb), JSON.stringify(refusedNode), "sandbox refusal byte-identical");
});

test("BROWSER-GLOBAL: two independent sandbox instantiations agree with each other (no cross-instance leakage)", () => {
  const a = loadCommittedBundleInBrowserGlobal();
  const b = loadCommittedBundleInBrowserGlobal();
  assert.notEqual(a.global, b.global, "each call must build a fresh, independent vm context");
  assert.equal(a.PolicyVaultCore.intent.sha256Hex("x"), b.PolicyVaultCore.intent.sha256Hex("x"));
});
