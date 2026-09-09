"use strict";

/*
 * REAL, SELF-VERIFYING `policyvault-rooted-hd-vault-manifest/1` fixtures for
 * web/test/hd-vault-ui.test.js. core/intent/org-root-manifest-v7-hd.js's
 * verifier is a PURE data-consistency recomputation (manifest hash, Merkle
 * fold of the declared ancestor chain to the declared prior agentRoot, the
 * declared successor agentRoot as the correct nested refold, frozen-tx
 * input/output/fee arithmetic) — it needs no VM, no compiled encoder, and
 * no live silverc build. Every hash/root/fold below is produced by the SAME
 * pinned core/model/hd-leaf-v7.js functions the verifier itself recomputes
 * with, so these fixtures are internally consistent BY CONSTRUCTION, not by
 * hand-picked numbers — and `buildSpendFixture`/`buildDelegationFixture`
 * assert VERIFIED before returning, so a fixture that stops verifying
 * (e.g. after an upstream core change) fails loudly here rather than
 * silently feeding a broken manifest into the UI suite.
 *
 * This is NOT a substitute for `sdk/tools/gen-v7-hd-vectors.js` (the real
 * production-byte generator over the compiled VM path) — it is a portable,
 * VM-free fixture for the WEB UI layer only, which never re-derives
 * consensus bytes itself and only needs a manifest that verifies through
 * the SAME core function this app's browser calls
 * (core.intentRouter.verifyManifest / core.hdVaultExplain).
 */

const REPO = require("path").join(__dirname, "..", "..", "..");
const hd = require(require("path").join(REPO, "core/model/hd-leaf-v7.js"));
const { buildRootedHdVaultManifestV7, verifyRootedHdVaultManifestV7 } = require(require("path").join(REPO, "core/intent/org-root-manifest-v7-hd.js"));

const ZERO = "00".repeat(32);
const pk = (i) => i.toString(16).padStart(2, "0").repeat(32);

function leaf(i, extra = {}) {
  return {
    pk: pk(i),
    maxPerSpend: "250000",
    periodBudget: "400000",
    periodLengthDaa: "1000",
    periodStartDaa: "5000",
    periodSpent: "0",
    maxFeePerTx: "60000",
    maxCarryKas: "25000000",
    expiryDaa: "9000000",
    recipientRoot: ZERO,
    childRoot: ZERO,
    ...extra
  };
}

function jsonSafeLeaf(l) {
  return {
    pk: l.pk,
    maxPerSpend: l.maxPerSpend.toString(),
    periodBudget: l.periodBudget.toString(),
    periodLengthDaa: l.periodLengthDaa.toString(),
    periodStartDaa: l.periodStartDaa.toString(),
    periodSpent: l.periodSpent.toString(),
    maxFeePerTx: l.maxFeePerTx.toString(),
    maxCarryKas: l.maxCarryKas.toString(),
    expiryDaa: l.expiryDaa.toString(),
    recipientRoot: l.recipientRoot,
    childRoot: l.childRoot
  };
}

const TEMPLATE_IDENTITY = Object.freeze({
  vaultId: "1a".repeat(32),
  covenantId: "2b".repeat(32),
  orgRootCovenantId: "3c".repeat(32),
  descriptorHash: "4d".repeat(32),
  tokenCovenantId: "5e".repeat(32),
  templateVmHash: "6f".repeat(32),
  rootTemplateVmHash: "7a".repeat(32),
  recoveryPk: "aa".repeat(32)
});

function templateFor() {
  return {
    vaultId: TEMPLATE_IDENTITY.vaultId,
    descriptorHash: TEMPLATE_IDENTITY.descriptorHash,
    tokenCovenantId: TEMPLATE_IDENTITY.tokenCovenantId,
    templateVmHash: TEMPLATE_IDENTITY.templateVmHash,
    templatePrefixLen: 10, templateStateLen: 46, templateSuffixLen: 12,
    orgRootCovenantId: TEMPLATE_IDENTITY.orgRootCovenantId,
    rootTemplateVmHash: TEMPLATE_IDENTITY.rootTemplateVmHash,
    rootPrefixLen: 10, rootStateLen: 467, rootSuffixLen: 12,
    recoveryPk: TEMPLATE_IDENTITY.recoveryPk
  };
}

/*
 * `tree`/`path` (the level-1 forest + child-index path this test builds
 * with) are also returned so a test can independently exercise
 * hd-vault-ui.js's own resolveHdChain() against the SAME tree/path and
 * confirm it reproduces the identical chain this fixture used.
 */
function buildSpendFixture({ level, recipient = "cd".repeat(32), spendAmount = "1000", descriptor = null } = {}) {
  if (![1, 2, 3].includes(level)) throw new Error("level must be 1, 2 or 3");
  let node = { leaf: leaf(level), kids: [] };
  for (let l = level - 1; l >= 1; l--) node = { leaf: leaf(l), kids: [node] };
  const tree = [node];
  const path = new Array(level).fill(0);
  const chainRaw = hd.chainProofs(tree, path);
  const beforeAgentRoot = hd.forestRoot(tree);
  const periodsElapsedByLevel = chainRaw.map(() => 0n);
  const afterAgentRoot = hd.nestedRefoldAfterSpend(chainRaw, BigInt(spendAmount), periodsElapsedByLevel);

  const ancestorChain = chainRaw.map((e) => ({ leaf: jsonSafeLeaf(e.leaf), siblingsHex: e.siblingsHex, pathBits: e.pathBits.toString(), level: e.level, periodsElapsed: "0" }));

  const predecessorFeeReserve = 1000000n;
  const reserveConsumed = 500n;
  const successorFeeReserve = predecessorFeeReserve - reserveConsumed;
  const fuelIn = 10000n;
  const changeOut = fuelIn; // fuel nets to zero; the reserve pays the whole fee

  const frozenCanonicalJson = JSON.stringify({
    inputs: [
      { utxo: { amount: predecessorFeeReserve.toString(), covenantId: TEMPLATE_IDENTITY.covenantId } },
      { utxo: { amount: fuelIn.toString(), covenantId: null } }
    ],
    outputs: [
      { value: successorFeeReserve.toString(), covenant: { covenantId: TEMPLATE_IDENTITY.covenantId } },
      { value: changeOut.toString(), covenant: null }
    ]
  });

  const build = {
    contractVersion: "policyvault-0.7-payment-hd",
    kind: "hdTransition",
    action: level === 1 ? "hdSpend" : level === 2 ? "childSpendL2" : "childSpendL3",
    networkId: "testnet-10",
    covenantId: TEMPLATE_IDENTITY.covenantId,
    template: templateFor(),
    ancestorChain,
    predecessorStateId: "81".repeat(32),
    stateJson: { feeReserve: predecessorFeeReserve.toString(), paused: "0", agentRoot: beforeAgentRoot, policyNonce: "3" },
    predecessorOutpoint: { transactionId: "aa".repeat(32), index: 0 },
    successorStateId: "92".repeat(32),
    successorState: { feeReserve: successorFeeReserve.toString(), paused: "0", agentRoot: afterAgentRoot, policyNonce: "3" },
    accounting: {
      token: { positionBefore: "500000", spendAmount, positionAfter: (BigInt("500000") - BigInt(spendAmount)).toString(), recipient },
      kas: { predecessorFeeReserve: predecessorFeeReserve.toString(), successorFeeReserve: successorFeeReserve.toString(), reserveConsumed: reserveConsumed.toString() }
    },
    txId: "bb".repeat(32),
    computeBudget: 150,
    requiredFeeSompi: reserveConsumed.toString(),
    frozenCanonicalJson
  };

  const manifest = buildRootedHdVaultManifestV7({ build, descriptor });
  const verification = verifyRootedHdVaultManifestV7({ manifest });
  if (verification.verdict !== "VERIFIED") {
    throw new Error(`hd-manifest-fixtures: spend fixture (level ${level}) failed to self-verify: ${JSON.stringify(verification.failures)}`);
  }
  return { manifest, verification, tree, path };
}

function buildDelegationFixture({ level, newChildRoot = "cd".repeat(32) } = {}) {
  if (![1, 2].includes(level)) throw new Error("level must be 1 or 2 (a delegation NARROWS a level's own childRoot)");
  let node = { leaf: leaf(level), kids: [] };
  for (let l = level - 1; l >= 1; l--) node = { leaf: leaf(l), kids: [node] };
  const tree = [node];
  const path = new Array(level).fill(0);
  const chainRaw = hd.chainProofs(tree, path);
  const beforeAgentRoot = hd.forestRoot(tree);
  const afterAgentRoot = hd.nestedRefoldAfterDelegation(chainRaw, newChildRoot);

  const ancestorChain = chainRaw.map((e) => ({ leaf: jsonSafeLeaf(e.leaf), siblingsHex: e.siblingsHex, pathBits: e.pathBits.toString(), level: e.level, periodsElapsed: "0" }));

  const predecessorFeeReserve = 1000000n;
  const reserveConsumed = 0n; // a delegation never moves the fee reserve
  const successorFeeReserve = predecessorFeeReserve - reserveConsumed;
  const fuelIn = 10000n;
  const fee = 500n;
  const changeOut = fuelIn - fee; // fuel alone pays the fee here

  const frozenCanonicalJson = JSON.stringify({
    inputs: [
      { utxo: { amount: predecessorFeeReserve.toString(), covenantId: TEMPLATE_IDENTITY.covenantId } },
      { utxo: { amount: fuelIn.toString(), covenantId: null } }
    ],
    outputs: [
      { value: successorFeeReserve.toString(), covenant: { covenantId: TEMPLATE_IDENTITY.covenantId } },
      { value: changeOut.toString(), covenant: null }
    ]
  });

  const build = {
    contractVersion: "policyvault-0.7-payment-hd",
    kind: "hdTransition",
    action: level === 1 ? "delegateSetChildRoot1" : "delegateSetChildRoot2",
    networkId: "testnet-10",
    covenantId: TEMPLATE_IDENTITY.covenantId,
    template: templateFor(),
    ancestorChain,
    delegatingParentLevel: level,
    newChildRoot,
    predecessorStateId: "81".repeat(32),
    stateJson: { feeReserve: predecessorFeeReserve.toString(), paused: "0", agentRoot: beforeAgentRoot, policyNonce: "3" },
    predecessorOutpoint: { transactionId: "aa".repeat(32), index: 0 },
    successorStateId: "92".repeat(32),
    successorState: { feeReserve: successorFeeReserve.toString(), paused: "0", agentRoot: afterAgentRoot, policyNonce: "3" },
    accounting: { token: {}, kas: { predecessorFeeReserve: predecessorFeeReserve.toString(), successorFeeReserve: successorFeeReserve.toString(), reserveConsumed: reserveConsumed.toString() } },
    txId: "bb".repeat(32),
    computeBudget: 150,
    requiredFeeSompi: fee.toString(),
    frozenCanonicalJson
  };

  const manifest = buildRootedHdVaultManifestV7({ build });
  const verification = verifyRootedHdVaultManifestV7({ manifest });
  if (verification.verdict !== "VERIFIED") {
    throw new Error(`hd-manifest-fixtures: delegation fixture (level ${level}) failed to self-verify: ${JSON.stringify(verification.failures)}`);
  }
  return { manifest, verification, tree, path };
}

module.exports = { buildSpendFixture, buildDelegationFixture, leaf, jsonSafeLeaf, ZERO, pk, TEMPLATE_IDENTITY };
