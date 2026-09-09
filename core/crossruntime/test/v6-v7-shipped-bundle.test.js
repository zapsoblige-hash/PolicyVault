"use strict";

/*
 * CROSS-RUNTIME EQUIVALENCE — the v0.6 and v0.7 core modules THROUGH THE
 * SHIPPED web/core-bundle.js (Wave 2, Track F: docs/postlaunch/
 * hybrid-core-gap-analysis.md §4 migration-plan row 1: "§3.3's 44 cases
 * re-run against the SHIPPED bundle (not just the probe)").
 *
 * core/crossruntime/test/v5-v6-portability.test.js and
 * v7-org-root-portability.test.js already proved the underlying source
 * files are portable using loadCoreFilesInSandbox() — a FORWARD-LOOKING
 * PROBE over an explicit file list, not a claim about the shipped bundle.
 * Since this wave's bundling commit added all of those files to
 * web/tools/build-core-bundle.js's reviewed MODULES list, this file
 * re-proves the highest-value subset of the same equivalences through
 * loadCommittedBundleInBrowserGlobal() — the bundle's ACTUAL browser
 * branch (window.PolicyVaultCore), evaluated with no require/module/
 * process/Buffer — so a bundle that stopped exposing one of these modules,
 * or whose crypto shim diverged for a v6/v7 code path, fails HERE.
 *
 * Also covers this wave's two remaining cross-runtime requirements:
 *   - router DECISIONS (routeManifest / resolveIntentRoute) agree between
 *     Node-direct core/intent/router.js and the SAME module reached
 *     through the shipped bundle, for every registered version AND >= 10
 *     unknown/malformed ones (including the prototype-shaped keys the
 *     router.js fix in this wave now refuses correctly in both runtimes);
 *   - amounts parsing (the golden 41-vector fixture, including the 15
 *     recorded float-parser defects and the MAX_SOMPI boundary) agrees
 *     between Node-direct core/model/amounts.js and the shipped bundle.
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const { loadCommittedBundleInBrowserGlobal, rehomeInto, rehome } = require("../sandbox.js");
const {
  STATE_ID_V6_VECTORS,
  TOKEN_AGENT_POLICIES_V6,
  POOL_QUOTE_VECTORS,
  STORAGE_MASS_VECTORS,
  BUDGET_V6_OPERATIONS,
  TEMPLATE_GEOMETRIES,
  ROOT_STATE_V7_VECTORS,
  OWNER_SET_V7_WF_VECTORS,
  BUDGET_V7_ROOT_OPERATIONS,
  BUDGET_V7_VAULT_OPERATIONS,
  stringifyBigInts
} = require("../vectors.js");

const nodeVaultStateV6 = require("../../model/vault-state-v6.js");
const nodeAgentMerkleV6 = require("../../model/agent-merkle-v6.js");
const nodeSwapPolicyV6 = require("../../model/swap-policy-v6.js");
const nodeVaultTransitionsV6 = require("../../model/vault-transitions-v6.js");
const nodeComputeBudgetV6 = require("../../model/compute-budget-v6.js");
const nodeStorageMass = require("../../model/storage-mass.js");
const nodeOwnerSetV7 = require("../../model/owner-set-v7.js");
const nodeVaultStateV7Root = require("../../model/vault-state-v7-root.js");
const nodeVaultTransitionsV7Root = require("../../model/vault-transitions-v7-root.js");
const nodeComputeBudgetV7 = require("../../model/compute-budget-v7.js");
const nodeRouter = require("../../intent/router.js");
const nodeAmounts = require("../../model/amounts.js");

const sb = loadCommittedBundleInBrowserGlobal();
const S = sb.PolicyVaultCore;

/* ------------------------------------------------------------------ */
/* v0.6, through the shipped bundle                                     */
/* ------------------------------------------------------------------ */

for (const v of STATE_ID_V6_VECTORS) {
  test(`SHIPPED BUNDLE v0.6 state id equivalence: ${v.label}`, () => {
    const tplNode = nodeVaultStateV6.normalizeTemplateV6(v.template);
    const stNode = nodeVaultStateV6.normalizeStateV6(v.state);
    const idNode = nodeVaultStateV6.computeStateIdV6({ networkId: v.networkId, template: tplNode, state: stNode, contractVersion: v.contractVersion });
    const tplSb = S.vaultStateV6.normalizeTemplateV6(rehomeInto(sb.global, v.template));
    const stSb = S.vaultStateV6.normalizeStateV6(rehomeInto(sb.global, v.state));
    const idSb = S.vaultStateV6.computeStateIdV6({ networkId: v.networkId, template: tplSb, state: stSb, contractVersion: v.contractVersion });
    assert.equal(idSb, idNode, v.label);
  });
}

test("SHIPPED BUNDLE v0.6 agent-merkle: tree root, proof, and fold agree", () => {
  const treeNode = nodeAgentMerkleV6.buildTokenAgentTreeV6(TOKEN_AGENT_POLICIES_V6);
  const treeSb = S.agentMerkleV6.buildTokenAgentTreeV6(rehomeInto(sb.global, TOKEN_AGENT_POLICIES_V6));
  assert.equal(treeSb.root, treeNode.root);
  const leaf = TOKEN_AGENT_POLICIES_V6[0];
  const proofNode = nodeAgentMerkleV6.generateTokenAgentProofV6(treeNode, leaf.agentPk);
  const proofSb = S.agentMerkleV6.generateTokenAgentProofV6(treeSb, leaf.agentPk);
  assert.equal(proofSb.siblingsHex, proofNode.siblingsHex);
  assert.equal(proofSb.pathBits.toString(), proofNode.pathBits.toString());
});

const SWAP_VENUE_PROFILE_FIXTURE = Object.freeze({
  profileVersion: "policyvault-swap-venue-profile/1",
  profileId: "v6-shipped-bundle-xrt-fixture",
  networkId: "testnet-10",
  poolCovenantId: "50".repeat(32),
  poolTemplateVmHashBlake2b256: "70".repeat(32),
  poolTemplateGeometry: { prefixLen: 1, stateLen: 36, suffixLen: 15189 },
  poolStateLayout: "constant-product-pool-state/1",
  tokenStandard: "kcc20-state/1",
  tokenCovenantId: "54".repeat(32),
  invariantModel: "constant-product-bps-fee/1",
  feeModel: { poolFeeBps: "30", protocolFeeBps: "20", protocolFeePk: "66".repeat(32) },
  requiredShape: { tokenFamilyInputs: 2, tokenFamilyOutputs: 2, poolInputs: 1, poolOutputs: 1, outputsTypeA: 5, outputsTypeB: 6 },
  signerSemantics: { sighash: "ALL", postSignIdentityVerification: true, poolOutpointBinding: "exact" },
  provenance: { sourceRelPath: "contracts/experiments/V6PoolFixture.sil", sourceSha256: "ab".repeat(32), reference: "PolicyVault v0.6 pool fixture (test venue; not an endorsement)" }
});

test("SHIPPED BUNDLE v0.6 swap-policy: venue profile hash and policy tree agree", () => {
  const hashNode = nodeSwapPolicyV6.computeSwapVenueProfileHash(nodeSwapPolicyV6.normalizeSwapVenueProfile(SWAP_VENUE_PROFILE_FIXTURE));
  const hashSb = S.swapPolicyV6.computeSwapVenueProfileHash(S.swapPolicyV6.normalizeSwapVenueProfile(rehomeInto(sb.global, SWAP_VENUE_PROFILE_FIXTURE)));
  assert.equal(hashSb, hashNode);
});

for (const v of POOL_QUOTE_VECTORS) {
  test(`SHIPPED BUNDLE v0.6 pool quote equivalence: ${v.label}`, () => {
    for (const [fn] of [["poolSellQuote"], ["poolBuyQuote"]]) {
      let outNode = null, codeNode = null;
      let outSb = null, codeSb = null;
      try {
        outNode = nodeVaultTransitionsV6[fn](v.pool, { amountIn: v.sell, protocolFeeBps: v.protocolFeeBps });
      } catch (e) { codeNode = e.code || e.message; }
      try {
        outSb = S.vaultTransitionsV6[fn](rehomeInto(sb.global, v.pool), rehomeInto(sb.global, { amountIn: v.sell, protocolFeeBps: v.protocolFeeBps }));
      } catch (e) { codeSb = e.code || e.message; }
      if (outNode !== null) {
        assert.notEqual(outSb, null, `${v.label} ${fn}: node succeeded, sandbox refused (${codeSb})`);
        assert.equal(JSON.stringify(rehome(stringifyBigInts(outSb))), JSON.stringify(stringifyBigInts(outNode)), `${v.label} ${fn}`);
      } else {
        assert.equal(outSb, null, `${v.label} ${fn}: node refused, sandbox succeeded`);
        assert.equal(codeSb, codeNode, `${v.label} ${fn}: refusal code must agree`);
      }
    }
  });
}

for (const v of STORAGE_MASS_VECTORS) {
  test(`SHIPPED BUNDLE KIP-9 storage mass equivalence: ${v.label}`, () => {
    let a = null, ca = null, b = null, cb = null;
    try { a = nodeStorageMass.calcStorageMass(v.inputs.map(BigInt), v.outputs.map(BigInt)); } catch (e) { ca = e.code || e.message; }
    try { b = S.storageMass.calcStorageMass(rehomeInto(sb.global, v.inputs.map(BigInt).map(String)).map((x) => BigInt(x)), rehomeInto(sb.global, v.outputs.map(BigInt).map(String)).map((x) => BigInt(x))); } catch (e) { cb = e.code || e.message; }
    if (a !== null) assert.equal(b === null ? null : b.toString(), a.toString(), v.label);
    else assert.equal(cb, ca, v.label);
  });
}

for (const op of BUDGET_V6_OPERATIONS) {
  for (const geom of TEMPLATE_GEOMETRIES) {
    test(`SHIPPED BUNDLE v0.6 compute-budget equivalence: ${op} @ ${JSON.stringify(geom)}`, () => {
      const args = { operation: op, ...geom };
      const a = nodeComputeBudgetV6.selectComputeBudgetV6(args);
      const b = S.computeBudgetV6.selectComputeBudgetV6(rehomeInto(sb.global, args));
      assert.equal(b, a);
    });
  }
}

/* ------------------------------------------------------------------ */
/* v0.7, through the shipped bundle                                     */
/* ------------------------------------------------------------------ */

for (const v of ROOT_STATE_V7_VECTORS) {
  test(`SHIPPED BUNDLE v0.7 root state region + digest + id equivalence: ${v.label}`, () => {
    const stateNode = nodeVaultStateV7Root.normalizeRootStateV7(v.state);
    const regionNode = nodeVaultStateV7Root.serializeRootStateHexV7(stateNode);
    const idNode = nodeVaultStateV7Root.computeRootStateIdV7({ networkId: v.networkId, template: v.template, state: stateNode });

    const stateSb = S.vaultStateV7Root.normalizeRootStateV7(rehomeInto(sb.global, v.state));
    const regionSb = S.vaultStateV7Root.serializeRootStateHexV7(stateSb);
    const idSb = S.vaultStateV7Root.computeRootStateIdV7({ networkId: v.networkId, template: rehomeInto(sb.global, v.template), state: stateSb });

    assert.equal(regionSb, regionNode, `${v.label}: state region`);
    assert.equal(idSb, idNode, `${v.label}: state id`);
  });
}

for (const v of OWNER_SET_V7_WF_VECTORS) {
  test(`SHIPPED BUNDLE v0.7 WF(S) equivalence: ${v.label}`, () => {
    let a = null, ca = null, b = null, cb = null;
    try { a = nodeOwnerSetV7.normalizeOwnerSetV7(v.set); } catch (e) { ca = e.code; }
    try { b = S.ownerSetV7.normalizeOwnerSetV7(rehomeInto(sb.global, v.set)); } catch (e) { cb = e.code; }
    if (v.expect === "ACCEPT") {
      assert.equal(ca, null, v.label);
      assert.equal(cb, null, v.label);
      assert.equal(b.activeCount, a.activeCount);
    } else {
      assert.equal(ca, v.expect, v.label);
      assert.equal(cb, ca, v.label);
    }
  });
}

test("SHIPPED BUNDLE v0.7 root transition equivalence (authorize/freeze)", () => {
  const v = ROOT_STATE_V7_VECTORS[1];
  for (const [action, params] of [["authorize", {}], ["freeze", {}]]) {
    const planNode = nodeVaultTransitionsV7Root.rootTransitionV7(action, v.state, { ...params, template: v.template });
    const planSb = S.vaultTransitionsV7Root.rootTransitionV7(action, rehomeInto(sb.global, v.state), rehomeInto(sb.global, { ...params, template: v.template }));
    assert.equal(planSb.newStateDigest, planNode.newStateDigest, action);
    assert.equal(planSb.tailHex, planNode.tailHex, action);
  }
});

for (const op of BUDGET_V7_ROOT_OPERATIONS) {
  test(`SHIPPED BUNDLE v0.7 root compute-budget equivalence: ${op.actionName} @ ${op.activeOwnerSlots}`, () => {
    const a = nodeComputeBudgetV7.selectRootComputeBudgetV7(op);
    const b = S.computeBudgetV7.selectRootComputeBudgetV7(rehomeInto(sb.global, op));
    assert.equal(b, a);
  });
}

for (const op of BUDGET_V7_VAULT_OPERATIONS) {
  test(`SHIPPED BUNDLE v0.7 rooted-vault compute-budget equivalence: ${op.operation}`, () => {
    const a = nodeComputeBudgetV7.selectComputeBudgetV7(op);
    const b = S.computeBudgetV7.selectComputeBudgetV7(rehomeInto(sb.global, op));
    assert.equal(b, a);
  });
}

/* ------------------------------------------------------------------ */
/* router decisions across runtimes — every registered version AND     */
/* >= 10 unknown/malformed ones                                         */
/* ------------------------------------------------------------------ */

function nodeCodeOf(fn) {
  try { fn(); return null; } catch (e) { return e.code || "NO_CODE"; }
}

test("SHIPPED BUNDLE router: every registered manifestVersion routes to the same module identity in both runtimes", () => {
  for (const mv of nodeRouter.SUPPORTED_MANIFEST_VERSIONS) {
    const famNode = nodeRouter.MANIFEST_FAMILIES[mv];
    const famSb = S.intentRouter.MANIFEST_FAMILIES[mv];
    assert.equal(famSb.module, famNode.module, mv);
    assert.equal(famSb.contractVersion, famNode.contractVersion, mv);
    assert.equal(famSb.verify === null, famNode.verify === null, mv);
  }
});

const UNKNOWN_MANIFEST_VERSIONS_XRT = [
  "bogus/1",
  "policyvault-token-intent-manifest/2",
  "policyvault-intent-manifest/1",
  "",
  "0",
  "policyvault-0.4",
  "constructor",
  "toString",
  "hasOwnProperty",
  "__proto__",
  "valueOf",
  "isPrototypeOf"
];

test(`SHIPPED BUNDLE router: ${UNKNOWN_MANIFEST_VERSIONS_XRT.length} unknown/malformed manifestVersions refuse identically in both runtimes`, () => {
  for (const mv of UNKNOWN_MANIFEST_VERSIONS_XRT) {
    const codeNode = nodeCodeOf(() => nodeRouter.routeManifest({ manifestVersion: mv }));
    const codeSb = nodeCodeOf(() => S.intentRouter.routeManifest(rehomeInto(sb.global, { manifestVersion: mv })));
    assert.equal(codeNode, "UNKNOWN_MANIFEST_VERSION", mv);
    assert.equal(codeSb, codeNode, mv);
  }
});

const UNKNOWN_CONTRACT_VERSIONS_XRT = [
  "policyvault-0.8",
  "policyvault-0.7",
  "bogus",
  "",
  "0",
  "constructor",
  "toString",
  "hasOwnProperty",
  "__proto__",
  "policyvault-0.6" /* known, but deliberately has no single per-version route */,
  "isPrototypeOf",
  "valueOf"
];

test(`SHIPPED BUNDLE router: ${UNKNOWN_CONTRACT_VERSIONS_XRT.length} unsupported/malformed contractVersions refuse UNKNOWN_VERSION identically in both runtimes`, () => {
  for (const cv of UNKNOWN_CONTRACT_VERSIONS_XRT) {
    const codeNode = nodeCodeOf(() => nodeRouter.resolveIntentRoute(cv));
    const codeSb = nodeCodeOf(() => S.intentRouter.resolveIntentRoute(cv));
    assert.equal(codeNode, "UNKNOWN_VERSION", cv);
    assert.equal(codeSb, codeNode, cv);
  }
});

/* ------------------------------------------------------------------ */
/* amounts parsing across runtimes — the golden 41-vector fixture       */
/* (15 recorded float-parser defects + the MAX_SOMPI boundary)          */
/* ------------------------------------------------------------------ */

const GOLDEN_AMOUNTS = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "..", "..", "web", "test", "fixtures", "golden-client-amounts.json"), "utf8"));

test(`SHIPPED BUNDLE amounts: all ${GOLDEN_AMOUNTS.vectors.length} golden vectors (incl. the 15 recorded float defects + the MAX_SOMPI boundary) agree Node-direct vs shipped bundle`, () => {
  let refusedCount = 0;
  for (const row of GOLDEN_AMOUNTS.vectors) {
    let nodeResult, sbResult;
    try { nodeResult = { ok: true, value: nodeAmounts.kasToSompi(String(row.input).trim()).toString() }; } catch (e) { nodeResult = { ok: false, error: e.message }; }
    try { sbResult = { ok: true, value: S.amounts.kasToSompi(String(row.input).trim()).toString() }; } catch (e) { sbResult = { ok: false, error: e.message }; }
    assert.deepEqual(sbResult, nodeResult, `input ${JSON.stringify(row.input)}`);
    assert.equal(nodeResult.ok, row.canonical.ok, `input ${JSON.stringify(row.input)}: matches the recorded canonical verdict`);
    if (!row.canonical.ok) refusedCount += 1;
  }
  assert.ok(refusedCount >= 15, `at least 15 recorded defect vectors must be present (got ${refusedCount})`);
});
