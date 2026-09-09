"use strict";

/*
 * CROSS-RUNTIME EQUIVALENCE — the v0.7 HIERARCHICAL DELEGATION core modules
 * (core/model/hd-leaf-v7.js, core/model/compute-budget-v7-hd.js). Wave 2
 * Track D, gate I2. Sibling of v7-org-root-portability.test.js: the SAME
 * raw, JSON-safe vector goes into each runtime's OWN copy of the pipeline (a
 * fresh V8 context with `window` as its global and NO require/module/
 * process/Buffer, plus the exact crypto shim a real browser gets), and only
 * the final primitive outputs are compared.
 *
 * Why this matters here specifically: an HD leaf hash, a Merkle fold and the
 * NESTED REFOLD that produces a spend/delegation's successor `agentRoot` are
 * ALL bytes a signer's browser/mobile/CLI wallet must reproduce identically
 * to the SDK that built the transaction, or the two are silently describing
 * different transactions.
 *
 * SCOPE NOTE, as in the sibling probe: core/model is NOT part of the
 * reviewed web/core-bundle.js MODULES list, so this is a forward-looking
 * portability probe on the committed source, not a claim about the shipped
 * bundle.
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");

const { loadCoreFilesInSandbox, rehome, rehomeInto } = require("../sandbox.js");
const { stringifyBigInts } = require("../vectors.js");

/* Every HD core file plus its transitive core/model dependencies. */
const HD_FILES = Object.freeze(["core/model/own-get.js", "core/model/amounts.js", "core/model/contract-version.js", "core/model/vault-state.js", "core/model/token-amounts.js", "core/model/recipient-merkle-v3.js", "core/model/hd-leaf-v7.js", "core/model/compute-budget-v7.js", "core/model/compute-budget-v7-hd.js", "core/model/owner-set-v7.js"]);

const sandbox = loadCoreFilesInSandbox(HD_FILES);

const HD_OWN_FILES = ["core/model/hd-leaf-v7.js", "core/model/compute-budget-v7-hd.js"];

for (const relPath of HD_OWN_FILES) {
  test(`smoke: ${relPath} loads in the browser-like sandbox with the SAME export key set as Node`, () => {
    const nodeMod = require(`../../../${relPath}`);
    const sandboxMod = sandbox.require(relPath);
    assert.deepEqual(Object.keys(sandboxMod).sort(), Object.keys(nodeMod).sort());
  });
}

const hdNode = require("../../model/hd-leaf-v7.js");
const hdSandbox = sandbox.require("core/model/hd-leaf-v7.js");
const budgetNode = require("../../model/compute-budget-v7-hd.js");
const budgetSandbox = sandbox.require("core/model/compute-budget-v7-hd.js");

const ZERO = "00".repeat(32);
const pk = (i) => i.toString(16).padStart(2, "0").repeat(32);
const leaf = (i, extra = {}) => ({
  pk: pk(i),
  maxPerSpend: "250",
  periodBudget: "400",
  periodLengthDaa: "1000",
  periodStartDaa: "5000",
  periodSpent: "0",
  maxFeePerTx: "60000",
  maxCarryKas: "25000000",
  expiryDaa: "9000000",
  recipientRoot: ZERO,
  childRoot: ZERO,
  ...extra
});

/* ------------------------------------------------------------------ */
/* leaf body / hash equivalence                                         */
/* ------------------------------------------------------------------ */

for (const [label, l, level] of [
  ["level 1, defaults", leaf(1), 1],
  ["level 2, nonzero counters", leaf(2, { periodSpent: "40", periodStartDaa: "6000" }), 2],
  ["level 3, nonzero recipientRoot/childRoot", leaf(3, { recipientRoot: "cd".repeat(32), childRoot: "ef".repeat(32) }), 3]
]) {
  test(`HD leaf body/hash equivalence: ${label}`, () => {
    const bodyNode = hdNode.encodeHdLeafBodyHex(l);
    const bodySandbox = hdSandbox.encodeHdLeafBodyHex(rehomeInto(sandbox.global, l));
    assert.equal(bodySandbox, bodyNode, `${label}: the 160-byte canonical body must be byte-identical`);
    assert.equal(bodyNode.length, hdNode.HD_LEAF_BODY_LEN * 2);

    const hashNode = hdNode.hdLeafHashHex(l, level);
    const hashSandbox = hdSandbox.hdLeafHashHex(rehomeInto(sandbox.global, l), level);
    assert.equal(hashSandbox, hashNode, `${label}: the 173-byte-preimage leaf hash must be byte-identical`);

    /* decode is the inverse in BOTH runtimes, over the same bytes */
    const decodedNode = hdNode.hdLeafToJson(hdNode.decodeHdLeafBody(bodyNode));
    const decodedSandbox = rehome(hdSandbox.hdLeafToJson(hdSandbox.decodeHdLeafBody(bodySandbox)));
    assert.deepEqual(decodedSandbox, decodedNode);
  });
}

test("HD leaf reject paths fail closed identically (closed layout, zero periodLengthDaa, level out of range)", () => {
  const rows = [
    ["unknown field", { ...leaf(1), extra: "1" }, "normalizeHdLeaf"],
    ["zero periodLengthDaa", leaf(1, { periodLengthDaa: "0" }), "normalizeHdLeaf"],
    ["malformed body length", "ab", "decodeHdLeafBody"]
  ];
  for (const [label, input, fn] of rows) {
    let nodeCode = null;
    let sandboxCode = null;
    try {
      hdNode[fn](input);
    } catch (e) {
      nodeCode = e.code ?? "ERROR";
    }
    try {
      hdSandbox[fn](fn === "decodeHdLeafBody" ? input : rehomeInto(sandbox.global, input));
    } catch (e) {
      sandboxCode = e.code ?? "ERROR";
    }
    assert.ok(nodeCode, `${label}: Node must refuse`);
    assert.equal(sandboxCode, nodeCode, `${label}: both runtimes must refuse the same way`);
  }
  /* level out of range */
  for (const [mod, global, name] of [
    [hdNode, null, "node"],
    [hdSandbox, sandbox.global, "sandbox"]
  ]) {
    let code = null;
    try {
      mod.hdLeafHashHex(global ? rehomeInto(global, leaf(1)) : leaf(1), 4);
    } catch (e) {
      code = e.code;
    }
    assert.equal(code, "LEVEL_OUT_OF_RANGE", `${name}: level 4 must fail closed (MAX_LEVEL is measured, never configurable)`);
  }
});

/* ------------------------------------------------------------------ */
/* tree fold / chain proofs / effective authority equivalence           */
/* ------------------------------------------------------------------ */

function smallTree() {
  const kid0 = { leaf: leaf(10), kids: [] };
  const kid1 = { leaf: leaf(11), kids: [] };
  const l1n0 = { leaf: leaf(1), kids: [kid0, kid1] };
  const l1n1 = { leaf: leaf(2), kids: [] };
  return [l1n0, l1n1];
}

test("forestRoot + chainProofs equivalence across runtimes for a 2-level tree", () => {
  const tree = smallTree();
  const rootNode = hdNode.forestRoot(tree);
  const rootSandbox = hdSandbox.forestRoot(rehomeInto(sandbox.global, tree));
  assert.equal(rootSandbox, rootNode, "the committed agentRoot must be byte-identical");

  const chainNode = hdNode.chainProofs(tree, [0, 0]);
  const chainSandbox = hdSandbox.chainProofs(rehomeInto(sandbox.global, tree), rehomeInto(sandbox.global, [0, 0]));
  assert.equal(chainSandbox.length, chainNode.length);
  for (let i = 0; i < chainNode.length; i++) {
    assert.equal(chainSandbox[i].siblingsHex, chainNode[i].siblingsHex, `level ${i + 1}: co-path siblings must agree`);
    assert.equal(chainSandbox[i].pathBits.toString(), chainNode[i].pathBits.toString(), `level ${i + 1}: pathBits must agree`);
    assert.equal(hdSandbox.hdLeafHashHex(chainSandbox[i].leaf, chainSandbox[i].level), hdNode.hdLeafHashHex(chainNode[i].leaf, chainNode[i].level), `level ${i + 1}: the resolved leaf hash must agree`);
  }

  const effNode = hdNode.effectiveAuthority(chainNode);
  /* chainSandbox is ALREADY a sandbox-realm object (chainProofs' own
   * output) — feed it straight back in, never round-trip a BigInt-carrying
   * object through rehomeInto's JSON.stringify. */
  const effSandbox = hdSandbox.effectiveAuthority(chainSandbox);
  assert.equal(effSandbox.maxPerSpend.toString(), effNode.maxPerSpend.toString());
  assert.equal(effSandbox.maxFeePerTx.toString(), effNode.maxFeePerTx.toString());
  assert.equal(effSandbox.maxCarryKas.toString(), effNode.maxCarryKas.toString());
  assert.equal(effSandbox.expiryDaa.toString(), effNode.expiryDaa.toString());
});

/* ------------------------------------------------------------------ */
/* nested refold (the exact successor agentRoot bytes) equivalence      */
/* ------------------------------------------------------------------ */

test("nestedRefoldAfterSpend equivalence across runtimes", () => {
  const tree = smallTree();
  const chainNode = hdNode.chainProofs(tree, [0, 0]);
  const chainSandboxInput = rehomeInto(sandbox.global, stringifyBigInts(chainNode));
  const newRootNode = hdNode.nestedRefoldAfterSpend(chainNode, "50", ["0", "0"]);
  const newRootSandbox = hdSandbox.nestedRefoldAfterSpend(chainSandboxInput, "50", rehomeInto(sandbox.global, ["0", "0"]));
  assert.equal(newRootSandbox, newRootNode, "the successor agentRoot after a spend must be byte-identical across runtimes");
});

test("nestedRefoldAfterDelegation equivalence across runtimes", () => {
  const tree = smallTree();
  const chainNode = hdNode.chainProofs(tree, [1]);
  const newChildRoot = "aa".repeat(32);
  const newRootNode = hdNode.nestedRefoldAfterDelegation(chainNode, newChildRoot);
  const newRootSandbox = hdSandbox.nestedRefoldAfterDelegation(rehomeInto(sandbox.global, stringifyBigInts(chainNode)), newChildRoot);
  assert.equal(newRootSandbox, newRootNode, "the successor agentRoot after a delegation must be byte-identical across runtimes");
});

test("nested-refold reject paths fail closed identically (chain length vs periodsElapsedByLevel length mismatch)", () => {
  const tree = smallTree();
  const chainNode = hdNode.chainProofs(tree, [0]);
  for (const [mod, global, name] of [
    [hdNode, null, "node"],
    [hdSandbox, sandbox.global, "sandbox"]
  ]) {
    let code = null;
    try {
      mod.nestedRefoldAfterSpend(global ? rehomeInto(global, stringifyBigInts(chainNode)) : chainNode, "1", []);
    } catch (e) {
      code = e.message;
    }
    assert.ok(code && /periodsElapsedByLevel/.test(code), `${name}: a length mismatch must fail closed`);
  }
});

/* ------------------------------------------------------------------ */
/* HD guard functions (SDK/UI pre-flight, never the security boundary)  */
/* ------------------------------------------------------------------ */

test("verifyChildNeverExceedsParent / verifyDelegationOnlyChangesChildRoot equivalence", () => {
  const parent = leaf(1);
  const broaderChild = leaf(2, { maxPerSpend: "999" });
  const rNode = hdNode.verifyChildNeverExceedsParent(parent, broaderChild);
  const rSandbox = hdSandbox.verifyChildNeverExceedsParent(rehomeInto(sandbox.global, parent), rehomeInto(sandbox.global, broaderChild));
  assert.equal(rSandbox.ok, rNode.ok);
  assert.deepEqual(rehome(rSandbox.violations), rNode.violations);

  const current = leaf(1, { childRoot: ZERO });
  const forged = { ...current, childRoot: "11".repeat(32), maxPerSpend: "999" };
  const dNode = hdNode.verifyDelegationOnlyChangesChildRoot(current, forged);
  const dSandbox = hdSandbox.verifyDelegationOnlyChangesChildRoot(rehomeInto(sandbox.global, current), rehomeInto(sandbox.global, forged));
  assert.equal(dSandbox.ok, dNode.ok);
  assert.deepEqual(rehome(dSandbox.violations), dNode.violations);
});

/* ------------------------------------------------------------------ */
/* HD compute budgets equivalence                                       */
/* ------------------------------------------------------------------ */

for (const operation of ["hdSpend", "childSpendL2", "childSpendL3", "delegateSetChildRoot1", "delegateSetChildRoot2"]) {
  for (const atMaxDepth of [true, false]) {
    test(`HD compute budget equivalence: ${operation} atMaxDepth=${atMaxDepth}`, () => {
      const a = budgetNode.selectHdComputeBudgetV7({ operation, atMaxDepth });
      const b = budgetSandbox.selectHdComputeBudgetV7(rehomeInto(sandbox.global, { operation, atMaxDepth }));
      assert.equal(typeof a, "number");
      assert.equal(b, a, "a committed budget that differed across runtimes would make a valid transaction fail on a node");
    });
  }
}

for (const operation of ["ownerSetAgentRoot", "ownerTopUpReserve", "ownerPause", "ownerUnpause", "ownerEmergencyPause", "ownerRecover"]) {
  test(`HD owner-op compute budget equivalence: ${operation}`, () => {
    const geometry = { templatePrefixLen: 1, templateSuffixLen: 1521, rootPrefixLen: 1, rootSuffixLen: 11077 };
    const a = budgetNode.selectHdOwnerComputeBudgetV7({ operation, ...geometry });
    const b = budgetSandbox.selectHdOwnerComputeBudgetV7(rehomeInto(sandbox.global, { operation, ...geometry }));
    assert.equal(b, a);
  });
}

test("HD compute-budget reject paths fail closed identically", () => {
  for (const [mod, global, name] of [
    [budgetNode, null, "node"],
    [budgetSandbox, sandbox.global, "sandbox"]
  ]) {
    assert.throws(() => mod.selectHdComputeBudgetV7(global ? rehomeInto(global, { operation: "childSpendL4" }) : { operation: "childSpendL4" }), /unknown v0.7-hd operation/, `${name}: an unknown HD operation must fail closed`);
    assert.throws(() => mod.selectHdOwnerComputeBudgetV7(global ? rehomeInto(global, { operation: "dissolve", templatePrefixLen: 1, templateSuffixLen: 1, rootPrefixLen: 1, rootSuffixLen: 1 }) : { operation: "dissolve", templatePrefixLen: 1, templateSuffixLen: 1, rootPrefixLen: 1, rootSuffixLen: 1 }), /unknown v0.7-payment-hd owner operation/, `${name}: an unknown owner operation must fail closed`);
  }
});
