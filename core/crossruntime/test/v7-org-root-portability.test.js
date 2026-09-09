"use strict";

/*
 * CROSS-RUNTIME EQUIVALENCE — the v0.7 organizational-root core modules.
 *
 * Same discipline as core-model-portability.test.js: the SAME raw, JSON-safe
 * vector goes into each runtime's OWN copy of the pipeline (a fresh V8
 * context with `window` as its global and NO require/module/process/Buffer,
 * plus the exact crypto shim a real browser gets), and only the final
 * primitive outputs are compared.
 *
 * Why this matters more here than usual: the v0.7 root's authority model is
 * BYTES. A rooted vault slices the root's 467-byte state region by fixed
 * offsets and rebuilds its successor tail; the SDK, a browser verifier and a
 * mobile signer must all produce EXACTLY those bytes or they are describing a
 * different transaction than consensus will execute. And WF(S) must fail
 * closed identically in every runtime — a rule that refused in Node and
 * passed in a browser would be a silent authority hole (a duplicate owner key
 * counted twice, an emergency quorum heavier than the full one).
 *
 * SCOPE NOTE, as in the sibling probe: core/model is NOT part of the reviewed
 * web/core-bundle.js MODULES list, so this is a forward-looking portability
 * probe on the committed source, not a claim about the shipped bundle. I2
 * deliberately does NOT bundle the v0.7 modules.
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");

const { loadCoreFilesInSandbox, rehome, rehomeInto } = require("../sandbox.js");
const { ROOT_STATE_V7_VECTORS, OWNER_SET_V7_WF_VECTORS, BUDGET_V7_ROOT_OPERATIONS, BUDGET_V7_VAULT_OPERATIONS, stringifyBigInts } = require("../vectors.js");

/* Every v0.7 core file plus its transitive core/model dependencies. */
const V7_FILES = Object.freeze([
  "core/model/own-get.js",
  "core/model/amounts.js",
  "core/model/contract-version.js",
  "core/model/vault-state.js",
  "core/model/token-amounts.js",
  "core/model/vault-state-v5.js",
  "core/model/agent-merkle-v5.js",
  "core/model/recipient-merkle-v3.js",
  "core/model/vault-transitions-v5.js",
  "core/model/owner-set-v7.js",
  "core/model/vault-state-v7-root.js",
  "core/model/vault-state-v7.js",
  "core/model/vault-transitions-v7-root.js",
  "core/model/vault-transitions-v7.js",
  "core/model/compute-budget-v7.js"
]);

const sandbox = loadCoreFilesInSandbox(V7_FILES);

const V7_OWN_FILES = V7_FILES.filter((f) => /-v7(-root)?\.js$/.test(f));

for (const relPath of V7_OWN_FILES) {
  test(`smoke: ${relPath} loads in the browser-like sandbox with the SAME export key set as Node`, () => {
    const nodeMod = require(`../../../${relPath}`);
    const sandboxMod = sandbox.require(relPath);
    assert.deepEqual(Object.keys(sandboxMod).sort(), Object.keys(nodeMod).sort());
  });
}

const rootNode = require("../../model/vault-state-v7-root.js");
const rootSandbox = sandbox.require("core/model/vault-state-v7-root.js");
const ownersNode = require("../../model/owner-set-v7.js");
const ownersSandbox = sandbox.require("core/model/owner-set-v7.js");
const transNode = require("../../model/vault-transitions-v7-root.js");
const transSandbox = sandbox.require("core/model/vault-transitions-v7-root.js");
const budgetNode = require("../../model/compute-budget-v7.js");
const budgetSandbox = sandbox.require("core/model/compute-budget-v7.js");

/* ------------------------------------------------------------------ */
/* the EXACT consensus-visible state region                             */
/* ------------------------------------------------------------------ */

for (const v of ROOT_STATE_V7_VECTORS) {
  test(`root state region + digest + id equivalence: ${v.label}`, () => {
    const stateNode = rootNode.normalizeRootStateV7(v.state);
    const regionNode = rootNode.serializeRootStateHexV7(stateNode);
    const digestNode = rootNode.computeRootStateDigestV7(stateNode);
    const idNode = rootNode.computeRootStateIdV7({ networkId: v.networkId, template: v.template, state: stateNode });
    const tailNode = rootNode.rootStateTailHexV7({ frozen: stateNode.frozen, rootNonce: stateNode.rootNonce });

    const stateSandbox = rootSandbox.normalizeRootStateV7(rehomeInto(sandbox.global, v.state));
    const regionSandbox = rootSandbox.serializeRootStateHexV7(stateSandbox);
    const digestSandbox = rootSandbox.computeRootStateDigestV7(stateSandbox);
    const idSandbox = rootSandbox.computeRootStateIdV7({ networkId: v.networkId, template: rehomeInto(sandbox.global, v.template), state: stateSandbox });
    const tailSandbox = rootSandbox.rootStateTailHexV7({ frozen: stateSandbox.frozen, rootNonce: stateSandbox.rootNonce });

    assert.equal(regionNode.length / 2, 467, "sanity: the measured rootStateLen");
    assert.equal(regionSandbox, regionNode, `${v.label}: the state region must be byte-identical across runtimes`);
    assert.equal(tailSandbox, tailNode, `${v.label}: the fixed-width TAIL must be byte-identical`);
    assert.match(digestNode, /^[0-9a-f]{64}$/);
    assert.equal(digestSandbox, digestNode, `${v.label}: the state digest must be byte-identical`);
    assert.equal(idSandbox, idNode, `${v.label}: the state id must be byte-identical`);

    /* parse is the inverse in BOTH runtimes, over the same bytes */
    assert.deepEqual(rehome(stringifyBigInts(rootSandbox.rootStateToJsonV7(rootSandbox.parseRootStateV7(regionSandbox)))), rehome(stringifyBigInts(rootNode.rootStateToJsonV7(rootNode.parseRootStateV7(regionNode)))));
  });
}

test("root state reject paths fail closed identically (length, prefix, frozen domain)", () => {
  const region = rootNode.serializeRootStateHexV7(rootNode.normalizeRootStateV7(ROOT_STATE_V7_VECTORS[1].state));
  const rows = [
    ["short region", region.slice(0, -2), "BAD_STATE_LENGTH"],
    ["corrupt data prefix", "21" + region.slice(2), "BAD_STATE_ENCODING"],
    ["frozen byte 0x80 (negative zero)", region.slice(0, (467 - 11 + 1) * 2) + "80" + region.slice((467 - 11 + 1) * 2 + 2), "BAD_FROZEN_DOMAIN"]
  ];
  for (const [label, bad, code] of rows) {
    let nodeCode = null;
    let sandboxCode = null;
    try {
      rootNode.parseRootStateV7(bad);
    } catch (e) {
      nodeCode = e.code;
    }
    try {
      rootSandbox.parseRootStateV7(bad);
    } catch (e) {
      sandboxCode = e.code;
    }
    assert.equal(nodeCode, code, `${label}: Node must refuse with ${code}`);
    assert.equal(sandboxCode, nodeCode, `${label}: both runtimes must refuse with the same code`);
  }
});

/* ------------------------------------------------------------------ */
/* WF(S) — accepted and refused identically                             */
/* ------------------------------------------------------------------ */

for (const v of OWNER_SET_V7_WF_VECTORS) {
  test(`WF(S) equivalence: ${v.label}`, () => {
    const runNode = () => ownersNode.normalizeOwnerSetV7(v.set);
    const runSandbox = () => ownersSandbox.normalizeOwnerSetV7(rehomeInto(sandbox.global, v.set));
    if (v.expect === "ACCEPT") {
      const a = runNode();
      const b = runSandbox();
      assert.equal(b.activeCount, a.activeCount);
      assert.equal(b.ownerM.toString(), a.ownerM.toString());
      assert.deepEqual(rehome(ownersSandbox.activeOwnerSlotsV7(b).map((s) => `${s.slot}:${s.publicKey}`)), ownersNode.activeOwnerSlotsV7(a).map((s) => `${s.slot}:${s.publicKey}`));
      return;
    }
    let nodeCode = null;
    let sandboxCode = null;
    try {
      runNode();
    } catch (e) {
      nodeCode = e.code;
    }
    try {
      runSandbox();
    } catch (e) {
      sandboxCode = e.code;
    }
    assert.equal(nodeCode, v.expect, `${v.label}: Node must refuse with ${v.expect}`);
    assert.equal(sandboxCode, nodeCode, `${v.label}: a WF rule that refuses in Node must refuse in a browser too`);
  });
}

test("the 780-byte blob, its canonical placeholder and the quorum table are identical across runtimes", () => {
  const set = OWNER_SET_V7_WF_VECTORS[0].set;
  const a = ownersNode.normalizeOwnerSetV7(set);
  const b = ownersSandbox.normalizeOwnerSetV7(rehomeInto(sandbox.global, set));
  assert.equal(ownersSandbox.PLACEHOLDER_SLOT_HEX_V7, ownersNode.PLACEHOLDER_SLOT_HEX_V7);
  assert.equal(ownersSandbox.placeholderOwnerSigsBlobV7(), ownersNode.placeholderOwnerSigsBlobV7());
  assert.equal(ownersNode.placeholderOwnerSigsBlobV7().length / 2, 780);
  const sig = (byte) => byte.repeat(64) + "01";
  const approvals = [{ slot: 1, signatureHex: sig("a1") }, { slot: 2, signatureHex: sig("a2") }];
  const blobNode = ownersNode.assembleOwnerSigsBlobV7({ ownerSet: a, actionName: "authorize", approvals });
  const blobSandbox = ownersSandbox.assembleOwnerSigsBlobV7({ ownerSet: b, actionName: "authorize", approvals: rehomeInto(sandbox.global, approvals) });
  assert.equal(blobSandbox.blobHex, blobNode.blobHex, "the assembled blob must be byte-identical");
  assert.equal(blobSandbox.requiredApprovals.toString(), blobNode.requiredApprovals.toString());
  for (const action of ["authorize", "rotate", "freeze", "unfreeze", "ownerRecover", "succession"]) {
    assert.equal(ownersSandbox.requiredApprovalsV7(b, action).toString(), ownersNode.requiredApprovalsV7(a, action).toString(), `${action}: the required quorum must agree`);
    assert.equal(ownersSandbox.resolveRootActionV7(action).class, ownersNode.resolveRootActionV7(action).class, `${action}: the authority class must agree`);
  }
  /* unknown actions fail closed in both runtimes */
  for (const [mod, name] of [[ownersNode, "node"], [ownersSandbox, "sandbox"]]) {
    let code = null;
    try {
      mod.resolveRootActionV7("dissolve");
    } catch (e) {
      code = e.code;
    }
    assert.equal(code, "UNKNOWN_ROOT_ACTION", `${name}: an unknown root action must fail closed`);
  }
});

/* ------------------------------------------------------------------ */
/* transitions and budgets                                              */
/* ------------------------------------------------------------------ */

test("root successor derivation is identical across runtimes for every action", () => {
  const v = ROOT_STATE_V7_VECTORS[1];
  const newSet = { owners: [...v.state.owners.slice(0, 2), ...v.state.owners.slice(2)], ownerM: "3", emergencyK: "2", recoveryM: "2" };
  const rows = [
    ["authorize", {}],
    ["freeze", {}],
    ["rotate", { newOwnerSet: newSet }],
    ["ownerRecover", { newOwnerSet: { owners: v.state.owners, ownerM: "2", emergencyK: "1", recoveryM: "1" } }]
  ];
  for (const [action, params] of rows) {
    const planNode = transNode.rootTransitionV7(action, v.state, { ...params, template: v.template });
    const planSandbox = transSandbox.rootTransitionV7(action, rehomeInto(sandbox.global, v.state), rehomeInto(sandbox.global, { ...params, template: v.template }));
    assert.equal(planSandbox.newStateDigest, planNode.newStateDigest, `${action}: the successor digest must agree`);
    assert.equal(planSandbox.tailHex, planNode.tailHex, `${action}: the successor TAIL bytes must agree`);
    assert.equal(planSandbox.requiredApprovals.toString(), planNode.requiredApprovals.toString(), `${action}: the required quorum must agree`);
    assert.equal(planSandbox.class, planNode.class, `${action}: the authority class must agree`);
    assert.equal(planSandbox.minSequence.toString(), planNode.minSequence.toString(), `${action}: the relative-age gate must agree`);
  }
  /* unfreeze on an unfrozen root fails closed in both */
  for (const [mod, global, name] of [[transNode, null, "node"], [transSandbox, sandbox.global, "sandbox"]]) {
    let code = null;
    try {
      mod.rootTransitionV7("unfreeze", global ? rehomeInto(global, v.state) : v.state, global ? rehomeInto(global, { template: v.template }) : { template: v.template });
    } catch (e) {
      code = e.code;
    }
    assert.equal(code, "NOT_FROZEN", `${name}: unfreezing an unfrozen root must fail closed`);
  }
});

for (const op of BUDGET_V7_ROOT_OPERATIONS) {
  test(`root compute budget equivalence: ${op.actionName} @ ${op.activeOwnerSlots} active slots`, () => {
    const a = budgetNode.selectRootComputeBudgetV7(op);
    const b = budgetSandbox.selectRootComputeBudgetV7(rehomeInto(sandbox.global, op));
    assert.equal(typeof a, "number");
    assert.equal(b, a, "a committed budget that differed across runtimes would make a valid transaction fail on a node");
  });
}

for (const op of BUDGET_V7_VAULT_OPERATIONS) {
  test(`rooted-vault compute budget equivalence: ${op.operation}`, () => {
    const a = budgetNode.selectComputeBudgetV7(op);
    const b = budgetSandbox.selectComputeBudgetV7(rehomeInto(sandbox.global, op));
    assert.equal(b, a);
  });
}

test("compute-budget reject paths fail closed identically", () => {
  for (const [mod, global, name] of [[budgetNode, null, "node"], [budgetSandbox, sandbox.global, "sandbox"]]) {
    assert.throws(() => mod.selectRootComputeBudgetV7(global ? rehomeInto(global, { actionName: "dissolve", activeOwnerSlots: 3 }) : { actionName: "dissolve", activeOwnerSlots: 3 }), /unknown v0.7 root action/, `${name}: an unknown root action must fail closed`);
    assert.throws(() => mod.selectComputeBudgetV7(global ? rehomeInto(global, { operation: "delegateSpend", templatePrefixLen: 1, templateSuffixLen: 1521 }) : { operation: "delegateSpend", templatePrefixLen: 1, templateSuffixLen: 1521 }), /unknown v0.7 rooted-vault operation/, `${name}: an unknown vault operation must fail closed`);
  }
});
