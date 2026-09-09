"use strict";

/*
 * CROSS-RUNTIME EQUIVALENCE — the v0.7-kas ROOTED KAS SAFE-PAYMENT VAULT
 * core modules (vault-state-v7-kas.js, vault-transitions-v7-kas.js,
 * compute-budget-v7-kas.js).
 *
 * Sibling of core/crossruntime/test/v7-org-root-portability.test.js. SAME
 * discipline: the SAME raw, JSON-safe vector goes into each runtime's OWN
 * copy of the pipeline (a fresh V8 context with `window` as its global and
 * NO require/module/process/Buffer, plus the exact crypto shim a real
 * browser gets), and only the final primitive outputs are compared.
 *
 * Why this matters here specifically: this profile's template normalizer
 * (normalizeTemplateV7Kas) pins the rootStateLen geometry a rooted vault
 * slices the organizational root's revealed redeem by, and its mutable-
 * state math DELEGATES to the frozen v0.4.1 core modules
 * (vault-state-v4.js, vault-transitions-v4.js, agent-merkle-v4.js,
 * recipient-merkle-v3.js) rather than restating them — this suite proves
 * that delegation is portable too, not merely that the new v0.7-kas files
 * happen to load. A rule that fails closed in Node and passes in a browser
 * (or vice versa) would be a silent authority hole.
 *
 * SCOPE NOTE, as in the sibling probe: core/model is NOT part of the
 * reviewed web/core-bundle.js MODULES list, so this is a forward-looking
 * portability probe on the committed source, not a claim about the shipped
 * bundle. The v0.7-kas intent/manifest layer (core/intent/org-root-
 * manifest-v7-kas.js) is likewise NOT covered here, matching the payment
 * profile's own precedent (core/intent/org-root-manifest-v7.js is not
 * covered by any existing crossruntime test either) — an honest, explicitly
 * recorded scope limitation, not an oversight.
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");

const { loadCoreFilesInSandbox, rehome, rehomeInto } = require("../sandbox.js");

/* Every v0.7-kas core file plus its transitive core/model dependencies
 * (the frozen v0.4.1 modules it delegates to, and the shared v0.7 root
 * modules its owner-authority overlay reuses). */
const V7_KAS_FILES = Object.freeze([
  "core/model/amounts.js",
  "core/model/contract-version.js",
  "core/model/vault-state.js",
  "core/model/own-get.js",
  "core/model/vault-state-v4.js",
  "core/model/agent-merkle-v4.js",
  "core/model/recipient-merkle-v3.js",
  "core/model/vault-transitions-v4.js",
  "core/model/owner-set-v7.js",
  "core/model/vault-state-v7-root.js",
  "core/model/vault-state-v7-kas.js",
  "core/model/vault-transitions-v7-root.js",
  "core/model/vault-transitions-v7-kas.js",
  "core/model/compute-budget-v7.js",
  "core/model/compute-budget-v7-kas.js"
]);

const sandbox = loadCoreFilesInSandbox(V7_KAS_FILES);

const V7_KAS_OWN_FILES = ["core/model/vault-state-v7-kas.js", "core/model/vault-transitions-v7-kas.js", "core/model/compute-budget-v7-kas.js"];

for (const relPath of V7_KAS_OWN_FILES) {
  test(`smoke: ${relPath} loads in the browser-like sandbox with the SAME export key set as Node`, () => {
    const nodeMod = require(`../../../${relPath}`);
    const sandboxMod = sandbox.require(relPath);
    assert.deepEqual(Object.keys(sandboxMod).sort(), Object.keys(nodeMod).sort());
  });
}

const stateNode = require("../../model/vault-state-v7-kas.js");
const stateSandbox = sandbox.require("core/model/vault-state-v7-kas.js");
const transNode = require("../../model/vault-transitions-v7-kas.js");
const transSandbox = sandbox.require("core/model/vault-transitions-v7-kas.js");
const budgetNode = require("../../model/compute-budget-v7-kas.js");
const budgetSandbox = sandbox.require("core/model/compute-budget-v7-kas.js");

const ZERO32 = "00".repeat(32);
function xonly(byte) {
  return byte.repeat(32);
}
function stringifyBigInts(value) {
  if (typeof value === "bigint") return value.toString();
  if (Array.isArray(value)) return value.map(stringifyBigInts);
  if (value && typeof value === "object") {
    const out = {};
    for (const [k, v] of Object.entries(value)) out[k] = stringifyBigInts(v);
    return out;
  }
  return value;
}

const TEMPLATE_VECTORS = Object.freeze([
  {
    label: "genesis-shaped template, no active approvers",
    template: { vaultId: xonly("44"), orgRootCovenantId: xonly("a7"), rootTemplateVmHash: xonly("b7"), rootPrefixLen: 1, rootStateLen: 467, rootSuffixLen: 349, recoveryPk: xonly("51") },
    state: { protectedValue: "1000000000", feeReserve: "500000000", paused: "0", agentRoot: ZERO32, approvers: [], approvalM: "0", policyNonce: "0" }
  },
  {
    label: "3 active approvers, M=2, nonzero policyNonce",
    template: { vaultId: xonly("55"), orgRootCovenantId: xonly("a8"), rootTemplateVmHash: xonly("b8"), rootPrefixLen: 1, rootStateLen: 467, rootSuffixLen: 349, recoveryPk: xonly("52") },
    state: { protectedValue: "999900000000", feeReserve: "600000000", paused: "1", agentRoot: xonly("cd"), approvers: [xonly("91"), xonly("92"), xonly("93")], approvalM: "2", policyNonce: "7" }
  }
]);

/* ------------------------------------------------------------------ */
/* template + state normalization, id, and reject paths                */
/* ------------------------------------------------------------------ */

for (const v of TEMPLATE_VECTORS) {
  test(`template/state normalization + state id equivalence: ${v.label}`, () => {
    const tNode = stateNode.normalizeTemplateV7Kas(v.template);
    const sNode = stateNode.normalizeStateV7Kas(v.state);
    const idNode = stateNode.computeStateIdV7Kas({ networkId: "testnet-10", template: tNode, state: sNode });
    const jsonNode = stateNode.stateToJsonV7Kas(sNode);
    const templateJsonNode = stateNode.templateToJsonV7Kas(tNode);

    const tSandbox = stateSandbox.normalizeTemplateV7Kas(rehomeInto(sandbox.global, v.template));
    const sSandbox = stateSandbox.normalizeStateV7Kas(rehomeInto(sandbox.global, v.state));
    const idSandbox = stateSandbox.computeStateIdV7Kas({ networkId: "testnet-10", template: tSandbox, state: sSandbox });
    const jsonSandbox = stateSandbox.stateToJsonV7Kas(sSandbox);
    const templateJsonSandbox = stateSandbox.templateToJsonV7Kas(tSandbox);

    assert.match(idNode, /^[0-9a-f]{64}$/);
    assert.equal(idSandbox, idNode, `${v.label}: the state id must be byte-identical across runtimes`);
    assert.deepEqual(rehome(stringifyBigInts(jsonSandbox)), rehome(stringifyBigInts(jsonNode)), `${v.label}: the JSON state form must agree`);
    assert.deepEqual(rehome(templateJsonSandbox), rehome(templateJsonNode), `${v.label}: the JSON template form must agree`);
  });
}

test("template reject paths fail closed identically (root geometry, sentinel root pin)", () => {
  const base = TEMPLATE_VECTORS[0].template;
  const rows = [
    ["wrong rootStateLen", { ...base, rootStateLen: 466 }, "ROOT_GEOMETRY_MISMATCH"],
    ["rootStateLen <= tail length", { ...base, rootStateLen: 11, rootPrefixLen: 1, rootSuffixLen: 0 }, "ROOT_GEOMETRY_MISMATCH"],
    ["sentinel orgRootCovenantId", { ...base, orgRootCovenantId: ZERO32 }, "ROOT_PIN_MISSING"]
  ];
  for (const [label, bad, code] of rows) {
    let nodeCode = null;
    let sandboxCode = null;
    try {
      stateNode.normalizeTemplateV7Kas(bad);
    } catch (e) {
      nodeCode = e.code;
    }
    try {
      stateSandbox.normalizeTemplateV7Kas(rehomeInto(sandbox.global, bad));
    } catch (e) {
      sandboxCode = e.code;
    }
    assert.equal(nodeCode, code, `${label}: Node must refuse with ${code}`);
    assert.equal(sandboxCode, nodeCode, `${label}: both runtimes must refuse with the same code`);
  }
});

test("unknown contractVersion fails closed identically in both runtimes", () => {
  for (const [mod, global, name] of [
    [stateNode, null, "node"],
    [stateSandbox, sandbox.global, "sandbox"]
  ]) {
    let code = null;
    try {
      mod.resolveV7KasAbi("policyvault-0.7-kas-v2");
    } catch (e) {
      code = e.code;
    }
    assert.equal(code, "UNKNOWN_VERSION", `${name}: an unknown v0.7-kas contract version must fail closed`);
  }
});

/* ------------------------------------------------------------------ */
/* owner-op + delegate-spend successor derivation (delegates to v4)    */
/* ------------------------------------------------------------------ */

test("ownerOpSuccessorV7Kas is identical across runtimes for every selector", () => {
  const t = TEMPLATE_VECTORS[1].template;
  const s = stateNode.normalizeStateV7Kas(TEMPLATE_VECTORS[1].state); // paused: "1"
  const sSandboxState = stateSandbox.normalizeStateV7Kas(rehomeInto(sandbox.global, TEMPLATE_VECTORS[1].state));
  const unpausedInput = { ...TEMPLATE_VECTORS[1].state, paused: "0" };
  const sUnpaused = stateNode.normalizeStateV7Kas(unpausedInput);
  const sUnpausedSandbox = stateSandbox.normalizeStateV7Kas(rehomeInto(sandbox.global, unpausedInput));
  void t;
  const rows = [
    ["ownerSetAgentRoot", s, sSandboxState, { newAgentRoot: xonly("ee") }],
    ["ownerTopUp", s, sSandboxState, { topUpAmountSompi: "12345" }],
    ["ownerTopUpReserve", s, sSandboxState, { topUpReserveAmountSompi: "999" }],
    ["ownerUnpause", s, sSandboxState, {}], // predecessor already paused: "1"
    ["ownerEmergencyPause", sUnpaused, sUnpausedSandbox, {}] // predecessor unpaused: "0"
  ];
  for (const [action, base, baseSandbox, params] of rows) {
    const planNode = transNode.ownerOpSuccessorV7Kas(action, base, params);
    const planSandbox = transSandbox.ownerOpSuccessorV7Kas(action, baseSandbox, rehomeInto(sandbox.global, params));
    assert.equal(planSandbox.opSelector, planNode.opSelector, `${action}: opSelector must agree`);
    assert.equal(planSandbox.rootAuthority.rootActionName, planNode.rootAuthority.rootActionName, `${action}: required root action must agree`);
    assert.equal(planSandbox.rootAuthority.expectFrozenAfter.toString(), planNode.rootAuthority.expectFrozenAfter.toString(), `${action}: expected frozen byte must agree`);
    assert.equal(planSandbox.externalFunding.toString(), planNode.externalFunding.toString(), `${action}: externalFunding must agree`);
    assert.deepEqual(rehome(stringifyBigInts(stateSandbox.stateToJsonV7Kas(planSandbox.successor))), rehome(stringifyBigInts(stateNode.stateToJsonV7Kas(planNode.successor))), `${action}: successor state must agree`);
  }
  /* unknown owner action fails closed identically (each realm's OWN
   * already-normalized state — an already-normalized state carries BigInt
   * fields, which cannot cross rehomeInto's host-side JSON.stringify) */
  for (const [mod, base, name] of [
    [transNode, s, "node"],
    [transSandbox, sSandboxState, "sandbox"]
  ]) {
    let code = null;
    try {
      mod.ownerOpSuccessorV7Kas("ownerDissolve", base, {});
    } catch (e) {
      code = e.code;
    }
    assert.equal(code, "UNKNOWN_ACTION", `${name}: an unknown owner action must fail closed`);
  }
});

test("recoverPlanV7Kas pays the genesis-pinned recoveryPk identically across runtimes", () => {
  const t = TEMPLATE_VECTORS[1].template;
  const s = stateNode.normalizeStateV7Kas(TEMPLATE_VECTORS[1].state);
  const planNode = transNode.recoverPlanV7Kas(s, t);
  const planSandbox = transSandbox.recoverPlanV7Kas(stateSandbox.normalizeStateV7Kas(rehomeInto(sandbox.global, TEMPLATE_VECTORS[1].state)), rehomeInto(sandbox.global, t));
  assert.equal(planNode.payoutXOnly, t.recoveryPk);
  assert.equal(planSandbox.payoutXOnly, planNode.payoutXOnly, "the recovery destination must be byte-identical across runtimes");
  assert.equal(planSandbox.payoutValue.toString(), planNode.payoutValue.toString());
  assert.equal(planSandbox.rootAuthority.expectFrozenAfter.toString(), planNode.rootAuthority.expectFrozenAfter.toString());
});

test("agentSpendSuccessorV7Kas (D2 zero-length-period hardening) fails closed identically across runtimes", () => {
  const agentKey = xonly("30");
  const recipientRoot = xonly("cc");
  const agentPolicy = { agentPk: agentKey, maxPerSpend: "20000000000", periodBudget: "50000000000", periodLengthDaa: "0", periodStartDaa: "541000000", periodSpent: "0", approvalThreshold: "10000000000000", agentMaxFeePerTx: "100000000", agentRecipientRoot: recipientRoot };
  const rawState = { protectedValue: "1000000000000", feeReserve: "500000000", paused: "0", agentRoot: xonly("11"), approvers: [], approvalM: "0", policyNonce: "0" };
  /* NOTE: periodsElapsed/reserveConsumed/pathBits are digit STRINGS here
   * (not raw BigInt) — rehomeInto's host-side JSON.stringify step cannot
   * cross a real BigInt (or an already-normalized state object, whose
   * fields ARE BigInt) into the sandbox realm (documented in its own
   * header comment: "callers with a raw BigInt ... must render it to a
   * string themselves first"); parseSompi/BigInt(...) accept a digit
   * string identically to a BigInt in both agentSpendSuccessorV4 and the
   * D2 check itself, so this is not a weaker test. Each realm normalizes
   * the RAW (JSON-safe) state input itself, exactly like every other test
   * in this file. */
  const params = { agentPolicy, agentProof: { siblingsHex: "", pathBits: "0" }, payAmount: "1000000000", periodsElapsed: "1", reserveConsumed: "0" };
  for (const [mod, stateMod, global, name] of [
    [transNode, stateNode, null, "node"],
    [transSandbox, stateSandbox, sandbox.global, "sandbox"]
  ]) {
    const s = global ? stateMod.normalizeStateV7Kas(rehomeInto(global, rawState)) : stateMod.normalizeStateV7Kas(rawState);
    let code = null;
    try {
      mod.agentSpendSuccessorV7Kas(s, global ? rehomeInto(global, params) : params);
    } catch (e) {
      code = e.code;
    }
    assert.equal(code, "D2_ZERO_LENGTH_PERIOD", `${name}: a zero-length period must fail closed`);
  }
});

/* ------------------------------------------------------------------ */
/* compute-budget equivalence                                          */
/* ------------------------------------------------------------------ */

const BUDGET_OPS = Object.freeze([
  { operation: "agentSpend", rootPrefixLen: 1, rootSuffixLen: 349, agentTreeDepth: 0, recipientDepth: 0, approvalsChecked: 0, rollover: false },
  { operation: "agentSpend", rootPrefixLen: 1, rootSuffixLen: 349, agentTreeDepth: 12, recipientDepth: 16, approvalsChecked: 10, rollover: false },
  { operation: "agentSpend", rootPrefixLen: 1, rootSuffixLen: 349, agentTreeDepth: 0, recipientDepth: 0, approvalsChecked: 0, rollover: true },
  { operation: "ownerSetAgentRoot", rootPrefixLen: 1, rootSuffixLen: 349 },
  { operation: "ownerSetApprovers", rootPrefixLen: 1, rootSuffixLen: 349 },
  { operation: "ownerTopUp", rootPrefixLen: 1, rootSuffixLen: 349 },
  { operation: "ownerTopUpReserve", rootPrefixLen: 1, rootSuffixLen: 349 },
  { operation: "ownerPause", rootPrefixLen: 1, rootSuffixLen: 349 },
  { operation: "ownerUnpause", rootPrefixLen: 1, rootSuffixLen: 349 },
  { operation: "ownerEmergencyPause", rootPrefixLen: 1, rootSuffixLen: 349 },
  { operation: "ownerRecover", rootPrefixLen: 1, rootSuffixLen: 349 }
]);

for (const op of BUDGET_OPS) {
  test(`v0.7-kas compute budget equivalence: ${op.operation} (agentDepth=${op.agentTreeDepth ?? "-"}, approvals=${op.approvalsChecked ?? "-"})`, () => {
    const a = budgetNode.selectComputeBudgetV7Kas(op);
    const b = budgetSandbox.selectComputeBudgetV7Kas(rehomeInto(sandbox.global, op));
    assert.equal(typeof a, "number");
    assert.equal(b, a, "a committed budget that differed across runtimes would make a valid transaction fail on a node");
  });
}

test("v0.7-kas compute-budget reject paths fail closed identically", () => {
  for (const [mod, global, name] of [
    [budgetNode, null, "node"],
    [budgetSandbox, sandbox.global, "sandbox"]
  ]) {
    assert.throws(
      () => mod.selectComputeBudgetV7Kas(global ? rehomeInto(global, { operation: "ownerDissolve", rootPrefixLen: 1, rootSuffixLen: 349 }) : { operation: "ownerDissolve", rootPrefixLen: 1, rootSuffixLen: 349 }),
      /unknown v0.7-kas rooted-vault operation/,
      `${name}: an unknown vault operation must fail closed`
    );
  }
});

test("v0.7-kas budget model re-exports selectRootComputeBudgetV7 unchanged (the root side is byte-for-byte shared)", () => {
  const op = { actionName: "authorize", activeOwnerSlots: 3 };
  const a = budgetNode.selectRootComputeBudgetV7(op);
  const b = budgetSandbox.selectRootComputeBudgetV7(rehomeInto(sandbox.global, op));
  assert.equal(typeof a, "number");
  assert.equal(b, a);
});
