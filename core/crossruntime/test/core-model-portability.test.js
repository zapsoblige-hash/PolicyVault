"use strict";

/*
 * Cross-runtime PORTABILITY PROBE for core/model (PostLaunchUpgradeOG
 * cross-runtime equivalence battery: "state IDs (computeStateIdV4 etc.);
 * fee/mass + budget outputs").
 *
 * IMPORTANT SCOPE NOTE: core/model is NOT (yet) part of
 * web/tools/build-core-bundle.js's reviewed MODULES list — only
 * core/intent, core/explain, and core/signer ship in web/core-bundle.js
 * today (docs/postlaunch/browser-verification.md §2). This file therefore
 * does NOT test "the shipped bundle" for core/model; it tests something
 * narrower but still valuable: whether core/model's OWN, UNMODIFIED
 * source files would ALREADY run identically in a browser-like
 * environment (no require/module/process/Buffer; the exact crypto shim
 * real browsers get) if a future wave added them to the bundle. Every
 * comparison below feeds the SAME raw, JSON-safe vector into each
 * runtime's OWN copy of the pipeline (normalize -> compute) independently
 * — see ../sandbox.js and ../vectors.js.
 *
 * HISTORY (see docs/postlaunch/cross-runtime-equivalence.md): the browser
 * wave found a TIER 2 gap — agent-merkle-v4, recipient-merkle-v3, and
 * (transitively) vault-transitions-v4 could NOT load in a Buffer-free
 * sandbox (ambient Node `Buffer` usage + a byte-shaped
 * `createHash().update(<Buffer>).digest()` outside the crypto shim's
 * string-only surface). The F1 browser-portability wave CLOSED that gap:
 * the two Merkle modules are byte-native (Uint8Array) with byte identity
 * pinned by core/model/test/golden-f1-merkle.test.js, and the bundle
 * crypto shim now supports exactly `update(<Uint8Array>)` / `digest()`
 * alongside the original string surface. ALL 14 core/model files now
 * load and run byte-identically in the browser-like sandbox; the former
 * TIER 2 gap tests below became full cross-runtime equivalence tests
 * (roots, proofs, folds, reject identities).
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");

const { loadCoreFilesInSandbox, rehome, rehomeInto } = require("../sandbox.js");
const { CANONICAL_JSON_VECTORS, reverseKeysDeep, STATE_ID_V4_VECTORS, STATE_ID_V1_VECTORS, FEE_MASS_TX_VECTORS, BUDGET_V4_OPERATIONS, BUDGET_V3_OPERATIONS, REPRESENTATIVE_SOMPI, MAX_SOMPI_STRING, OVER_MAX_SOMPI_STRING, stringifyBigInts } = require("../vectors.js");

const TIER1_FILES = Object.freeze([
  "core/model/amounts.js",
  "core/model/contract-version.js",
  "core/model/canonical-json.js",
  "core/model/vault-state.js",
  "core/model/vault-state-v2.js",
  "core/model/vault-state-v3.js",
  "core/model/vault-state-v4.js",
  "core/model/vault-transitions-v3.js",
  "core/model/fee-mass.js",
  "core/model/compute-budget-v3.js",
  "core/model/compute-budget-v4.js",
  /* Former TIER 2 — portable since the F1 byte-native Merkle refactor: */
  "core/model/agent-merkle-v4.js",
  "core/model/recipient-merkle-v3.js",
  "core/model/vault-transitions-v4.js"
]);
const ALL_MODEL_FILES = TIER1_FILES;

const sandbox = loadCoreFilesInSandbox(ALL_MODEL_FILES);

/* ------------------------------------------------------------------ */
/* TIER 1 — smoke: every file loads and exports the same surface        */
/* ------------------------------------------------------------------ */

for (const relPath of TIER1_FILES) {
  test(`TIER1 smoke: ${relPath} loads in the browser-like sandbox with the SAME export key set as Node`, () => {
    const nodeMod = require(`../../../${relPath}`);
    const sandboxMod = sandbox.require(relPath);
    assert.deepEqual(Object.keys(sandboxMod).sort(), Object.keys(nodeMod).sort());
  });
}

/* ------------------------------------------------------------------ */
/* state IDs — computeStateIdV4 and computeStateId (v1)                  */
/* ------------------------------------------------------------------ */

const vaultStateV4Node = require("../../model/vault-state-v4.js");
const vaultStateV4Sandbox = sandbox.require("core/model/vault-state-v4.js");
const vaultStateNode = require("../../model/vault-state.js");
const vaultStateSandbox = sandbox.require("core/model/vault-state.js");

for (const vector of STATE_ID_V4_VECTORS) {
  test(`computeStateIdV4 equivalence: ${vector.label}`, () => {
    const tplNode = vaultStateV4Node.normalizeTemplateV4(vector.template);
    const stateNode = vaultStateV4Node.normalizeStateV4(vector.state);
    const idNode = vaultStateV4Node.computeStateIdV4({ networkId: vector.networkId, template: tplNode, state: stateNode, contractVersion: vector.contractVersion });

    const tplSandbox = vaultStateV4Sandbox.normalizeTemplateV4(rehomeInto(sandbox.global, vector.template));
    const stateSandbox = vaultStateV4Sandbox.normalizeStateV4(rehomeInto(sandbox.global, vector.state));
    const idSandbox = vaultStateV4Sandbox.computeStateIdV4({ networkId: vector.networkId, template: tplSandbox, state: stateSandbox, contractVersion: vector.contractVersion });

    assert.match(idNode, /^[0-9a-f]{64}$/, "sanity: a real sha256 hex digest");
    assert.equal(idSandbox, idNode, `${vector.label}: stateId must be byte-identical across runtimes`);
  });
}

test("computeStateIdV4 reject-path equivalence: empty networkId fails closed identically", () => {
  const v = STATE_ID_V4_VECTORS[0];
  const tplNode = vaultStateV4Node.normalizeTemplateV4(v.template);
  const stateNode = vaultStateV4Node.normalizeStateV4(v.state);
  assert.throws(() => vaultStateV4Node.computeStateIdV4({ networkId: "", template: tplNode, state: stateNode }), /networkId is required/);

  const tplSandbox = vaultStateV4Sandbox.normalizeTemplateV4(rehomeInto(sandbox.global, v.template));
  const stateSandbox = vaultStateV4Sandbox.normalizeStateV4(rehomeInto(sandbox.global, v.state));
  assert.throws(() => vaultStateV4Sandbox.computeStateIdV4({ networkId: "", template: tplSandbox, state: stateSandbox }), /networkId is required/);
});

for (const vector of STATE_ID_V1_VECTORS) {
  test(`computeStateId (v1) equivalence: ${vector.label}`, () => {
    const policyNode = vaultStateNode.normalizePolicy(vector.policy);
    const stateNode = vaultStateNode.normalizeState(vector.state);
    const idNode = vaultStateNode.computeStateId({ networkId: vector.networkId, policy: policyNode, state: stateNode });

    const policySandbox = vaultStateSandbox.normalizePolicy(rehomeInto(sandbox.global, vector.policy));
    const stateSandbox = vaultStateSandbox.normalizeState(rehomeInto(sandbox.global, vector.state));
    const idSandbox = vaultStateSandbox.computeStateId({ networkId: vector.networkId, policy: policySandbox, state: stateSandbox });

    assert.equal(idSandbox, idNode, `${vector.label}: v1 stateId must be byte-identical across runtimes`);
  });
}

/* ------------------------------------------------------------------ */
/* fee/mass                                                              */
/* ------------------------------------------------------------------ */

const feeMassNode = require("../../model/fee-mass.js");
const feeMassSandbox = sandbox.require("core/model/fee-mass.js");

for (const vector of FEE_MASS_TX_VECTORS) {
  test(`fee-mass equivalence: ${vector.label}`, () => {
    const rNode = feeMassNode.calculateRequiredFee(vector.tx);
    const rSandbox = feeMassSandbox.calculateRequiredFee(rehomeInto(sandbox.global, vector.tx));
    assert.deepEqual(rehome(stringifyBigInts(rSandbox)), rehome(stringifyBigInts(rNode)), `${vector.label}: fee/mass fields must be byte-identical`);
  });
}

test("fee-mass reject-path equivalence: exceeding the standard mass cap fails closed identically", () => {
  const overCap = { version: 1, payloadHex: "", inputs: [{ signatureScriptHex: "ab".repeat(300000), computeBudget: 10 }], outputs: [{ scriptHex: "cd".repeat(34), hasCovenant: false }] };
  assert.throws(() => feeMassNode.calculateRequiredFee(overCap), /exceeds the standard mass cap/);
  assert.throws(() => feeMassSandbox.calculateRequiredFee(rehomeInto(sandbox.global, overCap)), /exceeds the standard mass cap/);
});

/* ------------------------------------------------------------------ */
/* compute budgets v3 / v4                                              */
/* ------------------------------------------------------------------ */

const budgetV4Node = require("../../model/compute-budget-v4.js");
const budgetV4Sandbox = sandbox.require("core/model/compute-budget-v4.js");
const budgetV3Node = require("../../model/compute-budget-v3.js");
const budgetV3Sandbox = sandbox.require("core/model/compute-budget-v3.js");

test("compute-budget-v4 selectComputeBudgetV4/assertBudgetSufficientV4 equivalence over every v0.4 operation", () => {
  assert.deepEqual(rehome(budgetV4Sandbox.V4_BUDGET), rehome(budgetV4Node.V4_BUDGET));
  for (const op of BUDGET_V4_OPERATIONS) {
    const vNode = budgetV4Node.selectComputeBudgetV4(op);
    const vSandbox = budgetV4Sandbox.selectComputeBudgetV4(op);
    assert.equal(vSandbox, vNode, JSON.stringify(op));
    assert.equal(budgetV4Sandbox.assertBudgetSufficientV4({ ...op, committed: vNode }), budgetV4Node.assertBudgetSufficientV4({ ...op, committed: vNode }));
  }
  let nodeMsg = null;
  try {
    budgetV4Node.selectComputeBudgetV4({ operation: "notAnOperation" });
  } catch (e) {
    nodeMsg = e.message;
  }
  let sandboxMsg = null;
  try {
    budgetV4Sandbox.selectComputeBudgetV4({ operation: "notAnOperation" });
  } catch (e) {
    sandboxMsg = e.message;
  }
  assert.match(nodeMsg, /unknown v0\.4 operation/);
  assert.equal(sandboxMsg, nodeMsg);
});

test("compute-budget-v3 selectComputeBudgetV3/assertBudgetSufficient equivalence over every v0.3 operation", () => {
  assert.deepEqual(rehome(budgetV3Sandbox.V3_BUDGET), rehome(budgetV3Node.V3_BUDGET));
  for (const op of BUDGET_V3_OPERATIONS) {
    const vNode = budgetV3Node.selectComputeBudgetV3(op);
    const vSandbox = budgetV3Sandbox.selectComputeBudgetV3(op);
    assert.equal(vSandbox, vNode, JSON.stringify(op));
  }
});

/* ------------------------------------------------------------------ */
/* canonical-json.js (core/model) — cross-implementation + cross-runtime */
/* ------------------------------------------------------------------ */

const canonicalJsonModelNode = require("../../model/canonical-json.js");
const canonicalJsonModelSandbox = sandbox.require("core/model/canonical-json.js");
const canonicalJsonIntentNode = require("../../intent/canonical.js");

for (const vector of CANONICAL_JSON_VECTORS) {
  test(`canonical-json THREE-WAY equivalence (core/model node, core/model sandbox, core/intent node) for ${JSON.stringify(vector).slice(0, 50)}`, () => {
    const viaModelNode = canonicalJsonModelNode.canonicalJsonStringify(vector);
    const viaModelSandbox = canonicalJsonModelSandbox.canonicalJsonStringify(rehomeInto(sandbox.global, vector));
    const viaIntentNode = canonicalJsonIntentNode.canonicalJsonStringify(vector);
    assert.equal(viaModelSandbox, viaModelNode, "core/model/canonical-json.js must agree with itself across runtimes");
    assert.equal(viaIntentNode, viaModelNode, "core/intent/canonical.js and core/model/canonical-json.js are independently-maintained TWINS (both mirror the same G-2 remediation semantics) and must serialize identically");
  });
}

test("canonical-json reject-path equivalence: BigInt/undefined/non-finite/function all fail closed with the SAME code, across implementations", () => {
  const rejects = [{ v: 1n }, { v: undefined }, { v: NaN }, { v: Infinity }, { v: () => 1 }];
  for (const bad of rejects) {
    let codeModelNode = null;
    try {
      canonicalJsonModelNode.canonicalJsonStringify(bad);
    } catch (e) {
      codeModelNode = e.code;
    }
    let codeIntentNode = null;
    try {
      canonicalJsonIntentNode.canonicalJsonStringify(bad);
    } catch (e) {
      codeIntentNode = e.code;
    }
    assert.equal(codeModelNode, "CANONICAL_JSON_INVALID", JSON.stringify(String(bad.v)));
    assert.equal(codeIntentNode, codeModelNode);
  }

  /* BigInt/undefined/function cannot survive a JSON round trip at all
   * (JSON.stringify itself throws on BigInt, and silently drops
   * undefined/function members) so rehomeInto cannot carry them into the
   * sandbox; NaN CAN be expressed as a sandbox-realm-native object
   * literal directly (no rehoming needed for a plain `{ v: NaN }`),
   * which is enough to prove the sandboxed copy fails closed the same
   * way as both host-realm copies above. */
  let nanCodeSandbox = null;
  try {
    canonicalJsonModelSandbox.canonicalJsonStringify({ v: NaN });
  } catch (e) {
    nanCodeSandbox = e.code;
  }
  assert.equal(nanCodeSandbox, "CANONICAL_JSON_INVALID");
});

test("canonical-json REALM-SENSITIVITY finding: a raw cross-realm plain object is refused as non-plain (documented, not a bug — see cross-runtime-equivalence.md)", () => {
  /* Reproduces, precisely, the finding this suite's own harness had to
   * work around (sandbox.js `rehome`/`rehomeInto` doc comments): both
   * canonicalJsonStringify twins detect "plain object" via
   * `Object.getPrototypeOf(v) === Object.prototype` against the CALLING
   * code's OWN realm. A structurally plain object built in a DIFFERENT
   * realm (here: the sandbox) fails that identity check when handed,
   * unconverted, to the HOST realm's canonicalJsonStringify. */
  const sandboxRealmObject = sandbox.require("core/model/vault-state-v4.js").normalizeTemplateV4({ owner: "11".repeat(32), vaultId: "22".repeat(32) });
  assert.throws(() => canonicalJsonModelNode.canonicalJsonStringify(sandboxRealmObject), (e) => e.code === "CANONICAL_JSON_INVALID");
  /* re-homed, it canonicalizes normally: */
  assert.doesNotThrow(() => canonicalJsonModelNode.canonicalJsonStringify(rehome(sandboxRealmObject)));
});

/* ------------------------------------------------------------------ */
/* amounts.js <-> core/explain/kas.js cross-IMPLEMENTATION pairing       */
/* ------------------------------------------------------------------ */

const amountsNode = require("../../model/amounts.js");
const amountsSandbox = sandbox.require("core/model/amounts.js");
const explainKas = require("../../explain/kas.js");

test("KAS rendering cross-implementation pairing: core/model/amounts.js sompiToKas === core/explain/kas.js sompiToKasString, over the representative + MAX_SOMPI domain", () => {
  for (const sompi of [...REPRESENTATIVE_SOMPI, MAX_SOMPI_STRING]) {
    const viaAmountsNode = amountsNode.sompiToKas(sompi);
    const viaAmountsSandbox = amountsSandbox.sompiToKas(sompi);
    const viaExplain = explainKas.sompiToKasString(sompi);
    assert.equal(viaAmountsSandbox, viaAmountsNode, `sompiToKas must agree across runtimes for ${sompi}`);
    assert.equal(viaExplain, viaAmountsNode, `core/explain/kas.js and core/model/amounts.js render ${sompi} KAS identically (independent implementations, same domain)`);
  }
});

test("MAX_SOMPI boundary equivalence: core/model/amounts.js parseSompi accepts the ceiling and refuses one above it, node and sandbox agree", () => {
  assert.equal(amountsNode.parseSompi(MAX_SOMPI_STRING).toString(), MAX_SOMPI_STRING);
  assert.equal(amountsSandbox.parseSompi(MAX_SOMPI_STRING).toString(), MAX_SOMPI_STRING);
  assert.throws(() => amountsNode.parseSompi(OVER_MAX_SOMPI_STRING), /exceeds maximum representable sompi/);
  assert.throws(() => amountsSandbox.parseSompi(OVER_MAX_SOMPI_STRING), /exceeds maximum representable sompi/);
});

/* ------------------------------------------------------------------ */
/* Merkle modules — full cross-runtime BYTE equivalence                  */
/* (the former TIER 2 gap, closed by the F1 byte-native refactor)        */
/* ------------------------------------------------------------------ */

const agentMerkleNode = require("../../model/agent-merkle-v4.js");
const agentMerkleSandbox = sandbox.require("core/model/agent-merkle-v4.js");
const recipientMerkleNode = require("../../model/recipient-merkle-v3.js");
const recipientMerkleSandbox = sandbox.require("core/model/recipient-merkle-v3.js");

const MERKLE_POLICY = (pkByte, over = {}) => ({
  agentPk: pkByte.repeat(32),
  maxPerSpend: "100000000",
  periodBudget: "1000000000",
  periodLengthDaa: "86400",
  periodStartDaa: "541000000",
  periodSpent: "0",
  approvalThreshold: "500000000",
  agentMaxFeePerTx: "100000",
  agentRecipientRoot: "cd".repeat(32),
  ...over
});

test("agent-merkle-v4 cross-runtime equivalence: constants, leaves, trees, proofs, folds, spend advance are byte-identical", () => {
  assert.equal(agentMerkleSandbox.PADDING_LEAF_HEX, agentMerkleNode.PADDING_LEAF_HEX);
  assert.deepEqual([...agentMerkleSandbox.AGENT_LEAF_DOMAIN], [...agentMerkleNode.AGENT_LEAF_DOMAIN]);
  assert.deepEqual([...agentMerkleSandbox.AGENT_PADDING_DOMAIN], [...agentMerkleNode.AGENT_PADDING_DOMAIN]);

  const policies = [MERKLE_POLICY("c3"), MERKLE_POLICY("a1"), MERKLE_POLICY("b2", { periodSpent: "9007199254740993", periodBudget: MAX_SOMPI_STRING })];
  const hexOf = (u8) => Buffer.from(u8).toString("hex");
  assert.equal(
    hexOf(agentMerkleSandbox.agentLeafPreimage(MERKLE_POLICY("a1"))),
    hexOf(agentMerkleNode.agentLeafPreimage(MERKLE_POLICY("a1"))),
    "124-byte leaf preimage bytes identical across runtimes"
  );
  assert.equal(hexOf(agentMerkleSandbox.agentLeafHash(MERKLE_POLICY("a1"))), hexOf(agentMerkleNode.agentLeafHash(MERKLE_POLICY("a1"))));

  const tNode = agentMerkleNode.buildAgentTreeV4(policies);
  const tSandbox = agentMerkleSandbox.buildAgentTreeV4(policies.map((p) => rehomeInto(sandbox.global, p)));
  assert.equal(tSandbox.root, tNode.root, "agent tree root byte-identical across runtimes");
  const levelsHex = (t) => JSON.parse(JSON.stringify([...t.levels].map((l) => [...l].map(hexOf)))); // realm-normalized
  assert.deepEqual(levelsHex(tSandbox), levelsHex(tNode), "every intermediate node identical");
  assert.equal(agentMerkleSandbox.buildAgentTreeV4([]).root, agentMerkleNode.buildAgentTreeV4([]).root, "empty registry root (padding leaf) identical");

  const pNode = agentMerkleNode.generateAgentProofV4(tNode, "a1".repeat(32));
  const pSandbox = agentMerkleSandbox.generateAgentProofV4(tSandbox, "a1".repeat(32));
  assert.equal(pSandbox.siblingsHex, pNode.siblingsHex);
  assert.equal(pSandbox.pathBits.toString(), pNode.pathBits.toString());
  assert.equal(
    agentMerkleSandbox.verifyAgentProofV4({ root: tSandbox.root, policy: rehomeInto(sandbox.global, MERKLE_POLICY("a1")), siblingsHex: pSandbox.siblingsHex, pathBits: pSandbox.pathBits }),
    true
  );

  const advNode = agentMerkleNode.applyAgentSpendV4(tNode, "a1".repeat(32), { newPeriodStartDaa: "541086400", newPeriodSpent: "250000000" });
  const advSandbox = agentMerkleSandbox.applyAgentSpendV4(tSandbox, "a1".repeat(32), rehomeInto(sandbox.global, { newPeriodStartDaa: "541086400", newPeriodSpent: "250000000" }));
  assert.equal(advSandbox.tree.root, advNode.tree.root, "successor root after accounting advance identical");
  assert.equal(
    agentMerkleSandbox.foldAgentPolicyV4(rehomeInto(sandbox.global, MERKLE_POLICY("a1")), pSandbox.siblingsHex, pSandbox.pathBits),
    agentMerkleNode.foldAgentPolicyV4(MERKLE_POLICY("a1"), pNode.siblingsHex, pNode.pathBits),
    "single-leaf fold identical"
  );
});

test("agent-merkle-v4 cross-runtime reject-path equivalence: fail-closed identities are identical", () => {
  let msgNode = null;
  try {
    agentMerkleNode.buildAgentTreeV4([MERKLE_POLICY("a1"), MERKLE_POLICY("a1", { maxPerSpend: "5" })]);
  } catch (e) {
    msgNode = `${e.message}|${e.code ?? ""}`;
  }
  let msgSandbox = null;
  try {
    agentMerkleSandbox.buildAgentTreeV4([rehomeInto(sandbox.global, MERKLE_POLICY("a1")), rehomeInto(sandbox.global, MERKLE_POLICY("a1", { maxPerSpend: "5" }))]);
  } catch (e) {
    msgSandbox = `${e.message}|${e.code ?? ""}`;
  }
  assert.match(msgNode, /duplicate agentPk/);
  assert.equal(msgSandbox, msgNode, "duplicate-agent refusal identical (message + code)");

  const t1Node = agentMerkleNode.buildAgentTreeV4([MERKLE_POLICY("a1")]);
  const t1Sandbox = agentMerkleSandbox.buildAgentTreeV4([rehomeInto(sandbox.global, MERKLE_POLICY("a1"))]);
  for (const [label, fn] of [
    ["node", () => agentMerkleNode.foldLeafV4("not-bytes", "", 0n)],
    ["sandbox", () => agentMerkleSandbox.foldLeafV4("not-bytes", "", 0n)]
  ]) {
    assert.throws(fn, /leaf must be a 32-byte Buffer/, `${label}: foldLeafV4 bad-leaf refusal identical`);
  }
  assert.throws(() => agentMerkleNode.generateAgentProofV4(t1Node, "77".repeat(32)), /is not in this tree/);
  assert.throws(() => agentMerkleSandbox.generateAgentProofV4(t1Sandbox, "77".repeat(32)), /is not in this tree/);
});

test("recipient-merkle-v3 cross-runtime equivalence: leaves, trees, proofs, verification are byte-identical", () => {
  assert.deepEqual([...recipientMerkleSandbox.LEAF_DOMAIN], [...recipientMerkleNode.LEAF_DOMAIN]);
  const hexOf = (u8) => Buffer.from(u8).toString("hex");
  const keys = ["ee".repeat(32), "aa".repeat(32), "cc".repeat(32), "bb".repeat(32), "dd".repeat(32)];
  assert.equal(hexOf(recipientMerkleSandbox.leafHash(keys[0])), hexOf(recipientMerkleNode.leafHash(keys[0])));

  const tNode = recipientMerkleNode.buildRecipientTree(keys);
  const tSandbox = recipientMerkleSandbox.buildRecipientTree(rehomeInto(sandbox.global, keys));
  assert.equal(tSandbox.root, tNode.root, "recipient tree root byte-identical across runtimes");
  assert.deepEqual([...tSandbox.recipients], [...tNode.recipients], "canonical sorted de-duplicated key order identical");
  const levelsHexR = (t) => JSON.parse(JSON.stringify([...t.levels].map((l) => [...l].map(hexOf)))); // realm-normalized
  assert.deepEqual(levelsHexR(tSandbox), levelsHexR(tNode), "every intermediate node identical (incl. duplicate-last padding)");

  for (const k of keys) {
    const pNode = recipientMerkleNode.generateRecipientProof(tNode, k);
    const pSandbox = recipientMerkleSandbox.generateRecipientProof(tSandbox, k);
    assert.equal(pSandbox.siblingsHex, pNode.siblingsHex, `${k}: siblings identical`);
    assert.equal(pSandbox.pathBits.toString(), pNode.pathBits.toString(), `${k}: pathBits identical`);
    assert.equal(
      recipientMerkleSandbox.verifyRecipientProof({ root: tSandbox.root, recipient: k, siblingsHex: pSandbox.siblingsHex, pathBits: pSandbox.pathBits }),
      true
    );
    assert.equal(
      recipientMerkleSandbox.verifyRecipientProof({ root: "00".repeat(32), recipient: k, siblingsHex: pSandbox.siblingsHex, pathBits: pSandbox.pathBits }),
      false
    );
  }
});

test("recipient-merkle-v3 cross-runtime reject-path equivalence: fail-closed identities are identical", () => {
  for (const [label, mod] of [["node", recipientMerkleNode], ["sandbox", recipientMerkleSandbox]]) {
    assert.throws(() => mod.buildRecipientTree([]), /recipients must be a non-empty array/, `${label}: empty set refusal`);
    assert.throws(
      () => mod.verifyRecipientProof({ root: "00".repeat(32), recipient: "aa".repeat(32), siblingsHex: "AB".repeat(32), pathBits: 0n }),
      /siblingsHex must be lowercase hex/,
      `${label}: uppercase siblings refusal`
    );
    assert.throws(
      () => mod.verifyRecipientProof({ root: "00".repeat(32), recipient: "aa".repeat(32), siblingsHex: "ab".repeat(32 * 17), pathBits: 0n }),
      /exceeds the covenant maximum 16/,
      `${label}: over-depth refusal`
    );
  }
});

test("crypto shim byte surface: update(<Uint8Array>)/digest() equals node:crypto and still fails closed outside the exact surface", () => {
  /* Runs the committed CRYPTO_SHIM source (the exact code the bundle and
   * this suite's sandbox embed) directly, byte vectors against
   * node:crypto — the byte-mode extension that made the Merkle modules
   * portable must be EXACT, and everything else must still refuse. */
  const { CRYPTO_SHIM } = require("../../../web/tools/build-core-bundle.js");
  const vm = require("vm");
  const nodeCryptoWebcrypto = require("crypto").webcrypto;
  const sandboxGlobal = {};
  sandboxGlobal.globalThis = sandboxGlobal;
  sandboxGlobal.crypto = { getRandomValues: (a) => nodeCryptoWebcrypto.getRandomValues(a) };
  vm.createContext(sandboxGlobal);
  const shimFactory = new vm.Script(`(function(module, exports, require) {\n${CRYPTO_SHIM}\n})`).runInContext(sandboxGlobal);
  const shimMod = { exports: {} };
  shimFactory(shimMod, shimMod.exports, () => {
    throw new Error("shim needs no require");
  });
  const shimCrypto = shimMod.exports;
  const nodeCryptoReal = require("crypto");

  const byteVectors = [
    new Uint8Array(0),
    Uint8Array.of(0x00),
    Uint8Array.of(0x50, 0x56, 0x34, 0x00),
    new Uint8Array(55).fill(0xab),
    new Uint8Array(56).fill(0xab),
    new Uint8Array(63).fill(0x01),
    new Uint8Array(64).fill(0xff),
    new Uint8Array(65).fill(0x80),
    new Uint8Array(124).fill(0x42),
    Uint8Array.from({ length: 1000 }, (_, i) => i % 251)
  ];
  const hexOf = (u8) => Buffer.from(u8).toString("hex");
  for (const v of byteVectors) {
    const expected = nodeCryptoReal.createHash("sha256").update(v).digest("hex");
    assert.equal(hexOf(shimCrypto.createHash("sha256").update(v).digest()), expected, `byte digest() equality at length ${v.length}`);
    assert.equal(shimCrypto.createHash("sha256").update(v).digest("hex"), expected, `byte digest("hex") equality at length ${v.length}`);
  }
  /* chunked byte updates concatenate exactly like node */
  const chunked = shimCrypto.createHash("sha256").update(Uint8Array.of(1, 2)).update(Uint8Array.of(3)).digest("hex");
  assert.equal(chunked, nodeCryptoReal.createHash("sha256").update(Uint8Array.of(1, 2, 3)).digest("hex"));

  /* fail-closed outside the exact surface */
  assert.throws(() => shimCrypto.createHash("sha256").update(123), /strings and Uint8Array bytes only/);
  assert.throws(() => shimCrypto.createHash("sha256").update(null), /strings and Uint8Array bytes only/);
  assert.throws(() => shimCrypto.createHash("sha256").update(Uint8Array.of(1), "hex"), /byte updates take no encoding/);
  assert.throws(() => shimCrypto.createHash("sha256").update("x", "latin1"), /unsupported update encoding/);
  assert.throws(() => shimCrypto.createHash("sha256").update("x").digest("base64"), /unsupported digest format/);
  const once = shimCrypto.createHash("sha256");
  once.update(Uint8Array.of(1)).digest();
  assert.throws(() => once.digest(), /digest called twice/);
});
