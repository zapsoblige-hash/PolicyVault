"use strict";

/*
 * Cross-runtime PORTABILITY + EQUIVALENCE probe for the v0.5 / v0.6
 * token-controller half of the shared core.
 *
 * WHY THIS EXISTS: the existing battery
 * (core-model-portability.test.js) covers the 14 v0.2–v0.4 core/model
 * files. Everything the v0.5 TOKEN and v0.6 ATOMIC-COMPOSABILITY waves
 * added — the v5/v6 state serializers and state ids, the v5/v6 token-agent
 * Merkle leaves, the v6 swap-policy leaves and venue-profile hash, the
 * exact constant-product pool quotes, KIP-9 storage mass, the v5/v6
 * compute-budget tiers, the whole core/assets KCC20 codec, and the
 * v0.5/v0.6 intent manifests + the version router — had NO cross-runtime
 * coverage at all, even though web/core-bundle.js already ships the v0.5
 * half of that list to real browsers and mobile ships the identical bytes.
 * A divergence there would land directly on a signer's screen.
 *
 * The binding property, same as the rest of the battery: the local-first
 * verification a signer relies on must not silently compute something
 * different depending on where it runs. Each raw, JSON-safe vector is fed
 * into EACH runtime's OWN copy of the pipeline independently; only final
 * primitives / plain JSON are compared (structured results are re-homed
 * across the realm boundary first — see sandbox.js `rehome`).
 *
 * Runtime 2 here is the browser-shaped `vm` context (no require / module /
 * process / Buffer; the exact crypto shim real browsers get), loading the
 * UNMODIFIED core sources — the same technique and the same shim the
 * committed bundle uses.
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");

const { loadCoreFilesInSandbox, rehome, rehomeInto } = require("../sandbox.js");
const {
  STATE_ID_V5_VECTORS,
  STATE_ID_V6_VECTORS,
  TOKEN_AGENT_POLICIES_V5,
  TOKEN_AGENT_POLICIES_V6,
  POOL_QUOTE_VECTORS,
  STORAGE_MASS_VECTORS,
  BUDGET_V5_OPERATIONS,
  BUDGET_V6_OPERATIONS,
  TEMPLATE_GEOMETRIES,
  stringifyBigInts
} = require("../vectors.js");

/*
 * The EXACT dependency closure of the v0.5/v0.6 controller stack (plus the
 * v0.7 root/payment and v0.7-kas manifest families the shared router now
 * requires), computed from the sources' own requires. The sandbox refuses
 * any require outside this explicit list, so a new non-portable dependency
 * fails loudly here
 * instead of silently in a browser.
 */
const V5_V6_FILES = Object.freeze([
  "core/assets/blake2b.js",
  "core/assets/descriptor.js",
  "core/assets/index.js",
  "core/assets/kcc20.js",
  "core/explain/kas.js",
  "core/explain/token-explain.js",
  "core/intent/canonical.js",
  "core/intent/org-root-manifest-v7-kas.js",
  "core/intent/org-root-manifest-v7.js",
  "core/intent/root-script-v7.js", // rc20 review R5-04: the verifier rebuilds the frozen root script (STALE ASSUMPTION: new dependency)
  "core/intent/vault-script-v7.js", // Codex checkpoint 6 (UX-02 / UX-13): the verifier rebuilds the rooted-vault successor script (STALE ASSUMPTION: new dependency)
  "core/intent/org-root-manifest-v7-hd.js",
  "core/intent/org-root-manifest-v7-kas.js",
  "core/intent/router.js",
  "core/intent/swap-manifest-v6.js",
  "core/intent/token-manifest-v5.js",
  "core/intent/token-manifest-v6.js",
  "core/model/agent-merkle-v4.js",
  "core/model/agent-merkle-v5.js",
  "core/model/agent-merkle-v6.js",
  "core/model/amounts.js",
  "core/model/approval-package-v3.js",
  "core/model/approval-package-v4.js",
  "core/model/canonical-json.js",
  "core/model/compute-budget-v5.js",
  "core/model/compute-budget-v6.js",
  "core/model/compute-budget-v7.js",
  "core/model/compute-budget-v7-hd.js",
  "core/model/hd-leaf-v7.js",
  "core/model/vault-state-v7-kas.js",
  "core/model/vault-transitions-v7-kas.js",
  "core/model/compute-budget-v7-kas.js",
  "core/model/own-get.js",
  "core/model/vault-state-v4.js",
  "core/model/vault-transitions-v4.js",
  "core/model/agent-merkle-v4.js",
  "core/model/compute-budget-v4.js",
  "core/model/contract-version.js",
  "core/model/frozen-tx-v3.js",
  "core/model/owner-set-v7.js",
  "core/model/recipient-merkle-v3.js",
  "core/model/storage-mass.js",
  "core/model/swap-policy-v6.js",
  "core/model/token-amounts.js",
  "core/model/vault-state-v3.js",
  "core/model/vault-state-v4.js",
  "core/model/vault-state-v5.js",
  "core/model/vault-state-v6.js",
  "core/model/vault-state-v7-kas.js",
  "core/model/vault-state-v7-root.js",
  "core/model/vault-state-v7.js",
  "core/model/vault-state.js",
  "core/model/vault-transitions-v5.js",
  "core/model/vault-transitions-v6.js"
]);

const sandbox = loadCoreFilesInSandbox(V5_V6_FILES);
const nodeOf = (rel) => require(`../../../${rel}`);
/* Byte results (Uint8Array) cross a realm boundary as a structurally
 * identical but NOT reference-equal object, and `instanceof` is false in
 * the other realm — so compare bytes as a plain hex string, never by
 * identity (see sandbox.js's realm-identity note). */
const hexOf = (bytes) => Array.from(bytes, (x) => x.toString(16).padStart(2, "0")).join("");
const boxOf = (rel) => sandbox.require(rel);
/* Any value handed to sandboxed code that CANONICALIZES it (the manifest
 * layer's canonicalJsonStringify checks `Object.getPrototypeOf(v) ===
 * Object.prototype` against its OWN realm) must be re-homed INTO the
 * sandbox realm, not merely JSON-round-tripped in the host realm — the
 * realm-identity caveat recorded in docs/postlaunch/cross-runtime-
 * equivalence.md §5.2. Feeding a host-realm object instead makes the
 * sandbox refuse it as "non-plain", which looks like a divergence and is
 * not one. */
const into = (value) => rehomeInto(sandbox.global, value);

/* ------------------------------------------------------------------ */
/* smoke — every file loads with the SAME export surface                */
/* ------------------------------------------------------------------ */

for (const rel of V5_V6_FILES) {
  test(`v5/v6 smoke: ${rel} loads in the browser-like sandbox with the SAME export key set as Node`, () => {
    assert.deepEqual(Object.keys(boxOf(rel)).sort(), Object.keys(nodeOf(rel)).sort());
  });
}

/* ------------------------------------------------------------------ */
/* state ids — the commitment a client compares against the chain       */
/* ------------------------------------------------------------------ */

test("v0.5 state ids: computeStateIdV5 is byte-identical across runtimes (including the MAX_SOMPI / max-nonce boundary)", () => {
  const n = nodeOf("core/model/vault-state-v5.js");
  const b = boxOf("core/model/vault-state-v5.js");
  for (const v of STATE_ID_V5_VECTORS) {
    /* each runtime normalizes the SAME raw JSON vector with its OWN codec */
    const nId = n.computeStateIdV5({ networkId: v.networkId, template: n.normalizeTemplateV5(v.template), state: n.normalizeStateV5(v.state), contractVersion: v.contractVersion });
    const bId = b.computeStateIdV5({ networkId: v.networkId, template: b.normalizeTemplateV5(rehome(v.template)), state: b.normalizeStateV5(rehome(v.state)), contractVersion: v.contractVersion });
    assert.equal(bId, nId, v.label);
    assert.match(nId, /^[0-9a-f]{64}$/);
  }
  /* the reject path is identical too (never a different refusal) */
  const t0 = STATE_ID_V5_VECTORS[0];
  assert.throws(() => n.computeStateIdV5({ networkId: "", template: n.normalizeTemplateV5(t0.template), state: n.normalizeStateV5(t0.state), contractVersion: "policyvault-0.5" }));
  assert.throws(() => b.computeStateIdV5({ networkId: "", template: b.normalizeTemplateV5(rehome(t0.template)), state: b.normalizeStateV5(rehome(t0.state)), contractVersion: "policyvault-0.5" }));
});

test("v0.6 state ids: computeStateIdV6 is byte-identical across runtimes, and the two v0.6-only fields are committed", () => {
  const n = nodeOf("core/model/vault-state-v6.js");
  const b = boxOf("core/model/vault-state-v6.js");
  const nId = (v, state) => n.computeStateIdV6({ networkId: v.networkId, template: n.normalizeTemplateV6(v.template), state: n.normalizeStateV6(state ?? v.state), contractVersion: v.contractVersion });
  const bId = (v, state) => b.computeStateIdV6({ networkId: v.networkId, template: b.normalizeTemplateV6(rehome(v.template)), state: b.normalizeStateV6(rehome(state ?? v.state)), contractVersion: v.contractVersion });
  const ids = [];
  for (const v of STATE_ID_V6_VECTORS) {
    const id = nId(v);
    assert.equal(bId(v), id, v.label);
    assert.match(id, /^[0-9a-f]{64}$/);
    ids.push(id);
  }
  /* changing swapPrincipal or swapRoot MUST change the id in BOTH runtimes */
  const base = STATE_ID_V6_VECTORS[0];
  for (const field of ["swapPrincipal", "swapRoot"]) {
    const mutated = { ...base.state, [field]: field === "swapPrincipal" ? "1" : "cc".repeat(32) };
    assert.notEqual(nId(base, mutated), ids[0], `${field} must be committed`);
    assert.equal(bId(base, mutated), nId(base, mutated), `${field} mutation agrees across runtimes`);
  }
  /* the closed state layout refuses an unknown field identically */
  const extra = { ...base.state, surprise: "1" };
  assert.throws(() => n.normalizeStateV6(extra));
  assert.throws(() => b.normalizeStateV6(rehome(extra)));
});

/* ------------------------------------------------------------------ */
/* Merkle authority — the leaves and roots a signer re-proves locally   */
/* ------------------------------------------------------------------ */

test("v0.5 token-agent Merkle: leaf hashes, tree roots, proofs and folds are byte-identical across runtimes", () => {
  const n = nodeOf("core/model/agent-merkle-v5.js");
  const b = boxOf("core/model/agent-merkle-v5.js");
  assert.equal(b.PADDING_LEAF_HEX, n.PADDING_LEAF_HEX, "module-load-time padding leaf");
  for (const p of TOKEN_AGENT_POLICIES_V5) {
    assert.deepEqual(hexOf(b.tokenAgentLeafHash(rehome(p))), hexOf(n.tokenAgentLeafHash(p)), `v5 leaf hash ${p.agentPk.slice(0, 8)}`);
    assert.deepEqual(hexOf(b.tokenAgentLeafPreimage(rehome(p))), hexOf(n.tokenAgentLeafPreimage(p)), `v5 leaf preimage ${p.agentPk.slice(0, 8)}`);
  }
  const nTree = n.buildTokenAgentTreeV5(TOKEN_AGENT_POLICIES_V5);
  const bTree = b.buildTokenAgentTreeV5(rehome(TOKEN_AGENT_POLICIES_V5));
  assert.equal(bTree.root, nTree.root, "tree root");
  const nProof = n.generateTokenAgentProofV5(nTree, TOKEN_AGENT_POLICIES_V5[0].agentPk);
  const bProof = b.generateTokenAgentProofV5(bTree, TOKEN_AGENT_POLICIES_V5[0].agentPk);
  assert.equal(bProof.siblingsHex, nProof.siblingsHex);
  assert.equal(String(bProof.pathBits), String(nProof.pathBits));
  assert.equal(n.verifyTokenAgentProofV5({ root: nTree.root, policy: TOKEN_AGENT_POLICIES_V5[0], siblingsHex: nProof.siblingsHex, pathBits: BigInt(nProof.pathBits) }), true);
  assert.equal(b.verifyTokenAgentProofV5(rehome({ root: nTree.root, policy: TOKEN_AGENT_POLICIES_V5[0], siblingsHex: nProof.siblingsHex, pathBits: String(nProof.pathBits) })), true);
  assert.equal(
    b.foldTokenAgentPolicyV5(rehome(TOKEN_AGENT_POLICIES_V5[0]), nProof.siblingsHex, BigInt(nProof.pathBits)),
    n.foldTokenAgentPolicyV5(TOKEN_AGENT_POLICIES_V5[0], nProof.siblingsHex, BigInt(nProof.pathBits)),
    "single-leaf successor fold"
  );
});

test("v0.6 token-agent Merkle: the KAS-cap-bearing leaf hashes, roots, proofs and folds are byte-identical across runtimes", () => {
  const n = nodeOf("core/model/agent-merkle-v6.js");
  const b = boxOf("core/model/agent-merkle-v6.js");
  assert.equal(b.PADDING_LEAF_HEX, n.PADDING_LEAF_HEX);
  assert.equal(b.LEAF_PREIMAGE_LEN_V6, n.LEAF_PREIMAGE_LEN_V6, "the v0.6 leaf preimage length is a consensus fact");
  for (const p of TOKEN_AGENT_POLICIES_V6) {
    assert.deepEqual(hexOf(b.tokenAgentLeafHashV6(rehome(p))), hexOf(n.tokenAgentLeafHashV6(p)), `v6 leaf hash ${p.agentPk.slice(0, 8)}`);
    assert.deepEqual(hexOf(b.tokenAgentLeafPreimageV6(rehome(p))), hexOf(n.tokenAgentLeafPreimageV6(p)), `v6 leaf preimage ${p.agentPk.slice(0, 8)}`);
  }
  const nTree = n.buildTokenAgentTreeV6(TOKEN_AGENT_POLICIES_V6);
  const bTree = b.buildTokenAgentTreeV6(rehome(TOKEN_AGENT_POLICIES_V6));
  assert.equal(bTree.root, nTree.root);
  const nProof = n.generateTokenAgentProofV6(nTree, TOKEN_AGENT_POLICIES_V6[0].agentPk);
  const bProof = b.generateTokenAgentProofV6(bTree, TOKEN_AGENT_POLICIES_V6[0].agentPk);
  assert.equal(bProof.siblingsHex, nProof.siblingsHex);
  /* the successor root a v0.6 spend/swap commits: fold the advanced leaf */
  const advanced = { ...TOKEN_AGENT_POLICIES_V6[0], tokenPeriodSpent: "123", kasPeriodSpent: "456" };
  assert.equal(
    b.foldTokenAgentPolicyV6(rehome(advanced), nProof.siblingsHex, BigInt(nProof.pathBits)),
    n.foldTokenAgentPolicyV6(advanced, nProof.siblingsHex, BigInt(nProof.pathBits))
  );
  /* a v0.5 leaf must NOT be accepted by the v0.6 normalizer in either runtime (closed tuple) */
  assert.throws(() => n.normalizeTokenAgentPolicyV6(TOKEN_AGENT_POLICIES_V5[0]));
  assert.throws(() => b.normalizeTokenAgentPolicyV6(rehome(TOKEN_AGENT_POLICIES_V5[0])));
});

test("v0.6 swap policy: leaf hashes, tree roots and the venue-profile hash are byte-identical across runtimes", () => {
  const n = nodeOf("core/model/swap-policy-v6.js");
  const b = boxOf("core/model/swap-policy-v6.js");
  assert.equal(b.PADDING_LEAF_HEX, n.PADDING_LEAF_HEX);
  assert.equal(b.LEAF_PREIMAGE_LEN_SWAP, n.LEAF_PREIMAGE_LEN_SWAP);
  assert.deepEqual(Object.keys(b.DIRECTION).sort(), Object.keys(n.DIRECTION).sort());
  const leaf = {
    poolCovenantId: "50".repeat(32),
    poolTemplateVmHash: "51".repeat(32),
    poolPrefixLen: "100",
    poolSuffixLen: "50",
    poolFeePk: "66".repeat(32),
    profileHash: "67".repeat(32),
    maxProtocolFeeKas: "500000000",
    sellFloorNum: "90000000",
    sellFloorDen: "1",
    buyCeilNum: "110000000",
    buyCeilDen: "1",
    directionMask: "3",
    destScheme: 2,
    destIdentity: "00".repeat(32)
  };
  const nNorm = n.normalizeSwapPolicyV6(leaf);
  const bNorm = b.normalizeSwapPolicyV6(rehome(leaf));
  assert.deepEqual(stringifyBigInts(bNorm), stringifyBigInts(nNorm), "normalized leaf");
  assert.deepEqual(hexOf(b.swapPolicyLeafHashV6(rehome(leaf))), hexOf(n.swapPolicyLeafHashV6(leaf)), "leaf hash");
  assert.equal(b.swapPolicyLeafHexV6(rehome(leaf)), n.swapPolicyLeafHexV6(leaf), "leaf hex");
  assert.equal(b.buildSwapPolicyTreeV6(rehome([leaf])).root, n.buildSwapPolicyTreeV6([leaf]).root, "tree root");
});

/* ------------------------------------------------------------------ */
/* exact financial arithmetic — quotes, storage mass, budgets           */
/* ------------------------------------------------------------------ */

test("v0.6 pool quotes: poolSellQuote / poolBuyQuote agree to the sompi across runtimes (integer rounding included)", () => {
  const n = nodeOf("core/model/vault-transitions-v6.js");
  const b = boxOf("core/model/vault-transitions-v6.js");
  assert.equal(b.SWAP_INPUT_COUNT, n.SWAP_INPUT_COUNT, "the pinned swap input count is a consensus fact");
  /* Either BOTH runtimes quote the same numbers, or BOTH refuse with the
   * same code (e.g. QUOTE_TOO_SMALL when the pool fee eats the whole
   * amount). A quote in one runtime and a refusal in the other would be
   * the worst possible divergence, so it is asserted away explicitly. */
  const outcome = (fn) => {
    try {
      return { ok: true, value: stringifyBigInts(fn()) };
    } catch (e) {
      return { ok: false, code: e.code ?? "NO_CODE" };
    }
  };
  let quoted = 0;
  let refused = 0;
  for (const v of POOL_QUOTE_VECTORS) {
    const nSell = outcome(() => n.poolSellQuote(v.pool, v.sell, v.protocolFeeBps));
    const bSell = outcome(() => b.poolSellQuote(rehome(v.pool), v.sell, v.protocolFeeBps));
    assert.deepEqual(bSell, nSell, `sell: ${v.label}`);
    const nBuy = outcome(() => n.poolBuyQuote(v.pool, v.buy, v.protocolFeeBps));
    const bBuy = outcome(() => b.poolBuyQuote(rehome(v.pool), v.buy, v.protocolFeeBps));
    assert.deepEqual(bBuy, nBuy, `buy: ${v.label}`);
    for (const r of [nSell, nBuy]) (r.ok ? (quoted += 1) : (refused += 1));
  }
  assert.ok(quoted >= 4, `the battery must exercise real quotes, got ${quoted}`);
  assert.ok(refused >= 1, `the battery must exercise a refusal path, got ${refused}`);
  /* a pool with a >= 100% fee is refused identically */
  const insane = { kasReserve: "1000", tokenReserve: "1000", feeBps: "10000", nonce: "0" };
  assert.throws(() => n.poolSellQuote(insane, "1", "0"));
  assert.throws(() => b.poolSellQuote(rehome(insane), "1", "0"));
});

test("KIP-9 storage mass: calcStorageMass agrees across runtimes on the relaxed path, the general path, and an over-limit shape", () => {
  const n = nodeOf("core/model/storage-mass.js");
  const b = boxOf("core/model/storage-mass.js");
  assert.equal(String(b.STORAGE_MASS_LIMIT), String(n.STORAGE_MASS_LIMIT));
  assert.equal(String(b.STORAGE_MASS_PARAMETER), String(n.STORAGE_MASS_PARAMETER));
  let sawOverLimit = false;
  for (const v of STORAGE_MASS_VECTORS) {
    const ins = v.inputs.map((x) => BigInt(x));
    const outs = v.outputs.map((x) => BigInt(x));
    const nMass = n.calcStorageMass(ins, outs);
    const bMass = b.calcStorageMass(ins, outs);
    assert.equal(String(bMass), String(nMass), v.label);
    if (nMass > n.STORAGE_MASS_LIMIT) sawOverLimit = true;
  }
  assert.ok(sawOverLimit, "the battery must include a shape that exceeds the consensus limit");
  /* a zero-value output is refused identically (never silently 0 mass) */
  assert.throws(() => n.calcStorageMass([1n], [0n]));
  assert.throws(() => b.calcStorageMass([1n], [0n]));
});

test("v0.5 / v0.6 compute budgets: every production operation resolves to the SAME tier across runtimes, at two template geometries", () => {
  const n5 = nodeOf("core/model/compute-budget-v5.js");
  const b5 = boxOf("core/model/compute-budget-v5.js");
  const n6 = nodeOf("core/model/compute-budget-v6.js");
  const b6 = boxOf("core/model/compute-budget-v6.js");
  for (const geometry of TEMPLATE_GEOMETRIES) {
    for (const operation of BUDGET_V5_OPERATIONS) {
      const args = { operation, ...geometry };
      assert.equal(String(b5.selectComputeBudgetV5(rehome(args))), String(n5.selectComputeBudgetV5(args)), `v5 ${operation} @ ${geometry.templatePrefixLen}`);
    }
    for (const operation of BUDGET_V6_OPERATIONS) {
      const args = { operation, ...geometry };
      assert.equal(String(b6.selectComputeBudgetV6(rehome(args))), String(n6.selectComputeBudgetV6(args)), `v6 ${operation} @ ${geometry.templatePrefixLen}`);
    }
    assert.equal(String(b5.selectTokenInputBudgetV5(rehome(geometry))), String(n5.selectTokenInputBudgetV5(geometry)));
    assert.equal(String(b6.selectTokenInputBudgetV6(rehome(geometry))), String(n6.selectTokenInputBudgetV6(geometry)));
  }
  /* an unknown operation fails closed with the same refusal in both runtimes */
  assert.throws(() => n6.selectComputeBudgetV6({ operation: "ownerDrainEverything", ...TEMPLATE_GEOMETRIES[0] }));
  assert.throws(() => b6.selectComputeBudgetV6(rehome({ operation: "ownerDrainEverything", ...TEMPLATE_GEOMETRIES[0] })));
});

/* ------------------------------------------------------------------ */
/* the manifest layer itself — versions, routing, refusals              */
/* ------------------------------------------------------------------ */

test("intent manifests: the v0.5 / v0.6 manifest version strings and action tables are identical across runtimes", () => {
  const n5 = nodeOf("core/intent/token-manifest-v5.js");
  const b5 = boxOf("core/intent/token-manifest-v5.js");
  const n6 = nodeOf("core/intent/token-manifest-v6.js");
  const b6 = boxOf("core/intent/token-manifest-v6.js");
  const nS = nodeOf("core/intent/swap-manifest-v6.js");
  const bS = boxOf("core/intent/swap-manifest-v6.js");
  assert.equal(b5.TOKEN_MANIFEST_VERSION_1, n5.TOKEN_MANIFEST_VERSION_1);
  assert.equal(b6.CONTROLLER_MANIFEST_VERSION_1, n6.CONTROLLER_MANIFEST_VERSION_1);
  assert.equal(bS.SWAP_MANIFEST_VERSION_1, nS.SWAP_MANIFEST_VERSION_1);
  assert.deepEqual(Object.keys(b6.ACTIONS).sort(), Object.keys(n6.ACTIONS).sort());
  assert.deepEqual(JSON.parse(JSON.stringify(b6.ACTIONS)), JSON.parse(JSON.stringify(n6.ACTIONS)), "the action table (role/terminal/opSelector) must not differ by runtime");
  /* the VERIFIED statement a human reads is the same text everywhere */
  assert.equal(b6.VERIFIED_STATEMENT, n6.VERIFIED_STATEMENT);
  assert.equal(b5.VERIFIED_STATEMENT, n5.VERIFIED_STATEMENT);
});

test("manifest router: dispatch and every fail-closed refusal code are identical across runtimes", () => {
  const n = nodeOf("core/intent/router.js");
  const b = boxOf("core/intent/router.js");
  assert.deepEqual([...b.SUPPORTED_MANIFEST_VERSIONS], [...n.SUPPORTED_MANIFEST_VERSIONS]);
  const BUILDS = [
    { contractVersion: "policyvault-0.5", kind: "transition", action: "tokenAgentSpend" },
    { contractVersion: "policyvault-0.5", kind: "tokenDeposit" },
    { contractVersion: "policyvault-0.6", kind: "transition", action: "tokenAgentSpend" },
    { contractVersion: "policyvault-0.6", kind: "transition", action: "ownerFundSwapPrincipal" },
    { contractVersion: "policyvault-0.6", kind: "transition", action: "ownerRecover" },
    { contractVersion: "policyvault-0.6", kind: "tokenDeposit" },
    { contractVersion: "policyvault-0.6", kind: "transition", action: "tokenAtomicSell", swap: {} },
    { contractVersion: "policyvault-0.6", kind: "transition", action: "tokenAtomicBuy", swap: {} }
  ];
  for (const build of BUILDS) {
    assert.equal(b.routeBuild(rehome(build)).module, n.routeBuild(build).module, JSON.stringify(build));
  }
  const REFUSALS = [
    { contractVersion: "policyvault-0.4", kind: "transition", action: "agentSpend" },
    { contractVersion: "policyvault-0.4.1", kind: "transition", action: "agentSpend" },
    { contractVersion: "policyvault-0.7", kind: "transition", action: "tokenAgentSpend" },
    { contractVersion: "policyvault-0.6", kind: "genesis", action: "createTokenController" },
    { contractVersion: "policyvault-0.6", kind: "transition", action: "ownerDrainEverything" },
    { contractVersion: "policyvault-0.6", kind: "transition", action: "tokenAtomicSell" },
    { contractVersion: "policyvault-0.6", kind: "transition", action: "tokenAgentSpend", swap: {} },
    {}
  ];
  const codeOf = (fn) => {
    try {
      fn();
    } catch (e) {
      return e.code ?? "NO_CODE"; // e.code is a plain string: realm-safe (instanceof is not)
    }
    return "DID_NOT_THROW";
  };
  for (const build of REFUSALS) {
    const nodeCode = codeOf(() => n.routeBuild(build));
    const boxCode = codeOf(() => b.routeBuild(rehome(build)));
    assert.notEqual(nodeCode, "DID_NOT_THROW", `${JSON.stringify(build)} must refuse in Node`);
    assert.equal(boxCode, nodeCode, `${JSON.stringify(build)}: the refusal code must not differ by runtime`);
  }
});

test("v0.6 controller manifest: the verifier's refusal surface is identical across runtimes (no runtime-dependent verdict)", () => {
  const n = nodeOf("core/intent/token-manifest-v6.js");
  const b = boxOf("core/intent/token-manifest-v6.js");
  const CASES = [
    { manifest: null, descriptor: {} },
    { manifest: {}, descriptor: {} },
    { manifest: { manifestVersion: "policyvault-controller-intent-manifest/2" }, descriptor: {} },
    { manifest: { manifestVersion: "policyvault-controller-intent-manifest/1", action: { sdkAction: "tokenAtomicSell" } }, descriptor: {} },
    { manifest: { manifestVersion: "policyvault-controller-intent-manifest/1", action: { sdkAction: "ownerPause" } }, descriptor: {} }
  ];
  for (const args of CASES) {
    const nodeResult = JSON.parse(JSON.stringify(n.verifyControllerIntentManifestV6(args)));
    const boxResult = JSON.parse(JSON.stringify(b.verifyControllerIntentManifestV6(into(args))));
    assert.equal(nodeResult.verdict, "REFUSED", JSON.stringify(args));
    assert.equal(boxResult.verdict, nodeResult.verdict);
    assert.equal(boxResult.statement, null);
    assert.deepEqual(
      boxResult.failures.map((f) => f.name),
      nodeResult.failures.map((f) => f.name),
      `the failing check names must not differ by runtime: ${JSON.stringify(args)}`
    );
  }
});

test("core/assets KCC20 codec: state encode/decode, redeem reconstruction and the P2SH script are byte-identical across runtimes", () => {
  const n = nodeOf("core/assets/kcc20.js");
  const b = boxOf("core/assets/kcc20.js");
  const STATES = [
    { ownerIdentifier: "43".repeat(32), identifierType: 2, amount: "300", isMinter: false },
    { ownerIdentifier: "33".repeat(32), identifierType: 0, amount: "0", isMinter: false },
    { ownerIdentifier: "11".repeat(32), identifierType: 0, amount: "9223372036854775807", isMinter: true }
  ];
  for (const s of STATES) {
    const nEnc = n.bytesToHex(n.encodeState(s));
    const bEnc = b.bytesToHex(b.encodeState(rehome(s)));
    assert.equal(bEnc, nEnc, JSON.stringify(s));
    assert.deepEqual(stringifyBigInts(b.decodeState(b.hexToBytes(bEnc))), stringifyBigInts(n.decodeState(n.hexToBytes(nEnc))));
  }
  const prefixHex = "aa".repeat(60);
  const suffixHex = "bb".repeat(40);
  const state = n.encodeState(STATES[0]);
  const nRedeem = n.reconstructRedeem(prefixHex, state, suffixHex);
  const bRedeem = b.reconstructRedeem(prefixHex, b.encodeState(rehome(STATES[0])), suffixHex);
  assert.equal(b.bytesToHex(bRedeem), n.bytesToHex(nRedeem), "reconstructed redeem");
  assert.equal(b.p2shSpkHex(bRedeem), n.p2shSpkHex(nRedeem), "P2SH script — a wrong byte here pays the wrong script");
  assert.equal(b.templateVmHashHex(prefixHex, suffixHex), n.templateVmHashHex(prefixHex, suffixHex), "blake2b template identity");
  /* an out-of-range amount is refused identically */
  assert.throws(() => n.encodeState({ ...STATES[0], amount: "9223372036854775808" }));
  assert.throws(() => b.encodeState(rehome({ ...STATES[0], amount: "9223372036854775808" })));
});
