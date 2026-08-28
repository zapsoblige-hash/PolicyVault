"use strict";

/*
 * F1 browser-portability wave — deep Merkle byte-identity golden generator.
 *
 * Captures EVERY consensus-visible byte surface of the two Merkle modules
 * (recipient-merkle-v3, agent-merkle-v4): leaf preimages, leaf hashes,
 * every intermediate node of every level, roots, proof siblings/pathBits,
 * verification outcomes, fold results, successor roots from tree edits and
 * agent-spend accounting, and the exact thrown-error identities of the
 * fail-closed paths.
 *
 * The fixture (core/model/test/fixtures/golden-f1-merkle.json) is captured
 * from the ORIGINAL pre-refactor implementations at the F1 baseline commit
 * and is thereafter FROZEN: the byte-native refactor must reproduce it
 * exactly, from both require roots (core/model and sdk/src shims). Any
 * divergence — a single node byte, one error message, one pathBit — fails.
 *
 * Node-only testutil: Buffer is used here (only here) to hex-encode
 * outputs, because it accepts both Buffer and plain Uint8Array inputs and
 * therefore works identically before and after the refactor.
 */

const HEX32 = (b) => b.repeat(32); // "ab" -> 64-hex x-only key

function toHex(bytes) {
  return Buffer.from(bytes).toString("hex");
}

/* Capture a thrown error's observable identity (message + code). */
function threw(fn) {
  try {
    const v = fn();
    return { threw: false, value: typeof v === "bigint" ? v.toString() : v };
  } catch (error) {
    return { threw: true, message: error.message, code: error.code ?? null };
  }
}

function apiSurface(mod) {
  const keys = Object.keys(mod).sort();
  const types = {};
  for (const k of keys) types[k] = typeof mod[k];
  return { keys, types };
}

/* Full tree byte surface: every level, every node, plus shape. */
function treeBytes(tree) {
  return {
    root: tree.root,
    leafCount: tree.leafCount,
    depth: tree.depth,
    levels: tree.levels.map((level) => level.map((node) => toHex(node)))
  };
}

function policyBytes(p) {
  const out = {};
  for (const k of Object.keys(p).sort()) {
    out[k] = typeof p[k] === "bigint" ? p[k].toString() : p[k];
  }
  return out;
}

/* ------------------------------------------------ recipient merkle (v3) */
function recipientGolden(m) {
  const {
    MAX_DEPTH,
    MAX_RECIPIENTS,
    LEAF_DOMAIN,
    leafHash,
    buildRecipientTree,
    generateRecipientProof,
    verifyRecipientProof
  } = m;

  const R = ["aa", "bb", "cc", "dd", "ee", "12", "34", "56"].map(HEX32);

  const trees = {};
  const proofSets = {};
  for (const [name, input] of [
    ["one", [R[0]]],
    ["two", [R[1], R[0]]], // unsorted input — canonical sort pinned
    ["twoDup", [R[0], R[1], R[0], R[1]]], // dedup pinned
    ["three", [R[2], R[0], R[1]]], // odd count — duplicate-last padding
    ["four", [R[3], R[2], R[1], R[0]]],
    ["five", R.slice(0, 5)], // pad 5 -> 8
    ["seven", R.slice(0, 7)],
    ["eight", R]
  ]) {
    const tree = buildRecipientTree(input);
    trees[name] = { recipients: [...tree.recipients], ...treeBytes(tree) };
    const proofs = {};
    for (const r of tree.recipients) {
      const p = generateRecipientProof(tree, r);
      proofs[r] = {
        siblingsHex: p.siblingsHex,
        pathBits: p.pathBits.toString(),
        depth: p.depth,
        verifies: verifyRecipientProof({
          root: tree.root,
          recipient: r,
          siblingsHex: p.siblingsHex,
          pathBits: p.pathBits
        }),
        wrongRoot: verifyRecipientProof({
          root: HEX32("00"),
          recipient: r,
          siblingsHex: p.siblingsHex,
          pathBits: p.pathBits
        })
      };
    }
    proofSets[name] = proofs;
  }

  /* Deeper tree exercising two padded levels: 33 leaves -> 64 slots. */
  const many = [];
  for (let i = 0; i < 33; i++) {
    many.push(i.toString(16).padStart(2, "0").repeat(32));
  }
  const deep = buildRecipientTree(many);
  const deepProof = generateRecipientProof(deep, many[32]);

  const p5 = generateRecipientProof(buildRecipientTree(R.slice(0, 5)), R[0]);

  return {
    api: apiSurface(m),
    constants: {
      MAX_DEPTH,
      MAX_RECIPIENTS,
      LEAF_DOMAIN: toHex(LEAF_DOMAIN)
    },
    leafHashes: Object.fromEntries(R.map((r) => [r, toHex(leafHash(r))])),
    trees,
    proofSets,
    deep: {
      ...treeBytes(deep),
      lastProof: {
        siblingsHex: deepProof.siblingsHex,
        pathBits: deepProof.pathBits.toString(),
        depth: deepProof.depth,
        verifies: verifyRecipientProof({
          root: deep.root,
          recipient: many[32],
          siblingsHex: deepProof.siblingsHex,
          pathBits: deepProof.pathBits
        })
      }
    },
    verifyEdges: {
      excessPathBits: verifyRecipientProof({
        root: trees.five.root,
        recipient: R[0],
        siblingsHex: p5.siblingsHex,
        pathBits: p5.pathBits + (1n << BigInt(p5.depth))
      }),
      tamperedSibling: verifyRecipientProof({
        root: trees.five.root,
        recipient: R[0],
        siblingsHex: p5.siblingsHex.slice(0, -2) + (p5.siblingsHex.endsWith("00") ? "01" : "00"),
        pathBits: p5.pathBits
      }),
      flippedPathBit: verifyRecipientProof({
        root: trees.five.root,
        recipient: R[0],
        siblingsHex: p5.siblingsHex,
        pathBits: p5.pathBits ^ 1n
      }),
      nonMemberKey: verifyRecipientProof({
        root: trees.five.root,
        recipient: HEX32("77"),
        siblingsHex: p5.siblingsHex,
        pathBits: p5.pathBits
      })
    },
    rejects: {
      emptySet: threw(() => buildRecipientTree([])),
      notArray: threw(() => buildRecipientTree("nope")),
      badKey: threw(() => buildRecipientTree(["zz"])),
      shortKey: threw(() => buildRecipientTree(["ab"])),
      proofNotInTree: threw(() =>
        generateRecipientProof(buildRecipientTree(R.slice(0, 5)), HEX32("77"))
      ),
      verifyOddHex: threw(() =>
        verifyRecipientProof({ root: HEX32("00"), recipient: R[0], siblingsHex: "abc", pathBits: 0n })
      ),
      verifyUppercaseHex: threw(() =>
        verifyRecipientProof({ root: HEX32("00"), recipient: R[0], siblingsHex: "AB".repeat(32), pathBits: 0n })
      ),
      verifyBadWidth: threw(() =>
        verifyRecipientProof({ root: HEX32("00"), recipient: R[0], siblingsHex: "ab".repeat(31), pathBits: 0n })
      ),
      verifyTooDeep: threw(() =>
        verifyRecipientProof({ root: HEX32("00"), recipient: R[0], siblingsHex: "ab".repeat(32 * 17), pathBits: 0n })
      ),
      verifyPathBitsRange: threw(() =>
        verifyRecipientProof({ root: HEX32("00"), recipient: R[0], siblingsHex: "", pathBits: 65536n })
      ),
      verifyPathBitsNegative: threw(() =>
        verifyRecipientProof({ root: HEX32("00"), recipient: R[0], siblingsHex: "", pathBits: -1n })
      )
    }
  };
}

/* -------------------------------------------------- agent merkle (v4) */
function agentGolden(m) {
  const {
    AGENT_LEAF_DOMAIN,
    AGENT_PADDING_DOMAIN,
    PADDING_LEAF_HEX,
    MAX_AGENT_DEPTH,
    MAX_AGENTS,
    normalizeAgentPolicyV4,
    agentLeafPreimage,
    agentLeafHash,
    buildAgentTreeV4,
    generateAgentProofV4,
    verifyAgentProofV4,
    foldLeafV4,
    foldAgentPolicyV4,
    addAgentV4,
    removeAgentV4,
    updateAgentPolicyV4,
    rotateAgentV4,
    applyAgentSpendV4
  } = m;

  const MAX_SOMPI_STR = "2900000000000000000";
  const policy = (pkByte, over = {}) => ({
    agentPk: HEX32(pkByte),
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

  /* Boundary-valued policies: zeros where allowed, MAX_SOMPI, and a value
   * above Number.MAX_SAFE_INTEGER (BigInt-exactness pin). */
  const pBoundary = policy("0f", {
    maxPerSpend: MAX_SOMPI_STR,
    periodBudget: MAX_SOMPI_STR,
    periodLengthDaa: "1",
    periodStartDaa: "0",
    periodSpent: "9007199254740993",
    approvalThreshold: "0",
    agentMaxFeePerTx: "0",
    agentRecipientRoot: "00".repeat(32)
  });

  const preimages = {};
  const leaves = {};
  for (const [name, p] of [
    ["basic", policy("a1")],
    ["boundary", pBoundary],
    ["allOnes", policy("ff", {
      maxPerSpend: "1", periodBudget: "1", periodLengthDaa: "1",
      periodStartDaa: "1", periodSpent: "1", approvalThreshold: "1",
      agentMaxFeePerTx: "1", agentRecipientRoot: "11".repeat(32)
    })]
  ]) {
    preimages[name] = toHex(agentLeafPreimage(p));
    leaves[name] = toHex(agentLeafHash(p));
  }

  const trees = {};
  const proofSets = {};
  const agentSets = {
    empty: [],
    one: [policy("a1")],
    two: [policy("b2"), policy("a1")], // unsorted — canonical sort pinned
    three: [policy("c3"), policy("a1"), policy("b2")], // pad 3 -> 4 with padding leaf
    five: [policy("c3"), policy("a1"), policy("0f"), policy("b2"), policy("e5")]
  };
  for (const [name, input] of Object.entries(agentSets)) {
    const tree = buildAgentTreeV4(input);
    trees[name] = {
      agents: tree.agents.map(policyBytes),
      realCount: tree.realCount,
      ...treeBytes(tree)
    };
    const proofs = {};
    for (const a of tree.agents) {
      const p = generateAgentProofV4(tree, a.agentPk);
      proofs[a.agentPk] = {
        siblingsHex: p.siblingsHex,
        pathBits: p.pathBits.toString(),
        depth: p.depth,
        policy: policyBytes(p.policy),
        verifies: verifyAgentProofV4({
          root: tree.root,
          policy: p.policy,
          siblingsHex: p.siblingsHex,
          pathBits: p.pathBits
        }),
        wrongRoot: verifyAgentProofV4({
          root: "00".repeat(32),
          policy: p.policy,
          siblingsHex: p.siblingsHex,
          pathBits: p.pathBits
        })
      };
    }
    proofSets[name] = proofs;
  }

  /* Folds: single-leaf root derivation incl. excess-bits null. */
  const t3 = buildAgentTreeV4(agentSets.three);
  const proofA1 = generateAgentProofV4(t3, HEX32("a1"));
  const newA1 = policy("a1", { periodSpent: "250000000", periodStartDaa: "541086400" });
  const folds = {
    successorRoot: foldAgentPolicyV4(newA1, proofA1.siblingsHex, proofA1.pathBits),
    identityRoot: foldAgentPolicyV4(t3.agents.find((a) => a.agentPk === HEX32("a1")), proofA1.siblingsHex, proofA1.pathBits),
    identityMatchesTreeRoot:
      foldAgentPolicyV4(t3.agents.find((a) => a.agentPk === HEX32("a1")), proofA1.siblingsHex, proofA1.pathBits) === t3.root,
    excessBitsNull: foldLeafV4(agentLeafHash(newA1), proofA1.siblingsHex, proofA1.pathBits + (1n << BigInt(proofA1.depth))),
    depthZeroLeafRoot: foldLeafV4(agentLeafHash(policy("a1")), "", 0n)
  };

  /* Lifecycle edits: each is a canonical rebuild — pin the roots. */
  const edits = {
    add: treeBytes(addAgentV4(t3, policy("d4"))),
    remove: treeBytes(removeAgentV4(t3, HEX32("b2"))),
    removeToEmptyRoot: treeBytes(removeAgentV4(removeAgentV4(removeAgentV4(t3, HEX32("a1")), HEX32("b2")), HEX32("c3"))),
    update: treeBytes(updateAgentPolicyV4(t3, policy("b2", { maxPerSpend: "42" }))),
    rotate: treeBytes(rotateAgentV4(t3, HEX32("c3"), policy("d4", { periodSpent: "7" })))
  };

  /* agentSpend accounting advance: successor tree + invariant. */
  const spend = applyAgentSpendV4(t3, HEX32("a1"), {
    newPeriodStartDaa: "541000000",
    newPeriodSpent: "300000000"
  });
  const spendGolden = {
    previousPolicy: policyBytes(spend.previousPolicy),
    newPolicy: policyBytes(spend.newPolicy),
    tree: treeBytes(spend.tree),
    successorEqualsFold: spend.tree.root === foldAgentPolicyV4(spend.newPolicy, proofA1.siblingsHex, proofA1.pathBits)
  };

  return {
    api: apiSurface(m),
    constants: {
      AGENT_LEAF_DOMAIN: toHex(AGENT_LEAF_DOMAIN),
      AGENT_PADDING_DOMAIN: toHex(AGENT_PADDING_DOMAIN),
      PADDING_LEAF_HEX,
      MAX_AGENT_DEPTH,
      MAX_AGENTS
    },
    normalized: policyBytes(normalizeAgentPolicyV4(policy("a1"))),
    preimages,
    leaves,
    trees,
    proofSets,
    folds,
    edits,
    spend: spendGolden,
    rejects: {
      duplicateAgent: threw(() => buildAgentTreeV4([policy("a1"), policy("a1", { maxPerSpend: "5" })])),
      notArray: threw(() => buildAgentTreeV4("nope")),
      badPolicyIndexed: threw(() => buildAgentTreeV4([policy("a1"), { agentPk: "zz" }])),
      zeroMaxPerSpend: threw(() => normalizeAgentPolicyV4(policy("a1", { maxPerSpend: "0" }))),
      negativeSpent: threw(() => normalizeAgentPolicyV4(policy("a1", { periodSpent: "-1" }))),
      floatBudget: threw(() => normalizeAgentPolicyV4(policy("a1", { periodBudget: 5 }))),
      overMaxSompi: threw(() => normalizeAgentPolicyV4(policy("a1", { periodBudget: "2900000000000000001" }))),
      shortRoot: threw(() => normalizeAgentPolicyV4(policy("a1", { agentRecipientRoot: "cd" }))),
      proofNotInTree: threw(() => generateAgentProofV4(t3, HEX32("77"))),
      foldBadLeafType: threw(() => foldLeafV4("00".repeat(32), proofA1.siblingsHex, proofA1.pathBits)),
      foldShortLeaf: threw(() => foldLeafV4(agentLeafHash(policy("a1")).slice(0, 16), proofA1.siblingsHex, proofA1.pathBits)),
      foldOddHex: threw(() => foldLeafV4(agentLeafHash(policy("a1")), "abc", 0n)),
      foldBadWidth: threw(() => foldLeafV4(agentLeafHash(policy("a1")), "ab".repeat(31), 0n)),
      foldTooDeep: threw(() => foldLeafV4(agentLeafHash(policy("a1")), "ab".repeat(32 * 13), 0n)),
      foldPathBitsRange: threw(() => foldLeafV4(agentLeafHash(policy("a1")), "", 4096n)),
      addExisting: threw(() => addAgentV4(t3, policy("a1"))),
      removeMissing: threw(() => removeAgentV4(t3, HEX32("77"))),
      updateMissing: threw(() => updateAgentPolicyV4(t3, policy("77"))),
      rotateMissing: threw(() => rotateAgentV4(t3, HEX32("77"), policy("d4"))),
      rotateSameKey: threw(() => rotateAgentV4(t3, HEX32("a1"), policy("a1"))),
      spendMissing: threw(() => applyAgentSpendV4(t3, HEX32("77"), { newPeriodStartDaa: "0", newPeriodSpent: "0" }))
    }
  };
}

/*
 * Compute the complete F1 golden structure from a module pair.
 * mods = { recipientMerkle, agentMerkle } (any require root).
 */
function computeF1MerkleGolden(mods) {
  return {
    recipientMerkle: recipientGolden(mods.recipientMerkle),
    agentMerkle: agentGolden(mods.agentMerkle)
  };
}

module.exports = { computeF1MerkleGolden };
