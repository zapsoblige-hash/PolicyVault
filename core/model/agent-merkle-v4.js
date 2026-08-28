"use strict";

/*
 * PolicyVault v0.4 canonical agent-policy Merkle tree / proof SDK
 * (Checkpoint E §E1).
 *
 * This is the ONE tree builder + proof generator + verifier for the v0.4
 * agent authenticated set (docs/covenant-spec-v0.4.md §2/§3 — FROZEN ABI).
 * The production covenant is the authority; this module must produce
 * exactly the bytes the PRODUCTION covenant accepts (proven by
 * tests/vm/tests/v4_sdk_integration.rs, which drives SDK-generated proofs
 * through the real pv_call_encoder binary and the production
 * PolicyVault.v0.4.sil on the real TxScriptEngine).
 *
 * Canonical construction (frozen, byte-exact):
 *   leaf  = SHA256(0x50 0x56 0x34 0x01 || agentPk
 *                  || num8(maxPerSpend)      || num8(periodBudget)
 *                  || num8(periodLengthDaa)  || num8(periodStartDaa)
 *                  || num8(periodSpent)      || num8(approvalThreshold)
 *                  || num8(agentMaxFeePerTx) || agentRecipientRoot)
 *           (124-byte preimage; the covenant ALWAYS recomputes the leaf
 *            from typed call arguments, never accepts a preformed leaf)
 *   num8(v) = 8-byte little-endian (consensus OpNum2Bin(v,8) /
 *            serialize_i64 — injective over 0 <= v < 2^63; this module's
 *            numeric domain [0, MAX_SOMPI] sits strictly inside it)
 *   node  = SHA256(left || right)   (64-byte preimage — cannot collide
 *            with the 124-byte agent-leaf or 36-byte recipient-leaf
 *            preimages: three distinct lengths)
 *   depth <= 12 (siblings.length <= 384 and a multiple of 32; pathBits in
 *            [0, 4096) and fully consumed after the walk)
 *
 * Determinism / identity rules:
 *   - the agent x-only key is the UNIQUE identity inside one tree: two
 *     leaves with the same agentPk are REJECTED (they would be two
 *     independent budget lanes for one key — a policy-dilution hole);
 *   - real agent leaves are sorted ascending by agentPk (fixed-width
 *     lowercase hex sorts identically to byte order), so one logical
 *     agent set has exactly ONE root regardless of caller insertion order;
 *   - the leaf level is padded to the next power of two with the
 *     STRUCTURALLY UNSPENDABLE padding leaf (below) — never by
 *     duplicating a real leaf;
 *   - an EMPTY agent set is allowed and canonical: root = the padding
 *     leaf itself (depth 0). No agent can ever spend from it; the owner
 *     uses it to suspend all agent activity via ownerSetAgentRoot.
 *
 * SECURITY — WHY DUPLICATE-LAST PADDING IS FORBIDDEN HERE (Checkpoint E
 * finding). The v0.3 RECIPIENT tree pads by duplicating the last leaf,
 * which is benign there because recipient trees are static membership
 * sets. The v0.4 AGENT tree is DYNAMIC: every agentSpend advances the
 * target leaf's period accounting in place (single-leaf Merkle update).
 * If the last real agent's leaf were duplicated as padding, EACH padded
 * copy would itself be a valid, spendable member of the same root
 * carrying an independent copy of that agent's period accounting — one
 * extra full periodBudget lane per copy, consensus-accepted (verified
 * hostile on the real VM: v4_sdk_integration.rs
 * `v4_sdk_duplicate_padding_budget_lane_is_real_and_padding_is_unspendable`).
 * Padding therefore uses a constant leaf that can never satisfy
 * membership for ANY typed agent-policy preimage:
 *
 *   PADDING_LEAF = SHA256(0x50 0x56 0x34 0x00)
 *
 * (4-byte domain-separated preimage, recordType 0 = padding). Spending
 * through a padding slot would require exhibiting 124-byte agent-policy
 * arguments whose SHA256 equals PADDING_LEAF — a SHA-256 preimage.
 *
 * pathBits convention (exactly the covenant's): bit i (LSB-first) is 1
 * when the running node is the RIGHT child at level i, i.e. the sibling
 * is hashed on the LEFT: node = SHA256(sib || node).
 *
 * All identities are 32-byte x-only pubkeys (lowercase hex). Wallet
 * addresses must be resolved through the shared address-identity boundary
 * (sdk/src/address-identity.js) BEFORE reaching this module.
 *
 * BROWSER-PORTABLE (F1 byte-native refactor): all byte plumbing is
 * Uint8Array-native — no Buffer dependency — so this module runs
 * byte-identically in Node and inside the browser core bundle
 * (web/core-bundle.js crypto shim: update(<Uint8Array>) / digest()).
 * Byte identity with the pre-refactor Buffer implementation is pinned by
 * core/model/test/golden-f1-merkle.test.js (fixture captured from the
 * ORIGINAL code). In Node, hash outputs (agentLeafHash, tree levels) are
 * the node:crypto digest objects (Buffer IS a Uint8Array) exactly as
 * before; foldLeafV4 accepts any 32-byte Uint8Array (a Buffer still
 * qualifies — its reject message text is kept verbatim from the frozen
 * behavior fixture).
 */

const crypto = require("crypto");
const { parseSompi, parsePositiveSompi } = require("./amounts");
const { normalizeXOnlyPubkey, normalizeHex } = require("./vault-state");

const AGENT_LEAF_DOMAIN = Uint8Array.of(0x50, 0x56, 0x34, 0x01);
const AGENT_PADDING_DOMAIN = Uint8Array.of(0x50, 0x56, 0x34, 0x00);
const MAX_AGENT_DEPTH = 12;
const MAX_AGENTS = 1 << MAX_AGENT_DEPTH; // 4,096

function fail(message, code) {
  const error = new Error(`agent-merkle-v4: ${message}`);
  if (code) error.code = code;
  throw error;
}

/* ---- portable byte helpers (inputs validated upstream) ---- */

function bytesToHex(bytes) {
  let hex = "";
  for (let i = 0; i < bytes.length; i++) hex += bytes[i].toString(16).padStart(2, "0");
  return hex;
}

function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function concatBytes(chunks) {
  let total = 0;
  for (const c of chunks) total += c.length;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) {
    out.set(c, offset);
    offset += c.length;
  }
  return out;
}

function sha256(bytes) {
  return crypto.createHash("sha256").update(bytes).digest();
}

const PADDING_LEAF = sha256(AGENT_PADDING_DOMAIN);
const PADDING_LEAF_HEX = bytesToHex(PADDING_LEAF);

/* Consensus-canonical num8: 8-byte little-endian, injective over the
 * module's whole numeric domain (0 <= v <= MAX_SOMPI < 2^63). */
function num8(value, field) {
  const v = parseSompi(value, field);
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, v, true);
  return out;
}

/*
 * Normalize one agent policy (the full frozen leaf tuple). Strict
 * fail-closed validation; every quantity BigInt. periodSpent above
 * periodBudget is structurally representable (it simply cannot spend
 * until rollover) and is NOT rejected here — the covenant is the
 * authority on spendability, this module on byte shape.
 */
function normalizeAgentPolicyV4(input) {
  if (!input || typeof input !== "object") {
    fail("agent policy object is required");
  }
  return Object.freeze({
    agentPk: normalizeXOnlyPubkey(input.agentPk, "agentPolicy.agentPk"),
    maxPerSpend: parsePositiveSompi(input.maxPerSpend, "agentPolicy.maxPerSpend"),
    periodBudget: parsePositiveSompi(input.periodBudget, "agentPolicy.periodBudget"),
    periodLengthDaa: parsePositiveSompi(input.periodLengthDaa, "agentPolicy.periodLengthDaa"),
    periodStartDaa: parseSompi(input.periodStartDaa, "agentPolicy.periodStartDaa"),
    periodSpent: parseSompi(input.periodSpent, "agentPolicy.periodSpent"),
    approvalThreshold: parseSompi(input.approvalThreshold, "agentPolicy.approvalThreshold"),
    agentMaxFeePerTx: parseSompi(input.agentMaxFeePerTx, "agentPolicy.agentMaxFeePerTx"),
    agentRecipientRoot: normalizeHex(input.agentRecipientRoot, 32, "agentPolicy.agentRecipientRoot")
  });
}

/* The exact frozen 124-byte leaf preimage. */
function agentLeafPreimage(policyInput) {
  const p = normalizeAgentPolicyV4(policyInput);
  const preimage = concatBytes([
    AGENT_LEAF_DOMAIN,
    hexToBytes(p.agentPk),
    num8(p.maxPerSpend, "maxPerSpend"),
    num8(p.periodBudget, "periodBudget"),
    num8(p.periodLengthDaa, "periodLengthDaa"),
    num8(p.periodStartDaa, "periodStartDaa"),
    num8(p.periodSpent, "periodSpent"),
    num8(p.approvalThreshold, "approvalThreshold"),
    num8(p.agentMaxFeePerTx, "agentMaxFeePerTx"),
    hexToBytes(p.agentRecipientRoot)
  ]);
  if (preimage.length !== 124) {
    fail(`internal: agent-leaf preimage is ${preimage.length} bytes, not 124`);
  }
  return preimage;
}

/* Canonical agent-leaf hash (32 bytes). */
function agentLeafHash(policyInput) {
  return sha256(agentLeafPreimage(policyInput));
}

/*
 * Build the canonical agent tree from an array of agent policies
 * (0..4096 entries). Returns a frozen object:
 *   { root, agents, realCount, leafCount, depth, levels }
 * where `agents` is the sorted (by agentPk) normalized policy list,
 * `leafCount` includes unspendable padding, and `levels` holds the raw
 * byte levels for proof generation.
 */
function buildAgentTreeV4(agentsInput) {
  if (!Array.isArray(agentsInput)) {
    fail("agents must be an array of agent-policy objects (may be empty)");
  }
  const agents = agentsInput.map((a, i) => {
    try {
      return normalizeAgentPolicyV4(a);
    } catch (error) {
      fail(`agents[${i}]: ${error.message}`);
    }
  });
  const seen = new Set();
  for (const a of agents) {
    if (seen.has(a.agentPk)) {
      fail(`duplicate agentPk ${a.agentPk} — one key may hold exactly one policy leaf (duplicate leaves would be independent budget lanes)`, "DUPLICATE_AGENT");
    }
    seen.add(a.agentPk);
  }
  if (agents.length > MAX_AGENTS) {
    fail(`agent count ${agents.length} exceeds the maximum ${MAX_AGENTS} (depth ${MAX_AGENT_DEPTH})`);
  }
  agents.sort((x, y) => (x.agentPk < y.agentPk ? -1 : x.agentPk > y.agentPk ? 1 : 0));

  /* Leaf level: real leaves then UNSPENDABLE padding to the next power of
   * two (see the module header for why duplicate-last is forbidden). */
  let level = agents.map((a) => agentLeafHash(a));
  if (level.length === 0) {
    level = [PADDING_LEAF];
  }
  while ((level.length & (level.length - 1)) !== 0) {
    level.push(PADDING_LEAF);
  }
  const levels = [level];
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) {
      next.push(sha256(concatBytes([level[i], level[i + 1]])));
    }
    levels.push(next);
    level = next;
  }

  const depth = levels.length - 1;
  if (depth > MAX_AGENT_DEPTH) {
    fail(`tree depth ${depth} exceeds the covenant maximum ${MAX_AGENT_DEPTH}`);
  }

  return Object.freeze({
    root: bytesToHex(levels[levels.length - 1][0]),
    agents: Object.freeze(agents),
    realCount: agents.length,
    leafCount: levels[0].length,
    depth,
    levels
  });
}

function agentIndex(tree, agentPkHex, label) {
  const key = normalizeXOnlyPubkey(agentPkHex, label ?? "agentPk");
  const index = tree.agents.findIndex((a) => a.agentPk === key);
  return { key, index };
}

/*
 * Generate the canonical membership proof for one agent. Returns
 * { agentPk, policy, root, siblingsHex, pathBits, depth }:
 *   siblingsHex — depth * 32 bytes, leaf-to-root sibling order;
 *   pathBits    — BigInt; bit i set <=> node is the RIGHT child at level i.
 * Fails closed if the agent is not in the tree (padding slots are not
 * agents and can never be proven).
 */
function generateAgentProofV4(tree, agentPkHex) {
  const { key, index } = agentIndex(tree, agentPkHex);
  if (index < 0) {
    fail(`agent ${key} is not in this tree — refusing to fabricate a proof`);
  }
  let idx = index;
  const siblings = [];
  let pathBits = 0n;
  for (let levelIdx = 0; levelIdx < tree.depth; levelIdx++) {
    const level = tree.levels[levelIdx];
    const siblingIdx = idx % 2 === 0 ? idx + 1 : idx - 1;
    siblings.push(level[siblingIdx]);
    if (idx % 2 === 1) {
      pathBits |= 1n << BigInt(levelIdx);
    }
    idx = Math.floor(idx / 2);
  }
  return Object.freeze({
    agentPk: key,
    policy: tree.agents[index],
    root: tree.root,
    siblingsHex: bytesToHex(concatBytes(siblings)),
    pathBits,
    depth: tree.depth
  });
}

function normalizeSiblings(siblingsHex) {
  if (typeof siblingsHex !== "string" || !/^[0-9a-f]*$/.test(siblingsHex) || siblingsHex.length % 2 !== 0) {
    fail("siblingsHex must be lowercase hex");
  }
  const siblings = hexToBytes(siblingsHex);
  if (siblings.length % 32 !== 0) {
    fail("siblings length must be a multiple of 32 bytes");
  }
  if (siblings.length > 32 * MAX_AGENT_DEPTH) {
    fail(`proof depth ${siblings.length / 32} exceeds the covenant maximum ${MAX_AGENT_DEPTH}`);
  }
  return siblings;
}

function normalizePathBits(pathBits) {
  const bits = typeof pathBits === "bigint" ? pathBits : BigInt(pathBits);
  if (bits < 0n || bits >= BigInt(MAX_AGENTS)) {
    fail(`pathBits out of range [0, ${MAX_AGENTS})`);
  }
  return bits;
}

/*
 * Fold a leaf hash up a co-path — the exact covenant computeMerkleRoot
 * walk. Throws on malformed inputs exactly where the covenant would
 * abort; returns null when pathBits are not fully consumed (the covenant
 * requires bits == 0 after the walk).
 */
function foldLeafV4(leafBuffer, siblingsHex, pathBits) {
  if (!(leafBuffer instanceof Uint8Array) || leafBuffer.length !== 32) {
    fail("leaf must be a 32-byte Buffer");
  }
  const siblings = normalizeSiblings(siblingsHex);
  let bits = normalizePathBits(pathBits);
  const depth = siblings.length / 32;
  let node = leafBuffer;
  for (let level = 0; level < depth; level++) {
    const sib = siblings.subarray(level * 32, level * 32 + 32);
    if (bits % 2n === 1n) {
      node = sha256(concatBytes([sib, node]));
    } else {
      node = sha256(concatBytes([node, sib]));
    }
    bits /= 2n;
  }
  if (bits !== 0n) {
    return null; // excess path bits — the covenant rejects
  }
  return bytesToHex(node);
}

/* Fold a full agent policy up a co-path (successor-root derivation). */
function foldAgentPolicyV4(policyInput, siblingsHex, pathBits) {
  return foldLeafV4(agentLeafHash(policyInput), siblingsHex, pathBits);
}

/*
 * SDK-side proof verification: the exact covenant walk over the leaf
 * recomputed from the full policy. Local pre-check ONLY — the production
 * covenant remains the authority. Returns true/false for well-formed
 * inputs; throws on malformed inputs (odd hex, bad widths, depth > 12,
 * pathBits out of range) exactly where the covenant would abort.
 */
function verifyAgentProofV4({ root, policy, siblingsHex, pathBits }) {
  const rootHex = normalizeHex(root, 32, "root");
  const computed = foldAgentPolicyV4(policy, siblingsHex, pathBits);
  return computed !== null && computed === rootHex;
}

/* ---------------- canonical tree edits (owner lifecycle) ----------------
 * ownerSetAgentRoot replaces the committed root wholesale, so every edit
 * is a canonical REBUILD of the modified agent set: deterministic,
 * insertion-order-free, and re-validated from scratch. Each returns a NEW
 * tree; the input tree is never mutated. */

function addAgentV4(tree, policyInput) {
  const policy = normalizeAgentPolicyV4(policyInput);
  const { index } = agentIndex(tree, policy.agentPk, "new agentPk");
  if (index >= 0) {
    fail(`agent ${policy.agentPk} already exists — use updateAgentPolicyV4/rotateAgentV4`, "DUPLICATE_AGENT");
  }
  return buildAgentTreeV4([...tree.agents, policy]);
}

function removeAgentV4(tree, agentPkHex) {
  const { key, index } = agentIndex(tree, agentPkHex);
  if (index < 0) {
    fail(`agent ${key} is not in this tree — nothing to remove`);
  }
  return buildAgentTreeV4(tree.agents.filter((a) => a.agentPk !== key));
}

/* Replace one agent's policy IN PLACE (same key, new limits/roots). */
function updateAgentPolicyV4(tree, policyInput) {
  const policy = normalizeAgentPolicyV4(policyInput);
  const { index } = agentIndex(tree, policy.agentPk, "agentPk");
  if (index < 0) {
    fail(`agent ${policy.agentPk} is not in this tree — use addAgentV4`);
  }
  return buildAgentTreeV4(tree.agents.map((a) => (a.agentPk === policy.agentPk ? policy : a)));
}

/* Rotate an agent key: remove the old key's leaf, add the full new
 * policy under the new key (the caller decides whether accounting resets
 * — a rotation is a NEW leaf, so it carries whatever the new policy
 * states; there is no implicit carry-over). */
function rotateAgentV4(tree, currentPkHex, newPolicyInput) {
  const { key, index } = agentIndex(tree, currentPkHex, "currentPk");
  if (index < 0) {
    fail(`agent ${key} is not in this tree — cannot rotate`);
  }
  const newPolicy = normalizeAgentPolicyV4(newPolicyInput);
  if (newPolicy.agentPk === key) {
    fail("rotation requires a NEW agent key — use updateAgentPolicyV4 to re-policy the same key");
  }
  const without = tree.agents.filter((a) => a.agentPk !== key);
  return buildAgentTreeV4([...without, newPolicy]);
}

/*
 * Apply an agentSpend accounting advance to the tree: ONLY the spending
 * agent's periodStartDaa/periodSpent change; every other leaf (and all
 * padding) is untouched. Returns { tree, previousPolicy, newPolicy }.
 *
 * INVARIANT (asserted, fail-closed): with unspendable padding the
 * canonical rebuild of the updated set equals the covenant's single-leaf
 * fold of the new leaf up the old co-path — i.e. the SDK's successor
 * tree is byte-identical to the successor root consensus enforces.
 */
function applyAgentSpendV4(tree, agentPkHex, { newPeriodStartDaa, newPeriodSpent }) {
  const { key, index } = agentIndex(tree, agentPkHex);
  if (index < 0) {
    fail(`agent ${key} is not in this tree — cannot advance accounting`);
  }
  const previousPolicy = tree.agents[index];
  const newPolicy = normalizeAgentPolicyV4({
    ...previousPolicy,
    periodStartDaa: parseSompi(newPeriodStartDaa, "newPeriodStartDaa"),
    periodSpent: parseSompi(newPeriodSpent, "newPeriodSpent")
  });
  const proof = generateAgentProofV4(tree, key);
  const foldedRoot = foldAgentPolicyV4(newPolicy, proof.siblingsHex, proof.pathBits);
  const rebuilt = buildAgentTreeV4(tree.agents.map((a) => (a.agentPk === key ? newPolicy : a)));
  if (rebuilt.root !== foldedRoot) {
    fail(
      `internal invariant violated: canonical rebuild root ${rebuilt.root} != single-leaf fold root ${foldedRoot} — refusing to emit a successor tree that disagrees with consensus`
    );
  }
  return Object.freeze({ tree: rebuilt, previousPolicy, newPolicy });
}

module.exports = {
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
};
