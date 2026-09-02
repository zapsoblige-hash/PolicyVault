"use strict";

/*
 * v0.5 TOKEN-AGENT policy Merkle tree — the per-agent, TOKEN-denominated
 * policy leaves committed by a PolicyVault v0.5 controller's agentRoot
 * (contracts/PolicyVault.v0.5.sil; docs/postlaunch/v0.5-design-freeze.md).
 *
 * Frozen leaf (125-byte preimage; distinct from every other PolicyVault
 * leaf length — v0.4 agent 124, recipient 36, node 64):
 *   sha256(0x50563501 || agentPk(32) || num8(tokenMaxPerSpend) ||
 *          num8(tokenPeriodBudget) || num8(periodLengthDaa) ||
 *          num8(periodStartDaa) || num8(tokenPeriodSpent) ||
 *          num8(agentMaxFeePerTx) || num8(agentMaxCarryKas) ||
 *          agentRecipientRoot(32) || 0x00)
 * where num8 = 8-byte little-endian and the trailing byte is the
 * recipient scheme (0x00 = p2pk, the only scheme v0.5 supports).
 *
 * TWO DOMAINS inside one leaf, never mixed: tokenMaxPerSpend /
 * tokenPeriodBudget / tokenPeriodSpent are TOKEN atomic units (i64-bounded,
 * see core/assets/kcc20 parseAtomicAmount); agentMaxFeePerTx /
 * agentMaxCarryKas are KAS sompi. DAA fields are block-score integers.
 *
 * Tree mechanics (sorted leaves, UNSPENDABLE padding, depth <= 12,
 * single-leaf co-path fold == the covenant computeMerkleRoot) are the
 * VM-proven v0.4 mechanism; the recipient tree reuses the v0.3 recipient
 * leaf (core/model/recipient-merkle-v3.js).
 *
 * Status: IMPLEMENTED + UNIT-TESTED; leaf bytes pinned to the fixture
 * captured from the SAME Rust leaf function the real-engine v0.5
 * production suite accepted (core/model/test/fixtures/token-agent-leaf-v5.json).
 */

const crypto = require("crypto");
const { parseSompi } = require("./amounts");
const { normalizeHex, normalizeXOnlyPubkey } = require("./vault-state");
const { parseAtomicAmount } = require("./token-amounts");

const TOKEN_AGENT_LEAF_DOMAIN = Uint8Array.of(0x50, 0x56, 0x35, 0x01);
const TOKEN_AGENT_PADDING_DOMAIN = Uint8Array.of(0x50, 0x56, 0x35, 0x00);
const RECIPIENT_SCHEME_P2PK = 0x00;
const MAX_AGENT_DEPTH = 12;
const MAX_AGENTS = 1 << MAX_AGENT_DEPTH;
const LEAF_PREIMAGE_LEN = 125;

function fail(message, code) {
  const error = new Error(`agent-merkle-v5: ${message}`);
  if (code) error.code = code;
  throw error;
}

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
  return new Uint8Array(crypto.createHash("sha256").update(bytes).digest());
}

const PADDING_LEAF = sha256(TOKEN_AGENT_PADDING_DOMAIN);
const PADDING_LEAF_HEX = bytesToHex(PADDING_LEAF);

/* 8-byte little-endian over 0 <= v < 2^63 (injective over both domains). */
function num8(value) {
  if (typeof value !== "bigint" || value < 0n || value > 0x7fffffffffffffffn) {
    fail("num8 requires a BigInt in 0..2^63-1");
  }
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, value, true);
  return out;
}

function parsePositiveAtomic(value, field) {
  const n = parseAtomicAmount(value, field);
  if (n <= 0n) fail(`${field} must be > 0 (atomic token units)`);
  return n;
}
function parseDaa(value, field, { positive = false } = {}) {
  const n = parseSompi(value, field); // integer domain check (0..MAX_SOMPI is ample for DAA scores)
  if (positive && n <= 0n) fail(`${field} must be > 0`);
  return n;
}

/*
 * Normalize one token-agent policy (the full frozen leaf tuple). Strict
 * fail-closed validation; every quantity BigInt. tokenPeriodSpent above
 * tokenPeriodBudget is representable (cannot spend until rollover) — the
 * covenant is the authority on spendability, this module on byte shape.
 */
function normalizeTokenAgentPolicyV5(input) {
  if (!input || typeof input !== "object") {
    fail("token agent policy object is required");
  }
  for (const key of Object.keys(input)) {
    if (!TOKEN_AGENT_POLICY_FIELDS.includes(key)) {
      fail(`unknown token agent policy field ${JSON.stringify(key)} — closed layout, failing closed`);
    }
  }
  return Object.freeze({
    agentPk: normalizeXOnlyPubkey(input.agentPk, "agentPolicy.agentPk"),
    tokenMaxPerSpend: parsePositiveAtomic(input.tokenMaxPerSpend, "agentPolicy.tokenMaxPerSpend"),
    tokenPeriodBudget: parsePositiveAtomic(input.tokenPeriodBudget, "agentPolicy.tokenPeriodBudget"),
    periodLengthDaa: parseDaa(input.periodLengthDaa, "agentPolicy.periodLengthDaa", { positive: true }),
    periodStartDaa: parseDaa(input.periodStartDaa, "agentPolicy.periodStartDaa"),
    tokenPeriodSpent: parseAtomicAmount(input.tokenPeriodSpent, "agentPolicy.tokenPeriodSpent"),
    agentMaxFeePerTx: parseSompi(input.agentMaxFeePerTx, "agentPolicy.agentMaxFeePerTx"),
    agentMaxCarryKas: parseSompi(input.agentMaxCarryKas, "agentPolicy.agentMaxCarryKas"),
    agentRecipientRoot: normalizeHex(input.agentRecipientRoot, 32, "agentPolicy.agentRecipientRoot")
  });
}

const TOKEN_AGENT_POLICY_FIELDS = Object.freeze([
  "agentPk",
  "tokenMaxPerSpend",
  "tokenPeriodBudget",
  "periodLengthDaa",
  "periodStartDaa",
  "tokenPeriodSpent",
  "agentMaxFeePerTx",
  "agentMaxCarryKas",
  "agentRecipientRoot"
]);

function tokenAgentLeafPreimage(policyInput) {
  const p = normalizeTokenAgentPolicyV5(policyInput);
  const preimage = concatBytes([
    TOKEN_AGENT_LEAF_DOMAIN,
    hexToBytes(p.agentPk),
    num8(p.tokenMaxPerSpend),
    num8(p.tokenPeriodBudget),
    num8(p.periodLengthDaa),
    num8(p.periodStartDaa),
    num8(p.tokenPeriodSpent),
    num8(p.agentMaxFeePerTx),
    num8(p.agentMaxCarryKas),
    hexToBytes(p.agentRecipientRoot),
    Uint8Array.of(RECIPIENT_SCHEME_P2PK)
  ]);
  if (preimage.length !== LEAF_PREIMAGE_LEN) {
    fail(`internal: token-agent leaf preimage is ${preimage.length} bytes, not ${LEAF_PREIMAGE_LEN}`);
  }
  return preimage;
}

function tokenAgentLeafHash(policyInput) {
  return sha256(tokenAgentLeafPreimage(policyInput));
}

function buildTokenAgentTreeV5(agentsInput) {
  if (!Array.isArray(agentsInput)) {
    fail("agents must be an array of token-agent-policy objects (may be empty)");
  }
  const agents = agentsInput.map((a, i) => {
    try {
      return normalizeTokenAgentPolicyV5(a);
    } catch (error) {
      fail(`agents[${i}]: ${error.message}`);
    }
  });
  const seen = new Set();
  for (const a of agents) {
    if (seen.has(a.agentPk)) {
      fail(`duplicate agentPk ${a.agentPk} — one key may hold exactly one policy leaf`, "DUPLICATE_AGENT");
    }
    seen.add(a.agentPk);
  }
  if (agents.length > MAX_AGENTS) {
    fail(`agent count ${agents.length} exceeds the maximum ${MAX_AGENTS} (depth ${MAX_AGENT_DEPTH})`);
  }
  agents.sort((x, y) => (x.agentPk < y.agentPk ? -1 : x.agentPk > y.agentPk ? 1 : 0));

  let level = agents.map((a) => tokenAgentLeafHash(a));
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

function generateTokenAgentProofV5(tree, agentPkHex) {
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

/* Exact covenant computeMerkleRoot walk; null when path bits are not consumed. */
function foldLeafV5(leafBuffer, siblingsHex, pathBits) {
  if (!(leafBuffer instanceof Uint8Array) || leafBuffer.length !== 32) {
    fail("leaf must be a 32-byte Uint8Array");
  }
  const siblings = normalizeSiblings(siblingsHex);
  let bits = normalizePathBits(pathBits);
  const depth = siblings.length / 32;
  let node = leafBuffer;
  for (let level = 0; level < depth; level++) {
    const sib = siblings.subarray(level * 32, level * 32 + 32);
    node = bits % 2n === 1n ? sha256(concatBytes([sib, node])) : sha256(concatBytes([node, sib]));
    bits /= 2n;
  }
  if (bits !== 0n) {
    return null;
  }
  return bytesToHex(node);
}

function foldTokenAgentPolicyV5(policyInput, siblingsHex, pathBits) {
  return foldLeafV5(tokenAgentLeafHash(policyInput), siblingsHex, pathBits);
}

function verifyTokenAgentProofV5({ root, policy, siblingsHex, pathBits }) {
  const rootHex = normalizeHex(root, 32, "root");
  const computed = foldTokenAgentPolicyV5(policy, siblingsHex, pathBits);
  return computed !== null && computed === rootHex;
}

/* ---- canonical tree edits (owner lifecycle; every edit is a rebuild) ---- */
function addTokenAgentV5(tree, policyInput) {
  const policy = normalizeTokenAgentPolicyV5(policyInput);
  if (agentIndex(tree, policy.agentPk, "new agentPk").index >= 0) {
    fail(`agent ${policy.agentPk} already exists — use updateTokenAgentPolicyV5/rotateTokenAgentV5`, "DUPLICATE_AGENT");
  }
  return buildTokenAgentTreeV5([...tree.agents, policy]);
}
function removeTokenAgentV5(tree, agentPkHex) {
  const { key, index } = agentIndex(tree, agentPkHex);
  if (index < 0) fail(`agent ${key} is not in this tree — nothing to remove`);
  return buildTokenAgentTreeV5(tree.agents.filter((a) => a.agentPk !== key));
}
function updateTokenAgentPolicyV5(tree, policyInput) {
  const policy = normalizeTokenAgentPolicyV5(policyInput);
  if (agentIndex(tree, policy.agentPk, "agentPk").index < 0) fail(`agent ${policy.agentPk} is not in this tree — use addTokenAgentV5`);
  return buildTokenAgentTreeV5(tree.agents.map((a) => (a.agentPk === policy.agentPk ? policy : a)));
}
function rotateTokenAgentV5(tree, currentPkHex, newPolicyInput) {
  const { key, index } = agentIndex(tree, currentPkHex, "currentPk");
  if (index < 0) fail(`agent ${key} is not in this tree — cannot rotate`);
  const newPolicy = normalizeTokenAgentPolicyV5(newPolicyInput);
  if (newPolicy.agentPk === key) fail("rotation requires a NEW agent key — use updateTokenAgentPolicyV5 to re-policy the same key");
  return buildTokenAgentTreeV5([...tree.agents.filter((a) => a.agentPk !== key), newPolicy]);
}

/*
 * Apply a tokenAgentSpend accounting advance: ONLY the spending agent's
 * periodStartDaa/tokenPeriodSpent change. INVARIANT (asserted): the
 * canonical rebuild equals the covenant's single-leaf fold of the new
 * leaf up the old co-path.
 */
function applyTokenAgentSpendV5(tree, agentPkHex, { newPeriodStartDaa, newTokenPeriodSpent }) {
  const { key, index } = agentIndex(tree, agentPkHex);
  if (index < 0) fail(`agent ${key} is not in this tree — cannot advance accounting`);
  const previousPolicy = tree.agents[index];
  const newPolicy = normalizeTokenAgentPolicyV5({
    ...previousPolicy,
    periodStartDaa: parseDaa(newPeriodStartDaa, "newPeriodStartDaa"),
    tokenPeriodSpent: parseAtomicAmount(newTokenPeriodSpent, "newTokenPeriodSpent")
  });
  const proof = generateTokenAgentProofV5(tree, key);
  const foldedRoot = foldTokenAgentPolicyV5(newPolicy, proof.siblingsHex, proof.pathBits);
  const rebuilt = buildTokenAgentTreeV5(tree.agents.map((a) => (a.agentPk === key ? newPolicy : a)));
  if (rebuilt.root !== foldedRoot) {
    fail(`internal invariant violated: canonical rebuild root ${rebuilt.root} != single-leaf fold root ${foldedRoot} — refusing to emit a successor tree that disagrees with consensus`);
  }
  return Object.freeze({ tree: rebuilt, previousPolicy, newPolicy });
}

function tokenAgentPolicyToJsonV5(p) {
  const n = normalizeTokenAgentPolicyV5(p);
  return {
    agentPk: n.agentPk,
    tokenMaxPerSpend: n.tokenMaxPerSpend.toString(),
    tokenPeriodBudget: n.tokenPeriodBudget.toString(),
    periodLengthDaa: n.periodLengthDaa.toString(),
    periodStartDaa: n.periodStartDaa.toString(),
    tokenPeriodSpent: n.tokenPeriodSpent.toString(),
    agentMaxFeePerTx: n.agentMaxFeePerTx.toString(),
    agentMaxCarryKas: n.agentMaxCarryKas.toString(),
    agentRecipientRoot: n.agentRecipientRoot
  };
}

module.exports = {
  TOKEN_AGENT_LEAF_DOMAIN,
  TOKEN_AGENT_PADDING_DOMAIN,
  TOKEN_AGENT_POLICY_FIELDS,
  RECIPIENT_SCHEME_P2PK,
  PADDING_LEAF_HEX,
  MAX_AGENT_DEPTH,
  MAX_AGENTS,
  LEAF_PREIMAGE_LEN,
  normalizeTokenAgentPolicyV5,
  tokenAgentLeafPreimage,
  tokenAgentLeafHash,
  buildTokenAgentTreeV5,
  generateTokenAgentProofV5,
  verifyTokenAgentProofV5,
  foldLeafV5,
  foldTokenAgentPolicyV5,
  addTokenAgentV5,
  removeTokenAgentV5,
  updateTokenAgentPolicyV5,
  rotateTokenAgentV5,
  applyTokenAgentSpendV5,
  tokenAgentPolicyToJsonV5
};
