"use strict";

/*
 * v0.6 TOKEN-AGENT policy Merkle tree — the per-agent policy leaves
 * committed by a PolicyVault v0.6 controller's agentRoot
 * (contracts/PolicyVault.v0.6.sil CANDIDATE; docs/postlaunch/v0.6-architecture-freeze.md).
 *
 * Leaf (149-byte preimage; distinct from every other PolicyVault leaf
 * length — v0.5 agent 125, v0.4 agent 124, recipient 36, node 64, v0.6
 * swap policy 229):
 *   sha256(0x50563601 || agentPk(32) || num8(tokenMaxPerSpend) ||
 *          num8(tokenPeriodBudget) || num8(periodLengthDaa) ||
 *          num8(periodStartDaa) || num8(tokenPeriodSpent) ||
 *          num8(agentMaxFeePerTx) || num8(agentMaxCarryKas) ||
 *          num8(kasMaxPerSwap) || num8(kasPeriodBudget) || num8(kasPeriodSpent) ||
 *          agentRecipientRoot(32) || 0x00)
 *
 * THREE DOMAINS inside one leaf, never mixed: tokenMaxPerSpend /
 * tokenPeriodBudget / tokenPeriodSpent are TOKEN atomic units (bound
 * tokenAgentSpend + tokenAtomicSell); kasMaxPerSwap / kasPeriodBudget /
 * kasPeriodSpent are KAS sompi of BUY consideration (bound tokenAtomicBuy;
 * kasMaxPerSwap = 0 means NO buy authority); agentMaxFeePerTx /
 * agentMaxCarryKas are KAS sompi of the fee-reserve / carry domains. One
 * period clock resets BOTH spent counters at rollover.
 *
 * Tree mechanics (sorted leaves, UNSPENDABLE padding, depth <= 12,
 * single-leaf co-path fold == the covenant computeMerkleRoot) are the
 * VM-proven v0.4/v0.5 mechanism.
 *
 * Status: IMPLEMENTED + UNIT-TESTED; leaf bytes pinned against the SAME
 * Rust leaf function the real-engine v0.6 suite accepts
 * (core/model/test/fixtures/token-agent-leaf-v6.json).
 */

const crypto = require("crypto");
const { parseSompi } = require("./amounts");
const { normalizeHex, normalizeXOnlyPubkey } = require("./vault-state");
const { parseAtomicAmount } = require("./token-amounts");

const TOKEN_AGENT_LEAF_DOMAIN_V6 = Uint8Array.of(0x50, 0x56, 0x36, 0x01);
const TOKEN_AGENT_PADDING_DOMAIN_V6 = Uint8Array.of(0x50, 0x56, 0x36, 0x00);
const RECIPIENT_SCHEME_P2PK = 0x00;
const MAX_AGENT_DEPTH = 12;
const MAX_AGENTS = 1 << MAX_AGENT_DEPTH;
const LEAF_PREIMAGE_LEN_V6 = 149;

function fail(message, code) {
  const error = new Error(`agent-merkle-v6: ${message}`);
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
const PADDING_LEAF = sha256(TOKEN_AGENT_PADDING_DOMAIN_V6);
const PADDING_LEAF_HEX = bytesToHex(PADDING_LEAF);

function num8(value) {
  if (typeof value !== "bigint" || value < 0n || value > 0x7fffffffffffffffn) fail("num8 requires a BigInt in 0..2^63-1");
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
  const n = parseSompi(value, field);
  if (positive && n <= 0n) fail(`${field} must be > 0`);
  return n;
}

const TOKEN_AGENT_POLICY_FIELDS_V6 = Object.freeze([
  "agentPk",
  "tokenMaxPerSpend",
  "tokenPeriodBudget",
  "periodLengthDaa",
  "periodStartDaa",
  "tokenPeriodSpent",
  "agentMaxFeePerTx",
  "agentMaxCarryKas",
  "kasMaxPerSwap",
  "kasPeriodBudget",
  "kasPeriodSpent",
  "agentRecipientRoot"
]);

/*
 * Normalize one v0.6 token-agent policy (the full frozen leaf tuple).
 * Strict fail-closed validation; every quantity BigInt. kasMaxPerSwap and
 * kasPeriodBudget MAY be 0 (an agent without BUY authority); the token
 * caps must be positive (a leaf without any authority is not a policy).
 */
function normalizeTokenAgentPolicyV6(input) {
  if (!input || typeof input !== "object") fail("token agent policy object is required");
  for (const key of Object.keys(input)) {
    if (!TOKEN_AGENT_POLICY_FIELDS_V6.includes(key)) fail(`unknown token agent policy field ${JSON.stringify(key)} — closed layout, failing closed`);
  }
  const p = Object.freeze({
    agentPk: normalizeXOnlyPubkey(input.agentPk, "agentPolicy.agentPk"),
    tokenMaxPerSpend: parsePositiveAtomic(input.tokenMaxPerSpend, "agentPolicy.tokenMaxPerSpend"),
    tokenPeriodBudget: parsePositiveAtomic(input.tokenPeriodBudget, "agentPolicy.tokenPeriodBudget"),
    periodLengthDaa: parseDaa(input.periodLengthDaa, "agentPolicy.periodLengthDaa", { positive: true }),
    periodStartDaa: parseDaa(input.periodStartDaa, "agentPolicy.periodStartDaa"),
    tokenPeriodSpent: parseAtomicAmount(input.tokenPeriodSpent, "agentPolicy.tokenPeriodSpent"),
    agentMaxFeePerTx: parseSompi(input.agentMaxFeePerTx, "agentPolicy.agentMaxFeePerTx"),
    agentMaxCarryKas: parseSompi(input.agentMaxCarryKas, "agentPolicy.agentMaxCarryKas"),
    kasMaxPerSwap: parseSompi(input.kasMaxPerSwap, "agentPolicy.kasMaxPerSwap"),
    kasPeriodBudget: parseSompi(input.kasPeriodBudget, "agentPolicy.kasPeriodBudget"),
    kasPeriodSpent: parseSompi(input.kasPeriodSpent, "agentPolicy.kasPeriodSpent"),
    agentRecipientRoot: normalizeHex(input.agentRecipientRoot, 32, "agentPolicy.agentRecipientRoot")
  });
  if (p.kasMaxPerSwap > p.kasPeriodBudget && p.kasPeriodBudget !== 0n) fail("agentPolicy.kasMaxPerSwap exceeds kasPeriodBudget — an unusable BUY cap; failing closed");
  return p;
}

function tokenAgentLeafPreimageV6(policyInput) {
  const p = normalizeTokenAgentPolicyV6(policyInput);
  const preimage = concatBytes([
    TOKEN_AGENT_LEAF_DOMAIN_V6,
    hexToBytes(p.agentPk),
    num8(p.tokenMaxPerSpend),
    num8(p.tokenPeriodBudget),
    num8(p.periodLengthDaa),
    num8(p.periodStartDaa),
    num8(p.tokenPeriodSpent),
    num8(p.agentMaxFeePerTx),
    num8(p.agentMaxCarryKas),
    num8(p.kasMaxPerSwap),
    num8(p.kasPeriodBudget),
    num8(p.kasPeriodSpent),
    hexToBytes(p.agentRecipientRoot),
    Uint8Array.of(RECIPIENT_SCHEME_P2PK)
  ]);
  if (preimage.length !== LEAF_PREIMAGE_LEN_V6) fail(`internal: token-agent leaf preimage is ${preimage.length} bytes, not ${LEAF_PREIMAGE_LEN_V6}`);
  return preimage;
}
function tokenAgentLeafHashV6(policyInput) {
  return sha256(tokenAgentLeafPreimageV6(policyInput));
}

function buildTokenAgentTreeV6(agentsInput) {
  if (!Array.isArray(agentsInput)) fail("agents must be an array of token-agent-policy objects (may be empty)");
  const agents = agentsInput.map((a, i) => {
    try {
      return normalizeTokenAgentPolicyV6(a);
    } catch (error) {
      fail(`agents[${i}]: ${error.message}`);
    }
  });
  const seen = new Set();
  for (const a of agents) {
    if (seen.has(a.agentPk)) fail(`duplicate agentPk ${a.agentPk} — one key may hold exactly one policy leaf`, "DUPLICATE_AGENT");
    seen.add(a.agentPk);
  }
  if (agents.length > MAX_AGENTS) fail(`agent count ${agents.length} exceeds the maximum ${MAX_AGENTS} (depth ${MAX_AGENT_DEPTH})`);
  agents.sort((x, y) => (x.agentPk < y.agentPk ? -1 : x.agentPk > y.agentPk ? 1 : 0));

  let level = agents.map((a) => tokenAgentLeafHashV6(a));
  if (level.length === 0) level = [PADDING_LEAF];
  while ((level.length & (level.length - 1)) !== 0) level.push(PADDING_LEAF);
  const levels = [level];
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) next.push(sha256(concatBytes([level[i], level[i + 1]])));
    levels.push(next);
    level = next;
  }
  const depth = levels.length - 1;
  if (depth > MAX_AGENT_DEPTH) fail(`tree depth ${depth} exceeds the covenant maximum ${MAX_AGENT_DEPTH}`);
  return Object.freeze({ root: bytesToHex(levels[levels.length - 1][0]), agents: Object.freeze(agents), realCount: agents.length, leafCount: levels[0].length, depth, levels });
}

function agentIndex(tree, agentPkHex, label) {
  const key = normalizeXOnlyPubkey(agentPkHex, label ?? "agentPk");
  return { key, index: tree.agents.findIndex((a) => a.agentPk === key) };
}

function generateTokenAgentProofV6(tree, agentPkHex) {
  const { key, index } = agentIndex(tree, agentPkHex);
  if (index < 0) fail(`agent ${key} is not in this tree — refusing to fabricate a proof`);
  let idx = index;
  const siblings = [];
  let pathBits = 0n;
  for (let levelIdx = 0; levelIdx < tree.depth; levelIdx++) {
    const level = tree.levels[levelIdx];
    const siblingIdx = idx % 2 === 0 ? idx + 1 : idx - 1;
    siblings.push(level[siblingIdx]);
    if (idx % 2 === 1) pathBits |= 1n << BigInt(levelIdx);
    idx = Math.floor(idx / 2);
  }
  return Object.freeze({ agentPk: key, policy: tree.agents[index], root: tree.root, siblingsHex: bytesToHex(concatBytes(siblings)), pathBits, depth: tree.depth });
}

function normalizeSiblings(siblingsHex) {
  if (typeof siblingsHex !== "string" || !/^[0-9a-f]*$/.test(siblingsHex) || siblingsHex.length % 2 !== 0) fail("siblingsHex must be lowercase hex");
  const siblings = hexToBytes(siblingsHex);
  if (siblings.length % 32 !== 0) fail("siblings length must be a multiple of 32 bytes");
  if (siblings.length > 32 * MAX_AGENT_DEPTH) fail(`proof depth ${siblings.length / 32} exceeds the covenant maximum ${MAX_AGENT_DEPTH}`);
  return siblings;
}
function normalizePathBits(pathBits) {
  const bits = typeof pathBits === "bigint" ? pathBits : BigInt(pathBits);
  if (bits < 0n || bits >= BigInt(MAX_AGENTS)) fail(`pathBits out of range [0, ${MAX_AGENTS})`);
  return bits;
}

/* Exact covenant computeMerkleRoot walk; null when path bits are not consumed. */
function foldLeafV6(leafBuffer, siblingsHex, pathBits) {
  if (!(leafBuffer instanceof Uint8Array) || leafBuffer.length !== 32) fail("leaf must be a 32-byte Uint8Array");
  const siblings = normalizeSiblings(siblingsHex);
  let bits = normalizePathBits(pathBits);
  const depth = siblings.length / 32;
  let node = leafBuffer;
  for (let level = 0; level < depth; level++) {
    const sib = siblings.subarray(level * 32, level * 32 + 32);
    node = bits % 2n === 1n ? sha256(concatBytes([sib, node])) : sha256(concatBytes([node, sib]));
    bits /= 2n;
  }
  if (bits !== 0n) return null;
  return bytesToHex(node);
}
function foldTokenAgentPolicyV6(policyInput, siblingsHex, pathBits) {
  return foldLeafV6(tokenAgentLeafHashV6(policyInput), siblingsHex, pathBits);
}
function verifyTokenAgentProofV6({ root, policy, siblingsHex, pathBits }) {
  const rootHex = normalizeHex(root, 32, "root");
  const computed = foldTokenAgentPolicyV6(policy, siblingsHex, pathBits);
  return computed !== null && computed === rootHex;
}

/* ---- canonical tree edits (owner lifecycle; every edit is a rebuild) ---- */
function addTokenAgentV6(tree, policyInput) {
  const policy = normalizeTokenAgentPolicyV6(policyInput);
  if (agentIndex(tree, policy.agentPk, "new agentPk").index >= 0) fail(`agent ${policy.agentPk} already exists — use updateTokenAgentPolicyV6/rotateTokenAgentV6`, "DUPLICATE_AGENT");
  return buildTokenAgentTreeV6([...tree.agents, policy]);
}
function removeTokenAgentV6(tree, agentPkHex) {
  const { key, index } = agentIndex(tree, agentPkHex);
  if (index < 0) fail(`agent ${key} is not in this tree — nothing to remove`);
  return buildTokenAgentTreeV6(tree.agents.filter((a) => a.agentPk !== key));
}
function updateTokenAgentPolicyV6(tree, policyInput) {
  const policy = normalizeTokenAgentPolicyV6(policyInput);
  if (agentIndex(tree, policy.agentPk, "agentPk").index < 0) fail(`agent ${policy.agentPk} is not in this tree — use addTokenAgentV6`);
  return buildTokenAgentTreeV6(tree.agents.map((a) => (a.agentPk === policy.agentPk ? policy : a)));
}
function rotateTokenAgentV6(tree, currentPkHex, newPolicyInput) {
  const { key, index } = agentIndex(tree, currentPkHex, "currentPk");
  if (index < 0) fail(`agent ${key} is not in this tree — cannot rotate`);
  const newPolicy = normalizeTokenAgentPolicyV6(newPolicyInput);
  if (newPolicy.agentPk === key) fail("rotation requires a NEW agent key — use updateTokenAgentPolicyV6 to re-policy the same key");
  return buildTokenAgentTreeV6([...tree.agents.filter((a) => a.agentPk !== key), newPolicy]);
}

/*
 * Apply an agent accounting advance (spend / sell / buy): ONLY the acting
 * agent's periodStartDaa / tokenPeriodSpent / kasPeriodSpent change.
 * INVARIANT (asserted): the canonical rebuild equals the covenant's
 * single-leaf fold of the new leaf up the old co-path.
 */
function applyTokenAgentAdvanceV6(tree, agentPkHex, { newPeriodStartDaa, newTokenPeriodSpent, newKasPeriodSpent }) {
  const { key, index } = agentIndex(tree, agentPkHex);
  if (index < 0) fail(`agent ${key} is not in this tree — cannot advance accounting`);
  const previousPolicy = tree.agents[index];
  const newPolicy = normalizeTokenAgentPolicyV6({
    ...previousPolicy,
    periodStartDaa: parseDaa(newPeriodStartDaa, "newPeriodStartDaa"),
    tokenPeriodSpent: parseAtomicAmount(newTokenPeriodSpent, "newTokenPeriodSpent"),
    kasPeriodSpent: parseSompi(newKasPeriodSpent, "newKasPeriodSpent")
  });
  const proof = generateTokenAgentProofV6(tree, key);
  const foldedRoot = foldTokenAgentPolicyV6(newPolicy, proof.siblingsHex, proof.pathBits);
  const rebuilt = buildTokenAgentTreeV6(tree.agents.map((a) => (a.agentPk === key ? newPolicy : a)));
  if (rebuilt.root !== foldedRoot) fail(`internal invariant violated: canonical rebuild root ${rebuilt.root} != single-leaf fold root ${foldedRoot} — refusing to emit a successor tree that disagrees with consensus`);
  return Object.freeze({ tree: rebuilt, previousPolicy, newPolicy });
}

function tokenAgentPolicyToJsonV6(p) {
  const n = normalizeTokenAgentPolicyV6(p);
  const out = {};
  for (const f of TOKEN_AGENT_POLICY_FIELDS_V6) out[f] = typeof n[f] === "bigint" ? n[f].toString() : n[f];
  return out;
}

module.exports = {
  TOKEN_AGENT_LEAF_DOMAIN_V6,
  TOKEN_AGENT_PADDING_DOMAIN_V6,
  TOKEN_AGENT_POLICY_FIELDS_V6,
  RECIPIENT_SCHEME_P2PK,
  PADDING_LEAF_HEX,
  MAX_AGENT_DEPTH,
  MAX_AGENTS,
  LEAF_PREIMAGE_LEN_V6,
  normalizeTokenAgentPolicyV6,
  tokenAgentLeafPreimageV6,
  tokenAgentLeafHashV6,
  buildTokenAgentTreeV6,
  generateTokenAgentProofV6,
  verifyTokenAgentProofV6,
  foldLeafV6,
  foldTokenAgentPolicyV6,
  addTokenAgentV6,
  removeTokenAgentV6,
  updateTokenAgentPolicyV6,
  rotateTokenAgentV6,
  applyTokenAgentAdvanceV6,
  tokenAgentPolicyToJsonV6
};
