"use strict";

/*
 * HIERARCHICAL DELEGATION leaf + tree — the shared-core model for
 * contracts/PolicyVault.v0.7-payment-hd.sil (contract
 * `PolicyVaultRootedTokenHD`, tools/gen_v7_payment_hd.js), productionizing
 * the real-engine probe (contracts/experiments/HDProbe.sil) whose DESIGN is
 * frozen by docs/postlaunch/hierarchical-delegation-design-freeze.md and
 * docs/postlaunch/hierarchical-delegation-design.md.
 *
 * CORE INVARIANT (owner, verbatim): AUTHORITY MAY NEVER INCREASE DESCENDING.
 * A child or grandchild must never gain a higher per-spend cap, a higher
 * periodic budget, a broader destination set, a longer expiry, a broader
 * fee/carry allowance, or an ability to escape revocation.
 *
 * NEW HD leaf domain tag 0x50564801 over a 173-byte preimage
 * (0x50564801 || body(160) || num8(level) || 0x00), disjoint from the v0.5 /
 * v0.7-payment flat token-agent leaf (0x50563501 / 125 bytes) and from
 * every other PolicyVault leaf length, in both directions.
 *
 * LEAF CARRIAGE (measured, design record §6.2): the leaf is ONE canonical
 * 160-byte BODY, never 11 separate fields — MAX_STACK_SIZE (244) is the
 * binding constraint on MAX_LEVEL, and the field-argument layout does not
 * fit at level 3. `level` is NEVER part of the body or a caller argument at
 * spend time; each covenant entrypoint substitutes the level CONSTANT of
 * the position it is checking, so a leaf committed at level k fails
 * membership anywhere else — this module mirrors that by taking `level`
 * as an explicit parameter to every hashing function, never inferring it.
 *
 * Body layout (little-endian num8 for every integer field):
 *   [  0,  32) pk
 *   [ 32,  40) maxPerSpend        [ 40,  48) periodBudget
 *   [ 48,  56) periodLengthDaa    [ 56,  64) periodStartDaa
 *   [ 64,  72) periodSpent        [ 72,  80) maxFeePerTx
 *   [ 80,  88) maxCarryKas        [ 88,  96) expiryDaa
 *   [ 96, 128) recipientRoot      [128, 160) childRoot
 *
 * `expiryDaa` is a CONSISTENCY field only (child <= parent down the chain).
 * Kaspa `lockTime` is a LOWER bound (`OpCheckLockTimeVerify`), so this is
 * NEVER a consensus-enforced expiry — the real retirement mechanisms are
 * REVOCATION (a zeroed/re-policied `childRoot` fails membership at every
 * descendant) and the periodic budget. Every caller of this module that
 * surfaces `expiryDaa` MUST say so; see `EXPIRY_IS_NOT_CONSENSUS_ENFORCED`.
 *
 * `effectiveAuthority(chain)` is a PURE, READ-ONLY function: it computes
 * the bounds a spend through the given ancestor chain would need to satisfy
 * on the real engine, for UI/manifest display and SDK pre-flight refusal.
 * IT IS NEVER THE SECURITY BOUNDARY — the covenant re-derives and enforces
 * every one of these bounds independently at spend time from the proven
 * leaves, never trusting this module's (or any off-chain) computation.
 *
 * Status: IMPLEMENTED + UNIT-TESTED (core/model/test/hd-leaf-v7.test.js).
 * NOT covenant-byte-frozen, NOT production, NOT authorized for mainnet use
 * (docs/postlaunch/hierarchical-delegation-design-freeze.md §5 note on this
 * wave's scope).
 */

const crypto = require("crypto");
const { parseSompi } = require("./amounts");
const { normalizeHex, normalizeXOnlyPubkey } = require("./vault-state");
const { parseAtomicAmount } = require("./token-amounts");
const { verifyRecipientProof } = require("./recipient-merkle-v3");

const HD_LEAF_DOMAIN = Uint8Array.of(0x50, 0x56, 0x48, 0x01);
const HD_LEAF_BODY_LEN = 160;
const HD_LEAF_PREIMAGE_LEN = 173; // domain(4) + body(160) + num8(level)(8) + trailing(1)
const MAX_LEVEL = 3; // MEASURED bound (design freeze §2): level-3 spend peaks at 208/244 combined
// stack items (36 headroom); a level-4 spend extrapolates to 254 — OVER. Never a config flag.
const MAX_AGENT_DEPTH = 12; // level-1 forest under agentRoot (v0.4 mechanism)
const MAX_CHILD_DEPTH = 8; // every childRoot subtree (256 children per node)
const ZERO_ROOT_HEX = "00".repeat(32);

const EXPIRY_IS_NOT_CONSENSUS_ENFORCED =
  "expiryDaa is enforced by PolicyVault's core (consistency: child <= parent) and by revocation / periodic-budget decay, NOT by Kaspa consensus. Kaspa lockTime is a LOWER bound only; nothing makes a transaction invalid once a DAA score has passed.";

function fail(message, code) {
  const error = new Error(`hd-leaf-v7: ${message}`);
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
function num8(value) {
  if (typeof value !== "bigint" || value < 0n || value > 0x7fffffffffffffffn) {
    fail("num8 requires a BigInt in 0..2^63-1");
  }
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, value, true);
  return out;
}
function bin2num(bytes) {
  if (bytes.length !== 8) fail("bin2num requires exactly 8 bytes");
  return new DataView(bytes.buffer, bytes.byteOffset, 8).getBigUint64(0, true);
}
function parseDaa(value, field, { positive = false } = {}) {
  const n = parseSompi(value, field); // integer domain check (0..MAX_SOMPI is ample for DAA scores)
  if (positive && n <= 0n) fail(`${field} must be > 0`);
  return n;
}
function parseLevel(level, field = "level") {
  const n = typeof level === "bigint" ? Number(level) : level;
  if (!Number.isInteger(n) || n < 1 || n > MAX_LEVEL) {
    fail(`${field} must be an integer in [1, ${MAX_LEVEL}] — MAX_LEVEL is a MEASURED stack bound, never a configuration choice`, "LEVEL_OUT_OF_RANGE");
  }
  return n;
}

const HD_LEAF_FIELDS = Object.freeze([
  "pk",
  "maxPerSpend",
  "periodBudget",
  "periodLengthDaa",
  "periodStartDaa",
  "periodSpent",
  "maxFeePerTx",
  "maxCarryKas",
  "expiryDaa",
  "recipientRoot",
  "childRoot"
]);

/*
 * Normalize one HD leaf. Strict fail-closed validation; every quantity
 * BigInt. `childRoot` all-zero means "no children"; `periodLengthDaa` must
 * be > 0 (D2-style hardening, mirroring v0.7-payment's own agent path — see
 * tools/gen_v7_payment_hd.js header for why this is NOT re-added inside the
 * in-covenant HD accounting, and why that is still safe).
 */
function normalizeHdLeaf(input) {
  if (!input || typeof input !== "object") fail("HD leaf object is required");
  for (const key of Object.keys(input)) {
    if (!HD_LEAF_FIELDS.includes(key)) fail(`unknown HD leaf field ${JSON.stringify(key)} — closed layout, failing closed`);
  }
  const periodLengthDaa = parseDaa(input.periodLengthDaa, "leaf.periodLengthDaa", { positive: true });
  return Object.freeze({
    pk: normalizeXOnlyPubkey(input.pk, "leaf.pk"),
    maxPerSpend: parseAtomicAmount(input.maxPerSpend, "leaf.maxPerSpend"),
    periodBudget: parseAtomicAmount(input.periodBudget, "leaf.periodBudget"),
    periodLengthDaa,
    periodStartDaa: parseDaa(input.periodStartDaa, "leaf.periodStartDaa"),
    periodSpent: parseAtomicAmount(input.periodSpent, "leaf.periodSpent"),
    maxFeePerTx: parseSompi(input.maxFeePerTx, "leaf.maxFeePerTx"),
    maxCarryKas: parseSompi(input.maxCarryKas, "leaf.maxCarryKas"),
    expiryDaa: parseDaa(input.expiryDaa, "leaf.expiryDaa"),
    recipientRoot: normalizeHex(input.recipientRoot, 32, "leaf.recipientRoot"),
    childRoot: normalizeHex(input.childRoot, 32, "leaf.childRoot")
  });
}

/* The canonical 160-byte body — the SAME bytes at every level; `level` is
 * carried nowhere inside it (design record §6.10 item 2). */
function encodeHdLeafBody(leafInput) {
  const l = normalizeHdLeaf(leafInput);
  const body = concatBytes([
    hexToBytes(l.pk),
    num8(l.maxPerSpend),
    num8(l.periodBudget),
    num8(l.periodLengthDaa),
    num8(l.periodStartDaa),
    num8(l.periodSpent),
    num8(l.maxFeePerTx),
    num8(l.maxCarryKas),
    num8(l.expiryDaa),
    hexToBytes(l.recipientRoot),
    hexToBytes(l.childRoot)
  ]);
  if (body.length !== HD_LEAF_BODY_LEN) fail(`internal: HD leaf body is ${body.length} bytes, not ${HD_LEAF_BODY_LEN}`);
  return body;
}
function encodeHdLeafBodyHex(leafInput) {
  return bytesToHex(encodeHdLeafBody(leafInput));
}

/* The inverse of encodeHdLeafBody — used to read a leaf back out of a
 * revealed sigscript argument or a stored manifest field. */
function decodeHdLeafBody(bodyBytesOrHex) {
  const body = typeof bodyBytesOrHex === "string" ? hexToBytes(bodyBytesOrHex) : bodyBytesOrHex;
  if (!(body instanceof Uint8Array) || body.length !== HD_LEAF_BODY_LEN) {
    fail(`HD leaf body must be exactly ${HD_LEAF_BODY_LEN} bytes`, "MALFORMED_BODY");
  }
  const leaf = {
    pk: bytesToHex(body.subarray(0, 32)),
    maxPerSpend: bin2num(body.subarray(32, 40)),
    periodBudget: bin2num(body.subarray(40, 48)),
    periodLengthDaa: bin2num(body.subarray(48, 56)),
    periodStartDaa: bin2num(body.subarray(56, 64)),
    periodSpent: bin2num(body.subarray(64, 72)),
    maxFeePerTx: bin2num(body.subarray(72, 80)),
    maxCarryKas: bin2num(body.subarray(80, 88)),
    expiryDaa: bin2num(body.subarray(88, 96)),
    recipientRoot: bytesToHex(body.subarray(96, 128)),
    childRoot: bytesToHex(body.subarray(128, 160))
  };
  return normalizeHdLeaf(leaf);
}

/* leaf hash = sha256(0x50564801 || body(160) || num8(level) || 0x00) — the
 * EXACT bytes contracts/PolicyVault.v0.7-payment-hd.sil's `hdLeafHash`
 * computes. `level` is REQUIRED and is never inferred from the leaf. */
function hdLeafPreimage(leafInput, level) {
  const lvl = parseLevel(level);
  const body = encodeHdLeafBody(leafInput);
  const preimage = concatBytes([HD_LEAF_DOMAIN, body, num8(BigInt(lvl)), Uint8Array.of(0x00)]);
  if (preimage.length !== HD_LEAF_PREIMAGE_LEN) fail(`internal: HD leaf preimage is ${preimage.length} bytes, not ${HD_LEAF_PREIMAGE_LEN}`);
  return preimage;
}
function hdLeafHash(leafInput, level) {
  return sha256(hdLeafPreimage(leafInput, level));
}
function hdLeafHashHex(leafInput, level) {
  return bytesToHex(hdLeafHash(leafInput, level));
}

/* ---- Merkle fold: byte-identical to the covenant's computeMerkleRoot ---- */

function normalizeSiblings(siblingsHex, maxDepth) {
  if (typeof siblingsHex !== "string" || !/^[0-9a-f]*$/.test(siblingsHex) || siblingsHex.length % 2 !== 0) {
    fail("siblingsHex must be lowercase hex");
  }
  const siblings = hexToBytes(siblingsHex);
  if (siblings.length % 32 !== 0) fail("siblings length must be a multiple of 32 bytes");
  if (siblings.length > 32 * maxDepth) fail(`proof depth ${siblings.length / 32} exceeds the covenant maximum ${maxDepth}`);
  return siblings;
}
function normalizePathBits(pathBits, maxDepth) {
  const bits = typeof pathBits === "bigint" ? pathBits : BigInt(pathBits);
  if (bits < 0n || bits >= 1n << BigInt(maxDepth)) fail(`pathBits out of range for depth <= ${maxDepth}`);
  return bits;
}

/* leafHashBytes -> root, folding over siblings/pathBits (co-path order
 * identical to the covenant: bit 1 => sibling-then-node, bit 0 =>
 * node-then-sibling). Returns null when pathBits is not fully consumed
 * (mirrors the covenant's `require(bits == 0)` at the end of the loop). */
function foldHdLeaf(leafHashBytes, siblingsHex, pathBits, maxDepth) {
  if (!(leafHashBytes instanceof Uint8Array) || leafHashBytes.length !== 32) fail("leaf hash must be a 32-byte Uint8Array");
  const siblings = normalizeSiblings(siblingsHex, maxDepth);
  let bits = normalizePathBits(pathBits, maxDepth);
  const depth = siblings.length / 32;
  let node = leafHashBytes;
  for (let level = 0; level < depth; level++) {
    const sib = siblings.subarray(level * 32, level * 32 + 32);
    node = bits % 2n === 1n ? sha256(concatBytes([sib, node])) : sha256(concatBytes([node, sib]));
    bits /= 2n;
  }
  if (bits !== 0n) return null;
  return node;
}
function foldHdLeafHex(leafHashBytes, siblingsHex, pathBits, maxDepth) {
  const r = foldHdLeaf(leafHashBytes, siblingsHex, pathBits, maxDepth);
  return r === null ? null : bytesToHex(r);
}

/* ---- tree fold with nested child roots ---- */

/*
 * Build a canonical Merkle tree from a flat array of 32-byte leaf hashes
 * (sorted callers' responsibility — this module does not sort, since HD
 * leaves at different levels compare on different key domains; ordering
 * policy lives in the SDK builder). UNSPENDABLE padding to the next power
 * of two, depth-bounded.
 */
function buildMerkleLevels(leafHashes, maxDepth, paddingLeaf) {
  if (!Array.isArray(leafHashes) || leafHashes.length === 0) fail("at least one leaf hash is required");
  let level = leafHashes.map((h) => (typeof h === "string" ? hexToBytes(h) : h));
  for (const h of level) {
    if (!(h instanceof Uint8Array) || h.length !== 32) fail("every leaf hash must be 32 bytes");
  }
  while (level.length & (level.length - 1)) level.push(paddingLeaf);
  const levels = [level];
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) next.push(sha256(concatBytes([level[i], level[i + 1]])));
    levels.push(next);
    level = next;
  }
  const depth = levels.length - 1;
  if (depth > maxDepth) fail(`tree depth ${depth} exceeds the maximum ${maxDepth}`);
  return levels;
}

const PADDING_LEAF = sha256(Uint8Array.of(0x50, 0x56, 0x48, 0x00)); // disjoint padding domain

/*
 * A tree NODE is { leaf, kids: [node, ...] }. `leaf.childRoot` is IGNORED
 * on input and always RECOMPUTED from `kids` so a caller can never commit a
 * tree whose childRoot lies about its own children — mirrors
 * `kids_root`/`resolved` in the VM test harness.
 */
function resolvedLeaf(node, level) {
  const kidsRoot = node.kids.length === 0 ? ZERO_ROOT_HEX : childRootOf(node.kids, level + 1);
  return { ...normalizeHdLeaf(node.leaf), childRoot: kidsRoot };
}
function childRootOf(kids, level) {
  parseLevel(level);
  const hashes = kids.map((k) => hdLeafHash(resolvedLeaf(k, level), level));
  const levels = buildMerkleLevels(hashes, MAX_CHILD_DEPTH, PADDING_LEAF);
  return bytesToHex(levels[levels.length - 1][0]);
}

/* The committed forest root (the vault's `agentRoot`) over the level-1
 * agent tree (depth <= 12). */
function forestRoot(level1Nodes) {
  const hashes = level1Nodes.map((n) => hdLeafHash(resolvedLeaf(n, 1), 1));
  const levels = buildMerkleLevels(hashes, MAX_AGENT_DEPTH, PADDING_LEAF);
  return bytesToHex(levels[levels.length - 1][0]);
}

/*
 * Resolve the ancestor CHAIN along `path` (array of child indices, one per
 * level, path.length in [1, MAX_LEVEL]), returning per level
 * { leaf, siblingsHex, pathBits, level } — exactly what a spend or
 * delegation entrypoint needs to prove membership at that level.
 */
function chainProofs(level1Nodes, path) {
  if (!Array.isArray(path) || path.length < 1 || path.length > MAX_LEVEL) {
    fail(`path must have length in [1, ${MAX_LEVEL}]`, "LEVEL_OUT_OF_RANGE");
  }
  const out = [];
  let nodes = level1Nodes;
  let level = 1;
  for (const step of path) {
    if (!Number.isInteger(step) || step < 0 || step >= nodes.length) fail(`path step ${step} out of range at level ${level}`);
    const hashes = nodes.map((n) => hdLeafHash(resolvedLeaf(n, level), level));
    const maxDepth = level === 1 ? MAX_AGENT_DEPTH : MAX_CHILD_DEPTH;
    const levels = buildMerkleLevels(hashes, maxDepth, PADDING_LEAF);
    const { siblingsHex, pathBits } = proofFromLevels(levels, step);
    out.push({ leaf: resolvedLeaf(nodes[step], level), siblingsHex, pathBits, level });
    nodes = nodes[step].kids;
    level += 1;
  }
  return out;
}
function proofFromLevels(levels, index) {
  let idx = index;
  const siblings = [];
  let pathBits = 0n;
  for (let levelIdx = 0; levelIdx < levels.length - 1; levelIdx++) {
    const level = levels[levelIdx];
    const siblingIdx = idx % 2 === 0 ? idx + 1 : idx - 1;
    siblings.push(level[siblingIdx]);
    if (idx % 2 === 1) pathBits |= 1n << BigInt(levelIdx);
    idx = Math.floor(idx / 2);
  }
  return { siblingsHex: bytesToHex(concatBytes(siblings)), pathBits };
}

/* ---- effective authority (PURE, READ-ONLY — never the security boundary) ---- */

/*
 * Given the FULL ancestor chain [level-1 leaf, ..., level-k leaf] (as
 * returned by chainProofs, or any array of normalized HD leaves in
 * ancestor order), compute the bounds a spend through this chain must
 * satisfy per design record §1.3: the per-request cap is the MINIMUM over
 * every ancestor; fee and carry likewise; expiry is the MINIMUM (and MUST
 * already be monotonically non-increasing down the chain — see
 * `verifyExpiryMonotone`); the recipient must be a member of EVERY level's
 * OWN recipientRoot (reported per level, never collapsed into one root,
 * because recipientRoot is a commitment, not a set the SDK can intersect
 * off-chain); each level keeps its OWN period-budget clock (siblings never
 * share a counter except through the shared PARENT counter itself).
 *
 * THIS FUNCTION NEVER ENFORCES ANYTHING. It is read-only reporting for
 * manifests, UI and SDK pre-flight refusal; the covenant independently
 * re-derives and enforces every one of these bounds at spend time from the
 * PROVEN leaves, and is the only rule that matters for funds safety.
 */
function effectiveAuthority(chainInput) {
  if (!Array.isArray(chainInput) || chainInput.length < 1 || chainInput.length > MAX_LEVEL) {
    fail(`chain must have length in [1, ${MAX_LEVEL}]`, "LEVEL_OUT_OF_RANGE");
  }
  const chain = chainInput.map((entry) => normalizeHdLeaf(entry.leaf ?? entry));
  let maxPerSpend = chain[0].maxPerSpend;
  let maxFeePerTx = chain[0].maxFeePerTx;
  let maxCarryKas = chain[0].maxCarryKas;
  let expiryDaa = chain[0].expiryDaa;
  for (let i = 1; i < chain.length; i++) {
    if (chain[i].maxPerSpend < maxPerSpend) maxPerSpend = chain[i].maxPerSpend;
    if (chain[i].maxFeePerTx < maxFeePerTx) maxFeePerTx = chain[i].maxFeePerTx;
    if (chain[i].maxCarryKas < maxCarryKas) maxCarryKas = chain[i].maxCarryKas;
    if (chain[i].expiryDaa < expiryDaa) expiryDaa = chain[i].expiryDaa;
  }
  return Object.freeze({
    level: chain.length,
    maxPerSpend,
    maxFeePerTx,
    maxCarryKas,
    expiryDaa,
    expiryIsNotConsensusEnforced: EXPIRY_IS_NOT_CONSENSUS_ENFORCED,
    perLevelBudgets: Object.freeze(
      chain.map((l, i) => Object.freeze({ level: i + 1, periodBudget: l.periodBudget, periodSpent: l.periodSpent, periodLengthDaa: l.periodLengthDaa, periodStartDaa: l.periodStartDaa, remaining: l.periodBudget - l.periodSpent }))
    ),
    recipientRootsByLevel: Object.freeze(chain.map((l, i) => Object.freeze({ level: i + 1, recipientRoot: l.recipientRoot })))
  });
}

/*
 * SDK/UI pre-flight guard (NEVER a substitute for the covenant): refuse to
 * even BUILD a delegation whose proposed child leaf is not authority-
 * REDUCING relative to its immediate parent. The covenant enforces the
 * REAL bound (the full-chain intersection) at every spend regardless of
 * what this check allows through — a parent that lies to this function
 * gains nothing on-chain (design record §1.3) — but failing closed here
 * saves a doomed transaction and gives an honest error before any
 * signature is spent.
 */
function verifyChildNeverExceedsParent(parentLeafInput, childLeafInput) {
  const parent = normalizeHdLeaf(parentLeafInput);
  const child = normalizeHdLeaf(childLeafInput);
  const violations = [];
  if (child.maxPerSpend > parent.maxPerSpend) violations.push("maxPerSpend");
  if (child.periodBudget > parent.periodBudget) violations.push("periodBudget");
  if (child.maxFeePerTx > parent.maxFeePerTx) violations.push("maxFeePerTx");
  if (child.maxCarryKas > parent.maxCarryKas) violations.push("maxCarryKas");
  if (child.expiryDaa > parent.expiryDaa) violations.push("expiryDaa");
  return Object.freeze({ ok: violations.length === 0, violations: Object.freeze(violations) });
}

/* Expiry consistency across a FULL chain (design record §1.4): every
 * descendant's expiryDaa must be <= its immediate parent's. */
function verifyExpiryMonotone(chainInput) {
  const chain = chainInput.map((entry) => normalizeHdLeaf(entry.leaf ?? entry));
  for (let i = 1; i < chain.length; i++) {
    if (chain[i].expiryDaa > chain[i - 1].expiryDaa) {
      return Object.freeze({ ok: false, level: i + 1, message: `level ${i + 1} expiryDaa exceeds its parent's — ${EXPIRY_IS_NOT_CONSENSUS_ENFORCED}` });
    }
  }
  return Object.freeze({ ok: true });
}

/* Level/position consistency: a chain entry's OWN `level` marker (when the
 * caller tracks one alongside the leaf, e.g. from chainProofs output) must
 * equal its 1-based position — mirrors the covenant substituting the level
 * CONSTANT of the position it checks. */
function verifyChainPositions(chainWithLevels) {
  for (let i = 0; i < chainWithLevels.length; i++) {
    const expected = i + 1;
    if (chainWithLevels[i].level !== expected) {
      return Object.freeze({ ok: false, index: i, expectedLevel: expected, gotLevel: chainWithLevels[i].level });
    }
  }
  return Object.freeze({ ok: true });
}

/*
 * SDK/UI pre-flight guard: a delegateSetChildRoot1/2 op is signed by the
 * parent and MUST change ONLY that parent's own `childRoot` — every other
 * field (including every KAS/token cap, both period fields, expiryDaa and
 * recipientRoot) is pinned equal by the covenant's byte-level splice
 * (`parentLeaf.slice(0,128) + newChildRoot`). This mirrors that rule so a
 * malformed delegation request is refused before any signature is spent.
 * NEVER a substitute for the covenant — a caller who bypasses the SDK and
 * submits a forged op directly is still bound by the in-covenant splice.
 */
function verifyDelegationOnlyChangesChildRoot(currentLeafInput, proposedLeafInput) {
  const current = normalizeHdLeaf(currentLeafInput);
  const proposed = normalizeHdLeaf(proposedLeafInput);
  const violations = [];
  for (const field of HD_LEAF_FIELDS) {
    if (field === "childRoot") continue;
    if (String(current[field]) !== String(proposed[field])) violations.push(field);
  }
  const childRootChanged = current.childRoot !== proposed.childRoot;
  return Object.freeze({ ok: violations.length === 0, violations: Object.freeze(violations), childRootChanged });
}

/*
 * SDK/UI pre-flight guard: the destination must be a member of EVERY
 * level's OWN recipientRoot (design record §1.3 item 3) — never only the
 * spending leaf's. `proofsByLevel[i]` is `{ siblingsHex, pathBits }` for
 * `chain[i]`. Returns the first level that refuses, or ok:true. NEVER a
 * substitute for the covenant's own per-level requireRecipientMember call.
 */
function verifyRecipientAllowedByEveryLevel(chainInput, recipientXOnlyPk, proofsByLevel) {
  const chain = chainInput.map((entry) => normalizeHdLeaf(entry.leaf ?? entry));
  if (!Array.isArray(proofsByLevel) || proofsByLevel.length !== chain.length) {
    fail("proofsByLevel must carry exactly one entry per chain level");
  }
  for (let i = 0; i < chain.length; i++) {
    const ok = verifyRecipientProof({ root: chain[i].recipientRoot, recipient: recipientXOnlyPk, siblingsHex: proofsByLevel[i].siblingsHex, pathBits: proofsByLevel[i].pathBits });
    if (!ok) return Object.freeze({ ok: false, level: i + 1 });
  }
  return Object.freeze({ ok: true });
}

/*
 * SDK/UI pre-flight guard: a proposed spend amount, fee and carry must sit
 * within the chain's effectiveAuthority (the minimum over every ancestor).
 * Never the security boundary — the covenant independently re-derives and
 * enforces the same intersection from the proven leaves.
 */
function verifySpendWithinEffectiveAuthority(chainInput, { amount, feeSompi, carrySompi, periodsElapsedByLevel }) {
  const eff = effectiveAuthority(chainInput);
  const violations = [];
  if (amount !== undefined && parseAtomicAmount(amount, "amount") > eff.maxPerSpend) violations.push("maxPerSpend");
  if (feeSompi !== undefined && parseSompi(feeSompi, "feeSompi") > eff.maxFeePerTx) violations.push("maxFeePerTx");
  if (carrySompi !== undefined && parseSompi(carrySompi, "carrySompi") > eff.maxCarryKas) violations.push("maxCarryKas");
  /* EVERY ancestor's PERIOD BUDGET participates (design record §1.3 item 2):
   * each level's counter advances by the same spend after its own rollover,
   * so an exhausted ancestor refuses a descendant even when the leaf's own
   * cap/budget would allow it. Found live (2026-09-03): a level-3 spend of 25
   * under a level-2 leaf whose 150 budget was already spent was signed by
   * the builder and refused by consensus — this check makes the SDK refuse
   * BEFORE signing, exactly as the covenant does. */
  if (amount !== undefined) {
    const chain = Array.isArray(chainInput) ? chainInput : [];
    const spend = parseAtomicAmount(amount, "amount");
    for (let i = 0; i < chain.length; i++) {
      const leaf = normalizeHdLeaf(chain[i].leaf ?? chain[i]);
      const pe = periodsElapsedByLevel ? (typeof periodsElapsedByLevel[i] === "bigint" ? periodsElapsedByLevel[i] : BigInt(periodsElapsedByLevel[i] ?? 0)) : 0n;
      const adv = advanceHdLeafPeriod(leaf, spend, pe);
      if (adv.periodSpent > leaf.periodBudget) violations.push(`periodBudget@level${i + 1}`);
    }
  }
  return Object.freeze({ ok: violations.length === 0, violations: Object.freeze(violations), effectiveAuthority: eff });
}

/*
 * ---- state advance + nested refold (Wave 2 Track D, gate I2) ----
 *
 * These reproduce, byte-for-byte, the covenant's own accounting for a
 * SPEND (`advance`/`nested_refold` in tests/vm/tests/v7_hd_production.rs)
 * and a DELEGATION (`dsc_refold`). They are the ONLY place the SDK computes
 * the new `agentRoot` a spend or delegation must pin — the covenant
 * independently re-derives the identical fold in-VM from the proven leaves
 * and is the only rule that matters for funds safety; a builder that gets
 * this wrong produces a transaction the real engine refuses, never one that
 * silently succeeds with the wrong bytes.
 */

/*
 * One leaf's period-counter advance for a spend of `spendAmount` after
 * `periodsElapsed` full periods have passed since `periodStartDaa`:
 *   periodsElapsed >= 1 (rollover): periodStartDaa += periodsElapsed *
 *     periodLengthDaa; periodSpent resets to exactly `spendAmount`.
 *   periodsElapsed == 0 (same period): periodStartDaa unchanged; periodSpent
 *     accumulates += spendAmount.
 * Returns { periodStartDaa, periodSpent } (BigInt). Every OTHER leaf field
 * is left to the caller — this function only ever touches the two period
 * fields, mirroring the covenant's `advance`.
 */
function advanceHdLeafPeriod(leafInput, spendAmount, periodsElapsed) {
  const l = normalizeHdLeaf(leafInput);
  const spend = parseAtomicAmount(spendAmount, "spendAmount");
  const pe = typeof periodsElapsed === "bigint" ? periodsElapsed : BigInt(periodsElapsed);
  if (pe < 0n) fail("periodsElapsed must be >= 0");
  if (pe >= 1n) {
    return Object.freeze({ periodStartDaa: l.periodStartDaa + pe * l.periodLengthDaa, periodSpent: spend });
  }
  return Object.freeze({ periodStartDaa: l.periodStartDaa, periodSpent: l.periodSpent + spend });
}

/*
 * The new `agentRoot` (or, for a shallower composition, the new value that
 * carries into the NEXT fold up) after a spend through the full ancestor
 * `chain` (as returned by `chainProofs`, oldest ancestor first, deepest =
 * the spending leaf itself). `periodsElapsedByLevel[i]` pairs with
 * `chain[i]`. Every ancestor's OWN period counters advance (design record
 * §1.3: a child can never outrun a parent budget because the parent counter
 * also advances; siblings share the parent's counter through this same
 * fold). The deepest leaf's OWN `childRoot` is carried through UNCHANGED (a
 * spend never touches children). Returns lowercase hex.
 */
function nestedRefoldAfterSpend(chainInput, spendAmount, periodsElapsedByLevel) {
  if (!Array.isArray(chainInput) || chainInput.length < 1 || chainInput.length > MAX_LEVEL) {
    fail(`chain must have length in [1, ${MAX_LEVEL}]`, "LEVEL_OUT_OF_RANGE");
  }
  const k = chainInput.length;
  if (!Array.isArray(periodsElapsedByLevel) || periodsElapsedByLevel.length !== k) {
    fail("periodsElapsedByLevel must carry exactly one entry per chain level");
  }
  const deepest = normalizeHdLeaf(chainInput[k - 1].leaf ?? chainInput[k - 1]);
  let carried = hexToBytes(deepest.childRoot);
  for (let i = k - 1; i >= 0; i--) {
    const entry = chainInput[i];
    const l = normalizeHdLeaf(entry.leaf ?? entry);
    const level = entry.level ?? i + 1;
    if (level !== i + 1) fail(`chain[${i}].level ${level} does not match its chain position ${i + 1}`, "LEVEL_OUT_OF_RANGE");
    const { periodStartDaa, periodSpent } = advanceHdLeafPeriod(l, spendAmount, periodsElapsedByLevel[i]);
    const nl = { ...l, periodStartDaa, periodSpent, childRoot: bytesToHex(carried) };
    const maxDepth = level === 1 ? MAX_AGENT_DEPTH : MAX_CHILD_DEPTH;
    const folded = foldHdLeaf(hdLeafHash(nl, level), entry.siblingsHex, entry.pathBits, maxDepth);
    if (folded === null) fail(`internal: the fold at level ${level} did not fully consume pathBits`);
    carried = folded;
  }
  return bytesToHex(carried);
}

/*
 * The new `agentRoot` after a `delegateSetChildRoot1/2` op: ONLY the
 * delegating parent's `childRoot` moves to `newChildRootHex` (design record
 * §1.2: one parent signature can only NAME a key, never create authority —
 * every OTHER field of every ancestor, including the parent's own policy
 * fields, is folded through UNCHANGED). `chain` is the ancestor stack
 * INCLUDING the delegating parent as its deepest (last) entry.
 */
function nestedRefoldAfterDelegation(chainInput, newChildRootHex) {
  if (!Array.isArray(chainInput) || chainInput.length < 1 || chainInput.length > MAX_LEVEL) {
    fail(`chain must have length in [1, ${MAX_LEVEL}]`, "LEVEL_OUT_OF_RANGE");
  }
  const newChildRoot = normalizeHex(newChildRootHex, 32, "newChildRoot");
  const k = chainInput.length;
  let carried = hexToBytes(newChildRoot);
  for (let i = k - 1; i >= 0; i--) {
    const entry = chainInput[i];
    const l = normalizeHdLeaf(entry.leaf ?? entry);
    const level = entry.level ?? i + 1;
    if (level !== i + 1) fail(`chain[${i}].level ${level} does not match its chain position ${i + 1}`, "LEVEL_OUT_OF_RANGE");
    const nl = { ...l, childRoot: bytesToHex(carried) };
    const maxDepth = level === 1 ? MAX_AGENT_DEPTH : MAX_CHILD_DEPTH;
    const folded = foldHdLeaf(hdLeafHash(nl, level), entry.siblingsHex, entry.pathBits, maxDepth);
    if (folded === null) fail(`internal: the fold at level ${level} did not fully consume pathBits`);
    carried = folded;
  }
  return bytesToHex(carried);
}

function hdLeafToJson(leafInput) {
  const l = normalizeHdLeaf(leafInput);
  return {
    pk: l.pk,
    maxPerSpend: l.maxPerSpend.toString(),
    periodBudget: l.periodBudget.toString(),
    periodLengthDaa: l.periodLengthDaa.toString(),
    periodStartDaa: l.periodStartDaa.toString(),
    periodSpent: l.periodSpent.toString(),
    maxFeePerTx: l.maxFeePerTx.toString(),
    maxCarryKas: l.maxCarryKas.toString(),
    expiryDaa: l.expiryDaa.toString(),
    recipientRoot: l.recipientRoot,
    childRoot: l.childRoot,
    expiryIsNotConsensusEnforced: EXPIRY_IS_NOT_CONSENSUS_ENFORCED
  };
}

module.exports = {
  HD_LEAF_DOMAIN,
  HD_LEAF_BODY_LEN,
  HD_LEAF_PREIMAGE_LEN,
  MAX_LEVEL,
  MAX_AGENT_DEPTH,
  MAX_CHILD_DEPTH,
  ZERO_ROOT_HEX,
  EXPIRY_IS_NOT_CONSENSUS_ENFORCED,
  HD_LEAF_FIELDS,
  PADDING_LEAF,
  normalizeHdLeaf,
  encodeHdLeafBody,
  encodeHdLeafBodyHex,
  decodeHdLeafBody,
  hdLeafPreimage,
  hdLeafHash,
  hdLeafHashHex,
  foldHdLeaf,
  foldHdLeafHex,
  resolvedLeaf,
  childRootOf,
  forestRoot,
  chainProofs,
  effectiveAuthority,
  verifyChildNeverExceedsParent,
  verifyExpiryMonotone,
  verifyChainPositions,
  verifyDelegationOnlyChangesChildRoot,
  verifyRecipientAllowedByEveryLevel,
  verifySpendWithinEffectiveAuthority,
  advanceHdLeafPeriod,
  nestedRefoldAfterSpend,
  nestedRefoldAfterDelegation,
  hdLeafToJson
};
