"use strict";

/*
 * PolicyVault v0.3 canonical recipient Merkle tree / proof SDK.
 *
 * This is the ONE tree builder + proof generator + verifier for the v0.3
 * recipient allowlist (docs/v03-recipient-auth-design.md). The covenant is
 * the authority; this module must produce exactly the bytes the PRODUCTION
 * covenant accepts (proven by tests/vm/tests/v3_sdk_integration.rs, which
 * drives SDK-generated proofs through the real pv_call_encoder binary and
 * the production PolicyVault.v0.3.sil on the real TxScriptEngine).
 *
 * Canonical construction (all source-checked against the covenant):
 *   leaf  = SHA256(0x50 0x56 0x33 0x01 || recipient_xonly_pubkey)
 *           (36-byte preimage; the covenant ALWAYS recomputes the leaf
 *            from recipientPk, never accepts a preformed leaf)
 *   node  = SHA256(left || right)   (64-byte preimage — cannot collide
 *            with the 36-byte leaf preimage)
 *   depth <= 16 (siblings.length <= 512 and multiple of 32; pathBits in
 *            [0, 65536) and fully consumed after the walk)
 *
 * Determinism rules:
 *   - active recipient x-only keys are DE-DUPLICATED and sorted ascending
 *     (fixed-width lowercase hex sorts identically to byte order), so one
 *     recipient set has exactly one root;
 *   - non-power-of-two leaf counts are padded by DUPLICATING THE LAST NODE
 *     at each level (matching the VM test fixture semantics: padding
 *     happens at the leaf level up to the next power of two);
 *   - a single recipient is depth 0: empty siblings, pathBits 0, and
 *     root == leaf (VM-proven);
 *   - zero recipients is DISALLOWED (a vault that can pay nobody is a
 *     policy error; fail closed).
 *
 * Known benign property of duplicate-padding: where a node equals its own
 * sibling (a padded level), SHA256(node||sib) == SHA256(sib||node), so
 * that level's path bit is not significant — two encodings prove the SAME
 * recipient under the SAME root. Membership and exact output binding are
 * unaffected; this is proof-encoding malleability only, never an
 * authorization change.
 *
 * pathBits convention (exactly the covenant's): bit i (LSB-first) is 1
 * when the running node is the RIGHT child at level i, i.e. the sibling is
 * hashed on the LEFT: node = SHA256(sib || node). Bit 0 => sibling on the
 * right: node = SHA256(node || sib).
 *
 * All identities are 32-byte x-only pubkeys (lowercase hex). Wallet
 * addresses must be resolved through the shared address-identity boundary
 * (sdk/src/address-identity.js) BEFORE reaching this module — this module
 * never parses addresses.
 */

const crypto = require("crypto");
const { normalizeXOnlyPubkey } = require("./vault-state");

const LEAF_DOMAIN = Buffer.from([0x50, 0x56, 0x33, 0x01]);
const MAX_DEPTH = 16;
const MAX_RECIPIENTS = 1 << MAX_DEPTH; // 65,536

function fail(message) {
  throw new Error(`recipient-merkle-v3: ${message}`);
}

function sha256(buffer) {
  return crypto.createHash("sha256").update(buffer).digest();
}

/* Canonical leaf hash for one recipient x-only pubkey (hex in, Buffer out). */
function leafHash(recipientXOnlyHex) {
  const key = normalizeXOnlyPubkey(recipientXOnlyHex, "recipient");
  return sha256(Buffer.concat([LEAF_DOMAIN, Buffer.from(key, "hex")]));
}

/*
 * Build the canonical recipient tree.
 *
 * recipients: array of x-only pubkey hex strings (>= 1). Duplicates are
 * collapsed; the active set is sorted ascending. Returns a frozen object:
 *   { root, recipients, leafCount, depth, levels }
 * where `root` is 64-hex, `recipients` is the sorted de-duplicated key
 * list, `depth` is the proof depth every generated proof will have, and
 * `levels` holds the raw Buffer levels for proof generation.
 */
function buildRecipientTree(recipientsInput) {
  if (!Array.isArray(recipientsInput) || recipientsInput.length === 0) {
    fail("recipients must be a non-empty array — a vault with no recipients cannot spend");
  }
  const seen = new Set();
  const keys = [];
  recipientsInput.forEach((r, i) => {
    const key = normalizeXOnlyPubkey(r, `recipients[${i}]`);
    if (!seen.has(key)) {
      seen.add(key);
      keys.push(key);
    }
  });
  keys.sort();
  if (keys.length > MAX_RECIPIENTS) {
    fail(`recipient count ${keys.length} exceeds the maximum ${MAX_RECIPIENTS} (depth ${MAX_DEPTH})`);
  }

  /* Pad the LEAF level to the next power of two by duplicating the last
   * leaf, then hash pairwise up. This matches the production VM fixtures
   * (tests/vm: `while level.len().count_ones() != 1 { push(last) }` at the
   * leaf level). */
  let level = keys.map((k) => leafHash(k));
  while ((level.length & (level.length - 1)) !== 0) {
    level.push(level[level.length - 1]);
  }
  const levels = [level];
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) {
      next.push(sha256(Buffer.concat([level[i], level[i + 1]])));
    }
    levels.push(next);
    level = next;
  }

  const depth = levels.length - 1;
  if (depth > MAX_DEPTH) {
    fail(`tree depth ${depth} exceeds the covenant maximum ${MAX_DEPTH}`);
  }

  return Object.freeze({
    root: levels[levels.length - 1][0].toString("hex"),
    recipients: Object.freeze(keys.slice()),
    leafCount: levels[0].length,
    depth,
    levels
  });
}

/*
 * Generate the canonical membership proof for one recipient.
 * Returns { recipient, root, siblingsHex, pathBits, depth }:
 *   siblingsHex — depth * 32 bytes, leaf-to-root sibling order;
 *   pathBits    — BigInt; bit i set <=> node is the RIGHT child at level i.
 * Fails closed if the recipient is not in the tree.
 */
function generateRecipientProof(tree, recipientXOnlyHex) {
  const key = normalizeXOnlyPubkey(recipientXOnlyHex, "recipient");
  const index = tree.recipients.indexOf(key);
  if (index < 0) {
    fail(`recipient ${key} is not in this tree — refusing to fabricate a proof`);
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
    recipient: key,
    root: tree.root,
    siblingsHex: Buffer.concat(siblings).toString("hex"),
    pathBits,
    depth: tree.depth
  });
}

/*
 * SDK-side proof verification: the exact covenant walk. This is a local
 * pre-check ONLY — the production covenant remains the authority. Returns
 * true/false for well-formed inputs; throws on malformed inputs (odd hex,
 * bad widths, depth > 16, pathBits out of range) exactly where the
 * covenant would abort.
 */
function verifyRecipientProof({ root, recipient, siblingsHex, pathBits }) {
  const rootHex = normalizeXOnlyPubkey(root, "root"); // 32-byte hex, same shape rule
  const key = normalizeXOnlyPubkey(recipient, "recipient");
  if (typeof siblingsHex !== "string" || !/^[0-9a-f]*$/.test(siblingsHex) || siblingsHex.length % 2 !== 0) {
    fail("siblingsHex must be lowercase hex");
  }
  const siblings = Buffer.from(siblingsHex, "hex");
  if (siblings.length % 32 !== 0) {
    fail("siblings length must be a multiple of 32 bytes");
  }
  if (siblings.length > 32 * MAX_DEPTH) {
    fail(`proof depth ${siblings.length / 32} exceeds the covenant maximum ${MAX_DEPTH}`);
  }
  const depth = siblings.length / 32;
  let bits = typeof pathBits === "bigint" ? pathBits : BigInt(pathBits);
  if (bits < 0n || bits >= 65536n) {
    fail("pathBits out of range [0, 65536)");
  }
  let node = sha256(Buffer.concat([LEAF_DOMAIN, Buffer.from(key, "hex")]));
  for (let level = 0; level < depth; level++) {
    const sib = siblings.subarray(level * 32, level * 32 + 32);
    if (bits % 2n === 1n) {
      node = sha256(Buffer.concat([sib, node]));
    } else {
      node = sha256(Buffer.concat([node, sib]));
    }
    bits /= 2n;
  }
  if (bits !== 0n) {
    return false; // excess path bits — the covenant requires bits == 0
  }
  return node.toString("hex") === rootHex;
}

module.exports = {
  MAX_DEPTH,
  MAX_RECIPIENTS,
  LEAF_DOMAIN,
  leafHash,
  buildRecipientTree,
  generateRecipientProof,
  verifyRecipientProof
};
