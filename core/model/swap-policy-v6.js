"use strict";

/*
 * v0.6 SWAP VENUE PROFILE (policyvault-swap-venue-profile/1) + owner-approved
 * SWAP POLICY leaves and their Merkle tree (committed by a v0.6 controller's
 * swapRoot). docs/postlaunch/v0.6-architecture-freeze.md.
 *
 * BOUNDARY (frozen): the VENUE PROFILE holds only mechanically verifiable
 * protocol facts about ONE external pool covenant family/template (identity,
 * geometry, state layout, invariant + fee model, required shape, sighash
 * semantics, provenance). It never carries owner financial authority. The
 * SWAP POLICY LEAF is the owner's authority: it pins the profile (by hash),
 * the pool family + template + geometry + protocol-fee key (the VM-relevant
 * facts, explicit so the covenant needs no profile parser), the
 * protocol-fee cap, the SELL floor / BUY ceiling prices, the allowed
 * directions and the proceeds destination. PolicyVault never becomes a
 * DEX: the profile DESCRIBES a venue, it never blesses one.
 *
 * Leaf (229-byte preimage; distinct length):
 *   sha256(0x50563602 || profileHash || poolCovenantId || poolTemplateVmHash ||
 *          num8(poolPrefixLen) || num8(poolSuffixLen) || poolFeePk ||
 *          num8(maxProtocolFeeKas) || num8(sellFloorNum) || num8(sellFloorDen) ||
 *          num8(buyCeilNum) || num8(buyCeilDen) || num8(directionMask) ||
 *          destScheme || destIdentity)
 * Tree: sorted by leaf hash, UNSPENDABLE padding, depth <= 8 (the covenant
 * fold accepts <= 12; the core keeps the owner's tree small), single-leaf
 * co-path fold == the covenant computeMerkleRoot.
 *
 * Status: IMPLEMENTED + UNIT-TESTED (core/model/test/swap-policy-v6.test.js);
 * leaf bytes pinned against the SAME Rust leaf function the real-engine
 * v0.6 suite accepts (core/model/test/fixtures/swap-policy-leaf-v6.json).
 */

const crypto = require("crypto");
const { parseSompi } = require("./amounts");
const { normalizeHex, normalizeXOnlyPubkey } = require("./vault-state");
const { canonicalJsonStringify } = require("./canonical-json");

const SWAP_VENUE_PROFILE_VERSION_1 = "policyvault-swap-venue-profile/1";
const SWAP_POLICY_LEAF_DOMAIN_V6 = Uint8Array.of(0x50, 0x56, 0x36, 0x02);
const SWAP_POLICY_PADDING_DOMAIN_V6 = Uint8Array.of(0x50, 0x56, 0x36, 0x03);
const LEAF_PREIMAGE_LEN_SWAP = 229;
const MAX_SWAP_DEPTH = 8;
const MAX_SWAP_LEAVES = 1 << MAX_SWAP_DEPTH;
const COVENANT_MAX_DEPTH = 12;
/* rationals are bounded so covenant products (sompi × den, tokens × num) stay far inside i64 */
const MAX_PRICE_TERM = 1_000_000_000n;

const DIRECTION = Object.freeze({ SELL: 1n, BUY: 2n, BOTH: 3n });
const DEST_SCHEME = Object.freeze({ CONTROLLER: 0x02, P2PK: 0x00 });
const ZERO32_HEX = "00".repeat(32);

function fail(message, code) {
  const error = new Error(`swap-policy-v6: ${message}`);
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
  if (typeof value !== "bigint" || value < 0n || value > 0x7fffffffffffffffn) fail("num8 requires a BigInt in 0..2^63-1");
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, value, true);
  return out;
}
const PADDING_LEAF = sha256(SWAP_POLICY_PADDING_DOMAIN_V6);
const PADDING_LEAF_HEX = bytesToHex(PADDING_LEAF);

function requireKeys(obj, keys, where) {
  if (!obj || typeof obj !== "object" || Array.isArray(obj)) fail(`${where} must be an object`);
  const actual = Object.keys(obj).sort();
  const expected = [...keys].sort();
  if (JSON.stringify(actual) !== JSON.stringify(expected)) fail(`${where} must carry exactly [${expected.join(", ")}], got [${actual.join(", ")}] — closed schema, failing closed`);
}
function smallInt(value, field, max = 1_000_000) {
  if (typeof value === "string" && /^(0|[1-9][0-9]*)$/.test(value) && value.length <= 7) value = Number(value);
  if (typeof value === "bigint" && value >= 0n && value <= BigInt(max)) value = Number(value);
  if (!Number.isInteger(value) || value < 0 || value > max) fail(`${field} must be an integer 0..${max}`);
  return value;
}
function nonEmptyString(value, field, max = 200) {
  if (typeof value !== "string" || value.length === 0 || value.length > max) fail(`${field} must be a non-empty string (<= ${max} chars)`);
  return value;
}

/* ---------------- venue profile (protocol facts only) ---------------- */

const PROFILE_FIELDS = Object.freeze([
  "profileVersion",
  "profileId",
  "networkId",
  "poolCovenantId",
  "poolTemplateVmHashBlake2b256",
  "poolTemplateGeometry",
  "poolStateLayout",
  "tokenStandard",
  "tokenCovenantId",
  "invariantModel",
  "feeModel",
  "requiredShape",
  "signerSemantics",
  "provenance"
]);
const POOL_STATE_LAYOUT_1 = "constant-product-pool-state/1"; // kasReserve, tokenReserve, feeBps, nonce (LE64 each)
const INVARIANT_MODEL_1 = "constant-product-bps-fee/1";
const REQUIRED_SHAPE_1 = Object.freeze({ tokenFamilyInputs: 2, tokenFamilyOutputs: 2, poolInputs: 1, poolOutputs: 1, outputsTypeA: 5, outputsTypeB: 6 });

function normalizeSwapVenueProfile(input) {
  requireKeys(input, PROFILE_FIELDS, "venue profile");
  if (input.profileVersion !== SWAP_VENUE_PROFILE_VERSION_1) fail(`unknown profileVersion ${JSON.stringify(input.profileVersion)} — failing closed`, "UNKNOWN_VERSION");
  requireKeys(input.poolTemplateGeometry, ["prefixLen", "stateLen", "suffixLen"], "venue profile.poolTemplateGeometry");
  requireKeys(input.feeModel, ["poolFeeBps", "protocolFeeBps", "protocolFeePk"], "venue profile.feeModel");
  requireKeys(input.requiredShape, Object.keys(REQUIRED_SHAPE_1), "venue profile.requiredShape");
  requireKeys(input.signerSemantics, ["sighash", "postSignIdentityVerification", "poolOutpointBinding"], "venue profile.signerSemantics");
  requireKeys(input.provenance, ["sourceRelPath", "sourceSha256", "reference"], "venue profile.provenance");
  if (input.poolStateLayout !== POOL_STATE_LAYOUT_1) fail(`unsupported poolStateLayout ${JSON.stringify(input.poolStateLayout)} — failing closed`);
  if (input.invariantModel !== INVARIANT_MODEL_1) fail(`unsupported invariantModel ${JSON.stringify(input.invariantModel)} — failing closed`);
  if (input.tokenStandard !== "kcc20-state/1") fail(`unsupported tokenStandard ${JSON.stringify(input.tokenStandard)} — failing closed`);
  for (const k of Object.keys(REQUIRED_SHAPE_1)) {
    if (input.requiredShape[k] !== REQUIRED_SHAPE_1[k]) fail(`requiredShape.${k} must be ${REQUIRED_SHAPE_1[k]} for ${INVARIANT_MODEL_1}`);
  }
  if (input.signerSemantics.sighash !== "ALL") fail("signerSemantics.sighash must be ALL");
  if (input.signerSemantics.postSignIdentityVerification !== true || input.signerSemantics.poolOutpointBinding !== "exact") fail("signerSemantics must declare post-sign identity verification and exact pool-outpoint binding");
  const geometry = input.poolTemplateGeometry;
  const stateLen = smallInt(geometry.stateLen, "poolTemplateGeometry.stateLen");
  if (stateLen !== 36) fail(`poolTemplateGeometry.stateLen must be 36 for ${POOL_STATE_LAYOUT_1}`);
  const feeModel = input.feeModel;
  const poolFeeBps = parseSompi(feeModel.poolFeeBps, "feeModel.poolFeeBps");
  const protocolFeeBps = parseSompi(feeModel.protocolFeeBps, "feeModel.protocolFeeBps");
  if (poolFeeBps > 10_000n || protocolFeeBps > 10_000n) fail("fee bps out of range");
  return Object.freeze({
    profileVersion: SWAP_VENUE_PROFILE_VERSION_1,
    profileId: nonEmptyString(input.profileId, "profileId"),
    networkId: nonEmptyString(input.networkId, "networkId"),
    poolCovenantId: normalizeHex(input.poolCovenantId, 32, "poolCovenantId"),
    poolTemplateVmHashBlake2b256: normalizeHex(input.poolTemplateVmHashBlake2b256, 32, "poolTemplateVmHashBlake2b256"),
    poolTemplateGeometry: Object.freeze({ prefixLen: smallInt(geometry.prefixLen, "poolTemplateGeometry.prefixLen"), stateLen, suffixLen: smallInt(geometry.suffixLen, "poolTemplateGeometry.suffixLen") }),
    poolStateLayout: POOL_STATE_LAYOUT_1,
    tokenStandard: "kcc20-state/1",
    tokenCovenantId: normalizeHex(input.tokenCovenantId, 32, "tokenCovenantId"),
    invariantModel: INVARIANT_MODEL_1,
    feeModel: Object.freeze({ poolFeeBps, protocolFeeBps, protocolFeePk: normalizeXOnlyPubkey(feeModel.protocolFeePk, "feeModel.protocolFeePk") }),
    requiredShape: REQUIRED_SHAPE_1,
    signerSemantics: Object.freeze({ sighash: "ALL", postSignIdentityVerification: true, poolOutpointBinding: "exact" }),
    provenance: Object.freeze({
      sourceRelPath: nonEmptyString(input.provenance.sourceRelPath, "provenance.sourceRelPath"),
      sourceSha256: normalizeHex(input.provenance.sourceSha256, 32, "provenance.sourceSha256"),
      reference: nonEmptyString(input.provenance.reference, "provenance.reference", 500)
    })
  });
}
function swapVenueProfileToJson(profile) {
  const p = normalizeSwapVenueProfile(profile);
  return {
    ...p,
    poolTemplateGeometry: { ...p.poolTemplateGeometry },
    feeModel: { poolFeeBps: p.feeModel.poolFeeBps.toString(), protocolFeeBps: p.feeModel.protocolFeeBps.toString(), protocolFeePk: p.feeModel.protocolFeePk },
    requiredShape: { ...p.requiredShape },
    signerSemantics: { ...p.signerSemantics },
    provenance: { ...p.provenance }
  };
}
/* Application identity of a profile (never evaluated in-VM; pinned by the leaf). */
function computeSwapVenueProfileHash(profile) {
  const canonical = canonicalJsonStringify(swapVenueProfileToJson(profile));
  return crypto.createHash("sha256").update(`${SWAP_VENUE_PROFILE_VERSION_1}\n${canonical}`, "utf8").digest("hex");
}

/* ---------------- swap policy leaf (owner authority) ---------------- */

const SWAP_POLICY_FIELDS_V6 = Object.freeze([
  "profileHash",
  "poolCovenantId",
  "poolTemplateVmHash",
  "poolPrefixLen",
  "poolSuffixLen",
  "poolFeePk",
  "maxProtocolFeeKas",
  "sellFloorNum",
  "sellFloorDen",
  "buyCeilNum",
  "buyCeilDen",
  "directionMask",
  "destScheme",
  "destIdentity"
]);

function priceTerm(value, field, { positive }) {
  const n = parseSompi(value, field);
  if (positive && n <= 0n) fail(`${field} must be > 0`);
  if (n > MAX_PRICE_TERM) fail(`${field} exceeds ${MAX_PRICE_TERM} — bounded so covenant products stay inside i64`);
  return n;
}

function normalizeSwapPolicyV6(input) {
  if (!input || typeof input !== "object") fail("swap policy object is required");
  for (const key of Object.keys(input)) {
    if (!SWAP_POLICY_FIELDS_V6.includes(key)) fail(`unknown swap policy field ${JSON.stringify(key)} — closed layout, failing closed`);
  }
  const directionMask = parseSompi(input.directionMask, "swapPolicy.directionMask");
  if (directionMask < 1n || directionMask > 3n) fail("swapPolicy.directionMask must be 1 (SELL), 2 (BUY) or 3 (BOTH)");
  const destScheme = input.destScheme;
  if (destScheme !== DEST_SCHEME.CONTROLLER && destScheme !== DEST_SCHEME.P2PK) fail("swapPolicy.destScheme must be 0x02 (PolicyVault-controlled successor) or 0x00 (allowlisted P2PK) — no other destination schemes exist");
  const destIdentity = normalizeHex(input.destIdentity, 32, "swapPolicy.destIdentity");
  if (destScheme === DEST_SCHEME.CONTROLLER && destIdentity !== ZERO32_HEX) fail("swapPolicy.destIdentity must be all-zero for the controller destination (type A)");
  if (destScheme === DEST_SCHEME.P2PK) {
    normalizeXOnlyPubkey(destIdentity, "swapPolicy.destIdentity");
    if (directionMask !== DIRECTION.SELL) fail("a type-B (allowlisted P2PK) destination is SELL-only: tokens never leave to a third party on a buy — failing closed");
  }
  const p = Object.freeze({
    profileHash: normalizeHex(input.profileHash, 32, "swapPolicy.profileHash"),
    poolCovenantId: normalizeHex(input.poolCovenantId, 32, "swapPolicy.poolCovenantId"),
    poolTemplateVmHash: normalizeHex(input.poolTemplateVmHash, 32, "swapPolicy.poolTemplateVmHash"),
    poolPrefixLen: BigInt(smallInt(input.poolPrefixLen, "swapPolicy.poolPrefixLen")),
    poolSuffixLen: BigInt(smallInt(input.poolSuffixLen, "swapPolicy.poolSuffixLen")),
    poolFeePk: normalizeXOnlyPubkey(input.poolFeePk, "swapPolicy.poolFeePk"),
    maxProtocolFeeKas: parseSompi(input.maxProtocolFeeKas, "swapPolicy.maxProtocolFeeKas"),
    sellFloorNum: priceTerm(input.sellFloorNum, "swapPolicy.sellFloorNum", { positive: false }),
    sellFloorDen: priceTerm(input.sellFloorDen, "swapPolicy.sellFloorDen", { positive: true }),
    buyCeilNum: priceTerm(input.buyCeilNum, "swapPolicy.buyCeilNum", { positive: false }),
    buyCeilDen: priceTerm(input.buyCeilDen, "swapPolicy.buyCeilDen", { positive: true }),
    directionMask,
    destScheme,
    destIdentity
  });
  if (p.poolCovenantId === ZERO32_HEX) fail("swapPolicy.poolCovenantId must not be zero");
  if ((directionMask & DIRECTION.SELL) !== 0n && p.sellFloorNum === 0n) fail("a SELL-enabled leaf must set a positive floor price (sellFloorNum > 0) — a zero floor is no protection");
  if ((directionMask & DIRECTION.BUY) !== 0n && p.buyCeilNum === 0n) fail("a BUY-enabled leaf must set a positive ceiling price (buyCeilNum > 0)");
  return p;
}

/* A leaf derived from a profile: the VM-relevant facts come from the profile, the authority from the owner. */
function swapPolicyFromProfileV6(profile, owner) {
  const p = normalizeSwapVenueProfile(profile);
  return normalizeSwapPolicyV6({
    profileHash: computeSwapVenueProfileHash(p),
    poolCovenantId: p.poolCovenantId,
    poolTemplateVmHash: p.poolTemplateVmHashBlake2b256,
    poolPrefixLen: p.poolTemplateGeometry.prefixLen,
    poolSuffixLen: p.poolTemplateGeometry.suffixLen,
    poolFeePk: p.feeModel.protocolFeePk,
    maxProtocolFeeKas: owner.maxProtocolFeeKas,
    sellFloorNum: owner.sellFloorNum ?? 0n,
    sellFloorDen: owner.sellFloorDen ?? 1n,
    buyCeilNum: owner.buyCeilNum ?? 0n,
    buyCeilDen: owner.buyCeilDen ?? 1n,
    directionMask: owner.directionMask,
    destScheme: owner.destScheme,
    destIdentity: owner.destIdentity ?? ZERO32_HEX
  });
}

function swapPolicyLeafPreimageV6(policyInput) {
  const p = normalizeSwapPolicyV6(policyInput);
  const preimage = concatBytes([
    SWAP_POLICY_LEAF_DOMAIN_V6,
    hexToBytes(p.profileHash),
    hexToBytes(p.poolCovenantId),
    hexToBytes(p.poolTemplateVmHash),
    num8(p.poolPrefixLen),
    num8(p.poolSuffixLen),
    hexToBytes(p.poolFeePk),
    num8(p.maxProtocolFeeKas),
    num8(p.sellFloorNum),
    num8(p.sellFloorDen),
    num8(p.buyCeilNum),
    num8(p.buyCeilDen),
    num8(p.directionMask),
    Uint8Array.of(p.destScheme),
    hexToBytes(p.destIdentity)
  ]);
  if (preimage.length !== LEAF_PREIMAGE_LEN_SWAP) fail(`internal: swap-policy leaf preimage is ${preimage.length} bytes, not ${LEAF_PREIMAGE_LEN_SWAP}`);
  return preimage;
}
function swapPolicyLeafHashV6(policyInput) {
  return sha256(swapPolicyLeafPreimageV6(policyInput));
}
function swapPolicyLeafHexV6(policyInput) {
  return bytesToHex(swapPolicyLeafHashV6(policyInput));
}

function buildSwapPolicyTreeV6(policiesInput) {
  if (!Array.isArray(policiesInput)) fail("policies must be an array of swap-policy objects (may be empty)");
  const policies = policiesInput.map((p, i) => {
    try {
      return normalizeSwapPolicyV6(p);
    } catch (error) {
      fail(`policies[${i}]: ${error.message}`);
    }
  });
  const withLeaf = policies.map((policy) => ({ policy, leaf: swapPolicyLeafHashV6(policy), leafHex: swapPolicyLeafHexV6(policy) }));
  const seen = new Set();
  for (const e of withLeaf) {
    if (seen.has(e.leafHex)) fail(`duplicate swap policy leaf ${e.leafHex}`, "DUPLICATE_POLICY");
    seen.add(e.leafHex);
  }
  if (withLeaf.length > MAX_SWAP_LEAVES) fail(`swap policy count ${withLeaf.length} exceeds the maximum ${MAX_SWAP_LEAVES} (depth ${MAX_SWAP_DEPTH})`);
  withLeaf.sort((x, y) => (x.leafHex < y.leafHex ? -1 : x.leafHex > y.leafHex ? 1 : 0));
  let level = withLeaf.map((e) => e.leaf);
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
  if (depth > MAX_SWAP_DEPTH) fail(`tree depth ${depth} exceeds the core maximum ${MAX_SWAP_DEPTH}`);
  return Object.freeze({
    root: bytesToHex(levels[levels.length - 1][0]),
    policies: Object.freeze(withLeaf.map((e) => e.policy)),
    leafHexes: Object.freeze(withLeaf.map((e) => e.leafHex)),
    realCount: withLeaf.length,
    leafCount: levels[0].length,
    depth,
    levels
  });
}

function policyIndex(tree, policyInput) {
  const leafHex = swapPolicyLeafHexV6(policyInput);
  return { leafHex, index: tree.leafHexes.indexOf(leafHex) };
}

function generateSwapPolicyProofV6(tree, policyInput) {
  const { leafHex, index } = policyIndex(tree, policyInput);
  if (index < 0) fail(`swap policy ${leafHex} is not in this tree — refusing to fabricate a proof`);
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
  return Object.freeze({ leafHex, policy: tree.policies[index], root: tree.root, siblingsHex: bytesToHex(concatBytes(siblings)), pathBits, depth: tree.depth });
}

function normalizeSiblings(siblingsHex) {
  if (typeof siblingsHex !== "string" || !/^[0-9a-f]*$/.test(siblingsHex) || siblingsHex.length % 2 !== 0) fail("siblingsHex must be lowercase hex");
  const siblings = hexToBytes(siblingsHex);
  if (siblings.length % 32 !== 0) fail("siblings length must be a multiple of 32 bytes");
  if (siblings.length > 32 * COVENANT_MAX_DEPTH) fail(`proof depth ${siblings.length / 32} exceeds the covenant maximum ${COVENANT_MAX_DEPTH}`);
  return siblings;
}
function foldSwapPolicyV6(policyInput, siblingsHex, pathBits) {
  const siblings = normalizeSiblings(siblingsHex);
  let bits = typeof pathBits === "bigint" ? pathBits : BigInt(pathBits);
  if (bits < 0n || bits >= BigInt(1 << COVENANT_MAX_DEPTH)) fail("pathBits out of range");
  let node = swapPolicyLeafHashV6(policyInput);
  const depth = siblings.length / 32;
  for (let level = 0; level < depth; level++) {
    const sib = siblings.subarray(level * 32, level * 32 + 32);
    node = bits % 2n === 1n ? sha256(concatBytes([sib, node])) : sha256(concatBytes([node, sib]));
    bits /= 2n;
  }
  if (bits !== 0n) return null;
  return bytesToHex(node);
}
function verifySwapPolicyProofV6({ root, policy, siblingsHex, pathBits }) {
  const rootHex = normalizeHex(root, 32, "root");
  const computed = foldSwapPolicyV6(policy, siblingsHex, pathBits);
  return computed !== null && computed === rootHex;
}

function addSwapPolicyV6(tree, policyInput) {
  const policy = normalizeSwapPolicyV6(policyInput);
  if (policyIndex(tree, policy).index >= 0) fail("this swap policy already exists in the tree", "DUPLICATE_POLICY");
  return buildSwapPolicyTreeV6([...tree.policies, policy]);
}
function removeSwapPolicyV6(tree, policyInput) {
  const { leafHex, index } = policyIndex(tree, policyInput);
  if (index < 0) fail(`swap policy ${leafHex} is not in this tree — nothing to remove`);
  return buildSwapPolicyTreeV6(tree.policies.filter((_, i) => i !== index));
}

function swapPolicyToJsonV6(p) {
  const n = normalizeSwapPolicyV6(p);
  const out = {};
  for (const f of SWAP_POLICY_FIELDS_V6) out[f] = typeof n[f] === "bigint" ? n[f].toString() : n[f];
  return out;
}

module.exports = {
  SWAP_VENUE_PROFILE_VERSION_1,
  POOL_STATE_LAYOUT_1,
  INVARIANT_MODEL_1,
  REQUIRED_SHAPE_1,
  SWAP_POLICY_LEAF_DOMAIN_V6,
  SWAP_POLICY_PADDING_DOMAIN_V6,
  SWAP_POLICY_FIELDS_V6,
  PROFILE_FIELDS,
  LEAF_PREIMAGE_LEN_SWAP,
  MAX_SWAP_DEPTH,
  MAX_SWAP_LEAVES,
  MAX_PRICE_TERM,
  PADDING_LEAF_HEX,
  DIRECTION,
  DEST_SCHEME,
  ZERO32_HEX,
  normalizeSwapVenueProfile,
  swapVenueProfileToJson,
  computeSwapVenueProfileHash,
  normalizeSwapPolicyV6,
  swapPolicyFromProfileV6,
  swapPolicyLeafPreimageV6,
  swapPolicyLeafHashV6,
  swapPolicyLeafHexV6,
  buildSwapPolicyTreeV6,
  generateSwapPolicyProofV6,
  foldSwapPolicyV6,
  verifySwapPolicyProofV6,
  addSwapPolicyV6,
  removeSwapPolicyV6,
  swapPolicyToJsonV6
};
