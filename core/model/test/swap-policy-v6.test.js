"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const sp = require("../swap-policy-v6");

const profile = () => ({
  profileVersion: "policyvault-swap-venue-profile/1",
  profileId: "v6-pool-fixture-testnet-10",
  networkId: "testnet-10",
  poolCovenantId: "50".repeat(32),
  poolTemplateVmHashBlake2b256: "70".repeat(32),
  poolTemplateGeometry: { prefixLen: 1, stateLen: 36, suffixLen: 15189 },
  poolStateLayout: "constant-product-pool-state/1",
  tokenStandard: "kcc20-state/1",
  tokenCovenantId: "54".repeat(32),
  invariantModel: "constant-product-bps-fee/1",
  feeModel: { poolFeeBps: "30", protocolFeeBps: "20", protocolFeePk: "66".repeat(32) },
  requiredShape: { tokenFamilyInputs: 2, tokenFamilyOutputs: 2, poolInputs: 1, poolOutputs: 1, outputsTypeA: 5, outputsTypeB: 6 },
  signerSemantics: { sighash: "ALL", postSignIdentityVerification: true, poolOutpointBinding: "exact" },
  provenance: { sourceRelPath: "contracts/experiments/V6PoolFixture.sil", sourceSha256: "ab".repeat(32), reference: "PolicyVault v0.6 pool fixture (test venue; not an endorsement)" }
});
const ownerA = { maxProtocolFeeKas: "200", sellFloorNum: "90", sellFloorDen: "1", buyCeilNum: "110", buyCeilDen: "1", directionMask: "3", destScheme: 0x02 };

test("venue profile: closed schema, protocol facts only, deterministic hash", () => {
  const p = sp.normalizeSwapVenueProfile(profile());
  const h1 = sp.computeSwapVenueProfileHash(p);
  const h2 = sp.computeSwapVenueProfileHash(profile());
  assert.equal(h1, h2);
  assert.match(h1, /^[0-9a-f]{64}$/);
  assert.throws(() => sp.normalizeSwapVenueProfile({ ...profile(), maxIn: "5" }), /closed schema/);
  assert.throws(() => sp.normalizeSwapVenueProfile({ ...profile(), profileVersion: "policyvault-swap-venue-profile/2" }), /failing closed/);
  assert.throws(() => sp.normalizeSwapVenueProfile({ ...profile(), invariantModel: "order-book/1" }), /failing closed/);
  assert.throws(() => sp.normalizeSwapVenueProfile({ ...profile(), signerSemantics: { sighash: "SINGLE", postSignIdentityVerification: true, poolOutpointBinding: "exact" } }), /ALL/);
  const other = sp.computeSwapVenueProfileHash({ ...profile(), feeModel: { ...profile().feeModel, protocolFeeBps: "21" } });
  assert.notEqual(h1, other);
});

test("swap policy leaf: 229-byte preimage under 0x50563602; destination/direction rules fail closed", () => {
  const leaf = sp.swapPolicyFromProfileV6(profile(), ownerA);
  const pre = sp.swapPolicyLeafPreimageV6(leaf);
  assert.equal(pre.length, sp.LEAF_PREIMAGE_LEN_SWAP);
  assert.deepEqual([...pre.subarray(0, 4)], [0x50, 0x56, 0x36, 0x02]);
  assert.equal(pre[pre.length - 33], 0x02); // destScheme before the 32-byte identity
  /* type A must carry a zero identity; type B must be SELL-only and carry a real key */
  assert.throws(() => sp.normalizeSwapPolicyV6({ ...sp.swapPolicyToJsonV6(leaf), destIdentity: "63".repeat(32) }), /all-zero/);
  assert.throws(() => sp.normalizeSwapPolicyV6({ ...sp.swapPolicyToJsonV6(leaf), destScheme: 0x00, destIdentity: "63".repeat(32) }), /SELL-only/);
  const typeB = sp.normalizeSwapPolicyV6({ ...sp.swapPolicyToJsonV6(leaf), destScheme: 0x00, destIdentity: "63".repeat(32), directionMask: "1" });
  assert.equal(typeB.destScheme, 0x00);
  assert.throws(() => sp.normalizeSwapPolicyV6({ ...sp.swapPolicyToJsonV6(leaf), destScheme: 0x01 }), /no other destination schemes/);
  assert.throws(() => sp.normalizeSwapPolicyV6({ ...sp.swapPolicyToJsonV6(leaf), directionMask: "4" }), /directionMask/);
  assert.throws(() => sp.normalizeSwapPolicyV6({ ...sp.swapPolicyToJsonV6(leaf), sellFloorNum: "0" }), /positive floor/);
  assert.throws(() => sp.normalizeSwapPolicyV6({ ...sp.swapPolicyToJsonV6(leaf), buyCeilDen: "0" }), /must be > 0/);
  assert.throws(() => sp.normalizeSwapPolicyV6({ ...sp.swapPolicyToJsonV6(leaf), buyCeilNum: "1000000001" }), /inside i64/);
});

test("swap policy tree: sorted, padded, proofs verify, unapproved leaves never verify", () => {
  const a = sp.swapPolicyFromProfileV6(profile(), ownerA);
  const b = sp.swapPolicyFromProfileV6(profile(), { ...ownerA, directionMask: "1", destScheme: 0x00, destIdentity: "63".repeat(32) });
  const tree = sp.buildSwapPolicyTreeV6([a, b]);
  assert.equal(tree.realCount, 2);
  assert.equal(tree.depth, 1);
  const proof = sp.generateSwapPolicyProofV6(tree, b);
  assert.ok(sp.verifySwapPolicyProofV6({ root: tree.root, policy: b, siblingsHex: proof.siblingsHex, pathBits: proof.pathBits }));
  const forged = { ...sp.swapPolicyToJsonV6(b), maxProtocolFeeKas: "2000" };
  assert.ok(!sp.verifySwapPolicyProofV6({ root: tree.root, policy: forged, siblingsHex: proof.siblingsHex, pathBits: proof.pathBits }));
  assert.throws(() => sp.addSwapPolicyV6(tree, a), /already exists/);
  const smaller = sp.removeSwapPolicyV6(tree, a);
  assert.equal(smaller.realCount, 1);
  assert.notEqual(sp.PADDING_LEAF_HEX, require("../agent-merkle-v6").PADDING_LEAF_HEX);
  const full = sp.buildSwapPolicyTreeV6(Array.from({ length: 256 }, (_, i) => ({ ...sp.swapPolicyToJsonV6(a), maxProtocolFeeKas: String(200 + i) })));
  assert.equal(full.depth, 8);
  assert.throws(() => sp.buildSwapPolicyTreeV6(Array.from({ length: 257 }, (_, i) => ({ ...sp.swapPolicyToJsonV6(a), maxProtocolFeeKas: String(200 + i) }))), /exceeds the maximum/);
});
