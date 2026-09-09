"use strict";

/*
 * UNIT — v0.7 organizational ROOT state: the exact 467-byte state region,
 * the fixed-width 11-byte TAIL, canonical parse/serialize round-trips, the
 * state digest and the state ID.
 *
 * The byte layout is PINNED to the REAL silverc compiler's own
 * `state_layout` region for the production candidate
 * contracts/PolicyVault.v0.7-root.sil, captured by
 * core/model/tools/capture-v7-root-layout.js into
 * fixtures/v7-root-state-layout.json. A drift in either the compiler's
 * encoding or this serializer fails here — before any SDK builds a state
 * region consensus would read differently.
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");

const {
  CONTRACT_VERSION_V7_ROOT,
  ROOT_STATE_LEN_V7,
  ROOT_TAIL_LEN_V7,
  ROOT_HEAD_LEN_V7,
  MAX_ROOT_NONCE_V7,
  resolveV7RootAbi,
  normalizeRootTemplateV7,
  normalizeRootStateV7,
  genesisRootStateV7,
  serializeRootStateV7,
  serializeRootStateHexV7,
  parseRootStateV7,
  rootStateTailHexV7,
  expectedRootSuccessorTailHexV7,
  computeRootStateDigestV7,
  computeRootStateIdV7,
  rootStateToJsonV7,
  rootTemplateToJsonV7
} = require("../vault-state-v7-root");
const { OWNER_SLOTS_V7, INACTIVE_SLOT_KEY } = require("../owner-set-v7");

const FIXTURE = JSON.parse(fs.readFileSync(path.join(__dirname, "fixtures", "v7-root-state-layout.json"), "utf8"));

const K = (b) => b.toString(16).padStart(2, "0").repeat(32);
const ORG_ID = "a7".repeat(32);
function owners(n) {
  const out = [];
  for (let i = 0; i < OWNER_SLOTS_V7; i += 1) out.push(i < n ? K(0x71 + i) : INACTIVE_SLOT_KEY);
  return out;
}
const TEMPLATE = { orgId: ORG_ID, recoveryDelayDaa: 1000n, successorPk: K(0x7f), successionDelayDaa: 2000n, rootMaxFeePerTx: 200000n };
const state = (over = {}) => normalizeRootStateV7({ boundOrgId: ORG_ID, owners: owners(3), ownerM: 2, emergencyK: 1, recoveryM: 2, frozen: 0, rootNonce: 0, ...over });

test("layout constants match the measured production geometry (§12.3)", () => {
  assert.equal(ROOT_STATE_LEN_V7, 467);
  assert.equal(ROOT_TAIL_LEN_V7, 11);
  assert.equal(ROOT_HEAD_LEN_V7, 456);
  assert.equal(33 + 12 * 33 + 3 * 9 + 2 + 9, ROOT_STATE_LEN_V7);
  assert.equal(FIXTURE.rootStateLen, ROOT_STATE_LEN_V7);
  assert.equal(FIXTURE.rootTailLen, ROOT_TAIL_LEN_V7);
});

test("PINNED: the serializer reproduces the real compiler's state region byte-for-byte", () => {
  assert.ok(FIXTURE.cases.length >= 4, "the fixture must cover the reachable-state corners");
  for (const c of FIXTURE.cases) {
    assert.equal(c.compiled.contractName, "PolicyVaultOrgRoot");
    assert.equal(c.compiled.stateLayout.len, ROOT_STATE_LEN_V7, `${c.name}: the compiler's state region must be the constant length`);
    const rebuilt = serializeRootStateHexV7(normalizeRootStateV7(c.state));
    assert.equal(rebuilt, c.compiled.stateRegionHex, `${c.name}: core serialization != compiler state region`);
    assert.equal(c.coreSerializedHex, c.compiled.stateRegionHex, `${c.name}: the captured fixture itself must agree`);
  }
  /* the region length is a CONSTANT — the whole reason a rooted vault can
   * slice HEAD and TAIL by fixed offsets */
  const lens = new Set(FIXTURE.cases.map((c) => c.compiled.stateLayout.len));
  assert.equal(lens.size, 1);
  const redeems = new Set(FIXTURE.cases.map((c) => c.compiled.scriptLen));
  assert.equal(redeems.size, 1, "the root redeem length must not depend on the live state");
});

test("TAIL bytes are exactly 0x01 || frozen || 0x08 || nonce(8 LE)", () => {
  assert.equal(rootStateTailHexV7({ frozen: 0n, rootNonce: 0n }), "0100" + "08" + "0000000000000000");
  assert.equal(rootStateTailHexV7({ frozen: 1n, rootNonce: 1n }), "0101" + "08" + "0100000000000000");
  assert.equal(rootStateTailHexV7({ frozen: 0n, rootNonce: 258n }), "0100" + "08" + "0201000000000000");
  /* the successor tail a rooted vault rebuilds and pins */
  assert.equal(expectedRootSuccessorTailHexV7({ prevRootNonce: 41n, expectFrozenAfter: 0n }), rootStateTailHexV7({ frozen: 0n, rootNonce: 42n }));
  assert.equal(expectedRootSuccessorTailHexV7({ prevRootNonce: 41n, expectFrozenAfter: 1n }), rootStateTailHexV7({ frozen: 1n, rootNonce: 42n }));
  /* the TAIL is the last 11 bytes of the serialized region */
  const bytes = serializeRootStateV7(state({ frozen: 1, rootNonce: 7 }));
  assert.equal(Buffer.from(bytes.subarray(ROOT_STATE_LEN_V7 - ROOT_TAIL_LEN_V7)).toString("hex"), rootStateTailHexV7({ frozen: 1n, rootNonce: 7n }));
});

test("parse is the exact inverse of serialize, and refuses malformed regions", () => {
  for (const c of FIXTURE.cases) {
    const parsed = parseRootStateV7(c.compiled.stateRegionHex);
    const original = normalizeRootStateV7(c.state);
    assert.deepEqual(rootStateToJsonV7(parsed), rootStateToJsonV7(original), `${c.name}: round-trip`);
  }
  assert.throws(() => parseRootStateV7("00".repeat(466)), (e) => e.code === "BAD_STATE_LENGTH");
  /* a corrupted data prefix */
  const hex = serializeRootStateHexV7(state());
  assert.throws(() => parseRootStateV7("21" + hex.slice(2)), (e) => e.code === "BAD_STATE_ENCODING");
  /* a frozen byte outside {0x00, 0x01} — the covenant's byte-domain rule
   * exists because a numeric range check would admit 0x80 (negative zero) */
  const off = (ROOT_STATE_LEN_V7 - ROOT_TAIL_LEN_V7 + 1) * 2;
  assert.throws(() => parseRootStateV7(hex.slice(0, off) + "80" + hex.slice(off + 2)), (e) => e.code === "BAD_FROZEN_DOMAIN");
});

test("template + state normalization fails closed on out-of-domain values", () => {
  assert.equal(normalizeRootTemplateV7(TEMPLATE).successionEnabled, true);
  assert.equal(normalizeRootTemplateV7({ ...TEMPLATE, successorPk: INACTIVE_SLOT_KEY }).successionEnabled, false, "a zero successorPk DISABLES succession");
  assert.throws(() => normalizeRootTemplateV7({ ...TEMPLATE, recoveryDelayDaa: 0n }), /recoveryDelayDaa out of range/);
  assert.throws(() => normalizeRootTemplateV7({ ...TEMPLATE, successionDelayDaa: 0n }), /successionDelayDaa out of range/);
  assert.throws(() => normalizeRootTemplateV7({ ...TEMPLATE, rootMaxFeePerTx: -1n }), /rootMaxFeePerTx out of range/);
  assert.throws(() => state({ frozen: 2 }), /state.frozen out of range/);
  assert.throws(() => state({ rootNonce: -1 }), /rootNonce/);
  assert.throws(() => state({ rootNonce: MAX_ROOT_NONCE_V7 + 1n }), /rootNonce out of range/);
  assert.throws(() => resolveV7RootAbi("policyvault-0.6"), (e) => e.code === "UNKNOWN_VERSION");
  assert.equal(resolveV7RootAbi(CONTRACT_VERSION_V7_ROOT).contractName, "PolicyVaultOrgRoot");
});

test("genesis state derives from the template + owner set", () => {
  const g = genesisRootStateV7({ template: TEMPLATE, ownerSet: { owners: owners(3), ownerM: 2, emergencyK: 1, recoveryM: 2 } });
  assert.equal(g.boundOrgId, ORG_ID);
  assert.equal(g.rootNonce, 0n);
  assert.equal(g.frozen, 0n);
  assert.equal(serializeRootStateHexV7(g), serializeRootStateHexV7(state()));
});

test("digest and state ID are deterministic and change with any consensus-visible field", () => {
  const base = state();
  const digest = computeRootStateDigestV7(base);
  assert.match(digest, /^[0-9a-f]{64}$/);
  assert.equal(digest, computeRootStateDigestV7(state()), "same bytes, same digest");
  assert.notEqual(digest, computeRootStateDigestV7(state({ rootNonce: 1 })));
  assert.notEqual(digest, computeRootStateDigestV7(state({ frozen: 1 })));
  assert.notEqual(digest, computeRootStateDigestV7(state({ ownerM: 3, owners: owners(3) })));

  const id = computeRootStateIdV7({ networkId: "testnet-10", template: TEMPLATE, state: base });
  assert.match(id, /^[0-9a-f]{64}$/);
  assert.notEqual(id, computeRootStateIdV7({ networkId: "mainnet", template: TEMPLATE, state: base }), "the network is part of the identity");
  assert.notEqual(id, computeRootStateIdV7({ networkId: "testnet-10", template: { ...TEMPLATE, recoveryDelayDaa: 1001n }, state: base }), "template constants are part of the identity");
  assert.throws(() => computeRootStateIdV7({ networkId: "", template: TEMPLATE, state: base }), /networkId is required/);
  assert.equal(rootTemplateToJsonV7(TEMPLATE).rootMaxFeePerTx, "200000");
});
