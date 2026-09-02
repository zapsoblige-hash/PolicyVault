"use strict";

/* UNIT + PRODUCTION-BYTE: the canonical KCC20 adapter against the
 * real-compiler/engine fixture. */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");

const k = require("../kcc20");

const fixture = JSON.parse(fs.readFileSync(path.join(__dirname, "fixtures", "kcc20-template-v1.json"), "utf8"));
const b2 = fixture.bounds.find((b) => b.familyBound === 2);

test("fixture identity", () => {
  assert.equal(fixture.fixture, "policyvault-kcc20-template-fixture/1");
  assert.equal(fixture.stateLayout, k.STATE_LAYOUT_ID);
  for (const b of fixture.bounds) assert.equal(b.stateLen, k.STATE_LEN);
});

test("PRODUCTION-BYTE: encodeState reproduces every compiler-emitted state byte-for-byte, decodeState inverts it", () => {
  for (const b of fixture.bounds) {
    for (const s of b.states) {
      const encoded = k.bytesToHex(k.encodeState({ ownerIdentifier: s.ownerIdentifier, identifierType: s.identifierType, amount: s.amount, isMinter: s.isMinter }));
      assert.equal(encoded, s.stateHex, `bound ${b.familyBound} amount ${s.amount}`);
      const decoded = k.decodeState(s.stateHex);
      assert.equal(decoded.ownerIdentifier, s.ownerIdentifier);
      assert.equal(decoded.identifierType, s.identifierType);
      assert.equal(decoded.amount, BigInt(s.amount));
      assert.equal(decoded.isMinter, s.isMinter);
    }
  }
});

test("PRODUCTION-BYTE: redeem reconstruction + P2SH envelope equal the engine's script public key for every state", () => {
  for (const b of fixture.bounds) {
    for (const s of b.states) {
      const redeem = k.reconstructRedeem(b.prefixHex, s.stateHex, b.suffixHex);
      assert.equal(k.p2shSpkHex(redeem), s.p2shSpkHex);
      const parts = k.splitRedeem(redeem, { prefixLen: b.prefixLen, stateLen: b.stateLen, suffixLen: b.suffixLen });
      assert.equal(k.bytesToHex(parts.prefix), b.prefixHex);
      assert.equal(k.bytesToHex(parts.suffix), b.suffixHex);
      assert.equal(k.templateVmHashHex(parts.prefix, parts.suffix), b.templateVmHashBlake2b256);
    }
  }
});

test("PRODUCTION-BYTE: static P2SH sig-op scan equals the node's post-Toccata scanner for bounds 2/4/8/15/16", () => {
  for (const b of fixture.bounds) {
    const redeem = k.reconstructRedeem(b.prefixHex, b.states[0].stateHex, b.suffixHex);
    const scan = k.countStaticSigOps(redeem);
    assert.equal(scan.malformed, false);
    assert.equal(scan.sigOps, b.staticP2shSigOps, `bound ${b.familyBound}`);
    assert.equal(scan.sigOps, b.familyBound, "one checkSig per unrolled family iteration");
  }
});

test("standardness envelope: bounds <= 15 STANDARD, bound 16 REFUSED, malformed template REFUSED", () => {
  for (const b of fixture.bounds) {
    const r = k.templateStandardness(b.prefixHex, b.suffixHex);
    if (b.familyBound <= 15) {
      assert.equal(r.standard, true, `bound ${b.familyBound}`);
    } else {
      assert.equal(r.standard, false);
      assert.equal(r.reason, "TEMPLATE_NONSTANDARD_FAMILY_BOUND");
      assert.equal(r.staticSigOps, 16);
    }
  }
  const truncated = k.templateStandardness(b2.prefixHex, b2.suffixHex.slice(0, -2) + "4c"); // dangling PUSHDATA1
  assert.equal(truncated.standard, false);
  assert.equal(truncated.reason, "TEMPLATE_MALFORMED");
});

test("sig-op scanner semantics: multisig counts from Op1..16 and from non-minimal pushes; unknown count = 20", () => {
  const scan = (hex) => k.countStaticSigOps(hex);
  assert.equal(scan("53ae").sigOps, 3); // Op3 OpCheckMultiSig
  assert.equal(scan("0102ae").sigOps, 2); // OpData1 0x02 OpCheckMultiSig
  assert.equal(scan("ae").sigOps, 20); // no count -> MAX_PUB_KEYS_PER_MULTISIG
  assert.equal(scan("0115ae").sigOps, 20); // 21 out of range -> 20
  assert.equal(scan("acadabd7d8").sigOps, 5);
  assert.equal(scan("aa").sigOps, 0);
  assert.equal(scan("4c").malformed, true);
});

test("malformed / hostile token states fail closed", () => {
  const good = b2.states[0].stateHex;
  assert.throws(() => k.decodeState(good.slice(0, -2)), /46 bytes/);
  assert.throws(() => k.decodeState("21" + good.slice(2)), /push framing/);
  assert.throws(() => k.decodeState(good.slice(0, 68) + "07" + good.slice(70)), /not a known owner scheme/);
  assert.throws(() => k.decodeState(good.slice(0, 90) + "02"), /isMinter/);
  const signBit = good.slice(0, 72) + "ffffffffffffffff" + good.slice(88);
  assert.throws(() => k.decodeState(signBit), /sign bit/);
  assert.throws(() => k.encodeState({ ownerIdentifier: "00".repeat(32), identifierType: 0, amount: "-1", isMinter: false }));
  assert.throws(() => k.encodeState({ ownerIdentifier: "00".repeat(32), identifierType: 0, amount: "9223372036854775808", isMinter: false }), /i64/);
  assert.throws(() => k.encodeState({ ownerIdentifier: "00".repeat(32), identifierType: 0, amount: "1", isMinter: "no" }));
  assert.throws(() => k.encodeState({ ownerIdentifier: "00".repeat(32), identifierType: 3, amount: "1", isMinter: false }), /owner scheme/);
  assert.throws(() => k.encodeState({ ownerIdentifier: "00".repeat(32), identifierType: 0, amount: "1", isMinter: false, extra: 1 }), /unknown field/);
  assert.throws(() => k.splitRedeem("00".repeat(10), { prefixLen: 1, stateLen: 46, suffixLen: 1 }), /geometry/);
  assert.throws(() => k.normalizeGeometry({ prefixLen: 1, stateLen: 45, suffixLen: 1 }));
});

test("lastPushData extracts the redeem from a P2SH signature script (last push), fails closed otherwise", () => {
  const redeemHex = b2.prefixHex + b2.states[0].stateHex + b2.suffixHex;
  const len = redeemHex.length / 2;
  const sigscript = "0100" + "4d" + (len & 0xff).toString(16).padStart(2, "0") + (len >> 8).toString(16).padStart(2, "0") + redeemHex; // OpData1 0x00, PUSHDATA2 redeem
  assert.equal(k.bytesToHex(k.lastPushData(sigscript)), redeemHex);
  assert.throws(() => k.lastPushData(sigscript + "ac"), /does not end with a data push/);
  assert.throws(() => k.lastPushData(""), /malformed or empty/);
});
