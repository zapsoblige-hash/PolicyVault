"use strict";

/* UNIT + PRODUCTION-BYTE: the public asset-layer interface. */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");

const assets = require("../index");
const k = assets.kcc20;

const fixture = JSON.parse(fs.readFileSync(path.join(__dirname, "fixtures", "kcc20-template-v1.json"), "utf8"));
const b2 = fixture.bounds.find((b) => b.familyBound === 2);
const b4 = fixture.bounds.find((b) => b.familyBound === 4);
const b16 = fixture.bounds.find((b) => b.familyBound === 16);

const POWERS = { mint: false, burn: false, freeze: false, blacklist: false, redemptionControl: false, upgradeMigration: false, controllerRotation: false, emergencyControl: false };
function descriptorFor(bounds, extra = {}) {
  return {
    schema: "policyvault-asset-descriptor/1",
    assetId: "11".repeat(32),
    displayName: "Fixture Token",
    tokenStandard: "kcc20/1",
    tokenCovenantId: "54".repeat(32),
    acceptedTransferTemplates: bounds.map((b) => ({
      templateVmHashBlake2b256: b.templateVmHashBlake2b256,
      templateKcc1HashBlake3: b.templateKcc1HashBlake3,
      prefixLen: b.prefixLen,
      suffixLen: b.suffixLen,
      stateLayout: "kcc20-state/1"
    })),
    decimalsDisplay: 8,
    issuerPowers: { ...POWERS },
    ...extra
  };
}

test("computeDescriptorHash is deterministic, key-order independent, and changes on every semantic change", () => {
  const d = descriptorFor([b2]);
  const h1 = assets.computeDescriptorHash(d);
  const reordered = JSON.parse(JSON.stringify({ issuerPowers: d.issuerPowers, decimalsDisplay: d.decimalsDisplay, acceptedTransferTemplates: d.acceptedTransferTemplates, tokenCovenantId: d.tokenCovenantId, tokenStandard: d.tokenStandard, displayName: d.displayName, assetId: d.assetId, schema: d.schema }));
  assert.equal(assets.computeDescriptorHash(reordered), h1);
  assert.match(h1, /^[0-9a-f]{64}$/);
  const variants = [
    descriptorFor([b4]),
    descriptorFor([b2], { tokenCovenantId: "55".repeat(32) }),
    descriptorFor([b2], { issuerPowers: { ...POWERS, mint: true } }),
    descriptorFor([b2], { decimalsDisplay: 6 }),
    descriptorFor([b2], { notes: "x" }),
    descriptorFor([b2, b4])
  ];
  const seen = new Set([h1]);
  for (const v of variants) {
    const h = assets.computeDescriptorHash(v);
    assert.equal(seen.has(h), false, "every semantic change must produce a distinct descriptor hash");
    seen.add(h);
  }
  /* the optional KCC-0001 hash is part of the pinned identity when present */
  const withoutKcc1 = descriptorFor([b2]);
  delete withoutKcc1.acceptedTransferTemplates[0].templateKcc1HashBlake3;
  assert.notEqual(assets.computeDescriptorHash(withoutKcc1), h1);
  /* invalid descriptors never hash */
  assert.throws(() => assets.computeDescriptorHash({ ...d, schema: "policyvault-asset-descriptor/2" }), /unknown descriptor schema/);
  assert.throws(() => assets.computeDescriptorHash({ ...d, extra: 1 }), /unknown field/);
});

test("PRODUCTION-BYTE: corroborateTemplate accepts the real template bytes (bounds 2/4) and reports the standardness envelope", () => {
  const d = descriptorFor([b2, b4]);
  const r2 = assets.corroborateTemplate({ descriptor: d, templateIndex: 0, prefixHex: b2.prefixHex, suffixHex: b2.suffixHex });
  assert.equal(r2.ok, true);
  assert.equal(r2.staticSigOps, 2);
  assert.equal(r2.standardness, "STANDARD");
  assert.equal(r2.kcc1Corroboration, "NOT_AVAILABLE");
  assert.deepEqual(r2.geometry, { prefixLen: 1, stateLen: 46, suffixLen: 1521 });
  const r4 = assets.corroborateTemplate({ descriptor: d, templateIndex: 1, prefixHex: b4.prefixHex, suffixHex: b4.suffixHex });
  assert.equal(r4.staticSigOps, 4);
  const noKcc1 = descriptorFor([b2]);
  delete noKcc1.acceptedTransferTemplates[0].templateKcc1HashBlake3;
  assert.equal(assets.corroborateTemplate({ descriptor: noKcc1, prefixHex: b2.prefixHex, suffixHex: b2.suffixHex }).kcc1Corroboration, "NOT_DECLARED");
});

test("corroborateTemplate REFUSES: wrong VM hash, wrong geometry, split shift, byte mutation, other-variant bytes, non-standard bound", () => {
  const d = descriptorFor([b2]);
  const refuse = (args, code) => {
    let err;
    try {
      assets.corroborateTemplate({ descriptor: d, templateIndex: 0, ...args });
    } catch (e) {
      err = e;
    }
    assert.ok(err, "must refuse");
    assert.equal(err.code, code);
  };
  refuse({ prefixHex: b2.prefixHex, suffixHex: b4.suffixHex }, "TEMPLATE_GEOMETRY_MISMATCH"); // other accepted-template variant of the same family
  refuse({ prefixHex: b2.prefixHex + b2.suffixHex.slice(0, 2), suffixHex: b2.suffixHex.slice(2) }, "TEMPLATE_GEOMETRY_MISMATCH"); // hash-preserving split shift
  refuse({ prefixHex: "6c", suffixHex: b2.suffixHex }, "TEMPLATE_HASH_MISMATCH"); // one-byte prefix mutation (same geometry)
  const flipped = b2.suffixHex.slice(0, 100) + (b2.suffixHex[100] === "0" ? "1" : "0") + b2.suffixHex.slice(101);
  refuse({ prefixHex: b2.prefixHex, suffixHex: flipped }, "TEMPLATE_HASH_MISMATCH");
  const wrongHash = descriptorFor([{ ...b2, templateVmHashBlake2b256: "ab".repeat(32) }]);
  assert.throws(() => assets.corroborateTemplate({ descriptor: wrongHash, prefixHex: b2.prefixHex, suffixHex: b2.suffixHex }), /TEMPLATE_HASH_MISMATCH|does not equal/);
  /* a descriptor may DECLARE a bound-16 template, but it can never become spend-enabled */
  const d16 = descriptorFor([b16]);
  let err;
  try {
    assets.corroborateTemplate({ descriptor: d16, prefixHex: b16.prefixHex, suffixHex: b16.suffixHex });
  } catch (e) {
    err = e;
  }
  assert.equal(err.code, "TEMPLATE_NONSTANDARD_FAMILY_BOUND");
  assert.match(err.message, /16 exceed the standard limit 15/);
});

test("PRODUCTION-BYTE: verifyTokenInputRedeem identifies the accepted template by bytes, decodes the state, returns the exact P2SH spk", () => {
  const d = descriptorFor([b4, b2]); // order deliberately swapped: matching is by bytes, never by position or label
  for (const s of b2.states) {
    const redeemHex = b2.prefixHex + s.stateHex + b2.suffixHex;
    const r = assets.verifyTokenInputRedeem({ descriptor: d, redeemHex });
    assert.equal(r.templateIndex, 1);
    assert.equal(r.templateVmHashBlake2b256, b2.templateVmHashBlake2b256);
    assert.equal(r.state.amount, BigInt(s.amount));
    assert.equal(r.state.ownerIdentifier, s.ownerIdentifier);
    assert.equal(r.p2shSpkHex, s.p2shSpkHex);
  }
  /* alien template (bound 8 not accepted) and hostile mutations refuse */
  const b8 = fixture.bounds.find((b) => b.familyBound === 8);
  assert.throws(() => assets.verifyTokenInputRedeem({ descriptor: d, redeemHex: b8.prefixHex + b8.states[0].stateHex + b8.suffixHex }), /matches none/);
  const flipped = b2.prefixHex + b2.states[0].stateHex + b2.suffixHex.slice(0, 20) + (b2.suffixHex[20] === "0" ? "1" : "0") + b2.suffixHex.slice(21);
  assert.throws(() => assets.verifyTokenInputRedeem({ descriptor: d, redeemHex: flipped }), /matches none/);
  const badState = b2.prefixHex + "21" + b2.states[0].stateHex.slice(2) + b2.suffixHex; // right template, malformed state framing
  assert.throws(() => assets.verifyTokenInputRedeem({ descriptor: d, redeemHex: badState }), /push framing/);
});

test("redeemFromSignatureScript returns the last push (the P2SH redeem)", () => {
  const redeemHex = b2.prefixHex + b2.states[0].stateHex + b2.suffixHex;
  const len = redeemHex.length / 2;
  const sig = "0100" + "4d" + (len & 0xff).toString(16).padStart(2, "0") + (len >> 8).toString(16).padStart(2, "0") + redeemHex;
  assert.equal(assets.redeemFromSignatureScript(sig), redeemHex);
  const verified = assets.verifyTokenInputRedeem({ descriptor: descriptorFor([b2]), redeemHex: assets.redeemFromSignatureScript(sig) });
  assert.equal(verified.p2shSpkHex, b2.states[0].p2shSpkHex);
});
