"use strict";

/* UNIT + PRODUCTION-BYTE: pure-JS BLAKE2b against RFC 7693 / reference
 * vectors and against the real-engine fixture. */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");
const nodeCrypto = require("crypto");

const { blake2b, blake2bHex } = require("../blake2b");

const enc = (s) => new TextEncoder().encode(s);

test("blake2b-512 matches RFC 7693 appendix vector for 'abc'", () => {
  assert.equal(
    blake2bHex(enc("abc"), 64),
    "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"
  );
});

test("blake2b-512 of the empty message matches the reference vector", () => {
  assert.equal(
    blake2bHex(new Uint8Array(0), 64),
    "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
  );
});

test("blake2b-256 reference vectors (empty, 'abc')", () => {
  assert.equal(blake2bHex(new Uint8Array(0), 32), "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8");
  assert.equal(blake2bHex(enc("abc"), 32), "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319");
});

test("blake2b-512 agrees with Node's OpenSSL blake2b512 on random multi-block inputs", () => {
  for (const len of [0, 1, 63, 64, 127, 128, 129, 255, 256, 1000, 4096, 10033]) {
    const data = nodeCrypto.randomBytes(len);
    assert.equal(blake2bHex(new Uint8Array(data), 64), nodeCrypto.createHash("blake2b512").update(data).digest("hex"), `len ${len}`);
  }
});

test("multi-part hashing equals single-buffer hashing (no boundary artefacts)", () => {
  const a = nodeCrypto.randomBytes(1000);
  const b = nodeCrypto.randomBytes(777);
  const joined = Buffer.concat([a, b]);
  assert.equal(blake2bHex([new Uint8Array(a), new Uint8Array(b)], 32), blake2bHex(new Uint8Array(joined), 32));
  assert.equal(blake2bHex([a.toString("hex"), b.toString("hex")], 32), blake2bHex(new Uint8Array(joined), 32));
});

test("PRODUCTION-BYTE: blake2b-256(prefix || suffix) equals the real-engine template identity for every family bound", () => {
  const fixture = JSON.parse(fs.readFileSync(path.join(__dirname, "fixtures", "kcc20-template-v1.json"), "utf8"));
  assert.equal(fixture.vmHashConvention, "blake2b-256(prefix || suffix)");
  for (const b of fixture.bounds) {
    assert.equal(blake2bHex([b.prefixHex, b.suffixHex], 32), b.templateVmHashBlake2b256, `bound ${b.familyBound}`);
    /* P2SH envelope commits to blake2b-256 of the WHOLE redeem: OpBlake2b(aa) OpData32(20) <hash> OpEqual(87). */
    const ref = b.states[0];
    const redeemHex = b.prefixHex + ref.stateHex + b.suffixHex;
    assert.equal("aa20" + blake2bHex(redeemHex, 32) + "87", b.referenceP2shSpkHex, `bound ${b.familyBound} P2SH envelope`);
  }
});

test("rejects invalid outlen and malformed input", () => {
  assert.throws(() => blake2b(new Uint8Array(1), 0));
  assert.throws(() => blake2b(new Uint8Array(1), 65));
  assert.throws(() => blake2b("abc"));
  assert.throws(() => blake2b(123));
});
