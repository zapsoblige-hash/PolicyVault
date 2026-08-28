"use strict";

/*
 * UNIT / ADVERSARIAL — strict SD-JWT verification, the §8 downgrade and
 * malformation matrix at the crypto layer: A-19 (_sd_alg), A-20 (JWS
 * downgrades + key injection), A-16 (expiry), A-24 (malformed/oversized),
 * A-25 (disclosure attacks), key binding (sd_hash / cnf / nonce).
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const { ecKeyPair, buildSdJwt, signJws, b64u, b64uSha256 } = require("./helpers/fixtures");
const { verifySdJwtMandate, CAPS } = require("../ap2/sdjwt");
const { Ap2Refusal } = require("../ap2/codes");

const issuer = ecKeyPair();
const holder = ecKeyPair();
const stranger = ecKeyPair();
const ANCHORS = { "user-1": { jwk: issuer.jwk, role: "user" }, "agent-1": { jwk: stranger.jwk, role: "agent" } };
const NOW = Math.floor(Date.now() / 1000);

function goodClaims(extra = {}) {
  return { vct: "mandate.payment.1", transaction_id: "T".repeat(43), exp: NOW + 600, ...extra };
}
function build(overrides = {}) {
  return buildSdJwt({ claims: goodClaims(), issuer, holder, kid: "user-1", ...overrides });
}
function codeOf(compact, opts = {}) {
  try {
    verifySdJwtMandate(compact, { trustAnchors: ANCHORS, nowSeconds: NOW, ...opts });
  } catch (e) {
    assert.ok(e instanceof Ap2Refusal, `expected Ap2Refusal, got ${e.constructor.name}: ${e.message}`);
    return e.code;
  }
  return null;
}

test("a well-formed, correctly bound presentation verifies; role comes from the pinned anchor, never the token", () => {
  const out = verifySdJwtMandate(build({ sdProperties: { payee: { id: "m1" } } }), { trustAnchors: ANCHORS, nowSeconds: NOW });
  assert.equal(out.claims.vct, "mandate.payment.1");
  assert.deepEqual(out.claims.payee, { id: "m1" });
  assert.equal(out.role, "user");
  assert.equal(out.verification.signatureValid, true);
  assert.equal(out.verification.keyBindingValid, true);
  assert.equal(out.claims.cnf, undefined); // consumed by binding, not exposed as a claim
  assert.equal(out.claims._sd_alg, undefined);
});

test("A-20: alg none / HS256 / RS256 / unknown / absent all refuse — pinned, never negotiated from the token", () => {
  for (const alg of ["none", "HS256", "RS256", "ES384", "", undefined]) {
    const header = alg === undefined ? { kid: "user-1" } : { alg, kid: "user-1" };
    const jws = `${b64u(header)}.${b64u(goodClaims({ _sd_alg: "sha-256" }))}.${b64u("sig")}`;
    const kb = signJws({ alg: "ES256", kid: "h", typ: "kb+jwt" }, { iat: NOW, sd_hash: b64uSha256(`${jws}~`) }, holder.privateKey);
    assert.equal(codeOf(`${jws}~${kb}`), "AP2_ALG_UNSUPPORTED", JSON.stringify(alg));
  }
});

test("A-20: embedded jwk/jku/x5u header key material refuses outright (key injection)", () => {
  for (const injected of [{ jwk: issuer.jwk }, { jku: "https://evil.example/keys" }, { x5u: "https://evil.example/cert" }, { x5c: ["MIIB"] }]) {
    assert.equal(codeOf(build({ extraHeader: injected })), "AP2_ALG_UNSUPPORTED", JSON.stringify(Object.keys(injected)));
  }
});

test("algorithm confusion is structurally unreachable: a symmetric-alg token dies at the alg gate before any key is touched", () => {
  // HS256 'signed' with the public key bytes as the MAC secret.
  const crypto = require("node:crypto");
  const header = { alg: "HS256", kid: "user-1" };
  const payload = goodClaims({ _sd_alg: "sha-256" });
  const input = `${b64u(header)}.${b64u(payload)}`;
  const mac = crypto.createHmac("sha256", Buffer.from(JSON.stringify(issuer.jwk))).update(input).digest("base64url");
  const kb = signJws({ alg: "ES256", kid: "h", typ: "kb+jwt" }, { iat: NOW, sd_hash: b64uSha256(`${input}.${mac}~`) }, holder.privateKey);
  assert.equal(codeOf(`${input}.${mac}~${kb}`), "AP2_ALG_UNSUPPORTED");
});

test("unknown kid refuses; unconfigured anchors fail closed with their own code", () => {
  assert.equal(codeOf(build({ kid: "not-pinned" })), "AP2_TRUST_ANCHOR_UNKNOWN");
  assert.equal(codeOf(build(), { trustAnchors: null }), "AP2_TRUST_ANCHOR_UNCONFIGURED");
  assert.equal(codeOf(build(), { trustAnchors: {} }), "AP2_TRUST_ANCHOR_UNCONFIGURED");
});

test("a tampered payload or a signature from the wrong key refuses AP2_SIGNATURE_INVALID", () => {
  const good = build();
  const [jws, ...rest] = good.split("~");
  const [h, p, s] = jws.split(".");
  const tamperedPayload = [h, b64u(goodClaims({ _sd_alg: "sha-256", exp: NOW + 999999 })), s].join(".");
  assert.equal(codeOf([tamperedPayload, ...rest].join("~")), "AP2_SIGNATURE_INVALID");
  const wrongKey = buildSdJwt({ claims: goodClaims(), issuer: stranger, holder, kid: "user-1" });
  assert.equal(codeOf(wrongKey), "AP2_SIGNATURE_INVALID");
});

test("A-19: _sd_alg absent, weak, unknown, or wrong-typed refuses — no default, ever", () => {
  assert.equal(codeOf(build({ sdAlg: null })), "AP2_SD_ALG_UNSUPPORTED"); // absent
  for (const alg of ["sha-1", "md5", "SHA-256", "sha256", 5]) {
    assert.equal(codeOf(build({ sdAlg: alg })), "AP2_SD_ALG_UNSUPPORTED", JSON.stringify(alg));
  }
});

test("A-16: expired mandates refuse; iat in the future beyond skew refuses", () => {
  assert.equal(codeOf(build({ claims: goodClaims({ exp: NOW - 10 }) })), "AP2_MANDATE_EXPIRED");
  assert.equal(codeOf(build({ claims: goodClaims({ iat: NOW + 100000 }) })), "AP2_MANDATE_EXPIRED");
  assert.equal(codeOf(build({ claims: goodClaims({ iat: NOW + 10 }) })), null, "small skew tolerated");
});

test("A-25 disclosure attacks: duplicates, unreferenced disclosures, double-references, and name collisions refuse", () => {
  // Duplicate disclosure.
  const base = build({ sdProperties: { payee: { id: "m1" } } });
  const segments = base.split("~");
  const disclosure = segments[1];
  const doubled = [segments[0], disclosure, disclosure, ...segments.slice(2)].join("~");
  assert.equal(codeOf(doubled), "AP2_DISCLOSURE_INVALID");
  // Unreferenced disclosure (valid format, digest not in any _sd).
  const alien = b64u(JSON.stringify(["salt-x", "alien", 1]));
  const withAlien = [segments[0], disclosure, alien, ...segments.slice(2)].join("~");
  assert.equal(codeOf(withAlien), "AP2_DISCLOSURE_INVALID");
  // Disclosure whose name collides with a cleartext claim.
  const collide = buildSdJwt({ claims: goodClaims({ payee: { id: "clear" } }), sdProperties: { payee: { id: "hidden" } }, issuer, holder, kid: "user-1" });
  assert.equal(codeOf(collide), "AP2_DISCLOSURE_INVALID");
  // Malformed disclosure JSON.
  const badJson = [segments[0], b64u("not json"), ...segments.slice(2)].join("~");
  assert.equal(codeOf(badJson), "AP2_DISCLOSURE_INVALID");
  // Forbidden claim name via disclosure.
  const proto = buildSdJwt({ claims: goodClaims(), sdProperties: { __proto__x: 1 }, issuer, holder, kid: "user-1" });
  void proto; // (the builder cannot express a literal __proto__ key safely; direct disclosure below)
  const protoDisclosure = b64u(JSON.stringify(["s", "__proto__", { polluted: 1 }]));
  const payload = goodClaims({ _sd_alg: "sha-256", _sd: [b64uSha256(protoDisclosure)] });
  const jws = signJws({ alg: "ES256", kid: "user-1" }, { ...payload, cnf: { jwk: holder.jwk } }, issuer.privateKey);
  const prefix = `${jws}~${protoDisclosure}~`;
  const kb = signJws({ alg: "ES256", kid: "h", typ: "kb+jwt" }, { iat: NOW, sd_hash: b64uSha256(prefix) }, holder.privateKey);
  assert.equal(codeOf(prefix + kb), "AP2_DISCLOSURE_INVALID");
  assert.equal(Object.prototype.polluted, undefined);
});

test("key binding: absent KB, tampered sd_hash, KB signed by a non-cnf key, and missing cnf each refuse", () => {
  assert.equal(codeOf(build({ omitKb: true })), "AP2_KEY_BINDING_INVALID");
  assert.equal(codeOf(build({ tamperSdHash: true })), "AP2_KEY_BINDING_INVALID");
  // KB signed by a different key than cnf.jwk binds.
  const good = build();
  const segs = good.split("~");
  const prefix = segs.slice(0, -1).join("~") + "~";
  const forgedKb = signJws({ alg: "ES256", kid: "h", typ: "kb+jwt" }, { iat: NOW, sd_hash: b64uSha256(prefix) }, stranger.privateKey);
  assert.equal(codeOf(prefix + forgedKb), "AP2_SIGNATURE_INVALID");
  // No cnf in the issuer-signed payload.
  const noCnfJws = signJws({ alg: "ES256", kid: "user-1" }, goodClaims({ _sd_alg: "sha-256" }), issuer.privateKey);
  const noCnfPrefix = `${noCnfJws}~`;
  const kb = signJws({ alg: "ES256", kid: "h", typ: "kb+jwt" }, { iat: NOW, sd_hash: b64uSha256(noCnfPrefix) }, holder.privateKey);
  assert.equal(codeOf(noCnfPrefix + kb), "AP2_KEY_BINDING_INVALID");
});

test("expectedNonce, when demanded by the caller, must match the KB-JWT nonce", () => {
  assert.equal(codeOf(build({ kbNonce: "abc" }), { expectedNonce: "abc" }), null);
  assert.equal(codeOf(build({ kbNonce: "abc" }), { expectedNonce: "different" }), "AP2_KEY_BINDING_INVALID");
});

test("A-24 malformation: oversize (pre-parse), alien characters, missing segments, disclosure fan-out cap", () => {
  assert.equal(codeOf("x".repeat(CAPS.compactBytes + 10)), "AP2_ENVELOPE_INVALID");
  assert.equal(codeOf("has spaces~x"), "AP2_ENVELOPE_INVALID");
  assert.equal(codeOf("single-segment-no-tilde.but.jws"), "AP2_ENVELOPE_INVALID");
  const good = build();
  const segs = good.split("~");
  const fanout = [segs[0], ...Array.from({ length: CAPS.maxDisclosures + 1 }, (_, i) => b64u(JSON.stringify([`s${i}`, `n${i}`, i]))), segs[segs.length - 1]].join("~");
  assert.equal(codeOf(fanout), "AP2_ENVELOPE_INVALID");
});
