"use strict";

/*
 * Strict SD-JWT verification for AP2 v0.2 mandates — implemented on
 * node:crypto ONLY (zero new runtime dependencies), per ap2-adapter-spec
 * §3.2/§3.3 and the §8 downgrade/malformation matrix (A-19/A-20/A-24/
 * A-25/A-26). This code runs over ATTACKER-SUPPLIED input in its own
 * process (the spec's strongest argument for process separation).
 *
 * Pinned, never negotiated:
 *   - JWS alg: ES256 exactly. `none`, HS*, RS*, unknown -> refuse. The
 *     alg is matched BEFORE any key material is touched, so algorithm
 *     confusion (symmetric alg with a public key as MAC secret) is
 *     structurally unreachable.
 *   - _sd_alg: "sha-256" exactly, and REQUIRED — absence refuses for
 *     inbound mandates (no "SHA-256 if absent" default; A-19).
 *   - Trust anchors: operator-PINNED JWKs by kid
 *     (config.trustAnchors[kid] = { jwk, role }). Header `kid` is a
 *     lookup key into pinned config ONLY; embedded `jwk`/`jku`/`x5u`/
 *     `x5c` header key material is refused outright (A-20 key
 *     injection). Unconfigured anchors fail closed
 *     (AP2_TRUST_ANCHOR_UNCONFIGURED) — the structural validation and
 *     pinned-alg refusals still run first, so downgrade probes get their
 *     precise refusal even on an unconfigured deployment.
 *
 * Key binding: REQUIRED. The presentation must end in a KB-JWT whose
 *   - alg is ES256 (pinned), typ is "kb+jwt",
 *   - sd_hash equals b64url(sha-256(<presentation up to and including
 *     the final '~'>)),
 *   - signature verifies under the ISSUER-SIGNED payload's cnf.jwk.
 * A partial or absent binding refuses (AP2_KEY_BINDING_INVALID).
 *
 * A verification PASS proves AUTHORSHIP, never authorization: a valid
 * user signature over "up to 500 KAS to anyone" grants the agent exactly
 * zero additional PolicyVault authority — the covenant's caps, budgets,
 * allowlists and approval tiers are enforced by Kaspa consensus and no
 * off-chain credential can raise any of them.
 */

const crypto = require("node:crypto");
const { parseStrictJson, decodeBase64UrlStrict, utf8TextOf, GuardError, PLAIN_INT_RE } = require("../lib/json-guard");
const { Ap2Refusal } = require("./codes");

const PINNED_ALG = "ES256";
const PINNED_SD_ALG = "sha-256";
const FORBIDDEN_HEADER_KEYS = Object.freeze(["jwk", "jku", "x5u", "x5c", "x5t", "x5t#S256"]);
const HEADER_ALLOWED = Object.freeze(new Set(["alg", "kid", "typ"]));
const KB_PAYLOAD_ALLOWED = Object.freeze(new Set(["iat", "aud", "nonce", "sd_hash"]));
const FORBIDDEN_CLAIM_NAMES = Object.freeze(new Set(["__proto__", "constructor", "prototype", "_sd", "..."]));

const CAPS = Object.freeze({
  compactBytes: 65536, // per-mandate cap (spec-recommended 64 KiB), applied to ENCODED bytes first
  jsonDepth: 8,
  maxDisclosures: 64
});

function refuse(code, detail) {
  throw new Ap2Refusal(code, detail);
}

function b64urlSha256(text) {
  return crypto.createHash("sha256").update(text, "utf8").digest("base64url");
}

function decodeJsonPart(b64, { code, tolerate }) {
  let text;
  try {
    text = utf8TextOf(decodeBase64UrlStrict(b64, { maxEncodedBytes: CAPS.compactBytes }), code);
  } catch (error) {
    if (error instanceof GuardError) refuse(code, error.message);
    throw error;
  }
  try {
    return parseStrictJson(text, { maxBytes: CAPS.compactBytes, maxDepth: CAPS.jsonDepth, tolerateNonIntegerNumbers: tolerate === true });
  } catch (error) {
    if (error instanceof GuardError) refuse(code, `${error.code}: ${error.message}`);
    throw error;
  }
}

function importPinnedJwk(jwk, where) {
  if (!jwk || typeof jwk !== "object" || jwk.kty !== "EC" || jwk.crv !== "P-256" || typeof jwk.x !== "string" || typeof jwk.y !== "string") {
    refuse("AP2_TRUST_ANCHOR_UNKNOWN", `${where}: pinned anchors must be EC P-256 public JWKs`);
  }
  try {
    return crypto.createPublicKey({ key: { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y }, format: "jwk" });
  } catch (error) {
    refuse("AP2_TRUST_ANCHOR_UNKNOWN", `${where}: pinned JWK rejected by node:crypto (${error.message})`);
  }
}

/* Verify one compact JWS (header.payload.signature) under a resolved
 * public key. The alg gate runs FIRST and is pinned. */
function verifyJwsStructure(compact, { code }) {
  if (typeof compact !== "string" || compact.length === 0) refuse(code, "JWS must be a non-empty string");
  const parts = compact.split(".");
  if (parts.length !== 3) refuse(code, "JWS must have exactly three dot-separated segments");
  const [h, p, s] = parts;
  const header = decodeJsonPart(h, { code }).value;
  if (!header || typeof header !== "object" || Array.isArray(header)) refuse(code, "JWS header must be an object");
  for (const k of FORBIDDEN_HEADER_KEYS) {
    if (k in header) refuse("AP2_ALG_UNSUPPORTED", `embedded ${k} header key material is never trusted (key-injection refusal)`);
  }
  for (const k of Object.keys(header)) {
    if (!HEADER_ALLOWED.has(k)) refuse(code, `unknown JWS header parameter ${JSON.stringify(k)} — closed header schema`);
  }
  if (header.alg !== PINNED_ALG) {
    refuse("AP2_ALG_UNSUPPORTED", `alg ${JSON.stringify(header.alg ?? null)} — pinned allow-list is [${PINNED_ALG}]`);
  }
  let signature;
  try {
    signature = decodeBase64UrlStrict(s, { maxEncodedBytes: 512 });
  } catch (error) {
    if (error instanceof GuardError) refuse("AP2_SIGNATURE_INVALID", "signature segment is not base64url");
    throw error;
  }
  if (signature.length !== 64) refuse("AP2_SIGNATURE_INVALID", "ES256 signatures are exactly 64 bytes (r||s)");
  return { header, payloadB64: p, signingInput: `${h}.${p}`, signature };
}

function verifyJwsSignature({ signingInput, signature }, publicKey) {
  const ok = crypto.verify("sha256", Buffer.from(signingInput, "utf8"), { key: publicKey, dsaEncoding: "ieee-p1363" }, signature);
  if (!ok) refuse("AP2_SIGNATURE_INVALID", "signature verification failed under the pinned trust anchor");
}

/* One disclosure: base64url(JSON [salt, name, value] | [salt, value]).
 * Returns { digest, kind, name?, value }. */
function parseDisclosure(encoded, index) {
  const { value } = decodeJsonPart(encoded, { code: "AP2_DISCLOSURE_INVALID", tolerate: true });
  if (!Array.isArray(value) || (value.length !== 2 && value.length !== 3)) {
    refuse("AP2_DISCLOSURE_INVALID", `disclosure[${index}] must be a 2- or 3-element array`);
  }
  if (typeof value[0] !== "string" || value[0].length === 0) refuse("AP2_DISCLOSURE_INVALID", `disclosure[${index}] salt must be a non-empty string`);
  if (value.length === 3) {
    const name = value[1];
    if (typeof name !== "string" || FORBIDDEN_CLAIM_NAMES.has(name)) refuse("AP2_DISCLOSURE_INVALID", `disclosure[${index}] claim name is forbidden or not a string`);
    return { digest: b64urlSha256(encoded), kind: "property", name, value: value[2] };
  }
  return { digest: b64urlSha256(encoded), kind: "array", value: value[1] };
}

/*
 * SD-JWT reassembly: replace _sd digests / {"...": digest} placeholders
 * with disclosed values, recursively (including inside inserted values).
 * Every provided disclosure MUST be consumed exactly once; a duplicate,
 * unreferenced, or colliding disclosure refuses (A-25). Undisclosed
 * digests are DROPPED from the claims and counted — the no-silent-absence
 * rule is enforced later on the reassembled claims by the normalizer.
 */
function reassemble(payload, disclosures) {
  const byDigest = new Map();
  for (const d of disclosures) {
    if (byDigest.has(d.digest)) refuse("AP2_DISCLOSURE_INVALID", "duplicate disclosure (digest collision) — refusing");
    byDigest.set(d.digest, d);
  }
  const used = new Set();
  let undisclosedCount = 0;

  function walk(node, depth) {
    if (depth > CAPS.jsonDepth * 2) refuse("AP2_ENVELOPE_INVALID", "reassembled claims exceed the depth cap");
    if (Array.isArray(node)) {
      const out = [];
      for (const element of node) {
        if (element && typeof element === "object" && !Array.isArray(element) && Object.keys(element).length === 1 && typeof element["..."] === "string") {
          const d = byDigest.get(element["..."]);
          if (!d) {
            undisclosedCount += 1;
            continue; // withheld array element: dropped, counted
          }
          if (d.kind !== "array") refuse("AP2_DISCLOSURE_INVALID", "property disclosure referenced from an array placeholder");
          if (used.has(d.digest)) refuse("AP2_DISCLOSURE_INVALID", "disclosure referenced twice");
          used.add(d.digest);
          out.push(walk(d.value, depth + 1));
          continue;
        }
        out.push(walk(element, depth + 1));
      }
      return out;
    }
    if (node && typeof node === "object") {
      const out = {};
      for (const [k, v] of Object.entries(node)) {
        if (k === "_sd") continue;
        if (k === "...") refuse("AP2_DISCLOSURE_INVALID", "stray array-disclosure placeholder key");
        out[k] = walk(v, depth + 1);
      }
      if (Array.isArray(node._sd)) {
        for (const digest of node._sd) {
          if (typeof digest !== "string") refuse("AP2_DISCLOSURE_INVALID", "_sd entries must be digest strings");
          const d = byDigest.get(digest);
          if (!d) {
            undisclosedCount += 1;
            continue; // withheld property: dropped, counted
          }
          if (d.kind !== "property") refuse("AP2_DISCLOSURE_INVALID", "array disclosure referenced from an _sd digest");
          if (used.has(d.digest)) refuse("AP2_DISCLOSURE_INVALID", "disclosure referenced twice");
          used.add(d.digest);
          if (d.name in out) refuse("AP2_DISCLOSURE_INVALID", `disclosed claim ${JSON.stringify(d.name)} collides with an existing claim`);
          out[d.name] = walk(d.value, depth + 1);
        }
      } else if (node._sd !== undefined) {
        refuse("AP2_DISCLOSURE_INVALID", "_sd must be an array of digest strings");
      }
      return out;
    }
    return node;
  }

  const claims = walk(payload, 1);
  for (const d of disclosures) {
    if (!used.has(d.digest)) refuse("AP2_DISCLOSURE_INVALID", "a provided disclosure is not referenced by any _sd digest — refusing");
  }
  return { claims, undisclosedCount, disclosedNames: disclosures.filter((d) => used.has(d.digest) && d.kind === "property").map((d) => d.name) };
}

/*
 * Verify one compact SD-JWT presentation:
 *   <issuer-jws>~<disclosure>*~<kb-jws>
 * against pinned trust anchors. Returns
 *   { claims, header, kid, role, verification, raw }
 * where `claims` is the reassembled, _sd/_sd_alg-free claim set and
 * `verification` is the evidence block for the audit record (never
 * authority). expectedNonce, when supplied by the caller, must equal the
 * KB-JWT nonce.
 */
function verifySdJwtMandate(compact, { trustAnchors, nowSeconds, clockSkewSeconds = 120, expectedNonce } = {}) {
  if (typeof compact !== "string") refuse("AP2_ENVELOPE_INVALID", "mandate must be a compact SD-JWT string");
  if (Buffer.byteLength(compact, "utf8") > CAPS.compactBytes) {
    refuse("AP2_ENVELOPE_INVALID", `mandate exceeds ${CAPS.compactBytes} bytes — refused before parsing`);
  }
  if (!/^[A-Za-z0-9_.~-]+$/.test(compact)) refuse("AP2_ENVELOPE_INVALID", "mandate contains characters outside the compact SD-JWT alphabet");

  const segments = compact.split("~");
  if (segments.length < 2) refuse("AP2_ENVELOPE_INVALID", "compact SD-JWT must end in '~<kb-jwt>' (or '~' plus a KB-JWT) — key binding is required");
  const issuerJws = segments[0];
  const kbJws = segments[segments.length - 1];
  const disclosureSegments = segments.slice(1, -1);
  if (disclosureSegments.length > CAPS.maxDisclosures) {
    refuse("AP2_ENVELOPE_INVALID", `presentation carries ${disclosureSegments.length} disclosures (cap ${CAPS.maxDisclosures})`);
  }
  if (disclosureSegments.some((d) => d.length === 0)) refuse("AP2_ENVELOPE_INVALID", "empty disclosure segment");

  // ---- issuer-signed JWS: structure + pinned alg FIRST ---------------
  const jws = verifyJwsStructure(issuerJws, { code: "AP2_ENVELOPE_INVALID" });
  if (typeof jws.header.kid !== "string" || !jws.header.kid) refuse("AP2_TRUST_ANCHOR_UNKNOWN", "JWS header must carry a kid resolving to a pinned trust anchor");

  // ---- pinned trust anchor resolution (fail closed when unconfigured) -
  if (!trustAnchors || typeof trustAnchors !== "object" || Object.keys(trustAnchors).length === 0) {
    refuse("AP2_TRUST_ANCHOR_UNCONFIGURED");
  }
  const anchor = trustAnchors[jws.header.kid];
  if (!anchor) refuse("AP2_TRUST_ANCHOR_UNKNOWN", `kid ${JSON.stringify(jws.header.kid)} is not pinned`);
  const issuerKey = importPinnedJwk(anchor.jwk, `trustAnchors[${jws.header.kid}]`);
  verifyJwsSignature(jws, issuerKey);

  // ---- payload ------------------------------------------------------
  const payload = decodeJsonPart(jws.payloadB64, { code: "AP2_ENVELOPE_INVALID", tolerate: true }).value;
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) refuse("AP2_ENVELOPE_INVALID", "JWS payload must be an object");

  // _sd_alg: REQUIRED, pinned (absence refuses — A-19).
  if (payload._sd_alg !== PINNED_SD_ALG) {
    refuse("AP2_SD_ALG_UNSUPPORTED", `_sd_alg ${JSON.stringify(payload._sd_alg ?? null)} — pinned to ${PINNED_SD_ALG}, absence refuses`);
  }

  // ---- disclosures + reassembly -------------------------------------
  const disclosures = disclosureSegments.map((d, idx) => parseDisclosure(d, idx));
  const { claims, undisclosedCount, disclosedNames } = reassemble(payload, disclosures);
  delete claims._sd_alg;

  // ---- exp / iat (integers, lexically checked upstream by the strict
  // parser; used only for the adapter's own deadline — never lockTime) --
  const now = Number.isSafeInteger(nowSeconds) ? nowSeconds : Math.floor(Date.now() / 1000);
  if (claims.exp !== undefined) {
    if (!Number.isSafeInteger(claims.exp)) refuse("AP2_MANDATE_EXPIRED", "exp must be an integer epoch");
    if (claims.exp <= now) refuse("AP2_MANDATE_EXPIRED", "mandate exp is in the past");
  }
  if (claims.iat !== undefined) {
    if (!Number.isSafeInteger(claims.iat)) refuse("AP2_MANDATE_EXPIRED", "iat must be an integer epoch");
    if (claims.iat > now + clockSkewSeconds) refuse("AP2_MANDATE_EXPIRED", "iat is in the future beyond the allowed skew");
  }

  // ---- key binding: REQUIRED (partial or absent refuses) --------------
  if (!kbJws) refuse("AP2_KEY_BINDING_INVALID", "KB-JWT is absent");
  const cnf = claims.cnf;
  if (!cnf || typeof cnf !== "object" || Array.isArray(cnf) || !cnf.jwk) {
    refuse("AP2_KEY_BINDING_INVALID", "issuer-signed payload carries no cnf.jwk to bind the holder");
  }
  const kb = verifyJwsStructure(kbJws, { code: "AP2_KEY_BINDING_INVALID" });
  if (kb.header.typ !== "kb+jwt") refuse("AP2_KEY_BINDING_INVALID", "KB-JWT typ must be kb+jwt");
  const holderKey = (() => {
    const jwk = cnf.jwk;
    if (!jwk || typeof jwk !== "object" || jwk.kty !== "EC" || jwk.crv !== "P-256" || typeof jwk.x !== "string" || typeof jwk.y !== "string") {
      refuse("AP2_KEY_BINDING_INVALID", "cnf.jwk must be an EC P-256 public JWK");
    }
    try {
      return crypto.createPublicKey({ key: { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y }, format: "jwk" });
    } catch (error) {
      refuse("AP2_KEY_BINDING_INVALID", `cnf.jwk rejected by node:crypto (${error.message})`);
    }
  })();
  verifyJwsSignature(kb, holderKey);
  const kbPayload = decodeJsonPart(kb.payloadB64, { code: "AP2_KEY_BINDING_INVALID", tolerate: true }).value;
  if (!kbPayload || typeof kbPayload !== "object" || Array.isArray(kbPayload)) refuse("AP2_KEY_BINDING_INVALID", "KB-JWT payload must be an object");
  for (const k of Object.keys(kbPayload)) {
    if (!KB_PAYLOAD_ALLOWED.has(k)) refuse("AP2_KEY_BINDING_INVALID", `unknown KB-JWT claim ${JSON.stringify(k)}`);
  }
  const presentationPrefix = compact.slice(0, compact.length - kbJws.length); // includes the final '~'
  const expectedSdHash = b64urlSha256(presentationPrefix);
  if (kbPayload.sd_hash !== expectedSdHash) refuse("AP2_KEY_BINDING_INVALID", "sd_hash does not bind this exact presentation");
  if (expectedNonce !== undefined && kbPayload.nonce !== expectedNonce) refuse("AP2_KEY_BINDING_INVALID", "KB-JWT nonce does not match the expected nonce");
  delete claims.cnf;

  return {
    claims,
    header: jws.header,
    kid: jws.header.kid,
    role: typeof anchor.role === "string" ? anchor.role : null,
    verification: {
      alg: jws.header.alg,
      sdAlg: PINNED_SD_ALG,
      kid: jws.header.kid,
      signatureValid: true,
      keyBindingValid: true,
      disclosuresPresented: disclosedNames,
      undisclosedCount,
      expiresAt: Number.isSafeInteger(claims.exp) ? claims.exp : null
    },
    raw: compact
  };
}

module.exports = { CAPS, PINNED_ALG, PINNED_SD_ALG, verifySdJwtMandate, b64urlSha256, PLAIN_INT_RE };
