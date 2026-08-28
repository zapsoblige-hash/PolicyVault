"use strict";

/*
 * Shared test fixtures for the integrations suites (UNIT + INTEGRATION
 * layers; docs/test-plan.md labeling discipline). Tests may import repo
 * modules freely — the dependency-direction rules govern the ADAPTER
 * RUNTIME (integrations/{lib,x402,ap2}), not the test harness.
 */

const crypto = require("node:crypto");
const path = require("node:path");
const os = require("node:os");
const fs = require("node:fs");

const REPO_ROOT = path.join(__dirname, "..", "..", "..");
const DEFAULT_KASPA_WASM = path.join(os.homedir(), "rusty-kaspa/wasm/nodejs/kaspa");

function tmpdir(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

/* ---------------- Kaspa key/address helpers (wasm) ------------------- */

let kaspaModule = null;
function kaspa() {
  if (!kaspaModule) kaspaModule = require(DEFAULT_KASPA_WASM);
  return kaspaModule;
}
function KEY(v) {
  return new (kaspa().PrivateKey)(v.toString(16).padStart(2, "0").repeat(32));
}
function XO(priv) {
  return priv.toPublicKey().toXOnlyPublicKey().toString().toLowerCase();
}
function ADDR(priv, networkId = "testnet-10") {
  return priv.toPublicKey().toAddress(networkId).toString();
}

/* ---------------- x402 fixtures -------------------------------------- */

const X402_TEST_ASSET = "KAS";
const X402_TEST_NETWORK = "kaspa:testnet-10";

function paymentRequiredDoc(overrides = {}) {
  const base = {
    x402Version: 2,
    resource: { url: "https://api.example.test/data", description: "test resource", mimeType: "application/json" },
    accepts: [
      {
        scheme: "exact",
        network: X402_TEST_NETWORK,
        amount: "100000000", // 1 KAS in sompi
        asset: X402_TEST_ASSET,
        payTo: null, // caller must set a real address
        maxTimeoutSeconds: 600,
        extra: { paymentFlow: "upfront" }
      }
    ]
  };
  return { ...base, ...overrides };
}

function encodePaymentRequired(doc) {
  return Buffer.from(JSON.stringify(doc), "utf8").toString("base64");
}

/* ---------------- AP2 SD-JWT fixtures -------------------------------- */

function b64u(value) {
  return Buffer.from(typeof value === "string" ? value : JSON.stringify(value)).toString("base64url");
}
function b64uSha256(text) {
  return crypto.createHash("sha256").update(text, "utf8").digest("base64url");
}
function ecKeyPair() {
  const pair = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  const jwk = pair.publicKey.export({ format: "jwk" });
  return { ...pair, jwk: { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y } };
}
function signJws(header, payload, privateKey) {
  const input = `${b64u(header)}.${b64u(payload)}`;
  const sig = crypto.sign("sha256", Buffer.from(input), { key: privateKey, dsaEncoding: "ieee-p1363" });
  return `${input}.${sig.toString("base64url")}`;
}

/*
 * Build a compact SD-JWT presentation:
 *   claims: the payload claims (non-SD),
 *   sdProperties: { name: value } made selectively disclosable,
 *   sdArrayItems: { claimName: [values...] } array with each element disclosable,
 *   withhold: [names] disclosures generated but NOT presented,
 *   issuer/holder: ec key pairs; kid; extraHeader; omitKb; sdAlg (default sha-256; null omits).
 */
function buildSdJwt({
  claims,
  sdProperties = {},
  sdArrayItems = {},
  withhold = [],
  issuer,
  holder,
  kid,
  extraHeader = {},
  omitKb = false,
  sdAlg = "sha-256",
  kbNonce = "test-nonce",
  tamperSdHash = false
}) {
  const payload = { ...claims };
  if (sdAlg !== null) payload._sd_alg = sdAlg;
  const disclosures = [];
  const sdDigests = [];
  for (const [name, value] of Object.entries(sdProperties)) {
    const disclosure = b64u(JSON.stringify([`salt-${name}`, name, value]));
    sdDigests.push(b64uSha256(disclosure));
    if (!withhold.includes(name)) disclosures.push(disclosure);
  }
  if (sdDigests.length > 0) payload._sd = sdDigests;
  for (const [claimName, items] of Object.entries(sdArrayItems)) {
    const placeholders = [];
    items.forEach((value, i) => {
      const disclosure = b64u(JSON.stringify([`salt-${claimName}-${i}`, value]));
      placeholders.push({ "...": b64uSha256(disclosure) });
      if (!withhold.includes(`${claimName}[${i}]`)) disclosures.push(disclosure);
    });
    payload[claimName] = placeholders;
  }
  if (holder && !payload.cnf) payload.cnf = { jwk: holder.jwk };
  const jws = signJws({ alg: "ES256", kid, ...extraHeader }, payload, issuer.privateKey);
  const prefix = [jws, ...disclosures].join("~") + "~";
  if (omitKb) return prefix; // ends with '~': no KB-JWT presented
  const sdHash = tamperSdHash ? b64uSha256(prefix + "x") : b64uSha256(prefix);
  const kb = signJws({ alg: "ES256", kid: "holder", typ: "kb+jwt" }, { iat: Math.floor(Date.now() / 1000), nonce: kbNonce, sd_hash: sdHash }, holder.privateKey);
  return prefix + kb;
}

/* A ready-made closed Payment Mandate + matching checkout material. */
function buildPaymentMandateSet({ issuer, holder, kid, amount = 100000000, currency = "KAS", payeeId = "merchant-1", instrumentId = "instr-1", instrumentType = "org.policy-vault.kaspa.covenant-vault.v1", expSeconds = 600, claimsOverride = {}, checkoutJwt = "eyJmYWtlIjoiY2hlY2tvdXQifQ" }) {
  const transactionId = b64uSha256(checkoutJwt);
  const claims = {
    vct: "mandate.payment.1",
    transaction_id: transactionId,
    payee: { id: payeeId, name: "Merchant One", website: "https://merchant.example" },
    payment_amount: { amount, currency },
    payment_instrument: { id: instrumentId, type: instrumentType },
    exp: Math.floor(Date.now() / 1000) + expSeconds,
    ...claimsOverride
  };
  const paymentMandate = buildSdJwt({ claims, issuer, holder, kid });
  const checkoutClaims = {
    vct: "mandate.checkout.1",
    checkout_jwt: checkoutJwt,
    checkout_hash: b64uSha256(checkoutJwt),
    exp: Math.floor(Date.now() / 1000) + expSeconds
  };
  const checkoutMandate = buildSdJwt({ claims: checkoutClaims, issuer, holder, kid });
  return { paymentMandate, checkoutMandate, transactionId, claims };
}

module.exports = {
  REPO_ROOT,
  DEFAULT_KASPA_WASM,
  tmpdir,
  kaspa,
  KEY,
  XO,
  ADDR,
  X402_TEST_ASSET,
  X402_TEST_NETWORK,
  paymentRequiredDoc,
  encodePaymentRequired,
  b64u,
  b64uSha256,
  ecKeyPair,
  signJws,
  buildSdJwt,
  buildPaymentMandateSet
};
