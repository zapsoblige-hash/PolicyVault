"use strict";

/*
 * Closed-schema intake of the facilitator wire objects (spec §2, §17).
 * Every byte is UNTRUSTED. Unknown field, wrong type, non-canonical
 * number, or any situation this parser is unsure about → SCHEMA_INVALID
 * (or the more specific closed code named in the spec). Nothing here
 * touches the node or a store.
 */

const { parseStrictJson, GuardError } = require("../lib/json-guard");
const { canonicalJsonStringify, domainDigestHex } = require("../lib/canonical");
const { requireCanonicalSompiString, AmountError } = require("../lib/amounts-gate");
const { assertLiteralAddressForm, AddressError } = require("../lib/address");
const { parseAtomicAmount: parseTokenAmount } = require("../../core/model/token-amounts");
const { X402_VERSION, SCHEME, PAYMENT_FLOW, KASPA_SCHEME_ID, REQUIREMENT_DIGEST_DOMAIN, ASSET_KAS } = require("./constants");
const { refuse, FacilitatorRefusal } = require("./codes");
const { requireBoundNetwork } = require("./network");
const { parseDaaString, validateWindow, resolveSettlementPolicy } = require("./policy");

const CAPS = Object.freeze({
  bodyBytes: 1024 * 1024, // transaction carriage for token payments is large (redeems ≈ 1.5 KB each, hex-of-JSON)
  depth: 8,
  resourceUrlBytes: 2048,
  descriptionBytes: 1024,
  mimeTypeBytes: 255,
  payerBytes: 256,
  transactionHexBytes: 768 * 1024,
  redeemHexBytes: 64 * 1024,
  maxRedeems: 64,
  maxOutputIndex: 100000,
  timeoutCeilingSeconds: 3600
});

const BODY_KEYS = new Set(["x402Version", "paymentPayload", "paymentRequirements"]);
const REQ_KEYS = new Set(["scheme", "network", "amount", "asset", "payTo", "maxTimeoutSeconds", "extra"]);
const EXTRA_KEYS = new Set(["paymentFlow", "kaspaScheme", "settlementPolicy", "requirementId", "resourceUrl", "validFromDaaScore", "validUntilDaaScore"]);
const PAYLOAD_KEYS = new Set(["x402Version", "resource", "accepted", "payload"]);
const RESOURCE_KEYS = new Set(["url", "description", "mimeType"]);
const INNER_KEYS = new Set(["transactionId", "outputIndex", "payer", "transactionHex", "outputRedeems"]);

const HEX64_RE = /^[0-9a-f]{64}$/;
const HEX_EVEN_RE = /^(?:[0-9a-f]{2})*$/;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const INDEX_KEY_RE = /^(0|[1-9][0-9]*)$/;

function isPlainObject(v) {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function assertClosed(obj, allowed, where) {
  if (!isPlainObject(obj)) refuse("SCHEMA_INVALID", `${where} must be an object`);
  for (const key of Object.keys(obj)) {
    if (!allowed.has(key)) refuse("SCHEMA_INVALID", `unknown field ${JSON.stringify(key)} at ${where}`);
  }
}

function requireString(v, where, maxBytes) {
  if (typeof v !== "string" || v.length === 0) refuse("SCHEMA_INVALID", `${where} must be a non-empty string`);
  if (maxBytes !== undefined && Buffer.byteLength(v, "utf8") > maxBytes) refuse("SCHEMA_INVALID", `${where} exceeds ${maxBytes} bytes`);
  return v;
}

function requirePlainInteger(v, tokens, path, where, { min, max }) {
  const token = tokens.get(path);
  if (typeof v !== "number" || !Number.isSafeInteger(v) || typeof token !== "string" || !/^(0|[1-9][0-9]*)$/.test(token) || String(v) !== token) {
    refuse("SCHEMA_INVALID", `${where} must be a plain non-negative integer`);
  }
  if (v < min || v > max) refuse("SCHEMA_INVALID", `${where} must be within ${min}..${max}`);
  return v;
}

function parseResourceUrl(value, where) {
  const text = requireString(value, where, CAPS.resourceUrlBytes);
  let url;
  try {
    url = new URL(text);
  } catch {
    refuse("SCHEMA_INVALID", `${where} is not an absolute URL`);
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") refuse("SCHEMA_INVALID", `${where} must be http(s)`);
  if (url.username || url.password) refuse("SCHEMA_INVALID", `${where} must not carry credentials`);
  return { text, origin: url.origin };
}

/*
 * Parse ONE PaymentRequirements object (already a plain tree from the
 * strict parser). `numberTokens` + `path` re-check every number's lexical
 * token. `bound` is the deployment network; `assets` resolves asset
 * literals. Returns the normalized requirement + its binding digest.
 */
function parseRequirements(raw, { numberTokens, path, bound, assets, minDepthDaa, config, addressGate }) {
  assertClosed(raw, REQ_KEYS, path);
  for (const k of REQ_KEYS) if (raw[k] === undefined) refuse("SCHEMA_INVALID", `${path}.${k} is required`);
  if (raw.scheme !== SCHEME) refuse("SCHEME_UNSUPPORTED", `scheme ${JSON.stringify(String(raw.scheme).slice(0, 32))}`);
  if (typeof raw.network !== "string") refuse("SCHEMA_INVALID", `${path}.network must be a string`);
  requireBoundNetwork(bound, raw.network); // byte-exact; "" and look-alikes → NETWORK_MISMATCH
  assertClosed(raw.extra, EXTRA_KEYS, `${path}.extra`);
  for (const k of EXTRA_KEYS) if (raw.extra[k] === undefined) refuse("SCHEMA_INVALID", `${path}.extra.${k} is required`);
  if (raw.extra.paymentFlow !== PAYMENT_FLOW) refuse("FLOW_UNSUPPORTED");
  if (raw.extra.kaspaScheme !== KASPA_SCHEME_ID) refuse("SCHEME_UNSUPPORTED", `kaspaScheme ${JSON.stringify(String(raw.extra.kaspaScheme).slice(0, 64))}`);
  const policy = resolveSettlementPolicy(raw.extra.settlementPolicy, { minDepthDaa });

  requireString(raw.asset, `${path}.asset`, 128);
  const asset = assets.resolve(raw.asset); // ASSET_UNSUPPORTED on anything unknown

  // amount: canonical decimal integer string, atomic units, > 0, within the asset's bound
  if (typeof raw.amount !== "string") refuse("AMOUNT_INVALID", "amount must be a JSON string");
  let amount;
  if (asset.kind === ASSET_KAS) {
    try {
      amount = BigInt(requireCanonicalSompiString(raw.amount, { code: "AMOUNT_INVALID", field: "amount" }));
    } catch (e) {
      if (e instanceof AmountError) refuse("AMOUNT_INVALID", e.message);
      throw e;
    }
  } else {
    try {
      amount = parseTokenAmount(raw.amount, "amount");
    } catch (e) {
      refuse("AMOUNT_INVALID", e.message);
    }
    if (amount <= 0n) refuse("AMOUNT_INVALID", "amount must be > 0");
  }

  // payTo: literal-form pre-gate (bound network prefix, charset, case) then the authoritative decode
  requireString(raw.payTo, `${path}.payTo`, 256);
  try {
    assertLiteralAddressForm(raw.payTo, bound.kaspadNetworkId, { notLiteralCode: "ADDRESS_INVALID", invalidCode: "ADDRESS_INVALID" });
  } catch (e) {
    if (e instanceof AddressError) refuse("ADDRESS_INVALID", e.message);
    throw e;
  }
  const destination = addressGate(raw.payTo); // { address, prefix, addressVersion, scriptHex } — throws ADDRESS_INVALID
  if (destination.address !== raw.payTo) refuse("ADDRESS_INVALID", "payTo is not in canonical form");
  if (asset.kind !== ASSET_KAS && destination.addressVersion !== "PubKey" && destination.addressVersion !== "ScriptHash") {
    refuse("ADDRESS_INVALID", `a ${destination.addressVersion} address has no kcc20-state/1 owner encoding`);
  }

  const maxTimeoutSeconds = requirePlainInteger(raw.maxTimeoutSeconds, numberTokens, `${path}.maxTimeoutSeconds`, `${path}.maxTimeoutSeconds`, { min: 1, max: CAPS.timeoutCeilingSeconds });

  requireString(raw.extra.requirementId, `${path}.extra.requirementId`, 128);
  if (!UUID_RE.test(raw.extra.requirementId) && !HEX64_RE.test(raw.extra.requirementId)) refuse("SCHEMA_INVALID", "extra.requirementId must be a lowercase UUID or 64 lowercase hex characters");
  const resource = parseResourceUrl(raw.extra.resourceUrl, `${path}.extra.resourceUrl`);
  const validFrom = parseDaaString(raw.extra.validFromDaaScore, "extra.validFromDaaScore", "REQUIREMENT_WINDOW_INVALID");
  const validUntil = parseDaaString(raw.extra.validUntilDaaScore, "extra.validUntilDaaScore", "REQUIREMENT_WINDOW_INVALID");
  validateWindow(validFrom, validUntil);

  const digest = domainDigestHex(REQUIREMENT_DIGEST_DOMAIN, raw);
  return Object.freeze({
    raw,
    canonical: canonicalJsonStringify(raw),
    requirementDigest: digest,
    scheme: SCHEME,
    network: bound.identifier,
    amount,
    amountString: raw.amount,
    asset,
    assetLiteral: raw.asset,
    payTo: destination.address,
    destination,
    maxTimeoutSeconds,
    policy,
    requirementId: raw.extra.requirementId,
    resourceUrl: resource.text,
    resourceOrigin: resource.origin,
    validFrom,
    validUntil
  });
}

/* PaymentPayload (spec §2.3). `requirements` is the already-parsed
 * PaymentRequirements the resource server presented alongside. */
function parsePayload(raw, { numberTokens, path, requirements }) {
  assertClosed(raw, PAYLOAD_KEYS, path);
  if (raw.x402Version !== X402_VERSION) refuse("VERSION_UNSUPPORTED", `paymentPayload.x402Version ${JSON.stringify(raw.x402Version)}`);
  if (raw.accepted === undefined) refuse("SCHEMA_INVALID", `${path}.accepted is required`);
  if (!isPlainObject(raw.accepted)) refuse("SCHEMA_INVALID", `${path}.accepted must be an object`);
  if (canonicalJsonStringify(raw.accepted) !== requirements.canonical) refuse("REQUIREMENTS_MISMATCH");
  if (raw.resource !== undefined) {
    assertClosed(raw.resource, RESOURCE_KEYS, `${path}.resource`);
    const url = parseResourceUrl(raw.resource.url, `${path}.resource.url`);
    if (url.text !== requirements.resourceUrl) refuse("REQUIREMENTS_MISMATCH", "resource.url differs from extra.resourceUrl");
    if (raw.resource.description !== undefined) requireString(raw.resource.description, `${path}.resource.description`, CAPS.descriptionBytes);
    if (raw.resource.mimeType !== undefined) requireString(raw.resource.mimeType, `${path}.resource.mimeType`, CAPS.mimeTypeBytes);
  }
  const inner = raw.payload;
  assertClosed(inner, INNER_KEYS, `${path}.payload`);
  if (typeof inner.transactionId !== "string" || !HEX64_RE.test(inner.transactionId)) refuse("SCHEMA_INVALID", "payload.transactionId must be 64 lowercase hex characters");
  const outputIndex = requirePlainInteger(inner.outputIndex, numberTokens, `${path}.payload.outputIndex`, "payload.outputIndex", { min: 0, max: CAPS.maxOutputIndex });
  let payer = null;
  if (inner.payer !== undefined) payer = requireString(inner.payer, "payload.payer", CAPS.payerBytes);
  let transactionHex = null;
  if (inner.transactionHex !== undefined) {
    transactionHex = requireString(inner.transactionHex, "payload.transactionHex", CAPS.transactionHexBytes);
    if (!HEX_EVEN_RE.test(transactionHex)) refuse("SCHEMA_INVALID", "payload.transactionHex must be lowercase even-length hex");
  }
  let outputRedeems = null;
  if (inner.outputRedeems !== undefined) {
    if (!isPlainObject(inner.outputRedeems)) refuse("SCHEMA_INVALID", "payload.outputRedeems must be an object");
    const entries = Object.entries(inner.outputRedeems);
    if (entries.length > CAPS.maxRedeems) refuse("SCHEMA_INVALID", `payload.outputRedeems carries more than ${CAPS.maxRedeems} entries`);
    outputRedeems = new Map();
    for (const [k, v] of entries) {
      if (!INDEX_KEY_RE.test(k) || Number(k) > CAPS.maxOutputIndex) refuse("SCHEMA_INVALID", `payload.outputRedeems key ${JSON.stringify(k.slice(0, 16))} is not a decimal output index`);
      if (typeof v !== "string" || v.length === 0 || v.length > CAPS.redeemHexBytes || !HEX_EVEN_RE.test(v)) refuse("SCHEMA_INVALID", `payload.outputRedeems[${k}] must be lowercase even-length hex`);
      outputRedeems.set(Number(k), v);
    }
  }
  return Object.freeze({ transactionId: inner.transactionId, outputIndex, payer, transactionHex, outputRedeems });
}

/*
 * Whole facilitator request body for /verify and /settle:
 *   { x402Version: 2, paymentPayload, paymentRequirements }
 */
function parseFacilitatorRequest(text, deps) {
  let parsed;
  try {
    parsed = parseStrictJson(text, { maxBytes: CAPS.bodyBytes, maxDepth: CAPS.depth, maxStringBytes: CAPS.transactionHexBytes });
  } catch (e) {
    if (e instanceof GuardError) {
      const r = new FacilitatorRefusal(e.code === "JSON_TOO_LARGE" ? "BODY_TOO_LARGE" : "SCHEMA_INVALID", e.message);
      r.unparseable = true; // §17.7: an unparseable body is 400, a parseable-but-invalid one is a 200 judgement
      throw r;
    }
    throw e;
  }
  const body = parsed.value;
  assertClosed(body, BODY_KEYS, "$");
  if (body.x402Version !== X402_VERSION) refuse("VERSION_UNSUPPORTED", `x402Version ${JSON.stringify(body.x402Version)}`);
  if (body.paymentRequirements === undefined || body.paymentPayload === undefined) refuse("SCHEMA_INVALID", "paymentRequirements and paymentPayload are required");
  const requirements = parseRequirements(body.paymentRequirements, { ...deps, numberTokens: parsed.numberTokens, path: "$.paymentRequirements" });
  const payload = parsePayload(body.paymentPayload, { numberTokens: parsed.numberTokens, path: "$.paymentPayload", requirements });
  return Object.freeze({ requirements, payload });
}

module.exports = { CAPS, parseRequirements, parsePayload, parseFacilitatorRequest, FacilitatorRefusal };
