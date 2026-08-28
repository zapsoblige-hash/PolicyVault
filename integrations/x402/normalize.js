"use strict";

/*
 * x402 v2 `PaymentRequired` -> closed PolicyVault intent proposal
 * (x402-adapter-spec.md §3, implemented field-for-field).
 *
 * Every byte here is UNTRUSTED. A field is either a PROPOSAL (normalized
 * into the closed intent and then subjected in full to policy,
 * governance, risk, deterministic verification, and finally the
 * covenant) or AUDIT-ONLY METADATA (length-capped, recorded verbatim,
 * read by NOTHING in the decision path). There is no third category:
 * unknown keys refuse (X402_SCHEMA_UNKNOWN_FIELD).
 *
 * The resource server MAY REQUEST. POLICYVAULT DETERMINISTICALLY
 * DECIDES. THE COVENANT ENFORCES FINANCIAL AUTHORITY. THE SIGNER RETAINS
 * CUSTODY. A valid, well-formed PaymentRequired is a request for money
 * and carries zero authority to move any.
 */

const { parseStrictJson, decodeBase64Strict, utf8TextOf, GuardError, PLAIN_INT_RE } = require("../lib/json-guard");
const { requireCanonicalSompiString, AmountError } = require("../lib/amounts-gate");
const { resolveLiteralDestination, AddressError } = require("../lib/address");
const { x402RequirementDigest } = require("../lib/digests");
const { X402Refusal } = require("./codes");

const SUPPORTED_X402_VERSIONS = Object.freeze(new Set([2])); // v2 only (spec OQ-1: v1 refused, never reinterpreted)
const SUPPORTED_SCHEMES = Object.freeze(new Set(["exact"]));

/* Closed key sets — any other key, at any depth of the CLASSIFIED tree,
 * refuses. (`extra` members other than paymentFlow and `extensions`
 * members are classified AUDIT-ONLY by the spec's field table and are
 * therefore carried opaquely, not treated as unknown keys.) */
const TOP_KEYS = Object.freeze(new Set(["x402Version", "error", "resource", "accepts", "extensions"]));
const RESOURCE_KEYS = Object.freeze(new Set(["url", "description", "mimeType"]));
const REQUIREMENT_KEYS = Object.freeze(new Set(["scheme", "network", "amount", "asset", "payTo", "maxTimeoutSeconds", "extra"]));

const CAPS = Object.freeze({
  headerEncodedBytes: 21848, // ceil(16 KiB * 4/3) + padding — encoded cap first
  decodedBytes: 16384, // spec-recommended 16 KiB decoded
  depth: 8,
  urlBytes: 2048,
  descriptionBytes: 1024,
  mimeTypeBytes: 255,
  errorBytes: 1024,
  extraBytes: 4096,
  extensionsBytes: 8192,
  acceptsMaxEntries: 64,
  timeoutCeilingSeconds: 3600
});

function refuse(code, detail) {
  throw new X402Refusal(code, detail);
}

function byteLen(value) {
  return Buffer.byteLength(JSON.stringify(value ?? null), "utf8");
}

function assertClosedKeys(obj, allowed, path) {
  for (const key of Object.keys(obj)) {
    if (!allowed.has(key)) refuse("X402_SCHEMA_UNKNOWN_FIELD", `unknown field ${JSON.stringify(key)} at ${path}`);
  }
}

/*
 * Gate ONE accepts[] entry. Returns the normalized candidate or throws
 * an X402Refusal naming the exact gate that failed. Order matters and is
 * fixed: version was already gated; per-entry order is scheme -> network
 * -> asset -> flow -> amount -> destination form -> timeout. The
 * authoritative address decode runs here; ALLOWLIST membership is a
 * separate, later gate (it needs vault state).
 */
function gateRequirement(entry, index, { config, numberTokens, pathPrefix }) {
  if (!entry || typeof entry !== "object" || Array.isArray(entry)) refuse("X402_SCHEMA_UNKNOWN_FIELD", `accepts[${index}] must be an object`);
  assertClosedKeys(entry, REQUIREMENT_KEYS, `${pathPrefix}`);
  for (const required of ["scheme", "network", "amount", "asset", "payTo", "maxTimeoutSeconds"]) {
    if (entry[required] === undefined) refuse("X402_SCHEMA_UNKNOWN_FIELD", `accepts[${index}].${required} is required`);
  }

  if (typeof entry.scheme !== "string" || !SUPPORTED_SCHEMES.has(entry.scheme)) {
    refuse("X402_SCHEME_UNSUPPORTED", `accepts[${index}].scheme ${JSON.stringify(entry.scheme)} — exact match against the supported set only`);
  }
  if (typeof entry.network !== "string" || entry.network !== config.caip2NetworkId) {
    refuse("X402_NETWORK_MISMATCH", `accepts[${index}].network ${JSON.stringify(entry.network)} != configured ${JSON.stringify(config.caip2NetworkId)}`);
  }
  if (typeof entry.asset !== "string" || entry.asset !== config.assetLiteral) {
    refuse("X402_ASSET_UNSUPPORTED", `accepts[${index}].asset ${JSON.stringify(entry.asset)} != configured native-KAS literal`);
  }

  // Pay-first only: extra.paymentFlow MUST be "upfront" (spec §6.4 — no
  // delegated pull, ever). Absent extra / absent flag / "authorization"
  // all refuse. Other extra.* members are AUDIT-ONLY and size-capped.
  const extra = entry.extra;
  if (extra !== undefined) {
    if (!extra || typeof extra !== "object" || Array.isArray(extra)) refuse("X402_SCHEMA_UNKNOWN_FIELD", `accepts[${index}].extra must be an object`);
    if (byteLen(extra) > CAPS.extraBytes) refuse("X402_EXTRA_TOO_LARGE", `accepts[${index}].extra exceeds ${CAPS.extraBytes} bytes`);
  }
  const paymentFlow = extra ? extra.paymentFlow : undefined;
  if (paymentFlow !== "upfront") {
    refuse("X402_FLOW_UNSUPPORTED", `accepts[${index}] paymentFlow ${JSON.stringify(paymentFlow ?? null)} — Kaspa requires the upfront flow`);
  }

  // Amount: MUST be a JSON string (a number is its own refusal), then the
  // canonical sompi grammar. Atomic unit == sompi, identity mapping.
  if (typeof entry.amount === "number" || numberTokens.has(`${pathPrefix}.amount`)) {
    refuse("X402_AMOUNT_NOT_STRING", `accepts[${index}].amount arrived as a JSON number`);
  }
  let payAmountSompi;
  try {
    payAmountSompi = requireCanonicalSompiString(entry.amount, { code: "X402_AMOUNT_INVALID", field: `accepts[${index}].amount` });
  } catch (error) {
    if (error instanceof AmountError) refuse(error.code, error.message);
    throw error;
  }

  // Destination: literal-form gates + authoritative decode to the x-only
  // P2PK key (the canonical internal identity — never the address string).
  let destination;
  try {
    destination = resolveLiteralDestination(config, entry.payTo, {
      notLiteralCode: "X402_DESTINATION_NOT_LITERAL",
      invalidCode: "X402_DESTINATION_INVALID"
    });
  } catch (error) {
    if (error instanceof AddressError) refuse(error.code, error.message);
    throw error;
  }

  // Deadline: adapter wall clock ONLY. Never enters lockTime, CLTV, fee,
  // period arithmetic, or any covenant field.
  const t = entry.maxTimeoutSeconds;
  const token = numberTokens.get(`${pathPrefix}.maxTimeoutSeconds`);
  if (typeof t !== "number" || !Number.isSafeInteger(t) || !PLAIN_INT_RE.test(token ?? "") || t < 1 || t > CAPS.timeoutCeilingSeconds) {
    refuse("X402_TIMEOUT_INVALID", `accepts[${index}].maxTimeoutSeconds ${JSON.stringify(t)} not an integer in 1..${CAPS.timeoutCeilingSeconds}`);
  }

  return {
    index,
    scheme: entry.scheme,
    network: entry.network,
    payAmountSompi,
    recipientAddress: destination.address,
    recipientXOnly: destination.xOnlyPubkey,
    maxTimeoutSeconds: t,
    payTo: entry.payTo,
    entry
  };
}

/*
 * Decode + normalize a PAYMENT-REQUIRED header (base64 JSON) into:
 * {
 *   normalized: { payAmountSompi, recipientXOnly, recipientAddress,
 *                 deadlineEpochSeconds },
 *   selected:   { index, entry, raw },       accepts[i], byte-verbatim raw
 *   requirementDigest, resourceRaw, extensionsRaw,
 *   audit: { x402Version, selectedIndex, paymentRequiredRaw },
 *   perEntryRefusals: [{ index, code }]      when selection had losers
 * }
 * Throws X402Refusal on every refusal path. PURE: no I/O, no clock reads
 * beyond the injected receiveTime.
 */
function normalizePaymentRequired(headerB64, { config, receiveTimeMs }) {
  if (typeof receiveTimeMs !== "number" || !Number.isSafeInteger(receiveTimeMs)) throw new Error("receiveTimeMs must be injected");
  let decodedText;
  try {
    const buf = decodeBase64Strict(headerB64, { maxEncodedBytes: CAPS.headerEncodedBytes });
    if (buf.length > CAPS.decodedBytes) refuse("X402_HEADER_INVALID", `decoded header exceeds ${CAPS.decodedBytes} bytes`);
    decodedText = utf8TextOf(buf, "X402_HEADER_INVALID");
  } catch (error) {
    if (error instanceof X402Refusal) throw error;
    if (error instanceof GuardError) refuse("X402_HEADER_INVALID", error.message);
    throw error;
  }

  let parsed;
  try {
    parsed = parseStrictJson(decodedText, {
      maxBytes: CAPS.decodedBytes,
      maxDepth: CAPS.depth,
      tolerateNonIntegerNumbers: true, // audit-only subtrees may carry floats; decision fields re-check lexical tokens
      rawPaths: (p) => p === "$.resource" || p === "$.extensions" || /^\$\.accepts\[\d+\]$/.test(p)
    });
  } catch (error) {
    if (error instanceof GuardError) {
      if (error.code === "JSON_TOO_DEEP" || error.code === "JSON_TOO_LARGE") refuse("X402_HEADER_INVALID", error.message);
      refuse("X402_HEADER_INVALID", error.message);
    }
    throw error;
  }
  const { value: doc, numberTokens, rawSlices } = parsed;

  if (!doc || typeof doc !== "object" || Array.isArray(doc)) refuse("X402_HEADER_INVALID", "PaymentRequired must be a JSON object");
  assertClosedKeys(doc, TOP_KEYS, "$");

  // Version gate FIRST, before any structural assumption. Lexical: the
  // token must be exactly `2` — `2.0`, `"2"`, null, absent all refuse.
  const versionToken = numberTokens.get("$.x402Version");
  if (typeof doc.x402Version !== "number" || versionToken !== String(doc.x402Version) || !SUPPORTED_X402_VERSIONS.has(doc.x402Version)) {
    refuse("X402_VERSION_UNSUPPORTED", `x402Version ${JSON.stringify(doc.x402Version ?? null)} (token ${JSON.stringify(versionToken ?? null)})`);
  }

  // resource: AUDIT-ONLY, but structurally validated + length-capped.
  if (!doc.resource || typeof doc.resource !== "object" || Array.isArray(doc.resource)) refuse("X402_RESOURCE_INVALID", "resource is required and must be an object");
  assertClosedKeys(doc.resource, RESOURCE_KEYS, "$.resource");
  const url = doc.resource.url;
  if (typeof url !== "string" || Buffer.byteLength(url, "utf8") > CAPS.urlBytes || !/^https:\/\/[^\s]+$/.test(url)) {
    refuse("X402_RESOURCE_INVALID", "resource.url must be an absolute https URI within the size cap");
  }
  if (doc.resource.description !== undefined && (typeof doc.resource.description !== "string" || Buffer.byteLength(doc.resource.description, "utf8") > CAPS.descriptionBytes)) {
    refuse("X402_METADATA_TOO_LARGE", "resource.description exceeds its cap or is not a string");
  }
  if (doc.resource.mimeType !== undefined && (typeof doc.resource.mimeType !== "string" || Buffer.byteLength(doc.resource.mimeType, "utf8") > CAPS.mimeTypeBytes)) {
    refuse("X402_METADATA_TOO_LARGE", "resource.mimeType exceeds its cap or is not a string");
  }
  if (doc.error !== undefined && (typeof doc.error !== "string" || Buffer.byteLength(doc.error, "utf8") > CAPS.errorBytes)) {
    refuse("X402_METADATA_TOO_LARGE", "error exceeds its cap or is not a string");
  }
  if (doc.extensions !== undefined) {
    if (!doc.extensions || typeof doc.extensions !== "object" || Array.isArray(doc.extensions)) refuse("X402_SCHEMA_UNKNOWN_FIELD", "extensions must be an object");
    if (byteLen(doc.extensions) > CAPS.extensionsBytes) refuse("X402_EXTENSIONS_TOO_LARGE", `extensions exceeds ${CAPS.extensionsBytes} bytes`);
  }

  if (!Array.isArray(doc.accepts)) refuse("X402_SCHEMA_UNKNOWN_FIELD", "accepts must be an array");
  if (doc.accepts.length === 0) refuse("X402_NO_ACCEPTABLE_REQUIREMENT", "accepts is empty");
  if (doc.accepts.length > CAPS.acceptsMaxEntries) refuse("X402_HEADER_INVALID", `accepts carries ${doc.accepts.length} entries (cap ${CAPS.acceptsMaxEntries})`);

  // Gate every entry; collect survivors and per-entry refusal codes.
  const survivors = [];
  const perEntryRefusals = [];
  for (let i = 0; i < doc.accepts.length; i += 1) {
    try {
      survivors.push(gateRequirement(doc.accepts[i], i, { config, numberTokens, pathPrefix: `$.accepts[${i}]` }));
    } catch (error) {
      if (error instanceof X402Refusal) {
        perEntryRefusals.push({ index: i, code: error.code });
        continue;
      }
      throw error;
    }
  }
  if (survivors.length === 0) {
    const summary = perEntryRefusals.map((r) => `[${r.index}] ${r.code}`).join(", ");
    const single = doc.accepts.length === 1 ? perEntryRefusals[0].code : "X402_NO_ACCEPTABLE_REQUIREMENT";
    const err = new X402Refusal(single, `no accepts[] entry passed every gate: ${summary}`);
    err.perEntryRefusals = perEntryRefusals;
    throw err;
  }

  // Deterministic, PolicyVault-side selection: lexicographically-first
  // surviving entry by (amount ascending as BigInt, scheme, network,
  // payTo). Never "pick the closest".
  survivors.sort((a, b) => {
    const av = BigInt(a.payAmountSompi);
    const bv = BigInt(b.payAmountSompi);
    if (av !== bv) return av < bv ? -1 : 1;
    if (a.scheme !== b.scheme) return a.scheme < b.scheme ? -1 : 1;
    if (a.network !== b.network) return a.network < b.network ? -1 : 1;
    if (a.payTo !== b.payTo) return a.payTo < b.payTo ? -1 : 1;
    return a.index - b.index;
  });
  const selected = survivors[0];

  const deadlineEpochSeconds = Math.floor(receiveTimeMs / 1000) + Math.min(selected.maxTimeoutSeconds, CAPS.timeoutCeilingSeconds);
  const requirementDigest = x402RequirementDigest({
    x402Version: doc.x402Version,
    resource: doc.resource,
    accepted: selected.entry
  });

  return {
    normalized: {
      payAmountSompi: selected.payAmountSompi,
      recipientXOnly: selected.recipientXOnly,
      recipientAddress: selected.recipientAddress,
      deadlineEpochSeconds
    },
    selected: {
      index: selected.index,
      entry: selected.entry,
      raw: rawSlices.get(`$.accepts[${selected.index}]`) ?? null
    },
    requirementDigest,
    resourceRaw: rawSlices.get("$.resource") ?? null,
    extensionsRaw: doc.extensions !== undefined ? rawSlices.get("$.extensions") ?? null : null,
    audit: {
      x402Version: doc.x402Version,
      selectedIndex: selected.index,
      paymentRequiredRaw: decodedText
    },
    perEntryRefusals
  };
}

/*
 * §4.6 settlement payload: `accepted`, `resource` and `extensions` are
 * spliced in BYTE-VERBATIM from the decoded header (never re-serialized
 * from parsed values), so the resource server's own comparison cannot be
 * defeated by a re-encoding difference and the requirement digest stays
 * reproducible. `payer` and `daaScore` are deliberately omitted (spec
 * OQ-3 / OQ-2 — the conservative options, recorded as interim decisions).
 */
function buildPaymentSignatureHeader({ resourceRaw, acceptedRaw, extensionsRaw, txId, payAmountSompi }) {
  if (typeof resourceRaw !== "string" || typeof acceptedRaw !== "string") {
    throw new Error("buildPaymentSignatureHeader: raw resource/accepted slices are required (byte-verbatim echo)");
  }
  if (!/^[0-9a-f]{64}$/.test(txId ?? "")) throw new Error("buildPaymentSignatureHeader: txId must be the 64-hex chain-proven txid");
  const payload = `{"transactionId":${JSON.stringify(txId)},"amount":${JSON.stringify(payAmountSompi)}}`;
  const extensions = typeof extensionsRaw === "string" ? `,"extensions":${extensionsRaw}` : "";
  const text = `{"x402Version":2,"resource":${resourceRaw},"accepted":${acceptedRaw},"payload":${payload}${extensions}}`;
  return { headerValue: Buffer.from(text, "utf8").toString("base64"), payloadText: text };
}

module.exports = { CAPS, SUPPORTED_X402_VERSIONS, SUPPORTED_SCHEMES, normalizePaymentRequired, buildPaymentSignatureHeader };
