"use strict";

/*
 * Per-tenant webhook endpoint subscriptions (completion-standard surface
 * 18; docs/postlaunch/webhooks-events-spec.md §6–§7).
 *
 * An endpoint is a NOTIFICATION SINK, never authority: it receives signed
 * copies of platform events its creating wallet could already read via
 * the API (tenancy inherits from creatorXOnly exactly like machine
 * identities — server/src/machine-identity.js). Nothing an endpoint (or
 * whoever controls its URL) returns is ever parsed as instructions
 * (events-delivery.js drains and discards response bodies).
 *
 * SECRET STORAGE — the honest tradeoff (spec §7): the per-endpoint HMAC
 * secret must be available in the clear to the SERVER at every delivery
 * (HMAC needs the raw key), so the hash-at-rest discipline used for
 * sessions and machine credentials is STRUCTURALLY IMPOSSIBLE here. The
 * secret is stored as a versioned envelope:
 *   - "aes256gcm/v1" when the operator sets POLICYVAULT_WEBHOOK_SECRET_KEY
 *     (64-hex, 32 bytes): protects DB dumps/backups leaving the host. The
 *     key lives beside the process, so a fully compromised app host is NOT
 *     in this control's threat model — documented, never oversold.
 *   - "plain/v1" otherwise: plaintext within this single restricted
 *     category, documented as such.
 * Unknown envelope versions and undecryptable envelopes FAIL CLOSED
 * (deliveries refuse with SECRET_UNAVAILABLE; never a plaintext fallback,
 * never a guessed key). Rotation: a new secret is minted and returned
 * once; the PREVIOUS secret co-signs deliveries for a bounded grace
 * window so consumers can roll without dropping verification.
 */

const crypto = require("crypto");
const { Categories, getEventsStore } = require("./events-store");
const { EVENT_TYPES } = require("./events");

const ENDPOINT_SCHEMA = "policyvault-webhook-endpoint/v1";
const SECRET_PREFIX = "pvwh_";
const MAX_ENDPOINTS_PER_WALLET = 20;
const MAX_LABEL_LEN = 128;
const MAX_URL_LEN = 2000;
const ROTATION_GRACE_MS = 24 * 60 * 60 * 1000; // previous secret co-signs for 24h
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function fail(status, code, message) {
  const e = new Error(message);
  e.status = status;
  e.code = code;
  return e;
}

/* ------------------------------------------------------------------ */
/* Secret envelopes                                                    */
/* ------------------------------------------------------------------ */

function atRestKey() {
  const raw = process.env.POLICYVAULT_WEBHOOK_SECRET_KEY;
  if (raw === undefined || raw === "") return null;
  if (!/^[0-9a-f]{64}$/i.test(raw)) {
    throw fail(500, "WEBHOOK_SECRET_KEY_INVALID", "POLICYVAULT_WEBHOOK_SECRET_KEY must be 64 hex characters (32 bytes) — failing closed");
  }
  return Buffer.from(raw, "hex");
}

function sealSecret(secret) {
  const key = atRestKey();
  if (!key) return { v: "plain/v1", secret };
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const ct = Buffer.concat([cipher.update(secret, "utf8"), cipher.final()]);
  return { v: "aes256gcm/v1", iv: iv.toString("hex"), ct: ct.toString("hex"), tag: cipher.getAuthTag().toString("hex") };
}

/* Envelope -> raw secret. FAIL CLOSED on unknown versions, a missing key,
 * or an undecryptable envelope — never a guess, never plaintext fallback. */
function openSecret(envelope) {
  if (!envelope || typeof envelope !== "object") throw fail(500, "WEBHOOK_SECRET_UNAVAILABLE", "endpoint secret envelope missing — failing closed");
  if (envelope.v === "plain/v1") {
    if (typeof envelope.secret !== "string" || !envelope.secret) throw fail(500, "WEBHOOK_SECRET_UNAVAILABLE", "endpoint secret envelope malformed — failing closed");
    return envelope.secret;
  }
  if (envelope.v === "aes256gcm/v1") {
    const key = atRestKey();
    if (!key) throw fail(500, "WEBHOOK_SECRET_UNAVAILABLE", "endpoint secret is encrypted at rest but POLICYVAULT_WEBHOOK_SECRET_KEY is not set — failing closed");
    try {
      const decipher = crypto.createDecipheriv("aes-256-gcm", key, Buffer.from(envelope.iv, "hex"));
      decipher.setAuthTag(Buffer.from(envelope.tag, "hex"));
      return Buffer.concat([decipher.update(Buffer.from(envelope.ct, "hex")), decipher.final()]).toString("utf8");
    } catch {
      throw fail(500, "WEBHOOK_SECRET_UNAVAILABLE", "endpoint secret envelope failed authenticated decryption (wrong key or tampering) — failing closed");
    }
  }
  throw fail(500, "WEBHOOK_SECRET_UNAVAILABLE", `unknown endpoint secret envelope version ${JSON.stringify(envelope.v)} — failing closed`);
}

function mintSecret() {
  const secret = `${SECRET_PREFIX}${crypto.randomBytes(32).toString("hex")}`;
  return { secret, secretPrefix: secret.slice(0, SECRET_PREFIX.length + 8) };
}

/* The signing secrets currently valid for an endpoint: always the current
 * one; the previous one only inside its rotation grace window. */
function signingSecretsFor(endpoint, nowMs = Date.now()) {
  const secrets = [openSecret(endpoint.secret)];
  if (endpoint.previousSecret && typeof endpoint.previousSecretValidUntilMs === "number" && nowMs <= endpoint.previousSecretValidUntilMs) {
    try {
      secrets.push(openSecret(endpoint.previousSecret));
    } catch {
      /* an unopenable EXPIRING secret never blocks current-secret signing */
    }
  }
  return secrets;
}

/* ------------------------------------------------------------------ */
/* URL validation (creation-time; delivery re-checks + pins DNS)       */
/* ------------------------------------------------------------------ */

/* https:// only. The explicit development override
 * (POLICYVAULT_WEBHOOK_ALLOW_INSECURE_LOCAL=1, never honored on mainnet)
 * additionally permits http:// to loopback hosts ONLY — local consumer
 * testing, exactly the dev-signer gating idiom. */
function insecureLocalAllowed(config) {
  return process.env.POLICYVAULT_WEBHOOK_ALLOW_INSECURE_LOCAL === "1" && config.networkId !== "mainnet";
}

const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]", "::1"]);

function validateEndpointUrl(config, rawUrl) {
  if (typeof rawUrl !== "string" || !rawUrl || rawUrl.length > MAX_URL_LEN) {
    throw fail(422, "WEBHOOK_URL_INVALID", `url must be a string of at most ${MAX_URL_LEN} characters`);
  }
  let url;
  try {
    url = new URL(rawUrl);
  } catch {
    throw fail(422, "WEBHOOK_URL_INVALID", "url does not parse");
  }
  if (url.username || url.password) throw fail(422, "WEBHOOK_URL_INVALID", "url must not carry credentials (userinfo)");
  if (url.protocol === "https:") return url.toString();
  if (url.protocol === "http:") {
    if (insecureLocalAllowed(config) && LOOPBACK_HOSTS.has(url.hostname)) return url.toString();
    throw fail(
      422,
      "WEBHOOK_URL_INSECURE",
      "webhook urls must be https:// (http:// to localhost is permitted only with POLICYVAULT_WEBHOOK_ALLOW_INSECURE_LOCAL=1 on a non-mainnet network)"
    );
  }
  throw fail(422, "WEBHOOK_URL_INVALID", `unsupported url scheme ${JSON.stringify(url.protocol)} — https:// only`);
}

function normalizeLabel(label) {
  if (label === undefined || label === null) return "";
  if (typeof label !== "string" || label.length > MAX_LABEL_LEN) {
    throw fail(422, "WEBHOOK_LABEL_INVALID", `label must be a string of at most ${MAX_LABEL_LEN} characters`);
  }
  return label;
}

/* Event-type filter: ["*"] (everything visible to the tenant) or a
 * non-empty subset of the closed catalog. Unknown types fail closed. */
function normalizeEventTypes(eventTypes) {
  if (eventTypes === undefined || eventTypes === null) return ["*"];
  if (!Array.isArray(eventTypes) || eventTypes.length === 0) {
    throw fail(422, "WEBHOOK_EVENT_TYPES_INVALID", "eventTypes must be a non-empty array (or omitted for all events)");
  }
  if (eventTypes.length === 1 && eventTypes[0] === "*") return ["*"];
  const out = [];
  const seen = new Set();
  for (const t of eventTypes) {
    if (typeof t !== "string" || !EVENT_TYPES[t]) {
      throw fail(422, "WEBHOOK_EVENT_TYPE_UNKNOWN", `event type ${JSON.stringify(t)} is not in the closed catalog — unknown types fail closed`);
    }
    if (!seen.has(t)) {
      seen.add(t);
      out.push(t);
    }
  }
  return out.sort();
}

/* ------------------------------------------------------------------ */
/* CRUD                                                                */
/* ------------------------------------------------------------------ */

async function createEndpoint(config, { creatorXOnly, url, eventTypes, label }) {
  if (creatorXOnly !== null && (typeof creatorXOnly !== "string" || !/^[0-9a-f]{64}$/.test(creatorXOnly))) {
    throw fail(500, "WEBHOOK_INTERNAL", "internal: creatorXOnly must be resolved by the caller — failing closed");
  }
  const store = getEventsStore(config);
  const existing = await store.listValues(Categories.WEBHOOK_ENDPOINT);
  const mine = existing.filter((r) => r && r.creatorXOnly === creatorXOnly && r.status === "ACTIVE");
  if (mine.length >= MAX_ENDPOINTS_PER_WALLET) {
    throw fail(429, "WEBHOOK_QUOTA_EXCEEDED", `this wallet already has ${mine.length} active webhook endpoints (limit ${MAX_ENDPOINTS_PER_WALLET})`);
  }
  const { secret, secretPrefix } = mintSecret();
  const endpoint = {
    schema: ENDPOINT_SCHEMA,
    endpointId: crypto.randomUUID(),
    networkId: config.networkId,
    creatorXOnly,
    url: validateEndpointUrl(config, url),
    eventTypes: normalizeEventTypes(eventTypes),
    label: normalizeLabel(label),
    status: "ACTIVE",
    secret: sealSecret(secret),
    secretPrefix,
    previousSecret: null,
    previousSecretValidUntilMs: null,
    secretRotatedAt: null,
    // New endpoints start at the CURRENT stream head: subscribing never
    // floods a consumer with the full history (polling serves history).
    initialCursor: await store.latestCursor(),
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    revokedAt: null
  };
  const created = await store.createExclusive(Categories.WEBHOOK_ENDPOINT, endpoint.endpointId, endpoint);
  if (!created) throw fail(500, "WEBHOOK_MINT_COLLISION", "internal: endpoint id collision — retry the request");
  return { endpoint, secret };
}

async function loadEndpointRaw(config, endpointId) {
  if (typeof endpointId !== "string" || !UUID_RE.test(endpointId)) return null;
  return getEventsStore(config).read(Categories.WEBHOOK_ENDPOINT, endpointId);
}

/* 404 hides foreign endpoints (tenancy.js existence-hiding discipline). */
async function requireOwnedEndpoint(config, endpointId, creatorXOnly) {
  const endpoint = await loadEndpointRaw(config, endpointId);
  if (!endpoint || endpoint.creatorXOnly !== creatorXOnly) {
    throw fail(404, "WEBHOOK_ENDPOINT_NOT_FOUND", "no such webhook endpoint");
  }
  return endpoint;
}

async function listEndpointsForCreator(config, creatorXOnly) {
  const all = await getEventsStore(config).listValues(Categories.WEBHOOK_ENDPOINT);
  return all.filter((r) => r && r.creatorXOnly === creatorXOnly);
}

async function listActiveEndpoints(config) {
  const all = await getEventsStore(config).listValues(Categories.WEBHOOK_ENDPOINT);
  return all.filter((r) => r && r.schema === ENDPOINT_SCHEMA && r.status === "ACTIVE" && r.networkId === config.networkId);
}

async function rotateEndpointSecret(config, { endpointId, creatorXOnly, graceMs = ROTATION_GRACE_MS }) {
  const endpoint = await requireOwnedEndpoint(config, endpointId, creatorXOnly);
  if (endpoint.status !== "ACTIVE") throw fail(409, "WEBHOOK_ENDPOINT_REVOKED", "a revoked endpoint cannot rotate its secret");
  const { secret, secretPrefix } = mintSecret();
  endpoint.previousSecret = endpoint.secret;
  endpoint.previousSecretValidUntilMs = Date.now() + Math.max(0, graceMs);
  endpoint.secret = sealSecret(secret);
  endpoint.secretPrefix = secretPrefix;
  endpoint.secretRotatedAt = new Date().toISOString();
  endpoint.updatedAt = endpoint.secretRotatedAt;
  await getEventsStore(config).write(Categories.WEBHOOK_ENDPOINT, endpoint.endpointId, endpoint);
  return { endpoint, secret };
}

async function revokeEndpoint(config, { endpointId, creatorXOnly }) {
  const endpoint = await requireOwnedEndpoint(config, endpointId, creatorXOnly);
  if (endpoint.status !== "REVOKED") {
    endpoint.status = "REVOKED";
    endpoint.revokedAt = new Date().toISOString();
    endpoint.updatedAt = endpoint.revokedAt;
    await getEventsStore(config).write(Categories.WEBHOOK_ENDPOINT, endpoint.endpointId, endpoint);
  }
  return endpoint;
}

/* API presentation — NEVER a secret envelope, NEVER raw secret material.
 * secretPrefix (first 13 chars, "pvwh_" + 8 hex) identifies which secret
 * a consumer holds, exactly the machine-credential tokenPrefix idiom. */
function presentEndpoint(endpoint) {
  const { schema, endpointId, networkId, creatorXOnly, url, eventTypes, label, status, secretPrefix, secretRotatedAt, previousSecretValidUntilMs, initialCursor, createdAt, updatedAt, revokedAt } = endpoint;
  return {
    schema,
    endpointId,
    networkId,
    creatorXOnly,
    url,
    eventTypes,
    label,
    status,
    secretPrefix,
    secretRotatedAt,
    previousSecretValidUntilMs,
    initialCursor,
    createdAt,
    updatedAt,
    revokedAt
  };
}

module.exports = {
  ENDPOINT_SCHEMA,
  MAX_ENDPOINTS_PER_WALLET,
  ROTATION_GRACE_MS,
  createEndpoint,
  loadEndpointRaw,
  requireOwnedEndpoint,
  listEndpointsForCreator,
  listActiveEndpoints,
  rotateEndpointSecret,
  revokeEndpoint,
  presentEndpoint,
  signingSecretsFor,
  validateEndpointUrl,
  insecureLocalAllowed,
  sealSecret,
  openSecret
};
