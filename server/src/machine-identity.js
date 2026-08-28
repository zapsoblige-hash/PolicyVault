"use strict";

/*
 * First-class AI/machine identities + scoped API credentials (completion-
 * standard surface 6; docs/postlaunch/platform-agent-api-spec.md).
 *
 * AUTH SURFACE ONLY. A machine identity is bound at creation to the
 * authenticated wallet session that created it (`creatorXOnly`) and
 * inherits EXACTLY that wallet's tenancy — never more (server/src/
 * tenancy.js already derives vault/org access from a real signing
 * identity's xOnlyPubkey; a resolved machine principal presents that SAME
 * xOnlyPubkey, so every existing tenancy/covenant-authorization check
 * applies completely unmodified). The scope list (server/src/scopes.js)
 * is a SEPARATE, narrower gate on top: which API operations this specific
 * credential may attempt. Neither layer can substitute for the covenant's
 * own signer authorization (sdk assertSignerAuthorizedV4) — a machine
 * identity can REQUEST that PolicyVault build/submit an operation; it
 * never holds owner/agent/approver key material, and the covenant decides
 * independently whether the resulting transaction is valid.
 *
 * Credential secrecy mirrors server/src/auth.js sessions exactly: the raw
 * bearer token is a 256-bit random value shown to the caller ONCE at mint
 * time; only its SHA-256 is ever persisted (as the record's own store key
 * — see server/src/platform-store.js), and it is never logged (only the
 * non-secret credentialId and a short display prefix are).
 */

const crypto = require("crypto");
const { Categories, getPlatformStore } = require("./platform-store");
const { SCOPES, isKnownScope } = require("./scopes");

const IDENTITY_SCHEMA = "policyvault-machine-identity/v1";
const CREDENTIAL_SCHEMA = "policyvault-machine-credential/v1";
const TOKEN_PREFIX = "pvmk_";
const TOKEN_HEX_RE = /^[0-9a-f]{64}$/;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const MAX_LABEL_LEN = 128;
const MAX_IDENTITIES_PER_WALLET = 50;
const MAX_CREDENTIALS_PER_IDENTITY = 10;

function fail(status, code, message) {
  const e = new Error(message);
  e.status = status;
  e.code = code;
  return e;
}

function sha256Hex(value) {
  return crypto.createHash("sha256").update(value, "utf8").digest("hex");
}

function normalizeLabel(label) {
  if (label === undefined || label === null) return "";
  if (typeof label !== "string" || label.length > MAX_LABEL_LEN) {
    throw fail(422, "MACHINE_IDENTITY_LABEL_INVALID", `label must be a string of at most ${MAX_LABEL_LEN} characters`);
  }
  return label;
}

/* Deny-by-default: an unknown scope string refuses the WHOLE request — a
 * typo or a future-build scope name is never silently dropped. */
function normalizeScopes(scopes) {
  if (!Array.isArray(scopes) || scopes.length === 0) {
    throw fail(422, "MACHINE_IDENTITY_SCOPES_REQUIRED", `scopes must be a non-empty array drawn from ${JSON.stringify(SCOPES)}`);
  }
  const out = [];
  const seen = new Set();
  for (const s of scopes) {
    if (!isKnownScope(s)) {
      throw fail(422, "MACHINE_IDENTITY_SCOPE_UNKNOWN", `scope ${JSON.stringify(s)} is not a known scope — unknown scopes fail closed`);
    }
    if (!seen.has(s)) {
      seen.add(s);
      out.push(s);
    }
  }
  return out.sort();
}

function mintToken() {
  const token = `${TOKEN_PREFIX}${crypto.randomBytes(32).toString("hex")}`;
  return { token, tokenHash: sha256Hex(token), tokenPrefix: token.slice(0, TOKEN_PREFIX.length + 8) };
}

async function saveIdentity(config, record) {
  await getPlatformStore(config).write(Categories.MACHINE_IDENTITY, record.identityId, record);
  return record;
}
async function loadIdentityRaw(config, identityId) {
  if (typeof identityId !== "string" || !UUID_RE.test(identityId)) return null;
  return getPlatformStore(config).read(Categories.MACHINE_IDENTITY, identityId);
}

async function saveCredential(config, record) {
  await getPlatformStore(config).write(Categories.MACHINE_CREDENTIAL, record.tokenHashKey, record);
  return record;
}

/*
 * Create a machine identity + its first credential in one call (the usual
 * API-key UX: the secret is shown exactly once, right here).
 * `creatorXOnly` is the AUTHENTICATED WALLET SESSION'S xOnlyPubkey — never
 * a client-supplied field (the route resolves it before calling in).
 */
async function createIdentity(config, { creatorXOnly, orgId, label, scopes }) {
  if (typeof creatorXOnly !== "string" || !/^[0-9a-f]{64}$/.test(creatorXOnly)) {
    throw fail(500, "MACHINE_IDENTITY_INTERNAL", "internal: creatorXOnly must be resolved by the caller — failing closed");
  }
  const store = getPlatformStore(config);
  const existing = await store.listValues(Categories.MACHINE_IDENTITY);
  const mine = existing.filter((r) => r && r.creatorXOnly === creatorXOnly && r.status === "ACTIVE");
  if (mine.length >= MAX_IDENTITIES_PER_WALLET) {
    throw fail(429, "MACHINE_IDENTITY_QUOTA_EXCEEDED", `this wallet already has ${mine.length} active machine identities (limit ${MAX_IDENTITIES_PER_WALLET})`);
  }
  const normalizedOrgId = orgId === undefined || orgId === null ? null : String(orgId);
  const identity = {
    schema: IDENTITY_SCHEMA,
    identityId: crypto.randomUUID(),
    networkId: config.networkId,
    creatorXOnly,
    orgId: normalizedOrgId,
    label: normalizeLabel(label),
    scopes: normalizeScopes(scopes),
    status: "ACTIVE",
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    revokedAt: null
  };
  await saveIdentity(config, identity);
  const credential = await mintCredentialRecord(config, identity, { label: "initial" });
  return { identity, credential };
}

/* Internal: mint ONE credential row + its raw token for an identity
 * already loaded/authorized by the caller. Never called directly from a
 * route — routes go through mintCredential (which re-checks status/quota
 * against durable state). */
async function mintCredentialRecord(config, identity, { label }) {
  const { token, tokenHash, tokenPrefix } = mintToken();
  const record = {
    schema: CREDENTIAL_SCHEMA,
    credentialId: crypto.randomUUID(),
    identityId: identity.identityId,
    networkId: config.networkId,
    tokenHashKey: tokenHash, // the store key; also carried in-record for listing-time key recovery
    tokenPrefix,
    status: "ACTIVE",
    label: normalizeLabel(label),
    createdAt: new Date().toISOString(),
    lastUsedAt: null,
    revokedAt: null
  };
  const created = await getPlatformStore(config).createExclusive(Categories.MACHINE_CREDENTIAL, tokenHash, record);
  if (!created) {
    // 256-bit collision: astronomically unlikely: treat as a transient
    // mint failure rather than ever reusing/overwriting another
    // credential's slot (createExclusive already refused that atomically).
    throw fail(500, "MACHINE_CREDENTIAL_MINT_COLLISION", "internal: credential token collision — retry the request");
  }
  return { record, token };
}

/*
 * Mint an ADDITIONAL credential for an existing identity (rotation without
 * revoking the old one first). `creatorXOnly` must match the identity's
 * creator (404 hides a foreign identity, matching tenancy.js's existence-
 * hiding discipline for every other hosted object).
 */
async function mintCredential(config, { identityId, creatorXOnly, label }) {
  const identity = await requireOwnedIdentity(config, identityId, creatorXOnly);
  const mine = (await listCredentialsForIdentity(config, identityId)).filter((c) => c.status === "ACTIVE");
  if (mine.length >= MAX_CREDENTIALS_PER_IDENTITY) {
    throw fail(429, "MACHINE_CREDENTIAL_QUOTA_EXCEEDED", `this identity already has ${mine.length} active credentials (limit ${MAX_CREDENTIALS_PER_IDENTITY}) — revoke an old one before minting another`);
  }
  return mintCredentialRecord(config, identity, { label });
}

async function requireOwnedIdentity(config, identityId, creatorXOnly) {
  const identity = await loadIdentityRaw(config, identityId);
  if (!identity || identity.creatorXOnly !== creatorXOnly) {
    throw fail(404, "MACHINE_IDENTITY_NOT_FOUND", "no such machine identity");
  }
  return identity;
}

async function listCredentialsForIdentity(config, identityId) {
  const all = await getPlatformStore(config).listValues(Categories.MACHINE_CREDENTIAL);
  return all.filter((r) => r && r.identityId === identityId);
}

async function listIdentitiesForCreator(config, creatorXOnly) {
  const all = await getPlatformStore(config).listValues(Categories.MACHINE_IDENTITY);
  return all.filter((r) => r && r.creatorXOnly === creatorXOnly);
}

async function getIdentityScoped(config, identityId, creatorXOnly) {
  return requireOwnedIdentity(config, identityId, creatorXOnly);
}

async function revokeCredential(config, { identityId, credentialId, creatorXOnly }) {
  await requireOwnedIdentity(config, identityId, creatorXOnly);
  const all = await listCredentialsForIdentity(config, identityId);
  const record = all.find((c) => c.credentialId === credentialId);
  if (!record) throw fail(404, "MACHINE_CREDENTIAL_NOT_FOUND", "no such credential on this identity");
  if (record.status !== "REVOKED") {
    record.status = "REVOKED";
    record.revokedAt = new Date().toISOString();
    await getPlatformStore(config).write(Categories.MACHINE_CREDENTIAL, record.tokenHashKey, record);
  }
  return record;
}

/* Revoke the identity itself. resolveBearerToken independently checks the
 * PARENT identity's status on every use, so this alone immediately
 * invalidates every credential the identity ever minted — no fan-out
 * write is required for correctness (still idempotent to call twice). */
async function revokeIdentity(config, { identityId, creatorXOnly }) {
  const identity = await requireOwnedIdentity(config, identityId, creatorXOnly);
  if (identity.status !== "REVOKED") {
    identity.status = "REVOKED";
    identity.revokedAt = new Date().toISOString();
    identity.updatedAt = identity.revokedAt;
    await saveIdentity(config, identity);
  }
  return identity;
}

/*
 * Resolve a raw `Authorization: Bearer <token>` value into an active
 * machine identity + credential, or throw MACHINE_TOKEN_INVALID (a single
 * collapsed failure code — no oracle distinguishing "wrong token" from
 * "revoked" from "unknown", exactly auth.js's AUTH_SIGNATURE_INVALID
 * collapse rationale). Touches lastUsedAt best-effort (mirrors
 * auth.js sessionTouch — not load-bearing for correctness).
 */
async function resolveBearerToken(config, authorizationHeader) {
  if (typeof authorizationHeader !== "string") throw fail(401, "MACHINE_TOKEN_INVALID", "no machine credential presented");
  const m = /^Bearer\s+(\S+)$/i.exec(authorizationHeader.trim());
  const token = m ? m[1] : null;
  if (!token || !token.startsWith(TOKEN_PREFIX) || !TOKEN_HEX_RE.test(token.slice(TOKEN_PREFIX.length))) {
    throw fail(401, "MACHINE_TOKEN_INVALID", "malformed machine credential");
  }
  const tokenHash = sha256Hex(token);
  const store = getPlatformStore(config);
  const credential = await store.read(Categories.MACHINE_CREDENTIAL, tokenHash);
  if (!credential || credential.schema !== CREDENTIAL_SCHEMA || credential.networkId !== config.networkId) {
    throw fail(401, "MACHINE_TOKEN_INVALID", "invalid machine credential");
  }
  if (credential.status !== "ACTIVE") {
    throw fail(401, "MACHINE_TOKEN_INVALID", "invalid machine credential");
  }
  const identity = await loadIdentityRaw(config, credential.identityId);
  if (!identity || identity.schema !== IDENTITY_SCHEMA || identity.status !== "ACTIVE" || identity.networkId !== config.networkId) {
    throw fail(401, "MACHINE_TOKEN_INVALID", "invalid machine credential");
  }
  credential.lastUsedAt = new Date().toISOString();
  store.write(Categories.MACHINE_CREDENTIAL, tokenHash, credential).catch(() => {}); // best-effort, never blocks/fails the request
  return { identity, credential };
}

/* API presentation — NEVER the token, NEVER the hash. */
function presentIdentity(identity) {
  const { schema, identityId, networkId, creatorXOnly, orgId, label, scopes, status, createdAt, updatedAt, revokedAt } = identity;
  return { schema, identityId, networkId, creatorXOnly, orgId, label, scopes, status, createdAt, updatedAt, revokedAt };
}
function presentCredential(record) {
  const { schema, credentialId, identityId, networkId, tokenPrefix, status, label, createdAt, lastUsedAt, revokedAt } = record;
  return { schema, credentialId, identityId, networkId, tokenPrefix, status, label, createdAt, lastUsedAt, revokedAt };
}

module.exports = {
  IDENTITY_SCHEMA,
  CREDENTIAL_SCHEMA,
  MAX_IDENTITIES_PER_WALLET,
  MAX_CREDENTIALS_PER_IDENTITY,
  createIdentity,
  mintCredential,
  revokeCredential,
  revokeIdentity,
  listIdentitiesForCreator,
  listCredentialsForIdentity,
  getIdentityScoped,
  resolveBearerToken,
  presentIdentity,
  presentCredential
};
