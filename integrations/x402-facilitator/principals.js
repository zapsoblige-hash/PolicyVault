"use strict";

/*
 * Resource-server principals + facilitator-issued credentials (spec
 * §14.1; OQ-F7 RESOLVED). A DEDICATED credential model: never a
 * PolicyVault browser session, never a `pvmk_` machine credential, never
 * a wallet signature, never a payer or signer credential. Authority is
 * facilitator-local ONLY — a principal record grants nothing in
 * PolicyVault.
 *
 * Credential secrecy: 32 bytes of CSPRNG (256 bits) shown exactly once at
 * mint; only sha256(raw) is persisted; comparison is constant-time over
 * the fixed-length verifier; the raw value never appears in any record,
 * list, log line, or URL. Principal files are re-read on EVERY
 * authentication so revocation is immediate.
 *
 * Store: one JSON file per principal under `dir`, written atomically
 * (temp + rename, mode 0600). Single-operator configuration data — not
 * tenant data, not PolicyVault state.
 */

const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { CREDENTIAL_PREFIX, CREDENTIAL_RE, PRINCIPAL_OPERATIONS, NETWORKS } = require("./constants");

const SCHEMA = "policyvault-x402-facilitator-principal/1";
const ID_RE = /^[a-z0-9][a-z0-9-]{0,63}$/;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const HEX64_RE = /^[0-9a-f]{64}$/;
const PRINCIPAL_KEYS = new Set(["schema", "principalId", "label", "status", "createdAt", "updatedAt", "expiresAt", "operations", "networks", "allowedPayTo", "allowedResourceOrigins", "credentials"]);
const CREDENTIAL_KEYS = new Set(["credentialId", "label", "verifier", "status", "createdAt", "expiresAt", "revokedAt"]);

class PrincipalError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "PrincipalError";
    this.code = code;
  }
}
function fail(code, message) {
  throw new PrincipalError(code, message);
}

function sha256Hex(text) {
  return crypto.createHash("sha256").update(text, "utf8").digest("hex");
}

/* Mint: raw credential + verifier. The raw value is returned to the
 * caller ONCE and is never stored anywhere by this module. */
function mintCredential() {
  const raw = `${CREDENTIAL_PREFIX}${crypto.randomBytes(32).toString("hex")}`;
  return { raw, verifier: sha256Hex(raw), display: `${raw.slice(0, CREDENTIAL_PREFIX.length + 6)}…` };
}

function isIso(v) {
  return typeof v === "string" && !Number.isNaN(Date.parse(v)) && new Date(v).toISOString() === v;
}

function closed(obj, allowed, where) {
  if (typeof obj !== "object" || obj === null || Array.isArray(obj)) fail("PRINCIPAL_MALFORMED", `${where} must be an object`);
  for (const k of Object.keys(obj)) if (!allowed.has(k)) fail("PRINCIPAL_MALFORMED", `${where} carries unknown field ${JSON.stringify(k)} — closed schema`);
}

/* Validate + freeze a principal record (closed schema; fail closed). */
function normalizePrincipal(rec) {
  closed(rec, PRINCIPAL_KEYS, "principal");
  if (rec.schema !== SCHEMA) fail("PRINCIPAL_MALFORMED", `unknown principal schema ${JSON.stringify(rec.schema)}`);
  if (typeof rec.principalId !== "string" || !ID_RE.test(rec.principalId)) fail("PRINCIPAL_MALFORMED", "principalId must match ^[a-z0-9][a-z0-9-]{0,63}$");
  if (typeof rec.label !== "string" || rec.label.length > 128) fail("PRINCIPAL_MALFORMED", "label must be a string ≤ 128");
  if (rec.status !== "active" && rec.status !== "revoked") fail("PRINCIPAL_MALFORMED", "status must be active|revoked");
  if (!isIso(rec.createdAt) || !isIso(rec.updatedAt)) fail("PRINCIPAL_MALFORMED", "createdAt/updatedAt must be ISO-8601");
  if (rec.expiresAt !== null && !isIso(rec.expiresAt)) fail("PRINCIPAL_MALFORMED", "expiresAt must be null or ISO-8601");
  if (!Array.isArray(rec.operations) || rec.operations.some((o) => !PRINCIPAL_OPERATIONS.includes(o)) || new Set(rec.operations).size !== rec.operations.length) {
    fail("PRINCIPAL_MALFORMED", `operations must be a unique subset of ${PRINCIPAL_OPERATIONS.join(",")}`);
  }
  if (!Array.isArray(rec.networks) || rec.networks.length === 0 || rec.networks.some((n) => !Object.prototype.hasOwnProperty.call(NETWORKS, n)) || new Set(rec.networks).size !== rec.networks.length) {
    fail("PRINCIPAL_MALFORMED", "networks must be a non-empty unique subset of the frozen network identifiers");
  }
  const pt = rec.allowedPayTo;
  closed(pt, new Set(["mode", "addresses"]), "allowedPayTo");
  if (pt.mode === "any") {
    if (pt.addresses !== undefined) fail("PRINCIPAL_MALFORMED", "allowedPayTo.mode any takes no addresses");
  } else if (pt.mode === "list") {
    if (!Array.isArray(pt.addresses) || pt.addresses.length === 0 || pt.addresses.length > 10000 || pt.addresses.some((a) => typeof a !== "string" || !a || a.length > 256) || new Set(pt.addresses).size !== pt.addresses.length) {
      fail("PRINCIPAL_MALFORMED", "allowedPayTo.mode list requires a non-empty unique address list");
    }
  } else fail("PRINCIPAL_MALFORMED", "allowedPayTo.mode must be any|list (explicit — no implicit default)");
  const ro = rec.allowedResourceOrigins;
  closed(ro, new Set(["mode", "origins"]), "allowedResourceOrigins");
  if (ro.mode === "any") {
    if (ro.origins !== undefined) fail("PRINCIPAL_MALFORMED", "allowedResourceOrigins.mode any takes no origins");
  } else if (ro.mode === "list") {
    if (!Array.isArray(ro.origins) || ro.origins.length === 0 || ro.origins.length > 1000) fail("PRINCIPAL_MALFORMED", "allowedResourceOrigins.mode list requires a non-empty origin list");
    for (const o of ro.origins) {
      let u;
      try {
        u = new URL(o);
      } catch {
        fail("PRINCIPAL_MALFORMED", `origin ${JSON.stringify(String(o).slice(0, 64))} is not a URL`);
      }
      if (u.origin !== o) fail("PRINCIPAL_MALFORMED", `origin ${JSON.stringify(o.slice(0, 64))} must be a bare origin (scheme://host[:port])`);
    }
  } else fail("PRINCIPAL_MALFORMED", "allowedResourceOrigins.mode must be any|list");
  if (!Array.isArray(rec.credentials) || rec.credentials.length > 32) fail("PRINCIPAL_MALFORMED", "credentials must be an array of at most 32");
  const seen = new Set();
  const credentials = rec.credentials.map((c) => {
    closed(c, CREDENTIAL_KEYS, "credential");
    if (typeof c.credentialId !== "string" || !UUID_RE.test(c.credentialId) || seen.has(c.credentialId)) fail("PRINCIPAL_MALFORMED", "credentialId must be a unique lowercase UUID");
    seen.add(c.credentialId);
    if (typeof c.label !== "string" || c.label.length > 128) fail("PRINCIPAL_MALFORMED", "credential label must be a string ≤ 128");
    if (typeof c.verifier !== "string" || !HEX64_RE.test(c.verifier)) fail("PRINCIPAL_MALFORMED", "credential verifier must be sha256 hex");
    if (CREDENTIAL_RE.test(c.verifier) || c.verifier.startsWith(CREDENTIAL_PREFIX)) fail("PRINCIPAL_MALFORMED", "a raw credential must never be persisted");
    if (c.status !== "active" && c.status !== "revoked") fail("PRINCIPAL_MALFORMED", "credential status must be active|revoked");
    if (!isIso(c.createdAt)) fail("PRINCIPAL_MALFORMED", "credential createdAt must be ISO-8601");
    if (c.expiresAt !== null && !isIso(c.expiresAt)) fail("PRINCIPAL_MALFORMED", "credential expiresAt must be null or ISO-8601");
    if (c.revokedAt !== null && !isIso(c.revokedAt)) fail("PRINCIPAL_MALFORMED", "credential revokedAt must be null or ISO-8601");
    return Object.freeze({ ...c });
  });
  return Object.freeze({ ...rec, operations: Object.freeze([...rec.operations]), networks: Object.freeze([...rec.networks]), allowedPayTo: Object.freeze({ ...pt, ...(pt.addresses ? { addresses: Object.freeze([...pt.addresses]) } : {}) }), allowedResourceOrigins: Object.freeze({ ...ro, ...(ro.origins ? { origins: Object.freeze([...ro.origins]) } : {}) }), credentials: Object.freeze(credentials) });
}

/* Public (list/read) view: NEVER the raw credential (never stored), and
 * not even the verifier — only ids, labels, statuses, timestamps. */
function publicView(p) {
  return {
    principalId: p.principalId,
    label: p.label,
    status: p.status,
    createdAt: p.createdAt,
    updatedAt: p.updatedAt,
    expiresAt: p.expiresAt,
    operations: [...p.operations],
    networks: [...p.networks],
    allowedPayTo: p.allowedPayTo.mode === "list" ? { mode: "list", addresses: [...p.allowedPayTo.addresses] } : { mode: "any" },
    allowedResourceOrigins: p.allowedResourceOrigins.mode === "list" ? { mode: "list", origins: [...p.allowedResourceOrigins.origins] } : { mode: "any" },
    credentials: p.credentials.map((c) => ({ credentialId: c.credentialId, label: c.label, status: c.status, createdAt: c.createdAt, expiresAt: c.expiresAt, revokedAt: c.revokedAt }))
  };
}

class PrincipalStore {
  constructor({ dir }) {
    if (typeof dir !== "string" || !dir) throw new Error("x402-facilitator: principal store dir is required");
    this.dir = dir;
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  }

  _file(principalId) {
    if (typeof principalId !== "string" || !ID_RE.test(principalId)) fail("PRINCIPAL_MALFORMED", "principalId must match ^[a-z0-9][a-z0-9-]{0,63}$");
    return path.join(this.dir, `${principalId}.json`);
  }

  _write(rec) {
    const normalized = normalizePrincipal(rec);
    const file = this._file(normalized.principalId);
    const tmp = `${file}.${process.pid}.${crypto.randomBytes(4).toString("hex")}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify(normalized, null, 1), { mode: 0o600 });
    fs.renameSync(tmp, file);
    return normalized;
  }

  read(principalId) {
    let text;
    try {
      text = fs.readFileSync(this._file(principalId), "utf8");
    } catch (e) {
      if (e.code === "ENOENT") return null;
      throw e;
    }
    return normalizePrincipal(JSON.parse(text));
  }

  /* Every principal on disk, re-read now. A malformed file fails closed
   * (that principal is unusable) but does not break the others. */
  readAll() {
    const out = [];
    for (const entry of fs.readdirSync(this.dir)) {
      if (!entry.endsWith(".json")) continue;
      try {
        out.push(normalizePrincipal(JSON.parse(fs.readFileSync(path.join(this.dir, entry), "utf8"))));
      } catch {
        out.push(null);
      }
    }
    return out;
  }

  createPrincipal({ principalId, label = "", operations, networks, allowedPayTo, allowedResourceOrigins = { mode: "any" }, expiresAt = null }) {
    if (fs.existsSync(this._file(principalId))) fail("PRINCIPAL_EXISTS", `principal ${principalId} already exists`);
    const now = new Date().toISOString();
    return this._write({ schema: SCHEMA, principalId, label, status: "active", createdAt: now, updatedAt: now, expiresAt, operations, networks, allowedPayTo, allowedResourceOrigins, credentials: [] });
  }

  /* Mint ONE credential for an existing principal. Returns { raw, credential }
   * — `raw` exists only in this return value. Multiple ACTIVE credentials
   * exist only when the caller explicitly allows overlap (rotation). */
  mintCredential(principalId, { label = "", expiresAt = null, allowOverlap = false } = {}) {
    const p = this.read(principalId);
    if (!p) fail("PRINCIPAL_NOT_FOUND", `no principal ${principalId}`);
    if (p.status !== "active") fail("PRINCIPAL_REVOKED", `principal ${principalId} is revoked`);
    const active = p.credentials.filter((c) => c.status === "active");
    if (active.length > 0 && !allowOverlap) fail("CREDENTIAL_OVERLAP_NOT_ALLOWED", "an active credential exists — pass allowOverlap for rotation, or revoke the existing credential first");
    const minted = mintCredential();
    const now = new Date().toISOString();
    const credential = { credentialId: crypto.randomUUID(), label, verifier: minted.verifier, status: "active", createdAt: now, expiresAt, revokedAt: null };
    this._write({ ...p, updatedAt: now, credentials: [...p.credentials, credential] });
    return { raw: minted.raw, display: minted.display, credentialId: credential.credentialId };
  }

  revokeCredential(principalId, credentialId) {
    const p = this.read(principalId);
    if (!p) fail("PRINCIPAL_NOT_FOUND", `no principal ${principalId}`);
    const now = new Date().toISOString();
    let found = false;
    const credentials = p.credentials.map((c) => {
      if (c.credentialId !== credentialId) return c;
      found = true;
      return c.status === "revoked" ? c : { ...c, status: "revoked", revokedAt: now };
    });
    if (!found) fail("CREDENTIAL_NOT_FOUND", `no credential ${credentialId} on ${principalId}`);
    return this._write({ ...p, updatedAt: now, credentials });
  }

  revokePrincipal(principalId) {
    const p = this.read(principalId);
    if (!p) fail("PRINCIPAL_NOT_FOUND", `no principal ${principalId}`);
    const now = new Date().toISOString();
    return this._write({ ...p, status: "revoked", updatedAt: now, credentials: p.credentials.map((c) => (c.status === "revoked" ? c : { ...c, status: "revoked", revokedAt: now })) });
  }

  list() {
    return this.readAll().filter(Boolean).map(publicView);
  }

  /*
   * Authenticate a presented raw credential. Returns { principal, credential }
   * or null. Constant-time over verifiers; NO early exit — every stored
   * verifier is compared so a miss and a hit take the same work. Expired
   * or revoked credentials / principals authenticate as null (the caller
   * emits one CREDENTIAL_INVALID for all of those cases).
   */
  authenticate(presented, now = Date.now()) {
    if (typeof presented !== "string" || !CREDENTIAL_RE.test(presented)) return null;
    const probe = Buffer.from(sha256Hex(presented), "hex");
    let hit = null;
    for (const p of this.readAll()) {
      if (!p) continue;
      for (const c of p.credentials) {
        const stored = Buffer.from(c.verifier, "hex");
        const equal = stored.length === probe.length && crypto.timingSafeEqual(stored, probe);
        if (equal && hit === null) hit = { principal: p, credential: c };
      }
    }
    if (!hit) return null;
    const { principal, credential } = hit;
    if (principal.status !== "active" || credential.status !== "active") return null;
    if (principal.expiresAt !== null && Date.parse(principal.expiresAt) <= now) return null;
    if (credential.expiresAt !== null && Date.parse(credential.expiresAt) <= now) return null;
    return hit;
  }
}

module.exports = { SCHEMA, PrincipalStore, PrincipalError, mintCredential, normalizePrincipal, publicView };
