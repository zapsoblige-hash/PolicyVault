"use strict";

/*
 * Per-organization CONTROLS record (postlaunch-rc server integration):
 * governance ceremony configuration (quorum + delay) and risk adapter
 * configuration, persisted as ONE durable record per organization
 * (Categories.ORG_CONTROLS, migration 004).
 *
 * METADATA PLANE ONLY (docs/postlaunch/governance-spec.md §2.1): this
 * record can ADD hosted workflow ceremony (extra governance approvers,
 * a delay window, restrictive risk adapters) and can never subtract the
 * covenant's own requirements. Rewriting it in the database changes
 * hosted ceremony/displays, never what Kaspa consensus accepts. Two
 * hard floors are enforced structurally elsewhere and restated here:
 *   - the vault OWNER's governance approval signature is ALWAYS
 *     required for an AUTHORITY EXPANSION (server/src/governance.js) —
 *     org quorum configuration adds approvers, it can never replace or
 *     remove the owner requirement;
 *   - break-glass owner actions (ownerPause freeze, terminal
 *     ownerRecover) are never gated, delayed, or quorumed by ANY
 *     configuration (governance-spec §6.1).
 *
 * Validation is strict and fail-closed: unknown schema, unknown adapter
 * types, unknown fields, malformed keys/amounts all refuse. Records
 * carry an integer `version` with expectedVersion CAS on update,
 * mirroring sdk/src/organization.js discipline.
 */

const { getStore, Categories } = require("../../sdk/src/store");
const { ADAPTER_TYPES } = require("./risk-adapters");

const ORG_CONTROLS_SCHEMA = "policyvault-org-controls/v1";
const XONLY_RE = /^[0-9a-f]{64}$/;
const MAX_GOVERNANCE_APPROVERS = 32;
const MAX_ADAPTERS = 16;
const MAX_DELAY_MS = 90 * 24 * 60 * 60 * 1000; // 90 days — a config typo must not brick a workflow forever

function fail(code, message, status = 422) {
  const e = new Error(`org-controls: ${message}`);
  e.code = code;
  e.status = status;
  return e;
}

function isPlainObject(v) {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

/* Governance block: { quorum: { approvers: [xonly...], m } | null, delayMs }. */
function normalizeGovernance(input) {
  if (input === undefined || input === null) return { quorum: null, delayMs: 0 };
  if (!isPlainObject(input)) throw fail("CONTROLS_INVALID", "governance must be an object");
  for (const k of Object.keys(input)) {
    if (k !== "quorum" && k !== "delayMs") throw fail("CONTROLS_INVALID", `governance.${k} is not a known field — unknown fields fail closed`);
  }
  let quorum = null;
  if (input.quorum !== undefined && input.quorum !== null) {
    if (!isPlainObject(input.quorum)) throw fail("CONTROLS_INVALID", "governance.quorum must be an object or null");
    for (const k of Object.keys(input.quorum)) {
      if (k !== "approvers" && k !== "m") throw fail("CONTROLS_INVALID", `governance.quorum.${k} is not a known field`);
    }
    const approvers = input.quorum.approvers;
    if (!Array.isArray(approvers) || approvers.length === 0) {
      throw fail("CONTROLS_INVALID", "governance.quorum.approvers must be a non-empty array of x-only public keys");
    }
    if (approvers.length > MAX_GOVERNANCE_APPROVERS) {
      throw fail("CONTROLS_INVALID", `governance.quorum.approvers exceeds ${MAX_GOVERNANCE_APPROVERS} entries`);
    }
    const normalized = [];
    const seen = new Set();
    for (const [i, a] of approvers.entries()) {
      if (typeof a !== "string" || !XONLY_RE.test(a.toLowerCase())) {
        throw fail("CONTROLS_INVALID", `governance.quorum.approvers[${i}] must be 64-hex x-only`);
      }
      const key = a.toLowerCase();
      if (seen.has(key)) throw fail("CONTROLS_INVALID", `governance.quorum.approvers duplicates ${key}`);
      seen.add(key);
      normalized.push(key);
    }
    const m = input.quorum.m;
    if (!Number.isInteger(m) || m < 1 || m > normalized.length) {
      throw fail("CONTROLS_INVALID", `governance.quorum.m must satisfy 1 <= m <= ${normalized.length}`);
    }
    quorum = { approvers: normalized, m };
  }
  let delayMs = 0;
  if (input.delayMs !== undefined) {
    if (!Number.isInteger(input.delayMs) || input.delayMs < 0 || input.delayMs > MAX_DELAY_MS) {
      throw fail("CONTROLS_INVALID", `governance.delayMs must be an integer 0..${MAX_DELAY_MS}`);
    }
    delayMs = input.delayMs;
  }
  return { quorum, delayMs };
}

/* Risk block: { adapters: [{type, name?, params?, timeoutMs?}...],
 * onAdapterError?, onEmpty?, timeoutMs?, reviewRequired? }. Adapter
 * PARAMS are validated by the factory (risk-adapters.js) at save time
 * so a bad configuration refuses HERE, not at first evaluation. */
function normalizeRisk(input) {
  if (input === undefined || input === null) return { adapters: [], onAdapterError: "REVIEW", reviewRequired: false };
  if (!isPlainObject(input)) throw fail("CONTROLS_INVALID", "risk must be an object");
  const KNOWN = ["adapters", "onAdapterError", "onEmpty", "timeoutMs", "reviewRequired"];
  for (const k of Object.keys(input)) {
    if (!KNOWN.includes(k)) throw fail("CONTROLS_INVALID", `risk.${k} is not a known field — unknown fields fail closed`);
  }
  const out = { adapters: [], onAdapterError: "REVIEW", reviewRequired: false };
  if (input.adapters !== undefined) {
    if (!Array.isArray(input.adapters)) throw fail("CONTROLS_INVALID", "risk.adapters must be an array");
    if (input.adapters.length > MAX_ADAPTERS) throw fail("CONTROLS_INVALID", `risk.adapters exceeds ${MAX_ADAPTERS} entries`);
    const names = new Set();
    for (const [i, entry] of input.adapters.entries()) {
      if (!isPlainObject(entry)) throw fail("CONTROLS_INVALID", `risk.adapters[${i}] must be an object`);
      for (const k of Object.keys(entry)) {
        if (!["type", "name", "params", "timeoutMs"].includes(k)) {
          throw fail("CONTROLS_INVALID", `risk.adapters[${i}].${k} is not a known field`);
        }
      }
      if (typeof entry.type !== "string" || !Object.prototype.hasOwnProperty.call(ADAPTER_TYPES, entry.type)) {
        throw fail(
          "RISK_ADAPTER_TYPE_UNKNOWN",
          `risk.adapters[${i}].type ${JSON.stringify(entry.type)} is not a registered adapter type (${Object.keys(ADAPTER_TYPES).join(", ")}) — unknown types fail closed`
        );
      }
      const name = entry.name === undefined ? entry.type : entry.name;
      if (typeof name !== "string" || !/^[a-z0-9][a-z0-9-]{0,63}$/.test(name)) {
        throw fail("CONTROLS_INVALID", `risk.adapters[${i}].name must match /^[a-z0-9][a-z0-9-]{0,63}$/`);
      }
      if (names.has(name)) throw fail("CONTROLS_INVALID", `risk.adapters duplicates adapter name ${JSON.stringify(name)}`);
      names.add(name);
      if (entry.timeoutMs !== undefined && (!Number.isInteger(entry.timeoutMs) || entry.timeoutMs < 1 || entry.timeoutMs > 600000)) {
        throw fail("CONTROLS_INVALID", `risk.adapters[${i}].timeoutMs must be an integer 1..600000`);
      }
      const params = entry.params === undefined ? {} : entry.params;
      if (!isPlainObject(params)) throw fail("CONTROLS_INVALID", `risk.adapters[${i}].params must be an object`);
      // Validate the params against the factory NOW (fail closed at save).
      ADAPTER_TYPES[entry.type].validateParams(params);
      out.adapters.push({ type: entry.type, name, params, ...(entry.timeoutMs !== undefined ? { timeoutMs: entry.timeoutMs } : {}) });
    }
  }
  if (input.onAdapterError !== undefined) {
    if (input.onAdapterError !== "REVIEW" && input.onAdapterError !== "DENY") {
      // "ALLOW" is refused BY CONSTRUCTION here and again by
      // core/risk normalizeCompositionConfig — an erroring control can
      // never resolve permissive.
      throw fail("CONTROLS_INVALID", 'risk.onAdapterError must be "REVIEW" or "DENY" (never "ALLOW")');
    }
    out.onAdapterError = input.onAdapterError;
  }
  if (input.onEmpty !== undefined) {
    if (!["ALLOW", "REVIEW", "DENY"].includes(input.onEmpty)) throw fail("CONTROLS_INVALID", "risk.onEmpty must be ALLOW|REVIEW|DENY");
    out.onEmpty = input.onEmpty;
  }
  if (input.timeoutMs !== undefined) {
    if (!Number.isInteger(input.timeoutMs) || input.timeoutMs < 1 || input.timeoutMs > 600000) {
      throw fail("CONTROLS_INVALID", "risk.timeoutMs must be an integer 1..600000");
    }
    out.timeoutMs = input.timeoutMs;
  }
  if (input.reviewRequired !== undefined) {
    if (typeof input.reviewRequired !== "boolean") throw fail("CONTROLS_INVALID", "risk.reviewRequired must be a boolean");
    out.reviewRequired = input.reviewRequired;
  }
  if (out.reviewRequired && out.onEmpty === "ALLOW") {
    // Mirror core/risk RISK_CONFIG_CONFLICT at configuration time.
    throw fail("RISK_CONFIG_CONFLICT", 'risk.onEmpty "ALLOW" contradicts reviewRequired=true — default-restrictive for review-required organizations');
  }
  return out;
}

function normalizeControls(input, orgId) {
  if (!isPlainObject(input)) throw fail("CONTROLS_INVALID", "controls record must be an object");
  if (input.schema !== ORG_CONTROLS_SCHEMA) {
    throw fail("CONTROLS_SCHEMA_UNKNOWN", `unknown controls schema ${JSON.stringify(input.schema)} — failing closed`);
  }
  if (input.orgId !== orgId) throw fail("CONTROLS_INVALID", "controls orgId does not match its key");
  if (!Number.isInteger(input.version) || input.version < 1) throw fail("CONTROLS_INVALID", "version must be a positive integer");
  return {
    schema: ORG_CONTROLS_SCHEMA,
    orgId,
    version: input.version,
    governance: normalizeGovernance(input.governance),
    risk: normalizeRisk(input.risk),
    createdAt: typeof input.createdAt === "string" ? input.createdAt : new Date().toISOString(),
    updatedAt: typeof input.updatedAt === "string" ? input.updatedAt : new Date().toISOString()
  };
}

/* The effective defaults for a vault with no organization (or an org
 * with no stored controls): personal-vault semantics — governance
 * quorum = the owner alone (enforced structurally by governance.js),
 * zero delay, no adapters (core/risk onEmpty default = ALLOW). */
function defaultControls() {
  return {
    schema: ORG_CONTROLS_SCHEMA,
    orgId: null,
    version: 0,
    governance: { quorum: null, delayMs: 0 },
    risk: { adapters: [], onAdapterError: "REVIEW", reviewRequired: false },
    createdAt: null,
    updatedAt: null
  };
}

async function loadOrgControls(config, orgId) {
  const stored = await getStore(config).read(Categories.ORG_CONTROLS, orgId);
  if (stored === null) return null;
  return normalizeControls(stored, orgId); // unknown schema / malformed -> throw (fail closed)
}

/* Save with expectedVersion CAS (organization.js discipline). */
async function saveOrgControls(config, orgId, { governance, risk, expectedVersion }) {
  const existing = await getStore(config).read(Categories.ORG_CONTROLS, orgId);
  const currentVersion = existing === null ? 0 : normalizeControls(existing, orgId).version;
  if (expectedVersion !== undefined && expectedVersion !== null && expectedVersion !== currentVersion) {
    throw fail("VERSION_CONFLICT", `controls changed (version ${currentVersion}, expected ${expectedVersion}) — reload and retry`, 409);
  }
  const now = new Date().toISOString();
  const record = normalizeControls(
    {
      schema: ORG_CONTROLS_SCHEMA,
      orgId,
      version: currentVersion + 1,
      governance,
      risk,
      createdAt: existing && typeof existing.createdAt === "string" ? existing.createdAt : now,
      updatedAt: now
    },
    orgId
  );
  await getStore(config).write(Categories.ORG_CONTROLS, orgId, record);
  return record;
}

/* The controls that apply to a VAULT: its assigned organization's
 * stored controls, or personal defaults. Corrupt/unknown stored
 * controls FAIL CLOSED (throw) — they are a security configuration, so
 * a record this build cannot understand must never silently degrade to
 * "no controls". */
async function controlsForVault(config, vaultId) {
  const { assignmentFor } = require("../../sdk/src/organization");
  const assignment = await assignmentFor(config, vaultId);
  if (!assignment) return { orgId: null, controls: defaultControls() };
  const controls = await loadOrgControls(config, assignment.orgId);
  return { orgId: assignment.orgId, controls: controls ?? { ...defaultControls(), orgId: assignment.orgId } };
}

module.exports = {
  ORG_CONTROLS_SCHEMA,
  normalizeControls,
  defaultControls,
  loadOrgControls,
  saveOrgControls,
  controlsForVault
};
