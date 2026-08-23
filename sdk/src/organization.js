"use strict";

/*
 * Organization / business layer — OFF-CHAIN APPLICATION METADATA ONLY.
 *
 * Organization roles are application metadata. They do not grant or
 * modify Kaspa covenant authority. On-chain authority is determined
 * solely by the vault/covenant (template.owner, live state.delegate,
 * paused state, recipient policy, and future v0.3 approvers). Nothing in
 * this module can move or authorize KAS, and the wallet-request pipeline
 * never consults it.
 *
 * Storage (durable-json atomic writes, one operator-local data root):
 *   data/orgs/<orgId>.json            one organization record (schema v2)
 *   data/orgs/assignments.json        canonical vaultId -> {orgId, group}
 *
 * Concurrency: every record carries an integer `version`; mutations
 * require the caller's `expectedVersion` to match and fail with
 * VERSION_CONFLICT otherwise — competing writes are rejected loudly,
 * never silently merged or lost.
 *
 * Fail-closed rules: unknown schemas are rejected (the legacy v1 schema
 * is explicitly refused with guidance, never silently upgraded); member
 * wallet addresses go through the ONE shared address-identity boundary;
 * malformed records throw with .code so callers can surface an
 * operational metadata error WITHOUT touching vault truth — metadata
 * failure never makes funds unreachable, because vault operations read
 * only manifests/claims/requests.
 */

const path = require("path");
const fs = require("fs");
const crypto = require("crypto");

const { persistJsonDurably, readJsonStrict } = require("./durable-json");
const { resolveAddressIdentity } = require("./address-identity");
const { appendAudit } = require("./audit");

const ORG_SCHEMA_V2 = "policyvault-organization/v2";
const ORG_SCHEMA_V1 = "policyvault-organization/v1";
const ASSIGNMENTS_SCHEMA = "policyvault-org-assignments/v1";

/* Application role LABELS (metadata only — never on-chain authority). */
const ROLE_LABELS = Object.freeze([
  "owner",
  "administrator",
  "treasurer",
  "approver",
  "delegate",
  "auditor",
  "viewer"
]);

const MEMBER_STATUS = Object.freeze(["ACTIVE", "INACTIVE"]);

/* Organization lifecycle status — LOCAL VISIBILITY METADATA ONLY. Archiving,
 * restoring, or deleting an organization never touches vaults, covenants,
 * manifests, or on-chain state. */
const ORG_STATUS = Object.freeze(["ACTIVE", "ARCHIVED"]);

const NAME_MAX = 120;
const NOTE_MAX = 500;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const VAULT_ID_RE = /^[0-9a-f]{64}$/;
const CONTROL_CHARS_RE = new RegExp("[\\u0000-\\u001f\\u007f]");

function fail(code, message) {
  const e = new Error(`organization: ${message}`);
  e.code = code;
  return e;
}

function requireOrgId(orgId) {
  if (typeof orgId !== "string" || !UUID_RE.test(orgId)) {
    throw fail("ORG_ID_INVALID", "organization id must be a UUID");
  }
  return orgId;
}

function cleanText(value, field, { max, required = false } = {}) {
  if (value === undefined || value === null || value === "") {
    if (required) throw fail("TEXT_REQUIRED", `${field} is required`);
    return "";
  }
  if (typeof value !== "string") {
    throw fail("TEXT_INVALID", `${field} must be a string`);
  }
  const trimmed = value.trim();
  if (required && !trimmed) throw fail("TEXT_REQUIRED", `${field} is required`);
  if (trimmed.length > max) throw fail("TEXT_TOO_LONG", `${field} exceeds ${max} characters`);
  if (CONTROL_CHARS_RE.test(trimmed)) throw fail("TEXT_INVALID", `${field} contains control characters`);
  return trimmed;
}

function normalizeRoles(roles) {
  if (!Array.isArray(roles) || roles.length === 0) {
    throw fail("ROLES_INVALID", "at least one role label is required");
  }
  const out = [];
  for (const r of roles) {
    if (typeof r !== "string" || !ROLE_LABELS.includes(r)) {
      throw fail("ROLES_INVALID", `unknown role label ${JSON.stringify(r)} — allowed: ${ROLE_LABELS.join(", ")}`);
    }
    if (!out.includes(r)) out.push(r);
  }
  return out;
}

/* ------------------------------------------------------------ storage */

function orgDir(config) {
  return path.join(config.dataRoot, "orgs");
}

function orgPath(config, orgId) {
  return path.join(orgDir(config), `${requireOrgId(orgId)}.json`);
}

function assignmentsPath(config) {
  return path.join(orgDir(config), "assignments.json");
}

/* -------------------------------------------------- record validation */

function normalizeMember(m, i) {
  if (!m || typeof m !== "object" || Array.isArray(m)) {
    throw fail("MEMBER_INVALID", `members[${i}] must be an object`);
  }
  if (typeof m.memberId !== "string" || !UUID_RE.test(m.memberId)) {
    throw fail("MEMBER_INVALID", `members[${i}].memberId must be a UUID`);
  }
  const status = m.status ?? "ACTIVE";
  if (!MEMBER_STATUS.includes(status)) {
    throw fail("MEMBER_INVALID", `members[${i}].status must be one of ${MEMBER_STATUS.join(", ")}`);
  }
  if (m.address !== null && m.address !== undefined && typeof m.address !== "string") {
    throw fail("MEMBER_INVALID", `members[${i}].address must be a string or null`);
  }
  if ((m.address == null) !== (m.xOnlyPubkey == null)) {
    throw fail("MEMBER_INVALID", `members[${i}] address/xOnlyPubkey must be stored together`);
  }
  if (m.xOnlyPubkey != null && !/^[0-9a-f]{64}$/.test(m.xOnlyPubkey)) {
    throw fail("MEMBER_INVALID", `members[${i}].xOnlyPubkey malformed`);
  }
  return {
    memberId: m.memberId,
    displayName: cleanText(m.displayName, `members[${i}].displayName`, { max: NAME_MAX, required: true }),
    address: m.address ?? null,
    xOnlyPubkey: m.xOnlyPubkey ?? null,
    roles: normalizeRoles(m.roles),
    status,
    note: cleanText(m.note, `members[${i}].note`, { max: NOTE_MAX }),
    createdAt: cleanText(m.createdAt, `members[${i}].createdAt`, { max: 40, required: true }),
    updatedAt: cleanText(m.updatedAt, `members[${i}].updatedAt`, { max: 40, required: true })
  };
}

function normalizeOrg(input) {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    throw fail("ORG_INVALID", "organization record must be an object");
  }
  if (input.schema === ORG_SCHEMA_V1) {
    throw fail(
      "ORG_SCHEMA_LEGACY",
      "legacy v1 organization record — the v1 layer was never surfaced; recreate the organization via the dashboard"
    );
  }
  if (input.schema !== ORG_SCHEMA_V2) {
    throw fail("ORG_SCHEMA_UNKNOWN", `unknown organization schema ${JSON.stringify(input.schema)} — failing closed`);
  }
  requireOrgId(input.orgId);
  if (!Number.isInteger(input.version) || input.version < 1) {
    throw fail("ORG_INVALID", "version must be a positive integer");
  }
  const members = Array.isArray(input.members) ? input.members.map(normalizeMember) : [];
  const seen = new Set();
  for (const m of members) {
    if (seen.has(m.memberId)) throw fail("MEMBER_INVALID", `duplicate memberId ${m.memberId}`);
    seen.add(m.memberId);
  }
  const status = input.status ?? "ACTIVE"; // pre-lifecycle records default ACTIVE
  if (!ORG_STATUS.includes(status)) {
    throw fail("ORG_INVALID", `status must be one of ${ORG_STATUS.join(", ")}`);
  }
  return {
    schema: ORG_SCHEMA_V2,
    orgId: input.orgId,
    name: cleanText(input.name, "name", { max: NAME_MAX, required: true }),
    version: input.version,
    status,
    members,
    createdAt: cleanText(input.createdAt, "createdAt", { max: 40, required: true }),
    updatedAt: cleanText(input.updatedAt, "updatedAt", { max: 40, required: true })
  };
}

/* ------------------------------------------------------------ orgs */

function saveOrg(config, org) {
  persistJsonDurably({ filePath: orgPath(config, org.orgId), value: org });
  return org;
}

function loadOrganization(config, orgId) {
  const filePath = orgPath(config, orgId);
  if (!fs.existsSync(filePath)) return null;
  return normalizeOrg(readJsonStrict(filePath, "organization"));
}

/*
 * Load-for-update with optimistic concurrency: the caller's
 * expectedVersion must equal the stored version, else VERSION_CONFLICT.
 */
function loadOrgForUpdate(config, orgId, expectedVersion) {
  const org = loadOrganization(config, orgId);
  if (!org) throw fail("ORG_NOT_FOUND", `no organization ${orgId}`);
  if (!Number.isInteger(expectedVersion)) {
    throw fail("VERSION_REQUIRED", "expectedVersion is required for organization updates");
  }
  if (org.version !== expectedVersion) {
    throw fail("VERSION_CONFLICT", `organization changed (version ${org.version}, expected ${expectedVersion}) — reload and retry`);
  }
  return org;
}

function createOrganization(config, { name }) {
  const now = new Date().toISOString();
  const org = normalizeOrg({
    schema: ORG_SCHEMA_V2,
    orgId: crypto.randomUUID(),
    name,
    version: 1,
    members: [],
    createdAt: now,
    updatedAt: now
  });
  saveOrg(config, org);
  appendAudit(config, { kind: "metadata", orgId: org.orgId, action: "org_created", detail: org.name });
  return org;
}

function renameOrganization(config, orgId, { name, expectedVersion }) {
  const org = loadOrgForUpdate(config, orgId, expectedVersion);
  const newName = cleanText(name, "name", { max: NAME_MAX, required: true });
  const updated = { ...org, name: newName, version: org.version + 1, updatedAt: new Date().toISOString() };
  saveOrg(config, updated);
  appendAudit(config, { kind: "metadata", orgId, action: "org_renamed", detail: `${org.name} -> ${newName}` });
  return updated;
}

/*
 * Archive: the preferred normal cleanup action. Changes ONLY local
 * organization visibility — the record remains on disk and recoverable,
 * vault associations are preserved untouched, and nothing on-chain or in
 * any manifest changes.
 */
function archiveOrganization(config, orgId, { expectedVersion }) {
  const org = loadOrgForUpdate(config, orgId, expectedVersion);
  if (org.status === "ARCHIVED") throw fail("ORG_ALREADY_ARCHIVED", `organization ${orgId} is already archived`);
  const updated = { ...org, status: "ARCHIVED", version: org.version + 1, updatedAt: new Date().toISOString() };
  saveOrg(config, updated);
  appendAudit(config, { kind: "metadata", orgId, action: "org_archived", detail: org.name });
  return updated;
}

function restoreOrganization(config, orgId, { expectedVersion }) {
  const org = loadOrgForUpdate(config, orgId, expectedVersion);
  if (org.status !== "ARCHIVED") throw fail("ORG_NOT_ARCHIVED", `organization ${orgId} is not archived`);
  const updated = { ...org, status: "ACTIVE", version: org.version + 1, updatedAt: new Date().toISOString() };
  saveOrg(config, updated);
  appendAudit(config, { kind: "metadata", orgId, action: "org_restored", detail: org.name });
  return updated;
}

/*
 * Permanent delete — ONLY when no vaults are assigned to the organization
 * (fail closed with ORG_NOT_EMPTY otherwise; the caller offers moving the
 * vaults or setting them to Unassigned first). Deleting an organization
 * NEVER deletes, recovers, closes, or alters a vault: only the local
 * metadata record is removed.
 */
function deleteOrganization(config, orgId, { expectedVersion }) {
  const org = loadOrgForUpdate(config, orgId, expectedVersion);
  let assigned = [];
  try {
    assigned = Object.entries(loadAssignments(config).assignments)
      .filter(([, a]) => a.orgId === orgId)
      .map(([vaultId]) => vaultId);
  } catch (e) {
    // Corrupt assignments -> cannot PROVE the organization is empty; fail closed.
    throw fail("ASSIGNMENTS_UNREADABLE", `cannot verify the organization is empty: ${e.message}`);
  }
  if (assigned.length > 0) {
    const err = fail(
      "ORG_NOT_EMPTY",
      `organization ${orgId} still has ${assigned.length} assigned vault(s) — move them to another organization or set them to Unassigned first`
    );
    err.assignedVaultIds = assigned;
    throw err;
  }
  fs.unlinkSync(orgPath(config, orgId));
  appendAudit(config, { kind: "metadata", orgId, action: "org_deleted", detail: org.name });
  return { deleted: true, orgId, name: org.name };
}

/*
 * Listing tolerates per-file corruption WITHOUT hiding it: corrupt
 * records surface as { orgId, error } entries so the dashboard can show
 * an operational metadata error while other organizations — and every
 * vault operation — keep working. Nothing is auto-repaired.
 */
function listOrganizations(config) {
  const dir = orgDir(config);
  if (!fs.existsSync(dir)) return [];
  const out = [];
  for (const f of fs.readdirSync(dir)) {
    if (!f.endsWith(".json") || f === "assignments.json") continue;
    const orgId = f.replace(/\.json$/, "");
    try {
      out.push(normalizeOrg(readJsonStrict(path.join(dir, f), "organization")));
    } catch (e) {
      out.push({ orgId: UUID_RE.test(orgId) ? orgId : "(invalid-filename)", error: "CORRUPT_METADATA", detail: e.message });
    }
  }
  return out.sort((a, b) => String(a.name ?? "").localeCompare(String(b.name ?? "")));
}

/* ------------------------------------------------------------ members */

function resolveMemberAddress(config, address) {
  if (address === undefined || address === null || String(address).trim() === "") {
    return { address: null, xOnlyPubkey: null };
  }
  // The ONE shared address boundary; malformed/wrong-network fails closed.
  const id = resolveAddressIdentity(config, String(address));
  return { address: id.address, xOnlyPubkey: id.xOnlyPubkey };
}

function addMember(config, orgId, { displayName, address, roles, note, expectedVersion }) {
  const org = loadOrgForUpdate(config, orgId, expectedVersion);
  const now = new Date().toISOString();
  const member = normalizeMember(
    {
      memberId: crypto.randomUUID(),
      displayName,
      ...resolveMemberAddress(config, address),
      roles,
      status: "ACTIVE",
      note,
      createdAt: now,
      updatedAt: now
    },
    org.members.length
  );
  const updated = { ...org, members: [...org.members, member], version: org.version + 1, updatedAt: now };
  saveOrg(config, updated);
  appendAudit(config, { kind: "metadata", orgId, action: "member_added", detail: member.displayName, memberId: member.memberId });
  return { org: updated, member };
}

function updateMember(config, orgId, memberId, { displayName, address, roles, note, status, expectedVersion }) {
  const org = loadOrgForUpdate(config, orgId, expectedVersion);
  const index = org.members.findIndex((m) => m.memberId === memberId);
  if (index < 0) throw fail("MEMBER_NOT_FOUND", `no member ${memberId} in organization ${orgId}`);
  const prev = org.members[index];
  const now = new Date().toISOString();
  const next = normalizeMember(
    {
      ...prev,
      ...(displayName !== undefined ? { displayName } : {}),
      ...(address !== undefined ? resolveMemberAddress(config, address) : {}),
      ...(roles !== undefined ? { roles } : {}),
      ...(note !== undefined ? { note } : {}),
      ...(status !== undefined ? { status } : {}),
      updatedAt: now
    },
    index
  );
  const members = [...org.members];
  members[index] = next;
  const updated = { ...org, members, version: org.version + 1, updatedAt: now };
  saveOrg(config, updated);
  appendAudit(config, { kind: "metadata", orgId, action: "member_updated", detail: next.displayName, memberId });
  return { org: updated, member: next };
}

function removeMember(config, orgId, memberId, { expectedVersion }) {
  const org = loadOrgForUpdate(config, orgId, expectedVersion);
  const member = org.members.find((m) => m.memberId === memberId);
  if (!member) throw fail("MEMBER_NOT_FOUND", `no member ${memberId} in organization ${orgId}`);
  const updated = {
    ...org,
    members: org.members.filter((m) => m.memberId !== memberId),
    version: org.version + 1,
    updatedAt: new Date().toISOString()
  };
  saveOrg(config, updated);
  appendAudit(config, { kind: "metadata", orgId, action: "member_removed", detail: member.displayName, memberId });
  return updated;
}

/* -------------------------------------------------- vault assignments */

function normalizeAssignments(input) {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    throw fail("ASSIGNMENTS_INVALID", "assignments record must be an object");
  }
  if (input.schema !== ASSIGNMENTS_SCHEMA) {
    throw fail("ASSIGNMENTS_SCHEMA_UNKNOWN", `unknown assignments schema ${JSON.stringify(input.schema)} — failing closed`);
  }
  if (!Number.isInteger(input.version) || input.version < 0) {
    throw fail("ASSIGNMENTS_INVALID", "assignments version must be a non-negative integer");
  }
  const map = input.assignments;
  if (!map || typeof map !== "object" || Array.isArray(map)) {
    throw fail("ASSIGNMENTS_INVALID", "assignments map must be an object");
  }
  const out = {};
  for (const [vaultId, a] of Object.entries(map)) {
    if (!VAULT_ID_RE.test(vaultId)) throw fail("ASSIGNMENTS_INVALID", `invalid vault id key ${vaultId}`);
    if (!a || typeof a !== "object") throw fail("ASSIGNMENTS_INVALID", `assignment for ${vaultId} must be an object`);
    requireOrgId(a.orgId);
    out[vaultId] = {
      orgId: a.orgId,
      group: a.group == null ? null : cleanText(a.group, `assignment ${vaultId} group`, { max: NAME_MAX }),
      assignedAt: cleanText(a.assignedAt, `assignment ${vaultId} assignedAt`, { max: 40, required: true })
    };
  }
  return { schema: ASSIGNMENTS_SCHEMA, version: input.version, assignments: out };
}

function loadAssignments(config) {
  const p = assignmentsPath(config);
  if (!fs.existsSync(p)) {
    return { schema: ASSIGNMENTS_SCHEMA, version: 0, assignments: {} };
  }
  return normalizeAssignments(readJsonStrict(p, "org assignments"));
}

function saveAssignments(config, record) {
  persistJsonDurably({ filePath: assignmentsPath(config), value: record });
  return record;
}

/*
 * Assign (or move) a vault to an organization. The map keyed by vaultId
 * structurally enforces ONE canonical organization per vault. This is
 * LOCAL POLICYVAULT METADATA: it never touches the chain, vault ids,
 * covenant ids, owners, delegates, or wallet authorization.
 */
function assignVault(config, { vaultId, orgId, group = null, expectedVersion, vaultExists }) {
  if (!VAULT_ID_RE.test(String(vaultId ?? ""))) throw fail("VAULT_ID_INVALID", "vaultId must be 32-byte hex");
  requireOrgId(orgId);
  const target = loadOrganization(config, orgId);
  if (!target) throw fail("ORG_NOT_FOUND", `no organization ${orgId}`);
  if (target.status === "ARCHIVED") throw fail("ORG_ARCHIVED", `organization ${orgId} is archived — restore it before assigning vaults`);
  if (typeof vaultExists === "function" && !vaultExists(vaultId)) {
    throw fail("VAULT_NOT_FOUND", `unknown vault ${vaultId}`);
  }
  const record = loadAssignments(config);
  if (!Number.isInteger(expectedVersion)) throw fail("VERSION_REQUIRED", "expectedVersion is required");
  if (record.version !== expectedVersion) {
    throw fail("VERSION_CONFLICT", `assignments changed (version ${record.version}, expected ${expectedVersion}) — reload and retry`);
  }
  const previous = record.assignments[vaultId] ?? null;
  const cleanGroup = group == null || String(group).trim() === "" ? null : cleanText(group, "group", { max: NAME_MAX });
  record.assignments[vaultId] = { orgId, group: cleanGroup, assignedAt: new Date().toISOString() };
  record.version += 1;
  saveAssignments(config, record);
  appendAudit(config, {
    kind: "metadata",
    orgId,
    vaultId,
    action: previous && previous.orgId !== orgId ? "vault_moved" : previous ? "vault_assignment_updated" : "vault_assigned",
    detail: previous && previous.orgId !== orgId ? `from ${previous.orgId}` : cleanGroup ?? undefined
  });
  return record.assignments[vaultId];
}

function unassignVault(config, { vaultId, expectedVersion }) {
  if (!VAULT_ID_RE.test(String(vaultId ?? ""))) throw fail("VAULT_ID_INVALID", "vaultId must be 32-byte hex");
  const record = loadAssignments(config);
  if (!Number.isInteger(expectedVersion)) throw fail("VERSION_REQUIRED", "expectedVersion is required");
  if (record.version !== expectedVersion) {
    throw fail("VERSION_CONFLICT", `assignments changed (version ${record.version}, expected ${expectedVersion}) — reload and retry`);
  }
  const previous = record.assignments[vaultId];
  if (!previous) throw fail("ASSIGNMENT_NOT_FOUND", `vault ${vaultId} is not assigned`);
  delete record.assignments[vaultId];
  record.version += 1;
  saveAssignments(config, record);
  appendAudit(config, { kind: "metadata", orgId: previous.orgId, vaultId, action: "vault_unassigned" });
  return { unassigned: true };
}

function assignmentFor(config, vaultId) {
  try {
    return loadAssignments(config).assignments[vaultId] ?? null;
  } catch {
    // Corrupt assignments never block vault presentation — the API layer
    // surfaces the corruption separately via loadAssignments' throw.
    return null;
  }
}

module.exports = {
  ORG_SCHEMA_V2,
  ASSIGNMENTS_SCHEMA,
  ROLE_LABELS,
  MEMBER_STATUS,
  ORG_STATUS,
  createOrganization,
  renameOrganization,
  archiveOrganization,
  restoreOrganization,
  deleteOrganization,
  loadOrganization,
  listOrganizations,
  addMember,
  updateMember,
  removeMember,
  loadAssignments,
  assignVault,
  unassignVault,
  assignmentFor,
  normalizeOrg,
  normalizeAssignments
};
