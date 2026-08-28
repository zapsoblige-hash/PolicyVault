"use strict";

/*
 * INSTANT HOSTED-LAYER AGENT SUSPEND (fullscale surface 21 residual;
 * docs/postlaunch/hosted-agent-suspend.md; migration 007).
 *
 * ============================ TRUST HONESTY ============================
 * THIS IS A COORDINATION CONTROL, NOT A COVENANT CONTROL. A suspension
 * makes THIS server refuse to build/finalize/submit NEW agent-driven
 * requests for the suspended agent — instantly, with zero fees and no
 * chain interaction. It does NOT and CANNOT bind the covenant: a
 * malicious actor holding the legitimate delegate key can still construct
 * and submit transactions directly to a Kaspa node, and only the
 * covenant's own consensus rules constrain what those transactions can
 * do. The covenant-enforced controls remain the security boundary and the
 * only controls that hold against that adversary:
 *   - ownerPause          — covenant-enforced freeze of ALL spending;
 *   - removeAgent / ownerSetAgentRoot — covenant-enforced removal of the
 *     agent's spending authority;
 *   - ownerRecover        — terminal recovery of all funds to the owner.
 * A suspension is the owner's INSTANT hosted stopgap while (or instead
 * of) executing one of those on-chain actions — useful precisely because
 * PolicyVault's hosted pipeline is how well-behaved agents/integrations
 * transact. Every API response and refusal from this module carries
 * NOT_COVENANT_NOTICE verbatim so no consumer can honestly mistake a
 * suspension for on-chain enforcement, and nothing anywhere treats a
 * suspension as satisfying, replacing, or weakening covenant pause.
 * =======================================================================
 *
 * Record: ONE per vault (platform-store AGENT_SUSPENSION, key = vaultId):
 *   { schema, vaultId, networkId, version, allAgents, agents: [xonly...],
 *     updatedAt, updatedBy: { type, identityId|null } }
 * with expectedVersion CAS (org-controls discipline). Strict fail-closed
 * validation; a stored record this build cannot understand REFUSES agent
 * operations rather than silently degrading to "not suspended" (the
 * restrictive direction — a corrupt security-configuration record must
 * never fail open).
 */

const { Categories, getPlatformStore } = require("./platform-store");

const AGENT_SUSPENSIONS_SCHEMA = "policyvault-agent-suspensions/v1";
const XONLY_RE = /^[0-9a-f]{64}$/;
const HEX64_RE = /^[0-9a-f]{64}$/;
const MAX_SUSPENDED_AGENTS = 4096; // the covenant registry maximum

const NOT_COVENANT_NOTICE =
  "Hosted coordination control only — NOT a covenant control. This suspension makes the PolicyVault server refuse new build/finalize/submit requests for the agent; it cannot stop a malicious holder of the delegate key from submitting transactions directly to a Kaspa node. Only covenant-enforced controls (ownerPause freeze, removeAgent/ownerSetAgentRoot, ownerRecover) bind that adversary on-chain. For covenant-enforced protection, pause the vault or remove the agent.";

function fail(status, code, message) {
  const e = new Error(message);
  e.status = status;
  e.code = code;
  return e;
}

function isPlainObject(v) {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

/* Strict record validation (fail closed — see the header). */
function normalizeSuspensions(input, vaultId, networkId) {
  if (!isPlainObject(input)) throw fail(500, "SUSPENSIONS_INVALID", "agent-suspensions record must be an object — failing closed (restrictive)");
  if (input.schema !== AGENT_SUSPENSIONS_SCHEMA) {
    throw fail(500, "SUSPENSIONS_SCHEMA_UNKNOWN", `unknown agent-suspensions schema ${JSON.stringify(input.schema)} — failing closed (restrictive)`);
  }
  if (input.vaultId !== vaultId) throw fail(500, "SUSPENSIONS_INVALID", "agent-suspensions vaultId does not match its key — failing closed");
  if (networkId !== undefined && input.networkId !== networkId) {
    throw fail(500, "SUSPENSIONS_INVALID", "agent-suspensions networkId does not match this server — failing closed");
  }
  if (!Number.isInteger(input.version) || input.version < 1) throw fail(500, "SUSPENSIONS_INVALID", "version must be a positive integer");
  if (typeof input.allAgents !== "boolean") throw fail(500, "SUSPENSIONS_INVALID", "allAgents must be a boolean");
  if (!Array.isArray(input.agents) || input.agents.length > MAX_SUSPENDED_AGENTS) {
    throw fail(500, "SUSPENSIONS_INVALID", `agents must be an array of at most ${MAX_SUSPENDED_AGENTS} x-only keys`);
  }
  const agents = [];
  const seen = new Set();
  for (const a of input.agents) {
    if (typeof a !== "string" || !XONLY_RE.test(a)) throw fail(500, "SUSPENSIONS_INVALID", "agents entries must be 64-hex x-only keys");
    if (seen.has(a)) throw fail(500, "SUSPENSIONS_INVALID", `agents duplicates ${a}`);
    seen.add(a);
    agents.push(a);
  }
  agents.sort();
  const by = isPlainObject(input.updatedBy) ? input.updatedBy : {};
  return {
    schema: AGENT_SUSPENSIONS_SCHEMA,
    vaultId,
    networkId: input.networkId,
    version: input.version,
    allAgents: input.allAgents,
    agents,
    updatedAt: typeof input.updatedAt === "string" ? input.updatedAt : new Date().toISOString(),
    updatedBy: {
      type: by.type === "wallet" || by.type === "machine" || by.type === "operator" ? by.type : "operator",
      identityId: typeof by.identityId === "string" ? by.identityId : null
    }
  };
}

function emptySuspensions(vaultId, networkId) {
  return {
    schema: AGENT_SUSPENSIONS_SCHEMA,
    vaultId,
    networkId,
    version: 0,
    allAgents: false,
    agents: [],
    updatedAt: null,
    updatedBy: null
  };
}

/*
 * Load the vault's suspension record (null-safe: a vault with no record
 * has nothing suspended). A CORRUPT/unknown stored record THROWS — callers
 * on the enforcement path convert that into a refusal of the agent
 * operation (restrictive), and the management routes surface it to the
 * owner for repair via a fresh suspend/unsuspend write.
 */
async function loadSuspensions(config, vaultId) {
  if (typeof vaultId !== "string" || !HEX64_RE.test(vaultId)) throw fail(400, "BAD_VAULT_ID", "vaultId must be 32-byte hex");
  const stored = await getPlatformStore(config).read(Categories.AGENT_SUSPENSION, vaultId);
  if (stored === null) return emptySuspensions(vaultId, config.networkId);
  return normalizeSuspensions(stored, vaultId, config.networkId);
}

/*
 * ENFORCEMENT READ (build/finalize/submit/simulate gates): is this agent
 * suspended for this vault right now? `agentPks` — every x-only identity
 * the caller can attribute to the acting agent (params.agentPk, the
 * stored request.agentPk, the resolved signer identity); ANY match
 * refuses. Returns { suspended, allAgents, matched } and never throws for
 * the no-record case; a corrupt record throws (restrictive — see header).
 */
async function checkAgentSuspension(config, vaultId, agentPks) {
  const record = await loadSuspensions(config, vaultId);
  if (record.allAgents) return { suspended: true, allAgents: true, matched: null, record };
  const set = new Set(record.agents);
  for (const pk of agentPks) {
    if (typeof pk === "string" && set.has(pk)) return { suspended: true, allAgents: false, matched: pk, record };
  }
  return { suspended: false, allAgents: false, matched: null, record };
}

/* The exact refusal every enforcement point throws — one code, one shape,
 * the covenant-honesty notice always attached. */
function suspendedError(check, action) {
  const who = check.allAgents ? "all agents of this vault are suspended" : `agent ${check.matched} is suspended`;
  const e = fail(
    403,
    "AGENT_SUSPENDED_HOSTED",
    `${who} at the hosted layer — refusing to ${action}. ${NOT_COVENANT_NOTICE}`
  );
  e.extra = { suspension: { allAgents: check.allAgents, agentPk: check.matched, notice: NOT_COVENANT_NOTICE } };
  return e;
}

/*
 * Mutate the vault's suspension state (owner wallet-session or a machine
 * identity holding vaults:suspend-agents — BOTH additionally tenancy-
 * checked to the vault OWNER by the route). op:
 *   suspend   + agentPk        — suspend one agent (must be a covenant
 *                                agent of the vault — typo fail-closed);
 *   suspend   + allAgents:true — suspend every agent of the vault;
 *   unsuspend + agentPk        — lift one agent's suspension (idempotent;
 *                                accepts keys no longer in the registry so
 *                                stale entries can always be cleared);
 *   unsuspend + allAgents:true — clear the all-agents flag (per-agent
 *                                entries persist unless also unsuspended).
 * expectedVersion (optional) CAS-guards against concurrent flips.
 */
async function updateSuspensions(config, vaultId, { op, agentPk, allAgents, expectedVersion, updatedBy, registryAgentPks }) {
  if (op !== "suspend" && op !== "unsuspend") throw fail(400, "BAD_SUSPENSION_OP", 'op must be "suspend" or "unsuspend"');
  const wantsAll = allAgents === true;
  if (wantsAll && agentPk !== undefined && agentPk !== null) throw fail(400, "BAD_SUSPENSION_OP", "pass agentPk OR allAgents:true, not both");
  if (!wantsAll) {
    if (typeof agentPk !== "string" || !XONLY_RE.test(agentPk)) throw fail(400, "BAD_AGENT_PK", "agentPk must be a 64-hex x-only key (or pass allAgents:true)");
  }
  const current = await loadSuspensions(config, vaultId);
  if (expectedVersion !== undefined && expectedVersion !== null && expectedVersion !== current.version) {
    throw fail(409, "VERSION_CONFLICT", `suspensions changed (version ${current.version}, expected ${expectedVersion}) — reload and retry`);
  }
  if (op === "suspend" && !wantsAll) {
    // fail closed on typos: suspending a key that is not a covenant agent
    // of this vault is a mistake, not a control (unsuspend stays permissive
    // so stale entries can always be cleared after removeAgent/rotate).
    if (Array.isArray(registryAgentPks) && !registryAgentPks.includes(agentPk)) {
      throw fail(422, "AGENT_UNKNOWN", `agent ${agentPk} is not a covenant agent of this vault — refusing to record a suspension for an unknown key`);
    }
  }
  let agents = current.agents.slice();
  let all = current.allAgents;
  if (op === "suspend") {
    if (wantsAll) all = true;
    else if (!agents.includes(agentPk)) agents.push(agentPk);
  } else {
    if (wantsAll) all = false;
    else agents = agents.filter((a) => a !== agentPk);
  }
  agents.sort();
  const record = normalizeSuspensions(
    {
      schema: AGENT_SUSPENSIONS_SCHEMA,
      vaultId,
      networkId: config.networkId,
      version: current.version + 1,
      allAgents: all,
      agents,
      updatedAt: new Date().toISOString(),
      updatedBy: updatedBy ?? { type: "operator", identityId: null }
    },
    vaultId,
    config.networkId
  );
  await getPlatformStore(config).write(Categories.AGENT_SUSPENSION, vaultId, record);
  return record;
}

/* API presentation — always carries the covenant-honesty notice. */
function presentSuspensions(record) {
  return {
    schema: record.schema,
    vaultId: record.vaultId,
    version: record.version,
    allAgents: record.allAgents,
    agents: [...record.agents],
    updatedAt: record.updatedAt,
    updatedBy: record.updatedBy,
    notice: NOT_COVENANT_NOTICE
  };
}

module.exports = {
  AGENT_SUSPENSIONS_SCHEMA,
  NOT_COVENANT_NOTICE,
  loadSuspensions,
  checkAgentSuspension,
  suspendedError,
  updateSuspensions,
  presentSuspensions
};
