"use strict";

/*
 * CONFORMANCE PATH REGISTRY (docs/postlaunch/conformance-suite-spec.md §4).
 *
 * Every agent-facing integration path that claims PolicyVault conformance
 * registers here with a DECLARED CAPABILITY SUBSET. The scenario matrix
 * consults these declarations: a capability a path declares is exercised
 * and must behave EQUIVALENTLY to every other declaring path; a capability
 * a path declares absent is a DOCUMENTED LIMITATION and the suite ASSERTS
 * the absence (the suite must fail if, e.g., the Python client silently
 * gains a local "verifier" or the MCP catalog gains an undocumented
 * mutating tool).
 *
 * Registering a new path:
 *   const { registerPath } = require("../conformance/paths");
 *   registerPath({ id, surface, kind, capabilities, limitations, notes });
 * then provide a driver exposing the ops for each declared capability and
 * pass it to the runner (see the spec doc §8 for the op contract). The
 * x402/AP2 protocol adapters are REGISTERED below (W4-refinements —
 * drivers/x402-driver.js, drivers/ap2-driver.js). Extra registration
 * modules can still be injected without editing this file via
 *   POLICYVAULT_CONFORMANCE_EXTRA_PATHS=/abs/mod1.js,/abs/mod2.js
 * (each module must export `register(registry)`) — the operator hook for
 * out-of-tree paths.
 */

/* Closed capability vocabulary — unknown keys fail closed at registration. */
const CAPABILITY_KEYS = Object.freeze([
  "discovery", // capability/version discovery document
  "vaultReads", // vault list/detail/audit
  "auditFeed", // global tenant-scoped activity feed
  "simulate", // dry-run simulation
  "build", // durable request build
  "requestReads", // request status/listing
  "eventsPolling", // GET /events cursor polling
  "approvals", // POST approvals (externally produced signatures)
  "rejectRequest", // cancel an open request
  "governanceReads",
  "riskReads",
  "webhooksManage",
  "callerIdempotencyKey", // caller supplies Idempotency-Key values
  "derivedIdempotencyKey", // path derives deterministic keys itself
  "schemaVersionOverride", // path can place an arbitrary schemaVersion in a body
  "localVerification" // independent local deterministic verification (JS core)
]);

const registry = [];

function registerPath(descriptor) {
  const { id, surface, kind, capabilities, limitations, notes } = descriptor;
  if (typeof id !== "string" || !/^[a-z0-9-]{1,32}$/.test(id)) throw new Error("registerPath: id must be a short lowercase slug");
  if (registry.some((p) => p.id === id)) throw new Error(`registerPath: duplicate path id ${id}`);
  if (!Number.isInteger(surface)) throw new Error("registerPath: surface (addendum surface number) required");
  if (typeof kind !== "string") throw new Error("registerPath: kind required");
  if (!capabilities || typeof capabilities !== "object") throw new Error("registerPath: capabilities object required");
  for (const k of Object.keys(capabilities)) {
    if (!CAPABILITY_KEYS.includes(k)) throw new Error(`registerPath: unknown capability ${JSON.stringify(k)} — the vocabulary is closed; extend it deliberately`);
    if (typeof capabilities[k] !== "boolean") throw new Error(`registerPath: capability ${k} must be boolean`);
  }
  const entry = Object.freeze({
    id,
    surface,
    kind,
    capabilities: Object.freeze({ ...capabilities }),
    limitations: Object.freeze([...(limitations ?? [])]),
    notes: notes ?? ""
  });
  registry.push(entry);
  return entry;
}

function allPaths() {
  return [...registry];
}

function pathsWith(capability) {
  if (!CAPABILITY_KEYS.includes(capability)) throw new Error(`pathsWith: unknown capability ${capability}`);
  return registry.filter((p) => p.capabilities[capability] === true);
}

/* ---- the three REAL reference paths (addendum surfaces 7 / 9 / 10) ---- */

registerPath({
  id: "js",
  surface: 9,
  kind: "in-process (sdk/src/http-client.js PolicyVaultClient over real HTTP)",
  capabilities: {
    discovery: true,
    vaultReads: true,
    auditFeed: true,
    simulate: true,
    build: true,
    requestReads: true,
    eventsPolling: true, // via the documented request() escape hatch
    approvals: true,
    rejectRequest: true,
    governanceReads: true,
    riskReads: true,
    webhooksManage: true, // via the documented request() escape hatch
    callerIdempotencyKey: true,
    derivedIdempotencyKey: false,
    schemaVersionOverride: true, // an explicit body schemaVersion wins over the pin
    localVerification: true // the JS runtime hosts the ONE authoritative core
  },
  limitations: [],
  notes: "Reference client; the only path co-resident with the portable core."
});

registerPath({
  id: "python",
  surface: 10,
  kind: "subprocess (python3 -m pv_conformance_driver; stdlib-only policyvault_client)",
  capabilities: {
    discovery: true,
    vaultReads: true,
    auditFeed: true,
    simulate: true,
    build: true,
    requestReads: true,
    eventsPolling: true, // via the client's own raw transport
    approvals: true,
    rejectRequest: true,
    governanceReads: true,
    riskReads: true,
    webhooksManage: true, // via raw transport
    callerIdempotencyKey: true,
    derivedIdempotencyKey: false,
    schemaVersionOverride: true, // via raw transport only (typed specs pin it)
    localVerification: false // ASSERTED ABSENT — python-client-spec.md asymmetry
  },
  limitations: [
    "NO local verification: Python has no port of the deterministic core; a caller needing independent verification runs the JS core. The suite asserts the package module/attribute surface stays transport-only (introspection lock)."
  ],
  notes: "Thin stdlib transport client."
});

registerPath({
  id: "mcp",
  surface: 7,
  kind: "subprocess over stdio (node mcp/server.js; newline-delimited JSON-RPC 2.0)",
  capabilities: {
    discovery: true, // policyvault_capabilities tool
    vaultReads: true,
    auditFeed: true,
    simulate: true,
    build: true, // policyvault_create_request
    requestReads: true,
    eventsPolling: false, // ASSERTED ABSENT in v1
    approvals: false, // ASSERTED ABSENT in v1
    rejectRequest: true, // policyvault_reject_request
    governanceReads: true,
    riskReads: true,
    webhooksManage: false, // ASSERTED ABSENT in v1
    callerIdempotencyKey: false, // ASSERTED: keys are DERIVED, never caller-supplied
    derivedIdempotencyKey: true,
    schemaVersionOverride: false, // ASSERTED: closed schemas refuse the field (structural pin)
    localVerification: false // thin adapter; holds no core
  },
  limitations: [
    "v1 mutating surface is EXACTLY {policyvault_create_request, policyvault_reject_request} — no sign/approve/submit/webhook/identity tools; the suite asserts the exact catalog.",
    "Idempotency-Key is derived (mcp1-sha256), replay = same JSON-RPC id + identical args; a caller cannot supply a key.",
    "schemaVersion is pinned from live discovery; tool args carrying schemaVersion are SCHEMA_REFUSED locally (never transmitted)."
  ],
  notes: "Thin adapter; every tool is a 1:1 route translation."
});

/* ---- the two protocol-adapter paths (addendum surfaces 27 / 28) ----
 *
 * PAY-FIRST TRANSLATORS, not general clients: each turns ONE untrusted
 * inbound protocol object (an x402 PAYMENT-REQUIRED header / an AP2
 * payment-mandate SD-JWT) into ONE closed PolicyVault intent and drives
 * it through the same authoritative pipeline as everyone else with a
 * six-scope machine credential. Internally each adapter runs
 * discovery/vault-read/simulate calls as MANDATORY PIPELINE STAGES —
 * but none of those are caller-drivable ops on its surface, so the
 * corresponding capabilities are declared ABSENT and the suite asserts
 * the surface stays that narrow (route locks + closed caller schemas).
 */

registerPath({
  id: "x402",
  surface: 27,
  kind: "separate-process HTTP service (integrations/x402/service.js over real HTTP; six-scope machine credential to the platform)",
  capabilities: {
    discovery: false, // internal network gate only — not exposed to callers
    vaultReads: false, // internal allowlist pre-check only
    auditFeed: false,
    simulate: false, // internal MANDATORY dry run only
    build: true, // an attempt performs a REAL durable platform build
    requestReads: false, // callers read the adapter's own attempt records, not platform requests
    eventsPolling: false,
    approvals: false,
    rejectRequest: false,
    governanceReads: false,
    riskReads: false,
    webhooksManage: false,
    callerIdempotencyKey: false, // ASSERTED: closed caller schema refuses the field
    derivedIdempotencyKey: true, // x402 spec §3.4: attemptId + requirement digest
    schemaVersionOverride: false, // callers never author platform bodies
    localVerification: false // thin translator; holds no core
  },
  limitations: [
    "Caller surface is EXACTLY {POST /x402/attempts, POST /x402/attempts/:id/delivery-result, GET /x402/attempts/:id, GET /healthz} — no vault/audit/event/governance/risk/approval/reject op exists to drive; the suite asserts unknown adapter routes refuse.",
    "Idempotency keys are DERIVED (attemptId + requirement digest): a caller cannot supply an Idempotency-Key (closed caller schema — unknown fields X402_CALLER_INPUT_INVALID); a mutated requirement under the same attemptId is a deterministic IDEMPOTENCY_KEY_CONFLICT, never a second spend.",
    "RESTRICTIVE-ONLY pay-first translator: every pre-build gate (network, allowlist, mandatory dry run) can only refuse, refusals are PURE (no durable request), and platform refusals surface verbatim (e.g. VAULT_NOT_FOUND, SIMULATION_FAILED) — never softened, never invented."
  ],
  notes: "x402 client/payer adapter; PolicyVault never emits a 402 of its own (free forever)."
});

registerPath({
  id: "ap2",
  surface: 28,
  kind: "separate-process HTTP service (integrations/ap2/service.js over real HTTP; PolicyVault as AP2 Credential Provider; six-scope machine credential to the platform)",
  capabilities: {
    discovery: false,
    vaultReads: false,
    auditFeed: false,
    simulate: false, // internal MANDATORY dry run only
    build: true,
    requestReads: false,
    eventsPolling: false,
    approvals: false,
    rejectRequest: false,
    governanceReads: false,
    riskReads: false,
    webhooksManage: false,
    callerIdempotencyKey: false, // ASSERTED: closed caller schema; key derives from transaction_id
    derivedIdempotencyKey: true, // ap2 spec §3.4: mandate transaction_id scope
    schemaVersionOverride: false,
    localVerification: false
  },
  limitations: [
    "Caller surface is EXACTLY {POST /ap2/payment-mandates, GET /ap2/attempts/:transactionId, GET /healthz} — no other op exists to drive; the suite asserts unknown adapter routes refuse.",
    "Idempotency keys are DERIVED from the mandate's transaction_id: replaying the same mandate converges on the ONE durable request; the same transaction_id with a different amount is a deterministic IDEMPOTENCY_KEY_CONFLICT.",
    "RESTRICTIVE-ONLY double destination binding: a mandate can never name a destination — payees resolve ONLY through the operator payee directory AND must already be covenant-allowlisted (AP2_PAYEE_UNKNOWN / AP2_PAYEE_NOT_ALLOWLISTED are free, pure refusals); a cryptographically valid mandate proves authorship, never authorization."
  ],
  notes: "AP2 Credential-Provider adapter; mandates are verified evidence, never spending authority."
});

/* Operator-supplied extra registrations (external/operator adapter suites). */
if (process.env.POLICYVAULT_CONFORMANCE_EXTRA_PATHS) {
  for (const mod of process.env.POLICYVAULT_CONFORMANCE_EXTRA_PATHS.split(",").map((s) => s.trim()).filter(Boolean)) {
    // eslint-disable-next-line global-require
    require(mod).register({ registerPath });
  }
}

module.exports = { registerPath, allPaths, pathsWith, CAPABILITY_KEYS };
