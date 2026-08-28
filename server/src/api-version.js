"use strict";

/* The API version string, single-sourced so server/src/api.js and
 * server/src/capabilities.js (GET /api/v1/capabilities) can never drift
 * from each other — extracted as its own tiny module purely to avoid a
 * require() cycle between the two (capabilities.js is required lazily
 * from inside api.js's route dispatch, well after api.js's own
 * module.exports is populated, but a top-level require("./api") from
 * capabilities.js would still be fragile to reorder api.js's require
 * graph around; a value with no behavior has no reason to risk that). */
const API_VERSION = "v1";

/*
 * Versioned platform schema (completion-standard surface 23) for the v0.4
 * wallet-request family's request/response bodies. ADDITIVE ONLY: a
 * caller MAY send `schemaVersion` in the request body; if present it MUST
 * equal this value (unknown/future versions fail closed — never routed to
 * a default) — see api.js assertSchemaVersion. Omitting it entirely keeps
 * TODAY'S exact behavior for every existing caller, including the shipped
 * web client, which never sends it. Every v0.4 wallet-request response
 * additionally carries this value as a top-level sibling field
 * (`{ request: {...}, schemaVersion }`) — an additive response field, not
 * a shape change.
 *
 * v1 shape note (residuals wave): a GENESIS request document's
 * `initialRegistry` field (full agent-registry leaf tuples + per-agent
 * recipient keys) is a DOCUMENTED, LOAD-BEARING part of this version's
 * presented response — it has been stored and presented since the v0.4
 * create flow existed, and the browser now recomputes the genesis
 * agentRoot from it (fail closed when absent). It is a pre-existing
 * field made contractual, not a shape change; no version bump.
 */
const V4_WALLET_REQUEST_SCHEMA_VERSION = "policyvault-wallet-v4-request/v1";

module.exports = { API_VERSION, V4_WALLET_REQUEST_SCHEMA_VERSION };
