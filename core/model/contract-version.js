"use strict";

/*
 * Frozen protocol-identity constant, severed from sdk/src/config.js during
 * shared-core extraction step 1 — the ONLY value vault-state.js needed from
 * the impure config module (config reads process.env / fs and must not
 * enter the portable core).
 *
 * CONTRACT_VERSION participates in every v1 state-ID preimage
 * ("contract:<version>" line in computeStateId), so it is frozen
 * application identity, NOT deployment configuration: changing it would
 * re-identify every existing v1 vault state. Since extraction step 2,
 * sdk/src/config.js consumes THIS module (no duplicate literal exists);
 * core/model/test/contract-version-sync.test.js proves the single
 * sourcing and pins the frozen tag.
 */

const CONTRACT_VERSION = "policyvault-0.1-beta";

module.exports = { CONTRACT_VERSION };
