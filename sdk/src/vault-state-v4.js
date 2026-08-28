"use strict";
// Re-export shim: the implementation moved to ../../core/model/vault-state-v4.js (shared-core extraction step 2).
// The §35 G13 live-layer sabotage test mutates the REAL implementation at its
// core/model location (retarget sanctioned by the coordinator for step 2).
module.exports = require("../../core/model/vault-state-v4");
