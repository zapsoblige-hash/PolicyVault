"use strict";

/*
 * PolicyVault post-launch governance core (Program B).
 *
 * Pure, dependency-free classification + canonical-encoding primitives
 * for policy-change governance. Design: docs/postlaunch/governance-spec.md.
 *
 * This package holds NO signing logic, NO storage, NO network access and
 * grants NO authority: covenant financial authority moves only through
 * owner/quorum wallet signatures over frozen transaction bytes, verified
 * by Kaspa consensus. Everything here is coordination logic layered
 * ABOVE that hard boundary.
 */

const canonical = require("./canonical");
const authorityDelta = require("./authority-delta");

module.exports = {
  ...canonical,
  ...authorityDelta
};
