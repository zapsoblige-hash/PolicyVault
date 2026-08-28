"use strict";

/*
 * PolicyVault post-launch risk adapter framework core (Program D).
 *
 * Pure, dependency-free adapter contract + deny-wins composition.
 * Design: docs/postlaunch/risk-adapter-spec.md.
 *
 * Hard invariant: adapters can only make PolicyVault MORE restrictive.
 * A risk ALLOW never bypasses covenant policy; a covenant/policy DENY
 * is final (applyRiskToPolicyDecision is structurally incapable of
 * upgrading it); adapter errors, timeouts, and unknown verdicts resolve
 * to REVIEW or DENY, never ALLOW.
 */

const iface = require("./interface");
const compose = require("./compose");
const mocks = require("./mock-adapters");

module.exports = {
  ...iface,
  ...compose,
  mocks
};
