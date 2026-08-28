"use strict";

/*
 * PolicyVault post-launch EXPLANATION layer (completion-standard item 6).
 *
 * Human-readable intent/governance explanations with structured API
 * equivalents, as a pure portable module:
 *
 *   intentExplain.structured / .humanReadable
 *     — explain a VERIFIED Transaction Intent Manifest (core/intent);
 *       refusal rendering for anything not a full verification pass.
 *   governanceExplain.structured / .humanReadable
 *     — explain a core/governance authority-delta result
 *       (REDUCTION/EXPANSION lanes, per-field lines, mixed/opaque
 *       expansion warnings).
 *   riskExplain.structured / .humanReadable
 *     — explain a risk evaluation (core/risk evaluateRisk result or the
 *       server's stored record): deny-wins composition narrated with the
 *       decision/codes/status RECOMPUTED from the per-adapter results
 *       (self-inconsistent records refuse — never narrated).
 *   kas helpers — exact integer sompi -> KAS decimal rendering
 *       (mirrors sdk/src/amounts.js sompiToKas semantics; see kas.js).
 *
 * Pure CommonJS, zero external dependencies, no SDK/server imports;
 * only core/intent and core/governance public exports are consumed.
 * Explanations render; they never authorize: covenant financial
 * authority moves only through wallet signatures over frozen
 * transaction bytes, verified by Kaspa consensus.
 *
 * Status: IMPLEMENTED + UNIT-TESTED (core/explain/test). Not
 * VM-verified, not testnet-verified; wired into no production path.
 */

const kas = require("./kas");
const intentExplain = require("./intent-explain");
const governanceExplain = require("./governance-explain");
const riskExplain = require("./risk-explain");

module.exports = {
  /* exact KAS rendering (integer math only) */
  SOMPI_PER_KAS: kas.SOMPI_PER_KAS,
  I64_MAX: kas.I64_MAX,
  parseCanonicalSompi: kas.parseCanonicalSompi,
  sompiToKasString: kas.sompiToKasString,
  kasAmount: kas.kasAmount,

  /* intent-manifest explanations */
  INTENT_EXPLANATION_VERSION_1: intentExplain.INTENT_EXPLANATION_VERSION_1,
  EXPLANATION_VERDICTS: intentExplain.EXPLANATION_VERDICTS,
  intentExplain: Object.freeze({
    structured: intentExplain.structured,
    humanReadable: intentExplain.humanReadable
  }),

  /* governance authority-delta explanations */
  GOVERNANCE_EXPLANATION_VERSION_1: governanceExplain.GOVERNANCE_EXPLANATION_VERSION_1,
  GOVERNANCE_EXPLANATION_VERDICTS: governanceExplain.GOVERNANCE_EXPLANATION_VERDICTS,
  governanceExplain: Object.freeze({
    structured: governanceExplain.structured,
    humanReadable: governanceExplain.humanReadable
  }),

  /* risk-evaluation explanations */
  RISK_EXPLANATION_VERSION_1: riskExplain.RISK_EXPLANATION_VERSION_1,
  RISK_EXPLANATION_VERDICTS: riskExplain.RISK_EXPLANATION_VERDICTS,
  riskExplain: Object.freeze({
    structured: riskExplain.structured,
    humanReadable: riskExplain.humanReadable
  })
};
