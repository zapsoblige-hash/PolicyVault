"use strict";

/*
 * PolicyVault Transaction Intent Manifest — portable core, v1.
 *
 * Spec: docs/postlaunch/intent-manifest-spec.md
 * Status: IMPLEMENTED + UNIT-TESTED (core/intent/test). Pure CommonJS,
 * zero external dependencies, no server/SDK imports.
 */

const canonical = require("./canonical");
const manifest = require("./manifest");
const verify = require("./verify");

module.exports = {
  /* canonical serialization + representation-independent hashing */
  MANIFEST_HASH_DOMAIN_V1: canonical.MANIFEST_HASH_DOMAIN_V1,
  canonicalJsonStringify: canonical.canonicalJsonStringify,
  sha256Hex: canonical.sha256Hex,
  computeManifestHashV1: canonical.computeManifestHashV1,
  canonicalEqual: canonical.canonicalEqual,

  /* schema + validation + build */
  MANIFEST_VERSION_1: manifest.MANIFEST_VERSION_1,
  REQUESTED_INTENT_VERSION_1: manifest.REQUESTED_INTENT_VERSION_1,
  SUPPORTED_COVENANT_VERSIONS: manifest.SUPPORTED_COVENANT_VERSIONS,
  ACTIONS: manifest.ACTIONS,
  HIGH_LEVEL_TO_SDK: manifest.HIGH_LEVEL_TO_SDK,
  STATE_FIELDS: manifest.STATE_FIELDS,
  AGENT_POLICY_FIELDS: manifest.AGENT_POLICY_FIELDS,
  ACCOUNTING_FIELDS: manifest.ACCOUNTING_FIELDS,
  parseAmount: manifest.parseAmount,
  parsePositiveAmount: manifest.parsePositiveAmount,
  requireInt: manifest.requireInt,
  requireHex: manifest.requireHex,
  p2pkScriptHex: manifest.p2pkScriptHex,
  validateStateShape: manifest.validateStateShape,
  validateAgentPolicyShape: manifest.validateAgentPolicyShape,
  validateRequestedIntent: manifest.validateRequestedIntent,
  validateTransactionShape: manifest.validateTransactionShape,
  validateManifest: manifest.validateManifest,
  diffStates: manifest.diffStates,
  buildIntentManifest: manifest.buildIntentManifest,

  /* fail-closed verification */
  VERIFIED_STATEMENT: verify.VERIFIED_STATEMENT,
  VERDICTS: verify.VERDICTS,
  verifyIntentManifest: verify.verifyIntentManifest
};
