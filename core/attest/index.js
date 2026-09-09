"use strict";

/*
 * PolicyVault EXECUTION ATTESTATIONS — portable core, v1.
 *
 * Spec: docs/postlaunch/execution-attestation-spec.md
 * CLI:  tools/attestation-verify.js (zero dependencies, node only)
 *
 * Pure CommonJS, zero external dependencies, no sdk/ or server/ imports;
 * the only Node builtin reached is node:crypto sha256 (through
 * core/intent/canonical, which isolates it for a future WebCrypto
 * substitution). Safe to bundle for browser/mobile.
 *
 * Claim label: IMPLEMENTED + UNIT-TESTED (core/attest/test) + API-TESTED
 * (sdk/test/postlaunch-attestations-server.test.js). NOT VM-verified (it
 * touches no covenant), NOT externally reviewed. An attestation describes;
 * Kaspa consensus decides.
 */

const canonical = require("./canonical");
const schema = require("./schema");
const record = require("./record");
const verify = require("./verify");
const exporter = require("./export");
const summary = require("./summary");

module.exports = {
  /* versions + closed vocabularies */
  ATTESTATION_VERSION_1: schema.ATTESTATION_VERSION_1,
  BATCH_VERSION_1: schema.BATCH_VERSION_1,
  VERIFIER_VERSION_1: schema.VERIFIER_VERSION_1,
  SIGNATURE_SCHEME_1: schema.SIGNATURE_SCHEME_1,
  NOT_AVAILABLE: schema.NOT_AVAILABLE,
  LADDER: schema.LADDER,
  DECISIONS: schema.DECISIONS,
  DISPOSITIONS: schema.DISPOSITIONS,
  ASSET_KINDS: schema.ASSET_KINDS,
  DESTINATION_KINDS: schema.DESTINATION_KINDS,
  SUPPORTED_CONTRACT_VERSIONS: schema.SUPPORTED_CONTRACT_VERSIONS,
  BODY_KEYS: schema.BODY_KEYS,
  RECORD_KEYS: schema.RECORD_KEYS,

  /* canonical serialization + representation-independent hashing */
  ATTESTATION_HASH_DOMAIN_V1: canonical.ATTESTATION_HASH_DOMAIN_V1,
  canonicalJsonStringify: canonical.canonicalJsonStringify,
  attestationBodyOf: canonical.attestationBodyOf,
  computeAttestationHashV1: canonical.computeAttestationHashV1,

  /* build */
  AttestationError: record.AttestationError,
  buildExecutionAttestation: record.buildExecutionAttestation,
  attachSignature: record.attachSignature,
  recomputeAttestationHash: record.recomputeAttestationHash,
  approvalSignatureDigest: record.approvalSignatureDigest,

  /* verify (structure + expectation binding + optional chain facts) */
  VERDICTS: verify.VERDICTS,
  CHAIN_STATUS: verify.CHAIN_STATUS,
  verifyAttestation: verify.verifyAttestation,
  checkChainFacts: verify.checkChainFacts,
  addressesToQuery: verify.addressesToQuery,

  /* export / import */
  AttestationExportError: exporter.AttestationExportError,
  exportAttestationJson: exporter.exportAttestationJson,
  parseAttestationJson: exporter.parseAttestationJson,
  exportAttestationBatchNdjson: exporter.exportAttestationBatchNdjson,
  parseAttestationBatchNdjson: exporter.parseAttestationBatchNdjson,
  computeBatchDigest: exporter.computeBatchDigest,

  /* rendering + the binding language rules */
  FORBIDDEN_TERMS: summary.FORBIDDEN_TERMS,
  FORBIDDEN_PHRASES: summary.FORBIDDEN_PHRASES,
  SANCTIONED_VOCABULARY: summary.SANCTIONED_VOCABULARY,
  forbiddenLanguageHits: summary.forbiddenLanguageHits,
  assertNoForbiddenLanguage: summary.assertNoForbiddenLanguage,
  attestationSummary: Object.freeze({
    structured: summary.structured,
    humanReadable: summary.humanReadable
  })
};
