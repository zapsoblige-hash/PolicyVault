"use strict";

/*
 * PolicyVault Universal Signer Interface v1 — public entry point.
 *
 * Spec: docs/postlaunch/signer-interface-spec.md
 * KasWare mapping: docs/postlaunch/signer-kasware-mapping.md
 *
 * Pure Node CommonJS. Zero external dependencies. No imports from
 * server/ or sdk/.
 */

const errors = require("./errors");
const iface = require("./interface");
const { createMockSignerAdapter, DEFAULT_ACCOUNTS } = require("./mock-adapter");

module.exports = {
  /* errors.js */
  SIGNER_INTERFACE_VERSION: errors.SIGNER_INTERFACE_VERSION,
  SignerErrorCodes: errors.SignerErrorCodes,
  SignerError: errors.SignerError,
  signerError: errors.signerError,
  isSignerError: errors.isSignerError,
  isKnownErrorCode: errors.isKnownErrorCode,
  assertKnownErrorCode: errors.assertKnownErrorCode,
  normalizeAdapterFailure: errors.normalizeAdapterFailure,

  /* interface.js */
  SIGNATURE_SCHEMES: iface.SIGNATURE_SCHEMES,
  SIGNER_NETWORKS: iface.SIGNER_NETWORKS,
  ADAPTER_KINDS: iface.ADAPTER_KINDS,
  CAPABILITY_FEATURES: iface.CAPABILITY_FEATURES,
  REQUEST_KINDS: iface.REQUEST_KINDS,
  SIGNING_STATES: iface.SIGNING_STATES,
  SIGHASH_ALL: iface.SIGHASH_ALL,
  REQUIRED_METHODS: iface.REQUIRED_METHODS,
  FEATURE_METHODS: iface.FEATURE_METHODS,
  validateCapabilityDescriptor: iface.validateCapabilityDescriptor,
  validateAdapter: iface.validateAdapter,
  SignerRegistry: iface.SignerRegistry,
  negotiateCapabilities: iface.negotiateCapabilities,
  requireCapabilities: iface.requireCapabilities,
  normalizePublicKeyToXOnly: iface.normalizePublicKeyToXOnly,
  assertCanonicalSignInputs: iface.assertCanonicalSignInputs,
  createMessageSigningRequest: iface.createMessageSigningRequest,
  createTransactionSigningRequest: iface.createTransactionSigningRequest,
  assertSigningRequest: iface.assertSigningRequest,
  validateSignatureResponse: iface.validateSignatureResponse,
  validateSignedTransactionResponse: iface.validateSignedTransactionResponse,
  executeSigning: iface.executeSigning,

  /* mock-adapter.js */
  createMockSignerAdapter,
  MOCK_DEFAULT_ACCOUNTS: DEFAULT_ACCOUNTS
};
