"use strict";

/*
 * PolicyVault Universal Signer Interface v2 — public entry point.
 *
 * Spec: docs/postlaunch/signer-interface-v2-spec.md
 * v1 (frozen, still supported, still exported from core/signer): see
 * docs/postlaunch/signer-interface-spec.md.
 *
 * Additive by construction: requiring this module does not change,
 * shadow, or re-export v1 behaviour. A consumer may hold both a v1 and a
 * v2 registry; version strings are matched by exact equality in both
 * directions, so a descriptor or request of the wrong version is refused
 * with INTERFACE_VERSION_UNSUPPORTED rather than silently adapted.
 *
 * The Node-only CLI signer adapter is deliberately NOT re-exported here
 * (it loads kaspa-wasm and the filesystem): require
 * `core/signer/v2/adapters/cli` directly, exactly as v1 does.
 */

const errors = require("./errors");
const iface = require("./interface");
const { createMockSignerAdapterV2, DEFAULT_ACCOUNTS } = require("./mock-adapter");
const lift = require("./adapters/lift");
const kasware = require("./adapters/kasware");
const airgap = require("./adapters/airgap");

module.exports = {
  /* errors.js */
  SIGNER_INTERFACE_VERSION_V2: errors.SIGNER_INTERFACE_VERSION_V2,
  SignerErrorCodesV2: errors.SignerErrorCodesV2,
  SignerErrorV2: errors.SignerErrorV2,
  signerErrorV2: errors.signerErrorV2,
  isSignerErrorV2: errors.isSignerErrorV2,
  isKnownErrorCodeV2: errors.isKnownErrorCodeV2,
  assertKnownErrorCodeV2: errors.assertKnownErrorCodeV2,
  normalizeAdapterFailureV2: errors.normalizeAdapterFailureV2,

  /* interface.js — vocabularies */
  SIGNATURE_SCHEMES: iface.SIGNATURE_SCHEMES,
  SIGNER_NETWORKS: iface.SIGNER_NETWORKS,
  ADAPTER_KINDS: iface.ADAPTER_KINDS,
  CAPABILITY_FEATURES: iface.CAPABILITY_FEATURES,
  REQUEST_KINDS: iface.REQUEST_KINDS,
  SIGHASH_ALL: iface.SIGHASH_ALL,
  SIGHASH_FLAGS: iface.SIGHASH_FLAGS,
  TRANSACTION_FORMATS: iface.TRANSACTION_FORMATS,
  PSKT_ROLES: iface.PSKT_ROLES,
  TRANSPORT_KINDS: iface.TRANSPORT_KINDS,
  USER_PRESENCE_MODES: iface.USER_PRESENCE_MODES,
  CANCELLATION_MODES: iface.CANCELLATION_MODES,
  SIGNING_STATES_V2: iface.SIGNING_STATES_V2,
  REQUIRED_METHODS_V2: iface.REQUIRED_METHODS_V2,
  FEATURE_METHODS_V2: iface.FEATURE_METHODS_V2,
  DESCRIPTOR_KEYS_V2: iface.DESCRIPTOR_KEYS_V2,
  REQUIREMENT_KEYS_V2: iface.REQUIREMENT_KEYS_V2,
  ENVELOPE_KEYS: iface.ENVELOPE_KEYS,
  MIN_TTL_MS: iface.MIN_TTL_MS,
  MAX_TTL_MS: iface.MAX_TTL_MS,
  POLICYVAULT_TRANSACTION_REQUIREMENTS: iface.POLICYVAULT_TRANSACTION_REQUIREMENTS,

  /* interface.js — behaviour */
  validateCapabilityDescriptorV2: iface.validateCapabilityDescriptorV2,
  validateProbeReport: iface.validateProbeReport,
  verifyDeclaredCapabilities: iface.verifyDeclaredCapabilities,
  validateAdapterV2: iface.validateAdapterV2,
  SignerRegistryV2: iface.SignerRegistryV2,
  negotiateCapabilitiesV2: iface.negotiateCapabilitiesV2,
  requireCapabilitiesV2: iface.requireCapabilitiesV2,
  normalizePublicKeyToXOnly: iface.normalizePublicKeyToXOnly,
  assertCanonicalSignInputsV2: iface.assertCanonicalSignInputsV2,
  createMessageSigningRequestV2: iface.createMessageSigningRequestV2,
  createTransactionSigningRequestV2: iface.createTransactionSigningRequestV2,
  assertSigningRequestV2: iface.assertSigningRequestV2,
  buildResponseEnvelope: iface.buildResponseEnvelope,
  validateResponseEnvelope: iface.validateResponseEnvelope,
  createReplayGuard: iface.createReplayGuard,
  createCancellationToken: iface.createCancellationToken,
  executeSigningV2: iface.executeSigningV2,

  /* adapters (portable ones only — see the header) */
  liftV1Adapter: lift.liftV1Adapter,
  KASWARE_V2_DECLARATIONS: kasware.KASWARE_V2_DECLARATIONS,
  probeKasWareProvider: kasware.probeKasWareProvider,
  kaswareProviderMethodNames: kasware.providerMethodNames,
  createAirGapSignerAdapter: airgap.createAirGapSignerAdapter,
  AIRGAP_LIMITATIONS: airgap.AIRGAP_LIMITATIONS,

  /* mock-adapter.js */
  createMockSignerAdapterV2,
  MOCK_V2_DEFAULT_ACCOUNTS: DEFAULT_ACCOUNTS
};
