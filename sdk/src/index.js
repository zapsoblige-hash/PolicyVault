"use strict";

/*
 * PolicyVault JS/TS SDK — curated public entry point.
 * (FULLSCALE_COMPLETION_ADDENDUM.md surface 9: "JavaScript/TypeScript SDK".)
 *
 * ANTI-BLOAT CONTRACT (addendum "ONE authoritative core"): this file
 * implements NOTHING. Every value below is a re-export of an existing
 * module — the sdk/src/* modules (which themselves re-export core/model/*)
 * and the portable core/* namespaces. There is deliberately no second
 * implementation of amount parsing, successor derivation, Merkle folding,
 * fee/mass, approval-package integrity, or intent verification here. If a
 * behavior needs to change, it changes in its owning module and this entry
 * inherits it; a re-export can never drift from what it re-exports.
 *
 * WHAT IS EXPORTED: the DETERMINISTIC, PORTABLE, EXTERNALLY-USEFUL surface
 * — the parts an integrator can run locally, offline, with no server, no
 * database, no RPC dial, and no host toolchain, to INDEPENDENTLY CHECK what
 * a PolicyVault deployment tells them. Plus one network client
 * (http-client.js) for talking to a PolicyVault server.
 *
 * WHAT IS DELIBERATELY NOT EXPORTED (and why) — see README.md "Not
 * exported" for the full list; briefly: hosted/operator-side modules
 * (store, manifest*, audit, organization, reconcile*, durable-json,
 * submission-claim, wallet-*), anything that dials a node or spawns the
 * silverc toolchain (chain, contract-compiler*, vault-builders*,
 * create/spend/lifecycle/recover-vault), process-environment config
 * (config.js), and the TEST-ONLY dev signer + key helpers (signer-dev,
 * keys). Those are the SERVER's business, not an SDK consumer's, and
 * exporting them would advertise a support surface PolicyVault does not
 * intend to keep stable. They remain reachable by deep path
 * (`require("policyvault-sdk/src/<module>.js")`, or a relative require,
 * which is exactly how server/, web/, tools/, and the test suites already
 * reach them) — nothing existing changes.
 *
 * STABILITY: the flat names below are the intended stable surface. The
 * namespace objects are the live module objects, exported verbatim, so
 * they carry each module's own versioning discipline (v3/v4 suffixes are
 * covenant-version identity, never "old/new" — a frozen covenant version
 * is never mutated in place; CLAUDE.md).
 */

/* ---- deterministic model modules (sdk/src -> core/model) ---------------- */
const amounts = require("./amounts");
const canonicalJson = require("./canonical-json");
const feeMass = require("./fee-mass");
const contractVersion = require("../../core/model/contract-version");

const vaultStateV3 = require("./vault-state-v3");
const vaultStateV4 = require("./vault-state-v4");
const vaultTransitionsV3 = require("./vault-transitions-v3");
const vaultTransitionsV4 = require("./vault-transitions-v4");

const recipientMerkleV3 = require("./recipient-merkle-v3");
const agentMerkleV4 = require("./agent-merkle-v4");

const approvalPackageV3 = require("./approval-package-v3");
const approvalPackageV4 = require("./approval-package-v4");
const frozenTxV3 = require("./frozen-tx-v3");

const computeBudgetV3 = require("./compute-budget-v3");
const computeBudgetV4 = require("./compute-budget-v4");

const uxNormalizeV4 = require("./ux-normalize-v4");
const addressIdentity = require("./address-identity");
const operationalStatus = require("./operational-status");
const donationAddress = require("./donation-address");

/* ---- portable core namespaces (pure CommonJS, zero external deps) ------- */
const intent = require("../../core/intent");
const signer = require("../../core/signer");
const explain = require("../../core/explain");
const governance = require("../../core/governance");

/* ---- network client ---------------------------------------------------- */
const httpClient = require("./http-client");

module.exports = Object.freeze({
  /* =====================================================================
   * FLAT SURFACE — the handful of things nearly every integrator needs.
   * Everything else is namespaced (below) because the same NAME legitimately
   * exists at more than one covenant version (MAX_APPROVERS, normalizeApprovers,
   * p2pkScriptHex, ...) and silently collapsing those would be exactly the
   * kind of version ambiguity CLAUDE.md's fail-closed rule forbids.
   * ===================================================================== */

  /* Numeric safety. ALL consensus/accounting values are integer sompi —
   * BigInt in, decimal STRING out. There is no Number path anywhere in
   * this SDK, by design (CLAUDE.md "Numeric safety"). parseSompi accepts
   * BigInt | canonical decimal string and rejects NaN/Infinity/negative/
   * unsafe/malformed input; kasToSompi/sompiToKas are the ONLY sanctioned
   * KAS<->sompi conversions. */
  SOMPI_PER_KAS: amounts.SOMPI_PER_KAS,
  MAX_SOMPI: amounts.MAX_SOMPI,
  parseSompi: amounts.parseSompi,
  parsePositiveSompi: amounts.parsePositiveSompi,
  kasToSompi: amounts.kasToSompi,
  sompiToKas: amounts.sompiToKas,

  /* Representation-independent hashing. Any integrity commitment whose
   * preimage is JSON MUST be built through this — the Phase G "G-2" bug
   * was a commitment preimage that depended on object key order, which
   * PostgreSQL jsonb silently reorders. Key-sorted, deterministic. */
  canonicalJsonStringify: canonicalJson.canonicalJsonStringify,

  /* Covenant/protocol version identity. Unknown versions FAIL CLOSED —
   * never route an unrecognized version to a default handler. */
  CONTRACT_VERSION: contractVersion.CONTRACT_VERSION, // v1 state-ID preimage tag
  CONTRACT_VERSION_V3: vaultStateV3.CONTRACT_VERSION_V3,
  CONTRACT_VERSION_V4: vaultStateV4.CONTRACT_VERSION_V4,
  CONTRACT_VERSION_V4_1: vaultStateV4.CONTRACT_VERSION_V4_1,
  SUPPORTED_COVENANT_VERSIONS: intent.SUPPORTED_COVENANT_VERSIONS,
  V4_ABIS: vaultStateV4.V4_ABIS,
  resolveV4Abi: vaultStateV4.resolveV4Abi,

  /* HTTP client for a PolicyVault server (see http-client.js). */
  PolicyVaultClient: httpClient.PolicyVaultClient,
  PolicyVaultApiError: httpClient.PolicyVaultApiError,
  PolicyVaultNetworkError: httpClient.PolicyVaultNetworkError,
  createClient: httpClient.createClient,
  randomIdempotencyKey: httpClient.randomIdempotencyKey,
  API_PREFIX: httpClient.API_PREFIX,
  V4_WALLET_REQUEST_SCHEMA_VERSION: httpClient.V4_WALLET_REQUEST_SCHEMA_VERSION,

  /* =====================================================================
   * NAMESPACES — each is the live module object, re-exported verbatim.
   * ===================================================================== */

  /* Amounts / canonical JSON / fee+mass, in full. feeMass covers exact
   * Kaspa mass computation, the minimum relay fee, the standard mass cap,
   * compute-budget validation, and exact-fee finalization — the arithmetic
   * an integrator needs to check a fee a server proposed. */
  amounts,
  canonicalJson,
  feeMass,

  /* Vault state: canonical normalization, state-ID computation, and JSON
   * round-tripping, per covenant version. computeStateId lets a client
   * verify that a state a server reports is the state whose ID the covenant
   * is actually bound to. */
  vaultStateV3,
  vaultStateV4,

  /* Successor derivation: given a before-state and an action's parameters,
   * derive the EXACT successor state the covenant will accept. This is the
   * local half of "the client independently detects server/frontend
   * manipulation before signing" — recompute the successor yourself and
   * compare, never adopt a server-supplied successor. */
  vaultTransitionsV3,
  vaultTransitionsV4,

  /* Merkle commitments. recipientMerkleV3 builds/proves authorized-recipient
   * roots (used by BOTH v0.3 recipient roots and each v0.4 agent's own
   * agentRecipientRoot); agentMerkleV4 builds/proves the v0.4 agent
   * registry root and folds policy updates (add/remove/rotate/re-policy/
   * spend accounting). Recompute roots locally; never adopt one. */
  recipientMerkleV3,
  agentMerkleV4,

  /* M-of-N approval packages + the frozen-transaction commitment they sign
   * over. The package-integrity assertions verify a collected package has
   * not been tampered with; frozenTxV3 canonicalizes and commits to the
   * exact transaction bytes an approver is being asked to endorse. */
  approvalPackageV3,
  approvalPackageV4,
  frozenTxV3,

  /* Script compute-budget selection/assertion (the covenant's VM budget). */
  computeBudgetV3,
  computeBudgetV4,

  /* Human-facing input normalization for v0.4 policies: budget periods
   * <-> DAA scores, agent-policy and approver input shapes. UX helpers —
   * they normalize INPUT, they never decide authority. */
  uxNormalizeV4,

  /* Address <-> x-only public key, and the required address prefix for a
   * network id. Network-aware and fail-closed on prefix mismatch. */
  addressIdentity,

  /* Durable wallet-request state -> operational status/summary, so a client
   * renders the SERVER's state machine rather than inventing its own. */
  operationalStatus,

  /* Voluntary-support (donation) address validation. Public receiving info
   * only — PolicyVault never asks for, stores, or signs with a seed,
   * private key, or wallet backup (docs/product-policy.md). */
  donationAddress,

  /* Transaction-intent manifest: canonical serialization, manifest hashing,
   * closed-schema validation, state diffing, and the FAIL-CLOSED verifier.
   * Portable core — pure CommonJS, no server/SDK imports. This is the
   * strongest local check available to an integrator: verify the manifest
   * a server hands you against the intent you actually requested, before
   * any signature exists. */
  intent,

  /* Universal Signer Interface: the capability descriptor/adapter contract,
   * the signing-request kinds, the error taxonomy, and the registry.
   * Implement this to plug your own signer (hardware, offline/CLI, mobile)
   * into PolicyVault — custody stays with the signer, never the server. */
  signer,

  /* Deterministic explanations (structured + human-readable) of an intent
   * manifest and of a governance authority-delta. Deterministic means an
   * agent and a human are shown the SAME derived facts. */
  explain,

  /* Governance canonicalization + authority-delta classification: does this
   * operation change financial authority, and how. */
  governance
});
