/**
 * Type declarations for the PolicyVault SDK entry point (sdk/src/index.js).
 *
 * HONESTY NOTE. These are HAND-WRITTEN and deliberately NOT exhaustive.
 * The flat surface (amounts, canonical JSON, version identity, the HTTP
 * client) is typed precisely, because those contracts are small and frozen.
 * The namespaced deterministic modules are typed at the level the JavaScript
 * actually guarantees: normalized state, policies, and Merkle trees are
 * BigInt-bearing plain objects whose exact field sets live in
 * core/model/*.js, and restating every field here would create a second
 * description that can silently go stale. Where a precise type would be a
 * guess, the declaration says `NormalizedState` / `AgentTree` / an open
 * record and points at the owning module instead of inventing structure.
 *
 * The rule that matters more than any type here: NEVER `Number()` a sompi
 * value. Amounts are BigInt in JavaScript and decimal strings on the wire.
 */

export * from "./http-client";

/* ====================================================================== */
/* Numeric safety — canonical KAS <-> sompi (core/model/amounts.js)        */
/* ====================================================================== */

/** `100000000n` — sompi per KAS. */
export declare const SOMPI_PER_KAS: bigint;
/** Hard sanity ceiling (~29B KAS in sompi). Anything above fails closed. */
export declare const MAX_SOMPI: bigint;

/**
 * Parse an integer-sompi amount to BigInt. Accepts BigInt or a base-10
 * digit string. REJECTS `number` outright (floating-point risk), plus
 * negatives, malformed strings, and anything above MAX_SOMPI.
 */
export declare function parseSompi(value: bigint | string, field?: string): bigint;
/** As parseSompi, and additionally rejects zero. */
export declare function parsePositiveSompi(value: bigint | string, field?: string): bigint;
/** Parse a human KAS decimal string ("12", "0.5", "1.23456789") to BigInt sompi. Max 8 fractional digits; no exponents, no signs, no floats. */
export declare function kasToSompi(value: string, field?: string): bigint;
/** Render BigInt sompi as a canonical KAS decimal string, trailing zeros trimmed. */
export declare function sompiToKas(value: bigint | string, field?: string): string;

/* ====================================================================== */
/* Canonical JSON (core/model/canonical-json.js)                          */
/* ====================================================================== */

/**
 * Deterministic, strictly key-sorted JSON. MANDATORY for any integrity
 * commitment whose preimage is JSON: a preimage that depends on object key
 * order breaks the moment the value round-trips through PostgreSQL jsonb,
 * which reorders keys (the Phase G "G-2" fail-closed availability bug).
 */
export declare function canonicalJsonStringify(value: unknown): string;

/* ====================================================================== */
/* Covenant / protocol version identity — unknown versions FAIL CLOSED     */
/* ====================================================================== */

/** `"policyvault-0.1-beta"` — the v1 state-ID preimage tag. Frozen application identity, not configuration. */
export declare const CONTRACT_VERSION: string;
/** `"policyvault-0.3"` */
export declare const CONTRACT_VERSION_V3: string;
/** `"policyvault-0.4"` */
export declare const CONTRACT_VERSION_V4: string;
/** `"policyvault-0.4.1"` */
export declare const CONTRACT_VERSION_V4_1: string;
/** The covenant versions the intent core will verify. Anything else refuses. */
export declare const SUPPORTED_COVENANT_VERSIONS: readonly string[];
/** Per-version ABI descriptors for the v0.4 family. */
export declare const V4_ABIS: Readonly<Record<string, unknown>>;
/** Resolve a v0.4-family ABI by contract version. Throws on an unknown version — never returns a default. */
export declare function resolveV4Abi(contractVersion: string): unknown;

/* ====================================================================== */
/* Shared shapes for the deterministic namespaces                         */
/* ====================================================================== */

/**
 * A normalized covenant state: a plain object whose amount fields are
 * BigInt and whose root/approver fields are lowercase hex. The exact field
 * set is version-specific and owned by core/model/vault-state-v3.js /
 * vault-state-v4.js — treat it as opaque and produce it only via
 * `normalizeStateV3` / `normalizeStateV4`.
 */
export type NormalizedState = { readonly [field: string]: unknown };

/** A normalized covenant template (owner x-only, vaultId, ...). Produce via `normalizeTemplateV3` / `normalizeTemplateV4`. */
export type NormalizedTemplate = { readonly [field: string]: unknown };

/** A normalized v0.4 agent policy (BigInt budget/limit fields, hex keys/roots). Produce via `normalizeAgentPolicyV4`. */
export type AgentPolicy = { readonly [field: string]: unknown };

/** A built Merkle tree: its `root` plus the leaf/level data proof generation needs. */
export interface MerkleTree {
  root: string;
  readonly [field: string]: unknown;
}

/** A Merkle inclusion proof: sibling hashes plus the path bits that order them. */
export interface MerkleProof {
  siblingsHex: string[];
  pathBits: unknown;
  readonly [field: string]: unknown;
}

/** JSON-safe state (every amount rendered as a decimal string). */
export type StateJson = Record<string, string | string[]>;

/* ====================================================================== */
/* Namespaces — each is the live module object, re-exported verbatim       */
/* ====================================================================== */

/** Full core/model/amounts.js. */
export declare const amounts: {
  SOMPI_PER_KAS: bigint;
  MAX_SOMPI: bigint;
  parseSompi(value: bigint | string, field?: string): bigint;
  parsePositiveSompi(value: bigint | string, field?: string): bigint;
  kasToSompi(value: string, field?: string): bigint;
  sompiToKas(value: bigint | string, field?: string): string;
};

/** Full core/model/canonical-json.js. */
export declare const canonicalJson: {
  canonicalJsonStringify(value: unknown): string;
};

/**
 * Exact Kaspa mass/fee arithmetic (core/model/fee-mass.js) — the numbers a
 * client needs to check a fee a server proposed rather than trusting it.
 */
export declare const feeMass: {
  MINIMUM_RELAY_TRANSACTION_FEE: bigint;
  STANDARD_MASS_CAP: bigint;
  estimatedSerializedSize(tx: unknown): number;
  computeMass(tx: unknown): bigint;
  feeMass(tx: unknown): bigint;
  calculateRequiredFee(tx: unknown): bigint;
  describeWasmTransaction(transaction: unknown): unknown;
  /** Throws unless the observed compute budget equals the expected one. */
  validateComputeBudget(value: unknown, expected: unknown, label: string): void;
  finalizeWithExactFee(args: {
    transaction: unknown;
    signAll: unknown;
    changeIndex: number;
    totalInputValue: bigint;
    relayMargin?: bigint;
  }): unknown;
};

/** v0.3 vault state (core/model/vault-state-v3.js). */
export declare const vaultStateV3: {
  CONTRACT_VERSION_V3: string;
  MAX_APPROVERS: number;
  APPROVER_SENTINEL: string;
  normalizeTemplateV3(input: unknown): NormalizedTemplate;
  normalizeStateV3(input: unknown): NormalizedState;
  normalizeStateV3ForRecovery(input: unknown): NormalizedState;
  normalizeApprovers(input: unknown): string[];
  normalizeRecipientRoot(input: unknown): string;
  computeStateIdV3(args: { networkId: string; template: unknown; state: unknown; contractVersion?: string }): string;
  stateToJsonV3(state: unknown): StateJson;
};

/** v0.4 family vault state (core/model/vault-state-v4.js). */
export declare const vaultStateV4: {
  CONTRACT_VERSION_V4: string;
  CONTRACT_VERSION_V4_1: string;
  V4_ABIS: Readonly<Record<string, unknown>>;
  OWNER_OP_SELECTOR_V4_1: unknown;
  resolveV4Abi(contractVersion: string): unknown;
  MAX_APPROVERS: number;
  APPROVER_SENTINEL: string;
  normalizeTemplateV4(input: unknown): NormalizedTemplate;
  normalizeStateV4(input: unknown): NormalizedState;
  normalizeStateV4ForRecovery(input: unknown): NormalizedState;
  normalizeApprovers(input: unknown): string[];
  /** The state's covenant-bound identity. Recompute it; never adopt a reported one. */
  computeStateIdV4(args: { networkId: string; template: unknown; state: unknown; contractVersion?: string }): string;
  stateToJsonV4(state: unknown): StateJson;
};

/**
 * v0.3 successor derivation (core/model/vault-transitions-v3.js). Each
 * function returns the EXACT successor state the covenant will accept for
 * that action, or throws.
 */
export declare const vaultTransitionsV3: {
  MAX_APPROVERS: number;
  spendSuccessorV3(state: unknown, args: unknown): NormalizedState;
  rolloverSuccessorV3(state: unknown, args: unknown): NormalizedState;
  pauseSuccessorV3(state: unknown, pause: unknown): NormalizedState;
  revokeSuccessorV3(state: unknown, args: unknown): NormalizedState;
  rotateSuccessorV3(state: unknown, args: unknown): NormalizedState;
  topUpSuccessorV3(state: unknown, topUpAmount: bigint | string): NormalizedState;
  migrateSuccessorV3(state: unknown, args: unknown): NormalizedState;
  setRecipientRootSuccessorV3(state: unknown, newRoot: string): NormalizedState;
  setApproversSuccessorV3(state: unknown, args: unknown): NormalizedState;
  recoverPlanV3(state: unknown, ownerXOnly: string): unknown;
};

/**
 * v0.4 successor derivation (core/model/vault-transitions-v4.js). Recompute
 * the successor locally and compare it with what a server proposes — this
 * is how a client detects server/frontend manipulation BEFORE signing.
 */
export declare const vaultTransitionsV4: {
  MAX_PERIODS_ELAPSED: bigint;
  MAX_APPROVERS: number;
  agentSpendSuccessorV4(
    state: unknown,
    args: { agentPolicy: unknown; agentProof: unknown; payAmount: bigint | string; periodsElapsed: bigint | string; reserveConsumed: bigint | string }
  ): NormalizedState;
  setAgentRootSuccessorV4(state: unknown, newAgentRoot: string): NormalizedState;
  setApproversSuccessorV4(state: unknown, args: { approvers?: unknown; approverSlots?: unknown; approvalM: bigint | string | number }): NormalizedState;
  topUpSuccessorV4(state: unknown, topUpAmount: bigint | string): NormalizedState;
  topUpReserveSuccessorV4(state: unknown, topUpAmount: bigint | string): NormalizedState;
  pauseSuccessorV4(state: unknown, pause: unknown): NormalizedState;
  recoverPlanV4(state: unknown, ownerXOnly: string): unknown;
};

/**
 * Authorized-recipient Merkle commitments (core/model/recipient-merkle-v3.js).
 * Used by v0.3 recipient roots AND by each v0.4 agent's own
 * `agentRecipientRoot` — it is not "the old version".
 */
export declare const recipientMerkleV3: {
  MAX_DEPTH: number;
  MAX_RECIPIENTS: number;
  LEAF_DOMAIN: string;
  leafHash(recipientXOnlyHex: string): string;
  buildRecipientTree(recipientsInput: readonly string[]): MerkleTree;
  generateRecipientProof(tree: MerkleTree, recipientXOnlyHex: string): MerkleProof;
  verifyRecipientProof(args: unknown): boolean;
};

/** v0.4 agent-registry Merkle commitments + policy folding (core/model/agent-merkle-v4.js). */
export declare const agentMerkleV4: {
  AGENT_LEAF_DOMAIN: string;
  AGENT_PADDING_DOMAIN: string;
  PADDING_LEAF_HEX: string;
  MAX_AGENT_DEPTH: number;
  MAX_AGENTS: number;
  normalizeAgentPolicyV4(input: unknown): AgentPolicy;
  agentLeafPreimage(policyInput: unknown): Uint8Array;
  agentLeafHash(policyInput: unknown): string;
  buildAgentTreeV4(agentsInput: readonly unknown[]): MerkleTree;
  generateAgentProofV4(tree: MerkleTree, agentPkHex: string): MerkleProof;
  verifyAgentProofV4(args: { root: string; policy: unknown; siblingsHex: readonly string[]; pathBits: unknown }): boolean;
  foldLeafV4(leafBuffer: Uint8Array, siblingsHex: readonly string[], pathBits: unknown): string;
  foldAgentPolicyV4(policyInput: unknown, siblingsHex: readonly string[], pathBits: unknown): string;
  addAgentV4(tree: MerkleTree, policyInput: unknown): MerkleTree;
  removeAgentV4(tree: MerkleTree, agentPkHex: string): MerkleTree;
  updateAgentPolicyV4(tree: MerkleTree, policyInput: unknown): MerkleTree;
  rotateAgentV4(tree: MerkleTree, currentPkHex: string, newPolicyInput: unknown): MerkleTree;
  applyAgentSpendV4(tree: MerkleTree, agentPkHex: string, args: { newPeriodStartDaa: bigint | string; newPeriodSpent: bigint | string }): MerkleTree;
};

/** M-of-N approval packages, v0.3 (sdk/src/approval-package-v3.js). */
export declare const approvalPackageV3: {
  APPROVAL_PACKAGE_SCHEMA: string;
  PLACEHOLDER_APPROVAL: unknown;
  createApprovalPackageV3(args: unknown): unknown;
  /** Commitment over the package. Built with canonicalJsonStringify — key order can never affect it. */
  packageCommitmentV3(pkg: unknown): string;
  assertPackageIntegrity(pkg: unknown): void;
  submitApprovalV3(args: unknown): unknown;
  approvalsBlobV3(pkg: unknown): string;
  placeholderApprovalsBlob(count: number): string;
  missingSlots(pkg: unknown): number[];
  isCompleteV3(pkg: unknown): boolean;
  collectedCount(pkg: unknown): number;
  approvalPackageToJson(pkg: unknown): unknown;
  loadApprovalPackage(json: unknown): unknown;
  p2pkScriptHex(xOnlyHex: string): string;
};

/** M-of-N approval packages, v0.4 (sdk/src/approval-package-v4.js). */
export declare const approvalPackageV4: {
  APPROVAL_PACKAGE_SCHEMA_V4: string;
  PLACEHOLDER_APPROVAL: unknown;
  placeholderApprovalsBlob(count: number): string;
  p2pkScriptHex(xOnlyHex: string): string;
  createApprovalPackageV4(args: unknown): unknown;
  packageCommitmentV4(pkg: unknown): string;
  assertPackageIntegrityV4(pkg: unknown): void;
  submitApprovalV4(args: unknown): unknown;
  approvalsBlobV4(pkg: unknown): string;
  missingSlotsV4(pkg: unknown): number[];
  isCompleteV4(pkg: unknown): boolean;
  collectedCountV4(pkg: unknown): number;
  approvalPackageToJsonV4(pkg: unknown): unknown;
  loadApprovalPackageV4(json: unknown): unknown;
};

/**
 * The frozen transaction an approver commits to (sdk/src/frozen-tx-v3.js).
 * `frozenTxCommitment` is what a signature actually endorses — canonicalize
 * and commit locally rather than trusting a supplied commitment.
 */
export declare const frozenTxV3: {
  TX_PROBE_PATH: string;
  normalizeFrozenTxV3(input: unknown): unknown;
  canonicalFrozenTxJson(frozen: unknown): string;
  frozenTxCommitment(frozen: unknown): string;
  describeFrozenTx(frozen: unknown): unknown;
  verifyApprovalSignature(args: unknown): boolean;
  feeDescriptorFromFrozen(frozen: unknown): unknown;
  /** Requires the kaspa WASM module at call time (not at import time). */
  frozenToWasmTransaction(frozen: unknown, ...rest: unknown[]): unknown;
};

/** v0.3 script compute budget. */
export declare const computeBudgetV3: {
  V3_BUDGET: unknown;
  selectComputeBudgetV3(args: unknown): unknown;
  assertBudgetSufficient(args: unknown): void;
};

/** v0.4 script compute budget. */
export declare const computeBudgetV4: {
  V4_BUDGET: unknown;
  selectComputeBudgetV4(args: unknown): unknown;
  assertBudgetSufficientV4(args: unknown): void;
};

/**
 * Human input normalization for v0.4 policies (sdk/src/ux-normalize-v4.js).
 * Normalizes INPUT; it never decides authority.
 */
export declare const uxNormalizeV4: {
  DAA_PER_SECOND: number;
  PERIOD_PRESETS: unknown;
  UNIT_SECONDS: unknown;
  MIN_PERIOD_DAA: bigint;
  MAX_PERIOD_DAA: bigint;
  MAX_APPROVERS: number;
  DEFAULT_AGENT_MAX_FEE_PER_TX_KAS: string;
  budgetPeriodToDaa(input: unknown): bigint;
  daaToHumanPeriod(daa: bigint | string): unknown;
  normalizeAgentPolicyInputV4(input: unknown): unknown;
  normalizeApproversInputV4(input: unknown): unknown;
};

/** Address <-> x-only public key, network-aware and fail-closed on prefix mismatch. */
export declare const addressIdentity: {
  resolveAddressIdentity(args: unknown): unknown;
  addressForXOnlyPubkey(xOnlyHex: string, networkId: string): string;
  /** e.g. `"kaspa"` for mainnet, `"kaspatest"` for testnet. */
  requiredAddressPrefix(networkId: string): string;
};

/** Durable wallet-request state -> operational status/summary for display. */
export declare const operationalStatus: {
  OperationalStatus: Readonly<Record<string, string>>;
  deriveOperationalStatus(request: unknown): string;
  requestSummary(request: unknown): unknown;
};

/** Voluntary-support (donation) address validation. Public receiving info only. */
export declare const donationAddress: {
  validateDonationAddress(address: unknown, ...rest: unknown[]): unknown;
  SUPPORTED_TYPES: readonly string[];
};

/* ---------------------------------------------------------------------- */
/* Portable core namespaces                                               */
/* ---------------------------------------------------------------------- */

/** The result of `intent.verifyIntentManifest` — fail-closed by construction. */
export interface IntentVerificationResult {
  ok: boolean;
  /** `"VERIFIED_EXACT"` or `"REFUSED"`. */
  verdict: string;
  /** The verified statement string when ok, otherwise null. */
  statement: string | null;
  manifestHash: string | null;
  txId: string | null;
  checks: ReadonlyArray<unknown>;
  /** Structured remediation codes; empty exactly when ok. */
  failures: ReadonlyArray<{ code: string; detail?: unknown }>;
}

/**
 * Transaction-intent manifests (core/intent) — canonical serialization,
 * manifest hashing, closed-schema validation, state diffing, and the
 * fail-closed verifier. Pure CommonJS, no server/SDK imports, browser- and
 * mobile-portable. This is the strongest local check available: verify the
 * manifest a server hands you against the intent you actually requested,
 * BEFORE any signature exists.
 */
export declare const intent: {
  MANIFEST_HASH_DOMAIN_V1: string;
  MANIFEST_VERSION_1: string;
  REQUESTED_INTENT_VERSION_1: string;
  SUPPORTED_COVENANT_VERSIONS: readonly string[];
  ACTIONS: Readonly<Record<string, unknown>>;
  HIGH_LEVEL_TO_SDK: Readonly<Record<string, string>>;
  VERIFIED_STATEMENT: string;
  VERDICTS: Readonly<Record<string, string>>;
  canonicalJsonStringify(value: unknown): string;
  sha256Hex(input: string | Uint8Array): string;
  /** Throws if `manifestHash` is present — strip it before hashing. */
  computeManifestHashV1(manifestBody: Record<string, unknown>): string;
  canonicalEqual(a: unknown, b: unknown): boolean;
  validateRequestedIntent(intent: unknown): unknown;
  validateManifest(manifest: unknown): unknown;
  buildIntentManifest(inputs: unknown): unknown;
  diffStates(before: unknown, after: unknown): unknown;
  verifyIntentManifest(args: { manifest: unknown; requestedIntent: unknown; decodedTransaction: unknown }): IntentVerificationResult;
  readonly [name: string]: unknown;
};

/**
 * Universal Signer Interface (core/signer) — the adapter/capability
 * contract to implement for your own signer. Custody stays with the signer;
 * the server never holds keys.
 */
export declare const signer: {
  SIGNER_INTERFACE_VERSION: string;
  SignerErrorCodes: Readonly<Record<string, string>>;
  SignerError: new (...args: any[]) => Error;
  SIGNATURE_SCHEMES: Readonly<Record<string, string>>;
  SIGNER_NETWORKS: Readonly<Record<string, string>>;
  ADAPTER_KINDS: Readonly<Record<string, string>>;
  CAPABILITY_FEATURES: Readonly<Record<string, string>>;
  REQUEST_KINDS: Readonly<Record<string, string>>;
  SIGNING_STATES: Readonly<Record<string, string>>;
  validateCapabilityDescriptor(descriptor: unknown): unknown;
  validateAdapter(adapter: unknown): unknown;
  SignerRegistry: new (...args: any[]) => unknown;
  negotiateCapabilities(...args: unknown[]): unknown;
  requireCapabilities(...args: unknown[]): unknown;
  normalizePublicKeyToXOnly(publicKey: string): string;
  createMessageSigningRequest(args: unknown): unknown;
  createTransactionSigningRequest(args: unknown): unknown;
  assertSigningRequest(request: unknown): unknown;
  readonly [name: string]: unknown;
};

/**
 * Deterministic explanations (core/explain) — structured + human-readable
 * renderings of an intent manifest and of a governance authority delta, so
 * an agent and a human are shown the SAME derived facts.
 */
export declare const explain: {
  SOMPI_PER_KAS: bigint;
  I64_MAX: bigint;
  parseCanonicalSompi(value: unknown, field?: string): bigint;
  sompiToKasString(value: bigint | string): string;
  kasAmount(value: unknown): unknown;
  INTENT_EXPLANATION_VERSION_1: string;
  EXPLANATION_VERDICTS: Readonly<Record<string, string>>;
  intentExplain: Readonly<{ structured(...args: unknown[]): unknown; humanReadable(...args: unknown[]): string }>;
  GOVERNANCE_EXPLANATION_VERSION_1: string;
  GOVERNANCE_EXPLANATION_VERDICTS: Readonly<Record<string, string>>;
  governanceExplain: Readonly<{ structured(...args: unknown[]): unknown; humanReadable(...args: unknown[]): string }>;
};

/** Governance canonicalization + authority-delta classification (core/governance). */
export declare const governance: {
  readonly [name: string]: unknown;
};
