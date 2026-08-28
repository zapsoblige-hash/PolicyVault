/**
 * Type declarations for sdk/src/http-client.js — the PolicyVault API client.
 *
 * HONESTY NOTE (read this before trusting a type here). These declarations
 * are HAND-WRITTEN against server/src/api.js and
 * docs/postlaunch/platform-agent-api-spec.md. Response bodies are typed
 * where the server's shape is a stable, versioned contract (the health,
 * capabilities, simulation, and error envelopes) and left as
 * `PolicyVaultResponse` — an open record — everywhere else. That is
 * deliberate: inventing a precise `Vault` or `WalletRequest` interface here
 * would create a SECOND, drift-prone description of a shape whose single
 * source of truth is the server, and a stale type that says a field exists
 * is worse than no type at all. Where the server stamps a `schemaVersion`,
 * pin THAT at runtime — it is the guarantee that actually holds.
 *
 * AMOUNTS ARE STRINGS. Every consensus/accounting value crossing this API
 * is an integer-sompi decimal STRING (`Sompi` below), never a `number`.
 * `JSON.parse` would destroy a u64 as an IEEE-754 double. Parse them with
 * `parseSompi` from the SDK entry point.
 */

/**
 * An integer-sompi amount as a base-10 digit string, e.g. `"150000000"`.
 * Never a `number`: u64 amounts exceed IEEE-754's exact-integer range.
 */
export type Sompi = string;

/** An open JSON object body. See the honesty note above. */
export type PolicyVaultResponse = { [key: string]: unknown };

/** The server's error envelope, carried verbatim onto PolicyVaultApiError. */
export interface ApiErrorEnvelope {
  error: {
    /** Machine-readable refusal code, e.g. `"SCOPE_FORBIDDEN"`, `"IDEMPOTENCY_KEY_CONFLICT"`. */
    code: string;
    message: string;
    /** Route-specific extras (`request`, `idempotency`, ...) are additive siblings. */
    [key: string]: unknown;
  };
}

/** Present on any response to a call that carried an `Idempotency-Key`. */
export interface IdempotencyMarker {
  /** `true` when the server replayed a previously recorded outcome instead of re-executing. */
  replayed: boolean;
  key: string;
}

/** `GET /health` — liveness. */
export interface HealthBody extends PolicyVaultResponse {
  ok: true;
  api: string;
  networkId: string;
  authMode: string;
  buildId?: string;
  staging?: true;
}

/** `GET /health/ready` — readiness. A NOT-ready server answers 503, i.e. a thrown PolicyVaultApiError. */
export interface ReadyBody extends PolicyVaultResponse {
  ready: boolean;
  reason?: string;
  networkId: string;
  buildId?: string;
}

/**
 * `GET /capabilities` — the discovery document (surface 22). Generated
 * server-side from code truth, not prose, so it is safe to branch on.
 */
export interface CapabilitiesBody extends PolicyVaultResponse {
  schemaVersion: string;
  apiVersion: string;
  networkId: string;
  buildId?: string;
  contract: {
    supportedCovenantVersions: string[];
    currentV4Versions: string[];
  };
  actions: {
    /** Each v0.4 action with the signer ROLE it requires (`"owner"` | `"agent"`). */
    v4: Array<{ action: string; role: string }>;
  };
  scopes: Array<{ scope: string; description: string }>;
  /** Every schemaVersion string this build understands, by surface. */
  schemas: { [surface: string]: string };
  limits: PolicyVaultResponse;
  features: { [feature: string]: boolean };
}

/**
 * `POST /wallet/v4/simulate` — a dry run of the REAL pipeline that persists
 * nothing, consumes no gate, and never broadcasts. A well-formed body always
 * answers 200; a malformed body is a real 4xx.
 */
export interface SimulationBody extends PolicyVaultResponse {
  schemaVersion: string;
  simulation: {
    /** `true` = the real call would proceed; `false` = it would refuse (see refusalReason). */
    ok: boolean;
    /** Present when `ok` is false — the exact refusal the real route would have produced. */
    refusalReason?: { status: number; code: string; message: string };
    governance?: PolicyVaultResponse;
    risk?: PolicyVaultResponse;
    review?: PolicyVaultResponse;
    intent?: PolicyVaultResponse;
    /** What the real call would still require: approvals, a proposal, a risk release. */
    wouldRequire?: PolicyVaultResponse;
    /** Always reported as skipped: a dry run has no signature to verify. */
    vmPreflight?: { skipped: true; reason: string };
    [key: string]: unknown;
  };
  idempotency?: IdempotencyMarker;
}

/** Per-call options accepted by every client method. */
export interface RequestOptions {
  /**
   * `undefined` (default on POST) — a fresh key is generated per call.
   * A string — your key; retrying with it is guaranteed at-most-once execution.
   * `null` — send no key at all (byte-identical to a pre-platform caller).
   * Ignored on GET.
   */
  idempotencyKey?: string | null;
  /** Extra headers for this call. Cannot override `Authorization`. */
  headers?: Record<string, string>;
  /** Standard fetch abort signal. */
  signal?: AbortSignal;
}

/** Options for the low-level `request()` escape hatch. */
export interface RawRequestOptions extends RequestOptions {
  query?: Record<string, string | number | boolean | null | undefined>;
  body?: unknown;
}

export interface PolicyVaultClientOptions {
  /** Origin, with or without the `/api/v1` suffix. */
  baseUrl: string;
  /**
   * A machine credential (`pvmk_...`). Stored in a module-private WeakMap,
   * never as an own property: it cannot appear in `console.log(client)`,
   * `JSON.stringify(client)`, `util.inspect`, a stack trace, or an error
   * message. Omit for a self-hosted server.
   */
  token?: string;
  /** Defaults to global `fetch` (Node >= 18). */
  fetchImpl?: typeof fetch;
  /**
   * Stamp the pinned `schemaVersion` on the three v0.4 bodies the server
   * validates (create / requests / simulate). Default `true` — a server on
   * a different wire shape then answers a clean 422 rather than
   * reinterpreting your body. `false` behaves like the shipped web client.
   */
  stampSchemaVersion?: boolean;
  /** Default headers for every call. Cannot override `Authorization`. */
  headers?: Record<string, string>;
}

/**
 * A non-2xx answer. Carries the server's envelope VERBATIM — this client
 * never maps one refusal code onto another, and never invents one.
 */
export declare class PolicyVaultApiError extends Error {
  readonly name: "PolicyVaultApiError";
  /** HTTP status as sent. */
  readonly status: number;
  /** `body.error.code`, or `"UNKNOWN"` if the answer had no envelope. */
  readonly code: string;
  /** `body.error.message`, unmodified. */
  readonly serverMessage: string;
  readonly method: string;
  readonly path: string;
  /** The full parsed body exactly as received (`null` if unparseable). */
  readonly body: ApiErrorEnvelope | PolicyVaultResponse | null;
  /** Envelope fields other than code/message (`request`, `idempotency`, ...). */
  readonly extra: PolicyVaultResponse;
  /** The Idempotency-Key that was sent, if any — reuse it to retry safely. */
  readonly idempotencyKey: string | null;
  /** `true` when this refusal was a replay of a previously recorded outcome. */
  readonly replayed: boolean;
}

/**
 * No HTTP answer arrived (DNS/connect/TLS/timeout/abort). You cannot know
 * whether the server executed the call — replay `idempotencyKey` to find
 * out safely.
 */
export declare class PolicyVaultNetworkError extends Error {
  readonly name: "PolicyVaultNetworkError";
  readonly method: string;
  readonly path: string;
  readonly cause: unknown;
  readonly idempotencyKey: string | null;
}

/**
 * Zero-dependency client for the PolicyVault API.
 *
 * Transport only: it holds no financial authority, no policy semantics, and
 * no verification logic. Pair it with the deterministic modules re-exported
 * from the SDK entry point to check locally what a server tells you.
 */
export declare class PolicyVaultClient {
  constructor(options: PolicyVaultClientOptions);

  /** The resolved endpoint, always ending in `/api/v1`. */
  readonly baseUrl: string;
  readonly stampSchemaVersion: boolean;
  readonly defaultHeaders: Readonly<Record<string, string>>;
  /** Whether a credential was supplied. Reveals existence only, never the value. */
  readonly authenticated: boolean;
  toJSON(): { baseUrl: string; authenticated: boolean; stampSchemaVersion: boolean };

  /**
   * Low-level escape hatch for any route without a named method.
   * Returns the parsed body, carrying a non-enumerable `idempotencyKey`
   * when one was sent (non-enumerable so `JSON.stringify(result)` is still
   * exactly the server's response).
   */
  request<T = PolicyVaultResponse>(method: "GET" | "POST", path: string, options?: RawRequestOptions): Promise<T>;

  /* Discovery — public routes, no credential required. */
  health(options?: RequestOptions): Promise<HealthBody>;
  ready(options?: RequestOptions): Promise<ReadyBody>;
  capabilities(options?: RequestOptions): Promise<CapabilitiesBody>;
  support(options?: RequestOptions): Promise<PolicyVaultResponse>;

  /* Vaults / audit / network. */
  listVaults(options?: RequestOptions): Promise<PolicyVaultResponse>;
  getVault(vaultId: string, options?: RequestOptions): Promise<PolicyVaultResponse>;
  getVaultStatus(vaultId: string, options?: RequestOptions): Promise<PolicyVaultResponse>;
  getVaultAudit(vaultId: string, options?: RequestOptions): Promise<PolicyVaultResponse>;
  audit(options?: RequestOptions & { limit?: number }): Promise<PolicyVaultResponse>;
  reconcileVault(vaultId: string, options?: RequestOptions): Promise<PolicyVaultResponse>;
  networkStatus(options?: RequestOptions): Promise<PolicyVaultResponse>;
  fuel(address: string, options?: RequestOptions): Promise<PolicyVaultResponse>;
  getManifest(manifestHash: string, options?: RequestOptions): Promise<PolicyVaultResponse>;

  /* v0.4 wallet requests. Simulate first; builders never broadcast. */
  simulate(body: PolicyVaultResponse, options?: RequestOptions): Promise<SimulationBody>;
  createRequest(body: PolicyVaultResponse, options?: RequestOptions): Promise<PolicyVaultResponse>;
  createVault(body: PolicyVaultResponse, options?: RequestOptions): Promise<PolicyVaultResponse>;
  listRequests(options?: RequestOptions & { vaultId?: string; open?: boolean }): Promise<PolicyVaultResponse>;
  getRequest(requestId: string, options?: RequestOptions): Promise<PolicyVaultResponse>;
  submitApproval(requestId: string, body: PolicyVaultResponse, options?: RequestOptions): Promise<PolicyVaultResponse>;
  submitSignature(requestId: string, body: PolicyVaultResponse, options?: RequestOptions): Promise<PolicyVaultResponse>;
  /** The one call here that can move funds on a live network. A 200 is not proof of settlement — read the request state. */
  submitRequest(requestId: string, options?: RequestOptions): Promise<PolicyVaultResponse>;
  submitGenesis(requestId: string, body: PolicyVaultResponse, options?: RequestOptions): Promise<PolicyVaultResponse>;
  rejectRequest(requestId: string, options?: RequestOptions): Promise<PolicyVaultResponse>;

  /* Governance. */
  listProposals(options?: RequestOptions & { vaultId?: string; limit?: number }): Promise<PolicyVaultResponse>;
  getProposal(proposalId: string, options?: RequestOptions): Promise<PolicyVaultResponse>;
  createProposal(body: PolicyVaultResponse, options?: RequestOptions): Promise<PolicyVaultResponse>;
  approveProposal(proposalId: string, body: PolicyVaultResponse, options?: RequestOptions): Promise<PolicyVaultResponse>;
  cancelProposal(proposalId: string, options?: RequestOptions): Promise<PolicyVaultResponse>;

  /* Risk. */
  getRiskEvaluation(evaluationId: string, options?: RequestOptions): Promise<PolicyVaultResponse>;
  releaseRiskEvaluation(evaluationId: string, options?: RequestOptions): Promise<PolicyVaultResponse>;

  /* Organizations. */
  listOrganizations(options?: RequestOptions): Promise<PolicyVaultResponse>;
  getOrganization(orgId: string, options?: RequestOptions): Promise<PolicyVaultResponse>;
  getOrganizationControls(orgId: string, options?: RequestOptions): Promise<PolicyVaultResponse>;
  setOrganizationControls(orgId: string, body: PolicyVaultResponse, options?: RequestOptions): Promise<PolicyVaultResponse>;
  getOrganizationAudit(orgId: string, options?: RequestOptions): Promise<PolicyVaultResponse>;

  /* Machine identities — WALLET-SESSION ONLY. Structurally unreachable by a
   * machine credential at any scope; called with a Bearer token they refuse
   * with 403 MACHINE_IDENTITY_ROUTE_FORBIDDEN, which is the intended design. */
  createIdentity(body: { label?: string; scopes: string[]; orgId?: string }, options?: RequestOptions): Promise<PolicyVaultResponse>;
  listIdentities(options?: RequestOptions): Promise<PolicyVaultResponse>;
  getIdentity(identityId: string, options?: RequestOptions): Promise<PolicyVaultResponse>;
  mintCredential(identityId: string, body?: { label?: string }, options?: RequestOptions): Promise<PolicyVaultResponse>;
  revokeCredential(identityId: string, credentialId: string, options?: RequestOptions): Promise<PolicyVaultResponse>;
  revokeIdentity(identityId: string, options?: RequestOptions): Promise<PolicyVaultResponse>;
}

/** Convenience factory equivalent to `new PolicyVaultClient(options)`. */
export declare function createClient(options: PolicyVaultClientOptions): PolicyVaultClient;

/** A fresh key inside the server's `[A-Za-z0-9_.:-]{1,200}` grammar, prefixed `pvsdk-`. */
export declare function randomIdempotencyKey(): string;

/** `"/api/v1"` — where server/src/server.js mounts the API. */
export declare const API_PREFIX: string;

/** The v0.4 wallet-request schema version this client is written against. */
export declare const V4_WALLET_REQUEST_SCHEMA_VERSION: string;
