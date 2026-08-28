"use strict";

/*
 * JS/TS-path driver (surface 9): the REAL sdk/src/http-client.js
 * PolicyVaultClient, in-process, over real HTTP to the harness server.
 * No mocks — this is exactly the client an agent embeds.
 *
 * Every op returns the normalized outcome shape (lib/normalize.js).
 */

const path = require("path");
const util = require("util");

const ROOT = path.resolve(__dirname, "..", "..");
const {
  PolicyVaultClient,
  PolicyVaultApiError,
  PolicyVaultNetworkError,
  V4_WALLET_REQUEST_SCHEMA_VERSION
} = require(path.join(ROOT, "sdk/src/http-client"));
const { outcome } = require("../lib/normalize");

class JsDriver {
  constructor({ baseUrl, tokens }) {
    this.id = "js";
    this.baseUrl = baseUrl;
    this.clients = {};
    for (const [name, token] of Object.entries(tokens)) {
      this.clients[name] = new PolicyVaultClient({ baseUrl, token });
    }
    this.clients.anonymous = new PolicyVaultClient({ baseUrl });
    // Every PolicyVaultApiError message observed — scanned by the token-
    // hygiene scenario (guarantee: the credential is structurally absent).
    this.errorMessages = [];
  }

  pinnedSchemaVersion() {
    return V4_WALLET_REQUEST_SCHEMA_VERSION;
  }

  /* Serialize/inspect every client — the hygiene scenario greps this. */
  serializationSurface() {
    return Object.entries(this.clients)
      .map(([name, c]) => `${name}: ${JSON.stringify(c)} | ${util.inspect(c, { depth: 4 })}`)
      .join("\n");
  }

  async #run(fn) {
    try {
      const body = await fn();
      return outcome({
        ok: true,
        body,
        replayed: Boolean(body && body.idempotency && body.idempotency.replayed)
      });
    } catch (error) {
      if (error instanceof PolicyVaultApiError) {
        this.errorMessages.push(error.message);
        return outcome({
          ok: false,
          httpStatus: error.status,
          code: error.code,
          body: error.body,
          replayed: Boolean(error.replayed),
          errorType: "PolicyVaultApiError"
        });
      }
      if (error instanceof PolicyVaultNetworkError) {
        this.errorMessages.push(error.message);
        return outcome({ ok: false, errorType: "PolicyVaultNetworkError", body: null });
      }
      // Local validation (e.g. malformed idempotency key) — never reached HTTP.
      this.errorMessages.push(String(error && error.message));
      return outcome({ ok: false, errorType: error.constructor ? error.constructor.name : "Error", body: null });
    }
  }

  capabilities() {
    return this.#run(() => this.clients.anonymous.capabilities());
  }

  listVaults(who) {
    return this.#run(() => this.clients[who].listVaults());
  }

  getVault(who, vaultId) {
    return this.#run(() => this.clients[who].getVault(vaultId));
  }

  vaultAudit(who, vaultId) {
    return this.#run(() => this.clients[who].getVaultAudit(vaultId));
  }

  auditFeed(who, limit) {
    return this.#run(() => this.clients[who].audit({ limit }));
  }

  simulate(who, spec) {
    return this.#run(() => this.clients[who].simulate(spec));
  }

  /* An explicit schemaVersion in the body always wins over the pin. */
  simulateWithSchemaVersion(who, spec, schemaVersion) {
    return this.#run(() => this.clients[who].simulate({ ...spec, schemaVersion }));
  }

  buildRequest(who, spec, idempotencyKey) {
    return this.#run(() => this.clients[who].createRequest(spec, idempotencyKey !== undefined ? { idempotencyKey } : {}));
  }

  getRequest(who, requestId) {
    return this.#run(() => this.clients[who].getRequest(requestId));
  }

  listRequests(who, { vaultId, openOnly } = {}) {
    return this.#run(() => this.clients[who].listRequests({ vaultId, open: openOnly ? true : undefined }));
  }

  submitApproval(who, requestId, body, { unkeyed } = {}) {
    // unkeyed: suppress this client's auto-generated Idempotency-Key so a
    // wire-identity comparison sees the same envelope an unkeyed client
    // (the Python default) sees. The auto-key default itself is a
    // documented JS-client convenience, not a wire divergence.
    return this.#run(() => this.clients[who].submitApproval(requestId, body, unkeyed ? { idempotencyKey: null } : {}));
  }

  getProposal(who, proposalId) {
    return this.#run(() => this.clients[who].getProposal(proposalId));
  }

  listProposals(who, { vaultId, limit } = {}) {
    return this.#run(() => this.clients[who].listProposals({ vaultId, limit }));
  }

  getRiskEvaluation(who, evaluationId) {
    return this.#run(() => this.clients[who].getRiskEvaluation(evaluationId));
  }

  rejectRequest(who, requestId, { unkeyed } = {}) {
    return this.#run(() => this.clients[who].rejectRequest(requestId, unkeyed ? { idempotencyKey: null } : {}));
  }

  /* Events polling + webhooks go through the documented low-level
   * `request()` escape hatch — the JS client deliberately has no named
   * methods for them yet; the escape hatch IS the supported surface. */
  pollEvents(who, { cursor, limit, types } = {}) {
    return this.#run(() =>
      this.clients[who].request("GET", "/events", {
        query: {
          ...(cursor !== undefined ? { cursor } : {}),
          ...(limit !== undefined ? { limit } : {}),
          ...(types !== undefined ? { types } : {})
        }
      })
    );
  }

  createWebhook(who, body) {
    return this.#run(() => this.clients[who].request("POST", "/webhooks", { body, idempotencyKey: null }));
  }

  listWebhooks(who) {
    return this.#run(() => this.clients[who].request("GET", "/webhooks"));
  }

  attemptIdentityMint(who, body) {
    return this.#run(() => this.clients[who].createIdentity(body));
  }
}

module.exports = { JsDriver };
