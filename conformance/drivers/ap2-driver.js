"use strict";

/*
 * AP2 protocol-adapter path driver (surface 28; spec:
 * docs/postlaunch/ap2-adapter-spec.md, registration contract:
 * docs/postlaunch/conformance-suite-spec.md §8).
 *
 * Boots the REAL adapter service — integrations/ap2/service.js
 * createAp2Service(), the exact production entry point (PolicyVault as
 * AP2 Credential Provider) — on its own ephemeral loopback port with
 * the harness's six-scope machine credential, and drives it over REAL
 * HTTP with REAL compact SD-JWT payment mandates (ES256 over
 * node:crypto, minted by this driver's own issuer/holder key pairs —
 * the trust-anchor role the operator plays in production). The adapter
 * then speaks real HTTP to the one conformance server.
 *
 * Instrument + payee-directory configuration mirrors production: the
 * instrument maps to conformance VAULT_A / the AGENT key, and the
 * directory binds payee ids to OPERATOR-configured addresses — a
 * mandate can never name a destination directly. A deliberate
 * "instr-foreign" instrument points at a nonexistent vault so the
 * matrix can prove the platform's tenancy refusal surfaces verbatim.
 */

const http = require("http");
const fs = require("fs");
const os = require("os");
const path = require("path");

const ROOT = path.resolve(__dirname, "..", "..");
const { createAp2Service } = require(path.join(ROOT, "integrations/ap2/service.js"));
/* Test-fixture SD-JWT mint helpers (ES256 JWS + selective disclosure) —
 * the harness plays the mandate-ISSUER role the same way it plays the
 * wallet-owner role: with local test keys. */
const { ecKeyPair, buildSdJwt, b64uSha256 } = require(path.join(ROOT, "integrations/test/helpers/fixtures.js"));
const { outcome } = require("../lib/normalize");

const INSTRUMENT_TYPE = "org.policy-vault.kaspa.covenant-vault.v1";
const FOREIGN_VAULT_ID = "9f".repeat(32);

class Ap2Session {
  constructor({ harness, vaultId }) {
    this.id = "ap2";
    this.harness = harness;
    this.vaultId = vaultId;
    this.dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "pv-conformance-ap2-"));
    this.service = null;
    this.port = 0;
    this.bodyCorpus = [];
    this.issuer = ecKeyPair(); // user (human-present) trust anchor
    this.holder = ecKeyPair();
    this.checkoutSeq = 0;
  }

  async start() {
    this.service = createAp2Service({
      networkId: this.harness.config.networkId,
      rustyKaspaModule: this.harness.config.rustyKaspaModule,
      policyVault: { baseUrl: this.harness.baseUrl, token: this.harness.tokens.six },
      dataDir: this.dataDir,
      trustAnchors: { "user-1": { jwk: this.issuer.jwk, role: "user" } },
      instruments: {
        "instr-1": { vaultId: this.vaultId, agentPk: this.harness.xonly("AGENT") },
        // deliberately maps to a vault that does not exist: proves the
        // platform's existence-hiding 404 surfaces verbatim through the CP
        "instr-foreign": { vaultId: FOREIGN_VAULT_ID, agentPk: this.harness.xonly("AGENT") }
      },
      payeeDirectory: {
        schema: "policyvault-payee-directory/v1",
        networkId: this.harness.config.networkId,
        payees: {
          "merchant-1": { address: this.harness.address("RECIPIENT"), label: "Conformance Merchant" },
          // in the directory but NOT in the agent's covenant allowlist —
          // the restrictive-only double binding (spec A-2)
          "stranger": { address: this.harness.address("APPROVER_A") }
        }
      },
      requiredConstraintTypes: []
    });
    await new Promise((resolve, reject) => {
      this.service.once("error", reject);
      this.service.listen(0, "127.0.0.1", resolve);
    });
    this.port = this.service.address().port;
    return this;
  }

  /* Mint one closed payment mandate (compact SD-JWT + KB-JWT, ES256).
   * `amountMinor` is the AP2-protocol minor-unit integer (sompi for KAS);
   * `checkoutJwt` pins the transaction id (same checkout ⇒ same
   * transaction_id ⇒ the adapter's derived idempotency scope). */
  mintPaymentMandate({ amountMinor, payeeId = "merchant-1", instrumentId = "instr-1", checkoutJwt, expSeconds = 3600 } = {}) {
    const jwt = checkoutJwt ?? `conformance-checkout-${this.checkoutSeq++}`;
    const transactionId = b64uSha256(jwt);
    const claims = {
      vct: "mandate.payment.1",
      transaction_id: transactionId,
      payee: { id: payeeId, name: "Conformance Merchant" },
      payment_amount: { amount: amountMinor, currency: "KAS" },
      payment_instrument: { id: instrumentId, type: INSTRUMENT_TYPE },
      exp: Math.floor(Date.now() / 1000) + expSeconds
    };
    return { paymentMandate: buildSdJwt({ claims, issuer: this.issuer, holder: this.holder, kid: "user-1" }), transactionId, checkoutJwt: jwt };
  }

  #req(method, pathName, body) {
    return new Promise((resolve, reject) => {
      const data = body === undefined ? undefined : JSON.stringify(body);
      const req = http.request(
        {
          host: "127.0.0.1",
          port: this.port,
          method,
          path: pathName,
          headers: { ...(data !== undefined ? { "Content-Type": "application/json" } : {}) }
        },
        (res) => {
          let buf = "";
          res.on("data", (d) => (buf += d));
          res.on("end", () => {
            let json = null;
            try {
              json = buf ? JSON.parse(buf) : null;
            } catch {
              json = null;
            }
            this.bodyCorpus.push(buf);
            resolve({ status: res.statusCode, json });
          });
        }
      );
      req.on("error", reject);
      if (data !== undefined) req.write(data);
      req.end();
    });
  }

  #normalize(res) {
    const body = res.json;
    const code =
      body && Array.isArray(body.codes) && body.codes.length > 0
        ? body.codes[0]
        : body && body.error && body.error.code
          ? body.error.code
          : null;
    return outcome({ ok: res.status < 400, httpStatus: res.status, code, body });
  }

  /* One mandate presentation (POST /ap2/payment-mandates). */
  async presentMandate(body) {
    return this.#normalize(await this.#req("POST", "/ap2/payment-mandates", body));
  }

  /* The stored attempt record (GET /ap2/attempts/:transactionId). */
  async getAttempt(transactionId) {
    return this.#normalize(await this.#req("GET", `/ap2/attempts/${transactionId}`));
  }

  async raw(method, pathName, body) {
    return this.#normalize(await this.#req(method, pathName, body));
  }

  durableBytes() {
    const parts = [];
    const walk = (dir) => {
      let entries;
      try {
        entries = fs.readdirSync(dir, { withFileTypes: true });
      } catch {
        return;
      }
      for (const e of entries) {
        const abs = path.join(dir, e.name);
        if (e.isDirectory()) walk(abs);
        else if (e.isFile()) parts.push(fs.readFileSync(abs, "utf8"));
      }
    };
    walk(this.dataDir);
    return parts.join("\n");
  }

  async close() {
    if (this.service) {
      await new Promise((r) => this.service.close(r));
      this.service = null;
    }
    try {
      fs.rmSync(this.dataDir, { recursive: true, force: true });
    } catch {
      /* best effort */
    }
  }
}

module.exports = { Ap2Session, FOREIGN_VAULT_ID };
