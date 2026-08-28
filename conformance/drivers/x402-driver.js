"use strict";

/*
 * x402 protocol-adapter path driver (surface 27; spec:
 * docs/postlaunch/x402-adapter-spec.md, registration contract:
 * docs/postlaunch/conformance-suite-spec.md §8).
 *
 * Boots the REAL adapter service — integrations/x402/service.js
 * createX402Service(), the exact production entry point — on its own
 * ephemeral loopback port, configured with the harness's six-scope
 * machine credential, and drives it over REAL HTTP (the adapter itself
 * then speaks real HTTP to the one conformance server through
 * integrations/lib/pv-client.js). Nothing is mocked on either hop.
 *
 * The adapter is a PAY-FIRST TRANSLATOR, not a general client: its
 * whole caller surface is attempts. Ops here mirror that surface
 * exactly; the capabilities it does NOT expose are declared absent in
 * conformance/paths.js and asserted absent by the matrix.
 *
 * Every response body is captured into `bodyCorpus` (C11 token-hygiene
 * scan) and the on-disk attempt store lives under `dataDir` so the
 * hygiene scenario can additionally grep the DURABLE records for
 * credentials (the specs promise the token is never stored).
 */

const http = require("http");
const fs = require("fs");
const os = require("os");
const path = require("path");

const ROOT = path.resolve(__dirname, "..", "..");
const { createX402Service } = require(path.join(ROOT, "integrations/x402/service.js"));
const { outcome } = require("../lib/normalize");

class X402Session {
  constructor({ harness }) {
    this.id = "x402";
    this.harness = harness;
    this.dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "pv-conformance-x402-"));
    this.service = null;
    this.port = 0;
    this.bodyCorpus = [];
  }

  async start() {
    this.service = createX402Service({
      networkId: this.harness.config.networkId,
      assetLiteral: "KAS", // operator-configured sentinel (spec OQ-6: no default exists)
      rustyKaspaModule: this.harness.config.rustyKaspaModule,
      policyVault: { baseUrl: this.harness.baseUrl, token: this.harness.tokens.six },
      dataDir: this.dataDir
    });
    await new Promise((resolve, reject) => {
      this.service.once("error", reject);
      this.service.listen(0, "127.0.0.1", resolve);
    });
    this.port = this.service.address().port;
    return this;
  }

  /* A protocol-correct PAYMENT-REQUIRED header (x402 v2 shape, base64
   * JSON) for the harness network. */
  paymentRequiredHeader({ amountSompi, payTo, network } = {}) {
    const doc = {
      x402Version: 2,
      resource: { url: "https://api.example.test/data", description: "conformance resource", mimeType: "application/json" },
      accepts: [
        {
          scheme: "exact",
          network: network ?? `kaspa:${this.harness.config.networkId}`,
          amount: amountSompi,
          asset: "KAS",
          payTo: payTo ?? this.harness.address("RECIPIENT"),
          maxTimeoutSeconds: 3600,
          extra: { paymentFlow: "upfront" }
        }
      ]
    };
    return Buffer.from(JSON.stringify(doc), "utf8").toString("base64");
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

  /* Normalize the adapter's outcome documents to the §4 shape. `code` is
   * the FIRST machine code of the outcome (for platform refusals the
   * adapter carries the server's code verbatim there, e.g.
   * VAULT_NOT_FOUND); adapter-internal service errors normalize from the
   * {error:{code}} envelope. */
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

  /* One logical purchase attempt (POST /x402/attempts). */
  async attempt(body) {
    return this.#normalize(await this.#req("POST", "/x402/attempts", body));
  }

  /* The stored attempt record (GET /x402/attempts/:id). */
  async getAttempt(attemptId) {
    return this.#normalize(await this.#req("GET", `/x402/attempts/${attemptId}`));
  }

  /* An arbitrary raw probe against the adapter's own surface (route-lock
   * limitation assertions). */
  async raw(method, pathName, body) {
    return this.#normalize(await this.#req(method, pathName, body));
  }

  /* Every durable byte the adapter wrote (attempt store) — the hygiene
   * scenario greps this for credentials. */
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

module.exports = { X402Session };
