"use strict";

/*
 * AGENT-INTEGRATION CONFORMANCE SUITE — real-platform harness
 * (FULLSCALE_COMPLETION_ADDENDUM surface 24; spec:
 * docs/postlaunch/conformance-suite-spec.md).
 *
 * Boots ONE real PolicyVault server — server/src/server.js
 * createServer(config), the same entry point production uses — on an
 * ephemeral loopback port with the JSON persistence backend and hosted
 * auth ENABLED. Nothing here is a mock or a route re-implementation: the
 * conformance paths (JS client in-process, Python client subprocess,
 * MCP server subprocess over stdio, and the x402/AP2 adapter services
 * over HTTP) all speak real HTTP to this one server.
 *
 * The harness additionally plays the two roles a machine credential can
 * never play for itself (both structurally wallet-session-only):
 *   - the HUMAN WALLET OWNER who signs in (Schnorr over
 *     PersonalMessageSigningHash via kaspa-wasm) and mints the machine
 *     identities the paths authenticate with;
 *   - the EXTERNAL SIGNER who produces the approver signature used by the
 *     approval-replay scenario (sdk/src/signer-dev.js — TEST-ONLY signer,
 *     testnet keys only; the covenant contract is unaffected).
 *
 * ENVIRONMENT NOTE (documented, mirrors python/tests/_server_boot.js):
 * the v0.4 builder shells out to the REAL Rust call encoder at
 * tests/vm/target/debug/pv_call_encoder, a gitignored Cargo artifact. In a
 * git worktree Cargo cannot resolve the sibling ../silverscript path, so
 * the binary is COPIED from the main checkout (see the spec doc §9). Its
 * absence is an ENVIRONMENT gap, never a driven-surface defect.
 */

const fs = require("fs");
const os = require("os");
const path = require("path");
const http = require("http");
const crypto = require("crypto");

const ROOT = path.resolve(__dirname, "..", "..");

const { loadConfig } = require(path.join(ROOT, "sdk/src/config"));
const { buildAgentTreeV4, normalizeAgentPolicyV4 } = require(path.join(ROOT, "sdk/src/agent-merkle-v4"));
const { buildRecipientTree } = require(path.join(ROOT, "sdk/src/recipient-merkle-v3"));
const {
  normalizeStateV4,
  computeStateIdV4,
  stateToJsonV4,
  CONTRACT_VERSION_V4,
  CONTRACT_VERSION_V4_1
} = require(path.join(ROOT, "sdk/src/vault-state-v4"));
const { compileExactStateV4 } = require(path.join(ROOT, "sdk/src/contract-compiler-v4"));
const { MANIFEST_SCHEMA_V4, persistManifestV4 } = require(path.join(ROOT, "sdk/src/manifest-v4"));
const { makeDevSigner } = require(path.join(ROOT, "sdk/src/signer-dev"));

const KAS = 100000000n;
/* The gitignored Rust artifacts the REAL build pipeline shells out to
 * (sdk/src/vault-builders-v4.js, frozen-tx-v3.js, wallet-requests-v4.js). */
const PROBE_BINARIES = Object.freeze(["pv_call_encoder", "pv_tx_probe", "pv_vm_preflight"]);
const ENCODER_PATH = path.join(ROOT, "tests/vm/target/debug/pv_call_encoder");
const missingProbeBinaries = () => PROBE_BINARIES.filter((b) => !fs.existsSync(path.join(ROOT, "tests/vm/target/debug", b)));

/* Deterministic test keys (testnet only — CLAUDE.md secrets rule). */
const KEYBYTE = Object.freeze({
  OWNER: 0x61,
  AGENT: 0x62,
  RECIPIENT: 0x63,
  APPROVER_A: 0x64,
  APPROVER_B: 0x65,
  OWNER2: 0x66
});

const VAULT_A = "6a".repeat(32); // plain vault: no approvers, high threshold
const VAULT_B = "6b".repeat(32); // approvals vault: 2-of-2, 5 KAS threshold

function keyHex(byte) {
  return byte.toString(16).padStart(2, "0").repeat(32);
}

class ConformanceHarness {
  constructor() {
    this.dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "pv-conformance-"));
    // Webhook delivery worker OFF: the injection scenario creates endpoint
    // RECORDS only; background delivery dials would be nondeterministic.
    process.env.POLICYVAULT_WEBHOOK_DELIVERY = "0";
    this.config = loadConfig({
      dataRoot: this.dataRoot,
      authMode: "enabled", // machine identities exist only in hosted mode
      authCookieInsecure: true, // plaintext loopback, testnet only
      persistenceBackend: "json"
    });
    this.kaspa = require(this.config.rustyKaspaModule);
    this.server = null;
    this.port = 0;
    this.baseUrl = null;
    this.tokens = {}; // name -> raw pvmk_ credential (test-only; scanned-for, never printed)
    this.scopes = {}; // name -> the exact scope list minted for that credential
    this.encoderAvailable = fs.existsSync(ENCODER_PATH);
  }

  key(name) {
    return new this.kaspa.PrivateKey(keyHex(KEYBYTE[name]));
  }

  xonly(name) {
    return this.key(name).toPublicKey().toXOnlyPublicKey().toString().toLowerCase();
  }

  address(name) {
    return this.key(name).toPublicKey().toAddress(this.config.networkId).toString();
  }

  devSigner(name) {
    return makeDevSigner(this.config, { secretHex: keyHex(KEYBYTE[name]), expectedAddress: this.address(name) });
  }

  /* ---- raw HTTP (the reference wire probe; also the cookie path) ---- */

  raw(method, pathName, { body, cookie, token, idempotencyKey, headers, origin } = {}) {
    return new Promise((resolve, reject) => {
      const data = body === undefined ? undefined : JSON.stringify(body);
      const h = {
        Accept: "application/json",
        Host: `127.0.0.1:${this.port}`,
        ...(data !== undefined ? { "Content-Type": "application/json" } : {}),
        ...(cookie ? { Cookie: cookie } : {}),
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
        ...(idempotencyKey ? { "Idempotency-Key": idempotencyKey } : {}),
        // Wallet-session/anonymous POSTs sit behind the hosted origin wall;
        // bearer requests are deliberately exempt (limits.js split). The
        // harness plays browser roles, so Origin is attached by default
        // UNLESS the request authenticates with a bearer token (a real
        // machine client sends none); origin:null suppresses it, an explicit
        // origin overrides it.
        ...(origin !== undefined ? (origin === null ? {} : { Origin: origin }) : token ? {} : { Origin: `http://127.0.0.1:${this.port}` }),
        ...(headers || {})
      };
      const req = http.request(
        { host: "127.0.0.1", port: this.port, method, path: `/api/v1${pathName}`, headers: h },
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
            resolve({ status: res.statusCode, headers: res.headers, json });
          });
        }
      );
      req.on("error", reject);
      if (data !== undefined) req.write(data);
      req.end();
    });
  }

  /* ---- hosted wallet session (Schnorr over PersonalMessageSigningHash) ---- */

  async signIn(ownerName) {
    const priv = this.key(ownerName);
    const address = this.address(ownerName);
    const ch = await this.raw("POST", "/auth/challenge", { body: { walletAddress: address } });
    if (ch.status !== 200) throw new Error(`harness sign-in challenge failed: http ${ch.status}`);
    const signature = this.kaspa.signMessage({ message: ch.json.challenge.message, privateKey: priv.toString() });
    const v = await this.raw("POST", "/auth/verify", {
      body: { nonce: ch.json.challenge.nonce, signature, publicKey: priv.toPublicKey().toString().toLowerCase() }
    });
    if (v.status !== 200) throw new Error(`harness sign-in verify failed: http ${v.status}`);
    return v.headers["set-cookie"][0].split(";")[0];
  }

  async mintIdentity(cookie, name, scopes, label) {
    const created = await this.raw("POST", "/identities", { body: { scopes, label }, cookie });
    if (created.status !== 201) {
      throw new Error(`harness mint '${name}' failed: http ${created.status} ${created.json && created.json.error ? created.json.error.code : ""}`);
    }
    this.tokens[name] = created.json.credential.token;
    this.scopes[name] = [...scopes];
    return created.json;
  }

  /* The exact scope list minted for a named credential (principal-scoped
   * discovery parity checks compare against this, never against prose). */
  scopesOf(name) {
    if (!this.scopes[name]) throw new Error(`harness: no minted credential named '${name}'`);
    return [...this.scopes[name]];
  }

  /* Expected mint-time refusal (over-scoped / unknown scope — fail closed). */
  async mintExpectRefusal(cookie, scopes) {
    const res = await this.raw("POST", "/identities", { body: { scopes, label: "over-scoped-refused" }, cookie });
    return res;
  }

  /* ---- vault seeding (same pattern as python/tests/_server_boot.js) ---- */

  async seedVaults() {
    // Vault A — no approvers; 500 KAS threshold so ordinary spends never
    // await approvals. contractVersion v0.4.
    await this.#seedVault({
      vaultId: VAULT_A,
      contractVersion: CONTRACT_VERSION_V4,
      label: "conformance vault A",
      approvers: [],
      approvalM: "0",
      approvalThreshold: (500n * KAS).toString(),
      outpointTx: "6c".repeat(32),
      covenantId: "6d".repeat(32),
      creationTxId: "6e".repeat(32)
    });
    // Vault B — 2-of-2 approvers, 5 KAS threshold: an above-threshold spend
    // lands in AWAITING_APPROVALS for the approval-replay scenario.
    // contractVersion v0.4.1.
    await this.#seedVault({
      vaultId: VAULT_B,
      contractVersion: CONTRACT_VERSION_V4_1,
      label: "conformance vault B (approvals)",
      approvers: [this.xonly("APPROVER_A"), this.xonly("APPROVER_B")],
      approvalM: "2",
      approvalThreshold: (5n * KAS).toString(),
      outpointTx: "7c".repeat(32),
      covenantId: "7d".repeat(32),
      creationTxId: "7e".repeat(32)
    });
  }

  async #seedVault({ vaultId, contractVersion, label, approvers, approvalM, approvalThreshold, outpointTx, covenantId, creationTxId }) {
    const config = this.config;
    const registry = [
      {
        agentPk: this.xonly("AGENT"),
        maxPerSpend: (20n * KAS).toString(),
        periodBudget: (500n * KAS).toString(),
        periodLengthDaa: "864000",
        periodStartDaa: "541000000",
        periodSpent: "0",
        approvalThreshold,
        agentMaxFeePerTx: (1n * KAS).toString(),
        recipients: [this.xonly("RECIPIENT")]
      }
    ];
    const template = { owner: this.xonly("OWNER"), vaultId };
    const policies = registry.map((e) => normalizeAgentPolicyV4({ ...e, agentRecipientRoot: buildRecipientTree(e.recipients).root }));
    const state = normalizeStateV4({
      protectedValue: (1000n * KAS).toString(),
      feeReserve: (5n * KAS).toString(),
      paused: "0",
      agentRoot: buildAgentTreeV4(policies).root,
      approvers,
      approvalM,
      policyNonce: "0"
    });
    const compiled = compileExactStateV4({ config, template, state, contractVersion });
    const stateId = computeStateIdV4({ networkId: config.networkId, template, state, contractVersion });
    await persistManifestV4(config, {
      schema: MANIFEST_SCHEMA_V4,
      contractVersion,
      networkId: config.networkId,
      vaultId,
      label,
      status: "ACTIVE",
      template,
      agentRegistry: registry,
      live: {
        state: stateToJsonV4(state),
        stateId,
        outpoint: { transactionId: outpointTx, index: 0 },
        outpointValue: (state.protectedValue + state.feeReserve).toString(),
        scriptSha256: compiled.scriptSha256,
        covenantId
      },
      creationTxId,
      latestTransitionTxId: null,
      lastTransition: null
    });
  }

  /* ---- durable-store snapshot (persist-nothing proof) ---- */

  /*
   * Hash every file under the data root, EXCLUDING platform/credentials/:
   * machine-credential records carry a best-effort lastUsedAt touch on
   * EVERY authenticated call (server/src/machine-identity.js
   * resolveBearerToken) — auth bookkeeping, not simulation state. Every
   * other byte of durable state must be identical around a dry run.
   */
  snapshotStore() {
    const out = new Map();
    const walk = (dir, rel) => {
      let entries;
      try {
        entries = fs.readdirSync(dir, { withFileTypes: true });
      } catch {
        return;
      }
      for (const e of entries) {
        const abs = path.join(dir, e.name);
        const r = rel ? `${rel}/${e.name}` : e.name;
        if (e.isDirectory()) {
          walk(abs, r);
        } else if (e.isFile()) {
          if (r.startsWith("platform/credentials/")) continue; // documented exclusion
          out.set(r, crypto.createHash("sha256").update(fs.readFileSync(abs)).digest("hex"));
        }
      }
    };
    walk(this.dataRoot, "");
    return out;
  }

  static diffSnapshots(before, after) {
    const diffs = [];
    for (const [k, v] of before) {
      if (!after.has(k)) diffs.push(`removed: ${k}`);
      else if (after.get(k) !== v) diffs.push(`changed: ${k}`);
    }
    for (const k of after.keys()) if (!before.has(k)) diffs.push(`added: ${k}`);
    return diffs;
  }

  /* ---- lifecycle ---- */

  async start() {
    await this.seedVaults();
    const { createServer } = require(path.join(ROOT, "server/src/server"));
    this.server = createServer(this.config);
    await new Promise((resolve, reject) => {
      this.server.once("error", reject);
      this.server.listen(0, "127.0.0.1", resolve);
    });
    this.port = this.server.address().port;
    this.baseUrl = `http://127.0.0.1:${this.port}`;

    // Wallet sessions: OWNER (tenant 1, owns vaults A+B), OWNER2 (tenant 2,
    // owns nothing — the isolation probe).
    this.ownerCookie = await this.signIn("OWNER");
    this.owner2Cookie = await this.signIn("OWNER2");

    // Machine identities (deny-by-default scopes; minted per scenario role).
    // "six" is the documented adapter profile (x402/ap2 spec §4.2): the
    // complete six-scope set an autonomous payment agent is granted.
    await this.mintIdentity(this.ownerCookie, "six", ["read:network", "read:vaults", "read:requests", "read:manifests", "request:build", "request:submit"], "conformance-agent-six-scope");
    await this.mintIdentity(this.ownerCookie, "readonly", ["read:vaults"], "conformance-read-only");
    await this.mintIdentity(this.ownerCookie, "reader", ["read:audit", "read:events", "read:governance", "read:risk"], "conformance-observer");
    await this.mintIdentity(this.ownerCookie, "signer", ["read:requests", "request:sign"], "conformance-approval-submitter");
    await this.mintIdentity(this.ownerCookie, "janitor", ["read:requests", "request:reject"], "conformance-request-janitor");
    await this.mintIdentity(this.ownerCookie, "hooks", ["webhooks:manage"], "conformance-webhooks");
    await this.mintIdentity(this.owner2Cookie, "tenant2", ["read:vaults", "read:requests", "read:events"], "conformance-tenant2");
    return this;
  }

  async stop() {
    if (this.server) {
      await new Promise((r) => this.server.close(r));
      this.server = null;
    }
    try {
      fs.rmSync(this.dataRoot, { recursive: true, force: true });
    } catch {
      /* best effort */
    }
  }
}

module.exports = { ConformanceHarness, VAULT_A, VAULT_B, KAS, ENCODER_PATH, PROBE_BINARIES, missingProbeBinaries, ROOT };
