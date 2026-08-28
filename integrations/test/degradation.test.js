"use strict";

/*
 * DEGRADATION — "adapters down ≠ any server impact" (x402 §7.3, ap2
 * §7.3, addendum degradation requirement). The strongest proof is
 * architectural and is the build-failing dependency-direction test
 * (dependency-direction.test.js). This suite asserts the OPERATIONAL
 * facts that make degradation real:
 *
 *   - the PolicyVault server module tree can be required and a server
 *     constructed with NOTHING from integrations/ loaded into it;
 *   - a crashing/absent adapter is just an absent API client — the
 *     server's own routes are unaffected (proven by the server coming
 *     up and answering /health with no adapter in the process);
 *   - the adapters, conversely, hard-fail closed when PolicyVault is
 *     unreachable (they never fabricate a settlement) — the "adapter
 *     cannot invent chain truth" direction of the same boundary.
 */

const { test, after } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const fs = require("node:fs");
const os = require("node:os");

const REPO = path.join(__dirname, "..", "..");

test("the server module graph never pulls in integrations/ (require.cache proof)", () => {
  // Fresh child-process-free proof: clear any integrations modules, load
  // the server entrypoint, and assert no integrations/ file entered the
  // module cache as a dependency of the server.
  for (const key of Object.keys(require.cache)) {
    if (key.includes(`${path.sep}integrations${path.sep}`)) delete require.cache[key];
  }
  require(path.join(REPO, "server/src/server.js"));
  const leaked = Object.keys(require.cache).filter((k) => k.includes(`${path.sep}integrations${path.sep}`));
  assert.deepEqual(leaked, [], `loading the server must not load any integrations/ module:\n${leaked.join("\n")}`);
});

test("a real server starts and answers /health with NO adapter anywhere in the process (adapter absence => zero core impact)", async () => {
  const { loadConfig } = require(path.join(REPO, "sdk/src/config"));
  const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "pv-degradation-"));
  const config = loadConfig({ dataRoot, authMode: "enabled", authCookieInsecure: true });
  const { createServer } = require(path.join(REPO, "server/src/server"));
  const server = createServer(config);
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const port = server.address().port;
  const http = require("node:http");
  const health = await new Promise((resolve, reject) => {
    const req = http.request({ host: "127.0.0.1", port, method: "GET", path: "/api/v1/health" }, (res) => {
      let buf = "";
      res.on("data", (d) => (buf += d));
      res.on("end", () => resolve({ status: res.statusCode, json: buf ? JSON.parse(buf) : null }));
    });
    req.on("error", reject);
    req.end();
  });
  assert.equal(health.status, 200);
  const leaked = Object.keys(require.cache).filter((k) => k.includes(`${path.sep}integrations${path.sep}`));
  assert.deepEqual(leaked, [], "no integrations/ module was loaded by serving a request");
  await new Promise((r) => server.close(r));
});

test("the x402 adapter fails CLOSED when PolicyVault is unreachable — it never fabricates a settlement", async () => {
  const { X402Adapter } = require("../x402/adapter");
  const { paymentRequiredDoc, encodePaymentRequired, KEY, ADDR, X402_TEST_NETWORK } = require("./helpers/fixtures");
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "pv-x402-degraded-"));
  const adapter = new X402Adapter({
    networkId: "testnet-10",
    assetLiteral: "KAS",
    rustyKaspaModule: require(path.join(REPO, "sdk/src/config")).loadConfig({ dataRoot: dataDir }).rustyKaspaModule,
    policyVault: { baseUrl: "http://127.0.0.1:1", token: "pvmk_unreachable" }, // nothing listening
    dataDir
  });
  const doc = paymentRequiredDoc();
  doc.accepts = [{ scheme: "exact", network: X402_TEST_NETWORK, amount: "100000000", asset: "KAS", payTo: ADDR(KEY(0x91)), maxTimeoutSeconds: 600, extra: { paymentFlow: "upfront" } }];
  const out = await adapter.handleAttempt({
    attemptId: "11111111-1111-4111-8111-111111111111",
    vaultId: "aa".repeat(32),
    agentPk: "bb".repeat(32),
    paymentRequiredHeader: encodePaymentRequired(doc)
  });
  assert.notEqual(out.status, "SETTLED", "an unreachable PolicyVault can never produce a settlement");
  assert.equal(out.status, "PENDING"); // retryable-upstream, fail-closed
  assert.ok(out.codes.includes("X402_UPSTREAM_UNAVAILABLE"));
  assert.equal(out.settlement, undefined);
});

test("the AP2 adapter fails CLOSED when its trust anchors are unconfigured — verification refuses before any network call", async () => {
  const { Ap2Adapter } = require("../ap2/adapter");
  const { ecKeyPair, buildSdJwt, b64uSha256 } = require("./helpers/fixtures");
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "pv-ap2-degraded-"));
  const adapter = new Ap2Adapter({
    networkId: "testnet-10",
    rustyKaspaModule: require(path.join(REPO, "sdk/src/config")).loadConfig({ dataRoot: dataDir }).rustyKaspaModule,
    policyVault: { baseUrl: "http://127.0.0.1:1", token: "pvmk_unreachable" },
    dataDir,
    trustAnchors: null, // unconfigured => fail closed
    instruments: {}
  });
  const issuer = ecKeyPair();
  const holder = ecKeyPair();
  const compact = buildSdJwt({
    claims: { vct: "mandate.payment.1", transaction_id: b64uSha256("c"), payee: { id: "m" }, payment_amount: { amount: 1, currency: "KAS" }, payment_instrument: { id: "i", type: "org.policy-vault.kaspa.covenant-vault.v1" }, exp: Math.floor(Date.now() / 1000) + 600 },
    issuer,
    holder,
    kid: "user-1"
  });
  const out = await adapter.handlePaymentMandate({ paymentMandate: compact });
  assert.equal(out.status, "REJECTED");
  assert.deepEqual(out.codes, ["AP2_TRUST_ANCHOR_UNCONFIGURED"]);
});

after(() => {
  // Leave require.cache as-is; other suites run in separate processes.
});
