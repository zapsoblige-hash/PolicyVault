"use strict";

/*
 * Test bootstrap for the Python reference client (surface 10).
 *
 * Spawned as a SUBPROCESS by python/tests/harness.py. It starts the REAL
 * PolicyVault HTTP server from THIS worktree — server/src/server.js
 * `createServer(config)`, the same entry point every hosted-* /
 * postlaunch-* Node test uses — on an ephemeral loopback port with the
 * JSON persistence backend and a throwaway data root. Nothing here is a
 * mock, a stub, or a re-implementation of a route: the Python tests speak
 * real HTTP to the real handler.
 *
 * It additionally does the one thing a stdlib-only Python client cannot do
 * for itself: establish a hosted WALLET SESSION (Schnorr over
 * PersonalMessageSigningHash via kaspa-wasm) so it can mint machine bearer
 * credentials. Machine identities are wallet-session-only by design
 * (server/src/scopes.js isWalletSessionOnlyRoute) — a token can never mint
 * or widen its own authority — so a Python client can never bootstrap its
 * own credential, and must not be able to. Two credentials are minted:
 *
 *   fullToken  — the scopes the Python tests exercise
 *   readToken  — read:vaults only, to prove the deny-by-default scope gate
 *                refuses an operation the credential does not hold
 *
 * Handshake: one line of JSON on stdout prefixed `PVBOOT ` once listening.
 * Shutdown: SIGTERM, or stdin EOF (so an abandoned parent can never leak
 * a server process).
 */

const fs = require("fs");
const os = require("os");
const path = require("path");
const http = require("http");

const ROOT = path.resolve(__dirname, "..", "..");
const { loadConfig } = require(path.join(ROOT, "sdk/src/config"));
const { buildAgentTreeV4, normalizeAgentPolicyV4 } = require(path.join(ROOT, "sdk/src/agent-merkle-v4"));
const { buildRecipientTree } = require(path.join(ROOT, "sdk/src/recipient-merkle-v3"));
const {
  normalizeStateV4,
  computeStateIdV4,
  stateToJsonV4,
  CONTRACT_VERSION_V4
} = require(path.join(ROOT, "sdk/src/vault-state-v4"));
const { compileExactStateV4 } = require(path.join(ROOT, "sdk/src/contract-compiler-v4"));
const { MANIFEST_SCHEMA_V4, persistManifestV4 } = require(path.join(ROOT, "sdk/src/manifest-v4"));

const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "pv-python-client-"));
const config = loadConfig({
  dataRoot,
  authMode: "enabled", // hosted: machine identities exist only in hosted mode
  authCookieInsecure: true, // plaintext loopback, testnet only
  persistenceBackend: "json"
});
const kaspa = require(config.rustyKaspaModule);

const KEY = (v) => new kaspa.PrivateKey(v.toString(16).padStart(2, "0").repeat(32));
const XO = (p) => p.toPublicKey().toXOnlyPublicKey().toString().toLowerCase();
const ADDR = (p) => p.toPublicKey().toAddress(config.networkId).toString();
const KAS = 100000000n;

const OWNER = KEY(0x51);
const AGENT = KEY(0x52);
const RECIPIENT = KEY(0x53);
const VAULT_ID = "5a".repeat(32);

let server = null;

function req(port, method, pathName, { body, cookie, authorization } = {}) {
  return new Promise((resolve, reject) => {
    const data = body === undefined ? undefined : JSON.stringify(body);
    const headers = {
      "Content-Type": "application/json",
      Host: `127.0.0.1:${port}`,
      Origin: `http://127.0.0.1:${port}`
    };
    if (cookie) headers.Cookie = cookie;
    if (authorization) headers.Authorization = authorization;
    const r = http.request({ host: "127.0.0.1", port, method, path: pathName, headers }, (res) => {
      let buf = "";
      res.on("data", (d) => (buf += d));
      res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, json: buf ? JSON.parse(buf) : null }));
    });
    r.on("error", reject);
    if (data) r.write(data);
    r.end();
  });
}

async function signIn(port, priv) {
  const address = ADDR(priv);
  const ch = await req(port, "POST", "/api/v1/auth/challenge", { body: { walletAddress: address } });
  if (ch.status !== 200) throw new Error(`challenge failed: ${JSON.stringify(ch.json)}`);
  const signature = kaspa.signMessage({ message: ch.json.challenge.message, privateKey: priv.toString() });
  const v = await req(port, "POST", "/api/v1/auth/verify", {
    body: {
      nonce: ch.json.challenge.nonce,
      signature,
      publicKey: priv.toPublicKey().toString().toLowerCase()
    }
  });
  if (v.status !== 200) throw new Error(`verify failed: ${JSON.stringify(v.json)}`);
  return v.headers["set-cookie"][0].split(";")[0];
}

async function mint(port, cookie, scopes, label) {
  const created = await req(port, "POST", "/api/v1/identities", { body: { scopes, label }, cookie });
  if (created.status !== 201) throw new Error(`mint failed: ${JSON.stringify(created.json)}`);
  return created.json.credential.token;
}

async function seedVault() {
  const template = { owner: XO(OWNER), vaultId: VAULT_ID };
  const registry = [
    {
      agentPk: XO(AGENT),
      maxPerSpend: (20n * KAS).toString(),
      periodBudget: (500n * KAS).toString(),
      periodLengthDaa: "864000",
      periodStartDaa: "541000000",
      periodSpent: "0",
      approvalThreshold: (500n * KAS).toString(),
      agentMaxFeePerTx: (1n * KAS).toString(),
      recipients: [XO(RECIPIENT)]
    }
  ];
  const policies = registry.map((e) =>
    normalizeAgentPolicyV4({ ...e, agentRecipientRoot: buildRecipientTree(e.recipients).root })
  );
  const state = normalizeStateV4({
    protectedValue: (1000n * KAS).toString(),
    feeReserve: (5n * KAS).toString(),
    paused: "0",
    agentRoot: buildAgentTreeV4(policies).root,
    approvers: [],
    approvalM: "0",
    policyNonce: "0"
  });
  const compiled = compileExactStateV4({ config, template, state });
  const stateId = computeStateIdV4({ networkId: config.networkId, template, state });
  await persistManifestV4(config, {
    schema: MANIFEST_SCHEMA_V4,
    contractVersion: CONTRACT_VERSION_V4,
    networkId: config.networkId,
    vaultId: VAULT_ID,
    label: "python client test vault",
    status: "ACTIVE",
    template,
    agentRegistry: registry,
    live: {
      state: stateToJsonV4(state),
      stateId,
      outpoint: { transactionId: "5b".repeat(32), index: 0 },
      outpointValue: (state.protectedValue + state.feeReserve).toString(),
      scriptSha256: compiled.scriptSha256,
      covenantId: "5c".repeat(32)
    },
    creationTxId: "5d".repeat(32),
    latestTransitionTxId: null,
    lastTransition: null
  });
}

function shutdown(code) {
  const done = () => {
    try {
      fs.rmSync(dataRoot, { recursive: true, force: true });
    } catch {
      /* best effort */
    }
    process.exit(code);
  };
  if (server) server.close(done);
  else done();
}

(async () => {
  await seedVault();

  const { createServer } = require(path.join(ROOT, "server/src/server"));
  server = createServer(config);
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const port = server.address().port;

  const cookie = await signIn(port, OWNER);
  const fullToken = await mint(
    port,
    cookie,
    [
      "read:vaults",
      "read:requests",
      "read:governance",
      "read:risk",
      "read:audit",
      "read:manifests",
      "read:network",
      "request:build",
      "governance:propose"
    ],
    "python-client-full"
  );
  const readToken = await mint(port, cookie, ["read:vaults"], "python-client-readonly");

  // The v0.4 builder shells out to the REAL Rust call encoder. It lives
  // under the gitignored tests/vm/target/, so a fresh checkout (or a git
  // worktree, where Cargo cannot resolve the sibling silverscript path)
  // may not have it. Report it rather than letting the Python tests
  // misread an ENVIRONMENT gap as a client defect.
  const encoderPath = path.join(ROOT, "tests/vm/target/debug/pv_call_encoder");

  process.stdout.write(
    "PVBOOT " +
      JSON.stringify({
        baseUrl: `http://127.0.0.1:${port}`,
        port,
        networkId: config.networkId,
        dataRoot,
        vaultId: VAULT_ID,
        encoderAvailable: fs.existsSync(encoderPath),
        encoderPath,
        fullToken,
        readToken,
        ownerAddress: ADDR(OWNER),
        agentAddress: ADDR(AGENT),
        agentPk: XO(AGENT),
        recipientPk: XO(RECIPIENT),
        ownerPk: XO(OWNER)
      }) +
      "\n"
  );
})().catch((error) => {
  process.stderr.write(`PVBOOT-FAILED ${error && error.stack ? error.stack : error}\n`);
  shutdown(1);
});

process.on("SIGTERM", () => shutdown(0));
process.on("SIGINT", () => shutdown(0));
process.stdin.resume();
process.stdin.on("end", () => shutdown(0));
process.stdin.on("close", () => shutdown(0));
