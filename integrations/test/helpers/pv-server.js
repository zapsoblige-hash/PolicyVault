"use strict";

/*
 * REAL PolicyVault server harness for the integrations INTEGRATION
 * suites — the exact idiom of sdk/test/postlaunch-origin-policy-server
 * .test.js: a real HTTP server (server/src/server.js), a persisted v0.4
 * vault manifest, real wallet sign-in (kaspa-wasm Schnorr over the auth
 * challenge), and a machine identity minted with EXACTLY the six adapter
 * scopes. No mocks anywhere on the PolicyVault side.
 */

const http = require("node:http");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const REPO_ROOT = path.join(__dirname, "..", "..", "..");
const { loadConfig } = require(path.join(REPO_ROOT, "sdk/src/config"));
const { buildAgentTreeV4, normalizeAgentPolicyV4 } = require(path.join(REPO_ROOT, "sdk/src/agent-merkle-v4"));
const { buildRecipientTree } = require(path.join(REPO_ROOT, "sdk/src/recipient-merkle-v3"));
const { normalizeStateV4, computeStateIdV4, stateToJsonV4, CONTRACT_VERSION_V4 } = require(path.join(REPO_ROOT, "sdk/src/vault-state-v4"));
const { compileExactStateV4 } = require(path.join(REPO_ROOT, "sdk/src/contract-compiler-v4"));
const { MANIFEST_SCHEMA_V4, persistManifestV4 } = require(path.join(REPO_ROOT, "sdk/src/manifest-v4"));
const { ADAPTER_SCOPES } = require(path.join(REPO_ROOT, "integrations/lib/pv-client"));

const KAS = 100000000n;

function req(port, method, pathName, { body, cookie, origin, authorization } = {}) {
  return new Promise((resolve, reject) => {
    const data = body === undefined ? undefined : JSON.stringify(body);
    const headers = { "Content-Type": "application/json", Host: `127.0.0.1:${port}` };
    headers.Origin = origin !== undefined ? origin : `http://127.0.0.1:${port}`;
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

/*
 * Boot a real server with one v0.4 vault:
 *   owner OWNER, agent AGENT (allowlisted recipients: RECIP, RECIP2),
 *   maxPerSpend / approvalThreshold / periodBudget as given.
 * Returns everything the suites need, including a token minted with the
 * EXACT six adapter scopes and helpers for extra identities.
 */
async function startPvServer({
  maxPerSpendKas = 20n,
  approvalThresholdKas = 5n,
  periodBudgetKas = 500n,
  approvers = [],
  approvalM = "0",
  keys = {}
} = {}) {
  const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "pv-integrations-"));
  const config = loadConfig({ dataRoot, authMode: "enabled", authCookieInsecure: true });
  const kaspa = require(config.rustyKaspaModule);
  const KEY = (v) => new kaspa.PrivateKey(v.toString(16).padStart(2, "0").repeat(32));
  const XO = (p) => p.toPublicKey().toXOnlyPublicKey().toString().toLowerCase();
  const ADDR = (p) => p.toPublicKey().toAddress(config.networkId).toString();

  const OWNER = keys.owner ?? KEY(0x31);
  const AGENT = keys.agent ?? KEY(0x32);
  const RECIP = keys.recip ?? KEY(0x33);
  const RECIP2 = keys.recip2 ?? KEY(0x34);
  const OUTSIDER = keys.outsider ?? KEY(0x35); // never allowlisted
  const APPROVER1 = keys.approver1 ?? KEY(0x36);
  const APPROVER2 = keys.approver2 ?? KEY(0x37);
  const VAULT_ID = "5a".repeat(32);
  // Default: a real approver tier so above-threshold spends land in
  // AWAITING_APPROVALS (the covenant refuses above-threshold spends when
  // approvalM is 0 and no approvers exist — a real covenant rule).
  const effectiveApprovers = approvers.length ? approvers : [XO(APPROVER1), XO(APPROVER2)];
  const effectiveApprovalM = approvers.length ? approvalM : approvalM !== "0" ? approvalM : "2";

  const template = { owner: XO(OWNER), vaultId: VAULT_ID };
  const registry = [
    {
      agentPk: XO(AGENT),
      maxPerSpend: (maxPerSpendKas * KAS).toString(),
      periodBudget: (periodBudgetKas * KAS).toString(),
      periodLengthDaa: "864000",
      periodStartDaa: "541000000",
      periodSpent: "0",
      approvalThreshold: (approvalThresholdKas * KAS).toString(),
      agentMaxFeePerTx: (1n * KAS).toString(),
      recipients: [XO(RECIP), XO(RECIP2)]
    }
  ];
  const policies = registry.map((e) => normalizeAgentPolicyV4({ ...e, agentRecipientRoot: buildRecipientTree(e.recipients).root }));
  const st = normalizeStateV4({
    protectedValue: (1000n * KAS).toString(),
    feeReserve: (5n * KAS).toString(),
    paused: "0",
    agentRoot: buildAgentTreeV4(policies).root,
    approvers: effectiveApprovers,
    approvalM: effectiveApprovalM,
    policyNonce: "0"
  });
  const compiled = compileExactStateV4({ config, template, state: st });
  const stateId = computeStateIdV4({ networkId: config.networkId, template, state: st });
  await persistManifestV4(config, {
    schema: MANIFEST_SCHEMA_V4,
    contractVersion: CONTRACT_VERSION_V4,
    networkId: config.networkId,
    vaultId: VAULT_ID,
    label: "integrations harness vault",
    status: "ACTIVE",
    template,
    agentRegistry: registry,
    live: {
      state: stateToJsonV4(st),
      stateId,
      outpoint: { transactionId: "5b".repeat(32), index: 0 },
      outpointValue: (st.protectedValue + st.feeReserve).toString(),
      scriptSha256: compiled.scriptSha256,
      covenantId: "5c".repeat(32)
    },
    creationTxId: "5d".repeat(32),
    latestTransitionTxId: null,
    lastTransition: null
  });

  const { createServer } = require(path.join(REPO_ROOT, "server/src/server"));
  const server = createServer(config);
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const port = server.address().port;

  async function signIn(priv) {
    const address = ADDR(priv);
    const ch = await req(port, "POST", "/api/v1/auth/challenge", { body: { walletAddress: address } });
    const signature = kaspa.signMessage({ message: ch.json.challenge.message, privateKey: priv.toString() });
    const v = await req(port, "POST", "/api/v1/auth/verify", {
      body: { nonce: ch.json.challenge.nonce, signature, publicKey: priv.toPublicKey().toString().toLowerCase() }
    });
    return v.headers["set-cookie"][0].split(";")[0];
  }

  async function mintIdentity(cookie, scopes, label) {
    const created = await req(port, "POST", "/api/v1/identities", { body: { scopes, ...(label ? { label } : {}) }, cookie });
    if (created.status !== 201) throw new Error(`identity mint failed: ${JSON.stringify(created.json)}`);
    return created;
  }

  const cookie = await signIn(OWNER);
  const minted = await mintIdentity(cookie, [...ADAPTER_SCOPES], "integrations-adapter");
  const token = minted.json.credential.token;

  return {
    config,
    server,
    port,
    baseUrl: `http://127.0.0.1:${port}`,
    dataRoot,
    vaultId: VAULT_ID,
    cookie,
    token,
    identity: minted.json.identity,
    keys: { OWNER, AGENT, RECIP, RECIP2, OUTSIDER, APPROVER1, APPROVER2 },
    XO,
    ADDR,
    KAS,
    req: (method, pathName, opts) => req(port, method, pathName, opts),
    signIn,
    mintIdentity,
    close: () => new Promise((r) => server.close(r))
  };
}

module.exports = { startPvServer, ADAPTER_SCOPES };
