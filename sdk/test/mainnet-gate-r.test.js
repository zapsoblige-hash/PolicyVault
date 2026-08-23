"use strict";

/* GATE R — mainnet production unlock regression suite (owner authorization
 * 2026-08-22: "Authorize Gate R. Enable PolicyVault mainnet production
 * release."). ENTIRELY OFFLINE — no node, no broadcast. Pins the unlocked
 * posture:
 *   §R1 the dual-flag config lock survives, mainnet demands an explicit RPC
 *       URL, and the operational-network gate fails closed on everything
 *       that is not testnet-10 or dual-flag-unlocked mainnet;
 *   §R2 a mainnet process still refuses dev signer / test hooks / legacy
 *       create at startup and reports the enabled posture;
 *   §R3 the v0.4.1 pipeline is OPERATIONAL on mainnet: BUILD -> sign ->
 *       FINALIZE -> production covenant VM PREFLIGHT with kaspa: addresses
 *       against a mainnet-stamped data root;
 *   §R4 cross-network material fails closed end-to-end (tampered request
 *       network at finalize; foreign-network manifest at reconcile);
 *   §R5 the v4 API demands addresses of the CONFIGURED network and keeps
 *       the dev signer dead on mainnet. */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");
const os = require("os");

const { loadConfig, assertOperationalNetwork, DEFAULT_DONATION_ADDRESS } = require("../src/config");
const { requiredAddressPrefix } = require("../src/address-identity");
const { buildAgentTreeV4, normalizeAgentPolicyV4 } = require("../src/agent-merkle-v4");
const { buildRecipientTree } = require("../src/recipient-merkle-v3");
const { normalizeStateV4, computeStateIdV4, stateToJsonV4, CONTRACT_VERSION_V4 } = require("../src/vault-state-v4");
const { compileExactStateV4 } = require("../src/contract-compiler-v4");
const { MANIFEST_SCHEMA_V4, persistManifestV4 } = require("../src/manifest-v4");
const {
  buildWalletRequestV4,
  buildCreateWalletRequestV4,
  finalizeWalletRequestV4,
  RequestState,
  requestPath
} = require("../src/wallet-requests-v4");
const { validateStartup } = require("../../server/src/server");
const { handle } = require("../../server/src/api");

/* ---- configs: a REAL dual-flag-unlocked mainnet config + testnet control ---- */

const mainRoot = fs.mkdtempSync(path.join(os.tmpdir(), "pv-gate-r-main-"));
const testRoot = fs.mkdtempSync(path.join(os.tmpdir(), "pv-gate-r-test-"));

function withEnv(pairs, fn) {
  const saved = {};
  for (const [k, v] of Object.entries(pairs)) {
    saved[k] = process.env[k];
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
  try {
    return fn();
  } finally {
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  }
}

const mainnetConfig = withEnv({ POLICYVAULT_ALLOW_MAINNET: "true" }, () =>
  loadConfig({ networkId: "mainnet", allowMainnet: true, rpcUrl: "ws://127.0.0.1:1", dataRoot: mainRoot })
);
const testnetConfig = loadConfig({ dataRoot: testRoot });

const kaspa = require(mainnetConfig.rustyKaspaModule);
const KEY = (v) => new kaspa.PrivateKey(v.toString(16).padStart(2, "0").repeat(32));
const SEC = (v) => v.toString(16).padStart(2, "0").repeat(32);
const XO = (p) => p.toPublicKey().toXOnlyPublicKey().toString().toLowerCase();
const MADDR = (p) => p.toPublicKey().toAddress("mainnet").toString();
const TADDR = (p) => p.toPublicKey().toAddress("testnet-10").toString();
const KAS = 100000000n;

const owner = KEY(1);
const agentA = KEY(0x1e);
const recipient = KEY(0x28);
const other = KEY(0x29);

const VAULT_ID = "5a".repeat(32);
const template = { owner: XO(owner), vaultId: VAULT_ID };

function agentEntry(kp, recipients) {
  return {
    agentPk: XO(kp), maxPerSpend: (20n * KAS).toString(), periodBudget: (50n * KAS).toString(),
    periodLengthDaa: "864000", periodStartDaa: "541000000", periodSpent: "0",
    approvalThreshold: (5n * KAS).toString(), agentMaxFeePerTx: (1n * KAS).toString(),
    recipients: recipients.map(XO)
  };
}
const REGISTRY = [agentEntry(agentA, [recipient, other])];

let seedCounter = 0;
function seedManifest(config) {
  seedCounter += 1;
  const outTxId = seedCounter.toString(16).padStart(2, "0").repeat(32).slice(0, 64);
  const policies = REGISTRY.map((e) => normalizeAgentPolicyV4({ ...e, agentRecipientRoot: buildRecipientTree(e.recipients).root }));
  const agentRoot = buildAgentTreeV4(policies).root;
  const state = normalizeStateV4({
    protectedValue: (1000n * KAS).toString(), feeReserve: (5n * KAS).toString(), paused: "0",
    agentRoot, approvers: [], approvalM: "0", policyNonce: "0"
  });
  const compiled = compileExactStateV4({ config, template, state });
  const stateId = computeStateIdV4({ networkId: config.networkId, template, state });
  return persistManifestV4(config, {
    schema: MANIFEST_SCHEMA_V4, contractVersion: CONTRACT_VERSION_V4, networkId: config.networkId,
    vaultId: VAULT_ID, label: "gate-r", status: "ACTIVE", template, agentRegistry: REGISTRY,
    live: {
      state: stateToJsonV4(state), stateId,
      outpoint: { transactionId: outTxId, index: 0 },
      outpointValue: (state.protectedValue + state.feeReserve).toString(),
      scriptSha256: compiled.scriptSha256, covenantId: "41".repeat(32)
    },
    creationTxId: "42".repeat(32), latestTransitionTxId: null, lastTransition: null
  });
}

/*
 * Wallet-seam signer for the mainnet pipeline tests. The production dev
 * signer REFUSES mainnet by design (a guard §R2 depends on), so these tests
 * sign the frozen Safe JSON exactly the way a REAL browser wallet does —
 * deserialize, createInputSignature (SIG_HASH_ALL default), re-serialize —
 * which is the same mechanics KasWare applies on mainnet.
 */
function walletSeamSign(secretHex, unsignedSafeJson, signInputs) {
  const tx = kaspa.Transaction.deserializeFromSafeJSON(unsignedSafeJson);
  const priv = new kaspa.PrivateKey(secretHex);
  for (const entry of signInputs) {
    const index = Number(entry.index ?? entry);
    const sigScript = kaspa.createInputSignature(tx, index, priv);
    const ins = tx.inputs;
    ins[index].signatureScript = sigScript;
    tx.inputs = ins;
  }
  return tx.serializeToSafeJSON();
}

/* ------------------------------- §R1 config ------------------------------- */

test("§R1 the dual-flag mainnet lock SURVIVES Gate R (both sides still required)", () => {
  withEnv({ POLICYVAULT_ALLOW_MAINNET: undefined, KASPA_RPC_URL: undefined }, () => {
    assert.throws(() => loadConfig({ networkId: "mainnet", rpcUrl: "ws://x", dataRoot: mainRoot }), /mainnet mode is locked/);
    assert.throws(() => loadConfig({ networkId: "mainnet", allowMainnet: true, rpcUrl: "ws://x", dataRoot: mainRoot }), /mainnet mode is locked/);
  });
  withEnv({ POLICYVAULT_ALLOW_MAINNET: "true", KASPA_RPC_URL: undefined }, () => {
    assert.throws(() => loadConfig({ networkId: "mainnet", rpcUrl: "ws://x", dataRoot: mainRoot }), /mainnet mode is locked/); // override absent
  });
  assert.throws(() => loadConfig({ networkId: "devnet" }), /unknown networkId/);
});

test("§R1 mainnet requires an EXPLICIT RPC URL (never the testnet default) and defaults to the data-mainnet root", () => {
  withEnv({ POLICYVAULT_ALLOW_MAINNET: "true", KASPA_RPC_URL: undefined }, () => {
    assert.throws(() => loadConfig({ networkId: "mainnet", allowMainnet: true, dataRoot: mainRoot }), /explicit KASPA_RPC_URL/);
    const viaEnvUrl = withEnv({ KASPA_RPC_URL: "ws://127.0.0.1:17110" }, () => loadConfig({ networkId: "mainnet", allowMainnet: true }));
    assert.equal(viaEnvUrl.rpcUrl, "ws://127.0.0.1:17110");
    assert.equal(viaEnvUrl.dataRoot, path.join(viaEnvUrl.repoRoot, "data-mainnet")); // checkout-relative
    assert.equal(viaEnvUrl.allowMainnet, true);
  });
});

test("§R1 assertOperationalNetwork: testnet-10 and UNLOCKED mainnet only; everything else fails closed", () => {
  assert.equal(assertOperationalNetwork(testnetConfig), "testnet-10");
  assert.equal(assertOperationalNetwork(mainnetConfig), "mainnet");
  assert.throws(() => assertOperationalNetwork({ ...mainnetConfig, allowMainnet: false }), /dual-flag unlock/);
  assert.throws(() => assertOperationalNetwork({ ...testnetConfig, networkId: "devnet" }), /not an operational/);
  assert.throws(() => assertOperationalNetwork({ networkId: "simnet" }), /not an operational/);
  assert.throws(() => assertOperationalNetwork(undefined), /not an operational/);
});

test("§R1 requiredAddressPrefix maps the operational networks and refuses the rest", () => {
  assert.equal(requiredAddressPrefix("testnet-10"), "kaspatest");
  assert.equal(requiredAddressPrefix("mainnet"), "kaspa");
  assert.throws(() => requiredAddressPrefix("devnet"), /no address prefix/);
});

/* ------------------------------ §R2 startup ------------------------------ */

test("§R2 mainnet startup still refuses dev signer / test hooks / legacy create; clean posture reports ENABLED broadcast", () => {
  for (const arm of [{ POLICYVAULT_DEV_SIGNER: "1" }, { PV_TEST_CRASH_AT: "AFTER_SUBMITTING" }, { POLICYVAULT_LEGACY_CREATE: "1" }]) {
    withEnv({ POLICYVAULT_DEV_SIGNER: undefined, PV_TEST_CRASH_AT: undefined, POLICYVAULT_LEGACY_CREATE: undefined, ...arm }, () => {
      assert.throws(() => validateStartup(mainnetConfig), /must not be enabled on mainnet/);
    });
  }
  const report = withEnv({ POLICYVAULT_DEV_SIGNER: undefined, PV_TEST_CRASH_AT: undefined, POLICYVAULT_LEGACY_CREATE: undefined }, () => validateStartup(mainnetConfig));
  assert.equal(report.network, "mainnet");
  assert.equal(report.mainnetBroadcast, "ENABLED");
  assert.match(report.donation, /^configured /); // the owner mainnet donation address validates
});

/* ------------------------- §R3 mainnet pipeline -------------------------- */

test("§R3 v0.4.1 agentSpend BUILD -> sign -> FINALIZE -> production covenant VM PREFLIGHT on MAINNET (offline)", () => {
  seedManifest(mainnetConfig);
  const req = buildWalletRequestV4({
    config: mainnetConfig, vaultId: VAULT_ID, action: "agentSpend",
    params: { payAmountSompi: (4n * KAS).toString(), agentPk: XO(agentA), recipient: XO(recipient) },
    signerAddress: MADDR(agentA)
  });
  assert.equal(req.state, RequestState.BUILT);
  assert.equal(req.networkId, "mainnet");
  assert.equal(req.review.fundingMode, "RESERVE-FUNDED");
  const signed = walletSeamSign(SEC(0x1e), req.transaction.unsignedSafeJson, req.transaction.signInputs);
  const done = finalizeWalletRequestV4({ config: mainnetConfig, requestId: req.requestId, signedSafeJson: signed });
  assert.equal(done.state, RequestState.PREFLIGHT_VERIFIED);
  assert.equal(done.txId, req.txId);
});

test("§R3 the create builder's network gate is OPEN on mainnet (fails later, on input validation — not on network)", () => {
  assert.throws(
    () => buildCreateWalletRequestV4({ config: mainnetConfig, templateInput: null, initialAgents: [], initialState: { protectedValue: "1" }, signerAddress: MADDR(owner), funding: null }),
    (e) => !/operational|testnet-10 only|network/.test(e.message)
  );
  const devnetish = { ...mainnetConfig, networkId: "devnet" };
  assert.throws(
    () => buildCreateWalletRequestV4({ config: devnetish, templateInput: null, initialAgents: [], initialState: { protectedValue: "1" }, signerAddress: MADDR(owner), funding: null }),
    /not an operational/
  );
});

/* ------------------------ §R4 cross-network refusal ----------------------- */

test("§R4 a BUILT request whose durable network stamp drifts from the config is refused at FINALIZE (nothing preflights)", () => {
  seedManifest(mainnetConfig);
  const req = buildWalletRequestV4({
    config: mainnetConfig, vaultId: VAULT_ID, action: "agentSpend",
    params: { payAmountSompi: (3n * KAS).toString(), agentPk: XO(agentA), recipient: XO(recipient) },
    signerAddress: MADDR(agentA)
  });
  const p = requestPath(mainnetConfig, req.requestId);
  const raw = JSON.parse(fs.readFileSync(p, "utf8"));
  raw.networkId = "testnet-10"; // simulated cross-network contamination
  fs.writeFileSync(p, JSON.stringify(raw, null, 2));
  const signed = walletSeamSign(SEC(0x1e), req.transaction.unsignedSafeJson, req.transaction.signInputs);
  assert.throws(
    () => finalizeWalletRequestV4({ config: mainnetConfig, requestId: req.requestId, signedSafeJson: signed }),
    /network drift at preflight/
  );
});

test("§R4 build refuses non-operational and un-unlocked configs outright", () => {
  assert.throws(
    () => buildWalletRequestV4({ config: { ...testnetConfig, networkId: "devnet" }, vaultId: VAULT_ID, action: "agentSpend", params: {}, signerAddress: TADDR(agentA) }),
    /not an operational/
  );
  assert.throws(
    () => buildWalletRequestV4({ config: { ...mainnetConfig, allowMainnet: false }, vaultId: VAULT_ID, action: "agentSpend", params: {}, signerAddress: MADDR(agentA) }),
    /dual-flag unlock/
  );
});

test("§R4 reconcile refuses a manifest stamped with a FOREIGN network before touching any node", async () => {
  seedManifest(mainnetConfig);
  const { reconcileVaultV4 } = require("../src/reconcile-v4");
  // A testnet-configured process pointed (wrongly) at the mainnet data root:
  const foreign = loadConfig({ dataRoot: mainRoot });
  await assert.rejects(reconcileVaultV4(foreign, VAULT_ID), /manifest network mainnet != configured testnet-10/);
});

/* ------------------------------ §R5 API layer ----------------------------- */

test("§R5 the v4 API demands addresses of the CONFIGURED network (kaspa: on mainnet) and the dev signer stays dead", async () => {
  seedManifest(mainnetConfig);
  // testnet-prefixed signer on a mainnet server -> BAD_SIGNER
  await assert.rejects(
    handle(mainnetConfig, "POST", ["wallet", "v4", "requests"], {}, { vaultId: VAULT_ID, action: "agentSpend", params: {}, signerAddress: TADDR(agentA) }),
    (e) => e.status === 400 && e.code === "BAD_SIGNER" && /mainnet address/.test(e.message)
  );
  // mainnet-prefixed signer passes the prefix gate (fails later on policy input, NOT on the prefix)
  await assert.rejects(
    handle(mainnetConfig, "POST", ["wallet", "v4", "requests"], {}, { vaultId: VAULT_ID, action: "agentSpend", params: {}, signerAddress: MADDR(agentA) }),
    (e) => e.code !== "BAD_SIGNER"
  );
  // fuel endpoint mirrors the network prefix rule
  await assert.rejects(
    handle(mainnetConfig, "GET", ["wallet", "fuel", encodeURIComponent(TADDR(owner))], {}, null),
    (e) => e.status === 400 && e.code === "BAD_ADDRESS"
  );
  // dev signer: 404 on mainnet even when the env is (wrongly) armed.
  // (env is managed inline: withEnv restores synchronously and cannot wrap an await)
  const savedDev = process.env.POLICYVAULT_DEV_SIGNER;
  process.env.POLICYVAULT_DEV_SIGNER = "1";
  try {
    await assert.rejects(
      handle(mainnetConfig, "GET", ["wallet", "dev-accounts"], {}, null),
      (e) => e.status === 404 && e.code === "DEV_SIGNER_DISABLED"
    );
  } finally {
    if (savedDev === undefined) delete process.env.POLICYVAULT_DEV_SIGNER;
    else process.env.POLICYVAULT_DEV_SIGNER = savedDev;
  }
  // health reports the configured network
  const health = await handle(mainnetConfig, "GET", ["health"], {}, null);
  assert.equal(health.body.networkId, "mainnet");
  // the testnet control config still demands kaspatest:
  await assert.rejects(
    handle(testnetConfig, "POST", ["wallet", "v4", "requests"], {}, { vaultId: VAULT_ID, action: "agentSpend", params: {}, signerAddress: MADDR(agentA) }),
    (e) => e.status === 400 && e.code === "BAD_SIGNER" && /testnet-10 address/.test(e.message)
  );
});
