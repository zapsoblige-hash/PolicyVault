"use strict";

/*
 * OPEN-REQUEST QUOTA (Phase D) — the abandoned-request cap per vault and
 * per signer wallet, enforced at the API build routes BEFORE any build
 * work (a refusal is pure). Open = the cancellable states (v2 BUILT,
 * v4 BUILT/AWAITING_APPROVALS); explicit cancellation (reject) or
 * completion frees quota. Both request families share the durable
 * category, so the count is family-mixed by design.
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const os = require("node:os");
const fs = require("node:fs");
const path = require("node:path");

const { handle, loadConfig } = require("../../server/src/api");
const { getStore, Categories } = require("../src/store");

const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "pv-quota-"));
const config = loadConfig({ dataRoot, maxOpenRequestsPerVault: 2, maxOpenRequestsPerWallet: 3 });
const kaspa = require(config.rustyKaspaModule);
const KEY = (v) => new kaspa.PrivateKey(v.toString(16).padStart(2, "0").repeat(32));
const XO = (p) => p.toPublicKey().toXOnlyPublicKey().toString().toLowerCase();
const ADDR = (p) => p.toPublicKey().toAddress(config.networkId).toString();
const KAS = 100000000n;
const owner = KEY(1);
const agentA = KEY(0x1e);
const recipient = KEY(0x28);

const VAULT_A = "aa".repeat(32);
const VAULT_B = "bb".repeat(32);

async function seedVault(vaultId) {
  const { buildAgentTreeV4, normalizeAgentPolicyV4 } = require("../src/agent-merkle-v4");
  const { buildRecipientTree } = require("../src/recipient-merkle-v3");
  const { normalizeStateV4, computeStateIdV4, stateToJsonV4, CONTRACT_VERSION_V4 } = require("../src/vault-state-v4");
  const { compileExactStateV4 } = require("../src/contract-compiler-v4");
  const { MANIFEST_SCHEMA_V4, persistManifestV4 } = require("../src/manifest-v4");
  const entry = {
    agentPk: XO(agentA), maxPerSpend: (20n * KAS).toString(), periodBudget: (50n * KAS).toString(),
    periodLengthDaa: "864000", periodStartDaa: "541000000", periodSpent: "0",
    approvalThreshold: (5n * KAS).toString(), agentMaxFeePerTx: (1n * KAS).toString(),
    recipients: [XO(recipient)]
  };
  const template = { owner: XO(owner), vaultId };
  const policies = [normalizeAgentPolicyV4({ ...entry, agentRecipientRoot: buildRecipientTree(entry.recipients).root })];
  const state = normalizeStateV4({ protectedValue: (1000n * KAS).toString(), feeReserve: (5n * KAS).toString(), paused: "0", agentRoot: buildAgentTreeV4(policies).root, approvers: [], approvalM: "0", policyNonce: "0" });
  const compiled = compileExactStateV4({ config, template, state });
  await persistManifestV4(config, {
    schema: MANIFEST_SCHEMA_V4, contractVersion: CONTRACT_VERSION_V4, networkId: config.networkId, vaultId,
    label: "quota test", status: "ACTIVE", template, agentRegistry: [entry],
    live: { state: stateToJsonV4(state), stateId: computeStateIdV4({ networkId: config.networkId, template, state }), outpoint: { transactionId: vaultId.slice(0, 64), index: 0 }, outpointValue: (state.protectedValue + state.feeReserve).toString(), scriptSha256: compiled.scriptSha256, covenantId: "41".repeat(32) },
    creationTxId: "42".repeat(32), latestTransitionTxId: null, lastTransition: null
  });
}

const fuel = () => ({ outpoint: { transactionId: "44".repeat(32), index: 0 }, amount: (100n * KAS).toString(), scriptPublicKeyHex: `20${XO(owner)}ac` });
const build = (vaultId) =>
  handle(config, "POST", ["wallet", "v4", "requests"], {}, { vaultId, action: "ownerPause", params: { fuel: fuel() }, signerAddress: ADDR(owner) });

async function expectQuota(promise) {
  try {
    await promise;
    assert.fail("expected QUOTA_EXCEEDED");
  } catch (e) {
    assert.equal(e.code, "QUOTA_EXCEEDED", e.message);
    assert.equal(e.status, 429);
  }
}

let openRequests = [];

test("§Q1 per-vault quota: the third open request on one vault refuses; nothing durable is created by the refusal", async () => {
  await seedVault(VAULT_A);
  await seedVault(VAULT_B);
  const r1 = await build(VAULT_A);
  assert.equal(r1.status, 201);
  const r2 = await build(VAULT_A);
  assert.equal(r2.status, 201);
  openRequests = [r1.body.request.requestId, r2.body.request.requestId];

  const before = (await getStore(config).listValues(Categories.REQUEST)).length;
  await expectQuota(build(VAULT_A));
  const after = (await getStore(config).listValues(Categories.REQUEST)).length;
  assert.equal(after, before, "a quota refusal creates no durable record");
});

test("§Q2 explicit cancellation frees per-vault quota", async () => {
  const rejected = await handle(config, "POST", ["wallet", "v4", "requests", openRequests[0], "reject"], {}, {});
  assert.equal(rejected.body.request.state, "WALLET_REJECTED");
  const again = await build(VAULT_A);
  assert.equal(again.status, 201, "capacity freed by cancellation");
  openRequests = [openRequests[1], again.body.request.requestId];
});

test("§Q3 per-wallet quota: the same signer is capped across vaults", async () => {
  // The owner wallet already holds 2 open requests on vault A; a third
  // on vault B is fine (wallet cap 3), a fourth refuses even though
  // vault B itself is under its per-vault cap.
  const b1 = await build(VAULT_B);
  assert.equal(b1.status, 201);
  await expectQuota(build(VAULT_B));
});

test("§Q4 the v2 build route enforces the same quota (guard sits before any build work)", async () => {
  // The signer's wallet is at its cap — the v2 family route must refuse
  // BEFORE reaching the v2 builder (no manifest for this id even exists;
  // reaching the builder would 404/422 with a different code).
  try {
    await handle(config, "POST", ["wallet", "requests"], {}, { vaultId: "cc".repeat(32), action: "pause", params: {}, signerAddress: ADDR(owner).replace(/^kaspa:/, "kaspatest:") });
    assert.fail("expected QUOTA_EXCEEDED");
  } catch (e) {
    assert.equal(e.code, "QUOTA_EXCEEDED", e.message);
  }
});

test("§Q5 synthetic open records count toward quota (state-based, family-agnostic)", async () => {
  // A hand-written AWAITING_APPROVALS record for another wallet counts
  // against ITS vault, not against unrelated wallets.
  const otherSigner = ADDR(KEY(9));
  await getStore(config).write(Categories.REQUEST, "synthetic-1", {
    requestId: "synthetic-1", vaultId: VAULT_B, state: "AWAITING_APPROVALS", signerAddress: otherSigner
  });
  await getStore(config).write(Categories.REQUEST, "synthetic-2", {
    requestId: "synthetic-2", vaultId: VAULT_B, state: "AWAITING_APPROVALS", signerAddress: otherSigner
  });
  // VAULT_B now holds 1 (real, §Q3) + 2 synthetic = 3 ≥ perVault 2 → refuse
  // regardless of which wallet asks.
  await expectQuota(build(VAULT_B));
  // Terminal states never count: flip one synthetic to a closed state.
  await getStore(config).write(Categories.REQUEST, "synthetic-1", {
    requestId: "synthetic-1", vaultId: VAULT_B, state: "WALLET_REJECTED", signerAddress: otherSigner
  });
  await getStore(config).write(Categories.REQUEST, "synthetic-2", {
    requestId: "synthetic-2", vaultId: VAULT_B, state: "PREFLIGHT_FAILED", signerAddress: otherSigner
  });
  // Still refused for THIS signer (wallet cap), but the VAULT no longer
  // blocks: a different wallet may build on vault B again.
  await expectQuota(build(VAULT_B));
});

test("§Q6 defaults are generous and validated", () => {
  const d = loadConfig({ dataRoot: fs.mkdtempSync(path.join(os.tmpdir(), "pv-quota-d-")) });
  assert.equal(d.requestProtection.openRequestQuota.perVault, 32);
  assert.equal(d.requestProtection.openRequestQuota.perWallet, 64);
  assert.throws(() => loadConfig({ dataRoot, maxOpenRequestsPerVault: 0 }), /must be an integer/);
  assert.throws(() => loadConfig({ dataRoot, maxOpenRequestsPerWallet: "lots" }), /must be an integer/);
});
