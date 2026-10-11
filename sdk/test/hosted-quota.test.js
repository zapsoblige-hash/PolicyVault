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
/*
 * RC45 F3 (plan rc45-simplified-plan-r2 §2.3 A1, §8.1 hosted-quota, CR-M9):
 * the owner's break-glass (ownerPause, ownerRecover) is exempt from this quota
 * and its BUILT rows are not counted (H-13), so the suite is RE-BASED on an
 * ORDINARY owner action (ownerTopUp; was ownerPause at :60-61) — every quota
 * assertion kept — and each re-based test also pins the exemption
 * (expectBreakGlassBuilt, RED on C1).
 */
const build = (vaultId) =>
  handle(config, "POST", ["wallet", "v4", "requests"], {}, { vaultId, action: "ownerTopUp", params: { topUpAmountSompi: KAS.toString(), fuel: fuel() }, signerAddress: ADDR(owner) });
const buildBreakGlass = (vaultId, action, signer = owner) =>
  handle(config, "POST", ["wallet", "v4", "requests"], {}, { vaultId, action, params: { fuel: fuel() }, signerAddress: ADDR(signer) });
async function expectBreakGlassBuilt(vaultId, action) {
  const r = await buildBreakGlass(vaultId, action).catch((e) => ({ status: e.status, code: e.code, message: e.message }));
  assert.equal(r.status, 201, `RC45 A1: the owner's ${action} is exempt from the open-request quota (${r.code}: ${r.message})`);
  assert.equal(r.body.request.state, "BUILT");
  return r;
}

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
  // RC45 F3 (§8.1 :85): the owner's Pause is exempt at the full per-vault quota.
  await expectBreakGlassBuilt(VAULT_A, "ownerPause");
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
  openRequests.push(b1.body.request.requestId);
  await expectQuota(build(VAULT_B));
  // RC45 F3 (§8.1 :104): the owner's Close & recover is exempt at the full per-wallet quota.
  await expectBreakGlassBuilt(VAULT_B, "ownerRecover");
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
  // RC45 F3 (§8.1 :115): the same capped wallet still builds its v4 break-glass Pause.
  await expectBreakGlassBuilt(VAULT_A, "ownerPause");
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
  // RC45 F3 (§8.1 :131): with the vault (and the wallet) capped, the owner's Pause is still exempt.
  await expectBreakGlassBuilt(VAULT_B, "ownerPause");
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

test("§Q7 RC45 F3 (T8 j, H-13): BUILT break-glass rows are not counted; the exemption covers only ownerPause / ownerRecover; an agent sending ownerPause is never built", async () => {
  // Free the owner wallet (its ordinary open requests from §Q1-§Q3).
  for (const id of openRequests) {
    const r = await handle(config, "POST", ["wallet", "v4", "requests", id, "reject"], {}, {});
    assert.equal(r.body.request.state, "WALLET_REJECTED");
  }
  const VAULT_C = "cd".repeat(32);
  await seedVault(VAULT_C);
  await expectBreakGlassBuilt(VAULT_C, "ownerPause");
  await expectBreakGlassBuilt(VAULT_C, "ownerRecover");
  // Two BUILT break-glass rows on VAULT_C (per-vault limit 2): ordinary builds still fit (sabotage j).
  const o1 = await build(VAULT_C).catch((e) => ({ status: e.status, code: e.code, message: e.message }));
  assert.equal(o1.status, 201, `break-glass rows are not counted: the first ordinary build fits (${o1.code}: ${o1.message})`);
  const o2 = await build(VAULT_C);
  assert.equal(o2.status, 201, "the second ordinary build fits");
  await expectQuota(build(VAULT_C)); // ordinary actions stay counted and refused
  await expectBreakGlassBuilt(VAULT_C, "ownerPause"); // break-glass stays exempt at the full per-vault quota
  // An agent naming the break-glass action is refused (NOT_OWNER in the builder, B3, or the quota) and never built.
  const before = (await getStore(config).listValues(Categories.REQUEST)).length;
  const agentTry = await buildBreakGlass(VAULT_C, "ownerPause", agentA).then((r) => ({ status: r.status }), (e) => ({ status: e.status, code: e.code, message: e.message }));
  assert.ok(agentTry.code === "NOT_OWNER" || agentTry.code === "QUOTA_EXCEEDED", `an agent's ownerPause is refused (${agentTry.status} ${agentTry.code}: ${agentTry.message})`);
  assert.equal((await getStore(config).listValues(Categories.REQUEST)).length, before, "nothing durable for the agent's attempt");
});
