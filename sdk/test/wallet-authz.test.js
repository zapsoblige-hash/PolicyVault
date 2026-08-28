"use strict";

/*
 * SDK layer — signer authorization BEFORE the funds pipeline, and
 * submission-outcome classification (motivating incident 2026-08-16: a
 * delegate-signed ownerTopUp reached build/sign/claim/submit, the node
 * definitively rejected it, and the stranded transition claim blocked the
 * vault with CLAIM_CONFLICT).
 *
 * Every unauthorized build below must throw BEFORE construction and leave
 * ZERO durable mutation: no request file, no transition claim, no
 * submission claim. No node is contacted (authorization precedes RPC).
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const { loadConfig } = require("../src/config");
const { addressForXOnlyPubkey } = require("../src/address-identity");
const { persistManifestV2, MANIFEST_SCHEMA_V2 } = require("../src/manifest-v2");
const { computeStateIdV2, normalizeTemplateV2, normalizeStateV2, CONTRACT_VERSION_V2 } = require("../src/vault-state-v2");
const {
  buildWalletRequestV2,
  buildCreateWalletRequestV2,
  isDefinitiveSubmitRejection,
  ROLE_BY_ACTION
} = require("../src/wallet-requests-v2");
const {
  claimTransition,
  claimSubmission,
  loadTransitionClaim,
  releaseTransitionClaim,
  releaseSubmissionClaim,
  submissionClaimPath
} = require("../src/submission-claim");

/* Known-valid secp256k1 X coordinates. */
const OWNER_X = "cbaedc26f03fd3ba02fc936f338e980c9e2172c5e23128877ed46827e935296f";
const DELEGATE_X = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const RECIP_X = "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
const UNRELATED_X = "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9";

const VAULT_ID = "5f".repeat(32);

function tempConfig() {
  return loadConfig({ dataRoot: fs.mkdtempSync(path.join(os.tmpdir(), "pv2-authz-")) });
}

function stateInput() {
  return {
    protectedValue: "19500000000",
    periodStartDaa: "545127882",
    periodSpent: "500000000",
    paused: "0",
    delegate: DELEGATE_X,
    maxPerSpend: "1000000000",
    periodBudget: "10000000000",
    periodLengthDaa: "600",
    recipients: [RECIP_X],
    delegateActive: "1",
    policyNonce: "0"
  };
}

async function seedVault(config) {
  const template = normalizeTemplateV2({ owner: OWNER_X, vaultId: VAULT_ID });
  const state = normalizeStateV2(stateInput());
  await persistManifestV2(config, {
    schema: MANIFEST_SCHEMA_V2,
    contractVersion: CONTRACT_VERSION_V2,
    networkId: config.networkId,
    vaultId: VAULT_ID,
    label: "authz-test",
    status: "ACTIVE",
    template,
    live: {
      state,
      stateId: computeStateIdV2({ networkId: config.networkId, template, state }),
      outpoint: { transactionId: "ab".repeat(32), index: 1 },
      outpointValue: "19500000000",
      scriptSha256: "cd".repeat(32),
      covenantId: "ef".repeat(32)
    },
    creationTxId: "12".repeat(32),
    latestTransitionTxId: null,
    lastTransition: null
  });
}

function assertZeroDurableMutation(config) {
  for (const sub of ["claims/transition", "claims/submission", "requests", "receipts"]) {
    const dir = path.join(config.dataRoot, sub);
    const entries = fs.existsSync(dir) ? fs.readdirSync(dir) : [];
    assert.deepEqual(entries, [], `${sub} must stay empty after an unauthorized attempt`);
  }
}

const addr = (x) => {
  const config = loadConfig();
  return addressForXOnlyPubkey(config, x);
};
const OWNER_ADDR = addr(OWNER_X);
const DELEGATE_ADDR = addr(DELEGATE_X);
const UNRELATED_ADDR = addr(UNRELATED_X);

const OWNER_ACTIONS = [
  ["ownerPause", {}],
  ["ownerUnpause", {}],
  ["revokeDelegate", {}],
  ["rotateDelegate", { newDelegate: RECIP_X }],
  ["ownerTopUp", { topUpAmountSompi: "1000000000" }],
  ["migratePolicy", { newPolicy: { maxPerSpend: "2000000000" } }]
];

test("A/C: delegate attempting every owner action fails NOT_OWNER with zero durable mutation", async () => {
  const config = tempConfig();
  await seedVault(config);
  for (const [action, params] of OWNER_ACTIONS) {
    await assert.rejects(
      () => buildWalletRequestV2({ config, vaultId: VAULT_ID, action, params, signerAddress: DELEGATE_ADDR }),
      (e) => e.code === "NOT_OWNER" && new RegExp(action).test(e.message),
      `${action} must reject the delegate signer`
    );
  }
  assertZeroDurableMutation(config);
});

test("D: unrelated wallet attempting owner and delegate mutations fails with zero durable mutation", async () => {
  const config = tempConfig();
  await seedVault(config);
  for (const [action, params] of OWNER_ACTIONS) {
    await assert.rejects(
      () => buildWalletRequestV2({ config, vaultId: VAULT_ID, action, params, signerAddress: UNRELATED_ADDR }),
      (e) => e.code === "NOT_OWNER"
    );
  }
  await assert.rejects(
    () => buildWalletRequestV2({ config, vaultId: VAULT_ID, action: "delegateSpend", params: { payAmountSompi: "100000000", recipientIndex: 1 }, signerAddress: UNRELATED_ADDR }),
    (e) => e.code === "NOT_DELEGATE"
  );
  assertZeroDurableMutation(config);
});

test("E: owner attempting delegateSpend (owner != delegate) fails NOT_DELEGATE with zero durable mutation", async () => {
  const config = tempConfig();
  await seedVault(config);
  await assert.rejects(
    () => buildWalletRequestV2({ config, vaultId: VAULT_ID, action: "delegateSpend", params: { payAmountSompi: "100000000", recipientIndex: 1 }, signerAddress: OWNER_ADDR }),
    (e) => e.code === "NOT_DELEGATE"
  );
  assertZeroDurableMutation(config);
});

test("unknown action and malformed signer address fail closed before construction", async () => {
  const config = tempConfig();
  await seedVault(config);
  await assert.rejects(
    () => buildWalletRequestV2({ config, vaultId: VAULT_ID, action: "adminDrain", params: {}, signerAddress: OWNER_ADDR }),
    (e) => e.code === "BUILD_FAILED" && /unknown action/.test(e.message)
  );
  await assert.rejects(
    () => buildWalletRequestV2({ config, vaultId: VAULT_ID, action: "ownerPause", params: {}, signerAddress: "not-an-address" }),
    (e) => e.code === "AUTHORIZATION_FAILED"
  );
  await assert.rejects(
    () => buildWalletRequestV2({ config, vaultId: VAULT_ID, action: "ownerPause", params: {}, signerAddress: undefined }),
    (e) => e.code === "AUTHORIZATION_FAILED"
  );
  assertZeroDurableMutation(config);
});

test("create: funding signer must BE the template owner (NOT_OWNER otherwise, zero durable mutation)", async () => {
  const config = tempConfig();
  await assert.rejects(
    () => buildCreateWalletRequestV2({
      config,
      templateInput: { owner: OWNER_X, vaultId: VAULT_ID },
      initialStateInput: stateInput(),
      signerAddress: DELEGATE_ADDR
    }),
    (e) => e.code === "NOT_OWNER"
  );
  assertZeroDurableMutation(config);
});

test("every wallet action is present in the role map (fail-closed coverage)", async () => {
  assert.deepEqual(
    Object.keys(ROLE_BY_ACTION).sort(),
    ["delegateSpend", "migratePolicy", "ownerPause", "ownerRecover", "ownerTopUp", "ownerUnpause", "revokeDelegate", "rolloverAndSpend", "rotateDelegate"].sort()
  );
  for (const role of Object.values(ROLE_BY_ACTION)) {
    assert.ok(role === "owner" || role === "delegate");
  }
});

/* ---- submission-outcome classification (Bug 2) ---- */

test("classification: node-evaluated rejections are DEFINITIVE", async () => {
  assert.ok(isDefinitiveSubmitRejection(
    "Rejected transaction 12ffe0c2353ab546a3d91be0d7bdb635c667bc565441650ce76099938ae4f033: failed to verify the signature script: script ran, but verification failed"
  ));
  assert.ok(isDefinitiveSubmitRejection("Rejected transaction deadbeef: transaction is invalid"));
  assert.ok(isDefinitiveSubmitRejection("Rejected transaction abc123: policy rejection: mass exceeds limit"));
});

test("classification: transport/ambiguous failures are NEVER definitive", async () => {
  for (const message of [
    "websocket connection dropped before response",
    "RPC timeout after 15000ms",
    "connection refused",
    "socket hang up",
    "node is not synced — refusing live operations",
    "",
    null,
    undefined,
    "transaction Rejected transaction" // prefix must anchor at the start
  ]) {
    assert.equal(isDefinitiveSubmitRejection(message), false, `"${message}" must stay ambiguous`);
  }
});

/* ---- claim release: guarded, idempotent, crash-safe (test 10) ---- */

test("releaseTransitionClaim releases only the matching txId, idempotently", async () => {
  const config = tempConfig();
  const outpoint = { transactionId: "aa".repeat(32), index: 1 };
  const txId = "bb".repeat(32);
  await claimTransition(config, { outpoint, action: "ownerTopUp", txId, vaultId: VAULT_ID, stateId: "22".repeat(32), expected: null });

  // Wrong txId: refused loudly, claim intact.
  await assert.rejects(async () => releaseTransitionClaim(config, { outpoint, txId: "cc".repeat(32) }),
    (e) => e.code === "CLAIM_CONFLICT" && /refusing to release/.test(e.message)
  );
  assert.ok(await loadTransitionClaim(config, outpoint), "claim must survive a mismatched release");

  // Matching txId: released; second call is a no-op (idempotent).
  assert.equal(await releaseTransitionClaim(config, { outpoint, txId }), true);
  assert.equal(await loadTransitionClaim(config, outpoint), null);
  assert.equal(await releaseTransitionClaim(config, { outpoint, txId }), false);

  // The outpoint is immediately claimable again (vault usable).
  await claimTransition(config, { outpoint, action: "delegateSpend", txId: "dd".repeat(32), vaultId: VAULT_ID, stateId: "22".repeat(32), expected: null });
});

test("releaseSubmissionClaim is idempotent", async () => {
  const config = tempConfig();
  const txId = "ee".repeat(32);
  await claimSubmission(config, { txId, vaultId: VAULT_ID, action: "delegateSpend" });
  assert.ok(fs.existsSync(submissionClaimPath(config, txId)));
  assert.equal(await releaseSubmissionClaim(config, txId), true);
  assert.equal(fs.existsSync(submissionClaimPath(config, txId)), false);
  assert.equal(await releaseSubmissionClaim(config, txId), false);
});
