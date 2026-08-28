"use strict";

/* CRASH/CONCURRENCY layer — durable claim conflict semantics. */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const { loadConfig } = require("../src/config");
const { claimTransition, loadTransitionClaim, claimSubmission } = require("../src/submission-claim");

function tempConfig() {
  const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "pv-claims-"));
  return { config: loadConfig({ dataRoot }), dataRoot };
}

const outpoint = { transactionId: "a".repeat(64), index: 1 };

test("transition claim is create-only: a second attempt on the same outpoint conflicts", async () => {
  const { config, dataRoot } = tempConfig();
  try {
    await claimTransition(config, { outpoint, action: "delegateSpend", txId: "b".repeat(64), vaultId: "v", stateId: "s" });
    await assert.rejects(async () => claimTransition(config, { outpoint, action: "ownerRecover", txId: "c".repeat(64), vaultId: "v", stateId: "s" }),
      (e) => e.code === "CLAIM_CONFLICT"
    );
    const loaded = await loadTransitionClaim(config, outpoint);
    assert.equal(loaded.action, "delegateSpend");
    assert.equal(loaded.txId, "b".repeat(64));
  } finally {
    fs.rmSync(dataRoot, { recursive: true, force: true });
  }
});

test("two different outpoints can be claimed independently", async () => {
  const { config, dataRoot } = tempConfig();
  try {
    await claimTransition(config, { outpoint, action: "delegateSpend", txId: "b".repeat(64), vaultId: "v", stateId: "s" });
    const other = { transactionId: "d".repeat(64), index: 0 };
    await assert.doesNotReject(() =>
      claimTransition(config, { outpoint: other, action: "delegateSpend", txId: "e".repeat(64), vaultId: "v", stateId: "s" })
    );
  } finally {
    fs.rmSync(dataRoot, { recursive: true, force: true });
  }
});

test("submission claim is idempotent for the same txid", async () => {
  const { config, dataRoot } = tempConfig();
  try {
    const txId = "f".repeat(64);
    const p1 = await claimSubmission(config, { txId, vaultId: "v", action: "delegateSpend" });
    const p2 = await claimSubmission(config, { txId, vaultId: "v", action: "delegateSpend" });
    assert.equal(p1, p2);
  } finally {
    fs.rmSync(dataRoot, { recursive: true, force: true });
  }
});
