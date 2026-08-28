"use strict";

/*
 * RC-GV-1 PG PARITY — the governance proposal terminal-status machine
 * against a REAL PostgreSQL backend (finding RC-GV-1,
 * docs/postlaunch/rc-mainnet-acceptance-evidence.md §5.6 — the live
 * incident happened on the hosted PG store).
 *
 * SKIPPED cleanly without POLICYVAULT_TEST_PG_* (same pattern as
 * budget-reservation-pg.test.js: a fresh, uniquely-named database on the
 * shared cluster, created + dropped here).
 *
 * Proves store parity of the transition guard: the per-proposal
 * transition lock arbitrates through the store's atomic create-only
 * claim (INSERT ... ON CONFLICT DO NOTHING — the link()/EEXIST
 * equivalent), consume/cancel races resolve to exactly one winner with
 * the loser refusing deterministically, terminal states refuse every
 * further transition, legacy pre-fix row shapes normalize (consumption
 * evidence is terminal truth), unknown statuses fail closed, and no lock
 * residue survives a completed transition.
 */

const { test, before, after } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");
const os = require("os");
const crypto = require("crypto");

const { loadConfig } = require("../src/config");
const { openPgStore, getStore, Categories } = require("../src/store");
const { buildAgentTreeV4, normalizeAgentPolicyV4 } = require("../src/agent-merkle-v4");
const { buildRecipientTree } = require("../src/recipient-merkle-v3");
const { normalizeStateV4, computeStateIdV4, stateToJsonV4, CONTRACT_VERSION_V4 } = require("../src/vault-state-v4");
const { compileExactStateV4 } = require("../src/contract-compiler-v4");
const { MANIFEST_SCHEMA_V4, persistManifestV4 } = require("../src/manifest-v4");

const PG = {
  host: process.env.POLICYVAULT_TEST_PG_HOST || "127.0.0.1",
  port: Number(process.env.POLICYVAULT_TEST_PG_PORT || 0),
  user: process.env.POLICYVAULT_TEST_PG_USER,
  database: process.env.POLICYVAULT_TEST_PG_DATABASE
};
const PG_AVAILABLE = Boolean(PG.port && PG.user && PG.database);
const skip = PG_AVAILABLE ? undefined : "set POLICYVAULT_TEST_PG_{PORT,USER,DATABASE} to run the RC-GV-1 PG parity suite";

let adminPool;
let config;
let store;
let kaspa;
let governance;
let manifest;
const dbName = `pv_rcgv1_${process.pid}_${Date.now() % 100000}`;

const KAS = 100000000n;
const VAULT_ID = "6b".repeat(32);

let owner;
const XO = (p) => p.toPublicKey().toXOnlyPublicKey().toString().toLowerCase();
const ADDR = (p) => p.toPublicKey().toAddress(config.networkId).toString();

before(async () => {
  if (!PG_AVAILABLE) return;
  const { Pool } = require("pg");
  adminPool = new Pool({ host: PG.host, port: PG.port, user: PG.user, database: PG.database });
  await adminPool.query(`CREATE DATABASE ${dbName}`);
  config = loadConfig({
    persistenceBackend: "postgres", pgHost: PG.host, pgPort: PG.port, pgUser: PG.user, pgDatabase: dbName, pgNoTls: true,
    authMode: "enabled", authCookieInsecure: true,
    dataRoot: fs.mkdtempSync(path.join(os.tmpdir(), "pv-rcgv1pg-"))
  });
  store = await openPgStore(config, { migrate: true });
  kaspa = require(config.rustyKaspaModule);
  governance = require("../../server/src/governance");
  owner = new kaspa.PrivateKey("01".repeat(32));

  // A PAUSED vault: ownerUnpause is the governed EXPANSION (the exact
  // live-incident action) and needs no agent-lifecycle params.
  const template = { owner: XO(owner), vaultId: VAULT_ID };
  const registry = [{
    agentPk: XO(new kaspa.PrivateKey("1e".repeat(32))), maxPerSpend: (20n * KAS).toString(), periodBudget: (50n * KAS).toString(),
    periodLengthDaa: "864000", periodStartDaa: "541000000", periodSpent: "0",
    approvalThreshold: (5n * KAS).toString(), agentMaxFeePerTx: (1n * KAS).toString(),
    recipients: [XO(new kaspa.PrivateKey("28".repeat(32)))]
  }];
  const policies = registry.map((e) => normalizeAgentPolicyV4({ ...e, agentRecipientRoot: buildRecipientTree(e.recipients).root }));
  const state = normalizeStateV4({
    protectedValue: (1000n * KAS).toString(), feeReserve: (5n * KAS).toString(), paused: "1",
    agentRoot: buildAgentTreeV4(policies).root, approvers: [], approvalM: "0", policyNonce: "0"
  });
  const compiled = compileExactStateV4({ config, template, state });
  const stateId = computeStateIdV4({ networkId: config.networkId, template, state });
  manifest = await persistManifestV4(config, {
    schema: MANIFEST_SCHEMA_V4, contractVersion: CONTRACT_VERSION_V4, networkId: config.networkId, vaultId: VAULT_ID,
    label: "rc-gv1 pg", status: "PAUSED", template, agentRegistry: registry,
    live: { state: stateToJsonV4(state), stateId, outpoint: { transactionId: "b1".repeat(32), index: 0 }, outpointValue: (state.protectedValue + state.feeReserve).toString(), scriptSha256: compiled.scriptSha256, covenantId: "4d".repeat(32) },
    creationTxId: "42".repeat(32), latestTransitionTxId: null, lastTransition: null
  });
});

after(async () => {
  if (!PG_AVAILABLE) return;
  try {
    await store.close();
  } catch {
    /* closed */
  }
  await adminPool.query(`DROP DATABASE IF EXISTS ${dbName} WITH (FORCE)`);
  await adminPool.end();
});

const newProposal = () =>
  governance.createProposal({ config, manifest, vaultId: VAULT_ID, action: "ownerUnpause", params: {}, proposedByXOnly: XO(owner) });

async function expectCode(promise, status, code) {
  try {
    await promise;
    assert.fail(`expected ${code}`);
  } catch (e) {
    if (e.code === "ERR_ASSERTION") throw e;
    assert.equal(e.status, status, `status ${e.status} != ${status}: ${e.message}`);
    assert.equal(e.code, code, `code ${e.code} != ${code}: ${e.message}`);
    return e;
  }
}

const rowStatus = async (proposalId) => {
  const r = await store.pool().query(`SELECT value->>'status' AS s, value FROM governance_proposals WHERE network_id=$1 AND key=$2`, [config.networkId, proposalId]);
  return { status: r.rows[0]?.s ?? null, value: r.rows[0]?.value ?? null };
};

test("PG lifecycle: OPEN -> CONSUMED is terminal; cancel-after-consume, re-consume, and re-admission all refuse; same-request restamp is idempotent", { skip }, async () => {
  const record = await newProposal();
  assert.equal((await rowStatus(record.proposalId)).status, "OPEN");

  // Signature verification machinery UNCHANGED: the real owner approval verifies.
  const message = governance.approvalMessageText(config, record.proposalId, record.proposalDigest);
  const signature = kaspa.signMessage({ message, privateKey: owner.toString() });
  await governance.collectProposalApproval({ config, proposalId: record.proposalId, approverAddress: ADDR(owner), signature });

  const reqX = crypto.randomUUID();
  const loaded = await governance.loadProposalRecord(config, record.proposalId);
  await governance.markProposalConsumed(config, loaded, { requestId: reqX, txId: "ee".repeat(32) });
  const consumed = await rowStatus(record.proposalId);
  assert.equal(consumed.status, "CONSUMED", "the stored PG row carries the terminal CONSUMED status");
  assert.equal(consumed.value.lastConsumedRequestId, reqX);

  // Cancel after consume: the live defect, refused on PG.
  await expectCode(governance.cancelProposal({ config, proposalId: record.proposalId, cancelledByXOnly: XO(owner) }), 409, "GOVERNANCE_PROPOSAL_TERMINAL");
  const afterCancelAttempt = await rowStatus(record.proposalId);
  assert.equal(afterCancelAttempt.status, "CONSUMED");
  assert.equal(afterCancelAttempt.value.cancelledAt ?? null, null, "the refused cancel stamped nothing");

  // Idempotent same-request restamp; terminal against a different request.
  const before = (await rowStatus(record.proposalId)).value;
  await governance.markProposalConsumed(config, await governance.loadProposalRecord(config, record.proposalId), { requestId: reqX, txId: "ee".repeat(32) });
  assert.deepEqual((await rowStatus(record.proposalId)).value, before, "idempotent restamp changed nothing");
  await expectCode(
    governance.markProposalConsumed(config, await governance.loadProposalRecord(config, record.proposalId), { requestId: crypto.randomUUID(), txId: null }),
    409,
    "GOVERNANCE_PROPOSAL_TERMINAL"
  );
  assert.deepEqual((await rowStatus(record.proposalId)).value, before, "the first consumption evidence is permanent");

  // Re-admission and further approvals refuse at the status gate.
  const gate = governance.classifyActionV4(config, manifest, "ownerUnpause", {});
  await expectCode(
    governance.requireApprovedProposal({ config, manifest, vaultId: VAULT_ID, action: "ownerUnpause", params: {}, proposalId: record.proposalId, gate, controls: null }),
    409,
    "GOVERNANCE_PROPOSAL_CLOSED"
  );
  await expectCode(
    governance.collectProposalApproval({ config, proposalId: record.proposalId, approverAddress: ADDR(owner), signature }),
    409,
    "GOVERNANCE_PROPOSAL_CLOSED"
  );
});

test("PG cancel lane: OPEN -> CANCELLED; duplicate cancel refuses CLOSED; consume-after-cancel refuses TERMINAL; exactly one cancellation audit row", { skip }, async () => {
  const record = await newProposal();
  await governance.cancelProposal({ config, proposalId: record.proposalId, cancelledByXOnly: XO(owner) });
  assert.equal((await rowStatus(record.proposalId)).status, "CANCELLED");
  await expectCode(governance.cancelProposal({ config, proposalId: record.proposalId, cancelledByXOnly: XO(owner) }), 409, "GOVERNANCE_PROPOSAL_CLOSED");
  await expectCode(
    governance.markProposalConsumed(config, await governance.loadProposalRecord(config, record.proposalId), { requestId: crypto.randomUUID(), txId: null }),
    409,
    "GOVERNANCE_PROPOSAL_TERMINAL"
  );
  const after = await rowStatus(record.proposalId);
  assert.equal(after.status, "CANCELLED");
  assert.equal(after.value.lastConsumedRequestId ?? null, null, "no consumption evidence forged onto the cancelled record");
  const audit = await store.pool().query(
    `SELECT count(*)::int AS n FROM audit_events WHERE network_id=$1 AND proposal_id=$2 AND value->>'result'='GOVERNANCE_PROPOSAL_CANCELLED'`,
    [config.networkId, record.proposalId]
  );
  assert.equal(audit.rows[0].n, 1, "exactly one durable cancellation audit event");
});

test("PG race: concurrent cancel vs consume — exactly one wins per round, the loser refuses GOVERNANCE_PROPOSAL_TERMINAL, the row equals the winner", { skip }, async () => {
  for (let round = 0; round < 6; round++) {
    const record = await newProposal();
    const requestId = crypto.randomUUID();
    const recForConsume = await governance.loadProposalRecord(config, record.proposalId);
    const [cancelR, consumeR] = await Promise.allSettled([
      governance.cancelProposal({ config, proposalId: record.proposalId, cancelledByXOnly: XO(owner) }),
      governance.markProposalConsumed(config, recForConsume, { requestId, txId: null })
    ]);
    const winners = [cancelR, consumeR].filter((r) => r.status === "fulfilled");
    assert.equal(winners.length, 1, `round ${round}: exactly one transition wins`);
    const loser = cancelR.status === "fulfilled" ? consumeR : cancelR;
    assert.equal(loser.reason.code, "GOVERNANCE_PROPOSAL_TERMINAL", `round ${round}: deterministic loser refusal`);
    const row = await rowStatus(record.proposalId);
    if (cancelR.status === "fulfilled") {
      assert.equal(row.status, "CANCELLED", `round ${round}`);
      assert.equal(row.value.lastConsumedRequestId ?? null, null);
    } else {
      assert.equal(row.status, "CONSUMED", `round ${round}`);
      assert.equal(row.value.lastConsumedRequestId, requestId);
    }
  }
});

test("PG legacy pre-fix shapes: consumption evidence is terminal truth; unknown status fails closed; no lock residue; stale locks reclaim", { skip }, async () => {
  // (a) pre-fix consumed shape: status OPEN + lastConsumed* stamped.
  const a = await newProposal();
  await store.pool().query(
    `UPDATE governance_proposals SET value = value || $3::jsonb WHERE network_id=$1 AND key=$2`,
    [config.networkId, a.proposalId, JSON.stringify({ lastConsumedRequestId: crypto.randomUUID(), lastConsumedTxId: "ff".repeat(32), lastConsumedAt: new Date().toISOString() })]
  );
  await expectCode(governance.cancelProposal({ config, proposalId: a.proposalId, cancelledByXOnly: XO(owner) }), 409, "GOVERNANCE_PROPOSAL_TERMINAL");
  assert.equal((await rowStatus(a.proposalId)).status, "OPEN", "the refused cancel rewrote nothing (effective status is CONSUMED)");

  // (b) the live-incident damaged shape: CANCELLED label + consumption evidence -> effective CONSUMED.
  const b = await newProposal();
  await store.pool().query(
    `UPDATE governance_proposals SET value = value || $3::jsonb WHERE network_id=$1 AND key=$2`,
    [config.networkId, b.proposalId, JSON.stringify({ status: "CANCELLED", cancelledAt: new Date().toISOString(), lastConsumedRequestId: crypto.randomUUID(), lastConsumedAt: new Date().toISOString() })]
  );
  const eb = await expectCode(
    governance.collectProposalApproval({ config, proposalId: b.proposalId, approverAddress: ADDR(owner), signature: "ab".repeat(64) }),
    409,
    "GOVERNANCE_PROPOSAL_CLOSED"
  );
  assert.match(eb.message, /CONSUMED/, "gates report the effective (true) state, not the wrong label");
  await expectCode(governance.cancelProposal({ config, proposalId: b.proposalId, cancelledByXOnly: XO(owner) }), 409, "GOVERNANCE_PROPOSAL_TERMINAL");

  // (c) unknown stored status fails closed on transitions.
  const c = await newProposal();
  await store.pool().query(
    `UPDATE governance_proposals SET value = value || '{"status":"MYSTERY_FUTURE_STATE"}'::jsonb WHERE network_id=$1 AND key=$2`,
    [config.networkId, c.proposalId]
  );
  await expectCode(governance.cancelProposal({ config, proposalId: c.proposalId, cancelledByXOnly: XO(owner) }), 422, "GOVERNANCE_STATUS_UNKNOWN");
  await expectCode(
    governance.markProposalConsumed(config, await governance.loadProposalRecord(config, c.proposalId), { requestId: crypto.randomUUID(), txId: null }),
    422,
    "GOVERNANCE_STATUS_UNKNOWN"
  );

  // (d) lock hygiene: no xlock- residue from every transition above…
  const residue = await store.pool().query(`SELECT key FROM governance_proposals WHERE network_id=$1 AND key LIKE 'xlock-%'`, [config.networkId]);
  assert.deepEqual(residue.rows, [], "no transition lock residue");
  // …and a crashed (stale) holder is reclaimed deterministically.
  const d = await newProposal();
  await store.createExclusive(Categories.GOVERNANCE_PROPOSAL, `xlock-${d.proposalId}`, {
    schema: "policyvault-governance-transition-lock/v1", proposalId: d.proposalId, holderToken: "dead-holder",
    createdAt: new Date(Date.now() - 60_000).toISOString(), createdAtMs: Date.now() - 60_000
  });
  const cancelled = await governance.cancelProposal({ config, proposalId: d.proposalId, cancelledByXOnly: XO(owner) });
  assert.equal(cancelled.status, "CANCELLED", "stale lock reclaimed on PG; the transition proceeded");
  assert.equal(await store.read(Categories.GOVERNANCE_PROPOSAL, `xlock-${d.proposalId}`), null, "reclaimed lock released");
});
