"use strict";

/*
 * R7-05 (browser initiation of rooted-vault owner operations, launch scope
 * 2026-09-08): GET /org-roots/:id/vaults presents, beside the live state,
 * what an owner needs to prefill and review an operation truthfully — the
 * installed delegate registry as SDK registry-entry JSON (policy fields +
 * recipients; the exact shape sdk/src/manifest-v7 normalizeRegistry accepts
 * back), the pinned recovery key, the generation, the asset display fields.
 * Presentation only: the numbers are the manifest's own, nothing is trusted
 * back from a client, and the route's tenancy scoping is unchanged (pinned
 * by sdk/test/hosted-foreign-tenant-matrix.test.js).
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const { presentRootedVaultSummary } = require("../../server/src/org-roots");
const { normalizeRegistry, registryEntryToJson } = require("../src/manifest-v7");
const { buildRecipientTree } = require("../../core/model/recipient-merkle-v3");

const K = (b) => b.toString(16).padStart(2, "0").repeat(32);

function manifest(overrides = {}) {
  const recipients = [K(0x33), K(0x34)];
  const { entries } = normalizeRegistry([{ agentPk: K(0x22), tokenMaxPerSpend: "250", tokenPeriodBudget: "2000", periodLengthDaa: "100000000", periodStartDaa: "12345", tokenPeriodSpent: "7", agentMaxFeePerTx: "100000000", agentMaxCarryKas: "25000000", recipients }]);
  return {
    vaultId: K(0xee), label: "Ops", status: "ACTIVE", orgRootCovenantId: K(0xaa), contractVersion: "policyvault-0.7-payment", generation: 3, latestTransitionTxId: K(0xcc),
    template: { recoveryPk: K(0x99), orgRootCovenantId: K(0xaa) },
    asset: { descriptor: { assetId: K(0x11), displayName: "Org Treasury Token", tokenStandard: "kcc20/1", decimalsDisplay: 2 }, descriptorHash: K(0x12), templateIndex: 0 },
    agentRegistry: entries,
    live: { covenantId: K(0xbb), outpoint: { transactionId: K(0xcc), index: 1 }, state: { feeReserve: 150000000n, paused: 0n }, tokenPosition: null },
    ...overrides
  };
}

test("presentRootedVaultSummary carries the installed registry as registry-entry JSON (policy strings + recipients), the pinned recovery key, generation and asset display fields", () => {
  const m = manifest();
  const p = presentRootedVaultSummary(m);
  assert.equal(p.vaultId, m.vaultId);
  assert.equal(p.contractVersion, "policyvault-0.7-payment");
  assert.equal(p.authorityModel, "ON_CHAIN_ORGANIZATIONAL_ROOT");
  assert.equal(p.generation, 3);
  assert.equal(p.latestTransitionTxId, K(0xcc));
  assert.equal(p.recoveryPk, K(0x99));
  assert.deepEqual(p.asset, { assetId: K(0x11), displayName: "Org Treasury Token", tokenStandard: "kcc20/1", decimalsDisplay: 2 });
  assert.equal(p.live.feeReserveKas, "1.5");
  assert.equal(p.live.paused, false);
  assert.equal(p.agents.length, 1);
  const a = p.agents[0];
  assert.deepEqual(a, registryEntryToJson(m.agentRegistry[0]), "the exact SDK registry-entry JSON");
  assert.equal(a.agentPk, K(0x22));
  assert.equal(a.tokenMaxPerSpend, "250"); assert.equal(a.tokenPeriodBudget, "2000"); assert.equal(a.periodLengthDaa, "100000000");
  assert.equal(a.periodStartDaa, "12345"); assert.equal(a.tokenPeriodSpent, "7"); assert.equal(a.agentMaxFeePerTx, "100000000"); assert.equal(a.agentMaxCarryKas, "25000000");
  assert.deepEqual(a.recipients, [K(0x33), K(0x34)]);
  assert.equal(a.agentRecipientRoot, buildRecipientTree([K(0x33), K(0x34)]).root, "the recipient commitment the covenant enforces");
  for (const v of Object.values(a)) assert.ok(typeof v === "string" || Array.isArray(v), "JSON-safe (no BigInt) — the browser reads it back into the same validator");
  assert.equal(JSON.stringify(p).includes("undefined"), false);
  /* round trip: the presented entries are accepted back by the SDK's registry normalizer unchanged */
  const { tree } = normalizeRegistry(p.agents);
  assert.equal(tree.root, normalizeRegistry([registryEntryToJson(m.agentRegistry[0])]).tree.root);
});

test("presentRootedVaultSummary fails soft on absent optional facts (no registry → [], no recovery key → null, terminal vault with live:null) and never invents them", () => {
  const p = presentRootedVaultSummary(manifest({ agentRegistry: undefined, template: {}, asset: undefined, generation: undefined, latestTransitionTxId: undefined, status: "RECOVERED", live: null }));
  assert.deepEqual(p.agents, []);
  assert.equal(p.recoveryPk, null);
  assert.equal(p.asset, null);
  assert.equal(p.generation, null);
  assert.equal(p.latestTransitionTxId, null);
  assert.equal(p.status, "RECOVERED");
  assert.equal(p.live, null);
});
