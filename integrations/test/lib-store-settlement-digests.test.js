"use strict";

/* UNIT — attempt store (create-only + write-once + quarantine mechanics),
 * settlement classifier/evidence/poller (chain-proven-only), and the
 * §3.4 digest derivations (domain separation + key-order independence —
 * the G-2 property at the unit layer; live-PG round trip is a separate
 * suite). */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const http = require("node:http");
const { tmpdir } = require("./helpers/fixtures");
const { AttemptStore, AttemptStoreError } = require("../lib/attempt-store");
const { classifyRequestState, settlementEvidenceFrom, pollForSettlement } = require("../lib/settlement");
const digests = require("../lib/digests");

test("attempt store: claim is create-exclusive; duplicate claims lose and see the existing record", () => {
  const store = new AttemptStore({ dir: tmpdir("pv-store-") });
  const record = { attemptId: "a1", outcome: { status: "IN_PROGRESS", stage: "normalize", codes: [], at: new Date().toISOString() } };
  assert.equal(store.claim("a1", record).claimed, true);
  const second = store.claim("a1", { other: true });
  assert.equal(second.claimed, false);
  assert.equal(second.existing.attemptId, "a1");
});

test("attempt store: outcome transitions append history; correlation fields are write-once; everything else is frozen", () => {
  const store = new AttemptStore({ dir: tmpdir("pv-store-") });
  store.claim("a1", { attemptId: "a1", requestId: null, protocol: { protocol: "x402", settlementResponseRaw: null }, outcome: { status: "IN_PROGRESS", stage: "normalize", codes: [], at: new Date().toISOString() } });
  const t1 = store.transition("a1", { status: "PENDING", stage: "build", codes: [] }, { set: { requestId: "r1" } });
  assert.equal(t1.requestId, "r1");
  assert.equal(t1.outcomeHistory.length, 1);
  // write-once: same value is idempotent, a different value refuses
  store.transition("a1", { status: "PENDING", stage: "build", codes: [] }, { set: { requestId: "r1" } });
  assert.throws(() => store.transition("a1", { status: "PENDING", stage: "build", codes: [] }, { set: { requestId: "r2" } }), (e) => e instanceof AttemptStoreError && e.code === "FIELD_FROZEN");
  // non-additive fields refuse
  assert.throws(() => store.transition("a1", { status: "PENDING", stage: "build", codes: [] }, { set: { normalized: {} } }), (e) => e.code === "FIELD_FROZEN");
  // protocol.settlementResponseRaw: write-once through its dedicated slot
  store.transition("a1", { status: "SETTLED", stage: "deliver", codes: [] }, { set: { settlementResponseRaw: "{}" } });
  assert.throws(() => store.transition("a1", { status: "SETTLED", stage: "deliver", codes: [] }, { set: { settlementResponseRaw: "{2}" } }), (e) => e.code === "FIELD_FROZEN");
});

test("settlement classifier: CHAIN_VERIFIED alone settles; unknown/reconciliation states fail closed; submitTransaction-returned states never settle", () => {
  assert.equal(classifyRequestState("CHAIN_VERIFIED"), "SETTLED");
  assert.equal(classifyRequestState("SUBMITTED"), "IN_FLIGHT");
  assert.equal(classifyRequestState("SUBMITTING"), "IN_FLIGHT");
  assert.equal(classifyRequestState("RECONCILIATION_REQUIRED"), "UNKNOWN");
  assert.equal(classifyRequestState("TERMINATED_UNKNOWN"), "UNKNOWN");
  assert.equal(classifyRequestState("BUILT"), "PENDING_SIGNATURE");
  assert.equal(classifyRequestState("AWAITING_APPROVALS"), "PENDING_APPROVALS");
  assert.equal(classifyRequestState("PREFLIGHT_VERIFIED"), "READY_TO_SUBMIT");
  assert.equal(classifyRequestState("SUBMISSION_REJECTED"), "FAILED");
  assert.equal(classifyRequestState("SOME_FUTURE_STATE"), "FAILED");
  assert.equal(classifyRequestState(null), "UNKNOWN");
});

test("settlement evidence is refused for anything not CHAIN_VERIFIED", () => {
  assert.throws(() => settlementEvidenceFrom({ state: "SUBMITTED", txId: "aa".repeat(32) }), /not CHAIN_VERIFIED/);
  const evidence = settlementEvidenceFrom({ state: "CHAIN_VERIFIED", txId: "aa".repeat(32), successorStateId: "bb".repeat(32), manifestHash: "cc".repeat(32), review: { feeSompi: "17000" } });
  assert.deepEqual(evidence, { txId: "aa".repeat(32), successorStateId: "bb".repeat(32), manifestHash: "cc".repeat(32), feeSompi: "17000", requestState: "CHAIN_VERIFIED" });
});

test("settlement poller: polls through IN_FLIGHT, settles only on CHAIN_VERIFIED, and reports UNKNOWN (never settled) at the attempt cap", async () => {
  const states = ["SUBMITTED", "SUBMITTED", "CHAIN_VERIFIED"];
  let i = 0;
  const server = http.createServer((req, res) => {
    const state = states[Math.min(i, states.length - 1)];
    i += 1;
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ request: { requestId: "r1", state, txId: "aa".repeat(32), review: { feeSompi: "1" } } }));
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const { PolicyVaultClient } = require("../../sdk/src/http-client");
  const client = new PolicyVaultClient({ baseUrl: `http://127.0.0.1:${server.address().port}` });
  const settled = await pollForSettlement(client, "r1", { attempts: 5, delayMs: 1 });
  assert.equal(settled.classification, "SETTLED");

  i = 0;
  states.length = 0;
  states.push("SUBMITTED"); // never advances
  const stuck = await pollForSettlement(client, "r1", { attempts: 3, delayMs: 1 });
  assert.equal(stuck.classification, "UNKNOWN");
  await new Promise((r) => server.close(r));
});

test("digests: key-order independent, domain-separated, and distinct across adapters (G-2 unit layer)", () => {
  const a = digests.x402RequirementDigest({ x402Version: 2, resource: { url: "https://a", mimeType: "t" }, accepted: { scheme: "exact", amount: "5" } });
  const b = digests.x402RequirementDigest({ x402Version: 2, resource: { mimeType: "t", url: "https://a" }, accepted: { amount: "5", scheme: "exact" } });
  assert.equal(a, b);
  const c = digests.x402RequirementDigest({ x402Version: 2, resource: { url: "https://a", mimeType: "t" }, accepted: { scheme: "exact", amount: "6" } });
  assert.notEqual(a, c);

  const key1 = digests.x402IdempotencyKey({ attemptId: "at", requirementDigest: a, vaultId: "v", agentPk: "p" });
  assert.match(key1, /^pvx402-[0-9a-f]{64}$/);
  // Same inputs, different domain: the AP2 key can never collide with the x402 key.
  const key2 = digests.ap2IdempotencyKey({ transaction_id: "at", paymentMandateDigest: a, vaultId: "v", agentPk: "p" });
  assert.match(key2, /^pvap2-[0-9a-f]{64}$/);
  assert.notEqual(key1.slice(7), key2.slice(6));

  // AP2 mandate digest: absent exp commits as null (one value, one encoding).
  const m1 = digests.ap2MandateDigest({ vct: "mandate.payment.1", transaction_id: "t", payee: { id: "m" }, payment_amount: { amount: 1, currency: "KAS" }, payment_instrument: { id: "i", type: "t" } });
  const m2 = digests.ap2MandateDigest({ vct: "mandate.payment.1", transaction_id: "t", payee: { id: "m" }, payment_amount: { currency: "KAS", amount: 1 }, payment_instrument: { type: "t", id: "i" }, exp: undefined });
  assert.equal(m1, m2);
});

test("digest preimage domains are the spec's exact strings", () => {
  assert.equal(digests.X402_REQUIREMENT_DOMAIN, "policyvault-x402-requirement-digest/1");
  assert.equal(digests.X402_IDEMPOTENCY_DOMAIN, "policyvault-x402-idempotency/1");
  assert.equal(digests.AP2_MANDATE_DOMAIN, "policyvault-ap2-mandate-digest/1");
  assert.equal(digests.AP2_IDEMPOTENCY_DOMAIN, "policyvault-ap2-idempotency/1");
});
