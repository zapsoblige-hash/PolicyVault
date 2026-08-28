"use strict";

/*
 * REAL-DOCUMENT INTEGRATION for the browser verifier (F2 wave).
 *
 * The fixture suites (helpers.js) compute their fees/state ids with the
 * SAME core modules web/verify-intent.js recomputes with — deliberate for
 * unit precision, but circular as evidence that the REAL system agrees.
 * This suite breaks the circularity: it stands up the REAL server over
 * HTTP, seeds a REAL v0.4.1 vault manifest, has the REAL SDK builders
 * (buildWalletRequestV4 / buildCreateWalletRequestV4 — silverscript
 * compilation, pv_call_encoder, real kaspa-wasm serialization, the real
 * exactFee call path) produce the request documents the browser actually
 * receives, and drives those EXACT documents + the REAL presentVaultV4
 * output through verifyBeforeSigning with the REAL committed core bundle.
 *
 * A PASS here proves the independent recomputations (fee floor/exact,
 * compute-budget tiers, canonical successor states, state ids) accept
 * what the production pipeline actually builds; the tamper cases prove
 * the same real documents are refused the moment one recomputable fact
 * is falsified. Layers: API + BROWSER-VERIFIER. No broadcast, no node.
 *
 * Environment: needs sdk/node_modules (kaspa-wasm) and the gitignored
 * tests/vm probe binaries (pv_call_encoder, pv_tx_probe ...) — consumed
 * read-only, as in the F1/approver-wallet suites.
 */

const { test, before, after } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const { loadConfig } = require("../../sdk/src/config");
const { createServer } = require("../../server/src/server");
const { buildAgentTreeV4, normalizeAgentPolicyV4 } = require("../../core/model/agent-merkle-v4.js");
const { buildRecipientTree } = require("../../core/model/recipient-merkle-v3.js");
const { normalizeStateV4, computeStateIdV4, stateToJsonV4, CONTRACT_VERSION_V4_1 } = require("../../core/model/vault-state-v4.js");
const { sompiToKas } = require("../../core/model/amounts.js");
const { compileExactStateV4 } = require("../../sdk/src/contract-compiler-v4");
const { MANIFEST_SCHEMA_V4, persistManifestV4 } = require("../../sdk/src/manifest-v4");

const core = require("../core-bundle.js");
const { createVerifyIntent } = require("../verify-intent.js");
const vi = createVerifyIntent(core);

const config = loadConfig({ dataRoot: fs.mkdtempSync(path.join(os.tmpdir(), "pv-verify-real-")) });
const kaspa = require(config.rustyKaspaModule);
const KEYHEX = (v) => v.toString(16).padStart(2, "0").repeat(32);
const KEY = (v) => new kaspa.PrivateKey(KEYHEX(v));
const XO = (v) => KEY(v).toPublicKey().toXOnlyPublicKey().toString().toLowerCase();
const ADDR = (v) => KEY(v).toPublicKey().toAddress(config.networkId).toString();
const KAS = 100000000n;
const OWNER = 3, AGENT = 0x2e, APPR_A = 0x61, APPR_B = 0x62, RECIP = 0x38;
const VAULT = "7b".repeat(32);
const p2pk = (x) => `20${x}ac`;

let BASE = null;
let server;

async function seed() {
  const registry = [{
    agentPk: XO(AGENT),
    maxPerSpend: (20n * KAS).toString(),
    periodBudget: (50n * KAS).toString(),
    periodLengthDaa: "864000",
    periodStartDaa: "541000000",
    periodSpent: "0",
    approvalThreshold: (5n * KAS).toString(),
    agentMaxFeePerTx: (1n * KAS).toString(),
    recipients: [XO(RECIP)]
  }];
  const template = { owner: XO(OWNER), vaultId: VAULT };
  const policies = registry.map((e) => normalizeAgentPolicyV4({ ...e, agentRecipientRoot: buildRecipientTree(e.recipients).root }));
  const state = normalizeStateV4({
    protectedValue: (1000n * KAS).toString(),
    feeReserve: (5n * KAS).toString(),
    paused: "0",
    agentRoot: buildAgentTreeV4(policies).root,
    approvers: [XO(APPR_A), XO(APPR_B)],
    approvalM: "2",
    policyNonce: "0"
  });
  const compiled = compileExactStateV4({ config, template, state, contractVersion: CONTRACT_VERSION_V4_1 });
  const stateId = computeStateIdV4({ networkId: config.networkId, template, state, contractVersion: CONTRACT_VERSION_V4_1 });
  await persistManifestV4(config, {
    schema: MANIFEST_SCHEMA_V4,
    contractVersion: CONTRACT_VERSION_V4_1,
    networkId: config.networkId,
    vaultId: VAULT,
    label: "verify-real",
    status: "ACTIVE",
    template,
    agentRegistry: registry,
    live: {
      state: stateToJsonV4(state),
      stateId,
      outpoint: { transactionId: "57".repeat(32), index: 0 },
      outpointValue: (state.protectedValue + state.feeReserve).toString(),
      scriptSha256: compiled.scriptSha256,
      covenantId: "51".repeat(32)
    },
    creationTxId: "52".repeat(32),
    latestTransitionTxId: null,
    lastTransition: null
  });
}

const post = async (url, body) => {
  const r = await fetch(BASE + url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body ?? {}) });
  return { status: r.status, j: await r.json() };
};
const get = async (url) => {
  const r = await fetch(BASE + url);
  return { status: r.status, j: await r.json() };
};

before(async () => {
  await seed();
  server = createServer(config);
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  BASE = `http://127.0.0.1:${server.address().port}/api/v1`;
});
after(() => server && server.close());

function expectRealPass(outcome, label) {
  assert.equal(outcome.ok, true, `${label}: expected PASS on the REAL document, got ${JSON.stringify(outcome.refusalCodes)}\n${(outcome.lines || []).join("\n")}`);
  assert.equal(outcome.verdict, "VERIFIED_EXACT");
}

let SPEND = null; // the real below-threshold reserve-funded spend request
let VAULT_DOC = null;

test("REAL: presentVaultV4 output passes the predecessor recomputations (registry root + canonical state id)", async () => {
  const r = await get(`/vaults/${VAULT}`);
  assert.equal(r.status, 200);
  VAULT_DOC = r.j;
  assert.equal(VAULT_DOC.networkId, config.networkId);
  // the view's stateId IS the canonical commitment of the presented state —
  // exactly what knowledgeFromVault now recomputes and enforces
  assert.match(VAULT_DOC.live.stateId, /^[0-9a-f]{64}$/);
});

test("REAL: a below-threshold reserve-funded agentSpend built by the REAL SDK passes every independent recomputation", async () => {
  const r = await post("/wallet/v4/requests", {
    vaultId: VAULT,
    action: "agentSpend",
    params: { agentPk: XO(AGENT), recipient: XO(RECIP), payAmountSompi: (2n * KAS).toString() },
    signerAddress: ADDR(AGENT)
  });
  assert.equal(r.status, 201, JSON.stringify(r.j).slice(0, 300));
  SPEND = r.j.request;
  assert.equal(SPEND.state, "BUILT");
  const out = vi.verifyBeforeSigning({
    request: SPEND,
    vault: VAULT_DOC,
    clientAction: "agentSpend",
    clientParams: { agentPk: XO(AGENT), recipient: XO(RECIP), payAmountSompi: (2n * KAS).toString() },
    sessionNetwork: config.networkId,
    sessionXOnly: XO(AGENT)
  });
  expectRealPass(out, "real reserve-funded spend");
  // the REAL builder's fee satisfied the recomputed floor, its budgets the
  // canonical tiers, and its successorStateId the canonical commitment
  assert.ok(out.notes.some((n) => n.includes("network-fee lower bound")), "fee-floor note on the real document");
  assert.ok(out.notes.some((n) => n.includes("compute budgets")), "budget-pinning note on the real document");
  assert.ok(out.notes.some((n) => n.includes("successor state id")), "state-id recomputation note on the real document");
  // sanity outside the verifier: the REAL committed covenant budget is the canonical tier
  const payload = JSON.parse(SPEND.transaction.unsignedSafeJson);
  assert.equal(payload.inputs[0].computeBudget, 32, "the REAL SDK committed the canonical below-threshold spend tier");
  /* F2-1 RESOLVED: the SDK now finalize()s the unsigned wasm transaction
   * before serializeToSafeJSON (txids exclude signature scripts), so the
   * payload-embedded id IS the consensus id — held to strict equality
   * against the probe-computed claim here AND inside verify-intent
   * (TXID_MISMATCH on divergence). */
  assert.equal(payload.id, SPEND.txId, "F2-1 resolved: unsigned-payload embedded id equals the consensus txId claim");
});

test("REAL-TAMPER: a payload whose embedded id diverges from the txId claim refuses (TXID_MISMATCH)", () => {
  const s = structuredClone(SPEND);
  const tampered = JSON.parse(s.transaction.unsignedSafeJson);
  tampered.id = tampered.id.slice(0, 63) + (tampered.id.endsWith("0") ? "1" : "0");
  s.transaction = { ...s.transaction, unsignedSafeJson: JSON.stringify(tampered) };
  const out = vi.verifyBeforeSigning({
    request: s,
    vault: VAULT_DOC,
    clientAction: "agentSpend",
    clientParams: { agentPk: XO(AGENT), recipient: XO(RECIP), payAmountSompi: (2n * KAS).toString() },
    sessionNetwork: config.networkId,
    sessionXOnly: XO(AGENT)
  });
  assert.equal(out.ok, false);
  assert.ok(out.refusalCodes.includes("TXID_MISMATCH"), JSON.stringify(out.refusalCodes));
});

test("REAL-TAMPER: one flipped hex digit in the REAL request's successorStateId refuses (STATE_ID_MISMATCH)", () => {
  const s = structuredClone(SPEND);
  const id = s.successorStateId;
  const flipped = (id[0] === "0" ? "1" : "0") + id.slice(1);
  s.successorStateId = flipped;
  s.review.successorStateId = flipped;
  const out = vi.verifyBeforeSigning({
    request: s,
    vault: VAULT_DOC,
    clientAction: "agentSpend",
    clientParams: { agentPk: XO(AGENT), recipient: XO(RECIP), payAmountSompi: (2n * KAS).toString() },
    sessionNetwork: config.networkId,
    sessionXOnly: XO(AGENT)
  });
  assert.equal(out.ok, false);
  assert.ok(out.refusalCodes.includes("STATE_ID_MISMATCH"), JSON.stringify(out.refusalCodes));
});

test("REAL-TAMPER: the REAL payload with a de-tiered compute budget refuses (COMPUTE_BUDGET_MISMATCH)", () => {
  const s = structuredClone(SPEND);
  const tx = JSON.parse(s.transaction.unsignedSafeJson);
  tx.inputs[0].computeBudget = 31;
  s.transaction.unsignedSafeJson = JSON.stringify(tx);
  s.review.computeBudget = 31; // consistent lie
  const out = vi.verifyBeforeSigning({
    request: s,
    vault: VAULT_DOC,
    clientAction: "agentSpend",
    clientParams: { agentPk: XO(AGENT), recipient: XO(RECIP), payAmountSompi: (2n * KAS).toString() },
    sessionNetwork: config.networkId,
    sessionXOnly: XO(AGENT)
  });
  assert.equal(out.ok, false);
  assert.ok(out.refusalCodes.includes("COMPUTE_BUDGET_MISMATCH"), JSON.stringify(out.refusalCodes));
});

test("REAL: an ownerTopUp built by the REAL SDK (fuel-funded) passes every independent recomputation", async () => {
  const fuel = {
    outpoint: { transactionId: "58".repeat(32), index: 1 },
    amount: (10n * KAS).toString(),
    scriptPublicKeyHex: p2pk(XO(OWNER))
  };
  const r = await post("/wallet/v4/requests", {
    vaultId: VAULT,
    action: "ownerTopUp",
    params: { topUpAmountSompi: (7n * KAS).toString(), fuel },
    signerAddress: ADDR(OWNER)
  });
  assert.equal(r.status, 201, JSON.stringify(r.j).slice(0, 300));
  const req = r.j.request;
  const out = vi.verifyBeforeSigning({
    request: req,
    vault: VAULT_DOC,
    clientAction: "ownerTopUp",
    clientParams: { topUpAmountSompi: (7n * KAS).toString() },
    clientFuel: { outpoint: fuel.outpoint, amount: fuel.amount },
    sessionNetwork: config.networkId,
    sessionXOnly: XO(OWNER)
  });
  expectRealPass(out, "real owner top-up");
  const payload = JSON.parse(req.transaction.unsignedSafeJson);
  assert.equal(payload.inputs[0].computeBudget, 30, "the REAL SDK committed the canonical owner-op tier");
  assert.equal(payload.inputs[1].computeBudget, 10, "the REAL SDK committed the ordinary fuel tier");
});

let CREATE = null;
const DEPOSIT = 700n * KAS;
const RESERVE = 3n * KAS;
const NEW_VAULT = "7c".repeat(32);

test("REAL: a genesis built by the REAL SDK passes the EXACT fee recomputation (all-ordinary-input shape)", async () => {
  const r = await post("/wallet/v4/create", {
    // canonical schema — fully offline (the friendly schema needs a live node for DAA)
    templateInput: { owner: XO(OWNER), vaultId: NEW_VAULT },
    initialAgents: [{
      agentPk: XO(AGENT),
      maxPerSpend: (20n * KAS).toString(),
      periodBudget: (50n * KAS).toString(),
      periodLengthDaa: "864000",
      periodStartDaa: "541000000",
      periodSpent: "0",
      approvalThreshold: (5n * KAS).toString(),
      agentMaxFeePerTx: (1n * KAS).toString(),
      recipients: [XO(RECIP)]
    }],
    initialState: { protectedValue: DEPOSIT.toString(), feeReserve: RESERVE.toString(), approvers: [XO(APPR_A), XO(APPR_B)], approvalM: "2" },
    signerAddress: ADDR(OWNER),
    funding: [{ outpoint: { transactionId: "59".repeat(32), index: 0 }, amount: (800n * KAS).toString(), scriptPublicKeyHex: p2pk(XO(OWNER)) }],
    label: "verify-real-genesis",
    contractVersion: CONTRACT_VERSION_V4_1
  });
  assert.equal(r.status, 201, JSON.stringify(r.j).slice(0, 300));
  CREATE = r.j.request;
  const out = vi.verifyBeforeSigning({
    request: CREATE,
    createContext: {
      vaultId: NEW_VAULT,
      depositKas: sompiToKas(DEPOSIT),
      feeReserveKas: sompiToKas(RESERVE),
      approvalM: "2",
      approverXOnlys: [XO(APPR_A), XO(APPR_B)],
      agentXOnly: XO(AGENT)
    },
    sessionNetwork: config.networkId,
    sessionXOnly: XO(OWNER)
  });
  expectRealPass(out, "real genesis");
  assert.ok(out.notes.some((n) => n.includes("network fee (EXACT")), "the REAL genesis fee equals the browser's exact recomputation");
  assert.ok(out.notes.some((n) => n.includes("genesis state id")), "genesis state id recomputed on the real document");
  // residuals wave: the REAL presented document disclosed the registry
  // tuples and the genesis agentRoot was RECOMPUTED from them (no claim)
  assert.ok(out.notes.some((n) => n.includes("Independently recomputed") && n.includes("genesis agent-registry root")), "genesis agent-registry root recomputed from the REAL document's initialRegistry");
  assert.ok(Array.isArray(CREATE.initialRegistry) && CREATE.initialRegistry.length === 1, "the REAL presented genesis document carries initialRegistry");
});

test("REAL-TAMPER: a tampered tuple in the REAL genesis document's initialRegistry refuses (AGENT_REGISTRY_ROOT_MISMATCH)", () => {
  const s = structuredClone(CREATE);
  s.initialRegistry[0].maxPerSpend = (500n * KAS).toString(); // root left as served
  const out = vi.verifyBeforeSigning({
    request: s,
    createContext: {
      vaultId: NEW_VAULT,
      depositKas: sompiToKas(DEPOSIT),
      feeReserveKas: sompiToKas(RESERVE),
      approvalM: "2",
      approverXOnlys: [XO(APPR_A), XO(APPR_B)],
      agentXOnly: XO(AGENT)
    },
    sessionNetwork: config.networkId,
    sessionXOnly: XO(OWNER)
  });
  assert.equal(out.ok, false);
  assert.ok(out.refusalCodes.includes("AGENT_REGISTRY_ROOT_MISMATCH"), JSON.stringify(out.refusalCodes));
});

test("REAL-TAMPER: the REAL genesis payload with its fee moved by ONE SOMPI refuses (FEE_MISMATCH)", () => {
  const s = structuredClone(CREATE);
  const tx = JSON.parse(s.transaction.unsignedSafeJson);
  const changeIdx = tx.outputs.findIndex((o) => o.covenant === null);
  tx.outputs[changeIdx].value = (BigInt(tx.outputs[changeIdx].value) - 1n).toString(); // fee +1
  s.transaction.unsignedSafeJson = JSON.stringify(tx);
  const out = vi.verifyBeforeSigning({
    request: s,
    createContext: {
      vaultId: NEW_VAULT,
      depositKas: sompiToKas(DEPOSIT),
      feeReserveKas: sompiToKas(RESERVE),
      approvalM: "2",
      approverXOnlys: [XO(APPR_A), XO(APPR_B)],
      agentXOnly: XO(AGENT)
    },
    sessionNetwork: config.networkId,
    sessionXOnly: XO(OWNER)
  });
  assert.equal(out.ok, false);
  assert.ok(out.refusalCodes.includes("FEE_MISMATCH"), JSON.stringify(out.refusalCodes));
});
