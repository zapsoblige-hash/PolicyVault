"use strict";

/*
 * DRY-RUN/SIMULATION (surface 16), CAPABILITY DISCOVERY (surface 22),
 * VERSIONED PLATFORM SCHEMAS (surface 23) — completion-standard;
 * docs/postlaunch/platform-agent-api-spec.md; server/src/simulate.js,
 * server/src/capabilities.js, server/src/api.js schemaVersion handling.
 *
 * Real server api.handle() over a real seeded v0.4 vault (JSON backend,
 * hosted authMode — matches the other new test files' idiom).
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");
const os = require("os");

const { handle, loadConfig } = require("../../server/src/api");
const { Categories, getPlatformStore } = require("../../server/src/platform-store");
const { getStore, Categories: SdkCategories } = require("../src/store");
const { buildAgentTreeV4, normalizeAgentPolicyV4 } = require("../src/agent-merkle-v4");
const { buildRecipientTree } = require("../src/recipient-merkle-v3");
const { normalizeStateV4, computeStateIdV4, stateToJsonV4, CONTRACT_VERSION_V4 } = require("../src/vault-state-v4");
const { compileExactStateV4 } = require("../src/contract-compiler-v4");
const { MANIFEST_SCHEMA_V4, persistManifestV4 } = require("../src/manifest-v4");
const { saveOrgControls } = require("../../server/src/org-controls");
const org = require("../src/organization");

const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "pv-simcap-"));
const config = loadConfig({ dataRoot, authMode: "enabled", authCookieInsecure: true });
const kaspa = require(config.rustyKaspaModule);
const KEY = (v) => new kaspa.PrivateKey(v.toString(16).padStart(2, "0").repeat(32));
const XO = (p) => p.toPublicKey().toXOnlyPublicKey().toString().toLowerCase();
const ADDR = (p) => p.toPublicKey().toAddress(config.networkId).toString();
const KAS = 100000000n;

const A = KEY(0xf1);
const AGENT = KEY(0xf2);
const RECIP = KEY(0xf3);
const OTHER = KEY(0xf4);
const VAULT_ID = "6a".repeat(32);

const POST = (segs, body, headers) => handle(config, "POST", segs, {}, body, { headers: headers ?? {} });
const GET = (segs, query, headers) => handle(config, "GET", segs, query ?? {}, null, { headers: headers ?? {} });
async function expectThrow(promise, status, code) {
  try {
    await promise;
    assert.fail("expected an API error");
  } catch (e) {
    if (e.code === "ERR_ASSERTION") throw e;
    if (status !== undefined) assert.equal(e.status, status, `status ${e.status} != ${status}: ${e.message}`);
    if (code !== undefined) assert.equal(e.code, code, `code ${e.code} != ${code}: ${e.message}`);
    return e;
  }
}

async function seedVault() {
  const template = { owner: XO(A), vaultId: VAULT_ID };
  const registry = [
    {
      agentPk: XO(AGENT), maxPerSpend: (20n * KAS).toString(), periodBudget: (500n * KAS).toString(),
      periodLengthDaa: "864000", periodStartDaa: "541000000", periodSpent: "0",
      approvalThreshold: (500n * KAS).toString(), agentMaxFeePerTx: (1n * KAS).toString(),
      recipients: [XO(RECIP)]
    }
  ];
  const policies = registry.map((e) => normalizeAgentPolicyV4({ ...e, agentRecipientRoot: buildRecipientTree(e.recipients).root }));
  const state = normalizeStateV4({ protectedValue: (1000n * KAS).toString(), feeReserve: (5n * KAS).toString(), paused: "0", agentRoot: buildAgentTreeV4(policies).root, approvers: [], approvalM: "0", policyNonce: "0" });
  const compiled = compileExactStateV4({ config, template, state });
  const stateId = computeStateIdV4({ networkId: config.networkId, template, state });
  await persistManifestV4(config, {
    schema: MANIFEST_SCHEMA_V4, contractVersion: CONTRACT_VERSION_V4, networkId: config.networkId, vaultId: VAULT_ID,
    label: "simulate test", status: "ACTIVE", template, agentRegistry: registry,
    live: { state: stateToJsonV4(state), stateId, outpoint: { transactionId: "6b".repeat(32), index: 0 }, outpointValue: (state.protectedValue + state.feeReserve).toString(), scriptSha256: compiled.scriptSha256, covenantId: "6c".repeat(32) },
    creationTxId: "6d".repeat(32), latestTransitionTxId: null, lastTransition: null
  });
}
const ownerFuel = () => ({ outpoint: { transactionId: "6e".repeat(32), index: 1 }, amount: (100n * KAS).toString(), scriptPublicKeyHex: `20${XO(A)}ac` });

/* Snapshot every durable category the simulation surface must never touch. */
async function snapshotStore() {
  const store = getStore(config);
  const platformStore = getPlatformStore(config);
  const out = {};
  for (const [name, cat] of Object.entries(SdkCategories)) out[`sdk:${name}`] = (await store.listValues(cat)).length;
  for (const [name, cat] of Object.entries(Categories)) out[`platform:${name}`] = (await platformStore.listValues(cat)).length;
  const auditFile = path.join(dataRoot, "audit", "events.log");
  out.auditLines = fs.existsSync(auditFile) ? fs.readFileSync(auditFile, "utf8").trim().split("\n").filter(Boolean).length : 0;
  return out;
}

test("setup: seed a real v0.4 vault", async () => {
  await seedVault();
});

test("simulate ok:true for an in-policy agentSpend: reports review/fee/successor + intent verification, no risk/governance gate for agentSpend absent org controls, and touches NOTHING durable", async () => {
  const before = await snapshotStore();
  const r = await POST(["wallet", "v4", "simulate"], {
    vaultId: VAULT_ID, action: "agentSpend",
    params: { payAmountSompi: (5n * KAS).toString(), agentPk: XO(AGENT), recipient: XO(RECIP) },
    signerAddress: ADDR(AGENT)
  });
  assert.equal(r.status, 200);
  const sim = r.body.simulation;
  assert.equal(sim.ok, true, JSON.stringify(sim));
  assert.equal(sim.governance.governed, false);
  assert.equal(sim.risk.skipped, true);
  assert.equal(sim.review.paymentKas, "5");
  assert.match(sim.intent.manifestHash, /^[0-9a-f]{64}$/);
  assert.equal(sim.intent.ok, true);
  assert.equal(sim.intent.verdict, "VERIFIED_EXACT");
  assert.equal(sim.vmPreflight.skipped, true);
  assert.deepEqual(sim.wouldRequire, { approvals: null, proposal: false, riskRelease: false });

  const after = await snapshotStore();
  assert.deepEqual(after, before, "simulation must persist absolutely nothing — store snapshot must be byte-identical");
});

test("simulate ok:false with a precise refusalReason for an unauthorized signer, insufficient-fee-reserve builds, and unknown actions — still touches nothing", async () => {
  const before = await snapshotStore();

  const wrongSigner = await POST(["wallet", "v4", "simulate"], {
    vaultId: VAULT_ID, action: "agentSpend",
    params: { payAmountSompi: (5n * KAS).toString(), agentPk: XO(AGENT), recipient: XO(RECIP) },
    signerAddress: ADDR(OTHER)
  });
  assert.equal(wrongSigner.status, 200);
  assert.equal(wrongSigner.body.simulation.ok, false);
  assert.equal(wrongSigner.body.simulation.refusalReason.code, "NOT_AGENT");

  const unknownAction = await POST(["wallet", "v4", "simulate"], { vaultId: VAULT_ID, action: "notARealAction", params: {}, signerAddress: ADDR(A) });
  assert.equal(unknownAction.body.simulation.ok, false);
  assert.equal(unknownAction.body.simulation.refusalReason.code, "BUILD_FAILED");

  const overBudget = await POST(["wallet", "v4", "simulate"], {
    vaultId: VAULT_ID, action: "agentSpend",
    params: { payAmountSompi: (999n * KAS).toString(), agentPk: XO(AGENT), recipient: XO(RECIP) }, // exceeds maxPerSpend
    signerAddress: ADDR(AGENT)
  });
  assert.equal(overBudget.body.simulation.ok, false);
  assert.ok(overBudget.body.simulation.refusalReason.code, JSON.stringify(overBudget.body.simulation));

  const after = await snapshotStore();
  assert.deepEqual(after, before, "even refusal paths must persist nothing");
});

test("malformed INPUT (as opposed to a substantive refusal) is a real HTTP error, not an ok:false body", async () => {
  await expectThrow(POST(["wallet", "v4", "simulate"], { vaultId: "not-hex", action: "agentSpend", params: {}, signerAddress: ADDR(A) }), 400, "BAD_VAULT_ID");
  await expectThrow(POST(["wallet", "v4", "simulate"], { vaultId: VAULT_ID, action: "", params: {}, signerAddress: ADDR(A) }), 400, "BAD_ACTION");
  await expectThrow(POST(["wallet", "v4", "simulate"], { vaultId: VAULT_ID, action: "agentSpend", params: {}, signerAddress: "kaspa:bogus" }), 400, "BAD_SIGNER");
});

test("simulate reports governance classification + risk composition accurately WITHOUT consuming any gate (no proposal, no risk evaluation record, no audit row) — then the REAL route still requires them", async () => {
  const created = await org.createOrganization(config, { name: "sim-org" });
  const orgId = created.orgId;
  await org.assignVault(config, { vaultId: VAULT_ID, orgId, group: null, expectedVersion: 0, vaultExists: async () => true });
  await saveOrgControls(config, orgId, {
    governance: { quorum: { approvers: [XO(A)], m: 1 }, delayMs: 0 },
    risk: { adapters: [{ type: "amount-threshold", params: { reviewAboveSompi: (2n * KAS).toString() } }] },
    expectedVersion: 0
  });

  const before = await snapshotStore();
  const sim = await POST(["wallet", "v4", "simulate"], {
    vaultId: VAULT_ID, action: "agentSpend",
    params: { payAmountSompi: (5n * KAS).toString(), agentPk: XO(AGENT), recipient: XO(RECIP) },
    signerAddress: ADDR(AGENT)
  });
  assert.equal(sim.body.simulation.ok, true, JSON.stringify(sim.body.simulation));
  assert.equal(sim.body.simulation.risk.skipped, false);
  assert.equal(sim.body.simulation.risk.decision, "REVIEW");
  assert.equal(sim.body.simulation.wouldRequire.riskRelease, true);

  // addAgent (adding a NEW spending party to the registry) is an
  // AUTHORITY EXPANSION — and, unlike ownerPause/ownerUnpause, its
  // classification does not depend on any prior state mutation (nothing
  // in these dry-run-only tests ever finalizes/persists a real
  // transition, so testing on the vault's paused flag would be flaky).
  const newAgent = {
    agentPk: XO(OTHER), maxPerSpend: (1n * KAS).toString(), periodBudget: (2n * KAS).toString(),
    periodLengthDaa: "864000", periodStartDaa: "541000000", periodSpent: "0",
    approvalThreshold: (2n * KAS).toString(), agentMaxFeePerTx: (1n * KAS).toString(),
    recipients: [XO(RECIP)]
  };
  const governedSim = await POST(["wallet", "v4", "simulate"], {
    vaultId: VAULT_ID, action: "addAgent", params: { agent: newAgent, fuel: ownerFuel() }, signerAddress: ADDR(A)
  });
  assert.equal(governedSim.body.simulation.ok, true, JSON.stringify(governedSim.body.simulation));
  assert.equal(governedSim.body.simulation.governance.governed, true);
  assert.equal(governedSim.body.simulation.governance.classification, "EXPANSION");
  assert.equal(governedSim.body.simulation.wouldRequire.proposal, true);
  assert.deepEqual(governedSim.body.simulation.governance.quorum, { approvers: [XO(A)], m: 1 });

  const after = await snapshotStore();
  assert.deepEqual(after, before, "governance/risk REPORTING must never create a proposal, risk-evaluation record, or audit row");

  // The REAL route (not simulate) for the SAME above-REVIEW-line spend
  // genuinely requires the gate the simulation only reported.
  await expectThrow(
    POST(["wallet", "v4", "requests"], { vaultId: VAULT_ID, action: "agentSpend", params: { payAmountSompi: (5n * KAS).toString(), agentPk: XO(AGENT), recipient: XO(RECIP) }, signerAddress: ADDR(AGENT) }),
    409,
    "RISK_REVIEW_REQUIRED"
  );
});

test("break-glass actions report governed:false + risk skipped:true in simulation, matching the real route's bypass", async () => {
  const sim = await POST(["wallet", "v4", "simulate"], { vaultId: VAULT_ID, action: "ownerPause", params: { fuel: ownerFuel() }, signerAddress: ADDR(A) });
  assert.equal(sim.body.simulation.governance.governed, false);
  assert.equal(sim.body.simulation.governance.breakGlass, true);
  assert.equal(sim.body.simulation.risk.skipped, true);
  assert.equal(sim.body.simulation.risk.breakGlass, true);
});

test("capability discovery (GET /capabilities) is PUBLIC even in hosted mode, and accurately reflects code truth", async () => {
  const r = await GET(["capabilities"]);
  assert.equal(r.status, 200);
  assert.equal(r.body.schemaVersion, "policyvault-capabilities/v1");
  assert.equal(r.body.apiVersion, "v1");
  assert.equal(r.body.networkId, config.networkId);
  assert.ok(r.body.contract.supportedCovenantVersions.includes("policyvault-0.4.1"));
  assert.ok(r.body.actions.v4.some((a) => a.action === "agentSpend" && a.role === "agent"));
  assert.ok(r.body.scopes.some((s) => s.scope === "request:build"));
  assert.equal(r.body.features.machineIdentities, true, "hosted mode: machine identities are available");
  assert.equal(r.body.features.dryRunSimulation, true);
  assert.equal(r.body.features.capabilityDiscovery, true);

  // Public: no cookie, no Authorization header, no throw.
  const selfHosted = loadConfig({ dataRoot: fs.mkdtempSync(path.join(os.tmpdir(), "pv-simcap-sh-")) });
  const rSelfHosted = await handle(selfHosted, "GET", ["capabilities"], {}, null, { headers: {} });
  assert.equal(rSelfHosted.status, 200);
  assert.equal(rSelfHosted.body.features.machineIdentities, false, "self-hosted mode: no machine-identity surface");
});

test("schemaVersion: omitted is unchanged behavior; the exact current version is accepted; an unrecognized version fails CLOSED (never routed to a default)", async () => {
  const omitted = await POST(["wallet", "v4", "simulate"], { vaultId: VAULT_ID, action: "agentSpend", params: { payAmountSompi: (1n * KAS).toString(), agentPk: XO(AGENT), recipient: XO(RECIP) }, signerAddress: ADDR(AGENT) });
  assert.equal(omitted.status, 200);
  assert.equal(omitted.body.schemaVersion, "policyvault-wallet-v4-request/v1");

  const current = await POST(["wallet", "v4", "simulate"], {
    vaultId: VAULT_ID, action: "agentSpend", params: { payAmountSompi: (1n * KAS).toString(), agentPk: XO(AGENT), recipient: XO(RECIP) }, signerAddress: ADDR(AGENT),
    schemaVersion: "policyvault-wallet-v4-request/v1"
  });
  assert.equal(current.status, 200);

  await expectThrow(
    POST(["wallet", "v4", "simulate"], {
      vaultId: VAULT_ID, action: "agentSpend", params: {}, signerAddress: ADDR(AGENT), schemaVersion: "policyvault-wallet-v4-request/v99-from-the-future"
    }),
    422,
    "SCHEMA_VERSION_UNSUPPORTED"
  );

  // The SAME fail-closed rule applies to the real build route (build/create) too.
  await expectThrow(
    POST(["wallet", "v4", "requests"], { vaultId: VAULT_ID, action: "agentSpend", params: {}, signerAddress: ADDR(AGENT), schemaVersion: "downgrade-attempt/v0" }),
    422,
    "SCHEMA_VERSION_UNSUPPORTED"
  );

  // Every real v4 response (not just simulate) is additively stamped.
  const real = await POST(["wallet", "v4", "requests"], { vaultId: VAULT_ID, action: "agentSpend", params: { payAmountSompi: (1n * KAS).toString(), agentPk: XO(AGENT), recipient: XO(RECIP) }, signerAddress: ADDR(AGENT) });
  assert.equal(real.status, 201);
  assert.equal(real.body.schemaVersion, "policyvault-wallet-v4-request/v1");
  assert.ok(real.body.request, "the schemaVersion stamp is ADDITIVE — the existing `request` field is untouched");
});
