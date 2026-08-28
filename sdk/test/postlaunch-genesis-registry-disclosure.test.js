"use strict";

/*
 * GENESIS REGISTRY DISCLOSURE PIN (residuals wave; server/src/api.js
 * presentRequest + api-version.js v1 shape note).
 *
 * The presented v0.4 GENESIS wallet-request document MUST carry
 * `initialRegistry` — the initial agent registry's full leaf tuples (the
 * exact nine fields core/model/agent-merkle-v4.js agentLeafHash consumes)
 * plus each agent's recipient x-only keys — in a form the browser can
 * independently recompute initialState.agentRoot from. web/verify-intent.js
 * FAILS CLOSED on genesis documents without it, so stripping the field in
 * presentRequest would render every honest create flow DO-NOT-SIGN (a
 * G-2-class fail-closed availability break). This suite pins:
 *   1. the field is present on the create response AND on the reload
 *      (GET by id) path, with exactly the expected tuple shape;
 *   2. the disclosed tuples actually recompute to the presented
 *      initialState.agentRoot (and each allowlist root to its recipients);
 *   3. the presenter still strips the server-internal fields
 *      (build/encoderBuildDir/approvalPackage/newRegistry/finalTransaction).
 *
 * Layers: API (real api.handle(), JSON backend, offline canonical-schema
 * genesis — no node, no broadcast). Needs the gitignored tests/vm probe
 * binaries (real silverscript compile + pv_call_encoder) and
 * sdk/node_modules (kaspa-wasm), like the other postlaunch suites.
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");
const os = require("os");

const { handle, loadConfig } = require("../../server/src/api");
const { buildAgentTreeV4 } = require("../src/agent-merkle-v4");
const { buildRecipientTree } = require("../src/recipient-merkle-v3");

const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "pv-genesis-disclosure-"));
const config = loadConfig({ dataRoot });
const kaspa = require(config.rustyKaspaModule);
const KEY = (v) => new kaspa.PrivateKey(v.toString(16).padStart(2, "0").repeat(32));
const XO = (p) => p.toPublicKey().toXOnlyPublicKey().toString().toLowerCase();
const ADDR = (p) => p.toPublicKey().toAddress(config.networkId).toString();
const KAS = 100000000n;

const OWNER = KEY(0xa3);
const AGENT = KEY(0xa4);
const RECIP_1 = KEY(0xa5);
const RECIP_2 = KEY(0xa6);
const APPR = KEY(0xa7);
const VAULT_ID = "3c".repeat(32);
const p2pk = (x) => `20${x}ac`;

const POST = (segs, body) => handle(config, "POST", segs, {}, body, { headers: {} });
const GET = (segs) => handle(config, "GET", segs, {}, null, { headers: {} });

const AGENT_ENTRY = {
  agentPk: null, // filled below
  maxPerSpend: (20n * KAS).toString(),
  periodBudget: (50n * KAS).toString(),
  periodLengthDaa: "864000",
  periodStartDaa: "541000000",
  periodSpent: "0",
  approvalThreshold: (5n * KAS).toString(),
  agentMaxFeePerTx: (1n * KAS).toString(),
  recipients: null // filled below
};

const LEAF_FIELDS = [
  "agentPk",
  "maxPerSpend",
  "periodBudget",
  "periodLengthDaa",
  "periodStartDaa",
  "periodSpent",
  "approvalThreshold",
  "agentMaxFeePerTx",
  "agentRecipientRoot"
];

function assertDisclosedRegistry(presented, label) {
  assert.ok(Array.isArray(presented.initialRegistry), `${label}: initialRegistry must be presented`);
  assert.equal(presented.initialRegistry.length, 1, `${label}: one committed agent`);
  const entry = presented.initialRegistry[0];
  // exact tuple shape: the nine leaf fields + recipients, nothing else
  assert.deepEqual(Object.keys(entry).sort(), [...LEAF_FIELDS, "recipients"].sort(), `${label}: exact disclosed tuple field set`);
  for (const f of LEAF_FIELDS.slice(0, 8)) {
    assert.equal(typeof entry[f], "string", `${label}: ${f} is a string`);
  }
  assert.match(entry.agentPk, /^[0-9a-f]{64}$/);
  assert.match(entry.agentRecipientRoot, /^[0-9a-f]{64}$/);
  assert.ok(Array.isArray(entry.recipients) && entry.recipients.length === 2, `${label}: recipient keys disclosed`);

  // the disclosure is RECOMPUTABLE: recipients -> allowlist root; tuples -> agentRoot
  assert.equal(buildRecipientTree(entry.recipients).root, entry.agentRecipientRoot, `${label}: allowlist root recomputes from the disclosed recipients`);
  const { recipients, ...leaf } = entry;
  assert.equal(buildAgentTreeV4([leaf]).root, presented.initialState.agentRoot, `${label}: initialState.agentRoot recomputes from the disclosed tuples`);

  // the presenter still strips server-internal fields
  for (const stripped of ["build", "encoderBuildDir", "approvalPackage", "newRegistry", "finalTransaction"]) {
    assert.equal(presented[stripped], undefined, `${label}: ${stripped} must stay stripped`);
  }
}

test("genesis create response discloses the recomputable initialRegistry leaf tuples (presentRequest pin)", async () => {
  const entry = { ...AGENT_ENTRY, agentPk: XO(AGENT), recipients: [XO(RECIP_1), XO(RECIP_2)] };
  const r = await POST(["wallet", "v4", "create"], {
    templateInput: { owner: XO(OWNER), vaultId: VAULT_ID },
    initialAgents: [entry],
    initialState: { protectedValue: (500n * KAS).toString(), feeReserve: (1n * KAS).toString(), approvers: [XO(APPR)], approvalM: "1" },
    signerAddress: ADDR(OWNER),
    funding: [{ outpoint: { transactionId: "77".repeat(32), index: 0 }, amount: (600n * KAS).toString(), scriptPublicKeyHex: p2pk(XO(OWNER)) }],
    label: "disclosure-pin"
  });
  assert.equal(r.status, 201, JSON.stringify(r.body).slice(0, 300));
  assertDisclosedRegistry(r.body.request, "create response");

  // reload path: the durable document re-presents identically
  const g = await GET(["wallet", "v4", "requests", r.body.request.requestId]);
  assert.equal(g.status, 200);
  assertDisclosedRegistry(g.body.request, "GET by id");
  assert.deepEqual(g.body.request.initialRegistry, r.body.request.initialRegistry, "byte-stable across present calls");
});
