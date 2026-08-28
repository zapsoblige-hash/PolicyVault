"use strict";

/*
 * RC-UX-1 BROWSER-INTEGRATION REGRESSION — the REAL self-hosted solo
 * risk workflow, end to end (finding from the fullscale-rc1 controlled-
 * mainnet acceptance, docs/postlaunch/rc-mainnet-acceptance-evidence.md
 * §5.2).
 *
 * Harness composition (both established idioms, combined):
 *   - REAL HTTP server (server/src/server.js createServer) over a temp
 *     JSON data root with a REAL v0.4.1 vault manifest, org and
 *     amount-threshold risk controls — the same stack the mainnet
 *     acceptance ran (verify-intent-real-server.test.js pattern);
 *   - the REAL production browser sources (gov-risk-explain.js,
 *     risk-ui.js, app-v4.js) evaluated in the vm sandbox with the REAL
 *     verify-intent + core bundle injected on window, and sandbox fetch
 *     wired to the REAL server (app-v4-govrisk-wiring.test.js pattern).
 *
 * THE FLOW UNDER TEST (solo operator, single browser):
 *   spend attempt -> RISK_REVIEW_REQUIRED hold panel (self-release
 *   refused for the initiating wallet — the mainnet-observed state) ->
 *   hold released via the API (the out-of-band operator release) ->
 *   plain re-attempt of the identical action from the vault card ->
 *   the server consumes the exact released hold ONCE and the build
 *   reaches the NORMAL VERIFIED pre-sign review (data-verify="pass",
 *   VERIFIED_EXACT) -> a SECOND identical re-attempt spawns a FRESH
 *   hold (exactly-once). The wallet is a spy stub and is NEVER invoked;
 *   nothing is signed; nothing is broadcast.
 *
 * On the frozen fullscale-rc1 tree this suite is RED at the re-attempt:
 * the server spawns a new hold instead of continuing the released one.
 */

const { test, before, after } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const vm = require("node:vm");

const { loadConfig } = require("../../sdk/src/config");
const { createServer } = require("../../server/src/server");
const { buildAgentTreeV4, normalizeAgentPolicyV4 } = require("../../core/model/agent-merkle-v4.js");
const { buildRecipientTree } = require("../../core/model/recipient-merkle-v3.js");
const { normalizeStateV4, computeStateIdV4, stateToJsonV4, CONTRACT_VERSION_V4_1 } = require("../../core/model/vault-state-v4.js");
const { compileExactStateV4 } = require("../../sdk/src/contract-compiler-v4");
const { MANIFEST_SCHEMA_V4, persistManifestV4 } = require("../../sdk/src/manifest-v4");
const org = require("../../sdk/src/organization");
const { saveOrgControls, loadOrgControls } = require("../../server/src/org-controls");

const core = require("../core-bundle.js");
const { createVerifyIntent } = require("../verify-intent.js");

const APP_V4 = fs.readFileSync(path.join(__dirname, "..", "app-v4.js"), "utf8");
const RISK_UI = fs.readFileSync(path.join(__dirname, "..", "risk-ui.js"), "utf8");
const GOV_RISK_EXPLAIN = fs.readFileSync(path.join(__dirname, "..", "gov-risk-explain.js"), "utf8");

const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "pv-rcux1-web-"));
const config = loadConfig({ dataRoot });
const kaspa = require(config.rustyKaspaModule);
const KEYHEX = (v) => v.toString(16).padStart(2, "0").repeat(32);
const KEY = (v) => new kaspa.PrivateKey(KEYHEX(v));
const XO = (v) => KEY(v).toPublicKey().toXOnlyPublicKey().toString().toLowerCase();
const ADDR = (v) => KEY(v).toPublicKey().toAddress(config.networkId).toString();
const KAS = 100000000n;
const OWNER = 3, AGENT = 0x2e, APPR_A = 0x61, APPR_B = 0x62, RECIP = 0x38;
const VAULT = "7d".repeat(32);

let BASE = null; // http://127.0.0.1:<port>
let server;

async function seed() {
  const registry = [{
    agentPk: XO(AGENT),
    maxPerSpend: (20n * KAS).toString(),
    periodBudget: (50n * KAS).toString(),
    periodLengthDaa: "864000",
    periodStartDaa: "541000000",
    periodSpent: "0",
    approvalThreshold: (100n * KAS).toString(), // spends here stay far below — direct-sign path
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
    label: "rc-ux1-web",
    status: "ACTIVE",
    template,
    agentRegistry: registry,
    live: {
      state: stateToJsonV4(state),
      stateId,
      outpoint: { transactionId: "5a".repeat(32), index: 0 },
      outpointValue: (state.protectedValue + state.feeReserve).toString(),
      scriptSha256: compiled.scriptSha256,
      covenantId: "51".repeat(32)
    },
    creationTxId: "52".repeat(32),
    latestTransitionTxId: null,
    lastTransition: null
  });
  const created = await org.createOrganization(config, { name: "rc-ux1 web org" });
  const assignments = await org.loadAssignments(config);
  await org.assignVault(config, { vaultId: VAULT, orgId: created.orgId, group: null, expectedVersion: assignments.version, vaultExists: async () => true });
  const cur = await loadOrgControls(config, created.orgId);
  await saveOrgControls(config, created.orgId, {
    governance: {},
    risk: { adapters: [{ type: "amount-threshold", params: { reviewAboveSompi: (5n * KAS).toString() } }] },
    expectedVersion: cur ? cur.version : 0
  });
}

/* Out-of-band HTTP (the operator's own API access — how the mainnet
 * acceptance released the hold). */
const apiPost = async (url, body) => {
  const r = await fetch(`${BASE}/api/v1${url}`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body ?? {}) });
  return { status: r.status, j: await r.json() };
};
const apiGet = async (url) => {
  const r = await fetch(`${BASE}/api/v1${url}`);
  return { status: r.status, j: await r.json() };
};

/* ---- minimal DOM (app-v4-govrisk-wiring.test.js makeDom, verbatim) ---- */
function makeDom() {
  const elements = new Map();
  const element = (id) => {
    if (!elements.has(id)) {
      const queryCache = new Map();
      const el = {
        id,
        innerHTML: "",
        textContent: "",
        className: "",
        style: {},
        onclick: null,
        addEventListener() {},
        classList: { toggle() {}, add() {}, remove() {} },
        querySelectorAll: () => [],
        querySelector(sel) {
          const key = `${el.innerHTML}::${sel}`;
          if (queryCache.has(key)) return queryCache.get(key);
          const m = /^\[([a-zA-Z0-9-]+)(?:="([^"]*)")?\]$/.exec(sel);
          let stub = null;
          if (m) {
            const [, attr, wantVal] = m;
            const re = new RegExp(`${attr}(?:="([^"]*)")?`);
            const found = re.exec(el.innerHTML);
            if (found) {
              const actualVal = found[1];
              if (wantVal === undefined || actualVal === wantVal) {
                stub = { onclick: null, disabled: false, style: {}, getAttribute: (n) => (n === attr ? (actualVal ?? "") : null) };
              }
            }
          }
          queryCache.set(key, stub);
          return stub;
        }
      };
      elements.set(id, el);
    }
    return elements.get(id);
  };
  const document = { getElementById: (id) => element(id), querySelectorAll: () => [] };
  return { document, element };
}

/* Wallet SPY adapter: any invocation is a test failure — this suite must
 * never reach a wallet, sign, or broadcast. */
const walletSpy = { calls: 0, signInputs() { walletSpy.calls += 1; throw new Error("RC-UX-1 suite must NEVER invoke the wallet"); } };
function sessionWith(adapter) {
  const snap = { connected: true, ready: true, address: ADDR(AGENT), xonly: XO(AGENT), network: config.networkId, serverNetwork: config.networkId, provider: "spy", adapter };
  return { active: () => snap, subscribe(cb) { cb(snap); return () => {}; }, connect() {}, disconnect() {} };
}

/* Sandbox fetch = the REAL server (records every call for assertions). */
function makeRealFetch() {
  const calls = [];
  const fetchFn = async (url, opts) => {
    const method = (opts && opts.method) || "GET";
    calls.push({ method, url, body: opts && opts.body ? JSON.parse(opts.body) : undefined });
    return fetch(`${BASE}${url}`, opts);
  };
  fetchFn.calls = calls;
  return fetchFn;
}

function loadApp(dom, fetchFn) {
  const windowObj = {
    addEventListener() {},
    confirm: () => true,
    scrollTo() {},
    PolicyVaultWalletSession: sessionWith(walletSpy),
    PolicyVaultVerifyIntent: createVerifyIntent(core) // the REAL browser verifier + REAL committed core bundle
  };
  const sandbox = {
    window: windowObj,
    document: dom.document,
    console,
    crypto: { getRandomValues: (arr) => { for (let i = 0; i < arr.length; i++) arr[i] = i & 0xff; return arr; } },
    fetch: fetchFn,
    setTimeout,
    clearTimeout
  };
  vm.createContext(sandbox);
  vm.runInContext(GOV_RISK_EXPLAIN, sandbox, { filename: "gov-risk-explain.js" });
  vm.runInContext(RISK_UI, sandbox, { filename: "risk-ui.js" });
  vm.runInContext(APP_V4, sandbox, { filename: "app-v4.js" });
  return { window: windowObj, element: dom.element, api: windowObj.PolicyVaultV4 };
}

const SPEND_PARAMS = (kas) => ({ payAmountSompi: (kas * KAS).toString(), agentPk: XO(AGENT), recipient: XO(RECIP) });

/* The durable evaluations as the server stores them (JSON backend). */
const evalDir = () => path.join(dataRoot, "risk", "evaluations");
const evalRecords = () =>
  (fs.existsSync(evalDir()) ? fs.readdirSync(evalDir()) : [])
    .filter((f) => f.endsWith(".json"))
    .map((f) => JSON.parse(fs.readFileSync(path.join(evalDir(), f), "utf8")));

let loaded;

before(async () => {
  await seed();
  server = createServer(config);
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  BASE = `http://127.0.0.1:${server.address().port}`;
  const dom = makeDom();
  const fetchFn = makeRealFetch();
  loaded = { ...loadApp(dom, fetchFn), fetchFn };
  // DOMContentLoaded never fires in the sandbox (addEventListener is a
  // no-op) — populate the session-derived state and the vault view the
  // way render() would (same idiom as the wiring suite's _state setup).
  loaded.api._state.address = ADDR(AGENT);
  loaded.api._state.xonly = XO(AGENT);
  const v = await apiGet(`/vaults/${VAULT}`);
  assert.equal(v.status, 200);
  loaded.api._state.vaultsById[VAULT] = v.j;
});
after(() => server && server.close());

test("RC-UX-1 browser 1: the spend attempt is held — the solo initiator's panel shows the hold and refuses self-release (the mainnet-observed state)", async () => {
  await loaded.api._runFlow(VAULT, "agentSpend", SPEND_PARAMS(7n), "Sign spend");
  const html = loaded.element("v4-modal").innerHTML;
  assert.ok(/REVIEW_HELD/.test(html), html.slice(0, 400));
  assert.ok(/cannot release their own review hold/i.test(html), "self-release refusal banner for the initiating wallet");
  assert.ok(!html.includes("data-risk-release"), "no release affordance for the initiator");
  assert.ok(!html.includes('id="v4-confirm"'), "no signing review — the refusal is not softened");
  const held = evalRecords().filter((r) => r.status === "REVIEW_HELD");
  assert.equal(held.length, 1, "one durable REVIEW_HELD evaluation");
});

test("RC-UX-1 browser 2: after the out-of-band operator release, the plain re-attempt from the vault card continues the released hold to the NORMAL VERIFIED pre-sign review", async () => {
  const held = evalRecords().find((r) => r.status === "REVIEW_HELD");
  const rel = await apiPost(`/risk/evaluations/${held.evaluationId}/release`, {});
  assert.equal(rel.status, 200);
  assert.equal(rel.j.evaluation.status, "RELEASED");
  assert.equal(rel.j.evaluation.releasedBy, "self-hosted-operator");

  // The re-attempt is EXACTLY the original action again — no riskEvaluationId in hand.
  await loaded.api._runFlow(VAULT, "agentSpend", SPEND_PARAMS(7n), "Sign spend");
  const html = loaded.element("v4-modal").innerHTML;
  const after = evalRecords().find((r) => r.evaluationId === held.evaluationId);
  assert.ok(
    !/REVIEW_HELD/.test(html),
    `RC-UX-1 DEFECT REPRODUCED: the re-attempt opened ANOTHER hold panel instead of continuing the released hold ` +
      `(released evaluation ${held.evaluationId} is ${after.status}; the solo continuation is structurally unreachable)`
  );
  assert.ok(html.includes('data-verify="pass"'), "the browser's own verification banner is the PASS state");
  assert.ok(/VERIFIED BY THIS BROWSER/.test(html), "normal pre-sign review with independent browser verification");
  assert.ok(/VERIFIED_EXACT/.test(html), "verdict VERIFIED_EXACT");
  assert.ok(html.includes('id="v4-confirm"'), "the signing action is offered (and deliberately never clicked)");
  assert.ok(!/DO NOT SIGN/.test(html));

  assert.equal(after.status, "CONSUMED", "the released hold was consumed by the continuation");
  assert.equal(after.consumedVia, "RELEASED_INTENT_REMATCH");
  assert.match(after.consumedByRequestId, /^[0-9a-f-]{36}$/);
});

test("RC-UX-1 browser 3: exactly-once — a SECOND identical re-attempt spawns a FRESH hold, and the consumed record is untouched", async () => {
  const consumed = evalRecords().find((r) => r.status === "CONSUMED");
  await loaded.api._runFlow(VAULT, "agentSpend", SPEND_PARAMS(7n), "Sign spend");
  const html = loaded.element("v4-modal").innerHTML;
  assert.ok(/REVIEW_HELD/.test(html), "the second re-attempt is a fresh hold (no silent reuse)");
  const held = evalRecords().filter((r) => r.status === "REVIEW_HELD" && r.intentHash === consumed.intentHash);
  assert.equal(held.length, 1, "one fresh HELD evaluation for the same intent");
  assert.notEqual(held[0].evaluationId, consumed.evaluationId);
  const still = evalRecords().find((r) => r.evaluationId === consumed.evaluationId);
  assert.equal(still.status, "CONSUMED");
  assert.equal(still.consumedByRequestId, consumed.consumedByRequestId);
});

test("RC-UX-1 browser 4: a RELEASED panel opened WITHOUT action context tells the truth — and the described vault-card re-attempt actually works", async () => {
  // Second workflow at a different amount: hold it, release it out of band.
  await loaded.api._runFlow(VAULT, "agentSpend", SPEND_PARAMS(9n), "Sign spend");
  const held = evalRecords().find((r) => r.status === "REVIEW_HELD" && r.intent.payAmountSompi === (9n * KAS).toString());
  assert.ok(held, "the 9-KAS hold exists");
  await apiPost(`/risk/evaluations/${held.evaluationId}/release`, {});

  // The jump-in path: the panel opened bare (evaluationId only, e.g. from
  // the Activity feed) — RELEASED, so it offers Re-submit; without the
  // original action in hand the button explains the vault-card path.
  await loaded.api._openRiskHold({ evaluationId: held.evaluationId });
  const modal = loaded.element("v4-modal");
  assert.ok(/RELEASED/.test(modal.innerHTML));
  const resubmit = modal.querySelector("[data-risk-resubmit]");
  assert.ok(resubmit, "a RELEASED panel offers re-submit");
  const buildsBefore = loaded.fetchFn.calls.filter((c) => c.method === "POST" && c.url === "/api/v1/wallet/v4/requests").length;
  resubmit.onclick();
  const notice = loaded.element("v4-notice").textContent;
  assert.ok(/re-attempt the identical action from the vault card/i.test(notice), `fallback copy states the true continuation: ${notice}`);
  assert.ok(/consum/i.test(notice), "the copy names the exactly-once consumption");
  const buildsAfter = loaded.fetchFn.calls.filter((c) => c.method === "POST" && c.url === "/api/v1/wallet/v4/requests").length;
  assert.equal(buildsAfter, buildsBefore, "the context-less button itself never fires a build — the user re-attempts from the vault card");

  // The copy is TRUE: the vault-card re-attempt continues this release.
  await loaded.api._runFlow(VAULT, "agentSpend", SPEND_PARAMS(9n), "Sign spend");
  const html = loaded.element("v4-modal").innerHTML;
  assert.ok(html.includes('data-verify="pass"') && /VERIFIED BY THIS BROWSER/.test(html), "the described re-attempt reaches the VERIFIED pre-sign review");
  const after = evalRecords().find((r) => r.evaluationId === held.evaluationId);
  assert.equal(after.status, "CONSUMED");
});

test("RC-UX-1 browser 5: the whole journey used the ONE build endpoint with NO riskEvaluationId, and the wallet was NEVER invoked", async () => {
  const builds = loaded.fetchFn.calls.filter((c) => c.method === "POST" && c.url === "/api/v1/wallet/v4/requests");
  assert.ok(builds.length >= 4, `all attempts went through the one build endpoint (${builds.length})`);
  for (const c of builds) {
    assert.equal(c.body.riskEvaluationId, undefined, "the browser never needed to carry riskEvaluationId — the continuation is server-side exact-intent matching");
  }
  assert.equal(walletSpy.calls, 0, "no wallet invocation — nothing signed, nothing broadcast");
  const consumed = evalRecords().filter((r) => r.status === "CONSUMED");
  assert.equal(consumed.length, 2, "exactly the two released holds were consumed, once each");
  for (const r of consumed) assert.equal(r.consumedVia, "RELEASED_INTENT_REMATCH");
});
