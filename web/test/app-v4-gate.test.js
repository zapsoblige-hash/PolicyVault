"use strict";

/*
 * BROWSER wiring — the REAL production web/app-v4.js evaluated with a
 * minimal window/document stub (no DOM library): proves that
 *
 *   1. walletSign stage D2 makes browser verification MANDATORY whenever
 *      the verification layer is loaded: a missing, refused, or unbound
 *      verification outcome refuses BEFORE any provider call — fail
 *      closed, no proceed-anyway;
 *   2. reviewModal renders the unmistakable DO-NOT-SIGN state with NO
 *      signing action on any refusal, the full explanation lines +
 *      details on a pass, and the explicit "verification unavailable"
 *      warning on a legacy page without the module;
 *   3. the legacy stage contract (B/C/D codes, canonical-signInputs
 *      guard) is preserved bit-for-bit when the verification layer is
 *      absent (mirrors sdk/test/approver-wallet-v4_1.test.js).
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const core = require("../core-bundle.js");
const { createVerifyIntent } = require("../verify-intent.js");
const H = require("./helpers.js");

const APP_V4 = fs.readFileSync(path.join(__dirname, "..", "app-v4.js"), "utf8");

const AGENT_ADDR = H.AGENT_ADDR;

/* minimal DOM/document stub sufficient for the modal + notice paths of
 * app-v4.js (see the harness note in each test). getElementById returns a
 * persistent stub per id; the v4-cancel / v4-confirm lookups reflect
 * whether the current modal HTML actually contains those buttons. */
function makeDom() {
  const elements = new Map();
  const element = (id) => {
    if (!elements.has(id)) {
      elements.set(id, {
        id,
        innerHTML: "",
        textContent: "",
        className: "",
        style: {},
        onclick: null,
        addEventListener() {},
        querySelectorAll: () => [],
        classList: { toggle() {}, add() {}, remove() {} }
      });
    }
    return elements.get(id);
  };
  const document = {
    getElementById(id) {
      if (id === "v4-cancel" || id === "v4-confirm") {
        return element("v4-modal").innerHTML.includes(`id="${id}"`) ? element(id) : null;
      }
      return element(id);
    },
    querySelectorAll: () => []
  };
  return { document, element };
}

function loadApp({ session, verify, dom }) {
  const { document, element } = dom || makeDom();
  const windowObj = {
    addEventListener() {},
    PolicyVaultWalletSession: session,
    ...(verify !== undefined ? { PolicyVaultVerifyIntent: verify } : {})
  };
  const sandbox = {
    window: windowObj,
    document,
    console,
    crypto: { getRandomValues: (arr) => { for (let i = 0; i < arr.length; i++) arr[i] = i & 0xff; return arr; } },
    fetch: async () => ({ ok: true, json: async () => ({}) }),
    setTimeout,
    clearTimeout
  };
  vm.createContext(sandbox);
  vm.runInContext(APP_V4, sandbox, { filename: "app-v4.js" });
  return { window: windowObj, element, api: windowObj.PolicyVaultV4 };
}

function sessionWith(adapter) {
  const snap = {
    connected: true,
    ready: true,
    address: AGENT_ADDR,
    xonly: H.AGENT,
    network: "testnet-10",
    serverNetwork: "testnet-10",
    provider: "spy",
    adapter
  };
  return { active: () => snap, subscribe(cb) { cb(snap); return () => {}; }, connect() {}, disconnect() {} };
}

function spyAdapter() {
  const calls = [];
  return {
    calls,
    signInputs: async (unsignedSafeJson, signInputs, expectations) => {
      calls.push({ unsignedSafeJson, signInputs: structuredClone(signInputs), expectations: structuredClone(expectations) });
      return '{"signed":true}';
    }
  };
}

const vi = createVerifyIntent(core);
function passingOutcome() {
  const s = H.spendScenario();
  const out = vi.verifyBeforeSigning({
    request: s.request,
    vault: s.vault,
    clientAction: s.clientAction,
    clientParams: s.clientParams,
    sessionNetwork: s.sessionNetwork,
    sessionXOnly: s.sessionXOnly
  });
  assert.equal(out.ok, true, "fixture outcome must pass");
  return { scenario: s, outcome: out };
}
function refusedOutcome() {
  const s = H.withTamperedTx(H.spendScenario(), (tx) => {
    tx.outputs[0].scriptPublicKey = H.spkWire(H.p2pk(H.ATTACKER));
  });
  const out = vi.verifyBeforeSigning({
    request: s.request,
    vault: s.vault,
    clientAction: s.clientAction,
    clientParams: s.clientParams,
    sessionNetwork: s.sessionNetwork,
    sessionXOnly: s.sessionXOnly
  });
  assert.equal(out.ok, false, "fixture outcome must refuse");
  return { scenario: s, outcome: out };
}

/* =================== walletSign stage D2 =================== */

test("D2: with the verify layer loaded, walletSign REFUSES without a verification outcome — provider never invoked", async () => {
  const adapter = spyAdapter();
  const { api } = loadApp({ session: sessionWith(adapter), verify: vi });
  const s = H.spendScenario();
  await assert.rejects(
    () => api._walletSign(s.request.transaction.unsignedSafeJson, s.request.transaction.signInputs, AGENT_ADDR),
    (e) => e.code === "VERIFICATION_REQUIRED" && e.walletStage === "D2:browser-verification-bound"
  );
  assert.equal(adapter.calls.length, 0, "the wallet is NEVER invoked without a verification outcome");
});

test("D2: a REFUSED verification blocks the provider call", async () => {
  const adapter = spyAdapter();
  const { api } = loadApp({ session: sessionWith(adapter), verify: vi });
  const { scenario, outcome } = refusedOutcome();
  await assert.rejects(
    () => api._walletSign(scenario.request.transaction.unsignedSafeJson, scenario.request.transaction.signInputs, AGENT_ADDR, outcome),
    (e) => e.code === "VERIFICATION_REFUSED" && e.walletStage === "D2:browser-verification-bound"
  );
  assert.equal(adapter.calls.length, 0);
});

test("D2: a passing verification bound to DIFFERENT bytes blocks the provider call", async () => {
  const adapter = spyAdapter();
  const { api } = loadApp({ session: sessionWith(adapter), verify: vi });
  const { outcome } = passingOutcome();
  const other = H.topUpScenario();
  await assert.rejects(
    () => api._walletSign(other.request.transaction.unsignedSafeJson, other.request.transaction.signInputs, AGENT_ADDR, outcome),
    (e) => e.code === "VERIFICATION_TX_BINDING_MISMATCH"
  );
  assert.equal(adapter.calls.length, 0);
});

test("D2: a passing, correctly bound verification lets signing proceed — with session expectations forwarded to the adapter", async () => {
  const adapter = spyAdapter();
  const { api } = loadApp({ session: sessionWith(adapter), verify: vi });
  const { scenario, outcome } = passingOutcome();
  const signed = await api._walletSign(scenario.request.transaction.unsignedSafeJson, scenario.request.transaction.signInputs, AGENT_ADDR, outcome);
  assert.equal(signed, '{"signed":true}');
  assert.equal(adapter.calls.length, 1);
  assert.equal(adapter.calls[0].unsignedSafeJson, scenario.request.transaction.unsignedSafeJson, "the EXACT verified bytes reach the provider");
  assert.deepEqual(adapter.calls[0].signInputs, [{ index: 0, sighashType: 1 }]);
  assert.deepEqual(adapter.calls[0].expectations, { network: "testnet-10", expectedSignerAddress: AGENT_ADDR }, "session identity/network expectations forwarded for the USI adapter");
});

test("legacy contract preserved WITHOUT the verify layer: stage codes and canonical-signInputs guard intact", async () => {
  const adapter = spyAdapter();
  const { api } = loadApp({ session: sessionWith(adapter) }); // no PolicyVaultVerifyIntent
  const s = H.spendScenario();
  // the exact shape that panicked real KasWare: missing sighashType
  await assert.rejects(
    () => api._walletSign(s.request.transaction.unsignedSafeJson, [{ index: 0 }], AGENT_ADDR),
    (e) => e.code === "SIGN_INPUTS_INVALID" && e.walletStage === "D:signInputs-validated"
  );
  await assert.rejects(
    () => api._walletSign(s.request.transaction.unsignedSafeJson, [], AGENT_ADDR),
    (e) => e.code === "SIGN_INPUTS_INVALID"
  );
  await assert.rejects(
    () => api._walletSign(s.request.transaction.unsignedSafeJson, s.request.transaction.signInputs, "kaspatest:someoneelse"),
    (e) => e.code === "SIGNER_MISMATCH" && e.walletStage === "C:expected-signer-resolved"
  );
  assert.equal(adapter.calls.length, 0);
  // and without the layer, signing proceeds legacy-style (no verification)
  const signed = await api._walletSign(s.request.transaction.unsignedSafeJson, s.request.transaction.signInputs, AGENT_ADDR);
  assert.equal(signed, '{"signed":true}');
});

test("D2 ordering: the signInputs guard still fires at stage D even when verification is present", async () => {
  const adapter = spyAdapter();
  const { api } = loadApp({ session: sessionWith(adapter), verify: vi });
  const { scenario, outcome } = passingOutcome();
  await assert.rejects(
    () => api._walletSign(scenario.request.transaction.unsignedSafeJson, [{ index: 0, sighashType: 3 }], AGENT_ADDR, outcome),
    (e) => e.code === "SIGN_INPUTS_INVALID" && e.walletStage === "D:signInputs-validated"
  );
  assert.equal(adapter.calls.length, 0);
});

/* =================== reviewModal rendering =================== */

test("reviewModal: a refused verification renders DO-NOT-SIGN with NO signing action (even though a confirm callback was supplied)", () => {
  const dom = makeDom();
  const { api } = loadApp({ session: sessionWith(spyAdapter()), verify: vi, dom });
  const { scenario, outcome } = refusedOutcome();
  let confirmed = false;
  api._reviewModal(scenario.request.review, () => { confirmed = true; }, "Sign spend", undefined, outcome);
  const html = dom.element("v4-modal").innerHTML;
  assert.ok(html.includes("DO NOT SIGN"), "unmistakable DO-NOT-SIGN state");
  assert.ok(html.includes('data-verify="refused"'), "refusal banner present");
  assert.ok(!html.includes('id="v4-confirm"'), "NO signing button is rendered — no proceed-anyway exists");
  assert.ok(html.includes("HIDDEN_RECIPIENT"), "detector codes surfaced to the human");
  assert.ok(html.includes('id="v4-cancel"'), "only the close action remains");
  assert.equal(confirmed, false);
});

test("reviewModal: a missing verification outcome on a signing modal is blocked the same way", () => {
  const dom = makeDom();
  const { api } = loadApp({ session: sessionWith(spyAdapter()), verify: vi, dom });
  api._reviewModal({ action: "agentSpend" }, () => {}, "Sign spend", undefined, null);
  const html = dom.element("v4-modal").innerHTML;
  assert.ok(!html.includes('id="v4-confirm"'), "no signing action without a verification outcome");
  assert.ok(html.includes("DO NOT SIGN"));
  assert.ok(html.includes("VERIFICATION_REQUIRED"));
});

test("reviewModal: a passing verification renders the full explanation lines, the confirm action, and the details disclosure", () => {
  const dom = makeDom();
  const { api } = loadApp({ session: sessionWith(spyAdapter()), verify: vi, dom });
  const { scenario, outcome } = passingOutcome();
  api._reviewModal(scenario.request.review, () => {}, "Sign spend", undefined, outcome);
  const html = dom.element("v4-modal").innerHTML;
  assert.ok(html.includes("VERIFIED BY THIS BROWSER"), "pass banner");
  assert.ok(html.includes('id="v4-confirm"'), "signing action available on a full pass");
  assert.ok(html.includes(H.RECIPIENT), "FULL recipient key rendered (no truncation-only display)");
  assert.ok(html.includes("THIS TRANSACTION DOES EXACTLY WHAT WAS REQUESTED AND NOTHING ELSE."), "the verified statement");
  assert.ok(html.includes(outcome.manifestHash), "manifest hash in the details disclosure");
  assert.ok(html.includes("Verification details"), "collapsed details");
});

test("reviewModal: WITHOUT the verify layer the legacy modal renders with an explicit unavailable warning", () => {
  const dom = makeDom();
  const { api } = loadApp({ session: sessionWith(spyAdapter()), dom }); // no verify layer
  api._reviewModal({ action: "agentSpend", paymentKas: "10" }, () => {}, "Sign spend");
  const html = dom.element("v4-modal").innerHTML;
  assert.ok(html.includes('data-verify="unavailable"'), "the degraded state is visibly labeled");
  assert.ok(html.includes("not loaded in this build"), "warning text");
  assert.ok(html.includes('id="v4-confirm"'), "legacy behavior preserved for pages without the module");
});

test("informational modal (no confirm callback) with a refused verification still shows DO-NOT-SIGN", () => {
  const dom = makeDom();
  const { api } = loadApp({ session: sessionWith(spyAdapter()), verify: vi, dom });
  const { scenario, outcome } = refusedOutcome();
  api._reviewModal(scenario.request.review, null, "Close", "Awaiting approvals — 0 of 2", outcome);
  const html = dom.element("v4-modal").innerHTML;
  assert.ok(html.includes("DO NOT SIGN"));
  assert.ok(!html.includes('id="v4-confirm"'));
});

/* =================== end-to-end wiring sanity =================== */

test("_verifyForSigning wires session network/identity + client vault knowledge into the verifier", () => {
  const { api } = loadApp({ session: sessionWith(spyAdapter()), verify: vi });
  const s = H.spendScenario();
  api._state.vaultsById = { [H.VAULT_ID]: s.vault };
  api._state.xonly = H.AGENT;
  const out = api._verifyForSigning({
    request: s.request,
    vaultId: H.VAULT_ID,
    clientAction: "agentSpend",
    clientParams: s.clientParams,
    role: "agent"
  });
  assert.equal(out.ok, true, (out.lines || []).join("\n"));
  assert.equal(out.unsignedSafeJson, s.request.transaction.unsignedSafeJson);
});

test("_verifyForSigning fails closed when the client has no vault knowledge for the target", () => {
  const { api } = loadApp({ session: sessionWith(spyAdapter()), verify: vi });
  const s = H.spendScenario();
  api._state.vaultsById = {}; // nothing known
  api._state.xonly = H.AGENT;
  const out = api._verifyForSigning({ request: s.request, vaultId: H.VAULT_ID, clientAction: "agentSpend", clientParams: s.clientParams, role: "agent" });
  assert.equal(out.ok, false);
  assert.ok(out.refusalCodes.includes("VAULT_KNOWLEDGE_MISSING"));
});
