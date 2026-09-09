"use strict";

/*
 * BROWSER — the delegated spend workflow (TRACK 11 flagship UX pass,
 * finding D1, HIGH).
 *
 * Before: the most-used action in the product was a chain of two native
 * window.prompt() dialogs —
 *     "Recipient wallet address (must be in this agent's allowlist):"
 *     "Spend amount (KAS):"
 * The allowlist the first prompt names was NEVER SHOWN anywhere in the UI,
 * although the addresses were already in the vault presentation the browser
 * held. Nothing was checked against the agent's own limits until the server
 * refused. And a prompt chain has no labels, no field-level errors, and
 * nothing readable at 375 px.
 *
 * After: the agent card discloses the covenant-enforced allowlist, and the
 * spend is a labelled form that offers those addresses, shows the agent's
 * cap / remaining budget / approval threshold, and refuses locally before
 * a round-trip.
 *
 * WHAT THESE TESTS PROTECT — the properties that keep it defense-in-depth
 * rather than a new authority:
 *   1. the chosen ADDRESS is still resolved through the server's one
 *      address-identity boundary; the browser never substitutes a paired
 *      x-only for the address the human read;
 *   2. the flow still ends in the identical runFlow("agentSpend", …) call
 *      with the identical params, so review, browser verification, the
 *      approvals workflow and signing are untouched;
 *   3. local checks can only refuse EARLIER, never permit — and the copy
 *      says so;
 *   4. missing agent policy fails closed (no form is offered).
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { baseVault } = require("./helpers.js");

const WEB_DIR = path.join(__dirname, "..");
const APP_V4 = fs.readFileSync(path.join(WEB_DIR, "app-v4.js"), "utf8");
// index.html loads the committed core bundle BEFORE app-v4.js; the client
// amount checks delegate to window.PolicyVaultCore.amounts.kasToSompi (the
// canonical shared-core parser — T4 migration), so the sandbox must model the
// real page: evaluate the bundle first, then app-v4.js.
const CORE_BUNDLE = fs.readFileSync(path.join(WEB_DIR, "core-bundle.js"), "utf8");

/* ---------------- a DOM shim big enough for one form ---------------- */

function field(name, value) {
  return { name, value, className: "", classList: { add() {}, remove() {} }, focus() {}, getAttribute: () => null };
}

function makeEnv({ fetchImpl } = {}) {
  const elements = new Map();
  const element = (id) => {
    if (!elements.has(id)) {
      elements.set(id, {
        id, innerHTML: "", textContent: "", className: "", value: "", disabled: false,
        style: {}, dataset: {}, onclick: null,
        listeners: {},
        addEventListener(n, f) { (this.listeners[n] = this.listeners[n] || []).push(f); },
        insertAdjacentHTML() {}, querySelectorAll: () => [], querySelector: () => null,
        classList: { toggle() {}, add() {}, remove() {} }, closest: () => null, focus() {}
      });
    }
    return elements.get(id);
  };
  const calls = [];
  const sandbox = {
    console,
    document: { getElementById: element, querySelectorAll: () => [], addEventListener() {} },
    localStorage: { getItem: () => null, setItem() {}, removeItem() {} },
    setTimeout: () => 0, clearTimeout() {},
    crypto: { getRandomValues: (a) => a.fill(7) },
    fetch: (u, opts) => {
      const p = String(u).replace("/api/v1", "");
      calls.push({ p, method: (opts && opts.method) || "GET", body: opts && opts.body ? JSON.parse(opts.body) : null });
      return fetchImpl ? fetchImpl(p, opts) : Promise.resolve({ ok: true, status: 200, json: async () => ({}) });
    },
    PolicyVaultWalletSession: { active: () => ({ connected: false, ready: false }), subscribe: () => () => {} }
  };
  sandbox.listeners = {};
  sandbox.addEventListener = (n, f) => { (sandbox.listeners[n] = sandbox.listeners[n] || []).push(f); };
  sandbox.window = sandbox;
  sandbox.globalThis = sandbox;
  vm.createContext(sandbox);
  vm.runInContext(CORE_BUNDLE, sandbox, { filename: "core-bundle.js" });
  vm.runInContext(APP_V4, sandbox, { filename: "app-v4.js" });
  return { element, calls, sandbox, V4: sandbox.window.PolicyVaultV4 };
}

const settle = async (n = 20) => { for (let i = 0; i < n; i++) await new Promise((r) => setImmediate(r)); };
const VAULT = baseVault();
const AGENT = VAULT.agents[0];

/* ---------------- 1. the allowlist is visible on the agent card -------- */

test("the agent card DISCLOSES the covenant-enforced allowlist it already holds", () => {
  const { V4 } = makeEnv();
  Object.assign(V4._state, { xonly: AGENT.agentPk, address: "kaspa:qagent" });
  const html = V4._agentCard(VAULT, AGENT);
  assert.match(html, /Allowed recipients \(1\)/);
  assert.match(html, /kaspatest:recipient0/, "the actual allowed address is shown");
  assert.match(html, /enforced by the covenant/i);
  assert.match(html, /committed on-chain/i);
  assert.match(html, /straight to a Kaspa node/i, "states the rule binds a direct-to-node submission too");
});

test("an agent with no presented allowlist says so honestly instead of implying there is none", () => {
  const { V4 } = makeEnv();
  const html = V4._agentCard(VAULT, { ...AGENT, recipientAddresses: undefined });
  assert.match(html, /data-allowlist-empty="1"/);
  assert.match(html, /not available in this vault view/i);
  assert.ok(!/Allowed recipients \(/.test(html), "it never renders an empty list as the policy");
});

/* ---------------- 2. the form ------------------------------------------ */

test("the spend form offers the allowlisted addresses and shows the agent's real limits", () => {
  const { V4 } = makeEnv();
  V4._state.address = "kaspa:qagent";
  const html = V4._spendFormHtml(VAULT, AGENT);
  assert.match(html, /<select id="v4-spend-to"/, "recipients are a choice, not a memory test");
  assert.match(html, /<option value="kaspatest:recipient0"/);
  assert.match(html, /Max per transaction<\/div><div class="v">20 KAS/);
  assert.match(html, /Remaining this period<\/div><div class="v">45 KAS/);
  assert.match(html, /Approval required above<\/div><div class="v">15 KAS/);
  assert.match(html, /enforced by the covenant on Kaspa and re-derived by the server/i, "states where authority actually lives");
  // accessibility: real labels bound to real controls, and a dialog role
  assert.match(html, /role="dialog" aria-modal="true" aria-labelledby="v4-spend-title"/);
  assert.match(html, /<label for="v4-spend-to">/);
  assert.match(html, /<label for="v4-spend-amount">/);
});

test("with no presented allowlist the form degrades to a text field and says the covenant still enforces it", () => {
  const { V4 } = makeEnv();
  V4._state.address = "kaspa:qagent";
  const html = V4._spendFormHtml(VAULT, { ...AGENT, recipientAddresses: [] });
  assert.match(html, /<input id="v4-spend-to"/);
  assert.match(html, /The covenant still enforces the allowlist/i);
  assert.ok(!/<select id="v4-spend-to"/.test(html));
});

test("a hostile label / address cannot inject markup into the form", () => {
  const { V4 } = makeEnv();
  V4._state.address = "kaspa:qagent";
  const html = V4._spendFormHtml(
    { ...VAULT, label: '<img src=x onerror="alert(1)">' },
    { ...AGENT, recipientAddresses: ['"><script>alert(2)</script>'], maxPerSpendKas: "<b>20</b>" }
  );
  assert.ok(!/<script/i.test(html));
  assert.ok(!/<img/i.test(html));
  assert.ok(!/onerror=/i.test(html.replace(/&quot;|&lt;|&gt;|&amp;/g, "")) || /&lt;img/.test(html), "hostile text is escaped, not executed");
  assert.match(html, /&lt;script&gt;/);
});

/* ---------------- 3. local pre-checks refuse earlier, never permit ------ */

function form(to, amount) {
  const els = { '[name="to"]': field("to", to), '[name="amount"]': field("amount", amount) };
  return {
    querySelector: (sel) => els[sel] || null,
    querySelectorAll: () => [],
    addEventListener() {},
    _els: els
  };
}

test("the local checks mirror the agent's own limits", () => {
  const { V4 } = makeEnv();
  const v = (to, amt) => V4._validateSpendForm(form(to, amt), AGENT);

  assert.equal(v("kaspatest:recipient0", "5").ok, true, "within cap and budget");
  assert.equal(v("kaspatest:recipient0", "5").sompi, "500000000");

  assert.match(v("kaspatest:recipient0", "21").errors.get("amount").message, /maximum per transaction \(20 KAS\)/);
  assert.match(v("kaspatest:recipient0", "21").errors.get("amount").message, /covenant refuses it/i);
  // The cap is checked first, so exercise the budget branch with an agent
  // whose remaining period budget is BELOW its per-transaction cap.
  const tight = { ...AGENT, remainingBudgetKas: "10" };
  const budgetErr = V4._validateSpendForm(form("kaspatest:recipient0", "15"), tight).errors.get("amount");
  assert.match(budgetErr.message, /remaining budget for the current period \(10 KAS\)/);
  assert.match(budgetErr.message, /covenant refuses it/i);
  assert.equal(V4._validateSpendForm(form("kaspatest:recipient0", "10"), tight).ok, true, "exactly the remaining budget is allowed through");
  assert.equal(V4._validateSpendForm(form("kaspatest:recipient0", "20"), AGENT).ok, true, "exactly the cap is allowed through");
  assert.match(v("kaspatest:recipient0", "0").errors.get("amount").message, /greater than 0 KAS/);
  assert.match(v("kaspatest:recipient0", "1.234567891").errors.get("amount").message, /8 decimal places/);
  assert.match(v("kaspatest:recipient0", "abc").errors.get("amount").message, /greater than 0 KAS/);
  assert.match(v("", "5").errors.get("to").message, /recipient address/i);
  assert.match(v("kaspatest:recipient0", "").errors.get("amount").message, /Enter an amount in KAS/);
});

test("the checks are amounts only — they never decide who may sign or what is allowlisted", () => {
  const fn = /function validateSpendForm\(f, agent\) \{[\s\S]*?\n  \}/.exec(APP_V4)[0];
  assert.ok(!/xonly|owner|approver|signer|recipientAddresses/.test(fn), "no authority decision in the local checks");
  assert.ok(!/fetch|postJSON|getJSON/.test(fn), "the local checks make no request of their own");
});

/* ---------------- 4. it still ends in the SAME runFlow ------------------ */

test("submitting resolves the chosen ADDRESS through the server, then runs the identical agentSpend flow", async () => {
  const built = { requestId: "req-1", state: "BUILT", vaultId: VAULT.vaultId, review: { paymentKas: "5" },
    transaction: { unsignedSafeJson: "UNSIGNED", signInputs: [{ index: 0, sighashType: 1 }] } };
  const { element, calls, V4 } = makeEnv({
    fetchImpl: (p) => {
      if (p === "/identity/resolve-address") return Promise.resolve({ ok: true, status: 200, json: async () => ({ identity: { xOnlyPubkey: "dd".repeat(32) } }) });
      if (p === "/wallet/v4/requests") return Promise.resolve({ ok: true, status: 200, json: async () => ({ request: built }) });
      return Promise.resolve({ ok: true, status: 200, json: async () => ({}) });
    }
  });
  Object.assign(V4._state, { address: "kaspa:qagent", xonly: AGENT.agentPk, ready: true, vaultsById: { [VAULT.vaultId]: VAULT } });

  V4._openSpendForm(VAULT, AGENT);

  // Hand the code the form it looked up, populated as a user would.
  const f = element("v4-spend-form");
  const els = { '[name="to"]': field("to", "kaspatest:recipient0"), '[name="amount"]': field("amount", "5"), 'button[type="submit"]': { disabled: false } };
  f.querySelector = (sel) => els[sel] || null;
  f.querySelectorAll = () => [];

  const submit = (f.listeners.submit || [])[0];
  assert.equal(typeof submit, "function", "the form has a submit handler");
  await submit({ preventDefault() {} });
  await settle();

  const resolve = calls.find((c) => c.p === "/identity/resolve-address");
  assert.ok(resolve, "the address is resolved through the server's identity boundary");
  assert.equal(resolve.body.address, "kaspatest:recipient0", "the ADDRESS the human read is what gets resolved");

  const build = calls.find((c) => c.p === "/wallet/v4/requests");
  assert.ok(build, "the same build call is made");
  assert.equal(build.body.action, "agentSpend");
  assert.equal(build.body.vaultId, VAULT.vaultId);
  assert.equal(build.body.params.agentPk, AGENT.agentPk);
  assert.equal(build.body.params.recipient, "dd".repeat(32), "the SERVER-resolved x-only is used, not a browser-paired one");
  assert.equal(build.body.params.payAmountSompi, "500000000");
  assert.equal(build.body.signerAddress, "kaspa:qagent");
});

test("a rejected recipient address never reaches the build call", async () => {
  const { element, calls, V4 } = makeEnv({
    fetchImpl: (p) => {
      if (p === "/identity/resolve-address") return Promise.resolve({ ok: false, status: 422, json: async () => ({ error: { code: "ADDRESS_INVALID", message: "bad checksum" } }) });
      return Promise.resolve({ ok: true, status: 200, json: async () => ({}) });
    }
  });
  Object.assign(V4._state, { address: "kaspa:qagent", ready: true, vaultsById: { [VAULT.vaultId]: VAULT } });
  V4._openSpendForm(VAULT, AGENT);
  const f = element("v4-spend-form");
  const els = { '[name="to"]': field("to", "kaspatest:nope"), '[name="amount"]': field("amount", "5"), 'button[type="submit"]': { disabled: false } };
  f.querySelector = (sel) => els[sel] || null;
  f.querySelectorAll = () => [];
  await (f.listeners.submit || [])[0]({ preventDefault() {} });
  await settle();
  assert.ok(!calls.some((c) => c.p === "/wallet/v4/requests"), "no transaction was built");
});

test("a locally-refused amount never reaches the server at all", async () => {
  const { element, calls, V4 } = makeEnv();
  Object.assign(V4._state, { address: "kaspa:qagent", ready: true, vaultsById: { [VAULT.vaultId]: VAULT } });
  V4._openSpendForm(VAULT, AGENT);
  const f = element("v4-spend-form");
  const els = { '[name="to"]': field("to", "kaspatest:recipient0"), '[name="amount"]': field("amount", "999"), 'button[type="submit"]': { disabled: false } };
  f.querySelector = (sel) => els[sel] || null;
  f.querySelectorAll = () => [];
  await (f.listeners.submit || [])[0]({ preventDefault() {} });
  await settle();
  assert.deepEqual(calls, [], "over the cap: refused in the browser, no round-trip");
});

/* ---------------- 5. fail closed on missing policy --------------------- */

test("the Spend button fails closed when the agent's presented policy is not loaded", () => {
  const { element, V4 } = makeEnv();
  Object.assign(V4._state, { address: "kaspa:qagent", ready: true, vaultsById: {} });
  const btn = { getAttribute: () => AGENT.agentPk, closest: () => ({ getAttribute: () => VAULT.vaultId }) };
  const root = { querySelectorAll: (sel) => (sel === "[data-spend]" ? [btn] : []) };
  const src = /root\.querySelectorAll\("\[data-spend\]"\)[\s\S]*?\}\)\);/.exec(APP_V4)[0];
  assert.match(src, /if \(!vault \|\| !agent\)/, "no vault/agent means no form");
  assert.match(src, /is not loaded — reload before spending/);
  assert.ok(!/window\.prompt/.test(src), "the prompt chain is gone from the spend path");
  void element; void root;
});

test("no window.prompt remains in the spend path anywhere in app-v4.js", () => {
  assert.ok(!/window\.prompt\("Recipient wallet address/.test(APP_V4));
  assert.ok(!/promptKas\("Spend amount/.test(APP_V4));
});

/* ---------------- 6. agent identity + terminal-operation copy ---------- */

test("the agent card shows WHICH agent it is, in full", () => {
  const { V4 } = makeEnv();
  Object.assign(V4._state, { xonly: VAULT.owner, address: "kaspa:qowner" });
  const html = V4._agentCard(VAULT, AGENT);
  assert.match(html, new RegExp(`data-agent-identity="${AGENT.agentPk}"`));
  assert.ok(html.includes(AGENT.agentAddress), "the agent's address is shown");
  assert.ok(!html.includes(AGENT.agentAddress.slice(0, 8) + "…"), "never truncated");
});

test("an agent with no presented address falls back to its public key — never to nothing", () => {
  const { V4 } = makeEnv();
  const html = V4._agentCard(VAULT, { ...AGENT, agentAddress: undefined });
  assert.match(html, new RegExp(AGENT.agentPk));
});

test("owner recovery names the destination, the amount, and the terminal effect before the wallet is opened", () => {
  const src = /root\.querySelectorAll\("\[data-recover\]"\)[\s\S]*?\}\)\);/.exec(APP_V4)[0];
  assert.match(src, /Close this vault permanently and withdraw/);
  assert.match(src, /protectedValueKas/, "the actual protected value is named when known");
  assert.match(src, /to the owner wallet \$\{state\.address\}/, "the destination is named");
  assert.match(src, /every agent loses access immediately/);
  assert.match(src, /cannot be reopened/);
  assert.match(src, /review the exact transaction and sign it in your wallet before anything is broadcast/);
  // and it still goes through the same reviewed flow
  assert.match(src, /runFlow\(vid\(b\), "ownerRecover", p, "Approve in wallet"\)/ /* STALE ASSUMPTION (2026-09-05): the confirm label now names the wallet step ("Approve in wallet"), per the owner UX directive; the flow and params are unchanged */);
});
