"use strict";

/*
 * app-v4.js hosted agent-suspend UI (fullscale surface 21 web
 * composition; server routes GET/POST /vaults/:id/agent-suspensions —
 * server/src/agent-suspensions.js). Proves:
 *   - the vault card renders the suspension state with the SERVER'S
 *     NOT_COVENANT_NOTICE VERBATIM (pinned against the server module's
 *     actual constant — the UI never invents softer copy), keeping the
 *     covenant Pause control rendered alongside;
 *   - owner-only flip buttons (per-agent + all-agents + stale-entry
 *     unsuspend), agent-visible SUSPENDED (hosted) marker;
 *   - FAIL-CLOSED rendering: a failed/unrecognized suspension load
 *     renders UNKNOWN and offers no flip controls; _suspendUpdate on
 *     unknown state refuses locally without a network call;
 *   - _suspendUpdate wire shape: op/agentPk/allAgents + expectedVersion
 *     CAS on POST; VERSION_CONFLICT and the server's 403/404 surface
 *     verbatim as notes (never softened, never retried).
 *
 * Harness: the same vm-sandbox style as app-v4-govrisk-wiring.test.js
 * (real production source, minimal window/document stub, recording
 * fetch mock).
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const APP_V4 = fs.readFileSync(path.join(__dirname, "..", "app-v4.js"), "utf8");
// READ-ONLY import of the server's real constant: the UI banner must carry
// exactly this text (a copy drift here is a covenant-honesty regression).
const { NOT_COVENANT_NOTICE } = require("../../server/src/agent-suspensions.js");
const { baseVault, VAULT_ID, OWNER, AGENT, OWNER_ADDR } = require("./helpers.js");

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
        classList: { toggle() {}, add() {}, remove() {} },
        querySelectorAll: () => [],
        querySelector: () => null
      });
    }
    return elements.get(id);
  };
  return { document: { getElementById: (id) => element(id), querySelectorAll: () => [] }, element };
}

function makeFetch(handlers) {
  const calls = [];
  const fetchFn = async (url, opts) => {
    const method = (opts && opts.method) || "GET";
    const body = opts && opts.body ? JSON.parse(opts.body) : undefined;
    calls.push({ method, url, body });
    const handler = handlers[`${method} ${url}`];
    if (handler) {
      const result = typeof handler === "function" ? handler(body, calls.length) : handler;
      return { ok: result.status < 400, status: result.status, json: async () => result.body };
    }
    return { ok: true, json: async () => ({}) };
  };
  fetchFn.calls = calls;
  return fetchFn;
}

function sessionWith() {
  const snap = { connected: true, ready: true, address: OWNER_ADDR, xonly: OWNER, network: "testnet-10", serverNetwork: "testnet-10", provider: "spy", adapter: {} };
  return { active: () => snap, subscribe(cb) { cb(snap); return () => {}; }, connect() {}, disconnect() {} };
}

function loadApp(dom, fetchFn, { confirmResult = true } = {}) {
  const confirms = [];
  const windowObj = {
    addEventListener() {},
    confirm: (msg) => { confirms.push(msg); return confirmResult; },
    prompt: () => null,
    PolicyVaultWalletSession: sessionWith()
  };
  const sandbox = { window: windowObj, document: dom.document, console, crypto: { getRandomValues: (a) => a }, fetch: fetchFn, setTimeout, clearTimeout };
  vm.createContext(sandbox);
  vm.runInContext(APP_V4, sandbox, { filename: "app-v4.js" });
  const api = windowObj.PolicyVaultV4;
  // The DOMContentLoaded wiring never fires in this harness — set the
  // ready session state directly (established suite pattern).
  api._state.ready = true;
  api._state.address = OWNER_ADDR;
  api._state.xonly = OWNER;
  api._state.view = "vaults";
  return { window: windowObj, element: dom.element, api, confirms };
}

function suspRecord(over = {}) {
  return {
    schema: "policyvault-agent-suspensions/v1",
    vaultId: VAULT_ID,
    version: 3,
    allAgents: false,
    agents: [],
    updatedAt: "2026-08-26T00:00:00.000Z",
    updatedBy: { type: "wallet", identityId: null },
    notice: NOT_COVENANT_NOTICE,
    ...over
  };
}

function routes({ susp, suspStatus = 200 } = {}) {
  return {
    "GET /api/v1/vaults": { status: 200, body: { vaults: [baseVault()] } },
    "GET /api/v1/organizations": { status: 200, body: { organizations: [], assignments: {} } },
    "GET /api/v1/wallet/v4/requests?open=1": { status: 200, body: { requests: [] } },
    [`GET /api/v1/vaults/${VAULT_ID}/agent-suspensions`]:
      suspStatus >= 400
        ? { status: suspStatus, body: { error: { code: "VAULT_NOT_FOUND", message: "no such vault" } } }
        : { status: 200, body: { suspensions: susp || suspRecord() } }
  };
}

/* ---------------- rendering ---------------- */

test("owner with clean suspension state: per-agent Suspend (hosted) + Suspend all agents (hosted) render NEXT TO the covenant Pause control; no banner", async () => {
  const dom = makeDom();
  const loaded = loadApp(dom, makeFetch(routes({})));
  await loaded.api.render();
  const html = loaded.element("v4-root").innerHTML;
  assert.ok(html.includes(`data-suspend="${AGENT}"`), "per-agent suspend button");
  assert.ok(html.includes("Suspend (hosted)"), "per-agent label says hosted");
  assert.ok(html.includes(`data-suspendall="${VAULT_ID}"`) && html.includes("Suspend all agents (hosted)"), "all-agents control");
  assert.ok(html.includes(`data-pause="${VAULT_ID}"`), "the covenant Pause control stays rendered alongside — suspension never replaces it");
  assert.ok(!html.includes("Hosted suspension active"), "no active-suspension banner on a clean record");
  assert.ok(!html.includes("data-unsuspend"), "no unsuspend affordance when nothing is suspended");
});

test("active per-agent suspension: banner carries the server's NOT_COVENANT_NOTICE VERBATIM; agent row shows SUSPENDED (hosted); owner gets Unsuspend", async () => {
  const dom = makeDom();
  const loaded = loadApp(dom, makeFetch(routes({ susp: suspRecord({ agents: [AGENT], version: 5 }) })));
  await loaded.api.render();
  const html = loaded.element("v4-root").innerHTML;
  assert.ok(html.includes("Hosted suspension active"), "banner present");
  assert.ok(html.includes(NOT_COVENANT_NOTICE), "the server's covenant-honesty notice is rendered VERBATIM");
  assert.ok(html.includes("SUSPENDED (hosted)"), "agent marker names the hosted layer, never implying covenant pause");
  assert.ok(html.includes(`data-unsuspend="${AGENT}"`) && html.includes("Unsuspend (hosted)"));
  assert.ok(!html.includes(`data-suspend="${AGENT}"`), "a suspended agent offers unsuspend, not suspend");
  // the covenant-honesty pairing: the on-chain controls are still there
  assert.ok(html.includes(`data-pause="${VAULT_ID}"`) && html.includes(`data-remove="${AGENT}"`));
});

test("allAgents suspension: banner says ALL agents; vault control flips to Unsuspend all (hosted); per-agent flip is not offered", async () => {
  const dom = makeDom();
  const loaded = loadApp(dom, makeFetch(routes({ susp: suspRecord({ allAgents: true, version: 9 }) })));
  await loaded.api.render();
  const html = loaded.element("v4-root").innerHTML;
  assert.ok(html.includes("Hosted suspension active — ALL agents"));
  assert.ok(html.includes(`data-unsuspendall="${VAULT_ID}"`) && html.includes("Unsuspend all (hosted)"));
  assert.ok(!html.includes(`data-suspend="${AGENT}"`) && !html.includes(`data-unsuspend="${AGENT}"`), "per-agent flip hidden while the all-agents flag rules");
  assert.ok(html.includes(NOT_COVENANT_NOTICE));
});

test("stale suspended key (agent no longer in the registry) gets an inline Unsuspend affordance in the banner", async () => {
  const staleKey = "9d".repeat(32);
  const dom = makeDom();
  const loaded = loadApp(dom, makeFetch(routes({ susp: suspRecord({ agents: [staleKey] }) })));
  await loaded.api.render();
  const html = loaded.element("v4-root").innerHTML;
  assert.ok(html.includes("Stale entries"), html.includes("Hosted suspension active") ? "stale section present" : html);
  assert.ok(html.includes(`data-unsuspend="${staleKey}"`), "stale entries can always be cleared");
});

test("non-owner participant: sees the SUSPENDED (hosted) marker and the verbatim notice, but NO flip controls", async () => {
  const dom = makeDom();
  const loaded = loadApp(dom, makeFetch(routes({ susp: suspRecord({ agents: [AGENT] }) })));
  loaded.api._state.xonly = AGENT; // the agent's own wallet, not the owner
  await loaded.api.render();
  const html = loaded.element("v4-root").innerHTML;
  assert.ok(html.includes("SUSPENDED (hosted)"), "the agent can see it is suspended");
  assert.ok(html.includes(NOT_COVENANT_NOTICE));
  assert.ok(!html.includes("data-suspendall") && !html.includes("data-unsuspend=") && !html.includes("data-suspend="), "no flip controls for non-owners");
});

test("FAIL-CLOSED rendering: a failed suspension load renders UNKNOWN state and offers no flip controls (never 'not suspended')", async () => {
  const dom = makeDom();
  const loaded = loadApp(dom, makeFetch(routes({ suspStatus: 404 })));
  await loaded.api.render();
  const html = loaded.element("v4-root").innerHTML;
  assert.ok(/Hosted agent-suspension state unavailable/.test(html), html.slice(0, 400));
  assert.ok(html.includes("UNKNOWN"));
  assert.ok(html.includes("VAULT_NOT_FOUND"), "the server's refusal code surfaces verbatim");
  assert.ok(!html.includes("data-suspend=") && !html.includes("data-suspendall"), "no flip controls on unknown state");
  assert.ok(html.includes(`data-pause="${VAULT_ID}"`), "covenant controls unaffected");
});

test("FAIL-CLOSED rendering: an unrecognized suspension record shape is treated as unknown, not as unsuspended", async () => {
  const dom = makeDom();
  const loaded = loadApp(dom, makeFetch(routes({ susp: { schema: "policyvault-agent-suspensions/v99", weird: true } })));
  await loaded.api.render();
  const html = loaded.element("v4-root").innerHTML;
  assert.ok(/Hosted agent-suspension state unavailable/.test(html));
  assert.ok(!html.includes("data-suspend="), "no flip controls");
});

/* ---------------- _suspendUpdate wire shape ---------------- */

async function renderThen(loaded) {
  await loaded.api.render();
}

test("_suspendUpdate POSTs op/agentPk with the loaded version as expectedVersion CAS; the response updates local state", async () => {
  const dom = makeDom();
  const fetchFn = makeFetch({
    ...routes({ susp: suspRecord({ version: 7 }) }),
    [`POST /api/v1/vaults/${VAULT_ID}/agent-suspensions`]: (body) => ({
      status: 200,
      body: { suspensions: suspRecord({ version: 8, agents: [body.agentPk] }) }
    })
  });
  const loaded = loadApp(dom, fetchFn);
  await renderThen(loaded);
  await loaded.api._suspendUpdate(VAULT_ID, { op: "suspend", agentPk: AGENT });
  const post = fetchFn.calls.find((c) => c.method === "POST" && c.url === `/api/v1/vaults/${VAULT_ID}/agent-suspensions`);
  assert.ok(post, "one POST to the real route");
  assert.deepEqual(post.body, { op: "suspend", expectedVersion: 7, agentPk: AGENT });
  assert.equal(loaded.api._state.suspByVault[VAULT_ID].version, 8, "local state adopts the server's returned record");
  assert.ok(loaded.confirms.length === 1 && /NOT a covenant control/.test(loaded.confirms[0]), "the confirm copy states the covenant-honesty boundary");
  assert.ok(/Pause or Remove agent/.test(loaded.confirms[0]), "paired with the covenant pause guidance");
});

test("_suspendUpdate allAgents flip sends allAgents:true (no agentPk)", async () => {
  const dom = makeDom();
  const fetchFn = makeFetch({
    ...routes({ susp: suspRecord({ version: 2 }) }),
    [`POST /api/v1/vaults/${VAULT_ID}/agent-suspensions`]: { status: 200, body: { suspensions: suspRecord({ version: 3, allAgents: true }) } }
  });
  const loaded = loadApp(dom, fetchFn);
  await renderThen(loaded);
  await loaded.api._suspendUpdate(VAULT_ID, { op: "suspend", allAgents: true });
  const post = fetchFn.calls.find((c) => c.method === "POST" && c.url.endsWith("agent-suspensions"));
  assert.deepEqual(post.body, { op: "suspend", expectedVersion: 2, allAgents: true });
});

test("_suspendUpdate on UNKNOWN state refuses locally — no POST is ever sent (fail closed)", async () => {
  const dom = makeDom();
  const fetchFn = makeFetch(routes({ suspStatus: 404 }));
  const loaded = loadApp(dom, fetchFn);
  await renderThen(loaded);
  await loaded.api._suspendUpdate(VAULT_ID, { op: "suspend", agentPk: AGENT });
  assert.ok(!fetchFn.calls.some((c) => c.method === "POST"), "no network mutation on unknown state");
  assert.ok(/unknown/i.test(loaded.element("v4-notice").textContent) && /failing closed/i.test(loaded.element("v4-notice").textContent));
});

test("a declined confirm sends nothing", async () => {
  const dom = makeDom();
  const fetchFn = makeFetch(routes({}));
  const loaded = loadApp(dom, fetchFn, { confirmResult: false });
  await renderThen(loaded);
  await loaded.api._suspendUpdate(VAULT_ID, { op: "suspend", agentPk: AGENT });
  assert.ok(!fetchFn.calls.some((c) => c.method === "POST"));
});

test("VERSION_CONFLICT surfaces as a reload-and-retry note (never an automatic retry loop)", async () => {
  const dom = makeDom();
  const fetchFn = makeFetch({
    ...routes({}),
    [`POST /api/v1/vaults/${VAULT_ID}/agent-suspensions`]: { status: 409, body: { error: { code: "VERSION_CONFLICT", message: "suspensions changed (version 4, expected 3) — reload and retry" } } }
  });
  const loaded = loadApp(dom, fetchFn);
  await renderThen(loaded);
  await loaded.api._suspendUpdate(VAULT_ID, { op: "unsuspend", agentPk: AGENT });
  const posts = fetchFn.calls.filter((c) => c.method === "POST");
  assert.equal(posts.length, 1, "exactly one attempt — no retry loop");
  assert.ok(/concurrently/.test(loaded.element("v4-notice").textContent));
});

test("the server's authorization refusal (403/404) surfaces verbatim in the note — never softened", async () => {
  const dom = makeDom();
  const fetchFn = makeFetch({
    ...routes({}),
    [`POST /api/v1/vaults/${VAULT_ID}/agent-suspensions`]: { status: 403, body: { error: { code: "FORBIDDEN", message: "vault access denied" } } }
  });
  const loaded = loadApp(dom, fetchFn);
  await renderThen(loaded);
  await loaded.api._suspendUpdate(VAULT_ID, { op: "suspend", agentPk: AGENT });
  const noticeText = loaded.element("v4-notice").textContent;
  assert.ok(/Suspension update failed/.test(noticeText) && /FORBIDDEN/.test(noticeText) && /vault access denied/.test(noticeText), noticeText);
});
