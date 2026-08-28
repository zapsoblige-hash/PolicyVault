"use strict";

/*
 * web/org-controls-ui.js — organization governance/risk controls form
 * (completion-standard item 3). Covers: CAS version-conflict handling
 * (reload-and-retry, NEVER a blind overwrite/auto-merge), form-value ->
 * request-body construction (mixed wallet-address / x-only approver
 * lines, delay hours -> ms, adapters JSON), and client-side validation
 * that fails closed on malformed input before any network call.
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");

const { createModule } = require("../org-controls-ui.js");

const ORG_ID = "org-1";
const APPROVER_X = "cc".repeat(32);

function fakeApi({ resolveMap } = {}) {
  const calls = [];
  const responses = new Map();
  const resolves = resolveMap || {};
  return {
    calls,
    on(key, value) { responses.set(key, value); return this; },
    async getJSON(path) {
      calls.push({ method: "GET", path });
      const r = responses.get(`GET ${path}`);
      if (typeof r === "function") return r();
      if (r === undefined) throw Object.assign(new Error(`no fake response for GET ${path}`), { code: "FAKE_UNMAPPED" });
      return r;
    },
    async postJSON(path, body) {
      calls.push({ method: "POST", path, body });
      const r = responses.get(`POST ${path}`);
      if (typeof r === "function") return r(body);
      if (r === undefined) throw Object.assign(new Error(`no fake response for POST ${path}`), { code: "FAKE_UNMAPPED" });
      return r;
    },
    async resolveXOnly(address) {
      calls.push({ method: "resolveXOnly", address });
      if (Object.prototype.hasOwnProperty.call(resolves, address)) return resolves[address];
      throw Object.assign(new Error(`address rejected: ${address}`), { code: "ADDRESS_INVALID" });
    }
  };
}

function baseControls(overrides) {
  return Object.assign(
    {
      schema: "policyvault-org-controls/v1",
      orgId: ORG_ID,
      version: 3,
      governance: { quorum: null, delayMs: 0 },
      risk: { adapters: [], onAdapterError: "REVIEW", reviewRequired: false },
      createdAt: "2026-08-01T00:00:00.000Z",
      updatedAt: "2026-08-20T00:00:00.000Z"
    },
    overrides
  );
}

/* ==================== createModule guards ==================== */

test("createModule: requires api.{getJSON,postJSON,resolveXOnly}", () => {
  assert.throws(() => createModule({ api: { getJSON: async () => {}, postJSON: async () => {} } }), /requires api/, "missing resolveXOnly");
  assert.throws(() => createModule({}), /requires api/);
});

/* ==================== rendering ==================== */

test("renderControlsFormHtml: carries the CAS version and orgId as data attributes on the form", () => {
  const cu = createModule({ api: fakeApi() });
  const html = cu.renderControlsFormHtml(baseControls());
  assert.ok(html.includes('data-controls-form'));
  assert.ok(html.includes('data-org-id="org-1"'));
  assert.ok(html.includes('data-org-version="3"'));
});

test("renderControlsFormHtml: pre-fills existing quorum approvers and M", () => {
  const cu = createModule({ api: fakeApi() });
  const html = cu.renderControlsFormHtml(baseControls({ governance: { quorum: { approvers: [APPROVER_X], m: 1 }, delayMs: 3600000 } }));
  assert.ok(html.includes(APPROVER_X));
  assert.ok(html.includes('value="1"')); // M
  assert.ok(html.includes('value="1"') && /Delay window/.test(html));
});

test("renderControlsFormHtml: never breaks on a fresh org with no stored controls (defaultControls shape)", () => {
  const cu = createModule({ api: fakeApi() });
  assert.doesNotThrow(() => cu.renderControlsFormHtml({ schema: "policyvault-org-controls/v1", orgId: ORG_ID, version: 0, governance: { quorum: null, delayMs: 0 }, risk: { adapters: [], onAdapterError: "REVIEW", reviewRequired: false } }));
});

/* ==================== buildControlsBody: form values -> request body ==================== */

test("buildControlsBody: blank approvers -> owner-only governance (quorum omitted)", async () => {
  const cu = createModule({ api: fakeApi() });
  const body = await cu.buildControlsBody({ approverAddresses: "", m: "", delayHours: "24", adaptersJson: "" });
  assert.deepEqual(body.governance, { delayMs: 24 * 3600000 });
});

test("buildControlsBody: mixed wallet-address and raw x-only lines are both accepted — addresses resolve, x-only passes through unchanged", async () => {
  const addr = "kaspatest:approver1";
  const api = fakeApi({ resolveMap: { [addr]: "dd".repeat(32) } });
  const cu = createModule({ api });
  const body = await cu.buildControlsBody({ approverAddresses: `${addr}\n${APPROVER_X}`, m: "2", delayHours: "0", adaptersJson: "" });
  assert.deepEqual(body.governance.quorum.approvers, ["dd".repeat(32), APPROVER_X]);
  assert.equal(body.governance.quorum.m, 2);
  const resolveCalls = api.calls.filter((c) => c.method === "resolveXOnly");
  assert.equal(resolveCalls.length, 1, "only the wallet-address line goes through resolution — the x-only line never does");
});

test("buildControlsBody: comma-separated approver lines are also accepted", async () => {
  const api = fakeApi();
  const cu = createModule({ api });
  const body = await cu.buildControlsBody({ approverAddresses: `${APPROVER_X}, dd${"11".repeat(31)}`, m: "1", delayHours: "0", adaptersJson: "" });
  assert.equal(body.governance.quorum.approvers.length, 2);
});

test("buildControlsBody: M out of range fails closed BEFORE any network call would happen", async () => {
  const cu = createModule({ api: fakeApi() });
  await assert.rejects(
    () => cu.buildControlsBody({ approverAddresses: APPROVER_X, m: "5", delayHours: "0", adaptersJson: "" }),
    (e) => e.code === "CONTROLS_FORM_INVALID" && /between 1 and 1/.test(e.message)
  );
});

test("buildControlsBody: a rejected approver address surfaces the exact address in the error message", async () => {
  const api = fakeApi({ resolveMap: {} }); // resolveXOnly always rejects
  const cu = createModule({ api });
  await assert.rejects(
    () => cu.buildControlsBody({ approverAddresses: "kaspatest:bogus", m: "1", delayHours: "0", adaptersJson: "" }),
    (e) => e.code === "CONTROLS_FORM_INVALID" && e.message.includes("kaspatest:bogus")
  );
});

test("buildControlsBody: delay hours must be a non-negative number", async () => {
  const cu = createModule({ api: fakeApi() });
  await assert.rejects(() => cu.buildControlsBody({ approverAddresses: "", delayHours: "not-a-number", adaptersJson: "" }), (e) => e.code === "CONTROLS_FORM_INVALID");
  await assert.rejects(() => cu.buildControlsBody({ approverAddresses: "", delayHours: "-1", adaptersJson: "" }), (e) => e.code === "CONTROLS_FORM_INVALID");
  const body = await cu.buildControlsBody({ approverAddresses: "", delayHours: "1.5", adaptersJson: "" });
  assert.equal(body.governance.delayMs, 1.5 * 3600000);
});

test("buildControlsBody: adaptersJson must parse to an array; invalid JSON fails closed with a clear message", async () => {
  const cu = createModule({ api: fakeApi() });
  await assert.rejects(() => cu.buildControlsBody({ approverAddresses: "", delayHours: "0", adaptersJson: "{not json" }), (e) => e.code === "CONTROLS_FORM_INVALID" && /invalid/i.test(e.message));
  await assert.rejects(() => cu.buildControlsBody({ approverAddresses: "", delayHours: "0", adaptersJson: '{"type":"threshold"}' }), (e) => e.code === "CONTROLS_FORM_INVALID" && /array/i.test(e.message));
  const body = await cu.buildControlsBody({ approverAddresses: "", delayHours: "0", adaptersJson: '[{"type":"threshold","params":{}}]' });
  assert.deepEqual(body.risk.adapters, [{ type: "threshold", params: {} }]);
});

test("buildControlsBody: risk toggles pass through only when set; onAdapterError='' omits the field (server default)", async () => {
  const cu = createModule({ api: fakeApi() });
  const omitted = await cu.buildControlsBody({ approverAddresses: "", delayHours: "0", onAdapterError: "", onEmpty: "", timeoutMs: "", reviewRequired: false, adaptersJson: "" });
  assert.ok(!Object.prototype.hasOwnProperty.call(omitted.risk, "onAdapterError"));
  assert.ok(!Object.prototype.hasOwnProperty.call(omitted.risk, "onEmpty"));
  assert.ok(!Object.prototype.hasOwnProperty.call(omitted.risk, "timeoutMs"));
  const set = await cu.buildControlsBody({ approverAddresses: "", delayHours: "0", onAdapterError: "DENY", onEmpty: "DENY", timeoutMs: "3000", reviewRequired: true, adaptersJson: "" });
  assert.equal(set.risk.onAdapterError, "DENY");
  assert.equal(set.risk.onEmpty, "DENY");
  assert.equal(set.risk.timeoutMs, 3000);
  assert.equal(set.risk.reviewRequired, true);
});

/* ==================== saveControls: CAS discipline ==================== */

test("saveControls: sends expectedVersion and returns the server's saved record on success", async () => {
  const api = fakeApi();
  api.on(`POST /organizations/${ORG_ID}/controls`, (body) => {
    assert.equal(body.expectedVersion, 3);
    return { controls: baseControls({ version: 4 }) };
  });
  const cu = createModule({ api });
  const saved = await cu.saveControls(ORG_ID, { approverAddresses: "", delayHours: "0", adaptersJson: "" }, { expectedVersion: 3 });
  assert.equal(saved.version, 4);
});

test("saveControls: a 409 VERSION_CONFLICT is marked versionConflict:true and thrown UNCHANGED — never retried, never merged, never overwritten by this function", async () => {
  const api = fakeApi();
  let postCount = 0;
  api.on(`POST /organizations/${ORG_ID}/controls`, () => {
    postCount++;
    const e = new Error("controls changed (version 5, expected 3) — reload and retry");
    e.code = "VERSION_CONFLICT";
    e.status = 409;
    throw e;
  });
  const cu = createModule({ api });
  await assert.rejects(
    () => cu.saveControls(ORG_ID, { approverAddresses: "", delayHours: "0", adaptersJson: "" }, { expectedVersion: 3 }),
    (e) => e.code === "VERSION_CONFLICT" && e.versionConflict === true
  );
  assert.equal(postCount, 1, "saveControls makes exactly one attempt — no automatic retry loop");
});

test("saveControls: a form-validation failure never reaches the network", async () => {
  const api = fakeApi();
  const cu = createModule({ api });
  await assert.rejects(
    () => cu.saveControls(ORG_ID, { approverAddresses: APPROVER_X, m: "9", delayHours: "0", adaptersJson: "" }, { expectedVersion: 3 }),
    (e) => e.code === "CONTROLS_FORM_INVALID"
  );
  assert.equal(api.calls.filter((c) => c.method === "POST").length, 0);
});

test("fetchControls: GETs the exact org controls route", async () => {
  const api = fakeApi();
  api.on(`GET /organizations/${ORG_ID}/controls`, { controls: baseControls() });
  const cu = createModule({ api });
  const c = await cu.fetchControls(ORG_ID);
  assert.equal(c.version, 3);
});
