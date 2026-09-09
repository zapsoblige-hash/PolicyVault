"use strict";

/*
 * BROWSER layer (jsdom) — H2 final-polish create-form regression (§13/§17),
 * carried onto the GUIDED SETUP of the 2026-09-05 flagship UX successor
 * (STALE ASSUMPTION update: the DOM changed — a stepper with all step
 * panels present, an OPTIONAL approver list that starts with no row, an
 * "Approvals needed" SELECT that reads "k of N approvers", a duration
 * control with the exact DAA under a "Technical detail" disclosure — the
 * PROPERTIES pinned here are unchanged and every assertion is as strict).
 *
 * Loads the REAL served markup (web/index.html) and the REAL production
 * web/core-bundle.js + web/setup-ui.js + web/app-v4.js in a DOM (exactly the
 * order index.html loads them), mocking ONLY the documented seams: the
 * canonical wallet session (window.PolicyVaultWalletSession — the same
 * contract app.js exposes) and fetch (the HTTP API). This is the permanent
 * regression net for the approver-row multiplication bug: the delegated row
 * wiring is attached to the persistent #v4-root exactly once, so re-renders
 * (tab switches, wallet session emissions) can never accumulate duplicate
 * listeners.
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { JSDOM } = require("jsdom");

const WEB = path.join(__dirname, "..", "..", "web");
const HTML = fs.readFileSync(path.join(WEB, "index.html"), "utf8")
  .replace(/<script src="[^"]*"><\/script>/g, ""); // scripts are evaluated manually
const APP_V4 = fs.readFileSync(path.join(WEB, "app-v4.js"), "utf8");
/* The REAL committed browser core bundle, evaluated FIRST — exactly the
 * order web/index.html loads it in (core-bundle.js precedes setup-ui.js and
 * app-v4.js). app-v4.js reads window.PolicyVaultCore.amounts for the
 * canonical KAS->sompi parser and window.PolicyVaultSetupUi for the guided
 * setup components, so a harness that omitted either would be modelling a
 * page that never exists. */
const CORE_BUNDLE = fs.readFileSync(path.join(WEB, "core-bundle.js"), "utf8");
const SETUP_UI = fs.readFileSync(path.join(WEB, "setup-ui.js"), "utf8");

const OWNER = "kaspatest:qq" + "0".repeat(59);
const fakeXOnly = (addr) => crypto.createHash("sha256").update(String(addr).trim()).digest("hex");

async function harness() {
  const dom = new JSDOM(HTML, { url: "http://127.0.0.1:3080/", runScripts: "outside-only", pretendToBeVisual: true });
  const { window } = dom;
  const calls = { create: [] };
  window.fetch = async (url, opts) => {
    const u = String(url);
    const body = opts && opts.body ? JSON.parse(opts.body) : null;
    const json = (status, payload) => ({ ok: status < 400, status, json: async () => payload });
    if (u.includes("/identity/resolve-address")) {
      const addr = String(body.address ?? "").trim();
      if (!addr.startsWith("kaspatest:")) return json(422, { error: { code: "ADDRESS_WRONG_NETWORK", message: "address is not a testnet-10 address" } });
      if (addr.includes("badcheck")) return json(422, { error: { code: "ADDRESS_INVALID", message: "Enter a valid Kaspa wallet address." } });
      return json(200, { identity: { xOnlyPubkey: fakeXOnly(addr) } });
    }
    if (u.includes("/wallet/v4/create")) {
      calls.create.push(body);
      return json(422, { error: { code: "TEST_STOP", message: "harness stop" } });
    }
    if (u.includes("/organizations")) return json(200, { organizations: [], assignments: {}, assignmentsVersion: 0 });
    if (u.includes("/vaults")) return json(200, { vaults: [] });
    return json(200, {});
  };
  const listeners = [];
  const snap = () => ({
    connected: true, ready: true, address: OWNER, xonly: "aa".repeat(32),
    network: "testnet-10", provider: "mock", adapter: { signInputs: async () => "{}" }
  });
  window.PolicyVaultWalletSession = {
    active: snap,
    subscribe(cb) { listeners.push(cb); cb(snap()); return () => {}; },
    connect() {}, disconnect() {}
  };
  window.eval(CORE_BUNDLE);
  window.eval(SETUP_UI);
  window.eval(APP_V4);
  window.dispatchEvent(new window.Event("DOMContentLoaded"));
  const doc = window.document;
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const waitFor = async (fn, ms = 2000) => {
    const t0 = Date.now();
    for (;;) {
      const v = fn();
      if (v) return v;
      if (Date.now() - t0 > ms) throw new Error("waitFor timed out");
      await sleep(10);
    }
  };
  return {
    window, doc, calls, sleep, waitFor,
    emit: () => { for (const cb of listeners) cb(snap()); },
    click: (el) => el.dispatchEvent(new window.MouseEvent("click", { bubbles: true, cancelable: true })),
    tab: (v) => doc.querySelector(`.v4-tab[data-view="${v}"]`),
    rows: () => [...doc.querySelectorAll('[data-rows="approver"] [name="approver"]')],
    rowEls: () => [...doc.querySelectorAll('[data-rows="approver"] .addr-row')],
    addBtn: () => doc.getElementById("v4-add-approver"),
    form: () => doc.getElementById("v4-create-form"),
    /* jsdom applies no visibility rules, so the hidden step panels are
     * reachable; each helper re-queries the LIVE form because row and
     * navigation clicks re-render the whole setup (values kept). */
    set: (name, value) => { const el = doc.getElementById("v4-create-form").querySelector(`[name="${name}"]`); el.value = value; el.dispatchEvent(new window.Event("input", { bubbles: true })); },
    setRow: (i, value) => { const el = doc.querySelectorAll('[data-rows="approver"] [name="approver"]')[i]; el.value = value; el.dispatchEvent(new window.Event("input", { bubbles: true })); },
    errors: () => [...doc.querySelectorAll(".ferr")].map((e) => e.textContent.trim()).filter(Boolean),
    /* submit() dispatches the event and then waits until the guided setup is
     * IDLE again (buildAndReviewVault ignores a submit while one is in
     * flight — a duplicate-submission guard), so a following assertion or
     * submit never races the asynchronous, server-boundary validation. */
    submit: async () => {
      doc.getElementById("v4-create-form").dispatchEvent(new window.Event("submit", { bubbles: true, cancelable: true }));
      await waitFor(() => window.PolicyVaultV4._vaultSetup().busy === false, 5000);
    }
  };
}

async function openCreate(h) {
  h.click(h.tab("create"));
  await h.waitFor(() => h.doc.getElementById("v4-create-form"));
  return h.doc.getElementById("v4-create-form");
}

test("§13 one click adds exactly one blank row: 0→1, 1→2, …, 9→10, 10→still 10 (button disabled)", async () => {
  const h = await harness();
  await openCreate(h);
  assert.equal(h.rows().length, 0, "an OPTIONAL list starts with no row (a blank row would read as required)");
  for (let expected = 1; expected <= 10; expected++) {
    h.click(h.addBtn());
    assert.equal(h.rows().length, expected, `after click #${expected}`);
    assert.equal(h.rows()[expected - 1].value, "", "a new row is always blank");
  }
  assert.equal(h.addBtn().disabled, true, "+ Add approver is disabled at the 10-slot maximum");
  h.click(h.addBtn());
  assert.equal(h.rows().length, 10, "clicks at the maximum add nothing");
});

test("§13 listener idempotency: repeated renders (wallet emissions + tab switches) never multiply rows per click", async () => {
  const h = await harness();
  await openCreate(h);
  // Three wallet-session emissions while on the create view…
  h.emit(); h.emit(); h.emit();
  await h.sleep(30);
  // …plus two full Vaults <-> Create round trips.
  h.click(h.tab("vaults")); await h.sleep(20);
  h.click(h.tab("create")); await h.waitFor(() => h.doc.getElementById("v4-create-form"));
  h.click(h.tab("vaults")); await h.sleep(20);
  h.click(h.tab("create")); await h.waitFor(() => h.doc.getElementById("v4-create-form"));
  const before = h.rows().length;
  h.click(h.addBtn());
  assert.equal(h.rows().length, before + 1, "ONE click adds exactly ONE row after any number of re-renders");
});

test("§13 remove removes exactly the chosen row; other values preserved; new rows never clone", async () => {
  const h = await harness();
  await openCreate(h);
  for (let i = 0; i < 5; i++) h.click(h.addBtn());
  for (let i = 0; i < 5; i++) h.setRow(i, `kaspatest:qqrow${i + 1}`);
  // Remove row 4 (index 3): only that row disappears, values elsewhere intact.
  h.click(h.rowEls()[3].querySelector(".rm-approver"));
  const after = h.rows().map((r) => r.value);
  assert.deepEqual(after, ["kaspatest:qqrow1", "kaspatest:qqrow2", "kaspatest:qqrow3", "kaspatest:qqrow5"]);
  // No clone: with row 1 holding a value, a new row arrives blank.
  h.click(h.addBtn());
  const values = h.rows().map((r) => r.value);
  assert.equal(values[values.length - 1], "", "new row is blank, never a copy of a previous row");
  assert.equal(values[0], "kaspatest:qqrow1", "existing values preserved");
});

test("§17 budget period: presets kept, Custom shows value+unit (hours/days/weeks), copy is plain language, DAA only under Technical detail", async () => {
  const h = await harness();
  const form = await openCreate(h);
  const sel = form.querySelector('[name="period"]');
  assert.deepEqual([...sel.options].map((o) => o.value), ["1h", "6h", "1d", "1w", "custom"]);
  const effect = () => h.form().querySelector('[data-duration-effect="period"]');
  assert.equal(effect().textContent, "About 1 day. Measured using Kaspa network progress, so the elapsed time is approximate.");
  assert.ok(!/DAA/.test(effect().textContent), "primary copy never mentions DAA");
  // Custom reveals the value/unit controls.
  sel.value = "custom";
  sel.dispatchEvent(new h.window.Event("change", { bubbles: true }));
  assert.equal(h.form().querySelector('[data-duration-custom="period"]').hidden, false);
  assert.deepEqual([...h.form().querySelector('[name="periodUnit"]').options].map((o) => o.value), ["hour", "day", "week"]);
  h.set("periodValue", "2");
  assert.equal(effect().textContent, "About 2 days. Measured using Kaspa network progress, so the elapsed time is approximate.");
  h.form().querySelector('[name="periodUnit"]').value = "hour";
  h.set("periodValue", "2");
  assert.equal(effect().textContent, "About 2 hours. Measured using Kaspa network progress, so the elapsed time is approximate.");
  // A decimal is refused live with the whole-number equivalent — never truncated.
  h.set("periodValue", "1.5");
  h.form().querySelector('[name="periodUnit"]').value = "day";
  h.set("periodValue", "1.5");
  assert.match(effect().textContent, /36 hours/);
  // The technical DAA value lives under Technical detail (<details>), not in primary copy.
  h.set("periodValue", "2");
  const tech = [...h.form().querySelectorAll("details")].filter((d) => /DAA score/.test(d.textContent));
  assert.ok(tech.length > 0, "technical detail available under a disclosure");
  let primary = h.form().textContent;
  for (const d of h.form().querySelectorAll("details")) primary = primary.replace(d.textContent, "");
  assert.ok(!/DAA/.test(primary), "no DAA jargon outside Technical detail / Advanced");
  assert.ok(!h.form().querySelector('[name="periodLengthDaa"]'), "raw periodLengthDaa is never a normal-mode input");
});

test("§17 pre-Review validation blocks the server call: duplicate approvers, M > configured, empty row; field-local errors shown", async () => {
  const h = await harness();
  await openCreate(h);
  // Fill an otherwise-valid form (every panel is in the DOM).
  h.set("label", "H2 KasWare Acceptance");
  h.set("deposit", "20");
  h.set("reserve", "2");
  h.set("agent", "kaspatest:qqagent1");
  h.set("maxPerSpend", "2");
  h.set("budget", "10");
  h.set("approvalThreshold", "1");
  h.set("recipient", "kaspatest:qqrecipient1");
  // Duplicate approvers + inflated M.
  h.click(h.addBtn()); h.click(h.addBtn()); h.click(h.addBtn());
  h.setRow(0, "kaspatest:qqapprover1");
  h.setRow(1, "kaspatest:qqapprover1"); // duplicate address
  h.setRow(2, "");                       // empty row must not count as configured
  h.form().querySelector('[name="approvalM"]').innerHTML = `<option value="3" selected>3</option>`; // a stale/hostile choice above the configured count
  await h.submit();
  await h.waitFor(() => h.errors().length > 0);
  assert.equal(h.calls.create.length, 0, "invalid form NEVER reaches POST /wallet/v4/create");
  const errText = h.errors().join(" ");
  assert.ok(/Same wallet as approver 1/.test(errText), "duplicate approver rejected with a row-local error");
  assert.ok(/Enter an address or remove this row/.test(errText), "empty approver row rejected, not silently skipped");

  // Fix duplicates but leave M above the configured count -> still blocked, never lowered for the user.
  h.setRow(1, "kaspatest:qqapprover2");
  h.click(h.rowEls()[2].querySelector(".rm-approver"));
  await h.sleep(50);
  assert.deepEqual(h.rows().map((r) => r.value), ["kaspatest:qqapprover1", "kaspatest:qqapprover2"], "the removed row is gone; the others keep their values");
  h.form().querySelector('[name="approvalM"]').innerHTML = `<option value="3" selected>3</option>`;
  await h.submit();
  await h.waitFor(() => h.errors().some((e) => /3 of 2 is impossible/.test(e)) && h.errors().every((e) => !/Same wallet/.test(e)), 5000);
  assert.equal(h.calls.create.length, 0, "M > configured approvers never reaches the server");
  assert.equal(h.form().querySelector('[name="approvalM"]').value, "3", "the impossible value is preserved for an explicit correction, never silently lowered");

  // Wrong-network / malformed addresses are field-local errors too.
  h.form().querySelector('[name="approvalM"]').innerHTML = `<option value="2" selected>2 of 2 approvers</option>`;
  h.set("agent", "kaspa:qqmainnet");
  await h.submit();
  await h.waitFor(() => h.errors().some((e) => /Agent address rejected/.test(e)));
  assert.equal(h.calls.create.length, 0);
});

test("§17 a valid form reaches the server with the canonical friendly body (custom period travels as {value,unit}; the browser never supplies a DAA value)", async () => {
  const h = await harness();
  const form = await openCreate(h);
  h.set("label", "H2 KasWare Acceptance");
  h.set("deposit", "20");
  h.set("reserve", "2");
  h.set("agent", "kaspatest:qqagent1");
  h.set("maxPerSpend", "2");
  h.set("budget", "10");
  h.set("approvalThreshold", "1");
  h.set("recipient", "kaspatest:qqrecipient1");
  const sel = form.querySelector('[name="period"]');
  sel.value = "custom";
  sel.dispatchEvent(new h.window.Event("change", { bubbles: true }));
  h.form().querySelector('[name="periodUnit"]').value = "hour";
  h.set("periodValue", "2");
  h.click(h.addBtn()); h.click(h.addBtn());
  h.setRow(0, "kaspatest:qqapprover1");
  h.setRow(1, "kaspatest:qqapprover2");
  const m = h.form().querySelector('[name="approvalM"]');
  m.value = "2";
  m.dispatchEvent(new h.window.Event("change", { bubbles: true }));
  await h.submit();
  await h.waitFor(() => h.calls.create.length === 1, 5000);
  const body = h.calls.create[0];
  assert.equal(body.contractVersion, "policyvault-0.4.1");
  assert.equal(body.signerAddress, OWNER);
  assert.match(body.vaultId, /^[0-9a-f]{64}$/);
  assert.deepEqual(body.agent.budgetPeriod, { value: "2", unit: "hour" }, "custom period is sent as human intent — the SERVER derives periodLengthDaa");
  assert.equal(body.agent.agentAddress, "kaspatest:qqagent1");
  assert.deepEqual(body.agent.recipientAddresses, ["kaspatest:qqrecipient1"]);
  assert.deepEqual(body.approvers, { addresses: ["kaspatest:qqapprover1", "kaspatest:qqapprover2"], approvalM: "2" });
  assert.ok(!("periodLengthDaa" in body.agent), "browser never supplies periodLengthDaa");
  assert.ok(!("periodStartDaa" in body.agent), "browser never supplies periodStartDaa");
  assert.ok(!("periodSpent" in body.agent), "browser never supplies periodSpent");
});
