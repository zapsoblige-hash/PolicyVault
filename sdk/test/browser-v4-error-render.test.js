"use strict";

/*
 * BROWSER layer (jsdom) — Phase G regression: v0.4.1 API error rendering.
 *
 * Found by the REAL KasWare human acceptance run (Phase G): when the hosted
 * session ended, GET /vaults returned the standard hosted error envelope
 *   { error: { code: "SESSION_INVALID", message: "sign in to use this route" } }
 * and the v0.4.1 vaults view rendered "Could not load vaults: [object Object]"
 * — app-v4.js getJSON threw `new Error(j.error)` with the OBJECT envelope,
 * and neither helper exposed the envelope's `code` to callers (so notices
 * printed an empty code and code-specific handling like ORG_NOT_EMPTY could
 * never match). app.js already extracted both correctly; this pins app-v4.js
 * to the same contract:
 *   message = error.message (envelope) | error (string) | statusText
 *   e.code  = error.code, e.payload = the full body.
 *
 * Loads the REAL served markup and the REAL production web/app-v4.js in a
 * DOM, mocking ONLY the documented seams (canonical wallet session + fetch).
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { JSDOM } = require("jsdom");

const WEB = path.join(__dirname, "..", "..", "web");
const HTML = fs.readFileSync(path.join(WEB, "index.html"), "utf8")
  .replace(/<script src="[^"]*"><\/script>/g, ""); // scripts are evaluated manually
const APP_V4 = fs.readFileSync(path.join(WEB, "app-v4.js"), "utf8");

const OWNER = "kaspatest:qq" + "0".repeat(59);

/* The EXACT hosted envelope observed through the real tunnel in Phase G. */
const SESSION_ENVELOPE = { error: { code: "SESSION_INVALID", message: "sign in to use this route" } };
const ORG_ENVELOPE = { error: { code: "ORG_LIMIT", message: "too many organizations" } };

async function harness() {
  const dom = new JSDOM(HTML, { url: "http://127.0.0.1:3080/", runScripts: "outside-only", pretendToBeVisual: true });
  const { window } = dom;
  window.fetch = async (url, opts) => {
    const u = String(url);
    const json = (status, payload) => ({ ok: status < 400, status, statusText: status === 401 ? "Unauthorized" : "Error", json: async () => payload });
    if (u.includes("/vaults")) return json(401, SESSION_ENVELOPE);
    if (u.includes("/organizations") && opts && opts.method === "POST") return json(422, ORG_ENVELOPE);
    if (u.includes("/organizations")) return json(200, { organizations: [], assignments: {}, assignmentsVersion: 0 });
    if (u.includes("/wallet/v4/requests")) return json(401, SESSION_ENVELOPE);
    return json(200, {});
  };
  window.PolicyVaultWalletSession = {
    active: () => ({
      connected: true, ready: true, address: OWNER, xonly: "aa".repeat(32),
      network: "testnet-10", provider: "mock", adapter: { signInputs: async () => "{}" }
    }),
    subscribe(cb) { cb(this.active()); return () => {}; },
    connect() {}, disconnect() {}
  };
  window.eval(APP_V4);
  window.dispatchEvent(new window.Event("DOMContentLoaded"));
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
  return { window, doc: window.document, sleep, waitFor };
}

test("BROWSER v4: hosted error envelope renders its message, never [object Object] (Phase G)", async () => {
  const { doc, waitFor } = await harness();
  const empty = await waitFor(() => {
    const el = doc.querySelector("#v4-root .empty");
    return el && /Could not load vaults/.test(el.textContent) ? el : null;
  });
  assert.ok(!empty.textContent.includes("[object Object]"),
    `vaults-view failure must not render the raw envelope object — got: ${empty.textContent}`);
  assert.ok(empty.textContent.includes("sign in to use this route"),
    `vaults-view failure must surface the server's message — got: ${empty.textContent}`);
});

test("BROWSER v4: postJSON exposes envelope code + message to notices (Phase G)", async () => {
  const { window, doc, waitFor } = await harness();
  // Drive a postJSON failure through a real UI path: create-organization.
  window.PolicyVaultV4._state.view = "orgs";
  await window.PolicyVaultV4.render();
  const nameInput = await waitFor(() => doc.getElementById("v4-org-new-name"));
  nameInput.value = "Phase G Org";
  const btn = doc.getElementById("v4-org-create-btn");
  btn.dispatchEvent(new window.MouseEvent("click", { bubbles: true, cancelable: true }));
  const notice = await waitFor(() => {
    const el = doc.getElementById("v4-notice");
    return el && /Create organization failed/.test(el.textContent) ? el : null;
  });
  assert.ok(!notice.textContent.includes("[object Object]"),
    `notice must not render the raw envelope object — got: ${notice.textContent}`);
  assert.ok(notice.textContent.includes("too many organizations"),
    `notice must carry the envelope message — got: ${notice.textContent}`);
  assert.ok(notice.textContent.includes("ORG_LIMIT"),
    `notice must carry the envelope code (e.code extraction) — got: ${notice.textContent}`);
});
