"use strict";

/*
 * BROWSER — truthful authority language (TRACK 11 flagship UX pass,
 * finding T1, HIGH).
 *
 * Every covenant generation PolicyVault ships (v0.2 … v0.6) commits
 * EXACTLY ONE on-chain owner key. Nothing in the product said so. Users
 * arriving from custodial products assume a support path, a second owner,
 * or an organizational owner exists — and the Organizations tab looks
 * exactly like the feature that would provide one. Getting this wrong is
 * not a cosmetic problem: it is the difference between backing up the
 * owner wallet before funding a vault and not.
 *
 * These tests pin the statement AND, just as importantly, pin that the
 * product does not overclaim in the other direction: no organizational
 * quorum, no member rotation, no recovery service is promised anywhere.
 * (Those are v0.7 organizational-root work and are NOT built here — see
 * docs/postlaunch/flagship-ux-review.md.)
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const WEB_DIR = path.join(__dirname, "..");
const APP_V4 = fs.readFileSync(path.join(WEB_DIR, "app-v4.js"), "utf8");
const ONBOARDING = fs.readFileSync(path.join(WEB_DIR, "onboarding.js"), "utf8");
const RX = require("../refusal-explain.js");

function loadV4() {
  const elements = new Map();
  const element = (id) => {
    if (!elements.has(id)) {
      elements.set(id, {
        id, innerHTML: "", textContent: "", className: "", value: "", disabled: false,
        style: {}, dataset: {}, onclick: null, listeners: {},
        addEventListener(n, f) { (this.listeners[n] = this.listeners[n] || []).push(f); },
        insertAdjacentHTML() {}, querySelectorAll: () => [], querySelector: () => null,
        classList: { toggle() {}, add() {}, remove() {} }, closest: () => null, focus() {}
      });
    }
    return elements.get(id);
  };
  const sandbox = {
    console,
    document: { getElementById: element, querySelectorAll: () => [], addEventListener() {} },
    localStorage: { getItem: () => null, setItem() {}, removeItem() {} },
    setTimeout: () => 0, clearTimeout() {},
    crypto: { getRandomValues: (a) => a.fill(7) },
    // UX-05: the create view now awaits the durable unresolved-creation listing
    // before rendering; answer it with an empty listing (never-resolving fetch
    // would hang the render). Every other request still gets an empty body.
    fetch: async (u) => ({ ok: true, status: 200, json: async () => (/unresolved=1/.test(String(u)) ? { requests: [] } : {}) }),
    PolicyVaultWalletSession: { active: () => ({ connected: false, ready: false }), subscribe: () => () => {} },
    /* STALE ASSUMPTION (2026-09-05, guided setup): the create view is
     * rendered from the shared setup components over the reviewed core
     * bundle, so the sandbox carries both — exactly as index.html loads them. */
    PolicyVaultCore: require("../core-bundle.js"),
    PolicyVaultSetupUi: require("../setup-ui.js")
  };
  sandbox.listeners = {};
  sandbox.addEventListener = (n, f) => { (sandbox.listeners[n] = sandbox.listeners[n] || []).push(f); };
  sandbox.window = sandbox;
  sandbox.globalThis = sandbox;
  vm.createContext(sandbox);
  vm.runInContext(APP_V4, sandbox, { filename: "app-v4.js" });
  return { element, V4: sandbox.window.PolicyVaultV4 };
}

/* ---------------- the statement is made where the decision is made ------ */

test("Create Vault states that the connected wallet becomes the ONLY owner key", async () => {
  const { element, V4 } = loadV4();
  Object.assign(V4._state, { address: "kaspa:qowner", ready: true, view: "create" });
  await V4.render(); // UX-05: the create view first reads the durable unresolved-creation state (async) before it renders
  const root = element("v4-root").innerHTML;
  assert.match(root, /data-owner-authority="1"/);
  assert.match(root, /becomes the vault's only owner key/i);
  assert.match(root, /no second owner, no owner quorum, and no organizational owner/i);
  assert.match(root, /no master key and offers no custodial recovery/i);
  assert.match(root, /Back this wallet up before funding the vault/i);
});

test("Create Vault says approvers cannot spend and cannot act as the owner", async () => {
  const { element, V4 } = loadV4();
  Object.assign(V4._state, { address: "kaspa:qowner", ready: true, view: "create" });
  await V4.render(); // UX-05: the create view first reads the durable unresolved-creation state (async) before it renders
  const root = element("v4-root").innerHTML;
  assert.match(root, /cannot spend, and they cannot act as the owner/i);
  assert.match(root, /An approver cannot spend vault funds or act as the owner/i, "the existing approver hint is retained");
});

test("Organizations names owner authority explicitly, not just \"covenant authority\"", () => {
  assert.match(APP_V4, /not owner authority, not approver authority, and no recovery path/);
  assert.match(APP_V4, /Each vault still has exactly one on-chain owner key/);
  assert.match(APP_V4, /covenant approvers are set on the vault itself/);
});

/* ---------------- and the product does NOT overclaim -------------------- */

/* Anything that would imply organizational ownership, an owner quorum,
 * member key rotation as an authority change, or a recovery service must
 * not appear as an offered capability of a LEGACY vault or a HOSTED
 * ORGANIZATION — those still have exactly one on-chain owner key and no
 * covenant authority at all, respectively.
 *
 * SCOPE UPDATE (Wave 2, Track B-web, STALE ASSUMPTION): this file's
 * original comment said "v0.7 organizational-root APIs do not exist;
 * promising them here would be a lie with funds attached." That is no
 * longer true — web/org-root-ui.js (Wave 2) implements the v0.7 ON-CHAIN
 * ORGANIZATIONAL ROOT surface for real, and app-v4.js / refusal-explain.js
 * now legitimately carry POSITIVE M-of-N / owner-quorum language describing
 * THAT NEW COVENANT GENERATION. The check below still refuses every one of
 * these phrases when it is NOT inside a denial UNLESS the surrounding text
 * is unambiguously talking about the on-chain organizational root (the
 * words "organizational root" or "on-chain" nearby) — so a claim that a
 * LEGACY vault or a HOSTED ORGANIZATION has owner-quorum/recovery authority
 * still fails here exactly as before; only the genuinely new, real
 * capability is exempted. web/org-root-ui.js itself is covered by its own
 * v0.7-appropriate truthfulness tests (web/test/org-root-ui.test.js), not
 * this pre-v0.7 scan. */
const OVERCLAIM = [
  /organization owner/i,
  /owner quorum/i,
  /M-of-N owner/i,
  /recover(?:y)? (?:your |the )?(?:vault |account )?(?:with|via|through) (?:support|us|PolicyVault)/i,
  /reset (?:your )?owner key/i,
  /(?:we|PolicyVault) can restore/i,
  /account recovery/i
];

for (const src of ["app-v4.js", "app.js", "onboarding.js", "refusal-explain.js", "setup-ui.js"]) {
  test(`${src} promises no organizational ownership, owner quorum, or recovery service outside the real v0.7 on-chain root`, () => {
    const text = fs.readFileSync(path.join(WEB_DIR, src), "utf8");
    for (const re of OVERCLAIM) {
      const hit = re.exec(text);
      if (hit) {
        const around = text.slice(Math.max(0, hit.index - 90), hit.index + hit[0].length + 40);
        const isDenial = /\b(no|never|not|nobody|cannot)\b/i.test(around);
        const isRealV7Root = /organizational root|on-chain/i.test(around);
        assert.ok(isDenial || isRealV7Root, `${src}: "${hit[0]}" must appear only in a denial, or describing the real v0.7 on-chain organizational root — got: ${around}`);
      }
    }
  });
}

test("the onboarding walkthrough's authority claims stay bounded (agents may not obtain owner custody)", () => {
  assert.match(ONBOARDING, /obtain owner custody/, "the may-not list still denies owner custody to an agent");
  assert.match(ONBOARDING, /approvers cannot spend or act as the owner/);
});

test("the refusal table's NOT_OWNER entry agrees with the create-vault statement", () => {
  const e = RX.explain("NOT_OWNER");
  assert.match(e.meaning, /exactly ONE on-chain owner key/);
  // both surfaces must deny organizational owner authority
  assert.match(e.meaning, /grant no owner authority/i);
  assert.match(APP_V4, /grant nobody owner authority/);
});
