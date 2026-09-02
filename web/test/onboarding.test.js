"use strict";

/*
 * BROWSER — first-run walkthrough / Help menu / home entry (web/onboarding.js,
 * adoption UX track). Presentation only; these tests pin the contract that
 * keeps it that way:
 *
 *   1. the four-line authority statement and the wallet-vs-PolicyVault
 *      question are rendered VERBATIM; the flow reads AI / App → PolicyVault
 *      → Covenant → Kaspa in that order;
 *   2. first run shows the walkthrough ONCE (a second boot with the same
 *      storage shows nothing), Skip is visible on step 1 and closes it;
 *   3. "Don't show again" persists and suppresses auto-show — even for a
 *      newer onboarding version — while replay from Help still works;
 *   4. the home entry opens it; keyboard: Escape closes, Tab wraps inside
 *      the dialog, focus returns to the opener; backdrop click closes;
 *   5. storage that THROWS on access: the module still loads, wires, mounts
 *      (showing nothing — it cannot remember, so it never nags), and replay
 *      still works;
 *   6. no functionality gating: the REAL web/app.js boot sequence reaches
 *      the module only via a post-boot `.finally` hook (mount called exactly
 *      once, after boot's reads), an absent module is a no-op, and neither
 *      app.js nor app-v4.js reads onboarding state;
 *   7. no private-key / seed language, no input other than the one
 *      checkbox, no network calls, no wallet/signing globals, no audit
 *      claims — in the module source AND in every rendered step;
 *   8. presentation + accessibility (visual upgrade, owner direction
 *      2026-09-02): every step carries a labelled illustrated figure whose
 *      icons/wires/packets are decorative; the six figures show what the
 *      direction asked for (flow with edge labels, owner → vault with the
 *      custody boundary, rules as chips/meters, the bounded envelope with
 *      may / may-not, accepted-versus-refused gauges, wallet-versus-
 *      PolicyVault + the composition); "Replay animation" is a keyboard
 *      button that re-renders without touching state; no remote asset,
 *      no video/GIF, no colour literal in the module, token-only colours
 *      in the CSS, the broad reduced-motion rule, the narrow-viewport
 *      rule, and the static-state-is-final-state invariant for the
 *      travelling packet.
 *
 * The DOM is a minimal in-file shim (elements, attributes, focus, event
 * bubbling, simple selectors) — enough to drive the module's real code
 * paths; nothing here re-implements the module.
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const WEB_DIR = path.join(__dirname, "..");
const ONBOARDING_SRC = fs.readFileSync(path.join(WEB_DIR, "onboarding.js"), "utf8");
const APP_JS = fs.readFileSync(path.join(WEB_DIR, "app.js"), "utf8");
const APP_V4 = fs.readFileSync(path.join(WEB_DIR, "app-v4.js"), "utf8");
const INDEX_HTML = fs.readFileSync(path.join(WEB_DIR, "index.html"), "utf8");
const Onb = require("../onboarding.js");

/* ---------------- minimal DOM shim ---------------- */

class Evt {
  constructor(type, init) {
    Object.assign(this, { type, key: null, shiftKey: false, target: null, defaultPrevented: false, _stop: false }, init || {});
  }
  preventDefault() { this.defaultPrevented = true; }
  stopPropagation() { this._stop = true; }
}

class El {
  constructor(doc, tag) {
    this.doc = doc;
    this.tagName = String(tag).toUpperCase();
    this.attrs = {};
    this.children = [];
    this.parentNode = null;
    this.listeners = {};
    this.hidden = false;
    this.disabled = false;
    this.checked = false;
    this.style = {};
    this._text = "";
    const self = this;
    this.classList = {
      _set: () => new Set((self.attrs.class || "").split(/\s+/).filter(Boolean)),
      _save: (s) => { self.attrs.class = [...s].join(" "); },
      add(c) { const s = this._set(); s.add(c); this._save(s); },
      remove(c) { const s = this._set(); s.delete(c); this._save(s); },
      contains(c) { return this._set().has(c); },
      toggle(c, force) { const s = this._set(); const on = force === undefined ? !s.has(c) : !!force; on ? s.add(c) : s.delete(c); this._save(s); return on; }
    };
  }
  get id() { return this.attrs.id || ""; }
  set id(v) { this.attrs.id = String(v); }
  get className() { return this.attrs.class || ""; }
  set className(v) { this.attrs.class = String(v); }
  get textContent() { return this._text + this.children.map((c) => c.textContent).join(""); }
  set textContent(v) { this.children.forEach((c) => (c.parentNode = null)); this.children = []; this._text = String(v); }
  setAttribute(k, v) { this.attrs[k] = String(v); }
  getAttribute(k) { return Object.prototype.hasOwnProperty.call(this.attrs, k) ? this.attrs[k] : null; }
  hasAttribute(k) { return Object.prototype.hasOwnProperty.call(this.attrs, k); }
  removeAttribute(k) { delete this.attrs[k]; }
  appendChild(c) {
    if (c.parentNode) c.parentNode.children = c.parentNode.children.filter((x) => x !== c);
    c.parentNode = this;
    this.children.push(c);
    return c;
  }
  contains(n) { for (let x = n; x; x = x.parentNode) if (x === this) return true; return false; }
  focus() { this.doc.activeElement = this; }
  addEventListener(type, fn) { (this.listeners[type] = this.listeners[type] || []).push(fn); }
  removeEventListener(type, fn) { this.listeners[type] = (this.listeners[type] || []).filter((f) => f !== fn); }
  dispatchEvent(ev) {
    if (!ev.target) ev.target = this;
    for (let n = this; n && !ev._stop; n = n.parentNode) for (const fn of (n.listeners[ev.type] || []).slice()) fn(ev);
    if (!ev._stop) for (const fn of (this.doc.listeners[ev.type] || []).slice()) fn(ev);
    return !ev.defaultPrevented;
  }
  click() { return this.dispatchEvent(new Evt("click")); }
  *walk() { for (const c of this.children) { yield c; yield* c.walk(); } }
  matches(sel) {
    const m = /^([a-z0-9]*)(#[\w-]+)?((?:\.[\w-]+)*)((?:\[[^\]]+\])*)$/i.exec(sel.trim());
    if (!m) throw new Error(`shim: unsupported selector ${sel}`);
    if (m[1] && m[1].toUpperCase() !== this.tagName) return false;
    if (m[2] && this.id !== m[2].slice(1)) return false;
    for (const c of (m[3] || "").split(".").filter(Boolean)) if (!this.classList.contains(c)) return false;
    for (const a of (m[4] || "").match(/\[[^\]]+\]/g) || []) {
      const am = /^\[([\w-]+)(=("?)([^"\]]*)\3)?\]$/.exec(a);
      const k = am[1];
      const v = am[2] === undefined ? undefined : am[4];
      if (!this.hasAttribute(k)) return false;
      if (v !== undefined && this.getAttribute(k) !== v) return false;
    }
    return true;
  }
  querySelectorAll(sel) {
    const parts = sel.split(",");
    return [...this.walk()].filter((n) => parts.some((p) => n.matches(p)));
  }
  querySelector(sel) { return this.querySelectorAll(sel)[0] || null; }
}

class Doc {
  constructor() {
    this.listeners = {};
    this.body = new El(this, "body");
    this.activeElement = this.body;
  }
  createElement(tag) { return new El(this, tag); }
  createElementNS(_ns, tag) { return new El(this, tag); }
  getElementById(id) { for (const n of this.body.walk()) if (n.id === id) return n; return null; }
  addEventListener(type, fn) { (this.listeners[type] = this.listeners[type] || []).push(fn); }
  removeEventListener(type, fn) { this.listeners[type] = (this.listeners[type] || []).filter((f) => f !== fn); }
  dispatchEvent(ev) { for (const fn of (this.listeners[ev.type] || []).slice()) fn(ev); return !ev.defaultPrevented; }
}

/* The static markup web/index.html ships (ids only — what the module wires). */
function pageFixture(doc) {
  const add = (parent, tag, attrs) => { const n = doc.createElement(tag); for (const k of Object.keys(attrs || {})) { if (k === "hidden") n.hidden = true; else n.setAttribute(k, attrs[k]); } parent.appendChild(n); return n; };
  const header = add(doc.body, "header");
  add(header, "button", { id: "pv-help-btn", "aria-expanded": "false" });
  const menu = add(header, "div", { id: "pv-help-menu", hidden: true });
  add(menu, "button", { id: "pv-help-replay" });
  add(menu, "a", { href: "https://docs.policy-vault.org" });
  add(header, "a", { class: "btnlink", href: "https://docs.policy-vault.org" });
  const main = add(doc.body, "main");
  add(main, "button", { id: "btn-connect-kasware" });
  const home = add(main, "div", { id: "pv-onb-home" });
  add(home, "button", { id: "pv-onb-home-btn" });
  add(main, "div", { id: "v4-root" });
  add(doc.body, "div", { id: "pv-onboarding", hidden: true });
}

function memoryStorage(seed) {
  const m = new Map(Object.entries(seed || {}));
  return { getItem: (k) => (m.has(k) ? m.get(k) : null), setItem: (k, v) => { m.set(k, String(v)); }, removeItem: (k) => { m.delete(k); }, _map: m };
}

function env({ storage, throwingStorage, version } = {}) {
  const document = new Doc();
  pageFixture(document);
  const win = { document };
  if (throwingStorage) Object.defineProperty(win, "localStorage", { get() { throw new Error("SecurityError: storage disabled"); } });
  else win.localStorage = storage || memoryStorage();
  const ctl = Onb.create({ window: win, document, ...(version ? { onboardingVersion: version } : {}) });
  ctl.wire();
  const $ = (id) => document.getElementById(id);
  const container = $("pv-onboarding");
  const card = () => container.children[0];
  const btn = (cls) => card().querySelector(`button.${cls}`);
  const record = () => (throwingStorage ? null : Onb.parseRecord(win.localStorage.getItem(Onb.STORAGE_KEY)));
  const key = (k, init) => document.dispatchEvent(new Evt("keydown", { key: k, ...(init || {}) }));
  return { document, win, ctl, $, container, card, btn, record, key };
}

/* ---------------- 1. content: verbatim message, flow, questions ---------------- */

test("the four-line authority statement is exported verbatim and rendered verbatim, in order, on step 1", () => {
  assert.deepEqual([...Onb.CORE_MESSAGE], ["AI MAY REQUEST.", "POLICYVAULT DETERMINISTICALLY DECIDES.", "THE COVENANT ENFORCES.", "SIGNERS RETAIN CUSTODY."]);
  const e = env();
  assert.equal(e.ctl.replay(), true);
  const lines = e.card().querySelectorAll(".pv-onb-core-line").map((n) => n.textContent);
  assert.deepEqual(lines, [...Onb.CORE_MESSAGE]);
  // Also present in the module source as literal strings (never assembled from fragments).
  for (const line of Onb.CORE_MESSAGE) assert.ok(ONBOARDING_SRC.includes(`"${line}"`), `verbatim literal missing: ${line}`);
});

test("step 1 explains the flow AI / App → PolicyVault → Covenant → Kaspa in that order with the edge labels request / authorized transaction / enforcement; step 6 carries the wallet-vs-PolicyVault question verbatim", () => {
  const e = env();
  e.ctl.replay();
  const stages = e.card().querySelectorAll(".pv-onb-stage-name").map((n) => n.textContent);
  assert.deepEqual(stages, ["AI / App", "PolicyVault", "Covenant", "Kaspa"]);
  assert.deepEqual(e.card().querySelectorAll(".pv-onb-stage-role").map((n) => n.textContent), ["requests a spend", "decides: authorized or refused", "enforces the rules on-chain", "consensus rejects anything outside them"]);
  assert.equal(e.card().querySelectorAll(".pv-onb-arrow").length, 3);
  assert.deepEqual(e.card().querySelectorAll(".pv-onb-arrow-label").map((n) => n.textContent), ["request", "authorized transaction", "enforcement"]);
  const text = e.card().textContent;
  assert.ok(text.includes("PolicyVault is not a wallet"), "must say plainly that PolicyVault is not a wallet");
  assert.ok(text.includes("never holds your funds"), "must never imply custody");
  assert.ok(text.includes("it never signs for you"), "must never imply that PolicyVault signs");
  e.ctl.goTo(Onb.STEPS.length - 1);
  const last = e.card().textContent;
  assert.ok(last.includes('A wallet asks: "Can this key sign?"'));
  assert.ok(last.includes('PolicyVault asks: "Is this action authorized?"'));
  assert.ok(last.includes("never holds your funds"));
});

test("the walkthrough covers the six required steps in order and the last step shows accepted, refused, and needs-approval examples", () => {
  assert.deepEqual(Onb.STEPS.map((s) => s.id), ["flow", "create", "rules", "delegate", "examples", "distinction"]);
  const e = env();
  e.ctl.replay();
  const titles = [];
  for (let i = 0; i < Onb.STEPS.length; i++) {
    titles.push(e.card().querySelector(".pv-onb-title").textContent);
    assert.equal(e.card().querySelector(".pv-onb-progress").textContent, `Step ${i + 1} of ${Onb.STEPS.length}`);
    assert.equal(e.btn("pv-onb-back").disabled, i === 0, "Back is disabled only on step 1");
    assert.equal(e.btn("pv-onb-next").textContent, i === Onb.STEPS.length - 1 ? "Finish" : "Next");
    assert.equal(e.btn("pv-onb-skip").hidden, false, "Skip is visible on every step");
    if (i < Onb.STEPS.length - 1) e.btn("pv-onb-next").click();
  }
  assert.deepEqual(titles, ["What PolicyVault is", "Create and control a vault", "Set bounded rules", "Delegate bounded authority", "Accepted versus refused", "A wallet versus PolicyVault"]);
  e.ctl.goTo(4);
  const verdicts = e.card().querySelectorAll(".pv-onb-verdict").map((n) => n.textContent);
  assert.deepEqual(verdicts, ["ACCEPTED", "REFUSED", "REFUSED", "NEEDS APPROVAL"]);
  const examples = e.card().textContent;
  assert.ok(examples.includes("even a correctly signed 8 KAS transaction would be rejected by Kaspa consensus"));
  assert.ok(examples.includes("free to use, including commercial use"));
  assert.ok(examples.includes("PolicyVault itself never signs"));
});

/* ---------------- 2. first run once; Skip on step 1 ---------------- */

test("first run: mountAfterBoot shows the walkthrough once; the same storage on a second boot shows nothing", () => {
  const storage = memoryStorage();
  const e = env({ storage });
  assert.equal(e.ctl.shouldAutoShow(), true);
  assert.equal(e.container.hidden, true, "hidden before mount");
  assert.equal(e.ctl.mountAfterBoot(), true);
  assert.equal(e.container.hidden, false);
  assert.equal(e.ctl.reason(), "first-run");
  const card = e.card();
  assert.equal(card.getAttribute("role"), "dialog");
  assert.equal(card.getAttribute("aria-modal"), "true");
  assert.equal(card.getAttribute("aria-labelledby"), "pv-onb-title");
  assert.equal(card.querySelector("#pv-onb-title").textContent, "What PolicyVault is");
  assert.equal(e.btn("pv-onb-skip").textContent, "Skip");
  assert.deepEqual(e.record(), { onboardingVersion: Onb.ONBOARDING_VERSION, completed: false, dontShowAgain: false }, "seen-for-this-version is persisted on show");
  assert.equal(e.ctl.mountAfterBoot(), false, "idempotent within one boot");
  // "Reload": a fresh controller over the SAME storage.
  const e2 = env({ storage });
  assert.equal(e2.ctl.shouldAutoShow(), false);
  assert.equal(e2.ctl.mountAfterBoot(), false);
  assert.equal(e2.container.hidden, true);
});

test("Skip on step 1 closes the walkthrough, keeps the seen record, and the app stays fully interactive", () => {
  const e = env();
  let connectClicks = 0;
  e.$("btn-connect-kasware").addEventListener("click", () => connectClicks++);
  e.ctl.mountAfterBoot();
  assert.equal(e.ctl.step(), 0);
  e.btn("pv-onb-skip").click();
  assert.equal(e.container.hidden, true);
  assert.equal(e.ctl.isOpen(), false);
  assert.equal(e.ctl.lastClose(), "skip");
  assert.deepEqual(e.record(), { onboardingVersion: 1, completed: false, dontShowAgain: false });
  e.$("btn-connect-kasware").click();
  assert.equal(connectClicks, 1, "unrelated app controls are untouched by the walkthrough");
  // The ✕ button closes too.
  e.ctl.replay();
  e.btn("pv-onb-close").click();
  assert.equal(e.ctl.lastClose(), "close");
});

test("Finish on the last step records completed:true", () => {
  const e = env();
  e.ctl.mountAfterBoot();
  for (let i = 0; i < Onb.STEPS.length - 1; i++) e.ctl.next();
  assert.equal(e.btn("pv-onb-next").textContent, "Finish");
  e.btn("pv-onb-next").click();
  assert.equal(e.ctl.isOpen(), false);
  assert.deepEqual(e.record(), { onboardingVersion: 1, completed: true, dontShowAgain: false });
});

/* ---------------- 3. Don't show again + replay ---------------- */

test("Don't show again persists immediately and suppresses auto-show — even for a newer onboarding version", () => {
  const storage = memoryStorage();
  const e = env({ storage });
  e.ctl.mountAfterBoot();
  const box = e.card().querySelector("#pv-onb-dsa");
  assert.equal(box.getAttribute("type"), "checkbox");
  box.checked = true;
  box.dispatchEvent(new Evt("change"));
  assert.equal(e.record().dontShowAgain, true);
  e.btn("pv-onb-skip").click();
  assert.equal(env({ storage }).ctl.shouldAutoShow(), false);
  // A FUTURE content version (the module's version override exists only for
  // this proof): "Don't show again" still suppresses...
  const bumped = Onb.ONBOARDING_VERSION + 1;
  assert.equal(env({ storage, version: bumped }).ctl.shouldAutoShow(), false);
  // ...whereas a user who merely SAW (even completed) the older version is
  // shown the updated content once more — and the record is bumped.
  const olderSeen = memoryStorage({ [Onb.STORAGE_KEY]: JSON.stringify({ onboardingVersion: Onb.ONBOARDING_VERSION, completed: true, dontShowAgain: false }) });
  const eb = env({ storage: olderSeen, version: bumped });
  assert.equal(eb.ctl.shouldAutoShow(), true);
  assert.equal(eb.ctl.mountAfterBoot(), true);
  assert.equal(eb.record().onboardingVersion, bumped);
  assert.equal(env({ storage: olderSeen, version: bumped }).ctl.shouldAutoShow(), false, "shown once for the new version");
  // The browser never runs an overridden version: an invalid override falls back to the constant.
  assert.equal(env({ storage: memoryStorage(), version: 0 }).ctl.mountAfterBoot(), true);
  // Unchecking persists too.
  const e3 = env({ storage });
  e3.ctl.replay();
  const box3 = e3.card().querySelector("#pv-onb-dsa");
  assert.equal(box3.checked, true, "the checkbox reflects the stored choice");
  box3.checked = false;
  box3.dispatchEvent(new Evt("change"));
  assert.equal(e3.record().dontShowAgain, false);
});

test("replay from the Help menu works after Don't show again, and the menu closes; the stored choice is untouched", () => {
  const storage = memoryStorage({ [Onb.STORAGE_KEY]: JSON.stringify({ onboardingVersion: 1, completed: false, dontShowAgain: true }) });
  const e = env({ storage });
  assert.equal(e.ctl.mountAfterBoot(), false, "suppressed on boot");
  const helpBtn = e.$("pv-help-btn");
  const menu = e.$("pv-help-menu");
  assert.equal(menu.hidden, true);
  helpBtn.click();
  assert.equal(menu.hidden, false);
  assert.equal(helpBtn.getAttribute("aria-expanded"), "true");
  e.$("pv-help-replay").click();
  assert.equal(e.ctl.isOpen(), true);
  assert.equal(e.ctl.reason(), "replay");
  assert.equal(menu.hidden, true, "the menu closes when the walkthrough opens");
  assert.equal(helpBtn.getAttribute("aria-expanded"), "false");
  assert.deepEqual(e.record(), { onboardingVersion: 1, completed: false, dontShowAgain: true });
  // Menu: Escape closes it (when the walkthrough is not open); an outside click closes it.
  e.ctl.close();
  helpBtn.click();
  e.key("Escape");
  assert.equal(menu.hidden, true);
  helpBtn.click();
  assert.equal(menu.hidden, false);
  e.$("btn-connect-kasware").click();
  assert.equal(menu.hidden, true);
});

test("the persistent home entry opens the walkthrough; storage suppression never hides the entry", () => {
  const storage = memoryStorage({ [Onb.STORAGE_KEY]: JSON.stringify({ onboardingVersion: 1, completed: true, dontShowAgain: true }) });
  const e = env({ storage });
  e.ctl.mountAfterBoot();
  assert.equal(e.$("pv-onb-home").hidden, false);
  e.$("pv-onb-home-btn").click();
  assert.equal(e.ctl.isOpen(), true);
  assert.equal(e.ctl.reason(), "home");
});

/* ---------------- 4. keyboard, focus, backdrop ---------------- */

test("keyboard: Escape closes and focus returns to the opener; Tab wraps within the dialog; focus lands on the step title", () => {
  const e = env();
  const home = e.$("pv-onb-home-btn");
  home.focus();
  home.click();
  assert.equal(e.document.activeElement, e.card().querySelector("#pv-onb-title"), "focus moves to the title on open");
  const focusables = e.card().querySelectorAll("button, a[href], input, select, textarea, [tabindex]").filter((n) => !n.disabled && n.getAttribute("tabindex") !== "-1");
  const first = focusables[0];
  const last = focusables[focusables.length - 1];
  last.focus();
  const tab = new Evt("keydown", { key: "Tab" });
  e.document.dispatchEvent(tab);
  assert.equal(e.document.activeElement, first, "Tab from the last focusable wraps to the first");
  assert.equal(tab.defaultPrevented, true);
  const shiftTab = new Evt("keydown", { key: "Tab", shiftKey: true });
  e.document.dispatchEvent(shiftTab);
  assert.equal(e.document.activeElement, last, "Shift+Tab from the first wraps to the last");
  e.key("Escape");
  assert.equal(e.ctl.isOpen(), false);
  assert.equal(e.ctl.lastClose(), "escape");
  assert.equal(e.document.activeElement, home, "focus is restored to the opener");
  // Closed: Escape is inert (the listener is detached, nothing throws).
  e.key("Escape");
  assert.equal(e.ctl.isOpen(), false);
});

test("backdrop click closes; a click inside the card does not", () => {
  const e = env();
  e.ctl.replay();
  e.card().querySelector(".pv-onb-body").dispatchEvent(new Evt("click"));
  assert.equal(e.ctl.isOpen(), true);
  e.container.dispatchEvent(new Evt("click"));
  assert.equal(e.ctl.isOpen(), false);
  assert.equal(e.ctl.lastClose(), "backdrop");
});

/* ---------------- 5. storage unavailable ---------------- */

test("storage that throws on access: create/wire/mount never throw, nothing auto-shows (cannot remember = never nag), replay and the checkbox still work", () => {
  const e = env({ throwingStorage: true });
  assert.equal(e.ctl.shouldAutoShow(), false);
  assert.equal(e.ctl.mountAfterBoot(), false);
  assert.equal(e.container.hidden, true);
  assert.equal(e.ctl.readRecord(), null);
  assert.equal(e.ctl.replay(), true);
  const box = e.card().querySelector("#pv-onb-dsa");
  box.checked = true;
  box.dispatchEvent(new Evt("change")); // write fails silently
  e.ctl.finish(); // write fails silently, dialog still closes
  assert.equal(e.ctl.isOpen(), false);
});

test("browser bootstrap: evaluating the module with a window exposes a wired PolicyVaultOnboarding — even when storage throws — exactly as app.js's hook expects", () => {
  const document = new Doc();
  pageFixture(document);
  const win = { document };
  Object.defineProperty(win, "localStorage", { get() { throw new Error("SecurityError: storage disabled"); } });
  const sandbox = { window: win, document, console };
  vm.createContext(sandbox);
  vm.runInContext(ONBOARDING_SRC, sandbox, { filename: "web/onboarding.js" });
  const api = win.PolicyVaultOnboarding;
  assert.ok(api && typeof api.mountAfterBoot === "function", "window.PolicyVaultOnboarding.mountAfterBoot is what app.js calls");
  assert.equal(api.mountAfterBoot(), false, "storage unavailable: nothing auto-shows");
  document.getElementById("pv-onb-home-btn").click();
  assert.equal(api.isOpen(), true, "the home entry was wired at load");
  assert.deepEqual([...api.CORE_MESSAGE], [...Onb.CORE_MESSAGE]);
});

test("malformed or foreign stored values are treated as absent (never throw, never trusted)", () => {
  for (const raw of ["", "not json", "42", "null", "[]", JSON.stringify({ completed: true }), JSON.stringify({ onboardingVersion: "1" }), JSON.stringify({ onboardingVersion: 0 })]) {
    assert.equal(Onb.parseRecord(raw), null, `raw=${raw}`);
  }
  assert.deepEqual(Onb.parseRecord(JSON.stringify({ onboardingVersion: 3, completed: "yes", dontShowAgain: 1, extra: "x" })), { onboardingVersion: 3, completed: false, dontShowAgain: false });
  const e = env({ storage: memoryStorage({ [Onb.STORAGE_KEY]: "{broken" }) });
  assert.equal(e.ctl.mountAfterBoot(), true, "unparseable = first run");
});

/* ---------------- 6. no functionality gating ---------------- */

test("static: app.js reaches the module ONLY through a post-boot .finally hook that passes boot's outcome through; app.js / app-v4.js never read onboarding state", () => {
  assert.ok(APP_JS.includes("boot().finally(() => { try { window.PolicyVaultOnboarding?.mountAfterBoot?.(); } catch (_) { /* presentation only */ } });"));
  assert.equal((APP_JS.match(/PolicyVaultOnboarding/g) || []).length, 1, "exactly one reference in app.js");
  assert.equal((APP_V4.match(/PolicyVaultOnboarding/g) || []).length, 0, "app-v4.js is untouched");
  for (const src of [APP_JS, APP_V4]) assert.ok(!src.includes(Onb.STORAGE_KEY), "the app never reads pv.onboarding");
  assert.ok(!APP_JS.includes("await boot()"), "boot is never awaited on the walkthrough");
});

test("REAL app.js boot: the mount hook fires exactly once, only after boot has settled, and an absent module is a silent no-op", async () => {
  const run = async (withModule) => {
    const calls = [];
    const events = [];
    const elements = new Map();
    const element = (id) => {
      if (!elements.has(id)) elements.set(id, { id, innerHTML: "", textContent: "", className: "", value: "", disabled: false, style: {}, dataset: {}, options: [], onclick: null, addEventListener() {}, querySelectorAll: () => [], querySelector: () => null, classList: { toggle() {}, add() {}, remove() {} } });
      return elements.get(id);
    };
    const json = (body, ok = true) => ({ ok, status: ok ? 200 : 503, json: async () => body });
    const route = (p) => {
      calls.push(p);
      events.push("fetch:" + p);
      if (p.endsWith("/health")) return json({ ok: true, networkId: "mainnet", authMode: "disabled" });
      if (p.endsWith("/network/status")) return json({ ok: true, networkId: "mainnet", synced: true });
      if (p.endsWith("/organizations")) return json({ organizations: [], roleLabels: [], assignments: {}, assignmentsVersion: 0 });
      if (p.endsWith("/vaults")) return json({ vaults: [] });
      if (p.endsWith("/wallet/dev-accounts")) return json({}, false);
      return Promise.reject(new Error(`unrouted: ${p}`));
    };
    const sandbox = {
      console,
      document: { getElementById: element, querySelectorAll: () => [], addEventListener() {} },
      localStorage: { getItem: () => null, setItem() {}, removeItem() {} },
      setTimeout: () => 0,
      clearTimeout() {},
      fetch: (url) => Promise.resolve().then(() => route(String(url))),
      PolicyVaultWallet: require("../wallet.js"),
      PolicyVaultIdentity: {}
    };
    if (withModule) sandbox.PolicyVaultOnboarding = { mountAfterBoot() { events.push("mount"); return false; } };
    sandbox.window = sandbox;
    sandbox.globalThis = sandbox;
    vm.createContext(sandbox);
    vm.runInContext(APP_JS, sandbox, { filename: "web/app.js" });
    for (let i = 0; i < 60; i++) await new Promise((r) => setImmediate(r));
    return { calls, events };
  };
  const withModule = await run(true);
  assert.equal(withModule.events.filter((e) => e === "mount").length, 1, "mounted exactly once");
  assert.equal(withModule.events[withModule.events.length - 1], "mount", "mount is the LAST event — after every boot read was issued");
  assert.ok(withModule.calls.some((c) => c.endsWith("/network/status")) && withModule.calls.some((c) => c.endsWith("/vaults")), "boot's reads ran unchanged");
  const without = await run(false);
  assert.deepEqual(without.calls, withModule.calls, "the walkthrough adds no request and changes no boot read");
  assert.ok(!without.events.includes("mount"));
});

test("static: index.html ships the Help menu, the persistent home entry, a hidden dialog container, onboarding.js as the LAST script, and the reduced-motion rule", () => {
  assert.ok(INDEX_HTML.includes('<button id="pv-help-btn" type="button" aria-haspopup="true" aria-expanded="false" aria-controls="pv-help-menu">Help</button>'));
  assert.ok(INDEX_HTML.includes('<div id="pv-help-menu" hidden aria-label="Help">'));
  assert.ok(INDEX_HTML.includes('<button id="pv-help-replay" type="button">How PolicyVault works'));
  assert.ok(INDEX_HTML.includes('<div id="pv-onb-home" class="panel">'));
  assert.ok(INDEX_HTML.includes('<button id="pv-onb-home-btn" type="button">How PolicyVault works</button>'));
  assert.ok(INDEX_HTML.includes("AI / App → PolicyVault → Covenant → Kaspa"));
  assert.ok(INDEX_HTML.includes('<div id="pv-onboarding" hidden></div>'));
  assert.ok(INDEX_HTML.includes("#pv-onboarding[hidden] { display: none; }"), "hidden must beat the flex display");
  const scripts = INDEX_HTML.match(/<script src="[^"]+"><\/script>/g);
  assert.equal(scripts[scripts.length - 1], '<script src="/onboarding.js"></script>');
  assert.ok(/@media \(prefers-reduced-motion: reduce\) \{ \.pv-onb-card, \.pv-onb-card \* \{ animation: none !important; transition: none !important; \} \.pv-onb-art-replay \{ display: none !important; \} \}/.test(INDEX_HTML), "reduced motion disables EVERY walkthrough animation and hides the replay control");
  // CSP (script-src 'self'): no inline handlers anywhere in the markup.
  assert.ok(!/\son(click|load|keydown|change)=/.test(INDEX_HTML), "no inline event handlers");
  // The header Docs anchor is byte-identical to what app-v4-gate.test.js pins.
  assert.ok(INDEX_HTML.includes('<a class="btnlink" href="https://docs.policy-vault.org" target="_blank" rel="noopener noreferrer">Docs</a>'));
});

/* ---------------- 7. no keys, no inputs, no network, no audit claims ---------------- */

test("the module carries no private-key / seed language, no wallet/signing/network globals, no fetch, and no audit claims", () => {
  assert.ok(!/seed|mnemonic|private key|privkey|passphrase|secret/i.test(ONBOARDING_SRC), "no key/seed language");
  assert.ok(!/fetch\(|XMLHttpRequest|WebSocket|\/api\/|navigator\./.test(ONBOARDING_SRC), "no network access");
  // (KasWare is NAMED in the copy — "signed inside your own wallet (KasWare)" — but the provider global is never touched.)
  assert.ok(!/PolicyVaultWalletSession|PolicyVaultVerifyIntent|PolicyVaultV4|window\.kasware|signInputs|signPskt|submitTransaction/.test(ONBOARDING_SRC), "no wallet / signing / submission globals");
  assert.ok(!/audit|externally reviewed|professionally reviewed/i.test(ONBOARDING_SRC), "no audit claims");
  assert.ok(!/subscription|premium|paid|upgrade to/i.test(ONBOARDING_SRC), "no paid-tier language");
  assert.ok(/non-custodial/.test(ONBOARDING_SRC));
});

test("every rendered step has exactly one input (the Don't-show-again checkbox), no textarea, and only new-tab docs links with rel=noopener noreferrer", () => {
  const e = env();
  e.ctl.replay();
  for (let i = 0; i < Onb.STEPS.length; i++) {
    const inputs = e.card().querySelectorAll("input, textarea, select");
    assert.equal(inputs.length, 1, `step ${i + 1}: one input`);
    assert.equal(inputs[0].getAttribute("type"), "checkbox");
    assert.equal(inputs[0].id, "pv-onb-dsa");
    for (const a of e.card().querySelectorAll("a")) {
      assert.ok(a.getAttribute("href").startsWith(Onb.DOCS_BASE + "/"), `step ${i + 1}: link must target the docs site`);
      assert.equal(a.getAttribute("target"), "_blank");
      assert.equal(a.getAttribute("rel"), "noopener noreferrer");
    }
    assert.ok(!/seed|mnemonic|private key|secret/i.test(e.card().textContent), `step ${i + 1}: no key/seed language`);
    if (i < Onb.STEPS.length - 1) e.ctl.next();
  }
});

/* ---------------- 8. presentation + accessibility (visual upgrade) ---------------- */

const ONB_CSS = (() => {
  const start = INDEX_HTML.indexOf("/* ---- Adoption UX:");
  const end = INDEX_HTML.indexOf("</style>", start);
  assert.ok(start > 0 && end > start, "the walkthrough CSS block is present in index.html");
  return INDEX_HTML.slice(start, end);
})();

function allSvgs(node) { return node.querySelectorAll("svg"); }

test("every step renders a labelled figure (role=group + non-empty aria-label); every inline SVG is decorative (aria-hidden, not focusable, currentColor); wires/packets/probes are aria-hidden", () => {
  const e = env();
  e.ctl.replay();
  for (let i = 0; i < Onb.STEPS.length; i++) {
    const figs = e.card().querySelectorAll(".pv-onb-fig");
    assert.ok(figs.length >= 1, `step ${i + 1}: at least one figure`);
    for (const f of figs) {
      assert.equal(f.getAttribute("role"), "group");
      assert.ok((f.getAttribute("aria-label") || "").length > 40, `step ${i + 1}: the figure carries a real text alternative`);
    }
    for (const s of allSvgs(e.card())) {
      assert.equal(s.getAttribute("aria-hidden"), "true");
      assert.equal(s.getAttribute("focusable"), "false");
      assert.equal(s.getAttribute("stroke"), "currentColor");
      assert.equal(s.getAttribute("fill"), "none");
      assert.ok(s.querySelectorAll("path").length >= 1);
    }
    for (const sel of [".pv-onb-wire", ".pv-onb-packet", ".pv-onb-link-packet", ".pv-onb-probe", ".pv-onb-node", ".pv-onb-arrow-head", ".pv-onb-meter-track", ".pv-onb-custody-line"]) {
      for (const n of e.card().querySelectorAll(sel)) assert.equal(n.getAttribute("aria-hidden"), "true", `${sel} is decorative`);
    }
    assert.equal(e.card().querySelectorAll("img, video, iframe, object, embed, canvas").length, 0, `step ${i + 1}: no media element`);
    if (i < Onb.STEPS.length - 1) e.ctl.next();
  }
});

test("step 1 (system flow): one packet on one wire, four lit stages with icons, the three edge labels, and the authority statement beneath — in the owner's order", () => {
  const e = env();
  e.ctl.replay();
  const body = e.card().querySelector(".pv-onb-body");
  assert.equal(body.getAttribute("data-step"), "flow");
  assert.equal(body.querySelectorAll(".pv-onb-packet").length, 1);
  assert.equal(body.querySelectorAll(".pv-onb-wire").length, 1);
  const stages = body.querySelectorAll(".pv-onb-stage");
  assert.equal(stages.length, 4);
  stages.forEach((s, i) => {
    assert.ok(s.classList.contains(`pv-onb-seq-${i + 1}`), "stages light in sequence");
    assert.equal(s.querySelector(".pv-onb-node").querySelectorAll("svg").length, 1, "each layer has an icon");
  });
  // Figure first, then the four-line statement: the picture explains, the statement anchors.
  const kids = body.children.map((n) => n.className.split(" ")[0]);
  assert.deepEqual(kids.slice(0, 2), ["pv-onb-art", "pv-onb-core"]);
  assert.deepEqual(body.querySelectorAll(".pv-onb-core-line").map((n) => n.textContent), [...Onb.CORE_MESSAGE]);
});

test("step 2 (create / control): OWNER → POLICYVAULT VAULT with a signed transaction dropping down the wire, and the custody boundary strip keeps keys, signing and custody in the wallet", () => {
  const e = env();
  e.ctl.replay();
  e.ctl.goTo(1);
  const body = e.card().querySelector(".pv-onb-body");
  assert.equal(body.getAttribute("data-step"), "create");
  assert.deepEqual(body.querySelectorAll(".pv-onb-box-title").map((n) => n.textContent), ["OWNER", "POLICYVAULT VAULT"]);
  assert.equal(body.querySelectorAll(".pv-onb-link-packet").length, 1);
  assert.equal(body.querySelector(".pv-onb-link-packet-text").textContent, "signed transaction");
  assert.ok(body.querySelector(".pv-onb-box-owner").textContent.includes("keys stay here"));
  const custody = body.querySelector(".pv-onb-custody");
  assert.ok(custody, "custody boundary strip present");
  assert.ok(custody.textContent.includes("custody boundary"));
  assert.ok(custody.textContent.includes("keys · signing · custody"));
  assert.ok(custody.textContent.includes("never signs · never holds keys"));
  assert.deepEqual(body.querySelector(".pv-onb-box-vault").querySelectorAll(".pv-onb-chip").map((n) => n.textContent), ["policy", "principal", "fee reserve"]);
});

test("step 3 (rules): chips + meters instead of paragraphs — the four rule chips verbatim, a cap meter with an allowed and an over-cap segment, a budget meter, recipient chips, and 2-of-3 approvers", () => {
  const e = env();
  e.ctl.replay();
  e.ctl.goTo(2);
  const body = e.card().querySelector(".pv-onb-body");
  assert.equal(body.getAttribute("data-step"), "rules");
  assert.deepEqual(body.querySelectorAll(".pv-onb-chip.rule").map((n) => n.textContent), ["Per spend ≤ 5 KAS", "Daily budget ≤ 25 KAS", "Approved recipients only", "Approval above 3 KAS"]);
  assert.equal(body.querySelector(".pv-onb-fig").querySelectorAll("p, ul, li").length, 0, "no paragraphs or bullet lists inside the rules figure");
  const rules = body.querySelectorAll(".pv-onb-rule");
  assert.equal(rules.length, 4);
  const capFills = rules[0].querySelectorAll(".pv-onb-meter-fill");
  assert.deepEqual(capFills.map((n) => [n.className, n.getAttribute("style")]), [["pv-onb-meter-fill ok", "left:0%;width:50%"], ["pv-onb-meter-fill over", "left:50%;width:50%"]]);
  assert.equal(rules[0].querySelector(".pv-onb-meter-tag").textContent, "cap 5 KAS");
  assert.deepEqual(rules[1].querySelectorAll(".pv-onb-meter-fill").map((n) => n.getAttribute("style")), ["left:0%;width:36%"]);
  assert.equal(rules[1].querySelector(".pv-onb-meter-tag").textContent, "9 KAS used today");
  assert.ok(rules[1].textContent.includes("DAA score"), "period time is consensus time");
  assert.deepEqual(rules[2].querySelectorAll(".pv-onb-chip").map((n) => n.textContent).slice(1), ["recipient A ✓", "recipient B ✓", "anyone else ✕"]);
  const approvers = rules[3].querySelectorAll(".pv-onb-approver");
  assert.equal(approvers.length, 3);
  assert.equal(approvers.filter((n) => n.classList.contains("on")).length, 2);
  assert.ok(rules[3].textContent.includes("approvers cannot spend or act as the owner"));
});

test("step 4 (bounded delegation): OWNER → AGENT inside a policy envelope; what the agent MAY do sits inside it, what it MAY NOT do sits outside it, verbatim", () => {
  const e = env();
  e.ctl.replay();
  e.ctl.goTo(3);
  const body = e.card().querySelector(".pv-onb-body");
  assert.equal(body.getAttribute("data-step"), "delegate");
  assert.deepEqual(body.querySelectorAll(".pv-onb-box-title").map((n) => n.textContent), ["OWNER", "AGENT"]);
  assert.equal(body.querySelector(".pv-onb-link-packet-text").textContent, "bounded authority");
  const env_ = body.querySelector(".pv-onb-envelope");
  assert.ok(env_, "envelope present");
  assert.equal(env_.querySelector(".pv-onb-env-tag").textContent, "policy envelope");
  assert.ok(env_.contains(body.querySelector(".pv-onb-box-agent")), "the agent sits INSIDE the envelope");
  assert.deepEqual(env_.querySelector(".pv-onb-may").querySelectorAll("li").map((n) => n.textContent), ["✓ request or spend within policy"]);
  assert.equal(env_.querySelectorAll(".pv-onb-probe").length, 1, "the probe that hits the envelope wall");
  const mayNot = body.querySelector(".pv-onb-maynot");
  assert.ok(!env_.contains(mayNot), "the may-not list sits OUTSIDE the envelope");
  assert.deepEqual(mayNot.querySelectorAll("li").map((n) => n.textContent), ["✕ exceed the cap", "✕ exceed the budget", "✕ expand the policy", "✕ obtain owner custody"]);
  assert.ok(body.textContent.includes("not shared keys"));
});

test("step 5 (accepted versus refused): four request cards in verdict order with gauges against the cap — 2 KAS accepted, 8 KAS refused with a hatched over-cap segment, 1 KAS to an unlisted address refused, 4 KAS needs approval — and PolicyVault never signs", () => {
  const e = env();
  e.ctl.replay();
  e.ctl.goTo(4);
  const body = e.card().querySelector(".pv-onb-body");
  assert.equal(body.getAttribute("data-step"), "examples");
  const cards = body.querySelectorAll(".pv-onb-example");
  assert.equal(cards.length, 4);
  const expect = [
    { verdict: "ACCEPTED", cls: "ok", fills: ["left:0%;width:20%"], title: "Agent requests 2 KAS to recipient A" },
    { verdict: "REFUSED", cls: "bad", fills: ["left:0%;width:50%", "left:50%;width:30%"], title: "Agent requests 8 KAS to recipient A" },
    { verdict: "REFUSED", cls: "bad", fills: ["left:0%;width:10%"], title: "Agent requests 1 KAS to an address not on the list" },
    { verdict: "NEEDS APPROVAL", cls: "warn", fills: ["left:0%;width:40%"], title: "Agent requests 4 KAS to recipient B" }
  ];
  cards.forEach((c, i) => {
    const x = expect[i];
    assert.ok(c.classList.contains(x.cls) && c.classList.contains(`pv-onb-seq-${i + 1}`));
    assert.equal(c.querySelector(".pv-onb-verdict").textContent, x.verdict);
    assert.equal(c.querySelector(".pv-onb-example-title").textContent, x.title);
    assert.deepEqual(c.querySelectorAll(".pv-onb-meter-fill").map((n) => n.getAttribute("style")), x.fills);
    assert.deepEqual(c.querySelectorAll(".pv-onb-meter-tag").map((n) => n.textContent), ["approval > 3 KAS", "cap 5 KAS"]);
    assert.ok(c.querySelectorAll(".pv-onb-chip.fact").length >= 2, "each card states its facts as chips");
  });
  assert.ok(cards[1].querySelector(".pv-onb-meter-fill.over"), "the over-cap portion is drawn as a distinct segment");
  assert.ok(cards[0].textContent.includes("PolicyVault never signs"));
  assert.ok(cards[2].querySelectorAll(".pv-onb-chip.fact.bad").map((n) => n.textContent).includes("✕ recipient not approved"));
  assert.ok(cards[3].querySelectorAll(".pv-onb-chip.fact.warn").length === 1);
  assert.ok(body.textContent.includes("fails closed"));
});

test("step 6 (key distinction): wallet 'Can this key sign?' versus PolicyVault 'Is this action authorized?', then policy + external signer + Kaspa covenant enforcement", () => {
  const e = env();
  e.ctl.replay();
  e.ctl.goTo(5);
  const body = e.card().querySelector(".pv-onb-body");
  assert.equal(body.getAttribute("data-step"), "distinction");
  const w = body.querySelector(".pv-onb-compare-wallet");
  const p = body.querySelector(".pv-onb-compare-pv");
  assert.equal(w.querySelector(".pv-onb-cmp-q").textContent, '"Can this key sign?"');
  assert.equal(p.querySelector(".pv-onb-cmp-q").textContent, '"Is this action authorized?"');
  assert.equal(w.textContent.indexOf(Onb.WALLET_QUESTION) >= 0, true, "verbatim wallet question survives the visual split");
  assert.equal(p.textContent.indexOf(Onb.POLICYVAULT_QUESTION) >= 0, true, "verbatim PolicyVault question survives the visual split");
  assert.deepEqual(body.querySelectorAll(".pv-onb-sum-tile").map((n) => n.textContent), ["PolicyVault policy", "external signer", "Kaspa covenant enforcement", "bounded, non-custodial delegated spending"]);
  assert.deepEqual(body.querySelectorAll(".pv-onb-sum-op").map((n) => n.textContent), ["+", "+", "="]);
  assert.ok(body.textContent.includes("never signs for you"));
});

test("'Replay animation' is a real button in every figure: it re-renders the figure (fresh nodes, identical content), keeps the step, touches no stored state, and stays inside the focus trap", () => {
  const storage = memoryStorage();
  const e = env({ storage });
  e.ctl.replay();
  for (let i = 0; i < Onb.STEPS.length; i++) {
    const before = JSON.stringify(storage._map.get(Onb.STORAGE_KEY) || null);
    const arts = e.card().querySelectorAll(".pv-onb-art");
    for (const art of arts) {
      const btn = art.querySelector("button.pv-onb-art-replay");
      assert.ok(btn && btn.getAttribute("type") === "button", `step ${i + 1}: a real button`);
      assert.equal(btn.textContent, "↻ Replay animation");
      const figBefore = art.querySelector(".pv-onb-fig");
      const textBefore = figBefore.textContent;
      btn.click();
      const figAfter = art.querySelector(".pv-onb-fig");
      assert.notEqual(figAfter, figBefore, "the figure is rebuilt (which restarts its CSS animations)");
      assert.equal(figAfter.textContent, textBefore, "identical content after replay");
      assert.equal(figAfter.getAttribute("aria-label"), figBefore.getAttribute("aria-label"));
      assert.ok(!art.querySelector(".pv-onb-fig").contains(art.querySelector("button.pv-onb-art-replay")), "the control is outside the labelled figure");
    }
    assert.equal(e.ctl.step(), i, "replaying an animation never changes the step");
    assert.equal(e.ctl.isOpen(), true);
    assert.equal(JSON.stringify(storage._map.get(Onb.STORAGE_KEY) || null), before, "replaying an animation writes nothing");
    // Keyboard: the replay buttons are ordinary focusables inside the dialog's Tab cycle.
    const focusables = e.card().querySelectorAll("button, a[href], input, select, textarea, [tabindex]").filter((n) => !n.disabled && n.getAttribute("tabindex") !== "-1");
    for (const art of arts) assert.ok(focusables.includes(art.querySelector("button.pv-onb-art-replay")));
    if (i < Onb.STEPS.length - 1) e.ctl.next();
  }
});

test("static: the module is self-contained (no remote asset, no media, no colour literal — every colour comes from the app's theme tokens via CSS); index.html has no media element for the walkthrough", () => {
  const code = ONBOARDING_SRC.replace(/\/\*[\s\S]*?\*\//g, "").replace(/^\s*\/\/.*$/gm, ""); // comments stripped
  const urls = code.match(/https?:\/\/[^\s"'`)]+/g) || [];
  assert.deepEqual([...new Set(urls)], ["https://docs.policy-vault.org", "http://www.w3.org/2000/svg"], "only the docs origin and the SVG namespace");
  assert.ok(!/url\(|\.gif|\.webp|\.mp4|\.webm|<img|<video|<iframe|@import|analytics|gtag|beacon/i.test(code), "no remote/animation/analytics dependency");
  assert.ok(!/#[0-9a-fA-F]{3,8}\b|rgba?\(|hsla?\(/.test(code), "no colour literal in the module");
  assert.ok(ONBOARDING_SRC.includes('stroke: "currentColor"'));
  assert.ok(!/<video|<iframe|\.gif|\.webp/i.test(INDEX_HTML), "no video / GIF / WebP in the page");
  assert.equal((INDEX_HTML.match(/<img /g) || []).length, 1, "the only image in the page is the brand mark");
});

test("static CSS: token-only colours (no hex literal in the walkthrough block), the broad reduced-motion rule, the narrow-viewport bottom-sheet rule, dynamic-viewport sizing, focus-visible outlines, and static-state-is-final-state for the travelling packet", () => {
  assert.ok(!/#[0-9a-fA-F]{3,8}\b/.test(ONB_CSS.replace(/#pv-[a-z-]+/g, "")), "no hex colour literal — every colour is a var() token or a translucent overlay");
  assert.ok(ONB_CSS.includes("@media (prefers-reduced-motion: reduce) { .pv-onb-card, .pv-onb-card * { animation: none !important; transition: none !important; } .pv-onb-art-replay { display: none !important; } }"));
  assert.ok(ONB_CSS.includes("@media (max-width: 600px) {"), "narrow-viewport rule");
  assert.ok(/@media \(max-width: 600px\) \{[\s\S]*#pv-onboarding \{ padding: 0; align-items: flex-end; \}/.test(ONB_CSS), "bottom sheet on narrow viewports");
  assert.ok(ONB_CSS.includes("max-height: 90dvh") && ONB_CSS.includes("max-height: 100dvh"), "dynamic viewport units with vh fallbacks");
  assert.ok(ONB_CSS.includes(".pv-onb-card button:focus-visible, .pv-onb-card a:focus-visible, .pv-onb-card input:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }"));
  // The packet's resting transform equals the last keyframe of its journey, so with animations
  // disabled it sits at Kaspa (the end of the flow) instead of at the start.
  const rest = /\.pv-onb-packet \{[^}]*transform: translateY\((\d+)px\)/.exec(ONB_CSS);
  const last = /@keyframes pv-onb-travel \{[^@]*?84%, 100% \{ transform: translateY\((\d+)px\); \}/.exec(ONB_CSS);
  assert.ok(rest && last && rest[1] === last[1], "packet resting position == final keyframe");
  assert.equal(Number(rest[1]), 3 * (54 + 30), "three pitches of stage(54px) + arrow(30px)");
  assert.ok(ONB_CSS.includes(".pv-onb-stage { position: relative; height: 54px;") && ONB_CSS.includes(".pv-onb-arrow { position: relative; height: 30px;"), "fixed-pitch rows keep the packet on the wire at every width");
  // Every keyframe the block references is defined in the block.
  const used = new Set((ONB_CSS.match(/animation: (pv-onb-[a-z-]+)/g) || []).map((m) => m.split(" ")[1]));
  for (const k of used) assert.ok(ONB_CSS.includes(`@keyframes ${k} {`), `keyframes ${k} defined`);
  assert.ok(used.size >= 8, `several distinct animations (${used.size})`);
});
