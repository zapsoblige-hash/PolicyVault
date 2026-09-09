"use strict";

/*
 * BROWSER — flagship UX pass, ACCESSIBILITY of the live status surfaces
 * (TRACK 11). These are the regions whose CONTENT CHANGES while the user
 * is not looking at them, and every one of them carries safety-relevant
 * meaning:
 *
 *   #testnet-banner  the network identity (MAINNET / a testnet / the
 *                    fail-closed NETWORK STATUS UNKNOWN);
 *   #net             the node chip (synced / SYNCING / unreachable);
 *   #wallet-status   wallet connection + WRONG_NETWORK;
 *   #auth-status     hosted session state;
 *   #v4-notice       the ENTIRE v0.4.1 transaction lifecycle narration —
 *                    preparing / waiting for the wallet / signed /
 *                    broadcasting / CHAIN_VERIFIED / every refusal;
 *   #notice          the legacy toast.
 *
 * Before this pass none of them was an ARIA live region, so a screen-reader
 * user got NO announcement that a transaction had been refused, that a
 * broadcast was still pending, or that the network identity had failed
 * closed to UNKNOWN. The markup below is the fix; these tests pin it.
 *
 * The banner's DERIVATION is untouched and stays pinned by
 * web/test/network-banner.test.js — this file only proves the announcement
 * wrapper exists and that the real app.js update paths never remove it.
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const WEB_DIR = path.join(__dirname, "..");
const INDEX_HTML = fs.readFileSync(path.join(WEB_DIR, "index.html"), "utf8");
const APP_JS = fs.readFileSync(path.join(WEB_DIR, "app.js"), "utf8");
const APP_V4 = fs.readFileSync(path.join(WEB_DIR, "app-v4.js"), "utf8");

/* The tag that OPENS each element, so the assertions read its own attributes
 * and never a neighbour's. */
function openingTag(id) {
  const m = new RegExp(`<[a-z0-9]+[^>]*\\sid="${id}"[^>]*>`).exec(INDEX_HTML);
  assert.ok(m, `#${id} exists in web/index.html`);
  return m[0];
}

const LIVE_REGIONS = ["testnet-banner", "net", "wallet-status", "auth-status", "v4-notice", "notice"];

for (const id of LIVE_REGIONS) {
  test(`#${id} is an ARIA live region (role=status, aria-live=polite, aria-atomic=true)`, () => {
    const tag = openingTag(id);
    assert.match(tag, /\srole="status"/, `#${id} needs role="status"`);
    assert.match(tag, /\saria-live="polite"/, `#${id} needs aria-live="polite"`);
    assert.match(tag, /\saria-atomic="true"/, `#${id} must be announced as a whole, not word by word`);
  });
}

test("the network banner's initial markup is still the neutral VERIFYING state (fail-closed rule unchanged)", () => {
  const tag = openingTag("testnet-banner");
  const after = INDEX_HTML.slice(INDEX_HTML.indexOf(tag) + tag.length, INDEX_HTML.indexOf(tag) + tag.length + 60);
  assert.match(after, /^VERIFYING NETWORK…/, "neutral initial text, never a network name");
  // (the element's legacy id "testnet-banner" is kept for CSS/JS
  // compatibility and is NOT a network claim — exclude it before checking.)
  assert.ok(!/MAINNET|TESTNET/i.test(tag.replace(/id="testnet-banner"/, "")), "the opening tag never names a network");
});

/* The live-region attributes must survive every real update path. app.js
 * writes textContent / dataset / style on these elements — it must never
 * replace the elements themselves (which would silently drop the ARIA
 * wrapper and re-break the announcement). */
test("app.js updates the banner by textContent/dataset only — it never re-creates the element", () => {
  assert.ok(/b\.textContent = /.test(APP_JS), "banner text is set via textContent");
  assert.ok(!/getElementById\("testnet-banner"\)[^\n]*\.outerHTML/.test(APP_JS), "the banner element is never replaced wholesale");
  assert.ok(!/removeAttribute\(\s*["']aria-live["']\s*\)/.test(APP_JS + APP_V4), "no code path removes aria-live");
  assert.ok(!/removeAttribute\(\s*["']role["']\s*\)/.test(APP_JS + APP_V4), "no code path removes role");
});

test("app-v4.js note() writes the status region's text without rebuilding the element", () => {
  const noteFn = /function note\(msg, cls\) \{[\s\S]*?\n  \}/.exec(APP_V4);
  assert.ok(noteFn, "note() found");
  assert.match(noteFn[0], /el\.textContent = msg/, "text is assigned, not innerHTML-replaced onto a new node");
  assert.ok(!/\$\("v4-notice"\)\.replaceWith/.test(APP_V4));
});

/* Behavioural: drive the REAL applyNetworkBanner through its three
 * outcomes and prove the element identity (and therefore its ARIA
 * attributes) is stable across all of them. */
test("applyNetworkBanner keeps ONE element across mainnet / testnet / fail-closed UNKNOWN", () => {
  const attrs = {};
  const banner = {
    id: "testnet-banner", dataset: {}, style: {}, textContent: "VERIFYING NETWORK…",
    setAttribute(k, v) { attrs[k] = v; }, removeAttribute(k) { delete attrs[k]; },
    getAttribute: (k) => attrs[k]
  };
  attrs.role = "status"; attrs["aria-live"] = "polite"; attrs["aria-atomic"] = "true";
  const sandbox = {
    console,
    document: { getElementById: (id) => (id === "testnet-banner" ? banner : { textContent: "", innerHTML: "", style: {}, dataset: {}, classList: { add() {}, remove() {}, toggle() {} }, addEventListener() {}, querySelectorAll: () => [], querySelector: () => null }), querySelectorAll: () => [], addEventListener() {} },
    localStorage: { getItem: () => null, setItem() {}, removeItem() {} },
    fetch: () => new Promise(() => {}),
    setTimeout: () => 0, clearTimeout() {},
    crypto: { getRandomValues: (a) => a.fill(7) },
    PolicyVaultWallet: require("../wallet.js"),
    PolicyVaultIdentity: {}
  };
  sandbox.window = sandbox;
  vm.createContext(sandbox);
  vm.runInContext(APP_JS, sandbox, { filename: "app.js" });
  const apply = sandbox.window.PolicyVaultNetworkBanner._apply;

  apply("mainnet");
  assert.equal(banner.textContent, "MAINNET — real KAS");
  apply("testnet-10");
  assert.match(banner.textContent, /TESTNET-10/);
  apply(null);
  assert.equal(banner.textContent, "NETWORK STATUS UNKNOWN — verify connection before transacting");

  assert.equal(attrs.role, "status", "role survived every transition");
  assert.equal(attrs["aria-live"], "polite", "aria-live survived every transition");
  assert.equal(attrs["aria-atomic"], "true", "aria-atomic survived every transition");
});
