"use strict";

/*
 * PolicyVault mobile — ACCESSIBILITY OF THE STATUS SURFACE (TRACK 11
 * flagship UX pass).
 *
 * #banner is not decoration. It normally carries the scaffold notice, but
 * it FLIPS to "PACKAGED VERIFIER UNAVAILABLE — every verification on this
 * device refuses" when the on-device verifier could not load. That is a
 * fail-closed security state, and a screen-reader user must hear it rather
 * than happen to read it. It is now an ARIA live region.
 *
 * Also pinned here: an explicit focus ring (the stylesheet paints its own
 * backgrounds on every control, so the ring cannot be left to the WebView),
 * 44 px tab targets (a mis-tap navigates away from a verification the user
 * is reading), and the standing rules the stylesheet already carries — no
 * truncation of value-bearing text, and no animation at all, so
 * prefers-reduced-motion has nothing to switch off.
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const WWW = path.join(__dirname, "..", "www");
const INDEX = fs.readFileSync(path.join(WWW, "index.html"), "utf8");
const CSS_RAW = fs.readFileSync(path.join(WWW, "css", "app.css"), "utf8");
/* Scan DECLARATIONS, not prose: this stylesheet documents its own rules in
 * comments ("deliberately absent: text-overflow, -webkit-line-clamp"), and
 * a scan that counted those would pass or fail on the documentation rather
 * than on the CSS. */
const CSS = CSS_RAW.replace(/\/\*[\s\S]*?\*\//g, "");
const APP = fs.readFileSync(path.join(WWW, "js", "app.js"), "utf8");

test("#banner is an ARIA live region", () => {
  const tag = /<div id="banner"[^>]*>/.exec(INDEX);
  assert.ok(tag, "#banner exists");
  assert.match(tag[0], /role="status"/);
  assert.match(tag[0], /aria-live="polite"/);
  assert.match(tag[0], /aria-atomic="true"/);
});

test("the verifier-unavailable refusal is written into that same element (never a new one)", () => {
  assert.match(APP, /banner\.textContent = "PACKAGED VERIFIER UNAVAILABLE/);
  assert.ok(!/getElementById\("banner"\)[^\n]*outerHTML/.test(APP), "the element is never replaced, so the ARIA wrapper survives");
  assert.ok(!/removeAttribute\(\s*["'](aria-live|role)["']\s*\)/.test(APP));
});

test("interactive elements have an explicit focus ring, and nothing removes it", () => {
  assert.match(CSS, /a:focus-visible, button:focus-visible, input:focus-visible, select:focus-visible,\s*textarea:focus-visible, \[tabindex\]:focus-visible \{[^}]*outline: 2px solid var\(--accent\)/);
  const killers = [...CSS.matchAll(/([^{}]+)\{[^}]*outline:\s*(none|0)[^}]*\}/g)].map((m) => m[1].trim());
  assert.deepEqual(killers, [], `focus outline removed by: ${killers.join(", ")}`);
});

test("tabs are at least 44 px tall", () => {
  assert.match(CSS, /\.tab \{[^}]*min-height: 44px/);
});

/* ---- standing rules of this stylesheet, re-pinned by this pass ---- */

test("NO truncation of value-bearing text anywhere in the mobile stylesheet", () => {
  assert.ok(!/text-overflow|line-clamp/.test(CSS), "eliding an address on a small screen silently weakens the ceremony");
  assert.match(CSS, /\.fullvalue \{[\s\S]*?overflow-wrap: anywhere/);
  assert.match(CSS_RAW, /`\.fullvalue` NEVER truncates/, "and the rule is still documented at the top of the sheet");
});

test("no animation or transition ships, so prefers-reduced-motion has nothing to disable", () => {
  const animated = [...CSS.matchAll(/([^{}]+)\{[^}]*(?:^|[;\s])(?:animation|transition):\s*(?!none)[^};]+/gm)].map((m) => m[1].trim());
  assert.deepEqual(animated, [], `unexpected motion: ${animated.join(" | ")}`);
  assert.ok(!/@keyframes/.test(CSS));
});

test("the refusal still owns the screen — opaque, full-viewport, alertdialog", () => {
  assert.match(CSS, /\.interstitial \{[^}]*position: fixed[^}]*\}/);
  assert.match(CSS, /\.interstitial \{[^}]*inset: 0[^}]*\}/);
  const ui = fs.readFileSync(path.join(WWW, "js", "platform", "ui.js"), "utf8");
  assert.match(ui, /role: "alertdialog", "aria-modal": "true"/);
});
