"use strict";

/*
 * BROWSER — narrow-viewport layout, focus visibility, reduced motion
 * (TRACK 11 flagship UX pass, findings M1 and A2).
 *
 * M1 (MED-HIGH, 375 px). Before this pass the ONLY max-width rule in the
 * whole stylesheet was the first-run walkthrough's. The product itself —
 * header, panels, vault cards, the review modal, the member and delegate
 * directory tables — had no responsive rules at all. At 375 px the
 * directory tables (5 and 7 columns of wallet addresses) pushed the entire
 * PAGE into horizontal scroll, and every control was roughly 35 px tall.
 *
 * A2 (MED, keyboard). Only the walkthrough dialog defined a focus ring;
 * everywhere else the app relied on whatever the browser drew over its
 * custom dark backgrounds.
 *
 * REDUCED MOTION. The existing rule is deliberately scoped to the
 * walkthrough card. That is complete ONLY while the walkthrough is the
 * only animated thing in the app — so this file pins that invariant: a
 * future animation added outside that scope FAILS here rather than
 * silently shipping motion that prefers-reduced-motion cannot switch off.
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const WEB_DIR = path.join(__dirname, "..");
const INDEX_HTML = fs.readFileSync(path.join(WEB_DIR, "index.html"), "utf8");
const CSS = /<style>([\s\S]*?)<\/style>/.exec(INDEX_HTML)[1];

/* The narrow-viewport block that belongs to the APPLICATION (the other
 * max-width block is the walkthrough's, added by the onboarding pass). */
function mediaBlocks() {
  const out = [];
  const re = /@media \(max-width: 600px\) \{/g;
  let m;
  while ((m = re.exec(CSS))) {
    let depth = 1;
    let i = re.lastIndex;
    while (i < CSS.length && depth > 0) {
      if (CSS[i] === "{") depth++;
      else if (CSS[i] === "}") depth--;
      i++;
    }
    out.push(CSS.slice(m.index, i));
  }
  return out;
}

const APP_MEDIA = mediaBlocks().find((b) => /\bmain \{/.test(b));

test("the application itself has a narrow-viewport block, not only the walkthrough", () => {
  assert.ok(APP_MEDIA, "an @media (max-width: 600px) block styling the app shell exists");
  for (const sel of ["main {", "header {", ".panel, .vault {", ".modal-card {", ".mtable {"]) {
    assert.ok(APP_MEDIA.includes(sel), `narrow-viewport rules must cover ${sel}`);
  }
});

test("wide directory tables scroll inside their OWN container, never the page", () => {
  assert.match(APP_MEDIA, /\.mtable \{[^}]*overflow-x: auto/, ".mtable becomes its own horizontal scroll container");
  assert.match(APP_MEDIA, /\.mtable \{[^}]*max-width: 100%/);
  // and the body must never be given a horizontal scroll as the "fix"
  assert.ok(!/body[^{]*\{[^}]*overflow-x/.test(CSS), "the page itself never scrolls sideways");
});

test("touch targets reach 44 px at narrow widths, without changing any label", () => {
  assert.match(APP_MEDIA, /button, a\.btnlink, \.v4-tab, \.filterbar \.pill, select, input \{[^}]*min-height: 44px/);
});

test("nothing is hidden, reordered, or truncated at narrow widths", () => {
  assert.ok(!/display:\s*none/.test(APP_MEDIA), "no content is hidden on small screens");
  assert.ok(!/text-overflow|line-clamp/.test(APP_MEDIA), "no value-bearing text is ever elided");
  assert.ok(!/\border:\s*-?\d/.test(APP_MEDIA), "no reordering that would separate a control from its meaning");
});

test("value-bearing strings still wrap in full — no ellipsis rule anywhere in the app CSS", () => {
  // The walkthrough's decorative stage-role caption is the ONE ellipsis in
  // the sheet and it carries no address, amount, or identifier.
  const ellipsisRules = [...CSS.matchAll(/([^{}]+)\{[^}]*text-overflow:\s*ellipsis[^}]*\}/g)].map((m) => m[1].trim());
  assert.deepEqual(ellipsisRules, [".pv-onb-stage-role"], `unexpected truncation rule(s): ${ellipsisRules.join(", ")}`);
});

test("every interactive element gets an explicit focus ring", () => {
  const rule = /a:focus-visible, button:focus-visible, input:focus-visible, select:focus-visible,\s*textarea:focus-visible, summary:focus-visible, \[tabindex\]:focus-visible \{([^}]*)\}/.exec(CSS);
  assert.ok(rule, "a global :focus-visible rule exists");
  assert.match(rule[1], /outline: 2px solid var\(--accent\)/);
  assert.match(rule[1], /outline-offset: 2px/);
  assert.ok(!/outline:\s*none/.test(rule[1]));
});

test("no rule anywhere removes the focus outline", () => {
  const killers = [...CSS.matchAll(/([^{}]+)\{[^}]*outline:\s*(none|0)[^}]*\}/g)].map((m) => m[1].trim());
  // .pv-onb-title is focused programmatically for screen readers on step
  // change and defines its own :focus-visible ring on the next line.
  assert.deepEqual(killers, [".pv-onb-title:focus"], `focus outline removed by: ${killers.join(", ")}`);
  assert.match(CSS, /\.pv-onb-title:focus-visible \{ outline: 1px solid var\(--accent\)/);
});

/* ---------------- reduced motion covers 100% of shipped animation ------- */

test("the reduced-motion rule is present and disables EVERY walkthrough animation", () => {
  assert.match(CSS, /@media \(prefers-reduced-motion: reduce\) \{ \.pv-onb-card, \.pv-onb-card \* \{ animation: none !important; transition: none !important; \} \.pv-onb-art-replay \{ display: none !important; \} \}/);
});

test("ANTI-DRIFT: no animation or transition exists outside the reduced-motion scope", () => {
  // Every animated selector must be inside the .pv-onb- family, which is
  // exactly what the reduced-motion rule switches off. A new animation on
  // anything else would ship motion the user cannot turn off.
  const animated = [...CSS.matchAll(/([^{}]+)\{[^}]*(?:^|[;\s])(?:animation|transition):\s*(?!none)[^};]+/gm)]
    .map((m) => m[1].trim())
    .filter((sel) => !/@(media|keyframes)/.test(sel))
    .filter((sel) => !sel.split(",").every((s) => /\.pv-onb-/.test(s)));
  assert.deepEqual(animated, [], `animated selectors outside the reduced-motion scope: ${animated.join(" | ")}`);
});

test("keyframes are only consumed by the walkthrough", () => {
  const names = [...CSS.matchAll(/@keyframes ([\w-]+)/g)].map((m) => m[1]);
  assert.ok(names.length > 0);
  for (const n of names) assert.match(n, /^pv-onb-/, `keyframe "${n}" is outside the walkthrough namespace`);
});
