"use strict";

/*
 * PolicyVault mobile — THE PORTABLE/PLATFORM SEAM, ENFORCED.
 *
 * mobile-architecture-decision.md §3.6 makes the Capacitor decision
 * REVERSIBLE by requiring a hard two-layer seam: the portable layer never
 * imports from the platform layer, never touches the DOM, and never takes
 * a host object other than the core API. If React Native is ever adopted
 * (the documented escape hatch), the portable layer moves unmodified and
 * only the platform layer is rewritten.
 *
 * A rule like that decays unless something fails when it is broken —
 * risk R10 in the decision document names exactly this. This file is that
 * something: a static gate over the shipped payload, not a convention.
 *
 * It also enforces the other half of the anti-drift argument: the
 * DO-NOT-SIGN text a human reads must come from the reviewed explanation
 * layer, so the platform renderer must not contain sentences of its own
 * about what a transaction does.
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const S = require("./sandbox.js");

const PORTABLE_DIR = path.join(S.WWW, "js", "portable");
const PLATFORM_DIR = path.join(S.WWW, "js", "platform");

/* Remove comments and string literals so a rule cannot be tripped by
 * prose that merely NAMES a forbidden thing (these files discuss the DOM
 * at length precisely because they must not touch it). */
function stripCommentsAndStrings(source) {
  let out = "";
  let i = 0;
  const n = source.length;
  while (i < n) {
    const c = source[i];
    const next = source[i + 1];
    if (c === "/" && next === "*") {
      const end = source.indexOf("*/", i + 2);
      i = end < 0 ? n : end + 2;
      out += " ";
      continue;
    }
    if (c === "/" && next === "/") {
      const end = source.indexOf("\n", i);
      i = end < 0 ? n : end;
      out += " ";
      continue;
    }
    if (c === '"' || c === "'" || c === "`") {
      const quote = c;
      i++;
      while (i < n) {
        if (source[i] === "\\") { i += 2; continue; }
        if (source[i] === quote) { i++; break; }
        i++;
      }
      out += '""';
      continue;
    }
    out += c;
    i++;
  }
  return out;
}

/* Comments only — string literals are preserved, for checks that need to
 * see the exact source form of a guarded expression. */
function stripComments(source) {
  return source.replace(/\/\*[\s\S]*?\*\//g, " ").replace(/^\s*\/\/.*$/gm, " ");
}

function portableFiles() {
  return fs.readdirSync(PORTABLE_DIR).filter((f) => f.endsWith(".js")).sort();
}

function platformFiles() {
  return fs.readdirSync(PLATFORM_DIR).filter((f) => f.endsWith(".js")).sort();
}

/* Everything the portable layer is forbidden to reach for. */
const FORBIDDEN_IN_PORTABLE = [
  { re: /\bdocument\s*[.[]/, why: "the DOM" },
  { re: /\bnavigator\b/, why: "navigator" },
  { re: /\blocalStorage\b/, why: "localStorage" },
  { re: /\bsessionStorage\b/, why: "sessionStorage" },
  { re: /\bindexedDB\b/, why: "IndexedDB" },
  { re: /\bfetch\s*\(/, why: "an ambient fetch (transport must be injected)" },
  { re: /\bXMLHttpRequest\b/, why: "XMLHttpRequest" },
  { re: /\bCapacitor\b/, why: "the Capacitor host" },
  { re: /\balert\s*\(/, why: "alert()" },
  { re: /\bPolicyVaultMobilePlatform\b/, why: "the platform module" },
  { re: /\bPolicyVaultMobileUi\b/, why: "the UI module" },
  { re: /\brequire\s*\(/, why: "a module loader (the payload is plain <script> tags)" }
];

test("SEAM: no portable module reaches for the DOM, a platform module, or an ambient host capability", () => {
  const files = portableFiles();
  assert.ok(files.length >= 6, `expected the portable layer to have modules, found ${files.length}`);

  for (const file of files) {
    const code = stripCommentsAndStrings(fs.readFileSync(path.join(PORTABLE_DIR, file), "utf8"));
    for (const rule of FORBIDDEN_IN_PORTABLE) {
      assert.equal(
        rule.re.test(code),
        false,
        `js/portable/${file} reaches for ${rule.why} — the portable layer must move to another host unmodified`
      );
    }
  }
});

test("SEAM: `window` appears in a portable module only as the self-install guard", () => {
  /* The ONE line a portable module is allowed to mention `window` on. Any
   * other reference means the module has started depending on a browser
   * host and would no longer move to another host unmodified. */
  const INSTALL_GUARD = /^\s*if \(typeof window !== "undefined"\) window\.PolicyVault\w+ = api;\s*$/;

  for (const file of portableFiles()) {
    const lines = stripComments(fs.readFileSync(path.join(PORTABLE_DIR, file), "utf8")).split("\n");
    let guards = 0;
    for (const line of lines) {
      if (!/\bwindow\b/.test(line)) continue;
      assert.ok(INSTALL_GUARD.test(line), `js/portable/${file} uses window outside the install guard: ${line.trim()}`);
      guards++;
    }
    assert.equal(guards, 1, `js/portable/${file} must have exactly one install guard, found ${guards}`);
  }
});

test("SEAM: every portable module exposes BOTH the browser global and the CommonJS export", () => {
  /* Dual export is what lets the identical file run in the WebView and in
   * this test process. Losing one half silently breaks a host. */
  for (const file of portableFiles()) {
    const source = fs.readFileSync(path.join(PORTABLE_DIR, file), "utf8");
    assert.match(source, /typeof window !== "undefined"\) window\.PolicyVault\w+ = api;/, `js/portable/${file} does not install a browser global`);
    assert.match(source, /typeof module !== "undefined" && module\.exports\) module\.exports = api;/, `js/portable/${file} does not export for CommonJS`);
  }
});

test("SEAM: the platform layer never re-implements verification or explanation text", () => {
  /* The single most valuable anti-drift property of this architecture is
   * that there is exactly ONE implementation of the words a human reads
   * before authorizing money to move. The renderer must display
   * outcome.lines, not compose its own. */
  const forbiddenPhrases = [
    "THIS TRANSACTION DOES EXACTLY WHAT WAS REQUESTED",
    "buildIntentManifest",
    "verifyIntentManifest",
    "agentRecipientRoot",
    "successorStateId"
  ];
  const appFiles = platformFiles().map((f) => path.join(PLATFORM_DIR, f)).concat([path.join(S.WWW, "js", "app.js")]);

  for (const abs of appFiles) {
    const source = fs.readFileSync(abs, "utf8");
    for (const phrase of forbiddenPhrases) {
      assert.equal(
        source.includes(phrase),
        false,
        `${path.relative(S.WWW, abs)} contains ${JSON.stringify(phrase)} — the platform layer must never restate what the reviewed verifier says`
      );
    }
  }
});

test("SEAM: the UI renders the verifier's own lines, and its verdict view offers no control but Cancel", () => {
  const ui = fs.readFileSync(path.join(PLATFORM_DIR, "ui.js"), "utf8");
  assert.match(ui, /outcome\.lines/, "the verdict renderer must read outcome.lines");

  /* §6.3 rule 2: on a refusal the signing affordance is ABSENT, not
   * disabled. The verdict renderer creates exactly one control in the
   * whole file, and it is the cancel button on the refusal
   * interstitial. Anything else appearing here would be a control the
   * refusal path could render. */
  const buttons = stripComments(ui).match(/el\("button"/g) || [];
  assert.equal(buttons.length, 1, `ui.js creates ${buttons.length} controls; the verdict layer may create only the Cancel control`);
  assert.match(ui, /text: "Cancel — nothing was signed"/, "the sole control must be the explicit cancel");
  assert.equal(/disabled/.test(stripComments(ui)), false, "ui.js must never render a disabled control — an absent affordance is the rule, not a greyed one");
});

test("SEAM: the stylesheet structurally forbids truncating value-bearing text", () => {
  /* §6.3 rule 8. Eliding an address or an amount is the most likely way a
   * small screen silently weakens the ceremony, so the rule lives in the
   * style sheet, not only in review. */
  const css = fs.readFileSync(path.join(S.WWW, "css", "app.css"), "utf8").replace(/\/\*[\s\S]*?\*\//g, " ");
  for (const banned of ["text-overflow", "line-clamp", "nowrap"]) {
    assert.equal(css.includes(banned), false, `app.css uses ${banned}, which can truncate a displayed address or amount`);
  }
  assert.match(css, /overflow-wrap:\s*anywhere/, "the full-value style must wrap rather than truncate");
});
