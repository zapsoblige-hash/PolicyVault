"use strict";

/*
 * MECHANICAL SCAN — floating-point financial parsing is forbidden
 * everywhere (Wave 2, Track F item 5; CLAUDE.md "Numeric safety": "All
 * consensus/accounting values are integer sompi... Never floating point").
 *
 * The motivating incident is docs/postlaunch/hybrid-core-gap-analysis.md
 * gap G1: web/app.js computed
 * `BigInt(Math.round(Number(v) * 1e8))` on a live funds path (double-
 * precision loss on large amounts, "0.000000001" -> 0 sompi, "0x10"
 * accepted as 16). That defect was in ordinary application code, not a
 * covenant/consensus path, and nothing caught it mechanically until the
 * shared-core migration wave captured golden fixtures of the ORIGINAL
 * broken behavior. This scan exists so the NEXT such defect fails a test
 * instead of shipping.
 *
 * SCOPE: web/, mobile/www/js/, server/src/, sdk/src/, mcp/src/, core/,
 * python/ (non-test source only — test files legitimately construct
 * adversarial float inputs to prove they are REFUSED, which is the whole
 * point of e.g. sdk/test/amounts.test.js).
 *
 * PATTERNS (each is a plain substring/regex match, not a type-aware
 * analysis — mechanical and auditable over precision):
 *   FLOAT_PARSE        parseFloat(...)                     — anywhere
 *   NUMBER_ON_FINANCIAL Number(<expr>) where <expr> textually names a
 *                       financial identifier (amount/sompi/kas/fee/
 *                       budget/cap/balance/price/quote/principal/
 *                       reserve/payout/spend/value)
 *   UNARY_PLUS_FINANCIAL +<financialIdentifier> in coercion position
 *                       (after =, (, ,, return, or :)
 *   ROUND_TIMES_1E8     Math.round(...) on the same statement as a
 *                       1e8 / 100000000 literal — the exact G1 shape
 *   TOFIXED_ON_FINANCIAL <financialIdentifier>.toFixed(...)
 *   PY_FLOAT_ON_FINANCIAL float(<expr>) in a .py file where <expr>
 *                       textually names a financial identifier
 *
 * A hit is EITHER fixed (real bug) or added to
 * sdk/test/no-float-financial-parsing.allowlist.json with a reason a
 * human can check (file + pattern [+ line] + reason). An unlisted hit
 * fails this test — never weakened by broadening the allowlist without a
 * reason, per CLAUDE.md testing discipline.
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const REPO_ROOT = path.join(__dirname, "..", "..");
const ALLOWLIST_PATH = path.join(__dirname, "no-float-financial-parsing.allowlist.json");

const SCAN_ROOTS = ["web", "mobile/www/js", "server/src", "sdk/src", "mcp/src", "core", "python"];

/* Directories/files never scanned: generated bundles (verbatim-embedded
 * source is scanned at its OWN location; scanning the bundle too would
 * double-report every hit with a useless bundle-relative path), vendored
 * mobile copies (byte-identical to their web/sdk source, same reason),
 * node_modules, and test/fixture directories (adversarial float inputs in
 * tests are the point, not a defect). */
const EXCLUDE_SEGMENTS = ["node_modules", "vendor", "fixtures", "testutil", ".git"];
const EXCLUDE_DIR_NAMES = new Set(["test", "tests"]);
const EXCLUDE_FILES = new Set([
  path.join(REPO_ROOT, "web", "core-bundle.js") // generated; embeds core/** verbatim, scanned at its real location
]);
const EXCLUDE_SUFFIXES = [".test.js", ".min.js"];

const FINANCIAL_WORD = "(amount|sompi|kas|fee|budget|cap|balance|price|quote|principal|reserve|payout|spend|value)";
const FINANCIAL_IDENTIFIER_RE = new RegExp(FINANCIAL_WORD, "i");

function walk(dir, out) {
  let entries;
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return; // a listed root that does not exist in this checkout is simply empty
  }
  for (const entry of entries) {
    if (EXCLUDE_SEGMENTS.includes(entry.name)) continue;
    const abs = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (EXCLUDE_DIR_NAMES.has(entry.name)) continue;
      walk(abs, out);
    } else if (entry.isFile()) {
      if (EXCLUDE_FILES.has(abs)) continue;
      if (EXCLUDE_SUFFIXES.some((suf) => entry.name.endsWith(suf))) continue;
      if (entry.name.endsWith(".js") || entry.name.endsWith(".py")) out.push(abs);
    }
  }
  return out;
}

function collectFiles() {
  const out = [];
  for (const root of SCAN_ROOTS) walk(path.join(REPO_ROOT, root), out);
  return out.sort();
}

/*
 * Balanced-paren argument extraction: given source text and the index just
 * after an opening "(" for a call like Number(, parseFloat(, float(,
 * returns the argument text up to the matching ")".  Simple depth counter;
 * good enough for the shapes real call sites use (no need to be a full
 * parser — this is a mechanical GREP-grade scan, not static analysis).
 */
function extractArgs(text, openParenIndex) {
  let depth = 1;
  let i = openParenIndex + 1;
  for (; i < text.length && depth > 0; i++) {
    if (text[i] === "(") depth++;
    else if (text[i] === ")") depth--;
  }
  return text.slice(openParenIndex + 1, i - 1);
}

function lineColOf(text, index) {
  const upTo = text.slice(0, index);
  const line = (upTo.match(/\n/g) || []).length + 1;
  const lastNl = upTo.lastIndexOf("\n");
  return { line, column: index - lastNl };
}

function scanFile(abs, relPath) {
  const text = fs.readFileSync(abs, "utf8");
  const isPy = abs.endsWith(".py");
  const hits = [];

  const pushHit = (pattern, index, snippetLen = 80) => {
    const { line, column } = lineColOf(text, index);
    hits.push({ file: relPath, line, column, pattern, snippet: text.slice(Math.max(0, index - 10), index + snippetLen).replace(/\s+/g, " ").trim() });
  };

  if (!isPy) {
    // FLOAT_PARSE
    for (const m of text.matchAll(/\bparseFloat\s*\(/g)) pushHit("FLOAT_PARSE", m.index);

    // NUMBER_ON_FINANCIAL
    for (const m of text.matchAll(/\bNumber\s*\(/g)) {
      const openIdx = m.index + m[0].length - 1;
      const args = extractArgs(text, openIdx);
      if (FINANCIAL_IDENTIFIER_RE.test(args)) pushHit("NUMBER_ON_FINANCIAL", m.index);
    }

    // UNARY_PLUS_FINANCIAL: a coercion-position "+" (preceded by =,(,{,,,return,: or start-of-line)
    // immediately followed by a financial identifier, NOT part of "++" or a numeric literal.
    for (const m of text.matchAll(/(^|[=([{,:]|\breturn)\s*\+(?!\+|\d)([A-Za-z_$][\w$.]*)/gm)) {
      const ident = m[2];
      if (FINANCIAL_IDENTIFIER_RE.test(ident)) pushHit("UNARY_PLUS_FINANCIAL", m.index + m[0].indexOf("+", m[1].length));
    }

    // ROUND_TIMES_1E8: Math.round(...) whose argument text contains a
    // 1e8 / 1E8 / 100000000 literal (the exact G1 shape:
    // Math.round(Number(v) * 1e8)).
    for (const m of text.matchAll(/\bMath\.round\s*\(/g)) {
      const openIdx = m.index + m[0].length - 1;
      const args = extractArgs(text, openIdx);
      if (/\b1e8\b/i.test(args) || /\b100000000\b/.test(args)) pushHit("ROUND_TIMES_1E8", m.index);
    }

    // TOFIXED_ON_FINANCIAL: <financialIdentifier>.toFixed(
    for (const m of text.matchAll(/([A-Za-z_$][\w$.]*)\s*\.\s*toFixed\s*\(/g)) {
      const receiver = m[1];
      if (FINANCIAL_IDENTIFIER_RE.test(receiver)) pushHit("TOFIXED_ON_FINANCIAL", m.index);
    }
  } else {
    // PY_FLOAT_ON_FINANCIAL
    for (const m of text.matchAll(/\bfloat\s*\(/g)) {
      const openIdx = m.index + m[0].length - 1;
      const args = extractArgs(text, openIdx);
      if (FINANCIAL_IDENTIFIER_RE.test(args)) pushHit("PY_FLOAT_ON_FINANCIAL", m.index);
    }
  }

  return hits;
}

function loadAllowlist() {
  const doc = JSON.parse(fs.readFileSync(ALLOWLIST_PATH, "utf8"));
  return doc.entries || [];
}

function isAllowlisted(hit, entries) {
  return entries.some((e) => e.file === hit.file && e.pattern === hit.pattern && (e.line === undefined || e.line === hit.line));
}

test("MECHANICAL SCAN: no unjustified floating-point financial parsing across web/mobile/server/sdk/mcp/core/python source", () => {
  const files = collectFiles();
  assert.ok(files.length > 100, `sanity: expected > 100 scanned files, got ${files.length}`);
  const allowlist = loadAllowlist();

  const allHits = [];
  for (const abs of files) {
    const rel = path.relative(REPO_ROOT, abs).split(path.sep).join("/");
    allHits.push(...scanFile(abs, rel));
  }

  const unlisted = allHits.filter((h) => !isAllowlisted(h, allowlist));

  if (unlisted.length > 0) {
    const report = unlisted.map((h) => `  ${h.pattern} ${h.file}:${h.line}:${h.column}  ${JSON.stringify(h.snippet)}`).join("\n");
    assert.fail(
      `${unlisted.length} unjustified floating-point financial-parsing hit(s):\n${report}\n\n` +
        "Fix the real ones (PRODUCTION CODE BUG). For a genuinely non-financial use, add a reasoned entry to " +
        "sdk/test/no-float-financial-parsing.allowlist.json — never delete/weaken this scan to silence a real hit."
    );
  }

  /* the allowlist itself must not carry stale entries (a file moved, a
   * line renumbered, a pattern the scanner no longer emits) — a stale
   * entry is a silent hole the NEXT real hit could hide inside */
  const staleEntries = allowlist.filter((e) => !allHits.some((h) => h.file === e.file && h.pattern === e.pattern && (e.line === undefined || e.line === h.line)));
  assert.deepEqual(staleEntries, [], `${staleEntries.length} stale allowlist entrie(s) no longer match any scan hit — remove them`);
});
