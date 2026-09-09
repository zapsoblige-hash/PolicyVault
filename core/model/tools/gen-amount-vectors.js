"use strict";

/*
 * Shared-core amounts parity — generated vector file (Wave 2, Track F:
 * docs/postlaunch/hybrid-core-gap-analysis.md gap G5: "python/
 * policyvault_client/amounts.py ... test vectors are hand-copied ... a
 * change to the canonical parser would not fail any Python test. Needs a
 * generated shared vector file (JSON emitted from core/model/amounts.js,
 * consumed by both suites)").
 *
 * Every INPUT below is a fixed string; every EXPECTED outcome is computed
 * by CALLING the real, canonical core/model/amounts.js (never hand-typed),
 * so the fixture is a mechanical function of the parser's actual current
 * behavior. sdk/test/amount-vectors-fixture.test.js and
 * python/tests/test_amount_vectors_fixture.py both read the SAME
 * core/model/test/fixtures/amount-vectors.json and assert their own
 * parser reproduces it — a change to the canonical parsing RULES changes
 * this file (regenerate + `--check` catches drift), and a Python
 * divergence from it fails the Python suite instead of silently going
 * unnoticed (the exact gap G5 names).
 *
 * `pythonDivergence` tags the handful of inputs where python/
 * policyvault_client/amounts.py is DELIBERATELY STRICTER than the JS
 * parser (its own module docstring, divergences 1-2): ASCII-only
 * whitespace trimming, where JS's String.prototype.trim() strips a wider
 * Unicode whitespace set than Python's ASCII-only strip. Every other
 * vector must produce IDENTICAL ok/refuse verdicts (and identical values
 * where both accept) in both languages — silent divergence anywhere else
 * is exactly what this fixture exists to catch.
 *
 * Usage:  node core/model/tools/gen-amount-vectors.js          (write)
 *         node core/model/tools/gen-amount-vectors.js --check  (verify, exit 1 on drift)
 */

const fs = require("fs");
const path = require("path");

const { kasToSompi, parseSompi, MAX_SOMPI } = require("../amounts.js");

const OUT_PATH = path.join(__dirname, "..", "test", "fixtures", "amount-vectors.json");

/* [input, pythonDivergence] — pythonDivergence is null unless the Python
 * port's OWN documented stricter behavior applies to this exact input. */
const INPUTS = [
  ["0", null],
  ["1", null],
  ["12", null],
  ["007", null],
  ["100000000", null],
  ["21000000", null],
  ["999999999", null],
  ["0.1", null],
  ["0.5", null],
  ["1.5", null],
  ["1.23456789", null],
  ["1.00000000", null],
  ["0.00000001", null],
  ["0.10000000", null],
  ["00.5", null],
  [" 1.5", null], // ASCII leading space — both languages trim this
  ["1.5 ", null], // ASCII trailing space — both languages trim this
  [" 1.5 ", null],
  ["1.", null],
  [".5", null],
  ["1.123456789", null], // 9 fractional digits — one too many
  ["1.0000000000", null], // 10 fractional digits
  ["-1", null],
  ["-0", null],
  ["+1", null],
  ["1e3", null],
  ["1E3", null],
  ["1.5e2", null],
  ["0x10", null],
  ["1_000", null],
  ["1,5", null],
  ["NaN", null],
  ["Infinity", null],
  ["-Infinity", null],
  ["", null],
  [" ", null],
  ["  ", null],
  ["٣", null], // Arabic-indic digit 3 — refused by BOTH (JS \d is ASCII-only without the u flag; Python amounts.py deliberately spells [0-9])
  ["0.000000001", null], // 9th fractional digit, no rounding — refused
  ["0.1000000000000000055511151231257827", null], // float-string artifact shape
  ["9007199254740993", null], // > Number.MAX_SAFE_INTEGER, well-formed digits, well under MAX_SOMPI as raw sompi
  ["90071992547.40993", null],
  ["29000000000", null], // exactly MAX_SOMPI in KAS
  ["29000000001", null], // one KAS over MAX_SOMPI
  ["1000000000000", null], // far over MAX_SOMPI
  [MAX_SOMPI.toString(), null], // MAX_SOMPI itself, as a raw sompi digit string (parseSompi boundary)
  [(MAX_SOMPI + 1n).toString(), null], // one sompi over the ceiling
  [(MAX_SOMPI - 1n).toString(), null],
  ["12345678901234567", null], // large, well within range, exceeds 2**53
  ["01", null], // leading zero, otherwise well-formed
  [" 1.5", "ascii-only-whitespace"], // NBSP prefix: JS .trim() strips it, Python's ASCII-only strip does not
  ["1.5 ", "ascii-only-whitespace"], // NBSP suffix
  ["﻿1.5", "ascii-only-whitespace"], // BOM prefix — also Unicode whitespace-adjacent per JS trim()
  ["\t1.5\n", null], // ASCII tab/newline — both strip these
  ["true", null],
  ["null", null],
  ["1.5,0.5", null]
];

function outcomeOf(fn, input) {
  try {
    return { ok: true, value: fn(input).toString() };
  } catch (e) {
    return { ok: false, error: e.message };
  }
}

function generate() {
  const vectors = INPUTS.map(([input, pythonDivergence]) => ({
    input,
    pythonDivergence: pythonDivergence || null,
    kasToSompi: outcomeOf(kasToSompi, input),
    parseSompi: outcomeOf(parseSompi, input)
  }));
  const doc = {
    schema: "policyvault-amount-vectors/1",
    generatedBy: "core/model/tools/gen-amount-vectors.js (deterministic: same core/model/amounts.js => same file; regenerate + byte-compare with --check)",
    sourceModule: "core/model/amounts.js",
    maxSompi: MAX_SOMPI.toString(),
    vectors
  };
  return `${JSON.stringify(doc, null, 2)}\n`;
}

function main() {
  const content = generate();
  const check = process.argv.includes("--check");
  if (check) {
    const existing = fs.existsSync(OUT_PATH) ? fs.readFileSync(OUT_PATH, "utf8") : null;
    if (existing !== content) {
      process.stderr.write("amount-vectors DRIFT: core/model/test/fixtures/amount-vectors.json does not match a deterministic regeneration from core/model/amounts.js\n");
      process.exit(1);
    }
    process.stdout.write("amount-vectors OK: byte-identical regeneration\n");
    return;
  }
  fs.mkdirSync(path.dirname(OUT_PATH), { recursive: true });
  fs.writeFileSync(OUT_PATH, content);
  process.stdout.write(`wrote ${path.relative(path.join(__dirname, "..", "..", ".."), OUT_PATH)} (${INPUTS.length} vectors)\n`);
}

if (require.main === module) main();
module.exports = { generate, OUT_PATH, INPUTS };
