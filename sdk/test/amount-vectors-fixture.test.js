"use strict";

/*
 * Amounts parity — generated shared vector file (Wave 2, Track F: closes
 * gap G5, docs/postlaunch/hybrid-core-gap-analysis.md). The fixture
 * (core/model/test/fixtures/amount-vectors.json) is GENERATED from
 * core/model/amounts.js by core/model/tools/gen-amount-vectors.js (every
 * expected outcome is computed by calling the real parser, never hand-
 * typed) and consumed here AND by python/tests/test_amount_vectors_fixture.py
 * over the SAME file, so a change to the canonical parsing rules that
 * regenerates this fixture also changes what the Python suite must match —
 * exactly the mechanical parity gate gap G5 asked for.
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");

const { generate, OUT_PATH } = require("../../core/model/tools/gen-amount-vectors.js");
const { kasToSompi, parseSompi } = require("../src/amounts");

const FIXTURE = JSON.parse(fs.readFileSync(OUT_PATH, "utf8"));

test("REPRODUCIBLE: the committed amount-vectors fixture is byte-identical to a fresh regeneration from core/model/amounts.js", () => {
  const regenerated = generate();
  const committed = fs.readFileSync(OUT_PATH, "utf8");
  assert.equal(committed, regenerated, "core/model/test/fixtures/amount-vectors.json has drifted — run node core/model/tools/gen-amount-vectors.js");
});

test(`sdk/src/amounts.js (the re-export shim) reproduces all ${FIXTURE.vectors.length} fixture vectors exactly`, () => {
  for (const v of FIXTURE.vectors) {
    let kasOutcome;
    try {
      kasOutcome = { ok: true, value: kasToSompi(v.input).toString() };
    } catch (e) {
      kasOutcome = { ok: false, error: e.message };
    }
    assert.deepEqual(kasOutcome, v.kasToSompi, `kasToSompi(${JSON.stringify(v.input)})`);

    let sompiOutcome;
    try {
      sompiOutcome = { ok: true, value: parseSompi(v.input).toString() };
    } catch (e) {
      sompiOutcome = { ok: false, error: e.message };
    }
    assert.deepEqual(sompiOutcome, v.parseSompi, `parseSompi(${JSON.stringify(v.input)})`);
  }
});

test("at least 3 vectors are tagged with the documented Python ASCII-only-whitespace divergence (evidence the tag path is exercised)", () => {
  const tagged = FIXTURE.vectors.filter((v) => v.pythonDivergence === "ascii-only-whitespace");
  assert.ok(tagged.length >= 3, `expected >= 3 tagged vectors, got ${tagged.length}`);
  for (const v of tagged) {
    assert.equal(v.kasToSompi.ok, true, `${JSON.stringify(v.input)}: the JS side must ACCEPT for this to be a real divergence (Python is stricter)`);
  }
});
