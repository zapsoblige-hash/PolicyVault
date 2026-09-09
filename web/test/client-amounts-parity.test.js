"use strict";

/*
 * PARITY GATE — browser KAS→sompi client parsers vs the canonical
 * core/model/amounts.js.
 *
 * `web/test/fixtures/golden-client-amounts.json` was captured from the
 * ORIGINAL committed sources (web/app.js promptSompi/promptCheck and
 * web/app-v4.js kasToSompiClient) BEFORE they were migrated, over a
 * 41-vector battery, exactly the method core/model/test/golden-f1-merkle
 * uses. This suite proves, vector by vector, what the migration did:
 *
 *   1. AGREEMENT — on every input the canonical parser accepts, the
 *      migrated client produces the byte-identical digit string the
 *      original produced. No accepted amount changed value.
 *   2. FAIL-CLOSED — on every input where the original silently produced
 *      a value the canonical grammar refuses (hex/exponent forms, a 9th
 *      decimal, sub-sompi rounded to 0, and float precision loss on large
 *      amounts), the migrated client now REFUSES instead of guessing.
 *   3. NO REGRESSION — web/ contains no floating-point KAS→sompi
 *      conversion and no second amount grammar anywhere.
 *
 * The canonical parser is reached exactly as the browser reaches it:
 * through the COMMITTED web/core-bundle.js evaluated in a browser-shaped
 * vm context (no require/module/process/Buffer), not through a Node
 * require of core/. If the bundle stopped exposing it, these tests fail.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");

const { loadCommittedBundleInBrowserGlobal } = require("../../core/crossruntime/sandbox.js");
const canonicalAmounts = require("../../core/model/amounts.js");

const WEB_DIR = path.join(__dirname, "..");
const GOLDEN = JSON.parse(fs.readFileSync(path.join(__dirname, "fixtures", "golden-client-amounts.json"), "utf8"));

const { PolicyVaultCore } = loadCommittedBundleInBrowserGlobal();

/* The MIGRATED client behaviour, reproduced exactly: both web/app.js
 * kasToSompiCanonical (positive-only) and web/app-v4.js kasToSompiClient
 * (zero allowed) are `core.amounts.kasToSompi` + a fail-closed catch. */
function migratedAppJs(value) {
  let sompi;
  try {
    sompi = PolicyVaultCore.amounts.kasToSompi(String(value).trim());
  } catch {
    return null;
  }
  return sompi <= 0n ? null : sompi.toString();
}
function migratedAppV4(value) {
  try {
    return PolicyVaultCore.amounts.kasToSompi(String(value).trim()).toString();
  } catch {
    return null;
  }
}

test("the browser bundle exposes the canonical amounts module, and it is the SAME function as core/model/amounts.js", () => {
  assert.equal(typeof PolicyVaultCore.amounts.kasToSompi, "function");
  assert.equal(typeof PolicyVaultCore.amounts.sompiToKas, "function");
  assert.equal(PolicyVaultCore.amounts.MAX_SOMPI, canonicalAmounts.MAX_SOMPI, "the browser must carry the SAME supply ceiling as Node");
  assert.equal(PolicyVaultCore.amounts.SOMPI_PER_KAS, canonicalAmounts.SOMPI_PER_KAS);
  for (const row of GOLDEN.vectors) {
    const node = (() => {
      try {
        return canonicalAmounts.kasToSompi(String(row.input).trim()).toString();
      } catch {
        return null;
      }
    })();
    const browser = migratedAppV4(row.input);
    assert.equal(browser, node, `cross-runtime: ${JSON.stringify(row.input)} must parse identically in Node and in the committed bundle`);
  }
});

test("PARITY: every amount the canonical parser accepts keeps its EXACT original value (no accepted amount changed)", () => {
  let agreed = 0;
  for (const row of GOLDEN.vectors) {
    if (!row.canonical.ok) continue;
    const expected = row.canonical.value;
    /* app-v4: the original was integer-exact, so it must AGREE outright */
    assert.equal(row.originalKasToSompiClient, expected, `app-v4 original must already agree on ${JSON.stringify(row.input)}`);
    assert.equal(migratedAppV4(row.input), expected, `app-v4 migrated value changed for ${JSON.stringify(row.input)}`);
    /* app.js: identical for every accepted POSITIVE amount (its callers require > 0) */
    if (BigInt(expected) > 0n) {
      assert.equal(row.originalPrompt, expected, `app.js original must agree on the accepted amount ${JSON.stringify(row.input)}`);
      assert.equal(migratedAppJs(row.input), expected, `app.js migrated value changed for ${JSON.stringify(row.input)}`);
    } else {
      assert.equal(migratedAppJs(row.input), null, "app.js requires a positive amount");
    }
    agreed += 1;
  }
  assert.ok(agreed >= 12, `expected a substantial accepted set, got ${agreed}`);
});

test("FAIL-CLOSED: every input the ORIGINAL app.js silently mis-converted is now REFUSED (with the recorded defect)", () => {
  /* The exact defect set the capture recorded. Each entry is
   * [input, the value the FLOATING-POINT original produced]. */
  const DEFECTS = [
    ["1.", "100000000"], // trailing dot accepted
    [".5", "50000000"], // leading dot accepted
    ["+1", "100000000"], // sign accepted
    ["1e3", "100000000000"], // exponent -> 1000 KAS
    ["1E3", "100000000000"],
    ["0x10", "1600000000"], // hex -> 16 KAS
    ["1.5e2", "15000000000"],
    ["1.123456789", "112345679"], // 9th decimal silently rounded
    ["1.0000000000", "100000000"], // >8 decimals accepted
    ["0.1000000000000000055511151231257827", "10000000"],
    ["0.000000001", "0"], // sub-sompi silently rounded to ZERO
    ["9007199254740993", "900719925474099200000000"], // float loss: 1000 KAS low
    ["90071992547.40993", "9007199254740993024"], // float loss: 24 sompi high
    ["29000000001", "2900000000099999744"], // above MAX_SOMPI and imprecise
    ["1000000000000", "100000000000000000000"] // far above the supply ceiling
  ];
  const byInput = new Map(GOLDEN.vectors.map((r) => [r.input, r]));
  for (const [input, originalValue] of DEFECTS) {
    const row = byInput.get(input);
    assert.ok(row, `the golden fixture must carry the vector ${JSON.stringify(input)}`);
    assert.equal(row.originalPrompt, originalValue, `the fixture must pin the ORIGINAL value for ${JSON.stringify(input)}`);
    assert.equal(row.canonical.ok, false, `${JSON.stringify(input)} must not be canonically parseable`);
    assert.equal(migratedAppJs(input), null, `${JSON.stringify(input)} must now be REFUSED, not converted to ${originalValue}`);
    assert.equal(migratedAppV4(input), null, `${JSON.stringify(input)} must now be REFUSED in app-v4 too`);
  }
});

test("FAIL-CLOSED: app-v4's missing supply ceiling is closed (the original accepted amounts above MAX_SOMPI)", () => {
  const overSupply = GOLDEN.vectors.filter((r) => r.originalKasToSompiClient !== null && !r.canonical.ok);
  assert.ok(overSupply.length > 0, "the capture recorded at least one over-ceiling acceptance");
  for (const row of overSupply) {
    assert.ok(BigInt(row.originalKasToSompiClient) > canonicalAmounts.MAX_SOMPI, `${JSON.stringify(row.input)} was accepted above MAX_SOMPI`);
    assert.equal(migratedAppV4(row.input), null, `${JSON.stringify(row.input)} must now be refused`);
  }
});

test("NO REGRESSION: no web/ source performs a floating-point KAS→sompi conversion or carries a second amount grammar", () => {
  const files = fs
    .readdirSync(WEB_DIR)
    .filter((f) => f.endsWith(".js") && f !== "core-bundle.js")
    .map((f) => ({ name: f, text: fs.readFileSync(path.join(WEB_DIR, f), "utf8") }));
  assert.ok(files.length >= 8, "the scan must actually see the web sources");
  for (const { name, text } of files) {
    /* the exact float conversion shape that was removed */
    assert.ok(!/Math\.round\s*\([^)]*\*\s*1e8\s*\)/.test(text), `${name}: floating-point KAS→sompi conversion reintroduced`);
    assert.ok(!/BigInt\s*\(\s*Math\.round/.test(text), `${name}: BigInt(Math.round(...)) on an amount path reintroduced`);
    /* a hand-rolled sompi multiplier outside the reviewed verifier */
    if (name !== "verify-intent.js") {
      assert.ok(!/\*\s*100000000n/.test(text), `${name}: hand-rolled KAS→sompi multiplication — use window.PolicyVaultCore.amounts`);
    }
  }
  /* the two migrated call sites actually go through the bundle */
  const appJs = files.find((f) => f.name === "app.js").text;
  const appV4 = files.find((f) => f.name === "app-v4.js").text;
  assert.match(appJs, /PolicyVaultCore[\s\S]{0,400}amounts\.kasToSompi/, "app.js must reach the canonical parser through the bundle");
  assert.match(appV4, /PolicyVaultCore[\s\S]{0,400}amounts\.kasToSompi/, "app-v4.js must reach the canonical parser through the bundle");
  /* the original float functions are gone (their source hashes cannot recur) */
  const crypto = require("crypto");
  for (const [label, meta] of Object.entries(GOLDEN.originalSources)) {
    if (!meta.usesFloatingPoint) continue;
    const file = label.split(":")[0].replace("web/", "");
    const fn = label.split(":")[1];
    const text = files.find((f) => f.name === file).text;
    const i = text.indexOf(`function ${fn}(`);
    assert.ok(i >= 0, `${label} must still exist (its implementation changed, not its name)`);
    let depth = 0;
    let started = false;
    let j = i;
    for (; j < text.length; j++) {
      const c = text[j];
      if (c === "{") {
        depth++;
        started = true;
      } else if (c === "}") {
        depth--;
        if (started && depth === 0) {
          j++;
          break;
        }
      }
    }
    const now = crypto.createHash("sha256").update(text.slice(i, j), "utf8").digest("hex");
    assert.notEqual(now, meta.sha256, `${label} must no longer be the captured floating-point implementation`);
  }
});

/*
 * RESIDUAL, recorded not fixed: web/verify-intent.js keeps its OWN
 * kasToSompi. It is a reviewed, byte-vendored signing artifact (mobile
 * ships the identical bytes), so it is proven in lockstep with the
 * canonical parser rather than rewritten — the same treatment
 * docs/postlaunch/cross-runtime-equivalence.md §3 gives the
 * canonical-json and sompiToKas twins. Any divergence fails HERE.
 */
test("TWIN LOCKSTEP: web/verify-intent.js's own kasToSompi agrees with core/model/amounts.js on every vector it accepts", () => {
  const src = fs.readFileSync(path.join(WEB_DIR, "verify-intent.js"), "utf8");
  const i = src.indexOf("function kasToSompi(value, field)");
  assert.ok(i > 0, "verify-intent.js must still define its twin parser");
  let depth = 0;
  let started = false;
  let j = i;
  for (; j < src.length; j++) {
    const c = src[j];
    if (c === "{") {
      depth++;
      started = true;
    } else if (c === "}") {
      depth--;
      if (started && depth === 0) {
        j++;
        break;
      }
    }
  }
  /* evaluate the twin in isolation with the two symbols it closes over */
  const twin = new Function(
    "SOMPI_PER_KAS",
    "refuse",
    `${src.slice(i, j)}; return kasToSompi;`
  )(100000000n, (code, message) => {
    const e = new Error(message);
    e.code = code;
    throw e;
  });

  let compared = 0;
  for (const row of GOLDEN.vectors) {
    const twinResult = (() => {
      try {
        return twin(row.input, "vector").toString();
      } catch {
        return null;
      }
    })();
    if (row.canonical.ok) {
      assert.equal(twinResult, row.canonical.value, `twin must equal the canonical parser on ${JSON.stringify(row.input)}`);
      compared += 1;
    } else if (twinResult !== null) {
      /* The ONE documented, funds-safe divergence: the twin has no supply
       * ceiling. It must never differ in any other way, and never on a
       * value at or below MAX_SOMPI. */
      assert.ok(
        BigInt(twinResult) > canonicalAmounts.MAX_SOMPI,
        `undocumented twin divergence on ${JSON.stringify(row.input)}: twin=${twinResult}, canonical refuses`
      );
    }
  }
  assert.ok(compared >= 12, `expected a substantial agreed set, got ${compared}`);
});
