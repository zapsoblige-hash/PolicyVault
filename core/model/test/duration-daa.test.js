"use strict";

/*
 * UNIT — core/model/duration-daa.js, the ONE human-duration <-> DAA
 * conversion path (owner UX directive 2026-09-05 §5).
 *
 * Pins: the source-verified basis (10 DAA/s), unambiguous units, exact
 * integer arithmetic (no rounding — a security delay can never be
 * silently shortened), whole-number-only input with actionable precision
 * refusals, generation-specific bounds that fail closed, preset round
 * trips, EXISTING exact values round-tripping UNCHANGED even when they map
 * to no preset, and the approximate description used everywhere.
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const D = require("../duration-daa");

test("basis: 10 DAA per second; 1 day = 24 hours = 864000 DAA; 1 week = 7 days", () => {
  assert.equal(D.DAA_PER_SECOND, 10n);
  assert.equal(D.UNIT_SECONDS.hour, 3600n);
  assert.equal(D.UNIT_SECONDS.day, 24n * 3600n);
  assert.equal(D.UNIT_SECONDS.week, 7n * 24n * 3600n);
  assert.equal(D.humanToDaa({ value: 1, unit: "day" }), 864000n);
  assert.equal(D.humanToDaa({ value: "1", unit: "week" }), 6048000n);
  assert.equal(D.humanToDaa({ value: 24n, unit: "hour" }), D.humanToDaa({ value: 1, unit: "day" }));
});

test("exact integer arithmetic: no rounding, ever (large values, leading zeros)", () => {
  assert.equal(D.humanToDaa({ value: "007", unit: "day" }), 7n * 864000n);
  assert.equal(D.humanToDaa({ value: "123456789", unit: "hour" }), 123456789n * 36000n);
});

test("whole numbers only: decimals are refused with the whole-number equivalent suggested, never truncated", () => {
  assert.throws(() => D.humanToDaa({ value: "1.5", unit: "day" }), (e) => {
    assert.equal(e.code, "DURATION_PRECISION");
    assert.match(e.message, /36 hours/);
    return true;
  });
  assert.throws(() => D.humanToDaa({ value: "0.5", unit: "week" }), (e) => { assert.equal(e.code, "DURATION_PRECISION"); assert.match(e.message, /84 hours/); return true; });
  assert.throws(() => D.humanToDaa({ value: "2.25", unit: "hour" }), (e) => { assert.equal(e.code, "DURATION_PRECISION"); return true; });
  assert.throws(() => D.humanToDaa({ value: 1.5, unit: "day" }), (e) => { assert.equal(e.code, "DURATION_VALUE_INVALID"); return true; });
});

test("invalid values / units fail closed with codes", () => {
  for (const v of ["", " ", "0", "-1", "abc", "1e3", "NaN", "Infinity", null, undefined, {}, []]) {
    assert.throws(() => D.humanToDaa({ value: v, unit: "day" }), (e) => /DURATION_VALUE_INVALID|DURATION_PRECISION/.test(e.code), `value ${JSON.stringify(v)}`);
  }
  for (const u of ["month", "year", "days", "", null, "__proto__", "constructor"]) {
    assert.throws(() => D.humanToDaa({ value: 1, unit: u }), (e) => e.code === "DURATION_UNIT_INVALID", `unit ${JSON.stringify(u)}`);
  }
  assert.throws(() => D.humanToDaa(null), (e) => e.code === "DURATION_VALUE_INVALID");
});

test("describeDaa: approximate text, exact decomposition, tenths kept", () => {
  assert.equal(D.describeDaa(864000n).text, "about 1 day");
  assert.equal(D.describeDaa("6048000", { largestUnit: "day" }).text, "about 7 days");
  assert.equal(D.describeDaa("6048000", { largestUnit: "week" }).text, "about 1 week");
  assert.equal(D.describeDaa(864000n + 6n * 36000n).text, "about 1 day 6 hours");
  const odd = D.describeDaa(1005n); // 100.5 seconds
  assert.equal(odd.wholeSeconds, false);
  assert.equal(odd.text, "about 1 minute 40 seconds");
  assert.equal(odd.exactText, "1 minute 40 seconds 5/10 second");
  assert.equal(D.describeDaa(0n).text, "about 0 seconds");
  assert.equal(D.describeDaa(5n).exactText, "0 seconds 5/10 second");
  assert.throws(() => D.describeDaa("-1"), (e) => e.code === "DAA_INVALID");
  assert.throws(() => D.describeDaa("1.5"), (e) => /DAA_INVALID|DURATION_PRECISION/.test(e.code));
});

test("daaToHumanPeriod keeps the SDK contract: whole single units, else exact seconds; garbage echoes", () => {
  assert.equal(D.daaToHumanPeriod("864000"), "1 day");
  assert.equal(D.daaToHumanPeriod("36000"), "1 hour");
  assert.equal(D.daaToHumanPeriod("216000"), "6 hours");
  assert.equal(D.daaToHumanPeriod("6048000"), "1 week");
  assert.equal(D.daaToHumanPeriod("12096000"), "2 weeks");
  assert.equal(D.daaToHumanPeriod("1000"), "100 seconds");
  assert.equal(D.daaToHumanPeriod("1005"), "100.5 seconds");
  assert.equal(D.daaToHumanPeriod("x"), "x");
  assert.equal(D.daaToHumanPeriod("0"), "0");
});

test("settings: every preset is inside its bounds and its DAA is exact", () => {
  for (const s of Object.values(D.DURATION_SETTINGS)) {
    for (const p of s.presets) {
      assert.equal(p.daa, D.humanToDaa({ value: p.value, unit: p.unit }).toString(), `${s.kind}/${p.key}`);
      assert.ok(BigInt(p.daa) >= BigInt(s.minDaa) && BigInt(p.daa) <= BigInt(s.maxDaa));
    }
    assert.ok(s.presets.some((p) => p.key === s.defaultPreset), `${s.kind} default preset exists`);
  }
  assert.equal(D.DURATION_SETTINGS.budgetPeriod.minDaa, "36000");
  assert.equal(D.DURATION_SETTINGS.budgetPeriod.maxDaa, (604800n * 53n * 10n).toString());
  assert.equal(D.DURATION_SETTINGS.rootRecoveryDelay.maxDaa, "4294967295");
  assert.equal(D.DURATION_SETTINGS.rootSuccessionDelay.minDaa, "1");
});

test("durationSettingFor: generation-specific; unknown setting or generation FAILS CLOSED", () => {
  assert.equal(D.durationSettingFor("budgetPeriod", "policyvault-0.4.1").kind, "budgetPeriod");
  assert.equal(D.durationSettingFor("rootRecoveryDelay", "policyvault-0.7-root").kind, "rootRecoveryDelay");
  assert.throws(() => D.durationSettingFor("budgetPeriod", "policyvault-0.7-root"), (e) => e.code === "DURATION_SETTING_UNKNOWN");
  assert.throws(() => D.durationSettingFor("rootRecoveryDelay", "policyvault-0.4.1"), (e) => e.code === "DURATION_SETTING_UNKNOWN");
  assert.throws(() => D.durationSettingFor("nope"), (e) => e.code === "DURATION_SETTING_UNKNOWN");
  assert.throws(() => D.durationSettingFor("__proto__"), (e) => e.code === "DURATION_SETTING_UNKNOWN");
  assert.throws(() => D.durationSettingFor("constructor"), (e) => e.code === "DURATION_SETTING_UNKNOWN");
});

test("normalizeDurationSelection: presets and custom values round-trip exactly", () => {
  const s = D.DURATION_SETTINGS.budgetPeriod;
  const p = D.normalizeDurationSelection(s, { mode: "preset", preset: "1d" });
  assert.deepEqual([p.daa, p.source, p.preset, p.exact], ["864000", "preset", "1d", true]);
  const c = D.normalizeDurationSelection(s, { mode: "custom", value: "36", unit: "hour" });
  assert.deepEqual([c.daa, c.source, c.preset], ["1296000", "custom", null]);
  const c2 = D.normalizeDurationSelection(s, { mode: "custom", value: "7", unit: "day" });
  assert.equal(c2.preset, "1w", "a custom value equal to a preset is recognised as that preset");
  assert.equal(c2.describe.text, "about 1 week");
  const r = D.DURATION_SETTINGS.rootRecoveryDelay;
  assert.equal(D.normalizeDurationSelection(r, { mode: "preset", preset: "30d" }).daa, "25920000");
  assert.equal(D.normalizeDurationSelection(r, { mode: "custom", value: "90", unit: "day" }).preset, "90d");
});

test("normalizeDurationSelection: out-of-range custom values are REFUSED (never clamped), with bounds in the message", () => {
  const s = D.DURATION_SETTINGS.budgetPeriod;
  assert.doesNotThrow(() => D.normalizeDurationSelection(s, { mode: "custom", value: "30", unit: "hour" })); // 30 h is in range
  assert.throws(() => D.normalizeDurationSelection(s, { mode: "custom", value: "54", unit: "week" }), (e) => { assert.equal(e.code, "DURATION_OUT_OF_RANGE"); assert.match(e.message, /1 hour .. 53 weeks/); return true; });
  assert.doesNotThrow(() => D.normalizeDurationSelection(s, { mode: "custom", value: "53", unit: "week" }));
  assert.doesNotThrow(() => D.normalizeDurationSelection(s, { mode: "custom", value: "1", unit: "hour" }));
  const r = D.DURATION_SETTINGS.rootRecoveryDelay;
  assert.throws(() => D.normalizeDurationSelection(r, { mode: "custom", value: "5000", unit: "day" }), (e) => e.code === "DURATION_OUT_OF_RANGE"); // 4,320,000,000 > 2^32-1
  assert.doesNotThrow(() => D.normalizeDurationSelection(r, { mode: "custom", value: "4971", unit: "day" })); // 4,294,944,000 <= bound
  assert.throws(() => D.normalizeDurationSelection(r, { mode: "custom", value: "1.5", unit: "day" }), (e) => e.code === "DURATION_PRECISION");
  assert.throws(() => D.normalizeDurationSelection(r, { mode: "preset", preset: "1h" }), (e) => e.code === "DURATION_VALUE_INVALID", "a preset of another setting is not silently accepted");
  assert.throws(() => D.normalizeDurationSelection(r, { mode: "nope" }), (e) => e.code === "DURATION_VALUE_INVALID");
  assert.throws(() => D.normalizeDurationSelection(r, null), (e) => e.code === "DURATION_VALUE_INVALID");
});

test("normalizeDurationSelection: an EXISTING exact value round-trips unchanged, even off-preset and outside the product range", () => {
  const s = D.DURATION_SETTINGS.budgetPeriod;
  const e1 = D.normalizeDurationSelection(s, { mode: "existing", daa: "86400" }); // 2.4 hours — no preset, in range
  assert.deepEqual([e1.daa, e1.source, e1.preset, e1.outOfProductRange], ["86400", "existing", null, false]);
  assert.equal(e1.describe.text, "about 2 hours 24 minutes");
  const e2 = D.normalizeDurationSelection(s, { mode: "existing", daa: "1000" }); // below the product minimum but a valid live value
  assert.deepEqual([e2.daa, e2.outOfProductRange, e2.exact], ["1000", true, true]);
  const e3 = D.normalizeDurationSelection(s, { mode: "existing", daa: "1005" });
  assert.equal(e3.exact, false, "a value that is not a whole number of seconds is flagged, still preserved");
  assert.equal(e3.daa, "1005");
  const e4 = D.normalizeDurationSelection(s, { mode: "existing", daa: 864000n });
  assert.equal(e4.preset, "1d");
  assert.throws(() => D.normalizeDurationSelection(s, { mode: "existing", daa: "0" }), (e) => e.code === "DAA_INVALID");
  assert.throws(() => D.normalizeDurationSelection(D.DURATION_SETTINGS.rootRecoveryDelay, { mode: "existing", daa: "4294967296" }), (e) => e.code === "DURATION_OUT_OF_RANGE");
  // rc15 review F-04: an existing value ABOVE the product maximum (53 weeks)
  // but within the covenant encoding bound round-trips flagged, exactly like
  // one below the product minimum — only the ENCODING bound refuses.
  const e5 = D.normalizeDurationSelection(s, { mode: "existing", daa: "320544001" });
  assert.deepEqual([e5.daa, e5.source, e5.outOfProductRange], ["320544001", "existing", true]);
  const MAX_SOMPI = require("../amounts").MAX_SOMPI;
  const e6 = D.normalizeDurationSelection(s, { mode: "existing", daa: MAX_SOMPI.toString() });
  assert.deepEqual([e6.daa, e6.outOfProductRange], [MAX_SOMPI.toString(), true]);
  assert.throws(() => D.normalizeDurationSelection(s, { mode: "existing", daa: (MAX_SOMPI + 1n).toString() }), (e) => e.code === "DURATION_OUT_OF_RANGE" && /accepted range/.test(e.message));
  // the budget-period bound IS the v0.4.1 agent-policy leaf parser's bound
  // (agent-merkle-v4 parsePositiveSompi -> amounts MAX_SOMPI; rc16 review
  // N-01) — pinned against the source so the two can never drift apart
  assert.equal(String(s.encodingMaxDaa), MAX_SOMPI.toString());
  const v4src = require("fs").readFileSync(require("path").join(__dirname, "..", "agent-merkle-v4.js"), "utf8");
  assert.match(v4src, /periodLengthDaa: parsePositiveSompi\(input\.periodLengthDaa, "agentPolicy\.periodLengthDaa"\)/);
  for (const k of ["rootRecoveryDelay", "rootSuccessionDelay"]) assert.equal(D.DURATION_SETTINGS[k].encodingMaxDaa, D.DURATION_SETTINGS[k].maxDaa, `${k}: the product range IS the covenant encoding range`);
});

test("presetForDaa / boundsText", () => {
  const r = D.DURATION_SETTINGS.rootRecoveryDelay;
  assert.equal(D.presetForDaa(r, "6048000"), "7d");
  assert.equal(D.presetForDaa(r, "6048001"), null);
  assert.equal(D.boundsText(r), "0 seconds .. 4971 days 38 minutes");
  assert.equal(D.boundsText(D.DURATION_SETTINGS.budgetPeriod), "1 hour .. 53 weeks");
});

test("the measurement note is the fixed sentence every duration control shows", () => {
  assert.equal(D.MEASUREMENT_NOTE, "Measured using Kaspa network progress, so the elapsed time is approximate.");
});
