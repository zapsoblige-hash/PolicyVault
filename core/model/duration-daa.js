"use strict";

/*
 * PolicyVault — THE ONE conversion path between human durations (hours /
 * days / weeks) and Kaspa DAA score, shared by the SDK
 * (sdk/src/ux-normalize-v4.js re-exports it), the browser (through the
 * reviewed web/core-bundle.js closure) and the mobile client (through the
 * vendored copy of that bundle). No other file may carry its own
 * DAA-per-second constant, unit table, or bound (owner UX directive
 * 2026-09-05 §5: "Convert through one tested normalization path ... never
 * duplicate an arbitrary conversion constant in web and mobile").
 *
 * BASIS (verified in source, not inferred from a screenshot): both
 * operational networks run 10 blocks/second and the DAA score advances by
 * one per block — testnet-10 AND mainnet use BlockrateParams::new::<10>()
 * with Crescendo activated (~/rusty-kaspa/consensus/core/src/config/
 * params.rs, MAINNET_PARAMS / TESTNET_PARAMS, source-verified 2026-08-22).
 * The frozen reference policies use periodLengthDaa 864000 for a ~1-day
 * period. DAA score is NETWORK PROGRESS, not a clock: DAA -> wall time is
 * APPROXIMATE by protocol nature. Every rendered duration says so.
 *
 * ARITHMETIC: BigInt only. A human duration is value x unitSeconds x
 * DAA_PER_SECOND — an exact integer product, so nothing is ever rounded,
 * and in particular a security delay can never be silently shortened. The
 * reverse direction is exact rational: daa / 10 seconds with the remainder
 * kept as tenths of a second. Whole-number input only: "1.5 days" is
 * refused with the whole-number equivalent suggested (36 hours), never
 * truncated.
 *
 * UNITS (unambiguous, fixed): 1 hour = 3600 s; 1 day = 24 hours; 1 week =
 * 7 days. Calendar months/years are NOT units (they are not fixed lengths).
 *
 * SETTINGS are generation-specific. A setting names the covenant
 * generation(s) it applies to, its encoding/product bounds, and the presets
 * a UI may offer. Unknown settings / generations FAIL CLOSED.
 */

const DAA_PER_SECOND = 10n;
const UNIT_SECONDS = Object.freeze({ hour: 3600n, day: 86400n, week: 604800n });
const UNIT_ORDER = Object.freeze(["week", "day", "hour"]);
const UNIT_LABEL = Object.freeze({ week: ["week", "weeks"], day: ["day", "days"], hour: ["hour", "hours"], minute: ["minute", "minutes"], second: ["second", "seconds"] });

function fail(message, code, extra) {
  const e = new Error(`duration-daa: ${message}`);
  e.code = code;
  if (extra) Object.assign(e, extra);
  throw e;
}

function isPlainObject(v) {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

/* Exact BigInt from a digit string / integer / bigint; refuses everything else. */
function toBigInt(value, label, code) {
  if (typeof value === "bigint") return value;
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) fail(`${label} must be a safe whole number`, code);
    return BigInt(value);
  }
  if (typeof value === "string") {
    const s = value.trim();
    if (/^(0|[1-9][0-9]*)$/.test(s)) return BigInt(s);
    if (/^[0-9]+$/.test(s)) return BigInt(s); // leading zeros: still a whole number
    if (/^[0-9]*[.,][0-9]+$/.test(s) || /^[0-9]+[.,][0-9]*$/.test(s)) fail(`${label} must be a whole number of the chosen unit — decimals are not supported`, "DURATION_PRECISION");
    fail(`${label} must be a whole number`, code);
  }
  fail(`${label} is required`, code);
  return 0n;
}

/* A human duration -> exact DAA score (BigInt). */
function humanToDaa(input) {
  if (!isPlainObject(input)) fail("a { value, unit } duration is required", "DURATION_VALUE_INVALID");
  const unitSecs = Object.prototype.hasOwnProperty.call(UNIT_SECONDS, String(input.unit)) ? UNIT_SECONDS[input.unit] : undefined;
  if (unitSecs === undefined) fail(`unknown duration unit ${JSON.stringify(input.unit)} — supported: ${Object.keys(UNIT_SECONDS).join(", ")}`, "DURATION_UNIT_INVALID");
  const raw = input.value;
  if (typeof raw === "string" && /^\s*[0-9]*[.,][0-9]*\s*$/.test(raw) && raw.trim() !== "") {
    fail(precisionHint(raw.trim(), input.unit), "DURATION_PRECISION");
  }
  const value = toBigInt(raw, "duration value", "DURATION_VALUE_INVALID");
  if (value <= 0n) fail("duration value must be greater than 0", "DURATION_VALUE_INVALID");
  return value * unitSecs * DAA_PER_SECOND;
}

/* "1.5 days" -> "36 hours" when the decimal maps exactly to a smaller unit. */
function precisionHint(raw, unit) {
  const base = "Enter a whole number of the chosen unit (decimals are not supported)";
  const m = /^([0-9]*)[.,]([0-9]+)$/.exec(raw);
  if (!m || !UNIT_SECONDS[unit]) return `${base}.`;
  const whole = BigInt(m[1] || "0");
  const fracDigits = m[2];
  const denom = 10n ** BigInt(fracDigits.length);
  const numer = whole * denom + BigInt(fracDigits);
  const totalSeconds = numer * UNIT_SECONDS[unit];
  if (totalSeconds % denom !== 0n) return `${base}.`;
  const seconds = totalSeconds / denom;
  for (const u of ["day", "hour"]) {
    if (u === unit) continue;
    if (seconds % UNIT_SECONDS[u] === 0n && UNIT_SECONDS[u] < UNIT_SECONDS[unit]) {
      const n = seconds / UNIT_SECONDS[u];
      return `${base} — for ${raw} ${UNIT_LABEL[unit][1]} enter ${n} ${n === 1n ? UNIT_LABEL[u][0] : UNIT_LABEL[u][1]}.`;
    }
  }
  return `${base}.`;
}

/* DAA -> exact seconds + tenths (10 DAA per second). */
function daaToSeconds(daa) {
  const d = toBigInt(daa, "DAA score", "DAA_INVALID");
  if (d < 0n) fail("DAA score must not be negative", "DAA_INVALID");
  return Object.freeze({ seconds: d / DAA_PER_SECOND, tenths: d % DAA_PER_SECOND });
}

function plural(count, unit) {
  const [one, many] = UNIT_LABEL[unit];
  return `${count} ${count === 1n ? one : many}`;
}

/*
 * Describe a DAA score as an APPROXIMATE human duration.
 *   largestUnit: "week" (budget periods) or "day" (waiting periods) — the
 *   largest unit the decomposition may use, so "7 days" stays "7 days" for a
 *   waiting period instead of becoming "1 week".
 * Returns { daa, seconds, tenths, parts, text, exactText, wholeSeconds }.
 *   text      — "about 1 day" / "about 1 day 6 hours" (at most the two
 *               largest non-zero parts; never rounds the number shown)
 *   exactText — the full decomposition incl. minutes/seconds/tenths.
 */
function describeDaa(daa, { largestUnit = "day" } = {}) {
  const { seconds, tenths } = daaToSeconds(daa);
  const units = largestUnit === "week" ? ["week", "day", "hour"] : largestUnit === "day" ? ["day", "hour"] : largestUnit === "hour" ? ["hour"] : fail(`unknown largestUnit ${JSON.stringify(largestUnit)}`, "DURATION_UNIT_INVALID");
  const parts = [];
  let rest = seconds;
  for (const u of units) {
    const n = rest / UNIT_SECONDS[u];
    if (n > 0n) parts.push({ unit: u, count: n });
    rest %= UNIT_SECONDS[u];
  }
  const minutes = rest / 60n;
  const secs = rest % 60n;
  if (minutes > 0n) parts.push({ unit: "minute", count: minutes });
  if (secs > 0n || parts.length === 0) parts.push({ unit: "second", count: secs });
  const shown = parts.slice(0, 2);
  const text = `about ${shown.map((p) => plural(p.count, p.unit)).join(" ")}`;
  const exact = parts.map((p) => plural(p.count, p.unit)).join(" ") + (tenths > 0n ? ` ${tenths}/10 second` : "");
  return Object.freeze({
    daa: toBigInt(daa, "DAA score", "DAA_INVALID").toString(),
    seconds,
    tenths,
    wholeSeconds: tenths === 0n,
    parts: Object.freeze(parts.map((p) => Object.freeze({ ...p }))),
    text,
    exactText: exact
  });
}

/* Canonical "N unit(s)" when the DAA score is exactly a whole number of ONE
 * unit (the SDK's historical daaToHumanPeriod contract); otherwise the
 * approximate text without the "about" prefix. Never throws on garbage:
 * echoes the input string (presentation convenience only). */
function daaToHumanPeriod(periodLengthDaa) {
  let daa;
  try { daa = toBigInt(periodLengthDaa, "DAA score", "DAA_INVALID"); } catch { return String(periodLengthDaa); }
  if (daa <= 0n) return String(periodLengthDaa);
  const { seconds, tenths } = daaToSeconds(daa);
  if (tenths === 0n) {
    for (const [name, secs] of [["week", 604800n], ["day", 86400n], ["hour", 3600n], ["minute", 60n]]) {
      if (seconds >= secs && seconds % secs === 0n) return plural(seconds / secs, name);
    }
    return plural(seconds, "second");
  }
  return `${seconds}.${tenths} seconds`;
}

/* ------------------------------------------------------------------ */
/* generation-specific settings                                        */
/* ------------------------------------------------------------------ */

function preset(key, value, unit, label) {
  return Object.freeze({ key, value, unit, label, daa: humanToDaa({ value, unit }).toString() });
}

const DURATION_SETTINGS = Object.freeze({
  /* Budget period of a delegate/agent policy: the rolling window over which
   * the spending budget is counted. Product range 1 hour .. 53 weeks (the
   * SDK's frozen product range; the covenant itself only requires > 0 via
   * the shared-core leaf normalizers). */
  budgetPeriod: Object.freeze({
    kind: "budgetPeriod",
    label: "Budget period",
    generations: Object.freeze(["policyvault-0.4.1"]),
    minDaa: (3600n * DAA_PER_SECOND).toString(),
    maxDaa: (604800n * 53n * DAA_PER_SECOND).toString(),
    /* The protocol's accepted range for a v0.4.1 periodLengthDaa is FAR wider
     * than the product range: the agent-policy leaf parser accepts any
     * positive value up to MAX_SOMPI (core/model/agent-merkle-v4
     * parsePositiveSompi; core/model/amounts MAX_SOMPI — pinned equal by
     * test; rc16 review N-01). An EXISTING exact value between the two must
     * round-trip, flagged — never be refused (rc15 review F-04). */
    encodingMaxDaa: "2900000000000000000",
    largestUnit: "week",
    rolling: true,
    presets: Object.freeze([preset("1h", 1n, "hour", "1 hour"), preset("6h", 6n, "hour", "6 hours"), preset("1d", 1n, "day", "1 day"), preset("1w", 1n, "week", "1 week")]),
    defaultPreset: "1d"
  }),
  /* Organizational root recovery waiting period: relative age of the current
   * root output before the recovery quorum may act. Covenant encoding bound
   * 1 .. 2^32-1 (core/model/vault-state-v7-root normalizeRootTemplateV7). */
  rootRecoveryDelay: Object.freeze({
    kind: "rootRecoveryDelay",
    label: "Recovery waiting period",
    generations: Object.freeze(["policyvault-0.7-root"]),
    minDaa: "1",
    maxDaa: "4294967295",
    encodingMaxDaa: "4294967295",
    largestUnit: "day",
    rolling: false,
    presets: Object.freeze([preset("1d", 1n, "day", "1 day"), preset("7d", 7n, "day", "7 days"), preset("30d", 30n, "day", "30 days"), preset("90d", 90n, "day", "90 days")]),
    defaultPreset: "30d"
  }),
  rootSuccessionDelay: Object.freeze({
    kind: "rootSuccessionDelay",
    label: "Successor waiting period",
    generations: Object.freeze(["policyvault-0.7-root"]),
    minDaa: "1",
    maxDaa: "4294967295",
    encodingMaxDaa: "4294967295",
    largestUnit: "day",
    rolling: false,
    presets: Object.freeze([preset("1d", 1n, "day", "1 day"), preset("7d", 7n, "day", "7 days"), preset("30d", 30n, "day", "30 days"), preset("90d", 90n, "day", "90 days")]),
    defaultPreset: "90d"
  })
});

/* Self-check at load: every preset lies inside its setting's bounds. */
for (const s of Object.values(DURATION_SETTINGS)) {
  for (const p of s.presets) {
    if (BigInt(p.daa) < BigInt(s.minDaa) || BigInt(p.daa) > BigInt(s.maxDaa)) throw new Error(`duration-daa: preset ${s.kind}/${p.key} lies outside its own bounds`);
  }
}

/* Resolve a setting for a covenant generation — unknown pairs FAIL CLOSED. */
function durationSettingFor(kind, contractVersion) {
  const s = Object.prototype.hasOwnProperty.call(DURATION_SETTINGS, String(kind)) ? DURATION_SETTINGS[kind] : null;
  if (!s) fail(`unknown duration setting ${JSON.stringify(kind)} — failing closed`, "DURATION_SETTING_UNKNOWN");
  if (contractVersion !== undefined && !s.generations.includes(String(contractVersion))) {
    fail(`${s.label} is not a setting of covenant generation ${JSON.stringify(contractVersion)} — failing closed`, "DURATION_SETTING_UNKNOWN");
  }
  return s;
}

function presetForDaa(setting, daa) {
  const d = toBigInt(daa, "DAA score", "DAA_INVALID").toString();
  const hit = setting.presets.find((p) => p.daa === d);
  return hit ? hit.key : null;
}

function withinBounds(setting, daa) {
  return daa >= BigInt(setting.minDaa) && daa <= BigInt(setting.maxDaa);
}

function boundsText(setting) {
  return `${describeDaa(setting.minDaa, { largestUnit: setting.largestUnit }).text.replace(/^about /, "")} .. ${describeDaa(setting.maxDaa, { largestUnit: setting.largestUnit }).text.replace(/^about /, "")}`;
}

/*
 * Normalize ONE duration selection for a setting.
 *   selection = { mode: "preset", preset: "1d" }
 *             | { mode: "custom", value, unit }
 *             | { mode: "existing", daa }       (an imported/live exact value
 *                                                that must round-trip UNCHANGED)
 * Returns { daa (digit string), source, exact (bool), preset|null,
 *           describe, outOfProductRange (existing only: outside minDaa..maxDaa
 *           but within the protocol's accepted range — kept, never refused) }.
 * Fails closed (never clamps, never rounds) on invalid / out-of-bounds
 * input with an actionable message.
 */
function normalizeDurationSelection(setting, selection) {
  if (!setting || !Array.isArray(setting.presets)) fail("a duration setting is required", "DURATION_SETTING_UNKNOWN");
  if (!isPlainObject(selection)) fail(`${setting.label}: choose a preset or enter a custom duration`, "DURATION_VALUE_INVALID");
  let daa;
  let source;
  let key = null;
  if (selection.mode === "preset") {
    const p = setting.presets.find((x) => x.key === selection.preset);
    if (!p) fail(`${setting.label}: unknown preset ${JSON.stringify(selection.preset)}`, "DURATION_VALUE_INVALID");
    daa = BigInt(p.daa);
    source = "preset";
    key = p.key;
  } else if (selection.mode === "custom") {
    try {
      daa = humanToDaa({ value: selection.value, unit: selection.unit });
    } catch (e) {
      throw Object.assign(new Error(`${setting.label}: ${e.message.replace(/^duration-daa: /, "")}`), { code: e.code });
    }
    source = "custom";
    key = presetForDaa(setting, daa);
  } else if (selection.mode === "existing") {
    daa = toBigInt(selection.daa, `${setting.label} (existing exact value)`, "DAA_INVALID");
    if (daa < 1n) fail(`${setting.label}: the existing value ${daa} is not a positive DAA score`, "DAA_INVALID");
    // Only the covenant ENCODING bound refuses an existing value; the product
    // range (minDaa..maxDaa) is reported as a flag so the exact value can be
    // kept unchanged on display and resubmit (directive §5).
    if (daa > BigInt(setting.encodingMaxDaa)) fail(`${setting.label}: the existing value ${daa} exceeds the protocol's accepted range (max ${setting.encodingMaxDaa})`, "DURATION_OUT_OF_RANGE");
    source = "existing";
    key = presetForDaa(setting, daa);
    const d = describeDaa(daa, { largestUnit: setting.largestUnit });
    return Object.freeze({ daa: daa.toString(), source, preset: key, exact: d.wholeSeconds, describe: d, outOfProductRange: !withinBounds(setting, daa) });
  } else {
    fail(`${setting.label}: choose a preset or enter a custom duration`, "DURATION_VALUE_INVALID");
  }
  if (!withinBounds(setting, daa)) {
    fail(`${setting.label} must be between ${boundsText(setting)} (you chose ${describeDaa(daa, { largestUnit: setting.largestUnit }).text})`, "DURATION_OUT_OF_RANGE");
  }
  const d = describeDaa(daa, { largestUnit: setting.largestUnit });
  return Object.freeze({ daa: daa.toString(), source, preset: key, exact: d.wholeSeconds, describe: d, outOfProductRange: false });
}

/* The fixed helper sentence every duration control shows. */
const MEASUREMENT_NOTE = "Measured using Kaspa network progress, so the elapsed time is approximate.";

module.exports = {
  DAA_PER_SECOND,
  UNIT_SECONDS,
  UNIT_ORDER,
  DURATION_SETTINGS,
  MEASUREMENT_NOTE,
  humanToDaa,
  daaToSeconds,
  describeDaa,
  daaToHumanPeriod,
  durationSettingFor,
  presetForDaa,
  normalizeDurationSelection,
  boundsText
};
