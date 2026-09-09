"use strict";

/*
 * H2 browser-UX normalization for v0.4.1 (server/SDK-authoritative). The browser
 * collects human-friendly inputs (wallet addresses, KAS amounts, a
 * budget-reset period); this module derives the EXACT canonical agent policy the
 * v0.4.1 builder expects. It NEVER changes covenant/consensus semantics — it
 * only converts convenient representations into the canonical fields using the
 * project's own parsers (kasToSompi, resolveAddressIdentity). Consensus-visible
 * values are derived here (server side), not trusted from the browser:
 *   - periodStartDaa comes from the authoritative node DAA score (caller passes
 *     it in; browser values are ignored),
 *   - periodSpent is always 0 for a new agent.
 * The canonical object returned is byte-for-byte the same shape the existing
 * builder consumes (agentPk, maxPerSpend, periodBudget, periodLengthDaa,
 * periodStartDaa, periodSpent, approvalThreshold, agentMaxFeePerTx, recipients).
 */

const { kasToSompi } = require("./amounts");
const { resolveAddressIdentity } = require("./address-identity");
/*
 * THE ONE human-duration <-> DAA conversion path (owner UX directive
 * 2026-09-05 §5): the 10 DAA/second basis (source-verified in
 * ~/rusty-kaspa/consensus/core/src/config/params.rs, 2026-08-22), the unit
 * table (1 day = 24 h, 1 week = 7 d), the presets and the product range all
 * live in core/model/duration-daa.js and are shared verbatim by the browser
 * bundle and the mobile client. This module keeps its historical API and
 * error codes; it no longer carries a constant of its own.
 */
const durationDaa = require("../../core/model/duration-daa");

function fail(message, code = "UX_NORMALIZE_FAILED") {
  const e = new Error(`ux-normalize-v4: ${message}`);
  e.code = code;
  throw e;
}

const DAA_PER_SECOND = durationDaa.DAA_PER_SECOND;
// Practical product units for CUSTOM budget periods (directive: hours/days/weeks).
const UNIT_SECONDS = durationDaa.UNIT_SECONDS;
const BUDGET_PERIOD_SETTING = durationDaa.DURATION_SETTINGS.budgetPeriod;
const PERIOD_PRESETS = Object.freeze(Object.fromEntries(BUDGET_PERIOD_SETTING.presets.map((p) => [p.key, BigInt(p.daa)])));
// Supported PRODUCT range for a budget period (fail closed outside it — never
// silently clamp): 1 hour .. 53 weeks. Purely an application-layer bound. NOTE
// (adversarial review 2026-09-03, finding F1): the covenant carries NO
// periodLengthDaa > 0 check of its own — a zero-length period would make the
// PERIOD budget vacuous in-covenant; positivity is enforced by the shared-core
// leaf normalizers (core/model/agent-merkle-v4/v5/v6) and pinned by
// core/model/test/period-length-positive-invariant.test.js.
const MIN_PERIOD_DAA = BigInt(BUDGET_PERIOD_SETTING.minDaa); // 1 hour
const MAX_PERIOD_DAA = BigInt(BUDGET_PERIOD_SETTING.maxDaa); // 53 weeks (~1 year)
// A safe default per-agent max network fee cap (§10): comfortably above measured
// v0.4.1 spend fees (~0.037 KAS) without weakening the per-agent fee-cap model.
const DEFAULT_AGENT_MAX_FEE_PER_TX_KAS = "0.10";

/* Human budget period -> canonical periodLengthDaa (string). Accepts a preset
 * key ("1h"|"6h"|"1d"|"1w") or a custom { value, unit } with unit in
 * hour|day|week. Fails closed (never clamps) on zero/negative/blank/NaN/
 * non-integer/unsupported-unit input and on any result outside the supported
 * product range (1 hour .. 53 weeks). */
function budgetPeriodToDaa(period) {
  let daa;
  if (typeof period === "string") {
    daa = PERIOD_PRESETS[period];
    if (daa === undefined) fail(`unknown budget-period preset ${JSON.stringify(period)}`, "PERIOD_INVALID");
  } else if (period && typeof period === "object" && period.unit !== undefined) {
    const unitSecs = Object.prototype.hasOwnProperty.call(UNIT_SECONDS, String(period.unit)) ? UNIT_SECONDS[period.unit] : undefined;
    if (unitSecs === undefined) fail(`unknown budget-period unit ${JSON.stringify(period.unit)} — supported: ${Object.keys(UNIT_SECONDS).join(", ")}`, "PERIOD_UNIT_INVALID");
    const raw = String(period.value ?? "").trim();
    if (!/^[0-9]+$/.test(raw)) fail(`budget-period value must be a whole number, got ${JSON.stringify(period.value)}`, "PERIOD_INVALID");
    const value = BigInt(raw);
    if (value <= 0n) fail("budget-period value must be > 0", "PERIOD_INVALID");
    daa = durationDaa.humanToDaa({ value, unit: period.unit });
  } else {
    fail("budget period must be a preset key or { value, unit }", "PERIOD_INVALID");
  }
  if (daa < MIN_PERIOD_DAA || daa > MAX_PERIOD_DAA) {
    fail(`budget period is outside the supported range (${daaToHumanPeriod(MIN_PERIOD_DAA.toString())} .. ${daaToHumanPeriod(MAX_PERIOD_DAA.toString())})`, "PERIOD_OUT_OF_RANGE");
  }
  return daa.toString();
}

/* Canonical periodLengthDaa -> human-readable approximate duration ("1 hour",
 * "6 hours", "2 weeks", ...). Presentation convenience only — DAA→wall-time is
 * approximate by protocol nature and this string never enters consensus. */
function daaToHumanPeriod(periodLengthDaa) {
  return durationDaa.daaToHumanPeriod(periodLengthDaa);
}

function resolveXOnly(config, address, label) {
  if (typeof address !== "string" || !address.trim()) fail(`${label} address is required`, "ADDRESS_INVALID");
  let id;
  try {
    id = resolveAddressIdentity(config, address);
  } catch (e) {
    // resolveAddressIdentity fails closed on wrong network / bad checksum /
    // unsupported (non-PubKey) address type / mismatch.
    throw Object.assign(new Error(`ux-normalize-v4: ${label} ${e.message}`), { code: e.code || "ADDRESS_INVALID" });
  }
  return id.xOnlyPubkey;
}

/*
 * Derive the canonical v0.4.1 agent policy from friendly input.
 *   input: { agentAddress, maxPerSpendKas, budgetKas, budgetPeriod|periodLengthDaa,
 *            approvalThresholdKas, maxFeePerTxKas?, recipientAddresses:[...] }
 *   currentDaaScore: authoritative node virtual DAA score (BigInt|string).
 */
function normalizeAgentPolicyInputV4(config, input, currentDaaScore) {
  if (!input || typeof input !== "object") fail("agent input object required");
  const agentPk = resolveXOnly(config, input.agentAddress, "agent");

  const maxPerSpend = kasToSompi(input.maxPerSpendKas, "maxPerSpend").toString();
  if (BigInt(maxPerSpend) <= 0n) fail("maximum per transaction must be > 0 KAS", "MAX_PER_SPEND_INVALID");
  const periodBudget = kasToSompi(input.budgetKas, "budget").toString();
  if (BigInt(periodBudget) <= 0n) fail("budget must be > 0 KAS", "BUDGET_INVALID");
  if (BigInt(periodBudget) < BigInt(maxPerSpend)) {
    fail(`budget (${input.budgetKas} KAS) must be >= maximum per transaction (${input.maxPerSpendKas} KAS)`, "BUDGET_LT_MAX");
  }
  // approvalThreshold may be 0 (every spend needs approval); it must not be negative.
  const approvalThreshold = kasToSompi(input.approvalThresholdKas, "approvalThreshold").toString();
  const agentMaxFeePerTx = kasToSompi(input.maxFeePerTxKas ?? DEFAULT_AGENT_MAX_FEE_PER_TX_KAS, "maxFeePerTx").toString();
  if (BigInt(agentMaxFeePerTx) <= 0n) fail("maximum network fee per transaction must be > 0 KAS", "FEE_CAP_INVALID");

  const periodLengthDaa = input.periodLengthDaa !== undefined && input.periodLengthDaa !== null
    ? BigInt(String(input.periodLengthDaa)).toString()
    : budgetPeriodToDaa(input.budgetPeriod);
  if (BigInt(periodLengthDaa) <= 0n) fail("periodLengthDaa must be > 0", "PERIOD_INVALID");

  // SERVER-DERIVED (never browser-trusted): current node DAA + zero spent.
  if (currentDaaScore === undefined || currentDaaScore === null) fail("currentDaaScore (authoritative node DAA) is required — refusing a browser-supplied periodStartDaa", "PERIOD_START_REQUIRED");
  const periodStartDaa = BigInt(String(currentDaaScore)).toString();
  const periodSpent = "0";

  if (!Array.isArray(input.recipientAddresses) || input.recipientAddresses.length === 0) {
    fail("at least one allowed recipient address is required", "RECIPIENTS_REQUIRED");
  }
  const recipients = input.recipientAddresses.map((a, i) => resolveXOnly(config, a, `recipient[${i}]`));

  // Canonical shape — identical to what the existing v0.4.1 builder consumes.
  return { agentPk, maxPerSpend, periodBudget, periodLengthDaa, periodStartDaa, periodSpent, approvalThreshold, agentMaxFeePerTx, recipients };
}

/* v0.4/v0.4.1 frozen consensus model: exactly 10 approver slots. */
const MAX_APPROVERS = 10;

/* Friendly approver config -> canonical { approvers:[x-only,...], approvalM }.
 * The exact slot/distinctness/sentinel/approvalM semantics remain the frozen
 * state layer's (vault-state-v4 normalizeApprovers/normalizeStateV4 — the
 * authoritative reject); this layer resolves addresses to x-only and repeats
 * the same product rules EARLY with clear codes: max 10 approvers, distinct
 * addresses AND distinct resolved x-only identities, and
 * 0 <= M <= 10, M <= configured approvers, M >= 1 when approvers exist.
 * Nothing is truncated, merged, inferred, or reordered. */
function normalizeApproversInputV4(config, input) {
  if (!input || (input.addresses === undefined && input.approvers === undefined)) return { approvers: [], approvalM: "0" };
  const list = input.addresses ?? input.approvers ?? [];
  if (!Array.isArray(list)) fail("approvers must be a list of addresses", "APPROVERS_INVALID");
  if (list.length > MAX_APPROVERS) {
    fail(`${list.length} approvers configured; the maximum is ${MAX_APPROVERS}`, "APPROVERS_TOO_MANY");
  }
  const seenInput = new Set();
  const seenXOnly = new Set();
  const approvers = list.map((a, i) => {
    const raw = typeof a === "string" ? a.trim() : a;
    if (typeof raw === "string" && raw !== "" && seenInput.has(raw)) {
      fail(`approver[${i}] duplicates an earlier approver address`, "APPROVER_DUPLICATE");
    }
    if (typeof raw === "string") seenInput.add(raw);
    const x = resolveXOnly(config, a, `approver[${i}]`);
    if (seenXOnly.has(x)) fail(`approver[${i}] resolves to the same signing identity as an earlier approver`, "APPROVER_DUPLICATE");
    seenXOnly.add(x);
    return x;
  });
  const rawM = input.approvalM ?? (approvers.length ? approvers.length : 0);
  const mStr = String(rawM).trim();
  if (!/^[0-9]+$/.test(mStr)) fail(`required approvals (M) must be a whole number, got ${JSON.stringify(rawM)}`, "APPROVAL_M_INVALID");
  const m = Number(mStr);
  if (m > MAX_APPROVERS) fail(`required approvals (M=${m}) exceeds the maximum of ${MAX_APPROVERS}`, "APPROVAL_M_INVALID");
  if (m > approvers.length) fail(`required approvals (M=${m}) exceeds the ${approvers.length} configured approver(s)`, "APPROVAL_M_INVALID");
  if (approvers.length > 0 && m < 1) fail("required approvals (M) must be >= 1 when approvers are configured", "APPROVAL_M_INVALID");
  if (approvers.length === 0 && m !== 0) fail("required approvals (M) must be 0 when no approvers are configured", "APPROVAL_M_INVALID");
  return { approvers, approvalM: String(m) };
}

module.exports = {
  DAA_PER_SECOND,
  PERIOD_PRESETS,
  UNIT_SECONDS,
  MIN_PERIOD_DAA,
  MAX_PERIOD_DAA,
  MAX_APPROVERS,
  DEFAULT_AGENT_MAX_FEE_PER_TX_KAS,
  budgetPeriodToDaa,
  daaToHumanPeriod,
  normalizeAgentPolicyInputV4,
  normalizeApproversInputV4
};
