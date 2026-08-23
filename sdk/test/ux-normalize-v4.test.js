"use strict";

/* SDK — H2 §27 browser-UX normalization tests (v0.4.1). The friendly-input layer
 * must derive the EXACT canonical agent policy the builder expects, with all
 * consensus-visible values validated/derived server-side. */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const { loadConfig } = require("../src/config");
const { normalizeAgentPolicyInputV4, normalizeApproversInputV4, budgetPeriodToDaa, PERIOD_PRESETS, DEFAULT_AGENT_MAX_FEE_PER_TX_KAS } = require("../src/ux-normalize-v4");
const { buildAgentTreeV4, normalizeAgentPolicyV4 } = require("../src/agent-merkle-v4");
const { buildRecipientTree } = require("../src/recipient-merkle-v3");

const config = loadConfig();
const kaspa = require(config.rustyKaspaModule);
const KEY = (v) => new kaspa.PrivateKey(v.toString(16).padStart(2, "0").repeat(32));
const ADDR = (v) => KEY(v).toPublicKey().toAddress(config.networkId).toString();
const XO = (v) => KEY(v).toPublicKey().toXOnlyPublicKey().toString().toLowerCase();

const DAA = 550000000n;
const baseInput = () => ({
  agentAddress: ADDR(30),
  maxPerSpendKas: "2",
  budgetKas: "10",
  budgetPeriod: "1h",
  approvalThresholdKas: "1",
  recipientAddresses: [ADDR(40), ADDR(41)]
});

test("§27 addresses resolve to canonical x-only (agent + recipients)", () => {
  const p = normalizeAgentPolicyInputV4(config, baseInput(), DAA);
  assert.equal(p.agentPk, XO(30));
  assert.deepEqual(p.recipients, [XO(40), XO(41)]);
});

test("§27 KAS -> exact sompi (maxPerSpend, budget, approvalThreshold)", () => {
  const p = normalizeAgentPolicyInputV4(config, { ...baseInput(), maxPerSpendKas: "2", budgetKas: "10.5", approvalThresholdKas: "1.23456789" }, DAA);
  assert.equal(p.maxPerSpend, "200000000");
  assert.equal(p.periodBudget, "1050000000");
  assert.equal(p.approvalThreshold, "123456789");
});

test("§27 default agentMaxFeePerTx applied; explicit override honored", () => {
  assert.equal(normalizeAgentPolicyInputV4(config, baseInput(), DAA).agentMaxFeePerTx, "10000000"); // 0.10 KAS default
  assert.equal(normalizeAgentPolicyInputV4(config, { ...baseInput(), maxFeePerTxKas: "0.25" }, DAA).agentMaxFeePerTx, "25000000");
  assert.equal(DEFAULT_AGENT_MAX_FEE_PER_TX_KAS, "0.10");
});

test("§27 budget period presets + custom -> periodLengthDaa (DAA/sec = 10)", () => {
  assert.equal(budgetPeriodToDaa("1h"), "36000");
  assert.equal(budgetPeriodToDaa("6h"), "216000");
  assert.equal(budgetPeriodToDaa("1d"), "864000");
  assert.equal(budgetPeriodToDaa("1w"), "6048000");
  assert.equal(budgetPeriodToDaa({ value: "2", unit: "hour" }), "72000");
  assert.equal(budgetPeriodToDaa({ value: "3", unit: "day" }), "2592000");
  assert.equal(PERIOD_PRESETS["1d"].toString(), "864000");
  assert.throws(() => budgetPeriodToDaa("2y"), /unknown budget-period preset/);
  assert.throws(() => budgetPeriodToDaa({ value: "0", unit: "hour" }), /> 0/);
});

test("§27 periodStartDaa is SERVER-derived (browser value ignored); periodSpent = 0", () => {
  // A browser attempt to set periodStartDaa/periodSpent is ignored: the values
  // come from the authoritative node DAA + a fixed zero.
  const p = normalizeAgentPolicyInputV4(config, { ...baseInput(), periodStartDaa: "1", periodSpent: "999" }, DAA);
  assert.equal(p.periodStartDaa, DAA.toString());
  assert.equal(p.periodSpent, "0");
  // missing node DAA fails closed (never defaults to a browser value).
  assert.throws(() => normalizeAgentPolicyInputV4(config, baseInput(), undefined), /authoritative node DAA/);
});

test("§27 budget >= maxPerSpend invariant enforced", () => {
  assert.throws(() => normalizeAgentPolicyInputV4(config, { ...baseInput(), maxPerSpendKas: "10", budgetKas: "5" }, DAA), /must be >= maximum per transaction/);
});

test("§27 invalid KAS amounts fail closed (negative, zero-not-allowed, excessive precision)", () => {
  assert.throws(() => normalizeAgentPolicyInputV4(config, { ...baseInput(), maxPerSpendKas: "-1" }, DAA));
  assert.throws(() => normalizeAgentPolicyInputV4(config, { ...baseInput(), maxPerSpendKas: "0" }, DAA)); // 0 maxPerSpend rejected downstream / must be positive
  assert.throws(() => normalizeAgentPolicyInputV4(config, { ...baseInput(), maxPerSpendKas: "1.234567891" }, DAA)); // > 8 dp
});

test("§27 address failures fail closed (wrong network, malformed, unsupported type)", () => {
  const mainnetAddr = KEY(30).toPublicKey().toAddress("mainnet").toString();
  assert.throws(() => normalizeAgentPolicyInputV4(config, { ...baseInput(), agentAddress: mainnetAddr }, DAA), /network|WRONG_NETWORK|ADDRESS/i);
  assert.throws(() => normalizeAgentPolicyInputV4(config, { ...baseInput(), agentAddress: "kaspatest:qqnotarealaddress" }, DAA));
  const ecdsa = new kaspa.PublicKey("02" + XO(30)).toAddressECDSA(config.networkId).toString();
  assert.throws(() => normalizeAgentPolicyInputV4(config, { ...baseInput(), agentAddress: ecdsa }, DAA), /ADDRESS|unsupported|type/i);
});

test("§27 recipients: multiple allowed (no artificial 3-recipient cap); empty rejected", () => {
  const many = normalizeAgentPolicyInputV4(config, { ...baseInput(), recipientAddresses: [ADDR(40), ADDR(41), ADDR(42), ADDR(43), ADDR(44)] }, DAA);
  assert.equal(many.recipients.length, 5);
  assert.throws(() => normalizeAgentPolicyInputV4(config, { ...baseInput(), recipientAddresses: [] }, DAA), /at least one/);
});

test("§27 CANONICAL PARITY: the derived policy feeds the existing builder unchanged", () => {
  const p = normalizeAgentPolicyInputV4(config, baseInput(), DAA);
  // The builder consumes { ...policyFields, recipients } via normalizeAgentPolicyV4
  // (with agentRecipientRoot derived from recipients). This must not throw and
  // must reproduce a stable agent-tree root.
  const withRoot = normalizeAgentPolicyV4({ ...p, agentRecipientRoot: buildRecipientTree(p.recipients).root });
  const root1 = buildAgentTreeV4([withRoot]).root;
  const root2 = buildAgentTreeV4([normalizeAgentPolicyV4({ ...normalizeAgentPolicyInputV4(config, baseInput(), DAA), agentRecipientRoot: buildRecipientTree(p.recipients).root })]).root;
  assert.equal(root1, root2, "deterministic canonical policy");
  // exact field shape the builder expects
  assert.deepEqual(Object.keys(p).sort(), ["agentMaxFeePerTx", "agentPk", "approvalThreshold", "maxPerSpend", "periodBudget", "periodLengthDaa", "periodSpent", "periodStartDaa", "recipients"].sort());
});

test("§27 approvers: addresses -> x-only + approvalM; empty when none", () => {
  const a = normalizeApproversInputV4(config, { addresses: [ADDR(20), ADDR(21), ADDR(22)], approvalM: "2" });
  assert.deepEqual(a.approvers, [XO(20), XO(21), XO(22)]);
  assert.equal(a.approvalM, "2");
  assert.deepEqual(normalizeApproversInputV4(config, {}), { approvers: [], approvalM: "0" });
});

/* ================= H2 final browser polish — §14/§15 additions ================ */

const {
  daaToHumanPeriod,
  MIN_PERIOD_DAA,
  MAX_PERIOD_DAA,
  UNIT_SECONDS,
  MAX_APPROVERS
} = require("../src/ux-normalize-v4");

test("§15 budget-period presets stay canonical (1h/6h/1d/1w)", () => {
  assert.deepEqual(
    Object.fromEntries(Object.entries(PERIOD_PRESETS).map(([k, v]) => [k, v.toString()])),
    { "1h": "36000", "6h": "216000", "1d": "864000", "1w": "6048000" }
  );
});

test("§15 custom budget periods normalize to exact canonical DAA", () => {
  assert.equal(budgetPeriodToDaa({ value: "2", unit: "hour" }), "72000");
  assert.equal(budgetPeriodToDaa({ value: "12", unit: "hour" }), "432000");
  assert.equal(budgetPeriodToDaa({ value: "2", unit: "day" }), "1728000");
  assert.equal(budgetPeriodToDaa({ value: "3", unit: "day" }), "2592000");
  assert.equal(budgetPeriodToDaa({ value: "2", unit: "week" }), "12096000");
  // 24 hours == the 1d preset — unit composition is consistent.
  assert.equal(budgetPeriodToDaa({ value: "24", unit: "hour" }), budgetPeriodToDaa("1d"));
});

test("§15 invalid budget periods FAIL CLOSED (never clamp)", () => {
  const rejects = (input, re) => assert.throws(() => budgetPeriodToDaa(input), re);
  rejects({ value: "0", unit: "hour" }, /> 0/);
  rejects({ value: "-2", unit: "hour" }, /whole number/);
  rejects({ value: "", unit: "hour" }, /whole number/);
  rejects({ value: "NaN", unit: "hour" }, /whole number/);
  rejects({ value: "Infinity", unit: "day" }, /whole number/);
  rejects({ value: "1.5", unit: "hour" }, /whole number/);
  rejects({ value: "2", unit: "month" }, /unknown budget-period unit/);
  rejects({ value: "30", unit: "minute" }, /unknown budget-period unit/); // practical units are hour/day/week
  rejects("2y", /unknown budget-period preset/);
  rejects(null, /preset key or/);
  // Excessive / overflow-sized periods are outside the supported product range.
  rejects({ value: "54", unit: "week" }, /outside the supported range/);
  rejects({ value: "99999999999999999999999999", unit: "week" }, /outside the supported range/);
  // Boundary behavior is exact: 53 weeks passes, 1 hour passes.
  assert.equal(budgetPeriodToDaa({ value: "53", unit: "week" }), MAX_PERIOD_DAA.toString());
  assert.equal(budgetPeriodToDaa({ value: "1", unit: "hour" }), MIN_PERIOD_DAA.toString());
  assert.deepEqual(Object.keys(UNIT_SECONDS), ["hour", "day", "week"]);
});

test("§8 daaToHumanPeriod renders plain language for the review screen", () => {
  assert.equal(daaToHumanPeriod("36000"), "1 hour");
  assert.equal(daaToHumanPeriod("216000"), "6 hours");
  assert.equal(daaToHumanPeriod("864000"), "1 day");
  assert.equal(daaToHumanPeriod("6048000"), "1 week");
  assert.equal(daaToHumanPeriod("12096000"), "2 weeks");
  assert.equal(daaToHumanPeriod("432000"), "12 hours");
});

test("§14 approver distinctness + M-of-N validation (server normalize layer)", () => {
  const A = ADDR(20), B = ADDR(21);
  // M=2 + A+B -> valid.
  assert.deepEqual(normalizeApproversInputV4(config, { addresses: [A, B], approvalM: "2" }), { approvers: [XO(20), XO(21)], approvalM: "2" });
  // M=0 + no approvers -> valid.
  assert.deepEqual(normalizeApproversInputV4(config, {}), { approvers: [], approvalM: "0" });
  // M=2 + A+A -> reject (duplicate wallet address).
  assert.throws(() => normalizeApproversInputV4(config, { addresses: [A, A], approvalM: "2" }), (e) => e.code === "APPROVER_DUPLICATE");
  // NOTE on "two addresses resolving to the same identity": the canonical
  // bech32 encoding is one-to-one for supported PubKey addresses (case
  // variants are rejected by the address boundary), so two DIFFERENT valid
  // address strings with one x-only identity are not constructible today.
  // The x-only distinctness check remains as defense-in-depth for any future
  // address form; the frozen state layer (vault-state-v4) also re-rejects
  // duplicate keys independently.
  // M=2 + only A -> reject.
  assert.throws(() => normalizeApproversInputV4(config, { addresses: [A], approvalM: "2" }), (e) => e.code === "APPROVAL_M_INVALID");
  // M=11 -> reject.
  const eleven = Array.from({ length: 11 }, (_, i) => ADDR(50 + i));
  assert.throws(() => normalizeApproversInputV4(config, { addresses: eleven.slice(0, 10), approvalM: "11" }), (e) => e.code === "APPROVAL_M_INVALID");
  // 11 configured approvers -> reject (no truncation, no merging).
  assert.throws(() => normalizeApproversInputV4(config, { addresses: eleven, approvalM: "2" }), (e) => e.code === "APPROVERS_TOO_MANY");
  assert.equal(MAX_APPROVERS, 10);
  // M=0 while approvers configured -> reject; junk M -> reject.
  assert.throws(() => normalizeApproversInputV4(config, { addresses: [A], approvalM: "0" }), (e) => e.code === "APPROVAL_M_INVALID");
  assert.throws(() => normalizeApproversInputV4(config, { addresses: [A], approvalM: "x" }), (e) => e.code === "APPROVAL_M_INVALID");
  // Wrong-network approver -> reject via the ONE address boundary.
  const mainnet = KEY(20).toPublicKey().toAddress("mainnet").toString();
  assert.throws(() => normalizeApproversInputV4(config, { addresses: [mainnet], approvalM: "1" }), (e) => /ADDRESS|NETWORK/.test(e.code || ""));
  // 10 distinct approvers with M=10 -> valid (exact slot capacity).
  const ten = eleven.slice(0, 10);
  const norm = normalizeApproversInputV4(config, { addresses: ten, approvalM: "10" });
  assert.equal(norm.approvers.length, 10);
  assert.equal(new Set(norm.approvers).size, 10);
  assert.equal(norm.approvalM, "10");
});
