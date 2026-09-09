"use strict";

/*
 * BROWSER — web/setup-ui.js, the shared guided-setup components (owner UX
 * directive 2026-09-05). Headless: the module renders HTML strings and
 * validates plain drafts; every conversion runs through the REAL committed
 * web/core-bundle.js (core.amounts, core.durationDaa).
 *
 * Risks pinned here (directive §9): duration conversion + exact-value round
 * trips; invalid / overflow / custom inputs; no silent threshold change
 * after owner edits; duplicate signer identity (address + key forms of one
 * signer); disabled recovery / succession serialization; generation-
 * specific bounds; and the copy that must stay accurate.
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const core = require("../core-bundle.js");
const setupMod = require("../setup-ui.js");
const SRC = fs.readFileSync(path.join(__dirname, "..", "setup-ui.js"), "utf8");

const su = setupMod.createModule({ core });
const K = (b) => b.toString(16).padStart(2, "0").repeat(32);
const IDS = { "kaspatest:qagent": K(0x22), "kaspatest:qrec1": K(0x33), "kaspatest:qrec2": K(0x34), "kaspatest:qappr1": K(0x44), "kaspatest:qappr2": K(0x55), "kaspatest:qappr1-alt": K(0x44), "kaspatest:qown1": K(0x71), "kaspatest:qown2": K(0x72), "kaspatest:qown3": K(0x73), "kaspatest:qfunder": K(0xf1), "kaspatest:qsucc": K(0xa1) };
const resolve = async (a) => { if (Object.prototype.hasOwnProperty.call(IDS, a)) return IDS[a]; throw Object.assign(new Error(`address rejected: ${a}`), { code: "ADDRESS_INVALID" }); };

/* ---------------- guards ---------------- */
test("createModule requires core.amounts + core.durationDaa (never a UI-local constant)", () => {
  assert.throws(() => setupMod.createModule({ core: { amounts: core.amounts } }), /requires the core bundle/);
  assert.throws(() => setupMod.createModule({}), /requires the core bundle/);
  assert.ok(!/DAA_PER_SEC(?:OND)?\s*=\s*\d/.test(SRC), "setup-ui.js must not carry its own DAA-per-second constant");
  assert.ok(!/3600n|86400n|604800n/.test(SRC), "setup-ui.js must not carry its own unit table");
});

/* ---------------- duration control ---------------- */
test("duration: presets, custom and existing selections round-trip EXACTLY through core.durationDaa", () => {
  const S = su.BUDGET_SETTING;
  assert.equal(su.readDurationSelection(S, { preset: "1d" }).daa, "864000");
  assert.equal(su.readDurationSelection(S, { preset: "custom", customValue: "36", customUnit: "hour" }).daa, "1296000");
  const ex = su.readDurationSelection(S, { preset: "existing", existingDaa: "86400" });
  assert.deepEqual([ex.daa, ex.source, ex.preset], ["86400", "existing", null]);
  const exImplicit = su.readDurationSelection(S, { existingDaa: "1005" });
  assert.deepEqual([exImplicit.daa, exImplicit.source, exImplicit.exact], ["1005", "existing", false], "an existing value with no explicit choice is kept, byte-exact, even when not a whole second");
  assert.equal(su.readDurationSelection(S, {}).daa, "864000", "no selection -> the setting's default preset");
});

test("duration: invalid / decimal / overflow custom input fails closed with actionable messages (never clamped, never rounded)", () => {
  const S = su.BUDGET_SETTING;
  assert.throws(() => su.readDurationSelection(S, { preset: "custom", customValue: "1.5", customUnit: "day" }), (e) => { assert.equal(e.code, "DURATION_PRECISION"); assert.match(e.message, /36 hours/); return true; });
  assert.throws(() => su.readDurationSelection(S, { preset: "custom", customValue: "54", customUnit: "week" }), (e) => e.code === "DURATION_OUT_OF_RANGE");
  assert.throws(() => su.readDurationSelection(S, { preset: "custom", customValue: "", customUnit: "day" }), (e) => e.code === "DURATION_VALUE_INVALID");
  assert.throws(() => su.readDurationSelection(S, { preset: "custom", customValue: "1", customUnit: "month" }), (e) => e.code === "DURATION_UNIT_INVALID");
  const R = su.RECOVERY_SETTING;
  assert.throws(() => su.readDurationSelection(R, { preset: "custom", customValue: "5000", customUnit: "day" }), (e) => e.code === "DURATION_OUT_OF_RANGE", "beyond the 2^32-1 encoding bound of the root template");
  assert.throws(() => su.readDurationSelection(R, { preset: "1h" }), (e) => e.code === "DURATION_VALUE_INVALID", "a budget-period preset is not a root-delay preset (generation-specific)");
});

test("duration control renders presets, a hidden custom row, and a live effect line with the exact DAA + measurement note", () => {
  const html = su.renderDurationControl({ name: "period", setting: su.BUDGET_SETTING, selection: { preset: "1d" } });
  for (const label of ["1 hour", "6 hours", "1 day", "1 week", "Custom…"]) assert.ok(html.includes(`>${label}<`), label);
  assert.match(html, /data-duration-custom="period" hidden/);
  assert.match(html, /About 1 day\. Measured using Kaspa network progress/);
  assert.match(html, /data-duration-exact="period">Exactly 864000 DAA score/, "the exact protocol value lives under Technical detail");
  assert.ok(!/DAA/.test(/data-duration-effect="period"[^>]*>([^<]*)</.exec(html)[1]), "the primary effect line never mentions DAA");
  const custom = su.renderDurationControl({ name: "period", setting: su.BUDGET_SETTING, selection: { preset: "custom", customValue: "3", customUnit: "day" } });
  assert.match(custom, /data-duration-custom="period">/, "custom row visible");
  assert.match(custom, /About 3 days\./);
  assert.match(custom, /Exactly 2592000 DAA score/);
  const existing = su.renderDurationControl({ name: "period", setting: su.BUDGET_SETTING, selection: { existingDaa: "86400" } });
  assert.match(existing, /Keep current value \(about 2 hours 24 minutes, exact\)/);
  assert.match(existing, /current value kept unchanged/);
  assert.equal(su.durationEffectText(su.BUDGET_SETTING, { preset: "custom", customValue: "1.5", customUnit: "day" }).includes("36 hours"), true);
  assert.equal(su.COPY.MEASUREMENT, "Measured using Kaspa network progress, so the elapsed time is approximate.");
  assert.equal(su.COPY.UNITS, "1 day = 24 hours; 1 week = 7 days.");
  assert.ok(!/midnight reset|resets at midnight/i.test(su.COPY.BUDGET_WINDOW) && /never aligned to midnight/.test(su.COPY.BUDGET_WINDOW));
});

/* ---------------- approval counts ---------------- */
test("approval select reads \"k of N owners\"; an impossible value is PRESERVED and flagged, never lowered", () => {
  assert.deepEqual(su.approvalOptions(3, "owners").map((o) => o.label), ["1 of 3 owners", "2 of 3 owners", "3 of 3 owners"]);
  const t = su.thresholdCheck({ count: 2, value: "3", noun: "owners", label: "Owners needed to approve changes" });
  assert.equal(t.ok, false);
  assert.match(t.message, /3 of 2 is impossible/);
  assert.match(t.message, /was not changed for you/);
  const html = su.renderApprovalSelect({ name: "ownerM", count: 2, value: "3", noun: "owners" });
  assert.match(html, /<option value="3" selected>3 of 2 owners — impossible, choose again<\/option>/);
  assert.ok(su.thresholdCheck({ count: 3, value: "2", noun: "owners", label: "x" }).ok);
  assert.equal(su.thresholdCheck({ count: 3, value: "0", noun: "owners", label: "x" }).ok, false);
  assert.equal(su.thresholdCheck({ count: 0, value: "1", noun: "owners", label: "x" }).ok, false);
  assert.equal(su.thresholdCheck({ count: 3, value: "3", noun: "owners", label: "x", max: 2 }).ok, false, "a max (e.g. K <= M) is enforced");
});

/* ---------------- address rows ---------------- */
test("address rows: labels render as TEXT (escaped), a new row is blank, key mode is an explicit advanced choice", () => {
  const html = su.renderAddressRows({ kind: "owner", rows: [{ address: "kaspatest:qown1", label: "<b>Alice</b>" }, { keyMode: true, publicKey: K(0x72) }], withLabel: true, allowKey: true, min: 1, max: 12, connectedAddress: "kaspatest:qown1" });
  assert.ok(html.includes("&lt;b&gt;Alice&lt;/b&gt;"), "label escaped");
  assert.ok(!html.includes("<b>Alice</b>"));
  assert.match(html, /name="ownerKey" value="7272/);
  assert.match(html, /data-row="1"[^]*?name="owner" value="" placeholder="kaspa:…" aria-label="owner 2 wallet address" autocomplete="off" class="mono addr-addr" hidden/);
  assert.match(html, /data-use-connected="owner"/);
  assert.match(html, /id="v4-add-owner"/);
  const blank = su.renderAddressRows({ kind: "recipient", rows: [] });
  assert.match(blank, /name="recipient" value=""/);
});

/* ---------------- vault draft ---------------- */
function vaultDraft(overrides = {}) {
  return {
    ...su.vaultDraftDefaults(),
    label: "Ops", deposit: "100", reserve: "5",
    agent: "kaspatest:qagent", recipients: [{ address: "kaspatest:qrec1" }, { address: "kaspatest:qrec2" }],
    maxPerSpend: "2", budget: "10", period: { preset: "1d" }, approvalThreshold: "1",
    approvers: [{ address: "kaspatest:qappr1" }, { address: "kaspatest:qappr2" }], approvalM: "2",
    ...overrides
  };
}

test("validateVaultDraft: the happy path yields the EXACT POST /wallet/v4/create body + browser verification context", async () => {
  const v = await su.validateVaultDraft(vaultDraft(), { resolve, signerAddress: "kaspatest:qowner", vaultId: "ee".repeat(32) });
  assert.equal(v.ok, true, [...v.errors].map(String).join(";"));
  assert.equal(v.body.contractVersion, "policyvault-0.4.1");
  assert.deepEqual(v.body.agent, { agentAddress: "kaspatest:qagent", maxPerSpendKas: "2", budgetKas: "10", budgetPeriod: "1d", approvalThresholdKas: "1", recipientAddresses: ["kaspatest:qrec1", "kaspatest:qrec2"] });
  assert.deepEqual(v.body.approvers, { addresses: ["kaspatest:qappr1", "kaspatest:qappr2"], approvalM: "2" });
  assert.equal(v.context.approvalM, "2");
  assert.deepEqual(v.context.approverXOnlys, [K(0x44), K(0x55)]);
  assert.equal(v.context.agentXOnly, K(0x22));
  assert.equal(v.normalized.period.daa, "864000");
});

test("validateVaultDraft: a custom period travels as HUMAN INTENT { value, unit } — the SERVER derives periodLengthDaa through the same core module; the browser never supplies it", async () => {
  const v = await su.validateVaultDraft(vaultDraft({ period: { preset: "custom", customValue: "36", customUnit: "hour" } }), { resolve, signerAddress: "s", vaultId: "ee".repeat(32) });
  assert.equal(v.ok, true);
  assert.deepEqual(v.body.agent.budgetPeriod, { value: "36", unit: "hour" });
  assert.ok(!("periodLengthDaa" in v.body.agent), "browser never supplies periodLengthDaa");
  assert.equal(v.normalized.period.daa, "1296000", "the browser's own conversion (display / pre-validation) agrees exactly");
  const v7 = await su.validateVaultDraft(vaultDraft({ period: { preset: "custom", customValue: "7", customUnit: "day" } }), { resolve, signerAddress: "s", vaultId: "ee".repeat(32) });
  assert.deepEqual(v7.body.agent.budgetPeriod, { value: "7", unit: "day" });
  assert.equal(v7.normalized.period.preset, "1w");
});

test("validateVaultDraft: duplicate signer identity across approvers (two address forms of ONE key) is refused beside the row", async () => {
  const v = await su.validateVaultDraft(vaultDraft({ approvers: [{ address: "kaspatest:qappr1" }, { address: "kaspatest:qappr1-alt" }] }), { resolve, signerAddress: "s", vaultId: "ee".repeat(32) });
  assert.equal(v.ok, false);
  assert.match(v.errors.get("approverRows")[1], /Same signing identity as approver 1/);
  const dupAddr = await su.validateVaultDraft(vaultDraft({ approvers: [{ address: "kaspatest:qappr1" }, { address: "kaspatest:qappr1" }] }), { resolve, signerAddress: "s", vaultId: "ee".repeat(32) });
  assert.match(dupAddr.errors.get("approverRows")[1], /Same wallet as approver 1/);
});

test("validateVaultDraft: approvals needed above the configured approvers is refused, never lowered; 0-threshold with no approvers is refused", async () => {
  const v = await su.validateVaultDraft(vaultDraft({ approvers: [{ address: "kaspatest:qappr1" }], approvalM: "2" }), { resolve, signerAddress: "s", vaultId: "ee".repeat(32) });
  assert.equal(v.ok, false);
  assert.match(v.errors.get("approvalM"), /2 of 1 is impossible/);
  const z = await su.validateVaultDraft(vaultDraft({ approvers: [], approvalM: "", approvalThreshold: "0" }), { resolve, signerAddress: "s", vaultId: "ee".repeat(32) });
  assert.equal(z.ok, false);
  assert.match(z.errors.get("approvalThreshold"), /every payment impossible/);
  const none = await su.validateVaultDraft(vaultDraft({ approvers: [], approvalM: "" }), { resolve, signerAddress: "s", vaultId: "ee".repeat(32) });
  assert.equal(none.ok, true);
  assert.equal(none.body.approvers, undefined);
  assert.equal(none.context.approvalM, "0");
});

test("validateVaultDraft: bad amounts, missing recipients, bad addresses and a bad agent are field-local; step-scoped validation touches only that step", async () => {
  const v = await su.validateVaultDraft(vaultDraft({ maxPerSpend: "abc", budget: "1", recipients: [{ address: "" }], agent: "kaspatest:nope", deposit: "0" }), { resolve, signerAddress: "s", vaultId: "ee".repeat(32) });
  assert.equal(v.ok, false);
  assert.match(v.errors.get("maxPerSpend"), /greater than 0/);
  assert.match(v.errors.get("recipients"), /at least one/);
  assert.match(v.errors.get("agent"), /rejected/);
  assert.match(v.errors.get("deposit"), /greater than 0/);
  const stepOnly = await su.validateVaultDraft(vaultDraft({ maxPerSpend: "abc" }), { resolve, step: "basics" });
  assert.equal(stepOnly.ok, true, "the basics step does not fail on a rules-step field");
  const budgetLt = await su.validateVaultDraft(vaultDraft({ maxPerSpend: "20", budget: "10" }), { resolve, step: "rules" });
  assert.match(budgetLt.errors.get("budget"), /at least the maximum per payment/);
});

test("vaultRulesSummary speaks plainly and says 'above' (strictly), matching the covenant's pay > threshold rule", () => {
  const s = su.vaultRulesSummary(vaultDraft()).join(" ");
  assert.match(s, /No single payment may exceed 2 KAS/);
  assert.match(s, /at most 10 KAS per 1 day/);
  assert.match(s, /Payments above 1 KAS need 2 of 2 approvers to sign first; at or below, the agent signs alone/);
  const none = su.vaultRulesSummary(vaultDraft({ approvers: [], approvalM: "", approvalThreshold: "0" })).join(" ");
  assert.match(none, /could not pay at all/);
});

test("vaultReviewRows names the exact budget period DAA beside the approximate duration", async () => {
  const v = await su.validateVaultDraft(vaultDraft(), { resolve, signerAddress: "s", vaultId: "ee".repeat(32) });
  const rows = su.vaultReviewRows(v.normalized);
  assert.match(rows.rules.find((r) => r[0] === "Budget period")[1].html, /^about 1 day<details class="adv f-tech"><summary>Technical detail<\/summary>exactly 864000 DAA score<\/details>$/);
  assert.match(rows.rules.find((r) => r[0] === "Spending budget")[1], /10 KAS per 1 day \(approximate\)/);
  assert.match(rows.rules.find((r) => r[0] === "Payments needing extra approval")[1], /^above 1 KAS$/);
});

/* ---------------- root draft ---------------- */
function rootDraft(overrides = {}) {
  return {
    ...su.rootDraftDefaults("kaspatest:qfunder"),
    owners: [{ address: "kaspatest:qown1", label: "Alice" }, { address: "kaspatest:qown2", label: "Bob" }, { address: "kaspatest:qown3", label: "Carol" }],
    ownerM: "2", emergencyK: "1",
    recoveryEnabled: true, recoveryM: "1", recoveryDelay: { preset: "30d" },
    successionEnabled: false, successorAddress: "", successionDelay: { preset: "90d" },
    rootValueKas: "1", rootMaxFeePerTxKas: "0.001", signerAddress: "kaspatest:qfunder",
    ...overrides
  };
}

test("validateRootDraft: the happy path yields the exact wizard form (owners by slot order, M/K/R, exact delays)", async () => {
  const v = await su.validateRootDraft(rootDraft(), { resolve, connectedAddress: "kaspatest:qfunder" });
  assert.equal(v.ok, true, [...v.errors].map(String).join(";"));
  assert.deepEqual(v.form.owners, [{ address: "kaspatest:qown1", label: "Alice" }, { address: "kaspatest:qown2", label: "Bob" }, { address: "kaspatest:qown3", label: "Carol" }]);
  assert.deepEqual([v.form.ownerM, v.form.emergencyK, v.form.recoveryM], ["2", "1", "1"]);
  assert.deepEqual([v.form.recoveryDelayDaa, v.form.successionDelayDaa, v.form.successorAddress], ["25920000", "77760000", ""]);
  assert.equal(v.form.signerAddress, "kaspatest:qfunder");
});

test("validateRootDraft: DISABLED recovery serializes recoveryM 0 regardless of the hidden select; DISABLED succession serializes no successor", async () => {
  const v = await su.validateRootDraft(rootDraft({ recoveryEnabled: false, recoveryM: "2", successionEnabled: false, successorAddress: "kaspatest:qsucc" }), { resolve, connectedAddress: "kaspatest:qfunder" });
  assert.equal(v.ok, true);
  assert.equal(v.form.recoveryM, "0");
  assert.equal(v.form.successorAddress, "");
  assert.equal(v.form.recoveryDelayDaa, "25920000", "the waiting period is still carried (template constant, cannot be changed later)");
  const on = await su.validateRootDraft(rootDraft({ successionEnabled: true, successorAddress: "kaspatest:qsucc", successionDelay: { preset: "custom", customValue: "45", customUnit: "day" } }), { resolve, connectedAddress: "kaspatest:qfunder" });
  assert.equal(on.ok, true);
  assert.deepEqual([on.form.successorAddress, on.form.successionDelayDaa], ["kaspatest:qsucc", "38880000"]);
});

test("validateRootDraft: K > M and R > M are refused on their own fields with an explicit-correction message; M above owners is refused", async () => {
  const k = await su.validateRootDraft(rootDraft({ ownerM: "1", emergencyK: "2" }), { resolve, connectedAddress: "kaspatest:qfunder" });
  assert.equal(k.ok, false);
  assert.match(k.errors.get("emergencyK"), /cannot exceed the 1 needed to approve changes/);
  const r = await su.validateRootDraft(rootDraft({ ownerM: "1", recoveryM: "2" }), { resolve, connectedAddress: "kaspatest:qfunder" });
  assert.match(r.errors.get("recoveryM"), /cannot exceed the 1 needed/);
  const m = await su.validateRootDraft(rootDraft({ owners: [{ address: "kaspatest:qown1" }], ownerM: "2" }), { resolve, connectedAddress: "kaspatest:qfunder" });
  assert.match(m.errors.get("ownerM"), /2 of 1 is impossible/);
});

test("validateRootDraft: the same signer as an address and as a public key is refused; key mode with no key is refused; > 12 owners refused; funder must be the connected wallet", async () => {
  const dup = await su.validateRootDraft(rootDraft({ owners: [{ address: "kaspatest:qown1" }, { keyMode: true, publicKey: K(0x71) }] }), { resolve, connectedAddress: "kaspatest:qfunder" });
  assert.equal(dup.ok, false);
  assert.match(dup.errors.get("ownerRows")[1], /Same signing key as owner 1|Same signing identity as owner 1/);
  const dup2 = await su.validateRootDraft(rootDraft({ owners: [{ keyMode: true, publicKey: K(0x71) }, { address: "kaspatest:qown1" }] }), { resolve, connectedAddress: "kaspatest:qfunder" });
  assert.match(dup2.errors.get("ownerRows")[1], /Same signing identity as owner 1/);
  const nokey = await su.validateRootDraft(rootDraft({ owners: [{ keyMode: true, publicKey: "" }] }), { resolve, step: "owners" });
  assert.match(nokey.errors.get("ownerRows")[0], /64-hex public key/);
  const many = await su.validateRootDraft(rootDraft({ owners: Array.from({ length: 13 }, (_, i) => ({ address: `kaspatest:q${i}` })) }), { resolve, step: "owners" });
  assert.match(many.errors.get("owners"), /At most 12/);
  const funder = await su.validateRootDraft(rootDraft({ signerAddress: "kaspatest:qown1" }), { resolve, connectedAddress: "kaspatest:qfunder" });
  assert.match(funder.errors.get("signerAddress"), /must be the connected wallet/);
  const bound = await su.validateRootDraft(rootDraft({ rootMaxFeePerTxKas: "1001" }), { resolve, step: "funding" });
  assert.match(bound.errors.get("rootMaxFeePerTxKas"), /encoding bound/);
});

test("rootRulesSummary: freeze does not stop agent payments; recovery-off consequence is stated", () => {
  const s = su.rootRulesSummary(rootDraft()).join(" ");
  assert.match(s, /Any 2 of the 3 owners must sign/);
  assert.match(s, /Any 1 owner can freeze governance in an emergency; 2 of 3 must sign to unfreeze\. A freeze does not stop agent payments\./);
  assert.match(s, /untouched for about 30 days, any 1 of the owners can recover control/);
  const off = su.rootRulesSummary(rootDraft({ recoveryEnabled: false })).join(" ");
  assert.match(off, /Recovery is off: if too many owner keys are lost, nobody can regain control/);
});

/* ---------------- review + funding blocks ---------------- */
test("stepper marks the current step (aria-current), review sections carry Edit links, the funding breakdown totals", () => {
  const st = su.renderStepper({ steps: [{ id: "a", label: "A" }, { id: "b", label: "B" }], current: 1 });
  assert.match(st, /data-step="b" aria-current="step"/);
  assert.match(st, /Step 2 of 2: B/);
  const rs = su.renderReviewSection({ title: "Owners", editStep: 0, rows: [["Owners", "x"]] });
  assert.match(rs, /data-edit-step="0">Edit</);
  const fb = su.renderFundingBreakdown({ rows: [{ label: "Deposit", kas: "100" }, { label: "Fee", kas: "0.001" }], total: { label: "Total", kas: "100.001" } });
  assert.match(fb, /fund-total[^]*100\.001 KAS/);
  const nav = su.renderNav({ index: 3, total: 4, finalLabel: "Build & review exact transaction" });
  assert.match(nav, /data-setup-build="1">Build &amp; review exact transaction</);
  assert.match(su.renderNav({ index: 1, total: 4 }), /data-setup-back="1"/);
});

test("UX-01 / UX-12 (Codex checkpoint 2): the verification context carries the EXACT locally normalized period and a creation fee limit that is independent of the agent's per-payment cap", async () => {
  const v = await su.validateVaultDraft(vaultDraft({ period: { preset: "custom", customValue: "36", customUnit: "hour" }, maxFee: "0.1", creationMaxFee: "0.5" }), { resolve, signerAddress: "s", vaultId: "ee".repeat(32) });
  assert.equal(v.ok, true, [...v.errors.entries()].join(";"));
  assert.equal(v.context.agentPeriodLengthDaa, "1296000", "36 hours = 1296000 DAA, bound into the genesis verification");
  assert.equal(v.body.agent.budgetPeriod.value, "36", "the body still carries the human intent (server derives)");
  assert.equal(v.context.agentMaxFeePerTxKas, "0.1", "the agent's per-payment fee cap is the policy the covenant enforces");
  assert.equal(v.context.maxFeeSompi, "50000000", "the creation fee LIMIT is the separate control (0.5 KAS)");
  assert.deepEqual(v.normalized.creationMaxFeeKas, "0.5");
  const dflt = await su.validateVaultDraft(vaultDraft({ maxFee: "0.1" }), { resolve, signerAddress: "s", vaultId: "ee".repeat(32) });
  assert.equal(dflt.context.maxFeeSompi, "100000000", "default creation limit 1 KAS — never the agent cap");
  assert.equal(dflt.context.agentPeriodLengthDaa, "864000");
  const bad = await su.validateVaultDraft(vaultDraft({ creationMaxFee: "0" }), { resolve, signerAddress: "s", vaultId: "ee".repeat(32), step: "funding" });
  assert.match(bad.errors.get("creationMaxFee") || "", /positive KAS amount/);
  assert.match(su.vaultReviewRows(v.normalized).funding.map((r) => r.join("=")).join("|"), /Network fee limit for creating the vault=0.5 KAS/);
});

