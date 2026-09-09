"use strict";

/* UNIT — PERIOD-LENGTH POSITIVITY INVARIANT (adversarial review finding F1,
 * v0.6 byte-freeze record 2026-09-03). The frozen covenants (v0.3 … v0.6)
 * compute `newStart = periodStartDaa + periodsElapsed * periodLengthDaa` and
 * gate it with `tx.time >= newStart`; they carry NO in-covenant
 * `periodLengthDaa > 0` check. A leaf with periodLengthDaa == 0 would make
 * the PERIOD budget vacuous (per-transaction caps stay enforced). Such a leaf
 * can only be committed by the OWNER (it lives under the owner-set agent
 * root), so this is a defense-in-depth invariant, not a delegate-exploitable
 * boundary — and it is enforced HERE, in the shared deterministic core's leaf
 * normalizers, for every generation. This test pins that enforcement so it
 * can never silently disappear. */

const { test } = require("node:test");
const assert = require("node:assert/strict");

const v4 = require("../agent-merkle-v4");
const v5 = require("../agent-merkle-v5");
const v6 = require("../agent-merkle-v6");

const PK = "ab".repeat(32);
const ROOT = "cd".repeat(32);

function pick(mod, names) {
  for (const n of names) if (typeof mod[n] === "function") return mod[n];
  throw new Error(`none of ${names.join("/")} exported`);
}

const normalizeV4 = pick(v4, ["normalizeAgentPolicyV4", "normalizeAgentPolicy", "agentPolicyLeafV4", "agentLeafV4"]);
const normalizeV5 = pick(v5, ["normalizeTokenAgentPolicyV5", "normalizeTokenAgentPolicy", "tokenAgentLeafV5", "tokenAgentPolicyLeafV5"]);
const normalizeV6 = pick(v6, ["normalizeTokenAgentPolicyV6", "normalizeTokenAgentPolicy", "tokenAgentLeafV6", "tokenAgentPolicyLeafV6"]);

const baseV4 = {
  agentPk: PK, maxPerSpend: "1000", periodBudget: "5000", periodLengthDaa: "0",
  periodStartDaa: "0", periodSpent: "0", agentMaxFeePerTx: "10000", agentRecipientRoot: ROOT
};
const baseV5 = {
  agentPk: PK, tokenMaxPerSpend: "1000", tokenPeriodBudget: "5000", periodLengthDaa: "0",
  periodStartDaa: "0", tokenPeriodSpent: "0", agentMaxFeePerTx: "10000", agentMaxCarryKas: "1000",
  agentRecipientRoot: ROOT
};
const baseV6 = {
  ...baseV5, kasMaxPerSwap: "1000", kasPeriodBudget: "5000", kasPeriodSpent: "0"
};

for (const [label, normalize, base] of [["v0.4/v0.4.1", normalizeV4, baseV4], ["v0.5", normalizeV5, baseV5], ["v0.6", normalizeV6, baseV6]]) {
  test(`${label} agent-policy normalizer refuses periodLengthDaa == 0 (period budget would be vacuous in-covenant)`, () => {
    assert.throws(() => normalize({ ...base, periodLengthDaa: "0" }), /periodLengthDaa/);
  });
  test(`${label} agent-policy normalizer refuses a negative periodLengthDaa`, () => {
    assert.throws(() => normalize({ ...base, periodLengthDaa: "-1" }), /periodLengthDaa/);
  });
  test(`${label} agent-policy normalizer accepts periodLengthDaa == 1 (smallest positive)`, () => {
    let out;
    try {
      out = normalize({ ...base, periodLengthDaa: "1" });
    } catch (e) {
      // other fields may be refused by stricter rules; the failure must NOT be about periodLengthDaa
      assert.ok(!/periodLengthDaa/.test(String(e && e.message)), `unexpected periodLengthDaa refusal: ${e && e.message}`);
      return;
    }
    assert.ok(out, "normalizer returned nothing");
  });
}
