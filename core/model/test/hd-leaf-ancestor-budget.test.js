"use strict";

/* UNIT — AUTHORITY MAY NEVER INCREASE DESCENDING: every ancestor's PERIOD
 * BUDGET participates in the pre-sign guard. Pinned from the live testnet-10
 * refusal of 2026-09-03: a level-3 spend of 25 under a level-2 leaf whose
 * 150 budget was already exhausted by the boundary spend was signed by the
 * builder and refused by consensus (`script ran, but verification failed`,
 * tx fd6d1b46…). The guard must refuse it BEFORE signing. */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const hd = require("../hd-leaf-v7");

const KAS = 100_000_000n;
const K = (b) => b.toString(16).padStart(2, "0").repeat(32);
const leaf = (pk, over = {}) => ({ pk, maxPerSpend: "250", periodBudget: "2000", periodLengthDaa: "100000000", periodStartDaa: "0", periodSpent: "0", maxFeePerTx: KAS.toString(), maxCarryKas: (KAS / 4n).toString(), expiryDaa: "900000000", recipientRoot: "00".repeat(32), childRoot: "00".repeat(32), ...over });

test("a spend that would push an EXHAUSTED ancestor over its period budget is a violation at that level, even when the leaf's own cap/budget allow it", () => {
  const chain = [
    { leaf: leaf(K(0xa1), { periodSpent: "150" }) }, // level 1: 2000 budget, 150 spent
    { leaf: leaf(K(0xc1), { maxPerSpend: "150", periodBudget: "150", periodSpent: "150" }) }, // level 2: EXHAUSTED
    { leaf: leaf(K(0xd1), { maxPerSpend: "50", periodBudget: "50" }) } // level 3: the spending leaf
  ];
  const r = hd.verifySpendWithinEffectiveAuthority(chain, { amount: "25", periodsElapsedByLevel: [0n, 0n, 0n] });
  assert.equal(r.ok, false);
  assert.deepEqual([...r.violations], ["periodBudget@level2"]);
});

test("with headroom at every level the same spend is within the effective authority; one unit over the tightest remaining budget is not", () => {
  const chain = [
    { leaf: leaf(K(0xa1), { periodSpent: "150" }) },
    { leaf: leaf(K(0xc1), { maxPerSpend: "150", periodBudget: "200", periodSpent: "150" }) }, // 50 remaining
    { leaf: leaf(K(0xd1), { maxPerSpend: "50", periodBudget: "50" }) }
  ];
  assert.equal(hd.verifySpendWithinEffectiveAuthority(chain, { amount: "25", periodsElapsedByLevel: [0n, 0n, 0n] }).ok, true);
  assert.equal(hd.verifySpendWithinEffectiveAuthority(chain, { amount: "50", periodsElapsedByLevel: [0n, 0n, 0n] }).ok, true);
  const over = hd.verifySpendWithinEffectiveAuthority(chain, { amount: "51", periodsElapsedByLevel: [0n, 0n, 0n] });
  assert.equal(over.ok, false);
  assert.ok(over.violations.includes("maxPerSpend")); // level-3 cap 50
  assert.ok(over.violations.includes("periodBudget@level2")); // 150 + 51 > 200
  assert.ok(over.violations.includes("periodBudget@level3")); // 51 > 50
});

test("a rollover at the exhausted level (periodsElapsed >= 1) resets that counter and admits the spend", () => {
  const chain = [
    { leaf: leaf(K(0xa1), { periodSpent: "150" }) },
    { leaf: leaf(K(0xc1), { maxPerSpend: "150", periodBudget: "150", periodSpent: "150" }) },
    { leaf: leaf(K(0xd1), { maxPerSpend: "50", periodBudget: "50" }) }
  ];
  assert.equal(hd.verifySpendWithinEffectiveAuthority(chain, { amount: "25", periodsElapsedByLevel: [0n, 1n, 0n] }).ok, true);
});
