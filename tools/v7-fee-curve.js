"use strict";
/*
 * v0.7 ORGANIZATIONAL ROOT — FEE CURVE (gate I4).
 *
 * Prints the relay-floor network fee for every measured v0.7 transaction
 * shape, the threshold curve 1-of-1 .. 12-of-12, and the cost of running a
 * whole organization for representative operating profiles.
 *
 * Deterministic; no node access; no compiler needed. Every number comes from
 * core/model/fee-mass-v7.js, whose shape table is a MEASUREMENT of finalized
 * production bytes (regenerate with sdk/tools/measure-v7-fee-shapes.js) and
 * whose arithmetic is core/model/fee-mass.js — the source-backed
 * reimplementation of rusty-kaspa's mass and minimum-relay-fee rules.
 *
 * NO ECONOMIC THRESHOLD IS INVENTED. The curve is presented; the record in
 * docs/postlaunch/v0.7-economic-viability.md draws the conclusions.
 *
 * Usage: node tools/v7-fee-curve.js [--json]
 */

const { V7_MEASURED_SHAPES, ROOT_FEE_CROSSOVER_ACTIVE_SLOTS, allShapeFees, rootThresholdCurve, organizationCost, feeForLabel } = require("../core/model/fee-mass-v7");

const SOMPI = 100000000n;

function fmtKas(sompi) {
  const s = BigInt(sompi).toString().padStart(9, "0");
  return `${s.slice(0, -8)}.${s.slice(-8)}`;
}

/* Representative operating profiles. These are ILLUSTRATIVE COUNTS, not
 * predictions: each is a plainly stated month of activity so a reader can
 * substitute their own numbers. */
const PROFILES = [
  { name: "small org (3 owners, 1 vault, 1 agent)", activeOwnerSlots: 3, vaults: 0, ownerOps: 1, rootOnlyActions: 0, delegateSpends: 100, heartbeats: 1 },
  { name: "mid org (5 owners, 5 vaults, weekly governance)", activeOwnerSlots: 5, vaults: 0, ownerOps: 8, rootOnlyActions: 4, delegateSpends: 1000, heartbeats: 4 },
  { name: "large org (12 owners, 25 vaults, daily governance)", activeOwnerSlots: 12, vaults: 0, ownerOps: 30, rootOnlyActions: 30, delegateSpends: 10000, heartbeats: 30 },
  { name: "onboarding month (5 owners, +10 new vaults)", activeOwnerSlots: 5, vaults: 10, ownerOps: 10, rootOnlyActions: 2, delegateSpends: 500, heartbeats: 4 }
];

/* The dead-man's-switch heartbeat. `recoveryDelayDaa` is a RELATIVE input age
 * in DAA score; any root transaction resets it. Post-Crescendo mainnet targets
 * 10 blocks per second (rusty-kaspa consensus/core/src/config/bps.rs
 * `TenBps = Bps<10>`; target_time_per_block = 100 ms), so a DAA score of D
 * corresponds to roughly D/10 seconds of DAG progress. That mapping is a
 * PLANNING approximation — DAA score tracks difficulty-adjusted block count,
 * not a wall clock — and is never a consensus guarantee. */
const BLOCKS_PER_SECOND = 10n;
const HEARTBEAT_WINDOWS = [
  { label: "30-day idle delay", daa: 30n * 86400n * BLOCKS_PER_SECOND },
  { label: "90-day idle delay", daa: 90n * 86400n * BLOCKS_PER_SECOND },
  { label: "365-day idle delay", daa: 365n * 86400n * BLOCKS_PER_SECOND }
];

const curve = rootThresholdCurve();
const shapes = allShapeFees();

const heartbeat = HEARTBEAT_WINDOWS.map((w) => {
  const perYear = (365n * 86400n * BLOCKS_PER_SECOND) / w.daa; /* integer heartbeats per year at one per window */
  return {
    ...w,
    daa: w.daa.toString(),
    approxDays: (w.daa / (86400n * BLOCKS_PER_SECOND)).toString(),
    heartbeatsPerYear: perYear.toString(),
    costPerYearSompiAt3: (perYear * feeForLabel("root authorize 3-of-3").relayFloorFeeSompi).toString(),
    costPerYearSompiAt12: (perYear * feeForLabel("root authorize 12-of-12").relayFloorFeeSompi).toString()
  };
});

const profiles = PROFILES.map((p) => {
  const c = organizationCost(p);
  return {
    name: p.name,
    ...p,
    perOwnerOpKas: fmtKas(c.perOwnerOpSompi),
    perRootActionKas: fmtKas(c.perRootActionSompi),
    perDelegateSpendKas: fmtKas(c.perDelegateSpendSompi),
    totalSompi: c.totalSompi.toString(),
    totalKas: fmtKas(c.totalSompi)
  };
});

if (process.argv.includes("--json")) {
  console.log(
    JSON.stringify(
      {
        generatedFrom: "core/model/fee-mass-v7.js (measured finalized production bytes; sdk/tools/measure-v7-fee-shapes.js)",
        policy: { relaySompiPerGram: 100, feeMass: "max(compute_mass, ceil(transient_mass/2))", storageLimitGrams: 500000 },
        crossoverActiveSlots: ROOT_FEE_CROSSOVER_ACTIVE_SLOTS,
        blocksPerSecondAssumedForDayConversion: Number(BLOCKS_PER_SECOND),
        shapes: shapes.map((s) => ({
          kind: s.kind,
          label: s.label,
          txBytes: Number(s.txBytes),
          computeMass: Number(s.computeMass),
          transientMass: Number(s.transientMass),
          feeMass: Number(s.feeMass),
          feeMassDominatedBy: s.feeMassDominatedBy,
          relayFloorFeeSompi: s.relayFloorFeeSompi.toString(),
          relayFloorFeeKas: fmtKas(s.relayFloorFeeSompi)
        })),
        thresholdCurve: curve.map((r) => ({
          activeSlots: r.activeSlots,
          txBytes: Number(r.txBytes),
          computeMass: Number(r.computeMass),
          feeMass: Number(r.feeMass),
          feeMassDominatedBy: r.feeMassDominatedBy,
          relayFloorFeeSompi: r.relayFloorFeeSompi.toString(),
          relayFloorFeeKas: fmtKas(r.relayFloorFeeSompi)
        })),
        heartbeat,
        profiles,
        measuredShapeCount: V7_MEASURED_SHAPES.length
      },
      null,
      2
    )
  );
} else {
  console.log("=== v0.7 SHAPES (relay floor, measured production bytes) ===");
  console.log("kind             | shape                                          |  tx B | compute | transient | fee mass | dominated | relay-floor fee KAS");
  for (const s of shapes) {
    console.log(
      `${s.kind.padEnd(16)} | ${s.label.padEnd(46)} | ${String(s.txBytes).padStart(5)} | ${String(s.computeMass).padStart(7)} | ${String(s.transientMass).padStart(9)} | ${String(s.feeMass).padStart(8)} | ${s.feeMassDominatedBy.padEnd(9)} | ${fmtKas(s.relayFloorFeeSompi).padStart(19)}`
    );
  }
  console.log("\n=== ROOT THRESHOLD CURVE (the owner set's own cost) ===");
  console.log("active owners | tx B (constant) | compute mass | fee mass | dominated | relay-floor fee KAS | vs 1-of-1");
  const base = curve[0].relayFloorFeeSompi;
  for (const r of curve) {
    const premiumBps = ((r.relayFloorFeeSompi - base) * 10000n) / base;
    console.log(
      `${String(r.activeSlots).padStart(13)} | ${String(r.txBytes).padStart(15)} | ${String(r.computeMass).padStart(12)} | ${String(r.feeMass).padStart(8)} | ${r.feeMassDominatedBy.padEnd(9)} | ${fmtKas(r.relayFloorFeeSompi).padStart(19)} | ${`+${premiumBps} bps`.padStart(9)}`
    );
  }
  console.log(`\ncrossover: the fee is FLAT up to ${ROOT_FEE_CROSSOVER_ACTIVE_SLOTS - 1} active owners and rises from ${ROOT_FEE_CROSSOVER_ACTIVE_SLOTS}`);

  console.log("\n=== DEAD-MAN'S-SWITCH HEARTBEAT (one root AUTHORIZE per idle window) ===");
  console.log("window              | recoveryDelayDaa | heartbeats/yr | cost/yr KAS (3 owners) | cost/yr KAS (12 owners)");
  for (const h of heartbeat) {
    console.log(
      `${h.label.padEnd(19)} | ${h.daa.padStart(16)} | ${h.heartbeatsPerYear.padStart(13)} | ${fmtKas(h.costPerYearSompiAt3).padStart(22)} | ${fmtKas(h.costPerYearSompiAt12).padStart(23)}`
    );
  }

  console.log("\n=== ORGANIZATIONAL COST (illustrative months; substitute your own counts) ===");
  console.log("profile                                        | owner ops | root actions | delegate spends | total KAS");
  for (const p of profiles) {
    console.log(`${p.name.padEnd(46)} | ${String(p.ownerOps).padStart(9)} | ${String(p.rootOnlyActions + p.heartbeats).padStart(12)} | ${String(p.delegateSpends).padStart(15)} | ${p.totalKas.padStart(9)}`);
  }
}
