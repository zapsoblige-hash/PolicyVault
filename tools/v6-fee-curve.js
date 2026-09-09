"use strict";
/*
 * v0.6 ECONOMIC VIABILITY CURVE (owner addendum 2026-09-03 §A).
 *
 * Computes the candidate swap transaction's expected KAS network fee under
 * CURRENT mainnet fee policy (rusty-kaspa v2.0.1, post-Toccata) for
 * representative swap principals, and reports fee-as-percentage of swap
 * value. Deterministic; no node access; no economic threshold is invented.
 *
 * Fee policy modeled (mining/src/mempool/check_transaction_standard.rs +
 * config.rs, consensus/core/src/mass/mod.rs):
 *   relay floor  = ceil(max(compute_mass, normalized_transient) × 100 sompi/gram)
 *                  (DEFAULT_MINIMUM_RELAY_TRANSACTION_FEE = 100,000 sompi/kg)
 *   normalized_transient = transient_mass × 0.5 (raw_post cofactor)
 *   storage_mass (KIP-9) = max(0, Σ C/out_i − |I|·C/mean(in)) with C = 10^12
 *                  for |I| > 2 (arithmetic path) — a CONSENSUS dimension
 *                  bounded by the 500,000-gram block-fit limit; it does not
 *                  enter the relay-fee floor but an over-limit value makes
 *                  the transaction INVALID, so it is reported per principal.
 * Non-contextual masses are the real-engine measurements of
 * tests/vm/tests/v6_production.rs (v6_measurement_units_mass_standardness,
 * 2026-09-03; upstream kcc20.sil bound-2 template, pool fixture redeem
 * 10,566 B, agent depth 12 / swap depth 12) — the max-depth (worst) shapes.
 *
 * Usage: node tools/v6-fee-curve.js [--json]
 */
const SOMPI = 100_000_000n;
const RELAY_SOMPI_PER_GRAM = 100n;
const C = 1_000_000_000_000n;
const STORAGE_LIMIT = 500_000n;

/* measured (compute_mass, transient_mass) at max depths */
const SHAPES = {
  sellA: { compute: 47_849n, transient: 163_236n, outputs: 5, inputs: 4, label: "tokenAtomicSell type A (proceeds -> principal)" },
  sellB: { compute: 47_186n + 663n, transient: 160_744n + 2_492n, outputs: 6, inputs: 4, label: "tokenAtomicSell type B (proceeds -> allowlisted P2PK)" },
  buy: { compute: 47_849n, transient: 163_236n, outputs: 5, inputs: 4, label: "tokenAtomicBuy (consideration <- principal)" }
};
const PRINCIPALS_KAS = [1n, 5n, 10n, 50n, 100n, 500n, 1000n];

/* representative live shape: controller value, note carries, pool reserve, protocol fee 20 bps of the swap value */
const CONTROLLER_KAS = 10n * SOMPI; // fee reserve + principal held by the controller (independent of the swap size)
const NOTE_CARRY = SOMPI / 5n; // 0.2 KAS per token note (sized for storage mass; persists across swaps)
const POOL_KAS = 10_000n * SOMPI;
const { calcStorageMass, minimumOutputValueForLimit } = require("../core/model/storage-mass");

const PROTO_BPS = 20n;

function ceilDiv(a, b) {
  return (a + b - 1n) / b;
}
function relayFloor(shape) {
  const normalizedTransient = ceilDiv(shape.transient, 2n);
  const feeMass = shape.compute > normalizedTransient ? shape.compute : normalizedTransient;
  return { feeMass, fee: feeMass * RELAY_SOMPI_PER_GRAM };
}
/* KIP-9 CORRECTED: every controller/token-note/pool output+input is a
 * covenant-bearing P2SH cell (plurality 2 — 4x a plain cell); the
 * protocol-fee and type-B proceeds outputs are plain P2PK (plurality 1).
 * Delegates to the exact rusty-kaspa v2.0.1 model in core/model/storage-mass.js. */
function cellsFor(amounts, plainTailCount) {
  // the last `plainTailCount` outputs (proto [, proceeds]) are plain P2PK; the rest are covenant P2SH
  const covCount = amounts.length - plainTailCount;
  return amounts.map((a, i) => ({ amount: a, plurality: i < covCount ? 2n : 1n }));
}
function storageMassCells(inCells, outCells) {
  return calcStorageMass(inCells, outCells);
}
function pct(fee, value) {
  /* basis points × 100 for two decimals */
  return Number((fee * 1_000_000n) / value) / 10_000;
}
function fmtKas(sompi) {
  const s = sompi.toString().padStart(9, "0");
  return `${s.slice(0, -8)}.${s.slice(-8)}`;
}

const rows = [];
for (const [key, shape] of Object.entries(SHAPES)) {
  const { feeMass, fee } = relayFloor(shape);
  for (const p of PRINCIPALS_KAS) {
    const value = p * SOMPI;
    const proto = ceilDiv(value * PROTO_BPS, 10_000n);
    /* controller value before/after: a buy needs principal >= the consideration, so the
     * controller enters with BASE + value and leaves with BASE; a type-A sell enters with
     * BASE and leaves with BASE + net proceeds */
    const ctrlIn = key === "buy" ? CONTROLLER_KAS + value : CONTROLLER_KAS;
    const ctrlOut = key === "buy" ? CONTROLLER_KAS : key === "sellA" ? CONTROLLER_KAS + value - proto : CONTROLLER_KAS;
    /* outputs: successor, our note, pool note, pool successor, protocol fee [, proceeds] */
    const outs = key === "sellB"
      ? [ctrlOut, NOTE_CARRY, NOTE_CARRY, POOL_KAS - value, proto, value - proto]
      : key === "sellA"
        ? [ctrlOut, NOTE_CARRY, NOTE_CARRY, POOL_KAS - value, proto]
        : [ctrlOut, NOTE_CARRY, NOTE_CARRY, POOL_KAS + value - proto, proto];
    const ins = [ctrlIn, NOTE_CARRY, NOTE_CARRY, POOL_KAS];
    const plainTail = key === "sellB" ? 2 : 1; // proto [, proceeds]
    const inCells = ins.map((a) => ({ amount: a, plurality: 2n })); // controller, our note, pool note, pool — all covenant P2SH
    const outCells = cellsFor(outs, plainTail);
    const feeOutIdx = 4;
    const storage = storageMassCells(inCells, outCells);
    /* if storage mass exceeds the block-fit limit the transaction is INVALID; the only
     * builder-side remedy is to PAD the protocol-fee output (an over-payment to the venue's
     * fee key, still <= the owner's maxProtocolFeeKas) until storage mass fits */
    let paddedProto = proto;
    let paddedStorage = storage;
    if (storage > STORAGE_LIMIT) {
      const min = minimumOutputValueForLimit(inCells, outCells, feeOutIdx);
      paddedProto = min === null ? -1n : min;
      if (paddedProto > 0n) {
        const outs2 = outCells.map((c, i) => (i === feeOutIdx ? { amount: paddedProto, plurality: c.plurality } : c));
        paddedStorage = storageMassCells(inCells, outs2);
      }
    }
    const padCost = paddedProto > proto ? paddedProto - proto : 0n;
    rows.push({
      shape: key,
      principalKas: p.toString(),
      feeMassGrams: feeMass.toString(),
      relayFeeSompi: fee.toString(),
      relayFeeKas: fmtKas(fee),
      feePctOfSwap: pct(fee, value),
      protocolFeeSompi: proto.toString(),
      storageMassGrams: storage.toString(),
      storageWithinLimit: storage <= STORAGE_LIMIT,
      protocolFeeOutputPaddedToSompi: paddedProto.toString(),
      paddedStorageMassGrams: paddedStorage.toString(),
      paddingCostSompi: padCost.toString(),
      effectiveCostPctOfSwap: pct(fee + padCost, value)
    });
  }
}

if (process.argv.includes("--json")) {
  console.log(JSON.stringify({ generatedFrom: "tests/vm/tests/v6_production.rs measurements 2026-09-03", policy: { relaySompiPerGram: 100, storageC: C.toString(), storageLimit: STORAGE_LIMIT.toString() }, assumptions: { controllerKas: CONTROLLER_KAS.toString(), noteCarry: NOTE_CARRY.toString(), poolKas: POOL_KAS.toString(), protocolFeeBps: PROTO_BPS.toString() }, rows }, null, 2));
} else {
  console.log("shape  | principal KAS | fee mass g | relay-floor fee KAS | fee % of swap | proto-fee out sompi | storage mass g | valid | padded proto-fee out | padding cost sompi | effective cost %");
  for (const r of rows) {
    console.log(`${r.shape.padEnd(6)} | ${r.principalKas.padStart(13)} | ${r.feeMassGrams.padStart(10)} | ${r.relayFeeKas.padStart(19)} | ${String(r.feePctOfSwap.toFixed(3)).padStart(12)}% | ${r.protocolFeeSompi.padStart(19)} | ${r.storageMassGrams.padStart(14)} | ${r.storageWithinLimit ? "yes" : "NO "}   | ${r.protocolFeeOutputPaddedToSompi.padStart(20)} | ${r.paddingCostSompi.padStart(18)} | ${String(r.effectiveCostPctOfSwap.toFixed(3)).padStart(14)}%`);
  }
}
