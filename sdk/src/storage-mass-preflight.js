"use strict";

/*
 * KIP-9 STORAGE-MASS PREFLIGHT for SDK builders.
 *
 * A transaction whose storage mass exceeds the per-transaction limit is
 * REJECTED by consensus/mempool ("transaction storage mass of N is larger
 * than max allowed size of 500000"). The covenant cannot see this bound, so
 * a builder that lets a tiny output through produces bytes that are
 * consensus-refused after signing — a reliability defect, never a
 * funds-safety one (it fails closed at the node), but exactly the class the
 * production-byte rule exists to catch before a signature is spent
 * (Wave 2: the first HD live level-1 spend was refused with 840,919 grams).
 *
 * This helper is PURE over the frozen transaction's input/output values and
 * delegates the arithmetic to core/model/storage-mass.js (the same formula
 * the mass measurements use). It only ever REFUSES; it never changes bytes.
 */

const { calcStorageMass, minimumOutputValueForLimit, cellsOfFrozenTx, STORAGE_MASS_LIMIT } = require("../../core/model/storage-mass");

function assertStorageMassWithinLimit(frozen, label) {
  const { inputCells, outputCells } = cellsOfFrozenTx(frozen);
  const inputValues = inputCells;
  const outputValues = outputCells.map((c) => c.amount);
  const mass = calcStorageMass(inputCells, outputCells);
  if (mass <= STORAGE_MASS_LIMIT) return { storageMass: mass };
  /* name the smallest output and the value that would fit, so the caller can
   * fix the shape instead of learning it from the node after signing */
  let smallest = 0;
  for (let i = 1; i < outputValues.length; i++) if (outputValues[i] < outputValues[smallest]) smallest = i;
  const minimum = minimumOutputValueForLimit(inputCells, outputCells, smallest);
  const e = new Error(`${label}: storage mass ${mass} exceeds the KIP-9 per-transaction limit ${STORAGE_MASS_LIMIT} — consensus would reject this transaction; smallest output #${smallest} = ${outputValues[smallest]} sompi (minimum that fits: ${minimum === null ? "none — reshape the transaction" : `${minimum} sompi`}); outputs [${outputCells.map((c) => `${c.amount}×p${c.plurality}`).join(", ")}]`);
  e.code = "STORAGE_MASS_EXCEEDS_LIMIT";
  e.storageMass = mass;
  e.smallestOutputIndex = smallest;
  e.minimumSompi = minimum === null ? null : minimum.toString();
  throw e;
}

module.exports = { assertStorageMassWithinLimit };
