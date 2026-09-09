"use strict";

/*
 * KIP-9 STORAGE MASS — an EXACT model of rusty-kaspa v2.0.1
 * consensus/core/src/mass/mod.rs (`calc_storage_mass` + `utxo_plurality`).
 *
 * A CONSENSUS dimension bounded per transaction by the post-Toccata block-fit
 * limit (500,000 grams): an over-limit value makes a transaction INVALID
 * regardless of the fee paid ("transaction storage mass of N is larger than
 * max allowed size of 500000"). Pure BigInt; no floating point.
 *
 * PLURALITY (the part the first version of this module omitted — found the
 * hard way on 2026-09-03 when a live HD level-1 spend was refused at 840,919
 * grams while this module said ~210,000): every UTXO occupies
 * p = ceil((63 + spk_script_len + (32 if it carries a covenant id)) / 100)
 * storage units and contributes C · p² / amount, so a covenant-bearing P2SH
 * output (35-byte script + 32-byte covenant id → 130 bytes → p = 2) weighs
 * FOUR times a plain output of the same amount. Standard plain outputs have
 * p = 1, which is why the omission never surfaced on plain shapes.
 *
 *   harmonic_outs  = Σ_o  C · p(o)² / amount(o)
 *   |O| = Σ p(o);  |I| = Σ p(i)
 *   relaxed path  (|O| = 1, or (≤ 2 inputs and (|I| = 1 or |O| = |I| = 2))):
 *       max(0, harmonic_outs − Σ_i C · p(i)² / amount(i))
 *   otherwise:
 *       mean = max(1, Σ amount(i) / |I|);  max(0, harmonic_outs − |I| · (C / mean))
 *
 * Every division is integer division, exactly as the node computes it.
 *
 * API: cells are `{ amount: BigInt, plurality: BigInt }`; a bare positive
 * BigInt is accepted as a plurality-1 cell (the pre-plurality call shape) so
 * plain-shape callers keep working — but any caller that can see the script
 * and covenant fields MUST pass real cells (`cellsOfFrozenTx`).
 */
const STORAGE_MASS_PARAMETER = 1_000_000_000_000n; // C
const STORAGE_MASS_LIMIT = 500_000n; // per-transaction block-fit limit (post-Toccata)
const UTXO_CONST_STORAGE = 63; // outpoint tx_id 32 + index 4 + amount 8 + DAA 8 + is_coinbase 1 + spk version 2 + spk len 8
const UTXO_COVENANT_STORAGE = 32; // HASH_SIZE
const UTXO_UNIT_SIZE = 100;

function fail(message) {
  throw new Error(`storage-mass: ${message}`);
}

/* rusty-kaspa `utxo_plurality(spk, has_covenant_id)` */
function utxoPlurality({ scriptLenBytes, hasCovenant }) {
  if (!Number.isInteger(scriptLenBytes) || scriptLenBytes < 0) fail("scriptLenBytes must be a non-negative integer");
  const bytes = UTXO_CONST_STORAGE + scriptLenBytes + (hasCovenant ? UTXO_COVENANT_STORAGE : 0);
  return BigInt(Math.ceil(bytes / UTXO_UNIT_SIZE));
}

function utxoPluralityOfScriptHex(scriptHex, hasCovenant) {
  if (typeof scriptHex !== "string" || scriptHex.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(scriptHex)) fail("scriptHex must be an even-length hex string");
  return utxoPlurality({ scriptLenBytes: scriptHex.length / 2, hasCovenant: Boolean(hasCovenant) });
}

function cells(list, label) {
  if (!Array.isArray(list) || list.length === 0) fail(`${label} must be a non-empty array of cells or BigInt sompi`);
  return list.map((v, i) => {
    if (typeof v === "bigint") {
      if (v <= 0n) fail(`${label}[${i}] must be a positive BigInt`);
      return { amount: v, plurality: 1n };
    }
    if (!v || typeof v !== "object" || typeof v.amount !== "bigint" || v.amount <= 0n) fail(`${label}[${i}].amount must be a positive BigInt`);
    const p = typeof v.plurality === "bigint" ? v.plurality : (v.plurality === undefined ? 1n : BigInt(v.plurality));
    if (p < 1n) fail(`${label}[${i}].plurality must be >= 1`);
    return { amount: v.amount, plurality: p };
  });
}

function harmonic(list) {
  return list.reduce((s, c) => s + (STORAGE_MASS_PARAMETER * c.plurality * c.plurality) / c.amount, 0n);
}

function insTermOf(ins, outsPlurality) {
  const insPlurality = ins.reduce((s, c) => s + c.plurality, 0n);
  let relaxed;
  if (outsPlurality === 1n) relaxed = true;
  else if (ins.length > 2) relaxed = false;
  else relaxed = insPlurality === 1n || (outsPlurality === 2n && insPlurality === 2n);
  if (relaxed) return harmonic(ins);
  const sumIns = ins.reduce((s, c) => s + c.amount, 0n);
  let mean = sumIns / insPlurality;
  if (mean < 1n) mean = 1n;
  return insPlurality * (STORAGE_MASS_PARAMETER / mean);
}

function calcStorageMass(inputCells, outputCells) {
  const ins = cells(inputCells, "inputs");
  const outs = cells(outputCells, "outputs");
  const outsPlurality = outs.reduce((s, c) => s + c.plurality, 0n);
  const harmonicOuts = harmonic(outs);
  const insTerm = insTermOf(ins, outsPlurality);
  return harmonicOuts > insTerm ? harmonicOuts - insTerm : 0n;
}

/* Cells of a frozen PolicyVault transaction (sdk frozen-tx shape): inputs
 * carry `utxo.{amount, scriptPublicKey.scriptHex, covenantId}`, outputs carry
 * `{value, scriptPublicKey.scriptHex, covenant}`. */
function cellsOfFrozenTx(frozen) {
  if (!frozen || !Array.isArray(frozen.inputs) || !Array.isArray(frozen.outputs)) fail("a frozen transaction with inputs and outputs is required");
  const inputCells = frozen.inputs.map((i, k) => {
    const u = i && i.utxo;
    if (!u || !u.scriptPublicKey || typeof u.scriptPublicKey.scriptHex !== "string") fail(`inputs[${k}].utxo.scriptPublicKey.scriptHex is required to compute plurality`);
    return { amount: BigInt(u.amount), plurality: utxoPluralityOfScriptHex(u.scriptPublicKey.scriptHex, u.covenantId !== null && u.covenantId !== undefined) };
  });
  const outputCells = frozen.outputs.map((o, k) => {
    if (!o || !o.scriptPublicKey || typeof o.scriptPublicKey.scriptHex !== "string") fail(`outputs[${k}].scriptPublicKey.scriptHex is required to compute plurality`);
    return { amount: BigInt(o.value), plurality: utxoPluralityOfScriptHex(o.scriptPublicKey.scriptHex, o.covenant !== null && o.covenant !== undefined) };
  });
  return { inputCells, outputCells };
}

/* The smallest amount for output `index` (its plurality kept) that keeps
 * storage mass within the limit (or null if impossible). */
function minimumOutputValueForLimit(inputCells, outputCells, index, limit = STORAGE_MASS_LIMIT) {
  const ins = cells(inputCells, "inputs");
  const outs = cells(outputCells, "outputs");
  if (!Number.isInteger(index) || index < 0 || index >= outs.length) fail("index out of range");
  const outsPlurality = outs.reduce((s, c) => s + c.plurality, 0n);
  const others = outs.reduce((s, c, i) => (i === index ? s : s + (STORAGE_MASS_PARAMETER * c.plurality * c.plurality) / c.amount), 0n);
  const insTerm = insTermOf(ins, outsPlurality);
  const room = limit + insTerm - others;
  if (room <= 0n) return null;
  const p = outs[index].plurality;
  let candidate = (STORAGE_MASS_PARAMETER * p * p + room - 1n) / room;
  /* integer division rounds down; step up until the exact formula fits */
  for (let guard = 0; guard < 8; guard++) {
    const test = outs.map((c, i) => (i === index ? { amount: candidate, plurality: c.plurality } : c));
    if (calcStorageMass(ins, test) <= limit) return candidate;
    candidate += 1n;
  }
  return null;
}

module.exports = {
  STORAGE_MASS_PARAMETER,
  STORAGE_MASS_LIMIT,
  UTXO_CONST_STORAGE,
  UTXO_COVENANT_STORAGE,
  UTXO_UNIT_SIZE,
  utxoPlurality,
  utxoPluralityOfScriptHex,
  cellsOfFrozenTx,
  calcStorageMass,
  minimumOutputValueForLimit
};
