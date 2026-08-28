"use strict";

/*
 * Authoritative Toccata transaction-v1 fee/mass accounting for PolicyVault.
 *
 * Source-backed reimplementation of rusty-kaspa's mass and minimum-relay-fee
 * rules (see docs/fee-mass-spec.md for the exact source citations). The WASM
 * helpers undercount covenant + v1 transactions, so funds paths use this
 * module instead and never trust the WASM recalculators.
 *
 * All arithmetic is BigInt. No floating point on the fee path (the single
 * rational cofactor is applied exactly as an integer ratio). Fails closed.
 */

// --- consensus constants (rusty-kaspa v2.0.1, testnet-10) ---
const MASS_PER_TX_BYTE = 1n;
const MASS_PER_SCRIPT_PUB_KEY_BYTE = 10n;
const GRAMS_PER_COMPUTE_BUDGET_UNIT = 100n;
const TRANSIENT_BYTE_TO_MASS_FACTOR = 4n;
const MINIMUM_RELAY_TRANSACTION_FEE = 100_000n; // sompi/kg
const RELAY_FEE_DIVISOR = 1000n;

// Post-Toccata block mass limits → transient cofactor = compute/transient.
const BLOCK_COMPUTE_LIMIT = 500_000n;
const BLOCK_TRANSIENT_LIMIT = 1_000_000n;
const STANDARD_MASS_CAP = 500_000n;

// Serialized-size fixed widths.
const OUTPOINT_SIZE = 36n; // 32 txid + 4 index
const SUBNETWORK_ID_SIZE = 20n;
const HASH_SIZE = 32n;

function fail(message) {
  throw new Error(`fee-mass: ${message}`);
}

function ceilDiv(a, b) {
  return (a + b - 1n) / b;
}

function hexLen(hex) {
  if (hex === undefined || hex === null || hex === "") {
    return 0n;
  }
  if (typeof hex !== "string" || hex.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(hex)) {
    fail(`expected an even-length hex string, got ${JSON.stringify(hex).slice(0, 40)}`);
  }
  return BigInt(hex.length / 2);
}

/*
 * A minimal transaction shape descriptor, read from a WASM Transaction or
 * built directly:
 *   { version, inputs: [{ signatureScriptHex, computeBudget }],
 *     outputs: [{ scriptHex, hasCovenant }], payloadHex }
 */
function estimatedSerializedSize(tx) {
  if (tx.version < 1) {
    fail("this module is for transaction version >= 1 (Toccata)");
  }
  let size = 2n; // version u16
  size += 8n; // input count u64
  for (const input of tx.inputs) {
    size += OUTPOINT_SIZE;
    size += 8n + hexLen(input.signatureScriptHex); // sig-script len prefix + bytes
    size += 8n; // sequence u64
    size += 2n; // compute_budget u16 (v >= 1)
  }
  size += 8n; // output count u64
  for (const output of tx.outputs) {
    size += 8n; // value u64
    size += 2n; // spk version u16
    size += 8n + hexLen(output.scriptHex); // spk len prefix + bytes
    if (output.hasCovenant) {
      size += 2n + HASH_SIZE; // authorizing_input u16 + covenant_id
    }
  }
  size += 8n; // lock time u64
  size += SUBNETWORK_ID_SIZE;
  size += 8n; // gas u64
  size += HASH_SIZE; // payload hash
  size += 8n + hexLen(tx.payloadHex); // payload len prefix + bytes
  return size;
}

function computeMass(tx) {
  const size = estimatedSerializedSize(tx);
  const sizeMass = size * MASS_PER_TX_BYTE;

  let totalSpkSize = 0n;
  for (const output of tx.outputs) {
    totalSpkSize += 2n + hexLen(output.scriptHex); // spk version u16 + script bytes
  }
  const spkMass = totalSpkSize * MASS_PER_SCRIPT_PUB_KEY_BYTE;

  let totalComputeBudget = 0n;
  for (const input of tx.inputs) {
    if (input.computeBudget === undefined || input.computeBudget === null) {
      fail("v1 input is missing computeBudget");
    }
    totalComputeBudget += BigInt(input.computeBudget);
  }
  const scriptMass = totalComputeBudget * GRAMS_PER_COMPUTE_BUDGET_UNIT;

  return { size, computeMass: sizeMass + spkMass + scriptMass };
}

/*
 * fee_mass = max(compute_mass, normalized_transient), where
 * normalized_transient = ceil(transient_mass * (L_compute / L_transient)).
 * Applied as an exact integer ratio (no floats).
 */
function feeMass(tx) {
  const { size, computeMass: cm } = computeMass(tx);
  const transientMass = size * TRANSIENT_BYTE_TO_MASS_FACTOR;
  const normalizedTransient = ceilDiv(transientMass * BLOCK_COMPUTE_LIMIT, BLOCK_TRANSIENT_LIMIT);
  const fm = cm > normalizedTransient ? cm : normalizedTransient;
  return { size, computeMass: cm, transientMass, normalizedTransient, feeMass: fm };
}

/*
 * The exact minimum consensus relay fee, in sompi:
 *   minimum_fee = (fee_mass * MINIMUM_RELAY_TRANSACTION_FEE) / 1000
 * with the node's `if minimum_fee == 0 { minimum_fee = relay_fee }` floor.
 */
function calculateRequiredFee(tx) {
  const m = feeMass(tx);
  if (m.feeMass > STANDARD_MASS_CAP) {
    fail(`fee_mass ${m.feeMass} exceeds the standard mass cap ${STANDARD_MASS_CAP}`);
  }
  let minimumFee = (m.feeMass * MINIMUM_RELAY_TRANSACTION_FEE) / RELAY_FEE_DIVISOR;
  if (minimumFee === 0n) {
    minimumFee = MINIMUM_RELAY_TRANSACTION_FEE;
  }
  return { ...m, minimumRequiredFee: minimumFee };
}

/*
 * Read a WASM Transaction object into the descriptor this module needs.
 * Reads only structural fields; never trusts WASM mass/fee helpers.
 */
function describeWasmTransaction(transaction) {
  return {
    version: Number(transaction.version),
    payloadHex: transaction.payload || "",
    inputs: transaction.inputs.map((input) => ({
      signatureScriptHex: input.signatureScript || "",
      computeBudget: input.computeBudget
    })),
    outputs: transaction.outputs.map((output) => {
      const spk = output.scriptPublicKey;
      const scriptHex = typeof spk === "string" ? spk : spk.script;
      return { scriptHex, hasCovenant: output.covenant !== undefined && output.covenant !== null };
    })
  };
}

/*
 * Validate a covenant-input compute budget against the expected value
 * (PolicyVault uses 100 for the covenant input, 10 for ordinary inputs).
 */
function validateComputeBudget(value, expected, label) {
  if (Number(value) !== Number(expected)) {
    fail(`${label} compute budget is ${value}, expected ${expected}`);
  }
}

/*
 * Finalize a covenant-spending transaction with the EXACT minimum fee plus
 * an optional, clearly-separated relay margin.
 *
 * Convergence: signature-script lengths do not depend on output *values*
 * (Schnorr signatures are fixed-width; covenant call fields are
 * fixed-width). So we (1) fully sign with a placeholder change, (2) measure
 * the exact required fee, (3) set change = totalFuel - selectedFee,
 * (4) re-sign once, (5) assert sig-script lengths are unchanged (=> mass
 * unchanged => fee still exact) and the realized fee meets the requirement.
 * One re-sign always suffices; there is no unbounded retry loop.
 *
 * signAll(transaction) must re-attach every signature/covenant call to the
 * transaction in place and return it. changeIndex is the ordinary change
 * output whose value absorbs the fee. totalInputValue is the sum of ALL
 * input UTXO values. The fee is, by definition, totalInputs − totalOutputs;
 * only the change output moves, so the extra fee comes from ordinary fuel
 * and never from protected principal (the covenant-funded payment and
 * successor outputs are left untouched). relayMargin is an optional extra
 * fee (default 0).
 */
function finalizeWithExactFee({ transaction, signAll, changeIndex, totalInputValue, relayMargin = 0n }) {
  const totalInput = BigInt(totalInputValue);
  const margin = BigInt(relayMargin);

  signAll(transaction);
  const lengths1 = transaction.inputs.map((i) => hexLen(i.signatureScript || ""));
  const required1 = calculateRequiredFee(describeWasmTransaction(transaction)).minimumRequiredFee;

  const selectedFee = required1 + margin;
  const outputsSum = transaction.outputs.reduce((s, o) => s + BigInt(o.value), 0n);
  const nonChangeOutputs = outputsSum - BigInt(transaction.outputs[changeIndex].value);
  // fee = totalInput − (nonChangeOutputs + change)  ⇒  change = totalInput − nonChangeOutputs − fee
  const newChange = totalInput - nonChangeOutputs - selectedFee;
  if (newChange <= 0n) {
    fail(`inputs ${totalInput} cannot cover outputs ${nonChangeOutputs} + fee ${selectedFee}`);
  }

  const adjusted = transaction.outputs;
  adjusted[changeIndex].value = newChange;
  transaction.outputs = adjusted;

  signAll(transaction);
  const lengths2 = transaction.inputs.map((i) => hexLen(i.signatureScript || ""));

  // Sig-script lengths must be stable, else mass (and the fee) would drift.
  for (let i = 0; i < lengths1.length; i++) {
    if (lengths1[i] !== lengths2[i]) {
      fail(`signature-script length for input ${i} changed on re-sign (${lengths1[i]} -> ${lengths2[i]}); fee did not converge`);
    }
  }

  const required2 = calculateRequiredFee(describeWasmTransaction(transaction)).minimumRequiredFee;
  const actualFee = totalInput - transaction.outputs.reduce((s, o) => s + BigInt(o.value), 0n);
  if (required2 !== required1) {
    fail(`required fee drifted (${required1} -> ${required2})`);
  }
  if (actualFee < required2) {
    fail(`finalized fee ${actualFee} is below the required minimum ${required2}`);
  }

  return { requiredFee: required2, actualFee, change: newChange };
}

module.exports = {
  MINIMUM_RELAY_TRANSACTION_FEE,
  STANDARD_MASS_CAP,
  estimatedSerializedSize,
  computeMass,
  feeMass,
  calculateRequiredFee,
  describeWasmTransaction,
  validateComputeBudget,
  finalizeWithExactFee
};
