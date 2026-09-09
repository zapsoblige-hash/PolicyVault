"use strict";

/*
 * PolicyVault v0.7 ORGANIZATIONAL ROOT — the EXACT FEE / MASS MODEL.
 *
 * What an organization actually PAYS, per transaction shape, at the consensus
 * relay floor. Every row below is a MEASUREMENT of production bytes: a real
 * transaction built and frozen by the production SDK (real SilverScript
 * compiler, real pv_call_encoder / pv_tx_probe, real Schnorr signatures over
 * TEST-ONLY keys) and then FINALIZED, so the byte geometry recorded here is
 * the geometry a node would receive. Regenerate with
 *   node sdk/tools/measure-v7-fee-shapes.js
 * which re-measures every shape and refuses if any derived fee disagrees with
 * the fee the SDK itself committed.
 *
 * NOTHING HERE IS A NEW CONSENSUS RULE. The arithmetic is
 * core/model/fee-mass.js (the source-backed reimplementation of rusty-kaspa's
 * mass and minimum-relay-fee rules) and core/model/storage-mass.js (KIP-9).
 * This module only carries the measured SHAPES and derives from them, so a
 * change to the consensus rules changes these numbers in exactly one place.
 *
 * THE THREE DIMENSIONS THAT DECIDE THE COST
 *
 *   fee_mass  = max(compute_mass, ceil(transient_mass x 500000/1000000))
 *   relay fee = fee_mass x 100 sompi          (100,000 sompi/kg)
 *   compute_mass  = bytes + 10 x SUM(2 + spk_bytes) + 100 x SUM(compute_budget)
 *   transient_mass = 4 x bytes
 *   storage_mass (KIP-9) is a VALIDITY bound (500,000 grams per transaction),
 *     never a fee: an over-limit transaction is invalid whatever fee it pays.
 *
 * THE ONE RESULT WORTH KNOWING. A v0.7 root transaction's signature blob is a
 * CONSTANT 780 bytes at every threshold (abstaining slots carry the canonical
 * placeholder), so its serialized size — and therefore its transient mass —
 * does not move with M or N at all. What moves is the committed COMPUTE
 * BUDGET, because the covenant runs one `checkSig` per ACTIVE owner slot. Up
 * to NINE active owners the transaction is TRANSIENT-DOMINATED and the fee is
 * FLAT; from TEN active owners compute mass overtakes and the fee starts to
 * rise. The measured crossover is recorded in ROOT_FEE_CROSSOVER_ACTIVE_SLOTS.
 *
 * Status: IMPLEMENTED + UNIT-TESTED (core/model/test/fee-mass-v7.test.js).
 * Economic record: docs/postlaunch/v0.7-economic-viability.md.
 */

const { calculateRequiredFee, MINIMUM_RELAY_TRANSACTION_FEE } = require("./fee-mass");
const { calcStorageMass, STORAGE_MASS_LIMIT } = require("./storage-mass");

/* Transaction version 1 (Toccata): every input carries a compute budget. */
const V7_TX_VERSION = 1;

/*
 * The measured shapes. `inputs[i].sigscriptBytes` and `computeBudget`, and
 * `outputs[i].scriptBytes` / `hasCovenant`, are read off the FINALIZED
 * transaction; `measured` is what the consensus arithmetic produced for it,
 * pinned so that a drift in either the shapes or the arithmetic fails a test
 * rather than silently changing what an organization is told it will pay.
 */
const V7_MEASURED_SHAPES = Object.freeze([
  {
    kind: "genesis",
    label: "organizational root genesis",
    inputs: [{ sigscriptBytes: 66, computeBudget: 10 }],
    outputs: [{ scriptBytes: 35, hasCovenant: true }, { scriptBytes: 34, hasCovenant: false }],
    payloadBytes: 0,
    measured: { txBytes: 353, computeMass: 2083, transientMass: 1412, feeMass: 2083, feeMassDominatedBy: "compute", relayFloorFeeSompi: "208300", storageMassAtReferenceValues: 3761 },
    note: "one-time: creates the organization's root UTXO"
  },
  {
    kind: "genesis",
    label: "rooted vault genesis",
    inputs: [{ sigscriptBytes: 66, computeBudget: 10 }],
    outputs: [{ scriptBytes: 35, hasCovenant: true }, { scriptBytes: 34, hasCovenant: false }],
    payloadBytes: 0,
    measured: { txBytes: 353, computeMass: 2083, transientMass: 1412, feeMass: 2083, feeMassDominatedBy: "compute", relayFloorFeeSompi: "208300", storageMassAtReferenceValues: 3000 },
    note: "one-time PER VAULT: creates one rooted vault under the existing root"
  },
  {
    kind: "root-only",
    label: "root authorize (3 active owners)",
    inputs: [{ sigscriptBytes: 12776, computeBudget: 42 }, { sigscriptBytes: 66, computeBudget: 10 }],
    outputs: [{ scriptBytes: 35, hasCovenant: true }, { scriptBytes: 34, hasCovenant: false }],
    payloadBytes: 0,
    measured: { txBytes: 13183, computeMass: 19113, transientMass: 52732, feeMass: 26366, feeMassDominatedBy: "transient", relayFloorFeeSompi: "2636600", storageMassAtReferenceValues: 270 },
    note: "the organization's own governance transaction; the root never pays anyone"
  },
  {
    kind: "root-only",
    label: "root rotate (3 active owners)",
    inputs: [{ sigscriptBytes: 12776, computeBudget: 43 }, { sigscriptBytes: 66, computeBudget: 10 }],
    outputs: [{ scriptBytes: 35, hasCovenant: true }, { scriptBytes: 34, hasCovenant: false }],
    payloadBytes: 0,
    measured: { txBytes: 13183, computeMass: 19213, transientMass: 52732, feeMass: 26366, feeMassDominatedBy: "transient", relayFloorFeeSompi: "2636600", storageMassAtReferenceValues: 270 },
    note: "the organization's own governance transaction; the root never pays anyone"
  },
  {
    kind: "root-only",
    label: "root freeze (3 active owners)",
    inputs: [{ sigscriptBytes: 12775, computeBudget: 42 }, { sigscriptBytes: 66, computeBudget: 10 }],
    outputs: [{ scriptBytes: 35, hasCovenant: true }, { scriptBytes: 34, hasCovenant: false }],
    payloadBytes: 0,
    measured: { txBytes: 13182, computeMass: 19112, transientMass: 52728, feeMass: 26364, feeMassDominatedBy: "transient", relayFloorFeeSompi: "2636400", storageMassAtReferenceValues: 270 },
    note: "the organization's own governance transaction; the root never pays anyone"
  },
  {
    kind: "root-only",
    label: "root unfreeze (3 active owners)",
    inputs: [{ sigscriptBytes: 12776, computeBudget: 42 }, { sigscriptBytes: 66, computeBudget: 10 }],
    outputs: [{ scriptBytes: 35, hasCovenant: true }, { scriptBytes: 34, hasCovenant: false }],
    payloadBytes: 0,
    measured: { txBytes: 13183, computeMass: 19113, transientMass: 52732, feeMass: 26366, feeMassDominatedBy: "transient", relayFloorFeeSompi: "2636600", storageMassAtReferenceValues: 270 },
    note: "the organization's own governance transaction; the root never pays anyone"
  },
  {
    kind: "root-only",
    label: "root ownerRecover (3 active owners)",
    inputs: [{ sigscriptBytes: 12775, computeBudget: 43 }, { sigscriptBytes: 66, computeBudget: 10 }],
    outputs: [{ scriptBytes: 35, hasCovenant: true }, { scriptBytes: 34, hasCovenant: false }],
    payloadBytes: 0,
    measured: { txBytes: 13182, computeMass: 19212, transientMass: 52728, feeMass: 26364, feeMassDominatedBy: "transient", relayFloorFeeSompi: "2636400", storageMassAtReferenceValues: 270 },
    note: "the organization's own governance transaction; the root never pays anyone"
  },
  {
    kind: "root-only",
    label: "root succession (3 active owners)",
    inputs: [{ sigscriptBytes: 12057, computeBudget: 20 }, { sigscriptBytes: 66, computeBudget: 10 }],
    outputs: [{ scriptBytes: 35, hasCovenant: true }, { scriptBytes: 34, hasCovenant: false }],
    payloadBytes: 0,
    measured: { txBytes: 12464, computeMass: 16194, transientMass: 49856, feeMass: 24928, feeMassDominatedBy: "transient", relayFloorFeeSompi: "2492800", storageMassAtReferenceValues: 255 },
    note: "the organization's own governance transaction; the root never pays anyone"
  },
  {
    kind: "threshold-sweep",
    label: "root authorize 1-of-1",
    inputs: [{ sigscriptBytes: 12776, computeBudget: 21 }, { sigscriptBytes: 66, computeBudget: 10 }],
    outputs: [{ scriptBytes: 35, hasCovenant: true }, { scriptBytes: 34, hasCovenant: false }],
    payloadBytes: 0,
    measured: { txBytes: 13183, computeMass: 17013, transientMass: 52732, feeMass: 26366, feeMassDominatedBy: "transient", relayFloorFeeSompi: "2636600", storageMassAtReferenceValues: 270 },
    note: "1 active owner slots; the covenant runs one checkSig per ACTIVE slot"
  },
  {
    kind: "threshold-sweep",
    label: "root authorize 2-of-2",
    inputs: [{ sigscriptBytes: 12776, computeBudget: 32 }, { sigscriptBytes: 66, computeBudget: 10 }],
    outputs: [{ scriptBytes: 35, hasCovenant: true }, { scriptBytes: 34, hasCovenant: false }],
    payloadBytes: 0,
    measured: { txBytes: 13183, computeMass: 18113, transientMass: 52732, feeMass: 26366, feeMassDominatedBy: "transient", relayFloorFeeSompi: "2636600", storageMassAtReferenceValues: 270 },
    note: "2 active owner slots; the covenant runs one checkSig per ACTIVE slot"
  },
  {
    kind: "threshold-sweep",
    label: "root authorize 3-of-3",
    inputs: [{ sigscriptBytes: 12776, computeBudget: 42 }, { sigscriptBytes: 66, computeBudget: 10 }],
    outputs: [{ scriptBytes: 35, hasCovenant: true }, { scriptBytes: 34, hasCovenant: false }],
    payloadBytes: 0,
    measured: { txBytes: 13183, computeMass: 19113, transientMass: 52732, feeMass: 26366, feeMassDominatedBy: "transient", relayFloorFeeSompi: "2636600", storageMassAtReferenceValues: 270 },
    note: "3 active owner slots; the covenant runs one checkSig per ACTIVE slot"
  },
  {
    kind: "threshold-sweep",
    label: "root authorize 4-of-4",
    inputs: [{ sigscriptBytes: 12776, computeBudget: 53 }, { sigscriptBytes: 66, computeBudget: 10 }],
    outputs: [{ scriptBytes: 35, hasCovenant: true }, { scriptBytes: 34, hasCovenant: false }],
    payloadBytes: 0,
    measured: { txBytes: 13183, computeMass: 20213, transientMass: 52732, feeMass: 26366, feeMassDominatedBy: "transient", relayFloorFeeSompi: "2636600", storageMassAtReferenceValues: 270 },
    note: "4 active owner slots; the covenant runs one checkSig per ACTIVE slot"
  },
  {
    kind: "threshold-sweep",
    label: "root authorize 5-of-5",
    inputs: [{ sigscriptBytes: 12776, computeBudget: 63 }, { sigscriptBytes: 66, computeBudget: 10 }],
    outputs: [{ scriptBytes: 35, hasCovenant: true }, { scriptBytes: 34, hasCovenant: false }],
    payloadBytes: 0,
    measured: { txBytes: 13183, computeMass: 21213, transientMass: 52732, feeMass: 26366, feeMassDominatedBy: "transient", relayFloorFeeSompi: "2636600", storageMassAtReferenceValues: 270 },
    note: "5 active owner slots; the covenant runs one checkSig per ACTIVE slot"
  },
  {
    kind: "threshold-sweep",
    label: "root authorize 6-of-6",
    inputs: [{ sigscriptBytes: 12776, computeBudget: 74 }, { sigscriptBytes: 66, computeBudget: 10 }],
    outputs: [{ scriptBytes: 35, hasCovenant: true }, { scriptBytes: 34, hasCovenant: false }],
    payloadBytes: 0,
    measured: { txBytes: 13183, computeMass: 22313, transientMass: 52732, feeMass: 26366, feeMassDominatedBy: "transient", relayFloorFeeSompi: "2636600", storageMassAtReferenceValues: 270 },
    note: "6 active owner slots; the covenant runs one checkSig per ACTIVE slot"
  },
  {
    kind: "threshold-sweep",
    label: "root authorize 7-of-7",
    inputs: [{ sigscriptBytes: 12776, computeBudget: 84 }, { sigscriptBytes: 66, computeBudget: 10 }],
    outputs: [{ scriptBytes: 35, hasCovenant: true }, { scriptBytes: 34, hasCovenant: false }],
    payloadBytes: 0,
    measured: { txBytes: 13183, computeMass: 23313, transientMass: 52732, feeMass: 26366, feeMassDominatedBy: "transient", relayFloorFeeSompi: "2636600", storageMassAtReferenceValues: 270 },
    note: "7 active owner slots; the covenant runs one checkSig per ACTIVE slot"
  },
  {
    kind: "threshold-sweep",
    label: "root authorize 8-of-8",
    inputs: [{ sigscriptBytes: 12776, computeBudget: 95 }, { sigscriptBytes: 66, computeBudget: 10 }],
    outputs: [{ scriptBytes: 35, hasCovenant: true }, { scriptBytes: 34, hasCovenant: false }],
    payloadBytes: 0,
    measured: { txBytes: 13183, computeMass: 24413, transientMass: 52732, feeMass: 26366, feeMassDominatedBy: "transient", relayFloorFeeSompi: "2636600", storageMassAtReferenceValues: 270 },
    note: "8 active owner slots; the covenant runs one checkSig per ACTIVE slot"
  },
  {
    kind: "threshold-sweep",
    label: "root authorize 9-of-9",
    inputs: [{ sigscriptBytes: 12776, computeBudget: 105 }, { sigscriptBytes: 66, computeBudget: 10 }],
    outputs: [{ scriptBytes: 35, hasCovenant: true }, { scriptBytes: 34, hasCovenant: false }],
    payloadBytes: 0,
    measured: { txBytes: 13183, computeMass: 25413, transientMass: 52732, feeMass: 26366, feeMassDominatedBy: "transient", relayFloorFeeSompi: "2636600", storageMassAtReferenceValues: 270 },
    note: "9 active owner slots; the covenant runs one checkSig per ACTIVE slot"
  },
  {
    kind: "threshold-sweep",
    label: "root authorize 10-of-10",
    inputs: [{ sigscriptBytes: 12776, computeBudget: 116 }, { sigscriptBytes: 66, computeBudget: 10 }],
    outputs: [{ scriptBytes: 35, hasCovenant: true }, { scriptBytes: 34, hasCovenant: false }],
    payloadBytes: 0,
    measured: { txBytes: 13183, computeMass: 26513, transientMass: 52732, feeMass: 26513, feeMassDominatedBy: "compute", relayFloorFeeSompi: "2651300", storageMassAtReferenceValues: 272 },
    note: "10 active owner slots; the covenant runs one checkSig per ACTIVE slot"
  },
  {
    kind: "threshold-sweep",
    label: "root authorize 11-of-11",
    inputs: [{ sigscriptBytes: 12776, computeBudget: 126 }, { sigscriptBytes: 66, computeBudget: 10 }],
    outputs: [{ scriptBytes: 35, hasCovenant: true }, { scriptBytes: 34, hasCovenant: false }],
    payloadBytes: 0,
    measured: { txBytes: 13183, computeMass: 27513, transientMass: 52732, feeMass: 27513, feeMassDominatedBy: "compute", relayFloorFeeSompi: "2751300", storageMassAtReferenceValues: 282 },
    note: "11 active owner slots; the covenant runs one checkSig per ACTIVE slot"
  },
  {
    kind: "threshold-sweep",
    label: "root authorize 12-of-12",
    inputs: [{ sigscriptBytes: 12776, computeBudget: 137 }, { sigscriptBytes: 66, computeBudget: 10 }],
    outputs: [{ scriptBytes: 35, hasCovenant: true }, { scriptBytes: 34, hasCovenant: false }],
    payloadBytes: 0,
    measured: { txBytes: 13183, computeMass: 28613, transientMass: 52732, feeMass: 28613, feeMassDominatedBy: "compute", relayFloorFeeSompi: "2861300", storageMassAtReferenceValues: 294 },
    note: "12 active owner slots; the covenant runs one checkSig per ACTIVE slot"
  },
  {
    kind: "rooted-owner-op",
    label: "vault ownerSetAgentRoot (root + vault + fuel)",
    inputs: [{ sigscriptBytes: 9714, computeBudget: 32 }, { sigscriptBytes: 12776, computeBudget: 42 }, { sigscriptBytes: 66, computeBudget: 10 }],
    outputs: [{ scriptBytes: 35, hasCovenant: true }, { scriptBytes: 35, hasCovenant: true }, { scriptBytes: 34, hasCovenant: false }],
    payloadBytes: 0,
    measured: { txBytes: 23038, computeMass: 32538, transientMass: 92152, feeMass: 46076, feeMassDominatedBy: "transient", relayFloorFeeSompi: "4607600", storageMassAtReferenceValues: 5817 },
    note: "ONE root input authorizes ONE vault operation in ONE transaction"
  },
  {
    kind: "rooted-owner-op",
    label: "vault ownerTopUpReserve (root + vault + fuel)",
    inputs: [{ sigscriptBytes: 9714, computeBudget: 32 }, { sigscriptBytes: 12776, computeBudget: 42 }, { sigscriptBytes: 66, computeBudget: 10 }],
    outputs: [{ scriptBytes: 35, hasCovenant: true }, { scriptBytes: 35, hasCovenant: true }, { scriptBytes: 34, hasCovenant: false }],
    payloadBytes: 0,
    measured: { txBytes: 23038, computeMass: 32538, transientMass: 92152, feeMass: 46076, feeMassDominatedBy: "transient", relayFloorFeeSompi: "4607600", storageMassAtReferenceValues: 17182 },
    note: "ONE root input authorizes ONE vault operation in ONE transaction"
  },
  {
    kind: "rooted-owner-op",
    label: "vault ownerPause (root + vault + fuel)",
    inputs: [{ sigscriptBytes: 9714, computeBudget: 32 }, { sigscriptBytes: 12776, computeBudget: 42 }, { sigscriptBytes: 66, computeBudget: 10 }],
    outputs: [{ scriptBytes: 35, hasCovenant: true }, { scriptBytes: 35, hasCovenant: true }, { scriptBytes: 34, hasCovenant: false }],
    payloadBytes: 0,
    measured: { txBytes: 23038, computeMass: 32538, transientMass: 92152, feeMass: 46076, feeMassDominatedBy: "transient", relayFloorFeeSompi: "4607600", storageMassAtReferenceValues: 5817 },
    note: "ONE root input authorizes ONE vault operation in ONE transaction"
  },
  {
    kind: "rooted-owner-op",
    label: "vault ownerUnpause (root + vault + fuel)",
    inputs: [{ sigscriptBytes: 9714, computeBudget: 32 }, { sigscriptBytes: 12776, computeBudget: 42 }, { sigscriptBytes: 66, computeBudget: 10 }],
    outputs: [{ scriptBytes: 35, hasCovenant: true }, { scriptBytes: 35, hasCovenant: true }, { scriptBytes: 34, hasCovenant: false }],
    payloadBytes: 0,
    measured: { txBytes: 23038, computeMass: 32538, transientMass: 92152, feeMass: 46076, feeMassDominatedBy: "transient", relayFloorFeeSompi: "4607600", storageMassAtReferenceValues: 5817 },
    note: "ONE root input authorizes ONE vault operation in ONE transaction"
  },
  {
    kind: "rooted-owner-op",
    label: "vault ownerEmergencyPause (root + vault + fuel)",
    inputs: [{ sigscriptBytes: 9714, computeBudget: 32 }, { sigscriptBytes: 12775, computeBudget: 42 }, { sigscriptBytes: 66, computeBudget: 10 }],
    outputs: [{ scriptBytes: 35, hasCovenant: true }, { scriptBytes: 35, hasCovenant: true }, { scriptBytes: 34, hasCovenant: false }],
    payloadBytes: 0,
    measured: { txBytes: 23037, computeMass: 32537, transientMass: 92148, feeMass: 46074, feeMassDominatedBy: "transient", relayFloorFeeSompi: "4607400", storageMassAtReferenceValues: 5816 },
    note: "ONE root input authorizes ONE vault operation in ONE transaction"
  },
  {
    kind: "rooted-owner-op",
    label: "vault ownerRecover (no token position)",
    inputs: [{ sigscriptBytes: 9682, computeBudget: 31 }, { sigscriptBytes: 12776, computeBudget: 42 }, { sigscriptBytes: 66, computeBudget: 10 }],
    outputs: [{ scriptBytes: 34, hasCovenant: false }, { scriptBytes: 35, hasCovenant: true }, { scriptBytes: 34, hasCovenant: false }],
    payloadBytes: 0,
    measured: { txBytes: 22971, computeMass: 32361, transientMass: 91884, feeMass: 45942, feeMassDominatedBy: "transient", relayFloorFeeSompi: "4594200", storageMassAtReferenceValues: 5815 },
    note: "TERMINAL: pays the reserve to the genesis-pinned recovery key"
  },
  {
    kind: "rooted-owner-op",
    label: "vault ownerRecover (with token position)",
    inputs: [{ sigscriptBytes: 9684, computeBudget: 31 }, { sigscriptBytes: 12776, computeBudget: 42 }, { sigscriptBytes: 1621, computeBudget: 6 }, { sigscriptBytes: 66, computeBudget: 10 }],
    outputs: [{ scriptBytes: 34, hasCovenant: false }, { scriptBytes: 35, hasCovenant: true }, { scriptBytes: 35, hasCovenant: true }, { scriptBytes: 34, hasCovenant: false }],
    payloadBytes: 0,
    measured: { txBytes: 24735, computeMass: 35095, transientMass: 98940, feeMass: 49470, feeMassDominatedBy: "transient", relayFloorFeeSompi: "4947000", storageMassAtReferenceValues: 6309 },
    note: "TERMINAL: reserve + the whole token position to the pinned recovery key"
  },
  {
    kind: "delegate",
    label: "delegate spend (fuel-funded)",
    inputs: [{ sigscriptBytes: 9982, computeBudget: 28 }, { sigscriptBytes: 1663, computeBudget: 6 }, { sigscriptBytes: 66, computeBudget: 10 }],
    outputs: [{ scriptBytes: 35, hasCovenant: true }, { scriptBytes: 35, hasCovenant: true }, { scriptBytes: 35, hasCovenant: true }, { scriptBytes: 34, hasCovenant: false }],
    payloadBytes: 0,
    measured: { txBytes: 12280, computeMass: 18150, transientMass: 49120, feeMass: 24560, feeMassDominatedBy: "transient", relayFloorFeeSompi: "2456000", storageMassAtReferenceValues: 56551 },
    note: "the ORDINARY operating transaction; never touches the root"
  },
  {
    kind: "delegate",
    label: "delegate spend (reserve-funded)",
    inputs: [{ sigscriptBytes: 9982, computeBudget: 28 }, { sigscriptBytes: 1663, computeBudget: 6 }],
    outputs: [{ scriptBytes: 35, hasCovenant: true }, { scriptBytes: 35, hasCovenant: true }, { scriptBytes: 35, hasCovenant: true }],
    payloadBytes: 0,
    measured: { txBytes: 12108, computeMass: 16618, transientMass: 48432, feeMass: 24216, feeMassDominatedBy: "transient", relayFloorFeeSompi: "2421600", storageMassAtReferenceValues: 51850 },
    note: "the vault's own fee reserve pays; no external fuel input"
  },
  {
    kind: "delegate",
    label: "delegate spend (period rollover)",
    inputs: [{ sigscriptBytes: 10016, computeBudget: 28 }, { sigscriptBytes: 1663, computeBudget: 6 }, { sigscriptBytes: 66, computeBudget: 10 }],
    outputs: [{ scriptBytes: 35, hasCovenant: true }, { scriptBytes: 35, hasCovenant: true }, { scriptBytes: 35, hasCovenant: true }, { scriptBytes: 34, hasCovenant: false }],
    payloadBytes: 0,
    measured: { txBytes: 12314, computeMass: 18184, transientMass: 49256, feeMass: 24628, feeMassDominatedBy: "transient", relayFloorFeeSompi: "2462800", storageMassAtReferenceValues: 56552 },
    note: "a new budget period starts; lockTime pins the new period start"
  },
  {
    kind: "deposit",
    label: "token deposit into a rooted vault",
    inputs: [{ sigscriptBytes: 1685, computeBudget: 16 }, { sigscriptBytes: 66, computeBudget: 10 }],
    outputs: [{ scriptBytes: 35, hasCovenant: true }, { scriptBytes: 34, hasCovenant: false }],
    payloadBytes: 0,
    measured: { txBytes: 2092, computeMass: 5422, transientMass: 8368, feeMass: 5422, feeMassDominatedBy: "compute", relayFloorFeeSompi: "542200", storageMassAtReferenceValues: 54 },
    note: "a user funds the vault; the vault is not an input and the root is not involved"
  }
].map(Object.freeze));

/* The measured active-slot count at which a root transaction stops being
 * transient-dominated and its fee starts to rise with the owner set. */
const ROOT_FEE_CROSSOVER_ACTIVE_SLOTS = 10;

const SHAPES_BY_LABEL = Object.freeze(Object.fromEntries(V7_MEASURED_SHAPES.map((s) => [s.label, s])));

function fail(message) {
  throw new Error(`fee-mass-v7: ${message}`);
}

/* Turn a measured shape into the descriptor core/model/fee-mass.js consumes.
 * Script CONTENT never affects mass — only its length — so a shape is
 * reconstructed from lengths alone, exactly and without inventing bytes. */
function shapeToTxDescriptor(shape) {
  const zeros = (n) => "0".repeat(n * 2);
  return {
    version: V7_TX_VERSION,
    payloadHex: zeros(shape.payloadBytes),
    inputs: shape.inputs.map((i) => ({ signatureScriptHex: zeros(i.sigscriptBytes), computeBudget: i.computeBudget })),
    outputs: shape.outputs.map((o) => ({ scriptHex: zeros(o.scriptBytes), hasCovenant: o.hasCovenant }))
  };
}

/*
 * Derive the consensus mass and the relay-floor fee for one measured shape.
 * Returns BigInt sompi and BigInt grams — never a JS number on the fee path.
 */
function feeForShape(shape) {
  if (!shape || !Array.isArray(shape.inputs)) fail("a measured shape is required");
  const m = calculateRequiredFee(shapeToTxDescriptor(shape));
  return Object.freeze({
    label: shape.label,
    kind: shape.kind,
    txBytes: m.size,
    computeMass: m.computeMass,
    transientMass: m.transientMass,
    normalizedTransient: m.normalizedTransient,
    feeMass: m.feeMass,
    feeMassDominatedBy: m.computeMass > m.normalizedTransient ? "compute" : "transient",
    relayFloorFeeSompi: m.minimumRequiredFee
  });
}

function feeForLabel(label) {
  const shape = SHAPES_BY_LABEL[label];
  if (!shape) fail(`unknown measured shape ${JSON.stringify(label)} — failing closed (no default route)`);
  return feeForShape(shape);
}

/* Every measured shape, derived. */
function allShapeFees() {
  return Object.freeze(V7_MEASURED_SHAPES.map(feeForShape));
}

/* The root threshold sweep as { activeSlots, ... } rows, 1..12. */
function rootThresholdCurve() {
  return Object.freeze(
    V7_MEASURED_SHAPES.filter((s) => s.kind === "threshold-sweep").map((s) => {
      const n = Number(/authorize (\d+)-of/.exec(s.label)[1]);
      return Object.freeze({ activeSlots: n, ...feeForShape(s) });
    })
  );
}

/*
 * ORGANIZATIONAL COST MODEL. What a whole organization pays over a period,
 * given how it actually operates. Every argument is a COUNT the caller
 * supplies; nothing about an organization's behaviour is assumed here.
 *
 *   vaults              rooted vaults created (one genesis each)
 *   ownerOps            rooted owner operations (each is ONE root + ONE vault)
 *   rootOnlyActions     root governance transactions with no vault operation
 *   delegateSpends      ordinary delegate spends (these never touch the root)
 *   heartbeats          root AUTHORIZE transactions run purely to reset the
 *                       dead-man's-switch idle clock
 *   activeOwnerSlots    the organization's ACTIVE owner slots (1..12), which
 *                       is what the root's compute cost scales with
 */
function organizationCost({ vaults = 0, ownerOps = 0, rootOnlyActions = 0, delegateSpends = 0, heartbeats = 0, activeOwnerSlots = 3 }) {
  for (const [name, v] of Object.entries({ vaults, ownerOps, rootOnlyActions, delegateSpends, heartbeats })) {
    if (!Number.isInteger(v) || v < 0) fail(`${name} must be a non-negative integer`);
  }
  if (!Number.isInteger(activeOwnerSlots) || activeOwnerSlots < 1 || activeOwnerSlots > 12) fail("activeOwnerSlots must be an integer 1..12");
  const rootAtN = feeForLabel(`root authorize ${activeOwnerSlots}-of-${activeOwnerSlots}`).relayFloorFeeSompi;
  const vaultGenesis = feeForLabel("rooted vault genesis").relayFloorFeeSompi;
  const ownerOp = feeForLabel("vault ownerPause (root + vault + fuel)").relayFloorFeeSompi;
  const delegate = feeForLabel("delegate spend (fuel-funded)").relayFloorFeeSompi;
  const rootGenesis = feeForLabel("organizational root genesis").relayFloorFeeSompi;
  const total =
    BigInt(vaults) * vaultGenesis + BigInt(ownerOps) * ownerOp + BigInt(rootOnlyActions + heartbeats) * rootAtN + BigInt(delegateSpends) * delegate;
  return Object.freeze({
    activeOwnerSlots,
    perRootGenesisSompi: rootGenesis,
    perVaultGenesisSompi: vaultGenesis,
    perOwnerOpSompi: ownerOp,
    perRootActionSompi: rootAtN,
    perDelegateSpendSompi: delegate,
    totalSompi: total
  });
}

/*
 * KIP-9 storage mass for a shape at CALLER-SUPPLIED values. Storage mass is
 * the one dimension that depends on VALUES rather than bytes, so it is never
 * pinned as a property of a shape: `measured.storageMassAtReferenceValues` is
 * the value at the measurement's own reference amounts and is informational.
 */
function storageMassFor({ inputValues, outputValues }) {
  const mass = calcStorageMass(inputValues, outputValues);
  return Object.freeze({ storageMass: mass, withinLimit: mass <= STORAGE_MASS_LIMIT, limit: STORAGE_MASS_LIMIT });
}

module.exports = {
  V7_TX_VERSION,
  V7_MEASURED_SHAPES,
  ROOT_FEE_CROSSOVER_ACTIVE_SLOTS,
  MINIMUM_RELAY_TRANSACTION_FEE,
  STORAGE_MASS_LIMIT,
  shapeToTxDescriptor,
  feeForShape,
  feeForLabel,
  allShapeFees,
  rootThresholdCurve,
  organizationCost,
  storageMassFor
};
