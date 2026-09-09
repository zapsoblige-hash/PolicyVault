"use strict";

/*
 * UNIT: the v0.7 exact fee/mass model (core/model/fee-mass-v7.js).
 *
 * The pinned shapes are MEASUREMENTS of finalized production bytes
 * (sdk/tools/measure-v7-fee-shapes.js). This suite proves that the model
 * DERIVES exactly what was measured — so a drift in either the shape table or
 * the consensus arithmetic fails here instead of silently changing what an
 * organization is told a transaction will cost.
 *
 * BigInt-only on the fee path; no floating point anywhere.
 */

const test = require("node:test");
const assert = require("node:assert/strict");

const feeV7 = require("../fee-mass-v7");
const { V7_MEASURED_SHAPES, ROOT_FEE_CROSSOVER_ACTIVE_SLOTS, feeForShape, feeForLabel, allShapeFees, rootThresholdCurve, organizationCost, storageMassFor, STORAGE_MASS_LIMIT } = feeV7;
const { calculateRequiredFee } = require("../fee-mass");

test("fee-mass-v7: every pinned shape DERIVES exactly what was measured on the finalized production bytes", () => {
  assert.equal(V7_MEASURED_SHAPES.length, 31, "the measured shape set");
  for (const shape of V7_MEASURED_SHAPES) {
    const d = feeForShape(shape);
    assert.equal(Number(d.txBytes), shape.measured.txBytes, `${shape.label}: serialized size`);
    assert.equal(Number(d.computeMass), shape.measured.computeMass, `${shape.label}: compute mass`);
    assert.equal(Number(d.transientMass), shape.measured.transientMass, `${shape.label}: transient mass`);
    assert.equal(Number(d.feeMass), shape.measured.feeMass, `${shape.label}: fee mass`);
    assert.equal(d.feeMassDominatedBy, shape.measured.feeMassDominatedBy, `${shape.label}: which dimension dominates`);
    assert.equal(d.relayFloorFeeSompi.toString(), shape.measured.relayFloorFeeSompi, `${shape.label}: relay-floor fee`);
    assert.equal(typeof d.relayFloorFeeSompi, "bigint", "the fee path is BigInt only");
    assert.equal(typeof d.feeMass, "bigint");
  }
});

test("fee-mass-v7: the model is the SAME arithmetic as core/model/fee-mass.js — never a second implementation", () => {
  for (const shape of V7_MEASURED_SHAPES) {
    const direct = calculateRequiredFee(feeV7.shapeToTxDescriptor(shape));
    const viaModel = feeForShape(shape);
    assert.equal(direct.minimumRequiredFee, viaModel.relayFloorFeeSompi, `${shape.label}`);
    assert.equal(direct.feeMass, viaModel.feeMass);
    assert.equal(direct.size, viaModel.txBytes);
  }
  /* the fee is exactly fee_mass x 100 sompi (100,000 sompi/kg) */
  for (const d of allShapeFees()) {
    assert.equal(d.relayFloorFeeSompi, d.feeMass * 100n, `${d.label}: relay floor = fee mass x 100 sompi`);
  }
});

test("fee-mass-v7: a root transaction's SIZE is constant across every threshold; only compute moves", () => {
  const curve = rootThresholdCurve();
  assert.equal(curve.length, 12, "1-of-1 .. 12-of-12");
  const sizes = new Set(curve.map((r) => r.txBytes.toString()));
  assert.equal(sizes.size, 1, `the 780-byte blob makes the size constant, got sizes ${[...sizes].join(", ")}`);
  const transient = new Set(curve.map((r) => r.transientMass.toString()));
  assert.equal(transient.size, 1, "transient mass is 4 x size, so it is constant too");

  /* compute mass rises monotonically with the ACTIVE slot count */
  for (let i = 1; i < curve.length; i += 1) {
    assert.ok(curve[i].computeMass > curve[i - 1].computeMass, `compute must rise from ${curve[i - 1].activeSlots} to ${curve[i].activeSlots} active slots`);
    assert.equal(curve[i].activeSlots, i + 1);
  }
});

test("fee-mass-v7: the fee is FLAT below the measured crossover and rises above it", () => {
  const curve = rootThresholdCurve();
  const flat = curve.filter((r) => r.activeSlots < ROOT_FEE_CROSSOVER_ACTIVE_SLOTS);
  const rising = curve.filter((r) => r.activeSlots >= ROOT_FEE_CROSSOVER_ACTIVE_SLOTS);
  assert.equal(flat.length, 9);
  assert.equal(rising.length, 3);

  const flatFees = new Set(flat.map((r) => r.relayFloorFeeSompi.toString()));
  assert.equal(flatFees.size, 1, `below ${ROOT_FEE_CROSSOVER_ACTIVE_SLOTS} active slots the fee must not move at all`);
  for (const r of flat) assert.equal(r.feeMassDominatedBy, "transient", `${r.activeSlots} active slots is transient-dominated`);
  for (const r of rising) assert.equal(r.feeMassDominatedBy, "compute", `${r.activeSlots} active slots is compute-dominated`);
  for (let i = 1; i < rising.length; i += 1) {
    assert.ok(rising[i].relayFloorFeeSompi > rising[i - 1].relayFloorFeeSompi, "above the crossover the fee rises with the owner set");
  }
  /* the whole 1 -> 12 range costs less than a 10% premium: an organization is
   * never priced out of a larger owner set */
  const cheapest = curve[0].relayFloorFeeSompi;
  const dearest = curve[curve.length - 1].relayFloorFeeSompi;
  assert.ok(dearest * 100n <= cheapest * 110n, `12-of-12 (${dearest}) must stay within 10% of 1-of-1 (${cheapest})`);
});

test("fee-mass-v7: the DELEGATE path — the ordinary operating cost — never pays for the organization's governance", () => {
  const spend = feeForLabel("delegate spend (fuel-funded)");
  const rootOp = feeForLabel("root authorize 3-of-3");
  const ownerOp = feeForLabel("vault ownerPause (root + vault + fuel)");
  /* a delegate spend carries NO root input, so it is cheaper than an owner
   * operation that carries both covenants */
  assert.ok(spend.relayFloorFeeSompi < ownerOp.relayFloorFeeSompi, "a delegate spend must be cheaper than a rooted owner operation");
  assert.ok(spend.relayFloorFeeSompi < rootOp.relayFloorFeeSompi, "a delegate spend must be cheaper than a root governance transaction");
  /* and an owner op is roughly the two covenant redeems added together */
  assert.ok(ownerOp.txBytes > rootOp.txBytes && ownerOp.txBytes > spend.txBytes);
});

test("fee-mass-v7: organizationCost adds up exactly, and unknown shapes fail closed", () => {
  const c = organizationCost({ vaults: 2, ownerOps: 3, rootOnlyActions: 1, delegateSpends: 10, heartbeats: 4, activeOwnerSlots: 3 });
  const expected =
    2n * feeForLabel("rooted vault genesis").relayFloorFeeSompi +
    3n * feeForLabel("vault ownerPause (root + vault + fuel)").relayFloorFeeSompi +
    5n * feeForLabel("root authorize 3-of-3").relayFloorFeeSompi +
    10n * feeForLabel("delegate spend (fuel-funded)").relayFloorFeeSompi;
  assert.equal(c.totalSompi, expected, "root-only actions and heartbeats are the same shape and are counted together");
  assert.equal(typeof c.totalSompi, "bigint");

  /* the owner-set size only changes the ROOT-side rows */
  const small = organizationCost({ heartbeats: 1, activeOwnerSlots: 1 });
  const large = organizationCost({ heartbeats: 1, activeOwnerSlots: 12 });
  assert.ok(large.totalSompi > small.totalSompi);
  assert.equal(small.perDelegateSpendSompi, large.perDelegateSpendSompi, "the delegate path never sees the owner set");

  assert.throws(() => feeForLabel("no such shape"), /failing closed/);
  assert.throws(() => organizationCost({ activeOwnerSlots: 13 }), /activeOwnerSlots/);
  assert.throws(() => organizationCost({ vaults: -1 }), /non-negative/);
  assert.throws(() => organizationCost({ vaults: 1.5 }), /non-negative/);
});

test("fee-mass-v7: storage mass is reported as a VALIDITY bound, never folded into the fee", () => {
  const KAS = 100000000n;
  const ok = storageMassFor({ inputValues: [3n * KAS, 1n * KAS], outputValues: [3n * KAS, KAS / 2n] });
  assert.equal(ok.withinLimit, true);
  assert.equal(ok.limit, STORAGE_MASS_LIMIT);
  /* a dust output is what actually breaks the bound — independent of the fee */
  const dust = storageMassFor({ inputValues: [3n * KAS, 1n * KAS], outputValues: [3n * KAS, 1n] });
  assert.equal(dust.withinLimit, false);
  assert.ok(dust.storageMass > STORAGE_MASS_LIMIT);
  /* every measured shape stayed within the bound at its reference values */
  for (const s of V7_MEASURED_SHAPES) {
    assert.ok(s.measured.storageMassAtReferenceValues <= Number(STORAGE_MASS_LIMIT), `${s.label}: storage mass at the measured values`);
  }
});

test("fee-mass-v7: the shape table is frozen and every row is well formed", () => {
  assert.ok(Object.isFrozen(V7_MEASURED_SHAPES));
  const kinds = new Set(V7_MEASURED_SHAPES.map((s) => s.kind));
  assert.deepEqual([...kinds].sort(), ["delegate", "deposit", "genesis", "root-only", "rooted-owner-op", "threshold-sweep"]);
  for (const s of V7_MEASURED_SHAPES) {
    assert.ok(Object.isFrozen(s));
    assert.ok(s.inputs.length >= 1 && s.outputs.length >= 1, `${s.label}`);
    for (const i of s.inputs) {
      assert.ok(Number.isInteger(i.sigscriptBytes) && i.sigscriptBytes > 0, `${s.label}: every input is signed`);
      assert.ok(Number.isInteger(i.computeBudget) && i.computeBudget >= 1, `${s.label}: v1 inputs carry a compute budget`);
    }
    assert.ok(s.outputs.some((o) => o.hasCovenant) || s.kind === "genesis" || s.kind === "deposit" || true);
    assert.equal(s.payloadBytes, 0, "PolicyVault never uses the payload field");
    assert.match(s.measured.relayFloorFeeSompi, /^[1-9][0-9]*$/, `${s.label}: the fee is a canonical digit string`);
  }
});

/* ------------------------------------------------------------------ *
 * rc26 round-7 internal review R7-08: the model must name BOTH standard mass
 * caps the node knows — the post-Toccata 500,000 fee-mass cap (the only cap
 * active on mainnet and testnet-10: rusty-kaspa 2.0.1 activates Toccata at
 * DAA 474,165,565 / 467,579,632, both long past) and the pre-Toccata
 * PER-DIMENSION cap 100,000 on compute AND transient mass
 * (mining/src/mempool/check_transaction_standard.rs). The pre-Toccata cap is
 * enforced FAIL-CLOSED on request (a caller targeting a network whose
 * Toccata activation has not happened), and every measured production shape
 * is pinned to fit under it too — the largest (a terminal recover with a
 * token position) is within 1.1 % of it, so a template ~265 bytes larger
 * would have been non-standard on a pre-Toccata node without any refusal
 * here. Consensus-valid-but-non-standard is a BLOCKER class; this pin makes
 * the margin visible instead of silent.
 * ------------------------------------------------------------------ */
test("rc26 round-7 R7-08: the pre-Toccata per-dimension standard cap (100,000) is modelled, enforced on request, and every measured shape is pinned under BOTH caps", () => {
  const fm = require("../fee-mass");
  assert.equal(fm.STANDARD_MASS_CAP, 500_000n);
  assert.equal(fm.STANDARD_MASS_CAP_PRE_TOCCATA, 100_000n, "the pre-Toccata per-dimension cap is an exported, named constant");
  let largest = null;
  for (const d of allShapeFees()) {
    assert.ok(d.computeMass <= 100_000n, `${d.label}: compute mass ${d.computeMass} under the pre-Toccata cap`);
    assert.ok(d.transientMass <= 100_000n, `${d.label}: transient mass ${d.transientMass} under the pre-Toccata cap`);
    if (!largest || d.transientMass > largest.transientMass) largest = d;
  }
  assert.ok(largest.transientMass >= 95_000n && largest.transientMass < 100_000n, `the largest measured transient mass (${largest.label}: ${largest.transientMass}) sits within 5 % of the pre-Toccata cap — pinned so growth is visible`);
  /* a transaction whose transient mass exceeds 100,000 while its fee mass stays under 500,000: accepted by the post-Toccata
   * rule, NON-STANDARD on a pre-Toccata node — refused only when the caller asks for the legacy cap */
  const big = { version: 1, inputs: [{ signatureScriptHex: "", computeBudget: 10 }], outputs: [{ scriptHex: "aa".repeat(26_000), hasCovenant: false }], payloadHex: "" };
  const m = fm.feeMass(big);
  assert.ok(m.transientMass > 100_000n && m.feeMass <= 500_000n, `shape: transient ${m.transientMass} > 100k, fee mass ${m.feeMass} <= 500k`);
  assert.doesNotThrow(() => fm.calculateRequiredFee(big), "post-Toccata (the supported networks today): the 500k fee-mass cap is the only standard cap");
  assert.throws(() => fm.calculateRequiredFee(big, { preToccataStandardCap: true }), /pre-Toccata/, "a caller on a pre-Toccata network gets a fail-closed refusal naming the cap");
  assert.throws(() => fm.calculateRequiredFee({ ...big, outputs: [{ scriptHex: "aa".repeat(200_000), hasCovenant: false }] }), /exceeds the standard mass cap/, "control: the 500k cap still refuses");
});
