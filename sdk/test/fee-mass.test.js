"use strict";

/*
 * UNIT layer — authoritative fee/mass accounting.
 *
 * The golden vectors are produced by `tests/vm/pv_mass_probe`, which calls
 * rusty-kaspa's own MassCalculator. The JS module must match them exactly.
 * If rusty-kaspa's constants change, regenerate with:
 *   cd tests/vm && cargo run --bin pv_mass_probe
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");

const { calculateRequiredFee, estimatedSerializedSize } = require("../src/fee-mass");

const zeros = (n) => "00".repeat(n);

function desc(inputs, outputs) {
  return {
    version: 1,
    payloadHex: "",
    inputs: inputs.map(([sig, cb]) => ({ signatureScriptHex: zeros(sig), computeBudget: cb })),
    outputs: outputs.map(([spk, cov]) => ({ scriptHex: zeros(spk), hasCovenant: cov }))
  };
}

// Golden vectors from rusty-kaspa MassCalculator (tag v2.0.1, testnet-10).
const GOLDEN = [
  { name: "create_2in_3out", d: desc([[66, 10], [66, 10]], [[34, true], [34, false], [34, false]]), feeMass: 3604n, fee: 360400n },
  { name: "delegate_spend", d: desc([[1950, 100], [66, 10]], [[34, false], [35, true], [34, false]]), feeMass: 14499n, fee: 1449900n },
  { name: "rollover_spend", d: desc([[1970, 100], [66, 10]], [[34, false], [35, true], [34, false]]), feeMass: 14519n, fee: 1451900n },
  { name: "pause", d: desc([[1930, 100], [66, 10]], [[35, true], [34, false]]), feeMass: 14067n, fee: 1406700n },
  { name: "unpause", d: desc([[1930, 100], [66, 10]], [[35, true], [34, false]]), feeMass: 14067n, fee: 1406700n },
  { name: "recover", d: desc([[1900, 100], [66, 10]], [[34, false], [34, false]]), feeMass: 13992n, fee: 1399200n },
  // v0.2 shapes (redeem ~4708 B, covenant compute budget 20): transient-
  // mass-dominated, so fee = ceil(size*4/2)*100.
  { name: "v2_delegate_spend", d: desc([[5150, 20], [66, 10]], [[34, false], [35, true], [34, false]]), feeMass: 11218n, fee: 1121800n },
  { name: "v2_lifecycle", d: desc([[5100, 20], [66, 10]], [[35, true], [34, false]]), feeMass: 11014n, fee: 1101400n },
  { name: "v2_recover", d: desc([[4850, 20], [66, 10]], [[34, false], [34, false]]), feeMass: 10444n, fee: 1044400n },
  // v0.3 shapes (redeem 28483 B incl. the Phase 4.5 predecessor
  // approver-set well-formedness gate; sig-script + compute budget measured
  // from real encoded txs under production sig-op pricing — see
  // tests/vm/tests/v3_encoder_integration.rs). Transient-mass-dominated.
  { name: "v3_create_2in_3out", d: desc([[66, 10], [66, 10]], [[34, true], [34, false], [34, false]]), feeMass: 3604n, fee: 360400n },
  { name: "v3_delegate_spend_depth0", d: desc([[29719, 29], [66, 10]], [[34, false], [35, true], [34, false]]), feeMass: 60356n, fee: 6035600n },
  { name: "v3_delegate_spend_depth16", d: desc([[30233, 31], [66, 10]], [[34, false], [35, true], [34, false]]), feeMass: 61384n, fee: 6138400n },
  { name: "v3_approved_spend_2of3", d: desc([[29977, 61], [66, 10]], [[34, false], [35, true], [34, false]]), feeMass: 60872n, fee: 6087200n },
  { name: "v3_approved_spend_10of10", d: desc([[29977, 134], [66, 10]], [[34, false], [35, true], [34, false]]), feeMass: 60872n, fee: 6087200n },
  { name: "v3_owner_op", d: desc([[29020, 29], [66, 10]], [[35, true], [34, false]]), feeMass: 58854n, fee: 5885400n },
  { name: "v3_recover", d: desc([[28577, 16], [66, 10]], [[34, false], [34, false]]), feeMass: 57898n, fee: 5789800n },
  // v0.4 shapes (redeem 18,839 B — smaller than v0.3 because the single
  // delegate + fixed policy fields moved into the per-agent leaf). Sig-script
  // lengths + compute budgets measured from the production covenant under
  // production sig-op pricing (tests/vm v4_production + v4_encoder_integration).
  // "reserve_funded" = no fuel input (fee from the covenant fee reserve).
  { name: "v4_create_2in_3out", d: desc([[66, 10], [66, 10]], [[34, true], [34, false], [34, false]]), feeMass: 3604n, fee: 360400n },
  { name: "v4_agent_spend_min_reserve_funded", d: desc([[20117, 23]], [[34, false], [35, true]]), feeMass: 40808n, fee: 4080800n },
  { name: "v4_agent_spend_min_fuel", d: desc([[20117, 23], [66, 10]], [[34, false], [35, true], [34, false]]), feeMass: 41152n, fee: 4115200n },
  { name: "v4_agent_spend_worst_fuel", d: desc([[21016, 132], [66, 10]], [[34, false], [35, true], [34, false]]), feeMass: 42950n, fee: 4295000n },
  { name: "v4_owner_op", d: desc([[19320, 22], [66, 10]], [[35, true], [34, false]]), feeMass: 39454n, fee: 3945400n },
  { name: "v4_recover", d: desc([[18926, 14], [66, 10]], [[34, false], [34, false]]), feeMass: 38596n, fee: 3859600n }
];

test("JS fee/mass matches rusty-kaspa golden vectors exactly", () => {
  for (const g of GOLDEN) {
    const r = calculateRequiredFee(g.d);
    assert.equal(r.feeMass, g.feeMass, `${g.name} feeMass`);
    assert.equal(r.minimumRequiredFee, g.fee, `${g.name} minimumRequiredFee`);
    assert.equal(r.minimumRequiredFee, r.feeMass * 100n, `${g.name} fee == feeMass*100`);
  }
});

test("covenant-binding bytes are counted (the WASM undercount)", () => {
  const withCov = estimatedSerializedSize(desc([[66, 10]], [[34, true]]));
  const withoutCov = estimatedSerializedSize(desc([[66, 10]], [[34, false]]));
  assert.equal(withCov - withoutCov, 34n); // 2 (authorizing_input) + 32 (covenant_id)
});

test("adding an ordinary fee input raises mass and fee monotonically", () => {
  const one = calculateRequiredFee(desc([[1950, 100]], [[34, false], [35, true]]));
  const two = calculateRequiredFee(desc([[1950, 100], [66, 10]], [[34, false], [35, true]]));
  assert.ok(two.feeMass > one.feeMass, "more inputs => more mass");
  assert.ok(two.minimumRequiredFee > one.minimumRequiredFee, "more mass => more fee");
});

test("numeric safety: malformed hex and missing compute budget fail closed", () => {
  assert.throws(() => estimatedSerializedSize({ version: 1, payloadHex: "", inputs: [{ signatureScriptHex: "abc", computeBudget: 10 }], outputs: [] }), /hex/);
  assert.throws(
    () => calculateRequiredFee({ version: 1, payloadHex: "", inputs: [{ signatureScriptHex: "", computeBudget: undefined }], outputs: [{ scriptHex: "00", hasCovenant: false }] }),
    /computeBudget/
  );
  assert.throws(() => estimatedSerializedSize({ version: 0, inputs: [], outputs: [] }), /version >= 1/);
});
