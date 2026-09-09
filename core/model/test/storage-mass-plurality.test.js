"use strict";

/* UNIT — KIP-9 storage mass with UTXO PLURALITY, pinned against the real
 * testnet-10 node's refusal of a live HD level-1 spend (2026-09-03):
 * `transaction storage mass of 840919 is larger than max allowed size of
 * 500000`. The plurality-1 model said ~210,000 for the same shape. */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const sm = require("../storage-mass");

const KAS = 100_000_000n;
const P2SH_HEX = "aa20" + "11".repeat(32) + "87"; // 35-byte P2SH script
const P2PK_HEX = "20" + "22".repeat(32) + "ac"; // 34-byte P2PK script

test("plurality: plain standard outputs are 1; covenant-bearing P2SH outputs are 2 (rusty-kaspa utxo_plurality)", () => {
  assert.equal(sm.utxoPluralityOfScriptHex(P2PK_HEX, false), 1n);
  assert.equal(sm.utxoPluralityOfScriptHex(P2SH_HEX, false), 1n);
  assert.equal(sm.utxoPluralityOfScriptHex(P2SH_HEX, true), 2n); // 63 + 35 + 32 = 130 → 2
  assert.equal(sm.utxoPlurality({ scriptLenBytes: 37, hasCovenant: false }), 1n); // 100 → 1
  assert.equal(sm.utxoPlurality({ scriptLenBytes: 38, hasCovenant: false }), 2n); // 101 → 2
  assert.equal(sm.utxoPlurality({ scriptLenBytes: 200, hasCovenant: true }), 3n); // 295 → 3
});

test("the live-refused HD level-1 spend reproduces the node's 840,919 grams EXACTLY (and the plurality-1 model does not)", () => {
  const fuel = 9_190_264_770_600n; // the funding change, plain
  const inputs = [
    { amount: 3n * KAS, plurality: 2n }, // rooted HD vault (covenant P2SH)
    { amount: 150_000_000n, plurality: 2n }, // vault token position (covenant P2SH)
    { amount: fuel, plurality: 1n }
  ];
  const outputs = [
    { amount: 3n * KAS, plurality: 2n }, // vault successor
    { amount: 145_000_000n, plurality: 2n }, // token self-carry (1.5 − 0.05 KAS)
    { amount: 5_000_000n, plurality: 2n }, // recipient carry 0.05 KAS
    { amount: fuel - 9_115_800n, plurality: 1n } // change
  ];
  assert.equal(sm.calcStorageMass(inputs, outputs), 840_919n);
  assert.ok(sm.calcStorageMass(inputs, outputs) > sm.STORAGE_MASS_LIMIT, "the node refuses this shape");
  /* the plurality-1 reading of the same amounts is what the old module computed */
  assert.equal(sm.calcStorageMass(inputs.map((c) => c.amount), outputs.map((c) => c.amount)), 210_229n);
  /* a 0.2 KAS recipient carry (the payment lifecycle tool's constant) fits */
  const fixed = outputs.map((c, i) => (i === 2 ? { ...c, amount: 20_000_000n } : i === 1 ? { ...c, amount: 130_000_000n } : c));
  assert.ok(sm.calcStorageMass(inputs, fixed) <= sm.STORAGE_MASS_LIMIT);
  /* minimumOutputValueForLimit names a carry that fits for output #2 */
  const min = sm.minimumOutputValueForLimit(inputs, outputs, 2);
  assert.ok(min !== null && min > 5_000_000n);
  assert.ok(sm.calcStorageMass(inputs, outputs.map((c, i) => (i === 2 ? { ...c, amount: min } : c))) <= sm.STORAGE_MASS_LIMIT);
  /* tightness up to the node's own integer-division rounding: a few sompi
   * below the returned minimum may still floor to the same term, so the
   * exact boundary is asserted with a small tolerance, never as "min − 1" */
  assert.ok(sm.calcStorageMass(inputs, outputs.map((c, i) => (i === 2 ? { ...c, amount: min - 64n } : c))) > sm.STORAGE_MASS_LIMIT, "64 sompi less exceeds the limit");
});

test("cellsOfFrozenTx derives plurality from the frozen transaction's script lengths and covenant fields", () => {
  const frozen = {
    inputs: [
      { utxo: { amount: 3n * KAS, scriptPublicKey: { version: 0, scriptHex: P2SH_HEX }, covenantId: "ab".repeat(32) } },
      { utxo: { amount: 10n * KAS, scriptPublicKey: { version: 0, scriptHex: P2PK_HEX }, covenantId: null } }
    ],
    outputs: [
      { value: 3n * KAS, scriptPublicKey: { version: 0, scriptHex: P2SH_HEX }, covenant: { authorizingInput: 0, covenantId: "ab".repeat(32) } },
      { value: 9n * KAS, scriptPublicKey: { version: 0, scriptHex: P2PK_HEX }, covenant: null }
    ]
  };
  const { inputCells, outputCells } = sm.cellsOfFrozenTx(frozen);
  assert.deepEqual(inputCells.map((c) => c.plurality), [2n, 1n]);
  assert.deepEqual(outputCells.map((c) => c.plurality), [2n, 1n]);
  assert.throws(() => sm.cellsOfFrozenTx({ inputs: [{ utxo: { amount: 1n } }], outputs: [] }), /scriptHex is required/);
});

test("relaxed-path selection follows the node: |O| = 1, or ≤ 2 inputs with |I| = 1 or |O| = |I| = 2 (pluralities, not counts)", () => {
  /* two plain inputs + two covenant outputs: |O| = 4, |I| = 2 → NOT relaxed (the count-based model would have said relaxed) */
  const ins = [{ amount: 10n * KAS, plurality: 1n }, { amount: 10n * KAS, plurality: 1n }];
  const outs = [{ amount: KAS, plurality: 2n }, { amount: KAS, plurality: 2n }];
  const harmonicOuts = 2n * (sm.STORAGE_MASS_PARAMETER * 4n / KAS);
  const arithmeticIns = 2n * (sm.STORAGE_MASS_PARAMETER / (10n * KAS));
  assert.equal(sm.calcStorageMass(ins, outs), harmonicOuts - arithmeticIns);
});
