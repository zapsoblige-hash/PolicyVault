"use strict";
/*
 * VM ↔ PRE-SIGN PARITY regression gate.
 *
 * Standing invariant (docs/postlaunch/vm-presign-parity-and-enforcement-matrix.md,
 * CLAUDE.md): every deterministic, signer-visible hostile condition the
 * covenant can reject and that is KNOWABLE PRE-SIGN must ALSO be rejected by
 * the shared deterministic core / SDK BEFORE signing. This gate pins the
 * canonical pre-sign-knowable case (an over-cap / over-budget spend) for the
 * shared v4 core that v0.4.1 / v0.5 / v0.6 delegate to, and the HD
 * ancestor-budget case that motivated the rule, so a future hostile-matrix
 * change cannot silently drop pre-sign enforcement without breaking a test.
 */
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");

const { normalizeStateV4 } = require("../src/vault-state-v4");
const { buildAgentTreeV4, generateAgentProofV4 } = require("../src/agent-merkle-v4");
const { agentSpendSuccessorV4 } = require("../src/vault-transitions-v4");
const hd = require("../../core/model/hd-leaf-v7");

const PK = (v) => v.toString(16).padStart(2, "0").repeat(32);
const KAS = 100_000_000n;

function policy(v, over = {}) {
  return { agentPk: PK(v), maxPerSpend: "20000000000", periodBudget: "50000000000", periodLengthDaa: "864000", periodStartDaa: "541000000", periodSpent: "0", approvalThreshold: "5000000000", agentMaxFeePerTx: "100000000", agentRecipientRoot: "ab".repeat(32), ...over };
}
const TREE = buildAgentTreeV4([policy(0x30), policy(0x31, { maxPerSpend: "90000000000", periodBudget: "90000000000" })]);
function state(over = {}) {
  return normalizeStateV4({ protectedValue: "1000000000000", feeReserve: "500000000", paused: "0", agentRoot: TREE.root, approvers: [PK(0x20), PK(0x21), PK(0x22)], approvalM: "2", policyNonce: "3", ...over });
}
function spendArgs(over = {}) {
  const proof = generateAgentProofV4(TREE, PK(0x30));
  return { agentPolicy: proof.policy, agentProof: { siblingsHex: proof.siblingsHex, pathBits: proof.pathBits }, payAmount: "4000000000", periodsElapsed: "0", reserveConsumed: "50000000", ...over };
}

/* ---- shared v4 core (v0.4.1 / v0.5 / v0.6 delegated-spend path) ---- */
test("PARITY: over-cap delegated spend is REFUSED pre-sign by the shared v4 core (OVER_CAP), never assembled/signed", () => {
  const s = state();
  // honest spend at the cap succeeds pre-sign
  assert.ok(agentSpendSuccessorV4(s, spendArgs({ payAmount: "20000000000" })).successor, "an at-cap spend is constructible");
  // one sompi over the per-spend cap is refused pre-sign with the closed code
  let threw = null;
  try { agentSpendSuccessorV4(s, spendArgs({ payAmount: "20000000001" })); } catch (e) { threw = e; }
  assert.ok(threw, "the builder must NOT produce a successor for an over-cap spend");
  assert.equal(threw.code, "OVER_CAP", "over-cap must fail closed with OVER_CAP pre-sign (parity with the covenant refusal)");
});

test("PARITY: over-period-budget delegated spend is REFUSED pre-sign by the shared v4 core (OVER_BUDGET)", () => {
  const spent = buildAgentTreeV4([policy(0x30, { periodSpent: "49000000000" })]);
  const proof = generateAgentProofV4(spent, PK(0x30));
  const s = state({ agentRoot: spent.root });
  let threw = null;
  try {
    agentSpendSuccessorV4(s, { agentPolicy: proof.policy, agentProof: { siblingsHex: proof.siblingsHex, pathBits: proof.pathBits }, payAmount: "2000000000", periodsElapsed: "0", reserveConsumed: "0" });
  } catch (e) { threw = e; }
  assert.ok(threw && threw.code === "OVER_BUDGET", `over-budget must fail closed with OVER_BUDGET pre-sign, got ${threw && threw.code}`);
});

/* ---- HD ancestor-budget (the motivating Wave-2 incident) ---- */
test("PARITY: HD spend over an EXHAUSTED ancestor budget is REFUSED pre-sign by the shared core (the Wave-2 motivating case)", () => {
  const leaf = (pk, over = {}) => ({ pk, maxPerSpend: "250", periodBudget: "2000", periodLengthDaa: "100000000", periodStartDaa: "0", periodSpent: "0", maxFeePerTx: KAS.toString(), maxCarryKas: (KAS / 4n).toString(), expiryDaa: "900000000", recipientRoot: "00".repeat(32), childRoot: "00".repeat(32), ...over });
  const chain = [
    leaf(PK(0x10), { periodBudget: "2000", periodSpent: "2000" }), // level-1 ancestor EXHAUSTED
    leaf(PK(0x11), { periodBudget: "1000", periodSpent: "0" }),
    leaf(PK(0x12), { maxPerSpend: "250", periodBudget: "1000", periodSpent: "0" })
  ];
  const r = hd.verifySpendWithinEffectiveAuthority(chain, { amount: "25", periodsElapsedByLevel: [0n, 0n, 0n] });
  assert.equal(r.ok, false, "a spend under an exhausted ancestor budget must be refused pre-sign, even when the leaf's own cap/budget allow it");
});

/* ---- the matrix contract itself ---- */
test("PARITY: the enforcement matrix documents pre-sign-knowable invariants with SHARED-CORE-SDK enforcement", () => {
  const doc = fs.readFileSync(path.join(__dirname, "..", "..", "docs", "postlaunch", "vm-presign-parity-and-enforcement-matrix.md"), "utf8");
  for (const needle of ["per-spend cap", "ancestor-budget intersection", "SHARED-CORE-SDK", "CHAIN-CONSENSUS", "NOT PROVEN"]) {
    assert.ok(doc.includes(needle), `the enforcement matrix must document "${needle}"`);
  }
});
