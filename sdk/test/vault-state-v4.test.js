"use strict";

/* UNIT — v0.4 exact live-state normalization + byte-exact compiler parity.
 * The compiler parity test proves sdk/src/contract-compiler-v4.js produces
 * the EXACT production covenant bytes (script 18,839 B, state region 441 B)
 * and the frozen constructor layout (vaultId at index 1). */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");
const os = require("os");

const { loadConfig } = require("../src/config");
const {
  normalizeTemplateV4,
  normalizeStateV4,
  computeStateIdV4,
  stateToJsonV4,
  APPROVER_SENTINEL,
  MAX_APPROVERS
} = require("../src/vault-state-v4");
const { compileExactStateV4, constructorArgsV4, buildLiveStateSourceV4 } = require("../src/contract-compiler-v4");

const OWNER = "cbaedc26f03fd3ba02fc936f338e980c9e2172c5e23128877ed46827e935296f";
const A1 = "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
const A2 = "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9";
const A3 = "e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13";
const ROOT = "11".repeat(32);
const VAULT_ID = "22".repeat(32);

function baseStateInput(over = {}) {
  return {
    protectedValue: "100000000000",
    feeReserve: "500000000",
    paused: "0",
    agentRoot: ROOT,
    approvers: [],
    approvalM: "0",
    policyNonce: "0",
    ...over
  };
}

test("valid template + state normalize; approvers padded to 10", () => {
  const t = normalizeTemplateV4({ owner: OWNER, vaultId: VAULT_ID });
  assert.equal(t.owner, OWNER);
  const s = normalizeStateV4(baseStateInput({ approvers: [A1, A2, A3], approvalM: "2" }));
  assert.equal(s.approvers.length, MAX_APPROVERS);
  assert.equal(s.activeApproverCount, 3);
  assert.equal(s.approvers[3], APPROVER_SENTINEL);
  assert.equal(s.approvalM, 2n);
  assert.equal(typeof s.protectedValue, "bigint");
  assert.equal(typeof s.feeReserve, "bigint");
});

test("zero-approver vault allowed (approvalM 0); configured requires 1<=M<=active", () => {
  assert.equal(normalizeStateV4(baseStateInput()).activeApproverCount, 0);
  assert.throws(() => normalizeStateV4(baseStateInput({ approvers: [], approvalM: "1" })), /approvalM must be 0 when there are no active approvers/);
  assert.throws(() => normalizeStateV4(baseStateInput({ approvers: [A1, A2, A3], approvalM: "4" })), /exceeds the active approver count/);
  assert.throws(() => normalizeStateV4(baseStateInput({ approvers: [A1, A2, A3], approvalM: "0" })), /must be >= 1 when approvers are configured/);
});

test("duplicate active approver key rejected; sentinel as active rejected; too many rejected", () => {
  assert.throws(() => normalizeStateV4(baseStateInput({ approvers: [A1, A1, A3], approvalM: "2" })), /duplicates an earlier approver key/);
  assert.throws(() => normalizeStateV4(baseStateInput({ approvers: [A1, APPROVER_SENTINEL] })), /all-zero sentinel/);
  const eleven = Array.from({ length: 11 }, (_, i) => `${(i + 1).toString(16).padStart(2, "0")}`.repeat(32));
  assert.throws(() => normalizeStateV4(baseStateInput({ approvers: eleven })), /max is 10/);
});

test("exact approverSlots layout preserved (never re-sorted); duplicates rejected", () => {
  const slots = [A3, A1, ...Array.from({ length: 8 }, () => APPROVER_SENTINEL)];
  const s = normalizeStateV4(baseStateInput({ approvers: undefined, approverSlots: slots, approvalM: "2" }));
  assert.deepEqual([...s.approvers], slots);
  assert.equal(s.activeApproverCount, 2);
  const dup = [A1, A1, ...Array.from({ length: 8 }, () => APPROVER_SENTINEL)];
  assert.throws(() => normalizeStateV4(baseStateInput({ approvers: undefined, approverSlots: dup, approvalM: "1" })), /duplicates an earlier active approver key/);
});

test("policyNonce REQUIRED (no implicit default); numeric safety", () => {
  const missing = baseStateInput();
  delete missing.policyNonce;
  assert.throws(() => normalizeStateV4(missing), /policyNonce/);
  assert.throws(() => normalizeStateV4(baseStateInput({ protectedValue: "-1" })), /protectedValue/);
  assert.throws(() => normalizeStateV4(baseStateInput({ paused: "2" })), /paused out of range/);
  assert.throws(() => normalizeStateV4(baseStateInput({ agentRoot: "11".repeat(31) })), /agentRoot must be 32-byte/);
});

test("state ID deterministic + field-sensitive; JSON round-trips exact slots", () => {
  const t = normalizeTemplateV4({ owner: OWNER, vaultId: VAULT_ID });
  const s = normalizeStateV4(baseStateInput({ approvers: [A1, A2, A3], approvalM: "2" }));
  const id1 = computeStateIdV4({ networkId: "testnet-10", template: t, state: s });
  assert.equal(id1, computeStateIdV4({ networkId: "testnet-10", template: t, state: normalizeStateV4(baseStateInput({ approvers: [A1, A2, A3], approvalM: "2" })) }));
  const s2 = normalizeStateV4(baseStateInput({ feeReserve: "600000000", approvers: [A1, A2, A3], approvalM: "2" }));
  assert.notEqual(id1, computeStateIdV4({ networkId: "testnet-10", template: t, state: s2 }));
  const j = stateToJsonV4(s);
  assert.equal(j.feeReserve, "500000000");
  assert.equal(j.approverSlots.length, 10);
  const back = normalizeStateV4(j);
  assert.deepEqual([...back.approvers], [...s.approvers]);
});

test("BYTE-EXACT compiler parity: SDK produces the production covenant bytes", () => {
  const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "pv4-compiler-test-"));
  const config = loadConfig({ dataRoot });
  const template = normalizeTemplateV4({ owner: OWNER, vaultId: VAULT_ID });
  const state = normalizeStateV4(baseStateInput({ approvers: [A1, A2, A3], approvalM: "2" }));
  const compiled = compileExactStateV4({ config, template, state });
  // Frozen ABI: state region 441 bytes; production script size.
  assert.equal(compiled.stateLayout.len, 441, "state region must be exactly 441 bytes");
  assert.equal(compiled.contractName, "PolicyVault");
  assert.ok(compiled.scriptBytes.length > 18000, "production redeem script present");
  // constructor arg order: owner(0), vaultId(1), agentRoot(2), feeReserve(3), approver1..10, approvalM, initValue
  const args = constructorArgsV4(template, state);
  assert.equal(args.length, 2 + 1 + 1 + 10 + 1 + 1);
  assert.equal(args[1].data.map((b) => b.data.toString(16).padStart(2, "0")).join(""), VAULT_ID, "vaultId at ctor index 1");
  // recompiling the same state reuses the artifact deterministically (write-or-assert)
  const again = compileExactStateV4({ config, template, state });
  assert.equal(again.scriptSha256, compiled.scriptSha256, "deterministic recompile");
  // live-state templating produces exactly one substitution per anchor
  const src = fs.readFileSync(path.join(config.repoRoot, "contracts/PolicyVault.v0.4.sil"), "utf8");
  const live = buildLiveStateSourceV4(src, state);
  assert.ok(live.includes(`int feeReserve = ${state.feeReserve};`), "feeReserve templated");
  assert.ok(live.includes(`byte[32] agentRoot = 0x${state.agentRoot};`), "agentRoot templated");
});
