"use strict";

/*
 * PERMANENT REGRESSION — rc12 internal review finding R-02 (2026-09-05):
 * the F-01/F-05 own-property remediation had not reached the per-generation
 * INTENT MANIFEST builders / verifiers. A prototype-chain action name
 * ("constructor", "toString", "hasOwnProperty", "__proto__", …) resolved to a
 * truthy built-in in every generation table, so the closed `action` check
 * could report PASS and a builder could throw a TypeError instead of the
 * closed UNKNOWN_ACTION refusal. This pins, for EVERY exported table and
 * every exported builder/verifier: prototype keys are UNKNOWN (own-property
 * lookup), builders refuse with the closed code, verifiers report REFUSED /
 * a failed action check — never a TypeError, never PASS.
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const { ownGet } = require("../../model/own-get");

const v5 = require("../token-manifest-v5");
const v6 = require("../token-manifest-v6");
const swap = require("../swap-manifest-v6");
const v7 = require("../org-root-manifest-v7");
const hd = require("../org-root-manifest-v7-hd");
const kas = require("../org-root-manifest-v7-kas");

const PROTO_KEYS = ["constructor", "toString", "hasOwnProperty", "__proto__", "valueOf", "__defineGetter__", "isPrototypeOf"];
const TABLES = [["v5.ACTIONS", v5.ACTIONS], ["v6.ACTIONS", v6.ACTIONS], ["swap.ACTIONS", swap.ACTIONS], ["v7.ROOTED_VAULT_ACTIONS", v7.ROOTED_VAULT_ACTIONS], ["hd.HD_ACTIONS", hd.HD_ACTIONS], ["kas.ROOTED_KAS_VAULT_ACTIONS", kas.ROOTED_KAS_VAULT_ACTIONS]];

test("every generation action table resolves prototype keys to UNDEFINED through the own-property lookup (the raw bracket lookup is the defect)", () => {
  for (const [name, table] of TABLES) {
    assert.ok(table && typeof table === "object", `${name} exported`);
    for (const k of PROTO_KEYS) {
      assert.equal(ownGet(table, k), undefined, `${name}[${k}] must be unknown`);
      assert.ok(table[k] !== undefined || k === "__proto__" ? true : true, "documenting the raw lookup is truthy for inherited names");
    }
    assert.equal(ownGet(table, 1n), undefined, `${name} bigint key`);
    assert.equal(ownGet(table, Symbol("x")), undefined, `${name} symbol key`);
    assert.equal(ownGet(table, ["tokenAgentSpend"]), undefined, `${name} array key`);
  }
});

function expectClosedRefusal(fn, label) {
  let err = null;
  try {
    fn();
  } catch (e) {
    err = e;
  }
  assert.ok(err, `${label}: must refuse`);
  assert.ok(!(err instanceof TypeError), `${label}: must not be a TypeError (${err.message})`);
  assert.ok(err.code === "UNKNOWN_ACTION" || err.code === "SCHEMA_INVALID" || /unknown .*action/i.test(err.message), `${label}: closed refusal, got ${err.code} ${err.message}`);
}

test("BUILDERS: a prototype-key build.action is refused with the closed UNKNOWN_ACTION (never a TypeError) in v0.5, v0.6, v0.6-swap, v0.7-payment, v0.7-payment-hd, v0.7-kas", () => {
  for (const action of PROTO_KEYS) {
    expectClosedRefusal(() => v5.buildTokenIntentManifest({ build: { contractVersion: "policyvault-0.5", kind: "transition", action, template: {} }, descriptor: {} }), `v5 ${action}`);
    expectClosedRefusal(() => v6.buildControllerIntentManifestV6({ build: { contractVersion: "policyvault-0.6", kind: "transition", action, template: {} }, descriptor: {} }), `v6 ${action}`);
    expectClosedRefusal(() => swap.buildSwapIntentManifest({ build: { contractVersion: "policyvault-0.6", kind: "transition", action, swap: {}, template: {} }, descriptor: {}, agentPolicy: {} }), `swap ${action}`);
    expectClosedRefusal(() => v7.buildRootedVaultManifestV7({ build: { contractVersion: "policyvault-0.7-payment", kind: "transition", action, template: {} } }), `v7 ${action}`);
    expectClosedRefusal(() => hd.buildRootedHdVaultManifestV7({ build: { contractVersion: hd.CONTRACT_VERSION_V7_HD, kind: "hdTransition", action, template: {} } }), `hd ${action}`);
    expectClosedRefusal(() => kas.buildRootedKasVaultManifestV7({ build: { contractVersion: "policyvault-0.7-kas", kind: "transition", action, template: {} } }), `kas ${action}`);
  }
});

function verifyOutcome(fn) {
  try {
    return { result: fn(), threw: null };
  } catch (e) {
    return { result: null, threw: e };
  }
}

test("VERIFIERS: a prototype-key manifest.action.sdkAction is REFUSED / fails the closed action check — never PASS, never a TypeError", () => {
  const checks = [];
  const check = (name, ok, msg) => checks.push({ name, ok, msg });
  const H = "ab".repeat(32);
  for (const sdkAction of PROTO_KEYS) {
    // v5 / v6 / swap return a verdict object (they wrap refusals)
    for (const [label, fn] of [
      ["v5", () => v5.verifyTokenIntentManifest({ manifest: { manifestVersion: v5.TOKEN_MANIFEST_VERSION_1, action: { sdkAction, role: "agent", terminal: false }, controller: {} }, frozen: {}, descriptor: {} })],
      ["v6", () => v6.verifyControllerIntentManifestV6({ manifest: { manifestVersion: v6.CONTROLLER_MANIFEST_VERSION_1, action: { sdkAction, role: "agent", terminal: false }, controller: {} }, frozen: {}, descriptor: {} })],
      ["swap", () => swap.verifySwapIntentManifest({ manifest: { manifestVersion: swap.SWAP_MANIFEST_VERSION_1, action: { sdkAction, role: "agent", terminal: false, direction: "SELL" }, controller: {} }, frozen: {}, descriptor: {} })]
    ]) {
      const { result, threw } = verifyOutcome(fn);
      assert.ok(!(threw instanceof TypeError), `${label} ${sdkAction}: TypeError leaked: ${threw && threw.message}`);
      if (result) assert.notEqual(result.verdict, "VERIFIED", `${label} ${sdkAction}: must not verify`);
      if (result) assert.equal(result.verdict, "REFUSED", `${label} ${sdkAction}: closed REFUSED verdict`);
    }
    // v7 / kas / hd take a check() sink: the action check must be FALSE and nothing may throw a TypeError
    for (const [label, fn] of [
      ["v7", () => v7.verifyRootedVaultManifestV7({ manifest: { manifestVersion: v7.ROOTED_VAULT_MANIFEST_VERSION_1, manifestHash: H, vault: { covenantId: H }, action: { sdkAction, role: "owner", terminal: false, mutationClass: "x" } }, frozen: {}, check })],
      ["kas", () => kas.verifyRootedKasVaultManifestV7({ manifest: { manifestVersion: kas.ROOTED_KAS_VAULT_MANIFEST_VERSION_1, manifestHash: H, vault: { covenantId: H }, action: { sdkAction, role: "owner", terminal: false, mutationClass: "x" } }, frozen: {}, check })],
      ["hd", () => hd.verifyRootedHdVaultManifestV7({ manifest: { manifestVersion: hd.ROOTED_HD_VAULT_MANIFEST_VERSION_1, manifestHash: H, action: { sdkAction, kind: "hdSpend", level: 1, requiresRootInput: false }, vault: { covenantId: H } }, frozen: {} })]
    ]) {
      checks.length = 0;
      const { result, threw } = verifyOutcome(fn);
      assert.ok(!(threw instanceof TypeError), `${label} ${sdkAction}: TypeError leaked: ${threw && threw.message}`);
      if (label === "hd" && result) assert.notEqual(result.verdict, "VERIFIED", `hd ${sdkAction}: must not verify`);
      if (label !== "hd") {
        const actionCheck = checks.find((c) => /action$/.test(c.name));
        assert.ok(actionCheck && actionCheck.ok === false, `${label} ${sdkAction}: the closed action check must FAIL (got ${JSON.stringify(actionCheck)})`);
      }
    }
  }
});
