"use strict";
/*
 * SDK — R7-04 closure (v0.7 enablement directive 2026-09-10): the shared-core
 * reconstruction of the v0.7-kas ROOTED KAS SAFE-PAYMENT VAULT script
 * (core/intent/vault-script-v7-kas.js, CANDIDATE generation — not byte-frozen)
 * is cross-checked against the REAL vendored compiler (silverc):
 *   - STATE MATRIX: silverc's state_layout is exactly (1, 441); the core's
 *     441-byte state region equals the compiler's; the template (prefix +
 *     suffix) is invariant across states of one vault; rebuilding any
 *     successor from any predecessor's redeem reproduces silverc's successor
 *     script and its P2SH byte for byte;
 *   - TEMPLATE MATRIX: every pin varied through its push-encoding classes
 *     (OP_1..16, 1-, 2- and 3-byte pushes; distinct 32-byte constants) — the
 *     whole script rebuilt from pins + state equals silverc's compile byte for
 *     byte, and the pins decode back out of silverc's script;
 *   - GENERATION PIN: the skeleton belongs to the CANDIDATE source
 *     (sha256 393f2130…); a real frozen v0.7-payment compile is refused by
 *     the KAS decoder and a real KAS compile by the payment decoder.
 * The skeleton itself was derived mechanically by
 * tools/derive-vault-script-skeleton-v7-kas.js. Any drift between the model
 * and the candidate covenant breaks this test. REQUIREMENT_NOT_AVAILABLE
 * (skipped, never silently passed) when the vendored silverc is absent.
 */
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");
const { loadConfig } = require("../src/config");
const { compileExactStateV7Kas } = require("../src/contract-compiler-v7-kas");
const { compileExactStateV7, deriveRootPinsV7 } = require("../src/contract-compiler-v7");
const { normalizeStateV7Kas, normalizeTemplateV7Kas } = require("../../core/model/vault-state-v7-kas");
const { stateToJsonV4, normalizeStateV4 } = require("../../core/model/vault-state-v4");
const assets = require("../../core/assets");
const { compileKcc20Program } = require("../src/token-program-kcc20");
const K = require("../../core/intent/vault-script-v7-kas");
const P = require("../../core/intent/vault-script-v7");
const { blake2bHex } = require("../../core/assets/blake2b");

const config = loadConfig({ dataRoot: fs.mkdtempSync(path.join(os.tmpdir(), "pv-vaultscript-kas-")) });
const available = fs.existsSync(config.silvercPath);
const SKIP = !available && "REQUIREMENT_NOT_AVAILABLE: vendored silverc not staged";
const H = (b) => b.toString(16).padStart(2, "0").repeat(32);
const p2sh = (hex) => "aa20" + blake2bHex(Buffer.from(hex, "hex"), 32) + "87";

const rootTemplate = { orgId: H(0xa7), recoveryDelayDaa: "1000", successorPk: H(0x7f), successionDelayDaa: "2000", rootMaxFeePerTx: "200000" };
const ownerSet = { owners: [H(0x71), H(0x72), H(0x73), ...Array(9).fill("00".repeat(32))], ownerM: 2, emergencyK: 1, recoveryM: 2 };
function vaultTemplate(over = {}) {
  const rootPins = deriveRootPinsV7({ config, template: rootTemplate, ownerSet, covenantId: H(0x52) });
  return { vaultId: H(0x44), ...rootPins, recoveryPk: H(0x51), ...over };
}
const compileKas = (template, state) => compileExactStateV7Kas({ config, template: normalizeTemplateV7Kas(template), state: normalizeStateV7Kas(state) });
const jsonState = (state) => stateToJsonV4(normalizeStateV4(state));

test("silverc cross-check (v0.7-kas CANDIDATE): layout (1, 441), state region, template invariance and successor reconstruction across a state matrix", { skip: SKIP }, () => {
  const template = vaultTemplate();
  const states = [
    { protectedValue: "10000000000", feeReserve: "500000000", paused: "0", agentRoot: H(0xe7), approvers: [H(0xa1), H(0xa2), H(0xa3)], approvalM: "2", policyNonce: "0" },
    { protectedValue: "10000000000", feeReserve: "500000000", paused: "1", agentRoot: H(0xe7), approvers: [H(0xa1), H(0xa2), H(0xa3)], approvalM: "3", policyNonce: "0" },
    { protectedValue: "1", feeReserve: "0", paused: "0", agentRoot: H(0x00), approvers: [], approvalM: "0", policyNonce: "1" },
    { protectedValue: "9007199254740991", feeReserve: "9007199254740991", paused: "1", agentRoot: H(0xff), approvers: Array.from({ length: 10 }, (_, i) => H(0xb0 + i)), approvalM: "10", policyNonce: "1000000000" },
    { protectedValue: "127", feeReserve: "128", paused: "0", agentRoot: H(0x80), approvers: [H(0xc1)], approvalM: "1", policyNonce: "128" },
    { protectedValue: "4294967296", feeReserve: "1", paused: "0", agentRoot: H(0x01), approvers: [H(0xc1), H(0xc2)], approvalM: "1", policyNonce: "65536" }
  ];
  const compiled = states.map((state) => ({ state, c: compileKas(template, state) }));
  const templates = new Set();
  for (const { state, c } of compiled) {
    assert.deepEqual({ start: c.stateLayout.start, len: c.stateLayout.len }, { start: K.VAULT_SCRIPT_PREFIX_LEN_V7_KAS, len: K.VAULT_STATE_REGION_LEN_V7_KAS }, "silverc's state_layout is the pinned (1, 441)");
    assert.equal(K.serializeVaultStateRegionHexV7Kas({ vaultId: template.vaultId, state }), c.stateRegionHex, `state region == silverc's for ${JSON.stringify(state).slice(0, 60)}`);
    const parts = K.splitVaultRedeemHexV7Kas(c.scriptHex);
    assert.equal(parts.prefixHex, c.prefixHex); assert.equal(parts.suffixHex, c.suffixHex); assert.equal(parts.regionHex, c.stateRegionHex);
    assert.deepEqual(parts.decoded, { vaultId: template.vaultId, state: jsonState(state) });
    templates.add(c.prefixHex + "|" + c.suffixHex);
  }
  assert.equal(templates.size, 1, "prefix + suffix (the template) are invariant across every state of one vault");
  let pairs = 0;
  for (const pred of compiled) for (const succ of compiled) {
    assert.equal(K.reconstructVaultSuccessorHexV7Kas({ redeemHex: pred.c.scriptHex, vaultId: template.vaultId, state: succ.state }), succ.c.scriptHex, "rebuilt successor script == silverc's compile of the successor state");
    assert.equal(K.reconstructVaultSuccessorSpkHexV7Kas({ redeemHex: pred.c.scriptHex, vaultId: template.vaultId, state: succ.state }), p2sh(succ.c.scriptHex));
    pairs += 1;
  }
  assert.equal(pairs, states.length * states.length);
  const other = compileKas(vaultTemplate({ recoveryPk: H(0x99) }), states[0]);
  assert.notEqual(K.reconstructVaultSuccessorHexV7Kas({ redeemHex: other.scriptHex, vaultId: template.vaultId, state: states[1] }), compiled[1].c.scriptHex, "another vault's redeem never rebuilds this vault's successors");
});

test("silverc cross-check (v0.7-kas CANDIDATE): the template skeleton rebuilds silverc's WHOLE script from pins + state across a constant-encoding matrix; the pins decode back out of the compiled script", { skip: SKIP }, () => {
  const base = vaultTemplate();
  const state = { protectedValue: "10000000000", feeReserve: "500000000", paused: "0", agentRoot: H(0xe7), approvers: [H(0xa1), H(0xa2), H(0xa3)], approvalM: "2", policyNonce: "3" };
  const matrix = [base];
  for (const v of [2, 16, 17, 127, 128, 255, 256, 65535, 65536, 1000000]) matrix.push({ ...base, rootPrefixLen: v });
  for (const v of [1, 16, 17, 127, 128, 12077, 32767, 32768, 1000000]) matrix.push({ ...base, rootSuffixLen: v });
  for (const k of ["orgRootCovenantId", "rootTemplateVmHash", "recoveryPk", "vaultId"]) { matrix.push({ ...base, [k]: H(0x9b) }); matrix.push({ ...base, [k]: "ff".repeat(32) }); if (k !== "orgRootCovenantId") matrix.push({ ...base, [k]: "00".repeat(32) }); }
  matrix.push({ ...base, rootPrefixLen: 16, rootSuffixLen: 17, recoveryPk: H(0x01), orgRootCovenantId: H(0x05), rootTemplateVmHash: H(0x06), vaultId: H(0x07) });
  let checked = 0;
  for (const template of matrix) {
    const c = compileKas(template, state);
    const rebuilt = K.reconstructVaultScriptHexV7Kas({ template, state });
    assert.equal(rebuilt, c.scriptHex, `skeleton(pins, state) == silverc for ${JSON.stringify({ rp: template.rootPrefixLen, rs: template.rootSuffixLen })}`);
    assert.equal(K.reconstructVaultScriptSpkHexV7Kas({ template, state }), p2sh(c.scriptHex));
    const decoded = K.decodeVaultTemplatePinsV7Kas(c.scriptHex);
    assert.deepEqual(decoded.pins, normalizeTemplateV7Kas(template), "the pins decode back out of silverc's script");
    assert.deepEqual(decoded.state, jsonState(state));
    checked += 1;
  }
  assert.ok(checked >= 30, `matrix size ${checked}`);
  const other = compileKas(base, { ...state, paused: "1", policyNonce: "4" });
  assert.equal(K.reconstructVaultScriptHexV7Kas({ template: base, state: { ...state, paused: "1", policyNonce: "4" } }), other.scriptHex);
  assert.equal(K.reconstructVaultSuffixHexV7Kas(base), other.suffixHex, "two states of one template share the suffix; the length holes follow the (constant) script size");
});

test("silverc cross-check: the skeleton belongs to the CANDIDATE v0.7-kas source (sha256 393f2130…, NOT byte-frozen); a real frozen v0.7-payment compile is refused by the KAS decoder and a real KAS compile by the payment decoder", { skip: SKIP }, () => {
  const template = vaultTemplate();
  const state = { protectedValue: "1", feeReserve: "0", paused: "0", agentRoot: H(0x00), approvers: [], approvalM: "0", policyNonce: "0" };
  const c = compileKas(template, state);
  assert.equal(c.scriptHex.length / 2, 1 + 441 + c.suffixHex.length / 2);
  assert.ok(c.suffixHex.length / 2 > 18400 && c.suffixHex.length / 2 < 18600, `suffix ${c.suffixHex.length / 2}`);
  const sha = crypto.createHash("sha256").update(fs.readFileSync(path.join(config.repoRoot, "contracts/PolicyVault.v0.7-kas.sil"))).digest("hex");
  assert.equal(sha, "393f2130b48d06ba4d5b29ad8846098dd16ae89ebfd658a2df163f0801ac1d8b", "the CANDIDATE v0.7-kas covenant source is the one the skeleton was derived from");
  assert.equal(sha, K.VAULT_SCRIPT_COVENANT_SOURCE_SHA256_V7_KAS, "the module records the source it was derived from");
  /* cross-generation with REAL compiles */
  const ref = compileKcc20Program({ config, state: assets.kcc20.ZERO_STATE, familyBound: 2 });
  const descriptor = {
    schema: "policyvault-asset-descriptor/1", assetId: H(0x11), displayName: "T", tokenStandard: "kcc20/1", tokenCovenantId: H(0x54),
    acceptedTransferTemplates: [{ templateVmHashBlake2b256: ref.templateVmHashBlake2b256, prefixLen: ref.geometry.prefixLen, suffixLen: ref.geometry.suffixLen, stateLayout: "kcc20-state/1" }],
    decimalsDisplay: 2, issuerPowers: { mint: false, burn: false, freeze: false, blacklist: false, redemptionControl: false, upgradeMigration: false, controllerRotation: false, emergencyControl: false }
  };
  const rootPins = deriveRootPinsV7({ config, template: rootTemplate, ownerSet, covenantId: H(0x52) });
  const paymentTemplate = { vaultId: H(0x44), descriptorHash: assets.computeDescriptorHash(descriptor), tokenCovenantId: H(0x54), templateVmHash: ref.templateVmHashBlake2b256, templatePrefixLen: ref.geometry.prefixLen, templateStateLen: ref.geometry.stateLen, templateSuffixLen: ref.geometry.suffixLen, ...rootPins, recoveryPk: H(0x51) };
  const payment = compileExactStateV7({ config, template: paymentTemplate, state: { feeReserve: "500000000", paused: "0", agentRoot: H(0xe7), policyNonce: "0" } });
  assert.ok(P.isPaymentGenerationScriptV7(payment.scriptHex), "sanity: the frozen payment skeleton accepts silverc's payment compile");
  assert.equal(K.isKasGenerationScriptV7(payment.scriptHex), false, "the KAS decoder refuses a real frozen v0.7-payment script");
  assert.throws(() => K.decodeVaultTemplatePinsV7Kas(payment.scriptHex));
  assert.equal(P.isPaymentGenerationScriptV7(c.scriptHex), false, "the payment decoder refuses a real v0.7-kas script");
  assert.ok(K.isKasGenerationScriptV7(c.scriptHex));
});
