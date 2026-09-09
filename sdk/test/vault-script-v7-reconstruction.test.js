"use strict";
/*
 * Codex checkpoint 6 (UX-02 / UX-13) — the shared-core reconstruction of the
 * v0.7-payment ROOTED VAULT successor locking script
 * (core/intent/vault-script-v7.js) is cross-checked against the REAL vendored
 * compiler (silverc) over a state matrix: for every compiled state the
 * artifact's state_layout must be exactly (1, 93), the core's serialized
 * state region must equal the compiler's, the template (prefix + suffix) must
 * be invariant across states of one vault, and rebuilding any successor from
 * any predecessor's redeem must reproduce silverc's successor script and its
 * P2SH byte for byte. Any drift between the model and the frozen generation
 * breaks this test. REQUIREMENT_NOT_AVAILABLE (skipped, never silently
 * passed) when the vendored silverc is absent.
 *
 * Codex checkpoint 7 (UX-02 / UX-13): the frozen v0.7-payment TEMPLATE
 * SKELETON (core/intent/vault-script-v7.js, 142 holes) is cross-checked the
 * same way across a TEMPLATE matrix — every pin varied through its push
 * encoding classes (OP_0, OP_1..16, 1-, 2- and 3-byte pushes; distinct
 * 32-byte constants) — the whole script rebuilt from pins + state must equal
 * silverc's compile byte for byte, and the pins must decode back out of
 * silverc's script.
 */
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { loadConfig } = require("../src/config");
const { compileExactStateV7, deriveRootPinsV7 } = require("../src/contract-compiler-v7");
const assets = require("../../core/assets");
const { compileKcc20Program } = require("../src/token-program-kcc20");
const V = require("../../core/intent/vault-script-v7");

const config = loadConfig({ dataRoot: fs.mkdtempSync(path.join(os.tmpdir(), "pv-vaultscript-")) });
const available = fs.existsSync(config.silvercPath);
const H = (b) => b.toString(16).padStart(2, "0").repeat(32);

function vaultTemplate(over = {}) {
  const ref = compileKcc20Program({ config, state: assets.kcc20.ZERO_STATE, familyBound: 2 });
  const descriptor = {
    schema: "policyvault-asset-descriptor/1", assetId: H(0x11), displayName: "T", tokenStandard: "kcc20/1", tokenCovenantId: H(0x54),
    acceptedTransferTemplates: [{ templateVmHashBlake2b256: ref.templateVmHashBlake2b256, prefixLen: ref.geometry.prefixLen, suffixLen: ref.geometry.suffixLen, stateLayout: "kcc20-state/1" }],
    decimalsDisplay: 2, issuerPowers: { mint: false, burn: false, freeze: false, blacklist: false, redemptionControl: false, upgradeMigration: false, controllerRotation: false, emergencyControl: false }
  };
  const rootTemplate = { orgId: H(0xa7), recoveryDelayDaa: "1000", successorPk: H(0x7f), successionDelayDaa: "2000", rootMaxFeePerTx: "200000" };
  const ownerSet = { owners: [H(0x71), H(0x72), H(0x73), ...Array(9).fill("00".repeat(32))], ownerM: 2, emergencyK: 1, recoveryM: 2 };
  const rootPins = deriveRootPinsV7({ config, template: rootTemplate, ownerSet, covenantId: H(0x52) });
  return {
    vaultId: H(0x44), descriptorHash: assets.computeDescriptorHash(descriptor), tokenCovenantId: H(0x54),
    templateVmHash: ref.templateVmHashBlake2b256, templatePrefixLen: ref.geometry.prefixLen, templateStateLen: ref.geometry.stateLen, templateSuffixLen: ref.geometry.suffixLen,
    ...rootPins, recoveryPk: H(0x51), ...over
  };
}

test("silverc cross-check: layout (1, 93), state region, template invariance and successor reconstruction across a state matrix", { skip: !available && "REQUIREMENT_NOT_AVAILABLE: vendored silverc not staged" }, () => {
  const template = vaultTemplate();
  const states = [
    { feeReserve: "500000000", paused: "0", agentRoot: H(0xe7), policyNonce: "0" },
    { feeReserve: "500000000", paused: "1", agentRoot: H(0xe7), policyNonce: "0" },
    { feeReserve: "1", paused: "0", agentRoot: H(0x00), policyNonce: "1" },
    { feeReserve: "9007199254740991", paused: "1", agentRoot: H(0xff), policyNonce: "1000000000" },
    { feeReserve: "127", paused: "0", agentRoot: H(0x80), policyNonce: "128" },
    { feeReserve: "4294967296", paused: "0", agentRoot: H(0x01), policyNonce: "65536" }
  ];
  const compiled = states.map((state) => ({ state, c: compileExactStateV7({ config, template, state }) }));
  const templates = new Set();
  for (const { state, c } of compiled) {
    assert.deepEqual({ start: c.stateLayout.start, len: c.stateLayout.len }, { start: V.VAULT_SCRIPT_PREFIX_LEN_V7, len: V.VAULT_STATE_REGION_LEN_V7 }, "silverc's state_layout is the pinned (1, 93)");
    assert.equal(V.serializeVaultStateRegionHexV7({ vaultId: template.vaultId, state }), c.stateRegionHex, `state region == silverc's for ${JSON.stringify(state)}`);
    const parts = V.splitVaultRedeemHexV7(c.scriptHex);
    assert.equal(parts.prefixHex, c.prefixHex); assert.equal(parts.suffixHex, c.suffixHex); assert.equal(parts.regionHex, c.stateRegionHex);
    assert.deepEqual(parts.decoded, { vaultId: template.vaultId, state });
    templates.add(c.prefixHex + "|" + c.suffixHex);
  }
  assert.equal(templates.size, 1, "prefix + suffix (the template) are invariant across every state of one vault");
  /* every successor from every predecessor: rebuild == compile */
  let pairs = 0;
  for (const pred of compiled) for (const succ of compiled) {
    const rebuilt = V.reconstructVaultSuccessorHexV7({ redeemHex: pred.c.scriptHex, vaultId: template.vaultId, state: succ.state });
    assert.equal(rebuilt, succ.c.scriptHex, "rebuilt successor script == silverc's compile of the successor state");
    assert.equal(V.reconstructVaultSuccessorSpkHexV7({ redeemHex: pred.c.scriptHex, vaultId: template.vaultId, state: succ.state }), "aa20" + require("../../core/assets/blake2b").blake2bHex(Buffer.from(succ.c.scriptHex, "hex"), 32) + "87");
    pairs += 1;
  }
  assert.equal(pairs, states.length * states.length);
  /* a different vault (other pins) has a different template: its redeem never rebuilds this vault's successors */
  const other = compileExactStateV7({ config, template: vaultTemplate({ recoveryPk: H(0x99) }), state: states[0] });
  assert.notEqual(V.reconstructVaultSuccessorHexV7({ redeemHex: other.scriptHex, vaultId: template.vaultId, state: states[1] }), compiled[1].c.scriptHex);
});

test("Codex checkpoint 7 — silverc cross-check: the template skeleton rebuilds silverc's WHOLE script from pins + state across a constant-encoding matrix; the pins decode back out of the compiled script", { skip: !available && "REQUIREMENT_NOT_AVAILABLE: vendored silverc not staged" }, () => {
  const base = vaultTemplate();
  const state = { feeReserve: "500000000", paused: "0", agentRoot: H(0xe7), policyNonce: "3" };
  const matrix = [base];
  for (const v of [0, 1, 2, 16, 17, 127, 128, 255, 256, 65535, 65536, 1000000]) matrix.push({ ...base, templatePrefixLen: v });
  for (const v of [0, 1, 16, 17, 127, 128, 1521, 32767, 32768, 1000000]) matrix.push({ ...base, templateSuffixLen: v });
  for (const v of [1, 2, 16, 17, 128, 1000000]) matrix.push({ ...base, rootPrefixLen: v });
  for (const v of [1, 16, 17, 127, 128, 11077, 12077, 32768, 1000000]) matrix.push({ ...base, rootSuffixLen: v });
  for (const k of ["descriptorHash", "tokenCovenantId", "templateVmHash", "orgRootCovenantId", "rootTemplateVmHash", "recoveryPk", "vaultId"]) { matrix.push({ ...base, [k]: H(0x9b) }); matrix.push({ ...base, [k]: "ff".repeat(32) }); if (k !== "orgRootCovenantId") matrix.push({ ...base, [k]: "00".repeat(32) }); }
  matrix.push({ ...base, templatePrefixLen: 0, templateSuffixLen: 1, rootPrefixLen: 16, rootSuffixLen: 17, recoveryPk: H(0x01), descriptorHash: H(0x02), tokenCovenantId: H(0x03), templateVmHash: H(0x04), orgRootCovenantId: H(0x05), rootTemplateVmHash: H(0x06) });
  let checked = 0;
  for (const template of matrix) {
    const c = compileExactStateV7({ config, template, state });
    const rebuilt = V.reconstructVaultScriptHexV7({ template, state });
    assert.equal(rebuilt, c.scriptHex, `skeleton(pins, state) == silverc for ${JSON.stringify({ tp: template.templatePrefixLen, ts: template.templateSuffixLen, rp: template.rootPrefixLen, rs: template.rootSuffixLen })}`);
    assert.equal(V.reconstructVaultScriptSpkHexV7({ template, state }), "aa20" + require("../../core/assets/blake2b").blake2bHex(Buffer.from(c.scriptHex, "hex"), 32) + "87");
    const decoded = V.decodeVaultTemplatePinsV7(c.scriptHex);
    assert.deepEqual(decoded.pins, require("../../core/model/vault-state-v7").normalizeTemplateV7(template), "the pins decode back out of silverc's script");
    assert.deepEqual(decoded.state, state);
    checked += 1;
  }
  assert.ok(checked >= 55, `matrix size ${checked}`);
  /* two states of one template share the suffix; the script length holes follow the (constant) script size */
  const other = compileExactStateV7({ config, template: base, state: { ...state, paused: "1", policyNonce: "4" } });
  assert.equal(V.reconstructVaultScriptHexV7({ template: base, state: { ...state, paused: "1", policyNonce: "4" } }), other.scriptHex);
  assert.equal(V.reconstructVaultSuffixHexV7(base), other.suffixHex);
});

test("Codex checkpoint 7 — silverc cross-check: the skeleton belongs to the FROZEN generation (script size class; a rebuilt script recompiles to the same bytes under the frozen source hash)", { skip: !available && "REQUIREMENT_NOT_AVAILABLE: vendored silverc not staged" }, () => {
  const template = vaultTemplate();
  const state = { feeReserve: "1", paused: "0", agentRoot: H(0x00), policyNonce: "0" };
  const c = compileExactStateV7({ config, template, state });
  assert.equal(c.scriptHex.length / 2, 1 + 93 + c.suffixHex.length / 2);
  assert.ok(c.suffixHex.length / 2 > 9500 && c.suffixHex.length / 2 < 9700, `suffix ${c.suffixHex.length / 2}`);
  const sha = require("node:crypto").createHash("sha256").update(fs.readFileSync(path.join(config.repoRoot, "contracts/PolicyVault.v0.7-payment.sil"))).digest("hex");
  assert.equal(sha, "09cdbb6c284d8bd6c4cd2f4aad20d9682172eea3e048631176034b517be25091", "the frozen v0.7-payment covenant source is the one the skeleton was extracted from");
});
