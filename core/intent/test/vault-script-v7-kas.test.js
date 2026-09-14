"use strict";
/*
 * UNIT — R7-04 closure (v0.7 enablement directive 2026-09-10): the rooted-KAS
 * vault script reconstruction (core/intent/vault-script-v7-kas.js) is pure
 * data + pure functions, no compiler. The 441-byte state region encoding, the
 * (1, 441) layout and the 27-hole CANDIDATE template skeleton are ALSO
 * cross-checked against the real vendored silverc by
 * sdk/test/vault-script-v7-kas-reconstruction.test.js; here the skeleton's
 * own consistency is pinned: rebuild(pins, state) decodes back to exactly
 * those pins + state across every push-encoding class, the successor rebuilt
 * from a predecessor redeem IS the script rebuilt from pins around the
 * successor state, every tamper (chunk byte, disagreeing constants, length
 * constant, foreign generation) is refused with VAULT_GENERATION_MISMATCH,
 * and neither generation's decoder accepts the other's script.
 */
const { test } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const K = require("../vault-script-v7-kas");
const P = require("../vault-script-v7");
const { normalizeStateV4, stateToJsonV4 } = require("../../model/vault-state-v4");
const { normalizeTemplateV7Kas } = require("../../model/vault-state-v7-kas");
const { blake2bHex } = require("../../assets/blake2b");

const H = (b) => b.toString(16).padStart(2, "0").repeat(32);
const TEMPLATE = { vaultId: H(0x44), orgRootCovenantId: H(0x52), rootTemplateVmHash: H(0xd5), rootPrefixLen: 1, rootStateLen: 467, rootSuffixLen: 11077, recoveryPk: H(0x51) };
const STATE = { protectedValue: "10000000000", feeReserve: "300000000", paused: "0", agentRoot: H(0xe7), approvers: [H(0xa1), H(0xa2), H(0xa3)], approvalM: "2", policyNonce: "0" };
const p2sh = (hex) => "aa20" + blake2bHex(Buffer.from(hex, "hex"), 32) + "87";

test("state region: 441 bytes = push32(vaultId) push8(protectedValue) push8(feeReserve) push8(paused) push32(agentRoot) 10 x push32(approverSlot) push8(approvalM) push8(policyNonce); parse is the exact inverse; malformed regions refuse", () => {
  const hex = K.serializeVaultStateRegionHexV7Kas({ vaultId: TEMPLATE.vaultId, state: STATE });
  assert.equal(hex.length, K.VAULT_STATE_REGION_LEN_V7_KAS * 2);
  assert.equal(K.VAULT_STATE_REGION_LEN_V7_KAS, 441);
  assert.equal(K.VAULT_SCRIPT_PREFIX_LEN_V7_KAS, 1);
  assert.ok(hex.startsWith(`20${TEMPLATE.vaultId}0800e40b54020000000800a3e1110000000008000000000000000020${H(0xe7)}20${H(0xa1)}20${H(0xa2)}20${H(0xa3)}20${"00".repeat(32)}`), "head bytes");
  assert.ok(hex.endsWith("080200000000000000080000000000000000"), "tail bytes: approvalM 2, policyNonce 0");
  const back = K.parseVaultStateRegionHexV7Kas(hex);
  assert.equal(back.vaultId, TEMPLATE.vaultId);
  assert.deepEqual(back.state, stateToJsonV4(normalizeStateV4(STATE)), "the decoded state is the shared v4 JSON shape (approverSlots, decimal strings)");
  /* the model's NORMALIZED state (BigInt fields, 10 slots) and the approverSlots JSON shape both serialize identically */
  assert.equal(K.serializeVaultStateRegionHexV7Kas({ vaultId: TEMPLATE.vaultId, state: normalizeStateV4(STATE) }), hex);
  assert.equal(K.serializeVaultStateRegionHexV7Kas({ vaultId: TEMPLATE.vaultId, state: back.state }), hex);
  assert.throws(() => K.parseVaultStateRegionHexV7Kas(hex.slice(2)), /441 bytes/);
  assert.throws(() => K.parseVaultStateRegionHexV7Kas(`21${hex.slice(2)}`), /unexpected push opcode/);
  assert.throws(() => K.serializeVaultStateRegionHexV7Kas({ vaultId: "zz", state: STATE }), /32 bytes/);
  assert.throws(() => K.serializeVaultStateRegionHexV7Kas({ vaultId: TEMPLATE.vaultId, state: { ...STATE, paused: "2" } }));
  assert.throws(() => K.serializeVaultStateRegionHexV7Kas({ vaultId: TEMPLATE.vaultId, state: { ...STATE, approvalM: "4" } }), /exceeds the active approver count/);
});

test("skeleton pin: 27 holes / 28 chunks, sha256(chunks|holes) is the committed constant, the holes are exactly the covenant's template-constant uses", () => {
  assert.equal(K.VAULT_SCRIPT_HOLES_V7_KAS.length, 27);
  assert.equal(K.VAULT_SCRIPT_CHUNKS_V7_KAS.length, 28);
  const counts = {};
  for (const h of K.VAULT_SCRIPT_HOLES_V7_KAS) counts[h] = (counts[h] || 0) + 1;
  assert.deepEqual(counts, { orgRootCovenantId: 10, rootPrefixLen: 6, scriptLen: 6, rootTemplateVmHash: 2, rootSuffixLen: 2, recoveryPk: 1 });
  const sha = crypto.createHash("sha256").update(K.VAULT_SCRIPT_CHUNKS_V7_KAS.join("|") + "#" + K.VAULT_SCRIPT_HOLES_V7_KAS.join(",")).digest("hex");
  assert.equal(sha, K.VAULT_SCRIPT_SKELETON_SHA256_V7_KAS);
  assert.equal(K.VAULT_SCRIPT_SKELETON_SHA256_V7_KAS, "13709e50585d8d77a95eb3c981045bb153ec95c08d8ba837acc21b8d1f4d1904");
  assert.equal(K.VAULT_SCRIPT_COVENANT_SOURCE_SHA256_V7_KAS, "393f2130b48d06ba4d5b29ad8846098dd16ae89ebfd658a2df163f0801ac1d8b", "derived from the CANDIDATE v0.7-kas source (not byte-frozen)");
  assert.equal(K.VAULT_SCRIPT_PREFIX_HEX_V7_KAS, "6b");
  assert.notEqual(K.VAULT_SCRIPT_SKELETON_SHA256_V7_KAS, P.VAULT_SCRIPT_SKELETON_SHA256_V7, "a different generation has a different skeleton");
});

test("rebuild(pins, state) decodes back to exactly those pins + state across every push-encoding class; successor-from-redeem == rebuild-from-pins; P2SH helpers agree", () => {
  const matrix = [TEMPLATE];
  for (const v of [2, 16, 17, 127, 128, 255, 256, 65535, 65536, 1000000]) matrix.push({ ...TEMPLATE, rootPrefixLen: v });
  for (const v of [1, 16, 17, 127, 128, 12077, 32767, 32768, 1000000]) matrix.push({ ...TEMPLATE, rootSuffixLen: v });
  for (const k of ["orgRootCovenantId", "rootTemplateVmHash", "recoveryPk", "vaultId"]) { matrix.push({ ...TEMPLATE, [k]: H(0x9b) }); matrix.push({ ...TEMPLATE, [k]: "ff".repeat(32) }); if (k !== "orgRootCovenantId") matrix.push({ ...TEMPLATE, [k]: "00".repeat(32) }); }
  const states = [STATE, { ...STATE, paused: "1", policyNonce: "7" }, { protectedValue: "1", feeReserve: "0", paused: "0", agentRoot: "00".repeat(32), approvers: [], approvalM: "0", policyNonce: "1000000000" }, { ...STATE, approvers: Array.from({ length: 10 }, (_, i) => H(0xb0 + i)), approvalM: "10" }];
  let checked = 0;
  for (const template of matrix) {
    for (const state of states) {
      const script = K.reconstructVaultScriptHexV7Kas({ template, state });
      assert.ok(script.startsWith("6b"));
      const dec = K.decodeVaultTemplatePinsV7Kas(script);
      assert.deepEqual(dec.pins, normalizeTemplateV7Kas(template), "pins decode back");
      assert.deepEqual(dec.state, stateToJsonV4(normalizeStateV4(state)), "state decodes back");
      assert.equal(dec.vaultId, template.vaultId);
      assert.equal(K.reconstructVaultScriptSpkHexV7Kas({ template, state }), p2sh(script));
      assert.ok(K.isKasGenerationScriptV7(script));
      assert.equal(P.isPaymentGenerationScriptV7(script), false, "the frozen payment decoder never accepts a KAS script");
      checked += 1;
    }
    /* successor from the predecessor's redeem == rebuild from pins around the successor state (template invariance) */
    const pred = K.reconstructVaultScriptHexV7Kas({ template, state: states[0] });
    for (const succ of states) {
      assert.equal(K.reconstructVaultSuccessorHexV7Kas({ redeemHex: pred, vaultId: template.vaultId, state: succ }), K.reconstructVaultScriptHexV7Kas({ template, state: succ }));
      assert.equal(K.reconstructVaultSuccessorSpkHexV7Kas({ redeemHex: pred, vaultId: template.vaultId, state: succ }), p2sh(K.reconstructVaultScriptHexV7Kas({ template, state: succ })));
    }
    /* the suffix is state-independent and the script length constant is its own length */
    assert.equal(K.splitVaultRedeemHexV7Kas(pred).suffixHex, K.reconstructVaultSuffixHexV7Kas(template));
  }
  assert.ok(checked >= 120, `matrix ${checked}`);
  /* a different vault (other pins) never rebuilds this vault's successors */
  const other = K.reconstructVaultScriptHexV7Kas({ template: { ...TEMPLATE, recoveryPk: H(0x99) }, state: STATE });
  assert.notEqual(K.reconstructVaultSuccessorHexV7Kas({ redeemHex: other, vaultId: TEMPLATE.vaultId, state: states[1] }), K.reconstructVaultScriptHexV7Kas({ template: TEMPLATE, state: states[1] }));
});

test("every tamper is refused with VAULT_GENERATION_MISMATCH: chunk byte, disagreeing hole constants, wrong length constant, truncation; a well-formed but wrong rootStateLen pin is refused by the model", () => {
  const script = K.reconstructVaultScriptHexV7Kas({ template: TEMPLATE, state: STATE });
  const code = (fn) => { try { fn(); return null; } catch (e) { return e.code; } };
  const regionEnd = (1 + 441) * 2;
  /* flip one byte inside the first constant chunk */
  const flipped = script.slice(0, regionEnd + 10) + (script[regionEnd + 10] === "0" ? "1" : "0") + script.slice(regionEnd + 11);
  assert.equal(code(() => K.decodeVaultTemplatePinsV7Kas(flipped)), "VAULT_GENERATION_MISMATCH");
  assert.equal(K.isKasGenerationScriptV7(flipped), false);
  /* the FIRST orgRootCovenantId push (located by walking the skeleton) replaced by another 32-byte value: the holes of one constant must agree */
  let firstHole = -1;
  { let p = regionEnd; for (let i = 0; i < K.VAULT_SCRIPT_HOLES_V7_KAS.length; i++) { p += K.VAULT_SCRIPT_CHUNKS_V7_KAS[i].length; const h = K.VAULT_SCRIPT_HOLES_V7_KAS[i]; if (h === "orgRootCovenantId") { firstHole = p; break; } if (h === "rootTemplateVmHash" || h === "recoveryPk") { p += 66; continue; } const op = parseInt(script.slice(p, p + 2), 16); p += op === 0 || (op >= 0x51 && op <= 0x60) ? 2 : 2 + op * 2; } }
  assert.ok(firstHole > regionEnd, "located the first orgRootCovenantId hole");
  assert.equal(script.slice(firstHole, firstHole + 2), "20", "the hole is a 32-byte push");
  assert.equal(script.slice(firstHole + 2, firstHole + 66), TEMPLATE.orgRootCovenantId, "the hole holds the pinned root covenant id");
  const disagree = script.slice(0, firstHole + 2) + H(0x9c) + script.slice(firstHole + 66);
  const dis = (() => { try { K.decodeVaultTemplatePinsV7Kas(disagree); return null; } catch (e) { return e; } })();
  assert.ok(dis && dis.code === "VAULT_GENERATION_MISMATCH" && /disagree|differs/.test(dis.message), `disagreeing constants refused: ${dis && dis.message}`);
  /* an extra trailing byte: the tail differs / the length constant is no longer the script's length */
  assert.equal(code(() => K.decodeVaultTemplatePinsV7Kas(script + "00")), "VAULT_GENERATION_MISMATCH");
  assert.equal(code(() => K.decodeVaultTemplatePinsV7Kas(script.slice(0, -2))), "VAULT_GENERATION_MISMATCH");
  /* too short / not hex */
  assert.equal(code(() => K.splitVaultRedeemHexV7Kas("6b00")), "VAULT_SCRIPT_INVALID");
  assert.equal(code(() => K.splitVaultRedeemHexV7Kas("zz")), "VAULT_SCRIPT_INVALID");
  /* a root geometry pin the frozen root cannot have is refused before any rebuild (the skeleton folds rootStateLen = 467) */
  assert.throws(() => K.reconstructVaultScriptHexV7Kas({ template: { ...TEMPLATE, rootStateLen: 466 }, state: STATE }), /rootStateLen must be 467/);
  assert.throws(() => K.reconstructVaultScriptHexV7Kas({ template: { ...TEMPLATE, orgRootCovenantId: "00".repeat(32) }, state: STATE }), /sentinel zero/);
});

test("cross-generation guard: a frozen v0.7-payment script (rebuilt purely from payment pins) is refused by the KAS decoder, and the KAS script by the payment decoder", () => {
  const paymentTemplate = { vaultId: H(0x44), descriptorHash: H(0x21), tokenCovenantId: H(0x54), templateVmHash: H(0x33), templatePrefixLen: 1, templateStateLen: 46, templateSuffixLen: 1521, orgRootCovenantId: H(0x52), rootTemplateVmHash: H(0xd5), rootPrefixLen: 1, rootStateLen: 467, rootSuffixLen: 11077, recoveryPk: H(0x51) };
  const paymentScript = P.reconstructVaultScriptHexV7({ template: paymentTemplate, state: { feeReserve: "500000000", paused: "0", agentRoot: H(0xe7), policyNonce: "0" } });
  assert.ok(P.isPaymentGenerationScriptV7(paymentScript), "sanity: the payment skeleton accepts its own rebuild");
  assert.equal(K.isKasGenerationScriptV7(paymentScript), false);
  assert.throws(() => K.decodeVaultTemplatePinsV7Kas(paymentScript), (e) => e.code === "VAULT_SCRIPT_INVALID" || e.code === "VAULT_GENERATION_MISMATCH");
  const kasScript = K.reconstructVaultScriptHexV7Kas({ template: TEMPLATE, state: STATE });
  assert.equal(P.isPaymentGenerationScriptV7(kasScript), false);
  assert.throws(() => P.decodeVaultTemplatePinsV7(kasScript));
  /* same root pins, same recovery key, same vaultId — still two different scripts (and lengths) */
  assert.notEqual(kasScript.length, paymentScript.length);
});

test("templatePinsFromManifestVaultV7Kas maps the manifest's declared vault block to the model's template shape (nothing trusted until rebuilt)", () => {
  const vault = { contractVersion: "policyvault-0.7-kas", vaultId: H(0x44), covenantId: H(0x44), orgRootCovenantId: H(0x52), rootTemplateVmHash: H(0xd5), rootGeometry: { prefixLen: 1, stateLen: 467, suffixLen: 11077 }, recoveryPk: H(0x51) };
  assert.deepEqual(K.templatePinsFromManifestVaultV7Kas(vault), TEMPLATE);
  assert.deepEqual(normalizeTemplateV7Kas(K.templatePinsFromManifestVaultV7Kas(vault)), normalizeTemplateV7Kas(TEMPLATE));
  assert.equal(K.templatePinsFromManifestVaultV7Kas({ ...vault, rootGeometry: null }).rootPrefixLen, undefined, "a missing geometry maps to undefined pins (the model refuses them)");
  assert.throws(() => normalizeTemplateV7Kas(K.templatePinsFromManifestVaultV7Kas({ ...vault, rootGeometry: null })));
});
