"use strict";
/*
 * UNIT — Codex checkpoint 6 (UX-02 / UX-13): the rooted-vault successor-script
 * reconstruction (core/intent/vault-script-v7.js): pure data + pure functions,
 * no compiler. The state-region encoding and the (1, 93) layout are ALSO
 * cross-checked against the real vendored silverc by
 * sdk/test/vault-script-v7-reconstruction.test.js; here the REAL production
 * fixture (core/explain/test/fixtures/v7-org-root-manifests.json, captured
 * from SDK builds) proves that the carried predecessor redeem hashes to the
 * vault input's P2SH and that the reviewed successor state rebuilds EXACTLY
 * the successor output's P2SH.
 *
 * Codex checkpoint 7 (UX-02 / UX-13): the frozen v0.7-payment TEMPLATE
 * SKELETON (142 holes) rebuilds the WHOLE predecessor script from the
 * declared pins + reviewed state; the real fixtures' carried redeems are
 * reproduced byte for byte; every pin substitution Codex reproduced (root
 * suffix +1000, token suffix 1, recovery key, predecessor paused byte)
 * rebuilds a DIFFERENT script; the pins decode back out of the real script;
 * the root script is not mistaken for a payment vault.
 */
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const V = require("../vault-script-v7");

const FIXTURES = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "..", "explain", "test", "fixtures", "v7-org-root-manifests.json"), "utf8"));
const fixture = (name) => FIXTURES.manifests.find((m) => m.name === name);

test("state region: 93 bytes = push32(vaultId) push8(feeReserve) push8(paused) push32(agentRoot) push8(policyNonce); parse is the exact inverse; malformed regions refuse", () => {
  const vaultId = "44".repeat(32);
  const state = { feeReserve: "499950000", paused: "1", agentRoot: "02a78123cf1eb157e1756064d944360ab46145824f5b622b9de264c631d9b7d2", policyNonce: "7" };
  const hex = V.serializeVaultStateRegionHexV7({ vaultId, state });
  assert.equal(hex.length, V.VAULT_STATE_REGION_LEN_V7 * 2);
  assert.equal(hex, `20${vaultId}08b0a1cc1d0000000008010000000000000020${state.agentRoot}080700000000000000`);
  const back = V.parseVaultStateRegionHexV7(hex);
  assert.equal(back.vaultId, vaultId);
  assert.deepEqual(back.state, state);
  assert.throws(() => V.parseVaultStateRegionHexV7(hex.slice(2)), /93 bytes/);
  assert.throws(() => V.parseVaultStateRegionHexV7(`21${hex.slice(2)}`), /unexpected push opcode/);
  assert.throws(() => V.serializeVaultStateRegionHexV7({ vaultId: "zz", state }), /32 bytes/);
  assert.throws(() => V.serializeVaultStateRegionHexV7({ vaultId, state: { ...state, paused: "2" } }));
});

test("real production fixture: the carried predecessor redeem hashes to the vault input's P2SH, its region decodes to stateBefore, and the reviewed stateAfter rebuilds EXACTLY the successor output's P2SH", () => {
  for (const name of ["vault_owner_pause_under_authorize", "vault_emergency_pause_under_freeze"]) {
    const f = fixture(name);
    const op = f.manifest.vaultOperations[0];
    const redeem = f.redeemScripts[op.covenantId];
    assert.ok(typeof redeem === "string" && redeem.length > 2 * (V.VAULT_SCRIPT_PREFIX_LEN_V7 + V.VAULT_STATE_REGION_LEN_V7), `${name}: the fixture carries the predecessor redeem`);
    const frozen = JSON.parse(f.manifest.transaction.frozenCanonicalJson);
    const vaultIn = frozen.inputs.find((i) => i.utxo.covenantId === op.covenantId);
    const succ = frozen.outputs.find((o) => o.covenant && o.covenant.covenantId === op.covenantId);
    assert.equal(V.p2shSpkHexOf(redeem), vaultIn.utxo.scriptPublicKey.scriptHex, `${name}: P2SH(redeem) == the vault input's locking script`);
    const parts = V.splitVaultRedeemHexV7(redeem);
    assert.equal(parts.prefixHex, "6b");
    assert.equal(parts.decoded.vaultId, op.manifest.vault.vaultId);
    assert.deepEqual(parts.decoded.state, op.manifest.stateBefore.state, `${name}: the region IS the reviewed predecessor state`);
    const rebuilt = V.reconstructVaultSuccessorSpkHexV7({ redeemHex: redeem, vaultId: op.manifest.vault.vaultId, state: op.manifest.stateAfter.state });
    assert.equal(rebuilt, succ.scriptPublicKey.scriptHex, `${name}: the successor output is exactly the rebuilt script's P2SH`);
    /* a DIFFERENT successor state (e.g. the pause not applied, or a nonce bump) rebuilds a DIFFERENT script */
    assert.notEqual(V.reconstructVaultSuccessorSpkHexV7({ redeemHex: redeem, vaultId: op.manifest.vault.vaultId, state: op.manifest.stateBefore.state }), succ.scriptPublicKey.scriptHex);
    assert.notEqual(V.reconstructVaultSuccessorSpkHexV7({ redeemHex: redeem, vaultId: op.manifest.vault.vaultId, state: { ...op.manifest.stateAfter.state, policyNonce: String(Number(op.manifest.stateAfter.state.policyNonce) + 1) } }), succ.scriptPublicKey.scriptHex);
    /* a substituted redeem (one byte of the suffix changed) no longer matches the input — the binding that stops a forged template */
    const forged = redeem.slice(0, -2) + (redeem.slice(-2) === "00" ? "01" : "00");
    assert.notEqual(V.p2shSpkHexOf(forged), vaultIn.utxo.scriptPublicKey.scriptHex);
  }
});

test("refusals: a redeem shorter than prefix + region + 1, non-hex, or with a region that does not decode is refused closed", () => {
  assert.throws(() => V.splitVaultRedeemHexV7("6b" + "20".repeat(40)), /shorter/);
  assert.throws(() => V.splitVaultRedeemHexV7("xyz"), /hex/);
  assert.throws(() => V.splitVaultRedeemHexV7("6b" + "ff".repeat(93) + "aa"), /unexpected push opcode/);
  assert.throws(() => V.reconstructVaultSuccessorSpkHexV7({ redeemHex: "6b" + "ff".repeat(93) + "aa", vaultId: "44".repeat(32), state: { feeReserve: "1", paused: "0", agentRoot: "00".repeat(32), policyNonce: "0" } }));
});

test("Codex checkpoint 7: skeleton pin — 143 chunks around 142 holes (10 template constants + scriptLen ×6), sha256 pinned; minimal script-number pushes", () => {
  assert.equal(V.VAULT_SCRIPT_CHUNKS_V7.length, 143);
  assert.equal(V.VAULT_SCRIPT_HOLES_V7.length, 142);
  const counts = {};
  for (const h of V.VAULT_SCRIPT_HOLES_V7) counts[h] = (counts[h] || 0) + 1;
  assert.deepEqual(counts, { tokenCovenantId: 11, templatePrefixLen: 57, templateSuffixLen: 37, templateVmHash: 5, descriptorHash: 3, scriptLen: 6, orgRootCovenantId: 11, rootPrefixLen: 6, rootSuffixLen: 2, rootTemplateVmHash: 2, recoveryPk: 2 });
  assert.equal(crypto.createHash("sha256").update(V.VAULT_SCRIPT_CHUNKS_V7.join("|") + "#" + V.VAULT_SCRIPT_HOLES_V7.join(",")).digest("hex"), V.VAULT_SCRIPT_SKELETON_SHA256_V7);
  assert.equal(V.VAULT_SCRIPT_SKELETON_SHA256_V7, "b67f8ce8a4e6459dc6b62bc3afa0ddcee25b9f4c93b91543021818a81a3d64fc");
  assert.equal(V.VAULT_SCRIPT_PREFIX_HEX_V7, "6b");
  assert.equal(V.pushScriptNumHex(0), "00"); assert.equal(V.pushScriptNumHex(1), "51"); assert.equal(V.pushScriptNumHex(16), "60");
  assert.equal(V.pushScriptNumHex(17), "0111"); assert.equal(V.pushScriptNumHex(127), "017f"); assert.equal(V.pushScriptNumHex(128), "028000");
  assert.equal(V.pushScriptNumHex(1521), "02f105"); assert.equal(V.pushScriptNumHex(11077), "02452b"); assert.equal(V.pushScriptNumHex(32768), "03008000");
  assert.throws(() => V.pushScriptNumHex(-1));
});

test("Codex checkpoint 7: the real production fixtures' carried redeems are rebuilt BYTE FOR BYTE from the declared pins + reviewed predecessor state (terminal op included); the pins decode back out of the script; every reproduced substitution rebuilds a different script", () => {
  for (const name of ["vault_owner_pause_under_authorize", "vault_emergency_pause_under_freeze", "vault_recover_terminal_with_position"]) {
    const f = fixture(name);
    const op = f.manifest.vaultOperations[0];
    const redeem = f.redeemScripts[op.covenantId];
    const frozen = JSON.parse(f.manifest.transaction.frozenCanonicalJson);
    const vaultIn = frozen.inputs.find((i) => i.utxo.covenantId === op.covenantId);
    const pins = V.templatePinsFromManifestVault(op.manifest.vault);
    const rebuilt = V.reconstructVaultScriptHexV7({ template: pins, state: op.manifest.stateBefore.state });
    assert.equal(rebuilt, redeem, `${name}: skeleton(pins, stateBefore) == the carried redeem`);
    assert.equal(rebuilt.length / 2, 9636);
    assert.equal(V.reconstructVaultScriptSpkHexV7({ template: pins, state: op.manifest.stateBefore.state }), vaultIn.utxo.scriptPublicKey.scriptHex, `${name}: its P2SH is the vault input's locking script`);
    const decoded = V.decodeVaultTemplatePinsV7(redeem);
    assert.deepEqual(decoded.pins, pins, `${name}: the pins decode back out of the real script`);
    assert.deepEqual(decoded.state, op.manifest.stateBefore.state);
    assert.equal(V.isPaymentGenerationScriptV7(redeem), true);
    if (op.manifest.stateAfter) {
      const succ = frozen.outputs.find((o) => o.covenant && o.covenant.covenantId === op.covenantId);
      assert.equal(V.reconstructVaultScriptSpkHexV7({ template: pins, state: op.manifest.stateAfter.state }), succ.scriptPublicKey.scriptHex, `${name}: skeleton(pins, stateAfter) is the successor output`);
    }
    /* the substitutions Codex reproduced at checkpoint 7, each rebuilding a DIFFERENT script from the one the transaction spends */
    const variants = [
      ["rootSuffixLen + 1000", { ...pins, rootSuffixLen: pins.rootSuffixLen + 1000 }],
      ["templateSuffixLen = 1", { ...pins, templateSuffixLen: 1 }],
      ["recoveryPk substituted", { ...pins, recoveryPk: "9b".repeat(32) }],
      ["rootTemplateVmHash substituted", { ...pins, rootTemplateVmHash: "9c".repeat(32) }],
      ["templateVmHash substituted", { ...pins, templateVmHash: "9d".repeat(32) }],
      ["descriptorHash substituted", { ...pins, descriptorHash: "9e".repeat(32) }],
      ["orgRootCovenantId substituted", { ...pins, orgRootCovenantId: "9f".repeat(32) }],
      ["tokenCovenantId substituted", { ...pins, tokenCovenantId: "a0".repeat(32) }],
      ["rootPrefixLen = 2", { ...pins, rootPrefixLen: 2 }],
      ["templatePrefixLen = 0", { ...pins, templatePrefixLen: 0 }]
    ];
    for (const [label, t] of variants) assert.notEqual(V.reconstructVaultScriptHexV7({ template: t, state: op.manifest.stateBefore.state }), redeem, `${name}: ${label} rebuilds a different script`);
    assert.notEqual(V.reconstructVaultScriptHexV7({ template: pins, state: { ...op.manifest.stateBefore.state, paused: op.manifest.stateBefore.state.paused === "0" ? "1" : "0" } }), redeem, `${name}: a falsified predecessor paused byte rebuilds a different script`);
    assert.throws(() => V.reconstructVaultScriptHexV7({ template: { ...pins, rootStateLen: 466 }, state: op.manifest.stateBefore.state }), /rootStateLen/);
    assert.throws(() => V.reconstructVaultScriptHexV7({ template: { ...pins, templateStateLen: 45 }, state: op.manifest.stateBefore.state }), /templateStateLen/);
  }
  /* a script of ANOTHER generation is never mistaken for a payment vault: the fixture's ROOT script, and a payment script with one suffix byte changed */
  const f = fixture("vault_owner_pause_under_authorize");
  const rootHex = require("../root-script-v7").reconstructRootScriptHexV7({ template: { ...f.manifest.root.template, orgId: f.manifest.root.orgId }, state: f.manifest.rootState.before.state });
  assert.equal(V.isPaymentGenerationScriptV7(rootHex), false);
  assert.throws(() => V.decodeVaultTemplatePinsV7(rootHex), (e) => e.code === "VAULT_GENERATION_MISMATCH" || e.code === "VAULT_SCRIPT_INVALID");
  const redeem = f.redeemScripts[f.manifest.vaultOperations[0].covenantId];
  const forged = redeem.slice(0, -2) + (redeem.slice(-2) === "00" ? "01" : "00");
  assert.equal(V.isPaymentGenerationScriptV7(forged), false);
  /* a script whose two recoveryPk holes disagree is not a compiled vault */
  const pins = V.templatePinsFromManifestVault(f.manifest.vaultOperations[0].manifest.vault);
  const idx = redeem.indexOf("20" + pins.recoveryPk);
  assert.ok(idx > 0);
  const disagree = redeem.slice(0, idx + 2) + "9b".repeat(32) + redeem.slice(idx + 66);
  assert.equal(V.isPaymentGenerationScriptV7(disagree), false);
});
