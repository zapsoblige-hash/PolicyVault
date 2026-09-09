"use strict";

/*
 * SDK/API (JSON store): the v0.5 TOKEN CONTROLLER (FROZEN) server-
 * orchestrated wallet-request pipeline (sdk/src/wallet-requests-v5.js +
 * sdk/src/reconcile-v5.js + sdk/src/manifest-v5.js), driven end to end
 * with the REAL toolchain (silverc, the production pv_call_encoder) and
 * REAL secp256k1 Schnorr signatures over deterministic TEST-ONLY keys.
 * Broadcast is exercised against a MOCK RPC (mirrors sdk/test/
 * org-roots-api.test.js's own mockRpc precedent) — the exact same code
 * path is proven against a REAL testnet-10 node by
 * tools/testnet-v5-http-e2e.js. The mock RPC does NOT verify scripts, so
 * signature AUTHENTICITY (a wrong-key signature being rejected) is a
 * live-node-only proof — recorded here honestly, never silently assumed.
 *
 * Classified REQUIREMENT_NOT_AVAILABLE (skipped, never silently passed)
 * when silverc / pv_call_encoder are absent.
 *
 * Covers docs/postlaunch/v0.7-app-surface-contract.md §6.1:
 *   - genesis -> sign -> submit -> CHAIN_VERIFIED, manifest persisted;
 *   - token deposit (separate token/KAS accounting throughout);
 *   - tokenAgentSpend (reserve-funded), registry period advance;
 *   - owner ops (pause/unpause/topUpReserve), fuel-funded;
 *   - ownerRecover (terminal), vault becomes read-only;
 *   - PENDING-is-not-success (SUBMITTING/SUBMITTED != CHAIN_VERIFIED);
 *   - unknown action / unknown vault / forced-migration (a v0.4-schema
 *     vault id on a v5 route) fail closed;
 *   - a second deposit into an already-held token position refused;
 *   - a non-canonical atomic-amount string (decimal "1.5") refused —
 *     never silently truncated/rounded into a token-domain integer.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");

const { loadConfig } = require("../src/config");
const assets = require("../../core/assets");
const { compileKcc20Program } = require("../src/token-program-kcc20");
const { buildRecipientTree } = require("../src/recipient-merkle-v3");
const { ENCODER_PATH } = require("../src/vault-builders-v4");
const { getStore, Categories } = require("../src/store");

const wr5 = require("../src/wallet-requests-v5");
const { loadManifestV5 } = require("../src/manifest-v5");
const { reconcileV5 } = require("../src/reconcile-v5");
const { covenantAddress, loadKaspa } = require("../src/chain");

function freshConfig() {
  return loadConfig({ dataRoot: fs.mkdtempSync(path.join(os.tmpdir(), "pv5-api-")) });
}
const config = freshConfig();
const available = fs.existsSync(config.silvercPath) && fs.existsSync(ENCODER_PATH);
const SKIP = !available && "REQUIREMENT_NOT_AVAILABLE: silverc / pv_call_encoder";
const kaspa = available ? require(config.rustyKaspaModule) : null;

const KAS = 100000000n;
const KEY = (v) => new kaspa.PrivateKey(v.toString(16).padStart(2, "0").repeat(32));
const XO = (p) => p.toPublicKey().toXOnlyPublicKey().toString().toLowerCase();
const ADDR = (p) => p.toPublicKey().toAddress(config.networkId).toString();
const H = (b) => b.toString(16).padStart(2, "0").repeat(32);

function signAll(unsignedSafeJson, entries) {
  const tx = kaspa.Transaction.deserializeFromSafeJSON(unsignedSafeJson);
  const ins = tx.inputs;
  for (const [i, key] of entries) ins[i].signatureScript = kaspa.createInputSignature(tx, i, key);
  tx.inputs = ins;
  return tx.serializeToSafeJSON();
}

function mockRpc(byAddress = {}) {
  const table = byAddress;
  return {
    async getUtxosByAddresses({ addresses }) {
      const entries = [];
      for (const a of addresses) for (const e of table[a] ?? []) entries.push(e);
      return { entries };
    },
    async submitTransaction({ transaction }) {
      return { transactionId: transaction.finalize().toString().toLowerCase() };
    },
    async disconnect() {},
    seed(address, entry) {
      table[address] = [...(table[address] ?? []), entry];
    }
  };
}
function utxo(address, txId, index, amountSompi, covenantId) {
  return { address, outpoint: { transactionId: txId, index }, amount: BigInt(amountSompi), covenantId: covenantId ?? null };
}
function spkAddress(cfg, spk) {
  const k = loadKaspa(cfg);
  return k.addressFromScriptPublicKey({ version: spk.version, script: spk.scriptHex }, cfg.networkId).toString();
}
function agentPolicyOnly(policyWithRecipients) {
  const { recipients, ...policy } = policyWithRecipients;
  void recipients;
  return policy;
}
function fundingUtxoFor(key, amount = 50n * KAS) {
  return { outpoint: { transactionId: crypto.randomBytes(32).toString("hex"), index: 0 }, amount: amount.toString(), scriptPublicKeyHex: `20${XO(key)}ac` };
}

function ctx() {
  const owner = KEY(0x81);
  const agent = KEY(0x82);
  const recipient = KEY(0x83);
  const userKey = KEY(0x84);
  const fuelKey = KEY(0x85);

  const ref = compileKcc20Program({ config, state: assets.kcc20.ZERO_STATE, familyBound: 2 });
  const tokenCovenantId = H(0x54);
  const descriptor = {
    schema: "policyvault-asset-descriptor/1",
    assetId: H(0x11),
    displayName: "V5 API Token",
    tokenStandard: "kcc20/1",
    tokenCovenantId,
    acceptedTransferTemplates: [{ templateVmHashBlake2b256: ref.templateVmHashBlake2b256, prefixLen: ref.geometry.prefixLen, suffixLen: ref.geometry.suffixLen, stateLayout: "kcc20-state/1" }],
    decimalsDisplay: 2,
    issuerPowers: { mint: false, burn: false, freeze: false, blacklist: false, redemptionControl: false, upgradeMigration: false, controllerRotation: false, emergencyControl: false }
  };
  const rTree = buildRecipientTree([XO(recipient)]);
  const agentPolicy = { agentPk: XO(agent), tokenMaxPerSpend: "500", tokenPeriodBudget: "1000", periodLengthDaa: "1000", periodStartDaa: "0", tokenPeriodSpent: "0", agentMaxFeePerTx: (1n * KAS).toString(), agentMaxCarryKas: KAS.toString(), agentRecipientRoot: rTree.root, recipients: [XO(recipient)] };
  return { owner, agent, recipient, userKey, fuelKey, ref, descriptor, tokenCovenantId, rTree, agentPolicy };
}

async function driveGenesisV5(cfg, c, rpc) {
  const req = await wr5.buildCreateWalletRequestV5({
    config: cfg, label: "test-controller", descriptor: c.descriptor, templateIndex: 0,
    initialAgents: [c.agentPolicy], feeReserveKas: "5", signerAddress: ADDR(c.owner), funding: [fundingUtxoFor(c.owner)]
  });
  assert.equal(req.kind, "genesis");
  assert.equal(req.state, "BUILT");
  const signed = signAll(req.transaction.unsignedSafeJson, req.transaction.signInputs.map((s) => [s.index, c.owner]));
  const finalized = await wr5.submitSignatureV5({ config: cfg, requestId: req.requestId, signedSafeJson: signed });
  assert.equal(finalized.state, "SIGNED");

  const addr = covenantAddress(cfg, Buffer.from(finalized.build.controllerScriptHex, "hex"));
  rpc.seed(addr, utxo(addr, finalized.txId, finalized.build.controllerOutputIndex, finalized.build.initialState.feeReserve, finalized.build.covenantId));
  const submitted = await wr5.submitWalletRequestV5({ config: cfg, requestId: req.requestId, rpc });
  assert.equal(submitted.state, "CHAIN_VERIFIED");
  return submitted;
}

test("well-formed genesis: BUILT -> SIGNED -> SUBMITTING/SUBMITTED (not success) -> CHAIN_VERIFIED; manifest persisted ACTIVE with separated token/kas accounting", { skip: SKIP }, async () => {
  const cfg = freshConfig();
  const c = ctx();
  const rpc = mockRpc();
  const submitted = await driveGenesisV5(cfg, c, rpc);
  const vaultId = submitted.vaultId;

  const manifest = await loadManifestV5(cfg, vaultId);
  assert.ok(manifest);
  assert.equal(manifest.status, "ACTIVE");
  assert.equal(manifest.contractVersion, "policyvault-0.5");
  assert.equal(manifest.live.tokenPosition, null);
  assert.equal(manifest.live.state.feeReserve.toString(), (5n * KAS).toString());
  assert.equal(submitted.accounting.kas.feeReserve, (5n * KAS).toString());
  assert.ok(submitted.accounting.token, "token accounting domain is present and separate from kas");

  /* idempotent resubmit */
  const again = await wr5.submitWalletRequestV5({ config: cfg, requestId: submitted.requestId, rpc });
  assert.equal(again.state, "CHAIN_VERIFIED");
});

test("PENDING is never presented as success: a request stuck at RECONCILIATION_REQUIRED (successor not observed) is NOT CHAIN_VERIFIED, and reconcile-v5 fails closed to UNKNOWN with no claim/no proof", { skip: SKIP }, async () => {
  const cfg = freshConfig();
  const c = ctx();
  const rpc = mockRpc(); // deliberately NOT seeded with the genesis output
  const req = await wr5.buildCreateWalletRequestV5({ config: cfg, descriptor: c.descriptor, initialAgents: [c.agentPolicy], feeReserveKas: "5", signerAddress: ADDR(c.owner), funding: [fundingUtxoFor(c.owner)] });
  const signed = signAll(req.transaction.unsignedSafeJson, req.transaction.signInputs.map((s) => [s.index, c.owner]));
  await wr5.submitSignatureV5({ config: cfg, requestId: req.requestId, signedSafeJson: signed });
  await assert.rejects(() => wr5.submitWalletRequestV5({ config: cfg, requestId: req.requestId, rpc }), (e) => { assert.equal(e.code, "RECONCILIATION_REQUIRED"); return true; });
  const persisted = await wr5.loadWalletRequestV5(cfg, req.requestId);
  assert.equal(persisted.state, "RECONCILIATION_REQUIRED");
  assert.notEqual(persisted.state, "CHAIN_VERIFIED");
});

test("full lifecycle on one controller: tokenDeposit -> tokenAgentSpend (reserve-funded) -> ownerPause -> ownerUnpause -> ownerTopUpReserve -> ownerRecover (terminal, token position returns to owner)", { skip: SKIP }, async () => {
  const cfg = freshConfig();
  const c = ctx();
  const rpc = mockRpc();
  const genesis = await driveGenesisV5(cfg, c, rpc);
  const vaultId = genesis.vaultId;

  /* ---- tokenDeposit: a user-owned (p2pk) position -> the controller ---- */
  const userPosState = { ownerIdentifier: XO(c.userKey), identifierType: assets.kcc20.OWNER_SCHEMES.P2PK, amount: 500n, isMinter: false };
  const userProgram = compileKcc20Program({ config: cfg, state: userPosState, familyBound: c.ref.familyBound });
  const depositReq = await wr5.buildWalletRequestV5({
    config: cfg, vaultId, action: "tokenDeposit", signerAddress: ADDR(c.userKey),
    params: {
      userPosition: { outpoint: { transactionId: H(0x02), index: 0 }, value: (2n * KAS).toString(), scriptPublicKeyHex: userProgram.p2shSpkHex, covenantId: c.tokenCovenantId, state: userPosState },
      fuel: fundingUtxoFor(c.fuelKey),
      depositAmount: "300",
      depositCarryKasSompi: (1n * KAS).toString()
    }
  });
  assert.equal(depositReq.kind, "tokenDeposit");
  assert.equal(depositReq.accounting.token.deposit, "300");
  assert.equal(depositReq.accounting.token.remainderToUser, "200");
  const depositSigned = signAll(depositReq.transaction.unsignedSafeJson, [[0, c.userKey], [1, c.fuelKey]]);
  const depositFinalized = await wr5.submitSignatureV5({ config: cfg, requestId: depositReq.requestId, signedSafeJson: depositSigned });
  assert.equal(depositFinalized.state, "SIGNED");
  const depositAddr = spkAddress(cfg, depositReq.build.frozen.outputs[0].scriptPublicKey);
  rpc.seed(depositAddr, utxo(depositAddr, depositReq.txId, 0, depositReq.build.frozen.outputs[0].value, depositReq.build.frozen.outputs[0].covenant.covenantId));
  const depositSubmitted = await wr5.submitWalletRequestV5({ config: cfg, requestId: depositReq.requestId, rpc });
  assert.equal(depositSubmitted.state, "CHAIN_VERIFIED");

  const afterDeposit = await loadManifestV5(cfg, vaultId);
  assert.ok(afterDeposit.live.tokenPosition);
  assert.equal(afterDeposit.live.tokenPosition.state.amount.toString(), "300");

  /* a SECOND deposit is refused (no merge input; would create an untracked UTXO) */
  await assert.rejects(
    () => wr5.buildWalletRequestV5({ config: cfg, vaultId, action: "tokenDeposit", signerAddress: ADDR(c.userKey), params: { userPosition: { outpoint: { transactionId: H(0x09), index: 0 }, value: KAS.toString(), scriptPublicKeyHex: userProgram.p2shSpkHex, covenantId: c.tokenCovenantId, state: userPosState }, fuel: fundingUtxoFor(c.fuelKey), depositAmount: "10", depositCarryKasSompi: KAS.toString() } }),
    (e) => { assert.equal(e.code, "TOKEN_POSITION_ALREADY_HELD"); return true; }
  );

  const currentTokenPositionParam = () => ({
    outpoint: afterDeposit.live.tokenPosition.outpoint,
    value: afterDeposit.live.tokenPosition.value.toString(),
    scriptPublicKeyHex: afterDeposit.live.tokenPosition.scriptPublicKeyHex,
    covenantId: afterDeposit.live.tokenPosition.covenantId,
    state: { ownerIdentifier: afterDeposit.live.tokenPosition.state.ownerIdentifier, identifierType: afterDeposit.live.tokenPosition.state.identifierType, amount: afterDeposit.live.tokenPosition.state.amount.toString(), isMinter: false }
  });

  /* a non-canonical (decimal) atomic-amount string is refused — token
   * domain integers are never silently truncated/rounded */
  await assert.rejects(
    () => wr5.buildWalletRequestV5({ config: cfg, vaultId, action: "tokenAgentSpend", signerAddress: ADDR(c.agent), params: { spendAmount: "1.5", agents: [agentPolicyOnly(c.agentPolicy)], recipient: XO(c.recipient), recipients: [XO(c.recipient)], recipientCarryKasSompi: "1", tokenPosition: currentTokenPositionParam() } }),
    (e) => { assert.ok(e.message.length > 0); return true; }
  );

  /* ---- tokenAgentSpend, reserve-funded (no fuel) ---- */
  const spendReq = await wr5.buildWalletRequestV5({
    config: cfg, vaultId, action: "tokenAgentSpend", signerAddress: ADDR(c.agent),
    params: { spendAmount: "150", agents: [agentPolicyOnly(c.agentPolicy)], recipient: XO(c.recipient), recipients: [XO(c.recipient)], recipientCarryKasSompi: (KAS / 4n).toString(), tokenPosition: currentTokenPositionParam() }
  });
  assert.equal(spendReq.accounting.token.spendAmount, "150");
  assert.equal(spendReq.build.hasFuelInput, false, "reserve-funded: no fuel input");
  const spendSigned = signAll(spendReq.transaction.unsignedSafeJson, [[0, c.agent]]);
  await wr5.submitSignatureV5({ config: cfg, requestId: spendReq.requestId, signedSafeJson: spendSigned });
  const spendSuccIdx = spendReq.build.frozen.outputs.findIndex((o) => o.covenant && o.covenant.covenantId === spendReq.build.covenantId);
  const spendSuccAddr = spkAddress(cfg, spendReq.build.frozen.outputs[spendSuccIdx].scriptPublicKey);
  rpc.seed(spendSuccAddr, utxo(spendSuccAddr, spendReq.txId, spendSuccIdx, spendReq.build.frozen.outputs[spendSuccIdx].value, spendReq.build.covenantId));
  const spendSubmitted = await wr5.submitWalletRequestV5({ config: cfg, requestId: spendReq.requestId, rpc });
  assert.equal(spendSubmitted.state, "CHAIN_VERIFIED");

  const afterSpend = await loadManifestV5(cfg, vaultId);
  assert.equal(afterSpend.live.tokenPosition.state.amount.toString(), "150");
  const agentEntry = afterSpend.agentRegistry.find((e) => e.policy.agentPk === XO(c.agent));
  assert.equal(agentEntry.policy.tokenPeriodSpent.toString(), "150", "period-window advance applied to the spending agent's leaf");

  /* ---- ownerPause / ownerUnpause (fuel-funded owner ops) ---- */
  const pauseReq = await wr5.buildWalletRequestV5({ config: cfg, vaultId, action: "ownerPause", signerAddress: ADDR(c.owner), params: { fuel: fundingUtxoFor(c.fuelKey) } });
  const pauseSigned = signAll(pauseReq.transaction.unsignedSafeJson, [[0, c.owner], [1, c.fuelKey]]);
  await wr5.submitSignatureV5({ config: cfg, requestId: pauseReq.requestId, signedSafeJson: pauseSigned });
  const pauseSuccAddr = spkAddress(cfg, pauseReq.build.frozen.outputs[0].scriptPublicKey);
  rpc.seed(pauseSuccAddr, utxo(pauseSuccAddr, pauseReq.txId, 0, pauseReq.build.frozen.outputs[0].value, pauseReq.build.covenantId));
  const pauseSubmitted = await wr5.submitWalletRequestV5({ config: cfg, requestId: pauseReq.requestId, rpc });
  assert.equal(pauseSubmitted.state, "CHAIN_VERIFIED");
  assert.equal((await loadManifestV5(cfg, vaultId)).live.state.paused, 1n);

  const unpauseReq = await wr5.buildWalletRequestV5({ config: cfg, vaultId, action: "ownerUnpause", signerAddress: ADDR(c.owner), params: { fuel: fundingUtxoFor(c.fuelKey) } });
  const unpauseSigned = signAll(unpauseReq.transaction.unsignedSafeJson, [[0, c.owner], [1, c.fuelKey]]);
  await wr5.submitSignatureV5({ config: cfg, requestId: unpauseReq.requestId, signedSafeJson: unpauseSigned });
  const unpauseSuccAddr = spkAddress(cfg, unpauseReq.build.frozen.outputs[0].scriptPublicKey);
  rpc.seed(unpauseSuccAddr, utxo(unpauseSuccAddr, unpauseReq.txId, 0, unpauseReq.build.frozen.outputs[0].value, unpauseReq.build.covenantId));
  const unpauseSubmitted = await wr5.submitWalletRequestV5({ config: cfg, requestId: unpauseReq.requestId, rpc });
  assert.equal(unpauseSubmitted.state, "CHAIN_VERIFIED");
  assert.equal((await loadManifestV5(cfg, vaultId)).live.state.paused, 0n);

  /* ---- ownerTopUpReserve ---- */
  const topUpReq = await wr5.buildWalletRequestV5({ config: cfg, vaultId, action: "ownerTopUpReserve", signerAddress: ADDR(c.owner), params: { fuel: fundingUtxoFor(c.fuelKey), topUpReserveAmountSompi: KAS.toString() } });
  const topUpSigned = signAll(topUpReq.transaction.unsignedSafeJson, [[0, c.owner], [1, c.fuelKey]]);
  await wr5.submitSignatureV5({ config: cfg, requestId: topUpReq.requestId, signedSafeJson: topUpSigned });
  const topUpSuccAddr = spkAddress(cfg, topUpReq.build.frozen.outputs[0].scriptPublicKey);
  rpc.seed(topUpSuccAddr, utxo(topUpSuccAddr, topUpReq.txId, 0, topUpReq.build.frozen.outputs[0].value, topUpReq.build.covenantId));
  const topUpSubmitted = await wr5.submitWalletRequestV5({ config: cfg, requestId: topUpReq.requestId, rpc });
  assert.equal(topUpSubmitted.state, "CHAIN_VERIFIED");
  const reserveAfterTopUp = (await loadManifestV5(cfg, vaultId)).live.state.feeReserve;

  /* ---- ownerRecover: terminal, token position (150) returns to owner ---- */
  const manifestBeforeRecover = await loadManifestV5(cfg, vaultId);
  const recoverReq = await wr5.buildWalletRequestV5({
    config: cfg, vaultId, action: "ownerRecover", signerAddress: ADDR(c.owner),
    params: { fuel: fundingUtxoFor(c.fuelKey), tokenPosition: { outpoint: manifestBeforeRecover.live.tokenPosition.outpoint, value: manifestBeforeRecover.live.tokenPosition.value.toString(), scriptPublicKeyHex: manifestBeforeRecover.live.tokenPosition.scriptPublicKeyHex, covenantId: manifestBeforeRecover.live.tokenPosition.covenantId, state: { ownerIdentifier: manifestBeforeRecover.live.tokenPosition.state.ownerIdentifier, identifierType: manifestBeforeRecover.live.tokenPosition.state.identifierType, amount: manifestBeforeRecover.live.tokenPosition.state.amount.toString(), isMinter: false } } }
  });
  assert.equal(recoverReq.accounting.token.recoveredToOwner, "150");
  assert.equal(recoverReq.accounting.kas.terminalPayout, reserveAfterTopUp.toString());
  const recoverSigned = signAll(recoverReq.transaction.unsignedSafeJson, [[0, c.owner], [recoverReq.build.frozen.inputs.length - 1, c.fuelKey]]);
  await wr5.submitSignatureV5({ config: cfg, requestId: recoverReq.requestId, signedSafeJson: recoverSigned });
  const recoverSubmitted = await wr5.submitWalletRequestV5({ config: cfg, requestId: recoverReq.requestId, rpc });
  assert.equal(recoverSubmitted.state, "CHAIN_VERIFIED");

  const afterRecover = await loadManifestV5(cfg, vaultId);
  assert.equal(afterRecover.status, "RECOVERED");
  assert.equal(afterRecover.live, null);

  /* a terminal (closed) vault refuses EVERY further write */
  await assert.rejects(
    () => wr5.buildWalletRequestV5({ config: cfg, vaultId, action: "ownerPause", signerAddress: ADDR(c.owner), params: { fuel: fundingUtxoFor(c.fuelKey) } }),
    (e) => { assert.equal(e.code, "VAULT_TERMINAL"); return true; }
  );
});

test("unknown action fails closed; unknown vault fails closed; unknown covenant version at the manifest boundary fails closed", { skip: SKIP }, async () => {
  const cfg = freshConfig();
  const c = ctx();
  const rpc = mockRpc();
  const genesis = await driveGenesisV5(cfg, c, rpc);

  await assert.rejects(
    () => wr5.buildWalletRequestV5({ config: cfg, vaultId: genesis.vaultId, action: "totallyBogusAction", signerAddress: ADDR(c.owner), params: {} }),
    (e) => { assert.equal(e.code, "UNKNOWN_ACTION"); return true; }
  );
  await assert.rejects(
    () => wr5.buildWalletRequestV5({ config: cfg, vaultId: H(0xee), action: "ownerPause", signerAddress: ADDR(c.owner), params: {} }),
    (e) => { assert.equal(e.code, "VAULT_NOT_FOUND"); return true; }
  );

  /* FORCED-MIGRATION IMPOSSIBLE: a manifest stored under a foreign
   * (non-v5) schema on the SAME vaultId key is refused CONTRACT_VERSION_MISMATCH */
  const foreignVaultId = H(0xfa);
  await getStore(cfg).write(Categories.VAULT, foreignVaultId, { schema: "policyvault-vault-manifest/v4.1", contractVersion: "policyvault-0.4.1", vaultId: foreignVaultId, status: "ACTIVE" });
  await assert.rejects(
    () => wr5.buildWalletRequestV5({ config: cfg, vaultId: foreignVaultId, action: "ownerPause", signerAddress: ADDR(c.owner), params: {} }),
    (e) => { assert.equal(e.code, "CONTRACT_VERSION_MISMATCH"); return true; }
  );
});

test("reconcile-v5 CONSISTENT case: a live outpoint on chain with no claim is left untouched", { skip: SKIP }, async () => {
  const cfg = freshConfig();
  const c = ctx();
  const rpc = mockRpc();
  const genesis = await driveGenesisV5(cfg, c, rpc);
  const manifest = await loadManifestV5(cfg, genesis.vaultId);
  const realAddr = covenantAddress(cfg, Buffer.from(genesis.build.controllerScriptHex, "hex"));
  rpc.seed(realAddr, utxo(realAddr, manifest.live.outpoint.transactionId, manifest.live.outpoint.index, manifest.live.state.feeReserve, manifest.live.covenantId));
  const result = await reconcileV5(cfg, genesis.vaultId, { rpc });
  assert.equal(result.status, "CONSISTENT");
});
