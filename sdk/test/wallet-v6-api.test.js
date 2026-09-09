"use strict";

/*
 * SDK/API (JSON store): the v0.6 OPTIONAL-ATOMIC-COMPOSABILITY TOKEN
 * CONTROLLER (FROZEN) server-orchestrated wallet-request pipeline
 * (sdk/src/wallet-requests-v6.js + sdk/src/reconcile-v6.js +
 * sdk/src/manifest-v6.js). Mirrors sdk/test/wallet-v5-api.test.js's
 * mock-RPC + real-signature discipline; the exact same code path is
 * proven against a real testnet-10 node by
 * tools/testnet-v6-atomic-proof.js (existing) / the live e2e evidence
 * this track's report cites.
 *
 * Classified REQUIREMENT_NOT_AVAILABLE when silverc / pv_call_encoder
 * are absent.
 *
 * Covers docs/postlaunch/v0.7-app-surface-contract.md §6.1:
 *   - genesis (agents + swap policies) -> sign -> submit -> CHAIN_VERIFIED;
 *   - tokenAtomicSell against the PolicyVault pool FIXTURE, venue
 *     presented as { kind: "FIXTURE", supported: false }, deadlineDaa
 *     presented as a pre-sign freshness boundary (never consensus expiry);
 *   - a request naming a NON-fixture venue profile refused
 *     VENUE_PROFILE_UNSUPPORTED before the SDK builder ever runs;
 *   - a swap whose deadline has passed by the time of SUBMIT (node's own
 *     current DAA score) is refused DEADLINE_PASSED, never silently
 *     broadcast;
 *   - ownerRecover (terminal) with a live token position.
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
const { swapPolicyFromProfileV6, swapPolicyToJsonV6 } = require("../src/swap-policy-v6");
const { compilePoolFixtureV6, poolFixtureVenueProfile } = require("../src/swap-pool-fixture-v6");
const { ENCODER_PATH } = require("../src/vault-builders-v4");

const wr6 = require("../src/wallet-requests-v6");
const { loadManifestV6 } = require("../src/manifest-v6");
const { covenantAddress, loadKaspa } = require("../src/chain");

function freshConfig() {
  return loadConfig({ dataRoot: fs.mkdtempSync(path.join(os.tmpdir(), "pv6-api-")) });
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
function mockRpc(byAddress = {}, virtualDaaScore = "1000") {
  const table = byAddress;
  return {
    virtualDaaScore,
    async getUtxosByAddresses({ addresses }) {
      const entries = [];
      for (const a of addresses) for (const e of table[a] ?? []) entries.push(e);
      return { entries };
    },
    async getBlockDagInfo() {
      return { virtualDaaScore: this.virtualDaaScore };
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
function fundingUtxoFor(key, amount = 50n * KAS) {
  return { outpoint: { transactionId: crypto.randomBytes(32).toString("hex"), index: 0 }, amount: amount.toString(), scriptPublicKeyHex: `20${XO(key)}ac` };
}
function agentPolicyOnly(policyWithRecipients) {
  const { recipients, ...policy } = policyWithRecipients;
  void recipients;
  return policy;
}

function ctx() {
  const owner = KEY(0x91);
  const agent = KEY(0x92);
  const recipient = KEY(0x93);
  const userKey = KEY(0x94);
  const protocolFeeKey = KEY(0x95);
  const poolIdKey = KEY(0x96); // a stand-in "identity" for the pool covenant id in this test's fixture

  const ref = compileKcc20Program({ config, state: assets.kcc20.ZERO_STATE, familyBound: 2 });
  const tokenCovenantId = H(0x54);
  const descriptor = {
    schema: "policyvault-asset-descriptor/1",
    assetId: H(0x11),
    displayName: "V6 API Token",
    tokenStandard: "kcc20/1",
    tokenCovenantId,
    acceptedTransferTemplates: [{ templateVmHashBlake2b256: ref.templateVmHashBlake2b256, prefixLen: ref.geometry.prefixLen, suffixLen: ref.geometry.suffixLen, stateLayout: "kcc20-state/1" }],
    decimalsDisplay: 2,
    issuerPowers: { mint: false, burn: false, freeze: false, blacklist: false, redemptionControl: false, upgradeMigration: false, controllerRotation: false, emergencyControl: false }
  };
  const rTree = buildRecipientTree([XO(recipient)]);
  const poolCovenantId = H(0x50);
  const poolState = { kasReserve: (10000n * KAS).toString(), tokenReserve: "10000", feeBps: "30", nonce: "0" };
  const pool0 = compilePoolFixtureV6({ config, params: { tokenCovenantId, kcc20: { prefixHex: ref.prefixHex, suffixHex: ref.suffixHex, templateVmHashBlake2b256: ref.templateVmHashBlake2b256 }, protocolFeePk: XO(protocolFeeKey), protocolFeeBps: "20", ...poolState } });
  const venueProfile = poolFixtureVenueProfile({ networkId: config.networkId, poolCovenantId, compiled: pool0 });
  const ownerSwapTerms = { maxProtocolFeeKas: (5n * KAS).toString(), sellFloorNum: (9n * KAS / 10n).toString(), sellFloorDen: "1", buyCeilNum: (11n * KAS / 10n).toString(), buyCeilDen: "1", directionMask: "3", destScheme: 0x02 };
  const swapPolicy = swapPolicyFromProfileV6(venueProfile, ownerSwapTerms);

  const agentPolicy = {
    agentPk: XO(agent), tokenMaxPerSpend: "500", tokenPeriodBudget: "2000", periodLengthDaa: "1000", periodStartDaa: "0", tokenPeriodSpent: "0",
    agentMaxFeePerTx: (1n * KAS).toString(), agentMaxCarryKas: KAS.toString(),
    kasMaxPerSwap: (500n * KAS).toString(), kasPeriodBudget: (900n * KAS).toString(), kasPeriodSpent: "0",
    agentRecipientRoot: rTree.root, recipients: [XO(recipient)]
  };
  return { owner, agent, recipient, userKey, protocolFeeKey, poolIdKey, ref, descriptor, tokenCovenantId, rTree, agentPolicy, poolCovenantId, pool0, poolState, venueProfile, swapPolicy };
}

async function driveGenesisV6(cfg, c, rpc) {
  const req = await wr6.buildCreateWalletRequestV6({
    config: cfg, label: "test-swap-controller", descriptor: c.descriptor, templateIndex: 0,
    initialAgents: [c.agentPolicy], initialSwapPolicies: [c.swapPolicy],
    feeReserveKas: "5", swapPrincipalKas: "10", signerAddress: ADDR(c.owner), funding: [fundingUtxoFor(c.owner)]
  });
  assert.equal(req.kind, "genesis");
  const signed = signAll(req.transaction.unsignedSafeJson, req.transaction.signInputs.map((s) => [s.index, c.owner]));
  const finalized = await wr6.submitSignatureV6({ config: cfg, requestId: req.requestId, signedSafeJson: signed });
  assert.equal(finalized.state, "SIGNED");
  const addr = covenantAddress(cfg, Buffer.from(finalized.build.controllerScriptHex, "hex"));
  const value = (BigInt(finalized.build.initialState.feeReserve) + BigInt(finalized.build.initialState.swapPrincipal)).toString();
  rpc.seed(addr, utxo(addr, finalized.txId, finalized.build.controllerOutputIndex, value, finalized.build.covenantId));
  const submitted = await wr6.submitWalletRequestV6({ config: cfg, requestId: req.requestId, rpc });
  assert.equal(submitted.state, "CHAIN_VERIFIED");
  return submitted;
}

test("well-formed genesis (agents + swap policies): BUILT -> SIGNED -> CHAIN_VERIFIED; manifest persisted ACTIVE with swapRegistry root reconstructed", { skip: SKIP }, async () => {
  const cfg = freshConfig();
  const c = ctx();
  const rpc = mockRpc();
  const submitted = await driveGenesisV6(cfg, c, rpc);
  const manifest = await loadManifestV6(cfg, submitted.vaultId);
  assert.equal(manifest.status, "ACTIVE");
  assert.equal(manifest.contractVersion, "policyvault-0.6");
  assert.equal(manifest.swapRegistry.length, 1);
  assert.equal(manifest.live.state.swapPrincipal.toString(), (10n * KAS).toString());
});

test("a request naming a non-fixture venue profile is refused VENUE_PROFILE_UNSUPPORTED BEFORE the SDK builder runs; the fixture venue is accepted and presented as unsupported-for-real-trading", { skip: SKIP }, async () => {
  const cfg = freshConfig();
  const c = ctx();
  const rpc = mockRpc();
  const genesis = await driveGenesisV6(cfg, c, rpc);
  const manifest = await loadManifestV6(cfg, genesis.vaultId);

  const tokenPositionParam = (amount) => {
    const posState = { ownerIdentifier: manifest.live.covenantId, identifierType: assets.kcc20.OWNER_SCHEMES.COVENANT_ID, amount, isMinter: false };
    const prog = compileKcc20Program({ config: cfg, state: posState, familyBound: c.ref.familyBound });
    return { outpoint: { transactionId: H(0x02), index: 0 }, value: (2n * KAS).toString(), scriptPublicKeyHex: prog.p2shSpkHex, covenantId: c.tokenCovenantId, state: { ownerIdentifier: posState.ownerIdentifier, identifierType: posState.identifierType, amount: posState.amount.toString(), isMinter: false } };
  };
  const poolNoteParam = (amount) => {
    const noteState = { ownerIdentifier: c.poolCovenantId, identifierType: assets.kcc20.OWNER_SCHEMES.COVENANT_ID, amount, isMinter: false };
    const prog = compileKcc20Program({ config: cfg, state: noteState, familyBound: c.ref.familyBound });
    return { outpoint: { transactionId: H(0x08), index: 0 }, value: (2n * KAS).toString(), scriptPublicKeyHex: prog.p2shSpkHex, covenantId: c.tokenCovenantId, state: { ownerIdentifier: noteState.ownerIdentifier, identifierType: noteState.identifierType, amount: noteState.amount.toString(), isMinter: false } };
  };
  const poolParam = { outpoint: { transactionId: H(0x09), index: 0 }, value: c.poolState.kasReserve, scriptPublicKeyHex: c.pool0.p2shSpkHex, covenantId: c.poolCovenantId, state: c.poolState };
  const poolNoteAmount = BigInt(c.poolState.tokenReserve);

  const badProfile = { ...c.venueProfile, provenance: { ...c.venueProfile.provenance, sourceRelPath: "contracts/experiments/NotTheFixture.sil" } };
  await assert.rejects(
    () => wr6.buildWalletRequestV6({
      config: cfg, vaultId: genesis.vaultId, action: "tokenAtomicSell", signerAddress: ADDR(c.agent),
      params: { agents: [agentPolicyOnly(c.agentPolicy)], swapPolicies: [c.swapPolicy], swapPolicy: c.swapPolicy, venueProfile: badProfile, deadlineDaa: "99999999", amountIn: "100", minKasOut: "1", tokenPosition: tokenPositionParam(5000n), poolNote: poolNoteParam(poolNoteAmount), pool: poolParam }
    }),
    (e) => { assert.equal(e.code, "VENUE_PROFILE_UNSUPPORTED"); return true; }
  );

  /* the SAME request shape with the REAL fixture profile is accepted at the venue gate */
  const goodReq = await wr6.buildWalletRequestV6({
    config: cfg, vaultId: genesis.vaultId, action: "tokenAtomicSell", signerAddress: ADDR(c.agent),
    params: { agents: [agentPolicyOnly(c.agentPolicy)], swapPolicies: [c.swapPolicy], swapPolicy: c.swapPolicy, venueProfile: c.venueProfile, deadlineDaa: "99999999", amountIn: "100", minKasOut: "1", tokenPosition: tokenPositionParam(5000n), poolNote: poolNoteParam(poolNoteAmount), pool: poolParam }
  });
  assert.deepEqual(goodReq.venue, { kind: "FIXTURE", supported: false, note: "no real DEX venue is supported — the PolicyVault pool fixture is conformance/testnet evidence only" });
  assert.equal(goodReq.deadlineDaa, "99999999");
  assert.match(goodReq.freshnessStatement, /pre-sign freshness boundary|kill switch/);
});

test("SELL swap lifecycle end to end; a deadline that has already passed by SUBMIT time (node's own DAA score) is refused DEADLINE_PASSED, never silently broadcast", { skip: SKIP }, async () => {
  const cfg = freshConfig();
  const c = ctx();
  const rpc = mockRpc({}, "1000");
  const genesis = await driveGenesisV6(cfg, c, rpc);
  const manifest = await loadManifestV6(cfg, genesis.vaultId);

  const posState = { ownerIdentifier: manifest.live.covenantId, identifierType: assets.kcc20.OWNER_SCHEMES.COVENANT_ID, amount: 5000n, isMinter: false };
  const posProgram = compileKcc20Program({ config: cfg, state: posState, familyBound: c.ref.familyBound });
  const tokenPosition = { outpoint: { transactionId: H(0x02), index: 0 }, value: (2n * KAS).toString(), scriptPublicKeyHex: posProgram.p2shSpkHex, covenantId: c.tokenCovenantId, state: { ownerIdentifier: posState.ownerIdentifier, identifierType: posState.identifierType, amount: "5000", isMinter: false } };
  const noteState = { ownerIdentifier: c.poolCovenantId, identifierType: assets.kcc20.OWNER_SCHEMES.COVENANT_ID, amount: BigInt(c.poolState.tokenReserve), isMinter: false };
  const noteProgram = compileKcc20Program({ config: cfg, state: noteState, familyBound: c.ref.familyBound });
  const poolNote = { outpoint: { transactionId: H(0x08), index: 0 }, value: (2n * KAS).toString(), scriptPublicKeyHex: noteProgram.p2shSpkHex, covenantId: c.tokenCovenantId, state: { ownerIdentifier: noteState.ownerIdentifier, identifierType: noteState.identifierType, amount: c.poolState.tokenReserve, isMinter: false } };
  const pool = { outpoint: { transactionId: H(0x09), index: 0 }, value: c.poolState.kasReserve, scriptPublicKeyHex: c.pool0.p2shSpkHex, covenantId: c.poolCovenantId, state: c.poolState };

  /* ---- deadline already stale at SUBMIT time ---- */
  const staleReq = await wr6.buildWalletRequestV6({
    config: cfg, vaultId: genesis.vaultId, action: "tokenAtomicSell", signerAddress: ADDR(c.agent),
    params: { agents: [agentPolicyOnly(c.agentPolicy)], swapPolicies: [c.swapPolicy], swapPolicy: c.swapPolicy, venueProfile: c.venueProfile, deadlineDaa: "1001", amountIn: "500", minKasOut: "1", tokenPosition, poolNote, pool }
  });
  const staleSigned = signAll(staleReq.transaction.unsignedSafeJson, [[0, c.agent]]);
  await wr6.submitSignatureV6({ config: cfg, requestId: staleReq.requestId, signedSafeJson: staleSigned });
  const staleRpc = mockRpc({}, "5000"); // node's current DAA far past the deadline
  await assert.rejects(() => wr6.submitWalletRequestV6({ config: cfg, requestId: staleReq.requestId, rpc: staleRpc }), (e) => { assert.equal(e.code, "DEADLINE_PASSED"); return true; });
  const staleAfter = await wr6.loadWalletRequestV6(cfg, staleReq.requestId);
  assert.equal(staleAfter.state, "DEADLINE_PASSED");

  /* ---- well-formed SELL, fresh deadline ---- */
  const sellReq = await wr6.buildWalletRequestV6({
    config: cfg, vaultId: genesis.vaultId, action: "tokenAtomicSell", signerAddress: ADDR(c.agent),
    params: { agents: [agentPolicyOnly(c.agentPolicy)], swapPolicies: [c.swapPolicy], swapPolicy: c.swapPolicy, venueProfile: c.venueProfile, deadlineDaa: "99999999", amountIn: "500", minKasOut: "1", tokenPosition, poolNote, pool }
  });
  assert.equal(sellReq.accounting.token.amountIn, "500");
  const sellSigned = signAll(sellReq.transaction.unsignedSafeJson, [[0, c.agent]]);
  await wr6.submitSignatureV6({ config: cfg, requestId: sellReq.requestId, signedSafeJson: sellSigned });
  const succIdx = sellReq.build.frozen.outputs.findIndex((o) => o.covenant && o.covenant.covenantId === sellReq.build.covenantId);
  const succAddr = spkAddress(cfg, sellReq.build.frozen.outputs[succIdx].scriptPublicKey);
  rpc.seed(succAddr, utxo(succAddr, sellReq.txId, succIdx, sellReq.build.frozen.outputs[succIdx].value, sellReq.build.covenantId));
  const sellSubmitted = await wr6.submitWalletRequestV6({ config: cfg, requestId: sellReq.requestId, rpc });
  assert.equal(sellSubmitted.state, "CHAIN_VERIFIED");

  const afterSell = await loadManifestV6(cfg, genesis.vaultId);
  assert.equal(afterSell.live.tokenPosition.state.amount.toString(), "4500");
  const agentEntry = afterSell.agentRegistry.find((e) => e.policy.agentPk === XO(c.agent));
  assert.equal(agentEntry.policy.tokenPeriodSpent.toString(), "500", "SELL advances the token-domain period counter");
});

test("unknown v0.6 action fails closed; forced migration (a foreign-schema vault id on a v6 route) refused CONTRACT_VERSION_MISMATCH", { skip: SKIP }, async () => {
  const cfg = freshConfig();
  const c = ctx();
  const rpc = mockRpc();
  const genesis = await driveGenesisV6(cfg, c, rpc);

  await assert.rejects(
    () => wr6.buildWalletRequestV6({ config: cfg, vaultId: genesis.vaultId, action: "totallyBogusAction", signerAddress: ADDR(c.owner), params: {} }),
    (e) => { assert.equal(e.code, "UNKNOWN_ACTION"); return true; }
  );

  const foreignVaultId = H(0xfb);
  const { getStore, Categories } = require("../src/store");
  await getStore(cfg).write(Categories.VAULT, foreignVaultId, { schema: "policyvault-token-controller-manifest/v5", contractVersion: "policyvault-0.5", vaultId: foreignVaultId, status: "ACTIVE" });
  await assert.rejects(
    () => wr6.buildWalletRequestV6({ config: cfg, vaultId: foreignVaultId, action: "ownerPause", signerAddress: ADDR(c.owner), params: {} }),
    (e) => { assert.equal(e.code, "CONTRACT_VERSION_MISMATCH"); return true; }
  );
});

test("ownerRecover (terminal) with a live token position: token returns to owner, vault becomes read-only", { skip: SKIP }, async () => {
  const cfg = freshConfig();
  const c = ctx();
  const rpc = mockRpc();
  const genesis = await driveGenesisV6(cfg, c, rpc);
  const manifest0 = await loadManifestV6(cfg, genesis.vaultId);

  const posState = { ownerIdentifier: manifest0.live.covenantId, identifierType: assets.kcc20.OWNER_SCHEMES.COVENANT_ID, amount: 300n, isMinter: false };
  const posProgram = compileKcc20Program({ config: cfg, state: posState, familyBound: c.ref.familyBound });
  const recoverReq = await wr6.buildWalletRequestV6({
    config: cfg, vaultId: genesis.vaultId, action: "ownerRecover", signerAddress: ADDR(c.owner),
    params: { fuel: fundingUtxoFor(c.userKey), tokenPosition: { outpoint: { transactionId: H(0x07), index: 0 }, value: (2n * KAS).toString(), scriptPublicKeyHex: posProgram.p2shSpkHex, covenantId: c.tokenCovenantId, state: { ownerIdentifier: posState.ownerIdentifier, identifierType: posState.identifierType, amount: "300", isMinter: false } } }
  });
  assert.equal(recoverReq.accounting.token.recoveredToOwner, "300");
  const signed = signAll(recoverReq.transaction.unsignedSafeJson, [[0, c.owner], [recoverReq.build.frozen.inputs.length - 1, c.userKey]]);
  await wr6.submitSignatureV6({ config: cfg, requestId: recoverReq.requestId, signedSafeJson: signed });
  const submitted = await wr6.submitWalletRequestV6({ config: cfg, requestId: recoverReq.requestId, rpc });
  assert.equal(submitted.state, "CHAIN_VERIFIED");

  const after = await loadManifestV6(cfg, genesis.vaultId);
  assert.equal(after.status, "RECOVERED");
  assert.equal(after.live, null);
  await assert.rejects(
    () => wr6.buildWalletRequestV6({ config: cfg, vaultId: genesis.vaultId, action: "ownerPause", signerAddress: ADDR(c.owner), params: { fuel: fundingUtxoFor(c.userKey) } }),
    (e) => { assert.equal(e.code, "VAULT_TERMINAL"); return true; }
  );
});
