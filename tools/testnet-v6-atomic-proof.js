"use strict";

/*
 * LIVE TESTNET-10 ATOMIC-COMPOSABILITY PROOF for the v0.6 CANDIDATE
 * controller (docs/postlaunch/v0.6-architecture-freeze.md §I3; owner
 * directive 2026-09-03 + addendum). Drives the REAL v0.6 SDK (core/assets,
 * token-program-kcc20, swap-pool-fixture-v6, vault-builders-v6,
 * contract-compiler-v6, swap-manifest-v6, the production pv_call_encoder)
 * against a LOCAL, VERIFIED testnet-10 node (connectVerified: network +
 * synced + utxoindex, never assumed). TEST ASSETS ONLY; TEST KEYS ONLY.
 *
 *   1. KCC20 ISSUANCE (user-owned genesis note)            -> family id
 *   2. POOL FIXTURE GENESIS (KAS reserve; NOT a product)   -> pool id
 *   3. POOL RESERVE NOTE (user -> pool covenant id)
 *   4. DESCRIPTOR + VENUE PROFILE + OWNER SWAP POLICIES
 *   5. v0.6 CONTROLLER GENESIS (fee reserve + swap principal, agentRoot, swapRoot)
 *   6. DEPOSIT (user -> controller; v0.5 mechanics)
 *   7. ATOMIC SELL (type A) — manifest VERIFIED -> signed -> broadcast
 *      IMMEDIATELY -> CHAIN_SEEN -> CHAIN_VERIFIED -> VERIFIED_OUTCOME
 *   8. ATOMIC BUY — same ladder
 *   9. LIVE NEGATIVE VALIDATION — authorized testnet negative-validation
 *      transactions constructed independently of the PolicyVault
 *      application (post-finalize mutations / re-encoded calls signed by the
 *      designated delegate), verifying that consensus rejects policy-invalid
 *      transactions even when correctly signed; plus the two freshness
 *      kill switches (spent pool outpoint / spent controller outpoint).
 *  10. OWNER setSwapRoot (selector 4), then RECOVER (reserve + principal +
 *      tokens back to the owner key).
 *
 * Every step is CHAIN-VERIFIED against the node's UTXO index (exact value,
 * script, covenant id); predecessors must be consumed; asset deltas are
 * reconciled from the bytes the SDK built — never from an indexer.
 * Evidence -> docs/testnet-v6-atomic-evidence.json.
 *
 * --dry: exercise the whole build/verify/sign/finalize plumbing against
 * SYNTHETIC chain facts with NO RPC (writes nothing under docs/). Live:
 *   KASPA_NETWORK_ID=testnet-10 KASPA_RPC_URL=ws://127.0.0.1:18210
 */

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const { loadConfig } = require("../sdk/src/config");
const { loadOrCreateTestKeys } = require("../sdk/src/keys");
const { connectVerified, getAddressUtxos, getVirtualDaaScore } = require("../sdk/src/chain");
const assets = require("../core/assets");
const { compileKcc20Program } = require("../sdk/src/token-program-kcc20");
const { buildTokenAgentTreeV6 } = require("../sdk/src/agent-merkle-v6");
const { buildRecipientTree } = require("../sdk/src/recipient-merkle-v3");
const { buildSwapPolicyTreeV6, swapPolicyFromProfileV6, computeSwapVenueProfileHash } = require("../sdk/src/swap-policy-v6");
const { compilePoolFixtureV6, poolFixtureVenueProfile } = require("../sdk/src/swap-pool-fixture-v6");
const { buildV6Transaction, buildCreateV6, finalizeV6Transaction, successorCallJsonV6 } = require("../sdk/src/vault-builders-v6");
const { buildTokenDepositV5, finalizeTokenDepositV5 } = require("../sdk/src/vault-builders-v5");
const { runEncoderV4 } = require("../sdk/src/vault-builders-v4");
const { covenantSigscript } = require("../sdk/src/spend-vault");
const { frozenToWasmTransaction, describeFrozenTx } = require("../sdk/src/frozen-tx-v3");
const { normalizeFrozenTxV3, canonicalFrozenTxJson, feeDescriptorFromFrozen } = require("../core/model/frozen-tx-v3");
const { calculateRequiredFee } = require("../sdk/src/fee-mass");
const { p2pkScriptHex } = require("../sdk/src/approval-package-v4");
const { buildTokenIntentManifest, verifyTokenIntentManifest } = require("../core/intent/token-manifest-v5");
const { buildSwapIntentManifest, verifySwapIntentManifest } = require("../core/intent/swap-manifest-v6");
const { poolSellQuote, poolBuyQuote } = require("../core/model/vault-transitions-v6");

const DRY = process.argv.includes("--dry");
const KAS = 100000000n;
const FAMILY_BOUND = 2;
const DATA_ROOT = process.env.PV_LIVE_DATA_ROOT || (DRY ? fs.mkdtempSync("/tmp/pv6-dry-") : "/tmp/pv6-live-data");
const EVIDENCE_PATH = path.join(__dirname, "..", "docs", "testnet-v6-atomic-evidence.json");
const evidence = { schema: "policyvault-testnet-v6-atomic-evidence/1", network: null, startedAt: new Date().toISOString(), dry: DRY, steps: [] };
function record(step, data) {
  evidence.steps.push({ step, at: new Date().toISOString(), ...data });
  console.log(`[${step}]`, JSON.stringify(data));
}
const sha256File = (p) => crypto.createHash("sha256").update(fs.readFileSync(p)).digest("hex");

/* economics of the live fixture (test assets): pool 500 KAS / 100,000 tokens (0.005 KAS/token), pool fee 30 bps, protocol fee 200 bps */
const POOL_KAS = 500n * KAS;
const POOL_TOKENS = 100000n;
const POOL_FEE_BPS = "30";
const PROTO_FEE_BPS = "200";
const NOTE_CARRY = 1n * KAS;
const RESERVE0 = 2n * KAS;
const PRINCIPAL0 = 100n * KAS;
const SELL_AMOUNT = 2000n;
const BUY_TOKENS = 1000n;

async function main() {
  const config = loadConfig({ dataRoot: DATA_ROOT, ...(DRY ? { networkId: "testnet-10", rpcUrl: "ws://127.0.0.1:18210" } : {}) });
  if (!DRY && config.networkId !== "testnet-10") throw new Error(`refusing: this script is testnet-10 only (configured ${config.networkId})`);
  const kaspa = require(config.rustyKaspaModule);
  const keys = loadOrCreateTestKeys(config);
  const roles = { owner: keys.owner, agent: keys.delegate, user: keys.funding ?? keys.owner, fuel: keys.funding ?? keys.owner };
  for (const [r, k] of Object.entries(roles)) if (!k) throw new Error(`test key role ${r} missing`);
  const PK = (k) => new kaspa.PrivateKey(k.secret);
  const XO = (k) => PK(k).toPublicKey().toXOnlyPublicKey().toString().toLowerCase();
  const recipientKey = new kaspa.PrivateKey("77".repeat(32)); // TEST ONLY (type-B destination)
  const RECIPIENT = recipientKey.toPublicKey().toXOnlyPublicKey().toString().toLowerCase();
  const poolFeeKey = new kaspa.PrivateKey("78".repeat(32)); // TEST ONLY (venue protocol-fee receiver)
  const POOL_FEE_PK = poolFeeKey.toPublicKey().toXOnlyPublicKey().toString().toLowerCase();

  let rpc = null;
  let serverInfo = null;
  if (!DRY) {
    ({ rpc, serverInfo } = await connectVerified(config));
    evidence.network = { networkId: serverInfo.networkId, serverVersion: serverInfo.serverVersion, isSynced: serverInfo.isSynced, hasUtxoIndex: serverInfo.hasUtxoIndex, virtualDaaScore: (await getVirtualDaaScore(rpc)).toString() };
    record("connect", evidence.network);
  } else evidence.network = { networkId: "testnet-10", dry: true };
  const daa = async () => (DRY ? 5_000_000n : await getVirtualDaaScore(rpc));

  /* ---- chain helpers (live) / synthetic facts (dry) ---- */
  let synthetic = 0;
  const syntheticOutpoint = () => ({ transactionId: (++synthetic).toString(16).padStart(2, "0").repeat(32), index: 0 });
  async function plainUtxo(key, minAmount) {
    if (DRY) return { outpoint: syntheticOutpoint(), amount: (2000n * KAS).toString(), scriptPublicKeyHex: `20${XO(key)}ac` };
    const utxos = (await getAddressUtxos(rpc, key.address)).filter((u) => u.covenantId === null && u.amount > minAmount);
    if (!utxos.length) throw new Error(`no plain UTXO > ${minAmount} sompi for ${key.address} — fund the test key first`);
    const u = utxos[0];
    return { outpoint: u.outpoint, amount: u.amount.toString(), scriptPublicKeyHex: u.scriptPublicKeyHex };
  }
  function finalToWasm(cfg, finalTx) {
    const { finalTxToWasm } = require("../sdk/src/wallet-submit-v4");
    return finalTxToWasm(cfg, finalTx);
  }
  const p2shAddress = (spkHex) => (DRY ? `dry:${spkHex.slice(4, 12)}` : kaspa.addressFromScriptPublicKey({ version: 0, script: spkHex }, config.networkId).toString());
  const p2pkAddress = (pk) => (DRY ? `dry:pk:${pk.slice(0, 8)}` : kaspa.addressFromScriptPublicKey({ version: 0, script: p2pkScriptHex(pk) }, config.networkId).toString());
  async function submitAndProve(label, finalTx, expectations) {
    if (DRY) {
      record(label, { dry: true, txId: expectations.txId, inputs: finalTx.inputs.length, outputs: finalTx.outputs.length, status: "DRY" });
      return { txId: expectations.txId };
    }
    const wasm = finalToWasm(config, finalTx);
    const submitted = await rpc.submitTransaction({ transaction: wasm, allowOrphan: false });
    const txId = String(submitted.transactionId).toLowerCase();
    if (txId !== expectations.txId) throw new Error(`${label}: node txid ${txId} != planned ${expectations.txId}`);
    record(`${label}:BROADCAST`, { txId, status: "BROADCAST" });
    const verified = [];
    for (const e of expectations.expect) {
      let found = null;
      for (let i = 0; i < 45 && !found; i++) {
        const utxos = await getAddressUtxos(rpc, e.address);
        found = utxos.find((u) => u.outpoint.transactionId === txId && u.outpoint.index === e.index) || null;
        if (!found) await new Promise((r) => setTimeout(r, 2000));
      }
      if (!found) throw new Error(`${label}: expected output ${txId}:${e.index} at ${e.address} did not appear`);
      if (found.amount.toString() !== e.value) throw new Error(`${label}: output value ${found.amount} != ${e.value}`);
      if (e.covenantId !== undefined && String(found.covenantId ?? "").toLowerCase() !== e.covenantId) throw new Error(`${label}: covenant id ${found.covenantId} != ${e.covenantId}`);
      verified.push({ ...e, blockDaaScore: found.blockDaaScore?.toString?.() ?? null });
    }
    /* predecessors consumed: none of the spent outpoints may remain in the index */
    for (const c of expectations.consumed ?? []) {
      const utxos = await getAddressUtxos(rpc, c.address);
      if (utxos.some((u) => u.outpoint.transactionId === c.transactionId && u.outpoint.index === c.index)) throw new Error(`${label}: predecessor ${c.transactionId}:${c.index} still unspent`);
    }
    record(`${label}:CHAIN_VERIFIED`, { txId, status: "CHAIN_VERIFIED", verified, consumed: expectations.consumed ?? [] });
    return { txId };
  }
  async function expectRejected(label, finalTx, why) {
    if (DRY) { record(label, { dry: true, expectRejected: true, why }); return; }
    let rejected = false;
    let detail = null;
    try {
      await rpc.submitTransaction({ transaction: finalToWasm(config, finalTx), allowOrphan: false });
    } catch (e) {
      rejected = true;
      detail = String(e.message ?? e).slice(0, 240);
    }
    if (!rejected) throw new Error(`${label}: the node ACCEPTED a policy-invalid transaction — STOP`);
    record(label, { rejected: true, why, detail });
  }
  const signInput = (frozen, idx, key) => kaspa.createInputSignature(frozenToWasmTransaction(config, frozen), idx, PK(key));

  /* ---- 1. KCC20 ISSUANCE ---- */
  const SUPPLY = "1000000";
  const userState = { ownerIdentifier: XO(roles.user), identifierType: 0, amount: SUPPLY, isMinter: false };
  const userProgram = compileKcc20Program({ config, state: userState, familyBound: FAMILY_BOUND });
  const issuanceFunding = await plainUtxo(roles.user, 5n * KAS);
  const issuanceValue = 3n * KAS;
  const unboundNote = new kaspa.TransactionOutput(issuanceValue, kaspa.payToScriptHashScript(userProgram.scriptHex));
  const familyId = kaspa.covenantId({ transactionId: issuanceFunding.outpoint.transactionId, index: issuanceFunding.outpoint.index }, [{ index: 0, output: unboundNote }]).toString().toLowerCase();
  const plainGenesis = (funding, outputScriptHex, value, covId, changeKey) => {
    const draft = {
      version: 1,
      inputs: [{ previousOutpoint: funding.outpoint, sequence: 0n, computeBudget: 10, utxo: { amount: BigInt(funding.amount), scriptPublicKey: { version: 0, scriptHex: funding.scriptPublicKeyHex }, covenantId: null, blockDaaScore: 0n } }],
      outputs: [
        { value, scriptPublicKey: { version: 0, scriptHex: outputScriptHex }, covenant: { authorizingInput: 0, covenantId: covId } },
        { value: 1n, scriptPublicKey: { version: 0, scriptHex: p2pkScriptHex(XO(changeKey)) }, covenant: null }
      ],
      lockTime: 0n, subnetworkId: "00".repeat(20), gas: 0n, payload: ""
    };
    const fee = calculateRequiredFee(feeDescriptorFromFrozen(normalizeFrozenTxV3(draft), [66])).minimumRequiredFee;
    draft.outputs[1].value = BigInt(funding.amount) - value - fee;
    const frozen = normalizeFrozenTxV3(draft);
    const json = JSON.parse(canonicalFrozenTxJson(frozen));
    json.inputs[0].signatureScript = signInput(frozen, 0, changeKey);
    return { frozen, json, txId: describeFrozenTx(frozen).txId };
  };
  const issuance = plainGenesis(issuanceFunding, userProgram.p2shSpkHex, issuanceValue, familyId, roles.user);
  await submitAndProve("issuance", issuance.json, { txId: issuance.txId, expect: [{ address: p2shAddress(userProgram.p2shSpkHex), index: 0, value: issuanceValue.toString(), covenantId: familyId }] });

  /* ---- 2. POOL FIXTURE GENESIS ---- */
  const poolParams = (over = {}) => ({ tokenCovenantId: familyId, kcc20: { prefixHex: userProgram.prefixHex, suffixHex: userProgram.suffixHex, templateVmHashBlake2b256: userProgram.templateVmHashBlake2b256 }, protocolFeePk: POOL_FEE_PK, protocolFeeBps: PROTO_FEE_BPS, kasReserve: POOL_KAS.toString(), tokenReserve: POOL_TOKENS.toString(), feeBps: POOL_FEE_BPS, nonce: "0", ...over });
  const pool0 = compilePoolFixtureV6({ config, params: poolParams() });
  const poolFunding = await plainUtxo(roles.user, POOL_KAS + 5n * KAS);
  const unboundPool = new kaspa.TransactionOutput(POOL_KAS, kaspa.payToScriptHashScript(pool0.scriptHex));
  const poolId = kaspa.covenantId({ transactionId: poolFunding.outpoint.transactionId, index: poolFunding.outpoint.index }, [{ index: 0, output: unboundPool }]).toString().toLowerCase();
  const poolGenesis = plainGenesis(poolFunding, pool0.p2shSpkHex, POOL_KAS, poolId, roles.user);
  await submitAndProve("pool-fixture-genesis", poolGenesis.json, { txId: poolGenesis.txId, expect: [{ address: p2shAddress(pool0.p2shSpkHex), index: 0, value: POOL_KAS.toString(), covenantId: poolId }] });
  record("pool-fixture", { poolCovenantId: poolId, fixtureVersion: pool0.fixtureVersion, sourceSha256: pool0.sourceSha256, templateVmHashBlake2b256: pool0.templateVmHashBlake2b256, geometry: pool0.geometry, scriptSha256: pool0.scriptSha256, notAProduct: true });

  /* ---- 3/4. DESCRIPTOR, venue profile, owner swap policies ---- */
  const descriptor = {
    schema: "policyvault-asset-descriptor/1",
    assetId: familyId,
    displayName: "TN10 v0.6 Test Token",
    tokenStandard: "kcc20/1",
    tokenCovenantId: familyId,
    acceptedTransferTemplates: [{ templateVmHashBlake2b256: userProgram.templateVmHashBlake2b256, prefixLen: userProgram.geometry.prefixLen, suffixLen: userProgram.geometry.suffixLen, stateLayout: "kcc20-state/1" }],
    decimalsDisplay: 0,
    issuerPowers: { mint: false, burn: false, freeze: false, blacklist: false, redemptionControl: false, upgradeMigration: false, controllerRotation: false, emergencyControl: false }
  };
  const descriptorHash = assets.computeDescriptorHash(descriptor);
  assets.corroborateTemplate({ descriptor, prefixHex: userProgram.prefixHex, suffixHex: userProgram.suffixHex });
  const template = { owner: XO(roles.owner), vaultId: descriptorHash.slice(0, 64), descriptorHash, tokenCovenantId: familyId, templateVmHash: userProgram.templateVmHashBlake2b256, templatePrefixLen: userProgram.geometry.prefixLen, templateStateLen: userProgram.geometry.stateLen, templateSuffixLen: userProgram.geometry.suffixLen };
  const venueProfile = poolFixtureVenueProfile({ networkId: config.networkId, poolCovenantId: poolId, compiled: pool0, profileId: `tn10-v6-pool-fixture:${poolId.slice(0, 16)}` });
  const profileHash = computeSwapVenueProfileHash(venueProfile);
  /* owner authority: floor 0.004 KAS/token (SELL), ceiling 0.006 KAS/token (BUY), protocol fee cap 1 KAS */
  const ownerA = { maxProtocolFeeKas: (1n * KAS).toString(), sellFloorNum: "400000", sellFloorDen: "1", buyCeilNum: "600000", buyCeilDen: "1", directionMask: "3", destScheme: 0x02 };
  const swapA = swapPolicyFromProfileV6(venueProfile, ownerA);
  const swapB = swapPolicyFromProfileV6(venueProfile, { ...ownerA, directionMask: "1", destScheme: 0x00, destIdentity: RECIPIENT });
  const swapPolicies = [swapA, swapB];
  const swapTree = buildSwapPolicyTreeV6(swapPolicies);
  const rTree = buildRecipientTree([RECIPIENT]);
  const agentPolicy = { agentPk: XO(roles.agent), tokenMaxPerSpend: "5000", tokenPeriodBudget: "10000", periodLengthDaa: "1000000", periodStartDaa: (await daa()).toString(), tokenPeriodSpent: "0", agentMaxFeePerTx: (1n * KAS).toString(), agentMaxCarryKas: (KAS / 4n).toString(), kasMaxPerSwap: (20n * KAS).toString(), kasPeriodBudget: (50n * KAS).toString(), kasPeriodSpent: "0", agentRecipientRoot: rTree.root };
  const tree = buildTokenAgentTreeV6([agentPolicy]);
  record("descriptor+profile+policy", { descriptorHash, familyId, templateVmHash: userProgram.templateVmHashBlake2b256, geometry: userProgram.geometry, venueProfileHash: profileHash, swapRoot: swapTree.root, agentRoot: tree.root, swapPolicies: swapPolicies.map((p) => ({ destScheme: p.destScheme, directionMask: p.directionMask.toString() })) });

  /* ---- 3b. POOL RESERVE NOTE (user -> pool covenant id; v0.5 family mechanics) ---- */
  const reserveFuel = await plainUtxo(roles.user, 2n * KAS);
  const reserveDeposit = buildTokenDepositV5({ config, descriptor, controller: { covenantId: poolId, template }, chain: { userPosition: { outpoint: { transactionId: issuance.txId, index: 0 }, value: issuanceValue.toString(), scriptPublicKeyHex: userProgram.p2shSpkHex, covenantId: familyId, state: userState }, fuel: reserveFuel }, params: { depositAmount: POOL_TOKENS.toString(), depositCarryKasSompi: NOTE_CARRY.toString() }, changeXOnly: XO(roles.user) });
  const reserveFinal = finalizeTokenDepositV5({ build: reserveDeposit, tokenOwnerSignatureHex: signInput(reserveDeposit.frozen, 0, roles.user).slice(2), fuelSignatureScriptHex: signInput(reserveDeposit.frozen, 1, roles.user) }).finalTransaction;
  const reserveNoteState = { ownerIdentifier: poolId, identifierType: 2, amount: POOL_TOKENS.toString(), isMinter: false };
  const reserveNoteProgram = compileKcc20Program({ config, state: reserveNoteState, familyBound: FAMILY_BOUND });
  const userRemainderState = { ...userState, amount: (BigInt(SUPPLY) - POOL_TOKENS).toString() };
  const userRemainderProgram = compileKcc20Program({ config, state: userRemainderState, familyBound: FAMILY_BOUND });
  await submitAndProve("pool-reserve-note", reserveFinal, { txId: reserveDeposit.txId, expect: [{ address: p2shAddress(reserveNoteProgram.p2shSpkHex), index: 0, value: NOTE_CARRY.toString(), covenantId: familyId }, { address: p2shAddress(userRemainderProgram.p2shSpkHex), index: 1, value: reserveDeposit.accounting.kas.remainderCarryKas, covenantId: familyId }] });

  /* ---- 5. v0.6 CONTROLLER GENESIS ---- */
  const state0 = { feeReserve: RESERVE0.toString(), swapPrincipal: PRINCIPAL0.toString(), paused: "0", agentRoot: tree.root, swapRoot: swapTree.root, policyNonce: "0" };
  const genesisFunding = await plainUtxo(roles.user, RESERVE0 + PRINCIPAL0 + 2n * KAS);
  const genesis = buildCreateV6({ config, templateInput: template, initialStateInput: state0, funding: [genesisFunding], changeXOnly: XO(roles.user), descriptor });
  const genesisJson = JSON.parse(genesis.frozenCanonicalJson);
  genesisJson.inputs[0].signatureScript = signInput(genesis.frozen, 0, roles.user);
  const controllerId = genesis.covenantId;
  await submitAndProve("controller-genesis", genesisJson, { txId: genesis.txId, expect: [{ address: p2shAddress(genesis.frozen.outputs[0].scriptPublicKey.scriptHex), index: 0, value: (RESERVE0 + PRINCIPAL0).toString(), covenantId: controllerId }] });
  record("controller", { covenantId: controllerId, stateId: genesis.stateId, scriptSha256: genesis.scriptSha256, contractVersion: genesis.contractVersion });

  /* ---- 6. DEPOSIT (user remainder -> controller) ---- */
  const depositFuel = await plainUtxo(roles.user, 2n * KAS);
  const DEPOSIT = 10000n;
  const deposit = buildTokenDepositV5({ config, descriptor, controller: { covenantId: controllerId, template }, chain: { userPosition: { outpoint: { transactionId: reserveDeposit.txId, index: 1 }, value: reserveDeposit.accounting.kas.remainderCarryKas, scriptPublicKeyHex: userRemainderProgram.p2shSpkHex, covenantId: familyId, state: userRemainderState }, fuel: depositFuel }, params: { depositAmount: DEPOSIT.toString(), depositCarryKasSompi: NOTE_CARRY.toString() }, changeXOnly: XO(roles.user) });
  const depManifest = buildTokenIntentManifest({ build: deposit, descriptor });
  if (verifyTokenIntentManifest({ manifest: depManifest, descriptor }).verdict !== "VERIFIED") throw new Error("deposit manifest did not verify locally");
  const depositFinal = finalizeTokenDepositV5({ build: deposit, tokenOwnerSignatureHex: signInput(deposit.frozen, 0, roles.user).slice(2), fuelSignatureScriptHex: signInput(deposit.frozen, 1, roles.user) }).finalTransaction;
  const positionState = { ownerIdentifier: controllerId, identifierType: 2, amount: DEPOSIT.toString(), isMinter: false };
  const positionProgram = compileKcc20Program({ config, state: positionState, familyBound: FAMILY_BOUND });
  await submitAndProve("deposit", depositFinal, { txId: deposit.txId, expect: [{ address: p2shAddress(positionProgram.p2shSpkHex), index: 0, value: NOTE_CARRY.toString(), covenantId: familyId }] });

  /* ---- shared swap plumbing ---- */
  let ctrl = { outpoint: { transactionId: genesis.txId, index: 0 }, state: state0 };
  let position = { outpoint: { transactionId: deposit.txId, index: 0 }, value: NOTE_CARRY.toString(), state: positionState, program: positionProgram };
  let poolNote = { outpoint: { transactionId: reserveDeposit.txId, index: 0 }, value: NOTE_CARRY.toString(), state: reserveNoteState, program: reserveNoteProgram };
  let pool = { outpoint: { transactionId: poolGenesis.txId, index: 0 }, state: { kasReserve: POOL_KAS.toString(), tokenReserve: POOL_TOKENS.toString(), feeBps: POOL_FEE_BPS, nonce: "0" }, compiled: pool0 };
  let agents = [agentPolicy];
  const swapChain = () => ({
    predecessorOutpoint: ctrl.outpoint,
    covenantId: controllerId,
    predecessorValue: (BigInt(ctrl.state.feeReserve) + BigInt(ctrl.state.swapPrincipal)).toString(),
    tokenPosition: { outpoint: position.outpoint, value: position.value, scriptPublicKeyHex: position.program.p2shSpkHex, covenantId: familyId, state: position.state },
    poolNote: { outpoint: poolNote.outpoint, value: poolNote.value, scriptPublicKeyHex: poolNote.program.p2shSpkHex, covenantId: familyId, state: poolNote.state },
    pool: { outpoint: pool.outpoint, value: pool.state.kasReserve, scriptPublicKeyHex: pool.compiled.p2shSpkHex, covenantId: poolId, state: pool.state }
  });
  async function runSwap(label, action, extra) {
    const now = await daa();
    const deadlineDaa = (now + 2000n).toString();
    const build = buildV6Transaction({ config, templateInput: template, stateInput: ctrl.state, action, params: { agentPk: XO(roles.agent), agents, swapPolicies, swapPolicy: swapA, venueProfile, deadlineDaa, ...extra }, chain: swapChain(), changeXOnly: XO(roles.agent), descriptor });
    const manifest = buildSwapIntentManifest({ build, descriptor, agentPolicy: agents[0] });
    const verdict = verifySwapIntentManifest({ manifest, descriptor, currentDaaScore: now.toString() });
    if (verdict.verdict !== "VERIFIED") throw new Error(`${label}: swap manifest REFUSED locally: ${JSON.stringify(verdict.failures)}`);
    record(`${label}:AUTHORIZED`, { status: "AUTHORIZED", txId: build.txId, manifestHash: manifest.manifestHash, checks: verdict.checks.length, quote: manifest.quote, destination: manifest.destination, economics: manifest.economics, freshness: { poolOutpoint: manifest.freshness.poolOutpoint, controllerOutpoint: manifest.freshness.controllerOutpoint, deadlineDaa }, explanation: manifest.explanation, computeBudget: build.computeBudget, poolComputeBudget: build.poolComputeBudget, storageMass: build.swap.storageMass });
    /* sign -> finalize (deadline re-checked) -> broadcast IMMEDIATELY */
    const signedAt = await daa();
    const finalTx = finalizeV6Transaction({ build, covenantSignatureHex: signInput(build.frozen, 0, roles.agent).slice(2), currentDaaScore: signedAt.toString() }).finalTransaction;
    record(`${label}:SIGNED`, { status: "SIGNED", txId: build.txId, signedAtDaa: signedAt.toString(), deadlineDaa, sighash: "ALL" });
    const succValue = (BigInt(build.successorState.feeReserve) + BigInt(build.successorState.swapPrincipal)).toString();
    const selfAfter = compileKcc20Program({ config, state: { ...position.state, amount: build.accounting.token.positionAfter }, familyBound: FAMILY_BOUND });
    const poolNoteAfter = compileKcc20Program({ config, state: { ...poolNote.state, amount: build.swap.poolNote.amountAfter }, familyBound: FAMILY_BOUND });
    const poolNext = compilePoolFixtureV6({ config, params: poolParams({ ...build.swap.pool.stateAfter }) });
    if (poolNext.scriptSha256 !== build.swap.pool.scriptSha256After) throw new Error("pool successor script mismatch");
    const expect = [
      { address: p2shAddress(build.frozen.outputs[0].scriptPublicKey.scriptHex), index: 0, value: succValue, covenantId: controllerId },
      { address: p2shAddress(selfAfter.p2shSpkHex), index: 1, value: position.value, covenantId: familyId },
      { address: p2shAddress(poolNoteAfter.p2shSpkHex), index: 2, value: poolNote.value, covenantId: familyId },
      { address: p2shAddress(poolNext.p2shSpkHex), index: 3, value: build.swap.pool.stateAfter.kasReserve, covenantId: poolId },
      { address: p2pkAddress(POOL_FEE_PK), index: 4, value: build.swap.quote.protocolFee }
    ];
    const consumed = [
      { address: p2shAddress(swapChain().pool.scriptPublicKeyHex), transactionId: pool.outpoint.transactionId, index: pool.outpoint.index },
      { address: p2shAddress(build.frozen.inputs[0].utxo.scriptPublicKey.scriptHex), transactionId: ctrl.outpoint.transactionId, index: ctrl.outpoint.index }
    ];
    const { txId } = await submitAndProve(label, finalTx, { txId: build.txId, expect, consumed });
    /* VERIFIED_OUTCOME: asset deltas reconciled from the bytes we built (never an indexer) */
    const outcome = {
      status: "VERIFIED_OUTCOME",
      txId,
      direction: build.swap.direction,
      tokenPosition: { before: build.accounting.token.positionBefore, after: build.accounting.token.positionAfter },
      poolNote: { before: build.swap.poolNote.amountBefore, after: build.swap.poolNote.amountAfter },
      swapPrincipal: { before: build.accounting.kas.predecessorSwapPrincipal, after: build.accounting.kas.successorSwapPrincipal, delta: build.accounting.kas.principalDelta },
      feeReserve: { before: build.accounting.kas.predecessorFeeReserve, after: build.accounting.kas.successorFeeReserve, networkFee: build.accounting.kas.fee },
      poolKas: { before: build.accounting.kas.poolKasBefore, after: build.accounting.kas.poolKasAfter },
      protocolFee: build.swap.quote.protocolFee,
      conservation: { token: (BigInt(build.accounting.token.positionBefore) + BigInt(build.swap.poolNote.amountBefore)).toString() === (BigInt(build.accounting.token.positionAfter) + BigInt(build.swap.poolNote.amountAfter)).toString() },
      successorStateId: build.successorStateId
    };
    record(`${label}:VERIFIED_OUTCOME`, outcome);
    /* advance the live model */
    const prevCtrl = ctrl;
    const prevPool = pool;
    ctrl = { outpoint: { transactionId: txId, index: 0 }, state: build.successorState };
    position = { outpoint: { transactionId: txId, index: 1 }, value: position.value, state: { ...position.state, amount: build.accounting.token.positionAfter }, program: selfAfter };
    poolNote = { outpoint: { transactionId: txId, index: 2 }, value: poolNote.value, state: { ...poolNote.state, amount: build.swap.poolNote.amountAfter }, program: poolNoteAfter };
    pool = { outpoint: { transactionId: txId, index: 3 }, state: { ...build.swap.pool.stateAfter }, compiled: poolNext };
    agents = [{ ...agents[0], periodStartDaa: build.callExtra.periodStartDaa, tokenPeriodSpent: (BigInt(agents[0].tokenPeriodSpent) + BigInt(build.accounting.token.amountIn)).toString(), kasPeriodSpent: (BigInt(agents[0].kasPeriodSpent) + BigInt(build.accounting.kas.consideration)).toString() }];
    if (buildTokenAgentTreeV6(agents).root !== ctrl.state.agentRoot) throw new Error(`${label}: local agent registry does not reproduce the successor agentRoot`);
    return { build, finalTx, prevCtrl, prevPool };
  }

  /* snapshot of the PRE-SWAP chain facts: a distinct swap built against them later must be dead (kill switches) */
  const staleChain = swapChain();
  const staleState = ctrl.state;
  const staleAgents = agents;

  /* ---- 7. ATOMIC SELL (type A) ---- */
  const sellQuote = poolSellQuote(pool.state, SELL_AMOUNT, PROTO_FEE_BPS);
  const sell = await runSwap("atomic-sell", "tokenAtomicSell", { amountIn: SELL_AMOUNT.toString(), minKasOut: ((sellQuote.netProceeds * 99n) / 100n).toString() });

  /* ---- 8. ATOMIC BUY ---- */
  const buyQuote = poolBuyQuote(pool.state, BUY_TOKENS, PROTO_FEE_BPS);
  const buy = await runSwap("atomic-buy", "tokenAtomicBuy", { tokensOut: BUY_TOKENS.toString(), maxKasIn: ((buyQuote.kasSpend * 101n) / 100n).toString() });

  /* ---- 9. LIVE NEGATIVE VALIDATION (bounded) ---- */
  {
    /* 9a. freshness kill switches — a DISTINCT, correctly signed swap built against the pre-swap pool
     * outpoint AND pre-swap controller outpoint (both spent by the accepted SELL) must be dead */
    {
      const nowStale = await daa();
      const staleBuild = buildV6Transaction({ config, templateInput: template, stateInput: staleState, action: "tokenAtomicSell", params: { agentPk: XO(roles.agent), agents: staleAgents, swapPolicies, swapPolicy: swapA, venueProfile, deadlineDaa: (nowStale + 2000n).toString(), amountIn: "1500", minKasOut: "1" }, chain: staleChain, changeXOnly: XO(roles.agent), descriptor });
      if (staleBuild.txId === sell.build.txId) throw new Error("stale swap must be a distinct transaction");
      const staleFinal = finalizeV6Transaction({ build: staleBuild, covenantSignatureHex: signInput(staleBuild.frozen, 0, roles.agent).slice(2), currentDaaScore: nowStale.toString() }).finalTransaction;
      await expectRejected("negative-stale-swap-spent-outpoints", staleFinal, `a distinct correctly-signed swap (${staleBuild.txId}) referencing the pre-swap pool outpoint ${staleChain.pool.outpoint.transactionId.slice(0, 16)}:${staleChain.pool.outpoint.index} and controller outpoint ${staleChain.predecessorOutpoint.transactionId.slice(0, 16)}:${staleChain.predecessorOutpoint.index}, both spent by the accepted SELL (transaction-level kill switches)`);
      /* the identical accepted bytes are also dead (already accepted) */
      await expectRejected("negative-accepted-swap-resubmitted", sell.finalTx, "the accepted SELL bytes resubmitted");
    }
    /* 9b. over-cap sell re-encoded through the real encoder, delegate-signed (amountIn 5001 > tokenMaxPerSpend 5000) */
    const now = await daa();
    const honest = buildV6Transaction({ config, templateInput: template, stateInput: ctrl.state, action: "tokenAtomicSell", params: { agentPk: XO(roles.agent), agents, swapPolicies, swapPolicy: swapA, venueProfile, deadlineDaa: (now + 2000n).toString(), amountIn: "1000", minKasOut: "1" }, chain: swapChain(), changeXOnly: XO(roles.agent), descriptor });
    const sig = signInput(honest.frozen, 0, roles.agent).slice(2);
    const call = { function: "tokenAtomicSell", signature: sig, ...honest.callExtra, successor: successorCallJsonV6(honest.successorState) };
    call.amountIn = "5001";
    call.selfNew = { ...call.selfNew, amount: (BigInt(position.state.amount) - 5001n).toString() };
    call.poolNoteNew = { ...call.poolNoteNew, amount: (BigInt(poolNote.state.amount) + 5001n).toString() };
    const callHex = runEncoderV4({ sourcePath: path.join(honest.encoderBuildDir, "PolicyVault.state.sil"), constructorArgsPath: path.join(honest.encoderBuildDir, "constructor-args.json"), call, contractVersion: "policyvault-0.6" });
    const artifact = JSON.parse(fs.readFileSync(path.join(honest.encoderBuildDir, "artifact.json")));
    const overCap = JSON.parse(honest.frozenCanonicalJson);
    overCap.inputs[0].signatureScript = covenantSigscript(callHex, Buffer.from(artifact.script));
    overCap.inputs[1].signatureScript = honest.tokenSignatureScriptHex;
    overCap.inputs[2].signatureScript = honest.poolNoteSignatureScriptHex;
    overCap.inputs[3].signatureScript = honest.poolSignatureScriptHex;
    await expectRejected("negative-over-cap-sell", overCap, "amountIn 5001 above the agent's tokenMaxPerSpend 5000 (re-encoded call, delegate-signed)");
    /* 9c. wrong signer: owner key on the agent path */
    const ownerSigned = finalizeV6Transaction({ build: honest, covenantSignatureHex: signInput(honest.frozen, 0, roles.owner).slice(2), currentDaaScore: now.toString() }).finalTransaction;
    await expectRejected("negative-wrong-signer", ownerSigned, "owner key signing tokenAtomicSell");
    /* 9d. redirected protocol fee output (post-finalize mutation, agent-signed over the ORIGINAL outputs) */
    const honestFinal = finalizeV6Transaction({ build: honest, covenantSignatureHex: sig, currentDaaScore: now.toString() }).finalTransaction;
    const redirected = JSON.parse(JSON.stringify(honestFinal));
    redirected.outputs[4].scriptPublicKey.scriptHex = p2pkScriptHex(XO(roles.agent));
    await expectRejected("negative-protocol-fee-redirected", redirected, "protocol-fee output redirected to the agent key");
    /* 9e. SDK-side deadline refusal (local, never reaches the node) */
    let deadlineRefused = false;
    try { finalizeV6Transaction({ build: honest, covenantSignatureHex: sig, currentDaaScore: (now + 2001n).toString() }); } catch (e) { deadlineRefused = e.code === "DEADLINE_PASSED"; }
    if (!deadlineRefused) throw new Error("finalize must refuse after the pre-sign deadline");
    record("negative-deadline-passed-local", { refusedLocally: true, code: "DEADLINE_PASSED", note: "pre-sign boundary; not a consensus expiry" });
  }

  /* ---- 10. OWNER setSwapRoot (selector 4) + RECOVER ---- */
  const swapRootFuel = await plainUtxo(roles.user, 1n * KAS);
  const setRoot = buildV6Transaction({ config, templateInput: template, stateInput: ctrl.state, action: "ownerSetSwapRoot", params: { newSwapPolicies: [swapA] }, chain: { predecessorOutpoint: ctrl.outpoint, covenantId: controllerId, predecessorValue: (BigInt(ctrl.state.feeReserve) + BigInt(ctrl.state.swapPrincipal)).toString(), fuel: swapRootFuel }, changeXOnly: XO(roles.user), descriptor });
  const setRootFinal = finalizeV6Transaction({ build: setRoot, covenantSignatureHex: signInput(setRoot.frozen, 0, roles.owner).slice(2), fuelSignatureScriptHex: signInput(setRoot.frozen, 1, roles.user) }).finalTransaction;
  await submitAndProve("owner-set-swap-root", setRootFinal, { txId: setRoot.txId, expect: [{ address: p2shAddress(setRoot.frozen.outputs[0].scriptPublicKey.scriptHex), index: 0, value: (BigInt(setRoot.successorState.feeReserve) + BigInt(setRoot.successorState.swapPrincipal)).toString(), covenantId: controllerId }] });
  ctrl = { outpoint: { transactionId: setRoot.txId, index: 0 }, state: setRoot.successorState };
  const recoverFuel = await plainUtxo(roles.user, 1n * KAS);
  const recover = buildV6Transaction({ config, templateInput: template, stateInput: ctrl.state, action: "ownerRecover", params: {}, chain: { predecessorOutpoint: ctrl.outpoint, covenantId: controllerId, predecessorValue: (BigInt(ctrl.state.feeReserve) + BigInt(ctrl.state.swapPrincipal)).toString(), fuel: recoverFuel, tokenPosition: { outpoint: position.outpoint, value: position.value, scriptPublicKeyHex: position.program.p2shSpkHex, covenantId: familyId, state: position.state } }, changeXOnly: XO(roles.user), descriptor });
  const recoverFinal = finalizeV6Transaction({ build: recover, covenantSignatureHex: signInput(recover.frozen, 0, roles.owner).slice(2), fuelSignatureScriptHex: signInput(recover.frozen, 2, roles.user) }).finalTransaction;
  const ownerToken = compileKcc20Program({ config, state: { ownerIdentifier: XO(roles.owner), identifierType: 0, amount: position.state.amount, isMinter: false }, familyBound: FAMILY_BOUND });
  await submitAndProve("owner-recover", recoverFinal, { txId: recover.txId, expect: [
    { address: p2pkAddress(XO(roles.owner)), index: 0, value: (BigInt(ctrl.state.feeReserve) + BigInt(ctrl.state.swapPrincipal)).toString() },
    { address: p2shAddress(ownerToken.p2shSpkHex), index: 1, value: position.value, covenantId: familyId }
  ] });

  evidence.finishedAt = new Date().toISOString();
  evidence.covenant = { v06CandidateSha256: sha256File(path.join(__dirname, "..", "contracts", "PolicyVault.v0.6.sil")), v05FrozenSha256: sha256File(path.join(__dirname, "..", "contracts", "PolicyVault.v0.5.sil")), poolFixtureSha256: pool0.sourceSha256 };
  evidence.summary = { controllerId, familyId, poolId, venueProfileHash: profileHash, sellTxId: sell.build.txId, buyTxId: buy.build.txId, byteFrozen: false, mainnet: false };
  if (!DRY) fs.writeFileSync(EVIDENCE_PATH, JSON.stringify(evidence, null, 2) + "\n");
  console.log(DRY ? "DRY RUN COMPLETE (no chain interaction, no evidence written)" : `LIVE ATOMIC PROOF COMPLETE — evidence ${EVIDENCE_PATH}`);
  if (rpc) await rpc.disconnect();
}

main().catch((e) => {
  console.error("FAILED:", e.message);
  process.exit(1);
});
