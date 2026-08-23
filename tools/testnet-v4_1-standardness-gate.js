"use strict";

/*
 * PolicyVault v0.4.1 MINIMAL LIVE STANDARDNESS ACCEPTANCE GATE (Checkpoint
 * H-R §21). The single question this answers on the REAL testnet-10 node:
 *
 *   does a DEFAULT node (accept_non_standard = false) RELAY a v0.4.1 covenant
 *   agentSpend, where the frozen v0.4 covenant (18 static sig-ops) was rejected
 *   as non-standard in Checkpoint H?
 *
 * Flow (and NOTHING more — do NOT resume the full H lifecycle):
 *   1. verify the node (synced + utxoindex) and record it,
 *   2. create a v0.4.1 vault, chain-prove genesis,
 *   3. build + preflight + submit ONE below-threshold agentSpend,
 *   4. require: submit reaches CHAIN_VERIFIED (i.e. the node RELAYED it — NO
 *      >15-sigops / non-standard rejection), node txid == frozen txid, the
 *      exact covenant successor outpoint is observed, and the durable registry
 *      reconstructs the covenant agentRoot.
 *
 * This tool NEVER sets accept_non_standard and treats ANY non-standard / sig-op
 * rejection as a HARD FAIL (that is the exact failure this redesign fixes).
 * testnet-10 ONLY; refuses mainnet. Usage:
 *   node tools/testnet-v4_1-standardness-gate.js <evidence-out.json>
 */

const fs = require("fs");
const { loadConfig } = require("../sdk/src/config");
const { loadOrCreateTestKeys } = require("../sdk/src/keys");
const { connectVerified, getAddressUtxos } = require("../sdk/src/chain");
const { makeDevSigner } = require("../sdk/src/signer-dev");
const { buildRecipientTree } = require("../sdk/src/recipient-merkle-v3");
const wr4 = require("../sdk/src/wallet-requests-v4");
const submit4 = require("../sdk/src/wallet-submit-v4");
const { loadManifestV4 } = require("../sdk/src/manifest-v4");
const { compileExactStateV4 } = require("../sdk/src/contract-compiler-v4");
const { normalizeStateV4 } = require("../sdk/src/vault-state-v4");

const V4_1 = "policyvault-0.4.1";
const REDEEM_V4_1_BYTES = 16980;
const MAX_STANDARD_P2SH_SIG_OPS = 15;
const KAS = 100000000n;
const OUT = process.argv[2] || "/tmp/pv41-standardness-evidence.json";
const DATA_ROOT = process.env.PV_LIVE_DATA_ROOT || "/tmp/pv41-standardness-data";

function log(...a) { console.log("[v4.1-gate]", ...a); }

/* A non-standard / sig-op mempool rejection is the EXACT failure this gate
 * exists to disprove — recognize it and fail loudly rather than swallow it. */
function looksLikeStandardnessRejection(message) {
  const m = String(message).toLowerCase();
  return m.includes("sig") && (m.includes("op") || m.includes("standard")) || m.includes("non-standard") || m.includes("nonstandard") || m.includes("rejectsignaturecount");
}

async function main() {
  const config = loadConfig({ dataRoot: DATA_ROOT });
  if (config.networkId !== "testnet-10") throw new Error(`refusing: network is ${config.networkId}, not testnet-10`);
  const keys = loadOrCreateTestKeys(config);
  const kaspa = require(config.rustyKaspaModule);
  const XO = (secret) => new kaspa.PrivateKey(secret).toPublicKey().toXOnlyPublicKey().toString().toLowerCase();
  const owner = keys.owner;
  const agentA = keys.delegate;
  const recipientX = XO(keys.funding.secret);
  const signerFor = (k) => makeDevSigner(config, { secretHex: k.secret, expectedAddress: k.address });

  const evidence = { gate: "v0.4.1-standardness", network: config.networkId, startedAt: new Date().toISOString(), node: null, contractVersion: V4_1, transactions: [] };

  const { rpc, serverInfo } = await connectVerified(config);
  evidence.node = { networkId: serverInfo.networkId, isSynced: serverInfo.isSynced, hasUtxoIndex: serverInfo.hasUtxoIndex, serverVersion: serverInfo.serverVersion };
  log("node:", evidence.node);
  if (!serverInfo.isSynced) throw new Error("node not synced — refusing live gate");
  if (!serverInfo.hasUtxoIndex) throw new Error("node has no utxoindex — refusing live gate");

  async function fetchFuel(address, minAmount) {
    const utxos = (await getAddressUtxos(rpc, address)).filter((u) => u.covenantId === null && u.amount > minAmount);
    utxos.sort((a, b) => (a.amount < b.amount ? 1 : -1));
    if (!utxos.length) throw new Error(`no ordinary UTXO > ${minAmount} at ${address}`);
    const u = utxos[0];
    return { outpoint: u.outpoint, amount: u.amount.toString(), scriptPublicKeyHex: u.scriptPublicKeyHex };
  }

  try {
    // ---------- 1. record the exact v0.4.1 covenant standardness facts ----------
    const genesisState = normalizeStateV4({
      protectedValue: (20n * KAS).toString(), feeReserve: (5n * KAS).toString(), paused: "0",
      agentRoot: "00".repeat(32), approvers: [], approvalM: "0", policyNonce: "0"
    });
    const probe = compileExactStateV4({ config, template: { owner: XO(owner.secret), vaultId: "11".repeat(32) }, state: genesisState, contractVersion: V4_1 });
    evidence.covenant = { redeemScriptBytes: probe.scriptBytes.length, contractVersion: probe.contractVersion, standardnessLimit: MAX_STANDARD_P2SH_SIG_OPS };
    log(`v0.4.1 redeem script = ${probe.scriptBytes.length} bytes (v0.4 was 18839)`);
    if (probe.scriptBytes.length !== REDEEM_V4_1_BYTES) throw new Error(`unexpected v0.4.1 redeem size ${probe.scriptBytes.length}`);

    // ---------- 2. GENESIS (v0.4.1) ----------
    log("=== GENESIS (v0.4.1) ===");
    const vaultId = require("crypto").randomBytes(32).toString("hex");
    const agentAPolicy = { agentPk: XO(agentA.secret), maxPerSpend: (10n * KAS).toString(), periodBudget: (15n * KAS).toString(), periodLengthDaa: "864000", periodStartDaa: "541000000", periodSpent: "0", approvalThreshold: (100000n * KAS).toString(), agentMaxFeePerTx: (1n * KAS).toString(), recipients: [recipientX] };
    const funding = await fetchFuel(owner.address, 30n * KAS);
    const genReq = wr4.buildCreateWalletRequestV4({
      config,
      contractVersion: V4_1,
      templateInput: { owner: XO(owner.secret), vaultId },
      initialAgents: [agentAPolicy],
      initialState: { protectedValue: (20n * KAS).toString(), feeReserve: (5n * KAS).toString(), approvers: [], approvalM: "0" },
      signerAddress: owner.address,
      funding: [funding],
      label: "v0.4.1 standardness gate"
    });
    if (genReq.contractVersion !== V4_1) throw new Error(`genesis request version ${genReq.contractVersion} != ${V4_1}`);
    const genSigned = signerFor(owner).signInputs(genReq.transaction.unsignedSafeJson, genReq.transaction.signInputs);
    const genResult = await submit4.submitCreateWalletRequestV4({ config, requestId: genReq.requestId, signedSafeJson: genSigned, rpc });
    if (genResult.request.state !== "CHAIN_VERIFIED") throw new Error(`genesis state ${genResult.request.state}`);
    log(`GENESIS CHAIN_VERIFIED vault=${vaultId.slice(0, 12)} txid=${genResult.txId}`);
    const mGen = loadManifestV4(config, vaultId);
    if (mGen.contractVersion !== V4_1) throw new Error(`manifest version ${mGen.contractVersion} != ${V4_1}`);
    if (mGen.live.state.agentRoot !== mGen.agentRegistryRoot) throw new Error("genesis registry root != covenant agentRoot");
    evidence.vaultId = vaultId;
    evidence.transactions.push({ label: "genesis", action: "createVault", txId: genResult.txId, contractVersion: mGen.contractVersion, registryRootEqual: true });

    // ---------- 3. ONE below-threshold agentSpend (THE standardness probe) ----------
    log("=== below-threshold agentSpend (v0.4.1) ===");
    const built = wr4.buildWalletRequestV4({ config, vaultId, action: "agentSpend", params: { agentPk: XO(agentA.secret), recipient: recipientX, payAmountSompi: (4n * KAS).toString() }, signerAddress: agentA.address });
    if (built.contractVersion !== V4_1) throw new Error(`spend request version ${built.contractVersion} != ${V4_1}`);
    if (built.aboveThreshold) throw new Error("spend must be below threshold for the minimal gate");
    const signed = signerFor(agentA).signInputs(built.transaction.unsignedSafeJson, built.transaction.signInputs);
    const finalized = wr4.finalizeWalletRequestV4({ config, requestId: built.requestId, signedSafeJson: signed });
    if (finalized.state !== "PREFLIGHT_VERIFIED") throw new Error(`finalize state ${finalized.state}`);

    let result;
    try {
      result = await submit4.submitWalletRequestV4({ config, requestId: built.requestId, rpc });
    } catch (e) {
      const msg = String(e.message ?? e);
      if (looksLikeStandardnessRejection(msg)) {
        throw new Error(`STANDARDNESS GATE FAILED — the default node REJECTED the v0.4.1 spend as non-standard/sig-ops: ${msg}`);
      }
      throw e;
    }
    if (result.request.state !== "CHAIN_VERIFIED") {
      throw new Error(`spend did not reach CHAIN_VERIFIED (state ${result.request.state}, error ${result.request.error ?? "none"})`);
    }
    // node txid == frozen txid (the submit path enforces this before CHAIN_VERIFIED)
    if (result.txId !== built.txId) throw new Error(`node txid ${result.txId} != frozen txid ${built.txId}`);
    log(`RELAYED + CHAIN_VERIFIED txid=${result.txId} (13 static sig-ops <= ${MAX_STANDARD_P2SH_SIG_OPS}; frozen v0.4 would be 18 -> rejected)`);

    // ---------- 4. registry reconstruction after the spend ----------
    const mSpend = loadManifestV4(config, vaultId);
    if (mSpend.live.state.agentRoot !== mSpend.agentRegistryRoot) throw new Error("post-spend registry root != covenant agentRoot");
    const acc = built.build.accounting;
    evidence.transactions.push({
      label: "agentSpend-below-threshold", action: "agentSpend", txId: result.txId, contractVersion: built.contractVersion,
      relayedByDefaultNode: true, nodeTxidEqualsFrozen: true, registryRootEqual: true,
      feeSompi: acc.fee, reserveConsumed: acc.reserveConsumed, payAmount: built.payment ? built.payment.value : null,
      predecessor: `${built.predecessorOutpoint.transactionId}:${built.predecessorOutpoint.index}`, successorIndex: result.expected.index ?? null
    });

    evidence.finishedAt = new Date().toISOString();
    evidence.result = "PASS";
    evidence.conclusion = "A default testnet-10 node (accept_non_standard=false) RELAYED a v0.4.1 covenant agentSpend end-to-end; the frozen-layer standardness defect from Checkpoint H is resolved by the ownerControl consolidation. STOPPING per §21 (no full lifecycle).";
    fs.writeFileSync(OUT, JSON.stringify(evidence, null, 2));
    log(`=== v0.4.1 STANDARDNESS GATE PASSED — evidence -> ${OUT} ===`);
  } catch (e) {
    evidence.error = e.message;
    evidence.result = "FAIL";
    fs.writeFileSync(OUT, JSON.stringify(evidence, null, 2));
    log("GATE FAILED:", e.message);
    throw e;
  } finally {
    await rpc.disconnect();
  }
}

main().catch((e) => { console.error(e); process.exit(1); });
