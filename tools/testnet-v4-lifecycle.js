"use strict";

/*
 * PolicyVault v0.4 LIVE testnet-10 lifecycle (Checkpoint H §H8/§H15/§H16).
 *
 * Drives the REAL server-side v0.4 path against the live kaspad node with
 * REAL broadcasts: genesis -> chain proof -> manifest, then agent spends,
 * multi-agent, approvals, owner lifecycle, reserve/fuel funding, and terminal
 * recovery. Signatures use the deterministic dev signer, which implements the
 * exact `signPskt` contract KasWare uses (proven in Checkpoint G) — the
 * REAL-KasWare manual acceptance path (H7) is a separate human step. Records
 * txids, exact fees, and per-transition agentRoot / registry reconstruction
 * proofs to an evidence JSON.
 *
 * testnet-10 ONLY; refuses mainnet. Usage:
 *   node tools/testnet-v4-lifecycle.js <evidence-out.json>
 */

const fs = require("fs");
const { loadConfig } = require("../sdk/src/config");
const { loadOrCreateTestKeys } = require("../sdk/src/keys");
const { connectVerified, getAddressUtxos } = require("../sdk/src/chain");
const { makeDevSigner } = require("../sdk/src/signer-dev");
const { buildRecipientTree } = require("../sdk/src/recipient-merkle-v3");
const { buildAgentTreeV4, normalizeAgentPolicyV4 } = require("../sdk/src/agent-merkle-v4");
const wr4 = require("../sdk/src/wallet-requests-v4");
const submit4 = require("../sdk/src/wallet-submit-v4");
const { loadManifestV4 } = require("../sdk/src/manifest-v4");

const KAS = 100000000n;
const OUT = process.argv[2] || "/tmp/pv4-live-evidence.json";
const DATA_ROOT = process.env.PV_LIVE_DATA_ROOT || "/tmp/pv4-live-data";

function log(...a) { console.log("[v4-live]", ...a); }

async function main() {
  const config = loadConfig({ dataRoot: DATA_ROOT });
  if (config.networkId !== "testnet-10") throw new Error(`refusing: network is ${config.networkId}, not testnet-10`);
  const keys = loadOrCreateTestKeys(config);
  const kaspa = require(config.rustyKaspaModule);
  const XO = (secret) => new kaspa.PrivateKey(secret).toPublicKey().toXOnlyPublicKey().toString().toLowerCase();
  const ADDR = (secret) => new kaspa.PrivateKey(secret).toPublicKey().toAddress(config.networkId).toString();

  // Roles from the funded test keys.
  const owner = keys.owner;        // vault owner
  const agentA = keys.delegate;    // agent A (funded, provides fuel for fuel-funded)
  const agentB = keys.recipient1;  // agent B
  const approver1 = keys.recipient2;
  const approver2 = keys.recipient3;
  const recipient = keys.funding;  // a payment recipient (any x-only)
  const recipientX = XO(recipient.secret);

  const signerFor = (k) => makeDevSigner(config, { secretHex: k.secret, expectedAddress: k.address });
  const evidence = { network: config.networkId, startedAt: new Date().toISOString(), node: null, transactions: [], rootAudits: [] };

  const { rpc, serverInfo } = await connectVerified(config);
  evidence.node = { networkId: serverInfo.networkId, isSynced: serverInfo.isSynced, hasUtxoIndex: serverInfo.hasUtxoIndex, serverVersion: serverInfo.serverVersion };
  log("node:", evidence.node);

  async function fetchFuel(address, minAmount) {
    const utxos = (await getAddressUtxos(rpc, address)).filter((u) => u.covenantId === null && u.amount > minAmount);
    utxos.sort((a, b) => (a.amount < b.amount ? 1 : -1));
    if (!utxos.length) throw new Error(`no ordinary UTXO > ${minAmount} at ${address}`);
    const u = utxos[0];
    return { outpoint: u.outpoint, amount: u.amount.toString(), scriptPublicKeyHex: u.scriptPublicKeyHex };
  }

  /* Run BUILD -> approvals -> sign -> FINALIZE -> SUBMIT -> CHAIN_VERIFIED and
   * record evidence. */
  async function doAction(label, { vaultId, action, params, signerKey, approverKeys = [] }) {
    log(`--- ${label} (${action}) ---`);
    const built = wr4.buildWalletRequestV4({ config, vaultId, action, params, signerAddress: signerKey.address });
    // approvals if above threshold
    if (built.aboveThreshold) {
      for (const ak of approverKeys) {
        const sJson = signerFor(ak).signInputs(built.transaction.unsignedSafeJson, [{ index: 0 }]);
        const r = wr4.collectApprovalV4({ config, requestId: built.requestId, approverAddress: ak.address, signedSafeJson: sJson });
        log(`  approval ${r.approvals.collected}/${r.approvals.required}`);
      }
    }
    const signed = signerFor(signerKey).signInputs(built.transaction.unsignedSafeJson, built.transaction.signInputs);
    const finalized = wr4.finalizeWalletRequestV4({ config, requestId: built.requestId, signedSafeJson: signed });
    if (finalized.state !== "PREFLIGHT_VERIFIED") throw new Error(`${label}: finalize state ${finalized.state}`);
    const result = await submit4.submitWalletRequestV4({ config, requestId: built.requestId, rpc });
    if (result.request.state !== "CHAIN_VERIFIED") throw new Error(`${label}: submit state ${result.request.state}`);
    const acc = built.build.accounting;
    const rec = { label, action, txId: result.txId, predecessor: `${built.predecessorOutpoint.transactionId}:${built.predecessorOutpoint.index}`, successorIndex: result.expected.index ?? null, feeSompi: acc.fee, reserveConsumed: acc.reserveConsumed, protectedBefore: acc.predecessorProtected, protectedAfter: acc.successorProtected, reserveBefore: acc.predecessorFeeReserve, reserveAfter: acc.successorFeeReserve, payment: built.payment ? built.payment.value : null };
    evidence.transactions.push(rec);
    log(`  CHAIN_VERIFIED txid=${result.txId} fee=${acc.fee} reserveConsumed=${acc.reserveConsumed}`);
    await auditRoots(label, vaultId);
    return { built, result };
  }

  async function auditRoots(label, vaultId) {
    const m = await loadManifestV4(config, vaultId); // loader recomputes + requires root-equality
    const audit = { label, agentRoot: m.live.state.agentRoot, reconstructedRoot: m.agentRegistryRoot, equal: m.live.state.agentRoot === m.agentRegistryRoot, policyNonce: m.live.state.policyNonce.toString(), protected: m.live.state.protectedValue.toString(), reserve: m.live.state.feeReserve.toString(), paused: m.live.state.paused.toString(), agents: m.agentRegistry.map((e) => ({ agentPk: e.policy.agentPk.slice(0, 12), periodSpent: e.policy.periodSpent.toString(), recipientRoot: e.policy.agentRecipientRoot === buildRecipientTree(e.recipients).root })) };
    if (!audit.equal) throw new Error(`${label}: REGISTRY ROOT MISMATCH — covenant ${audit.agentRoot} != reconstructed ${audit.reconstructedRoot}`);
    if (!audit.agents.every((a) => a.recipientRoot)) throw new Error(`${label}: an agent recipient root does not reconstruct`);
    evidence.rootAudits.push(audit);
    log(`  root audit OK (nonce ${audit.policyNonce}, ${audit.agents.length} agents)`);
  }

  try {
    // ---------- GENESIS ----------
    log("=== GENESIS ===");
    const vaultId = require("crypto").randomBytes(32).toString("hex");
    const agentAPolicy = { agentPk: XO(agentA.secret), maxPerSpend: (20n * KAS).toString(), periodBudget: (50n * KAS).toString(), periodLengthDaa: "864000", periodStartDaa: "541000000", periodSpent: "0", approvalThreshold: (5n * KAS).toString(), agentMaxFeePerTx: (1n * KAS).toString(), recipients: [recipientX] };
    const funding = await fetchFuel(owner.address, 200n * KAS);
    const genReq = wr4.buildCreateWalletRequestV4({
      config,
      templateInput: { owner: XO(owner.secret), vaultId },
      initialAgents: [agentAPolicy],
      initialState: { protectedValue: (100n * KAS).toString(), feeReserve: (5n * KAS).toString(), approvers: [XO(approver1.secret), XO(approver2.secret)], approvalM: "2" },
      signerAddress: owner.address,
      funding: [funding],
      label: "H live vault"
    });
    const genSigned = signerFor(owner).signInputs(genReq.transaction.unsignedSafeJson, genReq.transaction.signInputs);
    const genResult = await submit4.submitCreateWalletRequestV4({ config, requestId: genReq.requestId, signedSafeJson: genSigned, rpc });
    if (genResult.request.state !== "CHAIN_VERIFIED") throw new Error(`genesis state ${genResult.request.state}`);
    log(`GENESIS CHAIN_VERIFIED vault=${vaultId.slice(0,12)} txid=${genResult.txId}`);
    evidence.vaultId = vaultId;
    evidence.transactions.push({ label: "genesis", action: "createVault", txId: genResult.txId, protected: (100n * KAS).toString(), reserve: (5n * KAS).toString() });
    await auditRoots("genesis", vaultId);

    // ---------- AGENT A reserve-funded spend (below threshold) ----------
    await doAction("agentA reserve spend #1", { vaultId, action: "agentSpend", params: { agentPk: XO(agentA.secret), recipient: recipientX, payAmountSompi: (4n * KAS).toString() }, signerKey: agentA });
    // ---------- AGENT A second spend (accumulation) ----------
    const { built: spend2 } = await doAction("agentA reserve spend #2", { vaultId, action: "agentSpend", params: { agentPk: XO(agentA.secret), recipient: recipientX, payAmountSompi: (4n * KAS).toString() }, signerKey: agentA });
    const mAfter2 = await loadManifestV4(config, vaultId);
    const aSpent = mAfter2.agentRegistry.find((e) => e.policy.agentPk === XO(agentA.secret)).policy.periodSpent;
    if (aSpent !== 8n * KAS) throw new Error(`accumulation failed: agent A periodSpent=${aSpent}, expected 8 KAS`);
    log(`  accumulation proven: agent A periodSpent = ${aSpent} (8 KAS)`);
    void spend2;

    // ---------- OWNER addAgent B ----------
    const agentBPolicy = { agentPk: XO(agentB.secret), maxPerSpend: (30n * KAS).toString(), periodBudget: (30n * KAS).toString(), periodLengthDaa: "864000", periodStartDaa: "541000000", periodSpent: "0", approvalThreshold: (5n * KAS).toString(), agentMaxFeePerTx: (1n * KAS).toString(), recipients: [recipientX] };
    await doAction("owner addAgent B", { vaultId, action: "addAgent", params: { agent: agentBPolicy, fuel: await fetchFuel(owner.address, 2n * KAS) }, signerKey: owner });
    // ---------- AGENT B spend (independence) ----------
    await doAction("agentB reserve spend", { vaultId, action: "agentSpend", params: { agentPk: XO(agentB.secret), recipient: recipientX, payAmountSompi: (3n * KAS).toString() }, signerKey: agentB });
    const mB = await loadManifestV4(config, vaultId);
    const aSpentAfterB = mB.agentRegistry.find((e) => e.policy.agentPk === XO(agentA.secret)).policy.periodSpent;
    if (aSpentAfterB !== 8n * KAS) throw new Error(`independence failed: agent A periodSpent changed to ${aSpentAfterB}`);
    log(`  independence proven: agent A periodSpent unchanged (${aSpentAfterB}); agent B spent 3 KAS`);

    // ---------- APPROVAL-GATED spend (2-of-2, above threshold) ----------
    await doAction("agentA approval-gated spend", { vaultId, action: "agentSpend", params: { agentPk: XO(agentA.secret), recipient: recipientX, payAmountSompi: (6n * KAS).toString(), fuel: await fetchFuel(agentA.address, 2n * KAS) }, signerKey: agentA, approverKeys: [approver1, approver2] });

    // ---------- FUEL-FUNDED spend (zero reserve consumption) ----------
    await doAction("agentA fuel-funded spend", { vaultId, action: "agentSpend", params: { agentPk: XO(agentA.secret), recipient: recipientX, payAmountSompi: (2n * KAS).toString(), fuel: await fetchFuel(agentA.address, 2n * KAS) }, signerKey: agentA });

    // ---------- OWNER lifecycle: pause / unpause / topUp / topUpReserve / rotate ----------
    await doAction("owner pause", { vaultId, action: "ownerPause", params: { fuel: await fetchFuel(owner.address, 2n * KAS) }, signerKey: owner });
    await doAction("owner unpause", { vaultId, action: "ownerUnpause", params: { fuel: await fetchFuel(owner.address, 2n * KAS) }, signerKey: owner });
    await doAction("owner topUp principal", { vaultId, action: "ownerTopUp", params: { topUpAmountSompi: (10n * KAS).toString(), fuel: await fetchFuel(owner.address, 15n * KAS) }, signerKey: owner });
    await doAction("owner topUp reserve", { vaultId, action: "ownerTopUpReserve", params: { topUpReserveAmountSompi: (2n * KAS).toString(), fuel: await fetchFuel(owner.address, 5n * KAS) }, signerKey: owner });
    const agentBrot = { agentPk: XO(keys.recipient1.secret) === XO(agentB.secret) ? XO(owner.secret) : XO(agentB.secret), ...agentBPolicy };
    // rotate agent B to a new key (use approver1's key as the new B, distinct)
    await doAction("owner rotateAgent B", { vaultId, action: "rotateAgent", params: { agentPk: XO(agentB.secret), agent: { ...agentBPolicy, agentPk: XO(approver1.secret) }, fuel: await fetchFuel(owner.address, 2n * KAS) }, signerKey: owner });
    void agentBrot;

    // ---------- TERMINAL recovery ----------
    await doAction("owner recover (terminal)", { vaultId, action: "ownerRecover", params: { fuel: await fetchFuel(owner.address, 2n * KAS) }, signerKey: owner });
    const mFinal = await loadManifestV4(config, vaultId);
    if (mFinal.status !== "RECOVERED" || mFinal.live !== null) throw new Error(`recover did not close the vault: status=${mFinal.status}`);
    log(`  recovery proven: vault RECOVERED, no successor outpoint`);

    evidence.finishedAt = new Date().toISOString();
    evidence.result = "PASS";
    fs.writeFileSync(OUT, JSON.stringify(evidence, null, 2));
    log(`=== LIFECYCLE COMPLETE — ${evidence.transactions.length} transactions, evidence -> ${OUT} ===`);
  } catch (e) {
    evidence.error = e.message;
    evidence.result = "FAIL";
    fs.writeFileSync(OUT, JSON.stringify(evidence, null, 2));
    log("LIFECYCLE FAILED:", e.message);
    throw e;
  } finally {
    await rpc.disconnect();
  }
}

main().catch((e) => { console.error(e); process.exit(1); });
