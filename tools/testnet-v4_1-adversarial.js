"use strict";

/*
 * PolicyVault v0.4.1 LIVE direct-to-node adversarial validation (Checkpoint H2
 * §23). Authorized testnet negative-validation transactions constructed
 * independently of the PolicyVault application, verifying that consensus rejects
 * policy-invalid transactions even when correctly signed by the designated
 * delegate. Uses ONLY a project-controlled v0.4.1 testnet vault.
 *
 * Two layers are exercised and the exact failure point recorded:
 *   (a) application/builder guards — the SDK refuses to even build an
 *       out-of-policy intent (fails at BUILDER);
 *   (b) direct-to-node — a VALID below-threshold spend's covenant call is
 *       RE-ENCODED with a tampered policy claim (agent's own delegate signature
 *       reused unchanged, because SIG_HASH_ALL commits the outputs/inputs but
 *       NOT the call args), spliced into the frozen tx, and broadcast to the
 *       real node. The covenant VM rejects it => CONSENSUS rejection.
 *
 * A transport/timeout error is NEVER classified as a consensus rejection.
 * testnet-10 ONLY. Usage: node tools/testnet-v4_1-adversarial.js [out.json]
 */

const fs = require("fs");
const path = require("path");
const { loadConfig } = require("../sdk/src/config");
const { loadOrCreateTestKeys } = require("../sdk/src/keys");
const { connectVerified, getAddressUtxos } = require("../sdk/src/chain");
const { makeDevSigner } = require("../sdk/src/signer-dev");
const { frozenToWasmTransaction } = require("../sdk/src/frozen-tx-v3");
const wr4 = require("../sdk/src/wallet-requests-v4");
const submit4 = require("../sdk/src/wallet-submit-v4");
const vb4 = require("../sdk/src/vault-builders-v4");
const { covenantSigscript } = require("../sdk/src/spend-vault");

const V4_1 = "policyvault-0.4.1";
const KAS = 100000000n;
const OUT = process.argv[2] || "/tmp/pv41-adversarial-evidence.json";
const DATA_ROOT = process.env.PV_LIVE_DATA_ROOT || "/tmp/pv41-adv-data";
const log = (...a) => console.log("[v4.1-adv]", ...a);
function assert(c, m) { if (!c) throw new Error("ASSERT FAILED: " + m); }
const placeholderBlob = () => ("00".repeat(64) + "01").repeat(10); // 10 × 65-byte placeholders

// Is this a genuine node/consensus rejection (not transport ambiguity)?
function isConsensusRejection(msg) { return /Rejected transaction /i.test(String(msg)); }
function isTransport(msg) { const m = String(msg).toLowerCase(); return m.includes("not connected") || m.includes("timeout") || m.includes("timed out") || m.includes("econnrefused") || m.includes("socket"); }

async function main() {
  const config = loadConfig({ dataRoot: DATA_ROOT });
  if (config.networkId !== "testnet-10") throw new Error(`refusing: ${config.networkId}`);
  const keys = loadOrCreateTestKeys(config);
  const kaspa = require(config.rustyKaspaModule);
  const XO = (s) => new kaspa.PrivateKey(s).toPublicKey().toXOnlyPublicKey().toString().toLowerCase();
  const owner = keys.owner, agentA = keys.delegate, recipientX = XO(keys.funding.secret);
  const signerFor = (k) => makeDevSigner(config, { secretHex: k.secret, expectedAddress: k.address });
  const evidence = { gate: "v0.4.1-adversarial", network: config.networkId, startedAt: new Date().toISOString(), attacks: [] };

  const { rpc, serverInfo } = await connectVerified(config);
  if (!serverInfo.isSynced) throw new Error("node not synced");
  evidence.node = { networkId: serverInfo.networkId, serverVersion: serverInfo.serverVersion };

  async function fetchFuel(address, min) {
    const u = (await getAddressUtxos(rpc, address)).filter((x) => x.covenantId === null && x.amount > min).sort((a, b) => (a.amount < b.amount ? 1 : -1));
    if (!u.length) throw new Error(`no ordinary UTXO > ${min} at ${address}`);
    return { outpoint: u[0].outpoint, amount: u[0].amount.toString(), scriptPublicKeyHex: u[0].scriptPublicKeyHex };
  }

  // Submit a tx whose ONLY change from a valid finalized spend is a tampered
  // covenant call (same delegate signature). Returns { rejectedBy, message }.
  async function directToNode(built, tamper) {
    const build = built.build;
    // The agent's real covenant signature over input 0 (unchanged by the tamper).
    const covSig = kaspa.createInputSignature(frozenToWasmTransaction(config, build.frozen), 0, new kaspa.PrivateKey(agentA.secret)).slice(2);
    const call = { function: "agentSpend", signature: covSig, successor: vb4.successorCallJsonV4(build.successorState), approvals: placeholderBlob(), ...build.callExtra };
    tamper(call); // e.g. claim a bigger maxPerSpend, or forge the successor root
    const sourcePath = path.join(build.encoderBuildDir, "PolicyVault.state.sil");
    const constructorArgsPath = path.join(build.encoderBuildDir, "constructor-args.json");
    const callHex = vb4.runEncoderV4({ sourcePath, constructorArgsPath, call, contractVersion: V4_1 });
    const artifact = JSON.parse(fs.readFileSync(path.join(build.encoderBuildDir, "artifact.json")));
    const sigScript = covenantSigscript(callHex, Buffer.from(artifact.script));
    // Clone the finalized tx, replace ONLY input 0's signature script.
    const finalTx = JSON.parse(JSON.stringify(built.finalTransaction ?? built.request?.finalTransaction ?? built._finalTx));
    finalTx.inputs[0].signatureScript = Buffer.from(sigScript).toString("hex");
    const wasmTx = submit4.finalTxToWasm(config, finalTx);
    try {
      await rpc.submitTransaction({ transaction: wasmTx, allowOrphan: false });
      return { rejectedBy: "NONE-ACCEPTED", message: "node ACCEPTED a policy-invalid tx (SECURITY FAILURE)" };
    } catch (e) {
      const msg = String(e.message ?? e).split("\n").slice(0, 2).join(" ");
      if (isTransport(msg)) return { rejectedBy: "TRANSPORT-AMBIGUOUS", message: msg };
      if (isConsensusRejection(msg)) return { rejectedBy: "CONSENSUS", message: msg };
      return { rejectedBy: "OTHER", message: msg };
    }
  }

  try {
    // ---------- genesis: a controlled v0.4.1 vault ----------
    const vaultId = require("crypto").randomBytes(32).toString("hex");
    const pol = { agentPk: XO(agentA.secret), maxPerSpend: (10n * KAS).toString(), periodBudget: (100n * KAS).toString(), periodLengthDaa: "864000", periodStartDaa: "541000000", periodSpent: "0", approvalThreshold: (100000n * KAS).toString(), agentMaxFeePerTx: (1n * KAS).toString(), recipients: [recipientX] };
    const genReq = wr4.buildCreateWalletRequestV4({ config, contractVersion: V4_1, templateInput: { owner: XO(owner.secret), vaultId }, initialAgents: [pol], initialState: { protectedValue: (40n * KAS).toString(), feeReserve: (5n * KAS).toString(), approvers: [], approvalM: "0" }, signerAddress: owner.address, funding: [await fetchFuel(owner.address, 60n * KAS)], label: "adversarial" });
    const gr = await submit4.submitCreateWalletRequestV4({ config, requestId: genReq.requestId, signedSafeJson: signerFor(owner).signInputs(genReq.transaction.unsignedSafeJson, genReq.transaction.signInputs), rpc });
    assert(gr.request.state === "CHAIN_VERIFIED", "genesis");
    log("genesis CHAIN_VERIFIED", gr.txId.slice(0, 12));
    evidence.vaultId = vaultId;

    // ---------- (a) BUILDER-layer negatives: the SDK refuses out-of-policy ----------
    for (const [label, params] of [
      ["over maxPerSpend (pay 20 > cap 10)", { agentPk: XO(agentA.secret), recipient: recipientX, payAmountSompi: (20n * KAS).toString() }],
      ["unauthorized recipient", { agentPk: XO(agentA.secret), recipient: XO(keys.recipient2.secret), payAmountSompi: (3n * KAS).toString() }]
    ]) {
      let err = null;
      try { wr4.buildWalletRequestV4({ config, vaultId, action: "agentSpend", params, signerAddress: agentA.address }); } catch (e) { err = e; }
      assert(err, `${label} must fail at the builder`);
      log(`(a) builder rejects ${label}: ${err.code || err.message.slice(0, 60)} ✓`);
      evidence.attacks.push({ attack: label, rejectedBy: "BUILDER", code: err.code || null });
    }

    // ---------- (b) DIRECT-TO-NODE: valid spend, tampered covenant call ----------
    // Build+finalize a VALID below-threshold spend (this is the carrier tx).
    const built = wr4.buildWalletRequestV4({ config, vaultId, action: "agentSpend", params: { agentPk: XO(agentA.secret), recipient: recipientX, payAmountSompi: (3n * KAS).toString() }, signerAddress: agentA.address });
    const fin = wr4.finalizeWalletRequestV4({ config, requestId: built.requestId, signedSafeJson: signerFor(agentA).signInputs(built.transaction.unsignedSafeJson, built.transaction.signInputs) });
    assert(fin.state === "PREFLIGHT_VERIFIED", "carrier spend preflight");
    built.finalTransaction = fin.finalTransaction;

    // Attack 1: borrowed cap — claim maxPerSpend = 999999 KAS (the leaf's real
    // cap is 10 KAS, so the claimed leaf is NOT in the agentRoot -> VM rejects).
    const a1 = await directToNode(built, (c) => { c.maxPerSpend = (999999n * KAS).toString(); });
    assert(a1.rejectedBy === "CONSENSUS", `borrowed-cap must be a CONSENSUS rejection, got ${a1.rejectedBy}: ${a1.message}`);
    log(`(b) direct-to-node borrowed-cap: CONSENSUS rejected ✓ (${a1.message.slice(0, 70)})`);
    evidence.attacks.push({ attack: "direct-to-node borrowed maxPerSpend", rejectedBy: a1.rejectedBy, message: a1.message });

    // Attack 2: forged successor agentRoot — claim a successor root not folded
    // from the authenticated leaf.
    const a2 = await directToNode(built, (c) => { c.successor = { ...c.successor, agentRoot: "cc".repeat(32) }; });
    assert(a2.rejectedBy === "CONSENSUS", `forged-root must be a CONSENSUS rejection, got ${a2.rejectedBy}: ${a2.message}`);
    log(`(b) direct-to-node forged-successor-root: CONSENSUS rejected ✓ (${a2.message.slice(0, 70)})`);
    evidence.attacks.push({ attack: "direct-to-node forged successor agentRoot", rejectedBy: a2.rejectedBy, message: a2.message });

    // Attack 3: borrowed fee cap — claim agentMaxFeePerTx huge (leaf not in root).
    const a3 = await directToNode(built, (c) => { c.agentMaxFeePerTx = (999n * KAS).toString(); });
    assert(a3.rejectedBy === "CONSENSUS", `borrowed-fee-cap must be CONSENSUS, got ${a3.rejectedBy}: ${a3.message}`);
    log(`(b) direct-to-node borrowed-fee-cap: CONSENSUS rejected ✓`);
    evidence.attacks.push({ attack: "direct-to-node borrowed agentMaxFeePerTx", rejectedBy: a3.rejectedBy, message: a3.message });

    // Sanity: the UNtampered carrier spend is still valid and relays (the tamper,
    // not the carrier, is what consensus rejects).
    const good = await submit4.submitWalletRequestV4({ config, requestId: built.requestId, rpc });
    assert(good.request.state === "CHAIN_VERIFIED", "the untampered carrier spend must relay + chain-verify");
    log(`(b) control: the untampered carrier spend RELAYED + CHAIN_VERIFIED ${good.txId.slice(0, 12)} ✓`);
    evidence.attacks.push({ attack: "control untampered carrier", rejectedBy: "NONE", chainVerified: good.txId });

    evidence.result = "PASS";
    evidence.finishedAt = new Date().toISOString();
    fs.writeFileSync(OUT, JSON.stringify(evidence, null, 2));
    log(`=== ADVERSARIAL MATRIX PASS (${evidence.attacks.length} attacks) -> ${OUT} ===`);
  } catch (e) {
    evidence.result = "FAIL";
    evidence.error = e.message;
    fs.writeFileSync(OUT, JSON.stringify(evidence, null, 2));
    log("FAILED:", e.message);
    throw e;
  } finally {
    await rpc.disconnect();
  }
}

main().catch((e) => { console.error(e); process.exit(1); });
