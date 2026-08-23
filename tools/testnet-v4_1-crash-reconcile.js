"use strict";

/*
 * PolicyVault v0.4.1 LIVE crash/restart + reconcile matrix (Checkpoint H2 §25 +
 * §32). Uses the test-only PV_TEST_CRASH_AT injection (refuses mainnet) to
 * simulate a process crash at each durable submit boundary of a REAL v0.4.1
 * covenant spend on testnet-10, then proves reconcile-v4 recovers correctly from
 * durable state + chain truth:
 *
 *   AFTER_SUBMITTING  crash BEFORE broadcast  -> tx never sent; predecessor live,
 *                     effect absent -> claim released; NO blind resubmit; vault
 *                     unchanged.
 *   AFTER_SUBMITTED   crash AFTER broadcast    -> the critical ambiguity; tx is on
 *                     chain -> reconcile PROVES the successor and advances the
 *                     manifest EXACTLY once (never resubmits).
 *   AFTER_PROOF       crash after proof/before advance -> reconcile advances once.
 *   AFTER_ADVANCE     crash after advance/before claim release -> idempotent; no
 *                     double transition.
 *   recover+AFTER_SUBMITTED  terminal recovery crash-after-broadcast -> reconcile
 *                     marks RECOVERED; the closed vault cannot reactivate.
 *
 * testnet-10 ONLY. Usage: node tools/testnet-v4_1-crash-reconcile.js [out.json]
 */

const fs = require("fs");
const { loadConfig } = require("../sdk/src/config");
const { loadOrCreateTestKeys } = require("../sdk/src/keys");
const { connectVerified, getAddressUtxos } = require("../sdk/src/chain");
const { makeDevSigner } = require("../sdk/src/signer-dev");
const wr4 = require("../sdk/src/wallet-requests-v4");
const submit4 = require("../sdk/src/wallet-submit-v4");
const { reconcileVaultV4 } = require("../sdk/src/reconcile-v4");
const { loadManifestV4 } = require("../sdk/src/manifest-v4");

const V4_1 = "policyvault-0.4.1";
const KAS = 100000000n;
const OUT = process.argv[2] || "/tmp/pv41-crash-evidence.json";
const DATA_ROOT = process.env.PV_LIVE_DATA_ROOT || "/tmp/pv41-crash-data";
const log = (...a) => console.log("[v4.1-crash]", ...a);

function assert(cond, msg) { if (!cond) throw new Error("ASSERT FAILED: " + msg); }

async function main() {
  const config = loadConfig({ dataRoot: DATA_ROOT });
  if (config.networkId !== "testnet-10") throw new Error(`refusing: ${config.networkId} != testnet-10`);
  const keys = loadOrCreateTestKeys(config);
  const kaspa = require(config.rustyKaspaModule);
  const XO = (s) => new kaspa.PrivateKey(s).toPublicKey().toXOnlyPublicKey().toString().toLowerCase();
  const owner = keys.owner, agentA = keys.delegate, recipientX = XO(keys.funding.secret);
  const signerFor = (k) => makeDevSigner(config, { secretHex: k.secret, expectedAddress: k.address });
  const evidence = { gate: "v0.4.1-crash-reconcile", network: config.networkId, startedAt: new Date().toISOString(), cases: [] };

  const { rpc, serverInfo } = await connectVerified(config);
  evidence.node = { networkId: serverInfo.networkId, isSynced: serverInfo.isSynced, serverVersion: serverInfo.serverVersion };
  if (!serverInfo.isSynced) throw new Error("node not synced");

  async function fetchFuel(address, min) {
    const u = (await getAddressUtxos(rpc, address)).filter((x) => x.covenantId === null && x.amount > min).sort((a, b) => (a.amount < b.amount ? 1 : -1));
    if (!u.length) throw new Error(`no ordinary UTXO > ${min} at ${address}`);
    return { outpoint: u[0].outpoint, amount: u[0].amount.toString(), scriptPublicKeyHex: u[0].scriptPublicKeyHex };
  }

  // Build + finalize a below-threshold agentSpend; return the ready request.
  async function buildFinalizeSpend(vaultId) {
    const built = wr4.buildWalletRequestV4({ config, vaultId, action: "agentSpend", params: { agentPk: XO(agentA.secret), recipient: recipientX, payAmountSompi: (3n * KAS).toString() }, signerAddress: agentA.address });
    assert(built.contractVersion === V4_1, "spend request must be v0.4.1");
    const signed = signerFor(agentA).signInputs(built.transaction.unsignedSafeJson, built.transaction.signInputs);
    const fin = wr4.finalizeWalletRequestV4({ config, requestId: built.requestId, signedSafeJson: signed });
    assert(fin.state === "PREFLIGHT_VERIFIED", `finalize must preflight, got ${fin.state}`);
    return built;
  }

  // Submit with a crash armed at `point`; expect a throw (simulated crash).
  async function crashSubmit(requestId, point) {
    process.env.PV_TEST_CRASH_AT = point;
    let threw = null;
    try { await submit4.submitWalletRequestV4({ config, requestId, rpc }); }
    catch (e) { threw = e; }
    finally { delete process.env.PV_TEST_CRASH_AT; }
    assert(threw, `crash at ${point} must throw`);
    assert(/TEST INJECTION|crash/i.test(String(threw.message)), `throw must be the injected crash, got: ${threw.message}`);
    return threw;
  }

  // Reconcile, tolerating CLAIM_PENDING (tx broadcast but not yet mined/indexed
  // — the CORRECT conservative state): poll until it resolves. Proves reconcile
  // never advances on an unmined tx, and advances exactly once when provable.
  async function pollReconcile(vaultId, opts = {}, attempts = 40, delayMs = 2000) {
    let rec;
    for (let i = 0; i < attempts; i++) {
      rec = await reconcileVaultV4(config, vaultId, { rpc, ...opts });
      if (rec.status !== "CLAIM_PENDING") return rec;
      await new Promise((r) => setTimeout(r, delayMs));
    }
    return rec;
  }
  const liveOutpoint = (vaultId) => { const m = loadManifestV4(config, vaultId); return m.live ? `${m.live.outpoint.transactionId}:${m.live.outpoint.index}` : null; };
  const rootsOk = (vaultId) => { const m = loadManifestV4(config, vaultId); return !m.live || m.live.state.agentRoot === m.agentRegistryRoot; };

  try {
    // ---------- GENESIS ----------
    const vaultId = require("crypto").randomBytes(32).toString("hex");
    const agentAPolicy = { agentPk: XO(agentA.secret), maxPerSpend: (10n * KAS).toString(), periodBudget: (100n * KAS).toString(), periodLengthDaa: "864000", periodStartDaa: "541000000", periodSpent: "0", approvalThreshold: (100000n * KAS).toString(), agentMaxFeePerTx: (1n * KAS).toString(), recipients: [recipientX] };
    const genReq = wr4.buildCreateWalletRequestV4({ config, contractVersion: V4_1, templateInput: { owner: XO(owner.secret), vaultId }, initialAgents: [agentAPolicy], initialState: { protectedValue: (40n * KAS).toString(), feeReserve: (5n * KAS).toString(), approvers: [], approvalM: "0" }, signerAddress: owner.address, funding: [await fetchFuel(owner.address, 60n * KAS)], label: "crash-matrix" });
    const genSigned = signerFor(owner).signInputs(genReq.transaction.unsignedSafeJson, genReq.transaction.signInputs);
    const gr = await submit4.submitCreateWalletRequestV4({ config, requestId: genReq.requestId, signedSafeJson: genSigned, rpc });
    assert(gr.request.state === "CHAIN_VERIFIED", "genesis CHAIN_VERIFIED");
    log("genesis CHAIN_VERIFIED", gr.txId.slice(0, 16), "vault", vaultId.slice(0, 10));
    evidence.vaultId = vaultId;

    // ---------- CASE E: AFTER_SUBMITTING (crash BEFORE broadcast) ----------
    {
      const before = liveOutpoint(vaultId);
      const req = await buildFinalizeSpend(vaultId);
      await crashSubmit(req.requestId, "AFTER_SUBMITTING");
      // tx NEVER broadcast: predecessor live + effect absent. Force the release
      // path (we KNOW it wasn't sent) with stalePendingMinimumMs 0.
      const rec = await reconcileVaultV4(config, vaultId, { rpc, stalePendingMinimumMs: 0 });
      const after = liveOutpoint(vaultId);
      assert(after === before, `AFTER_SUBMITTING: vault must be UNCHANGED (no phantom advance); before=${before} after=${after}`);
      assert(["CLAIM_RELEASED", "CONSISTENT"].includes(rec.status), `AFTER_SUBMITTING reconcile must release/consistent, got ${rec.status}`);
      assert(rootsOk(vaultId), "roots must reconstruct");
      log(`CASE E AFTER_SUBMITTING: reconcile=${rec.status}, vault unchanged, no blind resubmit ✓`);
      evidence.cases.push({ case: "E:AFTER_SUBMITTING", crashBeforeBroadcast: true, reconcile: rec.status, vaultUnchanged: true });
    }

    // ---------- CASE G/F: AFTER_SUBMITTED (crash AFTER broadcast) ----------
    {
      const before = liveOutpoint(vaultId);
      const req = await buildFinalizeSpend(vaultId);
      const expectedTx = req.txId;
      await crashSubmit(req.requestId, "AFTER_SUBMITTED");
      // tx IS on chain now. reconcile must PROVE the successor and advance once.
      const rec = await pollReconcile(vaultId);
      const after = liveOutpoint(vaultId);
      assert(rec.status === "ADVANCED", `AFTER_SUBMITTED reconcile must ADVANCE (no resubmit), got ${rec.status}`);
      assert(rec.txId === expectedTx, `advanced to the EXACT broadcast tx ${expectedTx}, got ${rec.txId}`);
      assert(after && after.startsWith(expectedTx), `live outpoint must be the successor of ${expectedTx}, got ${after}`);
      assert(after !== before, "vault must have advanced");
      assert(rootsOk(vaultId), "roots must reconstruct after advance");
      // idempotent: a second reconcile is a no-op.
      const rec2 = await reconcileVaultV4(config, vaultId, { rpc });
      assert(rec2.status === "CONSISTENT", `reconcile must be idempotent, second run got ${rec2.status}`);
      log(`CASE G AFTER_SUBMITTED: reconcile ADVANCED to ${rec.txId.slice(0, 12)} exactly once; idempotent ✓`);
      evidence.cases.push({ case: "G:AFTER_SUBMITTED", crashAfterBroadcast: true, reconcile: rec.status, advancedTx: rec.txId, idempotentSecond: rec2.status, noResubmit: true });
    }

    // ---------- CASE AFTER_PROOF (crash after proof, before advance) ----------
    {
      const req = await buildFinalizeSpend(vaultId);
      const expectedTx = req.txId;
      await crashSubmit(req.requestId, "AFTER_PROOF");
      const rec = await pollReconcile(vaultId);
      assert(rec.status === "ADVANCED" && rec.txId === expectedTx, `AFTER_PROOF reconcile must advance to ${expectedTx}, got ${rec.status}/${rec.txId}`);
      assert(liveOutpoint(vaultId).startsWith(expectedTx) && rootsOk(vaultId), "advanced to successor + roots ok");
      log(`CASE AFTER_PROOF: reconcile ADVANCED exactly once ✓`);
      evidence.cases.push({ case: "AFTER_PROOF", reconcile: rec.status, advancedTx: rec.txId });
    }

    // ---------- CASE H: AFTER_ADVANCE (crash after advance, before claim release) ----------
    {
      const req = await buildFinalizeSpend(vaultId);
      const expectedTx = req.txId;
      // submit advances the manifest + sets CHAIN_VERIFIED, THEN crashes before
      // releasing claims / persisting the receipt.
      await crashSubmit(req.requestId, "AFTER_ADVANCE");
      const afterCrash = liveOutpoint(vaultId);
      assert(afterCrash.startsWith(expectedTx), `AFTER_ADVANCE: manifest already advanced to ${expectedTx}, got ${afterCrash}`);
      // reconcile must be idempotent — NO double transition.
      const rec = await pollReconcile(vaultId);
      assert(rec.status === "CONSISTENT", `AFTER_ADVANCE reconcile must be idempotent CONSISTENT, got ${rec.status}`);
      assert(liveOutpoint(vaultId) === afterCrash, "no second/double transition");
      assert(rootsOk(vaultId), "roots ok");
      log(`CASE H AFTER_ADVANCE: manifest advanced once; reconcile idempotent; no double transition ✓`);
      evidence.cases.push({ case: "H:AFTER_ADVANCE", advancedBeforeCrash: true, reconcile: rec.status, noDoubleTransition: true });
    }

    // ---------- CASE I: terminal recovery crash-after-broadcast ----------
    {
      const rreq = wr4.buildWalletRequestV4({ config, vaultId, action: "ownerRecover", params: { fuel: await fetchFuel(owner.address, 2n * KAS) }, signerAddress: owner.address });
      assert(rreq.contractVersion === V4_1, "recover request v0.4.1");
      const rsigned = signerFor(owner).signInputs(rreq.transaction.unsignedSafeJson, rreq.transaction.signInputs);
      const rfin = wr4.finalizeWalletRequestV4({ config, requestId: rreq.requestId, signedSafeJson: rsigned });
      assert(rfin.state === "PREFLIGHT_VERIFIED", "recover preflight");
      await crashSubmit(rreq.requestId, "AFTER_SUBMITTED");
      const rec = await pollReconcile(vaultId);
      assert(rec.status === "ADVANCED" && rec.to === "RECOVERED", `recover reconcile must mark RECOVERED, got ${rec.status}/${rec.to}`);
      const m = loadManifestV4(config, vaultId);
      assert(m.status === "RECOVERED" && m.live === null, `vault must be RECOVERED/closed, got ${m.status}`);
      // cannot reactivate: reconcile again is TERMINAL, and a new spend build fails.
      const rec2 = await reconcileVaultV4(config, vaultId, { rpc });
      assert(rec2.status === "TERMINAL", `closed vault reconcile must be TERMINAL, got ${rec2.status}`);
      let reactivated = false;
      try { wr4.buildWalletRequestV4({ config, vaultId, action: "agentSpend", params: { agentPk: XO(agentA.secret), recipient: recipientX, payAmountSompi: (1n * KAS).toString() }, signerAddress: agentA.address }); reactivated = true; } catch { /* expected */ }
      assert(!reactivated, "a closed vault must NOT accept a new spend build");
      log(`CASE I recover crash-after-broadcast: reconcile RECOVERED; closed vault cannot reactivate ✓`);
      evidence.cases.push({ case: "I:recover-AFTER_SUBMITTED", reconcile: rec.status, to: rec.to, terminalSecond: rec2.status, cannotReactivate: true });
    }

    evidence.result = "PASS";
    evidence.finishedAt = new Date().toISOString();
    fs.writeFileSync(OUT, JSON.stringify(evidence, null, 2));
    log(`=== CRASH/RECONCILE MATRIX PASS (${evidence.cases.length} cases) -> ${OUT} ===`);
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
