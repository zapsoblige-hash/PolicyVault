"use strict";

/*
 * PolicyVault v0.4.1 LIVE concurrency (Checkpoint H2 §26). A vault holds ONE
 * covenant UTXO, so at most one transition can win. This drives real conflicts
 * on testnet-10 and proves exactly one chain winner; every loser fails closed
 * (stale / claim-conflict / reconciliation-required), and no double transition
 * or double broadcast occurs. testnet-10 ONLY.
 *
 * Usage: node tools/testnet-v4_1-concurrency.js [out.json]
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
const OUT = process.argv[2] || "/tmp/pv41-concurrency-evidence.json";
const DATA_ROOT = process.env.PV_LIVE_DATA_ROOT || "/tmp/pv41-conc-data";
const log = (...a) => console.log("[v4.1-conc]", ...a);
function assert(c, m) { if (!c) throw new Error("ASSERT FAILED: " + m); }

async function main() {
  const config = loadConfig({ dataRoot: DATA_ROOT });
  if (config.networkId !== "testnet-10") throw new Error(`refusing: ${config.networkId}`);
  const keys = loadOrCreateTestKeys(config);
  const kaspa = require(config.rustyKaspaModule);
  const XO = (s) => new kaspa.PrivateKey(s).toPublicKey().toXOnlyPublicKey().toString().toLowerCase();
  const owner = keys.owner, agentA = keys.delegate, recipientX = XO(keys.funding.secret);
  const signerFor = (k) => makeDevSigner(config, { secretHex: k.secret, expectedAddress: k.address });
  const evidence = { gate: "v0.4.1-concurrency", network: config.networkId, startedAt: new Date().toISOString(), cases: [] };

  const { rpc, serverInfo } = await connectVerified(config);
  if (!serverInfo.isSynced) throw new Error("node not synced");
  evidence.node = { networkId: serverInfo.networkId, serverVersion: serverInfo.serverVersion };

  async function fetchFuel(address, min) {
    const u = (await getAddressUtxos(rpc, address)).filter((x) => x.covenantId === null && x.amount > min).sort((a, b) => (a.amount < b.amount ? 1 : -1));
    if (!u.length) throw new Error(`no ordinary UTXO > ${min} at ${address}`);
    return { outpoint: u[0].outpoint, amount: u[0].amount.toString(), scriptPublicKeyHex: u[0].scriptPublicKeyHex };
  }
  // Build+finalize an agentSpend of `payKas` against the CURRENT live state.
  function readySpend(vaultId, payKas) {
    const built = wr4.buildWalletRequestV4({ config, vaultId, action: "agentSpend", params: { agentPk: XO(agentA.secret), recipient: recipientX, payAmountSompi: (payKas * KAS).toString() }, signerAddress: agentA.address });
    const signed = signerFor(agentA).signInputs(built.transaction.unsignedSafeJson, built.transaction.signInputs);
    const fin = wr4.finalizeWalletRequestV4({ config, requestId: built.requestId, signedSafeJson: signed });
    assert(fin.state === "PREFLIGHT_VERIFIED", `finalize ${fin.state}`);
    return built;
  }
  const reqState = (id) => wr4.loadRequest(config, id).state;
  const live = async (vaultId) => { const m = await loadManifestV4(config, vaultId); return m.live ? `${m.live.outpoint.transactionId}:${m.live.outpoint.index}` : null; };
  async function pollReconcile(vaultId) { let r; for (let i = 0; i < 40; i++) { r = await reconcileVaultV4(config, vaultId, { rpc }); if (r.status !== "CLAIM_PENDING") return r; await new Promise((x) => setTimeout(x, 2000)); } return r; }

  try {
    const vaultId = require("crypto").randomBytes(32).toString("hex");
    const pol = { agentPk: XO(agentA.secret), maxPerSpend: (10n * KAS).toString(), periodBudget: (100n * KAS).toString(), periodLengthDaa: "864000", periodStartDaa: "541000000", periodSpent: "0", approvalThreshold: (100000n * KAS).toString(), agentMaxFeePerTx: (1n * KAS).toString(), recipients: [recipientX] };
    const genReq = wr4.buildCreateWalletRequestV4({ config, contractVersion: V4_1, templateInput: { owner: XO(owner.secret), vaultId }, initialAgents: [pol], initialState: { protectedValue: (40n * KAS).toString(), feeReserve: (5n * KAS).toString(), approvers: [], approvalM: "0" }, signerAddress: owner.address, funding: [await fetchFuel(owner.address, 60n * KAS)], label: "concurrency" });
    const gr = await submit4.submitCreateWalletRequestV4({ config, requestId: genReq.requestId, signedSafeJson: signerFor(owner).signInputs(genReq.transaction.unsignedSafeJson, genReq.transaction.signInputs), rpc });
    assert(gr.request.state === "CHAIN_VERIFIED", "genesis");
    log("genesis CHAIN_VERIFIED", gr.txId.slice(0, 12));
    evidence.vaultId = vaultId;

    // ---- CASE 1: the single-covenant-UTXO serialization is enforced at
    // FINALIZE (the transition claim). Two spends against the SAME predecessor
    // (two tabs / two agents / owner-vs-agent all reduce to this) — the first
    // finalizes and claims the predecessor; the second FAILS CLOSED with
    // CLAIM_CONFLICT. Then exactly one is submitted and wins. ----
    {
      const before = await live(vaultId);
      const A = readySpend(vaultId, 3n); // finalize -> claims the predecessor outpoint
      let bErr = null;
      try { readySpend(vaultId, 4n); } catch (e) { bErr = e; } // same predecessor
      assert(bErr && bErr.code === "CLAIM_CONFLICT", `second finalize on the same predecessor must be CLAIM_CONFLICT, got ${bErr && bErr.code}`);
      const r = await submit4.submitWalletRequestV4({ config, requestId: A.requestId, rpc });
      assert(r.request.state === "CHAIN_VERIFIED", `the one prepared transition wins, got ${r.request.state}`);
      await pollReconcile(vaultId);
      const after = await live(vaultId);
      assert(after !== before && after.startsWith(r.txId), "vault advanced to exactly the one winner");
      log(`CASE 1 conflict: 1st finalize claims predecessor; 2nd fails closed CLAIM_CONFLICT; winner ${r.txId.slice(0, 10)} ✓`);
      evidence.cases.push({ case: "finalize-serialization", secondFinalize: bErr.code, winnerTx: r.txId, oneWinner: true });
    }

    // ---- CASE 2: duplicate submit of the SAME (already CHAIN_VERIFIED) request
    // is idempotent — no second broadcast, no double transition. ----
    {
      const mid = await live(vaultId);
      const A = readySpend(vaultId, 3n);
      const r1 = await submit4.submitWalletRequestV4({ config, requestId: A.requestId, rpc });
      assert(r1.request.state === "CHAIN_VERIFIED", "first submit wins");
      await pollReconcile(vaultId);
      const at = await live(vaultId);
      assert(at.startsWith(r1.txId) && at !== mid, "advanced once");
      let dupErr = null, dupOk = null;
      try { dupOk = await submit4.submitWalletRequestV4({ config, requestId: A.requestId, rpc }); } catch (e) { dupErr = e; }
      assert((await live(vaultId)) === at, "duplicate submit must NOT cause a second/double transition");
      log(`CASE 2 duplicate submit: ${dupErr ? "rejected (" + (dupErr.code || dupErr.message.slice(0, 40)) + ")" : "idempotent " + dupOk.request.state}; no double transition ✓`);
      evidence.cases.push({ case: "duplicate-submit", secondOutcome: dupErr ? (dupErr.code || "REJECTED") : dupOk.request.state, noDoubleTransition: true });
    }

    // ---- CASE 3: an ABANDONED finalize (reload/restart with a pending request
    // that never submits) does not permanently lock the vault — reconcile
    // releases the stale claim and a fresh transition can then be prepared. ----
    {
      const A = readySpend(vaultId, 3n); // claims predecessor, never submitted
      // a second finalize is blocked while the (stale) claim is held:
      let blocked = null;
      try { readySpend(vaultId, 2n); } catch (e) { blocked = e; }
      assert(blocked && blocked.code === "CLAIM_CONFLICT", "held claim blocks a new finalize");
      // reconcile releases the stale claim (predecessor live + effect absent):
      const rec = await reconcileVaultV4(config, vaultId, { rpc, stalePendingMinimumMs: 0 });
      assert(["CLAIM_RELEASED", "CONSISTENT"].includes(rec.status), `stale claim must release, got ${rec.status}`);
      // now a fresh transition can be prepared and submitted:
      const B = readySpend(vaultId, 2n);
      const rb = await submit4.submitWalletRequestV4({ config, requestId: B.requestId, rpc });
      assert(rb.request.state === "CHAIN_VERIFIED", "after release, a new transition succeeds");
      await pollReconcile(vaultId);
      log(`CASE 3 abandoned finalize: held claim blocks; reconcile ${rec.status}; fresh transition then succeeds ✓`);
      evidence.cases.push({ case: "stale-claim-release", blocked: blocked.code, reconcile: rec.status, retrySucceeded: true });
      void A;
    }

    evidence.result = "PASS";
    evidence.finishedAt = new Date().toISOString();
    fs.writeFileSync(OUT, JSON.stringify(evidence, null, 2));
    log(`=== CONCURRENCY MATRIX PASS (${evidence.cases.length} cases) -> ${OUT} ===`);
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
