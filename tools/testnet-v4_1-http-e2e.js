"use strict";

/*
 * LIVE testnet-10 — v0.4.1 BROWSER-FACING HTTP live path (Checkpoint H2). Starts
 * the real PolicyVault server in-process and drives the EXACT endpoints the
 * browser dashboard calls for a v0.4.1 LIVE lifecycle, mocking ONLY the wallet
 * boundary via /wallet/dev-sign (the same seam the browser MockAdapter uses;
 * real KasWare's signPskt replaces it one-for-one). This proves the create +
 * broadcast + reconcile server plumbing end-to-end BEFORE the real-KasWare
 * manual run, so the browser UI only has to call these endpoints.
 *
 * Flow: POST /wallet/v4/create (contractVersion 0.4.1) -> dev-sign owner funding
 * -> POST .../genesis-submit (broadcast + chain-prove) -> GET /vaults/:id
 * -> POST /wallet/v4/requests (agentSpend) -> dev-sign agent -> POST .../signature
 * (finalize+preflight) -> POST .../submit (broadcast) -> POST /vaults/:id/reconcile.
 *
 * testnet-10 ONLY. Usage: POLICYVAULT_DEV_SIGNER=1 node tools/testnet-v4_1-http-e2e.js
 */

const path = require("path");
const crypto = require("crypto");
const sdkRoot = path.join(__dirname, "..", "sdk");
const { loadConfig } = require(path.join(sdkRoot, "src/config"));
const { loadOrCreateTestKeys } = require(path.join(sdkRoot, "src/keys"));
const { connectVerified, getAddressUtxos } = require(path.join(sdkRoot, "src/chain"));
const { createServer } = require(path.join(__dirname, "..", "server", "src", "server"));

const V4_1 = "policyvault-0.4.1";
const KAS = 100_000_000n;
const PORT = 3097;
const BASE = `http://127.0.0.1:${PORT}/api/v1`;

async function post(url, body) {
  const r = await fetch(BASE + url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  return { ok: r.ok, status: r.status, j: await r.json() };
}
async function get(url) {
  const r = await fetch(BASE + url);
  return { ok: r.ok, status: r.status, j: await r.json() };
}

(async () => {
  if (process.env.POLICYVAULT_DEV_SIGNER !== "1") { console.error("run with POLICYVAULT_DEV_SIGNER=1"); process.exit(2); }
  const config = loadConfig();
  if (config.networkId !== "testnet-10") { console.error("refusing: not testnet-10"); process.exit(2); }
  const keys = loadOrCreateTestKeys(config);
  const XO = (k) => k.xonly;
  const server = createServer(config);
  await new Promise((r) => server.listen(PORT, "127.0.0.1", r));
  console.log("== v0.4.1 browser-facing HTTP LIVE path (dev signer mocks only the wallet) ==");

  const { rpc } = await connectVerified(config);
  async function fetchFuel(address, min) {
    const u = (await getAddressUtxos(rpc, address)).filter((x) => x.covenantId === null && x.amount > min).sort((a, b) => (a.amount < b.amount ? 1 : -1));
    if (!u.length) throw new Error(`no ordinary UTXO > ${min} at ${address}`);
    return { outpoint: u[0].outpoint, amount: u[0].amount.toString(), scriptPublicKeyHex: u[0].scriptPublicKeyHex };
  }

  try {
    const health = await get("/health");
    console.log("health:", health.j.ok, health.j.networkId);

    // 1) CREATE a v0.4.1 vault via the FRIENDLY browser schema: human addresses
    // + KAS only. The server normalizes to canonical (owner x-only from the
    // signer, node-derived periodStartDaa, periodSpent=0, KAS→sompi, addresses→
    // x-only) and auto-selects funding. NO covenant/sompi/DAA fields from the
    // client — this is exactly what the dashboard Create form sends.
    const vaultId = crypto.randomBytes(32).toString("hex");
    const created = await post("/wallet/v4/create", {
      contractVersion: V4_1,
      signerAddress: keys.owner.address,
      vaultId,
      label: "Operations Treasury",
      depositKas: "20",
      feeReserveKas: "5",
      agent: {
        agentAddress: keys.delegate.address,
        maxPerSpendKas: "10",
        budgetKas: "15",
        budgetPeriod: "1d",
        approvalThresholdKas: "100000",
        recipientAddresses: [keys.funding.address]
      }
    });
    if (created.status !== 201) throw new Error(`friendly create build ${created.status}: ${JSON.stringify(created.j).slice(0, 240)}`);
    const creq = created.j.request;
    if (creq.contractVersion !== V4_1) throw new Error(`create request version ${creq.contractVersion} != ${V4_1}`);
    console.log("1) v0.4.1 FRIENDLY genesis BUILT (addresses+KAS) reqId", creq.requestId.slice(0, 8), "version", creq.contractVersion);

    // 2) owner signs the funding (dev-sign == the wallet boundary), then broadcast.
    const csig = await post("/wallet/dev-sign", { address: keys.owner.address, unsignedSafeJson: creq.transaction.unsignedSafeJson, signInputs: creq.transaction.signInputs });
    if (!csig.ok) throw new Error(`owner dev-sign: ${JSON.stringify(csig.j).slice(0, 160)}`);
    const gsub = await post(`/wallet/v4/requests/${creq.requestId}/genesis-submit`, { signedSafeJson: csig.j.signedSafeJson });
    if (!gsub.ok || gsub.j.request.state !== "CHAIN_VERIFIED") throw new Error(`genesis-submit: ${gsub.status} ${JSON.stringify(gsub.j).slice(0, 200)}`);
    console.log("2) genesis CHAIN_VERIFIED txid", gsub.j.txId.slice(0, 16));

    // 3) read the vault back through the API.
    const shown = await get(`/vaults/${vaultId}`);
    if (shown.j.contractVersion !== V4_1) throw new Error(`GET vault version ${shown.j.contractVersion} != ${V4_1}`);
    console.log("3) GET /vaults/:id ->", shown.j.contractVersion, shown.j.status);

    // 4) below-threshold agentSpend: BUILD -> agent sign -> FINALIZE/preflight -> BROADCAST.
    const built = await post("/wallet/v4/requests", { vaultId, action: "agentSpend", params: { agentPk: XO(keys.delegate), recipient: XO(keys.funding), payAmountSompi: (4n * KAS).toString() }, signerAddress: keys.delegate.address });
    if (built.status !== 201) throw new Error(`spend build ${built.status}: ${JSON.stringify(built.j).slice(0, 200)}`);
    const req = built.j.request;
    if (req.contractVersion !== V4_1) throw new Error(`spend request version ${req.contractVersion} != ${V4_1}`);
    const asig = await post("/wallet/dev-sign", { address: keys.delegate.address, unsignedSafeJson: req.transaction.unsignedSafeJson, signInputs: req.transaction.signInputs });
    const fin = await post(`/wallet/v4/requests/${req.requestId}/signature`, { signedSafeJson: asig.j.signedSafeJson });
    if (!fin.ok || fin.j.request.state !== "PREFLIGHT_VERIFIED") throw new Error(`finalize: ${JSON.stringify(fin.j).slice(0, 200)}`);
    console.log("4) agentSpend PREFLIGHT_VERIFIED (offline); now BROADCAST…");
    const sub = await post(`/wallet/v4/requests/${req.requestId}/submit`, {});
    if (!sub.ok || sub.j.request.state !== "CHAIN_VERIFIED") throw new Error(`submit: ${sub.status} ${JSON.stringify(sub.j).slice(0, 200)}`);
    if (sub.j.txId !== req.txId) throw new Error(`node txid ${sub.j.txId} != frozen ${req.txId}`);
    console.log("5) agentSpend RELAYED + CHAIN_VERIFIED txid", sub.j.txId.slice(0, 16), "(node txid == frozen txid)");

    // 6) reconcile the v0.4.1 vault via the browser "Verify Vault State" endpoint.
    const rec = await post(`/vaults/${vaultId}/reconcile`, {});
    if (!rec.ok) throw new Error(`reconcile: ${rec.status} ${JSON.stringify(rec.j).slice(0, 200)}`);
    console.log("6) POST /vaults/:id/reconcile ->", JSON.stringify(rec.j.reconcile).slice(0, 120));

    console.log("== v0.4.1 HTTP LIVE PATH PASS: create + genesis broadcast + spend broadcast + reconcile, all through the browser-facing API ==");
  } finally {
    await rpc.disconnect();
    await new Promise((r) => server.close(r));
  }
})().catch((e) => { console.error("FAILED:", e.message); process.exit(1); });
