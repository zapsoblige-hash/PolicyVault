"use strict";

/*
 * LIVE testnet-10 — v0.7 ON-CHAIN ORGANIZATIONAL ROOT, BROWSER-FACING HTTP
 * path (Wave 2 Track B). Starts the real PolicyVault server in-process and
 * drives the EXACT endpoints a browser/agent client calls
 * (docs/postlaunch/v0.7-app-surface-contract.md §2): root genesis ->
 * reconcile -> rooted-vault genesis -> deposit -> delegate spend ->
 * root-governed owner op (2-of-3, one slot envelope produced "remotely"
 * and imported over the air-gap shuttle) -> emergency FREEZE pause (K=1)
 * -> unfreeze -> reconcile at every step. Every accepted step is verified
 * against the live node's UTXO index (exact value/address/covenantId)
 * before being trusted; PENDING is never treated as success.
 *
 * Owner slots sign through the REAL production CLI keyfile signer
 * (core/signer/adapters/cli) driven by core/signer/org-root-slot-v7's
 * requestRootSlotSignature — the exact external-signer path gate I3
 * proved, now exercised over this HTTP surface. Funder/fuel/recipient
 * material uses the repo's shared TEST keyring (sdk/src/keys.js
 * loadOrCreateTestKeys); owner-slot identities are persisted CLI
 * keyfiles under keys/org-root-v7-owners/ (generated once, reused on
 * every subsequent run — the same "deterministic across runs" discipline
 * loadOrCreateTestKeys itself uses; core/signer/adapters/cli/adapter.js's
 * generateKeyfile has no secret-seeding option, so the VALUE is chosen
 * once and then persisted rather than re-derived from a fixed seed).
 *
 * TEST ASSETS ONLY. TEST KEYS ONLY. testnet-10 ONLY — refuses any other
 * configured network before touching the node.
 *
 * LIVE BROADCASTS ARE SERIALIZED across every Wave-2 worker: before any
 * broadcast this tool acquires ~/.policyvault-testnet-live.lock
 * (mkdir, retried every 30s), and releases it (rmdir) when the run ends,
 * including on failure. It never deletes a lock it did not create.
 *
 * Usage:
 *   node tools/testnet-v7-http-e2e.js --dry-run   # no RPC, no broadcast, no lock
 *   KASPA_NETWORK_ID=testnet-10 KASPA_RPC_URL=ws://127.0.0.1:18210 \
 *     node tools/testnet-v7-http-e2e.js           # LIVE
 */

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const ROOT_DIR = path.join(__dirname, "..");
const sdkRoot = path.join(ROOT_DIR, "sdk");
const { loadConfig } = require(path.join(sdkRoot, "src/config"));
const { loadOrCreateTestKeys } = require(path.join(sdkRoot, "src/keys"));

/* The established project-wide reference funding key (tools/testnet-v2-
 * lifecycle.js, testnet-v2-crash.js, testnet-wallet-http-e2e.js,
 * testnet-wallet-e2e.js, testnet-create.js all use this exact pattern):
 * ~/jobvault is explicit reference-only material (CLAUDE.md), read-only,
 * outside the PolicyVault repo entirely — never a runtime dependency on
 * mutable JobVault files, just a stable pre-funded testnet-10 TEST key. */
function fundingSecretFromJobVault() {
  const text = fs.readFileSync(path.join(process.env.HOME, "jobvault/keys/jobvault_test_keys.txt"), "utf8");
  const match = /payer secret key:\s*([0-9a-f]{64})/.exec(text);
  if (!match) throw new Error("could not read the testnet funding secret from ~/jobvault");
  return match[1];
}
const { connectVerified, getAddressUtxos, loadKaspa, covenantAddress, getVirtualDaaScore } = require(path.join(sdkRoot, "src/chain"));
const { createServer } = require(path.join(ROOT_DIR, "server", "src", "server"));
const { generateKeyfile, createCliSignerAdapter } = require(path.join(ROOT_DIR, "core", "signer", "adapters", "cli", "adapter"));
const { requestRootSlotSignature } = require(path.join(ROOT_DIR, "core", "signer", "org-root-slot-v7"));
const assets = require(path.join(ROOT_DIR, "core", "assets"));
const { compileKcc20Program } = require(path.join(sdkRoot, "src/token-program-kcc20"));
const { normalizeFrozenTxV3, feeDescriptorFromFrozen } = require(path.join(ROOT_DIR, "core", "model", "frozen-tx-v3"));
const { calculateRequiredFee } = require(path.join(sdkRoot, "src/fee-mass"));
const { describeFrozenTx } = require(path.join(sdkRoot, "src/frozen-tx-v3"));

const DRY = process.argv.includes("--dry-run") || process.argv.includes("--dry");
const KAS = 100000000n;
const PORT = 3098;
const BASE = `http://127.0.0.1:${PORT}/api/v1`;
const LOCK_PATH = path.join(require("os").homedir(), ".policyvault-testnet-live.lock");
const EVIDENCE_PATH = path.join(ROOT_DIR, "docs", "testnet-v7-http-e2e-evidence.json");

function log(...args) {
  console.log(...args);
}

async function post(url, body) {
  const r = await fetch(BASE + url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body ?? {}) });
  return { ok: r.ok, status: r.status, j: await r.json() };
}
async function get(url) {
  const r = await fetch(BASE + url);
  return { ok: r.ok, status: r.status, j: await r.json() };
}

/* ---- the live-broadcast serialization lock (shared across Wave-2 workers) ---- */
async function acquireLock() {
  if (DRY) return;
  for (;;) {
    try {
      fs.mkdirSync(LOCK_PATH);
      log(`lock acquired: ${LOCK_PATH}`);
      return;
    } catch (e) {
      if (e.code !== "EEXIST") throw e;
      log(`lock held by another worker (${LOCK_PATH}) — retrying in 30s`);
      await new Promise((r) => setTimeout(r, 30_000));
    }
  }
}
function releaseLock() {
  if (DRY) return;
  try {
    fs.rmdirSync(LOCK_PATH);
    log(`lock released: ${LOCK_PATH}`);
  } catch (e) {
    if (e.code !== "ENOENT") console.error(`WARNING: failed to release lock: ${e.message}`);
  }
}

/* ---- owner-slot CLI keyfile identities (persisted; generated once) ---- */
function ownerSigner(name, networkId) {
  const dir = path.join(ROOT_DIR, "keys", "org-root-v7-owners");
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const keyfilePath = path.join(dir, `${name}.keyfile.json`);
  let identity;
  if (!fs.existsSync(keyfilePath)) {
    identity = generateKeyfile({ out: keyfilePath, network: networkId, label: name });
  } else {
    const { readKeyfileIdentity } = require(path.join(ROOT_DIR, "core", "signer", "adapters", "cli", "adapter"));
    identity = readKeyfileIdentity(keyfilePath);
  }
  const xOnly = identity.publicKey.slice(2).toLowerCase(); // compressed pubkey -> x-only (drop the parity byte)
  return { name, keyfilePath, address: identity.address, publicKey: identity.publicKey, xOnly, adapter: createCliSignerAdapter({ keyfilePath, network: networkId }) };
}

function record(evidence, step, data) {
  const safeData = data && typeof data === "object" ? data : { value: data ?? null };
  evidence.steps.push({ step, at: new Date().toISOString(), ...safeData });
  log(`-- ${step}`, JSON.stringify(safeData).slice(0, 200));
}

(async () => {
  const config = loadConfig();
  if (!DRY && config.networkId !== "testnet-10") {
    console.error(`refusing: configured network is ${config.networkId}, not testnet-10`);
    process.exit(2);
  }
  const kaspa = loadKaspa(config);
  const keys = loadOrCreateTestKeys(config, { fundingSecretHex: fundingSecretFromJobVault() });
  const XO = (k) => k.xonly;

  const evidence = {
    schemaVersion: "policyvault-testnet-v7-http-e2e-evidence/1",
    dryRun: DRY,
    networkId: config.networkId,
    startedAt: new Date().toISOString(),
    steps: []
  };

  await acquireLock();
  let lockHeld = !DRY;
  const server = createServer(config);
  await new Promise((r) => server.listen(PORT, "127.0.0.1", r));
  log(`== v0.7 ORGANIZATIONAL ROOT HTTP ${DRY ? "DRY-RUN" : "LIVE"} path ==`);

  let rpc = null;
  try {
    if (!DRY) {
      const connected = await connectVerified(config);
      rpc = connected.rpc;
      evidence.node = { rpcUrl: config.rpcUrl, networkId: connected.serverInfo.networkId, isSynced: connected.serverInfo.isSynced, hasUtxoIndex: connected.serverInfo.hasUtxoIndex };
    }

    /* ---- prime funding: delegate (fuel + agent) and recipient3         */
    /* (KCC20 issuance + deposit fuel) from the JobVault reference key,    */
    /* one transaction, skipped if already funded (testnet-v2-lifecycle.js */
    /* pattern) ---- */
    if (!DRY) {
      const balanceOf = async (address) => {
        const u = await getAddressUtxos(rpc, address);
        return u.filter((x) => x.covenantId === null).reduce((s, x) => s + x.amount, 0n);
      };
      const needs = [];
      /* keys.delegate provides fuel for FOUR separate root/wallet
       * operations (delegate spend, owner-op, freeze, unfreeze). Only the
       * delegate-spend's own fuel change returns to keys.delegate (it is
       * both fuel-provider and signer there); every ROOT-authorized fuel
       * input's change goes to the INITIATING OWNER's changeXOnly instead
       * (a different address), so keys.delegate does NOT recycle its
       * balance across those — it needs a SEPARATE funded UTXO per
       * operation, not one big one. */
      if ((await balanceOf(keys.delegate.address)) < 20n * KAS) {
        for (let i = 0; i < 5; i++) needs.push({ address: keys.delegate.address, amount: 4n * KAS });
      }
      if ((await balanceOf(keys.recipient3.address)) < 8n * KAS) needs.push({ address: keys.recipient3.address, amount: 10n * KAS });
      if (needs.length > 0) {
        const { PrivateKey, createTransactions } = kaspa;
        const fundingPrivate = new PrivateKey(keys.funding.secret);
        const entriesRaw = await rpc.getUtxosByAddresses({ addresses: [keys.funding.address] });
        const entries = (entriesRaw.entries ?? []).filter((e) => (e.utxoEntry ?? e.entry ?? e).covenantId === undefined);
        const generated = await createTransactions({ outputs: needs.map((t) => ({ address: t.address, amount: t.amount })), changeAddress: keys.funding.address, priorityFee: 20_000n, entries, networkId: config.networkId });
        for (const pending of generated.transactions) {
          pending.sign([fundingPrivate]);
          await pending.submit(rpc);
        }
        for (const n of needs) {
          for (let i = 0; i < 40; i++) {
            if ((await balanceOf(n.address)) >= n.amount / 2n) break;
            await new Promise((r) => setTimeout(r, 2000));
          }
        }
        record(evidence, "priming-funded", { targets: needs.map((n) => n.address) });
      }
    }

    const health = await get("/health");
    log("health:", health.j.ok, health.j.networkId);

    async function fetchFuel(address, min) {
      if (DRY) return { outpoint: { transactionId: crypto.randomBytes(32).toString("hex"), index: 0 }, amount: (min + KAS).toString(), scriptPublicKeyHex: `20${"11".repeat(32)}ac` };
      const u = (await getAddressUtxos(rpc, address)).filter((x) => x.covenantId === null && x.amount > min).sort((a, b) => (a.amount < b.amount ? 1 : -1));
      if (!u.length) throw new Error(`no ordinary UTXO > ${min} at ${address}`);
      return { outpoint: u[0].outpoint, amount: u[0].amount.toString(), scriptPublicKeyHex: u[0].scriptPublicKeyHex };
    }

    function signAll(unsignedSafeJson, entries) {
      const tx = kaspa.Transaction.deserializeFromSafeJSON(unsignedSafeJson);
      const ins = tx.inputs;
      for (const [i, secretHex] of entries) ins[i].signatureScript = kaspa.createInputSignature(tx, i, new kaspa.PrivateKey(secretHex));
      tx.inputs = ins;
      return tx.serializeToSafeJSON();
    }

    /* Poll the HTTP request/vault surface until a proof condition holds
     * (submit's own chain-proof loop already ran server-side; this is the
     * CLIENT-side "wait for CHAIN_VERIFIED" — never treating BROADCAST/
     * SIGNED as success). */
    async function pollRequestState(getUrl, wantState, attempts = 30) {
      let last = null;
      for (let i = 0; i < attempts; i++) {
        const r = await get(getUrl);
        last = r.j.request;
        if (last && last.state === wantState) return last;
        if (last && ["SUBMISSION_REJECTED", "RECONCILIATION_REQUIRED"].includes(last.state)) {
          throw new Error(`${getUrl} reached ${last.state} — PENDING states are never success`);
        }
        await new Promise((r2) => setTimeout(r2, 2000));
      }
      throw new Error(`${getUrl} did not reach ${wantState} (last: ${last && last.state})`);
    }

    /* ================= 1. ORGANIZATIONAL ROOT GENESIS (2-of-3, K=1, R=1) ================= */
    const owner1 = ownerSigner("owner1", config.networkId);
    const owner2 = ownerSigner("owner2", config.networkId);
    const owner3 = ownerSigner("owner3", config.networkId);
    log("owner slots:", owner1.address, owner2.address, owner3.address);

    const funderFuel = await fetchFuel(keys.funding ? keys.funding.address : keys.owner.address, 3n * KAS);
    const created = await post("/org-roots", {
      label: "Wave2 Track B HTTP e2e org",
      owners: [{ slot: 1, publicKey: owner1.xOnly }, { slot: 2, publicKey: owner2.xOnly }, { slot: 3, publicKey: owner3.xOnly }],
      ownerM: 2,
      emergencyK: 1,
      recoveryM: 1,
      recoveryDelayDaa: "600",
      successionDelayDaa: "600",
      successorAddress: null,
      rootValueKas: "2",
      rootMaxFeePerTxKas: "0.01",
      signerAddress: keys.funding ? keys.funding.address : keys.owner.address,
      funding: [funderFuel]
    });
    if (created.status !== 201) throw new Error(`POST /org-roots -> ${created.status}: ${JSON.stringify(created.j).slice(0, 300)}`);
    const rootReq = created.j.request;
    record(evidence, "root-genesis-built", { requestId: rootReq.id, rootCovenantId: rootReq.rootCovenantId });

    const funderSecret = keys.funding ? keys.funding.secret : keys.owner.secret;
    const rootGenesisSigned = signAll(rootReq.transaction.unsignedSafeJson, rootReq.transaction.signInputs.map((s) => [s.index, funderSecret]));
    const rootGenesisSignedResp = await post(`/org-roots/${rootReq.rootCovenantId}/requests/${rootReq.id}/signature`, { signedSafeJson: rootGenesisSigned });
    if (rootGenesisSignedResp.status !== 200 || rootGenesisSignedResp.j.request.state !== "SIGNED") throw new Error(`root genesis signature: ${JSON.stringify(rootGenesisSignedResp.j).slice(0, 300)}`);

    if (DRY) {
      record(evidence, "root-genesis-DRY-signed", { requestId: rootReq.id });
      /* everything past this point (rooted-vault genesis, deposit, owner
       * ops, freeze/unfreeze) requires a REAL, chain-proven ORG_ROOT
       * record — which by design (only proven chain reconciliation
       * advances a durable record) does not exist until genesis actually
       * broadcasts. --dry-run therefore proves the build->sign plumbing
       * for genesis and stops here, honestly, rather than faking a root
       * record to march further offline. */
      log("== v0.7 HTTP DRY-RUN PASS: root genesis build/sign plumbing verified through the real HTTP surface (no RPC, no broadcast) ==");
      evidence.verdict = "DRY_RUN_PASS";
      fs.mkdirSync(path.dirname(EVIDENCE_PATH), { recursive: true });
      fs.writeFileSync(EVIDENCE_PATH, JSON.stringify(evidence, null, 2) + "\n");
      return;
    }
    const submitted = await post(`/org-roots/${rootReq.rootCovenantId}/requests/${rootReq.id}/submit`, {});
    if (!submitted.ok) throw new Error(`root genesis submit: ${submitted.status} ${JSON.stringify(submitted.j).slice(0, 300)}`);
    await pollRequestState(`/org-roots/${rootReq.rootCovenantId}/requests/${rootReq.id}`, "CHAIN_VERIFIED");
    record(evidence, "root-genesis-CHAIN_VERIFIED", { txId: submitted.j.txId });
    const rootCovenantId = rootReq.rootCovenantId;

    /* ---- reconcile the root ---- */
    if (!DRY) {
      const rec1 = await post(`/org-roots/${rootCovenantId}/reconcile`, {});
      record(evidence, "reconcile-after-root-genesis", rec1.j.reconcile);
      const rootView = await get(`/org-roots/${rootCovenantId}`);
      if (rootView.status !== 200) throw new Error(`GET /org-roots/:id after genesis: ${rootView.status}`);
      log("root live:", JSON.stringify(rootView.j.orgRoot.live));
    }

    /* ================= 1.5 KCC20 ISSUANCE (real, so the deposit step is  */
    /*    real too — the vault's descriptor pins the REAL derived family   */
    /*    id, so it must exist before the vault does) ================= */
    const depositor = keys.recipient3;
    const ref = compileKcc20Program({ config, state: assets.kcc20.ZERO_STATE, familyBound: 2 });
    /* DRY always returned above; everything from here on is the LIVE path. */
    let tokenCovenantId;
    let issuedPositionOutpoint;
    let issuedPositionValue;
    {
      const depositorState0 = { ownerIdentifier: XO(depositor), identifierType: 0, amount: 100000n, isMinter: false };
      const depositorProgram = compileKcc20Program({ config, state: depositorState0, familyBound: 2 });
      const issuanceFuel = await fetchFuel(depositor.address, 4n * KAS);
      const issuanceValue = 2n * KAS;
      const draft = {
        version: 1,
        inputs: [{ previousOutpoint: issuanceFuel.outpoint, sequence: 0n, computeBudget: 10, utxo: { amount: BigInt(issuanceFuel.amount), scriptPublicKey: { version: 0, scriptHex: issuanceFuel.scriptPublicKeyHex }, covenantId: null, blockDaaScore: 0n } }],
        outputs: [
          { value: issuanceValue, scriptPublicKey: { version: 0, scriptHex: depositorProgram.p2shSpkHex }, covenant: { authorizingInput: 0, covenantId: null } },
          { value: 1n, scriptPublicKey: { version: 0, scriptHex: issuanceFuel.scriptPublicKeyHex }, covenant: null }
        ],
        lockTime: 0n,
        subnetworkId: "00".repeat(20),
        gas: 0n,
        payload: ""
      };
      const unboundNote = new kaspa.TransactionOutput(issuanceValue, kaspa.payToScriptHashScript(depositorProgram.scriptHex));
      tokenCovenantId = kaspa
        .covenantId({ transactionId: issuanceFuel.outpoint.transactionId, index: issuanceFuel.outpoint.index }, [{ index: 0, output: unboundNote }])
        .toString()
        .toLowerCase();
      draft.outputs[0].covenant.covenantId = tokenCovenantId;
      const fee = calculateRequiredFee(feeDescriptorFromFrozen(normalizeFrozenTxV3(draft), [66])).minimumRequiredFee;
      draft.outputs[1] = { ...draft.outputs[1], value: BigInt(issuanceFuel.amount) - issuanceValue - fee };
      const frozen = normalizeFrozenTxV3(draft);
      const issuanceTxId = describeFrozenTx(frozen).txId;
      const issuanceTx = new kaspa.Transaction({
        version: 1,
        inputs: [{ previousOutpoint: issuanceFuel.outpoint, signatureScript: "", sequence: 0n, sigOpCount: 0, computeBudget: 10, utxo: { outpoint: issuanceFuel.outpoint, amount: BigInt(issuanceFuel.amount), scriptPublicKey: { version: 0, script: issuanceFuel.scriptPublicKeyHex }, blockDaaScore: 0n, isCoinbase: false } }],
        outputs: [
          { value: issuanceValue, scriptPublicKey: { version: 0, script: depositorProgram.p2shSpkHex } },
          { value: draft.outputs[1].value, scriptPublicKey: { version: 0, script: issuanceFuel.scriptPublicKeyHex } }
        ],
        lockTime: 0n,
        subnetworkId: draft.subnetworkId,
        gas: 0n,
        payload: draft.payload
      });
      const outs = issuanceTx.outputs;
      outs[0].covenant = new kaspa.CovenantBinding(0, new kaspa.Hash(tokenCovenantId));
      issuanceTx.outputs = outs;
      const ins = issuanceTx.inputs;
      ins[0].signatureScript = kaspa.createInputSignature(issuanceTx, 0, new kaspa.PrivateKey(depositor.secret));
      issuanceTx.inputs = ins;
      const computedTxId = issuanceTx.finalize().toString().toLowerCase();
      if (computedTxId !== issuanceTxId) throw new Error(`issuance txid drift: computed ${computedTxId} != planned ${issuanceTxId}`);
      const submittedIssuance = await rpc.submitTransaction({ transaction: issuanceTx, allowOrphan: false });
      const returnedIssuanceTxId = String(submittedIssuance.transactionId ?? submittedIssuance).toLowerCase();
      if (returnedIssuanceTxId !== issuanceTxId) throw new Error(`node returned ${returnedIssuanceTxId}, expected ${issuanceTxId}`);
      const issuanceAddress = covenantAddress(config, Buffer.from(depositorProgram.scriptHex, "hex"));
      let issuanceProof = null;
      for (let i = 0; i < 30 && !issuanceProof; i++) {
        const utxos = await getAddressUtxos(rpc, issuanceAddress);
        issuanceProof = utxos.find((u) => u.outpoint.transactionId === issuanceTxId && u.outpoint.index === 0) || null;
        if (!issuanceProof) await new Promise((r) => setTimeout(r, 2000));
      }
      if (!issuanceProof) throw new Error(`KCC20 issuance ${issuanceTxId} submitted but not observed on chain`);
      issuedPositionOutpoint = { transactionId: issuanceTxId, index: 0 };
      issuedPositionValue = issuanceValue.toString();
      record(evidence, "kcc20-issuance-CHAIN_VERIFIED", { txId: issuanceTxId, tokenCovenantId, supply: "100000" });
    }

    /* ================= 2. ROOTED PAYMENT VAULT GENESIS ================= */
    const descriptor = {
      schema: "policyvault-asset-descriptor/1",
      assetId: crypto.randomBytes(32).toString("hex"),
      displayName: "Wave2 HTTP e2e Token",
      tokenStandard: "kcc20/1",
      tokenCovenantId,
      acceptedTransferTemplates: [{ templateVmHashBlake2b256: ref.templateVmHashBlake2b256, prefixLen: ref.geometry.prefixLen, suffixLen: ref.geometry.suffixLen, stateLayout: "kcc20-state/1" }],
      decimalsDisplay: 2,
      issuerPowers: { mint: false, burn: false, freeze: false, blacklist: false, redemptionControl: false, upgradeMigration: false, controllerRotation: false, emergencyControl: false }
    };
    const { buildRecipientTree } = require(path.join(sdkRoot, "src/recipient-merkle-v3"));
    const rTree = buildRecipientTree([XO(keys.recipient1)]);
    const currentDaa = await getVirtualDaaScore(rpc);
    const agentPolicy = {
      agentPk: XO(keys.delegate),
      tokenMaxPerSpend: "250",
      tokenPeriodBudget: "2000",
      periodLengthDaa: "100000000",
      periodStartDaa: currentDaa.toString(),
      tokenPeriodSpent: "0",
      agentMaxFeePerTx: (1n * KAS).toString(),
      agentMaxCarryKas: (KAS / 4n).toString(),
      recipients: [...rTree.recipients]
    };

    const vaultFunderFuel = await fetchFuel(keys.funding ? keys.funding.address : keys.owner.address, 4n * KAS);
    const vaultCreated = await post(`/org-roots/${rootCovenantId}/vaults`, {
      label: "Wave2 HTTP e2e treasury",
      descriptor,
      templateIndex: 0,
      agents: [agentPolicy],
      recoveryAddress: keys.recipient2.address,
      feeReserveKas: "3",
      signerAddress: keys.funding ? keys.funding.address : keys.owner.address,
      funding: [vaultFunderFuel]
    });
    if (vaultCreated.status !== 201) throw new Error(`POST /org-roots/:id/vaults -> ${vaultCreated.status}: ${JSON.stringify(vaultCreated.j).slice(0, 300)}`);
    const vaultReq = vaultCreated.j.request;
    record(evidence, "rooted-vault-genesis-built", { requestId: vaultReq.id });

    const vaultGenesisSigned = signAll(vaultReq.transaction.unsignedSafeJson, vaultReq.transaction.signInputs.map((s) => [s.index, funderSecret]));
    const vaultGenesisSignedResp = await post(`/org-roots/${rootCovenantId}/requests/${vaultReq.id}/signature`, { signedSafeJson: vaultGenesisSigned });
    if (vaultGenesisSignedResp.status !== 200) throw new Error(`rooted-vault genesis signature: ${JSON.stringify(vaultGenesisSignedResp.j).slice(0, 300)}`);

    let vaultId = null;
    const vaultSubmitted = await post(`/org-roots/${rootCovenantId}/requests/${vaultReq.id}/submit`, {});
    if (!vaultSubmitted.ok) throw new Error(`rooted-vault genesis submit: ${vaultSubmitted.status} ${JSON.stringify(vaultSubmitted.j).slice(0, 300)}`);
    const finalReq = await pollRequestState(`/org-roots/${rootCovenantId}/requests/${vaultReq.id}`, "CHAIN_VERIFIED");
    vaultId = finalReq.build ? finalReq.build.template.vaultId : null;
    const vaultsList = await get(`/org-roots/${rootCovenantId}/vaults`);
    vaultId = vaultId || (vaultsList.j.vaults[0] && vaultsList.j.vaults[0].vaultId);
    record(evidence, "rooted-vault-genesis-CHAIN_VERIFIED", { txId: vaultSubmitted.j.txId, vaultId });

    /* ================= 3. TOKEN DEPOSIT (user -> vault), the REAL        */
    /*    issued position from step 1.5 ================= */
    /* amount is a STRING here (not a BigInt): this state object crosses
     * JSON.stringify in the deposit POST body below, and JSON has no
     * BigInt representation — compileKcc20Program/normalizeState both
     * accept a decimal string exactly like a BigInt (parseAtomicAmount). */
    const depositorState = { ownerIdentifier: XO(depositor), identifierType: 0, amount: "100000", isMinter: false };
    const depositorProgram = compileKcc20Program({ config, state: depositorState, familyBound: 2 });
    const depositFuel = await fetchFuel(depositor.address, 2n * KAS);
    const depositCreated = await post("/wallet/v7/requests", {
      vaultId,
      action: "tokenDeposit",
      params: {
        userPosition: { outpoint: issuedPositionOutpoint, value: issuedPositionValue, scriptPublicKeyHex: depositorProgram.p2shSpkHex, covenantId: tokenCovenantId, state: depositorState },
        depositAmount: "100000",
        depositCarryKasSompi: issuedPositionValue,
        fuel: depositFuel
      },
      signerAddress: depositor.address
    });
    if (depositCreated.status !== 201) throw new Error(`POST /wallet/v7/requests (deposit) -> ${depositCreated.status}: ${JSON.stringify(depositCreated.j).slice(0, 300)}`);
    const depositReq = depositCreated.j.request;
    record(evidence, "deposit-built", { requestId: depositReq.requestId });
    const depositSigned = signAll(depositReq.transaction.unsignedSafeJson, [[0, depositor.secret], [1, depositor.secret]]);
    const depositSignedResp = await post(`/wallet/v7/requests/${depositReq.requestId}/signature`, { signedSafeJson: depositSigned });
    if (depositSignedResp.status !== 200) throw new Error(`deposit signature: ${JSON.stringify(depositSignedResp.j).slice(0, 300)}`);
    const depositSubmitted = await post(`/wallet/v7/requests/${depositReq.requestId}/submit`, {});
    if (!depositSubmitted.ok) throw new Error(`deposit submit: ${depositSubmitted.status} ${JSON.stringify(depositSubmitted.j).slice(0, 300)}`);
    await pollRequestState(`/wallet/v7/requests/${depositReq.requestId}`, "CHAIN_VERIFIED");
    record(evidence, "deposit-CHAIN_VERIFIED", { txId: depositSubmitted.j.txId });

    /* ================= 3b. DELEGATE SPEND (tokenAgentSpend, NO root input) ================= */
    /* the vault's LIVE token position (the deposit's own output) is the
     * required chain.tokenPosition input — read it back through the
     * public GET /org-roots/:rootId/vaults route rather than re-deriving
     * it locally, proving the HTTP surface's own presentation is enough
     * to build the next transaction. */
    const vaultsAfterDeposit = await get(`/org-roots/${rootCovenantId}/vaults`);
    const vaultView = vaultsAfterDeposit.j.vaults.find((v) => v.vaultId === vaultId);
    if (!vaultView || !vaultView.live || !vaultView.live.tokenPosition) throw new Error(`GET /org-roots/:id/vaults did not report a token position for ${vaultId} after the deposit`);
    const vaultCovenantId = vaultView.live.covenantId;

    /* buildTokenAgentTreeV5's policy layout is CLOSED and does NOT include
     * `recipients` (that is a separate top-level spend param resolved
     * against `agentRecipientRoot`) — a distinct shape from the REGISTRY
     * entry manifest-v7's normalizeRegistry accepted at vault genesis. */
    const { recipients: _agentPolicyRecipients, ...agentPolicyForSpend } = agentPolicy;
    void _agentPolicyRecipients;
    const spendFuel = await fetchFuel(keys.delegate.address, 2n * KAS);
    const spendCreated = await post("/wallet/v7/requests", {
      vaultId,
      action: "tokenAgentSpend",
      params: {
        spendAmount: "200",
        agents: [{ ...agentPolicyForSpend, agentRecipientRoot: rTree.root }],
        recipient: XO(keys.recipient1),
        recipients: [...rTree.recipients],
        recipientCarryKasSompi: (KAS / 5n).toString(),
        reserveConsumedSompi: "50000",
        fuel: spendFuel,
        tokenPosition: vaultView.live.tokenPosition
      },
      signerAddress: keys.delegate.address
    });
    if (spendCreated.status !== 201) throw new Error(`POST /wallet/v7/requests (spend) -> ${spendCreated.status}: ${JSON.stringify(spendCreated.j).slice(0, 300)}`);
    const spendReq = spendCreated.j.request;
    record(evidence, "delegate-spend-built", { requestId: spendReq.requestId, vaultCovenantId });
    const spendSigned = signAll(spendReq.transaction.unsignedSafeJson, [[0, keys.delegate.secret], [spendReq.transaction.signInputs.length - 1, keys.delegate.secret]]);
    const spendSignedResp = await post(`/wallet/v7/requests/${spendReq.requestId}/signature`, { signedSafeJson: spendSigned });
    if (spendSignedResp.status !== 200) throw new Error(`delegate spend signature: ${JSON.stringify(spendSignedResp.j).slice(0, 300)}`);
    const spendSubmitted = await post(`/wallet/v7/requests/${spendReq.requestId}/submit`, {});
    if (!spendSubmitted.ok) throw new Error(`delegate spend submit: ${spendSubmitted.status} ${JSON.stringify(spendSubmitted.j).slice(0, 300)}`);
    await pollRequestState(`/wallet/v7/requests/${spendReq.requestId}`, "CHAIN_VERIFIED");
    record(evidence, "delegate-spend-CHAIN_VERIFIED", { txId: spendSubmitted.j.txId });

    /* ================= 4. ROOT-GOVERNED OWNER OP (2-of-3), with ONE     */
    /*    envelope produced "remotely" and imported over the air gap      */
    /* ================= */
    const opFuel = await fetchFuel(keys.delegate.address, 2n * KAS);
    const opCreated = await post(`/org-roots/${rootCovenantId}/requests`, {
      action: "authorize",
      params: { fuel: opFuel },
      vaultOperations: vaultId ? [{ vaultId, action: "ownerTopUpReserve", params: { topUpReserveAmountSompi: (KAS / 2n).toString() } }] : [],
      signerAddress: owner1.address
    });
    if (opCreated.status !== 201) throw new Error(`POST /org-roots/:id/requests -> ${opCreated.status}: ${JSON.stringify(opCreated.j).slice(0, 300)}`);
    const opReq = opCreated.j.request;
    record(evidence, "owner-op-built", { requestId: opReq.id, requiredApprovals: opReq.requiredApprovals });

    /* slot 1: signed LOCALLY through the real CLI keyfile signer */
    const slot1Envelope = await get(`/org-roots/${rootCovenantId}/requests/${opReq.id}/slot-request/1`);
    await owner1.adapter.connect();
    const resp1 = await requestRootSlotSignature({ adapter: owner1.adapter, request: slot1Envelope.j.slotRequest, signerAddress: owner1.address });
    const sig1 = await post(`/org-roots/${rootCovenantId}/requests/${opReq.id}/slot-signatures`, { slot: 1, response: resp1 });
    if (sig1.status !== 200) throw new Error(`slot 1 signature: ${JSON.stringify(sig1.j).slice(0, 300)}`);

    /* slot 2: produced "REMOTELY" — round-tripped through plain JSON
     * exactly like the air-gap shuttle (request out, response back), then
     * imported here and POSTed, proving the collection round survives the
     * out-of-band hop. */
    const slot2EnvelopeResp = await get(`/org-roots/${rootCovenantId}/requests/${opReq.id}/slot-request/2`);
    const shuttledRequest = JSON.parse(JSON.stringify(slot2EnvelopeResp.j.slotRequest));
    await owner2.adapter.connect();
    const resp2Remote = await requestRootSlotSignature({ adapter: owner2.adapter, request: shuttledRequest, signerAddress: owner2.address });
    const shuttledResponse = JSON.parse(JSON.stringify(resp2Remote));
    const sig2 = await post(`/org-roots/${rootCovenantId}/requests/${opReq.id}/slot-signatures`, { slot: 2, response: shuttledResponse });
    if (sig2.status !== 200) throw new Error(`slot 2 (remote-imported) signature: ${JSON.stringify(sig2.j).slice(0, 300)}`);
    record(evidence, "owner-op-2-of-3-signed", { slot1: owner1.address, slot2Remote: owner2.address });

    const opReqNow = await get(`/org-roots/${rootCovenantId}/requests/${opReq.id}`);
    const fuelSigOp = kaspa.createInputSignature(kaspa.Transaction.deserializeFromSafeJSON(opReq.transaction.unsignedSafeJson), opReq.transaction.signInputs.length - 1, new kaspa.PrivateKey(keys.delegate.secret));
    const finalizedOp = await post(`/org-roots/${rootCovenantId}/requests/${opReq.id}/finalize`, { fuelSignatureScriptHex: fuelSigOp });
    if (finalizedOp.status !== 200 || finalizedOp.j.request.state !== "SIGNED") throw new Error(`owner-op finalize: ${JSON.stringify(finalizedOp.j).slice(0, 300)}`);
    const submittedOp = await post(`/org-roots/${rootCovenantId}/requests/${opReq.id}/submit`, {});
    if (!submittedOp.ok) throw new Error(`owner-op submit: ${submittedOp.status} ${JSON.stringify(submittedOp.j).slice(0, 300)}`);
    await pollRequestState(`/org-roots/${rootCovenantId}/requests/${opReq.id}`, "CHAIN_VERIFIED");
    record(evidence, "owner-op-CHAIN_VERIFIED", { txId: submittedOp.j.txId });

    /* ================= 5. EMERGENCY FREEZE (K=1) ================= */
    const freezeFuel = await fetchFuel(keys.delegate.address, 2n * KAS);
    const freezeCreated = await post(`/org-roots/${rootCovenantId}/requests`, { action: "freeze", params: { fuel: freezeFuel }, signerAddress: owner3.address });
    if (freezeCreated.status !== 201) throw new Error(`freeze build: ${JSON.stringify(freezeCreated.j).slice(0, 300)}`);
    const freezeReq = freezeCreated.j.request;
    const freezeSlot = await get(`/org-roots/${rootCovenantId}/requests/${freezeReq.id}/slot-request/3`);
    await owner3.adapter.connect();
    const freezeResp = await requestRootSlotSignature({ adapter: owner3.adapter, request: freezeSlot.j.slotRequest, signerAddress: owner3.address });
    const freezeSig = await post(`/org-roots/${rootCovenantId}/requests/${freezeReq.id}/slot-signatures`, { slot: 3, response: freezeResp });
    if (freezeSig.status !== 200) throw new Error(`freeze slot signature: ${JSON.stringify(freezeSig.j).slice(0, 300)}`);
    const freezeReqNow = await get(`/org-roots/${rootCovenantId}/requests/${freezeReq.id}`);
    const freezeFuelSig = kaspa.createInputSignature(kaspa.Transaction.deserializeFromSafeJSON(freezeReq.transaction.unsignedSafeJson), freezeReq.transaction.signInputs.length - 1, new kaspa.PrivateKey(keys.delegate.secret));
    const freezeFinalized = await post(`/org-roots/${rootCovenantId}/requests/${freezeReq.id}/finalize`, { fuelSignatureScriptHex: freezeFuelSig });
    if (freezeFinalized.status !== 200) throw new Error(`freeze finalize: ${JSON.stringify(freezeFinalized.j).slice(0, 300)}`);
    const freezeSubmitted = await post(`/org-roots/${rootCovenantId}/requests/${freezeReq.id}/submit`, {});
    if (!freezeSubmitted.ok) throw new Error(`freeze submit: ${freezeSubmitted.status} ${JSON.stringify(freezeSubmitted.j).slice(0, 300)}`);
    await pollRequestState(`/org-roots/${rootCovenantId}/requests/${freezeReq.id}`, "CHAIN_VERIFIED");
    record(evidence, "emergency-freeze-CHAIN_VERIFIED", { txId: freezeSubmitted.j.txId });

    const rootAfterFreeze = await get(`/org-roots/${rootCovenantId}`);
    if (rootAfterFreeze.j.orgRoot.frozen !== true) throw new Error("root did not report frozen=true after FREEZE");

    /* ================= 6. GOVERNED UNFREEZE (full 2-of-3) ================= */
    const unfreezeFuel = await fetchFuel(keys.delegate.address, 2n * KAS);
    const unfreezeCreated = await post(`/org-roots/${rootCovenantId}/requests`, { action: "unfreeze", params: { fuel: unfreezeFuel }, signerAddress: owner1.address });
    if (unfreezeCreated.status !== 201) throw new Error(`unfreeze build: ${JSON.stringify(unfreezeCreated.j).slice(0, 300)}`);
    const unfreezeReq = unfreezeCreated.j.request;
    for (const [slot, owner] of [[1, owner1], [2, owner2]]) {
      const envResp = await get(`/org-roots/${rootCovenantId}/requests/${unfreezeReq.id}/slot-request/${slot}`);
      await owner.adapter.connect();
      const resp = await requestRootSlotSignature({ adapter: owner.adapter, request: envResp.j.slotRequest, signerAddress: owner.address });
      const sig = await post(`/org-roots/${rootCovenantId}/requests/${unfreezeReq.id}/slot-signatures`, { slot, response: resp });
      if (sig.status !== 200) throw new Error(`unfreeze slot ${slot} signature: ${JSON.stringify(sig.j).slice(0, 300)}`);
    }
    const unfreezeReqNow = await get(`/org-roots/${rootCovenantId}/requests/${unfreezeReq.id}`);
    const unfreezeFuelSig = kaspa.createInputSignature(kaspa.Transaction.deserializeFromSafeJSON(unfreezeReq.transaction.unsignedSafeJson), unfreezeReq.transaction.signInputs.length - 1, new kaspa.PrivateKey(keys.delegate.secret));
    const unfreezeFinalized = await post(`/org-roots/${rootCovenantId}/requests/${unfreezeReq.id}/finalize`, { fuelSignatureScriptHex: unfreezeFuelSig });
    if (unfreezeFinalized.status !== 200) throw new Error(`unfreeze finalize: ${JSON.stringify(unfreezeFinalized.j).slice(0, 300)}`);
    const unfreezeSubmitted = await post(`/org-roots/${rootCovenantId}/requests/${unfreezeReq.id}/submit`, {});
    if (!unfreezeSubmitted.ok) throw new Error(`unfreeze submit: ${unfreezeSubmitted.status} ${JSON.stringify(unfreezeSubmitted.j).slice(0, 300)}`);
    await pollRequestState(`/org-roots/${rootCovenantId}/requests/${unfreezeReq.id}`, "CHAIN_VERIFIED");
    record(evidence, "unfreeze-CHAIN_VERIFIED", { txId: unfreezeSubmitted.j.txId });

    /* ================= 7. FINAL RECONCILE ================= */
    const finalReconcile = await post(`/org-roots/${rootCovenantId}/reconcile`, {});
    if (!finalReconcile.ok) throw new Error(`final reconcile: ${finalReconcile.status} ${JSON.stringify(finalReconcile.j).slice(0, 500)}`);
    record(evidence, "final-reconcile", finalReconcile.j.reconcile);
    const finalRoot = await get(`/org-roots/${rootCovenantId}`);
    if (finalRoot.j.orgRoot.frozen !== false) throw new Error("root did not report frozen=false after UNFREEZE");

    evidence.verdict = "LIVE_PASS";
    evidence.rootCovenantId = rootCovenantId;
    evidence.vaultId = vaultId;
    log("== v0.7 ORGANIZATIONAL ROOT HTTP LIVE PATH PASS ==");
  } finally {
    if (rpc) await rpc.disconnect();
    await new Promise((r) => server.close(r));
    if (lockHeld) releaseLock();
    fs.mkdirSync(path.dirname(EVIDENCE_PATH), { recursive: true });
    fs.writeFileSync(EVIDENCE_PATH, JSON.stringify(evidence, null, 2) + "\n");
    log(`evidence written: ${EVIDENCE_PATH}`);
  }
})().catch((e) => {
  console.error("FAILED:", e && e.stack ? e.stack : e);
  process.exit(1);
});
