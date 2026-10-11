"use strict";
/*
 * RC45 R2 test kit for the hosted request-REJECTION scope legs of
 * sdk/test/rc45-r2-az-reject-scope.test.js (items R2-10 and R2-11). Internal
 * RED-first regression material; not an audit.
 *
 * It builds, once, a self-hosted JSON TEMPLATE with the real SDK builders and
 * the real compiler (TEST keys only; an explicit mock chain answers every
 * observation the template's own submits make):
 *   - an organizational root: owners 0x71 / 0x72 / 0x73 in slots 1..3 (2-of-3),
 *     a pinned successor 0x74, funded by owner 0x71, CHAIN_VERIFIED;
 *   - under it, a rooted v0.7-kas treasury with TWO delegates (A 0x62 and
 *     B 0x66, recipient 0x63, realistic period starts) and two vault-level
 *     approver slots (0x5a, 0x5b; both approvals required above a delegate's
 *     threshold), CHAIN_VERIFIED;
 *   - under it, a rooted v0.7-payment vault whose agent registry holds the same
 *     two delegates, CHAIN_VERIFIED;
 *   - under it, a rooted v0.7-payment-hd vault whose level-1 delegation forest
 *     holds the same two delegates, CHAIN_VERIFIED;
 *   - (seedTokenControllers) a v0.5 and a v0.6 token controller owned by 0x71
 *     with the same two delegates as registered agents, CHAIN_VERIFIED.
 * The node DAA read of the delegate period-start rule answers 0 while the
 * template is built (at or below every start the template commits).
 *
 * fresh(backend) installs the template into a fresh case: HOSTED (tenancy
 * enforced, wallet sessions signed in through /auth with TEST keys) on the JSON
 * store or on a fresh PostgreSQL database (the rc45 runner's pg mode; a skipped
 * PostgreSQL leg there is a FAIL), or SELF-HOSTED on the JSON store
 * (PostgreSQL persistence requires hosted authentication, so a self-hosted
 * case is JSON only). Every route call goes through the real
 * server/src/api.js handle; the route paths themselves are spelled in the test
 * file. Nothing dials a node: every config names ws://127.0.0.1:1.
 */
const path = require("node:path");
const crypto = require("node:crypto");
const assert = require("node:assert/strict");
const K = require("./rc45-f5-kit");
const F3 = require("./rc45-f3-kit");
const KK = require("./rc45-r2-kas-kit");
const { useAnchorDaa, withDaa } = require("./rc45-r2-daa");

const SDK_SRC = path.join(__dirname, "..", "src");
const sdk = (name) => require(path.join(SDK_SRC, name));
const { KAS, LOOPBACK } = K;
const D = 545000000n; // a realistic node DAA score
const H = (b) => b.toString(16).padStart(2, "0").repeat(32);
const said = (r) => `${r.status} ${r.code ?? ""} ${r.message ?? ""}`.trim();
const RATE_LIMITS = { auth: { limit: 100000 }, build: { limit: 100000 }, mutate: { limit: 100000 }, submit: { limit: 100000 } };

/* ---------------- TEST wallets ---------------- */
function azWallets(config) {
  const o = (b) => KK.walletOf(config, b);
  return {
    o1: o(0x71), o2: o(0x72), o3: o(0x73), successor: o(0x74),
    agentA: o(0x62), agentB: o(0x66), recipient: o(0x63), fuel: o(0x64), recovery: o(0x51),
    ap1: o(0x5a), ap2: o(0x5b), user: o(0x84), n1: o(0x41), stranger: o(0x99)
  };
}

/* An ordinary P2PK UTXO of `wallet` (TEST outpoint, unique per tag). */
function p2pk(wallet, tag, amountKas = 50n) {
  return { outpoint: { transactionId: K.hex(`rc45-r2-az-utxo-${tag}-${crypto.randomUUID()}`), index: 0 }, amount: (BigInt(amountKas) * KAS).toString(), scriptPublicKeyHex: `20${wallet.xonly}ac` };
}

/* ---------------- the explicit mock chain of the template ---------------- */
function mockRpc() {
  const table = {};
  const rpc = {
    async getUtxosByAddresses({ addresses }) { const entries = []; for (const a of addresses) for (const e of table[a] ?? []) entries.push(e); return { entries }; },
    async submitTransaction({ transaction }) { return { transactionId: transaction.finalize().toString().toLowerCase() }; },
    async disconnect() {},
    seed(address, entry) { table[address] = [...(table[address] ?? []), entry]; }
  };
  return withDaa(rpc, D.toString());
}
const utxo = (address, txId, index, amount, covenantId) => ({ address, outpoint: { transactionId: txId, index }, amount: BigInt(amount), covenantId: covenantId ?? null });
function spkAddress(config, spk) {
  return sdk("chain.js").loadKaspa(config).addressFromScriptPublicKey({ version: spk.version, script: spk.scriptHex }, config.networkId).toString();
}
function signAll(config, unsignedSafeJson, signInputs, wallet) {
  const kaspa = sdk("chain.js").loadKaspa(config);
  const tx = kaspa.Transaction.deserializeFromSafeJSON(unsignedSafeJson);
  const ins = tx.inputs;
  for (const s of signInputs) ins[s.index].signatureScript = kaspa.createInputSignature(tx, s.index, wallet.key);
  tx.inputs = ins;
  return tx.serializeToSafeJSON();
}
/* An approver slot's raw 65-byte signature over the covenant input (input 0) of a delegate spend. */
function approvalSignatureHex(config, unsignedSafeJson, wallet) {
  const kaspa = sdk("chain.js").loadKaspa(config);
  return kaspa.createInputSignature(kaspa.Transaction.deserializeFromSafeJSON(unsignedSafeJson), 0, wallet.key).slice(2, 2 + 130);
}

/* ---------------- asset descriptor and delegate policies ---------------- */
function descriptorFor(config) {
  const assets = require("../../core/assets");
  const { compileKcc20Program } = sdk("token-program-kcc20.js");
  const ref = compileKcc20Program({ config, state: assets.kcc20.ZERO_STATE, familyBound: 2 });
  return {
    ref,
    descriptor: {
      schema: "policyvault-asset-descriptor/1", assetId: H(0x11), displayName: "R2 TEST Token", tokenStandard: "kcc20/1", tokenCovenantId: H(0x54),
      acceptedTransferTemplates: [{ templateVmHashBlake2b256: ref.templateVmHashBlake2b256, prefixLen: ref.geometry.prefixLen, suffixLen: ref.geometry.suffixLen, stateLayout: "kcc20-state/1" }],
      decimalsDisplay: 2,
      issuerPowers: { mint: false, burn: false, freeze: false, blacklist: false, redemptionControl: false, upgradeMigration: false, controllerRotation: false, emergencyControl: false }
    }
  };
}
/* v0.7-kas (v0.4.1 leaf): 5 KAS per spend, approvals above 2 KAS, a daily period that started at a realistic position. */
function kasDelegate(agent, recipient, over = {}) {
  return KK.kasDelegate(agent.xonly, [recipient.xonly], { periodStartDaa: "544000000", ...over });
}
/* token-family delegate (v0.5 / v0.7-payment leaf) */
function tokenPolicy(agent, recipient) {
  const { buildRecipientTree } = sdk("recipient-merkle-v3.js");
  return { agentPk: agent.xonly, tokenMaxPerSpend: "500", tokenPeriodBudget: "1000", periodLengthDaa: "1000", periodStartDaa: "544000000", tokenPeriodSpent: "0", agentMaxFeePerTx: KAS.toString(), agentMaxCarryKas: KAS.toString(), agentRecipientRoot: buildRecipientTree([recipient.xonly]).root, recipients: [recipient.xonly] };
}
/* v0.6 delegate: the token leaf plus its KAS swap budget fields */
function tokenPolicyV6(agent, recipient) {
  return { ...tokenPolicy(agent, recipient), kasMaxPerSwap: (500n * KAS).toString(), kasPeriodBudget: (900n * KAS).toString(), kasPeriodSpent: "0" };
}
/* HD level-1 leaf */
function hdLeaf(agent, recipient) {
  return { pk: agent.xonly, maxPerSpend: "500", periodBudget: "2000", periodLengthDaa: "1000", periodStartDaa: "544000000", periodSpent: "0", maxFeePerTx: KAS.toString(), maxCarryKas: KAS.toString(), expiryDaa: "999999999", recipients: [recipient.xonly] };
}
const policyOnly = (p) => { const { recipients, ...policy } = p; void recipients; return policy; };

/* ---------------- template seeding (self-hosted JSON, real SDK) ---------------- */
async function driveRootRequest(config, request, funder, rpc) {
  const wr7 = sdk("wallet-requests-v7.js");
  const finalized = await wr7.submitOrgRootRequestSignature({ config, requestId: request.id, signedSafeJson: signAll(config, request.transaction.unsignedSafeJson, request.transaction.signInputs, funder) });
  assert.equal(finalized.state, "SIGNED");
  const scriptHex = finalized.build.rootScriptHex ?? finalized.build.vaultScriptHex;
  const outIndex = finalized.build.rootOutputIndex ?? finalized.build.vaultOutputIndex;
  const covId = finalized.build.covenantId ?? finalized.rootCovenantId;
  const value = finalized.build.accounting?.kas?.rootValue ?? finalized.build.initialState.feeReserve;
  const addr = sdk("chain.js").covenantAddress(config, Buffer.from(scriptHex, "hex"));
  rpc.seed(addr, utxo(addr, finalized.txId, outIndex, value, covId));
  const submitted = await wr7.submitOrgRootRequest({ config, requestId: request.id, rpc });
  assert.equal(submitted.state, "CHAIN_VERIFIED", `template: ${submitted.error ?? ""}`);
  return submitted;
}

/* The root and its three rooted vaults (v0.7-kas, v0.7-payment, v0.7-payment-hd). */
async function seedRootedVaults(config, w, rpc) {
  const wr7 = sdk("wallet-requests-v7.js"), wr7kas = sdk("wallet-requests-v7-kas.js"), wr7hd = sdk("wallet-requests-v7-hd.js");
  const { covenantAddress } = sdk("chain.js");
  const { descriptor } = descriptorFor(config);

  const rootReq = await wr7.buildRootGenesisRequest({
    config, label: "R2 TEST root",
    owners: [{ slot: 1, publicKey: w.o1.xonly }, { slot: 2, publicKey: w.o2.xonly }, { slot: 3, publicKey: w.o3.xonly }],
    ownerM: 2, emergencyK: 1, recoveryM: 1, recoveryDelayDaa: "600", successionDelayDaa: "600", successorAddress: w.successor.address,
    rootValueKas: "2", rootMaxFeePerTxKas: "0.01", signerAddress: w.o1.address, funding: [p2pk(w.o1, "root", 20n)]
  });
  const rootId = (await driveRootRequest(config, rootReq, w.o1, rpc)).rootCovenantId;

  /* v0.7-kas treasury: delegates A and B, approver slots ap1 / ap2, both approvals required above a delegate's threshold */
  const kasReq = await wr7kas.buildKasVaultGenesisRequest({
    config, rootCovenantId: rootId, label: "R2 TEST treasury", agents: [kasDelegate(w.agentA, w.recipient), kasDelegate(w.agentB, w.recipient)],
    approvers: [w.ap1.xonly, w.ap2.xonly], approvalM: 2, recoveryAddress: w.recovery.address, depositKas: "100", feeReserveKas: "5",
    signerAddress: w.o1.address, funding: [p2pk(w.o1, "kas", 200n)]
  });
  const kasSigned = await wr7kas.finalizeKasWalletRequest({ config, requestId: kasReq.requestId, signedSafeJson: signAll(config, kasReq.transaction.unsignedSafeJson, kasReq.transaction.signInputs, w.o1) });
  assert.equal(kasSigned.state, "SIGNED");
  const kasAddr = covenantAddress(config, Buffer.from(kasReq.build.vaultScriptHex, "hex"));
  rpc.seed(kasAddr, utxo(kasAddr, kasReq.txId, 0, kasReq.build.frozen.outputs[0].value, kasReq.build.covenantId));
  const kasDone = await wr7kas.submitKasWalletRequest({ config, requestId: kasReq.requestId, rpc });
  assert.equal(kasDone.state, "CHAIN_VERIFIED", `template treasury: ${kasDone.error ?? ""}`);

  /* v0.7-payment vault: the same two delegates */
  const payReq = await wr7.buildRootedVaultGenesisRequest({
    config, rootCovenantId: rootId, label: "R2 TEST payment vault", descriptor, templateIndex: 0,
    agents: [tokenPolicy(w.agentA, w.recipient), tokenPolicy(w.agentB, w.recipient)], recoveryAddress: w.recovery.address, depositKas: "0", feeReserveKas: "5",
    signerAddress: w.o1.address, funding: [p2pk(w.o1, "payment")]
  });
  const payVaultId = (await driveRootRequest(config, payReq, w.o1, rpc)).build.template.vaultId;

  /* v0.7-payment-hd vault: the same two delegates as level-1 leaves */
  const hdReq = await wr7hd.buildHdVaultGenesisRequest({
    config, rootCovenantId: rootId, label: "R2 TEST hd vault", descriptor, templateIndex: 0,
    initialAgents: [hdLeaf(w.agentA, w.recipient), hdLeaf(w.agentB, w.recipient)], recoveryAddress: w.recovery.address, feeReserveKas: "5",
    signerAddress: w.o1.address, funding: [p2pk(w.o1, "hd")]
  });
  const hdSigned = await wr7hd.finalizeHdWalletRequest({ config, requestId: hdReq.requestId, signedSafeJson: signAll(config, hdReq.transaction.unsignedSafeJson, hdReq.transaction.signInputs, w.o1) });
  assert.equal(hdSigned.state, "SIGNED");
  const hdAddr = covenantAddress(config, Buffer.from(hdSigned.build.vaultScriptHex, "hex"));
  rpc.seed(hdAddr, utxo(hdAddr, hdSigned.txId, hdSigned.build.vaultOutputIndex, hdSigned.build.initialState.feeReserve, hdSigned.build.covenantId));
  const hdDone = await wr7hd.submitHdWalletRequest({ config, requestId: hdReq.requestId, rpc });
  assert.equal(hdDone.state, "CHAIN_VERIFIED", `template hd vault: ${hdDone.error ?? ""}`);

  return { rootId, kasVaultId: kasReq.vaultId, payVaultId, hdVaultId: hdDone.vaultId };
}

/* A v0.5 and a v0.6 token controller owned by 0x71 with the two delegates as registered agents (no swap policy). */
async function seedTokenControllers(config, w, rpc) {
  const wr5 = sdk("wallet-requests-v5.js"), wr6 = sdk("wallet-requests-v6.js");
  const { covenantAddress } = sdk("chain.js");
  const { descriptor } = descriptorFor(config);
  const v5Req = await wr5.buildCreateWalletRequestV5({ config, label: "R2 TEST v0.5 controller", descriptor, templateIndex: 0, initialAgents: [tokenPolicy(w.agentA, w.recipient), tokenPolicy(w.agentB, w.recipient)], feeReserveKas: "5", signerAddress: w.o1.address, funding: [p2pk(w.o1, "v5")] });
  const v5Signed = await wr5.submitSignatureV5({ config, requestId: v5Req.requestId, signedSafeJson: signAll(config, v5Req.transaction.unsignedSafeJson, v5Req.transaction.signInputs, w.o1) });
  assert.equal(v5Signed.state, "SIGNED");
  const v5Addr = covenantAddress(config, Buffer.from(v5Signed.build.controllerScriptHex, "hex"));
  rpc.seed(v5Addr, utxo(v5Addr, v5Signed.txId, v5Signed.build.controllerOutputIndex, v5Signed.build.initialState.feeReserve, v5Signed.build.covenantId));
  const v5Done = await wr5.submitWalletRequestV5({ config, requestId: v5Req.requestId, rpc });
  assert.equal(v5Done.state, "CHAIN_VERIFIED", `template v0.5 controller: ${v5Done.error ?? ""}`);

  const v6Req = await wr6.buildCreateWalletRequestV6({ config, label: "R2 TEST v0.6 controller", descriptor, templateIndex: 0, initialAgents: [tokenPolicyV6(w.agentA, w.recipient), tokenPolicyV6(w.agentB, w.recipient)], initialSwapPolicies: [], feeReserveKas: "5", signerAddress: w.o1.address, funding: [p2pk(w.o1, "v6")] });
  const v6Signed = await wr6.submitSignatureV6({ config, requestId: v6Req.requestId, signedSafeJson: signAll(config, v6Req.transaction.unsignedSafeJson, v6Req.transaction.signInputs, w.o1) });
  assert.equal(v6Signed.state, "SIGNED");
  const v6Addr = covenantAddress(config, Buffer.from(v6Signed.build.controllerScriptHex, "hex"));
  const v6Value = (BigInt(v6Signed.build.initialState.feeReserve) + BigInt(v6Signed.build.initialState.swapPrincipal ?? 0)).toString();
  rpc.seed(v6Addr, utxo(v6Addr, v6Signed.txId, v6Signed.build.controllerOutputIndex, v6Value, v6Signed.build.covenantId));
  const v6Done = await wr6.submitWalletRequestV6({ config, requestId: v6Req.requestId, rpc });
  assert.equal(v6Done.state, "CHAIN_VERIFIED", `template v0.6 controller: ${v6Done.error ?? ""}`);

  return { v5VaultId: v5Done.vaultId, v5CovenantId: v5Signed.build.covenantId, v6VaultId: v6Done.vaultId, v6CovenantId: v6Signed.build.covenantId };
}

/* ---------------- suite: template + fresh cases ---------------- */
function azSuite(prefix) {
  const roots = [], stores = [], databases = [];
  const PG = K.pgFromEnv(), PG_AVAILABLE = Boolean(PG.port && PG.user && PG.database);
  const PG_SKIP = PG_AVAILABLE ? undefined : "REQUIREMENT_NOT_AVAILABLE in this process: isolated PostgreSQL (the rc45 runner's pg mode runs these legs; a skipped PostgreSQL leg there is a FAIL)";
  let admin = null, serial = 0, history = null, templateRoot = null, w = null, ids = null, templateRpc = null;
  const mk = (p) => { const dir = K.ownedTempRoot(p); roots.push(dir); return dir; };
  const store = () => sdk("store.js");
  const S = {
    PG_AVAILABLE, PG_SKIP, D,
    get ids() { return ids; },
    get w() { return w; },
    /* Build the self-hosted template with every `seeders` entry (each (config, w, rpc) -> object merged into ids). */
    async setup(seeders) {
      const template = sdk("config.js").loadConfig({ dataRoot: mk(`pv-rc45-${prefix}-template-`), rpcUrl: LOOPBACK });
      assert.equal(template.tenancyEnforced, false, "the template is self-hosted (tenancy off)");
      w = azWallets(template);
      const rpc = mockRpc();
      const restore = useAnchorDaa(0n);
      ids = {};
      try { for (const seed of seeders) Object.assign(ids, await seed(template, w, rpc)); } finally { restore(); }
      templateRpc = rpc; // RC45 L2-01 guard inventory: the template's mock table (it carries the root output a root build reads)
      history = await KK.kasSnapshot(template);
      templateRoot = template.dataRoot;
      if (PG_AVAILABLE) admin = new (require("pg").Pool)(PG);
      return ids;
    },
    async teardown() {
      for (const s of stores) { try { await s.close(); } catch { /* closed */ } }
      if (admin) { for (const db of databases) await admin.query(`DROP DATABASE IF EXISTS ${db} WITH (FORCE)`); await admin.end(); }
      for (const root of roots) K.removeOwnedRoot(root);
    },
    /* A fresh case with the template installed: backend "JSON" | "PostgreSQL" (hosted) | "self-hosted" (JSON, tenancy off). */
    async fresh(backend) {
      const config0 = sdk("config.js");
      const dataRoot = mk(`pv-rc45-${prefix}-case-`);
      KK.warmAllCaches(templateRoot, dataRoot);
      const hosted = { authMode: "enabled", authCookieInsecure: true, dataRoot, rpcUrl: LOOPBACK, rateLimits: RATE_LIMITS };
      let config, pgDatabase = null;
      if (backend === "PostgreSQL") {
        pgDatabase = `pv_rc45_${prefix.replace(/[^a-z0-9]/g, "_")}_${process.pid}_${++serial}`;
        await admin.query(`CREATE DATABASE ${pgDatabase}`); databases.push(pgDatabase);
        config = config0.loadConfig({ persistenceBackend: "postgres", pgHost: PG.host, pgPort: PG.port, pgUser: PG.user, pgDatabase, pgNoTls: true, ...hosted });
        stores.push(await store().openPgStore(config, { migrate: true }));
        assert.equal(store().getStore(config).kind, "postgres");
        assert.equal(config.tenancyEnforced, true);
      } else if (backend === "JSON") {
        config = config0.loadConfig(hosted);
        assert.equal(config.tenancyEnforced, true);
      } else if (backend === "self-hosted") {
        config = config0.loadConfig({ dataRoot, rpcUrl: LOOPBACK });
        assert.equal(config.tenancyEnforced, false);
      } else throw new Error(`unknown backend ${backend}`);
      await K.install({ store: store() }, config, history);
      if (templateRpc) require("./guard-node").registerFixtureNode(config, templateRpc); // RC45 L2-01 guard inventory: a case reads the template's chain
      const api = F3.apiFor(config), cookies = new Map();
      const x = {
        config, pgDatabase, w, ids, backend,
        store: store().getStore(config),
        /* a wallet session (cached per case); self-hosted cases have no sessions */
        as: async (wallet) => {
          if (!config.tenancyEnforced) return null;
          if (!cookies.has(wallet.xonly)) cookies.set(wallet.xonly, await api.signIn(wallet));
          return cookies.get(wallet.xonly);
        },
        /* the real hosted route handler; auth: null (no principal) | a cookie string | { authorization: "Bearer ..." } */
        call: (method, segments, body, auth = null, query = {}) => {
          const { handle } = require("../../server/src/api");
          const ctx = auth === null ? {} : typeof auth === "string" ? { headers: { cookie: auth } } : { headers: auth };
          return handle(config, method, segments, query, body, ctx).then(
            (r) => ({ status: r.status, code: null, body: r.body, message: null }),
            (e) => { if (e && e.code === "ERR_ASSERTION") throw e; return { status: e && e.status !== undefined ? e.status : null, code: e && e.code ? e.code : null, body: null, message: String(e && e.message), extra: e && e.extra }; }
          );
        },
        /* every durable record family a reject could write (vaults, requests, roots, root requests, both claim kinds,
         * receipts) plus the audit, in sorted-key JSON (a rewrite with a new updatedAt is a write) */
        state: async () => KK.strictJson(await KK.kasSnapshot(config)),
        record: async (id) => KK.strictJson(await store().getStore(config).read(store().Categories.REQUEST, id)),
        stored: (id) => store().getStore(config).read(store().Categories.REQUEST, id)
      };
      /* a machine credential minted by `wallet` (its own session) */
      x.credential = async (wallet, scopes) => {
        const r = await x.call("POST", ["identities"], { label: "R2 TEST machine", scopes }, await x.as(wallet));
        assert.equal(r.status, 201, `machine credential minted by ${wallet.xonly.slice(0, 8)} (${said(r)})`);
        return { authorization: `Bearer ${r.body.credential.token}` };
      };
      return x;
    },
    async release(x) {
      if (!x.pgDatabase) return;
      const s = x.store, i = stores.indexOf(s);
      if (i >= 0) { stores.splice(i, 1); await s.close(); }
    }
  };
  return S;
}

/* ---------------- request bodies ---------------- */
/* A v0.7-kas delegate spend of `kas` KAS to the recipient (offline: the vault's own fee reserve pays). */
const kasSpendBody = (ids, w, signer, kas) => ({ vaultId: ids.kasVaultId, action: "agentSpend", signerAddress: signer.address, params: { payAmountSompi: (BigInt(kas) * KAS).toString(), recipient: w.recipient.xonly } });
/* A first token deposit of the signer's own KCC20 position into a rooted payment / HD vault (fuel supplied). */
function tokenDepositBody(config, vaultId, signer, w, tag) {
  const assets = require("../../core/assets");
  const { compileKcc20Program } = sdk("token-program-kcc20.js");
  const st = { ownerIdentifier: signer.xonly, identifierType: assets.kcc20.OWNER_SCHEMES.P2PK, amount: 500n, isMinter: false };
  const prog = compileKcc20Program({ config, state: st, familyBound: 2 });
  return { vaultId, action: "tokenDeposit", signerAddress: signer.address, params: { userPosition: { outpoint: { transactionId: K.hex(`rc45-r2-az-position-${tag}-${crypto.randomUUID()}`), index: 0 }, value: (2n * KAS).toString(), scriptPublicKeyHex: prog.p2shSpkHex, covenantId: H(0x54), state: { ...st, amount: "500" } }, fuel: p2pk(w.fuel, `deposit-${tag}`), depositAmount: "300", depositCarryKasSompi: KAS.toString() } };
}

/* ---------------- token-controller request bodies (v0.5 / v0.6) ---------------- */
/* The owner's fuel-funded owner operation on a controller (offline: the fee comes from the supplied fuel UTXO). */
const ownerOpBody = (vaultId, w, action, extra = {}, tag = action) => ({ vaultId, action, signerAddress: w.o1.address, params: { fuel: p2pk(w.fuel, `${tag}-fuel`), ...extra } });
/* A delegate's reserve-funded token spend from the controller's token position (the position is supplied; offline). */
function tokenSpendBody(config, gen, vaultId, covenantId, signer, w) {
  const assets = require("../../core/assets");
  const { compileKcc20Program } = sdk("token-program-kcc20.js");
  const st = { ownerIdentifier: covenantId, identifierType: assets.kcc20.OWNER_SCHEMES.COVENANT_ID, amount: 300n, isMinter: false };
  const prog = compileKcc20Program({ config, state: st, familyBound: 2 });
  const policy = gen === "v6" ? tokenPolicyV6 : tokenPolicy;
  return { vaultId, action: "tokenAgentSpend", signerAddress: signer.address, params: {
    spendAmount: "100", agents: [policyOnly(policy(w.agentA, w.recipient)), policyOnly(policy(w.agentB, w.recipient))], recipient: w.recipient.xonly, recipients: [w.recipient.xonly], recipientCarryKasSompi: (KAS / 4n).toString(),
    tokenPosition: { outpoint: { transactionId: K.hex(`rc45-r2-az-controller-position-${gen}-${crypto.randomUUID()}`), index: 0 }, value: (2n * KAS).toString(), scriptPublicKeyHex: prog.p2shSpkHex, covenantId: H(0x54), state: { ...st, amount: "300" } }
  } };
}

module.exports = {
  K, KK, F3, KAS, LOOPBACK, D, H, said, azWallets, p2pk, mockRpc, utxo, spkAddress, signAll, approvalSignatureHex,
  descriptorFor, kasDelegate, tokenPolicy, tokenPolicyV6, hdLeaf, policyOnly, seedRootedVaults, seedTokenControllers, azSuite, kasSpendBody, tokenDepositBody,
  ownerOpBody, tokenSpendBody, useAnchorDaa
};
