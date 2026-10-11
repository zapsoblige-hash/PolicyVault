"use strict";
/*
 * RC45 R2 test kit for the v0.7-kas delegate period-start legs:
 *   sdk/test/rc45-r2-04-kas-anchor.test.js            (anchor at build)
 *   sdk/test/rc45-r2-05-kas-commit-freshness.test.js  (freshness before the point of no return, stale withdrawal)
 *   sdk/test/rc45-r2-06-codes.test.js                 (closed codes over the real routes)
 * Internal RED-first regression material; not an audit.
 *
 * On top of the R2 kit (sdk/testutil/rc45-r2-kit.js: the node DAA test seam useAnchorDaa,
 * the F5/F3 helpers, the friendly-create node patch) it adds:
 *   - kasSuite(prefix, seed): a self-hosted JSON TEMPLATE built with the real
 *     SDK — an organizational root (owners 0x71 / 0x72 / 0x73, 2-of-3) whose
 *     genesis is driven to CHAIN_VERIFIED, and a rooted v0.7-kas treasury (two
 *     installed delegates, one with a lagging period start) driven to
 *     CHAIN_VERIFIED — against an explicit mock chain; the template is built with
 *     the node DAA seam at 0, which is at or below every template start, so the
 *     template's committed bytes are the requested bytes on every runtime. Fresh
 *     HOSTED cases install it on the JSON store or on a fresh PostgreSQL database
 *     (the rc45 runner's pg mode; a skipped PostgreSQL leg there is a FAIL), with
 *     the owners signed in through /auth (TEST keys);
 *   - the route helpers of the v0.7-kas flows: treasury genesis (POST
 *     /org-roots/:id/vaults), its funder signature / submit / withdrawal
 *     (/wallet/v7/requests/:id/...), root requests (POST /org-roots/:id/requests),
 *     owner slot signatures, M-of-N finalize (real fee signature; the server runs
 *     the pinned pv_vm_preflight over the assembled transaction), submit and
 *     withdrawal;
 *   - chainNode: an explicit mock chain (getBlockDagInfo with a chosen virtual
 *     DAA score, getUtxosByAddresses over a UTXO table, submitTransaction that
 *     counts broadcasts and applies the frozen transaction's effect — inputs
 *     spent, outputs created — only when that exact transaction id is
 *     broadcast). Route-level calls that open their own node connection reach it
 *     through the R2 kit's connectVerified patch (installKasNodePatch must run
 *     before anything loads server/src/api.js or the v7 request modules);
 *   - durable snapshots of every record family a v0.7-kas refusal must leave
 *     untouched (vault, wallet requests, root requests, roots, both claim kinds,
 *     receipts).
 *
 * Nothing dials a node: every config names ws://127.0.0.1:1 and every node
 * observation comes from an explicit mock. TEST keys only.
 */
const path = require("node:path"), fs = require("node:fs");
const assert = require("node:assert/strict");
const R = require("./rc45-r2-kit");
const { K, F3, KAS, LOOPBACK, D, DAY, HOUR, windowDaa, said, nodeDown, useAnchorDaa, withAnchor } = R;

const SDK_SRC = path.join(__dirname, "..", "src");
const sdk = (name) => require(path.join(SDK_SRC, name));
const lazy = {
  get wr7() { return sdk("wallet-requests-v7.js"); },
  get wr7kas() { return sdk("wallet-requests-v7-kas.js"); },
  get manifestKas() { return sdk("manifest-v7-kas.js"); },
  get chain() { return sdk("chain.js"); },
  get store() { return sdk("store.js"); }
};

/* The R2 kit's connectVerified patch, asserted to precede every module that captures connectVerified at load. */
function installKasNodePatch() {
  for (const f of ["wallet-requests-v7.js", "wallet-requests-v7-kas.js", "wallet-requests-v7-hd.js"]) {
    assert.equal(require.cache[path.join(SDK_SRC, f)], undefined, `the node patch must be installed before sdk/src/${f} loads (it destructures connectVerified)`);
  }
  return R.installNodePatch();
}

/* ---------------- TEST wallets ---------------- */
function walletOf(config, byte) {
  const kaspa = require(config.rustyKaspaModule);
  const secretHex = byte.toString(16).padStart(2, "0").repeat(32), priv = new kaspa.PrivateKey(secretHex);
  return { byte, secretHex, key: priv, xonly: priv.toPublicKey().toXOnlyPublicKey().toString().toLowerCase(), address: priv.toPublicKey().toAddress(config.networkId).toString() };
}
/* owners 0x71..0x73 (slots 1..3), installed delegates A 0x62 and B 0x66, their recipient 0x63, the root-op fee payer
 * 0x64, the treasury's recovery key 0x51, new delegate keys 0x41..0x46, a stranger 0x99. */
function kasWallets(config) {
  const o = (b) => walletOf(config, b);
  return { o1: o(0x71), o2: o(0x72), o3: o(0x73), agentA: o(0x62), agentB: o(0x66), recipient: o(0x63), fee: o(0x64), recovery: o(0x51), n1: o(0x41), n2: o(0x42), n3: o(0x43), n4: o(0x44), n5: o(0x45), n6: o(0x46), stranger: o(0x99) };
}
/* A v0.4.1 delegate policy entry with its recipient allowlist (the genesis / ownerSetAgentRoot `agents` shape). */
function kasDelegate(agentPk, recipients, over = {}) {
  return { agentPk, maxPerSpend: (5n * KAS).toString(), periodBudget: (20n * KAS).toString(), periodLengthDaa: DAY.toString(), periodStartDaa: "0", periodSpent: "0", approvalThreshold: (2n * KAS).toString(), agentMaxFeePerTx: (KAS / 10n).toString(), recipients: [...recipients], ...over };
}
/* An ordinary P2PK UTXO of `wallet` (TEST outpoint). */
function p2pkUtxo(wallet, tag, amountKas = 50n) {
  return { outpoint: { transactionId: K.hex(`rc45-r2-kas-utxo-${tag}`), index: 0 }, amount: (BigInt(amountKas) * KAS).toString(), scriptPublicKeyHex: `20${wallet.xonly}ac` };
}

/* ---------------- the explicit mock chain ---------------- */
function spkAddress(config, spk) {
  return lazy.chain.loadKaspa(config).addressFromScriptPublicKey({ version: spk.version, script: spk.scriptHex }, config.networkId).toString();
}
/*
 * Opt-ins (RC45 L2-01 legs; the defaults above are unchanged when none is used):
 *   stampAcceptingDaa  every output put while it is on carries the node's virtual DAA at that moment (the accepting
 *                      DAA) and getUtxosByAddresses answers that stamp as the entry's blockDaaScore; entries without a
 *                      stamp keep the read-time answer (state.daa). setStamping(on) switches it after construction;
 *   node.afterRead(pred, nth, mutate)  after the nth node call c with pred(c) true (c = { method, addresses }) has
 *                      computed its answer, mutate() runs once (the call itself still sees the state before it);
 *   node.reads()       every node call made so far ({ method, addresses }), for counting wrappers;
 *   node.spendOutpoint / putEntry / entryAt / mutateEntry   direct table edits (an out-of-app spend, a reorg that
 *                      restores an output, a non-exact or non-canonical entry); mutateEntry returns its restore().
 * RC45 R3N-B1a inventory (contract rc45-l201-contract-03 §8; clarification 01 item 2 (a); mock capabilities only):
 *   node.rpc carries the selected-chain walk of the shared seam (sdk/testutil/guard-node.js chainWalk: the 20-hop
 *                      walk below this node's sink, header-bound anchor), which the B1 runtime reads at build, submit
 *                      and withdrawal;
 *   node.seedFuel(fuel)  the fee payer's supplied fee UTXO is on the node before the build reads it (the B1
 *                      build observes every non-root frozen input live and exact, D6b), as the real chain carries a
 *                      fee payer's UTXO: put at its outpoint with its amount and P2PK script and an accepting DAA
 *                      FUEL_DEPTH below the virtual (an ordinary wallet UTXO older than 1,000 DAA), unless it is
 *                      already in the table or this node already spent it (never resurrected). Returns `fuel`.
 */
const FUEL_DEPTH = 100000n;
function chainNode(config, { daa = D, table = null, stampAcceptingDaa = false } = {}) {
  const utxos = new Map(); // address -> [{ address, outpoint, amount, covenantId, scriptPublicKey, daaStamp? }]
  if (table) for (const [address, entries] of table) utxos.set(address, entries.map((e) => ({ ...e, outpoint: { ...e.outpoint }, scriptPublicKey: e.scriptPublicKey ? { ...e.scriptPublicKey } : undefined })));
  const state = { daa: BigInt(daa), broadcasts: [], calls: [], effects: new Map(), stamp: stampAcceptingDaa === true, reads: [], hooks: [] };
  const put = (address, entry) => utxos.set(address, [...(utxos.get(address) ?? []), { address, ...entry, ...(state.stamp && entry.daaStamp === undefined ? { daaStamp: state.daa.toString() } : {}) }]);
  const sameOp = (e, outpoint) => e.outpoint.transactionId === String(outpoint.transactionId).toLowerCase() && Number(e.outpoint.index) === Number(outpoint.index);
  const spentOutpoints = new Set();
  const spend = (outpoint) => {
    spentOutpoints.add(`${String(outpoint.transactionId).toLowerCase()}:${Number(outpoint.index)}`);
    for (const [address, entries] of utxos) utxos.set(address, entries.filter((e) => !sameOp(e, outpoint)));
  };
  /* opt-in bookkeeping: record the call, then run the afterRead hooks it completes */
  const seen = (method, addresses) => {
    const call = { method, addresses: addresses ? addresses.map(String) : null };
    state.reads.push(call);
    return () => {
      for (const h of state.hooks) {
        if (h.done || !h.pred(call)) continue;
        h.count += 1;
        if (h.count === h.nth) { h.done = true; h.mutate(call); }
      }
    };
  };
  const node = {
    state,
    rpc: {
      async getBlockDagInfo() {
        state.calls.push("getBlockDagInfo");
        const after = seen("getBlockDagInfo", null);
        const answer = { virtualDaaScore: state.daa.toString(), sink: "39".repeat(32), networkName: "kaspa-testnet-10" };
        after();
        return answer;
      },
      async getUtxosByAddresses({ addresses }) {
        state.calls.push("getUtxosByAddresses");
        const after = seen("getUtxosByAddresses", addresses);
        const entries = [];
        for (const a of addresses.map(String)) for (const e of utxos.get(a) ?? []) {
          entries.push({ address: a, outpoint: { ...e.outpoint }, utxoEntry: { amount: e.amount.toString(), scriptPublicKey: e.scriptPublicKey ?? { version: 0, script: "" }, covenantId: e.covenantId ?? undefined, blockDaaScore: e.daaStamp !== undefined ? e.daaStamp : state.daa.toString(), isCoinbase: false } });
        }
        after();
        return { entries };
      },
      async submitTransaction({ transaction }) {
        state.calls.push("submitTransaction");
        const id = transaction.finalize().toString().toLowerCase();
        state.broadcasts.push(id);
        const fx = state.effects.get(id);
        if (fx) fx();
        return { transactionId: id };
      },
      async getMempoolEntry() { state.calls.push("getMempoolEntry"); throw new Error("TEST mock: transaction not found in the mempool"); },
      async disconnect() { state.calls.push("disconnect"); }
    },
    table: () => new Map([...utxos].map(([a, es]) => [a, es.map((e) => ({ ...e }))])),
    seedP2pk(wallet, outpoint, amountSompi) { put(wallet.address, { outpoint: { transactionId: outpoint.transactionId.toLowerCase(), index: outpoint.index }, amount: BigInt(amountSompi), covenantId: null, scriptPublicKey: { version: 0, script: `20${wallet.xonly}ac` } }); },
    seedFuel(fuel) {
      const op = { transactionId: String(fuel.outpoint.transactionId).toLowerCase(), index: Number(fuel.outpoint.index) };
      const script = String(fuel.scriptPublicKeyHex).toLowerCase();
      if (node.entryAt(op) === null && !spentOutpoints.has(`${op.transactionId}:${op.index}`)) put(spkAddress(config, { version: 0, scriptHex: script }), { outpoint: op, amount: BigInt(fuel.amount), covenantId: null, scriptPublicKey: { version: 0, script }, daaStamp: (state.daa > FUEL_DEPTH ? state.daa - FUEL_DEPTH : 0n).toString() });
      return fuel;
    },
    /* When `txId` is broadcast: its inputs are spent and its frozen outputs exist. */
    expectFrozen(frozen, txId) {
      state.effects.set(String(txId).toLowerCase(), () => {
        for (const input of frozen.inputs) spend(input.previousOutpoint);
        frozen.outputs.forEach((o, i) => put(spkAddress(config, o.scriptPublicKey), { outpoint: { transactionId: String(txId).toLowerCase(), index: i }, amount: BigInt(o.value), covenantId: o.covenant ? String(o.covenant.covenantId).toLowerCase() : null, scriptPublicKey: { version: o.scriptPublicKey.version, script: o.scriptPublicKey.scriptHex } }));
      });
    },
    broadcasts: () => state.broadcasts.length,
    /* ---- opt-ins ---- */
    setStamping(on) { state.stamp = on === true; },
    afterRead(pred, nth, mutate) { assert.ok(Number.isInteger(nth) && nth >= 1, "afterRead: nth is a 1-based count"); state.hooks.push({ pred, nth, mutate, count: 0, done: false }); },
    reads: () => state.reads.map((c) => ({ method: c.method, addresses: c.addresses ? [...c.addresses] : null })),
    spendOutpoint(outpoint) { spend(outpoint); },
    putEntry(address, entry) { put(String(address), { ...entry, outpoint: { transactionId: String(entry.outpoint.transactionId).toLowerCase(), index: Number(entry.outpoint.index) }, amount: BigInt(entry.amount) }); },
    entryAt(outpoint) {
      for (const [address, entries] of utxos) for (const e of entries) if (sameOp(e, outpoint)) return { address, entry: { ...e, outpoint: { ...e.outpoint }, scriptPublicKey: e.scriptPublicKey ? { ...e.scriptPublicKey } : undefined } };
      return null;
    },
    mutateEntry(outpoint, patch) {
      for (const [address, entries] of utxos) {
        const i = entries.findIndex((e) => sameOp(e, outpoint));
        if (i < 0) continue;
        const before = entries[i];
        const next = entries.slice();
        next[i] = { ...before, ...patch };
        utxos.set(address, next);
        return () => { const now = utxos.get(address).slice(); const j = now.findIndex((e) => sameOp(e, outpoint)); if (j >= 0) now[j] = before; else now.push(before); utxos.set(address, now); };
      }
      throw new Error(`TEST mock: no entry at ${outpoint.transactionId}:${outpoint.index} to mutate`);
    }
  };
  require("./guard-node").chainWalk(node.rpc, config);
  return node;
}
/* A stored request's frozen transaction (root requests and KAS requests both keep it under build.frozen). */
const frozenOf = (request) => request.build.frozen;

/* ---------------- signatures (TEST keys) ---------------- */
function kaspaOf(config) { return lazy.chain.loadKaspa(config); }
/* The funder's signatures over every listed input (SIGHASH_ALL). */
function signInputs(config, unsignedSafeJson, signInputsList, wallet) {
  const kaspa = kaspaOf(config);
  const tx = kaspa.Transaction.deserializeFromSafeJSON(unsignedSafeJson);
  const ins = tx.inputs;
  for (const s of signInputsList) ins[s.index].signatureScript = kaspa.createInputSignature(tx, s.index, wallet.key);
  tx.inputs = ins;
  return tx.serializeToSafeJSON();
}
/* An owner slot's raw 65-byte Schnorr signature over the root input. */
function slotSignatureHex(config, unsignedSafeJson, rootInputIndex, wallet) {
  const kaspa = kaspaOf(config);
  return kaspa.createInputSignature(kaspa.Transaction.deserializeFromSafeJSON(unsignedSafeJson), rootInputIndex, wallet.key).slice(2, 2 + 130);
}
/* The fee payer's signature script over the root request's fee input (the last input). */
function feeSignatureScriptHex(config, request, wallet) {
  const kaspa = kaspaOf(config);
  return kaspa.createInputSignature(kaspa.Transaction.deserializeFromSafeJSON(request.transaction.unsignedSafeJson), frozenOf(request).inputs.length - 1, wallet.key);
}

/* ---------------- registry helpers ---------------- */
const kasJson = (entry) => lazy.manifestKas.registryEntryToJson(entry);
/* The installed registry of a KAS treasury in the stored (registryEntryToJson) form. */
async function installedRegistry(config, vaultId) {
  const m = await lazy.manifestKas.loadManifestV7Kas(config, vaultId);
  assert.ok(m, `the KAS treasury ${vaultId.slice(0, 8)} exists`);
  return m.agentRegistry.map(kasJson);
}
/* Every `agentSet` array carried by a manifest document (the owners' reviewed policy set). */
function agentSetsOf(doc) {
  const out = [];
  (function walk(v) {
    if (Array.isArray(v)) { v.forEach(walk); return; }
    if (v && typeof v === "object") for (const [k, x] of Object.entries(v)) { if (k === "agentSet" && Array.isArray(x)) out.push(x); else walk(x); }
  })(doc);
  return out;
}

/* ---------------- durable snapshots ---------------- */
function kasCategories() {
  const C = lazy.store.Categories;
  return [C.VAULT, C.REQUEST, C.ORG_ROOT, C.ORG_ROOT_REQUEST, C.SUBMISSION_CLAIM, C.TRANSITION_CLAIM, C.RECEIPT];
}
async function kasRecords(config) {
  const s = lazy.store.getStore(config), out = {};
  for (const c of kasCategories()) out[c] = await Promise.all((await s.listKeys(c)).sort().map(async (k) => [k, await s.read(c, k)]));
  return out;
}
async function kasSnapshot(config) { return { records: await kasRecords(config), audit: await lazy.store.getStore(config).readAudit({ limit: 5000 }) }; }
/* Sorted-key JSON that drops nothing (a rewrite with a new updatedAt is a write). */
function strictJson(value) {
  if (Array.isArray(value)) return `[${value.map(strictJson).join(",")}]`;
  if (value && typeof value === "object") return `{${Object.keys(value).sort().map((k) => `${JSON.stringify(k)}:${strictJson(value[k])}`).join(",")}}`;
  return JSON.stringify(value);
}
/* Every record family except the audit (a refusal may log; it writes no record), exactly. */
async function scope(config) { return strictJson(await kasRecords(config)); }

/* Copy every compile cache (real-silverc artifacts keyed by state under dataRoot) from the template to a case. */
function warmAllCaches(fromRoot, toRoot) {
  for (const sub of fs.readdirSync(fromRoot)) {
    if (!/^build/.test(sub)) continue;
    const from = path.join(fromRoot, sub);
    if (fs.statSync(from).isDirectory()) fs.cpSync(from, path.join(toRoot, sub), { recursive: true, force: false, errorOnExist: false });
  }
}

/* ---------------- the template: root + KAS treasury, CHAIN_VERIFIED ---------------- */
/*
 * Builds, in a self-hosted JSON data root, with the SDK and the mock chain:
 *   - the organizational root ROOT (owners o1/o2/o3 in slots 1/2/3, ownerM 2, emergencyK 1, recoveryM 1), funded by o1;
 *   - the KAS treasury (vaultId kasVaultId) with `agents` installed (100 KAS principal, 5 KAS fee reserve), funded by o1;
 * both driven to CHAIN_VERIFIED. The node DAA seam answers 0 throughout (at or below every template start).
 */
async function buildRootAndTreasury(config, w, node, { label = "RC45 R2 TEST", agents, kasVaultId, approvers = [], approvalM = 0 }) {
  const restore = useAnchorDaa(0n);
  try {
    const wr7 = lazy.wr7, wr7kas = lazy.wr7kas;
    const rootFunding = p2pkUtxo(w.o1, `${label}-root-funding`, 20n);
    node.seedP2pk(w.o1, rootFunding.outpoint, rootFunding.amount);
    const rootReq = await wr7.buildRootGenesisRequest({
      config, label: `${label} root`,
      owners: [{ slot: 1, publicKey: w.o1.xonly }, { slot: 2, publicKey: w.o2.xonly }, { slot: 3, publicKey: w.o3.xonly }],
      ownerM: 2, emergencyK: 1, recoveryM: 1, recoveryDelayDaa: "600", successionDelayDaa: "600", successorAddress: null,
      rootValueKas: "2", rootMaxFeePerTxKas: "0.01", signerAddress: w.o1.address, funding: [rootFunding]
    });
    const signedRoot = await wr7.submitOrgRootRequestSignature({ config, requestId: rootReq.id, signedSafeJson: signInputs(config, rootReq.transaction.unsignedSafeJson, rootReq.transaction.signInputs, w.o1) });
    assert.equal(signedRoot.state, "SIGNED");
    node.expectFrozen(signedRoot.build.frozen, signedRoot.txId);
    const rootDone = await wr7.submitOrgRootRequest({ config, requestId: rootReq.id, rpc: node.rpc, pollAttempts: 1, pollDelayMs: 0 });
    assert.equal(rootDone.state, "CHAIN_VERIFIED", `template root genesis: ${rootDone.error ?? ""}`);
    const rootId = rootReq.rootCovenantId;

    const kasFunding = p2pkUtxo(w.o1, `${label}-kas-funding`, 200n);
    node.seedP2pk(w.o1, kasFunding.outpoint, kasFunding.amount);
    const kasReq = await wr7kas.buildKasVaultGenesisRequest({ config, rootCovenantId: rootId, label: `${label} treasury`, agents, approvers, approvalM, recoveryAddress: w.recovery.address, depositKas: "100", feeReserveKas: "5", signerAddress: w.o1.address, funding: [kasFunding], vaultId: kasVaultId });
    const signedKas = await wr7kas.finalizeKasWalletRequest({ config, requestId: kasReq.requestId, signedSafeJson: signInputs(config, kasReq.transaction.unsignedSafeJson, kasReq.transaction.signInputs, w.o1) });
    assert.equal(signedKas.state, "SIGNED");
    node.expectFrozen(signedKas.build.frozen, signedKas.txId);
    const kasDone = await wr7kas.submitKasWalletRequest({ config, requestId: kasReq.requestId, rpc: node.rpc, pollAttempts: 1, pollDelayMs: 0 });
    assert.equal(kasDone.state, "CHAIN_VERIFIED", `template treasury genesis: ${kasDone.error ?? ""}`);
    assert.deepEqual(await installedRegistry(config, kasReq.vaultId), lazy.manifestKas.normalizeRegistry(agents).entries.map(kasJson), "the template commits the requested registry");
    return { rootId, vaultId: kasReq.vaultId };
  } finally { restore(); }
}

function kasSuite(prefix) {
  const roots = [], stores = [], databases = [];
  const PG = K.pgFromEnv(), PG_AVAILABLE = Boolean(PG.port && PG.user && PG.database);
  const PG_SKIP = PG_AVAILABLE ? undefined : "REQUIREMENT_NOT_AVAILABLE in this process: isolated PostgreSQL (the rc45 runner's pg mode runs these legs; a skipped PostgreSQL leg there is a FAIL)";
  let admin = null, serial = 0, history = null, templateRoot = null, chainTable = null;
  const mk = (p) => { const dir = K.ownedTempRoot(p); roots.push(dir); return dir; };
  const S = {
    PG_AVAILABLE, PG_SKIP, track: (root) => roots.push(root), mk,
    /* Build the self-hosted template with `seed(template, node)`, snapshot it and its chain. */
    async setup(seed) {
      const template = sdk("config.js").loadConfig({ dataRoot: mk(`pv-rc45-${prefix}-template-`), rpcUrl: LOOPBACK });
      assert.equal(template.tenancyEnforced, false, "the template is self-hosted (tenancy off); every case is hosted");
      const node = chainNode(template);
      const out = await seed(template, node);
      history = await kasSnapshot(template);
      chainTable = node.table();
      templateRoot = template.dataRoot;
      if (PG_AVAILABLE) admin = new (require("pg").Pool)(PG);
      return out;
    },
    async teardown() {
      for (const s of stores) { try { await s.close(); } catch { /* closed */ } }
      if (admin) { for (const db of databases) await admin.query(`DROP DATABASE IF EXISTS ${db} WITH (FORCE)`); await admin.end(); }
      for (const root of roots) K.removeOwnedRoot(root);
    },
    /* A fresh HOSTED case with the template installed; owners o1..o3 signed in. */
    async fresh(backend, w, { daa = D, stampAcceptingDaa = false } = {}) {
      const config0 = sdk("config.js");
      const dataRoot = mk(`pv-rc45-${prefix}-case-`);
      warmAllCaches(templateRoot, dataRoot);
      const hosted = { authMode: "enabled", authCookieInsecure: true, dataRoot, rpcUrl: LOOPBACK };
      let config, pgDatabase = null;
      if (backend === "PostgreSQL") {
        pgDatabase = `pv_rc45_${prefix.replace(/[^a-z0-9]/g, "_")}_${process.pid}_${++serial}`;
        await admin.query(`CREATE DATABASE ${pgDatabase}`); databases.push(pgDatabase);
        config = config0.loadConfig({ persistenceBackend: "postgres", pgHost: PG.host, pgPort: PG.port, pgUser: PG.user, pgDatabase, pgNoTls: true, ...hosted });
        stores.push(await lazy.store.openPgStore(config, { migrate: true }));
        assert.equal(lazy.store.getStore(config).kind, "postgres");
      } else config = config0.loadConfig(hosted);
      assert.equal(config.tenancyEnforced, true);
      await K.install({ store: lazy.store }, config, history);
      const store = lazy.store.getStore(config), api = F3.apiFor(config);
      const node = chainNode(config, { daa, table: chainTable, stampAcceptingDaa });
      const x = {
        config, store, api, pgDatabase, w, node,
        cookie: { o1: await api.signIn(w.o1), o2: await api.signIn(w.o2), o3: await api.signIn(w.o3) },
        call: (method, segments, body, auth = null, query = {}) => {
          const { handle } = require("../../server/src/api");
          const ctx = auth === null ? {} : typeof auth === "string" ? { headers: { cookie: auth } } : { headers: auth };
          return handle(config, method, segments, query, body, ctx).then(
            (r) => ({ status: r.status, code: null, body: r.body, message: null }),
            (e) => { if (e && e.code === "ERR_ASSERTION") throw e; return { status: e && e.status !== undefined ? e.status : null, code: e && e.code ? e.code : null, body: null, message: String(e && e.message), extra: e && e.extra }; }
          );
        },
        snap: () => kasSnapshot(config),
        scope: () => scope(config),
        rootRecord: (rootId) => lazy.wr7.loadOrgRoot(config, rootId),
        rootReq: (id) => lazy.wr7.loadOrgRootRequest(config, id),
        kasReq: (id) => lazy.wr7kas.loadKasWalletRequest(config, id),
        installed: (vaultId) => installedRegistry(config, vaultId),
        vault: (vaultId) => lazy.manifestKas.loadManifestV7Kas(config, vaultId),
        /* store-damage / sabotage modelling: read-modify-write of a stored record */
        editRootReq: async (id, fn) => { const C = lazy.store.Categories, rec = await store.read(C.ORG_ROOT_REQUEST, id); fn(rec); await store.write(C.ORG_ROOT_REQUEST, id, rec); return rec; },
        editKasReq: async (id, fn) => { const C = lazy.store.Categories, rec = await store.read(C.REQUEST, id); fn(rec); await store.write(C.REQUEST, id, rec); return rec; },
        removeVault: (vaultId) => store.remove(lazy.store.Categories.VAULT, vaultId),
        recordJson: async (category, key) => strictJson(await store.read(lazy.store.Categories[category], key))
      };
      /* ---- the treasury genesis (POST /org-roots/:id/vaults, profile policyvault-0.7-kas) ---- */
      x.kasGenesis = (rootId, body, cookie = x.cookie.o1) => x.call("POST", ["org-roots", rootId, "vaults"], { profile: "policyvault-0.7-kas", ...body }, cookie);
      x.kasSign = async (requestId, wallet = w.o1, cookie = x.cookie.o1) => {
        const q = await x.kasReq(requestId);
        return x.call("POST", ["wallet", "v7", "requests", requestId, "signature"], { signedSafeJson: signInputs(config, q.transaction.unsignedSafeJson, q.transaction.signInputs, wallet) }, cookie);
      };
      x.kasSubmit = async (requestId, cookie = x.cookie.o1) => {
        const q = await x.kasReq(requestId);
        if (q && q.build && q.build.frozen) node.expectFrozen(q.build.frozen, q.txId);
        return NODE().with(node.rpc, () => x.call("POST", ["wallet", "v7", "requests", requestId, "submit"], {}, cookie));
      };
      x.kasReject = (requestId, cookie = x.cookie.o1) => x.call("POST", ["wallet", "v7", "requests", requestId, "reject"], {}, cookie);
      /* ---- root requests ---- */
      x.rootBuild = (rootId, body, cookie = x.cookie.o1) => x.call("POST", ["org-roots", rootId, "requests"], body, cookie);
      x.slotSign = async (rootId, requestId, slot, wallet, cookie) => {
        const env = await x.call("GET", ["org-roots", rootId, "requests", requestId, "slot-request", String(slot)], null, cookie);
        assert.equal(env.status, 200, `slot ${slot} signing request (${said(env)})`);
        const e = env.body.slotRequest, q = await x.rootReq(requestId);
        const response = { responseVersion: "policyvault-org-root-slot-response/1", requestVersion: e.requestVersion, requestId: e.requestId, network: e.network, manifestHash: e.manifestHash, txId: e.txId, root: e.root, slot: e.slot, signerAddress: wallet.address, signatureHex: slotSignatureHex(config, q.transaction.unsignedSafeJson, q.rootInputIndex, wallet), sighashType: 1, signedAtMs: Date.now() };
        const r = await x.call("POST", ["org-roots", rootId, "requests", requestId, "slot-signatures"], { slot, response }, cookie);
        assert.equal(r.status, 200, `slot ${slot} signature attached (${said(r)})`);
        return r;
      };
      /* owners 1 and 2 attach their slot signatures (the 2-of-3 quorum) */
      x.quorum = async (rootId, requestId) => { await x.slotSign(rootId, requestId, 1, w.o1, x.cookie.o1); await x.slotSign(rootId, requestId, 2, w.o2, x.cookie.o2); };
      x.rootFinalize = async (rootId, requestId, feeWallet = w.fee, cookie = x.cookie.o1) => {
        const q = await x.rootReq(requestId);
        return x.call("POST", ["org-roots", rootId, "requests", requestId, "finalize"], { fuelSignatureScriptHex: feeSignatureScriptHex(config, q, feeWallet) }, cookie);
      };
      x.rootSubmit = async (rootId, requestId, cookie = x.cookie.o1) => {
        const q = await x.rootReq(requestId);
        if (q && q.build && q.build.frozen) node.expectFrozen(q.build.frozen, q.txId);
        return NODE().with(node.rpc, () => x.call("POST", ["org-roots", rootId, "requests", requestId, "submit"], {}, cookie));
      };
      x.rootReject = (rootId, requestId, cookie = x.cookie.o1) => x.call("POST", ["org-roots", rootId, "requests", requestId, "reject"], { reason: "RC45 R2 TEST withdrawal" }, cookie);
      /* an ownerSetAgentRoot on the treasury riding AUTHORIZE, fee from the fee payer's supplied UTXO (or from the node when fuel is null).
       * RC45 L2-01 guard inventory (mock seeding): these two root builds run inside the route-level node answering THIS
       * case's mock chain, which carries the root and treasury outputs the real chain would carry, so a build-time read of
       * the configured node reaches it (a supplied fee input never needed the node; the node-funded fee path already ran
       * inside it). */
      /* R3N-B1a inventory: a supplied fee UTXO is seeded on this case's node before the build (node.seedFuel) */
      x.setAgents = (rootId, vaultId, agents, { tag, fuel = undefined, cookie = x.cookie.o1, signer = w.o1 } = {}) => NODE().with(node.rpc, () => x.rootBuild(rootId, {
        action: "authorize",
        params: fuel === null ? {} : { fuel: node.seedFuel(fuel ?? p2pkUtxo(w.fee, `${prefix}-${tag}-fee`)) },
        vaultOperations: [{ vaultId, action: "ownerSetAgentRoot", params: { agents } }],
        signerAddress: signer.address
      }, cookie));
      x.vaultOp = (rootId, vaultId, action, params, { tag, rootAction = "authorize" } = {}) => NODE().with(node.rpc, () => x.rootBuild(rootId, { action: rootAction, params: { fuel: node.seedFuel(p2pkUtxo(w.fee, `${prefix}-${tag}-fee`)) }, vaultOperations: [{ vaultId, action, params }], signerAddress: w.o1.address }));
      /* ---- external callers: an owner-minted machine credential, the real HTTP server (SDK client, MCP adapter) ---- */
      x.credential = async (scopes, cookie = x.cookie.o1) => {
        const r = await x.call("POST", ["identities"], { label: "RC45 R2 TEST machine", scopes }, cookie);
        assert.equal(r.status, 201, `owner-minted machine credential (${said(r)})`);
        return r.body.credential.token;
      };
      x.http = async () => {
        const { createServer } = require("../../server/src/server");
        const server = createServer(config);
        await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
        const baseUrl = `http://127.0.0.1:${server.address().port}`;
        return { baseUrl, close: () => new Promise((resolve) => { server.closeAllConnections?.(); server.close(() => resolve()); }) };
      };
      return x;
    },
    async release(x) {
      if (!x.pgDatabase) return;
      const i = stores.indexOf(x.store);
      if (i >= 0) { stores.splice(i, 1); await x.store.close(); }
    }
  };
  return S;
}

/* The real MCP adapter session (mcp/server.js createMcpSession) over in-process line-framed streams, exactly as its
 * stdio transport frames them; it reaches the API only through its own HTTP client with the given credential. */
function mcpSession({ baseUrl, token }) {
  const { PassThrough } = require("node:stream");
  const { createMcpSession } = require("../../mcp/server");
  const input = new PassThrough(), output = new PassThrough(), errput = new PassThrough();
  output.setEncoding("utf8"); errput.setEncoding("utf8");
  let buf = "", stderr = "";
  const inbox = [], waiters = [];
  const drain = () => {
    for (let i = waiters.length - 1; i >= 0; i--) {
      const at = inbox.findIndex((m) => m.id === waiters[i].id && (m.result !== undefined || m.error !== undefined));
      if (at >= 0) { const [m] = inbox.splice(at, 1); const [wt] = waiters.splice(i, 1); clearTimeout(wt.timer); wt.resolve(m); }
    }
  };
  output.on("data", (chunk) => {
    buf += chunk;
    let nl;
    while ((nl = buf.indexOf("\n")) >= 0) { const line = buf.slice(0, nl); buf = buf.slice(nl + 1); if (line) { inbox.push(JSON.parse(line)); drain(); } }
  });
  errput.on("data", (chunk) => { stderr += chunk; });
  const session = createMcpSession({ input, output, errput, env: { POLICYVAULT_MCP_SERVER_URL: baseUrl, POLICYVAULT_MCP_TOKEN: token } });
  const request = (id, method, params) => new Promise((resolve, reject) => {
    const wt = { id, resolve, timer: setTimeout(() => reject(new Error(`TEST MCP: no response to ${method} (${stderr.slice(-500)})`)), 300000) };
    waiters.push(wt);
    input.write(`${JSON.stringify({ jsonrpc: "2.0", id, method, ...(params !== undefined ? { params } : {}) })}\n`);
    drain();
  });
  return {
    stderr: () => stderr,
    async start() {
      await session.start();
      const init = await request("init", "initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "rc45-r2-test", version: "0.0.0" } });
      assert.ok(init.result, `MCP initialize (${JSON.stringify(init.error ?? null)})`);
      input.write(`${JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" })}\n`);
    },
    callTool: (id, name, args) => request(id, "tools/call", { name, arguments: args }),
    close: () => session.close()
  };
}

/* The route-level node: the R2 kit's connectVerified patch (installKasNodePatch). */
let NODE_PATCH = null;
function NODE() { assert.ok(NODE_PATCH, "installKasNodePatch() must run before the suite uses a route-level node"); return NODE_PATCH; }
function installNode() { NODE_PATCH = installKasNodePatch(); return NODE_PATCH; }

/* ---------------- committed-state checks ---------------- */
/* A built treasury genesis commits exactly the root its stored registry folds to; the reviewed summary carries it. */
function assertKasGenesisFolds(q, label) {
  assert.ok(Array.isArray(q.initialRegistry), `${label}: the stored initial registry is an array`);
  assert.equal(R.fold(q.initialRegistry), String(q.build.initialState.agentRoot).toLowerCase(), `${label}: the stored initial registry folds to the genesis build's agent root (the committed root)`);
  assert.deepEqual(q.summary.agents, q.initialRegistry, `${label}: the reviewed summary carries the committed registry`);
  assert.equal(String(q.summary.initialState.agentRoot).toLowerCase(), String(q.build.initialState.agentRoot).toLowerCase(), `${label}: the reviewed summary carries the committed agent root`);
}
/* A built ownerSetAgentRoot root request commits exactly the root its stored registry folds to; the record and the
 * owners' reviewed manifest are self-consistent. */
function assertRootOpFolds(q, label) {
  assert.equal(q.vaultOperations[0].action, "ownerSetAgentRoot", `${label}: a delegate-rule change`);
  assert.ok(Array.isArray(q.newRegistry), `${label}: the stored registry is an array`);
  assert.equal(R.fold(q.newRegistry), String(q.build.successorState.agentRoot).toLowerCase(), `${label}: the stored registry folds to the committed successor agent root`);
  const opAgents = q.vaultOperations[0].params && q.vaultOperations[0].params.agents;
  assert.ok(Array.isArray(opAgents), `${label}: the recorded vault operation carries its agents`);
  assert.equal(R.fold(opAgents), R.fold(q.newRegistry), `${label}: the recorded vault operation's agents fold to the same root as the stored registry`);
  for (const e of q.newRegistry) {
    const op = opAgents.find((a) => a.agentPk === e.agentPk);
    assert.ok(op, `${label}: the recorded vault operation names delegate ${e.agentPk.slice(0, 8)}`);
    assert.equal(String(op.periodStartDaa), e.periodStartDaa, `${label}: the recorded vault operation carries the committed start of ${e.agentPk.slice(0, 8)}`);
  }
  const sets = agentSetsOf(q.manifest);
  assert.ok(sets.length > 0, `${label}: the owners' reviewed manifest carries the new policy set`);
  for (const set of sets) for (const e of q.newRegistry) {
    const p = set.find((a) => a.agentPk === e.agentPk);
    assert.ok(p, `${label}: the reviewed policy set names delegate ${e.agentPk.slice(0, 8)}`);
    assert.equal(String(p.periodStartDaa), e.periodStartDaa, `${label}: the reviewed policy set shows the committed start of ${e.agentPk.slice(0, 8)}`);
  }
}

/* ---------------- promoted out-of-band helpers (RC45 L2-01 legs; explicit arguments, TEST keys only) ----------------
 * Promoted from the sealed G1-G4 assessment harness and generalized (root id, treasury id, wallets passed in). Every
 * root build runs inside the route-level node (NODE().with), so a build-time node read reaches the explicit mock. */
const H32 = (b) => b.toString(16).padStart(2, "0").repeat(32);
const sameOp = (a, b) => Boolean(a && b) && String(a.transactionId).toLowerCase() === String(b.transactionId).toLowerCase() && Number(a.index) === Number(b.index);
/* Is this outpoint in the mock UTXO table? */
function inTable(x, outpoint) { return x.node.entryAt(outpoint) !== null; }
/* Seed a stored request's fee input (its last input) into the mock UTXO table when absent (the kit's fee UTXOs are synthetic). */
function seedFee(x, rec, wallet = x.w.fee) {
  const f = rec.build.frozen.inputs[rec.build.frozen.inputs.length - 1];
  if (!inTable(x, f.previousOutpoint)) x.node.seedP2pk(wallet, { transactionId: String(f.previousOutpoint.transactionId), index: Number(f.previousOutpoint.index) }, BigInt(f.utxo.amount));
}
/*
 * The case-5 request A: a v0.7-kas delegate-rule change on `vaultId` (agents = the new registry) built at `buildDaa`,
 * carrying the owners' slot signatures (`slots`), its fee input seeded; then at `staleDaa` (the node's DAA and the
 * check-time read) the hosted finalize refuses 409 PERIOD_START_STALE and, when `withdraw`, the owners withdraw it
 * (REFUSED, the root's reservation released). Returns { id, recA } (recA re-read after the steps).
 */
async function staleWithdrawnA(x, { rootId, vaultId, agents, tag, buildDaa = D, staleDaa, withdraw = true, slots = [1, 2], feeWallet = null }) {
  const fee = feeWallet ?? x.w.fee;
  let id = null;
  await withAnchor(buildDaa, async () => {
    const r = await NODE().with(x.node.rpc, () => x.setAgents(rootId, vaultId, agents, { tag }));
    assert.equal(r.status, 201, `${tag}: the delegate-rule change is built (${said(r)})`);
    id = r.body.request.id;
    for (const s of slots) await x.slotSign(rootId, id, s, x.w[`o${s}`], x.cookie[`o${s}`]);
  });
  const built = await x.rootReq(id);
  assert.equal(built.state, "AUTHORIZED", `${tag}: the owners' slot signatures are attached`);
  seedFee(x, built, fee);
  x.node.state.daa = BigInt(staleDaa);
  let f = null, wd = null;
  await withAnchor(BigInt(staleDaa), async () => {
    f = await x.call("POST", ["org-roots", rootId, "requests", id, "finalize"], { fuelSignatureScriptHex: feeSignatureScriptHex(x.config, built, fee) }, x.cookie.o1);
    if (withdraw) wd = await x.rootReject(rootId, id);
  });
  assert.equal(f.code, "PERIOD_START_STALE", `${tag}: the stale delegate-rule change is not finalized (${said(f)})`);
  if (withdraw) {
    assert.equal(wd.status, 200, `${tag}: the stale delegate-rule change is withdrawn (${said(wd)})`);
    assert.equal(wd.body.request.state, "REFUSED");
  }
  return { id, recA: await x.rootReq(id) };
}
/* The request's exact transaction confirmed outside PolicyVault (assembled from the owners' approvals and the fee key):
 * its inputs are spent and its frozen outputs exist in the mock (stamped with the accepting DAA when stamping is on). */
function confirmOutOfBand(x, rec) {
  x.node.expectFrozen(rec.build.frozen, rec.txId);
  x.node.state.effects.get(String(rec.txId).toLowerCase())();
  return String(rec.txId).toLowerCase();
}
/*
 * A node with the outcome-arbitration surface (start/sink hashes, acceptance window, blocks) over the mock UTXO table.
 *   submitAnswer "orphan"          every submit is refused as an orphan (rusty-kaspa's disallowed-orphan answer);
 *                "strict"          refused as an orphan when a frozen input is missing, else the effect is applied;
 *                "alreadyAccepted" rusty-kaspa RejectAlreadyAccepted for the submitted id;
 *                "lost"            the node's response is lost (transport failure), nothing is applied.
 *   conflict { outpoint, payToXOnly }  at the submit (after its start hash was read) an accepted competing
 *                transaction spends `outpoint`: it leaves the UTXO table and appears in the acceptance window and in
 *                the second block (engine-computed identities), as in rc27f-outcome-fixture.js.
 */
function outcomeRpc(x, { submitAnswer = "orphan", frozen = null, conflict = null } = {}) {
  const { blockHashOfRpcHeader, transactionIdOfRpcBody } = require("../src/tx-identity");
  const header = (nonce) => ({ version: 1, parentsByLevel: [[H32(0)]], hashMerkleRoot: H32(0), acceptedIdMerkleRoot: H32(0), utxoCommitment: H32(0), timestamp: 0n, bits: 0, daaScore: 0n, blueWork: 0n, blueScore: 0n, pruningPoint: H32(0), nonce });
  const hs = [header(300n), header(301n)], hashes = hs.map((h) => blockHashOfRpcHeader(x.config, h));
  const body = conflict ? { version: 1, inputs: [{ previousOutpoint: { transactionId: String(conflict.outpoint.transactionId).toLowerCase(), index: Number(conflict.outpoint.index) }, signatureScript: "", sequence: "0", sigOpCount: 0, computeBudget: 0 }], outputs: [{ value: "1", scriptPublicKey: { version: 0, script: `20${conflict.payToXOnly}ac` } }], lockTime: "0", subnetworkId: "00".repeat(20), gas: "0", payload: "" } : null;
  const conflictId = body ? transactionIdOfRpcBody(x.config, body).transactionId : null;
  let attempted = false, conflictApplied = false;
  const block = (i) => ({ header: hs[i], verboseData: { hash: hashes[i], isChainBlock: true }, transactions: i === 1 && conflictApplied ? [{ ...structuredClone(body), verboseData: { transactionId: conflictId, blockHash: hashes[1] } }] : [] });
  const base = x.node.rpc;
  /* R3N-B1a inventory: this node also carries the seam's selected-chain walk below its sink; the B1 runtime records the
   * submit start as the sink's 20th selected parent (A_s) instead of the sink, so the acceptance window and the block
   * scan modelled FROM hashes[0] (the submit-time sink) are answered from any start on hashes[0]'s walk too: the walk
   * blocks above that start (they accept nothing), hashes[0], then exactly what hashes[0]'s window holds. */
  let walk = null;
  const above0 = (start) => { const s0 = String(start).toLowerCase(); if (s0 === hashes[0]) return []; const p = walk.pathAbove(s0); return p && p.head === hashes[0] ? p.blocks : null; };
  const rpcObj = {
    conflictId,
    getUtxosByAddresses: base.getUtxosByAddresses,
    disconnect: base.disconnect,
    async getBlockDagInfo() { return { virtualDaaScore: x.node.state.daa.toString(), sink: hashes[attempted ? 1 : 0], networkName: "kaspa-testnet-10" }; },
    async submitTransaction({ transaction }) {
      attempted = true;
      const id = transaction.finalize().toString().toLowerCase();
      x.node.state.broadcasts.push(id);
      if (conflict && !conflictApplied) { x.node.spendOutpoint(conflict.outpoint); conflictApplied = true; }
      if (submitAnswer === "lost") throw new Error("TEST node: the submit response was lost (connection reset); outcome unknown");
      if (submitAnswer === "alreadyAccepted") throw new Error(`Rejected transaction ${id}: transaction ${id} was already accepted by the consensus`);
      /* faithful to rusty-kaspa mempool: a missing outpoint is an orphan, refused when orphans are disallowed */
      const missing = frozen ? frozen.inputs.some((i) => !inTable(x, i.previousOutpoint)) : true;
      if (missing || submitAnswer === "orphan") throw new Error(`Rejected transaction ${id}: transaction ${id} is an orphan where orphan is disallowed`);
      const fx = x.node.state.effects.get(id); if (fx) fx();
      return { transactionId: id };
    },
    async getMempoolEntry({ transactionId }) { throw new Error(`Transaction ${transactionId} not found`); },
    async getVirtualChainFromBlock({ startHash }) {
      const pre = above0(startHash);
      return { removedChainBlockHashes: [], addedChainBlockHashes: pre !== null ? [...pre, hashes[1]] : [], acceptedTransactionIds: pre !== null ? [...pre.map((h) => ({ acceptingBlockHash: h, acceptedTransactionIds: [] })), { acceptingBlockHash: hashes[1], acceptedTransactionIds: conflictApplied ? [conflictId] : [] }] : [] };
    },
    async getBlocks({ lowHash } = {}) {
      const pre = lowHash === undefined ? null : above0(lowHash);
      if (pre === null || pre.length === 0) return { blockHashes: hashes, blocks: [block(0), block(1)] };
      const low = String(lowHash).toLowerCase(), seam = [low, ...pre.slice(0, -1)];
      return { blockHashes: [...seam, ...hashes], blocks: [...seam.map((h) => walk.view(h)), block(0), block(1)] };
    },
    async getBlock({ hash }) { return { block: block(hashes.indexOf(hash)) }; }
  };
  walk = require("./guard-node").chainWalk(rpcObj, x.config);
  return rpcObj;
}
/* A's successor root and treasury, reconstructed ONLY from A's stored request (as an outside party holding A would). */
async function successorsOf(x, rec, { rootId, vaultId }) {
  const { normalizeStateV4 } = require("../../core/model/vault-state-v4");
  const kp = sdk("rooted-kas-profile-v7.js");
  const rootRec = await x.rootRecord(rootId);
  const rootOutIdx = rec.build.frozen.outputs.findIndex((o) => o.covenant && String(o.covenant.covenantId).toLowerCase() === rootId);
  const root = { template: rootRec.template, state: rec.manifest.rootState.after.state, outpoint: { transactionId: rec.txId, index: rootOutIdx }, covenantId: rootId, value: String(rec.build.frozen.outputs[rootOutIdx].value) };
  const vrec = await x.vault(vaultId);
  const vIdx = kp.vaultSuccessorIndexOf(rec);
  const vault = { ...vrec, live: { ...vrec.live, state: normalizeStateV4(rec.build.successorState), outpoint: { transactionId: rec.txId, index: vIdx } } };
  return { root, vault, rootOutIdx, vIdx };
}
/* The owners' own on-chain action built OUTSIDE PolicyVault with existing SDK functions (buildOwnerOp, frozenToWasmTransaction,
 * createInputSignature with TEST keys, finalizeOwnerOp) and checked on the real VM (verifyFinalTransactionInputs). */
function offlineOwnerOp(x, { vault, root, rootId, action, signers, tag }) {
  const { frozenToWasmTransaction } = require("../src/frozen-tx-v3");
  const kp = sdk("rooted-kas-profile-v7.js");
  const kaspa = lazy.chain.loadKaspa(x.config);
  const w = x.w;
  const fuel = p2pkUtxo(w.fee, `offline-${tag}-fee`);
  x.node.seedP2pk(w.fee, fuel.outpoint, BigInt(fuel.amount));
  const build = kp.buildOwnerOp({ config: x.config, vaultRecord: vault, action, params: {}, fuel, root, changeXOnly: w.fee.xonly });
  const wtx = frozenToWasmTransaction(x.config, build.frozen); wtx.finalize();
  const unsigned = wtx.serializeToSafeJSON();
  const rootIdx = build.frozen.inputs.findIndex((i) => String(i.utxo.covenantId ?? "").toLowerCase() === rootId);
  const approvals = signers.map((slot) => ({ slot, publicKey: w[`o${slot}`].xonly, signatureHex: slotSignatureHex(x.config, unsigned, rootIdx, w[`o${slot}`]) }));
  const feeScript = kaspa.createInputSignature(kaspa.Transaction.deserializeFromSafeJSON(unsigned), build.frozen.inputs.length - 1, w.fee.key);
  const fin = kp.finalizeOwnerOp({ build, approvals, fuelSignatureScriptHex: feeScript });
  let vm = "PASS";
  try { require("../src/vm-preflight").verifyFinalTransactionInputs(fin.finalTransaction); } catch (e) { vm = `FAIL ${String(e.message).slice(0, 200)}`; }
  return { build, fin, vm, txId: String(build.txId).toLowerCase() };
}
/* A delegate payment made OUTSIDE PolicyVault from a given treasury position (an agentSpend built with the SDK builder
 * from that output; its effect is applied to the mock: the position is spent, the payment and the new position exist). */
function outOfAppAgentSpend(x, { template, state, outpoint, covenantId, registry, delegate, recipient, payKas = 1n, periodsElapsed = "0" }) {
  const { normalizeStateV4, stateToJsonV4 } = require("../../core/model/vault-state-v4");
  const b7k = sdk("vault-builders-v7-kas.js");
  const st = normalizeStateV4(stateToJsonV4(normalizeStateV4(state)));
  const policies = registry.map(({ recipients, ...p }) => { void recipients; return p; });
  const entry = registry.find((e) => e.agentPk === delegate.xonly);
  assert.ok(entry, "outOfAppAgentSpend: the delegate is in the registry");
  const build = b7k.buildV7KasTransaction({ config: x.config, contractVersion: "policyvault-0.7-kas", templateInput: template, stateInput: stateToJsonV4(st), action: "agentSpend", params: { payAmountSompi: (BigInt(payKas) * KAS).toString(), agentPk: delegate.xonly, agents: policies, recipient, recipients: [...entry.recipients], periodsElapsed: String(periodsElapsed) }, chain: { predecessorOutpoint: outpoint, predecessorValue: (st.protectedValue + st.feeReserve).toString(), covenantId }, changeXOnly: delegate.xonly });
  x.node.expectFrozen(build.frozen, build.txId);
  x.node.state.effects.get(String(build.txId).toLowerCase())();
  return { build, txId: String(build.txId).toLowerCase() };
}

module.exports = {
  R, K, F3, KAS, LOOPBACK, D, DAY, HOUR, windowDaa, said, nodeDown, useAnchorDaa, withAnchor, lazy,
  installNode, NODE, mcpSession, walletOf, kasWallets, kasDelegate, p2pkUtxo, chainNode, frozenOf, signInputs, slotSignatureHex, feeSignatureScriptHex,
  kasJson, installedRegistry, agentSetsOf, kasCategories, kasRecords, kasSnapshot, strictJson, scope, warmAllCaches, buildRootAndTreasury, kasSuite,
  assertKasGenesisFolds, assertRootOpFolds,
  /* promoted out-of-band helpers (RC45 L2-01 legs) */
  inTable, seedFee, staleWithdrawnA, confirmOutOfBand, outcomeRpc, successorsOf, offlineOwnerOp, outOfAppAgentSpend
};
