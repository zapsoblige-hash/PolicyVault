"use strict";
/*
 * RC45 R2 test kit: the hosted v0.4.1 delegate period-start legs of
 * sdk/test/rc45-r2-02-v4-anchor.test.js (anchor at build) and
 * sdk/test/rc45-r2-03-v4-commit-freshness.test.js (freshness before the point
 * of no return). Internal RED-first regression material; not an audit.
 *
 * On top of the F5 kit (vaults, wallets, the explicit chain model, snapshots,
 * install; reused unchanged), the F3 kit (apiFor: the real hosted route
 * handler with TEST-key wallet sessions; submitThroughModel) and the R2-13
 * seam (useAnchorDaa: the build/check-time node DAA read; withDaa) it adds:
 *   - suite(prefix): a self-hosted JSON template holding the seeded vaults
 *     (and their warm compile cache), and fresh HOSTED cases installed from it
 *     on the JSON store or on a fresh PostgreSQL database (the rc45 runner's
 *     pg mode; a skipped PostgreSQL leg there is a FAIL);
 *   - governance and risk ceremony over the real routes: proposals by the
 *     owner session or by an owner-minted machine credential holding
 *     governance:propose, the owner's real approval signature, organization
 *     controls (delay window, static REVIEW risk) and the reviewer release;
 *   - the registry fold (normalizeRegistry(entries).tree.root) and the
 *     committed-root agreement checks;
 *   - a genesis node (getBlockDagInfo with a chosen virtual DAA score,
 *     counted broadcasts, the exact covenant output answered after a
 *     broadcast) and the route-level genesis-submit wrapper: the route calls
 *     submitCreateWalletRequestV4({ config, requestId, signedSafeJson })
 *     without an rpc, so the module-cache export is wrapped to call the REAL
 *     function with the explicit node and restored afterwards (the same rule
 *     as F3 submitThroughModel);
 *   - installNodePatch(): the friendly create calls chain.connectVerified,
 *     which server/src/api.js destructures when it loads; the patch (installed
 *     before api.js loads) answers a test-chosen mock node and otherwise calls
 *     the real function;
 *   - useNodeClient / withNodeClient: with NO seam installed, a TEST node
 *     client replaces the rusty-kaspa RpcClient constructor that the real
 *     connectVerified uses, so the code under test runs its own node DAA read
 *     (sync / index / network gate, canonical parse, disconnect) over a
 *     test-chosen answer, with every connection counted.
 *
 * Nothing dials a node: every config names ws://127.0.0.1:1 and every node
 * observation comes from an explicit mock. TEST keys only.
 */
const path = require("node:path");
const assert = require("node:assert/strict");
const K = require("./rc45-f5-kit");
const F3 = require("./rc45-f3-kit");
const { useAnchorDaa, withDaa } = require("./rc45-r2-daa");

const SDK_SRC = path.join(__dirname, "..", "src");
const cand = K.modulesOf(SDK_SRC);
const { Categories } = cand.store;
const { KAS, LOOPBACK } = K;
const D = 545000000n; // a realistic node DAA score
const DAY = 864000n, HOUR = 36000n;
const windowDaa = (L) => (BigInt(L) - 6000n > 600n ? BigInt(L) - 6000n : 600n);
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const said = (r) => `${r.status} ${r.code ?? ""} ${r.message ?? ""}`.trim();
const nodeDown = () => { throw Object.assign(new Error("TEST node unavailable: the configured node is not connected or not synced"), { code: "PERIOD_START_REQUIRED" }); };

/* TEST wallets: the F5 set (owner 0x11, agent 0x21, recipients 0x31..0x33) plus a second agent, new delegate keys and a reviewer. */
function wallets(config) {
  const kaspa = require(config.rustyKaspaModule);
  const one = (byte) => {
    const secretHex = byte.toString(16).padStart(2, "0").repeat(32), priv = new kaspa.PrivateKey(secretHex);
    return { secretHex, xonly: priv.toPublicKey().toXOnlyPublicKey().toString().toLowerCase(), address: priv.toPublicKey().toAddress(config.networkId).toString() };
  };
  return { ...K.walletsFor(config), agentB: one(0x22), n1: one(0x41), n2: one(0x42), n3: one(0x43), n4: one(0x44), n5: one(0x45), n6: one(0x46), reviewer: one(0x51) };
}
/* A delegate entry in the request / registry JSON shape (recipients by x-only key). */
function delegate(agentPk, recipients, over = {}) {
  return { agentPk, maxPerSpend: (10n * KAS).toString(), periodBudget: (30n * KAS).toString(), periodLengthDaa: DAY.toString(), periodStartDaa: "0", periodSpent: "0", approvalThreshold: (5n * KAS).toString(), agentMaxFeePerTx: KAS.toString(), recipients: [...recipients], ...over };
}
/* Registry entries in the stored (registryEntryToJson) form, for exact comparison. */
const canonicalEntries = (entries) => cand.manifest4.normalizeRegistry(entries).entries.map((e) => cand.manifest4.registryEntryToJson(e));
const fold = (entries) => cand.manifest4.normalizeRegistry(entries).tree.root;
const entryOf = (entries, agentPk) => (entries ?? []).find((e) => e.agentPk === agentPk) ?? null;

/* Seed a live v0.4.1 vault manifest (the F5 kit's shape) with the given registry. */
async function seedVault(config, v, w, registry, { label = "RC45 R2 TEST", protectedKas = 1000n } = {}) {
  const m = cand;
  const template = { owner: w.owner.xonly, vaultId: v.vaultId };
  const policies = registry.map((e) => m.agents.normalizeAgentPolicyV4({ ...e, agentRecipientRoot: m.recipients.buildRecipientTree(e.recipients).root }));
  const state = m.vs4.normalizeStateV4({ protectedValue: (BigInt(protectedKas) * KAS).toString(), feeReserve: (5n * KAS).toString(), paused: "0", agentRoot: m.agents.buildAgentTreeV4(policies).root, approvers: [], approvalM: "0", policyNonce: "0" });
  const contractVersion = m.vs4.CONTRACT_VERSION_V4_1;
  const compiled = m.compiler4.compileExactStateV4({ config, template, state, contractVersion });
  await m.manifest4.persistManifestV4(config, { schema: "policyvault-vault-manifest/v4", contractVersion, networkId: config.networkId, vaultId: v.vaultId, label: `${label} ${v.tag}`, status: "ACTIVE", template, agentRegistry: registry,
    live: { state: m.vs4.stateToJsonV4(state), stateId: m.vs4.computeStateIdV4({ networkId: config.networkId, template, state, contractVersion }), outpoint: { transactionId: v.out, index: 0 }, outpointValue: (state.protectedValue + state.feeReserve).toString(), scriptSha256: compiled.scriptSha256, covenantId: v.cov },
    creationTxId: v.out, latestTransitionTxId: null, lastTransition: null });
}

/* The durable records a refusal must leave untouched: the F5 five (vault, request, both claim kinds incl. the budget
 * reservations, receipts) plus governance proposals, intent-manifest records and risk evaluations, and the audit. */
const EXTRA = Object.freeze([Categories.GOVERNANCE_PROPOSAL, Categories.INTENT_MANIFEST, Categories.RISK_EVALUATION]);
async function snapAll(config) {
  const snap = await K.snapshot(cand, config), s = cand.store.getStore(config);
  for (const c of EXTRA) snap.records[c] = await Promise.all((await s.listKeys(c)).sort().map(async (k) => [k, await s.read(c, k)]));
  return snap;
}
/* The "nothing written" scope of a node-read refusal at a build: requests, reservations and claims, receipts, the
 * vault, governance proposals (not consumed). Audit rows and risk evaluations are outside it (a matched released
 * hold is consumed by the intent-stage gate before the read). */
async function buildScope(config) {
  const snap = await snapAll(config);
  const r = snap.records;
  return { [Categories.VAULT]: r[Categories.VAULT], [Categories.REQUEST]: r[Categories.REQUEST], [Categories.SUBMISSION_CLAIM]: r[Categories.SUBMISSION_CLAIM], [Categories.TRANSITION_CLAIM]: r[Categories.TRANSITION_CLAIM], [Categories.RECEIPT]: r[Categories.RECEIPT], [Categories.GOVERNANCE_PROPOSAL]: r[Categories.GOVERNANCE_PROPOSAL] };
}

/* Run `fn` with the node DAA read answering `value` (a canonical DAA or a function); restores afterwards. */
async function withAnchor(value, fn) {
  const restore = useAnchorDaa(value);
  try { return await fn(restore); } finally { restore(); }
}

/* ---------------- the friendly-create node ---------------- */
function installNodePatch() {
  assert.equal(require.cache[require.resolve("../../server/src/api")], undefined, "the node patch must be installed before server/src/api.js loads (it destructures connectVerified)");
  const chain = require(path.join(SDK_SRC, "chain.js"));
  const real = chain.connectVerified;
  let node = null;
  chain.connectVerified = async function connectVerified(config) {
    if (node === null) return real(config);
    return { rpc: node, kaspa: chain.loadKaspa(config), serverInfo: { networkId: config.networkId, isSynced: true, hasUtxoIndex: true } };
  };
  return {
    async with(rpc, fn) { node = rpc; try { return await fn(); } finally { node = null; } }
  };
}
/* ---------------- the REAL node DAA read over a TEST node client (no seam) ---------------- */
/*
 * useNodeClient(config, node) -> handle. chain.connectVerified constructs its node client from the loaded rusty-kaspa
 * module (kaspa.RpcClient) at call time; this replaces that constructor with a TEST client, so the code under test runs
 * its OWN node DAA read unchanged over it — connect, the getServerInfo gate (network, isSynced, hasUtxoIndex),
 * getBlockDagInfo, disconnect. Use it with NO useAnchorDaa seam installed.
 *   node.serverInfo       merged over { networkId: config.networkId, isSynced: true, hasUtxoIndex: true }
 *   node.virtualDaaScore  answered verbatim by getBlockDagInfo (it may be non-canonical; the key is absent from the
 *                         answer when `node` has no such property)
 *   node.connectError     when set, connect() throws an Error with this message (no connection opens)
 * handle.log() -> { clients, connectAttempts, opened, disconnects, open, calls, unexpected }: `open` counts clients that
 * connected and were not disconnected since; any other client method throws an Error naming it (recorded in
 * `unexpected`). handle.restore() puts the real constructor back. Nothing dials a node.
 */
function useNodeClient(config, node = {}) {
  const chain = require(path.join(SDK_SRC, "chain.js"));
  const kaspa = chain.loadKaspa(config);
  const Real = kaspa.RpcClient;
  const log = { clients: 0, connectAttempts: 0, opened: 0, disconnects: 0, calls: [], unexpected: [] };
  const live = new Set();
  const has = (k) => Object.prototype.hasOwnProperty.call(node, k);
  class TestNodeClient {
    constructor(options) { log.clients += 1; this.options = options; }
    async connect() {
      log.calls.push("connect"); log.connectAttempts += 1;
      if (node.connectError) throw new Error(node.connectError);
      live.add(this); log.opened += 1;
    }
    async getServerInfo() { log.calls.push("getServerInfo"); return { networkId: config.networkId, isSynced: true, hasUtxoIndex: true, ...(node.serverInfo || {}) }; }
    async getBlockDagInfo() {
      log.calls.push("getBlockDagInfo");
      const answer = { sink: "3a".repeat(32), networkName: `kaspa-${config.networkId}` };
      if (has("virtualDaaScore")) answer.virtualDaaScore = node.virtualDaaScore;
      return answer;
    }
    async disconnect() { log.calls.push("disconnect"); log.disconnects += 1; live.delete(this); }
  }
  for (const name of ["getUtxosByAddresses", "submitTransaction", "getMempoolEntry", "getMempoolEntries", "getBlock", "getBlocks", "getVirtualChainFromBlock", "getSinkBlueScore", "getBalanceByAddress"]) {
    TestNodeClient.prototype[name] = async function unexpected() { log.calls.push(name); log.unexpected.push(name); throw new Error(`TEST node client: unexpected ${name} call`); };
  }
  kaspa.RpcClient = TestNodeClient;
  return {
    restore() { kaspa.RpcClient = Real; },
    log: () => ({ ...log, calls: [...log.calls], unexpected: [...log.unexpected], open: live.size })
  };
}
/* Run `fn(handle)` with the TEST node client installed; restores the real constructor afterwards. */
async function withNodeClient(config, node, fn) {
  const handle = useNodeClient(config, node);
  try { return await fn(handle); } finally { handle.restore(); }
}
/* Node answers the real node DAA read must refuse (PERIOD_START_REQUIRED). The gate cases also answer a canonical
 * score, so only the gate itself can refuse them; the parse cases come from a synced, indexed node on the configured
 * network. */
const UNREADABLE_NODES = Object.freeze([
  ["a node that reports it is not synced (isSynced false)", { serverInfo: { isSynced: false }, virtualDaaScore: (D + 4242n).toString() }],
  ["a node that reports no UTXO index (hasUtxoIndex false)", { serverInfo: { hasUtxoIndex: false }, virtualDaaScore: (D + 4242n).toString() }],
  ["a node on another network (mainnet)", { serverInfo: { networkId: "mainnet" }, virtualDaaScore: (D + 4242n).toString() }],
  ["a hex virtual DAA score (0x207c8a40)", { virtualDaaScore: "0x207c8a40" }],
  ["a negative virtual DAA score (-545000000)", { virtualDaaScore: "-545000000" }],
  ["a fractional virtual DAA score (545000000.5)", { virtualDaaScore: "545000000.5" }],
  ["no virtual DAA score at all", {}],
  ["a connection that cannot be opened", { connectError: "TEST node refused the connection (ECONNREFUSED 127.0.0.1:1)", virtualDaaScore: (D + 4242n).toString() }]
]);
/* Every connection the read opened was closed; the node was asked; no other node method was used. */
function assertNodeClientClosed(log, node, label) {
  assert.ok(log.connectAttempts >= 1, `${label}: the configured node was asked (the read ran its own body)`);
  if (!node.connectError) assert.ok(log.opened >= 1, `${label}: the connection opened`);
  assert.equal(log.open, 0, `${label}: no node connection is left open (opened ${log.opened}, disconnected ${log.disconnects})`);
  assert.ok(log.disconnects >= log.opened, `${label}: every opened connection was disconnected (opened ${log.opened}, disconnected ${log.disconnects})`);
  assert.deepEqual(log.unexpected, [], `${label}: no other node method was used`);
}

/* A mock node answering one getBlockDagInfo value (passed through verbatim: it may be non-canonical). */
function dagNode(virtualDaaScore) {
  const calls = [];
  return { calls, async getBlockDagInfo() { calls.push("getBlockDagInfo"); return { virtualDaaScore, sink: "37".repeat(32), networkName: "kaspa-testnet-10" }; }, async getUtxosByAddresses() { calls.push("getUtxosByAddresses"); return { entries: [] }; }, async disconnect() { calls.push("disconnect"); } };
}

/* ---------------- the genesis node and the route-level genesis submit ---------------- */
/* A node at virtual DAA `daa` that counts broadcasts and, after one, answers the genesis covenant output `target`. */
function genesisNode(daa) {
  const state = { daa: BigInt(daa), target: null, broadcasts: [], calls: [] };
  const rpc = {
    async getBlockDagInfo() { state.calls.push("getBlockDagInfo"); return { virtualDaaScore: state.daa.toString(), sink: "38".repeat(32), networkName: "kaspa-testnet-10" }; },
    async submitTransaction({ transaction }) { state.calls.push("submitTransaction"); const id = transaction.finalize().toString().toLowerCase(); state.broadcasts.push(id); return { transactionId: id }; },
    async getUtxosByAddresses({ addresses }) {
      state.calls.push("getUtxosByAddresses");
      const t = state.target;
      if (!t || !state.broadcasts.includes(t.txId) || !addresses.map(String).includes(t.address)) return { entries: [] };
      return { entries: [{ address: t.address, outpoint: { transactionId: t.txId, index: t.index }, utxoEntry: { amount: t.amount, scriptPublicKey: { version: 0, script: "" }, covenantId: t.covenantId, blockDaaScore: state.daa.toString(), isCoinbase: false } }] };
    },
    async disconnect() { state.calls.push("disconnect"); }
  };
  return { rpc, state, expect(config, request) { const { vaultAddress, vaultValue } = cand.submit4.genesisTargetV4(config, request); state.target = { address: vaultAddress, txId: request.txId, index: request.vaultOutputIndex, amount: vaultValue, covenantId: request.covenantId }; } };
}
async function genesisSubmitThrough(rpc, fn) {
  const mod = cand.submit4, real = mod.submitCreateWalletRequestV4;
  mod.submitCreateWalletRequestV4 = (args) => real({ ...args, rpc, pollAttempts: 1, pollDelayMs: 0 });
  try { return await fn(); } finally { mod.submitCreateWalletRequestV4 = real; }
}
/* The owner's TEST-key signatures over every funding input of a genesis (SIGHASH_ALL). */
function signGenesis(config, request, wallet) {
  const kaspa = require(config.rustyKaspaModule);
  const tx = kaspa.Transaction.deserializeFromSafeJSON(request.transaction.unsignedSafeJson);
  const ins = tx.inputs, key = new kaspa.PrivateKey(wallet.secretHex);
  for (const s of request.transaction.signInputs) ins[s.index].signatureScript = kaspa.createInputSignature(tx, s.index, key);
  tx.inputs = ins;
  return tx.serializeToSafeJSON();
}
/* An ordinary owner P2PK funding UTXO (TEST outpoint). */
function fundingFor(wallet, tag, amountKas = 2000n) {
  return { outpoint: { transactionId: K.hex(`rc45-r2-funding-${tag}`), index: 0 }, amount: (BigInt(amountKas) * KAS).toString(), scriptPublicKeyHex: `20${wallet.xonly}ac` };
}

/* ---------------- the hosted suite ---------------- */
function suite(prefix) {
  const roots = [], stores = [], databases = [];
  const PG = K.pgFromEnv(), PG_AVAILABLE = Boolean(PG.port && PG.user && PG.database);
  const PG_SKIP = PG_AVAILABLE ? undefined : "REQUIREMENT_NOT_AVAILABLE in this process: isolated PostgreSQL (the rc45 runner's pg mode runs these legs; a skipped PostgreSQL leg there is a FAIL)";
  let admin = null, serial = 0, history = null, templateRoot = null;
  const mk = (p) => { const dir = K.ownedTempRoot(p); roots.push(dir); return dir; };
  const S = {
    PG_AVAILABLE, PG_SKIP, cand, track: (root) => roots.push(root), mk,
    /* Build the self-hosted template with `seed(template)`, snapshot it. */
    async setup(seed) {
      const template = cand.config.loadConfig({ dataRoot: mk(`pv-rc45-${prefix}-template-`), rpcUrl: LOOPBACK });
      assert.equal(template.tenancyEnforced, false, "the template is self-hosted (tenancy off); every case is hosted");
      await seed(template);
      history = await snapAll(template);
      templateRoot = template.dataRoot;
      if (PG_AVAILABLE) admin = new (require("pg").Pool)(PG);
      return template;
    },
    async teardown() {
      for (const s of stores) { try { await s.close(); } catch { /* closed */ } }
      if (admin) { for (const db of databases) await admin.query(`DROP DATABASE IF EXISTS ${db} WITH (FORCE)`); await admin.end(); }
      for (const root of roots) K.removeOwnedRoot(root);
    },
    /* A fresh HOSTED case (authMode enabled) with the template installed; owner, agent and reviewer signed in. */
    async fresh(backend, w) {
      const dataRoot = mk(`pv-rc45-${prefix}-case-`);
      K.warmCompileCache(templateRoot, dataRoot);
      const hosted = { authMode: "enabled", authCookieInsecure: true, dataRoot, rpcUrl: LOOPBACK };
      let config, pgDatabase = null;
      if (backend === "PostgreSQL") {
        pgDatabase = `pv_rc45_${prefix.replace(/[^a-z0-9]/g, "_")}_${process.pid}_${++serial}`;
        await admin.query(`CREATE DATABASE ${pgDatabase}`); databases.push(pgDatabase);
        config = cand.config.loadConfig({ persistenceBackend: "postgres", pgHost: PG.host, pgPort: PG.port, pgUser: PG.user, pgDatabase, pgNoTls: true, ...hosted });
        stores.push(await cand.store.openPgStore(config, { migrate: true }));
        assert.equal(cand.store.getStore(config).kind, "postgres");
      } else config = cand.config.loadConfig(hosted);
      assert.equal(config.tenancyEnforced, true);
      await K.install(cand, config, history);
      const store = cand.store.getStore(config), api = F3.apiFor(config), kit = K.kitFor(cand, config, w);
      const kaspa = require(config.rustyKaspaModule);
      const x = {
        config, store, api, pgDatabase, kit, w,
        req: (requestId) => cand.wr4.loadRequest(config, requestId),
        raw: (category, key) => store.read(category, key),
        manifest: (v) => cand.manifest4.loadManifestV4(config, v.vaultId),
        snap: () => snapAll(config),
        scope: () => buildScope(config),
        cookie: { owner: await api.signIn(w.owner), agent: await api.signIn(w.agent), reviewer: await api.signIn(w.reviewer) },
        call: (method, segments, body, auth = null) => {
          const { handle } = require("../../server/src/api");
          const ctx = auth === null ? {} : typeof auth === "string" ? { headers: { cookie: auth } } : { headers: auth };
          return handle(config, method, segments, {}, body, ctx).then(
            (r) => ({ status: r.status, code: null, body: r.body, message: null }),
            (e) => { if (e && e.code === "ERR_ASSERTION") throw e; return { status: e && e.status !== undefined ? e.status : null, code: e && e.code ? e.code : null, body: null, message: String(e && e.message), extra: e && e.extra }; }
          );
        }
      };
      x.build = (body, cookie = x.cookie.owner) => x.call("POST", ["wallet", "v4", "requests"], body, cookie);
      x.create = (body, cookie = x.cookie.owner) => x.call("POST", ["wallet", "v4", "create"], body, cookie);
      x.simulate = (body, cookie = x.cookie.owner) => x.call("POST", ["wallet", "v4", "simulate"], body, cookie);
      x.ownerFinalize = async (requestId) => x.call("POST", ["wallet", "v4", "requests", requestId, "signature"], { signedSafeJson: kit.sign(await x.req(requestId), w.owner) }, x.cookie.owner);
      x.agentFinalize = async (requestId) => x.call("POST", ["wallet", "v4", "requests", requestId, "signature"], { signedSafeJson: kit.sign(await x.req(requestId), w.agent) }, x.cookie.agent);
      x.submitThrough = (model, requestId, cookie = x.cookie.owner) => F3.submitThroughModel(() => model, () => x.call("POST", ["wallet", "v4", "requests", requestId, "submit"], {}, cookie));
      x.genesisSubmit = (rpc, requestId, signedSafeJson) => genesisSubmitThrough(rpc, () => x.call("POST", ["wallet", "v4", "requests", requestId, "genesis-submit"], { signedSafeJson }, x.cookie.owner));
      /* governance over the real routes */
      x.propose = async (vaultId, action, params, auth = x.cookie.owner) => {
        const r = await x.call("POST", ["governance", "proposals"], { vaultId, action, params }, auth);
        assert.equal(r.status, 201, `proposal created (${said(r)})`);
        return r.body.proposal;
      };
      x.approve = async (proposalId) => {
        const got = await x.call("GET", ["governance", "proposals", proposalId], null, x.cookie.owner);
        assert.equal(got.status, 200, `proposal readable (${said(got)})`);
        const signature = kaspa.signMessage({ message: got.body.proposal.approvalMessage, privateKey: new kaspa.PrivateKey(w.owner.secretHex).toString() });
        const r = await x.call("POST", ["governance", "proposals", proposalId, "approvals"], { approverAddress: w.owner.address, signature }, x.cookie.owner);
        assert.equal(r.status, 200, `owner approval (${said(r)})`);
        assert.equal(r.body.proposal.approvals.satisfied, true, "the owner's approval satisfies the proposal");
        return r.body.proposal;
      };
      x.proposalRecord = (proposalId) => require("../../server/src/governance").loadProposalRecord(config, proposalId);
      x.proposerCredential = async () => {
        const r = await x.call("POST", ["identities"], { label: "RC45 R2 TEST proposer", scopes: ["governance:propose"] }, x.cookie.owner);
        assert.equal(r.status, 201, `owner-minted machine credential (${said(r)})`);
        return { authorization: `Bearer ${r.body.credential.token}` };
      };
      /* An organization owned by the reviewer, holding vault v, with the given governance / risk controls. */
      x.organize = async (v, { governance = {}, risk = {} } = {}) => {
        const org = require(path.join(SDK_SRC, "organization.js"));
        const created = await org.createOrganization(config, { name: `RC45 R2 TEST org ${v.tag}`, tenantOwner: w.reviewer.xonly });
        const assignments = await org.loadAssignments(config);
        await org.assignVault(config, { vaultId: v.vaultId, orgId: created.orgId, group: null, expectedVersion: assignments.version, vaultExists: async () => true });
        await require("../../server/src/org-controls").saveOrgControls(config, created.orgId, { governance, risk, expectedVersion: 0 });
        return created.orgId;
      };
      x.release = async (evaluationId) => {
        const r = await x.call("POST", ["risk", "evaluations", evaluationId, "release"], {}, x.cookie.reviewer);
        assert.equal(r.status, 200, `the reviewer releases the hold (${said(r)})`);
        assert.equal(r.body.evaluation.status, "RELEASED");
        return r.body.evaluation;
      };
      x.evaluation = (evaluationId) => store.read(Categories.RISK_EVALUATION, evaluationId);
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

/* ---------------- committed-state checks ---------------- */
/* A built lifecycle request commits exactly the root its stored registry folds to. */
function assertLifecycleFolds(request, label) {
  assert.equal(request.sdkAction, "ownerSetAgentRoot", `${label}: a leaf-setting request`);
  assert.ok(Array.isArray(request.newRegistry), `${label}: the stored registry is an array`);
  assert.equal(fold(request.newRegistry), request.build.successorState.agentRoot, `${label}: the stored registry folds to the committed successor agent root`);
}
/* A built genesis commits exactly the root its stored registry folds to, in the broadcast build and the top-level state. */
function assertGenesisFolds(request, label) {
  assert.ok(Array.isArray(request.initialRegistry), `${label}: the stored initial registry is an array`);
  assert.equal(fold(request.initialRegistry), request.build.initialState.agentRoot, `${label}: the initial registry folds to the genesis build's agent root`);
  assert.equal(String(request.build.initialState.agentRoot).toLowerCase(), String(request.initialState.agentRoot).toLowerCase(), `${label}: the genesis build's agent root equals the top-level initial state's`);
}
/* The approved change vs the committed one: the only differences may be later periodStartDaa values (periodSpent identical). */
function assertGovernanceException(proposalRecord, manifest, request, label) {
  const governance = require("../../server/src/governance");
  const { classifyPolicyDelta } = require("../../core/governance");
  const approvedAfter = proposalRecord.proposal.after;
  const committedAfter = governance.v4PolicyTuple({ live: manifest.live, agentRegistry: cand.manifest4.normalizeRegistry(request.newRegistry).entries });
  if (require("../../core/intent").canonicalEqual(approvedAfter, committedAfter)) return;
  const delta = classifyPolicyDelta({ covenantVersion: manifest.contractVersion, before: approvedAfter, after: committedAfter });
  const moved = delta.perField.filter((e) => e.direction !== "NEUTRAL" && e.code !== "UNCHANGED");
  assert.ok(moved.length > 0, `${label}: a differing committed state is classified`);
  for (const e of moved) {
    assert.match(e.field, /^agents\[[0-9a-f]{64}\]\.periodStartDaa$/, `${label}: only a delegate's periodStartDaa may differ from the approved after-state (got ${e.field} ${e.code})`);
    assert.ok(BigInt(e.after) >= BigInt(e.before), `${label}: the committed start ${e.after} is never earlier than the approved ${e.before}`);
  }
  for (const e of delta.perField.filter((x) => /\.periodSpent$/.test(x.field))) assert.equal(e.code, "UNCHANGED", `${label}: periodSpent is committed exactly as approved`);
}

module.exports = {
  cand, Categories, K, F3, KAS, LOOPBACK, D, DAY, HOUR, windowDaa, sleep, said, nodeDown,
  wallets, delegate, canonicalEntries, fold, entryOf, seedVault, snapAll, buildScope, withAnchor, useAnchorDaa, withDaa,
  installNodePatch, useNodeClient, withNodeClient, UNREADABLE_NODES, assertNodeClientClosed, dagNode, genesisNode, genesisSubmitThrough, signGenesis, fundingFor, suite,
  assertLifecycleFolds, assertGenesisFolds, assertGovernanceException
};
