"use strict";
/*
 * RC45 F5 test kit (fix item F5 RC45-L5-VERIFY-SETTLEMENT; plan
 * rc45-simplified-plan-r2 §2.0 SEEN / CONFIRMED / depth, §2.2 the Verify
 * settlement pass, §2.5 adoption, §4 crash points, §8 rules). Internal
 * RED-first regression material for the RC45 candidate; not an audit.
 *
 * Shared by sdk/test/rc45-t3-verify-settlement.test.js (T3 Verify-pass legs),
 * sdk/test/rc45-t5-adoption.test.js (T5 adoption / restore legs) and
 * sdk/test/rc45-t7-verify-crash.test.js (T7 crash convergence), and by the
 * RC44 child in sdk/testutil/rc45-f5-rc44-history.js. Every function takes the
 * module set `m` it must use (the candidate's own sdk/src, or the pinned RC44
 * overlay in the RC44 child), so this file loads no runtime module itself.
 *
 * THE CHAIN MODEL (plan r2 §8 rules): UTXOs carry blockDaaScore; the DAG
 * reports a virtualDaaScore and a sink on a linear selected chain whose blocks
 * record the transactions they accepted (getVirtualChainFromBlock answers from
 * it); submitTransaction admits a registered transaction to the mempool only
 * when every input is unspent and unclaimed by another mempool transaction,
 * answering with rusty-kaspa v2.0.1 wire texts (rpc/core/src/error.rs
 * "Rejected transaction {id}: {reason}" over mining/errors/src/mempool.rs
 * reasons); getMempoolEntry answers the exact "Transaction {id} not found"
 * miss. Outputs appear only through confirm() (or confirmOnSubmit). Nothing
 * dials a node: every config names ws://127.0.0.1:1 and every call passes the
 * model as `rpc`. TEST keys only.
 *
 * VERIFY CHILD (this file run as a script): the candidate reconcileVaultV4 in
 * a FRESH process against the same JSON root or PostgreSQL database, with a
 * serialized chain model, killed with SIGKILL at a chosen durable step (every
 * store write / createExclusive / remove / appendAudit is one step) or right
 * after the terminal (RECOVERED) manifest write.
 */
const path = require("node:path"), fs = require("node:fs"), crypto = require("node:crypto");
const assert = require("node:assert/strict");
const H44 = require("./rc45-rc44-history");
const { KAS, LOOPBACK, clone, modulesOf, ownedTempRoot, removeOwnedRoot } = H44;

const SETTLE_DEPTH_DAA = 1000n; // plan r2 §2.0 D
const V0 = 90_000_000n; // the model's initial virtualDaaScore
const ANCHOR = "31".repeat(32);
const CHILD_MODE = "rc45-f5-verify-child", CHILD_TAG = "RC45-F5-VERIFY-CHILD-RESULT ";
const hex = (s) => crypto.createHash("sha256").update(String(s)).digest("hex");
const frozenOf = (request) => JSON.parse(request.build.frozenCanonicalJson);
const jsonSafe = (value) => JSON.parse(JSON.stringify(value, (_k, v) => (typeof v === "bigint" ? String(v) : v)));
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/* One TEST vault: id, genesis outpoint L0, covenant id and three owner fuels (distinct hex64 values per tag). */
function vault(tag) {
  const h = (what) => hex(`rc45-f5-${tag}-${what}`);
  return Object.freeze({ tag, vaultId: h("vault"), out: h("genesis"), cov: h("covenant"), fuel: h("fuel"), fuel2: h("fuel2"), fuel3: h("fuel3") });
}
/* TEST wallets: owner 0x11, agent 0x21, recipients 0x31 / 0x32 / 0x33. */
function walletsFor(config) {
  const kaspa = require(config.rustyKaspaModule);
  const one = (byte) => {
    const secretHex = byte.toString(16).padStart(2, "0").repeat(32), priv = new kaspa.PrivateKey(secretHex);
    return { secretHex, xonly: priv.toPublicKey().toXOnlyPublicKey().toString().toLowerCase(), address: priv.toPublicKey().toAddress(config.networkId).toString() };
  };
  return { owner: one(0x11), agent: one(0x21), recipient: one(0x31), recipient2: one(0x32), recipient3: one(0x33) };
}
/* `n` further deterministic TEST recipient keys (x-only only; nothing ever signs for them). */
function spamRecipients(config, n) {
  const kaspa = require(config.rustyKaspaModule);
  return Array.from({ length: n }, (_, i) => ({ xonly: new kaspa.PrivateKey(hex(`rc45-f5-test-recipient-${i}`)).toPublicKey().toXOnlyPublicKey().toString().toLowerCase() }));
}
/* Copy the v0.4 / v0.4.1 compile cache (deterministic real-silverc artifacts keyed by stateId under dataRoot) from
 * one test-owned root to another, so a fresh case does not recompile states its template already compiled. */
function warmCompileCache(fromRoot, toRoot) {
  for (const sub of ["build-v4", "build-v4_1"]) {
    const from = path.join(fromRoot, sub);
    if (fs.existsSync(from)) fs.cpSync(from, path.join(toRoot, sub), { recursive: true, force: false, errorOnExist: false });
  }
}
/* Seed a v0.4.1 vault manifest at L0 = v.out:0 (the shape every RC45 suite uses). */
async function seedVault(m, config, v, w, { paused = false, periodBudgetKas = 50n, protectedKas = 1000n, recipients = null, label = "RC45 F5 TEST" } = {}) { // recipients: objects with .xonly
  const rs = (recipients ?? [w.recipient]).map((r) => r.xonly);
  const entry = { agentPk: w.agent.xonly, maxPerSpend: (20n * KAS).toString(), periodBudget: (BigInt(periodBudgetKas) * KAS).toString(), periodLengthDaa: "864000", periodStartDaa: "541000000", periodSpent: "0", approvalThreshold: (5n * KAS).toString(), agentMaxFeePerTx: KAS.toString(), recipients: rs };
  const template = { owner: w.owner.xonly, vaultId: v.vaultId };
  const policy = m.agents.normalizeAgentPolicyV4({ ...entry, agentRecipientRoot: m.recipients.buildRecipientTree(entry.recipients).root });
  const state = m.vs4.normalizeStateV4({ protectedValue: (BigInt(protectedKas) * KAS).toString(), feeReserve: (5n * KAS).toString(), paused: paused ? "1" : "0", agentRoot: m.agents.buildAgentTreeV4([policy]).root, approvers: [], approvalM: "0", policyNonce: "0" });
  const contractVersion = m.vs4.CONTRACT_VERSION_V4_1;
  const compiled = m.compiler4.compileExactStateV4({ config, template, state, contractVersion });
  await m.manifest4.persistManifestV4(config, { schema: "policyvault-vault-manifest/v4", contractVersion, networkId: config.networkId, vaultId: v.vaultId, label: `${label} ${v.tag}`, status: paused ? "PAUSED" : "ACTIVE", template, agentRegistry: [entry],
    live: { state: m.vs4.stateToJsonV4(state), stateId: m.vs4.computeStateIdV4({ networkId: config.networkId, template, state, contractVersion }), outpoint: { transactionId: v.out, index: 0 }, outpointValue: (state.protectedValue + state.feeReserve).toString(), scriptSha256: compiled.scriptSha256, covenantId: v.cov },
    creationTxId: v.out, latestTransitionTxId: null, lastTransition: null });
}
function kitFor(m, config, w) {
  const spend = (sompi, recipient = w.recipient) => ({ payAmountSompi: BigInt(sompi).toString(), agentPk: w.agent.xonly, recipient: recipient.xonly });
  const fuelOf = (v, which = "fuel") => ({ outpoint: { transactionId: v[which], index: 1 }, amount: (100n * KAS).toString(), scriptPublicKeyHex: `20${w.owner.xonly}ac` });
  const build = (v, action, params, signer) => m.wr4.buildWalletRequestV4({ config, vaultId: v.vaultId, action, params, signerAddress: signer.address });
  const sign = (request, signer) => m.signer.makeDevSigner(config, { secretHex: signer.secretHex, expectedAddress: signer.address }).signInputs(request.transaction.unsignedSafeJson, request.transaction.signInputs);
  return {
    spend, fuelOf, sign,
    agentSpend: (v, kas, recipient) => build(v, "agentSpend", spend(BigInt(kas) * KAS, recipient), w.agent),
    agentSpendSompi: (v, sompi, recipient) => build(v, "agentSpend", spend(sompi, recipient), w.agent),
    ownerOp: (v, action, which = "fuel") => build(v, action, { fuel: fuelOf(v, which) }, w.owner),
    finalize: (request, signer) => m.wr4.finalizeWalletRequestV4({ config, requestId: request.requestId, signedSafeJson: sign(request, signer) })
  };
}

/* ---------------- THE CHAIN MODEL ---------------- */
function chainModel(config, init = null) {
  const kaspa = require(config.rustyKaspaModule);
  const utxos = new Map(), mempool = new Map(), known = new Map(), calls = [], reads = [], broadcasts = [];
  const state = { virtualDaaScore: V0, confirmOnSubmit: false, failRead: null, sinks: [ANCHOR], accepted: new Map([[ANCHOR, []]]) };
  if (init) {
    for (const u of init.utxos) utxos.set(`${u.outpoint.transactionId}:${u.outpoint.index}`, clone(u));
    state.virtualDaaScore = BigInt(init.virtualDaaScore);
    state.sinks = [...init.sinks]; state.accepted = new Map(init.accepted.map(([h, ids]) => [h, [...ids]]));
    for (const [id, spends] of init.mempool) mempool.set(id, { spends: [...spends] });
    if (init.failReadAll === true) state.failRead = () => true;
  }
  const key = (o) => `${String(o.transactionId).toLowerCase()}:${Number(o.index)}`;
  const addressOf = (spk) => kaspa.addressFromScriptPublicKey({ version: Number(spk.version), script: spk.scriptHex }, config.networkId).toString();
  function block(ids) { const h = hex(`rc45-f5-block-${state.sinks.length}-${ids.join(",")}-${state.sinks.at(-1)}`); state.sinks.push(h); state.accepted.set(h, [...ids]); return h; }
  function add(outpoint, amount, spk, covenantId, blockDaaScore = state.virtualDaaScore) {
    utxos.set(key(outpoint), { address: addressOf(spk), outpoint: { transactionId: String(outpoint.transactionId).toLowerCase(), index: Number(outpoint.index) }, amount: String(amount),
      scriptPublicKey: { version: Number(spk.version), script: spk.scriptHex }, covenantId: covenantId ?? null, blockDaaScore: String(blockDaaScore), isCoinbase: false });
  }
  /* The inputs of `tx` as settled UTXOs (deep: 5,000 DAA below the virtual). */
  function seedInputs(tx, covenantId, blockDaaScore = state.virtualDaaScore - 5000n) {
    tx.inputs.forEach((i, index) => add(i.previousOutpoint, i.utxo.amount, i.utxo.scriptPublicKey, index === 0 ? covenantId : (i.utxo.covenantId ?? null), blockDaaScore));
  }
  /* `tx` accepted in a new selected-chain block at `blockDaaScore` (default: the current virtual score, depth 0). */
  function confirm(tx, txId, blockDaaScore = state.virtualDaaScore) {
    for (const i of tx.inputs) utxos.delete(key(i.previousOutpoint));
    mempool.delete(txId);
    tx.outputs.forEach((o, index) => add({ transactionId: txId, index }, o.value, o.scriptPublicKey, o.covenant?.covenantId ?? null, blockDaaScore));
    block([txId]);
  }
  const rpc = {
    async getUtxosByAddresses({ addresses }) {
      calls.push("getUtxosByAddresses"); reads.push(addresses.map(String));
      if (state.failRead && addresses.some((a) => state.failRead(String(a)))) throw new Error("TEST chain model: RPC connection reset by peer (getUtxosByAddresses unavailable)");
      const wanted = new Set(addresses.map(String));
      return { entries: [...utxos.values()].filter((u) => wanted.has(u.address)).map(clone) };
    },
    async getBlockDagInfo() { calls.push("getBlockDagInfo"); return { networkName: `kaspa-${config.networkId}`, sink: state.sinks.at(-1), virtualDaaScore: String(state.virtualDaaScore) }; },
    async getMempoolEntry({ transactionId }) {
      calls.push("getMempoolEntry");
      const id = String(transactionId).toLowerCase();
      if (!mempool.has(id)) throw new Error(`Transaction ${id} not found`);
      throw new Error("TEST chain model: mempool entry bodies are not modelled (unavailable)");
    },
    async getVirtualChainFromBlock({ startHash }) {
      calls.push("getVirtualChainFromBlock");
      const i = state.sinks.indexOf(String(startHash));
      if (i < 0) throw new Error(`TEST chain model: block ${startHash} is not on the modelled selected chain`);
      const added = state.sinks.slice(i + 1);
      return { removedChainBlockHashes: [], addedChainBlockHashes: added, acceptedTransactionIds: added.map((h) => ({ acceptingBlockHash: h, acceptedTransactionIds: [...(state.accepted.get(h) ?? [])] })) };
    },
    async submitTransaction({ transaction }) {
      calls.push("submitTransaction");
      const id = transaction.finalize().toString().toLowerCase();
      broadcasts.push(id);
      block([]); // the virtual moved on since the submitter read its start hash
      const tx = known.get(id);
      if (!tx) throw new Error(`TEST chain model: transaction ${id} was never registered with the model`);
      if (mempool.has(id)) throw new Error(`Rejected transaction ${id}: transaction ${id} is already in the mempool`);
      for (const i of tx.inputs) {
        for (const [other, entry] of mempool) {
          if (entry.spends.includes(key(i.previousOutpoint))) throw new Error(`Rejected transaction ${id}: output (${i.previousOutpoint.transactionId}, ${i.previousOutpoint.index}) already spent by transaction ${other} in the mempool`);
        }
      }
      if (tx.inputs.some((i) => !utxos.has(key(i.previousOutpoint)))) throw new Error(`Rejected transaction ${id}: transaction ${id} is an orphan where orphan is disallowed`);
      mempool.set(id, { spends: tx.inputs.map((i) => key(i.previousOutpoint)) });
      if (state.confirmOnSubmit) confirm(tx, id);
      return { transactionId: id };
    },
    async disconnect() { calls.push("disconnect"); }
  };
  return {
    rpc, add, remove: (outpoint) => utxos.delete(key(outpoint)), has: (outpoint) => utxos.has(key(outpoint)), seedInputs, confirm, calls, reads, broadcasts, addressOf,
    know(request) { known.set(request.txId, clone(request.finalTransaction)); },
    mempoolAdd(txId, outpoints) { mempool.set(String(txId).toLowerCase(), { spends: outpoints.map(key) }); },
    advance(daa) { state.virtualDaaScore += BigInt(daa); },
    set confirmOnSubmit(value) { state.confirmOnSubmit = value === true; },
    set failRead(predicate) { state.failRead = predicate; },
    get virtualDaaScore() { return state.virtualDaaScore; },
    /* Every address requested since `from` (a reads index), flattened. */
    readAddresses(from = 0) { return reads.slice(from).flat(); },
    serialize() {
      return { utxos: [...utxos.values()].map(clone), virtualDaaScore: String(state.virtualDaaScore), sinks: [...state.sinks],
        accepted: [...state.accepted.entries()].map(([h, ids]) => [h, [...ids]]), mempool: [...mempool.entries()].map(([id, e]) => [id, [...e.spends]]) };
    }
  };
}

/* ---------------- store helpers ---------------- */
function categoriesOf(m) { const C = m.store.Categories; return [C.VAULT, C.REQUEST, C.SUBMISSION_CLAIM, C.TRANSITION_CLAIM, C.RECEIPT]; }
async function records(m, config) {
  const s = m.store.getStore(config), out = {};
  for (const c of categoriesOf(m)) out[c] = await Promise.all((await s.listKeys(c)).sort().map(async (k) => [k, await s.read(c, k)]));
  return out;
}
async function snapshot(m, config) { return { records: await records(m, config), audit: await m.store.getStore(config).readAudit({ limit: 5000 }) }; }
async function install(m, config, snap) {
  const s = m.store.getStore(config);
  for (const [c, entries] of Object.entries(snap.records)) for (const [k, v] of entries) await s.write(c, k, clone(v));
  for (const row of [...snap.audit].reverse()) await s.appendAudit(clone(row));
}
/* Canonical durable state for crash-convergence and JSON/PostgreSQL parity: sorted keys, volatile timestamps dropped
 * (manifest updatedAt, receipt verifiedAt, audit `at`), audit rows as a sorted multiset. */
const VOLATILE = new Set(["updatedAt", "verifiedAt", "at"]);
function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value && typeof value === "object") return `{${Object.keys(value).filter((k) => !VOLATILE.has(k)).sort().map((k) => `${JSON.stringify(k)}:${canonicalJson(value[k])}`).join(",")}}`;
  return JSON.stringify(value);
}
function canonicalState(snap) {
  return canonicalJson({ records: snap.records, audit: snap.audit.map(canonicalJson).sort() });
}
function pgFromEnv() {
  return { host: process.env.POLICYVAULT_TEST_PG_HOST || "127.0.0.1", port: Number(process.env.POLICYVAULT_TEST_PG_PORT || 0), user: process.env.POLICYVAULT_TEST_PG_USER, database: process.env.POLICYVAULT_TEST_PG_DATABASE };
}

/*
 * Finalize each listed request in its OWN scratch copy of `template` (every other request of the vault is still
 * BUILT there, so no guard of any runtime sees pending work), then merge each finalized request record, its
 * submission claim, its budget reservation and its finalize audit rows back into `template`. The transition claim on
 * the predecessor is copied only for `claimHolder` (a request id, or null for no claim). This writes, with the
 * candidate's own finalize, exactly the durable records the RC45 contested break-glass finalize leaves (plan r2 §2.3
 * finalize row: the owner's W1 carries the bytes, the delegate's claim stays the only claim) — CANDIDATE-WRITTEN,
 * finalized apart and merged.
 */
async function finalizeApart(m, template, jobs, { claimHolder = null, track = () => {} } = {}) {
  const C = m.store.Categories, s = m.store.getStore(template), base = await snapshot(m, template);
  const seen = new Set(base.audit.map((row) => JSON.stringify(row)));
  let holder = null;
  for (const job of jobs) {
    const root = ownedTempRoot("pv-rc45-f5-apart-"); track(root);
    const scratch = m.config.loadConfig({ dataRoot: root, rpcUrl: LOOPBACK });
    await install(m, scratch, base);
    const ss = m.store.getStore(scratch);
    const r = await m.wr4.loadRequest(scratch, job.requestId);
    assert.equal(r.state, "BUILT", `${job.requestId} is BUILT before its apart finalize`);
    const signed = m.signer.makeDevSigner(scratch, { secretHex: job.signer.secretHex, expectedAddress: job.signer.address }).signInputs(r.transaction.unsignedSafeJson, r.transaction.signInputs);
    const done = await m.wr4.finalizeWalletRequestV4({ config: scratch, requestId: r.requestId, signedSafeJson: signed });
    assert.equal(done.state, "PREFLIGHT_VERIFIED", `${r.action} finalizes apart`);
    await s.write(C.REQUEST, r.requestId, await ss.read(C.REQUEST, r.requestId));
    const sub = await ss.read(C.SUBMISSION_CLAIM, done.txId);
    if (sub && !(await s.read(C.SUBMISSION_CLAIM, done.txId))) await s.write(C.SUBMISSION_CLAIM, done.txId, sub);
    if (r.sdkAction === "agentSpend") { const rk = m.budget.reservationKey(r); await s.write(C.TRANSITION_CLAIM, rk, await ss.read(C.TRANSITION_CLAIM, rk)); }
    const claimKey = m.claims.transitionClaimKey(r.predecessorOutpoint);
    if (job.requestId === claimHolder) holder = [claimKey, await ss.read(C.TRANSITION_CLAIM, claimKey)];
    for (const row of [...(await ss.readAudit({ limit: 5000 }))].reverse()) { const j = JSON.stringify(row); if (!seen.has(j)) { seen.add(j); await s.appendAudit(row); } }
  }
  if (holder) { assert.ok(holder[1], "the claim holder took its claim"); await s.write(C.TRANSITION_CLAIM, holder[0], holder[1]); }
}

/* The transition claim a finalize takes for `r` (shape of the finalize's own claim), for SYNTHETIC orphan claims. */
function claimArgsFor(r) {
  const b = r.build, index = b.frozen.outputs.findIndex((o) => o.covenant !== null);
  const expected = { kind: "successor", txId: r.txId, index, valueSompi: (BigInt(b.successorState.protectedValue) + BigInt(b.successorState.feeReserve)).toString(), covenantId: r.covenantId,
    scriptSha256: b.successorScriptSha256, stateId: r.successorStateId, state: b.successorState, newRegistry: r.newRegistry, action: r.sdkAction, contractVersion: r.contractVersion };
  return { outpoint: r.predecessorOutpoint, action: r.action, txId: r.txId, vaultId: r.vaultId, stateId: r.predecessorStateId, expected };
}

/* ---------------- the Verify child ---------------- */
async function verifyChild(input) {
  const cand = modulesOf(path.join(__dirname, "..", "src"));
  let config;
  if (input.pg) {
    config = cand.config.loadConfig({ persistenceBackend: "postgres", pgHost: input.pg.host, pgPort: input.pg.port, pgUser: input.pg.user, pgDatabase: input.pg.database, pgNoTls: true, hostedDevOpen: true, dataRoot: input.dataRoot, rpcUrl: LOOPBACK });
    await cand.store.openPgStore(config, { migrate: false });
  } else config = cand.config.loadConfig({ dataRoot: input.dataRoot, rpcUrl: LOOPBACK });
  assert.equal(config.networkId, "testnet-10");
  const store = cand.store.getStore(config), C = cand.store.Categories;
  let steps = 0;
  const die = () => { process.kill(process.pid, "SIGKILL"); return new Promise(() => {}); };
  for (const name of ["write", "createExclusive", "remove", "appendAudit"]) {
    const original = store[name].bind(store);
    store[name] = async (...args) => {
      if (input.killBefore === steps) await die();
      steps += 1;
      const out = await original(...args);
      if (input.killAfterTerminalManifest && name === "write" && args[0] === C.VAULT && args[2] && args[2].status === "RECOVERED") await die();
      return out;
    };
  }
  const model = chainModel(config, input.model);
  let result;
  try {
    const out = await cand.reconcile4.reconcileVaultV4(config, input.vaultId, { rpc: model.rpc });
    result = { ok: true, value: jsonSafe(out), steps, calls: model.calls.length };
  } catch (error) {
    result = { ok: false, code: error.code ?? null, message: String(error.message), steps, calls: model.calls.length };
  }
  if (input.pg) await store.close();
  return result;
}
/* Run the candidate Verify in a fresh child against `x` (a case from a suite's fresh()). */
function verifyInChild(x, v, { killBefore = null, killAfterTerminalManifest = false, env = {}, pg = null } = {}) {
  const payload = { vaultId: v.vaultId, dataRoot: x.config.dataRoot, pg: x.pgDatabase ? { ...pg, database: x.pgDatabase } : null, model: x.model.serialize(), killBefore, killAfterTerminalManifest };
  const child = require("node:child_process").spawnSync(process.execPath, [__filename, CHILD_MODE, JSON.stringify(payload)], { encoding: "utf8", timeout: 300000, maxBuffer: 16 * 1024 * 1024, env: { ...process.env, ...env } });
  const line = (child.stdout || "").split("\n").find((l) => l.startsWith(CHILD_TAG));
  return { signal: child.signal, status: child.status, stderr: (child.stderr || "").slice(-4000), result: line ? JSON.parse(line.slice(CHILD_TAG.length)) : null };
}

if (require.main === module && process.argv[2] === CHILD_MODE) {
  verifyChild(JSON.parse(process.argv[3])).then(
    (result) => { process.stdout.write(`${CHILD_TAG}${JSON.stringify(result)}\n`); },
    (error) => { process.stderr.write(`${error && error.stack ? error.stack : error}\n`); process.exitCode = 1; }
  );
}

module.exports = {
  KAS, LOOPBACK, ANCHOR, V0, SETTLE_DEPTH_DAA, clone, hex, frozenOf, jsonSafe, sleep,
  modulesOf, ownedTempRoot, removeOwnedRoot, verifyRc44Tree: H44.verifyRc44Tree, rc44Overlay: H44.rc44Overlay,
  vault, walletsFor, spamRecipients, warmCompileCache, seedVault, kitFor, chainModel, records, snapshot, install, canonicalJson, canonicalState, pgFromEnv,
  finalizeApart, claimArgsFor, verifyInChild
};
