"use strict";
/*
 * RC45 T2 — BLOCKING SCOPED TO THE LIVE OUTPOINT (fix item F2 RC45-L5-SCOPE;
 * plan rc45-simplified-plan-r2 §2.1(2)-(3), §2.3 staleness row, §2.4 H-35 and
 * "absence never labels", §8 T2, §8.2 sabotage q/h/s/t). Internal RED-first
 * regression material for the RC45 candidate; not an audit.
 *
 * RED on C1 e62b1973 (vault-wide guard; no pre-sign claim check; STALE on a
 * closed manifest, on the request's own advanced transaction and on an
 * unindexed live outpoint; staleness by stateId only). GREEN after F2:
 *   - closed vault -> the first vault-wide PENDING record refuses every action
 *     (RC40, unchanged, HOLDS);
 *   - live vault + owner break-glass (ownerPause / ownerRecover) -> never
 *     refused by pending records or claims;
 *   - otherwise -> only a PENDING record ON the live outpoint whose txid
 *     differs from the caller's refuses (422 REQUEST_RECOVERY_REQUIRED, with
 *     error.extra naming it); an ordinary build is also refused pre-sign by
 *     any claim on the live outpoint (409 CLAIM_CONFLICT, extra.claimTxId);
 *   - submit/finalize staleness: !manifest.live -> 422 with no write
 *     (VAULT_TERMINAL when RECOVERED, else RECONCILIATION_REQUIRED); STALE only
 *     when the live manifest differs by stateId OR outpoint and the manifest
 *     was not advanced by the request's own txid (own txid -> 422
 *     RECONCILIATION_REQUIRED, no write); an unindexed live outpoint at submit
 *     -> 422 RECONCILIATION_REQUIRED, request/claims/reservation byte-identical.
 *
 * Layers: SDK plus one HTTP status leg (real api.handle). Real v0.4.1
 * compiler, pv_call_encoder, TEST-key signatures (deterministic dev signer)
 * and pv_vm_preflight for every consensus byte. Node observations come ONLY
 * from the explicit chain model below (UTXO sets with blockDaaScore, a
 * virtualDaaScore, a mempool with conflict detection, rusty-kaspa v2.0.1 wire
 * texts); every config names ws://127.0.0.1:1, so nothing can dial a node.
 *
 * RC44-written shapes (CR-M13) — an age-released PREFLIGHT_VERIFIED (RC44
 * case C), RC44's zero-depth RECOVERED, RC44 case-E TERMINATED_UNKNOWN, an
 * RC44 case-A manifest advanced by the request's own txid, RC44-built twins —
 * are written by the pinned df5b8de writers in POLICYVAULT_TEST_RC44_TREE,
 * run in a child process (this file in "rc44-writer" mode, which loads ONLY
 * that tree's modules). A missing or mismatched tree FAILS (never skips).
 * The RC44 extraction ships no VM binaries and its pv_tx_probe path is
 * tree-relative, so the child runs from a test-local overlay: byte copies of
 * the RC44 sdk/src, core and contracts (the writer pins and the sdk/src tree
 * are re-verified on the copy), links to its remaining directories and
 * dependencies, and links to this tree's pv_tx_probe / pv_call_encoder /
 * pv_vm_preflight. The RC44 child writes a JSON root; each PostgreSQL leg installs
 * those exact record values into its own freshly migrated database.
 * Candidate-written bases (the H-35 recurrence, the absence leg and the L-16
 * claim-without-bytes shape) are written by the candidate's own writers; the
 * H-35 manifest rewrite and the L-16 claim are labelled synthetic below.
 *
 * Both stores: JSON always; PostgreSQL with POLICYVAULT_TEST_PG_{PORT,USER,
 * DATABASE} (the rc45 runner's pg mode; a skipped PostgreSQL leg in that run
 * is a FAIL). TEST keys only; no production data, credentials or endpoints.
 */
const path = require("node:path"), fs = require("node:fs"), os = require("node:os"), crypto = require("node:crypto");
const assert = require("node:assert/strict");

const KAS = 100000000n, ANCHOR = "31".repeat(32), LOOPBACK = "ws://127.0.0.1:1";
const WRITER_MODE = "rc44-writer", RESULT_TAG = "RC44-T2-WRITER-RESULT ";
/* Plan r2 §8 (CR-M13): the df5b8de writer files and the df5b8de sdk/src tree. */
const RC44_WRITER_PINS = Object.freeze({
  "sdk/src/wallet-requests-v4.js": "267ea76b5f580cdf10495d83721b862748f416b7c5b1dea570047dd4d3178dfe",
  "sdk/src/wallet-submit-v4.js": "a2b98ccfa696d927a61e8fb4727ccd4988aad959ffcb3b0c994001b34099c0b6",
  "sdk/src/wallet-recovery-v4.js": "b4c18259d905e1785a29a882d5ca89c1f143d54d99240fd7064dd3e38537ac68",
  "sdk/src/reconcile-v4.js": "56b45432e0092196e645aa91518cdbf0c207d2c11fecb660feac5775ea1454e0",
  "sdk/src/store.js": "239b3c8418b63e4112385c9a8198ee821eac52432b6bdb9e8d8202e822b3f426"
});
const RC44_SDK_SRC_TREE = "af22dfb2238a7e271ffd65eea5dba3b773c9bd6c";
const VM_BIN = path.join(__dirname, "..", "..", "tests", "vm", "target", "debug");

const clone = (value) => JSON.parse(JSON.stringify(value));
const sha256File = (file) => crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");
/* git tree id of a flat directory of regular 100644 files (the pinned
 * df5b8de sdk/src tree has 96 such blobs and no subtree). */
function gitTreeOfFlatDir(dir) {
  const names = fs.readdirSync(dir).sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)));
  const parts = [];
  for (const name of names) {
    const file = path.join(dir, name);
    assert.ok(fs.lstatSync(file).isFile(), `${file} must be a regular file`);
    const body = fs.readFileSync(file);
    parts.push(Buffer.from(`100644 ${name}\0`), crypto.createHash("sha1").update(Buffer.concat([Buffer.from(`blob ${body.length}\0`), body])).digest());
  }
  const content = Buffer.concat(parts);
  return crypto.createHash("sha1").update(Buffer.concat([Buffer.from(`tree ${content.length}\0`), content])).digest("hex");
}
function verifyRc44Tree(tree) {
  assert.ok(typeof tree === "string" && path.isAbsolute(tree), "POLICYVAULT_TEST_RC44_TREE must name the absolute df5b8de extraction (a missing tree is a FAIL, never a SKIP)");
  for (const [rel, pin] of Object.entries(RC44_WRITER_PINS)) assert.equal(sha256File(path.join(tree, rel)), pin, `RC44 writer ${rel} is not the pinned df5b8de byte sequence`);
  assert.equal(gitTreeOfFlatDir(path.join(tree, "sdk", "src")), RC44_SDK_SRC_TREE, "RC44 sdk/src is not the pinned df5b8de tree");
  assert.ok(fs.existsSync(path.join(tree, "sdk", "node_modules")), "the RC44 tree carries its exact offline dependencies");
}
/* A test-local copy of the df5b8de extraction that can run its writers: the
 * RC44 modules resolve tests/vm/target/debug relative to their own files. */
function rc44Overlay(tree, root) {
  fs.mkdirSync(path.join(root, "sdk"));
  for (const entry of fs.readdirSync(tree)) {
    if (entry === "sdk") continue;
    if (entry === "core" || entry === "contracts") fs.cpSync(path.join(tree, entry), path.join(root, entry), { recursive: true });
    else fs.symlinkSync(path.join(tree, entry), path.join(root, entry));
  }
  for (const entry of fs.readdirSync(path.join(tree, "sdk"))) {
    if (entry === "src") fs.cpSync(path.join(tree, "sdk", "src"), path.join(root, "sdk", "src"), { recursive: true });
    else fs.symlinkSync(path.join(tree, "sdk", entry), path.join(root, "sdk", entry));
  }
  fs.mkdirSync(path.join(root, "tests", "vm", "target", "debug"), { recursive: true });
  for (const bin of ["pv_tx_probe", "pv_call_encoder", "pv_vm_preflight"]) fs.symlinkSync(path.join(VM_BIN, bin), path.join(root, "tests", "vm", "target", "debug", bin));
  // The extraction is read-only; make the COPIED directories removable (links are never followed).
  (function writable(dir) {
    fs.chmodSync(dir, 0o755);
    for (const entry of fs.readdirSync(dir)) { const p = path.join(dir, entry); if (fs.lstatSync(p).isDirectory()) writable(p); }
  })(root);
  verifyRc44Tree(root);
  return root;
}
/* Remove a test-owned temporary root without ever following a link (the
 * RC44 overlay links into the read-only extraction and this tree's VM bins). */
function removeOwnedRoot(root) {
  const tmp = fs.realpathSync(os.tmpdir());
  assert.ok(typeof root === "string" && root.length > tmp.length + 1 && path.dirname(root) === tmp && path.basename(root).startsWith("pv-rc45-t2-"), `refusing to remove ${root}`);
  (function remove(p) {
    const st = fs.lstatSync(p, { throwIfNoEntry: false });
    if (!st) return;
    if (st.isDirectory()) { for (const entry of fs.readdirSync(p)) remove(path.join(p, entry)); fs.rmdirSync(p); }
    else fs.unlinkSync(p); // a regular file, or the link itself
  })(root);
}
function modulesOf(sdkSrc) {
  const r = (name) => require(path.join(sdkSrc, name));
  return { config: r("config.js"), store: r("store.js"), wr4: r("wallet-requests-v4.js"), submit4: r("wallet-submit-v4.js"), reconcile4: r("reconcile-v4.js"),
    manifest4: r("manifest-v4.js"), vs4: r("vault-state-v4.js"), compiler4: r("contract-compiler-v4.js"), agents: r("agent-merkle-v4.js"),
    recipients: r("recipient-merkle-v3.js"), signer: r("signer-dev.js"), claims: r("submission-claim.js"), budget: r("budget-reservation.js") };
}
function walletsFor(config) {
  const kaspa = require(config.rustyKaspaModule);
  const one = (byte) => {
    const secretHex = byte.toString(16).padStart(2, "0").repeat(32), priv = new kaspa.PrivateKey(secretHex);
    return { secretHex, xonly: priv.toPublicKey().toXOnlyPublicKey().toString().toLowerCase(), address: priv.toPublicKey().toAddress(config.networkId).toString() };
  };
  return { owner: one(0x11), agent: one(0x21), recipient: one(0x31) };
}
/* One vault per history: its id, genesis outpoint L0, covenant id and owner fuel. */
function vault(tag) { const d = tag[1]; return Object.freeze({ tag, vaultId: tag.repeat(32), out: `d${d}`.repeat(32), cov: `e${d}`.repeat(32), fuel: `f${d}`.repeat(32) }); }
const V = Object.freeze({
  anc: vault("c1"), ancS: vault("c2"), onL: vault("c3"), onLs: vault("c4"), twinS: vault("c5"), recS: vault("c6"), recF: vault("c7"),
  tuS: vault("c8"), tuF: vault("c9"), own: vault("ca"), h35s: vault("cb"), h35f: vault("cc"), abs: vault("cd"), claim: vault("ce")
});
/* H-35: the recorded pause (L0 -> P2) and unpause (P2 -> P3) return the vault to the same stateId at a new outpoint. */
const P2 = Object.freeze({ transactionId: "b1".repeat(32), index: 0 }), P3 = Object.freeze({ transactionId: "b2".repeat(32), index: 0 });

async function seedVault(m, config, v, w) {
  const entry = { agentPk: w.agent.xonly, maxPerSpend: (20n * KAS).toString(), periodBudget: (50n * KAS).toString(), periodLengthDaa: "864000", periodStartDaa: "541000000", periodSpent: "0", approvalThreshold: (5n * KAS).toString(), agentMaxFeePerTx: KAS.toString(), recipients: [w.recipient.xonly] };
  const template = { owner: w.owner.xonly, vaultId: v.vaultId };
  const policy = m.agents.normalizeAgentPolicyV4({ ...entry, agentRecipientRoot: m.recipients.buildRecipientTree(entry.recipients).root });
  const state = m.vs4.normalizeStateV4({ protectedValue: (1000n * KAS).toString(), feeReserve: (5n * KAS).toString(), paused: "0", agentRoot: m.agents.buildAgentTreeV4([policy]).root, approvers: [], approvalM: "0", policyNonce: "0" });
  const contractVersion = m.vs4.CONTRACT_VERSION_V4_1;
  const compiled = m.compiler4.compileExactStateV4({ config, template, state, contractVersion });
  await m.manifest4.persistManifestV4(config, { schema: "policyvault-vault-manifest/v4", contractVersion, networkId: config.networkId, vaultId: v.vaultId, label: `RC45 T2 TEST ${v.tag}`, status: "ACTIVE", template, agentRegistry: [entry],
    live: { state: m.vs4.stateToJsonV4(state), stateId: m.vs4.computeStateIdV4({ networkId: config.networkId, template, state, contractVersion }), outpoint: { transactionId: v.out, index: 0 }, outpointValue: (state.protectedValue + state.feeReserve).toString(), scriptSha256: compiled.scriptSha256, covenantId: v.cov },
    creationTxId: v.out, latestTransitionTxId: null, lastTransition: null });
}
function kitFor(m, config, w) {
  const spend = (kas) => ({ payAmountSompi: (BigInt(kas) * KAS).toString(), agentPk: w.agent.xonly, recipient: w.recipient.xonly });
  const fuel = (v) => ({ outpoint: { transactionId: v.fuel, index: 1 }, amount: (100n * KAS).toString(), scriptPublicKeyHex: `20${w.owner.xonly}ac` });
  const build = (v, action, params, signer) => m.wr4.buildWalletRequestV4({ config, vaultId: v.vaultId, action, params, signerAddress: signer.address });
  const sign = (request, signer) => m.signer.makeDevSigner(config, { secretHex: signer.secretHex, expectedAddress: signer.address }).signInputs(request.transaction.unsignedSafeJson, request.transaction.signInputs);
  return {
    spend, fuel, sign,
    agentSpend: (v, kas) => build(v, "agentSpend", spend(kas), w.agent),
    ownerOp: (v, action, extra = {}) => build(v, action, { fuel: fuel(v), ...extra }, w.owner),
    finalize: (request, signer) => m.wr4.finalizeWalletRequestV4({ config, requestId: request.requestId, signedSafeJson: sign(request, signer) })
  };
}

/* THE CHAIN MODEL (plan r2 §8 rules). UTXOs carry blockDaaScore; the DAG
 * reports a virtualDaaScore; submitTransaction admits a known transaction to
 * the mempool only when every input is unspent and unclaimed by another
 * mempool transaction, answering exactly as rusty-kaspa v2.0.1 does
 * (rpc/core/src/error.rs "Rejected transaction {id}: {reason}" over
 * mining/errors/src/mempool.rs reasons). Outputs appear only through
 * confirm() (or confirmOnSubmit). Historical acceptance and mempool bodies
 * are not modelled and answer as unavailable (fail closed). */
function chainModel(config) {
  const kaspa = require(config.rustyKaspaModule);
  const utxos = new Map(), mempool = new Map(), known = new Map(), calls = [], broadcasts = [];
  const state = { virtualDaaScore: 90_000_000n, confirmOnSubmit: false };
  const key = (o) => `${String(o.transactionId).toLowerCase()}:${Number(o.index)}`;
  const addressOf = (spk) => kaspa.addressFromScriptPublicKey({ version: Number(spk.version), script: spk.scriptHex }, config.networkId).toString();
  function add(outpoint, amount, spk, covenantId, blockDaaScore = state.virtualDaaScore) {
    utxos.set(key(outpoint), { address: addressOf(spk), outpoint: { transactionId: String(outpoint.transactionId).toLowerCase(), index: Number(outpoint.index) }, amount: String(amount),
      scriptPublicKey: { version: Number(spk.version), script: spk.scriptHex }, covenantId: covenantId ?? null, blockDaaScore: String(blockDaaScore), isCoinbase: false });
  }
  /* The inputs of `tx` as settled UTXOs (deep: 5,000 DAA below the virtual). */
  function seedInputs(tx, covenantId) {
    tx.inputs.forEach((i, index) => add(i.previousOutpoint, i.utxo.amount, i.utxo.scriptPublicKey, index === 0 ? covenantId : (i.utxo.covenantId ?? null), state.virtualDaaScore - 5000n));
  }
  function confirm(tx, txId) {
    for (const i of tx.inputs) utxos.delete(key(i.previousOutpoint));
    mempool.delete(txId);
    tx.outputs.forEach((o, index) => add({ transactionId: txId, index }, o.value, o.scriptPublicKey, o.covenant?.covenantId ?? null));
  }
  const rpc = {
    async getUtxosByAddresses({ addresses }) {
      calls.push("getUtxosByAddresses");
      const wanted = new Set(addresses.map(String));
      return { entries: [...utxos.values()].filter((u) => wanted.has(u.address)).map(clone) };
    },
    async getBlockDagInfo() { calls.push("getBlockDagInfo"); return { networkName: `kaspa-${config.networkId}`, sink: ANCHOR, virtualDaaScore: String(state.virtualDaaScore) }; },
    async getMempoolEntry({ transactionId }) {
      calls.push("getMempoolEntry");
      const id = String(transactionId).toLowerCase();
      if (!mempool.has(id)) throw new Error(`Transaction ${id} not found`);
      throw new Error("TEST chain model: mempool entry bodies are not modelled (unavailable)");
    },
    async getVirtualChainFromBlock() { calls.push("getVirtualChainFromBlock"); throw new Error("TEST chain model: virtual-chain acceptance history is not modelled (unavailable)"); },
    async submitTransaction({ transaction }) {
      calls.push("submitTransaction");
      const id = transaction.finalize().toString().toLowerCase();
      broadcasts.push(id);
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
    rpc, add, seedInputs, confirm, calls, broadcasts,
    know(request) { known.set(request.txId, clone(request.finalTransaction)); },
    set confirmOnSubmit(value) { state.confirmOnSubmit = value === true; },
    get virtualDaaScore() { return state.virtualDaaScore; }
  };
}

/* ======================================================================
 * RC44 WRITER (child process): executes ONLY the pinned df5b8de modules.
 * ==================================================================== */
async function rc44Writer(input) {
  verifyRc44Tree(input.tree);
  const m = modulesOf(path.join(input.tree, "sdk", "src"));
  const config = m.config.loadConfig({ dataRoot: input.dataRoot, rpcUrl: LOOPBACK });
  assert.equal(config.networkId, "testnet-10");
  const w = walletsFor(config), k = kitFor(m, config, w), hist = {};
  const pick = (r) => ({ requestId: r.requestId, txId: r.txId, state: r.state, action: r.action, predecessorOutpoint: r.predecessorOutpoint });
  const expectState = (r, s) => { assert.equal(r.state, s, `${r.action} ${r.requestId} is ${r.state}, expected ${s}`); return r; };
  const fin = async (r, signer) => expectState(await k.finalize(r, signer), "PREFLIGHT_VERIFIED");
  const reconcile = (v, model, extra = {}) => m.reconcile4.reconcileVaultV4(config, v.vaultId, { rpc: model.rpc, ...extra });
  // RC44 case C: live predecessor + effect absent + claim age >= minimum -> releases the claims and reservation.
  const ageRelease = async (v, model, r) => {
    model.seedInputs(r.finalTransaction, r.covenantId);
    const status = await reconcile(v, model, { stalePendingMinimumMs: 0 });
    assert.equal(status.status, "CLAIM_RELEASED"); assert.equal(status.claimTxId, r.txId);
  };
  // RC44 submit: accepted and observed at zero depth -> CHAIN_VERIFIED (RC44 standard).
  const submitObserved = async (model, r) => {
    model.know(r); model.seedInputs(r.finalTransaction, r.covenantId); model.confirmOnSubmit = true;
    const done = await m.submit4.submitWalletRequestV4({ config, requestId: r.requestId, rpc: model.rpc, pollAttempts: 1, pollDelayMs: 0 });
    model.confirmOnSubmit = false;
    return expectState(done.request, "CHAIN_VERIFIED");
  };
  const status = async (v) => (await m.store.getStore(config).read(m.store.Categories.VAULT, v.vaultId)).status;
  { // anc: A age-released on L0; B advanced L0 -> L1; C BUILT on L1.
    const v = V.anc, model = chainModel(config); await seedVault(m, config, v, w);
    const a = await fin(await k.agentSpend(v, 4), w.agent); await ageRelease(v, model, a);
    const b = await submitObserved(model, await fin(await k.agentSpend(v, 3), w.agent));
    const c = expectState(await k.agentSpend(v, 2), "BUILT");
    assert.equal(c.predecessorOutpoint.transactionId, b.txId, "C spends B's successor L1");
    hist.anc = { a: pick(a), b: pick(b), c: pick(c) };
  }
  { // ancS: as anc, with C finalized (claim on L1).
    const v = V.ancS, model = chainModel(config); await seedVault(m, config, v, w);
    const a = await fin(await k.agentSpend(v, 4), w.agent); await ageRelease(v, model, a);
    const b = await submitObserved(model, await fin(await k.agentSpend(v, 3), w.agent));
    const c = await fin(await k.agentSpend(v, 2), w.agent);
    assert.equal(c.predecessorOutpoint.transactionId, b.txId);
    hist.ancS = { a: pick(a), b: pick(b), c: pick(c) };
  }
  { // onL: A age-released on the live L0; D (3 KAS), T (A's twin) and Q (ownerPause) BUILT on L0.
    const v = V.onL, model = chainModel(config); await seedVault(m, config, v, w);
    const a = await fin(await k.agentSpend(v, 4), w.agent); await ageRelease(v, model, a);
    const d = expectState(await k.agentSpend(v, 3), "BUILT");
    const t = expectState(await k.agentSpend(v, 4), "BUILT");
    assert.equal(t.txId, a.txId, "the same spend on the same live state freezes the same transaction (twin)");
    const q = expectState(await k.ownerOp(v, "ownerPause"), "BUILT");
    hist.onL = { a: pick(a), d: pick(d), t: pick(t), q: pick(q) };
  }
  { // onLs: A age-released on L0; D (3 KAS) finalized, holding the L0 claim.
    const v = V.onLs, model = chainModel(config); await seedVault(m, config, v, w);
    const a = await fin(await k.agentSpend(v, 4), w.agent); await ageRelease(v, model, a);
    const d = await fin(await k.agentSpend(v, 3), w.agent);
    assert.notEqual(d.txId, a.txId);
    hist.onLs = { a: pick(a), d: pick(d) };
  }
  { // twinS: A age-released on L0; its twin T finalized (T holds the shared L0 claim).
    const v = V.twinS, model = chainModel(config); await seedVault(m, config, v, w);
    const a = await fin(await k.agentSpend(v, 4), w.agent); await ageRelease(v, model, a);
    const t = await fin(await k.agentSpend(v, 4), w.agent);
    assert.equal(t.txId, a.txId, "twin");
    hist.twinS = { a: pick(a), t: pick(t) };
  }
  { // recS: A age-released on L0; the owner's recover then completed at zero depth (RC44) -> RECOVERED.
    const v = V.recS, model = chainModel(config); await seedVault(m, config, v, w);
    const a = await fin(await k.agentSpend(v, 4), w.agent); await ageRelease(v, model, a);
    const r = await submitObserved(model, await fin(await k.ownerOp(v, "ownerRecover"), w.owner));
    assert.equal(await status(v), "RECOVERED");
    hist.recS = { a: pick(a), r: pick(r) };
  }
  { // recF: K BUILT on L0; the owner's recover completed at zero depth (RC44) -> RECOVERED.
    const v = V.recF, model = chainModel(config); await seedVault(m, config, v, w);
    const kk = expectState(await k.agentSpend(v, 4), "BUILT");
    const r = await submitObserved(model, await fin(await k.ownerOp(v, "ownerRecover"), w.owner));
    assert.equal(await status(v), "RECOVERED");
    hist.recF = { k: pick(kk), r: pick(r) };
  }
  { // tuS: A finalized (claims held); L0 then vanished with no provable effect -> RC44 case E TERMINATED_UNKNOWN.
    const v = V.tuS, model = chainModel(config); await seedVault(m, config, v, w);
    const a = await fin(await k.agentSpend(v, 4), w.agent);
    assert.equal((await reconcile(v, model)).status, "UNKNOWN");
    assert.equal(await status(v), "TERMINATED_UNKNOWN");
    hist.tuS = { a: pick(a) };
  }
  { // tuF: K BUILT; L0 vanished, no claim -> RC44 case E TERMINATED_UNKNOWN.
    const v = V.tuF, model = chainModel(config); await seedVault(m, config, v, w);
    const kk = expectState(await k.agentSpend(v, 4), "BUILT");
    assert.equal((await reconcile(v, model)).status, "UNKNOWN");
    assert.equal(await status(v), "TERMINATED_UNKNOWN");
    hist.tuF = { k: pick(kk) };
  }
  { // own: A and its twin T built; A finalized and landed out of band; RC44 case A advanced the manifest by A's own txid (A stays PREFLIGHT_VERIFIED).
    const v = V.own, model = chainModel(config); await seedVault(m, config, v, w);
    const a0 = await k.agentSpend(v, 4), t = expectState(await k.agentSpend(v, 4), "BUILT");
    assert.equal(t.txId, a0.txId, "twin");
    const a = await fin(a0, w.agent);
    model.seedInputs(a.finalTransaction, a.covenantId); model.know(a); model.confirm(a.finalTransaction, a.txId);
    const advanced = await reconcile(v, model);
    assert.equal(advanced.status, "ADVANCED"); assert.equal(advanced.txId, a.txId);
    const stored = await m.store.getStore(config).read(m.store.Categories.VAULT, v.vaultId);
    assert.equal(stored.latestTransitionTxId, a.txId);
    hist.own = { a: pick(await m.wr4.loadRequest(config, a.requestId)), t: pick(t) };
  }
  return { hist, vmBinaries: Object.fromEntries(["pv_call_encoder", "pv_vm_preflight"].map((b) => [b, sha256File(path.join(VM_BIN, b))])) };
}

if (process.argv[2] === WRITER_MODE) {
  rc44Writer(JSON.parse(process.argv[3])).then(
    (result) => { process.stdout.write(`${RESULT_TAG}${JSON.stringify(result)}\n`); },
    (error) => { process.stderr.write(`${error && error.stack ? error.stack : error}\n`); process.exitCode = 1; }
  );
} else {
  const { test, before, after } = require("node:test");
  const cp = require("node:child_process");
  const cand = modulesOf(path.join(__dirname, "..", "src"));
  const { handle } = require("../../server/src/api");
  const { Categories } = cand.store;
  const RC44_TREE = process.env.POLICYVAULT_TEST_RC44_TREE || "";
  const TOOLCHAIN = require("../testutil/org-root-durable-fixture").toolchainAvailable();
  const PG = { host: process.env.POLICYVAULT_TEST_PG_HOST || "127.0.0.1", port: Number(process.env.POLICYVAULT_TEST_PG_PORT || 0), user: process.env.POLICYVAULT_TEST_PG_USER, database: process.env.POLICYVAULT_TEST_PG_DATABASE };
  const PG_AVAILABLE = Boolean(PG.port && PG.user && PG.database);
  const CATEGORIES = [Categories.VAULT, Categories.REQUEST, Categories.SUBMISSION_CLAIM, Categories.TRANSITION_CLAIM, Categories.RECEIPT];
  const roots = [], stores = [], databases = [];
  let admin = null, serial = 0, history = null, H = null, B = null, w = null;
  const mk = (prefix) => { const dir = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), prefix)); roots.push(dir); return dir; };

  async function records(config) {
    const s = cand.store.getStore(config), out = {};
    for (const c of CATEGORIES) out[c] = await Promise.all((await s.listKeys(c)).sort().map(async (k) => [k, await s.read(c, k)]));
    return out;
  }
  async function snapshot(config) { return { records: await records(config), audit: await cand.store.getStore(config).readAudit({ limit: 5000 }) }; }
  async function install(config, snap) {
    const s = cand.store.getStore(config);
    for (const [c, entries] of Object.entries(snap.records)) for (const [k, v] of entries) await s.write(c, k, clone(v));
    for (const row of [...snap.audit].reverse()) await s.appendAudit(clone(row));
  }
  async function rejection(promise, message) {
    let caught = null;
    await assert.rejects(promise, (e) => { caught = e; return true; }, message);
    return caught;
  }
  async function resolved(fn, message) {
    let value;
    await assert.doesNotReject(async () => { value = await fn(); }, message);
    return value;
  }
  const settle = (promise) => promise.then((value) => ({ value, error: null }), (error) => ({ value: null, error }));
  const extraOf = (e) => (e && e.extra ? { requestId: e.extra.requestId, action: e.extra.action, state: e.extra.state, signerRole: e.extra.signerRole } : null);

  before(async () => {
    assert.ok(TOOLCHAIN, "real compiler, encoder and VM are required (a missing VM toolchain is a FAIL, never a SKIP)");
    verifyRc44Tree(RC44_TREE);
    // (1) RC44-written histories, by the pinned df5b8de writers only.
    const childRoot = mk("pv-rc45-t2-rc44-"), overlay = rc44Overlay(RC44_TREE, mk("pv-rc45-t2-rc44-overlay-"));
    const env = { ...process.env }; delete env.POLICYVAULT_PV_VM_PREFLIGHT_PATH; delete env.POLICYVAULT_PV_CALL_ENCODER_PATH;
    const child = cp.spawnSync(process.execPath, [__filename, WRITER_MODE, JSON.stringify({ tree: overlay, dataRoot: childRoot })], { encoding: "utf8", timeout: 600000, maxBuffer: 64 * 1024 * 1024, env });
    assert.equal(child.status, 0, `RC44 writer failed: ${(child.stderr || "").slice(-4000)}`);
    const line = (child.stdout || "").split("\n").find((l) => l.startsWith(RESULT_TAG));
    assert.ok(line, "the RC44 writer reported its histories");
    H = JSON.parse(line.slice(RESULT_TAG.length)).hist;
    // (2) One template root: the RC44 records plus the candidate-written bases.
    const template = cand.config.loadConfig({ dataRoot: mk("pv-rc45-t2-template-"), rpcUrl: LOOPBACK });
    await install(template, await snapshot(cand.config.loadConfig({ dataRoot: childRoot, rpcUrl: LOOPBACK })));
    w = walletsFor(template);
    const k = kitFor(cand, template, w);
    B = {};
    { // h35s: G finalized on L0 (claims, CONSUMED reservation). SYNTHETIC manifest: pause L0 -> P2, unpause P2 -> P3 (the stateId recurs, H-35).
      await seedVault(cand, template, V.h35s, w);
      const g = await k.finalize(await k.agentSpend(V.h35s, 4), w.agent); assert.equal(g.state, "PREFLIGHT_VERIFIED");
      B.h35s = { g: { requestId: g.requestId, txId: g.txId } };
    }
    { // h35f: H BUILT on L0 (ACTIVE reservation); the same synthetic pause -> unpause history.
      await seedVault(cand, template, V.h35f, w);
      const h = await k.agentSpend(V.h35f, 3); assert.equal(h.state, "BUILT");
      B.h35f = { h: { requestId: h.requestId, txId: h.txId } };
    }
    for (const v of [V.h35s, V.h35f]) {
      const manifest = await cand.manifest4.loadManifestV4(template, v.vaultId), json = cand.submit4.manifestToJson(manifest);
      const paused = cand.vs4.normalizeStateV4({ ...json.live.state, paused: "1" });
      const pausedId = cand.vs4.computeStateIdV4({ networkId: template.networkId, template: json.template, state: paused, contractVersion: json.contractVersion });
      await cand.manifest4.persistManifestV4(template, { ...json, live: { ...json.live, outpoint: clone(P3) }, latestTransitionTxId: P3.transactionId,
        lastTransition: { action: "ownerUnpause", txId: P3.transactionId, oldStateId: pausedId, newStateId: json.live.stateId, oldOutpoint: clone(P2), newOutpoint: clone(P3) } });
      const reloaded = await cand.manifest4.loadManifestV4(template, v.vaultId);
      assert.equal(reloaded.live.stateId, manifest.live.stateId, "H-35: the stateId recurred"); assert.deepEqual(reloaded.live.outpoint, P3);
    }
    { // abs: R finalized on L0 (claims, CONSUMED reservation); the node will not index L0.
      await seedVault(cand, template, V.abs, w);
      const r = await k.finalize(await k.agentSpend(V.abs, 4), w.agent); assert.equal(r.state, "PREFLIGHT_VERIFIED");
      B.abs = { r: { requestId: r.requestId, txId: r.txId } };
    }
    { // claim: E BUILT on L0 plus E's own transition claim and no bytes — the L-16 shape (an ordinary
      // finalize that took W2 and stopped before W1), written with the finalize's own claim writer (SYNTHETIC stop).
      await seedVault(cand, template, V.claim, w);
      const e = await k.agentSpend(V.claim, 4), b = e.build;
      const index = b.frozen.outputs.findIndex((o) => o.covenant !== null);
      const expected = { kind: "successor", txId: e.txId, index, valueSompi: (BigInt(b.successorState.protectedValue) + BigInt(b.successorState.feeReserve)).toString(), covenantId: e.covenantId,
        scriptSha256: b.successorScriptSha256, stateId: e.successorStateId, state: b.successorState, newRegistry: e.newRegistry, action: e.sdkAction, contractVersion: e.contractVersion };
      await cand.claims.claimTransition(template, { outpoint: e.predecessorOutpoint, action: e.action, txId: e.txId, vaultId: e.vaultId, stateId: e.predecessorStateId, expected });
      B.claim = { e: { requestId: e.requestId, txId: e.txId, predecessorOutpoint: e.predecessorOutpoint } };
    }
    history = await snapshot(template);
    if (PG_AVAILABLE) admin = new (require("pg").Pool)(PG);
  });
  after(async () => {
    for (const s of stores) { try { await s.close(); } catch { /* closed */ } }
    if (admin) { for (const db of databases) await admin.query(`DROP DATABASE IF EXISTS ${db} WITH (FORCE)`); await admin.end(); }
    for (const root of roots) removeOwnedRoot(root);
  });

  async function fresh(backend) {
    const dataRoot = mk("pv-rc45-t2-case-");
    let config;
    if (backend === "PostgreSQL") {
      const db = `pv_rc45_t2_${process.pid}_${++serial}`;
      await admin.query(`CREATE DATABASE ${db}`); databases.push(db);
      config = cand.config.loadConfig({ persistenceBackend: "postgres", pgHost: PG.host, pgPort: PG.port, pgUser: PG.user, pgDatabase: db, pgNoTls: true, hostedDevOpen: true, dataRoot, rpcUrl: LOOPBACK });
      stores.push(await cand.store.openPgStore(config, { migrate: true }));
      assert.equal(cand.store.getStore(config).kind, "postgres");
    } else config = cand.config.loadConfig({ dataRoot, rpcUrl: LOOPBACK });
    await install(config, history);
    const store = cand.store.getStore(config), model = chainModel(config);
    return {
      config, store, model, k: kitFor(cand, config, w),
      req: (requestId) => cand.wr4.loadRequest(config, requestId),
      rawRequest: (requestId) => store.read(Categories.REQUEST, requestId),
      rawManifest: (v) => store.read(Categories.VAULT, v.vaultId),
      claimOn: (outpoint) => store.read(Categories.TRANSITION_CLAIM, cand.claims.transitionClaimKey(outpoint)),
      snap: () => snapshot(config),
      recordsOnly: () => records(config),
      submit: (requestId) => cand.submit4.submitWalletRequestV4({ config, requestId, rpc: model.rpc, pollAttempts: 1, pollDelayMs: 0 })
    };
  }

  const PG_SKIP = PG_AVAILABLE ? undefined : "REQUIREMENT_NOT_AVAILABLE in this process: isolated PostgreSQL (the rc45 runner's pg mode runs these legs; a skipped PostgreSQL leg there is a FAIL)";
  for (const [backend, skip] of [["JSON", undefined], ["PostgreSQL", PG_SKIP]]) {
    const t2 = (name, fn) => test(`RC45 T2 ${backend}: ${name}`, { skip }, async () => fn(await fresh(backend)));

    /* ---------------- scope: ancestors never block (sabotage q) ---------------- */
    t2("ancestor PENDING does not block: ordinary agent and owner builds on the live outpoint succeed [RED on C1]", async (x) => {
      const h = H.anc, heldA = await x.rawRequest(h.a.requestId);
      const spend = await resolved(() => x.k.agentSpend(V.anc, 1), "an RC44 age-released PREFLIGHT_VERIFIED on the ancestor L0 must not block a build on the live L1");
      assert.equal(spend.state, "BUILT");
      assert.deepEqual(spend.predecessorOutpoint, h.c.predecessorOutpoint, "the build spends the live L1");
      const topUp = await resolved(() => x.k.ownerOp(V.anc, "ownerTopUp", { topUpAmountSompi: (10n * KAS).toString() }), "an owner ordinary build is not blocked by an ancestor record either");
      assert.equal(topUp.state, "BUILT");
      assert.deepEqual(await x.rawRequest(h.a.requestId), heldA, "the ancestor record is byte-identical");
    });
    t2("ancestor PENDING does not block: finalize of an ordinary request on the live outpoint [RED on C1]", async (x) => {
      const h = H.anc, heldA = await x.rawRequest(h.a.requestId);
      const done = await resolved(async () => x.k.finalize(await x.req(h.c.requestId), w.agent), "finalize on L1 is not blocked by the ancestor record on L0");
      assert.equal(done.state, "PREFLIGHT_VERIFIED");
      assert.equal((await x.claimOn(h.c.predecessorOutpoint)).txId, h.c.txId, "C holds the claim on L1");
      assert.deepEqual(await x.rawRequest(h.a.requestId), heldA);
    });
    t2("ancestor PENDING does not block: submit of an ordinary request on the live outpoint completes [RED on C1]", async (x) => {
      const h = H.ancS, heldA = await x.rawRequest(h.a.requestId), c = await x.req(h.c.requestId);
      x.model.know(c); x.model.seedInputs(c.finalTransaction, c.covenantId); x.model.confirmOnSubmit = true;
      const done = await resolved(() => x.submit(c.requestId), "submit on L1 is not blocked by the ancestor record on L0");
      assert.equal(done.request.state, "CHAIN_VERIFIED");
      assert.deepEqual(x.model.broadcasts, [c.txId]);
      assert.equal((await x.rawManifest(V.ancS)).latestTransitionTxId, c.txId);
      assert.deepEqual(await x.rawRequest(h.a.requestId), heldA);
    });

    /* ---------------- PENDING on the live outpoint still blocks (HOLD) ---------------- */
    t2("PENDING on the live outpoint blocks ordinary builds and finalize before any write [HOLDS on C1]", async (x) => {
      const h = H.onL, before = await x.snap();
      await assert.rejects(x.k.agentSpend(V.onL, 1), { code: "REQUEST_RECOVERY_REQUIRED" });
      await assert.rejects(x.k.ownerOp(V.onL, "ownerTopUp", { topUpAmountSompi: (10n * KAS).toString() }), { code: "REQUEST_RECOVERY_REQUIRED" });
      await assert.rejects(x.k.finalize(await x.req(h.d.requestId), w.agent), { code: "REQUEST_RECOVERY_REQUIRED" });
      assert.deepEqual(await x.snap(), before, "no request, reservation, claim or audit row was written");
    });
    t2("PENDING on the live outpoint blocks another already-signed ordinary submission before any write [HOLDS on C1]", async (x) => {
      const h = H.onLs, d = await x.req(h.d.requestId);
      x.model.know(d); x.model.seedInputs(d.finalTransaction, d.covenantId);
      const before = await x.snap();
      await assert.rejects(x.submit(d.requestId), { code: "REQUEST_RECOVERY_REQUIRED" });
      assert.deepEqual(await x.snap(), before); assert.deepEqual(x.model.broadcasts, []);
    });
    t2("the blocking refusal names the PENDING record on the live outpoint (error.extra) [RED on C1]", async (x) => {
      const h = H.onL, want = { requestId: h.a.requestId, action: "agentSpend", state: "PREFLIGHT_VERIFIED", signerRole: "agent" };
      const atBuild = await rejection(x.k.agentSpend(V.onL, 1));
      assert.equal(atBuild.code, "REQUEST_RECOVERY_REQUIRED");
      assert.deepEqual(extraOf(atBuild), want, "build refusal: error.extra = {requestId, action, state, signerRole, claimTxId}");
      const atFinalize = await rejection(x.k.finalize(await x.req(h.d.requestId), w.agent));
      assert.equal(atFinalize.code, "REQUEST_RECOVERY_REQUIRED");
      assert.deepEqual(extraOf(atFinalize), want, "finalize refusal names the same record");
    });

    /* ---------------- break-glass is never refused on a live vault ---------------- */
    t2("owner break-glass on a live vault is never refused by PENDING delegate work on the live outpoint: Pause/Recover build, Pause finalize and submit [RED on C1]", async (x) => {
      const h = H.onL, heldA = await x.rawRequest(h.a.requestId), manifestBefore = await x.rawManifest(V.onL);
      const pause = await resolved(() => x.k.ownerOp(V.onL, "ownerPause"), "ownerPause build is never refused on a live vault");
      assert.equal(pause.state, "BUILT");
      const recover = await resolved(() => x.k.ownerOp(V.onL, "ownerRecover"), "ownerRecover build is never refused on a live vault");
      assert.equal(recover.state, "BUILT");
      const q = await resolved(async () => x.k.finalize(await x.req(h.q.requestId), w.owner), "the RC44-built ownerPause finalizes");
      assert.equal(q.state, "PREFLIGHT_VERIFIED");
      x.model.know(q); x.model.seedInputs(q.finalTransaction, q.covenantId); // L0 and the fuel are live; the mempool admits, nothing confirms yet
      const outcome = await settle(x.submit(q.requestId));
      assert.notEqual(outcome.error?.code, "REQUEST_RECOVERY_REQUIRED", "the submit is never refused by pending delegate work");
      assert.deepEqual(x.model.broadcasts, [q.txId], "the signed owner Pause reached the node exactly once");
      assert.deepEqual(await x.rawRequest(h.a.requestId), heldA, "the delegate's record is untouched");
      assert.deepEqual(await x.rawManifest(V.onL), manifestBefore, "nothing settled at zero depth here");
    });

    /* ---------------- pre-sign claim check for ordinary builds ---------------- */
    t2("a claim on the live outpoint refuses ordinary builds pre-sign (409 CLAIM_CONFLICT, extra.claimTxId, no write); break-glass builds are not refused [RED on C1]", async (x) => {
      const e = B.claim.e, claimBefore = await x.claimOn(e.predecessorOutpoint), before = await x.snap();
      assert.equal(claimBefore.txId, e.txId);
      const agent = await rejection(x.k.agentSpend(V.claim, 1), "an ordinary agent build must be refused while a claim sits on the live outpoint");
      assert.equal(agent.code, "CLAIM_CONFLICT");
      assert.equal(agent.extra?.claimTxId, e.txId, "the refusal names the claim's txid");
      const owner = await rejection(x.k.ownerOp(V.claim, "ownerTopUp", { topUpAmountSompi: (10n * KAS).toString() }), "an ordinary owner build is refused the same way");
      assert.equal(owner.code, "CLAIM_CONFLICT");
      assert.deepEqual(await x.snap(), before, "no request, reservation or claim was written");
      assert.equal((await resolved(() => x.k.ownerOp(V.claim, "ownerPause"))).state, "BUILT");
      assert.equal((await resolved(() => x.k.ownerOp(V.claim, "ownerRecover"))).state, "BUILT");
      assert.deepEqual(await x.claimOn(e.predecessorOutpoint), claimBefore, "the claim is byte-identical");
    });

    /* ---------------- H-35: staleness compares the outpoint (sabotage h) ---------------- */
    t2("stateId recurrence is refused by the outpoint at submit (H-35): STALE, nothing broadcast [RED on C1]", async (x) => {
      const g = await x.req(B.h35s.g.requestId), manifestBefore = await x.rawManifest(V.h35s);
      x.model.know(g);
      x.model.add(P3, g.finalTransaction.inputs[0].utxo.amount, g.finalTransaction.inputs[0].utxo.scriptPublicKey, g.covenantId, x.model.virtualDaaScore - 2000n);
      const refusal = await rejection(x.submit(g.requestId));
      assert.equal(refusal.code, "STALE", "the live outpoint differs although the stateId recurred");
      assert.deepEqual(x.model.broadcasts, [], "nothing was broadcast");
      assert.equal((await x.rawRequest(g.requestId)).state, "STALE");
      assert.equal(await x.store.read(Categories.TRANSITION_CLAIM, cand.budget.reservationKey(g)), null, "its reservation is released");
      assert.deepEqual(await x.rawManifest(V.h35s), manifestBefore);
    });
    t2("stateId recurrence is refused by the outpoint at finalize (H-35): STALE, no claim taken [RED on C1]", async (x) => {
      const h = await x.req(B.h35f.h.requestId), manifestBefore = await x.rawManifest(V.h35f);
      const refusal = await rejection(x.k.finalize(h, w.agent), "finalize must refuse a request built on the superseded outpoint");
      assert.equal(refusal.code, "STALE");
      const after = await x.rawRequest(h.requestId);
      assert.equal(after.state, "STALE"); assert.equal(after.finalTransaction, undefined);
      assert.equal(await x.claimOn(h.predecessorOutpoint), null, "no claim on the superseded outpoint");
      assert.equal(await x.store.read(Categories.TRANSITION_CLAIM, cand.budget.reservationKey(h)), null, "its reservation is released");
      assert.deepEqual(await x.rawManifest(V.h35f), manifestBefore);
    });

    /* ---------------- closed manifest at submit/finalize: 422, no write (sabotage t) ---------------- */
    t2("closed manifest (RECOVERED) at submit -> 422 VAULT_TERMINAL, no write [RED on C1]", async (x) => {
      const before = await x.snap();
      const refusal = await rejection(x.submit(H.recS.a.requestId));
      assert.equal(refusal.code, "VAULT_TERMINAL");
      assert.deepEqual(await x.snap(), before, "no STALE label, reservation, claim or audit change");
      assert.deepEqual(x.model.broadcasts, []);
    });
    t2("closed manifest (RECOVERED) at finalize -> 422 VAULT_TERMINAL, no write [RED on C1]", async (x) => {
      const before = await x.snap();
      const refusal = await rejection(x.k.finalize(await x.req(H.recF.k.requestId), w.agent));
      assert.equal(refusal.code, "VAULT_TERMINAL");
      assert.deepEqual(await x.snap(), before);
    });
    t2("closed manifest (TERMINATED_UNKNOWN) at submit -> 422 RECONCILIATION_REQUIRED, no write [RED on C1]", async (x) => {
      const before = await x.snap();
      const refusal = await rejection(x.submit(H.tuS.a.requestId));
      assert.equal(refusal.code, "RECONCILIATION_REQUIRED");
      assert.deepEqual(await x.snap(), before);
      assert.deepEqual(x.model.broadcasts, []);
    });
    t2("closed manifest (TERMINATED_UNKNOWN) at finalize -> 422 RECONCILIATION_REQUIRED, no write [RED on C1]", async (x) => {
      const before = await x.snap();
      const refusal = await rejection(x.k.finalize(await x.req(H.tuF.k.requestId), w.agent));
      assert.equal(refusal.code, "RECONCILIATION_REQUIRED");
      assert.deepEqual(await x.snap(), before);
    });
    t2("HTTP: a closed (RECOVERED) manifest answers 422 VAULT_TERMINAL at submit and finalize, records unchanged [RED on C1]", async (x) => {
      const before = await x.recordsOnly(), k = await x.req(H.recF.k.requestId);
      const submitted = await rejection(handle(x.config, "POST", ["wallet", "v4", "requests", H.recS.a.requestId, "submit"], {}, {}));
      assert.deepEqual({ status: submitted.status, code: submitted.code }, { status: 422, code: "VAULT_TERMINAL" });
      const finalized = await rejection(handle(x.config, "POST", ["wallet", "v4", "requests", k.requestId, "signature"], {}, { signedSafeJson: x.k.sign(k, w.agent) }));
      assert.deepEqual({ status: finalized.status, code: finalized.code }, { status: 422, code: "VAULT_TERMINAL" });
      assert.deepEqual(await x.recordsOnly(), before);
    });
    t2("closed vault with unresolved history refuses every action, break-glass included (RC40) [HOLDS on C1]", async (x) => {
      const before = await x.snap();
      for (const attempt of [() => x.k.agentSpend(V.recS, 1), () => x.k.ownerOp(V.recS, "ownerPause"), () => x.k.ownerOp(V.recS, "ownerRecover")]) {
        await assert.rejects(attempt(), { code: "REQUEST_RECOVERY_REQUIRED" });
      }
      assert.deepEqual(await x.snap(), before);
    });

    /* ---------------- own txid (CR-L14): 422, never STALE ---------------- */
    t2("own txid at submit: the manifest already advanced by this request's transaction -> 422 RECONCILIATION_REQUIRED, never STALE, no write [RED on C1]", async (x) => {
      const before = await x.snap();
      const refusal = await rejection(x.submit(H.own.a.requestId));
      assert.equal(refusal.code, "RECONCILIATION_REQUIRED");
      assert.equal((await x.rawRequest(H.own.a.requestId)).state, "PREFLIGHT_VERIFIED", "never STALE");
      assert.deepEqual(await x.snap(), before);
      assert.deepEqual(x.model.broadcasts, []);
    });
    t2("own txid at finalize: the BUILT twin of the transaction that advanced the manifest -> 422 RECONCILIATION_REQUIRED, never STALE, no write [RED on C1]", async (x) => {
      const before = await x.snap();
      const refusal = await rejection(x.k.finalize(await x.req(H.own.t.requestId), w.agent));
      assert.equal(refusal.code, "RECONCILIATION_REQUIRED");
      assert.equal((await x.rawRequest(H.own.t.requestId)).state, "BUILT", "never STALE");
      assert.deepEqual(await x.snap(), before);
    });

    /* ---------------- absence never labels (CR-M12, sabotage s) ---------------- */
    t2("absence: the live outpoint is not indexed at submit -> 422 RECONCILIATION_REQUIRED; request, claims and reservation byte-identical [RED on C1]", async (x) => {
      const r = await x.req(B.abs.r.requestId);
      x.model.know(r); // the model indexes nothing: L0 is absent
      const before = await x.snap();
      const refusal = await rejection(x.submit(r.requestId));
      assert.equal(refusal.code, "RECONCILIATION_REQUIRED", "absence is not evidence: no STALE");
      assert.deepEqual(await x.snap(), before, "request, claims and reservation are byte-identical");
      assert.deepEqual(x.model.broadcasts, []);
    });

    /* ---------------- twins never refuse each other ---------------- */
    t2("twins never refuse each other: the BUILT twin of an age-released PREFLIGHT_VERIFIED record finalizes [RED on C1]", async (x) => {
      const h = H.onL, heldA = await x.rawRequest(h.a.requestId);
      const t = await resolved(async () => x.k.finalize(await x.req(h.t.requestId), w.agent), "a same-txid twin is not a competing record");
      assert.equal(t.state, "PREFLIGHT_VERIFIED"); assert.equal(t.txId, h.a.txId);
      assert.equal((await x.claimOn(h.t.predecessorOutpoint)).txId, h.a.txId, "the one claim names the shared transaction");
      assert.deepEqual(await x.rawRequest(h.a.requestId), heldA);
    });
    t2("twins never refuse each other: one twin submits while the other holds the shared claim [RED on C1]", async (x) => {
      const h = H.twinS, a = await x.req(h.a.requestId), heldT = await x.rawRequest(h.t.requestId);
      x.model.know(a); x.model.seedInputs(a.finalTransaction, a.covenantId); x.model.confirmOnSubmit = true;
      const done = await resolved(() => x.submit(a.requestId), "the twin holding the shared claim does not refuse this submit");
      assert.equal(done.request.state, "CHAIN_VERIFIED");
      assert.deepEqual(x.model.broadcasts, [a.txId]);
      assert.deepEqual(await x.rawRequest(h.t.requestId), heldT, "submit never relabels the twin");
    });
  }
}
