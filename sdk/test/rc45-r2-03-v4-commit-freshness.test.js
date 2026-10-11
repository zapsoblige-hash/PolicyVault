"use strict";
/*
 * RC45 R2-03 — v0.4.1 COMMIT-TIME FRESHNESS of delegate period starts.
 * Internal RED-first regression material for the RC45 candidate; not an audit.
 *
 * THE DEFECT (b89f0f7): nothing bounds the time between a build and its
 * broadcast. A genesis, a lifecycle finalize and a lifecycle submit commit a
 * new or changed delegate leaf however old its period start has become —
 * including records RC44 wrote with start 0 — so the delegate confirms with
 * every elapsed period's budget at once. Nothing checks that the registry a
 * record carries folds to the agent root its frozen transaction commits.
 *
 * REQUIRED BEHAVIOUR (freshness before the point of no return; registry-to-
 * root integrity):
 *   - genesis-submit (before the submission claim), lifecycle finalize (before
 *     the signature is parsed or any claim taken) and lifecycle submit (before
 *     the transaction is rebuilt or a claim re-created) refuse
 *     409 PERIOD_START_STALE and WRITE NOTHING (the record stays byte-identical,
 *     no claim, no broadcast) when an ANCHORED leaf (one not byte-identical to
 *     the predecessor leaf; every leaf of a genesis) has
 *     D - periodStartDaa > W(periodLengthDaa), W(L) = max(L - 6,000, 600), D
 *     read at the check (finalize: the node DAA read; genesis-submit and
 *     submit: the open node);
 *   - at each of those points, before the node read, the record's registry
 *     must be an array folding to the committed root (genesis: the broadcast
 *     build's initial agent root, itself equal to the top-level initial
 *     state's; lifecycle: the frozen build's successor agent root), else 422
 *     REGISTRY_ROOT_MISMATCH writing nothing (a deleted registry refuses, it
 *     is never skipped);
 *   - requests carrying no ANCHORED leaf (agent spend, pause, recover, a
 *     removal) read no DAA and are unaffected.
 *
 * Layers: API (the real server/src/api.js handle in hosted mode, TEST-key
 * wallet sessions; JSON store and a fresh PostgreSQL database per leg) plus
 * SDK. Real v0.4.1 compiler, pv_call_encoder, TEST-key signatures and the
 * pinned pv_vm_preflight for every finalize. Node observations come only from
 * explicit models: the finalize-time DAA read is the test seam (useAnchorDaa);
 * lifecycle submits run the REAL submitWalletRequestV4 against the F5 chain
 * model (module export wrapped with the model's rpc, as F3
 * submitThroughModel); genesis submits run the REAL
 * submitCreateWalletRequestV4 against a genesis node model (counted
 * broadcasts, the exact covenant output after a broadcast). The start-0
 * records are written by the pinned RC44 (df5b8de) writers
 * (sdk/testutil/rc45-r2-rc44-writer.js). Realistic DAA values (about 5.45e8).
 * Nothing dials a node; no production data.
 */
const R = require("../testutil/rc45-r2-kit");
const assert = require("node:assert/strict");
const { test, before, after } = require("node:test");
const W44 = require("../testutil/rc45-r2-rc44-writer");
const { cand, Categories, K, KAS, D, DAY, HOUR, windowDaa, said } = R;
const TOOLCHAIN = require("../testutil/org-root-durable-fixture").toolchainAvailable();

const S = R.suite("r2-03");
const V = Object.freeze({ base: K.vault("r2-03-base"), rc44Built: K.vault("r2-03-rc44-built"), rc44Signed: K.vault("r2-03-rc44-signed"), single: K.vault("r2-03-single") });
const RC44_GENESIS_VAULT = K.hex("rc45-r2-03-rc44-genesis");
const FLOOR_L = 1200n; // below 6,600 DAA: W = 600
const FAR = D + 100n * DAY; // far past every start in this file
let w = null, A = null, B = null, RC44 = null;

before(async () => {
  assert.ok(TOOLCHAIN, "real compiler, encoder and VM are required (a missing VM toolchain is a FAIL, never a SKIP)");
  await S.setup(async (template) => {
    w = R.wallets(template);
    A = R.delegate(w.agent.xonly, [w.recipient.xonly], { maxPerSpend: (20n * KAS).toString(), periodBudget: (50n * KAS).toString(), periodStartDaa: (D - 5n * DAY).toString(), periodSpent: (3n * KAS).toString() });
    B = R.delegate(w.agentB.xonly, [w.recipient.xonly], { maxPerSpend: (20n * KAS).toString(), periodBudget: (50n * KAS).toString(), periodStartDaa: (D - 1000n).toString(), periodSpent: "0" });
    await R.seedVault(template, V.base, w, [A, B]);
    await R.seedVault(template, V.single, w, [B]); // one delegate: removing it commits the EMPTY agent root
    // RC44-written start-0 records (BUILT addAgent, PREFLIGHT_VERIFIED addAgent, BUILT genesis), installed into the template.
    const vaultInput = (v) => ({ vaultId: v.vaultId, out: v.out, cov: v.cov, fuel: v.fuel, owner: w.owner.xonly, registry: [A, B], label: `RC45 R2 TEST ${v.tag}` });
    const rc44 = W44.runRc44R2("records", { built: vaultInput(V.rc44Built), signed: vaultInput(V.rc44Signed), genesis: { vaultId: RC44_GENESIS_VAULT, funding: R.fundingFor(w.owner, "r2-03-rc44-genesis") }, agent: newAgent(w.n1, "0") }, { track: S.track });
    RC44 = rc44.result;
    const rc44Config = cand.config.loadConfig({ dataRoot: rc44.dataRoot, rpcUrl: R.LOOPBACK });
    await K.install(cand, template, await K.snapshot(cand, rc44Config));
    for (const id of [RC44.built.requestId, RC44.signed.requestId]) {
      const q = await cand.wr4.loadRequest(template, id);
      assert.equal(R.entryOf(q.newRegistry, w.n1.xonly).periodStartDaa, "0", "RC44 committed the requested start 0");
      for (const s of [q.build.stateJson, q.build.successorState]) cand.submit4.successorAddressAndScript(template, q.build.template, s, q.contractVersion); // warm the compile cache
    }
    assert.equal((await cand.wr4.loadRequest(template, RC44.signed.requestId)).state, "PREFLIGHT_VERIFIED");
    assert.equal(R.entryOf((await cand.wr4.loadRequest(template, RC44.genesis.requestId)).initialRegistry, w.n1.xonly).periodStartDaa, "0");
  });
});
after(async () => { await S.teardown(); });

function newAgent(wallet, start, over = {}) { return R.delegate(wallet.xonly, [w.recipient.xonly], { periodStartDaa: String(start), ...over }); }
/* An SDK-built addAgent (new delegate start D, length L) on the base vault: its start is D before and after the anchor. */
const buildAdd = (x, L = DAY, wallet = w.n1) => R.withAnchor(D, () => cand.wr4.buildWalletRequestV4({ config: x.config, vaultId: V.base.vaultId, action: "addAgent", params: { fuel: x.kit.fuelOf(V.base), agent: newAgent(wallet, D, { periodLengthDaa: L.toString() }) }, signerAddress: w.owner.address }));
/* ... finalized through the hosted route at node DAA D (fresh). */
async function signedAdd(x, L = DAY) {
  const q = await buildAdd(x, L);
  const f = await R.withAnchor(D, () => x.ownerFinalize(q.requestId));
  assert.equal(f.status, 200, `the fresh addAgent finalizes (${said(f)})`);
  assert.equal(f.body.request.state, "PREFLIGHT_VERIFIED");
  return x.req(q.requestId);
}
/* The F5 chain model at virtual DAA `daa` holding the request's live predecessor and fuel. */
function modelFor(x, request, daa, { confirm = false } = {}) {
  const model = K.chainModel(x.config, { utxos: [], virtualDaaScore: String(daa), sinks: [K.ANCHOR], accepted: [[K.ANCHOR, []]], mempool: [] });
  model.know(request); model.seedInputs(K.frozenOf(request), request.covenantId); model.confirmOnSubmit = confirm;
  return model;
}
/* A canonical-create genesis (one delegate, start D, length L) through the hosted route, and the owner's signature. */
async function builtGenesis(x, tag, L = DAY) {
  const body = { templateInput: { owner: w.owner.xonly, vaultId: K.hex(`rc45-r2-03-genesis-${tag}`) }, initialAgents: [newAgent(w.n2, D, { periodLengthDaa: L.toString() })], initialState: { protectedValue: (1000n * KAS).toString(), feeReserve: (5n * KAS).toString(), approvers: [], approvalM: "0" }, signerAddress: w.owner.address, funding: [R.fundingFor(w.owner, `r2-03-${tag}`)], contractVersion: "policyvault-0.4.1", label: `RC45 R2 TEST ${tag}` };
  const r = await R.withAnchor(D, () => x.create(body));
  assert.equal(r.status, 201, `the genesis builds (${said(r)})`);
  const q = await x.req(r.body.request.requestId);
  assert.equal(R.entryOf(q.initialRegistry, w.n2.xonly).periodStartDaa, D.toString());
  return { q, signed: R.signGenesis(x.config, q, w.owner) };
}
async function expectRefusal(x, run, { status, code, label, node = null }) {
  const before = await x.scope();
  const r = await run();
  assert.equal(r.status, status, `${label} (${said(r)})`);
  assert.equal(r.code, code, `${label}: the refusal code`);
  if (node) assert.deepEqual(node(), [], `${label}: nothing is broadcast`);
  assert.deepEqual(await x.scope(), before, `${label}: nothing is written (request byte-identical, no transition or submission claim, vault unchanged)`);
  return r;
}
/* Edit the STORED record (store damage or sabotage between two stages). */
const editStored = async (x, request, edit) => { const copy = JSON.parse(JSON.stringify(await x.raw(Categories.REQUEST, request.requestId))); edit(copy); await x.store.write(Categories.REQUEST, copy.requestId, copy); return copy; };

/* EMPTY committed agent root: a record whose registry is the empty registry commits the empty tree's root, so a check
 * that folded a missing (non-array) registry as [] would find it EQUAL and let the record through — only refusing the
 * non-array registry itself catches its deletion. */
const EMPTY_ROOT = R.fold([]);
/* The removal of the single-delegate vault's only delegate (an ownerSetAgentRoot committing the empty agent root). */
async function buildRemoveLast(x) {
  const q = await R.withAnchor(D, () => cand.wr4.buildWalletRequestV4({ config: x.config, vaultId: V.single.vaultId, action: "removeAgent", params: { fuel: x.kit.fuelOf(V.single), agentPk: B.agentPk }, signerAddress: w.owner.address }));
  assert.equal(q.sdkAction, "ownerSetAgentRoot");
  assert.deepEqual(q.newRegistry, [], "the removal leaves the empty registry");
  assert.equal(String(q.build.successorState.agentRoot).toLowerCase(), EMPTY_ROOT, "the committed successor agent root is the empty registry's root");
  return q;
}
/* A canonical-create genesis with NO delegate (its committed initial agent root is the empty registry's root), and the owner's signature. */
async function builtEmptyGenesis(x, tag) {
  const body = { templateInput: { owner: w.owner.xonly, vaultId: K.hex(`rc45-r2-03-genesis-${tag}`) }, initialAgents: [], initialState: { protectedValue: (1000n * KAS).toString(), feeReserve: (5n * KAS).toString(), approvers: [], approvalM: "0" }, signerAddress: w.owner.address, funding: [R.fundingFor(w.owner, `r2-03-${tag}`)], contractVersion: "policyvault-0.4.1", label: `RC45 R2 TEST ${tag}` };
  const r = await R.withAnchor(D, () => x.create(body));
  assert.equal(r.status, 201, `the genesis builds (${said(r)})`);
  const q = await x.req(r.body.request.requestId);
  assert.deepEqual(q.initialRegistry, [], "no delegate");
  assert.equal(String(q.build.initialState.agentRoot).toLowerCase(), EMPTY_ROOT, "the genesis build commits the empty registry's root");
  assert.equal(String(q.initialState.agentRoot).toLowerCase(), EMPTY_ROOT, "the top-level initial state carries the same root");
  return { q, signed: R.signGenesis(x.config, q, w.owner) };
}

for (const [backend, skip] of [["JSON", undefined], ["PostgreSQL", S.PG_SKIP]]) {
  const leg = (name, fn) => test(`RC45 R2-03 ${backend}: ${name}`, { skip }, async () => { const x = await S.fresh(backend, w); try { await fn(x); } finally { await S.release(x); } });

  /* ---------------- genesis-submit: the window edges ---------------- */
  for (const [label, L] of [["a daily", DAY], ["a 1-hour", HOUR], ["a 1,200-DAA (below the product range, the 600-DAA floor)", FLOOR_L]]) {
    leg(`genesis-submit of a genesis with ${label} delegate period at exactly D - S = W(L) proceeds: one broadcast, CHAIN_VERIFIED`, async (x) => {
      const { q, signed } = await builtGenesis(x, `edge-${L}`, L);
      const node = R.genesisNode(D + windowDaa(L)); node.expect(x.config, q);
      const r = await x.genesisSubmit(node.rpc, q.requestId, signed);
      assert.equal(r.status, 200, said(r)); assert.equal(r.body.request.state, "CHAIN_VERIFIED");
      assert.equal(node.state.broadcasts.length, 1);
    });
    leg(`genesis-submit of a genesis with ${label} delegate period at D - S = W(L) + 1 refuses 409 PERIOD_START_STALE before the submission claim: the request stays BUILT byte-identical, no submission claim, zero broadcasts [RED on b89f0f7]`, async (x) => {
      const { q, signed } = await builtGenesis(x, `stale-${L}`, L);
      const node = R.genesisNode(D + windowDaa(L) + 1n); node.expect(x.config, q);
      await expectRefusal(x, () => x.genesisSubmit(node.rpc, q.requestId, signed), { status: 409, code: "PERIOD_START_STALE", label: "a stale genesis is never broadcast", node: () => node.state.broadcasts });
      assert.equal((await x.req(q.requestId)).state, "BUILT");
    });
  }

  /* ---------------- finalize: the window edges ---------------- */
  for (const [label, L] of [["a daily", DAY], ["a 1-hour", HOUR], ["a 1,200-DAA (the 600-DAA floor)", FLOOR_L]]) {
    leg(`finalize of an addAgent with ${label} new delegate period at exactly D - S = W(L) succeeds through the VM preflight (PREFLIGHT_VERIFIED)`, async (x) => {
      const q = await buildAdd(x, L);
      const f = await R.withAnchor(D + windowDaa(L), () => x.ownerFinalize(q.requestId));
      assert.equal(f.status, 200, said(f)); assert.equal(f.body.request.state, "PREFLIGHT_VERIFIED");
    });
    leg(`finalize of an addAgent with ${label} new delegate period at D - S = W(L) + 1 refuses 409 PERIOD_START_STALE before any claim: the request stays BUILT byte-identical, no transition or submission claim [RED on b89f0f7]`, async (x) => {
      const q = await buildAdd(x, L);
      await R.withAnchor(D + windowDaa(L) + 1n, () => expectRefusal(x, () => x.ownerFinalize(q.requestId), { status: 409, code: "PERIOD_START_STALE", label: "a stale lifecycle request is never finalized" }));
      assert.equal((await x.req(q.requestId)).state, "BUILT");
    });
  }

  /* ---------------- submit: the window edges ---------------- */
  leg("submit of a PREFLIGHT_VERIFIED addAgent (daily period) at exactly D - S = W(L) broadcasts and completes CHAIN_VERIFIED", async (x) => {
    const q = await signedAdd(x);
    const model = modelFor(x, q, D + windowDaa(DAY), { confirm: true });
    const r = await x.submitThrough(model, q.requestId);
    assert.equal(r.status, 200, said(r)); assert.equal(r.body.request.state, "CHAIN_VERIFIED");
    assert.equal(model.broadcasts.length, 1);
  });
  leg("submit of a PREFLIGHT_VERIFIED addAgent (daily period) at D - S = W(L) + 1 refuses 409 PERIOD_START_STALE: the armed request and both of its claims are unchanged, zero broadcasts [RED on b89f0f7]", async (x) => {
    const q = await signedAdd(x);
    const model = modelFor(x, q, D + windowDaa(DAY) + 1n, { confirm: true });
    await expectRefusal(x, () => x.submitThrough(model, q.requestId), { status: 409, code: "PERIOD_START_STALE", label: "a stale armed request is never broadcast", node: () => model.broadcasts });
    assert.equal((await x.req(q.requestId)).state, "PREFLIGHT_VERIFIED");
  });

  /* ---------------- RC44-written start-0 records ---------------- */
  leg("an RC44-written BUILT addAgent whose new delegate starts at 0 is refused at finalize 409 PERIOD_START_STALE at the node DAA: BUILT byte-identical, no claim [RED on b89f0f7]", async (x) => {
    await R.withAnchor(D, () => expectRefusal(x, () => x.ownerFinalize(RC44.built.requestId), { status: 409, code: "PERIOD_START_STALE", label: "the RC44 start 0 is caught at finalize" }));
  });
  leg("an RC44-written PREFLIGHT_VERIFIED addAgent whose new delegate starts at 0 is refused at submit 409 PERIOD_START_STALE: record and claims unchanged, zero broadcasts [RED on b89f0f7]", async (x) => {
    const q = await x.req(RC44.signed.requestId);
    const model = modelFor(x, q, D, { confirm: true });
    await expectRefusal(x, () => x.submitThrough(model, q.requestId), { status: 409, code: "PERIOD_START_STALE", label: "the RC44 start 0 is caught at submit", node: () => model.broadcasts });
  });
  leg("an RC44-written BUILT v0.4.1 genesis whose delegate starts at 0 is refused at genesis-submit 409 PERIOD_START_STALE: BUILT byte-identical, no submission claim, zero broadcasts [RED on b89f0f7]", async (x) => {
    const q = await x.req(RC44.genesis.requestId);
    const node = R.genesisNode(D); node.expect(x.config, q);
    await expectRefusal(x, () => x.genesisSubmit(node.rpc, q.requestId, R.signGenesis(x.config, q, w.owner)), { status: 409, code: "PERIOD_START_STALE", label: "the RC44 start 0 is caught at genesis-submit", node: () => node.state.broadcasts });
  });

  /* ---------------- no ANCHORED leaf: unaffected, no read ---------------- */
  for (const [label, make, finalize, terminal] of [
    ["an agent spend of the lagging delegate", (x) => x.kit.agentSpendSompi(V.base, KAS), (x, id) => x.agentFinalize(id), false],
    ["an ownerPause", (x) => x.kit.ownerOp(V.base, "ownerPause"), (x, id) => x.ownerFinalize(id), false],
    ["an ownerRecover", (x) => x.kit.ownerOp(V.base, "ownerRecover"), (x, id) => x.ownerFinalize(id), true],
    ["a removeAgent (the remaining lagging delegate CARRIED)", (x) => cand.wr4.buildWalletRequestV4({ config: x.config, vaultId: V.base.vaultId, action: "removeAgent", params: { fuel: x.kit.fuelOf(V.base), agentPk: B.agentPk }, signerAddress: w.owner.address }), (x, id) => x.ownerFinalize(id), false]
  ]) {
    leg(`${label} finalizes with the node DAA read throwing (no read) and submits with the node far past every start (no check): unaffected`, async (x) => {
      const q = await make(x);
      await R.withAnchor(R.nodeDown, async (seam) => {
        const f = await finalize(x, q.requestId);
        assert.equal(f.status, 200, `finalize (${said(f)})`); assert.equal(f.body.request.state, "PREFLIGHT_VERIFIED");
        assert.equal(seam.calls(), 0, "no node DAA read at finalize");
      });
      const signed = await x.req(q.requestId);
      const model = modelFor(x, signed, FAR, { confirm: true });
      const cookie = q.signerRole === "agent" ? x.cookie.agent : x.cookie.owner;
      const r = await x.submitThrough(model, q.requestId, cookie);
      assert.equal(r.status, 200, `submit (${said(r)})`);
      assert.equal(r.body.request.state, terminal ? "SUBMITTED" : "CHAIN_VERIFIED");
      assert.equal(model.broadcasts.length, 1);
    });
  }

  /* ---------------- registry-to-root integrity ---------------- */
  leg("finalize of a BUILT addAgent whose stored registry was edited (a delegate field changed, so it no longer folds to the committed successor root) refuses 422 REGISTRY_ROOT_MISMATCH before any node read: record byte-identical, no claim [RED on b89f0f7]", async (x) => {
    const q = await buildAdd(x);
    await editStored(x, q, (r) => { R.entryOf(r.newRegistry, w.n1.xonly).maxPerSpend = (11n * KAS).toString(); });
    await R.withAnchor(R.nodeDown, () => expectRefusal(x, () => x.ownerFinalize(q.requestId), { status: 422, code: "REGISTRY_ROOT_MISMATCH", label: "an edited registry is never finalized" }));
  });
  leg("finalize of the RC44-written start-0 addAgent whose stored registry was rewritten to show a fresh start (so the freshness check alone would pass while the frozen root still commits start 0) refuses 422 REGISTRY_ROOT_MISMATCH: record byte-identical, no claim [RED on b89f0f7]", async (x) => {
    const q = await x.req(RC44.built.requestId);
    await editStored(x, q, (r) => { R.entryOf(r.newRegistry, w.n1.xonly).periodStartDaa = D.toString(); });
    await R.withAnchor(D, () => expectRefusal(x, () => x.ownerFinalize(q.requestId), { status: 422, code: "REGISTRY_ROOT_MISMATCH", label: "the stored registry must fold to the committed root" }));
  });
  leg("finalize of a BUILT addAgent whose stored registry was deleted refuses 422 REGISTRY_ROOT_MISMATCH (refused, never skipped): record byte-identical, no claim [RED on b89f0f7]", async (x) => {
    const q = await buildAdd(x);
    await editStored(x, q, (r) => { delete r.newRegistry; });
    await R.withAnchor(R.nodeDown, () => expectRefusal(x, () => x.ownerFinalize(q.requestId), { status: 422, code: "REGISTRY_ROOT_MISMATCH", label: "a missing registry is refused" }));
  });
  leg("submit of a PREFLIGHT_VERIFIED addAgent whose stored registry was edited refuses 422 REGISTRY_ROOT_MISMATCH: record and claims unchanged, zero broadcasts [RED on b89f0f7]", async (x) => {
    const q = await signedAdd(x);
    await editStored(x, q, (r) => { R.entryOf(r.newRegistry, w.n1.xonly).maxPerSpend = (11n * KAS).toString(); });
    const model = modelFor(x, q, D, { confirm: true });
    await expectRefusal(x, () => x.submitThrough(model, q.requestId), { status: 422, code: "REGISTRY_ROOT_MISMATCH", label: "an edited registry is never broadcast", node: () => model.broadcasts });
  });
  leg("submit of a PREFLIGHT_VERIFIED addAgent whose stored registry was deleted refuses 422 REGISTRY_ROOT_MISMATCH: record and claims unchanged, zero broadcasts [RED on b89f0f7]", async (x) => {
    const q = await signedAdd(x);
    await editStored(x, q, (r) => { delete r.newRegistry; });
    const model = modelFor(x, q, D, { confirm: true });
    await expectRefusal(x, () => x.submitThrough(model, q.requestId), { status: 422, code: "REGISTRY_ROOT_MISMATCH", label: "a missing registry is refused at submit", node: () => model.broadcasts });
  });
  for (const [label, edit] of [
    ["whose stored initial registry was edited (a delegate field changed)", (r) => { R.entryOf(r.initialRegistry, w.n2.xonly).maxPerSpend = (11n * KAS).toString(); }],
    ["whose stored initial registry was deleted", (r) => { delete r.initialRegistry; }],
    ["whose genesis build's initial agent root was edited", (r) => { r.build.initialState.agentRoot = R.fold([]); }],
    ["whose top-level initial state's agent root was edited (the build's root unchanged)", (r) => { r.initialState.agentRoot = R.fold([]); }]
  ]) {
    leg(`genesis-submit of a genesis ${label} refuses 422 REGISTRY_ROOT_MISMATCH: BUILT byte-identical, no submission claim, zero broadcasts [RED on b89f0f7]`, async (x) => {
      const { q, signed } = await builtGenesis(x, `psi-${label.length}`);
      const node = R.genesisNode(D); node.expect(x.config, q);
      await editStored(x, q, edit);
      await expectRefusal(x, () => x.genesisSubmit(node.rpc, q.requestId, signed), { status: 422, code: "REGISTRY_ROOT_MISMATCH", label: "the genesis registry must fold to the committed roots", node: () => node.state.broadcasts });
    });
  }

  /* ---------------- registry-to-root integrity with an EMPTY committed root: a deleted registry is refused, never folded as [] ---------------- */
  leg("genesis-submit of a genesis with NO delegate (its committed initial agent root is the empty registry's root) whose stored initial registry was deleted refuses 422 REGISTRY_ROOT_MISMATCH (a missing registry is refused, never folded as empty): BUILT byte-identical, no submission claim, zero broadcasts [RED on b89f0f7]", async (x) => {
    const { q, signed } = await builtEmptyGenesis(x, "psi-empty-deleted");
    const node = R.genesisNode(D); node.expect(x.config, q);
    await editStored(x, q, (r) => { delete r.initialRegistry; });
    await expectRefusal(x, () => x.genesisSubmit(node.rpc, q.requestId, signed), { status: 422, code: "REGISTRY_ROOT_MISMATCH", label: "a deleted initial registry is never broadcast, even when the committed root is the empty one", node: () => node.state.broadcasts });
    assert.equal((await x.req(q.requestId)).state, "BUILT");
  });
  leg("finalize of a BUILT removal of the vault's last delegate (an ownerSetAgentRoot whose committed successor agent root is the empty registry's root) whose stored registry was deleted refuses 422 REGISTRY_ROOT_MISMATCH (a missing registry is refused, never folded as empty): record byte-identical, no claim [RED on b89f0f7]", async (x) => {
    const q = await buildRemoveLast(x);
    await editStored(x, q, (r) => { delete r.newRegistry; });
    await R.withAnchor(R.nodeDown, () => expectRefusal(x, () => x.ownerFinalize(q.requestId), { status: 422, code: "REGISTRY_ROOT_MISMATCH", label: "a deleted registry is never finalized, even when the committed root is the empty one" }));
    assert.equal((await x.raw(Categories.REQUEST, q.requestId)).state, "BUILT");
  });
  leg("submit of a PREFLIGHT_VERIFIED removal of the vault's last delegate (committed successor agent root = the empty registry's root) whose stored registry was deleted refuses 422 REGISTRY_ROOT_MISMATCH (never folded as empty): record and claims unchanged, zero broadcasts [RED on b89f0f7]", async (x) => {
    const q = await buildRemoveLast(x);
    const f = await R.withAnchor(D, () => x.ownerFinalize(q.requestId));
    assert.equal(f.status, 200, `the intact removal finalizes through the VM preflight (${said(f)})`);
    assert.equal(f.body.request.state, "PREFLIGHT_VERIFIED");
    const signed = await x.req(q.requestId);
    await editStored(x, signed, (r) => { delete r.newRegistry; });
    const model = modelFor(x, signed, D, { confirm: true });
    await expectRefusal(x, () => x.submitThrough(model, q.requestId), { status: 422, code: "REGISTRY_ROOT_MISMATCH", label: "a deleted registry is never broadcast, even when the committed root is the empty one", node: () => model.broadcasts });
  });
}
