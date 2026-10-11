"use strict";
/*
 * RC45 R2-05 — v0.7-kas COMMIT-TIME FRESHNESS of delegate period starts, and
 * the withdrawal of a delegate-rule change that can no longer be finalized for
 * that reason. Internal RED-first regression material for the RC45 candidate;
 * not an audit.
 *
 * THE DEFECT (b89f0f7): nothing bounds the time between the build that
 * commits a new or changed delegate leaf and the moment the transaction
 * becomes irreversible. A treasury creation can be signed, and an M-of-N
 * delegate-rule change finalized, any time later (the owner quorum has no
 * request expiry), so a delegate confirms with every period that elapsed since
 * its start — at once. And a delegate-rule change carrying any owner slot
 * signature can never be withdrawn while it blocks every root transition.
 *
 * REQUIRED BEHAVIOUR:
 *   - treasury creation: at the funder's signature, before SIGNED, the stored
 *     initial registry must fold to the genesis build's agent root (else 422
 *     REGISTRY_ROOT_MISMATCH, checked before any node read; a non-array registry
 *     refuses, never skips); then, with the node DAA D read now, every new
 *     delegate must satisfy D - periodStartDaa <= W(periodLengthDaa),
 *     W(L) = max(L - 6,000, 600), else 409 PERIOD_START_STALE; an unreadable D
 *     refuses 422 PERIOD_START_REQUIRED. A refusal writes nothing: the request
 *     stays BUILT and can be withdrawn;
 *   - root request carrying a v0.7-kas ownerSetAgentRoot: at finalize, after the
 *     quorum check, the stored registry must be an array folding to the
 *     committed successor root (422 REGISTRY_ROOT_MISMATCH) and the treasury
 *     record must exist (404 VAULT_NOT_FOUND), before the node read; then the
 *     same freshness predicate over the leaves that are not byte-identical to
 *     the treasury's installed leaves (409 PERIOD_START_STALE; 422
 *     PERIOD_START_REQUIRED). A refusal writes nothing: AUTHORIZED, signatures
 *     kept. Operations that set no new or changed delegate stay node-free;
 *   - stale withdrawal: such a request whose ONLY withdrawal blocker is its
 *     owner slot signatures (AUTHORIZED, never finalized, no submission or
 *     completion evidence) is withdrawn (REFUSED, the root's pending slot
 *     cleared) when the same predicate holds at a D read now — evaluated on the
 *     stored registry, independently of the registry-to-root check. Any other
 *     case, or an unreadable D, keeps CANNOT_REJECT;
 *   - strand rule: a SIGNED treasury creation and a finalized (SIGNED) root
 *     request are NOT refused at submit, however old their starts — neither can
 *     be withdrawn — including records signed by RC44 with start 0 (the stated
 *     residual that the pre-activation check counts).
 *
 * Layers: API (the real server/src/api.js handle in hosted mode, owner wallet
 * sessions signed in with TEST keys) plus SDK, over the JSON store and a fresh
 * PostgreSQL database per leg. Real v0.7-kas / v0.7 root compiler and
 * encoder, TEST-key signatures; every finalize runs the pinned pv_vm_preflight
 * over the assembled transaction (production-byte rule). The node DAA read at
 * the signature / finalize / withdrawal is the test seam (useAnchorDaa); every
 * broadcast goes to an explicit mock chain (the node's own DAA is set to the
 * same stale value in the strand-rule legs). The RC44 records are written by
 * the pinned df5b8de writers (sdk/testutil/rc45-r2-kas-rc44-writer.js).
 * Realistic DAA values (about 5.45e8). Nothing dials a node; no production data.
 */
const KK = require("../testutil/rc45-r2-kas-kit");
KK.installNode(); // before anything loads server/src/api.js or the v7 request modules
const assert = require("node:assert/strict");
const { test, before, after } = require("node:test");
const { K, KAS, D, DAY, HOUR, said, nodeDown, withAnchor, windowDaa } = KK;
const W44 = require("../testutil/rc45-r2-kas-rc44-writer");
const TOOLCHAIN = require("../testutil/org-root-durable-fixture").toolchainAvailable();

/* ---------------------------------------------------------------------------------------------------------------
 * SHARED VECTORS — written inline here and, verbatim, in the browser suite of the delegate-rule withdrawal gating:
 * the treasury's installed registry, a delegate-rule change's stored registry, and the network position D at which
 * the server's root finalize and the stale-request withdrawal judge it. stale = some leaf of newRegistry that is not
 * byte-identical in its nine committed fields to the installed leaf with the same key has
 * D - periodStartDaa > W(periodLengthDaa), W(L) = max(L - 6000, 600).
 * ------------------------------------------------------------------------------------------------------------- */
const PK_A = "cb144659ef300200912762786a173663150592d78f4408390c47e9956d9a6c31"; // installed, lagging (TEST key 0x62)
const PK_B = "5ab4689e400a4a160cf01cd44730845a54768df8547dcdf073d964f109f18c30"; // installed (TEST key 0x66)
const PK_N1 = "eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619"; // new (TEST key 0x41)
const PK_N2 = "24653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1c"; // new (TEST key 0x42)
const RECIPIENT = "1195a8046dcbb8e17034bca630065e7a0982e4e36f6f7e5a8d4554e4846fcd99"; // TEST key 0x63
const RECIPIENT_ROOT = "125252f3e043c314d06f8989ed81d9d716552e2d1ebf73b35c826c5ee3cc89d4";
const leaf = (agentPk, periodStartDaa, over = {}) => ({ agentPk, maxPerSpend: "500000000", periodBudget: "2000000000", periodLengthDaa: "864000", periodStartDaa: String(periodStartDaa), periodSpent: "0", approvalThreshold: "200000000", agentMaxFeePerTx: "10000000", agentRecipientRoot: RECIPIENT_ROOT, recipients: [RECIPIENT], ...over });
const V_A = leaf(PK_A, 540680000, { periodSpent: "300000000" });
const V_B = leaf(PK_B, 544999000);
const INSTALLED_V = [V_A, V_B];
const VECTORS = [
  { name: "new daily delegate at exactly W", newRegistry: [V_A, V_B, leaf(PK_N1, 545000000)], D: 545858000, stale: false },
  { name: "new daily delegate at W + 1", newRegistry: [V_A, V_B, leaf(PK_N1, 545000000)], D: 545858001, stale: true },
  { name: "the CARRIED lagging delegate is not judged; the new delegate is fresh", newRegistry: [V_A, V_B, leaf(PK_N1, 545000000)], D: 545001000, stale: false },
  { name: "installed delegate's period shortened to one hour, at W + 1", newRegistry: [leaf(PK_A, 545000000, { periodSpent: "300000000", periodLengthDaa: "36000" }), V_B], D: 545030001, stale: true },
  { name: "two new delegates, daily fresh and hourly at W + 1", newRegistry: [V_A, V_B, leaf(PK_N1, 545000000), leaf(PK_N2, 545000000, { periodLengthDaa: "36000" })], D: 545030001, stale: true },
  { name: "1,200-DAA period at exactly the 600-DAA floor", newRegistry: [V_A, V_B, leaf(PK_N1, 545000000, { periodLengthDaa: "1200" })], D: 545000600, stale: false },
  { name: "1,200-DAA period at 601", newRegistry: [V_A, V_B, leaf(PK_N1, 545000000, { periodLengthDaa: "1200" })], D: 545000601, stale: true },
  { name: "a later requested start keeps the window open", newRegistry: [V_A, V_B, leaf(PK_N1, 545100000)], D: 545958000, stale: false }
];

const S = KK.kasSuite("r2-05");
const W_DAY = windowDaa(DAY), W_HOUR = windowDaa(HOUR);
const EMPTY_ROOT = KK.R.fold([]); // the committed agent root of an empty registry: a check folding a deleted registry as [] would match it
const FAR = D + 100n * DAY; // far past every delegate start in this file
let w = null, T = null, A = null, B = null, R44 = null;

before(async () => {
  assert.ok(TOOLCHAIN, "real compiler, encoder and VM are required (a missing VM toolchain is a FAIL, never a SKIP)");
  await S.setup(async (template, node) => {
    w = KK.kasWallets(template);
    A = KK.kasDelegate(w.agentA.xonly, [w.recipient.xonly], { periodStartDaa: (D - 5n * DAY).toString(), periodSpent: (3n * KAS).toString() });
    B = KK.kasDelegate(w.agentB.xonly, [w.recipient.xonly], { periodStartDaa: (D - 1000n).toString() });
    T = await KK.buildRootAndTreasury(template, w, node, { label: "RC45 R2-05 TEST", agents: [A, B], kasVaultId: K.hex("rc45-r2-05-treasury") });
    assert.deepEqual(await KK.installedRegistry(template, T.vaultId), canon(INSTALLED_V), "the shared vectors' installed registry is this treasury's installed registry");
    assert.deepEqual([w.agentA.xonly, w.agentB.xonly, w.n1.xonly, w.n2.xonly, w.recipient.xonly], [PK_A, PK_B, PK_N1, PK_N2, RECIPIENT], "the shared vectors name these TEST keys");
    // The RC44-signed records (start 0) of the strand-rule residual, on their own root.
    const rc44 = W44.runRc44Kas({ daa: D.toString(), installed: [A, B], creationAgents: [row(w.n1, "0")], newAgents: [A, B, row(w.n1, "0")], treasuryVaultId: K.hex("rc45-r2-05-rc44-treasury"), creationVaultId: K.hex("rc45-r2-05-rc44-creation") }, { track: S.track });
    R44 = rc44.result;
    const written = require("../src/config").loadConfig({ dataRoot: rc44.dataRoot, rpcUrl: KK.LOOPBACK });
    await K.install({ store: KK.lazy.store }, template, await KK.kasSnapshot(written));
    KK.warmAllCaches(rc44.dataRoot, template.dataRoot);
    assert.equal((await KK.lazy.wr7kas.loadKasWalletRequest(template, R44.creationRequestId)).state, "SIGNED", "the RC44 creation is SIGNED");
    assert.equal((await KK.lazy.wr7.loadOrgRootRequest(template, R44.rootRequestId)).state, "SIGNED", "the RC44 delegate-rule change is SIGNED");
  });
});
after(async () => { await S.teardown(); });

const canon = (entries) => KK.lazy.manifestKas.normalizeRegistry(entries).entries.map(KK.kasJson);
const entryOf = (list, pk) => (list ?? []).find((e) => e.agentPk === pk) ?? null;
const row = (wallet, start, over = {}) => KK.kasDelegate(wallet.xonly, [w.recipient.xonly], { periodStartDaa: String(start), ...over });
const genesisBody = (tag, agents) => ({ label: `RC45 R2-05 TEST ${tag}`, agents, approvers: [], approvalM: 0, recoveryAddress: w.recovery.address, depositKas: "10", feeReserveKas: "1", signerAddress: w.o1.address, funding: [KK.p2pkUtxo(w.o1, `r2-05-genesis-${tag}`, 200n)], vaultId: K.hex(`rc45-r2-05-genesis-${tag}`) });

/* A treasury creation built at D whose delegates are requested at D or later (so S >= D on every runtime). */
async function builtCreation(x, tag, agents) {
  return withAnchor(D, async () => {
    const r = await x.kasGenesis(T.rootId, genesisBody(tag, agents));
    assert.equal(r.status, 201, `${tag}: the creation is built (${said(r)})`);
    const q = await x.kasReq(r.body.request.requestId);
    for (const a of agents) assert.equal(entryOf(q.initialRegistry, a.agentPk).periodStartDaa, String(a.periodStartDaa), `${tag}: the requested start (>= the build's D) is committed`);
    return q;
  });
}
/* A delegate-rule change built at D (requested starts >= D) carrying the two owner slot signatures (AUTHORIZED). */
async function signedSlots(x, agents, tag, { buildDaa = D } = {}) {
  return withAnchor(buildDaa, async () => {
    const r = await x.setAgents(T.rootId, T.vaultId, agents, { tag });
    assert.equal(r.status, 201, `${tag}: the delegate-rule change is built (${said(r)})`);
    const id = r.body.request.id;
    await x.quorum(T.rootId, id);
    const q = await x.rootReq(id);
    assert.equal(q.state, "AUTHORIZED");
    assert.equal(q.slots.filter((s) => s.status === "SIGNED").length, 2, `${tag}: two owner slot signatures are attached`);
    return q;
  });
}
const stillPending = async (x, q, label) => assert.equal((await x.rootRecord(T.rootId)).pendingRequestId, q.id, `${label}: the root still reserves this request`);
async function refusedWritingNothing(x, call, status, code, label) {
  const before = await x.scope();
  const r = await call();
  assert.equal(r.status, status, `${label} (${said(r)})`);
  assert.equal(r.code, code, `${label}: ${code}`);
  assert.equal(await x.scope(), before, `${label}: nothing is written (every request, root, vault, claim and receipt record is byte-identical)`);
  return r;
}

for (const [backend, skip] of [["JSON", undefined], ["PostgreSQL", S.PG_SKIP]]) {
  const leg = (name, fn) => test(`RC45 R2-05 ${backend}: ${name}`, { skip }, async () => { const x = await S.fresh(backend, w); try { await fn(x); } finally { await S.release(x); } });

  /* ================= treasury creation: the funder's signature ================= */
  leg("treasury creation with a daily delegate starting at D, signed at D + W(L) + 1: 409 PERIOD_START_STALE before SIGNED, the request stays BUILT byte-identical (nothing is written), and the funder can then withdraw it (WALLET_REJECTED) [RED on b89f0f7]", async (x) => {
    const q = await builtCreation(x, "daily-stale", [row(w.n1, D)]);
    await withAnchor(D + W_DAY + 1n, () => refusedWritingNothing(x, () => x.kasSign(q.requestId), 409, "PERIOD_START_STALE", "a creation whose delegate start aged past its window is not signed"));
    assert.equal((await x.kasReq(q.requestId)).state, "BUILT");
    const wd = await x.kasReject(q.requestId);
    assert.equal(wd.status, 200, `the BUILT creation is withdrawn (${said(wd)})`);
    assert.equal(wd.body.request.state, "WALLET_REJECTED");
  });

  leg("treasury creation with a daily delegate starting at D, signed at exactly D + W(L): the signature is accepted (SIGNED)", async (x) => {
    const q = await builtCreation(x, "daily-edge", [row(w.n1, D)]);
    await withAnchor(D + W_DAY, async () => {
      const r = await x.kasSign(q.requestId);
      assert.equal(r.status, 200, `at the window edge the creation is signed (${said(r)})`);
      assert.equal(r.body.request.state, "SIGNED");
    });
  });

  leg("treasury creation with a one-hour delegate starting at D, signed at D + W(1 h) + 1 (30,001): 409 PERIOD_START_STALE, BUILT byte-identical [RED on b89f0f7]", async (x) => {
    const q = await builtCreation(x, "hourly-stale", [row(w.n1, D, { periodLengthDaa: HOUR.toString() })]);
    await withAnchor(D + W_HOUR + 1n, () => refusedWritingNothing(x, () => x.kasSign(q.requestId), 409, "PERIOD_START_STALE", "a one-hour delegate past its 50-minute window"));
  });

  leg("treasury creation with a 1,200-DAA delegate (below the product range; the 600-DAA floor) starting at D, signed at D + 601: 409 PERIOD_START_STALE, BUILT byte-identical [RED on b89f0f7]", async (x) => {
    const q = await builtCreation(x, "floor-stale", [row(w.n1, D, { periodLengthDaa: "1200" })]);
    await withAnchor(D + 601n, () => refusedWritingNothing(x, () => x.kasSign(q.requestId), 409, "PERIOD_START_STALE", "a 1,200-DAA delegate past the 600-DAA floor window"));
  });

  leg("treasury creation with a 1,200-DAA delegate starting at D, signed at exactly D + 600: the signature is accepted (SIGNED)", async (x) => {
    const q = await builtCreation(x, "floor-edge", [row(w.n1, D, { periodLengthDaa: "1200" })]);
    await withAnchor(D + 600n, async () => {
      const r = await x.kasSign(q.requestId);
      assert.equal(r.status, 200, `at the floor window edge the creation is signed (${said(r)})`);
      assert.equal(r.body.request.state, "SIGNED");
    });
  });

  leg("treasury creation signed while the node DAA cannot be read: 422 PERIOD_START_REQUIRED, BUILT byte-identical [RED on b89f0f7]", async (x) => {
    const q = await builtCreation(x, "sig-down", [row(w.n1, D)]);
    await withAnchor(nodeDown, () => refusedWritingNothing(x, () => x.kasSign(q.requestId), 422, "PERIOD_START_REQUIRED", "the signature step refuses rather than guess the network position"));
  });

  leg("treasury creation whose stored initial registry was edited (it no longer folds to the genesis build's agent root): the signature refuses 422 REGISTRY_ROOT_MISMATCH before any node read, BUILT byte-identical [RED on b89f0f7]", async (x) => {
    const q = await builtCreation(x, "psi-edited", [row(w.n1, D)]);
    await x.editKasReq(q.requestId, (rec) => { rec.initialRegistry[0].maxPerSpend = (4n * KAS).toString(); });
    await withAnchor(nodeDown, () => refusedWritingNothing(x, () => x.kasSign(q.requestId), 422, "REGISTRY_ROOT_MISMATCH", "an edited initial registry is never signed"));
  });

  leg("treasury creation whose stored initial registry was deleted: the signature refuses 422 REGISTRY_ROOT_MISMATCH (refused, never skipped), BUILT byte-identical [RED on b89f0f7]", async (x) => {
    const q = await builtCreation(x, "psi-deleted", [row(w.n1, D)]);
    await x.editKasReq(q.requestId, (rec) => { delete rec.initialRegistry; });
    await withAnchor(nodeDown, () => refusedWritingNothing(x, () => x.kasSign(q.requestId), 422, "REGISTRY_ROOT_MISMATCH", "a missing initial registry is never signed"));
  });

  leg("treasury creation with NO delegate (its committed initial agent root is the empty registry's root) whose stored initial registry was deleted: the signature refuses 422 REGISTRY_ROOT_MISMATCH (a missing registry is refused, never folded as empty), BUILT byte-identical, nothing broadcast [RED on b89f0f7]", async (x) => {
    const q = await builtCreation(x, "psi-empty-deleted", []);
    assert.deepEqual(q.initialRegistry, [], "no delegate");
    assert.equal(String(q.build.initialState.agentRoot).toLowerCase(), EMPTY_ROOT, "the genesis build commits the empty registry's root");
    await x.editKasReq(q.requestId, (rec) => { delete rec.initialRegistry; });
    await withAnchor(nodeDown, () => refusedWritingNothing(x, () => x.kasSign(q.requestId), 422, "REGISTRY_ROOT_MISMATCH", "a deleted initial registry is never signed, even when the committed root is the empty one"));
    assert.equal((await x.kasReq(q.requestId)).state, "BUILT");
    assert.equal(x.node.broadcasts(), 0);
  });

  leg("strand rule: a SIGNED treasury creation (signed fresh at D) submitted after its delegate's start aged past W(L) (node and DAA read both at D + W + 1) is NOT refused: one broadcast, CHAIN_VERIFIED, the treasury installs the committed registry", async (x) => {
    const q = await builtCreation(x, "strand", [row(w.n1, D)]);
    await withAnchor(D, async () => { const r = await x.kasSign(q.requestId); assert.equal(r.status, 200, `signed fresh (${said(r)})`); });
    x.node.state.daa = D + W_DAY + 1n;
    await withAnchor(D + W_DAY + 1n, async () => {
      const sub = await x.kasSubmit(q.requestId);
      assert.equal(sub.status, 200, `a SIGNED creation cannot be withdrawn, so its submit is never refused for its start (${said(sub)})`);
      assert.equal(sub.body.request.state, "CHAIN_VERIFIED");
    });
    assert.equal(x.node.broadcasts(), 1);
    assert.deepEqual((await x.vault(q.vaultId)).agentRegistry.map(KK.kasJson), q.initialRegistry);
  });

  leg("strand rule, RC44 residual: an RC44-signed treasury creation whose delegate starts at 0 is NOT refused at submit: one broadcast, CHAIN_VERIFIED, the delegate is installed with start 0 (the residual the pre-activation check counts)", async (x) => {
    await withAnchor(D, async () => {
      const sub = await x.kasSubmit(R44.creationRequestId);
      assert.equal(sub.status, 200, `the RC44-signed creation is submitted unrefused (${said(sub)})`);
      assert.equal(sub.body.request.state, "CHAIN_VERIFIED");
    });
    assert.equal(x.node.broadcasts(), 1);
    assert.equal(entryOf((await x.vault(R44.creationVaultId)).agentRegistry.map(KK.kasJson), w.n1.xonly).periodStartDaa, "0");
  });

  /* ================= root request (v0.7-kas ownerSetAgentRoot): finalize ================= */
  leg("delegate-rule change with two owner slot signatures finalized while the node DAA cannot be read: 422 PERIOD_START_REQUIRED, AUTHORIZED byte-identical with its signatures, the root still reserves it [RED on b89f0f7]", async (x) => {
    const q = await signedSlots(x, [A, B, row(w.n1, D)], "fin-down");
    await withAnchor(nodeDown, () => refusedWritingNothing(x, () => x.rootFinalize(T.rootId, q.id), 422, "PERIOD_START_REQUIRED", "finalize refuses rather than guess the network position"));
    await stillPending(x, q, "node down");
  });

  leg("delegate-rule change whose stored registry was edited (it no longer folds to the committed successor root): finalize refuses 422 REGISTRY_ROOT_MISMATCH before any node read, AUTHORIZED byte-identical [RED on b89f0f7]", async (x) => {
    const q = await signedSlots(x, [A, B, row(w.n1, D)], "fin-psi-edited");
    await x.editRootReq(q.id, (rec) => { rec.newRegistry.find((e) => e.agentPk === w.n1.xonly).maxPerSpend = (4n * KAS).toString(); });
    await withAnchor(nodeDown, () => refusedWritingNothing(x, () => x.rootFinalize(T.rootId, q.id), 422, "REGISTRY_ROOT_MISMATCH", "an edited registry is never finalized"));
  });

  leg("delegate-rule change whose stored registry was deleted: finalize refuses 422 REGISTRY_ROOT_MISMATCH (refused, never skipped), AUTHORIZED byte-identical [RED on b89f0f7]", async (x) => {
    const q = await signedSlots(x, [A, B, row(w.n1, D)], "fin-psi-deleted");
    await x.editRootReq(q.id, (rec) => { delete rec.newRegistry; });
    await withAnchor(nodeDown, () => refusedWritingNothing(x, () => x.rootFinalize(T.rootId, q.id), 422, "REGISTRY_ROOT_MISMATCH", "a missing registry is never finalized"));
  });

  leg("delegate-rule change removing every delegate (its committed successor agent root is the empty registry's root) whose stored registry was deleted: finalize refuses 422 REGISTRY_ROOT_MISMATCH (a missing registry is refused, never folded as empty), AUTHORIZED byte-identical with its signatures, the root still reserves it [RED on b89f0f7]", async (x) => {
    const q = await signedSlots(x, [], "fin-psi-empty-deleted");
    assert.deepEqual(q.newRegistry, [], "every delegate removed");
    assert.equal(String(q.build.successorState.agentRoot).toLowerCase(), EMPTY_ROOT, "the committed successor agent root is the empty registry's root");
    await x.editRootReq(q.id, (rec) => { delete rec.newRegistry; });
    await withAnchor(nodeDown, () => refusedWritingNothing(x, () => x.rootFinalize(T.rootId, q.id), 422, "REGISTRY_ROOT_MISMATCH", "a deleted registry is never finalized, even when the committed root is the empty one"));
    await stillPending(x, q, "empty-root deleted registry");
  });

  leg("delegate-rule change whose treasury record is absent: finalize refuses 404 VAULT_NOT_FOUND (never finalized), AUTHORIZED byte-identical [RED on b89f0f7]", async (x) => {
    const q = await signedSlots(x, [A, B, row(w.n1, D)], "fin-novault");
    await x.removeVault(T.vaultId);
    await withAnchor(D, () => refusedWritingNothing(x, () => x.rootFinalize(T.rootId, q.id), 404, "VAULT_NOT_FOUND", "a change to a missing treasury record is never finalized"));
  });

  leg("delegate-rule change re-submitting the installed rows unchanged is finalized with the node DAA read throwing (no new or changed delegate: no node read): SIGNED through the VM", async (x) => {
    await withAnchor(nodeDown, async (restore) => {
      const q = await signedSlots(x, [A, B], "fin-carried", { buildDaa: nodeDown });
      const f = await x.rootFinalize(T.rootId, q.id);
      assert.equal(f.status, 200, `finalized offline (${said(f)})`);
      assert.equal(f.body.request.state, "SIGNED");
      assert.equal(restore.calls(), 0, "no DAA read for a change without a new or changed delegate");
    });
  });

  leg("a reserve top-up on the treasury is built and finalized with the node DAA read throwing (no delegate leaf: no node read): SIGNED through the VM", async (x) => {
    await withAnchor(nodeDown, async (restore) => {
      const r = await x.vaultOp(T.rootId, T.vaultId, "ownerTopUpReserve", { topUpReserveAmountSompi: KAS.toString() }, { tag: "fin-topup" });
      assert.equal(r.status, 201, `built (${said(r)})`);
      await x.quorum(T.rootId, r.body.request.id);
      const f = await x.rootFinalize(T.rootId, r.body.request.id);
      assert.equal(f.status, 200, `finalized offline (${said(f)})`);
      assert.equal(restore.calls(), 0, "no DAA read");
    });
  });

  leg("strand rule: a finalized (SIGNED) delegate-rule change whose new delegate's start then aged past W(L) (node and DAA read both at D + W + 1) cannot be withdrawn (409 CANNOT_REJECT) and its submit is NOT refused: one broadcast, CHAIN_VERIFIED, the committed registry is installed", async (x) => {
    const q = await signedSlots(x, [A, B, row(w.n1, D)], "strand-root");
    await withAnchor(D, async () => { const f = await x.rootFinalize(T.rootId, q.id); assert.equal(f.status, 200, `finalized fresh (${said(f)})`); });
    x.node.state.daa = D + W_DAY + 1n;
    await withAnchor(D + W_DAY + 1n, async () => {
      await refusedWritingNothing(x, () => x.rootReject(T.rootId, q.id), 409, "CANNOT_REJECT", "a finalized request is never withdrawn");
      const sub = await x.rootSubmit(T.rootId, q.id);
      assert.equal(sub.status, 200, `a finalized request is submitted unrefused (${said(sub)})`);
      assert.equal(sub.body.request.state, "CHAIN_VERIFIED");
    });
    assert.equal(x.node.broadcasts(), 1);
    assert.deepEqual(await x.installed(T.vaultId), (await x.rootReq(q.id)).newRegistry);
  });

  leg("strand rule, RC44 residual: an RC44-finalized, never-attempted delegate-rule change adding a delegate at start 0 is NOT refused at submit: one broadcast, CHAIN_VERIFIED, the delegate is installed with start 0 (the residual the pre-activation check counts)", async (x) => {
    /* R3N-B1a inventory (TEST BUG): the RC44 records were written against the RC44 writer's own mock chain; this case's
     * node also carries the never-attempted request's frozen inputs (the RC44 root's live output, the RC44 treasury's
     * output and its fee UTXO), as the real chain does for a request that was never broadcast — the B1 submit read
     * observes every frozen input (C3 never read them) */
    const rq = await x.rootReq(R44.rootRequestId), kaspa = KK.lazy.chain.loadKaspa(x.config);
    for (const i of KK.frozenOf(rq).inputs) {
      const spk = i.utxo.scriptPublicKey;
      if (!KK.inTable(x, i.previousOutpoint)) x.node.putEntry(kaspa.addressFromScriptPublicKey({ version: spk.version, script: spk.scriptHex }, x.config.networkId).toString(), { outpoint: i.previousOutpoint, amount: i.utxo.amount, covenantId: i.utxo.covenantId ?? null, scriptPublicKey: { version: spk.version, script: spk.scriptHex } });
    }
    await withAnchor(D, async () => {
      const sub = await x.rootSubmit(R44.rootId, R44.rootRequestId);
      assert.equal(sub.status, 200, `the RC44-finalized request is submitted unrefused (${said(sub)})`);
      assert.equal(sub.body.request.state, "CHAIN_VERIFIED");
    });
    assert.equal(x.node.broadcasts(), 1);
    assert.equal(entryOf(await x.installed(R44.treasuryVaultId), w.n1.xonly).periodStartDaa, "0");
  });

  /* ================= shared vectors: root finalize and the stale withdrawal ================= */
  for (const v of VECTORS) {
    leg(v.stale
      ? `shared vector "${v.name}" (D = ${v.D}): finalize refuses 409 PERIOD_START_STALE writing nothing (AUTHORIZED, signatures kept), then the stale withdrawal succeeds (REFUSED; the root's pending slot is cleared) [RED on b89f0f7]`
      : `shared vector "${v.name}" (D = ${v.D}): the withdrawal of a request with owner slot signatures stays 409 CANNOT_REJECT and finalize succeeds (SIGNED through the VM)`, async (x) => {
      const q = await signedSlots(x, v.newRegistry, `vector-${VECTORS.indexOf(v)}`);
      assert.deepEqual(q.newRegistry, canon(v.newRegistry), "the stored registry is the vector's registry");
      await withAnchor(BigInt(v.D), async () => {
        if (v.stale) {
          await refusedWritingNothing(x, () => x.rootFinalize(T.rootId, q.id), 409, "PERIOD_START_STALE", "a stale delegate-rule change is never finalized");
          const wd = await x.rootReject(T.rootId, q.id);
          assert.equal(wd.status, 200, `the stale request is withdrawn (${said(wd)})`);
          assert.equal(wd.body.request.state, "REFUSED");
          assert.equal((await x.rootRecord(T.rootId)).pendingRequestId, null, "the root's pending slot is cleared");
        } else {
          await refusedWritingNothing(x, () => x.rootReject(T.rootId, q.id), 409, "CANNOT_REJECT", "a fresh request with owner signatures is not withdrawable");
          const f = await x.rootFinalize(T.rootId, q.id);
          assert.equal(f.status, 200, `a fresh request is finalized (${said(f)})`);
          assert.equal(f.body.request.state, "SIGNED");
        }
      });
    });
  }

  /* ================= the stale withdrawal ================= */
  leg("stale withdrawal: a never-attempted delegate-rule change with two owner slot signatures whose new delegate's start aged past W(L) is withdrawn (REFUSED), the root's pending slot is cleared, and a new root request then builds [RED on b89f0f7]", async (x) => {
    const q = await signedSlots(x, [A, B, row(w.n1, D)], "wstale");
    await withAnchor(D + W_DAY + 1n, async () => {
      const wd = await x.rootReject(T.rootId, q.id);
      assert.equal(wd.status, 200, `withdrawn (${said(wd)})`);
      assert.equal(wd.body.request.state, "REFUSED");
      assert.equal((await x.rootRecord(T.rootId)).pendingRequestId, null, "the root's pending slot is cleared");
      const next = await x.vaultOp(T.rootId, T.vaultId, "ownerTopUpReserve", { topUpReserveAmountSompi: KAS.toString() }, { tag: "wstale-next" });
      assert.equal(next.status, 201, `a new root request builds (${said(next)})`);
    });
  });

  leg("stale withdrawal while the node DAA cannot be read: 409 CANNOT_REJECT, nothing written", async (x) => {
    const q = await signedSlots(x, [A, B, row(w.n1, D)], "wstale-down");
    await withAnchor(nodeDown, () => refusedWritingNothing(x, () => x.rootReject(T.rootId, q.id), 409, "CANNOT_REJECT", "no withdrawal without a readable network position"));
    await stillPending(x, q, "node down");
  });

  leg("stale withdrawal of a request with durable submission evidence (a submission claim on its transaction): 409 CANNOT_REJECT, nothing written", async (x) => {
    const q = await signedSlots(x, [A, B, row(w.n1, D)], "wstale-attempt");
    await require("../src/submission-claim").claimSubmission(x.config, { txId: q.txId, vaultId: T.rootId, action: q.action });
    await withAnchor(D + W_DAY + 1n, () => refusedWritingNothing(x, () => x.rootReject(T.rootId, q.id), 409, "CANNOT_REJECT", "a request with attempt evidence is never withdrawn"));
  });

  leg("stale withdrawal is judged independently of the registry-to-root check: a stale request whose stored registry was edited (fold differs from the committed root) is refused 422 REGISTRY_ROOT_MISMATCH by finalize, and the withdrawal then succeeds (REFUSED) [RED on b89f0f7]", async (x) => {
    const q = await signedSlots(x, [A, B, row(w.n1, D)], "wstale-psi");
    await x.editRootReq(q.id, (rec) => { rec.newRegistry.find((e) => e.agentPk === w.n1.xonly).maxPerSpend = (4n * KAS).toString(); });
    await withAnchor(D + W_DAY + 1n, async () => {
      await refusedWritingNothing(x, () => x.rootFinalize(T.rootId, q.id), 422, "REGISTRY_ROOT_MISMATCH", "an edited registry is never finalized");
      const wd = await x.rootReject(T.rootId, q.id);
      assert.equal(wd.status, 200, `the stale request is withdrawn (${said(wd)})`);
      assert.equal(wd.body.request.state, "REFUSED");
    });
  });

  leg("store-damage residual: a stale request whose treasury record is absent keeps 409 CANNOT_REJECT (the predicate cannot be evaluated), nothing written", async (x) => {
    const q = await signedSlots(x, [A, B, row(w.n1, D)], "wstale-novault");
    await x.removeVault(T.vaultId);
    await withAnchor(D + W_DAY + 1n, () => refusedWritingNothing(x, () => x.rootReject(T.rootId, q.id), 409, "CANNOT_REJECT", "no withdrawal judged against a missing treasury record"));
  });

  leg("store-damage residual: a stale request whose stored registry is not an array keeps 409 CANNOT_REJECT, nothing written", async (x) => {
    const q = await signedSlots(x, [A, B, row(w.n1, D)], "wstale-nonarray");
    await x.editRootReq(q.id, (rec) => { rec.newRegistry = { damaged: true }; });
    await withAnchor(D + W_DAY + 1n, () => refusedWritingNothing(x, () => x.rootReject(T.rootId, q.id), 409, "CANNOT_REJECT", "no withdrawal judged on a non-array registry"));
  });

  leg("stale-withdrawal scope: a never-attempted reserve top-up on the treasury carrying two owner slot signatures (another operation; it sets no delegate rule) is NOT withdrawn at a network position far past every delegate start — 409 CANNOT_REJECT, nothing written — nor once its stored record also carries a stale-looking delegate registry (only a v0.7-kas delegate-rule change is ever judged stale): 409 CANNOT_REJECT, nothing written, the root still reserves it", async (x) => {
    const r = await withAnchor(D, () => x.vaultOp(T.rootId, T.vaultId, "ownerTopUpReserve", { topUpReserveAmountSompi: KAS.toString() }, { tag: "wstale-scope-topup" }));
    assert.equal(r.status, 201, `built (${said(r)})`);
    await x.quorum(T.rootId, r.body.request.id);
    const q = await x.rootReq(r.body.request.id);
    assert.equal(q.state, "AUTHORIZED");
    assert.equal(q.slots.filter((s) => s.status === "SIGNED").length, 2, "two owner slot signatures are attached");
    await withAnchor(FAR, () => refusedWritingNothing(x, () => x.rootReject(T.rootId, q.id), 409, "CANNOT_REJECT", "a slot-signed top-up is never withdrawn as stale"));
    await x.editRootReq(q.id, (rec) => { rec.newRegistry = canon([A, B, row(w.n1, D)]); }); // a delegate at D, judged at D + 100 days, would be stale
    await withAnchor(FAR, () => refusedWritingNothing(x, () => x.rootReject(T.rootId, q.id), 409, "CANNOT_REJECT", "a registry stored on another operation is never judged"));
    await stillPending(x, q, "another operation");
  });

  leg("a delegate-rule change without any owner slot signature is withdrawn as before (REFUSED) with no node DAA read", async (x) => {
    const r = await withAnchor(D, () => x.setAgents(T.rootId, T.vaultId, [A, B, row(w.n1, D)], { tag: "unsigned" }));
    assert.equal(r.status, 201, `built (${said(r)})`);
    await withAnchor(nodeDown, async (restore) => {
      const wd = await x.rootReject(T.rootId, r.body.request.id);
      assert.equal(wd.status, 200, `withdrawn (${said(wd)})`);
      assert.equal(wd.body.request.state, "REFUSED");
      assert.equal(restore.calls(), 0, "no DAA read for an unsigned withdrawal");
    });
  });

  leg("concurrent finalize and withdrawal of a stale request (both under the root request lock): finalize answers 409 (PERIOD_START_STALE, or REFUSED when the withdrawal ran first), the withdrawal succeeds, and the request ends REFUSED with no final transaction [RED on b89f0f7]", async (x) => {
    const q = await signedSlots(x, [A, B, row(w.n1, D)], "race-stale");
    await withAnchor(D + W_DAY + 1n, async () => {
      const [f, wd] = await Promise.all([x.rootFinalize(T.rootId, q.id), x.rootReject(T.rootId, q.id)]);
      assert.equal(f.status, 409, `finalize never signs a stale request (${said(f)})`);
      assert.ok(["PERIOD_START_STALE", "REFUSED"].includes(f.code), `finalize: ${f.code}`);
      assert.equal(wd.status, 200, `the withdrawal succeeds (${said(wd)})`);
    });
    const end = await x.rootReq(q.id);
    assert.equal(end.state, "REFUSED");
    assert.ok(!end.finalTransaction, "no final transaction was assembled");
    assert.equal((await x.rootRecord(T.rootId)).pendingRequestId, null);
  });

  leg("concurrent finalize and withdrawal of a fresh request with owner slot signatures: finalize SIGNED, the withdrawal 409 CANNOT_REJECT, the request ends SIGNED", async (x) => {
    const q = await signedSlots(x, [A, B, row(w.n1, D)], "race-fresh");
    await withAnchor(D + 1000n, async () => {
      const [f, wd] = await Promise.all([x.rootFinalize(T.rootId, q.id), x.rootReject(T.rootId, q.id)]);
      assert.equal(f.status, 200, `finalize (${said(f)})`);
      assert.equal(wd.status, 409, `withdrawal (${said(wd)})`);
      assert.equal(wd.code, "CANNOT_REJECT");
    });
    assert.equal((await x.rootReq(q.id)).state, "SIGNED");
  });
}
