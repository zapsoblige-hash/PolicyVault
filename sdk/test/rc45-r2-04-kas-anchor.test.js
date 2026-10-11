"use strict";
/*
 * RC45 R2-04 — v0.7-kas BUILD ANCHORING of delegate period starts. Internal
 * RED-first regression material for the RC45 candidate; not an audit.
 *
 * THE DEFECT (b89f0f7): every hosted path that commits a new or changed
 * delegate leaf of a rooted KAS treasury commits the caller's periodStartDaa
 * verbatim — the treasury genesis (POST /org-roots/:id/vaults) and the
 * delegate-rule change (a root request carrying ownerSetAgentRoot): a "0", a
 * stale snapshot, a key typed into an installed row (the new key inherits the
 * old start), a shortened period or a raised budget on a lagging row. The
 * covenant then confirms the delegate with every elapsed period's budget at
 * once. Supplied funding / fee UTXOs make those builds node-free, so nothing
 * there ever reads the network position.
 *
 * REQUIRED BEHAVIOUR (the period-start rule; anchor at build):
 *   - a leaf of the new registry that is not byte-identical in its nine
 *     committed fields to the installed leaf with the same key (empty for a
 *     genesis) commits periodStartDaa = max(requested, D_build), D_build being
 *     the configured synced node's canonical virtual DAA score; every other
 *     field (periodSpent included) exactly as requested; byte-identical
 *     (CARRIED) leaves are untouched and a registry without such a leaf reads
 *     no DAA (other owner operations stay node-free);
 *   - the agent root is recomputed from the committed leaves: the stored
 *     registry folds to the committed root (genesis: build.initialState.agentRoot,
 *     carried by the reviewed summary; root request: build.successorState.agentRoot),
 *     and the recorded vault operation and the owners' reviewed policy set
 *     carry the committed starts (one self-consistent record);
 *   - the build reads the DAA even when funding / the fee input is supplied;
 *     an unreadable DAA refuses 422 PERIOD_START_REQUIRED writing no request
 *     (the root keeps no pending request);
 *   - the same holds for API, SDK-client and MCP callers.
 *
 * Layers: API (the real server/src/api.js handle in hosted mode — owner wallet
 * sessions signed in with TEST keys; an owner-minted machine credential over
 * the real HTTP server for the SDK client and the MCP adapter) plus SDK, over
 * the JSON store and a fresh PostgreSQL database per leg. Real v0.7-kas and
 * v0.7 root compiler and encoder, TEST-key signatures; every root request a
 * leg builds and keeps is slot-signed by two owners and finalized through the
 * hosted finalize route, which runs the pinned pv_vm_preflight over the
 * assembled transaction (production-byte rule). The node DAA read at build is
 * the test seam (useAnchorDaa: a value, or a thrower modelling a node that is
 * down); funding / fee UTXOs the node supplies and every broadcast come from an
 * explicit mock chain. Realistic DAA values (about 5.45e8). Nothing dials a
 * node; no production data.
 */
const KK = require("../testutil/rc45-r2-kas-kit");
KK.installNode(); // before anything loads server/src/api.js or the v7 request modules
const assert = require("node:assert/strict");
const { test, before, after } = require("node:test");
const { K, KAS, D, DAY, HOUR, said, nodeDown, withAnchor } = KK;
const TOOLCHAIN = require("../testutil/org-root-durable-fixture").toolchainAvailable();

const S = KK.kasSuite("r2-04");
const STALE_A = D - 5n * DAY; // installed delegate A: five periods behind the node
let w = null, T = null, A = null, B = null, INSTALLED = null;

before(async () => {
  assert.ok(TOOLCHAIN, "real compiler, encoder and VM are required (a missing VM toolchain is a FAIL, never a SKIP)");
  await S.setup(async (template, node) => {
    w = KK.kasWallets(template);
    A = KK.kasDelegate(w.agentA.xonly, [w.recipient.xonly], { periodStartDaa: STALE_A.toString(), periodSpent: (3n * KAS).toString() });
    B = KK.kasDelegate(w.agentB.xonly, [w.recipient.xonly], { periodStartDaa: (D - 1000n).toString() });
    T = await KK.buildRootAndTreasury(template, w, node, { label: "RC45 R2-04 TEST", agents: [A, B], kasVaultId: K.hex("rc45-r2-04-treasury") });
    INSTALLED = canon([A, B]);
  });
});
after(async () => { await S.teardown(); });

const canon = (entries) => KK.lazy.manifestKas.normalizeRegistry(entries).entries.map(KK.kasJson);
const entryOf = (list, pk) => (list ?? []).find((e) => e.agentPk === pk) ?? null;
const row = (wallet, start, over = {}) => KK.kasDelegate(wallet.xonly, [w.recipient.xonly], { periodStartDaa: String(start), ...over });
const genesisBody = (tag, agents, { funding = true } = {}) => ({ label: `RC45 R2-04 TEST ${tag}`, agents, approvers: [], approvalM: 0, recoveryAddress: w.recovery.address, depositKas: "10", feeReserveKas: "1", signerAddress: w.o1.address, ...(funding ? { funding: [KK.p2pkUtxo(w.o1, `r2-04-genesis-${tag}`, 200n)] } : {}), vaultId: K.hex(`rc45-r2-04-genesis-${tag}`) });

function assertStart(list, pk, start, label) {
  const e = entryOf(list, pk);
  assert.ok(e, `${label}: delegate ${pk.slice(0, 8)} is in the committed registry`);
  assert.equal(e.periodStartDaa, String(start), `${label}: the committed period start of ${pk.slice(0, 8)} is max(requested, node DAA at the build)`);
}
/* Every committed field other than the start is exactly as requested. */
function assertAsRequested(list, requested, label) {
  const want = canon([requested])[0], got = entryOf(list, requested.agentPk);
  for (const f of Object.keys(want).filter((k) => k !== "periodStartDaa")) assert.deepEqual(got[f], want[f], `${label}: ${f} of ${requested.agentPk.slice(0, 8)} is committed exactly as requested`);
}
function assertCarried(list, pks, label) {
  for (const pk of pks) assert.deepEqual(entryOf(list, pk), entryOf(INSTALLED, pk), `${label}: the CARRIED delegate ${pk.slice(0, 8)} is byte-identical to its installed leaf (its period start is untouched)`);
}
async function finalizedThroughVm(x, requestId, label, feeWallet = w.fee) {
  await x.quorum(T.rootId, requestId);
  const f = await x.rootFinalize(T.rootId, requestId, feeWallet);
  assert.equal(f.status, 200, `${label}: two owners' slot signatures and the fee signature finalize through the VM preflight (${said(f)})`);
  assert.equal(f.body.request.state, "SIGNED");
}
/* A built delegate-rule change: 201, the stored record, its fold and self-consistency. */
async function builtRootOp(x, r, label) {
  assert.equal(r.status, 201, `${label}: the delegate-rule change is built (${said(r)})`);
  const q = await x.rootReq(r.body.request.id);
  KK.assertRootOpFolds(q, label);
  assert.equal((await x.rootRecord(T.rootId)).pendingRequestId, q.id, `${label}: the root reserves this request`);
  return q;
}
async function builtGenesis(x, r, label) {
  assert.equal(r.status, 201, `${label}: the treasury genesis is built (${said(r)})`);
  const q = await x.kasReq(r.body.request.requestId);
  assert.equal(q.kind, "kasGenesis");
  return q;
}

for (const [backend, skip] of [["JSON", undefined], ["PostgreSQL", S.PG_SKIP]]) {
  const leg = (name, fn) => test(`RC45 R2-04 ${backend}: ${name}`, { skip }, async () => { const x = await S.fresh(backend, w); try { await fn(x); } finally { await S.release(x); } });

  /* ---------------- treasury genesis ---------------- */
  leg("treasury genesis with a delegate requested at start 0 and supplied funding: 201, the committed start is the node DAA at the build, every other field as requested, the stored registry folds to the genesis build's root and the reviewed summary carries it; the funder's signature is accepted and the submitted genesis installs exactly the committed registry [RED on b89f0f7]", async (x) => {
    await withAnchor(D, async () => {
      const N1 = row(w.n1, "0");
      const q = await builtGenesis(x, await x.kasGenesis(T.rootId, genesisBody("zero", [N1])), "start 0");
      assertStart(q.initialRegistry, w.n1.xonly, D, "start 0");
      assertAsRequested(q.initialRegistry, N1, "start 0");
      KK.assertKasGenesisFolds(q, "start 0");
      const signed = await x.kasSign(q.requestId);
      assert.equal(signed.status, 200, `the funder's TEST-key signature is accepted (${said(signed)})`);
      assert.equal(signed.body.request.state, "SIGNED");
      const sub = await x.kasSubmit(q.requestId);
      assert.equal(sub.status, 200, `the signed genesis is broadcast and observed (${said(sub)})`);
      assert.equal(sub.body.request.state, "CHAIN_VERIFIED");
      assert.equal(x.node.broadcasts(), 1);
      const v = await x.vault(q.vaultId);
      assert.deepEqual(v.agentRegistry.map(KK.kasJson), q.initialRegistry, "the treasury installs exactly the committed registry");
      assert.equal(KK.R.fold(v.agentRegistry.map(KK.kasJson)), String(v.live.state.agentRoot).toLowerCase(), "the installed registry folds to the treasury's live agent root");
    });
  });

  leg("treasury genesis with a delegate requested five periods behind the node (D - 3 days) and one requested in the future (D + 5,000): the stale start is committed at the node DAA, the future start is kept, every other field as requested, and the stored registry folds to the committed root [RED on b89f0f7]", async (x) => {
    await withAnchor(D, async () => {
      const N1 = row(w.n1, D - 3n * DAY), N2 = row(w.n2, D + 5000n, { periodLengthDaa: HOUR.toString() });
      const q = await builtGenesis(x, await x.kasGenesis(T.rootId, genesisBody("stale", [N1, N2])), "stale + future");
      assertStart(q.initialRegistry, w.n1.xonly, D, "stale + future");
      assertStart(q.initialRegistry, w.n2.xonly, D + 5000n, "stale + future");
      assertAsRequested(q.initialRegistry, N1, "stale + future");
      assertAsRequested(q.initialRegistry, N2, "stale + future");
      KK.assertKasGenesisFolds(q, "stale + future");
    });
  });

  leg("treasury genesis with a delegate requested in the future (D + 5,000) keeps that start; the stored registry folds to the genesis build's root and the reviewed summary carries it", async (x) => {
    await withAnchor(D, async () => {
      const N1 = row(w.n1, D + 5000n);
      const q = await builtGenesis(x, await x.kasGenesis(T.rootId, genesisBody("future", [N1])), "future");
      assertStart(q.initialRegistry, w.n1.xonly, D + 5000n, "future");
      assertAsRequested(q.initialRegistry, N1, "future");
      KK.assertKasGenesisFolds(q, "future");
    });
  });

  leg("treasury genesis with a delegate requested at start 0 and NO supplied funding (the node supplies the funder's UTXO): the committed start is the node DAA at the build and the stored registry folds to the committed root [RED on b89f0f7]", async (x) => {
    const u = KK.p2pkUtxo(w.o1, "r2-04-node-funding", 5000n); // the largest ordinary UTXO of the funder (the node's choice)
    x.node.seedP2pk(w.o1, u.outpoint, u.amount);
    await withAnchor(D, async () => {
      const N1 = row(w.n1, "0");
      const r = await KK.NODE().with(x.node.rpc, () => x.kasGenesis(T.rootId, genesisBody("nofunding", [N1], { funding: false })));
      const q = await builtGenesis(x, r, "node-supplied funding");
      assert.equal(KK.frozenOf(q).inputs[0].previousOutpoint.transactionId, u.outpoint.transactionId, "the build spends the node-supplied UTXO");
      assertStart(q.initialRegistry, w.n1.xonly, D, "node-supplied funding");
      assertAsRequested(q.initialRegistry, N1, "node-supplied funding");
      KK.assertKasGenesisFolds(q, "node-supplied funding");
    });
  });

  leg("treasury genesis with supplied funding while the node DAA cannot be read: 422 PERIOD_START_REQUIRED, and no request or other record is written [RED on b89f0f7]", async (x) => {
    const before = await x.scope();
    await withAnchor(nodeDown, async () => {
      const r = await x.kasGenesis(T.rootId, genesisBody("down", [row(w.n1, "0")]));
      assert.equal(r.status, 422, `the build refuses rather than commit an unanchored start (${said(r)})`);
      assert.equal(r.code, "PERIOD_START_REQUIRED");
    });
    assert.equal(await x.scope(), before, "nothing is written: no request, no vault, no root change, no claim");
  });

  /* The real node DAA read (no test seam; the node client is a TEST client below connectVerified): the build reads the
   * configured node through its own body — connect, the network / isSynced / hasUtxoIndex gate, the canonical parse,
   * disconnect — even though the supplied funding makes the build otherwise node-free. */
  KK.R.UNREADABLE_NODES.forEach(([label, node], i) => {
    leg(`treasury genesis with a delegate and supplied funding built with NO test seam while the configured node answers ${label}: the real node DAA read refuses 422 PERIOD_START_REQUIRED${node.connectError ? " carrying the connection error as its cause" : ""}, every opened node connection is disconnected, and no request or other record is written [RED on b89f0f7]`, async (x) => {
      assert.notEqual(x.config.networkId, "mainnet", "the configured network differs from the node's in the network case");
      const before = await x.scope();
      const { r, log } = await KK.R.withNodeClient(x.config, node, async (client) => ({ r: await x.kasGenesis(T.rootId, genesisBody(`real-read-${i}`, [row(w.n1, "0")])), log: client.log() }));
      assert.equal(r.status, 422, `an unreadable node never anchors a start (${said(r)})`);
      assert.equal(r.code, "PERIOD_START_REQUIRED");
      if (node.connectError) assert.ok(String(r.message).includes(node.connectError), `the refusal carries the connection error as its cause: ${r.message}`);
      KK.R.assertNodeClientClosed(log, node, label);
      assert.equal(await x.scope(), before, "nothing is written: no request, no vault, no root change, no claim");
    });
  });

  leg("treasury genesis with a delegate requested at start 0 and supplied funding built with NO test seam while the configured, synced, indexed node answers a canonical virtual DAA score (a digit string): the real node DAA read anchors the delegate's start at that score, the node connection is disconnected, the stored registry folds to the genesis build's root, and the funder's signature is accepted [RED on b89f0f7]", async (x) => {
    const DN = D + 4242n, node = { virtualDaaScore: DN.toString() };
    const N1 = row(w.n1, "0");
    const { r, log } = await KK.R.withNodeClient(x.config, node, async (client) => ({ r: await x.kasGenesis(T.rootId, genesisBody("real-read-canonical", [N1])), log: client.log() }));
    const q = await builtGenesis(x, r, "real node read");
    assertStart(q.initialRegistry, w.n1.xonly, DN, "real node read");
    assertAsRequested(q.initialRegistry, N1, "real node read");
    KK.assertKasGenesisFolds(q, "real node read");
    KK.R.assertNodeClientClosed(log, node, "real node read");
    await withAnchor(DN, async () => {
      const signed = await x.kasSign(q.requestId);
      assert.equal(signed.status, 200, `the funder's TEST-key signature is accepted (${said(signed)})`);
      assert.equal(signed.body.request.state, "SIGNED");
    });
  });

  leg("treasury genesis with no delegate makes no node DAA read (the read answers a thrower and is never called): 201", async (x) => {
    await withAnchor(nodeDown, async (restore) => {
      const q = await builtGenesis(x, await x.kasGenesis(T.rootId, genesisBody("nodelegate", [])), "no delegate");
      assert.deepEqual(q.initialRegistry, []);
      assert.equal(restore.calls(), 0, "no DAA read for a registry without a new delegate");
    });
  });

  leg("treasury genesis through the SDK client (createRootedVault, owner-minted write:org-roots credential, the real HTTP server) with a delegate requested at start 0: the committed start is the node DAA at the build and the stored registry folds to the committed root [RED on b89f0f7]", async (x) => {
    const token = await x.credential(["read:org-roots", "write:org-roots"]);
    const http = await x.http();
    try {
      await withAnchor(D, async () => {
        const { PolicyVaultClient } = require("../src/http-client");
        const client = new PolicyVaultClient({ baseUrl: http.baseUrl, token });
        const body = await client.createRootedVault(T.rootId, { profile: "policyvault-0.7-kas", ...genesisBody("sdk", [row(w.n1, "0")]) });
        const q = await x.kasReq(body.request.requestId);
        assertStart(q.initialRegistry, w.n1.xonly, D, "SDK client");
        KK.assertKasGenesisFolds(q, "SDK client");
      });
    } finally { await http.close(); }
  });

  /* ---------------- delegate-rule changes (root request ownerSetAgentRoot) ---------------- */
  leg("delegate-rule change adding a new row requested at start 0 (installed rows unchanged): 201, the new delegate's start is the node DAA at the build, the installed delegates are byte-identical (the lagging one keeps its start), the stored registry, the recorded operation and the reviewed policy set agree and fold to the committed root, and the request finalizes through the VM [RED on b89f0f7]", async (x) => {
    await withAnchor(D, async () => {
      const N1 = row(w.n1, "0");
      const q = await builtRootOp(x, await x.setAgents(T.rootId, T.vaultId, [A, B, N1], { tag: "newrow" }), "new row");
      assertStart(q.newRegistry, w.n1.xonly, D, "new row");
      assertAsRequested(q.newRegistry, N1, "new row");
      assertCarried(q.newRegistry, [A.agentPk, B.agentPk], "new row");
      await finalizedThroughVm(x, q.id, "new row");
    });
  });

  leg("delegate-rule change typing a different key into the installed row of the lagging delegate (old start and spent amount kept by the form): the new key is a new delegate whose start is the node DAA at the build, its spent amount is committed as requested, the other installed delegate is byte-identical, the record folds and finalizes through the VM [RED on b89f0f7]", async (x) => {
    await withAnchor(D, async () => {
      const typed = { ...A, agentPk: w.n2.xonly };
      const q = await builtRootOp(x, await x.setAgents(T.rootId, T.vaultId, [typed, B], { tag: "keyswap" }), "key substitution");
      assertStart(q.newRegistry, w.n2.xonly, D, "key substitution");
      assertAsRequested(q.newRegistry, typed, "key substitution");
      assert.equal(entryOf(q.newRegistry, w.n2.xonly).periodSpent, (3n * KAS).toString(), "key substitution: the inherited spent amount is kept (it only restricts)");
      assert.equal(entryOf(q.newRegistry, A.agentPk), null, "key substitution: the old key is gone");
      assertCarried(q.newRegistry, [B.agentPk], "key substitution");
      await finalizedThroughVm(x, q.id, "key substitution");
    });
  });

  leg("delegate-rule change shortening the lagging delegate's period to one hour (its lagging start unchanged in the row): the changed delegate's start is the node DAA at the build, every other field as requested, the other delegate byte-identical, the record folds and finalizes through the VM [RED on b89f0f7]", async (x) => {
    await withAnchor(D, async () => {
      const shorter = { ...A, periodLengthDaa: HOUR.toString() };
      const q = await builtRootOp(x, await x.setAgents(T.rootId, T.vaultId, [shorter, B], { tag: "shorter" }), "shortened period");
      assertStart(q.newRegistry, A.agentPk, D, "shortened period");
      assertAsRequested(q.newRegistry, shorter, "shortened period");
      assertCarried(q.newRegistry, [B.agentPk], "shortened period");
      await finalizedThroughVm(x, q.id, "shortened period");
    });
  });

  leg("delegate-rule change raising the lagging delegate's period budget (its lagging start unchanged in the row): the changed delegate's start is the node DAA at the build, its spent amount as requested, the other delegate byte-identical, the record folds and finalizes through the VM [RED on b89f0f7]", async (x) => {
    await withAnchor(D, async () => {
      const raised = { ...A, periodBudget: (40n * KAS).toString() };
      const q = await builtRootOp(x, await x.setAgents(T.rootId, T.vaultId, [raised, B], { tag: "raised" }), "raised budget");
      assertStart(q.newRegistry, A.agentPk, D, "raised budget");
      assertAsRequested(q.newRegistry, raised, "raised budget");
      assertCarried(q.newRegistry, [B.agentPk], "raised budget");
      await finalizedThroughVm(x, q.id, "raised budget");
    });
  });

  leg("delegate-rule change that leaves the lagging delegate's row unchanged while lowering the other delegate's per-spend cap: the lagging delegate stays byte-identical (CARRIED; its start is not reset — the covenant's banking of its unused periods is unchanged); the record folds and finalizes through the VM", async (x) => {
    await withAnchor(D, async () => {
      const lowered = { ...B, maxPerSpend: (4n * KAS).toString() };
      const r = await x.setAgents(T.rootId, T.vaultId, [A, lowered], { tag: "carried" });
      assert.equal(r.status, 201, `built (${said(r)})`);
      const q = await x.rootReq(r.body.request.id);
      assertCarried(q.newRegistry, [A.agentPk], "carried lagging row");
      assert.equal(KK.R.fold(q.newRegistry), String(q.build.successorState.agentRoot).toLowerCase(), "the stored registry folds to the committed root");
      await finalizedThroughVm(x, q.id, "carried lagging row");
    });
  });

  leg("delegate-rule change re-submitting the installed rows unchanged makes no node DAA read (the read answers a thrower and is never called): 201, the stored registry is the installed one and folds to the committed root; the request finalizes through the VM", async (x) => {
    let id = null;
    await withAnchor(nodeDown, async (restore) => {
      const r = await x.setAgents(T.rootId, T.vaultId, [A, B], { tag: "unchanged" });
      assert.equal(r.status, 201, `built offline (${said(r)})`);
      const q = await x.rootReq(r.body.request.id);
      assert.deepEqual(q.newRegistry, INSTALLED, "the stored registry is the installed registry");
      assert.equal(KK.R.fold(q.newRegistry), String(q.build.successorState.agentRoot).toLowerCase(), "the stored registry folds to the committed root");
      assert.equal(restore.calls(), 0, "no DAA read when no delegate is new or changed");
      id = q.id;
    });
    await withAnchor(D, () => finalizedThroughVm(x, id, "unchanged rows"));
  });

  leg("delegate-rule change naming a treasury whose record is absent is refused 404 VAULT_NOT_FOUND at build (before any node DAA read; the read answers a thrower), and nothing is written", async (x) => {
    await x.removeVault(T.vaultId);
    const before = await x.scope();
    await withAnchor(nodeDown, async (restore) => {
      const r = await x.setAgents(T.rootId, T.vaultId, [A, B, row(w.n1, "0")], { tag: "novault" });
      assert.equal(r.status, 404, `a missing treasury record is reported, never masked (${said(r)})`);
      assert.equal(r.code, "VAULT_NOT_FOUND");
      assert.equal(restore.calls(), 0, "no DAA read before the treasury record is found");
    });
    assert.equal(await x.scope(), before, "nothing is written");
  });

  leg("delegate-rule change with a new row and a SUPPLIED fee UTXO while the node DAA cannot be read: 422 PERIOD_START_REQUIRED (the supplied fee input does not make the build node-free), no root request is written and the root keeps no pending request [RED on b89f0f7]", async (x) => {
    const before = await x.scope();
    await withAnchor(nodeDown, async () => {
      const r = await x.setAgents(T.rootId, T.vaultId, [A, B, row(w.n1, "0")], { tag: "down" });
      assert.equal(r.status, 422, `the build refuses rather than commit an unanchored start (${said(r)})`);
      assert.equal(r.code, "PERIOD_START_REQUIRED");
    });
    assert.equal((await x.rootRecord(T.rootId)).pendingRequestId, null, "the root keeps no pending request");
    assert.equal(await x.scope(), before, "nothing is written: no root request, no root or vault change, no claim");
  });

  leg("delegate-rule change with a new row requested at start 0 and NO supplied fee UTXO (the node supplies the initiating owner's UTXO): the new delegate's start is the node DAA at the build, the record folds and finalizes through the VM with the owner's fee signature [RED on b89f0f7]", async (x) => {
    const u = KK.p2pkUtxo(w.o1, "r2-04-node-fee", 5000n); // the largest ordinary UTXO of the owner (the node's choice)
    x.node.seedP2pk(w.o1, u.outpoint, u.amount);
    await withAnchor(D, async () => {
      const r = await KK.NODE().with(x.node.rpc, () => x.setAgents(T.rootId, T.vaultId, [A, B, row(w.n1, "0")], { tag: "nodefee", fuel: null }));
      const q = await builtRootOp(x, r, "node-supplied fee");
      assert.equal(KK.frozenOf(q).inputs[KK.frozenOf(q).inputs.length - 1].previousOutpoint.transactionId, u.outpoint.transactionId, "the fee input is the node-supplied UTXO");
      assertStart(q.newRegistry, w.n1.xonly, D, "node-supplied fee");
      assertCarried(q.newRegistry, [A.agentPk, B.agentPk], "node-supplied fee");
      await finalizedThroughVm(x, q.id, "node-supplied fee", w.o1);
    });
  });

  leg("other owner operations on the treasury (reserve top-up, approver set, pause) build with no node DAA read (the read answers a thrower and is never called)", async (x) => {
    await withAnchor(nodeDown, async (restore) => {
      for (const [action, params] of [["ownerTopUpReserve", { topUpReserveAmountSompi: KAS.toString() }], ["ownerSetApprovers", { approvers: [w.n5.xonly], approvalM: "1" }], ["ownerPause", {}]]) {
        const r = await x.vaultOp(T.rootId, T.vaultId, action, params, { tag: `other-${action}` });
        assert.equal(r.status, 201, `${action} builds offline (${said(r)})`);
        const w2 = await x.rootReject(T.rootId, r.body.request.id);
        assert.equal(w2.status, 200, `the unsigned ${action} request is withdrawn (${said(w2)})`);
      }
      assert.equal(restore.calls(), 0, "no DAA read for an owner operation that sets no delegate leaf");
    });
  });

  leg("delegate-rule change through the SDK client (createOrgRootRequest, owner-minted write:org-roots credential, the real HTTP server) with a new row requested at start 0: the new delegate's start is the node DAA at the build, the record folds and finalizes through the VM [RED on b89f0f7]", async (x) => {
    const token = await x.credential(["read:org-roots", "write:org-roots"]);
    const http = await x.http();
    try {
      /* RC45 L2-01 guard inventory (mock seeding): the in-process server's root build reads this case's mock chain */
      await KK.NODE().with(x.node.rpc, () => withAnchor(D, async () => {
        const { PolicyVaultClient } = require("../src/http-client");
        const client = new PolicyVaultClient({ baseUrl: http.baseUrl, token });
        const body = await client.createOrgRootRequest(T.rootId, { action: "authorize", params: { fuel: x.node.seedFuel(KK.p2pkUtxo(w.fee, "r2-04-sdk-fee")) }, vaultOperations: [{ vaultId: T.vaultId, action: "ownerSetAgentRoot", params: { agents: [A, B, row(w.n1, "0")] } }], signerAddress: w.o1.address });
        const q = await x.rootReq(body.request.id);
        KK.assertRootOpFolds(q, "SDK client");
        assertStart(q.newRegistry, w.n1.xonly, D, "SDK client");
        assertCarried(q.newRegistry, [A.agentPk, B.agentPk], "SDK client");
        await finalizedThroughVm(x, q.id, "SDK client");
      }));
    } finally { await http.close(); }
  });

  leg("delegate-rule change through the MCP adapter (policyvault_create_org_root_request, owner-minted write:org-roots credential, the real HTTP server) with a new row requested at start 0: the envelope is OK 201 and the new delegate's start is the node DAA at the build; the record folds and finalizes through the VM [RED on b89f0f7]", async (x) => {
    const token = await x.credential(["read:org-roots", "write:org-roots"]);
    const http = await x.http();
    const mcp = KK.mcpSession({ baseUrl: http.baseUrl, token });
    try {
      await mcp.start();
      /* RC45 L2-01 guard inventory (mock seeding): the in-process server's root build reads this case's mock chain */
      await KK.NODE().with(x.node.rpc, () => withAnchor(D, async () => {
        const res = await mcp.callTool("r2-04-mcp-1", "policyvault_create_org_root_request", { rootId: T.rootId, action: "authorize", params: { fuel: x.node.seedFuel(KK.p2pkUtxo(w.fee, "r2-04-mcp-fee")) }, vaultOperations: [{ vaultId: T.vaultId, action: "ownerSetAgentRoot", params: { agents: [A, B, row(w.n1, "0")] } }], signerAddress: w.o1.address });
        const sc = res.result && res.result.structuredContent;
        assert.ok(sc, `MCP answered a tool result (${JSON.stringify(res.error ?? null)})`);
        assert.equal(sc.status, "OK", `the MCP envelope (${JSON.stringify(sc.data).slice(0, 400)})`);
        assert.equal(sc.httpStatus, 201);
        assertStart(sc.data.request.newRegistry, w.n1.xonly, D, "MCP envelope");
        const q = await x.rootReq(sc.data.request.id);
        KK.assertRootOpFolds(q, "MCP");
        assertStart(q.newRegistry, w.n1.xonly, D, "MCP");
        await finalizedThroughVm(x, q.id, "MCP");
      }));
    } finally { mcp.close(); await http.close(); }
  });
}
