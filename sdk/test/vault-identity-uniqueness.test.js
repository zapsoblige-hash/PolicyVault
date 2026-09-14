"use strict";
/*
 * SDK / CRASH-RECOVERY / CONCURRENCY — RC33-ID-01 GLOBAL VAULT-RECORD UNIQUENESS (owner repair directive 2026-09-11;
 * sdk/src/vault-identity.js).
 *
 * The finding (independent RC33 affected review, checkpoint 02, HIGH / high confidence): a caller-selected `vaultId`
 * could collide with an existing record of ANOTHER covenant generation during genesis completion — the generation-
 * filtered loader returned null for the other schema and the completion writer overwrote that slot (reproduced on the
 * exact fullscale-rc33 image with a synthetic sentinel, test signatures and a mock node; no production loss, no real
 * broadcast). A same-generation collision was refused only late, after funding could have been broadcast.
 *
 * ATTRIBUTION: tests 1–6 are the reviewer's own regression cases
 * (docs/postlaunch/v07-enablement-evidence/codex-rc33-review/checkpoint-02/probes/identity-regression.test.js), which
 * ran RED 0/6 on the original build source efe9372 (identity-regression-RED.tap in that checkpoint). Their assertions are
 * kept unchanged here (formatting only). Tests 7 onward are the implementation's own controls: fresh identities keep
 * working, same-request retries stay idempotent, "same identity" alone is never accepted, EVERY generation with a
 * caller-selectable identity refuses an occupied one before anything is built / signed / claimed / sent, EVERY
 * generation's completion is an atomic create-only write (a competing writer between the check and the create never
 * gets replaced), and restart recovery keeps the durable identities truthful.
 *
 * Everything runs on isolated JSON data roots with TEST keys and in-process mock nodes (nothing leaves the process).
 * REQUIREMENT_NOT_AVAILABLE (skipped, never silently passed) without silverc / the encoder / pv_tx_probe.
 */
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");

const { loadConfig } = require("../src/config");
const { ENCODER_PATH } = require("../src/vault-builders-v4");
const { getStore, Categories } = require("../src/store");
const { covenantAddress } = require("../src/chain");
const K = require("../src/wallet-requests-v7-kas");
const wr7 = require("../src/wallet-requests-v7");
const wr7hd = require("../src/wallet-requests-v7-hd");
const wr5 = require("../src/wallet-requests-v5");
const wr6 = require("../src/wallet-requests-v6");
const wr4 = require("../src/wallet-requests-v4");
const submit4 = require("../src/wallet-submit-v4");
const assets = require("../../core/assets");
const { compileKcc20Program } = require("../src/token-program-kcc20");
const { buildRecipientTree } = require("../src/recipient-merkle-v3");
const { createHarness } = require("./helpers/v7-kas-mock-harness");

const probe = loadConfig({ dataRoot: fs.mkdtempSync(path.join(os.tmpdir(), "pv-vid-probe-")) });
const available = fs.existsSync(probe.silvercPath) && fs.existsSync(ENCODER_PATH) && fs.existsSync(path.join(probe.repoRoot, "tests/vm/target/debug/pv_tx_probe"));
const SKIP = !available && "REQUIREMENT_NOT_AVAILABLE: silverc / pv_call_encoder / pv_tx_probe";
const KAS = 100000000n;
const H = (b) => b.toString(16).padStart(2, "0").repeat(32);
const hex32 = () => crypto.randomBytes(32).toString("hex");

/* the reviewer's synthetic other-generation sentinel (checkpoint 02): a record this build cannot adapt and must never replace */
const marker = (id) => ({ schema: "test-other-generation", vaultId: id, retained: "existing-record" });

async function setup(t, over = {}) {
  const cfg = loadConfig({ dataRoot: fs.mkdtempSync(path.join(os.tmpdir(), "pv-kas-id-")), ...over });
  const Hh = createHarness(cfg);
  const c = Hh.ctx();
  const rpc = Hh.mockRpc();
  const root = await Hh.rootGenesis(cfg, c, rpc);
  t.after(() => fs.rmSync(cfg.dataRoot, { recursive: true, force: true }));
  const store = getStore(cfg);
  return {
    cfg, H: Hh, c, rpc, store, root,
    build: (over2) => K.buildKasVaultGenesisRequest({ config: cfg, rootCovenantId: root, agents: [c.policy], approvers: [], approvalM: 0, recoveryAddress: Hh.ADDR(c.recoveryKey), depositKas: "3", feeReserveKas: "0.5", signerAddress: Hh.ADDR(c.funder), funding: [Hh.fuelUtxoFor(c.funder, 20n * Hh.KAS)], ...over2 }),
    sign: (r) => K.finalizeKasWalletRequest({ config: cfg, requestId: r.requestId, signedSafeJson: Hh.signAll(r.transaction.unsignedSafeJson, r.transaction.signInputs.map((x) => [x.index, c.funder])) }),
    seed: (r) => { const address = covenantAddress(cfg, Buffer.from(r.build.vaultScriptHex, "hex")); rpc.seed(address, Hh.utxo(address, r.txId, 0, r.build.frozen.outputs[0].value, r.build.covenantId)); },
    spy: () => { const s = { calls: 0, rpc: { ...rpc, async submitTransaction(a) { s.calls += 1; return rpc.submitTransaction(a); } } }; return s; }
  };
}

/* a competing writer that lands EXACTLY between the completion's pre-checks and its create-only write: the store's own
 * create-only primitive (link()/EEXIST on the JSON driver) is what must refuse the second writer — never a re-read */
function competeAtCreate(store, vaultId, competitor) {
  const original = store.createExclusive.bind(store);
  const seen = { challenged: false };
  store.createExclusive = async (category, key, value) => {
    if (category === Categories.VAULT && key === vaultId && !seen.challenged) { seen.challenged = true; await store.write(category, key, competitor); }
    return original(category, key, value);
  };
  return { seen, restore: () => { store.createExclusive = original; } };
}

/* ------------------------------------------------------------------ */
/* 1–6: the reviewer's regression cases (RED 0/6 on efe9372)            */
/* ------------------------------------------------------------------ */

test("1 (reviewer): KAS genesis refuses an occupied global vault ID before a request is written", { skip: SKIP }, async (t) => {
  const x = await setup(t), id = "a1".repeat(32), before = marker(id);
  await x.store.write(Categories.VAULT, id, before);
  const rows = await x.store.listValues(Categories.REQUEST);
  await assert.rejects(() => x.build({ vaultId: id }), (e) => e.code === "VAULT_ID_IN_USE");
  assert.deepEqual(await x.store.read(Categories.VAULT, id), before);
  assert.deepEqual(await x.store.listValues(Categories.REQUEST), rows);
});

test("2 (reviewer): KAS genesis reserves the identity of an existing draft while fresh independent IDs remain usable", { skip: SKIP }, async (t) => {
  const x = await setup(t), a = await x.build({ vaultId: "a2".repeat(32) });
  await assert.rejects(() => x.build({ vaultId: a.vaultId }), (e) => e.code === "VAULT_ID_IN_USE");
  const [b, c] = await Promise.all([x.build({}), x.build({})]);
  assert.notEqual(b.vaultId, c.vaultId);
  assert.equal(b.state, "BUILT");
  assert.equal(c.state, "BUILT");
  assert.equal((await K.loadKasWalletRequest(x.cfg, a.requestId)).state, "BUILT");
});

test("3 (reviewer): a prebuilt genesis cannot accept signatures after its vault ID becomes occupied", { skip: SKIP }, async (t) => {
  const x = await setup(t), r = await x.build({}), before = marker(r.vaultId);
  await x.store.write(Categories.VAULT, r.vaultId, before);
  const saved = await K.loadKasWalletRequest(x.cfg, r.requestId);
  await assert.rejects(() => x.sign(r), (e) => e.code === "VAULT_ID_IN_USE");
  assert.deepEqual(await K.loadKasWalletRequest(x.cfg, r.requestId), saved);
  assert.deepEqual(await x.store.read(Categories.VAULT, r.vaultId), before);
});

test("4 (reviewer): a pre-signed genesis refuses an occupied ID before claims or broadcast", { skip: SKIP }, async (t) => {
  const x = await setup(t), r = await x.build({});
  await x.sign(r);
  const before = marker(r.vaultId);
  await x.store.write(Categories.VAULT, r.vaultId, before);
  const saved = await K.loadKasWalletRequest(x.cfg, r.requestId);
  let broadcasts = 0;
  await assert.rejects(() => K.submitKasWalletRequest({ config: x.cfg, requestId: r.requestId, rpc: { ...x.rpc, async submitTransaction(a) { broadcasts++; return x.rpc.submitTransaction(a); } }, pollAttempts: 1, pollDelayMs: 0 }), (e) => e.code === "VAULT_ID_IN_USE");
  assert.equal(broadcasts, 0);
  assert.equal(await x.store.read(Categories.SUBMISSION_CLAIM, r.txId), null);
  assert.deepEqual(await K.loadKasWalletRequest(x.cfg, r.requestId), saved);
  assert.deepEqual(await x.store.read(Categories.VAULT, r.vaultId), before);
});

test("5 (reviewer): observation of an uncertain genesis preserves a different generation record and its signed identity", { skip: SKIP }, async (t) => {
  const x = await setup(t), r = await x.build({});
  await x.sign(r);
  let broadcasts = 0;
  const rpc = { ...x.rpc, async submitTransaction(a) { broadcasts++; return x.rpc.submitTransaction(a); } };
  await assert.rejects(() => K.submitKasWalletRequest({ config: x.cfg, requestId: r.requestId, rpc, pollAttempts: 1, pollDelayMs: 0 }), (e) => e.code === "RECONCILIATION_REQUIRED");
  const saved = await K.loadKasWalletRequest(x.cfg, r.requestId), before = marker(r.vaultId);
  await x.store.write(Categories.VAULT, r.vaultId, before);
  x.seed(r);
  await assert.rejects(() => K.submitKasWalletRequest({ config: x.cfg, requestId: r.requestId, rpc, pollAttempts: 1, pollDelayMs: 0 }), (e) => e.code === "RECONCILIATION_REQUIRED");
  assert.equal(broadcasts, 1);
  assert.deepEqual(await x.store.read(Categories.VAULT, r.vaultId), before);
  const after = await K.loadKasWalletRequest(x.cfg, r.requestId);
  assert.equal(after.signedSafeJson, saved.signedSafeJson);
  assert.equal(after.txId, saved.txId);
  assert.equal(after.requestId, saved.requestId);
  assert.ok(await x.store.read(Categories.SUBMISSION_CLAIM, r.txId));
});

test("6 (reviewer): genesis completion creates the vault atomically and never replaces a competing writer", { skip: SKIP }, async (t) => {
  const x = await setup(t), r = await x.build({});
  await x.sign(r);
  x.seed(r);
  const original = x.store.createExclusive.bind(x.store), before = marker(r.vaultId);
  let challenged = false;
  x.store.createExclusive = async (category, key, value) => { if (category === Categories.VAULT && key === r.vaultId) { challenged = true; await x.store.write(category, key, before); } return original(category, key, value); };
  t.after(() => { x.store.createExclusive = original; });
  await assert.rejects(() => K.submitKasWalletRequest({ config: x.cfg, requestId: r.requestId, rpc: x.rpc, pollAttempts: 1, pollDelayMs: 0 }), (e) => e.code === "RECONCILIATION_REQUIRED");
  assert.equal(challenged, true);
  assert.deepEqual(await x.store.read(Categories.VAULT, r.vaultId), before);
});

/* ------------------------------------------------------------------ */
/* controls: fresh identities, idempotence, "same ID alone" refused     */
/* ------------------------------------------------------------------ */

test("7 (control): fresh identities keep working — two concurrent unsigned preparations stay distinct and discoverable, and both complete under the same root; an explicit unused identity works end to end", { skip: SKIP }, async (t) => {
  const x = await setup(t);
  const [a, b] = await Promise.all([x.build({}), x.build({})]);
  assert.notEqual(a.vaultId, b.vaultId);
  const listed = (await K.listKasWalletRequests(x.cfg)).filter((q) => q.kind === "kasGenesis").map((q) => q.requestId).sort();
  assert.deepEqual(listed, [a.requestId, b.requestId].sort(), "both drafts are discoverable");
  for (const r of [a, b]) {
    await x.sign(r);
    x.seed(r);
    const done = await K.submitKasWalletRequest({ config: x.cfg, requestId: r.requestId, rpc: x.rpc, pollAttempts: 1, pollDelayMs: 0 });
    assert.equal(done.state, "CHAIN_VERIFIED");
    assert.equal((await x.store.read(Categories.VAULT, r.vaultId)).schema, "policyvault-rooted-kas-vault-manifest-record/1");
  }
  const root = await wr7.loadOrgRoot(x.cfg, x.root);
  assert.ok(root.vaults.includes(a.vaultId) && root.vaults.includes(b.vaultId), "the root lists both treasuries");
  const explicit = "e7".repeat(32);
  const e = await x.build({ vaultId: explicit });
  assert.equal(e.vaultId, explicit);
  await x.sign(e);
  x.seed(e);
  assert.equal((await K.submitKasWalletRequest({ config: x.cfg, requestId: e.requestId, rpc: x.rpc, pollAttempts: 1, pollDelayMs: 0 })).state, "CHAIN_VERIFIED");
});

test("8 (control): same-request retries are idempotent — a repeated submit of a CHAIN_VERIFIED genesis and a replayed completion after a crash between the record write and the request save leave the record byte-identical, broadcast nothing and touch no claim", { skip: SKIP }, async (t) => {
  const x = await setup(t), r = await x.build({});
  await x.sign(r);
  x.seed(r);
  const done = await K.submitKasWalletRequest({ config: x.cfg, requestId: r.requestId, rpc: x.rpc, pollAttempts: 1, pollDelayMs: 0 });
  assert.equal(done.state, "CHAIN_VERIFIED");
  const record = await x.store.read(Categories.VAULT, r.vaultId);
  const rootBefore = await wr7.loadOrgRoot(x.cfg, x.root);
  /* (a) a further submit of the CHAIN_VERIFIED request */
  const s1 = x.spy();
  const again = await K.submitKasWalletRequest({ config: x.cfg, requestId: r.requestId, rpc: s1.rpc, pollAttempts: 1, pollDelayMs: 0 });
  assert.equal(s1.calls, 0);
  assert.equal(again.state, "CHAIN_VERIFIED");
  assert.deepEqual(await x.store.read(Categories.VAULT, r.vaultId), record, "the record is not rewritten");
  /* (b) the crash window: the record exists but the request never reached CHAIN_VERIFIED — the replayed completion finds
   *     the SAME genesis outcome (ALREADY_PRESENT) and completes without touching the record */
  const req = await K.loadKasWalletRequest(x.cfg, r.requestId);
  req.state = "SUBMITTED";
  await K.saveKasWalletRequest(x.cfg, req);
  const s2 = x.spy();
  const replayed = await K.submitKasWalletRequest({ config: x.cfg, requestId: r.requestId, rpc: s2.rpc, pollAttempts: 1, pollDelayMs: 0 });
  assert.equal(s2.calls, 0, "observation only — never rebroadcast");
  assert.equal(replayed.state, "CHAIN_VERIFIED");
  assert.deepEqual(await x.store.read(Categories.VAULT, r.vaultId), record, "ALREADY_PRESENT: byte-identical record, not even updatedAt changes");
  assert.deepEqual((await wr7.loadOrgRoot(x.cfg, x.root)).vaults, rootBefore.vaults);
  assert.equal(await x.store.read(Categories.SUBMISSION_CLAIM, r.txId), null);
  assert.equal((await K.listKasWalletRequests(x.cfg)).filter((q) => q.kind === "kasGenesis" && q.state === "CHAIN_VERIFIED").length, 1, "no replacement was ever created");
});

test("9 (control): matching the identity alone is never sufficient — a DIFFERENT creation of the SAME generation under the same identity is refused at completion; the earlier record and this request's signed identity are preserved", { skip: SKIP }, async (t) => {
  const x = await setup(t), a = await x.build({});
  await x.sign(a);
  x.seed(a);
  assert.equal((await K.submitKasWalletRequest({ config: x.cfg, requestId: a.requestId, rpc: x.rpc, pollAttempts: 1, pollDelayMs: 0 })).state, "CHAIN_VERIFIED");
  const recordA = await x.store.read(Categories.VAULT, a.vaultId);
  /* a second, DIFFERENT creation (other funding, other txid) that is made to target A's identity at the last instant */
  const b = await x.build({});
  await x.sign(b);
  x.seed(b);
  assert.notEqual(b.txId, a.txId);
  const sameSchemaCompetitor = { ...recordA, vaultId: b.vaultId, template: { ...recordA.template, vaultId: b.vaultId } };
  const { seen, restore } = competeAtCreate(x.store, b.vaultId, sameSchemaCompetitor);
  t.after(restore);
  const claimBefore = await x.store.read(Categories.SUBMISSION_CLAIM, b.txId);
  await assert.rejects(() => K.submitKasWalletRequest({ config: x.cfg, requestId: b.requestId, rpc: x.rpc, pollAttempts: 1, pollDelayMs: 0 }), (e) => e.code === "RECONCILIATION_REQUIRED");
  assert.equal(seen.challenged, true);
  assert.deepEqual(await x.store.read(Categories.VAULT, b.vaultId), sameSchemaCompetitor, "the competing same-generation record is preserved");
  const after = await K.loadKasWalletRequest(x.cfg, b.requestId);
  assert.equal(after.state, "RECONCILIATION_REQUIRED");
  assert.match(after.error, /could not be created/);
  assert.equal(after.txId, b.txId);
  assert.equal(typeof after.signedSafeJson, "string");
  assert.ok(await x.store.read(Categories.SUBMISSION_CLAIM, b.txId), "the submission claim is held — the outcome is on chain and unresolved locally");
  assert.equal(claimBefore, null, "(the claim was written by this submission, not before)");
  assert.deepEqual(await x.store.read(Categories.VAULT, a.vaultId), recordA, "the first treasury is untouched");
});

/* ------------------------------------------------------------------ */
/* every generation with a caller-selectable identity                  */
/* ------------------------------------------------------------------ */

function tokenFixture(cfg) {
  const ref = compileKcc20Program({ config: cfg, state: assets.kcc20.ZERO_STATE, familyBound: 2 });
  const descriptor = {
    schema: "policyvault-asset-descriptor/1", assetId: H(0x11), displayName: "Uniqueness Token", tokenStandard: "kcc20/1", tokenCovenantId: H(0x54),
    acceptedTransferTemplates: [{ templateVmHashBlake2b256: ref.templateVmHashBlake2b256, prefixLen: ref.geometry.prefixLen, suffixLen: ref.geometry.suffixLen, stateLayout: "kcc20-state/1" }],
    decimalsDisplay: 2,
    issuerPowers: { mint: false, burn: false, freeze: false, blacklist: false, redemptionControl: false, upgradeMigration: false, controllerRotation: false, emergencyControl: false }
  };
  return { descriptor };
}
function tokenPolicyFor(Hh, agentKey, recipientKey) {
  const rec = Hh.XO(recipientKey);
  return { agentPk: Hh.XO(agentKey), tokenMaxPerSpend: "500", tokenPeriodBudget: "1000", periodLengthDaa: "1000", periodStartDaa: "0", tokenPeriodSpent: "0", agentMaxFeePerTx: KAS.toString(), agentMaxCarryKas: KAS.toString(), agentRecipientRoot: buildRecipientTree([rec]).root, recipients: [rec] };
}
function hdLeafFor(Hh, agentKey, recipientKey) {
  return { pk: Hh.XO(agentKey), maxPerSpend: "500", periodBudget: "2000", periodLengthDaa: "1000", periodStartDaa: "0", periodSpent: "0", maxFeePerTx: KAS.toString(), maxCarryKas: KAS.toString(), expiryDaa: "999999999", recipients: [Hh.XO(recipientKey)] };
}

/* every genesis builder that accepts a caller-selected identity, driven with its real inputs */
function builders(x) {
  const { cfg, H: Hh, c, root } = x;
  const { descriptor } = tokenFixture(cfg);
  const owner = Hh.KEY(0x21);
  return {
    "v0.4.1": (vaultId) => wr4.buildCreateWalletRequestV4({ config: cfg, contractVersion: "policyvault-0.4.1", templateInput: { owner: Hh.XO(owner), vaultId }, initialAgents: [], initialState: { protectedValue: "1000000000", feeReserve: "100000000", approvers: [], approvalM: "0" }, signerAddress: Hh.ADDR(owner), funding: [Hh.fuelUtxoFor(owner, 5000n * KAS)] }),
    "v0.5": (vaultId) => wr5.buildCreateWalletRequestV5({ config: cfg, label: "ctl", descriptor, templateIndex: 0, initialAgents: [tokenPolicyFor(Hh, c.agentKey, c.recipientKey)], feeReserveKas: "5", signerAddress: Hh.ADDR(c.funder), funding: [Hh.fuelUtxoFor(c.funder)], vaultId }),
    "v0.6": (vaultId) => wr6.buildCreateWalletRequestV6({ config: cfg, label: "ctl6", descriptor, templateIndex: 0, initialAgents: [tokenPolicyFor(Hh, c.agentKey, c.recipientKey)], initialSwapPolicies: [], feeReserveKas: "5", swapPrincipalKas: "0", signerAddress: Hh.ADDR(c.funder), funding: [Hh.fuelUtxoFor(c.funder)], vaultId }),
    "v0.7-payment": (vaultId) => wr7.buildRootedVaultGenesisRequest({ config: cfg, rootCovenantId: root, label: "rooted", descriptor, templateIndex: 0, agents: [tokenPolicyFor(Hh, c.agentKey, c.recipientKey)], recoveryAddress: Hh.ADDR(c.recoveryKey), depositKas: "0", feeReserveKas: "5", signerAddress: Hh.ADDR(c.funder), funding: [Hh.fuelUtxoFor(c.funder)], vaultId }),
    "v0.7-payment-hd": (vaultId) => wr7hd.buildHdVaultGenesisRequest({ config: cfg, rootCovenantId: root, label: "hd", descriptor, templateIndex: 0, initialAgents: [hdLeafFor(Hh, c.agentKey, c.recipientKey)], recoveryAddress: Hh.ADDR(c.recoveryKey), feeReserveKas: "5", signerAddress: Hh.ADDR(c.funder), funding: [Hh.fuelUtxoFor(c.funder)], vaultId }),
    "v0.7-kas": (vaultId) => x.build({ vaultId })
  };
}
const idOf = (r) => r.vaultId ?? r.build?.template?.vaultId;
const stateOf = (r) => r.state;

test("10 (matrix): EVERY generation with a caller-selectable identity refuses an identity held by another generation's record BEFORE anything is built or written, still builds a fresh identity, and then reserves that identity against every OTHER generation's build", { skip: SKIP }, async (t) => {
  const x = await setup(t);
  const B = builders(x);
  const occupied = "0c".repeat(32), before = marker(occupied);
  await x.store.write(Categories.VAULT, occupied, before);
  const requestsBefore = (await x.store.listValues(Categories.REQUEST)).length + (await x.store.listValues(Categories.ORG_ROOT_REQUEST)).length;
  for (const [generation, build] of Object.entries(B)) {
    await assert.rejects(() => build(occupied), (e) => e.code === "VAULT_ID_IN_USE", `${generation}: an occupied identity must be refused at build`);
  }
  assert.deepEqual(await x.store.read(Categories.VAULT, occupied), before, "the other generation's record is untouched");
  assert.equal((await x.store.listValues(Categories.REQUEST)).length + (await x.store.listValues(Categories.ORG_ROOT_REQUEST)).length, requestsBefore, "a refused build writes no request");
  /* fresh identities build; each BUILT draft then reserves its identity against every other generation */
  const drafts = {};
  for (const [generation, build] of Object.entries(B)) {
    const fresh = crypto.randomBytes(32).toString("hex");
    const r = await build(fresh);
    assert.equal(idOf(r), fresh, `${generation}: the requested fresh identity is used`);
    assert.ok(["BUILT", "AUTHORIZED"].includes(stateOf(r)), `${generation}: ${stateOf(r)}`);
    drafts[generation] = fresh;
  }
  for (const [owner, fresh] of Object.entries(drafts)) {
    for (const [generation, build] of Object.entries(B)) {
      if (generation === owner) continue;
      await assert.rejects(() => build(fresh), (e) => e.code === "VAULT_ID_IN_USE", `${generation} must not reuse the identity of ${owner}'s draft`);
    }
  }
});

/* ------------------------------------------------------------------ */
/* v0.4.1 (the mainnet production generation): sign+submit, atomic     */
/* completion, replay                                                  */
/* ------------------------------------------------------------------ */

async function v4Setup(t) {
  const cfg = loadConfig({ dataRoot: fs.mkdtempSync(path.join(os.tmpdir(), "pv-v4-id-")) });
  t.after(() => fs.rmSync(cfg.dataRoot, { recursive: true, force: true }));
  const Hh = createHarness(cfg), owner = Hh.KEY(0x21), rpc = Hh.mockRpc(), store = getStore(cfg);
  const build = (vaultId = crypto.randomBytes(32).toString("hex")) => wr4.buildCreateWalletRequestV4({ config: cfg, contractVersion: "policyvault-0.4.1", templateInput: { owner: Hh.XO(owner), vaultId }, initialAgents: [], initialState: { protectedValue: "1000000000", feeReserve: "100000000", approvers: [], approvalM: "0" }, signerAddress: Hh.ADDR(owner), funding: [Hh.fuelUtxoFor(owner, 5000n * KAS)] });
  const signed = (r) => Hh.signAll(r.transaction.unsignedSafeJson, r.transaction.signInputs.map((s) => [s.index, owner]));
  const seed = (r) => { const { vaultAddress, vaultValue } = submit4.genesisTargetV4(cfg, r); rpc.seed(vaultAddress, Hh.utxo(vaultAddress, r.build.txId, r.vaultOutputIndex, vaultValue, r.covenantId)); };
  const spy = () => { const s = { calls: 0, rpc: { ...rpc, async submitTransaction(a) { s.calls += 1; return rpc.submitTransaction(a); } } }; return s; };
  return { cfg, Hh, owner, rpc, store, build, signed, seed, spy };
}

test("11 (v0.4.1): a BUILT genesis whose identity became occupied is refused at genesis-submit BEFORE the signature is accepted, the claim and the broadcast (request byte-identical); a competing writer at completion is never replaced (RECONCILIATION_REQUIRED, claim held, signed identity preserved) and reconciliation stays truthful", { skip: SKIP }, async (t) => {
  const v = await v4Setup(t);
  /* (a) occupied before the wallet's signature is presented */
  const r1 = await v.build();
  const before1 = marker(r1.vaultId);
  await v.store.write(Categories.VAULT, r1.vaultId, before1);
  const saved1 = await wr4.loadRequest(v.cfg, r1.requestId);
  const s1 = v.spy();
  await assert.rejects(() => submit4.submitCreateWalletRequestV4({ config: v.cfg, requestId: r1.requestId, signedSafeJson: v.signed(r1), rpc: s1.rpc, pollAttempts: 1, pollDelayMs: 0 }), (e) => e.code === "VAULT_ID_IN_USE");
  assert.equal(s1.calls, 0);
  assert.equal(await v.store.read(Categories.SUBMISSION_CLAIM, r1.build.txId), null);
  assert.deepEqual(await wr4.loadRequest(v.cfg, r1.requestId), saved1, "the unsigned request is untouched (still BUILT)");
  assert.deepEqual(await v.store.read(Categories.VAULT, r1.vaultId), before1);
  /* (b) the competing writer lands between the completion's checks and its create-only write */
  const r2 = await v.build();
  v.seed(r2);
  const competitor = marker(r2.vaultId);
  const { seen, restore } = competeAtCreate(v.store, r2.vaultId, competitor);
  t.after(restore);
  const s2 = v.spy();
  await assert.rejects(() => submit4.submitCreateWalletRequestV4({ config: v.cfg, requestId: r2.requestId, signedSafeJson: v.signed(r2), rpc: s2.rpc, pollAttempts: 1, pollDelayMs: 0 }), (e) => e.code === "RECONCILIATION_REQUIRED");
  assert.equal(seen.challenged, true);
  assert.equal(s2.calls, 1, "exactly one broadcast");
  assert.deepEqual(await v.store.read(Categories.VAULT, r2.vaultId), competitor, "the competing record is preserved");
  const after2 = await wr4.loadRequest(v.cfg, r2.requestId);
  assert.equal(after2.state, "RECONCILIATION_REQUIRED");
  assert.equal(after2.txId, r2.build.txId);
  assert.match(after2.error, /could not be created/);
  assert.ok(await v.store.read(Categories.SUBMISSION_CLAIM, r2.build.txId), "the submission claim is held");
  /* (c) reconciliation observes the output again, reaches the same occupied identity and stays truthful — nothing rebroadcast */
  restore();
  const { seen: seen3, restore: restore3 } = competeAtCreate(v.store, r2.vaultId, competitor);
  t.after(restore3);
  const s3 = v.spy();
  await assert.rejects(() => submit4.reconcileCreateWalletRequestV4({ config: v.cfg, requestId: r2.requestId, rpc: s3.rpc }), (e) => e.code === "RECONCILIATION_REQUIRED");
  assert.equal(s3.calls, 0);
  assert.equal(seen3.challenged, true);
  assert.deepEqual(await v.store.read(Categories.VAULT, r2.vaultId), competitor);
  assert.equal((await wr4.loadRequest(v.cfg, r2.requestId)).state, "RECONCILIATION_REQUIRED");
  assert.ok(await v.store.read(Categories.SUBMISSION_CLAIM, r2.build.txId));
});

test("12 (v0.4.1): the same proven genesis completes idempotently — a reconciliation replayed after a crash between the record write and the request save finds ALREADY_PRESENT and leaves the record byte-identical", { skip: SKIP }, async (t) => {
  const v = await v4Setup(t);
  const r = await v.build();
  v.seed(r);
  const done = await submit4.submitCreateWalletRequestV4({ config: v.cfg, requestId: r.requestId, signedSafeJson: v.signed(r), rpc: v.rpc, pollAttempts: 1, pollDelayMs: 0 });
  assert.equal(done.request.state, "CHAIN_VERIFIED");
  const record = await v.store.read(Categories.VAULT, r.vaultId);
  const req = await wr4.loadRequest(v.cfg, r.requestId);
  req.state = "SUBMITTED";
  req.submittedAt = new Date(Date.now() - 10 * 60_000).toISOString(); // outside the submitter window: reconciliation acts
  await wr4.saveRequest(v.cfg, req);
  const s = v.spy();
  const out = await submit4.reconcileCreateWalletRequestV4({ config: v.cfg, requestId: r.requestId, rpc: s.rpc });
  assert.equal(s.calls, 0, "observation only");
  assert.equal(out.outcome, "CHAIN_VERIFIED");
  assert.deepEqual(await v.store.read(Categories.VAULT, r.vaultId), record, "ALREADY_PRESENT: the record is not rewritten");
  assert.equal((await wr4.loadRequest(v.cfg, r.requestId)).state, "CHAIN_VERIFIED");
});

/* ------------------------------------------------------------------ */
/* the other generations' completions are the same atomic write        */
/* ------------------------------------------------------------------ */

test("13 (matrix): the completion of EVERY other genesis path (v0.5, v0.6, v0.7-payment, v0.7-payment-hd) is an atomic create-only write — a competing writer between the checks and the create is never replaced; the request keeps its signed bytes and txid as RECONCILIATION_REQUIRED with its claim held", { skip: SKIP }, async (t) => {
  const x = await setup(t);
  const { cfg, H: Hh, c, rpc, store } = x;
  const B = builders(x);
  const drive = {
    "v0.5": async (r) => {
      const signed = Hh.signAll(r.transaction.unsignedSafeJson, r.transaction.signInputs.map((s) => [s.index, c.funder]));
      const fin = await wr5.submitSignatureV5({ config: cfg, requestId: r.requestId, signedSafeJson: signed });
      const addr = covenantAddress(cfg, Buffer.from(fin.build.controllerScriptHex, "hex"));
      rpc.seed(addr, Hh.utxo(addr, fin.txId, fin.build.controllerOutputIndex, fin.build.frozen.outputs[fin.build.controllerOutputIndex].value, fin.build.covenantId));
      return { id: r.vaultId, txId: fin.txId, submit: () => wr5.submitWalletRequestV5({ config: cfg, requestId: r.requestId, rpc }), load: () => wr5.loadWalletRequestV5(cfg, r.requestId) };
    },
    "v0.6": async (r) => {
      const signed = Hh.signAll(r.transaction.unsignedSafeJson, r.transaction.signInputs.map((s) => [s.index, c.funder]));
      const fin = await wr6.submitSignatureV6({ config: cfg, requestId: r.requestId, signedSafeJson: signed });
      const addr = covenantAddress(cfg, Buffer.from(fin.build.controllerScriptHex, "hex"));
      rpc.seed(addr, Hh.utxo(addr, fin.txId, fin.build.controllerOutputIndex, fin.build.frozen.outputs[fin.build.controllerOutputIndex].value, fin.build.covenantId));
      return { id: r.vaultId, txId: fin.txId, submit: () => wr6.submitWalletRequestV6({ config: cfg, requestId: r.requestId, rpc }), load: () => wr6.loadWalletRequestV6(cfg, r.requestId) };
    },
    "v0.7-payment": async (r) => {
      const signed = Hh.signAll(r.transaction.unsignedSafeJson, r.transaction.signInputs.map((s) => [s.index, c.funder]));
      const fin = await wr7.submitOrgRootRequestSignature({ config: cfg, requestId: r.id, signedSafeJson: signed });
      const addr = covenantAddress(cfg, Buffer.from(fin.build.vaultScriptHex, "hex"));
      rpc.seed(addr, Hh.utxo(addr, fin.txId, fin.build.vaultOutputIndex, fin.build.frozen.outputs[fin.build.vaultOutputIndex].value, fin.build.covenantId));
      return { id: r.build.template.vaultId, txId: fin.txId, submit: () => wr7.submitOrgRootRequest({ config: cfg, requestId: r.id, rpc }), load: () => wr7.loadOrgRootRequest(cfg, r.id) };
    },
    "v0.7-payment-hd": async (r) => {
      const signed = Hh.signAll(r.transaction.unsignedSafeJson, r.transaction.signInputs.map((s) => [s.index, c.funder]));
      const fin = await wr7hd.finalizeHdWalletRequest({ config: cfg, requestId: r.requestId, signedSafeJson: signed });
      const addr = covenantAddress(cfg, Buffer.from(fin.build.vaultScriptHex, "hex"));
      rpc.seed(addr, Hh.utxo(addr, fin.txId, fin.build.vaultOutputIndex, fin.build.frozen.outputs[fin.build.vaultOutputIndex].value, fin.build.covenantId));
      return { id: r.vaultId, txId: fin.txId, submit: () => wr7hd.submitHdWalletRequest({ config: cfg, requestId: r.requestId, rpc }), load: () => wr7hd.loadHdWalletRequest(cfg, r.requestId) };
    }
  };
  for (const [generation, prepare] of Object.entries(drive)) {
    const r = await B[generation](crypto.randomBytes(32).toString("hex"));
    const d = await prepare(r);
    const competitor = marker(d.id);
    const { seen, restore } = competeAtCreate(store, d.id, competitor);
    let broadcasts = 0;
    const origSubmit = rpc.submitTransaction;
    rpc.submitTransaction = async (a) => { broadcasts++; return origSubmit.call(rpc, a); };
    try {
      await assert.rejects(d.submit, (e) => e.code === "RECONCILIATION_REQUIRED", `${generation}: a competing writer at completion is a conflict, never an overwrite`);
    } finally {
      restore();
      rpc.submitTransaction = origSubmit;
    }
    assert.equal(seen.challenged, true, `${generation}: the completion reached the create-only arbiter`);
    assert.equal(broadcasts, 1, `${generation}: exactly one broadcast`);
    assert.deepEqual(await store.read(Categories.VAULT, d.id), competitor, `${generation}: the competing record is preserved`);
    const after = await d.load();
    assert.equal(after.state, "RECONCILIATION_REQUIRED", `${generation}: truthful state`);
    assert.equal(after.txId, d.txId, `${generation}: the frozen txid is preserved`);
    assert.equal(typeof after.signedSafeJson, "string", `${generation}: the signed bytes are preserved`);
    assert.match(after.error, /could not be created/, `${generation}: the reason is recorded`);
    assert.ok(await store.read(Categories.SUBMISSION_CLAIM, d.txId), `${generation}: the submission claim is held`);
  }
});

/* ------------------------------------------------------------------ */
/* restart recovery                                                    */
/* ------------------------------------------------------------------ */

test("14 (restart): after a completion conflict, a fresh process on the same data root recovers by observation only — the same request stays RECONCILIATION_REQUIRED with its signed bytes, txid and claim, withdrawal is refused, the foreign record is still preserved, and a NEW creation with a fresh identity keeps working", { skip: SKIP }, async (t) => {
  const x = await setup(t), r = await x.build({});
  await x.sign(r);
  x.seed(r);
  const foreign = marker(r.vaultId);
  const { seen, restore } = competeAtCreate(x.store, r.vaultId, foreign);
  await assert.rejects(() => K.submitKasWalletRequest({ config: x.cfg, requestId: r.requestId, rpc: x.rpc, pollAttempts: 1, pollDelayMs: 0 }), (e) => e.code === "RECONCILIATION_REQUIRED");
  restore();
  assert.equal(seen.challenged, true);
  const saved = await K.loadKasWalletRequest(x.cfg, r.requestId);
  /* a fresh config object over the SAME data root = a restarted process (new store instance, no in-memory state) */
  const cfg2 = loadConfig({ dataRoot: x.cfg.dataRoot });
  assert.notEqual(getStore(cfg2), x.store);
  const s = { calls: 0, rpc: { ...x.rpc, async submitTransaction(a) { s.calls += 1; return x.rpc.submitTransaction(a); } } };
  await assert.rejects(() => K.submitKasWalletRequest({ config: cfg2, requestId: r.requestId, rpc: s.rpc, pollAttempts: 1, pollDelayMs: 0 }), (e) => e.code === "RECONCILIATION_REQUIRED");
  assert.equal(s.calls, 0, "never rebroadcast");
  const again = await K.loadKasWalletRequest(cfg2, r.requestId);
  assert.equal(again.state, "RECONCILIATION_REQUIRED");
  assert.equal(again.txId, saved.txId);
  assert.equal(again.signedSafeJson, saved.signedSafeJson);
  assert.equal(again.requestId, saved.requestId);
  assert.ok(await getStore(cfg2).read(Categories.SUBMISSION_CLAIM, r.txId), "the claim is held across the restart");
  assert.deepEqual(await getStore(cfg2).read(Categories.VAULT, r.vaultId), foreign, "the foreign record is still preserved");
  assert.equal((await K.markKasWalletRejected(cfg2, r.requestId)).state, "RECONCILIATION_REQUIRED", "a request that carried a broadcast is never withdrawn");
  assert.ok(!(await wr7.loadOrgRoot(cfg2, x.root)).vaults.includes(r.vaultId), "the root never lists a treasury whose record is not this genesis");
  /* new creation with a fresh identity is unaffected */
  const H2 = createHarness(cfg2);
  const fresh = await K.buildKasVaultGenesisRequest({ config: cfg2, rootCovenantId: x.root, agents: [x.c.policy], approvers: [], approvalM: 0, recoveryAddress: H2.ADDR(x.c.recoveryKey), depositKas: "3", feeReserveKas: "0.5", signerAddress: H2.ADDR(x.c.funder), funding: [H2.fuelUtxoFor(x.c.funder, 20n * KAS)] });
  assert.equal(fresh.state, "BUILT");
  assert.notEqual(fresh.vaultId, r.vaultId);
});

test("15 (fail closed): a record under the identity that this build cannot read (corrupt JSON) still occupies the identity — build refuses VAULT_ID_IN_USE, completion refuses RECONCILIATION_REQUIRED, nothing is replaced", { skip: SKIP }, async (t) => {
  const x = await setup(t);
  const id = "c0".repeat(32);
  const file = path.join(x.cfg.dataRoot, "vaults", id, "manifest.json");
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, "{ this is not json");
  await assert.rejects(() => x.build({ vaultId: id }), (e) => e.code === "VAULT_ID_IN_USE");
  const { createVaultRecordOrMatch } = require("../src/vault-identity");
  await assert.rejects(() => createVaultRecordOrMatch(x.cfg, id, { schema: "policyvault-rooted-kas-vault-manifest-record/1", vaultId: id }), (e) => e.code === "RECONCILIATION_REQUIRED");
  assert.equal(fs.readFileSync(file, "utf8"), "{ this is not json", "the unreadable record is untouched");
});

/* ------------------------------------------------------------------ */
/* PRE-CORRECTION pairs under CONCURRENCY (internal read-only review of  */
/* 6c52660, finding F1: the commit-phase check must be serialized per   */
/* identity inside the root / signer / request lock — a check-then-act  */
/* window lets a legacy pair double-broadcast)                          */
/* ------------------------------------------------------------------ */

/* Two drafts naming ONE identity can only exist as PRE-CORRECTION data (the corrected build refuses the second); model
 * that pair by building B with the reservation scan hidden — exactly what the withdrawn rc33 build did. A and B are
 * genuine builds with different funding, so different transactions and txids. */
async function buildLegacyPair(store, build, vaultId) {
  const a = await build(vaultId);
  const listValues = store.listValues.bind(store);
  store.listValues = async (category, opts) => (category === Categories.REQUEST || category === Categories.ORG_ROOT_REQUEST ? [] : listValues(category, opts));
  let b;
  try { b = await build(vaultId); } finally { store.listValues = listValues; }
  return [a, b];
}
const oneFulfilledOneRefused = (results) => {
  assert.equal(results.filter((r) => r.status === "fulfilled").length, 1, `exactly one of the pair proceeds: ${JSON.stringify(results.map((r) => r.status === "fulfilled" ? "ok" : r.reason && r.reason.code))}`);
  const refused = results.find((r) => r.status === "rejected");
  assert.equal(refused.reason.code, "VAULT_ID_IN_USE", refused.reason && refused.reason.message);
};

test("16 (review F1, v0.4.1): a PRE-CORRECTION pair of drafts naming one identity submitted CONCURRENTLY — exactly ONE broadcast; one CHAIN_VERIFIED; the other refused VAULT_ID_IN_USE, left BUILT (withdrawable) and never claimed; one record", { skip: SKIP }, async (t) => {
  const v = await v4Setup(t);
  const id = hex32();
  const [a, b] = await buildLegacyPair(v.store, (vid) => v.build(vid), id);
  assert.equal(a.vaultId, id); assert.equal(b.vaultId, id); assert.notEqual(a.build.txId, b.build.txId);
  v.seed(a); v.seed(b); // the mock node would observe EITHER creation if it were broadcast
  const s = v.spy();
  const results = await Promise.allSettled([a, b].map((r) => submit4.submitCreateWalletRequestV4({ config: v.cfg, requestId: r.requestId, signedSafeJson: v.signed(r), rpc: s.rpc, pollAttempts: 1, pollDelayMs: 0 })));
  assert.equal(s.calls, 1, "exactly one broadcast for the pair");
  oneFulfilledOneRefused(results);
  const states = await Promise.all([a, b].map(async (r) => (await wr4.loadRequest(v.cfg, r.requestId)).state));
  assert.deepEqual([...states].sort(), ["BUILT", "CHAIN_VERIFIED"]);
  const record = await v.store.read(Categories.VAULT, id);
  const winner = [a, b].find((r) => r.build.txId === record.creationTxId), loser = [a, b].find((r) => r.build.txId !== record.creationTxId);
  assert.ok(winner && loser);
  assert.equal(await v.store.read(Categories.SUBMISSION_CLAIM, loser.build.txId), null, "the refused draft never claimed");
  assert.equal((await wr4.loadRequest(v.cfg, loser.requestId)).state, "BUILT");
});

test("17 (review F1, v0.7-kas): a PRE-CORRECTION pair signed CONCURRENTLY — exactly one becomes SIGNED, the other is refused VAULT_ID_IN_USE and stays BUILT (withdrawable); the SIGNED one submits with one broadcast", { skip: SKIP }, async (t) => {
  const x = await setup(t);
  const id = hex32();
  const [a, b] = await buildLegacyPair(x.store, (vid) => x.build({ vaultId: vid }), id);
  assert.notEqual(a.txId, b.txId);
  const results = await Promise.allSettled([a, b].map((r) => x.sign(r)));
  oneFulfilledOneRefused(results);
  const states = await Promise.all([a, b].map(async (r) => (await K.loadKasWalletRequest(x.cfg, r.requestId)).state));
  assert.deepEqual([...states].sort(), ["BUILT", "SIGNED"]);
  const signed = [a, b][states.indexOf("SIGNED")], draft = [a, b][states.indexOf("BUILT")];
  x.seed(signed);
  const s = x.spy();
  const done = await K.submitKasWalletRequest({ config: x.cfg, requestId: signed.requestId, rpc: s.rpc, pollAttempts: 1, pollDelayMs: 0 });
  assert.equal(done.state, "CHAIN_VERIFIED"); assert.equal(s.calls, 1);
  await assert.rejects(() => x.sign(draft), (e) => e.code === "VAULT_ID_IN_USE", "the draft can never be signed once the identity is held");
  assert.equal((await K.markKasWalletRejected(x.cfg, draft.requestId)).state, "WALLET_REJECTED", "the unsigned draft remains withdrawable");
});

test("18 (review F1, every other family): a PRE-CORRECTION pair signed CONCURRENTLY for v0.5, v0.6, v0.7-payment and v0.7-payment-hd — exactly one signature is accepted, the other refused VAULT_ID_IN_USE with its request left unsigned", { skip: SKIP }, async (t) => {
  const x = await setup(t);
  const { cfg, H: Hh, c, store } = x;
  const B = builders(x);
  const sign = {
    "v0.5": (r) => wr5.submitSignatureV5({ config: cfg, requestId: r.requestId, signedSafeJson: Hh.signAll(r.transaction.unsignedSafeJson, r.transaction.signInputs.map((s) => [s.index, c.funder])) }),
    "v0.6": (r) => wr6.submitSignatureV6({ config: cfg, requestId: r.requestId, signedSafeJson: Hh.signAll(r.transaction.unsignedSafeJson, r.transaction.signInputs.map((s) => [s.index, c.funder])) }),
    "v0.7-payment": (r) => wr7.submitOrgRootRequestSignature({ config: cfg, requestId: r.id, signedSafeJson: Hh.signAll(r.transaction.unsignedSafeJson, r.transaction.signInputs.map((s) => [s.index, c.funder])) }),
    "v0.7-payment-hd": (r) => wr7hd.finalizeHdWalletRequest({ config: cfg, requestId: r.requestId, signedSafeJson: Hh.signAll(r.transaction.unsignedSafeJson, r.transaction.signInputs.map((s) => [s.index, c.funder])) })
  };
  const load = {
    "v0.5": (r) => wr5.loadWalletRequestV5(cfg, r.requestId), "v0.6": (r) => wr6.loadWalletRequestV6(cfg, r.requestId),
    "v0.7-payment": (r) => wr7.loadOrgRootRequest(cfg, r.id), "v0.7-payment-hd": (r) => wr7hd.loadHdWalletRequest(cfg, r.requestId)
  };
  const unsignedState = { "v0.5": "BUILT", "v0.6": "BUILT", "v0.7-payment": "AUTHORIZED", "v0.7-payment-hd": "BUILT" };
  for (const generation of Object.keys(sign)) {
    const id = hex32();
    const [a, b] = await buildLegacyPair(store, (vid) => B[generation](vid), id);
    const results = await Promise.allSettled([a, b].map((r) => sign[generation](r)));
    try { oneFulfilledOneRefused(results); } catch (e) { e.message = `${generation}: ${e.message}`; throw e; }
    const states = await Promise.all([a, b].map(async (r) => (await load[generation](r)).state));
    assert.deepEqual([...states].sort(), [unsignedState[generation], "SIGNED"].sort(), `${generation}: one SIGNED, one still unsigned`);
    const unsigned = [a, b][states.indexOf(unsignedState[generation])];
    assert.equal((await load[generation](unsigned)).signedSafeJson, undefined, `${generation}: no signature stored on the refused request`);
  }
});
