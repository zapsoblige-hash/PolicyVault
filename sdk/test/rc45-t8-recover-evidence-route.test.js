"use strict";
/*
 * RC45 T8 — THE VERIFY ROUTE CARRIES OWNER RECOVER EVIDENCE (fix item F6
 * RC45-L5-RECOVER-EVIDENCE; plan rc45-simplified-plan-r2 §3 concept 3
 * `outOfAppTransaction`, §5 A5, §8 rules (CR-M14, CR2-L12) and T8 "body
 * limits; GATE 1 foreign evidence -> 404, no parse or node call (CR-L6); v2
 * vault + field -> 422 (CR-L15)", §A F6 -> T5, T8). The inventory row, the
 * `vault.reconciled` correlation.requestId, WEB-1..3 and every other T8 leg
 * are F8's. Internal RED-first regression material for the RC45 candidate;
 * not an audit.
 *
 * RED on C1 e62b1973: POST /vaults/:id/reconcile never reads the body; it
 * calls reconcileVaultV4(config, vaultId) with no options (so a paste cannot
 * settle anything) and runs the v2 reconciler for a v2 vault whatever the
 * body says. GREEN after F6 (A5):
 *   - principal and requireVaultAccess(owner) FIRST (GATE 1: a foreign
 *     principal gets 404, an agent 403, no session 401, whatever the body;
 *     no parse, no reconcile, no node call);
 *   - then `outOfAppTransaction`: a non-string value or a string over 64 KiB
 *     -> 400 BAD_FORMAT, no reconcile; on a non-v4 vault the field -> 422
 *     UNSUPPORTED_VERSION, no reconcile (without the field the v2 reconciler
 *     still runs);
 *   - otherwise the field is threaded into reconcileVaultV4(config, vaultId,
 *     { outOfAppTransaction }) and a real pasted recover settles the vault
 *     RECOVERED at depth.
 *
 * Layers: API (the real server/src/api.js handle in hosted mode, wallet
 * sessions signed in with TEST keys, sdk/testutil/rc45-f3-kit.js apiFor).
 * The route cannot pass `rpc` and the default rpcUrl is the operator's
 * testnet-10 node, so, as plan §8 rules allow for route-level Verify (CR-M14,
 * CR2-L12), the module-cache exports of the REAL reconcileVaultV4 and
 * reconcileVaultV2 are wrapped to call themselves with the explicit chain
 * model's rpc (never a stub), recording each call's options, and restored
 * afterwards; every config names ws://127.0.0.1:1. The pasted recover is a
 * real TEST-key signed, VM-preflighted hosted-built recover finalized in a
 * side root (its record never reaches the tested store). The v2 vault is a
 * closed (RECOVERED) policyvault-0.2 manifest owned by the TEST owner.
 *
 * Both stores: JSON always; PostgreSQL with POLICYVAULT_TEST_PG_{PORT,USER,
 * DATABASE} (the rc45 runner's pg mode; a skipped PostgreSQL leg there is a
 * FAIL). TEST keys only; no production data, credentials or endpoints.
 */
const path = require("node:path");
const assert = require("node:assert/strict");
const { test, before, after } = require("node:test");
const K = require("../testutil/rc45-f5-kit");
const F3 = require("../testutil/rc45-f3-kit");
const F6 = require("../testutil/rc45-f6-kit");
const { LOOPBACK, SETTLE_DEPTH_DAA, frozenOf } = K;

const cand = K.modulesOf(path.join(__dirname, "..", "src"));
const { Categories } = cand.store;
const { persistManifestV2, MANIFEST_SCHEMA_V2 } = require("../src/manifest-v2");
const { normalizeTemplateV2, CONTRACT_VERSION_V2 } = require("../src/vault-state-v2");
const TOOLCHAIN = require("../testutil/org-root-durable-fixture").toolchainAvailable();
const PG = K.pgFromEnv();
const PG_AVAILABLE = Boolean(PG.port && PG.user && PG.database);
const PASTE_LIMIT = 64 * 1024;
const V = Object.freeze({ rt: K.vault("t8r-rt"), v2: Object.freeze({ vaultId: K.hex("rc45-f6-t8r-v2-vault") }) });
const roots = [], stores = [], databases = [];
let admin = null, serial = 0, history = null, B = null, w = null, templateRoot = null;
const mk = (prefix) => { const dir = K.ownedTempRoot(prefix); roots.push(dir); return dir; };
const said = (r) => `${r.status} ${r.code ?? ""} ${r.message ?? ""}`.trim();

before(async () => {
  assert.ok(TOOLCHAIN, "real compiler, encoder and VM are required (a missing VM toolchain is a FAIL, never a SKIP)");
  const template = cand.config.loadConfig({ dataRoot: mk("pv-rc45-f6-t8-template-"), rpcUrl: LOOPBACK });
  w = K.walletsFor(template);
  B = {};
  { // rt: a clean live vault at L. Side root: the owner's hosted-built Close & recover (fuel2), finalized there.
    const v = V.rt; await K.seedVault(cand, template, v, w);
    const side = cand.config.loadConfig({ dataRoot: mk("pv-rc45-f6-t8-side-"), rpcUrl: LOOPBACK });
    K.warmCompileCache(template.dataRoot, side.dataRoot);
    await K.seedVault(cand, side, v, w);
    const sk = K.kitFor(cand, side, w);
    const x = await sk.finalize(await sk.ownerOp(v, "ownerRecover", "fuel2"), w.owner);
    assert.equal(x.state, "PREFLIGHT_VERIFIED");
    B.rt = { txId: x.txId, frozen: frozenOf(x), safe: F6.safeJsonOf(side, x.finalTransaction), L: x.predecessorOutpoint, input0: frozenOf(x).inputs[0] };
    assert.ok(Buffer.byteLength(B.rt.safe) <= PASTE_LIMIT, "the real recover paste is within the 64 KiB limit");
    K.warmCompileCache(side.dataRoot, template.dataRoot);
  }
  { // v2: a closed policyvault-0.2 vault owned by the TEST owner.
    const vaultId = V.v2.vaultId;
    await persistManifestV2(template, { schema: MANIFEST_SCHEMA_V2, contractVersion: CONTRACT_VERSION_V2, networkId: template.networkId, vaultId, label: "RC45 F6 T8 v2 TEST", status: "RECOVERED",
      template: normalizeTemplateV2({ owner: w.owner.xonly, vaultId }), live: null, creationTxId: K.hex("rc45-f6-t8r-v2-creation"), latestTransitionTxId: null, lastTransition: null });
  }
  history = await K.snapshot(cand, template);
  templateRoot = template.dataRoot;
  if (PG_AVAILABLE) admin = new (require("pg").Pool)(PG);
});
after(async () => {
  for (const s of stores) { try { await s.close(); } catch { /* closed */ } }
  if (admin) { for (const db of databases) await admin.query(`DROP DATABASE IF EXISTS ${db} WITH (FORCE)`); await admin.end(); }
  for (const root of roots) K.removeOwnedRoot(root);
});

/* A fresh hosted case (authMode enabled; owner, agent and a foreign wallet signed in with TEST keys). */
async function fresh(backend) {
  const dataRoot = mk("pv-rc45-f6-t8-case-");
  K.warmCompileCache(templateRoot, dataRoot);
  const hosted = { authMode: "enabled", authCookieInsecure: true, dataRoot, rpcUrl: LOOPBACK };
  let config, pgDatabase = null;
  if (backend === "PostgreSQL") {
    pgDatabase = `pv_rc45_f6_t8_${process.pid}_${++serial}`;
    await admin.query(`CREATE DATABASE ${pgDatabase}`); databases.push(pgDatabase);
    config = cand.config.loadConfig({ persistenceBackend: "postgres", pgHost: PG.host, pgPort: PG.port, pgUser: PG.user, pgDatabase, pgNoTls: true, ...hosted });
    stores.push(await cand.store.openPgStore(config, { migrate: true }));
    assert.equal(cand.store.getStore(config).kind, "postgres");
  } else config = cand.config.loadConfig(hosted);
  assert.equal(config.tenancyEnforced, true);
  await K.install(cand, config, history);
  const store = cand.store.getStore(config), api = F3.apiFor(config);
  const x = { config, store, api, pgDatabase, model: K.chainModel(config), snap: () => K.snapshot(cand, config), rawManifest: (id) => store.read(Categories.VAULT, id), receipt: (txId) => store.read(Categories.RECEIPT, txId) };
  x.cookie = { owner: await api.signIn(w.owner), agent: await api.signIn(w.agent), foreign: await api.signIn(w.recipient3) };
  /* POST /vaults/:id/reconcile through the REAL reconcilers wrapped with the explicit chain model's rpc. */
  x.verify = async (vaultId, body, cookie) => {
    const m4 = require(path.join(F6.SDK_SRC, "reconcile-v4.js")), m2 = require(path.join(F6.SDK_SRC, "reconcile-v2.js"));
    const real4 = m4.reconcileVaultV4, real2 = m2.reconcileVaultV2, seen = { v4: [], v2: [] };
    m4.reconcileVaultV4 = (c, id, options = {}) => { seen.v4.push({ vaultId: id, options: { ...options } }); return real4(c, id, { ...options, rpc: x.model.rpc }); };
    m2.reconcileVaultV2 = (c, id, options = {}) => { seen.v2.push({ vaultId: id, options: { ...options } }); return real2(c, id, { ...options, rpc: x.model.rpc }); };
    try { return { r: await api.call("POST", ["vaults", vaultId, "reconcile"], body, cookie), seen }; } finally { m4.reconcileVaultV4 = real4; m2.reconcileVaultV2 = real2; }
  };
  return x;
}
async function release(x) {
  if (!x.pgDatabase) return;
  const i = stores.indexOf(x.store);
  if (i >= 0) { stores.splice(i, 1); await x.store.close(); }
}
/* A refused Verify: exact status/code, no reconcile call, no node call, nothing written. */
async function assertRefusedAtRoute(x, vaultId, body, cookie, status, code, label) {
  const before = await x.snap(), calls = x.model.calls.length;
  const { r, seen } = await x.verify(vaultId, body, cookie);
  assert.equal(r.status, status, `${label}: ${status} ${code ?? ""} (got ${said(r)})`);
  if (code) assert.equal(r.code, code, `${label}: ${code}`);
  assert.equal(seen.v4.length + seen.v2.length, 0, `${label}: no reconcile runs`);
  assert.equal(x.model.calls.length, calls, `${label}: no node call`);
  assert.deepEqual(await x.snap(), before, `${label}: nothing is written`);
}

const PG_SKIP = PG_AVAILABLE ? undefined : "REQUIREMENT_NOT_AVAILABLE in this process: isolated PostgreSQL (the rc45 runner's pg mode runs these legs; a skipped PostgreSQL leg there is a FAIL)";
for (const [backend, skip] of [["JSON", undefined], ["PostgreSQL", PG_SKIP]]) {
  const t8 = (name, fn) => test(`RC45 T8 ${backend}: ${name}`, { skip }, async () => { const x = await fresh(backend); try { await fn(x); } finally { await release(x); } });
  const liveL = (x) => { const i0 = B.rt.input0; x.model.add(i0.previousOutpoint, i0.utxo.amount, i0.utxo.scriptPublicKey, V.rt.cov, x.model.virtualDaaScore - 5000n); };

  t8("A5 threads the owner's paste: POST /vaults/:id/reconcile {outOfAppTransaction} passes the exact field to reconcileVaultV4(config, vaultId, { outOfAppTransaction }); a real pasted recover observed at depth D settles the vault RECOVERED (200, ADVANCED to RECOVERED, case-B receipt) [RED on C1]", async (x) => {
    x.model.confirm(B.rt.frozen, B.rt.txId); x.model.advance(SETTLE_DEPTH_DAA);
    const { r, seen } = await x.verify(V.rt.vaultId, { outOfAppTransaction: B.rt.safe }, x.cookie.owner);
    assert.equal(seen.v4.length, 1, `the v0.4 reconciler runs once (${said(r)})`);
    assert.equal(seen.v4[0].options.outOfAppTransaction, B.rt.safe, "A5: the route threads the exact pasted field");
    assert.equal(r.status, 200, said(r));
    assert.equal(r.body.reconcile.status, "ADVANCED"); assert.equal(r.body.reconcile.to, "RECOVERED"); assert.equal(r.body.reconcile.txId, B.rt.txId);
    const m = await x.rawManifest(V.rt.vaultId);
    assert.equal(m.status, "RECOVERED"); assert.equal(m.live, null); assert.equal(m.latestTransitionTxId, B.rt.txId);
    const receipt = await x.receipt(B.rt.txId);
    assert.ok(receipt); assert.equal(receipt.action, "ownerRecover"); assert.equal(receipt.proof.consumedOutpoint, `${B.rt.L.transactionId}:${B.rt.L.index}`);
  });
  t8("A5 body limits: a non-string outOfAppTransaction (number, object, array, boolean) -> 400 BAD_FORMAT with no reconcile, no node call and no write [RED on C1]", async (x) => {
    liveL(x);
    for (const value of [42, { txId: B.rt.txId }, [B.rt.safe], true]) {
      await assertRefusedAtRoute(x, V.rt.vaultId, { outOfAppTransaction: value }, x.cookie.owner, 400, "BAD_FORMAT", `outOfAppTransaction ${JSON.stringify(value).slice(0, 40)}`);
    }
  });
  t8("A5 body limits: an outOfAppTransaction over 64 KiB (the real recover paste padded to 65,537 bytes) -> 400 BAD_FORMAT with no reconcile, no node call and no write [RED on C1]", async (x) => {
    liveL(x);
    const padded = B.rt.safe + " ".repeat(PASTE_LIMIT + 1 - Buffer.byteLength(B.rt.safe));
    assert.equal(Buffer.byteLength(padded), PASTE_LIMIT + 1);
    await assertRefusedAtRoute(x, V.rt.vaultId, { outOfAppTransaction: padded }, x.cookie.owner, 400, "BAD_FORMAT", "a 65,537-byte paste");
  });
  t8("CR-L15: a v2 vault receiving outOfAppTransaction -> 422 UNSUPPORTED_VERSION with no reconcile (the v2 reconciler never runs), no node call and no write [RED on C1]", async (x) => {
    await assertRefusedAtRoute(x, V.v2.vaultId, { outOfAppTransaction: B.rt.safe }, x.cookie.owner, 422, "UNSUPPORTED_VERSION", "the paste on a v2 vault");
  });
  t8("a v2 vault Verify without the field still runs the v2 reconciler (200 TERMINAL for the closed v2 vault) [holds on C1]", async (x) => {
    const { r, seen } = await x.verify(V.v2.vaultId, {}, x.cookie.owner);
    assert.equal(r.status, 200, said(r)); assert.equal(r.body.reconcile.status, "TERMINAL");
    assert.equal(seen.v2.length, 1); assert.equal(seen.v4.length, 0);
  });
  t8("GATE 1 (CR-L6): foreign evidence -> 404 VAULT_NOT_FOUND before any parse (malformed, oversized or valid paste alike), an agent principal -> 403, no session -> 401; never a reconcile, a node call or a write [holds on C1]", async (x) => {
    x.model.confirm(B.rt.frozen, B.rt.txId); x.model.advance(SETTLE_DEPTH_DAA);
    const oversized = "x".repeat(PASTE_LIMIT + 10);
    for (const value of [42, oversized, B.rt.safe]) {
      const label = typeof value === "string" ? `${value.length}-char paste` : "a non-string paste";
      await assertRefusedAtRoute(x, V.rt.vaultId, { outOfAppTransaction: value }, x.cookie.foreign, 404, "VAULT_NOT_FOUND", `foreign principal, ${label}`);
      await assertRefusedAtRoute(x, V.rt.vaultId, { outOfAppTransaction: value }, x.cookie.agent, 403, "VAULT_FORBIDDEN", `agent principal, ${label}`);
      await assertRefusedAtRoute(x, V.rt.vaultId, { outOfAppTransaction: value }, null, 401, null, `no session, ${label}`);
    }
  });
}
