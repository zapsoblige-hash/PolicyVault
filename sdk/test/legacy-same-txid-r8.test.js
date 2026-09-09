"use strict";
/* Round-8 internal review of fullscale-rc27 (2026-09-08), findings R8-01 (LOW) and R8-02 (MEDIUM) — LEGACY (pre-RC27F,
 * df68a1f-produced) records in which TWO requests share ONE transaction id:
 *   - an owner operation built, withdrawn and rebuilt with the same fuel (identical frozen bytes): A REFUSED + B CHAIN_VERIFIED;
 *   - a delegate spend built twice with one completed: S1 CHAIN_VERIFIED + S2 BUILT, the legacy submission claim retained
 *     (written by the old inline completion with `expected: null`).
 * Rule under test: a request that was never finalized, or that ended in a terminal refusal before any submission, cannot
 * have produced the chain effect — it is never associated as the completed request, never a completion candidate, and a
 * failed inspection never writes onto it (F-5 for drafts). RED on e7c0cb6: every build on the vault was refused with
 * VAULT_PENDING_REQUEST, the public vault reconcile durably downgraded the BUILT draft to RECONCILIATION_REQUIRED and
 * aborted before repairing the completed spend. Fixtures in sdk/test/fixtures/legacy-df68a1f/ were produced by the REAL
 * df68a1f runtime through its public entry points (TEST keys, seeded UTXO table; nothing broadcast); their compile-cache
 * paths are redacted metadata the runtime never reads. */
const { test } = require("node:test"), assert = require("node:assert/strict");
const fs = require("node:fs"), path = require("node:path");
const source = process.env.POLICYVAULT_RC27F_SOURCE || path.resolve(__dirname, "../..");
const dep = (p) => require(path.join(source, p));
const d = dep("sdk/testutil/cp13e-delegate-fixture"), { fx } = d, wr = fx.wr7;
const rec = dep("sdk/src/reconcile-v7");
const fixtures = path.resolve(__dirname, "fixtures/legacy-df68a1f");
async function fixture(name) {
  const saved = JSON.parse(fs.readFileSync(path.join(fixtures, name + ".json")), (_k, v) => v?.$big ? BigInt(v.$big) : v);
  assert.equal(saved.producedBy, "df68a1fd64775948e799935759d08b549181100c");
  const config = fx.freshJsonConfig("pv-r8-legacy-"), store = fx.getStore(config);
  for (const [c, values] of Object.entries(saved.records)) for (const [k, v] of Object.entries(values)) await store.write(c, k, v);
  for (const e of saved.audit) await store.appendAudit(e);
  const rpc = fx.mockRpc(); for (const [a, entries] of Object.entries(saved.rpc)) for (const e of entries) rpc.seed(a, e);
  const o = { ...saved.ids, fuelKey: fx.KEY(config, 0x64), agentKey: fx.KEY(config, 0x62), owner1: fx.KEY(config, 0x71), owner2: fx.KEY(config, 0x72), owner3: fx.KEY(config, 0x73), recipientKey: fx.KEY(config, 0x63),
    rTree: dep("sdk/src/recipient-merkle-v3").buildRecipientTree([fx.XO(config, fx.KEY(config, 0x63))]) };
  return { config, saved, o, rpc };
}
const codeOf = async (fn) => { try { return { ok: true, value: await fn() }; } catch (e) { return { ok: false, code: e.code, message: String(e.message) }; } };
const ownerOp = (config, o, action) => wr.buildRootActionRequest({ config, rootCovenantId: o.rootCovenantId, action: "authorize", params: { fuel: fx.fuelUtxoFor(config, o.fuelKey) }, vaultOperations: [{ vaultId: o.vaultId, action, params: {} }], signerAddress: fx.ADDR(config, o.owner1) });
const agentSpend = (config, o) => wr.buildV7WalletRequest({ config, vaultId: o.vaultId, action: "tokenAgentSpend", signerAddress: fx.ADDR(config, o.agentKey), params: { spendAmount: "1", periodsElapsed: "0", agents: [], recipient: fx.XO(config, o.recipientKey), recipients: [...o.rTree.recipients], recipientCarryKasSompi: "0", tokenPosition: null } });

for (const variant of ["unsigned", "signed"]) test(`R8-01: legacy withdraw-and-rebuild owner operation (${variant} withdrawal, one txid) — the completed request is the sole association; new work builds; nothing is downgraded; nothing broadcast`, async () => {
  const x = await fixture(`ownerop-withdraw-rebuild-${variant}`), { o, rpc } = x;
  const A0 = await wr.loadOrgRootRequest(x.config, o.A), B0 = await wr.loadOrgRootRequest(x.config, o.B);
  assert.equal(A0.state, "REFUSED"); assert.equal(B0.state, "CHAIN_VERIFIED"); assert.equal(A0.txId, B0.txId);
  assert.equal(!!A0.finalTransaction, variant === "signed", "the signed variant carries a final transaction on the withdrawn request");
  const root0 = await wr.loadOrgRoot(x.config, o.rootCovenantId), vault0 = await fx.loadManifestV7(x.config, o.vaultId);
  assert.equal(root0.pendingRequestId, null);
  // The documented public path: reconcile the organization. It must be CONSISTENT and never pin or rewrite history.
  const r = await rec.reconcileOrgRootV7(x.config, o.rootCovenantId, { rpc });
  assert.equal(r.root.status, "CONSISTENT");
  assert.deepEqual(await wr.loadOrgRoot(x.config, o.rootCovenantId), root0, "no pin / no rewrite of the root");
  assert.deepEqual(await fx.loadManifestV7(x.config, o.vaultId), vault0, "no rollback / no advance of the vault");
  assert.deepEqual(await wr.loadOrgRootRequest(x.config, o.A), A0, "the withdrawn duplicate is untouched");
  assert.deepEqual(await wr.loadOrgRootRequest(x.config, o.B), B0, "the completed request is untouched");
  // A new owner operation on the vault builds (the vault is paused by B's ownerPause: unpause it).
  const b = await ownerOp(x.config, o, "ownerUnpause");
  assert.equal(b.state, "AUTHORIZED"); assert.equal(b.vaultOperations[0].vaultId, o.vaultId);
  await wr.rejectOrgRootRequest({ config: x.config, requestId: b.id, reason: "test cleanup" });
  // Delegate admission is not guarded by the legacy pair (the paused vault may refuse the spend for its own reason).
  const s = await codeOf(() => agentSpend(x.config, o));
  assert.notEqual(s.code, "VAULT_PENDING_REQUEST", s.message);
  // Idempotent public re-submit of the completed request stays a no-op on the chain and keeps every record.
  const again = await wr.submitOrgRootRequest({ config: x.config, requestId: o.B, rpc });
  assert.equal(again.state, "CHAIN_VERIFIED");
  assert.deepEqual(await wr.loadOrgRoot(x.config, o.rootCovenantId), root0);
  assert.deepEqual(await fx.loadManifestV7(x.config, o.vaultId), vault0);
  const b2 = await ownerOp(x.config, o, "ownerUnpause");
  await wr.rejectOrgRootRequest({ config: x.config, requestId: b2.id, reason: "test cleanup" });
  assert.equal(rpc.submits(), 0, "nothing was ever broadcast on legacy data");
});

test("R8-02: legacy delegate spend built twice (one completed, one BUILT, one txid, legacy claim retained) — the draft is never a completion candidate; the public reconcile repairs the completed spend and never downgrades the draft; the vault stays usable", async () => {
  const x = await fixture("delegate-dup-built-twice"), { o, rpc } = x;
  const S1 = await wr.loadV7WalletRequest(x.config, o.S1), S2 = await wr.loadV7WalletRequest(x.config, o.S2);
  assert.equal(S1.state, "CHAIN_VERIFIED"); assert.equal(S2.state, "BUILT"); assert.equal(S1.txId, S2.txId); assert.equal(S2.finalTransaction, undefined);
  const claim0 = await fx.loadSubmissionClaim(x.config, o.txId);
  assert.ok(claim0 && claim0.expected == null, "the legacy submission claim (expected: null) is retained by the old runtime");
  const root0 = await wr.loadOrgRoot(x.config, o.rootCovenantId), vault0 = await fx.loadManifestV7(x.config, o.vaultId);
  // The documented public path (vault reconcile) finishes the completed spend's local records and leaves the draft alone.
  const v = await rec.reconcileVault(x.config, rpc, o.vaultId);
  assert.notEqual(v.status, "UNKNOWN", JSON.stringify(v));
  assert.deepEqual(await wr.loadV7WalletRequest(x.config, o.S2), S2, "F-5 for drafts: the never-finalized duplicate is untouched");
  assert.equal((await wr.loadV7WalletRequest(x.config, o.S1)).state, "CHAIN_VERIFIED");
  assert.equal(await fx.loadSubmissionClaim(x.config, o.txId), null, "the completed spend's legacy submission claim is released");
  assert.equal((await fx.loadReceipt(x.config, o.txId)).proof.requestId, o.S1, "the receipt now points at the completed request");
  assert.deepEqual(await wr.loadOrgRoot(x.config, o.rootCovenantId), root0);
  assert.deepEqual(await fx.loadManifestV7(x.config, o.vaultId), vault0, "the vault's live state is neither rolled back nor advanced");
  const again = await rec.reconcileVault(x.config, rpc, o.vaultId);
  assert.equal(again.status, "CONSISTENT", JSON.stringify(again));
  // Owner operations and the next agent spend proceed.
  const b = await ownerOp(x.config, o, "ownerPause");
  assert.equal(b.state, "AUTHORIZED");
  await wr.rejectOrgRootRequest({ config: x.config, requestId: b.id, reason: "test cleanup" });
  const spend = await d.signedSpend(x.config, o);
  assert.equal(spend.state, "SIGNED");
  // The stale draft has a supported exit and never blocks anything.
  assert.equal((await wr.markV7WalletRejected(x.config, o.S2)).state, "WALLET_REJECTED");
  assert.equal(rpc.submits(), 0, "nothing was ever broadcast on legacy data");
});

test("R8-02 (already-damaged draft): a never-finalized draft that an earlier runtime marked RECONCILIATION_REQUIRED is not a completion candidate and can be withdrawn", async () => {
  const x = await fixture("delegate-dup-built-twice"), { o, rpc } = x;
  const S2 = await wr.loadV7WalletRequest(x.config, o.S2);
  await wr.saveV7WalletRequest(x.config, { ...S2, state: "RECONCILIATION_REQUIRED", error: "frozen-tx-v3: frozen transactions must be version 1 (Toccata)" });
  const v = await rec.reconcileVault(x.config, rpc, o.vaultId);
  assert.notEqual(v.status, "UNKNOWN", JSON.stringify(v));
  const b = await ownerOp(x.config, o, "ownerPause");
  await wr.rejectOrgRootRequest({ config: x.config, requestId: b.id, reason: "test cleanup" });
  assert.equal((await wr.markV7WalletRejected(x.config, o.S2)).state, "WALLET_REJECTED");
  assert.equal(rpc.submits(), 0);
});

test("R8-07: a never-finalized draft is refused from submission with a closed code and a truthful message", async () => {
  const x = await fixture("delegate-dup-built-twice"), { o, rpc } = x;
  const refused = await codeOf(() => wr.submitV7WalletRequest({ config: x.config, requestId: o.S2, rpc }));
  assert.equal(refused.ok, false); assert.equal(refused.code, "RECONCILIATION_REQUIRED"); assert.match(refused.message, /BUILT|never finalized/);
  assert.equal((await wr.loadV7WalletRequest(x.config, o.S2)).state, "BUILT", "the refusal writes nothing");
  assert.equal(rpc.submits(), 0);
});

/* R8-09 (round-8 re-check): a legacy delegate spend FINALIZED twice (S1 and S2 both SIGNED with their own signature
 * scripts, same fuel, ONE txid; only S1 submitted → CHAIN_VERIFIED; legacy claim retained). Requests sharing one txid
 * carry identical frozen bytes — one chain effect — and the request this system completed or attempted owns it; a
 * SIGNED record with the same txid and no submission evidence is a SAME-EFFECT DUPLICATE: never the completed request,
 * never a completion candidate, never an admission guard, never relabelled CHAIN_VERIFIED; it may be withdrawn. (This runtime
 * cannot produce the shape itself: a second build while one is pending yields different bytes, and modern claims name their
 * request — the reviewer's rc27 controls cover that; the fixture below is the legacy shape.) */
test("R8-09: legacy delegate spend finalized twice (S1 CHAIN_VERIFIED + S2 SIGNED, one txid, legacy claim retained) — the duplicate is never completed nor guards; the vault stays usable; the duplicate can be withdrawn", async () => {
  const x = await fixture("delegate-dup-signed-twice"), { o, rpc } = x;
  const S1 = await wr.loadV7WalletRequest(x.config, o.S1), S2 = await wr.loadV7WalletRequest(x.config, o.S2);
  assert.equal(S1.state, "CHAIN_VERIFIED"); assert.equal(S2.state, "SIGNED"); assert.equal(S1.txId, S2.txId); assert.ok(S2.finalTransaction);
  assert.ok(await fx.loadSubmissionClaim(x.config, o.txId), "legacy submission claim retained");
  const root0 = await wr.loadOrgRoot(x.config, o.rootCovenantId), vault0 = await fx.loadManifestV7(x.config, o.vaultId);
  for (let round = 1; round <= 2; round++) {
    const v = await rec.reconcileVault(x.config, rpc, o.vaultId);
    assert.notEqual(v.status, "UNKNOWN", JSON.stringify(v));
    assert.deepEqual(await wr.loadV7WalletRequest(x.config, o.S2), S2, `round ${round}: the same-effect duplicate is never relabelled or written`);
    assert.equal((await wr.loadV7WalletRequest(x.config, o.S1)).state, "CHAIN_VERIFIED");
    assert.equal((await fx.loadReceipt(x.config, o.txId)).proof.requestId, o.S1, `round ${round}: the receipt names the request that was actually submitted`);
    assert.equal(await fx.loadSubmissionClaim(x.config, o.txId), null, `round ${round}: the legacy claim is released`);
    assert.deepEqual(await wr.loadOrgRoot(x.config, o.rootCovenantId), root0); assert.deepEqual(await fx.loadManifestV7(x.config, o.vaultId), vault0);
  }
  assert.equal((await rec.reconcileVault(x.config, rpc, o.vaultId)).status, "CONSISTENT");
  const b = await ownerOp(x.config, o, "ownerPause");
  assert.equal(b.state, "AUTHORIZED");
  await wr.rejectOrgRootRequest({ config: x.config, requestId: b.id, reason: "test cleanup" });
  const withdrawn = await wr.markV7WalletRejected(x.config, o.S2);
  assert.equal(withdrawn.state, "WALLET_REJECTED"); assert.match(String(withdrawn.error), /same-effect duplicate/);
  assert.equal((await d.signedSpend(x.config, o)).state, "SIGNED");
  assert.equal(rpc.submits(), 0, "nothing was ever broadcast on legacy data");
});
