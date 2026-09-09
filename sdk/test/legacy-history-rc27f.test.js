"use strict";
const { test } = require("node:test"), assert = require("node:assert/strict");
const fs = require("node:fs"), path = require("node:path");
const source = process.env.POLICYVAULT_RC27F_SOURCE || path.resolve(__dirname, "../..");
const dep = (p) => require(path.join(source, p));
const d = dep("sdk/testutil/cp13e-delegate-fixture"), { fx } = d, wr = fx.wr7;
const evidence = path.resolve(__dirname, "../../docs/postlaunch/ux-evidence/codex-rc27f/fixtures");
async function fixture(name) {
  const saved = JSON.parse(fs.readFileSync(path.join(evidence, name + ".json")), (_k, v) => v?.$big ? BigInt(v.$big) : v);
  assert.equal(saved.producedBy, "df68a1fd64775948e799935759d08b549181100c");
  const config = fx.freshJsonConfig("pv-rc27f-legacy-"), store = fx.getStore(config);
  for (const [c, values] of Object.entries(saved.records)) for (const [k, v] of Object.entries(values)) await store.write(c, k, v);
  for (const e of saved.audit) await store.appendAudit(e);
  const rpc = fx.mockRpc(); for (const [a, entries] of Object.entries(saved.rpc)) for (const e of entries) rpc.seed(a, e);
  const o = { ...saved.ids, fuelKey: fx.KEY(config, 0x64), agentKey: fx.KEY(config, 0x62), owner1: fx.KEY(config, 0x71), owner2: fx.KEY(config, 0x72), recipientKey: fx.KEY(config, 0x63), rTree: dep("sdk/src/recipient-merkle-v3").buildRecipientTree([fx.XO(config, fx.KEY(config, 0x63))]) };
  return { config, saved, o, rpc };
}
for (const scenario of ["terminal-with-retained-token", "deposit-terminal-with-retained-token"]) for (const retainedClaim of [true, false]) test(`RC27F F-2/F-3: actual df68 ${scenario}, claims ${retainedClaim}, preserves history without claiming a token sweep`, async () => {
  const x = await fixture(scenario), { o, rpc } = x;
  if (!retainedClaim) for (const id of [o.spend, o.secondSpend, o.deposit].filter(Boolean)) {
    const q = await wr.loadV7WalletRequest(x.config, id);
    await fx.getStore(x.config).remove(fx.Categories.SUBMISSION_CLAIM, q.txId);
  }
  const root = await wr.loadOrgRoot(x.config, o.rootCovenantId), vault = await fx.loadManifestV7(x.config, o.vaultId);
  const terminal = await wr.loadOrgRootRequest(x.config, o.terminal);
  assert.equal(terminal.build.hasTokenInput, false); assert.equal(vault.status, "RECOVERED"); assert.equal(vault.live, null);
  const latest = await wr.loadV7WalletRequest(x.config, o.secondSpend ?? o.deposit), index = o.secondSpend ? 1 : 0, token = latest.build.frozen.outputs[index];
  const address = fx.spkAddress(x.config, token.scriptPublicKey);
  const before = await rpc.getUtxosByAddresses({ addresses: [address] });
  assert.ok(before.entries.some((e) => e.outpoint.transactionId === latest.txId && e.outpoint.index === index));
  for (const requestId of [o.spend, o.secondSpend, o.deposit].filter(Boolean)) {
    assert.equal((await wr.submitV7WalletRequest({ config: x.config, requestId, rpc })).state, "CHAIN_VERIFIED");
    x.config = fx.reloadJsonConfig(x.config);
  }
  await dep("sdk/src/reconcile-v7").reconcileOrgRootV7(x.config, o.rootCovenantId, { rpc });
  assert.deepEqual(await wr.loadOrgRoot(x.config, o.rootCovenantId), root);
  assert.deepEqual(await fx.loadManifestV7(x.config, o.vaultId), vault);
  assert.deepEqual(await rpc.getUtxosByAddresses({ addresses: [address] }), before);
  await fx.signedRootOnly(x.config, o);
  assert.equal(rpc.submits(), 0);
});
for (const mode of ["missing-receipt", "ambiguous-deposit"]) test(`RC27F F-2/F-3: legacy deposit-only terminal ${mode} refuses without downgrading completion`, async () => {
  const x = await fixture("deposit-terminal-with-retained-token"), { o, rpc } = x, store = fx.getStore(x.config);
  const q = await wr.loadV7WalletRequest(x.config, o.deposit), root = await wr.loadOrgRoot(x.config, o.rootCovenantId), vault = await fx.loadManifestV7(x.config, o.vaultId);
  if (mode === "missing-receipt") await store.remove(fx.Categories.RECEIPT, q.txId);
  else await wr.saveV7WalletRequest(x.config, { ...q, requestId: "11111111-1111-4111-8111-111111111111" });
  await assert.rejects(wr.submitV7WalletRequest({ config: x.config, requestId: o.deposit, rpc }), { code: "RECONCILIATION_REQUIRED" });
  assert.deepEqual(await wr.loadV7WalletRequest(x.config, o.deposit), q);
  assert.deepEqual(await wr.loadOrgRoot(x.config, o.rootCovenantId), root);
  assert.deepEqual(await fx.loadManifestV7(x.config, o.vaultId), vault); assert.equal(rpc.submits(), 0);
});
for (const scenario of ["latest-delegate", "interleaved-agents", "replaced-agent-and-recipients"]) {
  test(`RC27F F-2: actual df68 ${scenario} permits same-request recovery and valid future work`, async () => {
    const x = await fixture(scenario), { saved, o, rpc } = x;
    const beforeRoot = await wr.loadOrgRoot(x.config, o.rootCovenantId), beforeVault = await fx.loadManifestV7(x.config, o.vaultId);
    // Latest legacy requests must be recognized even before owner reconciliation.
    if (scenario === "latest-delegate") await d.signedSpend(x.config, o);
    const q = await wr.submitV7WalletRequest({ config: x.config, requestId: o.spend, rpc });
    assert.equal(q.state, "CHAIN_VERIFIED");
    x.config = fx.reloadJsonConfig(x.config);
    const rec = dep("sdk/src/reconcile-v7");
    await rec.reconcileOrgRootV7(x.config, o.rootCovenantId, { rpc });
    await rec.reconcileOrgRootV7(x.config, o.rootCovenantId, { rpc });
    for (const id of [o.first, o.change].filter(Boolean)) assert.equal((await wr.loadOrgRootRequest(x.config, id)).state, "CHAIN_VERIFIED");
    assert.deepEqual(await wr.loadOrgRoot(x.config, o.rootCovenantId), beforeRoot, "legacy verification must not pin or rewrite old root history");
    assert.deepEqual(await fx.loadManifestV7(x.config, o.vaultId), beforeVault, "no rollback of later registry, token or owner state");
    assert.equal(rpc.submits(), 0);
    if (scenario === "replaced-agent-and-recipients") {
      o.agentKey = fx.KEY(x.config, 0x66); o.recipientKey = fx.KEY(x.config, 0x67);
      o.rTree = dep("sdk/src/recipient-merkle-v3").buildRecipientTree([fx.XO(x.config, o.recipientKey)]);
    }
    await d.signedSpend(x.config, o);
    assert.ok(Object.values(saved.records[fx.Categories.RECEIPT]).every((r) => !r.proof?.requestId), "phase A never manufactured modern receipt pointers");
  });
}
