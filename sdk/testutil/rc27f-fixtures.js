"use strict";
const path = require("node:path"), assert = require("node:assert/strict");
const source = process.env.POLICYVAULT_RC27F_SOURCE || path.resolve(__dirname, "../..");
const dep = (p) => require(path.join(source, p));
const d = dep("sdk/testutil/cp13e-delegate-fixture"), { fx } = d, wr = fx.wr7;
async function depositBase() {
  const config = fx.freshJsonConfig("pv-rc27f-deposit-base-"), rpc = fx.mockRpc(), o = await fx.organization(config, rpc);
  const depositor = fx.KEY(config, 0x91);
  const state = { ownerIdentifier: fx.XO(config, depositor), identifierType: 0, amount: 100000n, isMinter: false };
  const program = dep("sdk/src/token-program-kcc20").compileKcc20Program({ config, state, familyBound: 2 });
  const params = { userPosition: { outpoint: { transactionId: fx.H(0x92), index: 0 }, value: fx.KAS.toString(), scriptPublicKeyHex: program.p2shSpkHex, covenantId: o.descriptor.tokenCovenantId, state }, depositAmount: "100000", depositCarryKasSompi: fx.KAS.toString(), fuel: fx.fuelUtxoFor(config, o.fuelKey) };
  const make = () => wr.buildV7WalletRequest({ config, vaultId: o.vaultId, action: "tokenDeposit", signerAddress: fx.ADDR(config, depositor), params });
  const q = await make(), prebuilt = await make();
  const signed = fx.signAll(config, q.transaction.unsignedSafeJson, [[0, depositor], [1, o.fuelKey]]);
  const finalized = await wr.finalizeV7WalletRequest({ config, requestId: q.requestId, signedSafeJson: signed });
  return { config, o, q: finalized, prebuilt, signed, params, depositor, before: fx.manifestToJsonV7(await fx.loadManifestV7(config, o.vaultId)), root: await wr.loadOrgRoot(config, o.rootCovenantId) };
}
function depositCase(base, config = fx.cloneJsonConfig(base.config, "pv-rc27f-deposit-")) {
  const x = d.caseFor(base, config);
  x.build = () => wr.buildV7WalletRequest({ config: x.config, vaultId: x.o.vaultId, action: "tokenDeposit", signerAddress: fx.ADDR(x.config, x.depositor), params: x.params });
  return x;
}
async function assertDepositComplete(x, broadcasts = 1) {
  const q = await x.request(), v = await x.vault();
  assert.equal(q.state, "CHAIN_VERIFIED", q.error);
  assert.equal(v.generation, x.before.generation + 1);
  assert.deepEqual(v.live.outpoint, x.before.live.outpoint);
  assert.equal(v.live.stateId, x.before.live.stateId);
  assert.equal(v.live.tokenPosition.state.amount, "100000");
  assert.deepEqual(v.live.tokenPosition.outpoint, { transactionId: q.txId, index: 0 });
  assert.equal(v.latestTransitionTxId, q.txId);
  assert.equal(await fx.loadSubmissionClaim(x.config, q.txId), null);
  assert.equal((await fx.loadReceipt(x.config, q.txId)).proof.requestId, q.requestId);
  assert.equal((await fx.auditLinesFor(x.config, q.txId)).length, 1);
  assert.deepEqual(await wr.loadOrgRoot(x.config, x.o.rootCovenantId), x.root);
  assert.equal(x.rpc.submits(), broadcasts);
}
module.exports = { dep, fx, d, wr, depositBase, depositCase, assertDepositComplete };
