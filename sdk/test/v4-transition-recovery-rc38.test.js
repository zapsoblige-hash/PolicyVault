"use strict";
/* Real signed v041 transition builds and VM verification; only node observations
 * are mocked. JSON reloads and fresh PostgreSQL pools exercise the ordinary
 * persistence APIs, including failures AFTER each durable completion boundary.
 * No production credentials, database, wallet, or chain endpoint is used. */
const { test, before, after } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs"), os = require("node:os"), path = require("node:path");
const fx = require("../testutil/v4-transition-recovery-fixture");
const { openPgStore } = require("../src/store");
const { canonicalRecordFingerprint } = require("../src/wallet-recovery-v4");
const { makeDevSigner } = require("../src/signer-dev");
const { Categories, wr4, submit4, clone, getStore, transitionClaimKey } = fx;
const TOOLCHAIN = require("../testutil/org-root-durable-fixture").toolchainAvailable();
const PG = { host: process.env.POLICYVAULT_TEST_PG_HOST || "127.0.0.1", port: Number(process.env.POLICYVAULT_TEST_PG_PORT || 0), user: process.env.POLICYVAULT_TEST_PG_USER, database: process.env.POLICYVAULT_TEST_PG_DATABASE };
const PG_AVAILABLE = Boolean(PG.port && PG.user && PG.database);
const skip = TOOLCHAIN ? undefined : "REQUIREMENT_NOT_AVAILABLE: real compiler and VM";
const pgSkip = skip || (PG_AVAILABLE ? undefined : "set POLICYVAULT_TEST_PG_{PORT,USER,DATABASE}");
const bases = {}, roots = [], stores = [], databases = [];
let admin, serial = 0;
before(async () => {
  if (!TOOLCHAIN) return;
  for (const action of ["agentSpend", "ownerRecover"]) bases[action] = await fx.baseFixture(action);
  if (PG_AVAILABLE) admin = new (require("pg").Pool)(PG);
});
after(async () => {
  for (const s of stores) await s.close();
  if (admin) {
    for (const db of databases) await admin.query(`DROP DATABASE IF EXISTS ${db} WITH (FORCE)`);
    await admin.end();
  }
  for (const base of Object.values(bases)) base.cleanup();
  for (const root of roots) fs.rmSync(root, {recursive:true,force:true});
});
async function jsonCase(base) {
  const x = await fx.jsonCase(base); roots.push(x.config.dataRoot);
  x.reopen = async () => { x.config = fx.loadConfig({dataRoot:x.config.dataRoot}); };
  return x;
}
async function pgCase(base) {
  const db = `pv_rc38_v4_${process.pid}_${++serial}`;
  await admin.query(`CREATE DATABASE ${db}`); databases.push(db);
  const root = fs.mkdtempSync(path.join(os.tmpdir(),"pv-rc38-v4-pg-")); roots.push(root);
  const configFor = () => fx.loadConfig({ persistenceBackend:"postgres", pgHost:PG.host, pgPort:PG.port, pgUser:PG.user, pgDatabase:db, pgNoTls:true, authMode:"enabled", authCookieInsecure:true, dataRoot:root });
  const config = configFor(); stores.push(await openPgStore(config,{migrate:true}));
  await fx.install(config,base.snapshot);
  const x = fx.caseFor(base,config);
  x.reopen = async () => { x.config=configFor(); stores.push(await openPgStore(x.config)); };
  x.assertSql = async () => {
    const pool=x.store().pool(), q=base.request, args=[x.config.networkId,q.txId];
    assert.equal((await pool.query("SELECT key FROM receipts WHERE network_id=$1 AND key=$2",args)).rowCount,1);
    assert.equal((await pool.query("SELECT key FROM submission_claims WHERE network_id=$1 AND key=$2",args)).rowCount,0);
    assert.equal((await pool.query("SELECT key FROM transition_claims WHERE network_id=$1 AND key=$2",[x.config.networkId,transitionClaimKey(q.predecessorOutpoint)])).rowCount,0);
    const audit=await pool.query("SELECT value FROM audit_events WHERE network_id=$1 AND tx_id=$2",args);
    assert.equal(audit.rows.filter(r=>r.value.result==="CHAIN_VERIFIED").length,1);
  };
  return x;
}
async function assertIdempotent(x,base) {
  const before=await fx.snapshot(x.config), reads=x.reads();
  x.empty();
  assert.equal((await x.recover()).outcome,"CHAIN_VERIFIED");
  assert.deepEqual(await fx.snapshot(x.config),before,"completed replay performs no persistence writes");
  assert.equal(x.reads(),reads,"durable completion needs no new observation");
  await fx.assertComplete(x,base);
  if (x.assertSql) await x.assertSql();
}
for (const [backend,create,skipped] of [["JSON",jsonCase,skip],["PostgreSQL",pgCase,pgSkip]]) {
  for (const action of ["agentSpend","ownerRecover"]) {
    test(`RC38 transition ${backend} ${action}: legacy rejection remains protected after reload and generic reconcile`,{skip:skipped},async()=>{
      const base=bases[action],x=await create(base);
      const raw=await fx.snapshot(x.config);
      assert.equal((await x.generic()).status,"REQUEST_RECOVERY_REQUIRED");
      assert.deepEqual(await fx.snapshot(x.config),raw,"generic recovery does not mutate historical evidence");
      const fingerprint=canonicalRecordFingerprint(await x.request());
      assert.equal((await x.recover({expectedFingerprint:fingerprint})).outcome,"PROTECTED_UNRESOLVED");
      await fx.assertProtected(x,base);
      const retained=await fx.snapshot(x.config);
      await x.reopen(); x.empty();
      assert.equal((await x.recover()).outcome,"PROTECTED_UNRESOLVED");
      assert.equal((await x.generic()).status,"REQUEST_RECOVERY_REQUIRED");
      assert.deepEqual(await fx.snapshot(x.config),retained);
      assert.equal((await x.request()).error,base.request.error,"original known-node answer retained");
      await fx.assertProtected(x,base);
    });
    test(`RC38 transition ${backend} ${action}: exact original observed effect completes once`,{skip:skipped},async()=>{
      const base=bases[action],x=await create(base); x.settle();
      assert.equal((await x.recover()).outcome,"CHAIN_VERIFIED");
      await fx.assertComplete(x,base); await x.reopen(); await assertIdempotent(x,base);
    });
    for (const boundary of ["manifest","receipt","audit","claim","request"]) {
      test(`RC38 transition ${backend} ${action}: restart after ${boundary} write resumes bookkeeping once`,{skip:skipped},async()=>{
        const base=bases[action],x=await create(base); x.settle();
        const fault=fx.injectAfter(x.config,boundary);
        await assert.rejects(x.recover(),new RegExp(`TEST interruption after ${boundary}`));
        assert.equal(fault.hit(),true,"actual persistence boundary executed"); fault.restore();
        const interrupted=await x.request();
        assert.equal(interrupted.transitionRecovery.phase,boundary==="request"?"COMPLETE":"EFFECT_PROVEN");
        assert.equal(interrupted.state,boundary==="request"?"CHAIN_VERIFIED":"RECONCILIATION_REQUIRED");
        if(boundary!=="request") assert.equal((await x.generic()).status,"REQUEST_RECOVERY_REQUIRED");
        const reads=x.reads(); await x.reopen(); x.empty();
        assert.equal((await x.recover()).outcome,"CHAIN_VERIFIED");
        assert.equal(x.reads(),reads,"saved exact effect proof permits bookkeeping after output is spent");
        await fx.assertComplete(x,base); await assertIdempotent(x,base);
      });
    }
  }
}
test("RC38 transition: changed selected fingerprint refuses before observations or writes",{skip},async()=>{
  const x=await jsonCase(bases.agentSpend),before=await fx.snapshot(x.config);
  await assert.rejects(x.recover({expectedFingerprint:"00".repeat(32)}),{code:"REQUEST_FINGERPRINT_MISMATCH"});
  assert.deepEqual(await fx.snapshot(x.config),before); assert.equal(x.reads(),0); assert.equal(x.submits(),0);
});
for (const field of ["signature","frozen","signed-output"]) test(`RC38 transition: tampered ${field} cannot authorize completion`,{skip},async()=>{
  const x=await jsonCase(bases.agentSpend),r=await x.request();
  if(field==="signature") r.finalTransaction.inputs[0].signatureScript="00";
  else if(field==="frozen") r.build.frozen.outputs[0].value=(BigInt(r.build.frozen.outputs[0].value)+1n).toString();
  else r.finalTransaction.outputs[0].value=(BigInt(r.finalTransaction.outputs[0].value)+1n).toString();
  await wr4.saveRequest(x.config,r); const before=await fx.snapshot(x.config); x.settle();
  await assert.rejects(x.recover());
  assert.deepEqual(await fx.snapshot(x.config),before); assert.equal(x.reads(),0); assert.equal(x.submits(),0);
});
test("RC38 transition: missing retained signature stays protected despite positive output observation",{skip},async()=>{
  const base=bases.agentSpend,x=await jsonCase(base),r=await x.request();delete r.finalTransaction;
  await wr4.saveRequest(x.config,r);x.settle();
  assert.equal((await x.recover()).outcome,"PROTECTED_UNRESOLVED");
  assert.equal((await x.request()).finalTransaction,undefined);assert.deepEqual(await x.manifest(),base.before);
  assert.equal(await x.store().read(Categories.RECEIPT,r.txId),null);assert.equal(x.reads(),0);assert.equal(x.submits(),0);
  assert.ok(await x.store().read(Categories.TRANSITION_CLAIM,transitionClaimKey(r.predecessorOutpoint)));
});
for (const collision of ["submission","transition","same-tx-foreign-request","receipt","budget"]) test(`RC38 transition: foreign ${collision} record remains unchanged`,{skip},async()=>{
  const base=bases.agentSpend,x=await jsonCase(base),q=base.request;
  if(collision==="receipt") await x.store().write(Categories.RECEIPT,q.txId,{schema:"policyvault-receipt/v1",txId:q.txId,vaultId:"ff".repeat(32),action:q.action});
  else if(collision==="budget") await x.store().write(Categories.TRANSITION_CLAIM,base.budgetKey,{...clone(base.originalReservation),amountSompi:"1"});
  else if(collision==="transition") await x.store().write(Categories.TRANSITION_CLAIM,transitionClaimKey(q.predecessorOutpoint),{schema:"policyvault-transition-claim/v1",outpoint:q.predecessorOutpoint,txId:"ee".repeat(32),vaultId:q.vaultId,action:q.action});
  else await x.store().write(Categories.SUBMISSION_CLAIM,q.txId,{schema:"policyvault-submission-claim/v1",txId:q.txId,vaultId:collision==="submission"?"ff".repeat(32):q.vaultId,action:q.action,...(collision==="same-tx-foreign-request"?{requestId:"foreign-request"}:{})});
  const before=await fx.snapshot(x.config);x.settle();
  await assert.rejects(x.recover(),{code:collision==="receipt"?"RECEIPT_CONFLICT":"CLAIM_CONFLICT"});
  assert.deepEqual(await fx.snapshot(x.config),before);assert.equal(x.reads(),0);assert.equal(x.submits(),0);
});
test("RC38 transition: exact original budget reservation is removed only after durable completion",{skip},async()=>{
  const base=bases.agentSpend,x=await jsonCase(base);
  assert.ok(base.originalReservation);
  await x.store().write(Categories.TRANSITION_CLAIM,base.budgetKey,clone(base.originalReservation));
  assert.equal((await x.recover()).outcome,"PROTECTED_UNRESOLVED");
  assert.deepEqual(await x.store().read(Categories.TRANSITION_CLAIM,base.budgetKey),base.originalReservation);
  x.settle();assert.equal((await x.recover()).outcome,"CHAIN_VERIFIED");
  assert.equal(await x.store().read(Categories.TRANSITION_CLAIM,base.budgetKey),null);await assertIdempotent(x,base);
});
test("RC38 transition: exact advanced manifest and own receipt resume an old premature terminal request without double spend accounting",{skip},async()=>{
  const base=bases.agentSpend,x=await jsonCase(base);x.settle();await x.recover();
  const advanced=await x.manifest(),r=await x.request();delete r.transitionRecovery;
  await wr4.saveRequest(x.config,r);x.empty();
  assert.equal((await x.recover()).outcome,"CHAIN_VERIFIED");assert.deepEqual(await x.manifest(),advanced);await assertIdempotent(x,base);
});
test("RC38 transition: later current manifest is preserved while original attempt remains protected",{skip},async()=>{
  const base=bases.agentSpend,x=await jsonCase(base);x.settle();await x.recover();
  const later=await x.manifest();later.live.outpoint={transactionId:"99".repeat(32),index:0};later.latestTransitionTxId="99".repeat(32);
  await x.store().write(Categories.VAULT,base.request.vaultId,later);
  await wr4.saveRequest(x.config,clone(base.request));x.empty();
  assert.equal((await x.recover()).outcome,"PROTECTED_UNRESOLVED");assert.deepEqual(await x.manifest(),later);
  assert.equal((await x.request()).state,"RECONCILIATION_REQUIRED");assert.equal(x.submits(),0);
});
test("RC38 transition: protected historical request blocks ordinary build and finalize before state mutation",{skip},async()=>{
  const base=bases.agentSpend,x=await jsonCase(base),before=await fx.snapshot(x.config);
  await assert.rejects(wr4.buildWalletRequestV4({...base.pendingBuild,config:x.config}),{code:"REQUEST_RECOVERY_REQUIRED"});
  const q=base.prebuilt;
  const signed=makeDevSigner(x.config,{secretHex:base.owner.secretHex,expectedAddress:base.owner.address}).signInputs(q.transaction.unsignedSafeJson,q.transaction.signInputs);
  await assert.rejects(wr4.finalizeWalletRequestV4({config:x.config,requestId:q.requestId,signedSafeJson:signed}),{code:"REQUEST_RECOVERY_REQUIRED"});
  assert.deepEqual(await fx.snapshot(x.config),before);assert.equal(x.submits(),0);
});
test("RC38 transition: protected historical request blocks another already-signed ordinary submission",{skip},async()=>{
  const base=bases.agentSpend,x=await jsonCase(base),q=base.prebuilt;
  // Build the alternate retained signed request in isolation, as it could have
  // existed under the earlier runtime before the missing-claim guard repair.
  await x.store().remove(Categories.REQUEST,base.request.requestId);
  const signed=makeDevSigner(x.config,{secretHex:base.owner.secretHex,expectedAddress:base.owner.address}).signInputs(q.transaction.unsignedSafeJson,q.transaction.signInputs);
  assert.equal((await wr4.finalizeWalletRequestV4({config:x.config,requestId:q.requestId,signedSafeJson:signed})).state,"PREFLIGHT_VERIFIED");
  await wr4.saveRequest(x.config,clone(base.request));const before=await fx.snapshot(x.config);
  await assert.rejects(submit4.submitWalletRequestV4({config:x.config,requestId:q.requestId,rpc:x.rpc,pollAttempts:1,pollDelayMs:0}),{code:"REQUEST_RECOVERY_REQUIRED"});
  assert.deepEqual(await fx.snapshot(x.config),before);assert.equal(x.submits(),0);
});
for (const altered of ["phase","lifecycle","binding","claim-fingerprint"]) test(`RC38 transition: malformed saved journal ${altered} refuses without further writes`,{skip},async()=>{
  const base=bases.agentSpend,x=await jsonCase(base);await x.recover();const r=await x.request();
  if(altered==="phase")r.transitionRecovery.phase="UNRECOGNIZED";
  else if(altered==="lifecycle")r.state="CHAIN_VERIFIED";
  else if(altered==="binding")r.transitionRecovery.requestBinding="00".repeat(32);
  else r.transitionRecovery.claimFingerprints=["not-a-fingerprint",null];
  await wr4.saveRequest(x.config,r);const before=await fx.snapshot(x.config);x.settle();const reads=x.reads();
  assert.equal((await x.generic()).status,"REQUEST_RECOVERY_REQUIRED");
  await assert.rejects(x.recover(),{code:"TRANSITION_RECOVERY_REFUSED"});
  assert.deepEqual(await fx.snapshot(x.config),before);assert.equal(x.reads(),reads);assert.equal(x.submits(),0);
});
for (const observed of ["predecessor-also-present","wrong-amount","wrong-script","wrong-version","missing-version","missing-script"]) test(`RC38 transition: inconclusive ${observed} observation preserves original manifest and protection`,{skip},async()=>{
  const base=bases.agentSpend,x=await jsonCase(base);x.settle({retainFunding:observed==="predecessor-also-present"});
  if(observed!=="predecessor-also-present"){
    const get=x.rpc.getUtxosByAddresses;
    x.rpc.getUtxosByAddresses=async args=>{
      const response=await get(args);
      for(const entry of response.entries)if(entry.outpoint.transactionId===base.request.txId){
        if(observed==="wrong-amount")entry.amount=(BigInt(entry.amount)+1n).toString();
        else if(observed==="wrong-script") entry.scriptPublicKey={version:0,script:`20${base.owner.xonly}ac`};
        else if(observed==="wrong-version") entry.scriptPublicKey.version=1;
        else if(observed==="missing-version") delete entry.scriptPublicKey.version;
        else delete entry.scriptPublicKey;
      }
      return response;
    };
  }
  assert.equal((await x.recover()).outcome,"PROTECTED_UNRESOLVED");await fx.assertProtected(x,base);
});
test("RC38 transition: genuine mainnet-encoded fixture can protect and observe while new creation is disabled",{skip},async()=>{
  // Explicit, temporary TEST configuration. All RPC methods remain the local
  // in-memory node fixture; the configured loopback discard endpoint is unused.
  const old=process.env.POLICYVAULT_ALLOW_MAINNET;let config;
  try{
    process.env.POLICYVAULT_ALLOW_MAINNET="true";
    config=fx.freshConfig({networkId:"mainnet",allowMainnet:true,rpcUrl:"ws://127.0.0.1:1",mainnetCreationDisabled:"policyvault-0.4.1"});
  }finally{if(old===undefined)delete process.env.POLICYVAULT_ALLOW_MAINNET;else process.env.POLICYVAULT_ALLOW_MAINNET=old;}
  roots.push(config.dataRoot);
  assert.equal(require("../src/config").isGenerationMainnetCreatable(config,"policyvault-0.4.1"),false);
  const base=await fx.baseFixture("agentSpend",config),x=fx.caseFor(base,config);
  assert.equal(base.request.networkId,"mainnet");assert.match(base.agent.address,/^kaspa:/);
  assert.equal((await x.recover()).outcome,"PROTECTED_UNRESOLVED");await fx.assertProtected(x,base);
  x.settle();assert.equal((await x.recover()).outcome,"CHAIN_VERIFIED");await assertIdempotent(x,base);
});
for (const [backend,create,skipped] of [["JSON",jsonCase,skip],["PostgreSQL",pgCase,pgSkip]]) {
  for (const boundary of ["protection-journal","first-restored-claim"]) test(`RC38 transition ${backend}: interrupted ${boundary} still blocks admission and restores missing claims`,{skip:skipped},async()=>{
    const base=bases.agentSpend,x=await create(base),store=x.store();
    const method=boundary==="protection-journal"?"write":"createExclusive",original=store[method].bind(store);let hit=false;
    store[method]=async(...args)=>{
      const matches=!hit&&(boundary==="protection-journal"?args[0]===Categories.REQUEST&&args[2]?.transitionRecovery?.phase==="PROTECTED":args[0]===Categories.TRANSITION_CLAIM&&args[1]===transitionClaimKey(base.request.predecessorOutpoint));
      const result=await original(...args);
      if(matches){hit=true;throw Error(`TEST interruption after ${boundary}`);}
      return result;
    };
    await assert.rejects(x.recover(),new RegExp(`TEST interruption after ${boundary}`));assert.equal(hit,true);store[method]=original;
    assert.equal((await x.request()).transitionRecovery.phase,"PROTECTED");
    assert.equal(await store.read(Categories.SUBMISSION_CLAIM,base.request.txId),null);
    assert.equal(Boolean(await store.read(Categories.TRANSITION_CLAIM,transitionClaimKey(base.request.predecessorOutpoint))),boundary==="first-restored-claim");
    const interrupted=await fx.snapshot(x.config);
    await x.reopen();assert.equal((await x.generic()).status,"REQUEST_RECOVERY_REQUIRED");
    await assert.rejects(wr4.buildWalletRequestV4({...base.pendingBuild,config:x.config}),{code:"REQUEST_RECOVERY_REQUIRED"});
    assert.deepEqual(await fx.snapshot(x.config),interrupted,"admission never clears incomplete protection");
    assert.equal((await x.recover()).outcome,"PROTECTED_UNRESOLVED");await fx.assertProtected(x,base);
    x.settle();assert.equal((await x.recover()).outcome,"CHAIN_VERIFIED");await assertIdempotent(x,base);
  });
  test(`RC38 transition ${backend}: concurrent same-request recovery serializes one completion in the supported process`,{skip:skipped},async()=>{
    const base=bases.agentSpend,x=await create(base);x.settle();
    const results=await Promise.all([x.recover(),x.recover()]);
    assert.deepEqual(results.map(r=>r.outcome),["CHAIN_VERIFIED","CHAIN_VERIFIED"]);
    await assertIdempotent(x,base);
  });
}
for (const entry of ["submit","finalize"]) test(`RC38 transition: marked same-request ${entry} cannot bypass protection by relabeling lifecycle`,{skip},async()=>{
  const base=bases.agentSpend,x=await jsonCase(base);await x.recover();const q=await x.request();
  q.state=entry==="submit"?"PREFLIGHT_VERIFIED":"BUILT";await wr4.saveRequest(x.config,q);
  const before=await fx.snapshot(x.config);
  if(entry==="submit")await assert.rejects(submit4.submitWalletRequestV4({config:x.config,requestId:q.requestId,rpc:x.rpc,pollAttempts:1,pollDelayMs:0}),{code:"REQUEST_RECOVERY_REQUIRED"});
  else{
    const signed=makeDevSigner(x.config,{secretHex:base.agent.secretHex,expectedAddress:base.agent.address}).signInputs(q.transaction.unsignedSafeJson,q.transaction.signInputs);
    await assert.rejects(wr4.finalizeWalletRequestV4({config:x.config,requestId:q.requestId,signedSafeJson:signed}),{code:"REQUEST_RECOVERY_REQUIRED"});
  }
  assert.deepEqual(await fx.snapshot(x.config),before);assert.equal(x.submits(),0);
});
test("RC38 transition: bare historical NOT_BROADCAST label does not bypass protection or authorize rejection",{skip},async()=>{
  const base=bases.agentSpend,x=await jsonCase(base),q=await x.request();q.state="NOT_BROADCAST";
  await wr4.saveRequest(x.config,q);const original=await fx.snapshot(x.config);
  assert.equal((await x.generic()).status,"REQUEST_RECOVERY_REQUIRED");
  await assert.rejects(wr4.buildWalletRequestV4({...base.pendingBuild,config:x.config}),{code:"REQUEST_RECOVERY_REQUIRED"});
  assert.deepEqual(await fx.snapshot(x.config),original);
  assert.equal((await x.recover()).outcome,"PROTECTED_UNRESOLVED");await fx.assertProtected(x,base);
  x.settle();assert.equal((await x.recover()).outcome,"CHAIN_VERIFIED");await assertIdempotent(x,base);
});
