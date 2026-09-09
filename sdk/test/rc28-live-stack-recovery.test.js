"use strict";
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

// RC28 live-stack follow-up: public submission must obey the same legacy
// completion ownership rule as discovery, reconciliation and withdrawal.
test("R8-09 direct submission of the never-attempted legacy duplicate cannot claim its sibling's completed effect", async () => {
  const x=await fixture("delegate-dup-signed-twice"),{config,o,rpc}=x;
  const s2=await wr.loadV7WalletRequest(config,o.S2);
  const root=await wr.loadOrgRoot(config,o.rootCovenantId),vault=await fx.loadManifestV7(config,o.vaultId);
  const result=await codeOf(()=>wr.submitV7WalletRequest({config,requestId:o.S2,rpc}));
  assert.equal(result.ok,false,"never-attempted sibling must be refused, not relabelled CHAIN_VERIFIED");
  assert.equal(result.code,"RECONCILIATION_REQUIRED");
  assert.deepEqual(await wr.loadV7WalletRequest(config,o.S2),s2,"refusal preserves the duplicate");
  assert.deepEqual(await wr.loadOrgRoot(config,o.rootCovenantId),root);
  assert.deepEqual(await fx.loadManifestV7(config,o.vaultId),vault);
  await rec.reconcileVault(config,rpc,o.vaultId);
  assert.equal((await fx.loadReceipt(config,o.txId)).proof.requestId,o.S1);
  assert.equal((await wr.loadV7WalletRequest(config,o.S1)).state,"CHAIN_VERIFIED");
  const owner=await ownerOp(config,o,"ownerPause");assert.equal(owner.state,"AUTHORIZED");
  await wr.rejectOrgRootRequest({config,requestId:owner.id,reason:"isolated regression control"});
  assert.equal((await wr.markV7WalletRejected(config,o.S2)).state,"WALLET_REJECTED");
  assert.equal((await d.signedSpend(config,o)).state,"SIGNED");
  assert.equal(rpc.submits(),0);
});

test("R8-09 direct submit of the actually completed legacy request remains recoverable before reconcile", async () => {
  const x=await fixture("delegate-dup-signed-twice"),{config,o,rpc}=x;
  const sibling=await wr.loadV7WalletRequest(config,o.S2);
  const again=await wr.submitV7WalletRequest({config,requestId:o.S1,rpc});
  assert.equal(again.state,"CHAIN_VERIFIED");
  assert.equal((await fx.loadReceipt(config,o.txId)).proof.requestId,o.S1);
  assert.deepEqual(await wr.loadV7WalletRequest(config,o.S2),sibling);
  const owner=await ownerOp(config,o,"ownerPause");assert.equal(owner.state,"AUTHORIZED");
  await wr.rejectOrgRootRequest({config,requestId:owner.id,reason:"isolated regression control"});
  assert.equal(rpc.submits(),0);
});

const {outcomeRpc}=dep("sdk/testutil/rc27f-outcome-fixture");
for(const selected of ["S1","S2"]) test(`R8-10: unchanged legacy prebroadcast pair recovers the same selected ${selected} through aged public submission observations`, async()=>{
 const x=await fixture("delegate-dup-prebroadcast"),{config,o,rpc}=x;
 const q=await wr.loadV7WalletRequest(config,o[selected]);x.q=q;
 const siblingId=o[selected==="S1"?"S2":"S1"],sibling=await wr.loadV7WalletRequest(config,siblingId);
 const root=await wr.loadOrgRoot(config,o.rootCovenantId),vault=await fx.loadManifestV7(config,o.vaultId);
 const originalClaim=await fx.loadSubmissionClaim(config,q.txId);assert.ok(originalClaim && originalClaim.expected == null,"actual legacy claim has no request pointer");
 const {hashes}=outcomeRpc(x);let advanced=false,broadcasts=0;rpc.getBlockDagInfo=async()=>({sink:hashes[advanced?1:0]});
 rpc.submitTransaction=async()=>{broadcasts++;throw Error("no broadcast allowed by this legacy recovery probe");};
 const first=await codeOf(()=>wr.submitV7WalletRequest({config,requestId:q.requestId,rpc}));assert.equal(first.ok,false);
 const uncertain=await wr.loadV7WalletRequest(config,q.requestId);assert.equal(uncertain.state,"RECONCILIATION_REQUIRED");assert.equal(uncertain.reconcileStartHash,hashes[0]);assert.ok(await fx.loadSubmissionClaim(config,q.txId));
 advanced=true;const clock=Date.now;Date.now=()=>Date.parse(uncertain.outcomeObservationAt)+120001;let resolved;
 try{resolved=await wr.submitV7WalletRequest({config,requestId:q.requestId,rpc});}finally{Date.now=clock;}
 assert.equal(resolved.state,"NOT_BROADCAST");assert.equal(resolved.submissionOutcome.proof.completeAcceptanceWindow,true);
 assert.equal(await fx.loadSubmissionClaim(config,q.txId),null);assert.equal(await fx.loadReceipt(config,q.txId),null);
 assert.deepEqual(await wr.loadV7WalletRequest(config,siblingId),sibling);
 assert.deepEqual(await wr.loadOrgRoot(config,o.rootCovenantId),root);assert.deepEqual(await fx.loadManifestV7(config,o.vaultId),vault);
 await rec.reconcileOrgRootV7(config,o.rootCovenantId,{rpc});
 const owner=await ownerOp(config,o,"ownerPause");assert.equal(owner.state,"AUTHORIZED");
 await wr.rejectOrgRootRequest({config,requestId:owner.id,reason:"isolated legacy recovery control"});
 assert.equal(broadcasts,0);
 // Labels and incomplete settlement do not authorize a sibling retry.
 for(const defect of ["fingerprint","missing-proof","settlement-pending"]){
  const bad=structuredClone(resolved);
  if(defect==="fingerprint")bad.submissionOutcome.requestFingerprint="f".repeat(64);
  if(defect==="missing-proof")delete bad.submissionOutcome;
  if(defect==="settlement-pending")bad.state="RECONCILIATION_REQUIRED";
  await fx.getStore(config).write(fx.Categories.REQUEST,q.requestId,bad);
  await assert.rejects(wr.submitV7WalletRequest({config,requestId:siblingId,rpc}),e=>e.code==="RECONCILIATION_REQUIRED");
  assert.deepEqual(await wr.loadV7WalletRequest(config,siblingId),sibling);assert.equal(broadcasts,0);
  if(defect==="settlement-pending")assert.equal((await wr.submitV7WalletRequest({config,requestId:q.requestId,rpc})).state,"NOT_BROADCAST");
  await fx.getStore(config).write(fx.Categories.REQUEST,q.requestId,resolved);
 }
 // A genuinely settled negative does not reserve its sibling's later positive effect.
 rpc.submitTransaction=async()=>{broadcasts++;d.settle(config,rpc,sibling);return {transactionId:sibling.txId};};
 const retry=await wr.submitV7WalletRequest({config,requestId:siblingId,rpc,pollAttempts:1,pollDelayMs:0});
 assert.equal(retry.state,"CHAIN_VERIFIED");assert.equal(broadcasts,1);
 assert.equal((await fx.loadReceipt(config,q.txId)).proof.requestId,siblingId);
 assert.deepEqual(await wr.loadV7WalletRequest(config,q.requestId),resolved);
 assert.equal((await wr.submitV7WalletRequest({config,requestId:siblingId,rpc})).state,"CHAIN_VERIFIED");
 assert.equal((await wr.submitV7WalletRequest({config,requestId:q.requestId,rpc})).state,"NOT_BROADCAST");
 assert.equal(broadcasts,1);assert.equal((await d.signedSpend(config,o)).state,"SIGNED");
});


test("R8-09 already affected completed pair preserves its existing bound effect representative",async()=>{
 const {config,o,rpc}=await fixture("delegate-dup-both-completed-rc28");
 const store=fx.getStore(config),before=await store.read(fx.Categories.RECEIPT,o.txId);
 const requests=await Promise.all([o.S1,o.S2].map(id=>wr.loadV7WalletRequest(config,id)));
 for(let n=0;n<2;n++){
  await rec.reconcileOrgRootV7(config,o.rootCovenantId,{rpc});await rec.reconcileVault(config,rpc,o.vaultId);
  for(const id of [o.S1,o.S2])assert.equal((await wr.submitV7WalletRequest({config,requestId:id,rpc})).state,"CHAIN_VERIFIED");
  assert.deepEqual(await store.read(fx.Categories.RECEIPT,o.txId),before,"recovery cannot switch the already-bound representative");
  assert.deepEqual(await Promise.all([o.S1,o.S2].map(id=>wr.loadV7WalletRequest(config,id))),requests);
 }
 const owner=await ownerOp(config,o,"ownerPause");assert.equal(owner.state,"AUTHORIZED");
 await wr.rejectOrgRootRequest({config,requestId:owner.id,reason:"isolated completed-pair control"});
 const later=await d.signedSpend(config,o);d.settle(config,rpc,later);
 const fault=fx.inject(config,"write",(c,k)=>c===fx.Categories.RECEIPT&&k===later.txId);
 try{await assert.rejects(wr.submitV7WalletRequest({config,requestId:later.requestId,rpc}),e=>e.code==="RECONCILIATION_REQUIRED");}finally{fault.restore();}
 await rec.reconcileVault(config,rpc,o.vaultId);assert.equal((await wr.loadV7WalletRequest(config,later.requestId)).state,"CHAIN_VERIFIED");
 for(const id of [o.S1,o.S2])assert.equal((await wr.submitV7WalletRequest({config,requestId:id,rpc})).state,"CHAIN_VERIFIED");
 assert.deepEqual(await store.read(fx.Categories.RECEIPT,o.txId),before);
 assert.deepEqual(await Promise.all([o.S1,o.S2].map(id=>wr.loadV7WalletRequest(config,id))),requests);
 const next=await ownerOp(config,o,"ownerPause");assert.equal(next.state,"AUTHORIZED");
 await wr.rejectOrgRootRequest({config,requestId:next.id,reason:"isolated later-history control"});
 assert.equal((await d.signedSpend(config,o)).state,"SIGNED");assert.equal(rpc.submits(),1);
});

for(const defect of ["missing-receipt","wrong-fingerprint","changed-funding","missing-audit","retained-claim"])test(`R8-09 affected pair refuses ${defect} without choosing a new representative`,async()=>{
 const {config,o,rpc}=await fixture("delegate-dup-both-completed-rc28"),store=fx.getStore(config);
 const receipt=await fx.loadReceipt(config,o.txId),aliasId=receipt.proof.requestId===o.S1?o.S2:o.S1;
 const alias=await wr.loadV7WalletRequest(config,aliasId);
 if(defect==="missing-receipt")await store.remove(fx.Categories.RECEIPT,o.txId);
 if(defect==="wrong-fingerprint"){receipt.proof.requestFingerprint="f".repeat(64);await store.write(fx.Categories.RECEIPT,o.txId,receipt);}
 if(defect==="changed-funding"){alias.build.frozen.inputs.at(-1).utxo.amount="999";await store.write(fx.Categories.REQUEST,aliasId,alias);}
 if(defect==="retained-claim")await store.write(fx.Categories.SUBMISSION_CLAIM,o.txId,{txId:o.txId,vaultId:o.vaultId,action:alias.action,expected:wr.completionReceiptPointer(alias)});
 const readAudit=store.readAudit?.bind(store);
 if(defect==="missing-audit")store.readAudit=async()=>[];
 const before=await store.read(fx.Categories.RECEIPT,o.txId),q=await wr.loadV7WalletRequest(config,aliasId);
 try{const r=await codeOf(()=>wr.submitV7WalletRequest({config,requestId:aliasId,rpc}));assert.equal(r.ok,false);assert.equal(r.code,"RECONCILIATION_REQUIRED");}
 finally{if(readAudit)store.readAudit=readAudit;}
 assert.deepEqual(await store.read(fx.Categories.RECEIPT,o.txId),before);assert.deepEqual(await wr.loadV7WalletRequest(config,aliasId),q);assert.equal(rpc.submits(),0);
});
for(const defect of ["early","mempool-present","mempool-unknown","incomplete-window"])test(`R8-10 uncertainty retains original claims: ${defect}`,async()=>{
 const x=await fixture("delegate-dup-prebroadcast"),{config,o,rpc}=x;
 x.q=await wr.loadV7WalletRequest(config,o.S1);const {hashes}=outcomeRpc(x);let advanced=false;
 rpc.getBlockDagInfo=async()=>({sink:hashes[advanced?1:0]});let broadcasts=0;rpc.submitTransaction=async()=>{broadcasts++;throw Error("forbidden probe broadcast");};
 await assert.rejects(wr.submitV7WalletRequest({config,requestId:o.S1,rpc}));
 const pending=await wr.loadV7WalletRequest(config,o.S1),claim=await fx.loadSubmissionClaim(config,o.txId);advanced=true;
 if(defect==="mempool-present")rpc.getMempoolEntry=async()=>({entry:{transaction:{verboseData:{transactionId:o.txId}}}});
 if(defect==="mempool-unknown")rpc.getMempoolEntry=async()=>{throw Error("unknown RPC method");};
 if(defect==="incomplete-window")rpc.getVirtualChainFromBlock=async()=>({removedChainBlockHashes:[],addedChainBlockHashes:[hashes[1]],acceptedTransactionIds:[]});
 const clock=Date.now;Date.now=()=>Date.parse(pending.outcomeObservationAt)+(defect==="early"?1:120001);
 try{await assert.rejects(wr.submitV7WalletRequest({config,requestId:o.S1,rpc}));}finally{Date.now=clock;}
 assert.equal((await wr.loadV7WalletRequest(config,o.S1)).state,"RECONCILIATION_REQUIRED");
 assert.deepEqual(await fx.loadSubmissionClaim(config,o.txId),claim);assert.equal(await fx.loadReceipt(config,o.txId),null);assert.equal(broadcasts,0);
});
