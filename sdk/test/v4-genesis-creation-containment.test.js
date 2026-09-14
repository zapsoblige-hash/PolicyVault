"use strict";
const {test}=require('node:test');const assert=require('node:assert/strict');const fs=require('node:fs');const os=require('node:os');const path=require('node:path');
const {getStore,Categories}=require('../src/store');
const {loadConfig}=require('../src/config');const wr4=require('../src/wallet-requests-v4');const {submitCreateWalletRequestV4}=require('../src/wallet-submit-v4');const {createHarness}=require('./helpers/v7-kas-mock-harness');
test('creation containment refuses a pre-switch v0.4.1 genesis before claims, request mutation or broadcast',async()=>{
 const beforeFlag=process.env.POLICYVAULT_ALLOW_MAINNET;process.env.POLICYVAULT_ALLOW_MAINNET='true';
 const dataRoot=fs.mkdtempSync(path.join(os.tmpdir(),'pv-v4-creation-containment-'));
 try{
  const config=loadConfig({networkId:'mainnet',allowMainnet:true,rpcUrl:'ws://127.0.0.1:1',dataRoot});const H=createHarness(config);const owner=H.KEY(0x21);
  const args={config,contractVersion:'policyvault-0.4.1',templateInput:{owner:H.XO(owner),vaultId:'42'.repeat(32)},initialAgents:[],initialState:{protectedValue:'1000000000',feeReserve:'100000000',approvers:[],approvalM:'0'},signerAddress:H.ADDR(owner),funding:[H.fuelUtxoFor(owner,500000000000n)]};
  const request=await wr4.buildCreateWalletRequestV4(args);const before=await wr4.loadRequest(config,request.requestId);
  const off=loadConfig({...config,mainnetCreationDisabled:['policyvault-0.4.1']});
  await assert.rejects(wr4.buildCreateWalletRequestV4({...args,config:off}),e=>e.code==='GENERATION_NOT_MAINNET_AUTHORIZED');
  const signed=H.signAll(request.transaction.unsignedSafeJson,request.transaction.signInputs.map(s=>[s.index,owner]));let calls=0;
  const rpc={submitTransaction:async({transaction})=>{calls++;return{transactionId:transaction.finalize().toString()}},getUtxosByAddresses:async()=>({entries:[]}),getBlockDagInfo:async()=>({sink:'aa'.repeat(32)})};
  await assert.rejects(submitCreateWalletRequestV4({config:off,requestId:request.requestId,signedSafeJson:signed,rpc,pollAttempts:1,pollDelayMs:0}),e=>e.code==='GENERATION_NOT_MAINNET_AUTHORIZED');
  assert.equal(calls,0);assert.deepEqual(await wr4.loadRequest(off,request.requestId),before,'disabled submit preserves the exact unsigned request');
  // Removing containment restores the unchanged submit path; the mock cannot establish chain settlement.
  assert.equal(await getStore(off).read(Categories.SUBMISSION_CLAIM,request.build.txId),null,'disabled submit creates no submission claim');
  await assert.rejects(submitCreateWalletRequestV4({config,requestId:request.requestId,signedSafeJson:signed,rpc,pollAttempts:1,pollDelayMs:0}),e=>e.code==='RECONCILIATION_REQUIRED');
  assert.equal(calls,1);assert.equal((await wr4.loadRequest(config,request.requestId)).state,'RECONCILIATION_REQUIRED');
 }finally{if(beforeFlag===undefined)delete process.env.POLICYVAULT_ALLOW_MAINNET;else process.env.POLICYVAULT_ALLOW_MAINNET=beforeFlag;}
});
