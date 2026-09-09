"use strict";
const {test}=require('node:test'),assert=require('node:assert/strict');
const {createClient,PolicyVaultNetworkError}=require('../src/http-client');
test('LS-05 response-body failure preserves the original generated retry key without retrying',async()=>{
 let attempts=0,key;const cause=Error('stub connection lost after response headers');
 const client=createClient({baseUrl:'https://example.invalid',fetchImpl:async(_url,init)=>{attempts++;key=init.headers['Idempotency-Key'];return {ok:true,status:200,text:async()=>{throw cause;}};}});
 await assert.rejects(client.request('POST','/organizations',{body:{name:'stub'}}),e=>e instanceof PolicyVaultNetworkError&&e.cause===cause&&e.idempotencyKey===key&&typeof key==='string');
 assert.equal(attempts,1);
});
test('LS-05 malformed successful JSON preserves uncertainty/key; HTTP errors retain their status and key',async()=>{
 for(const status of [200,502]){
  let calls=0,key;const client=createClient({baseUrl:'https://example.invalid',fetchImpl:async(_url,init)=>{calls++;key=init.headers['Idempotency-Key'];return {ok:status===200,status,text:async()=>'{truncated'};}});
  await assert.rejects(client.request('POST','/organizations',{body:{name:'stub'}}),e=>e.idempotencyKey===key&&(status===200?e instanceof PolicyVaultNetworkError:e.status===502));
  assert.equal(calls,1);
 }
});
