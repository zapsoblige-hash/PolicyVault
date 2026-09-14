"use strict";
const {test}=require('node:test');
const assert=require('node:assert/strict');
const core=require('../core-bundle');
const setupModule=require('../setup-ui');
const kasModule=require('../kas-vault-ui');
const rootModule=require('../org-root-ui');
const fixtures=require('../../core/explain/test/fixtures/v7-kas-manifests.json');
const G=fixtures.genesis, R=fixtures.manifests[0].manifest;
const clone=x=>JSON.parse(JSON.stringify(x));
const selectedRoot={rootCovenantId:R.root.covenantId,orgId:R.root.orgId,networkId:R.network.networkId,template:{...R.root.template,orgId:R.root.orgId},state:R.rootState.before.state};
// Expected pins come from the independently reviewed root rules, not the creation response.
const script=core.rootScriptV7.reconstructRootScriptHexV7({template:selectedRoot.template,state:selectedRoot.state});
const prefix=core.rootScriptV7.ROOT_SCRIPT_PREFIX_HEX_V7;
const stateLen=core.vaultStateV7Root.ROOT_STATE_LEN_V7;
const suffix=script.slice(prefix.length+stateLen*2);
const rootPins={orgRootCovenantId:selectedRoot.rootCovenantId,networkId:selectedRoot.networkId,rootPrefixLen:prefix.length/2,rootStateLen:stateLen,rootSuffixLen:suffix.length/2,rootTemplateVmHash:core.assets.blake2b.blake2bHex([Buffer.from(prefix,'hex'),Buffer.from(suffix,'hex')],32)};
const norm=()=>({protectedSompi:BigInt(G.summary.initialState.protectedValue),feeReserveSompi:BigInt(G.summary.initialState.feeReserve),agents:clone(G.summary.agents),agentRoot:G.summary.initialState.agentRoot,approvers:G.summary.initialState.approverSlots.filter(k=>k!=='00'.repeat(32)),approvalM:String(G.summary.initialState.approvalM),recoveryPk:G.summary.recoveryPk,rootPins:{...rootPins}});
function moduleAndCalls(getJSON=async()=>{throw Error('unused')}){
 const calls={adapter:0,posts:0};
 const api={getJSON,postJSON:async()=>{calls.posts++;return{}},resolveXOnly:async()=>{throw Error('unused')}};
 const setup=setupModule.createModule({core});const payload=rootModule.createModule({api,core,setup});
 return {km:kasModule.createModule({api,core,setup,payload}),calls};
}
function forgedRequest(change){
 const summary=clone(G.summary);change(summary);
 const safe=JSON.parse(G.unsignedSafeJson),frozen=JSON.parse(G.frozenCanonicalJson);
 const spk=core.vaultScriptV7Kas.reconstructVaultScriptSpkHexV7Kas({template:summary.template,state:summary.initialState});
 safe.outputs[0].scriptPublicKey='0000'+spk;frozen.outputs[0].scriptPublicKey={version:0,scriptHex:spk};
 // Signature-binding tests compare all frozen fields. The independent review probe additionally recomputes the consensus txid.
 return {requestId:'synthetic',kind:'kasGenesis',state:'BUILT',summary,transaction:{unsignedSafeJson:JSON.stringify(safe),frozenCanonicalJson:JSON.stringify(frozen),signInputs:G.signInputs}};
}
async function attempt(km,calls,request,reviewed,crossCheck){
 return km.signKasGenesisRequest({request,norm:reviewed,crossCheck,network:G.summary.networkId,connectedXOnly:G.funderXOnly,expectedSignerAddress:'synthetic-funder',adapter:{signInputs:async()=>{calls.adapter++;throw Object.assign(Error('adapter reached; no signature'),{code:'ADAPTER_REACHED'});}}});
}
test('KAS genesis honest control: selected-root pins match the compiler fixture and the wallet remains reachable',async()=>{
 const {km,calls}=moduleAndCalls();const n=norm();const req=forgedRequest(()=>{});
 for(const k of ['orgRootCovenantId','rootPrefixLen','rootStateLen','rootSuffixLen','rootTemplateVmHash'])assert.equal(rootPins[k],G.summary.template[k],k);
 const crossCheck=km.genesisCrossCheck({summary:req.summary,norm:n});assert.equal(crossCheck.ok,true);
 await assert.rejects(attempt(km,calls,req,n,crossCheck),e=>e.code==='ADAPTER_REACHED');assert.equal(calls.adapter,1);assert.equal(calls.posts,0);
});
for(const [name,change] of [
 ['owning root substitution',s=>{s.orgRootCovenantId=s.template.orgRootCovenantId='9b'.repeat(32)}],
 ['hidden template root substitution',s=>{s.template.orgRootCovenantId='9b'.repeat(32)}],
 ['root template hash substitution',s=>{s.template.rootTemplateVmHash='9c'.repeat(32)}],
 ['root geometry substitution',s=>{s.template.rootSuffixLen+=1000}]
])test('KAS genesis refuses consistent '+name+' before the external wallet',async()=>{
 const {km,calls}=moduleAndCalls();const n=norm();const req=forgedRequest(change);const crossCheck=km.genesisCrossCheck({summary:req.summary,norm:n});
 await assert.rejects(attempt(km,calls,req,n,crossCheck),e=>e.code==='REVIEW_REFUSED');assert.equal(calls.adapter,0);assert.equal(calls.posts,0);
});
test('KAS genesis rechecks current rules at signing; a cached positive review cannot authorize a changed recovery script',async()=>{
 const {km,calls}=moduleAndCalls();const n=norm();const cached=km.genesisCrossCheck({summary:G.summary,norm:n});assert.equal(cached.ok,true);
 const req=forgedRequest(s=>{s.recoveryPk=s.template.recoveryPk='9d'.repeat(32)});
 await assert.rejects(attempt(km,calls,req,n,cached),e=>e.code==='REVIEW_REFUSED');assert.equal(calls.adapter,0);
});
test('KAS genesis fails closed without a selected-root review',async()=>{
 const {km,calls}=moduleAndCalls();const n=norm();delete n.rootPins;
 await assert.rejects(attempt(km,calls,forgedRequest(()=>{}),n,{ok:true,mismatches:[]}),e=>e.code==='REVIEW_REFUSED');assert.equal(calls.adapter,0);
});
test('KAS selected-root pin derivation reconstructs the frozen root; it ignores server pin declarations',()=>{
 const {km}=moduleAndCalls();assert.deepEqual(km.kasRootPinsForReview({...selectedRoot,rootPins:{rootTemplateVmHash:'ff'.repeat(32)}}),rootPins);
 assert.throws(()=>km.kasRootPinsForReview({...selectedRoot,template:{}}));
 const pins=km.kasRootPinsForReview(selectedRoot);assert.ok(Object.isFrozen(pins));
});

for (const when of ['before-wallet', 'while-wallet-open', 'current']) {
 test(`KAS genesis signature upload is bound to the active review: ${when}`, async () => {
  const {km,calls}=moduleAndCalls();const n=norm();const request=forgedRequest(()=>{});
  const crossCheck=km.genesisCrossCheck({summary:request.summary,norm:n});
  let active=when!=='before-wallet';let release;const waiting=new Promise(resolve=>{release=resolve;});
  const pending=km.signKasGenesisRequest({request,norm:n,crossCheck,network:G.summary.networkId,connectedXOnly:G.funderXOnly,expectedSignerAddress:'synthetic-funder',isCurrent:()=>active,
   adapter:{signInputs:async()=>{calls.adapter++;await waiting;return 'synthetic-signature-upload-control';}}});
  if(when==='while-wallet-open') active=false;
  release();
  if(when==='current') {await pending;assert.equal(calls.posts,1);assert.equal(calls.adapter,1);}
  else {await assert.rejects(pending,e=>e.code==='REVIEW_INTERRUPTED');assert.equal(calls.posts,0);assert.equal(calls.adapter,when==='before-wallet'?0:1);}
 });
}

test('KAS request recovery refuses a status response for a different request identity',async()=>{
 const {km,calls}=moduleAndCalls(async()=>({request:{requestId:'another-request',kind:'kasGenesis',state:'SIGNED'}}));
 await assert.rejects(km.fetchKasRequest('original-request'),e=>e.code==='REQUEST_MISMATCH');
 assert.equal(calls.adapter,0);assert.equal(calls.posts,0);
});
