"use strict";
// Fast production-module probes: persistence, RPC, compilation and broadcast are in-memory stubs.
// No real compiler, service, wallet or filesystem mutation is performed by this fixture.
module.exports = function memoryRoot() {

const fs=require("node:fs"),vm=require("node:vm"),path=require("node:path");
const WT=path.resolve(__dirname,"../.."),clone=structuredClone,H=b=>b.repeat(32),cfg={dataRoot:"memory",networkId:"testnet-10"};
const fix=JSON.parse(fs.readFileSync(WT+"/core/explain/test/fixtures/v7-org-root-manifests.json","utf8")).manifests.find(x=>x.name==="vault_set_agent_root_under_authorize");
const m=fix.manifest,op=m.vaultOperations[0].manifest,fr=JSON.parse(m.transaction.frozenCanonicalJson),rootId=m.root.covenantId,vid=op.vault.vaultId,vc=op.vault.covenantId,txid=m.transaction.txId;
const pure=name=>require(WT+"/core/model/"+name);
// Explicit byte-to-identity fixtures: a different modeled transaction must be
// registered separately, so changed bytes cannot inherit the first txid.
const { normalizeFrozenTxV3, canonicalFrozenTxJson } = pure("frozen-tx-v3");
const transactionKey = tx => canonicalFrozenTxJson(normalizeFrozenTxV3({ ...tx, inputs: tx.inputs.map(({ signatureScript, ...input }) => input) }));
const transactionIds = new Map();
function registerTransaction(tx, id) { transactionIds.set(transactionKey(tx), id); }
registerTransaction(fr, txid);
const Categories={ORG_ROOT:"roots",ORG_ROOT_REQUEST:"requests",VAULT:"vaults",REQUEST:"walletRequests",RECEIPT:"receipts",SUBMISSION_CLAIM:"subClaims",TRANSITION_CLAIM:"transitionClaims"};
let db,claims,landed,writeFailure,events,audits,fault=null,auditBarrier=null;
const key=(cat,id)=>cat+":"+id,okey=o=>o.transactionId+":"+o.index;
function failStage(stage) {if(fault===stage)throw Error("STUB_PERSISTENT_"+stage);}
const store={
read:async(c,id)=>clone(db.get(key(c,id))??null),
write:async(c,id,x)=>{ const stage=c==="roots"?(x.pendingRequestId==null?"pointerClear":"rootWrite"):c==="requests"?(x.state==="CHAIN_VERIFIED"?"finalRequest":x.state==="RECONCILIATION_REQUIRED"?"diagnostic":"requestWrite"):c==="vaults"?"vaultWrite":c==="receipts"?"receipt":c;failStage(stage);events.push("write:"+stage);db.set(key(c,id),clone(x));},
createExclusive:async(c,id,x)=>{if(db.has(key(c,id)))return false;db.set(key(c,id),clone(x));return true;},
remove:async(c,id)=>{const stage=c==="subClaims"?"submissionRelease":id===m.root.outpoint.transactionId+"-"+m.root.outpoint.index?"rootRelease":"vaultRelease";failStage(stage);events.push("remove:"+stage);return db.delete(key(c,id));},
listValues:async(c)=>[...db].filter(([k])=>k.startsWith(c+":")).map(([,v])=>clone(v)),
appendAudit:async e=>{failStage("audit");events.push("audit");audits.push(clone(e));},
readAudit:async({vaultId,txId,limit})=>{const snapshot=clone(audits.filter(e=>(!vaultId||e.vaultId===vaultId)&&(!txId||e.txId===txId)).slice(-limit));if(auditBarrier)await auditBarrier();return snapshot;}
};
const stat={ACTIVE:"ACTIVE",PAUSED:"PAUSED",RECOVERED:"RECOVERED",PENDING_CREATE:"PENDING_CREATE"};
const address=spk=>"spk:"+spk.script;
const chain={connectVerified:async()=>{throw Error("NETWORK_FORBIDDEN")},getAddressUtxos:async(rpc,addr)=>rpc.query(addr),loadKaspa:()=>({addressFromScriptPublicKey:spk=>({toString:()=>address(spk)})}),covenantAddress:()=> db?.get(key("vaults",vid))?.live?.outpoint?.transactionId===txid?"spk:"+fr.outputs.find(o=>o.covenant?.covenantId===vc).scriptPublicKey.scriptHex:"vault-pre"};
const claimModule={};
let manifestModule,wr;
const shared={"path":path,"fs":{},"os":{},"crypto":require("node:crypto"),"./store":{getStore:()=>store,Categories},"./org-root-lock":require(WT+"/sdk/src/org-root-lock"),"./config":{assertOperationalNetwork:()=>{},assertGenerationMainnetCreatable:()=>{}},"./amounts":pure("amounts"),"./vault-state":pure("vault-state"),"./agent-merkle-v5":pure("agent-merkle-v5"),"./recipient-merkle-v3":pure("recipient-merkle-v3"),"./chain":chain,"./manifest":{VaultStatus:stat,TERMINAL_STATUSES:new Set(["RECOVERED"])},"./address-identity":{addressForXOnlyPubkey:(c,x)=>x},"./submission-claim":claimModule,"./audit":{},"./contract-compiler-v7":{compileExactStateV7:({state})=>({scriptSha256:state.agentRoot===op.stateAfter.state.agentRoot?H("bb"):H("aa"),scriptHex:"11"})},"./build-cache":{},"./vm-preflight":{},"./frozen-tx-v3":{},"./approval-package-v4":{},"./vault-builders-v7":{},"./wallet-submit-v4":{finalTxToWasm:()=>({finalize:()=>txid}),isDefinitiveSubmitRejection:()=>false}};
function sourceFor(file){const baseline=process.env.PV_CP13_BASELINE;if(baseline&&["wallet-requests-v7.js","reconcile-v7.js"].includes(file))return require("node:child_process").execFileSync("git",["show",baseline+":sdk/src/"+file],{cwd:WT,encoding:"utf8"});return fs.readFileSync(WT+"/sdk/src/"+file,"utf8");}
function load(file){let module={exports:{}};const req=n=>{if(n==="./manifest-v7")return manifestModule;if(n==="./wallet-requests-v7")return wr;if(n.startsWith("../../core/"))return require(path.resolve(WT+"/sdk/src",n));if(Object.hasOwn(shared,n))return shared[n];throw Error("UNSTUBBED_IMPORT:"+n)};vm.compileFunction(sourceFor(file),["module","exports","require","Buffer","process","setTimeout","clearTimeout","console"],{filename:file})(module,module.exports,req,Buffer,{env:{}},(cb)=>queueMicrotask(cb),()=>{},console);return module.exports;}
shared["./wallet-submit-v4"].finalTxToWasm = (_config, tx) => ({ finalize: () => { const id = transactionIds.get(transactionKey(tx)); if (!id) throw Error("UNREGISTERED_STUB_TRANSACTION"); return id; } });
shared["./tx-identity"]={transactionIdOfRpcBody:()=>{throw Error("STUB_IDENTITY_UNAVAILABLE")},blockHashOfRpcHeader:()=>{throw Error("STUB_IDENTITY_UNAVAILABLE")}};shared["./submission-outcome-v7"]=load("submission-outcome-v7.js");Object.assign(claimModule,load("submission-claim.js"));Object.assign(shared["./audit"],load("audit.js"));manifestModule=load("manifest-v7.js");wr=load("wallet-requests-v7.js");const rec=load("reconcile-v7.js");
const v=op.vault,template={vaultId:vid,descriptorHash:v.descriptorHash,tokenCovenantId:v.tokenCovenantId,templateVmHash:v.templateVmHashBlake2b256,templatePrefixLen:v.templateGeometry.prefixLen,templateStateLen:v.templateGeometry.stateLen,templateSuffixLen:v.templateGeometry.suffixLen,orgRootCovenantId:rootId,rootTemplateVmHash:v.rootTemplateVmHash,rootPrefixLen:v.rootGeometry.prefixLen,rootStateLen:v.rootGeometry.stateLen,rootSuffixLen:v.rootGeometry.suffixLen,recoveryPk:v.recoveryPk};
const newRegistry=op.policy.agentSet.map(p=>({...p,recipients:p.recipients || [H("63")]})),oldRegistry=[{...newRegistry[0],tokenMaxPerSpend:"250"}];
const doc={manifestVersion:manifestModule.MANIFEST_SCHEMA_V7,contractVersion:v.contractVersion,networkId:cfg.networkId,template,orgRootCovenantId:rootId,asset:{descriptor:fix.descriptors[vc],templateIndex:0},agentRegistry:oldRegistry,status:"ACTIVE",live:{state:op.stateBefore.state,stateId:op.stateBefore.stateId,outpoint:op.stateBefore.outpoint,outpointValue:op.stateBefore.state.feeReserve,scriptSha256:H("aa"),covenantId:vc,tokenPosition:null},generation:0};
const root={rootCovenantId:rootId,networkId:cfg.networkId,live:{outpoint:m.root.outpoint,address:"root-pre",value:m.root.valueBefore},state:m.rootState.before.state,vaults:[vid],generation:0,pendingRequestId:"memory-request"};
const req={id:"memory-request",kind:"rootAction",state:"SIGNED",action:"authorize",rootCovenantId:rootId,txId:txid,manifest:m,finalTransaction:fr,build:{kind:"transition",predecessorOutpoint:clone(op.stateBefore.outpoint),frozen:fr,successorState:op.stateAfter.state,successorScriptSha256:H("bb"),covenantId:vc},vaultOperations:[{vaultId:vid,action:"ownerSetAgentRoot",predecessor:{outpoint:clone(op.stateBefore.outpoint),generation:0}}],newRegistry};
const rpc={query:async addr=>{if(!landed)return [];return fr.outputs.flatMap((o,index)=>addr==="spk:"+o.scriptPublicKey.scriptHex?[{outpoint:{transactionId:txid,index},amount:BigInt(o.value),covenantId:o.covenant?.covenantId}]:[])},submitTransaction:async()=>{events.push("STUB_SUBMIT");return{transactionId:txid}}};
async function reset(){db=new Map();claims=new Map();audits=[];fault=null;auditBarrier=null;landed=true;events=[];await manifestModule.persistManifestV7(cfg,doc);await wr.saveOrgRoot(cfg,clone(root));let q=clone(req);q.state="RECONCILIATION_REQUIRED";await wr.saveOrgRootRequest(cfg,q);for(const outpoint of [m.root.outpoint,op.stateBefore.outpoint])await claimModule.claimTransition(cfg,{outpoint,txId:txid,vaultId:vid,action:"authorize",expected:{kind:"orgRootRequest",requestId:req.id}});await claimModule.claimSubmission(cfg,{txId:txid,vaultId:rootId,action:"authorize"});events=[];}
function reload(){db=new Map(JSON.parse(JSON.stringify([...db])));audits=JSON.parse(JSON.stringify(audits));}
async function invoke(which){try {let r=which==="submit"?await wr.submitOrgRootRequest({config:{...cfg},requestId:req.id,rpc}):await rec.reconcileOrgRootV7({...cfg},rootId,{rpc,allowClaimRelease:false});return {result:which==="submit"?r.state:r.root?.status};}catch(e){return {error:e.code||e.message};}}
async function status(){const r=await wr.loadOrgRoot(cfg,rootId),q=await wr.loadOrgRootRequest(cfg,req.id),v=await manifestModule.loadManifestV7(cfg,vid);let verification;try{verification=await wr.verifyRootActionCompletion(cfg,q)}catch(e){verification={error:e.code||e.message}}return {requestState:q.state,rootGeneration:r.generation,vaultGeneration:v.generation,pending:r.pendingRequestId,registryUpdated:v.live.state.agentRoot===op.stateAfter.state.agentRoot,oldRootClaim:!!await claimModule.loadTransitionClaim(cfg,m.root.outpoint),oldVaultClaim:!!await claimModule.loadTransitionClaim(cfg,op.stateBefore.outpoint),submissionClaim:!!await store.read(Categories.SUBMISSION_CLAIM,txid),auditCount:audits.length,complete:verification.complete,missing:verification.missing,classification:verification.vault?.position,events};}
return {reset,reload,invoke,status,rpc,wr,rec,cfg,req,root,doc,m,op,fr,rootId,vid,txid,clone,H,newRegistry,oldRegistry,store,Categories,key,manifestModule,claimModule,registerTransaction,
setFault:v=>{fault=v},setLanded:v=>{landed=v},getEvents:()=>events,getAudits:()=>audits,
readRequest:()=>wr.loadOrgRootRequest(cfg,req.id),readRoot:()=>wr.loadOrgRoot(cfg,rootId),readVault:()=>manifestModule.loadManifestV7(cfg,vid)};
};
