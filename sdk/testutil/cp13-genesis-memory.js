"use strict";
// Actual JSON driver and wallet request/reconcile modules, with durable IO and RPC stubbed.
module.exports = function memoryGenesis(){

const fs=require("node:fs"),vm=require("node:vm"),path=require("node:path"),WT=path.resolve(__dirname,"../.."),H=b=>b.repeat(32),pure=n=>require(WT+"/core/model/"+n);
const actualFs=fs; let realpathMode="actual", realpathCalls=0;const safeFs={realpathSync:{native:p=>{if(realpathMode==="appearing"){realpathCalls++;if(realpathCalls===1){const e=Error("not created");e.code="ENOENT";throw e;}return p.replace("/var/run/","/run/");}return actualFs.realpathSync.native(p)}}};
const cfg={dataRoot:"/memory/store",networkId:"testnet-10",persistenceBackend:"json"},id="12345678-1234-4234-8234-123456789abc";
const state=pure("vault-state-v4").stateToJsonV4(pure("vault-state-v4").normalizeStateV4({protectedValue:"100",feeReserve:"10",paused:"0",agentRoot:H("00"),policyNonce:"0",approvers:[],approvalM:"0"}));
const initial={requestId:id,kind:"genesis",schema:"policyvault-wallet-request/v4",state:"SUBMITTED",networkId:"testnet-10",txId:H("11"),vaultId:H("22"),covenantId:H("33"),vaultOutputIndex:0,template:{owner:H("44")},initialState:state,initialRegistry:[],contractVersion:"policyvault-0.4.1",submittedAt:new Date(Date.now()-600000).toISOString(),transaction:{unsignedSafeJson:JSON.stringify({inputs:[{transactionId:H("55"),index:0}]})}};
let durable,manifest,queries,loadCalls,failLoad,manifestReady;let releaseManifest;
let WR;const memory=new Map(),manifests=new Map();const rootKey=c=>c.persistenceBackend==="postgres"?"/memory/pg/"+c.pg.database:path.resolve(c.dataRoot);
const m4={loadManifestV4:async c=>structuredClone(manifests.get(rootKey(c))??null),persistManifestV4:async(c,m)=>{manifest={...structuredClone(m),agentRegistryRoot:m.live.state.agentRoot};manifests.set(rootKey(c),manifest);releaseManifest();}};
const deps={"fs":safeFs,"path":path,"node:crypto":require("node:crypto"),"./vault-state-v4":pure("vault-state-v4"),"./contract-compiler-v4":{compileExactStateV4:()=>({scriptBytes:Buffer.from("00","hex")})},"./chain":{covenantAddress:()=> "vault",getAddressUtxos:async(rpc,a)=>rpc.query(a),connectVerified:async()=>{throw Error("NETWORK_FORBIDDEN")}},"./manifest-v4":m4,"./agent-merkle-v4":pure("agent-merkle-v4"),"./recipient-merkle-v3":pure("recipient-merkle-v3"),"./submission-claim":{releaseSubmissionClaim:async()=>{throw Error("UNEXPECTED_RELEASE")},persistReceipt:async()=>{}},"./audit":{appendAudit:async()=>{}},"./manifest":{VaultStatus:{ACTIVE:"ACTIVE"}},"./wallet-requests-v4":WR,"./budget-reservation":{},"./config":{assertOperationalNetwork:()=>{}},"./tx-identity":{}};
function sourceFor(file){const baseline=process.env.PV_CP13_BASELINE;if(baseline&&["wallet-submit-v4.js","store.js"].includes(file))return require("node:child_process").execFileSync("git",["show",baseline+":sdk/src/"+file],{cwd:WT,encoding:"utf8"});return fs.readFileSync(WT+"/sdk/src/"+file,"utf8");}
function load(){let module={exports:{}};vm.runInNewContext(sourceFor("wallet-submit-v4.js"),{module,exports:module.exports,require:n=>{if(Object.hasOwn(deps,n))return deps[n];throw Error("UNSTUBBED:"+n)},Buffer,process:{env:{}},console},{filename:"wallet-submit-v4.js"});return module.exports}
safeFs.existsSync=p=>memory.has(p);
function loadAux(file,imports){const module={exports:{}};vm.compileFunction(sourceFor(file),["module","exports","require"],{filename:file})(module,module.exports,n=>{if(Object.hasOwn(imports,n))return imports[n];throw Error("UNSTUBBED_AUX:"+n)});return module.exports;}
const actualStore=loadAux("store.js",{"fs":safeFs,"path":path,"./durable-json":{readJsonStrict:p=>{loadCalls++;if(failLoad){failLoad=false;throw Error("STUB_READ_FAILURE")}return structuredClone(memory.get(p)??null);},persistJsonDurably:({filePath,value})=>memory.set(filePath,structuredClone(value))}});
const actualStoreFacade={...actualStore,getStore:c=>actualStore.getStore({...c,persistenceBackend:"json",dataRoot:rootKey(c)})};
const wrImports={...deps,"fs":safeFs,"path":path,"os":{},"crypto":require("node:crypto"),"child_process":{spawnSync:()=>{throw Error("SPAWN_FORBIDDEN")}},"./store":actualStoreFacade,"./build-cache":{},"../../core/model/own-get":pure("own-get"),"./vault-builders-v4":{},"./frozen-tx-v3":{},"./approval-package-v4":{},"./address-identity":{},"./amounts":pure("amounts"),"./vm-preflight":{}};
WR=loadAux("wallet-requests-v4.js",wrImports);deps["./wallet-requests-v4"]=WR;deps["./store"]=actualStoreFacade;let mod=load();
function reset(configs=[cfg]){memory.clear();manifests.clear();for(const c of configs)memory.set(path.join(rootKey(c),"requests",id+".json"),structuredClone(initial));durable=structuredClone(initial);manifest=null;queries=0;loadCalls=0;failLoad=false;manifestReady=new Promise(r=>releaseManifest=r)}
const rpc={query:async()=>{queries++;if(queries===1){await new Promise(r=>setImmediate(r));return [{outpoint:{transactionId:initial.txId,index:0},amount:110n,covenantId:initial.covenantId}]}await manifestReady;await new Promise(r=>setImmediate(r));throw Error("STUB_RPC_UNAVAILABLE")}};
return {cfg,id,reset,rpc,WR,mod,actualStore,safeFs,manifests,rootKey,
loads:()=>loadCalls,queries:()=>queries,failRead:()=>{failLoad=true},
setRealpathMode:v=>{realpathMode=v;realpathCalls=0}};
};

