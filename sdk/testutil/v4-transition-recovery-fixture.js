"use strict";
// Deterministic TEST wallets, actual v041 encoder/VM/signature pipeline, mocked
// node only. Every JSON root and PostgreSQL database is owned by its test.
const assert = require("node:assert/strict");
const fs = require("node:fs"), os = require("node:os"), path = require("node:path");
const { loadConfig } = require("../src/config");
const { getStore, Categories } = require("../src/store");
const wr4 = require("../src/wallet-requests-v4");
const submit4 = require("../src/wallet-submit-v4");
const vs4 = require("../src/vault-state-v4");
const { persistManifestV4, loadManifestV4 } = require("../src/manifest-v4");
const { compileExactStateV4 } = require("../src/contract-compiler-v4");
const { buildAgentTreeV4, normalizeAgentPolicyV4 } = require("../src/agent-merkle-v4");
const { buildRecipientTree } = require("../src/recipient-merkle-v3");
const { makeDevSigner } = require("../src/signer-dev");
const { transitionClaimKey } = require("../src/submission-claim");
const KAS = 100000000n, ANCHOR = "31".repeat(32), VAULT = "a8".repeat(32);
const clone = (value) => JSON.parse(JSON.stringify(value));
const CATEGORIES = [Categories.VAULT, Categories.REQUEST, Categories.SUBMISSION_CLAIM, Categories.TRANSITION_CLAIM, Categories.RECEIPT];
const freshConfig = (overrides = {}) => loadConfig({ ...overrides, dataRoot: fs.mkdtempSync(path.join(os.tmpdir(), "pv-rc38-v4-transition-")) });
function wallet(config, byte) {
  const kaspa = require(config.rustyKaspaModule), secretHex = byte.toString(16).padStart(2,"0").repeat(32), priv = new kaspa.PrivateKey(secretHex);
  return { secretHex, priv, xonly: priv.toPublicKey().toXOnlyPublicKey().toString().toLowerCase(), address: priv.toPublicKey().toAddress(config.networkId).toString() };
}
function localNode(config, request) {
  const table = new Map(); let submits = 0, reads = 0;
  const kaspa = require(config.rustyKaspaModule);
  const address = (script) => kaspa.addressFromScriptPublicKey({ version: script.version, script: script.scriptHex }, config.networkId).toString();
  function seed(address, outpoint, amount, script, covenantId = null) {
    table.set(address, [...(table.get(address) ?? []), { address, outpoint: clone(outpoint), amount: String(amount), scriptPublicKey: { version: script.version, script: script.scriptHex }, covenantId, blockDaaScore: "1", isCoinbase: false }]);
  }
  function funding() {
    table.clear();
    request.finalTransaction.inputs.forEach((i,index) => seed(address(i.utxo.scriptPublicKey), i.previousOutpoint, i.utxo.amount, i.utxo.scriptPublicKey, index===0 ? request.covenantId : i.utxo.covenantId ?? null));
  }
  function settle({retainFunding = false} = {}) {
    if (retainFunding) funding(); else table.clear();
    request.finalTransaction.outputs.forEach((o,index) => seed(address(o.scriptPublicKey), { transactionId: request.txId, index }, o.value, o.scriptPublicKey, o.covenant?.covenantId ?? null));
  }
  const rpc = {
    async getUtxosByAddresses({ addresses }) { reads++; return { entries: addresses.flatMap((a) => clone(table.get(a) ?? [])) }; },
    async getBlockDagInfo() { reads++; return { sink: ANCHOR }; },
    async getMempoolEntry() { reads++; throw Error("TEST unavailable mempool history"); },
    async getVirtualChainFromBlock() { reads++; throw Error("TEST unavailable historical acceptance"); },
    async submitTransaction({ transaction }) {
      submits++;
      assert.equal(transaction.finalize().toString().toLowerCase(), request.txId);
      const stored = await wr4.loadRequest(config,request.requestId);
      assert.equal(stored.state,"SUBMITTING"); assert.equal(stored.submitStartHash,ANCHOR);
      assert.deepEqual(stored.finalTransaction,request.finalTransaction);
      throw Error("TEST connection lost after signed transition submission");
    },
    async disconnect() {}
  };
  funding();
  return { rpc, funding, settle, empty: () => table.clear(), submits: () => submits, reads: () => reads };
}
async function snapshot(config) {
  const store=getStore(config), data={};
  for(const category of CATEGORIES) data[category]=await Promise.all((await store.listKeys(category)).map(async key=>[key,await store.read(category,key)]));
  return { records:data, audit:await store.readAudit({limit:1000}) };
}
async function install(config, snap) {
  const store=getStore(config);
  for(const [category,entries] of Object.entries(snap.records)) for(const [key,value] of entries) await store.write(category,key,clone(value));
  for(const row of [...snap.audit].reverse()) await store.appendAudit(clone(row));
}
// The production development signer deliberately refuses mainnet. For the one
// wholly synthetic mainnet-encoded fixture, sign the frozen dummy transaction
// directly with its deterministic TEST key. The in-memory node never connects
// to an endpoint; this helper is not exported as a wallet adapter.
function signFixtureInputs(config, signer, request) {
  if (config.networkId !== "mainnet") return makeDevSigner(config,{secretHex:signer.secretHex,expectedAddress:signer.address}).signInputs(request.transaction.unsignedSafeJson,request.transaction.signInputs);
  assert.equal(config.rpcUrl,"ws://127.0.0.1:1");
  const kaspa=require(config.rustyKaspaModule),tx=kaspa.Transaction.deserializeFromSafeJSON(request.transaction.unsignedSafeJson);
  for(const entry of request.transaction.signInputs){
    const index=Number(entry.index??entry), inputs=tx.inputs;
    inputs[index].signatureScript=kaspa.createInputSignature(tx,index,signer.priv);tx.inputs=inputs;
  }
  return tx.serializeToSafeJSON();
}
async function baseFixture(action="agentSpend", suppliedConfig) {
  const config=suppliedConfig || freshConfig(), owner=wallet(config,0x11), agent=wallet(config,0x21), recipient=wallet(config,0x31);
  const entry={agentPk:agent.xonly,maxPerSpend:(20n*KAS).toString(),periodBudget:(50n*KAS).toString(),periodLengthDaa:"864000",periodStartDaa:"541000000",periodSpent:"0",approvalThreshold:(5n*KAS).toString(),agentMaxFeePerTx:KAS.toString(),recipients:[recipient.xonly]};
  const template={owner:owner.xonly,vaultId:VAULT};
  const policy=normalizeAgentPolicyV4({...entry,agentRecipientRoot:buildRecipientTree(entry.recipients).root});
  const state=vs4.normalizeStateV4({protectedValue:(1000n*KAS).toString(),feeReserve:(5n*KAS).toString(),paused:"0",agentRoot:buildAgentTreeV4([policy]).root,approvers:[],approvalM:"0",policyNonce:"0"});
  const compiled=compileExactStateV4({config,template,state,contractVersion:vs4.CONTRACT_VERSION_V4_1});
  await persistManifestV4(config,{schema:"policyvault-vault-manifest/v4",contractVersion:vs4.CONTRACT_VERSION_V4_1,networkId:config.networkId,vaultId:VAULT,label:"RC38 TEST transition",status:"ACTIVE",template,agentRegistry:[entry],
    live:{state:vs4.stateToJsonV4(state),stateId:vs4.computeStateIdV4({networkId:config.networkId,template,state,contractVersion:vs4.CONTRACT_VERSION_V4_1}),outpoint:{transactionId:"42".repeat(32),index:0},outpointValue:(state.protectedValue+state.feeReserve).toString(),scriptSha256:compiled.scriptSha256,covenantId:"41".repeat(32)},creationTxId:"42".repeat(32),latestTransitionTxId:null,lastTransition:null});
  const before=await getStore(config).read(Categories.VAULT,VAULT);
  const fuel={outpoint:{transactionId:"43".repeat(32),index:1},amount:(100n*KAS).toString(),scriptPublicKeyHex:`20${owner.xonly}ac`};
  const pendingBuild={config,vaultId:VAULT,action:"ownerPause",params:{fuel},signerAddress:owner.address};
  const prebuilt=await wr4.buildWalletRequestV4(pendingBuild);
  const signer=action==="agentSpend"?agent:owner;
  const request=await wr4.buildWalletRequestV4({config,vaultId:VAULT,action,params:action==="agentSpend"?{payAmountSompi:(4n*KAS).toString(),agentPk:agent.xonly,recipient:recipient.xonly}:{fuel},signerAddress:signer.address});
  const signed=signFixtureInputs(config,signer,request);
  const finalized=await wr4.finalizeWalletRequestV4({config,requestId:request.requestId,signedSafeJson:signed});
  assert.equal(finalized.state,"PREFLIGHT_VERIFIED");
  const node=localNode(config,finalized);
  await assert.rejects(submit4.submitWalletRequestV4({config,requestId:finalized.requestId,rpc:node.rpc,pollAttempts:1,pollDelayMs:0}),{code:"RECONCILIATION_REQUIRED"});
  assert.equal(node.submits(),1);
  const legacy=await wr4.loadRequest(config,finalized.requestId);
  legacy.state="SUBMISSION_REJECTED";
  legacy.error=`Rejected transaction ${legacy.txId}: transaction ${legacy.txId} was already accepted by the consensus`;
  for(const key of ["submitStartHash","submissionRejection","submissionOutcome","submissionResponse","transitionRecovery"]) delete legacy[key];
  await wr4.saveRequest(config,legacy);
  const store=getStore(config);
  const budgetKey = action === "agentSpend" ? require("../src/budget-reservation").reservationKey(legacy) : null;
  const originalReservation = budgetKey ? await store.read(Categories.TRANSITION_CLAIM, budgetKey) : null;
  await store.remove(Categories.SUBMISSION_CLAIM,legacy.txId);
  await store.remove(Categories.TRANSITION_CLAIM,transitionClaimKey(legacy.predecessorOutpoint));
  await require("../src/budget-reservation").releaseReservationForRequest(config,legacy);
  return {config,owner,agent,recipient,before,request:legacy,prebuilt,pendingBuild:{...pendingBuild,config:undefined},snapshot:await snapshot(config),budgetKey,originalReservation,submits:node.submits(),cleanup:()=>fs.rmSync(config.dataRoot,{recursive:true,force:true})};
}
function caseFor(base,config) {
  const node=localNode(config,base.request), q=clone(base.request);
  const x={config,q,...node,store:()=>getStore(x.config),request:()=>wr4.loadRequest(x.config,q.requestId),manifest:()=>getStore(x.config).read(Categories.VAULT,q.vaultId)};
  x.recover=(options={})=>require("../src/wallet-recovery-v4").reconcileTransitionWalletRequestV4({config:x.config,requestId:q.requestId,rpc:x.rpc,...options});
  x.generic=()=>require("../src/reconcile-v4").reconcileVaultV4(x.config,q.vaultId,{rpc:x.rpc,stalePendingMinimumMs:0});
  return x;
}
async function jsonCase(base) {const config=freshConfig();await install(config,base.snapshot);return caseFor(base,config);}
function injectAfter(config,boundary) {
  const store=getStore(config);let hit=false;
  const originals=Object.fromEntries(["write","createExclusive","appendAudit","remove"].map(m=>[m,store[m].bind(store)]));
  for(const method of Object.keys(originals)) store[method]=async(...args)=>{
    const yes=!hit&&(boundary==="manifest"&&method==="write"&&args[0]===Categories.VAULT || boundary==="receipt"&&method==="createExclusive"&&args[0]===Categories.RECEIPT || boundary==="audit"&&method==="appendAudit"&&args[0]?.result==="CHAIN_VERIFIED" || boundary==="claim"&&method==="remove"&&args[0]===Categories.SUBMISSION_CLAIM || boundary==="request"&&method==="write"&&args[0]===Categories.REQUEST&&args[2]?.state==="CHAIN_VERIFIED");
    const result=await originals[method](...args);
    if(yes){hit=true;throw Error(`TEST interruption after ${boundary}`);}
    return result;
  };
  return {hit:()=>hit,restore:()=>{for(const [method,fn]of Object.entries(originals))store[method]=fn;}};
}
async function assertProtected(x,base) {
  const r=await x.request();assert.equal(r.state,"RECONCILIATION_REQUIRED");
  assert.deepEqual(r.finalTransaction,base.request.finalTransaction);assert.deepEqual(r.build,base.request.build);
  assert.equal(r.submitStartHash,undefined,"missing original evidence is not invented");
  assert.deepEqual(await x.manifest(),base.before);
  const s=x.store(), claim=await s.read(Categories.SUBMISSION_CLAIM,r.txId), transition=await s.read(Categories.TRANSITION_CLAIM,transitionClaimKey(r.predecessorOutpoint));
  assert.equal(claim.txId,r.txId);assert.equal(claim.vaultId,r.vaultId);assert.equal(claim.action,r.action);
  assert.equal(transition.txId,r.txId);assert.equal(transition.vaultId,r.vaultId);assert.equal(transition.action,r.action);
  assert.equal(await s.read(Categories.RECEIPT,r.txId),null);assert.equal(x.submits(),0);
}
async function assertComplete(x,base) {
  const r=await x.request(),m=await x.manifest(),s=x.store();assert.equal(r.state,"CHAIN_VERIFIED");
  assert.deepEqual(r.finalTransaction,base.request.finalTransaction);assert.deepEqual(r.build,base.request.build);
  assert.equal(m.creationTxId,base.before.creationTxId);assert.equal(m.latestTransitionTxId,r.txId);
  if(r.sdkAction==="ownerRecover"){assert.equal(m.status,"RECOVERED");assert.equal(m.live,null);}
  else{assert.equal(m.live.outpoint.transactionId,r.txId);assert.equal(m.live.stateId,r.successorStateId);assert.equal(m.agentRegistry[0].periodSpent,(4n*KAS).toString());}
  const receipt=await s.read(Categories.RECEIPT,r.txId);assert.equal(receipt.txId,r.txId);assert.equal(receipt.vaultId,r.vaultId);assert.equal(receipt.action,r.action);
  const audits=(await s.readAudit({vaultId:r.vaultId,txId:r.txId,limit:1000})).filter(e=>e.result==="CHAIN_VERIFIED");assert.equal(audits.length,1,"one completion audit across retries");
  assert.equal(await s.read(Categories.SUBMISSION_CLAIM,r.txId),null);assert.equal(await s.read(Categories.TRANSITION_CLAIM,transitionClaimKey(r.predecessorOutpoint)),null);assert.equal(x.submits(),0);
}
module.exports={baseFixture,jsonCase,caseFor,install,snapshot,injectAfter,assertProtected,assertComplete,freshConfig,clone,wallet,wr4,submit4,vs4,getStore,Categories,loadConfig,loadManifestV4,transitionClaimKey,KAS};
