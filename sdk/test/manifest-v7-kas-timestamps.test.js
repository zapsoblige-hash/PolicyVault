"use strict";
// G1-01 integration follow-up: real manifest writers must not sample updatedAt
// before a later synthesized createdAt. Synthetic JSON storage; no chain action.
const {test}=require("node:test"),assert=require("node:assert/strict");
const fs=require("node:fs"),os=require("node:os"),path=require("node:path");
const {loadConfig}=require("../src/config"),{getStore,Categories}=require("../src/store");
const {createManifestV7Kas,persistManifestV7Kas}=require("../src/manifest-v7-kas");
// Narrow schema11 option: explicit public synthetic template, no roadmap fixture dependency.
const template=Object.freeze({"vaultId":"f3cc42cf578f714d0712490e308c747ae6f34700ec81676406e41ad8c45d3c4d","orgRootCovenantId":"4bff69a3d1890364255e12eb6f07bff6aac99342192ecf95dd51113eb0a48fb1","rootTemplateVmHash":"b1d95c9d106917b367f8be42cde6d29c157036fc8be2febdadb34870476be520","rootPrefixLen":1,"rootStateLen":467,"rootSuffixLen":11077,"recoveryPk":"baf7689c0a3558fb604589036a8d1e4b685d909f6e0e2c6018a14049ae64ec26"});
function input(){return {schema:"policyvault-rooted-kas-vault-manifest-record/1",contractVersion:"policyvault-0.7-kas",networkId:"testnet-10",template,status:"PENDING_CREATE",agentRegistry:[],live:null};}
for(const [name,write] of [["create",createManifestV7Kas],["persist",persistManifestV7Kas]]){
 test(`${name}: synthesized creation and update timestamps agree across clock ticks`,async()=>{
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),"pv-kas-manifest-clock-")),config=loadConfig({dataRoot:dir});
  const RealDate=Date;let tick=RealDate.parse("2026-09-17T00:00:00.000Z");
  try{
   global.Date=class extends RealDate{constructor(...args){super(...(args.length?args:[tick++]));}static now(){return tick++;}};
   await write(config,input());
   const stored=await getStore(config).read(Categories.VAULT,template.vaultId);
   assert.equal(stored.createdAt,stored.updatedAt,"one new manifest has one creation instant even when normalization crosses a clock tick");
  }finally{global.Date=RealDate;fs.rmSync(dir,{recursive:true,force:true});}
 });
 test(`${name}: preserve supplied creation time`,async()=>{
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),"pv-kas-manifest-existing-")),config=loadConfig({dataRoot:dir});
  try{
   await write(config,{...input(),createdAt:"2020-01-01T00:00:00.000Z"});
   const stored=await getStore(config).read(Categories.VAULT,template.vaultId);
   assert.equal(stored.createdAt,"2020-01-01T00:00:00.000Z");
   assert.ok(stored.updatedAt>=stored.createdAt);
  }finally{fs.rmSync(dir,{recursive:true,force:true});}
 });
}
