"use strict";
const {test}=require("node:test"),assert=require("node:assert/strict"),https=require("node:https"),dns=require("node:dns"),{EventEmitter}=require("node:events");
const {isForbiddenTargetIp,httpPostJson}=require("../../server/src/events-delivery");
const forbidden=["::ffff:7f00:1","::ffff:a00:1","::ffff:a9fe:a9fe","0:0:0:0:0:ffff:7f00:1","0:0:0:0:0:0:0:1","0000::","0064:ff9b::a00:1","2001:0db8::1","::7f00:1","::10.0.0.1","fe80::1%eth0"];
test("LS-04 all equivalent private IPv6 encodings refuse at literal and DNS transport boundaries before dialing",async()=>{
 const old=https.request,lookup=dns.lookup;let dials=0;
 https.request=(options)=>{const req=new EventEmitter();req.destroy=()=>{};req.end=()=>{
  const finish=(err)=>{if(!err)dials++;queueMicrotask(()=>req.emit("error",err||Object.assign(Error("stub only"),{code:"STUB"})));};
  if(require("node:net").isIP(options.hostname)){dials++;finish(Object.assign(Error("literal stub"),{code:"STUB"}));}else options.lookup(options.hostname,{},finish);
 };return req;};
 try{
  for(const ip of forbidden){
   assert.equal(isForbiddenTargetIp(ip),true,ip);
   if(!ip.includes("%")){const r=await httpPostJson({url:`https://[${ip}]/x`,rawBody:"{}",headers:{},timeoutMs:50,allowLoopback:false});assert.equal(r.errorCode,"WEBHOOK_TARGET_FORBIDDEN",ip);}
   dns.lookup=(_h,_o,cb)=>cb(null,ip,6);
   const r=await httpPostJson({url:"https://receiver.example/x",rawBody:"{}",headers:{},timeoutMs:50,allowLoopback:false});assert.equal(r.errorCode,"WEBHOOK_TARGET_FORBIDDEN",ip);
  }
  assert.equal(dials,0);
  for(const ip of ["2606:4700::1111","::ffff:808:808","::ffff:8.8.8.8"]){assert.equal(isForbiddenTargetIp(ip),false,ip);}
  assert.equal(isForbiddenTargetIp("0:0:0:0:0:0:0:1",{allowLoopback:true}),false);
  assert.equal(isForbiddenTargetIp("::ffff:7f00:1",{allowLoopback:true}),false);
  assert.equal(isForbiddenTargetIp("::ffff:a00:1",{allowLoopback:true}),true);
 }finally{https.request=old;dns.lookup=lookup;}
});
