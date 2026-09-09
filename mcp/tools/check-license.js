"use strict";
// Pack only the approved canonical Apache-2.0 license and notices, byte for byte.
const fs=require('node:fs'),path=require('node:path');
const root=path.resolve(__dirname,'../..'),pkg=path.resolve(__dirname,'..');
for(const name of ['LICENSE','NOTICE']){
 const a=path.join(root,name),b=path.join(pkg,name);
 if(!fs.existsSync(a)||!fs.existsSync(b)||!fs.readFileSync(a).equals(fs.readFileSync(b))){console.error(`license check failed: canonical/packaged ${name} missing or differs`);process.exit(1);}
}
console.error('license check: approved canonical LICENSE and NOTICE byte-identical');
