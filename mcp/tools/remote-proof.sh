#!/usr/bin/env bash
# POST-PUBLICATION REMOTE CLEAN-ROOM PROOF for policyvault-mcp@<version>.
# Installs the PUBLIC registry artifact into a fresh directory outside the
# repository, checks exact version + tarball identity, runs the installed
# executable via npx, drives a REAL MCP stdio initialize against
# POLICYVAULT_MCP_SERVER_URL (default: a local stub if PV_STUB_PORT is set,
# else https://app.policy-vault.org), and requires a valid protocol response.
# Exit 0 only when every step passed. Usage:
#   mcp/tools/remote-proof.sh 1.4.1 [expected-shasum]
set -u
VERSION="${1:?version required}"; EXPECT_SHASUM="${2:-}"
DIR="$(mktemp -d /tmp/pv-mcp-remote-proof-XXXXXX)"
cd "$DIR" || exit 2
echo "proof dir: $DIR"
npm init -y >/dev/null 2>&1 || { echo "FAIL: npm init"; exit 1; }
npm install --no-audit --no-fund --loglevel=error "policyvault-mcp@${VERSION}" || { echo "FAIL: npm install policyvault-mcp@${VERSION}"; exit 1; }
RESOLVED="$(node -e 'console.log(require("./node_modules/policyvault-mcp/package.json").version)')"
[ "$RESOLVED" = "$VERSION" ] || { echo "FAIL: resolved $RESOLVED != $VERSION"; exit 1; }
DIST="$(npm view "policyvault-mcp@${VERSION}" dist --json 2>/dev/null)"
echo "registry dist: $DIST"
if [ -n "$EXPECT_SHASUM" ]; then
  echo "$DIST" | grep -q "\"shasum\": \"$EXPECT_SHASUM\"" || { echo "FAIL: published shasum != expected $EXPECT_SHASUM"; exit 1; }
fi
[ -e node_modules/.bin/policyvault-mcp ] || { echo "FAIL: bin mapping missing"; exit 1; }
[ ! -e core ] && [ ! -e node_modules/core ] || { echo "FAIL: sibling core present in consumer tree"; exit 1; }
URL="${POLICYVAULT_MCP_SERVER_URL:-https://app.policy-vault.org}"
# runtime-resolution audit: a --require preload (written HERE, outside the repo)
# records every module the server process resolves; only node builtins and
# files under the installed package may appear.
cat > preload.js <<'PRELOAD'
"use strict";
const Module = require("module"); const fs = require("fs");
const seen = new Set(); const orig = Module._resolveFilename;
Module._resolveFilename = function (request, parent, isMain, options) { const r = orig.call(this, request, parent, isMain, options); seen.add(r); return r; };
process.on("exit", () => { try { fs.writeFileSync(process.env.PV_RESOLVE_LOG + "." + process.pid, JSON.stringify([...seen])); } catch (_) {} });
PRELOAD
printf '%s\n%s\n%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"remote-proof","version":"0"}}}' \
  '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}' \
  | (sleep 4; cat) \
  | NODE_OPTIONS="--require $DIR/preload.js" PV_RESOLVE_LOG="$DIR/resolved" POLICYVAULT_MCP_SERVER_URL="$URL" POLICYVAULT_MCP_TOKEN="${POLICYVAULT_MCP_TOKEN:-pvmk_remote_proof_token_0000000000}" NODE_PATH= timeout 40 npx --no-install policyvault-mcp > init.out 2> init.err
CODE=$?
echo "npx exit=$CODE"; echo "stderr: $(head -c 300 init.err)"
node -e '
const fs=require("fs"); const path=require("path");
const lines=fs.readFileSync("init.out","utf8").split("\n").filter(Boolean);
const msgs=lines.map(l=>{try{return JSON.parse(l)}catch{return null}}).filter(Boolean);
const r=msgs.find(m=>m.id===1); const t=msgs.find(m=>m.id===2);
if(!r||!r.result||typeof r.result.protocolVersion!=="string"||!r.result.serverInfo){console.error("FAIL: no valid initialize result:",JSON.stringify(lines).slice(0,300));process.exit(1)}
if(r.result.serverInfo.version!==process.argv[1]){console.error("FAIL: serverInfo.version",r.result.serverInfo.version);process.exit(1)}
if(!t||!t.result||!Array.isArray(t.result.tools)){console.error("FAIL: no valid tools/list result");process.exit(1)}
const expectTools=Number(process.env.PV_EXPECT_TOOLS||14);
if(t.result.tools.length!==expectTools){console.error("FAIL: tool count",t.result.tools.length,"!=",expectTools);process.exit(1)}
console.log("initialize OK:",JSON.stringify({protocolVersion:r.result.protocolVersion,serverInfo:r.result.serverInfo.version,tools:!!r.result.capabilities.tools}));
console.log("tools/list OK:",t.result.tools.length,"tools:",t.result.tools.map(x=>x.name).join(","));
/* resolution audit over the process that loaded the installed server.js */
const dir=process.cwd(); const pkgRoot=fs.realpathSync(path.join(dir,"node_modules","policyvault-mcp"));
const logs=fs.readdirSync(dir).filter(f=>f.startsWith("resolved."));
let audited=false;
for(const f of logs){const list=JSON.parse(fs.readFileSync(path.join(dir,f),"utf8")); if(!list.some(x=>x.endsWith(path.join("policyvault-mcp","server.js")))) continue; audited=true;
  const offenders=list.filter(x=>path.isAbsolute(x)&&!fs.realpathSync(x).startsWith(pkgRoot)&&fs.realpathSync(x)!==path.join(fs.realpathSync(dir),"preload.js"));
  if(offenders.length){console.error("FAIL: runtime modules escaped the installed package:",offenders);process.exit(1)}
  if(!list.some(x=>x.endsWith(path.join("policyvault-mcp","core","model","canonical-json.js")))){console.error("FAIL: packaged shared-core copy not resolved");process.exit(1)}
  console.log("resolution audit OK:",list.filter(x=>path.isAbsolute(x)).length,"absolute modules, all under",pkgRoot);}
if(!audited){console.error("FAIL: no resolution log for the server process");process.exit(1)}' "$VERSION" || exit 1
[ "$CODE" = 0 ] || { echo "FAIL: npx exit $CODE"; exit 1; }
echo "REMOTE PROOF PASSED for policyvault-mcp@${VERSION} (dir $DIR)"
