"use strict";
/*
 * EXACT-TARBALL CANDIDATE PROOF for policyvault-mcp (least-privilege
 * discovery corrective, 2026-09-02). Usage:
 *   node mcp/tools/candidate-proof.js /abs/path/policyvault-mcp-<ver>.tgz
 * Proves, against a REAL corrected PolicyVault server booted in-process
 * (conformance harness: hosted auth, real wallet sign-in, real machine
 * identities) and a fresh consumer directory OUTSIDE the repository:
 *   1. clean `npm install <tgz>` → published bin mapping, no sibling core;
 *   2. REAL stdio initialize through the installed executable;
 *   3. credential-scoped tools/list for a read:network-only credential
 *      (exactly capabilities + network_status), full catalog for a
 *      credential holding every scope;
 *   4. unauthorized EXACT-NAME invocation (policyvault_list_vaults with
 *      read:network only) still receives the server's 403 SCOPE_FORBIDDEN;
 *   5. malformed capability discovery (feature declared, no principal)
 *      fails CLOSED at startup (exit 3); a bogus credential fails closed
 *      with the server's own code (http 401 MACHINE_TOKEN_INVALID);
 *   6. runtime-resolution audit: every module the installed server resolves
 *      is a node builtin or lives under the installed package.
 * Prints a JSON evidence record; exit 0 only when every step passed.
 * Nothing is published.
 */
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const http = require("node:http");
const crypto = require("node:crypto");
const { spawn, execSync } = require("node:child_process");

const TGZ = path.resolve(process.argv[2] || "");
if (!fs.existsSync(TGZ)) { console.error("usage: candidate-proof.js <tarball>"); process.exit(2); }
const REPO = path.resolve(__dirname, "..", "..");
const { ConformanceHarness } = require(path.join(REPO, "conformance/lib/server-harness"));
const { SCOPES } = require(path.join(REPO, "server/src/scopes"));

const evidence = { schema: "policyvault-mcp-candidate-proof/1", at: new Date().toISOString(), tarball: { path: TGZ, sha256: crypto.createHash("sha256").update(fs.readFileSync(TGZ)).digest("hex"), bytes: fs.statSync(TGZ).size }, steps: [] };
const step = (name, data) => { evidence.steps.push({ step: name, ...data }); console.error(`[${name}] ${JSON.stringify(data)}`); };
const fail = (msg) => { step("FAIL", { message: msg }); console.log(JSON.stringify(evidence, null, 2)); process.exit(1); };

function runMcp({ dir, env, messages, preloadLog }) {
  return new Promise((resolve) => {
    const child = spawn("npx", ["--no-install", "policyvault-mcp"], { cwd: dir, env: { ...process.env, ...env, NODE_PATH: "", ...(preloadLog ? { NODE_OPTIONS: `--require ${path.join(dir, "preload.js")}`, PV_RESOLVE_LOG: preloadLog } : {}) }, stdio: ["pipe", "pipe", "pipe"] });
    let out = "", err = "";
    child.stdout.on("data", (d) => (out += d));
    child.stderr.on("data", (d) => (err += d));
    const timer = setTimeout(() => child.kill("SIGKILL"), 40000);
    child.on("exit", (code) => { clearTimeout(timer); resolve({ code, out, err }); });
    setTimeout(() => { for (const m of messages) child.stdin.write(JSON.stringify(m) + "\n"); setTimeout(() => child.stdin.end(), 4000); }, 2500);
  });
}
const parse = (out) => out.split("\n").filter(Boolean).map((l) => { try { return JSON.parse(l); } catch { return { PARSE_ERROR: l.slice(0, 80) }; } });
const INIT = { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "candidate-proof", version: "0" } } };
const INITED = { jsonrpc: "2.0", method: "notifications/initialized" };
const LIST = { jsonrpc: "2.0", id: 2, method: "tools/list", params: {} };

(async () => {
  // 1. fresh consumer directory OUTSIDE the repository
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "pv-mcp-candidate-"));
  execSync("npm init -y", { cwd: dir, stdio: "ignore" });
  execSync(`npm install --no-audit --no-fund --loglevel=error ${JSON.stringify(TGZ)}`, { cwd: dir, stdio: "ignore" });
  const pkgDir = path.join(dir, "node_modules", "policyvault-mcp");
  const pkg = JSON.parse(fs.readFileSync(path.join(pkgDir, "package.json"), "utf8"));
  const walk = (d) => fs.readdirSync(d, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? walk(path.join(d, e.name)) : [path.relative(pkgDir, path.join(d, e.name))]));
  const installed = walk(pkgDir).sort();
  if (!fs.existsSync(path.join(dir, "node_modules", ".bin", "policyvault-mcp"))) fail("bin mapping missing");
  if (fs.existsSync(path.join(dir, "core")) || fs.existsSync(path.join(dir, "node_modules", "core"))) fail("sibling core present");
  step("install", { consumerDir: dir, version: pkg.version, files: installed.length, bin: true, siblingCore: false });
  fs.writeFileSync(path.join(dir, "preload.js"), `"use strict";const Module=require("module");const fs=require("fs");const seen=new Set();const orig=Module._resolveFilename;Module._resolveFilename=function(r,p,i,o){const x=orig.call(this,r,p,i,o);seen.add(x);return x;};process.on("exit",()=>{try{fs.writeFileSync(process.env.PV_RESOLVE_LOG+"."+process.pid,JSON.stringify([...seen]))}catch(_){}});`);

  // 2. REAL corrected server (hosted auth, real identities)
  const harness = await new ConformanceHarness().start();
  try {
    await harness.mintIdentity(harness.ownerCookie, "netonly", ["read:network"], "candidate-proof-read-network");
    await harness.mintIdentity(harness.ownerCookie, "all", [...SCOPES], "candidate-proof-all-scopes");
    step("server", { baseUrl: harness.baseUrl, credentials: ["netonly(read:network)", `all(${SCOPES.length} scopes)`] });

    // 3. credential-scoped tools/list (+ real initialize) — read:network only
    const logA = path.join(dir, "resolved-netonly");
    const a = await runMcp({ dir, env: { POLICYVAULT_MCP_SERVER_URL: harness.baseUrl, POLICYVAULT_MCP_TOKEN: harness.tokens.netonly }, preloadLog: logA, messages: [INIT, INITED, LIST, { jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "policyvault_list_vaults", arguments: {} } }, { jsonrpc: "2.0", id: 4, method: "tools/call", params: { name: "policyvault_network_status", arguments: {} } }] });
    const ma = parse(a.out);
    const init = ma.find((m) => m.id === 1); const list = ma.find((m) => m.id === 2); const hidden = ma.find((m) => m.id === 3); const net = ma.find((m) => m.id === 4);
    if (!init || !init.result || init.result.serverInfo.version !== pkg.version) fail(`initialize: ${JSON.stringify(init).slice(0, 200)}`);
    const names = list && list.result ? list.result.tools.map((t) => t.name) : null;
    if (!names || names.join(",") !== "policyvault_capabilities,policyvault_network_status") fail(`read:network tools/list = ${JSON.stringify(names)}`);
    const sc = hidden && hidden.result && hidden.result.structuredContent;
    if (!sc || sc.status !== "REFUSED" || sc.httpStatus !== 403 || sc.data.error.code !== "SCOPE_FORBIDDEN") fail(`hidden exact-name call: ${JSON.stringify(hidden).slice(0, 300)}`);
    // network_status is AUTHORIZED for read:network: it must never be a scope
    // refusal. The in-process proof server has no reachable kaspad, so the
    // authorized call may surface the server's node-availability error
    // (non-auth 5xx) instead of OK — both prove the authorization boundary.
    const ns = net && net.result && net.result.structuredContent;
    if (!ns) fail(`network_status: ${JSON.stringify(net).slice(0, 200)}`);
    const nsAuthorized = ns.status === "OK" ? true : ns.httpStatus !== 401 && ns.httpStatus !== 403 && ns.data && ns.data.error && ns.data.error.code !== "SCOPE_FORBIDDEN";
    if (!nsAuthorized) fail(`network_status not authorized: ${JSON.stringify(ns).slice(0, 300)}`);
    if (a.err.includes(harness.tokens.netonly) || a.out.includes(harness.tokens.netonly)) fail("credential leaked to an output channel");
    step("scoped-discovery", { initialize: { protocolVersion: init.result.protocolVersion, serverInfo: init.result.serverInfo.version }, advertised: names, hiddenExactName: { status: sc.status, http: sc.httpStatus, code: sc.data.error.code }, networkStatus: ns.status === "OK" ? { status: "OK", networkId: ns.data.networkId } : { status: ns.status, http: ns.httpStatus, code: ns.data.error.code, note: "authorized (not a scope refusal); proof server has no kaspad" }, stderrDiag: a.err.split("\n").find((l) => l.includes("advertised")) || null, exit: a.code });

    // 3b. full catalog for an all-scope credential
    const b = await runMcp({ dir, env: { POLICYVAULT_MCP_SERVER_URL: harness.baseUrl, POLICYVAULT_MCP_TOKEN: harness.tokens.all }, messages: [INIT, INITED, LIST] });
    const lb = parse(b.out).find((m) => m.id === 2);
    const fullNames = lb && lb.result ? lb.result.tools.map((t) => t.name) : null;
    if (!fullNames || fullNames.length !== 14) fail(`all-scope tools/list = ${JSON.stringify(fullNames)}`);
    step("full-catalog", { advertised: fullNames.length, exit: b.code });

    // 5a. bogus credential → refused at discovery with the server's code
    const c = await runMcp({ dir, env: { POLICYVAULT_MCP_SERVER_URL: harness.baseUrl, POLICYVAULT_MCP_TOKEN: `pvmk_${"0".repeat(64)}` }, messages: [INIT] });
    if (c.code !== 3 || !/refused at discovery \(http 401 MACHINE_TOKEN_INVALID\)/.test(c.err)) fail(`bogus credential: exit ${c.code} stderr ${c.err.slice(0, 200)}`);
    if (parse(c.out).length !== 0) fail("bogus credential produced stdout");
    step("bogus-credential", { exit: c.code, stderr: c.err.trim().split("\n").pop() });

    // 5b. malformed discovery: feature declared, no principal → fail closed
    const stub = http.createServer((req, res) => { res.writeHead(200, { "content-type": "application/json" }); res.end(JSON.stringify({ schemaVersion: "policyvault-capabilities/v1", apiVersion: "v1", networkId: "testnet-10", actions: { v4: [{ action: "agentSpend", role: "agent" }] }, scopes: SCOPES.map((scope) => ({ scope, description: "" })), schemas: { walletV4Request: "policyvault-wallet-v4-request/v1" }, features: { principalScopedDiscovery: true, dryRunSimulation: true } })); });
    await new Promise((r) => stub.listen(0, "127.0.0.1", r));
    const d = await runMcp({ dir, env: { POLICYVAULT_MCP_SERVER_URL: `http://127.0.0.1:${stub.address().port}`, POLICYVAULT_MCP_TOKEN: harness.tokens.netonly }, messages: [INIT] });
    stub.close();
    if (d.code !== 3 || !/named no principal/.test(d.err)) fail(`malformed discovery: exit ${d.code} stderr ${d.err.slice(0, 200)}`);
    step("malformed-discovery", { exit: d.code, stderr: d.err.trim().split("\n").pop() });

    // 6. runtime-resolution audit (the read:network run)
    const logs = fs.readdirSync(dir).filter((f) => f.startsWith("resolved-netonly."));
    const pkgReal = fs.realpathSync(pkgDir);
    let audited = 0, escaped = [];
    for (const f of logs) {
      const seen = JSON.parse(fs.readFileSync(path.join(dir, f), "utf8"));
      const abs = seen.filter((s) => path.isAbsolute(s));
      if (!abs.some((s) => s.startsWith(pkgReal))) continue; // a process that did not load the package (npx shim)
      audited++;
      for (const s of abs) if (!s.startsWith(pkgReal)) escaped.push(s);
    }
    if (audited === 0 || escaped.length) fail(`resolution audit: audited=${audited} escaped=${JSON.stringify(escaped.slice(0, 5))}`);
    step("resolution-audit", { processesAudited: audited, escapedModules: 0 });
  } finally {
    await harness.stop();
    fs.rmSync(dir, { recursive: true, force: true });
  }
  evidence.result = "PASS";
  console.log(JSON.stringify(evidence, null, 2));
})().catch((e) => fail(`unexpected: ${e && e.stack ? e.stack.split("\n").slice(0, 3).join(" | ") : e}`));
