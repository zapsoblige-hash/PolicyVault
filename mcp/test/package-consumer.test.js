"use strict";

/*
 * PERMANENT PACKAGED-ARTIFACT CONSUMER GATE (owner directive 2026-09-01,
 * after the escaped policyvault-mcp@1.4.0 defect).
 *
 * Tests the EXACT tarball `npm pack` produces from this package — never
 * the working tree — the way an npm consumer receives it:
 *   1. npm pack -> candidate .tgz (sha256 + npm shasum/integrity recorded)
 *   2. fresh consumer directory OUTSIDE the repository (os.tmpdir())
 *   3. npm init -y ; npm install /exact/path/policyvault-mcp-<ver>.tgz
 *   4. run the installed executable through the published bin mapping
 *   5. drive a REAL MCP stdio initialize handshake (+ initialized,
 *      tools/list) against a mock PolicyVault API and REQUIRE a valid
 *      protocol response — "process stayed alive" is never success
 *   6. audit every module the installed server resolved at runtime: only
 *      node builtins and files under the consumer's installed package root
 *      (a --require preload written INTO the consumer dir records
 *      Module._resolveFilename results; no repository path may appear)
 * plus NEGATIVE variants proving the gate fails when the topology breaks:
 *   - package.json "files" omits core/            -> consumer initialize FAILS
 *   - a runtime require escapes to ../../core     -> consumer initialize FAILS
 *     (the consumer tree has no sibling checkout to resolve against)
 *   - the packaged shared implementation is missing -> `npm pack` itself
 *     FAILS (prepack drift gate)
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");
const { spawn, spawnSync } = require("child_process");

const { startMockApi, TEST_TOKEN } = require("./harness");

const MCP_ROOT = path.join(__dirname, "..");
const REPO_ROOT = path.join(MCP_ROOT, "..");
const PKG = JSON.parse(fs.readFileSync(path.join(MCP_ROOT, "package.json"), "utf8"));

const PRELOAD_SOURCE = `"use strict";
const Module = require("module");
const fs = require("fs");
const out = process.env.PV_RESOLVE_LOG;
const seen = new Set();
const orig = Module._resolveFilename;
Module._resolveFilename = function (request, parent, isMain, options) {
  const r = orig.call(this, request, parent, isMain, options);
  seen.add(r);
  return r;
};
const flush = () => { try { fs.writeFileSync(out, JSON.stringify([...seen])); } catch (_) {} };
process.on("exit", flush);
`;

function sh(cmd, args, opts = {}) {
  const r = spawnSync(cmd, args, { encoding: "utf8", maxBuffer: 64 * 1024 * 1024, ...opts });
  return r;
}

function packFrom(srcDir) {
  const dest = fs.mkdtempSync(path.join(os.tmpdir(), "pv-mcp-pack-"));
  const r = sh("npm", ["pack", "--json", "--pack-destination", dest], { cwd: srcDir, env: { ...process.env, npm_config_loglevel: "error" } });
  if (r.status !== 0) return { ok: false, stderr: r.stderr, stdout: r.stdout, dest };
  const info = JSON.parse(r.stdout)[0];
  const tgz = path.join(dest, info.filename);
  const bytes = fs.readFileSync(tgz);
  return { ok: true, tgz, dest, info, sha256: crypto.createHash("sha256").update(bytes).digest("hex"), shasum: info.shasum, integrity: info.integrity, files: info.files.map((f) => f.path).sort() };
}

function freshConsumer(tgz) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "pv-mcp-consumer-"));
  assert.ok(!dir.startsWith(REPO_ROOT), "consumer dir must be outside the repository");
  assert.equal(sh("npm", ["init", "-y"], { cwd: dir }).status, 0);
  const inst = sh("npm", ["install", "--no-audit", "--no-fund", "--loglevel=error", tgz], { cwd: dir, env: { ...process.env, NODE_PATH: "" } });
  assert.equal(inst.status, 0, `npm install of the exact tarball failed: ${inst.stderr}`);
  /* the consumer tree must not be able to resolve the monorepo: no sibling core/, no NODE_PATH */
  assert.ok(!fs.existsSync(path.join(dir, "core")) && !fs.existsSync(path.join(dir, "node_modules", "core")));
  fs.writeFileSync(path.join(dir, "preload.js"), PRELOAD_SOURCE);
  return dir;
}

/* Minimal newline-delimited JSON-RPC stdio client over the INSTALLED bin. */
function runInstalled(consumerDir, { env, messages, timeoutMs = 15000 }) {
  return new Promise((resolve) => {
    const binLink = path.join(consumerDir, "node_modules", ".bin", "policyvault-mcp");
    const resolveLog = path.join(consumerDir, "resolved.json");
    const child = spawn(process.execPath, ["--require", path.join(consumerDir, "preload.js"), binLink], {
      cwd: consumerDir,
      env: { PATH: process.env.PATH, HOME: process.env.HOME, PV_RESOLVE_LOG: resolveLog, NODE_PATH: "", ...env },
      stdio: ["pipe", "pipe", "pipe"]
    });
    let stdout = "";
    let stderr = "";
    const responses = [];
    child.stdout.on("data", (d) => {
      stdout += d;
      let idx;
      while ((idx = stdout.indexOf("\n")) >= 0) {
        const line = stdout.slice(0, idx).trim();
        stdout = stdout.slice(idx + 1);
        if (!line) continue;
        try {
          responses.push(JSON.parse(line));
        } catch {
          responses.push({ unparseable: line });
        }
        if (responses.filter((r) => r.id !== undefined).length >= messages.filter((m) => m.id !== undefined).length) {
          child.stdin.end();
        }
      }
    });
    child.stderr.on("data", (d) => (stderr += d));
    const timer = setTimeout(() => child.kill("SIGKILL"), timeoutMs);
    child.on("exit", (code, signal) => {
      clearTimeout(timer);
      let resolved = [];
      try {
        resolved = JSON.parse(fs.readFileSync(resolveLog, "utf8"));
      } catch {}
      resolve({ code, signal, responses, stderr, resolved, binLink });
    });
    /* give the server a moment to fetch capabilities, then send the messages */
    setTimeout(() => {
      for (const m of messages) child.stdin.write(JSON.stringify(m) + "\n");
    }, 400);
  });
}

const INITIALIZE = { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "consumer-gate", version: "0" } } };
const INITIALIZED = { jsonrpc: "2.0", method: "notifications/initialized" };
const TOOLS_LIST = { jsonrpc: "2.0", id: 2, method: "tools/list", params: {} };

test("EXACT candidate tarball: pack, clean consumer install, bin mapping, REAL initialize + tools/list, runtime resolution never escapes the installed package", async () => {
  const packed = packFrom(MCP_ROOT);
  assert.ok(packed.ok, `npm pack failed: ${packed.stderr}`);
  assert.equal(packed.info.name, "policyvault-mcp");
  assert.equal(packed.info.version, PKG.version);
  for (const required of ["package.json", "server.js", "server.json", "README.md", "src/idempotency.js", "core/model/canonical-json.js", "core/MANIFEST.json"]) {
    assert.ok(packed.files.includes(required), `tarball must contain ${required}`);
  }
  assert.ok(!packed.files.some((f) => f.startsWith("test/") || f.startsWith("tools/")), "tests/tools are not shipped");
  const record = { tarball: path.basename(packed.tgz), sha256: packed.sha256, shasum: packed.shasum, integrity: packed.integrity, files: packed.files, unpackedSize: packed.info.unpackedSize };
  fs.writeFileSync(path.join(os.tmpdir(), "policyvault-mcp-candidate-record.json"), JSON.stringify(record, null, 2));
  console.log(`CANDIDATE ${record.tarball} sha256=${record.sha256} shasum=${record.shasum} integrity=${record.integrity} files=${record.files.length}`);

  const consumer = freshConsumer(packed.tgz);
  const installedPkg = JSON.parse(fs.readFileSync(path.join(consumer, "node_modules", "policyvault-mcp", "package.json"), "utf8"));
  assert.equal(installedPkg.version, PKG.version);
  const binLink = path.join(consumer, "node_modules", ".bin", "policyvault-mcp");
  assert.equal(fs.realpathSync(binLink), fs.realpathSync(path.join(consumer, "node_modules", "policyvault-mcp", "server.js")), "bin mapping resolves to the installed server.js");

  const mock = await startMockApi();
  try {
    const run = await runInstalled(consumer, { env: { POLICYVAULT_MCP_SERVER_URL: mock.baseUrl, POLICYVAULT_MCP_TOKEN: TEST_TOKEN }, messages: [INITIALIZE, INITIALIZED, TOOLS_LIST] });
    const init = run.responses.find((r) => r.id === 1);
    assert.ok(init && init.result, `initialize must be answered with a result; stderr: ${run.stderr}; responses: ${JSON.stringify(run.responses)}`);
    assert.equal(typeof init.result.protocolVersion, "string");
    assert.equal(init.result.serverInfo.version, PKG.version);
    assert.ok(init.result.capabilities && init.result.capabilities.tools, "tools capability declared");
    const list = run.responses.find((r) => r.id === 2);
    assert.ok(list && list.result && Array.isArray(list.result.tools) && list.result.tools.length > 0, "tools/list returns the catalog");
    assert.equal(run.code, 0, `installed server must exit cleanly after stdin closes; stderr: ${run.stderr}`);
    /* runtime resolution audit */
    const pkgRoot = fs.realpathSync(path.join(consumer, "node_modules", "policyvault-mcp"));
    const consumerRoot = fs.realpathSync(consumer);
    const offenders = run.resolved.filter((r) => path.isAbsolute(r) && !fs.realpathSync(r).startsWith(pkgRoot) && !fs.realpathSync(r).startsWith(path.join(consumerRoot, "preload.js")));
    assert.deepEqual(offenders, [], "every runtime-resolved file must live under the installed package root");
    assert.ok(run.resolved.some((r) => r.endsWith(path.join("policyvault-mcp", "core", "model", "canonical-json.js"))), "the packaged shared-core copy was what the runtime resolved");
    assert.ok(!run.resolved.some((r) => r.startsWith(REPO_ROOT)), "no repository path resolved at runtime");
  } finally {
    await mock.close();
  }
});

/* A mutated copy of the package inside a FAKE repository layout
 * (<tmp>/core/<closure files> + <tmp>/mcp), so the prepack drift gate runs
 * exactly as it would in the real repository. */
function mutatedCopy(mutate) {
  const repo = fs.mkdtempSync(path.join(os.tmpdir(), "pv-mcp-mut-"));
  for (const rel of require("../tools/sync-core").CORE_FILES) {
    fs.mkdirSync(path.dirname(path.join(repo, rel)), { recursive: true });
    fs.copyFileSync(path.join(REPO_ROOT, rel), path.join(repo, rel));
  }
  const dir = path.join(repo, "mcp");
  fs.cpSync(MCP_ROOT, dir, { recursive: true, filter: (src) => !src.includes(`${path.sep}node_modules`) && !src.includes(`${path.sep}test${path.sep}`) && !src.endsWith(`${path.sep}test`) });
  mutate(dir);
  return dir;
}

test("NEGATIVE: package.json files omitting core/ produces a tarball whose clean consumer install FAILS before initialize", async () => {
  const dir = mutatedCopy((d) => {
    const p = path.join(d, "package.json");
    const pkg = JSON.parse(fs.readFileSync(p, "utf8"));
    pkg.files = pkg.files.filter((f) => f !== "core/");
    fs.writeFileSync(p, JSON.stringify(pkg, null, 2));
  });
  const packed = packFrom(dir);
  assert.ok(packed.ok, packed.stderr);
  assert.ok(!packed.files.some((f) => f.startsWith("core/")), "the broken tarball lacks core/");
  const consumer = freshConsumer(packed.tgz);
  const mock = await startMockApi();
  try {
    const run = await runInstalled(consumer, { env: { POLICYVAULT_MCP_SERVER_URL: mock.baseUrl, POLICYVAULT_MCP_TOKEN: TEST_TOKEN }, messages: [INITIALIZE] });
    assert.ok(!run.responses.some((r) => r.id === 1 && r.result), "no initialize result may be produced");
    assert.notEqual(run.code, 0);
    assert.match(run.stderr, /Cannot find module '\.\.\/core\/model\/canonical-json'/);
  } finally {
    await mock.close();
  }
});

test("NEGATIVE: a runtime require escaping to ../../core FAILS in the clean consumer (no sibling checkout resolves it)", async () => {
  const dir = mutatedCopy((d) => {
    const f = path.join(d, "src", "idempotency.js");
    fs.writeFileSync(f, fs.readFileSync(f, "utf8").replace('require("../core/model/canonical-json")', 'require("../../core/model/canonical-json")'));
  });
  const packed = packFrom(dir);
  assert.ok(packed.ok, packed.stderr);
  const consumer = freshConsumer(packed.tgz);
  const mock = await startMockApi();
  try {
    const run = await runInstalled(consumer, { env: { POLICYVAULT_MCP_SERVER_URL: mock.baseUrl, POLICYVAULT_MCP_TOKEN: TEST_TOKEN }, messages: [INITIALIZE] });
    assert.ok(!run.responses.some((r) => r.id === 1 && r.result));
    assert.notEqual(run.code, 0);
    assert.match(run.stderr, /Cannot find module '\.\.\/\.\.\/core\/model\/canonical-json'/);
  } finally {
    await mock.close();
  }
});

test("NEGATIVE: a missing/drifted packaged shared implementation makes `npm pack` itself FAIL (prepack gate)", () => {
  const dir = mutatedCopy((d) => fs.rmSync(path.join(d, "core"), { recursive: true, force: true }));
  const packed = packFrom(dir);
  assert.equal(packed.ok, false, "npm pack must refuse a package without its shared-core copy");
  assert.match(packed.stderr + packed.stdout, /sync-core: DRIFT|missing packaged copy/);
});
