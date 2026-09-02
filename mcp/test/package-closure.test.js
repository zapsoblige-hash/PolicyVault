"use strict";

/*
 * PACKAGING: mechanical RUNTIME DEPENDENCY-CLOSURE audit of the npm package
 * `policyvault-mcp`, starting at server.js. Every runtime-reachable require
 * must be a node builtin OR resolve to a file INSIDE the package root that
 * is covered by package.json "files". Nothing may escape to the monorepo
 * (../../core, sdk/, server/, ...), depend on generated developer artifacts,
 * or on undeclared packages (the package declares zero dependencies).
 *
 * The 1.4.0 escape (src/idempotency.js -> ../../core/model/canonical-json)
 * is exactly what this gate would have caught.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");
const os = require("os");
const { isBuiltin } = require("node:module");

const MCP_ROOT = path.join(__dirname, "..");

function stripComments(text) {
  return text.replace(/\/\*[\s\S]*?\*\//g, "").replace(/^\s*\/\/.*$/gm, "");
}

/* Walk static require() targets from an entry file; returns { files, problems }. */
function closure(root, entry) {
  const pkg = JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf8"));
  const deps = Object.keys(pkg.dependencies ?? {});
  const filesGlobs = pkg.files ?? [];
  const covered = (abs) => {
    const rel = path.relative(root, abs).split(path.sep).join("/");
    if (rel === "package.json") return true; // npm always includes it
    return filesGlobs.some((g) => (g.endsWith("/") ? rel.startsWith(g) : rel === g));
  };
  const seen = new Set();
  const problems = [];
  const queue = [path.resolve(root, entry)];
  while (queue.length) {
    const file = queue.shift();
    if (seen.has(file)) continue;
    seen.add(file);
    const relToRoot = path.relative(root, file);
    if (relToRoot.startsWith("..") || path.isAbsolute(relToRoot)) {
      problems.push(`ESCAPES PACKAGE ROOT: ${file}`);
      continue;
    }
    if (!fs.existsSync(file)) {
      problems.push(`MISSING: ${relToRoot}`);
      continue;
    }
    if (!covered(file)) problems.push(`NOT IN package.json files: ${relToRoot}`);
    const text = stripComments(fs.readFileSync(file, "utf8"));
    for (const m of text.matchAll(/require\(\s*(["'])([^"')]+)\1\s*\)/g)) {
      const target = m[2];
      if (isBuiltin(target)) continue;
      if (target.startsWith(".")) {
        let resolved = path.resolve(path.dirname(file), target);
        if (fs.existsSync(resolved) && fs.statSync(resolved).isDirectory()) resolved = path.join(resolved, "index.js");
        else if (!resolved.endsWith(".js") && !resolved.endsWith(".json")) resolved = `${resolved}.js`;
        queue.push(resolved);
      } else if (!deps.includes(target)) {
        problems.push(`UNDECLARED PACKAGE DEPENDENCY: ${target} (from ${relToRoot})`);
      }
    }
  }
  return { files: [...seen].map((f) => path.relative(root, f)).sort(), problems };
}

test("runtime closure of server.js stays inside the package and inside package.json files", () => {
  const { files, problems } = closure(MCP_ROOT, "server.js");
  assert.deepEqual(problems, []);
  assert.ok(files.includes("core/model/canonical-json.js"), "the packaged shared-core copy is part of the closure");
  assert.ok(files.includes("src/idempotency.js"));
  for (const f of files) assert.ok(!f.startsWith("..") && !f.includes("/../"), `no monorepo path in the closure: ${f}`);
  /* the package declares no dependencies: every non-builtin require is package-internal */
  const pkg = JSON.parse(fs.readFileSync(path.join(MCP_ROOT, "package.json"), "utf8"));
  assert.equal(Object.keys(pkg.dependencies ?? {}).length, 0);
  assert.ok(pkg.files.includes("core/"), "package.json files must ship core/");
  assert.equal(pkg.scripts.prepack, "node tools/sync-core.js --check");
  fs.writeFileSync(path.join(os.tmpdir(), "policyvault-mcp-closure-report.json"), JSON.stringify({ entry: "server.js", files, problems }, null, 2));
});

function tempCopy() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "pv-mcp-closure-"));
  fs.cpSync(MCP_ROOT, dir, { recursive: true, filter: (src) => !src.includes(`${path.sep}node_modules`) && !src.includes(`${path.sep}test`) });
  return dir;
}

test("NEGATIVE: an escaping monorepo require is flagged", () => {
  const dir = tempCopy();
  const f = path.join(dir, "src", "idempotency.js");
  fs.writeFileSync(f, fs.readFileSync(f, "utf8").replace('require("../core/model/canonical-json")', 'require("../../core/model/canonical-json")'));
  const { problems } = closure(dir, "server.js");
  assert.ok(problems.some((p) => p.startsWith("ESCAPES PACKAGE ROOT")), JSON.stringify(problems));
});

test("NEGATIVE: a missing shared implementation is flagged", () => {
  const dir = tempCopy();
  fs.rmSync(path.join(dir, "core"), { recursive: true, force: true });
  const { problems } = closure(dir, "server.js");
  assert.ok(problems.some((p) => p.startsWith("MISSING: core/model/canonical-json.js")), JSON.stringify(problems));
});

test("NEGATIVE: omitting core/ from package.json files is flagged", () => {
  const dir = tempCopy();
  const pkgPath = path.join(dir, "package.json");
  const pkg = JSON.parse(fs.readFileSync(pkgPath, "utf8"));
  pkg.files = pkg.files.filter((f) => f !== "core/");
  fs.writeFileSync(pkgPath, JSON.stringify(pkg, null, 2));
  const { problems } = closure(dir, "server.js");
  assert.ok(problems.some((p) => p.startsWith("NOT IN package.json files: core/")), JSON.stringify(problems));
});

test("NEGATIVE: an undeclared external package dependency is flagged", () => {
  const dir = tempCopy();
  const f = path.join(dir, "src", "http.js");
  fs.writeFileSync(f, `const _x = require("left-pad");\n` + fs.readFileSync(f, "utf8"));
  const { problems } = closure(dir, "server.js");
  assert.ok(problems.some((p) => p.startsWith("UNDECLARED PACKAGE DEPENDENCY: left-pad")), JSON.stringify(problems));
});
