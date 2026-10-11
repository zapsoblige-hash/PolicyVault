"use strict";
/*
 * RC45 R1-02 — the mechanical binding of the authorization-boundary inventory
 * to the route code (remediation plan rc45-r1-plan-01 PLAN-R1 revision 2 §2
 * R1-02 and §4 R1-02; review finding S-02 of rc45-patch-independent-01;
 * conditions C5 and K7). Internal RED-first regression material; not an audit.
 *
 * Used by sdk/test/authorization-boundary-inventory.test.js (the permanent
 * STRUCTURAL GATE 2 / GATE 1 checks, whose name-only predicates R1-02 replaces
 * by these) and sdk/test/rc45-r1-02-authorization-binding.test.js (the named
 * row legs, the sabotage rows and the extractor's own sanity legs).
 *
 * GATE 2 BINDING (plan §2 R1-02, K7). For a row of server/src/api.js,
 * server/src/org-roots.js or server/src/wallet-token-surface.js:
 *   1. the dispatcher source is LEXED (line and block comments blanked, string,
 *      template and regular-expression contents masked for structure), so a
 *      gate written in a comment never counts;
 *   2. the row's HANDLER BLOCK is located mechanically: every `if (...)` whose
 *      condition is made only of routing atoms (method === "X",
 *      segments.length OP n, segments[i] ===/!== "lit", &&, ||, !, parens)
 *      is a routing if; a routing if without else whose consequent always
 *      exits (its last statement returns or throws) is a GUARD (the
 *      statements after it in the same block run only when its condition is
 *      false); a function whose bare call sites in the same file sit under
 *      routing conditions is entered only under them (the org-roots
 *      dispatch() -> dispatchOrgRoots / dispatchWalletV7 linkage). The
 *      handler block is the deepest routing-if block whose whole chain (its
 *      own condition, every enclosing routing condition, every preceding
 *      guard, the function entry predicate) is true for the row's method and
 *      path (a :param segment never equals a literal) and which constrains
 *      the method (a family block whose nested routes all miss the row is not
 *      a handler). A row with no such block, or with more than one deepest
 *      block, CANNOT BE LOCATED (fails);
 *   3. the WRAPPER SET of the row is the handler block's text plus its FAMILY
 *      PRELUDE: in every enclosing block (and, through the call-site linkage,
 *      in every calling function), the statements before the path, with
 *      sibling routing-if statements and nested function bodies removed (a
 *      closure defined in a prelude is not executed by being defined) —
 *      e.g. the identities / governance / risk / webhooks / notifications /
 *      organizations / agent-suspensions principal resolution, org-roots.js
 *      dispatch() and the dispatchWalletTokenSurface preamble; plus,
 *      transitively, the bodies of the same-file functions it calls bare (so
 *      requireRequestMutation binds the requestMutationAllowed it applies);
 *   4. the row's authGate must be CALLED in the wrapper set; every symbol of
 *      its mutationGate (a camelCase identifier or a server/src/tenancy.js
 *      export, the extraction the inventory test already uses) must occur in
 *      it; a PARAMETERIZED gate (requireRequestAccess, requireWalletRequest,
 *      loadRequestScoped, and any dispatcher function declared with a
 *      `mutation` option) counts as a mutation gate only where it is called
 *      with { mutation: true } (K7).
 * GATE 1 FULL PATTERN (plan §2 R1-02): the hostile-evidence file (comments
 * stripped) must contain a request path — a string or template literal
 * ("/api/v1/..." or "/..."), or a segment array literal (["wallet", ...]) —
 * of exactly the row's segment count whose literal segments equal the row's
 * literal segments (its exact version segment included) and whose :param
 * positions hold an expression, a ":x" placeholder or a literal that is not a
 * route literal anywhere in the inventory. A loop variable bound by
 * `for (const x of ["a", "b"])` (or `for (const [x, ...] of [["a", ...]])`)
 * stands for each of its literals; any other expression never equals a
 * literal segment.
 */
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const ROOT = path.join(__dirname, "..", "..");
const DISPATCHERS = Object.freeze(["server/src/api.js", "server/src/org-roots.js", "server/src/wallet-token-surface.js"]);
const PARAMETERIZED = Object.freeze(["requireRequestAccess", "requireWalletRequest", "loadRequestScoped"]); // K7
const WILD = Symbol("expression");
const PARAM = Symbol("param");

/* ---------------- the lexer ---------------- */
const REGEX_AFTER = new Set(["", "(", ",", "=", ":", "[", "!", "&", "|", "?", "{", "}", ";", "+", "-", "*", "%", "<", ">", "~", "^", "k"]);
const REGEX_KEYWORDS = new Set(["return", "typeof", "instanceof", "in", "of", "new", "delete", "void", "throw", "case", "do", "else", "yield", "await"]);
/* Returns { code: comments blanked, skel: comments blanked AND literal contents masked } — both position-preserving. */
function lex(src) {
  const n = src.length, code = src.split(""), skel = src.split("");
  const blank = (arr, a, b) => { for (let k = a; k < b; k++) if (arr[k] !== "\n") arr[k] = " "; };
  const stack = [{ t: "code", depth: null }];
  let i = 0, lastSig = "";
  while (i < n) {
    const top = stack[stack.length - 1], c = src[i];
    if (top.t === "tpl") {
      if (c === "\\") { blank(skel, i, i + 2); i += 2; continue; }
      if (c === "`") { stack.pop(); lastSig = "\""; i += 1; continue; }
      if (c === "$" && src[i + 1] === "{") { stack.push({ t: "code", depth: 0 }); i += 2; lastSig = "{"; continue; }
      blank(skel, i, i + 1); i += 1; continue;
    }
    if (c === "/" && src[i + 1] === "/") { let e = i; while (e < n && src[e] !== "\n") e += 1; blank(code, i, e); blank(skel, i, e); i = e; continue; }
    if (c === "/" && src[i + 1] === "*") { const e = src.indexOf("*/", i + 2); const end = e < 0 ? n : e + 2; blank(code, i, end); blank(skel, i, end); i = end; continue; }
    if (c === "\"" || c === "'") {
      let e = i + 1;
      while (e < n && src[e] !== c) { if (src[e] === "\\") e += 1; else if (src[e] === "\n") throw new Error(`lexer: unterminated string at ${i}`); e += 1; }
      blank(skel, i + 1, e); i = e + 1; lastSig = "\""; continue;
    }
    if (c === "`") { stack.push({ t: "tpl" }); i += 1; continue; }
    if (c === "/") {
      if (REGEX_AFTER.has(lastSig)) {
        let e = i + 1, inClass = false;
        while (e < n) {
          const d = src[e];
          if (d === "\\") { e += 2; continue; }
          if (d === "\n") throw new Error(`lexer: unterminated regular expression at ${i}`);
          if (inClass) { if (d === "]") inClass = false; } else if (d === "[") inClass = true; else if (d === "/") break;
          e += 1;
        }
        blank(skel, i + 1, e); e += 1;
        while (e < n && /[a-z]/.test(src[e])) e += 1;
        i = e; lastSig = "r"; continue;
      }
      lastSig = "/"; i += 1; continue;
    }
    if (c === "{") { if (top.depth !== null) top.depth += 1; lastSig = "{"; i += 1; continue; }
    if (c === "}") {
      if (top.depth !== null) { if (top.depth === 0) { stack.pop(); i += 1; continue; } top.depth -= 1; }
      lastSig = "}"; i += 1; continue;
    }
    if (/[A-Za-z_$]/.test(c)) { let e = i + 1; while (e < n && /[\w$]/.test(src[e])) e += 1; const word = src.slice(i, e); lastSig = REGEX_KEYWORDS.has(word) ? "k" : "w"; i = e; continue; }
    if (/[0-9]/.test(c)) { let e = i + 1; while (e < n && /[\w.]/.test(src[e])) e += 1; lastSig = "n"; i = e; continue; }
    if (/\s/.test(c)) { i += 1; continue; }
    lastSig = c; i += 1;
  }
  if (stack.length !== 1) throw new Error("lexer: unterminated template literal");
  return { code: code.join(""), skel: skel.join("") };
}
/* The lexed source compiles exactly as the original does (comment stripping changed nothing but comments). */
function compiles(code) { vm.compileFunction(code, ["require", "module", "exports", "__filename", "__dirname"]); return true; }

/* ---------------- structure ---------------- */
function pairsOf(skel) {
  const match = new Map(), st = [], open = { "(": ")", "[": "]", "{": "}" }, close = { ")": "(", "]": "[", "}": "{" };
  for (let i = 0; i < skel.length; i++) {
    const c = skel[i];
    if (open[c]) st.push([c, i]);
    else if (close[c]) {
      const t = st.pop();
      if (!t || t[0] !== close[c]) throw new Error(`structure: unbalanced ${c} at ${i}`);
      match.set(t[1], i); match.set(i, t[1]);
    }
  }
  if (st.length) throw new Error("structure: unclosed bracket");
  return match;
}
const skipWs = (s, i) => { while (i < s.length && /\s/.test(s[i])) i += 1; return i; };
const skipWsBack = (s, i) => { while (i >= 0 && /\s/.test(s[i])) i -= 1; return i; };
/* End (exclusive) of the statement starting at `i` (depth-0 ';' or the end of a braced block that is the whole statement). */
function statementEnd(skel, match, i) {
  let k = i;
  while (k < skel.length) {
    const c = skel[k];
    if (c === "(" || c === "[" || c === "{") { k = match.get(k) + 1; continue; }
    if (c === ";") return k + 1;
    if (c === "}" || c === ")" || c === "]") return k; // the enclosing block closes (no semicolon)
    k += 1;
  }
  return k;
}
const wordAt = (s, i, w) => s.startsWith(w, i) && !/[\w$]/.test(s[i - 1] ?? "") && !/[\w$]/.test(s[i + w.length] ?? "");
/* The statement starting at `i`: { start, end (exclusive), kind } — compound statements (if/else chains, loops, try, blocks,
 * function declarations) are consumed whole; any other statement runs to its depth-0 semicolon. */
function parseStatement(skel, match, i) {
  i = skipWs(skel, i);
  const start = i;
  const body = (k) => { k = skipWs(skel, k); return skel[k] === "{" ? match.get(k) + 1 : parseStatement(skel, match, k).end; };
  if (wordAt(skel, i, "if")) {
    const po = skel.indexOf("(", i);
    let end = body(match.get(po) + 1);
    const j = skipWs(skel, end);
    if (wordAt(skel, j, "else")) end = body(j + 4);
    return { start, end, kind: "if" };
  }
  if (wordAt(skel, i, "for") || wordAt(skel, i, "while") || wordAt(skel, i, "switch")) { const po = skel.indexOf("(", i); return { start, end: body(match.get(po) + 1), kind: "loop" }; }
  if (wordAt(skel, i, "try")) {
    let end = body(i + 3), j = skipWs(skel, end);
    if (wordAt(skel, j, "catch")) { let k = skipWs(skel, j + 5); if (skel[k] === "(") k = match.get(k) + 1; end = body(k); j = skipWs(skel, end); }
    if (wordAt(skel, j, "finally")) end = body(j + 7);
    return { start, end, kind: "try" };
  }
  if (skel[i] === "{") return { start, end: match.get(i) + 1, kind: "block" };
  if (wordAt(skel, i, "function") || (wordAt(skel, i, "async") && wordAt(skel, skipWs(skel, i + 5), "function"))) {
    const po = skel.indexOf("(", i), b = skipWs(skel, match.get(po) + 1);
    return { start, end: match.get(b) + 1, kind: "function" };
  }
  return { start, end: statementEnd(skel, match, i), kind: wordAt(skel, i, "return") ? "return" : wordAt(skel, i, "throw") ? "throw" : "simple" };
}
function statementsIn(skel, match, a, b) {
  const out = [];
  let k = skipWs(skel, a);
  while (k < b) { const st = parseStatement(skel, match, k); if (st.end <= k) break; out.push(st); k = skipWs(skel, st.end); }
  return out;
}

function analyze(file, srcOverride = null) {
  const src = srcOverride ?? fs.readFileSync(path.join(ROOT, file), "utf8");
  const { code, skel } = lex(src);
  const match = pairsOf(skel);
  const braces = [...match.entries()].filter(([a, b]) => skel[a] === "{" && b > a).map(([a, b]) => ({ open: a, close: b })).sort((x, y) => x.open - y.open);
  const enclosing = (pos) => braces.filter((p) => p.open < pos && pos < p.close).sort((x, y) => y.open - x.open); // innermost first
  /* if statements: a routing if (only routing atoms) whose consequent always exits (its last statement returns or
   * throws) and that has no else is a GUARD for the statements after it in the same block */
  const ifs = [];
  for (const m of skel.matchAll(/(?<![\w$.])if\s*\(/g)) {
    const kw = m.index, po = skel.indexOf("(", kw), pc = match.get(po);
    const cond = code.slice(po + 1, pc);
    const k = skipWs(skel, pc + 1);
    const braced = skel[k] === "{";
    const cons = braced ? { open: k, close: match.get(k), braced } : { open: k, close: parseStatement(skel, match, k).end - 1, braced };
    const end = parseStatement(skel, match, kw).end;
    const hasElse = end > cons.close + 1;
    const before = skipWsBack(skel, kw - 1);
    const isElseIf = wordAt(skel, before - 3, "else");
    const ast = parseCondition(cond);
    const last = braced ? statementsIn(skel, match, cons.open + 1, cons.close).at(-1) : parseStatement(skel, match, cons.open);
    ifs.push({ kw, cond, ast, routing: ast !== null, cons, end, hasElse, isElseIf, guard: ast !== null && !hasElse && Boolean(last) && (last.kind === "return" || last.kind === "throw") });
  }
  /* function bodies (declarations, expressions, arrows) and their names */
  const fns = [];
  for (const m of skel.matchAll(/(?<![\w$.])function\b\s*\*?\s*([A-Za-z_$][\w$]*)?\s*\(/g)) {
    const po = skel.indexOf("(", m.index + 8), pc = match.get(po), b = skipWs(skel, pc + 1);
    if (skel[b] !== "{") continue;
    fns.push({ name: m[1] ?? null, kw: m.index, open: b, close: match.get(b), decl: true });
  }
  for (const m of skel.matchAll(/=>\s*\{/g)) {
    const b = m.index + m[0].length - 1;
    let k = skipWsBack(skel, m.index - 1), name = null;
    if (skel[k] === ")") k = match.get(k) - 1; else while (k >= 0 && /[\w$]/.test(skel[k])) k -= 1;
    k = skipWsBack(skel, k);
    if (skel.slice(k - 4, k + 1) === "async") k = skipWsBack(skel, k - 5);
    if (skel[k] === "=" && skel[k - 1] !== "=" && skel[k - 1] !== "!") { let e = skipWsBack(skel, k - 1), s = e; while (s >= 0 && /[\w$]/.test(skel[s])) s -= 1; const id = skel.slice(s + 1, e + 1); if (/^[A-Za-z_$][\w$]*$/.test(id) && /(const|let|var)\s+$/.test(skel.slice(Math.max(0, s - 8), s + 1))) name = id; }
    fns.push({ name, kw: b, open: b, close: match.get(b), decl: false });
  }
  const fnByName = new Map();
  for (const f of fns) if (f.name && !fnByName.has(f.name)) fnByName.set(f.name, f);
  /* functions declared with a `mutation` option are parameterized gates too */
  const parameterized = new Set(PARAMETERIZED);
  for (const f of fns) if (f.name && f.decl) { const po = skel.indexOf("(", f.kw + 8); const params = code.slice(po, match.get(po) + 1); if (/\{\s*[^}]*\bmutation\b[^}]*\}/.test(params)) parameterized.add(f.name); }
  return { file, src, code, skel, match, braces, enclosing, ifs, fns, fnByName, parameterized };
}

/* ---------------- routing conditions ---------------- */
function tokenize(s) {
  const out = [], re = /\s*(?:(===|!==|==|!=|>=|<=|&&|\|\||[()!<>.\[\]])|("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')|([0-9]+)|([A-Za-z_$][\w$]*))/y;
  let i = 0;
  while (i < s.length) {
    if (/^\s*$/.test(s.slice(i))) break;
    re.lastIndex = i;
    const m = re.exec(s);
    if (!m) return null;
    out.push(m[1] ? { op: m[1] } : m[2] ? { str: JSON.parse(m[2][0] === "'" ? `"${m[2].slice(1, -1).replace(/"/g, "\\\"")}"` : m[2]) } : m[3] ? { num: Number(m[3]) } : { id: m[4] });
    i = re.lastIndex;
  }
  return out;
}
/* AST of a condition made ONLY of routing atoms, or null. */
function parseCondition(text) {
  const t = tokenize(text);
  if (!t || !t.length) return null;
  let p = 0;
  const peek = () => t[p], eat = (op) => (t[p] && t[p].op === op ? (p += 1, true) : false);
  function operand() {
    const a = t[p];
    if (!a) return null;
    if (a.str !== undefined) { p += 1; return { kind: "str", v: a.str }; }
    if (a.num !== undefined) { p += 1; return { kind: "num", v: a.num }; }
    if (a.id === "method") { p += 1; return { kind: "method" }; }
    if (a.id === "segments") {
      p += 1;
      if (eat(".")) { if (t[p] && t[p].id === "length") { p += 1; return { kind: "len" }; } return null; }
      if (eat("[")) { const n = t[p]; if (!n || n.num === undefined) return null; p += 1; if (!eat("]")) return null; return { kind: "seg", i: n.num }; }
      return null;
    }
    return null;
  }
  function comparison() {
    const l = operand(); if (!l) return null;
    const o = peek(); if (!o || !["===", "!==", "==", "!=", ">=", "<=", ">", "<"].includes(o.op)) return null;
    p += 1;
    const r = operand(); if (!r) return null;
    return { kind: "cmp", op: o.op, l, r };
  }
  function unary() {
    if (eat("!")) { const e = unary(); return e && { kind: "not", e }; }
    if (eat("(")) { const e = or(); if (!e || !eat(")")) return null; return e; }
    return comparison();
  }
  function and() { let l = unary(); while (l && eat("&&")) { const r = unary(); l = r && { kind: "and", l, r }; } return l; }
  function or() { let l = and(); while (l && eat("||")) { const r = and(); l = r && { kind: "or", l, r }; } return l; }
  const ast = or();
  return ast && p === t.length ? ast : null;
}
function evaluate(ast, row) {
  const val = (o) => (o.kind === "str" || o.kind === "num" ? o.v : o.kind === "method" ? row.method : o.kind === "len" ? row.segs.length : row.segs[o.i]);
  switch (ast.kind) {
    case "and": return evaluate(ast.l, row) && evaluate(ast.r, row);
    case "or": return evaluate(ast.l, row) || evaluate(ast.r, row);
    case "not": return !evaluate(ast.e, row);
    case "cmp": {
      const a = val(ast.l), b = val(ast.r);
      if (ast.op === "===" || ast.op === "==") return a !== PARAM && b !== PARAM && a === b;
      if (ast.op === "!==" || ast.op === "!=") return !(a !== PARAM && b !== PARAM && a === b);
      if (typeof a !== "number" || typeof b !== "number") return false;
      return ast.op === ">=" ? a >= b : ast.op === "<=" ? a <= b : ast.op === ">" ? a > b : a < b;
    }
    default: return false;
  }
}
const hasMethod = (ast) => (ast.kind === "cmp" ? ast.l.kind === "method" || ast.r.kind === "method" : ast.kind === "not" ? hasMethod(ast.e) : ast.kind === "and" || ast.kind === "or" ? hasMethod(ast.l) || hasMethod(ast.r) : false);
const rowShape = (row) => ({ method: row.method, segs: row.path.split("/").filter(Boolean).map((s) => (s.startsWith(":") ? PARAM : s)) });

/* ---------------- the chain of a position ---------------- */
/* The routing constraints and the prelude regions dominating position `pos` inside the function enclosing it. */
function chainOf(A, pos) {
  const constraints = [], regions = [];
  const encl = A.enclosing(pos);
  let child = pos;
  for (const block of encl) {
    const fn = A.fns.find((f) => f.open === block.open);
    const asIf = A.ifs.find((f) => f.cons.braced && f.cons.open === block.open);
    const childStart = (() => { const f = A.ifs.find((g) => g.cons.braced && g.cons.open === child); return f ? f.kw : child; })();
    regions.push({ a: block.open + 1, b: childStart, prelude: true });
    for (const g of A.ifs) if (g.guard && g.kw > block.open && g.end <= childStart && A.enclosing(g.kw)[0] === block) constraints.push({ not: true, ast: g.ast, kw: g.kw });
    if (asIf && asIf.routing) constraints.push({ not: false, ast: asIf.ast, kw: asIf.kw });
    if (fn) return { constraints, regions, fn };
    child = block.open;
  }
  return { constraints, regions, fn: null };
}
const holds = (constraints, row) => constraints.every((c) => (c.not ? !evaluate(c.ast, row) : evaluate(c.ast, row)));
/* Bare call sites of `name` in the analysed file (not member calls, not the declaration). */
function callSites(A, name) {
  const out = [];
  for (const m of A.code.matchAll(new RegExp(`(?<![\\w$.])${name}\\s*\\(`, "g"))) if (!/function\s*$/.test(A.code.slice(Math.max(0, m.index - 12), m.index))) out.push(m.index);
  return out;
}
/* Every way `pos` is reached for `row`: [{ regions }] (empty when unreachable). Follows routed call-site linkage. */
function reachOf(A, pos, row, depth = 0) {
  const c = chainOf(A, pos);
  if (!holds(c.constraints, row)) return [];
  if (!c.fn || !c.fn.name || depth > 4) return [{ regions: c.regions }];
  const sites = callSites(A, c.fn.name).filter((q) => !(q > c.fn.open && q < c.fn.close)).map((q) => ({ q, chain: chainOf(A, q) })).filter((s) => s.chain.constraints.length > 0);
  if (!sites.length) return [{ regions: c.regions }];
  const out = [];
  for (const s of sites) for (const up of reachOf(A, s.q, row, depth + 1)) out.push({ regions: [...c.regions, ...up.regions] });
  return out;
}

/* ---------------- locating a row ---------------- */
function locate(A, row) {
  const shape = rowShape(row);
  const hits = [];
  for (const f of A.ifs) {
    if (!f.routing || !f.cons.braced || !evaluate(f.ast, shape)) continue;
    const reach = reachOf(A, f.cons.open + 1, shape);
    /* a HANDLER constrains the method (its own condition or an enclosing routing condition); a family block whose
     * nested routes all miss the row falls through or answers its own 404/405 and is not the row's handler */
    const methodBound = hasMethod(f.ast) || chainOf(A, f.cons.open + 1).constraints.some((c) => !c.not && hasMethod(c.ast));
    if (reach.length && methodBound) hits.push({ f, reach });
  }
  const inside = (o, h) => (o.f.cons.open > h.f.cons.open && o.f.cons.close < h.f.cons.close) || o.reach.some((r) => r.regions.some((g) => g.a > h.f.cons.open && g.b <= h.f.cons.close + 1 && g.b > g.a));
  const deepest = hits.filter((h) => !hits.some((o) => o !== h && inside(o, h)));
  if (deepest.length !== 1) return { located: false, why: deepest.length === 0 ? "no routing block matches the row" : `${deepest.length} routing blocks match the row (lines ${deepest.map((h) => lineOf(A, h.f.kw)).join(", ")})` };
  const h = deepest[0];
  return { located: true, handler: { a: h.f.cons.open + 1, b: h.f.cons.close, line: lineOf(A, h.f.kw) }, reach: h.reach };
}
const lineOf = (A, i) => A.src.slice(0, i).split("\n").length;
/* The text of a prelude region with sibling routing-if statements and nested function bodies removed. */
function preludeText(A, a, b) {
  const cut = [];
  for (const f of A.ifs) if (f.routing && f.kw >= a && f.kw < b) cut.push([f.kw, Math.min(f.end, b)]);
  for (const f of A.fns) if (f.open >= a && f.open < b) cut.push([f.open, Math.min(f.close + 1, b)]);
  const chars = A.code.slice(a, b).split("");
  for (const [x, y] of cut) for (let k = x; k < y; k++) chars[k - a] = " ";
  return chars.join("");
}
/* The wrapper set of a located row: handler text + family prelude + transitive same-file function bodies. */
function wrapperSet(A, loc) {
  const parts = [A.code.slice(loc.handler.a, loc.handler.b)];
  for (const r of loc.reach) for (const g of r.regions) if (g.b > g.a) parts.push(preludeText(A, g.a, g.b));
  let text = parts.join("\n"), grew = true;
  const seen = new Set();
  while (grew) {
    grew = false;
    for (const [name, f] of A.fnByName) {
      if (seen.has(name)) continue;
      if (new RegExp(`(?<![\\w$.])${name}\\s*\\(`).test(text)) { seen.add(name); text += "\n" + A.code.slice(f.open + 1, f.close); grew = true; }
    }
  }
  return text;
}

/* ---------------- the binding check ---------------- */
function gateSymbols(text, tenancyExports) {
  return [...String(text).matchAll(/[A-Za-z_][A-Za-z0-9_]*/g)].map((m) => m[0]).filter((s) => /[a-z][A-Z]/.test(s) || tenancyExports.has(s));
}
const occurs = (text, sym) => [...text.matchAll(new RegExp(`(?<![\\w$])${sym}(?![\\w$])`, "g"))].some((m) => !/function\s*$/.test(text.slice(Math.max(0, m.index - 12), m.index)));
const called = (text, sym) => [...text.matchAll(new RegExp(`(?<![\\w$])${sym}\\s*\\(`, "g"))].some((m) => !/function\s*$/.test(text.slice(Math.max(0, m.index - 12), m.index)));
function calledWithMutation(text, sym) {
  const { skel } = lex(text), match = pairsOf(skel);
  for (const m of text.matchAll(new RegExp(`(?<![\\w$])${sym}\\s*\\(`, "g"))) {
    const po = m.index + m[0].length - 1, pc = match.get(po);
    if (pc !== undefined && /\{\s*mutation\s*:\s*true\s*\}/.test(text.slice(po, pc + 1))) return true;
  }
  return false;
}
/* GATE 2 for one row: { located, handlerLine, auth: [violations], mutation: [violations] } (`analyses`: file -> analyze). */
function bindingReport(row, analyses, tenancyExports) {
  const tag = `${row.method} ${row.path}`;
  if (!DISPATCHERS.includes(row.file)) { const v = `${tag}: file ${row.file} is not a dispatcher the binding covers (${DISPATCHERS.join(", ")})`; return { located: false, auth: [v], mutation: [v] }; }
  const A = analyses.get(row.file);
  const loc = locate(A, row);
  if (!loc.located) { const v = `${tag}: binding cannot be located in ${row.file} (${loc.why})`; return { located: false, auth: [v], mutation: [v] }; }
  const text = wrapperSet(A, loc), auth = [], mutation = [];
  if (!/^[A-Za-z_$][\w$]*$/.test(row.authGate)) auth.push(`${tag}: authGate "${row.authGate}" is not a single gate symbol`);
  else if (!called(text, row.authGate)) auth.push(`${tag}: authGate ${row.authGate} is not called by its handler (${row.file}:${loc.handler.line}) or its family prelude`);
  if (row.mutationGate !== "n/a") {
    const syms = gateSymbols(row.mutationGate, tenancyExports);
    if (!syms.length) mutation.push(`${tag}: mutationGate "${row.mutationGate}" names no gate symbol`);
    for (const sym of syms) {
      if (!occurs(text, sym)) mutation.push(`${tag}: mutationGate symbol ${sym} is not bound to its handler (${row.file}:${loc.handler.line}) or its family prelude`);
      else if (A.parameterized.has(sym) && !calledWithMutation(text, sym)) mutation.push(`${tag}: parameterized gate ${sym} counts as a mutation gate only with { mutation: true }, and the handler (${row.file}:${loc.handler.line}) never calls it so`);
    }
  }
  return { located: true, handlerLine: loc.handler.line, handlerText: A.code.slice(loc.handler.a, loc.handler.b), auth, mutation };
}
/* Every GATE 2 violation of one row ([] when the row binds). */
function bindingViolations(row, analyses, tenancyExports) {
  const r = bindingReport(row, analyses, tenancyExports);
  return r.located ? [...r.auth, ...r.mutation] : r.auth;
}
/* The analyses of the three dispatchers (optionally with a sabotaged source for one file). */
function analyzeDispatchers(override = {}) {
  return new Map(DISPATCHERS.map((f) => [f, analyze(f, override[f] ?? null)]));
}

/* ---------------- GATE 1 full pattern ---------------- */
function staticLiterals(inventory) {
  const s = new Set();
  for (const r of inventory.routes) for (const seg of r.path.split("/")) if (seg && !seg.startsWith(":")) s.add(seg);
  return s;
}
/* String items of an array literal (null unless every item is a string literal, or, with `first`, an array literal whose
 * first item is a string literal — the `for (const [tail, body] of [["signature", {...}], ...])` idiom). */
function literalItems(code, skel, match, open, first = false) {
  const close = match.get(open), sk = skel.slice(open + 1, close), out = [];
  let depth = 0, last = 0;
  const items = [];
  for (let k = 0; k <= sk.length; k++) {
    const ch = sk[k];
    if (k === sk.length || (ch === "," && depth === 0)) { const a = open + 1 + last, b = open + 1 + k; if (code.slice(a, b).trim()) items.push([a, b]); last = k + 1; continue; }
    if ("([{".includes(ch)) depth += 1; else if (")]}".includes(ch)) depth -= 1;
  }
  for (const [a, b] of items) {
    let x = skipWs(skel, a);
    if (first) { if (skel[x] !== "[") return null; x = skipWs(skel, x + 1); }
    const q = code[x];
    if (q !== "\"" && q !== "'") return null;
    const end = code.indexOf(q, x + 1);
    if (!first && code.slice(end + 1, b).trim()) return null;
    out.push(code.slice(x + 1, end));
  }
  return out;
}
/* Loop variables bound to literal arrays: name -> Set of literal values. */
function loopLiterals(code, skel, match) {
  const map = new Map();
  for (const m of skel.matchAll(/(?<![\w$.])for\s*\(\s*(?:const|let|var)\s+(\[\s*([A-Za-z_$][\w$]*)[^\]]*\]|([A-Za-z_$][\w$]*))\s+of\s+\[/g)) {
    const name = m[2] ?? m[3], open = m.index + m[0].length - 1;
    const values = literalItems(code, skel, match, open, Boolean(m[2]));
    if (!values) continue;
    if (!map.has(name)) map.set(name, new Set());
    for (const v of values) map.get(name).add(v);
  }
  return map;
}
/* Request paths in a test source (comments stripped): arrays of segments, an expression segment as WILD (or, for a loop
 * variable over literal strings, each of its literals). */
function requestPaths(src) {
  const { code, skel } = lex(src), match = pairsOf(skel), loops = loopLiterals(code, skel, match), out = [];
  const expand = (segs) => {
    let acc = [[]];
    for (const s of segs) {
      const alts = Array.isArray(s) ? s : [s];
      acc = acc.flatMap((prefix) => alts.map((x) => [...prefix, x]));
      if (acc.length > 256) return;
    }
    out.push(...acc);
  };
  const segOf = (seg) => (seg.includes("\u0000") || seg.startsWith(":") ? WILD : seg);
  const fromText = (text) => {
    const at = text.indexOf("/api/v1/");
    let p = at >= 0 ? text.slice(at + 7) : text.startsWith("/") ? text : null;
    if (p === null) return;
    p = p.split("?")[0].split("#")[0];
    const segs = p.split("/").filter((x) => x.length);
    if (!segs.length || segs.some((x) => /\s/.test(x))) return;
    expand(segs.map(segOf));
  };
  /* A template's text with each loop-variable placeholder replaced by each of its literals (its values may carry "/"),
   * every other placeholder by an expression marker. */
  const fromString = (text, exprs = []) => {
    let texts = [text];
    exprs.forEach((e, k) => {
      const mark = `\u0000${k}\u0001`, name = e.trim();
      texts = loops.has(name) ? texts.flatMap((t) => [...loops.get(name)].map((v) => t.split(mark).join(v))) : texts.map((t) => t.split(mark).join("\u0000"));
    });
    if (texts.length <= 256) for (const t of texts) fromText(t);
  };
  for (let i = 0; i < code.length; i++) {
    const c = skel[i];
    if ((c === "\"" || c === "'") && code[i] === c) {
      let e = i + 1; while (e < code.length && code[e] !== c) { if (code[e] === "\\") e += 1; e += 1; }
      let text = null;
      try { text = JSON.parse(c === "'" ? `"${code.slice(i + 1, e).replace(/"/g, "\\\"")}"` : code.slice(i, e + 1)); } catch { text = null; }
      if (text !== null) fromString(text);
      i = e; continue;
    }
    if (code[i] === "`" && skel[i] === "`") {
      let e = i + 1, text = "";
      const exprs = [];
      while (e < code.length && !(code[e] === "`" && skel[e] === "`")) {
        if (code[e] === "$" && code[e + 1] === "{" && skel[e] === "$") { const close = match.get(e + 1); text += `\u0000${exprs.length}\u0001`; exprs.push(code.slice(e + 2, close)); e = close + 1; continue; }
        text += code[e]; e += 1;
      }
      fromString(text, exprs); i = e; continue;
    }
    if (c === "[") {
      const close = match.get(i), sk = skel.slice(i + 1, close);
      const items = []; let depth = 0, last = 0;
      for (let k = 0; k <= sk.length; k++) {
        const ch = sk[k];
        if (k === sk.length || (ch === "," && depth === 0)) { items.push(code.slice(i + 1 + last, i + 1 + k).trim()); last = k + 1; continue; }
        if ("([{".includes(ch)) depth += 1; else if (")]}".includes(ch)) depth -= 1;
      }
      if (items.length >= 1 && /^"[a-z0-9-]+"$|^'[a-z0-9-]+'$/.test(items[0]) && !items.some((x) => x.startsWith("..."))) {
        expand(items.map((x) => (/^"[^"\\]*"$|^'[^'\\]*'$/.test(x) ? x.slice(1, -1) : loops.has(x) ? [...loops.get(x)] : WILD)));
      }
    }
  }
  return out;
}
function matchesRow(segs, row, literals) {
  const pat = row.path.split("/").filter(Boolean);
  if (segs.length !== pat.length) return false;
  return pat.every((p, i) => (p.startsWith(":") ? segs[i] === WILD || (typeof segs[i] === "string" && !literals.has(segs[i])) : segs[i] === p));
}
function evidenceMatches(row, inventory, src) {
  const literals = staticLiterals(inventory);
  return requestPaths(src).some((segs) => matchesRow(segs, row, literals));
}

module.exports = { ROOT, DISPATCHERS, PARAMETERIZED, lex, compiles, pairsOf, analyze, analyzeDispatchers, parseCondition, locate, wrapperSet, bindingReport, bindingViolations, gateSymbols, requestPaths, evidenceMatches, rowShape };
