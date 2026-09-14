#!/usr/bin/env node
"use strict";
/*
 * tools/derive-vault-script-skeleton-v7-kas.js — MECHANICAL extraction of the
 * v0.7-kas (PolicyVaultRootedKas, CANDIDATE — not byte-frozen) rooted-vault
 * TEMPLATE SKELETON from REAL silverc output, the data that
 * core/intent/vault-script-v7-kas.js embeds (R7-04 closure: shared-core
 * reconstruction of the predecessor + successor scripts from declared pins).
 *
 * Method (the discipline of the frozen v0.7-payment skeleton, Codex
 * checkpoint 7): compile ONE state under three templates whose template
 * constants ALL differ but keep IDENTICAL push widths, so the compiled
 * suffixes are token-aligned; tokenize each suffix as Kaspa script; every
 * token that differs across the three compiles is a HOLE, identified by the
 * template constant it encodes (unique by construction); every token that is
 * identical is generation-constant and folds into a chunk. The script's OWN
 * LENGTH holes are located with a FOURTH template of a different push width
 * (a shorter script): a constant token equal to the length push in every
 * equal-width compile that equals the NEW length push in the shorter compile
 * is a scriptLen hole. Before anything is printed the skeleton is
 * self-verified by rebuilding all four suffixes (length solved as a fixed
 * point) byte for byte, and the state region encoding is checked against the
 * compiler across two states.
 *
 * Usage: node tools/derive-vault-script-skeleton-v7-kas.js [OUT=<json path>]
 * Requires the vendored silverc; exits 2 with REQUIREMENT_NOT_AVAILABLE
 * otherwise. Never touches contracts/ (no covenant bytes change).
 */
const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");
const { loadConfig } = require("../sdk/src/config");
const { compileExactStateV7Kas } = require("../sdk/src/contract-compiler-v7-kas");
const { normalizeStateV7Kas, normalizeTemplateV7Kas } = require("../core/model/vault-state-v7-kas");
const { pushScriptNumHex } = require("../core/intent/vault-script-v7");

const H = (b) => b.toString(16).padStart(2, "0").repeat(32);
const PIN_NAMES = ["vaultId", "orgRootCovenantId", "rootTemplateVmHash", "rootPrefixLen", "rootStateLen", "rootSuffixLen", "recoveryPk"];
const INT_PINS = new Set(["rootPrefixLen", "rootStateLen", "rootSuffixLen"]);

function tokenize(hex) {
  const out = [];
  let p = 0;
  while (p < hex.length) {
    const op = parseInt(hex.slice(p, p + 2), 16);
    let len = 1;
    if (op >= 0x01 && op <= 0x4b) len = 1 + op;
    else if (op === 0x4c) len = 2 + parseInt(hex.slice(p + 2, p + 4), 16);
    else if (op === 0x4d) len = 3 + parseInt(hex.slice(p + 4, p + 6) + hex.slice(p + 2, p + 4), 16);
    else if (op === 0x4e) len = 5 + parseInt(hex.slice(p + 8, p + 10) + hex.slice(p + 6, p + 8) + hex.slice(p + 4, p + 6) + hex.slice(p + 2, p + 4), 16);
    const tok = hex.slice(p, p + len * 2);
    if (tok.length !== len * 2) throw new Error(`truncated push at byte ${p / 2}`);
    out.push(tok);
    p += len * 2;
  }
  return out;
}
const enc = (name, value) => (INT_PINS.has(name) ? pushScriptNumHex(value) : "20" + String(value).toLowerCase());

function main() {
  const outArg = process.argv.find((a) => a.startsWith("OUT=")) || (process.env.OUT ? `OUT=${process.env.OUT}` : null);
  const config = loadConfig({ dataRoot: fs.mkdtempSync(path.join(os.tmpdir(), "pv-kas-skel-")) });
  if (!fs.existsSync(config.silvercPath)) { console.error("REQUIREMENT_NOT_AVAILABLE: vendored silverc not staged"); process.exit(2); }
  const state = normalizeStateV7Kas({ protectedValue: "10000000000", feeReserve: "300000000", paused: "0", agentRoot: H(0xe7), approvers: [H(0xa1), H(0xa2), H(0xa3)], approvalM: "2", policyNonce: "0" });
  const state2 = normalizeStateV7Kas({ protectedValue: "1", feeReserve: "9007199254740991", paused: "1", agentRoot: H(0x00), approvers: [], approvalM: "0", policyNonce: "128" });
  /* equal-width templates: 2-byte int pushes (17..19) and 3-byte int pushes (11077..11079); all 32-byte constants distinct */
  const T = [
    { vaultId: H(0x44), orgRootCovenantId: H(0x52), rootTemplateVmHash: H(0xd5), rootPrefixLen: 17, rootStateLen: 467, rootSuffixLen: 11077, recoveryPk: H(0x51) },
    { vaultId: H(0x45), orgRootCovenantId: H(0x53), rootTemplateVmHash: H(0xd6), rootPrefixLen: 18, rootStateLen: 467, rootSuffixLen: 11078, recoveryPk: H(0x5a) },
    { vaultId: H(0x46), orgRootCovenantId: H(0x54), rootTemplateVmHash: H(0xd7), rootPrefixLen: 19, rootStateLen: 467, rootSuffixLen: 11079, recoveryPk: H(0x5b) }
  ];
  const shorter = { ...T[0], rootPrefixLen: 1 }; /* OP_1: one byte narrower per occurrence -> a different script length */
  const compile = (template, st) => compileExactStateV7Kas({ config, template: normalizeTemplateV7Kas(template), state: st });
  const C = T.map((t) => compile(t, state));
  const D = compile(shorter, state);
  const A2 = compile(T[0], state2);
  for (const c of [...C, D, A2]) {
    if (c.prefixHex !== "6b" || c.stateLayout.start !== 1 || c.stateLayout.len !== 441) throw new Error(`unexpected layout ${JSON.stringify(c.stateLayout)} prefix ${c.prefixHex}`);
    if (c.stateRegionHex.length !== 441 * 2 || c.scriptHex !== c.prefixHex + c.stateRegionHex + c.suffixHex) throw new Error("script != prefix || region || suffix");
  }
  if (C[0].suffixHex !== A2.suffixHex || C[0].prefixHex !== A2.prefixHex) throw new Error("the template (prefix + suffix) varies with the state");
  const toks = C.map((c) => tokenize(c.suffixHex));
  const tokD = tokenize(D.suffixHex);
  if (new Set([...toks.map((t) => t.length), tokD.length]).size !== 1) throw new Error(`token counts differ: ${toks.map((t) => t.length).join("/")} vs shorter ${tokD.length}`);
  const lens = C.map((c) => c.scriptHex.length / 2);
  const lenD = D.scriptHex.length / 2;
  if (lens[0] !== lens[1] || lens[1] !== lens[2] || lenD >= lens[0]) throw new Error(`length classes wrong: ${lens.join("/")} shorter ${lenD}`);
  const holes = [];
  const chunks = [""];
  const holeCounts = {};
  for (let i = 0; i < toks[0].length; i += 1) {
    const [a, b, c] = toks.map((t) => t[i]);
    const d = tokD[i];
    if (a === b && b === c) {
      if (a === pushScriptNumHex(lens[0]) && d === pushScriptNumHex(lenD)) {
        holes.push("scriptLen"); chunks.push(""); holeCounts.scriptLen = (holeCounts.scriptLen || 0) + 1;
      } else {
        if (a !== d) throw new Error(`token ${i} is constant across the equal-width compiles but differs in the shorter compile: ${a} vs ${d}`);
        chunks[chunks.length - 1] += a;
      }
      continue;
    }
    const matches = PIN_NAMES.filter((n) => a === enc(n, T[0][n]) && b === enc(n, T[1][n]) && c === enc(n, T[2][n]) && d === enc(n, shorter[n]));
    if (matches.length !== 1) throw new Error(`token ${i} (${a} / ${b} / ${c} / ${d}) matches ${matches.length} template constants: ${matches.join(",")}`);
    holes.push(matches[0]); chunks.push(""); holeCounts[matches[0]] = (holeCounts[matches[0]] || 0) + 1;
  }
  if (chunks.length !== holes.length + 1) throw new Error("chunk/hole arity");
  /* self-verification: rebuild every compiled suffix from the skeleton (length as a fixed point) */
  const assemble = (template, lenPush) => {
    let out = "";
    for (let i = 0; i < holes.length; i += 1) { out += chunks[i]; out += holes[i] === "scriptLen" ? lenPush : enc(holes[i], template[holes[i]]); }
    return out + chunks[chunks.length - 1];
  };
  const rebuild = (template) => {
    let lenPush = pushScriptNumHex(1 + 441 + assemble(template, "020000").length / 2);
    for (let round = 0; round < 4; round += 1) {
      const suffix = assemble(template, lenPush);
      const next = pushScriptNumHex(1 + 441 + suffix.length / 2);
      if (next === lenPush) return suffix;
      lenPush = next;
    }
    throw new Error("length fixed point did not converge");
  };
  const checks = [[T[0], C[0]], [T[1], C[1]], [T[2], C[2]], [shorter, D]];
  for (const [t, c] of checks) if (rebuild(t) !== c.suffixHex) throw new Error(`self-verification failed for ${JSON.stringify(t.rootPrefixLen)}`);
  const sha256 = crypto.createHash("sha256").update(chunks.join("|") + "#" + holes.join(",")).digest("hex");
  const covenantSha = crypto.createHash("sha256").update(fs.readFileSync(path.join(config.repoRoot, "contracts/PolicyVault.v0.7-kas.sil"))).digest("hex");
  const result = {
    generation: "policyvault-0.7-kas", status: "CANDIDATE (not byte-frozen)", covenantSourceSha256: covenantSha, compilerVersion: C[0].compilerVersion,
    prefixHex: "6b", prefixLen: 1, stateRegionLen: 441, suffixLenAtEqualWidth: C[0].suffixHex.length / 2, scriptLenSamples: { equalWidth: lens[0], shorter: lenD },
    holeCount: holes.length, holeCounts, chunkCount: chunks.length, skeletonSha256: sha256,
    sampleRegionHex: C[0].stateRegionHex, sampleRegion2Hex: A2.stateRegionHex,
    holes, chunks
  };
  const json = JSON.stringify(result);
  if (outArg) { fs.writeFileSync(outArg.slice(4), json); console.log(`wrote ${outArg.slice(4)}`); }
  const { holes: _h, chunks: _c, ...summary } = result; void _h; void _c;
  console.log(JSON.stringify(summary, null, 1));
}
main();
