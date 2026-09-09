"use strict";

/*
 * ADOPTION DOCS TRUTHFULNESS SCAN (Track J, flagship wave 2).
 *
 * Mechanically enforces the claim-discipline rules that apply to every
 * PolicyVault adoption/marketing surface (CLAUDE.md "Claim discipline";
 * docs/postlaunch/flagship-development-program.md §5): docs/adoption/
 * may never claim certification/regulatory status or call internal reviews audits,
 * decentralization/privacy properties, or comparative superiority that
 * has not actually been demonstrated, and may never market real DEX
 * integration (v0.6's venue is a conformance FIXTURE only).
 *
 * This is a scanner over rendered TEXT, not a semantic understanding of
 * truth — it catches the specific forbidden vocabulary the project has
 * been burned by before (see the readiness-matrix "Claim discipline"
 * section), with narrow, EXPLICIT exemptions for the truthful negative
 * forms the project's own rules require it to be able to state (e.g.
 * "PolicyVault is NOT audited", "private key"). Widening an exemption
 * requires the same evidence discipline as any other claim; do not
 * loosen this file to make a doc pass without checking the doc first.
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");

const ADOPTION_DOCS_DIR = path.join(__dirname, "..", "..", "docs", "adoption");

const AUTHORITY_STATEMENT_LINES = [
  "AI MAY REQUEST.",
  "POLICYVAULT DETERMINISTICALLY DECIDES.",
  "THE COVENANT ENFORCES.",
  "SIGNERS RETAIN CUSTODY."
];

/*
 * Bare terms/phrases that may NEVER appear, with no exemption. Checked
 * case-insensitively, word/phrase-boundary matched (\b on each side) so
 * a hyphenated or embedded compound is still caught but an unrelated
 * word sharing a substring (e.g. "upgrade" vs "grade") is not.
 */
const ABSOLUTE_FORBIDDEN = [
  "certified",
  "compliant",
  "compliance",
  /regulator[- ]approved/i,
  /institutional[- ]grade/i,
  /industry[- ]standard/i,
  "best",
  /fully decentrali[sz]ed/i,
  /trustless stablecoin/i,
  /production[- ]verified/i
];

/*
 * Terms that ARE forbidden EXCEPT in one specific, explicit truthful
 * form. Each entry supplies its own exemption check over the raw
 * (original-case) surrounding text; failing the exemption is a hit.
 */
const NEGATION_EXEMPT = [
  {
    name: "audited",
    re: /\baudited\b/gi,
    // Allowed only directly after "not " (e.g. "NOT audited.", "Not audited.").
    isExempt: (text, matchIndex) => /\bnot\s+$/i.test(text.slice(Math.max(0, matchIndex - 12), matchIndex))
  },
  {
    name: "externally reviewed",
    re: /\bexternally reviewed\b/gi,
    isExempt: (text, matchIndex) => /\bnot\s+$/i.test(text.slice(Math.max(0, matchIndex - 12), matchIndex))
  },
  {
    // "private" is forbidden as a standalone privacy/anonymity claim
    // ("PolicyVault is private") but "private key(s)" is the ordinary,
    // unrelated cryptographic term this project uses constantly.
    name: "private",
    re: /\bprivate\b/gi,
    isExempt: (text, matchIndex, matchLength) => /^\s+keys?\b/i.test(text.slice(matchIndex + matchLength, matchIndex + matchLength + 8))
  }
];

/*
 * Non-exhaustive denylist of real, named external DEX/exchange products.
 * PolicyVault must never market "supports <real DEX name>" — v0.6's
 * pool is a conformance FIXTURE only (no real venue). This list cannot
 * be complete; it is a best-effort guard, not a substitute for review.
 */
const REAL_DEX_NAMES = ["uniswap", "pancakeswap", "sushiswap", "curve finance", "1inch", "raydium", "dydx"];

function listMarkdownFiles(dir) {
  return fs
    .readdirSync(dir)
    .filter((f) => f.endsWith(".md"))
    .map((f) => path.join(dir, f));
}

function lineNumberAt(text, index) {
  return text.slice(0, index).split("\n").length;
}

function scanFile(filePath) {
  const text = fs.readFileSync(filePath, "utf8");
  const hits = [];

  for (const entry of ABSOLUTE_FORBIDDEN) {
    const re = entry instanceof RegExp ? new RegExp(entry.source, entry.flags.includes("g") ? entry.flags : entry.flags + "g") : new RegExp(`\\b${entry}\\b`, "gi");
    let m;
    while ((m = re.exec(text)) !== null) {
      hits.push({ term: m[0], line: lineNumberAt(text, m.index) });
      if (m[0].length === 0) re.lastIndex += 1; // never infinite-loop on a zero-width match
    }
  }

  for (const { name, re, isExempt } of NEGATION_EXEMPT) {
    let m;
    while ((m = re.exec(text)) !== null) {
      if (!isExempt(text, m.index, m[0].length)) {
        hits.push({ term: name, line: lineNumberAt(text, m.index) });
      }
    }
  }

  const lower = text.toLowerCase();
  for (const dexName of REAL_DEX_NAMES) {
    if (lower.includes(dexName)) {
      hits.push({ term: `real DEX name: ${dexName}`, line: lineNumberAt(text, lower.indexOf(dexName)) });
    }
  }

  return hits;
}

test("docs/adoption/ exists and is non-empty", () => {
  assert.ok(fs.existsSync(ADOPTION_DOCS_DIR), `expected ${ADOPTION_DOCS_DIR} to exist`);
  const files = listMarkdownFiles(ADOPTION_DOCS_DIR);
  assert.ok(files.length >= 10, `expected at least 10 adoption docs, found ${files.length}`);
});

test("no adoption doc uses forbidden claim vocabulary", () => {
  const files = listMarkdownFiles(ADOPTION_DOCS_DIR);
  const allHits = [];
  for (const file of files) {
    for (const hit of scanFile(file)) {
      allHits.push(`${path.basename(file)}:${hit.line} — ${JSON.stringify(hit.term)}`);
    }
  }
  assert.deepEqual(allHits, [], `forbidden vocabulary found:\n${allHits.join("\n")}`);
});

test("not-a-wallet.md carries the exact four-line authority statement verbatim", () => {
  const filePath = path.join(ADOPTION_DOCS_DIR, "not-a-wallet.md");
  const text = fs.readFileSync(filePath, "utf8");
  for (const line of AUTHORITY_STATEMENT_LINES) {
    assert.ok(text.includes(line), `not-a-wallet.md is missing the authority-statement line: ${JSON.stringify(line)}`);
  }
  // Order matters — assert the four lines appear in sequence, not just
  // present anywhere in the file.
  let cursor = -1;
  for (const line of AUTHORITY_STATEMENT_LINES) {
    const idx = text.indexOf(line, cursor + 1);
    assert.ok(idx > cursor, `authority-statement line out of order or missing: ${JSON.stringify(line)}`);
    cursor = idx;
  }
});

test("every adoption doc is non-trivial (not a stub)", () => {
  const files = listMarkdownFiles(ADOPTION_DOCS_DIR);
  for (const file of files) {
    const text = fs.readFileSync(file, "utf8");
    assert.ok(text.trim().length > 200, `${path.basename(file)} looks like an empty stub (${text.trim().length} chars)`);
  }
});
