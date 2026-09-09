"use strict";

/*
 * PolicyVault v0.7-payment-hd HIERARCHICAL DELEGATION — SIGNER-VISIBLE
 * EXPLANATIONS (v1). Wave 2 Track D, gate I2. Sibling of
 * core/explain/org-root-explain.js, same discipline, scoped to
 * `policyvault-rooted-hd-vault-manifest/1`
 * (core/intent/org-root-manifest-v7-hd.js) — the five HD spend/delegation
 * entrypoints, which are STANDALONE verifiable (they never touch the
 * organizational root; the HD vault's owner operations are explained by
 * core/explain/org-root-explain.js, exactly like the payment profile's).
 *
 *   structured({ manifest }) -> a stable, versioned, JSON-safe explanation
 *     document ("policyvault-hd-vault-explanation/1");
 *   humanReadable({ manifest }) -> deterministic FIXED lines a signer reads
 *     BEFORE producing the spending/delegating leaf's signature.
 *
 * WHAT THIS LAYER EXISTS TO SHOW (design record §1.3, freeze record §2):
 *   - the FULL ANCESTOR CHAIN, every level, in order — never just the
 *     leaf's own advertised numbers;
 *   - the EFFECTIVE (intersected) authority a spend is actually bound by;
 *   - for a delegation: EXACTLY which level delegates, to what new
 *     childRoot, and that every other field is pinned equal;
 *   - the HONEST EXPIRY STATEMENT verbatim — expiryDaa is a consistency
 *     field, never a consensus deadline;
 *   - that the organizational root is NEVER involved in this transaction.
 *
 * BINDING RULES (same as org-root-explain.js):
 *   - The manifest is INDEPENDENTLY RE-VERIFIED here
 *     (verifyRootedHdVaultManifestV7). No caller-supplied verdict is
 *     accepted.
 *   - A non-VERIFIED manifest renders ONLY a prominent REFUSAL naming every
 *     failing check — never a normal approval screen.
 *   - Unknown manifest versions refuse (no default route).
 *   - NO truncation of keys/ids/amounts.
 *   - Every amount renders as an integer sompi string alongside a KAS/atomic
 *     display value — never a JS float.
 *
 * Both entry points are TOTAL: they never throw.
 *
 * Portable shared core: pure CommonJS, zero external dependencies.
 */

const { verifyRootedHdVaultManifestV7, ROOTED_HD_VAULT_MANIFEST_VERSION_1 } = require("../intent/org-root-manifest-v7-hd");

const HD_EXPLANATION_VERSION_1 = "policyvault-hd-vault-explanation/1";
const EXPLANATION_VERDICTS = Object.freeze({ VERIFIED_EXACT: "VERIFIED_EXACT", REFUSED: "REFUSED" });

function deepFreeze(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const k of Object.keys(value)) deepFreeze(value[k]);
  }
  return value;
}
function isPlainObject(v) {
  if (v === null || typeof v !== "object" || Array.isArray(v)) return false;
  const proto = Object.getPrototypeOf(v);
  return proto === Object.prototype || proto === null;
}
/* Same untrusted-text sanitization as org-root-explain.js's sanitizeDetail
 * (hostile review H-1): collapse control/bidi-override characters so a
 * crafted manifest field can never inject a fake verdict line. */
function sanitizeDetail(value) {
  const s = String(value == null ? "" : value);
  let out = "";
  for (const ch of s) {
    const c = ch.codePointAt(0);
    const isControl = c <= 0x1f || (c >= 0x7f && c <= 0x9f);
    const isBidi = (c >= 0x202a && c <= 0x202e) || (c >= 0x2066 && c <= 0x2069);
    out += isControl || isBidi ? " " : ch;
  }
  out = out.replace(/ +/g, " ").trim();
  return out.length > 500 ? `${out.slice(0, 497)}...` : out;
}

function baseDocument() {
  return {
    explanationVersion: HD_EXPLANATION_VERSION_1,
    verdict: null,
    statement: null,
    refusal: null,
    manifestHash: null,
    txId: null,
    network: null,
    vault: null,
    action: null,
    ancestorChain: null,
    effectiveAuthority: null,
    delegation: null,
    payment: null,
    expiryStatement: null,
    fee: null,
    verification: null
  };
}

function refusalDocument({ reason, failures, manifestHash = null, txId = null, verification = null }) {
  const names = [...new Set(failures.map((f) => f.name))].sort();
  const doc = baseDocument();
  doc.verdict = EXPLANATION_VERDICTS.REFUSED;
  doc.refusal = { reason: String(reason), failingChecks: names, failures: failures.map((f) => ({ name: String(f.name), detail: f.detail == null ? null : String(f.detail) })) };
  doc.manifestHash = manifestHash;
  doc.txId = txId;
  doc.verification = verification;
  return deepFreeze(doc);
}

function leafSummary(entry) {
  const l = entry.leaf;
  return {
    level: entry.level,
    pk: l.pk,
    maxPerSpend: l.maxPerSpend,
    periodBudget: l.periodBudget,
    periodSpent: l.periodSpent,
    periodLengthDaa: l.periodLengthDaa,
    periodStartDaa: l.periodStartDaa,
    maxFeePerTx: l.maxFeePerTx,
    maxCarryKas: l.maxCarryKas,
    expiryDaa: l.expiryDaa,
    recipientRoot: l.recipientRoot,
    childRoot: l.childRoot
  };
}

function structured(input) {
  const { manifest } = input && typeof input === "object" ? input : {};
  try {
    if (!isPlainObject(manifest)) {
      return refusalDocument({ reason: "No hierarchical-delegation vault manifest was supplied — failing closed.", failures: [{ name: "manifestSupplied", detail: "an HD vault manifest object is required" }] });
    }
    if (manifest.manifestVersion !== ROOTED_HD_VAULT_MANIFEST_VERSION_1) {
      return refusalDocument({
        reason: "Unknown manifest version — failing closed (no default route).",
        failures: [{ name: "manifestVersion", detail: `expected ${ROOTED_HD_VAULT_MANIFEST_VERSION_1}, got ${JSON.stringify(manifest.manifestVersion)}` }],
        manifestHash: typeof manifest.manifestHash === "string" ? manifest.manifestHash : null
      });
    }

    /* INDEPENDENT re-verification — never a caller-supplied verdict. */
    const verification = verifyRootedHdVaultManifestV7({ manifest });
    const verificationSummary = { verdict: verification.verdict, checks: verification.checks.map((c) => ({ name: c.name, ok: c.ok })), failingChecks: [...new Set(verification.failures.map((f) => f.name))].sort() };
    if (verification.verdict !== "VERIFIED") {
      return refusalDocument({
        reason: "This hierarchical-delegation approval FAILED local verification against the frozen transaction it describes and must not be signed.",
        failures: verification.failures.map((f) => ({ name: f.name, detail: f.detail })),
        manifestHash: typeof manifest.manifestHash === "string" ? manifest.manifestHash : null,
        txId: manifest.transaction && typeof manifest.transaction.txId === "string" ? manifest.transaction.txId : null,
        verification: verificationSummary
      });
    }

    const doc = baseDocument();
    doc.verdict = EXPLANATION_VERDICTS.VERIFIED_EXACT;
    doc.statement = verification.statement;
    doc.manifestHash = manifest.manifestHash;
    doc.txId = manifest.transaction.txId;
    doc.network = { networkId: manifest.network.networkId };
    doc.vault = { covenantId: manifest.vault.covenantId, vaultId: manifest.vault.vaultId, contractVersion: manifest.vault.contractVersion, orgRootCovenantId: manifest.vault.orgRootCovenantId };
    doc.action = { sdkAction: manifest.action.sdkAction, kind: manifest.action.kind, level: manifest.action.level, neverTouchesRoot: manifest.action.requiresRootInput === false };
    doc.ancestorChain = manifest.ancestorChain.map(leafSummary);
    doc.effectiveAuthority = manifest.effectiveAuthority
      ? { maxPerSpend: manifest.effectiveAuthority.maxPerSpend, maxFeePerTx: manifest.effectiveAuthority.maxFeePerTx, maxCarryKas: manifest.effectiveAuthority.maxCarryKas, expiryDaa: manifest.effectiveAuthority.expiryDaa, perLevelBudgets: manifest.effectiveAuthority.perLevelBudgets }
      : null;
    doc.delegation = manifest.delegation ? { delegatingParentLevel: manifest.delegation.delegatingParentLevel, newChildRoot: manifest.delegation.newChildRoot } : null;
    doc.payment = manifest.action.kind === "spend" ? { recipient: manifest.accounting.token.recipient, spendAmount: manifest.accounting.token.spendAmount, positionBefore: manifest.accounting.token.positionBefore, positionAfter: manifest.accounting.token.positionAfter } : null;
    doc.expiryStatement = manifest.expiryStatement;
    doc.fee = { requiredFeeSompi: manifest.transaction.requiredFeeSompi, computeBudget: manifest.transaction.computeBudget, reserveConsumed: manifest.accounting.kas.reserveConsumed };
    doc.verification = verificationSummary;
    return deepFreeze(doc);
  } catch (e) {
    return refusalDocument({ reason: "An internal error occurred while explaining this manifest — failing closed, never rendered as a normal approval.", failures: [{ name: "internalError", detail: `${e && e.code ? e.code : "ERROR"}: ${e && e.message ? e.message : String(e)}` }] });
  }
}

function refusalLines(doc) {
  const lines = [];
  lines.push("!! DO NOT SIGN !!");
  lines.push("HIERARCHICAL-DELEGATION APPROVAL REFUSED — this description FAILED verification and must not be signed.");
  lines.push(`Reason: ${sanitizeDetail(doc.refusal.reason)}`);
  lines.push(`Failing checks: ${doc.refusal.failingChecks.join(", ")}.`);
  for (const f of doc.refusal.failures) lines.push(`- ${f.name}: ${sanitizeDetail(f.detail)}`);
  if (doc.txId !== null) lines.push(`Transaction id (NOT verified): ${sanitizeDetail(doc.txId)}.`);
  if (doc.manifestHash !== null) lines.push(`Manifest hash (NOT verified): ${sanitizeDetail(doc.manifestHash)}.`);
  lines.push("A refused approval is never rendered as a normal transaction summary. Rebuild the request and verify again.");
  return lines;
}

function verifiedLines(doc) {
  const lines = [];
  const isSpend = doc.action.kind === "spend";
  lines.push(`HIERARCHICAL-DELEGATION ${isSpend ? "SPEND" : "DELEGATION"} — ${doc.action.sdkAction} (level ${doc.action.level}).`);
  lines.push(`Vault ${doc.vault.covenantId} (id ${doc.vault.vaultId}). This transaction does NOT touch your organization's root: a delegate/child leaf is never an owner.`);
  lines.push(`Ancestor chain (${doc.ancestorChain.length} level(s), oldest first):`);
  for (const l of doc.ancestorChain) {
    lines.push(`  Level ${l.level}: signer key ${l.pk}, maxPerSpend ${l.maxPerSpend}, periodBudget ${l.periodBudget} (spent ${l.periodSpent} so far this period), maxFeePerTx ${l.maxFeePerTx}, maxCarryKas ${l.maxCarryKas}, expiryDaa ${l.expiryDaa}, childRoot ${l.childRoot}.`);
  }
  if (doc.effectiveAuthority) {
    lines.push(`Effective (intersected) authority for this spend: maxPerSpend ${doc.effectiveAuthority.maxPerSpend}, maxFeePerTx ${doc.effectiveAuthority.maxFeePerTx}, maxCarryKas ${doc.effectiveAuthority.maxCarryKas} — the TIGHTEST value across every ancestor, never just this leaf's own.`);
  }
  if (doc.payment) {
    lines.push(`Paying ${doc.payment.spendAmount} (atomic units) to ${doc.payment.recipient}. Token position: ${doc.payment.positionBefore} -> ${doc.payment.positionAfter}.`);
  }
  if (doc.delegation) {
    lines.push(`Delegation: level ${doc.delegation.delegatingParentLevel} parent's childRoot is being set to ${doc.delegation.newChildRoot}. Every OTHER field of that parent's leaf (caps, budgets, expiry, recipient allowlist) is UNCHANGED — a delegation can only narrow authority for the subtree it names, never widen it.`);
  }
  lines.push(`Expiry: ${doc.expiryStatement}`);
  lines.push(`Network fee: ${doc.fee.requiredFeeSompi} sompi (compute budget ${doc.fee.computeBudget}); vault fee reserve consumed: ${doc.fee.reserveConsumed} sompi.`);
  lines.push(`Network: ${doc.network.networkId}. Transaction id: ${doc.txId}. Manifest hash: ${doc.manifestHash}.`);
  lines.push(`Verification: PASSED — ${doc.statement}`);
  return lines;
}

function humanReadable(input) {
  const doc = structured(input);
  const lines = doc.verdict === EXPLANATION_VERDICTS.VERIFIED_EXACT ? verifiedLines(doc) : refusalLines(doc);
  return deepFreeze(lines);
}

module.exports = {
  HD_EXPLANATION_VERSION_1,
  EXPLANATION_VERDICTS,
  structured,
  humanReadable
};
