"use strict";

/*
 * PolicyVault v0.7 ROOTED HIERARCHICAL-DELEGATION (HD) vault — web UI
 * module (Wave 2, Track H-web). Binding API contract:
 * docs/postlaunch/v0.7-app-surface-contract.md §6 (Token and
 * hierarchical-delegation request surfaces). Sibling of web/org-root-ui.js
 * and web/token-vault-ui.js: same shape, same discipline — a headless,
 * DOM-free `createModule({ api, core })` factory.
 *
 * WHAT AN HD VAULT IS. A `policyvault-0.7-payment-hd` rooted vault is bound
 * to an ON-CHAIN ORGANIZATIONAL ROOT (web/org-root-ui.js's domain — root
 * genesis, owner quorum, freeze) but its OWN spend/delegation authority is
 * a SEPARATE, standalone Merkle forest of "HD leaves" (up to MAX_LEVEL
 * levels deep): a level-1 delegate may itself delegate a NARROWER slice of
 * its own authority to a level-2 child, and a level-2 delegate to a
 * level-3 child. AUTHORITY MAY NEVER INCREASE DESCENDING — every field of
 * a child leaf (maxPerSpend, periodBudget, maxFeePerTx, maxCarryKas,
 * expiryDaa) must be <= its parent's, and this module enforces that LOCALLY
 * (core.hdLeafV7.verifyChildNeverExceedsParent) before ever building a
 * delegation request, exactly like every other WF pre-check in this app.
 * A delegation/spend transaction NEVER touches the organizational root —
 * only the rooted vault's own owner OPERATIONS do (root requests,
 * web/org-root-ui.js's `renderRootedVaultOwnerOpsHtml`).
 *
 * THE SERVER LANE (Track E) FOR THE HD ACTIONS ON /wallet/v7/requests HAD
 * NOT LANDED WHEN THIS MODULE WAS WRITTEN (the existing route only serves
 * the payment profile's tokenAgentSpend/tokenDeposit). This module is
 * built directly against the coordinator contract §6.1 and against the
 * REAL, already-frozen core manifest module
 * (core/intent/org-root-manifest-v7-hd.js) and its explain layer
 * (core/explain/hd-vault-explain.js) — fixture-tested
 * (web/test/hd-vault-ui.test.js), not driven against a live server.
 *
 * EXPIRY (contract §6.1, verbatim, from the pinned core constant — never
 * re-worded in this file): every level's `expiryDaa` is a CONSISTENCY
 * field the core enforces and revocation can act on; it is NOT a Kaspa
 * consensus deadline. `EXPIRY_STATEMENT` below IS
 * core.hdLeafV7.EXPIRY_IS_NOT_CONSENSUS_ENFORCED, read from the core, never
 * retyped.
 *
 * AUTHORITY BOUNDARY: AI MAY REQUEST · POLICYVAULT DETERMINISTICALLY
 * DECIDES · THE COVENANT ENFORCES · SIGNERS RETAIN CUSTODY. This vault's
 * authorityModel is ON_CHAIN_ORGANIZATIONAL_ROOT (it is bound to a root)
 * and its `status` is CANDIDATE (v0.7-payment-hd is NOT covenant-byte-
 * frozen) — never rendered as FROZEN, never rendered as a legacy
 * single-owner vault.
 *
 * No fetch, no storage, no wallet call outside the explicit `adapter`
 * argument the caller injects, no keys, no ambient state.
 */

(function () {
  function esc(s) {
    return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
  }
  const HEX64_RE = /^[0-9a-f]{64}$/i;

  function fail(message, code, extra) {
    return Object.assign(new Error(message), { code, ...(extra || {}) });
  }

  /* ------------------------------------------------------------------ *
   * The contract's closed §6.1 HD refusal vocabulary this module may     *
   * throw locally, fail-closed, before any network round trip. The rest  *
   * are the server's own codes, passed through unchanged.                *
   * ------------------------------------------------------------------ */
  const HD_REFUSAL_CODES = Object.freeze([
    "HD_LEVEL_UNPROVEN", "HD_CHAIN_STALE", "HD_AUTHORITY_EXCEEDS_ANCESTOR",
    "DELEGATION_WHILE_PAUSED", "DELEGATION_WHILE_ROOT_FROZEN", "UNKNOWN_COVENANT_VERSION"
  ]);

  function displayCodeFor(e) {
    if (!e) return "UNKNOWN";
    if (e.code && HD_REFUSAL_CODES.includes(e.code)) return e.code;
    if (e.code) return e.code;
    return "UNKNOWN";
  }

  /* ==================================================================
   * createModule
   * ================================================================== */
  function createModule({ api, core } = {}) {
    if (!api || typeof api.getJSON !== "function" || typeof api.postJSON !== "function" || typeof api.resolveXOnly !== "function") {
      throw new Error("hd-vault-ui: createModule requires api.{getJSON,postJSON,resolveXOnly}");
    }
    if (!core || !core.hdLeafV7 || !core.hdVaultManifestV7 || !core.hdVaultExplain || !core.intentRouter || !core.amounts) {
      throw new Error("hd-vault-ui: createModule requires the v0.7-payment-hd core bundle (core.{hdLeafV7,hdVaultManifestV7,hdVaultExplain,intentRouter,amounts})");
    }
    const hd = core.hdLeafV7;
    const HD_ACTIONS = core.hdVaultManifestV7.HD_ACTIONS; // { hdSpend:{kind,level}, childSpendL2, childSpendL3, delegateSetChildRoot1, delegateSetChildRoot2 }
    const EXPIRY_STATEMENT = hd.EXPIRY_IS_NOT_CONSENSUS_ENFORCED; // read from the core, never retyped
    const MAX_LEVEL = hd.MAX_LEVEL;
    const REVOCATION_ROOT = hd.ZERO_ROOT_HEX;
    const NEVER_TOUCHES_ROOT_STATEMENT = "This transaction does NOT touch your organization's root: a delegate/child leaf is never an owner.";

    function statusRegion(inner, extraClass) {
      return `<div class="opbanner${extraClass ? ` ${extraClass}` : ""}" role="status" aria-live="polite" aria-atomic="true">${inner}</div>`;
    }

    async function resolveKey(raw, label) {
      const s = String(raw || "").trim();
      if (!s) throw fail(`${label} is required`, "HD_LEVEL_UNPROVEN");
      if (HEX64_RE.test(s)) return s.toLowerCase();
      try {
        return (await api.resolveXOnly(s)).toLowerCase();
      } catch (e) {
        throw fail(`${label} "${s}": ${e.message}`, "ADDRESS_INVALID", { cause: e });
      }
    }

    function actionInfo(action) {
      if (action === "tokenDeposit") return { kind: "deposit", level: null };
      const info = HD_ACTIONS[action];
      if (!info) throw fail(`${JSON.stringify(action)} is not a recognised HD action — the maximum proven level is ${MAX_LEVEL}`, "HD_LEVEL_UNPROVEN");
      return info;
    }
    function isDelegationAction(action) { return !!HD_ACTIONS[action] && HD_ACTIONS[action].kind === "delegation"; }
    function isSpendAction(action) { return !!HD_ACTIONS[action] && HD_ACTIONS[action].kind === "spend"; }

    /* ================================================================
     * LOCAL LEAF / CHAIN pre-checks — real core computation, mirrors
     * org-root-ui.js's owner-set pre-check discipline exactly.
     * ================================================================ */

    /* One HD leaf from form fields (string-safe amounts; parseAtomicAmount
     * / parseSompi / parseDaa run INSIDE core.hdLeafV7.normalizeHdLeaf, so
     * a malformed leaf is refused here, locally, before anything else. */
    async function normalizeHdLeafForm(form) {
      const pk = await resolveKey(form.pk, "leaf signer key");
      const recipientRoot = String(form.recipientRoot || "").trim().toLowerCase();
      if (!HEX64_RE.test(recipientRoot)) throw fail("a 64-hex recipientRoot is required (build it from the allowed recipient list first)", "HD_AUTHORITY_EXCEEDS_ANCESTOR");
      const childRoot = String(form.childRoot || REVOCATION_ROOT).trim().toLowerCase();
      const raw = {
        pk,
        maxPerSpend: String(form.maxPerSpend ?? ""),
        periodBudget: String(form.periodBudget ?? ""),
        periodLengthDaa: String(form.periodLengthDaa ?? ""),
        periodStartDaa: String(form.periodStartDaa ?? "0"),
        periodSpent: String(form.periodSpent ?? "0"),
        maxFeePerTx: String(core.amounts.kasToSompi(form.maxFeePerTxKas ?? "0", "leaf max fee per tx")),
        maxCarryKas: String(core.amounts.kasToSompi(form.maxCarryKas ?? "0", "leaf max carry")),
        expiryDaa: String(form.expiryDaa ?? ""),
        recipientRoot,
        childRoot: HEX64_RE.test(childRoot) ? childRoot : REVOCATION_ROOT
      };
      try {
        hd.normalizeHdLeaf(raw);
      } catch (e) {
        throw fail(e.message, "HD_AUTHORITY_EXCEEDS_ANCESTOR", { cause: e });
      }
      return raw;
    }

    /*
     * AUTHORITY MAY NEVER INCREASE DESCENDING — the ONE invariant this
     * module treats as absolute. Refuses locally, BEFORE any network call,
     * naming every field the proposed child would widen.
     */
    function verifyChildNeverExceedsParent(parentLeaf, proposedChildLeaf) {
      let result;
      try {
        result = hd.verifyChildNeverExceedsParent(parentLeaf, proposedChildLeaf);
      } catch (e) {
        throw fail(e.message, "HD_AUTHORITY_EXCEEDS_ANCESTOR", { cause: e });
      }
      if (!result.ok) {
        throw fail(`a child leaf may never exceed its parent's authority — this proposal WIDENS: ${result.violations.join(", ")}`, "HD_AUTHORITY_EXCEEDS_ANCESTOR", { violations: result.violations });
      }
      return result;
    }

    /*
     * Resolve the ancestor CHAIN a spend or delegation at `action`'s level
     * needs, from the OWNER'S OWN maintained level-1 forest (`tree`,
     * hd-leaf-v7 `{leaf, kids}` node format) and `path` (child index per
     * level, oldest first). The forest's root is checked against the
     * vault's LIVE agentRoot FIRST — a stale local copy is refused
     * (HD_CHAIN_STALE) before any proof is even computed, exactly the same
     * "supplied set must reproduce the live root" discipline
     * token-vault-ui.js's verifyAgentSetReproducesRoot and org-root-ui.js's
     * owner-set pre-check already use.
     *
     * Returns { chain (JSON-safe: pathBits as decimal strings),
     * effectiveAuthority } — `chain` is exactly the SDK builder's
     * `params.chain` shape (sdk/src/vault-builders-v7-hd.js
     * resolveHdChain's "precomputed ancestor proof" mode).
     */
    function resolveHdChain({ tree, path, liveAgentRoot, action }) {
      const info = actionInfo(action);
      if (info.kind === "deposit") throw fail("tokenDeposit carries no HD chain", "HD_LEVEL_UNPROVEN");
      const neededLen = info.kind === "delegation" ? info.level : info.level; // spend at level L needs a chain of length L; delegation at level L delegates FROM level L (its own leaf), so also length L
      if (!Array.isArray(path) || path.length < neededLen) {
        throw fail(`${action} needs a path of at least ${neededLen} step(s) — got ${Array.isArray(path) ? path.length : 0}`, "HD_LEVEL_UNPROVEN");
      }
      let root;
      try {
        root = hd.forestRoot(tree);
      } catch (e) {
        throw fail(e.message, "HD_CHAIN_STALE", { cause: e });
      }
      if (String(root).toLowerCase() !== String(liveAgentRoot || "").toLowerCase()) {
        throw fail("the delegation tree this browser is holding does not reproduce the vault's live agentRoot — it is stale; reload the current tree before building this request", "HD_CHAIN_STALE");
      }
      let chainRaw;
      try {
        chainRaw = hd.chainProofs(tree, path.slice(0, neededLen));
      } catch (e) {
        throw fail(e.message, "HD_LEVEL_UNPROVEN", { cause: e });
      }
      const jsonSafeLeaf = (leaf) => ({
        pk: leaf.pk,
        maxPerSpend: leaf.maxPerSpend.toString(),
        periodBudget: leaf.periodBudget.toString(),
        periodLengthDaa: leaf.periodLengthDaa.toString(),
        periodStartDaa: leaf.periodStartDaa.toString(),
        periodSpent: leaf.periodSpent.toString(),
        maxFeePerTx: leaf.maxFeePerTx.toString(),
        maxCarryKas: leaf.maxCarryKas.toString(),
        expiryDaa: leaf.expiryDaa.toString(),
        recipientRoot: leaf.recipientRoot,
        childRoot: leaf.childRoot
      });
      const chain = chainRaw.map((entry) => ({
        leaf: jsonSafeLeaf(entry.leaf),
        siblingsHex: entry.siblingsHex,
        pathBits: entry.pathBits.toString(),
        level: entry.level
      }));
      let effectiveAuthority = null;
      try {
        effectiveAuthority = hd.effectiveAuthority(chainRaw);
      } catch { /* rendering-only convenience; never blocks the request */ }
      return { chain, effectiveAuthority, root };
    }

    /* ================================================================
     * REQUEST building (contract §6.1: POST /wallet/v7/requests extended).
     * `level` is NEVER a caller field on the wire — it is derived from
     * `action` alone, exactly as the contract requires.
     * ================================================================ */
    async function buildHdRequest({ vaultId, action, params, signerAddress, vaultPaused, rootFrozen }) {
      if (!vaultId) throw fail("vaultId is required", "HD_LEVEL_UNPROVEN");
      actionInfo(action); // fail-closed on an unrecognised action, locally
      if (isDelegationAction(action)) {
        if (vaultPaused) throw fail("delegation is refused while the vault is paused", "DELEGATION_WHILE_PAUSED");
        if (rootFrozen) throw fail("delegation is refused while the organizational root is FROZEN", "DELEGATION_WHILE_ROOT_FROZEN");
      }
      const { request } = await api.postJSON("/wallet/v7/requests", { vaultId, action, params: params || {}, signerAddress });
      return request;
    }
    const fetchHdRequests = (vaultId) => api.getJSON(`/wallet/v7/requests${vaultId ? `?vaultId=${encodeURIComponent(vaultId)}` : ""}`);
    const fetchHdRequest = (requestId) => api.getJSON(`/wallet/v7/requests/${encodeURIComponent(requestId)}`);

    /*
     * SIGN — single-signer (no root input; contract §6.1's rooted owner
     * ops stay ROOT REQUESTS — org-root-ui.js's domain — this path is only
     * the delegate/child's own spend or delegation). BEFORE invoking the
     * wallet, the request's own manifest is independently re-verified
     * through core.intentRouter.verifyManifest (routes
     * policyvault-rooted-hd-vault-manifest/1 to
     * core.hdVaultManifestV7.verifyRootedHdVaultManifestV7 — a REAL
     * standalone verifier, unlike the payment profile's owner ops).
     */
    async function signHdRequest({ request, adapter, network, expectedSignerAddress }) {
      if (!request || !request.transaction || !request.transaction.unsignedSafeJson) throw fail("no build on this request — refusing to sign", "HD_LEVEL_UNPROVEN");
      if (request.manifest) {
        let verification;
        try {
          verification = core.intentRouter.verifyManifest({ manifest: request.manifest });
        } catch (e) {
          throw fail(`local verification could not run for this request (${e.message}) — refusing to invoke the wallet`, displayCodeFor(e), { cause: e });
        }
        if (verification.verdict !== "VERIFIED") {
          throw fail(`local verification refused this request (${(verification.failures || []).map((f) => f.name).join(", ")}) — refusing to invoke the wallet`, "HD_CHAIN_STALE");
        }
      }
      if (!adapter || typeof adapter.signInputs !== "function") throw fail("wallet is not connected", "WALLET_NOT_READY");
      const signed = await adapter.signInputs(request.transaction.unsignedSafeJson, request.transaction.signInputs, { network, expectedSignerAddress });
      if (typeof signed !== "string" || !signed.trim()) throw fail("wallet returned no signed transaction", "INVALID_SIGNATURE_RESPONSE");
      return api.postJSON(`/wallet/v7/requests/${encodeURIComponent(request.requestId)}/signature`, { signedSafeJson: signed });
    }
    const submitHdRequest = (requestId) => api.postJSON(`/wallet/v7/requests/${encodeURIComponent(requestId)}/submit`, {});
    const rejectHdRequest = (requestId, reason) => api.postJSON(`/wallet/v7/requests/${encodeURIComponent(requestId)}/reject`, { reason });
    const buildDepositRequest = (args) => buildHdRequest({ ...args, action: "tokenDeposit" });

    /*
     * REVOCATION — a delegateSetChildRoot{1,2} request with the new child
     * root forced to the ZERO root (hd.ZERO_ROOT_HEX). Named explicitly so
     * a caller can never confuse this with an ordinary delegation, and so
     * a UI never has to hand-type the zero root.
     */
    async function buildRevokeDelegationRequest({ vaultId, level, chain, signerAddress, vaultPaused, rootFrozen }) {
      if (level !== 1 && level !== 2) throw fail("revocation is only meaningful at delegating level 1 or 2 (the level whose childRoot is being cleared)", "HD_LEVEL_UNPROVEN");
      const action = level === 1 ? "delegateSetChildRoot1" : "delegateSetChildRoot2";
      return buildHdRequest({ vaultId, action, params: { chain, newChildRoot: REVOCATION_ROOT }, signerAddress, vaultPaused, rootFrozen });
    }

    /* ================================================================
     * ROOTED HD VAULT CREATION — profile is ALWAYS forced to
     * "policyvault-0.7-payment-hd" here; a caller can never accidentally
     * create a different profile through this function.
     * ================================================================ */
    async function createRootedHdVault(rootId, body) {
      const { request } = await api.postJSON(`/org-roots/${encodeURIComponent(rootId)}/vaults`, { ...body, profile: "policyvault-0.7-payment-hd" });
      return request;
    }

    /* ================================================================
     * REVIEW rendering — DO NOT SIGN gate, same discipline as
     * org-root-ui.js / token-vault-ui.js.
     * ================================================================ */
    function renderHdRequestReviewHtml(request) {
      if (!request || !request.manifest) {
        return statusRegion("No manifest is attached to this request yet — refusing to render a review. Do not sign.", "bad");
      }
      const doc = core.hdVaultExplain.structured({ manifest: request.manifest });
      const lines = core.hdVaultExplain.humanReadable({ manifest: request.manifest });
      const lineDivs = lines.map((l) => `<div class="mono" style="padding:0.12rem 0;word-break:break-all">${esc(l)}</div>`).join("");
      const verified = doc.verdict === "VERIFIED_EXACT";
      return (
        `<div class="${verified ? "opbanner" : "opbanner bad"}" data-hd-review="${verified ? "verified" : "refused"}" role="status" aria-live="polite" aria-atomic="true" style="border-width:2px">` +
        `<b style="color:${verified ? "var(--good)" : "var(--bad)"}">${verified ? "VERIFIED — EXACT DELEGATION CHAIN BEFORE SIGNING" : "DO NOT SIGN — LOCAL VERIFICATION REFUSED"}</b>` +
        `<div style="margin-top:0.4rem;font-size:0.8rem;max-height:18rem;overflow:auto">${lineDivs}</div>` +
        `</div>`
      );
    }

    /* The delegation TREE (levels, per-level caps/budgets/counters, the
     * effective intersection at the selected leaf — contract §6.3),
     * rendered from a REAL manifest's own ancestorChain/effectiveAuthority
     * (core/explain/hd-vault-explain.js's structured() output) — never
     * from a UI-invented forest walk. */
    function renderAncestorChainHtml(structuredDoc) {
      if (!structuredDoc || structuredDoc.verdict !== "VERIFIED_EXACT" || !Array.isArray(structuredDoc.ancestorChain)) {
        return statusRegion("No verified ancestor chain to display.", "warn");
      }
      const rows = structuredDoc.ancestorChain.map((l) =>
        `<tr><td>${esc(l.level)}</td><td class="mono" style="word-break:break-all">${esc(l.pk)}</td>` +
        `<td>${esc(l.maxPerSpend)}</td><td>${esc(l.periodBudget)} (spent ${esc(l.periodSpent)})</td>` +
        `<td>${esc(l.maxFeePerTx)}</td><td>${esc(l.maxCarryKas)}</td><td>${esc(l.expiryDaa)}</td>` +
        `<td class="mono" style="word-break:break-all">${esc(l.childRoot)}</td></tr>`
      ).join("");
      const ea = structuredDoc.effectiveAuthority;
      return (
        `<table class="mtable"><thead><tr><th>Level</th><th>Signer key (full)</th><th>Max per spend</th><th>Period budget</th><th>Max fee/tx</th><th>Max carry (sompi)</th><th>Expiry DAA</th><th>childRoot</th></tr></thead>` +
        `<tbody>${rows}</tbody></table>` +
        (ea ? `<div class="kv-line">Effective (intersected) authority at this leaf: maxPerSpend ${esc(ea.maxPerSpend)}, maxFeePerTx ${esc(ea.maxFeePerTx)}, maxCarryKas ${esc(ea.maxCarryKas)} — the TIGHTEST value across every ancestor, never just this leaf's own.</div>` : "") +
        statusRegion(esc(EXPIRY_STATEMENT))
      );
    }

    /* Card rendering (contract §6.3). Same defensive-field-reading
     * discipline as token-vault-ui.js's renderTokenVaultCardHtml: the
     * exact GET /vaults shape for an HD vault is Track E's presenter, not
     * yet landed — this reads what is present and never fabricates what
     * is not. */
    function renderHdVaultCardHtml(vault) {
      const badge = vault.status === "PAUSED" ? "PAUSED" : vault.status === "RECOVERED" ? "RECOVERED" : "ACTIVE";
      return (
        `<div class="vault" data-hd-vault="${esc(vault.vaultId)}">` +
        `<div class="vault-head"><span class="vault-title">${esc(vault.label || vault.vaultId)}</span> ` +
        `<span><span class="badge ${badge}">${esc(vault.status || "UNKNOWN")}</span> <span class="badge ver">${esc(vault.contractVersion || "policyvault-0.7-payment-hd")}</span></span></div>` +
        statusRegion(`authorityModel: ON_CHAIN_ORGANIZATIONAL_ROOT · status: CANDIDATE — hierarchical delegation up to ${esc(String(MAX_LEVEL))} levels.`) +
        (vault.orgRootCovenantId ? `<div class="kv-line">Bound organizational root: <span class="mono" style="word-break:break-all">${esc(vault.orgRootCovenantId)}</span></div>` : "") +
        `<div class="hint">${esc(NEVER_TOUCHES_ROOT_STATEMENT)}</div>` +
        statusRegion(esc(EXPIRY_STATEMENT)) +
        `<div class="hint">Owner operations on this vault are authorized by the organizational root's M-of-N owner quorum — they are created as ROOT REQUESTS, never a single-owner signature.</div>` +
        `<div class="actions">` +
        `<button data-hddelegate="${esc(vault.vaultId)}">Delegate (create a child)</button>` +
        `<button class="warn" data-hdrevoke="${esc(vault.vaultId)}">Revoke a delegation</button>` +
        `<button data-hdspend="${esc(vault.vaultId)}">Spend</button>` +
        `</div>` +
        `</div>`
      );
    }

    return {
      /* constants */
      EXPIRY_STATEMENT, MAX_LEVEL, REVOCATION_ROOT, HD_ACTIONS, HD_REFUSAL_CODES, NEVER_TOUCHES_ROOT_STATEMENT,
      /* action classification */
      actionInfo, isDelegationAction, isSpendAction,
      /* local pre-checks */
      normalizeHdLeafForm, verifyChildNeverExceedsParent, resolveHdChain,
      /* rendering */
      renderHdRequestReviewHtml, renderAncestorChainHtml, renderHdVaultCardHtml,
      /* network */
      buildHdRequest, fetchHdRequests, fetchHdRequest, signHdRequest, submitHdRequest, rejectHdRequest,
      buildDepositRequest, buildRevokeDelegationRequest, createRootedHdVault,
      /* error display mapping */
      displayCodeFor
    };
  }

  const surface = { createModule };
  if (typeof window !== "undefined") window.PolicyVaultHdVaultUI = surface;
  if (typeof module !== "undefined" && module.exports) module.exports = surface;
})();
