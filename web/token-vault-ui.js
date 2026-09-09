"use strict";

/*
 * PolicyVault v0.5 / v0.6 TOKEN CONTROLLER — web UI module (Wave 2,
 * Track H-web). Binding API contract:
 * docs/postlaunch/v0.7-app-surface-contract.md §6 (Token and
 * hierarchical-delegation request surfaces). Sibling of web/org-root-ui.js:
 * same shape, same discipline — a headless, DOM-free
 * `createModule({ api, core })` factory. `api` is this app's existing
 * network layer ({ getJSON, postJSON, resolveXOnly }); `core` is
 * `window.PolicyVaultCore` (web/core-bundle.js), the SAME deterministic
 * portable shared core the covenant, the SDK, and the server agree with.
 *
 * WHAT THIS MODULE IS NOT: it never computes a financial fact of its own.
 * Every atomic token amount, every KAS amount, every descriptor hash and
 * every manifest verdict is either read verbatim from a server response or
 * recomputed by a PINNED core function (core.assets, core.agentMerkleV5/V6,
 * core.tokenExplain, core.intentRouter). Amount parsing goes through
 * core.amounts (KAS<->sompi) or core.assets.parseAtomicAmount (token atomic
 * units) ONLY — never Number()/parseFloat on a funds-relevant value.
 *
 * THE SERVER LANE (Track E) FOR /wallet/v5/* AND /wallet/v6/* HAD NOT
 * LANDED WHEN THIS MODULE WAS WRITTEN. This module is built directly
 * against the coordinator contract's route/body shapes (§6.1) and against
 * the REAL, already-frozen core manifest modules those routes must
 * ultimately produce (core/intent/token-manifest-v5.js,
 * core/intent/token-manifest-v6.js, core/intent/swap-manifest-v6.js) — the
 * exact technique docs/postlaunch/v0.7-app-surface-contract.md §3 already
 * sanctions for org-root-ui.js ("until [Track F wires the router], use the
 * bundle's ...verify...Manifest directly"). Every network call in this
 * file is therefore fixture-tested (web/test/token-vault-ui.test.js), not
 * driven against a live server. The one field-shape assumption that is
 * genuinely uncertain is the SERVER'S vault-summary presentation (what
 * `GET /vaults` puts on a v0.5/v0.6 vault entry beyond `contractVersion`);
 * `renderTokenVaultCardHtml` documents and defends against that at its own
 * definition, reading several plausible shapes and never fabricating a
 * missing fact.
 *
 * AUTHORITY BOUNDARY (unchanged, restated): AI MAY REQUEST · POLICYVAULT
 * DETERMINISTICALLY DECIDES · THE COVENANT ENFORCES · SIGNERS RETAIN
 * CUSTODY. A v0.5/v0.6 vault has exactly ONE on-chain owner key
 * (authorityModel SINGLE_ON_CHAIN_OWNER) — this module never presents one
 * as M-of-N.
 *
 * TOKEN / KAS SEPARATION (contract §6.3, permanent product rule): a token
 * controller carries TWO independent accounting domains — the token
 * position (atomic units of the accepted asset) and the KAS fee reserve
 * that pays network fees. They are rendered in separate sections and the
 * verbatim sentence TOKEN_KAS_SENTENCE appears wherever either is shown.
 * v0.6 additionally supports OPTIONAL atomic composability against exactly
 * ONE fixture venue — never a real DEX, never PolicyVault liquidity
 * (CLAUDE.md "PolicyVault MUST NOT become a DEX"). Every swap surface
 * carries VENUE_FIXTURE_NOTICE_SENTENCE verbatim.
 *
 * PENDING IS NOT SUCCESS: contract §6.1 states v0.5/v0.6 requests reuse
 * "the same request/signature/submit/reconcile pattern as
 * /wallet/v4/requests" — the SAME durable RequestState ladder
 * (BUILT -> ... -> CHAIN_VERIFIED) v4.1 already uses. This module therefore
 * does NOT reimplement an outcome table (unlike org-root-ui.js's v0.7
 * ladder, which is genuinely different): the caller renders
 * `request.state` through the app's EXISTING web/refusal-explain.js
 * outcome() / isVerifiedOutcome() / renderOutcomeHtml(), exactly as the v4
 * flow already does (app-v4.js noteOutcome()).
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
   * The two PERMANENT, verbatim sentences this module never re-words.   *
   * ------------------------------------------------------------------ */
  const TOKEN_KAS_SENTENCE = "token amounts and KAS are never converted into each other.";
  const V6_COMPOSABILITY_SENTENCE = "optional atomic composability — no real DEX venue is supported (fixture/conformance only).";
  /* The pre-sign deadlineDaa explanation (contract §6.1: "deadlineDaa is
   * presented as a PRE-SIGN freshness boundary, never a consensus expiry"). */
  const DEADLINE_DAA_SENTENCE =
    "deadlineDaa is a PRE-SIGN freshness boundary this browser checked before asking you to sign, not a consensus expiry — Kaspa enforces no upper time bound on an already-signed transaction. The swap becomes unusable only once its pool outpoint or controller outpoint is actually spent.";

  /* ------------------------------------------------------------------ *
   * The contract's closed §6.1 token/HD refusal vocabulary this module   *
   * may throw locally, fail-closed, before any network round trip or     *
   * before the wallet is ever invoked. The rest are the server's own     *
   * codes, passed through unchanged (refusal-explain.js rule 2).         *
   * ------------------------------------------------------------------ */
  const TOKEN_REFUSAL_CODES = Object.freeze([
    "UNKNOWN_COVENANT_VERSION", "VENUE_PROFILE_UNSUPPORTED", "ASSET_DESCRIPTOR_INVALID", "TOKEN_TEMPLATE_MISMATCH"
  ]);

  const REASON_TO_DISPLAY_CODE = Object.freeze({
    DESCRIPTOR_UNKNOWN_VERSION: "ASSET_DESCRIPTOR_INVALID",
    DESCRIPTOR_MALFORMED: "ASSET_DESCRIPTOR_INVALID",
    DESCRIPTOR_UNKNOWN_STANDARD: "ASSET_DESCRIPTOR_INVALID",
    DESCRIPTOR_MISSING_BINDING: "ASSET_DESCRIPTOR_INVALID",
    DESCRIPTOR_UNKNOWN_FIELD: "ASSET_DESCRIPTOR_INVALID",
    DESCRIPTOR_MISMATCH: "TOKEN_TEMPLATE_MISMATCH",
    DESCRIPTOR_PIN_MISMATCH: "TOKEN_TEMPLATE_MISMATCH",
    TEMPLATE_HASH_MISMATCH: "TOKEN_TEMPLATE_MISMATCH",
    TEMPLATE_GEOMETRY_MISMATCH: "TOKEN_TEMPLATE_MISMATCH",
    TEMPLATE_PIN_MISMATCH: "TOKEN_TEMPLATE_MISMATCH",
    UNKNOWN_MANIFEST_VERSION: "UNKNOWN_COVENANT_VERSION",
    UNKNOWN_COVENANT_VERSION: "UNKNOWN_COVENANT_VERSION"
  });

  function displayCodeFor(e) {
    if (!e) return "UNKNOWN";
    const reason = (e.details && e.details.reason) || null;
    if (reason && REASON_TO_DISPLAY_CODE[reason]) return REASON_TO_DISPLAY_CODE[reason];
    if (reason && TOKEN_REFUSAL_CODES.includes(reason)) return reason;
    if (e.code && REASON_TO_DISPLAY_CODE[e.code]) return REASON_TO_DISPLAY_CODE[e.code];
    if (e.code) return e.code;
    return "UNKNOWN";
  }

  /* contractVersion -> { route, authorityModel, status, composability? } —
   * the ONLY place a "0.5"/"0.6" string turns into an HTTP route segment or
   * a displayed authority claim. An unrecognised contractVersion is NEVER
   * routed to a default (CLAUDE.md fail-closed rule). */
  const CONTRACT_VERSIONS = Object.freeze({
    "policyvault-0.5": Object.freeze({ route: "v5", authorityModel: "SINGLE_ON_CHAIN_OWNER", status: "FROZEN" }),
    "policyvault-0.6": Object.freeze({ route: "v6", authorityModel: "SINGLE_ON_CHAIN_OWNER", status: "FROZEN", composability: "OPTIONAL_ATOMIC", venues: Object.freeze(["FIXTURE"]) })
  });
  function versionInfo(contractVersion) {
    const info = Object.prototype.hasOwnProperty.call(CONTRACT_VERSIONS, String(contractVersion)) ? CONTRACT_VERSIONS[contractVersion] : null;
    if (!info) throw fail(`unknown token covenant version ${JSON.stringify(contractVersion)} — failing closed (never routed to a default)`, "UNKNOWN_COVENANT_VERSION");
    return info;
  }
  const SWAP_ACTIONS = Object.freeze(new Set(["tokenAtomicSell", "tokenAtomicBuy"]));

  /* ==================================================================
   * createModule
   * ================================================================== */
  function createModule({ api, core } = {}) {
    if (!api || typeof api.getJSON !== "function" || typeof api.postJSON !== "function" || typeof api.resolveXOnly !== "function") {
      throw new Error("token-vault-ui: createModule requires api.{getJSON,postJSON,resolveXOnly}");
    }
    if (!core || !core.assets || !core.agentMerkleV5 || !core.agentMerkleV6 || !core.tokenManifestV5 || !core.tokenExplain || !core.controllerManifestV6 || !core.swapManifestV6 || !core.amounts || !core.recipientMerkle || !core.intentRouter) {
      throw new Error("token-vault-ui: createModule requires the v0.5/v0.6 core bundle (core.{assets,agentMerkleV5,agentMerkleV6,tokenManifestV5,tokenExplain,controllerManifestV6,swapManifestV6,amounts,recipientMerkle,intentRouter})");
    }

    function statusRegion(inner, extraClass) {
      return `<div class="opbanner${extraClass ? ` ${extraClass}` : ""}" role="status" aria-live="polite" aria-atomic="true">${inner}</div>`;
    }

    async function resolveKey(raw, label) {
      const s = String(raw || "").trim();
      if (!s) throw fail(`${label} is required`, "ASSET_DESCRIPTOR_INVALID");
      if (HEX64_RE.test(s)) return s.toLowerCase();
      try {
        return (await api.resolveXOnly(s)).toLowerCase();
      } catch (e) {
        throw fail(`${label} "${s}": ${e.message}`, "ADDRESS_INVALID", { cause: e });
      }
    }

    /* ================================================================
     * DESCRIPTOR handling — the asset's hash-verified template pinning.
     * ================================================================ */

    /* Parses a pasted descriptor JSON blob and validates it through the
     * REAL core validator BEFORE anything else touches it — a malformed or
     * unknown-schema descriptor is refused here, locally, never sent to the
     * server and never used to compute anything. */
    function parseAndValidateDescriptor(text) {
      let parsed;
      const s = typeof text === "string" ? text : JSON.stringify(text ?? null);
      try {
        parsed = typeof text === "string" ? JSON.parse(text) : text;
      } catch (e) {
        throw fail(`descriptor is not valid JSON: ${e.message}`, "ASSET_DESCRIPTOR_INVALID", { cause: e });
      }
      try {
        const validated = core.assets.validateAssetDescriptor(parsed);
        return { raw: parsed, validated, descriptorHash: core.assets.computeDescriptorHash(validated), sourceText: s };
      } catch (e) {
        throw fail(e.message, displayCodeFor(e), { cause: e });
      }
    }

    /* ================================================================
     * TOKEN AGENT POLICY — local WF pre-check, mirrors org-root-ui.js's
     * owner-set pre-check discipline: the SAME normalizer the covenant's
     * Merkle-leaf encoding relies on, run in the browser before any
     * network round trip.
     * ================================================================ */
    async function normalizeAgentPolicyForm(form, contractVersion) {
      const { route } = versionInfo(contractVersion);
      const agentPk = await resolveKey(form.agentPk, "agent key");
      const recipients = String(form.recipients || "")
        .split(/[\n,]/)
        .map((s) => s.trim())
        .filter(Boolean);
      let agentRecipientRoot = String(form.agentRecipientRoot || "").trim().toLowerCase();
      let recipientKeys = null;
      if (!HEX64_RE.test(agentRecipientRoot)) {
        if (recipients.length === 0) throw fail("either a 64-hex agentRecipientRoot or at least one allowed recipient is required", "ASSET_DESCRIPTOR_INVALID");
        recipientKeys = [];
        for (const r of recipients) recipientKeys.push(await resolveKey(r, "recipient"));
        try {
          agentRecipientRoot = core.recipientMerkle.buildRecipientTree(recipientKeys).root;
        } catch (e) {
          throw fail(e.message, "ASSET_DESCRIPTOR_INVALID", { cause: e });
        }
      }
      const raw = {
        agentPk,
        tokenMaxPerSpend: String(form.tokenMaxPerSpend ?? ""),
        tokenPeriodBudget: String(form.tokenPeriodBudget ?? ""),
        periodLengthDaa: String(form.periodLengthDaa ?? ""),
        periodStartDaa: String(form.periodStartDaa ?? "0"),
        tokenPeriodSpent: String(form.tokenPeriodSpent ?? "0"),
        agentMaxFeePerTx: String(core.amounts.kasToSompi(form.agentMaxFeePerTxKas ?? "0", "agent max fee per tx")),
        agentMaxCarryKas: String(core.amounts.kasToSompi(form.agentMaxCarryKas ?? "0", "agent max carry")),
        agentRecipientRoot
      };
      if (route === "v6") {
        raw.kasMaxPerSwap = String(core.amounts.kasToSompi(form.kasMaxPerSwapKas ?? "0", "agent max KAS per swap"));
        raw.kasPeriodBudget = String(core.amounts.kasToSompi(form.kasPeriodBudgetKas ?? "0", "agent KAS period budget"));
        raw.kasPeriodSpent = String(core.amounts.kasToSompi(form.kasPeriodSpentKas ?? "0", "agent KAS period spent"));
      }
      /* Local WF re-derivation — this is the EXACT function the leaf
       * Merkle encoding uses; a malformed policy is refused here, never
       * silently sent on. The BigInt-bearing result is used only for local
       * validation/preview; the network body always carries the string
       * form above (BigInt is not JSON-safe). */
      try {
        if (route === "v5") core.agentMerkleV5.normalizeTokenAgentPolicyV5(raw);
        else core.agentMerkleV6.normalizeTokenAgentPolicyV6(raw);
      } catch (e) {
        throw fail(e.message, "ASSET_DESCRIPTOR_INVALID", { cause: e });
      }
      return { policy: raw, recipients: recipientKeys };
    }

    /* ================================================================
     * CREATE — descriptor + token agent policy (contract §6.1).
     * ================================================================ */
    async function normalizeTokenCreateForm(form) {
      const contractVersion = String(form.contractVersion || "").trim();
      const { route } = versionInfo(contractVersion);
      const descriptor = parseAndValidateDescriptor(form.descriptorJson);
      const { policy: agentPolicy, recipients } = await normalizeAgentPolicyForm(form, contractVersion);
      const recoveryAddress = String(form.recoveryAddress || "").trim();
      if (!recoveryAddress) throw fail("a recovery address is required", "ASSET_DESCRIPTOR_INVALID");
      const depositSompi = core.amounts.kasToSompi(form.depositKas ?? "0", "deposit");
      const feeReserveSompi = core.amounts.kasToSompi(form.feeReserveKas ?? "0", "fee reserve");
      const signerAddress = String(form.signerAddress || "").trim();
      if (!signerAddress) throw fail("a funder wallet address is required to sign the creation transaction", "ASSET_DESCRIPTOR_INVALID");
      const body = {
        label: String(form.label || "").trim() || null,
        descriptor: descriptor.raw,
        agentPolicy,
        ...(recipients ? { recipients } : {}),
        recoveryAddress,
        depositKas: String(form.depositKas ?? "0"),
        feeReserveKas: String(form.feeReserveKas ?? "0"),
        signerAddress
      };
      return { contractVersion, route, descriptor, agentPolicy, recipients, depositSompi, feeReserveSompi, body };
    }

    /* "EXACT ASSET POLICY BEFORE SIGNING" — rendered entirely from the
     * locally-validated descriptor + agent policy (real core output),
     * never re-typed UI text. */
    function renderCreatePolicyPanelHtml(normalized) {
      const d = normalized.descriptor.validated;
      const a = normalized.agentPolicy;
      const powers = Object.entries(d.issuerPowers || {}).filter(([, on]) => on).map(([n]) => n);
      return (
        `<div class="panel" data-token-policy="create">` +
        `<h4 style="margin-top:0">EXACT ASSET POLICY BEFORE SIGNING</h4>` +
        `<div class="hint">Recomputed locally from the same descriptor validator and agent-policy normalizer the covenant relies on — not typed UI text.</div>` +
        `<div class="kv-line">Asset: ${esc(d.displayName)} (assetId <span class="mono">${esc(d.assetId)}</span>)</div>` +
        `<div class="kv-line">Descriptor hash (pinned in the controller): <span class="mono" style="word-break:break-all">${esc(normalized.descriptor.descriptorHash)}</span></div>` +
        `<div class="kv-line">${powers.length ? `Declared issuer powers: ${esc(powers.join(", "))} — this asset is ISSUER-CONTROLLED` : "No declared issuer powers (declared-only; PolicyVault cannot discover undeclared powers)"}.</div>` +
        `<div class="kv-line">Agent key: <span class="mono" style="word-break:break-all">${esc(a.agentPk)}</span></div>` +
        `<div class="kv-line">Agent cap per spend: ${esc(a.tokenMaxPerSpend)} atomic units (display ${esc(core.tokenExplain.scaled(a.tokenMaxPerSpend, d.decimalsDisplay))}); period budget ${esc(a.tokenPeriodBudget)} atomic units.</div>` +
        `<div class="kv-line">Deposit: ${esc(core.amounts.sompiToKas(normalized.depositSompi))} KAS. Fee reserve: ${esc(core.amounts.sompiToKas(normalized.feeReserveSompi))} KAS.</div>` +
        `<div class="hint"><b>${esc(TOKEN_KAS_SENTENCE)}</b></div>` +
        `</div>`
      );
    }

    /* ================================================================
     * NETWORK — contract §6.1 routes, exactly.
     * ================================================================ */
    function routeOf(contractVersion) { return versionInfo(contractVersion).route; }

    const createTokenVault = (contractVersion, body) => api.postJSON(`/wallet/${routeOf(contractVersion)}/create`, body);
    const fetchTokenVaultRequests = (contractVersion, vaultId) => api.getJSON(`/wallet/${routeOf(contractVersion)}/requests${vaultId ? `?vaultId=${encodeURIComponent(vaultId)}` : ""}`);
    const fetchTokenVaultRequest = (contractVersion, requestId) => api.getJSON(`/wallet/${routeOf(contractVersion)}/requests/${encodeURIComponent(requestId)}`);

    async function buildTokenRequest({ vaultId, contractVersion, action, params, signerAddress }) {
      const route = routeOf(contractVersion);
      if (!vaultId) throw fail("vaultId is required", "ASSET_DESCRIPTOR_INVALID");
      if (route !== "v6" && SWAP_ACTIONS.has(action)) throw fail(`${action} is a v0.6 atomic-swap action — not available on ${contractVersion}`, "VENUE_PROFILE_UNSUPPORTED");
      const { request } = await api.postJSON(`/wallet/${route}/requests`, { vaultId, action, params: params || {}, signerAddress });
      return request;
    }

    /* A swap request additionally refuses LOCALLY, before any network call,
     * when the caller names a venue that is not the one fixture profile
     * PolicyVault's server knows (contract §6.1: "a request naming any
     * other venue fails closed VENUE_PROFILE_UNSUPPORTED"). This module
     * cannot independently know the server's accepted profile hash without
     * a round trip, so the ONLY local check available is the shape's own
     * declared kind — a real venue-profile object with no fixture marker
     * still reaches the server, which remains the authority; a request
     * that explicitly names a non-fixture kind is refused here. */
    async function buildSwapRequest({ vaultId, action, params, signerAddress }) {
      if (!SWAP_ACTIONS.has(action)) throw fail(`${action} is not an atomic-swap action`, "VENUE_PROFILE_UNSUPPORTED");
      const venueProfile = params && params.venueProfile;
      if (venueProfile && typeof venueProfile === "object" && venueProfile.kind && venueProfile.kind !== "FIXTURE") {
        throw fail(`venue profile ${JSON.stringify(venueProfile.kind)} is not supported — PolicyVault only knows the FIXTURE conformance venue`, "VENUE_PROFILE_UNSUPPORTED");
      }
      return buildTokenRequest({ vaultId, contractVersion: "policyvault-0.6", action, params, signerAddress });
    }

    /*
     * SIGN — single-signer, no M-of-N (contract §6.1 mirrors /wallet/v4/*
     * exactly: a request builds directly into a signable state). BEFORE
     * ever invoking the wallet, the request's OWN manifest (when present)
     * is independently re-verified through core.intentRouter.verifyManifest
     * — the SAME fail-closed router web/verify-intent.js's
     * verifyManifestBeforeSigning uses internally, called directly here
     * exactly as contract §3 already sanctions for org-root-ui.js pending
     * Track F's wiring. A manifest that does not verify, or that carries
     * no manifest at all, refuses DO NOT SIGN.
     */
    async function signTokenRequest({ request, contractVersion, adapter, network, expectedSignerAddress, descriptor, currentDaaScore }) {
      if (!request || !request.transaction || !request.transaction.unsignedSafeJson) throw fail("no build on this request — refusing to sign", "ASSET_DESCRIPTOR_INVALID");
      if (request.manifest) {
        let verification;
        try {
          verification = core.intentRouter.verifyManifest({ manifest: request.manifest, descriptor, currentDaaScore });
        } catch (e) {
          throw fail(`local verification could not run for this request (${e.message}) — refusing to invoke the wallet`, displayCodeFor(e), { cause: e });
        }
        if (verification.verdict !== "VERIFIED") {
          throw fail(`local verification refused this request (${(verification.failures || []).map((f) => f.name).join(", ")}) — refusing to invoke the wallet`, "TOKEN_TEMPLATE_MISMATCH");
        }
      }
      if (!adapter || typeof adapter.signInputs !== "function") throw fail("wallet is not connected", "WALLET_NOT_READY");
      const signed = await adapter.signInputs(request.transaction.unsignedSafeJson, request.transaction.signInputs, { network, expectedSignerAddress });
      if (typeof signed !== "string" || !signed.trim()) throw fail("wallet returned no signed transaction", "INVALID_SIGNATURE_RESPONSE");
      return api.postJSON(`/wallet/${routeOf(contractVersion)}/requests/${encodeURIComponent(request.requestId)}/signature`, { signedSafeJson: signed });
    }

    const submitTokenRequest = (contractVersion, requestId) => api.postJSON(`/wallet/${routeOf(contractVersion)}/requests/${encodeURIComponent(requestId)}/submit`, {});
    const rejectTokenRequest = (contractVersion, requestId, reason) => api.postJSON(`/wallet/${routeOf(contractVersion)}/requests/${encodeURIComponent(requestId)}/reject`, { reason });

    /*
     * DEPOSIT — the token holder's own wallet key signs the token input
     * directly; PolicyVault never holds it (core/explain/token-explain.js
     * "Signer: your own wallet key ... signs the token input — PolicyVault
     * never holds it"). Same build/sign/submit shape, action "tokenDeposit".
     */
    const buildDepositRequest = (args) => buildTokenRequest({ ...args, action: "tokenDeposit" });

    /* Local pre-check for an owner "set agent root" operation: the
     * supplied FULL agent set must reproduce the vault's LIVE agentRoot —
     * refused here, locally, exactly like the SDK builder itself refuses
     * AGENT_ROOT_MISMATCH, before any network round trip. */
    function verifyAgentSetReproducesRoot({ agents, liveAgentRoot, contractVersion }) {
      const route = routeOf(contractVersion);
      const tree = route === "v5" ? core.agentMerkleV5.buildTokenAgentTreeV5(agents) : core.agentMerkleV6.buildTokenAgentTreeV6(agents);
      if (String(tree.root).toLowerCase() !== String(liveAgentRoot || "").toLowerCase()) {
        throw fail("the supplied agent set does not reproduce this vault's live agentRoot — refusing to build a request that would be refused on-chain", "AGENT_ROOT_MISMATCH");
      }
      return tree;
    }

    /* ================================================================
     * REVIEW rendering — DO NOT SIGN gate, same discipline as
     * org-root-ui.js's renderRequestReviewHtml.
     * ================================================================ */
    function renderTokenRequestReviewHtml(request, { descriptor, currentDaaScore } = {}) {
      if (!request || !request.manifest) {
        return statusRegion("No manifest is attached to this request yet — refusing to render a review. Do not sign.", "bad");
      }
      const manifest = request.manifest;
      let verification;
      try {
        verification = core.intentRouter.verifyManifest({ manifest, descriptor, currentDaaScore });
      } catch (e) {
        return statusRegion(`DO NOT SIGN — local verification could not run: ${esc(e.message)}`, "bad");
      }
      const verified = verification.verdict === "VERIFIED";
      let lineDivs;
      if (manifest.manifestVersion === core.tokenManifestV5.TOKEN_MANIFEST_VERSION_1 && descriptor) {
        const doc = core.tokenExplain.explainTokenIntent({ manifest, descriptor });
        const lines = [];
        for (const section of doc.sections) { lines.push(`== ${section.title} ==`); lines.push(...section.lines); }
        lineDivs = lines.map((l) => `<div class="mono" style="padding:0.12rem 0;word-break:break-all">${esc(l)}</div>`).join("");
      } else if (manifest.manifestVersion === core.swapManifestV6.SWAP_MANIFEST_VERSION_1 && Array.isArray(manifest.explanation)) {
        lineDivs = manifest.explanation.map((l) => `<div class="mono" style="padding:0.12rem 0;word-break:break-all">${esc(l)}</div>`).join("");
      } else {
        const checks = (verification.checks || []).map((c) => `${c.ok ? "PASS" : "FAIL"} ${c.name}${c.detail ? `: ${c.detail}` : ""}`);
        lineDivs = [`verdict: ${verification.verdict}`, ...checks].map((l) => `<div class="mono" style="padding:0.12rem 0;word-break:break-all">${esc(l)}</div>`).join("");
      }
      return (
        `<div class="${verified ? "opbanner" : "opbanner bad"}" data-token-review="${verified ? "verified" : "refused"}" role="status" aria-live="polite" aria-atomic="true" style="border-width:2px">` +
        `<b style="color:${verified ? "var(--good)" : "var(--bad)"}">${verified ? "VERIFIED — EXACT REQUEST BEFORE SIGNING" : "DO NOT SIGN — LOCAL VERIFICATION REFUSED"}</b>` +
        `<div style="margin-top:0.4rem;font-size:0.8rem;max-height:18rem;overflow:auto">${lineDivs}</div>` +
        (SWAP_ACTIONS.has(manifest.action && manifest.action.sdkAction) ? `<div class="hint" style="margin-top:0.4rem">${esc(DEADLINE_DAA_SENTENCE)}</div>` : "") +
        `</div>`
      );
    }

    /* v0.6 fixture-venue truth banner — offered on EVERY swap surface. */
    function renderVenueFixtureNoticeHtml() {
      return (
        `<div class="opbanner warn" role="status" aria-live="polite" aria-atomic="true" data-venue="fixture">` +
        `<b>${esc(V6_COMPOSABILITY_SENTENCE)}</b>` +
        `<div class="hint" style="margin-top:0.3rem">${esc(DEADLINE_DAA_SENTENCE)}</div>` +
        `</div>`
      );
    }

    /* ================================================================
     * CARD rendering (contract §6.3). DEFENSIVE field reading: the exact
     * shape of a v0.5/v0.6 GET /vaults entry beyond `contractVersion` is
     * this app's own presenter (Track E), not yet landed when this module
     * was written. This function reads the shape the frozen manifest
     * modules themselves use (`asset.{assetId,displayName,decimalsDisplay}`,
     * `accounting.token.position`, `accounting.kas.feeReserve` — the SAME
     * field names token-manifest-v5.js/v6.js already freeze) with a
     * fallback to the flat `live.feeReserveKas` convention every other
     * vault card in this app already uses, and renders "unavailable" —
     * NEVER a fabricated number — for anything neither shape carries.
     * ================================================================ */
    function tokenBalanceHtml(vault) {
      const asset = vault.asset || {};
      const tokenAcct = (vault.accounting && vault.accounting.token) || {};
      const position = tokenAcct.position ?? tokenAcct.positionAfter ?? (vault.live && vault.live.tokenBalance) ?? null;
      if (position == null) return `<div class="field"><div class="k">Token balance</div><div class="v">unavailable — not yet reported by the server</div></div>`;
      const decimals = Number.isInteger(asset.decimalsDisplay) ? asset.decimalsDisplay : null;
      const display = decimals != null ? ` (display ${esc(core.tokenExplain.scaled(String(position), decimals))})` : "";
      const symbol = asset.displayName ? ` ${esc(asset.displayName)}` : "";
      return `<div class="field"><div class="k">Token balance</div><div class="v">${esc(String(position))} atomic units${symbol}${display}</div></div>`;
    }
    function kasReserveHtml(vault) {
      const kasAcct = (vault.accounting && vault.accounting.kas) || {};
      const reserveSompi = kasAcct.feeReserve ?? kasAcct.successorFeeReserve ?? null;
      if (reserveSompi != null) {
        return `<div class="field"><div class="k">KAS fee reserve</div><div class="v">${esc(core.amounts.sompiToKas(String(reserveSompi)))} KAS</div></div>`;
      }
      if (vault.live && vault.live.feeReserveKas != null) {
        return `<div class="field"><div class="k">KAS fee reserve</div><div class="v">${esc(vault.live.feeReserveKas)} KAS</div></div>`;
      }
      return `<div class="field"><div class="k">KAS fee reserve</div><div class="v">unavailable — not yet reported by the server</div></div>`;
    }

    function renderTokenVaultCardHtml(vault) {
      const { authorityModel, status, composability } = versionInfo(vault.contractVersion);
      const asset = vault.asset || {};
      const badge = vault.status === "PAUSED" ? "PAUSED" : vault.status === "RECOVERED" ? "RECOVERED" : "ACTIVE";
      return (
        `<div class="vault" data-token-vault="${esc(vault.vaultId)}">` +
        `<div class="vault-head"><span class="vault-title">${esc(vault.label || vault.vaultId)}</span> ` +
        `<span><span class="badge ${badge}">${esc(vault.status || "UNKNOWN")}</span> <span class="badge ver">${esc(vault.contractVersion)}</span></span></div>` +
        statusRegion(`authorityModel: ${esc(authorityModel)} · status: ${esc(status)}${composability ? ` · composability: ${esc(composability)}` : ""}`) +
        `<div class="kv-line">Asset identity: ${esc(asset.displayName || "unavailable")} (assetId <span class="mono">${esc(asset.assetId || "unavailable")}</span>)${asset.descriptorHash ? ` · descriptor <span class="mono">${esc(asset.descriptorHash)}</span>` : ""}</div>` +
        `<div class="grid">${tokenBalanceHtml(vault)}${kasReserveHtml(vault)}</div>` +
        `<div class="hint"><b>${esc(TOKEN_KAS_SENTENCE)}</b></div>` +
        (composability ? `<div class="hint" style="margin-top:0.3rem">${esc(V6_COMPOSABILITY_SENTENCE)}</div>` : "") +
        `</div>`
      );
    }

    return {
      /* constants */
      TOKEN_KAS_SENTENCE, V6_COMPOSABILITY_SENTENCE, DEADLINE_DAA_SENTENCE, CONTRACT_VERSIONS, SWAP_ACTIONS, TOKEN_REFUSAL_CODES,
      /* rendering */
      renderCreatePolicyPanelHtml, renderTokenRequestReviewHtml, renderVenueFixtureNoticeHtml, renderTokenVaultCardHtml,
      /* normalization / local pre-checks */
      parseAndValidateDescriptor, normalizeAgentPolicyForm, normalizeTokenCreateForm, verifyAgentSetReproducesRoot,
      /* network */
      routeOf, versionInfo, createTokenVault, fetchTokenVaultRequests, fetchTokenVaultRequest,
      buildTokenRequest, buildSwapRequest, buildDepositRequest, signTokenRequest, submitTokenRequest, rejectTokenRequest,
      /* error display mapping */
      displayCodeFor
    };
  }

  const surface = { createModule, TOKEN_KAS_SENTENCE, V6_COMPOSABILITY_SENTENCE, CONTRACT_VERSIONS };
  if (typeof window !== "undefined") window.PolicyVaultTokenVaultUI = surface;
  if (typeof module !== "undefined" && module.exports) module.exports = surface;
})();
