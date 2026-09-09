"use strict";

/*
 * PolicyVault — REFUSAL AND OUTCOME EXPLANATIONS (TRACK 11 flagship
 * UX pass).
 *
 * THIS RENDERS; IT IS NOT AN AUTHORITY. Nothing here decides, softens,
 * retries, or works around a refusal. It turns the refusal the SERVER (or
 * the browser's own fail-closed pre-sign gate) already produced into a
 * plain-language explanation plus the honest next step, so a refusal stops
 * being an unexplained machine code in a red bar.
 *
 * Rules this module obeys, permanently:
 *
 *  1. CLOSED TABLE, FAIL-CLOSED. `explain()` answers ONLY for codes that
 *     are actually emitted by this codebase (each entry below was traced
 *     to its throw site). An unknown or absent code returns null and the
 *     renderer shows the server's message VERBATIM with an explicit "no
 *     closed explanation for this code" line. It NEVER guesses at, pattern-
 *     matches, or invents a meaning — a fabricated explanation of a
 *     funds-safety refusal is worse than a bare code.
 *  2. THE SERVER'S MESSAGE IS ALWAYS SHOWN. The explanation is added
 *     ALONGSIDE the exact code and message, never instead of them: the
 *     specific detail (which limit, which amount, which key) lives in the
 *     server's message and must reach the user and any support channel.
 *  3. NO PROCEED-ANYWAY. No entry offers an override, a bypass, or a
 *     "try again ignoring this"; `next` steps only ever describe the
 *     lawful path (connect the right wallet, collect the approvals,
 *     verify the vault, fund the owner address, rebuild the request).
 *  4. TRUTHFUL AUTHORITY LANGUAGE. Hosted-layer refusals say so and say
 *     what they cannot do; covenant-enforced limits say so. Vault owner
 *     authority is ONE on-chain owner key in every shipped covenant
 *     generation — an organization in this application is metadata and
 *     grants nobody owner authority, and that is stated where it matters.
 *
 * The OUTCOME half of this module (see OUTCOMES below) obeys one extra
 * rule, the most important one in the file:
 *
 *  5. PENDING IS NOT SUCCESS, AND AN UNKNOWN STATE IS NOT SUCCESS. Exactly
 *     one durable request state — CHAIN_VERIFIED — is chain-proven success.
 *     Every other state, INCLUDING one this table does not recognise,
 *     renders as NOT YET CONFIRMED with the honest next step. There is no
 *     path by which an unrecognised state can be presented as done.
 *
 * No fetch, no storage, no wallet, no keys, no state.
 */

(function () {
  function esc(s) {
    return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
  }

  /* ------------------------------------------------------------------ *
   * The closed table. Each key is a code this codebase actually throws.  *
   *   title   — what happened, in the user's terms                       *
   *   meaning — why, truthfully, including where it was enforced         *
   *   next    — the lawful next step(s); never an override               *
   * ------------------------------------------------------------------ */
  const TABLE = {
    /* ---- authorization / role (server/src/api.js v4Error) ---- */
    NOT_OWNER: {
      title: "This wallet is not the vault owner",
      meaning:
        "Owner actions (pause, top up, add or remove an agent, set approvers, close & recover) are authorized by the vault's owner key, which is committed on-chain. The connected wallet is a different key. A vault has exactly ONE on-chain owner key — organizations and their member roles in this application are metadata and grant no owner authority.",
      next: ["Connect the owner wallet in the Wallet panel, then retry the action."]
    },
    NOT_AGENT: {
      title: "This wallet is not an agent of this vault",
      meaning: "Spending is authorized only for a key in the vault's on-chain agent registry. The connected wallet is not one of them.",
      next: ["Connect the agent wallet that the owner registered.", "Or ask the vault owner to add this key as an agent, with its own limits."]
    },
    AUTHORIZATION_FAILED: {
      title: "The connected wallet may not perform this action",
      meaning: "PolicyVault refused before building anything: the signer has no role that authorizes this action on this vault.",
      next: ["Check which wallet is connected in the Wallet panel.", "The vault card shows the role this wallet has, if any."]
    },
    UNKNOWN_APPROVER: {
      title: "This wallet is not one of the vault's approvers",
      meaning: "Approvals are accepted only from the covenant approver keys recorded on the vault itself. An organization role labelled \"approver\" in this application is NOT a covenant approver.",
      next: ["Connect one of the approver wallets set on this vault.", "The owner can change the approver set with Set approvers."]
    },

    /* ---- policy / build ---- */
    BUILD_FAILED: {
      title: "PolicyVault refused to build this transaction",
      meaning: "The request did not satisfy this vault's rules or its current state, so no transaction was created and nothing was signed or sent. The exact reason is in the message above.",
      next: ["Read the message above — it names the limit, amount, or value that failed.", "Adjust the request to fit the policy and try again."]
    },
    INSUFFICIENT_APPROVALS: {
      title: "Not enough approvals yet",
      meaning: "This spend is above the vault's approval threshold, so the required number of approver signatures must be collected before the agent can sign. The covenant enforces this — the server cannot waive it.",
      next: ["The approval card on the vault shows the progress (collected of required).", "Each approver signs from their own wallet; the agent signs last."]
    },
    INSUFFICIENT_FUEL: {
      title: "Not enough ordinary funds to pay the network fee",
      meaning: "Owner operations are paid from an ordinary (non-vault) UTXO belonging to the owner wallet. Vault principal is never used for this.",
      next: ["Send KAS to the connected owner address, wait for it to confirm, then retry."]
    },
    FUEL_REQUIRED: {
      title: "This action needs a funding input",
      meaning: "The transaction requires an ordinary owner-owned UTXO to pay the network fee, and none was supplied or found.",
      next: ["Send KAS to the connected owner address, wait for it to confirm, then retry."]
    },
    AGENT_SUSPENDED_HOSTED: {
      title: "This agent is suspended at the hosted layer",
      meaning:
        "This PolicyVault server is refusing new requests for this agent. This is a coordination control only — it is NOT enforced by the covenant, and it cannot stop a holder of the agent key submitting transactions directly to a Kaspa node.",
      next: [
        "The vault owner can lift the suspension (Unsuspend) on the vault card.",
        "For protection that binds on-chain, the owner must use Pause, Remove agent, or Close & recover — those are covenant-enforced."
      ]
    },

    /* ---- vault / request state ---- */
    STALE: {
      title: "The vault moved on before this was submitted",
      meaning: "The vault's on-chain state changed after this transaction was built, so the transaction no longer applies. Nothing was broadcast.",
      next: ["The view reloads the current state — build the action again from the fresh state."]
    },
    CLAIM_CONFLICT: {
      title: "Another transaction for this vault is still unresolved",
      meaning: "PolicyVault records a durable claim before broadcasting so a crash can never leave the outcome ambiguous. One is still open for this vault, so a second transaction is refused rather than risking a conflicting spend.",
      next: ["Use Verify state on the vault to reconcile the open claim against the chain, then retry."]
    },
    RECONCILIATION_REQUIRED: {
      title: "The vault must be verified against the chain first",
      meaning: "PolicyVault cannot act on a vault whose exact on-chain state it has not confirmed. It fails closed instead of assuming.",
      next: ["Use Verify state on the vault card, then retry the action."]
    },
    VAULT_TERMINAL: {
      title: "This vault is closed",
      meaning: "The vault was recovered or otherwise terminated. It is permanently read-only history; no transaction can be built for it.",
      next: ["Create a new vault for new activity. The closed vault's history stays visible in Details and Activity."]
    },
    VERSION_CONFLICT: {
      title: "Someone else changed this first",
      meaning: "This record changed after the form was loaded. PolicyVault refuses to overwrite the newer version blindly.",
      next: ["The current version is reloaded — re-apply the change against it and save again."]
    },
    ORG_NOT_EMPTY: {
      title: "The organization still has vaults assigned",
      meaning: "Deleting an organization is permanent, so it is only possible once nothing is assigned to it. This is application metadata; no vault or on-chain state is affected either way.",
      next: ["Move or unassign the vaults listed under the organization, then delete it."]
    },
    ADDRESS_INVALID: {
      title: "That address was rejected",
      meaning: "The address is malformed, has a bad checksum, is an unsupported type, or belongs to a different Kaspa network than this server is configured for.",
      next: ["Paste the address again from the wallet that owns it, and check it is for this network."]
    },

    /* ---- signing / submission ---- */
    WALLET_REJECTED: {
      title: "The signature was declined in the wallet",
      meaning: "Nothing was signed and nothing was broadcast. The vault is unchanged.",
      next: ["Retry the action and approve it in the wallet popup if it is what you intended."]
    },
    USER_REJECTED: {
      title: "You declined the request in your wallet",
      meaning: "Nothing was signed and nothing was broadcast. The vault is unchanged.",
      next: ["Retry the action when you are ready."]
    },
    WALLET_NOT_READY: {
      title: "The wallet is not connected on the required network",
      meaning: "PolicyVault will not open a signing prompt unless the wallet is connected and on the exact network this server's node reports.",
      next: ["Connect the wallet in the Wallet panel and switch it to the network shown in the banner at the top of the page."]
    },
    SIGNER_MISMATCH: {
      title: "The connected wallet is not the expected signer",
      meaning: "This transaction was built for a specific signing key. PolicyVault refuses to open a wallet prompt for a different account rather than producing a signature that cannot be used.",
      next: ["Switch the wallet to the account named above, or rebuild the action from the account you want to sign with."]
    },
    SIGNER_CHANGED: {
      title: "The wallet account changed while signing",
      meaning: "The account or network changed between opening the wallet prompt and receiving the signature. The signature was discarded and nothing was submitted.",
      next: ["Set the wallet to the account you intend to sign with, then rebuild the action."]
    },
    SIGN_INPUTS_INVALID: {
      title: "The signing metadata was not the canonical frozen form",
      meaning: "PolicyVault refused to invoke the wallet because the per-input signing metadata was not the exact frozen { index, sighashType: 1 } this application emits. This is a fail-closed guard against a malformed wallet call.",
      next: ["Reload the page and rebuild the action.", "If it happens again, report it with the code above — do not include any key material."]
    },
    SIGNATURE_INVALID: {
      title: "The signature did not verify",
      meaning: "The server independently re-checked the returned signature against the exact frozen transaction and rejected it. Nothing was broadcast.",
      next: ["Rebuild the action and sign again with the correct account."]
    },
    PREFLIGHT_FAILED: {
      title: "The final pre-broadcast check refused this transaction",
      meaning: "After signing, PolicyVault re-validates the complete transaction before it is allowed near the network. It did not pass, so it was never broadcast.",
      next: ["Rebuild the action. The message above names what failed."]
    },
    SUBMISSION_REJECTED: {
      title: "The Kaspa node rejected the transaction",
      meaning: "The transaction reached the node and consensus refused it. It is not on the chain and the vault is unchanged.",
      next: ["Use Verify state on the vault, then rebuild the action from the confirmed state."]
    },
    NETWORK_MISMATCH: {
      title: "Wrong Kaspa network",
      meaning: "The wallet, the request, and this server's node must all be on the same network. They are not, so PolicyVault fails closed.",
      next: ["Switch the wallet to the network shown in the banner at the top of the page."]
    },

    /* ---- browser-local pre-sign verification (fail-closed; no override) ---- */
    VERIFICATION_REQUIRED: {
      title: "This browser produced no verification result — DO NOT SIGN",
      meaning: "PolicyVault re-derives what a transaction does in your own browser before the wallet is ever opened. No result exists for this one, so the wallet was not invoked.",
      next: ["Reload the page and rebuild the action.", "There is no proceed-anyway path, by design."]
    },
    VERIFICATION_REFUSED: {
      title: "This browser REFUSED this transaction — DO NOT SIGN",
      meaning: "Independent re-derivation in your browser disagreed with what the transaction claims to do. It was never sent to the wallet.",
      next: ["Do not sign it anywhere else either.", "Rebuild the action and verify again. Report the refusal codes above if it repeats."]
    },
    VERIFICATION_TX_BINDING_MISMATCH: {
      title: "The verified transaction is not the one being signed — DO NOT SIGN",
      meaning: "The payload that passed verification and the payload about to be signed are not the same bytes. PolicyVault refuses to invoke the wallet.",
      next: ["Reload the page and rebuild the action.", "Report this with the code above if it repeats."]
    },

    /* ---- hosted session ---- */
    AUTH_REQUIRED: {
      title: "Sign in to continue",
      meaning: "This is a hosted PolicyVault server and the action needs an authenticated session. Connecting a wallet is not the same as signing in.",
      next: ["Use Sign in in the Wallet panel, then retry."]
    },
    SESSION_EXPIRED: {
      title: "Your session expired",
      meaning: "The hosted session timed out. Nothing was changed.",
      next: ["Sign in again in the Wallet panel, then retry."]
    },
    SESSION_INVALID: {
      title: "Your session is no longer valid",
      meaning: "The server rejected the session — it may have been signed out elsewhere or invalidated. Nothing was changed.",
      next: ["Sign in again in the Wallet panel, then retry."]
    },

    /* ---- hosted workflow gates (handled by their own UI when loaded) ---- */
    GOVERNANCE_PROPOSAL_REQUIRED: {
      title: "This change needs a governance proposal first",
      meaning: "The organization's hosted controls require this authority change to go through a proposal and approval ceremony before PolicyVault will build it. This is hosted coordination above the covenant, not a covenant rule.",
      next: ["Create the proposal and collect its approvals, then retry the same action."]
    },
    RISK_REVIEW_REQUIRED: {
      title: "This action is on hold for review",
      meaning: "The organization's hosted risk controls put this action on hold. This is hosted coordination above the covenant, not a covenant rule.",
      next: ["Once the hold is released, run the same action again."]
    },
    RISK_DENIED: {
      title: "The hosted risk controls denied this action",
      meaning: "A risk adapter configured for this organization returned a deny. This is hosted coordination above the covenant, not a covenant rule, and there is no override in this UI.",
      next: ["Review the organization's risk controls, or ask an administrator about the denial."]
    },

    /* ---- v0.7 ON-CHAIN ORGANIZATIONAL ROOT (Wave 2, Track B-web) ----
     * docs/postlaunch/v0.7-app-surface-contract.md §2's closed refusal
     * vocabulary. Several of these are thrown LOCALLY by web/org-root-ui.js
     * (fail-closed pre-checks before a network round trip or before the
     * wallet is ever invoked) as well as by the server; both paths render
     * identically here. */
    OWNER_SET_ILL_FORMED: {
      title: "That owner set is not well-formed",
      meaning: "An organizational root's owner set must have at least one active slot, active slots contiguous from slot 1, every active key distinct, and the required-approvals (M), emergency-freeze (K) and recovery (R) quorums each within the active owner count. This is the exact rule the covenant itself enforces — PolicyVault checked it locally and refused before any transaction was built.",
      next: ["Fix the owner slots, thresholds, or delays named above and try again."]
    },
    NOT_AN_ACTIVE_SLOT: {
      title: "This wallet does not hold that owner slot",
      meaning: "A root slot signature is accepted only from the exact key the organizational root's owner set holds for that slot. The connected wallet's key is not it — an owner may sign ONLY their own slot; another owner's approval must come from that owner's own wallet or an imported signed envelope.",
      next: ["Connect the wallet that holds this slot, or ask that owner to sign and share their response envelope (paste / file / QR)."]
    },
    UNDER_QUORUM: {
      title: "Not enough owner signatures yet",
      meaning: "This root action needs more owner-slot signatures than are collected so far before it can be finalized. This is the covenant's own M-of-N (or emergency K, or recovery R) rule, re-checked locally.",
      next: ["Collect the remaining owner signatures (each owner signs their own slot, or shares a signed envelope), then finalize."]
    },
    DUPLICATE_SLOT_SIGNATURE: {
      title: "That owner slot already has a signature",
      meaning: "One slot accepts exactly one signature. A second signature offered for a slot that already has one is refused rather than silently replacing it.",
      next: ["If this is a mistake, remove the earlier signature first (reload the request) rather than layering another one on top."]
    },
    SLOT_KEY_MISMATCH: {
      title: "That signature does not match this slot's key",
      meaning: "The organizational root's owner set names an exact public key for this slot. The signature (or the envelope's declared key) offered for it is under a different key, so it can never count toward this root's quorum.",
      next: ["Confirm which slot this owner actually holds on the current owner set, and collect the signature from the right wallet."]
    },
    RESPONSE_BINDING_MISMATCH: {
      title: "That signed response does not match this request",
      meaning: "Every collected owner-slot response is bound to an exact manifest hash, transaction id, root outpoint and request — that is what stops a signature collected for one root request being replayed into another. This one does not match, so it is refused before it is ever placed in the signature blob.",
      next: ["Re-fetch the current slot-signing request and have the owner sign that exact one.", "If this repeats, the root may have moved on — reload the root and rebuild the request."]
    },
    ROOT_FROZEN: {
      title: "This organizational root is frozen",
      meaning: "While frozen, the root accepts only ROTATE, UNFREEZE, owner recovery, and succession — no general owner operation on any vault of this organization can be authorized.",
      next: ["The owners can UNFREEZE the root with their approval quorum (M of N of the installed set), then retry this action."]
    },
    ROOT_STALE_OUTPOINT: {
      title: "This root has moved on since this request was built",
      meaning: "The organizational root's own outpoint is its freshness kill switch: spending it invalidates every collected approval on the previous outpoint at once. Something else already spent this root's UTXO, so this request no longer applies.",
      next: ["Verify state (reconcile) on the root, then rebuild the request against its current outpoint."]
    },
    ROOT_PENDING_REQUEST: {
      title: "A request is already pending on this root",
      meaning: "Only one owner-operation transaction may be in flight per root transition, so a second one is refused until the first resolves (finalized-and-broadcast, or withdrawn).",
      next: ["Finish or withdraw the pending request, or wait for it to reconcile, before starting another."]
    },
    DELAY_NOT_ELAPSED: {
      title: "The relative idle delay has not elapsed yet",
      meaning: "Owner recovery and succession are gated by a RELATIVE input age, not a wall clock: the root's UTXO must have been unspent for the configured delay. Any root transaction — including a routine owner AUTHORIZE — resets that clock, which is what keeps this path closed while the owners are active.",
      next: ["Wait for the configured delay to elapse with the root untouched, or use the normal owner-quorum path instead if it is available."]
    },
    ROOT_INPUT_REQUIRED: {
      title: "This owner action needs the organizational root as an input",
      meaning: "A rooted vault has no owner key of its own — its owner authority IS the organizational root's input. PolicyVault refused to build this transaction without it.",
      next: ["Rebuild the request through the root's owner-request flow, not as a standalone vault action."]
    },
    OWNER_PATH_TAKES_NO_SIGNATURE: {
      title: "This owner operation takes no owner signature of its own",
      meaning: "A rooted vault's owner entrypoints authorize through the organizational root's owner-quorum input, not through a vault-level owner signature — there is no owner key on the vault to sign with.",
      next: ["Authorize this change through the organizational root's request flow."]
    },
    HOSTED_ORG_IS_NOT_A_ROOT: {
      title: "This organization has no on-chain organizational root",
      meaning: "A hosted organization is application metadata only and grants no covenant authority. This action needs an ON-CHAIN organizational root (a separate covenant holding a real M-of-N owner quorum) — this hosted organization is not linked to one.",
      next: ["Create an organizational root for this organization, or use the linked root if one already exists."]
    },

    /* ---- v0.5/v0.6 TOKEN and v0.7-payment-hd HIERARCHICAL DELEGATION
     * (Wave 2, Track H-web) ----
     * docs/postlaunch/v0.7-app-surface-contract.md §6.1's closed refusal
     * vocabulary. Several of these are thrown LOCALLY by
     * web/token-vault-ui.js / web/hd-vault-ui.js (fail-closed pre-checks
     * before a network round trip or before the wallet is ever invoked) as
     * well as by the server; both paths render identically here. */
    UNKNOWN_COVENANT_VERSION: {
      title: "PolicyVault does not know this covenant version",
      meaning: "Every vault, request and manifest carries an exact covenant version. An unrecognised one is refused rather than guessed at or routed to a default — that is the fail-closed rule this entire product is built on.",
      next: ["Reload the page. If a vault genuinely uses a version this build does not support yet, it stays visible as read-only history rather than being acted on."]
    },
    VENUE_PROFILE_UNSUPPORTED: {
      title: "That swap venue is not supported",
      meaning: "PolicyVault's v0.6 atomic-composability controller knows exactly ONE venue: its own FIXTURE conformance pool. No real DEX venue is supported. PolicyVault MUST NOT become a DEX — it never runs, custodies, or blesses a trading venue, and a request naming any other venue is refused before a transaction is ever built.",
      next: ["Use the FIXTURE venue this vault's owner already approved, or do not attempt an atomic swap on this vault."]
    },
    ASSET_DESCRIPTOR_INVALID: {
      title: "That asset descriptor was rejected",
      meaning: "A token asset's descriptor is the hash-verified record of what the asset is and which exact template bytes may carry it. This one failed the closed-schema validator — malformed, an unknown field, an unknown schema version, or a missing required binding — so it was refused before anything was computed from it.",
      next: ["Get the exact descriptor JSON from the asset's issuer or a source you trust, and paste it again unmodified."]
    },
    TOKEN_TEMPLATE_MISMATCH: {
      title: "The token template does not match what this vault pinned",
      meaning: "A vault's controller pins one exact accepted token template (hash + byte geometry) at creation. The descriptor or transaction offered here names a different one, so PolicyVault refuses rather than risk describing the wrong asset.",
      next: ["Confirm you are using the descriptor this specific vault was created with — a different asset, even from the same issuer, is a different template."]
    },
    HD_LEVEL_UNPROVEN: {
      title: "That delegation level is not offered",
      meaning: "Hierarchical delegation on this vault is proven up to a measured maximum level; the action requested is not one of the recognised spend/delegation entrypoints at a proven level.",
      next: ["Use one of the offered spend or delegate buttons for this vault — there is no deeper level to request."]
    },
    HD_CHAIN_STALE: {
      title: "This delegation tree is out of date",
      meaning: "The local copy of the delegation forest this browser is holding does not reproduce the vault's live on-chain agentRoot — something changed it since this copy was taken (a spend, a delegation, or a revocation).",
      next: ["Reload the current delegation tree for this vault, then rebuild the request."]
    },
    HD_AUTHORITY_EXCEEDS_ANCESTOR: {
      title: "A child may never be granted more authority than its parent",
      meaning: "Every field of a delegated child leaf (spend cap, period budget, fee cap, carry cap, expiry) must be less than or equal to its parent's. This proposal would WIDEN at least one of them, so it is refused before it is ever built — authority may never increase descending the delegation tree.",
      next: ["Narrow the proposed child's limits so every field is <= the delegating parent's, then try again."]
    },
    DELEGATION_WHILE_PAUSED: {
      title: "Delegation is refused while this vault is paused",
      meaning: "A paused vault accepts no new delegation — pausing is the owner's immediate break-glass control and delegation would undermine it.",
      next: ["Ask the vault owner to unpause it, then retry."]
    },
    DELEGATION_WHILE_ROOT_FROZEN: {
      title: "Delegation is refused while the organizational root is frozen",
      meaning: "This vault is bound to an on-chain organizational root. While that root is FROZEN, no delegation on any vault it roots is authorized.",
      next: ["The owners can UNFREEZE the root with their approval quorum (M of N of the installed set), then retry this action."]
    }
  };

  /* The one honest answer for a code with no closed entry. */
  function explain(code) {
    if (typeof code !== "string" || !code) return null;
    return Object.prototype.hasOwnProperty.call(TABLE, code) ? TABLE[code] : null;
  }

  /*
   * renderRefusalHtml({ summary, code, message })
   *
   * `summary` is the one-line text already written to the status region
   * (kept as the heading so the region reads the same to a screen reader
   * and to the eye). The code and the server's message are ALWAYS shown.
   * Everything is escaped; nothing here is ever inserted unescaped.
   */
  function renderRefusalHtml({ summary, code, message }) {
    const e = explain(code);
    const head = `<div class="refusal-head"><b>${esc(e ? e.title : summary || "Refused")}</b></div>`;
    const detail =
      `<div class="refusal-detail hint">` +
      (code ? `<span class="mono">${esc(code)}</span> — ` : "") +
      `${esc(message || summary || "no message")}</div>`;
    if (!e) {
      return (
        `<div class="refusal" data-refusal="unexplained">` + head + detail +
        `<div class="refusal-why">PolicyVault has no closed explanation for this refusal code, so the server's exact message above is shown unchanged rather than guessed at.</div>` +
        `<ul class="refusal-next"><li>Retry the action from the current state.</li>` +
        `<li>If it repeats, report the code and message above — they contain no key material.</li></ul></div>`
      );
    }
    return (
      `<div class="refusal" data-refusal="${esc(code)}">` + head + detail +
      `<div class="refusal-why">${esc(e.meaning)}</div>` +
      `<ul class="refusal-next">${e.next.map((n) => `<li>${esc(n)}</li>`).join("")}</ul></div>`
    );
  }

  /* ------------------------------------------------------------------ *
   * OUTCOMES — the durable request states of the v0.4.1 pipeline          *
   * (sdk/src/wallet-requests-v4.js RequestState), in their real names:    *
   *   BUILT -> [AWAITING_APPROVALS ->] SIGNED -> FINALIZED ->             *
   *   PREFLIGHT_VERIFIED -> SUBMITTING -> SUBMITTED -> CHAIN_VERIFIED     *
   * plus SUBMISSION_REJECTED / RECONCILIATION_REQUIRED /                  *
   * TERMINATED_UNKNOWN.                                                   *
   *                                                                       *
   * `level` is what the UI may claim:                                     *
   *   "verified" — chain-proven success. ONLY CHAIN_VERIFIED.             *
   *   "pending"  — real progress, NOT success. Funds may or may not have  *
   *                moved; the chain has not been checked yet.             *
   *   "attention"— the outcome is not established and needs an action.    *
   *   "failed"   — it definitively did not happen.                        *
   * ------------------------------------------------------------------ */
  const OUTCOMES = {
    CHAIN_VERIFIED: {
      level: "verified",
      title: "Chain-verified",
      meaning: "PolicyVault found the transaction on the Kaspa DAG, confirmed the previous vault state was consumed, and confirmed the expected successor state exists. This is the only outcome that is proven.",
      next: []
    },
    SUBMITTED: {
      level: "pending",
      title: "Broadcast — NOT yet confirmed",
      meaning: "The transaction was accepted by the node for relay. That is not proof it is in the DAG, and it is not proof the vault changed. It may still be confirmed, or it may not.",
      next: ["Use Verify state on the vault to check the chain.", "Do not treat this as a completed payment yet."]
    },
    SUBMITTING: {
      level: "pending",
      title: "Broadcasting — NOT yet confirmed",
      meaning: "The transaction is being sent to the node. No outcome is established yet, and nothing has moved as far as PolicyVault can prove.",
      next: ["Wait for the outcome, then use Verify state on the vault if it does not resolve."]
    },
    PREFLIGHT_VERIFIED: {
      level: "pending",
      title: "Checked, not yet broadcast",
      meaning: "The signed transaction passed PolicyVault's final pre-broadcast checks. Nothing has been sent to the network.",
      next: ["Broadcasting follows automatically; if it does not complete, rebuild the action."]
    },
    FINALIZED: {
      level: "pending",
      title: "Assembled, not yet broadcast",
      meaning: "The signature was accepted and the transaction assembled. Nothing has been sent to the network.",
      next: ["If this does not progress, use Verify state on the vault and rebuild the action."]
    },
    SIGNED: {
      level: "pending",
      title: "Signed — NOT yet broadcast",
      meaning: "The wallet returned a signature. No transaction has reached the network and nothing has moved.",
      next: ["If this does not progress, use Verify state on the vault and rebuild the action."]
    },
    BUILT: {
      level: "pending",
      title: "Built, awaiting signature",
      meaning: "PolicyVault authorized this action and froze the exact transaction. Nothing is signed and nothing has moved.",
      next: ["Review it and sign it in your wallet to continue."]
    },
    AWAITING_APPROVALS: {
      level: "pending",
      title: "Awaiting approvals",
      meaning: "This spend is above the vault's approval threshold. The required approver signatures must be collected before the agent can sign. Nothing has moved.",
      next: ["Each approver signs from their own wallet; the agent signs last."]
    },
    RECONCILIATION_REQUIRED: {
      level: "attention",
      title: "Outcome NOT established — verification required",
      meaning: "PolicyVault could not establish from the chain whether this transaction took effect. It fails closed rather than guessing, and further actions on this vault are blocked until it is resolved.",
      next: ["Use Verify state on the vault card.", "Do not assume either outcome until it reports."]
    },
    TERMINATED_UNKNOWN: {
      level: "attention",
      title: "Terminal state could not be classified",
      meaning: "The vault reached a terminal state that PolicyVault could not classify automatically. It is read-only.",
      next: ["Inspect the identifiers under Details / Activity against the chain."]
    },
    SUBMISSION_REJECTED: {
      level: "failed",
      title: "Rejected by the node — nothing happened",
      meaning: "Consensus refused the transaction. It is not on the chain and the vault is unchanged.",
      next: ["Use Verify state on the vault, then rebuild the action from the confirmed state."]
    }
  };

  /* The fail-closed answer for a state with no closed entry: pending —
   * NEVER success. */
  const UNKNOWN_OUTCOME = Object.freeze({
    level: "pending",
    title: "Outcome NOT confirmed",
    meaning: "PolicyVault has no closed description for this request state, so it is treated as unconfirmed. It is NOT a completed transaction.",
    next: ["Use Verify state on the vault to check the chain before assuming anything."]
  });

  function outcome(state) {
    if (typeof state !== "string" || !state) return UNKNOWN_OUTCOME;
    return Object.prototype.hasOwnProperty.call(OUTCOMES, state) ? OUTCOMES[state] : UNKNOWN_OUTCOME;
  }
  const isVerifiedOutcome = (state) => state === "CHAIN_VERIFIED";

  /*
   * renderOutcomeHtml({ summary, state, txId, detail })
   *
   * `summary` is the one-line text already in the status region; the raw
   * state name and the txid are always kept visible.
   */
  function renderOutcomeHtml({ summary, state, txId, detail }) {
    const o = outcome(state);
    const known = Object.prototype.hasOwnProperty.call(OUTCOMES, String(state));
    return (
      `<div class="refusal" data-outcome="${esc(state)}" data-outcome-level="${esc(o.level)}">` +
      `<div class="refusal-head"><b>${esc(o.title)}</b></div>` +
      `<div class="refusal-detail hint"><span class="mono">${esc(state)}</span>` +
      (txId ? ` — txid <span class="mono">${esc(txId)}</span>` : "") +
      (detail ? ` — ${esc(detail)}` : "") +
      `</div>` +
      `<div class="refusal-why">${esc(o.meaning)}</div>` +
      (o.next.length ? `<ul class="refusal-next">${o.next.map((n) => `<li>${esc(n)}</li>`).join("")}</ul>` : "") +
      (known ? "" : `<div class="refusal-why">${esc(summary || "")}</div>`) +
      `</div>`
    );
  }

  const api = {
    explain,
    renderRefusalHtml,
    codes: () => Object.keys(TABLE).slice().sort(),
    outcome,
    isVerifiedOutcome,
    renderOutcomeHtml,
    outcomeStates: () => Object.keys(OUTCOMES).slice().sort()
  };
  if (typeof window !== "undefined") window.PolicyVaultRefusalExplain = api;
  if (typeof module !== "undefined" && module.exports) module.exports = api;
})();
