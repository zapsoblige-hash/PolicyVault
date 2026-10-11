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
 *     closed explanation for this code" line. The sole legacy wrapper
 *     exception is BUILD_FAILED containing the exact mainnet generation
 *     guard sentence from sdk/src/config.js for a known generation. It
 *     never infers a meaning from other message text — a fabricated
 *     explanation of a funds-safety refusal is worse than a bare code.
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
    GENERATION_NOT_MAINNET_AUTHORIZED: {
      title: "This feature is unavailable on mainnet in this release",
      meaning: "This action uses a covenant generation that is not enabled for mainnet in this release, or its new creation has been switched off by the operator. Changing the address or amounts will not enable it. Existing vaults and organizations of an enabled generation stay manageable.",
      next: ["For a supported single-owner vault, use Create Vault with Protocol v0.4.1.", "For a shared treasury, create an organizational root and a rooted KAS vault when this release lists them as mainnet-creatable in Capabilities."]
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
    REQUEST_RECOVERY_REQUIRED: {
      /* RC45 F8 WEB-1 (plan r2 §5, CR2-L16): the v0.4 transition guard, sdk/src/wallet-recovery-v4.js */
      title: "Signed work on this vault is still unresolved",
      meaning: "Unresolved signed work blocks this action; on a live vault, Pause and Close & recover stay available. A signed request on this vault's current state may still be broadcast and take effect, so PolicyVault refuses a second transaction rather than risking a conflicting spend. The message above names the blocking request.",
      next: ["Use Verify state on the vault: it settles the request only once the chain shows its outcome at depth.", "On a live vault, Pause or Close & recover — if yours confirms first, the pending request can never execute."]
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

    /* ---- delegate budget period start (hosted rule; the covenant cannot check it) ----
     * PERIOD_START_STALE: the freshness check of sdk/src/manifest-v4.js, run before a v0.4.1 genesis-submit,
     * finalize or submit and before a v0.7-kas creation signature or root-request finalize (409 in server/src/api.js
     * and server/src/org-roots.js). PERIOD_START_REQUIRED: the canonical node DAA read of sdk/src/chain.js and the
     * friendly-create read of sdk/src/ux-normalize-v4.js (422). */
    PERIOD_START_STALE: {
      title: "This request waited too long to be signed or sent",
      meaning: "PolicyVault starts the budget period of every new or changed delegate at the network position when the change is built. This request is now older than that delegate's budget period allows, so confirming it would hand the delegate more than one period's budget at once. Nothing was stored or broadcast by this step. PolicyVault did not keep or send the signature you gave for this step; a signed transaction would stay valid until one of its coins is spent (for a creation, its funding coins), so do not broadcast it from anywhere else — build it again. The covenant cannot check this; PolicyVault refuses it.",
      next: [
        "Withdraw (Cancel) this request and build the action again — the new build starts the period at the current network position.",
        "For a signed vault request that is already armed: Pause, press Verify about two minutes later, then unpause and build the action again."
      ]
    },
    PERIOD_START_REQUIRED: {
      title: "The current network position could not be read",
      meaning: "PolicyVault anchors every new or changed delegate's budget period to the synced Kaspa node's current DAA score and refuses rather than guess when it cannot read it. No request was built. If this action used a released risk review, that review was used up and must be released again.",
      next: ["Check the network banner, then try again when the node is synced."]
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
    /* v0.7 ROOTED KAS TREASURY (v0.7 mainnet enablement, 2026-09-10): the delegate-payment / approver-tier refusals the
     * KAS profile raises (core/model/vault-transitions-v4 rules re-checked pre-sign by sdk/src/wallet-requests-v7-kas.js)
     * and the browser's own signing-boundary refusals (web/kas-vault-ui.js). Each is a CLOSED reason; none has an override. */
    OVER_CAP: {
      title: "Above this delegate's cap per payment",
      meaning: "The amount is larger than the cap the owners installed for this delegate. The covenant enforces the cap; PolicyVault refused before anything was signed.",
      next: ["Pay a smaller amount, or ask the organization's owners to change the delegate rules (a root-governed operation)."]
    },
    OVER_BUDGET: {
      title: "Above this delegate's remaining budget for the period",
      meaning: "Adding this payment would exceed the delegate's budget for the current period. The budget resets when the period ends; nothing was signed.",
      next: ["Wait for the period to roll over, pay a smaller amount, or ask the owners to change the rules."]
    },
    OVER_AGENT_FEE_CAP: {
      title: "The network fee exceeds this delegate's fee cap",
      meaning: "A treasury payment carries the treasury's covenant script, so its network fee is about 0.04 KAS; this delegate's installed fee cap is lower, so the payment cannot be built. Nothing was signed or sent.",
      next: ["Ask the owners to change the delegate rules with a fee cap of at least 0.05 KAS (Change delegate rules on the treasury).", "Changing the amount or the recipient does not help — the fee depends on the transaction, not the amount."]
    },
    INSUFFICIENT_RESERVE: {
      title: "The treasury's fee reserve cannot pay this payment's network fee",
      meaning: "Delegate payments take their network fee from the treasury's fee reserve, and the reserve is too low for this payment. Nothing was signed or sent.",
      next: ["Ask the owners to top up the fee reserve (a root-governed operation)."]
    },
    VAULT_PAUSED: {
      title: "This treasury is paused",
      meaning: "The owners paused the treasury: the covenant refuses every delegate payment until they unpause it. Nothing was signed or sent.",
      next: ["Only the organization's owners can unpause it (Unpause treasury on the root)."]
    },
    AGENT_NOT_REGISTERED: {
      title: "This wallet is not a delegate of this treasury",
      meaning: "Only a wallet with an installed delegate rule can pay from a treasury. The connected wallet has none, so no payment can be built for it.",
      next: ["Connect the delegate wallet, or ask the owners to install a rule for this wallet."]
    },
    NOT_AN_APPROVER: {
      title: "This wallet is not one of the treasury's approvers",
      meaning: "Approvals of an above-threshold payment are accepted only from the treasury's installed approver slots. The connected wallet is not one of them; nothing was recorded.",
      next: ["Connect an approver wallet, or ask the owners to change the approvers."]
    },
    VAULT_ID_IN_USE: {
      /* RC33-ID-01 (2026-09-11): global vault-record uniqueness — sdk/src/vault-identity.js */
      title: "This vault identity is already in use",
      meaning: "Every vault record is stored under one global identity shared by every covenant generation. The identity supplied for this creation already belongs to an existing vault record or to an existing creation request, so the creation was refused before any signature was accepted, before any claim was recorded and before anything was sent. Existing records are never replaced and identities are never recycled.",
      next: ["Create the vault again with a fresh identity (the app generates one automatically).", "If a creation with this identity is still pending, open it and finish or withdraw it instead of creating a duplicate."]
    },
    VAULT_PENDING_REQUEST: {
      title: "The treasury already has an unfinished request",
      meaning: "A payment or an owner operation on this treasury is still in flight (unsigned, awaiting approvals, submitted, or awaiting reconciliation). Only one transition per treasury can be in flight at a time.",
      next: ["Open the pending request and finish or withdraw it, or use Verify state on the root to settle an uncertain one."]
    },
    AGENT_SET_REQUIRED: {
      title: "The complete delegate rule set is required",
      meaning: "Changing delegate rules replaces the whole installed set; the request must carry every delegate's full rule (including its recipients), never a bare Merkle root. Nothing was built.",
      next: ["Use Change delegate rules on the treasury, which sends the complete set."]
    },
    REVIEW_REFUSED: {
      title: "This browser's own verification refused the transaction",
      meaning: "PolicyVault re-verified the transaction locally (with the treasury's current script bound) and it did not match the rules being reviewed. The wallet was never invoked; nothing was signed.",
      next: ["Do not sign this transaction anywhere else.", "Reload and rebuild it; if it refuses again, report the exact reason shown."]
    },
    PAYLOAD_MISMATCH: {
      title: "The transaction handed to the wallet is not the one reviewed",
      meaning: "The bytes the wallet was about to sign differ from the transaction this browser reviewed (or, for a treasury creation, the destination is not the script rebuilt from the reviewed rules). The wallet was never invoked.",
      next: ["Do not sign.", "Reload and rebuild the request; if it refuses again, report the exact reason shown."]
    },
    NOT_THE_SIGNER: {
      title: "The connected wallet is not this request's signer",
      meaning: "This payment was built for a different delegate wallet. Only that wallet can sign it; nothing was signed.",
      next: ["Connect the wallet the payment was built for, or withdraw the request and build a new one from your wallet."]
    },
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
    },

    /* ---- RC45 L2-01 (Narrowed C + guard) and R3N-B1: the organizational-root request refusals of
     * sdk/src/wallet-requests-v7.js (and sdk/src/wallet-requests-v7-kas.js for TREASURY_STATE_UNRESOLVED), served by
     * server/src/org-roots.js. RECORDED_OUTPUT_SPENT is the BUILD-time answer here; the same code answered by Submit
     * (with extra.submitRead) has its own explanation below (SUBMIT_CONTEXT), chosen from that structured field only. */
    RECORDED_OUTPUT_SPENT: {
      title: "An output this request would spend is no longer reported unspent",
      meaning: "Before recording anything, PolicyVault read the synced node: the recorded root or treasury output this request would spend is not reported unspent (or not with the recorded value, covenant id and script). Nothing was recorded and the root is not reserved. That output may have been spent outside PolicyVault, including by a transaction of an earlier request broadcast outside PolicyVault.",
      next: [
        "Press Verify state on the root.",
        "Build again only if Verify then shows the root (and the treasury) verified with no request holding it.",
        "If Verify answers UNKNOWN (the root moved outside PolicyVault, duplicate records, or a request outside this repair's scope), the build stays refused while that answer stands."
      ]
    },
    TREASURY_STATE_UNRESOLVED: {
      title: "This treasury's state is UNRESOLVED",
      /* binding wording: writer decision 'wording after the PARTIAL upgrade' item 1, verbatim */
      meaning: "PolicyVault cannot confirm this treasury's current state: its expected output was spent outside PolicyVault after an out-of-band change to its delegate rules. Hosted actions on this treasury stay closed. A later Verify restores them only if it finds that expected output unspent again (for example after a reorganization); otherwise only the owners' direct on-chain exit can act on it.",
      next: [
        "Hosted owner operations on this treasury (FREEZE and emergency pause included) and its delegate payments are refused while it is UNRESOLVED; a root FREEZE does not stop its delegates.",
        "Press Verify state on the root later: it reopens this treasury only if it observes that expected output unspent again at depth.",
        "The owners' direct on-chain exit moves the root outside PolicyVault, which then answers UNKNOWN for the root."
      ]
    },
    SUBMIT_INPUT_UNRESOLVED: {
      title: "Submit refused — an input of this request is not confirmed unspent",
      meaning: "Before recording anything, PolicyVault read every output this finalized request spends. One is not reported unspent, or is reported with different contents, and PolicyVault cannot establish that another transaction spent it. Nothing was recorded or broadcast; the request still reserves the root, and withdrawal is not available for this answer.",
      next: ["Press Verify state on the root.", "The server's message above names the input and what was observed."]
    },
    WITHDRAWAL_DEPTH_PENDING: {
      title: "Withdrawal pending — the second step comes later",
      meaning: "PolicyVault withdraws a finalized request whose input another transaction spent in two steps, at least 1,000 DAA apart: the first step records only a chain anchor, and the second step withdraws only if that spend is then final at 1,000 DAA and every observation agrees again. This step wrote at most that anchor; the request stays finalized and still reserves the root.",
      /* C4-06c (writer clarification 02 item 1): while a withdrawal is pending the text offers Wait, step 2 or Submit and
       * claims nothing about which succeeds; the server re-decides each */
      next: ["Wait, then take the second step between the earliest and latest network positions (DAA) named in the message above, or press Submit on the same finalized request: PolicyVault re-reads the chain for each and decides.", "Until then the request keeps its reservation; Verify state on the root shows whether anything changed."]
    },
    FEE_INPUT_NOT_LIVE: {
      title: "The fee input is not reported unspent",
      meaning: "PolicyVault reads the fee input before recording a root request, and it is not reported unspent, is reported with different contents, or could not be read from the node. Nothing was recorded and the root is not reserved.",
      next: ["Choose another fee input, or build again once it is reported unspent."]
    },
    OBSERVATION_ERROR: {
      title: "The node could not be read exactly",
      meaning: "PolicyVault refuses rather than guess when it cannot read the synced node's chain position, or an output a root request spends, exactly. At build nothing was recorded and the root is not reserved. At Submit nothing was recorded or broadcast; the finalized request still reserves the root.",
      next: ["Check the network banner.", "When the node answers again, repeat the same step: build again (nothing is reserved), or press Submit on the same finalized request (it is never rebuilt)."]
    },
    CANNOT_REJECT: {
      title: "This request cannot be withdrawn now",
      meaning: "PolicyVault withdraws only an unsigned request that was never sent, a delegate-rule change whose budget period start has aged out, or a finalized, never-sent request whose input another transaction spent, once that spend is final at 1,000 DAA. This request does not meet that rule now, so nothing was written and it keeps its reservation of the root.",
      next: ["Read the message above: it names why.", "Continue the request as its state allows, or press Verify state on the root."]
    }
  };

  /* R3N-B1 (addendum v2b revision 3 §2 S3, §5 R4; writer amendment A1-6): the Submit answers, keyed on the structured
   * extra.submitRead.finding the server attaches (never on message text). */
  const HOLD_CLAUSE = "holds the root until it is withdrawn (two steps, at least 1,000 DAA apart), or longer in the disclosed cases where a withdrawal cannot be proven safe";
  const RETENTION_NOTE = "Start the withdrawal while the node still holds the history from this request's build (at least about 30 hours by default); after that PolicyVault can no longer establish that the output existed, unless the first step already recorded that evidence.";
  const SUBMIT_CONTEXT = Object.freeze({
    CONFLICTING_SPEND: Object.freeze({
      title: "Submit refused — nothing was recorded or sent",
      meaning: `A recorded output this finalized request spends is no longer reported unspent, while the root output it spends still is, so this request's own transaction has not spent it: PolicyVault treats it as spent by another transaction. Nothing was recorded or broadcast. The request still reserves the root: it ${HOLD_CLAUSE}.`,
      next: Object.freeze([
        "Withdraw it in two steps: the first step records a chain anchor; PolicyVault withdraws at the second step, at least 1,000 DAA later, only once that spend is final at 1,000 DAA and it has checked everything again.",
        "Then press Verify state on the root."
      ])
    }),
    ROOT_INPUT_NOT_LIVE: Object.freeze({
      title: "Submit refused — the root output it spends is not reported unspent",
      meaning: "The root output this request spends is not reported unspent, and no output of this request's own transaction is observed. Either this request's transaction was broadcast outside PolicyVault and its outputs were already spent, or another root transaction spent the root output; PolicyVault cannot tell which. Nothing was recorded or broadcast. Withdrawal is not available.",
      next: Object.freeze(["Press Verify state on the root."])
    }),
    INPUT_CONTRADICTED: Object.freeze({
      title: "Submit refused — an input is reported with different contents",
      meaning: "The node reports an input of this request with a different value, covenant id or script than this request records. Nothing was recorded or broadcast. Withdrawal is not available.",
      next: Object.freeze(["Press Verify state on the root."])
    }),
    INPUT_EXISTENCE_UNPROVEN: Object.freeze({
      title: "Submit refused — an input is not reported unspent",
      meaning: "An input of this request is not reported unspent, and PolicyVault cannot establish that it was created on the selected chain. It may still be created, and then this request can be submitted, so PolicyVault does not treat it as spent and does not withdraw the request. Nothing was recorded or broadcast; the request still reserves the root.",
      next: Object.freeze(["Submit again once the input is reported unspent, or press Verify state on the root."])
    })
  });
  /* CANNOT_REJECT of the input-spent withdrawal (extra.withdrawal.finding): the next step each finding allows. C4-06c
   * (writer clarification 02 item 1): after a CANNOT_REJECT finding the next step is Submit, then Verify state; the
   * server's submit read decides (a 409 with nothing written, or the completion route when its own output is observed). */
  const SUBMIT_DECIDES = "PolicyVault re-reads every input before recording anything";
  const WITHDRAWAL_FINDING_NEXT = Object.freeze({
    INPUTS_LIVE: "Every output it spends is reported unspent again: submit it, then press Verify state on the root.",
    OWN_OUTPUT: "An output of this request's own transaction is observed: submit it, then press Verify state on the root.",
    IN_TRANSACTION_POOL: `This request's own transaction is in the node's transaction pool: press Submit on it, then Verify state on the root (${SUBMIT_DECIDES}), and do not withdraw it.`,
    ROOT_INPUT_NOT_LIVE: `The root output it spends is not reported unspent, and this request's own transaction may have spent it: press Submit on it, then Verify state on the root (${SUBMIT_DECIDES}).`,
    INPUT_EXISTENCE_UNPROVEN: `PolicyVault cannot establish that the spent input existed on the selected chain, so it does not withdraw the request: press Submit on it, then Verify state on the root (${SUBMIT_DECIDES} and refuses, with nothing written, while one is not reported unspent).`,
    ACCEPTED_IN_WINDOW: `This request's own transaction was accepted after the anchor: press Submit on it, then Verify state on the root (${SUBMIT_DECIDES}).`,
    UNSTABLE: `The root output it spends changed while PolicyVault was reading it: press Submit on it, then Verify state on the root (${SUBMIT_DECIDES}).`
  });
  const isObj = (v) => !!v && typeof v === "object" && !Array.isArray(v);
  const digits = (v) => (typeof v === "string" && /^(0|[1-9][0-9]*)$/.test(v) ? v : null);
  /* the structured extra of a refusal (the server spreads it into the error body), or null */
  function refusalExtra(extra) {
    return isObj(extra) ? extra : null;
  }
  function submitContextOf(code, extra) {
    const x = refusalExtra(extra);
    const read = x && isObj(x.submitRead) ? x.submitRead : null;
    if (!read) return null;
    if (code === "RECORDED_OUTPUT_SPENT" && read.finding === "CONFLICTING_SPEND" && read.withdrawal === "TWO_STEP") {
      const base = SUBMIT_CONTEXT.CONFLICTING_SPEND;
      return read.existence === "E2" || read.existence === "E3" ? { title: base.title, meaning: base.meaning, next: [...base.next, RETENTION_NOTE] } : base;
    }
    if (code === "SUBMIT_INPUT_UNRESOLVED" && ["ROOT_INPUT_NOT_LIVE", "INPUT_CONTRADICTED", "INPUT_EXISTENCE_UNPROVEN"].includes(read.finding)) return SUBMIT_CONTEXT[read.finding];
    return null;
  }

  /* Older SDK request wrappers replace the generation guard's code with
   * BUILD_FAILED. Recognize only its exact refusal sentence for these
   * known restricted generations; unrelated build failures keep their
   * generic explanation. This never changes the raw code or message. */
  const LEGACY_MAINNET_GENERATION_REFUSALS = [
    "policyvault-0.4", "policyvault-0.5", "policyvault-0.6",
    "policyvault-0.7-root", "policyvault-0.7-payment",
    "policyvault-0.7-kas", "policyvault-0.7-payment-hd"
  ].map((version) =>
    `mainnet: covenant generation "${version}" is NOT owner-authorized for mainnet creation/mutation — refusing (fail closed).`
  ).concat([
    "policyvault-0.4.1", "policyvault-0.7-root", "policyvault-0.7-kas"
  ].map((version) =>
    /* v0.7 enablement (2026-09-10): the operator kill switch for NEW mainnet creation (existing state stays operable) */
    `mainnet: creation of covenant generation "${version}" is DISABLED by operator configuration (POLICYVAULT_MAINNET_CREATION_DISABLED) — refusing this new genesis (fail closed).`
  ));

  /* The one honest answer for a code with no closed entry. `extra` is the
   * refusal's STRUCTURED detail as the server sent it (never message text):
   * it selects only the R3N-B1 Submit and withdrawal variants of a known code. */
  function explain(code, message, extra) {
    if (typeof code !== "string" || !code) return null;
    if (code === "BUILD_FAILED" && typeof message === "string" &&
        LEGACY_MAINNET_GENERATION_REFUSALS.some((guard) => message.includes(guard))) {
      return TABLE.GENERATION_NOT_MAINNET_AUTHORIZED;
    }
    if (!Object.prototype.hasOwnProperty.call(TABLE, code)) return null;
    const submit = submitContextOf(code, extra);
    if (submit) return submit;
    const x = refusalExtra(extra);
    if (code === "WITHDRAWAL_DEPTH_PENDING" && x && digits(x.earliestDaa) && digits(x.latestDaa)) {
      return { title: TABLE.WITHDRAWAL_DEPTH_PENDING.title, meaning: TABLE.WITHDRAWAL_DEPTH_PENDING.meaning, next: [`Wait, then take the second step from DAA ${x.earliestDaa} to DAA ${x.latestDaa}, or press Submit on the same finalized request: PolicyVault re-reads the chain for each and decides.`, TABLE.WITHDRAWAL_DEPTH_PENDING.next[1]] };
    }
    if (code === "CANNOT_REJECT" && x && isObj(x.withdrawal) && Object.prototype.hasOwnProperty.call(WITHDRAWAL_FINDING_NEXT, x.withdrawal.finding)) {
      return { title: TABLE.CANNOT_REJECT.title, meaning: TABLE.CANNOT_REJECT.meaning, next: [WITHDRAWAL_FINDING_NEXT[x.withdrawal.finding], TABLE.CANNOT_REJECT.next[0]] };
    }
    return TABLE[code];
  }

  /*
   * renderRefusalHtml({ summary, code, message, extra })
   *
   * `summary` is the one-line text already written to the status region
   * (kept as the heading so the region reads the same to a screen reader
   * and to the eye). The code and the server's message are ALWAYS shown.
   * Everything is escaped; nothing here is ever inserted unescaped.
   */
  function renderRefusalHtml({ summary, code, message, extra }) {
    const e = explain(code, message, extra);
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

  /* ------------------------------------------------------------------ *
   * v0.4-FAMILY TRANSITION LINES (RC45 F8; plan r2 §5 WEB-1, CR-H2,     *
   * CR-M7, CR2-L13, CR2-M5). The shared OUTCOMES and TABLE entries above *
   * stay unchanged: these lines are true only of a v0.4 / v0.4.1        *
   * TRANSITION (every Close & recover stops at SUBMITTED until Verify   *
   * completes it at depth; an armed request blocks ordinary actions;    *
   * owner break-glass is never refused by pending work on a live vault).*
   * They are requested only by the v0.4 transition caller               *
   * (web/app-v4.js completeRequestFlow) and are keyed on the request's  *
   * own contractVersion and kind, so a genesis or another generation    *
   * never receives them.                                                *
   * ------------------------------------------------------------------ */
  const V04_FAMILY = Object.freeze(["policyvault-0.4", "policyvault-0.4.1"]);
  const V04_TRANSITION_LINES = Object.freeze({
    closure: "If this was Close & recover, do not move the recovered funds until Verify state shows RECOVERED.",
    armed:
      "This signed request can still be broadcast and blocks other actions on this vault until it completes. " +
      "Pause and Close & recover stay available; after a Pause, Verify at depth marks it superseded, then Unpause through a governance proposal (three owner signatures, plus any delay or quorum).",
    available: "Pause and Close & recover stay available."
  });
  function v04TransitionLines(request, { state, code } = {}) {
    if (!request || typeof request !== "object" || !V04_FAMILY.includes(request.contractVersion)) return [];
    if (request.kind !== undefined && request.kind !== "transition") return [];
    if (code === "CLAIM_CONFLICT") return [V04_TRANSITION_LINES.available];
    if (code) return [];
    if (state === "SUBMITTED") return [V04_TRANSITION_LINES.closure];
    if (state === "PREFLIGHT_VERIFIED" || state === "FINALIZED") return [V04_TRANSITION_LINES.armed];
    return [];
  }
  function renderV04TransitionLinesHtml(request, which) {
    const lines = v04TransitionLines(request, which);
    return lines.length ? `<ul class="refusal-next" data-v04-transition="1">${lines.map((l) => `<li>${esc(l)}</li>`).join("")}</ul>` : "";
  }

  /* ------------------------------------------------------------------ *
   * VERIFY — the closed map of Verify state answers (POST              *
   * /vaults/:id/reconcile on a v0.4-family vault, sdk/src/reconcile-v4.js)*
   * RC45 F8 WEB-1 (plan r2 §5 WEB-1, CR-M1, CR2-L14, CR2-L16). Rule 5    *
   * applies here too: an answer this map does not know renders "bad"   *
   * with its token shown, never success. `level` is the status-region  *
   * class:                                                             *
   *   "good" — the record agrees with the chain, or this Verify settled *
   *            it on positive chain evidence at depth;                  *
   *   "warn" — not settled yet (below depth, a live claim, or signed    *
   *            work that may still execute); never success;            *
   *   "bad"  — PolicyVault cannot establish the vault's state from the  *
   *            chain; nothing changed.                                  *
   * Verify writes only on positive chain evidence at depth; UNKNOWN and *
   * CHAIN_CONTRADICTION never write.                                    *
   * RC45 R1-07 (F-02; C8): an answer that wrote is told as a write.     *
   * "Nothing was changed." is said only when settled[] is empty and no  *
   * restore occurred; each settled[] entry is labelled by its resulting *
   * state (completed / superseded / released leftover; any other state  *
   * keeps its raw token on a neutral line). A restore is not in the     *
   * answer: the caller derives it (the card was TERMINATED_UNKNOWN      *
   * before this Verify and the route's `vault` document is live after   *
   * it) and passes { restored: true }; no response field is read for it.*
   * ------------------------------------------------------------------ */
  const VERIFY_STATUSES = Object.freeze({
    CONSISTENT: { level: "good", title: "The recorded vault state matches the chain" },
    ADVANCED: { level: "good", title: "Verify settled the vault from the chain" },
    TERMINAL: { level: "good", title: "This vault is closed — history only" },
    CLAIM_PENDING: { level: "warn", title: "Not settled yet" },
    REQUEST_RECOVERY_REQUIRED: { level: "warn", title: "Signed work on this vault is still unresolved" },
    UNKNOWN: { level: "bad", title: "PolicyVault cannot establish this vault's state" },
    CHAIN_CONTRADICTION: { level: "bad", title: "The chain contradicts the record" }
  });
  /* Kaspa's DAA score advances about 10 per second; the settlement depth is
   * 1,000 DAA (about 100 s). Display only; integers only. */
  const DAA_PER_SECOND = 10n;
  const DEFAULT_WAIT_SECONDS = 100n;
  const short = (id) => (typeof id === "string" && id ? (id.length > 16 ? `${id.slice(0, 8)}…${id.slice(-6)}` : id) : "—");
  const decimal = (v) => (typeof v === "string" && /^\d{1,19}$/.test(v) ? BigInt(v) : null);
  function waitSeconds(depth, required) {
    const d = decimal(depth), r = decimal(required);
    if (d === null || r === null) return DEFAULT_WAIT_SECONDS;
    const remaining = r > d ? r - d : 0n;
    const seconds = (remaining + DAA_PER_SECOND - 1n) / DAA_PER_SECOND;
    return seconds > 0n ? seconds : 1n;
  }
  function entryLine(entry) {
    if (!entry || typeof entry !== "object") return "an unrecognised entry";
    return `${entry.action ?? "request"} request ${short(entry.requestId)} — ${entry.state ?? "state unknown"}` +
      (entry.signerRole ? ` (${entry.signerRole})` : "") + (entry.txId ? ` — txid ${short(entry.txId)}` : "");
  }
  /* RC45 R1-07: the label of a settled[] entry by its resulting state
   * (sdk/src/reconcile-v4.js entryOf). A state not listed here is never
   * told as one of these; it keeps its raw token under SETTLED_UNLABELLED. */
  const SETTLED_LABELS = Object.freeze([
    ["CHAIN_VERIFIED", "Completed by this Verify"],
    ["STALE", "Superseded by this Verify"],
    ["SUBMISSION_REJECTED", "Released by this Verify (an established rejection's leftover claims and reservation)"]
  ]);
  const SETTLED_UNLABELLED = "Settled by this Verify with a resulting state this page does not describe (nothing is assumed)";
  const RESTORED_LINE =
    "Restored: this vault was recorded as TERMINATED_UNKNOWN before this Verify and is live again; " +
    "its last recorded live state was restored from the chain at depth.";
  /* The answers after which a restore can stand (sdk/src/reconcile-v4.js
   * restore and completePositive / adoption from a TERMINATED_UNKNOWN base);
   * TERMINAL, UNKNOWN and CHAIN_CONTRADICTION never carry the notice. */
  const RESTORE_ANSWERS = Object.freeze(["CONSISTENT", "ADVANCED", "CLAIM_PENDING", "REQUEST_RECOVERY_REQUIRED"]);
  function verifyStatus(result, context) {
    const status = result && typeof result === "object" && typeof result.status === "string" ? result.status : "";
    const known = Object.prototype.hasOwnProperty.call(VERIFY_STATUSES, status);
    const lines = [];
    const list = (label, entries) => {
      if (Array.isArray(entries) && entries.length) lines.push(`${label}: ${entries.map(entryLine).join("; ")}.`);
    };
    const listSettled = (entries) => {
      if (!Array.isArray(entries)) return;
      for (const [state, label] of SETTLED_LABELS) list(label, entries.filter((e) => e && typeof e === "object" && e.state === state));
      list(SETTLED_UNLABELLED, entries.filter((e) => !(e && typeof e === "object" && SETTLED_LABELS.some(([state]) => e.state === state))));
    };
    if (!known) {
      lines.push("PolicyVault has no closed description for this Verify answer, so it is not treated as success. Nothing is assumed; inspect the vault under Details / Activity.");
      return { status, known, level: "bad", title: "Unrecognised Verify answer", lines };
    }
    const r = result;
    // Only the caller's own derivation counts (C8); a `restored` key in the answer is never read.
    const restored = Boolean(context && typeof context === "object" && context.restored === true) && RESTORE_ANSWERS.includes(status);
    // An absent settled[] is empty; anything else that is not an empty array is never told "nothing".
    const settledNothing = r.settled === undefined || (Array.isArray(r.settled) && r.settled.length === 0);
    if (restored) lines.push(RESTORED_LINE);
    if (status === "CONSISTENT") {
      if (settledNothing && !restored) lines.push("Nothing was changed.");
      listSettled(r.settled);
    } else if (status === "ADVANCED") {
      lines.push(`The vault advanced by ${r.to ?? "an unnamed action"}${r.adopted === true ? " (change made outside PolicyVault)" : ""}` +
        `${r.txId ? ` — txid ${short(r.txId)}` : ""}${r.requestId ? ` — request ${short(r.requestId)}` : ""}.`);
      listSettled(r.settled);
    } else if (status === "TERMINAL") {
      lines.push(`The vault is recorded as ${r.vaultStatus ?? "closed"}; there is nothing further to verify.`);
      listSettled(r.settled);
    } else if (status === "CLAIM_PENDING") {
      if (r.required !== undefined && r.required !== null) {
        lines.push(`${r.txId ? `Transaction ${short(r.txId)} is ` : ""}confirming (${r.depth ?? "?"} of ${r.required}); press Verify again in about ${waitSeconds(r.depth, r.required)} s. ` +
          "If this is a closure, do not move the recovered funds until Verify shows RECOVERED.");
      } else if (r.claimTxId) {
        lines.push(`A claim by ${short(r.claimTxId)} may still execute. Pause and Close & recover stay available; Verify again later.`);
      } else {
        lines.push("The outcome is not settled yet. Pause and Close & recover stay available; Verify again later.");
      }
      listSettled(r.settled);
    } else if (status === "REQUEST_RECOVERY_REQUIRED") {
      if (r.recordedVaultClosed === true) {
        // RC45 R1-13 (C1): "nothing was written" only when settled[] is absent or empty;
        // otherwise this Verify finished records first and listSettled names them below.
        lines.push(settledNothing
          ? "The vault is recorded as closed (closed vault, history only): historical signed work remains unresolved and protected; nothing was written and no new transaction is authorized."
          : "The vault is recorded as closed (closed vault, history only): historical signed work remains unresolved and protected; no new transaction is authorized.");
      } else {
        lines.push("Signed work may still execute and blocks other actions; Pause and Close & recover stay available — if yours confirms first, the pending one can never execute.");
        lines.push("If it is your own signed request: Pause, then Verify at depth marks it superseded, then Unpause through a governance proposal (three owner signatures, plus any delay or quorum).");
      }
      list("Pending", r.pending);
      listSettled(r.settled);
    } else if (status === "UNKNOWN") {
      lines.push(
        `${settledNothing ? "Nothing changed. " : ""}The vault may have moved outside PolicyVault with a vault key. Do not sign new actions for this vault. ` +
        "If a delegate key may be misused, pause or close the vault on chain with the owner key. " +
        "Hosted Pause and Close & recover cannot act on this vault. " +
        "After you act on chain, PolicyVault keeps showing this vault's last recorded state; only a recover that spends the recorded outpoint can be pasted below."
      );
      listSettled(r.settled);
    } else if (status === "CHAIN_CONTRADICTION") {
      lines.push("The chain currently contradicts the record (for example a reorganization); nothing changed; Verify again later.");
    }
    return { status, known, level: VERIFY_STATUSES[status].level, title: VERIFY_STATUSES[status].title, lines };
  }
  /*
   * renderVerifyHtml(result, context) — the raw status token and the
   * server's own `reason` always stay visible; everything is escaped.
   * `context` is the caller's own { restored } derivation (R1-07, C8).
   */
  function renderVerifyHtml(result, context) {
    const v = verifyStatus(result, context);
    const reason = result && typeof result === "object" && typeof result.reason === "string" ? result.reason : "";
    return (
      `<div class="refusal" data-verify-answer="${esc(v.status || "none")}" data-verify-level="${esc(v.level)}">` +
      `<div class="refusal-head"><b>${esc(v.title)}</b></div>` +
      `<div class="refusal-detail hint">Verify state: <span class="mono">${esc(v.status || "no status")}</span>` +
      (reason ? ` — ${esc(reason)}` : "") +
      `</div>` +
      v.lines.map((l) => `<div class="refusal-why">${esc(l)}</div>`).join("") +
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
    outcomeStates: () => Object.keys(OUTCOMES).slice().sort(),
    v04TransitionLines,
    renderV04TransitionLinesHtml,
    verifyStatus,
    renderVerifyHtml,
    verifyStatuses: () => Object.keys(VERIFY_STATUSES).slice().sort()
  };
  if (typeof window !== "undefined") window.PolicyVaultRefusalExplain = api;
  if (typeof module !== "undefined" && module.exports) module.exports = api;
})();
