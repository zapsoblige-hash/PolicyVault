# Changelog

## v1.10.11 — fullscale-rc45 reconciliation and delegate period-start remediation candidate

Successor of fullscale-rc44 (public v1.10.10): the completed remediation of v0.4-family transition claims and reconciliation (L5-01, present in RC42 and RC44), the hosted repair of delegate budget period starts (HOSTED-PERIOD-START-ANCHOR-01, present in RC42 and RC44), corrections to who may reject a hosted request, Verify attribution of an organization-root move broadcast outside PolicyVault (L2-01), the submit read and two-step withdrawal of a finalized organization-root request whose input another transaction spent (R3N-B1), and documentation corrections. The full record is `docs/postlaunch/lead5-reconciliation-remediation.md`; the period-start rule is specified in section 5.2 of `docs/postlaunch/platform-agent-api-spec.md`, and the organization-root rules in section 2.2 of `docs/postlaunch/v0.7-app-surface-contract.md`.

- Transition claims (L5-01): for `policyvault-0.4` and `policyvault-0.4.1` vaults, nothing releases a transition claim or its period reservation any longer because of age, repeated UTXO absence or a caller option, and protection covers signed, finalized and preflight-verified records. Before this release the reconciler released them for those reasons, so a later build could race a signed transaction that was still valid. No production occurrence is inferred.
- Blocking scoped to the live outpoint: an unresolved transition record of another transaction blocks new work only when it spends the vault's recorded live outpoint (on a closed vault, any unresolved record blocks). An ordinary build also refuses before signing when a transaction claim sits on the live outpoint (`409 CLAIM_CONFLICT`). The refusal names the blocking record (`requestId`, `action`, `state`, `signerRole`, `claimTxId`).
- Owner exits: on a live vault, the owner's Pause and Close & recover are never refused by pending delegate work and do not count toward the open-request quota. A Pause contested by pending delegate work, and every Close & recover, now returns at `SUBMITTED` ("Broadcast — NOT yet confirmed"); Verify completes it once the transaction is observed at depth. If the delegate's transaction lands first, the owner's transaction is rejected by the node or labelled STALE; press Pause again.
- Finalize: it decides everything while the request is still BUILT and never writes FINALIZED. Its first request write stores the signed bytes as PREFLIGHT_VERIFIED, so a crash can no longer leave a signed record without its bytes. An ordinary finalize takes its transition claim just before that write, and submit re-creates a missing claim of its own.
- For v0.4-family vaults, Verify (`POST /vaults/:id/reconcile`, vault owner only) is the one settlement place. Apart from three writes that need no fresh chain read (it finishes a transition the manifest already records, finishes a request from its own completion receipt, and releases an established rejection's leftover claims and reservation), it writes only on positive chain evidence at a depth of 1,000 DAA (about 100 seconds), never because of age, absence, a node error or a caller option. Its answers are CONSISTENT, ADVANCED, TERMINAL, CLAIM_PENDING, REQUEST_RECOVERY_REQUIRED, UNKNOWN and the new CHAIN_CONTRADICTION. For these vaults CLAIM_RELEASED is no longer produced and Verify never writes TERMINATED_UNKNOWN; v0.2 vaults keep their earlier Verify, and, as before, the route answers a `policyvault-0.1-beta` vault with `422 UNSUPPORTED_VERSION` and the id of a vault of any other generation with `404 VAULT_NOT_FOUND`. A `settled[]` list names the requests a Verify completed (CHAIN_VERIFIED), superseded (STALE) or released (an established rejection's leftover claims and reservation), so a CONSISTENT answer can have written. A node that cannot be read, a judged output whose `blockDaaScore` is not a canonical DAA score, or a classified environment failure answers `422 RECONCILE_FAILED` with nothing written and no event, except a restore earlier in the same pass, which the message names.
- Owner actions taken outside PolicyVault: Verify adopts, at depth, an owner's pause, unpause, or pause then unpause made outside PolicyVault on the recorded outpoint. Only an output carrying the vault's exact covenant id is a candidate, so a third party's payment to the vault's addresses can neither force a contradiction nor hide the paste control. For a recover made outside PolicyVault, the owner pastes the signed transaction (Safe JSON, at most 64 KiB and 64 outputs) on the UNKNOWN answer; it is sent as the new optional body field `outOfAppTransaction`, grants no authority, and Verify writes RECOVERED once the recover is observed at depth. On these v0.4-family vaults, a PolicyVault-built transaction broadcast elsewhere is attributed by its txid; organization roots follow their own rule, stated in the organization-root items below.
- Historical TERMINATED_UNKNOWN cards: Verify is offered on the owner's card. It restores the last recorded live state at depth, or settles the vault as above.
- Request-scoped transition recovery (the known issue listed for v1.10.10, now fixed): `reconcileTransitionWalletRequestV4` decides before it writes. A request that is not pending answers its own label with no write and no node call; a pending one is finished from a recorded advancement or settled by the same Verify pass. It writes no recovery journal for a record that has none and re-creates no claim (a record that RC42 or RC44 already journaled keeps its earlier journal path, whose chain observation now settles only at a depth of at least 1,000 DAA), so invoking it on an already-settled request no longer re-opens that request or blocks the vault. It stays an SDK/operator path; no hosted route calls it.
- Delegate period start (HOSTED-PERIOD-START-ANCHOR-01, fixed in this release for hosted paths): every hosted path that commits a new or changed delegate of a `policyvault-0.4.1` or `policyvault-0.7-kas` vault, whether the change comes from the web, raw HTTP, the SDK, the Python client, MCP, machine credentials or a self-hosted server, now starts that delegate's budget period no earlier than the synced node's DAA score when the transaction is built; a requested later start is kept, and the spent amount is committed as requested. Any change to a delegate, including a recipient-only change, restarts that delegate's budget period at the build. A request whose new or changed delegate start has become older than that delegate's budget period minus ten minutes (never less than one minute; the window is `W(L) = max(L − 6,000, 600)` DAA for a period of L DAA, 50 minutes for a 1-hour period and 23 h 50 min for a daily one) is refused with `409 PERIOD_START_STALE`, writing nothing, at the last check before it is signed into a state that cannot be withdrawn on that ground or is broadcast: v0.4-family genesis-submit, finalize and submit, the signature of a `policyvault-0.7-kas` creation, and organization-root request finalize. A node that answers but cannot be used (not synced, another network, no UTXO index, or a network position that cannot be read or is not a canonical DAA score) refuses with `422 PERIOD_START_REQUIRED`; at v0.4-family genesis-submit and submit, the submit's own node check refuses a node that is not synced, is on another network or has no UTXO index first, with `422 BUILD_FAILED`, so there `422 PERIOD_START_REQUIRED` means that the network position could not be read or is not a canonical DAA score; at a v0.4-family creation sent with the `agent` field (the form the web uses), the creation route's own node check likewise refuses such a node first, with `422 BUILD_FAILED`; at an organization-root request build whose fee input is selected automatically, the fee-input selection's own node check refuses such a node first, with `422 ORG_ROOTS_ERROR`; while the node cannot be reached at all, the build or check waits instead (see the known issues). Leaves the change does not touch are carried unchanged. A v0.4-family request reports the node DAA score it was anchored to as `review.periodStartAnchorDaa`; the committed start is the later of the requested start and that score.
- Governance exception (governance specification, section 6.2 step 4): for a delegate that an approved change adds, replaces or re-policies, the hosted pipeline commits a period start that may be later than approved, never earlier, with the spent amount exactly as approved. Moving a start later with the spent amount unchanged never raises what the delegate can spend at any time; classification stays on the approved change, and the same rule applies to changes that need no approval because they only reduce authority. A proposal therefore stays executable after any delay window. Its explanation text still shows the start the proposal requests, not the start its execution commits (the later of that start and the `review.periodStartAnchorDaa` that the built request reports).
- Delegate rule changes of a `policyvault-0.7-kas` treasury must collect every owner approval and be finalized within the new or changed delegate's budget period minus ten minutes of the build; a slower quorum cannot finalize the request, which can then only be withdrawn and built again. A not-yet-finalized, never-attempted delegate rule change whose period start has aged out can now be withdrawn (`POST /org-roots/:rootId/requests/:id/reject`) although it carries owner approvals, so a stale request no longer holds the organization root. Withdrawal does not revoke signatures or prevent an otherwise valid out-of-app broadcast. API, SDK and MCP callers may request a later start, which extends the window; the web has no such input in this release.
- Organization roots, a root move broadcast outside PolicyVault (L2-01): a delegate rule change of a `policyvault-0.7-kas` treasury that the owners approved but that was withdrawn or never finalized can still be broadcast outside PolicyVault by whoever holds its owner approvals and the fee-input signature. With this release's stale refusal and withdrawal alone (above), Verify would then have answered UNKNOWN on every call and every hosted action on the root, FREEZE included, would have been refused for good; L2-01 is rated MEDIUM. The remediation record permits one summary of this release's status, quoted here: L2-01: Narrowed C + guard implemented. From the first Verify at ≥ 1,000 DAA after an attributable case-5 broadcast, the root and its unaffected treasuries regain hosted actions, FREEZE included, once no stranded request still holds them; that Verify names any that does. Not a complete root-and-treasury recovery: the changed treasury stays UNRESOLVED when it moved outside PolicyVault (GAP-2); a later Verify restores it only when that treasury's expected output is observed unspent again; GAP-2b, GAP-3 and GAP-16 remain as stated in the disposition table; the late-broadcast funds exposure (GAP-6) and the pre-activation check omission (GAP-9) are unresolved and not accepted. For an attributable case-5 broadcast this release repairs the root-wide loss of hosted actions; it does not bring back hosted control of a treasury that moved outside PolicyVault after the broadcast. Verify (`POST /org-roots/:rootId/reconcile`) attributes such a move to the request it was built from only from fresh and exact chain evidence at a depth of at least 1,000 DAA; a contradictory, unstable, ambiguous or shallow observation writes nothing, and no spent state is recorded as current. It completes the request FULL, where the changed treasury follows the request's output, or PARTIAL, where that treasury's new output was already spent outside PolicyVault, so that the treasury is UNRESOLVED and its record unchanged. Verify then settles, on proof, the requests that the attributed transaction stranded and reports `holds` and `buildable`; only `buildable.root` true means that owner actions on the root and on the listed treasuries, FREEZE included, can be built again, and every hold names what still has to resolve. Both fields are as of that Verify: a listed treasury's own unfinished delegate request, or an output spent since, still refuses that treasury's owner actions (`409 VAULT_PENDING_REQUEST` or `409 RECORDED_OUTPUT_SPENT`), and a delegate request left unsettled after the attribution can refuse them for good (see the known issues below). A build-time liveness guard refuses to record a root request, or to reserve the root with it, when the request spends a root or `policyvault-0.7-kas` treasury output that the synced node does not report unspent at build time (`409 RECORDED_OUTPUT_SPENT`); it keeps no state, so it never closes a usable treasury, and it does not prevent a spend accepted after its read or held only in the mempool, a broadcast of the request's own transaction outside PolicyVault, or a node that misreports.
- Organization roots, a finalized request whose input another transaction spent (R3N-B1): Submit first reads every input the request spends and writes nothing when it refuses. A non-root input reported absent answers `409 RECORDED_OUTPUT_SPENT` only when the root input is still reported unspent, no output of the request's own transaction is observed, and existence evidence shows that the input was created on the selected chain for good; without that evidence it is not treated as spent (`409 SUBMIT_INPUT_UNRESOLVED`), and a chain position that cannot be read answers `422 OBSERVATION_ERROR`. After `RECORDED_OUTPUT_SPENT` the request can be withdrawn through `POST /org-roots/:rootId/requests/:id/reject` in two steps at least 1,000 DAA apart (`409 WITHDRAWAL_DEPTH_PENDING` until the second step may run), once that spend and the input's existence are final; owner actions on the root, FREEZE included, can then be built again. When the request's own transaction was broadcast outside PolicyVault, Submit and Verify keep its completion path. Uncertainty never causes a withdrawal, a claim release or a retry under a new key. A root build also refuses a fee input that is not reported unspent and exact (`409 FEE_INPUT_NOT_LIVE`) and now needs the node when an explicit fee input is named.
- Live evidence (internal automated evidence): the period-start repair and the narrowed `/wallet/v7` reject were exercised on testnet-10 with test keys (TESTNET-VERIFIED for eight live legs by automated runs, not a manual acceptance test: an anchored creation and an anchored governed change, each followed by an early rollover that the node refused; a stale refusal at genesis-submit; an anchored `policyvault-0.7-kas` creation and an anchored installed-row key substitution; a stale root finalize followed by its withdrawal and a next root request that confirmed; another agent's reject refused `403`; and a control in which a lagging delegate still paid several budgets at once, which shows that the banking stated below is unchanged). The four v0.4-family legs (the two anchored changes, the stale refusal at genesis-submit and the banking control) ran on an earlier candidate whose code on the paths those legs use this release carries unchanged apart from comments; the four organization-root and `policyvault-0.7-kas` legs were run again on this release's runtime code. Section 5.2 of the API specification still says the rule is not TESTNET-VERIFIED; that sentence is out of date and a documentation update is planned. The organization-root attribution and the spent-input withdrawal were also exercised on testnet-10 with test keys on this release's runtime code (TESTNET-VERIFIED by automated runs, not a manual acceptance test): an attributed broadcast of a withdrawn delegate rule change completed FULL at depth, with the request it stranded settled, then FREEZE with emergency pause and unfreeze of both treasuries and a root FREEZE confirmed; the owners' direct on-chain exit before any Verify, after which Verify answered UNKNOWN and wrote nothing; a PARTIAL completion whose treasury stayed UNRESOLVED and refused its hosted actions while the root and the other treasury were frozen and unfrozen; a request whose own transaction was broadcast outside PolicyVault, completed through Submit and the next Verify; and three two-step withdrawals after an input was spent by another transaction, each followed by a confirmed root FREEZE and unfreeze. Those runs did not record the submit-time chain anchor of the three withdrawals, and they confirmed the node's answer shapes except for a transaction-pool entry that is present (see the known issues). Section 10 of the remediation record still says these legs are to run; that statement is out of date. The release image itself was also run on testnet-10 with test keys and a development signer (TESTNET-VERIFIED on the exact image, by automated runs, not a manual acceptance test): a hosted vault creation, confirmed at genesis-submit; the Verify badge of a signed delegate request that was not broadcast; an agent's reject of the owner's request refused `403` and the legacy reject route answering `404`; an owner pause and recovery, each settled by Verify at depth; and a smoke of the anchored start and of the stale refusal. Browser checks of the image's served page (not testnet legs) also passed: a signed-out start that loaded the five changed web assets and rendered the Verify answers, and, with fixture answers and nothing sent to the image, the withdrawal texts, the attribution answers, the `STATE UNRESOLVED` badge, the Submit offer and the dialog shown when a root cannot be read. In the same run, the hosted build-authority suite (all eight cases, including the four that need a live node) passed from a fresh extraction of the release source, not from the image, against the same testnet-10 node and an isolated PostgreSQL database.
- Rejecting a request: in hosted mode, only the request's signer or the vault owner may reject a request on `POST /wallet/v4/requests/:id/reject`, the legacy `POST /wallet/requests/:id/reject`, `POST /wallet/v5/requests/:id/reject` and `POST /wallet/v6/requests/:id/reject`, and only the request's signer or an active owner of the vault's organizational root on `POST /wallet/v7/requests/:id/reject`: any other participant, another agent or an approver-only participant included, gets `403 REQUEST_FORBIDDEN` with nothing written, and a non-participant gets `404`. Owner-minted machine credentials act as the owner. The legacy reject and signature routes answer `404 REQUEST_NOT_FOUND` for every record that is not a v0.2 request. Before this release an agent could reject the owner's request, and through the legacy route any participant who could read a request, an approver-only participant included, could reject any v0.2 or v0.4-family BUILT request, the owner's Pause, Close & recover and removeAgent included; on rooted `policyvault-0.7-kas` vaults an agent could reject another agent's spend request while it was BUILT or AWAITING_APPROVALS, an agent of a testnet-only rooted `policyvault-0.7-payment` or `policyvault-0.7-payment-hd` vault could likewise reject another agent's spend request, and on the testnet-only `policyvault-0.5` and `policyvault-0.6` vaults an agent could reject the owner's BUILT requests and another agent's spend requests.
- Organization identity events: `POST /identities` with an `orgId` now requires the caller to own that organization. An `orgId` that is not a lowercase UUID string answers `422 ORG_ID_INVALID`, a missing or foreign organization `404 ORG_NOT_FOUND`, and a member who is not the owner `403 ORG_FORBIDDEN`; each of these answered `201` before, and none of them now writes an identity, credential or event. A request without `orgId` is unchanged. `identity.revoked` carries the stored `orgId` only when the revoking wallet still owns that live organization. The fix is forward-only: identity events already stored by earlier releases with an organization their creator did not own stay visible to that organization's readers, and nothing is rewritten or purged.
- Events: `request.confirmed` is emitted only when a submit reaches CHAIN_VERIFIED. A submit that returns at `SUBMITTED` emits no `request.*` event, and neither do the settlements a Verify performs. `vault.reconciled` carries the Verify status as `outcome` and, when the outcome names one, the `requestId` in `correlation`; its `data` stays `{outcome, to}`, so `settled[]` is not published. Every answered vault Verify (`POST /vaults/:id/reconcile`, HTTP 200), UNKNOWN and CHAIN_CONTRADICTION included, emits one `vault.reconciled` event, which the event store keeps; the organization-root Verify (`POST /org-roots/:rootId/reconcile`) emits no event, as before. Where these notes say that Verify writes nothing, they mean that no vault, organization-root, request, claim, reservation, receipt or history record changes.
- Web console: every Verify answer is shown through a closed status map, so an answer the page does not know is never shown as success. The owner's UNKNOWN answer offers the recover paste, and Pause and Close & recover read "Broadcast — NOT yet confirmed" until Verify settles them. The legacy console no longer verifies v0.4-family vaults automatically and offers Cancel only for v0.2 requests. For `policyvault-0.4.1` and `policyvault-0.7-kas` vaults, the web never invents a delegate period start: the `policyvault-0.7-kas` forms read the network position when Build is pressed and refuse to build without it (there is no `0` fallback) and no longer replace an installed delegate's wallet in place (remove the delegate and add a new one), and the browser accepts the server's anchored start only if it is no earlier than its own requested start and no more than 600 DAA earlier than its own network read taken before the build. The web forms of the testnet-only token and HD generations keep their earlier start defaults, which can be `0`. Signing reviews of delegate changes, and a resumed signed treasury creation, show what the delegate could spend at once if the transaction were confirmed now and when its next budget becomes available; a delegate rule change shows its finalize deadline on the root request, next to each approval button and on the Change delegate rules form. The organization-root page marks a treasury that Verify left UNRESOLVED and explains its refusals, offers Submit for a finalized request and the two-step withdrawal after `409 RECORDED_OUTPUT_SPENT`, and its withdrawal confirmations state that withdrawing marks the request withdrawn in PolicyVault and releases the root's reservation, broadcasts nothing, and does not revoke the owner signatures already given. Five served assets change: `app-v4.js`, `app.js`, `kas-vault-ui.js`, `org-root-ui.js` and `refusal-explain.js`.
- Documentation: the new remediation record states the settlement rule, the owner exits, the limitations and the rollback posture. Section 4.1 of the execution-attestation specification now lists the governance refusals (`GOVERNANCE_PROPOSAL_TERMINAL`, `GOVERNANCE_PROPOSAL_UNKNOWN`) and their attestation semantics, which v1.10.10 noted as missing. The API, events and authorization-boundary documents describe the changes above; the API specification (section 5.2), the governance specification, the organization-root application contract and the MCP and Python client specifications state the delegate period-start rule and its limits. Section 10 of the remediation record and section 2.2 of the organization-root application contract describe the organization-root attribution, the build-time guard, the UNRESOLVED treasury, the submit read and the two-step withdrawal, with the status label, the disposition of each sub-case and the remaining cases. The mainnet generation statement is corrected: v0.4-family transition build, finalize, submit and Verify check the network, not the generation, except where a record's identity is validated, so the earlier statement that v0.4 mainnet mutation and request recovery stay refused by the allowlist was wrong for those operations. New mainnet creation is unchanged (`policyvault-0.4.1`, `policyvault-0.7-root`, `policyvault-0.7-kas`).

Known issues and limits of this release (unless an item states an exposure or a state change, they fail closed and change no vault or request state):

- Changes with no hosted exit: if a vault moves outside PolicyVault in a way Verify cannot attribute (a delegate spend made outside PolicyVault, an owner top-up or governance action made outside PolicyVault, a chain of several such changes, or a racing delegate spend that overturns a hosted Pause or removeAgent completed at zero depth), Verify answers UNKNOWN or CHAIN_CONTRADICTION and the hosted exits are lost: hosted Pause and Close & recover spend the recorded outpoint, so their submit is refused, with nothing written and no fee paid. While this lasts, each delegate can spend its banked amount (below) at once and then one period budget per further period, with payments capped by the protected value and fees by the fee reserve. At consensus the owner of a v0.4-family vault can still pause or recover the current output with one owner signature plus a fee input. No packaged tool does this yet; it is a planned follow-up. For a `policyvault-0.7-kas` treasury, which has no owner key, the consensus exit goes through its organization root: either FREEZE with the root's emergency quorum K plus the treasury's emergency pause, or AUTHORIZE with the root's full quorum M plus the treasury's pause or its recover to the recovery key fixed at its creation; one FREEZE pauses one treasury, and while the root is frozen it accepts neither another FREEZE nor an AUTHORIZE, so pausing a second treasury of that root, or recovering the treasury just paused, first needs an UNFREEZE with the full quorum M. No packaged tool performs this exit, and it moves the root outside PolicyVault (the GAP-1 boundary below). For a v0.4-family vault, the hosted record does not converge after such an on-chain remedy: a pasted recover is reconciled only when it spends the recorded outpoint, which in this class is already spent or never existed; the `policyvault-0.7-kas` exit through the root is not reconciled (the GAP-1 boundary below). Owner top-ups and governance actions made outside PolicyVault are not reconciled. Press Verify about two minutes after any action that reduces authority (for example Pause, Close & recover or removing an agent) to confirm that it settled at depth. The same class covers an organization root moved outside PolicyVault by any transaction other than one of its recorded requests, the owners' direct on-chain exit included: Verify answers UNKNOWN for the root, writes nothing and runs no settlement, and its hosted exits are lost (the GAP-1 boundary below); a broadcast of a recorded request's own transaction is attributed as the organization-root items above state.
- Accepted for this release as an explicit, disclosed exception: the limits of changes with no hosted exit, exactly as the item above states them. For v0.4-family vaults, Verify reconciles owner actions taken outside PolicyVault only for pause, unpause, pause then unpause, and a pasted recover; for an organization root it attributes only a move by the transaction of one of the root's recorded requests. The class is not repaired and stays open in the repair backlog for a later release; this acceptance is not a technical closure of it and accepts no future finding.
- Organization roots, unresolved after this release (L2-01 sub-cases): GAP-2, rated MEDIUM, unresolved: while a treasury is UNRESOLVED, hosted builds, finalize and broadcast on it are refused (`409 TREASURY_STATE_UNRESOLVED`, naming the attributed request and its txid, with nothing written), an approval of an existing delegate request on it is still recorded but cannot reach the chain, and a root FREEZE does not stop its delegates, which stay bounded by their covenant policy and recipients. Hosted actions on it return only if a later Verify observes its expected output unspent again at depth, never from stale or spent state; attribution follows one move, so a treasury moved again outside PolicyVault is not followed. The only other remedy is the owners' direct on-chain exit, which moves the root outside PolicyVault. GAP-3, rated MEDIUM (a low-likelihood sub-case), unresolved: when two records carry the attributed transaction, Verify answers AMBIGUOUS and writes nothing, and the root-wide loss of hosted actions, FREEZE included, persists for that root. GAP-16, rated LOW: for a finalized request whose own transaction was broadcast outside PolicyVault, Verify answers SUBMIT_TO_RECORD until the request's Submit; Submit records the request and answers `409 RECONCILIATION_REQUIRED`, because the node reports the transaction already accepted, and the next Verify completes it and re-attaches the root; an earlier unobserved treasury write can name a spent output, so that treasury answers UNKNOWN and its builds are refused `409 RECORDED_OUTPUT_SPENT`. The GAP-1 boundary: a root moved outside PolicyVault in any other way stays UNKNOWN. A request that settlement cannot settle keeps holding the root, and Verify names it.
- Accepted for this release as an explicit, disclosed exception: GAP-2, exactly as the item on the L2-01 sub-cases above states it; section 10.2 of the remediation record, which does not accept GAP-2, predates this acceptance. GAP-2 is not repaired and stays open in the repair backlog for a later release; this acceptance is not a technical closure of GAP-2 and accepts no future finding.
- Accepted for this release as an explicit, disclosed exception: GAP-3, exactly as the item on the L2-01 sub-cases above states it; section 10.2 of the remediation record, which says that unresolved HIGH and MEDIUM findings remain release blockers, predates this acceptance. GAP-3 is not repaired and stays open in the repair backlog for a later release; this acceptance is not a technical closure of GAP-3 and accepts no future finding.
- Organization roots, finalized requests whose input another transaction spent (R3N-B1; GAP-2b in the disposition table): the remaining cases are listed in section 10.3 of the remediation record; each is rated LOW, one of them only with the control described next. Requests built before this release, which carry no build-time input observation, and requests already held at CLAIM_PENDING cannot be withdrawn and keep holding the root; this case is rated LOW only with the pre-activation check, which counts every pending root request without a build-time input observation (AUTHORIZED, SIGNED, BROADCAST or RECONCILIATION_REQUIRED) and every request whose Verify answers CLAIM_PENDING before this release is activated (section 10.3 of the remediation record says that it lists them; it reports counts only); a count above zero stops activation until each counted record is located and assessed, with no invalidation, deletion or repair of any record (without that check this case is MEDIUM). After a withdrawal, a reorganization deeper than 1,000 DAA, an index lag of 1,000 DAA or more, or a node that does not merge what it accepted could let the withdrawn request's transaction be accepted; Verify then answers NOT_IN_SCOPE naming it and writes nothing, and the root's hosted exits, FREEZE included, are lost, as at the GAP-1 boundary above. Any block producer can postpone a withdrawal, and the hosted FREEZE with it, for as long as it keeps placing transactions that name one of the request's inputs, at no cost in keys or fees. The root lock is held within one process only, so a second service process could interleave with a withdrawal (only one service writer is supported). One corner keeps a permanent root-wide hold, FREEZE included: a non-root input under 1,000 DAA deep at build, created by a transaction other than the root's, spent by another party before Submit, no PolicyVault save of the request between about 100 seconds after the build and the end of the node's retention (at least about 30 hours), and a first withdrawal step only after that retention ended. In the hosted record this hold does not end. The owners' direct on-chain exit moves the root outside PolicyVault (GAP-1): Verify then answers UNKNOWN and writes nothing; no settlement runs. In that corner a Submit answers 409 at once and offers the withdrawal, which works at any time within the retention.
- Separate and unresolved: the late-broadcast funds exposure (GAP-6): a delegate rule change the owners signed can be broadcast outside PolicyVault later, also after it was withdrawn, until one of its inputs is spent (for example by a confirmed later root transition), and each delegate it installs can then spend one extra budget for each period elapsed since its build, capped just below the protected value, and about the whole principal for an AUTHORIZED request that RC44 built with a `0` period start; withdrawal does not stop such a broadcast, and whoever holds the signatures chooses its timing. The pre-activation check omission (GAP-9): the pre-activation check (revision 6) does not count AUTHORIZED requests that RC44 built with a `0` delegate period start. The later revision of that check, described in the item above, counts every pending root request without a build-time input observation and is therefore expected to count such requests while they are pending; no test confirms this, and that check is an operator procedure of the hosted service and is not part of the published source. GAP-6 and GAP-9 are each rated MEDIUM. Neither is changed by this release, and being outside its repairs does not by itself make either accepted.
- Accepted for this release as an explicit, disclosed exception: the late-broadcast funds exposure (GAP-6), exactly as the separate item above states it; the status quoted from the remediation record above, its section 10.2 and row r5 of its section 10.3, which call GAP-6 not accepted, predate this acceptance. GAP-6 is not repaired and stays open in the repair backlog for a later release; this acceptance is not a technical closure of GAP-6 and accepts no future finding.
- Accepted for this release as an explicit, disclosed exception: the pre-activation check omission (GAP-9), exactly as the separate item above states it; the status quoted from the remediation record above and its section 10.2, which call GAP-9 not accepted, predate this acceptance. GAP-9 is not repaired and stays open in the repair backlog for a later release; this acceptance is not a technical closure of GAP-9 and accepts no future finding.
- Organization-root saves that wait for the node: the slot-request, slot-signature, finalize and succession-signature saves of a root request now connect to the node to record existence evidence whenever an input of the request other than the root's was less than 1,000 DAA deep at its build and its existence is not yet recorded as final, with no overall timeout. During a node outage these owner saves can wait indefinitely and hold the in-process root lock until restart, so every other action on that root, FREEZE included, waits too. Nothing false is written, and the save completes once the node answers.
- Deferred to a later release as a disclosed item: a bounded timeout for the organization-root saves that wait for the node (the item above). The bounded timeout stays open in the repair backlog; deferring it is not a technical closure and accepts no future finding.
- Another root's identifiers in a refusal: a root request on one root that names another root's UNRESOLVED treasury is refused `409 TREASURY_STATE_UNRESOLVED` with that other root's attributed request id and txid in the message, and the treasury summaries' `stateUnresolved` shows that request id and txid to the treasury's delegates and approvers, who are not root participants. These identifiers grant no access, because the root request routes are root-scoped.
- Delegate requests left unsettled after an attributed root move: when the settlement of a delegate request that the attributed transaction stranded fails in the Verify that attributes the move (a store or node error; the answer lists the request under `unsettled`) and a hosted root transition then completes before the next Verify, no later Verify settles that request. It stays RECONCILIATION_REQUIRED, and the hosted owner actions on its treasury, FREEZE with emergency pause included, are refused `409 VAULT_PENDING_REQUEST` for good; the root and the other treasuries stay usable. Pressing Verify again retries that settlement only while the root's live output is still the one the attributed transaction created. Under RC44 the same request strands that treasury as well; the class is not new.
- One damaged organization-root request record of any root makes `GET /wallet/v7/vaults` and `GET /org-roots/:rootId/vaults` answer 422 for every principal who sees a `policyvault-0.7-kas` treasury; every `policyvault-0.7-kas` action is already refused in that state.
- Store damage can also hold a root: a `policyvault-0.7-kas` delegate rule change that carries owner approvals and is not finalized, and whose stored delegate registry is not a list or whose treasury record is missing, can be neither finalized (once its approvals are complete, finalize refuses it with `422 REGISTRY_ROOT_MISMATCH` or `404 VAULT_NOT_FOUND`) nor withdrawn (`409 CANNOT_REJECT`), so it keeps the root reserved and every new hosted action on that root, FREEZE included, is refused (`409 ROOT_PENDING_REQUEST`) until the store is repaired. Where the stored registry is a list but does not fold to the agent root the request commits, the request can be withdrawn only once the stale withdrawal above applies to one of its new or changed delegates.
- The withdrawal's transaction-pool check reads the orphan flag under a field name that the node does not use: when the request's own transaction is in the node's transaction pool, a withdrawal step refuses `409 CANNOT_REJECT` with the finding MEMPOOL_UNCLEAR instead of naming the transaction pool and pointing to Submit, and a transaction the node holds only as an orphan never lets the withdrawal proceed. Nothing is written and no request is withdrawn in error.
- The organization-root request view still says that a finalized request cannot be withdrawn when its period start aged after it was finalized, although the same view offers the two-step withdrawal once Submit has found an input spent by another transaction; the server decides every withdrawal.
- The confirmations of the two-step withdrawal say that PolicyVault withdraws the request "only because an output it spends was spent by another transaction" without naming which of the outputs it spends (the fee, treasury or vault output) was spent; the request's own view names it, and the meaning is the same.
- Further organization-root limits are listed in section 10.4 of the remediation record, among them: a crash between a later Verify's treasury write and its history line leaves that upgrade without its line; a Verify that reverses an interrupted upgrade answers ADVANCED although neither the root nor the treasury moved in it; a completion finished after a crash carries `via` `reconcile` or `submit-recovery` in its history line; and the internal codes `500 TREASURY_STATE_UNDETERMINED` and `500 RECONCILE_ANSWER_SHAPE` have no closed web explanation and are not reachable through the routes with the current SDK. No test pins that a failed treasury write during a later Verify's upgrade is raised as `RECONCILIATION_REQUIRED`; the code fails closed either way (no upgrade is reported, the treasury stays unwritten and its builds are refused, and the next Verify completes the upgrade).
- Correction to section 10.2 of the remediation record: its GAP-3 row says "the guard prevents new strands of this kind", which overstates the build-time liveness guard. The guard reads only at build, while the root output is unspent: it refuses new requests on a root output that is already spent, but it does not prevent two records from carrying one transaction (two such records left by RC44, or an unsigned request withdrawn and rebuilt with a requested future start, or a removal-only change, that reuses the same automatically selected fee input). The rating and likelihood of GAP-3 stated above are unchanged; a documentation update is planned.
- Correction to sections 10.1 and 10.2 of the remediation record and to section 2.2.3 of the organization-root application contract: of a treasury that Verify left UNRESOLVED, they say "every hosted action on it is refused", which overstates the refusal. Hosted builds, finalize and broadcast on such a treasury are refused (`409 TREASURY_STATE_UNRESOLVED`), but an approval of an existing delegate request on it is still recorded and cannot reach the chain, and a withdrawal of a delegate request on it and a Verify of it still answer. The GAP-2 item above states this scope, and its rating is unchanged; a documentation update is planned.
- Armed requests: a request that is preflight-verified or finalized but not submitted (armed) on the live outpoint refuses every other ordinary build, and the web has no submit control for it. The exit is Pause, then Verify at depth (the armed request becomes STALE), then Unpause through a governance proposal: three owner signatures in the web ceremony plus any configured governance delay and quorum, and network fees. An owner can also submit the armed request through the API. A v0.4-family request refused `409 PERIOD_START_STALE` at submit stays armed in the same way.
- Recover: every Close & recover is two-step. The submit returns `SUBMITTED`, and Verify writes RECOVERED at depth. Keep one output of the recover unspent until Verify shows RECOVERED. A pasted recover must be Safe JSON and spend the recorded outpoint directly; Verify reads only the address of `outputs[0]` and at most 4 further distinct output addresses, so keep `outputs[0]` unspent. If every output is spent before depth, Verify answers UNKNOWN and the card stays live, although the funds are with the owner.
- UNKNOWN is a point-in-time answer: UNKNOWN leaves no durable marker. The card keeps its last recorded status until a Verify settles it.
- Zero-depth completions: on v0.4-family vaults, uncontested non-terminal hosted submits (an uncontested Pause, and ordinary actions such as removeAgent) still complete at zero depth, as before; Close & recover never does. A RECOVERED status that an earlier release wrote at zero depth is not re-checked; a historical TERMINATED_UNKNOWN is.
- A request that was never signed in PolicyVault (BUILT, AWAITING_APPROVALS or WALLET_REJECTED; signed elsewhere) whose spend Verify completes by its txid keeps its receipt and its unsigned label if that completion stops after the vault's state is advanced. Verify never finishes an unsigned request from its receipt, so a WALLET_REJECTED label, or a later reject, then exports FAILED for an executed spend.
- When Verify advances a vault by the transaction of an unsigned request that the governance gate refuses, that request keeps its label (a closed one included), exports REFUSED and gets no receipt; the ADVANCED answer names no request, but a CLAIM_PENDING answer below depth still names it. A crash between that advance and its history row loses the history row; the vault state, the request and its attestation stay correct. If another pending request sits on the spent outpoint, a stop after that advance also leaves it unsettled until the next Verify settles it, or for good if the vault moves on first. An authorized unsigned retry that shares the transaction of such a request and consumed its own proposal is never completed: it stays BUILT, exports AUTHORIZED / IN_PROGRESS, can later be labelled STALE, and has no receipt.
- Two requests can share one transaction. After the request that a completion receipt names has executed and one further transition has moved the vault, the other, signed request is mislabelled: its own submit writes STALE (hosted `409 STALE`), or Verify never finishes it, so a closed vault answers REQUEST_RECOVERY_REQUIRED for it permanently. When its submit writes STALE, it exports AUTHORIZED / FAILED (STALE) with no transaction id while the executed request exports SETTLED. The executed request, the vault state and the agent registry stay correct; funds, authority and the covenant are unaffected.
- A Verify that stops (process kill or store error) after completing a transition and before marking a non-terminal competing request STALE, followed by the vault moving on before a Verify settles that step (a further zero-depth transition, or a further transition that a later Verify settles at depth or adopts), leaves that request unsettled: for example, the owner's contested Pause stays `SUBMITTED` and, after a Close & recover, the closed vault answers REQUEST_RECOVERY_REQUIRED for it permanently. The owner's Pause and Close & recover keep working.
- The transaction probe that Verify runs is dynamically linked. A dynamic-loader failure (exit 127; a broken runtime image, or a transient failure to map a shared library, for example under memory pressure) is treated as a defect of the record being checked, not as an environment error: in a terminal settlement the affected competing request stays unsettled, and if the probe fails for every record Verify answers CHAIN_CONTRADICTION with nothing written instead of `422`.
- The repository's authorization-boundary check is lexical and does not bind role arguments. The routes changed here are pinned by their own hostile tests; the owner-only rule on governance proposal creation and cancellation has no merged behavioural regression test yet.
- An `orgId` that names a legacy-format or unknown-schema organization answers `500 ORG_SCHEMA_*` to any caller, including one who does not belong to it (an existing store-integrity alarm).
- The web derives the restore notice after a Verify from the card on screen, so a stale TERMINATED_UNKNOWN card can attribute an earlier restore to this Verify.
- In hosted mode, a participant with build authority on a vault, an agent included, can submit a request that another participant has already signed and preflight-verified. This gives no new authority, because the transaction is already signed and verified, but such a signed and preflight-verified request cannot be withdrawn: an owner who no longer wants it broadcast should Pause. A narrower submit rule is a recorded follow-up.
- The v0.4-family reject route also accepts an open request record of another generation from that record's signer or vault owner and marks it with the v0.4 rejected state. This gives the caller no authority it does not already have over that record.
- Rejections through `POST /wallet/v7/requests/:id/reject` record no rejecting wallet on the request and emit no event. None of the five wallet reject routes records the rejecting wallet on the request or in an event: the v0.4-family reject route emits `request.rejected`, which does not name it, and the legacy and the testnet-only `/wallet/v5` and `/wallet/v6` reject routes emit no event. Rejections made before this release, when another agent could still reject such a request (see the item on rejecting a request above), therefore cannot be attributed to a wallet from the request records or the stored events.
- Delegate budget banking (V041-V07KAS-PERIOD-BANKING-01; a pre-existing covenant property, not changed by this release): in the frozen `policyvault-0.4.1` and `policyvault-0.7-kas` covenants, the period rollover proves only that a period has begun, not that it is the latest one. A delegate whose period lags can therefore roll into each missed period in turn and spend a full budget in each, all valid at the same moment. For one delegate with current DAA score T, period start S (S < T), period length L, budget B and spent amount σ, it can spend at once (floor((T − 1 − S) / L) + 1) × B − σ, then B per further period (internal VM-verified evidence with the real compiler and test-key signatures; the exact bound is not testnet-verified, although the live control above observed the banking itself; finality was modelled from rusty-kaspa source, not executed on a node). Other covenant generations with the same rollover rule were not probed. The vault total stays capped by its protected value, every spend is still bounded by its per-spend cap, recipient allowlist, approval tier and fee cap, and a paused vault allows no delegate spend. The hosted remaining-budget display (budget minus spent) understates what a lagging delegate can spend at once, and the earlier "budget-conservative" wording in `docs/architecture.md` is corrected. A consensus fix needs a new additive covenant version.
- The delegate period-start repair does not change the banking above: an idle or lagging delegate still banks one budget per elapsed period, a delegate holding its key can still submit directly to a Kaspa node, an unpause still releases the paused backlog, and delegates already on chain keep their starts until an owner action changes, rotates or removes them. Until the vault's existing delegates are changed, compare each delegate's period start with the current DAA score, remove idle delegates, and remember that an unpause releases the paused backlog.
- Two windows remain after the period-start repair: a signed `policyvault-0.7-kas` creation and a finalized organization-root request are not re-checked for their period start at submit, and neither can be withdrawn on that ground (a finalized root request can be withdrawn only after Submit finds an input spent by another transaction, as described above); the web submits a creation immediately and shows the immediately spendable amount before a resumed creation or a root request is submitted. For requests built by this release these windows give a delegate no more than a delegate whose period started at the build and stayed idle.
- Requests already signed before this release (a signed `policyvault-0.7-kas` creation, or a finalized organization-root request carrying a delegate rule change) keep the start they were signed with, which may be `0`, and are not re-checked at submit; they are a separate residual with no upper bound other than the protected principal, and the operator counts them before this release is activated.
- The period-start check is hosted: the browser compares the server's start only with the same server's network position, and the covenant sees only the agent root, so a dishonest server can still commit a stale start; only a new additive covenant version could enforce the rule at consensus.
- Delegate periods shorter than 6,600 DAA (below the 1-hour product minimum; reachable only through the API) are accepted with a 600-DAA window: a delegate that passes the last check and is accepted within ten minutes of it can confirm with up to `⌊6,599 / L⌋` budgets beyond its remaining budget (1 for L = 6,000; 10 for L = 600), and acceptance later than those ten minutes adds one more budget for each further L DAA of delay. Each payment stays bounded by its per-spend cap, fee cap, recipients and approval tier, and the total by the protected value.
- Node lag counts against the ten-minute margin: the configured node is accepted while Kaspa reports it synced, which tolerates about 11 minutes of lag (about 6,610 DAA). A delegate change that passes its last check near the edge of its window on a lagging but synced node and is accepted shortly after can therefore confirm with one extra budget; periods of 6,600 DAA or more confirm with no extra budget when the node's lag plus the acceptance delay after the check stay within ten minutes. Planned follow-up: refuse `422 PERIOD_START_REQUIRED` unless the node's latest block is recent within a stated tolerance, or widen the margin.
- An unreachable node does not refuse: while the configured node cannot be reached, a build or check of a new or changed delegate waits until the node is reachable instead of answering `422 PERIOD_START_REQUIRED`, and the withdrawal check of a stale root request waits likewise (once the node answers, a withdrawal that the check cannot confirm is refused with `409 CANNOT_REJECT`, never `422`), writing nothing meanwhile. While a `policyvault-0.7-kas` delegate rule build waits, every other build, finalize, submit or reject on that organization root, FREEZE included, waits for the root's lock. Planned follow-up: a bounded node connection, so that an unreachable node refuses `422`.
- A proposal created through the API, SDK or Python client that requests a delegate period start later than the network position at the build cannot be executed from the web: the web review refuses to sign it, and the web attempt has already used up the proposal when it built the request. The refusal never gives a delegate more. Execute such a proposal through the API or SDK; after a web attempt, finalize and submit the request the web already built through the API or SDK (its requested later start passes the freshness check), or reject it and create a new proposal. The specifications name only the first and last of these exits; a documentation update is planned.
- On the v0.4 wallet-request routes, an error raised inside the request pipeline, including an infrastructure failure, is still answered as a retained 4xx refusal, not `503 IDEMPOTENCY_OUTCOME_UNKNOWN`. Such an answer does not prove that no request was built, so check the vault's requests. Because a 4xx answer is retained under its Idempotency-Key, a keyed build refused with `422 REQUEST_RECOVERY_REQUIRED` is replayed for that key even after the blocking work resolves; use a new key (for MCP, a new request id) for a genuinely new attempt.
- Precision on the remediation record, the API specification and the events specification: their list of environment failures that answer `422 RECONCILE_FAILED` attributes the compiler and VM-preflight failures to the step that classifies the probe-harness failures; an earlier step of this release classifies them. Behaviour is as stated: every listed failure answers 422 RECONCILE_FAILED with no event and nothing written, except a restore earlier in the same pass, which the message names.
- A delegate can chase the owner within its per-period budget (with banking) and the fee-reserve cap; the remedy is to pause again or suspend agents.
- API-RAW-ERROR-500-01 is not fixed and remains a LOW residual, unchanged since v1.10.10: raw error text can still reach clients through credential-lookup failures before the idempotency layer, requests without an Idempotency-Key, the /auth and secret-bearing routes, and v4-build 422 remaps.
- Under network congestion, a new low-value `policyvault-0.4.1` vault (about 19 KAS or less) can miss the 60-second window of its creation submit: its creation transaction pays the minimum fee for its compute mass, but for a low-value vault its storage mass is larger, so when blocks are full it ranks below ordinary minimum-fee transactions. The submit then answers `422 RECONCILIATION_REQUIRED` and keeps its claim, and the creation completes through `POST /wallet/v4/requests/:id/reconcile` (the request's signer; in the web app, "Reconcile against the chain" on the unresolved creation) once the transaction is mined. There is no priority-fee option; pricing the creation fee on the larger mass, or a bounded priority fee, is a planned follow-up. This is unchanged since v1.10.10.
- A creation completed through that reconcile route emits no `vault.created` or `request.confirmed` event: the last event for it is the `request.failed` of the refused submit, although the vault was created, so event and webhook consumers should read the vault state. Emitting the same completion events as the creation submit is a planned follow-up.
- A request authenticated with a machine credential can briefly hold a second database connection, because the update of the credential's last use is not awaited (unchanged since v1.10.10).

Upgrading and rollback:

- Upgrading: stop every older service writer before starting this release, and do not run an older version and this release against one store. Only one service writer is supported; mixed RC44 and RC45 writers are unsupported. After the upgrade, reload every open console page: pages loaded before it still run the earlier web assets, which show the Verify answers UNKNOWN, CHAIN_CONTRADICTION and REQUEST_RECOVERY_REQUIRED in the success style and none of this release's delegate period-start lines.
- Rollback is forward-only. Apart from the organization-root records named below, RC45 writes only shapes that RC44 and RC42 can read, but an image-only return to RC44 (or RC42) is not a qualified recovery: the age release of claims returns; contested Pause or recover records still `SUBMITTED`, and unresolved records RC45 left on earlier outpoints, fall under RC44's vault-wide guard, so every hosted build, owner Pause included, and every Verify answers REQUEST_RECOVERY_REQUIRED; a preflight-verified record without its own claim gets CLAIM_CONFLICT from RC44's submit, RC44's Verify can release the delegate's claim, and a later landing makes it write TERMINATED_UNKNOWN; RC44's Verify writes TERMINATED_UNKNOWN on vaults RC45 left at UNKNOWN, and RC44's web has no Verify on that card; a paste from an open RC45 page is ignored by RC44, which then writes TERMINATED_UNKNOWN; RC44 counts RC45's uncounted Pause and recover requests toward the quota again, so the owner's Pause and Close & recover can hit QUOTA_EXCEEDED; and the quota exemption, the reject rule, the organization-owner check on `POST /identities` and the v0.2-only rule of the legacy reject and signature routes revert, which reopens the request-rejection defect fixed here (still present in RC44) and lets new identity events again name an organization their creator does not own. The `/wallet/v5`, `/wallet/v6` and `/wallet/v7` reject rules and the delegate period-start repair revert as well: RC44 again commits the delegate starts that a request or proposal carries, and it does not use `review.periodStartAnchorDaa`, which it can read. RC44 and RC42 recognize none of the organization-root records this release adds (the attribution marker, the build-time input observation, the withdrawal anchor, the input-spent withdrawal record and the treasury upgrade fields); RC44's completion check of a chain-verified root request requires a final transaction, which an attributed request does not carry, and RC44 has neither the build-time guard, the UNRESOLVED treasury refusal nor the submit read, so after an attributable root move outside PolicyVault every hosted action on that root, FREEZE included, is lost again (L2-01 reopens). RC44 never withdraws a root request that carries owner approvals, so the withdrawal of a stale delegate rule change is gone as well, and RC44 treats a request this release withdrew that way as ended and never effective. A forced return needs an empty drain set: every record RC44's guard protects, every claimless preflight-verified record on a live outpoint, every contested record, the owner's Pause and recover requests beyond RC44's quota, every live v0.4-family vault that answers UNKNOWN in an owner-run Verify sweep, every request built by this release that sets a delegate period start and is not yet submitted, every `policyvault-0.7-kas` root request finalized by this release and not yet submitted, and every organization root or treasury that holds an organization-root record RC44 cannot read (a pending root request with a build-time input observation, a request with an input-spent record, an attributed chain-verified root request, or a treasury Verify left UNRESOLVED); section 8 of the remediation record lists only the first five of these classes. No reviewed read-only query that counts this drain set exists yet. A vault with no hosted exit never drains, so a forced return accepts, visibly to the owner, that RC44 writes TERMINATED_UNKNOWN on it; a root or treasury holding such a record never drains either, so a forced return accepts, visibly to the owner, that RC44 cannot read that record: an attributed root's history cannot complete, and an UNRESOLVED treasury loses its refusal. An unchanged schema number (011) does not establish rollback safety.
- This release is made with its forward-only rollback posture accepted; acceptance of an earlier release's rollback does not carry over to this release. That acceptance includes the stated fact that no reviewed query counts the drain set yet, and it authorizes no forced return, restoration or data disposal. It is an explicit, disclosed exception: the missing drain-set query stays open in the repair backlog, and this acceptance is not a technical closure of that gap and accepts no future finding.

For API consumers: `403 REQUEST_FORBIDDEN` on the five wallet reject routes for a participant who is neither the request's signer nor the vault owner (on `/wallet/v7`, an active owner of the organizational root); `422 PERIOD_START_REQUIRED` on any build of a new or changed delegate (`POST /wallet/v4/create`, `POST /wallet/v4/requests`, `POST /org-roots/:rootId/vaults`, `POST /org-roots/:rootId/requests`; simulate reports it as `refusalReason`) and at every check point when the configured node answers but its DAA score cannot be used (at a v0.4-family build the gates before that read have already run: a released risk review that matched the action is used up, and the attempt may already be logged; at v0.4-family genesis-submit and submit, a node that is not synced, is on another network or has no UTXO index is refused first by the submit's own node check with `422 BUILD_FAILED`, at `POST /wallet/v4/create` with the `agent` field such a node is refused first by the creation route's own node check, also with `422 BUILD_FAILED`, and at `POST /org-roots/:rootId/requests` with an automatically selected fee input such a node is refused first by the fee-input selection with `422 ORG_ROOTS_ERROR`); `409 PERIOD_START_STALE` at the check points above, and from v0.4-family finalize and submit it carries five detail fields, `agentPk`, `periodStartDaa`, `currentDaa`, `periodLengthDaa` and `windowDaa`, which the API specification's refusal table does not list yet (none is stored); `422 REGISTRY_ROOT_MISMATCH` when a request's stored registry does not fold to the agent root it commits (store damage), and `404 VAULT_NOT_FOUND` at root finalize for a missing treasury record; the optional `review.periodStartAnchorDaa` (a decimal string) on v0.4-family requests that anchored a delegate; `404 REQUEST_NOT_FOUND` on the legacy `/wallet/requests/:id/reject` and `/signature` for any record that is not a v0.2 request; `409 CLAIM_CONFLICT` before signing when a transaction claim sits on the live outpoint, and `422 REQUEST_RECOVERY_REQUIRED` when an unresolved record of another transaction spends it, both carrying `requestId`, `action`, `state`, `signerRole` and `claimTxId` (the signature and submit routes also carry the caller's own `request`); `422 VAULT_TERMINAL` or `422 RECONCILIATION_REQUIRED` instead of `409 STALE` for a closed manifest or one already advanced by the request's own transaction; `422 RECONCILIATION_REQUIRED` at signature and submit, with nothing written, when the request's own completion receipt exists; the Verify answers and `settled[]` above, with `400 BAD_FORMAT` for an `outOfAppTransaction` that is not a string, is a string over 64 KiB or is a transaction with more than 64 outputs (a document that does not parse as a transaction is not refused: it settles nothing), and `422 UNSUPPORTED_VERSION` when it is sent for a `policyvault-0.1-beta` or v0.2 vault (the id of a vault of any other generation answers `404 VAULT_NOT_FOUND`); `422 ORG_ID_INVALID`, `404 ORG_NOT_FOUND` and `403 ORG_FORBIDDEN` on `POST /identities`; and, for organization roots, `409 RECORDED_OUTPUT_SPENT` at a root request build (a recorded root, treasury or vault input that the node does not report unspent and exact; nothing recorded, the root not reserved) and at Submit (with `error.submitRead`), `409 TREASURY_STATE_UNRESOLVED` on every hosted build, finalize and broadcast on an UNRESOLVED treasury, `409 FEE_INPUT_NOT_LIVE` at a root request build (with `error.feeInput`), `409 SUBMIT_INPUT_UNRESOLVED` at Submit, `409 WITHDRAWAL_DEPTH_PENDING` (with `error.earliestDaa` and `error.latestDaa`) and `409 CANNOT_REJECT` (with `error.withdrawal.finding`) on the two-step withdrawal, and `422 OBSERVATION_ERROR` at a root request build or Submit when the node's chain position cannot be read; the root Verify answer's `holds`, `buildable` and `treasuryUpgrades`; and the treasury summaries' `stateUnresolved`, which a client reads first, because while it is set the status, live state, agents and approvers shown are the last record. These refusal fields are top-level members of the HTTP error envelope, beside `code` and `message`, and the JavaScript client exposes them as `err.extra`. An Idempotency-Key reused for both withdrawal steps replays the first step's 409, so send a new key for the second step. The unchanged clients report the new refusals verbatim: the MCP reject tool returns a REFUSED envelope with `httpStatus` 403 and `data.error.code` `REQUEST_FORBIDDEN` (a same-request retry replays that refusal), the JavaScript client throws `PolicyVaultApiError` with that status and code, and the Python client raises `ScopeError`, its class for every 403, with `.code` `REQUEST_FORBIDDEN`, so branch on `.code`. A `periodStartDaa` that a client sends for a new or changed delegate is a lower bound, and the unchanged clients pass the period-start refusals through verbatim like every other API refusal (MCP as a `REFUSED` envelope with the API error under `data`).

There is no migration, database schema change (schema 011), covenant, generator or compiler change, and no MCP package change; the new stored values are the optional request field `review.periodStartAnchorDaa` and, on organization-root requests, the optional records of an attribution, a build-time input observation, a withdrawal anchor and an input-spent withdrawal, with an attribution proof on the requests an attributed move superseded and an upgrade line in the history; none needs a migration. Five served web assets change. This preparation does not imply deployment or publication.

Image `sha256:32d45a3096b29eefc0dd97f2fc1e582ee00cb32236bbd7293c6626fd8bd4652d`, build `1fa26b33`, source `1fa26b337aaf2767c75268ff8ed7f67ee83d07a3`. Source verification: 799/799 selected Node-only checks from 62 changed suites pass with zero failures and no skipped test in a fresh run from the candidate source. The candidate's complete SDK, API, browser and MCP suites ran on the JSON store and on PostgreSQL (318 suites in both modes, 8613 passing checks, no failing check) from an extraction verified identical to that source. The hosted build-authority suite ran only as its node-free subset, so its four cases that need a live node are not claimed by these suite runs (the changelog's live evidence states where they ran), and two other suites that need a live testnet node (a live-chain attestation vector, whose offline check passed, and an organization-root genesis recovery, none of whose cases ran) timed out without a node, so their node-dependent cases are not claimed; the second part of the hierarchical-delegation hostile suite (the testnet-only `policyvault-0.7-payment-hd` generation), which needs a Rust toolchain, ran in neither mode and is not claimed.

Public verification: Fresh selected checks from the exported tree: 799/799 pass with zero failures and no skipped test. Exact result SHA256 `a89f8ab7fbe78ed54c2bd3bf3f33b830ce737f72afc51d4f242e571df923cb1c`. Historical evidence applies only to explicitly unchanged bytes; this is not a fresh full SDK/PostgreSQL, VM or financial-cycle claim.

MCP `policyvault-mcp@1.6.2` remains unchanged, SHA256 `128403f81d4af7b73ae86a31a750d39ec21c28f518d214f4e678807c3dff0c14`; no package republication is part of this release.

## v1.10.10 — fullscale-rc44 schema-011 repair candidate

Narrow repair successor of fullscale-rc42 (public v1.10.8): four corrections and the store-path governance attestation ladder.

- Idempotency (IDEMPOTENCY-UNRESOLVED-01): on idempotency-supported routes, a keyed POST protects its original attempt permanently. When the operation itself fails on a keyed POST without a definitive 4xx (any 5xx or status-less error), the response is `503 IDEMPOTENCY_OUTCOME_UNKNOWN` — the original error code is not returned — and the claim is kept, because the operation may already have taken effect. While the store is healthy, every retry with the same key then gets `409 IDEMPOTENCY_OUTCOME_UNKNOWN` without running the handler. If the server stopped or its store failed mid-request, a same-key retry may instead get `409 IDEMPOTENCY_IN_PROGRESS` indefinitely (age never releases a claim), or the retained original response; a claim whose creation never landed simply executes afresh. A 5xx raised before the operation starts (for example a failed credential lookup) keeps no claim. In every case, inspect the operation's domain state before using a new key for a genuinely new attempt. Completion is conditional on the original claim owner.
- Authentication routes (AUTH-VERIFY-IDEMPOTENCY-01): `/auth/*` joins `/identities`, `/webhooks` and `/notifications` as routes that never persist or replay a keyed response.
- Governance (GOVERNANCE-TERMINAL-RACE-01): a create-only terminal claim arbitrates each proposal's terminal transition (cancel or consume), so exactly one succeeds even when process clocks are skewed. A build whose proposal consumption is refused is marked, and finalize and submit refuse it; for a governed request with a recorded intent manifest they also re-check that its proposal was consumed by that request. Such a request stays listed as BUILT, and the unchanged web client does not yet explain that state before signing. Other known residuals (LOW): a malformed terminal claim fails closed on read and transition paths but listings still show the proposal as open; after a crash between the claim and the record write the raw proposal record is not rewritten (reads overlay the claim; metrics count the raw status).
- v0.7-kas manifest timestamps (G1-01-TIMESTAMP): a record written without a `createdAt` gets identical `createdAt` and `updatedAt`, and a supplied `createdAt` is kept verbatim.
- Governance attestations (GOVERNANCE-ATTESTATION-LADDER-01, store path): Attestations for governed v0.4 requests follow the finalize/submit gate's governance refusal (store-path attestation ladder), except where broadcast evidence exists: a request in a broadcast-pipeline state keeps its record, and a signed row (FINALIZED or PREFLIGHT_VERIFIED) with a receipt for its transaction id keeps its broadcast rung while the gate refuses it — a receipt that carries a request id (submit pipeline or request-scoped recovery) names the request that executed, but a vault-reconcile receipt (no request id) cannot distinguish a reconciled own transaction from an executed content-identical retry; an unsigned row whose content-identical retry executed is presented REFUSED like the gate, and its record does not mention the retry; a governed row built before this release whose proposal was not consumed by it, and that was marked STALE after its own transaction reached the chain, is presented REFUSED (a STALE row whose proposal it consumed, or an ungoverned one, is still presented AUTHORIZED with a STALE failure); the refusal-marker branch presents REFUSED regardless of broadcast (reachable over a broadcast only after an image-only return to RC42), and so do the intent-verification branches (reachable over a broadcast only through tampering or a verifier change); and some gate/attestation differences on tampered records remain. Informational: a governed request interrupted before its intent manifest is recorded skips the finalize/submit re-check while its proposal stays open, and a request built before this release that shares another request's content-identical manifest record is not bound to its own proposal by the re-check.

Also part of this release:

- Every governed v0.4 request built by RC44 carries the new additive field governanceProposalId; a refused governed build also carries governanceConsumption ('REFUSED') and governanceConsumptionCode. The governance record (`docs/postlaunch/governance-terminal-race-repair.md`) does not yet name governanceProposalId.
- The header comment of migration 005 (server/migrations/005_platform_agent_api.sql lines 41-43) still says a CLAIMED (IN_PROGRESS) idempotency record is reclaimable after a bounded staleness window (IN_PROGRESS_STALE_MS). That no longer describes behaviour: from RC44, age never reclaims a claim. Migrations are checksum-pinned and immutable, so the comment stays. server/src/idempotency.js still exports IN_PROGRESS_STALE_MS for source compatibility only ('Age never grants ownership', line 16).
- API-RAW-ERROR-500-01 is not fixed and remains a LOW residual in RC44. Raw error text can still reach clients through credential-lookup failures before the idempotency layer, requests without an Idempotency-Key, the /auth and secret-bearing routes, and v4-build 422 remaps. The new 503 IDEMPOTENCY_OUTCOME_UNKNOWN answer on keyed POSTs to wrapped routes hides some raw messages incidentally; that is not an API-RAW fix.
- Known issue, not changed by this release: request-scoped transition recovery in the SDK (`reconcileTransitionWalletRequestV4` in `sdk/src/wallet-recovery-v4.js`; no hosted route calls it) does not check that the request it is given is the one the vault reconcile names. Invoked on a request whose outcome is already settled, it can re-open that request and leave the vault blocked (building, finalizing and submitting wallet requests for that vault are refused), with no supported undo. Invoke it only on the request that `POST /vaults/:id/reconcile` (or `findProtectedTransitionV4`) returns as needing request-scoped recovery.
- Upgrading: stop every older service writer before starting this release, and do not run an older version and this release against one store (for example during a rolling update). Older code such as RC42 can delete aged unfinished idempotency claims and execute those operations again, and it ignores governance terminal claims and refused-consumption markers.
- Rollback is forward-only. Once RC44 has written records, an image-only return to RC42 is not a qualified recovery: RC42 re-executes uncertain keyed operations after 5 minutes, ignores governance terminal claims and REFUSED markers (a refused governed request becomes finalizable again), stores and replays keyed sign-in responses again, and presents every governance attestation population above as AUTHORIZED again. An unchanged schema number (011) does not establish rollback safety. RC42 itself still refuses the intent-verification branches and requests in a refused authorization state (AUTHORIZATION_FAILED or INSUFFICIENT_APPROVALS), so those stay REFUSED after such a return, with RC42's own codes.

For API consumers: a governed build whose proposal consumption is refused answers with that refusal (`409 GOVERNANCE_PROPOSAL_TERMINAL` when the proposal was already cancelled or consumed), although the request has been persisted. Finalize and submit answer `409 GOVERNANCE_PROPOSAL_TERMINAL` for such a request. For a governed request with a recorded intent manifest, once that manifest re-verifies, they also answer `409 GOVERNANCE_PROPOSAL_TERMINAL` when its proposal was not consumed by it, and `409 GOVERNANCE_PROPOSAL_UNKNOWN` when its proposal record is missing or belongs to another vault. Where the attestation ladder above presents one of these requests REFUSED, its execution attestation carries the same governance code as `refusalCode` (a governed request in a refused authorization state may now carry the governance code instead of its state code), and an attestation decided on a governed request's proposal record lists `policyvault-governance-proposal-record/v1` in `producer.sources`. Section 4.1 of the execution-attestation specification (`docs/postlaunch/execution-attestation-spec.md`) does not yet list governance refusals.

Client documentation (the SDK README, the Python client's docstrings and README, and the platform API specification) now describes the idempotency and authentication-route outcomes; the Python client change is documentation only. The governance and attestation changes are described in this section and in the governance record. Recovery guidance and known residuals: `docs/postlaunch/idempotency-recovery.md` and `docs/postlaunch/governance-terminal-race-repair.md`.

There is no migration, database schema change, covenant or generator change, served web asset change or MCP package change. This preparation does not imply deployment or publication.

Image `sha256:8208ba6fb3e01907a125881f45787fbe63df28997f977f145d1c51f06a4966a1`, build `df5b8de`, source `df5b8deafadb2dbfb3c65f6156f57a3b52543184`. Source verification: 66/66 selected Node-only repair checks pass with zero failures; 3 attestation-ladder suites that need PostgreSQL or an RC42 extraction are skipped by design in this Node-only run and are covered by the ladder's separately reviewed JSON and PostgreSQL runs; the 2 changed PostgreSQL-bearing suites pass 100/100 on PostgreSQL 16.4 in a separate pre-release run on the four-fix source, after which the only runtime change is the read-only attestation ladder, which adds no SQL statement and was not re-run on PostgreSQL.

Public verification: Fresh selected repair checks from the exported tree: 66/66 pass with zero failures or skipped tests; 3 attestation-ladder suites that need PostgreSQL or an RC42 extraction are skipped by design. Exact result SHA256 `ab9155b096f81ea3113812e8d33f79133f0d8ea460d5fad2bd8ae1d55229dabf`. Historical evidence applies only to explicitly unchanged bytes; this is not a fresh full SDK/PostgreSQL, VM or financial-cycle claim.

MCP `policyvault-mcp@1.6.2` remains unchanged, SHA256 `128403f81d4af7b73ae86a31a750d39ec21c28f518d214f4e678807c3dff0c14`; no package republication is part of this release.

## v1.10.8 — fullscale-rc42 UI release candidate

KAS treasury delegate forms use the shared recipient and period controls, and approved public funding/signing explanations distinguish free software and self-hosting from current official hosted access. Existing approver and signing-threshold behavior is preserved. Backend, contract, core, dependency and MCP package bytes are unchanged from RC40. This candidate is not a deployment or human acceptance claim.

Image `sha256:f108d5384b3a95b55f52d5e1e706fa565f8a9955e79f5389d28a672bfb0517f2`, build `a84e2a9`, source `a84e2a957bd6a43a86b28b860c1894515758e1e4`. Source verification: 245/245 focused source checks pass, zero failures/skips.

Public verification: Fresh exported UI suite: 245/245 pass, zero failures/skips. Exact result SHA256 `bae7a348545119a123f75ee8852e61ee46712e583049bfe74c5ab857a73ae7de`. Prior full-suite and MCP evidence is explicitly unchanged baseline reuse; no new full-suite or financial run is claimed.

MCP `policyvault-mcp@1.6.2` remains unchanged, SHA256 `128403f81d4af7b73ae86a31a750d39ec21c28f518d214f4e678807c3dff0c14`; no package republication or new credential proof cycle is part of this UI release.

## v1.10.6 — fullscale-rc40 release candidate

A narrowly validated retained owner-recovery conflict now returns PROTECTED_UNRESOLVED without writing when another recorded completed owner recovery owns the exact predecessor claim and the retained request, receipt, signatures and closed manifest agree. The historical losing request, winner records, claims, reservations, receipts, manifest and audit remain unchanged; its admission guard remains active. This disposition does not establish rejection or nonacceptance, remove claims, rebuild, sign or rebroadcast. Incomplete or conflicting evidence still refuses.

This candidate supersedes the blocked, unpublished fullscale-rc36, fullscale-rc37, fullscale-rc38 and fullscale-rc39 artifacts. Public v1.9.3 remains the published baseline. Its image is `sha256:3919653b7316228d29c0196d329c3ee3550d07dad7ac9015ada6b98f1cc85a7c`, buildId `79dec5f`. Deployment, public publication and independent acceptance are pending. Served health and the package registry identify what is actually delivered.

A delayed Bearer-authentication usage update can no longer restore an ordinarily revoked machine credential. The usage writer conditionally changes only lastUsedAt on the currently matching ACTIVE credential. JSON performs the latest-record check and patch without yielding under the supported one-service-writer contract; PostgreSQL applies one conditional field UPDATE. Revoked, missing or mismatched records remain unchanged, and usage telemetry never grants another scope. Fresh restart and both database lock-order regressions cover the correction. Authentication already admitted before revocation is not retroactively cancelled; initial identity/credential creation remains a separate two-record operation.

Negative settlement now requires the original submission anchor, a complete acceptance window without a reorg or this transaction's acceptance, repeated exact funding observations, exact mempool misses, absent outputs and a stable sink. Settlement of an actual node rejection requires a durable proof bound to that request and its retained rejection. An eligible stale ordinary request with transport ambiguity can instead reach NOT_BROADCAST through a nonacceptance proof bound to the original request, transaction and saved submission anchor, without inventing a rejection. Historical unproved negative labels and known-accepted node answers cannot use that ordinary fallback. A missing current output or historical error string cannot establish nonacceptance; spent or missing inputs, incomplete metadata/history, errors and contradictions retain the claim.

Recovery observes the same durable request without rebuilding, signing or rebroadcasting it. Positive completion still requires the supported outcome evidence and preserves existing records through create-only writes and matching genesis lineage. Retained v0.4.1 transitions now recover through request-bound observation, durable completion journaling, exact output script/version checks, and protected ordinary admission. Legacy NOT_BROADCAST labels and known-node answers cannot bypass these guards. Old requests without enough original evidence remain protected. Legacy headless claims require their original definition; unsupported or unavailable history is not invented. One service writer per data root remains the supported operating contract.

Source verification: Focused RC40 source checks 94/94; new foreign-completion and existing transition recovery coverage, no failures/skips. RC38 full and RC39 affected results remain historical evidence.

Public reproduction: RC40 fresh public affected verification: sdk-affected 136/136, mcp 58/58; no failures or skips. The retained RC38 public baseline has 4262 JavaScript, 92 reference Python, 23 tools Python and 450 VM passes, 8 byte-identical regenerations and 3 consistency checks, with original run03/04 provenance. The separately validated RC39 affected run has 135 SDK and 58 MCP passes. Complete published path/blob/mode correspondence binds RC39 to that baseline and RC40 to exactly two recovery runtime changes, one new synthetic test, the independently reviewed section 3e freeze record, and the exact root-reviewed public classification record delta. Prior RC39 scanner-policy approval does not establish a public-byte PASS for that new record; fresh RC40 privacy is required. Historical and fresh counts overlap and are not added. This is not a full RC40 rerun.

The KAS covenant remains labelled CANDIDATE. Any byte-freeze attestation requires independent review of the exact replacement artifacts. MCP `policyvault-mcp@1.6.2` is a proposed package (tarball SHA-256 `128403f81d4af7b73ae86a31a750d39ec21c28f518d214f4e678807c3dff0c14`); its delivery is pending. The adapter provides unsigned scoped operations, carries no genesis/signature/submission tool, and supports root `ownerRecover` without implying rooted-vault recovery support.


## v1.9.3 — PRODUCTION RELEASE `fullscale-rc31`: organizational-root availability and refusal presentation on mainnet (owner-observed RC30 finding RC30-HA-UX-01) — browser presentation only

**WEB/AGENT PRODUCTION: LIVE at https://app.policy-vault.org — this release's build is `fullscale-rc31` (buildId `ec80d60`, image `sha256:cae6b7e7cb073a17b7f9dc0dd54288556e13c6157f08a1712e91624e0878fc32`); the served `/api/v1/health` `buildId` is authoritative for which build is active (`ec80d60` = this release, `9dbc5f7` = the preceding rc30 build, live since 2026-09-09 06:01 UTC) · NATIVE MOBILE: DEVELOPMENT.**
This release changes three browser files and nothing else at runtime (`web/app-v4.js`, `web/org-root-ui.js`, `web/refusal-explain.js`, plus three test files): no SDK, server, covenant, compiler, authorization, signing or submission byte changed; schema 011 is unchanged (migrations byte-identical), so rc30 remains a schema-compatible image-only rollback target — with the finding below reintroduced if it is ever re-activated — and every write made under either build stays readable by the other. The mainnet-creatable generation stays `policyvault-0.4.1`; new v0.7 organizational-root / payment creation remains unauthorized on mainnet, and no UI test enables it. The finding was observed by the owner during the live mainnet acceptance of rc30 and corrected by the separate AI reviewer that runs that acceptance (internal review — not an external audit); this release re-verified the correction independently, corrected one residual its own second reviewer found, rebuilt and re-verified the exact artifact, and deployed it. Security assurance stays INTERNAL and evidence-based.

### What changed for live users (mainnet exposure)

- **Organizational-root creation is offered only where it can succeed (RC30-HA-UX-01).** The Organizations view previously offered the full "Create organizational root" wizard on mainnet even though only `policyvault-0.4.1` vaults can be created there; the build was then refused by the SDK's generation guard, the refusal appeared in the global notice behind the wizard with generic "change the values" advice, and it persisted after navigating to Create Vault. Now the console reads the server's capability discovery (`GET /api/v1/capabilities`) next to the root list and enables root setup only when discovery for the SAME network advertises both `policyvault-0.7-root` and `policyvault-0.7-payment` as creatable; missing, malformed, mismatched or incomplete discovery leaves the control disabled with an upfront explanation ("not available for creation on mainnet in this release — use Create Vault for a single-owner vault, or create a hosted organization to group vaults"). Existing on-chain roots, their history and hosted organization grouping stay readable (hosted grouping never confers covenant owner authority). Discovery is presentation: the server and SDK generation gates remain the authority and are unchanged. `web/org-root-ui.js` (`rootCreationAvailability`), `web/app-v4.js` (`rootCreationAllowed`, checked before the wizard opens and again before a build).
- **Generation refusals explain themselves.** A refusal for a covenant generation that is not owner-authorized on mainnet now says that changing the wallet address or amounts cannot enable it and points at the supported single-owner Create Vault flow; the server's exact code and message stay visible verbatim. The older `BUILD_FAILED` wrapper is recognized only when its message contains the SDK guard's exact sentence for one of seven known generations — unrelated build failures keep their existing explanation. `web/refusal-explain.js`.
- **Build errors belong to the wizard.** A server refusal during root setup renders inside the wizard (announced as an alert and focused); cancelling or leaving Organizations clears only the wizard's own notices; a newer pending or uncertain-outcome warning is always preserved — including when the refused response of an abandoned build arrives late — and a build that completes after the owner cancelled is withdrawn ("withdrawn before signing") instead of re-opening a review over whatever view is now open. `web/app-v4.js` (`noteRootWizard`, `navigateTo`, the late-outcome guards in `buildAndReviewRoot`).
- Supported v0.4.1 Create Vault, the Vaults / Activity views and tab navigation are unchanged in behaviour (navigation goes through one helper that clears only a wizard-scoped notice).

### Distribution and build integrity

- Image `policyvault-app:fullscale-rc31` = `sha256:cae6b7e7cb073a17b7f9dc0dd54288556e13c6157f08a1712e91624e0878fc32`, buildId `ec80d60`, `SOURCE_DATE_EPOCH` 1789015576, base `ubuntu:26.04@sha256:2260313b…`; context = the deterministic 317-file source bundle of `ec80d60` (content id `5396ca1a…`) + the privacy-safe vendor stage (six tracked pins, byte-identical). The image's `/app` file set differs from the live rc30 image in exactly the three runtime files and three test files above.
- **Reproducibility, stated exactly.** Two pipeline builds of the identical context produce the identical image digest and byte-identical OCI archives, both under the pipeline's Docker layer cache (the first build took its base and toolchain layers from the cache and built every application layer fresh; the second build was fully cached). No cold-cache reproduction is claimed: the cold-rebuild timestamp limitation recorded for v1.9.2 is unchanged by a web-only delta. An intermediate image of the reviewer's uncorrected commit was built and verified during this release and never deployed or published.
- Exact-artifact verification on the release archive: archive ↔ build record ↔ OCI index/manifest/config ↔ loaded image id; 314 `/app` source files, 12 vendor files and six tracked pins byte-identical to the context and the source commit; both ISC notice copies present, root-owned and not group/world-writable; `LICENSE` / `NOTICE` byte-identical at root, `mcp/` and inside the image.
- Fail-closed artifact privacy scan of the exact release archive: complete, 25 designated production values, 0 findings, 28 exact classifications (the new image config's nine upstream base-image build-path history commands are byte-identical to the previously classified rc30 config; the config differs from it only in the build id and the timestamps).
- `policyvault-mcp@1.5.0` is unchanged by this release (registry version and integrity re-read; no republish). Installed SDK / mobile clients are unaffected (no client-library byte changed).

### Tests and evidence (automated / internal — never human acceptance)

- Automated gates on the build source `ec80d60` (automated / internal evidence only): full web suite **815/815** (the launch floor 796 + 19 new / changed cases); the new 13-case DOM regression **13/13** GREEN, with RED classified by the failure reached — **11 fail / 2 pass** on the live rc30 web bytes (`9dbc5f7`) and **3 fail / 10 pass** on the reviewer's uncorrected commit (the two notice-scoping assertions and the late-success case); the seven affected web suites re-run on the PRODUCT BYTES extracted from the exact image (`/app/web`, `core`, `sdk/src`, `server/src`, `contracts` from the image; test-only fixtures and dev dependencies from the source commit) **227/227**; core-bundle anti-drift IDENTICAL; portable sync identical; exact-artifact verification of the release archive (archive ↔ build record ↔ OCI index / manifest / config ↔ loaded image id; 314 `/app` source files, 12 vendor files and six tracked pins byte-identical to the context and the source commit; both ISC notice copies root-owned and not group/world-writable; `LICENSE` / `NOTICE` byte-identical at root, `mcp/` and in the image); hosted-mode boot of the exact image with its own empty PostgreSQL database and the migrations run inside the container (schema 011, health `buildId ec80d60`, readiness 200, synchronized testnet-10 node with UTXO index, capabilities, six served hashes == source, anonymous build refused 401, zero financial rows); fail-closed privacy scan of the exact release archive (complete, 25 designated production values, 0 findings, 28 exact classifications).
- Public-tree delta reproduction from ONLY this release's exported candidate tree (fake HOME, the documented sibling toolchains, lockfile `npm ci`; reproduction subject = candidate A `3ceddafb…`, whose runtime bytes are identical to the final tree — the final tree differs only in the release documents): byte delta vs the reproduced v1.9.2 tree = exactly the three changed browser files, the three changed / added tests, the two added tooling files, the classifications file and the four regenerated release documents (`delta-vs-v192.txt`); every reused suite's inputs unchanged (0 differing entries under `tests/vm` — the earlier reproduction's generated `Cargo.lock` aside — `sdk/src`, `sdk/tools`, `server`, `core`, `mobile`, `mcp`, `python`, `security`, `integrations`, `conformance`, `sdk/package{,-lock}.json`; every `contracts/*.sil` identical); private-path grep = the scanner's own regex literal only (classified since v1.9.1); `npm audit` 0; core-bundle anti-drift identical; tools **20/20**; image-scan classification **4/4**; scanner unit controls **13/13**; the new protected-backup helper's unit tests **10/10**; the FULL web suite from the public tree: run 1 **803 pass / 12 fail** — every failure `pv_call_encoder` / `pv_tx_probe not built` (the RC-UX-1 browser cases and the REAL / REAL-TAMPER pre-sign cases build real v4 requests through the VM encoder; the delta script had not built the VM binaries — the same TEST ENVIRONMENT class as the v1.9.2 run 1; retained as `web-full.log.txt`), run 2 after `cargo build --bins` from the public workspace **815/815, 0 skipped** (`web-full-run2.log.txt`). VM, covenant regeneration, core, SDK, server, mobile, mcp, python, security, integrations and conformance are reused from the v1.9.1 reproduction and the v1.9.2 delta on that mechanical evidence.
- Browser: signed headless-Chromium harness on the exact image (TEST-ONLY dev signer, testnet-10, tmpfs JSON data; every section including the rooted-vault owner operations) **212/212, 0 uncaught page errors**, served bytes captured before and after the run and stable (the harness's known console-error entries retained and classified in the private record) + the UX-11 self-test failing as intended (64/65, exit 1, only the injected page error); signed-out first-run smoke in real headless Chromium on the exact image at 1280 px and 375 px — PASS, 0 page errors / 0 console errors; the 13-case DOM regression drives the real page and scripts with a synthetic wallet and intercepted HTTP. No real-wallet or human evidence is claimed by automation.
- Live (after the rollout): the rollout of this build on the hosted deployment and its served verification (plain canonical GETs of every changed asset with body hashes compared to the release image and the edge cache status recorded; a fresh-context real-Chromium check of the affected views with a synthetic wallet provider bound to an unfunded test identity for message sign-in only; the acceptance, first-run and served-extras suites through the public route) are recorded in the private release record; the served `/api/v1/health` `buildId` is authoritative for which build is active at any moment, and a browser that still holds an older copy of a changed file keeps the previous behaviour until it revalidates.
- Reused with recorded applicability (mechanically checked: no byte under `core/`, `sdk/`, `server/`, `mobile/`, `mcp/`, `tests/`, `contracts/`, `deploy/`, `python/`, `security/`, `integrations/`, `conformance/` changed between the rc30 build source `9dbc5f7` and `ec80d60` — the whole runtime delta is the three browser files): the v1.9.2 / v1.9.1 core 1343/1343, security 54/54, integrations 188/188, conformance 21/21, mcp 58/58, mobile 98/98, python 92/92, full SDK + live PostgreSQL 1399/1399, the eight webhook / notification suites 53/53, covenant regeneration IDENTICAL ×7, VM 406/5 + delta 44/44 (not one clean run — the recorded erratum stands), the rc30 exact-image webhook regression and hosted-boot evidence for the unchanged server, the MCP 1.5.0 live consumer proofs and the 100-user capacity run.
- Independent read-only reviews (internal AI reviews, not audits): the correction was written by the separate AI reviewer that runs the owner's live acceptance, with its own read-only reviewer pass; this release's session read the whole diff independently and its second read-only reviewer found one LOW presentation-only residual (the wizard's progress notice surviving Cancel; a build succeeding after Cancel re-opening the review) — corrected in this release with RED-first regressions and re-reviewed on the exact bytes ("no concrete regression found"). The reviewer's affected live re-verification follows this release; owner mainnet human acceptance follows that.

### Not in this release / limitations

- Native mobile stays DEVELOPMENT. No real-wallet (KasWare) evidence is claimed by automation for this release (the served UI check uses a synthetic wallet provider bound to an unfunded test identity for message sign-in only); the owner validates live mainnet independently. Rooted vaults, token surfaces and the HD / KAS candidates are testnet-only; the mainnet-creatable generation stays `policyvault-0.4.1`. Silverscript v1.0 adoption (SS-UPGRADE-01) is deliberately NOT part of this release. The permanent purge-on-deploy / content-addressed-bundle follow-up (rc29-OPS-1) remains open: the origin serves the browser files with `Cache-Control: no-cache` and the edge revalidated them on every observed request, which is not a durable invalidation guarantee for every edge or existing browser copy. x402 facilitator: PRODUCTION-READY pilot packet, NOT deployed. MCP usage telemetry OFF.

## v1.9.2 — PRODUCTION RELEASE `fullscale-rc30`: corrections from the independent post-launch launch review of the running rc29 deployment (webhook response-socket lifetime bound, upstream Silverscript ISC notice) + evidence errata for v1.9.1

**WEB/AGENT PRODUCTION: LIVE at https://app.policy-vault.org — this release's build is `fullscale-rc30` (buildId `9dbc5f7`, image `sha256:4a6dce6e7646e9aa460340339887e117c48185bf7ecdbcae8c5107c72da8be21`); the served `/api/v1/health` `buildId` is authoritative for which build is active (`9dbc5f7` = this release, `f217011` = the preceding rc29 build, live since 2026-09-09 01:17 UTC) · NATIVE MOBILE: DEVELOPMENT.**
The rc30 activation on the hosted deployment is recorded in the private release ledger; schema 011 is unchanged (migrations byte-identical), so rc29 remains a schema-compatible image-only rollback target — with the two defects below reintroduced if it is ever re-activated — and every write made under either build stays readable by the other. The corrections come from the independent read-only launch review of the LIVE rc29 stack by the separate AI reviewer (internal review — not an external audit), which also prepared the source correction; this release re-verified that correction independently, rebuilt and re-verified the exact artifact, and deployed it. Security assurance stays INTERNAL and evidence-based; nothing here is externally audited and no external audit is part of the process.

### What changed for live users (mainnet exposure)

- **Webhook response-socket lifetime (review finding RC29-LR-01, medium — availability only)**: the delivery worker's only per-attempt deadline was cleared as soon as the receiver's response HEADERS arrived, so a receiver that acknowledged and then stalled or trickled its body below the 8 KiB drain cap could keep that socket open indefinitely inside the shared API process while the worker moved on and opened further sockets. The absolute deadline (10 s default) now survives header acknowledgement until the response ends or the socket closes; the header outcome is unchanged (2xx delivered, non-2xx failed, 3xx never followed), the byte cap, the DNS-answer pinning and the private-address refusal are intact. `server/src/events-delivery.js`; RED-first `sdk/test/rc29-webhook-response-deadline.test.js` (real loopback sockets, nine cases: complete, success-stall, refusal-stall, redirect-stall, oversized, broken, trickle, no-headers, six concurrent acknowledged stalls — 4 pass / 5 fail on the previous module → 9/9). Production impact: zero active webhook endpoints were registered at every observation; the defect could not affect authorization, custody or funds — it bounded nothing on the receiver's side.
- **Upstream Silverscript ISC notice (LS-02 extension, low)**: the shipped `silverc` compiler and the vendored KCC20 reference program come from Silverscript revision `d25bd3427a093c17327ca3d6b9e1aa5f7688c863`; its unchanged ISC copyright and permission notice (sha256 `feee0f42096fab1ad3cbd301091c303d0f424766fa24be3cd36718fdd2a2aaa3`) now ships at `contracts/vendor/LICENSE` and, inside the image, beside the compiler at `/home/pv/silverscript/LICENSE` (`deploy/Dockerfile`); `contracts/vendor/README.md` states the provenance. PolicyVault's Apache-2.0 `LICENSE` / `NOTICE` and every other third-party notice are unchanged. This closes the identified notice obligation; it is not an exhaustive third-party licensing opinion.

### Evidence errata for v1.9.1 (public statements corrected; the published v1.9.1 tree itself is unchanged)

- `PUBLIC_RELEASE_MANIFEST.md` of v1.9.1 stated "1097 byte-identical + 2 public-only, 9 presentation-modified". The measured, disjoint classification of the same 1,099 published files is **1089 byte-identical to the source commit + 8 presentation-modified + 2 public-only**: the five legacy test fixtures under `docs/postlaunch/ux-evidence/codex-rc27f/fixtures/` are presentation-modified by their generator-path redaction (the cp13 delegate-recovery fixture is byte-identical), and README, SECURITY and `deploy/droplet-setup.sh` are the other three. This release's manifest is generated by a corrected writer that computes disjoint categories from the actual bytes and refuses missing or unclassified paths.
- The v1.9.1 statement "two byte-identical builds" of the rc29 image is correct but both builds used the Docker layer cache; the reproducibility statement for THIS release records cache use explicitly (below).
- The v1.9.1 public-tree VM evidence was **406 passed / 5 failed** (stale v0.7 SDK vector generators; `cargo` stopped at the failing binary) followed by a **44 passed / 0 failed** delta run of the four affected binaries with the corrected generators — retained suite inventories support 450 distinct final cases, but it was not one clean 450/0 run. The dated notes in `docs/postlaunch/v0.7-covenant-byte-freeze.md`, `v0.7-kas-profile-readiness.md` and `v0.7-security-claims.md` describe the RED period; this entry states the run shape.
- Private-record errata (restore-rehearsal attribution, whole-host journal totals, image-layer reuse coverage) were corrected in the private release records by the reviewer and are carried forward there; none of them changes a public claim.

### Distribution and build integrity

- Image `policyvault-app:fullscale-rc30` = `sha256:4a6dce6e7646e9aa460340339887e117c48185bf7ecdbcae8c5107c72da8be21`, buildId `9dbc5f7`, `SOURCE_DATE_EPOCH` 1788926971, base `ubuntu:26.04@sha256:2260313b…`; context = the deterministic 316-file source bundle of `9dbc5f7` (content id `2a869676…`) + the privacy-safe vendor stage (six tracked pins, byte-identical).
- **Reproducibility, stated exactly.** Three builds were compared. The reviewer's build (2026-09-09 04:13 UTC; base/toolchain layers from the Docker layer cache, application layers built fresh) and this release's pipeline build (05:01 UTC; every step from the layer cache) produce the **identical image digest** — identical layer blobs and config; their OCI archives differ only in the index annotation that names the tag. A **cold `--no-cache` rebuild does NOT reproduce the digest**: 8 of 25 layers differ (the apt layer, the two `/tmp` COPY layers and the Node-install layer, the `useradd` layer and the three `/home/pv` vendor layers) — in modification timestamps (cache-assisted layers keep the epoch-clamped timestamps of the 2026-09-02 build that populated the cache; cold layers carry this source's epoch) and in seven build-time-stamped files (`etc/shadow` — the `pv` account's last-change day; `var/cache/ldconfig/aux-cache`; `var/log/alternatives.log`, `var/log/apt/eipp.log.xz`, `var/log/apt/history.log`, `var/log/apt/term.log`, `var/log/dpkg.log` — dates only, same sizes); every file's size, every other file's content, the dpkg package set (90 packages, identical versions) and all 14 `/app` application layers plus the permissions layer are byte-identical. The release artifact is therefore reproducible under the pipeline's layer cache; from a cold cache the application layers reproduce and the base layers reproduce in content but not in timestamps (recorded limitation; timestamp normalization of cached base layers is a follow-up, not a defect of this release's bytes).
- Exact-artifact verification on the release archive: archive ↔ build record ↔ OCI index/manifest/config ↔ loaded image id; 313 `/app` source files, 12 vendor files and six tracked pins byte-identical to the context and the source commit; both ISC notice copies root-owned and not group/world-writable; `LICENSE` / `NOTICE` byte-identical at root, `mcp/` and inside the image. The image's `/app` file set differs from the live rc29 image in exactly `server/src/events-delivery.js`, `contracts/vendor/README.md` and the added `contracts/vendor/LICENSE`.
- Fail-closed artifact privacy scan of the exact release archive: complete, 25 designated production values loaded, 0 findings, 28 exact classifications (the reviewer's scan of its own archive of the same image: identical result).
- `policyvault-mcp@1.5.0` is unchanged by this release: published on the npm registry on 2026-09-09 (registry tarball sha256 `73567fe0858b8a1c2382adb28dbc8b5381f56015b2a43532b7acf637e4dfc5b9`, byte-identical to the audited artifact, re-verified by a fresh consumer install for this release); no republish.

### Tests and evidence (automated / internal — never human acceptance)

- Automated gates on the build source `9dbc5f7` (every result with unchanged before/after source fingerprints; automated / internal evidence only): the RC29-LR-01 real-socket regression **9/9** on the source (the reviewer's run and this release's independent run) and **9/9 inside the exact image** — on the reviewer's build and again on the release tag (same digest); the eight affected webhook / notification / DNS-transport / target suites with live PostgreSQL **53/53** (44 pre-existing + 9 new; the reviewer's 44/44 + 9/9 on the same bytes; 0 skipped); exact-artifact verification of the release archive (archive ↔ build record ↔ OCI index / manifest / config ↔ loaded image id; 313 `/app` source files, 12 vendor files and six tracked pins byte-identical to the context and the source commit; both ISC notice copies root-owned and not group/world-writable; `LICENSE` / `NOTICE` byte-identical at root, `mcp/` and in the image); hosted-mode boot of the exact image with its own empty PostgreSQL database and the migrations run inside the container (schema 011, health `buildId 9dbc5f7`, readiness 200, synchronized testnet-10 node with UTXO index, capabilities, four served hashes == source, anonymous build refused 401, zero financial rows); fail-closed privacy scan of the exact release archive (complete, 25 designated production values, 0 findings, 28 exact classifications).
- Public-tree delta reproduction from ONLY this release's exported candidate tree (fake HOME, the documented sibling toolchains, lockfile `npm ci`, live PostgreSQL; reproduction subject = candidate A `ce08024a…`, whose runtime bytes are identical to this final tree — the final tree differs only in the release documents): byte delta vs the fully reproduced v1.9.1 tree = exactly the seven changed and two added files listed in `PUBLIC_RELEASE_MANIFEST.md`; every reused suite's inputs unchanged (0 differing entries under `tests/vm`, `sdk/src`, `sdk/tools`, `core`, `web`, `mobile`, `mcp`, `python`, `security`, `integrations`, `conformance`, `sdk/package{,-lock}.json`; every `contracts/*.sil` identical); private-path grep 1 (the scanner's own regex literal, classified since v1.9.1); `npm audit` 0; core-bundle anti-drift identical; tools **20/20**; image-scan classification **4/4**; scanner unit controls **13/13**; the eight affected webhook / notification / DNS-transport / target suites **53/53 with the VM binaries built from the public workspace** (a first run without the built `pv_call_encoder` failed nine notification / webhook PostgreSQL cases on that missing prerequisite — a test-environment gap of the delta script, retained as evidence — while the nine RC29-LR-01 cases passed in both runs). VM, covenant regeneration, core, web, mobile, mcp, python, security, integrations and conformance are reused from the v1.9.1 reproduction on that mechanical evidence.
- Browser: signed-out first-run smoke in real headless Chromium on the exact image at 1280 px and 375 px — PASS, 0 page errors / 0 console errors. This release changed no `web/` byte, so the signed headless-Chromium harness (212/212, 0 uncaught page errors, UX-11 self-test failing as intended) on the byte-identical rc29 bundles is reused with recorded applicability. No real-wallet or human evidence is claimed.
- Reused with recorded applicability (mechanically checked: no byte under `core/`, `web/`, `mobile/`, `mcp/`, `tests/vm`, `contracts/*.sil`, `sdk/src`, `sdk/tools` changed between the rc29 build source `f217011` and `9dbc5f7` — the whole runtime delta is `server/src/events-delivery.js`, `contracts/vendor/LICENSE`, `contracts/vendor/README.md`, `deploy/Dockerfile` and the new test): the v1.9.1 core 1343/1343, web 798/798, security 54/54, integrations 188/188, conformance 21/21, tools 20/20, mcp 58/58, mobile 98/98, python 92/92, full SDK + live PostgreSQL 1399/1399, covenant regeneration IDENTICAL ×7, VM 406/5 + delta 44/44, the signed headless-Chromium harness 212/212 on the rc29 image (identical `web/` bytes) and the 100-user capacity run (runtime deltas outside the measured mix).
- Independent read-only review (internal AI review, not an audit): the post-launch launch review of the running rc29 deployment found RC29-LR-01 and the LS-02 extension and prepared the correction; this release's session re-verified the correction and the exact artifact independently and deployed it. The affected live re-verification by the reviewer follows this release; owner mainnet acceptance follows that.

### Not in this release / limitations

- Native mobile stays DEVELOPMENT. No real-wallet (KasWare) evidence is claimed by automation; the owner validates live mainnet independently. Rooted vaults, token surfaces and the HD / KAS candidates are testnet-only; the mainnet-creatable generation stays `policyvault-0.4.1`. Installed SDK / mobile clients are unaffected by this release (no client byte changed). Edge caching of the unchanged browser bundles is unaffected (no `web/` byte changed); the permanent purge-on-deploy / content-addressed-bundle follow-up (rc29-OPS-1) remains open. x402 facilitator: PRODUCTION-READY pilot packet, NOT deployed. MCP usage telemetry OFF.

## v1.9.1 — PRODUCTION RELEASE `fullscale-rc29`: corrections from the independent post-launch live-stack review of the running rc28 deployment (webhook target policy + DNS transport, SDK transport recovery key, legacy same-effect completion ownership, image/package license + privacy-safe runtime artifacts, recovery guidance)

**WEB/AGENT PRODUCTION: LIVE at https://app.policy-vault.org — this release's build is `fullscale-rc29` (buildId `f217011`, image `sha256:ab893b13aeae661921dda11bc0782f2e0e29ead61cc232409f9532ba3cc2f847`); the served `/api/v1/health` `buildId` is authoritative for which build is active (`f217011` = this release, `890b42c` = the preceding rc28 build, live since 2026-09-08 14:05 UTC) · NATIVE MOBILE: DEVELOPMENT.**
This release supersedes the prepared-but-never-published v1.9.0 (its entry follows below for the record; no v1.9.0 tag or release exists publicly). The rc29 activation on the hosted deployment is recorded in the private release ledger; schema 011 is unchanged, so rc28 remains a schema-compatible rollback image and every write made under either build stays readable by the other. The corrections come from an independent read-only review of the LIVE rc28 stack by a separate AI reviewer (internal review — not an external audit) plus one further defect found while re-verifying those corrections. Security assurance stays INTERNAL and evidence-based; nothing here is externally audited and no external audit is part of the process.

### What changed for live users (mainnet exposure)

- **Webhook target policy (review finding LS-04, medium)**: outbound webhook destinations are judged on the eight 16-bit groups of EVERY IPv6 spelling (compressed / expanded / zero-padded / dotted-embedded), so hex or expanded IPv4-mapped forms of loopback, private, link-local, CGNAT or metadata targets can no longer bypass the private-destination policy. v4-compatible, SIIT, NAT64 (`64:ff9b::/96`, `64:ff9b:1::/48`), 6to4 (`2002::/16`), Teredo (`2001:0::/32`), ORCHID, site-local, discard-only and documentation ranges are denied conservatively; real global addresses adjacent to the documentation prefix (`2001:db81::/32` …) are no longer refused. `server/src/events-delivery.js`; RED-first `sdk/test/rc28-webhook-target.test.js`, `sdk/test/rc29-webhook-dns-transport.test.js`.
- **Webhook DNS transport (rc29; pre-existing functional defect found by the second read-only review)**: on Node ≥ 20 every webhook endpoint addressed by a DNS hostname failed to connect — the guarded lookup did not honour net's `{ all: true }` lookup contract — so hostname endpoints dead-lettered after their attempts and the advertised DNS-rebinding pin never ran (fail-safe direction: no forbidden dial). The lookup now resolves the full answer set, refuses when ANY answer is forbidden (Happy-Eyeballs never races a private address) and dials exactly the validated addresses. Production impact: the live deployment reported zero active webhook endpoints at every observation; no customer delivery was affected.
- **SDK / mobile HTTP client (LS-05, medium)**: a response-body transport failure, or an invalid JSON body after a successful HTTP status, now surfaces as `PolicyVaultNetworkError` carrying the original `Idempotency-Key` (previously a raw exception lost the key, and a retry with a fresh key could repeat a server-side mutation). No route is auto-retried; a same-key retry recovers the recorded outcome only on idempotency-supported routes — the secret-bearing identity / webhook / notification routes require inspecting the existing resource first (`sdk/src/http-client.js`, `sdk/types/http-client.d.ts`). **Installed SDK and mobile clients must upgrade to receive this — the hosted deployment alone does not update them**; `mobile/www/vendor/http-client.js` is regenerated from the same source. `sdk/test/rc28-http-body-failure.test.js`.
- **Legacy same-effect completion ownership (R8-09 extension, medium; pre-RC27F v0.7 records only — none exist on mainnet)**: direct public submission of an unattempted SIGNED sibling of a request this system already completed (one txid, two legacy finalizations) is refused BEFORE any RPC or completion write — it can no longer be marked `CHAIN_VERIFIED` or take the original's keyed receipt; already-damaged both-`CHAIN_VERIFIED` pairs preserve the existing fully validated receipt representative (the runtime never guesses which signature witness was broadcast); a genuinely settled negative sibling no longer strands a valid retry. `sdk/src/wallet-requests-v7.js`; `sdk/test/rc28-live-stack-recovery.test.js` on real df68a1f-produced fixtures (`sdk/test/fixtures/legacy-df68a1f/`). The earlier "no supported exit" statement for the crash-before-broadcast legacy shape (R8-10) is withdrawn on counter-evidence: retain ONE request and re-invoke its normal public submission (`POST /api/v1/wallet/v7/requests/:id/submit`) after the minimum observation age — complete acceptance coverage, repeated funding/output checks and exact mempool absence settle `NOT_BROADCAST`; waiting alone does not.
- **Recovery / succession explanations (UX-08 residual, low)**: shared help, owner-change summaries and confirmation warnings now agree with the actual rules — with succession enabled, funds are not "locked forever" when recovery is off; the owner-change summary uses the root's real successor and fixed delays; heartbeat / unfreeze language names the approval quorum (M of N of the installed set), never "all owners"; succession keeps a previous owner only if that key is listed again. `web/org-root-ui.js`, `core/explain/org-root-explain.js` (regenerated `web/core-bundle.js`, `mobile/www/vendor/core-bundle.js`); `web/test/org-root-setup.test.js`.

### Distribution and build integrity

- **Apache-2.0 `LICENSE` and `NOTICE` ship inside the container image (`/app/LICENSE`, `/app/NOTICE`) and inside the `policyvault-mcp` npm package** (LS-02); `mcp/tools/check-license.js` refuses to pack unless both are byte-identical to the canonical files; `deploy/Dockerfile` and the deterministic source bundle (`deploy/pipeline/bundle-source.sh`) include them. Third-party notices are unchanged; nothing is relicensed.
- **Privacy-safe runtime artifacts (LS-01)**: the pinned native tools (`silverc`, `pv_call_encoder`, `pv_vm_preflight`, `pv_tx_probe`) and the kaspa WASM SDK are rebuilt from the same pinned upstream sources (silverscript `d25bd342…`, rusty-kaspa `cfafeb4c…`, Rust 1.96.1, wasm-pack 0.15.0) with neutral source paths (`--remap-path-prefix`) and only non-allocated debug sections stripped — the previous image carried the build machine's private filesystem paths inside five compiled artifacts (a privacy defect; no secret value and no publicly served binary were involved). Six tracked pins (`deploy/vendor-pins.sha256`) now bind the native AND WASM bytes: `tools/build-private-safe-vendor.sh` (fresh output only), `tools/stage-vendor.sh` (fresh stage only, never overwrites), `tools/verify-image-vendor-pins.sh` (exactly six pins).
- **Fail-closed artifact privacy scanner** (`tools/artifact-privacy-scan.py` behind `tools/image-privacy-scan.sh` and `tools/audit-public-candidate.sh`): traverses every image layer including deleted / whiteout content, metadata, nested archives and compressed payloads; binds declared compression, tar structure, uncompressed `diff_ids` and the referenced application identity; exact path / SHA / family / count classifications; incomplete coverage FAILS. The previous scanner's clean result on the rc28 image is withdrawn for the compiled-path property. Unit controls: `tools/test_artifact_privacy_scan.py`.
- **Rollback / recovery guidance (LS-03)**: `deploy/pipeline/deploy-by-digest.sh` now prints that its image switch does not restore or migrate the database; forward repair, a maintenance boundary, a fresh protected backup and an isolated restore target replace the former image-only rollback across a schema boundary (private runbook). Self-hosting: `deploy/selfhost.sh` requires a verified privacy-safe vendor stage and refuses raw toolchain copies (`docs/selfhost-quickstart.md`).

### Tests and evidence (automated / internal — never human acceptance)

- Automated gates (every result with unchanged before/after source fingerprints; automated / internal evidence only). On the Codex-reviewed correction bytes (`543a392` … `04ec054`, whose runtime files are byte-identical to `f217011` except `server/src/events-delivery.js`): full SDK + live PostgreSQL 1,388 pass / 0 fail / 1 prerequisite skip (the HD private-encoder rebuild lacked a copied lockfile; closed by a prerequisite-complete targeted run 16/16, 0 skipped — the skip is not folded into an invented no-skip total), web 798/798, core (whole `core/`) 1343/1343, mobile 98/98, SDK delta 36/36, MCP 58/58 including the exact `policyvault-mcp@1.5.0` tarball clean-consumer proof, neutral-vendor VM 67/67 on the real TxScriptEngine with the pinned privacy-safe encoder, recovery controls 22/22, artifact-privacy-scanner controls 13/13, core-bundle and mobile-portable byte-identical. On `f217011`: webhook / notification suites 44/44 with live PostgreSQL (the new DNS-transport test 3/3 RED on the previous module, GREEN on the correction), `tools/test_artifact_privacy_scan.py` 13/13, `sdk/test/image-scan-classify.test.js` 4/4; image `fullscale-rc29` (buildId `f217011`): two byte-identical builds, six vendored native/WASM pins byte-identical, fail-closed layer/metadata/nested-payload privacy scanner PASS with every match exactly classified, extracted-rootfs audit 0 findings / 0 hashed known-value hits, hosted boot with the migrations inside the container (schema 011, readiness 200, served bytes == source, anonymous build refused 401), the image's `/app` file set differs from the Codex-verified neutral image in exactly `server/src/events-delivery.js` and from the live rc28 image in 10 changed + 2 added files (`LICENSE`, `NOTICE`); the public-tree reproduction results are recorded in the release packet.
- Browser: headless-Chromium signed harness on the EXACT `fullscale-rc29` image (TEST-ONLY dev signer, testnet-10, tmpfs data): 212/212 checks, 0 uncaught page errors, served bytes == the build tree before and after the run, buildId `f217011` — and identically 212/212 on the Codex-verified neutral image the release was re-verified from; the UX-11 injected-page-error self-test fails as intended on both (64/65, the only failure is the injected uncaught error); the rooted-vault owner-operation lifecycles ran with independent kaspad checks within the recorded finite testnet-10 transaction bound. Signed-out first-run smoke at 1280 px and 375 px on the exact image: 7/7, 0 page / console errors. No real-wallet or human evidence is claimed.
- Independent read-only reviews (internal AI reviews, not audits): the post-launch live-stack review of the running rc28 deployment (findings LS-01…LS-05, the R8-09 extension and the UX-08 residual; R8-10 withdrawn) and a narrow read-only review of the rc29 corrections (which found the DNS-transport defect). Every finding was corrected RED-first with a permanent regression.

### Not in this release / limitations

- Native mobile stays DEVELOPMENT. No real-wallet (KasWare) evidence is claimed by automation; the owner validates live mainnet independently. Rooted vaults, token surfaces and the HD / KAS candidates are testnet-only; the mainnet-creatable generation stays `policyvault-0.4.1`. `policyvault-mcp@1.5.0` (source in `mcp/`, with the corrected client and the license/notice files) — its npm publication status is stated in the README. x402 facilitator: PRODUCTION-READY pilot packet, NOT deployed. MCP usage telemetry OFF. The KIP-9 storage-mass upstream write-up is prepared but not posted.

## v1.9.0 — PRODUCTION RELEASE `fullscale-rc28`: organizational M-of-N owner root (v0.7, byte-frozen) with browser initiation of rooted-vault owner operations, the RC27 durable-completion model, hosted tenancy for every route family, generation gate, MCP 1.5.0 (org-root tools)

> Prepared 2026-09-08 for the rc28 deployment and staged locally; never published as a tag or release — superseded before publication by v1.9.1 above (the rc28 build it describes was live from 2026-09-08 14:05 UTC until the rc29 activation).
**WEB/AGENT PRODUCTION: LIVE (`fullscale-rc28`, buildId `890b42c`, image `sha256:fe90f1153d0bef29b81fb4cdf39337df3b3c5e465efa57e6ee07a88f664bdee8`) · NATIVE MOBILE: DEVELOPMENT.**
This release is the FIRST production deployment since `fullscale-rc8` and publishes, in one step, the source of the three prepared-but-never-published candidates v1.6.0, v1.7.0 and v1.8.0 (their entries follow below, unchanged) plus everything since. The hosted deployment at https://app.policy-vault.org now serves THIS source (schema 011; the pre-migration backup and the compatible rollback path are recorded in the private ledger). Security assurance for this release is INTERNAL only — independent internal AI falsification reviews of the exact candidates (rounds 3–8), hostile/adversarial matrices, RED-first reproductions, production-byte and live testnet-10 evidence, and the owner's own live mainnet validation after deployment; nothing here is externally audited and no external audit is part of the process.

### Mainnet exposure — what changed for live users

- **rc8 security findings closed on production** (`docs/postlaunch/rc11-internal-review-remediation.md`, `mainnet-exposure-audit-rc11.md`): hosted BUILD AUTHORITY (every hosted build/create/simulate requires the signed-in wallet or its machine credential; the genesis signer must be the caller; a bounded compiled-artifact cache replaces unbounded temporary storage), own-property version/action lookups with explicit `UNKNOWN_VERSION` refusals, and the **mainnet-creatable generation allowlist = `policyvault-0.4.1` only** (`GENERATION_NOT_MAINNET_AUTHORIZED` for everything else — v0.4, v0.5, v0.6, v0.7 and the HD/KAS candidates are testnet-only and fail closed on mainnet; existing v0.4 vaults stay readable and reconcilable). Hosted tenancy (non-oracle 404 / 403) now covers `/org-roots`, `/wallet/v7`, `/wallet/v5|v6` — every route family, with foreign-tenant probes per family in the suites (`docs/postlaunch/authorization-boundary-inventory.md`).
- **Web client**: the flagship UX pass (guided vault/root setups, canonical amount parsing, truthful pending states, network-identity fail-closed banner), UX-01…UX-14 and R6/R7 closures (pre-sign binding of every consensus field the wallet signs, fee-payer finalization authority derived from the fee input, no hidden relative locks, full agent-rule review), and — new in this release — **browser initiation of rooted-vault owner operations** (change agent rules with the full recipient sets, top up the fee reserve, pause, unpause, emergency-pause under the root's freeze quorum, close & recover to the pinned recovery key) plus reservation/withdrawal guidance (an unsigned request reserves the root and guards its vault; only an unsigned, never-attempted request can be withdrawn; a finalized request resumes its original submission; an attempted one goes through outcome recovery). Rooted-vault operations are TESTNET-ONLY today (v0.7 is not mainnet-authorized); on mainnet the web client offers none of them.
- **Durable completion model (RC27, F-1…F-9)**: a later incomplete delegate completes before earlier root history is judged; a failed inspection never downgrades completed history; a proven negative outcome settles only its own claims (including a narrow removed-initial-anchor rule for a first rejection proven through repeated all-inputs-unspent, exact-mempool-miss and absent-output observations); legacy pointerless records recover without pinning an old root; one process-local queue serializes finalize/slot/signature/submit/reject; typed store keys. Live testnet-10 evidence: six-transaction deposit/delegate recovery demonstration and the recovered original browser request (private evidence, summarized in the packet).

### Covenant

- **`contracts/PolicyVault.v0.7-root.sil` + `PolicyVault.v0.7-payment.sil` — organizational M-of-N owner root and its rooted payment profile, COVENANT-BYTE-FROZEN 2026-09-03** (sha256 `69417514…` / `09cdbb6c…`; generators `tools/gen_v7_root.js` / `tools/gen_v7_payment.js`; freeze record `docs/postlaunch/v0.7-covenant-byte-freeze.md`; adversarial review FREEZE-NOT-FALSIFIED). Rules D1/D2/D6–D9; every counted owner signature SIGHASH_ALL-gated in-covenant; FREEZE (K) is the only lighter quorum and can only freeze; owner recovery and succession land frozen after consensus-enforced relative-age delays; ONE vault operation per root transition. **Status: VM-VERIFIED · SDK/PRODUCTION-BYTE-VERIFIED · TESTNET-VERIFIED (live testnet-10 lifecycle, consensus sequence-lock proof, negatives) · NOT mainnet-authorized.**
- `PolicyVault.v0.7-kas.sil` (rooted KAS profile) and `PolicyVault.v0.7-payment-hd.sil` (hierarchical delegation) — additive CANDIDATES, TESTNET-VERIFIED, NOT frozen, NOT mainnet (`docs/postlaunch/v0.7-kas-profile-readiness.md`, `v0.7-hd-readiness.md`, `hierarchical-delegation-design*.md`).
- Shared-core/SDK pre-sign parity with the covenants is maintained as a permanent invariant (`docs/postlaunch/vm-presign-parity-and-enforcement-matrix.md`, `sdk/test/vm-presign-parity.test.js`).

### Application surface

- v0.7 organizational roots: server routes (`/org-roots`, `/wallet/v7`), SDK request lifecycle (genesis, root actions with at most one vault operation, slot signing through the Universal Signer Interface, finalize by the fee payer, submit, reconcile with dependency-first recovery), web (guided root setup with plain-language governance, exact-policy review, own-slot signing, out-of-band approval import, request lifecycle, the rooted-vault owner-operation panels), MCP tools (`policyvault-mcp` 1.5.0: org-root schema fragments and tools; the adapter now identifies itself with an `x-policyvault-mcp-client` header that the server records only when telemetry is explicitly enabled), execution attestations for v0.7.
- Token surfaces for v0.5/v0.6 (version-aware token vault UI; testnet-only) and the HD candidate surface.

### Tests and evidence (automated / internal — never human acceptance)

- `Automated gates on the build source `890b42c` (SDK-only correction of the round-8-reviewed `e7c0cb6`; every gate with unchanged before/after source fingerprints): full SDK + live PostgreSQL 1379/1379 (0 fail / 0 cancelled / 0 skipped) on `890b42c`; core (whole `core/`) 1343/1343, web 796/796, mcp 56/56 (1.5.0 bytes), core-bundle and mobile-portable byte-identical, mobile 97/97 and VM 589/0 — reused with recorded applicability (no change under `core/`, `web/`, `mcp/`, `server/`, `mobile/`, `tests/vm`, `contracts/`, generators since their runs); image `fullscale-rc28`: two byte-identical builds, vendored pins 4/4, per-layer privacy scan CLEAN, rootfs audit 0 findings, hosted boot + migrations inside the container, mainnet-configured allowlist = `policyvault-0.4.1` only, unauthenticated builds refused; the image's file set differs from the reviewed rc27 image in exactly the two corrected SDK files.`
- Browser: headless-Chromium signed harness on the exact image (dev signer, testnet-10; `212/212 checks, 0 uncaught page errors, served bytes == the build tree, on the exact rc28 image; UX-11 injected-error self-test fails as intended`), including the rooted-vault owner-operation lifecycles with independent kaspad checks; UX-11 injected-page-error self-test.
- Round-8 independent internal falsification review of the exact commit + image (`fullscale-rc27`, `e7c0cb6`): BLOCKED on two legacy-data findings (no funds impact; pre-RC27F v0.7 records, none in production) — corrected RED-first on the reviewer's df68a1f-produced snapshots (`sdk/test/legacy-same-txid-r8.test.js`), the reviewer's re-check found the adjacent shape which the lead closed, the second re-check PASSED, and the corrected source was rebuilt as `fullscale-rc28`: `original review BLOCKED (R8-01 LOW, R8-02 MEDIUM, legacy data only, no funds impact) → corrected RED-first → re-check found R8-09 (MEDIUM, legacy) → corrected → second re-check POLICYVAULT-RC27-R8-RECHECK2-PASS; residual R8-10 LOW pre-existing recorded`.
- Migration/rollback rehearsal (009 → 011 on disposable representative data incl. an incomplete request; rc8 fails closed on 011; restore + rc8 path proven) and a 100-regular-user capacity run on an isolated production-shaped container (`100 authenticated users, 60 min sustained realistic mix + burst on the production compose limits: 36,435 requests, read p95 19.8 ms / p99 1,051 ms, build p95 1,638 ms, 0 × 5xx/timeouts/transport errors, CPU avg 2.7 %, memory max 252 MiB, PG connections max 11 — every declared criterion met`).

### Not in this release / limitations

- Native mobile stays DEVELOPMENT (unit + emulator + portable parity only). No real-wallet (KasWare) account/network-change evidence is claimed by the automated runs; the owner validates live mainnet independently. Rooted vaults, token surfaces and the HD/KAS candidates are testnet-only. x402 facilitator: PRODUCTION-READY pilot packet, NOT deployed. MCP usage telemetry: implemented, OFF, not enabled. The KIP-9 storage-mass upstream write-up is prepared but not posted.

## v1.7.0 — FLAGSHIP WAVE 1: v0.6 atomic-composability covenant (byte-frozen), Universal Signer Interface v2, execution attestations, MCP usage telemetry (OFF), release-signing tooling, deployment pipeline, self-host + UX correctives

**WEB/AGENT PRODUCTION: LIVE (`fullscale-rc8`, buildId `1c02162`) · NATIVE
MOBILE: DEVELOPMENT · THIS RELEASE IS SOURCE ONLY — NOT DEPLOYED.**

This release changes **no production runtime**. The live hosted deployment
still serves `fullscale-rc8` (buildId `1c02162`); the `server/`, `web/` and
`mobile/www/` sources in this tree are a **prepared successor that has not
been built, deployed, or human-accepted**. Nothing here is externally
reviewed or audited.

### Covenant

- **`contracts/PolicyVault.v0.6.sil` — NEW covenant generation v0.6
  "ATOMIC COMPOSABILITY", COVENANT-BYTE-FROZEN 2026-09-03** (owner
  conditional authorization satisfied by exact mechanical re-verification
  plus an independent adversarial review that returned
  FREEZE-NOT-FALSIFIED). sha256
  `c7c5f22c54a55d933ec8440a28bc2c628b9b99262541d50dbe9ffbdd16ba025c`,
  deterministic generator `tools/gen_v6.js`. One owner-approved
  constant-product pool family; `tokenAgentSpend`, `tokenAtomicSell`,
  `tokenAtomicBuy`, `ownerControl`, `ownerRecover`; swaps pinned to
  exactly four inputs (no external fuel input is admissible); SIGHASH_ALL
  gate; 24,920-byte redeem; 5 static sig-ops.
  **Status: VM-VERIFIED (`tests/vm/tests/v6_production.rs`, real
  TxScriptEngine) · SDK/PRODUCTION-BYTE-VERIFIED
  (`tests/vm/tests/v6_sdk_integration.rs`, 36 vectors) · TESTNET-VERIFIED
  (live testnet-10 SELL + BUY lifecycle).**
  **Exact limitations, stated up front: FIXTURE VENUE ONLY** — the only
  swap counterparty proven is the repository's own conformance pool
  fixture (`contracts/experiments/V6PoolFixture.sil`, which is a test
  fixture, **not** a PolicyVault product and not an endorsement of any
  venue); **no real DEX venue is supported, there is no mainnet swap, and
  there is no server/web/mobile/MCP surface for v0.6**; `deadlineDaa` is a
  **pre-sign boundary, not a consensus expiry**; swaps are **not
  economically viable below roughly 10 KAS** (flat cost ≈ 0.0816 KAS —
  `docs/postlaunch/v0.6-economic-viability.md`); period budgets in
  v0.3–v0.6 rely on the shared-core `periodLengthDaa > 0` invariant,
  now pinned by
  `core/model/test/period-length-positive-invariant.test.js`.
  Freeze record `docs/postlaunch/v0.6-covenant-byte-freeze.md`; pin
  `sdk/test/covenant-freeze-v6.test.js`. **PolicyVault is not a DEX and
  will not become one** — it authorizes, verifies intent deterministically
  and enforces policy; liquidity and execution stay external
  (`docs/postlaunch/roadmap-dex-adapter-and-protocol-evolution.md`).
- Unchanged bytes: v0.5 `c693aeff…`, v0.4.1, v0.4, v0.3, v0.2,
  v0.1.beta. No frozen covenant was regenerated or edited.
- New shared-core and SDK layers for v0.6: `core/model/{vault-state,
  agent-merkle,swap-policy,vault-transitions,compute-budget}-v6.js`,
  `core/model/storage-mass.js`, `core/intent/{token-manifest,
  swap-manifest}-v6.js` and the fail-closed `core/intent/router.js`;
  `sdk/src/{contract-compiler,vault-builders,swap-pool-fixture,
  vault-state,vault-transitions,agent-merkle,swap-policy,
  compute-budget}-v6.js`. Leaf fixtures are pinned byte-for-byte to the
  Rust leaf functions the real engine accepts
  (`tests/vm/tests/v6_fixture_capture.rs`).

### Universal Signer Interface v2 (additive; nothing migrated to it yet)

- **`core/signer/v2/` — `policyvault-signer/2`: IMPLEMENTED ·
  UNIT-TESTED · ADVERSARIAL-TESTED (hostile suite 48/48).** Explicit
  negotiation of sighash type, PSKT support, transaction format,
  user-presence, transport, timeout and cancellation; response envelopes
  bound to the request; a replay guard; and a probe-versus-declared
  capability check that fails closed when a signer's real behaviour
  contradicts what it advertised. Adapters for KasWare, the reference CLI
  signer (real cryptography via kaspa-wasm) and air-gapped transport.
- **Honest limits: no production consumer has been migrated to v2** — v1
  (`policyvault-signer/1`) remains what ships in the app, so v2 is
  additive and inert. **No live independent second wallet has been
  exercised**, and the PSKT / ECDSA wire contracts are deliberately left
  unfrozen pending source-backed evidence. The v2 air-gap adapter is not
  yet wired into the mobile platform layer.
- Fixed: a mobile air-gap envelope serialization defect found by the v2
  conformance suite (`mobile/www/js/portable/airgap.js`).

### Execution attestations (exportable, machine-verifiable outcome records)

- **`core/attest/` — `policyvault-execution-attestation/1`: IMPLEMENTED ·
  UNIT-TESTED · ADVERSARIAL-UNIT-TESTED · API-TESTED.** A canonical,
  hash-addressed record of what was authorized, what was signed and what
  the chain actually did, with the outcome ladder enforced as a
  contiguous prefix and refusal attribution kept narrow. 103 tests
  including 32 tamper classes (naive and re-hashed) and a language rule
  that forbids the words *compliant*, *certified* and *regulator*.
- **`tools/attestation-verify.js`** — an INDEPENDENT verifier: structure,
  expectation binding, and an opt-in **pure** chain re-check that reports
  `CHAIN_CONFIRMED` · `UNCONFIRMED` · `UNAVAILABLE` · `CONTRADICTED`. The
  chain re-check path is TESTNET-VERIFIED against the v0.6 live evidence
  shipped in `docs/testnet-v6-atomic-evidence.json` (that file is also the
  positive test vector for the attestation suite).
- **Server:** `GET /api/v1/attestations/requests/:id` and
  `GET /api/v1/attestations/export` (json / ndjson) behind a NEW
  deny-by-default scope `read:attestations`; SDK client methods declared
  in `sdk/types/http-client.d.ts`.
- **Honest limits:** the signature slot is designed but **has no key** —
  deliberately, because PolicyVault holds no server-side key anywhere near
  funds; the accepting-block DAA score is not persisted in `receipt/v1`,
  so exports state no depth; there is no hosted `VERIFIED_OUTCOME`
  producer yet; exports are v0.4/v0.4.1 KAS-only (token/swap mapping is
  additive future work); no MCP tool and not in the browser core bundle.

### MCP usage telemetry — OFF BY DEFAULT, NOT ENABLED ANYWHERE

- `server/src/mcp-telemetry.js` + `server/migrations/010_mcp_telemetry.sql`
  (`policyvault-mcp-telemetry-event/v1`, create-only category),
  aggregates behind `read:metrics`, client header in `mcp/src/http.js`.
  **Recording defaults OFF** (`POLICYVAULT_MCP_TELEMETRY` unset or
  `"off"`) and is **not enabled in any deployment**; turning it on is an
  operator decision. Includes a privacy-negative byte scan proving no
  vault identifiers, amounts, addresses, credentials or free text are
  recorded, retention pruning and a hard cap. Spec:
  `docs/postlaunch/mcp-usage-telemetry-todo.md`.

### Release signing and succession governance (tooling only — no key exists)

- `tools/release-manifest.js` / `release-sign.js` / `release-verify.js`
  build, sign and verify a `policyvault-release-manifest/1` artifact
  identity (tree hash, covenant hashes, lockfile hashes, optional image
  and archive digests) using OpenSSH `ssh-keygen -Y` signatures against
  the threshold policy in `release-signers.json`.
- **`release-signers.json` ships with ONE signer entry whose public key is
  the literal placeholder `OWNER-TO-FILL`, threshold 1.**
  `tools/release-verify.js` **refuses to count any signature** against an
  unfilled entry. The structure is multi-signer *capable*; it is **not**
  a multi-signer policy today, and no second maintainer exists — the
  onboarding checklist in `docs/postlaunch/release-trust-model.md`
  deliberately names no fabricated person. **No release has been signed.**
- Webhook at-rest key rotation: a written procedure
  (`docs/postlaunch/webhook-secret-rotation-procedure.md`, **NOT
  executed**), a `POLICYVAULT_WEBHOOK_SECRET_KEY_PREVIOUS` overlap
  fallback, the `tools/reseal-webhook-secrets.js` resealing tool, and a
  Python HMAC verifier (`python/policyvault_client/webhooks.py`).

### Deployment pipeline (local proof only; production use is owner-gated)

- **`deploy/pipeline/`: DESIGNED · IMPLEMENTED · INTEGRATION-VERIFIED
  LOCALLY (non-production).** A reproducible OCI build
  (`SOURCE_DATE_EPOCH` + timestamp rewrite, provenance/SBOM off;
  bit-reproducible export proven twice; digest-pinned base byte-identical),
  a content-addressed layer delta (**1,382,400 B for a one-file deploy
  versus a 207,922,176 B full image — about 150×**), a signed source
  bundle with a remote-builder fallback, deploy-by-digest with a rollback
  ledger, and verify-before-activate (privacy scan plus a private
  health/readiness probe). Cost: zero. `sdk/test/deploy-pipeline.test.js`.
  **Never run against production**; the first production use is an owner
  decision. Residual: the apt layer is content-equivalent, not
  bit-identical. Rationale and threat model:
  `docs/postlaunch/deployment-pipeline-independence.md`.

### Self-hosting correctives (from an outsider clean-environment re-test)

- **Three genuine first-run defects FIXED:** `tools/stage-vendor.sh` failed
  under `pipefail` when the vendor dist directory was missing (this broke
  *every* first run); undocumented prerequisites now produce actionable
  fail-closed messages with the exact commands; `deploy/selfhost.sh` used a
  constant build-id fallback that broke `upgrade` on git-less checkouts and
  left rollback serving the wrong buildId.
- **New `tools/selfhost-acceptance.sh`** — a 22-step self-host acceptance
  run: real Schnorr authentication, backup/restore into an isolated
  database with row-count and hash verification, upgrade/rollback identity,
  log redaction, host-reboot simulation and a hidden-dependency scan.
  Record: `docs/postlaunch/selfhost-flagship-retest.md`. Known gap:
  wallet authentication end-to-end is NOT tested headlessly (it needs a
  browser and a wallet extension).

### Web and mobile UX pass — UNIT/jsdom-BROWSER tested, NOT human-accepted

- 13 correctives to real adoption failures, not aesthetics: ARIA live
  regions on all six status surfaces; a **closed** 35-code refusal
  explanation table (`web/refusal-explain.js`, no overrides); an outcome
  table driven by the SDK request state where **PENDING is never
  presented as success**; recipient-allowlist disclosure with a real spend
  form (replacing a `window.prompt`); a truthful "one on-chain owner"
  statement; node-problem versus wallet-problem messaging; 375 px
  responsive rules; a visible focus ring; reduced-motion anti-drift; a
  recovery warning; clearer agent naming. Mobile: banner announcement,
  focus handling and 44 px touch targets.
- **No person has operated these screens in a browser, on a device, or
  against production. Human acceptance is not claimed.**

### Shared deterministic core (hybrid local-first)

- **PRODUCTION CODE BUG FIXED:** the browser's KAS→sompi conversion on the
  spend path used floating point — it accepted `0x10` and `1e3`, rounded a
  ninth decimal, turned `0.000000001` into `0`, and lost precision on large
  values. It now goes through the canonical `core/model/amounts` parser via
  the browser core bundle, with 15 recorded defects pinned as refusals and
  a golden parity fixture (`web/test/client-amounts-parity.test.js`).
- `core/intent/token-manifest-v6.js` + `core/intent/router.js` — a
  `policyvault-controller-intent-manifest/1` verifier for v0.6
  spend/owner/recover/deposit with a **fail-closed** version router
  (unknown versions are never routed to a default). Two false-refusal bugs
  in the new verifier were found by real-build tests and fixed.
- A v0.5/v0.6 cross-runtime equivalence battery (44 cases over the 32-file
  closure), and the SDK browser harnesses now load the **real** shipped
  core bundle exactly as `web/index.html` does.

### Not in this release

- The organizational M-of-N owner root (**v0.7**) is DESIGNED and being
  implemented on a separate lane; **no v0.7 covenant, generator or test is
  in this tree**, and none is frozen.
- Hierarchical delegation is DESIGNED only (experimental probe evidence);
  no production covenant, no SDK, no manifest.
- The DEX / swap adapter framework has **no implementation**; its design
  candidate is published as `docs/postlaunch/dex-adapter-design-spec.md`
  and remains gated on an owner design-freeze decision.
- Internal program, planning and acceptance records (readiness matrices,
  wave logs, deployment packets, live acceptance transcripts) are not
  published — see `PUBLIC_RELEASE_MANIFEST.md` for the exact exclusion
  set.
- **No external professional security review or audit has occurred.**

## v1.6.0 — x402 FACILITATOR (Kaspa `exact`/upfront scheme; read-only chain verification / settlement attestation)

**WEB/AGENT PRODUCTION: LIVE (fullscale-rc8, buildId `1c02162`, unchanged by this release) · NATIVE MOBILE: DEVELOPMENT · x402 FACILITATOR: IMPLEMENTED + TESTNET-VERIFIED, not a hosted production service.**

- **New: `integrations/x402-facilitator/`** — a separately deployed,
  unprivileged, READ-ONLY chain verification / settlement attestation
  service for the proposed Kaspa x402 scheme `exact` +
  `extra.paymentFlow: "upfront"` (`pv-x402-kaspa-exact-upfront/1`). The
  payer settles first with an ordinary Kaspa transaction; the facilitator
  checks the exact outpoint against a synced UTXO-indexed node and, on
  `/settle`, records ONE durable single-use claim with the evidence. It
  holds no keys, signs nothing, broadcasts nothing, escrows nothing,
  never calls a PolicyVault API, never emits a 402, and never charges.
  Design frozen by the owner (`docs/postlaunch/x402-facilitator-design-freeze.md`,
  spec revision 3); network identifiers `kaspa:mainnet` /
  `kaspa:testnet-10` are PolicyVault's PROVISIONAL CAIP-2-syntax
  identifiers (no upstream registration is claimed); resource-server
  authentication = facilitator-issued API key over HTTPS with a dedicated
  principal model (mTLS optional future hardening); settlement policy
  `pv-x402-settlement/1` (depth 100 default, hard floor 20, window
  ≤ 36,000 DAA); token payments use the FROZEN v0.5 semantics through
  `core/assets` (both bindings + conservation). PostgreSQL claim store
  (race-proven) and a single-instance JSON store; `/readyz` + `/healthz`;
  launcher + admin CLI; `deploy/x402f/` image, compose overlay and env
  template for self-hosting.
- **New: `sdk/src/tx-identity.js`** — a read-only SDK leaf that
  recomputes a carried transaction's CONSENSUS id through the engine
  (the wasm `deserializeFromSafeJSON` echoes the embedded id and the wasm
  `Transaction` caches its id at construction; the Kaspa txid commits to
  output covenant bindings) — pinned against the Rust `pv_tx_probe`
  hasher (`sdk/test/tx-identity.test.js`).
- `sdk/src/chain.js`: additive `isCoinbase` field on normalized UTXO
  entries (null when the node omits it; consumers fail closed on null).
- `integrations/test/dependency-direction.test.js`: rule 5 — the
  facilitator may import only `core/**`, `integrations/lib/**`,
  `sdk/src/chain.js`, `sdk/src/tx-identity.js`.
- `tools/image-privacy-scan.sh`: SIGPIPE-safe sanity check +
  `PV_SCAN_SANITY_PATH` for non-app images.
- Docs: facilitator spec (frozen), design-freeze record, program record,
  conformance spec §12, adapter spec §1.6 cross-reference, README status
  + layout, SECURITY claim block (CLAIM → ENFORCEMENT → TEST → EVIDENCE).
- Evidence (this tree, all suites green): freeze pin 6 · unit 14 ·
  hostile matrix 34 · service/auth 12 (+ readiness 1) · PostgreSQL claims
  6 · txid production-byte 3 · dependency direction 8; live testnet-10
  proof (real KAS + real frozen-v0.5 token payments; evidence retained
  privately). Honest ecosystem statement: no upstream Kaspa x402 scheme
  exists; the facilitator is not "x402-compatible" beyond the proposed
  scheme. No external security review has occurred.
- Unchanged: covenant bytes (v0.5 `c693aeff…`, v0.4.1, v0.4, v0.3),
  the production web/API surface, MCP 1.4.2, mobile.

## v1.5.0 — v0.5 token-controller covenant (byte-frozen), least-privilege discovery + console correctives (fullscale-rc8), MCP 1.4.2, illustrated onboarding

The corrective + v0.5 successor to v1.4.0. Production runtime successor
**`fullscale-rc8`** (buildId **`1c02162`**, built from the v1.3.0/v1.4.0
production source `6c3177f` + ONLY the six-file server/web corrective
delta) — **LIVE** — deployed and accepted on automated evidence on 2026-09-02 (production acceptance 46/46 through the public edge + successor-specific live checks; the owner validates the console independently; no human acceptance test is claimed). The v0.5 covenant, SDK, and core layers ship as
SOURCE (frozen, VM- and testnet-verified) — no v0.5 server/API/web surface
exists yet and no v0.5 vault exists on mainnet. Schema (009), webhooks,
custody/signing architecture, and the frozen v0.4 / v0.4.1 covenant bytes
are unchanged; the covenant/VM toolchain binaries in the production image
are byte-identical to v1.3.0's.

### Added — v0.5 TOKEN CONTROLLER covenant (COVENANT-BYTE-FROZEN 2026-09-02)
- `contracts/PolicyVault.v0.5.sil` — sha256
  `c693aeffb59286d21d44452bde0943d78840b66cf480b629624b7747b4197dd9`,
  regenerated byte-identically by `tools/gen_v5.js`; one instance per
  (vault, accepted asset descriptor, accepted template); owns a KCC20 token
  position and authorizes delegated TOKEN-denominated agent spends under
  per-agent caps, period budgets and recipient allowlists, with its own KAS
  held exclusively as a covenant-accounted fee reserve (two-domain
  accounting); owner pause / unpause / recover. Carriage:
  TRANSACTION-DERIVED VERIFIED TEMPLATE CARRIAGE (dual binding: covenant-ID
  + hash-verified template + pinned geometry). Spec
  `docs/covenant-spec-v0.5.md`; design freeze, independent internal
  reread, readiness synthesis and the freeze record under
  `docs/postlaunch/v0.5-*.md`. `sdk/test/covenant-freeze-v5.test.js` pins
  the frozen identities (covenant, generator, vendored KCC20 program).
- Vendored KCC20 reference program `contracts/vendor/kcc20-reference.sil`
  (byte-exact upstream; sha256 `2b7d59b0…`), canonical token parsing
  (`core/assets/`: kcc20 state codec, redeem split/reconstruct, static
  sig-op scan, BLAKE2b, `policyvault-asset-descriptor/1` validation and
  template corroboration), v0.5 model/intent/explain modules (`core/model/*-v5.js`,
  `core/intent/token-manifest-v5.js`, `core/explain/token-explain.js`),
  SDK builders/manifests (`sdk/src/*-v5.js`, `token-program-kcc20.js`),
  and the browser/mobile core bundles rebuilt with the assets layer
  (byte-identical to each other; anti-drift pinned).
- Evidence labels (exact): VM-VERIFIED on the real engine with production
  encoder bytes (`tests/vm/tests/v5_production.rs` 37-case hostile spend
  matrix, `v5_sdk_integration.rs` production-byte vectors);
  TESTNET-VERIFIED — one full live testnet-10 lifecycle (issuance →
  descriptor → controller genesis → deposit → agent spend → two
  consensus-rejected negative-validation transactions constructed
  independently of the application → pause → unpause → recovery), every
  outpoint chain-verified through the node's UTXO index; the txids are
  recorded in `docs/postlaunch/v0.5-covenant-byte-freeze.md`. NOT
  production, NOT externally reviewed.

### Fixed — least-privilege capability discovery (server + MCP 1.4.2)
- `GET /api/v1/capabilities` now names the PRESENTED machine credential's
  own principal (identity id + granted scopes) and advertises
  `features.principalScopedDiscovery`; anonymous / browser callers receive
  the byte-identical public document; an invalid presented credential is
  refused (401 `MACHINE_TOKEN_INVALID`) — never downgraded to anonymous.
  Server-side scope enforcement was never affected (a hidden tool called by
  exact name is still refused 403 `SCOPE_FORBIDDEN`); this closes a
  DISCOVERY gap, not an authorization bypass.
- `policyvault-mcp@1.4.2`: presents its credential at discovery and
  advertises ONLY the tools whose scopes are granted (a `read:network`-only
  credential lists exactly `policyvault_capabilities` and
  `policyvault_network_status`); malformed discovery and refused
  credentials fail closed at startup with the server's own code; legacy
  servers fall back to the build-level catalog with a stderr notice. Exact
  tarball identity: sha256 `2f9ff1b85d9097128a7936f503d15418e5b7157e5730e599dfed2fcc9519768e`,
  npm shasum `e33bcc6549c662a0d1b098f68efb6fdd4d5d063f`. Proof tooling:
  `mcp/tools/candidate-proof.js` (exact-tarball clean consumer + real
  server), `mcp/tools/remote-proof.sh` (public artifact clean-room proof).
- `policyvault-mcp@1.4.1` packaging correction is carried in source: the
  package resolves its shared core through a sha256-pinned verbatim copy
  (`mcp/core/`, `mcp/tools/sync-core.js`, `mcp/test/core-sync.test.js`,
  `package-closure`/`package-consumer` gates) — 1.4.0's standalone
  topology was broken and is deprecated on npm.

### Fixed — production web console (owner-live findings 2026-09-02)
- No `/wallet/dev-accounts` probe on production: the mock signer is
  offered only when `/health` advertises `devSigner:true` (testnet +
  `POLICYVAULT_DEV_SIGNER=1`, never mainnet; shared server predicate).
- WALLET CONNECTED ≠ SESSION AUTHENTICATED: a connected wallet with a
  signed-out hosted session issues zero privileged reads (quiet sign-in
  states on every view); an auth refusal while believed authenticated
  triggers exactly one server-truth re-read (`revalidateAuth`) and no retry
  loop; 401 stays a genuine refusal.
- Wallet public-key normalization diagnostics are opt-in
  (`localStorage pv.debug=1`); public material only — seeds, keys, bearers
  and session secrets were never logged and still are not.

### Added — illustrated onboarding (presentation only)
- The six-step first-run walkthrough is now illustrated (system flow,
  create/control, rules, bounded delegation, accepted vs refused, key
  distinction) with theme-token colours, reduced-motion-safe animation,
  keyboard-reachable replay and accessible labelling. Semantics unchanged:
  skippable everywhere, "don't show again", Help replay, verbatim authority
  statement, no key request, never gates any action.

### Added — roadmap
- `docs/postlaunch/roadmap-dex-adapter-and-protocol-evolution.md`: the
  post-v0.5 sequence (x402 FACILITATOR → DEX / Swap Adapter Framework →
  …), the product boundary (PolicyVault MUST NOT become a DEX; external
  liquidity/execution; external signers; fail-closed adapter verification
  surface) and the permanent Kaspa Protocol Evolution Compatibility program
  (vProgs/DAGKNIGHT foresight, consensus-upgrade freeze-reopen rule,
  additive migration invariant).

### Status labels carried (unchanged discipline)
- WEB/AGENT PRODUCTION: LIVE. NATIVE MOBILE: DEVELOPMENT (not
  production-capable; APK identities carry unchanged from v1.3.0 — `mobile/`
  runtime is unchanged apart from the vendored core bundle used by the
  portable verification layer). No external professional security audit has
  occurred; nothing in this repository claims otherwise.

## v1.4.0 — Distribution: MCP registry packaging, agent examples, one-command self-hosting

A source/distribution release: **no runtime change and no production
deployment** — every directory the production container copies
(`core/ sdk/ server/ web/ contracts/`) is byte-identical to v1.3.0
(live buildId `6c3177f` unchanged). The adoption-first program's first
three deliverables ship here.

### Added — MCP distribution (official registry + npm)
- `mcp/package.json` is npm-publishable (`policyvault-mcp`; zero runtime
  dependencies) with the official MCP registry ownership binding
  (`mcpName: io.github.zapsoblige-hash/policyvault`), and
  `mcp/server.json` carries the registry metadata (stdio transport,
  environment variables with secret marking, authority statement).
- `docs/postlaunch/mcp-distribution.md`: install, transport,
  configuration, auth setup, read-only vs mutation semantics, network
  guidance, example prompts, version compatibility, and fail-closed
  behavior. The MCP layer remains a thin distribution surface over
  existing capability — it implements no financial semantics, holds no
  keys, and gains no authority from being packaged.

### Added — agent-framework examples
- `examples/agents/`: thin wiring for the OpenAI Agents SDK, LangChain,
  and CrewAI that attaches an existing agent to PolicyVault through the
  MCP server only. No adapter contains financial logic; the README
  carries the authority statement, minimal-scope credential guidance,
  simulate-before-create discipline, and untrusted-data rules.

### Added — one-command self-hosting
- `deploy/selfhost.sh` (init / up / check / acceptance / upgrade /
  rollback / backup / restore / down / destroy) with
  `deploy/docker-compose.selfhost.yml` and `docs/selfhost-quickstart.md`.
  Equal-security by construction: testnet-10 default; mainnet requires
  the same dual unlock as hosted production, an https origin, and a
  TLS-capable PostgreSQL (the app refuses no-TLS postgres on mainnet);
  generated config is mode-600 with a random database secret; dev/test
  flags are never written; the self-check verifies release identity,
  network equality, node sync + utxoindex, posture, and the structural
  absence of wallet secrets.

### Added — research transparency
- `docs/postlaunch/v0.5-token-d1-spike.md`: the v0.5 token-support D1
  research spike (KCC-0001/0002/0020 and current node-source findings),
  with every claim labeled SOURCE-VERIFIED / SPEC-VERIFIED / DESIGN
  TARGET / OPEN — nothing frozen, nothing VM-proven yet, and the
  required dual binding (controller authorization + hash-verified
  template pinning) recorded as a non-negotiable design constraint.

### Notes
- No schema, webhook, auth, or consensus change of any kind. No
  external security audit has occurred; nothing here claims one.

## v1.3.0 — Bearer wallet-sessions + native mobile production transport

The native-mobile/bearer successor to v1.2.0 (production buildId
`6c3177f`, built on the v1.2.0 production source `5b90e74`). The server
delta is bearer-session code only (additive, config-gated); the client
delta is the mobile app: the full validated Capacitor Android project
with an explicit native HTTP transport. Web client, covenant, schema
(009), webhooks, and all consensus-visible bytes are unchanged —
the covenant/VM toolchain binaries in the production image are
byte-identical to v1.2.0's.

### Added — bearer wallet-sessions (server, config-gated, default OFF)
- `POST /auth/verify` accepts an explicit `transport: "bearer"` and,
  ONLY when `POLICYVAULT_AUTH_BEARER_SESSIONS` is enabled, returns the
  wallet-session token in the response body instead of setting a
  cookie. Without that flag — or without the explicit request — the
  route is byte-identical to the cookie-only behavior. Live production
  has the flag enabled as of this release.
- Authentication only, never authority: a bearer session grants the
  same tenancy/read/coordination access as the cookie session and, like
  it, is never consulted for signing authority. Custody stays with
  wallet signers; the server still holds no keys.
- Fail-closed resolution order, proven by suite + live acceptance: an
  explicitly presented invalid bearer refuses as an invalid session
  (never an anonymous downgrade); machine-credential-shaped
  `Authorization` values stay on the machine-credential path (strict
  separation); wrong-network wallets are refused at challenge;
  challenge nonces are single-use (replay refused); `POST /auth/logout`
  revokes a presented bearer server-side
  (`sdk/test/hosted-auth-bearer-sessions.test.js`).

### Added — native mobile production transport (Android)
- The mobile app now ships the full Capacitor Android project
  (`mobile/android/`) with an explicit native HTTP transport
  (`mobile/www/js/platform/native-http.js`, CapacitorHttp at the
  platform seam — no global fetch/XHR patching). The hosted API keeps
  its strict same-origin/no-CORS posture: no CORS grant exists or is
  required; the web client's browser security model is unchanged.
- The native adapter declares its request origin explicitly
  (documented programmatic-client contract with the hosted origin
  wall); the packaged WebView itself cannot reach the API cross-origin.
- Wallet sign-in on mobile uses the existing air-gap QR framing +
  manual-paste signature transport with the offline CLI signer
  (camera capture is not built; paste-only v1). The bearer token is
  held memory-only — never persisted, never logged by the app, never
  in a URL — and an app restart is signed out by design.
- Validated on a real Android emulator against live production:
  reads, the complete UI-driven bearer lifecycle (challenge → offline
  CLI signature → verify → authenticated read → sign out → server-side
  revocation), and the adversarial matrix (malformed/revoked bearer,
  wrong network, wrong signer, nonce replay). Android release signing,
  store packaging, and camera capture remain pending — native mobile
  stays DEVELOPMENT, not production-capable.

### Notes
- No migration: schema stays 009. No webhook, rate-limit, or
  cookie-auth change. `mobile/test/native-http.test.js` and
  `sdk/test/hosted-auth-bearer-sessions.test.js` are the new suites;
  all existing suites carry unchanged.
- No external security audit has occurred; nothing here claims one.


## v1.2.0 — Responsive client orchestration + quiet signed-out state

A client-orchestration/presentation successor to v1.1.1. No server,
schema, covenant, signing, or authentication-semantics change — the
runtime difference is exactly five `web/` files (two application files,
three test files) plus the build identity.

### Fixed — signed-out UX (hosted deployments)
- A fresh signed-out visit no longer shows the spurious
  "Organizations unavailable: sign in to use this route" toast: on a
  hosted server the client simply does not request privileged data
  (organizations, vaults) until an authenticated session exists, and
  shows quiet inline states instead ("Sign in to view your vaults." /
  "Sign in to use Organizations."). An auth refusal that still occurs
  while signed out (races) renders the same quiet state.
  AUTHENTICATED failures and all non-auth errors surface exactly as
  before; self-hosted (authMode disabled) behavior is unchanged;
  authentication semantics are untouched.

### Improved — responsiveness (client orchestration only)
- Startup parallelized: the network probe, hosted-session restore, and
  session-gated data loads run concurrently (the wallet reconnect still
  awaits the authoritative network identity first — that ordering is a
  correctness property). One `/health` request at startup instead of
  three.
- Views retain their last-good data bound to an identity epoch (wallet
  address + wallet network + session status): returning to a tab paints
  immediately with a truthful "Refreshing…" marker while an
  authoritative background refresh runs. Wallet, account, network, and
  session changes discard every retained entry and shared in-flight
  read; a response that started under an older identity is discarded
  (never painted, never cached). Cold views paint "Loading …"
  immediately.
- The vaults view's independent reads (vaults, organizations, open
  approval requests, governance proposals) run concurrently, with the
  per-vault suspension reads following as before (fail-closed
  suspension rendering preserved verbatim); serial depth drops from
  4–5 round-trips to 2. The Organizations view is parallelized the same
  way.
- Concurrent identical GETs share one in-flight request (never a
  response cache; mutations are never deduplicated). The
  network-identity banner probe deliberately bypasses this sharing so a
  self-heal retry can never be absorbed by a hung earlier probe.
- Signing in prefetches organizations + vaults and re-renders the
  dashboard (previously nothing re-rendered after sign-in).
- Immediate truthful progress states on financial actions:
  "Preparing transaction…", "Waiting for KasWare…",
  "signed — submitting…". **Pending is not success**: only the existing
  authoritative CHAIN_VERIFIED outcome renders as success, and every
  fail-closed path (RECONCILIATION_REQUIRED included) is unchanged.
- The wallet-invocation path was audited and carries zero unrelated
  awaits (fuel selection, transaction build, review, and the mandatory
  browser verification are all required inputs/gates); a regression now
  pins that unrelated reads cannot delay the wallet popup.

### Tests
- `web/test/ux-responsiveness.test.js` (new): 18 browser regressions —
  the signed-out matrix, identity-epoch invalidation (wallet / network
  / session), stale-response protection, in-flight dedupe, read
  parallelism, signing independence from unrelated reads, wallet
  rejection, and pending-is-not-success.
- `web/test/network-banner.test.js`: probe-source assertion follows the
  banner's dedupe exemption; `web/test/network-strings.test.js`:
  pinned line numbers updated.

## v1.1.1 — Truthful, fail-closed network-identity banner

A minimal, presentation-only successor to v1.1.0. Its single product
change fixes a production presentation defect: the web client's top
banner was a hardcoded `TESTNET-10` warning that was only corrected
after a *successful* network-status probe — so a MAINNET deployment
whose node probe failed kept displaying a stale, false network
identity.

### Fixed — web client only
- The banner now derives ONLY from `GET /api/v1/network/status` — the
  node-verified network identity (server-side `connectVerified`: node
  network == configured network, synced, utxoindex), which is the same
  server-reported identity the wallet signing gate compares against.
  It is never derived from the hostname, a build-time constant, or
  cached markup.
- Initial markup is a neutral `VERIFYING NETWORK…` state (it never
  names a network before one is verified).
- Resolved mainnet → a restrained `MAINNET — real KAS` indicator;
  resolved testnet → the explicit
  `<NETWORK> — no real value · mainnet broadcasting is disabled`
  warning; failed / malformed / pending →
  `NETWORK STATUS UNKNOWN — verify connection before transacting`
  (fail closed — never a stale or guessed network).
- Stale-response guard: a late response (any outcome) can never
  overwrite a newer resolution, in either direction. Bounded retry
  after failure (15s → 30s → 60s cap, stops at first success), so open
  pages self-heal after a transient node outage.
- The hosted-staging `NON-PRODUCTION` label now owns the banner
  outright — network resolution can never overwrite it.
- The pre-JS `#v4-root` placeholder and an HTML comment no longer name
  a network.

### Tests
- `web/test/network-banner.test.js` (new): 18 browser regressions
  evaluating the real production `app.js` — mainnet / testnet /
  pending / failure / malformed / retry-recovery / bounded backoff /
  stale-response ordering / staging ownership / signing-gate
  byte-identity / authoritative-source-only.
- `web/test/network-strings.test.js`: the hardcoded-network-string
  regression net now also covers `index.html` (pinned to zero
  occurrences).

### Changed
- Nothing else. The runtime difference between the v1.1.0 production
  image and this release's image is exactly four `web/` files plus the
  build identity: `web/index.html`, `web/app.js`,
  `web/test/network-banner.test.js` (new),
  `web/test/network-strings.test.js`. The wallet network verification
  gate (`verifyNetwork()`) is byte-identical — signing remains
  unavailable wherever it already required a verified network.
  Covenant bytes, transaction construction, signing, wallet adapter,
  server authentication, tenancy, policy enforcement, and the database
  schema (009) are unchanged. No CSP change. No dependency change.

## v1.1.0 — In-app documentation discovery

A minimal, presentation-only successor to v1.0.0. Its single product
change is making the documentation site, https://docs.policy-vault.org,
discoverable from inside the application.

### Added — web client only
- Persistent **Docs** link in the application header (new tab,
  `rel="noopener noreferrer"`).
- Nine contextual help affordances deep-linking to verified
  documentation pages: seven concept links in the vault-creation form
  (fee reserve, agent/delegate, per-transaction limit, periodic budget,
  destination allowlist, approval threshold, external approver) and two
  vault-action help icons (pause/revoke, owner recovery). All link
  targets are static literals verified against the live documentation
  site; titles are escaped; anchors never leak an opener or referrer.
- Three regression tests pinning the feature (header link, a real
  render of the creation form proving exactly the expected links, and
  the action-icon/helper shape).

### Changed
- Nothing else. The runtime difference between the v1.0.0 production
  image and this release's image is exactly four `web/` files plus the
  build identity: `web/index.html`, `web/app-v4.js`,
  `web/test/app-v4-gate.test.js`, `web/test/network-strings.test.js`
  (proven by a full per-file SHA256 manifest of both container
  filesystems, 11,626 files each). Covenant bytes, transaction
  construction, signing, wallet adapter, server authentication,
  tenancy, policy enforcement, and the database schema (009) are
  byte-identical to v1.0.0. No CSP change. No dependency change.

## v1.0.0 — Web/Agent Production Release (from v0.4.1)

The platform around the (unchanged) v0.4.1 covenant grew from a self-hosted
single-user application into the full Web/Agent production system now serving
https://app.policy-vault.org. The covenant protocol itself is **unchanged**:
`contracts/PolicyVault.v0.4.1.sil` is byte-identical to the v0.4.1 release
and regenerates identically.

### Added — deterministic core (`core/`)
- Portable shared core extracted from the SDK: model (Merkle trees, state
  commitments, fee/mass, frozen transactions, compute budgets), **intent
  manifests + verification**, human-readable explanations, governance
  classification + canonical digests, risk composition, signer protocol —
  byte-equivalent across Node, browser, and the mobile scaffold
  (`docs/postlaunch/cross-runtime-equivalence.md`).

### Added — hosted platform (`server/`)
- PostgreSQL persistence with migrations 001–009 (hosted schema, audit
  correlation, governance store, org controls/risk, platform agent API,
  events/webhooks, agent suspensions, hash-chained audit, notifications);
  JSON persistence remains the self-hosted default with full feature parity
  at the store layer.
- Hosted authentication (Schnorr wallet sign-in, Secure cookies), tenancy
  isolation, Origin/CSRF gate, rate limits, body caps, trusted-proxy
  handling (`docs/hosted-request-protection.md`).
- **Governance**: proposal/approval ceremony for authority-expanding policy
  changes, owner-signature-verified over domain-separated digests; proposal
  consumption is terminal. **Risk pipeline**: restrictive-only review/deny
  adapters with exactly-once released-hold continuation.
- **Intent-manifest records**: content-addressed, integrity-re-hashed on
  read, content-bound at finalize; served with live re-verification.
- Budget reservations, idempotency keys, machine identities + scoped
  capabilities, dry-run simulation, capability discovery, hash-chained
  audit with correlation ids, webhooks (HMAC-signed, optional at-rest
  encryption), human notifications, operational observability.

### Added — clients and agent surfaces
- **Browser-local independent verification** (`web/verify-intent.js` +
  `web/core-bundle.js`): full pre-sign re-derivation from the exact signing
  payload, DO-NOT-SIGN rendering, Merkle-root and state-id recomputation.
- Universal Signer Interface + KasWare mapping + offline CLI signer
  reference (verifying `/2` request format).
- MCP server (`mcp/`), Python client (`python/`), x402 and AP2
  payment-protocol adapters (`integrations/`), platform REST API for
  agents; five-path conformance matrix (`conformance/`) proving cross-path
  transaction byte-equivalence.
- Native mobile scaffold (`mobile/`) — DEVELOPMENT status, honestly labeled.

### Changed
- `agent-sdk/` (v0.4.1's headless delegate helper) was superseded by the
  platform agent API + machine identities/capabilities.
- `tools/staging-acceptance.js` drives the staging deployment from the
  outside (static/security posture, real Schnorr auth, tenancy, caps,
  rate limits); `tools/prod-acceptance.js` is its network-aware
  production successor with a fail-closed identity gate (required
  expected network + buildId) and strictly read-only foreign-data
  isolation probes.
- VM covenant workspace (`tests/vm`) is now path-portable: the repo
  root is resolved workspace-relatively (`CARGO_MANIFEST_DIR`) instead
  of assuming a `~/policyvault` checkout, so `cargo test` passes from
  any clone location (the v0.4.1 tree hardcoded the path). The
  published suite is the production + adversarial + encoder/
  SDK-integration set; internal design-probe experiment tests are not
  published (their probe contracts under `contracts/experiments/` are
  intentionally excluded — see `PUBLIC_RELEASE_MANIFEST.md`).

### Fixed (found during internal production acceptance; each with
reproduce-first regression + sabotage-sensitivity suites)
- Manifest-record lifecycle: an identical-intent rebuild after a reject
  could silently bind to a stale record and fail only after the wallet
  signature; records are now content-addressed shared evidence with an
  explicit create/share/reuse classification and a content-bound finalize
  gate (`sdk/test/rc-lc1-*`).
- Risk workflow: a released review hold was unreachable for a solo
  operator; an id-less exact re-submission now consumes the released hold
  exactly once, restrictive-only (`sdk/test/rc-ux1-*`, `web/test/rc-ux1-*`).
- Governance lifecycle: a consumed proposal could later be relabeled
  cancelled; consumption is now terminal with a closed transition machine
  (`sdk/test/rc-gv1-*`).
- External-approver discovery (found in live production operation,
  2026-08-27; hotfix deployed and automated-accepted): hosted tenancy's
  participant derivation read the persisted-JSON field name
  (`approverSlots`) off the normalized in-memory manifest (field:
  `approvers`), so external covenant-approver keys never entered the
  participant set — an approver-only wallet could not see its vault, the
  open request, the request by id, or reach the approvals route (tenancy
  404 in front of the signature verifier). Strictly fail-closed
  availability defect: no funds, authority, or cross-tenant exposure;
  approval authority itself (slot-bound signature verification) was
  never affected. The fix reads the normalized field, and a new
  request-mutation guard pins reject/signature/submit/genesis-submit to
  signer/owner/agent/delegate principals so approvers gain exactly
  read + approve and nothing wider
  (`sdk/test/external-approver-discovery*.test.js`,
  `web/test/external-approver-inbox.test.js`).

### Security posture
- Internal hostile-AI adversarial review published
  (`docs/postlaunch/hostile-ai-review.md`) with its remediations and
  pinning suites (`security/hostile-ai/`).
- **No external professional audit has occurred** (planned; see SECURITY.md).

## v0.4.1 — Initial Mainnet Release (2026-08-23)

First public release: covenant v0.4.1 (fee reserve, multi-agent, Merkle
recipients, M-of-N approvals), Node SDK, self-hosted server + web client,
real-VM verification workspace, testnet drivers, protocol documentation.
