# L5 reconciliation remediation (RC45)

RC45 is the completed L5 remediation for the v0.4 family (`policyvault-0.4`
and `policyvault-0.4.1`), built on RC44. It is internal development work, not
an audit.

**Status (exact claim labels).**

- **RC45 source:** IMPLEMENTED and UNIT-TESTED. The SDK, API and browser-level
  suites run on JSON and PostgreSQL. Their transactions are built with the real
  compiler and encoder, TEST-key signatures and the VM preflight.
- **Further labels:** this record claims no further label for RC45; the release
  notes state the verification the release carries.
- **Unchanged:** RC45 adds no migration (schema 011 is unchanged). Frozen
  covenant bytes, generators, the compiler and `core/` are unchanged.
- **Organization roots (L2-01, §10):** IMPLEMENTED and UNIT-TESTED (the same
  suites and modes, with a mock chain). Not TESTNET-VERIFIED: the live testnet
  legs are still to run. The status label in §10 is the only permitted summary.

## 1. The defect and what RC45 changes

**L5-01.** The generic v0.4 reconciler released a transition claim and its
period reservation for three reasons: age, repeated UTXO absence, or a caller's
stale-timer or release option. A later build could then race a signed
transaction that was still valid. The defect is in RC42 and RC44. RC44 did not
include the L5 fix, which ships as RC45. No production occurrence is inferred.

RC45 keeps the reconstructed L5-01 correction:

- nothing releases a claim or a reservation because of age, absence or a caller
  option;
- protection covers signed, finalized and preflight-verified records and the
  legacy v0.4 labels;
- the request-scoped positive recovery of retained signed transactions
  (reshaped below);
- the LEAD-5 precedence ordering.

RC45 then completes the remediation:

- **Blocking is scoped to the live outpoint.** An unresolved (PENDING)
  transition record of another transaction blocks new work only when it spends
  the vault's recorded live outpoint. On a closed vault, any PENDING record
  blocks. An ordinary build also refuses before signing when a transaction
  claim sits on the live outpoint (`409 CLAIM_CONFLICT`). The refusal names the
  blocking record: `requestId`, `action`, `state`, `signerRole`, `claimTxId`.
- **Owner break-glass.** On a live vault the owner's Pause and Close & recover
  (`ownerPause`, `ownerRecover`, owner-signed) are:
  - never refused by pending work;
  - exempt from the open-request quota;
  - contesting the outpoint without touching the delegate's claim.
- **Finalize no longer leaves a byte-less signed record.** Finalize decides
  everything while the request is still BUILT and never writes FINALIZED. Its
  first request write is PREFLIGHT_VERIFIED together with the signed bytes. An
  ordinary finalize takes its transition claim just before that write. Submit
  re-creates a missing claim of its own.
- **Verify is the one settlement place (§2).** Request-scoped recovery decides
  before it writes. A settled record answers its own label with zero writes and
  zero node calls. It writes no recovery journal and re-creates no claim.
- **Hosted API and web** (see `platform-agent-api-spec.md` §5.1 and
  `webhooks-events-spec.md`):
  - every Verify status has a message;
  - Verify is offered on historical TERMINATED_UNKNOWN cards;
  - an owner can paste recover evidence;
  - `request.confirmed` is emitted only for CHAIN_VERIFIED;
  - on the v0.4-family reject route (`POST /wallet/v4/requests/:id/reject`)
    and the legacy v0.2 reject route (`POST /wallet/requests/:id/reject`),
    only the request's signer or the vault owner may reject a request
    (`403 REQUEST_FORBIDDEN` for another participant; `404` for a
    non-participant, which cannot learn that the request exists). Owner-minted machine credentials act
    as the owner. The legacy reject and signature routes answer
    `404 REQUEST_NOT_FOUND` for every record that is not a v0.2 request. On
    the `/wallet/v5`, `/wallet/v6` and `/wallet/v7` reject routes the same
    signer-or-owner rule applies; on `/wallet/v7` the owner is an active owner
    slot of the organizational root.
  - `POST /identities` with an `orgId` requires the organization owner (R1-11,
    OBS-R1-02-A; `platform-agent-api-spec.md`
    §1.2, `webhooks-events-spec.md` §10). Each of these answered 201 before:
    an `orgId` that is not a lowercase UUID string now answers
    `422 ORG_ID_INVALID`; a missing or foreign organization `404 ORG_NOT_FOUND`;
    a member who is not the owner `403 ORG_FORBIDDEN`. `identity.revoked`
    carries the stored `orgId` only for a revoker who owns that live
    organization. The fix is forward-only: identity events already stored on
    RC42/RC44 with a foreign `orgId` stay visible to that organization's
    readers, and nothing is rewritten or purged.

## 2. The settlement rule

Verify (`POST /vaults/:id/reconcile`, owner only) writes only on positive chain
evidence at depth D = 1,000 DAA, about 100 seconds at ten blocks per second. It
never writes because of:

- age;
- absence;
- a node error;
- a caller option.

**Depth evidence (R1-05).** Depth is the virtual DAA score, read first, minus
the `blockDaaScore` the node reports for an observed output. Only the outputs
an answer rests on are judged: the recorded outpoint, the observed outputs of
a recorded transaction, the one adoption candidate and the observed outputs
of a pasted recover. Request-scoped recovery of journaled history judges its
observed effect the same way.

- The node's raw value must be a non-negative bigint, a non-negative
  safe-integer number or a string of decimal digits. Anything else, a missing
  value included, answers `422 RECONCILE_FAILED` with nothing written
  (request-scoped recovery: PROTECTED_UNRESOLVED).
- A value above the virtual DAA score is below depth.
- Other outputs at the addresses read are never judged, whatever their value.

**Kaspa Protocol Evolution Compatibility.** This rule relies on
`blockDaaScore` in `getUtxosByAddresses`: a non-optional u64 in rusty-kaspa
v2.0.1 (`rpc/core/src/model/tx.rs:28`), a bigint from the WASM getter
(`consensus/client/src/utxo.rs:72`, `:188`). An upstream change to the field
or its encoding reopens this rule. Until then, any other encoding fails
closed.

Only three writes need no fresh chain read:

- finishing a transition the manifest already records;
- finishing a request from its own completion receipt (R1-06, below);
- releasing an established rejection's leftover claims, and only when at least
  one record names that transaction and every such record is an established
  rejection.

| Answer | Meaning |
|---|---|
| `CONSISTENT` | the recorded live state is on chain |
| `ADVANCED` | a transition observed at depth ≥ D was settled: `to`, `txId`, `requestId` (none for a governance-refused unsigned winner, below); `adopted: true` for an out-of-app pause/unpause |
| `TERMINAL` | the vault is closed |
| `CLAIM_PENDING` | observed below D (`depth`, `required`), or a live claim that may still execute (`claimTxId`) |
| `REQUEST_RECOVERY_REQUIRED` | signed work on the recorded outpoint may still execute (`pending[]`); on a closed vault, unresolved history |
| `UNKNOWN` | the recorded outpoint is spent and no known spender was seen (`reason`, `unchecked`) |
| `CHAIN_CONTRADICTION` | the chain contradicts the record, for example after a reorganization |
| `422 RECONCILE_FAILED` | nothing was observed and a node read failed; a judged output's `blockDaaScore` is not a canonical DAA score (above); or an environment failure that R1-04 classifies (a missing binary, a spawn error, a signal or temp-file I/O of the `pv_tx_probe` harness, or any compiler or VM-preflight failure); a dynamic-loader failure of `pv_tx_probe` is not one (L-17) |

**When Verify writes.**

- **ADVANCED:** a settlement at depth.
- **The recorded outpoint is live:** four writes are possible:
  - it restores a TERMINATED_UNKNOWN vault at depth;
  - it completes the manifest's last transition and supersedes that
    transition's losers at depth;
  - at depth, it finishes the requests their own completion receipts name
    (R1-06, below);
  - it releases an established rejection's leftover claims.

  The answer can then still be CONSISTENT, CLAIM_PENDING or
  REQUEST_RECOVERY_REQUIRED. An environment failure (R1-04) while Verify
  validates a request after the restore still answers `422 RECONCILE_FAILED`,
  and the restore stays written. Its message names the restore and says
  nothing else was written (R1-14); a failure before any write says "nothing
  was written". Request-scoped recovery quotes that message in its
  PROTECTED_UNRESOLVED detail.
- **Closed vault:** it finishes a recorded advancement and the requests their
  own completion receipts name.
- **No writes:** UNKNOWN, CHAIN_CONTRADICTION and every below-depth answer
  write nothing. UNKNOWN leaves no durable marker.

**What an answer reports (R1-07).** `settled[]` lists the requests this
Verify settled, each with its resulting state: CHAIN_VERIFIED (completed),
STALE (superseded) or SUBMISSION_REJECTED (an established rejection's
leftover claims and reservation released). These writes are not in
`settled[]`:

- an advance is the ADVANCED answer itself;
- a restore of a TERMINATED_UNKNOWN vault adds no field. The returned `vault`
  is live again, and the web derives its restore notice from the card's
  TERMINATED_UNKNOWN status before the Verify.

A closed vault's REQUEST_RECOVERY_REQUIRED answer carries `settled[]` when
Verify first finished something on that vault (R1-13): the requests of the
recorded advancement, the requests their own completion receipts name and
their signed same-txid twins, each CHAIN_VERIFIED. When nothing was finished
it carries no `settled[]`.

A CONSISTENT answer can therefore have written. The web says "Nothing was
changed." only when `settled[]` is empty and no restore occurred, and labels
each entry completed, superseded or released leftover. On a closed vault's
REQUEST_RECOVERY_REQUIRED it says "nothing was written" only when `settled[]`
is absent or empty; otherwise it lists the finished requests as completed.

**What a settlement does.**

- **The winner:** a recorded request's transaction is attributed by its txid,
  whatever the request's label. It becomes CHAIN_VERIFIED with a receipt.
  The exception is an unsigned winner (BUILT, AWAITING_APPROVALS or a closed
  state) that the governance gate refuses. The vault still advances by its
  txid, with the history row `reconciled_advanced` via
  `governance-refused-request-txid`, but the request keeps its label and
  exports REFUSED. No receipt names it, and the answer has no `requestId`.
- **Twins:** a content-identical twin in a signed state or SUBMISSION_REJECTED
  also becomes CHAIN_VERIFIED when Verify completes the winner, or finishes
  the manifest's last hop. A signed twin outside the last hop is completed
  only together with the request its receipt names, while that request is not
  yet CHAIN_VERIFIED. Once that request is CHAIN_VERIFIED (for example by its
  own zero-depth submit), the twin is not covered (the signed same-txid twin
  residual under L-2). An unsigned twin stays as it is.
- **Losers:** a PENDING loser whose predecessor the winner spent at depth
  becomes STALE, with a `transition_superseded` history row. Its claims and
  reservation are released.
- **Never:** Verify never writes TERMINATED_UNKNOWN and never returns
  `CLAIM_RELEASED`.

**A request whose own completion receipt names it is never STALE (R1-06).**
This protects the request the receipt names, not every request sharing its
transaction: a signed same-txid twin of an executed request is the residual
under L-2.

- **Receipt first.** The winner's create-only receipt is the first durable
  write of a completion, before the manifest advance and, for a recover, before
  the losers. An existing receipt is kept. A governance-refused unsigned winner
  gets no receipt.
- **Finalize and submit guard.** Finalize (of a BUILT request) and submit (of
  a PREFLIGHT_VERIFIED request) first look for a receipt of the request's own
  transaction that names this request with its expected output and value. If
  there is one, they answer `422 RECONCILIATION_REQUIRED` and write nothing,
  before the live-outpoint blocking check, before the staleness check and
  before any node call.
- **Finishing from the receipt.** Verify finishes a journal-free request in a
  signed state or SUBMISSION_REJECTED, not yet CHAIN_VERIFIED, whose own
  receipt names it with its expected output and value and whose identity is
  valid. It becomes CHAIN_VERIFIED from that receipt, with no node call,
  wherever its transaction sits in the recorded history. Its twins follow the
  twin rule above. Journaled history is never written. A request on the
  recorded live outpoint is left to the observation of its spend.

**Crash convergence.** Every write is a single-row statement. For a winner in
a signed state or SUBMISSION_REJECTED, an interrupted Verify converges on a
later Verify, because the receipt precedes every other durable write of the
completion:

- **Stopped before the manifest advance:** the next Verify observes the spend
  again and completes it. Meanwhile finalize and submit of the winner answer
  `422`.
- **Stopped after it:** Verify finishes the winner from its receipt, also after
  later transitions have moved the vault.
- **Losers:** a stop inside a loser's settlement after its STALE write can leave
  that loser's claims on the spent outpoint and its reservation, which the sweep
  reclaims.

An unsigned winner is the exception, and so is a non-terminal loser after a
further hop (both residuals under L-2).

## 3. Owner exits

| Situation | Exit |
|---|---|
| Delegate work is pending on the live outpoint (signed, finalized, preflight-verified or submitted) | Press Pause or Close & recover (below). |
| An armed ordinary request is on the live outpoint (L-5) | Pause, then Verify at depth (the request becomes STALE), then Unpause. |
| The owner acted outside PolicyVault on the recorded outpoint | Verify adopts a pause or unpause. For a recover, paste it (below). |
| A historical TERMINATED_UNKNOWN card | Press Verify on the card (below). |
| The vault moved outside PolicyVault in any other way (the L-4 class) | No hosted exit (below). |

**Pending delegate work.** Press Pause or Close & recover:

1. The action builds even when the quota is full.
2. The submit returns "Broadcast — NOT yet confirmed" (SUBMITTED).
3. About two minutes later, Verify answers `ADVANCED` and lists the superseded
   delegate request as `STALE`.

If the delegate's transaction lands first, the owner's transaction is rejected
by the node or labelled STALE. Pause again.

**Every Close & recover is two-step.** The submit returns SUBMITTED, and Verify
writes RECOVERED at depth. Keep one output of the recover unspent until Verify
shows RECOVERED (L-12).

**Armed ordinary request (L-5).** An armed request is one that is
PREFLIGHT_VERIFIED or FINALIZED but not submitted. The exit is:

1. Pause.
2. Verify at depth. The armed request becomes STALE.
3. Unpause through a governance proposal. Unpause is an expansion, so it takes
   three owner signatures in the web ceremony plus any configured delay and
   quorum.

An owner can also submit the armed request through the API.

**The owner acted outside PolicyVault.**

- **Pause, unpause, or pause then unpause:** Verify adopts it at depth. Only an
  output carrying the vault's exact covenant id is a candidate (PA-01, §7).
- **A recover:** paste the signed transaction (Safe JSON, at most 64 KiB and
  at most 64 outputs) on the UNKNOWN answer. Verify writes RECOVERED once the
  recover is observed at depth.
- **A PolicyVault-built transaction broadcast elsewhere:** Verify attributes it
  by its txid.

**Historical TERMINATED_UNKNOWN card.** Verify is offered on the owner's card.
It restores the last recorded live state at depth, or settles the vault as
above.

**The L-4 class (no hosted exit).** The vault moved outside PolicyVault in a
way not covered above:

- an out-of-app delegate spend;
- an out-of-app owner top-up or governance action;
- a multi-step out-of-app chain;
- a racing delegate spend that flipped a zero-depth hosted Pause or
  `removeAgent`.

Verify answers UNKNOWN or CHAIN_CONTRADICTION. Hosted Pause and Close & recover
spend the recorded outpoint, so the submit refuses them. Nothing is written and
no fee is paid. At consensus the owner can still pause or recover the current
output with one owner signature plus a fee input. No packaged tool does this
today; it is a roadmap follow-up, RC45-FOLLOWUP-DIRECT-OWNER-EXIT. The hosted
record does not converge afterwards unless the remedy is a recover of the
recorded outpoint, pasted as above.

A historical competing claim is never seized or deleted. Request-scoped
recovery stays an SDK/operator path; RC45 adds no hosted route for it.

## 4. The mainnet generation gate, as implemented

- **New mainnet creation** is limited to three generations:
  - `policyvault-0.4.1`;
  - `policyvault-0.7-root`;
  - `policyvault-0.7-kas`.

  The operator kill switch `POLICYVAULT_MAINNET_CREATION_DISABLED` can remove
  any of them. `policyvault-0.4` is never newly created on mainnet: its spends
  are non-standard on a default relay.
- **Operating existing state:** v0.4-family transition build, finalize, submit
  and Verify check the network (testnet-10, or mainnet with the dual-flag
  unlock). They do not check the generation, except in the places listed
  below. They would therefore operate a mainnet `policyvault-0.4` record if one
  existed.

  The earlier statement that "v0.4 mainnet mutation and request recovery
  remain refused by the existing allowlist" was wrong for build, finalize,
  submit and Verify.
- **Where the operable-generation gate does apply:** wherever a record's
  identity is validated. On mainnet a `policyvault-0.4` record is refused in
  three places:
  - **Verify's request-record writes** exclude it.
  - **Request-scoped recovery** refuses it when it is PENDING, with
    `GENERATION_NOT_MAINNET_AUTHORIZED`. A settled one answers its label with no
    write.
  - **A submit** that must re-create its own missing claim refuses it.

  Verify's manifest-level writes do not check the generation: restore, adoption
  and a pasted recover.
- **Activation:** the pre-activation check of a mainnet deployment treats any
  `policyvault-0.4` vault or request record as a stop condition.

## 5. Operator-relevant limitations (fail closed; no write unless stated)

- **L-1** A reorganization deeper than D after a Verify settlement is detected
  (CHAIN_CONTRADICTION or UNKNOWN) but not repaired.
- **L-2** Uncontested non-terminal hosted submits (`ownerPause`, ordinary actions
  including `removeAgent`) still complete at zero depth, as in RC44.
  `ownerRecover` never does.
  - **Residual of the receipt-first order (R1-06).** Verify completes an
    unsigned winner that the governance gate does not refuse (BUILT,
    AWAITING_APPROVALS or WALLET_REJECTED; signed outside PolicyVault) by its
    txid. If that completion stops after the manifest write and before the
    relabel, the request keeps its own receipt and its unsigned label. Verify
    never finishes an unsigned request from its receipt. A finalize of the
    BUILT one answers `422 RECONCILIATION_REQUIRED` by the receipt guard and
    writes nothing; finalize refuses the other two labels by their state. A
    WALLET_REJECTED label, or a later reject, therefore exports FAILED for an
    executed spend.
  - **Residual of the governed advance (R1-03; LOW, history only).** When
    Verify advances the manifest by the txid of an unsigned request that the
    governance gate refuses, its history row `reconciled_advanced` via
    `governance-refused-request-txid` is written after the manifest, the same
    order as the adoption path. A stop between the two loses that row, and no
    later Verify writes it. The manifest (advanced by the txid), the request
    (unchanged, and no receipt names it) and its export
    (REFUSED_TERMINAL_LADDER on every export path) stay correct. When the
    governed request was alone on the spent outpoint (no PENDING loser), the
    next Verify writes nothing and answers CONSISTENT. This is pinned for an
    in-process stop and for a process kill
    (`sdk/test/rc45-r1-d4-governed-audit-window.test.js`). With a PENDING
    loser there, a non-terminal advance settles the loser after the history
    row, so the stop also leaves the loser unsettled. The next Verify then
    supersedes it (STALE, its claims and reservation released) and names it
    in `settled[]`, unless the vault moves on again before a Verify settles
    the governed hop (a further zero-depth hop, or a further transition that a
    later Verify settles at depth or adopts): then no later Verify supersedes
    it (the loser-after-a-stopped-Verify residual below). The loser case without a hop follows from the code; the case with
    a hop was reproduced by the successor review (rc45-final-checks-01).
  - **Residual: signed same-txid twin (LOW; RC44 broader).** Two requests can
    share one transaction (twins). The receipt guard and the finishing rule
    protect only the request the receipt names. After the twin W that the
    receipt names has executed and one further transition has moved the vault,
    the other signed twin T is mislabelled with no fault needed: its own submit
    writes STALE (hosted `409 STALE`), or a Verify at depth never finishes it,
    so a closed vault answers REQUEST_RECOVERY_REQUIRED for it permanently. In
    the STALE case T exports AUTHORIZED/FAILED (STALE) with no txid; in the
    other case T stays PREFLIGHT_VERIFIED. W exports SETTLED; the ledger (W, the manifest and the registry) is correct. Funds, authority and
    covenant are unaffected.
  - **Residual: loser after a stopped Verify and a further hop (LOW).** A
    Verify can stop (process kill or a store error) after the winner's
    completion and before a non-terminal loser's STALE write. If the vault
    moves on again before a Verify settles that hop (a further zero-depth hop
    such as an uncontested hosted submit, L-2, or a further transition that a
    later Verify settles at depth or adopts), no later Verify supersedes that
    loser: for example the owner's contested Pause stays
    SUBMITTED, Verify answers CONSISTENT, and after a Close & recover the closed
    vault answers REQUEST_RECOVERY_REQUIRED for it permanently. The owner's
    exits (Pause, Close & recover) keep working.
- **L-3** A delegate can chase the owner. Its spending is bounded per period
  (with banking, §6) plus the fee-reserve cap. The remedy is to pause again or
  suspend agents.
- **L-4** The out-of-app class in §3, with no hosted exit. **Exposure while it
  lasts:**
  - per delegate leaf, the banked amount of §6 immediately, then one budget
    per further period;
  - payments capped by the protected value;
  - fees capped by the fee reserve.

  Whether the release accepts this class is stated in its release notes.
- **L-5** An armed ordinary request (PREFLIGHT_VERIFIED or FINALIZED, not
  submitted) on the live outpoint refuses every other ordinary build. The web
  has no submit control for it. The exit is in §3.
- **L-6** An ancestor record without a known direct spender keeps its label. It
  blocks nothing; its claims sit on spent outpoints, and its reservations are
  swept.
- **L-7** A non-permanent node rejection, or an environment SIGNATURE_INVALID,
  can still land later. Verify attributes it by txid.
- **L-8** RC44 surfaces that are unchanged; none blocks Pause or Recover:
  - reject is a no-op on signed records;
  - there is no rebroadcast;
  - Verify is owner-only;
  - unpause is governed;
  - an owner's ordinary BUILT requests count toward the quota (break-glass
    ones do not);
  - the web has no withdraw.
- **L-9** One writer is supported:
  - submit and finalize are lock-free;
  - mixed RC44/RC45 writers are unsupported;
  - a finalize close has a one-await residual window.
- **L-10** A build reads no chain. A break-glass signed after an out-of-app
  spend fails at submit, with no write and no fee.
- **L-11** Operational limits:
  - there is no RPC deadline;
  - point-in-time Verify answers and 4xx replies replay per Idempotency-Key;
  - a slow Verify may show an edge 524;
  - UNKNOWN leaves no durable marker;
  - receipts and history rows written after the manifest are best-effort (a
    Verify completion writes its receipt before the manifest, R1-06). The
    history row of a governed advance is one of them (the residual under
    L-2);
  - anyone can add outputs at the two adoption addresses, which slows Verify
    but changes no status.
- **L-12** A pasted recover must be Safe JSON, must spend the recorded outpoint
  directly, and must keep one output unspent at depth. If every output is spent
  before D, Verify answers UNKNOWN and the card stays live, although the funds
  are with the owner. Verify reads only the address of `outputs[0]` and at most
  4 further distinct output addresses, in output order (R1-09); an output at
  any other address is not read and its address is counted in `unchecked`.
  Keep `outputs[0]` unspent. More than 64 outputs is `400 BAD_FORMAT`.
- **L-13** A contested action whose outputs are all spent before D answers
  CLAIM_PENDING, then UNKNOWN.
- **L-14** Beyond 64 distinct candidate addresses, optional candidates are
  skipped and counted. Mandatory candidates are never skipped. A signed but
  unstored race loser can still execute; if not skipped, Verify attributes it
  by txid.
- **L-15** Journaled RC42/RC44 history is never written. It blocks only on the
  live outpoint.
- **L-16** An ordinary finalize that crashes between its claim and its first
  write leaves its own claim with no bytes. Ordinary builds then get the
  pre-sign 409 until one of these happens:
  - a retry;
  - a direct landing;
  - a break-glass followed by Verify at depth.
- **L-17** `pv_tx_probe` is dynamically linked. A dynamic-loader failure (exit
  127) is treated as a record defect, not as an environment error (R1-04
  classifies a missing binary, a spawn error, a signal and temp-file I/O). In
  a terminal settlement the affected loser then stays unsettled and every later
  Verify answers REQUEST_RECOVERY_REQUIRED for it; when the harness is down for
  every record, Verify answers CHAIN_CONTRADICTION and writes nothing, not
  `422`. This needs a dynamic-loader failure: a broken runtime image (verified
  at the image stage) or a transient failure to map a shared library, for
  example under memory pressure or file-table exhaustion.
- **L-18** GATE 2 (`sdk/test/authorization-boundary-inventory.test.js`) checks
  the authorization inventory lexically: a gate named in a string or template
  literal, in an uncalled closure or under a dead routing branch still counts
  as bound, and the role argument of a parameterized gate (for example
  `"owner"`) is not checked. The behaviour of the R1 routes is pinned by their
  hostile test legs (GATE 1 and the R1-01/R1-11 matrices), not by GATE 2 alone.
  Routes outside R1 rely on their own suites; for example the owner-only rule
  on governance proposal create and cancel has no merged behavioural
  regression leg (only the review-only probes of `rc45-patch-independent-02`
  exercised it).

## 6. Delegate budget banking (V041-V07KAS-PERIOD-BANKING-01; pre-existing)

**Evidence label:** VM-VERIFIED (automated, internal):

- real compiler, pinned VM tools and real TEST-key signatures;
- independently reproduced, plus a separate check with no shared code.

**Limits of the evidence:**

- consensus finality was modelled from rusty-kaspa source, not executed on a
  node;
- compute-budget pricing was not exercised;
- it is not TESTNET-VERIFIED;
- only the frozen `policyvault-0.4.1` and `policyvault-0.7-kas` covenants were
  probed.

**Not an RC45 regression.** The frozen bytes cannot change. A consensus fix
needs a new additive covenant version (a relative-age rule; this is untested
reasoning).

**Mechanism.** The rollover's only time check is
`require(tx.time >= newStart)`, which compiles to CLTV (`newStart ≤ lock_time`).
Consensus accepts `lock_time` below the current DAA score. The covenant can
therefore prove that a period has begun, never that it is the latest period.

A delegate whose leaf lags K periods can roll into each missed period in turn
(`periodsElapsed` = 1 each time) and pay a full budget in each. All of these
spends are valid at the same moment.

**Bound (VM-confirmed as exact).** Use this notation for one leaf:

- T: the current DAA score;
- S: the leaf's `periodStartDaa`;
- L: its `periodLengthDaa`;
- B: its `periodBudget`;
- σ: its `periodSpent`.

When S < T, the leaf can spend at once:

```
(floor((T − 1 − S) / L) + 1) × B − σ
```

After that it can spend B per further period. The vault total is capped by its
protected value. Each spend is still bounded by `maxPerSpend`, the leaf's
recipient allowlist, the approval tier, the per-transaction fee cap and pause.
A paused vault allows no delegate spend.

In the probe, a leaf lagging 3 periods with a 50 KAS budget paid 200 KAS
(4 budgets) at one moment. A fifth spend was refused.

**Consequences:**

- The hosted remaining-budget display (`periodBudget − periodSpent`)
  understates what a lagging leaf can spend at once.
- The design statement that under-claiming elapsed periods is
  "budget-conservative" holds only for the cumulative total. It is corrected in
  `docs/architecture.md` and `docs/source-review-findings.md` §3.

**Related finding: HOSTED-PERIOD-START-ANCHOR-01 (fixed in RC45 for hosted
paths).** Every hosted path that commits a new or changed delegate leaf of a
`policyvault-0.4.1` or `policyvault-0.7-kas` vault now starts its budget
period no earlier than the synced node's DAA score when the transaction is
built (a requested later start is kept), and refuses with
`409 PERIOD_START_STALE`, writing nothing, a request whose new or changed
delegate start has become older than that delegate's budget period minus ten
minutes (never less than one minute) at the last check before it is signed
into a state that cannot be withdrawn or is broadcast. A node whose DAA score
cannot be read refuses with `422 PERIOD_START_REQUIRED`. Leaves the change
does not touch are carried unchanged.

This does **not** change the banking above: an idle or lagging leaf still
banks one budget per elapsed period, a delegate holding its key can still
submit directly to a node, an unpause still releases the paused backlog, and
leaves already on chain keep their starts until an owner action changes,
rotates or removes them.

Two windows remain: a signed `policyvault-0.7-kas` creation and a finalized
organization-root request are not re-checked for their period start at
submit, because neither can be withdrawn on that ground (a finalized
organization-root request can be withdrawn only when an input it spends was
spent by another transaction, §10); the web submits the creation immediately
and shows the immediately spendable amount before a resumed creation or a
root request is submitted.
For requests built by this release these windows give a delegate no more than
a delegate whose period started at the build and stayed idle. Requests that
were already signed before this release (a signed creation or a finalized
organization-root request carrying a delegate rule change) keep the start they
were signed with, which may be `0`; they are a separate residual with no upper
bound other than the protected principal, and the operator counts them before
this release is activated.

Any change to a delegate, including a recipient-only change, restarts that
delegate's budget period at the build; the spent amount is committed as
requested.

A proposal created through the API, SDK or Python client that requests a
delegate period start later than the network position at the build cannot be
executed from the web: the web review refuses to sign it. Execute such a
proposal through the API or SDK, or reject the built request and create a new
proposal (a web attempt has already used up the proposal when it built the
request). The refusal never gives a delegate more.

The check is a hosted one. The browser compares the server's start only with
the same server's network position, and the covenant sees only the agent
root, so a dishonest server can still commit a stale start. The exact rule,
its check points and the limit for periods shorter than 6,600 DAA (API only)
are in `platform-agent-api-spec.md` §5.2.

## 7. Plan amendment PA-01 (Verify adoption candidates)

When the recorded outpoint is spent and no recorded transaction explains the
spend, Verify reads the two addresses of the recorded state S:
`address(S)` and `address(pauseSuccessorV4(S))`.

1. **Canonical covenant id required.** The recorded covenant id must be a
   canonical 32-byte lowercase hex string. Otherwise nothing is a candidate
   and nothing is adopted.
2. **Candidates.** A candidate is an output at either address whose covenant
   id equals the vault's covenant id exactly. An output with no covenant id, or
   with another covenant id, is ignored: it is no candidate, no evidence, and no
   status depends on it.
3. **Exact outpoints are never ignored.** The recorded outpoint itself, or the
   recorded old outpoint, observed there with any covenant id is
   CHAIN_CONTRADICTION.
4. **Refusals.** Each of these gives CHAIN_CONTRADICTION with no write:
   - a candidate whose value is not the protected value plus the fee reserve;
   - a candidate whose txid is the creation txid or a recorded request's txid;
   - more than one candidate across both addresses.
5. **No candidates.** Verify continues to the pasted recover and then to
   UNKNOWN, so the paste stays available.

A third party's payment to either address can therefore neither force a
contradiction nor hide the paste control.

## 8. Rollback: forward-only

Apart from the organization-root records of §10 (item 8), RC45 writes only
shapes that RC44 and RC42 can read: existing labels, v1 receipts, normal
manifests and history rows. It writes no journals. Even so, an image-only
return to RC44 or RC42 is **not qualified**:

1. The L5-01 age release returns.
2. Contested break-glass SUBMITTED records (every in-flight recover), and PENDING
   ancestors left by RC45, fall under RC44's vault-wide guard. Every hosted
   build, owner Pause included, and every Verify then answer
   REQUEST_RECOVERY_REQUIRED.
3. A PREFLIGHT_VERIFIED record without its own claim gets CLAIM_CONFLICT from
   RC44 submit. RC44's Verify can release the delegate's claim, and a later
   landing makes it write TERMINATED_UNKNOWN.
4. RC44's Verify writes TERMINATED_UNKNOWN on vaults that RC45 left at UNKNOWN,
   and RC44's web has no Verify on that card.
5. A paste from an open RC45 tab is ignored by RC44, which then writes
   TERMINATED_UNKNOWN.
6. RC44 counts RC45's uncounted break-glass BUILT rows again. Owner Pause and
   Recover can hit QUOTA_EXCEEDED.
7. The quota exemption and the reject narrowing revert. RC42 also lacks the RC44
   fixes.
8. The organization-root records of §10 are not recognized by RC44 or RC42:
   the attribution marker, the build-time input observation, the withdrawal
   anchor, the input-spent withdrawal record and the treasury upgrade fields.
   RC44's completion check of a CHAIN_VERIFIED root request requires a final
   transaction, which an attributed request does not carry, and RC44 has
   neither the build-time guard, the UNRESOLVED treasury refusal nor the
   submit read.

A forced return needs an empty drain set:

- every record RC44's guard protects;
- every claimless PREFLIGHT_VERIFIED record on a live outpoint;
- every contested record;
- break-glass BUILT rows beyond RC44's quota;
- every live v0.4-family vault that answers UNKNOWN in an owner-run Verify
  sweep.

An L-4 vault never drains. A forced return therefore accepts, visibly to the
owner, that RC44 writes TERMINATED_UNKNOWN on it.

Releasing RC45 requires accepting this forward-only posture; acceptance of an
earlier release's rollback does not carry over to RC45.

## 9. Release conditions for the L-4 class

The release notes state whether the release accepts the L-4 class (§5 L-4).
These four points hold for RC45:

1. The release notes state the exposure of §5 L-4 and §6, the hosted-exit
   loss, and the advice to press Verify about two minutes after any action
   that reduces authority.
2. The web's UNKNOWN text names the likely cause and the on-chain remedy.
3. RC45 never writes a terminal status at zero depth. A RECOVERED status that
   an earlier release wrote at zero depth is not re-checked; a historical
   TERMINATED_UNKNOWN is (§3).
4. The direct-owner-exit follow-up is recorded.

Accepting the class narrows direct-owner-action reconciliation to pause,
unpause, pause then unpause, and recover. Owner top-ups and governance actions
made outside PolicyVault are not reconciled; Verify answers UNKNOWN for them.
The forward-only rollback posture (§8) is a separate release condition.

## 10. Organization roots: a root move broadcast outside PolicyVault (L2-01)

This section covers organizational roots (`policyvault-0.7-root`) with
`policyvault-0.7-kas` treasuries. The rules, answers and codes are in
`v0.7-app-surface-contract.md` §2.2.

**Status label (the only permitted form):**

L2-01: Narrowed C + guard implemented. From the first Verify at ≥ 1,000 DAA after an attributable case-5 broadcast, the root and its unaffected treasuries regain hosted actions, FREEZE included, once no stranded request still holds them; that Verify names any that does. Not a complete root-and-treasury recovery: the changed treasury stays UNRESOLVED when it moved outside PolicyVault (GAP-2); a later Verify restores it only when that treasury's expected output is observed unspent again; GAP-2b, GAP-3 and GAP-16 remain as stated in the disposition table; the late-broadcast funds exposure (GAP-6) and the pre-activation check omission (GAP-9) are unresolved and not accepted.

**Evidence labels.** IMPLEMENTED and UNIT-TESTED: the SDK, API and web suites
run on JSON and PostgreSQL with the real compiler and encoder, TEST-key
signatures, the VM preflight and a mock chain. Not TESTNET-VERIFIED: the live
testnet-10 legs (L9–L12, and L14 with L14b and L14c for spent inputs) are
still to run. They must also confirm the node answer shapes that only the mock
has modelled so far: the `getBlock` verbose data (`selectedParentHash`,
`isChainBlock`), the `getVirtualChainFromBlock` added, removed and accepted
lists, and the mempool entry's `isOrphan`.

### 10.1 L2-01 and what this release does

**Case 5.** A root request carries a v0.7-kas delegate rule change that the
owners approved, but it was withdrawn or never finalized. Since R2, finalize
refuses such a request once a new or changed delegate's period start has aged
out, and the request can then be withdrawn although it carries the approvals.
Anyone holding those approvals and the fee-input signature can still broadcast
its transaction outside PolicyVault. Withdrawal does not revoke signatures or
prevent an otherwise valid out-of-app broadcast.

**L2-01 (introduced by R2).** Before R2 such a request could still be
finalized, and the root re-attached. Since R2, once a case-5 transaction was
accepted, no PolicyVault record explained the root's move: Verify answered
UNKNOWN on every call, and every hosted action on the root, FREEZE included,
was refused for good.

**What this release does** (details in `v0.7-app-surface-contract.md` §2.2):

- **Attribution.** Verify attributes such a move to the request it was built
  from, only from fresh and exact chain evidence at depth ≥ 1,000 DAA. It
  completes it FULL, where the changed treasury T1 follows the request's
  output, or PARTIAL, where T1's new output was already spent outside
  PolicyVault, so T1 is UNRESOLVED and its record is unchanged. A
  contradictory, unstable, ambiguous or shallow observation writes nothing,
  and no spent state is recorded as current.
- **Settlement and holds.** Verify settles, on proof, the requests that the
  attributed transaction stranded (SUPERSEDED), and reports `holds` and
  `buildable`. The root and its unaffected treasuries regain hosted actions,
  FREEZE included, once no request still holds them, and the answer names any
  that does.
- **UNRESOLVED treasury.** While T1 is UNRESOLVED, every hosted action on it is
  refused (`409 TREASURY_STATE_UNRESOLVED`), and a root FREEZE does not stop
  its delegates. A later Verify restores hosted actions on T1 only when it
  observes T1's expected output unspent again at depth, and never from stale
  or spent state. The depth used is the age of that output's acceptance, not
  the age of a reversal. If a restored output is spent again, T1 is refused
  `RECORDED_OUTPUT_SPENT` by the build-time guard, as for any spent treasury
  output. While T1 is UNRESOLVED, no answer presents its record as current.
- **The build-time liveness guard.** It refuses to record a root request, or
  to reserve the root with it, when the request spends a root or v0.7-kas
  treasury output that the synced node does not report unspent at build time.
  It does not prevent a spend accepted after its read or held only in the
  mempool, a broadcast of the request's own transaction outside PolicyVault, or
  a node that misreports; it keeps no state, so it never closes a usable
  treasury (`v0.7-app-surface-contract.md` §2.2.4).
- **R3N-B1 (spent inputs of a finalized request).** Submit first reads every
  input the request spends, with nothing written on a refusal. A non-root
  input reported absent answers `409 RECORDED_OUTPUT_SPENT` (spent by another
  transaction) only when the root input is still reported unspent, no output
  of the request's own transaction is observed, and existence evidence shows
  that the input was created on the selected chain for good; without that
  evidence it is not treated as spent (`409 SUBMIT_INPUT_UNRESOLVED`). After
  `RECORDED_OUTPUT_SPENT` the request can be withdrawn in two steps, at least
  1,000 DAA apart, once that spend and the input's existence are final. When
  the request's own transaction was broadcast outside PolicyVault, Submit and
  Verify keep its completion path. Uncertainty never causes a withdrawal, a claim release or a
  retry under a new key (`v0.7-app-surface-contract.md` §2.2.5).

### 10.2 Disposition

| Item | Origin | Consequence | Severity (proposed; rated by the independent review) | Coverage | Unresolved after this release |
|---|---|---|---|---|---|
| L2-01 | Introduced by R2 (finalize refuses a stale delegate rule change, which can then be withdrawn; before R2 the root re-attached) | Before this repair: root-wide permanent loss of hosted actions, FREEZE included, after a case-5 broadcast. Now the attribution Verify at depth ≥ 1,000 DAA returns hosted actions on the root and its unaffected treasuries, FREEZE included, once no stranded request holds them, and names any that does | MEDIUM | ATR-01..07, SET-01..11 (SET-06b, SET-09), GRD-01/05, WEB-05, L9 (live, pending) | The GAP-2, GAP-3 and GAP-16 sub-cases; the GAP-1 boundary (a root moved outside PolicyVault in any other way stays UNKNOWN); a request that settlement cannot settle keeps holding the root, and Verify names it |
| GAP-2 | Pre-existing class (an out-of-app delegate spend; RC44 recorded the request's spent successor); not worsened, now explicit | T1 has no hosted control: every hosted action on it is refused, a root FREEZE does not stop its delegates, and only the owners' direct on-chain exit acts on it, which moves the root outside PolicyVault (GAP-1): Verify then answers UNKNOWN and writes nothing, and no settlement runs. Hosted actions on T1 stay closed until a later Verify observes its expected output unspent again at depth; T1 is never restored from stale or spent state | MEDIUM proposed; not accepted by this record (multi-hop attribution is out of scope) | ATR-05, UNR-01..05, AFT-02/02b, UPG-01..25, L11 (live, pending) | Yes |
| GAP-2b (R3N-B1 approved) | Pre-existing (RC44 case 1); not worsened | A spend racing a hosted operation. Before the build: the guard and the input observation refuse. Between the build and the submit read: Submit refuses with nothing written, and the request can be withdrawn in two steps once the spend and the input's existence are final at 1,000 DAA, after which owner actions on the root, FREEZE included, build again. After the submit read: the existing path releases the claim (SUPERSEDED, judged from the 20-deep start). The request's own transaction accepted outside PolicyVault: SUBMIT_TO_RECORD, Submit, Verify. With FULL, T1's delegates can beat a hosted FREEZE of T1; a request that such a race strands holds the root until it is withdrawn (two steps, at least 1,000 DAA apart), or longer in the disclosed cases where a withdrawal cannot be proven safe | LOW for the repaired path if the B1 legs and L14 pass (the B1 legs pass; L14 is pending). Every residual of §10.3 is proposed LOW: r3 only with its control (MEDIUM without it); r13(d″) proposed LOW and rated LOW by the independent R3N-B1 check | GRD-06, B1-00..B1-14c, AFT-01, RACE-02/02b, L14/L14b/L14c (live, pending) | The residual windows r1–r15 of §10.3: r1 and r2 rest on assumptions IX and RD; r3 on its pre-activation control; r4 on G5, IX, MG′ and TN; r9 (any block producer can postpone a withdrawal); the r13(d″) corner, stated verbatim in §10.3, where B-1 is not described as fixed |
| GAP-3 | Introduced sub-case, left unrepaired | Two records carrying the attributed transaction: Verify answers AMBIGUOUS and writes nothing, and the root-wide loss persists for that root; the guard prevents new strands of this kind | MEDIUM sub-case, low likelihood | DUP-01, N08 | Yes |
| GAP-16 | Pre-existing (the class and its finalize-race sub-case; not introduced by R2) | A finalized request whose own transaction was broadcast outside PolicyVault: Verify answers SUBMIT_TO_RECORD until Submit; Submit then takes the existing completion route and the next Verify re-attaches the root (verified by RACE-02 and RACE-02b under both the "already accepted" and the orphan answer). An earlier unobserved treasury write can name a spent output (that treasury answers UNKNOWN and is refused RECORDED_OUTPUT_SPENT; no root hold) | LOW proposed if RACE-02/02b/03 and L12 pass (RACE-02/02b/03 pass; L12 is pending) | RACE-02..04, B1-03, B1-07c, L12 (live, pending) | The unobserved treasury write (Rule V was removed) |
| GAP-18 | Only in an earlier design (Rule V / K16), removed before implementation | None from this repair: the guard keeps no state | N/A | GRD-04/05, REG-04, N18 | None from this patch |
| GAP-6 | Pre-existing (an R2 residual) | Late-broadcast funds exposure: a delegate rule change the owners signed can be broadcast outside PolicyVault later, also after it was withdrawn; the delegates it installs can then spend one extra budget for each period elapsed since its build, capped at protectedValue − 1, and about the whole principal for an RC44-built AUTHORIZED request with a `0` period start; withdrawal does not stop such a broadcast, and whoever holds the signatures chooses its timing | Not accepted | Unchanged | Yes, separate |
| GAP-9 | Pre-existing | The pre-activation check omission: the pre-activation check (revision 6) still does not count RC44-built AUTHORIZED requests with a `0` delegate period start | Not accepted | Unchanged | Yes, separate |

GAP-6 and GAP-9 stay separate, unresolved matters: being outside this repair
does not make them accepted. Unresolved HIGH and MEDIUM findings remain
release blockers.

### 10.3 Residuals of GAP-2b (R3N-B1)

**Assumptions** (each proof names the ones it uses):

- **G5:** a selected-chain block observed at least 1,000 DAA below the virtual
  is never removed (the assumption settlement already makes).
- **IX:** the node's UTXO index lags consensus by fewer than 20 chain blocks
  for a read that a chain anchor brackets, and by less than 1,000 DAA at
  withdrawal step 2; it is unbounded in principle.
- **RD** (measured, not proven): a chain block 20 selected parents below the
  sink is not removed.
- **MG′:** a block holding a transaction that the node's virtual state accepted
  at withdrawal step 1, including one merged only by the virtual block's own
  mergeset, lies in the past of the node's sink at least 1,000 DAA later.
- **TN:** the configured synced node answers truthfully.

| # | Gap | Origin | Proposed severity and rationale |
|---|---|---|---|
| r1 | A spend at or below the submit anchor A_s that the node's index has not applied passes the submit read; the existing route then answers CLAIM_PENDING on every Verify, a root-wide hold. It needs an index lag of 20 or more chain blocks (27–47 DAA) at the submit instant; unbounded in principle (IX). | Pre-existing; narrowed | LOW: needs an IX violation on a synced node at the submit instant. |
| r2 | A_s later leaves the selected chain: the submission outcome refuses every negative answer, so CLAIM_PENDING. It needs a reorganization of 21 or more chain blocks (RD). | Pre-existing; narrowed from 33–40% of sinks | LOW: 0 of 420 removals measured at 20 deep; L14 re-measures. |
| r3 | Requests built before this release (no build-time input observation) and requests already stranded at CLAIM_PENDING cannot be withdrawn; they keep the B-1 hold. The live population is unknown here. | Pre-existing | LOW only with the control, MEDIUM without it: the population is fixed at activation and gains no new members. Control: the pre-activation record check is re-run on the final candidate and lists pending root requests (AUTHORIZED, SIGNED, BROADCAST, RECONCILIATION_REQUIRED) without a bound input observation, and every request whose Verify answers CLAIM_PENDING; activation then stops and each listed record is assessed, with no invalidation, deletion or repair of any record. This control is kept separate from GAP-9, which stays visible and unresolved. |
| r4 | After a withdrawal, a reorganization deeper than 1,000 DAA, an index lag of 1,000 DAA or more, or an MG′ failure could let the request's transaction be accepted; Verify then answers NOT_IN_SCOPE naming the request (root-wide loss). The single exception inside the assumptions is a creator flip of another input of that transaction, timed to the reads at both steps. | Repair residual (the depth class settlement already accepts) | LOW: the same G5, IX, MG′ and TN assumptions settlement relies on; the withdrawal text discloses it. |
| r5 | A request released NOT_BROADCAST after a mempool eviction, whose transaction is later broadcast outside PolicyVault, answers NOT_IN_SCOPE. In the removed-sink case the 20-deep start also newly makes NOT_BROADCAST and SUBMISSION_REJECTED provable, each releasing a claim from the submission outcome's own evidence. | Pre-existing | LOW. Its funds aspect is GAP-6, which stays separate, unresolved and not accepted. |
| r6 | The root moved past the request's transaction outside PolicyVault: UNKNOWN. | GAP-1 | LOW for R3N-B1: it adds no exposure (Submit answers ROOT_INPUT_NOT_LIVE and writes less than before); GAP-1's own rating governs. |
| r7 | Two separate statements. (a) The withdrawal waits are bounded: a root FREEZE returns no earlier than DAA(A1) + 1,000 (about 100 s); step 2 is accepted up to DAA(A1) + 12,000; a late step, an anchor removal, a new spender or an existence block above A1 renews (another ≥ 1,000 DAA), and the earliest and latest DAA are served. (b) The treasury whose output was spent stays refused without bound; that is the pre-existing GAP-2b consequence (AFT-01), not an R3N-B1 outcome. | Repair property | LOW: bounded waits, served. |
| r8 | The root lock is in-process only; withdrawal step 2 holds it for up to 64 scan batches. The reload check closes in-process interleavings; a second process can still interleave. | Pre-existing class | LOW: needs a store change from another process between the reload and the save. |
| r9 | The block scan treats inclusion as spending, so any block producer can postpone the withdrawal, and the hosted FREEZE with it, for as long as it keeps producing blocks. It suffices to place, in each anchor interval, a transaction naming one of the request's inputs: a re-inclusion of the accepted conflicting spender's public bytes, or any unsigned or invalid transaction. No keys or fees are needed. The request's own transaction in blocks or in the orphan pool does not delay it. An acceptance-only rule would be unsound. | Repair residual | LOW: it needs block production targeted at one request, with no financial gain; it is no worse than the permanent hold before this release; recorded final existence evidence survives long postponements; the owners' on-chain actions are unaffected. |
| r10 | A PREPARING attempt is released NOT_BROADCAST without chain evidence; a later broadcast of the transaction by the holder of the fee-input signature answers NOT_IN_SCOPE. | Pre-existing | LOW: needs a server crash between PREPARING and BROADCAST, then an outside broadcast. |
| r11 | SUPERSEDED releases claims with no depth on the conflicting spend; a reversal in favour of the request's transaction answers NOT_IN_SCOPE. The 20-deep start widens this to two cases that were CLAIM_PENDING on every Verify (index lag; a removed submit-time sink), each resting on an accepted, located and confirmed conflicting spend and replacing a permanent hold. | Pre-existing; reach widened | LOW: a reorganization must reverse a located and confirmed acceptance; the submission outcome logic is unchanged. |
| r12 | Legacy only: a request built before this release whose non-root input is reported with other contents can never be accepted, yet cannot be withdrawn (it is not spent by another transaction), so it holds the root. New requests cannot reach it: every non-root input is live and exact at build. | Pre-existing | LOW: legacy only, created only by the fee signer or an API caller supplying a fee input; the r3 control lists these records. |
| r13 | Absent inputs without existence evidence are never treated as spent, so the B-1 hold persists until the input appears (then Submit completes), or for good if it never does. | Pre-existing B-1 behaviour for these populations | Per sub-population below. |
| r13(a) | Legacy requests (no input observation). | | Covered by r3. |
| r13(b) | The creator's acceptance cannot be located from A_b: A_b removed (a reorganization of 21 or more chain blocks), or the creator's acceptance moved more than 2,480 merged blocks above A_b. A build anchor that cannot be read, or that left the selected chain by its recheck, now refuses the build while any non-root input is less than 1,000 DAA deep. | | LOW: needs an RD violation or a deep re-ordering. |
| r13(c) | A creator observed accepted at build was later replaced on the selected chain by a conflicting transaction; the input never exists there, so it is not spent by another transaction. | | LOW: needs the creator's input-key holder to double-spend it and a reorganization reversing an acceptance observed at build; it fails closed. |
| r13(d″) | The remaining corner, stated precisely below (it replaces revision 3's r13(d)). | | Proposed LOW; rated LOW by the independent R3N-B1 check. |
| r14 | The build anchor's soundness assumes no reorganization of 21 or more chain blocks and no index lag beyond 20 chain blocks during the build reads (RD, IX). | Repair assumption | LOW: milliseconds of exposure; RD measured. |
| r15 | MG′ fails: a block the virtual merged at step 1 that no chain block merges within the next 1,000 DAA is missed by the scan, so its spender's position could be misjudged (with r4's single exception). | Repair assumption | LOW: rusty-kaspa merges a mergeable tip in the next chain block's mergeset, and tips outside the finality point's future cannot be merged. |

**The remaining corner, stated precisely (r13(d″))**

A permanent root-wide hold, FREEZE included, remains for a finalized, never-attempted root request only when **all** of the following hold:
1. A non-root input was under 1,000 DAA deep at build.
2. Its creating transaction is not P's (a cross-root fee change, an explicit fresh fee input, or a treasury output created by a delegate payment).
3. Another party spends it before Submit.
4. No PolicyVault save of the request (slot request, slot signature or finalize) happened between about 100 s after the build and the end of the node's retention, which is at least about 30 h.
5. Withdraw step 1 first runs after that retention ended.

In the hosted record this hold does not end. The owners' direct on-chain exit moves the root outside PolicyVault (GAP-1): Verify then answers UNKNOWN and writes nothing; no settlement runs.

**Proposed rating:** LOW. A Submit answers 409 synchronously and offers Withdraw, which works at any time within retention. The corner needs every PolicyVault save to be under 100 s after the build, and then no withdrawal attempt for at least 30 h.

**The independent R3N-B1 check rates it.** If it is rated MEDIUM, it stays a release blocker, and the owner decides between K2′, K4 and acceptance.

**B-1 is not described as fixed for this corner.**

The independent R3N-B1 check rated r13(d″) LOW. Here P is the root output the
request spends. K2′ (requiring a fee input at least 1,000 DAA deep at build)
was declined because an emergency FREEZE could then wait up to about 100 s
whenever the fee wallet holds only fresh outputs; K4 (a longer node
retention) is a production node setting, not adopted here. K2 is adopted: a
root request's automatically chosen fee input is one at least 1,000 DAA deep
when one exists; it narrows the fee path of this corner and is never claimed
to close it. E1s closes the same-root back-to-back variants (the change of the
previous action on the root, and the treasury output of a previous owner
operation on the same treasury), and existence evidence recorded at a later
slot-request, slot-signature or finalize save closes the case where any such
save happens about 100 s or more after the build and within the node's
retention.

### 10.4 Further disclosures

- **Saves that wait for the node (LOW).** The slot-request, slot-signature,
  finalize and succession-signature saves of a root request now connect to
  the node to record existence evidence, with no overall timeout. During a
  node outage these owner saves can wait indefinitely and hold the in-process
  root lock until restart. Nothing false is written, and the save completes
  once the node answers.
- **Another root's identifiers in a refusal (LOW).** The UNRESOLVED refusal
  comes before the root-pin check, so a root request on one root that names
  another root's UNRESOLVED treasury is refused `TREASURY_STATE_UNRESOLVED`
  with that other root's attributed request id and txid in the message (a
  treasury that is not UNRESOLVED answers `HOSTED_ORG_IS_NOT_A_ROOT`). The
  summaries' `stateUnresolved` also shows that request id and txid to the
  treasury's delegates and approvers, who are not root participants. These
  identifiers grant no access, because the root request routes are
  root-scoped.
- **Summary routes fail closed on one damaged record.** One damaged
  organization-root request record of any root makes `GET /wallet/v7/vaults`
  and `GET /org-roots/:rootId/vaults` answer 422 for every principal who sees
  a v0.7-kas treasury. Every v0.7-kas action is already refused in that state.
- **The upgrade's history line.** A crash between the treasury record write
  and the history line of a later Verify's upgrade leaves the upgrade without
  its line for good; the marker still records it, and the next Verify has no
  candidate. Between the marker save and the treasury write, T1 is not
  reported UNRESOLVED, and the build-time guard refuses its builds
  `RECORDED_OUTPUT_SPENT` until the next Verify writes T1 or reverses the
  upgrade. If the root moves on by more than 128 transitions inside that
  window, discovery no longer reaches the request and T1 stays refused that
  way; a contradictory re-read on such a replay is refused (UNSTABLE) and
  writes nothing. These two cases follow from the code and were not exercised.
- **A reversed upgrade.** The Verify that reverses an interrupted upgrade
  (PARTIAL again) answers ADVANCED via attribution although neither the root
  nor T1 moved in it; its reason says what holds. The marker then keeps
  `upgradedFrom`, `upgradedAt` and `upgradeObservation`; only mode FULL with
  treasury ADVANCED means that T1 follows its expected output.
- **Replayed completions.** When a crashed attributed completion is finished by
  a later Verify or Submit, its CHAIN_VERIFIED history line carries `via`
  `reconcile` or `submit-recovery`; the marker keeps `via: "attribution"`.
- **Internal 500 codes.** `TREASURY_STATE_UNDETERMINED` and
  `RECONCILE_ANSWER_SHAPE` cannot be reached through the routes with the
  current SDK, have no closed web explanation and are shown verbatim. A later
  Verify does not report an upgrade again; the summaries and the marker show
  it.
- **Behaviour changes.** A root build with an explicit fee input now needs the
  node. A build refuses a fee input that is not reported unspent and exact
  (`409 FEE_INPUT_NOT_LIVE`) and a v0.7-payment vault input that is not
  (`409 RECORDED_OUTPUT_SPENT`), fails on any other input read failure (422),
  and refuses (`422 OBSERVATION_ERROR`) when the chain anchor cannot be read,
  or left the selected chain by its recheck, while an input is less than
  1,000 DAA deep. Submit refuses when the chain position cannot be read
  (`422 OBSERVATION_ERROR`) and when an input is not reported unspent (four
  findings), and its `submitStartHash` is the 20-deep selected-chain
  ancestor. Builds, submits and withdrawals make more node
  reads. Existence evidence of E2 or E3 needs the node's retained history from
  the build (at least about 30 hours by default); E1 and E1s do not.
