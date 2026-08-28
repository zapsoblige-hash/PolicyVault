# PolicyVault Hosted Threat Model

**Status: DESIGN (Phase A of the Hosted Web Architecture + Security
checkpoint, 2026-08-23).** Extends — never replaces — the covenant/
application threat model in `docs/threat-model.md`. Architecture
context: `docs/hosted-architecture.md`. Nothing here is deployed;
implementation phases must turn every "REQUIRED (hosted)" line into
enforced, tested behavior before the checkpoint can PASS.

Layer rule (directive §10): **on-chain covenant authority ≠ hosted
tenancy/metadata authorization.** The covenant layer is already
VM-proven/live-proven and does not change. The hosted layer adds a
second, independent authorization surface that must be proven on its
own.

## 1. Trust boundaries

```
B1  Internet ↔ Cloudflare edge
B2  Cloudflare edge ↔ origin app (Tunnel)
B3  Browser page ↔ KasWare extension
B4  Browser ↔ App API (same-origin HTTPS)
B5  App ↔ PostgreSQL (private VPC, TLS, least-priv role)
B6  App ↔ kaspad JSON wRPC (private VPC)
B7  kaspad ↔ public Kaspa P2P network
B8  Operator/deploy tooling ↔ infrastructure
```

For each boundary: what crosses / authority / authentication /
validation / persistent mutation / on ambiguity or failure.

- **B1:** all public traffic crosses; no authority. TLS to the edge; WAF/
  rate rules filter. No mutation. Failure → availability loss only.
- **B2:** filtered HTTP crosses via the authenticated outbound tunnel;
  no funds authority. The app must not blindly trust edge-injected
  headers: the trusted-proxy config defines exactly which headers
  (client IP) are believed, and Host is validated against the
  configured public origin. Tunnel down → no ingress (fail closed,
  availability-only).
- **B3:** unsigned frozen transaction bytes and challenge text go in;
  signatures come out. ALL covenant authority originates here and only
  here. The wallet popup is the last honest reviewer (see §4). The app
  never sees keys. Wallet absent/refusing → nothing signs; in-progress
  signing state is discarded on account/network switch (existing
  security-event handling).
- **B4:** requests carry session cookie + JSON bodies; tenancy authority
  only. Authentication: wallet-bound session (challenge/response,
  §7 of the architecture doc). Validation: schema, size caps, network
  equality, Origin/Sec-Fetch/Host checks, per-object tenancy checks,
  and — for covenant operations — the INDEPENDENT signer validation
  against frozen bytes that already exists. Mutation: durable requests/
  approvals/claims/metadata. Ambiguity → fail closed (existing
  discipline: unknown versions refuse, ambiguous submissions keep
  claims).
- **B5:** durable state crosses; no funds authority (the DB cannot sign;
  a DB writer still cannot forge covenant transitions the chain would
  accept). Authentication: private endpoint + app role + TLS.
  Validation: constraints (UNIQUE claim keys, FKs) are the final
  arbiter of races. Mutation: everything durable. DB down → API refuses
  writes (fail closed); crash mid-transaction → transaction rollback +
  the reconciliation invariants (claims held, chain re-proof).
- **B6:** chain queries + ALREADY-SIGNED transaction submissions cross.
  Authority: broadcast-only (a submission cannot move funds beyond what
  its wallet signatures already authorize). Authentication: network
  isolation (VPC + firewall). Validation: `connectVerified` (network id,
  synced, utxoindex) before live operations; node txid must equal the
  frozen txid; success requires chain proof, never `submitTransaction()`
  returning. Node lies/ambiguity → claims stay held, reconcile
  fail-closed (existing proven behavior).
- **B7:** blocks/transactions cross; consensus authority lives OUTSIDE
  our infrastructure (that is the security model). An eclipse/peer
  attack could feed a stale view → mitigations: synced-check, chain
  proof before claim release, and never treating local acceptance as
  finality; worst case is availability/latency, not forged covenant
  state (forging requires breaking consensus).
- **B8:** deploy artifacts + secrets cross; full infrastructure
  authority (NOT funds authority — see §3). MFA on provider accounts,
  no long-lived SSH exposure, pinned images, no secrets in images or
  repos. Operator mistake class → runbook checklists, staging first,
  posture printout at startup (already shipped), per-network data
  roots that refuse foreign state (already shipped).

## 2. Threat actors (directive §7 roster) and primary treatment

| Actor | Treatment (defense that bounds them) |
|---|---|
| Malicious anonymous web user | edge+app rate limits, size caps, no unauthenticated mutation beyond auth-challenge issuance (itself limited), same-origin+CSRF walls |
| Malicious authenticated wallet user | tenancy checks on every object; covenant ops still demand the RIGHT signer per vault; quotas bound resource use |
| Malicious agent | UNCHANGED covenant enforcement (caps/budget/allowlist/threshold consensus-proven, incl. live negative-validation evidence); hosted layer adds nothing they can escalate through |
| Malicious approver | can only fill their own canonical slot over frozen bytes (proven in approver suites); tenancy prevents foreign-request visibility abuse |
| Malicious owner (cross-vault) | owner authority is per-vault by covenant identity; hosted tenancy scopes their metadata reach; cross-vault substitution tests already exist and extend to tenancy |
| Compromised browser extension | out of scope for the server to prevent (it holds the keys) — bounded by the wallet's own review UI + our frozen-bytes model; documented honestly as the user's trust anchor |
| Compromised web frontend | §4 below |
| Compromised API server | §3 below — the checkpoint's central question |
| Compromised database | can corrupt/lose metadata and DENY service; CANNOT sign. Forged "successor state" fails reconcile against chain truth (chain is authoritative); tampered requests fail signature/commitment checks; backups + PITR bound damage |
| Compromised reverse proxy/edge | can serve wrong bytes to browsers (≡ compromised frontend, §4) and read traffic (no secrets-equivalent user material crosses; signatures are domain-bound); cannot mint covenant authority |
| Network attacker | TLS everywhere public; VPC-private for RPC/DB; no plaintext public origin traffic |
| Replay attacker | auth: single-use expiring nonces; sessions: server-side records; transactions: consensus rejects respent outpoints — a finalized signed transition binds ONE predecessor outpoint; replays fail (already proven by live matrices) |
| CSRF attacker | SameSite=Strict cookie + Origin/Sec-Fetch verification + same-origin API, hostile-case tested |
| Cross-origin malicious website | no CORS grants + Origin checks + cookie SameSite → browser fails closed (the loopback CORS lesson, kept permanently) |
| DoS/resource exhaustion | layered limits/caps/semaphores/quotas (architecture §11); refusals never corrupt covenant state |
| Malicious package/dependency | minimal pinned deps (lockfile), npm audit gate (currently 0 vulns), no third-party scripts/CDNs in the page (CSP 'self'), dependency review on change |
| Operator mistake | fail-closed configs, per-network roots that refuse foreign stamps, posture report, staging-first, runbook + rollback docs |
| Stale deployment | no-cache static policy (shipped after the stale-build incident) + release identity in /health + deploy checklist comparing running commit |
| Rollback to vulnerable release | release identity logging + runbook rule: rollbacks only to tagged, re-gated releases; DB migrations versioned/forward-checked (unknown schema version → fail closed) |

## 3. The compromised-server question (directive §13)

**Question: if the PolicyVault hosted API server is completely
compromised, what funds can the attacker steal?**

**Answer: none unilaterally.** No key material exists on the server; all
covenant transitions require BIP-340 signatures over the exact frozen
transaction bytes, produced inside users' wallets, and Kaspa consensus
independently enforces every covenant rule against whatever the server
submits. Authentication signatures cannot be converted into spend
authority (distinct keyed-blake2b domains: `PersonalMessageSigningHash`
vs `TransactionSigningHash` — verified in rusty-kaspa source). What a
compromised server CAN do: lie to browsers (push malicious frontend —
§4), serve false state (DoS/confusion, corrected by chain-proof
reconciliation), leak tenancy metadata (privacy damage — real, bounded,
documented), refuse service, and TRY to get users to sign
attacker-shaped transactions — which is exactly the attack matrix below.

Per-attack analysis (server builds the bytes; the wallet + covenant are
the last defenses). "WALLET REVIEW" = the human-visible KasWare
transaction display + the PolicyVault pre-sign review derived from the
frozen request; "COVENANT" = consensus enforcement proven by the
existing VM/live suites; "EXISTING TEST" cites the already-green layer.

| Compromised-server attack | What stops it, honestly |
|---|---|
| Replace recipient | COVENANT for agent spends (Merkle allowlist — VM+live negative-validation proven). For OWNER ops (e.g. recovery destination): covenant checks owner signature over the bytes; the last defense is WALLET REVIEW of the recipient in KasWare's display → REQUIRED (hosted): the pre-sign review must render recipient/amount FROM THE FROZEN BYTES (§4) so a lying page cannot show one thing while the wallet signs another; KasWare itself independently displays outputs from the actual PSKT — the human sees the real destination in the wallet popup regardless of page content |
| Increase amount | COVENANT: per-spend cap, budget, conservation equations (proven). Above caps → consensus-rejected even with a real agent signature |
| Increase fee | COVENANT: fee-reserve cap `agentMaxFeePerTx` + exact conservation (proven, incl. live borrowed-fee-cap rejection). Owner-funded fees: visible in the wallet's own fee display |
| Change agent | COVENANT: agent identity is in the leaf the signature must match; a different agent key fails checkSig; registry root transitions require the owner's signature (proven) |
| Change approver set / threshold | COVENANT: `setApprovers`/policy ops require the owner signature over bytes that contain the new set; nonce bump proven; a server cannot forge the owner's signature. WALLET REVIEW must show policy-change summaries (REQUIRED, hosted) |
| Borrow another vault's policy | COVENANT: `boundVaultId`/covenantId binding (the v0.2 production-boundary incident class — now byte-proven per version); cross-vault substitution tests exist at API layer and extend to tenancy |
| Swap predecessor | Frozen bytes commit to the exact predecessor outpoint; changed predecessor ⇒ different txid ⇒ signature invalid; stale predecessor ⇒ consensus rejects (already-spent outpoint). Proven by live matrices |
| Replay signed request | Consensus: the bound predecessor outpoint is consumed exactly once; duplicate submit idempotence proven live (concurrency matrix) |
| Replace network | Config==request==manifest==node equality chain (Gate R design, tested 11/11); address prefixes per network; wallet network binding is a security event; sessions are network-bound (hosted, REQUIRED) |
| Lie about chain state | Reconciliation trusts only the node's chain proof; claims stay held under ambiguity; a lying APP cannot release claims wrongly if the reconcile path re-proves — and a fully-compromised app lying to USERS is display-only damage corrected when honest infrastructure returns (durable receipts + chain remain) |
| Serve stale request | Frozen txid immutability: finalize re-verifies signed-tx id == frozen id; stale-predecessor submissions consensus-fail; browser flows restore from server truth (approval-flow suite) — REQUIRED (hosted): reload-restore keeps deriving from durable state, never client caches |
| Trick browser into signing different bytes | THE central residual risk. Mitigations: KasWare displays the REAL transaction it signs (independent of page DOM); PolicyVault review renders from frozen bytes; signInputs validated before any popup (`SIGN_INPUTS_INVALID` guard, shipped after the approver incident); expected-signer binding before/after popup (shipped); §4 investigates an additional independent commitment check. Honest statement: a user who approves a wallet popup without reading it can be defrauded by a fully-compromised frontend — this is the irreducible wallet-review trust anchor, stated in SECURITY.md |
| Alter signInputs / sighash metadata | Shipped guard: the browser refuses any entry that is not `{index: int, sighashType: 1}` BEFORE the wallet is invoked (approver-wallet suite 6/6); server-side finalize independently requires canonical SIG_HASH_ALL signatures — malformed metadata fails closed at two layers |
| Submit old signed transaction | Consensus: predecessor consumed → rejected; receipts/claims make it visible; proven live (crash matrix AFTER_SUBMITTED / idempotent duplicate) |
| Forge approval progress | Display-only if forged by the app: finalize requires M REAL signatures verified against the frozen tx's SIG_HASH_ALL digest per canonical slot (INSUFFICIENT_APPROVALS incident regression test); consensus re-verifies all approver signatures |
| Cross-vault request substitution | Covenant binding + existing API tests (cross-vault substitution refused) + tenancy scoping (hosted, REQUIRED) |

**Residual (accepted, documented):** metadata privacy loss on server/DB
compromise; service denial; and the wallet-review trust anchor for
owner-destination operations. None grant unilateral funds authority.

## 4. Compromised frontend (directive §14)

If the served JavaScript is malicious (server compromise, edge
compromise, or supply-chain): it can lie in every pixel of the PAGE. It
cannot read keys, and it cannot make KasWare display false transaction
contents — KasWare renders its signing popup from the actual PSKT bytes
handed to it, in extension-owned UI. Therefore the defense stack is:

1. **Wallet-native review (trust anchor):** the KasWare popup shows the
   real inputs/outputs/fee of the exact bytes being signed (observed
   throughout the smoke: the human verified balance change, totals,
   fee in the wallet). The signing-review REQUIREMENTS (network,
   operation, vault, acting role, recipient, amount, fee, budget
   effect, approval status, policy change, terminal consequences) must
   be satisfiable from wallet-visible data plus the PolicyVault review;
   anything the wallet cannot show natively must appear in the
   PolicyVault review DERIVED FROM THE FROZEN REQUEST BYTES, not from
   mutable UI state (implementation phase requirement; several already
   hold: the review modal renders the canonical server review of the
   frozen transaction).
2. **CSP/supply-chain (§15):** `script-src 'self'`, no inline/eval, no
   third-party scripts, pinned lockfile, npm audit 0 — a compromised
   CDN/analytics vector simply does not exist in the page.
3. **Independent commitment verification (investigation item):** the
   review page can recompute the frozen txid FROM the served unsigned
   transaction JSON in the browser (kaspa-wasm is already loaded
   client-side? — it is NOT today; the dashboard is dependency-free)
   and display it for comparison against the wallet's own hash display
   where available. Finding: KasWare's popup does not currently display
   a txid, so cross-checking hash-to-hash inside the wallet is not
   available; the practical v1 requirement is therefore field-level
   review from frozen bytes + the wallet's independent output display.
   A future "verify on a second device" flow (QR of the frozen bytes)
   is recorded as an idea, not a commitment.

**Frontend compromise verdict:** funds theft still requires a human to
approve a wallet popup whose contents KasWare itself renders truthfully.
The design maximizes the chance the human notices: canonical review
from frozen bytes, wallet-visible outputs, no silent signing paths, and
signing metadata validated before any popup.

## 5. Multi-tenancy model (directive §10) — to be enforced in Phase C

Ownership rules for every hosted object (tenant = authenticated wallet
identity; org-scoped objects add org-role checks):

| Object | Read | Write |
|---|---|---|
| Vault record | wallets with a covenant role in it (owner/agent/approver) + org members per org policy | covenant ops: the required signer only; metadata (labels/org assignment): owner-role session |
| Wallet request | participants of that vault | create: session whose wallet is the acting signer; cancel: acting agent or owner (existing rule); approve: the specific approver slot holder |
| Approvals | request participants | the named approver only (canonical slot — already covenant/API enforced) |
| Claims / receipts / reconciliation state | vault participants (read-only surfaces) | SERVER ONLY (never client-writable — existing rule preserved) |
| Organizations / members | members | org-admin roles (metadata-only; the §6 no-covenant-authority wording stands) |
| Activity records | vault/org participants | server only |
| Sessions | the session's wallet | owner of session (logout) + server expiry |
| Rate-limit state | server only | server only |

Phase C must prove the directive's negative list (A cannot read/mutate/
approve/submit/cancel/reuse/move anything of B's) with the hostile
multi-user matrix (directive §28), independently of covenant tests.

## 6. Findings and gaps feeding implementation (Phase A output)

1. **CLOSED in Phase B (2026-08-23):** the hosted wallet
   authentication + session layer is implemented (`server/src/auth.js`,
   config gates in `sdk/src/config.js`, routes in `server/src/api.js`,
   browser flow in `web/{app,wallet}.js`) and adversarially verified —
   hostile matrix `sdk/test/hosted-auth.test.js` (29), sabotage
   `sdk/test/hosted-auth-sabotage.test.js` (6+integrity), fuzz
   `sdk/test/hosted-auth-fuzz.test.js` (4). Wallet-challenge (single-use
   5-min nonce, server-reconstructed canonical text) → pinned kaspa-wasm
   Schnorr verify → opaque 256-bit session (SHA-256 at rest,
   Secure/HttpOnly/SameSite=Strict/Path=/api cookie, 30-min inactivity /
   24-h absolute, rotation on auth, immutable wallet+network binding).
   Disabled by default (self-hosted product unchanged). Auth grants
   tenancy identity only — never covenant authority. **Phase C still
   owns the tenancy AUTHORIZATION that consumes this principal; an
   authenticated identity is not yet an authorized tenant.**
2. **CLOSED in Phase C (2026-08-23):** hosted multi-tenant authorization
   is implemented (`server/src/tenancy.js`) and adversarially proven
   (`hosted-tenancy.test.js`, 11/11 over real HTTP + auth + PG). Tenant
   root = an authenticated wallet; vault access derives from covenant
   participation (owner/agents/approvers/delegate); organizations carry
   an explicit `tenantOwner`. Denials 404 to hide existence. The Phase B
   principal is the ONLY identity source (bodies/queries/headers never
   trusted). Org role ≠ covenant authority (proven). Enforced only when
   `config.tenancyEnforced` (hosted auth on); self-hosted mode unchanged.
3. **CLOSED in Phase C (2026-08-23):** the PostgreSQL backend +
   JSON↔PG equivalence are implemented (`sdk/src/store.js`,
   `server/src/migrate.js`, `server/migrations/`) and proven on REAL
   PostgreSQL (`hosted-pg-integration.test.js` 10/10,
   `hosted-pg-auth.test.js` 8/8). Semantics ported not redesigned; the
   UNIQUE `(network_id, key)` PK is the race arbiter; write-once network
   stamp + composite key give cross-network isolation; unknown backend /
   unopened PG / dangerous auth-off multi-user combos fail closed
   (`hosted-config-matrix.test.js` 9/9). DB compromise ≠ private-key
   compromise (no signing key in any table). Full model:
   `docs/hosted-persistence.md`.
4. **CLOSED in Phase D (2026-08-24):** Origin/Host verification,
   per-class rate limits, concurrency semaphores, slow-client
   deadlines, JSON depth cap, listing clamps, and abandoned-request
   quotas are implemented (`server/src/limits.js`, wired in
   `server/src/server.js`/`api.js`, config-validated in
   `sdk/src/config.js`) and adversarially proven:
   `hosted-request-protection.test.js` (18, hostile Origin/Host matrix
   incl. DNS-rebinding and Sec-Fetch cases), `hosted-rate-limit.test.js`
   (9, incl. refusal purity + trusted-proxy keying + session-keyed
   budgets), `hosted-dos-guards.test.js` (6, semaphores + slow-client
   cutoffs + depth/clamps), `hosted-quota.test.js` (6),
   `hosted-protection-sabotage.test.js` (5+integrity, every guard shown
   load-bearing). Hosted mode enforces the application origin on
   state-changing requests with no off-switch; the self-hosted product
   keeps its released origin semantics plus the rebinding Host guard.
   All refusals are pure (429/403/421 before any durable mutation).
   Full model: `docs/hosted-request-protection.md`. Remaining for later
   phases: Cloudflare edge rules + container enforcement (E), hostile
   multi-user matrix re-run on the hosted build (F).
5. **CLOSED in Phase E (2026-08-24):** reproducible container/compose
   artifacts, fail-closed hosted startup order, meaningful liveness/
   readiness, a REAL PostgreSQL backup/restore + chain-truth DR exercise
   on testnet-10, and measured real-Cloudflare-Tunnel ingress behavior
   are implemented and proven (`docs/hosted-deployment.md`,
   `docs/hosted-backup-restore.md`, `docs/hosted-staging-evidence.md`).
   Deployment artifacts hold NO signing material and cannot authorize a
   covenant transition (directive §52); a database restore never rolls
   back the blockDAG — reconcile keeps chain truth authoritative, with no
   duplicate submission and no ambiguous-claim release after restore
   (`sdk/test/hosted-deployment.test.js`,
   `sdk/test/hosted-deployment-sabotage.test.js`,
   `tools/staging-backup-restore.js`). One honest limitation: the
   container IMAGE build + live per-layer scan could not be executed in
   the development environment (no container runtime; sudo
   non-interactive) — artifacts are authored to spec and the build-context
   privacy guarantee was verified by scanning the exact COPY-source trees;
   the operator runs `docker build` + `tools/image-privacy-scan.sh` on a
   Docker host as runbook step 1 [SUPERSEDED BY PHASE E-R: the image was
   actually built + scanned CLEAN; see `docs/hosted-phase-e-r-evidence.md`].
   The full hostile multi-user matrix re-run on the hosted build remains
   Phase F.
5b. **CLOSED in Phase F (2026-08-25, `docs/hosted-phase-f-security-review.md`):**
   the hostile multi-user + compromised-component review. It FOUND and
   FIXED a real tenant-isolation defect class — the hosted wallet-request
   READ/LIST/REJECT/mutate-by-id routes and the global `GET /audit` feed
   were not tenant-scoped (Findings F-1 HIGH read/list, F-2 HIGH
   reject/mutate, F-3 MEDIUM audit; the released self-hosted product was
   never affected). Fix: `server/src/tenancy.js` `requestAccessAllowed`
   (covenant-participant-or-signer, server-derived, default deny) wired
   into every wallet-request route + a tenant-scoped audit feed;
   `sdk/test/hosted-phase-f-hostile.test.js` (reproduced RED, now GREEN)
   and `sdk/test/hosted-phase-f-sabotage.test.js` (guard load-bearing,
   byte-identical restore). The review independently re-verified the full
   required + additional matrix: the compromised-server/DB/RPC/edge/
   frontend authority is bounded honestly and NONE of them yields covenant
   spending authority (no private keys are anywhere in the hosted stack;
   an auth signature is domain-separated from a transaction signature —
   rusty-kaspa `hashers.rs` `PersonalMessageSigningHash` ≠
   `TransactionSigningHash`). Documented non-blocking limitations:
   process-local rate-limit/quota scaling (single-replica launch),
   in-policy compromised-frontend signing (human reads the wallet prompt),
   trusted-proxy-IP origin-reachability dependency, and DB-compromise
   authorization forgery (distinct from bearer-token recovery).
6. **DECISION RECORDED:** ECDSA-account (Tangem) authentication is
   refused in v1 with a clear error; schnorr-only.
7. **FINDING (honest limit):** the wallet-review trust anchor (§4) is
   irreducible; SECURITY.md language already states signing happens in
   the wallet — hosted SECURITY.md must state the compromised-frontend
   model explicitly at release.
8. **NON-CHANGE:** covenant bytes, SDK transaction pipeline, claim/
   reconcile invariants, and the self-hosted loopback product are
   unchanged by hosting; hosted persistence is an additional backend.

## 7. Phase G/H closure — real-wallet findings + storage-representation class (2026-08-25)

Phase G (REAL KasWare human hosted-like acceptance,
`docs/hosted-phase-g-kasware-acceptance.md`) validated the full hosted
lifecycle against this model with real human wallet signatures and
surfaced two real defects, both fixed with RED-first regressions and
re-verified by the human on the fixed build:

- **G-1 (UX, error presentation):** the v0.4.1 frontend rendered the
  hosted `{error:{code,message}}` envelope as "[object Object]" and
  dropped the machine code. Fixed (shared `apiError` extraction in
  `web/app-v4.js`); BROWSER regression pins it. Threat relevance:
  fail-closed refusals must be LEGIBLE — an unreadable refusal trains
  users to distrust correct security behavior.
- **G-2 (PRODUCTION, HIGH availability, fail-closed) — NEW THREAT
  CLASS RECORDED: storage-representation dependence of integrity
  commitments.** The approval-package commitment preimage depended on
  JSON object key order; PostgreSQL jsonb canonicalizes key order, so
  the package "mutated" across the store round trip and finalize
  correctly refused (collected approvals voided; nothing broadcast;
  invisible on the key-order-preserving JSON backend, which is why
  every pre-G suite passed). Fix: strict canonical key-sorted
  serialization (`sdk/src/canonical-json.js`) in BOTH v0.4 and v0.3
  package preimages; regressions include the full approval lifecycle
  through REAL PostgreSQL. **Standing rule:** any integrity
  commitment/hash over structured data MUST be representation-
  independent (canonical serialization or normalizer-rebuilt
  structures) and MUST carry a PostgreSQL-round-trip regression. The
  Phase H sweep of every analogous boundary (state IDs, frozen-tx
  hashing, immutability gates, store serialization, numerics,
  null-vs-absent, challenge reconstruction, backup transforms) found
  NO sibling — full table:
  `docs/hosted-production-runbook.md` §19.
- The wallet-prompt trust boundary (§4) is now GROUNDED in captured
  reality (runbook §20 Q13; Phase G §4.13): KasWare's itemized rows
  are sufficient for a careful human on self-funded transactions; its
  "Balance Change" headline can mislead; covenant-input prompt
  field-completeness was not captured — the canonical server review +
  frozen-bytes signing is the primary human verification surface.

Phase H (production runbook + final closeout) consolidates the final
launch posture: single app replica pinned (process-local limiter
scaling gate), bootstrap kaspad tradeoff stated honestly, hosted
mainnet enablement fail-closed matrix, incident response, and the
27-question final security re-review with evidence — all in
`docs/hosted-production-runbook.md`.
