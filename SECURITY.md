# PolicyVault Security

## Security model

PolicyVault's funds-control guarantees are enforced by **Kaspa L1 consensus**
via a SilverScript covenant. The backend, frontend, SDK, API, MCP server,
Python client, and payment-protocol adapters are convenience layers and are
explicitly **not** the security boundary. Any rule advertised as
covenant-enforced holds even against an actor who:

- holds the legitimate delegate private key;
- bypasses the PolicyVault frontend, backend, SDK, and API entirely;
- hand-constructs a transaction and submits it directly to a Kaspa node.

The authority model for AI/automation:

> **AI MAY REQUEST. POLICYVAULT DETERMINISTICALLY DECIDES.
> THE COVENANT ENFORCES. SIGNERS RETAIN CUSTODY.**

All LLM/tool output is treated as untrusted input. Hosted governance and risk
controls are restrictive-only coordination: they can add ceremony or refuse a
hosted workflow; they can never expand what consensus accepts, and break-glass
owner actions (pause, terminal recover) are never gated by them.

## Claim discipline

Every security statement in this repository follows
**CLAIM → ENFORCEMENT → TEST → EVIDENCE**, and carries one of three labels:

- **PROVEN** — enforced in code/consensus AND exercised by automated tests in
  this repository (and, where stated, by real-network transactions).
- **PARTIALLY PROVEN** — enforced and tested at some layers; the statement
  says exactly which layer is missing.
- **DESIGN TARGET** — designed and documented; not yet fully verified.

The invariant ledger is `docs/security-invariants.md`; the attack matrix with
per-row verification status is `docs/threat-model.md` and
`docs/hosted-threat-model.md`.

## What is PROVEN (highlights, with where the tests live)

- **Covenant policy enforcement against a key-holding delegate** — real Kaspa
  VM execution suites (`tests/vm/`, Rust, TxScriptEngine) plus authorized
  testnet negative-validation transactions constructed independently of the
  application, verifying that consensus rejects policy-invalid transactions
  even when correctly signed by the designated delegate
  (`tools/testnet-v4_1-adversarial.js`). The v0.4.1 covenant has additionally
  executed a complete real-mainnet lifecycle (create → delegated reserve-funded
  spend → pause → governed unpause → top-up → terminal recover) operated by
  its owner.
- **Deterministic byte-identity** — covenant sources regenerate byte-identically
  (`tools/gen_*.js`); identical intents build identical transactions across
  the REST/MCP/Python/x402/AP2 paths (`conformance/`); the browser bundle is
  anti-drift-pinned (`web/tools/build-core-bundle.js --check`).
- **Pre-sign independent verification** — the browser re-derives the manifest
  from the exact bytes to be signed and refuses on mismatch, including a
  27-case hostile matrix (`web/test/`); the offline CLI signer verifies
  `policyvault-cli-signing-request/2` manifests before signing.
- **Numeric safety** — integer sompi everywhere; canonical parsers reject
  numbers/arrays/leading zeros/unsafe integers at every API boundary
  (`sdk/test/amounts.test.js`, Python parity vectors).
- **Hosted request protection** — Origin/CSRF gate, Schnorr session auth,
  tenancy isolation, rate limits, body caps, trusted-proxy spoof resistance
  (`sdk/test/`, `tools/staging-acceptance.js` — 39 externally-driven checks).
- **Bearer wallet-sessions (v1.3.0, config-gated)** — an opt-in sibling of
  the cookie session for non-browser clients (`transport: "bearer"` on
  `/auth/verify`, honored only when `POLICYVAULT_AUTH_BEARER_SESSIONS` is
  enabled; with the flag off, behavior is byte-identical to cookie-only).
  Authentication only: a bearer session grants tenancy/read/coordination
  access, never signing authority or custody. Tokens are held memory-only
  in the mobile client (never persisted, never in URLs), revoked by
  logout, and fail closed: an explicitly presented invalid bearer refuses
  as an invalid session (no anonymous downgrade), a machine-credential-
  shaped value stays on the machine-credential path, and wrong-network
  wallets are refused (`sdk/test/hosted-auth-bearer-sessions.test.js`,
  `mobile/test/native-http.test.js`).
- **v0.5 TOKEN CONTROLLER covenant (COVENANT-BYTE-FROZEN, not production)** —
  `contracts/PolicyVault.v0.5.sil` (sha256 `c693aeff…`, regenerated
  byte-identically by `tools/gen_v5.js`; pinned by
  `sdk/test/covenant-freeze-v5.test.js`). CLAIM: a delegated agent
  holding the legitimate agent key cannot exceed the owner's TOKEN
  per-spend cap / period budget / recipient allowlist, cannot drain the
  covenant's KAS fee reserve, cannot substitute another token family or
  template, and the owner can pause / unpause / recover. ENFORCEMENT:
  Kaspa consensus (covenant-ID + hash-verified template dual binding;
  two-domain accounting). TEST: real TxScriptEngine execution with
  production encoder bytes — `tests/vm/tests/v5_production.rs` (37-case
  hostile spend matrix, owner matrix, load-bearing guard proofs) and
  `v5_sdk_integration.rs` (SDK-built vectors: accept / consensus-reject /
  SDK-refuse). EVIDENCE: **PROVEN on the VM**; **PROVEN on testnet-10 for
  ONE live lifecycle** (issuance → deposit → agent spend → two
  consensus-rejected negative-validation transactions constructed
  independently of the application → pause → unpause → recover; txids in
  `docs/postlaunch/v0.5-covenant-byte-freeze.md`). Rollover, deep
  registries and the full hostile matrix are VM-proven, not
  live-repeated (**PARTIALLY PROVEN** at the live layer). Limitations:
  reference KCC20 program family only (others refuse), p2pk recipients,
  no approval tier. No v0.5 production surface exists.
- **v0.6 ATOMIC COMPOSABILITY covenant (COVENANT-BYTE-FROZEN, not
  production)** — `contracts/PolicyVault.v0.6.sil` (sha256 `c7c5f22c…`,
  regenerated byte-identically by `tools/gen_v6.js`; pinned by
  `sdk/test/covenant-freeze-v6.test.js`). CLAIM: a delegated agent
  holding the legitimate agent key cannot exceed the owner's swap policy
  (per-swap cap, period budget, approved pool family, minimum output),
  cannot redirect the protocol fee, cannot introduce an external funding
  input into a swap, cannot replay an accepted swap or use stale pool
  outpoints, and the owner can control and recover. ENFORCEMENT: Kaspa
  consensus — swaps are pinned to exactly four inputs, both token
  bindings are re-derived in-VM, the pool successor is recomputed from
  the constant-product rule, and a SIGHASH_ALL gate binds the whole
  transaction. TEST: real TxScriptEngine execution with production
  encoder bytes — `tests/vm/tests/v6_production.rs`,
  `v6_sdk_integration.rs` (36 SDK-built vectors: accept /
  consensus-reject / SDK-refuse), `v6_adversarial_review_freeze.rs` (an
  independent adversarial review of the freeze, which returned
  FREEZE-NOT-FALSIFIED), and `v6_fixture_capture.rs` (the JS leaf
  fixtures pinned byte-for-byte to the Rust leaf functions the engine
  accepts). EVIDENCE: **PROVEN on the VM**; **PROVEN on testnet-10 for
  ONE live SELL and ONE live BUY lifecycle** with consensus-rejected
  negative-validation transactions constructed independently of the
  application (stale outpoints, resubmitted accepted swap, over-cap
  sell, wrong signer, redirected protocol fee, passed deadline).
  LIMITATIONS, stated plainly: **FIXTURE VENUE ONLY** — the only
  counterparty proven is this repository's own conformance pool fixture,
  which is a test artifact and not a PolicyVault product; **no real DEX
  venue, no mainnet swap, and no server / web / mobile / MCP surface**;
  `deadlineDaa` is a **pre-sign boundary, not a consensus expiry**;
  swaps are not economically viable below roughly 10 KAS; and the
  period-budget accounting in v0.3–v0.6 relies on the shared-core
  `periodLengthDaa > 0` invariant, pinned by
  `core/model/test/period-length-positive-invariant.test.js`.
  **PolicyVault is not a DEX**: it holds no pool, no liquidity and no
  order book, and it never becomes the counterparty.
- **Least-privilege capability discovery (v1.5.0)** — CLAIM: a machine
  credential learns and is advertised ONLY the capabilities its own
  scopes grant; an invalid presented credential is refused, never
  downgraded to anonymous. ENFORCEMENT: server-side scope checks on
  every call (unchanged) + principal-scoped `/capabilities` +
  credential-presenting MCP discovery (`policyvault-mcp@1.4.2`). TEST:
  `mcp/test/mcp-discovery-scopes.test.js`, conformance C01/C09/C16,
  `security/hostile-ai/mcp-agent-boundary.test.js`,
  `mcp/tools/candidate-proof.js` (exact tarball, real server: hidden
  exact-name call → 403 `SCOPE_FORBIDDEN`). EVIDENCE: **PROVEN** (the
  pre-1.4.2 behaviour was a discovery gap, never an authorization bypass).
- **Fail-closed lifecycle** — unknown versions/states/fields refuse; manifest
  records are content-addressed with build-time integrity re-hashing and a
  content-bound finalize gate; governance proposal consumption is terminal;
  released risk holds consume exactly once (regression + sabotage-sensitivity
  suites: `sdk/test/rc-lc1-*`, `rc-ux1-*`, `rc-gv1-*` — these encode real
  defects found during the internal production acceptance and their fixes).

## Internal adversarial review

An internal hostile-AI review of the agent-facing boundaries (MCP, adapters,
explanations, signer, API) is published at
`docs/postlaunch/hostile-ai-review.md` with its findings, remediations, and
the adversarial suites that now pin them (`security/hostile-ai/`). This was an
internal exercise and is labeled as such.

## Security assurance status (no external audit)

**No external professional security audit has occurred and none is part of PolicyVault's process** (owner policy, restated
2026-09-05). Security assurance is internal and evidence-based: independent internal AI falsification reviews of each exact
release candidate (the reviewer never repairs its own candidate; rounds 3–8 for the fullscale-rc15…rc28 candidates), hostile /
adversarial testing on the real Kaspa script engine with production bytes, RED-first reproduction of every finding, permanent
regressions, sabotage sensitivity, deterministic core/SDK/covenant parity, production-shaped mechanical verification (read-only
image, non-root, migrations rehearsed, rollback proven), live testnet-10 chain evidence, exact artifact and frozen-byte
verification, and the owner's own live mainnet validation after each deployment. Automated and internal evidence is always
labelled as such; human evidence is labelled as human. "Green floors measure what was tested."

## Custody

There are no master keys, no admin bypass, and no custodial recovery. The
hosted service never holds, requests, or reads seed phrases or private keys;
signing happens exclusively in the user's own wallet (KasWare today; any
signer implementing `docs/postlaunch/signer-interface-spec.md`). The one
at-rest secret class the server holds is per-endpoint webhook HMAC secrets,
with the documented envelope tradeoff in `server/src/webhooks.js`.

## Reporting a vulnerability

Open a GitHub security advisory on this repository (preferred), or a plain
issue if the report is not sensitive. Please include reproduction steps.
There is no bug bounty at this time; reports are credited unless you ask
otherwise.

## x402 facilitator claims (CLAIM → ENFORCEMENT → TEST → EVIDENCE; 2026-09-02)

`integrations/x402-facilitator/` is a separately deployed, unprivileged,
READ-ONLY chain verification / settlement attestation service for the
proposed Kaspa x402 scheme `pv-x402-kaspa-exact-upfront/1` (design frozen
by the owner: `docs/postlaunch/x402-facilitator-design-freeze.md`). It is
NOT a funds-security boundary — Kaspa consensus is — and it grants no
PolicyVault authority to anyone.

| claim | enforcement | test | evidence / label |
|---|---|---|---|
| The facilitator cannot sign, broadcast, escrow, net, or convert | no key material, no signer / builder / submit imports (dependency-direction rule 5 fails the build), `signers: {}` | `integrations/test/dependency-direction.test.js`, `x402f-hostile.test.js` (§12 row) | **PROVEN** (structural) |
| `isValid: true` / `success: true` only at CHAIN_VERIFIED: the exact outpoint observed in a synced UTXO-indexed node of the bound network, exact script + amount, covenant-free (KAS) / family covenant id (tokens), inclusion inside the DAA window, depth ≥ policy minimum | `verify-kas.js` / `verify-token.js` over `sdk/src/chain.js` reads; node identity re-verified per observation | hostile matrix (34 cases) + live proof | **PROVEN on testnet-10** (`docs/testnet-x402-facilitator-evidence.json`); PARTIALLY PROVEN for mainnet (same code path, no mainnet run — hosted deployment is a separate owner gate) |
| One payment settles at most one requirement, one requirement settles at most once, identical replays return the same stored evidence | create-only claims with two uniqueness invariants (JSON `link(2)` create-exclusive; PostgreSQL `PRIMARY KEY` + `UNIQUE`) | `x402f-policy-claims-principals.test.js`, `x402f-claims-pg.test.js` (16-way races), live proof (replay, second outpoint, second requirement) | **PROVEN** (single instance; PostgreSQL store proven for concurrent instances) |
| A payer cannot forge evidence: `transactionHex` is consistency data only; the consensus txid is recomputed by the engine, the embedded `id` and `utxo` fields are ignored | `sdk/src/tx-identity.js` rebuilds through the wasm constructor | hostile matrix (tampered id / outputs), live proof (embedded-id tamper ignored; output tamper → `TXID_MISMATCH`) | **PROVEN** — with the stated limit: the Kaspa txid does not commit to signature scripts, so token conservation over supplied inputs can only refuse, never accept |
| Token payments use the FROZEN v0.5 semantics with BOTH bindings (consensus covenant id + hash-verified template + decoded owner/amount) | `core/assets` only — no facilitator-local token parser | hostile token rows + live token leg (issuance → controller → deposit → authorized agent spend → facilitator) | **PROVEN on testnet-10**; issuer powers surfaced verbatim as DECLARED-ONLY trust properties |
| An unauthenticated or unauthorized caller gets zero node access, zero claim mutation, zero replay consumption, zero evidence, zero anonymous downgrade; a valid key of resource server A can never settle B's requirement | fixed request order in `service.js` (credential → scope → rate limit → body → facilitator); principal `payTo` / network / origin constraints supplement the deterministic binding | `x402f-service-integration.test.js` (incl. the mandatory cross-principal negative), live proof (401 / 403 rows) | **PROVEN** (v1 = facilitator-issued API key over HTTPS; TLS termination is the deployment's proxy — mTLS is optional future hardening) |
| Raw credentials are never persisted, logged, listed, or placed in URLs | `principals.js` stores `sha256(raw)` only; constant-time compare; query strings refused | service suite hygiene case | **PROVEN** |
| Unknown versions, schemes, policies, networks, assets, owner schemes, template variants fail closed | closed schemas + closed 35-code set | hostile matrix | **PROVEN** |
| Reorg after CHAIN_VERIFIED; outputs spent before `/settle`; `payTo` reuse | depth carried in evidence; documented limitation (kaspad has no txindex); `REQUIREMENT_DESTINATION_REUSED` | hostile matrix + live spent-before-settle row | **DESIGN TARGET with stated residual risk** (bounded by `MIN_DEPTH_DAA`, default 100, hard floor 20) |

No external security review of the facilitator has occurred; none is
claimed.

## Flagship wave 1 claims (CLAIM → ENFORCEMENT → TEST → EVIDENCE; v1.7.0)

Everything in this section is **SOURCE ONLY — not deployed**. The live
hosted deployment is unchanged by this release.

| claim | enforcement | test | evidence / label |
|---|---|---|---|
| The Universal Signer Interface v2 (`policyvault-signer/2`) cannot silently accept a signer whose real behaviour contradicts what it advertised, cannot replay a response across requests, and exposes no field through which a seed phrase, private key or wallet backup could travel | capability negotiation + a probe-versus-declared check that fails closed; response envelopes bound to the request; a replay guard; the request/response schemas have **no slot** for key material | `core/signer/test/hostile-v2.test.js` (48 cases), `v2-conformance.test.js`, `v2-lifecycle.test.js`, `v2-adapters.test.js`, `core/signer/adapters/cli/test/v2-conformance.test.js` | **PROVEN as a unit/adversarial property.** v2 is **additive and inert** — no production consumer has been migrated to it, and **no live independent second wallet has been exercised**. PSKT and ECDSA wire contracts are deliberately unfrozen |
| An execution attestation cannot be tampered with undetected, cannot claim an outcome the ladder does not support, and cannot be re-hashed into a valid-looking record | canonical serialization + hash addressing; the outcome ladder is enforced as a contiguous prefix with narrow refusal attribution; a closed schema | `core/attest/test/tamper.test.js` (32 tamper classes, naive and re-hashed), `record.test.js`, `chain-facts.test.js`, `purity.test.js`, `language.test.js` | **PROVEN as a unit/adversarial property** |
| An independent party can re-check an attestation against the chain without trusting PolicyVault | `tools/attestation-verify.js` is a pure, opt-in verifier that reads a node directly and reports `CHAIN_CONFIRMED` · `UNCONFIRMED` · `UNAVAILABLE` · `CONTRADICTED` | `sdk/test/postlaunch-attestation-cli.test.js`; the chain re-check path run against the v0.6 live evidence | **PROVEN on testnet-10** for the chain re-check path. **No signature key exists** — the signature slot is designed and deliberately empty, because PolicyVault holds no server-side key near funds. Exports state no confirmation depth (the accepting-block DAA score is not persisted in `receipt/v1`) |
| Attestation export cannot leak another tenant's data or be read without an explicit grant | a NEW deny-by-default scope `read:attestations`; organization scoping on the export route | `sdk/test/postlaunch-attestations-server.test.js` (incl. a banned-field byte scan) | **PROVEN as an API property** |
| MCP usage telemetry records no vault identifier, amount, address, credential or free text — and records nothing at all unless an operator turns it on | closed event schema, create-only storage category, `POLICYVAULT_MCP_TELEMETRY` default OFF, hard cap + retention pruning | `sdk/test/postlaunch-mcp-telemetry-server.test.js` (13 cases incl. a privacy-negative byte scan), conformance C21 | **PROVEN as a unit/API property**; **not enabled in any deployment** |
| A release signature cannot be counted against a placeholder or unknown key, and a manifest hash cannot be asserted by the caller | `tools/release-verify.js` refuses any signer entry whose public key is still `OWNER-TO-FILL`; `tools/release-manifest.js` computes every hash itself (only registry image digests are caller-supplied and shape-checked) | `tools/test/release-signing.test.js` | **PROVEN as a tooling property.** `release-signers.json` is **ONE signer, threshold 1, public key unfilled**; this is multi-signer *capable*, **not** a multi-signer policy, and **no release has been signed** |
| The deployment pipeline cannot activate an image that fails a privacy scan or a private health probe, and cannot lose the ability to roll back | `verify-before-activate.sh` gates activation; deploy-by-digest with a rollback ledger; interrupted-build safety | `sdk/test/deploy-pipeline.test.js`; a local 7/7 proof run | **INTEGRATION-VERIFIED LOCALLY (non-production).** Never run against production; the first production use is an owner decision |
| The browser cannot mis-parse a KAS amount on the spend path | the canonical `core/model/amounts` parser via the shipped core bundle; 15 recorded defects pinned as refusals | `web/test/client-amounts-parity.test.js` with a golden fixture captured from the pre-fix parsers | **PROVEN** — this fixed a real **production code bug** (floating-point conversion accepted `0x10` and `1e3`, rounded a ninth decimal, and turned `0.000000001` into `0`) |
| Unknown controller-intent versions are never routed to a default | `core/intent/router.js` fails closed | `core/intent/test/router.test.js`, `sdk/test/token-manifest-v6.test.js` | **PROVEN** |
| A self-hosted deployment redacts secrets from its logs, restores from its own backup, and depends on nothing specific to the maintainer's machine | `tools/selfhost-acceptance.sh` (22 steps): real Schnorr authentication, isolated-database backup/restore with row-count and hash verification, upgrade/rollback identity, log redaction, host-reboot simulation, hidden-dependency scan | the acceptance script itself, run in a clean environment | **INTEGRATION-VERIFIED.** Gap: wallet authentication end-to-end is **NOT tested headlessly** (it needs a browser and a wallet extension) |

The web and mobile UX work in this release is UNIT- and jsdom-BROWSER-tested
only. **No person has operated these screens in a browser, on a device, or
against production; human acceptance is not claimed.**

No external security review of any of this has occurred; none is claimed.

## Organizational root and RC27 claims (CLAIM → ENFORCEMENT → TEST → EVIDENCE; v1.9.0)

| Claim | Enforcement | Test | Evidence / status |
|---|---|---|---|
| Owner authority over a rooted vault is the covenant's M-of-N quorum, never a hosted role, never a single key | `PolicyVault.v0.7-root.sil` / `v0.7-payment.sil` (byte-frozen); every counted owner signature SIGHASH_ALL-gated in-covenant; server routes consult no hosted membership | `tests/vm/tests/v7_*.rs`, `sdk/test/org-root-hostile-matrix-v7.test.js`, `sdk/test/covenant-freeze-v7.test.js` | PROVEN (VM + production bytes + live testnet-10) |
| The wallet is never shown a rooted-vault payload whose consensus-visible bytes differ from the reviewed intent (fee reserve, terminal payout, agent root, sequences, lockTime) | shared-core verifier + `web/org-root-ui.js bindRootSigningPayload`; successor vault script reconstructed pre-sign | `web/test/org-root-signing-boundary.test.js`, `sdk/test/vm-presign-parity.test.js` | PROVEN (source + browser evidence) |
| An unsigned owner request reserves the root and guards its vault; only an unsigned, never-attempted request can be withdrawn; a finalized request resumes its original submission; an attempted one needs outcome recovery | `sdk/src/wallet-requests-v7.js` (`rejectOrgRootRequest`, `pendingRootRequests`, `assertVaultCompletionAvailable`), browser `withdrawEligibility` | `sdk/test/recovery-lifecycle-rc27f.test.js`, `completion-edges-rc27f.test.js`, `web/test/org-root-ui.test.js` | PROVEN (SDK/PG + browser evidence on the image) |
| A proven negative outcome settles only its own claims; uncertainty is never released on age, generic errors or a single read | `sdk/src/submission-outcome-v7.js` | `sdk/test/delegate-outcomes-rc27f.test.js`, `outcome-arbitration-rc27f.test.js`, `submission-reorg-rc27f.test.js` | PROVEN (SDK/PG; live testnet-10 removed-anchor recovery of a real request) |
| No hosted build without the signed-in wallet or its machine credential; no build into a stranger's inbox; bounded build storage | `server/src/api.js` build authority + bounded compiled-artifact cache | `sdk/test/hosted-foreign-tenant-matrix.test.js`, tenancy suites | PROVEN (source); production-shaped harness RED on rc8 / GREEN on the successor |
| Only `policyvault-0.4.1` can be created on mainnet; unknown versions fail closed | `assertGenerationMainnetCreatable`, own-property lookups | `sdk/test/generation-gate*.test.js`, capabilities document | PROVEN (source + served capabilities) |
| Older (pre-RC27F) v0.7 records recover through the public reconcile without an undocumented repair: a never-finalized or withdrawn request, or a signed same-effect duplicate of the request this system actually submitted, is never the completed request, never a completion candidate, never a vault guard, never relabelled | `sdk/src/wallet-requests-v7.js` (`neverEffective`, `sameEffectDuplicate`), `sdk/src/reconcile-v7.js` | `sdk/test/legacy-same-txid-r8.test.js` on df68a1f-produced snapshots (`sdk/test/fixtures/legacy-df68a1f/`), `legacy-history-rc27f.test.js` | PROVEN (SDK, RED-first; round-8 findings R8-01/R8-02/R8-09 closed by the reviewer's re-checks; residual R8-10 LOW recorded in SECURITY limitations) |

## Post-launch live-stack review corrections (CLAIM → ENFORCEMENT → TEST → EVIDENCE; v1.9.1)

| Claim | Enforcement | Test | Evidence / status |
|---|---|---|---|
| A webhook endpoint can never make the hosted service dial a loopback, private, link-local, CGNAT, metadata, tunnelled (v4-mapped / v4-compatible / SIIT / NAT64 / 6to4 / Teredo) or reserved address, however the literal is spelled and whatever DNS answers | `server/src/events-delivery.js` — `isForbiddenTargetIp` on the eight 16-bit groups of every IPv6 spelling; `guardedLookup` validates EVERY resolved address and refuses the whole answer set on one forbidden entry; the socket dials exactly the validated addresses (no second resolution) | `sdk/test/rc28-webhook-target.test.js`, `sdk/test/rc29-webhook-dns-transport.test.js` (RED-first on the rc28 bytes), `sdk/test/postlaunch-webhooks-delivery.test.js` | PROVEN (source + real Node transport on loopback); production had zero active webhook endpoints at every observation |
| A hostname-addressed webhook is actually delivered on the pinned Node 20 runtime (the lookup honours net's `{ all: true }` contract) | `guardedLookup` answers in the caller's shape (array for `all`, pair otherwise) | `sdk/test/rc29-webhook-dns-transport.test.js` (real `net.connect` with the default `autoSelectFamily`) | PROVEN (RED on rc28 bytes → GREEN) |
| An SDK / mobile caller never loses the `Idempotency-Key` of a mutating call whose outcome is unknown (transport failure before OR after the headers, invalid JSON after a success status) | `sdk/src/http-client.js` — body acquisition inside the transport boundary; `PolicyVaultNetworkError` carries the key; HTTP errors keep their status; no automatic retry | `sdk/test/rc28-http-body-failure.test.js` | PROVEN (SDK); same-key retry is at-most-once only on idempotency-supported routes — secret-bearing identity / webhook / notification routes require resource inspection first (documented) |
| A never-attempted SIGNED sibling of a completed legacy request can never be marked `CHAIN_VERIFIED`, take the original's keyed receipt or block later admission — through the public reconcile AND the direct submit route; an already-damaged both-`CHAIN_VERIFIED` pair keeps its fully validated representative and the runtime never guesses which witness was broadcast | `sdk/src/wallet-requests-v7.js` — same-effect refusal before any RPC / completion write in `submitDelegateRequest`; bound receipt representative in `inspectDelegateCompletion`; settled negative siblings excluded | `sdk/test/rc28-live-stack-recovery.test.js` on df68a1f-produced fixtures, `sdk/test/legacy-same-txid-r8.test.js` | PROVEN (SDK, RED-first); legacy / testnet v0.7 records only — no v0.7 record exists on mainnet |
| The container image and the npm package carry the Apache-2.0 `LICENSE` and `NOTICE` byte-identically; nothing is relicensed | `deploy/Dockerfile` (`COPY LICENSE NOTICE /app/`), `deploy/pipeline/bundle-source.sh`, `mcp/package.json` `files` + `prepack` → `mcp/tools/check-license.js` | `mcp/test/package-consumer.test.js`, `mcp/test/package-closure.test.js`; image inventory check in the private packet | PROVEN (exact image / tarball inventories) |
| The shipped native tools and WASM carry no private build-machine paths; every image layer, metadata record, nested archive and compressed payload is scanned fail-closed with exact classifications before rollout or publication | `tools/build-private-safe-vendor.sh` (path remapping + non-allocated debug strip), six tracked pins in `deploy/vendor-pins.sha256`, `tools/verify-image-vendor-pins.sh`, `tools/artifact-privacy-scan.py` | `tools/test_artifact_privacy_scan.py` (13 controls incl. recomputed hostile descriptors, orphan / deleted anchors, tar boundary secrets), `sdk/test/vendor-pins-tracked.test.js`, `sdk/test/image-scan-classify.test.js` | PROVEN for the exact rc29 image and the exact `policyvault-mcp@1.5.0` tarball (private evidence); arbitrary secrets and screenshot steganography are not exhaustively proven absent |
| Recovery / succession explanations shown to owners agree with the covenant rules (succession keeps a listed key, recovery-off with succession is not "locked forever", quorum language is M of N of the installed set) | `web/org-root-ui.js`, `core/explain/org-root-explain.js` (shared core; regenerated bundles pinned) | `web/test/org-root-setup.test.js`, `core/explain/test/org-root-explain.test.js`, rendered controls in the headless-Chromium harness | PROVEN (source + browser evidence on the exact image) |

## Second post-launch review corrections (CLAIM → ENFORCEMENT → TEST → EVIDENCE; v1.9.2)

| Claim | Enforcement | Test | Evidence / status |
|---|---|---|---|
| A webhook receiver that acknowledges with response headers and then stalls or trickles its body cannot hold a delivery socket open beyond the per-attempt deadline (10 s default) — in every outcome class (complete, success-stall, refusal-stall, redirect-stall, oversized, broken, trickle, no headers) and under concurrent acknowledged stalls | `server/src/events-delivery.js` — the absolute per-attempt deadline is cleared only on response `end` / `close`; destroying the request at the deadline never changes the already-recorded header outcome (2xx delivered / non-2xx failed / 3xx never followed); body drain capped at 8 KiB; DNS-answer pinning and private-address refusal unchanged | `sdk/test/rc29-webhook-response-deadline.test.js` (real loopback sockets; nine cases) | PROVEN (RED 4 pass / 5 fail on the previous module → 9/9 on the source and inside the exact release image; the seven pre-existing webhook / notification / DNS / target suites 44/44 with live PostgreSQL alongside it) |
| The shipped Silverscript compiler and the vendored KCC20 reference program carry the pinned upstream ISC notice beside the compiler and beside the program, without altering PolicyVault's Apache-2.0 `LICENSE` / `NOTICE` | `contracts/vendor/LICENSE` (unchanged notice of Silverscript `d25bd342…`, sha256 `feee0f42…`); `deploy/Dockerfile` (`COPY contracts/vendor/LICENSE /home/pv/silverscript/LICENSE`); provenance in `contracts/vendor/README.md` | exact image inventory (both notice paths hashed, root-owned, not group/world-writable; `LICENSE` / `NOTICE` byte-identical at root, `mcp/` and in the image) | PROVEN on the exact image (identified notice obligation only; not an exhaustive third-party licensing opinion) |

## Organization UI availability correction (CLAIM → ENFORCEMENT → TEST → EVIDENCE; v1.9.3)

| Claim | Enforcement | Test | Evidence / status |
|---|---|---|---|
| The console offers new organizational-root setup only when the server's capability discovery for the SAME network advertises both `policyvault-0.7-root` and `policyvault-0.7-payment` as creatable; missing, malformed, mismatched or incomplete discovery fails closed to a disabled control with an upfront explanation; existing roots, their history and hosted grouping stay readable | `web/org-root-ui.js` (`rootCreationAvailability`) and `web/app-v4.js` (`rootCreationAllowed`, before the wizard opens and again before a build) — presentation gates only; the authority stays `sdk/src/config.js` (`assertGenerationMainnetCreatable`) and `server/src/capabilities.js`, both unchanged | `web/test/org-root-mainnet-availability.test.js` — the real `index.html` and scripts in a DOM with a synthetic wallet and intercepted HTTP: six fail-closed discovery cases, the supported-testnet control, a refresh of discovery while setup is open | PROVEN on the exact image bytes (13/13; RED on the live rc30 bytes 11 fail / 2 pass); no UI test enables an unauthorized mainnet generation |
| A generation refusal explains that changing the address or amounts cannot enable an unsupported mainnet generation; the server's exact code and message stay visible; inside a legacy `BUILD_FAILED` wrapper only the SDK guard's exact sentence for a known generation is recognized | `web/refusal-explain.js` (`GENERATION_NOT_MAINNET_AUTHORIZED` entry; exact-sentence match for seven known generations) | `web/test/refusal-explain.test.js` — the sentence is generated by the real SDK guard; unrelated and near-miss messages keep the generic explanation; hostile text is escaped and the original code survives | PROVEN (unit + DOM, on the exact image bytes) |
| A root-build refusal renders inside the wizard; cancelling or leaving the wizard clears only the wizard's own notices; a delayed refusal of an abandoned build never overwrites a newer pending / uncertain notice; a build that completes after Cancel is withdrawn instead of opening a review over another view | `web/app-v4.js` (`noteRootWizard`, `navigateTo`, the late-outcome guards in `buildAndReviewRoot`) | the same DOM suite: stale-discovery refusal inside the modal, notice scoping across navigation, delayed refusal with and without a newer warning, delayed success after Cancel | PROVEN on the exact image bytes; presentation only — no request, signature or broadcast is involved |
