# Changelog

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
